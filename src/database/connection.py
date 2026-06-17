import asyncio
import asyncpg
import json
import logging
import datetime
from typing import Dict, Any, List, Optional
from config.settings import settings

logger = logging.getLogger("threat_detection.database")

class DatabaseHelper:
    """Manages the PostgreSQL database connection pool and CRUD operations for threat alerts."""
    
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        # Normalize connection string for pure asyncpg (replace postgresql+asyncpg with postgresql)
        self.dsn = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
        
        # Async batch queue state
        self.queue: asyncio.Queue = asyncio.Queue()
        self.redis_client = None
        self.worker_task: Optional[asyncio.Task] = None
        self.batch_size = settings.DB_BATCH_SIZE
        self.batch_interval = settings.DB_BATCH_INTERVAL

    async def connect(self):
        """Initializes the asyncpg connection pool with connection retries."""
        if self.pool is not None:
            return

        max_retries = settings.DB_MAX_RETRIES
        backoff = settings.DB_RETRY_BACKOFF
        
        for attempt in range(1, max_retries + 1):
            try:
                self.pool = await asyncpg.create_pool(
                    dsn=self.dsn,
                    min_size=2,
                    max_size=10,
                    command_timeout=60
                )
                logger.info("Successfully established PostgreSQL connection pool.")
                
                # Start batching background task
                if self.worker_task is None or self.worker_task.done():
                    self.worker_task = asyncio.create_task(self._batch_flusher())
                return
            except Exception as e:
                sleep_time = backoff * (2 ** (attempt - 1))
                logger.error(f"Failed to create database connection pool (attempt {attempt}/{max_retries}): {e}")
                if attempt == max_retries:
                    raise e
                logger.info(f"Retrying database connection in {sleep_time:.2f} seconds...")
                await asyncio.sleep(sleep_time)

    async def disconnect(self):
        """Closes the database connection pool after flushing any remaining queued alerts."""
        if self.worker_task is not None:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass
            self.worker_task = None
            
        await self._flush_remaining()
        
        if self.pool is not None:
            await self.pool.close()
            self.pool = None
            logger.info("Closed PostgreSQL connection pool.")

    async def initialize_db(self):
        """Creates the necessary schema tables if they do not exist in the database."""
        if self.pool is None:
            await self.connect()
            
        queries = [
            # 1. Threat alerts table
            """
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                time_epoch BIGINT,
                src_ip VARCHAR(45),
                src_port INTEGER,
                dst_ip VARCHAR(45),
                dst_port INTEGER,
                protocol VARCHAR(20),
                bytes_in BIGINT,
                bytes_out BIGINT,
                l1_anomaly_score DOUBLE PRECISION,
                l2_threat_prob DOUBLE PRECISION,
                l3_threat_prob DOUBLE PRECISION,
                classification VARCHAR(100),
                is_anomaly BOOLEAN,
                explanations TEXT,
                model_version VARCHAR(50) DEFAULT '1.0.0'
            );
            """,
            # Ensure model_version column exists if table was created in an older version
            """
            ALTER TABLE threat_alerts ADD COLUMN IF NOT EXISTS model_version VARCHAR(50) DEFAULT '1.0.0';
            """,
            # 2. Threat stats table
            """
            CREATE TABLE IF NOT EXISTS threat_stats (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                total_processed BIGINT,
                total_alerts BIGINT,
                l1_dropped BIGINT,
                l2_alerts BIGINT,
                l3_alerts BIGINT
            );
            """,
            # 3. Model configurations table
            """
            CREATE TABLE IF NOT EXISTS model_configurations (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                l1_threshold DOUBLE PRECISION,
                l2_feature_names TEXT,
                l3_window_size INTEGER
            );
            """
        ]
        
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                for query in queries:
                    await conn.execute(query)
        logger.info("Database tables initialized successfully.")

    async def log_alert(self, alert: Dict[str, Any]):
        """Pushes a threat alert record to the queue for background batch writing."""
        if "model_version" not in alert:
            alert["model_version"] = settings.MODEL_VERSION
            
        if settings.USE_REDIS and self.redis_client:
            try:
                await self.redis_client.rpush("threat_alerts:queue", json.dumps(alert))
            except Exception as e:
                logger.error(f"Failed to queue alert to Redis, dynamically disabling Redis client: {e}")
                self.redis_client = None
                await self.queue.put(alert)
        else:
            await self.queue.put(alert)

    def unwrap_item(self, item):
        """Checks if the item is a DLQ re-queued envelope. If so, logs its metadata and returns the unwrapped alert."""
        if isinstance(item, dict) and "alert" in item:
            logger.debug(
                f"[DLQ] Processing re-queued DLQ alert. Retry count: {item.get('dlq_retry_count', 0)}, "
                f"first failed at: {item.get('first_failed_at')}, reason: {item.get('failure_reason')}"
            )
            unwrapped = item["alert"]
            if isinstance(unwrapped, dict):
                # Attach the original envelope metadata using a private key
                unwrapped["_dlq_envelope"] = item
            return unwrapped
        return item

    async def _batch_flusher(self):
        """Background worker loop that aggregates alerts and writes them to database in batches."""
        while True:
            try:
                batch = []
                in_memory_count = 0
                
                # Check Redis first if enabled
                if settings.USE_REDIS and self.redis_client:
                    try:
                        res = await self.redis_client.blpop("threat_alerts:queue", timeout=int(self.batch_interval))
                        if res:
                            batch.append(self.unwrap_item(json.loads(res[1])))
                            while len(batch) < self.batch_size:
                                val = await self.redis_client.lpop("threat_alerts:queue")
                                if val is None:
                                    break
                                batch.append(self.unwrap_item(json.loads(val)))
                    except Exception as e:
                        logger.error(f"Error reading from Redis queue in flusher, dynamically disabling Redis client: {e}")
                        self.redis_client = None
                        
                # If Redis is not used/failed or returned nothing, check in-memory queue
                if not batch:
                    try:
                        item = await asyncio.wait_for(self.queue.get(), timeout=self.batch_interval)
                        if item is not None:
                            batch.append(self.unwrap_item(item))
                            in_memory_count += 1
                    except asyncio.TimeoutError:
                        pass
                        
                    while len(batch) < self.batch_size and not self.queue.empty():
                        try:
                            item = self.queue.get_nowait()
                            if item is not None:
                                batch.append(self.unwrap_item(item))
                                in_memory_count += 1
                        except asyncio.QueueEmpty:
                            break
                            
                if batch:
                    await self._write_batch(batch)
                    for _ in range(in_memory_count):
                        self.queue.task_done()
                        
            except asyncio.CancelledError:
                # Intercept task cancellation on shutdown
                await self._flush_remaining()
                break
            except Exception as e:
                logger.error(f"Error in database batch flusher: {e}")
                await asyncio.sleep(1.0)

    async def _write_batch(self, batch: List[Dict[str, Any]]):
        """Executes bulk insertion for a batch of alerts with retry and DLQ/poison pill routing."""
        if self.pool is None:
            logger.error("No database connection pool available for writing batch.")
            return
            
        query = """
            INSERT INTO threat_alerts (
                time_epoch, src_ip, src_port, dst_ip, dst_port, protocol, 
                bytes_in, bytes_out, l1_anomaly_score, l2_threat_prob, 
                l3_threat_prob, classification, is_anomaly, explanations, model_version
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        """
        
        def format_record(alert):
            explanations_json = json.dumps(alert.get("explanations", []))
            return (
                alert.get("time_epoch"),
                alert.get("src_ip"),
                alert.get("src_port"),
                alert.get("dst_ip"),
                alert.get("dst_port"),
                alert.get("protocol"),
                alert.get("bytes_in"),
                alert.get("bytes_out"),
                alert.get("l1_anomaly_score"),
                alert.get("l2_threat_prob"),
                alert.get("l3_threat_prob"),
                alert.get("classification"),
                alert.get("is_anomaly"),
                explanations_json,
                alert.get("model_version", settings.MODEL_VERSION)
            )

        def extract_alert_metadata(item):
            if isinstance(item, dict) and "_dlq_envelope" in item:
                return item, item["_dlq_envelope"]
            else:
                return item, {
                    "alert": item,
                    "dlq_retry_count": 0,
                    "first_failed_at": None,
                    "last_failed_at": None,
                    "failure_reason": None
                }
            
        alerts_metadata = []
        data = []
        for item in batch:
            inner_alert, meta = extract_alert_metadata(item)
            alerts_metadata.append(meta)
            data.append(format_record(inner_alert))
        
        # Retry logic parameters
        max_retries = settings.REDIS_MAX_RETRIES if settings.USE_REDIS else settings.DB_MAX_RETRIES
        backoff = settings.DB_RETRY_BACKOFF
        
        success = False
        for attempt in range(1, max_retries + 1):
            try:
                async with self.pool.acquire() as conn:
                    await conn.executemany(query, data)
                success = True
                break
            except Exception as e:
                logger.error(f"Failed to execute database batch insert (attempt {attempt}/{max_retries}): {e}")
                if attempt < max_retries:
                    sleep_time = backoff * (2 ** (attempt - 1))
                    await asyncio.sleep(sleep_time)
                else:
                    logger.critical("Batch insert failed after max retries. Isolating corrupt records (poison pills).")
                    
        if not success:
            # Isolate poison pills
            for meta in alerts_metadata:
                inner_alert = meta["alert"]
                record_data = format_record(inner_alert)
                try:
                    async with self.pool.acquire() as conn:
                        await conn.execute(query, *record_data)
                except Exception as ex:
                    logger.critical(f"[DLQ] Poison pill isolated: Failed to write individual alert to DB: {ex}. Alert: {inner_alert}")
                    if settings.USE_REDIS and hasattr(self, "redis_client") and self.redis_client:
                        try:
                            # Check if the retry count has reached/exceeded MAX_DLQ_RETRIES
                            current_retry = meta.get("dlq_retry_count", 0)
                            if current_retry >= settings.MAX_DLQ_RETRIES:
                                logger.critical(f"[DLQ] Alert exceeded max DLQ retries ({settings.MAX_DLQ_RETRIES}). Permanently discarding: {inner_alert}")
                                continue
                                
                            now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                            
                            # Increment retry count
                            meta["dlq_retry_count"] = current_retry + 1
                            
                            # Update envelope metadata
                            if meta.get("first_failed_at") is None:
                                meta["first_failed_at"] = now_str
                                meta["failure_reason"] = str(ex)
                            # Keep first_failed_at and failure_reason if they already existed
                            
                            meta["last_failed_at"] = now_str
                            
                            # Clean internal private keys before routing
                            if isinstance(inner_alert, dict):
                                inner_alert.pop("_dlq_envelope", None)
                            meta["alert"] = inner_alert
                            
                            # Push the envelope to threat_alerts:dlq
                            await self.redis_client.rpush("threat_alerts:dlq", json.dumps(meta))
                            logger.info(f"[DLQ] Successfully routed poison pill alert to Redis DLQ (threat_alerts:dlq). Retry count: {meta['dlq_retry_count']}.")
                        except Exception as redis_ex:
                            logger.error(f"[DLQ] Failed to route alert to Redis DLQ: {redis_ex}")
                    else:
                        logger.error(f"[DLQ] Fallback: Discarded corrupt record due to no Redis client: {inner_alert}")

    async def _flush_remaining(self):
        """Flushes any remaining items from both queues during app shutdown."""
        batch = []
        
        # Flush Redis queue first
        if settings.USE_REDIS and self.redis_client:
            try:
                while len(batch) < self.batch_size:
                    val = await self.redis_client.lpop("threat_alerts:queue")
                    if val is None:
                        break
                    batch.append(self.unwrap_item(json.loads(val)))
            except Exception as e:
                logger.error(f"Error flushing Redis queue on shutdown: {e}")
                
        # Flush in-memory queue
        while not self.queue.empty():
            try:
                item = self.queue.get_nowait()
                if item is not None:
                    batch.append(self.unwrap_item(item))
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break
                
        if batch:
            logger.info(f"Flushing {len(batch)} remaining alerts on shutdown.")
            await self._write_batch(batch)


    async def log_stats(self, total_processed: int, total_alerts: int, l1_dropped: int, l2_alerts: int, l3_alerts: int):
        """Asynchronously logs current runtime pipe stats."""
        if self.pool is None:
            await self.connect()
            
        query = """
            INSERT INTO threat_stats (
                total_processed, total_alerts, l1_dropped, l2_alerts, l3_alerts
            ) VALUES ($1, $2, $3, $4, $5)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(query, total_processed, total_alerts, l1_dropped, l2_alerts, l3_alerts)

    async def log_model_config(self, l1_threshold: float, feature_names: List[str], l3_window_size: int):
        """Logs active model thresholds and features list to database metadata."""
        if self.pool is None:
            await self.connect()
            
        query = """
            INSERT INTO model_configurations (
                l1_threshold, l2_feature_names, l3_window_size
            ) VALUES ($1, $2, $3)
        """
        feature_names_str = ",".join(feature_names)
        async with self.pool.acquire() as conn:
            await conn.execute(query, l1_threshold, feature_names_str, l3_window_size)

    async def requeue_from_dlq(self) -> Dict[str, Any]:
        """
        Pops up to DLQ_REQUEUE_BATCH_SIZE envelopes from threat_alerts:dlq,
        validates them, increments the retry counter, and pushes back to threat_alerts:queue.
        Permanently discards if retries exceed MAX_DLQ_RETRIES or validation fails.
        """
        from src.api.schemas import OCSFNetworkTrafficSchema
        
        result = {
            "processed": 0,
            "requeued": 0,
            "discarded_max_retries": 0,
            "discarded_validation_failed": 0,
            "errors": []
        }
        
        if not (settings.USE_REDIS and self.redis_client):
            logger.warning("[DLQ] Attempted to requeue from DLQ, but Redis is not available.")
            return result
            
        try:
            batch_size = settings.DLQ_REQUEUE_BATCH_SIZE
            for _ in range(batch_size):
                # Pop from the left of the DLQ (FIFO)
                val = await self.redis_client.lpop("threat_alerts:dlq")
                if val is None:
                    break
                
                result["processed"] += 1
                try:
                    envelope = json.loads(val)
                except Exception as e:
                    logger.error(f"[DLQ] Failed to parse DLQ envelope JSON: {e}")
                    result["discarded_validation_failed"] += 1
                    continue
                
                # Check envelope structure
                if not isinstance(envelope, dict) or "alert" not in envelope:
                    logger.error(f"[DLQ] Invalid DLQ envelope format: {envelope}")
                    result["discarded_validation_failed"] += 1
                    continue
                
                inner_alert = envelope.get("alert")
                dlq_retry_count = envelope.get("dlq_retry_count", 0)
                
                # Validate inner alert via Pydantic schema
                try:
                    OCSFNetworkTrafficSchema.model_validate(inner_alert)
                except Exception as val_err:
                    logger.error(f"[DLQ] Validation failed for alert: {val_err}. Alert: {inner_alert}")
                    result["discarded_validation_failed"] += 1
                    continue
                
                # Check max retry count limit
                if dlq_retry_count >= settings.MAX_DLQ_RETRIES:
                    logger.critical(f"[DLQ] Alert exceeded max DLQ retries ({settings.MAX_DLQ_RETRIES}). Permanently discarding: {inner_alert}")
                    result["discarded_max_retries"] += 1
                    continue
                
                # Increment retry counter
                envelope["dlq_retry_count"] = dlq_retry_count + 1
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                envelope["last_failed_at"] = now_str
                
                # Push back to the main queue
                await self.redis_client.rpush("threat_alerts:queue", json.dumps(envelope))
                result["requeued"] += 1
                logger.info(f"[DLQ] Requeued alert from DLQ (retry attempt {envelope['dlq_retry_count']}/{settings.MAX_DLQ_RETRIES}).")
                
        except Exception as e:
            logger.error(f"[DLQ] Error during requeue operation: {e}")
            result["errors"].append(str(e))
            
        return result

    async def get_alerts(self, limit: int = 50, offset: int = 0, is_anomaly: bool = None, classification: str = None) -> List[Dict[str, Any]]:
        """Retrieves a list of recent alerts from the database."""
        if self.pool is None:
            await self.connect()
        
        query = "SELECT * FROM threat_alerts"
        conditions = []
        params = []
        
        if is_anomaly is not None:
            params.append(is_anomaly)
            conditions.append(f"is_anomaly = ${len(params)}")
            
        if classification is not None:
            params.append(classification)
            conditions.append(f"classification = ${len(params)}")
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        params.append(limit)
        query += f" ORDER BY timestamp DESC LIMIT ${len(params)}"
        params.append(offset)
        query += f" OFFSET ${len(params)}"
        
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []

    async def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a single alert detail by its ID."""
        if self.pool is None:
            await self.connect()
            
        query = "SELECT * FROM threat_alerts WHERE id = $1"
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query, alert_id)
                if row:
                    res = dict(row)
                    if "explanations" in res and res["explanations"]:
                        try:
                            res["explanations"] = json.loads(res["explanations"])
                        except Exception:
                            pass
                    return res
                return None
        except Exception as e:
            logger.error(f"Failed to fetch alert by ID {alert_id}: {e}")
            return None

    async def get_aggregated_stats(self) -> Dict[str, Any]:
        """Gathers summary counters and latest stats from the database."""
        if self.pool is None:
            await self.connect()
            
        stats_query = "SELECT * FROM threat_stats ORDER BY timestamp DESC LIMIT 1"
        alerts_count_query = "SELECT COUNT(*) FROM threat_alerts"
        anomaly_count_query = "SELECT COUNT(*) FROM threat_alerts WHERE is_anomaly = TRUE"
        
        res = {
            "total_processed": 0,
            "total_alerts": 0,
            "l1_dropped": 0,
            "l2_alerts": 0,
            "l3_alerts": 0,
            "anomaly_rate": 0.0
        }
        
        try:
            async with self.pool.acquire() as conn:
                stats_row = await conn.fetchrow(stats_query)
                total_alerts = await conn.fetchval(alerts_count_query) or 0
                anomalies = await conn.fetchval(anomaly_count_query) or 0
                
                if stats_row:
                    res["total_processed"] = stats_row.get("total_processed") or 0
                    res["total_alerts"] = stats_row.get("total_alerts") or 0
                    res["l1_dropped"] = stats_row.get("l1_dropped") or 0
                    res["l2_alerts"] = stats_row.get("l2_alerts") or 0
                    res["l3_alerts"] = stats_row.get("l3_alerts") or 0
                else:
                    res["total_alerts"] = total_alerts
                    
                if res["total_processed"] > 0:
                    res["anomaly_rate"] = float(anomalies) / float(res["total_processed"])
                elif total_alerts > 0:
                    res["anomaly_rate"] = 1.0
        except Exception as e:
            logger.error(f"Failed to fetch aggregated stats: {e}")
            
        return res

    async def get_health(self) -> bool:
        """Verifies database operational health state by executing a query check."""
        if self.pool is None:
            return False
        try:
            async with self.pool.acquire() as conn:
                res = await asyncio.wait_for(conn.fetchval("SELECT 1"), timeout=1.0)
                return res == 1
        except Exception as e:
            logger.error(f"Health query check failed: {e}")
            return False

# Global single instance
db = DatabaseHelper()
