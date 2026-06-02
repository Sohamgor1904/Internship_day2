import asyncio
import asyncpg
import json
import logging
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
        """Pushes a threat alert record to the in-memory queue for background batch writing."""
        if "model_version" not in alert:
            alert["model_version"] = settings.MODEL_VERSION
        await self.queue.put(alert)

    async def _batch_flusher(self):
        """Background worker loop that aggregates alerts and writes them to database in batches."""
        while True:
            try:
                batch = []
                
                # Try to get the first item from the queue with a timeout
                try:
                    item = await asyncio.wait_for(self.queue.get(), timeout=self.batch_interval)
                    if item is not None:
                        batch.append(item)
                except asyncio.TimeoutError:
                    pass
                    
                # Dequeue remaining items up to batch size
                while len(batch) < self.batch_size and not self.queue.empty():
                    try:
                        item = self.queue.get_nowait()
                        if item is not None:
                            batch.append(item)
                    except asyncio.QueueEmpty:
                        break
                        
                if batch:
                    await self._write_batch(batch)
                    for _ in range(len(batch)):
                        self.queue.task_done()
                        
            except asyncio.CancelledError:
                # Intercept task cancellation on shutdown
                await self._flush_remaining()
                break
            except Exception as e:
                logger.error(f"Error in database batch flusher: {e}")
                await asyncio.sleep(1.0)

    async def _write_batch(self, batch: List[Dict[str, Any]]):
        """Executes bulk insertion for a batch of alerts."""
        if self.pool is None:
            return
            
        query = """
            INSERT INTO threat_alerts (
                time_epoch, src_ip, src_port, dst_ip, dst_port, protocol, 
                bytes_in, bytes_out, l1_anomaly_score, l2_threat_prob, 
                l3_threat_prob, classification, is_anomaly, explanations, model_version
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        """
        
        data = []
        for alert in batch:
            explanations_json = json.dumps(alert.get("explanations", []))
            data.append((
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
            ))
            
        try:
            async with self.pool.acquire() as conn:
                await conn.executemany(query, data)
        except Exception as e:
            logger.error(f"Failed to execute database batch insert: {e}")

    async def _flush_remaining(self):
        """Flushes any remaining items from the queue during app shutdown."""
        batch = []
        while not self.queue.empty():
            try:
                item = self.queue.get_nowait()
                if item is not None:
                    batch.append(item)
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
