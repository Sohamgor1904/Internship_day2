import pickle
import time
import json
import logging
from fastapi import FastAPI, HTTPException, status, Query
from fastapi.responses import PlainTextResponse
from contextlib import asynccontextmanager
from typing import Optional

from config.settings import settings
from src.api.schemas import OCSFNetworkTrafficSchema
from src.database.connection import db
from src.features.pipeline import StreamingFeaturePipeline
from src.models.estimators import (
    VolumetricStatisticalFilter,
    ContextualClassifier,
    Layer3LSTMTracker
)

# Set up logger
logger = logging.getLogger("threat_detection.api")

# JSON log formatter helper
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logging():
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        
    handler = logging.StreamHandler()
    if settings.LOG_FORMAT == "json":
        handler.setFormatter(JsonFormatter("%(asctime)s"))
    else:
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(name)s: %(message)s"))
        
    root.addHandler(handler)
    root.setLevel(logging.INFO if not settings.DEBUG else logging.DEBUG)

# Global variables for stateful streaming pipeline & models
feature_pipeline = None
l1_filter = None
l2_classifier = None
l3_lstm = None
scaler = None

# Statistics counters
stats = {
    "total_processed": 0,
    "total_alerts": 0,
    "l1_dropped": 0,
    "l2_alerts": 0,
    "l3_alerts": 0
}

# Prometheus metrics data
metrics_data = {
    "processed_events": {
        ("1", "dropped"): 0,
        ("2", "dropped"): 0,
        ("3", "benign"): 0,
        ("3", "threat"): 0,
    },
    "inference_latency_sum": {
        "rf": 0.0,
        "shap": 0.0,
        "lstm": 0.0
    },
    "inference_latency_count": {
        "rf": 0,
        "shap": 0,
        "lstm": 0
    }
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages lifespan events for startup and shutdown hooks."""
    global feature_pipeline, l1_filter, l2_classifier, l3_lstm, scaler
    
    # 1. Setup structured logging
    setup_logging()
    logger.info("Initializing API application lifespan setup.")
    
    # 2. Initialize DB pool and tables asynchronously in the background (non-blocking startup)
    import asyncio
    async def init_db_bg():
        try:
            await db.initialize_db()
        except Exception as e:
            logger.warning(f"Database initialization failed: {e}. Running API without DB backend.")
    asyncio.create_task(init_db_bg())
        
    # 3. Instantiate stateful pipeline
    feature_pipeline = StreamingFeaturePipeline(window_size=settings.L1_ROLLING_WINDOW_SIZE)
    l1_filter = VolumetricStatisticalFilter()
    
    # 4. Load ML Estimators
    # Load feature names from metadata if available
    feature_names = feature_pipeline.feature_names
    try:
        with open(settings.MODEL_METADATA_PATH, "rb") as f:
            feature_names = pickle.load(f)
    except Exception:
         pass
         
    l2_classifier = ContextualClassifier(feature_names=feature_names)
    l3_lstm = Layer3LSTMTracker()
    
    # Initialize Redis Client and Connection Pool
    if settings.USE_REDIS:
        try:
            import redis.asyncio as aioredis
            app.state.redis_pool = aioredis.ConnectionPool.from_url(
                settings.REDIS_URL,
                max_connections=50,
                decode_responses=True,
                socket_timeout=settings.REDIS_TIMEOUT
            )
            app.state.redis_client = aioredis.Redis(connection_pool=app.state.redis_pool)
            
            # Ping Redis to verify connection before continuing
            await app.state.redis_client.ping()
            
            # Pass Redis Client to feature pipeline, LSTM model tracker, and DB helper
            feature_pipeline.redis_client = app.state.redis_client
            l3_lstm.redis_client = app.state.redis_client
            db.redis_client = app.state.redis_client
            logger.info("Successfully established connection to Redis pool and verified with ping.")
            # Trigger startup DLQ requeue task
            async def run_startup_dlq_requeue():
                logger.info("[DLQ] Running startup DLQ requeue processing...")
                try:
                    res = await db.requeue_from_dlq()
                    logger.info(f"[DLQ] Startup DLQ requeue finished. Processed: {res['processed']}, Requeued: {res['requeued']}, Discarded Max Retries: {res['discarded_max_retries']}, Discarded Validation Failed: {res['discarded_validation_failed']}")
                except Exception as e:
                    logger.error(f"[DLQ] Error during startup DLQ requeue task: {e}")
            import asyncio
            asyncio.create_task(run_startup_dlq_requeue())
        except Exception as e:
            logger.critical(f"Failed to initialize Redis pool: {e}. Running with in-memory fallbacks.")
            app.state.redis_client = None
            app.state.redis_pool = None
            feature_pipeline.redis_client = None
            l3_lstm.redis_client = None
            db.redis_client = None
    else:
        app.state.redis_client = None
        app.state.redis_pool = None
        
    # Load StandardScaler
    try:
        with open(settings.SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        logger.info("Successfully loaded StandardScaler from disk.")
    except Exception as e:
        logger.warning(f"StandardScaler failed to load: {e}")
    
    # 5. Log active model configurations
    try:
        if db.pool:
            await db.log_model_config(
                l1_threshold=settings.L1_ANOMALY_THRESHOLD,
                feature_names=feature_names,
                l3_window_size=settings.L3_WINDOW_SIZE
            )
    except Exception:
        pass

    yield
    
    # Clean up Redis pool
    if hasattr(app.state, "redis_client") and app.state.redis_client:
        await app.state.redis_client.close()
    if hasattr(app.state, "redis_pool") and app.state.redis_pool:
        await app.state.redis_pool.disconnect()
    
    # Clean up database resources
    logger.info("Shutting down API application, cleaning up pool.")
    await db.disconnect()

# Initialize FastAPI application
app = FastAPI(
    title="Hybrid Threat Detection Pipeline API",
    version="1.1.0",
    description="Corporate tier-based streaming log filter utilizing OCSF metadata structures.",
    lifespan=lifespan
)

@app.post("/api/v1/detect", status_code=status.HTTP_200_OK)
async def detect_threat(record: OCSFNetworkTrafficSchema):
    """
    Ingests an OCSF record, flows it through the 3 tiered defense layers,
    and returns threat classification evaluation.
    """
    global feature_pipeline, l1_filter, l2_classifier, l3_lstm
    
    if feature_pipeline is None or l1_filter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pipeline models are not fully initialized."
        )

    stats["total_processed"] += 1
    event_dict = record.model_dump()
    
    # Backpressure check
    if settings.USE_REDIS and hasattr(app.state, "redis_client") and app.state.redis_client:
        try:
            q_len = await app.state.redis_client.llen("threat_alerts:queue")
            if q_len > settings.REDIS_QUEUE_MAX_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Ingestion rate exceeds processing limits. Queue is full."
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error checking queue backpressure, dynamically disabling Redis client: {e}")
            app.state.redis_client = None
            if hasattr(db, "redis_client"):
                db.redis_client = None
            
    # Extract details for Layer 1 Triage
    time_ms = event_dict.get("time", 0)
    src_ip = event_dict.get("src_endpoint", {}).get("ip", "127.0.0.1")
    src_port = event_dict.get("src_endpoint", {}).get("port", 0)
    dst_ip = event_dict.get("dst_endpoint", {}).get("ip", "127.0.0.1")
    dst_port = event_dict.get("dst_endpoint", {}).get("port", 0)
    
    traffic = event_dict.get("traffic", {})
    bytes_in = traffic.get("bytes_in", 0)
    bytes_out = traffic.get("bytes_out", 0)
    bytes_total = bytes_in + bytes_out
    
    conn = event_dict.get("connection_info", {})
    protocol_num = conn.get("protocol_num", 6)
    protocol_name = conn.get("protocol_name", "tcp")
    
    # Update state and extract numeric feature vector for the stream
    if settings.USE_REDIS and hasattr(app.state, "redis_client") and app.state.redis_client:
        feature_vector = await feature_pipeline.extract_features_async(event_dict, update_state=True)
    else:
        feature_vector = feature_pipeline.extract_features(event_dict, update_state=True)
    delta_t = float(feature_vector[1])  # Delta time position
    
    # ----------------------------------------------------
    # LAYER 1: Volumetric Statistical Filter
    # ----------------------------------------------------
    passed_triage, anomaly_score_l1 = l1_filter.update(
        delta_t=delta_t,
        bytes_total=bytes_total,
        dst_port=dst_port,
        protocol=protocol_num
    )
    
    if not passed_triage:
        # Event is dropped as benign baseline background activity
        stats["l1_dropped"] += 1
        metrics_data["processed_events"][("1", "dropped")] += 1
        
        # Log stats periodically
        if stats["total_processed"] % 100 == 0 and db.pool:
            try:
                await db.log_stats(
                    stats["total_processed"], stats["total_alerts"],
                    stats["l1_dropped"], stats["l2_alerts"], stats["l3_alerts"]
                )
            except Exception:
                pass
                
        return {
            "threat_detected": False,
            "classification": "Benign",
            "layer_reached": 1,
            "model_version": settings.MODEL_VERSION,
            "layer1": {
                "passed_triage": False,
                "anomaly_score": anomaly_score_l1
            },
            "layer2": {
                "prediction": 0,
                "threat_probability": 0.0,
                "explanations": []
            },
            "layer3": {
                "threat_probability": 0.0
            }
        }
        
    # Scale feature vector if scaler is loaded
    scaled_vector = feature_vector
    if scaler is not None:
        scaled_vector = scaler.transform(feature_vector.reshape(1, -1))[0]
        
    # ----------------------------------------------------
    # LAYER 2: Contextual Random Forest Classifier
    # ----------------------------------------------------
    rf_start = time.perf_counter()
    l2_prediction, l2_probability = l2_classifier.predict(scaled_vector)
    rf_duration = time.perf_counter() - rf_start
    metrics_data["inference_latency_sum"]["rf"] += rf_duration
    metrics_data["inference_latency_count"]["rf"] += 1
    
    passed_l2 = (l2_prediction == 1) or (l2_probability >= 0.5)
    
    if not passed_l2:
        # Event is dropped as benign baseline background activity at Layer 2
        metrics_data["processed_events"][("2", "dropped")] += 1
        # Log stats periodically
        if stats["total_processed"] % 100 == 0 and db.pool:
            try:
                await db.log_stats(
                    stats["total_processed"], stats["total_alerts"],
                    stats["l1_dropped"], stats["l2_alerts"], stats["l3_alerts"]
                )
            except Exception:
                pass
                
        return {
            "threat_detected": False,
            "classification": "Benign",
            "layer_reached": 2,
            "model_version": settings.MODEL_VERSION,
            "layer1": {
                "passed_triage": True,
                "anomaly_score": anomaly_score_l1
            },
            "layer2": {
                "prediction": l2_prediction,
                "threat_probability": l2_probability,
                "explanations": []
            },
            "layer3": {
                "threat_probability": 0.0
            }
        }
        
    # If passed Layer 2, compute SHAP attributions (since an alert is triggered)
    stats["l2_alerts"] += 1
    shap_start = time.perf_counter()
    explanations = l2_classifier.explain(scaled_vector)
    shap_duration = time.perf_counter() - shap_start
    metrics_data["inference_latency_sum"]["shap"] += shap_duration
    metrics_data["inference_latency_count"]["shap"] += 1
        
    # ----------------------------------------------------
    # LAYER 3: Chronological Sequential LSTM
    # ----------------------------------------------------
    lstm_start = time.perf_counter()
    if settings.USE_REDIS and hasattr(app.state, "redis_client") and app.state.redis_client:
        l3_probability = await l3_lstm.evaluate_ip_sequence_async(src_ip, scaled_vector)
    else:
        l3_probability = l3_lstm.evaluate_ip_sequence(src_ip, scaled_vector)
    lstm_duration = time.perf_counter() - lstm_start
    metrics_data["inference_latency_sum"]["lstm"] += lstm_duration
    metrics_data["inference_latency_count"]["lstm"] += 1
    
    if l3_probability >= 0.5:
        stats["l3_alerts"] += 1
        
    # Overall Intrusion/Threat decision logic
    threat_detected = True
    
    classification = event_dict.get("enrichments", {}).get("label", "Threat-Activity")
    if classification.lower() == "benign":
        classification = "Threat-Anomaly"
    if l3_probability >= 0.5:
        classification = "Threat-Sequential-APT"

    # Update processed event metric counts
    if threat_detected:
        metrics_data["processed_events"][("3", "threat")] += 1
    else:
        metrics_data["processed_events"][("3", "benign")] += 1

    # Async logging of alerts to database
    alert_log = {
        "time_epoch": time_ms,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol_name,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "l1_anomaly_score": anomaly_score_l1,
        "l2_threat_prob": l2_probability,
        "l3_threat_prob": l3_probability,
        "classification": classification,
        "is_anomaly": threat_detected,
        "explanations": explanations,
        "model_version": settings.MODEL_VERSION
    }
    
    logger.info(f"Threat detected: {classification} from src_ip={src_ip}. L2 Prob={l2_probability:.2f}, L3 Prob={l3_probability:.2f}")

    if db.pool:
        try:
            await db.log_alert(alert_log)
            # Log metrics updates
            if stats["total_processed"] % 10 == 0:
                await db.log_stats(
                    stats["total_processed"], stats["total_alerts"],
                    stats["l1_dropped"], stats["l2_alerts"], stats["l3_alerts"]
                )
        except Exception as e:
            logger.error(f"Database logging failure: {e}")
            
    return {
        "threat_detected": threat_detected,
        "classification": classification,
        "layer_reached": 3,
        "model_version": settings.MODEL_VERSION,
        "layer1": {
            "passed_triage": True,
            "anomaly_score": anomaly_score_l1
        },
        "layer2": {
            "prediction": l2_prediction,
            "threat_probability": l2_probability,
            "explanations": explanations
        },
        "layer3": {
            "threat_probability": l3_probability
        }
    }

@app.post("/api/v1/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_log(record: OCSFNetworkTrafficSchema):
    """
    Dedicated high-throughput endpoint to ingest raw OCSF logs.
    Pushes the log immediately to the database queue asynchronously and returns.
    """
    global stats
    stats["total_processed"] += 1
    event_dict = record.model_dump()

    # Backpressure check
    if settings.USE_REDIS and hasattr(app.state, "redis_client") and app.state.redis_client:
        try:
            q_len = await app.state.redis_client.llen("threat_alerts:queue")
            if q_len > settings.REDIS_QUEUE_MAX_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Ingestion rate exceeds processing limits. Queue is full."
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error checking queue backpressure, dynamically disabling Redis client: {e}")
            app.state.redis_client = None
            if hasattr(db, "redis_client"):
                db.redis_client = None
    
    # Extract details for database logging
    time_ms = event_dict.get("time", 0)
    src_ip = event_dict.get("src_endpoint", {}).get("ip", "127.0.0.1")
    src_port = event_dict.get("src_endpoint", {}).get("port", 0)
    dst_ip = event_dict.get("dst_endpoint", {}).get("ip", "127.0.0.1")
    dst_port = event_dict.get("dst_endpoint", {}).get("port", 0)
    
    traffic = event_dict.get("traffic", {})
    bytes_in = traffic.get("bytes_in", 0)
    bytes_out = traffic.get("bytes_out", 0)
    
    conn = event_dict.get("connection_info", {})
    protocol_name = conn.get("protocol_name", "tcp")
    
    # Log the ingested raw event directly to the database batch queue
    if db.pool:
        try:
            await db.log_alert({
                "time_epoch": time_ms,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol_name,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "l1_anomaly_score": 0.0,
                "l2_threat_prob": 0.0,
                "l3_threat_prob": 0.0,
                "classification": "Ingested-Raw-Log",
                "is_anomaly": False,
                "explanations": [],
                "model_version": settings.MODEL_VERSION
            })
        except Exception as e:
            logger.error(f"Failed to queue ingested log: {e}")

    return {
        "status": "ingested",
        "message": "Log queued for batch database storage successfully",
        "time": time_ms
    }

@app.get("/api/v1/health")
async def health_check():
    """Verifies operational status of the service models and database backend."""
    global l2_classifier, l3_lstm
    
    db_healthy = await db.get_health()
    
    pipeline_healthy = (
        l2_classifier is not None and 
        l2_classifier.model is not None and 
        l3_lstm is not None and 
        l3_lstm.model is not None
    )
    
    redis_healthy = False
    if settings.USE_REDIS and hasattr(app.state, "redis_client") and app.state.redis_client:
        try:
            redis_healthy = await app.state.redis_client.ping()
        except Exception:
            redis_healthy = False
            logger.error("Redis health check ping failed, dynamically disabling Redis client.")
            app.state.redis_client = None
            if hasattr(db, "redis_client"):
                db.redis_client = None
    elif not settings.USE_REDIS:
        redis_healthy = True
        
    status_code = status.HTTP_200_OK if (db_healthy and pipeline_healthy and redis_healthy) else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return {
        "status": "healthy" if status_code == status.HTTP_200_OK else "degraded",
        "components": {
            "database": "healthy" if db_healthy else "unhealthy",
            "pipeline": "healthy" if pipeline_healthy else "unhealthy",
            "redis": "healthy" if redis_healthy else "unhealthy"
        }
    }

@app.get("/metrics")
async def prometheus_metrics():
    """Exposes threat detection performance metrics formatted for Prometheus scrapers."""
    lines = []
    
    lines.append("# HELP threat_detector_processed_events_total Total number of security events processed.")
    lines.append("# TYPE threat_detector_processed_events_total counter")
    for (layer, decision), val in metrics_data["processed_events"].items():
        lines.append(f'threat_detector_processed_events_total{{layer="{layer}",decision="{decision}"}} {val}')
        
    lines.append("# HELP threat_detector_inference_latency_seconds_sum Sum of ML models execution durations.")
    lines.append("# TYPE threat_detector_inference_latency_seconds_sum gauge")
    for model, val in metrics_data["inference_latency_sum"].items():
        lines.append(f'threat_detector_inference_latency_seconds_sum{{model="{model}"}} {val}')
        
    lines.append("# HELP threat_detector_inference_latency_seconds_count Count of ML model inferences.")
    lines.append("# TYPE threat_detector_inference_latency_seconds_count gauge")
    for model, val in metrics_data["inference_latency_count"].items():
        lines.append(f'threat_detector_inference_latency_seconds_count{{model="{model}"}} {val}')
        
    lines.append("# HELP threat_detector_database_batch_queue_size Buffered DB alerts queue size.")
    lines.append("# TYPE threat_detector_database_batch_queue_size gauge")
    if settings.USE_REDIS and hasattr(app.state, "redis_client") and app.state.redis_client:
        try:
            qsize = await app.state.redis_client.llen("threat_alerts:queue")
        except Exception as e:
            logger.error(f"Error reading from Redis queue size, dynamically disabling Redis client: {e}")
            app.state.redis_client = None
            if hasattr(db, "redis_client"):
                db.redis_client = None
            qsize = db.queue.qsize() if db.queue else 0
    else:
        qsize = db.queue.qsize() if db.queue else 0
    lines.append(f"threat_detector_database_batch_queue_size {qsize}")
    
    lines.append("# HELP threat_detector_database_healthy Operational database connection check.")
    lines.append("# TYPE threat_detector_database_healthy gauge")
    db_healthy = await db.get_health()
    lines.append(f"threat_detector_database_healthy {1 if db_healthy else 0}")
    
    return PlainTextResponse("\n".join(lines) + "\n")


