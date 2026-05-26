import pickle
from fastapi import FastAPI, HTTPException, status
from contextlib import asynccontextmanager

from config.settings import settings
from src.api.schemas import OCSFNetworkTrafficSchema
from src.database.connection import db
from src.features.pipeline import StreamingFeaturePipeline
from src.models.estimators import (
    VolumetricStatisticalFilter,
    ContextualClassifier,
    Layer3LSTMTracker
)

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages lifespan events for startup and shutdown hooks."""
    global feature_pipeline, l1_filter, l2_classifier, l3_lstm, scaler
    
    # 1. Initialize DB pool and tables
    try:
        await db.initialize_db()
    except Exception as e:
        print(f"Warning: Database initialization failed: {e}. Running API without DB backend.")
        
    # 2. Instantiate stateful pipeline
    feature_pipeline = StreamingFeaturePipeline(window_size=settings.L1_ROLLING_WINDOW_SIZE)
    l1_filter = VolumetricStatisticalFilter()
    
    # 3. Load ML Estimators
    # Load feature names from metadata if available
    feature_names = feature_pipeline.feature_names
    try:
        with open(settings.MODEL_METADATA_PATH, "rb") as f:
            feature_names = pickle.load(f)
    except Exception:
         pass
         
    l2_classifier = ContextualClassifier(feature_names=feature_names)
    l3_lstm = Layer3LSTMTracker()
    
    # Load StandardScaler
    try:
        with open(settings.SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        print("Successfully loaded StandardScaler from disk.")
    except Exception as e:
        print(f"Warning: StandardScaler failed to load: {e}")
    
    # 4. Log active model configurations
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
    
    # Clean up database resources
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
    l2_prediction, l2_probability = l2_classifier.predict(scaled_vector)
    
    passed_l2 = (l2_prediction == 1) or (l2_probability >= 0.5)
    
    if not passed_l2:
        # Event is dropped as benign baseline background activity at Layer 2
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
    explanations = l2_classifier.explain(scaled_vector)
        
    # ----------------------------------------------------
    # LAYER 3: Chronological Sequential LSTM
    # ----------------------------------------------------
    l3_probability = l3_lstm.evaluate_ip_sequence(src_ip, scaled_vector)
    
    if l3_probability >= 0.5:
        stats["l3_alerts"] += 1
        
    # Overall Intrusion/Threat decision logic
    threat_detected = True
    
    classification = event_dict.get("enrichments", {}).get("label", "Threat-Activity")
    if classification.lower() == "benign":
        classification = "Threat-Anomaly"
    if l3_probability >= 0.5:
        classification = "Threat-Sequential-APT"

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
        "explanations": explanations
    }
    
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
            print(f"Database logging failure: {e}")
            
    return {
        "threat_detected": threat_detected,
        "classification": classification,
        "layer_reached": 3,
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
    
    status_code = status.HTTP_200_OK if db_healthy and pipeline_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return {
        "status": "healthy" if status_code == status.HTTP_200_OK else "degraded",
        "components": {
            "database": "healthy" if db_healthy else "unhealthy",
            "pipeline": "healthy" if pipeline_healthy else "unhealthy"
        }
    }
