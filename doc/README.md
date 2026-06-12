# OCSF-Based Hybrid Threat Detection Pipeline

A production-ready, modular, high-throughput threat detection pipeline implementing a **3-Layer Tiered Defense Architecture** utilizing the Open Cybersecurity Schema Framework (OCSF) model.

The system ingests security events, standardizes columns to OCSF `network_traffic` (Class ID 4001) metadata schema, filters traffic using low-overhead statistics, and runs contextual classification (with SHAP feature attributions) and sequential deep learning (PyTorch LSTM) to detect Advanced Persistent Threats (APTs) and lateral movements.

---

## Folder Structure

```
task2/
├── config/
│   ├── __init__.py
│   └── settings.py              # Configuration thresholds & DB URLs
├── src/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI endpoints (/detect, /health)
│   │   └── schemas.py           # Pydantic schemas for input validation
│   ├── database/
│   │   ├── __init__.py
│   │   └── connection.py        # Asyncpg database connector
│   ├── features/
│   │   ├── __init__.py
│   │   └── pipeline.py          # Feature extraction & streaming logic
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── mapper.py            # OCSF column normalizer
│   │   └── simulator.py         # Async simulator client (mock Kafka/queue)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── estimators.py        # Layer 1, Layer 2 (RF/SHAP) & Layer 3 (LSTM) classes
│   │   └── train.py             # Offline training pipeline
├── README.md                    # Setup and execution guide
└── requirements.txt             # Python project dependencies
```

---

## 3-Layer Tiered Architecture

1. **Layer 1: Volumetric Statistical Filter (Triage)**
   - Calculates instantaneous flow rates to compute a rolling Z-Score.
   - Computes an Exponentially Weighted Moving Average (EWMA) of flow byte volumes.
   - Measures Shannon Entropy over destination ports in the current sliding window.
   - Drops benign background traffic immediately if the combined anomaly score is below the threshold, saving downstream CPU cycles.

2. **Layer 2: Contextual Random Forest Classifier**
   - Evaluates triaged events using a Scikit-Learn `RandomForestClassifier` (trained with balanced class weights).
   - Generates local feature attribution values via `shap.TreeExplainer` when a threat is identified.
   - Returns attributions under the key `explanations` as a list of `{feature_name: str, shap_value: float}`.

3. **Layer 3: Chronological Sequential LSTM**
   - Evaluates a sliding window of the last 10 sequential events per host IP.
   - Processes the sequential transitions of OCSF flow characteristics using a PyTorch LSTM model.
   - Optimized for CPU execution fallback (`hidden_size=64`, `num_layers=2`).

---

## Setup & Running Guide

### 1. Requirements Installation (Local Run)
Install required python libraries:
```bash
pip install -r requirements.txt
```

### 2. Run Offline Training
Before launching the service, train the machine learning layers on the local datasets (`./data/cic/`, `./data/unsw/`, `./data/cse/`):
```bash
python -m src.models.train
```
This maps raw columns to OCSF format, extracts features, fits the RandomForest model & SHAP explainer, trains the LSTM sequence net, and exports serialized weights to `./data/models/`.

### 3. Start the FastAPI API Server Locally
Start the FastAPI server using Uvicorn:
```bash
python -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```
This runs the API locally on port 8000.

---

## Ingesting & Verifying the Pipeline

### Health Endpoint Check
Query the service health check endpoint:
```bash
curl http://localhost:8000/api/v1/health
```
A successful response indicates:
```json
{
  "status": "healthy",
  "components": {
    "database": "healthy",
    "pipeline": "healthy"
  }
}
```

### Stream Simulation Test
Run the queue-based async log simulator to stream test records from the raw directories and post them to the API:
```bash
# Streams 200 records from the UNSW dataset
python -m src.ingestion.simulator --dataset unsw --limit 200 --url http://localhost:8000/api/v1/detect --delay 0.05
```
You will see triage filter evaluations and threat alerts with corresponding SHAP reasons output to the terminal in real time.
