# Step-by-Step Execution Guide: Threat Detection Pipeline

Follow these instructions to set up, train, deploy, and verify the OCSF-based Hybrid Threat Detection Pipeline.

---

## 1. Prerequisites & Environment Setup

Make sure you have **Python 3.10+** installed on your system.

### Install Dependencies locally:
```bash
# Install the core project dependencies
pip install -r requirements.txt
```

---

## 2. Train the Machine Learning Layers

Before starting the web services, you must train the contextual Random Forest (Layer 2) and sequential LSTM (Layer 3) models. The training script will ingest the local sample datasets, map them to OCSF schemas, fit standardizers, and serialize the models to the `./data/models/` directory.

```bash
python -m src.models.train
```

*This will output standard classification reports and save confusion matrix plots to `./outputs/`.*

---

## 3. Start the FastAPI API Server Locally

Start the FastAPI application on your system:

```bash
python -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

*This runs the API backend locally on port `8000`. Database initialization will fall back gracefully to memory if no local database is running.*

---

## 4. Run Verification Tests

Run the test suite to verify the pipeline's algorithmic layers, database batching queues, and metrics.

### Run Production Integration Tests:
```bash
python tests/test_production.py
```

### Run Layer Algorithmic Tests:
```bash
python tests/test_layer1.py
python tests/test_layer2.py
python tests/test_layer3.py
```

---

## 5. Simulate Ingestion Traffic

Use the queue-based async log simulator to stream test records from the raw directories and post them to the API endpoint.

```bash
# Streams 200 records from the UNSW dataset to the API
python -m src.ingestion.simulator --dataset unsw --limit 200 --url http://localhost:8000/api/v1/detect --delay 0.05
```

---

## 6. Monitor Pipeline Performance & Health

Once traffic is streaming, query the monitoring endpoints in your browser or via curl:

### Health Check:
```bash
curl http://localhost:8000/api/v1/health
```

### Prometheus Performance Metrics:
Query the `/metrics` endpoint to view event counts, model layer inference latencies, database batching queue status, and connection health:
```bash
curl http://localhost:8000/metrics
```
