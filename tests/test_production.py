"""
Production Pipeline Upgrades Test Suite
Run from task2/ root directory:
    python tests/test_production.py
"""

import sys
import os
import asyncio
import time
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings
from src.database.connection import db
from src.api.main import metrics_data, app
from fastapi.testclient import TestClient

print("\n" + "="*50)
print("TESTING PRODUCTION-READY INFRASTRUCTURE UPGRADES")
print("="*50)

# Mock asyncpg connection to simulate database inserts
class MockPool:
    def __init__(self):
        self.inserts = []
        
    def acquire(self):
        class MockAcquire:
            def __init__(self, pool):
                self.pool = pool
            async def __aenter__(self):
                class MockConn:
                    def __init__(self, pool):
                        self.pool = pool
                    async def executemany(self, query, data):
                        self.pool.inserts.extend(data)
                        print(f"  [MockDB] Successfully inserted batch of {len(data)} items.")
                    async def execute(self, query, *args):
                        pass
                return MockConn(self.pool)
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
        return MockAcquire(self)

async def test_database_batching():
    print("\n--- Test 1: Database In-Memory Queue & Batch Ingestion ---")
    mock_pool = MockPool()
    db.pool = mock_pool
    
    # Empty queue
    while not db.queue.empty():
        db.queue.get_nowait()
        
    print("Pushing 5 items to connection helper queue...")
    for i in range(5):
        await db.log_alert({
            "time_epoch": int(time.time() * 1000),
            "src_ip": "10.0.0.1",
            "src_port": 1234 + i,
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "protocol": "tcp",
            "bytes_in": 500,
            "bytes_out": 500,
            "l1_anomaly_score": 1.2,
            "l2_threat_prob": 0.8,
            "l3_threat_prob": 0.0,
            "classification": "Threat-Activity",
            "is_anomaly": True,
            "explanations": [{"feature_name": "bytes_in", "shap_value": 0.4}]
        })
        
    print(f"Queue size after insertions: {db.queue.qsize()}")
    assert db.queue.qsize() == 5, "Queue size should be 5"
    
    print("Manually triggering flush remaining on connection helper...")
    await db._flush_remaining()
    print(f"Queue size after flushing: {db.queue.qsize()}")
    print(f"Mock Database total inserted alerts: {len(mock_pool.inserts)}")
    
    assert db.queue.qsize() == 0, "Queue should be empty after flushing"
    assert len(mock_pool.inserts) == 5, "Database should have received 5 insertions"
    print("SUCCESS: Asynchronous batch queue working correctly!")

def test_prometheus_endpoint():
    print("\n--- Test 2: Prometheus Metrics `/metrics` Endpoint ---")
    client = TestClient(app)
    
    # Put mock data into metrics_data
    metrics_data["processed_events"][("1", "dropped")] = 42
    metrics_data["inference_latency_sum"]["rf"] = 1.234
    metrics_data["inference_latency_count"]["rf"] = 10
    
    response = client.get("/metrics")
    assert response.status_code == 200, "Should return status 200"
    content = response.text
    
    print("Verifying Prometheus metrics payload contents...")
    assert "threat_detector_processed_events_total" in content
    assert 'threat_detector_processed_events_total{layer="1",decision="dropped"} 42' in content
    assert 'threat_detector_inference_latency_seconds_sum{model="rf"} 1.234' in content
    assert 'threat_detector_inference_latency_seconds_count{model="rf"} 10' in content
    assert "threat_detector_database_batch_queue_size" in content
    
    print(content)
    print("SUCCESS: Prometheus metrics endpoint formatted correctly!")

async def main():
    await test_database_batching()
    test_prometheus_endpoint()
    print("\n" + "="*50)
    print("ALL PRODUCTION FEATURE TESTS PASSED")
    print("="*50)

if __name__ == "__main__":
    asyncio.run(main())
