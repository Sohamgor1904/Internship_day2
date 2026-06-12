import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import numpy as np
import json

from src.features.pipeline import StreamingFeaturePipeline
from src.models.estimators import Layer3LSTMTracker
from src.database.connection import DatabaseHelper
from config.settings import settings

class TestRedisPipeline(unittest.IsolatedAsyncioTestCase):

    async def test_extract_features_async_success(self):
        # Instantiate pipeline
        pipeline = StreamingFeaturePipeline(window_size=10)
        
        # Create a mock redis client
        mock_redis = AsyncMock()
        pipeline.redis_client = mock_redis
        
        # Setup event
        event = {
            "src_endpoint": {"ip": "10.0.0.1"},
            "dst_endpoint": {"ip": "10.0.0.2", "port": 80},
            "time": 1700000000000,
            "traffic": {
                "bytes_in": 100,
                "bytes_out": 200,
                "packets_in": 1,
                "packets_out": 2
            },
            "connection_info": {
                "protocol_num": 6,
                "state": "CON"
            }
        }
        
        # Mock Lua evaluation output
        # Res is a list: [previous_last_seen, [list of json string records]]
        history_record = {
            "time": 1700000000000,
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "bytes_in": 100,
            "bytes_out": 200,
            "packets_in": 1,
            "packets_out": 2,
            "protocol": 6,
            "state": "CON"
        }
        mock_redis.eval.return_value = ["1700000000000", [json.dumps(history_record)]]
        
        # Run async extract
        features = await pipeline.extract_features_async(event, update_state=True)
        
        # Check eval was called with LUA script and arguments
        self.assertTrue(mock_redis.eval.called)
        call_args = mock_redis.eval.call_args[0]
        # script is call_args[0]
        self.assertEqual(call_args[1], 2) # numkeys
        self.assertEqual(call_args[2], "threat_detection:state:10.0.0.1") # KEYS[1]
        self.assertEqual(call_args[3], "threat_detection:last_seen:10.0.0.1") # KEYS[2]
        
        # Check features array
        self.assertIsInstance(features, np.ndarray)
        self.assertEqual(features.shape, (12,))
        
    async def test_extract_features_async_fallback_on_failure(self):
        pipeline = StreamingFeaturePipeline(window_size=10)
        mock_redis = AsyncMock()
        mock_redis.eval.side_effect = Exception("Redis error")
        pipeline.redis_client = mock_redis
        
        event = {
            "src_endpoint": {"ip": "10.0.0.1"},
            "dst_endpoint": {"ip": "10.0.0.2", "port": 80},
            "time": 1700000000000,
            "traffic": {
                "bytes_in": 100,
                "bytes_out": 200,
                "packets_in": 1,
                "packets_out": 2
            },
            "connection_info": {
                "protocol_num": 6,
                "state": "CON"
            }
        }
        
        # Run extraction, it should fallback to synchronous extract_features (in-memory)
        features = await pipeline.extract_features_async(event, update_state=True)
        self.assertIsInstance(features, np.ndarray)
        self.assertEqual(features.shape, (12,))

    async def test_evaluate_lstm_sequence_async_success(self):
        tracker = Layer3LSTMTracker()
        mock_redis = AsyncMock()
        tracker.redis_client = mock_redis
        
        # Mock model to avoid actual tensor operations failing if not loaded
        tracker.model = MagicMock()
        tracker.model.return_value = MagicMock()
        tracker.model.return_value.item.return_value = 0.85
        
        feature_vector = np.zeros(settings.L3_INPUT_SIZE, dtype=np.float32)
        
        # Mock Redis eval returning list of serialized vectors
        mock_redis.eval.return_value = [json.dumps(feature_vector.tolist())]
        
        prob = await tracker.evaluate_ip_sequence_async("10.0.0.1", feature_vector)
        
        # Check model inference return probability
        self.assertEqual(prob, 0.85)
        self.assertTrue(mock_redis.eval.called)
        
    async def test_database_helper_redis_queue(self):
        db = DatabaseHelper()
        mock_redis = AsyncMock()
        db.redis_client = mock_redis
        
        alert = {"src_ip": "10.0.0.1", "bytes_in": 120}
        
        # Enable Redis
        with patch("config.settings.settings.USE_REDIS", True):
            await db.log_alert(alert)
            self.assertTrue(mock_redis.rpush.called)
            mock_redis.rpush.assert_called_with("threat_alerts:queue", json.dumps(alert))
            
    async def test_database_helper_redis_queue_fallback(self):
        db = DatabaseHelper()
        mock_redis = AsyncMock()
        mock_redis.rpush.side_effect = Exception("Redis connection failed")
        db.redis_client = mock_redis
        
        alert = {"src_ip": "10.0.0.1", "bytes_in": 120}
        
        # Enable Redis, push fails, should fallback to in-memory queue
        with patch("config.settings.settings.USE_REDIS", True):
            await db.log_alert(alert)
            self.assertEqual(db.queue.qsize(), 1)
            dequeued = await db.queue.get()
            self.assertEqual(dequeued["src_ip"], "10.0.0.1")

    async def test_plain_alert_flusher_flow(self):
        db = DatabaseHelper()
        mock_redis = AsyncMock()
        db.redis_client = mock_redis
        
        # Mock database connection pool and connection
        class MockConn:
            def __init__(self):
                self.executemany_called = False
            async def executemany(self, query, data):
                self.executemany_called = True
        
        mock_conn = MockConn()
        class MockPool:
            def acquire(self):
                class MockAcquire:
                    async def __aenter__(self):
                        return mock_conn
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        pass
                return MockAcquire()
                
        db.pool = MockPool()
        
        alert = {"src_ip": "192.168.1.1", "time_epoch": 1000, "bytes_in": 100, "bytes_out": 100}
        await db._write_batch([alert])
        
        self.assertTrue(mock_conn.executemany_called)

    async def test_enveloped_alert_flusher_unwraps(self):
        db = DatabaseHelper()
        mock_redis = AsyncMock()
        db.redis_client = mock_redis
        
        envelope = {
            "alert": {"src_ip": "192.168.1.2", "time_epoch": 2000, "bytes_in": 100, "bytes_out": 100},
            "dlq_retry_count": 1,
            "first_failed_at": "2026-06-08T00:00:00Z",
            "last_failed_at": "2026-06-08T00:00:00Z",
            "failure_reason": "Database down"
        }
        
        # Test unwrapping
        unwrapped = db.unwrap_item(envelope)
        self.assertEqual(unwrapped["src_ip"], "192.168.1.2")
        self.assertIn("_dlq_envelope", unwrapped)
        self.assertEqual(unwrapped["_dlq_envelope"]["dlq_retry_count"], 1)
        
        # Mock database connection pool and connection
        class MockConn:
            def __init__(self, test_case):
                self.test_case = test_case
                self.executemany_called = False
            async def executemany(self, query, data):
                self.executemany_called = True
                # Assert the alert is formatted properly without internal keys affecting SQL data structure
                self.test_case.assertEqual(data[0][1], "192.168.1.2")
            async def execute(self, query, *args):
                pass
        
        mock_conn = MockConn(self)
        class MockPool:
            def acquire(self):
                class MockAcquire:
                    async def __aenter__(self):
                        return mock_conn
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        pass
                return MockAcquire()
                
        db.pool = MockPool()
        await db._write_batch([unwrapped])
        self.assertTrue(mock_conn.executemany_called)

    async def test_enveloped_alert_fails_insert_reroutes_to_dlq(self):
        db = DatabaseHelper()
        mock_redis = AsyncMock()
        db.redis_client = mock_redis
        
        envelope = {
            "alert": {"src_ip": "192.168.1.3", "time_epoch": 3000, "bytes_in": 100, "bytes_out": 100},
            "dlq_retry_count": 1,
            "first_failed_at": "2026-06-08T00:00:00Z",
            "last_failed_at": "2026-06-08T00:00:00Z",
            "failure_reason": "Database down"
        }
        
        unwrapped = db.unwrap_item(envelope)
        
        # Mock database to fail on both executemany and execute
        class MockConn:
            async def executemany(self, query, data):
                raise Exception("DB Batch Failure")
            async def execute(self, query, *args):
                raise Exception("DB Individual Failure")
                
        class MockPool:
            def acquire(self):
                class MockAcquire:
                    async def __aenter__(self):
                        return MockConn()
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        pass
                return MockAcquire()
                
        db.pool = MockPool()
        
        # Enable Redis so it routes to DLQ list
        with patch("config.settings.settings.USE_REDIS", True):
            await db._write_batch([unwrapped])
            
            # Assert pushed back to threat_alerts:dlq
            self.assertTrue(mock_redis.rpush.called)
            call_args = mock_redis.rpush.call_args[0]
            self.assertEqual(call_args[0], "threat_alerts:dlq")
            
            routed_envelope = json.loads(call_args[1])
            self.assertEqual(routed_envelope["alert"]["src_ip"], "192.168.1.3")
            # Assert dlq_retry_count incremented from 1 to 2
            self.assertEqual(routed_envelope["dlq_retry_count"], 2)
            # Assert original failure reason and first_failed_at preserved
            self.assertEqual(routed_envelope["first_failed_at"], "2026-06-08T00:00:00Z")
            self.assertEqual(routed_envelope["failure_reason"], "Database down")
            self.assertNotEqual(routed_envelope["last_failed_at"], "2026-06-08T00:00:00Z")

    async def test_alert_exceeding_max_retries_discarded(self):
        db = DatabaseHelper()
        mock_redis = AsyncMock()
        db.redis_client = mock_redis
        
        envelope = {
            "alert": {"src_ip": "192.168.1.4", "time_epoch": 4000, "bytes_in": 100, "bytes_out": 100},
            "dlq_retry_count": settings.MAX_DLQ_RETRIES,  # Already at MAX (3)
            "first_failed_at": "2026-06-08T00:00:00Z",
            "last_failed_at": "2026-06-08T00:00:00Z",
            "failure_reason": "Database down"
        }
        
        unwrapped = db.unwrap_item(envelope)
        
        # Mock database to fail
        class MockConn:
            async def executemany(self, query, data):
                raise Exception("DB Batch Failure")
            async def execute(self, query, *args):
                raise Exception("DB Individual Failure")
                
        class MockPool:
            def acquire(self):
                class MockAcquire:
                    async def __aenter__(self):
                        return MockConn()
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        pass
                return MockAcquire()
                
        db.pool = MockPool()
        
        with patch("config.settings.settings.USE_REDIS", True):
            await db._write_batch([unwrapped])
            
            # Assert rpush was NOT called to route back to threat_alerts:dlq
            self.assertFalse(mock_redis.rpush.called)

