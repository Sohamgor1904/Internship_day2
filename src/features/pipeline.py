import math
import numpy as np
from collections import deque, Counter
from typing import Dict, Any, List, Tuple
from config.settings import settings

def calculate_entropy(items: List[Any]) -> float:
    """Computes the Shannon Entropy of a list of categorical items."""
    if not items:
        return 0.0
    total = len(items)
    counts = Counter(items)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

class StreamingFeaturePipeline:
    """Stateful stream processor that transforms nested OCSF records into numerical feature vectors."""

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.redis_client = None
        # State tracking: keyed by src_ip
        # Stores deques of dicts with keys: time, dst_ip, dst_port, bytes_in, bytes_out, packets_in, packets_out, protocol, state
        self.state: Dict[str, deque] = {}
        # Stores the last seen timestamp for each src_ip to compute delta_t
        self.last_seen_time: Dict[str, int] = {}
        
        # Explicit feature ordering
        self.feature_names = [
            "flow_duration",
            "delta_t",
            "packets_out",
            "packets_in",
            "bytes_out",
            "bytes_in",
            "packets_rate",
            "byte_ratio",
            "dst_ip_entropy",
            "dst_port_entropy",
            "flag_switches",
            "protocol_num"
        ]

    def extract_features(self, event: Dict[str, Any], update_state: bool = True) -> np.ndarray:
        """Processes a single OCSF event dictionary and returns a 1D feature vector."""
        src_ip = event.get("src_endpoint", {}).get("ip", "127.0.0.1")
        dst_ip = event.get("dst_endpoint", {}).get("ip", "127.0.0.1")
        dst_port = event.get("dst_endpoint", {}).get("port", 0)
        
        time_ms = event.get("time", 0)
        
        traffic = event.get("traffic", {})
        bytes_in = traffic.get("bytes_in", 0)
        bytes_out = traffic.get("bytes_out", 0)
        packets_in = traffic.get("packets_in", 0)
        packets_out = traffic.get("packets_out", 0)
        
        conn = event.get("connection_info", {})
        protocol_num = conn.get("protocol_num", 6)
        state_str = conn.get("state", "CON")
        
        # 1. Temporal Feature: Delta t
        last_t = self.last_seen_time.get(src_ip, time_ms)
        delta_t = (time_ms - last_t) / 1000.0  # convert ms to seconds
        if delta_t < 0:
            delta_t = 0.0
            
        if update_state:
            self.last_seen_time[src_ip] = time_ms
            
        # Get history deque
        if src_ip not in self.state:
            self.state[src_ip] = deque(maxlen=self.window_size)
        history = self.state[src_ip]
        
        # Current record summary
        record = {
            "time": time_ms,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "packets_in": packets_in,
            "packets_out": packets_out,
            "protocol": protocol_num,
            "state": state_str
        }
        
        if update_state:
            history.append(record)
            
        # Compute rolling window metrics
        # If history is empty, initialize lists with current record
        hist_list = list(history) if history else [record]
        
        # 2. Volumetric rolling rate
        total_packets = sum(r["packets_in"] + r["packets_out"] for r in hist_list)
        start_time = hist_list[0]["time"]
        end_time = hist_list[-1]["time"]
        window_duration = (end_time - start_time) / 1000.0  # seconds
        
        packets_rate = total_packets / (window_duration + 1e-6)
        
        # 3. Rolling forward/backward byte ratio
        total_bytes_out = sum(r["bytes_out"] for r in hist_list)
        total_bytes_in = sum(r["bytes_in"] for r in hist_list)
        byte_ratio = total_bytes_out / (total_bytes_in + 1e-6)
        
        # 4. Structural: Dest IP entropy & Dest Port entropy
        dst_ips = [r["dst_ip"] for r in hist_list]
        dst_ports = [r["dst_port"] for r in hist_list]
        
        dst_ip_entropy = calculate_entropy(dst_ips)
        dst_port_entropy = calculate_entropy(dst_ports)
        
        # 5. Structural: Flag switches (count transitions in TCP connection state)
        flag_switches = 0
        for i in range(1, len(hist_list)):
            if hist_list[i]["state"] != hist_list[i-1]["state"]:
                flag_switches += 1
                
        # Flow duration (from datasets duration, we can approximate it using traffic packets and bytes rates if zero)
        # For simplicity, we fallback to window duration for this specific flow or 0
        flow_duration = window_duration / len(hist_list)
        
        # Assemble feature array
        features = [
            float(flow_duration),
            float(delta_t),
            float(packets_out),
            float(packets_in),
            float(bytes_out),
            float(bytes_in),
            float(packets_rate),
            float(byte_ratio),
            float(dst_ip_entropy),
            float(dst_port_entropy),
            float(flag_switches),
            float(protocol_num)
        ]
        
        return np.array(features, dtype=np.float32)

    def reset(self):
        """Resets the state of the streaming pipeline."""
        self.state.clear()
        self.last_seen_time.clear()

    # Lua script for pipeline state atomicity
    LUA_EXTRACT_SCRIPT = """
    local previous_last_seen = redis.call('GET', KEYS[2])
    if not previous_last_seen then
        previous_last_seen = ARGV[2]
    end
    if ARGV[4] == 'true' then
        redis.call('LPUSH', KEYS[1], ARGV[1])
        redis.call('LTRIM', KEYS[1], 0, ARGV[3] - 1)
        redis.call('SET', KEYS[2], ARGV[2])
    end
    local history = redis.call('LRANGE', KEYS[1], 0, ARGV[3] - 1)
    return {previous_last_seen, history}
    """

    async def extract_features_async(self, event: Dict[str, Any], update_state: bool = True) -> np.ndarray:
        """Processes a single OCSF event asynchronously using Redis for stateful features."""
        import json
        if not self.redis_client:
            # Fallback to synchronous extraction if Redis client is not available
            return self.extract_features(event, update_state=update_state)

        src_ip = event.get("src_endpoint", {}).get("ip", "127.0.0.1")
        dst_ip = event.get("dst_endpoint", {}).get("ip", "127.0.0.1")
        dst_port = event.get("dst_endpoint", {}).get("port", 0)
        
        time_ms = event.get("time", 0)
        
        traffic = event.get("traffic", {})
        bytes_in = traffic.get("bytes_in", 0)
        bytes_out = traffic.get("bytes_out", 0)
        packets_in = traffic.get("packets_in", 0)
        packets_out = traffic.get("packets_out", 0)
        
        conn = event.get("connection_info", {})
        protocol_num = conn.get("protocol_num", 6)
        state_str = conn.get("state", "CON")

        state_key = f"threat_detection:state:{src_ip}"
        last_seen_key = f"threat_detection:last_seen:{src_ip}"

        record = {
            "time": time_ms,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "packets_in": packets_in,
            "packets_out": packets_out,
            "protocol": protocol_num,
            "state": state_str
        }

        try:
            res = await self.redis_client.eval(
                self.LUA_EXTRACT_SCRIPT,
                2,
                state_key,
                last_seen_key,
                json.dumps(record),
                str(time_ms),
                str(self.window_size),
                "true" if update_state else "false"
            )
            
            previous_last_seen = int(res[0])
            history = res[1]
        except Exception as e:
            # Handle Redis failures gracefully
            print(f"Redis pipeline script failed: {e}. Falling back to in-memory state.")
            return self.extract_features(event, update_state=update_state)

        # 1. Temporal Feature: Delta t
        delta_t = (time_ms - previous_last_seen) / 1000.0
        if delta_t < 0:
            delta_t = 0.0

        hist_list = [json.loads(x) for x in reversed(history)] if history else [record]

        # 2. Volumetric rolling rate
        total_packets = sum(r["packets_in"] + r["packets_out"] for r in hist_list)
        start_time = hist_list[0]["time"]
        end_time = hist_list[-1]["time"]
        window_duration = (end_time - start_time) / 1000.0  # seconds
        
        packets_rate = total_packets / (window_duration + 1e-6)
        
        # 3. Rolling forward/backward byte ratio
        total_bytes_out = sum(r["bytes_out"] for r in hist_list)
        total_bytes_in = sum(r["bytes_in"] for r in hist_list)
        byte_ratio = total_bytes_out / (total_bytes_in + 1e-6)
        
        # 4. Structural: Dest IP entropy & Dest Port entropy
        dst_ips = [r["dst_ip"] for r in hist_list]
        dst_ports = [r["dst_port"] for r in hist_list]
        
        dst_ip_entropy = calculate_entropy(dst_ips)
        dst_port_entropy = calculate_entropy(dst_ports)
        
        # 5. Structural: Flag switches (count transitions in TCP connection state)
        flag_switches = 0
        for i in range(1, len(hist_list)):
            if hist_list[i]["state"] != hist_list[i-1]["state"]:
                flag_switches += 1
                
        # Flow duration
        flow_duration = window_duration / len(hist_list)
        
        # Assemble feature array
        features = [
            float(flow_duration),
            float(delta_t),
            float(packets_out),
            float(packets_in),
            float(bytes_out),
            float(bytes_in),
            float(packets_rate),
            float(byte_ratio),
            float(dst_ip_entropy),
            float(dst_port_entropy),
            float(flag_switches),
            float(protocol_num)
        ]
        
        return np.array(features, dtype=np.float32)

    async def reset_async(self):
        """Resets the state of the pipeline in Redis."""
        self.state.clear()
        self.last_seen_time.clear()
        if self.redis_client:
            try:
                # Find all state and last_seen keys and delete them
                keys = await self.redis_client.keys("threat_detection:state:*")
                keys += await self.redis_client.keys("threat_detection:last_seen:*")
                keys += await self.redis_client.keys("threat_detection:lstm:*")
                if keys:
                    await self.redis_client.delete(*keys)
            except Exception as e:
                print(f"Failed to reset Redis states: {e}")
