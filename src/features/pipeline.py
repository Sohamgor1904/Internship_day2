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
