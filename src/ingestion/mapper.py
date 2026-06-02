import os
import glob
import pandas as pd
import numpy as np
import datetime
import hashlib
from typing import Iterator, Dict, Any, List

# Map proto names to numbers
PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "ospf": 89,
    "sctp": 132,
    "gre": 47,
    "arp": 0,
    "igmp": 2,
    "ggp": 3,
    "ipip": 4,
    "egp": 8,
    "pup": 12,
    "hmp": 20,
    "xns-idp": 22,
    "rdp": 27,
    "rvd": 66
}

def clean_value(val: Any) -> Any:
    """Replaces NaNs, infinite values, or nulls with standard JSON equivalents."""
    if pd.isna(val):
        return 0
    if isinstance(val, (int, float)):
        if np.isinf(val) or np.isnan(val):
            return 0
    return val

def generate_mock_ip(port: int, key: str) -> str:
    """Generates a deterministic host IP address based on an entropy key (e.g. port/protocol)."""
    hashed = hashlib.md5(f"{port}_{key}".encode()).hexdigest()
    # Generate IP in 10.10.x.y range
    part_3 = int(hashed[0:2], 16) % 254 + 1
    part_4 = int(hashed[2:4], 16) % 254 + 1
    return f"10.10.{part_3}.{part_4}"

def map_unsw_to_ocsf(row: Dict[str, Any]) -> Dict[str, Any]:
    """Maps a row from UNSW-NB15 dataset to OCSF Network Traffic schema."""
    # Source & Dest IPs
    src_ip = str(row.get("srcip", "192.168.1.1"))
    dst_ip = str(row.get("dstip", "10.0.0.1"))
    
    # Ports
    src_port = int(clean_value(row.get("sport", 0)))
    dst_port = int(clean_value(row.get("dsport", 0)))
    
    # Protocol mapping
    proto_str = str(row.get("proto", "tcp")).lower()
    proto_num = PROTO_MAP.get(proto_str, 6)
    
    # Timestamps (convert float seconds to milliseconds)
    raw_time = clean_value(row.get("stime", 0))
    epoch_ms = int(raw_time * 1000) if raw_time > 0 else int(datetime.datetime.utcnow().timestamp() * 1000)
    
    # Threat indicators
    is_anomaly = int(clean_value(row.get("label", 0)))
    attack_cat = str(row.get("attack_cat", "Normal")).strip()
    
    severity_id = 3 if is_anomaly == 1 else 1
    severity = "High" if is_anomaly == 1 else "Informational"

    return {
        "class_uid": 4001,
        "class_name": "Network Traffic",
        "activity_id": 1,
        "time": epoch_ms,
        "src_endpoint": {
            "ip": src_ip,
            "port": src_port
        },
        "dst_endpoint": {
            "ip": dst_ip,
            "port": dst_port
        },
        "connection_info": {
            "protocol_num": proto_num,
            "protocol_name": proto_str,
            "state": str(row.get("state", "CON"))
        },
        "traffic": {
            "bytes_in": int(clean_value(row.get("dbytes", 0))),
            "bytes_out": int(clean_value(row.get("sbytes", 0))),
            "packets_in": int(clean_value(row.get("dpkts", 0))),
            "packets_out": int(clean_value(row.get("spkts", 0)))
        },
        "severity_id": severity_id,
        "severity": severity,
        "enrichments": {
            "label": attack_cat if attack_cat and attack_cat != "Normal" else "Benign",
            "is_anomaly": is_anomaly,
            "dataset": "unsw-nb15"
        }
    }

def map_cic_to_ocsf(row: Dict[str, Any], baseline_time: int, index: int) -> Dict[str, Any]:
    """Maps a row from CICIDS2017 dataset to OCSF Network Traffic schema."""
    # Standard CICIDS2017 files do not contain IP columns.
    # Generate deterministic IPs based on Destination Port and Protocol to allow sequence analysis.
    dst_port = int(clean_value(row.get("Destination Port", 80)))
    dst_ip = generate_mock_ip(dst_port, "dst_cic")
    src_ip = "192.168.10.15"  # Mock local client IP
    src_port = 49152 + (index % 16383)  # Sequential ephemeral source port
    
    # Protocol
    proto_num = int(clean_value(row.get("Protocol", 6)))
    proto_str = "tcp" if proto_num == 6 else "udp" if proto_num == 17 else "other"
    
    # Time fallback: CICIDS2017 lacks flow timestamps in some CSV files.
    # Simulate a stream sequence separated by 10ms intervals.
    epoch_ms = baseline_time + (index * 10)
    
    # Threat indicators
    raw_label = str(row.get("Label", "BENIGN")).strip()
    is_anomaly = 0 if raw_label.upper() == "BENIGN" else 1
    
    severity_id = 3 if is_anomaly == 1 else 1
    severity = "High" if is_anomaly == 1 else "Informational"

    return {
        "class_uid": 4001,
        "class_name": "Network Traffic",
        "activity_id": 1,
        "time": epoch_ms,
        "src_endpoint": {
            "ip": src_ip,
            "port": src_port
        },
        "dst_endpoint": {
            "ip": dst_ip,
            "port": dst_port
        },
        "connection_info": {
            "protocol_num": proto_num,
            "protocol_name": proto_str,
            "state": "CON"
        },
        "traffic": {
            "bytes_in": int(clean_value(row.get("Total Length of Bwd Packets", 0))),
            "bytes_out": int(clean_value(row.get("Total Length of Fwd Packets", 0))),
            "packets_in": int(clean_value(row.get("Total Backward Packets", 0))),
            "packets_out": int(clean_value(row.get("Total Fwd Packets", 0)))
        },
        "severity_id": severity_id,
        "severity": severity,
        "enrichments": {
            "label": "Benign" if is_anomaly == 0 else raw_label,
            "is_anomaly": is_anomaly,
            "dataset": "cicids2017"
        }
    }

def map_cse_to_ocsf(row: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Maps a row from CSE-CIC-IDS2018 dataset to OCSF Network Traffic schema."""
    dst_port = int(clean_value(row.get("Dst Port", 80)))
    dst_ip = generate_mock_ip(dst_port, "dst_cse")
    src_ip = "192.168.20.25"  # Mock local client IP
    src_port = 49152 + (index % 16383)
    
    # Protocol
    proto_num = int(clean_value(row.get("Protocol", 6)))
    proto_str = "tcp" if proto_num == 6 else "udp" if proto_num == 17 else "other"
    
    # Timestamp string (e.g. 14/02/2018 08:31:01)
    raw_ts = row.get("Timestamp", "")
    try:
        dt = pd.to_datetime(raw_ts, dayfirst=True) if raw_ts else pd.Timestamp.now()
        epoch_ms = int(dt.timestamp() * 1000)
    except Exception:
        epoch_ms = int(datetime.datetime.utcnow().timestamp() * 1000) + (index * 10)
        
    # Threat indicators
    raw_label = str(row.get("Label", "Benign")).strip()
    is_anomaly = 0 if raw_label.lower() == "benign" else 1
    
    severity_id = 3 if is_anomaly == 1 else 1
    severity = "High" if is_anomaly == 1 else "Informational"

    return {
        "class_uid": 4001,
        "class_name": "Network Traffic",
        "activity_id": 1,
        "time": epoch_ms,
        "src_endpoint": {
            "ip": src_ip,
            "port": src_port
        },
        "dst_endpoint": {
            "ip": dst_ip,
            "port": dst_port
        },
        "connection_info": {
            "protocol_num": proto_num,
            "protocol_name": proto_str,
            "state": "CON"
        },
        "traffic": {
            "bytes_in": int(clean_value(row.get("TotLen Bwd Pkts", 0))),
            "bytes_out": int(clean_value(row.get("TotLen Fwd Pkts", 0))),
            "packets_in": int(clean_value(row.get("Tot Bwd Pkts", 0))),
            "packets_out": int(clean_value(row.get("Tot Fwd Pkts", 0)))
        },
        "severity_id": severity_id,
        "severity": severity,
        "enrichments": {
            "label": "Benign" if is_anomaly == 0 else raw_label,
            "is_anomaly": is_anomaly,
            "dataset": "cse-cic-ids2018"
        }
    }

class OCSFDataIngestor:
    """Ingestion controller pointing directly to local directories to load and normalize entries."""
    
    def __init__(self, cic_dir: str, unsw_dir: str, cse_dir: str):
        self.cic_dir = cic_dir
        self.unsw_dir = unsw_dir
        self.cse_dir = cse_dir

    def stream_dataset(self, dataset_name: str, max_records: int = 1000000, start_date: str = None, end_date: str = None) -> Iterator[Dict[str, Any]]:
        """Yields OCSF standard records from the requested local dataset."""
        dataset_name = dataset_name.lower()
        baseline_time = int(datetime.datetime.utcnow().timestamp() * 1000)
        
        # Convert date boundaries to epoch milliseconds
        start_time_ms = int(pd.to_datetime(start_date).timestamp() * 1000) if start_date else None
        end_time_ms = int(pd.to_datetime(end_date).timestamp() * 1000) if end_date else None
        
        if dataset_name == "cic":
            files = glob.glob(os.path.join(self.cic_dir, "*.csv"))
            if not files:
                return
            count = 0
            for file_path in files:
                try:
                    for chunk in pd.read_csv(file_path, chunksize=2000):
                        chunk.columns = chunk.columns.str.strip()
                        for i, (_, row) in enumerate(chunk.iterrows()):
                            event = map_cic_to_ocsf(row.to_dict(), baseline_time, count)
                            if (start_time_ms is None or event["time"] >= start_time_ms) and \
                               (end_time_ms is None or event["time"] <= end_time_ms):
                                yield event
                                count += 1
                                if count >= max_records:
                                    return
                except Exception as e:
                    print(f"Error loading CIC file {file_path}: {e}")
                    
        elif dataset_name == "unsw":
            files = glob.glob(os.path.join(self.unsw_dir, "*training*.csv"))
            if not files:
                files = glob.glob(os.path.join(self.unsw_dir, "UNSW-NB15_*.csv"))
            if not files:
                return
            count = 0
            for file_path in files:
                try:
                    is_raw = "training" not in file_path.lower() and "testing" not in file_path.lower()
                    if is_raw:
                        col_names = [
                            "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", 
                            "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", 
                            "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", 
                            "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt", 
                            "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", 
                            "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", 
                            "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", 
                            "ct_dst_src_ltm", "attack_cat", "label"
                        ]
                        for chunk in pd.read_csv(file_path, header=None, names=col_names, chunksize=2000, low_memory=False):
                            for _, row in chunk.iterrows():
                                event = map_unsw_to_ocsf(row.to_dict())
                                if (start_time_ms is None or event["time"] >= start_time_ms) and \
                                   (end_time_ms is None or event["time"] <= end_time_ms):
                                    yield event
                                    count += 1
                                    if count >= max_records:
                                        return
                    else:
                        for chunk in pd.read_csv(file_path, chunksize=2000):
                            chunk.columns = chunk.columns.str.strip()
                            for _, row in chunk.iterrows():
                                event = map_unsw_to_ocsf(row.to_dict())
                                if (start_time_ms is None or event["time"] >= start_time_ms) and \
                                   (end_time_ms is None or event["time"] <= end_time_ms):
                                    yield event
                                    count += 1
                                    if count >= max_records:
                                        return
                except Exception as e:
                    print(f"Error loading UNSW file {file_path}: {e}")
                    
        elif dataset_name == "cse":
            files = glob.glob(os.path.join(self.cse_dir, "*.csv"))
            if not files:
                return
            count = 0
            for file_path in files:
                try:
                    for chunk in pd.read_csv(file_path, chunksize=2000):
                        chunk.columns = chunk.columns.str.strip()
                        for _, row in chunk.iterrows():
                            event = map_cse_to_ocsf(row.to_dict(), count)
                            if (start_time_ms is None or event["time"] >= start_time_ms) and \
                               (end_time_ms is None or event["time"] <= end_time_ms):
                                yield event
                                count += 1
                                if count >= max_records:
                                    return
                except Exception as e:
                    print(f"Error loading CSE file {file_path}: {e}")
