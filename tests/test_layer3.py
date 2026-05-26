"""
Layer 3 Independent Test - Sequential PyTorch LSTM
Tests the LSTM model with known attack and benign sequences.
Run from task2/ root directory:
    python -X utf8 tests/test_layer3.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import numpy as np
import pickle
from config.settings import settings
from src.models.estimators import PyTorchLSTMModel

print("\n" + "="*55)
print("LAYER 3 - SEQUENTIAL LSTM TEST")
print("="*55)

# ─────────────────────────────────────────
# STEP 1: Load LSTM Model and Metadata
# ─────────────────────────────────────────
print("\n[LOADING] Loading LSTM model from disk...")

try:
    with open(settings.MODEL_METADATA_PATH, "rb") as f:
        feature_names = pickle.load(f)
    print(f"  ✅ Feature names loaded : {len(feature_names)} features")
except FileNotFoundError:
    print("  ❌ Metadata not found. Run 'python -m src.models.train' first.")
    sys.exit(1)

try:
    with open(settings.SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    print("  ✅ StandardScaler loaded successfully")
except FileNotFoundError:
    print("  ❌ Scaler not found. Run 'python -m src.models.train' first.")
    sys.exit(1)

try:
    input_size  = len(feature_names)        # 12
    hidden_size = settings.L3_HIDDEN_SIZE   # 64
    num_layers  = settings.L3_NUM_LAYERS    # 2

    lstm_model = PyTorchLSTMModel(
        input_size=input_size,
        hidden_size=hidden_size,
        num_layers=num_layers
    )
    lstm_model.load_state_dict(
        torch.load(settings.LSTM_MODEL_PATH, map_location=torch.device('cpu'))
    )
    lstm_model.eval()
    print(f"  ✅ LSTM weights loaded from : {settings.LSTM_MODEL_PATH}")
    print(f"     Input size  : {input_size}")
    print(f"     Hidden size : {hidden_size}")
    print(f"     Num layers  : {num_layers}")
except Exception as e:
    print(f"  ❌ LSTM load error: {e}")
    sys.exit(1)

# ─────────────────────────────────────────
# STEP 2: Helper Functions
# ─────────────────────────────────────────
WINDOW_SIZE = settings.L3_WINDOW_SIZE  # 10

def build_sequence(events: list) -> torch.Tensor:
    """
    Converts a list of 10 feature dicts into
    a (1, 10, 12) torch tensor for LSTM inference.
    """
    rows = []
    for event in events:
        row = [event[f] for f in feature_names]
        rows.append(row)
    array = np.array(rows, dtype=np.float32)
    # Apply StandardScaler transform
    scaled_array = scaler.transform(array)
    return torch.tensor(scaled_array, dtype=torch.float32).unsqueeze(0)  # (1, 10, 12)


def run_lstm(sequence_tensor):
    """Runs LSTM inference and returns probability and prediction."""
    with torch.no_grad():
        output = lstm_model(sequence_tensor)
        # Note: The model's forward pass already applies sigmoid internally
        prob = output.item()
    prediction = 1 if prob >= 0.5 else 0
    return prediction, prob


# ─────────────────────────────────────────
# STEP 3: TEST 1 - APT Slow Beacon Sequence
# Simulates C2 beacon: regular small packets
# at consistent delta_t intervals
# Expected: prediction = 1 (Attack)
# ─────────────────────────────────────────
print("\n" + "-"*55)
print("TEST 1: APT SLOW BEACON SEQUENCE (C2 Communication)")
print("-"*55)

# Attack profile: tiny delta_t, zero bytes_in, zero entropy (single dst),
# high flag_switches — derived from real attack averages in training data
apt_sequence = []
for i in range(WINDOW_SIZE):
    apt_sequence.append({
        "flow_duration":    0.00013,
        "delta_t":          0.001,
        "packets_out":      10.0,
        "packets_in":       0.0,
        "bytes_out":        640.0,
        "bytes_in":         0.0,
        "packets_rate":     126000.0,
        "byte_ratio":       1.18,
        "dst_ip_entropy":   0.0,
        "dst_port_entropy": 0.0,
        "flag_switches":    65.0,
        "protocol_num":     6.0
    })

apt_tensor = build_sequence(apt_sequence)
apt_pred, apt_prob = run_lstm(apt_tensor)

print(f"  Sequence Length : {WINDOW_SIZE} events")
print(f"  Pattern         : Consistent 30s beacon interval with high flag_switches")
print(f"  L3 Probability  : {apt_prob:.4f}")
print(f"  Prediction      : {'Attack (1)' if apt_pred == 1 else 'Benign (0)'}")
print(f"  Result          : {'✅ PASS - APT beacon detected' if apt_pred == 1 else '⚠️  NOT detected - may need more epochs'}")

# ─────────────────────────────────────────
# STEP 4: TEST 2 - Normal User Session
# Simulates human browsing behavior
# Expected: prediction = 0 (Benign)
# ─────────────────────────────────────────
print("\n" + "-"*55)
print("TEST 2: NORMAL USER SESSION (Human Browsing)")
print("-"*55)

# Benign profile: high entropy (many unique dst IPs/ports), balanced
# bytes bidirectionally, slow regular delta_t — matches real benign averages
normal_sequence = []
delta_times  = [0.5, 2.1, 0.8, 5.3, 1.2, 3.7, 0.9, 4.1, 2.8, 1.5]
entropies    = [6.14, 6.11, 6.07, 6.03, 6.03, 6.00, 5.97, 5.93, 5.89, 5.87]

for i in range(WINDOW_SIZE):
    normal_sequence.append({
        "flow_duration":    0.0099,
        "delta_t":          delta_times[i],
        "packets_out":      float(np.random.randint(2, 10)),
        "packets_in":       float(np.random.randint(2, 10)),
        "bytes_out":        float(np.random.randint(50, 300)),
        "bytes_in":         float(np.random.randint(100, 500)),
        "packets_rate":     float(np.random.uniform(490, 520)),
        "byte_ratio":       float(np.random.uniform(0.60, 0.75)),
        "dst_ip_entropy":   entropies[i],
        "dst_port_entropy": entropies[i],
        "flag_switches":    0.0,
        "protocol_num":     6.0
    })

normal_tensor = build_sequence(normal_sequence)
normal_pred, normal_prob = run_lstm(normal_tensor)

print(f"  Sequence Length : {WINDOW_SIZE} events")
print(f"  Pattern         : Irregular human browsing timing, high entropy")
print(f"  L3 Probability  : {normal_prob:.4f}")
print(f"  Prediction      : {'Attack (1)' if normal_pred == 1 else 'Benign (0)'}")
print(f"  Result          : {'✅ PASS - Normal session correctly ignored' if normal_pred == 0 else '❌ FAIL - False positive'}")

# ─────────────────────────────────────────
# STEP 5: TEST 3 - Lateral Movement
# Simulates attacker pivoting hosts:
#   First 3 events: benign-like recon (slow, low entropy, protocol 0)
#   Next 7 events: escalating attack traffic (high flag_switches, zero entropy)
# Expected: prediction = 1 (Attack)
# ─────────────────────────────────────────
print("\n" + "-"*55)
print("TEST 3: LATERAL MOVEMENT SEQUENCE")
print("-"*55)

# The lateral movement sequence captures real dataset patterns:
# Phase 1 (recon, events 0-2): slow traffic, protocol 0, moderate entropy,
#   mimicking quiet host discovery behavior before active exploitation begins
# Phase 2 (escalation, events 3-9): protocol 6 (TCP), shrinking delta_t,
#   increasing bytes/packets, zero entropy (single target), high flag switches
lateral_sequence = [
    # Phase 1: Recon phase — quiet, slow, protocol 0
    {"flow_duration": 74.1, "delta_t": 169.0, "packets_out": 3.0, "packets_in": 0.0,
     "bytes_out": 0.0, "bytes_in": 0.0, "packets_rate": 0.128, "byte_ratio": 0.874,
     "dst_ip_entropy": 1.713, "dst_port_entropy": 1.713, "flag_switches": 0.0, "protocol_num": 0.0},
    {"flow_duration": 75.1, "delta_t": 169.0, "packets_out": 3.0, "packets_in": 0.0,
     "bytes_out": 0.0, "bytes_in": 0.0, "packets_rate": 0.125, "byte_ratio": 0.874,
     "dst_ip_entropy": 1.706, "dst_port_entropy": 1.706, "flag_switches": 0.0, "protocol_num": 0.0},
    {"flow_duration": 76.2, "delta_t": 169.0, "packets_out": 3.0, "packets_in": 0.0,
     "bytes_out": 0.0, "bytes_in": 0.0, "packets_rate": 0.122, "byte_ratio": 0.874,
     "dst_ip_entropy": 1.700, "dst_port_entropy": 1.700, "flag_switches": 0.0, "protocol_num": 0.0},
    # Phase 2: Active exploitation — TCP, zero entropy, escalating intensity
    {"flow_duration": 0.0002, "delta_t": 5.0, "packets_out": 5.0, "packets_in": 0.0,
     "bytes_out": 320.0, "bytes_in": 0.0, "packets_rate": 85000.0, "byte_ratio": 1.18,
     "dst_ip_entropy": 0.0, "dst_port_entropy": 0.0, "flag_switches": 30.0, "protocol_num": 6.0},
    {"flow_duration": 0.00015, "delta_t": 2.0, "packets_out": 8.0, "packets_in": 0.0,
     "bytes_out": 512.0, "bytes_in": 0.0, "packets_rate": 100000.0, "byte_ratio": 1.18,
     "dst_ip_entropy": 0.0, "dst_port_entropy": 0.0, "flag_switches": 45.0, "protocol_num": 6.0},
    {"flow_duration": 0.00013, "delta_t": 0.5, "packets_out": 12.0, "packets_in": 0.0,
     "bytes_out": 768.0, "bytes_in": 0.0, "packets_rate": 115000.0, "byte_ratio": 1.18,
     "dst_ip_entropy": 0.0, "dst_port_entropy": 0.0, "flag_switches": 55.0, "protocol_num": 6.0},
    {"flow_duration": 0.00013, "delta_t": 0.1, "packets_out": 15.0, "packets_in": 0.0,
     "bytes_out": 960.0, "bytes_in": 0.0, "packets_rate": 120000.0, "byte_ratio": 1.18,
     "dst_ip_entropy": 0.0, "dst_port_entropy": 0.0, "flag_switches": 60.0, "protocol_num": 6.0},
    {"flow_duration": 0.00013, "delta_t": 0.01, "packets_out": 18.0, "packets_in": 0.0,
     "bytes_out": 1152.0, "bytes_in": 0.0, "packets_rate": 124000.0, "byte_ratio": 1.18,
     "dst_ip_entropy": 0.0, "dst_port_entropy": 0.0, "flag_switches": 63.0, "protocol_num": 6.0},
    {"flow_duration": 0.00013, "delta_t": 0.001, "packets_out": 20.0, "packets_in": 0.0,
     "bytes_out": 1280.0, "bytes_in": 0.0, "packets_rate": 126000.0, "byte_ratio": 1.18,
     "dst_ip_entropy": 0.0, "dst_port_entropy": 0.0, "flag_switches": 65.0, "protocol_num": 6.0},
    {"flow_duration": 0.00013, "delta_t": 0.001, "packets_out": 20.0, "packets_in": 0.0,
     "bytes_out": 1280.0, "bytes_in": 0.0, "packets_rate": 126000.0, "byte_ratio": 1.18,
     "dst_ip_entropy": 0.0, "dst_port_entropy": 0.0, "flag_switches": 67.0, "protocol_num": 6.0},
]

lateral_tensor = build_sequence(lateral_sequence)
lateral_pred, lateral_prob = run_lstm(lateral_tensor)

print(f"  Sequence Length : {WINDOW_SIZE} events")
print(f"  Pattern         : Recon (3 events) escalating to TCP exploitation (7 events)")
print(f"  L3 Probability  : {lateral_prob:.4f}")
print(f"  Prediction      : {'Attack (1)' if lateral_pred == 1 else 'Benign (0)'}")
print(f"  Result          : {'✅ PASS - Lateral movement detected' if lateral_pred == 1 else '⚠️  NOT detected - subtle pattern'}")

# ─────────────────────────────────────────
# STEP 6: TEST 4 - Sequence Order Validation
# Reverse the lateral sequence to prove
# LSTM uses temporal order, not just feature values
# Expected: reversed sequence has meaningfully
#   different (lower) probability than forward
# ─────────────────────────────────────────
print("\n" + "-"*55)
print("TEST 4: SEQUENCE ORDER VALIDATION (Reversed Lateral)")
print("-"*55)

reversed_lateral = list(reversed(lateral_sequence))
reversed_tensor  = build_sequence(reversed_lateral)
reversed_pred, reversed_prob = run_lstm(reversed_tensor)

order_matters = abs(lateral_prob - reversed_prob) > 0.05

print(f"  Forward Lateral Prob  : {lateral_prob:.4f}")
print(f"  Reversed Lateral Prob : {reversed_prob:.4f}")
print(f"  Difference            : {abs(lateral_prob - reversed_prob):.4f}")
print(f"  Result                : {'✅ PASS - LSTM uses sequence order' if order_matters else '⚠️  Probabilities similar - LSTM may not be using order'}")

# ─────────────────────────────────────────
# STEP 7: Summary
# ─────────────────────────────────────────
print("\n" + "="*55)
print("LAYER 3 TEST SUMMARY")
print("="*55)
print(f"  APT Beacon Detected      : {'✅ YES' if apt_pred == 1 else '⚠️  NO'}")
print(f"  Normal Session Ignored   : {'✅ YES' if normal_pred == 0 else '❌ NO'}")
print(f"  Lateral Movement Caught  : {'✅ YES' if lateral_pred == 1 else '⚠️  NO'}")
print(f"  Sequence Order Matters   : {'✅ YES' if order_matters else '⚠️  NO'}")

core_passed = (apt_pred == 1) and (normal_pred == 0) and (lateral_pred == 1) and order_matters
print(f"\n  Overall Status : {'✅ LAYER 3 WORKING CORRECTLY' if core_passed else '❌ NEEDS FIXING'}")
print("="*55)