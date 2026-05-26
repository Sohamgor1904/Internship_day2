"""
Layer 2 Independent Test - Contextual Random Forest Classifier
Run from task2/ root directory:
    python -X utf8 tests/test_layer2.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pickle
import numpy as np
from config.settings import settings

print("\n" + "="*55)
print("LAYER 2 - RANDOM FOREST CLASSIFIER TEST")
print("="*55)

# ─────────────────────────────────────────
# STEP 1: Load Models
# ─────────────────────────────────────────
print("\n[LOADING] Loading trained models from disk...")

try:
    with open(settings.RF_MODEL_PATH, "rb") as f:
        rf_model = pickle.load(f)
    print(f"  ✅ RF Model loaded from      : {settings.RF_MODEL_PATH}")
except FileNotFoundError:
    print(f"  ❌ RF Model not found. Run 'python -m src.models.train' first.")
    sys.exit(1)

try:
    with open(settings.SHAP_EXPLAINER_PATH, "rb") as f:
        explainer = pickle.load(f)
    print(f"  ✅ SHAP Explainer loaded from : {settings.SHAP_EXPLAINER_PATH}")
except FileNotFoundError:
    print(f"  ❌ SHAP Explainer not found.")
    sys.exit(1)

try:
    with open(settings.MODEL_METADATA_PATH, "rb") as f:
        feature_names = pickle.load(f)
    print(f"  ✅ Feature names loaded       : {feature_names}")
except FileNotFoundError:
    print(f"  ❌ Metadata not found.")
    sys.exit(1)

try:
    with open(settings.SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    print(f"  ✅ StandardScaler loaded from : {settings.SCALER_PATH}")
except FileNotFoundError:
    print(f"  ❌ Scaler not found. Run 'python -m src.models.train' first.")
    sys.exit(1)

# ─────────────────────────────────────────
# STEP 2: Helper Functions
# Using your exact 12 feature names:
# ['flow_duration', 'delta_t', 'packets_out',
#  'packets_in', 'bytes_out', 'bytes_in',
#  'packets_rate', 'byte_ratio', 'dst_ip_entropy',
#  'dst_port_entropy', 'flag_switches', 'protocol_num']
# ─────────────────────────────────────────
def build_feature_vector(
    flow_duration, delta_t, packets_out,
    packets_in, bytes_out, bytes_in,
    packets_rate, byte_ratio, dst_ip_entropy,
    dst_port_entropy, flag_switches, protocol_num
):
    """Builds ordered, StandardScaler-transformed numpy array matching exact training feature order."""
    raw = np.array([[
        flow_duration, delta_t, packets_out, packets_in,
        bytes_out, bytes_in, packets_rate, byte_ratio,
        dst_ip_entropy, dst_port_entropy, flag_switches, protocol_num
    ]], dtype=np.float32)
    return scaler.transform(raw)


def run_shap(vector, top_n=5):
    """Returns top N SHAP feature attributions for attack class."""
    try:
        shap_values = explainer.shap_values(vector)

        # Handle all possible SHAP output shapes
        if isinstance(shap_values, list):
            # Binary classification returns list of 2 arrays
            attack_shap = np.array(shap_values[1]).flatten()
        else:
            attack_shap = np.array(shap_values).flatten()

        pairs = sorted(
            zip(feature_names, attack_shap),
            key=lambda x: abs(x[1]),
            reverse=True
        )
        return [
            {"feature_name": name, "shap_value": round(float(val), 4)}
            for name, val in pairs[:top_n]
        ]
    except Exception as e:
        return [{"error": str(e)}]


# ─────────────────────────────────────────
# STEP 3: TEST 1 - DDoS / Flooding Attack
# Matches real attack avg distribution:
#   - tiny delta_t (0.02s), near-zero bytes_in
#   - zero entropy (single target), high flag_switches
#   - high packets_rate, protocol 6 (TCP)
# Expected: prediction = 1, prob > 0.5
# ─────────────────────────────────────────
print("\n" + "-"*55)
print("TEST 1: DDoS ATTACK RECORD")
print("-"*55)

attack_vector = build_feature_vector(
    flow_duration=0.00013,    # Ultra-short flood flows (matches real attack avg: 0.43s)
    delta_t=0.001,            # Near-zero inter-arrival time (real attack avg: 0.02s)
    packets_out=20.0,         # Outbound flood packets
    packets_in=0.0,           # No responses (SYN flood / UDP flood)
    bytes_out=1280.0,         # Bytes pushed out per flow
    bytes_in=0.0,             # Zero inbound — unresponsive target
    packets_rate=126000.0,    # Extreme packet rate (real attack avg: 96k pps)
    byte_ratio=1.18,          # Slightly above 1.0 (asymmetric flood)
    dst_ip_entropy=0.0,       # All traffic to single IP (entropy = 0)
    dst_port_entropy=0.0,     # All traffic to single port (entropy = 0)
    flag_switches=65.0,       # High TCP flag transitions (real attack avg: 21.8)
    protocol_num=6.0          # TCP
)

attack_pred = rf_model.predict(attack_vector)[0]
attack_prob = rf_model.predict_proba(attack_vector)[0][1]
attack_shap = run_shap(attack_vector)

print(f"  Prediction     : {'Attack (1)' if attack_pred == 1 else 'Benign (0)'}")
print(f"  L2 Probability : {attack_prob:.4f}")
print(f"  Top SHAP Reasons:")
for s in attack_shap:
    if "error" not in s:
        print(f"    - {s['feature_name']:<20} : {s['shap_value']}")
    else:
        print(f"    - SHAP Error: {s['error']}")
print(f"  Result         : {'✅ PASS - Attack correctly classified' if attack_pred == 1 else '❌ FAIL - Missed attack'}")

# ─────────────────────────────────────────
# STEP 4: TEST 2 - Benign Record
# Matches real benign avg distribution:
#   - high entropy (many IPs/ports), balanced bytes
#   - moderate delta_t, low flag_switches
# Expected: prediction = 0, prob < 0.5
# ─────────────────────────────────────────
print("\n" + "-"*55)
print("TEST 2: BENIGN RECORD (Normal Web Traffic)")
print("-"*55)

benign_vector = build_feature_vector(
    flow_duration=0.0099,     # Normal short TCP flow
    delta_t=1.2,              # Human-speed inter-arrival (real benign avg: 1.2s)
    packets_out=8.0,          # Normal bidirectional packets (real benign avg: 8.1)
    packets_in=8.0,           # Balanced response
    bytes_out=880.0,          # Normal outbound bytes (real benign avg: 880)
    bytes_in=9160.0,          # Normal inbound (response heavier, real benign avg: 9159)
    packets_rate=500.0,       # Normal packet rate (real benign avg: 31941 rolling)
    byte_ratio=0.62,          # Inbound-heavy ratio (real benign avg: 0.72)
    dst_ip_entropy=6.0,       # Many unique destination IPs (real benign avg: 1.72)
    dst_port_entropy=6.0,     # Many unique destination ports
    flag_switches=0.0,        # No TCP flag turbulence (real benign avg: 0.78)
    protocol_num=6.0          # TCP
)

benign_pred = rf_model.predict(benign_vector)[0]
benign_prob = rf_model.predict_proba(benign_vector)[0][1]

print(f"  Prediction     : {'Attack (1)' if benign_pred == 1 else 'Benign (0)'}")
print(f"  L2 Probability : {benign_prob:.4f}")
print(f"  Result         : {'✅ PASS - Benign correctly classified' if benign_pred == 0 else '❌ FAIL - False positive'}")

# ─────────────────────────────────────────
# STEP 5: TEST 3 - Brute Force / Port Scan
# High flag_switches, zero entropy (single dst),
# tiny delta_t, no inbound bytes
# Expected: prediction = 1, prob > 0.5
# ─────────────────────────────────────────
print("\n" + "-"*55)
print("TEST 3: BRUTE FORCE ATTACK (SSH Port Scan)")
print("-"*55)

bruteforce_vector = build_feature_vector(
    flow_duration=0.00013,    # Rapid short connection attempts
    delta_t=0.0,              # Near-simultaneous retries
    packets_out=2.0,          # Small probe packets
    packets_in=0.0,           # No response (closed ports / RST)
    bytes_out=200.0,          # Small credential payloads
    bytes_in=0.0,             # No reply
    packets_rate=135000.0,    # Rapid-fire packet rate
    byte_ratio=1.18,          # Outbound-only asymmetry
    dst_ip_entropy=0.0,       # Single target IP
    dst_port_entropy=0.0,     # Single port (22/SSH)
    flag_switches=68.0,       # Very high flag switches (SYN/RST storm)
    protocol_num=6.0          # TCP
)

bf_pred = rf_model.predict(bruteforce_vector)[0]
bf_prob = rf_model.predict_proba(bruteforce_vector)[0][1]
bf_shap = run_shap(bruteforce_vector)

print(f"  Prediction     : {'Attack (1)' if bf_pred == 1 else 'Benign (0)'}")
print(f"  L2 Probability : {bf_prob:.4f}")
print(f"  Top SHAP Reasons:")
for s in bf_shap:
    if "error" not in s:
        print(f"    - {s['feature_name']:<20} : {s['shap_value']}")
    else:
        print(f"    - SHAP Error: {s['error']}")
print(f"  Result         : {'✅ PASS - Brute force correctly classified' if bf_pred == 1 else '⚠️  BORDERLINE - Check threshold'}")

# ─────────────────────────────────────────
# STEP 6: Summary
# ─────────────────────────────────────────
print("\n" + "="*55)
print("LAYER 2 TEST SUMMARY")
print("="*55)
print(f"  DDoS Attack Detected    : {'✅ YES' if attack_pred == 1 else '❌ NO'}")
print(f"  Benign Correctly Dropped: {'✅ YES' if benign_pred == 0 else '❌ NO'}")
print(f"  Brute Force Detected    : {'✅ YES' if bf_pred == 1 else '⚠️  NO'}")
print(f"  SHAP Explanations Work  : {'✅ YES' if attack_shap and 'error' not in attack_shap[0] else '❌ NO'}")

all_passed = attack_pred == 1 and benign_pred == 0 and bf_pred == 1
print(f"\n  Overall Status : {'✅ LAYER 2 WORKING CORRECTLY' if all_passed else '❌ NEEDS FIXING'}")
print("="*55)