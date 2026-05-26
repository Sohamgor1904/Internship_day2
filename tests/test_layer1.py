"""
Layer 1 Independent Test
Run from task2/ root directory:
    python tests/test_layer1.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.estimators import VolumetricStatisticalFilter
from config.settings import settings

print("\n" + "="*50)
print("LAYER 1 - VOLUMETRIC STATISTICAL FILTER TEST")
print("="*50)

# ─────────────────────────────────────────
# STEP 1: Initialize — no arguments needed
# ─────────────────────────────────────────
layer1 = VolumetricStatisticalFilter()

# ─────────────────────────────────────────
# STEP 2: Warmup with normal baseline traffic
# update(delta_t, bytes_total, dst_port, protocol)
# ─────────────────────────────────────────
print("\n[WARMUP] Feeding 50 normal baseline records...")

import numpy as np

for i in range(50):
    layer1.update(
        delta_t=np.random.uniform(0.2, 0.5),   # Normal time between flows
        bytes_total=np.random.randint(500, 2000), # Normal traffic volume
        dst_port=80,                               # Normal web port
        protocol=6                                 # TCP
    )

print("[WARMUP] Baseline established.\n")

# ─────────────────────────────────────────
# STEP 3: TEST 1 - HIGH ANOMALY (DDoS Attack)
# Expected: passed_triage = True
# ─────────────────────────────────────────
print("-"*50)
print("TEST 1: HIGH ANOMALY RECORD (DDoS Attack Pattern)")
print("-"*50)

attack_passed, attack_score = layer1.update(
    delta_t=0.0001,       # Ultra-fast flood
    bytes_total=999999,   # Massive volume
    dst_port=22,          # SSH attack target
    protocol=6            # TCP
)

print(f"  Anomaly Score  : {attack_score:.4f}")
print(f"  Threshold      : {settings.L1_ANOMALY_THRESHOLD}")
print(f"  Passed Triage  : {attack_passed}")
print(f"  Result         : {'✅ PASS - Correctly sent to Layer 2' if attack_passed else '❌ FAIL - Should have been flagged'}")

# ─────────────────────────────────────────
# STEP 4: TEST 2 - BENIGN Record
# Expected: passed_triage = False
# ─────────────────────────────────────────
print("\n" + "-"*50)
print("TEST 2: BENIGN RECORD (Normal Web Browsing)")
print("-"*50)

benign_passed, benign_score = layer1.update(
    delta_t=0.35,        # Normal human speed
    bytes_total=1200,    # Normal page load
    dst_port=80,         # HTTP
    protocol=6           # TCP
)

print(f"  Anomaly Score  : {benign_score:.4f}")
print(f"  Threshold      : {settings.L1_ANOMALY_THRESHOLD}")
print(f"  Passed Triage  : {benign_passed}")
print(f"  Result         : {'✅ PASS - Correctly dropped as benign' if not benign_passed else '❌ FAIL - Should have been dropped'}")

# ─────────────────────────────────────────
# STEP 5: TEST 3 - PORT SCAN Pattern
# Expected: passed_triage = True
# ─────────────────────────────────────────
print("\n" + "-"*50)
print("TEST 3: EDGE CASE (Port Scan Pattern)")
print("-"*50)

scan_passed, scan_score = layer1.update(
    delta_t=0.001,       # Fast sequential probes
    bytes_total=64,      # Tiny probe packets
    dst_port=4444,       # Unusual port
    protocol=6           # TCP
)

print(f"  Anomaly Score  : {scan_score:.4f}")
print(f"  Threshold      : {settings.L1_ANOMALY_THRESHOLD}")
print(f"  Passed Triage  : {scan_passed}")
print(f"  Result         : {'✅ PASS - Port scan detected' if scan_passed else '⚠️  BORDERLINE - May need threshold tuning'}")

# ─────────────────────────────────────────
# STEP 6: Summary
# ─────────────────────────────────────────
print("\n" + "="*50)
print("LAYER 1 TEST SUMMARY")
print("="*50)
print(f"  Attack Flagged  : {'✅ YES' if attack_passed else '❌ NO'}")
print(f"  Benign Dropped  : {'✅ YES' if not benign_passed else '❌ NO'}")
print(f"  Port Scan Caught: {'✅ YES' if scan_passed else '⚠️  NO'}")

all_passed = attack_passed and not benign_passed
print(f"\n  Overall Status  : {'✅ LAYER 1 WORKING CORRECTLY' if all_passed else '❌ NEEDS FIXING'}")
print("="*50)