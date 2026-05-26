"""
LEVEL 3 VERIFICATION — End-to-End API Testing
Fires real HTTP requests against a running FastAPI server
and validates every field of the response JSON.

IMPORTANT: Start the server first (in a separate terminal) with:
    python -X utf8 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

Then run this script:
    python -X utf8 verify/level3_api_test.py
"""
import sys, os, time, json, subprocess
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

print("\n" + "="*60)
print("LEVEL 3 — END-TO-END API TESTING")
print("="*60)

# ── Check / start server ────────────────────────────────────
def _server_alive():
    try:
        urllib.request.urlopen(f"{BASE_URL}/api/v1/health", timeout=3)
        return True
    except urllib.error.HTTPError:
        return True   # Got an HTTP error back → server is alive
    except Exception:
        return False

server_proc    = None
server_managed = False

if _server_alive():
    print("\n[SERVER] Server already running on port 8000 — reusing it.")
else:
    print("\n[SERVER] Launching uvicorn in background...")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.api.main:app",
         "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    server_managed = True
    for _ in range(30):
        time.sleep(0.5)
        if _server_alive():
            break
    else:
        out, err = server_proc.communicate(timeout=2)
        print("  ❌ Server failed to start.")
        print("  STDOUT:", out.decode()[:300])
        print("  STDERR:", err.decode()[:300])
        sys.exit(1)

print("  ✅ Server ready at http://127.0.0.1:8000\n")


# ── Helpers ─────────────────────────────────────────────────
def post_json(path, payload):
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        f"{BASE_URL}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body.decode()[:200]}

def get_json(path):
    try:
        with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}

results = {}

# ── 3A: Health ───────────────────────────────────────────────
print("-"*60)
print("3A — HEALTH CHECK: GET /api/v1/health")
print("-"*60)
code, resp = get_json("/api/v1/health")
print(f"  HTTP Status  : {code}")
print(f"  Response     : {json.dumps(resp, indent=2)}")
pipeline_ok = resp.get("components", {}).get("pipeline") == "healthy"
print(f"  [CHECK] Pipeline healthy : {'✅ YES' if pipeline_ok else '❌ NO'}")
results["health"] = pipeline_ok

# ── 3B: Attack Record ────────────────────────────────────────
print("\n" + "-"*60)
print("3B — ATTACK RECORD: POST /api/v1/detect")
print("-"*60)

# Step 1: Warm up L1 filter with 20 benign calls so a stable
# baseline is established before injecting the attack record.
print("  [WARMUP] Sending 20 benign records to establish L1 baseline...")
for _w in range(20):
    post_json("/api/v1/detect", {
        "class_uid": 4001, "severity_id": 1,
        "time": 1700000000000 + _w * 2000,
        "src_endpoint": {"ip": f"10.0.1.{_w}", "port": 52000 + _w},
        "dst_endpoint": {"ip": "8.8.8.8", "port": 80},
        "traffic": {"bytes_in": 800 + _w * 10, "bytes_out": 200 + _w * 5,
                    "packets_in": 6, "packets_out": 4},
        "connection_info": {"protocol_num": 6, "protocol_name": "tcp", "state": "ESTABLISHED"},
        "metadata": {"version": "1.1.0", "product": {"name": "Warmup"},
                     "uid": f"warmup-{_w:03d}", "timestamp": "2024-01-01T00:00:00Z"},
        "enrichments": {"is_anomaly": 0, "label": "Benign", "dataset": "verify"}
    })
print("  [WARMUP] Baseline established.\n")

# Step 2: Send a burst of 10 rapid attack records from the SAME source IP
# to the SAME dst_port=22. This causes the rolling pipeline features to:
#   - delta_t → near 0 (ultra-fast bursts)
#   - dst_port_entropy → 0 (single port target)
#   - packets_rate → very high (tiny delta_t)
#   - byte_ratio → high (all outbound, no inbound)
#   - flag_switches → non-zero (alternating SYN and CON TCP states)
# These derived features match the RF's trained attack distribution.
print("  [ATTACK] Sending 10-record attack burst (same src→dst:22)...")
final_resp = None
final_code = None

# Time stamps: rapid-fire (1ms apart) after warmup
for _a in range(10):
    ts = 1700000500000 + _a * 1   # 1ms apart = ultra-fast flood
    state = "SYN" if _a % 2 == 0 else "CON"
    code_a, resp_a = post_json("/api/v1/detect", {
        "class_uid": 4001, "severity_id": 4,
        "time": ts,
        "src_endpoint": {"ip": "192.168.99.1", "port": 4444},
        "dst_endpoint": {"ip": "10.0.0.1",     "port": 22},
        "traffic": {
            "bytes_in":    1000,
            "bytes_out":   1180,
            "packets_in":  10,
            "packets_out": 10
        },
        "connection_info": {"protocol_num": 6, "protocol_name": "tcp", "state": state},
        "metadata": {
            "version": "1.1.0", "product": {"name": "VerifyTest"},
            "uid": f"verify-atk-{_a:03d}", "timestamp": "2024-01-01T00:00:50Z"
        },
        "enrichments": {"is_anomaly": 1, "label": "Attack", "dataset": "verify"}
    })
    final_code, final_resp = code_a, resp_a
    t_det = resp_a.get("threat_detected", False)
    l1_s  = resp_a.get("layer1", {}).get("anomaly_score", 0)
    l2_p  = resp_a.get("layer2", {}).get("threat_probability", 0)
    print(f"    Burst {_a+1}/10: threat={t_det}  L1={l1_s:.2f}  L2={l2_p:.3f}  layer={resp_a.get('layer_reached')}")
    if t_det:
        break  # Stop once threat is confirmed

code, resp = final_code, final_resp
print(f"\n  Final Response  :\n{json.dumps(resp, indent=4)}")

l1   = resp.get("layer1", {})
l2   = resp.get("layer2", {})
l3   = resp.get("layer3", {})
expl = l2.get("explanations", [])

l1_score = l1.get("anomaly_score", 0)
l1_score = l1_score if isinstance(l1_score, (int, float)) else 0
l2_prob  = l2.get("threat_probability", 0)
l2_prob  = l2_prob if isinstance(l2_prob, (int, float)) else 0

print(f"  L1 anomaly_score   : {l1_score:.4f}  (threshold=2.5)")
print(f"  L2 threat_prob     : {l2_prob:.4f}")
print(f"  SHAP explanations  : {len(expl)} features")
for e in expl[:3]:
    print(f"    {e.get('feature_name','?'):<20} shap={e.get('shap_value','?')}")

checks_3b = {
    "HTTP 200"          : code == 200,
    "threat_detected"   : resp.get("threat_detected") is True,
    "SHAP non-empty"    : len(expl) > 0,
    "SHAP values non-0" : any(abs(e.get("shap_value", 0)) > 0.001 for e in expl),
    "L1 score > 0"      : l1_score > 0,
}
for label, ok in checks_3b.items():
    print(f"  [CHECK] {label:<25}: {'✅' if ok else '❌'}")
results["attack"] = all(checks_3b.values())




# ── 3C: Benign Record ────────────────────────────────────────
print("\n" + "-"*60)
print("3C — BENIGN RECORD: POST /api/v1/detect")
print("-"*60)

benign_payload = {
    "class_uid": 4001, "severity_id": 1, "time": 1700000001000,
    "src_endpoint": {"ip": "192.168.1.200", "port": 52000},
    "dst_endpoint": {"ip": "8.8.8.8",       "port": 443},
    "traffic":      {"bytes_in": 9000, "bytes_out": 800, "packets_in": 8, "packets_out": 8},
    "connection_info": {"protocol_num": 6, "protocol_name": "tcp", "state": "ESTABLISHED"},
    "metadata": {
        "version": "1.1.0", "product": {"name": "VerifyTest"},
        "uid": "verify-ben-001", "timestamp": "2024-01-01T00:00:01Z"
    },
    "enrichments": {"is_anomaly": 0, "label": "Benign", "dataset": "verify"}
}

code, resp = post_json("/api/v1/detect", benign_payload)
print(f"  HTTP Status     : {code}")
print(f"  threat_detected : {resp.get('threat_detected')}")
print(f"  classification  : {resp.get('classification')}")
print(f"  layer_reached   : {resp.get('layer_reached')}")
checks_3c = {
    "HTTP 200"      : code == 200,
    "Not threat"    : resp.get("threat_detected") is False,
    "classification": resp.get("classification") == "Benign",
}
for label, ok in checks_3c.items():
    print(f"  [CHECK] {label:<25}: {'✅' if ok else '❌'}")
results["benign"] = all(checks_3c.values())

# ── 3D: Bad payload → 422 ───────────────────────────────────
print("\n" + "-"*60)
print("3D — PYDANTIC VALIDATION: POST with missing required fields")
print("-"*60)

bad_payload = {"bad_field": "garbage", "time": "not-a-number"}
code, resp  = post_json("/api/v1/detect", bad_payload)
print(f"  HTTP Status  : {code}  (expected 422)")
print(f"  [CHECK] Returns 422 Unprocessable Entity : {'✅ YES' if code == 422 else f'❌ NO — got {code}'}")
results["validation"] = code == 422

# ── Cleanup ──────────────────────────────────────────────────
if server_managed and server_proc:
    print("\n[SERVER] Stopping uvicorn...")
    server_proc.terminate()
    try:
        server_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server_proc.kill()
    print("  ✅ Server stopped.")
else:
    print("\n[SERVER] External server left running on port 8000.")

# ── Summary ──────────────────────────────────────────────────
print("\n" + "="*60)
print("LEVEL 3 TEST SUMMARY")
print("="*60)
print(f"  3A Health check pipeline healthy : {'✅ PASS' if results.get('health')     else '❌ FAIL'}")
print(f"  3B Attack payload flagged        : {'✅ PASS' if results.get('attack')     else '❌ FAIL'}")
print(f"  3C Benign payload dropped        : {'✅ PASS' if results.get('benign')     else '❌ FAIL'}")
print(f"  3D Bad JSON returns 422          : {'✅ PASS' if results.get('validation') else '❌ FAIL'}")
all_ok = all(results.values())
print(f"\n  Overall Status : {'✅ LEVEL 3 COMPLETE — API end-to-end verified' if all_ok else '⚠️  Some checks failed'}")
print("="*60)
