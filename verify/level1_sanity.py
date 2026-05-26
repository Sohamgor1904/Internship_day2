"""
LEVEL 1 VERIFICATION — Training Metrics Sanity Check
Runs on held-out data to confirm RF is not overfitting
and LSTM accuracy drops when sequences are reversed.
Run: python -X utf8 verify/level1_sanity.py
"""
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pickle
import numpy as np
import torch
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from config.settings import settings
from src.ingestion.mapper import OCSFDataIngestor
from src.features.pipeline import StreamingFeaturePipeline
from src.models.estimators import PyTorchLSTMModel

print("\n" + "="*60)
print("LEVEL 1 — SANITY CHECK: TRAINING METRICS VERIFICATION")
print("="*60)

# ── Load Artifacts ──────────────────────────────────────────
with open(settings.RF_MODEL_PATH, "rb") as f:    rf_model = pickle.load(f)
with open(settings.SCALER_PATH, "rb") as f:      scaler   = pickle.load(f)
with open(settings.MODEL_METADATA_PATH, "rb") as f: feature_names = pickle.load(f)

# ── Ingest fresh test data ───────────────────────────────────
print("\n[DATA] Ingesting fresh held-out test data (3000 rows each)...")
ingestor = OCSFDataIngestor(
    cic_dir=settings.CIC_DATA_DIR,
    unsw_dir=settings.UNSW_DATA_DIR,
    cse_dir=settings.CSE_DATA_DIR
)
fp = StreamingFeaturePipeline(window_size=settings.L1_ROLLING_WINDOW_SIZE)

all_events = []
for src in ["cic", "unsw", "cse"]:
    all_events.extend(list(ingestor.stream_dataset(src, max_records=3000)))
all_events.sort(key=lambda x: x["time"])

X_raw, y = [], []
for ev in all_events:
    X_raw.append(fp.extract_features(ev, update_state=True))
    y.append(ev["enrichments"]["is_anomaly"])

X_raw = np.array(X_raw)
y     = np.array(y)
X     = scaler.transform(X_raw)

_, X_test, _, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
print(f"  Test samples : {len(y_test)}")
print(f"  Class distribution → Benign: {(y_test==0).sum()}, Attack: {(y_test==1).sum()}")

# ── RF Confusion Matrix ──────────────────────────────────────
print("\n" + "-"*60)
print("1A — RANDOM FOREST CONFUSION MATRIX (Held-Out Test Set)")
print("-"*60)
y_pred = rf_model.predict(X_test)
cm     = confusion_matrix(y_test, y_pred)
tn, fp_val, fn, tp = cm.ravel()

print(f"  True  Negatives (Benign correct)   : {tn}")
print(f"  False Positives (False alarms)      : {fp_val}")
print(f"  False Negatives (Missed attacks) ⚠️  : {fn}")
print(f"  True  Positives (Attacks caught)   : {tp}")
print(f"\n  Attack Recall (TPR) : {tp/(tp+fn)*100:.2f}%")
print(f"  Benign Precision    : {tn/(tn+fp_val)*100:.2f}%")
print()
print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))

majority_cheat = (y_pred == 1).all() or (y_pred == 0).all()
fn_acceptable  = fn / (tp + fn) < 0.05  # < 5% miss rate
print(f"  [CHECK] Majority class cheating     : {'❌ YES — model is cheating!' if majority_cheat else '✅ NO'}")
print(f"  [CHECK] Miss rate < 5%              : {'✅ YES' if fn_acceptable else '⚠️  HIGH — review training'}")

# ── LSTM Sequence Order Test ─────────────────────────────────
print("\n" + "-"*60)
print("1B — LSTM SEQUENCE ORDER SENSITIVITY TEST")
print("-"*60)

lstm_model = PyTorchLSTMModel(input_size=len(feature_names),
                               hidden_size=settings.L3_HIDDEN_SIZE,
                               num_layers=settings.L3_NUM_LAYERS)
lstm_model.load_state_dict(torch.load(settings.LSTM_MODEL_PATH, map_location='cpu'))
lstm_model.eval()

# Build attack sequence windows from real IP records
ip_records = {}
for idx, ev in enumerate(all_events):
    ip = ev["src_endpoint"]["ip"]
    ip_records.setdefault(ip, []).append((scaler.transform(X_raw[idx:idx+1])[0], ev["enrichments"]["is_anomaly"]))

W = settings.L3_WINDOW_SIZE
attack_seqs, benign_seqs = [], []
for ip, recs in ip_records.items():
    if len(recs) < W: continue
    for i in range(len(recs) - W + 1):
        win   = recs[i:i+W]
        label = win[-1][1]
        seqf  = [r[0] for r in win]
        if label == 1 and len(attack_seqs) < 50:
            attack_seqs.append(seqf)
        elif label == 0 and len(benign_seqs) < 50:
            benign_seqs.append(seqf)
        if len(attack_seqs) >= 50 and len(benign_seqs) >= 50:
            break

def batch_lstm(seqs):
    t = torch.tensor(np.array(seqs), dtype=torch.float32)
    with torch.no_grad():
        return (lstm_model(t).numpy() > 0.5).astype(int).flatten()

def batch_lstm_prob(seqs):
    t = torch.tensor(np.array(seqs), dtype=torch.float32)
    with torch.no_grad():
        return lstm_model(t).numpy().flatten()

if attack_seqs and benign_seqs:
    # Forward accuracy
    fwd_preds  = batch_lstm(attack_seqs)
    fwd_acc    = fwd_preds.mean()

    # Reversed accuracy
    rev_seqs   = [list(reversed(s)) for s in attack_seqs]
    rev_preds  = batch_lstm(rev_seqs)
    rev_acc    = rev_preds.mean()

    # Benign sequences should score low
    ben_preds  = batch_lstm(benign_seqs)
    ben_acc    = ben_preds.mean()

    print(f"  Attack sequences (forward)  → Attack rate: {fwd_acc*100:.1f}%")
    print(f"  Attack sequences (reversed) → Attack rate: {rev_acc*100:.1f}%")
    print(f"  Benign sequences            → Attack rate: {ben_acc*100:.1f}%")

    fwd_probs = batch_lstm_prob(attack_seqs)
    rev_probs = batch_lstm_prob(rev_seqs)
    avg_diff  = np.abs(fwd_probs - rev_probs).mean()

    print(f"\n  Mean prob difference (fwd vs rev): {avg_diff:.4f}")
    order_sensitive = avg_diff > 0.05
    print(f"  [CHECK] LSTM order-sensitive (Δ > 0.05): {'✅ YES' if order_sensitive else '⚠️  NO — may be ignoring sequence'}")
    print(f"  [CHECK] Benign correctly ignored        : {'✅ YES' if ben_acc < 0.3 else '⚠️  HIGH false positive rate'}")
else:
    print("  ⚠️  Insufficient sequences for LSTM order test")

print("\n" + "="*60)
print("LEVEL 1 COMPLETE")
print("="*60)
