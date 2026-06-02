import os
import pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import shap

from config.settings import settings
from src.ingestion.mapper import OCSFDataIngestor
from src.features.pipeline import StreamingFeaturePipeline
from src.models.estimators import PyTorchLSTMModel

def main():
    print("Initializing Offline Model Training Pipeline...")
    
    # Create directories if they do not exist
    os.makedirs(settings.MODEL_DIR, exist_ok=True)
    
    # Initialize ingestion
    ingestor = OCSFDataIngestor(
        cic_dir=settings.CIC_DATA_DIR,
        unsw_dir=settings.UNSW_DATA_DIR,
        cse_dir=settings.CSE_DATA_DIR
    )
    
    # Initialize stateful feature pipeline
    feature_pipeline = StreamingFeaturePipeline(window_size=settings.L1_ROLLING_WINDOW_SIZE)
    
    # Define baseline date windows for training each source dataset
    import datetime
    now = datetime.datetime.utcnow()
    
    baseline_windows = {
        "unsw": (
            (now - datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"),
            (now + datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
        ),
        "cse": ("2018-02-14 00:00:00", "2018-02-16 23:59:59"),
        "cic": (
            (now - datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"),
            (now + datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
        )
    }
    
    # Ingest data from the defined date baseline windows (sampling up to 6,000 records from each for memory efficiency)
    records_per_dataset = 6000
    print("Ingesting datasets from baseline training date windows...")
    
    all_events = []
    
    print(f"- Reading CICIDS2017 baseline ({baseline_windows['cic'][0]} to {baseline_windows['cic'][1]})...")
    cic_events = list(ingestor.stream_dataset(
        "cic", max_records=records_per_dataset, 
        start_date=baseline_windows['cic'][0], end_date=baseline_windows['cic'][1]
    ))
    print(f"  Loaded {len(cic_events)} OCSF records.")
    all_events.extend(cic_events)
    
    print(f"- Reading UNSW-NB15 baseline ({baseline_windows['unsw'][0]} to {baseline_windows['unsw'][1]})...")
    unsw_events = list(ingestor.stream_dataset(
        "unsw", max_records=records_per_dataset,
        start_date=baseline_windows['unsw'][0], end_date=baseline_windows['unsw'][1]
    ))
    print(f"  Loaded {len(unsw_events)} OCSF records.")
    all_events.extend(unsw_events)
    
    print(f"- Reading CSE-CIC-IDS2018 baseline ({baseline_windows['cse'][0]} to {baseline_windows['cse'][1]})...")
    cse_events = list(ingestor.stream_dataset(
        "cse", max_records=records_per_dataset,
        start_date=baseline_windows['cse'][0], end_date=baseline_windows['cse'][1]
    ))
    print(f"  Loaded {len(cse_events)} OCSF records.")
    all_events.extend(cse_events)
    
    if not all_events:
        print("ERROR: No dataset records found. Please check data directories.")
        return
        
    print(f"Ingested {len(all_events)} total events. Sorting chronologically...")
    all_events.sort(key=lambda x: x["time"])
    
    feature_vectors = []
    labels = []
    
    print("Extracting streaming volumetric and temporal features...")
    for idx, event in enumerate(all_events):
        feats = feature_pipeline.extract_features(event, update_state=True)
        label = event["enrichments"]["is_anomaly"]
        
        feature_vectors.append(feats)
        labels.append(label)
        
    X = np.array(feature_vectors)
    y = np.array(labels)
    
    print(f"Feature matrix shape: {X.shape}, labels distribution: {np.bincount(y)}")
    
    # Fit and save StandardScaler to normalize inputs and prevent LSTM saturation
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"Saving StandardScaler to {settings.SCALER_PATH}...")
    with open(settings.SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
        
    # Re-construct ip_records for Layer 3 LSTM training using the scaled feature vectors
    ip_records = {}
    for idx, event in enumerate(all_events):
        src_ip = event["src_endpoint"]["ip"]
        if src_ip not in ip_records:
            ip_records[src_ip] = []
        ip_records[src_ip].append((X_scaled[idx], event["enrichments"]["is_anomaly"]))
        
    # ----------------------------------------------------
    # LAYER 2: Contextual Random Forest Training
    # ----------------------------------------------------
    print("\n--- Training Layer 2 Contextual Random Forest Classifier ---")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, random_state=42, stratify=y
    )
    
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)

    # Sanity Check & Metrics
    y_pred = rf.predict(X_test)
    print("\n===== RANDOM FOREST CLASSIFICATION REPORT =====")
    print(classification_report(y_test, y_pred))

    try:
        from sklearn.metrics import confusion_matrix
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        cm = confusion_matrix(y_test, y_pred)
        print("Confusion Matrix:")
        print(cm)

        os.makedirs('outputs', exist_ok=True)

        plt.figure(figsize=(6, 4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Benign', 'Attack'],
                    yticklabels=['Benign', 'Attack'])
        plt.title('Random Forest Confusion Matrix')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.tight_layout()
        plt.savefig('outputs/rf_confusion_matrix.png')
        plt.close()
        print("Saved confusion matrix plot to outputs/rf_confusion_matrix.png")
    except ImportError:
        print("Optional plotting dependencies not found. Skipping plot.")
    
    print(f"Saving Layer 2 Random Forest to {settings.RF_MODEL_PATH}...")
    with open(settings.RF_MODEL_PATH, "wb") as f:
        pickle.dump(rf, f)
        
    print("Initializing SHAP TreeExplainer...")
    bg_samples = shap.kmeans(X_train, 100) if len(X_train) > 100 else X_train
    explainer = shap.TreeExplainer(
        rf,
        data=bg_samples.data if hasattr(bg_samples, "data") else bg_samples
    )
    
    print(f"Saving SHAP explainer to {settings.SHAP_EXPLAINER_PATH}...")
    with open(settings.SHAP_EXPLAINER_PATH, "wb") as f:
        pickle.dump(explainer, f)
        
    print(f"Saving metadata to {settings.MODEL_METADATA_PATH}...")
    with open(settings.MODEL_METADATA_PATH, "wb") as f:
        pickle.dump(feature_pipeline.feature_names, f)
        
    # ----------------------------------------------------
    # LAYER 3: Sequential PyTorch LSTM Training
    # ----------------------------------------------------
    print("\n--- Training Layer 3 PyTorch Sequential LSTM ---")
    
    window_size = settings.L3_WINDOW_SIZE
    sequences_X = []
    sequences_y = []
    
    for ip, records in ip_records.items():
        if len(records) < window_size:
            continue
        for i in range(len(records) - window_size + 1):
            window = records[i : i + window_size]
            seq_feats = [r[0] for r in window]
            seq_label = window[-1][1]
            sequences_X.append(seq_feats)
            sequences_y.append(seq_label)
            
    if not sequences_X:
        print("WARNING: Insufficient histories. Using fallback window size 3.")
        window_size = 3
        for ip, records in ip_records.items():
            if len(records) < window_size:
                continue
            for i in range(len(records) - window_size + 1):
                window = records[i : i + window_size]
                seq_feats = [r[0] for r in window]
                padding = [
                    np.zeros_like(seq_feats[0])
                    for _ in range(settings.L3_WINDOW_SIZE - window_size)
                ]
                sequences_X.append(padding + seq_feats)
                sequences_y.append(window[-1][1])
                
    seq_X = np.array(sequences_X, dtype=np.float32)
    seq_y = np.array(sequences_y, dtype=np.float32)
    
    print(f"Sequential samples count: {seq_X.shape[0]}, shape: {seq_X.shape}")
    
    # Shuffle sequences
    indices = np.arange(seq_X.shape[0])
    np.random.shuffle(indices)
    seq_X = seq_X[indices]
    seq_y = seq_y[indices]
    
    split = int(0.7 * len(seq_X))
    X_train_seq, X_test_seq = seq_X[:split], seq_X[split:]
    y_train_seq, y_test_seq = seq_y[:split], seq_y[split:]
    
    # Initialize PyTorch components
    lstm_model = PyTorchLSTMModel()
    criterion  = nn.BCELoss()
    optimizer  = optim.Adam(lstm_model.parameters(), lr=0.001)

    # ─────────────────────────────────────────
    # Increased to 20 epochs with early stopping
    # Saves best weights based on lowest loss
    # ─────────────────────────────────────────
    batch_size   = 64
    epochs       = 20          # Increased from 5 to 20
    patience     = 5           # Stop if no improvement for 5 epochs
    num_samples  = X_train_seq.shape[0]
    
    print(f"Training LSTM for {epochs} epochs with early stopping "
          f"(patience={patience}, batch size={batch_size})...")
    
    best_loss        = float('inf')
    best_model_state = None
    epochs_no_improve = 0

    for epoch in range(epochs):
        lstm_model.train()
        epoch_loss = 0.0
        
        for i in range(0, num_samples, batch_size):
            x_batch = torch.tensor(X_train_seq[i : i + batch_size])
            y_batch = torch.tensor(
                y_train_seq[i : i + batch_size]
            ).unsqueeze(1)
            
            optimizer.zero_grad()
            outputs = lstm_model(x_batch)
            loss    = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item() * x_batch.size(0)
            
        avg_loss = epoch_loss / num_samples

        # Check if this is the best epoch
        if avg_loss < best_loss:
            best_loss        = avg_loss
            best_model_state = {
                k: v.cpu().clone()
                for k, v in lstm_model.state_dict().items()
            }
            epochs_no_improve = 0
            print(f"  Epoch {epoch+1:02d}/{epochs} - Loss: {avg_loss:.4f} - Best")
        else:

            epochs_no_improve += 1
            print(f"  Epoch {epoch+1:02d}/{epochs} - Loss: {avg_loss:.4f} "
                  f"(no improvement {epochs_no_improve}/{patience})")

        # Early stopping check
        if epochs_no_improve >= patience:
            print(f"\n  Early stopping triggered at epoch {epoch+1}. "
                  f"Best loss: {best_loss:.4f}")
            break

    # Restore best weights
    if best_model_state is not None:
        lstm_model.load_state_dict(best_model_state)
        print(f"\nRestored best weights with loss: {best_loss:.4f}")
        
    # Evaluate LSTM on test set
    lstm_model.eval()
    with torch.no_grad():
        x_test_tensor = torch.tensor(X_test_seq)
        test_preds    = lstm_model(x_test_tensor).numpy()
        test_preds_bin = (test_preds > 0.5).astype(int)
        
    test_acc = accuracy_score(y_test_seq, test_preds_bin)
    print(f"LSTM Test Accuracy (best epoch weights): {test_acc:.4f}")

    # Save LSTM confusion matrix
    try:
        from sklearn.metrics import confusion_matrix
        import matplotlib.pyplot as plt
        import seaborn as sns

        cm_lstm = confusion_matrix(y_test_seq, test_preds_bin)
        plt.figure(figsize=(6, 4))
        sns.heatmap(cm_lstm, annot=True, fmt='d', cmap='Oranges',
                    xticklabels=['Benign', 'Attack'],
                    yticklabels=['Benign', 'Attack'])
        plt.title('LSTM Confusion Matrix (Best Epoch)')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.tight_layout()
        plt.savefig('outputs/lstm_confusion_matrix.png')
        plt.close()
        print("Saved LSTM confusion matrix to outputs/lstm_confusion_matrix.png")
    except ImportError:
        pass

    # Save best LSTM weights
    print(f"Saving Layer 3 LSTM model (best loss: {best_loss:.4f}) "
          f"to {settings.LSTM_MODEL_PATH}...")
    torch.save(
        best_model_state if best_model_state is not None
        else lstm_model.state_dict(),
        settings.LSTM_MODEL_PATH
    )
    
    print("\nModel Training Pipeline Completed Successfully!")
    
    # Auto-generate the PDF Performance Report
    print("\nCompiling automated model evaluation PDF report...")
    try:
        from src.reporting.generator import generate_pdf_report
        generate_pdf_report()
    except Exception as e:
        print(f"[WARNING] Failed to generate automated PDF report: {e}")

if __name__ == "__main__":
    main()