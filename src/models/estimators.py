import pickle
import math
import numpy as np
import torch
import torch.nn as nn
import shap
from typing import Dict, Any, List, Tuple
from collections import deque
from config.settings import settings

# Layer 1: Volumetric Statistical Filter State Machine
class VolumetricStatisticalFilter:
    """Ingestion-stage volumetric filter using rolling stats, EWMA, and Shannon entropy."""
    
    def __init__(self):
        self.count = 0
        self.mean_rate = 0.0
        self.m2_rate = 0.0
        self.ewma_volume = 0.0
        self.alpha = settings.L1_EWMA_ALPHA
        self.threshold = settings.L1_ANOMALY_THRESHOLD
        
        # History of Shannon entropy and rates to calibrate threshold
        self.entropy_history = deque(maxlen=settings.L1_ROLLING_WINDOW_SIZE)
        self.rate_history = deque(maxlen=settings.L1_ROLLING_WINDOW_SIZE)
        
    def update(self, delta_t: float, bytes_total: int, dst_port: int, protocol: int) -> Tuple[bool, float]:
        """
        Updates statistical indicators with the current flow details.
        Returns:
            passed_triage: True if event crosses the anomaly threshold (route to L2)
            anomaly_score: Combined statistical anomaly score
        """
        self.count += 1
        
        # 1. Rate calculation: instantaneous flow rate
        rate = 1.0 / (delta_t + 1e-3)
        self.rate_history.append(rate)
        
        # Update mean and variance using Welford's algorithm
        if self.count == 1:
            self.mean_rate = rate
            self.m2_rate = 0.0
        else:
            delta = rate - self.mean_rate
            self.mean_rate += delta / self.count
            delta_2 = rate - self.mean_rate
            self.m2_rate += delta * delta_2
            
        std_rate = math.sqrt(self.m2_rate / (self.count - 1)) if self.count > 1 else 0.0
        z_score = abs(rate - self.mean_rate) / (std_rate + 1e-6)
        
        # 2. EWMA Volume
        if self.count == 1:
            self.ewma_volume = float(bytes_total)
        else:
            self.ewma_volume = self.alpha * bytes_total + (1.0 - self.alpha) * self.ewma_volume
            
        volume_variation = abs(bytes_total - self.ewma_volume) / (self.ewma_volume + 1e-6)
        
        # 3. Shannon Entropy of Ports (using rate history as dynamic base)
        # For simplicity, we compute port distribution entropy in the current rate window
        # We simulate baseline entropy of a clean network as ~3.5. Lower entropy = concentration (attacks)
        self.entropy_history.append(dst_port)
        entropy_t = self._calculate_rolling_entropy()
        baseline_entropy = 3.5
        entropy_dev = max(0.0, baseline_entropy - entropy_t)
        
        # 4. Combined Anomaly Score
        # Weighted sum: 40% Z-Score, 30% EWMA Volume variation, 30% Port concentration
        anomaly_score = (
            settings.L1_WEIGHT_Z * min(z_score, 5.0) / 5.0 + 
            settings.L1_WEIGHT_EWMA * min(volume_variation, 5.0) / 5.0 + 
            settings.L1_WEIGHT_ENTROPY * min(entropy_dev, 3.5) / 3.5
        ) * 5.0  # Scale score to 0 - 5.0 range
        
        # Trigger L2 routing if combined score exceeds threshold standard deviations
        passed_triage = anomaly_score >= self.threshold
        
        return passed_triage, float(anomaly_score)

    def _calculate_rolling_entropy(self) -> float:
        if not self.entropy_history:
            return 0.0
        total = len(self.entropy_history)
        from collections import Counter
        counts = Counter(self.entropy_history)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * np.log2(p)
        return entropy


# Layer 2: Contextual Classifier (RF + SHAP Explainer)
class ContextualClassifier:
    """Supervised Random Forest Classifier with integrated SHAP explainability."""
    
    def __init__(self, model_path: str = settings.RF_MODEL_PATH, explainer_path: str = settings.SHAP_EXPLAINER_PATH, feature_names: List[str] = None):
        self.model_path = model_path
        self.explainer_path = explainer_path
        self.feature_names = feature_names or []
        self.model = None
        self.explainer = None
        self.load_model()
        
    def load_model(self):
        """Loads serialized RandomForest model and SHAP Explainer from disk."""
        try:
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)
            with open(self.explainer_path, "rb") as f:
                self.explainer = pickle.load(f)
            print("Successfully loaded Layer 2 Random Forest classifier and SHAP explainer.")
        except Exception as e:
            print(f"Layer 2 models not found or failed to load: {e}. Run training script first.")
            
    def predict(self, features: np.ndarray) -> Tuple[int, float]:
        """
        Predicts threat probability using RandomForest.
        Returns:
            class_prediction: 1 for threat, 0 for normal
            probability: float probability [0.0 - 1.0]
        """
        if self.model is None:
            return 0, 0.0
        # features shape is (num_features,) -> reshape to (1, num_features)
        X = features.reshape(1, -1)
        prob = self.model.predict_proba(X)[0][1]
        pred = int(self.model.predict(X)[0])
        return pred, float(prob)
        
    def explain(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """
        Computes SHAP feature attributions for a single feature vector.
        Returns:
            explanations: List of {feature_name: str, shap_value: float} sorted by contribution
        """
        if self.explainer is None or not self.feature_names:
            return []
        
        X = features.reshape(1, -1)
        try:
            # Compute shap values
            shap_values = self.explainer.shap_values(X)
            
            # Robust parsing of SHAP output dimensions across library versions
            if isinstance(shap_values, list):
                # Typically index 1 corresponds to class 1 (attack)
                feat_shaps = shap_values[1][0]
            elif isinstance(shap_values, np.ndarray):
                if len(shap_values.shape) == 3:
                    # shape is (samples, features, classes)
                    feat_shaps = shap_values[0, :, 1]
                else:
                    # shape is (samples, features)
                    feat_shaps = shap_values[0]
            else:
                # TreeExplainer explanation object
                feat_shaps = shap_values.values[0]
                if len(feat_shaps.shape) == 2: # multi-class
                    feat_shaps = feat_shaps[:, 1]
            
            # Match shap values to feature names
            explanations = []
            for name, val in zip(self.feature_names, feat_shaps):
                explanations.append({
                    "feature_name": name,
                    "shap_value": float(val)
                })
                
            # Sort by absolute contribution value descending
            explanations.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            # Limit to configured top K count
            return explanations[:settings.L2_ATTRIBUTION_FEATURES_COUNT]
        except Exception as e:
            print(f"Failed to generate SHAP explanations: {e}")
            return []


# Layer 3: Chronological Sequential LSTM Model
class PyTorchLSTMModel(nn.Module):
    """PyTorch LSTM architecture for sequential host-level threat analysis."""
    
    def __init__(self, input_size: int = settings.L3_INPUT_SIZE, hidden_size: int = settings.L3_HIDDEN_SIZE, num_layers: int = settings.L3_NUM_LAYERS):
        super(PyTorchLSTMModel, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True
        )
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Initialize hidden state and cell state with zeros
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        
        # Forward propagate LSTM
        out, _ = self.lstm(x, (h0, c0))  # out: tensor of shape (batch_size, seq_len, hidden_size)
        
        # Decode the hidden state of the last time step
        out = self.fc(out[:, -1, :])
        out = self.sigmoid(out)
        return out


class Layer3LSTMTracker:
    """Manages IP sliding sequence history and executes chronological LSTM inference."""
    
    def __init__(self, model_path: str = settings.LSTM_MODEL_PATH):
        self.model_path = model_path
        self.device = torch.device("cpu")  # Laptop CPU fallback optimization
        self.model = None
        # IP sequence queues tracking sliding window of past feature vectors
        self.ip_sequences: Dict[str, deque] = {}
        self.load_model()
        
    def load_model(self):
        """Loads serialized PyTorch LSTM model from disk."""
        try:
            self.model = PyTorchLSTMModel()
            state_dict = torch.load(self.model_path, map_location=self.device)
            self.model.load_state_dict(state_dict)
            self.model.to(self.device)
            self.model.eval()
            print("Successfully loaded Layer 3 Sequential LSTM model weights.")
        except Exception as e:
            print(f"Layer 3 LSTM weights not found or failed to load: {e}. Run training script first.")
            self.model = None

    def evaluate_ip_sequence(self, ip_address: str, feature_vector: np.ndarray) -> float:
        """
        Appends the latest feature vector to the IP sequence queue and executes LSTM inference.
        Returns:
            threat_probability: probability of APT/sequential threat [0.0 - 1.0]
        """
        if self.model is None:
            return 0.0
            
        if ip_address not in self.ip_sequences:
            self.ip_sequences[ip_address] = deque(maxlen=settings.L3_WINDOW_SIZE)
            
        queue = self.ip_sequences[ip_address]
        queue.append(feature_vector)
        
        # LSTM requires a minimum sequence length to perform logical sequential inference.
        # Zero-pad sequence if queue is not full yet.
        seq_len = len(queue)
        features_list = list(queue)
        
        if seq_len < settings.L3_WINDOW_SIZE:
            padding_count = settings.L3_WINDOW_SIZE - seq_len
            padding = [np.zeros_like(feature_vector) for _ in range(padding_count)]
            features_list = padding + features_list
            
        # Shape: (1, seq_len, num_features)
        seq_tensor = torch.tensor(np.array([features_list]), dtype=torch.float32).to(self.device)
        
        with torch.no_grad():
            threat_prob = self.model(seq_tensor).item()
            
        return float(threat_prob)

    def reset(self):
        """Resets sequence tracking states."""
        self.ip_sequences.clear()
