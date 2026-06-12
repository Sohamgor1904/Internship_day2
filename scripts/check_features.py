import os
import pickle

# Resolve paths dynamically relative to project root
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
metadata_path = os.path.join(project_root, "data", "models", "metadata.pkl")

try:
    with open(metadata_path, "rb") as f:
        feature_names = pickle.load(f)
    print("Feature Names loaded successfully:")
    print(feature_names)
except Exception as e:
    print(f"Error loading features: {e}")
