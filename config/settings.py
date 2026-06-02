import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # API settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = False

    # Local Dataset Folders
    CIC_DATA_DIR: str = os.getenv("CIC_DATA_DIR", "./data/cic/")
    UNSW_DATA_DIR: str = os.getenv("UNSW_DATA_DIR", "./data/unsw/")
    CSE_DATA_DIR: str = os.getenv("CSE_DATA_DIR", "./data/cse/")
    
    # Model Export Folders
    MODEL_DIR: str = os.getenv("MODEL_DIR", "./data/models/")
    RF_MODEL_PATH: str = os.path.join(MODEL_DIR, "random_forest.pkl")
    SHAP_EXPLAINER_PATH: str = os.path.join(MODEL_DIR, "shap_explainer.pkl")
    LSTM_MODEL_PATH: str = os.path.join(MODEL_DIR, "lstm_threat.pt")
    MODEL_METADATA_PATH: str = os.path.join(MODEL_DIR, "metadata.pkl")
    SCALER_PATH: str = os.path.join(MODEL_DIR, "scaler.pkl")

    # Layer 1 - Statistical Filter Configuration
    L1_ANOMALY_THRESHOLD: float = float(os.getenv("L1_ANOMALY_THRESHOLD", "2.5"))
    L1_EWMA_ALPHA: float = float(os.getenv("L1_EWMA_ALPHA", "0.2"))
    L1_ROLLING_WINDOW_SIZE: int = int(os.getenv("L1_ROLLING_WINDOW_SIZE", "100"))
    L1_WEIGHT_Z: float = 0.4
    L1_WEIGHT_EWMA: float = 0.3
    L1_WEIGHT_ENTROPY: float = 0.3

    # Layer 2 - Random Forest Configuration
    L2_ATTRIBUTION_FEATURES_COUNT: int = 5  # Top features to return in SHAP

    # Layer 3 - PyTorch LSTM Configuration
    L3_WINDOW_SIZE: int = int(os.getenv("L3_WINDOW_SIZE", "10"))
    L3_HIDDEN_SIZE: int = 64
    L3_NUM_LAYERS: int = 2
    L3_INPUT_SIZE: int = 12  # Number of input features to LSTM sequence

    # Database Configuration (PostgreSQL with asyncpg default)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql+asyncpg://postgres:postgres@db:5432/threat_detection"
    )

    # Production Pipeline and Reliability settings
    MODEL_VERSION: str = os.getenv("MODEL_VERSION", "1.0.0")
    DB_BATCH_SIZE: int = int(os.getenv("DB_BATCH_SIZE", "100"))
    DB_BATCH_INTERVAL: float = float(os.getenv("DB_BATCH_INTERVAL", "5.0"))
    DB_MAX_RETRIES: int = int(os.getenv("DB_MAX_RETRIES", "5"))
    DB_RETRY_BACKOFF: float = float(os.getenv("DB_RETRY_BACKOFF", "2.0"))
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json")

    class Config:
        env_file = ".env"

# Instantiate settings
settings = Settings()
