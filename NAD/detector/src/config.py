import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    mongodb_url: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Paths
    data_path: str = "/app/data"
    models_path: str = "/app/models"
    logs_path: str = "/app/logs"
    
    # Model Parameters
    batch_size: int = 32
    epochs: int = 100
    learning_rate: float = 0.001
    hidden_size: int = 64
    
    # Detection Parameters
    anomaly_threshold: float = 0.5
    
    # Dataset
    dataset_url: str = "https://www.unb.ca/cic/datasets/ids-2017.html"
    
    class Config:
        env_file = ".env"