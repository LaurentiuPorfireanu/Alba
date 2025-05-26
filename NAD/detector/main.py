#!/usr/bin/env python3
import asyncio
import uvicorn
from fastapi import FastAPI
from loguru import logger
import os
from contextlib import asynccontextmanager

from src.config import Settings
from src.api.routes import router, initialize_components
from src.database.connection import DatabaseManager

# Configurare logging
logger.add("logs/app.log", rotation="500 MB")

# Database manager global
db_manager = DatabaseManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Pornire Network Anomaly Detection System")
    db_manager.connect_mongodb()
    db_manager.connect_redis()
    
    # Initialize real-time components
    await initialize_components()
    
    yield
    
    # Shutdown
    logger.info("Oprire Network Anomaly Detection System")

# Initializare aplicatie
app = FastAPI(
    title="Network Anomaly Detection System",
    description="Sistem inteligent de detectie anomalii in traficul de retea cu capabilitati real-time",
    version="1.0.0",
    lifespan=lifespan
)

# Configurare
settings = Settings()

# Includere routes
app.include_router(router, prefix="/api/v1")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )