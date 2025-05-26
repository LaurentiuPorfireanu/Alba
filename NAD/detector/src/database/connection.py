from pymongo import MongoClient
import redis
from loguru import logger
import os

class DatabaseManager:
    def __init__(self):
        self.mongo_client = None
        self.redis_client = None
        self.db = None
        
    def connect_mongodb(self, url="mongodb://mongo:27017"):
        """Conectare la MongoDB"""
        try:
            self.mongo_client = MongoClient(url)
            self.db = self.mongo_client.anomaly_detection
            logger.info("Conectat la MongoDB")
        except Exception as e:
            logger.error(f"Eroare conectare MongoDB: {e}")
    
    def connect_redis(self, url="redis://redis:6379"):
        """Conectare la Redis"""
        try:
            self.redis_client = redis.from_url(url)
            self.redis_client.ping()
            logger.info("Conectat la Redis")
        except Exception as e:
            logger.error(f"Eroare conectare Redis: {e}")
    
    def save_detection_result(self, data):
        """Salveaza rezultatul detectiei"""
        if self.db:
            self.db.detections.insert_one(data)
    
    def get_recent_detections(self, limit=100):
        """Returneaza detectiile recente"""
        if self.db:
            return list(self.db.detections.find().sort("timestamp", -1).limit(limit))
        return []