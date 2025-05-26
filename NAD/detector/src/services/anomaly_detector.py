import torch
import numpy as np
from loguru import logger
from sklearn.ensemble import IsolationForest
import joblib
import os
from typing import Dict, List, Any, Optional, Tuple
import time
from collections import deque
import asyncio

class AnomalyDetector:
    """
    Detector de anomalii optimizat pentru procesare real-time
    Combina multiple modele pentru detectie robusta
    """
    
    def __init__(self, models_path="/app/models"):
        self.models_path = models_path
        self.pytorch_model = None
        self.isolation_forest = None
        self.scaler = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Threshold management
        self.base_threshold = 0.5
        self.adaptive_threshold = 0.5
        self.threshold_history = deque(maxlen=100)
        
        # Performance tracking
        self.prediction_times = deque(maxlen=1000)
        self.confidence_scores = deque(maxlen=1000)
        
        # Ensemble weights
        self.model_weights = {
            'pytorch': 0.6,
            'isolation_forest': 0.4
        }
        
        logger.info("AnomalyDetector initialized")
    
    def load_models(self):
        """Incarca toate modelele antrenate"""
        try:
            # Load PyTorch model
            pytorch_path = os.path.join(self.models_path, "autoencoder.pth")
            if os.path.exists(pytorch_path):
                self._load_pytorch_model(pytorch_path)
                logger.info("PyTorch model loaded successfully")
            else:
                logger.warning(f"PyTorch model not found at {pytorch_path}")
            
            # Load Isolation Forest
            if_path = os.path.join(self.models_path, "isolation_forest.pkl")
            if os.path.exists(if_path):
                self.isolation_forest = joblib.load(if_path)
                logger.info("Isolation Forest loaded successfully")
            else:
                logger.warning(f"Isolation Forest not found at {if_path}")
            
            # Load scaler
            scaler_path = os.path.join(self.models_path, "scaler.pkl")
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info("Data scaler loaded successfully")
            else:
                logger.warning(f"Scaler not found at {scaler_path}")
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self._initialize_fallback_models()
    
    def _load_pytorch_model(self, pytorch_path: str):
        """Incarca modelul PyTorch"""
        try:
            from ..models.neural_network import AnomalyDetectionNN
            
            checkpoint = torch.load(pytorch_path, map_location=self.device)
            
            # Infer model architecture from checkpoint
            model_state = checkpoint['model_state_dict']
            
            # Get input size from first layer
            first_layer_key = next(iter(model_state.keys()))
            if 'encoder.0.weight' in model_state:
                input_size = model_state['encoder.0.weight'].shape[1]
            else:
                input_size = 51  # Default fallback
            
            # Initialize model
            self.pytorch_model = AnomalyDetectionNN(input_size, hidden_size=128)
            self.pytorch_model.load_state_dict(model_state)
            self.pytorch_model.to(self.device)
            self.pytorch_model.eval()
            
        except Exception as e:
            logger.error(f"Failed to load PyTorch model: {e}")
            self.pytorch_model = None
    
    def _initialize_fallback_models(self):
        """Initializeaza modele de fallback daca nu se pot incarca"""
        logger.info("Initializing fallback models...")
        
        # Simple threshold-based detector
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=50
        )
        
        # Fit on some dummy data for fallback
        dummy_data = np.random.normal(0, 1, (1000, 51))
        self.isolation_forest.fit(dummy_data)
        
        logger.info("Fallback models initialized")
    
    async def predict_anomaly_async(self, features_list: List[List[float]]) -> List[Tuple[bool, float]]:
        """Predictie asincrona pentru multiple samples"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.predict_anomaly, features_list)
    
    def predict_anomaly(self, features_list: List[List[float]]) -> List[Tuple[bool, float]]:
        """
        Detecteaza anomalii pentru o lista de features
        Returns: List of (is_anomaly, confidence) tuples
        """
        if not features_list:
            return []
        
        start_time = time.time()
        
        try:
            features_array = np.array(features_list, dtype=np.float32)
            
            # Validate input
            if features_array.shape[1] == 0:
                return [(False, 0.0) for _ in features_list]
            
            # Preprocess features
            if self.scaler:
                try:
                    features_array = self.scaler.transform(features_array)
                except Exception as e:
                    logger.warning(f"Scaler transform failed: {e}")
            
            # Get predictions from all models
            predictions = self._ensemble_predict(features_array)
            
            # Track performance
            prediction_time = (time.time() - start_time) * 1000  # ms
            self.prediction_times.append(prediction_time)
            
            return predictions
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return [(False, 0.0) for _ in features_list]
    
    def _ensemble_predict(self, features_array: np.ndarray) -> List[Tuple[bool, float]]:
        """Combina predictiile din multiple modele"""
        results = []
        batch_size = features_array.shape[0]
        
        # Get predictions from each model
        pytorch_scores = self._predict_pytorch(features_array)
        if_scores = self._predict_isolation_forest(features_array)
        
        for i in range(batch_size):
            # Combine scores using weights
            combined_score = 0.0
            weight_sum = 0.0
            
            if pytorch_scores is not None:
                combined_score += self.model_weights['pytorch'] * pytorch_scores[i]
                weight_sum += self.model_weights['pytorch']
            
            if if_scores is not None:
                combined_score += self.model_weights['isolation_forest'] * if_scores[i]
                weight_sum += self.model_weights['isolation_forest']
            
            # Normalize by total weights
            if weight_sum > 0:
                final_score = combined_score / weight_sum
            else:
                final_score = 0.0
            
            # Apply adaptive threshold
            is_anomaly = final_score > self.adaptive_threshold
            confidence = min(final_score, 1.0)
            
            results.append((is_anomaly, confidence))
            
            # Track confidence for adaptive thresholding
            self.confidence_scores.append(confidence)
        
        return results
    
    def _predict_pytorch(self, features_array: np.ndarray) -> Optional[np.ndarray]:
        """Predictie cu modelul PyTorch"""
        if self.pytorch_model is None:
            return None
        
        try:
            with torch.no_grad():
                features_tensor = torch.FloatTensor(features_array).to(self.device)
                anomaly_scores = self.pytorch_model.get_anomaly_scores(features_tensor)
                
                # Normalize scores to [0, 1]
                scores = anomaly_scores.cpu().numpy()
                scores = np.clip(scores / (scores.max() + 1e-8), 0, 1)
                
                return scores
                
        except Exception as e:
            logger.error(f"PyTorch prediction error: {e}")
            return None
    
    def _predict_isolation_forest(self, features_array: np.ndarray) -> Optional[np.ndarray]:
        """Predictie cu Isolation Forest"""
        if self.isolation_forest is None:
            return None
        
        try:
            # Get anomaly scores (lower = more anomalous)
            scores = self.isolation_forest.decision_function(features_array)
            
            # Convert to [0, 1] where higher = more anomalous
            # Normalize and invert
            scores_normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
            anomaly_scores = 1 - scores_normalized
            
            return anomaly_scores
            
        except Exception as e:
            logger.error(f"Isolation Forest prediction error: {e}")
            return None
    
    def update_adaptive_threshold(self):
        """Actualizeaza threshold-ul adaptiv bazat pe istoricul recent"""
        if len(self.confidence_scores) < 50:
            return
        
        try:
            recent_scores = list(self.confidence_scores)[-50:]
            
            # Calculate statistics
            mean_score = np.mean(recent_scores)
            std_score = np.std(recent_scores)
            
            # Adaptive threshold: mean + k*std
            # Adjust k based on recent anomaly rate
            anomaly_rate = sum(1 for score in recent_scores if score > self.adaptive_threshold) / len(recent_scores)
            
            if anomaly_rate > 0.15:  # Too many anomalies, increase threshold
                k = 2.0
            elif anomaly_rate < 0.05:  # Too few anomalies, decrease threshold
                k = 1.0
            else:
                k = 1.5
            
            new_threshold = max(0.3, min(0.8, mean_score + k * std_score))
            
            # Smooth threshold changes
            self.adaptive_threshold = 0.9 * self.adaptive_threshold + 0.1 * new_threshold
            self.threshold_history.append(self.adaptive_threshold)
            
            logger.debug(f"Adaptive threshold updated to: {self.adaptive_threshold:.3f}")
            
        except Exception as e:
            logger.error(f"Threshold update error: {e}")
    
    def get_model_performance(self) -> Dict[str, Any]:
        """Returneaza metrici de performanta"""
        recent_times = list(self.prediction_times)[-100:] if self.prediction_times else [0]
        recent_scores = list(self.confidence_scores)[-100:] if self.confidence_scores else [0]
        
        return {
            'models_loaded': {
                'pytorch': self.pytorch_model is not None,
                'isolation_forest': self.isolation_forest is not None,
                'scaler': self.scaler is not None
            },
            'performance': {
                'avg_prediction_time_ms': np.mean(recent_times),
                'max_prediction_time_ms': np.max(recent_times),
                'predictions_per_second': 1000 / (np.mean(recent_times) + 1e-8)
            },
            'thresholds': {
                'base_threshold': self.base_threshold,
                'adaptive_threshold': self.adaptive_threshold,
                'threshold_history': list(self.threshold_history)[-10:]
            },
            'detection_stats': {
                'avg_confidence': np.mean(recent_scores),
                'confidence_std': np.std(recent_scores),
                'high_confidence_rate': sum(1 for score in recent_scores if score > 0.8) / max(len(recent_scores), 1)
            },
            'device': str(self.device)
        }
    
    def set_model_weights(self, pytorch_weight: float, if_weight: float):
        """Actualizeaza ponderile modelelor in ensemble"""
        total = pytorch_weight + if_weight
        if total > 0:
            self.model_weights = {
                'pytorch': pytorch_weight / total,
                'isolation_forest': if_weight / total
            }
            logger.info(f"Model weights updated: {self.model_weights}")
    
    def force_threshold_update(self, new_threshold: float):
        """Forteaza actualizarea threshold-ului"""
        if 0.1 <= new_threshold <= 0.9:
            self.adaptive_threshold = new_threshold
            self.base_threshold = new_threshold
            logger.info(f"Threshold manually set to: {new_threshold}")
        else:
            raise ValueError("Threshold must be between 0.1 and 0.9")
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Returneaza importanta features (doar pentru Isolation Forest)"""
        if self.isolation_forest is None:
            return {}
        
        try:
            # For Isolation Forest, we can't get direct feature importance
            # But we can provide some insights based on model structure
            return {
                'isolation_forest_estimators': self.isolation_forest.n_estimators,
                'contamination_rate': self.isolation_forest.contamination,
                'note': 'Feature importance not directly available for Isolation Forest'
            }
        except Exception as e:
            logger.error(f"Feature importance error: {e}")
            return {}
    
    def reset_adaptive_threshold(self):
        """Reseteaza threshold-ul adaptiv la valoarea de baza"""
        self.adaptive_threshold = self.base_threshold
        self.threshold_history.clear()
        self.confidence_scores.clear()
        logger.info("Adaptive threshold reset")
    
    def export_detection_data(self, filepath: str):
        """Exporta datele de detectie pentru analiza"""
        try:
            export_data = {
                'timestamp': time.time(),
                'performance_metrics': self.get_model_performance(),
                'threshold_history': list(self.threshold_history),
                'confidence_scores': list(self.confidence_scores)[-1000:],  # Last 1000
                'prediction_times': list(self.prediction_times)[-1000:]     # Last 1000
            }
            
            import json
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Detection data exported to: {filepath}")
            
        except Exception as e:
            logger.error(f"Export error: {e}")