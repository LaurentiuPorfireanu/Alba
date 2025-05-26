import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
import os
import pickle
from loguru import logger
from tqdm import tqdm
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import joblib
from typing import Dict, Tuple, Optional, List

from ..models.neural_network import AnomalyDetectionNN, LSTMAnomalyDetector

class ModelTrainer:
    def __init__(self, model_type='autoencoder', device=None):
        self.device = device or torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model_type = model_type
        self.model = None
        self.optimizer = None
        self.criterion = nn.MSELoss()
        self.training_history = {'loss': [], 'val_loss': []}
        
        # Isolation Forest model
        self.isolation_forest = None
        
        logger.info(f"ModelTrainer initialized - Using device: {self.device}")
    
    def initialize_pytorch_model(self, input_size: int, hidden_size: int = 64):
        """Initializeaza modelul PyTorch"""
        if self.model_type == 'autoencoder':
            self.model = AnomalyDetectionNN(input_size, hidden_size)
        elif self.model_type == 'lstm':
            self.model = LSTMAnomalyDetector(input_size, hidden_size)
        else:
            raise ValueError(f"Model type {self.model_type} not supported")
        
        self.model.to(self.device)
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        
        logger.info(f"PyTorch model initialized: {self.model_type}")
        logger.info(f"Model parameters: {sum(p.numel() for p in self.model.parameters())}")
    
    def initialize_isolation_forest(self, contamination: float = 0.15):
        """Initializeaza Isolation Forest"""
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            bootstrap=False,
            n_jobs=-1
        )
        logger.info("Isolation Forest initialized")
    
    def train_autoencoder(self, train_loader: DataLoader, val_loader: DataLoader, 
                         epochs: int = 100, early_stopping_patience: int = 10):
        """Antreneaza autoencoder pentru detectia anomaliilor"""
        logger.info(f"Starting autoencoder training for {epochs} epochs")
        
        self.model.train()
        best_val_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(epochs):
            # Training loop
            train_loss = 0.0
            train_batches = 0
            
            for batch_data in tqdm(train_loader, desc=f'Epoch {epoch+1}/{epochs}'):
                if isinstance(batch_data, (list, tuple)):
                    data = batch_data[0]  # Only use features, not labels for autoencoder
                else:
                    data = batch_data
                
                data = data.to(self.device)
                
                self.optimizer.zero_grad()
                reconstructed = self.model(data)
                loss = self.criterion(reconstructed, data)
                loss.backward()
                self.optimizer.step()
                
                train_loss += loss.item()
                train_batches += 1
            
            # Validation loop
            val_loss = self._validate_autoencoder(val_loader)
            
            avg_train_loss = train_loss / train_batches
            self.training_history['loss'].append(avg_train_loss)
            self.training_history['val_loss'].append(val_loss)
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                self._save_checkpoint('best_autoencoder.pth')
            else:
                patience_counter += 1
            
            if (epoch + 1) % 10 == 0:
                logger.info(f'Epoch {epoch+1}/{epochs} - Train Loss: {avg_train_loss:.6f}, Val Loss: {val_loss:.6f}')
            
            # Early stopping
            if patience_counter >= early_stopping_patience:
                logger.info(f"Early stopping at epoch {epoch+1}")
                break
        
        logger.info("Autoencoder training completed")
    
    def train_isolation_forest(self, X_train: np.ndarray):
        """Antreneaza Isolation Forest"""
        logger.info("Training Isolation Forest...")
        
        if self.isolation_forest is None:
            self.initialize_isolation_forest()
        
        # Antrenarea pe traficul normal (pentru detectia anomaliilor)
        self.isolation_forest.fit(X_train)
        
        logger.info("Isolation Forest training completed")
    
    def _validate_autoencoder(self, val_loader: DataLoader) -> float:
        """Validare model autoencoder"""
        self.model.eval()
        val_loss = 0.0
        val_batches = 0
        
        with torch.no_grad():
            for batch_data in val_loader:
                if isinstance(batch_data, (list, tuple)):
                    data = batch_data[0]
                else:
                    data = batch_data
                
                data = data.to(self.device)
                reconstructed = self.model(data)
                loss = self.criterion(reconstructed, data)
                val_loss += loss.item()
                val_batches += 1
        
        return val_loss / val_batches
    
    def evaluate_models(self, test_loader: DataLoader, threshold: float = 0.5) -> Dict:
        """Evalueaza performanta modelelor"""
        logger.info("Evaluating models performance...")
        
        results = {
            'pytorch_predictions': [],
            'isolation_forest_predictions': [],
            'ensemble_predictions': [],
            'true_labels': []
        }
        
        # Colectare predictii
        self.model.eval()
        with torch.no_grad():
            for batch_data in test_loader:
                if isinstance(batch_data, (list, tuple)):
                    data, labels = batch_data
                    results['true_labels'].extend(labels.cpu().numpy())
                else:
                    data = batch_data
                    labels = None
                
                data_np = data.cpu().numpy()
                data = data.to(self.device)
                
                # PyTorch predictions
                if self.model:
                    reconstruction_errors = self.model.get_reconstruction_error(data)
                    pytorch_pred = (reconstruction_errors > threshold).cpu().numpy()
                    results['pytorch_predictions'].extend(pytorch_pred)
                
                # Isolation Forest predictions
                if self.isolation_forest:
                    if_pred = self.isolation_forest.predict(data_np) == -1
                    results['isolation_forest_predictions'].extend(if_pred)
        
        # Ensemble predictions (voting)
        if results['pytorch_predictions'] and results['isolation_forest_predictions']:
            pytorch_arr = np.array(results['pytorch_predictions'])
            if_arr = np.array(results['isolation_forest_predictions'])
            ensemble_pred = (pytorch_arr.astype(int) + if_arr.astype(int)) >= 1
            results['ensemble_predictions'] = ensemble_pred.tolist()
        
        # Calculate metrics
        metrics = self._calculate_metrics(results)
        
        return metrics
    
    def _calculate_metrics(self, results: Dict) -> Dict:
        """Calculeaza metrici de performanta"""
        metrics = {}
        
        if results['true_labels']:
            true_labels = np.array(results['true_labels'])
            
            # PyTorch metrics
            if results['pytorch_predictions']:
                pytorch_pred = np.array(results['pytorch_predictions'])
                metrics['pytorch'] = {
                    'accuracy': np.mean(pytorch_pred == true_labels),
                    'classification_report': classification_report(true_labels, pytorch_pred, output_dict=True),
                    'confusion_matrix': confusion_matrix(true_labels, pytorch_pred).tolist()
                }
                
                # ROC AUC daca avem probabilitati
                try:
                    metrics['pytorch']['roc_auc'] = roc_auc_score(true_labels, pytorch_pred)
                except:
                    pass
            
            # Isolation Forest metrics
            if results['isolation_forest_predictions']:
                if_pred = np.array(results['isolation_forest_predictions'])
                metrics['isolation_forest'] = {
                    'accuracy': np.mean(if_pred == true_labels),
                    'classification_report': classification_report(true_labels, if_pred, output_dict=True),
                    'confusion_matrix': confusion_matrix(true_labels, if_pred).tolist()
                }
                
                try:
                    metrics['isolation_forest']['roc_auc'] = roc_auc_score(true_labels, if_pred)
                except:
                    pass
            
            # Ensemble metrics
            if results['ensemble_predictions']:
                ensemble_pred = np.array(results['ensemble_predictions'])
                metrics['ensemble'] = {
                    'accuracy': np.mean(ensemble_pred == true_labels),
                    'classification_report': classification_report(true_labels, ensemble_pred, output_dict=True),
                    'confusion_matrix': confusion_matrix(true_labels, ensemble_pred).tolist()
                }
                
                try:
                    metrics['ensemble']['roc_auc'] = roc_auc_score(true_labels, ensemble_pred)
                except:
                    pass
        
        return metrics
    
    def tune_hyperparameters(self, train_loader: DataLoader, val_loader: DataLoader,
                           param_grid: Dict) -> Dict:
        """Grid search pentru tuning hiperparametri"""
        logger.info("Starting hyperparameter tuning...")
        
        best_params = {}
        best_loss = float('inf')
        results = []
        
        # Pentru autoencoder
        if 'hidden_sizes' in param_grid:
            for hidden_size in param_grid['hidden_sizes']:
                for learning_rate in param_grid.get('learning_rates', [0.001]):
                    logger.info(f"Testing hidden_size={hidden_size}, lr={learning_rate}")
                    
                    # Initialize model
                    input_size = next(iter(train_loader))[0].shape[1]
                    self.initialize_pytorch_model(input_size, hidden_size)
                    self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
                    
                    # Train for few epochs
                    self.train_autoencoder(train_loader, val_loader, epochs=20)
                    
                    # Get validation loss
                    val_loss = self._validate_autoencoder(val_loader)
                    
                    results.append({
                        'hidden_size': hidden_size,
                        'learning_rate': learning_rate,
                        'val_loss': val_loss
                    })
                    
                    if val_loss < best_loss:
                        best_loss = val_loss
                        best_params = {
                            'hidden_size': hidden_size,
                            'learning_rate': learning_rate
                        }
        
        logger.info(f"Best parameters: {best_params}")
        return {'best_params': best_params, 'all_results': results}
    
    def save_models(self, base_path: str):
        """Salveaza toate modelele"""
        os.makedirs(base_path, exist_ok=True)
        
        # Save PyTorch model
        if self.model:
            pytorch_path = os.path.join(base_path, "autoencoder.pth")
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'optimizer_state_dict': self.optimizer.state_dict(),
                'model_type': self.model_type,
                'training_history': self.training_history
            }, pytorch_path)
            logger.info(f"PyTorch model saved to: {pytorch_path}")
        
        # Save Isolation Forest
        if self.isolation_forest:
            if_path = os.path.join(base_path, "isolation_forest.pkl")
            joblib.dump(self.isolation_forest, if_path)
            logger.info(f"Isolation Forest saved to: {if_path}")
    
    def load_models(self, base_path: str, input_size: int):
        """Incarca modelele salvate"""
        # Load PyTorch model
        pytorch_path = os.path.join(base_path, "autoencoder.pth")
        if os.path.exists(pytorch_path):
            checkpoint = torch.load(pytorch_path, map_location=self.device)
            self.model_type = checkpoint['model_type']
            self.initialize_pytorch_model(input_size)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            self.training_history = checkpoint['training_history']
            logger.info(f"PyTorch model loaded from: {pytorch_path}")
        
        # Load Isolation Forest
        if_path = os.path.join(base_path, "isolation_forest.pkl")
        if os.path.exists(if_path):
            self.isolation_forest = joblib.load(if_path)
            logger.info(f"Isolation Forest loaded from: {if_path}")
    
    def _save_checkpoint(self, filename: str):
        """Salveaza checkpoint intermediar"""
        if self.model:
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'optimizer_state_dict': self.optimizer.state_dict(),
                'training_history': self.training_history
            }, filename)
    
    def plot_training_history(self, save_path: Optional[str] = None):
        """Afiseaza istoricul antrenamentului"""
        if not self.training_history['loss']:
            logger.warning("No training history to plot")
            return
        
        plt.figure(figsize=(12, 5))
        
        # Loss plot
        plt.subplot(1, 2, 1)
        plt.plot(self.training_history['loss'], label='Training Loss', color='blue')
        plt.plot(self.training_history['val_loss'], label='Validation Loss', color='red')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.title('Training and Validation Loss')
        plt.legend()
        plt.grid(True)
        
        # Anomaly threshold plot
        plt.subplot(1, 2, 2)
        if self.training_history['val_loss']:
            thresholds = np.linspace(0.1, 2.0, 100)
            plt.plot(thresholds, thresholds, label='Threshold Values')
            plt.axhline(y=np.mean(self.training_history['val_loss']), 
                       color='red', linestyle='--', label='Mean Val Loss')
            plt.xlabel('Threshold')
            plt.ylabel('Value')
            plt.title('Threshold Analysis')
            plt.legend()
            plt.grid(True)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Training plots saved to: {save_path}")
        
        plt.show()
    
    def get_model_summary(self) -> Dict:
        """Returneaza sumar modele"""
        summary = {
            'device': str(self.device),
            'pytorch_model': None,
            'isolation_forest': None
        }
        
        if self.model:
            summary['pytorch_model'] = {
                'type': self.model_type,
                'parameters': sum(p.numel() for p in self.model.parameters()),
                'trainable_parameters': sum(p.numel() for p in self.model.parameters() if p.requires_grad)
            }
        
        if self.isolation_forest:
            summary['isolation_forest'] = {
                'n_estimators': self.isolation_forest.n_estimators,
                'contamination': self.isolation_forest.contamination,
                'max_samples': self.isolation_forest.max_samples
            }
        
        return summary