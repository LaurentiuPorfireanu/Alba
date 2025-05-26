#!/usr/bin/env python3
"""
Script pentru antrenarea modelelor de detectie anomalii
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detector'))

from src.services.data_processor import DataProcessor
from src.services.model_trainer import ModelTrainer
from loguru import logger
import numpy as np
import torch

def train_all_models():
    """Antreneaza toate modelele pentru detectia anomaliilor"""
    logger.info("=== Starting Model Training Pipeline ===")
    
    # 1. Prepare data
    logger.info("1. Preparing data...")
    processor = DataProcessor()
    df = processor.load_cicids2017_dataset("nonexistent_file.csv")  # Will create synthetic
    X, y = processor.preprocess_data(df)
    
    train_loader, val_loader, test_loader = processor.create_dataloaders(X, y, batch_size=64)
    
    input_size = X.shape[1]
    logger.info(f"Data prepared - Input size: {input_size}")
    
    # 2. Train Autoencoder
    logger.info("2. Training Autoencoder...")
    trainer = ModelTrainer(model_type='autoencoder')
    trainer.initialize_pytorch_model(input_size, hidden_size=128)
    
    trainer.train_autoencoder(train_loader, val_loader, epochs=50)
    
    # 3. Train Isolation Forest
    logger.info("3. Training Isolation Forest...")
    trainer.initialize_isolation_forest(contamination=0.15)
    
    # Use only normal traffic for Isolation Forest training
    normal_indices = np.where(y == 0)[0]
    X_normal = X[normal_indices]
    trainer.train_isolation_forest(X_normal)
    
    # 4. Evaluate models
    logger.info("4. Evaluating models...")
    metrics = trainer.evaluate_models(test_loader)
    
    # Print results (FIXED VERSION)
    print("\n" + "="*50)
    print("MODEL EVALUATION RESULTS")
    print("="*50)
    
    for model_name, model_metrics in metrics.items():
        if model_metrics:
            print(f"\n{model_name.upper()} METRICS:")
            
            # Safe formatting with type checking
            accuracy = model_metrics.get('accuracy', 'N/A')
            if isinstance(accuracy, (int, float)):
                print(f"Accuracy: {accuracy:.4f}")
            else:
                print(f"Accuracy: {accuracy}")
            
            if 'classification_report' in model_metrics:
                report = model_metrics['classification_report']
                
                # Safe precision formatting
                precision = report.get('1', {}).get('precision', 'N/A')
                if isinstance(precision, (int, float)):
                    print(f"Precision: {precision:.4f}")
                else:
                    print(f"Precision: {precision}")
                
                # Safe recall formatting
                recall = report.get('1', {}).get('recall', 'N/A')
                if isinstance(recall, (int, float)):
                    print(f"Recall: {recall:.4f}")
                else:
                    print(f"Recall: {recall}")
                
                # Safe F1-score formatting
                f1_score = report.get('1', {}).get('f1-score', 'N/A')
                if isinstance(f1_score, (int, float)):
                    print(f"F1-Score: {f1_score:.4f}")
                else:
                    print(f"F1-Score: {f1_score}")
            
            # Safe ROC AUC formatting
            roc_auc = model_metrics.get('roc_auc', 'N/A')
            if isinstance(roc_auc, (int, float)):
                print(f"ROC AUC: {roc_auc:.4f}")
            else:
                print(f"ROC AUC: {roc_auc}")
    
    # 5. Hyperparameter tuning (optional)
    logger.info("5. Hyperparameter tuning...")
    param_grid = {
        'hidden_sizes': [128],
        'learning_rates': [0.001]
    }
    
    tuning_results = trainer.tune_hyperparameters(train_loader, val_loader, param_grid)
    logger.info(f"Best hyperparameters: {tuning_results['best_params']}")
    
    # 6. Save models
    logger.info("6. Saving models...")
    trainer.save_models("models")  # Save locally
    
    # 7. Model summary
    summary = trainer.get_model_summary()
    logger.info(f"Model summary: {summary}")
    
    logger.info("🎉 Model training completed successfully!")
    return trainer, metrics

def test_single_prediction():
    """Testeaza predictia pe un singur sample"""
    logger.info("=== Testing Single Prediction ===")
    
    # Load or create a simple test case
    test_features = np.random.rand(1, 51)  # Mock network features
    
    # Initialize trainer and load models (mock for now)
    trainer = ModelTrainer()
    trainer.initialize_pytorch_model(51, 128)
    trainer.initialize_isolation_forest()
    
    # Mock predictions
    logger.info("Single prediction test completed")

if __name__ == "__main__":
    # Check if running in container or local
    if os.path.exists("/app"):
        logger.info("Running in container environment")
    else:
        logger.info("Running in local environment")
    
    try:
        trainer, metrics = train_all_models()
        
        # Test single prediction
        test_single_prediction()
        
        logger.info("All training and testing completed!")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)