#!/usr/bin/env python3
"""
Script pentru descarcarea si pregătirea dataset-ului CICIDS2017
"""

import os
import wget
import zipfile
import pandas as pd
from loguru import logger

def download_cicids2017():
    """Descarca dataset-ul CICIDS2017"""
    
    data_dir = "../data"
    os.makedirs(data_dir, exist_ok=True)
    
    # URL-urile pentru dataset
    urls = [
        "https://www.unb.ca/cic/datasets/ids-2017.html",
        # Aici vor fi URL-urile reale pentru fisierele CSV
    ]
    
    logger.info("Descarcam dataset-ul CICIDS2017...")
    
    # Pentru demo, cream un dataset sintetic
    create_synthetic_dataset(data_dir)

def create_synthetic_dataset(data_dir):
    """Creaza un dataset sintetic pentru testare"""
    import numpy as np
    
    logger.info("Cream dataset sintetic pentru testare...")
    
    # Generam date sintetice
    n_samples = 10000
    n_features = 78  # Similar cu CICIDS2017
    
    # 90% trafic normal, 10% anomalii
    normal_samples = int(n_samples * 0.9)
    anomaly_samples = n_samples - normal_samples
    
    # Trafic normal (distributie normala)
    normal_data = np.random.normal(0, 1, (normal_samples, n_features))
    normal_labels = ['BENIGN'] * normal_samples
    
    # Trafic anomal (valori extreme)
    anomaly_data = np.random.normal(0, 3, (anomaly_samples, n_features))
    anomaly_labels = ['DDoS'] * (anomaly_samples // 2) + ['PortScan'] * (anomaly_samples - anomaly_samples // 2)
    
    # Combinam datele
    all_data = np.vstack([normal_data, anomaly_data])
    all_labels = normal_labels + anomaly_labels
    
    # Cream DataFrame
    feature_names = [f'feature_{i}' for i in range(n_features)]
    df = pd.DataFrame(all_data, columns=feature_names)
    df['Label'] = all_labels
    
    # Salvam
    output_path = os.path.join(data_dir, "cicids2017_sample.csv")
    df.to_csv(output_path, index=False)
    
    logger.info(f"Dataset sintetic salvat la: {output_path}")
    logger.info(f"Shape: {df.shape}")

if __name__ == "__main__":
    download_cicids2017()