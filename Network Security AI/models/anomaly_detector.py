import torch
import torch.nn as nn
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import os

class AutoEncoder(nn.Module):
    def __init__(self, input_dim, hidden_dim=64):
        super(AutoEncoder, self).__init__()
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim//2),
            nn.ReLU(),
            nn.Linear(hidden_dim//2, hidden_dim//4)
        )
        
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim//4, hidden_dim//2),
            nn.ReLU(),
            nn.Linear(hidden_dim//2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = 0.1
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.feature_names = [
            'packet_size', 'duration', 'protocol', 'src_port', 'dst_port',
            'packet_count', 'byte_count', 'flow_rate', 'packet_interval'
        ]
        
    def preprocess_data(self, data):
        if isinstance(data, dict):
            df = pd.DataFrame([data])
        else:
            df = data.copy()
            
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
                
        df = df[self.feature_names].fillna(0)
        return self.scaler.transform(df)
    
    def train(self, training_data):
        print("Training anomaly detection model...")
        
        X = self.preprocess_data(training_data)
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        input_dim = X.shape[1]
        self.model = AutoEncoder(input_dim).to(self.device)
        
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        
        self.model.train()
        for epoch in range(100):
            optimizer.zero_grad()
            outputs = self.model(X_tensor)
            loss = criterion(outputs, X_tensor)
            loss.backward()
            optimizer.step()
            
            if epoch % 20 == 0:
                print(f'Epoch {epoch}, Loss: {loss.item():.4f}')
        
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            mse = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
            self.threshold = torch.quantile(mse, 0.95).item()
        
        print(f"Training complete. Threshold: {self.threshold:.4f}")
    
    def detect_anomaly(self, network_data):
        if self.model is None:
            return False, 0.0
            
        X = self.preprocess_data(network_data)
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            mse = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
            anomaly_score = mse.item()
            
        is_anomaly = anomaly_score > self.threshold
        confidence = min(anomaly_score / self.threshold, 2.0)
        
        return is_anomaly, confidence
    
    def save_model(self, path='models/anomaly_detector.pth'):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'threshold': self.threshold,
            'scaler': self.scaler
        }, path)
        
    def load_model(self, path='models/anomaly_detector.pth'):
        if os.path.exists(path):
            checkpoint = torch.load(path, map_location=self.device)
            input_dim = len(self.feature_names)
            self.model = AutoEncoder(input_dim).to(self.device)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.threshold = checkpoint['threshold']
            self.scaler = checkpoint['scaler']
            return True
        return False