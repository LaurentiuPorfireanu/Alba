import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

class AnomalyDetectionNN(nn.Module):
    """
    Autoencoder pentru detectia anomaliilor in traficul de retea
    Arhitectura optimizata pentru features de retea
    """
    def __init__(self, input_size, hidden_size=64, dropout_rate=0.2):
        super(AnomalyDetectionNN, self).__init__()
        
        self.input_size = input_size
        self.hidden_size = hidden_size
        
        # Encoder - compresie progresiva
        self.encoder = nn.Sequential(
            nn.Linear(input_size, hidden_size * 4),
            nn.BatchNorm1d(hidden_size * 4),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            nn.Linear(hidden_size * 4, hidden_size * 2),
            nn.BatchNorm1d(hidden_size * 2),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            nn.Linear(hidden_size * 2, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Bottleneck layer - reprezentare compacta
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU()
        )
        
        # Decoder - reconstructie progresiva
        self.decoder = nn.Sequential(
            nn.Linear(hidden_size // 2, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            nn.Linear(hidden_size, hidden_size * 2),
            nn.BatchNorm1d(hidden_size * 2),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            nn.Linear(hidden_size * 2, hidden_size * 4),
            nn.BatchNorm1d(hidden_size * 4),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            nn.Linear(hidden_size * 4, input_size),
            nn.Sigmoid()  # Sigmoid pentru features normalizate
        )
        
        # Initialize weights
        self.apply(self._init_weights)
    
    def _init_weights(self, module):
        """Initializare ponderilor pentru convergenta mai buna"""
        if isinstance(module, nn.Linear):
            torch.nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                torch.nn.init.zeros_(module.bias)
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        """Returneaza reprezentarea encoder (pentru analiza)"""
        return self.encoder(x)
    
    def get_reconstruction_error(self, x):
        """Calculeaza eroarea de reconstructie - baza pentru detectia anomaliilor"""
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = nn.MSELoss(reduction='none')
            error = mse(reconstructed, x).mean(dim=1)
            return error
    
    def get_anomaly_scores(self, x, return_reconstruction=False):
        """Returneaza scoruri de anomalie"""
        with torch.no_grad():
            reconstructed = self.forward(x)
            
            # Multiple metrics pentru detectia anomaliilor
            mse_error = nn.MSELoss(reduction='none')(reconstructed, x).mean(dim=1)
            mae_error = nn.L1Loss(reduction='none')(reconstructed, x).mean(dim=1)
            
            # Combined score
            anomaly_scores = 0.7 * mse_error + 0.3 * mae_error
            
            if return_reconstruction:
                return anomaly_scores, reconstructed
            return anomaly_scores

class LSTMAnomalyDetector(nn.Module):
    """
    LSTM-based Autoencoder pentru detectia anomaliilor in secvente de trafic
    Useful pentru detectia atacurilor temporale (DDoS patterns)
    """
    def __init__(self, input_size, hidden_size=64, num_layers=2, dropout_rate=0.2):
        super(LSTMAnomalyDetector, self).__init__()
        
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        # Encoder LSTM
        self.encoder_lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout_rate if num_layers > 1 else 0,
            bidirectional=True
        )
        
        # Decoder LSTM
        self.decoder_lstm = nn.LSTM(
            input_size=hidden_size * 2,  # bidirectional
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout_rate if num_layers > 1 else 0
        )
        
        # Output layer
        self.output_layer = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_size // 2, input_size),
            nn.Sigmoid()
        )
        
        self.dropout = nn.Dropout(dropout_rate)
    
    def forward(self, x):
        # x shape: (batch_size, seq_len, input_size)
        batch_size, seq_len, _ = x.size()
        
        # Encoder
        encoder_output, (hidden, cell) = self.encoder_lstm(x)
        encoder_output = self.dropout(encoder_output)
        
        # Decoder
        decoder_input = encoder_output
        decoder_output, _ = self.decoder_lstm(decoder_input)
        decoder_output = self.dropout(decoder_output)
        
        # Output
        output = self.output_layer(decoder_output)
        
        return output
    
    def get_reconstruction_error(self, x):
        """Calculeaza eroarea de reconstructie pentru secvente"""
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = nn.MSELoss(reduction='none')
            # Average over sequence and features
            error = mse(reconstructed, x).mean(dim=[1, 2])
            return error

class EnsembleAnomalyDetector(nn.Module):
    """
    Ensemble de modele pentru detectia robusta a anomaliilor
    Combina Autoencoder si LSTM pentru performanta maxima
    """
    def __init__(self, input_size, hidden_size=64):
        super(EnsembleAnomalyDetector, self).__init__()
        
        self.autoencoder = AnomalyDetectionNN(input_size, hidden_size)
        self.lstm_detector = LSTMAnomalyDetector(input_size, hidden_size)
        
        # Fusion layer pentru combinarea scorurilor
        self.fusion_layer = nn.Sequential(
            nn.Linear(2, 8),  # 2 scores din modelele de baza
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU(),
            nn.Linear(4, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        # Pentru autoencoder (batch_size, features)
        ae_output = self.autoencoder(x)
        
        # Pentru LSTM (batch_size, 1, features) - single timestep
        lstm_input = x.unsqueeze(1)
        lstm_output = self.lstm_detector(lstm_input).squeeze(1)
        
        return ae_output, lstm_output
    
    def get_ensemble_anomaly_score(self, x):
        """Returneaza scorul final de anomalie din ensemble"""
        with torch.no_grad():
            ae_scores = self.autoencoder.get_anomaly_scores(x)
            
            # Pentru LSTM
            lstm_input = x.unsqueeze(1)
            lstm_scores = self.lstm_detector.get_reconstruction_error(lstm_input)
            
            # Normalize scores
            ae_scores_norm = (ae_scores - ae_scores.min()) / (ae_scores.max() - ae_scores.min() + 1e-8)
            lstm_scores_norm = (lstm_scores - lstm_scores.min()) / (lstm_scores.max() - lstm_scores.min() + 1e-8)
            
            # Combine scores
            combined_input = torch.stack([ae_scores_norm, lstm_scores_norm], dim=1)
            final_scores = self.fusion_layer(combined_input).squeeze()
            
            return final_scores

class VariationalAutoencoder(nn.Module):
    """
    Variational Autoencoder pentru detectia anomaliilor
    Foloseste distributii probabilistice pentru detectia mai robusta
    """
    def __init__(self, input_size, latent_size=32, hidden_size=64):
        super(VariationalAutoencoder, self).__init__()
        
        self.input_size = input_size
        self.latent_size = latent_size
        
        # Encoder
        self.encoder_hidden = nn.Sequential(
            nn.Linear(input_size, hidden_size * 2),
            nn.ReLU(),
            nn.Linear(hidden_size * 2, hidden_size),
            nn.ReLU()
        )
        
        # Latent space parameters
        self.fc_mu = nn.Linear(hidden_size, latent_size)
        self.fc_logvar = nn.Linear(hidden_size, latent_size)
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_size, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, hidden_size * 2),
            nn.ReLU(),
            nn.Linear(hidden_size * 2, input_size),
            nn.Sigmoid()
        )
    
    def encode(self, x):
        h = self.encoder_hidden(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar
    
    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std
    
    def decode(self, z):
        return self.decoder(z)
    
    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        reconstructed = self.decode(z)
        return reconstructed, mu, logvar
    
    def loss_function(self, reconstructed, x, mu, logvar, beta=1.0):
        """VAE loss cu KL divergence"""
        mse_loss = nn.MSELoss()(reconstructed, x)
        kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
        return mse_loss + beta * kl_loss
    
    def get_anomaly_scores(self, x):
        """Anomaly scores bazate pe likelihood"""
        with torch.no_grad():
            reconstructed, mu, logvar = self.forward(x)
            
            # Reconstruction error
            recon_error = nn.MSELoss(reduction='none')(reconstructed, x).mean(dim=1)
            
            # KL divergence per sample
            kl_div = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp(), dim=1)
            
            # Combined anomaly score
            anomaly_scores = recon_error + 0.1 * kl_div
            
            return anomaly_scores

class AttentionAnomalyDetector(nn.Module):
    """
    Transformer-based anomaly detector pentru features complexe de retea
    Foloseste attention mechanism pentru detectia pattern-urilor anormale
    """
    def __init__(self, input_size, d_model=128, nhead=8, num_layers=3):
        super(AttentionAnomalyDetector, self).__init__()
        
        self.input_size = input_size
        self.d_model = d_model
        
        # Input projection
        self.input_projection = nn.Linear(input_size, d_model)
        
        # Positional encoding (optional pentru network features)
        self.pos_encoding = nn.Parameter(torch.randn(1, 100, d_model))
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=d_model * 4,
            dropout=0.1,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Output projection
        self.output_projection = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Linear(d_model // 2, input_size),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        # x shape: (batch_size, seq_len, input_size) sau (batch_size, input_size)
        if x.dim() == 2:
            x = x.unsqueeze(1)  # Add sequence dimension
        
        batch_size, seq_len, _ = x.size()
        
        # Project to model dimension
        x = self.input_projection(x)
        
        # Add positional encoding
        if seq_len <= self.pos_encoding.size(1):
            x = x + self.pos_encoding[:, :seq_len, :]
        
        # Transformer forward
        transformer_output = self.transformer(x)
        
        # Project back to input size
        output = self.output_projection(transformer_output)
        
        return output.squeeze(1) if output.size(1) == 1 else output
    
    def get_anomaly_scores(self, x):
        """Attention-based anomaly scores"""
        with torch.no_grad():
            reconstructed = self.forward(x)
            
            if x.dim() == 2 and reconstructed.dim() == 2:
                mse_error = nn.MSELoss(reduction='none')(reconstructed, x).mean(dim=1)
            else:
                mse_error = nn.MSELoss(reduction='none')(reconstructed, x).mean(dim=[1, 2])
            
            return mse_error

def create_model(model_type: str, input_size: int, **kwargs):
    """Factory function pentru crearea modelelor"""
    if model_type == 'autoencoder':
        return AnomalyDetectionNN(input_size, **kwargs)
    elif model_type == 'lstm':
        return LSTMAnomalyDetector(input_size, **kwargs)
    elif model_type == 'ensemble':
        return EnsembleAnomalyDetector(input_size, **kwargs)
    elif model_type == 'vae':
        return VariationalAutoencoder(input_size, **kwargs)
    elif model_type == 'attention':
        return AttentionAnomalyDetector(input_size, **kwargs)
    else:
        raise ValueError(f"Unknown model type: {model_type}")