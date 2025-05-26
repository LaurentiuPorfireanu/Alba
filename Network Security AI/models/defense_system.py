import torch
import torch.nn as nn
import numpy as np
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import os  # ADAUGĂ ACEASTĂ LINIE

class DefenseClassifier(nn.Module):
    def __init__(self, input_dim=9, hidden_dim=128):
        super(DefenseClassifier, self).__init__()
        
        self.classifier = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim//2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim//2, hidden_dim//4),
            nn.ReLU(),
            nn.Linear(hidden_dim//4, 3)  # Normal, Suspicious, Malicious
        )
        
    def forward(self, x):
        return torch.softmax(self.classifier(x), dim=1)

class DefenseSystem:
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.classifier = DefenseClassifier().to(self.device)
        
        # Network defense components
        self.blocked_ips = set()
        self.ip_request_counts = defaultdict(deque)
        self.connection_limits = {
            'max_connections_per_ip': 100,
            'max_requests_per_minute': 60,
            'ddos_threshold': 1000
        }
        
        # Rate limiting
        self.rate_limiter = defaultdict(lambda: {'count': 0, 'window': time.time()})
        
        # Defense actions log
        self.defense_actions = []
        self.threat_levels = {0: 'Normal', 1: 'Suspicious', 2: 'Malicious'}
        
        # Auto-learning mechanism
        self.training_data = []
        self.model_trained = False
        self.defense_mode = False  # ADAUGĂ ACEASTĂ LINIE
        
        print("Defense System initialized")
    
    def set_defense_mode(self, enabled):
        """Enable/disable defense testing mode"""
        self.defense_mode = enabled
        if enabled:
            print("Defense System: TESTING MODE ENABLED")
        else:
            print("Defense System: Training mode enabled")
    
    def rate_limit_check(self, src_ip, current_time):
        window_size = 60  # 1 minute window
        
        # Clean old entries
        self.ip_request_counts[src_ip] = deque([
            timestamp for timestamp in self.ip_request_counts[src_ip]
            if current_time - timestamp < window_size
        ])
        
        # Add current request
        self.ip_request_counts[src_ip].append(current_time)
        
        # Check if over limit
        request_count = len(self.ip_request_counts[src_ip])
        if request_count > self.connection_limits['max_requests_per_minute']:
            return False, request_count
        
        return True, request_count
    
    def detect_ddos(self, network_data, src_ip):
        packet_rate = network_data.get('flow_rate', 0)
        packet_count = network_data.get('packet_count', 0)
        
        # DDoS detection based on high packet rate and small packet size
        if (packet_rate > self.connection_limits['ddos_threshold'] and 
            network_data.get('packet_size', 1500) < 100):
            return True
        
        # Volumetric attack detection
        if packet_count > 5000:
            return True
            
        return False
    
    def detect_port_scan(self, network_data, src_ip):
        dst_port = network_data.get('dst_port', 0)
        packet_size = network_data.get('packet_size', 0)
        duration = network_data.get('duration', 0)
        
        # Port scan characteristics: small packets, short duration, low ports
        if (packet_size < 100 and duration < 1.0 and dst_port < 1024):
            return True
            
        return False
    
    def classify_threat(self, network_data):
        if not self.model_trained:
            return self.rule_based_classification(network_data)
        
        # Convert to tensor for ML classification
        features = [
            network_data.get('packet_size', 0) / 1500,
            network_data.get('duration', 0),
            network_data.get('protocol', 0) / 255,
            network_data.get('src_port', 0) / 65535,
            network_data.get('dst_port', 0) / 65535,
            network_data.get('packet_count', 0) / 10000,
            network_data.get('byte_count', 0) / 1000000,
            network_data.get('flow_rate', 0) / 10000,
            network_data.get('packet_interval', 0)
        ]
        
        X = torch.FloatTensor([features]).to(self.device)
        
        self.classifier.eval()
        with torch.no_grad():
            prediction = self.classifier(X)
            threat_class = torch.argmax(prediction, dim=1).item()
            confidence = torch.max(prediction).item()
        
        return threat_class, confidence
    
    def rule_based_classification(self, network_data):
        src_ip = network_data.get('src_ip', 'unknown')
        
        # Check for DDoS
        if self.detect_ddos(network_data, src_ip):
            return 2, 0.9  # Malicious, high confidence
        
        # Check for port scan
        if self.detect_port_scan(network_data, src_ip):
            return 1, 0.7  # Suspicious
        
        # Check rate limiting
        current_time = time.time()
        rate_ok, request_count = self.rate_limit_check(src_ip, current_time)
        
        if not rate_ok:
            if request_count > 200:
                return 2, 0.8  # Malicious
            else:
                return 1, 0.6  # Suspicious
        
        return 0, 0.3  # Normal
    
    def apply_defense_action(self, network_data, threat_level, confidence):
        src_ip = network_data.get('src_ip', 'unknown')
        action_taken = None
        
        if threat_level == 2:  # Malicious
            # Block IP
            self.blocked_ips.add(src_ip)
            action_taken = f"BLOCKED IP: {src_ip}"
            
        elif threat_level == 1:  # Suspicious
            # Rate limit more aggressively
            current_time = time.time()
            if src_ip not in self.rate_limiter:
                self.rate_limiter[src_ip] = {'count': 1, 'window': current_time}
            else:
                self.rate_limiter[src_ip]['count'] += 1
            
            action_taken = f"RATE LIMITED: {src_ip}"
        
        if action_taken:
            defense_log = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'threat_level': self.threat_levels[threat_level],
                'confidence': confidence,
                'action': action_taken,
                'network_data': network_data
            }
            
            self.defense_actions.append(defense_log)
            print(f"Defense Action: {action_taken} - Threat: {self.threat_levels[threat_level]} ({confidence:.2f})")
        
        return action_taken
    
    def defend_against_attack(self, network_data):
        src_ip = network_data.get('src_ip', f"192.168.1.{np.random.randint(1, 254)}")
        network_data['src_ip'] = src_ip
        
        # Check if IP is already blocked
        if src_ip in self.blocked_ips:
            return {
                'blocked': True,
                'action': 'Traffic dropped - IP blocked',
                'threat_level': 'Blocked'
            }
        
        # Classify threat
        threat_level, confidence = self.classify_threat(network_data)
        
        # Apply defense action
        action_taken = self.apply_defense_action(network_data, threat_level, confidence)
        
        # Store for training ONLY if not in defense mode
        if not self.defense_mode:
            self.training_data.append({
                'features': network_data,
                'label': threat_level
            })
        
        return {
            'blocked': threat_level == 2,
            'action': action_taken or 'Allowed',
            'threat_level': self.threat_levels[threat_level],
            'confidence': confidence,
            'src_ip': src_ip
        }
    
    def train_defense_model(self):
        if len(self.training_data) < 100:
            print("Not enough training data for ML model")
            return False
        
        print("Training defense classification model...")
        
        # Prepare training data
        X, y = [], []
        for sample in self.training_data:
            features = [
                sample['features'].get('packet_size', 0) / 1500,
                sample['features'].get('duration', 0),
                sample['features'].get('protocol', 0) / 255,
                sample['features'].get('src_port', 0) / 65535,
                sample['features'].get('dst_port', 0) / 65535,
                sample['features'].get('packet_count', 0) / 10000,
                sample['features'].get('byte_count', 0) / 1000000,
                sample['features'].get('flow_rate', 0) / 10000,
                sample['features'].get('packet_interval', 0)
            ]
            X.append(features)
            y.append(sample['label'])
        
        X_tensor = torch.FloatTensor(X).to(self.device)
        y_tensor = torch.LongTensor(y).to(self.device)
        
        # Train model
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self.classifier.parameters(), lr=0.001)
        
        self.classifier.train()
        for epoch in range(50):
            optimizer.zero_grad()
            outputs = self.classifier(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()
            optimizer.step()
            
            if epoch % 10 == 0:
                print(f'Defense Training Epoch {epoch}, Loss: {loss.item():.4f}')
        
        self.model_trained = True
        print("Defense model training complete")
        return True
    
    def get_defense_stats(self):
        threat_counts = defaultdict(int)
        for action in self.defense_actions:
            threat_counts[action['threat_level']] += 1
        
        return {
            'total_actions': len(self.defense_actions),
            'blocked_ips': len(self.blocked_ips),
            'threat_distribution': dict(threat_counts),
            'recent_actions': self.defense_actions[-10:] if self.defense_actions else [],
            'model_trained': self.model_trained,
            'defense_mode': self.defense_mode,
            'training_samples': len(self.training_data)
        }
    
    def reset_blocks(self):
        self.blocked_ips.clear()
        self.rate_limiter.clear()
        self.defense_actions.clear()
        print("All IP blocks and rate limits cleared")
    
    def save_model(self, path='models/defense_system.pth'):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            torch.save({
                'model_state_dict': self.classifier.state_dict(),
                'model_trained': self.model_trained,
                'training_samples': len(self.training_data)
            }, path)
            print(f"Defense model saved to {path}")
            return True
        except Exception as e:
            print(f"Error saving defense model: {e}")
            return False

    def load_model(self, path='models/defense_system.pth'):
        if os.path.exists(path):
            try:
                checkpoint = torch.load(path, map_location=self.device)
                self.classifier.load_state_dict(checkpoint['model_state_dict'])
                self.model_trained = checkpoint.get('model_trained', False)
                print(f"Defense model loaded from {path}")
                return True
            except Exception as e:
                print(f"Error loading defense model: {e}")
                return False
        return False