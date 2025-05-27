import torch
import torch.nn as nn
import numpy as np
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import os

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
        
        # Training and testing modes
        self.training_data = []
        self.model_trained = False
        self.system_mode = 'idle'  # 'idle', 'training', 'testing'
        
        # Testing statistics
        self.test_stats = {
            'total_tests': 0,
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0
        }
        
        print("Defense System initialized in idle mode")
    
    def set_system_mode(self, mode):
        """Set system mode: 'idle', 'training', or 'testing'"""
        valid_modes = ['idle', 'training', 'testing']
        if mode not in valid_modes:
            raise ValueError(f"Invalid mode. Must be one of: {valid_modes}")
            
        self.system_mode = mode
        print(f"Defense System mode set to: {mode.upper()}")
        
        if mode == 'testing':
            print("Defense System: TESTING MODE ENABLED - Real-time threat detection active")
        elif mode == 'training':
            print("Defense System: TRAINING MODE ENABLED - Collecting training data")
        else:
            print("Defense System: IDLE MODE - System ready")
    
    def set_defense_mode(self, enabled):
        """Legacy method for backward compatibility"""
        if enabled:
            self.set_system_mode('testing')
        else:
            self.set_system_mode('idle')
    
    def is_training_mode(self):
        return self.system_mode == 'training'
    
    def is_testing_mode(self):
        return self.system_mode == 'testing'
    
    def is_idle_mode(self):
        return self.system_mode == 'idle'
    
    def rate_limit_check(self, src_ip, current_time):
        """Check if IP is within rate limits"""
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
        """Detect DDoS attack patterns"""
        packet_rate = network_data.get('flow_rate', 0)
        packet_count = network_data.get('packet_count', 0)
        packet_size = network_data.get('packet_size', 1500)
        
        # DDoS detection based on high packet rate and small packet size
        if (packet_rate > self.connection_limits['ddos_threshold'] and packet_size < 100):
            return True
        
        # Volumetric attack detection
        if packet_count > 5000:
            return True
        
        # Amplification attack detection (small request, large response expected)
        if packet_size < 64 and packet_rate > 500:
            return True
            
        return False
    
    def detect_port_scan(self, network_data, src_ip):
        """Detect port scanning patterns"""
        dst_port = network_data.get('dst_port', 0)
        packet_size = network_data.get('packet_size', 0)
        duration = network_data.get('duration', 0)
        protocol = network_data.get('protocol', 0)
        
        # Port scan characteristics: small packets, short duration, low ports, TCP
        if (packet_size < 100 and duration < 1.0 and dst_port < 1024 and protocol == 6):
            return True
        
        # Sequential port scanning detection
        if dst_port < 1024 and packet_size < 80:
            return True
            
        return False
    
    def detect_brute_force(self, network_data, src_ip):
        """Detect brute force attack patterns"""
        dst_port = network_data.get('dst_port', 0)
        packet_count = network_data.get('packet_count', 0)
        duration = network_data.get('duration', 0)
        
        # Brute force on common service ports
        vulnerable_ports = [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3389]
        if dst_port in vulnerable_ports and packet_count > 10 and duration > 1.0:
            return True
            
        return False
    
    def classify_threat(self, network_data):
        """Classify network traffic as Normal, Suspicious, or Malicious"""
        if not self.model_trained:
            return self.rule_based_classification(network_data)
        
        # Convert to tensor for ML classification
        features = self._extract_features(network_data)
        X = torch.FloatTensor([features]).to(self.device)
        
        self.classifier.eval()
        with torch.no_grad():
            prediction = self.classifier(X)
            threat_class = torch.argmax(prediction, dim=1).item()
            confidence = torch.max(prediction).item()
        
        return threat_class, confidence
    
    def rule_based_classification(self, network_data):
        """Rule-based threat classification when ML model isn't available"""
        src_ip = network_data.get('src_ip', 'unknown')
        
        # Check for DDoS
        if self.detect_ddos(network_data, src_ip):
            return 2, 0.95  # Malicious, very high confidence
        
        # Check for port scan
        if self.detect_port_scan(network_data, src_ip):
            return 1, 0.8  # Suspicious, high confidence
        
        # Check for brute force
        if self.detect_brute_force(network_data, src_ip):
            return 2, 0.85  # Malicious, high confidence
        
        # Check rate limiting
        current_time = time.time()
        rate_ok, request_count = self.rate_limit_check(src_ip, current_time)
        
        if not rate_ok:
            if request_count > 200:
                return 2, 0.9  # Malicious - severe rate limit violation
            else:
                return 1, 0.7  # Suspicious - moderate rate limit violation
        
        return 0, 0.3  # Normal traffic
    
    def _extract_features(self, network_data):
        """Extract normalized features for ML classification"""
        return [
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
    
    def apply_defense_action(self, network_data, threat_level, confidence):
        """Apply appropriate defense action based on threat level"""
        src_ip = network_data.get('src_ip', 'unknown')
        action_taken = None
        
        current_time = time.time()
        
        if threat_level == 2:  # Malicious
            # Block IP immediately
            self.blocked_ips.add(src_ip)
            action_taken = f"BLOCKED IP: {src_ip} (Malicious threat detected)"
            
        elif threat_level == 1:  # Suspicious
            # Apply rate limiting
            if src_ip not in self.rate_limiter:
                self.rate_limiter[src_ip] = {'count': 1, 'window': current_time}
            else:
                self.rate_limiter[src_ip]['count'] += 1
                
                # Escalate to blocking if too many suspicious activities
                if self.rate_limiter[src_ip]['count'] > 10:
                    self.blocked_ips.add(src_ip)
                    action_taken = f"BLOCKED IP: {src_ip} (Escalated from suspicious)"
                else:
                    action_taken = f"RATE LIMITED: {src_ip} (Suspicious activity)"
        
        # Log defense action
        if action_taken:
            defense_log = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'threat_level': self.threat_levels[threat_level],
                'confidence': confidence,
                'action': action_taken,
                'network_data': network_data,
                'system_mode': self.system_mode
            }
            
            self.defense_actions.append(defense_log)
            print(f"Defense Action: {action_taken} - Threat: {self.threat_levels[threat_level]} ({confidence:.2f})")
        
        return action_taken
    
    def defend_against_attack(self, network_data):
        """Main defense function - analyze and respond to network traffic"""
        # Assign source IP if not provided
        src_ip = network_data.get('src_ip', f"192.168.1.{np.random.randint(1, 254)}")
        network_data['src_ip'] = src_ip
        
        # Check if IP is already blocked
        if src_ip in self.blocked_ips:
            return {
                'blocked': True,
                'action': 'Traffic dropped - IP blocked',
                'threat_level': 'Blocked',
                'confidence': 1.0,
                'src_ip': src_ip
            }
        
        # Classify threat
        threat_level, confidence = self.classify_threat(network_data)
        
        # Apply defense action only in testing mode
        action_taken = None
        if self.is_testing_mode():
            action_taken = self.apply_defense_action(network_data, threat_level, confidence)
            
            # Update test statistics
            self.test_stats['total_tests'] += 1
            if threat_level > 0:  # Suspicious or Malicious
                self.test_stats['true_positives'] += 1
            else:
                self.test_stats['true_negatives'] += 1
        
        # Store training data only in training mode
        if self.is_training_mode():
            self.training_data.append({
                'features': network_data,
                'label': threat_level
            })
        
        return {
            'blocked': threat_level == 2,
            'action': action_taken or 'Analyzed',
            'threat_level': self.threat_levels[threat_level],
            'confidence': confidence,
            'src_ip': src_ip,
            'system_mode': self.system_mode
        }
    
    def train_defense_model(self):
        """Train the ML defense classification model"""
        if len(self.training_data) < 100:
            print(f"Not enough training data: {len(self.training_data)} samples (minimum 100 required)")
            return False
        
        print(f"Training defense classification model with {len(self.training_data)} samples...")
        
        # Prepare training data
        X, y = [], []
        for sample in self.training_data:
            features = self._extract_features(sample['features'])
            X.append(features)
            y.append(sample['label'])
        
        X_tensor = torch.FloatTensor(X).to(self.device)
        y_tensor = torch.LongTensor(y).to(self.device)
        
        # Train model
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self.classifier.parameters(), lr=0.001)
        
        self.classifier.train()
        for epoch in range(100):
            optimizer.zero_grad()
            outputs = self.classifier(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()
            optimizer.step()
            
            if epoch % 20 == 0:
                print(f'Defense Training Epoch {epoch}, Loss: {loss.item():.4f}')
        
        # Calculate accuracy
        self.classifier.eval()
        with torch.no_grad():
            predictions = self.classifier(X_tensor)
            predicted_classes = torch.argmax(predictions, dim=1)
            accuracy = (predicted_classes == y_tensor).float().mean().item()
            print(f'Training accuracy: {accuracy:.4f}')
        
        self.model_trained = True
        print("Defense model training completed successfully")
        return True
    
    def get_defense_stats(self):
        """Get comprehensive defense system statistics"""
        threat_counts = defaultdict(int)
        for action in self.defense_actions:
            threat_counts[action['threat_level']] += 1
        
        # Calculate detection metrics
        total_tests = self.test_stats['total_tests']
        detection_rate = 0
        false_positive_rate = 0
        
        if total_tests > 0:
            tp = self.test_stats['true_positives']
            tn = self.test_stats['true_negatives']
            fp = self.test_stats['false_positives']
            fn = self.test_stats['false_negatives']
            
            detection_rate = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
            false_positive_rate = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
        
        return {
            'total_actions': len(self.defense_actions),
            'blocked_ips': len(self.blocked_ips),
            'threat_distribution': dict(threat_counts),
            'recent_actions': self.defense_actions[-10:] if self.defense_actions else [],
            'model_trained': self.model_trained,
            'system_mode': self.system_mode,
            'training_samples': len(self.training_data),
            'test_statistics': {
                'total_tests': total_tests,
                'detection_rate': round(detection_rate, 2),
                'false_positive_rate': round(false_positive_rate, 2),
                'true_positives': self.test_stats['true_positives'],
                'true_negatives': self.test_stats['true_negatives'],
                'false_positives': self.test_stats['false_positives'],
                'false_negatives': self.test_stats['false_negatives']
            }
        }
    
    def reset_blocks(self):
        """Reset all blocks and rate limits"""
        self.blocked_ips.clear()
        self.rate_limiter.clear()
        self.defense_actions.clear()
        self.test_stats = {
            'total_tests': 0,
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0
        }
        print("All IP blocks, rate limits, and test statistics cleared")
    
    def reset_training_data(self):
        """Reset training data"""
        self.training_data.clear()
        print("Training data cleared")
    
    def save_model(self, path='models/defense_system.pth'):
        """Save the trained model and system state"""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            torch.save({
                'model_state_dict': self.classifier.state_dict(),
                'model_trained': self.model_trained,
                'training_samples': len(self.training_data),
                'system_mode': self.system_mode,
                'threat_levels': self.threat_levels,
                'connection_limits': self.connection_limits
            }, path)
            print(f"Defense model saved to {path}")
            return True
        except Exception as e:
            print(f"Error saving defense model: {e}")
            return False

    def load_model(self, path='models/defense_system.pth'):
        """Load a saved model and system state"""
        if os.path.exists(path):
            try:
                checkpoint = torch.load(path, map_location=self.device)
                self.classifier.load_state_dict(checkpoint['model_state_dict'])
                self.model_trained = checkpoint.get('model_trained', False)
                
                # Load additional configuration if available
                if 'connection_limits' in checkpoint:
                    self.connection_limits = checkpoint['connection_limits']
                
                print(f"Defense model loaded from {path}")
                print(f"Model trained: {self.model_trained}")
                return True
            except Exception as e:
                print(f"Error loading defense model: {e}")
                return False
        else:
            print(f"Model file not found: {path}")
            return False
    
    def get_system_info(self):
        """Get detailed system information"""
        return {
            'system_mode': self.system_mode,
            'model_trained': self.model_trained,
            'training_samples': len(self.training_data),
            'blocked_ips_count': len(self.blocked_ips),
            'defense_actions_count': len(self.defense_actions),
            'device': str(self.device),
            'connection_limits': self.connection_limits,
            'threat_levels': self.threat_levels
        }