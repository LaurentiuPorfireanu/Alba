import torch
import torch.nn as nn
import numpy as np
import random
import time
from datetime import datetime

class AttackGenerator(nn.Module):
    def __init__(self, input_dim=10, hidden_dim=128):
        super(AttackGenerator, self).__init__()
        
        self.generator = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 9),
            nn.Sigmoid()
        )
    
    def forward(self, noise):
        return self.generator(noise)

class AttackSimulator:
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.generator = AttackGenerator().to(self.device)
        self.attack_types = [
            'DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 
            'XSS', 'Malware', 'Phishing', 'Man-in-Middle'
        ]
        self.attack_history = []
        
    def generate_normal_traffic(self):
        return {
            'packet_size': random.randint(64, 1500),
            'duration': random.uniform(0.001, 1.0),
            'protocol': random.choice([6, 17, 1]),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 21, 25]),
            'packet_count': random.randint(1, 100),
            'byte_count': random.randint(64, 150000),
            'flow_rate': random.uniform(1, 1000),
            'packet_interval': random.uniform(0.001, 0.1)
        }
    
    def generate_ddos_attack(self):
        return {
            'packet_size': random.randint(32, 64),
            'duration': random.uniform(0.0001, 0.001),
            'protocol': random.choice([6, 17]),
            'src_port': random.randint(1, 1024),
            'dst_port': random.choice([80, 443]),
            'packet_count': random.randint(1000, 10000),
            'byte_count': random.randint(32000, 640000),
            'flow_rate': random.uniform(5000, 50000),
            'packet_interval': random.uniform(0.0001, 0.001)
        }
    
    def generate_port_scan(self):
        return {
            'packet_size': random.randint(40, 80),
            'duration': random.uniform(0.1, 2.0),
            'protocol': 6,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.randint(1, 1024),
            'packet_count': random.randint(1, 10),
            'byte_count': random.randint(40, 800),
            'flow_rate': random.uniform(1, 100),
            'packet_interval': random.uniform(0.01, 0.1)
        }
    
    def generate_brute_force(self):
        return {
            'packet_size': random.randint(100, 200),
            'duration': random.uniform(1.0, 5.0),
            'protocol': 6,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([22, 21, 23, 3389]),
            'packet_count': random.randint(10, 100),
            'byte_count': random.randint(1000, 20000),
            'flow_rate': random.uniform(10, 500),
            'packet_interval': random.uniform(0.1, 1.0)
        }
    
    def launch_attack(self, attack_type=None):
        if attack_type is None:
            attack_type = random.choice(self.attack_types)
        
        attack_data = None
        
        if attack_type == 'DDoS':
            attack_data = self.generate_ddos_attack()
        elif attack_type == 'Port Scan':
            attack_data = self.generate_port_scan()
        elif attack_type == 'Brute Force':
            attack_data = self.generate_brute_force()
        else:
            attack_data = self.generate_normal_traffic()
            attack_data['packet_count'] *= random.randint(2, 5)
            attack_data['flow_rate'] *= random.uniform(2, 10)
        
        attack_info = {
            'type': attack_type,
            'timestamp': datetime.now(),
            'data': attack_data,
            'severity': random.choice(['Low', 'Medium', 'High', 'Critical'])
        }
        
        self.attack_history.append(attack_info)
        print(f"Attack launched: {attack_type} - Severity: {attack_info['severity']}")
        
        return attack_info
    
    def get_attack_stats(self):
        if not self.attack_history:
            return {}
            
        attack_counts = {}
        for attack in self.attack_history:
            attack_type = attack['type']
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            
        return {
            'total_attacks': len(self.attack_history),
            'attack_types': attack_counts,
            'last_attack': self.attack_history[-1] if self.attack_history else None
        }