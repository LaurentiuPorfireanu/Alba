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
    
    def generate_sql_injection(self):
        return {
            'packet_size': random.randint(200, 500),
            'duration': random.uniform(0.5, 2.0),
            'protocol': 6,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 3306, 1433]),
            'packet_count': random.randint(5, 50),
            'byte_count': random.randint(1000, 25000),
            'flow_rate': random.uniform(5, 200),
            'packet_interval': random.uniform(0.05, 0.5)
        }
    
    def generate_xss_attack(self):
        return {
            'packet_size': random.randint(150, 300),
            'duration': random.uniform(0.2, 1.5),
            'protocol': 6,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 8080]),
            'packet_count': random.randint(3, 30),
            'byte_count': random.randint(450, 9000),
            'flow_rate': random.uniform(2, 150),
            'packet_interval': random.uniform(0.02, 0.3)
        }
    
    def generate_malware_attack(self):
        return {
            'packet_size': random.randint(500, 1500),
            'duration': random.uniform(2.0, 10.0),
            'protocol': random.choice([6, 17]),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 53, 8080, 9999]),
            'packet_count': random.randint(20, 200),
            'byte_count': random.randint(10000, 300000),
            'flow_rate': random.uniform(50, 2000),
            'packet_interval': random.uniform(0.5, 2.0)
        }
    
    def generate_phishing_attack(self):
        return {
            'packet_size': random.randint(300, 800),
            'duration': random.uniform(1.0, 5.0),
            'protocol': 6,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 25, 110, 143]),
            'packet_count': random.randint(5, 100),
            'byte_count': random.randint(1500, 80000),
            'flow_rate': random.uniform(10, 800),
            'packet_interval': random.uniform(0.1, 1.0)
        }
    
    def generate_man_in_middle(self):
        return {
            'packet_size': random.randint(100, 400),
            'duration': random.uniform(0.5, 3.0),
            'protocol': random.choice([6, 17]),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 21, 23, 25]),
            'packet_count': random.randint(10, 150),
            'byte_count': random.randint(1000, 60000),
            'flow_rate': random.uniform(20, 1000),
            'packet_interval': random.uniform(0.05, 0.5)
        }
    
    def launch_attack(self, attack_type=None):
        if attack_type is None:
            attack_type = random.choice(self.attack_types)
        
        # Ensure the attack type is valid
        if attack_type not in self.attack_types:
            print(f"Unknown attack type: {attack_type}, using random")
            attack_type = random.choice(self.attack_types)
        
        attack_data = None
        
        # Generate specific attack data based on type
        if attack_type == 'DDoS':
            attack_data = self.generate_ddos_attack()
        elif attack_type == 'Port Scan':
            attack_data = self.generate_port_scan()
        elif attack_type == 'Brute Force':
            attack_data = self.generate_brute_force()
        elif attack_type == 'SQL Injection':
            attack_data = self.generate_sql_injection()
        elif attack_type == 'XSS':
            attack_data = self.generate_xss_attack()
        elif attack_type == 'Malware':
            attack_data = self.generate_malware_attack()
        elif attack_type == 'Phishing':
            attack_data = self.generate_phishing_attack()
        elif attack_type == 'Man-in-Middle':
            attack_data = self.generate_man_in_middle()
        else:
            # Fallback to normal traffic with modifications
            print(f"Warning: Unknown attack type {attack_type}, generating DDoS instead")
            attack_type = 'DDoS'
            attack_data = self.generate_ddos_attack()
        
        # Assign severity based on attack type
        severity_map = {
            'DDoS': ['High', 'Critical'],
            'Port Scan': ['Low', 'Medium'],
            'Brute Force': ['Medium', 'High'],
            'SQL Injection': ['High', 'Critical'],
            'XSS': ['Medium', 'High'],
            'Malware': ['High', 'Critical'],
            'Phishing': ['Medium', 'High'],
            'Man-in-Middle': ['High', 'Critical']
        }
        
        severity = random.choice(severity_map.get(attack_type, ['Medium', 'High']))
        
        attack_info = {
            'type': attack_type,
            'timestamp': datetime.now(),
            'data': attack_data,
            'severity': severity
        }
        
        self.attack_history.append(attack_info)
        print(f"Attack launched: {attack_type} - Severity: {attack_info['severity']}")
        
        return attack_info
    
    def get_attack_stats(self):
        if not self.attack_history:
            return {
                'total_attacks': 0,
                'attack_types': {},
                'last_attack': None
            }
            
        attack_counts = {}
        for attack in self.attack_history:
            attack_type = attack['type']
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            
        return {
            'total_attacks': len(self.attack_history),
            'attack_types': attack_counts,
            'last_attack': self.attack_history[-1] if self.attack_history else None
        }