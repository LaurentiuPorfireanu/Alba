import requests
import time
import random
import os
import threading
from datetime import datetime

class TrafficGenerator:
    def __init__(self):
        self.target_host = os.getenv('TARGET_HOST', 'target_server')
        self.traffic_rate = int(os.getenv('TRAFFIC_RATE', '10'))
        self.running = True
        
    def generate_normal_traffic(self):
        """Generate normal HTTP traffic"""
        urls = [
            f'http://{self.target_host}/',
            f'http://{self.target_host}/api',
            f'http://{self.target_host}/health'
        ]
        
        while self.running:
            try:
                url = random.choice(urls)
                response = requests.get(url, timeout=5)
                print(f"[{datetime.now()}] Normal traffic: {url} - Status: {response.status_code}")
                
                time.sleep(random.uniform(1, 5))
                
            except Exception as e:
                print(f"Traffic generation error: {e}")
                time.sleep(1)
    
    def generate_suspicious_traffic(self):
        """Generate suspicious traffic patterns"""
        while self.running:
            try:
                # Port scanning simulation
                for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
                    try:
                        requests.get(f'http://{self.target_host}:{port}', timeout=1)
                    except:
                        pass
                
                print(f"[{datetime.now()}] Suspicious: Port scan completed")
                time.sleep(random.uniform(30, 60))
                
            except Exception as e:
                print(f"Suspicious traffic error: {e}")
                time.sleep(5)
    
    def generate_attack_traffic(self):
        """Generate attack-like traffic"""
        while self.running:
            try:
                # Brute force simulation
                for i in range(10):
                    requests.get(f'http://{self.target_host}/admin', 
                               auth=('admin', f'password{i}'), timeout=2)
                
                print(f"[{datetime.now()}] Attack: Brute force attempt")
                time.sleep(random.uniform(10, 20))
                
            except Exception as e:
                print(f"Attack traffic error: {e}")
                time.sleep(5)
    
    def start(self):
        print("Starting traffic generator...")
        
        # Start different traffic types in separate threads
        threading.Thread(target=self.generate_normal_traffic, daemon=True).start()
        threading.Thread(target=self.generate_suspicious_traffic, daemon=True).start()
        threading.Thread(target=self.generate_attack_traffic, daemon=True).start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print("Traffic generator stopped")

if __name__ == "__main__":
    generator = TrafficGenerator()
    generator.start()