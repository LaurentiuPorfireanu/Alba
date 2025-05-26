import os
import sys
sys.path.append('src')
sys.path.append('models')

from flask import Flask
from web_app.app import create_app
from models.anomaly_detector import AnomalyDetector
from models.attack_simulator import AttackSimulator
from models.defense_system import DefenseSystem

def main():
    print("Initializing Network Security AI System...")
    
    # Create necessary directories
    os.makedirs('data/raw', exist_ok=True)
    os.makedirs('data/processed', exist_ok=True)
    os.makedirs('data/logs', exist_ok=True)
    
    # Initialize AI components
    print("Loading anomaly detector...")
    detector = AnomalyDetector()
    
    print("Loading attack simulator...")
    attacker = AttackSimulator()
    
    print("Loading defense system...")
    defender = DefenseSystem()
    
    print("Starting web application...")
    # Start web application
    app = create_app(detector, attacker, defender)
    print("Server running at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    main()