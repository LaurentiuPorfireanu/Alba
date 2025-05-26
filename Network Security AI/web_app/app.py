from flask import Flask, render_template, jsonify, request
import json
import threading
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def create_app(anomaly_detector, attack_simulator, defense_system):
    app = Flask(__name__)
    
    # Import network monitor
    from src.network_monitor import NetworkMonitor
    network_monitor = NetworkMonitor()
    
    # Global state
    app_state = {
        'simulation_running': False,
        'auto_attack': False,
        'attack_interval': 5,
        'defense_active': False,
        'training_in_progress': False,
        'continuous_training': False,
        'training_thread_running': False
    }
    
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')
    
    @app.route('/api/start_monitoring')
    def start_monitoring():
        interfaces = network_monitor.get_network_interfaces()
        interface = request.args.get('interface', interfaces[0]['name'] if interfaces else 'eth0')
        
        success = network_monitor.start_monitoring(interface)
        return jsonify({
            'success': success,
            'interface': interface,
            'message': f'Network monitoring started on {interface}'
        })
    
    @app.route('/api/stop_monitoring')
    def stop_monitoring():
        network_monitor.stop_monitoring()
        return jsonify({
            'success': True,
            'message': 'Network monitoring stopped'
        })
    
    @app.route('/api/network_stats')
    def get_network_stats():
        stats = network_monitor.get_network_stats()
        recent_traffic = network_monitor.get_recent_traffic(20)
        
        return jsonify({
            'stats': stats,
            'recent_traffic': recent_traffic
        })
    
    @app.route('/api/launch_attack')
    def launch_attack():
        attack_type = request.args.get('type', None)
        attack_info = attack_simulator.launch_attack(attack_type)
        
        # Test defense system if active
        defense_result = None
        if app_state['defense_active']:
            defense_result = defense_system.defend_against_attack(attack_info['data'])
        
        return jsonify({
            'attack': {
                'type': attack_info['type'],
                'severity': attack_info['severity'],
                'timestamp': attack_info['timestamp'].isoformat(),
                'data': attack_info['data']
            },
            'defense': defense_result
        })
    
    @app.route('/api/detect_anomaly')
    def detect_anomaly():
        # Get recent traffic for anomaly detection
        recent_traffic = network_monitor.get_recent_traffic(1)
        
        if not recent_traffic:
            return jsonify({
                'error': 'No traffic data available',
                'anomaly_detected': False
            })
        
        # Convert traffic data to format expected by anomaly detector
        traffic_data = recent_traffic[-1]
        network_data = {
            'packet_size': traffic_data.get('packet_size', 0),
            'duration': 0.1,  # Estimated
            'protocol': traffic_data.get('protocol', 0),
            'src_port': traffic_data.get('src_port', 0),
            'dst_port': traffic_data.get('dst_port', 0),
            'packet_count': 1,
            'byte_count': traffic_data.get('packet_size', 0),
            'flow_rate': 10,  # Estimated
            'packet_interval': 0.01
        }
        
        is_anomaly, confidence = anomaly_detector.detect_anomaly(network_data)
        
        return jsonify({
            'anomaly_detected': is_anomaly,
            'confidence': confidence,
            'traffic_data': traffic_data
        })
    
    @app.route('/api/defense_stats')
    def get_defense_stats():
        return jsonify(defense_system.get_defense_stats())
    
    @app.route('/api/attack_stats')
    def get_attack_stats():
        return jsonify(attack_simulator.get_attack_stats())
    
    @app.route('/api/start_ai_training')
    def start_ai_training():
        if app_state['training_in_progress']:
            return jsonify({
                'success': False,
                'message': 'Training already in progress'
            })
        
        def training_thread():
            app_state['training_in_progress'] = True
            try:
                print("Starting AI training process...")
                training_data = []
                
                # Generate normal traffic
                for _ in range(800):
                    normal_traffic = attack_simulator.generate_normal_traffic()
                    training_data.append(normal_traffic)
                
                # Generate attack traffic
                attack_types = ['DDoS', 'Port Scan', 'Brute Force']
                for attack_type in attack_types:
                    for _ in range(100):
                        attack_data = attack_simulator.launch_attack(attack_type)['data']
                        training_data.append(attack_data)
                
                # Train anomaly detector
                anomaly_detector.train(training_data)
                
                # Train defense system
                defense_system.train_defense_model()
                
                print("AI training completed successfully!")
            except Exception as e:
                print(f"Training error: {e}")
            finally:
                app_state['training_in_progress'] = False
        
        thread = threading.Thread(target=training_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': 'AI training started in background'
        })
    
    @app.route('/api/continuous_training', methods=['POST'])
    def toggle_continuous_training():
        data = request.get_json()
        app_state['continuous_training'] = data.get('enabled', False)
        
        if app_state['continuous_training']:
            start_continuous_training()
        
        return jsonify({
            'continuous_training': app_state['continuous_training']
        })
    
    def start_continuous_training():
        def training_loop():
            print("Starting continuous training...")
            while app_state.get('continuous_training', False) and not app_state['defense_active']:
                try:
                    # Generate some training data
                    for _ in range(50):
                        normal_traffic = attack_simulator.generate_normal_traffic()
                        defense_system.training_data.append({
                            'features': normal_traffic,
                            'label': 0  # Normal
                        })
                    
                    # Generate attack data
                    attack_types = ['DDoS', 'Port Scan', 'Brute Force']
                    for attack_type in attack_types:
                        for _ in range(10):
                            attack_data = attack_simulator.launch_attack(attack_type)['data']
                            label = 2 if attack_type == 'DDoS' else 1  # Malicious or Suspicious
                            defense_system.training_data.append({
                                'features': attack_data,
                                'label': label
                            })
                    
                    # Train model every 200 samples
                    if len(defense_system.training_data) >= 200:
                        defense_system.train_defense_model()
                        # Keep only recent training data
                        defense_system.training_data = defense_system.training_data[-1000:]
                    
                    time.sleep(10)  # Wait 10 seconds before next training cycle
                    
                except Exception as e:
                    print(f"Continuous training error: {e}")
                    time.sleep(5)
        
        if not app_state.get('training_thread_running', False):
            app_state['training_thread_running'] = True
            thread = threading.Thread(target=training_loop)
            thread.daemon = True
            thread.start()
    
    @app.route('/api/save_ai_models')
    def save_ai_models():
        try:
            # Save anomaly detector
            anomaly_detector.save_model('models/anomaly_detector.pth')
            
            # Save defense system
            success = defense_system.save_model('models/defense_system.pth')
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'AI models saved successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Error saving defense model'
                })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error saving models: {str(e)}'
            })
    
    @app.route('/api/load_ai_models')
    def load_ai_models():
        try:
            # Load models
            anomaly_loaded = anomaly_detector.load_model('models/anomaly_detector.pth')
            defense_loaded = defense_system.load_model('models/defense_system.pth')
            
            return jsonify({
                'success': True,
                'anomaly_loaded': anomaly_loaded,
                'defense_loaded': defense_loaded,
                'message': 'AI models loaded successfully'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error loading models: {str(e)}'
            })
    
    @app.route('/api/ai_training_status')
    def get_ai_training_status():
        return jsonify({
            'training_in_progress': app_state['training_in_progress']
        })
    
    @app.route('/api/train_models')
    def train_models():
        return start_ai_training()  # Redirect to new endpoint
    
    @app.route('/api/auto_attack', methods=['POST'])
    def toggle_auto_attack():
        data = request.get_json()
        app_state['auto_attack'] = data.get('enabled', False)
        app_state['attack_interval'] = data.get('interval', 5)
        
        if app_state['auto_attack'] and not app_state['simulation_running']:
            start_auto_attack_simulation()
        
        return jsonify({
            'auto_attack': app_state['auto_attack'],
            'interval': app_state['attack_interval']
        })
    
    @app.route('/api/toggle_defense', methods=['POST'])
    def toggle_defense():
        data = request.get_json()
        app_state['defense_active'] = data.get('enabled', True)
        
        # Set defense mode in defense system
        defense_system.set_defense_mode(app_state['defense_active'])
        
        # Stop continuous training if defense is enabled
        if app_state['defense_active']:
            app_state['continuous_training'] = False
        
        return jsonify({
            'defense_active': app_state['defense_active']
        })
    
    @app.route('/api/reset_system')
    def reset_system():
        # Reset all systems
        defense_system.reset_blocks()
        attack_simulator.attack_history.clear()
        app_state['auto_attack'] = False
        app_state['simulation_running'] = False
        app_state['continuous_training'] = False
        app_state['defense_active'] = False
        
        return jsonify({
            'success': True,
            'message': 'System reset completed'
        })
    
    def start_auto_attack_simulation():
        app_state['simulation_running'] = True
        
        def simulation_loop():
            while app_state['auto_attack'] and app_state['simulation_running']:
                # Launch random attack
                attack_info = attack_simulator.launch_attack()
                
                # Test defense
                if app_state['defense_active']:
                    defense_result = defense_system.defend_against_attack(attack_info['data'])
                    print(f"Defense result: {defense_result['action']}")
                
                time.sleep(app_state['attack_interval'])
            
            app_state['simulation_running'] = False
        
        thread = threading.Thread(target=simulation_loop)
        thread.daemon = True
        thread.start()
    
    @app.route('/api/system_status')
    def get_system_status():
        return jsonify({
            'monitoring': network_monitor.monitoring,
            'auto_attack': app_state['auto_attack'],
            'defense_active': app_state['defense_active'],
            'simulation_running': app_state['simulation_running'],
            'training_in_progress': app_state['training_in_progress'],
            'continuous_training': app_state['continuous_training'],
            'interfaces': network_monitor.get_network_interfaces()
        })
    
    return app