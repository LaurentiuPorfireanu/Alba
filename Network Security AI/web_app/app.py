from flask import Flask, render_template, jsonify, request
import json
import threading
import time
from datetime import datetime
import sys
import os
import random

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def create_app(anomaly_detector, attack_simulator, defense_system):
    app = Flask(__name__)
    
    # Import network monitor
    from src.network_monitor import NetworkMonitor
    network_monitor = NetworkMonitor()
    
    # Global state with separated modes
    app_state = {
        # System states
        'simulation_running': False,
        'training_mode': False,
        'testing_mode': False,
        
        # Training specific
        'training_in_progress': False,
        'continuous_training': False,
        'training_thread_running': False,
        'training_data_generated': {'normal': 0, 'attack': 0},
        'training_metrics': {'accuracy': [], 'loss': [], 'epochs': 0},
        
        # Testing specific
        'auto_attack': False,
        'attack_interval': 5,
        'test_results': {'total_tests': 0, 'successful_detections': 0},
        
        # General
        'defense_active': False
    }
    
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')
    
    # ==================== SYSTEM CONTROL ====================
    
    @app.route('/api/system_status')
    def get_system_status():
        return jsonify({
            'monitoring': network_monitor.monitoring,
            'training_mode': app_state['training_mode'],
            'testing_mode': app_state['testing_mode'],
            'training_in_progress': app_state['training_in_progress'],
            'continuous_training': app_state['continuous_training'],
            'auto_attack': app_state['auto_attack'],
            'defense_active': app_state['defense_active'],
            'simulation_running': app_state['simulation_running'],
            'interfaces': network_monitor.get_network_interfaces()
        })
    
    @app.route('/api/reset_system')
    def reset_system():
        # Reset all systems
        defense_system.reset_blocks()
        attack_simulator.attack_history.clear()
        
        # Reset app state
        app_state['training_mode'] = False
        app_state['testing_mode'] = False
        app_state['auto_attack'] = False
        app_state['simulation_running'] = False
        app_state['continuous_training'] = False
        app_state['defense_active'] = False
        app_state['training_in_progress'] = False
        app_state['test_results'] = {'total_tests': 0, 'successful_detections': 0}
        app_state['training_data_generated'] = {'normal': 0, 'attack': 0}
        app_state['training_metrics'] = {'accuracy': [], 'loss': [], 'epochs': 0}
        
        # Reset defense system mode
        defense_system.set_defense_mode(False)
        
        return jsonify({
            'success': True,
            'message': 'Complete system reset performed'
        })
    
    # ==================== TRAINING MODE ENDPOINTS ====================
    
    @app.route('/api/start_ai_training')
    def start_ai_training():
        if app_state['testing_mode']:
            return jsonify({
                'success': False,
                'message': 'Cannot start training while testing mode is active'
            })
            
        if app_state['training_in_progress']:
            return jsonify({
                'success': False,
                'message': 'Training already in progress'
            })
        
        def training_thread():
            app_state['training_in_progress'] = True
            app_state['training_mode'] = True
            try:
                print("Starting comprehensive AI training process...")
                training_data = []
                
                # Generate diverse normal traffic patterns
                print("Generating normal traffic patterns...")
                for _ in range(1000):
                    normal_traffic = attack_simulator.generate_normal_traffic()
                    training_data.append(normal_traffic)
                    app_state['training_data_generated']['normal'] += 1
                
                # Generate various attack patterns
                attack_types = ['DDoS', 'Port Scan', 'Brute Force']
                print("Generating attack patterns...")
                for attack_type in attack_types:
                    for _ in range(200):
                        attack_data = attack_simulator.launch_attack(attack_type)['data']
                        training_data.append(attack_data)
                        app_state['training_data_generated']['attack'] += 1
                
                # Train anomaly detector
                print("Training anomaly detection model...")
                anomaly_detector.train(training_data)
                
                # Train defense system
                print("Training defense classification model...")
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
        enabled = data.get('enabled', False)
        
        if enabled and app_state['testing_mode']:
            return jsonify({
                'success': False,
                'message': 'Cannot enable continuous training while testing mode is active'
            })
        
        app_state['continuous_training'] = enabled
        app_state['training_mode'] = enabled
        app_state['training_in_progress'] = enabled
        
        if enabled:
            start_continuous_training()
        else:
            stop_continuous_training()
        
        return jsonify({
            'success': True,
            'continuous_training': app_state['continuous_training']
        })
    
    def start_continuous_training():
        def training_loop():
            print("Starting continuous training loop...")
            app_state['training_thread_running'] = True
            epoch = 0
            
            while app_state.get('continuous_training', False) and not app_state['testing_mode']:
                try:
                    epoch += 1
                    app_state['training_metrics']['epochs'] = epoch
                    
                    # Generate training data in batches
                    batch_size = 50
                    
                    # Generate normal traffic
                    for _ in range(batch_size):
                        normal_traffic = attack_simulator.generate_normal_traffic()
                        defense_system.training_data.append({
                            'features': normal_traffic,
                            'label': 0  # Normal
                        })
                        app_state['training_data_generated']['normal'] += 1
                    
                    # Generate attack data
                    attack_types = ['DDoS', 'Port Scan', 'Brute Force']
                    for attack_type in attack_types:
                        for _ in range(batch_size // len(attack_types)):
                            attack_data = attack_simulator.launch_attack(attack_type)['data']
                            label = 2 if attack_type == 'DDoS' else 1  # Malicious or Suspicious
                            defense_system.training_data.append({
                                'features': attack_data,
                                'label': label
                            })
                            app_state['training_data_generated']['attack'] += 1
                    
                    # Simulate training metrics (realistic curves)
                    base_accuracy = min(95, 20 + epoch * 0.4)
                    accuracy = base_accuracy + (5 * (1 - 1/(1 + epoch/10))) # Sigmoid-like growth
                    accuracy = min(95, max(20, accuracy + (random.uniform(-2, 2))))
                    
                    base_loss = max(0.01, 2 - epoch * 0.01)
                    loss = base_loss * (1 + random.uniform(-0.1, 0.1))
                    
                    app_state['training_metrics']['accuracy'].append(accuracy)
                    app_state['training_metrics']['loss'].append(loss)
                    
                    # Keep only last 100 data points
                    if len(app_state['training_metrics']['accuracy']) > 100:
                        app_state['training_metrics']['accuracy'] = app_state['training_metrics']['accuracy'][-100:]
                        app_state['training_metrics']['loss'] = app_state['training_metrics']['loss'][-100:]
                    
                    # Train model every 100 samples
                    if len(defense_system.training_data) >= 100 and epoch % 10 == 0:
                        print(f"Retraining models at epoch {epoch}...")
                        defense_system.train_defense_model()
                        # Keep only recent training data to prevent memory issues
                        defense_system.training_data = defense_system.training_data[-1500:]
                    
                    time.sleep(0.5)  # Training speed control
                    
                except Exception as e:
                    print(f"Continuous training error: {e}")
                    time.sleep(2)
            
            app_state['training_thread_running'] = False
            print("Continuous training stopped")
        
        if not app_state.get('training_thread_running', False):
            thread = threading.Thread(target=training_loop)
            thread.daemon = True
            thread.start()
    
    def stop_continuous_training():
        app_state['continuous_training'] = False
        app_state['training_in_progress'] = False
        app_state['training_mode'] = False
    
    @app.route('/api/generate_training_data')
    def generate_training_data():
        data_type = request.args.get('type', 'mixed')
        count = 0
        
        try:
            if data_type == 'normal':
                for _ in range(100):
                    normal_traffic = attack_simulator.generate_normal_traffic()
                    defense_system.training_data.append({
                        'features': normal_traffic,
                        'label': 0
                    })
                    count += 1
                app_state['training_data_generated']['normal'] += count
                
            elif data_type == 'attack':
                attack_types = ['DDoS', 'Port Scan', 'Brute Force']
                for attack_type in attack_types:
                    for _ in range(30):
                        attack_data = attack_simulator.launch_attack(attack_type)['data']
                        label = 2 if attack_type == 'DDoS' else 1
                        defense_system.training_data.append({
                            'features': attack_data,
                            'label': label
                        })
                        count += 1
                app_state['training_data_generated']['attack'] += count
                
            elif data_type == 'mixed':
                # Generate mixed dataset
                for _ in range(70):
                    normal_traffic = attack_simulator.generate_normal_traffic()
                    defense_system.training_data.append({
                        'features': normal_traffic,
                        'label': 0
                    })
                app_state['training_data_generated']['normal'] += 70
                
                attack_types = ['DDoS', 'Port Scan', 'Brute Force']
                for attack_type in attack_types:
                    for _ in range(10):
                        attack_data = attack_simulator.launch_attack(attack_type)['data']
                        label = 2 if attack_type == 'DDoS' else 1
                        defense_system.training_data.append({
                            'features': attack_data,
                            'label': label
                        })
                app_state['training_data_generated']['attack'] += 30
                count = 100
            
            return jsonify({
                'success': True,
                'count': count,
                'type': data_type
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            })
    
    @app.route('/api/training_stats')
    def get_training_stats():
        defense_stats = defense_system.get_defense_stats()
        
        # Calculate current accuracy and epochs from training metrics
        current_accuracy = 0
        current_epochs = app_state['training_metrics']['epochs']
        
        if app_state['training_metrics']['accuracy']:
            current_accuracy = min(95, max(0, app_state['training_metrics']['accuracy'][-1]))
        
        return jsonify({
            'total_samples': len(defense_system.training_data),
            'normal_samples': app_state['training_data_generated']['normal'],
            'attack_samples': app_state['training_data_generated']['attack'],
            'model_trained': defense_stats.get('model_trained', False),
            'accuracy': round(current_accuracy, 1),
            'epochs': current_epochs,
            'training_in_progress': app_state['training_in_progress'],
            'continuous_training': app_state['continuous_training'],
            'training_metrics': {
                'accuracy': app_state['training_metrics']['accuracy'][-50:],  # Last 50 points
                'loss': app_state['training_metrics']['loss'][-50:],
                'epochs': list(range(max(1, current_epochs-49), current_epochs+1))
            }
        })
    
    @app.route('/api/save_ai_models')
    def save_ai_models():
        try:
            if not app_state['training_in_progress'] and len(defense_system.training_data) == 0:
                return jsonify({
                    'success': False,
                    'message': 'No training data available. Start training first!'
                })
            
            # Ensure models are trained before saving
            if len(defense_system.training_data) >= 100:
                print("Training models before saving...")
                defense_system.train_defense_model()
            
            # Save anomaly detector if it has a model
            anomaly_saved = False
            try:
                if hasattr(anomaly_detector, 'model') and anomaly_detector.model is not None:
                    anomaly_detector.save_model('models/anomaly_detector.pth')
                    anomaly_saved = True
            except Exception as e:
                print(f"Could not save anomaly detector: {e}")
            
            # Save defense system
            defense_saved = defense_system.save_model('models/defense_system.pth')
            
            if defense_saved:
                return jsonify({
                    'success': True,
                    'message': f'Defense model saved successfully. Anomaly detector: {"saved" if anomaly_saved else "not available"}'
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
            anomaly_loaded = False
            try:
                anomaly_loaded = anomaly_detector.load_model('models/anomaly_detector.pth')
            except Exception as e:
                print(f"Could not load anomaly detector: {e}")
            
            defense_loaded = defense_system.load_model('models/defense_system.pth')
            
            return jsonify({
                'success': True,
                'anomaly_loaded': anomaly_loaded,
                'defense_loaded': defense_loaded,
                'message': f'Models loaded - Defense: {"✓" if defense_loaded else "✗"}, Anomaly: {"✓" if anomaly_loaded else "✗"}'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error loading models: {str(e)}'
            })
    
    # ==================== TESTING MODE ENDPOINTS ====================
    
    @app.route('/api/enable_testing_mode', methods=['POST'])
    def enable_testing_mode():
        data = request.get_json()
        enabled = data.get('enabled', False)
        
        if enabled and app_state['training_mode']:
            return jsonify({
                'success': False,
                'message': 'Cannot enable testing mode while training is active'
            })
        
        app_state['testing_mode'] = enabled
        app_state['defense_active'] = enabled
        
        # Configure defense system for testing
        defense_system.set_defense_mode(enabled)
        
        if not enabled:
            app_state['auto_attack'] = False
            app_state['simulation_running'] = False
        
        return jsonify({
            'success': True,
            'testing_mode': app_state['testing_mode'],
            'message': f'Testing mode {"enabled" if enabled else "disabled"}'
        })
    
    @app.route('/api/launch_attack')
    def launch_attack():
        if not app_state['testing_mode']:
            return jsonify({
                'success': False,
                'message': 'Testing mode must be enabled to launch attacks'
            })
        
        attack_type = request.args.get('type', None)
        attack_info = attack_simulator.launch_attack(attack_type)
        
        # Test defense system
        defense_result = defense_system.defend_against_attack(attack_info['data'])
        
        # Update test results
        app_state['test_results']['total_tests'] += 1
        if defense_result['blocked'] or defense_result['threat_level'] != 'Normal':
            app_state['test_results']['successful_detections'] += 1
        
        return jsonify({
            'success': True,
            'attack': {
                'type': attack_info['type'],
                'severity': attack_info['severity'],
                'timestamp': attack_info['timestamp'].isoformat(),
                'data': attack_info['data']
            },
            'defense': defense_result
        })
    
    @app.route('/api/auto_attack', methods=['POST'])
    def toggle_auto_attack():
        if not app_state['testing_mode']:
            return jsonify({
                'success': False,
                'message': 'Testing mode must be enabled for auto attacks'
            })
        
        data = request.get_json()
        app_state['auto_attack'] = data.get('enabled', False)
        app_state['attack_interval'] = data.get('interval', 5)
        
        if app_state['auto_attack'] and not app_state['simulation_running']:
            start_auto_attack_simulation()
        
        return jsonify({
            'success': True,
            'auto_attack': app_state['auto_attack'],
            'interval': app_state['attack_interval']
        })
    
    def start_auto_attack_simulation():
        app_state['simulation_running'] = True
        
        def simulation_loop():
            while app_state['auto_attack'] and app_state['simulation_running'] and app_state['testing_mode']:
                try:
                    # Launch random attack
                    attack_info = attack_simulator.launch_attack()
                    
                    # Test defense
                    defense_result = defense_system.defend_against_attack(attack_info['data'])
                    
                    # Update test results
                    app_state['test_results']['total_tests'] += 1
                    if defense_result['blocked'] or defense_result['threat_level'] != 'Normal':
                        app_state['test_results']['successful_detections'] += 1
                    
                    print(f"Auto-attack: {attack_info['type']} -> {defense_result['action']}")
                    
                    time.sleep(app_state['attack_interval'])
                    
                except Exception as e:
                    print(f"Auto-attack simulation error: {e}")
                    time.sleep(2)
            
            app_state['simulation_running'] = False
        
        thread = threading.Thread(target=simulation_loop)
        thread.daemon = True
        thread.start()
    
    @app.route('/api/reset_test_results')
    def reset_test_results():
        app_state['test_results'] = {'total_tests': 0, 'successful_detections': 0}
        defense_system.reset_blocks()
        
        return jsonify({
            'success': True,
            'message': 'Test results reset successfully'
        })
    
    # ==================== MONITORING ENDPOINTS ====================
    
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
    
    # ==================== SHARED ENDPOINTS ====================
    
    @app.route('/api/defense_stats')
    def get_defense_stats():
        defense_stats = defense_system.get_defense_stats()
        
        # Add testing-specific stats
        if app_state['testing_mode']:
            total_tests = app_state['test_results']['total_tests']
            successful = app_state['test_results']['successful_detections']
            defense_stats['test_results'] = {
                'total_tests': total_tests,
                'successful_detections': successful,
                'detection_rate': (successful / total_tests * 100) if total_tests > 0 else 0
            }
        
        return jsonify(defense_stats)
    
    @app.route('/api/attack_stats')
    def get_attack_stats():
        return jsonify(attack_simulator.get_attack_stats())
    
    @app.route('/api/ai_training_status')
    def get_ai_training_status():
        return jsonify({
            'training_in_progress': app_state['training_in_progress'],
            'training_mode': app_state['training_mode'],
            'continuous_training': app_state['continuous_training']
        })
    
    # Legacy endpoints for backward compatibility
    @app.route('/api/toggle_defense', methods=['POST'])
    def toggle_defense():
        data = request.get_json()
        enabled = data.get('enabled', True)
        
        # This now maps to testing mode
        return enable_testing_mode()
    
    return app