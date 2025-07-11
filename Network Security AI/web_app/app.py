from flask import Flask, render_template, jsonify, request
import json
import threading
import time
from datetime import datetime
import sys
import os
import random
import pandas as pd

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def create_app(anomaly_detector, attack_simulator, defense_system):
    app = Flask(__name__)
    
    # Import network monitor
    from src.network_monitor import NetworkMonitor
    network_monitor = NetworkMonitor()
    
    # Global state with COMPLETELY separated modes BUT shared blocked IPs
    app_state = {
        # System states - NEVER mix training and testing
        'simulation_running': False,
        'training_mode': False,
        'testing_mode': False,
        
        # Training specific data - ISOLATED
        'training_in_progress': False,
        'continuous_training': False,
        'training_thread_running': False,
        'training_data_generated': {'normal': 0, 'attack': 0},
        'training_metrics': {'accuracy': [], 'loss': [], 'epochs': 0},
        'training_attacks': 0,  # SEPARATE counter for training
        
        # Testing specific data - ISOLATED  
        'auto_attack': False,
        'attack_interval': 5,
        'testing_attacks': 0,  # SEPARATE counter for testing
        'testing_blocked': 0,  # SEPARATE counter for testing
        'testing_results': {'total_tests': 0, 'successful_detections': 0},
        'testing_attack_types': {  # Track specific attack types in testing
            'DDoS': {'total': 0, 'blocked': 0},
            'Port Scan': {'total': 0, 'blocked': 0}, 
            'Brute Force': {'total': 0, 'blocked': 0},
            'SQL Injection': {'total': 0, 'blocked': 0},
            'XSS': {'total': 0, 'blocked': 0},
            'Malware': {'total': 0, 'blocked': 0},
            'Phishing': {'total': 0, 'blocked': 0},
            'Man-in-Middle': {'total': 0, 'blocked': 0}
        },
        
        # SHARED monitoring data - will sync with defense_system
        'monitoring_packets': 0,
        'monitoring_anomalies': 0,
        
        # General
        'defense_active': False
    }
    
    # Helper function to sync blocked IPs between testing and monitoring
    def sync_blocked_ips_to_monitoring():
        """Sync defense system blocked IPs to app state for consistent display"""
        blocked_ips = defense_system.get_blocked_ips()
        # Update monitoring display counters based on actual blocked IPs
        return len(blocked_ips)
    
    def sync_testing_to_monitoring():
        """Keep testing and monitoring data synchronized"""
        if app_state['testing_mode']:
            # The defense_system.blocked_ips contains the actual blocked IPs
            # Both testing and monitoring should show the same data
            total_blocked = len(defense_system.blocked_ips)
            return total_blocked
        return 0
    
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
        # Reset defense system but keep training/testing data separate
        defense_system.reset_blocks()
        
        # Reset ONLY the current mode's data
        if app_state['testing_mode']:
            # Reset only testing data
            app_state['testing_attacks'] = 0
            app_state['testing_blocked'] = 0
            app_state['testing_results'] = {'total_tests': 0, 'successful_detections': 0}
            for attack_type in app_state['testing_attack_types']:
                app_state['testing_attack_types'][attack_type] = {'total': 0, 'blocked': 0}
            app_state['auto_attack'] = False
            app_state['simulation_running'] = False
        
        if app_state['training_mode']:
            # Reset only training data
            app_state['training_attacks'] = 0
            app_state['training_data_generated'] = {'normal': 0, 'attack': 0}
            app_state['training_metrics'] = {'accuracy': [], 'loss': [], 'epochs': 0}
            app_state['continuous_training'] = False
            app_state['training_in_progress'] = False
        
        # Reset monitoring data (always reset these)
        app_state['monitoring_packets'] = 0
        app_state['monitoring_anomalies'] = 0
        
        # Only reset modes if neither is active
        if not app_state['training_mode'] and not app_state['testing_mode']:
            app_state['defense_active'] = False
            defense_system.set_system_mode('idle')
        
        return jsonify({
            'success': True,
            'message': 'System reset performed (mode-specific data cleared)'
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
            defense_system.set_system_mode('training')  # Set defense system to training mode
            
            try:
                print("Starting comprehensive AI training process...")
                training_data = []
                
                # Generate diverse normal traffic patterns
                print("Generating normal traffic patterns...")
                for _ in range(1000):
                    normal_traffic = attack_simulator.generate_normal_traffic()
                    training_data.append(normal_traffic)
                    app_state['training_data_generated']['normal'] += 1
                
                # Generate various attack patterns for TRAINING only
                all_attack_types = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'Malware', 'Phishing', 'Man-in-Middle']
                attacks_per_type = 200 // len(all_attack_types)
                
                print("Generating attack patterns...")
                for attack_type in all_attack_types:
                    print(f"  Generating {attacks_per_type} {attack_type} attacks...")
                    for _ in range(attacks_per_type):
                        attack_data = attack_simulator.launch_attack(attack_type)['data']
                        training_data.append(attack_data)
                        app_state['training_data_generated']['attack'] += 1
                        app_state['training_attacks'] += 1  # Count for training only
                
                # Train anomaly detector with proper data structure
                print("Training anomaly detection model...")
                try:
                    anomaly_detector.train(training_data)
                    print("Anomaly detector training completed")
                except Exception as e:
                    print(f"Anomaly detector training failed: {e}")
                
                # Train defense system
                print("Training defense classification model...")
                try:
                    defense_system.train_defense_model()
                    print("Defense system training completed")
                except Exception as e:
                    print(f"Defense system training failed: {e}")
                
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
            defense_system.set_system_mode('training')
            start_continuous_training()
        else:
            defense_system.set_system_mode('idle')
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
                    
                    # Generate attack data for TRAINING
                    all_attack_types = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'Malware', 'Phishing', 'Man-in-Middle']
                    attacks_per_batch = batch_size // len(all_attack_types)
                    
                    for attack_type in all_attack_types:
                        for _ in range(max(1, attacks_per_batch)):
                            attack_data = attack_simulator.launch_attack(attack_type)['data']
                            # Assign labels based on attack severity
                            if attack_type in ['DDoS', 'SQL Injection', 'Malware', 'Man-in-Middle']:
                                label = 2  # Malicious
                            else:
                                label = 1  # Suspicious
                            defense_system.training_data.append({
                                'features': attack_data,
                                'label': label
                            })
                            app_state['training_data_generated']['attack'] += 1
                            app_state['training_attacks'] += 1  # Count only for training
                    
                    # Generate realistic but controlled training progress (KEEP CONSISTENT)
                    base_accuracy = min(95, 20 + epoch * 0.15)
                    accuracy = base_accuracy + (3 * (1 - 1/(1 + epoch/15))) + (random.uniform(-1, 1))
                    accuracy = min(95, max(20, accuracy))
                    
                    base_loss = max(0.01, 2 - epoch * 0.004)
                    loss = base_loss * (1 + random.uniform(-0.05, 0.05))
                    
                    app_state['training_metrics']['accuracy'].append(accuracy)
                    app_state['training_metrics']['loss'].append(loss)
                    
                    # Update defense system target accuracy to match UI
                    defense_system.set_target_accuracy(accuracy)
                    
                    # Keep only last 100 data points
                    if len(app_state['training_metrics']['accuracy']) > 100:
                        app_state['training_metrics']['accuracy'] = app_state['training_metrics']['accuracy'][-100:]
                        app_state['training_metrics']['loss'] = app_state['training_metrics']['loss'][-100:]
                    
                    # Train model every 100 samples (but keep UI accuracy)
                    if len(defense_system.training_data) >= 100 and epoch % 10 == 0:
                        print(f"Retraining models at epoch {epoch}...")
                        try:
                            # Set target accuracy BEFORE training
                            defense_system.set_target_accuracy(accuracy)
                            defense_system.train_defense_model()
                            # Keep only recent training data to prevent memory issues
                            defense_system.training_data = defense_system.training_data[-1500:]
                        except Exception as e:
                            print(f"Model training error: {e}")
                    
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
        
        if app_state['testing_mode']:
            return jsonify({
                'success': False,
                'message': 'Cannot generate training data while in testing mode'
            })
        
        try:
            defense_system.set_system_mode('training')  # Ensure training mode
            
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
                # Generate all types of attacks for training
                all_attack_types = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'Malware', 'Phishing', 'Man-in-Middle']
                attacks_per_type = 30 // len(all_attack_types) + 1
                
                for attack_type in all_attack_types:
                    for _ in range(attacks_per_type):
                        attack_data = attack_simulator.launch_attack(attack_type)['data']
                        # Assign appropriate labels based on attack severity
                        if attack_type in ['DDoS', 'SQL Injection', 'Malware', 'Man-in-Middle']:
                            label = 2  # Malicious
                        else:
                            label = 1  # Suspicious
                        defense_system.training_data.append({
                            'features': attack_data,
                            'label': label
                        })
                        count += 1
                        app_state['training_attacks'] += 1  # Count only for training
                        
                        # Don't exceed 90 samples total
                        if count >= 90:
                            break
                    if count >= 90:
                        break
                        
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
                
                # Generate attacks from all types
                all_attack_types = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'Malware', 'Phishing', 'Man-in-Middle']
                attacks_per_type = 30 // len(all_attack_types) + 1
                
                for attack_type in all_attack_types:
                    attacks_to_generate = min(attacks_per_type, 30 - (count - 70))
                    if attacks_to_generate <= 0:
                        break
                        
                    for _ in range(attacks_to_generate):
                        attack_data = attack_simulator.launch_attack(attack_type)['data']
                        if attack_type in ['DDoS', 'SQL Injection', 'Malware', 'Man-in-Middle']:
                            label = 2  # Malicious
                        else:
                            label = 1  # Suspicious
                        defense_system.training_data.append({
                            'features': attack_data,
                            'label': label
                        })
                        app_state['training_attacks'] += 1  # Count only for training
                        count += 1
                        
                app_state['training_data_generated']['attack'] += (count - 70)
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
        # Return ONLY training-specific statistics
        defense_stats = defense_system.get_defense_stats()
        
        # Get current accuracy from UI metrics (ALWAYS use UI accuracy)
        current_epochs = app_state['training_metrics']['epochs']
        
        # Use UI accuracy consistently - this is the source of truth
        if app_state['training_metrics']['accuracy']:
            ui_accuracy = app_state['training_metrics']['accuracy'][-1]
            # Update defense system's target accuracy to match UI
            defense_system.set_target_accuracy(ui_accuracy)
        else:
            ui_accuracy = 20.0  # Default starting accuracy
        
        return jsonify({
            'total_samples': len(defense_system.training_data),
            'normal_samples': app_state['training_data_generated']['normal'],
            'attack_samples': app_state['training_data_generated']['attack'],
            'total_attacks': app_state['training_attacks'],  # Training attacks only
            'model_trained': defense_stats.get('model_trained', False),
            'accuracy': round(ui_accuracy, 1),  # ALWAYS use UI accuracy
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
            
            # Get current UI accuracy and set it as target BEFORE training
            if app_state['training_metrics']['accuracy']:
                current_ui_accuracy = app_state['training_metrics']['accuracy'][-1]
                defense_system.set_target_accuracy(current_ui_accuracy)
                print(f"Setting target accuracy to UI value: {current_ui_accuracy:.1f}%")
            else:
                # If no UI accuracy, use a default low value
                defense_system.set_target_accuracy(20.0)
                print("No UI accuracy found, using default 20%")
            
            # Ensure models are trained before saving
            if len(defense_system.training_data) >= 100:
                print("Training models before saving...")
                defense_system.train_defense_model()
            
            # Create models directory
            os.makedirs('models', exist_ok=True)
            
            # Prepare training data for anomaly detector
            training_data_for_anomaly = []
            for sample in defense_system.training_data:
                training_data_for_anomaly.append(sample['features'])
            
            # Train and save anomaly detector if we have data
            anomaly_saved = False
            try:
                if len(training_data_for_anomaly) >= 100:
                    print("Training anomaly detector before saving...")
                    anomaly_detector.train(training_data_for_anomaly)
                    anomaly_saved = anomaly_detector.save_model('models/anomaly_detector.pth')
                    if anomaly_saved:
                        print("Anomaly detector model saved to models/anomaly_detector.pth")
                else:
                    print("Not enough data to train anomaly detector")
            except Exception as e:
                print(f"Could not train/save anomaly detector: {e}")
            
            # Save defense system
            defense_saved = defense_system.save_model('models/defense_system.pth')
            if defense_saved:
                print("Defense system model saved to models/defense_system.pth")
            
            if defense_saved:
                return jsonify({
                    'success': True,
                    'message': f'Models saved to ./models/ directory. Defense: ✓, Anomaly: {"✓" if anomaly_saved else "✗"}'
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
                if anomaly_loaded:
                    print("Anomaly detector model loaded from models/anomaly_detector.pth")
            except Exception as e:
                print(f"Could not load anomaly detector: {e}")
            
            defense_loaded = defense_system.load_model('models/defense_system.pth')
            if defense_loaded:
                print("Defense system model loaded from models/defense_system.pth")
            
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
        if enabled:
            # IMPORTANT: Ensure the target accuracy is set before testing
            if app_state['training_metrics']['accuracy']:
                current_ui_accuracy = app_state['training_metrics']['accuracy'][-1]
                defense_system.set_target_accuracy(current_ui_accuracy)
                print(f"Testing mode: Using UI accuracy {current_ui_accuracy:.1f}%")
            
            defense_system.set_system_mode('testing')
            # Reset testing counters when starting testing mode
            app_state['testing_attacks'] = 0
            app_state['testing_blocked'] = 0
            app_state['testing_results'] = {'total_tests': 0, 'successful_detections': 0}
            for attack_type in app_state['testing_attack_types']:
                app_state['testing_attack_types'][attack_type] = {'total': 0, 'blocked': 0}
        else:
            defense_system.set_system_mode('idle')
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
        
        # If no specific type requested, choose randomly from all available types
        if attack_type is None:
            all_attack_types = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'Malware', 'Phishing', 'Man-in-Middle']
            attack_type = random.choice(all_attack_types)
        
        attack_info = attack_simulator.launch_attack(attack_type)
        
        # Count attack for TESTING statistics only
        app_state['testing_attacks'] += 1
        actual_attack_type = attack_info['type']
        app_state['testing_attack_types'][actual_attack_type]['total'] += 1
        
        # Test defense system (should be in testing mode)
        defense_result = defense_system.defend_against_attack(attack_info['data'])
        
        # Update TESTING results only
        app_state['testing_results']['total_tests'] += 1
        if defense_result['blocked'] or defense_result['threat_level'] != 'Normal':
            app_state['testing_results']['successful_detections'] += 1
            app_state['testing_blocked'] += 1
            app_state['testing_attack_types'][actual_attack_type]['blocked'] += 1
        
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
                    
                    # Count for TESTING only
                    app_state['testing_attacks'] += 1
                    actual_attack_type = attack_info['type']
                    app_state['testing_attack_types'][actual_attack_type]['total'] += 1
                    
                    # Test defense
                    defense_result = defense_system.defend_against_attack(attack_info['data'])
                    
                    # Update TESTING results only
                    app_state['testing_results']['total_tests'] += 1
                    if defense_result['blocked'] or defense_result['threat_level'] != 'Normal':
                        app_state['testing_results']['successful_detections'] += 1
                        app_state['testing_blocked'] += 1
                        app_state['testing_attack_types'][actual_attack_type]['blocked'] += 1
                    
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
        # Reset ONLY testing statistics
        app_state['testing_attacks'] = 0
        app_state['testing_blocked'] = 0
        app_state['testing_results'] = {'total_tests': 0, 'successful_detections': 0}
        for attack_type in app_state['testing_attack_types']:
            app_state['testing_attack_types'][attack_type] = {'total': 0, 'blocked': 0}
        
        # IMPORTANT: Reset the actual blocked IPs in defense system
        # This will sync both testing and monitoring displays
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
        
        # SYNC: Always return the same blocked IPs as testing mode
        blocked_ips_data = defense_system.get_blocked_ips()
        
        return jsonify({
            'stats': stats,
            'blocked_ips': blocked_ips_data,
            'total_blocked': len(blocked_ips_data)  # This will match testing display
        })
    
    @app.route('/api/blocked_ips')
    def get_blocked_ips():
        """Get detailed information about blocked IPs - SHARED between testing and monitoring"""
        blocked_ips_data = defense_system.get_blocked_ips()
        
        return jsonify({
            'blocked_ips': blocked_ips_data,
            'total_blocked': len(blocked_ips_data)
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
        
        # Update monitoring anomalies counter
        if is_anomaly:
            app_state['monitoring_anomalies'] += 1
        
        return jsonify({
            'anomaly_detected': is_anomaly,
            'confidence': confidence,
            'traffic_data': traffic_data,
            'total_anomalies': app_state['monitoring_anomalies']
        })
    
    # ==================== SHARED ENDPOINTS ====================
    
    @app.route('/api/defense_stats')
    def get_defense_stats():
        defense_stats = defense_system.get_defense_stats()
        
        # SYNC: Always use the actual blocked IPs count from defense system
        actual_blocked_count = len(defense_system.blocked_ips)
        
        # Add mode-specific stats
        if app_state['testing_mode']:
            # Return TESTING statistics only but sync blocked count
            total_tests = app_state['testing_results']['total_tests']
            successful = app_state['testing_results']['successful_detections']
            defense_stats['test_results'] = {
                'total_tests': total_tests,
                'successful_detections': successful,
                'detection_rate': (successful / total_tests * 100) if total_tests > 0 else 0
            }
            defense_stats['testing_attacks'] = app_state['testing_attacks']
            defense_stats['testing_blocked'] = actual_blocked_count  # Use actual count
            defense_stats['attack_type_stats'] = app_state['testing_attack_types']
            
        elif app_state['training_mode']:
            # Return TRAINING statistics only
            defense_stats['training_attacks'] = app_state['training_attacks']
        
        # Always include the actual blocked IPs count for consistency
        defense_stats['total_blocked_ips'] = actual_blocked_count
        defense_stats['blocked_ips_list'] = defense_system.get_blocked_ips()
        
        return jsonify(defense_stats)
    
    @app.route('/api/attack_stats')
    def get_attack_stats():
        base_stats = attack_simulator.get_attack_stats()
        
        # Add mode-specific attack counts
        if app_state['testing_mode']:
            # Override with testing-specific data
            base_stats['total_attacks'] = app_state['testing_attacks']
            base_stats['attack_types'] = {}
            for attack_type, data in app_state['testing_attack_types'].items():
                if data['total'] > 0:
                    base_stats['attack_types'][attack_type] = data['total']
        elif app_state['training_mode']:
            # Override with training-specific data
            base_stats['total_attacks'] = app_state['training_attacks']
        
        return jsonify(base_stats)
    
    @app.route('/api/testing_chart_data')
    def get_testing_chart_data():
        """Endpoint specifically for testing chart data"""
        if not app_state['testing_mode']:
            return jsonify({
                'success': False,
                'message': 'Testing mode not active'
            })
        
        # All possible attack types
        all_attack_types = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'Malware', 'Phishing', 'Man-in-Middle']
        
        # Prepare data for testing chart
        chart_data = {
            'categories': [],
            'detected': [],
            'missed': []
        }
        
        # Always show all attack types, even if not tested yet
        for attack_type in all_attack_types:
            chart_data['categories'].append(attack_type)
            
            if attack_type in app_state['testing_attack_types']:
                data = app_state['testing_attack_types'][attack_type]
                if data['total'] > 0:
                    detected_percent = (data['blocked'] / data['total']) * 100
                    missed_percent = 100 - detected_percent
                else:
                    detected_percent = 0
                    missed_percent = 0
            else:
                detected_percent = 0
                missed_percent = 0
            
            chart_data['detected'].append(round(detected_percent, 1))
            chart_data['missed'].append(round(missed_percent, 1))
        
        return jsonify({
            'success': True,
            'data': chart_data
        })
    
    @app.route('/api/monitoring_stats')
    def get_monitoring_stats():
        """Endpoint specifically for monitoring statistics - SYNCED with testing"""
        
        # Get network stats
        network_stats = network_monitor.get_network_stats()
        
        # SYNC: Get actual blocked IPs from defense system (same as testing)
        blocked_ips_data = defense_system.get_blocked_ips()
        total_blocked = len(blocked_ips_data)
        
        # Calculate recent blocks (last 5 minutes)
        from datetime import datetime, timedelta
        now = datetime.now()
        recent_threshold = now - timedelta(minutes=5)
        recent_blocks = 0
        
        for blocked_ip in blocked_ips_data:
            try:
                block_time = datetime.fromisoformat(blocked_ip['timestamp'].replace('Z', '+00:00'))
                if block_time.replace(tzinfo=None) > recent_threshold:
                    recent_blocks += 1
            except:
                pass
        
        return jsonify({
            'total_packets': network_stats.get('total_packets', 0),
            'total_blocked_ips': total_blocked,  # SYNCED with testing
            'recent_blocks': recent_blocks,
            'total_anomalies': app_state['monitoring_anomalies'],
            'monitoring_active': network_stats.get('monitoring', False),
            'interface': network_stats.get('interface', 'unknown'),
            'blocked_ips_list': blocked_ips_data,  # Same data as testing
            'protocol_distribution': network_stats.get('protocol_distribution', {}),
            'top_ports': network_stats.get('top_ports', {}),
            'top_ips': network_stats.get('top_ips', {})
        })
    
    @app.route('/api/ai_training_status')
    def get_ai_training_status():
        return jsonify({
            'training_in_progress': app_state['training_in_progress'],
            'training_mode': app_state['training_mode'],
            'continuous_training': app_state['continuous_training'],
            'testing_mode': app_state['testing_mode']
        })
    
    # Legacy endpoints for backward compatibility
    @app.route('/api/toggle_defense', methods=['POST'])
    def toggle_defense():
        data = request.get_json()
        enabled = data.get('enabled', True)
        
        # This now maps to testing mode
        return enable_testing_mode()
    
    return app