import asyncio
import time
import threading
from queue import Queue, Empty
from loguru import logger
from typing import Dict, List, Any, Optional, Callable
import psutil
import socket
import struct
from collections import defaultdict, deque
import json
from datetime import datetime

from .feature_extractor import NetworkFeatureExtractor
from .anomaly_detector import AnomalyDetector
from .alerting_system import AlertingSystem

class NetworkMonitor:
    """
    Real-time network traffic monitor pentru detectia anomaliilor
    """
    def __init__(self, interface: str = None, buffer_size: int = 10000):
        self.interface = interface or self._get_default_interface()
        self.buffer_size = buffer_size
        
        # Components
        self.feature_extractor = NetworkFeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.alerting_system = AlertingSystem()
        
        # Monitoring state
        self.is_monitoring = False
        self.packet_queue = Queue(maxsize=buffer_size)
        self.stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'start_time': None,
            'flows_active': 0,
            'alerts_sent': 0
        }
        
        # Real-time data
        self.recent_flows = deque(maxlen=1000)
        self.anomaly_history = deque(maxlen=500)
        self.threshold_adaptive = 0.5
        
        logger.info(f"NetworkMonitor initialized for interface: {self.interface}")
    
    def _get_default_interface(self) -> str:
        """Detecteaza interfata de retea principala"""
        try:
            # Get network interfaces
            interfaces = psutil.net_if_stats()
            for interface, stats in interfaces.items():
                if stats.isup and not interface.startswith('lo'):
                    logger.info(f"Using network interface: {interface}")
                    return interface
            return 'eth0'  # Fallback
        except Exception as e:
            logger.warning(f"Could not detect interface: {e}")
            return 'any'
    
    async def start_monitoring(self):
        """Porneste monitorizarea in timp real"""
        if self.is_monitoring:
            logger.warning("Monitoring already running")
            return
        
        logger.info("Starting real-time network monitoring...")
        self.is_monitoring = True
        self.stats['start_time'] = time.time()
        
        # Load trained models
        await self._load_models()
        
        # Start monitoring tasks
        tasks = [
            asyncio.create_task(self._packet_capture_task()),
            asyncio.create_task(self._packet_processing_task()),
            asyncio.create_task(self._anomaly_detection_task()),
            asyncio.create_task(self._adaptive_threshold_task()),
            asyncio.create_task(self._cleanup_task())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Monitoring tasks cancelled")
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        finally:
            self.is_monitoring = False
    
    async def stop_monitoring(self):
        """Opreste monitorizarea"""
        logger.info("Stopping network monitoring...")
        self.is_monitoring = False
        
        # Cleanup
        await self._save_session_data()
        
    async def _load_models(self):
        """Incarca modelele antrenate"""
        try:
            self.anomaly_detector.load_models()
            logger.info("Anomaly detection models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            # Continue with basic monitoring
    
    async def _packet_capture_task(self):
        """Task pentru capturarea pachetelor"""
        logger.info("Starting packet capture...")
        
        # Mock packet capture pentru demo
        # În producție, aici ar fi integrarea cu Scapy sau libpcap
        while self.is_monitoring:
            try:
                # Simulate network packet capture
                mock_packet = self._generate_mock_packet()
                
                if not self.packet_queue.full():
                    self.packet_queue.put(mock_packet)
                else:
                    logger.warning("Packet queue full, dropping packet")
                
                await asyncio.sleep(0.01)  # 100 packets/sec simulation
                
            except Exception as e:
                logger.error(f"Packet capture error: {e}")
                await asyncio.sleep(1)
    
    def _generate_mock_packet(self) -> Dict[str, Any]:
        """Genereaza pachete mock pentru demo"""
        import random
        
        # Simulate realistic network traffic
        packet_types = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
        protocols = [6, 17, 1]  # TCP, UDP, ICMP
        
        # 95% normal traffic, 5% potential anomalies
        is_anomaly = random.random() < 0.05
        
        if is_anomaly:
            # Simulate anomalous patterns
            packet = {
                'timestamp': time.time(),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 21, 25]),
                'protocol': random.choice(protocols),
                'packet_length': random.randint(1200, 1500),  # Large packets
                'flags': random.randint(0, 255),
                'type': 'ANOMALY_SIM'
            }
        else:
            packet = {
                'timestamp': time.time(),
                'src_ip': f"192.168.1.{random.randint(1, 50)}",
                'dst_ip': f"8.8.8.{random.randint(1, 8)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 53]),
                'protocol': random.choice([6, 17]),
                'packet_length': random.randint(64, 1200),
                'flags': random.choice([2, 16, 24]),  # SYN, ACK, PSH+ACK
                'type': 'NORMAL_SIM'
            }
        
        return packet
    
    async def _packet_processing_task(self):
        """Task pentru procesarea pachetelor si extragerea features"""
        logger.info("Starting packet processing...")
        
        while self.is_monitoring:
            try:
                # Get packet from queue
                try:
                    packet = self.packet_queue.get(timeout=1)
                except Empty:
                    continue
                
                # Extract features
                features = await self._process_packet(packet)
                
                if features:
                    # Add to recent flows
                    self.recent_flows.append({
                        'timestamp': packet['timestamp'],
                        'features': features,
                        'packet_info': packet
                    })
                    
                    self.stats['packets_processed'] += 1
                
                # Update active flows count
                self.stats['flows_active'] = len(self.feature_extractor.flow_cache)
                
                await asyncio.sleep(0.001)  # Small delay
                
            except Exception as e:
                logger.error(f"Packet processing error: {e}")
                await asyncio.sleep(0.1)
    
    async def _process_packet(self, packet: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Proceseaza un pachet si returneaza features"""
        try:
            # Create flow key
            flow_key = f"{packet['src_ip']}:{packet['src_port']}-{packet['dst_ip']}:{packet['dst_port']}-{packet['protocol']}"
            
            # Update flow in feature extractor
            self.feature_extractor.update_flow_features(packet, flow_key)
            
            # Calculate features for flow
            features = self.feature_extractor.calculate_flow_features(flow_key)
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return None
    
    async def _anomaly_detection_task(self):
        """Task pentru detectia anomaliilor"""
        logger.info("Starting anomaly detection...")
        
        while self.is_monitoring:
            try:
                # Process recent flows for anomaly detection
                if len(self.recent_flows) >= 10:  # Process in batches
                    flows_to_check = []
                    
                    # Get flows for checking
                    for _ in range(min(10, len(self.recent_flows))):
                        if self.recent_flows:
                            flows_to_check.append(self.recent_flows.popleft())
                    
                    # Check for anomalies
                    for flow_data in flows_to_check:
                        is_anomaly, confidence = await self._detect_anomaly(flow_data)
                        
                        if is_anomaly:
                            await self._handle_anomaly(flow_data, confidence)
                
                await asyncio.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                logger.error(f"Anomaly detection error: {e}")
                await asyncio.sleep(1)
    
    async def _detect_anomaly(self, flow_data: Dict[str, Any]) -> tuple[bool, float]:
        """Detecteaza anomalii pentru un flow"""
        try:
            features = flow_data['features']
            
            if not features:
                return False, 0.0
            
            # Convert features to array format expected by models
            feature_array = [features.get(name, 0.0) for name in self.feature_extractor.feature_names]
            
            # Use anomaly detector
            prediction = self.anomaly_detector.predict_anomaly([feature_array])
            
            if prediction and len(prediction) > 0:
                is_anomaly = bool(prediction[0])
                confidence = 0.8 if is_anomaly else 0.2  # Mock confidence
                
                return is_anomaly, confidence
            
            return False, 0.0
            
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return False, 0.0
    
    async def _handle_anomaly(self, flow_data: Dict[str, Any], confidence: float):
        """Gestioneaza detectia unei anomalii"""
        try:
            anomaly_info = {
                'timestamp': datetime.now().isoformat(),
                'confidence': confidence,
                'flow_data': flow_data,
                'type': 'network_anomaly',
                'severity': self._calculate_severity(confidence)
            }
            
            # Add to history
            self.anomaly_history.append(anomaly_info)
            self.stats['anomalies_detected'] += 1
            
            # Send alert
            await self._send_alert(anomaly_info)
            
            logger.warning(f"Anomaly detected: {flow_data['packet_info']['src_ip']} -> "
                          f"{flow_data['packet_info']['dst_ip']} (confidence: {confidence:.2f})")
            
        except Exception as e:
            logger.error(f"Anomaly handling error: {e}")
    
    def _calculate_severity(self, confidence: float) -> str:
        """Calculeaza severitatea anomaliei"""
        if confidence >= 0.9:
            return 'CRITICAL'
        elif confidence >= 0.7:
            return 'HIGH'
        elif confidence >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    async def _send_alert(self, anomaly_info: Dict[str, Any]):
        """Trimite alerta pentru anomalie"""
        try:
            await self.alerting_system.send_alert(anomaly_info)
            self.stats['alerts_sent'] += 1
        except Exception as e:
            logger.error(f"Alert sending error: {e}")
    
    async def _adaptive_threshold_task(self):
        """Task pentru ajustarea automata a threshold-urilor"""
        logger.info("Starting adaptive threshold adjustment...")
        
        while self.is_monitoring:
            try:
                # Adjust threshold based on recent anomaly rate
                if len(self.anomaly_history) >= 50:
                    recent_anomalies = [a for a in self.anomaly_history if 
                                      time.time() - datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')).timestamp() < 300]
                    
                    anomaly_rate = len(recent_anomalies) / 50
                    
                    # Adjust threshold
                    if anomaly_rate > 0.1:  # Too many anomalies
                        self.threshold_adaptive = min(0.9, self.threshold_adaptive + 0.05)
                    elif anomaly_rate < 0.02:  # Too few anomalies
                        self.threshold_adaptive = max(0.3, self.threshold_adaptive - 0.05)
                    
                    logger.info(f"Adaptive threshold adjusted to: {self.threshold_adaptive:.2f}")
                
                await asyncio.sleep(60)  # Adjust every minute
                
            except Exception as e:
                logger.error(f"Adaptive threshold error: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_task(self):
        """Task pentru curatenia periodica"""
        while self.is_monitoring:
            try:
                # Cleanup old flows
                self.feature_extractor.cleanup_old_flows(timeout=300)
                
                # Cleanup old history
                current_time = time.time()
                self.anomaly_history = deque([
                    a for a in self.anomaly_history 
                    if current_time - datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')).timestamp() < 3600
                ], maxlen=500)
                
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
                await asyncio.sleep(300)
    
    async def _save_session_data(self):
        """Salveaza datele sesiunii"""
        try:
            session_data = {
                'stats': self.stats,
                'anomaly_history': list(self.anomaly_history)[-100:],  # Last 100 anomalies
                'session_end': time.time()
            }
            
            # Save to file or database
            with open(f"logs/monitoring_session_{int(time.time())}.json", 'w') as f:
                json.dump(session_data, f, indent=2)
                
            logger.info("Session data saved")
            
        except Exception as e:
            logger.error(f"Session save error: {e}")
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """Returneaza statistici in timp real"""
        runtime = time.time() - (self.stats['start_time'] or time.time())
        
        return {
            'packets_processed': self.stats['packets_processed'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'flows_active': self.stats['flows_active'],
            'alerts_sent': self.stats['alerts_sent'],
            'runtime_seconds': runtime,
            'packets_per_second': self.stats['packets_processed'] / max(runtime, 1),
            'anomaly_rate': self.stats['anomalies_detected'] / max(self.stats['packets_processed'], 1),
            'adaptive_threshold': self.threshold_adaptive,
            'is_monitoring': self.is_monitoring
        }
    
    def get_recent_anomalies(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returneaza anomaliile recente"""
        return list(self.anomaly_history)[-limit:]
    
    async def force_threshold_update(self, new_threshold: float):
        """Forteaza actualizarea threshold-ului"""
        if 0.1 <= new_threshold <= 0.95:
            self.threshold_adaptive = new_threshold
            logger.info(f"Threshold manually updated to: {new_threshold}")
        else:
            raise ValueError("Threshold must be between 0.1 and 0.95")