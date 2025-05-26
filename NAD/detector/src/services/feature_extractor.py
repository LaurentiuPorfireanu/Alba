import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Ether
from loguru import logger
from typing import Dict, List, Any, Tuple
import time
from collections import defaultdict

class NetworkFeatureExtractor:
    def __init__(self):
        self.flow_cache = defaultdict(dict)
        self.feature_names = self._get_feature_names()
        logger.info("NetworkFeatureExtractor initialized with {} features", len(self.feature_names))
        
    def _get_feature_names(self):
        """Features compatibile cu CICIDS2017 dataset"""
        return [
            # Flow statistics  
            'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
            'total_length_fwd_packets', 'total_length_bwd_packets',
            'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean',
            'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean',
            
            # Timing features - critice pentru detectia anomaliilor
            'flow_bytes_s', 'flow_packets_s',
            'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
            'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
            'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
            
            # TCP flags - indicatori de atacuri
            'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
            'fwd_header_length', 'bwd_header_length',
            
            # Packet analysis
            'min_packet_length', 'max_packet_length', 'packet_length_mean',
            'packet_length_std', 'packet_length_variance',
            
            # Protocol features - pentru detectia port scan, DDoS
            'protocol', 'src_port', 'dst_port',
            'down_up_ratio', 'average_packet_size', 'fwd_segment_size_avg',
            'bwd_segment_size_avg', 'subflow_fwd_packets', 'subflow_bwd_packets',
            
            # Window size features - TCP specifice
            'init_win_bytes_forward', 'init_win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward'
        ]
    
    def extract_packet_features(self, packet) -> Dict[str, Any]:
        """Extrage features de retea dintr-un pachet individual"""
        features = {}
        current_time = time.time()
        
        if IP in packet:
            features['src_ip'] = packet[IP].src
            features['dst_ip'] = packet[IP].dst
            features['protocol'] = packet[IP].proto
            features['packet_length'] = len(packet)
            features['ttl'] = packet[IP].ttl
            features['ip_flags'] = packet[IP].flags
            
        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = packet[TCP].flags
            features['window_size'] = packet[TCP].window
            features['header_length'] = packet[TCP].dataofs * 4
            features['seq_num'] = packet[TCP].seq
            features['ack_num'] = packet[TCP].ack
            
            # TCP flags breakdown pentru detectia anomaliilor
            features['flag_fin'] = bool(packet[TCP].flags & 0x01)
            features['flag_syn'] = bool(packet[TCP].flags & 0x02)
            features['flag_rst'] = bool(packet[TCP].flags & 0x04)
            features['flag_psh'] = bool(packet[TCP].flags & 0x08)
            features['flag_ack'] = bool(packet[TCP].flags & 0x10)
            features['flag_urg'] = bool(packet[TCP].flags & 0x20)
            
        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            features['header_length'] = 8
            
        elif ICMP in packet:
            features['icmp_type'] = packet[ICMP].type
            features['icmp_code'] = packet[ICMP].code
            features['src_port'] = 0
            features['dst_port'] = 0
            
        features['timestamp'] = current_time
        return features
    
    def create_flow_key(self, packet) -> str:
        """Creeaza cheia unica pentru flow - crucial pentru analiza traficului"""
        if IP not in packet:
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        src_port = dst_port = 0
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Bidirectional flow key pentru detectia corecta
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def update_flow_features(self, packet, flow_key: str):
        """Actualizeaza features pentru flow - aici se intampla magia detectiei"""
        current_time = time.time()
        packet_features = self.extract_packet_features(packet)
        
        if flow_key not in self.flow_cache:
            # Initialize new flow
            self.flow_cache[flow_key] = {
                'start_time': current_time,
                'last_seen': current_time,
                'fwd_packets': [],
                'bwd_packets': [],
                'fwd_times': [],
                'bwd_times': [],
                'total_packets': 0,
                'protocol': packet_features.get('protocol', 0),
                'fwd_psh_flags': 0,
                'bwd_psh_flags': 0,
                'fwd_urg_flags': 0,
                'bwd_urg_flags': 0,
                'fwd_header_lengths': [],
                'bwd_header_lengths': [],
                'init_win_bytes_forward': 0,
                'init_win_bytes_backward': 0,
                'first_packet': True
            }
        
        flow = self.flow_cache[flow_key]
        
        # Determine packet direction based on initial flow direction
        src_ip = packet_features.get('src_ip')
        dst_ip = packet_features.get('dst_ip')
        src_port = packet_features.get('src_port', 0)
        dst_port = packet_features.get('dst_port', 0)
        
        if 'initial_src' not in flow:
            flow['initial_src'] = src_ip
            flow['initial_dst'] = dst_ip
            flow['initial_src_port'] = src_port
            flow['initial_dst_port'] = dst_port
        
        is_forward = (src_ip == flow['initial_src'] and src_port == flow['initial_src_port'])
        
        # Update packet statistics
        packet_size = packet_features.get('packet_length', 0)
        header_length = packet_features.get('header_length', 0)
        
        if is_forward:
            flow['fwd_packets'].append(packet_size)
            flow['fwd_times'].append(current_time)
            flow['fwd_header_lengths'].append(header_length)
            
            # TCP window size pentru primul pachet
            if TCP in packet and flow['first_packet']:
                flow['init_win_bytes_forward'] = packet[TCP].window
                
        else:
            flow['bwd_packets'].append(packet_size)
            flow['bwd_times'].append(current_time)
            flow['bwd_header_lengths'].append(header_length)
            
            # TCP window size pentru primul pachet backward
            if TCP in packet and flow.get('init_win_bytes_backward', 0) == 0:
                flow['init_win_bytes_backward'] = packet[TCP].window
        
        # Update TCP flags - importante pentru detectia atacurilor
        if TCP in packet:
            if is_forward:
                if packet_features.get('flag_psh'):
                    flow['fwd_psh_flags'] += 1
                if packet_features.get('flag_urg'):
                    flow['fwd_urg_flags'] += 1
            else:
                if packet_features.get('flag_psh'):
                    flow['bwd_psh_flags'] += 1
                if packet_features.get('flag_urg'):
                    flow['bwd_urg_flags'] += 1
        
        flow['total_packets'] += 1
        flow['last_seen'] = current_time
        flow['first_packet'] = False
    
    def calculate_flow_features(self, flow_key: str) -> Dict[str, float]:
        """Calculeaza toate features ML pentru un flow"""
        if flow_key not in self.flow_cache:
            return {}
        
        flow = self.flow_cache[flow_key]
        features = {}
        
        # Basic flow statistics
        features['total_fwd_packets'] = len(flow['fwd_packets'])
        features['total_bwd_packets'] = len(flow['bwd_packets'])
        features['total_length_fwd_packets'] = sum(flow['fwd_packets'])
        features['total_length_bwd_packets'] = sum(flow['bwd_packets'])
        
        # Flow duration in microseconds - critic pentru detectia DDoS
        features['flow_duration'] = (flow['last_seen'] - flow['start_time']) * 1000000
        
        # Packet length statistics - pattern recognition
        all_packets = flow['fwd_packets'] + flow['bwd_packets']
        if all_packets:
            features['min_packet_length'] = min(all_packets)
            features['max_packet_length'] = max(all_packets)
            features['packet_length_mean'] = np.mean(all_packets)
            features['packet_length_std'] = np.std(all_packets)
            features['packet_length_variance'] = np.var(all_packets)
        else:
            features.update({
                'min_packet_length': 0, 'max_packet_length': 0,
                'packet_length_mean': 0, 'packet_length_std': 0,
                'packet_length_variance': 0
            })
        
        # Forward packet statistics
        if flow['fwd_packets']:
            features['fwd_packet_length_max'] = max(flow['fwd_packets'])
            features['fwd_packet_length_min'] = min(flow['fwd_packets'])
            features['fwd_packet_length_mean'] = np.mean(flow['fwd_packets'])
            features['fwd_segment_size_avg'] = np.mean(flow['fwd_packets'])
        else:
            features.update({
                'fwd_packet_length_max': 0, 'fwd_packet_length_min': 0,
                'fwd_packet_length_mean': 0, 'fwd_segment_size_avg': 0
            })
        
        # Backward packet statistics
        if flow['bwd_packets']:
            features['bwd_packet_length_max'] = max(flow['bwd_packets'])
            features['bwd_packet_length_min'] = min(flow['bwd_packets'])
            features['bwd_packet_length_mean'] = np.mean(flow['bwd_packets'])
            features['bwd_segment_size_avg'] = np.mean(flow['bwd_packets'])
        else:
            features.update({
                'bwd_packet_length_max': 0, 'bwd_packet_length_min': 0,
                'bwd_packet_length_mean': 0, 'bwd_segment_size_avg': 0
            })
        
        # Flow rate statistics - vitale pentru detectia anomaliilor de volum
        if features['flow_duration'] > 0:
            total_bytes = features['total_length_fwd_packets'] + features['total_length_bwd_packets']
            duration_seconds = features['flow_duration'] / 1000000
            features['flow_bytes_s'] = total_bytes / duration_seconds
            features['flow_packets_s'] = flow['total_packets'] / duration_seconds
        else:
            features['flow_bytes_s'] = 0
            features['flow_packets_s'] = 0
        
        # Inter-arrival time statistics - detecteaza pattern-uri anormale
        self._calculate_iat_features(flow, features)
        
        # TCP flags - indicatori directi de atacuri
        features['fwd_psh_flags'] = flow['fwd_psh_flags']
        features['bwd_psh_flags'] = flow['bwd_psh_flags']
        features['fwd_urg_flags'] = flow['fwd_urg_flags']
        features['bwd_urg_flags'] = flow['bwd_urg_flags']
        
        # Header lengths
        if flow['fwd_header_lengths']:
            features['fwd_header_length'] = np.mean(flow['fwd_header_lengths'])
        else:
            features['fwd_header_length'] = 0
            
        if flow['bwd_header_lengths']:
            features['bwd_header_length'] = np.mean(flow['bwd_header_lengths'])
        else:
            features['bwd_header_length'] = 0
        
        # Protocol and port features
        features['protocol'] = flow['protocol']
        features['src_port'] = flow.get('initial_src_port', 0)
        features['dst_port'] = flow.get('initial_dst_port', 0)
        
        # Additional derived features
        total_length = features['total_length_fwd_packets'] + features['total_length_bwd_packets']
        if flow['total_packets'] > 0:
            features['average_packet_size'] = total_length / flow['total_packets']
        else:
            features['average_packet_size'] = 0
        
        # Down/Up ratio pentru detectia pattern-urilor
        if features['total_length_bwd_packets'] > 0:
            features['down_up_ratio'] = features['total_length_fwd_packets'] / features['total_length_bwd_packets']
        else:
            features['down_up_ratio'] = 0 if features['total_length_fwd_packets'] == 0 else float('inf')
        
        # Subflow features
        features['subflow_fwd_packets'] = features['total_fwd_packets']
        features['subflow_bwd_packets'] = features['total_bwd_packets']
        
        # TCP window features
        features['init_win_bytes_forward'] = flow.get('init_win_bytes_forward', 0)
        features['init_win_bytes_backward'] = flow.get('init_win_bytes_backward', 0)
        
        # Active data packets forward
        features['act_data_pkt_fwd'] = sum(1 for size in flow['fwd_packets'] if size > features['fwd_header_length'])
        
        # Minimum segment size forward
        if flow['fwd_packets']:
            features['min_seg_size_forward'] = min(flow['fwd_packets'])
        else:
            features['min_seg_size_forward'] = 0
        
        # Ensure all features have numeric values
        for feature_name in self.feature_names:
            if feature_name not in features:
                features[feature_name] = 0.0
            elif features[feature_name] == float('inf'):
                features[feature_name] = 999999.0
            elif np.isnan(features[feature_name]):
                features[feature_name] = 0.0
        
        return features
    
    def _calculate_iat_features(self, flow: Dict, features: Dict):
        """Calculeaza Inter-Arrival Time features - critice pentru ML"""
        
        # Forward IAT
        if len(flow['fwd_times']) > 1:
            fwd_iats = [(flow['fwd_times'][i] - flow['fwd_times'][i-1]) * 1000000 
                       for i in range(1, len(flow['fwd_times']))]
            features['fwd_iat_total'] = sum(fwd_iats)
            features['fwd_iat_mean'] = np.mean(fwd_iats)
            features['fwd_iat_std'] = np.std(fwd_iats)
            features['fwd_iat_max'] = max(fwd_iats)
            features['fwd_iat_min'] = min(fwd_iats)
        else:
            features.update({
                'fwd_iat_total': 0, 'fwd_iat_mean': 0, 'fwd_iat_std': 0,
                'fwd_iat_max': 0, 'fwd_iat_min': 0
            })
        
        # Backward IAT
        if len(flow['bwd_times']) > 1:
            bwd_iats = [(flow['bwd_times'][i] - flow['bwd_times'][i-1]) * 1000000 
                       for i in range(1, len(flow['bwd_times']))]
            features['bwd_iat_total'] = sum(bwd_iats)
            features['bwd_iat_mean'] = np.mean(bwd_iats)
            features['bwd_iat_std'] = np.std(bwd_iats)
            features['bwd_iat_max'] = max(bwd_iats)
            features['bwd_iat_min'] = min(bwd_iats)
        else:
            features.update({
                'bwd_iat_total': 0, 'bwd_iat_mean': 0, 'bwd_iat_std': 0,
                'bwd_iat_max': 0, 'bwd_iat_min': 0
            })
        
        # Overall flow IAT
        all_times = sorted(flow['fwd_times'] + flow['bwd_times'])
        if len(all_times) > 1:
            flow_iats = [(all_times[i] - all_times[i-1]) * 1000000 
                        for i in range(1, len(all_times))]
            features['flow_iat_mean'] = np.mean(flow_iats)
            features['flow_iat_std'] = np.std(flow_iats)
            features['flow_iat_max'] = max(flow_iats)
            features['flow_iat_min'] = min(flow_iats)
        else:
            features.update({
                'flow_iat_mean': 0, 'flow_iat_std': 0,
                'flow_iat_max': 0, 'flow_iat_min': 0
            })
    
    def process_packet(self, packet) -> Dict[str, float]:
        """Process single packet and return flow features"""
        flow_key = self.create_flow_key(packet)
        if flow_key:
            self.update_flow_features(packet, flow_key)
            return self.calculate_flow_features(flow_key)
        return {}
    
    def cleanup_old_flows(self, timeout=300):
        """Cleanup flows older than timeout seconds"""
        current_time = time.time()
        old_flows = [key for key, flow in self.flow_cache.items() 
                    if current_time - flow['last_seen'] > timeout]
        
        for flow_key in old_flows:
            del self.flow_cache[flow_key]
        
        if old_flows:
            logger.info(f"Cleaned up {len(old_flows)} old flows")