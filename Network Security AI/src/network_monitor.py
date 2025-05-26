import scapy.all as scapy
import threading
import time
from collections import defaultdict
import psutil
import socket

class NetworkMonitor:
    def __init__(self):
        self.monitoring = False
        self.packet_count = 0
        self.traffic_data = []
        self.interface = None
        self.monitor_thread = None
        
        # Network statistics
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        
    def get_network_interfaces(self):
        interfaces = []
        try:
            for interface_name, interface_addresses in psutil.net_if_addrs().items():
                for address in interface_addresses:
                    if address.family == socket.AF_INET:
                        interfaces.append({
                            'name': interface_name,
                            'ip': address.address
                        })
        except:
            interfaces = [{'name': 'eth0', 'ip': '192.168.1.100'}]
        
        return interfaces
    
    def extract_packet_features(self, packet):
        try:
            features = {
                'timestamp': time.time(),
                'packet_size': len(packet),
                'protocol': 0,
                'src_port': 0,
                'dst_port': 0,
                'src_ip': 'unknown',
                'dst_ip': 'unknown'
            }
            
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                features['src_ip'] = ip_layer.src
                features['dst_ip'] = ip_layer.dst
                features['protocol'] = ip_layer.proto
                
                if packet.haslayer(scapy.TCP):
                    tcp_layer = packet[scapy.TCP]
                    features['src_port'] = tcp_layer.sport
                    features['dst_port'] = tcp_layer.dport
                    
                elif packet.haslayer(scapy.UDP):
                    udp_layer = packet[scapy.UDP]
                    features['src_port'] = udp_layer.sport
                    features['dst_port'] = udp_layer.dport
            
            return features
            
        except Exception as e:
            return None
    
    def process_packet(self, packet):
        self.packet_count += 1
        
        features = self.extract_packet_features(packet)
        if features:
            self.traffic_data.append(features)
            
            # Update statistics
            self.protocol_stats[features['protocol']] += 1
            self.port_stats[features['dst_port']] += 1
            self.ip_stats[features['src_ip']] += 1
            
            # Keep only recent data (last 1000 packets)
            if len(self.traffic_data) > 1000:
                self.traffic_data = self.traffic_data[-1000:]
    
    def start_monitoring(self, interface='eth0'):
        if self.monitoring:
            return False
            
        self.interface = interface
        self.monitoring = True
        
        def monitor_loop():
            try:
                print(f"Starting network monitoring on {interface}")
                scapy.sniff(iface=interface, prn=self.process_packet, 
                           stop_filter=lambda x: not self.monitoring,
                           timeout=1)
            except Exception as e:
                print(f"Scapy monitoring failed: {e}")
                self.simulate_traffic()
        
        self.monitor_thread = threading.Thread(target=monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        return True
    
    def simulate_traffic(self):
        import random
        print("Simulating network traffic (Scapy not available)")
        
        while self.monitoring:
            fake_packet_data = {
                'timestamp': time.time(),
                'packet_size': random.randint(64, 1500),
                'protocol': random.choice([6, 17, 1]),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 21, 25, 53]),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}"
            }
            
            self.traffic_data.append(fake_packet_data)
            self.packet_count += 1
            
            # Update stats
            self.protocol_stats[fake_packet_data['protocol']] += 1
            self.port_stats[fake_packet_data['dst_port']] += 1
            self.ip_stats[fake_packet_data['src_ip']] += 1
            
            if len(self.traffic_data) > 1000:
                self.traffic_data = self.traffic_data[-1000:]
                
            time.sleep(random.uniform(0.01, 0.1))
    
    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def get_recent_traffic(self, count=50):
        return self.traffic_data[-count:] if self.traffic_data else []
    
    def get_network_stats(self):
        return {
            'total_packets': self.packet_count,
            'protocol_distribution': dict(self.protocol_stats),
            'top_ports': dict(sorted(self.port_stats.items(), 
                                   key=lambda x: x[1], reverse=True)[:10]),
            'top_ips': dict(sorted(self.ip_stats.items(), 
                                 key=lambda x: x[1], reverse=True)[:10]),
            'monitoring': self.monitoring,
            'interface': self.interface
        }