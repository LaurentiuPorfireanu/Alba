import scapy.all as scapy
import json
import time
import os
from datetime import datetime

class DockerNetworkMonitor:
    def __init__(self):
        self.log_dir = "/app/logs"
        os.makedirs(self.log_dir, exist_ok=True)
        
    def packet_handler(self, packet):
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'protocol': 'Unknown'
            }
            
            if packet.haslayer(scapy.IP):
                ip = packet[scapy.IP]
                packet_info.update({
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'protocol': ip.proto
                })
                
                if packet.haslayer(scapy.TCP):
                    tcp = packet[scapy.TCP]
                    packet_info.update({
                        'src_port': tcp.sport,
                        'dst_port': tcp.dport,
                        'protocol': 'TCP'
                    })
                    
                elif packet.haslayer(scapy.UDP):
                    udp = packet[scapy.UDP]
                    packet_info.update({
                        'src_port': udp.sport,
                        'dst_port': udp.dport,
                        'protocol': 'UDP'
                    })
            
            # Save to log file
            log_file = os.path.join(self.log_dir, 'network_traffic.json')
            with open(log_file, 'a') as f:
                f.write(json.dumps(packet_info) + '\n')
                
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    def start_monitoring(self):
        print("Starting Docker network monitoring...")
        try:
            scapy.sniff(iface="eth0", prn=self.packet_handler)
        except Exception as e:
            print(f"Monitoring error: {e}")

if __name__ == "__main__":
    monitor = DockerNetworkMonitor()
    monitor.start_monitoring()