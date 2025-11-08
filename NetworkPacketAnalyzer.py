from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        protocol = "Unknown"
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"Time: {timestamp} | Protocol: {protocol}")
        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
        
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload: {payload[:50]}...")  
        print("-" * 50)

def start_sniffer():
    print("Starting the packet sniffer... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffer()


