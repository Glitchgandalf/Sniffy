from scapy.all import sniff, IP, TCP, UDP
import argparse

# ANSI color codes
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Define suspicious ports
SUSPICIOUS_PORTS = {21, 22, 23, 1337, 4444, 3389}

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Simple packet sniffer with optional BPF filter.")
parser.add_argument("--filter", help="BPF filter string", default="ip")
args = parser.parse_args()

# Define packet processing logic
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"{BLUE}IP Packet: {ip_layer.src} -> {ip_layer.dst}{RESET}")

        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
            color = RED if sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS else GREEN
            print(f"{color}TCP Port: {sport} -> {dport}{RESET}")

        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
            color = RED if sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS else YELLOW
            print(f"{color}UDP Port: {sport} -> {dport}{RESET}")

# Start sniffing using provided filter
sniff(filter=args.filter, prn=packet_callback, store=0)