# Packet Sniffer (Python + Scapy)

A simple, color-coded packet sniffer written in Python using Scapy.  
This tool captures IP, TCP, and UDP traffic and highlights suspicious ports such as Telnet, FTP, SSH, and common backdoor ports.

## Features

- Continuous packet capture
- Optional BPF filter via CLI (e.g. `tcp`, `udp`, `port 80`)
- Highlights:
  - 🔵 IP traffic in blue
  - 🟢 TCP ports in green
  - 🟡 UDP ports in yellow
  - 🔴 Suspicious ports in red

## Installation

```bash
pip3 install scapy
```

## Usage

```bash
sudo python3 sniffer.py
```

Or with a custom filter:

```bash
sudo python3 sniffer.py --filter "tcp port 80"
```

## Legal & Ethical Disclaimer

This tool is for educational and ethical security research only.  
**Do not** use it on networks you do not own or have explicit permission to monitor.  
Unauthorized sniffing may be illegal and unethical.

Use responsibly.
