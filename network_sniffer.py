"""
CodeAlpha Cyber Security Internship - Task 1
Basic Network Sniffer

This program captures live network traffic packets and displays
useful information about each packet: source/destination IPs,
protocol, ports, and payload data.

Requirements:
    pip install scapy

Note:
    - Must be run with administrator/root privileges to capture packets.
    - On Windows, you need Npcap installed (https://npcap.com/) for scapy to work.

Usage:
    sudo python3 network_sniffer.py            # capture all traffic
    sudo python3 network_sniffer.py -i eth0    # capture on a specific interface
    sudo python3 network_sniffer.py -c 50      # stop after 50 packets
    sudo python3 network_sniffer.py -f "tcp"   # apply a BPF filter (e.g. tcp, udp, port 80)
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


# Counter for total packets captured, used for numbering output
packet_count = 0


def get_protocol_name(packet):
    """Return a human-readable protocol name for the given packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def process_packet(packet):
    """
    Callback function executed for every captured packet.
    Extracts and displays IP addresses, protocol, ports, and payload.
    """
    global packet_count

    # We only care about packets that have an IP layer
    if not packet.haslayer(IP):
        return

    packet_count += 1
    ip_layer = packet[IP]

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = get_protocol_name(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"\n[{packet_count}] Time: {timestamp}")
    print(f"    Source IP      : {src_ip}")
    print(f"    Destination IP : {dst_ip}")
    print(f"    Protocol       : {protocol}")
    print(f"    TTL            : {ip_layer.ttl}")
    print(f"    Packet Length  : {len(packet)} bytes")

    # Show port information for TCP/UDP packets
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"    Source Port    : {tcp_layer.sport}")
        print(f"    Dest Port      : {tcp_layer.dport}")
        print(f"    TCP Flags      : {tcp_layer.flags}")
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"    Source Port    : {udp_layer.sport}")
        print(f"    Dest Port      : {udp_layer.dport}")

    # Show payload data if present (truncated for readability)
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            decoded = payload.decode("utf-8", errors="replace")
        except Exception:
            decoded = str(payload)
        snippet = decoded[:100].replace("\n", " ").replace("\r", " ")
        print(f"    Payload (first 100 chars): {snippet}")

    print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer - CodeAlpha Task 1")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g. eth0, wlan0)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (default: unlimited)", default=0)
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g. 'tcp', 'udp', 'port 80')", default=None)
    args = parser.parse_args()

    print("=" * 60)
    print(" CodeAlpha Cyber Security Internship - Task 1")
    print(" Basic Network Sniffer")
    print("=" * 60)
    print(f"Interface : {args.interface if args.interface else 'default'}")
    print(f"Filter    : {args.filter if args.filter else 'none (all traffic)'}")
    print(f"Count     : {args.count if args.count else 'unlimited (Ctrl+C to stop)'}")
    print("=" * 60)
    print("Starting capture... (requires admin/root privileges)\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=process_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\n[ERROR] Permission denied. Run this script as Administrator (Windows) or with sudo (Linux/Mac).")
    except KeyboardInterrupt:
        print(f"\n\nCapture stopped by user. Total packets captured: {packet_count}")
    except Exception as e:
        print(f"\n[ERROR] {e}")


if __name__ == "__main__":
    main()
