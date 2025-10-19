#!/usr/bin/env python3
import sys
import os
from scapy.all import sniff, get_if_list
from scapy.all import Packet
from scapy.all import IP, TCP, UDP
from scapy.layers.inet import _IPOption_HDR


class PacketSniffer:
    """Simple packet sniffer for specific destination ports"""
    
    def __init__(self):
        self.iface = self._get_interface()
    
    def _get_interface(self):
        """Get first available eth interface"""
        ifaces = [i for i in get_if_list() if "eth0" in i]
        if not ifaces:
            print("Cannot find eth0 interface")
            sys.exit(1)
        return ifaces[0]
    
    def handle_packet(self, pkt, target_port):
        """Process packets with matching destination port"""
        if (TCP in pkt and pkt[TCP].dport == target_port) or \
           (UDP in pkt and pkt[UDP].dport == target_port):
            print("Received packet:")
            pkt.show2()
            if pkt.load:
                print(pkt.load)
            sys.stdout.flush()
    
    def start(self, port):
        """Start sniffing on specified port"""
        print(f"Sniffing on {self.iface} for port {port}")
        sniff(iface=self.iface, prn=lambda x: self.handle_packet(x, port))


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 sniffer.py <port>")
        sys.exit(1)
    
    try:
        port = int(sys.argv[1])
        sniffer = PacketSniffer()
        sniffer.start(port)
    except ValueError:
        print("Error: Port must be a number")
        sys.exit(1)


if __name__ == '__main__':
    main()
