#!/usr/bin/env python3
import sys
import socket
import random
from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP


class PacketSender:
    """Simple packet sender for TCP/UDP packets"""
    
    def __init__(self):
        self.iface = self._get_interface()
    
    def _get_interface(self):
        """Get first available eth interface"""
        ifaces = [i for i in get_if_list() if "eth0" in i]
        if not ifaces:
            print("Cannot find eth0 interface")
            sys.exit(1)
        return ifaces[0]
    
    def create_packet(self, dest_ip, protocol, dest_port, message):
        """Create TCP or UDP packet"""
        base_pkt = Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff') / IP(dst=dest_ip)
        sport = random.randint(49152, 65535)
        
        if protocol == "TCP":
            return base_pkt / TCP(dport=dest_port, sport=sport) / message
        else:
            return base_pkt / UDP(dport=dest_port, sport=sport) / message
    
    def send(self, dest_ip, protocol, dest_port, message):
        """Send packet to destination"""
        print(f"Sending on {self.iface} to {dest_ip}")
        pkt = self.create_packet(dest_ip, protocol, dest_port, message)
        pkt.show2()
        sendp(pkt, iface=self.iface, verbose=False)


def main():
    if len(sys.argv) < 5:
        print("Usage: python3 sender.py <destination> <TCP|UDP> <dport> <message>")
        sys.exit(1)
    
    try:
        dest_ip = socket.gethostbyname(sys.argv[1])
        protocol = sys.argv[2]
        dest_port = int(sys.argv[3])
        message = sys.argv[4]
        
        sender = PacketSender()
        sender.send(dest_ip, protocol, dest_port, message)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
