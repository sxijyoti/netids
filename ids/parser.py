# ids/parser.py
import struct
import socket

def parse_packet(packet):
    try:
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = struct.unpack("!6s6sH", eth_header)
        if socket.ntohs(eth[2]) != 8:
            return None

        ip_header = packet[eth_length:eth_length+20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        ip_info = {
            "src_ip": s_addr,
            "dst_ip": d_addr,
            "protocol": protocol
        }

        if protocol == 6:
            t = eth_length + (iph[0] & 0xF) * 4
            tcp_header = packet[t:t+20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            ip_info["src_port"] = tcph[0]
            ip_info["dst_port"] = tcph[1]
            ip_info["flags"] = tcph[5]

        return ip_info
    except:
        return None

