# ids/detector/ddos.py
from collections import defaultdict
from time import time
from logger import log_alert

syn_counts = defaultdict(list)
THRESHOLD = 20

def detect(packet):
    """Detect potential DDoS attacks (SYN floods)"""
    if packet.get("protocol") != 6:
        return False
        
    if packet.get("flags") == 2:  # SYN flag
        src_ip = packet["src_ip"]
        current_time = time()
        
        # Keep only recent SYN packets (within last 5 seconds)
        syn_counts[src_ip] = [t for t in syn_counts[src_ip] if current_time - t < 5]
        syn_counts[src_ip].append(current_time)
        
        # Check if threshold is exceeded
        if len(syn_counts[src_ip]) > THRESHOLD:
            return True
            
    return False
