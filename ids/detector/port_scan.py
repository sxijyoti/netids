# ids/detector/port_scan.py
from collections import defaultdict
from time import time
from logger import log_alert

scan_tracker = defaultdict(set)
scan_times = {}

PORT_SCAN_THRESHOLD = 20
TIME_WINDOW = 10

def detect(packet):
    """Detect potential port scanning activity"""
    if packet.get("protocol") != 6:
        return False
        
    src_ip = packet["src_ip"]
    dst_port = packet["dst_port"]
    current_time = time()

    # Reset tracking if time window expired
    if src_ip not in scan_times or current_time - scan_times[src_ip] > TIME_WINDOW:
        scan_tracker[src_ip].clear()
        scan_times[src_ip] = current_time

    # Track unique ports accessed by this IP
    scan_tracker[src_ip].add(dst_port)
    
    # Check if threshold is exceeded
    if len(scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
        return True
        
    return False
