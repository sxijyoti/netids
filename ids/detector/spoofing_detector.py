# ids/detector/spoofing_detector.py
from logger import log_alert
import ipaddress

def detect(packet):
    """Detect potentially spoofed IP addresses"""
    src_ip = packet.get("src_ip")
    
    try:
        ip = ipaddress.ip_address(src_ip)
        # Check for suspicious IP patterns
        if str(ip).startswith("0.") or str(ip).startswith("255."):
            return True
            
    except ValueError:
        # Invalid IP format
        return True
        
    return False
