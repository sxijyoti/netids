# ids/detector/__init__.py
# Import detection modules
from .ddos import detect as detect_ddos
from .port_scan import detect as detect_port_scan
from .spoofing_detector import detect as detect_spoofing
