# ids/logger.py
from datetime import datetime

LOG_FILE = "ids_logs.txt"

def log_alert(alert_type, details):
    """Log alerts to console and file"""
    msg = f"[{datetime.now()}] ALERT: {alert_type} - {details}"
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

