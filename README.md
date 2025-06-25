# Network Attack &amp; Intrusion Detection System

### using Raw Socket Handling (CN Project)

## Description:
Network Attack &amp; Intrusion Detection System (NETIDS) is built using Python socket programming. It simulates and detects common network attacks such as DDoS, Port Scanning, and IP Spoofing in real-time. The system consists of an IDS server that monitors network traffic and a client that receives alerts. Attack simulations are done using custom-built attackers, and detection is handled without any third-party libraries. It supports multiple clients and servers, uses separate channels for control and data, and ensures smooth, error-free communication.

## Filetree:

```sh
netids/
├── README.md
├── requirements.txt
├── run_ids_client.sh
├── run_ids_server.sh
├── ids/
│   ├── server.py
│   ├── client.py
│   ├── parser.py
│   ├── logger.py
│   └── detector/
│       ├── ddos.py
│       ├── port_scan.py
│       ├── spoofing_detector.py
│       └── __init__.py
├── attacker/
   ├── ddos.py
   ├── port_scan.py
   ├── spoofed_packet_sender.py
   └── __init__.py
```

## How to Run

```bash
# Start the server
chmod +x run_ids_server.sh
sudo ./run_ids_server.sh

# In another terminal, start a client
chmod +x run_ids_client.sh
sudo ./run_ids_client.sh
```
