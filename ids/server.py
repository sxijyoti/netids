import socket
import threading
import time
from parser import parse_packet
from logger import log_alert
from detector import ddos, port_scan, spoofing_detector

# Global variables for client management
clients = {}
client_lock = threading.Lock()

def packet_handler(packet):
    """Process captured packets and run detection algorithms"""
    ip_info = parse_packet(packet)
    if ip_info:
        # Run detection algorithms
        ddos_result = ddos.detect(ip_info)
        port_scan_result = port_scan.detect(ip_info)
        spoofing_result = spoofing_detector.detect(ip_info)
        
        # If any alerts, notify all connected clients
        if ddos_result or port_scan_result or spoofing_result:
            alert_type = None
            details = None
            
            # if ddos_result:
            #     alert_type = "DDoS (SYN flood)"
            #     details = f"Source IP: {ip_info['src_ip']}"
            # elif port_scan_result:
            #     alert_type = "Port Scan"
            #     details = f"Source IP: {ip_info['src_ip']}"
            # elif spoofing_result:
            #     alert_type = "Spoofed IP"
            #     details = f"Source IP: {ip_info['src_ip']}"
                
            # if alert_type and details:
            #     # Log the alert
            #     log_alert(alert_type, details)
            #     # Broadcast to all clients
            #     broadcast_alert(alert_type, details)
            if ddos_result:
                log_alert("DDoS (SYN flood)", f"Source IP: {ip_info['src_ip']}")
                broadcast_alert("DDoS (SYN flood)", f"Source IP: {ip_info['src_ip']}")

            if port_scan_result:
                log_alert("Port Scan", f"Source IP: {ip_info['src_ip']}")
                broadcast_alert("Port Scan", f"Source IP: {ip_info['src_ip']}")

            if spoofing_result:
                log_alert("Spoofed IP", f"Source IP: {ip_info['src_ip']}")
                broadcast_alert("Spoofed IP", f"Source IP: {ip_info['src_ip']}")

def start_sniffer():
    """Start packet sniffing in a separate thread"""
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        print("[+] Sniffer started. Listening for packets...")
        while True:
            raw_data, _ = sniffer.recvfrom(65535)
            packet_handler(raw_data)
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")

def broadcast_alert(alert_type, details):
    """Send alerts to all connected clients"""
    message = f"ALERT:{alert_type}:{details}"
    with client_lock:
        disconnected_clients = []
        for client_id, client_info in clients.items():
            try:
                data_socket = client_info['data_socket']
                data_socket.send(message.encode())
            except:
                # Mark client for removal
                disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            del clients[client_id]

def handle_client_control(client_socket, client_address, client_id):
    """Handle control channel communication with a client"""
    print(f"[+] Control channel established with client {client_id} ({client_address[0]}:{client_address[1]})")
    
    try:
        while True:
            # Wait for control messages from client
            command = client_socket.recv(1024).decode()
            
            if not command:
                # Client disconnected
                break
                
            if command == "TERMINATE":
                # Client is requesting to terminate the connection
                print(f"[+] Client {client_id} requested termination")
                break
    except:
        # Connection error occurred
        pass
    
    # Clean up client connections
    with client_lock:
        if client_id in clients:
            print(f"[+] Closing connection with client {client_id}")
            try:
                clients[client_id]['control_socket'].close()
                clients[client_id]['data_socket'].close()
            except:
                pass
            del clients[client_id]

def start_control_server():
    """Start the control server to handle client connections"""
    control_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set socket option to allow reuse of address to prevent "bind: address already in use" errors
    control_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control_server.bind(('0.0.0.0', 8888))
    control_server.listen(5)
    print("[+] Control server started on port 8888")
    
    try:
        while True:
            client_socket, client_address = control_server.accept()
            
            # Generate a unique client ID
            client_id = f"client_{int(time.time())}_{client_address[0]}_{client_address[1]}"
            
            # Send client_id to the client
            client_socket.send(client_id.encode())
            
            # Wait for data port connection
            data_port = int(client_socket.recv(1024).decode())
            
            # Wait for client to establish data connection
            # (The client will connect to the data port after receiving the client_id)
            
            # Add client to the clients dictionary
            with client_lock:
                clients[client_id] = {
                    'control_socket': client_socket,
                    'data_socket': None,  # Will be set when client connects to data channel
                    'address': client_address
                }
            
            # Start a new thread to handle client control messages
            threading.Thread(target=handle_client_control, args=(client_socket, client_address, client_id)).start()
    except KeyboardInterrupt:
        print("\n[!] Control server stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        control_server.close()

def start_data_server():
    """Start the data server for alert broadcasts"""
    data_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    data_server.bind(('0.0.0.0', 8889))
    data_server.listen(5)
    print("[+] Data server started on port 8889")
    
    try:
        while True:
            client_socket, client_address = data_server.accept()
            
            try:
                # Receive client_id to identify which client is connecting
                client_id = client_socket.recv(1024).decode()
                
                # Update clients dictionary with data socket
                with client_lock:
                    if client_id in clients:
                        clients[client_id]['data_socket'] = client_socket
                        print(f"[+] Data channel established with client {client_id}")
                    else:
                        # Unknown client, close connection
                        print(f"[!] Unknown client ID: {client_id}")
                        client_socket.close()
            except Exception as e:
                print(f"[!] Error establishing data channel: {e}")
                client_socket.close()
    except KeyboardInterrupt:
        print("\n[!] Data server stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        data_server.close()
        
if __name__ == "__main__":
    # Start all services in separate threads
    threading.Thread(target=start_sniffer, daemon=True).start()
    threading.Thread(target=start_data_server, daemon=True).start()
    
    # Start control server in the main thread
    start_control_server()
    
    print("[+] Server shutdown complete.")
