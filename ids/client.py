# ids/client.py
import socket
import threading
import time
import sys

class IDSClient:
    def __init__(self, server_ip='127.0.0.1', control_port=8888, data_port=8889):
        self.server_ip = server_ip
        self.control_port = control_port
        self.data_port = data_port
        self.client_id = None
        self.control_socket = None
        self.data_socket = None
        self.running = False
    
    def connect(self):
        """Establish connection to the IDS server"""
        try:
            # connect to control channel
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.connect((self.server_ip, self.control_port))
            
            # receive client_id from server
            self.client_id = self.control_socket.recv(1024).decode()
            print(f"[+] Connected to IDS server with ID: {self.client_id}")
            
            # data port used
            self.control_socket.send(str(self.data_port).encode())
            
            time.sleep(0.5)
            
            # connect to data channel
            self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_socket.connect((self.server_ip, self.data_port))
            
            # send client_id to server on data channel for identification
            self.data_socket.send(self.client_id.encode())
            print(f"[+] Data channel established")
            
            time.sleep(0.5)
            
            self.running = True
            return True
        except Exception as e:
            print(f"[!] Connection error: {e}")
            self.cleanup()
            return False
    
    def receive_alerts(self):
        """Listen for alerts from the server on the data channel"""
        try:
            while self.running:
                alert = self.data_socket.recv(1024).decode()
                if not alert:
                    # server closed
                    break
                
                # parse and display alert
                if alert.startswith("ALERT:"):
                    parts = alert.split(":", 2)
                    if len(parts) >= 3:
                        alert_type = parts[1]
                        details = parts[2]
                        print(f"\n[!] ALERT: {alert_type} - {details}")
        except Exception as e:
            if self.running:
                print(f"[!] Error receiving alerts: {e}")
        finally:
            if self.running:
                self.disconnect()
    
    def disconnect(self):
        """Gracefully disconnect from the server"""
        if self.running:
            try:
                # send termination message on control channel
                if self.control_socket:
                    self.control_socket.send("TERMINATE".encode())
            except:
                pass
            finally:
                self.cleanup()
    
    def cleanup(self):
        """Close all connections and reset client state"""
        self.running = False
        
        if self.control_socket:
            try:
                self.control_socket.close()
            except:
                pass
            self.control_socket = None
            
        if self.data_socket:
            try:
                self.data_socket.close()
            except:
                pass
            self.data_socket = None
            
        print("[+] Disconnected from IDS server")

def main():
    print("=== Network Intrusion Detection System Client ===")
    
    # get server IP 
    server_ip = input("Enter server IP address [127.0.0.1]: ").strip()
    if not server_ip:
        server_ip = "127.0.0.1"
    
    # create client and connect to server
    client = IDSClient(server_ip)
    if not client.connect():
        return
    
    # start thread to receive alerts
    threading.Thread(target=client.receive_alerts, daemon=True).start()
    
    print("\n=== Client connected to IDS server ===")
    print("You will receive alerts when attacks are detected.")
    print("Type 'exit' to disconnect and quit.")
    
    # main client loop
    try:
        while client.running:
            command = input("> ").strip().lower()
            if command == "exit":
                client.disconnect()
                break
    except KeyboardInterrupt:
        print("\n[!] Client interrupted.")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
