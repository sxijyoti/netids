# attacker/port_scan.py
import socket
import concurrent.futures
import time

def scan_port(ip, port):
    """Scan a single port"""
    try:
        s = socket.socket()
        s.settimeout(0.1)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return port
        return None
    except:
        return None

def port_scan():
    """Perform a port scan against the target IP"""
    ip = input("Enter target IP: ")
    start_port = int(input("Enter starting port [1]: ") or "1")
    end_port = int(input("Enter ending port [1024]: ") or "1024")
    
    print(f"[+] Starting port scan on {ip} from port {start_port} to {end_port}")
    start_time = time.time()
    open_ports = []
    
    # use a thread pool for faster scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # submit all scan tasks
        future_to_port = {
            executor.submit(scan_port, ip, port): port 
            for port in range(start_port, end_port + 1)
        }
        
        # process results 
        for future in concurrent.futures.as_completed(future_to_port):
            port = future.result()
            if port:
                print(f"[+] Port {port} is open")
                open_ports.append(port)
    
    scan_time = time.time() - start_time
    print(f"\n[+] Scan completed in {scan_time:.2f} seconds")
    print(f"[+] {len(open_ports)} open ports found")
    if open_ports:
        print(f"[+] Open ports: {', '.join(map(str, sorted(open_ports)))}")

if __name__ == "__main__":
    port_scan()
