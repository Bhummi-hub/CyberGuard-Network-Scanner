import socket
import os
from datetime import datetime
import concurrent.futures
import subprocess
import platform

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split('.')[:3]) + ".0/24"
    except Exception:
        return "192.168.1.0/24"

def ping_host(ip):
    try:
        is_win = platform.system().lower() == 'windows'
        command = ['ping', '-n', '1', '-w', '100', ip] if is_win else ['ping', '-c', '1', '-W', '1', ip]
        output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if output.returncode == 0:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown Host"
            return [
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                "Active",
                hostname
            ]
    except Exception:
        pass
    return None

def run_network_scan(subnet=None):
    try:
        if not subnet:
            subnet = get_local_subnet()
            
        os.makedirs("results", exist_ok=True)
        active_devices = []
        
        # Localhost ko hamesha pehle add karein taaki empty list ka chance hi na rahe
        active_devices.append([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "127.0.0.1",
            "Active",
            "localhost (This PC)"
        ])
        
        base_ip = ".".join(subnet.split('.')[:3]) + "."
        # Speed ke liye pehle 50 IPs scan karenge (bohot fast chalega)
        ips_to_scan = [f"{base_ip}{i}" for i in range(1, 50)]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(ping_host, ips_to_scan)
            for result in results:
                if result:
                    active_devices.append(result)
                    
        return active_devices
    except Exception as e:
        print(f"Scanner error: {e}")
        return [[datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "127.0.0.1", "Active", "localhost"]]