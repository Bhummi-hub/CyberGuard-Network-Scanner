import json
import socket
import csv
import ipaddress
import os
import urllib.request
from datetime import datetime
from scapy.all import IP, TCP, sr1

# Common TCP ports and their services
COMMON_PORTS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

def send_webhook_alert(webhook_url, target, high_risk_ports):
    if not webhook_url or webhook_url == "YOUR_WEBHOOK_URL_HERE":
        return False
    
    payload = {
        "content": f"🚨 **CYBERGUARD SECURITY ALERT** 🚨\n"
                   f"Target IP: **{target}**\n"
                   f"High-Risk Open Ports Found: `{', '.join(map(str, high_risk_ports))}`\n"
                   f"Please review the security report immediately!"
    }
    
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url, 
            data=data, 
            headers={'Content-Type': 'application/json', 'User-Agent': 'CyberGuard-Scanner'}
        )
        with urllib.request.urlopen(req) as response:
            return response.status in [200, 204]
    except Exception as e:
        print(f"Webhook error: {e}")
        return False
        
# Risk assessment based on port/service
def detect_risk(port, service, banner):

    if port == 22:
        return (
            "MEDIUM",
            "Review SSH authentication and configuration."
        )

    elif port == 80:
        return (
            "MEDIUM",
            "Review whether HTTP is required and use HTTPS where appropriate."
        )

    elif port == 443:
        return (
            "LOW",
            "Review HTTPS certificate and TLS configuration."
        )

    elif port == 445:
        return (
            "HIGH",
            "Review whether SMB is required and restrict network access."
        )

    elif port == 3389:
        return (
            "HIGH",
            "Restrict RDP access and review authentication settings."
        )

    elif port == 53:
        return (
            "LOW",
            "Review whether DNS access is required from this network."
        )

    return (
        "INFO",
        "Review the service and confirm whether it should be exposed."
    )


# Detect service banner
def detect_service(target, port):

    banner = "Unknown"

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as service_socket:

            service_socket.settimeout(2)
            service_socket.connect((target, port))

            # HTTP service identification
            if port == 80:
                service_socket.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
                )

            elif port == 443:
                # Avoid sending plain HTTP to a TLS port.
                return "HTTPS service detected; banner unavailable"

            try:
                response = service_socket.recv(1024)

                if response:
                    banner = response.decode(
                        "utf-8",
                        errors="replace"
                    ).strip()

                    banner = banner[:200]

            except socket.timeout:
                pass

    except (OSError, socket.timeout):
        pass

    return banner


# Scan one TCP port
def scan_port(target, port):

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as scan_socket:

            scan_socket.settimeout(1)
            result = scan_socket.connect_ex((target, port))

            if result == 0:
                return "OPEN"

            return "CLOSED/FILTERED"

    except OSError:
        return "CLOSED/FILTERED"


# Read devices from the discovery scanner CSV
def load_devices():

    filename = "results/scan_results.csv"
    devices = []

    if not os.path.exists(filename):
        print("\nDevice list not found!")
        print("First run: python scanner.py")
        return devices

    try:
        with open(
            filename,
            "r",
            newline="",
            encoding="utf-8-sig"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:
                ip = row.get("IP Address", "").strip()

                if ip:
                    try:
                        ipaddress.ip_address(ip)

                        if ip not in devices:
                            devices.append(ip)

                    except ValueError:
                        continue

    except (OSError, csv.Error) as error:
        print(f"Could not read device list: {error}")

    return devices


# Ask the user to choose a target
def choose_target():

    devices = load_devices()

    if not devices:
        print("No valid devices found in scan_results.csv.")
        return None

    print("\n========== DISCOVERED DEVICES ==========")

    for index, ip in enumerate(devices, start=1):
        print(f"{index}. {ip}")

    print("========================================")

    choice = input(
        "\nSelect a device number to scan: "
    ).strip()

    try:
        selected_number = int(choice)

        if not 1 <= selected_number <= len(devices):
            print("Invalid selection. Choose a listed number.")
            return None

        return devices[selected_number - 1]

    except ValueError:
        print("Invalid input. Please enter a number.")
        return None


# Save results to CSV
def save_csv(results):

    filename = "results/port_scan_results.csv"

    try:
        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Timestamp",
                "Target",
                "Port",
                "Status",
                "Service",
                "Banner",
                "Risk Level",
                "Recommendation"
            ])

            writer.writerows(results)

        print(f"\nCSV results saved to {filename}")

    except OSError as error:
        print(f"Could not save CSV report: {error}")


# Save results to JSON
def save_json(results):

    filename = "results/port_scan_results.json"
    json_results = []

    for result in results:
        json_results.append({
            "timestamp": result[0],
            "target": result[1],
            "port": result[2],
            "status": result[3],
            "service": result[4],
            "banner": result[5],
            "risk_level": result[6],
            "recommendation": result[7]
        })

    try:
        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                json_results,
                file,
                indent=4
            )

        print(f"JSON results saved to {filename}")

    except OSError as error:
        print(f"Could not save JSON report: {error}")


# Generate a readable security report
def save_security_report(target, scan_time, results):

    filename = "results/security_report.txt"

    open_results = [
        result for result in results
        if result[3] == "OPEN"
    ]

    high_risk = [
        result for result in open_results
        if result[6] == "HIGH"
    ]

    medium_risk = [
        result for result in open_results
        if result[6] == "MEDIUM"
    ]

    low_risk = [
        result for result in open_results
        if result[6] == "LOW"
    ]

    try:
        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            file.write("NETWORK PORT SCANNER - SECURITY REPORT\n")
            file.write("=" * 45 + "\n\n")
            file.write(f"Target IP: {target}\n")
            file.write(f"Scan Time: {scan_time}\n")
            file.write(f"Ports Checked: {len(COMMON_PORTS)}\n")
            file.write(f"Open Ports: {len(open_results)}\n\n")

            file.write("OPEN PORT DETAILS\n")
            file.write("-" * 45 + "\n")

            if not open_results:
                file.write("No selected TCP ports were found open.\n")

            for result in open_results:
                file.write(f"\nPort: {result[2]}\n")
                file.write(f"Service: {result[4]}\n")
                file.write(f"Banner: {result[5]}\n")
                file.write(f"Risk Level: {result[6]}\n")
                file.write(
                    f"Recommendation: {result[7]}\n"
                )

            file.write("\nRISK SUMMARY\n")
            file.write("-" * 45 + "\n")
            file.write(f"High risk flags: {len(high_risk)}\n")
            file.write(f"Medium risk flags: {len(medium_risk)}\n")
            file.write(f"Low risk flags: {len(low_risk)}\n")

            file.write(
                "\nIMPORTANT NOTE\n"
                "Risk labels are heuristic indicators, not proof "
                "of vulnerabilities. CLOSED/FILTERED means the "
                "connection was not established; this scan cannot "
                "reliably distinguish a closed port from filtering.\n"
            )

        print(f"Security report saved to {filename}")

    except OSError as error:
        print(f"Could not save security report: {error}")


# OS Fingerprinting function
def detect_os(target):
    try:
        packet = IP(dst=target)/TCP(dport=80, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response is None:
            packet = IP(dst=target)/TCP(dport=445, flags="S")
            response = sr1(packet, timeout=1, verbose=0)
            
        if response and response.haslayer(IP):
            ttl = response.ttl
            
            if ttl <= 64:
                if ttl == 64:
                    return f"Linux / Unix / macOS (TTL: {ttl})"
                return f"Linux / Unix (TTL: {ttl})"
            elif ttl <= 128:
                return f"Windows (TTL: {ttl})"
            elif ttl <= 255:
                return f"Cisco / Network Device (TTL: {ttl})"
            else:
                return f"Unknown OS (TTL: {ttl})"
        return "OS Undetected (No TCP Response)"
    except Exception as e:
        return f"Error: {str(e)}"


# Main program
def main():

    os.makedirs("results", exist_ok=True)

    print("\n========================================")
    print("        NETWORK PORT SCANNER")
    print("========================================")
    print("Only scan devices you own or have permission to test.")

    target = choose_target()

    if target is None:
        return

    try:
        ipaddress.ip_address(target)
    except ValueError:
        print("Invalid IP address.")
        return

    scan_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    results = []

    print(f"\nTarget: {target}")
    print(f"Scan started at: {scan_time}")
    
    # OS Fingerprinting execution
    target_os = detect_os(target)
    print(f"Detected OS: {target_os}")
    print("\nScanning selected TCP ports...\n")

    for port, service in COMMON_PORTS.items():

        status = scan_port(target, port)
        banner = "Not checked"

        if status == "OPEN":
            banner = detect_service(target, port)
            risk_level, recommendation = detect_risk(
                port,
                service,
                banner
            )
        else:
            risk_level = "N/A"
            recommendation = "No connection established."

        result = [
            scan_time,
            target,
            port,
            status,
            service,
            banner,
            risk_level,
            recommendation
        ]

        results.append(result)

        print(
            f"Port {port}: {status} | "
            f"Service: {service}"
        )

        if status == "OPEN":
            print(f"   Banner: {banner}")
            print(f"   Risk: {risk_level}")
            print(f"   Recommendation: {recommendation}")

    open_ports = [
        result for result in results
        if result[3] == "OPEN"
    ]

    print("\n========== SCAN SUMMARY ==========")
    print(f"Target IP: {target}")
    print(f"Detected OS: {target_os}")
    print(f"Ports checked: {len(COMMON_PORTS)}")
    print(f"Open ports found: {len(open_ports)}")

    if open_ports:
        print("\nOpen ports:")
        for result in open_ports:
            print(
                f"- Port {result[2]} ({result[4]}) "
                f"| Risk: {result[6]}"
            )
    else:
        print("No selected TCP ports accepted a connection.")

    print("\nRisk labels are indicators, not confirmed vulnerabilities.")

    save_csv(results)
    save_json(results)
    save_security_report(target, scan_time, results)


if __name__ == "__main__":
    main()