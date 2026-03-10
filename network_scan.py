import socket
import concurrent.futures
import subprocess
import platform

# Common ports with their service names and risk info
COMMON_PORTS = {
    21:  {"service": "FTP",        "risk": "High",   "info": "File Transfer Protocol - often misconfigured, allows anonymous login"},
    22:  {"service": "SSH",        "risk": "Medium", "info": "Secure Shell - brute force target if weak passwords used"},
    23:  {"service": "Telnet",     "risk": "Critical","info": "Unencrypted remote access - highly dangerous, should be disabled"},
    25:  {"service": "SMTP",       "risk": "Medium", "info": "Mail server - can be abused for spam if open relay"},
    53:  {"service": "DNS",        "risk": "Medium", "info": "Domain Name System - check for zone transfer vulnerability"},
    80:  {"service": "HTTP",       "risk": "Medium", "info": "Web server - unencrypted, check for web vulnerabilities"},
    110: {"service": "POP3",       "risk": "Medium", "info": "Email retrieval - unencrypted version is risky"},
    135: {"service": "RPC",        "risk": "High",   "info": "Remote Procedure Call - common attack vector on Windows"},
    139: {"service": "NetBIOS",    "risk": "High",   "info": "Windows file sharing - can expose sensitive files"},
    143: {"service": "IMAP",       "risk": "Medium", "info": "Email protocol - check for unencrypted version"},
    443: {"service": "HTTPS",      "risk": "Low",    "info": "Encrypted web server - check SSL certificate validity"},
    445: {"service": "SMB",        "risk": "Critical","info": "Windows sharing - EternalBlue exploit target (WannaCry)"},
    1433: {"service": "MSSQL",     "risk": "High",   "info": "Microsoft SQL Server - database exposure risk"},
    1521: {"service": "Oracle DB", "risk": "High",   "info": "Oracle database - sensitive data exposure risk"},
    3306: {"service": "MySQL",     "risk": "High",   "info": "MySQL database - should not be exposed publicly"},
    3389: {"service": "RDP",       "risk": "Critical","info": "Remote Desktop - brute force and BlueKeep exploit target"},
    5432: {"service": "PostgreSQL","risk": "High",   "info": "PostgreSQL database - check for public exposure"},
    5900: {"service": "VNC",       "risk": "High",   "info": "Remote desktop - often has weak/no authentication"},
    6379: {"service": "Redis",     "risk": "Critical","info": "Redis database - often runs without authentication"},
    8080: {"service": "HTTP-Alt",  "risk": "Medium", "info": "Alternative web server - often used for admin panels"},
    8443: {"service": "HTTPS-Alt", "risk": "Medium", "info": "Alternative HTTPS - check SSL certificate"},
    9200: {"service": "Elasticsearch","risk":"Critical","info": "Search engine DB - often exposed without authentication"},
    27017:{"service": "MongoDB",   "risk": "Critical","info": "MongoDB - frequently found open without authentication"},
}

def scan_port(target, port, timeout=1):
    """Scan a single port and return status."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False

def grab_banner(target, port, timeout=2):
    """Try to grab service banner for version detection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        # Send a generic request
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200] if banner else "No banner"
    except Exception:
        return "Could not grab banner"

def ping_host(target):
    """Check if host is alive."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        result = subprocess.run(
            ['ping', param, '1', '-W', '2', target],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False

def get_hostname(ip):
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Could not resolve hostname"

def resolve_target(target):
    """Resolve domain to IP."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except Exception:
        return None

def run_network_scan(target, port_range="common", custom_ports=None):
    """Main network scanning function."""
    results = {
        "target": target,
        "ip": None,
        "hostname": None,
        "host_alive": False,
        "open_ports": [],
        "scan_summary": {}
    }

    print(f"\n  [*] Resolving target: {target}")
    ip = resolve_target(target)
    if not ip:
        print(f"  [!] Could not resolve {target}")
        return results

    results["ip"] = ip
    results["hostname"] = get_hostname(ip)
    print(f"  [+] Resolved to IP: {ip}")
    print(f"  [+] Hostname: {results['hostname']}")

    print(f"  [*] Checking if host is alive...")
    alive = ping_host(ip)
    results["host_alive"] = alive
    if alive:
        print(f"  [+] Host is ALIVE")
    else:
        print(f"  [!] Host may be down or blocking ICMP — trying ports anyway...")

    # Determine ports to scan
    if port_range == "common" or custom_ports is None:
        ports_to_scan = list(COMMON_PORTS.keys())
    elif port_range == "extended":
        ports_to_scan = list(range(1, 1025))
    else:
        ports_to_scan = custom_ports

    print(f"  [*] Scanning {len(ports_to_scan)} ports on {ip}...")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    open_ports.sort()

    print(f"\n  [+] Found {len(open_ports)} open port(s):")
    for port in open_ports:
        info = COMMON_PORTS.get(port, {"service": "Unknown", "risk": "Unknown", "info": "No info available"})
        print(f"      Port {port:5d} | {info['service']:15s} | Risk: {info['risk']:8s} | {info['info'][:60]}")

        banner = grab_banner(ip, port)
        port_data = {
            "port": port,
            "service": info["service"],
            "risk": info["risk"],
            "info": info["info"],
            "banner": banner
        }
        results["open_ports"].append(port_data)

    # Summary stats
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for p in results["open_ports"]:
        risk = p.get("risk", "Unknown")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    results["scan_summary"] = risk_counts
    return results
