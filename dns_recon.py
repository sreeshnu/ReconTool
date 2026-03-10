import socket
import subprocess
import re

DNS_RECORD_TYPES = ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

def get_dns_records(domain):
    """Get DNS records using system dig/nslookup commands."""
    records = {}
    for record_type in DNS_RECORD_TYPES:
        try:
            result = subprocess.run(
                ['dig', '+short', record_type, domain],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                records[record_type] = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]
            else:
                records[record_type] = []
        except FileNotFoundError:
            # dig not available, try nslookup
            try:
                result = subprocess.run(
                    ['nslookup', '-type=' + record_type, domain],
                    capture_output=True, text=True, timeout=10
                )
                records[record_type] = [result.stdout.strip()[:200]] if result.stdout.strip() else []
            except Exception:
                records[record_type] = []
        except Exception:
            records[record_type] = []
    return records

def get_whois_info(domain):
    """Get WHOIS information."""
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            output = result.stdout
            # Extract key fields
            info = {}
            patterns = {
                "Registrar": r"Registrar:\s*(.+)",
                "Creation Date": r"Creation Date:\s*(.+)",
                "Expiry Date": r"Registry Expiry Date:\s*(.+)",
                "Name Servers": r"Name Server:\s*(.+)",
                "Organization": r"Registrant Organization:\s*(.+)",
                "Country": r"Registrant Country:\s*(.+)",
                "DNSSEC": r"DNSSEC:\s*(.+)",
            }
            for key, pattern in patterns.items():
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    info[key] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches[:3]]
            return info if info else {"Note": "WHOIS data not available or restricted"}
        return {"Note": "WHOIS lookup failed"}
    except FileNotFoundError:
        return {"Note": "whois tool not installed"}
    except Exception as e:
        return {"Note": f"WHOIS error: {str(e)}"}

def enumerate_subdomains(domain):
    """Enumerate common subdomains."""
    common_subdomains = [
        'www', 'mail', 'ftp', 'admin', 'portal', 'vpn', 'remote',
        'api', 'dev', 'staging', 'test', 'blog', 'shop', 'store',
        'app', 'mobile', 'cdn', 'static', 'assets', 'media',
        'login', 'secure', 'my', 'dashboard', 'cpanel', 'webmail',
        'smtp', 'pop', 'imap', 'ns1', 'ns2', 'mx', 'exchange',
        'backup', 'monitor', 'support', 'help', 'docs', 'wiki'
    ]

    found_subdomains = []
    print(f"  [*] Enumerating subdomains for {domain}...")

    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found_subdomains.append({"subdomain": subdomain, "ip": ip})
            print(f"      [+] Found: {subdomain} -> {ip}")
        except socket.gaierror:
            pass
        except Exception:
            pass

    return found_subdomains

def check_zone_transfer(domain):
    """Check if DNS zone transfer is possible (misconfiguration)."""
    try:
        # Get nameservers first
        ns_result = subprocess.run(
            ['dig', '+short', 'NS', domain],
            capture_output=True, text=True, timeout=10
        )
        nameservers = [ns.strip() for ns in ns_result.stdout.strip().split('\n') if ns.strip()]

        vulnerable = []
        for ns in nameservers[:3]:  # Check first 3 nameservers
            result = subprocess.run(
                ['dig', 'axfr', domain, f'@{ns}'],
                capture_output=True, text=True, timeout=10
            )
            if 'XFR size' in result.stdout or (result.stdout.count(domain) > 5):
                vulnerable.append(ns)

        return vulnerable
    except Exception:
        return []

def run_dns_recon(target):
    """Main DNS reconnaissance function."""
    results = {
        "target": target,
        "dns_records": {},
        "whois_info": {},
        "subdomains": [],
        "zone_transfer_vulnerable": [],
        "findings": []
    }

    # Skip DNS recon for plain IPs
    is_ip = False
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        pass

    if is_ip:
        print(f"\n  [*] Target is an IP address — performing reverse DNS only")
        try:
            hostname = socket.gethostbyaddr(target)[0]
            results["dns_records"]["PTR"] = [hostname]
            print(f"  [+] Reverse DNS: {hostname}")
        except Exception:
            print(f"  [!] No reverse DNS record found")
        return results

    print(f"\n  [*] Gathering DNS records for {target}...")
    results["dns_records"] = get_dns_records(target)

    for rtype, values in results["dns_records"].items():
        if values:
            print(f"  [+] {rtype} records: {', '.join(values[:3])}")

    print(f"\n  [*] Running WHOIS lookup...")
    results["whois_info"] = get_whois_info(target)
    for key, value in results["whois_info"].items():
        print(f"  [+] {key}: {value}")

    print(f"\n  [*] Checking for zone transfer vulnerability...")
    vulnerable_ns = check_zone_transfer(target)
    results["zone_transfer_vulnerable"] = vulnerable_ns
    if vulnerable_ns:
        results["findings"].append({
            "type": "CRITICAL",
            "title": "DNS Zone Transfer Enabled",
            "detail": f"Nameservers allowing zone transfer: {', '.join(vulnerable_ns)}",
            "recommendation": "Disable zone transfer on all public nameservers immediately"
        })
        print(f"  [!!!] CRITICAL: Zone transfer possible on: {', '.join(vulnerable_ns)}")
    else:
        print(f"  [+] Zone transfer: Not vulnerable")

    results["subdomains"] = enumerate_subdomains(target)
    if results["subdomains"]:
        results["findings"].append({
            "type": "INFO",
            "title": f"Found {len(results['subdomains'])} Subdomains",
            "detail": ", ".join([s["subdomain"] for s in results["subdomains"][:10]]),
            "recommendation": "Review all subdomains for unnecessary exposure"
        })

    return results
