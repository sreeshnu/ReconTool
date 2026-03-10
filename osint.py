import socket
import subprocess
import re
import urllib.request
import urllib.parse
import ssl
import json

def get_ip_geolocation(ip):
    """Get geolocation info for an IP using free API."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            data = json.loads(response.read().decode())
            return {
                "ip": ip,
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country_name", "Unknown"),
                "org": data.get("org", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
                "latitude": data.get("latitude", "Unknown"),
                "longitude": data.get("longitude", "Unknown"),
            }
    except Exception:
        # Fallback to ip-api.com
        try:
            url = f"http://ip-api.com/json/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "city": data.get("city", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "country": data.get("country", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "timezone": data.get("timezone", "Unknown"),
                        "latitude": data.get("lat", "Unknown"),
                        "longitude": data.get("lon", "Unknown"),
                    }
        except Exception:
            pass
        return {"ip": ip, "error": "Geolocation lookup failed"}

def get_asn_info(ip):
    """Get ASN information for an IP."""
    try:
        # Use Team Cymru whois for ASN lookup
        result = subprocess.run(
            ['whois', '-h', 'whois.cymru.com', f' -v {ip}'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                data = lines[-1].split('|')
                if len(data) >= 3:
                    return {
                        "asn": data[0].strip(),
                        "prefix": data[2].strip() if len(data) > 2 else "Unknown",
                        "description": data[-1].strip() if data else "Unknown"
                    }
    except Exception:
        pass

    # Fallback: use ipinfo.io
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://ipinfo.io/{ip}/org"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            org = response.read().decode().strip()
            return {"asn": org, "description": org}
    except Exception:
        return {"asn": "Unknown", "description": "ASN lookup failed"}

def check_shodan_exposure(ip):
    """Check basic exposure info (without API key using public data)."""
    findings = []
    # We check for common exposure indicators
    dangerous_ports = [23, 445, 3389, 6379, 27017, 9200, 5900]

    info = {
        "note": "For full Shodan data, visit: https://www.shodan.io/host/" + ip,
        "manual_check_url": f"https://www.shodan.io/host/{ip}",
        "censys_url": f"https://search.censys.io/hosts/{ip}",
    }
    return info

def find_email_pattern(domain):
    """Identify common email patterns for a domain."""
    common_patterns = [
        f"firstname@{domain}",
        f"firstname.lastname@{domain}",
        f"f.lastname@{domain}",
        f"firstnamelastname@{domain}",
        f"info@{domain}",
        f"contact@{domain}",
        f"admin@{domain}",
        f"support@{domain}",
        f"security@{domain}",
    ]
    return common_patterns

def check_common_admin_panels(target):
    """Check for exposed admin panels."""
    common_paths = [
        "/admin", "/administrator", "/admin.php", "/wp-admin",
        "/wp-login.php", "/login", "/cpanel", "/phpmyadmin",
        "/pma", "/manager/html", "/admin/login", "/backend",
        "/.env", "/config.php", "/configuration.php",
        "/web.config", "/.git/config", "/server-status",
        "/elmah.axd", "/trace.axd", "/.htaccess"
    ]

    found_panels = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"  [*] Checking for exposed admin panels and sensitive files...")

    for path in common_paths:
        for protocol in ["https", "http"]:
            try:
                url = f"{protocol}://{target}{path}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                    status = response.status
                    if status in [200, 301, 302, 403]:
                        found_panels.append({
                            "path": path,
                            "url": url,
                            "status": status,
                            "risk": "Critical" if path in ["/.env", "/.git/config", "/web.config"] else "High"
                        })
                        print(f"      [+] Found [{status}]: {url}")
                        break
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    found_panels.append({
                        "path": path,
                        "url": f"{protocol}://{target}{path}",
                        "status": 403,
                        "risk": "Medium"
                    })
                    print(f"      [!] Forbidden [{e.code}]: {protocol}://{target}{path}")
                    break
            except Exception:
                pass

    return found_panels

def run_osint(target, ip=None):
    """Main OSINT function."""
    results = {
        "target": target,
        "ip": ip,
        "geolocation": {},
        "asn_info": {},
        "shodan_info": {},
        "email_patterns": [],
        "admin_panels": [],
        "findings": []
    }

    # Resolve IP if not provided
    if not ip:
        try:
            ip = socket.gethostbyname(target)
            results["ip"] = ip
        except Exception:
            ip = target

    print(f"\n  [*] Getting IP geolocation for {ip}...")
    geo = get_ip_geolocation(ip)
    results["geolocation"] = geo
    if "error" not in geo:
        print(f"  [+] Location: {geo.get('city')}, {geo.get('region')}, {geo.get('country')}")
        print(f"  [+] Organization: {geo.get('org')}")
        print(f"  [+] Timezone: {geo.get('timezone')}")

    print(f"\n  [*] Getting ASN information...")
    asn = get_asn_info(ip)
    results["asn_info"] = asn
    print(f"  [+] ASN: {asn.get('asn', 'Unknown')}")

    print(f"\n  [*] Checking Shodan exposure references...")
    results["shodan_info"] = check_shodan_exposure(ip)
    print(f"  [+] Manual check: https://www.shodan.io/host/{ip}")

    # Only do domain-specific OSINT if target is not an IP
    is_ip = False
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        pass

    if not is_ip:
        print(f"\n  [*] Generating email patterns for {target}...")
        results["email_patterns"] = find_email_pattern(target)
        print(f"  [+] Common email patterns identified")

        results["admin_panels"] = check_common_admin_panels(target)
        if results["admin_panels"]:
            critical_panels = [p for p in results["admin_panels"] if p["risk"] == "Critical"]
            if critical_panels:
                results["findings"].append({
                    "type": "Critical",
                    "title": "Sensitive Files Exposed",
                    "detail": f"Found {len(critical_panels)} critical exposed files/panels",
                    "recommendation": "Immediately restrict access to sensitive files and admin panels"
                })
            results["findings"].append({
                "type": "High",
                "title": f"Admin Panels/Sensitive Paths Found: {len(results['admin_panels'])}",
                "detail": ", ".join([p["path"] for p in results["admin_panels"][:5]]),
                "recommendation": "Restrict access to admin panels using IP whitelisting or remove if unused"
            })

    return results
