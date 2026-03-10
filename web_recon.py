import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import re
import datetime

def get_http_headers(target, port=80, use_ssl=False):
    """Fetch HTTP headers from target."""
    try:
        protocol = "https" if use_ssl else "http"
        if not target.startswith("http"):
            url = f"{protocol}://{target}"
        else:
            url = target

        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            headers = dict(response.headers)
            status = response.status
            return {"status": status, "headers": headers, "url": url}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": dict(e.headers), "url": target}
    except Exception as e:
        return {"status": None, "headers": {}, "url": target, "error": str(e)}

def analyze_security_headers(headers):
    """Check for missing or misconfigured security headers."""
    security_headers = {
        "Strict-Transport-Security": {
            "risk": "High",
            "description": "HSTS missing — site vulnerable to SSL stripping attacks",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        },
        "X-Frame-Options": {
            "risk": "Medium",
            "description": "Clickjacking protection missing",
            "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
        },
        "X-Content-Type-Options": {
            "risk": "Medium",
            "description": "MIME sniffing protection missing",
            "recommendation": "Add: X-Content-Type-Options: nosniff"
        },
        "Content-Security-Policy": {
            "risk": "High",
            "description": "CSP missing — XSS attacks more likely to succeed",
            "recommendation": "Implement a strict Content-Security-Policy header"
        },
        "X-XSS-Protection": {
            "risk": "Medium",
            "description": "XSS filter header missing",
            "recommendation": "Add: X-XSS-Protection: 1; mode=block"
        },
        "Referrer-Policy": {
            "risk": "Low",
            "description": "Referrer policy not set — may leak sensitive URLs",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "risk": "Low",
            "description": "Permissions policy not set",
            "recommendation": "Add Permissions-Policy to control browser features"
        }
    }

    findings = []
    present = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, info in security_headers.items():
        if header.lower() in headers_lower:
            present.append({"header": header, "value": headers_lower[header.lower()]})
        else:
            findings.append({
                "header": header,
                "risk": info["risk"],
                "description": info["description"],
                "recommendation": info["recommendation"]
            })

    return {"missing": findings, "present": present}

def detect_technologies(headers, body=""):
    """Detect web technologies from headers and page content."""
    technologies = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Server detection
    if "server" in headers_lower:
        technologies.append({"name": "Server", "value": headers_lower["server"]})

    # Framework detection from headers
    header_tech = {
        "x-powered-by": "Powered By",
        "x-aspnet-version": "ASP.NET",
        "x-generator": "Generator",
        "x-drupal-cache": "Drupal CMS",
        "x-wordpress": "WordPress",
    }
    for h, name in header_tech.items():
        if h in headers_lower:
            technologies.append({"name": name, "value": headers_lower[h]})

    # Content-type
    if "content-type" in headers_lower:
        technologies.append({"name": "Content-Type", "value": headers_lower["content-type"]})

    return technologies

def check_ssl_certificate(target):
    """Analyze SSL/TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse expiry
                expiry_str = cert.get('notAfter', '')
                expiry_date = None
                days_left = None
                if expiry_str:
                    try:
                        expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry_date - datetime.datetime.utcnow()).days
                    except Exception:
                        pass

                # Get subject info
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                findings = []
                if days_left is not None and days_left < 30:
                    findings.append({
                        "type": "High",
                        "issue": f"SSL certificate expires in {days_left} days",
                        "recommendation": "Renew SSL certificate immediately"
                    })
                if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                    findings.append({
                        "type": "Critical",
                        "issue": f"Outdated TLS version: {version}",
                        "recommendation": "Upgrade to TLS 1.2 or TLS 1.3"
                    })

                return {
                    "valid": True,
                    "subject": subject,
                    "issuer": issuer,
                    "expiry": str(expiry_date) if expiry_date else expiry_str,
                    "days_left": days_left,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "findings": findings
                }
    except Exception as e:
        return {"valid": False, "error": str(e), "findings": []}

def check_robots_txt(target):
    """Fetch and analyze robots.txt."""
    try:
        if not target.startswith("http"):
            url = f"http://{target}/robots.txt"
        else:
            url = f"{target}/robots.txt"

        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            content = response.read().decode('utf-8', errors='ignore')
            disallowed = re.findall(r'Disallow:\s*(.+)', content, re.IGNORECASE)
            return {
                "found": True,
                "content": content[:1000],
                "disallowed_paths": [d.strip() for d in disallowed if d.strip()]
            }
    except Exception:
        return {"found": False, "disallowed_paths": []}

def run_web_recon(target):
    """Main web reconnaissance function."""
    results = {
        "target": target,
        "http_info": {},
        "https_info": {},
        "security_headers": {},
        "technologies": [],
        "ssl_info": {},
        "robots_txt": {},
        "findings": []
    }

    print(f"\n  [*] Scanning HTTP (port 80)...")
    http_result = get_http_headers(target, 80, use_ssl=False)
    results["http_info"] = http_result
    if http_result.get("status"):
        print(f"  [+] HTTP Status: {http_result['status']}")

    print(f"  [*] Scanning HTTPS (port 443)...")
    https_result = get_http_headers(target, 443, use_ssl=True)
    results["https_info"] = https_result
    if https_result.get("status"):
        print(f"  [+] HTTPS Status: {https_result['status']}")

    # Use whichever headers we got
    headers = https_result.get("headers") or http_result.get("headers") or {}

    print(f"  [*] Analyzing security headers...")
    sec_headers = analyze_security_headers(headers)
    results["security_headers"] = sec_headers

    missing_count = len(sec_headers["missing"])
    print(f"  [+] Present security headers: {len(sec_headers['present'])}")
    print(f"  [!] Missing security headers: {missing_count}")

    for missing in sec_headers["missing"]:
        results["findings"].append({
            "type": missing["risk"],
            "title": f"Missing Header: {missing['header']}",
            "detail": missing["description"],
            "recommendation": missing["recommendation"]
        })

    print(f"  [*] Detecting technologies...")
    results["technologies"] = detect_technologies(headers)
    for tech in results["technologies"]:
        print(f"  [+] Detected: {tech['name']} = {tech['value']}")

    print(f"  [*] Analyzing SSL/TLS certificate...")
    ssl_info = check_ssl_certificate(target)
    results["ssl_info"] = ssl_info
    if ssl_info.get("valid"):
        print(f"  [+] SSL Issuer: {ssl_info.get('issuer', {}).get('organizationName', 'Unknown')}")
        print(f"  [+] TLS Version: {ssl_info.get('tls_version', 'Unknown')}")
        print(f"  [+] Days until expiry: {ssl_info.get('days_left', 'Unknown')}")
        for finding in ssl_info.get("findings", []):
            results["findings"].append({
                "type": finding["type"],
                "title": finding["issue"],
                "detail": finding["issue"],
                "recommendation": finding["recommendation"]
            })
    else:
        print(f"  [!] SSL check failed: {ssl_info.get('error', 'Unknown')}")

    print(f"  [*] Checking robots.txt...")
    robots = check_robots_txt(target)
    results["robots_txt"] = robots
    if robots["found"]:
        print(f"  [+] robots.txt found with {len(robots['disallowed_paths'])} disallowed paths")
        if robots["disallowed_paths"]:
            results["findings"].append({
                "type": "INFO",
                "title": "Interesting Paths in robots.txt",
                "detail": f"Disallowed paths found: {', '.join(robots['disallowed_paths'][:5])}",
                "recommendation": "Review these paths as they may contain sensitive content"
            })
    else:
        print(f"  [!] No robots.txt found")

    return results
