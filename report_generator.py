import datetime
import os
import subprocess
import sys

def generate_html_report(scan_results, output_path):
    """Generate a full HTML report from scan results."""
    target = scan_results.get("target", "Unknown")
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    network = scan_results.get("network", {})
    dns = scan_results.get("dns", {})
    web = scan_results.get("web", {})
    osint = scan_results.get("osint", {})

    # Collect all findings
    all_findings = []
    for section in [network, dns, web, osint]:
        all_findings.extend(section.get("findings", []))

    # Count by severity
    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("type", "INFO")
        severity_count[sev] = severity_count.get(sev, 0) + 1

    risk_color = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#16a34a", "INFO": "#2563eb", "Unknown": "#6b7280"}

    def finding_rows(findings):
        if not findings:
            return "<tr><td colspan='3' style='text-align:center;color:#6b7280;padding:20px'>No findings in this category</td></tr>"
        rows = ""
        for f in findings:
            color = risk_color.get(f.get("type", "INFO"), "#6b7280")
            rows += f"""
            <tr>
                <td><span style='background:{color};color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold'>{f.get('type','INFO')}</span></td>
                <td><strong>{f.get('title','')}</strong><br><small style='color:#6b7280'>{f.get('detail','')}</small></td>
                <td style='color:#059669;font-size:13px'>{f.get('recommendation','')}</td>
            </tr>"""
        return rows

    def port_rows(ports):
        if not ports:
            return "<tr><td colspan='4' style='text-align:center;color:#6b7280;padding:20px'>No open ports found</td></tr>"
        rows = ""
        for p in ports:
            color = risk_color.get(p.get("risk", "Unknown"), "#6b7280")
            rows += f"""
            <tr>
                <td><strong>{p.get('port')}</strong></td>
                <td>{p.get('service','Unknown')}</td>
                <td><span style='background:{color};color:white;padding:2px 8px;border-radius:10px;font-size:12px'>{p.get('risk','Unknown')}</span></td>
                <td style='font-size:12px;color:#374151'>{p.get('info','')}</td>
            </tr>"""
        return rows

    def dns_section():
        records = dns.get("dns_records", {})
        if not records:
            return "<p style='color:#6b7280'>No DNS records found</p>"
        html = "<table style='width:100%;border-collapse:collapse'><tr><th style='background:#f3f4f6;padding:8px;text-align:left'>Type</th><th style='background:#f3f4f6;padding:8px;text-align:left'>Records</th></tr>"
        for rtype, values in records.items():
            if values:
                html += f"<tr><td style='padding:8px;border-bottom:1px solid #e5e7eb'><strong>{rtype}</strong></td><td style='padding:8px;border-bottom:1px solid #e5e7eb'>{', '.join(values[:3])}</td></tr>"
        html += "</table>"
        return html

    def whois_section():
        whois = dns.get("whois_info", {})
        if not whois:
            return "<p style='color:#6b7280'>No WHOIS data</p>"
        html = ""
        for key, value in whois.items():
            html += f"<div style='margin:5px 0'><strong>{key}:</strong> {value}</div>"
        return html

    def subdomain_section():
        subs = dns.get("subdomains", [])
        if not subs:
            return "<p style='color:#6b7280'>No subdomains found</p>"
        html = "<div style='display:flex;flex-wrap:wrap;gap:8px'>"
        for s in subs:
            html += f"<span style='background:#dbeafe;color:#1e40af;padding:3px 10px;border-radius:12px;font-size:13px'>{s['subdomain']} ({s['ip']})</span>"
        html += "</div>"
        return html

    def tech_section():
        techs = web.get("technologies", [])
        if not techs:
            return "<p style='color:#6b7280'>No technologies detected</p>"
        html = "<div style='display:flex;flex-wrap:wrap;gap:8px'>"
        for t in techs:
            html += f"<span style='background:#f0fdf4;color:#166534;padding:5px 12px;border-radius:12px;font-size:13px;border:1px solid #bbf7d0'><strong>{t['name']}:</strong> {t['value']}</span>"
        html += "</div>"
        return html

    def geo_section():
        geo = osint.get("geolocation", {})
        if not geo or "error" in geo:
            return "<p style='color:#6b7280'>Geolocation not available</p>"
        html = f"""
        <div style='display:grid;grid-template-columns:repeat(2,1fr);gap:10px'>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>🌍 Country:</strong> {geo.get('country','Unknown')}</div>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>🏙️ City:</strong> {geo.get('city','Unknown')}</div>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>🏢 Organization:</strong> {geo.get('org','Unknown')}</div>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>🕐 Timezone:</strong> {geo.get('timezone','Unknown')}</div>
        </div>"""
        return html

    def ssl_section():
        ssl_info = web.get("ssl_info", {})
        if not ssl_info or not ssl_info.get("valid"):
            return "<p style='color:#6b7280'>SSL/TLS not available or check failed</p>"
        days = ssl_info.get("days_left", "?")
        color = "#dc2626" if isinstance(days, int) and days < 30 else "#16a34a"
        return f"""
        <div style='display:grid;grid-template-columns:repeat(2,1fr);gap:10px'>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>Issuer:</strong> {ssl_info.get('issuer',{}).get('organizationName','Unknown')}</div>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>TLS Version:</strong> {ssl_info.get('tls_version','Unknown')}</div>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>Cipher:</strong> {ssl_info.get('cipher','Unknown')}</div>
            <div style='background:#f9fafb;padding:10px;border-radius:8px'><strong>Expiry:</strong> <span style='color:{color}'>{days} days remaining</span></div>
        </div>"""

    def admin_panels_section():
        panels = osint.get("admin_panels", [])
        if not panels:
            return "<p style='color:#16a34a'>✅ No exposed admin panels found</p>"
        html = ""
        for p in panels:
            color = risk_color.get(p.get("risk", "High"), "#ea580c")
            html += f"<div style='margin:5px 0;padding:8px;background:#fef2f2;border-left:4px solid {color};border-radius:4px'><strong>[{p['status']}]</strong> {p['url']} <span style='color:{color};font-size:12px'>({p['risk']})</span></div>"
        return html

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconTool Report — {target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f3f4f6; color: #111827; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px; }}
  .header {{ background: linear-gradient(135deg, #1e1b4b, #312e81, #4338ca); color: white; padding: 40px; border-radius: 16px; margin-bottom: 25px; }}
  .header h1 {{ font-size: 32px; font-weight: 800; margin-bottom: 8px; }}
  .header .subtitle {{ opacity: 0.8; font-size: 15px; }}
  .header .meta {{ margin-top: 20px; display: flex; gap: 30px; flex-wrap: wrap; }}
  .header .meta div {{ background: rgba(255,255,255,0.1); padding: 8px 16px; border-radius: 8px; }}
  .card {{ background: white; border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .card h2 {{ font-size: 18px; font-weight: 700; margin-bottom: 18px; padding-bottom: 10px; border-bottom: 2px solid #f3f4f6; display: flex; align-items: center; gap: 8px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px; }}
  .summary-box {{ border-radius: 12px; padding: 20px; text-align: center; color: white; }}
  .summary-box .count {{ font-size: 36px; font-weight: 800; }}
  .summary-box .label {{ font-size: 13px; opacity: 0.9; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #f9fafb; padding: 10px 12px; text-align: left; font-size: 13px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 12px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #fafafa; }}
  .disclaimer {{ background: #fef3c7; border: 1px solid #fcd34d; border-radius: 12px; padding: 20px; margin-top: 20px; }}
  .footer {{ text-align: center; padding: 20px; color: #9ca3af; font-size: 13px; }}
  @media print {{ body {{ background: white; }} .container {{ padding: 10px; }} }}
</style>
</head>
<body>
<div class="container">

  <!-- HEADER -->
  <div class="header">
    <h1>🔍 ReconTool — Security Report</h1>
    <p class="subtitle">Full Reconnaissance & Vulnerability Assessment</p>
    <div class="meta">
      <div>🎯 Target: <strong>{target}</strong></div>
      <div>🌐 IP: <strong>{network.get('ip', 'N/A')}</strong></div>
      <div>📅 Scan Time: <strong>{scan_time}</strong></div>
      <div>🖥️ Hostname: <strong>{network.get('hostname', 'N/A')}</strong></div>
    </div>
  </div>

  <!-- SUMMARY -->
  <div class="summary-grid">
    <div class="summary-box" style="background:#dc2626">
      <div class="count">{severity_count['Critical']}</div>
      <div class="label">Critical</div>
    </div>
    <div class="summary-box" style="background:#ea580c">
      <div class="count">{severity_count['High']}</div>
      <div class="label">High</div>
    </div>
    <div class="summary-box" style="background:#d97706">
      <div class="count">{severity_count['Medium']}</div>
      <div class="label">Medium</div>
    </div>
    <div class="summary-box" style="background:#16a34a">
      <div class="count">{severity_count['Low']}</div>
      <div class="label">Low</div>
    </div>
    <div class="summary-box" style="background:#2563eb">
      <div class="count">{severity_count['INFO']}</div>
      <div class="label">Info</div>
    </div>
  </div>

  <!-- NETWORK SCAN -->
  <div class="card">
    <h2>🌐 Network Scan Results</h2>
    <p style="margin-bottom:15px;color:#6b7280">Host Status: <strong style="color:{'#16a34a' if network.get('host_alive') else '#dc2626'}">{'ALIVE ✅' if network.get('host_alive') else 'DOWN / BLOCKING ICMP ⚠️'}</strong> &nbsp;|&nbsp; Open Ports Found: <strong>{len(network.get('open_ports', []))}</strong></p>
    <table>
      <tr><th>Port</th><th>Service</th><th>Risk</th><th>Description</th></tr>
      {port_rows(network.get('open_ports', []))}
    </table>
  </div>

  <!-- DNS RECON -->
  <div class="card">
    <h2>🔎 DNS Intelligence</h2>
    <h3 style="font-size:14px;color:#374151;margin-bottom:10px">DNS Records</h3>
    {dns_section()}
    <h3 style="font-size:14px;color:#374151;margin:20px 0 10px">WHOIS Information</h3>
    {whois_section()}
    <h3 style="font-size:14px;color:#374151;margin:20px 0 10px">Subdomains Found ({len(dns.get('subdomains', []))})</h3>
    {subdomain_section()}
  </div>

  <!-- WEB RECON -->
  <div class="card">
    <h2>🌍 Web Application Intelligence</h2>
    <h3 style="font-size:14px;color:#374151;margin-bottom:10px">Detected Technologies</h3>
    {tech_section()}
    <h3 style="font-size:14px;color:#374151;margin:20px 0 10px">SSL/TLS Certificate</h3>
    {ssl_section()}
    <h3 style="font-size:14px;color:#374151;margin:20px 0 10px">Security Headers Analysis</h3>
    <table>
      <tr><th>Risk</th><th>Finding</th><th>Recommendation</th></tr>
      {finding_rows(web.get('security_headers', {}).get('missing', []))}
    </table>
  </div>

  <!-- OSINT -->
  <div class="card">
    <h2>🕵️ OSINT Intelligence</h2>
    <h3 style="font-size:14px;color:#374151;margin-bottom:10px">IP Geolocation</h3>
    {geo_section()}
    <h3 style="font-size:14px;color:#374151;margin:20px 0 10px">Exposed Admin Panels & Sensitive Files</h3>
    {admin_panels_section()}
  </div>

  <!-- ALL FINDINGS -->
  <div class="card">
    <h2>⚠️ All Findings & Recommendations</h2>
    <table>
      <tr><th>Severity</th><th>Finding</th><th>Recommendation</th></tr>
      {finding_rows(all_findings) if all_findings else "<tr><td colspan='3' style='text-align:center;color:#16a34a;padding:20px'>✅ No significant findings</td></tr>"}
    </table>
  </div>

  <!-- DISCLAIMER -->
  <div class="disclaimer">
    <strong>⚖️ Legal Disclaimer:</strong> This tool is intended for authorized security testing only.
    Scanning systems without explicit written permission is illegal under computer crime laws in most countries.
    The user assumes full responsibility for how this tool is used. Always obtain proper authorization before scanning any target.
  </div>

  <div class="footer">
    Generated by ReconTool | {scan_time} | For authorized use only
  </div>
</div>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_path

def generate_pdf_report(scan_results, output_dir="reports"):
    """Generate PDF report by converting HTML to PDF."""
    os.makedirs(output_dir, exist_ok=True)
    target = scan_results.get("target", "unknown").replace(".", "_").replace("/", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    html_path = os.path.join(output_dir, f"recon_{target}_{timestamp}.html")
    pdf_path = os.path.join(output_dir, f"recon_{target}_{timestamp}.pdf")

    print(f"\n  [*] Generating HTML report...")
    generate_html_report(scan_results, html_path)
    print(f"  [+] HTML report saved: {html_path}")

    # Try to convert to PDF using available tools
    pdf_generated = False

    # Try wkhtmltopdf
    try:
        result = subprocess.run(
            ['wkhtmltopdf', '--quiet', '--page-size', 'A4',
             '--margin-top', '10mm', '--margin-bottom', '10mm',
             '--margin-left', '10mm', '--margin-right', '10mm',
             html_path, pdf_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and os.path.exists(pdf_path):
            pdf_generated = True
            print(f"  [+] PDF report saved: {pdf_path}")
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Try chromium/chrome headless
    if not pdf_generated:
        for browser in ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']:
            try:
                result = subprocess.run(
                    [browser, '--headless', '--disable-gpu', '--no-sandbox',
                     f'--print-to-pdf={pdf_path}', html_path],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and os.path.exists(pdf_path):
                    pdf_generated = True
                    print(f"  [+] PDF report saved: {pdf_path}")
                    break
            except FileNotFoundError:
                continue
            except Exception:
                continue

    if not pdf_generated:
        print(f"  [!] PDF conversion requires wkhtmltopdf or Chromium on your Kali system")
        print(f"      Install with: sudo apt install wkhtmltopdf")
        print(f"  [+] HTML report is fully usable — open in any browser")
        return html_path

    return pdf_path
