#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                    R E C O N T O O L                        ║
║          Full Reconnaissance & Vulnerability Scanner        ║
║                                                              ║
║  Modules: Network | DNS | Web | OSINT | PDF Report          ║
║  Usage:   python3 main.py -t <target> [options]             ║
║                                                              ║
║  ⚠️  For authorized testing only. Use responsibly.          ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import datetime
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.network_scan import run_network_scan
from modules.dns_recon import run_dns_recon
from modules.web_recon import run_web_recon
from modules.osint import run_osint
from modules.report_generator import generate_pdf_report

# ANSI Colors
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗████████╗ ██████╗  ██████╗ ██╗     
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║     
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║     
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ██║   ██║   ██║██║   ██║██║     
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{RESET}
{WHITE}        Full Reconnaissance & Vulnerability Assessment Tool{RESET}
{YELLOW}        ⚠️  For authorized security testing only{RESET}
{CYAN}        ─────────────────────────────────────────────{RESET}
"""

def print_section(title, icon="🔍"):
    print(f"\n{CYAN}{BOLD}{'─'*60}{RESET}")
    print(f"{CYAN}{BOLD}  {icon}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'─'*60}{RESET}")

def print_summary(all_results):
    """Print final summary to terminal."""
    network = all_results.get("network", {})
    dns     = all_results.get("dns", {})
    web     = all_results.get("web", {})
    osint_r = all_results.get("osint", {})

    all_findings = []
    for section in [network, dns, web, osint_r]:
        all_findings.extend(section.get("findings", []))

    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("type", "INFO")
        severity_count[sev] = severity_count.get(sev, 0) + 1

    print(f"\n{CYAN}{BOLD}{'═'*60}{RESET}")
    print(f"{CYAN}{BOLD}   SCAN COMPLETE — SUMMARY{RESET}")
    print(f"{CYAN}{BOLD}{'═'*60}{RESET}")
    print(f"  {WHITE}Target   :{RESET} {all_results.get('target')}")
    print(f"  {WHITE}IP       :{RESET} {network.get('ip', 'N/A')}")
    print(f"  {WHITE}Hostname :{RESET} {network.get('hostname', 'N/A')}")
    print(f"  {WHITE}Open Ports:{RESET} {len(network.get('open_ports', []))}")
    print(f"  {WHITE}Subdomains:{RESET} {len(dns.get('subdomains', []))}")
    print(f"  {WHITE}Admin Panels Found:{RESET} {len(osint_r.get('admin_panels', []))}")
    print(f"\n  {WHITE}Findings by Severity:{RESET}")
    print(f"    {RED}  Critical : {severity_count['Critical']}{RESET}")
    print(f"    {YELLOW}  High     : {severity_count['High']}{RESET}")
    print(f"    {YELLOW}  Medium   : {severity_count['Medium']}{RESET}")
    print(f"    {GREEN}  Low      : {severity_count['Low']}{RESET}")
    print(f"    {BLUE}  Info     : {severity_count['INFO']}{RESET}")

    if severity_count["Critical"] > 0:
        print(f"\n  {RED}{BOLD}⚠️  CRITICAL ISSUES FOUND — IMMEDIATE ACTION REQUIRED!{RESET}")
    elif severity_count["High"] > 0:
        print(f"\n  {YELLOW}{BOLD}⚠️  HIGH SEVERITY ISSUES FOUND — REVIEW RECOMMENDED{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}✅  No critical or high severity issues found{RESET}")

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ReconTool — Full Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IP address or domain (e.g. 192.168.1.1 or example.com)"
    )
    parser.add_argument(
        "--no-network", action="store_true",
        help="Skip network/port scanning"
    )
    parser.add_argument(
        "--no-dns", action="store_true",
        help="Skip DNS reconnaissance"
    )
    parser.add_argument(
        "--no-web", action="store_true",
        help="Skip web application recon"
    )
    parser.add_argument(
        "--no-osint", action="store_true",
        help="Skip OSINT gathering"
    )
    parser.add_argument(
        "--ports", choices=["common", "extended"], default="common",
        help="Port scan range: 'common' (default, ~25 ports) or 'extended' (1-1024)"
    )
    parser.add_argument(
        "--output-dir", default="reports",
        help="Directory to save reports (default: reports/)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also save raw results as JSON"
    )

    args = parser.parse_args()
    target = args.target.strip().rstrip("/")

    # Remove protocol if present
    for prefix in ["https://", "http://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
            break

    print(f"{WHITE}  Target   : {CYAN}{BOLD}{target}{RESET}")
    print(f"{WHITE}  Time     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{WHITE}  Modules  : {'Network ' if not args.no_network else ''}{'DNS ' if not args.no_dns else ''}{'Web ' if not args.no_web else ''}{'OSINT' if not args.no_osint else ''}{RESET}")

    all_results = {"target": target}

    # Network Scan
    if not args.no_network:
        print_section("NETWORK RECONNAISSANCE", "🌐")
        all_results["network"] = run_network_scan(target, port_range=args.ports)
    else:
        all_results["network"] = {}

    # DNS Recon
    if not args.no_dns:
        print_section("DNS INTELLIGENCE", "🔎")
        all_results["dns"] = run_dns_recon(target)
    else:
        all_results["dns"] = {}

    # Web Recon
    if not args.no_web:
        print_section("WEB APPLICATION INTELLIGENCE", "🌍")
        ip = all_results.get("network", {}).get("ip")
        all_results["web"] = run_web_recon(target)
    else:
        all_results["web"] = {}

    # OSINT
    if not args.no_osint:
        print_section("OSINT GATHERING", "🕵️")
        ip = all_results.get("network", {}).get("ip")
        all_results["osint"] = run_osint(target, ip=ip)
    else:
        all_results["osint"] = {}

    # Summary
    print_summary(all_results)

    # Save JSON if requested
    if args.json:
        os.makedirs(args.output_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(args.output_dir, f"recon_{target.replace('.','_')}_{ts}.json")
        with open(json_path, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n  {GREEN}[+] JSON saved: {json_path}{RESET}")

    # Generate Report
    print_section("GENERATING PDF REPORT", "📄")
    report_path = generate_pdf_report(all_results, output_dir=args.output_dir)
    print(f"\n  {GREEN}{BOLD}[+] Report ready: {report_path}{RESET}")
    print(f"\n{CYAN}{'═'*60}{RESET}\n")

if __name__ == "__main__":
    main()
