#!/usr/bin/env python3
"""
THREAT INTELLIGENCE SYSTEM — MAIN ORCHESTRATOR
College Project

Run this file to start a full scan:
    python main.py

Pipeline:
    1. You enter a domain name
    2. Subdomain enumeration (crt.sh + HackerTarget)
    3. Security checks (DNS, SSL, DMARC, SPF, Headers)
    4. IP Concentration Analysis (find exposed servers)
    5. Live Site Scanner (crawl + TruffleHog)
    6. Wayback Machine Scanner (historical files + TruffleHog)
    7. Final summary report
"""

import asyncio
import os
import json
import datetime

# ── Import all modules ────────────────────────────────────────────
from subdomain_enum import enumerate_subdomains
from security_checks import run_security_checks
from ipconc2 import run_ip_concentration
from LiveScan import scan_live_site
from WaybackScan import scan_wayback

RESULTS_DIR = "recon_data"

# Max subdomains to deep-scan (keeps it fast for demo/college)
MAX_DEEP_SCAN_TARGETS = 5


# ========== BANNER ==========
def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          THREAT INTELLIGENCE SYSTEM — v1.0                   ║
║          College Project | Bug Bounty Recon Tool             ║
╠══════════════════════════════════════════════════════════════╣
║  Phase 1 → Subdomain Enumeration                             ║
║  Phase 2 → Security Checks (DNS/SSL/DMARC/SPF/Headers)       ║
║  Phase 3 → IP Concentration Analysis                         ║
║  Phase 4 → Live Site Secret Scanner (TruffleHog)             ║
║  Phase 5 → Wayback Machine Secret Scanner (TruffleHog)       ║
╚══════════════════════════════════════════════════════════════╝
    """)


# ========== REPORT SAVER ==========
def save_final_report(domain, report_data):
    """
    Saves the complete scan results as a JSON file.
    Located at: recon_data/<domain>/final_report.json
    """
    domain_dir = os.path.join(RESULTS_DIR, domain)
    os.makedirs(domain_dir, exist_ok=True)

    report_file = os.path.join(domain_dir, "final_report.json")
    with open(report_file, 'w') as f:
        json.dump(report_data, f, indent=2, default=str)

    return report_file


def print_final_summary(domain, report, elapsed):
    """Prints a clean end-of-scan summary"""
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    SCAN COMPLETE                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Domain    : {domain:<48}║")
    print(f"║  Duration  : {str(elapsed).split('.')[0]:<48}║")
    print(f"║  Subdomains: {len(report.get('subdomains', [])):<48}║")

    ip_data = report.get('ip_concentration', {})
    exposed = ip_data.get('exposed_subdomains', [])
    print(f"║  Exposed   : {len(exposed)} subdomains without CDN protection{' '*(14-len(str(len(exposed))))}║")

    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Results saved to: recon_data/{domain}/{'':>25}║")
    print("║  Files:                                                      ║")
    print("║    - final_report.json       (full structured report)        ║")
    print("║    - leaks_found_live.txt    (live site secrets)             ║")
    print("║    - leaks_found_wayback.txt (historical secrets)            ║")
    print("╚══════════════════════════════════════════════════════════════╝")


# ========== MAIN SCAN PIPELINE ==========
async def run_full_scan(domain):
    """
    The full orchestrated pipeline.
    Each phase feeds data into the next.
    """
    start_time = datetime.datetime.now()
    report = {
        'domain': domain,
        'scan_started': str(start_time),
        'phases': {}
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)

    # ────────────────────────────────────────────────────────────
    # PHASE 1: SUBDOMAIN ENUMERATION
    # ────────────────────────────────────────────────────────────
    subdomains = enumerate_subdomains(domain)

    if not subdomains:
        print("\n  [WARNING] No subdomains found via APIs.")
        print("  [INFO] Using root domain + www as fallback targets.")
        subdomains = [domain, f"www.{domain}"]

    report['subdomains'] = subdomains
    report['phases']['1_subdomain_enum'] = {
        'total_found': len(subdomains),
        'subdomains': subdomains
    }

    # ────────────────────────────────────────────────────────────
    # PHASE 2: SECURITY CHECKS
    # ────────────────────────────────────────────────────────────
    security_results = run_security_checks(domain)
    report['phases']['2_security_checks'] = security_results

    # ────────────────────────────────────────────────────────────
    # PHASE 3: IP CONCENTRATION
    # ────────────────────────────────────────────────────────────
    ip_results = run_ip_concentration(subdomains)

    report['phases']['3_ip_concentration'] = {
        'total_live': len(ip_results['all_live']),
        'unique_ips': len(ip_results['clusters']),
        'exposed_subdomains': ip_results['exposed'],
        'clusters': {ip: subs for ip, subs in ip_results['clusters'].items()}
    }

    # ── Decide what to deep-scan ─────────────────────────────────
    # Priority: Exposed origins first (no CDN = real server)
    # Fallback: Just use first few live subdomains
    if ip_results['exposed']:
        targets_for_deep_scan = ip_results['exposed'][:MAX_DEEP_SCAN_TARGETS]
        print(f"\n[INFO] Targeting {len(targets_for_deep_scan)} EXPOSED subdomains for deep scan")
    elif ip_results['all_live']:
        targets_for_deep_scan = ip_results['all_live'][:MAX_DEEP_SCAN_TARGETS]
        print(f"\n[INFO] No exposed origins found. Scanning first {len(targets_for_deep_scan)} live subdomains")
    else:
        targets_for_deep_scan = subdomains[:2]
        print(f"\n[WARNING] No live subdomains found via DNS. Trying first 2 anyway...")

    report['phases']['3_ip_concentration']['deep_scan_targets'] = targets_for_deep_scan

    # ────────────────────────────────────────────────────────────
    # PHASE 4: LIVE SITE SCANNING
    # ────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"PHASE 4: LIVE SITE SCANNING ({len(targets_for_deep_scan)} targets)")
    print('='*60)

    for i, target in enumerate(targets_for_deep_scan, 1):
        print(f"\n  → [{i}/{len(targets_for_deep_scan)}] Scanning: {target}")
        try:
            await scan_live_site(target)
        except Exception as e:
            print(f"  [ERROR] Live scan failed for {target}: {e}")

    # ────────────────────────────────────────────────────────────
    # PHASE 5: WAYBACK MACHINE SCANNING
    # ────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"PHASE 5: WAYBACK MACHINE SCANNING ({len(targets_for_deep_scan)} targets)")
    print('='*60)

    for i, target in enumerate(targets_for_deep_scan, 1):
        print(f"\n  → [{i}/{len(targets_for_deep_scan)}] Wayback scan: {target}")
        try:
            await scan_wayback(target)
        except Exception as e:
            print(f"  [ERROR] Wayback scan failed for {target}: {e}")

    # ────────────────────────────────────────────────────────────
    # FINAL REPORT
    # ────────────────────────────────────────────────────────────
    elapsed = datetime.datetime.now() - start_time
    report['scan_completed'] = str(datetime.datetime.now())
    report['duration_seconds'] = elapsed.total_seconds()

    report_file = save_final_report(domain, report)
    print(f"\n[REPORT] Full JSON report saved: {report_file}")

    print_final_summary(domain, report, elapsed)

    return report


# ========== ENTRY POINT ==========
def main():
    print_banner()

    # ── Get target domain from user ───────────────────────────────
    print("Enter the target domain (e.g. example.com)")
    print("Do NOT include http:// or www\n")
    domain = input("  Domain: ").strip()

    # Clean input
    domain = (domain
              .replace("https://", "")
              .replace("http://", "")
              .replace("www.", "")
              .strip("/")
              .strip())

    if not domain or '.' not in domain:
        print("\n[ERROR] Invalid domain entered. Example: example.com")
        return

    print(f"\n[✓] Target confirmed: {domain}")
    print(f"[✓] Results will be saved to: {RESULTS_DIR}/{domain}/")
    print(f"[✓] Docker must be running for TruffleHog to work\n")

    confirm = input("Start scan? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Scan cancelled.")
        return

    # ── Run the full pipeline ─────────────────────────────────────
    asyncio.run(run_full_scan(domain))


if __name__ == "__main__":
    main()