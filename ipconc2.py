#!/usr/bin/env python3
"""
IP CONCENTRATION ANALYZER (Modified for orchestrator)
- Accepts a dynamic list of subdomains
- Resolves IPs via DNS
- Groups subdomains by shared IP (finds attack surface clusters)
- Classifies each cluster: CDN-protected vs Exposed Origin
- Returns exposed subdomains for deep scanning
"""

import dns.resolver
import requests
import socket
from tabulate import tabulate

# Silence SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Signature lists for infrastructure detection
CDN_KEYWORDS = [
    "cloudflare", "akamai", "fastly", "incapsula", "imperva",
    "sucuri", "stackpath", "edgio", "fly.io", "cloudfront",
    "cdn", "edge", "akadns"
]
HOSTING_KEYWORDS = [
    "amazon", "google", "digitalocean", "hetzner", "ovh",
    "linode", "vultr", "azure", "rackspace", "leaseweb",
    "contabo", "scaleway"
]


# ========== IP RESOLVER ==========
def resolve_ip(subdomain):
    """
    Resolves a subdomain to its IPv4 address.
    Returns None if subdomain doesn't resolve (dead/parked).
    """
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None
    except Exception:
        return None


# ========== ASN LOOKUP ==========
def get_asn_info(ip):
    """
    Queries ipinfo.io to find who owns this IP (the hosting provider / CDN).
    Free tier: 50,000 requests/month — plenty for recon.
    """
    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=5,
            headers={'User-Agent': 'ThreatIntelScanner/1.0'}
        ).json()
        return resp.get('org', 'unknown').lower()
    except Exception:
        return "unknown"


# ========== INFRASTRUCTURE CLASSIFIER ==========
def analyze_infrastructure(subdomain, ip):
    """
    Triple-verification to determine if subdomain is CDN-protected or exposed.
    
    Why this matters for bug bounty:
    - CDN-protected: Real IP is hidden, harder to attack directly
    - Exposed Origin: Real server IP is visible, higher attack surface
    
    Returns: (security_type, detection_method)
    """

    # Method 1: CNAME Check (most reliable)
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=5)
        for rdata in answers:
            cname = str(rdata.target).lower()
            cdn_cnames = [
                ".cloudflare.net", ".edgekey.net", ".cloudfront.net",
                ".fastly.net", ".akamaiedge.net", ".akamai.net"
            ]
            if any(k in cname for k in cdn_cnames):
                return "Protected (CDN)", f"CNAME → {cname[:40]}"
    except Exception:
        pass

    # Method 2: ASN / Org Lookup
    org_name = get_asn_info(ip)
    if any(k in org_name for k in CDN_KEYWORDS):
        return "Protected (CDN)", f"ASN: {org_name[:40].upper()}"

    # Method 3: Response Headers
    try:
        resp = requests.head(
            f"https://{subdomain}",
            timeout=5,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0'},
            allow_redirects=True
        )
        headers_str = str(resp.headers).lower()
        cdn_headers = ["cf-ray", "x-akamai", "x-amz-cf-id", "x-served-by", "x-cache"]
        for h in cdn_headers:
            if h in headers_str:
                return "Protected (CDN)", f"Header: {h}"
    except Exception:
        pass

    # Method 4: Classify by Hosting Provider
    if any(k in org_name for k in HOSTING_KEYWORDS):
        return "Exposed (Origin)", f"Host: {org_name[:40].upper()}"

    return "Unknown / Unresolved", "N/A"


# ========== MAIN ENTRY POINT ==========
def run_ip_concentration(subdomains):
    """
    Main function called by orchestrator.
    
    Input:  list of subdomain strings
    Output: dict with:
        - clusters: {ip: [subdomains]}
        - exposed:  [subdomains with no CDN — priority scan targets]
        - all_live: [all subdomains that resolved to an IP]
    """
    print(f"\n{'='*60}")
    print(f"PHASE 3: IP CONCENTRATION ANALYSIS")
    print('='*60)

    # ── Step 1: Resolve all IPs ──────────────────────────────────
    print(f"\n  [*] Resolving IPs for {len(subdomains)} subdomains...")
    live_data = []
    dead_subdomains = []

    for sub in subdomains:
        ip = resolve_ip(sub)
        if ip:
            live_data.append({'subdomain': sub, 'ip': ip})
            print(f"    ✓ {sub:<45} → {ip}")
        else:
            dead_subdomains.append(sub)
            print(f"    ✗ {sub:<45} → [no DNS / not live]")

    if dead_subdomains:
        print(f"\n  [INFO] {len(dead_subdomains)} subdomains didn't resolve (parked/dead):")
        for d in dead_subdomains:
            print(f"    - {d}")

    if not live_data:
        print("\n  [WARNING] No subdomains resolved to an IP!")
        return {'clusters': {}, 'exposed': [], 'all_live': []}

    # ── Step 2: Group by IP (find clusters) ──────────────────────
    clusters = {}
    for entry in live_data:
        ip = entry['ip']
        if ip not in clusters:
            clusters[ip] = []
        clusters[ip].append(entry['subdomain'])

    # ── Step 3: Classify each cluster ────────────────────────────
    print(f"\n  [*] Analyzing infrastructure for {len(clusters)} unique IPs...")
    table_data = []
    exposed_subdomains = []

    for ip, subs in clusters.items():
        # Analyze using first subdomain in cluster (they share the IP)
        infra_type, method = analyze_infrastructure(subs[0], ip)
        count = len(subs)

        # Risk rating
        if "Exposed" in infra_type and count > 1:
            risk = f"HIGH RISK — {count} assets on exposed IP"
        elif "Exposed" in infra_type:
            risk = "MEDIUM RISK — Exposed Origin"
        elif "Protected" in infra_type:
            risk = "LOW RISK — Behind CDN"
        else:
            risk = "UNKNOWN — Manual review needed"

        if "Exposed" in infra_type or "Unknown" in infra_type:
            exposed_subdomains.extend(subs)

        subdomain_display = "\n".join(subs) if len(subs) <= 3 else "\n".join(subs[:3]) + f"\n(+{len(subs)-3} more)"
        table_data.append([ip, count, risk, method, subdomain_display])

    # ── Step 4: Print table ───────────────────────────────────────
    headers = ["IP Address", "Count", "Risk Assessment", "Detection", "Subdomains"]
    print("\n" + "="*85)
    print("  INFRASTRUCTURE CONCENTRATION REPORT")
    print("="*85)
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print("="*85)

    # ── Step 5: Summary ───────────────────────────────────────────
    print(f"\n  [SUMMARY]")
    print(f"    Total live subdomains : {len(live_data)}")
    print(f"    Unique IPs            : {len(clusters)}")
    print(f"    Exposed/Unknown IPs   : {len([s for s in table_data if 'RISK' in s[2]])}")
    print(f"    Priority scan targets : {len(exposed_subdomains)} subdomains")

    if exposed_subdomains:
        print(f"\n  [PRIORITY TARGETS — No CDN protection detected]")
        for sub in exposed_subdomains:
            print(f"    → {sub}")

    return {
        'clusters': clusters,
        'exposed': exposed_subdomains,
        'all_live': [e['subdomain'] for e in live_data]
    }

# ========== STANDALONE TEST ==========
if __name__ == "__main__":
    # For standalone testing — you can hardcode subdomains here
    test_subdomains = [
        "admin.agents.valencia.com",
        "admin.portal.valencia.com",
        "agents.valencia.com",
        "events.valencia.com",
        "www.valencia.com",
    ]
    run_ip_concentration(test_subdomains)
