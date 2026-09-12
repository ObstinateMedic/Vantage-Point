#!/usr/bin/env python3
"""
SUBDOMAIN ENUMERATOR
Uses crt.sh (certificate transparency logs) + HackerTarget as backup
No API key required for either source
"""

import requests
import json

# Silence SSL warnings (common in recon tools)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ========== SOURCE 1: CRT.SH ==========
def get_subdomains_crtsh(domain):
    """
    Queries crt.sh certificate transparency database.
    When anyone gets an SSL cert for *.example.com, it's logged here publicly.
    """
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; ThreatIntelScanner/1.0)'}
        
        resp = requests.get(url, timeout=30, headers=headers)
        
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                # crt.sh returns multiple names per cert (SAN field)
                name_value = entry.get('name_value', '')
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    # Filter: must be subdomain of target, no wildcards
                    if name.endswith(f'.{domain}') and '*' not in name:
                        subdomains.add(name)
        else:
            print(f"    [crt.sh] HTTP {resp.status_code}")
            
    except requests.exceptions.Timeout:
        print("    [crt.sh] Timeout — server took too long")
    except Exception as e:
        print(f"    [crt.sh] Error: {e}")

    return list(subdomains)


# ========== SOURCE 2: HACKERTARGET ==========
def get_subdomains_hackertarget(domain):
    """
    Queries HackerTarget free API.
    Returns up to 100 subdomains on free tier — good enough for college project.
    """
    subdomains = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=30)
        
        if resp.status_code == 200:
            text = resp.text.strip()
            
            # HackerTarget returns "error" messages as plain text
            if 'error' in text.lower() or 'API count' in text:
                print(f"    [HackerTarget] Rate limited or error: {text[:60]}")
                return []
            
            # Format: "subdomain.example.com,1.2.3.4" per line
            for line in text.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub.endswith(f'.{domain}'):
                        subdomains.add(sub)
        else:
            print(f"    [HackerTarget] HTTP {resp.status_code}")
            
    except Exception as e:
        print(f"    [HackerTarget] Error: {e}")

    return list(subdomains)


# ========== MAIN FUNCTION ==========
def enumerate_subdomains(domain):
    """
    Main entry point — combines all sources and deduplicates.
    Called by main.py with just the root domain (e.g. 'example.com')
    """
    print(f"\n{'='*60}")
    print(f"PHASE 1: SUBDOMAIN ENUMERATION — {domain}")
    print('='*60)

    all_subdomains = set()

    # --- Source 1 ---
    print("  [*] Querying crt.sh (certificate transparency)...")
    crt_results = get_subdomains_crtsh(domain)
    all_subdomains.update(crt_results)
    print(f"  [+] crt.sh found: {len(crt_results)} subdomains")

    # --- Source 2 ---
    print("  [*] Querying HackerTarget...")
    ht_results = get_subdomains_hackertarget(domain)
    all_subdomains.update(ht_results)
    print(f"  [+] HackerTarget found: {len(ht_results)} subdomains")

    # Sort alphabetically for clean output
    final_list = sorted(list(all_subdomains))

    print(f"\n  [RESULT] Total unique subdomains discovered: {len(final_list)}")
    for sub in final_list:
        print(f"    → {sub}")

    return final_list


# ========== STANDALONE TEST ==========
if __name__ == "__main__":
    domain = input("Enter domain to enumerate: ").strip()
    results = enumerate_subdomains(domain)
    print(f"\nFinal list ({len(results)} subdomains):")
    for r in results:
        print(f"  {r}")