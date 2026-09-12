#!/usr/bin/env python3
"""
SECURITY CHECKS MODULE
Runs basic security posture checks on a domain:
  - DNS Records (A, MX, NS, TXT)
  - SSL Certificate (validity, issuer, expiry)
  - DMARC Policy (email spoofing protection)
  - SPF Record (email sender verification)
  - Security Headers (clickjacking, CSP, HSTS, etc.)
"""

import dns.resolver
import ssl
import socket
import requests
import datetime
from tabulate import tabulate

# Silence SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ========== DNS RECORDS ==========
def check_dns_records(domain):
    """
    Fetches A, MX, NS, TXT, AAAA records.
    These tell us who hosts the domain and handles its email.
    """
    results = {}
    record_types = ['A', 'MX', 'NS', 'TXT', 'AAAA']

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            results[rtype] = ["Domain does not exist"]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except Exception:
            results[rtype] = []

    return results


# ========== SSL CERTIFICATE ==========
def check_ssl(domain):
    """
    Connects to port 443 and reads the SSL certificate.
    Checks: validity, expiry date, issuer (CA).
    """
    result = {
        'valid': False,
        'issuer': 'Unknown',
        'subject': 'Unknown',
        'expiry': 'Unknown',
        'days_left': -1,
        'error': None
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Parse expiry
                expiry_str = cert['notAfter']
                expiry = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.datetime.utcnow()).days

                # Parse issuer
                issuer_dict = dict(x[0] for x in cert['issuer'])
                subject_dict = dict(x[0] for x in cert['subject'])

                result['valid'] = True
                result['issuer'] = issuer_dict.get('organizationName', 'Unknown')
                result['subject'] = subject_dict.get('commonName', domain)
                result['expiry'] = expiry.strftime('%Y-%m-%d')
                result['days_left'] = days_left

    except ssl.SSLCertVerificationError as e:
        result['error'] = f"Certificate invalid: {str(e)[:80]}"
    except ConnectionRefusedError:
        result['error'] = "Port 443 refused — HTTPS may not be running"
    except socket.timeout:
        result['error'] = "Connection timed out"
    except Exception as e:
        result['error'] = f"{type(e).__name__}: {str(e)[:80]}"

    return result


# ========== DMARC CHECK ==========
def check_dmarc(domain):
    """
    DMARC tells email providers what to do with spoofed emails.
    Record lives at: _dmarc.example.com TXT
    
    Policies:
      p=none      → Just monitor, do nothing (weak)
      p=quarantine → Send spoofed emails to spam (medium)
      p=reject    → Block spoofed emails entirely (strong)
    """
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)

        for r in answers:
            txt = str(r).strip('"')
            if 'v=DMARC1' in txt:
                if 'p=reject' in txt:
                    policy = 'reject ✓ (Strong)'
                elif 'p=quarantine' in txt:
                    policy = 'quarantine ⚠ (Medium)'
                elif 'p=none' in txt:
                    policy = 'none ✗ (Weak — monitor only)'
                else:
                    policy = 'unknown'
                return {'found': True, 'policy': policy, 'record': txt[:120]}

    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        pass

    return {
        'found': False,
        'policy': 'MISSING ✗ — domain can be spoofed for phishing!',
        'record': 'No DMARC record found'
    }


# ========== SPF CHECK ==========
def check_spf(domain):
    """
    SPF defines which mail servers are allowed to send email for this domain.
    Lives in TXT records of the root domain.
    
    Mechanisms:
      -all  → Hard fail — only listed servers allowed (strong)
      ~all  → Soft fail — others marked as suspicious (medium)
      +all  → DANGEROUS — anyone can send as this domain
      ?all  → Neutral — no preference
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)

        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith('v=spf1'):
                if '-all' in txt:
                    status = 'Strict ✓ (-all)'
                elif '~all' in txt:
                    status = 'Soft Fail ⚠ (~all)'
                elif '+all' in txt:
                    status = 'DANGEROUS ✗ (+all — anyone can spoof)'
                elif '?all' in txt:
                    status = 'Neutral ⚠ (?all)'
                else:
                    status = 'No "all" mechanism found'
                return {'found': True, 'record': txt[:120], 'status': status}

    except Exception:
        pass

    return {
        'found': False,
        'record': 'No SPF record found',
        'status': 'MISSING ✗ — email sender not verified'
    }


# ========== SECURITY HEADERS ==========
def check_security_headers(domain):
    """
    Checks HTTP response headers that protect against common attacks:
    - HSTS: Forces HTTPS
    - CSP: Prevents XSS
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME sniffing
    - Referrer-Policy: Controls referrer info
    - Permissions-Policy: Controls browser features (camera, mic, etc.)
    """
    headers_to_check = {
        'strict-transport-security': 'HSTS (Force HTTPS)',
        'content-security-policy': 'Content Security Policy (XSS)',
        'x-frame-options': 'Clickjacking Protection',
        'x-content-type-options': 'MIME Sniffing Protection',
        'referrer-policy': 'Referrer Policy',
        'permissions-policy': 'Permissions Policy',
    }

    results = {}

    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=10,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0'},
            allow_redirects=True
        )
        response_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_key, friendly_name in headers_to_check.items():
            present = header_key in response_headers_lower
            results[friendly_name] = {
                'present': present,
                'value': response_headers_lower.get(header_key, 'NOT SET')[:80]
            }

        results['_status_code'] = resp.status_code
        results['_final_url'] = str(resp.url)

    except requests.exceptions.SSLError:
        results['_error'] = 'SSL error — trying HTTP...'
        try:
            resp = requests.get(f"http://{domain}", timeout=10, verify=False,
                              headers={'User-Agent': 'Mozilla/5.0'})
            for name in headers_to_check.values():
                results[name] = {'present': False, 'value': 'NOT SET (HTTP only)'}
        except Exception as e2:
            results['_error'] = f"Both HTTPS and HTTP failed: {e2}"
    except Exception as e:
        results['_error'] = str(e)[:100]

    return results


# ========== DNSSEC CHECK ==========
def check_dnssec(domain):
    """
    DNSSEC prevents DNS cache poisoning attacks.
    Checks for DNSKEY or DS records.
    """
    try:
        dns.resolver.resolve(domain, 'DNSKEY', lifetime=5)
        return {'enabled': True, 'note': 'DNSKEY record found'}
    except:
        pass
    try:
        # Try parent zone DS record
        parts = domain.split('.')
        parent = '.'.join(parts[1:])
        dns.resolver.resolve(f"{parts[0]}.{parent}", 'DS', lifetime=5)
        return {'enabled': True, 'note': 'DS record found in parent zone'}
    except:
        pass
    return {'enabled': False, 'note': 'No DNSSEC records found'}


# ========== PRINT SUMMARY ==========
def print_security_summary(results):
    """Pretty-prints all security check results to terminal"""
    domain = results['domain']

    print(f"\n  ┌─────────────────────────────────────────┐")
    print(f"  │  SECURITY REPORT: {domain[:25]:<25}│")
    print(f"  └─────────────────────────────────────────┘")

    # DNS
    print(f"\n  [DNS RECORDS]")
    for rtype, records in results['dns'].items():
        if records:
            display = ', '.join(records[:2])
            if len(records) > 2:
                display += f" (+{len(records)-2} more)"
            print(f"    {rtype:<6} → {display[:70]}")
        else:
            print(f"    {rtype:<6} → (none)")

    # SSL
    print(f"\n  [SSL CERTIFICATE]")
    ssl_r = results['ssl']
    if ssl_r['valid']:
        days = ssl_r['days_left']
        if days < 0:
            status = "EXPIRED ✗"
        elif days < 14:
            status = f"CRITICAL — expires in {days} days ✗"
        elif days < 30:
            status = f"WARNING — expires in {days} days ⚠"
        else:
            status = f"Valid ✓ ({days} days left)"
        print(f"    Status  : {status}")
        print(f"    Issuer  : {ssl_r['issuer']}")
        print(f"    Expiry  : {ssl_r['expiry']}")
    else:
        print(f"    Status  : INVALID ✗")
        print(f"    Reason  : {ssl_r['error']}")

    # DNSSEC
    print(f"\n  [DNSSEC]")
    dnssec = results['dnssec']
    icon = "✓" if dnssec['enabled'] else "✗"
    print(f"    {icon} {dnssec['note']}")

    # Email Security
    print(f"\n  [EMAIL SECURITY]")
    dmarc = results['dmarc']
    spf = results['spf']
    icon_d = "✓" if dmarc['found'] else "✗"
    icon_s = "✓" if spf['found'] else "✗"
    print(f"    {icon_d} DMARC  : {dmarc['policy']}")
    print(f"    {icon_s} SPF    : {spf['status']}")

    # Security Headers
    print(f"\n  [HTTP SECURITY HEADERS]")
    if '_error' in results['headers']:
        print(f"    Error: {results['headers']['_error']}")
    else:
        for name, data in results['headers'].items():
            if name.startswith('_'):
                continue
            icon = "✓" if data['present'] else "✗"
            print(f"    {icon} {name}")

    print()


# ========== MAIN ENTRY POINT ==========
def run_security_checks(domain):
    """
    Run all checks and return combined results dict.
    Called by main.py orchestrator.
    """
    print(f"\n{'='*60}")
    print(f"PHASE 2: SECURITY CHECKS — {domain}")
    print('='*60)

    results = {'domain': domain}

    print("  [*] Fetching DNS records...")
    results['dns'] = check_dns_records(domain)

    print("  [*] Verifying SSL certificate...")
    results['ssl'] = check_ssl(domain)

    print("  [*] Checking DNSSEC...")
    results['dnssec'] = check_dnssec(domain)

    print("  [*] Checking DMARC policy...")
    results['dmarc'] = check_dmarc(domain)

    print("  [*] Checking SPF record...")
    results['spf'] = check_spf(domain)

    print("  [*] Checking HTTP security headers...")
    results['headers'] = check_security_headers(domain)

    print_security_summary(results)

    return results


# ========== STANDALONE TEST ==========
if __name__ == "__main__":
    domain = input("Enter domain to check: ").strip()
    run_security_checks(domain)