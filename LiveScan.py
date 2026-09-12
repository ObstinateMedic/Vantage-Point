#!/usr/bin/env python3
"""
LIVE SITE SECURITY SCANNER
Crawls live websites and scans for leaked secrets using TruffleHog.

Changes from original:
- main() no longer has hardcoded targets
- scan_live_site() is importable by orchestrator
- Added better error handling
"""

import asyncio
import os
import httpx
import subprocess
import json
import re
from playwright.async_api import async_playwright

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESULTS_DIR = "recon_data"


# ========== ASSET SNIFFER ==========
def asset_sniffer(request, storage_list):
    """Captures interesting assets from page requests"""
    url = request.url
    extensions = [".js", ".json", ".xml", ".env", ".config", ".yml", ".yaml"]

    if any(ext in url.lower() for ext in extensions):
        if url not in storage_list:
            storage_list.append(url)
            print(f"    [CAPTURED] {url}")


# ========== CONTEXT EXTRACTION ==========
def extract_context(file_path, secret):
    """Extracts the variable/key name before a secret for better reporting"""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            pattern = rf'([a-zA-Z0-9_\-\.]{{2,40}})[\s\=\:\"\'\>]{{1,10}}{re.escape(secret)}'
            match = re.search(pattern, content)
            return match.group(1).strip() if match else "CONTEXT_NOT_FOUND"
    except Exception:
        return "ERROR"


# ========== TRUFFLEHOG AUDIT ==========
def run_security_audit(subdomain):
    """Runs TruffleHog via Docker to find secrets in downloaded files"""
    target_dir = os.path.abspath(os.path.join(RESULTS_DIR, subdomain, "live"))
    config_file = os.path.abspath("config.yaml")
    leak_file = os.path.join(RESULTS_DIR, subdomain, "leaks_found_live.txt")

    if not os.path.exists(target_dir):
        print(f"    [ERROR] Directory not found: {target_dir}")
        return

    print(f"\n    [AUDIT] Scanning for secrets in live files...")

    if os.path.exists(config_file):
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_dir}:/pwd",
            "-v", f"{config_file}:/config.yaml",
            "trufflesecurity/trufflehog:latest",
            "filesystem", "/pwd", "--config=/config.yaml", "--json", "--no-update"
        ]
    else:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_dir}:/pwd",
            "trufflesecurity/trufflehog:latest",
            "filesystem", "/pwd", "--json", "--no-update"
        ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if proc.stdout:
            lines = [line for line in proc.stdout.strip().split('\n') if line.strip()]

            if len(lines) == 0:
                print(f"    [INFO] No secrets detected in live files")
                return

            print(f"    [FOUND] {len(lines)} potential secrets detected")

            with open(leak_file, "w") as f:
                f.write(f"--- LIVE LEAK REPORT: {subdomain} ---\n\n")

                for line in lines:
                    try:
                        item = json.loads(line)
                        secret = item.get('Raw', 'NO_SECRET')
                        detector = item.get('DetectorName', 'UNKNOWN')

                        source_metadata = item.get('SourceMetadata', {})
                        data = source_metadata.get('Data', {})
                        filesystem = data.get('Filesystem', {})
                        container_file = filesystem.get('file', '')

                        local_filename = container_file.replace('/pwd/', '') if container_file else 'UNKNOWN'
                        full_local_path = os.path.join(target_dir, local_filename)

                        context_key = extract_context(full_local_path, secret)

                        f.write(f"KEY_NAME : {context_key}\n")
                        f.write(f"DETECTOR : {detector}\n")
                        f.write(f"FILE     : {local_filename}\n")
                        f.write(f"SECRET   : {secret}\n")
                        f.write("-" * 30 + "\n")
                    except Exception:
                        continue

            print(f"    [SUCCESS] Report saved: {leak_file}")
        else:
            print(f"    [INFO] TruffleHog returned no output — no secrets found")

    except subprocess.TimeoutExpired:
        print(f"    [ERROR] TruffleHog timed out after 120s")
    except FileNotFoundError:
        print(f"    [ERROR] Docker not found — is Docker running?")
    except Exception as e:
        print(f"    [ERROR] Audit failed: {e}")


# ========== ASSET DOWNLOADER ==========
async def download_asset(client, url, subdomain):
    """Downloads a single asset from the live site"""
    try:
        clean_name = url.split("/")[-1].split("?")[0]
        if not clean_name or len(clean_name) > 80:
            ext = "js" if ".js" in url else "json" if ".json" in url else "txt"
            clean_name = f"asset_{abs(hash(url)) % 1000000}.{ext}"

        sub_path = os.path.join(RESULTS_DIR, subdomain, "live")
        os.makedirs(sub_path, exist_ok=True)
        file_path = os.path.join(sub_path, clean_name)

        resp = await client.get(url, timeout=20.0, follow_redirects=True)

        if resp.status_code == 200 and len(resp.content) > 0:
            with open(file_path, "wb") as f:
                f.write(resp.content)
            return file_path
    except Exception:
        return None


# ========== LIVE CRAWLER ==========
async def scan_live_site(subdomain):
    """
    Main function — crawls a live website and captures assets.
    Called by orchestrator with a subdomain string.
    """
    print(f"\n{'='*60}")
    print(f"PHASE 4: LIVE SCAN — {subdomain}")
    print('='*60)

    captured_assets = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            viewport={'width': 1920, 'height': 1080},
            ignore_https_errors=True
        )
        page = await context.new_page()

        page.on("request", lambda req: asset_sniffer(req, captured_assets))

        try:
            print(f"\n  [BROWSER] Navigating to https://{subdomain}...")
            await page.goto(f"https://{subdomain}", wait_until="domcontentloaded", timeout=60000)

            print(f"  [BROWSER] Scrolling to trigger lazy-loaded assets...")
            for i in range(4):
                await page.mouse.wheel(0, (i + 1) * 800)
                await asyncio.sleep(2)

            await asyncio.sleep(15)
            print(f"  [BROWSER] Asset capture complete")

        except Exception as e:
            print(f"  [WARNING] Browser issue: {e}")
        finally:
            await browser.close()

    print(f"\n  [SUMMARY] Captured {len(captured_assets)} assets")

    if captured_assets:
        print(f"\n  [DOWNLOAD] Downloading captured assets...")

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            tasks = [download_asset(client, url, subdomain) for url in captured_assets]
            results = await asyncio.gather(*tasks)
            successful = sum(1 for r in results if r is not None)
            print(f"  [DOWNLOAD] Saved {successful}/{len(captured_assets)} files")

        run_security_audit(subdomain)

    else:
        print(f"\n  [WARNING] No assets captured for {subdomain}")


# ========== STANDALONE TEST ==========
async def main():
    """
    Standalone test — edit targets list to test this file alone.
    When used via orchestrator (main.py), this block is NOT called.
    """
    targets = ["example.com"]  # ← Edit for standalone testing

    os.makedirs(RESULTS_DIR, exist_ok=True)
    for target in targets:
        await scan_live_site(target)


if __name__ == "__main__":
    asyncio.run(main())