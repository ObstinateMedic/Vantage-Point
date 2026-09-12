#!/usr/bin/env python3
"""
WAYBACK MACHINE SECURITY SCANNER
Fetches historical assets from Wayback Machine and scans for leaked secrets.

Changes from original:
- main() no longer has hardcoded targets
- scan_wayback() is importable by orchestrator
- Added better error handling and comments
"""

import asyncio
import os
import httpx
import subprocess
import json
import re

RESULTS_DIR = "recon_data"


# ========== CONTEXT EXTRACTION ==========
def extract_context(file_path, secret):
    """Extracts the variable/key name before a secret"""
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
    """Runs TruffleHog via Docker to find secrets in downloaded wayback files"""
    target_dir = os.path.abspath(os.path.join(RESULTS_DIR, subdomain, "wayback"))
    config_file = os.path.abspath("config.yaml")
    leak_file = os.path.join(RESULTS_DIR, subdomain, "leaks_found_wayback.txt")

    if not os.path.exists(target_dir):
        print(f"    [ERROR] Directory not found: {target_dir}")
        return

    print(f"\n    [AUDIT] Scanning wayback files for secrets...")

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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        if proc.stdout:
            lines = [line for line in proc.stdout.strip().split('\n') if line.strip()]

            if len(lines) == 0:
                print(f"    [INFO] No secrets detected in wayback files")
                return

            print(f"    [FOUND] {len(lines)} potential secrets detected")

            with open(leak_file, "w") as f:
                f.write(f"--- WAYBACK LEAK REPORT: {subdomain} ---\n\n")

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

            print(f"    [SUCCESS] Wayback report saved: {leak_file}")
        else:
            print(f"    [INFO] TruffleHog returned no output — no secrets found")

    except subprocess.TimeoutExpired:
        print(f"    [ERROR] TruffleHog timed out after 180s")
    except FileNotFoundError:
        print(f"    [ERROR] Docker not found — is Docker running?")
    except Exception as e:
        print(f"    [ERROR] Audit failed: {e}")


# ========== WAYBACK CDX FETCHER ==========
async def get_wayback_urls(subdomain):
    """
    Queries Wayback Machine CDX API for historical URLs.
    CDX = Capture inDex — archive.org's search API for crawled pages.
    
    We look for .js, .json, .xml, .env etc. from years past.
    Old files often have API keys that devs forgot to rotate!
    """
    print(f"    [CDX] Querying Wayback Machine for {subdomain}...")
    wayback_urls = []

    patterns = [
        f"{subdomain}/*",
        f"*.{subdomain}/*",
        f"www.{subdomain}/*"
    ]

    for pattern in patterns:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?"
            f"url={pattern}&"
            f"output=json&"
            f"fl=original,timestamp&"
            f"collapse=urlkey&"
            f"filter=statuscode:200&"
            f"limit=10000"
        )

        print(f"    [CDX] Trying pattern: {pattern}")

        async with httpx.AsyncClient(verify=True, timeout=60.0) as client:
            try:
                response = await client.get(cdx_url)

                if response.status_code == 200:
                    data = response.json()

                    if len(data) > 1:
                        print(f"    [CDX] Found {len(data)-1} archived URLs")

                        for row in data[1:]:  # Skip header row
                            original_url = row[0]
                            timestamp = row[1]

                            if any(ext in original_url.lower() for ext in
                                   ['.js', '.json', '.xml', '.env', '.config', '.yml', '.yaml']):
                                archive_url = f"https://web.archive.org/web/{timestamp}id_/{original_url}"
                                wayback_urls.append(archive_url)

                        if wayback_urls:
                            break

            except Exception as e:
                print(f"    [CDX] Error for {pattern}: {str(e)[:60]}")
                continue

    unique_urls = list(set(wayback_urls))
    print(f"    [CDX] Unique historical assets found: {len(unique_urls)}")
    return unique_urls


# ========== ASSET DOWNLOADER ==========
async def download_wayback_asset(client, url, subdomain):
    """Downloads a single historical asset from Wayback Machine"""
    try:
        clean_url = re.sub(r'https?://web\.archive\.org/web/\d+id_/', '', url)
        clean_name = clean_url.split("/")[-1].split("?")[0]

        if not clean_name or len(clean_name) > 80:
            ext = "js" if ".js" in clean_url else "json" if ".json" in clean_url else "txt"
            clean_name = f"wayback_{abs(hash(url)) % 1000000}.{ext}"

        sub_path = os.path.join(RESULTS_DIR, subdomain, "wayback")
        os.makedirs(sub_path, exist_ok=True)
        file_path = os.path.join(sub_path, clean_name)

        if os.path.exists(file_path):
            return file_path  # Skip already downloaded

        resp = await client.get(url, timeout=30.0, follow_redirects=True)

        if resp.status_code == 200:
            content = resp.content

            if len(content) < 100:
                return None

            if b"Wayback Machine has not archived that URL" in content:
                return None

            with open(file_path, "wb") as f:
                f.write(content)
            return file_path

    except Exception:
        return None


# ========== WAYBACK SCANNER ==========
async def scan_wayback(subdomain):
    """
    Main function — fetches and scans historical assets.
    Called by orchestrator with a subdomain string.
    """
    print(f"\n{'='*60}")
    print(f"PHASE 5: WAYBACK SCAN — {subdomain}")
    print('='*60)

    historical_urls = await get_wayback_urls(subdomain)

    if not historical_urls:
        print(f"\n  [INFO] No historical assets found for {subdomain}")
        return

    print(f"\n  [DOWNLOAD] Downloading {len(historical_urls)} historical assets...")

    downloaded_count = 0
    async with httpx.AsyncClient(verify=True, timeout=30.0) as client:
        batch_size = 20
        for i in range(0, len(historical_urls), batch_size):
            batch = historical_urls[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(historical_urls) - 1) // batch_size + 1

            print(f"    [BATCH {batch_num}/{total_batches}] Processing {len(batch)} files...")

            tasks = [download_wayback_asset(client, url, subdomain) for url in batch]
            results = await asyncio.gather(*tasks)

            downloaded_count += sum(1 for r in results if r is not None)

            if i + batch_size < len(historical_urls):
                await asyncio.sleep(2)  # Rate limit — be polite to archive.org

    print(f"\n  [DOWNLOAD] Saved {downloaded_count}/{len(historical_urls)} wayback files")

    if downloaded_count > 0:
        run_security_audit(subdomain)
    else:
        print(f"\n  [WARNING] No files downloaded — nothing to audit")


# ========== STANDALONE TEST ==========
async def main():
    """
    Standalone test — edit targets to test this file alone.
    When used via orchestrator (main.py), this block is NOT called.
    """
    targets = ["example.com"]  # ← Edit for standalone testing

    os.makedirs(RESULTS_DIR, exist_ok=True)
    for target in targets:
        await scan_wayback(target)


if __name__ == "__main__":
    asyncio.run(main())