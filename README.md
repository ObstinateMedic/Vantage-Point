# 🎯 Vantage Point

**An automated threat-intelligence & attack-surface recon pipeline** — enumerate subdomains, fingerprint infrastructure, and hunt for leaked secrets in both live and historical JS/config bundles.

Built as a bug-bounty recon tool. Runs one command, walks a target domain through five phases, and outputs a structured JSON and PDF report.

```
Domain in  →  Subdomains  →  Security Posture  →  Infra Clustering  →  Live Secret Scan  →  Wayback Secret Scan  →  Report out
```

---

## ✨ Features

| Phase | Module | What it does |
|-------|--------|---------------|
| 1 | `subdomain_enum.py` | Passive subdomain enumeration via **crt.sh** (certificate transparency) + **HackerTarget** — no API keys needed |
| 2 | `security_checks.py` | DNS records, SSL cert validity/expiry, DNSSEC, DMARC, SPF, and HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) |
| 3 | `ipconc2.py` | Resolves every subdomain, clusters by shared IP, and classifies each cluster as **CDN-protected** vs **exposed origin** via CNAME, ASN/org lookup, and response headers |
| 4 | `LiveScan.py` | Headless-browser crawl (Playwright) of prioritized targets, sniffs all `.js/.json/.xml/.env/.yml` network requests, downloads them, and runs **TruffleHog** against the haul |
| 5 | `WaybackScan.py` | Pulls historical `.js/.json/.env/.config` assets for the same targets from the **Wayback Machine CDX API**, downloads them, and runs **TruffleHog** again — catching secrets devs forgot to rotate after removal |
| — | `main.py` | Orchestrates all five phases, prioritizes exposed-origin subdomains for the expensive deep-scan phases, and writes a final structured report |

### Smart targeting
Rather than deep-scanning every subdomain (slow, noisy), the orchestrator uses Phase 3's infrastructure analysis to prioritize **exposed origins first** — servers with no CDN in front of them are the highest-value, most realistic attack surface.

### Planned: LLM triage layer 🚧
Currently integrating an LLM-based triage layer (via API) that will:
- Summarize raw TruffleHog findings into a human-readable vulnerability report
- Flag likely **false positives** (test keys, placeholder secrets, revoked tokens)
- Cut down manual review time by pre-sorting findings by likely severity

This lives on the `llm-triage` branch / is tracked in [Roadmap](#-roadmap) below.

---

## 🗂 Project Structure

```
vantage-point/
├── main.py                # Orchestrator — entry point
├── subdomain_enum.py       # Phase 1: crt.sh + HackerTarget
├── security_checks.py      # Phase 2: DNS/SSL/DMARC/SPF/headers
├── ipconc2.py               # Phase 3: IP clustering + CDN detection
├── LiveScan.py              # Phase 4: Playwright crawl + TruffleHog
├── WaybackScan.py           # Phase 5: Wayback CDX + TruffleHog
├── config.yaml.example      # Optional TruffleHog detector config
├── requirements.txt
├── .gitignore
├── LICENSE
└── recon_data/               # Output dir (git-ignored, created at runtime)
    └── <domain>/
        ├── final_report.json
        ├── leaks_found_live.txt
        ├── leaks_found_wayback.txt
        ├── live/              # downloaded live assets
        └── wayback/           # downloaded historical assets
```

---

## ⚙️ Prerequisites

- **Python 3.9+**
- **Docker** — TruffleHog runs as a container (`trufflesecurity/trufflehog:latest`); make sure the Docker daemon is running before a scan
- **Playwright browsers** — installed separately after the pip install (see below)

--- 

## 🚀 Installation

```bash
git clone https://github.com/ObstinateMedic/vantage-point.git
cd vantage-point

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
playwright install chromium

# Pull the TruffleHog image ahead of time (optional, saves time on first scan)
docker pull trufflesecurity/trufflehog:latest
```

---

## ▶️ Usage

```bash
python main.py
```

You'll be prompted for a target domain and a confirmation before the scan starts:

```
Enter the target domain (e.g. example.com)
Do NOT include http:// or www

  Domain: example.com

[✓] Target confirmed: example.com
[✓] Results will be saved to: recon_data/example.com/
[✓] Docker must be running for TruffleHog to work

Start scan? (y/n): y
```

Each phase prints live progress to the terminal. At the end you get:

- `recon_data/<domain>/final_report.json` — full structured report (subdomains, security posture, IP clusters, deep-scan targets)
- `recon_data/<domain>/leaks_found_live.txt` — secrets found in live JS/config bundles
- `recon_data/<domain>/leaks_found_wayback.txt` — secrets found in historical/archived bundles

### Custom TruffleHog detectors
Drop a `config.yaml` (see `config.yaml.example`) in the project root to scope TruffleHog to specific detectors — otherwise it runs with all default detectors enabled.

### Running a single phase standalone
Every module can be run on its own for testing:

```bash
python subdomain_enum.py      # prompts for a domain
python security_checks.py     # prompts for a domain
python LiveScan.py            # edit the `targets` list at the bottom of the file
python WaybackScan.py         # edit the `targets` list at the bottom of the file
```

---

## 🧩 Tech Stack

- **httpx / requests** — async & sync HTTP
- **dnspython** — DNS record resolution (A/MX/NS/TXT/AAAA/CNAME/DNSKEY/DS)
- **Playwright** — headless Chromium for live-site crawling & network sniffing
- **TruffleHog** (via Docker) — secret detection engine
- **tabulate** — clean terminal reporting
- **crt.sh** / **HackerTarget** — passive subdomain enumeration sources
- **Wayback Machine CDX API** — historical asset discovery
- **ipinfo.io** — ASN/org lookups for CDN vs. origin classification

---

## 🗺 Roadmap

- [ ] LLM-based finding triage & false-positive flagging (API call layer)
- [ ] Auto-generated human-readable Markdown/PDF vulnerability report per scan
- [ ] Rate-limit/backoff handling for crt.sh and HackerTarget under heavy use
- [ ] Parallelize Phase 4/5 across targets instead of sequential looping
- [ ] Optional Shodan/Censys integration for Phase 3
- [ ] Config file for scan parameters (max deep-scan targets, timeouts, etc.) instead of hardcoded constants

---

## ⚠️ Responsible Use

This tool is built for **authorized security testing only** — bug bounty programs you're enrolled in, CTFs, and domains/infrastructure you own or have explicit written permission to test.

- Only run this against targets covered by a bug bounty program's scope or your own infrastructure.
- Respect `robots.txt`, rate limits, and each service's terms of use (crt.sh, HackerTarget, Wayback Machine, ipinfo.io).
- Do not use findings to access systems or data you are not authorized to access — report leaked secrets through the program's responsible disclosure process.
- The maintainers are not responsible for misuse of this tool.

---

## 🤝 Contributing

Pull requests are welcome. For larger changes, please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push to the branch and open a PR

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
