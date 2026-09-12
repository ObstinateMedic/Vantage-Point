# Contributing to Vantage Point

Thanks for considering a contribution! This started as a college project and is actively growing — issues and PRs are welcome.

## Getting set up

1. Fork and clone the repo
2. `pip install -r requirements.txt && playwright install chromium`
3. Make sure Docker is running (needed for TruffleHog-dependent phases)

## Ways to contribute

- **Bug fixes** — especially around error handling for flaky sources (crt.sh, HackerTarget, ipinfo.io rate limits)
- **New recon sources** — additional subdomain enumeration sources, ASN lookups, etc.
- **The LLM triage layer** — see the [Roadmap in the README](README.md#-roadmap); this is the most active area of development
- **Performance** — Phases 4/5 currently loop sequentially per target; parallelization PRs are very welcome
- **Docs** — clarifying setup steps, adding example output, etc.

## Pull request guidelines

- Keep PRs focused on one change where possible
- Test your change against at least one real domain before submitting (a domain you own or a public bug-bounty-in-scope target)
- Don't commit anything under `recon_data/` — it's git-ignored for a reason (it can contain real leaked secrets)
- Describe *why* the change is needed, not just *what* changed

## Reporting bugs / requesting features

Open a GitHub issue with:
- What you ran (`python main.py`, or a specific module standalone)
- What you expected vs. what happened
- Python version, OS, and whether Docker/Playwright are set up correctly

## Code of conduct

Be respectful, assume good faith, and keep discussion focused on the project. This tool is for authorized security testing only — contributions that add functionality clearly intended to enable unauthorized access will not be accepted.
