# Threat Intel Scraper

Multi-platform threat intelligence collector that scrapes security researchers' posts from X/Twitter, Telegram, Reddit, and LinkedIn — then extracts IOCs, maps MITRE ATT&CK techniques, and outputs structured data for the security-research blog.

## Architecture

```
threat-intel-scraper/
├── scraper.py              # CLI entry point
├── config.yaml             # Default config (copy to config.local.yaml)
├── requirements.txt
├── extractors/
│   ├── ioc_extractor.py    # Regex-based IOC extraction (IP, hash, domain, URL, CVE)
│   └── mitre_mapper.py     # Keyword → ATT&CK technique mapping
├── scrapers/
│   ├── base.py             # Abstract base scraper
│   ├── twitter.py          # X/Twitter (API v2 + Nitter RSS fallback)
│   ├── telegram.py         # Telegram channels (Telethon)
│   ├── reddit.py           # Reddit subreddits + users (PRAW)
│   └── linkedin.py         # LinkedIn (RSS feeds + manual export)
└── outputs/
    ├── csv_writer.py       # IOC CSV (repo + blog format)
    ├── stix_writer.py      # STIX 2.1 bundles
    ├── markdown_writer.py  # Summary reports + blog drafts
    └── json_archive.py     # Raw post archive
```

## Quick Start

```bash
cd tools/threat-intel-scraper

# Install dependencies
pip install -r requirements.txt

# Copy and edit config
cp config.yaml config.local.yaml
# Edit config.local.yaml with your API keys

# Test connections
python scraper.py test

# Run a full scrape
python scraper.py scrape

# Scrape single platform
python scraper.py scrape --platform reddit --limit 25

# Generate a blog draft from the scrape
python scraper.py scrape --draft --campaign "aitm-campaign"

# Extract IOCs from a previously saved archive
python scraper.py extract --input output/archive/archive-daily-intel-20260428T120000.json

# Generate a report from an archive
python scraper.py report --input output/archive/archive-daily-intel-20260428T120000.json
```

## Platform Setup

### X / Twitter

**Option A — API v2 (recommended):**
1. Apply at [developer.x.com](https://developer.x.com)
2. Create a project → get Bearer Token
3. Set `twitter.mode: "api"` and `twitter.bearer_token` in config

**Option B — Nitter RSS (no auth):**
1. Set `twitter.mode: "nitter"` in config
2. Optionally set `twitter.nitter_instance` to a working Nitter instance
3. Note: Nitter instances frequently go down — check [status](https://status.d420.de)

### Telegram

1. Go to [my.telegram.org/apps](https://my.telegram.org/apps)
2. Create application → note `api_id` and `api_hash`
3. Set `telegram.api_id`, `telegram.api_hash`, and `telegram.phone` in config
4. First run will prompt for a verification code

### Reddit

1. Go to [reddit.com/prefs/apps](https://www.reddit.com/prefs/apps)
2. Create a **script** type application
3. Note the `client_id` (shown under app name) and `client_secret`
4. Set `reddit.client_id` and `reddit.client_secret` in config

### LinkedIn

LinkedIn has no public post-reading API. Two approaches:

**Option A — RSS feeds:**
1. Use a service like [rss.app](https://rss.app) to create RSS feeds from LinkedIn profiles
2. Add feed URLs to `linkedin.feeds` in config

**Option B — Manual exports:**
1. Copy/paste posts into `.txt` files in a folder
2. Format: line 1 = author, line 2 = date (YYYY-MM-DD), rest = content
3. Set `linkedin.mode: "manual"` and `linkedin.manual_dir` in config

## Output

Each scrape run produces:

| Output | Location | Format |
|--------|----------|--------|
| IOC feed | `iocs/<campaign>/` | CSV + STIX 2.1 JSON |
| Blog IOC table | `docs/_data/iocs/<campaign>/` | CSV (for `{% include ioc-table.html %}`) |
| Summary report | `output/reports/` | Markdown |
| Blog draft | `docs/_drafts/` | Markdown with Jekyll front matter |
| Raw archive | `output/archive/` | JSON |

## IOC Extraction

The extractor identifies:
- **Network:** IPv4, IPv6, domains, URLs, email addresses
- **File hashes:** MD5, SHA1, SHA256
- **Identifiers:** CVE IDs
- **Crypto:** Bitcoin and Ethereum addresses

Both fanged (`192.168.1.1`) and defanged (`192.168.1[.]1`) formats are recognized. Output is always defanged for safe handling.

## MITRE ATT&CK Mapping

The mapper uses a curated keyword-to-technique lookup covering 40+ Enterprise ATT&CK techniques across all tactics. Matches are scored by confidence (high/medium/low) based on keyword specificity and count.

## Security Notes

- **Never commit `config.local.yaml`** — it contains API keys
- The `.gitignore` should exclude `config.local.yaml` and `output/`
- All IOCs are defanged in reports and CSV output
- Telegram session files (`*.session`) contain auth tokens — keep them private

## License

MIT — see repository root LICENSE.
