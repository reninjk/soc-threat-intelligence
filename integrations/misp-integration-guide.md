# MISP Integration Guide

## Overview
This guide covers the SOC's integration with MISP (Malware Information Sharing Platform) for automated IOC ingestion, event sharing, and correlation with internal alerts.

---

## Architecture

```
External MISP Feeds
       |
       v
  [MISP Instance] <---> [PyMISP / feed-ingest.py] <---> [TI Platform]
       |                                                      |
       v                                                      v
  IOC Watchlist                                         SIEM Correlation
  (iocs/watchlist-template.md)                         (soc-automation)
```

---

## Prerequisites

- MISP instance accessible at your internal URL
- API key stored in `.env` as `MISP_API_KEY` (never hardcoded)
- Python 3.10+ with PyMISP installed: `pip install pymisp`
- Network path from the integration host to MISP API port (default: 443)

---

## Configuration

### Environment Variables
Add to your `.env` file (never commit this file):
```
MISP_URL=https://misp.internal.example.com
MISP_API_KEY=your-api-key-here
MISP_VERIFY_SSL=true
```

### Feed Configuration
Feed sources are defined in `feeds/feed-config.yml`. Each feed entry includes:
- Feed URL or MISP server URL
- TLP level filter (only ingest up to TLP:AMBER by default)
- IOC type filter (ip, domain, url, hash — configure per use case)
- Confidence threshold (minimum score to import)

---

## Using feed-ingest.py

The ingestion script is at `scripts/feed-ingest.py`.

### Run manually
```bash
# Activate your virtual environment first
source venv/bin/activate

# Ingest from all configured feeds
python scripts/feed-ingest.py

# Ingest specific IOC type only
python scripts/feed-ingest.py --type domain

# Dry run (no writes — preview only)
python scripts/feed-ingest.py --dry-run
```

### Scheduled ingestion
The GitHub Actions workflow at `.github/workflows/validate.yml` runs ingestion on schedule.
For production, run as a cron job on your integration server:
```bash
# Every 4 hours
0 */4 * * * /path/to/venv/bin/python /path/to/scripts/feed-ingest.py >> /var/log/ti-ingest.log 2>&1
```

---

## MISP Event Workflow

### Consuming events from MISP
1. Script polls MISP for events published in the last N hours
2. Filters by: TLP level, distribution level, minimum threat level
3. Extracts attributes (IOC values + type)
4. Deduplicates against existing watchlist
5. Appends new IOCs to `iocs/watchlist-template.md` (operational watchlist lives in TI platform)
6. Pushes IOCs to SIEM via API for correlation

### Publishing events to MISP
When the SOC observes new IOCs from an internal incident:
1. Create a new MISP event via the web UI or PyMISP
2. Set distribution: **Your Organisation Only** initially
3. Set TLP tag: amber or green depending on sensitivity
4. Add attributes (IOC values with type and context)
5. After CISO approval, promote to ISAC sharing level

**Do not publish:**
- IOCs that could identify your organisation's infrastructure
- Data that reveals internal detection capabilities
- Anything above TLP:AMBER without explicit CISO sign-off

---

## IOC Types Reference

| MISP Type | Our Classification | Example |
|-----------|-------------------|---------|
| ip-dst | ip | 198.51.100.1 |
| domain | domain | evil-domain.net |
| url | url | https://evil.net/path |
| md5 | md5_hash | d41d8cd98f00... |
| sha256 | sha256_hash | e3b0c44298fc... |
| vulnerability | cve | CVE-2024-XXXXX |

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| `AuthError: Invalid API key` | Wrong key in .env | Rotate key in MISP user profile |
| `SSL verification failed` | Self-signed cert | Set `MISP_VERIFY_SSL=false` for internal instances only |
| `0 events ingested` | TLP filter too restrictive | Lower minimum TLP in feed-config.yml |
| Script hangs | MISP timeout | Check network path; increase timeout in config |
| Duplicate IOCs in watchlist | Dedup logic failed | Check hash of existing entries; rebuild watchlist index |

---

## Security Notes

- The MISP API key is equivalent to a privileged credential — rotate every 90 days
- Store only in `.env` or secrets manager — never in code, logs, or this repository
- Audit MISP access logs monthly for unexpected queries
- IOCs ingested from external feeds must be validated before deploying as production blocks
- TLP:RED IOCs must never be shared or stored in systems without strict access controls

---

## References
- PyMISP documentation: https://pymisp.readthedocs.io/
- MISP Project: https://www.misp-project.org/
- TLP definitions: https://www.cisa.gov/tlp
- feed-ingest.py: scripts/feed-ingest.py
