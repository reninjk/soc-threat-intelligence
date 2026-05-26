# SOC Threat Intelligence

Threat intelligence resources for the Security Operations Centre: feed configurations, IOC watchlists, actor profiles, TI report templates, and automation scripts for feed ingestion.

## Repository Structure

```
soc-threat-intelligence/
├── feeds/                    # Feed source configs and ingestion rules
│   ├── feed-config.yml       # Master feed configuration
│   └── feed-sources.md       # Catalogue of vetted TI sources
├── iocs/                     # IOC management
│   ├── watchlist-template.md # Watchlist format and guidance
│   └── ioc-lifecycle.md      # IOC confidence, ageing, and retirement policy
├── actors/                   # Threat actor profiles
│   └── apt-profile-template.md
├── reports/                  # TI report templates
│   ├── ti-report-template.md
│   └── flash-report-template.md
├── integrations/
│   └── misp-integration-guide.md
├── scripts/
│   └── feed-ingest.py
└── CONTRIBUTING.md
```

## Quick Start

```bash
cd scripts
pip install -r requirements.txt
cp ../.env.example .env   # add your API keys
python feed-ingest.py --source all --output ../iocs/
```

## Feed Sources

| Feed | Type | Refresh | Licence |
|------|------|---------|---------|
| MISP Community | IOCs (STIX 2.1) | Real-time | Free |
| AlienVault OTX | IOCs + Pulses | 15 min | Free |
| Abuse.ch URLhaus | URLs/Domains | 5 min | Free |
| Abuse.ch MalwareBazaar | Hashes | Real-time | Free |
| CISA KEV | CVEs | Daily | Free |
| Recorded Future | All types | Hourly | Paid |

## IOC Confidence Scale

| Level | Score | Action |
|-------|-------|--------|
| Confirmed | 90-100 | Block immediately |
| High | 70-89 | Alert + investigate |
| Medium | 50-69 | Alert + context |
| Low | 30-49 | Monitor only |
| Stale | < 30 | Retire |

## Sensitive Data Policy

- Never commit real IOC data from live incidents
- Templates use placeholder values only — actual IOCs live in the SIEM/TI platform
- API keys belong in `.env` (git-ignored)
- Actor profiles must not include OSINT that could identify individual operators

## Related Repositories

- [soc-detection-rules](https://github.com/reninjk/soc-detection-rules)
- [soc-automation](https://github.com/reninjk/soc-automation)
- [soc-incident-response](https://github.com/reninjk/soc-incident-response)
