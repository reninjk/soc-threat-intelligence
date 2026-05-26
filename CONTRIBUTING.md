# Contributing to soc-threat-intelligence

Thank you for contributing to the SOC's threat intelligence capability. This repository contains feed configurations, IOC watchlist templates, actor profiles, report templates, and integration guides.

## What Belongs Here

- Feed configuration updates (new sources, filter adjustments)
- IOC watchlist template improvements
- Actor profile additions or updates (using public OSINT only)
- TI report and flash report template revisions
- Integration guides for TI tools and platforms
- Scripts for feed ingestion and processing

## What Does Not Belong Here

- **Real IOC data from live incidents** — operational IOCs belong in your TI platform, not this repo
- API keys, authentication tokens, or credentials of any kind
- IOCs that could identify specific victims or internal infrastructure
- OSINT data that could identify individual threat actor operators (PII)
- TLP:RED or TLP:AMBER content (this repo is accessible to the broader team)
- Vendor intelligence that has a redistribution restriction

## Contribution Process

1. **Open an issue** for any new actor profile or major template change
2. Branch naming: `feat/actor-name`, `fix/feed-config`, `docs/report-template`
3. Submit a PR and complete the PR template
4. Actor profiles require senior analyst review — confirm all data is from public sources
5. Integration guides require testing confirmation before merge

## Data Sensitivity Rules

- All IOC values in templates must be clearly marked as placeholders: `[HASH-PLACEHOLDER]`, `198.51.100[.]x`
- Defang all domains and IPs in documentation using `[.]` notation
- Actor profiles must cite public sources (vendor blogs, government advisories, academic papers)
- Never include internal incident ticket numbers, asset names, or employee data

## Commit Messages

```
feat: add actor profile template for FIN-style groups
fix: update feed-config TLP filter to exclude RED
docs: add TAXII 2.1 section to misp-integration-guide
chore: rotate example API key placeholders
```

## Questions

Raise a GitHub Discussion or contact the TI lead through the internal SOC channel.
