# IOC Watchlist Template

**Watchlist:** [Name — e.g. "Q2 2025 Active C2 Infrastructure"]
**Owner:** [Analyst Name]
**Created:** [Date]
**Expires:** [Date — max 90 days from creation]
**TLP:** WHITE / GREEN / AMBER / RED
**Source:** [Feed name / incident reference / analyst assessment]

---

## How to Use This Template

1. Copy this file to `iocs/active/<watchlist-name>-YYYY-MM-DD.md`
2. Fill in IOCs using the tables below
3. Set an expiry date — all IOCs must have one
4. Submit a PR for peer review before activating in SIEM
5. When expired, move to `iocs/retired/` and note the reason

**Confidence scoring:**

| Score | Meaning |
|-------|---------|
| 90–100 | Confirmed — directly observed or from CISA/government feed |
| 70–89 | High — multiple independent sources |
| 50–69 | Medium — single trusted source |
| 30–49 | Low — single source, unverified |
| < 30 | Stale — expire immediately |

---

## IP Addresses

| IP | Port | Protocol | Confidence | First Seen | Expiry | MITRE Technique | Source | Notes |
|----|------|----------|-----------|-----------|--------|----------------|--------|-------|
| [IP] | [port or *] | [TCP/UDP/*] | [0-100] | [Date] | [Date] | [T####.###] | [Source] | |

---

## Domains

| Domain | Subdomain Pattern | Confidence | First Seen | Expiry | MITRE Technique | Category | Source |
|--------|-------------------|-----------|-----------|--------|----------------|----------|--------|
| [domain.tld] | [*.domain.tld or exact] | [0-100] | [Date] | [Date] | [T####] | [C2/phishing/malware] | |

---

## URLs

| URL | Status Code | Confidence | First Seen | Expiry | MITRE Technique | Category | Source |
|-----|------------|-----------|-----------|--------|----------------|----------|--------|
| [https://...] | [200/301/etc] | [0-100] | [Date] | [Date] | [T####] | | |

---

## File Hashes

| Hash | Type | Filename | File Type | Size (bytes) | Confidence | First Seen | Expiry | Malware Family | MITRE Technique | Source |
|------|------|----------|-----------|-------------|-----------|-----------|--------|---------------|----------------|--------|
| [hash] | MD5/SHA256 | [name.exe] | [PE32/PDF/etc] | | [0-100] | [Date] | [Date] | [Family] | [T####] | |

---

## Email Indicators

| Indicator | Type | Value | Confidence | First Seen | Expiry | Campaign | Source |
|-----------|------|-------|-----------|-----------|--------|----------|--------|
| | Sender domain | | | | | | |
| | Subject pattern | | | | | | |
| | Attachment hash | | | | | | |

---

## CVEs / Vulnerabilities Being Exploited

| CVE | CVSS | Product | Active Exploitation | Patch Available | Confidence | Source |
|-----|------|---------|--------------------|-----------------|-----------|----|
| CVE-YYYY-NNNNN | [score] | [product] | Yes/No | Yes/No | [0-100] | |

---

## MITRE ATT&CK Mapping Summary

| Tactic | Technique ID | Technique Name | IOC Count |
|--------|-------------|---------------|-----------|
| | | | |

---

## Related Intelligence

- **Related incidents:** [IR-YYYY-NNN]
- **Related threat actor:** [Actor name / Unknown]
- **Related Sigma rules:** [rule file links]
- **Related playbooks:** [playbook links]

---

## Retirement / Expiry Log

When retiring this watchlist, add an entry here before moving to `iocs/retired/`:

| Date Retired | Reason | Analyst | Still Active? |
|-------------|--------|---------|---------------|
| | Expired / FP / Resolved | | Yes/No |
