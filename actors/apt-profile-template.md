# Threat Actor Profile Template

> Copy to `actors/<actor-name>.md`. Replace all placeholders. Never include real operator identities.

---

# [Actor Name / Alias]

**Profile ID:** TA-[YYYY]-[NNN]
**Classification:** Nation-State / Cybercriminal / Hacktivist / Unknown
**Attributed Nexus:** [Country / Unknown]
**Active Since:** [Year]
**Last Observed:** [Date]
**Confidence in Attribution:** High / Medium / Low / Unattributed
**TLP:** AMBER

---

## Aliases

| Alias | Source Organisation |
|-------|-------------------|
| [Primary name] | [Vendor] |
| [Alt name] | [Vendor] |

---

## Executive Summary

> 3–5 sentences describing who this actor is, what they want, and why they matter to your organisation.

---

## Targeting Profile

### Industries Targeted

| Industry | Frequency | Notes |
|----------|-----------|-------|
| Financial Services | High | |
| Government | High | |
| Defence | Medium | |
| Energy / Utilities | Medium | |

### Geographic Focus

| Region | Priority | Notes |
|--------|----------|-------|
| | High/Med/Low | |

### Assessed Motivation

- [ ] Espionage / Intelligence collection
- [ ] Financial gain / Ransomware
- [ ] Sabotage / Destructive
- [ ] Hacktivism / Ideological
- [ ] Supply chain access
- [ ] Unknown

---

## MITRE ATT&CK Coverage

### Tactics and Techniques

| Tactic | Technique ID | Technique Name | Observed | Notes |
|--------|-------------|---------------|---------|-------|
| Initial Access | T1566.001 | Spearphishing Attachment | Yes | |
| Initial Access | T1190 | Exploit Public-Facing Application | Yes | |
| Execution | T1059.001 | PowerShell | Yes | |
| Persistence | T1053.005 | Scheduled Task | Yes | |
| Defence Evasion | T1027 | Obfuscated Files | Yes | |
| Credential Access | T1003.001 | LSASS Memory | Yes | |
| Lateral Movement | T1550.002 | Pass the Hash | Yes | |
| Collection | T1560.001 | Archive via Utility | Yes | |
| Exfiltration | T1048.003 | Exfil over HTTPS | Yes | |

### Coverage Gap Analysis

Techniques observed for this actor NOT currently detected by our rules:

| Technique | Gap Type | Priority | Linked Rule Request |
|-----------|---------|----------|-------------------|
| | No detection | High | |

---

## Tools, Malware & Utilities

| Tool | Type | Description | Sigma Rule |
|------|------|-------------|------------|
| [Tool name] | RAT / Loader / Dropper / Util | Brief description | [rule link or pending] |

---

## Infrastructure

> Use generic descriptors only — no real IOCs in this profile file.

### Hosting Patterns

- **ASNs preferred:** [Hosting providers typically used, not specific IPs]
- **Domain patterns:** [e.g. "impersonates financial institutions using typosquatting"]
- **TLS certificate patterns:** [e.g. "uses Let's Encrypt, self-signed for C2"]
- **C2 protocols:** [e.g. HTTPS over port 443, DNS tunnelling]

### Infrastructure Lifecycle

- **Domain registration to first use:** [e.g. < 48 hours]
- **Infrastructure rotation frequency:** [e.g. Every 2–4 weeks]
- **Shared infrastructure with other actors:** [None known / Actor X]

---

## Campaigns

| Campaign | Timeframe | Target Sectors | Initial Vector | Key Malware | Outcome |
|----------|-----------|---------------|---------------|-------------|---------|
| [Name] | [Dates] | | | | |

---

## Incident History (Internal)

> Link to internal incidents involving this actor. Keep confidential.

| Date | Incident ID | Outcome | Lessons Learned |
|------|-------------|---------|----------------|
| | IR-YYYY-NNN | | |

---

## Detection Recommendations

### High-Priority Detections for This Actor

1. **[Technique]** — Deploy/tune Sigma rule `[rule-file]`
2. **[Technique]** — Add IOC watchlist `[watchlist-file]`
3. **[Behaviour]** — [Detection approach]

### Hunting Hypotheses

- [ ] Hunt for [behaviour] using [data source] query: `[query or link]`
- [ ] Hunt for [tool artefact] in [log source]

---

## Defensive Recommendations

| Control | CIS Control | Priority | Notes |
|---------|------------|----------|-------|
| Enforce MFA on all externally-exposed apps | CIS 6.3 | Critical | Blocks common initial access |
| Block execution from Temp/AppData | CIS 2.5 | High | Prevents loader execution |
| Enable PowerShell script block logging | CIS 8.8 | High | Detects encoded commands |
| Network segmentation for critical assets | CIS 12.2 | High | Limits lateral movement |

---

## Intelligence Sources

| Source | Type | Date | Confidence |
|--------|------|------|-----------|
| [Vendor report title] | Public report | [Date] | High |
| [Internal IR] | Internal | [Date] | Confirmed |

---

## Profile Maintenance

| Date | Change | Analyst |
|------|--------|---------|
| [Date] | Initial profile created | [Name] |
| | | |

**Next review:** [Date — 6 months or after new campaign observed]
