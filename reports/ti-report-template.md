# Threat Intelligence Report

**Report ID:** TIR-[YYYY]-[NNN]  
**Classification:** TLP:AMBER — Restricted to named recipients and their organisations  
**Date Produced:** [YYYY-MM-DD]  
**Produced By:** SOC Threat Intelligence Team  
**Validity Period:** 30 days from production date  
**Distribution:** SOC Manager, IR Lead, CISO

---

## Executive Summary

> 2–3 sentence non-technical summary for leadership. State the threat, who it targets, and the recommended action.

**Threat:** [Threat actor / campaign name]  
**Targeting:** [Industry vertical / geography / organisation type]  
**Confidence:** High / Medium / Low  
**Recommended Action:** [Patch X / Block Y / Hunt for Z]

---

## Threat Overview

### Actor Profile
| Field | Detail |
|-------|--------|
| Actor Name | [Name / alias — if publicly attributed] |
| Suspected Origin | [Country / region — if publicly attributed] |
| Motivation | [Financial / Espionage / Hacktivism / Destruction] |
| Active Since | [Year] |
| Targeting | [Sectors / geographies / org types] |
| Known Aliases | [Other names used in public reporting] |

### Campaign Summary
<!-- Describe the campaign, initial access method, and observed objectives. 
     Use only publicly available or internally observed (sanitised) information. -->

---

## Technical Analysis

### Attack Chain (MITRE ATT&CK)

| Stage | Tactic | Technique | ID |
|-------|--------|-----------|-----|
| Initial Access | Initial Access | [e.g., Spearphishing Attachment] | T1566.001 |
| Execution | Execution | [e.g., PowerShell] | T1059.001 |
| Persistence | Persistence | [e.g., Scheduled Task] | T1053.005 |
| C2 | Command and Control | [e.g., Web Protocols] | T1071.001 |
| Exfiltration | Exfiltration | [e.g., Exfil over C2 Channel] | T1041 |

### Indicators of Compromise (IOCs)

> All IOCs below are defanged. Do not deploy to production without validation.  
> For deployment-ready IOC lists, see the watchlist in `iocs/`.

| Type | Value | Confidence | Context |
|------|-------|-----------|---------|
| Domain | example-c2[.]net | High | C2 infrastructure |
| IP | 198.51.100[.]47 | Medium | Hosting provider |
| SHA-256 | [HASH-PLACEHOLDER] | High | Dropper binary |
| URL | hxxps://example[.]com/payload | High | Stage 2 download |

> **Note:** IOC values above are placeholders. Replace with actual intel from your TI platform before distribution.

### Malware / Tooling
<!-- Describe tools observed — use generic names or publicly attributed malware names only. -->

---

## Detection Guidance

### SIEM Detection Queries

> Adapt field names to your SIEM environment.

**Detect C2 domain communication:**
```
index=proxy dest_host IN (c2-domain-placeholder)
| stats count by src_ip, dest_host, _time
```

**Detect IOC file hash:**
```
index=edr hash IN (sha256-hash-placeholder)
| table _time, host, user, file_name, process
```

### Sigma Rules
Relevant rules from `soc-detection-rules/sigma/`:
- [Rule name / path]

### Recommended Blocks
| Block Type | Value | Platform |
|-----------|-------|---------|
| DNS sinkhole | [domain-placeholder] | DNS filter |
| IP block | [IP-placeholder] | Firewall |
| URL block | [URL-placeholder] | Proxy |

---

## Defensive Recommendations

### Immediate (within 48 hours)
1. [Action item]

### Short-term (within 30 days)
1. [Action item]

### Strategic
1. [Action item]

---

## Intelligence Gaps

<!-- List what is unknown or uncertain — helps prioritise future collection -->
- [ ] Attribution confidence not yet confirmed
- [ ] Full malware capability set unknown
- [ ] Infrastructure scope not fully mapped

---

## Source Summary

| Source | Type | Reliability | Classification |
|--------|------|------------|---------------|
| [Source name] | OSINT / ISAC / Internal | A–F (Admiral scale) | TLP:WHITE |

---

## Version History

| Version | Date | Change |
|---------|------|--------|
| 1.0 | [YYYY-MM-DD] | Initial publication |

---

_Report template v1.0 — Review annually_
