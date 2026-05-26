# Flash Report — Threat Intelligence Alert

**Report ID:** FLASH-[YYYY]-[NNN]  
**Classification:** TLP:AMBER — Restricted to named recipients  
**Issued:** [YYYY-MM-DD HH:MM UTC]  
**Produced By:** SOC Threat Intelligence Team  
**Distribution:** SOC Manager, IR Lead, CISO  
**Validity:** 72 hours — reassess if no further activity

---

## ALERT SUMMARY

> **One sentence:** What is happening, who is targeted, and what action is required RIGHT NOW.

**Threat:** [Threat name / CVE / campaign]  
**Severity:** CRITICAL / HIGH / MEDIUM  
**Confidence:** High / Medium / Low  
**Action Required:** [BLOCK / PATCH / HUNT / MONITOR]

---

## WHAT IS HAPPENING

<!-- 3–5 sentences maximum. Plain language. No jargon. -->

---

## WHO IS AFFECTED

| Scope | Detail |
|-------|--------|
| Industry targeting | [Sector — e.g., Financial Services, Healthcare] |
| Geography | [Region — if known] |
| Asset types | [e.g., Windows servers, VPN appliances, web-facing apps] |
| Relevance to us | HIGH / MEDIUM / LOW — [one sentence why] |

---

## INDICATORS OF COMPROMISE

> Defanged. Validate before deploying to production blocks.

| Type | Value | Confidence |
|------|-------|-----------|
| IP | 198.51.100[.]1 | High |
| Domain | malicious-domain[.]net | High |
| SHA-256 | [HASH-PLACEHOLDER] | High |
| URL | hxxps://evil[.]example/path | Medium |

---

## IMMEDIATE ACTIONS (next 4 hours)

- [ ] Block IOCs listed above at firewall / proxy / DNS
- [ ] Search SIEM for hits on IOCs (last 30 days)
- [ ] Check patch status for [CVE-XXXX-XXXXX] on affected asset types
- [ ] Alert asset owners for [affected system type]

---

## DETECTION

**SIEM search for IOC hits:**
```
index=* (198.51.100.1 OR malicious-domain.net OR HASH-PLACEHOLDER)
  earliest=-30d
| stats count by host, user, src_ip, dest_host
```

**Relevant Sigma rules:**
- [Rule path in soc-detection-rules/sigma/]

---

## SOURCE & CONFIDENCE

| Field | Detail |
|-------|--------|
| Primary Source | [ISAC / vendor advisory / OSINT / internal] |
| Source Reliability | A–F (Admiral scale) |
| Information Credibility | 1–6 |
| Public Advisory | [Link if applicable — e.g., CISA advisory URL] |

---

## FOLLOW-UP

Full TI Report to follow within **48 hours** if threat remains active: `reports/ti-report-template.md`

Next reassessment: [YYYY-MM-DD HH:MM UTC]

---

_Flash Report template v1.0_
