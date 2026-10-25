# Threat Actor Profile — GENERIC-ESPIONAGE-GROUP

> **OPSEC Notice:** This profile is a fictional composite for SOC portfolio demonstration.
> All IOCs are placeholder values only. Real operator identities are never included.
> In production, live IOCs live in the SIEM/TI platform — not in Git.

---

## Summary

| Field | Value |
|-------|-------|
| **Profile ID** | TA-2026-001 |
| **Alias(es)** | GENERIC-ESPIONAGE-GROUP, GEG |
| **Suspected Origin** | Unattributed (nation-state aligned) |
| **Motivation** | Cyber espionage — intellectual property theft, credential harvesting |
| **Target Sectors** | Defence, Aerospace, Critical Infrastructure, Financial Services |
| **Target Regions** | Western Europe, North America, APAC |
| **Activity Since** | 2021 (estimated) |
| **Confidence** | Medium |
| **Last Updated** | 2026-10-25 |

---

## Capability Assessment

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Technical Sophistication | High | Custom implant development, living-off-the-land |
| Operational Security | High | Frequent infrastructure rotation, VPN/proxy chaining |
| Persistence | High | Long-dwell-time campaigns (avg 6-9 months before detection) |
| Adaptability | Medium | Adjusts TTPs when burned; re-uses code between campaigns |

---

## MITRE ATT&CK TTP Mapping

| Tactic | Techniques | Notes |
|--------|-----------|-------|
| **Initial Access** | T1566.001 Spear Phishing, T1190 Exploit Public App | Targeted lure docs referencing victim industry |
| **Execution** | T1059.001 PowerShell, T1059.003 CMD | Heavily obfuscated encoded commands |
| **Persistence** | T1053.005 Scheduled Task, T1547.001 Registry Run Keys | Tasks named after legitimate Windows maintenance |
| **Defence Evasion** | T1027 Obfuscation, T1562.001 Disable Security Tools | Attempts to disable Defender before staging |
| **Credential Access** | T1003.001 LSASS Memory Dump, T1555 Password Stores | LSASS targeted within first 2 hours of access |
| **Discovery** | T1082 System Info, T1016 Network Config, T1018 Remote System Discovery | Automated host survey post-compromise |
| **Lateral Movement** | T1021.001 RDP, T1021.002 SMB, T1550.002 Pass-the-Hash | Pivots using harvested NTLM hashes |
| **Collection** | T1005 Data from Local System, T1039 Data from Network Share | Stages data before exfiltration |
| **Exfiltration** | T1048.003 Exfil via DNS, T1041 Exfil over C2 | Prefers DNS tunnelling; HTTPS as fallback |
| **Command & Control** | T1071.004 DNS, T1071.001 HTTPS, T1573 Encrypted Channel | 30-120s beaconing with +/-20% jitter |

---

## Known Infrastructure (PLACEHOLDER — Example Only)

> These are fictional examples. Replace with live IOCs from your TI platform.

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | update.example-cdn[.]net | C2 staging domain — mimics CDN |
| Domain | telemetry.corp-analytics[.]com | DNS tunnelling domain |
| IP | 198.51.100.42 | C2 server (TEST-NET placeholder per RFC 5737) |
| IP | 203.0.113.17 | Exfiltration endpoint (TEST-NET placeholder) |
| Hash (SHA-256) | e3b0c44...placeholder | Tool hash — placeholder only |

---

## Observed Kill-Chain Sequence

```
T+0h    Spear-phishing email with weaponised DOCX => macro drops loader
T+0.5h  Loader contacts DNS C2 (beaconing every 60s +/- jitter)
T+2h    LSASS memory dump via custom tool masquerading as svchost
T+4h    Lateral movement via Pass-the-Hash to file server
T+8h    Network share enumeration; 15 GB staged in %TEMP%\~DFS
T+24h   Exfiltration via DNS tunnelling over 6-hour window
T+30d   Backdoor remains dormant; re-activates after credential rotation
```

---

## Detection Opportunities

| Kill-Chain Stage | Detection Method | Sigma Rule / Hunt |
|-----------------|-----------------|-------------------|
| Initial Access | Macro execution from email attachment | sigma/execution/ |
| Execution | Encoded PowerShell | sigma/execution/ |
| Persistence | Scheduled task creation | sigma/privilege-escalation/scheduled-task-creation.yml |
| Credential Access | LSASS access | sigma/credential-access/lsass-memory-dump.yml |
| Lateral Movement | Pass-the-Hash / RDP | sigma/lateral-movement/rdp-lateral-movement.yml |
| C2 Beaconing | High-frequency DNS | sigma/command-and-control/c2-dns-beaconing.yml |
| Exfiltration | Abnormal DNS volume | hunting-queries/lateral-movement-hunting.md |

---

## Response Recommendations

1. **Detection priority:** Deploy all six Sigma rules above — they map directly to this actor's kill-chain
2. **Hardening:** Enforce MFA on privileged accounts; disable macros by default in Office
3. **Monitoring:** Increase logging for DNS (Sysmon EventID 22) and process access events
4. **Threat Hunting:** Run lateral-movement hunting queries weekly
5. **Incident Response:** If this actor suspected — engage IR retainer immediately; assume credentials compromised

---

*Profile classification: Internal — For SOC/IR team use only*
*Author: reninjk | Reviewed: 2026-10-25*
