# Security Policy

## Repository Sensitivity

This repository contains threat intelligence templates, feed configurations, and integration guides. It is **not** an operational IOC store — live threat data belongs in your TI platform.

## Absolute Prohibitions

The following must **never** appear in this repository under any circumstances:

- Real IOC values tied to live incidents or active investigations
- API keys, authentication tokens, MISP credentials, or any secrets
- TLP:RED or TLP:AMBER intelligence content
- Data that could identify victim organisations or internal infrastructure
- OSINT that could identify individual threat actor operators (names, photos, locations)
- Internal incident ticket numbers, asset identifiers, or network topology

All example values in this repository use:
- RFC 5737 placeholder IPs: `198.51.100.x`
- Defanged domains: `evil-domain[.]net`
- Placeholder hashes: `[HASH-PLACEHOLDER]`
- Fictional CVEs: `CVE-XXXX-XXXXX`

## Reporting Security Issues

If you identify a security concern with the processes or configurations in this repository:

1. Do **not** open a public GitHub issue
2. Contact the SOC TI Lead directly via the internal directory
3. For urgent issues (e.g., accidentally committed credentials): contact the SOC Manager immediately and rotate the affected credential before raising an issue
4. Expect acknowledgement within 2 business days for non-urgent issues

## Credential Exposure Response

If a credential is accidentally committed:

1. **Immediately** rotate/revoke the exposed credential in the issuing system
2. Contact SOC Manager and TI Lead
3. Review git history to determine exposure window
4. Document in the incident register
5. Force-push to remove from history (coordinate with repo admin)

Note: Force-pushing does not fully remove data from GitHub — always rotate the credential first.

## Supported Versions

Only the `main` branch is maintained and reviewed. Content is reviewed:
- When a new TI feed is added or removed
- After a major MISP version upgrade
- Annually as part of the TI programme review

## Compliance

This repository's content supports compliance with:
- ISO 27001:2022 Annex A 5.7 — Threat Intelligence
- NIST CSF 2.0 — Identify: Threat Intelligence (ID.RA)
- CIS Controls v8 — Control 17: Incident Response Management
