## Summary
<!-- What does this PR add or change, and why? -->

## Type of Change
- [ ] New actor profile
- [ ] Feed configuration update (new source, filter change, schedule)
- [ ] Report template revision (TI report, flash report)
- [ ] Integration guide update (MISP, TAXII, TI platform)
- [ ] IOC watchlist template update
- [ ] Script update (feed-ingest.py or other automation)
- [ ] Documentation fix

## Security Checklist
- [ ] No real IOC values from live incidents included
- [ ] No API keys, tokens, or credentials included
- [ ] No TLP:AMBER or TLP:RED content included
- [ ] All example IPs use RFC 5737 range (198.51.100.x) and are defanged
- [ ] All example domains are defanged with [.] notation
- [ ] Actor profile cites only public sources — no PII on individual operators
- [ ] No internal asset names, ticket numbers, or network topology

## Review Requirements
- [ ] 1 approver — template or documentation change
- [ ] Senior analyst — new actor profile or feed source addition
- [ ] SOC Manager — integration guide changes affecting production systems

## Related Issue
Closes #

## Testing (for script changes)
- [ ] Tested with --dry-run flag first
- [ ] No errors in feed ingestion logs
- [ ] IOC deduplication working correctly

## Reviewer Notes
<!-- Anything specific to check — e.g., confirm actor attribution is publicly sourced -->
