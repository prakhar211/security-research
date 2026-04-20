# Indicators of Compromise (IOCs)

Machine-readable IOC feeds, one directory per campaign.

```
iocs/
├── <campaign-slug>/
│   ├── indicators.csv             # Raw values (for SIEM ingestion)
│   └── indicators.stix2.json      # STIX 2.1 bundle (optional)
```

---

## Defanging Policy

### In blog posts (human-readable)

Defang all network indicators so auto-linkers and link-preview bots don't click through to attacker infrastructure.

| Type     | Raw                                    | Defanged                                |
|----------|----------------------------------------|-----------------------------------------|
| URL      | `https://example.com/path`             | `hxxps://example[.]com/path`            |
| Domain   | `malicious.domain.com`                 | `malicious[.]domain[.]com`              |
| IP       | `192.168.1.1`                          | `192[.]168[.]1[.]1`                     |
| Hash     | `a1b2c3d4e5f6...` (SHA256)             | `a1b2c3d4e5f6...` (no defanging)        |
| Email    | `compromised-svc@victim.com`           | `compromised-svc-account@[redacted].com`|

### In `iocs/<campaign>/indicators.csv` (machine-readable)

**Raw values — NOT defanged.** These are intended for direct SIEM ingestion.

### CSV Schema

```
type,value,first_seen,last_seen,confidence,context,tags
domain,fontmetrics.net,2026-04-01,,high,DNS case-randomization evasion C2,phishing;credential-harvest
url,https://d14hg94i292w87.cloudfront.net/deel-login,2026-04-01,,high,Fake Deel credential page,phishing;cloudfront
```

**Columns:**

| Column       | Type     | Notes                                                    |
|--------------|----------|----------------------------------------------------------|
| `type`       | string   | `ip`, `ipv6`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email`, `mutex`, `filename` |
| `value`      | string   | Raw indicator value, not defanged                        |
| `first_seen` | ISO date | YYYY-MM-DD when first observed                           |
| `last_seen`  | ISO date | Leave empty if still active                              |
| `confidence` | string   | `low`, `medium`, `high`                                  |
| `context`    | string   | Short free-text describing how this IOC was used         |
| `tags`       | string   | Semicolon-separated tags                                 |

---

## STIX 2.1 Bundles (optional)

One bundle per campaign: `iocs/<campaign>/indicators.stix2.json`.
Follow STIX 2.1 `indicator` and `relationship` objects linked to `malware`, `threat-actor`, or `campaign` SDOs.

---

## ⚠️ Warning

**These IOCs are provided for defensive use.**
- Importing raw IOCs into blocking rules without validation is at your own risk.
- IOCs may have been reused by legitimate services after attacker abandonment.
- Always validate with internal telemetry and current threat intel before enforcement.
- Do NOT use these indicators for offensive purposes.

---

## License

Code (the repository scaffolding): MIT.
Indicator data is factual and generally not copyrightable, but attribution is appreciated:

> Source: Prakhar Gupta, Security Research. https://github.com/{username}/security-research
