# Detections

Detection-as-code library. Every file is a single rule in YAML, grouped by platform:

```
detections/
├── logscale/      # CrowdStrike LogScale / Humio
├── kql/           # Azure Sentinel / Microsoft Defender XDR
├── dataprime/     # Coralogix DataPrime
└── sigma/         # Platform-agnostic Sigma format
```

## File Naming

`<TECHNIQUE-ID>-<short-slug>.yml`

Examples:
- `T1566.002-aitm-redirect-chain.yml`
- `T1110.003-password-spray-entra-id.yml`

## Schema (all platforms except Sigma)

```yaml
id: DET-YYYY-NNN                # Unique ID, DET-<year>-<counter>
name: "Human-readable name"
description: |
  Multi-line description of what this detects and why.
author: "Prakhar Gupta"
created: YYYY-MM-DD
modified: YYYY-MM-DD
severity: low | medium | high | critical
confidence: low | medium | high
mitre_attack:
  - technique: TXXXX(.NNN)
    tactic: "Tactic Name"
platform: logscale | kql | dataprime
data_sources:
  - "Log source name"
query: |
  // The actual query, verbatim.
false_positives:
  - "Description of known benign behavior that may fire this rule"
tuning_notes: |
  Environment-specific tuning guidance.
references:
  - "https://..."
tags:
  - free-form-tags
```

## Sigma Rules

Sigma rules under `sigma/` follow the [official Sigma spec](https://github.com/SigmaHQ/sigma-specification) — convertible to any SIEM backend via `sigmac` / `pySigma`.

## Testing / Validation

Every rule should include a test/validation section describing how to simulate the attack — ideally referencing [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test numbers.

## Warning

> **These queries are provided as-is for defensive use.** Always review, tune, and validate detections in a non-production environment before deploying. Thresholds, data source names, and field schemas vary across environments.

## Contributing

See [../CONTRIBUTING.md](../CONTRIBUTING.md).

## License

MIT — see [../LICENSE](../LICENSE).
