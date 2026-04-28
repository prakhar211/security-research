---
title: "[Campaign Name]: [Brief Description]"
date: YYYY-MM-DD
author: "Prakhar Gupta"
category: incident-casestudy
tags:
  - incident-response
  - (add relevant tags)
mitre_techniques:
  - id: TXXXX
    name: Technique Name
tldr: "One-line summary of what happened, how it was detected, and outcome."
# ioc_campaign must match a file in docs/_data/iocs/<campaign>.csv
# The canonical SIEM-ingestion CSV lives at repo-root iocs/<campaign>/indicators.csv — keep both in sync.
ioc_campaign: "campaign-slug"
severity: high    # critical | high | medium | low
---

## Executive Summary

(2–3 sentences: what happened, who was affected conceptually, outcome.)

## Attack Flow

<!-- STANDARD VISUAL: Attack flow diagram — create as SVG in docs/assets/img/posts/{slug}-attack-flow.svg -->
<!-- Replace the image path and alt text with your SVG filename and title -->
<!-- ![Attack Flow]({{ '/assets/img/posts/{slug}-attack-flow.svg' | relative_url }}) -->

## Attack Timeline

<!-- STANDARD VISUAL: Timeline graphic — create as SVG in docs/assets/img/posts/{slug}-timeline.svg -->
<!-- Replace the image path and alt text with your SVG filename and title -->
<!-- ![Investigation Timeline]({{ '/assets/img/posts/{slug}-timeline.svg' | relative_url }}) -->

| Time (UTC)   | Event                          | Data Source         |
|--------------|--------------------------------|---------------------|
| HH:MM        | Initial access observed        | Entra ID sign-in    |
| HH:MM        | Token theft confirmed          | Conditional Access  |
| HH:MM        | Mailbox rule created           | M365 Unified Audit  |
| HH:MM        | Containment: sessions revoked  | Response action     |

## Initial Access

(How the attacker got in — phishing kit, credential spray, supply chain, etc. Include sanitized lure screenshots if available.)

## Persistence & Lateral Movement

(What they did after initial access: mailbox rules, OAuth consent grants, device registration, MFA method tampering, cross-tenant activity.)

## Detection

(How this was caught — which alert, which query, which anomaly. Name the specific signal.)

### Hunting Query — CrowdStrike LogScale

```
// Paste your LogScale query here
```

### KQL Equivalent — Azure Sentinel

```kql
// Paste your KQL query here
```

### DataPrime Equivalent — Coralogix

```
// Paste your DataPrime query here
```

## Indicators of Compromise

{% include ioc-table.html campaign=page.ioc_campaign %}

## Mitigations & Recommendations

1. (Concrete action — config change, policy, detection, training)
2.
3.

## References

- [Link title](https://example.com)
