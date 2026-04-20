---
title: "Detection: [What It Detects]"
date: YYYY-MM-DD
author: "Prakhar Gupta"
category: detection-engineering
tags:
  - detection-as-code
  - (platform tags: logscale | kql | dataprime | sigma)
mitre_techniques:
  - id: TXXXX
    name: Technique Name
platforms:
  - logscale
  - kql
data_sources:
  - "Entra ID Sign-in Logs"
  - "CrowdStrike Process Execution"
false_positive_rate: low    # low | medium | high
confidence: high            # low | medium | high
tldr: "One-line: what behavior this catches and why it matters."
---

## What This Detects

(1–2 paragraphs: describe the adversary behavior, why it matters, and what stage of the kill chain it covers.)

## Detection Logic

### CrowdStrike LogScale

```
// LogScale query
```

### Azure Sentinel (KQL)

```kql
// KQL query
```

### Coralogix DataPrime

```
// DataPrime query
```

### Sigma

```yaml
title: ...
logsource: ...
detection:
  selection: ...
  condition: selection
```

## Data Source Requirements

(What logs must be ingested for this detection to work. Be specific — include log source names, required fields, and retention.)

## Tuning Guide

- **Known false positives**:
  - (e.g., legitimate scanner activity, internal admin tooling)
- **Recommended exclusions**:
  - (e.g., service account X, known-good parent process)
- **Threshold adjustments**:
  - (e.g., count threshold, time-window)

## Test / Validation

(How to simulate the attack to validate the detection fires. Reference atomic red team tests by ID where applicable.)

```bash
# Example: atomic red team
# Invoke-AtomicTest T1566.002 -TestNumbers 1
```

## References

- MITRE: [TXXXX](https://attack.mitre.org/techniques/TXXXX/)
- (Additional threat intel / research links)
