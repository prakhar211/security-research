---
title: "Hello World — What This Blog Is About"
date: 2026-04-21
author: "Prakhar Gupta"
category: cloud-security
tags:
  - soc
  - mdr
  - detection-as-code
  - open-source
tldr: "A new home for sanitized incident case studies, production detection queries, and open-source security tooling. Here's what to expect and how the content is structured."
pinned: true
---

If you're reading this, the site is live. Quick tour of what I'll publish here.

## Who I Am

I'm a Senior Cloud Security Analyst and SOC Shift Lead at Coralogix SRC MDR. Day-to-day I triage alerts, lead incident response, and build detection logic for a multi-tenant MDR. This site is my **independent research space** — nothing here represents my employer.

## What I'll Publish

Four content streams, all tagged and searchable by MITRE ATT&CK technique:

1. **Incident case studies** — sanitized writeups of real investigations. AiTM phishing kits, supply chain compromises, OAuth consent abuse, cloud misconfigurations. Every post will include a timeline, the detection signal that caught it, the hunting query, and IOCs.

2. **Detection engineering** — production queries for [LogScale]({{ '/detections/' | relative_url }}), KQL (Azure Sentinel / Defender XDR), Coralogix DataPrime, and Sigma. Every detection has false-positive notes and validation steps. Raw YAML lives in [`detections/`](https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/detections).

3. **Tool releases** — small open-source utilities. Dependency scanners, triage helpers, IOC enrichers.

4. **Threat hunt playbooks** — structured hunt methodologies, mapped to ATT&CK, with repeatable queries.

## How Content Is Structured

Every post includes:

- A **TL;DR** — one-line summary at the top
- **MITRE ATT&CK technique badges** linking to attack.mitre.org
- **Tags** for platform, attack type, and framework
- **Defanged IOCs in prose**, raw IOCs in [`iocs/`](https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/iocs) for SIEM ingestion
- Citable permalinks — everything is CC BY-SA 4.0 for content, MIT for code

## Subscribe

- [RSS / Atom feed]({{ '/feed.xml' | relative_url }})
- [GitHub repo](https://github.com/{{ site.author.github | default: 'username' }}/security-research) — star to get release notifications
- [About page]({{ '/about/' | relative_url }}) — contact + PGP

## Coming Soon

First two real posts in the queue:

- AiTM phishing campaign writeup — redirect-chain hunting with LogScale and KQL
- Open-source dependency supply-chain scanner release

Thanks for reading. If you spot errors, have questions, or want to suggest a detection, open an issue on [the repository](https://github.com/{{ site.author.github | default: 'username' }}/security-research/issues).
