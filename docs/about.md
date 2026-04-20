---
layout: default
title: About
permalink: /about/
description: "About Prakhar Gupta — Senior Cloud Security Analyst, SOC Shift Lead."
---

<article class="post container--narrow">
  <header class="post-header">
    <div class="post-category">about</div>
    <h1>About</h1>
  </header>

  <div class="post-content">

## Background

I'm **Prakhar Gupta**, a Senior Cloud Security Analyst and Shift Lead at Coralogix SRC MDR. My day job is running a SOC shift — triaging alerts, leading incident response, and building detection logic that fires on adversary behavior rather than tool signatures.

This site is my independent research space. Everything here is my own work and does not represent my employer.

## Focus Areas

- **Cloud security** — Entra ID, Microsoft 365, AWS, GCP, Kubernetes — misconfiguration patterns, identity abuse, token theft
- **Detection engineering** — writing production hunting queries in LogScale, KQL, DataPrime, and Sigma
- **Incident response** — AiTM phishing investigations, supply chain compromise, credential harvesting campaigns
- **Threat intelligence** — tracking adversary infrastructure, campaign analysis, IOC publication
- **Open-source tooling** — small utilities that fill gaps in SOC workflows

## Why This Site Exists

Detection knowledge is still overwhelmingly locked inside vendor portals and private Slack channels. I publish sanitized case studies, production queries, and tooling under permissive licenses because the defender community gets stronger when we share how attacks actually look in real telemetry.

## Publication Principles

- **Sanitized** — no customer names, tenant IDs, or internal infrastructure details
- **Reproducible** — every detection includes data source requirements, tuning notes, and validation steps
- **Mapped to MITRE ATT&CK** — every post and detection has technique IDs so it's searchable and comparable
- **Coordinated disclosure** — see [responsible_disclosure.md](https://github.com/{{ site.author.github | default: 'username' }}/security-research/blob/main/responsible_disclosure.md) for vulnerability reporting

## Contact

- **GitHub**: [@{{ site.author.github | default: 'username' }}](https://github.com/{{ site.author.github | default: 'username' }})
{%- if site.author.linkedin %}
- **LinkedIn**: [in/{{ site.author.linkedin }}](https://www.linkedin.com/in/{{ site.author.linkedin }}/)
{%- endif %}
{%- if site.author.twitter %}
- **Twitter / X**: [@{{ site.author.twitter }}](https://twitter.com/{{ site.author.twitter }})
{%- endif %}
- **Security reports / PGP**: see [responsible disclosure](https://github.com/{{ site.author.github | default: 'username' }}/security-research/blob/main/responsible_disclosure.md)

## PGP Public Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
(paste your public key here, or publish to keys/pgp.pub and link)
-----END PGP PUBLIC KEY BLOCK-----
```

## Citation

If you use any detection rule, tool, or writeup from this site, please cite it. Format:

```
Gupta, P. (YYYY). "Post Title." Security Research.
https://{{ site.url }}{{ site.baseurl }}/posts/...
```

Or use [CITATION.cff](https://github.com/{{ site.author.github | default: 'username' }}/security-research/blob/main/CITATION.cff) for automated tooling.

  </div>
</article>
