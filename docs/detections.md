---
layout: default
title: Detections
permalink: /detections/
description: "Detection-as-code library — LogScale, KQL, DataPrime, and Sigma rules mapped to MITRE ATT&CK."
---

<header class="post-header" style="margin-bottom: 2rem;">
  <div class="post-category">detection library</div>
  <h1>Detections</h1>
  <p style="color: var(--text-secondary);">
    Production hunting queries for CrowdStrike LogScale, Azure Sentinel (KQL),
    Coralogix DataPrime, and Sigma (platform-agnostic). Every rule is mapped
    to MITRE ATT&amp;CK and includes tuning notes and validation steps.
  </p>
</header>

{%- if site.detections and site.detections.size > 0 -%}

<table class="detections-table">
  <thead>
    <tr>
      <th>ID</th>
      <th>Name</th>
      <th>Platform</th>
      <th>Technique</th>
      <th>Severity</th>
      <th>Confidence</th>
    </tr>
  </thead>
  <tbody>
    {%- for det in site.detections -%}
      <tr>
        <td><code>{{ det.id }}</code></td>
        <td><a href="{{ det.url | relative_url }}">{{ det.name | default: det.title }}</a></td>
        <td>{{ det.platform }}</td>
        <td>
          {%- for t in det.mitre_attack -%}
            <code>{{ t.technique }}</code>{%- unless forloop.last -%}, {%- endunless -%}
          {%- endfor -%}
        </td>
        <td>{%- if det.severity -%}<span class="pill pill--{{ det.severity }}">{{ det.severity }}</span>{%- endif -%}</td>
        <td>{%- if det.confidence -%}<span class="pill pill--{{ det.confidence }}">{{ det.confidence }}</span>{%- endif -%}</td>
      </tr>
    {%- endfor -%}
  </tbody>
</table>

{%- else -%}

<p style="color: var(--text-secondary);">No detections published yet.</p>

{%- endif -%}

<div class="section-heading" style="margin-top: 3rem;">
  <h2>Raw Rules (YAML)</h2>
</div>

<p>
  All detection rules are maintained as machine-readable YAML in the
  <a href="https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/detections">
    <code>detections/</code>
  </a> directory of the repository.
</p>

<div class="card-grid">
  <div class="card">
    <h3>CrowdStrike LogScale</h3>
    <p class="card-tagline">Falcon LogScale / Humio query language rules.</p>
    <div class="card-meta"><a href="https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/detections/logscale">Browse on GitHub →</a></div>
  </div>
  <div class="card">
    <h3>Azure Sentinel (KQL)</h3>
    <p class="card-tagline">Kusto Query Language rules for Microsoft Sentinel and Defender XDR.</p>
    <div class="card-meta"><a href="https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/detections/kql">Browse on GitHub →</a></div>
  </div>
  <div class="card">
    <h3>Coralogix DataPrime</h3>
    <p class="card-tagline">DataPrime query language rules for Coralogix observability.</p>
    <div class="card-meta"><a href="https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/detections/dataprime">Browse on GitHub →</a></div>
  </div>
  <div class="card">
    <h3>Sigma</h3>
    <p class="card-tagline">Platform-agnostic Sigma-format rules, convertible to any SIEM backend.</p>
    <div class="card-meta"><a href="https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/detections/sigma">Browse on GitHub →</a></div>
  </div>
</div>
