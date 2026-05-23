---
layout: post
title: "TeamPCP and Mini Shai-Hulud"
date: 2026-05-23 13:30:30 +0530
categories: [security, threat-intelligence]
---


---
title: "TeamPCP (UNC6780) and the Mini Shai-Hulud Rampage: One Worm, Two Weeks, Four Codebases Stolen"
date: 2026-05-22
categories: [threat-intel]
tags: [teampcp, unc6780, mini-shai-hulud, supply-chain, npm, github-actions, oidc, vscode-extensions, detection-engineering]
---

## TL;DR

- **TeamPCP / UNC6780** is a financially-motivated supply-chain crew running a self-spreading worm called **Mini Shai-Hulud** — an adapted descendant of the [npm worm](https://www.helpnetsecurity.com/2025/09/16/self-replicating-worm-hits-180-npm-packages-in-largely-automated-supply-chain-attack/) first documented in September 2025.
- In the past 11 days they have publicly compromised **TanStack** (42 packages / 84 versions), **Nx Console** (2.2M-install VS Code extension), **GitHub** (~3,800 internal repos), **Grafana Labs** (codebase + ransom demand), and reportedly **OpenAI** and **Mistral AI** — all from a single root: the [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) by Tanner Linsley.
- Tradecraft is a chain of three known-but-rarely-fixed CI/CD weaknesses: `pull_request_target` Pwn Request → GitHub Actions cache poisoning → OIDC token extraction from `Runner.Worker` memory. No 0-days; just unaudited workflows and the [tj-actions Python memory-dump script from March 2025](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) reused verbatim.
- Exfil is over the **Session/Oxen** decentralized messenger network (`filev2.getsession.org`, `seed{1,2,3}.getsession.org`) — no traditional <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> to block.
- Prior TeamPCP victims include **Aqua Trivy**, **Checkmarx KICS**, **LiteLLM**, **Telnyx SDK**, **UiPath**, **Guardrails AI**, **OpenSearch**. This is a campaign, not an incident.

Rotation note: technically week 21 is the CVEs slot, but the TeamPCP campaign is the bigger story this week. Logging the deviation so the rotation can resync next Friday.

## Why this post

The Mini Shai-Hulud / Nx Console / GitHub story is the most defensively useful incident of 2026 so far — not because the tradecraft is novel, but because every step has been *publicly documented for over a year* and is still trivially repeatable across most npm/CI estates. If you maintain or consume a popular open-source package, this is the threat model.

## The actor: TeamPCP / UNC6780

Mandiant tracks the cluster as **UNC6780**; the actor self-identifies as **TeamPCP** and operates a Telegram leak channel under the same handle. Public reporting points to a small, financially-driven crew that specializes in **open-source security tooling and AI middleware** — exactly the developer footholds that yield the highest credential payout per intrusion. Confirmed prior victims, from Help Net Security's [chronology](https://www.helpnetsecurity.com/2026/03/30/teampcp-supply-chain-attacks-ransomware/):

- **Aqua Security Trivy** — [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- **Checkmarx KICS**, **LiteLLM**, **Telnyx SDK** — March 2026 spree, all via poisoned GitHub Actions
- **TanStack**, **Mistral AI**, **UiPath**, **OpenSearch**, **Guardrails AI** — Mini Shai-Hulud, May 2026
- **Nx Console** (VS Code extension, 2.2M installs) — the pivot vector into GitHub corp

Monetization is dual: ransom-and-leak (Grafana refused) and outright sale on criminal forums (~$50K asking price for GitHub's source). Per Aikido and Help Net Security, TeamPCP is on [Telegram and X](https://x.com/H4ckmanac/status/2056838119933001931), claiming credit publicly.

## The kill chain, end to end

![Diagram](https://kroki.io/mermaid/svg/eNpNjsFOwzAQRO_5ijnCoeQPgDYptBKtEHBBUQ-uuySrOLbldQoSgW_HSQRipZVWmpm3UwflG7yUGdIsq8J1PriOhU6wvsNOsY1pKRywWFwPj_3RsDQk8I7F2WTzSreqpgGri50yrNn1gtuorMSk_MqX04PVBBnBPMrGIAauawqJF8irQGicawcUn1sBRygU27wo8dTb1OHma6IUE-WVZEBZbVQ4k0Tcc9z0Ryx1ZGcFz6QDRTn8C-zdgPWf_8FpZfCdX6U2QSMfT5FmDpRjAHfV-uONTQwqEs6sElQk0bGn-O5CO3vXszfLfgAc1WtT)

The whole campaign is one connected chain. Tanner Linsley's [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) and [Grafana's update](https://grafana.com/blog/grafana-labs-security-update-latest-on-tanstack-npm-supply-chain-ransomware-incident/) lay it out cleanly.

```
[TanStack PR via fork]
        │  pull_request_target runs benchmark-pr
        ▼
[GitHub Actions cache poisoned]   ← Pwn Request + actions/cache@v5 quirk
        │  release.yml on next push restores poisoned pnpm-store
        ▼
[Runner.Worker memory dumped → OIDC token]   ← reuses tj-actions tradecraft
        │  authenticated POST to registry.npmjs.org
        ▼
[42 @tanstack/* packages, 84 versions, malicious]
        │  npm install triggers prepare → router_init.js
        ▼
[Dev/CI machines exfil AWS/GCP/k8s/Vault/npm/GitHub/SSH]
        │  Session messenger network exfil
        ▼
[Nx Console maintainer creds stolen → v18.95.0 published]
        │  VS Code Marketplace, 11–18 minutes live
        ▼
[GitHub employee, Grafana, OpenAI, Mistral devs]
        │  auto-update + IDE extension permissions = SYSTEM-equivalent
        ▼
[3,800 internal GitHub repos cloned + ransom demands]

```

### Stage 1 — pull_request_target "Pwn Request"

TanStack's `bundle-size.yml` ran on `pull_request_target`, checked out `refs/pull/<n>/merge` (fork-controlled code), and ran `pnpm install` plus a build. Author intended `permissions: contents: read` to make this safe. It isn't — `actions/cache@v5`'s post-job save uses a **runner-internal token**, not the workflow `GITHUB_TOKEN`. The cache write happens regardless of declared permissions.

### Stage 2 — Cache poisoning across the fork↔base boundary

The malicious `vite_setup.mjs` wrote into the pnpm-store under a key that the legit `release.yml` would later look up: `Linux-pnpm-store-${hashFiles('/pnpm-lock.yaml')}`. Per-repo cache scope means `pull_request_target` runs share cache namespace with `push` to `main`. Adnan Khan [documented exactly this attack in May 2024](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/). Nobody patched.

### Stage 3 — OIDC token extraction from runner memory

`release.yml` legitimately needs `id-token: write` for npm OIDC trusted publishing. When the poisoned cache restored, attacker binaries ran during the build step and:

1. Located `Runner.Worker` via `/proc/*/cmdline`
2. Read `/proc/<pid>/maps` and `/proc/<pid>/mem`
3. Extracted the lazily-minted OIDC token
4. POSTed directly to `registry.npmjs.org` — completely bypassing the workflow's `Publish Packages` step

This is the exact script (with the attribution comment left in) from the [tj-actions/changed-files compromise of March 2025](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised). Zero novel tradecraft.

### Stage 4 — Mini Shai-Hulud payload behavior

Every `npm install` of an affected version triggered the package's `prepare` lifecycle, executing a ~2.3 MB obfuscated `router_init.js`. The script harvests:

* AWS IMDS / Secrets Manager
* GCP metadata
* Kubernetes service-account tokens
* HashiCorp Vault tokens
* `~/.npmrc`, `~/.git-credentials`, GitHub CLI tokens, `~/.ssh/*`

Exfil is over the [Session/Oxen messenger network](https://getsession.org/) — end-to-end encrypted file uploads, no attacker-controlled DNS, no IP fingerprint beyond the well-known Session seed nodes. Worm propagation enumerates packages the victim maintains (`registry.npmjs.org/-/v1/search?text=maintainer:<user>`) and republishes them.

### Stage 5 — Pivot to Nx Console and downstream

Stolen GitHub creds from a TanStack victim belonged to a legitimate Nx Console maintainer. The attacker pushed an orphan commit to `nrwl/nx`, published Nx Console **v18.95.0** to the VS Code Marketplace at **2026-05-18 12:30 UTC**, and the extension auto-updated on ~2.2M dev machines during the **11–18 minute** window it was live. A GitHub employee was among them — yielding the 3,800-repo exfil.

## <span class="glossary-term" data-bs-toggle="tooltip" title="A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.">MITRE ATT&CK</span> mapping

Defenders writing TIPs / hunts can anchor on:

* **T1195.001** Compromise Software Dependencies and Development Tools (npm tarballs, VS Code extension)
* **T1195.002** Compromise Software Supply Chain
* **T1546** Event Triggered Execution — npm `prepare` lifecycle, VS Code extension `activationEvents`
* **T1059.007** Command and Scripting Interpreter: JavaScript
* **T1552.001 / .004** Credentials in Files / Private Keys (`.npmrc`, `.git-credentials`, SSH keys)
* **T1606.002** Forge Web Credentials: SAML Tokens *(closest equivalent — actually OIDC token forging via runner memory)*
* **T1078.004** Valid Accounts: Cloud Accounts (npm OIDC trusted publisher abuse)
* **T1567** Exfiltration Over Web Service — Session/Oxen network
* **T1199** Trusted Relationship — pivot via maintainer accounts
* **T1567.002** Exfiltration to Cloud Storage — second-stage payloads on `litter.catbox.moe`

## Indicators of Compromise

From the TanStack postmortem and the [StepSecurity Mini Shai-Hulud writeup](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem):

**npm manifest fingerprint (the smoking gun):**

```json
"optionalDependencies": {
  "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
}

```

**Files in tarball root:** `router_init.js` (~2.3 MB, not declared in `files`)

**GitHub Actions cache key (poisoned):**
`Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11`

**Stage-2 payload URLs:**

* `https://litter.catbox.moe/h8nc9u.js`
* `https://litter.catbox.moe/7rrc6l.mjs`

**Exfil network (Session/Oxen):**

* `filev2.getsession.org`
* `seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org`

**Forged commit identity:** `claude <claude@users.noreply.github.com>` *(fabricated GitHub no-reply, not Anthropic)*

**Attacker GitHub accounts:** `zblgg` (id 127806521), `voicproducoes` (id 269549300)
**Attacker fork:** `github.com/zblgg/configuration` (renamed fork of TanStack/router)
**Orphan payload commit (in fork network):** `79ac49eedf774dd4b0cfa308722bc463cfe5885c`

**Malicious VS Code extension:** `nrwl.angular-console` v18.95.0 (Nx Console), published 2026-05-18 12:30 UTC

**Affected npm scopes / packages (160+ across the campaign):** `@tanstack/*` (42 pkgs), `@mistralai/*`, `@uipath/*`, `@squawk/*`, `@tallyui/*`, Guardrails AI, OpenSearch packages — full list in the [Snyk advisory](https://snyk.io/blog/tanstack-npm-packages-compromised/).

## Detection & hunting

### 1) Find malicious tarballs in any artifact cache or `node_modules`

```bash
# Hunt for the optionalDependencies fingerprint across CI caches and dev hosts
find / -type f -name "package.json" 2>/dev/null \
  | xargs grep -l 'tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c' 2>/dev/null

# Hunt for the payload file at tarball root
find / -type f -name "router_init.js" -size +1M -size -10M 2>/dev/null \
  -exec sh -c 'echo "{}"; head -c200 "{}"; echo' \;

```

### 2) Sigma — Session/Oxen network beacons from dev/CI hosts

```yaml
title: Session Messenger Network Beacon (Possible Mini Shai-Hulud Exfil)
id: 6f2b81fe-7c4a-4ad4-8a5c-3d9b8a2b5b21
status: experimental
description: Detects DNS resolution or HTTPS connections to the Session/Oxen file-upload and seed nodes used for Mini Shai-Hulud exfiltration.
logsource:
  category: dns
  product: zeek
detection:
  selection:
    query|endswith:
      - 'filev2.getsession.org'
      - 'seed1.getsession.org'
      - 'seed2.getsession.org'
      - 'seed3.getsession.org'
  condition: selection
falsepositives:
  - Legitimate users of the Session messenger desktop client (uncommon on dev workstations and CI runners)
level: high
tags:
  - attack.exfiltration
  - attack.t1567

```

### 3) KQL — GitHub Actions OIDC token usage from unexpected workflow steps

If you ship GitHub audit logs to Sentinel / Defender XDR:

```kql
// Anomalous npm publishes via OIDC from workflows that didn't execute their Publish step
GitHubAudit
| where Action in ("workflow_run.completed", "package.publish")
| where Repository startswith "<your-org>/"
| extend WorkflowConclusion = tostring(parse_json(Payload).workflow_run.conclusion)
| where Action == "package.publish" and Actor matches regex @"^.*\[bot\]$" == false
| join kind=leftouter (
    GitHubAudit
    | where Action == "workflow_run.completed"
    | project RunId=tostring(parse_json(Payload).workflow_run.id),
              Conclusion=tostring(parse_json(Payload).workflow_run.conclusion),
              RunTime=Timestamp
) on $left.WorkflowRunId == $right.RunId
| where Conclusion == "failure"   // publish happened during a FAILED run = red flag
| project Timestamp, Repository, Actor, Package=tostring(parse_json(Payload).package.name), RunId, Conclusion

```

### 4) Sigma — npm `prepare` lifecycle spawning credential-search children

```yaml
title: npm/pnpm/yarn install spawning credential-discovery children
id: a8c1d7e0-5b6a-44a1-8b91-2d8d52a9f4b1
status: experimental
description: Detects npm/pnpm/yarn install lifecycle hooks launching processes that read AWS/GCP/SSH/k8s credentials — Mini Shai-Hulud router_init.js behavior.
logsource:
  category: process_creation
  product: linux
detection:
  parent:
    ParentImage|endswith:
      - '/npm'
      - '/pnpm'
      - '/yarn'
      - '/node'
    ParentCommandLine|contains:
      - 'install'
      - 'prepare'
  child_creds:
    CommandLine|contains:
      - '169.254.169.254'              # AWS/GCP IMDS
      - 'metadata.google.internal'
      - '/var/run/secrets/kubernetes.io/serviceaccount'
      - '~/.aws/credentials'
      - '~/.gcp'
      - '~/.npmrc'
      - '~/.ssh'
      - 'gh auth token'
  condition: parent and child_creds
level: high
tags:
  - attack.credential_access
  - attack.t1552.001

```

### 5) Dataprime — GitHub Actions cache restore from the known-poisoned key

If you ingest Actions logs into Coralogix:

```dataprime
source logs
| filter $d.workflow != null
| filter $d.message ~ /Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11/
| groupby $d.repository, $d.run_id, $d.workflow
| aggregate count() as restores, min($m.timestamp) as first_seen
| orderby first_seen asc

```

### 6) VS Code extension audit (one-liner)

```bash
# Enumerate installed VS Code extensions on a dev fleet and flag risky maintainer:extension pairs
code --list-extensions --show-versions \
  | awk -F'@' '{print $1"\t"$2}' \
  | while IFS=$'\t' read ext ver; do
      case "$ext" in
        nrwl.angular-console)
          if [ "$ver" = "18.95.0" ]; then
            echo "[!] COMPROMISED Nx Console version installed: $ver"
          fi
          ;;
      esac
    done

```

## Mitigation & response checklist

**If you've installed any affected @tanstack/* version on 2026-05-11, or Nx Console 18.95.0 on 2026-05-18:**

* Treat the install host as compromised. Rotate AWS, GCP, Kubernetes, Vault, GitHub, npm, and SSH credentials reachable from that host.
* Pull `gh auth status` and `gh auth token` audit; revoke any tokens issued from that workstation.
* Search GitHub Audit Log for any `git_clone` or `repo.download_zip` events on org repos from new IPs in the window 2026-05-11 → present.

**Pipeline hardening (do this regardless of whether you were hit):**

* **Kill `pull_request_target` for any workflow that checks out fork code.** If you must run untrusted code (e.g., benchmarks), do it in a separate repository with no access to the production cache or secrets.
* Pin every third-party action by **commit SHA**, not by tag (`actions/checkout@v6.0.2` becomes `actions/checkout@<sha>`).
* For npm OIDC trusted publishers: scope the `id-token: write` permission to a single dedicated `release` job that only runs after explicit manual approval, and add **provenance source verification** ([npm docs](https://docs.npmjs.com/generating-provenance-statements)).
* Periodically purge GitHub Actions caches across the org (`gh api -X DELETE /repos/{owner}/{repo}/actions/caches`).
* Block egress to `*.getsession.org` and `litter.catbox.moe` from dev workstations and CI runners.

**VS Code extension hygiene:**

* Disable extension auto-update on developer workstations; pin to known-good versions via [Extension Pack policy](https://code.visualstudio.com/docs/setup/enterprise) or `extensions.autoUpdate: false`.
* Use [OpenVSX](https://open-vsx.org/) mirrors with allow-listing for high-risk roles.
* Audit installed extension publishers monthly — Charlie Eriksen (Aikido) is right that VS Code extensions have the equivalent of SYSTEM on a dev box.

## Why this matters for defenders

The TeamPCP campaign is the cleanest demonstration to date that **the developer environment is now the highest-leverage initial-access surface in most enterprises**. None of the techniques used are novel — Pwn Requests, cache poisoning, and OIDC token theft have all been published and presented at conferences. The blast radius (GitHub, OpenAI, Grafana, Mistral, downstream consumers of any package any of those orgs published) is a function of how deeply trust is delegated through CI/CD and IDE extensions, and how invisible that trust graph is to traditional EDR.

If your shop ships software, the operational question for next week is not "are we patched?" — it's "do we have telemetry on what every CI runner and developer laptop in our org installed in the last 90 days, and from where?" If the answer is no, that's the work.

## References

* TanStack — [Postmortem: TanStack npm supply-chain compromise](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) (Tanner Linsley, May 11–15, 2026)
* TanStack — [GHSA-g7cv-rxg3-hmpx](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx)
* Grafana Labs — [Security update on TanStack npm supply chain ransomware incident](https://grafana.com/blog/grafana-labs-security-update-latest-on-tanstack-npm-supply-chain-ransomware-incident/)
* Help Net Security — [TeamPCP breached GitHub's internal codebase via poisoned VS Code extension](https://www.helpnetsecurity.com/2026/05/20/github-breached-teampcp/)
* Help Net Security — [GitHub, Grafana Labs breaches traced back to TanStack supply chain compromise](https://www.helpnetsecurity.com/2026/05/21/github-grafana-breach-root-cause-nx-console/)
* The Hacker News — [GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension](https://thehackernews.com/2026/05/github-internal-repositories-breached.html)
* The Hacker News — [Mini Shai-Hulud Worm Compromises TanStack, Mistral AI, Guardrails AI and More Packages](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html)
* Snyk — [TanStack npm Packages Hit by Mini Shai-Hulud](https://snyk.io/blog/tanstack-npm-packages-compromised/)
* Aikido — [The Wild West of VS Code extensions and how a poisoned extension breached GitHub](https://www.aikido.dev/blog/vs-code-extension-github-breach)
* Wiz — [Mini Shai-Hulud Strikes Again: TanStack + more npm Packages Compromised](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
* StepSecurity — [Mini Shai-Hulud is back: a self-spreading supply chain attack hits the npm ecosystem](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
* StepSecurity — [Harden-Runner detection: tj-actions/changed-files action is compromised](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) (March 2025, original OIDC-memory tradecraft)
* Adnan Khan — [The Monsters in Your Build Cache: GitHub Actions Cache Poisoning](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/) (May 2024)
* GitHub Security Lab — [Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
* BleepingComputer — [Shai Hulud attack ships signed malicious TanStack, Mistral npm packages](https://www.bleepingcomputer.com/news/security/shai-hulud-attack-ships-signed-malicious-tanstack-mistral-npm-packages/)
* BleepingComputer — [GitHub links repo breach to TanStack npm supply-chain attack](https://www.bleepingcomputer.com/news/security/github-links-repo-breach-to-tanstack-npm-supply-chain-attack/)
* Aqua Security — [Trivy supply-chain advisory GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
* Help Net Security — [Self-replicating worm hits 180 npm packages](https://www.helpnetsecurity.com/2025/09/16/self-replicating-worm-hits-180-npm-packages-in-largely-automated-supply-chain-attack/) (origin Shai-Hulud, September 2025)

```

```