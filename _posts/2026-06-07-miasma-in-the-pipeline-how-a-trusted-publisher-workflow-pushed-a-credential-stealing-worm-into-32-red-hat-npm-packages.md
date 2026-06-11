---
layout: post
title: "Miasma in the Pipeline: How a Trusted-Publisher Workflow Pushed a Credential-Stealing Worm Into 32 Red Hat npm Packages"
date: 2026-06-07
categories: [supply-chain, security]
tags: [npm, supply-chain, github-actions, oidc, slsa, shai-hulud, miasma]
author: Prakhar Gupta
description: "A technical deep-dive on the June 1, 2026 Miasma compromise of 32 @redhat-cloud-services npm packages — how OIDC trusted publishing was weaponised, what the dropper does, and the KQL, Sigma and GitHub Actions configuration changes SOC and platform teams need this week."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.** On June 1, 2026 a Red Hat employee's GitHub account was used to push *orphan commits* into `RedHatInsights/javascript-clients` and its sister repositories. Those repos' <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> workflows trusted the actor on push, requested an <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> `id-token`, and exchanged it for npm publish rights — pushing **96 trojanised versions across 32 `@redhat-cloud-services` packages** with **valid <span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span> provenance attestations**. An `npm install` of any affected version runs a `preinstall` hook that drops a 4.29 MB obfuscated `index.js`, downloads the <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> runtime to evade Node-focused detections, and harvests SSH keys, npm tokens, <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> runner secrets, and AWS/Azure/GCP/Vault/K8s credentials before republishing further poisoned packages under the victim maintainer's name. The single mitigation with the biggest blast-radius reduction is to **disable `preinstall`/`postinstall` lifecycle scripts in CI** (`npm install --ignore-scripts`) and require **environment-scoped, manually-approved <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> publishing** for any `npm publish` job — your existing `provenance: true` flag does *not* protect you when the trusted publisher itself is the attacker.

---

## Watch the 6-Minute Walkthrough

For IT generalists, platform engineers, and anyone who wants the intuition before the technical depth: a short narrated walkthrough of how an <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> trusted publisher gets turned into a worm vector, and the three things to do about it.

<!-- VIDEO_EMBED:START -->
<!--
  The Security Blog Automator pipeline replaces this block with the rendered
  <iframe> after NotebookLM Cinematic Video Overview generation completes.
  Source script: _video/script-<span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">miasma</span>-redhat-npm-supply-chain-deep-dive.md
-->
<div class="video-embed-placeholder" style="position:relative;padding-top:56.25%;background:#0b1220;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#cfd8e3;font-family:system-ui,sans-serif;">
  <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;padding:1rem;">
    <strong>Video rendering in progress.</strong><br/>
    A narrated walkthrough of this article will appear here once the publishing pipeline completes the NotebookLM video step.
  </div>
</div>
<!-- VIDEO_EMBED:END -->

> *Prefer to read?* Skip the video and jump straight to [Section 1 — Why This One Matters](#1-why-this-one-matters).

---

## 1. Why This One Matters

The defender narrative of the last two years has been: *"stop using long-lived npm tokens, switch to <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A package-registry scheme where the registry (npm, PyPI) trusts a CI workflow&#39;s OIDC token to mint short-lived publish credentials, eliminating the need to store a long-lived registry token in CI.">trusted publishing</span>, sign your artifacts with <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span>, and the provenance metadata will let consumers verify they got what the maintainer built."* That narrative is good. It is also, on June 1, exactly what got Red Hat's `@redhat-cloud-services` scope worm-bombed.

<span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> is the first wide-impact npm campaign where the attacker:

1. **Never stole an npm token** — they never needed to. <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> issued one on demand.
2. **Got a valid <span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span> Level 3 provenance signature** on the malicious tarballs from <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span>'s public <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore certificate authority that issues short-lived code-signing certificates whose subject is bound to the requester&#39;s OIDC identity.">Fulcio</span>/<span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore transparency log that records every signing event with an inclusion proof. Used by consumers to verify a signature&#39;s provenance.">Rekor</span> instances, because the malicious build *did* run inside the legitimate <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> workflow that <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> is supposed to attest.
3. **Wormed forward through <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> again** — the dropper, executing inside a victim's <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> runner, scraped `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from process memory, used it to mint a new npm publish <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> token for the victim maintainer's packages, and re-attested the poisoned tarball with a *forged* <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> certificate using the victim runner's own identity. Self-propagating, by design.

If you run a `@redhat-cloud-services/*` package anywhere in your dependency graph — direct or transitive — assume your build pipeline ran a credential harvester between June 1 and June 3, 2026 ([Microsoft Defender Security Research Team, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/); [JFrog Security Research, 2026-06-02](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/)). Red Hat's GitHub Insights org repositories sit at the centre of the Hybrid Cloud Console UI — *@redhat-cloud-services/chrome* alone has roughly **80,000–117,000 weekly downloads** across its dependents ([JFrog, 2026-06-02](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/)). The package handle is dormant relative to mainstream React utility libs, but its consumer set is precisely the population — cloud-console operators, OpenShift platform teams, internal IT tooling at Red Hat customers — that has the *highest* concentration of CSP, Vault, and Kubernetes credentials in any single CI runner.

For a Cloud Security Engineering team, the architectural takeaway is this: **the threat model for npm in 2026 is no longer "stolen maintainer token." It is "trusted publisher that ran an attacker's commit."** Every defence keyed to the *token boundary* (npm 2FA, npm token rotation, npm access provenance) is bypassed structurally. The boundary that matters now is the **commit ↔ workflow trust boundary** — which means <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span>, required reviewers, environment-scoped deployments, and the difference between `on: push` and `on: workflow_dispatch with environment: production`.

---

## 2. Background: How OIDC Trusted Publishing Is *Supposed* to Work

To understand the abuse, you have to understand the flow it imitates. The standard "modern" npm publish pipeline, used by `@redhat-cloud-services` and most large-org scopes since the npm provenance GA in mid-2023, looks like this:

![Diagram](https://kroki.io/mermaid/svg/eNptUsFu2zAMvecrePSwGcKuxhpgWLG1A4YGaYCdaZmxtdiSR1HJ-vejYqd12xgQLBF8j--RjPQ3kbd067BlHFagHyYJPg018fS0Ehh-ofOiZw6OyOKsG9ELbGkMgBF-OLlL9fn5pWazLrbU3KHc--jaTqL5g0eMlt0ope0deYkf3nF9teKCjwu6S2Sb_LXiD_e33xbZ5-eGw9E1V5L9OOTc_NtS66LwExQ7TlGogU2qexc74veqHl0btQmUwc_376m3LoBRqkPg1Rn00qVyvc6NqKB1AmOKHRRMPWEksGEYNGhAsJ1q5UwFzFYr2LFrW2I4BT7s-3CCIvhqYjGQrzPVhJ5hSpDdV8qmM40CriklHMhD8czTqYFLuIITO5k5MrJcSlCbXpvy8_cOCkzNjfbsE8RU33B2Fbg15wvTPp9oOsImmkG9vxWlyAo2D487MMfPJrjGmnP9kv7ZDn1LUGiVCaW5r1V0gaXs3VGl5KmN04zAMjW6QA77N8Uu05kMwKibQB51wQFFtCmYE6GYZ2eJBQ70pOwS4FnFheRaQ-rkm57g4zR1cN72KWZOLRX216wvdZfli6Kl4WlVdsg19r2SL3QPJNig4IWDmtV_rWg_eQ==)

Five things in that diagram matter for the attack we're about to dissect:

1. **The `sub` claim in the <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> JWT** identifies *the workflow run*: `repo:RedHatInsights/javascript-clients:ref:refs/heads/main`. npm's trusted publisher config is a regex pattern over that `sub`. If the pattern says "any push to `main`", any push to `main` qualifies.
2. **There is no human in the loop after the push.** `on: push` triggers atomically. No reviewer, no manual approval, no environment gate unless the workflow author explicitly configured one.
3. **<span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> is *not* enforced for the workflow's `sub` claim by default.** A push that bypasses <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span> (because the pusher has admin, or because they push an orphan-rooted history, or because the protection rule has stale required-reviewer exceptions) still produces a JWT that npm will honour.
4. **The <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> provenance signs *what was built*, not *who authorised the build*.** If the attacker's commit produces the tarball, <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> signs the attacker's tarball, and the resulting <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore transparency log that records every signing event with an inclusion proof. Used by consumers to verify a signature&#39;s provenance.">Rekor</span> entry looks indistinguishable from a legitimate release for anyone consuming the registry-side provenance.
5. **<span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> tokens are minted on every workflow run.** If the attacker's malware later runs *inside* a different victim's <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> runner, it can request a fresh <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> token from that runner's identity — `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN` are environment variables on every runner — and use it to publish poisoned packages for any scope that runner has trusted publisher config for.

This last property is what turns <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> from a single npm scope compromise into a *worm*. Microsoft Threat Intelligence and JFrog both observed the malware republishing packages owned by victim maintainers downstream — not Red Hat employees — using the victims' own runner identities and forged provenance ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/); [Wiz Blog, 2026-06-02](https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages)).

---

## 3. The Attack: How Miasma Inverts the Trusted-Publisher Flow

The pivotal observation behind <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> is brutally simple: **a trusted publisher trusts the workflow, not the maintainer.** If you can land a commit that the workflow runs against — even a commit that bypasses <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span> — you get the publish credential, you get the provenance signature, and you get the registry's blessing.

Here is the full attack chain, reconstructed from the Microsoft, JFrog, Wiz, and Snyk write-ups:

![Diagram](https://kroki.io/mermaid/svg/eNqNlF1P2zAUhu_3K47GxZiWAG0Z0GhC6helFOhGuoE0Tch1ThtDYme209L9-h07Sce0m7VqK9f2856P92SZqQ1PmbYw778BevW-v40tWyG0IrhhQlr6oP600IfnjHNVSgtc5YVWuTCY-P_3i1SYVMgVHIJVzyjBpri0tDJojFASUvHE-PP7tz8gDM-h30i0I5jpImXSIXNhoShNWkOtgjtMLpmdSCNWqTWgsVCmElxsC2YIDgvNJE-BwrHILUmRhk-j75UGjVInAiUjh4eN0s9LytqTNP4s0RBcJGEV-lowmE2Gg5oz8JxhwzmOQBY5WF0aiwnFu8go9bo--EKVlCsK6-p-Dkulm33gGhNTE4eeOGqIHyticzIMKZc1SkoLPbR7AmvUrooGGNfKGOi0oaBy0u2qHLFYGas0AhXKnbKWdlG_M2CZXrAsa6RHXvqikT6JYKg20liNLPdRCFrQeU8tNNZLSJV6Bl0SW8gEXw6eDOwfH7S7cNNv6n3h0eMGfRrB3WwePjzAB-iN4rDVPgvHgxsPTpDrbUE1T7QqCtQBJBRFplhioF9KJ2RFjjV47MGXDfiMXFlmVoQ8U2XiC4t0nFUxk5HX1E7UVbQlRasds3KNVAkCwVyZz2FBUvRTsK2TbvK49HKTRq7LIhhMHI2GwN_lmhVVZ-78nwf35Cfao7ZxcjvkmCu99QecA3qD-WR2Gz9Oho_z2XR0-3g3-vJ1FM-r1V-iVzvRBTUG196p1ABna5L2SMqNZRDHlwH07mP6-lVqDGA8-Bz4_W-MihPA9MwENBtqY1x5N9RDtLXWxGtNd1N-RJ3CMKdBf-1DD3NjUA-0S2UtaMJyclVjvqDJkjjxddxzzsM64OAfmhusHaIuqPDNs9s6tqmP7XoXGz2CqLo5GPKicwc9ExpC5aQ_7q1jogeJNGVOA1Mjjd1mCD1YiiyL9jqslbSSgO5QVtEeP-p024tX50b1uVPWpvfuHJ4e8w4PuMqUjvaWy-WrK9P_vfIbmX_AZw==)

Let's walk it stage by stage.

### 3.1 Stages 1–2 — Account Takeover and the Orphan Commit

Red Hat has not publicly confirmed the root-cause initial-access vector, but every published vendor analysis converges on the same shape: a single Red Hat employee's GitHub account was used to **push commits directly to repositories under `RedHatInsights/`** ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)). The commits are described by Microsoft and JFrog as *"orphan,"* meaning the attacker created a new root commit (no parent) and force-pushed it as a release-tagged tip. Two things matter here:

- An <span class="glossary-term" data-bs-toggle="tooltip" title="A git commit with no parent. Force-pushing an orphan-rooted history to a branch replaces the branch&#39;s history entirely; in many enterprise configurations this bypasses pull-request-based branch protection.">orphan commit</span> has no merge history. Required-reviewer policies that gate *pull requests* do not apply to a *push* that creates a new ref.
- <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> in many large orgs has historical *bypass actor* exceptions for admins and automation accounts. When the compromised account is in one of those exception sets, the push lands.

The commit modified `package.json` to add a `preinstall` hook and replaced `index.js` with the 4.29 MB dropper. Crucially, **source-map metadata was left unchanged** — strong evidence that the tampering happened at the build-pipeline level rather than via a local `npm publish` from a developer machine ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)).

### 3.2 Stages 3–5 — Trusted Publisher Mints the Credentials

Once the malicious commit lands, the existing `release.yml` (or equivalent) workflow runs. Its `permissions:` block grants `id-token: write` and `contents: read`. The runner calls the GitHub <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> endpoint, receives a JWT with `sub=repo:RedHatInsights/<repo>:ref:refs/heads/main`, posts it to npm's `/v1/oidc/token-exchange`, and npm — matching the JWT's `sub` against the scope's trusted publisher pattern — returns a short-lived publish credential.

The workflow then runs `npm publish --provenance`. The `--provenance` flag asks <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> (via <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore certificate authority that issues short-lived code-signing certificates whose subject is bound to the requester&#39;s OIDC identity.">Fulcio</span>) to issue a code-signing certificate whose subject includes the <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> JWT's identity, signs the tarball, and records the signature in <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore transparency log that records every signing event with an inclusion proof. Used by consumers to verify a signature&#39;s provenance.">Rekor</span>. From the registry's perspective and from any downstream consumer that checks `npm audit signatures` or pulls the `attestations` endpoint, **the tarball is signed by Red Hat's own canonical CI** — because it literally is.

Two release waves are visible in the npm publication timeline, both on June 1, 2026:

- **Wave 1 (~03:00 UTC):** 32 packages, single malicious version each — `chrome-2.3.1`, `frontend-components-7.7.2`, `rbac-client-9.0.3`, and so on.
- **Wave 2 (~05:00 UTC):** the same 32 packages republished, each with a second malicious version bump and a third "even-numbered" decoy bump (so consumers running `^` semver ranges on a higher minor pulled the malicious code without explicit opt-in).

The complete affected-version list is published by Microsoft ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/), Appendix A) and JFrog ([JFrog, 2026-06-02](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/)). Representative high-impact entries: `chrome@{2.3.1, 2.3.2, 2.3.4}`, `frontend-components@{7.7.2, 7.7.3, 7.7.5}`, `types@{3.6.1, 3.6.2, 3.6.4}`, `rbac-client@{9.0.3, 9.0.4, 9.0.6}`, `entitlements-client@{4.0.11, 4.0.12, 4.0.14}`.

### 3.3 Stage 6–8 — Preinstall to Persistence

The instant any of those tarballs lands on disk during `npm install`, npm executes the `preinstall` hook before any user code, before any build script, before the dependency resolver finishes printing its tree. The hook is a single line:

```json
"scripts": {
  "preinstall": "node index.js"
}
```

The replacement `index.js` is a 4.29 MB single-line file. Microsoft's reverse-engineering identifies four distinct obfuscation layers ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)):

1. **Layer 1 — ROT-XX character-code array.** A large array of integers, decoded at runtime through a rotated-Caesar transformation and `eval()`'d.
2. **Layer 2 — AES-128-GCM blobs.** The decoded layer-1 script decrypts two ciphertext blobs. Blob A is a platform-aware downloader for the <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> JavaScript runtime (from official `github.com/oven-sh/bun/releases` URLs). Blob B is the second-stage payload, written to `/tmp/p*.js` on Linux/macOS or `%TEMP%\p*.js` on Windows.
3. **Layer 3 — Obfuscator.io string-array protection.** The <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span>-executed payload is wrapped in a stock obfuscator.io transform: rotated string arrays, decoder functions, hundreds of alias wrappers.
4. **Layer 4 — Custom PBKDF2+permutation cipher.** Sensitive strings (<span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> URLs, <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> fragments, file paths) are kept encrypted at runtime behind a bespoke routine that derives keys with PBKDF2-HMAC-SHA-256 at **200,000 iterations**, then layers SHA-256-seeded permutation and XOR stages.

The malware then executes the second stage *via <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> rather than Node*. The resulting process chain — `node → sh → bun → payload` — is the single most useful detection signal in this whole campaign, because <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> is not part of any normal Node.js application's runtime tree and most endpoint-detection rule sets are tuned to Node-specific behaviour.

### 3.4 Stage 9 — Credential Theft (And Why "Just Don't Run As Root" Doesn't Help)

The <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span>-executed payload is a multi-cloud, multi-platform credential harvester. From Microsoft's recovered samples and JFrog's parallel analysis, the target list:

| Target | What is harvested | Where it is read from |
| --- | --- | --- |
| **GitHub** | Personal access tokens, fine-grained tokens, scopes via `/user`, repo and org enumeration, `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, Actions secrets, org secrets | env, `~/.config/gh/`, `/proc/<Runner.Worker>/mem` |
| **npm** | Whoami token, <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> publish exchange for republishing | env, `~/.npmrc`, `process.env.NODE_AUTH_TOKEN` |
| **AWS** | IAM creds via IMDSv1/v2, ECS metadata creds, Secrets Manager calls | `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, ECS `/v2/credentials`, `~/.aws/credentials` |
| **Azure** | <span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span> OAuth2 tokens for `management.azure.com`, `graph.microsoft.com`, and `*.vault.azure.net` | `http://169.254.169.254/metadata/identity/oauth2/token` |
| **GCP** | Service-account access tokens, Secret Manager, Resource Manager | `http://metadata.google.internal/computeMetadata/v1/` |
| **HashiCorp Vault** | Probes localhost Vault on `127.0.0.1:8200` across many token paths | Filesystem + env |
| **Kubernetes** | Service-account token + namespace secrets | `/var/run/secrets/kubernetes.io/serviceaccount/` |
| **Dev workstation** | SSH keys, gcloud config, kubeconfig, Docker config, `.env`, git creds, browser profiles, crypto wallet files (`*.wallet`, `wallet.dat`) | `~/.ssh/`, `~/.config/gcloud/`, `~/.kube/`, `~/.docker/`, `~/.gitconfig`, browser data dirs |
| **CI helpers** | CircleCI `CIRCLE_TOKEN`, anthropic API keys from `~/.claude.json` | env, filesystem |

The runner-memory scraping deserves a moment. <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> deliberately *masks* secrets in log output by replacing them with `***`, but the secret values themselves live in clear text inside the `Runner.Worker` process memory while the workflow is executing. <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> finds the PID by walking `/proc/*/cmdline`, then runs:

```bash
# Conceptual reconstruction of what the payload does
tr -d '\0' < /proc/<Runner.Worker_PID>/mem \
  | grep -aoE '"[^"]+":\{"value":"[^"]*","isSecret":true\}' \
  | sort -u
```

The output is a list of `{"name": "FOO", "value": "real-secret", "isSecret": true}` JSON fragments — every secret the workflow has access to, in plaintext, regardless of which `${{ secrets.FOO }}` references the workflow actually used ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)). This is not a CVE in Runner — it is intended behaviour. Secrets *must* be readable by the runner process; the mas
king is a log-side defence, not a memory-side one.

### 3.5 Stage 10–11 — Worm Propagation

The harvester opens four exfiltration channels (Microsoft's Section "Exfiltration"):

- **Channel A — victim-owned drop repo.** The malware creates a *public* GitHub repository under the victim's compromised account, names it from a wordlist (`adjective-creature-<0–99999>`), gives it the description `Miasma: The Spreading Blight`, and commits stolen credential JSON to `results/<timestamp>-<counter>.json`. This is the <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> hook that hunting queries pivot off — search org-wide for that description string.
- **Channel B — propagation via Git Data API.** Using the stolen GitHub token, the malware injects its own source as `.github/setup.js` into every non-protected branch of every repository the victim can write to, via blob → tree → commit → ref-update calls. Commit author is spoofed to `github-actions@github.com`, commit message is `chore: update dependencies [skip ci]`. The `[skip ci]` tag suppresses workflow triggering at *this* stage; the persistence sits idle until a future legitimate workflow imports `setup.js`.
- **Channel C — dormant HTTPS sender.** A disabled POST to `api.anthropic.com:443/v1/api` exists in the code with `noop: true`. The same domain is contacted to validate stolen Anthropic API keys from `~/.claude.json`, suggesting the operators planned to swap in a live exfiltration path later.
- **Channel D (the worm itself) — npm republish via stolen <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span>.** The runner-memory-scraped `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and `ACTIONS_RUNTIME_TOKEN` are used to mint a *fresh* npm <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> publish credential for whatever scope the victim's runner is configured for, then `npm publish --provenance` is invoked from the malware itself. <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> signs the malicious tarball with the victim runner's <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore certificate authority that issues short-lived code-signing certificates whose subject is bound to the requester&#39;s OIDC identity.">Fulcio</span> cert. The forged provenance points to a real, completed <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> run — because, again, the build literally happened inside that run.

<span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> is intentionally diffuse — Microsoft observed token-bearing GitHub API calls rotating across a pool of **16 attacker-controlled GitHub accounts per session**, with stolen tokens double-Base64 encoded in transit and `python-requests/2.31.0` as a forged user agent ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)).

### 3.6 The Destructive Tripwire

Buried in the payload is a planted *honeytoken* whose name itself is an <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span>: `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`. If a defender or maintainer attempts to revoke this token via the GitHub API, the malware — which is monitoring its own token's validity in a background loop — interprets revocation as discovery and triggers `rm -rf ~/` plus `rm -rf ~/Documents` on the host ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)). The lesson for <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span>: **do not blind-revoke tokens you find with this string** without first containing the host. Snapshot the workstation, kill the malware process tree, *then* revoke.

---

## 4. Why the Usual Defences Don't Stop It

| Defence | Why it fails against <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> |
| --- | --- |
| **npm 2FA on the maintainer account** | No login happened. <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A package-registry scheme where the registry (npm, PyPI) trusts a CI workflow&#39;s OIDC token to mint short-lived publish credentials, eliminating the need to store a long-lived registry token in CI.">trusted publishing</span> exchanges a workflow JWT for a publish credential; the maintainer's 2FA setting is never evaluated. |
| **`npm publish` provenance / <span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span> Level 3** | The malicious tarballs *have* valid provenance. <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> signs *what was built in the trusted workflow*, not *what was authorised*. `npm audit signatures` returns green. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> on `main`** | Orphan commits and admin-bypass actor allow-lists routinely sidestep <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span> in large enterprise orgs. The push itself was the bypass. |
| **`provenance: true` in publish workflow** | Same as above. Provenance is an integrity claim about the build, not an authorisation claim about the source. |
| **Dependabot / Renovate auto-pinning** | Acts in the attacker's favour. As soon as Wave 1 published, downstream PRs opened to bump to the malicious version. Many merged before the registry pulled the tarballs. |
| **`npm install --ignore-scripts` in production** | Helps in *production* — production rarely runs `npm install` from scratch. The damage happens in *CI* and on *developer workstations*, where `--ignore-scripts` is almost never set by default. |
| **Outbound firewall on CI runners** | The dropper downloads <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> from `github.com/oven-sh/bun/releases` — a domain virtually every CI build is allowed to reach. Exfiltration uses the GitHub API itself, also allowed. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> with Node-only behavioural rules** | The credential harvester runs under `bun`, not `node`. Rules keyed to `node` process trees miss the post-Stage-2 behaviour entirely. |

The two defences that *do* materially reduce the blast radius — at the cost of friction — are **disabling lifecycle scripts in CI** and **gating publish workflows behind GitHub Environments with required reviewers**. Both are covered in Section 6.

---

## 5. Detection: SOC-Side Hunting and KQL Queries

The detection strategy splits in two: **were we exposed (did we install a malicious version)** and **did the malware execute and reach out (did the post-install chain succeed)**. <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> below targets Microsoft Defender XDR Advanced Hunting; <span class="glossary-term" data-bs-toggle="tooltip" title="Security Operations Center. The team and tooling responsible for monitoring, detecting, and responding to security events across an organization.">SOC</span> teams on Sentinel only can drop the `CloudProcessEvents` queries and keep the rest. Equivalent Sigma is provided for vendor-neutral coverage.

### 5.1 KQL — `node → bun` Process Chain (highest fidelity)

The process tree `node → sh → bun → <payload>` is the single most reliable <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> signal because it is otherwise unheard-of in legitimate Node ecosystems.

```kusto
// Miasma — node spawns shell that spawns bun, all from CI/dev npm install
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in ("node", "node.exe")
| where FileName == "bun" or FileName == "bun.exe"
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName in ("npm", "npm.cmd", "yarn", "pnpm")
    | where FileName in ("node", "node.exe")
    | project DeviceId, ProcessId, NpmTriggerTime = Timestamp,
              NpmCommandLine = ProcessCommandLine
) on DeviceId, $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, AccountName,
          NpmCommandLine, BunCommandLine = ProcessCommandLine, FolderPath
| sort by Timestamp desc
```

### 5.2 KQL — Bun Execution From Temporary Directories

For self-hosted runners and dev workstations covered by `CloudProcessEvents`:

```kusto
CloudProcessEvents
| where Timestamp > ago(7d)
| where ProcessName =~ "bun" or ProcessCommandLine has "bun run"
| where FolderPath startswith "/tmp/" 
   or ProcessCommandLine matches regex @"/tmp/[^ ]*bun"
   or FolderPath startswith @"C:\Users\" and FolderPath has "AppData\\Local\\Temp"
| project Timestamp, TenantId, AzureResourceId,
          KubernetesNamespace, KubernetesPodName,
          ContainerImageName, ContainerId, AccountName,
          ProcessName, FolderPath, ParentProcessName, ProcessCommandLine
| sort by Timestamp desc
```

### 5.3 KQL — Cloud Metadata Endpoint Access From `node` or `bun`

The credential-theft module hammers `169.254.169.254` (AWS/Azure <span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span>) and `metadata.google.internal`. These endpoints have no legitimate consumer inside an npm install:

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("169.254.169.254", "169.254.170.2")
   or RemoteUrl has "metadata.google.internal"
| where InitiatingProcessFileName in ("node", "node.exe", "bun", "bun.exe", "sh", "bash")
| where InitiatingProcessParentFileName in ("npm", "npm.cmd", "yarn", "pnpm", "node")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| sort by Timestamp desc
```

### 5.4 KQL — Runner Memory Scraping Pattern

The `tr -d '\0' | grep "isSecret":true` shell pattern is a near-unique signature of the runner-memory exfil step:

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in ("grep", "grep.exe")
| where ProcessCommandLine has_all ("isSecret", "value", ":true")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessParentFileName
```

### 5.5 KQL — Suspicious GitHub Repo Creation (Exfil Channel A)

The malware drops stolen credentials into a brand-new public repo named with the pattern `<adjective>-<creature>-<0-99999>` and described `Miasma: The Spreading Blight`. The audit log is the highest-fidelity surface:

```kusto
CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "GitHub"
| where ActionType in ("CreateRepository", "repo.create")
| extend Description = tostring(RawEventData.repo.description)
| where Description has "Miasma" 
   or Description has "Spreading Blight"
   or tostring(RawEventData.repo.name) matches regex @"^[a-z]+-[a-z]+-[0-9]{1,5}$"
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType,
          RepoName = tostring(RawEventData.repo.name),
          Description, IPAddress, CountryCode
```

### 5.6 Sigma — Bun Spawned by Node Inside `node_modules`

For teams running Sigma-based detection on <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> telemetry (Elastic, Splunk UF, CrowdStrike):

```yaml
title: Miasma npm Worm — Bun Spawned by Node from npm Install Tree
id: 5e9b7a14-aa9a-4f0a-9b88-2026-miasma-deepdive
status: experimental
description: Detects the Miasma supply-chain worm process chain where a npm
    preinstall hook (node) spawns the Bun runtime, which is otherwise unused in
    pure Node.js applications.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/
    - https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/
author: Prakhar Gupta
date: 2026-06-07
tags:
    - attack.t1195.002   # Supply Chain Compromise: Compromise Software Supply Chain
    - attack.t1059.007   # Command and Scripting Interpreter: JavaScript
    - attack.t1552.001   # Unsecured Credentials: Credentials in Files
    - attack.t1555       # Credentials from Password Stores
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith: '/node'
    selection_image:
        Image|endswith:
            - '/bun'
            - '/sh'
    selection_path:
        CommandLine|contains:
            - '/tmp/'
            - 'bun run'
            - 'node_modules/@redhat-cloud-services/'
    condition: selection_parent and selection_image and selection_path
falsepositives:
    - Legitimate projects intentionally invoking Bun as a sub-runtime (very rare in production npm installs)
level: high
```

### 5.7 Exposure Hunt — Did We Install Affected Versions?

Run this in your build cache, lockfile mirror, or <span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span> tool (Defender Vulnerability Management, Snyk, JFrog Xray). The complete list of compromised `@redhat-cloud-services/*` versions is published by Microsoft and JFrog; the high-impact entries are reproduced in Section 8 (Glossary appendix). One-liner for a monorepo with multiple `package-lock.json` files:

```bash
find . -name 'package-lock.json' -print0 \
  | xargs -0 grep -lE '@redhat-cloud-services/[^"]+":\s*"[^"]*(2\.3\.[124]|7\.7\.[235]|9\.0\.[346]|3\.6\.[124]|4\.0\.(11|12|14)|6\.9\.[235]|4\.11\.[235])"' \
  | sort -u
```

If the find returns any hit, treat that build environment as compromised: rotate every secret it had access to, audit GitHub orgs for the `Miasma: The Spreading Blight` description string, audit npm publish history for the affected maintainers' other packages, and assume any tokens cached in `~/.npmrc`, `~/.aws/`, `~/.config/gcloud/`, or `~/.kube/` on developer machines are burned.

### 5.8 IOCs

From the Microsoft research team's recovered samples ([Microsoft, 2026-06-02](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)):

| Indicator | Type | Notes |
| --- | --- | --- |
| `@redhat-cloud-services/*` (32 packages, 96 versions) | npm scope | Full version list: Microsoft, Appendix A |
| `396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4` | SHA-256 | `index.js` — remediations-client |
| `d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223` | SHA-256 | `index.js` — frontend-components-advisor-components-3.8.2 |
| `f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c` | SHA-256 | `index.js` — hcc-kessel-mcp-0.3.4 |
| `d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b` | SHA-256 | `index.js` — frontend-components-testing-1.2.4 |
| `f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f` | SHA-256 | `index.js` — frontend-components-notifications-6.9.3 |
| `25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b` | SHA-256 | `index.js` — chrome-2.3.4 |
| `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner` | String | Honeytoken — do not naïvely revoke |
| `Miasma: The Spreading Blight` | String | GitHub repo description for exfil drop |
| `python-requests/2.31.0` (spoofed) | User-Agent | Forged UA for stolen-token <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> |

---

## 6. Mitigation: What Actually Works

Mitigation here is layered. There is no single switch, but there are a small number of high-leverage controls.

### 6.1 `--ignore-scripts` in CI: The Single Highest-Leverage Setting

`preinstall`/`postinstall`/`install` scripts are the Stage-0 detonator for *every* known npm supply-chain campaign of the last three years, not just <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span>. The cost of disabling them in CI is small (a handful of legitimate packages need a build-step fallback). Either set the registry-side flag globally:

```bash
npm config set ignore-scripts true --global
```

…or pass it explicitly in every CI install step:

```yaml
- name: Install dependencies
  run: npm ci --ignore-scripts
```

If you need certain scripts to run (e.g., for `node-gyp` builds), use `npm rebuild --ignore-scripts=false <package>` after `npm ci`, scoping the exception to the specific packages that legitimately require it.

### 6.2 Environment-Scoped, Reviewer-Gated `npm publish` Jobs

The architectural fix is to make `npm publish` a *separate workflow* triggered by `workflow_dispatch` against a <span class="glossary-term" data-bs-toggle="tooltip" title="A GitHub Actions construct that scopes secrets and deployment approval rules to a named environment. Required reviewers and wait timers configured here are the main defense against unattended OIDC publishing.">GitHub Environment</span> with **required reviewers** and **wait timer**. Even a one-minute timer plus a single reviewer would have blocked Wave 2 of <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> entirely, because a Wave 1 detection at any consumer would have escalated to the maintainer in time.

Example minimal-friction setup — separate the publish workflow from the build workflow:

```yaml
# .github/workflows/publish.yml — TRIGGERED MANUALLY ONLY
name: Publish to npm
on:
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to publish (must already exist as a git tag)'
        required: true

permissions:
  contents: read
  id-token: write

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: 
      name: npm-publish   # Configure required reviewers in repo settings
      url: https://www.npmjs.com/package/${{ github.repository }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.version }}   # Tag must already exist
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci --ignore-scripts
      - run: npm run build
      - run: npm publish --provenance --access public
```

The two non-negotiable pieces of repo configuration that go with this workflow:

1. In repo Settings → Environments → `npm-publish` → **Required reviewers**: add at least two people from the release engineering rotation. **Do not** allow the workflow's own actor to self-approve.
2. In Settings → Branches → `main` → **<span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">Branch protection</span> rule**: enable *Restrict pushes that create files*, *Require pull request before merging*, *Dismiss stale reviews on new commit*, *Require status checks*, and crucially **disable** *Allow force pushes* and *Allow deletions*. Then go to the **Bypass list** and remove every actor including admins. The bypass list is what the orphan-commit step in <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> exploited.

### 6.3 npm Trusted Publisher: Tighten the `sub` Pattern

In your npm package settings → **Trusted Publisher**, do not leave the GitHub workflow pattern wildcarded. Specify the *exact* workflow path and *exact* branch or tag pattern:

| Field | Bad (default) | Good (tight) |
| --- | --- | --- |
| Repository owner | `RedHatInsights` | `RedHatInsights` |
| Repository name | `*` | `javascript-clients` |
| Workflow filename | (any) | `publish.yml` |
| Environment | (any) | `npm-publish` |
| `sub` pattern | `repo:RedHatInsights/*` | `repo:RedHatInsights/javascript-clients:environment:npm-publish` |

A `sub` pattern that pins on `:environment:npm-publish` requires the workflow run to have used a <span class="glossary-term" data-bs-toggle="tooltip" title="A GitHub Actions construct that scopes secrets and deployment approval rules to a named environment. Required reviewers and wait timers configured here are the main defense against unattended OIDC publishing.">GitHub Environment</span> of that name. Combined with required reviewers on the environment (Section 6.2), the orphan-commit-on-`main` path no longer mints a publish token at all.

### 6.4 Pin Bun-Aware Detections in EDR

Open a ticket with your <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> vendor to add `bun` and `bun.exe` to the monitored-process inventory if they are not already there. Defender for Endpoint detects `node → bun` chains by default in the May 2026 sensor refresh, but third-party EDRs vary widely. The detection in Section 5.1 will only fire if your sensor *records* `bun` as a process at all.

### 6.5 Lockfile Hygiene

Switch every `package-lock.json` consumer from `npm install` to `npm ci`. `npm ci` errors out on lockfile drift, which means a malicious bump that changed the resolved tarball without a lockfile update gets surfaced before install. Pair with `package-lock.json` integrity field verification (the default since npm 8) and the registry-side `npm audit signatures` check, scheduled weekly.

### 6.6 Network Egress — Don't Try to Block GitHub, Do Block Bun Downloads

Blanket-blocking `github.com` from CI is impractical. Blanket-blocking `github.com/oven-sh/bun/releases` and `release-assets.githubusercontent.com/*bun*` is highly practical and breaks the Stage-2 chain entirely. If your platform team genuinely uses <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> in production, allow-list the specific <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> versions you ship and block everything else.

---

## 7. Operational Playbook for SOC and IR

If the detections in Section 5 fire — or your <span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span> flags an affected `@redhat-cloud-services/*` version in any lockfile — the playbook below covers the first six hours.

![Diagram](https://kroki.io/mermaid/svg/eNp1lFFv0zAQx9_5FPcyadUKTZsNWCUeSoG1mobGNsEjcpNraxrbke-8MT49Z6dpGjT85Dj27-5_f583yjK_AhmsuUK40YqMguUdPGiDlbYIpw9nGXyAEhkL1s4O0vZSMX5x3iiGxWJqTFpUvzXtF08W25ObZpWaczB3lpW2ae3eqpq2jkGt1_IbS_DBWvQwgifnd8QqHWnGtHQWhzIpxkPIsmmWDWF80cBvVSCEK82LsIJZCkQgJzsu1o5akJINj4IqJh0oa0AfK1fsADceiYAdrIKVsxUqwc8_fYXemLaTIk-g8VFGrdzPXpW6kDKl1WWJlvX6GVRVwdYRS5Ct1Mmro1y1FeHy_4DHRvD4Ygjne_y1lg3WlTiKGdbeFSlhj5h0s7BxH-AoT4yCx0lwvhf8LSgJztHiWhU7tcHXsQRvfpFgzlKIn8aVoRLwEShPoPwI1Aq-c9yqbaZgayOl3KFYchp1GbE_XgH0JFqBClfjAKaF1xzt9VHtpJfkHrT393b2QJJaa7ME9sjUuXIATQ6gt33Q7Mf9aPYneBxdzW9hvgQhJGdURfACKE-gqPayD_quQsWtuDO4fk9wP2u_XwCdCyjvZdSWbWkfkVhv2trNQqm5Vbx2vu3J0ru6d5t7F1HH2p33AjSg6EEdVpWmLWw1sfPPcNoZ0ZhAgw40-Q8oFqtyoQSDrKT9FRTiKUGliOGdPAjP1M8oP4Aus39fAmOC7ZpjHiQvk7q_dE_SBB6VkRsoDRM3dS9Bv_dc1HyR3Imp_gWuBl2F)

The three non-negotiable <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> actions in the first hour:

1. **Snapshot before you kill.** The honeytoken tripwire makes naive eradication destructive. Take a memory snapshot or full disk image first, then kill the `node`/`bun`/`sh` process tree.
2. **Rotate everything the runner could see, not just what you think it touched.** Because runner-memory scraping unmasks all secrets, every secret the workflow had `secrets.*` access to should be treated as exfiltrated — including secrets the workflow's code never explicitly referenced.
3. **Search GitHub at org scope for the <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> repo description.** The query is `description:"Miasma: The Spreading Blight"` via the GitHub search UI or REST API. Found repos are exfiltration drops; their contents are credential dumps from the compromised host.

After containment, two longer-running workstreams:

- **Provenance audit.** For every internal npm scope that publishes via <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span>, audit the last 14 days of publishes for tarballs whose <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> certificate `sub` claim does not match the expected workflow + branch + environment combination. Any mismatch — even on a package that "looks fine" — is a forged-provenance candidate.
- **Cloud-side correlation.** Cross-reference <span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span> metadata calls (`169.254.169.254`) from any node/<span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">bun</span> process on a CI runner against the time window the affected install ran. Microsoft's <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> in Section 5.3 is the start. Any hit means cloud creds were almost certainly minted and exfiltrated; treat the resulting IAM role / managed identity / service account as burned and rotate.

---

## 8. The Wider Picture: Trusted Publishing Was Never the Threat-Model Endpoint

<span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> is not a CVE. It is not a vulnerability in <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span>. It is not a vulnerability in <span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span>, in <span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span>, in npm, or in <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span>. Every one of those systems behaved exactly as designed.

The lesson is that **the trust model for "<span class="glossary-term" data-bs-toggle="tooltip" title="A package-registry scheme where the registry (npm, PyPI) trusts a CI workflow&#39;s OIDC token to mint short-lived publish credentials, eliminating the need to store a long-lived registry token in CI.">trusted publishing</span>" was always conditional on the commit-to-workflow boundary holding** — and that boundary, in the median enterprise GitHub org, is governed by <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span> rules that have accumulated bypass exceptions for admins, ops accounts, and migration tooling over a decade. <span class="glossary-term" data-bs-toggle="tooltip" title="A package-registry scheme where the registry (npm, PyPI) trusts a CI workflow&#39;s OIDC token to mint short-lived publish credentials, eliminating the need to store a long-lived registry token in CI.">Trusted publishing</span> replaced one weakness (long-lived npm tokens stored in CI) with another weakness (workflow runs trusted on the basis of *who pushed*, where *who pushed* is gated by <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span> that admins routinely bypass).

The strategic question every supply-chain security program needs to answer in 2026 is: **"For each package we publish, what is the *minimum* set of commit-acceptance gates that would have to fail for the wrong code to get a valid <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> token?"** If the answer is "one compromised account with admin," that is your real attack surface — not your npm token store. The <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> campaign is the proof.

Plan to migrate every internal publishing scope to environment-scoped, reviewer-gated workflows by end of Q3 2026. Plan to enforce `--ignore-scripts` in CI as the default and document the explicit exceptions. Plan to monitor for `node → bun` process chains as a permanent <span class="glossary-term" data-bs-toggle="tooltip" title="Security Operations Center. The team and tooling responsible for monitoring, detecting, and responding to security events across an organization.">SOC</span> use-case. The next campaign of this shape will not be Red Hat's, and it will not be called <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span>. But the structural play — "land a commit, ride the trusted publisher" — will be reused, because it works.

---

## Glossary

These terms are auto-tooltipped by the publishing pipeline; definitions are repeated here for the static reader.

- **<span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A package-registry scheme where the registry (npm, PyPI) trusts a CI workflow&#39;s OIDC token to mint short-lived publish credentials, eliminating the need to store a long-lived registry token in CI.">Trusted Publishing</span>** — A scheme where a package registry (npm, PyPI) trusts a workflow run's OpenID Connect JWT to mint short-lived publish credentials, eliminating the need to store a long-lived registry token in the CI system.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span> (Supply-chain Levels for Software Artifacts)** — A framework specifying integrity guarantees about how a software artifact was built. <span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span> Level 3 requires non-falsifiable provenance generated by a trusted build platform.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> (<span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore certificate authority that issues short-lived code-signing certificates whose subject is bound to the requester&#39;s OIDC identity.">Fulcio</span> + <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore transparency log that records every signing event with an inclusion proof. Used by consumers to verify a signature&#39;s provenance.">Rekor</span>)** — Open-source signing infrastructure where <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore certificate authority that issues short-lived code-signing certificates whose subject is bound to the requester&#39;s OIDC identity.">Fulcio</span> issues short-lived code-signing certificates keyed to <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> identities, and <span class="glossary-term" data-bs-toggle="tooltip" title="The Sigstore transparency log that records every signing event with an inclusion proof. Used by consumers to verify a signature&#39;s provenance.">Rekor</span> is the immutable public transparency log of those signatures.
- **`preinstall` hook** — An npm `package.json` script that runs *before* the package's dependencies are resolved or installed. Executes with the privileges of whoever ran `npm install`.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span>** — A JavaScript/TypeScript runtime alternative to Node.js. Used by <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> as a Stage-2 execution environment specifically to evade detection rules that key on `node` process trees.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A git commit with no parent. Force-pushing an orphan-rooted history to a branch replaces the branch&#39;s history entirely; in many enterprise configurations this bypasses pull-request-based branch protection.">Orphan commit</span>** — A git commit with no parent. Force-pushing an orphan-rooted history to a branch replaces the branch's commit history entirely; in many enterprise configurations this bypasses pull-request-based <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub repository setting that gates which actors and commit shapes are allowed to update a protected branch. Bypass-actor allow-lists are a recurring source of supply-chain compromise.">branch protection</span>.
- **`ACTIONS_ID_TOKEN_REQUEST_TOKEN`** — An environment variable injected into <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> runners with `id-token: write` permission, allowing the workflow to request an <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> JWT from the GitHub provider.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span>** — *Family of Client IDs*. Not relevant to <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> specifically, but mentioned in related M365 supply-chain literature; family refresh tokens are interchangeable across Microsoft first-party clients.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span>** — *Instance Metadata Service*. The link-local HTTP endpoint (`169.254.169.254` on AWS/Azure, `metadata.google.internal` on GCP) that hands out cloud credentials to workloads running on a VM.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A valid SLSA or Sigstore provenance attestation produced from a build that was itself malicious. The signature is mathematically correct; the meaning of what it attests has been subverted at the commit layer.">Trojanised provenance</span>** — A valid <span class="glossary-term" data-bs-toggle="tooltip" title="Supply-chain Levels for Software Artifacts. A security framework for software supply-chain integrity defined by the Open Source Security Foundation; provides build provenance attestation.">SLSA</span>/<span class="glossary-term" data-bs-toggle="tooltip" title="Open-source signing infrastructure for software artifacts. Combines Fulcio (short-lived code-signing certificates keyed to OIDC identities) and Rekor (immutable public transparency log).">Sigstore</span> provenance attestation produced from a build that itself was malicious. The signature is mathematically correct; the *meaning* of what it attests has been subverted at the commit layer.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A family of npm-targeting credential-stealing worms that originated in late 2025. Mini Shai-Hulud is a 2026 derivative; Miasma is the variant tailored to the @redhat-cloud-services scope.">Shai-Hulud</span>** — A family of npm-targeting worms that originated in late 2025; "Mini <span class="glossary-term" data-bs-toggle="tooltip" title="A family of npm-targeting credential-stealing worms that originated in late 2025. Mini Shai-Hulud is a 2026 derivative; Miasma is the variant tailored to the @redhat-cloud-services scope.">Shai-Hulud</span>" is a 2026 derivative; <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> is the variant tailored to the Red Hat Cloud Services scope.

---

## Sources & Further Reading

### Primary Vendor Research (the four you must read in full)

- [Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/) — The canonical technical write-up: complete affected-version table, full <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> set, <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> hashes, Defender XDR coverage map.
- [Shai-Hulud — Miasma: The Spreading Blight Hits Red Hat npm Packages — JFrog Security Research](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/) — Tarball-level reverse engineering; confirms the 96-version, 32-package scope and `package.json` tampering pattern.
- [Miasma: Supply Chain Attack Targeting RedHat npm Packages — Wiz](https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages) — Cloud-runtime detection guidance focused on <span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span> access patterns and <span class="glossary-term" data-bs-toggle="tooltip" title="A JavaScript and TypeScript runtime alternative to Node.js. Used by the Miasma worm as a second-stage execution environment specifically to evade detection rules tuned to Node.js process trees.">Bun</span> runtime download IOCs.
- [Miasma Attack Hits Red Hat npm Packages — Snyk](https://snyk.io/blog/miasma-supply-chain-attack-malicious-code-redhat-cloud-services-npm-packages/) — Dependency-graph blast-radius analysis and downstream consumer guidance.

### Secondary Coverage and Detection Resources

- [Miasma Supply Chain Attack Compromises Red Hat npm Packages with Credential-Stealing Worm — The Hacker News](https://thehackernews.com/2026/06/miasma-supply-chain-attack-compromises.html) — Industry-press summary and timeline.
- [Red Hat npm Packages Compromised in Supply-Chain Attack — Orca Security](https://orca.security/resources/blog/red-hat-npm-supply-chain-attack/) — Cloud-workload-protection angle and Vault/K8s <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> list.
- [Miasma: A Worming npm Supply Chain Attack on Red Hat Cloud Services — Upwind](https://www.upwind.io/feed/miasma-npm-supply-chain-worm-redhat-credential-harvest) — Runtime detection angle, ECS/<span class="glossary-term" data-bs-toggle="tooltip" title="Instance Metadata Service. The link-local HTTP endpoint (169.254.169.254 on AWS and Azure, metadata.google.internal on GCP) that hands out cloud credentials to workloads running on a VM.">IMDS</span> trace examples.
- [Miasma Poisoned Red Hat Cloud Services npm packages through Trusted Publishing — Corgea](https://corgea.com/research/redhat-cloud-services-npm-miasma-shai-hulud-worm) — Excellent focus on the <span class="glossary-term" data-bs-toggle="tooltip" title="OpenID Connect. An identity layer on top of OAuth 2.0 used widely (including by GitHub Actions) to federate trust between identity providers and cloud platforms without long-lived credentials.">OIDC</span> trusted-publisher abuse path.
- [Red Hat npm Packages Compromised to Spread a Credential-Stealing Worm — Aikido](https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm) — <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> consolidation across multiple analyses.
- [Multiple Red Hat Cloud Services npm Packages Compromised — CyberSecurityNews](https://cybersecuritynews.com/red-hat-cloud-services-npm-packages/) — Broader campaign summary.
- [Mini Shai-Hulud "Miasma: The Spreading Blight" Hits @redhat-cloud-services — SafeDep](https://safedep.io/redhat-cloud-services-hit-by-mini-shai-hulud-npm-worm/) — Family-lineage context (Mini <span class="glossary-term" data-bs-toggle="tooltip" title="A family of npm-targeting credential-stealing worms that originated in late 2025. Mini Shai-Hulud is a 2026 derivative; Miasma is the variant tailored to the @redhat-cloud-services scope.">Shai-Hulud</span> → <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span>).
- [Supply Chain Attack Affecting Numerous npm and PyPI Packages — NHS England Digital](https://digital.nhs.uk/cyber-alerts/2026/cc-4781) — UK national-CERT advisory framing.
- [Red Hat Cloud Services npm Packages Hijacked — Sonatype](https://www.sonatype.com/blog/red-hat-cloud-services-npm-packages-hijacked) — <span class="glossary-term" data-bs-toggle="tooltip" title="Software Composition Analysis. Tooling that inventories third-party packages in a codebase and matches them against vulnerability and compromise feeds.">SCA</span>-vendor perspective and detection in OSS Index.

### Hardening and Configuration References

- [Strengthening supply chain security: Preparing for the next malware campaign — GitHub Blog](https://github.blog/security/supply-chain-security/strengthening-supply-chain-security-preparing-for-the-next-malware-campaign/) — GitHub's own post-<span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span> guidance on environment-scoped <span class="glossary-term" data-bs-toggle="tooltip" title="A package-registry scheme where the registry (npm, PyPI) trusts a CI workflow&#39;s OIDC token to mint short-lived publish credentials, eliminating the need to store a long-lived registry token in CI.">trusted publishing</span>.
- [Configuring trusted publishers for npm — npm Docs](https://docs.npmjs.com/configuring-trusted-publishers) — Reference for the `sub` pattern tightening in Section 6.3.
- [GitHub Actions: Using environments for deployment — GitHub Docs](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) — Reference for required-reviewer environments.
- [npm provenance generation — npm Docs](https://docs.npmjs.com/generating-provenance-statements) — What `--provenance` does and (importantly) what it does *not* guarantee.

### Background and Family Lineage

- [The npm Threat Landscape: Attack Surface and Mitigations (June 2 update) — Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) — Six-month landscape view of <span class="glossary-term" data-bs-toggle="tooltip" title="A family of npm-targeting credential-stealing worms that originated in late 2025. Mini Shai-Hulud is a 2026 derivative; Miasma is the variant tailored to the @redhat-cloud-services scope.">Shai-Hulud</span> family.
- [Mini Shai-Hulud Worm Compromises TanStack, Mistral AI, Guardrails AI — The Hacker News](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html) — May 2026 precursor campaign; same lineage as <span class="glossary-term" data-bs-toggle="tooltip" title="The June 2026 npm supply-chain campaign that compromised 32 @redhat-cloud-services packages via the RedHatInsights GitHub Actions OIDC trusted publisher. Self-propagating worm; payload runs under Bun.">Miasma</span>.
- [Over 320 NPM Packages Hit by Fresh Mini Shai-Hulud Supply Chain Attack — SecurityWeek](https://www.securityweek.com/over-320-npm-packages-hit-by-fresh-mini-shai-hulud-supply-chain-attack/) — Scale data for the immediate prior wave.
- [Shai-Hulud Malware Hits 170+ npm & PyPi Packages — Ox Security](https://www.ox.security/blog/shai-hulud-here-we-go-again-170-packages-hit-across-npm-pypi/) — Family-history reference.

---

*Next week (rotation: Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel): an <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> deep-dive on the most operationally-significant newly attributed campaign of the week, with concrete <span class="glossary-term" data-bs-toggle="tooltip" title="Tactics, Techniques, and Procedures, the behavior of a threat actor. A tactic is the highest-level description of this behavior, while techniques give a more detailed description of behavior in the context of a tactic, and procedures an even lower-level, highly detailed description in the context of a technique.">TTPs</span>, victim-sector telemetry, and a detection cookbook for hunters.*
