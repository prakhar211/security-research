---
layout: post
title: "LSHIY Password Spray: How a Deprecated OAuth Flow Sprayed 81 Million Logins Past 'Fully Enabled' MFA"
date: 2026-07-06
categories: [threat-intel, security]
tags: [entra-id, ropc, azure-cli, password-spray, conditional-access, mfa-bypass]
author: Prakhar Gupta
description: "A deep-dive into the LSHIY ROPC password-spray campaign — how the Resource Owner Password Credentials flow lets attackers validate breached credentials at the /token endpoint and mint tokens with no MFA challenge, and the exact Conditional Access change that closes it."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.** Between **12–26 June 2026**, a <span class="glossary-term" data-bs-toggle="tooltip" title="An individual or a group of individuals that takes action to cause a malicious incident, or to pose a threat to the security of an organization&#39;s network.">threat actor</span> operating out of IPv6 range **`2a0a:d683::/32`** (LSHIY LLC, **AS32167 / AS955**) fired **81M+ login attempts** at Microsoft 365 tenants and compromised **78 accounts across 64 organisations**. The trick is not a CVE — it's the **<span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> Resource Owner Password Credentials (ROPC)** flow. ROPC submits a username and password *directly* to the Entra `/token` endpoint, so it **never touches the authorization endpoint where <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> injects <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>**. Every victim tenant *had* <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> — but scoped to specific apps, groups, or "trusted" locations, leaving a ROPC-shaped hole. The single most important mitigation: a <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> policy that enforces <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>/`userStrongAuthClientAuthNRequired` for **All Users, All Cloud Apps, All Client App Types**, plus blocking the **"Other clients"** legacy app type. Do this first, then hunt `authenticationProtocol == 'ropc'` with `resultType == 0` in your non-interactive <span class="glossary-term" data-bs-toggle="tooltip" title="The Entra ID audit table recording every interactive authentication event. Companion to AADNonInteractiveUserSignInLogs which records back-end token usage.">sign-in logs</span>.

---

## Watch the 6-Minute Walkthrough

For IT generalists, platform engineers, and anyone who wants the intuition before the technical depth: a short narrated walkthrough of how a "deprecated" login flow walked straight past <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>, and what to change today.

<!-- VIDEO_EMBED:START -->
<!--
  The Security Blog Automator pipeline replaces this block with the rendered
  <iframe> after NotebookLM Cinematic Video Overview generation completes.
  Source script: _video/script-lshiy-ropc-azure-cli-<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">mfa</span>-bypass.md
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

Most of the identity-attack coverage this year — including [our own ConsentFix v3 deep-dive](/security-research/) — has focused on *token theft*: <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> an <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">authorization code</span> or a <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> so the attacker rides a session the victim legitimately created. LSHIY is the blunter, older cousin, and it is arguably more dangerous precisely because it is so unglamorous. There is no <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> page, no <span class="glossary-term" data-bs-toggle="tooltip" title="A social-engineering pattern where the victim is shown a fake error and instructed to perform a &quot;fix&quot; action (paste-and-run, paste-into-form) that benefits the attacker.">ClickFix</span> paste trick, no malicious app. The attacker already has your users' passwords — from years-old breach dumps that were never rotated — and simply asks <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> politely, at the right endpoint, whether they still work.

The reason it warrants a full deep-dive rather than a line in a roundup is the **detection-blind gap it exploits**. This is a threat-intel piece built around a primary source: an advisory our own Snowbit by Coralogix threat-intelligence team distributed to managed customers, corroborated by public research from Huntress and reporting in the security press. The numbers are consistent across all three: **81 million login attempts in a 14-day window, 78 confirmed account compromises across 64 organisations**, with a clear escalation on **22 June 2026** when 30 identities across 23 businesses fell in a single day.

The uncomfortable finding, repeated verbatim across every compromised tenant: **they all had <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>, and none of them were configured to block this vector.** If your mental model is "<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> is on, therefore password spray is a solved problem," this campaign is the counter-example that should reset it. <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> enforces <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> *per authentication flow*, not globally — and the flow LSHIY chose is one most tenants never think to cover.

---

## 2. Background: What ROPC Is and Why It Exists

To understand the gap, you have to understand two very different <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> flows and *where* in each flow <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> actually runs.

The **<span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">Authorization Code</span> flow** — what a browser sign-in or `az login` uses — sends the user to the `/authorize` endpoint first. That is the interactive stage: the login page, the password prompt, and critically the **<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> challenge and <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> evaluation** all happen here. Only after those gates pass does Entra redirect back with a code that gets exchanged at `/token`.

The **Resource Owner Password Credentials (ROPC)** flow does something <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span>'s designers explicitly warn against: the client collects the username and password itself and `POST`s them **straight to `/token`**, skipping `/authorize` entirely. Microsoft's own documentation is blunt — *"we recommend you do not use the ROPC flow"* — because it is fundamentally incompatible with <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> and federated identity. It survives only for backward compatibility with a handful of legacy automation scenarios, and the <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span>'s non-interactive `--username/--password` path is the best-known first-party client that still speaks it.

Here is the legitimate ROPC exchange, so we can see exactly which stage the attack skips:

![Diagram](https://kroki.io/mermaid/svg/eNp1U9tu2zAMfe9X8DFBl3joY9AG8JxlGLBckAR7LRSZsYXKokfJ6dqnfcS-cF8ySs6lQzE_yRTPIc8h5fFHh07jzKiKVXMD8qkukOuaPXL_qwMx5G0LykMud40KhhxkkL92jFB8-3q_52w6cORGxgVkQZgjDhO6VRyMNq1yAXb0hC6yWKqMGzdGM3k6SDVrHI41NYkoI-mgvsuOd-OPWYiYd0xFHmkKcqWJvSgLudbofcKjE3Z8h9mgp441RuTiXBq-sGrrqGWzgCzBP__UtXIVSnBbK8Y1iaibRCcmjKbTJGMC69V2B2KaC4_hpcWHVnn_TFwmks4jO9Ug3MI5LkdtDUq6iWevqe2bXFJAoCNyb9CHIp_Arkax1nhYrkArayEQZNEWYvOK41RDcuCN37CY58Ir1lQqJKzDSMqodI3lONVKFa4avitrypjN6hk0YyntGWV9P3grRl9jcIzJkC9nsFmtC3AUYG9JP2GZ0q_0wi9OTWRz4kwe0whhcCudHBh93QeGSUOUFPl12qmNbKNhbCQCD-CNqyzO0_7l_-Rd6vUDOU92EtczOZSyJvAJZX4M928bmV7AZ9il33knRsfJjUq0GF0sTxoSBq3HXvpJNuxfot2DCNkGJlfF-kUacjwtT3rK4X8MyvPZdrcFZJYX9ufXb-itEsdNZMcDpSXwnZIn2vfgypu_sZE90g==)

The pivotal detail is the `Note` in the diagram. <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> policies that require <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> are wired to the **authorization endpoint**. ROPC never calls it. So a tenant can have a picture-perfect "Require <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>" policy and watch ROPC sign-ins sail through underneath it, landing in the logs as `singleFactorAuthentication` with no `mfa` value in the `amr` claim. The token Entra mints is a full **user-delegated** token — the same access the real user would get — granting Exchange Online, Teams, SharePoint, and OneDrive.

Five facts to internalise before we walk the attack:

1. **ROPC has no interactive stage.** No browser, no device signal, no `/authorize` — so no place for an <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> prompt to appear.
2. **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> is evaluated per flow.** "Require <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>" scoped to the wrong conditions simply never fires for ROPC.
3. **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> is a first-party, pre-consented client.** There is no malicious app to detect and nothing to consent to — the client identity is Microsoft's own.
4. **The credential is the whole payload.** No malware, no exploit. If the password is valid and unrotated, the attacker wins on the first try.
5. **Success looks like `resultType == 0` on a non-interactive event.** It is quiet by design. If you are not specifically watching `AADNonInteractiveUserSignInLogs`, you will not see it.

---

## 3. The Attack: LSHIY's Spray-and-Validate Chain

LSHIY is a **credential-validation** operation more than a "break-in." The actor holds enormous combo lists of breached `username:password` pairs and needs a cheap, <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>-blind oracle to tell them which ones still work against live M365 tenants. ROPC-to-`/token` is that oracle. Targeting is entirely opportunistic — driven by credential prevalence in leak dumps, not by industry or company size.

![Diagram](https://kroki.io/mermaid/svg/eNplU9tuEzEQfe9XDNuHpmrLbpImTVe0KDQtREpJRYJQFSHkeGcTC8de2d5ehJB44gMQ_9L3fkq_hLG3SQjsk3fsczxzznEu9S2fM-Ng3NsC-rhk1vYwB-Yc41_RQC6kTLfzHI_waN86o79ius07dazjPtdSm3S7xRKe8E28ULlhK3DeztprcNJhSbIEH7JmK0k2wQv7jMTjfIrHK2SDd1iDL5EJNrMEN5FTli0vpc08X0E9kHeWUA88ZFsBe6YXUz2J3hhkfI4ZcP8PUlhnX01NfForldGOOdoqLRrFFpgWdN2tNhkUTBi7G31O03SpWCDt-_En0WD0rn8Ng8FZpQc1U3JXGgzE_aubNjRYwtKs3WmmadxshHp31GzU20cQQ3d03GoF8gAPzKPCsPtJ1C2dXoSmPgyvzsD6KpqAnxmm3Bd3X-DJqs-nn78gdqSECke4FKhctyg-WsxS2Bm6OVldVe3O_-OMPXISXQputNW5g3PlyN5-L7DFmpVu3ohvGi-T6pLAsLAB-5a6_Bb1bdXoVGpizWB6D2fd15XAXSmBFYX1E9OyagP8ACTt9zXTBRNyEhm0pXRj2oUXJ5AEipx2iDSo4KOLi8JV3J365R7oHGhAi_D047dfgdLC4u7fXX4SaoN6yWyFmkm8YNxpQ5rPqTPBmRO6EtIn4iBDibPgRRgehLUlZoGd8hjoB1q7SXR-R49NzRCGSgqF8PgAY2SU9seHwDaip4hXWtD0tDVU2DPipgpLLS9JmgXNOdV3sOdDjsA4R_scP3_TOs9wcHBaRWUdx39qYRVqwd21z6HmXVvZRxWIrtFCraCngDyMiopithuF096ZzdPvNdQuL7pguS4qu8nheGZ0WcQUgaDgM5ikX1oQ_r1WW38A04h6Xw==)

### 3.1 The Infrastructure: LSHIY LLC

Nearly all observed traffic originates from **IPv6 range `2a0a:d683::/32`**, announced under **AS32167** and attributed to internet infrastructure provider **LSHIY LLC**. LSHIY operates at least two ASNs — **AS32167** (registered June 2021) and **AS955** (registered June 2022) — and the RIPE maintainer entry for the abused `/32` was created on **11 June 2026**, one day before the earliest confirmed campaign activity. That one-day gap between provisioning and first spray is itself a useful attribution signal: this was purpose-stood-up infrastructure.

Corporate records tie LSHIY to addresses in **Hong Kong and Wuhan**, plus a shared office at **42 Broadway, New York** — a layout that muddies true ownership. Note the deliberate **geolocation ambiguity**: third-party telemetry places the prefixes in China, yet some IPs resolve to **US (Nebraska)**. That inconsistency is not incidental — it is exactly what defeats "trusted location" <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> exclusions, which we cover in Section 4.

### 3.2 The Spray

The sprayer submits ROPC requests at high volume. Conceptually, each attempt is a single HTTPS `POST`:

```http
POST /organizations/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

grant_type=password
&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46   # Azure CLI first-party client
&username=victim@target.tld
&password=<from-breach-combo-list>
&scope=https://graph.microsoft.com/.default offline_access
```

The overwhelming majority of the 81M attempts return a non-zero `resultType` — wrong password, disabled account, or (in protected tenants) a strong-auth requirement error. Those failures are the noise. The signal the actor is mining for is the small fraction that return **`resultType == 0`**: a live, unrotated credential in a tenant that never closed the ROPC gap.

### 3.3 The Payoff

On a successful validation, Entra mints a user-delegated <span class="glossary-term" data-bs-toggle="tooltip" title="A bearer credential that an OAuth client uses to call a protected API on behalf of the authenticated user. Typically valid for 1 hour.">access token</span> — and because these were `offline_access`-scoped requests, often a <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> too. The sign-in is recorded as a **`NonInteractiveUser`** event with `authenticationProtocol: ropc`, `isInteractive: false`, `authenticationRequirement: singleFactorAuthentication`, and no `mfa` in the `amr` claim. From there the actor has the same reach the user has: read and exfiltrate mail via Graph or EWS, pull SharePoint and OneDrive content, and — if the account has any privilege — pivot.

### 3.4 The MFA Gaps That Let It Land

Every compromised tenant *had* <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>. Four recurring misconfigurations turned "<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> enabled" into "<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> irrelevant for ROPC":

- **Gap 1 — <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> scoped to specific apps only** (e.g. admin portals). <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> was simply not in the enforced-app list, so CA never evaluated it.
- **Gap 2 — <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> scoped to specific groups** (e.g. Admins). Standard user accounts — the bulk of any tenant, and the spray's target population — were exposed.
- **Gap 3 — Trusted-location exclusions.** Attacker IPs mislabeled as US-based by geolocation slipped past location conditions built to trust "the office."
- **Gap 4 — Report-only mode.** The policy existed, logged beautifully, and enforced nothing.

---

## 4. Why the Usual Defences Don't Stop It

| Defence | Why it fails against LSHIY / ROPC |
|---|---|
| **"<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> is enabled"** | <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> is evaluated at the `/authorize` endpoint. ROPC posts to `/token` and never reaches it. A tenant-wide "Require <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>" belief is not the same as an all-flows enforcement. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> scoped to specific apps** | If <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> (or "All Cloud Apps") isn't in scope, the ROPC sign-in is never evaluated. Gap 1. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> scoped to specific groups** | Standard users outside the protected group are wide open — and they're the majority target set. Gap 2. |
| **Trusted-location exclusions** | LSHIY IPs geolocate inconsistently (China *and* US-Nebraska). Location-only trust is defeated by inaccurate geo-IP. Gap 3. |
| **Report-only policies** | Log without enforcing. They give a false sense of coverage while blocking nothing. Gap 4. |
| **Password complexity / rotation policy** | Irrelevant if the breached password was never rotated. The exclusive target population is *unrotated* credentials from old dumps. |
| **Blocking by country** | Ambiguous geolocation means country blocks both miss the attacker and risk blocking legitimate users. Necessary but not sufficient. |
| **SMS / push <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> strength** | Doesn't matter — no second factor is ever requested in ROPC. The factor strength is moot when the flow never asks for one. |

The one control that **fundamentally breaks** ROPC is enforcing strong client authentication at the token layer — `userStrongAuthClientAuthNRequired` applied to **All Users / All Cloud Apps / All Client App Types** — which causes ROPC token issuance to fail *before* a token is minted. That is Section 6.1.

---

## 5. Detection: Hunting the Quiet Success

The highest-fidelity signal is a **successful, single-factor, non-interactive sign-in using the ROPC protocol** — ideally from the LSHIY ASNs, but the protocol/`resultType` combination is worth alerting on regardless of source. Because Prakhar's stack is Coralogix-backed, this section gives both **DataPrime** (from the Snowbit advisory) and **<span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span>** equivalents for Sentinel / Log Analytics shops.

### 5.1 KQL — Successful ROPC Sign-Ins With No MFA (Sentinel / Log Analytics)

This is the primary detector. It fires on the exact conditions the campaign produces. Tune `lookback` and add the ASN/IP filter once you have geo-IP enrichment.

```kusto
// LSHIY / ROPC — successful non-interactive single-factor sign-ins.
// The success (resultType 0) + ROPC + singleFactorAuthentication combo
// is the confirmed-compromise signal.
let lookback = 14d;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend authProtocol = tostring(parse_json(AuthenticationProtocol))
| where AuthenticationProtocol =~ "ropc"
      or ClientAppUsed == "Other clients"
| where AuthenticationRequirement == "singleFactorAuthentication"
| project TimeGenerated, UserPrincipalName, IPAddress,
          AppDisplayName, ClientAppUsed, AuthenticationProtocol,
          AuthenticationRequirement,
          Country = tostring(LocationDetails.countryOrRegion),
          AutonomousSystemNumber
| sort by TimeGenerated desc
```

### 5.2 KQL — Spray Volume: One IP / ASN Hammering Many Accounts

Catches the campaign shape even before individual successes — a single source attempting many distinct users:

```kusto
union AADNonInteractiveUserSignInLogs, SigninLogs
| where TimeGenerated > ago(14d)
| where AuthenticationProtocol =~ "ropc" or ClientAppUsed == "Other clients"
| summarize attempts = count(),
            distinct_users = dcount(UserPrincipalName),
            successes = countif(ResultType == 0),
            first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated)
            by IPAddress, AutonomousSystemNumber
| where distinct_users >= 5
| sort by attempts desc
```

Add an explicit LSHIY filter to pin known-bad: `| where AutonomousSystemNumber in ("32167", "955") or ipv6_is_match(IPAddress, "2a0a:d683::/32")`.

### 5.3 DataPrime — From the Snowbit Advisory (Coralogix)

These are the queries our Snowbit team shipped with the advisory; they run directly against Coralogix-ingested Entra <span class="glossary-term" data-bs-toggle="tooltip" title="The Entra ID audit table recording every interactive authentication event. Companion to AADNonInteractiveUserSignInLogs which records back-end token usage.">sign-in logs</span>.

**5.3.1 — ROPC sign-ins from LSHIY ASNs**

```text
source logs
| filter $d.properties.authenticationProtocol:string == 'ropc'
| filter $d.cx_security.source_ip_geoip.asn.number ~ '32167'
     || $d.cx_security.source_ip_geoip.asn.number ~ '955'
| choose $m.timestamp, $d.properties.userPrincipalName, $d.callerIpAddress,
         $d.resultType:string, $d.cx_security.source_ip, $l.applicationname
| orderby $m.timestamp desc | limit 200
```

`resultType '0'` = success → immediate triage priority; non-zero = failed spray attempt.

**5.3.2 — Successful single-factor auth from LSHIY ASNs (confirmed compromise)**

```text
source logs
| filter $d.resultType:string == '0'
| filter $d.properties.authenticationRequirement:string == 'singleFactorAuthentication'
| filter $d.cx_security.source_ip_geoip.asn.number ~ '32167'
     || $d.cx_security.source_ip_geoip.asn.number ~ '955'
| choose $m.timestamp, $d.properties.userPrincipalName, $d.callerIpAddress,
         $d.properties.appDisplayName, $d.cx_security.source_ip
| orderby $m.timestamp desc | limit 100
```

**5.3.3 — Tenant-wide ROPC spray volume by account (source-agnostic)**

```text
source logs
| filter $d.properties.authenticationProtocol:string == 'ropc'
| groupby $d.properties.userPrincipalName, $d.callerIpAddress as attempts count()
| filter attempts > 5
| orderby attempts desc | limit 100
```

Surfaces spray-targeted accounts regardless of ASN — useful for infrastructure not yet attributed to LSHIY.

**5.3.4 — Hourly spray-spike detection (last 30 days)**

```text
source logs
| filter $d.properties.authenticationProtocol:string == 'ropc'
| filter $d.resultType:string != '0'
| timechart count() by $d.properties.userPrincipalName span 1h
| filter count > 100
```

Spikes above ~100 failed ROPC attempts/hour per account indicate active spray targeting. Tune to your tenant baseline.

### 5.4 Hunt Hypotheses

- **H1 — Any successful ROPC at all.** *"Any `resultType == 0` sign-in with `authenticationProtocol == 'ropc'` in the last 30 days."* In most modern tenants the correct baseline is *zero*. Every hit is either a compromise or a legacy automation account you should be migrating off ROPC anyway.
- **H2 — "Other clients" against first-party CLI apps.** *"`clientAppUsed == 'Other clients'` targeting <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> / Azure PowerShell / Graph CLI client IDs."* Pivot to whether those clients are legitimately used in your environment.
- **H3 — Geo-impossible reuse.** *"A user account with a successful ROPC sign-in whose source ASN geolocates to two different countries within the campaign window."* Catches the China/US-Nebraska ambiguity directly.
- **H4 — Spray-then-succeed.** *"An account with hundreds of failed ROPC attempts followed by a single success."* The classic spray-validation fingerprint.

### 5.5 IOCs (from the Snowbit advisory)

| Type | Indicator |
|---|---|
| Source IPv6 range | `2a0a:d683::/32` |
| ASN | `AS32167` (LSHIY LLC, primary) · `AS955` (LSHIY LLC, secondary) |
| Infrastructure owner | LSHIY LLC — Hong Kong, Wuhan (China), 42 Broadway NY (shared office) |
| Auth protocol | <span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> ROPC → `/token` (`clientAppUsed: Other clients`) |
| Sign-in log signal | `authenticationProtocol: ropc` · `isInteractive: false` · `resultType: 0` |
| <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> signal | `authenticationRequirement: singleFactorAuthentication` · no `mfa` in `amr` |
| Credential source | Previously breached, unrotated username/password combo lists |

Treat IPs as rotatable; the **protocol + success + single-factor** behavioural signature is the durable detection, not the addresses.

---

## 6. Mitigation: What Actually Closes the Gap

### 6.1 Enforce Strong Client Auth for All Flows — The Architectural Fix

The root cause is that ROPC token issuance is allowed at all. The fix is a <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> grant that requires <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> (or blocks) for **All Users / All Cloud Apps / All Client App Types**, which forces `userStrongAuthClientAuthNRequired` and causes ROPC token requests to fail **before** a token is minted. This is the one control that breaks the attack class rather than chasing its symptoms.

Conceptually, the enforcement flips the Section-2 decision branch:

![Diagram](https://kroki.io/mermaid/svg/eNpVkM1uwjAQhO99ipW5FlVwAaKKKvydUEHApYo4OM4aLIKX2k5RVfXdu1lBq_rqmW9m1tZ0NUcdEiw3D8DP1DrGGVqgE1hX11kHR7bE0WNMgU6YdfpmqPvmv7bU1U1sLQ5w8Cs2wx72UMR5oTar9RTWq-0OnhJ_--cyPI0_dO0qKANqc8QKLoy8UqjUHrrdMUy-1DTPoOX5Awc69Al0k47iDfjeuMAuSwHy5RIsz4kv6lsSJ0yAVxLOtFC7NhJcjA1W4o7OH2pcaJMo5IxktDM6OfJqn2VZO6q1zgqVG0MNBxs6XwKdXcS74i_oDaPI54XaSttuWxNuFc8Ml1CjvacEJULkqGgdty8_oT2NMOkkyLmwFhydz7a7LWAIFAQgl4MKvTiRl6OM0t7gnfADEMCWsQ==)

A minimal policy shape (<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> `conditionalAccessPolicy`), scoped to everything with no location or group carve-outs:

```json
{
  "displayName": "Require MFA — All users, all apps, all client types (ROPC block)",
  "state": "enabled",
  "conditions": {
    "users":        { "includeUsers": ["All"] },
    "applications": { "includeApplications": ["All"] },
    "clientAppTypes": ["all"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

> **Roll out safely.** Do not flip an org-wide "All apps / all client types" policy straight to `enabled`. Stage it in **report-only**, run the **What If** simulator, identify service accounts and legacy automation that legitimately use ROPC, migrate or exempt them explicitly with a documented, monitored exclusion — *then* enforce. The whole point of this campaign is that report-only never protects anyone, so treat report-only as a *staging* state with a deadline, not a destination.

### 6.2 Block the "Other clients" Legacy App Type

ROPC surfaces in <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> under the **"Other clients"** legacy-authentication client-app type. A dedicated policy that **blocks "Other clients"** (and Exchange ActiveSync) for non-admin users removes the legacy-auth surface directly. If <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> is genuinely required for privileged workflows, carve those admins into a *separate, tightly scoped, monitored* policy rather than leaving the door open tenant-wide.

### 6.3 Restrict First-Party CLI Clients to the Accounts That Need Them

Most standard users never run <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span>. Require user assignment on the first-party CLI service principals and grant only the groups that need them — the same hardening we recommended for <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span>:

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All"

$azCliAppId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Microsoft Azure CLI
$sp = Get-MgServicePrincipal -Filter "appId eq '$azCliAppId'"
if (-not $sp) { $sp = New-MgServicePrincipal -AppId $azCliAppId }

# Require explicit assignment; users outside assigned groups can't get tokens for this client
Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AppRoleAssignmentRequired:$true

$group = Get-MgGroup -Filter "displayName eq 'cloud-admins'"
New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id `
    -PrincipalId $group.Id -ResourceId $sp.Id -AppRoleId ([Guid]::Empty)
```

Apply the same pattern to **Azure PowerShell** (`1950a258-227b-4e31-a9cf-717495945fc2`) and **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> CLI** (`14d82eec-204b-4c2f-b7e8-296a70dab67e`).

### 6.4 Reset Breached, Unrotated Credentials

The entire target population is *unrotated* leaked credentials. Cross-reference your users against breach data — **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> Protection leaked-credentials signals** and the **HIBP Enterprise API** — and force-reset any account that appears in a dump. This shrinks the exploitable set independent of the CA change.

### 6.5 Block the LSHIY Range, But Don't Rely On It

Block `2a0a:d683::/32` and the LSHIY ASNs at the firewall/proxy and as a CA named-location. Treat this as **containment, not prevention** — geolocation of these IPs is inconsistent (China *and* US-Nebraska), so location-only controls are unreliable by design, and the actor rotates infrastructure. The CA/strong-auth change (6.1) is what actually protects you; the block just reduces near-term noise.

### 6.6 Migrate High-Value Accounts to Phishing-Resistant MFA

**<span class="glossary-term" data-bs-toggle="tooltip" title="A phishing-resistant authentication standard combining the W3C WebAuthn API and the CTAP protocol for hardware-backed credentials. Resists credential phishing but does not protect post-authentication token theft.">FIDO2</span> passkeys** and **certificate-based authentication** are immune to credential stuffing because the secret is never shared with the identity provider — there is nothing in a combo list to replay. Prioritise administrators and other high-value identities. This is strategic, not a same-day fix, but it removes the credential-replay class entirely for the accounts that matter most.

---

## 7. Operational Playbook for SOC and IR

If Section 5 fires on a real account, work the timeline below. Because the token minted is a standard user-delegated token (and possibly a <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span>), your first hour is about **killing the session and rotating the credential** — in that order.

![Diagram](https://kroki.io/mermaid/svg/eNptU0Fu20AMvPcVPKaIhKRFe0lPjp00BprGiF0UPa53aYvwelcgqai-9RF9YV9SrhzbTRFdtOBSnBnOSGmLkRK-AXuUNCJ8md9Nf8AFPD7MxjB9hAl6EsoJFv_2CnodiueXcDbvvEcRCKhWxvB2aCkPo3RRF7sW4RLOgXPr7SWU1hHrlfOaGa5gwegUnIDPaUW8xWCnbct5S4IVpGyXsHW75UvsW2JRePcRtpQ6RTmiPuJT3qD1SSEuhrCv1Pfrb4I8p3Wapvn-Fv78-g0bilGARDqDdnsxxhZXxr8BtU_TafptZo_QOpE-cygSUQ1izBgwKblog2CTcp_qpQnzDYZPplydItDWxJGd4u4VKU3u-AgzIXFL82PwoXXaFIz9fmA8AlHOaV27zi4uYBmz38CDNsjgIxmPIgcwrQrZAGdlh4xtZq1ziruTQ3ddUojGiI14J2gon9m1TQU33-cVzBvHOMuUtIKHhBOmJzxsqEvB4AzzsOlXJL3_MKg6bW_UBVIzk-Iy_wTuIhZ_bKe942C5qMAk5TpgtDBV1sib2kltiwzP3b6kxTRRgp5SyP1_sy1EMiyg5G0__iv24Nr2eFXBbHpvMpSeXCFrhUCMJY67unwEvnFp_Rypg6JZFq0peSo-H0EXmFzSurdq8cUNHK5gFCOUsIm5U87jmLsAo7Y9FYpNpQLl_zAKB7eOo6-H-NT-lCzpEVubfje9npm-m6TsIKLbYHjRZgl3lmjnOZtRLg7Wmgt_AYMDTcg=)

The two non-negotiable first-hour actions:

1. **Revoke the user's sessions** (`Revoke-MgUserSignInSession`). This invalidates the access and refresh tokens the ROPC success produced. The user will re-authenticate — that's the correct trade.
2. **Force a password reset.** The credential is, by definition, in a public breach dump. Rotating it removes the oracle's answer. Pair with a hunt for anything the attacker did while holding the token: mailbox forwarding rules, mass downloads, new consents.

Then confirm the structural fix is actually *enforced* — the recurring finding across compromised tenants was policies stuck in report-only. A CA policy that logs the compromise but doesn't block it is not a mitigation.

---

## 8. The Wider Picture: "MFA Enabled" Is Not "MFA Enforced Everywhere"

LSHIY is not a clever new exploit. ROPC has been a known <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>-bypass footgun for years — Red Canary, Varonis, and Microsoft's own docs have all warned about it. What makes this campaign a threat-intel story worth your time is the **scale of the gap it revealed in the wild**: 81 million attempts, 64 organisations, every one of them believing <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> had them covered.

The strategic lesson maps cleanly onto the <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> lesson from earlier in this rotation. <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> abused *<span class="glossary-term" data-bs-toggle="tooltip" title="A Microsoft-published Entra ID application that is pre-consented in every tenant and cannot be deleted by tenant administrators.">first-party application</span> trust*; LSHIY abuses *authentication-flow coverage gaps*. Both exploit the space between "we turned the security feature on" and "we scoped it to cover every path an attacker can take." <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> is powerful precisely because it is granular — and granularity is exactly what leaves holes when policies are scoped to specific apps, specific groups, or "trusted" locations that geolocation can't reliably identify.

The audit every cloud-security program should run this quarter is a single question asked of each <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> policy: **"Does this enforce — not report — <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> or block for All Users, All Cloud Apps, and All Client App Types, with no location or group carve-out that a determined attacker could route through?"** If the answer for any policy is no, you have a ROPC-shaped hole, and combo lists of your users' old passwords are almost certainly already circulating. Close it before someone sprays it.

---

## Glossary

These terms are auto-tooltipped by the publishing pipeline; definitions are repeated here for the static reader.

- **ROPC (Resource Owner Password Credentials)** — A deprecated <span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> grant type where the client sends a raw username and password directly to the `/token` endpoint, skipping the interactive `/authorize` stage. Incompatible with <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>; Microsoft recommends against its use.
- **Password spray** — A brute-force variant that tries a small number of common or known passwords across many accounts (rather than many passwords against one account) to stay under lockout thresholds.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> Policy (CAP)** — <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span>'s policy engine that gates access based on user, app, device, location, and client-app-type signals. Evaluated per authentication flow, primarily at the authorization endpoint.
- **Authorization endpoint vs token endpoint** — `/authorize` handles interactive sign-in (where <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> and CA fire); `/token` issues tokens. ROPC posts straight to `/token`, bypassing the gate at `/authorize`.
- **`userStrongAuthClientAuthNRequired`** — The enforcement state that requires strong client authentication, causing ROPC-based token requests to fail before issuance. The control that closes the LSHIY gap.
- **"Other clients" (client app type)** — The <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> legacy-authentication category that covers protocols without modern-auth support, including ROPC. Blocking it removes the legacy-auth surface.
- **Non-interactive sign-in** — A sign-in with no user interaction, logged in `AADNonInteractiveUserSignInLogs`. ROPC successes appear here as `NonInteractiveUser` events.
- **`singleFactorAuthentication`** — The `authenticationRequirement` value indicating only one factor (password) satisfied the sign-in — the tell-tale of a successful ROPC compromise with no <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> claim.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> / <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>** — <span class="glossary-term" data-bs-toggle="tooltip" title="A phishing-resistant authentication standard combining the W3C WebAuthn API and the CTAP protocol for hardware-backed credentials. Resists credential phishing but does not protect post-authentication token theft.">FIDO2</span> passkeys and certificate-based auth bind authentication to a device-held secret that is never shared with the IdP, making credential replay (and therefore spraying) impossible.
- **Combo list** — An aggregated dump of `username:password` pairs from prior breaches, traded and reused by attackers; the exclusive fuel for this campaign.

---

## Sources & Further Reading

### Primary Source — This Campaign

- **Snowbit by Coralogix — *Threat Advisory: LSHIY Password Spray — <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> ROPC Attack Bypasses <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> at Scale*** — The internal threat-intelligence advisory that seeded this deep-dive; source of the timeline, IOCs, and DataPrime hunting queries. Distributed to Snowbit managed customers.
- [Huntress — LSHIY Password Spray Attack](https://www.huntress.com/blog/lshiy-password-spray-attack) — Originating public research; the 81M-attempt figure, 78 compromises / 64 orgs, and the misconfiguration breakdown.
- [Cyber Security News — Massive Password Stealing Attack Targeting Microsoft 365 Users With 81 Million Login Attempts](https://cybersecuritynews.com/microsofts-azure-password-spray-attack/) — Press corroboration of scope, LSHIY attribution, and the CAP failure modes (1 Jul 2026).
- [Security Boulevard — Massive Password Spray Campaign Targets Azure CLI](https://securityboulevard.com/2026/07/massive-password-spray-campaign-targets-azure-cli/) — Additional coverage and operational framing.

### ROPC, MFA, and the Protocol Gap

- [Microsoft Learn — Microsoft identity platform and OAuth 2.0 ROPC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc) — Microsoft's own "do not use this flow" guidance and its <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> incompatibility.
- [Varonis — When Passwords Win: A Deep Dive into ROPC-Enabled MFA Bypasses](https://www.varonis.com/blog/deep-dive-into-ropc) — Why ROPC bypasses <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> and how to test for it.
- [Red Canary — When MFA isn't an option: The legacy of ROPC](https://redcanary.com/blog/threat-detection/ropc-legacy-authentication/) — Detection-oriented background on ROPC and legacy auth.
- [Security Friends — Evading Entra ID Conditional Access via Cross-Tenant ROPC](https://blog.fndsec.net/2026/01/13/evading-entraid-conditional-access-policies-via-cross-tenant-ropc/) — A related cross-tenant ROPC bypass worth understanding when scoping CA.

### Detection and Configuration

- [Detect FYI — Abusing ROPC to Bypass MFA, and Building a Sentinel Detection](https://detect.fyi/abusing-ropc-to-bypass-mfa-and-how-i-built-a-detection-for-it-in-microsoft-sentinel-135e46aeb7c9) — <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> detection patterns for ROPC in Sentinel.
- [Microsoft Learn — Block legacy authentication with Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication) — How to block "Other clients" / legacy auth via CA.
- [Microsoft Learn — Password spray investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray) — Microsoft's <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> playbook for spray campaigns.
- [Elastic Security — Entra ID OAuth ROPC Grant Login Detected](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/azure/initial_access_entra_id_unusual_ropc_login_attempt) — Prebuilt detection rule for the same behaviour.

---

*Next week (rotation: Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel): back to the top of the rotation with a Cloud deep-dive — likely an Entra/AWS identity or Kubernetes-runtime story, chosen from the most operationally significant cloud incident of the week.*
