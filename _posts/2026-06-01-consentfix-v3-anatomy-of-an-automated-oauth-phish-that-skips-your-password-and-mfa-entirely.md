---
layout: post
title: "ConsentFix v3: Anatomy of an Automated OAuth Phish That Skips Your Password and MFA Entirely"
date: 2026-06-01
categories: [cloud-security, identity]
tags: [entra-id, oauth, conditional-access, mfa-bypass, azure-cli, threat-research]
author: Prakhar Gupta
description: "A technical deep-dive into ConsentFix v3 — how attackers abuse Azure CLI's first-party trust and OAuth 2.0 authorization codes to silently hijack Microsoft Entra ID accounts at scale, and what SOC teams can actually do about it."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.** <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3 is a fully automated <span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> *authorization-code* <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> toolkit that hijacks Microsoft <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> accounts **without stealing the password and without triggering an <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> prompt for the attacker**. The victim authenticates legitimately to a real Microsoft endpoint; the attacker walks away with the *<span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">authorization code</span>* and redeems it from their own infrastructure inside a ~10-minute window. Because the abused client is <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> — a Microsoft <span class="glossary-term" data-bs-toggle="tooltip" title="A Microsoft-published Entra ID application that is pre-consented in every tenant and cannot be deleted by tenant administrators.">first-party application</span>, pre-consented in every tenant — the attack is **architectural, not a CVE**. There is no patch. Mitigation requires explicit <span class="glossary-term" data-bs-toggle="tooltip" title="The local identity object created in an Entra tenant that represents an application instance. Required for assigning users and permissions to applications.">Service Principal</span> restriction, <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> (<span class="glossary-term" data-bs-toggle="tooltip" title="Proof-of-Possession. A token-binding scheme that requires the holder to cryptographically prove ownership of a device-bound key when using a token.">PoP</span>), and <span class="glossary-term" data-bs-toggle="tooltip" title="Security Operations Center. The team and tooling responsible for monitoring, detecting, and responding to security events across an organization.">SOC</span>-side correlation between interactive and non-interactive sign-ins for the same user across mismatched IPs.

---

## Watch the 6-Minute Walkthrough

For IT generalists, platform engineers, and anyone who wants the intuition before the technical depth: a short narrated walkthrough of the attack and what to do about it.

<!-- VIDEO_EMBED:START -->
<!--
  The Security Blog Automator pipeline replaces this block with the rendered
  <iframe> after NotebookLM Cinematic Video Overview generation completes.
  Expected replacement attributes:
    src       = https://www.youtube.com/embed/<video_id>
    title     = <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3 — Explainer (IT Generalists)
    poster    = /assets/img/2026-06-01-<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">consentfix</span>-v3-poster.jpg
  Source script: _video/script-<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">consentfix</span>-v3-explainer.md
-->
<div class="video-embed-placeholder" style="position:relative;padding-top:56.25%;background:#0b1220;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#cfd8e3;font-family:system-ui,sans-serif;">
  <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;padding:1rem;">
    <strong>Video rendering in progress.</strong><br/>
    A 6-minute narrated walkthrough of this article will appear here once the publishing pipeline completes the NotebookLM video step.<br/>
    <em>Source script:</em> <code>_video/script-<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">consentfix</span>-v3-explainer.md</code>
  </div>
</div>
<!-- VIDEO_EMBED:END -->

> *Prefer to read?* Skip the video and jump straight to [Section 1 — Why This One Matters](#1-why-this-one-matters).

---

## 1. Why This One Matters

Most "<span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>" coverage in the last few years has fixated on **illicit consent grants** — the attacker stands up a malicious multi-tenant app, tricks the user into clicking *Accept*, and walks off with delegated permissions. Defenders responded with admin consent workflows, app governance, and risky-app detections, and the technique's ROI fell.

<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> is the response to that response.

Instead of registering a malicious app, the attacker **borrows Microsoft's own <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> client identity**. There is no app to consent to, no <span class="glossary-term" data-bs-toggle="tooltip" title="The local identity object created in an Entra tenant that represents an application instance. Required for assigning users and permissions to applications.">service principal</span> to flag, no anomalous <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> grant to audit. The sign-in looks exactly like an administrator running `az login` from a new workstation — because, mechanically, it *is* an administrator running `az login`. The only difference is that the operator on the other end of the auth code isn't them.

<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3, observed in active operation throughout May 2026, takes that idea and **wraps it in automation**: a Cloudflare Workers–hosted <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> page, a <span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span> webhook backend that exchanges the code for tokens in under a second, and a Telegram or web dashboard that surfaces fresh refresh tokens to the operator in real time. The hand-off from victim click to attacker-controlled tenant access is now measured in seconds, not minutes.

For a Cloud Security or Detection Engineering team, the takeaway is uncomfortable but clear: **the trust model of first-party Microsoft applications is your attack surface now**, and every existing assumption baked into your <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> policies needs to be re-examined.

---

## 2. Background: How the Legitimate Flow Is *Supposed* to Work

To understand the abuse, you have to understand the flow it imitates. When an administrator runs `az login` on their workstation, the <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> executes the standard **<span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">Authorization Code</span> Flow with <span class="glossary-term" data-bs-toggle="tooltip" title="Proof Key for Code Exchange. A cryptographic binding between the authorization request and token redemption used to prevent authorization-code interception attacks for native public clients.">PKCE</span>** against Microsoft <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span>. It looks like this:

![Diagram](https://kroki.io/mermaid/svg/eNptU12P2jAQfOdX7COoENC11akRUOU4rkI9BOJ6z2hxFmI1sVPb6alU_e9dO-HjAJ6y9npmdmax9KsiJehR4s5g0QL-YeW0qooNmboUThtI0kIqQAuTXFdpXYbrEo2TQpaoHEyeZ74l2VeGfDHcmP64LXJJyq1lCoNPm8H9_ZfPvSiKOlevH4x-sw3p-flUOYMeN9c7qaJCCqOt3rLIXCqKhC6uniSr-UnIiqyujCCYo8IdmVpVEYqClUXo2zxOpxWQwnC98ZgniAH3NW-44ZPD-TdSZNARLL9PpvCbjNxKMvABRIZ5TmpHgefFsSxGEJhDLq3zr0AryJwr434_XGTaunhoUKW6WJfauPEZWeNKDIuSlM8m00buCV5Xzxf2dsFQKg0Jt66MHJ2gPWQXrNAljdiZfpTSFqucz4ROaX0UXEfSEDJ1MJ4nnf6A_pE49IQb7ghOxfDK_QoL4ulLtPZNm_RW2_wpObkD7YQhWbkU6BesrGzWhafZ4-KuC-REsyCHLBotEx7Rv8HcMpkHtOikZevfMx5d-zi44wWobQGnb_geDO9_9VaMhn7Mtf8cX3hRZ-6duOqEtsBqlznY_LkIunOWYzPAcvHCGE7_JBXi8whNDocd4vJ2pO8mDIL-8r9TkLXrAOi7t4ZsdihlWn_BvzMhvAExJE2cbJ7mZB4IDe_l8BytdoC7ewe2ZDljBltqZcm2_gNCHWSg)

Five things in that diagram matter for the attack we're about to dissect:

1. **`client_id` is constant and public.** <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span>'s first-party client ID — `04b07795-8ddb-461a-bbee-02f9e1bf7b46` — is the *same in every tenant*, on every workstation, in every country. You cannot delete it. You cannot block it from your tenant via standard means. It is pre-consented to all of `user_impersonation` on Azure Resource Manager.
2. **`redirect_uri` is `http://localhost:<random_port>`**. The Microsoft authorization server explicitly allows this for native public clients; it's the contract that lets `az login` work without an embedded webview.
3. **<span class="glossary-term" data-bs-toggle="tooltip" title="Proof Key for Code Exchange. A cryptographic binding between the authorization request and token redemption used to prevent authorization-code interception attacks for native public clients.">PKCE</span> is optional in the protocol but enforced by the client.** The CLI generates a fresh `code_verifier` and only that CLI instance knows it — *unless* the attacker can either coerce the victim's CLI into using the attacker's challenge, or use a flow that doesn't require <span class="glossary-term" data-bs-toggle="tooltip" title="Proof Key for Code Exchange. A cryptographic binding between the authorization request and token redemption used to prevent authorization-code interception attacks for native public clients.">PKCE</span> on redemption. <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> takes the latter route, as we'll see.
4. **The <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">authorization code</span> is short-lived (~10 minutes) but single-use across redemption attempts.** Whoever POSTs it first wins.
5. **Once the code is redeemed, the issued *<span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span>* is a <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> (Family-of-Client-IDs) <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span>.** That single token can be silently exchanged for access tokens against Outlook, Teams, OneDrive, SharePoint, and <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> — without any additional user interaction. The blast radius of one stolen <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> code is the entire Microsoft 365 stack.

---

## 3. The Attack: How ConsentFix v3 Inverts the Flow

The pivotal observation behind <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> is brutally simple: **the <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">authorization code</span> is delivered to the *browser*, not to the CLI.** The CLI catches it via a local HTTP listener — but if the listener never opens, or if the redirect points to a URI that doesn't have a listener, the code is *still issued*, still in the URL bar, and still valid for ten minutes.

If an attacker can convince the victim to copy that URL back to the attacker before the browser tab closes, the attacker holds the code. From there, redeeming it from anywhere on the internet is a single HTTPS POST.

Here's the full v3 attack chain:

![Diagram](https://kroki.io/mermaid/svg/eNptVO9PGzkQ_c5fMQoS3AnYLKQQSC895UK5VioiSlNaKTpVjnc2a8Vrr2ynQJU_vuPZ7ELo8SGsf8y8NzPvOdf2QRbCBZhd7wH9SS28v8YcfigZVAm50nqwj_28l-fHPji7wsH-ad4X2cWxtNq6wX666ImLxW60CEHIFbptfJ5jH_ttvLw8xVNs4s9FKlO5G1_6BvkqX-BVG3kmL8WZbJGxl6W4G6lM7kQLm18QzxY2vRRp2gS_Eb3zNN3j6Pv5fV3uWNt1BqOsVOa_wWBQN4GvfFo7nHcmhfKFMkvQtPxr4brvMFkmkIsVwng0mY0_jKBbL2-VdNbbPAA6Zx1fLqwPmIE1NVCuhUP4ah11ykNmS6FMJ-I27WPkf5x98OgaitvlK3rvTXBi3nkG5Q34eM242i6VScrm0BqtDCbSlnzaFetQWKd-IoOXnjN-mX6ad7ZgILLMofewEA6kNYGI-rqiEKpBt6utFDpWNzjQ4W1lXThYhrfdv6XNcJgmo292lCTJgQ8i4JC-XgJNBDVl3hlrJVc36hG-fIPg6HvAAIcTBv6qzNH0GKp4l_7xHpVI1IKlaT8e8uW7KRxyOgg0qFgC6YEu2DUp0boyXv6BTuVPh7_3eaKqOGH6pVpFCQ-4KKxdtWV6qjNW54ShUcX6kjKpmuuJwcA5WYCccGZX8049h24gBRpAk1WWGHHOyd3nGcQGwRHJV6EJ31UG6ZtF2u9fnb9q0rXwxbwzamyV0XJhhctIbTPUuHREeGHrxDfUnQJu7sYfwWHOC4b3v9c8mt5S1p8kZpiipzZJEq4wYkkYXfjXiapgBEGG7MJneilw0hbwhzBPDHOCRiw0Cdttc_zZUK_dBScn7zYyztezcTbsptZW9bETefTGsxiBRFp3v-3O8EV3-KQBHFIh241MOZRh2Cpy0zjmpZkiZG2RZ_cwDeGJI0kFJGUiUCW0p_nc3ow4_fZVjBzjoSQ5U0m4VLRL3_ppA_evMvbSM2hYwYMKBUfz4DdRoY3ZmBKL99kVnGCLKW2l8IWmq-YpisLesHpbGXMcPhIFwoxIx8Bqo7BaiVxMJKMMeCRHZ34T9drotu6FlGSz77V0j3YEVW_-DyoLtVUsp7EVOhGopWtP_HcSMA0i5ZWmduonoHc3bMW6ieLc-wXRBi4U)

Let's walk it stage by stage.

### 3.1 Stage 1 — Lure Delivery and the "ClickFix" Pattern

<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> inherits its name and UX from **<span class="glossary-term" data-bs-toggle="tooltip" title="A social-engineering pattern where the victim is shown a fake error and instructed to perform a &quot;fix&quot; action (paste-and-run, paste-into-form) that benefits the attacker.">ClickFix</span>**, the social-engineering pattern where the victim is shown a fake error message and instructed to "fix it" by performing some action — usually pasting a command into Run, into PowerShell, or into a form field. <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3 leans into two specific lures:

- **Fake CAPTCHA / "Verify you're human"** pages hosted on a Cloudflare Workers subdomain. The page tells the victim that Microsoft is rate-limiting them and they need to "verify" by signing in to Microsoft and pasting the resulting URL into a verification field.
- **Faked PDF previews** (PDFs hosted on Dropbox) that wrap a "click to view" button which kicks off the authorization request.

Crucially, the <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> page **never collects credentials**. It only collects the URL that the victim's browser ends up at *after they sign in to Microsoft*. This makes the <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> page itself completely benign to inspect — there's no harvested-credential leak that a content filter can fingerprint.

### 3.2 Stage 2 — The Malicious `/authorize` URL

When the victim clicks the lure, they're sent to a real `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize` URL constructed with parameters that look essentially identical to what <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> would build itself:

```
https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize
  ?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46
  &response_type=code
  &redirect_uri=http%3A%2F%2Flocalhost%3A8400
  &scope=https%3A%2F%2Fmanagement.azure.com%2F.default+offline_access+openid+profile
  &state=<attacker_generated>
  &prompt=select_account
```

Key points the <span class="glossary-term" data-bs-toggle="tooltip" title="Security Operations Center. The team and tooling responsible for monitoring, detecting, and responding to security events across an organization.">SOC</span> needs to internalise:

- **The destination is `login.microsoftonline.com`.** There is no domain to block. The URL is on Microsoft's own infrastructure and the TLS certificate is Microsoft's.
- **The `client_id` is the legitimate, pre-consented <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> ID.** No new app registration appears in your tenant. Nothing for App Governance or Defender for Cloud Apps to flag at the consent layer.
- **The `redirect_uri` is a localhost port.** Localhost is reserved for native public clients in the <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> spec. Entra will happily issue codes redirected here because it's the *correct* behaviour for the requested client.
- **The `scope` requests Azure Resource Manager** plus `offline_access` (which is what makes the response include a <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span>).

### 3.3 Stage 3 — Legitimate Authentication, Including MFA

This is the part that breaks most existing detection logic. The victim now authenticates **for real, against the real Microsoft endpoint**:

- Username + password are entered into Microsoft's actual login form.
- <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> is challenged and satisfied — Authenticator push, <span class="glossary-term" data-bs-toggle="tooltip" title="A phishing-resistant authentication standard combining the W3C WebAuthn API and the CTAP protocol for hardware-backed credentials. Resists credential phishing but does not protect post-authentication token theft.">FIDO2</span>, certificate, whatever the tenant requires.
- Any **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span>** that gates the *interactive* sign-in evaluates and passes, because the user is on a compliant device, from a trusted location, in a normal hour. Everything looks correct because everything *is* correct.

When the user completes authentication, Entra issues the 302 redirect. The browser now points at `http://localhost:8400/?code=0.AXoA...&state=...`, the browser tries to connect to localhost:8400, no listener answers (because there is no <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> running), and the user sees a "Site can't be reached" page **with the full URL — including the <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">authorization code</span> — sitting in their address bar**.

### 3.4 Stage 4 — Code Exfiltration

The <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> page reappears (or the victim navigates back to it) with instructions like *"Almost done. Copy the full URL from your address bar and paste it into the box below to complete verification."* Some v3 variants instead use a `Win+R` <span class="glossary-term" data-bs-toggle="tooltip" title="A social-engineering pattern where the victim is shown a fake error and instructed to perform a &quot;fix&quot; action (paste-and-run, paste-into-form) that benefits the attacker.">ClickFix</span> vector that pastes the URL into a <span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span>-controlled endpoint via a one-liner, bypassing the need for the victim to deliberately submit a form.

Either way, the captured URL is shipped to a **<span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span> webhook** — typically `https://<random>.m.pipedream.net/<path>`. <span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span>'s role here is critical and worth dwelling on: it is a **legitimate, free, low-friction serverless platform** that the attacker uses as their automation backplane. They don't need to stand up VPS infrastructure. They don't need a domain. They don't need to manage TLS. The traffic to a `pipedream.net` endpoint will not stand out in any meaningful way in your firewall logs unless you're explicitly tracking SaaS-automation domains.

### 3.5 Stage 5 — Automated Token Redemption

Within the <span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span> workflow, the attacker's pre-written automation runs in milliseconds:

```python
# Conceptual representation of the Pipedream workflow logic
import re, requests

def handler(pd):
    raw_url = pd.steps.trigger.event.body["captured_url"]
    code = re.search(r"[?&]code=([^&]+)", raw_url).group(1)

    token_resp = requests.post(
        "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
        data={
            "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8400",
            "scope": "https://management.azure.com/.default offline_access",
        },
    ).json()

    # FOCI refresh_token can now be exchanged for access tokens
    # against Graph, Teams, Outlook, OneDrive, SharePoint...
    pd.flow.exit(token_resp)
```

The response includes an **<span class="glossary-term" data-bs-toggle="tooltip" title="A bearer credential that an OAuth client uses to call a protected API on behalf of the authenticated user. Typically valid for 1 hour.">access token</span>** valid for ~1 hour against Azure Resource Manager and — because `offline_access` was requested — a **<span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span>** valid for up to 90 days (or until revocation/<span class="glossary-term" data-bs-toggle="tooltip" title="Continuous Access Evaluation. An Entra ID capability that allows critical security events (password change, risk events) to immediately invalidate tokens rather than waiting for expiration.">CAE</span>). The attacker's dashboard receives the tokens and the operator now has, effectively, the same authenticated session the victim has — minus the device, minus the <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> factor, minus the location.

### 3.6 Stage 6 — Lateral Movement via FOCI

The stolen <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> is a **family <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span>**. The attacker can immediately swap it for access tokens scoped to any other Microsoft first-party <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> client — Outlook, Teams, OneDrive, SharePoint, <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span>, even Visual Studio. From a single <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> code, the attacker now has the keys to the entire M365 stack for that user.

If the victim is a Global Administrator, Privileged Role Administrator, or an Application Administrator, the next 30 minutes typically look like: enumerate users, enumerate role assignments, add a backdoor user, consent a malicious multi-tenant app on the way out, and exfiltrate mail or SharePoint content via Graph in parallel.

---

## 4. Why the Usual Defences Don't Stop It

| Defence | Why it fails against <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3 |
|---|---|
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> enforcement** | The victim *does* <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>. The attacker never needs to. The token they replay was minted on the back of a real, <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>-satisfied sign-in. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> — device compliance** | The interactive sign-in occurs from the *victim's* compliant device. The CA evaluation happens at sign-in, not at token-redemption. By the time the attacker uses the <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> from their infrastructure, CA has already approved the session. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> — trusted location** | Same problem — evaluated at interactive sign-in, which is on the victim's IP. |
| **App consent governance / Admin consent workflow** | No app is being consented to. The <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> is already consented in every tenant by default. There is no consent event to gate. |
| **Defender for Cloud Apps anomaly detection** | The first detectable bad behaviour is a *non-interactive* sign-in for the same user from a different IP shortly after the interactive one — a signal that's noisy by default (it fires constantly for legitimate mobile mail clients, OS background services, etc.). |
| **Risk-based sign-in** | Sign-in risk is dominated by interactive-flow signals. The attacker's redemption call to `/token` doesn't carry user-agent risk signals — it's a back-end POST. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">Phishing</span>-resistant authenticators (<span class="glossary-term" data-bs-toggle="tooltip" title="A phishing-resistant authentication standard combining the W3C WebAuthn API and the CTAP protocol for hardware-backed credentials. Resists credential phishing but does not protect post-authentication token theft.">FIDO2</span>)** | Doesn't help. <span class="glossary-term" data-bs-toggle="tooltip" title="A phishing-resistant authentication standard combining the W3C WebAuthn API and the CTAP protocol for hardware-backed credentials. Resists credential phishing but does not protect post-authentication token theft.">FIDO2</span> binds the **authentication** to the device, but the <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">authorization code</span> that gets stolen here is a separate artifact issued *after* successful authentication. <span class="glossary-term" data-bs-toggle="tooltip" title="Proof-of-Possession. A token-binding scheme that requires the holder to cryptographically prove ownership of a device-bound key when using a token.">PoP</span> token binding (<span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span>) is what's needed, not <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant auth. |

The one defence that *does* fundamentally break the attack is **<span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> (Proof-of-Possession token binding)** — covered in Section 6.

---

## 5. Detection: SOC-Side Hunting and KQL Queries

The most reliable detection signal is the **temporal anomaly between an interactive and a non-interactive sign-in for the same user, against the <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> client, from mismatched IPs**. This won't catch every campaign — the attacker can use a residential proxy in the victim's region — but it catches the lazy/at-scale variants and is a high-fidelity starting point.

### 5.1 KQL — Mismatched Interactive vs Non-Interactive Sign-In for Azure CLI

Paste this into your Sentinel / Log Analytics workspace. Tune the time window (`lookback`) to your environment.

```kusto
// <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3 — interactive sign-in followed by non-interactive sign-in
// for the same user against <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> from a different IP within 10 minutes.
// <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> first-party client_id: 04b07795-8ddb-461a-bbee-02f9e1bf7b46
let lookback = 1d;
let suspect_app = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"; // <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span>
let interactive =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where AppId == suspect_app
    | where ResultType == 0
    | project i_time = TimeGenerated, UserPrincipalName, UserId,
              i_ip = IPAddress, i_country = LocationDetails.countryOrRegion,
              i_ua = UserAgent, i_session = tostring(parse_json(AuthenticationDetails)[0].correlationId);
let nonInteractive =
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(lookback)
    | where AppId == suspect_app
    | where ResultType == 0
    | project n_time = TimeGenerated, UserPrincipalName, UserId,
              n_ip = IPAddress, n_country = LocationDetails.countryOrRegion,
              n_ua = UserAgent;
interactive
| join kind=inner nonInteractive on UserId
| where n_time between (i_time .. i_time + 10m)   // within 10-min code lifetime
| where i_ip != n_ip                              // different source IP
| extend country_mismatch = tostring(i_country) != tostring(n_country)
| project i_time, n_time, UserPrincipalName,
          i_ip, n_ip, i_country, n_country, country_mismatch, i_ua, n_ua
| sort by i_time desc
```

### 5.2 KQL — High-Velocity FOCI Token Exchanges From a Single IP

If you suspect a campaign, hunt for an attacker IP that's redeeming tokens for many distinct users in a short window:

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where AppId == "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
| where ResultType == 0
| summarize distinct_users = dcount(UserId),
            distinct_uas = dcount(UserAgent),
            first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated)
            by IPAddress
| where distinct_users >= 3
| sort by distinct_users desc
```

### 5.3 KQL — Resource Pivots Off a Single Sign-In Session

<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span>'s <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> lateral-movement step means a single session correlation ID (the <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> `sid`) will fan out to multiple resource URIs (<span class="glossary-term" data-bs-toggle="tooltip" title="Azure Resource Manager. The control-plane API at management.azure.com that Azure CLI and Azure PowerShell use to manage Azure resources.">ARM</span>, Graph, Exchange, SharePoint) in short order:

```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend session_id = tostring(parse_json(tostring(AuthenticationDetails))[0].correlationId)
| where isnotempty(session_id)
| summarize distinct_resources = dcount(ResourceDisplayName),
            resources = make_set(ResourceDisplayName, 10),
            distinct_ips = dcount(IPAddress),
            ips = make_set(IPAddress, 10)
            by UserPrincipalName, session_id
| where distinct_resources >= 3 and distinct_ips >= 2
```

### 5.4 Hunt Hypotheses for the Threat Hunting Team

For teams running structured hunts (PEAK / TaHiTI methodology):

- **H1 — Localhost-Loopback <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">Phishing</span>**: *"A user authenticates to Entra against <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> / Azure PowerShell / Visual Studio Code from a workstation that has none of those clients installed."* Pivot: cross-reference sign-in events with <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> inventory of the source device.
- **H2 — Cross-Boundary Refresh**: *"An <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A bearer credential that an OAuth client uses to call a protected API on behalf of the authenticated user. Typically valid for 1 hour.">access token</span> is used against <span class="glossary-term" data-bs-toggle="tooltip" title="Azure Resource Manager. The control-plane API at management.azure.com that Azure CLI and Azure PowerShell use to manage Azure resources.">ARM</span> from an ASN/country that does not match the original interactive sign-in's ASN/country within the same refresh-token lineage."*
- **H3 — Family Token Spread**: *"A single user session results in token issuances against three or more distinct <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> resource principals within one hour."* False positives are non-trivial (Teams + Outlook + OneDrive is normal) — tune to *unattended workstation* user patterns.
- **H4 — <span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span> Egress**: *"Workstation tells DNS to resolve `*.m.pipedream.net` or `*.pipedream.workers.dev`, then within 60 seconds the same user has an <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> token redemption from a new IP."* Combines endpoint and identity telemetry.

### 5.5 IOCs Observed in v3 Campaigns

These are starting points — campaigns rotate infrastructure aggressively, so treat them as illustrative rather than authoritative:

- **Infrastructure**: `*.m.pipedream.net`, `*.pipedream.workers.dev`, Cloudflare Workers subdomains used as one-off lure hosts, Dropbox-hosted PDFs as lure delivery, ZoomInfo enrichment hits prior to <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>.
- **Sign-in log signature**: `AppId = 04b07795-8ddb-461a-bbee-02f9e1bf7b46` with `ResourceId = 797f4846-ba00-4fd7-ba43-dac1f8f63013` (Azure Resource Manager) where interactive and non-interactive events fork to different IPs.
- **User-Agent on redemption**: `python-requests/*` or generic `Mozilla/5.0` strings missing the platform fields that real <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> emits. Real <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> sends a recognisable `AZURECLI/<version> (<OS>)` UA on token POSTs.

---

## 6. Mitigation: What Actually Works

Mitigation is layered. There is no single switch.

### 6.1 Token Protection (Proof-of-Possession) — The Architectural Fix

<span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> binds the issued access/refresh tokens cryptographically to the originating device's TPM-backed key. A stolen <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">authorization code</span> redeemed from an attacker's <span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span> workflow **cannot produce a usable token** because the broker-signed proof of possession is missing.

This is the only mitigation that addresses the root cause. It requires <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> Premium P1/P2 and is enabled via a <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> policy in the **Session** controls.

![Diagram](https://kroki.io/mermaid/svg/eNpVkD1PwzAQhnd-xUkdWCioXdpGqCj9YgEUVV1Q1MGxz4pJ4itnB6go_x3HrVrwZvm953nPuqZPWQr28LS-gnBkLZxboAaqQJu6Tno40QVObpxnqjDpDeVYDOX_bCHUKaw1jnB0DsvxAAcYw2metr4ESQrBearR3hd8Ny32MCfr0PqV-dpCvz-F2fcmDFvImDxKb-iYRKuJJaqHn8ibhSy8UJyY56n3QlbIwKgQGxcnNFMDmdmhYhRNgN_2pwffsR0Y51pUB1jkqZTUWg-leQuIbZIkYZ2L4hVddCzzY6tO0OzOrRjfW8Mhk1EGOybS0Gnj24cJ7ZtrB5vsuV8EiYIK952BqihYRvLq0l4Ka8l3HNVKjBBf4h8uhKthMFazOP7WY74-NwKF1qA6GX4BSfGc0Q==)

### 6.2 Service Principal User Assignment for First-Party Apps

This is the **highest-impact configuration change** available without P1/P2. Pre-create the service principals for the abused first-party apps in your tenant, set them to "require user assignment," and assign only the security groups that legitimately need them. Anyone outside those groups can no longer obtain tokens for those clients — including via <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span>.

The minimum useful set:

| App | Client ID | Why |
|---|---|---|
| Microsoft <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Primary <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> target |
| Microsoft Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` | Equivalent abuse path |
| <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> Command Line Tools | `14d82eec-204b-4c2f-b7e8-296a70dab67e` | Equivalent abuse path |
| Visual Studio Code | `aebc6443-996d-45c2-90f0-388ff96faa56` | Increasingly abused variant |

PowerShell to create and lock down the <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> <span class="glossary-term" data-bs-toggle="tooltip" title="The local identity object created in an Entra tenant that represents an application instance. Required for assigning users and permissions to applications.">service principal</span> in a tenant that doesn't already have one:

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Create the SP for Azure CLI (idempotent)
$azCliAppId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
$sp = Get-MgServicePrincipal -Filter "appId eq '$azCliAppId'"
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $azCliAppId
}

# Require user assignment
Update-MgServicePrincipal -ServicePrincipalId $sp.Id `
    -AppRoleAssignmentRequired:$true

# Assign only the 'cloud-admins' group
$group = Get-MgGroup -Filter "displayName eq 'cloud-admins'"
New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id `
    -PrincipalId $group.Id -ResourceId $sp.Id -AppRoleId ([Guid]::Empty)
```

### 6.3 Conditional Access Targeting the Abused Apps

For tenants that do need broader <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> access, you can scope a CA policy to the abused first-party app IDs and require **device compliance + trusted location**. This won't stop the interactive sign-in (which is from the legitimate user) but it can block subsequent non-interactive token usage from non-compliant or out-of-region origins. Pair with <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> for full coverage.

### 6.4 Egress Controls and Domain Awareness

Add `*.m.pipedream.net`, `*.pipedream.workers.dev`, and `*.workers.dev` to your **SaaS automation watch list**. These are legitimate services and you can't blanket-block them, but you can prioritise alerts on workstation egress to them, especially when correlated to recent Entra sign-in events for the same identity.

### 6.5 User Awareness — The Underrated Lever

<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> collapses the entire phish into a single UX moment: *"copy this URL from your address bar and paste it here."* Train administrators specifically on this pattern. Any time a non-Microsoft website asks them to paste a `login.microsoftonline.com` redirect URL — or any URL containing `code=` — that is the indicator. The legitimate <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span> flow never asks the user to do this.

---

## 7. Operational Playbook for SOC and IR

If the detections in Section 5 fire on a real account, the timeline matters:

![Diagram](https://kroki.io/mermaid/svg/eNpdksFu2zAMhu99iv80bIgLJF2Hob1laTMEWLAgSR9AsFibqC0Zomw3lz77KMdNsugmUuTH_6ci11SxoxvoiRwrwsI7IReX_I7uO1ZbPFHOwt5hf_lYKI9DcDLF14W3hNw0sQ1kvw35dOZtLJGnXGcqtphNUbPDI-YxmvyNAkoj-BjD0UOrieqr_rOppNx-8qM-dd5wQzaQqccSOWIesaXXQFJqwRs5ON-DRVqy2ThC26ReD1NYc5BrUH3kzMoT54-JFEyF5d_FCvSel8YVdCmg4c7HYb7fwTRlhr0OJRmex7cZdqUJtPHs4jWuPOLu7s-8J5bcdxQO-IKGgrBEcnki_lKe9T6gFQqZyh22BP-KWoXl7FuBaZpMr1whtBX9L08X2bOzvj-xttSpSWrghWMyWJjit-viRUk7LtzK7UiGHzDR10IR6-X8YsmW4-c8Yz1TD0d9dfiMk03DCdKaS0JlJOLneQfnPk3gjisqtCB4_Y1GwYWrx9ab1RpG9XQmaVKbFQLLQTV69SxVyM0_SfDpfg==)

The two non-negotiable <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> actions in the first hour:

1. **Revoke all refresh tokens for the affected user** (`Revoke-MgUserSignInSession`). This invalidates the <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> token the attacker minted. Note: this revokes *the user's* tokens too, so they will need to re-authenticate. That's the right trade.
2. **Force a password reset and re-enrol <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>**. The attacker's existing token is now dead, but you don't want them to re-phish the same identity with the same payload.

Then, in parallel:

- Review **last 24 hours of consent grants** (`Get-MgOauth2PermissionGrant`, filter on `createdDateTime`) — attackers often consent a backdoor multi-tenant app on their way out, because that grant survives the password reset.
- Review **directory role assignments and PIM activations** for the affected user since the breach window.
- Review **Exchange transport rules** the user created (mail forwarding, mark-as-read auto-rules).
- Review **SharePoint and OneDrive sharing events** initiated by the user in the breach window.

---

## 8. The Wider Picture: First-Party Trust as Attack Surface

<span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> is not an isolated incident. It's an instance of a **class of techniques** that treat Microsoft's first-party client identities as a tool the attacker can pick up off the shelf. Device Code Flow <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> did the same thing in 2020-2022. Token Tactics V2 and ROADtools weaponised the <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> behaviour. <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3 is the productisation of these ideas into a turnkey criminal toolkit.

The strategic question every cloud-security program needs to answer in 2026 is: **"Which first-party Microsoft applications does my tenant *actually need*, and have I scoped them down accordingly?"** The default — that every first-party app is trusted by every user in every tenant — is no longer a safe default. It's the attack surface.

Plan to require user assignment for at least <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span>, Azure PowerShell, <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> CLI, and Visual Studio Code in every tenant by end of Q3 2026. Plan to roll out <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> wherever P1/P2 licensing permits. And build the interactive-vs-non-interactive correlation detection into your SIEM today — it's the single highest-fidelity detector for this whole technique family.

---

## Glossary

These terms are auto-tooltipped by the publishing pipeline; definitions are repeated here for the static reader.

- **<span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> <span class="glossary-term" data-bs-toggle="tooltip" title="A short-lived (typically 10-minute) one-time code issued by an OAuth authorization server that a client redeems for an access token at the token endpoint.">Authorization Code</span> Flow** — Standard <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> flow where the user authenticates to an authorization server, which issues a short-lived *code* redirected to the client, which the client exchanges for tokens.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Proof Key for Code Exchange. A cryptographic binding between the authorization request and token redemption used to prevent authorization-code interception attacks for native public clients.">PKCE</span>** — *Proof Key for Code Exchange*. A cryptographic binding between the authorization request and the token redemption that prevents code interception attacks for native public clients. Critical when present, but bypassable for public-client flows that don't require it.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A Microsoft-published Entra ID application that is pre-consented in every tenant and cannot be deleted by tenant administrators.">First-party application</span>** — A Microsoft-published <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> application that is pre-consented in every tenant and cannot be deleted by tenant admins.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span>** — *Family of Client IDs*. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s first-party command-line interface for Azure. Pre-consented in every Entra tenant with the client ID 04b07795-8ddb-461a-bbee-02f9e1bf7b46.">Azure CLI</span>, Graph CLI, etc.) whose refresh tokens are interchangeable — a <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> issued for any one can be exchanged for an <span class="glossary-term" data-bs-toggle="tooltip" title="A bearer credential that an OAuth client uses to call a protected API on behalf of the authenticated user. Typically valid for 1 hour.">access token</span> for any other.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> (<span class="glossary-term" data-bs-toggle="tooltip" title="Proof-of-Possession. A token-binding scheme that requires the holder to cryptographically prove ownership of a device-bound key when using a token.">PoP</span>)** — <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> feature that binds tokens cryptographically to a device-bound key, preventing token replay from non-originating devices. Requires <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> P1/P2.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A social-engineering pattern where the victim is shown a fake error and instructed to perform a &quot;fix&quot; action (paste-and-run, paste-into-form) that benefits the attacker.">ClickFix</span>** — Social-engineering pattern where the victim is shown a fake error and instructed to perform a "fix" action (paste-and-run, paste-into-form, etc.) that benefits the attacker.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span>** — <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> policy engine evaluated at interactive sign-in (and selectively on token use) that gates access based on user, device, location, app, and risk signals.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A free SaaS workflow automation platform whose serverless webhook endpoints have been adopted as low-effort attacker C2 infrastructure by toolkits including ConsentFix v3.">Pipedream</span>** — A free SaaS workflow/automation platform whose serverless webhook endpoints have been adopted as low-effort <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span>-ish infrastructure by criminal toolkits including <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span> v3.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Continuous Access Evaluation. An Entra ID capability that allows critical security events (password change, risk events) to immediately invalidate tokens rather than waiting for expiration.">CAE</span>** — *Continuous Access Evaluation*. Entra capability that allows critical security events (password change, risk events) to immediately invalidate tokens rather than waiting for them to expire.

---

## Sources & Further Reading

### Primary Research and Technical Analysis

- [ConsentFix v3: Automated OAuth Abuse Targets Microsoft Azure and Entra ID — Rescana](https://www.rescana.com/post/consentfix-v3-automated-oauth-abuse-targets-microsoft-azure-and-entra-id-bypassing-mfa-and-conditional-access) — End-to-end walkthrough of v3 automation and infrastructure.
- [ConsentFix v3: Analyzing a new criminal toolkit — Push Security](https://pushsecurity.com/blog/consentfix-v3-analyzing-a-new-toolkit) — In-depth toolkit analysis with operator workflow details.
- [ConsentFix debrief: Insights from the new OAuth phishing attack — BleepingComputer](https://www.bleepingcomputer.com/news/security/consentfix-debrief-insights-from-the-new-oauth-phishing-attack/) — Industry-press summary and timeline.
- [ConsentFix v3 attacks target Azure with automated OAuth abuse — BleepingComputer](https://www.bleepingcomputer.com/news/security/consentfix-v3-attacks-target-azure-with-automated-oauth-abuse/) — The May 2026 surge coverage.
- [ConsentFix v3 Automates OAuth Abuse to Bypass MFA and Hijack Azure Accounts — Security Boulevard](https://securityboulevard.com/2026/05/consentfix-v3-automates-oauth-abuse-to-bypass-mfa-and-hijack-azure-accounts/) — Operational impact framing.
- [ConsentFix: Browser-native ClickFix hijacks OAuth grants — Push Security](https://pushsecurity.com/blog/consentfix) — The original v1 disclosure and pattern description.
- [ConsentFix: How a New OAuth Attack Bypasses Microsoft Entra Conditional Access — glueckkanja](https://www.glueckkanja.com/en/posts/2025-12-31-vulnerability-consentfix) — Excellent technical breakdown with PoC URLs and the first-party trust analysis.
- [ConsentFix OAuth Phishing Explained — Mitiga](https://www.mitiga.io/blog/consentfix-oauth-phishing-explained-how-token-based-attacks-bypass-mfa-in-microsoft-entra-id) — Detection-focused write-up.
- [ConsentFix v3: The OAuth Attack That Skips Your Microsoft Password — gblock](https://www.gblock.app/articles/consentfix-v3-azure-cli-oauth-microsoft-365-phishing) — Plain-language walkthrough and admin guidance.
- [Azure CLI Trust Abused in ConsentFix Account Takeovers — eSecurity Planet](https://www.esecurityplanet.com/threats/azure-cli-trust-abused-in-consentfix-account-takeovers/) — Sector-impact summary.

### Detection and Hunting Resources

- [ConsentFix (a.k.a. AuthCodeFix): Detecting OAuth2 Authorization Code Phishing — NVISO Labs](https://blog.nviso.eu/2026/01/29/consentfix-a-k-a-authcodefix-detecting-oauth2-authorization-code-phishing/) — <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> queries and detection patterns.
- [Entra ID OAuth Authorization Code Grant for Unusual User, App, and Resource — Elastic Security](https://www.elastic.co/guide/en/security/8.19/entra-id-oauth-authorization-code-grant-for-unusual-user-app-and-resource.html) — Elastic detection rule for the same behavioural pattern.
- [3 Recent OAuth TTPs + How to Detect Them with Entra ID Logs — Wiz](https://www.wiz.io/blog/recent-oauth-attacks-detection-strategies) — Broader <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span>-attack detection framing.
- [ConsentFix: Securing Your Tenant Against OAuth Authorisation Code Theft — Sentinel.blog](https://sentinel.blog/consentfix-securing-your-tenant-against-oauth-authorisation-code-theft/) — Sentinel-focused detections and CA recommendations.

### Mitigation and Configuration

- [How to Mitigate ConsentFix Attack in Microsoft 365 — Admindroid](https://blog.admindroid.com/how-to-mitigate-consentfix-oauth-attacks-in-microsoft365/) — Step-by-step admin mitigation guide.
- [ConsentFix - The Quickfix — MSEndpointMgr](https://msendpointmgr.com/2026/01/08/consentfix-quickfix/) — Quick mitigation reference for Intune-aware admins.
- [How Token Protection Enhances Conditional Access Policies — Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection) — Microsoft's documentation on <span class="glossary-term" data-bs-toggle="tooltip" title="Proof-of-Possession. A token-binding scheme that requires the holder to cryptographically prove ownership of a device-bound key when using a token.">PoP</span> token binding.
- [ConsentFix debrief: insights, recommendations & predictions — Push Security](https://pushsecurity.com/blog/consentfix-debrief) — Forward-looking guidance.

### Background: First-Party Trust and FOCI

- [Abusing Family Refresh Tokens for Unauthorized Access and Persistence in Azure AD — TROOPERS22](https://troopers.de/downloads/troopers22/TR22_AbusingFamilyRefreshTokens.pdf) — The canonical research paper on <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> abuse.
- [secureworks/family-of-client-ids-research — GitHub](https://github.com/secureworks/family-of-client-ids-research) — Active reference for <span class="glossary-term" data-bs-toggle="tooltip" title="Family of Client IDs. A set of related Microsoft first-party clients (Outlook, Teams, OneDrive, Azure CLI, Graph CLI) whose refresh tokens are interchangeable across the family.">FOCI</span> client IDs and behaviour.
- [Weaponizing Legitimate Flows: OAuth Token Abuse and Device Join Exploitation in Microsoft Entra ID — CWL](https://cyberwarfare.live/weaponizing-legitimate-flows-oauth-token-abuse-and-device-join-exploitation-in-microsoft-entra-id-part1/) — Broader <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> abuse landscape.
- [Approved by Design. Abused by Attackers: Inside Device Code Flow Exploitation — Guardz](https://guardz.com/blog/approved-by-design-abused-by-attackers-inside-device-code-flow-exploitation/) — Sister technique to <span class="glossary-term" data-bs-toggle="tooltip" title="An OAuth 2.0 authorization-code phishing technique disclosed in late 2025 that abuses Microsoft first-party application trust to hijack Entra ID accounts without password or MFA theft.">ConsentFix</span>.

---

*Next week (rotation: Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel): a deep-dive on the Megalodon <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> mass-poisoning event and what a defensible <span class="glossary-term" data-bs-toggle="tooltip" title="GitHub&#39;s CI/CD platform. Workflows triggered by repository events run on hosted or self-hosted runners and often carry secrets with broad cloud-account access.">GitHub Actions</span> security posture looks like in 2026.*
