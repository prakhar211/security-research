---
layout: post
title: "TheHatman's Rolodex: How Infostealer-Sourced Credentials Turned Nine Fortune 500 Azure Tenants Into a Directory Fire-Sale"
date: 2026-08-16
categories: [cloud, security]
tags: [entra-id, infostealer, token-theft, directory-enumeration, microsoft-graph, bec, detection-engineering]
author: Prakhar Gupta
description: "A technical deep-dive into the August 2026 'TheHatman' Azure directory-exfiltration campaign — how stolen employee credentials and session tokens become millions of enumerated directory records, and the detections and controls that actually blunt it."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.** In the week of 11 August 2026 a <span class="glossary-term" data-bs-toggle="tooltip" title="An individual or a group of individuals that takes action to cause a malicious incident, or to pose a threat to the security of an organization&#39;s network.">threat actor</span> calling themselves **"TheHatman"** began listing **internal employee-directory records** for sale on **BreachForums**, claiming they were pulled straight from the victims' **Azure/Entra tenants using compromised credentials**. The listings were flagged publicly by CTI firm **S2W (@S2W_DailyThreat)** and, separately, by Hudson Rock. Named victims include **McDonald's (~1.7M records), TCS (~800K), Vodafone (~425K), HCL (~250K), IHG (~185K), Kyndryl (~170K), Gap (~80K), Hexaware (~20K), and Wyndham (~9K)**. Two things to hold in tension: **the intrusion vector is contested** — Hudson Rock found **infostealer-sourced Azure credentials** linked to most affected companies, while the actor's own BreachForums listing claims **password spraying + <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> fatigue** — and **several named victims (TCS, HCL) publicly dispute the framing**, saying the data appears **4+ years old** with **no evidence of a systems breach**. Both camps agree on one thing: this is **credential abuse, not an Azure <span class="glossary-term" data-bs-toggle="tooltip" title="A computer-software vulnerability that is unknown to, or unaddressed by, those who should be interested in mitigating the vulnerability.">zero-day</span>** (the exclusively-huge-enterprise victim profile argues against a platform flaw). The exfiltrated data is *directory metadata*, not passwords — but full names, UPNs, employee IDs, manager chains, group memberships, **service accounts, and Global Administrator listings** are a precision targeting map for BEC, spear-<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>, and privilege escalation. The single highest-value control is **<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> + <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span>** (kills replay) with **number-matching <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> + smart lockout** (blunts spray/fatigue), backed by **detecting bulk <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> directory enumeration** in your logs.

---

## Watch the 6-Minute Walkthrough

For IT generalists, platform engineers, and anyone who wants the intuition before the technical depth: a short narrated walkthrough of how a single infected laptop becomes a million-row directory dump for sale — and what to do about it.

<!-- VIDEO_EMBED:START -->
<!--
  The Security Blog Automator pipeline replaces this block with the rendered
  <iframe> after NotebookLM Cinematic Video Overview generation completes.
  Source script: _video/script-thehatman-azure-entra-directory-exfiltration-infostealer.md
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

There is no CVE here, no clever exploit, no novel malware. That is exactly why it deserves a deep-dive. TheHatman's campaign is a clean demonstration of the most boring and most effective cloud attack there is: **someone logged in as a real employee and pressed "export."**

The scale is what makes it notable. Nine named Fortune 500-class enterprises, across IT services, hospitality, telecom, retail, and logistics, with record counts that map closely to their global headcounts — 1.7 million for McDonald's, 800,000 for TCS, hundreds of thousands each for Vodafone, HCL, IHG, and Kyndryl. Researchers who reviewed the samples judged them highly authentic: corporate email addresses, tenant-specific `.onmicrosoft.com` structures, and field names that line up precisely with standard Entra directory exports.

The uncomfortable part for defenders is that **none of this is "hacking" in the way a board expects it to look.** A directory export is a routine administrative action. Reading the user list is something Entra permits *every member of the tenant* to do by default. The attacker didn't break Azure; they borrowed an employee and used Azure exactly as designed.

And the payload — a corporate directory — is easy to underrate because it contains no passwords and no financial data. That underrating is the mistake. A complete, structured, current org chart with job titles, reporting lines, group memberships, **service-account names, and the actual list of Global Administrators** is the single most useful reconnaissance artifact an attacker can hold before a BEC, spear-<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>, or <span class="glossary-term" data-bs-toggle="tooltip" title="A type of malware from cryptovirology that threatens to publish the victim&#39;s personal data or perpetually block access to it unless a ransom is paid.">ransomware</span> operation. TheHatman isn't selling a breach. They're selling everyone else's target package.

---

## 2. What Was Taken, and From Whom

The forum listings, per Hudson Rock's reporting, break down as follows:

| Organization | Sector | Records offered |
|---|---|---|
| McDonald's Corporation | Hospitality / QSR | ~1,700,000+ |
| Tata Consultancy Services (TCS) | IT services | ~800,000+ |
| Vodafone | Telecom | ~425,000+ |
| HCL Technologies | IT services | ~250,000+ |
| InterContinental Hotels Group (IHG) | Hospitality | ~185,000+ |
| Kyndryl | IT services | ~170,000+ |
| Gap Inc. | Retail | ~80,000+ |
| Hexaware Technologies | IT services | ~20,000+ |
| Wyndham Hotels | Hospitality | ~9,000+ |

Across the dumps, the leaked fields are consistent with a standard Entra directory export, and cluster into three tiers of usefulness to an attacker:

- **Core identity & contact:** full name, corporate email (with active domains and `.onmicrosoft.com` tenant structure), phone numbers, physical addresses.
- **Organizational structure:** employee IDs, job titles, departments, free-text notes, manager details, and direct reports — i.e., a machine-readable org chart.
- **Access & group mappings:** user group memberships, **service accounts**, and **highly privileged account records, including Global Administrator listings**.

That third tier is what turns a mailing list into a weapon. Knowing *who* the Global Admins are, and *what* the service accounts are named, hands an initial-access broker or <span class="glossary-term" data-bs-toggle="tooltip" title="A type of malware from cryptovirology that threatens to publish the victim&#39;s personal data or perpetually block access to it unless a ransom is paid.">ransomware</span> affiliate a prioritized target list before they've sent a single phish.

### 2.1 Corroboration and Attribution

The campaign has now been reported from more than one direction, which raises confidence that the listings are real even while the details remain contested:

- **Where:** The dumps were posted on **BreachForums** under the handle **"TheHatman."** For the TCS listing, the seller attached a **proof-of-concept sample of ~6,000 records** and advertised buyer contact over **Session, Tox, and Jabber**, noting that additional corporate dumps were available on request. The Kyndryl listing (first surfaced around **31 July 2026**) reportedly shipped a **~2,200-record sample that specifically called out Global Admin accounts**.
- **Who flagged it:** Threat-intel firm **S2W** publicized the TCS listing via its **@S2W_DailyThreat** handle on X, which is what prompted TCS's own disclosure. **Hudson Rock** independently reported the broader multi-victim campaign and the infostealer-credential linkage.
- **Corroboration gap:** The larger figures — notably **McDonald's (~1.7M)** and **Vodafone (~425K)** — currently rest primarily on Hudson Rock's reporting of the forum listings; I could not find independent confirmation from those companies or a second research vendor at the time of writing. (Note: a separate, unrelated 2025 McDonald's incident involving the *McHire* applicant chatbot is a different event — don't conflate the two.) Treat all record counts as **actor claims relayed by researchers**, not confirmed breach totals.

### 2.2 The Competing Attack-Vector Claim

The most important analytical nuance is that **the "how" is disputed**, and the two published hypotheses point at different controls:

| Hypothesis | Source | Implication for defenders |
|---|---|---|
| **Infostealer-sourced credentials / session tokens** | Hudson Rock (found stealer-linked Azure creds for most victims) | Prioritise token binding, <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>, dark-web credential monitoring, endpoint hygiene. |
| **Password spraying + <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> fatigue** | TheHatman's own BreachForums listing (per TCS's disclosure) | Prioritise number-matching <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>, smart lockout, legacy-auth blocking, and spray detection. |

These are **not mutually exclusive** — a real operation could spray to find valid passwords *and* buy infostealer logs to skip <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> where a session token is available. The defensive takeaway is to cover **both** paths rather than betting on one. The detection and mitigation sections below now address each.

### 2.3 The Victims' Pushback

Several named organizations have publicly disputed the severity, and their responses deserve equal billing:

- **TCS** told the BSE it found **no credible evidence of a breach of its systems or customer environments**, said the data **"appears to be" more than four years old** and limited to basic employee details, and stated it has had **safeguards against password spraying and <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> fatigue for over two years** that remain effective "based on the current review." Note the carefully qualified language ("not found," "no indication," "based on the current review") consistent with an early SEBI Regulation 30 disclosure made before a full forensic conclusion.
- **HCLTech** similarly indicated the referenced data **may be years old**.

This matters for how you weight the story: it is plausible that **some listings are repackaged older directory exports** rather than fresh 2026 exfiltration. That does **not** make the data harmless — a four-year-old org chart is still an excellent <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> kit, and stale service-account/admin names often persist — but it does mean "TheHatman breached Company X this week" is **not** an established fact for every victim. Report it as *claimed*, defend as if it's *live*.

---

## 3. The Assessed Kill Chain

**Important framing.** The exact intrusion vector is **not conclusively established**, and as noted in Section 2.2 the two published hypotheses differ: Hudson Rock corroborated **infostealer-sourced Azure credentials** for most affected companies, while the actor's own listing claims **password spraying + <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> fatigue**. Both converge on the same conclusion — the victim profile (exclusively very large enterprises, not a broad cross-section including SMBs) argues **against** a systemic Azure vulnerability and **for** targeted abuse of stolen or sprayed credentials. The chain below models the **infostealer path** because it is the better-corroborated and harder-to-detect of the two; the spray/fatigue variant simply swaps Phases 1–2 (an attacker guesses or fatigues their way to a valid session instead of buying it) and rejoins at Phase 3. It is an **assessed model**, not a confirmed forensic reconstruction.

![Diagram](https://kroki.io/mermaid/svg/eNptU8FuGzcQvfsrBvIhCSJ7V3FjOUIQILacNE1dF5bRIhByGHGHEiEuuRhyrTpNgf5D_7Bf0iEZKXIaHbSzw503b-Y9aus3aoUc4XZ6APJTFkOYkoY7o6JpQRtrJ4c01idaD0Nkv6bJ4UiPsTkdKm89Tw7rxQmeLh5WY4yo1sRf6rWmMY139epsRCPa1j_HWtXqYX0btp1f6AW92FU-U2f4TO0600lT08NK4zTjrq0-FZ67tvUZ1vW2-Ac8eV7XB7n6su3mA_mz_p4IyDWdNy6-XHD16nHvWnS4pAYqOP9wPZWH8i4yquj5yeDjZDIpu8pIs0hoieeDd077UF4SJ5IvvCuIitNuGghexw0yDaFFe0ccTTBuOQSNa4K-azBSwd9uM3f42fs4H8yit-TAysskowa8E8gro9gnXFBMTYCn-WzBfhOER6AQhEXFpJnCSubwa0Ph_z2ukNckXS4EhFw0aCvrl0IzpTuLijKuZ2gMy2jgO2KUfUAfKMNlGcpu067mg6_McgLeTTOEwBp33G4PvbPG0bHybUZpQ4Z4rZQw_3NQnoBqZUimLYNH0dYBk9C6h-ubnOvEDBvPDTyFDeG6ch6u3rwe_PXtnG8Zu9U-t5yAKoMUnp3niPbLnJ7vpRM2--Qu_0ifzAfnvV2Ldfo2bUK2XNhVshAOQ6iW7PsuBTukG1EwDIt4xOIh-pWNU6ZD-x1Jpn3y6Cxyr2IvsuwxauSoOOti9lv10-z6lyGM6vf__v3P6Hh8BUn87_jojee-FYnvF8SKTUugUwasCVFsWAAf3a7oR4xyAx49-UbXqd84uVmEAvI7Yeed-bQ3-PnlxRBCR8hH3cqEVXJ20YbNnbG0pCMKCm0ugYi8pNT2Ic_t5YSjo1fbq5XjdAlyUJyaw-KOPcOk7Gfs4ypZWMltEuuEpJ9NNuXPxYlfTZpRigNSVITNYVp-DvLSSmo3_sF_B3jDAg==)

The chain has three phases worth separating because the defenses differ for each: **credential capture** (endpoint problem), **access** (identity problem), and **enumeration + exfiltration** (cloud-telemetry problem).

### 3.1 Phase 1 — Credential Capture on the Endpoint

Infostealers — Lumma, and its many peers — are lightweight, commodity malware whose entire job is to copy secrets off a machine: saved browser passwords, autofill data, and, critically, **active session and refresh cookies**. They're delivered through the mundane channels: cracked applications, malvertising, fake software updates, "<span class="glossary-term" data-bs-toggle="tooltip" title="A social-engineering pattern where the victim is shown a fake error and instructed to perform a &quot;fix&quot; action (paste-and-run, paste-into-form) that benefits the attacker.">ClickFix</span>"-style paste-and-run lures. The infected machine is frequently *not* a corporate-managed device — a contractor's laptop, a BYOD home machine with the corporate mailbox signed in, a personal browser profile with work credentials saved.

That last point is why enterprise <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> coverage numbers lie to you. The stolen Microsoft credential can come from a device your <span class="glossary-term" data-bs-toggle="tooltip" title="Security Operations Center. The team and tooling responsible for monitoring, detecting, and responding to security events across an organization.">SOC</span> has zero visibility into.

### 3.2 Phase 2 — Access Without Tripping MFA

Two routes get the attacker signed in, and both are consistent with "compromised credentials":

- **Session/<span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> replay.** If the infostealer captured a valid Entra session or refresh cookie, the attacker imports it into their own browser and is *already authenticated*. There is no password prompt and **no <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> challenge**, because there is no new authentication event — they inherited a session that already satisfied <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>. This is the token-theft pattern (Cookie-Bite and similar) that makes <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> moot post-issuance.
- **Password + weak/no <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>.** Where a stolen plaintext credential meets a portal or account without enforced <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> — legacy auth paths, exception groups, unmanaged access to the Entra portal — a straight login works.

Either way, the sign-in looks like the real employee, and the *interactive* controls have nothing anomalous to flag at the moment of access.

### 3.3 Phase 3 — Enumerate and Export

Once authenticated, harvesting the directory is trivial and, by default, permitted. In a default Entra tenant, **member users can read the full user list, groups, and role memberships.** The attacker enumerates via <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> — programmatically hitting `/users`, `/groups`, `/directoryRoles`, and `/servicePrincipals` — exactly the pattern tools like AzureHound automate. The behavioral signature is a **burst of successful `GET` requests against directory resources, paginating through the entire tenant, in a short window**. Hundreds of thousands to millions of rows come out as CSV or JSON, and that file is what lands on the forum.

![Diagram](https://kroki.io/mermaid/svg/eNptUk1vGkEMvfMrfIiqRRVs1BuoIYWSoLRNQUmVu5k1MGJ2PPXMluTf1zsLVC3dw86H37Of3zjSz4a8obnFrWDdA_2wSeybek3SHU1igWUAjPonwfZYYEpo9iT9jAkoyRob0CeYSYucHuOwFj5EXUuIRmxIF_g7nwRbSrd5mCvU8db6C-RCMOxa5KM1wpE3x6sL4NxmDbpQK_4NikYlxHIr3IRYCjuK_V6mLcNgMpnJGB7qwJIgJg16iBSjZV8KbYTiDgzz3tLHtZSTQtvXdCdkwBgPLFVnxEw0XW5kDCtlkqpJvFdcCUao0rNFl6EZNThWnzZp18YMJqpO1aHwDJ4O8Hg_hSBchwR6KxQcvnX1HHOAFapbSoTDTiVBIq8m5PBZUvZpDIu7H1BmL26vIjl152Y4HMK7q8ThZjQanUkZrzy1cAxPhJX2uaVzWK8Hf7JqfQLeqDCjRsR_khw7_HB9DcuvUHx5Xn7PyeA9fOIKEw49vaZv1u-7lshXvf_qrk7P-dS-n9Jraoc0QrGxvoKF4zU6mFa19bFL9ZeAldhf1tFW_UVjuNGX0SFKxynP1ZZhDPeNc3AuBfSax6L4_PxSttL7vd8KuwU1)

---

## 4. Why the Data "Isn't Secret" — and Why That's the Trap

Push back on the instinct to shrug at a directory leak. Yes, Entra deliberately lets members read the directory; yes, none of these fields are passwords. But *aggregation and structure* are the value. Three concrete weaponizations:

1. **Precision BEC.** With the real reporting chain, an attacker can impersonate a specific manager to a specific report, referencing real department names and real peers. The fraudulent wire-transfer or gift-card request stops looking generic and starts looking like Tuesday.
2. **<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>-fatigue and helpdesk social engineering.** Knowing a target's manager, employee ID, and department lets an attacker pass helpdesk identity checks or craft a convincing "IT" pretext to harvest an <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> approval or reset.
3. **Privilege-escalation road-mapping.** The Global Admin and service-account listings tell a <span class="glossary-term" data-bs-toggle="tooltip" title="A type of malware from cryptovirology that threatens to publish the victim&#39;s personal data or perpetually block access to it unless a ransom is paid.">ransomware</span> affiliate *exactly* which accounts to phish or password-spray next. Reconnaissance that used to take weeks is now a spreadsheet lookup.

The directory export is not the breach's payload — it's the *fuel* for the next, targeted breach against the same organization and its people.

---

## 5. Why Standard Defences Don't Stop It

| Defence | Why it underperforms against this campaign |
|---|---|
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> (push/OTP)** | Defeated by session/<span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> replay — the attacker inherits an already-<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>'d session, so no challenge fires. Also bypassed where stolen passwords meet exception groups or legacy auth. |
| **Corporate <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span>** | The credential is frequently stolen from an *unmanaged* device (contractor / BYOD / personal browser) your <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> never sees. |
| **Password rotation policies** | Rotation doesn't invalidate a stolen *session/<span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span>*, and doesn't help until the specific stolen secret is known to be compromised. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> — location/device (as usually scoped)** | The initial sign-in can originate from a residential proxy in-region; and directory read is often not gated by a resource-specific CA policy. |
| **"Directory data is public internally" assumption** | Default member read of the full directory means enumeration generates no permission-denied errors and no consent events — it looks like normal usage. |
| **DLP on email/endpoints** | Exfiltration happens via Graph API to the attacker's own infrastructure, not through the corporate mail or endpoint channels DLP watches. |
| **Perimeter / firewall controls** | The whole chain rides authenticated HTTPS to Microsoft's own endpoints. There is nothing malicious to block at the network edge. |

The controls that *do* bite: **<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> + <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span>** (kills replay), **restricting default directory read** (raises the cost of enumeration), **bulk-Graph-enumeration detection** (catches the export), and **infostealer credential monitoring** (shortens the window before the stolen secret is usable).

---

## 6. Detection: Catching Enumeration and Token Replay

You cannot signature "an employee logged in." You *can* detect the two behaviours this campaign must produce: **anomalous bulk directory enumeration via Graph**, and **sign-in anomalies consistent with token replay from a new environment.**

### 6.1 KQL — Bulk Directory Enumeration via Microsoft Graph

The `MicrosoftGraphActivityLogs` table records Graph API calls. A single principal paginating the whole directory shows up as a high count of successful `GET`s against directory resources in a tight window.

```kusto
// Bulk enumeration of directory objects via Microsoft Graph.
// Tune UniqueRequestThreshold to tenant size (e.g. >5000 for >1000-user tenants).
let lookback = 24h;
let window = 1h;
let UniqueRequestThreshold = 2000;
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| where ResponseStatusCode == 200
| where RequestUri has_any (
        "/users", "/groups", "/directoryRoles",
        "/servicePrincipals", "/directoryObjects", "/members")
| extend principal = coalesce(UserId, tostring(ServicePrincipalId))
| summarize requests = count(),
            distinct_uris = dcount(RequestUri),
            uris = make_set(RequestUri, 20),
            ips = make_set(IPAddress, 10),
            first_seen = min(TimeGenerated),
            last_seen  = max(TimeGenerated)
        by principal, UserAgent, bin(TimeGenerated, window)
| where requests > UniqueRequestThreshold
| sort by requests desc
```

### 6.2 KQL — Offensive-Tooling User-Agents Hitting Graph / AAD Graph

Enumeration frameworks often leave recognisable user-agent fingerprints. High-fidelity when it fires; treat as a strong lead, not the only detector (UAs are trivially spoofed).

```kusto
union isfuzzy=true MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago(7d)
| where UserAgent has_any (
        "azurehound", "bloodhound", "roadrecon",
        "aadinternals", "python-requests", "msgraph-sdk", "GraphAPICLientLib")
| summarize requests = count(),
            resources = make_set(RequestUri, 25),
            first_seen = min(TimeGenerated),
            last_seen  = max(TimeGenerated)
        by UserId, UserAgent, IPAddress
| sort by requests desc
```

### 6.3 KQL — Token-Replay Sign-In Anomalies

Token replay shows up as the same user active from a new IP/ASN/device fingerprint without a corresponding fresh interactive auth, or as impossible travel between the legitimate session and the attacker's.

```kusto
// Same user, same day, mismatched IP/country between interactive and
// non-interactive sign-ins — a token-replay indicator.
let lookback = 1d;
let interactive =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0
    | project i_time = TimeGenerated, UserPrincipalName, UserId,
              i_ip = IPAddress, i_country = tostring(LocationDetails.countryOrRegion);
let noninteractive =
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0
    | project n_time = TimeGenerated, UserId,
              n_ip = IPAddress, n_country = tostring(LocationDetails.countryOrRegion);
interactive
| join kind=inner noninteractive on UserId
| where n_time > i_time and n_time < i_time + 12h
| where i_ip != n_ip and i_country != n_country
| project UserPrincipalName, i_time, n_time, i_ip, n_ip, i_country, n_country
| sort by n_time desc
```

### 6.4 KQL — Password Spraying and MFA Fatigue

Since the actor's own listing claims spray + fatigue, cover that access path too. Spraying looks like many failed authentications across *many distinct users* from few source IPs; <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> fatigue looks like repeated <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>-required results for one user culminating in a success.

```kusto
// Password spraying: one IP failing auth against many users in a short window.
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType in (50126, 50053, 50055, 50056)   // bad password / locked / expired
| summarize failed_users = dcount(UserPrincipalName),
            attempts = count(),
            users = make_set(UserPrincipalName, 25),
            apps = make_set(AppDisplayName, 10)
        by IPAddress, bin(TimeGenerated, 1h)
| where failed_users >= 15            // tune to environment
| sort by failed_users desc
```

```kusto
// MFA fatigue: repeated MFA-required prompts for a single user then a success.
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| summarize mfa_prompts = countif(ResultType == 50074 or ResultType == 500121),
            success = countif(ResultType == 0),
            first_seen = min(TimeGenerated),
            last_seen  = max(TimeGenerated)
        by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where mfa_prompts >= 5 and success >= 1     // many prompts, eventual approval
| sort by mfa_prompts desc
```

### 6.5 Hunt Hypotheses (PEAK / TaHiTI)

- **H1 — The whole-directory reader:** *"A single principal read more than N distinct directory objects via Graph within an hour, where N is above the tenant's normal admin-tooling baseline."* Pivot: is the principal an admin? From a known jump host? Running an approved tool?
- **H2 — New-environment session:** *"A user's session is active from an ASN/device fingerprint never before seen for that user, with no interactive re-auth in the preceding hour."* The token-replay footprint.
- **H3 — Infostealer-to-cloud correlation:** *"A corporate credential appears in infostealer/dark-web feeds, and the same account shows anomalous Graph enumeration or a new-IP session within days."* Combines external CTI with internal telemetry.
- **H4 — Privileged-roster pull:** *"Any non-admin principal enumerated `/directoryRoles` membership or `servicePrincipals` at volume."* Reading the list of admins is rarely a normal end-user action.
- **H5 — Spray-then-enumerate:** *"A source IP or ASN that generated a burst of failed sign-ins across many users later produces a successful sign-in followed by directory enumeration."* Links the actor's claimed access path to the export behaviour.

---

## 7. Mitigation: Shrink Capture, Access, and Enumeration

Attack this in the same three phases the kill chain uses.

### 7.1 Break Token Replay: Phishing-Resistant MFA + Token Protection

This is the highest-leverage control and it defeats the campaign's most dangerous access route.

![Diagram](https://kroki.io/mermaid/svg/eNpVkE1PAjEURff-ipewlRDYABODGQTdqJkgGzNh0XlzyzRTWtN2NMT43-10iB_d9px7byu1_eBGuECPuyuKh7XwfgNJtiWptM5GWMoKy2sfnG2RjWa8EDP-z1aivsBSYo75D8yLKaZIcF6-wHtlzcRBOviGQkTMTeUmKx-shqHqTMpI6wOEhjvQeLyi9ee-x6hwNoBD9JOByDlGffuVwteRpWebjLsyD0FwC0cOb1qc_Z8m6eyJQgPl6CS4UQaHLMv6_b26KfMuXpqgWATUJDx1Pi4ZkN-mV_jEb8thXGU7U8cWsk4d1dBU410xaF88UYtzH2HblLBN6n25S-MoLYqPgToaGqRhqVDaU2EL4gbcDgFJfShz5viXkTYK9SX6GyE-lQ8=)

Move privileged and directory-capable users to **<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant methods (<span class="glossary-term" data-bs-toggle="tooltip" title="A phishing-resistant authentication standard combining the W3C WebAuthn API and the CTAP protocol for hardware-backed credentials. Resists credential phishing but does not protect post-authentication token theft.">FIDO2</span> / passkeys / certificate-based)** and enable **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span>** (sign-in session token binding), now generally available for Exchange Online, SharePoint Online, and <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> in desktop apps with coverage broadening through 2026. A token stolen off an employee's machine cannot be redeemed from the attacker's.

### 7.2 Restrict Default Directory Read

By default every member can enumerate the directory. Tighten the tenant's authorization policy so ordinary members and guests can't read the whole org.

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Restrict guests to the most limited directory access
Update-MgPolicyAuthorizationPolicy `
  -GuestUserRoleId "2af84b1e-32c8-42b7-82bc-daa82404023b"  # Restricted Guest

# Review whether members are permitted to read other users / register apps, etc.
Get-MgPolicyAuthorizationPolicy |
  Select-Object DefaultUserRolePermissions
```

Where the business allows, disable or scope legacy **Azure AD Graph** access entirely and force everything through <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> so your `MicrosoftGraphActivityLogs`-based detections have full coverage. For the most sensitive principals (Global Admins, service accounts), apply **Restricted Management Administrative Units** so they can't be casually enumerated or modified.

### 7.3 Starve the Infostealer Pipeline

- **Extend identity to unmanaged devices.** Require device compliance / managed-device <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> for access to the Entra portal and Graph, so a token stolen from a contractor's personal browser can't be used against sensitive scopes.
- **Kill saved corporate credentials in personal browsers.** Enforce SSO through managed browsers/profiles; discourage saving Microsoft passwords in unmanaged browser stores.
- **Continuously monitor for infostealer-exposed corporate credentials** (dark-web / cybercrime intel feeds), and auto-trigger a password reset **plus session/refresh-token revocation** the moment a corporate credential surfaces. Resetting the password alone does not kill a stolen token.
- **Reduce initial infection**: application allow-listing, blocking cracked-software and malvertising delivery, and user education on <span class="glossary-term" data-bs-toggle="tooltip" title="A social-engineering pattern where the victim is shown a fake error and instructed to perform a &quot;fix&quot; action (paste-and-run, paste-into-form) that benefits the attacker.">ClickFix</span>-style paste-and-run lures.

### 7.4 Blunt Password Spraying and MFA Fatigue

Because the actor claims spray + fatigue, close that door explicitly:

- **Number-matching <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>** (now default in the Authenticator app) defeats blind "approve the prompt" fatigue attacks — the user must type a number shown on the sign-in screen, which they can't do if they aren't the one signing in.
- **Entra Smart Lockout** and banned-password lists blunt spraying by locking out guessing bursts without penalising legitimate users.
- **Block legacy authentication** protocols, which bypass <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> and are the classic spray target.
- **Sign-in risk & <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>-fatigue detections** in Identity Protection should trigger step-up or block; tune the queries in Section 6.4 into analytics rules.

### 7.5 Continuous Access Evaluation

Enable **Continuous Access Evaluation (<span class="glossary-term" data-bs-toggle="tooltip" title="Continuous Access Evaluation. An Entra ID capability that allows critical security events (password change, risk events) to immediately invalidate tokens rather than waiting for expiration.">CAE</span>)** so that risk events and credential changes invalidate tokens in near-real-time rather than waiting for expiry — shortening the useful life of any stolen session.

---

## 8. Operational Playbook for SOC and IR

If enumeration detections fire, or a corporate credential appears in an infostealer feed, work the timeline below.

![Diagram](https://kroki.io/mermaid/svg/eNptUk1v2zAMvfdX8LihMbJzLkPSpl0OAYI0Q8-KRdlsJNGg5Lj596Oc1suG6uIPPb73-MhMAT1FvAM9mbJH2ETHKaPxKFXm6pEE68xyqdbvjjxs9nC4LUp6SxzhcP8Dvh2Emgbl-3hTzqr3J3gW07WAsQ8oZgSzAP2VgZYyLGAZORjPfQL7qQmCxhY0vnec0EItaDFmMh6cN6pl_zHxRJIytNzL5GCPZz6hIlJSRIJ75UyYb5kWH6Bq2_xOKC_UxE18uRYovjMpDSz2o7AQVBiFPWyflpPOA0dHEiDV3CGwu1pfwGtLdXvTER_f9C3BgILQ9d6jncHxAkPL4YterLlMEpvRsLtAbrUhbbJGsHgmfSxga6LROEpYfQzXj5-wftxDGhA7mKshCvp3olumEgp0QmfyWGrHlHspdK_F3rPno-aztIE0ublak1HN1DX3UZv4nOmXY1DZ0yT2y4i6BxpbyBdV2LWUWopNpbFSyibmkucMDjqJCDvhfGWbldyzUJ3_24uJeye6kGB5iIpDEzQUh7HGpCorIXSg9M7p5ILRDVaXvRQPTrNarR_mqUMjVVf8wGDOePcH33IKVA==)

Non-negotiable first-hour actions:

1. **Revoke the user's sessions and refresh tokens** (`Revoke-MgUserSignInSession`), reset the password, and re-enrol <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>. Revocation is what actually kills a replayed token — a password reset alone does not.
2. **Determine exactly what was enumerated** from `MicrosoftGraphActivityLogs` — the object types and volume — so you can scope the downstream risk (a full-directory pull means *plan for a targeted BEC/<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> wave against your whole staff*, not just the compromised user).

Then, in parallel:

- **Trace the source device.** If it's unmanaged, treat the credential as fully compromised and sweep for what else that user had access to.
- **Check whether privileged rosters were read** (`/directoryRoles`, `servicePrincipals`). If Global Admin or service-account listings were pulled, prioritise <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> and credential rotation for exactly those accounts *now*.
- **Brief mail security and staff.** The directory is a spear-<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> kit; warn the impersonation-likely targets (finance, execs' direct reports, IT helpdesk) and tune BEC detections.
- **Feed IOCs back to CTI.** Correlate the attacker IPs/ASNs/user-agents against other identities to find parallel compromise.

---

## 9. The Wider Picture: The Endpoint Is Your Cloud's Front Door

TheHatman's campaign is a reminder that the boundary of your Entra tenant is not `login.microsoftonline.com` — it's **every browser, on every device, where an employee or contractor has ever saved a corporate credential or held a live session.** Infostealers have industrialised the harvesting of exactly those secrets, and a stolen session token quietly demotes <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> from a wall to a speed bump.

The strategic shift this asks for is to stop treating "we have <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>" as the finish line for identity security. The 2026 reality is that **token theft is the dominant path around <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>**, which makes *token binding* (<span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span>), *<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant factors*, and *fast token revocation on credential exposure* the new baseline — not advanced options. Pair that with the un-glamorous hygiene of restricting default directory read and watching for bulk Graph enumeration, and the economics flip: the stolen credential expires before it's usable, and the mass-export throws an alert instead of a CSV.

The question for the quarter: **if one of your employees' credentials showed up in an infostealer dump tonight, how many hours would pass before that token was revoked — and would a full directory export from that account trigger an alert, or a sale?**

---

## Glossary

These terms are auto-tooltipped by the publishing pipeline; definitions are repeated here for the static reader.

- **Infostealer** — Lightweight commodity malware that copies secrets from an infected machine: saved passwords, autofill data, and active browser session/refresh cookies. Delivered via cracked software, malvertising, fake updates, and <span class="glossary-term" data-bs-toggle="tooltip" title="A social-engineering pattern where the victim is shown a fake error and instructed to perform a &quot;fix&quot; action (paste-and-run, paste-into-form) that benefits the attacker.">ClickFix</span> lures.
- **Session / <span class="glossary-term" data-bs-toggle="tooltip" title="A long-lived OAuth credential used to mint new access tokens without prompting the user again. Lifetime varies; typically up to 90 days or until a critical event invalidates it.">refresh token</span> theft** — Stealing an already-authenticated session or refresh cookie so the attacker inherits a signed-in state without triggering a new authentication or <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> prompt.
- **Directory enumeration** — Systematically reading a tenant's users, groups, roles, and service principals — typically via <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> — to build a complete inventory.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span>** — The unified API for reading and writing Entra/M365 objects; the primary channel for programmatic directory reads (and thus bulk exports).
- **AzureHound / BloodHound / AADInternals** — Offensive tooling that automates Entra/Azure reconnaissance and enumeration; produces recognisable request patterns and user-agents.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> (<span class="glossary-term" data-bs-toggle="tooltip" title="Proof-of-Possession. A token-binding scheme that requires the holder to cryptographically prove ownership of a device-bound key when using a token.">PoP</span>)** — <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> feature binding tokens cryptographically to the origin device's key, so a stolen token can't be replayed from another machine. Requires <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> P1/P2.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">Phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>** — Authentication methods (<span class="glossary-term" data-bs-toggle="tooltip" title="A phishing-resistant authentication standard combining the W3C WebAuthn API and the CTAP protocol for hardware-backed credentials. Resists credential phishing but does not protect post-authentication token theft.">FIDO2</span>/passkeys, certificate-based) that resist <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> and adversary-in-the-middle; the token-binding side still needs <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> to stop post-issuance replay.
- **BEC** — *Business Email Compromise*; fraud that impersonates a trusted internal party, made far more convincing with an accurate org chart.
- **Global Administrator** — The highest-privilege Entra role; its members are a top-priority target, which is why leaking the roster is dangerous.
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Continuous Access Evaluation. An Entra ID capability that allows critical security events (password change, risk events) to immediately invalidate tokens rather than waiting for expiration.">CAE</span>** — *Continuous Access Evaluation*; invalidates tokens in near-real-time on risk/credential events instead of waiting for expiry.
- **Restricted Management Administrative Unit** — An Entra construct that limits who can read/manage a protected set of principals, reducing casual enumeration of sensitive accounts.

---

## Sources & Further Reading

### Primary Reporting

- [Massive Azure Exfiltration Campaign Exposes Millions of Enterprise Records via Compromised Credentials (McDonald's, Vodafone, Kyndryl & Others) — InfoStealers / Hudson Rock](https://www.infostealers.com/article/massive-azure-exfiltration-campaign-exposes-millions-of-enterprise-records-via-compromised-credentials-mcdonalds-vodafone-kyndryl-others/) — The originating multi-victim report: victims, record counts, data structure, and the infostealer-credential assessment.
- [S2W Daily Threat (@S2W_DailyThreat) — BreachForums TCS listing flag](https://x.com/S2W_DailyThreat/status/2086654850633470097) — The CTI post that surfaced TheHatman's TCS listing and prompted disclosure.

### Corroboration and Victim Responses

- [TCS says leaked employee data 'appears to be' over four years old — CRN Asia](https://www.crnasia.com/india/news/2026/tcs-says-leaked-employee-data-appears-to-be-over-four-years-old) — Detailed account of the BreachForums listing (sample size, Session/Tox/Jabber contacts, claimed spray + <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>-fatigue vector) and TCS's qualified BSE disclosure.
- [TCS flags possible data breach; employee data at risk, customer data safe — Business Today](https://www.businesstoday.in/technology/news/story/tcs-flags-possible-employee-data-exposure-says-customer-data-unaffected-548436-2026-08-11) — TCS's initial disclosure and scope statement.
- [TCS Faces Employee Data Exposure Claim; Says No Evidence of Systems Breach — Outlook Business](https://www.outlookbusiness.com/corporate/tcs-faces-employee-data-exposure-claim-says-no-evidence-of-systems-breach) — Corroborating coverage of the TCS response.
- [HCLTech says stolen data may be years-old after hacker's claims — Rankiteo](https://blog.rankiteo.com/hcltat1786448292-hcltech-tcs-breach-august-2026/) — HCLTech's parallel "data may be old" pushback.
- [BreachForums — overview](https://en.wikipedia.org/wiki/BreachForums) — Background on the forum used to list the dumps.

> **Note on the McHire incident:** Some searches for "McDonald's data breach 2026" surface the *2025 McHire/Paradox.ai applicant-chatbot* exposure ([CSO Online](https://www.csoonline.com/article/4020919/mcdonalds-ai-hiring-tools-password-123456-exposes-data-of-64m-applicants.html)). That is a **separate, unrelated** event and should not be conflated with the TheHatman directory-listing claim.

### Token Theft & MFA Bypass

- [Cookie-Bite: How Your Digital Crumbs Let Threat Actors Bypass MFA — Varonis](https://www.varonis.com/blog/cookie-bite) — How stolen session cookies enable persistent cloud access without re-authentication.
- [Session token theft: How infostealers bypass MFA — CyberCheck Security](https://cyberchecksecurity.com/en/insights/session_token_theft) — The infostealer-to-token-replay mechanism explained.
- [Token-Based Attacks: How Attackers Bypass MFA — Obsidian Security](https://www.obsidiansecurity.com/blog/token-based-attacks-how-attackers-bypass-mfa) — Token replay and detection considerations.
- [Securing Microsoft Entra ID: A Practical Guide to Preventing Token Theft — Formula5](https://formula5.com/securing-microsoft-entra-id-a-practical-guide-to-preventing-token-theft/) — <span class="glossary-term" data-bs-toggle="tooltip" title="An Entra Conditional Access feature that cryptographically binds tokens to the originating device&#39;s TPM-backed key (proof-of-possession). Prevents token replay from a different device.">Token Protection</span> and <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span>-resistant <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> guidance.

### Directory Enumeration Detection

- [Azure AD Graph Activity Logs: detecting directory enumeration — Elastic Security Labs](https://www.elastic.co/security-labs/aad-graph-activity-logs-threat-detection) — Detecting enumeration by user-agent and volume in graph activity logs.
- [Investigating Microsoft Graph Activity Logs (KQL) — kqlquery.com](https://kqlquery.com/posts/graphactivitylogs/) — Practical <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> for the `MicrosoftGraphActivityLogs` table.
- [Detect threats using Microsoft Graph activity logs — Cloudbrothers](https://cloudbrothers.info/en/detect-threats-microsoft-graph-logs-part-1/) — Threat-detection patterns over Graph activity.
- [AzureHound detection (KQL) — Bert-JanP/Hunting-Queries-Detection-Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Graph%20API/AzureHound.md) — Volume/threshold-based AzureHound detection query.
- [Entra ID (Azure AD) Enumeration: Complete Attacker Guide — Redfox Security](https://www.redfoxsec.com/blog/entra-id-azure-ad-enumeration) — What attackers enumerate and how, for detection context.

### Hardening & Directory Read Restriction

- [Restrict member users' default directory permissions — Microsoft Learn](https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions) — Reducing what ordinary members can read/enumerate.
- [How Token Protection Enhances Conditional Access Policies — Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection) — Configuring sign-in session token binding.
- [Restricted management administrative units — Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management) — Protecting sensitive principals from casual enumeration/modification.

---

*Off-cycle special report (outside the Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel rotation). The next scheduled deep-dive remains a Supply-Chain topic: the most significant recent package-registry or CI/CD build-system compromise and what a defensible pipeline-trust posture looks like heading into Q4 2026.*
