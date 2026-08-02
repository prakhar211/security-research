---
layout: post
title: "HOLLOWGRAPH: When Your Microsoft 365 Calendar Becomes an Iranian-Nexus Dead Drop"
date: 2026-08-02
categories: [apt, security]
tags: [hollowgraph, microsoft-graph, entra-id, dns-tunneling, cavern-manticore, cyber-espionage]
author: Prakhar Gupta
description: "A technical deep-dive into HOLLOWGRAPH — a Cavern-framework espionage implant that hides command-and-control and stolen files inside Microsoft 365 calendar events dated to the year 2050, and what SOC and IR teams can actually detect."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.** HOLLOWGRAPH is a Windows espionage implant, attributed by Group-IB (20 July 2026) with high confidence to the Iranian-nexus **Cavern** framework, that turns a *compromised* Microsoft 365 mailbox into its entire command-and-control channel. It uses the **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> API** to treat the mailbox calendar as a two-way **dead drop**: operators plant tasking as calendar events dated to **13 May 2050**, and the implant exfiltrates files as encrypted `File{n}.txt` attachments on its own far-future events. A second channel refreshes the app's <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> **client-credentials** over **DNS tunneling** (IPv6 `AAAA` queries to `cloudlanecdn[.]com`) and writes them to `logAzure.txt` on disk. There is **no CVE and no patch** — it rides legitimate Graph functionality and a stolen application identity. The single most important defensive move: **inventory, restrict, and monitor the client-credential <span class="glossary-term" data-bs-toggle="tooltip" title="An open standard for access delegation. Lets a user grant a third-party application limited access to their resources without sharing credentials.">OAuth</span> apps that hold `Calendars.ReadWrite` application permission**, and alert on app-driven calendar writes with far-future dates.

---

## Watch the 7-Minute Walkthrough

For IT generalists, platform engineers, and anyone who wants the intuition before the technical depth: a short narrated walkthrough of the attack and what to do about it.

<!-- VIDEO_EMBED:START -->
<!--
  Rendered NotebookLM Cinematic Video Overview.
  Source script: _video/script-hollowgraph-m365-calendar-<span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">c2</span>-deep-dive.md
  Video: https://www.youtube.com/watch?v=iLPNdg4VyY4
-->
<div class="video-embed" style="position:relative;padding-top:56.25%;border-radius:8px;overflow:hidden;">
  <iframe
    src="https://www.youtube-nocookie.com/embed/iLPNdg4VyY4"
    title="HOLLOWGRAPH — Explainer (IT Generalists)"
    style="position:absolute;top:0;left:0;width:100%;height:100%;border:0;"
    loading="lazy"
    referrerpolicy="strict-origin-when-cross-origin"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
    allowfullscreen>
  </iframe>
</div>
<!-- VIDEO_EMBED:END -->

> *Prefer to read?* Skip the video and jump straight to [Section 1 — Why This One Matters](#1-why-this-one-matters).

---

## 1. Why This One Matters

For a decade, "command-and-control" meant an attacker had *infrastructure* — a domain you could sinkhole, an IP you could block, a JA3 fingerprint you could hunt. The whole edifice of network detection is built on the assumption that malicious traffic eventually leaves your estate and heads somewhere it shouldn't.

HOLLOWGRAPH quietly dismantles that assumption. The implant **never contacts an attacker-owned server for command or payload traffic**. Every task it receives and every file it steals travels over `graph.microsoft.com` — Microsoft's own API, on Microsoft's own TLS certificate, to Microsoft's own cloud. From a NetFlow or proxy-log perspective, an infected host in a targeted Israeli organisation looks *exactly* like a host doing ordinary Microsoft 365 work, because mechanically that is what it is doing. The only attacker-controlled destination in the whole design is a DNS domain used purely to refresh credentials — and even that channel is disguised as innocuous `AAAA` lookups.

This is not a proof-of-concept. Group-IB observed live victim traffic from **3 June to 9 July 2026** across at least **12 infected systems**, of which roughly **three** were actively communicating during the analysis window. The small, disciplined footprint — combined with an Israeli exfiltration mailbox and samples uploaded from Israel — reads as *targeted espionage*, not opportunistic crime. Group-IB links the implant to the **Cavern** modular backdoor framework with high confidence; Check Point, which documented Cavern earlier in July as "**Cavern Manticore**," attributes that framework to an actor tied to Iran's Ministry of Intelligence and Security (MOIS), overlapping the known clusters **MuddyWater** and **Lyceum**. Group-IB itself will only commit to a *low-confidence* overlap with Lyceum for this specific campaign.

For a Cloud Security or Detection Engineering team, the takeaway is uncomfortable: **your SaaS control plane is now <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> infrastructure**, and the detections that matter live in Graph activity logs, mailbox audit, and service-principal sign-ins — not in your firewall.

---

## 2. Background: How Graph App-Only Access Is *Supposed* to Work

To understand the abuse, you have to understand the legitimate mechanism it imitates. <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> is the unified API surface for Microsoft 365 — mail, calendar, files, Teams, directory, everything. Applications authenticate to Graph in one of two broad ways:

- **Delegated access** — the app acts *on behalf of a signed-in user*, constrained by both the user's rights and the app's granted scopes.
- **Application (app-only) access** — the app acts *as itself*, with no user present, using the **<span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> client-credentials grant**. It presents a `client_id` + `client_secret` (or certificate) for a specific tenant (`tenant_id`) and receives an app-only <span class="glossary-term" data-bs-toggle="tooltip" title="A bearer credential that an OAuth client uses to call a protected API on behalf of the authenticated user. Typically valid for 1 hour.">access token</span> whose permissions come from **application permissions** consented by an administrator.

HOLLOWGRAPH abuses the second path. Its embedded configuration carries exactly the four fields a client-credentials flow needs — `tenantId`, `clientId`, `clientSecret`, and a target `mailbox` — plus the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> DNS domain and two RSA keys. On execution it writes all of this to disk as `logAzure.txt`, a filename chosen to blend in with routine log noise.

![Diagram](https://kroki.io/mermaid/svg/eNptUUtv00AQvudXzDEWShZ6tEqkUFAbqVIiQOJYTXYn9ir7Yncc0iL47Yw3fUQKvnhn_b3mc6GfAwVNny12Gf0E5MGBYxj8lnIdE2a22iYMDCufAAvcre_v1z9uvy43d2B9cvLpepvVYupit3waMs35yKBj2NmuuRD5EjjjKCNoG-be6hxL3Imps4HmOvoqpn4zBcGvzB8VJVN_pQ5X8_eK457ChehtxtSPot14eBMd5S7AN-hG6E30KUdvCxnwaN02HquzRkfBYIapITRgckzNpIrI_rPFoi7Qwmb97Tuc4sBUO0uBH3QmI2-LrjQnrdO9NfAOns-FBMUyFx0TfeyZU2mV-k9wNTe0w8FxNa-2M_GXFC1gSjNp7BFQayrl4TnHAZ14_f3QN2eBazktLKXEmO0Tso2hhU-EmTJcvypViUXlVYYwpakWsrSgfmXLBK_V0EFWKbIEMqPu_ThVpjBmb5YVBgYZQZ1BYfvIVM6cXrZablZiV1IMhQpMGcvehg6iGB53Vv6a3jeTf53m63w=)

Three properties of this legitimate flow are what make the abuse so quiet:

1. **App-only tokens carry no user-risk signal.** There is no interactive sign-in, no device, no <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> prompt, no impossible-travel heuristic to trip. The token is minted from a `client_id`/`client_secret` pair against the `/token` endpoint. Entra's identity-protection risk engine is largely blind here.
2. **`Calendars.ReadWrite` (application) is a common, boring permission.** Meeting-room bots, scheduling assistants, and CRM integrations legitimately hold it across most tenants. A calendar write by an app is not, by itself, anomalous.
3. **The traffic terminates on `graph.microsoft.com`.** No egress control keyed to attacker infrastructure will ever fire, because the destination *is* Microsoft.

The implant does not compromise the account itself — that is assumed to have happened upstream, either by <span class="glossary-term" data-bs-toggle="tooltip" title="A type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information or to deploy malicious software on the victim&#39;s infrastructure.">phishing</span> the app's secret, stealing it from source or CI, or standing up an attacker-registered app in a mailbox the operators already control. HOLLOWGRAPH is the *post-compromise* covert channel, and it is engineered specifically to survive in an environment where the perimeter has already been ceded.

---

## 3. The Attack: HOLLOWGRAPH's Calendar Dead Drop

The pivotal idea is simple and, in hindsight, obvious: **a calendar is a two-way, attachment-carrying, cloud-synchronised message queue that nobody monitors.** If both the operator and the implant can read and write the same mailbox's calendar via Graph, they have a full-duplex <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> channel that never touches attacker infrastructure. HOLLOWGRAPH dates every event to **13 May 2050, 22:00–23:00 UTC**, so the mailbox owner would have to deliberately scroll a quarter-century into the future to ever see it.

Here is the full channel topology:

![Diagram](https://kroki.io/mermaid/svg/eNpdU9FOIjEUfecrbjARN5FxgAV0NCYIrpKgGDXxYWI2pb2Fhk472xbUXfbft9NxEHZeZtrec-7puWe41G90QYyD51EN_EMlsXaEHNaCOpEBF1ImB9jnHc6PrTN6iclBi_cJ6x1TLbVJDuJZh_Rm-2jiHKFLNJ94zrGP_S2enrawhRW-S2Ia0318ZqvOZ3yGZ1tkm56SNt12xg6LcR8pFDdk25b3vM5t2_iUxHEF_k463TiuBfStti6tjxVH6pDBi1BMv1lY-O2LmTm5vJ1OJtOXm8fBwy1E99fPcE-cWONg-gyjySSUHGXE_lqhIQwtEAtXRjspQIrZt_prkiSln6HbkM_TutTzwe-Vwci9O9AKmLDLQORQEeXGDE78pQTufT4hNVhKyoiQM_3uj4ZtYNovlf9-fBrAEj_s_y2vlTMkrYcXjEfgvCEKULFcC1USlh1--gbMvwWRFubGKwlUmQ00N4bki7R-J6jRVnNXbsDgYRwo5sUqyqrTiOpsFz0kMq0PdZYbnQnrfb7r9LpQXYQS6fUQE5hw7TVYYKQYRzvuxs2422x1wlnjujj0t0jgULpzR-xyPDqcu_OGN6Bxpa2NovEoihqh-oeQ-Ef9DTaHVC6ygnpX1zRP69Pcj87psvvRkKzRKKDa-6WlRFPOsEp1QI3un9I6lXrFJFFImUqjV3_hQLCNvy8Ci8azhf2Bf7zI8cO6BwapNqwUEkJb-xQDzeblJvekDoq7CTWH0o5N4eA2r0VZEaUqUgFWDrG5M8RNOfuvFIQ6kudNreRHGYRNINxj3szRJV4jYZWITTns_SrrR5bAmxEOAd_9X7dbVYbjIujcEx55pEFu0C5gR-qXRVLr5Sr32r1_ldklrLCuiYpq5oNRYO2OeN8lqNKfwwz6bSVsmtf-AXLVluk=)

Let us walk it stage by stage.

### 3.1 The Implant: A Two-Command .NET DLL

HOLLOWGRAPH is a **.NET assembly compiled with NativeAOT** and shipped as a DLL that masquerades on disk as a **Brotli compression library**. NativeAOT compilation strips the managed metadata that reverse engineers and many .NET-aware detections rely on, making the sample behave more like an opaque native binary than a typical CLR assembly.

The loader invokes it with a single wide-character string in a rigid format:

```
<command>_;;_<arg0>_,_<arg1>_,_<arg2>
```

Outer components are separated by `_;;_`; inner arguments by `_,_`. A **7-character task identifier** is derived from the supplied argument and used to label the corresponding <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> exchange. The implant understands exactly **two** commands — `get` and `send` — and returns results to the caller as a wide string (decrypted instructions for `get`, or a completion status for `send`). Everything else is handled by the broader Cavern toolkit of which HOLLOWGRAPH is one module.

### 3.2 The `get` Command — Pulling Tasking

`get` retrieves the operator's command from the calendar dead drop. The Graph calls are precise:

```
GET /users/{mailbox}/calendarView
      ?startDateTime=2050-05-13T22:00:00
      &endDateTime=2050-05-13T23:00:00
      &$filter=contains(subject,'Event ID: ')
GET /users/{mailbox}/events/{event-id}?$expand&$select
GET /users/{mailbox}/events/{event-id}/attachments
```

The implant queries `calendarView` restricted to the fixed 2050-05-13 window, filters events whose subject contains `Event ID: <taskID>`, pulls each `File{n}.txt` attachment, and decrypts it — **unwrapping an AES-256 key via RSA-OAEP (SHA-256), then decrypting the payload with AES-256-GCM** — before handing the plaintext tasking back to the loader.

### 3.3 The `send` Command — Exfiltrating Files

`send` reverses the flow. The implant encrypts the target file with the configured **public** RSA key (RSA-OAEP wraps a freshly generated AES-256 key, then AES-256-GCM seals the payload), then performs a three-call Graph sequence:

```
POST  /users/{mailbox}/calendar/events                 (create event, far-future 2050-05-13)
POST  /users/{mailbox}/events/{event-id}/attachments   (upload each File{n}.txt chunk, base64 octet-stream)
PATCH /users/{mailbox}/events/{event-id}               (rename subject -> "Boss{..}ID{..}")
```

The placeholder event is created first with a random GUID as its subject, chunks are attached as `application/octet-stream` files named `File{n}.txt`, and a final `PATCH` renames the subject to the operator-recognisable `Boss{..}ID{..}` tag so the controller knows which events carry fresh loot.

Crucially, HOLLOWGRAPH uses **two separate RSA key pairs** — one for inbound tasking, one for outbound exfiltration — so that the two directions are cryptographically independent. Even full recovery of the agent's on-disk private key only lets you decrypt *tasking*, not the exfiltrated data, which is sealed with the <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> server's public key.

![Diagram](https://kroki.io/mermaid/svg/eNptUtFu2jAUfe9XXPGUqYQxKvpAUaQsySASXVBh7WN1iT3qNbE9xymtqv77rmPQKiAPVmyfc-65x7fhf1suS54K3BqsL4A-bK2Sbb3hxm9LqwwUGrChlRt02yDBF27klw6h0VhRCo3SQoKVA95eXY_dP5cMCc04MmBG6VNCXnfK82KxKB5md_FyfgJZKGRkpjv_qSwHRbXJS58KTGCNzbOQWwi23Hr5QodR1N0lhiPh-QsnmdFwPAyH4_Db1XRjvkZNu_nDSwu9rLvN0wlMLWnladTrAGgtlk_wQ1R8OLCvFoK7VXwZZytfhYwfysyyNZT7Zu8F30HgasFOSKZ2ffgtKkuG9wU9m3gh0Ulk4u2Fgp2T9SZqAjQQRp2Zd_nh7HxCdypkLizibAmt3BnUcAlkNRyNr8NZcguMl-ZN_ycRy8c6AV2hkJZTg6Wqa5TsOGkP7BdUJHt1zdAMCCUhaKhj346HHKy4c3i8uXmEqUb7FB1bpYlzZlwwnEZpBLrdVKKEZ_52ku2yWK33DxjMfuXpIcZ-957A6H3Pcz4ndz42j43Xyfwg6iLufVdN8z4YfOSpW3tHI2XcKDuIN9X0yXxVQaWUvfgHXH0DxQ==)

### 3.4 The DNS Channel — Keeping Graph Access Alive

App-only client secrets expire and get rotated. HOLLOWGRAPH solves this with a **second, cruder channel** that refreshes its four <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> credential fields (`tenantId`, `clientId`, `clientSecret`, `mailbox`) over DNS. It resolves specially encoded subdomains under `cloudlanecdn[.]com` using **`AAAA` (IPv6) records** via the `DnsClient.NET` library:

```
LENGTH query:  {random}.{7charTaskID}.{fieldIndex}.p.cloudlanecdn[.]com
DATA   query:  {random}.{7charTaskID}.{fieldIndex}.{byteOffset}.q.cloudlanecdn[.]com

{fieldIndex}  = 0..3  (which credential field: tenant/client/secret/mailbox)
{byteOffset}  = running offset, incremented by 14 per chunk
```

Length queries (`.p.` for "prime") return an IPv6 address whose first two bytes encode a big-endian `uint16` — the total length to expect. Data queries (`.q.`) each return an IPv6 address (16 bytes) yielding **14 usable payload bytes**. The implant reassembles the chunks, decodes UTF-8, and rewrites `logAzure.txt`. This channel is **not encrypted** — the credentials ride in the clear, encoded into IPv6 answers. That is a weakness for the attacker and an opportunity for the defender: high-frequency `AAAA` queries with long, high-entropy labels aimed at a single second-level domain are a classic tunneling signature.

### 3.5 Linking to Cavern

Group-IB's high-confidence link to the Cavern framework rests on concrete artefacts, not vibes. The invocation format `<command>_;;_<arg0>_,_<arg1>_,_<arg2>` matches Cavern's command syntax exactly. Among recovered tasking was the base64 string `MzU=`, which decodes to `003` — a **toggle-debug-logging** self-command in the Cavern taxonomy — arriving in a controller message of the form `{"cid": "oXhLaJ0ZvtPb9XB", "type": "self", "cmd": "003_;;__,_"}`. Cavern treats any non-`self` command as a plugin DLL name to load from disk, mirroring behaviour Check Point documented for **Cavern Manticore** and that earlier research tied to **Lyceum** (an OilRig subgroup). Group-IB assesses the Lyceum overlap for *this* campaign at **low confidence** — the code lineage is clear; the specific operator is not.

---

## 4. Why the Usual Defences Don't Stop It

| Defence | Why it fails against HOLLOWGRAPH |
|---|---|
| **Egress / firewall / proxy blocking** | All <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> and exfil traffic terminates on `graph.microsoft.com`. There is no attacker IP or domain in the data path to block — blocking Graph would break Microsoft 365 itself. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s cloud identity service (formerly Azure Active Directory). The identity provider for Microsoft 365 and Azure.">Entra ID</span> sign-in risk / Identity Protection** | The channel authenticates via the **client-credentials grant**. There is no interactive user sign-in, no device, no <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span>, no impossible-travel signal for the risk engine to score. |
| **DLP on email / attachments** | Nothing is emailed. Exfil rides as base64 `octet-stream` attachments on *calendar events*, a surface most DLP engines never inspect. |
| **App-consent governance** | The abused application permission (`Calendars.ReadWrite`) is common and legitimate; a mail-bot or scheduler holds it in most tenants. No *new* suspicious consent event necessarily appears. |
| **User-visible calendar review** | Every event is dated **2050-05-13**. The mailbox owner would have to scroll ~24 years forward to ever notice it. Default calendar views never surface it. |
| **AV / <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> signature on the DLL** | The implant is **NativeAOT-compiled** and masquerades as a Brotli compression library, stripping the managed metadata many .NET detections key on. |
| **Network <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> beaconing detection** | Beacon-detection tuned to periodicity against rare destinations sees only traffic to Microsoft — a destination on every allow-list on earth. |

The defences that *do* bite are all on the **identity, SaaS-audit, and DNS** planes: restricting which apps can hold Graph calendar permissions, watching app-only Graph writes for far-future calendar artefacts, and catching the `AAAA` tunneling to `cloudlanecdn[.]com`.

---

## 5. Detection: SOC-Side Hunting and KQL Queries

Because the abuse lives in the SaaS control plane, the highest-fidelity signals come from **Microsoft 365 / Graph audit logs**, **service-principal sign-ins**, and **endpoint DNS/file telemetry**. Table and field names below assume Microsoft Sentinel / Defender XDR advanced hunting; adapt to your schema. Treat these as starting points and tune to your baseline.

### 5.1 KQL — App-Only Graph Token Acquisition From an Anomalous Origin

The client-credentials flow surfaces in `AADServicePrincipalSignInLogs`. Hunt for the abused app acquiring Graph tokens from IPs/ASNs it has never used before:

```kusto
// HOLLOWGRAPH — app-only (service principal) sign-ins to Microsoft Graph
// from newly-seen source IPs. Scope 'watchApps' to the client IDs that
// legitimately hold Calendars.ReadWrite in your tenant, or leave broad to triage.
let lookback = 14d;
let learn = 30d;
let known =
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (ago(learn) .. ago(lookback))
    | where ResourceDisplayName == "Microsoft Graph"
    | distinct AppId, IPAddress;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(lookback)
| where ResourceDisplayName == "Microsoft Graph"
| where ResultType == 0
| join kind=leftanti known on AppId, IPAddress
| summarize firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated),
            tokenCount=count(), ips=make_set(IPAddress, 20)
          by AppId, ServicePrincipalName, ServicePrincipalId
| sort by tokenCount desc
```

### 5.2 KQL — App-Driven Calendar Writes With Far-Future Dates

The sharpest, most HOLLOWGRAPH-specific signal is a *calendar event created or updated by an application* (not a person) with a **2050** start date. In Sentinel, `OfficeActivity` (Exchange workload) records calendar item operations; app-driven changes carry an `AppId`/`ClientAppId`. Field availability varies by tenant, so this hunt errs toward recall:

```kusto
// HOLLOWGRAPH — calendar events written by an app, dated to the far future.
OfficeActivity
| where TimeGenerated > ago(7d)
| where RecordType in ("ExchangeItem", "ExchangeItemAggregated")
| where Operation in ("Create", "Update", "MailItemsAccessed")
| where ItemType == "CalendarItem" or Item has "IPM.Appointment"
| extend app = coalesce(column_ifexists("AppId",""), column_ifexists("ClientAppId",""))
| where isnotempty(app)                                   // app-driven, not user-driven
| where tostring(Item) has "2050" or tostring(OfficeObjectId) has "2050"
| project TimeGenerated, UserId, app, Operation, ItemType, Item, ClientIP
| sort by TimeGenerated desc
```

If your tenant streams richer Graph activity to `MicrosoftGraphActivityLogs`, hunt directly on the request signature — `POST`/`PATCH` to `/calendar/events` and `/events/{id}/attachments` from the app-only token:

```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| where RequestUri has_any ("/calendar/events", "/events/") and RequestUri has "attachments"
| where RequestMethod in ("POST", "PATCH")
| where isnotempty(ServicePrincipalId)                    // app-only caller
| summarize calls=count(), uris=make_set(RequestUri, 15), ips=make_set(IPAddress, 10)
          by ServicePrincipalId, AppId, UserId
| where calls >= 3
| sort by calls desc
```

### 5.3 KQL — DNS Tunneling to the C2 Domain (`AAAA` / High Entropy)

Endpoint DNS telemetry (`DeviceNetworkEvents` / `DeviceDnsEvents`) catches the credential-refresh channel. Two hunts: exact <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span>, and behavioural:

```kusto
// (a) Exact IOC — any resolution of the known C2 domain.
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteUrl endswith "cloudlanecdn.com" or RemoteUrl has "cloudlanecdn"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP

// (b) Behavioural — bursty AAAA lookups with long, high-entropy labels to one domain.
DeviceDnsEvents
| where TimeGenerated > ago(7d)
| where DnsQueryType == "AAAA" or QueryType == "AAAA"
| extend q = tolower(DnsQuery)
| extend reg = strcat(tostring(split(q, ".")[-2]), ".", tostring(split(q, ".")[-1]))
| extend leftLabel = tostring(split(q, ".")[0])
| where strlen(leftLabel) >= 12                           // long random label
| summarize queries=count(), distinctLabels=dcount(leftLabel),
            sample=make_set(q, 8) by DeviceName, reg, bin(TimeGenerated, 1h)
| where queries >= 30 and distinctLabels >= 20            // tunneling-shaped volume
| sort by queries desc
```

### 5.4 KQL — On-Disk Config Artefact (`logAzure.txt`)

The implant drops its configuration to `logAzure.txt`. That filename plus a co-located Brotli-named DLL is a strong host-level indicator:

```kusto
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where FileName =~ "logAzure.txt"
| project TimeGenerated, DeviceName, ActionType, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by TimeGenerated desc
```

### 5.5 Hunt Hypotheses for the Threat-Hunting Team

- **H1 — Ghost of Calendars Future**: *"Any calendar event in the tenant with a start date beyond, say, 2030, carrying a file attachment, written by an app principal."* Cross-reference `AppId` against your sanctioned scheduler/CRM allow-list.
- **H2 — Silent App on Graph**: *"A <span class="glossary-term" data-bs-toggle="tooltip" title="The local identity object created in an Entra tenant that represents an application instance. Required for assigning users and permissions to applications.">service principal</span> acquires <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> app-only tokens but has no corresponding interactive user activity and originates from a hosting/VPS ASN."* Pivot on newly created client secrets for that app (`Add service principal credentials` in `AuditLogs`).
- **H3 — IPv6 Whisper**: *"A workstation issues sustained `AAAA` queries with high-entropy leftmost labels to a single registrable domain, with no matching `A` queries."* Tunneling channels frequently prefer `AAAA` for the 16-byte payload width.
- **H4 — Brotli Impostor**: *"A DLL claiming to be a Brotli/compression library that is NativeAOT-compiled and loads from a user-writable path."* Combine with `logAzure.txt` presence.

### 5.6 IOCs (Group-IB, 20 July 2026)

Campaigns rotate infrastructure; treat these as illustrative, not exhaustive.

- **<span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> domain (DNS tunneling):** `cloudlanecdn[.]com`
- **On-disk config:** `logAzure.txt`
- **Calendar artefacts:** events dated `2050-05-13` (22:00–23:00 UTC); subjects that are bare GUIDs, or match `Event ID: <7-char taskID>` / `Boss{..}ID{..}`; attachments named `File{n}.txt`
- **SHA-256 hashes:**
  - `75e51774b8f79e5f256eaae639635f911b3e744d4774fd6068dd980255621509`
  - `f3f3006f8304788251b153d53b305322b8acab0c66ec816b8d9f101bcc851da3`
  - `b3d0f6e4e3be395fd7cf9e8101c89963d77216578cbb117a6ac9bc3564485eff`

---

## 6. Mitigation: What Actually Works

There is no patch — Microsoft has no vulnerability here. Mitigation is about **shrinking and watching the app-permission surface**, then hardening DNS. It is layered.

### 6.1 Inventory and Restrict Graph Calendar Application Permissions

The single highest-value action: find every <span class="glossary-term" data-bs-toggle="tooltip" title="The local identity object created in an Entra tenant that represents an application instance. Required for assigning users and permissions to applications.">service principal</span> in your tenant holding `Calendars.ReadWrite` (and `Calendars.Read`) as an **application** permission, and justify each one. HOLLOWGRAPH needs an app identity with this grant; if you shrink the set to only sanctioned integrations, you shrink the attacker's usable identities.

```powershell
Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All"

# Microsoft Graph resource SP
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# App-role IDs for calendar application permissions
$calRW = ($graph.AppRoles | Where-Object { $_.Value -eq "Calendars.ReadWrite" }).Id
$calR  = ($graph.AppRoles | Where-Object { $_.Value -eq "Calendars.Read" }).Id

# Every SP that has been granted those application permissions on Graph
Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All |
        Where-Object { $_.ResourceId -eq $graph.Id -and $_.AppRoleId -in @($calRW, $calR) } |
        ForEach-Object {
            [pscustomobject]@{
                App        = $sp.DisplayName
                AppId      = $sp.AppId
                SpId       = $sp.Id
                Permission = if ($_.AppRoleId -eq $calRW) { "Calendars.ReadWrite" } else { "Calendars.Read" }
                Granted    = $_.CreatedDateTime
            }
        }
} | Sort-Object Granted -Descending | Format-Table -Auto
```

Anything on that list you cannot map to a known business integration is an investigation lead. Where a real integration only needs a subset of mailboxes, scope it with **Application Access Policy** (`New-ApplicationAccessPolicy`) so the app can only touch the mailboxes it should — a broad-tenant `Calendars.ReadWrite` grant is exactly the blast radius HOLLOWGRAPH wants.

### 6.2 Kill Long-Lived Client Secrets; Prefer Certificates + Short Lifetimes

HOLLOWGRAPH persists on a stored **client secret** and even rebuilds it over DNS. Move sanctioned apps to **certificate credentials**, enforce short secret lifetimes via app-management policy, and alert whenever a *new* secret is added to any app:

```kusto
// Alert on new client secret / credential added to any application.
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Update application", "Add service principal credentials",
                               "Update application – Certificates and secrets management")
| where Result == "success"
| mv-expand td = TargetResources
| project TimeGenerated, InitiatedBy, OperationName,
          app = tostring(td.displayName), appId = tostring(td.id)
| sort by TimeGenerated desc
```

### 6.3 Conditional Access for Workload Identities

If you hold Entra Workload Identities Premium, apply **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft Entra ID&#39;s policy engine that evaluates user, device, location, app, and risk signals at sign-in to gate access or require additional controls.">Conditional Access</span> for service principals** to the sanctioned calendar apps: bind them to known IP ranges so an app-only token acquired from an attacker's VPS ASN is blocked outright. This directly counters the anomalous-origin pattern in §5.1.

### 6.4 DNS Egress Controls

Route workstation DNS through **controlled resolvers**, enable **DNS filtering/sinkholing**, and add `cloudlanecdn[.]com` to your blocklist now. Turn on detection for tunneling-shaped behaviour — sustained `AAAA` queries with long, high-entropy labels to a single second-level domain — which is the generic signature this channel cannot hide.

### 6.5 Mailbox & Graph Audit Coverage

Confirm **mailbox auditing** is on for the mailboxes your integrations touch and that **`MicrosoftGraphActivityLogs`** (or equivalent) is streaming to your SIEM. You cannot hunt §5.2 if the calendar-write events never leave Microsoft. This is table stakes, and many tenants still have Graph activity logging off by default.

---

## 7. Operational Playbook for SOC and IR

If the detections in Section 5 fire on a real mailbox/app, the response centres on **revoking the app identity and purging the dead drop** — not on reimaging one endpoint, because the channel lives in the cloud.

![Diagram](https://kroki.io/mermaid/svg/eNptU0tvGjEQvudXzKmiIgSUpIdyIyFNUqEGQSUOVQ_GnmVHeO2VZ5ZHq_73jjcEUFpLsOx4Ht9jEKrQU8AL0CMkHuHpZTJ5WTzORtMneJ7BGC0xxQDfz1MZrbTB7gA6Y5TX14_tXT73MRSUKjB13YvB7-ExmboEs2wYYQjPDoNQsYdRXT876IKNVZ1iRYwOKkN-GXdQaACYVqFHAfqHDj6u-B8EEvVxM6igo3PFaLqUCNQOkf0J1Qw3cY0ZFNiE7bXxrHhmWMUNgvWksdw6oXDfYhK-hPRaNZ_qryIhlzpvjYGPbcfEZqnK9TWBJZGVnDyEOx_t-sggJmAba4TYCNwbj8GZxFczNG6RSN7rmum0vK5L6EybtMKWlNN0cCnWJ1Zj9GoAXA8-DQA3SuCMkc5LRnR0F6iqvVF29jD6LdcEB1_I4-_w50p2AkbE2LLKd8cRUyWGSfvhJqtqs4cPuzomOXTpn1XBEouYMlTFlcnoW_6oZGTfm3ddHljeKs2HZBxZo2T0rowsJ5JPjUJX80e_moQtzi7cpSieYDyZ5JXi6HNlLlPTbPRehwAbpY0aWLZmlIZLPPGaU1iXUa0bf5sfDbM-Nk6lQuvCj6ufuprtDhBuYaQHSmJVdP-eyG3Zhc6IGZkBVRtWoCf889Z63BXkRR3JNUNYlEZAI8jgsVDp-Vz9S1AHE2xz0paCi1vo3MDXJvQ-67eHpeH2D3m231GyBB_e4A7fIsb7dusPm30JpnH03y2EVTLZQ8Ggz95W7b74CzniXN8=)

The non-negotiable first-hour actions:

1. **Revoke the application's credentials and refresh tokens.** Remove every client secret and certificate on the abused app (`Remove-MgApplicationPassword` / certificate removal) and revoke the <span class="glossary-term" data-bs-toggle="tooltip" title="The local identity object created in an Entra tenant that represents an application instance. Required for assigning users and permissions to applications.">service principal</span>'s tokens. The stored/DNS-refreshed secret is the attacker's lifeline; kill it first. Note the DNS channel *exists to re-supply this* — so also sinkhole `cloudlanecdn[.]com` so it cannot be replenished.
2. **Preserve, then purge the dead drop.** Before deleting, **export** the 2050-dated events and their `File{n}.txt` attachments — they are your record of what was tasked and exfiltrated. Then delete them so the operator loses the channel.

Then, in parallel:

- **Scope exfiltration.** Enumerate every `Boss{..}ID{..}` / GUID-subject event with attachments to reconstruct what left and when. Group-IB's observed window (3 June – 9 July 2026) is a baseline, not a bound for your tenant.
- **Tenant-wide app-permission audit.** Run §6.1 across the whole directory — assume the operators may hold more than one calendar-capable app.
- **Host eradication.** Isolate hosts with `logAzure.txt` or the Brotli-masquerading DLL, collect samples, and block the three SHA-256 hashes.
- **DNS retro-hunt.** Pull historical `AAAA` resolutions for `cloudlanecdn[.]com` to enumerate every infected host, not just the ones that alerted.

---

## 8. The Wider Picture: Trusted SaaS as C2

HOLLOWGRAPH is not a one-off gimmick; it is the latest entry in a lengthening pattern of **living-off-trusted-services (LOTS)** command-and-control. Attackers have already run <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> through Outlook inboxes, mail draft folders, OneDrive, Teams, GitHub, Google Drive, and Notion. The calendar — with its attachment support, two-way sync, and total absence of monitoring — was simply the next unwatched room. Dating events to 2050 is the small, elegant twist that keeps the channel invisible to the one human who could stumble on it.

The strategic lesson for a cloud-security program in 2026 is that **the boundary you defend is no longer the network edge; it is the app-permission model of your SaaS estate.** Every application permission you have granted — especially the broad, read-write, application-scoped ones on Graph — is a potential covert channel if the credential behind it is ever stolen or the app is ever attacker-controlled. The questions that matter now are inventory questions: *Which apps can read and write my users' calendars, mail, and files as themselves? Who owns each one? When were their secrets last rotated? Would I see it if one of them started writing events to the year 2050?*

If you cannot answer those quickly, that gap — not any single implant — is the exposure. Build the app-only Graph and far-future-calendar detections from Section 5 into your SIEM this week, run the §6.1 permission inventory, and put certificate credentials and CA-for-workload-identities on the roadmap for your sanctioned integrations. The Cavern operators, and everyone who copies them, are counting on the fact that most tenants have never looked.

---

## Glossary

These terms are auto-tooltipped by the publishing pipeline; definitions are repeated here for the static reader.

- **<span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> API** — Microsoft's unified REST API for Microsoft 365 (mail, calendar, files, Teams, directory). HOLLOWGRAPH uses it as its entire <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> transport.
- **Client-credentials grant** — <span class="glossary-term" data-bs-toggle="tooltip" title="The current widely deployed version of OAuth, used by Microsoft Entra ID, Google, and most modern identity providers.">OAuth 2.0</span> flow where an application authenticates *as itself* (no user) using a `client_id` + `client_secret`/certificate, receiving an app-only token whose rights come from admin-consented application permissions.
- **Application permission (app-only)** — A Graph permission (e.g. `Calendars.ReadWrite`) granted to an application to act without a signed-in user, across the tenant unless scoped by an Application Access Policy.
- **Dead drop** — A covert-communications technique where two parties exchange messages via a shared location neither owns openly; here, a compromised mailbox's calendar.
- **DNS tunneling** — Encoding data inside DNS queries/responses to move it past controls; HOLLOWGRAPH decodes credential bytes from IPv6 `AAAA` answers.
- **AAAA record** — A DNS record mapping a name to an IPv6 (128-bit / 16-byte) address; its width makes it convenient for smuggling 14 payload bytes per answer.
- **NativeAOT** — Ahead-of-time compilation for .NET that produces a native binary and strips managed metadata, hampering .NET-aware reverse engineering and detection.
- **RSA-OAEP + AES-256-GCM (hybrid encryption)** — A scheme where RSA-OAEP wraps a per-message AES key and AES-256-GCM encrypts the bulk payload; HOLLOWGRAPH uses separate RSA key pairs per direction.
- **Cavern / Cavern Manticore** — A modular Iranian-nexus backdoor framework (Check Point: "Cavern Manticore," linked to Iran's MOIS, overlapping MuddyWater and Lyceum) to which Group-IB attributes HOLLOWGRAPH with high confidence.
- **Lyceum** — An Iranian-nexus <span class="glossary-term" data-bs-toggle="tooltip" title="An individual or a group of individuals that takes action to cause a malicious incident, or to pose a threat to the security of an organization&#39;s network.">threat actor</span>, assessed as a subgroup of OilRig; HOLLOWGRAPH shows a *low-confidence* overlap with it.
- **Living-off-trusted-services (LOTS)** — Using legitimate SaaS platforms (Graph, OneDrive, GitHub, etc.) as <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> so malicious traffic blends with sanctioned traffic.

---

## Sources & Further Reading

### Primary Research

- [HOLLOWGRAPH: Turning Microsoft 365 Calendars into Covert Command-and-Control Channels — Group-IB](https://www.group-ib.com/blog/hollowgraph-microsoft-365/) — The originating technical report (Javier Castillo, 20 July 2026): full Graph call flow, DNS-tunneling scheme, configuration, IOCs, and Cavern linkage.
- [Cavern Manticore: Exposing an Iran-linked Modular C2 Framework — Check Point Research](https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/) — Check Point's July 2026 documentation of the Cavern framework and its MOIS-linked attribution overlapping MuddyWater and Lyceum.

### Industry Press and Corroboration

- [HollowGraph Malware Hides C2 and Stolen Files in Microsoft 365 Events Dated 2050 — The Hacker News](https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html) — Concise corroboration of the calendar dead-drop mechanism, DNS credential channel, and victimology.
- [HOLLOWGRAPH malware turns Microsoft 365 calendars into an espionage channel — Help Net Security](https://www.helpnetsecurity.com/2026/07/20/hollowgraph-malware-microsoft-365-calendar/) — Summary framing for defenders.
- [Microsoft 365 calendars become spy drop boxes in HOLLOWGRAPH campaign — The Register](https://www.theregister.com/security/2026/07/20/microsoft-365-calendars-become-spy-drop-boxes-in-hollowgraph-campaign/5274982) — Press narrative with attribution nuance.
- [New HollowGraph malware uses Microsoft Graph for stealthy C2 comms — BleepingComputer](https://www.bleepingcomputer.com/news/security/new-hollowgraph-malware-uses-microsoft-graph-for-stealthy-c2-comms/) — Technical summary and defender guidance.

### Detection and Defensive Analysis

- [HOLLOWGRAPH Backdoor Turns Microsoft 365 Calendars Into a C2 Channel — Picus Security](https://www.picussecurity.com/resource/blog/hollowgraph-backdoor-turns-microsoft-365-calendars-into-a-c2-channel) — Control-validation-oriented breakdown of the <span class="glossary-term" data-bs-toggle="tooltip" title="Tactics, Techniques, and Procedures, the behavior of a threat actor. A tactic is the highest-level description of this behavior, while techniques give a more detailed description of behavior in the context of a tactic, and procedures an even lower-level, highly detailed description in the context of a technique.">TTPs</span>.
- [HOLLOWGRAPH: Microsoft 365 Calendar C2 Attack Analysis — Gurucul](https://gurucul.com/latest-threats/hollowgraph-turning-microsoft-365-calendars-into-covert-command-and-control-channels/) — Detection-engineering perspective and hunting ideas.
- [Threat Advisory: HOLLOWGRAPH malware — UnderProtection / uvcyber](https://www.uvcyber.com/resources/reports/threat-advisory-hollowgraph-malware) — Advisory-format <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> and mitigation summary.

### Background: Graph API and Trusted-Service Abuse

- [Graph API threats — Broadcom/Symantec threat intelligence](https://www.security.com/threat-intelligence/graph-api-threats) — Prior art on adversaries abusing <span class="glossary-term" data-bs-toggle="tooltip" title="Microsoft&#39;s unified API for accessing data and intelligence across Microsoft 365 services (Outlook, Teams, OneDrive, SharePoint, Entra).">Microsoft Graph</span> (Outlook, drafts, OneDrive) for <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span>, the lineage HOLLOWGRAPH extends.

---

*Next week (rotation: Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel): a threat-intel deep-dive on the most operationally significant new CISA KEV addition or vendor advisory of the week — actionable detections and patch-prioritisation guidance for <span class="glossary-term" data-bs-toggle="tooltip" title="Security Operations Center. The team and tooling responsible for monitoring, detecting, and responding to security events across an organization.">SOC</span> teams.*
