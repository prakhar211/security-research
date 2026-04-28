---
title: "From Tycoon2FA to EvilTokens: The AiTM Phishing Pipeline That Won't Die"
date: 2026-04-28
author: "Prakhar Gupta"
category: threat-intelligence
tags:
  - aitm
  - phishing
  - tycoon2fa
  - eviltokens
  - device-code-phishing
  - token-theft
  - microsoft-365
  - detection-engineering
  - mdr
mitre_techniques:
  - id: T1566.002
    name: Spearphishing Link
  - id: T1557
    name: Adversary-in-the-Middle
  - id: T1528
    name: Steal Application Access Token
  - id: T1098
    name: Account Manipulation
  - id: T1114
    name: Email Collection
  - id: T1534
    name: Internal Spearphishing
  - id: T1078.004
    name: "Valid Accounts: Cloud Accounts"
tldr: "Europol disrupted Tycoon2FA in March 2026, but affiliates pivoted to EvilTokens — a device code PhaaS kit with AI-powered BEC. Here's the full attack chain, detection queries for LogScale/KQL/DataPrime, and IOCs."
ioc_campaign: "tycoon2fa-eviltokens-2026"
severity: high
---

On March 4, 2026, Europol announced the disruption of Tycoon2FA — the largest AiTM phishing-as-a-service platform, responsible for tens of millions of phishing emails per month hitting nearly 100,000 organizations globally. Within days, the platform was back. Within weeks, its affiliates had a new weapon: **EvilTokens**, a device code phishing kit that doesn't need a fake login page at all.

This post covers the full lifecycle: what Tycoon2FA was, how the takedown played out, why EvilTokens is harder to detect, and — most importantly — the hunting queries and detection logic you need in your SOC right now.

## The Tycoon2FA Era (2023–2026)

Tycoon2FA emerged in August 2023 and rapidly became the dominant AiTM phishing-as-a-service platform. At its peak, it powered campaigns against over 500,000 organizations per month.

### How It Worked

{% include attack-flow.html
   title="Tycoon2FA — AiTM Attack Flow"
   steps="Phishing Email|Reverse Proxy Page|Credential + MFA Capture|Token Replay|Mailbox Compromise"
   colors="#e74c3c|#e67e22|#e74c3c|#9b59b6|#e67e22"
   icons="✉️|🌐|🔓|🔑|📧"
   description="Tycoon2FA proxies the real Microsoft login, intercepting session cookies after MFA completion. The attacker replays the stolen cookie from their own infrastructure."
%}

The attack flow was textbook AiTM:

1. **Lure delivery** — phishing email with a link to a credential page, often behind Cloudflare Turnstile CAPTCHA to block automated analysis
2. **Reverse proxy** — victim lands on a page that proxies the real Microsoft login (or Gmail). The victim sees a legitimate-looking authentication flow
3. **Credential + session cookie capture** — the reverse proxy intercepts both the password and the session token issued after MFA completion
4. **Token replay** — attacker replays the stolen session cookie from their own infrastructure, bypassing MFA entirely
5. **Post-compromise** — mailbox rules for persistence, internal phishing for lateral movement, BEC for monetization

### Why It Scaled

Tycoon2FA operated as a true SaaS: affiliates purchased access, received a control panel for building campaigns, and the platform handled hosting, domain rotation, and anti-analysis evasion. Kits included pre-built templates for Microsoft 365 and Google Workspace.

The platform went through multiple updates, most notably in April 2025 when it rolled out significant anti-detection improvements including enhanced CAPTCHA challenges, obfuscated JavaScript, and better evasion of email security gateways.

## The Europol Disruption (March 4, 2026)

A coordinated action led by Microsoft and Europol, with law enforcement from Latvia, Lithuania, Portugal, Poland, Spain, and the UK, resulted in:

- **330 domains seized** — control panels and phishing pages
- **Activity dropped to 25%** of pre-disruption levels on March 4–5
- Intelligence shared through Europol's Cyber Intelligence Extension Programme

{% include trend-chart.html
   title="Tycoon2FA Activity Levels Around Europol Disruption"
   labels="Feb 28|Mar 1|Mar 2|Mar 3|Mar 4|Mar 5|Mar 6|Mar 7|Mar 8|Mar 10"
   values="100|100|100|100|25|25|60|85|95|100"
   highlight_indices="4|5"
   unit="%"
   annotation="Europol disruption"
   annotation_index="4"
%}

### But It Didn't Hold

The disruption proved temporary. Researchers at CrowdStrike and others observed Tycoon2FA returning to near-full operational capacity within days. Some older infrastructure was never taken offline. New domains and IP addresses were registered rapidly post-takedown.

The takedown did, however, trigger an important shift: **affiliates began migrating to device code phishing**, a technique that sidesteps the need for reverse proxies and fake login pages entirely.

## Enter EvilTokens: Device Code Phishing-as-a-Service

In mid-February 2026, Sekoia's TDR team uncovered **EvilTokens** — a turnkey device code phishing kit sold as PhaaS. By March, it was being widely adopted by former Tycoon2FA affiliates and BEC operators.

### How Device Code Phishing Works

{% include attack-flow.html
   title="EvilTokens — Device Code Phishing Flow"
   steps="Attacker Requests Code|Lure: 'Verify Device'|Victim Enters Code at MS|Attacker Gets Tokens|AI-Powered BEC"
   colors="#9b59b6|#e74c3c|#e67e22|#e74c3c|#9b59b6"
   icons="🖥️|✉️|🔐|🔑|🤖"
   description="The victim authenticates on a legitimate Microsoft URL. No fake login page needed — the attacker receives OAuth tokens directly."
%}

The brilliance — and danger — of this technique is that the victim interacts with a **legitimate Microsoft URL** throughout:

1. **Attacker initiates a device code flow** — requests a device code from Microsoft's OAuth endpoint (`https://login.microsoftonline.com/common/oauth2/v2.0/devicecode`)
2. **Lure delivery** — victim receives a message (email, Teams, or even a phone call) asking them to verify their device at `https://microsoft.com/devicelogin` and enter a code
3. **Victim authenticates** — because the URL is genuinely microsoft.com, email security gateways don't flag it. The victim enters the code and completes MFA on the real Microsoft page
4. **Attacker receives tokens** — the device code flow grants the attacker a refresh token and access token, providing persistent access that survives password changes

### EvilTokens Specific Features

EvilTokens goes beyond basic device code phishing:

- **AI-powered BEC automation** — uses LLMs to craft contextual replies from compromised mailboxes
- **Built-in webmail interface** — operators can read and send emails directly from the kit's control panel
- **Email harvesting and reconnaissance** — automated scraping of contacts, org charts, and financial conversations
- **Access weaponization** — automated creation of inbox rules, OAuth app registrations, and MFA method additions
- **Bot protection** — X-Antibot-Token headers, Cloudflare Workers hosting, multi-redirect chains through trusted domains

### EvilTokens Infrastructure Indicators

The kit's phishing pages use **Cloudflare Workers** as the hosting layer:

- HTTP paths: `/api/device/start`, `/api/device/status/*`
- Custom header: `X-Antibot-Token`
- Multiple `*.workers.dev` domains as entry points
- Redirect chains through legitimate services before reaching the phishing page

## Attack Chain Comparison

| Stage | Tycoon2FA (AiTM) | EvilTokens (Device Code) |
|-------|-------------------|--------------------------|
| **Lure** | Link to fake login page | "Verify your device" with legit Microsoft URL |
| **Credential capture** | Reverse proxy intercepts session cookie | OAuth device code flow grants tokens directly |
| **MFA bypass** | Stolen session cookie replays post-MFA | Device code completes real MFA on behalf of attacker |
| **Persistence** | Session cookie (short-lived) | Refresh token (long-lived, survives password reset) |
| **Detection difficulty** | URL reputation + proxy detection | Legitimate URLs — very hard to block at the gateway |
| **Infrastructure** | Custom phishing domains | Cloudflare Workers + legitimate Microsoft endpoints |

## Detection Engineering

### Signal 1: AiTM Session Cookie Theft (Tycoon2FA-style)

Detect sessions where the sign-in location doesn't match the subsequent session usage location — the hallmark of token replay.

#### KQL — Microsoft Sentinel

```kql
// AiTM token replay: sign-in from one location, session used from another
let timeframe = 7d;
let token_replay_threshold = 500; // km distance threshold
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0
| where IsInteractive == true
| extend City = tostring(LocationDetails.city),
         Country = tostring(LocationDetails.countryOrRegion),
         Latitude = toreal(LocationDetails.geoCoordinates.latitude),
         Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| project SessionId, UserPrincipalName, AppDisplayName,
          AuthCity = City, AuthCountry = Country,
          AuthLat = Latitude, AuthLon = Longitude,
          AuthTime = TimeGenerated, IPAddress
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType == 0
    | where IsInteractive == false
    | extend City = tostring(LocationDetails.city),
             Country = tostring(LocationDetails.countryOrRegion),
             Latitude = toreal(LocationDetails.geoCoordinates.latitude),
             Longitude = toreal(LocationDetails.geoCoordinates.longitude)
    | project SessionId, ReplayCity = City, ReplayCountry = Country,
              ReplayLat = Latitude, ReplayLon = Longitude,
              ReplayTime = TimeGenerated, ReplayIP = IPAddress
) on SessionId
| where AuthCountry != ReplayCountry
| where ReplayTime between (AuthTime .. (AuthTime + 1h))
| project UserPrincipalName, AuthTime, AuthCountry, AuthCity,
          ReplayTime, ReplayCountry, ReplayCity, ReplayIP, AppDisplayName
| sort by AuthTime desc
```

#### CrowdStrike LogScale

```
// AiTM detection: non-interactive sign-in from a different country within 1h of interactive auth
#repo=entra_signins
| ResultType = 0
| IsInteractive = true
| groupBy([UserPrincipalName, SessionId, LocationDetails.countryOrRegion],
    function=[earliest(TimeGenerated, as=AuthTime), collect(IPAddress, as=AuthIP)])
| join(
    {#repo=entra_signins
     | ResultType = 0
     | IsInteractive = false
     | rename(LocationDetails.countryOrRegion, as=ReplayCountry)
     | rename(IPAddress, as=ReplayIP)},
    field=SessionId, include=[ReplayCountry, ReplayIP, TimeGenerated])
| LocationDetails.countryOrRegion != ReplayCountry
| test(TimeGenerated - AuthTime < 3600000)
| table([UserPrincipalName, AuthTime, LocationDetails.countryOrRegion,
         ReplayCountry, AuthIP, ReplayIP])
```

#### Coralogix DataPrime

```
source entra_signins
| filter result_type == '0' && is_interactive == true
| groupby session_id, user_principal_name
    agg auth_country = first(location.country),
        auth_ip = first(ip_address),
        auth_time = min(timestamp)
| join source entra_signins
    | filter result_type == '0' && is_interactive == false
    on session_id
| filter auth_country != location.country
| filter timestamp - auth_time < 3600s
| select user_principal_name, auth_time, auth_country, auth_ip,
         location.country as replay_country, ip_address as replay_ip
| orderby auth_time desc
```

### Signal 2: Device Code Flow Authentication (EvilTokens-style)

Device code authentication is rare in most enterprises. Any device code flow from an unrecognized device should be investigated.

#### KQL — Microsoft Sentinel

```kql
// Device code authentication — flag all instances for investigation
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0
| extend DeviceDetail = tostring(DeviceDetail.displayName),
         OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser),
         Country = tostring(LocationDetails.countryOrRegion),
         City = tostring(LocationDetails.city)
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          IPAddress, Country, City, DeviceDetail, OS, Browser,
          ConditionalAccessStatus, AuthenticationRequirement
| sort by TimeGenerated desc
```

```kql
// Device code flow followed by suspicious email activity within 1h
let device_code_auths = SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0
| project DCTime = TimeGenerated, UserPrincipalName, DCIPAddress = IPAddress;
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
                        "MailItemsAccessed", "Send")
| join kind=inner device_code_auths on $left.AccountObjectId == $right.UserPrincipalName
| where TimeGenerated between (DCTime .. (DCTime + 1h))
| project TimeGenerated, UserPrincipalName, ActionType, DCTime, DCIPAddress
| sort by TimeGenerated desc
```

#### CrowdStrike LogScale

```
// Device code authentication events
#repo=entra_signins
| AuthenticationProtocol = "deviceCode"
| ResultType = 0
| table([TimeGenerated, UserPrincipalName, AppDisplayName,
         IPAddress, LocationDetails.countryOrRegion,
         DeviceDetail.displayName, ConditionalAccessStatus])
| sort(TimeGenerated, order=desc)
```

#### Coralogix DataPrime

```
source entra_signins
| filter authentication_protocol == 'deviceCode'
  && result_type == '0'
| select timestamp, user_principal_name, app_display_name,
         ip_address, location.country, device_detail.display_name,
         conditional_access_status
| orderby timestamp desc
```

### Signal 3: Post-Compromise — Inbox Rule Creation

Both Tycoon2FA and EvilTokens operators create inbox rules to intercept replies and hide evidence.

#### KQL — Microsoft Sentinel

```kql
// Suspicious inbox rules: forwarding or deleting inbound mail
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleParams = tostring(RawEventData)
| where RuleParams has_any ("ForwardTo", "ForwardAsAttachmentTo",
                             "RedirectTo", "DeleteMessage",
                             "MoveToFolder", "MarkAsRead")
| where RuleParams !has "IT-Notifications" // tune out known legitimate rules
| project TimeGenerated, AccountDisplayName, ActionType,
          RuleParams, IPAddress, UserAgent
| sort by TimeGenerated desc
```

### Signal 4: New MFA Method Registration After Compromise

Attackers add their own authenticator app or phone number for persistent MFA control.

#### KQL — Microsoft Sentinel

```kql
// New MFA method added — correlate with recent risky sign-in
let risky_users = SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("medium", "high")
| distinct UserPrincipalName;
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("User registered security info",
                                "User started security info registration",
                                "Admin registered security info")
| where InitiatedBy.user.userPrincipalName in (risky_users)
| project TimeGenerated, OperationName,
          User = tostring(InitiatedBy.user.userPrincipalName),
          TargetResources
| sort by TimeGenerated desc
```

## Indicators of Compromise

{% include ioc-table.html campaign=page.ioc_campaign %}

### EvilTokens Infrastructure

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `singer-bodners-bau-at-s-account[.]workers[.]dev` | EvilTokens phishing page |
| Domain | `dibafef289[.]workers[.]dev` | EvilTokens phishing page |
| HTTP Path | `/api/device/start` | Device code initiation |
| HTTP Path | `/api/device/status/*` | Authentication polling |
| HTTP Header | `X-Antibot-Token` | Bot protection header |

### Tycoon2FA Infrastructure (Post-Disruption)

See the [STIX 2.1 bundle](https://github.com/prakhar211/security-research/tree/main/iocs/tycoon2fa-eviltokens-2026) and [CSV feed](https://github.com/prakhar211/security-research/tree/main/iocs/tycoon2fa-eviltokens-2026) for machine-readable IOCs.

## Mitigations & Recommendations

1. **Block device code flow via Conditional Access** — create a policy that blocks the "Device code flow" authentication grant type for all users except a scoped exception group. This is the single most impactful control against EvilTokens.

2. **Enforce token protection (token binding)** — Microsoft's token protection feature binds access tokens to the device they were issued on, making stolen tokens unusable on attacker infrastructure. Enable this in Conditional Access for critical apps.

3. **Deploy phishing-resistant MFA** — FIDO2 security keys and Windows Hello for Business are resistant to both AiTM and device code phishing. Passkeys (rolling out in Entra as of late April 2026) offer the same protection with better UX.

4. **Monitor for anomalous token usage** — implement the KQL queries above as analytics rules in Sentinel. Set up near-real-time alerts for device code auth, geographic impossible travel, and inbox rule creation.

5. **Restrict OAuth app consent** — set user consent to "Do not allow user consent" in Entra ID → Enterprise applications → Consent and permissions. This prevents attackers from registering persistent OAuth apps post-compromise.

6. **Continuous access evaluation (CAE)** — enable CAE to revoke tokens in near real-time when risk signals change, reducing the window an attacker has with a stolen token.

7. **Security awareness** — train users that legitimate Microsoft or IT support will never ask them to enter a device code. Flag any "verify your device" messages as suspicious.

## Timeline

{% include timeline-visual.html
   title="Tycoon2FA → EvilTokens Campaign Timeline"
   events="Aug 2023: Tycoon2FA first observed in the wild|Apr 2025: Major anti-detection update to Tycoon2FA kit|Feb 2026: EvilTokens phishing pages first seen|Mar 4, 2026: Europol + Microsoft disrupt Tycoon2FA — 330 domains seized|Mar 6, 2026: Tycoon2FA back to near-full operational capacity|Mar 2026: Sekoia publishes EvilTokens analysis|Apr 2026: Microsoft publishes AI-enabled device code phishing report|Apr 2026: Former Tycoon2FA affiliates widely adopt device code phishing"
   highlights="3|4"
%}

## References

- [Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)
- [Europol: Global phishing-as-a-service platform taken down](https://www.europol.europa.eu/media-press/newsroom/news/global-phishing-service-platform-taken-down-in-coordinated-public-private-action)
- [New widespread EvilTokens kit: device code phishing as-a-service — Sekoia](https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1/)
- [EvilTokens: AI-Enabled Device Code Phishing Campaign — Coralogix](https://coralogix.com/blog/evil-token-ai-enabled-device-code-phishing-campaign/)
- [Tycoon2FA PhaaS platform persists following takedown — CrowdStrike](https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/)
- [Tycoon 2FA phishers scatter, adopt device code phishing — Dark Reading](https://www.darkreading.com/threat-intelligence/tycoon-2fa-hackers-device-code-phishing)
- [Token theft playbook — Microsoft Learn](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook)
- [AiTM & BEC threat hunting with KQL — Microsoft Community](https://techcommunity.microsoft.com/blog/azuredataexplorer/aitm--bec-threat-hunting-with-kql/3885166)
- [Detecting AiTM Phishing via 3rd-Party Network events — Microsoft Sentinel Blog](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/detecting-aitm-phishing-via-3rd-party-network-events-in-unified-security-operati/4224653)
- [Analyzing the rise in device code phishing attacks in 2026 — Push Security](https://pushsecurity.com/blog/device-code-phishing)
