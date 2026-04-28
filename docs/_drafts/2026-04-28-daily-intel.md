---
title: "Threat Intel Digest — daily-intel"
date: 2026-04-28
author: "Prakhar Gupta"
category: threat-intelligence
tags:
  - threat-intel
  - automated-scrape
  - daily-intel
tldr: "Automated threat intel digest: 50 posts scraped, 63 IOCs extracted, 16 ATT&CK techniques mapped."
mitre_techniques:
  - id: T1053
    name: Scheduled Task/Job
  - id: T1059
    name: Command and Scripting Interpreter
  - id: T1059.001
    name: PowerShell
  - id: T1068
    name: Exploitation for Privilege Escalation
  - id: T1078
    name: Valid Accounts
  - id: T1078.004
    name: Valid Accounts: Cloud Accounts
  - id: T1136
    name: Create Account
  - id: T1190
    name: Exploit Public-Facing Application
  - id: T1195
    name: Supply Chain Compromise
  - id: T1195.001
    name: Compromise Software Dependencies
  - id: T1486
    name: Data Encrypted for Impact
  - id: T1548
    name: Abuse Elevation Control Mechanism
  - id: T1566
    name: Phishing
  - id: T1566.002
    name: Spearphishing Link
  - id: T1199
    name: Trusted Relationship
  - id: T1547
    name: Boot or Logon Autostart Execution
ioc_campaign: "daily-intel"
severity: medium
---

# Threat Intel Scrape Summary — daily-intel

**Date:** 2026-04-28  
**Posts collected:** 50  
**IOCs extracted:** 63  
**MITRE techniques:** 16  

## Sources

| Platform | Posts |
|----------|-------|
| telegram | 50 |

## MITRE ATT&CK Techniques Observed

| Technique | Name | Tactic | Confidence |
|-----------|------|--------|------------|
| [T1053](https://attack.mitre.org/techniques/T1053) | Scheduled Task/Job | execution | high |
| [T1059](https://attack.mitre.org/techniques/T1059) | Command and Scripting Interpreter | execution | high |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001) | PowerShell | execution | high |
| [T1068](https://attack.mitre.org/techniques/T1068) | Exploitation for Privilege Escalation | privilege-escalation | high |
| [T1078](https://attack.mitre.org/techniques/T1078) | Valid Accounts | initial-access | high |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004) | Valid Accounts: Cloud Accounts | initial-access | high |
| [T1136](https://attack.mitre.org/techniques/T1136) | Create Account | persistence | high |
| [T1190](https://attack.mitre.org/techniques/T1190) | Exploit Public-Facing Application | initial-access | high |
| [T1195](https://attack.mitre.org/techniques/T1195) | Supply Chain Compromise | initial-access | high |
| [T1195.001](https://attack.mitre.org/techniques/T1195/001) | Compromise Software Dependencies | initial-access | high |
| [T1486](https://attack.mitre.org/techniques/T1486) | Data Encrypted for Impact | impact | high |
| [T1548](https://attack.mitre.org/techniques/T1548) | Abuse Elevation Control Mechanism | privilege-escalation | high |
| [T1566](https://attack.mitre.org/techniques/T1566) | Phishing | initial-access | high |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002) | Spearphishing Link | initial-access | high |
| [T1199](https://attack.mitre.org/techniques/T1199) | Trusted Relationship | initial-access | medium |
| [T1547](https://attack.mitre.org/techniques/T1547) | Boot or Logon Autostart Execution | persistence | medium |

## Indicators of Compromise

### CVE (2)

```
CVE-2026-40050
CVE-2026-32202
```

### URL (61)

```
hxxps://ift[.]tt/QsiNKlT
hxxps://ift[.]tt/iYFqIE2
hxxps://ift[.]tt/TpmfgUA
hxxps://ift[.]tt/SGiEtXK
hxxps://ift[.]tt/eglPD84
hxxps://ift[.]tt/4IcZEqz
hxxps://ift[.]tt/U3atqHI
hxxps://ift[.]tt/m9TDizX
hxxps://ift[.]tt/aEP1fKn
hxxps://ift[.]tt/K7eJkWn
hxxps://ift[.]tt/MSZpq71
hxxps://ransom-isac[.]org/blog/dragonbreath-dragon-in-the-kernel/
hxxps://darkatlas[.]io/blog/in-depth-technical-analysis-of-vect-ransomware
hxxps://www[.]cyberproof[.]com/blog/beyond-powershell-analyzing-the-multi-action-clickfix-variant/
hxxps://www[.]360[.]cn/n/13004.html
hxxps://www[.]360[.]cn/n/13005.html
hxxps://www[.]scmp[.]com/news/world/europe/article/3351502/italy-extradite-suspected-chinese-hacker-wanted-us-authorities-source?utm_source=rss_feed
hxxps://securityaffairs[.]com/191343/hacking/critical-bug-in-crowdstrike-logscale-let-attackers-access-files.html
hxxps://www[.]nozominetworks[.]com/blog/backdooring-codesys-applications-via-vulnerability-chaining
hxxps://unit42[.]paloaltonetworks[.]com/monitoring-npm-supply-chain-attacks/
... and 41 more (see CSV)
```

## Notable Posts

### 1. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24543)

> [ ](https://www.bleepingcomputer.com/news/security/money-launderer-linked-to-230m-crypto-heist-gets-70-months-in-prison/)**Money launderer linked to $230M crypto heist gets 70 months in prison**  ​22-year-old Evan Tangeman of Newport Beach, California, was sentenced to 70 months in prison for launde...

### 2. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24547)

> [ ](https://www.bleepingcomputer.com/news/security/pypi-package-with-11m-monthly-downloads-hacked-to-push-infostealer/)**PyPI package with 1.1M monthly downloads hacked to push infostealer**  An attacker pushed a malicious version of the popular elementary-data package Python Package Index (PyPI) to...

### 3. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24545)

> [ ](https://www.bleepingcomputer.com/news/security/webinar-spotting-cyberattacks-before-they-begin/)**Webinar: Spotting cyberattacks before they begin**  On Thursday, April 30 at 2:00 PM ET, BleepingComputer will host a live webinar with threat intelligence company Flare and threat intelligence rese...

### 4. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24546)

> [ ](https://www.bleepingcomputer.com/news/security/home-security-giant-adt-data-breach-affects-55-million-people/)**Home security giant ADT data breach affects 5.5 million people**  The ShinyHunters extortion group stole the personal information of 5.5 million individuals after breaching the systems...

### 5. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24544)

> [ ](https://www.bleepingcomputer.com/news/security/medtronic-confirms-breach-after-hackers-claim-9-million-records-theft/)**Medtronic confirms breach after hackers claim 9 million records theft**  Medical device giant Medtronic disclosed last week that hackers breached its network and accessed data...

### 6. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24548)

> [ ](https://www.bleepingcomputer.com/news/security/ftc-americans-lost-over-21-billion-to-social-media-scams-in-2025/)**FTC: Americans lost over $2.1 billion to social media scams in 2025**  The U.S. Federal Trade Commission (FTC) warned of a massive increase in losses from social media scams since 2...

### 7. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24550)

> [ ](https://www.bleepingcomputer.com/news/security/canada-arrests-three-for-operating-sms-blaster-device-in-toronto/)**Canada arrests three for operating “SMS blaster” device in Toronto**  Canadian authorities have arrested three men for operating an "SMS blaster" device that pretends to be a cellul...

### 8. @blueteamalerts (telegram)

[Source](https://t.me/blueteamalerts/19927)

> **Global Campaign Discovered with Modbus PLCs Targeted and China-Geolocated Infrastructure Observed** https://ift.tt/wLtakpx  Discuss on Reddit: https://ift.tt/2nI6HKc @blueteamalerts

### 9. @blueteamalerts (telegram)

[Source](https://t.me/blueteamalerts/19929)

> **SharkMCP: A swiss-knife MCP server for analysing PCAP files** https://ift.tt/EsPHQbS  Discuss on Reddit: https://ift.tt/t8QGbZU @blueteamalerts

### 10. @BleepingComputer (telegram)

[Source](https://t.me/BleepingComputer/24549)

> [ ](https://www.bleepingcomputer.com/news/security/alleged-silk-typhoon-hacker-extradited-to-us-for-cyberespionage/)**Alleged Silk Typhoon hacker extradited to US for cyberespionage**  A Chinese national accused of carrying out cyberespionage operations for China's intelligence services has been ext...

---

*Generated by threat-intel-scraper at 2026-04-28T04:58:27.440471Z*