---
layout: post
title: "Operation Highland: When the Login Itself Is the Backdoor — Inside Velvet Ant's Decade in the PAM and OpenSSH Stack"
date: 2026-06-29
categories: [apt, security]
tags: [velvet-ant, pam, openssh, linux-persistence, china-nexus, credential-theft, file-integrity-monitoring]
author: Prakhar Gupta
description: "A technical deep-dive into Sygnia's Operation Highland disclosure — how the China-nexus actor Velvet Ant backdoored pam_unix.so, ssh, and sshd to live undetected inside a critical-infrastructure network since 2016, and how SOC and IR teams can actually find it."
toc: true
---

> **TL;DR for analysts and <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> teams.** Velvet Ant — a China-nexus espionage actor — spent close to a decade inside a critical-infrastructure network by backdooring the authentication stack itself: `pam_unix.so`, `ssh`, `sshd`, and `scp`. There was **no novel CVE and no dropped second-stage malware** to catch. The attacker modified the *trusted login programs* so they accept a hardcoded password (`Pamauth@123456`), silently harvest every credential typed, and log every command — with a built-in `-d` switch to disable that logging when the operator works. Because the thing that *checks* credentials is working for the attacker, **password resets and killed sessions do nothing**. The only mitigation that matters is integrity verification: compare every authentication binary and PAM module against a known-good, per-distro baseline, and **remove the backdoor before you rotate a single credential**.

---

## Watch the 7-Minute Walkthrough

For IT generalists, platform engineers, and anyone who wants the intuition before the technical depth: a short narrated walkthrough of the attack and what to do about it.

<!-- VIDEO_EMBED:START -->
<!--
  The Security Blog Automator pipeline replaces this block with the rendered
  <iframe> after NotebookLM Cinematic Video Overview generation completes.
  Source script: _video/script-velvet-ant-operation-highland.md
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

On 8 June 2026, Sygnia published the most uncomfortable <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> case study of the year so far. Their incident-response team had been called into a critical-infrastructure organisation and found a China-nexus actor they track as **Velvet Ant** sitting inside the network — with forensic artifacts dating back to **2016**. Almost a full decade of undetected access.

What makes Operation Highland different from the usual "<span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> dwells for years" story is *where* the actor chose to hide. Velvet Ant did not drop a clever implant that an <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> might eventually fingerprint. They did not exploit a flashy <span class="glossary-term" data-bs-toggle="tooltip" title="A computer-software vulnerability that is unknown to, or unaddressed by, those who should be interested in mitigating the vulnerability.">zero-day</span>. They went one layer below everything your monitoring watches and **modified the login system itself** — the Linux Pluggable Authentication Modules (`pam_unix.so`) and the OpenSSH binaries (`ssh`, `sshd`, `scp`) that decide who is allowed in and what they can do.

This is the logical endpoint of a pattern Sygnia has tracked across multiple Velvet Ant engagements. Each time defenders evict them from one foothold, the group escalates to gear nobody is watching and rebuilds persistence from there. In their telling: "Legacy Windows servers gave way to F5 appliances, then Cisco NX-OS, and now the authentication stack itself." Operation Highland is that same idea, one level deeper than anyone had publicly documented.

For a Cloud Security or Detection Engineering team the takeaway is brutal and specific: **your trust in the authentication layer is now an attack surface.** Every detection you have built assumes that `sshd` is `sshd` and that `pam_unix.so` faithfully reports the result of an authentication. Operation Highland breaks that assumption, and it does so without leaving the kind of evidence your tooling is designed to surface. There is no malicious process to alert on. There is no anomalous outbound beacon from a second-stage payload. The malicious code *is* the trusted code.

---

## 2. Background: What the Authentication Stack Is *Supposed* to Do

To understand the abuse, you have to understand what's being subverted. On a modern Linux host, two subsystems decide who gets in:

**PAM (Pluggable Authentication Modules)** is the framework that programs like `login`, `sshd`, `sudo`, and `su` call when they need to authenticate a user. The workhorse module is `pam_unix.so`, which implements traditional Unix password authentication. When `sshd` receives a password, it ultimately hands it to `pam_unix.so`'s `pam_sm_authenticate` function, which hashes it, compares it against `/etc/shadow`, and returns success or failure. Everything that authenticates a local user trusts that return value.

**OpenSSH** provides the `ssh` client, the `sshd` server, and the file-transfer tools (`scp`, `sftp`). These binaries are signed by the distribution, shipped from the package manager, and almost never inspected after install. They are the definition of "trusted by default."

![Diagram](https://kroki.io/mermaid/svg/eNplkU1OwzAQhfc9xSyLUMg-QpGqUqmbClSTdeU4I2KpHhuPQzkBB-CInISxA-Wn2SRP843few7j84Rk8M7qp6jdAuTRU_I0uR7jLE3yETr-kkHHZI0NmhIwjwNoLu_bPtbt8j4gKbUFoV8wXl1sPKx2eeFo-6AdfLy9y9QdJrKvN-wvaDXqwZ_yQo3J1FxkoXKcqm2zcQPZ0HgiNMl6gms5g_nk41DQzAgqzk0xk3ojknjohMs5ocx-E_wfKt1GzSPwFMLR4vDXYt6f0zYSxUkJhLxQxvOg-rZwOpkRaiBflc_zEedCIg6qW683SgmX1ap73B42-_1PI4HzJTRy1cy5tvw_SpKshgFJIi4-AYxTmb0=)

Five properties of this flow matter for the attack:

1. **`pam_unix.so` is a single shared object.** Replace that one file and you control the verdict for every program that authenticates local users on the host.
2. **OpenSSH binaries are long-lived and rarely re-verified.** A `sshd` compiled in 2016 can run for years. Nobody diffs it against the distro package on a Tuesday afternoon.
3. **There is no "second process" in this design.** Authentication happens inside the trusted binary's own address space. A backdoor placed here spawns nothing, beacons nothing, and writes nothing unusual to `auth.log` unless it chooses to.
4. **The estate is heterogeneous.** A real critical-infrastructure network runs many distributions and versions. Each one ships a slightly different `pam_unix.so` and `sshd` — which, as we'll see, the attacker accounted for with a *per-target build pipeline*.
5. **The network had no direct internet connectivity.** Most hosts couldn't pull packages or reach a <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> directly. That shaped both how the attacker reached them and why traditional network detection was blind.

---

## 3. The Attack: How Velvet Ant Reached and Subverted the Login Layer

Operation Highland unfolds in three stages: get a foothold on internet-facing systems, bridge into the segregated critical-infrastructure network through a compromised web stack, and then subvert authentication everywhere to make the access permanent.

![Diagram](https://kroki.io/mermaid/svg/eNplk-FO2zAUhf_zFFdFE0zQNrSDQjUhQctKBSqoCdOkCKEb5zqxmsSR7ZSyB9gD7BH3JHOctqjQH8mV6_PZ594TnslXlqIyEIz3wP5YhlqPiQMag2xBCrjIsuE-5zSgwbE2Si5ouM_OT-iEjpnMpBrun6LHPLarFwVXuBXzs_jsXeydo-dtxN-wf-p5u-KlYEbkazUNeJ_zrfqED9DC1mov6uNZtKtmSpiN9oJHdLHV9tg59thWS_3Yoz0nHvXC1k_KlmTgqjAgS1JopPoeqe7lUiBM_PkMFGX4BodfOonumJSFnWepkq-t5-FwuGmXg038Wdia-O0ZGYbGypakNIFOKcscMRY6qYSmGFBDt9KqqyNRdLGKhYkjt6VUkpHWUGBOEC7SKoqfP590M57chK1pYUgVZNocmSgSuBdFtQJNqj7X0Q6nAdgNr1Itmvs2HXYM_2F054etR1JZU5-CPXxljWqtywx4Lfp8J51HMbTHjuaG7WCzyXT2K2yNZG43587iLBHFaqNfCdKAoEtiggsGT_N7-Pfn7wfK9dXoLmxd1z6LNQCOgLNEvCos4fAHajOaTJtbqarQwCptZA4HVWlt0QHYdqJ6-4idT12_boPgER4f_ABKVJjr-gb1yC3H928dVBRGgkmtTUoUJWisEVvmVJgP0NF8GljDNnOCYdZ2f9i8VcxUiiCV2jjg7AFioYgZ-2U00wJkdTcdro6so109BbeN81hKZQ8tMX-pCrHqaAld0DptnnH9YqVDH71_rFiZVCrxm-KXBb3p3cCsgw7t9mUdUfeuA7RNkltxEdhdckN1VT2YpnCtdGXdgG0n3EptYu8_bili2g==)

### 3.1 Stage 1 — Foothold and Tunnelling on Internet-Facing Hosts

The entry point was a set of internet-facing Linux servers in the IT network. On these, Velvet Ant deployed a modified build of **GS-Netcat** (part of The Hacker's Choice "Global Socket Toolkit"), which establishes an encrypted reverse shell through the **Global Socket Relay Network (GSRN)** — so the operator never needs a fixed inbound IP or open port. Three tradecraft details stand out:

- The binary was renamed **`auditdb`** and placed in **`/usr/sbin/`** to blend with system tooling.
- Its hardcoded <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> used the pattern **`%.gs.thc[.]org`**, where `%` is a single character `a`–`z` (a GSRN relay subdomain).
- It overwrote its own `argv[0]` with **`[khubd]`** so that in `ps` output it masquerades as a kernel thread.

Persistence for the reverse shell was distribution-aware: on `systemd` hosts, a malicious unit file dropped into `/lib/systemd/system/` and **disguised as a Chrome service**; on SysVinit hosts, a malicious line appended to an `/etc/init.d/` startup script.

Alongside it, Velvet Ant ran a **custom SOCKS5 proxy** — a Perl daemon based on the public `ssspl` project — to tunnel <span class="glossary-term" data-bs-toggle="tooltip" title="The techniques that a cyber attacker uses, after gaining initial access, to move deeper into a network in search of sensitive data and other high-value assets.">lateral movement</span>. It forked into the background, varied its listening port per sample, and disguised its process as **`smbd -D`**. Every sample used a unique filename, process name, and port specifically to defeat host-to-host correlation.

### 3.2 Stage 2 — Bridging Into the Air-Gapped Segment via Nginx + FastCGI

The crown-jewel network had **no direct internet connectivity**, so the attacker built an HTTP-to-SSH execution bridge out of the victim's own web stack. They modified an internet-facing **Nginx** configuration to proxy requests for one specific URL to the same URL on a compromised backend server. That backend Nginx forwarded the request to a **FastCGI process (`fcgiwrap`)** listening on a separate port, which executed a custom binary innocuously named **`uptime`**.

`uptime` was the bridge. Based on parameters supplied in the **HTTP POST body**, it opened an **SSH connection into a host inside the segregated network** and ran a script there to retrieve confidential data, returning the output back up through FastCGI and Nginx to the operator. The result: a remote-execution path into the isolated environment driven entirely by ordinary-looking HTTPS requests, with no direct connection to the critical segment ever required.

### 3.3 Stage 3 — Subverting Authentication Everywhere

Once inside, Velvet Ant made the access durable by attacking the one thing that survives credential rotation: the authentication code itself. They did this three independent ways — backdoored PAM, backdoored OpenSSH, and injected SSH keys — so that removing any single layer would not evict them.

![Diagram](https://kroki.io/mermaid/svg/eNptUt1umzAUvs9THJGbVAuB_LZFU7VOq1RpmRoV7WJCUXWwDVgBG9mm6Xa1p-mD9Ul2IGsz1vgCEPr-zueTlXrPCjQO1vcDoMNKtPaLyCBFDpksy2iYZeJcnI-tM3onoiG7mIqpGDNdahMNlxiykPWp1mkj3sjZiq-O5PACw_CVvMD5MgwHHds2aW6wLmBz_S3xPiPbcU0yHGqsHholnyZWw-gSHtFIVM6eeduO157NNPGuGRO1A5qFM81b3v5jaoKrDVbYuOLTdDZfLFfeNooiGu1InSXeLZpHYR0YgSUw8rSgVUdWWvkVOlZIlVMQa_fa8J6GULwfP45ve_HvaqHo3z9pY0prbQEfgJ48At5U9cH2Xbp41ofuxM9S58B0VaE6hZ8TntWkKS2mpYD4Zi1V8wQjo7U762YqJBeAFpIdNlw6vgXfFu-VFonn0waUmEfgGqPg7vs9kHneVqGz7GQLX29-xInX9q2N_CX4AwW2UWeLzlEpwkDdpKVk7SjH_IPDVYDvX8Ga6gkaawKbShVMaPAJ2XbQbrEGhw4P2Nkrlu5dBFTKZVAXwaQuJvT9P-ev_vwkB0b25fczjIG1L1pe0a7Ym8AftZj4MQ==)

**The PAM backdoors.** Sygnia recovered **nine distinct backdoored `pam_unix.so` files**, each linked to a *different build environment* — strong evidence of a structured, per-target compilation pipeline. The malicious logic lives in `pam_sm_authenticate`, and the variants fall into two behaviours:

- **Authentication bypass only.** Accepts a hardcoded backdoor password and skips normal verification. After a successful bypass it immediately overwrites the backdoor password string in memory with NULL bytes — a small but telling anti-forensics touch. Telltale build artifact: an embedded RPATH of `/home/kevin/Desktop/Linux-PAM-{version}/libpam/.libs:/lib64`.
- **Bypass *plus* credential harvesting.** Uses the backdoor password **`Pamauth@123456`** (stored encrypted in the binary). On a *non-matching* user password — i.e., a real login attempt — it records the username and password to a hidden file at **`/usr/sbin/.ssh.log`**, sometimes deduplicating entries. Telltale RPATH: `/c/src/Linux-PAM-{version}/libpam/.libs`.

That `kevin` build-host username and the `/c/src/...` paths are themselves hunting gold: a distribution-packaged `pam_unix.so` has no business carrying a developer's home-directory RPATH.

**The OpenSSH backdoors.** Velvet Ant shipped two generations. The **newer** variant modified `ssh`, `sshd`, `scp`, and `ssh-keygen` (only the first three carry malicious capability):

- **Credential dumping.** `ssh` and `sshd` capture authentication credentials for both outbound and inbound sessions, encrypt them, and append to **`/usr/share/man9/ph/.ph.man`** in the format `[Direction][AuthType][Status]-user@IP:port->password`, where Direction is `O`/`I`, AuthType is `B` (Kerberos), `C` (PAM), `X` (SSH2), and Status is `Y`/`N`.
- **Keylogging.** Every shell command is logged, encrypted, under **`/usr/share/man9/ph/`**. Files written by `sshd` start with `s` + an MD5 of the connected user and TTY; files written by `ssh` start with `c` + an MD5 of the UID and `SSH_TTY`.
- **A logging kill-switch.** A custom **`-d`** flag on `ssh` suppresses the attacker's own credential logging and keylogging, so the operator can work without leaving traces in their own stores.
- **SELinux disabling and process hiding.** Malicious `scp`, when run as root, disables SELinux to lift mandatory-access-control restrictions; a custom **`!`** flag disguises its process name as **`[kauditd] -sh`**, mimicking the kernel audit daemon.
- **Timestomping.** Every file under `/usr/share/man9/ph/` — and the directory itself — is timestomped to the creation time of `/etc/shells/`.

The **older** variant (only `ssh` and `sshd`) is cruder but historically revealing. Its `sshd` compares entered passwords against a hardcoded global MD5 hash *and* maintains **seven day-of-week MD5 hashes**, rotating which one it checks by the current day. It wrote harvested credentials to `/usr/lib/eth-scsi/libethscsi.so` and keylogs to **`/var/lib/sam/`** with filenames `sam_{timestamp}`. Because those filenames encode the connection time, Sygnia could date the earliest keylogging artifact to **2016**. Crucially, the older variant only timestomped the *directories* (to `/bin/ls`'s creation time) and left the inner file timestamps intact — which is exactly the seam that makes filesystem timeline analysis viable.

**The third layer.** Independently of the binaries, Velvet Ant appended their own public keys to `authorized_keys` files for password-less access that survives even a full binary rebuild — unless you also audit the key files.

---

## 4. Why the Usual Defences Don't Stop It

| Defence | Why it fails against Operation Highland |
|---|---|
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> / AV signatures** | There is no dropped malware to sign. The malicious code lives inside trusted, distribution-named binaries (`sshd`, `pam_unix.so`). Many isolated hosts had no <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> at all. |
| **Password resets** | The component that *validates* the new password is backdoored. Reset a credential and the same `pam_unix.so` harvests the new one to `/usr/sbin/.ssh.log` on first use. |
| **Killing sessions / disabling accounts** | The backdoor password (`Pamauth@123456`) and injected SSH keys work regardless of which legitimate accounts are active. |
| **`auth.log` / SIEM auth monitoring** | A successful backdoor-password login looks like a normal success. The keylogger has a `-d` switch to suppress its own evidence. Nothing anomalous is emitted. |
| **Network detection / egress filtering** | Stage-1 <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> rides the GSRN relay; the air-gapped segment is reached over the victim's *own* Nginx via ordinary HTTPS. No second-stage beacon leaves the critical network. |
| **<span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> at the application layer** | Local PAM authentication is below the app. The backdoor short-circuits `pam_sm_authenticate` before any higher-layer factor is consulted on these hosts. |
| **Patching** | There is no exploited CVE in Operation Highland. The fix is *verification of integrity*, not application of a patch. |

The one thing that fundamentally breaks this attack is **integrity verification of the authentication stack against a known-good, per-distribution baseline** — covered in Sections 5 and 6.

---

## 5. Detection: SOC-Side Hunting

Because the malicious behaviour is hidden inside trusted binaries, the highest-fidelity signal is *deviation from known-good state* and the presence of the attacker's host artifacts (hidden stores, anomalous RPATHs, masquerading process names). Microsoft Defender for Endpoint's Linux sensor populates `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceEvents`, so the following advanced-hunting <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> works against MDE-onboarded Linux estates. Tune paths and time windows to your environment.

### 5.1 KQL — Modification of Authentication Binaries and PAM Modules

The single most important detector: any write, rename, or replace touching the OpenSSH binaries or `pam_unix.so` outside a package-manager transaction.

```kusto
// Operation Highland — modification of the authentication stack on Linux
let auth_artifacts = dynamic([
    "pam_unix.so", "sshd", "ssh", "scp", "sftp", "ssh-keygen"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName in~ (auth_artifacts)
       or FolderPath has_any ("/lib/security/", "/usr/lib/security/")
// Exclude legitimate package management
| where not(InitiatingProcessFileName in~ ("dpkg","apt","apt-get","rpm","yum","dnf","zypper","unattended-upgrade"))
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp desc
```

### 5.2 KQL — Hidden Credential and Keylog Stores at Known IOC Paths

The backdoors write to specific, unusual locations. Hunt for them directly — and generalise to hidden files appearing under `man`, `lib`, and `sbin` trees.

```kusto
// Velvet Ant credential/keylog stores and lookalike hidden files
let ioc_paths = dynamic([
    "/usr/sbin/.ssh.log",
    "/usr/share/man9/ph/.ph.man",
    "/usr/lib/eth-scsi/libethscsi.so"
]);
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath in~ (ioc_paths)
       or FolderPath startswith "/usr/share/man9/ph/"
       or FolderPath startswith "/var/lib/sam/"
       // generalised: hidden files in system dirs that shouldn't hold them
       or (FileName startswith "." and FolderPath has_any ("/usr/sbin/","/usr/share/man","/usr/lib/"))
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### 5.3 KQL — Process-Name Masquerade as Kernel Threads

GS-Netcat hides as `[khubd]` and malicious `scp` as `[kauditd] -sh`. Real kernel threads are spawned by the kernel (PID 2 / `kthreadd`) and have no executable on disk. A *userland* process whose name is bracketed like a kernel thread is a strong anomaly.

```kusto
// Userland processes masquerading as kernel threads
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"^\[[a-z]+\]"          // e.g. [khubd], [kauditd]
       or ProcessCommandLine in~ ("smbd -D")                      // SOCKS5 proxy disguise
| where isnotempty(FolderPath)                                    // real kernel threads have no on-disk image
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### 5.4 Offline / On-Box Integrity Checks

On hosts without an <span class="glossary-term" data-bs-toggle="tooltip" title="Endpoint Detection and Response. A class of security tooling that records process, file, network, and identity events on endpoints for hunting, alerting, and response.">EDR</span> sensor (common in segregated networks), verification has to happen on-box. Two practical commands:

```bash
# 1) Compare packaged files against the distro's own manifest.
#    Debian/Ubuntu:
dpkg --verify openssh-server openssh-client libpam-modules 2>/dev/null
#    RHEL/Rocky/SUSE — '5' in column 3 means MD5/content mismatch:
rpm -Va openssh-server openssh-clients pam | grep -E '^..5|^missing'

# 2) Flag PAM modules and SSH binaries carrying a developer RPATH —
#    a distro build never embeds /home/<user>/ or /c/src/ search paths.
for f in /lib/security/pam_unix.so /usr/lib*/security/pam_unix.so \
         /usr/sbin/sshd /usr/bin/ssh /usr/bin/scp; do
  [ -f "$f" ] && readelf -d "$f" 2>/dev/null | grep -E 'RPATH|RUNPATH' \
    | grep -E '/home/|/c/src/|Linux-PAM' && echo "  ^ SUSPECT: $f"
done
```

### 5.5 Hunt Hypotheses (PEAK / TaHiTI)

- **H1 — Auth-binary drift.** *"An OpenSSH binary or `pam_unix.so` differs in hash from the distribution package that owns it, with no corresponding package-manager transaction in the host's history."* Pivot: `dpkg --verify` / `rpm -Va` against package timestamps.
- **H2 — Developer-path RPATH.** *"A production `pam_unix.so` or `sshd` carries an RPATH/RUNPATH referencing a home directory, `/c/src/`, or a `Linux-PAM` build tree."* High-fidelity, near-zero false positives.
- **H3 — Timestamp clusters.** *"Multiple files under a system directory share an identical, implausible mtime matching `/etc/shells` or `/bin/ls` creation time."* Catches both the new and old timestomping behaviour.
- **H4 — HTTP-to-SSH pivot.** *"An internet-facing web/FastCGI process (`nginx`, `fcgiwrap`) spawns or initiates SSH connections into a segregated network segment."* Combines web-tier and identity telemetry.
- **H5 — Bracketed userland.** *"A process with an on-disk executable presents a name in `[brackets]` mimicking a kernel thread, or runs as `smbd -D` from an unexpected path."*

### 5.6 IOCs Observed in Operation Highland

Treat these as illustrative; Sygnia publishes hashes in a separate <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> appendix (linked in Sources).

- **Host artifacts**: `/usr/sbin/auditdb` (GS-Netcat), `/usr/sbin/.ssh.log`, `/usr/share/man9/ph/` (and `/usr/share/man9/ph/.ph.man`), `/usr/lib/eth-scsi/libethscsi.so`, `/var/lib/sam/sam_{timestamp}`; fake "Chrome" systemd unit in `/lib/systemd/system/`.
- **Backdoor password**: `Pamauth@123456` (encrypted in the binary).
- **<span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> pattern**: `%.gs.thc[.]org` (`%` = single char `a`–`z`, GSRN relay).
- **RPATH markers**: `/home/kevin/Desktop/Linux-PAM-{version}/libpam/.libs:/lib64` and `/c/src/Linux-PAM-{version}/libpam/.libs`.
- **Process disguises**: `[khubd]`, `[kauditd] -sh`, `smbd -D`.
- **Credential entry format**: `[O|I][B|C|X][Y|N]-user@IP:port->password`.

---

## 6. Mitigation: What Actually Works

Mitigation here is integrity-first, not patch-first. There is nothing to patch.

### 6.1 Continuous File-Integrity Monitoring of the Auth Stack

Deploy FIM that alerts on *any* change to authentication components, with the auth stack as a top priority. AIDE is the standard open-source option:

```ini
# /etc/aide/aide.conf — watch the authentication stack tightly.
# 'VarFile' rule below uses full content hashing + metadata.
Auth = p+i+n+u+g+s+b+m+c+sha256

/usr/sbin/sshd            Auth
/usr/bin/ssh              Auth
/usr/bin/scp              Auth
/usr/bin/ssh-keygen       Auth
/etc/ssh/sshd_config      Auth
/lib/security/pam_unix.so Auth
/usr/lib/security         Auth
/etc/pam.d               Auth
/etc/sudoers              Auth
```

```bash
# Initialise the baseline on a KNOWN-GOOD host, store the DB offline/immutable,
# then schedule a daily check that emails/forwards diffs to the SIEM.
aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo '0 3 * * * root /usr/bin/aide --check | logger -t aide-check' \
  > /etc/cron.d/aide-check
```

For estates that can't run AIDE on every host, an `osquery` pack querying the package-verification tables and hashing `pam_unix.so`/`sshd` on a schedule gives equivalent fleet-wide visibility into a central log pipeline.

### 6.2 Auditd Rules That Catch Tampering Attempts

`auditd` runs below the OpenSSH/PAM layer and will record write attempts even when the resulting binary suppresses its own logging:

```bash
# /etc/audit/rules.d/auth-integrity.rules
-w /usr/sbin/sshd            -p wa -k auth_binary_tamper
-w /usr/bin/ssh              -p wa -k auth_binary_tamper
-w /usr/bin/scp              -p wa -k auth_binary_tamper
-w /lib/security/pam_unix.so -p wa -k auth_binary_tamper
-w /etc/ssh/sshd_config      -p wa -k auth_config_tamper
# Watch the attacker's known credential-store paths and authorized_keys:
-w /usr/share/man9/           -p wa -k susp_store
-w /root/.ssh/authorized_keys -p wa -k authkey_change
```

### 6.3 Privileged-Access Hardening

Reduce the blast radius even if a single host is subverted: disable direct root SSH login (`PermitRootLogin no`), enforce named accounts with scoped `sudo`, route administrative access through hardened jump servers or a PAM/PIM solution, vault privileged credentials, and require <span class="glossary-term" data-bs-toggle="tooltip" title="Multi-Factor Authentication. Authentication that requires two or more independent factors (knowledge, possession, inherence) such as password plus phone-based prompt or hardware token.">MFA</span> *before* an operator can reach a critical host (since the host-local factor cannot be trusted once `pam_unix.so` is in question).

### 6.4 Egress and Bridge Awareness

Treat any internet-facing web tier as a potential pivot. Alert when `nginx`/`fcgiwrap` or other web-server processes initiate SSH connections, especially into a segregated segment. Add the GSRN relay pattern (`*.gs.thc.org`) and unexpected outbound from edge Linux hosts to your watch list.

---

## 7. Operational Playbook for SOC and IR

The single most important <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> principle in Operation Highland inverts normal instinct: **remove the backdoor before you rotate any credential.** If you reset passwords while the malicious `pam_unix.so` is still in place, those new passwords are harvested to `/usr/sbin/.ssh.log` the first time anyone uses them.

![Diagram](https://kroki.io/mermaid/svg/eNplU81u2zAMvvcpeOywZtkPNmDpqW2KpViaFHE3YKeCkRhbsCwZIhM3GwbsIfaEe5JRXvNTTAfbkKXvj6S4hrwLdAK6xIknmLeUUFwMMHFl5TFY-PPrN9wsYEzGcf5xf3yLyfSnxyT61W_ldbGWasCCpgab3EpgFdcKNYKLm_H1ENfWiYWVx5KhxeZhHdzjK44QEzBXFkyFoaQ92lUMK5caYBNbUpAJcgXoPaDSwNIFTI5Y8Yhk0DlLsGGoQ-zCoIzRgnoC61hSfKZZYQVdgFMbYTa_h0RMAiaRZdiSvNjz33D0KHQGbT6SNllDEbDlKkoGrocNNTFtz0GRQt4jr3kAJnErNKLSXOJDOrfY9vLfgcctJVa4S43KxqjcBz8ve38xue9kH2ra5p1PxWBGYlCyKVZPFMzzSlwntE4PHOKb4nIgxKIGW4-GGgqSOW9RTAUmpqRXtQ6mxpKOwhpuMkUMe6CiU-FH8pK61jB6aSNY_EM_LuhZLmf_sPo07Tm066QcKLk1lChfPd_h8FbtNHbogvvfXl5f0TuLOdhc94rQ62u0b4-imAx9LLWiXUy14tZELahdpQxmC2gMMSsb2u2zyBZklD_B6Xw2_aYF7A6lX0TJhBfTad8YmpxDn93eIbPSWD7LvL0RtajN4TQCZdJ-Fz7A0GCJ3I9Nn9Sg95iHAcaXoBKMJwykKW2ePFqoIj8h7HTexaMmmigBSKV5u4223Ahm6vxxuDKl65LWyeRUShW1bkUnFpbJ2VJ7uJhffS7eg0UNPRwU7qYaJMLb128-KOAX1ppoMX_k-zrMTfsThtBg-HjU2Xp82c-27cj7k78yXnAC)

Concretely, the first-hour and follow-on actions:

1. **Preserve before you clean.** Image the disk and capture memory. The backdoored binaries, hidden stores, and RPATH artifacts are your strongest evidence — deleting them first destroys the timeline.
2. **Enumerate all three persistence layers** on every affected host: the modified `pam_unix.so`/`ssh`/`sshd`/`scp`, any injected `authorized_keys`, and the GS-Netcat/SOCKS5 footholds plus their systemd/init persistence.
3. **Engineer the replacement carefully.** Because the estate spans distributions, match each host to the correct known-good package and *lab-test* the swap — a wrong replacement can lock admins out of a live, zero-downtime production system. Prepare rollback and emergency access first.
4. **Eradicate, then — and only then — rotate credentials** across passwords, SSH keys, and service accounts.
5. **Hunt the bridge.** Review Nginx configurations for the proxy-to-backend rule, find the `fcgiwrap`/`uptime` execution path, and locate every SOCKS5 daemon.
6. **Bound the dwell time.** Use the `sam_{timestamp}` and `man9` artifacts to reconstruct how far back the access goes — in this case, to 2016.

---

## 8. The Wider Picture: Trust Below the Telemetry Line

Operation Highland is not an isolated trick; it is the maturation of a strategy. Velvet Ant has repeatedly demonstrated that when defenders harden and monitor the obvious layers, a patient state-aligned actor simply moves *beneath* them — to load balancers, to network OS, and now to the authentication stack. Each of these shares one property: it is trusted by default and rarely verified.

The lesson generalises well beyond Linux. The Windows analogue is the LSA authentication-package abuse pattern (Skeleton Key and its descendants), where the attacker tampers with `lsass`-loaded modules to mint a master password. The cloud analogue is the first-party trust abuse we covered earlier in this series — borrowing identities the platform pre-trusts. In every case the attacker is exploiting the same blind spot: **infrastructure that sits below your monitoring still needs integrity verification, and "below your monitoring" now explicitly includes the code that decides who is allowed to log in.**

The strategic question for a cloud-security and SecOps programme in 2026 is therefore concrete: *Do you have a known-good, per-distribution baseline for every authentication binary in your estate, and do you verify against it continuously — including on the isolated hosts where you assumed nothing could reach?* If the answer is no, Operation Highland is the case study that should change it. Stand up FIM and auditd coverage of `pam_unix.so` and the OpenSSH suite this quarter, build the per-distro golden baselines you'll need for eradication, and rehearse the inverted <span class="glossary-term" data-bs-toggle="tooltip" title="Incident Response. The structured set of activities an organization undertakes to identify, contain, eradicate, and recover from a security incident.">IR</span> order — clean first, rotate second — before you ever need it.

---

## Glossary

These terms are auto-tooltipped by the publishing pipeline; definitions are repeated here for the static reader.

- **PAM (Pluggable Authentication Modules)** — A Linux framework that lets programs like `sshd`, `login`, and `sudo` delegate authentication to loadable modules. `pam_unix.so` implements traditional password auth.
- **`pam_unix.so`** — The shared object that hashes a supplied password and compares it to `/etc/shadow`. Replacing it controls the authentication verdict for every program on the host.
- **OpenSSH** — The standard implementation of the SSH protocol on Linux, providing `ssh` (client), `sshd` (server), and `scp`/`sftp` (file transfer).
- **`authorized_keys`** — A per-account file listing the public keys permitted to log in without a password. Injecting a key grants durable access independent of passwords.
- **RPATH / RUNPATH** — A library search path embedded in an ELF binary at link time. A production system binary carrying a developer's home-directory RPATH is a strong indicator of attacker compilation.
- **GS-Netcat (Global Socket Toolkit)** — A legitimate connectivity tool by The Hacker's Choice that tunnels shells through the Global Socket Relay Network (GSRN), abused here for <span class="glossary-term" data-bs-toggle="tooltip" title="Command and Control, a server that is used by an attacker to maintain communications with compromised systems within a target network.">C2</span> without fixed infrastructure.
- **SOCKS5 proxy** — A protocol for tunnelling arbitrary TCP traffic through an intermediary host; used here for stealthy <span class="glossary-term" data-bs-toggle="tooltip" title="The techniques that a cyber attacker uses, after gaining initial access, to move deeper into a network in search of sensitive data and other high-value assets.">lateral movement</span>.
- **FastCGI / `fcgiwrap`** — A mechanism for a web server (Nginx) to execute external programs per request; weaponised here as an HTTP-to-SSH execution bridge into an air-gapped segment.
- **Timestomping** — Altering a file's timestamps to evade timeline analysis; Velvet Ant set artifact timestamps to match `/etc/shells` or `/bin/ls`.
- **File Integrity Monitoring (FIM)** — Continuous comparison of files against a known-good baseline (e.g., AIDE), the primary defence against trusted-binary tampering.
- **auditd** — The Linux Audit daemon, which records security-relevant events (including file writes) below the application layer, so it can catch tampering even when the tampered binary suppresses its own logs.
- **SELinux** — A Linux mandatory-access-control system; malicious `scp` disabled it (as root) to lift restrictions on file movement.

---

## Sources & Further Reading

### Primary Research

- [Velvet Ant's Operation Highland: How a China-Nexus Actor Infiltrated an Internal Network Undetected — Sygnia](https://www.sygnia.co/blog/operation-highland-velvet-ant/) — The primary incident-response writeup with the full technical narrative, PAM/OpenSSH behaviours, and remediation guidance.
- [Operation Highland — Indicators of Compromise (PDF) — Sygnia](https://bunny-wp-pullzone-5pkz60xvv9.b-cdn.net/wp-content/uploads/2026/06/Indicators-of-Compromise.pdf) — The hash-level <span class="glossary-term" data-bs-toggle="tooltip" title="Indicator of Compromise, an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion.">IOC</span> appendix accompanying the report.

### Industry Press and Corroboration

- [China-Linked Hackers Backdoored Linux Login Software to Hide for Nearly a Decade — The Hacker News](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html) — Concise summary with the three defender actions (watch the login files; hunt by comparing to known-good; remove the backdoor before resetting passwords).
- [China-nexus group hid in Linux login system for nearly a decade — SC Media](https://www.scworld.com/brief/china-nexus-group-hid-in-linux-login-system-for-nearly-a-decade) — Independent press coverage of the disclosure.
- [Sygnia uncovers Velvet Ant breach dating back to 2016 — SecurityBrief](https://securitybrief.com.au/story/sygnia-uncovers-velvet-ant-breach-dating-back-to-2016) — Timeline-focused summary.
- [Modified OpenSSH Binaries Let Velvet Ant Steal Passwords, Log Commands, and Hide Activity — GBHackers](https://gbhackers.com/modified-openssh-binaries/) — Detail on the OpenSSH modifications and the `-d` logging kill-switch.
- [Hackers Backdoor pam_unix.so and OpenSSH Binaries to Bypass Authentication and Steal Credentials — Cyberpress](https://cyberpress.org/backdoored-linux-binaries-steal-credentials/) — Coverage of the PAM backdoor variants and credential stores.

### Background: Velvet Ant's Earlier Campaigns

- [China-Nexus Threat Group "Velvet Ant" — Sygnia (2024)](https://www.sygnia.co/blog/china-nexus-threat-group-velvet-ant/) — The earlier case turning internet-exposed F5 BIG-IP appliances into internal command servers.
- [Chinese Hackers Exploiting Cisco NX-OS Zero-Day (CVE-2024-20399) — The Hacker News](https://thehackernews.com/2024/07/chinese-hackers-exploiting-cisco.html) — Velvet Ant's switch-firmware persistence via VELVETSHELL.
- [CVE-2024-20399 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-20399) — The Cisco NX-OS command-injection flaw used in the prior campaign.

### Detection and Hardening References

- [Microsoft Defender for Endpoint on Linux — Advanced Hunting Schema (DeviceFileEvents / DeviceProcessEvents) — Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) — Reference for the <span class="glossary-term" data-bs-toggle="tooltip" title="Kusto Query Language. The query language used by Microsoft Sentinel, Azure Log Analytics, and Defender for hunting and detection across telemetry.">KQL</span> tables used above.
- [AIDE — Advanced Intrusion Detection Environment](https://aide.github.io/) — The open-source file-integrity tool used in the mitigation section.
- [Linux Audit (auditd) Documentation](https://github.com/linux-audit/audit-documentation/wiki) — Reference for the auditd watch rules.

---

*Next week (rotation: Cloud → Supply-Chain → <span class="glossary-term" data-bs-toggle="tooltip" title="Advanced Persistent Threat, a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period.">APT</span> → Threat-Intel): a threat-intel deep-dive — we'll dissect the most consequential newly published advisory or CISA KEV addition of the week, turning a fresh vendor research drop into ready-to-deploy detections and a defender action plan.*
