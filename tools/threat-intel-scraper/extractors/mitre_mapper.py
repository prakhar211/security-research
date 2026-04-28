"""
MITRE ATT&CK Mapper — keyword-based technique identification from text.

Uses a curated lookup table of technique IDs, names, and trigger keywords
to tag threat intel with ATT&CK references. Covers Enterprise ATT&CK v15.

This is a heuristic mapper — for high-confidence mapping, pair with
MITRE ATT&CK STIX data or the ATT&CK Navigator API.
"""

import re
from dataclasses import dataclass, field


@dataclass
class MitreMatch:
    """A matched ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str  # high, medium, low
    matched_keywords: list = field(default_factory=list)


# Curated keyword → technique mapping.
# Each entry: (technique_id, technique_name, tactic, keywords[], confidence_if_single)
# Keywords are matched case-insensitively. Multi-word keywords require all words present.
TECHNIQUE_MAP = [
    # Initial Access
    ("T1566", "Phishing", "initial-access",
     ["phishing", "spear-phishing", "spearphishing", "phish kit", "lure", "credential harvesting email"],
     "high"),
    ("T1566.001", "Spearphishing Attachment", "initial-access",
     ["malicious attachment", "weaponized document", "macro-enabled", "maldoc"],
     "high"),
    ("T1566.002", "Spearphishing Link", "initial-access",
     ["phishing link", "credential phishing url", "aitm phishing", "evilginx", "adversary-in-the-middle phishing"],
     "high"),
    ("T1190", "Exploit Public-Facing Application", "initial-access",
     ["exploit public-facing", "rce vulnerability", "remote code execution", "web shell upload"],
     "high"),
    ("T1195", "Supply Chain Compromise", "initial-access",
     ["supply chain", "supply-chain", "dependency confusion", "typosquatting", "poisoned package"],
     "high"),
    ("T1195.001", "Compromise Software Dependencies", "initial-access",
     ["malicious package", "npm malware", "pypi malware", "poisoned dependency"],
     "high"),
    ("T1078", "Valid Accounts", "initial-access",
     ["stolen credentials", "credential stuffing", "valid accounts", "compromised credentials", "credential spray"],
     "medium"),
    ("T1199", "Trusted Relationship", "initial-access",
     ["trusted relationship", "msp compromise", "partner compromise", "third-party access"],
     "medium"),

    # Execution
    ("T1059", "Command and Scripting Interpreter", "execution",
     ["powershell", "cmd.exe", "bash script", "python script", "vbscript", "wscript", "cscript"],
     "medium"),
    ("T1059.001", "PowerShell", "execution",
     ["powershell -enc", "invoke-expression", "iex(", "powershell download cradle", "powershell bypass"],
     "high"),
    ("T1204", "User Execution", "execution",
     ["user clicked", "opened attachment", "enabled macros", "social engineering execution"],
     "medium"),
    ("T1053", "Scheduled Task/Job", "execution",
     ["scheduled task", "cron job", "at job", "schtasks"],
     "medium"),

    # Persistence
    ("T1098", "Account Manipulation", "persistence",
     ["added admin", "role assignment", "account manipulation", "mfa method added", "oauth consent grant"],
     "high"),
    ("T1136", "Create Account", "persistence",
     ["created account", "new admin account", "rogue account", "service account creation"],
     "medium"),
    ("T1547", "Boot or Logon Autostart Execution", "persistence",
     ["registry run key", "startup folder", "autostart", "logon script"],
     "medium"),
    ("T1546", "Event Triggered Execution", "persistence",
     ["wmi event subscription", "office application startup", "trap command"],
     "medium"),

    # Privilege Escalation
    ("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation",
     ["uac bypass", "sudo abuse", "elevation of privilege", "privilege escalation exploit"],
     "high"),
    ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
     ["local privilege escalation", "lpe", "kernel exploit", "privesc"],
     "high"),

    # Defense Evasion
    ("T1562", "Impair Defenses", "defense-evasion",
     ["disable antivirus", "tamper protection", "disable logging", "etw patching", "amsi bypass"],
     "high"),
    ("T1070", "Indicator Removal", "defense-evasion",
     ["clear event logs", "log deletion", "timestomp", "indicator removal", "clear history"],
     "medium"),
    ("T1027", "Obfuscated Files or Information", "defense-evasion",
     ["obfuscated", "encoded payload", "base64 encoded", "packed binary", "string encryption"],
     "medium"),
    ("T1036", "Masquerading", "defense-evasion",
     ["masquerading", "renamed binary", "lolbin", "living off the land"],
     "medium"),

    # Credential Access
    ("T1557", "Adversary-in-the-Middle", "credential-access",
     ["adversary-in-the-middle", "aitm", "man-in-the-middle", "mitm", "token theft proxy", "evilginx", "modlishka"],
     "high"),
    ("T1110", "Brute Force", "credential-access",
     ["brute force", "password spray", "credential stuffing", "password brute"],
     "high"),
    ("T1003", "OS Credential Dumping", "credential-access",
     ["credential dumping", "mimikatz", "lsass", "sam dump", "ntds.dit", "dcsync", "hashdump"],
     "high"),
    ("T1528", "Steal Application Access Token", "credential-access",
     ["token theft", "oauth token", "access token stolen", "jwt theft", "session hijack", "cookie theft"],
     "high"),
    ("T1621", "Multi-Factor Authentication Request Generation", "credential-access",
     ["mfa fatigue", "mfa bombing", "push notification spam", "mfa prompt bombing"],
     "high"),

    # Discovery
    ("T1087", "Account Discovery", "discovery",
     ["account enumeration", "user enumeration", "whoami", "net user", "get-aduser"],
     "low"),
    ("T1082", "System Information Discovery", "discovery",
     ["system enumeration", "systeminfo", "hostname", "os discovery"],
     "low"),

    # Lateral Movement
    ("T1021", "Remote Services", "lateral-movement",
     ["rdp lateral", "ssh lateral", "psexec", "wmi lateral", "winrm", "smb lateral"],
     "medium"),
    ("T1534", "Internal Spearphishing", "lateral-movement",
     ["internal phishing", "bec from compromised", "lateral phishing", "internal spearphishing"],
     "high"),

    # Collection
    ("T1114", "Email Collection", "collection",
     ["mailbox rule", "inbox rule", "email forwarding", "mail exfiltration", "email collection"],
     "high"),
    ("T1530", "Data from Cloud Storage", "collection",
     ["s3 bucket", "azure blob", "gcs bucket", "cloud storage access", "storage exfil"],
     "medium"),

    # Exfiltration
    ("T1567", "Exfiltration Over Web Service", "exfiltration",
     ["exfil over https", "data exfiltration", "exfil to cloud", "pastebin exfil", "telegram exfil"],
     "medium"),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration",
     ["dns exfiltration", "dns tunneling", "icmp exfil", "exfil over dns"],
     "high"),

    # Impact
    ("T1486", "Data Encrypted for Impact", "impact",
     ["ransomware", "encryption for impact", "files encrypted", "ransom note", "data encrypted"],
     "high"),
    ("T1489", "Service Stop", "impact",
     ["service stop", "killed process", "stopped antivirus", "disabled service"],
     "medium"),
    ("T1531", "Account Access Removal", "impact",
     ["password changed by attacker", "locked out", "account access removal"],
     "medium"),

    # Cloud-specific
    ("T1078.004", "Valid Accounts: Cloud Accounts", "initial-access",
     ["cloud account compromise", "entra id compromise", "azure ad compromise", "aws iam compromise", "gcp iam"],
     "high"),
    ("T1538", "Cloud Service Dashboard", "discovery",
     ["cloud console access", "azure portal", "aws console", "gcp console"],
     "low"),
    ("T1580", "Cloud Infrastructure Discovery", "discovery",
     ["cloud enumeration", "ec2 enumeration", "azure resource discovery", "cloud recon"],
     "medium"),
]


def map_techniques(text: str, min_confidence: str = "low") -> list:
    """
    Map text to MITRE ATT&CK techniques using keyword matching.

    Args:
        text: Raw text to analyze.
        min_confidence: Minimum confidence threshold (low, medium, high).

    Returns:
        List of MitreMatch objects, sorted by confidence (high first).
    """
    confidence_order = {"high": 3, "medium": 2, "low": 1}
    min_conf_val = confidence_order.get(min_confidence, 1)
    text_lower = text.lower()
    matches = []
    seen_ids = set()

    for tech_id, tech_name, tactic, keywords, base_confidence in TECHNIQUE_MAP:
        matched_kw = []
        for kw in keywords:
            # Multi-word: all words must be present (within reasonable proximity)
            words = kw.lower().split()
            if len(words) > 1:
                if all(w in text_lower for w in words):
                    matched_kw.append(kw)
            else:
                if re.search(r'\b' + re.escape(kw.lower()) + r'\b', text_lower):
                    matched_kw.append(kw)

        if not matched_kw:
            continue

        # Boost confidence if multiple keywords match
        if len(matched_kw) >= 3:
            confidence = "high"
        elif len(matched_kw) >= 2 and base_confidence != "low":
            confidence = "high"
        else:
            confidence = base_confidence

        conf_val = confidence_order.get(confidence, 1)
        if conf_val < min_conf_val:
            continue

        if tech_id not in seen_ids:
            seen_ids.add(tech_id)
            matches.append(MitreMatch(
                technique_id=tech_id,
                technique_name=tech_name,
                tactic=tactic,
                confidence=confidence,
                matched_keywords=matched_kw,
            ))

    # Sort: high confidence first, then by technique ID
    matches.sort(key=lambda m: (-confidence_order.get(m.confidence, 0), m.technique_id))
    return matches


def format_mitre_badges(matches: list) -> str:
    """Format matches as YAML front matter for blog posts."""
    if not matches:
        return "mitre_techniques: []\n"

    lines = ["mitre_techniques:"]
    for m in matches:
        lines.append(f"  - id: {m.technique_id}")
        lines.append(f"    name: {m.technique_name}")
    return "\n".join(lines) + "\n"


def format_mitre_table(matches: list) -> str:
    """Format matches as a markdown table."""
    if not matches:
        return "No MITRE ATT&CK techniques identified.\n"

    lines = [
        "| Technique | Name | Tactic | Confidence | Keywords |",
        "|-----------|------|--------|------------|----------|",
    ]
    for m in matches:
        kw = ", ".join(m.matched_keywords[:3])
        link = f"[{m.technique_id}](https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')})"
        lines.append(f"| {link} | {m.technique_name} | {m.tactic} | {m.confidence} | {kw} |")
    return "\n".join(lines) + "\n"


# --- Quick CLI test ---
if __name__ == "__main__":
    sample = """
    We observed an AiTM phishing campaign using Evilginx to proxy Microsoft login pages.
    After token theft, the attacker created inbox rules to forward emails and added a new
    MFA method for persistence. PowerShell was used to enumerate Azure AD. The attacker
    performed credential stuffing against multiple cloud accounts. Data was exfiltrated
    over HTTPS to an attacker-controlled S3 bucket.
    """
    matches = map_techniques(sample)
    print(format_mitre_table(matches))
