"""
IOC Extractor — regex-based indicator extraction from raw text.

Extracts: IPv4, IPv6, domains, URLs, email addresses,
MD5, SHA1, SHA256 hashes, CVE IDs, and Bitcoin/Ethereum addresses.

Supports both fanged and defanged indicators.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IOC:
    """Single extracted indicator of compromise."""
    type: str          # ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve, btc, eth
    value: str         # raw extracted value
    defanged: str      # defanged representation
    context: str = ""  # surrounding text snippet
    source: str = ""   # platform / post URL
    timestamp: str = ""


@dataclass
class ExtractionResult:
    """Collection of extracted IOCs from a single text."""
    iocs: list = field(default_factory=list)
    source: str = ""
    raw_text: str = ""

    @property
    def summary(self) -> dict:
        counts = {}
        for ioc in self.iocs:
            counts[ioc.type] = counts.get(ioc.type, 0) + 1
        return counts

    def deduplicate(self):
        seen = set()
        unique = []
        for ioc in self.iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        self.iocs = unique
        return self


# --- Refang / Defang utilities ---

REFANG_MAP = {
    "hxxp": "http",
    "hxxps": "https",
    "[.]": ".",
    "(.)": ".",
    "[:]": ":",
    "[at]": "@",
    "(at)": "@",
    "[dot]": ".",
    "(dot)": ".",
    "[@]": "@",
}

DEFANG_MAP = {
    "http": "hxxp",
    "https": "hxxps",
}


def refang(text: str) -> str:
    """Convert defanged indicators back to live form for matching."""
    result = text
    for defanged, fanged in REFANG_MAP.items():
        result = result.replace(defanged, fanged)
    return result


def defang_value(value: str) -> str:
    """Defang an indicator for safe display."""
    result = value
    for fanged, defanged in DEFANG_MAP.items():
        result = result.replace(fanged, defanged)
    # Defang dots in IPs and domains (not in URLs already handled)
    if not result.startswith("hxxp"):
        result = result.replace(".", "[.]")
    else:
        # For URLs, defang the protocol and the dots in the domain part
        proto_end = result.find("://")
        if proto_end > 0:
            rest = result[proto_end + 3:]
            path_start = rest.find("/")
            if path_start > 0:
                domain = rest[:path_start].replace(".", "[.]")
                result = result[:proto_end + 3] + domain + rest[path_start:]
            else:
                result = result[:proto_end + 3] + rest.replace(".", "[.]")
    return result


# --- Regex patterns ---

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.|\[\.\]|\(\.\))){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
        r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.|\[\.\]|\(\.\)))+(?:com|net|org|io|info|biz|xyz|top|"
        r"ru|cn|de|uk|fr|br|in|au|cc|me|co|tv|tk|ml|ga|cf|gq|"
        r"onion|bit|dev|app|cloud|security|cyber)\b",
        re.IGNORECASE
    ),
    "url": re.compile(
        r"(?:hxxps?|https?):\/\/[^\s\"'<>\]\)]{4,}",
        re.IGNORECASE
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+(?:@|\[at\]|\(at\)|\[@\])"
        r"[a-zA-Z0-9.\-]+(?:\.|\[\.\]|\(\.\))[a-zA-Z]{2,}\b",
        re.IGNORECASE
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    "btc": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "eth": re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
}

# Words that look like hashes but aren't
HASH_EXCLUSIONS = {
    "md5": {"d41d8cd98f00b204e9800998ecf8427e"},   # empty string md5
    "sha1": {"da39a3ee5e6b4b0d3255bfef95601890afd80709"},  # empty string sha1
    "sha256": {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
}

# Threshold: skip hex strings that are just common words
MIN_HEX_ENTROPY = 2.5


def _context_window(text: str, start: int, end: int, window: int = 80) -> str:
    """Extract surrounding context around a match."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    return text[ctx_start:ctx_end].replace("\n", " ").strip()


def _hex_entropy(s: str) -> float:
    """Shannon entropy of a hex string — filters out low-entropy false positives."""
    from math import log2
    if not s:
        return 0.0
    freq = {}
    for c in s.lower():
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * log2(p)
    return entropy


def extract_iocs(
    text: str,
    source: str = "",
    timestamp: str = "",
    types: Optional[list] = None,
    refang_input: bool = True,
) -> ExtractionResult:
    """
    Extract IOCs from text.

    Args:
        text: Raw text to scan.
        source: Attribution string (URL, platform name).
        timestamp: When the source was collected.
        types: List of IOC types to extract (None = all).
        refang_input: Whether to refang defanged indicators before matching.

    Returns:
        ExtractionResult with deduplicated IOCs.
    """
    result = ExtractionResult(source=source, raw_text=text)

    # Work on refanged copy for matching, but keep original for context
    match_text = refang(text) if refang_input else text

    active_types = types or list(PATTERNS.keys())

    for ioc_type in active_types:
        if ioc_type not in PATTERNS:
            continue

        pattern = PATTERNS[ioc_type]
        for match in pattern.finditer(match_text):
            value = match.group(0).strip().rstrip(".,;:!?)")

            # Filter low-quality hash matches
            if ioc_type in ("md5", "sha1", "sha256"):
                if value.lower() in HASH_EXCLUSIONS.get(ioc_type, set()):
                    continue
                if _hex_entropy(value) < MIN_HEX_ENTROPY:
                    continue

            # Skip domains that are just common words
            if ioc_type == "domain":
                if len(value.split(".")[0]) < 3:
                    continue

            ioc = IOC(
                type=ioc_type,
                value=value,
                defanged=defang_value(value),
                context=_context_window(match_text, match.start(), match.end()),
                source=source,
                timestamp=timestamp,
            )
            result.iocs.append(ioc)

    # URLs contain domains — deduplicate by removing domains found inside URLs
    url_values = {ioc.value for ioc in result.iocs if ioc.type == "url"}
    if url_values:
        result.iocs = [
            ioc for ioc in result.iocs
            if ioc.type != "domain" or not any(ioc.value in url for url in url_values)
        ]

    return result.deduplicate()


# --- Quick CLI test ---
if __name__ == "__main__":
    sample = """
    Observed C2 at 192.168.1[.]100 and hxxps://evil-domain[.]com/payload.exe
    SHA256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    Also seen: CVE-2024-21412 exploited via phishing from bad-actor[@]malware[.]ru
    Secondary C2: 10.0.0.50 port 443
    MD5: 5d41402abc4b2a76b9719d911017c592
    """
    result = extract_iocs(sample, source="test", timestamp="2026-04-28")
    for ioc in result.iocs:
        print(f"[{ioc.type:>8}] {ioc.defanged}")
    print(f"\nSummary: {result.summary}")
