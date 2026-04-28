"""
ThreatFox (abuse.ch) Scraper — community IOC sharing platform.

ThreatFox provides IOCs associated with malware families, botnets,
and threat actors. Searchable by malware family, IOC type, and tags.

Uses two endpoints:
  1. Public JSON export (no auth): https://threatfox.abuse.ch/export/json/recent/
  2. API (requires free auth key): https://threatfox-api.abuse.ch/api/v1/

The scraper prefers the API if a key is provided, falls back to public export.

Config:
  threatfox:
    enabled: true
    api_key: ""              # optional — get free key at https://threatfox.abuse.ch/api/
    days_lookback: 7         # fetch IOCs from the last N days
    malware_families: []     # filter by family (e.g., ["Cobalt Strike", "Emotet"])
    ioc_types: []            # filter by type (e.g., ["ip:port", "domain", "url"])
"""

import json
import re
import logging
from datetime import datetime

from .base import BaseScraper, ScrapedPost

logger = logging.getLogger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"


class ThreatFoxScraper(BaseScraper):
    platform_name = "threatfox"

    def _validate_config(self):
        self.enabled = self.config.get("enabled", True)
        self.api_key = self.config.get("api_key", "")
        self.days_lookback = self.config.get("days_lookback", 7)
        self.malware_families = self.config.get("malware_families", [])
        self.ioc_types = self.config.get("ioc_types", [])
        self.accounts = self.config.get("accounts", ["threatfox.abuse.ch"])

    def _api_request(self, payload: dict) -> dict:
        """Make a POST request to the ThreatFox API (requires auth key)."""
        try:
            import requests
        except ImportError:
            logger.error("requests library required: pip install requests")
            return {}

        if not self.api_key:
            logger.debug("No ThreatFox API key — skipping API request")
            return {}

        headers = {
            "Content-Type": "application/json",
            "Auth-Key": self.api_key,
        }

        try:
            resp = requests.post(API_URL, json=payload, headers=headers, timeout=30)
            if resp.status_code == 401:
                logger.warning("ThreatFox API: unauthorized — check your api_key")
                return {}
            if resp.status_code != 200:
                logger.error(f"ThreatFox API error: {resp.status_code}")
                return {}

            data = resp.json()
            if data.get("query_status") == "ok":
                return data
            elif data.get("query_status") == "no_result":
                logger.info("ThreatFox API: no results for query")
                return {"data": []}
            else:
                logger.error(f"ThreatFox query failed: {data.get('query_status')}")
                return {}

        except Exception as e:
            logger.error(f"ThreatFox API error: {e}")
            return {}

    def _fetch_public_export(self) -> list:
        """Fetch IOCs from the public JSON export (no auth needed)."""
        try:
            import requests
        except ImportError:
            logger.error("requests library required")
            return []

        try:
            resp = requests.get(EXPORT_URL, timeout=30)
            if resp.status_code != 200:
                logger.error(f"ThreatFox export error: {resp.status_code}")
                return []

            raw_data = resp.json()

            # Public export format: {"ioc_id": [entries], ...}
            # Flatten into a list of IOC dicts
            entries = []
            for ioc_id, ioc_list in raw_data.items():
                for ioc_entry in ioc_list:
                    ioc_entry["id"] = ioc_id
                    # Normalize field names to match API format
                    if "ioc_value" in ioc_entry and "ioc" not in ioc_entry:
                        ioc_entry["ioc"] = ioc_entry["ioc_value"]
                    entries.append(ioc_entry)

            logger.info(f"ThreatFox public export: {len(entries)} IOCs fetched")
            return entries

        except Exception as e:
            logger.error(f"ThreatFox export fetch error: {e}")
            return []

    def _ioc_to_post(self, ioc: dict) -> ScrapedPost:
        """Convert a ThreatFox IOC entry to a ScrapedPost."""
        ioc_value = ioc.get("ioc", ioc.get("ioc_value", ""))
        ioc_type = ioc.get("ioc_type", "unknown")
        threat_type = ioc.get("threat_type", "")
        malware = ioc.get("malware_printable", ioc.get("malware", "unknown"))
        malware_alias = ioc.get("malware_alias", "") or ""
        confidence = ioc.get("confidence_level", 0)
        tags = ioc.get("tags", []) or []
        reporter = ioc.get("reporter", "anonymous")
        reference = ioc.get("reference", "") or ""
        first_seen = ioc.get("first_seen_utc", "")
        ioc_id = ioc.get("id", "")

        tag_str = ", ".join(tags) if tags else "none"
        alias_str = f" (aliases: {malware_alias})" if malware_alias else ""

        content = (
            f"ThreatFox IOC [{ioc_type}]: {ioc_value}\n"
            f"Malware: {malware}{alias_str}\n"
            f"Threat type: {threat_type}\n"
            f"Tags: {tag_str}\n"
            f"Confidence: {confidence}%\n"
            f"Reporter: {reporter}\n"
            f"First seen: {first_seen}\n"
        )
        if reference:
            content += f"Reference: {reference}\n"

        url = f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else ""

        return ScrapedPost(
            platform="threatfox",
            author=reporter,
            content=content,
            url=url,
            timestamp=first_seen,
            engagement={"confidence": confidence},
            raw=ioc,
        )

    def scrape(self, limit: int = 50) -> list:
        """Fetch recent IOCs from ThreatFox."""
        if not self.enabled:
            logger.info("ThreatFox scraper disabled in config")
            return []

        posts = []

        # Try API first if we have a key and specific malware families
        if self.api_key and self.malware_families:
            for family in self.malware_families:
                payload = {"query": "malwareinfo", "malware": family, "limit": limit}
                data = self._api_request(payload)
                entries = data.get("data", [])
                for entry in entries[:limit]:
                    posts.append(self._ioc_to_post(entry))
                logger.info(f"ThreatFox API: {len(entries)} IOCs for '{family}'")
            return posts[:limit]

        # Otherwise use public export (no auth needed)
        entries = self._fetch_public_export()

        # Apply filters
        if self.malware_families:
            families_lower = [f.lower() for f in self.malware_families]
            entries = [
                e for e in entries
                if (e.get("malware_printable", "") or e.get("malware", "")).lower() in families_lower
                or any(f in (e.get("malware_alias", "") or "").lower() for f in families_lower)
            ]

        if self.ioc_types:
            entries = [e for e in entries if e.get("ioc_type") in self.ioc_types]

        for entry in entries[:limit]:
            posts.append(self._ioc_to_post(entry))

        logger.info(f"ThreatFox: {len(posts)} IOCs collected")
        return posts

    def search(self, keywords: list, limit: int = 50) -> list:
        """
        Search ThreatFox by malware family, tags, and keyword filtering.

        Strategy:
        1. Try API search by malware name and tag (if API key available)
        2. Fetch public export and filter by keywords
        """
        posts = []
        seen_ids = set()

        # Strategy 1: API search (if key available)
        if self.api_key:
            for keyword in keywords:
                # Search as malware family
                data = self._api_request({"query": "malwareinfo", "malware": keyword, "limit": limit})
                for entry in data.get("data", []):
                    ioc_id = entry.get("id", "")
                    if ioc_id not in seen_ids:
                        seen_ids.add(ioc_id)
                        posts.append(self._ioc_to_post(entry))

                # Search as tag
                data = self._api_request({
                    "query": "taginfo",
                    "tag": keyword.lower().replace(" ", "_"),
                    "limit": limit,
                })
                for entry in data.get("data", []):
                    ioc_id = entry.get("id", "")
                    if ioc_id not in seen_ids:
                        seen_ids.add(ioc_id)
                        posts.append(self._ioc_to_post(entry))

                # Search as IOC value if it looks like one
                if re.match(r'^[\d.:/]+$', keyword) or re.match(r'^[a-f0-9]{32,64}$', keyword, re.I):
                    data = self._api_request({"query": "search_ioc", "search_term": keyword})
                    for entry in data.get("data", []):
                        ioc_id = entry.get("id", "")
                        if ioc_id not in seen_ids:
                            seen_ids.add(ioc_id)
                            posts.append(self._ioc_to_post(entry))

        # Strategy 2: Public export + keyword filtering (always run)
        entries = self._fetch_public_export()
        keywords_lower = [kw.lower() for kw in keywords]

        for entry in entries:
            searchable = " ".join([
                entry.get("ioc", entry.get("ioc_value", "")),
                entry.get("malware_printable", entry.get("malware", "")),
                entry.get("malware_alias", "") or "",
                " ".join(entry.get("tags", []) or []),
                entry.get("threat_type", ""),
                entry.get("reference", "") or "",
                entry.get("reporter", ""),
            ]).lower()

            if any(kw in searchable for kw in keywords_lower):
                ioc_id = entry.get("id", "")
                if ioc_id not in seen_ids:
                    seen_ids.add(ioc_id)
                    posts.append(self._ioc_to_post(entry))

        logger.info(f"ThreatFox search: {len(posts)} results for '{' '.join(keywords)}'")
        return posts[:limit]

    def test_connection(self) -> bool:
        """Test ThreatFox connectivity — tries public export first, then API."""
        try:
            import requests
            # Test public export (always available)
            resp = requests.get(EXPORT_URL, timeout=10)
            if resp.status_code == 200:
                return True
            # Fallback: test API
            if self.api_key:
                resp = requests.post(
                    API_URL,
                    json={"query": "get_iocs", "days": 1},
                    headers={"Content-Type": "application/json", "Auth-Key": self.api_key},
                    timeout=10,
                )
                return resp.status_code == 200
            return False
        except Exception as e:
            logger.error(f"ThreatFox connection test failed: {e}")
            return False
