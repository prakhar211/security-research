"""
TweetFeed.live Scraper — pre-extracted IOCs from Twitter/X infosec community.

TweetFeed collects IOCs (URLs, domains, IPs, MD5, SHA256) shared by the
infosec community on Twitter/X, updated every 15 minutes. No auth required.

API: https://api.tweetfeed.live/v1/{time}/{tag}/{type}

Time periods: today, week, month, year
Tags: phishing, CobaltStrike, Emotet, AgentTesla, Trickbot, etc. (or omit for all)
Types: ip, url, domain, md5, sha256 (or omit for all)

Config:
  tweetfeed:
    enabled: true
    time_period: "month"     # today, week, month, year
    tags: []                 # filter by tag (empty = all)
    types: []                # filter by IOC type (empty = all)
"""

import logging
from datetime import datetime

from .base import BaseScraper, ScrapedPost

logger = logging.getLogger(__name__)

BASE_URL = "https://api.tweetfeed.live/v1"


class TweetFeedScraper(BaseScraper):
    platform_name = "tweetfeed"

    def _validate_config(self):
        self.enabled = self.config.get("enabled", True)
        self.time_period = self.config.get("time_period", "month")
        self.tags = self.config.get("tags", [])
        self.types = self.config.get("types", [])
        # accounts not used for TweetFeed but required by BaseScraper
        self.accounts = self.config.get("accounts", ["tweetfeed.live"])

    def _build_api_url(self, tag: str = None, ioc_type: str = None) -> str:
        """Build TweetFeed API URL from parameters."""
        parts = [BASE_URL, self.time_period]
        if tag:
            parts.append(tag)
        if ioc_type:
            parts.append(ioc_type)
        return "/".join(parts)

    def _fetch_feed(self, url: str) -> list:
        """Fetch IOCs from a TweetFeed API endpoint."""
        try:
            import requests
        except ImportError:
            logger.error("requests library required: pip install requests")
            return []

        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                logger.error(f"TweetFeed API error: {resp.status_code} for {url}")
                return []

            data = resp.json()
            if not isinstance(data, list):
                logger.error(f"Unexpected TweetFeed response format: {type(data)}")
                return []

            return data

        except Exception as e:
            logger.error(f"TweetFeed fetch error: {e}")
            return []

    def scrape(self, limit: int = 50) -> list:
        """Fetch IOCs from TweetFeed.live API and convert to ScrapedPost objects."""
        if not self.enabled:
            logger.info("TweetFeed scraper disabled in config")
            return []

        all_entries = []

        if self.tags:
            # Fetch per-tag feeds
            for tag in self.tags:
                if self.types:
                    for ioc_type in self.types:
                        url = self._build_api_url(tag=tag, ioc_type=ioc_type)
                        entries = self._fetch_feed(url)
                        all_entries.extend(entries)
                        logger.info(f"TweetFeed: {len(entries)} IOCs for tag={tag} type={ioc_type}")
                else:
                    url = self._build_api_url(tag=tag)
                    entries = self._fetch_feed(url)
                    all_entries.extend(entries)
                    logger.info(f"TweetFeed: {len(entries)} IOCs for tag={tag}")
        else:
            # Fetch all IOCs
            if self.types:
                for ioc_type in self.types:
                    url = self._build_api_url(ioc_type=ioc_type)
                    entries = self._fetch_feed(url)
                    all_entries.extend(entries)
                    logger.info(f"TweetFeed: {len(entries)} IOCs for type={ioc_type}")
            else:
                url = self._build_api_url()
                all_entries = self._fetch_feed(url)
                logger.info(f"TweetFeed: {len(all_entries)} total IOCs for {self.time_period}")

        # Convert to ScrapedPost objects
        posts = []
        for entry in all_entries[:limit]:
            # TweetFeed JSON format:
            # {"date": "...", "user": "...", "type": "...", "value": "...",
            #  "tags": [...], "tweet": "https://twitter.com/..."}
            ioc_value = entry.get("value", "")
            ioc_type = entry.get("type", "unknown")
            user = entry.get("user", "unknown")
            tags = entry.get("tags", [])
            tweet_url = entry.get("tweet", "")
            date_str = entry.get("date", "")

            # Build a meaningful content string from the IOC data
            tag_str = ", ".join(tags) if tags else "untagged"
            content = (
                f"IOC [{ioc_type}]: {ioc_value}\n"
                f"Tags: {tag_str}\n"
                f"Shared by: @{user}\n"
                f"Source tweet: {tweet_url}"
            )

            posts.append(ScrapedPost(
                platform="tweetfeed",
                author=user,
                content=content,
                url=tweet_url,
                timestamp=date_str,
                engagement={},
                raw=entry,
            ))

        logger.info(f"TweetFeed total: {len(posts)} IOC posts collected")
        return posts

    def search(self, keywords: list, limit: int = 50) -> list:
        """
        Search TweetFeed by tags and keyword filtering.

        TweetFeed tags map well to search terms — try matching keywords
        to known tags first, then fall back to content filtering.
        """
        # Known TweetFeed tags (subset — there are many more)
        known_tags = {
            "phishing", "cobalt strike", "cobaltstrike", "emotet", "qakbot",
            "agenttesla", "agent tesla", "trickbot", "icedid", "asyncrat",
            "remcos", "formbook", "lokibot", "raccoon", "redline", "vidar",
            "lumma", "amadey", "smokeloader", "pikabot", "darkgate",
            "ursnif", "gootloader", "bumblebee", "nanocore", "njrat",
            "quasar", "cryptbot", "stealc", "risepro", "meduza",
        }

        # Match keywords to TweetFeed tags
        matched_tags = []
        unmatched_keywords = []
        for kw in keywords:
            kw_lower = kw.lower().replace(" ", "")
            matched = False
            for tag in known_tags:
                if kw_lower in tag.replace(" ", "") or tag.replace(" ", "") in kw_lower:
                    matched_tags.append(tag.replace(" ", ""))
                    matched = True
                    break
            if not matched:
                unmatched_keywords.append(kw)

        # Fetch tagged results if we have matches
        all_entries = []
        if matched_tags:
            for tag in matched_tags:
                url = self._build_api_url(tag=tag)
                entries = self._fetch_feed(url)
                all_entries.extend(entries)
                logger.info(f"TweetFeed search: {len(entries)} IOCs for tag '{tag}'")

        # Always also fetch the full feed and filter by keywords
        url = self._build_api_url()
        full_feed = self._fetch_feed(url)

        # Filter full feed by keywords
        keywords_lower = [kw.lower() for kw in keywords]
        for entry in full_feed:
            text = " ".join([
                entry.get("value", ""),
                " ".join(entry.get("tags", [])),
                entry.get("user", ""),
            ]).lower()
            if any(kw in text for kw in keywords_lower):
                all_entries.append(entry)

        # Deduplicate by IOC value
        seen = set()
        unique = []
        for entry in all_entries:
            val = entry.get("value", "")
            if val not in seen:
                seen.add(val)
                unique.append(entry)

        # Convert to ScrapedPost
        posts = []
        for entry in unique[:limit]:
            ioc_value = entry.get("value", "")
            ioc_type = entry.get("type", "unknown")
            user = entry.get("user", "unknown")
            tags = entry.get("tags", [])
            tweet_url = entry.get("tweet", "")
            date_str = entry.get("date", "")

            tag_str = ", ".join(tags) if tags else "untagged"
            content = (
                f"IOC [{ioc_type}]: {ioc_value}\n"
                f"Tags: {tag_str}\n"
                f"Shared by: @{user}\n"
                f"Source tweet: {tweet_url}"
            )

            posts.append(ScrapedPost(
                platform="tweetfeed",
                author=user,
                content=content,
                url=tweet_url,
                timestamp=date_str,
                raw=entry,
            ))

        logger.info(f"TweetFeed search: {len(posts)} results for '{' '.join(keywords)}'")
        return posts

    def test_connection(self) -> bool:
        """Test TweetFeed API connectivity."""
        try:
            import requests
            resp = requests.get(f"{BASE_URL}/today", timeout=10)
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"TweetFeed connection test failed: {e}")
            return False
