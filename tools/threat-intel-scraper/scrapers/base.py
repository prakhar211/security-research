"""
Base scraper interface — all platform scrapers inherit from this.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScrapedPost:
    """A single scraped post/message from any platform."""
    platform: str          # twitter, telegram, reddit, linkedin
    author: str            # username or channel name
    content: str           # full text content
    url: str = ""          # link to original post
    timestamp: str = ""    # ISO 8601
    media_urls: list = field(default_factory=list)
    engagement: dict = field(default_factory=dict)  # likes, shares, etc.
    raw: dict = field(default_factory=dict)          # raw API response

    @property
    def collected_at(self) -> str:
        return datetime.utcnow().isoformat() + "Z"


class BaseScraper(ABC):
    """Abstract base for all platform scrapers."""

    platform_name: str = "unknown"

    def __init__(self, config: dict):
        self.config = config
        self.accounts = config.get("accounts", [])
        self._validate_config()

    def _validate_config(self):
        """Override to check required API keys, etc."""
        pass

    @abstractmethod
    def scrape(self, limit: int = 50) -> list:
        """
        Scrape recent posts from configured accounts.

        Args:
            limit: Max posts to fetch per account.

        Returns:
            List of ScrapedPost objects.
        """
        raise NotImplementedError

    @abstractmethod
    def test_connection(self) -> bool:
        """Verify API keys and connectivity."""
        raise NotImplementedError

    def search(self, keywords: list, limit: int = 50) -> list:
        """
        Search for posts matching specific keywords.

        Default implementation: scrape then filter by keywords.
        Platform scrapers can override this with native search APIs.

        Args:
            keywords: List of search terms (any match counts).
            limit: Max results to return.

        Returns:
            List of ScrapedPost objects matching the keywords.
        """
        posts = self.scrape(limit=limit * 2)  # over-fetch to account for filtering
        return self.filter_by_keywords(posts, keywords)[:limit]

    def filter_by_keywords(self, posts: list, keywords: list) -> list:
        """Filter posts that contain any of the given keywords."""
        if not keywords:
            return posts
        keywords_lower = [kw.lower() for kw in keywords]
        filtered = []
        for post in posts:
            text_lower = post.content.lower()
            if any(kw in text_lower for kw in keywords_lower):
                filtered.append(post)
        return filtered

    def filter_security_content(self, posts: list) -> list:
        """Basic filter to keep only security-relevant posts."""
        security_keywords = {
            "cve", "vulnerability", "exploit", "malware", "ransomware",
            "phishing", "c2", "ioc", "indicator", "threat", "apt",
            "campaign", "breach", "compromise", "attack", "detection",
            "hunting", "sigma", "yara", "snort", "suricata",
            "mitre", "att&ck", "ttp", "backdoor", "trojan", "rat",
            "cobalt strike", "beacon", "loader", "dropper", "infosteal",
            "zero-day", "0day", "patch tuesday", "advisory",
            "credential", "token theft", "lateral movement",
        }
        filtered = []
        for post in posts:
            text_lower = post.content.lower()
            if any(kw in text_lower for kw in security_keywords):
                filtered.append(post)
        return filtered
