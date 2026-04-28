"""
LinkedIn Scraper

LinkedIn aggressively blocks scraping and has no public post-reading API.
This module uses two practical workarounds:

  1. RSS via third-party services (e.g., rss.app, feedspot, or Phantom Buster exports)
  2. Manual export mode — point it at a folder of saved/exported post text files

For automated LinkedIn monitoring, the most reliable approach is:
  - Use a service like Phantom Buster, Apify, or rss.app to generate RSS feeds
    from LinkedIn profiles/companies
  - Configure the RSS feed URLs below

Config:
  linkedin:
    mode: "rss"    # "rss" or "manual"
    feeds:         # RSS feed URLs (from third-party services)
      - url: "https://rss.app/feeds/your-feed-id.xml"
        label: "Security Researcher A"
      - url: "https://rss.app/feeds/another-feed.xml"
        label: "MSRC Updates"
    manual_dir: "./linkedin_exports"   # folder with .txt files (manual mode)
    accounts: []   # Profile names for reference/labeling only
"""

import os
import logging
from datetime import datetime
from pathlib import Path

from .base import BaseScraper, ScrapedPost

logger = logging.getLogger(__name__)


class LinkedInScraper(BaseScraper):
    platform_name = "linkedin"

    def _validate_config(self):
        self.mode = self.config.get("mode", "rss")
        self.feeds = self.config.get("feeds", [])
        self.manual_dir = self.config.get("manual_dir", "./linkedin_exports")

        if self.mode == "rss" and not self.feeds:
            logger.warning(
                "LinkedIn RSS mode selected but no feeds configured. "
                "Use services like rss.app or Phantom Buster to create "
                "RSS feeds from LinkedIn profiles."
            )

    def scrape(self, limit: int = 50) -> list:
        if self.mode == "rss":
            return self._scrape_rss(limit)
        elif self.mode == "manual":
            return self._scrape_manual(limit)
        else:
            logger.error(f"Unknown LinkedIn mode: {self.mode}")
            return []

    def _scrape_rss(self, limit: int) -> list:
        """Scrape LinkedIn content via third-party RSS feeds."""
        try:
            import feedparser
        except ImportError:
            logger.error("feedparser library required: pip install feedparser")
            return []

        posts = []

        for feed_config in self.feeds:
            feed_url = feed_config.get("url", "")
            label = feed_config.get("label", "linkedin")

            if not feed_url:
                continue

            try:
                feed = feedparser.parse(feed_url)

                if feed.bozo and not feed.entries:
                    logger.warning(f"LinkedIn RSS feed failed for '{label}': {feed_url}")
                    continue

                for entry in feed.entries[:limit]:
                    content = entry.get("summary", entry.get("title", ""))
                    # Strip HTML
                    import re
                    content = re.sub(r"<[^>]+>", " ", content).strip()
                    content = re.sub(r"\s+", " ", content)

                    timestamp = ""
                    if hasattr(entry, "published_parsed") and entry.published_parsed:
                        timestamp = datetime(*entry.published_parsed[:6]).isoformat() + "Z"

                    posts.append(ScrapedPost(
                        platform="linkedin",
                        author=label,
                        content=content,
                        url=entry.get("link", ""),
                        timestamp=timestamp,
                        raw={"feed": feed_url, "title": entry.get("title", "")},
                    ))

                logger.info(f"Scraped {min(len(feed.entries), limit)} posts from LinkedIn feed '{label}'")

            except Exception as e:
                logger.error(f"LinkedIn RSS error for '{label}': {e}")

        return posts

    def _scrape_manual(self, limit: int) -> list:
        """
        Read manually exported LinkedIn post text files.

        Expected file format:
          - One .txt or .md file per post
          - First line: author name
          - Second line: date (YYYY-MM-DD) or URL
          - Rest: post content
        """
        posts = []
        manual_path = Path(self.manual_dir)

        if not manual_path.exists():
            logger.warning(f"LinkedIn manual export directory not found: {self.manual_dir}")
            return []

        files = sorted(manual_path.glob("*.txt")) + sorted(manual_path.glob("*.md"))

        for filepath in files[:limit]:
            try:
                text = filepath.read_text(encoding="utf-8").strip()
                lines = text.split("\n")

                if len(lines) < 3:
                    logger.warning(f"Skipping {filepath.name}: too few lines")
                    continue

                author = lines[0].strip()
                date_or_url = lines[1].strip()
                content = "\n".join(lines[2:]).strip()

                # Try to parse date
                timestamp = ""
                url = ""
                if date_or_url.startswith("http"):
                    url = date_or_url
                else:
                    try:
                        timestamp = datetime.strptime(date_or_url, "%Y-%m-%d").isoformat() + "Z"
                    except ValueError:
                        # Maybe it's a URL after all
                        url = date_or_url

                posts.append(ScrapedPost(
                    platform="linkedin",
                    author=author,
                    content=content,
                    url=url,
                    timestamp=timestamp,
                    raw={"file": str(filepath)},
                ))

            except Exception as e:
                logger.error(f"Error reading {filepath.name}: {e}")

        logger.info(f"Loaded {len(posts)} posts from LinkedIn manual exports")
        return posts

    def test_connection(self) -> bool:
        if self.mode == "rss":
            if not self.feeds:
                return False
            try:
                import feedparser
                feed = feedparser.parse(self.feeds[0].get("url", ""))
                return not feed.bozo or len(feed.entries) > 0
            except Exception:
                return False
        elif self.mode == "manual":
            return Path(self.manual_dir).exists()
        return False
