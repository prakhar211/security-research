"""
X / Twitter Scraper

Supports three modes:
  1. Twitter API v2 (requires Bearer Token — free tier: 100 reads/month)
  2. Nitter RSS for per-account feeds (no auth, but instances rotate)
  3. Nitter search for keyword-based queries (scrapes search results page)

All Nitter requests retry up to 3 times (Nitter often loads on the 2nd try).
The scraper auto-cycles through multiple Nitter instances if one is down.

Config:
  twitter:
    mode: "api"  # or "nitter"
    bearer_token: "YOUR_TOKEN"
    nitter_instances:
      - "https://nitter.privacydev.net"
      - "https://nitter.poast.org"
      - "https://nitter.net"
    accounts:
      - GossiTheDog
      - MsftSecIntel
"""

import re
import time
import logging
from datetime import datetime

from .base import BaseScraper, ScrapedPost

logger = logging.getLogger(__name__)

# Known Nitter instances (rotates frequently — update as needed)
DEFAULT_NITTER_INSTANCES = [
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
    "https://nitter.1d4.us",
    "https://nitter.kavin.rocks",
    "https://nitter.unixfox.eu",
    "https://nitter.net",
]

NITTER_MAX_RETRIES = 3
NITTER_RETRY_DELAY = 2  # seconds between retries


def _nitter_request(url: str, params: dict = None, timeout: int = 15) -> "requests.Response | None":
    """
    Make an HTTP request to a Nitter instance with up to 3 retries.
    Nitter frequently fails on the first request but loads on the 2nd try.
    """
    import requests

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    for attempt in range(1, NITTER_MAX_RETRIES + 1):
        try:
            resp = requests.get(url, params=params, timeout=timeout, headers=headers)
            if resp.status_code == 200:
                return resp
            logger.debug(
                f"Nitter attempt {attempt}/{NITTER_MAX_RETRIES}: "
                f"status {resp.status_code} for {url}"
            )
        except requests.exceptions.Timeout:
            logger.debug(f"Nitter attempt {attempt}/{NITTER_MAX_RETRIES}: timeout for {url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"Nitter attempt {attempt}/{NITTER_MAX_RETRIES}: connection error for {url}")
        except Exception as e:
            logger.debug(f"Nitter attempt {attempt}/{NITTER_MAX_RETRIES}: {e}")

        if attempt < NITTER_MAX_RETRIES:
            time.sleep(NITTER_RETRY_DELAY)

    return None


class TwitterScraper(BaseScraper):
    platform_name = "twitter"

    def _validate_config(self):
        self.mode = self.config.get("mode", "api")
        self.bearer_token = self.config.get("bearer_token", "")

        if self.config.get("nitter_instances"):
            self.nitter_instances = self.config["nitter_instances"]
        elif self.config.get("nitter_instance"):
            self.nitter_instances = [self.config["nitter_instance"]] + DEFAULT_NITTER_INSTANCES
        else:
            self.nitter_instances = DEFAULT_NITTER_INSTANCES

        self._working_instance = None

        if self.mode == "api" and not self.bearer_token:
            logger.warning(
                "Twitter API mode selected but no bearer_token provided. "
                "Falling back to Nitter. Get a token at https://developer.x.com"
            )
            self.mode = "nitter"

    def _find_working_instance(self) -> str:
        """Try Nitter instances (with retries each) until one responds."""
        if self._working_instance:
            return self._working_instance

        for instance in self.nitter_instances:
            logger.info(f"Trying Nitter instance: {instance} (up to {NITTER_MAX_RETRIES} attempts)...")
            resp = _nitter_request(f"{instance}/search", params={"q": "test"}, timeout=10)
            if resp is not None:
                self._working_instance = instance
                logger.info(f"Nitter instance alive: {instance}")
                return instance
            logger.debug(f"Nitter instance failed after {NITTER_MAX_RETRIES} tries: {instance}")

        logger.error(
            "No working Nitter instance found after trying all instances "
            f"({NITTER_MAX_RETRIES} attempts each). "
            "Use API mode or check https://status.d420.de for live instances."
        )
        return ""

    # --- Scrape (per-account feeds) ---

    def scrape(self, limit: int = 50) -> list:
        if self.mode == "api":
            return self._scrape_api(limit)
        return self._scrape_nitter(limit)

    def _scrape_api(self, limit: int) -> list:
        """Scrape via Twitter API v2."""
        try:
            import requests
        except ImportError:
            logger.error("requests library required: pip install requests")
            return []

        posts = []
        headers = {"Authorization": f"Bearer {self.bearer_token}"}

        for account in self.accounts:
            try:
                user_resp = requests.get(
                    f"https://api.twitter.com/2/users/by/username/{account}",
                    headers=headers, timeout=15,
                )
                if user_resp.status_code != 200:
                    logger.error(f"Failed to resolve @{account}: {user_resp.status_code}")
                    continue

                user_id = user_resp.json()["data"]["id"]
                params = {
                    "max_results": min(limit, 100),
                    "tweet.fields": "created_at,public_metrics,entities",
                    "exclude": "retweets,replies",
                }
                tweets_resp = requests.get(
                    f"https://api.twitter.com/2/users/{user_id}/tweets",
                    headers=headers, params=params, timeout=15,
                )
                if tweets_resp.status_code != 200:
                    logger.error(f"Failed to fetch tweets for @{account}: {tweets_resp.status_code}")
                    continue

                for tweet in tweets_resp.json().get("data", []):
                    metrics = tweet.get("public_metrics", {})
                    posts.append(ScrapedPost(
                        platform="twitter",
                        author=account,
                        content=tweet.get("text", ""),
                        url=f"https://x.com/{account}/status/{tweet['id']}",
                        timestamp=tweet.get("created_at", ""),
                        engagement={
                            "likes": metrics.get("like_count", 0),
                            "retweets": metrics.get("retweet_count", 0),
                            "replies": metrics.get("reply_count", 0),
                        },
                        raw=tweet,
                    ))
                logger.info(f"Scraped {len(tweets_resp.json().get('data', []))} tweets from @{account}")

            except Exception as e:
                logger.error(f"Error scraping @{account}: {e}")

        return posts

    def _scrape_nitter(self, limit: int) -> list:
        """Scrape via Nitter RSS feeds (with retries)."""
        try:
            import feedparser
        except ImportError:
            logger.error("feedparser library required: pip install feedparser")
            return []

        instance = self._find_working_instance()
        if not instance:
            return []

        posts = []
        for account in self.accounts:
            try:
                feed_url = f"{instance}/{account}/rss"

                # Use retry logic for RSS too — fetch raw XML then parse
                resp = _nitter_request(feed_url, timeout=15)
                if resp is None:
                    logger.warning(f"Nitter RSS failed for @{account} after {NITTER_MAX_RETRIES} retries")
                    continue

                feed = feedparser.parse(resp.text)

                if not feed.entries:
                    logger.warning(f"No entries in RSS for @{account}")
                    continue

                for entry in feed.entries[:limit]:
                    content = entry.get("summary", entry.get("title", ""))
                    content = re.sub(r"<[^>]+>", " ", content).strip()
                    content = re.sub(r"\s+", " ", content)

                    timestamp = ""
                    if hasattr(entry, "published_parsed") and entry.published_parsed:
                        timestamp = datetime(*entry.published_parsed[:6]).isoformat() + "Z"

                    posts.append(ScrapedPost(
                        platform="twitter",
                        author=account,
                        content=content,
                        url=entry.get("link", "").replace(instance, "https://x.com"),
                        timestamp=timestamp,
                        raw={"title": entry.get("title", ""), "link": entry.get("link", "")},
                    ))

                logger.info(f"Scraped {min(len(feed.entries), limit)} posts from @{account} via Nitter")

            except Exception as e:
                logger.error(f"Nitter RSS error for @{account}: {e}")

        return posts

    # --- Search ---

    def search(self, keywords: list, limit: int = 50) -> list:
        """Search Twitter for keywords using API v2 or Nitter search."""
        if self.mode == "api" and self.bearer_token:
            return self._search_api(keywords, limit)
        return self._search_nitter(keywords, limit)

    def _search_api(self, keywords: list, limit: int) -> list:
        """Search via Twitter API v2 recent search endpoint."""
        try:
            import requests
        except ImportError:
            logger.error("requests library required")
            return []

        posts = []
        headers = {"Authorization": f"Bearer {self.bearer_token}"}

        query_parts = [f'("{kw}")' for kw in keywords]
        query = f"({' OR '.join(query_parts)}) -is:retweet lang:en"
        if len(query) > 500:
            query = f"{' OR '.join(keywords[:3])} -is:retweet lang:en"

        try:
            params = {
                "query": query,
                "max_results": min(limit, 100),
                "tweet.fields": "created_at,public_metrics,author_id,entities",
                "expansions": "author_id",
                "user.fields": "username",
            }
            resp = requests.get(
                "https://api.twitter.com/2/tweets/search/recent",
                headers=headers, params=params, timeout=15,
            )
            if resp.status_code != 200:
                logger.error(f"Twitter search failed: {resp.status_code} — {resp.text[:200]}")
                return []

            data = resp.json()
            users = {}
            for u in data.get("includes", {}).get("users", []):
                users[u["id"]] = u["username"]

            for tweet in data.get("data", []):
                author = users.get(tweet.get("author_id"), "unknown")
                metrics = tweet.get("public_metrics", {})
                posts.append(ScrapedPost(
                    platform="twitter",
                    author=author,
                    content=tweet.get("text", ""),
                    url=f"https://x.com/{author}/status/{tweet['id']}",
                    timestamp=tweet.get("created_at", ""),
                    engagement={
                        "likes": metrics.get("like_count", 0),
                        "retweets": metrics.get("retweet_count", 0),
                        "replies": metrics.get("reply_count", 0),
                    },
                    raw={**tweet, "search_query": query},
                ))

            logger.info(f"Twitter API search: {len(posts)} results for '{' '.join(keywords)}'")

        except Exception as e:
            logger.error(f"Twitter search error: {e}")

        return posts

    def _search_nitter(self, keywords: list, limit: int) -> list:
        """Search via Nitter search page (with retries)."""
        instance = self._find_working_instance()
        if not instance:
            return self._search_nitter_fallback(keywords, limit)

        query = " ".join(keywords)

        resp = _nitter_request(
            f"{instance}/search",
            params={"f": "tweets", "q": query},
            timeout=15,
        )

        if resp is None:
            logger.warning(f"Nitter search failed after {NITTER_MAX_RETRIES} retries on {instance}")
            # Invalidate and try fallback
            self._working_instance = None
            return self._search_nitter_fallback(keywords, limit)

        posts = self._parse_nitter_search_results(resp.text, instance, limit)
        logger.info(f"Nitter search: {len(posts)} results for '{query}' on {instance}")
        return posts

    def _parse_nitter_search_results(self, html: str, instance: str, limit: int) -> list:
        """Parse Nitter search results HTML into ScrapedPost objects."""
        posts = []

        # Extract username, content, links, timestamps from HTML
        usernames = re.findall(r'<a class="username"[^>]*>@([^<]+)</a>', html)
        contents = re.findall(r'<div class="tweet-content[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
        tweet_links = re.findall(r'<a class="tweet-link"[^>]*href="([^"]+)"', html)
        timestamps = re.findall(r'<span class="tweet-date"><a[^>]*title="([^"]*)"', html)

        count = min(len(contents), len(usernames), limit)

        for i in range(count):
            content = re.sub(r"<[^>]+>", " ", contents[i]).strip()
            content = re.sub(r"\s+", " ", content)
            content = content.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")

            author = usernames[i] if i < len(usernames) else "unknown"
            link = tweet_links[i] if i < len(tweet_links) else ""
            ts = timestamps[i] if i < len(timestamps) else ""

            url = f"https://x.com{link}" if link else ""

            posts.append(ScrapedPost(
                platform="twitter",
                author=author,
                content=content,
                url=url,
                timestamp=ts,
                raw={"nitter_instance": instance, "search": True},
            ))

        return posts

    def _search_nitter_fallback(self, keywords: list, limit: int) -> list:
        """Fallback: scrape configured account feeds and filter by keywords."""
        logger.info("Falling back to Nitter RSS feed scraping + keyword filtering")
        posts = self._scrape_nitter(limit * 3)
        return self.filter_by_keywords(posts, keywords)[:limit]

    # --- Test ---

    def test_connection(self) -> bool:
        if self.mode == "api":
            try:
                import requests
                resp = requests.get(
                    "https://api.twitter.com/2/users/me",
                    headers={"Authorization": f"Bearer {self.bearer_token}"},
                    timeout=10,
                )
                return resp.status_code in (200, 403)
            except Exception:
                return False
        else:
            instance = self._find_working_instance()
            return bool(instance)
