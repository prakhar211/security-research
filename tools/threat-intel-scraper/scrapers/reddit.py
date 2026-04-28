"""
Reddit Scraper

Uses PRAW (Python Reddit API Wrapper) to scrape security-focused subreddits
and specific user profiles.

Requires Reddit API credentials:
  1. Go to https://www.reddit.com/prefs/apps
  2. Create a "script" type application
  3. Note the client_id (under app name) and client_secret

Config:
  reddit:
    client_id: "your_client_id"
    client_secret: "your_client_secret"
    user_agent: "threat-intel-scraper/1.0 by u/your_username"
    accounts:          # subreddits to monitor
      - netsec
      - blueteam
      - malware
      - cybersecurity
      - ReverseEngineering
    users: []          # specific users to follow (optional)
    sort: "new"        # new, hot, top
    time_filter: "week"  # hour, day, week, month, year, all
"""

import logging
from datetime import datetime

from .base import BaseScraper, ScrapedPost

logger = logging.getLogger(__name__)


class RedditScraper(BaseScraper):
    platform_name = "reddit"

    def _validate_config(self):
        self.client_id = self.config.get("client_id", "")
        self.client_secret = self.config.get("client_secret", "")
        self.user_agent = self.config.get("user_agent", "threat-intel-scraper/1.0")
        self.users = self.config.get("users", [])
        self.sort = self.config.get("sort", "new")
        self.time_filter = self.config.get("time_filter", "week")

        if not self.client_id or not self.client_secret:
            logger.warning(
                "Reddit client_id/client_secret not configured. "
                "Create an app at https://www.reddit.com/prefs/apps"
            )

    def _get_reddit(self):
        """Initialize PRAW Reddit instance."""
        import praw
        return praw.Reddit(
            client_id=self.client_id,
            client_secret=self.client_secret,
            user_agent=self.user_agent,
        )

    def scrape(self, limit: int = 50) -> list:
        """Scrape posts from configured subreddits and users."""
        try:
            import praw
        except ImportError:
            logger.error("praw library required: pip install praw")
            return []

        if not self.client_id or not self.client_secret:
            logger.error("Reddit credentials not configured. Skipping.")
            return []

        posts = []

        try:
            reddit = self._get_reddit()

            # Scrape subreddits
            for subreddit_name in self.accounts:
                try:
                    subreddit = reddit.subreddit(subreddit_name)

                    if self.sort == "new":
                        submissions = subreddit.new(limit=limit)
                    elif self.sort == "hot":
                        submissions = subreddit.hot(limit=limit)
                    elif self.sort == "top":
                        submissions = subreddit.top(time_filter=self.time_filter, limit=limit)
                    else:
                        submissions = subreddit.new(limit=limit)

                    count = 0
                    for submission in submissions:
                        # Combine title + selftext for full content
                        content = submission.title
                        if submission.selftext:
                            content += "\n\n" + submission.selftext

                        # If it's a link post, include the URL in content
                        if not submission.is_self and submission.url:
                            content += f"\n\nLinked: {submission.url}"

                        timestamp = datetime.utcfromtimestamp(
                            submission.created_utc
                        ).isoformat() + "Z"

                        posts.append(ScrapedPost(
                            platform="reddit",
                            author=f"r/{subreddit_name}/u/{submission.author}",
                            content=content,
                            url=f"https://reddit.com{submission.permalink}",
                            timestamp=timestamp,
                            engagement={
                                "score": submission.score,
                                "upvote_ratio": submission.upvote_ratio,
                                "comments": submission.num_comments,
                            },
                            raw={
                                "id": submission.id,
                                "subreddit": subreddit_name,
                                "flair": str(submission.link_flair_text or ""),
                                "is_self": submission.is_self,
                                "domain": submission.domain,
                            },
                        ))
                        count += 1

                    logger.info(f"Scraped {count} posts from r/{subreddit_name}")

                except Exception as e:
                    logger.error(f"Error scraping r/{subreddit_name}: {e}")

            # Scrape specific users
            for username in self.users:
                try:
                    user = reddit.redditor(username)
                    count = 0
                    for submission in user.submissions.new(limit=limit):
                        content = submission.title
                        if submission.selftext:
                            content += "\n\n" + submission.selftext

                        timestamp = datetime.utcfromtimestamp(
                            submission.created_utc
                        ).isoformat() + "Z"

                        posts.append(ScrapedPost(
                            platform="reddit",
                            author=f"u/{username}",
                            content=content,
                            url=f"https://reddit.com{submission.permalink}",
                            timestamp=timestamp,
                            engagement={
                                "score": submission.score,
                                "comments": submission.num_comments,
                            },
                            raw={"id": submission.id, "user": username},
                        ))
                        count += 1

                    logger.info(f"Scraped {count} posts from u/{username}")

                except Exception as e:
                    logger.error(f"Error scraping u/{username}: {e}")

        except Exception as e:
            logger.error(f"Reddit client error: {e}")

        return posts

    def search(self, keywords: list, limit: int = 50) -> list:
        """Search Reddit using native search API across security subreddits."""
        try:
            import praw
        except ImportError:
            logger.error("praw library required: pip install praw")
            return []

        if not self.client_id or not self.client_secret:
            logger.error("Reddit credentials not configured. Skipping search.")
            return []

        posts = []
        query = " OR ".join(keywords)

        try:
            reddit = self._get_reddit()

            # Search across configured subreddits
            search_subs = self.accounts if self.accounts else ["netsec", "cybersecurity", "malware"]

            for subreddit_name in search_subs:
                try:
                    subreddit = reddit.subreddit(subreddit_name)
                    results = subreddit.search(
                        query,
                        sort="relevance",
                        time_filter=self.time_filter,
                        limit=limit,
                    )

                    count = 0
                    for submission in results:
                        content = submission.title
                        if submission.selftext:
                            content += "\n\n" + submission.selftext
                        if not submission.is_self and submission.url:
                            content += f"\n\nLinked: {submission.url}"

                        timestamp = datetime.utcfromtimestamp(
                            submission.created_utc
                        ).isoformat() + "Z"

                        posts.append(ScrapedPost(
                            platform="reddit",
                            author=f"r/{subreddit_name}/u/{submission.author}",
                            content=content,
                            url=f"https://reddit.com{submission.permalink}",
                            timestamp=timestamp,
                            engagement={
                                "score": submission.score,
                                "upvote_ratio": submission.upvote_ratio,
                                "comments": submission.num_comments,
                            },
                            raw={
                                "id": submission.id,
                                "subreddit": subreddit_name,
                                "flair": str(submission.link_flair_text or ""),
                                "search_query": query,
                            },
                        ))
                        count += 1

                    logger.info(f"Found {count} results in r/{subreddit_name} for '{query}'")

                except Exception as e:
                    logger.error(f"Error searching r/{subreddit_name}: {e}")

        except Exception as e:
            logger.error(f"Reddit search error: {e}")

        return posts

    def test_connection(self) -> bool:
        try:
            reddit = self._get_reddit()
            # Read-only check
            subreddit = reddit.subreddit("netsec")
            _ = subreddit.display_name
            return True
        except Exception as e:
            logger.error(f"Reddit connection test failed: {e}")
            return False
