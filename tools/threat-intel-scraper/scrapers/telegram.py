"""
Telegram Channel Scraper

Uses Telethon (MTProto client) to scrape public channels and groups.

Requires Telegram API credentials:
  1. Go to https://my.telegram.org/apps
  2. Create an application → get api_id and api_hash

Config:
  telegram:
    api_id: 12345678
    api_hash: "your_api_hash"
    phone: "+1234567890"         # for first-time auth only
    session_name: "ti_scraper"   # session file name
    accounts:                    # channel/group usernames (without @)
      - vaboronhacknews
      - caboroncyber
      - exploitbroker
"""

import logging
from datetime import datetime

from .base import BaseScraper, ScrapedPost

logger = logging.getLogger(__name__)


class TelegramScraper(BaseScraper):
    platform_name = "telegram"

    def _validate_config(self):
        self.api_id = self.config.get("api_id")
        self.api_hash = self.config.get("api_hash", "")
        self.phone = self.config.get("phone", "")
        self.session_name = self.config.get("session_name", "ti_scraper")

        if not self.api_id or not self.api_hash:
            logger.warning(
                "Telegram api_id/api_hash not configured. "
                "Get credentials at https://my.telegram.org/apps"
            )

    def scrape(self, limit: int = 50) -> list:
        """Scrape messages from configured Telegram channels."""
        try:
            from telethon.sync import TelegramClient
            from telethon.tl.functions.messages import GetHistoryRequest
        except ImportError:
            logger.error("telethon library required: pip install telethon")
            return []

        if not self.api_id or not self.api_hash:
            logger.error("Telegram credentials not configured. Skipping.")
            return []

        posts = []

        try:
            client = TelegramClient(self.session_name, self.api_id, self.api_hash)
            client.start(phone=self.phone)

            for channel_name in self.accounts:
                try:
                    entity = client.get_entity(channel_name)
                    messages = client.get_messages(entity, limit=limit)

                    for msg in messages:
                        if not msg.text:
                            continue

                        # Build URL for the message
                        if hasattr(entity, 'username') and entity.username:
                            url = f"https://t.me/{entity.username}/{msg.id}"
                        else:
                            url = f"https://t.me/c/{entity.id}/{msg.id}"

                        media_urls = []
                        if msg.media:
                            media_urls.append(f"[media attached: {type(msg.media).__name__}]")

                        posts.append(ScrapedPost(
                            platform="telegram",
                            author=channel_name,
                            content=msg.text,
                            url=url,
                            timestamp=msg.date.isoformat() if msg.date else "",
                            media_urls=media_urls,
                            engagement={
                                "views": getattr(msg, 'views', 0) or 0,
                                "forwards": getattr(msg, 'forwards', 0) or 0,
                            },
                            raw={
                                "id": msg.id,
                                "peer_id": str(entity.id),
                                "date": msg.date.isoformat() if msg.date else "",
                            },
                        ))

                    logger.info(f"Scraped {len(messages)} messages from @{channel_name}")

                except Exception as e:
                    logger.error(f"Error scraping Telegram channel @{channel_name}: {e}")

            client.disconnect()

        except Exception as e:
            logger.error(f"Telegram client error: {e}")

        return posts

    def search(self, keywords: list, limit: int = 50) -> list:
        """Search Telegram channels using native message search."""
        try:
            from telethon.sync import TelegramClient
        except ImportError:
            logger.error("telethon library required: pip install telethon")
            return []

        if not self.api_id or not self.api_hash:
            logger.error("Telegram credentials not configured. Skipping search.")
            return []

        posts = []

        try:
            client = TelegramClient(self.session_name, self.api_id, self.api_hash)
            client.start(phone=self.phone)

            for channel_name in self.accounts:
                try:
                    entity = client.get_entity(channel_name)

                    for keyword in keywords:
                        messages = client.iter_messages(
                            entity,
                            search=keyword,
                            limit=limit,
                        )

                        count = 0
                        for msg in messages:
                            if not msg.text:
                                continue

                            if hasattr(entity, 'username') and entity.username:
                                url = f"https://t.me/{entity.username}/{msg.id}"
                            else:
                                url = f"https://t.me/c/{entity.id}/{msg.id}"

                            media_urls = []
                            if msg.media:
                                media_urls.append(f"[media: {type(msg.media).__name__}]")

                            posts.append(ScrapedPost(
                                platform="telegram",
                                author=channel_name,
                                content=msg.text,
                                url=url,
                                timestamp=msg.date.isoformat() if msg.date else "",
                                media_urls=media_urls,
                                engagement={
                                    "views": getattr(msg, 'views', 0) or 0,
                                    "forwards": getattr(msg, 'forwards', 0) or 0,
                                },
                                raw={
                                    "id": msg.id,
                                    "peer_id": str(entity.id),
                                    "search_keyword": keyword,
                                },
                            ))
                            count += 1

                        logger.info(f"Found {count} messages in @{channel_name} for '{keyword}'")

                except Exception as e:
                    logger.error(f"Error searching Telegram @{channel_name}: {e}")

            client.disconnect()

        except Exception as e:
            logger.error(f"Telegram search error: {e}")

        # Deduplicate (same message might match multiple keywords)
        seen_ids = set()
        unique = []
        for p in posts:
            msg_id = p.raw.get("id")
            if msg_id not in seen_ids:
                seen_ids.add(msg_id)
                unique.append(p)

        return unique[:limit]

    def test_connection(self) -> bool:
        try:
            from telethon.sync import TelegramClient
            client = TelegramClient(self.session_name, self.api_id, self.api_hash)
            client.start(phone=self.phone)
            me = client.get_me()
            client.disconnect()
            return me is not None
        except Exception as e:
            logger.error(f"Telegram connection test failed: {e}")
            return False
