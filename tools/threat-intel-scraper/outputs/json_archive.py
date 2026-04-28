"""
JSON Archive Writer — stores raw scraped posts for later review.
"""

import json
import os
from datetime import datetime


def write_archive(posts: list, output_path: str, campaign_name: str = "scrape") -> str:
    """
    Archive all scraped posts as JSON.

    Args:
        posts: List of ScrapedPost objects.
        output_path: Directory to write the archive.
        campaign_name: Identifier for the run.

    Returns:
        Path to the written JSON file.
    """
    os.makedirs(output_path, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    filename = f"archive-{campaign_name}-{timestamp}.json"
    filepath = os.path.join(output_path, filename)

    archive = {
        "metadata": {
            "campaign": campaign_name,
            "scraped_at": datetime.utcnow().isoformat() + "Z",
            "total_posts": len(posts),
            "platforms": list(set(p.platform for p in posts)),
        },
        "posts": [],
    }

    for post in posts:
        archive["posts"].append({
            "platform": post.platform,
            "author": post.author,
            "content": post.content,
            "url": post.url,
            "timestamp": post.timestamp,
            "collected_at": post.collected_at,
            "media_urls": post.media_urls,
            "engagement": post.engagement,
            "raw": post.raw,
        })

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(archive, f, indent=2, ensure_ascii=False, default=str)

    return filepath
