"""
CSV IOC Writer — outputs extracted IOCs in CSV format compatible with
the blog's iocs/ directory structure.
"""

import csv
import os
from datetime import datetime
from pathlib import Path


def write_ioc_csv(iocs: list, output_path: str, campaign_name: str = "scrape") -> str:
    """
    Write IOCs to CSV in the repo's iocs/ format.

    Args:
        iocs: List of IOC objects from ioc_extractor.
        output_path: Directory to write the CSV file.
        campaign_name: Name for the campaign/scrape run.

    Returns:
        Path to the written CSV file.
    """
    os.makedirs(output_path, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d")
    filename = f"{campaign_name}-{timestamp}.csv"
    filepath = os.path.join(output_path, filename)

    fieldnames = [
        "type", "value", "defanged", "source", "timestamp",
        "context", "first_seen", "confidence"
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in iocs:
            writer.writerow({
                "type": ioc.type,
                "value": ioc.value,
                "defanged": ioc.defanged,
                "source": ioc.source,
                "timestamp": ioc.timestamp,
                "context": ioc.context[:200],  # truncate long contexts
                "first_seen": datetime.utcnow().isoformat() + "Z",
                "confidence": "medium",
            })

    return filepath


def write_blog_ioc_csv(iocs: list, campaign_dir: str) -> str:
    """
    Write IOCs in the blog-compatible format for docs/_data/iocs/.

    This format is consumed by the {% include ioc-table.html %} template.
    """
    os.makedirs(campaign_dir, exist_ok=True)
    filepath = os.path.join(campaign_dir, "indicators.csv")

    fieldnames = ["type", "indicator", "context", "source"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in iocs:
            writer.writerow({
                "type": ioc.type,
                "indicator": ioc.defanged,
                "context": ioc.context[:150],
                "source": ioc.source,
            })

    return filepath
