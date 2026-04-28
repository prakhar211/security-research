#!/usr/bin/env python3
"""
Threat Intel Scraper — CLI entry point.

Scrapes security-focused accounts across X/Twitter, Telegram, Reddit,
and LinkedIn. Extracts IOCs, maps MITRE ATT&CK techniques, and outputs
structured data for the security-research blog.

Usage:
    python scraper.py scrape                    # Full scrape + extract + report
    python scraper.py scrape --platform twitter  # Single platform
    python scraper.py extract --input file.json  # Extract IOCs from archived JSON
    python scraper.py test                       # Test platform connections
    python scraper.py report --input file.json   # Generate report from archive

Configuration:
    Copy config.yaml to config.local.yaml and add your API keys.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import yaml


# --- Config loading ---

def load_config(config_path: str = None) -> dict:
    """Load config from YAML file. Prefers config.local.yaml over config.yaml."""
    base_dir = Path(__file__).parent

    if config_path:
        paths = [Path(config_path)]
    else:
        paths = [
            base_dir / "config.local.yaml",
            base_dir / "config.yaml",
        ]

    for p in paths:
        if p.exists():
            with open(p, "r") as f:
                config = yaml.safe_load(f)
                logging.info(f"Loaded config from {p}")
                return config

    logging.error("No config file found. Copy config.yaml to config.local.yaml")
    sys.exit(1)


def setup_logging(config: dict):
    """Configure logging from config."""
    log_config = config.get("logging", {})
    level = getattr(logging, log_config.get("level", "INFO").upper(), logging.INFO)
    log_file = log_config.get("file", "")

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


# --- Scraper registry ---

def get_scrapers(config: dict, platforms: list = None):
    """Initialize requested platform scrapers."""
    from scrapers.twitter import TwitterScraper
    from scrapers.telegram import TelegramScraper
    from scrapers.reddit import RedditScraper
    from scrapers.linkedin import LinkedInScraper
    from scrapers.tweetfeed import TweetFeedScraper
    from scrapers.threatfox import ThreatFoxScraper

    registry = {
        "twitter": (TwitterScraper, config.get("twitter", {})),
        "telegram": (TelegramScraper, config.get("telegram", {})),
        "reddit": (RedditScraper, config.get("reddit", {})),
        "linkedin": (LinkedInScraper, config.get("linkedin", {})),
        "tweetfeed": (TweetFeedScraper, config.get("tweetfeed", {})),
        "threatfox": (ThreatFoxScraper, config.get("threatfox", {})),
    }

    active = {}
    for name, (cls, platform_config) in registry.items():
        if platforms and name not in platforms:
            continue
        if platform_config.get("accounts") or platform_config.get("feeds") or platform_config.get("enabled"):
            active[name] = cls(platform_config)

    return active


# --- Commands ---

def cmd_scrape(args, config):
    """Full pipeline: scrape → filter → extract → map → output."""
    from extractors.ioc_extractor import extract_iocs
    from extractors.mitre_mapper import map_techniques
    from outputs.csv_writer import write_ioc_csv, write_blog_ioc_csv
    from outputs.stix_writer import write_stix_bundle
    from outputs.markdown_writer import write_summary
    from outputs.json_archive import write_archive

    logger = logging.getLogger("scrape")
    campaign = args.campaign or config.get("campaign", "daily-intel")
    extraction_config = config.get("extraction", {})
    output_config = config.get("output", {})

    # Resolve output paths relative to the tool directory
    base_dir = Path(__file__).parent
    iocs_dir = base_dir / output_config.get("iocs_dir", "./output/iocs")
    blog_data_dir = base_dir / output_config.get("blog_data_dir", "./output/blog")
    drafts_dir = base_dir / output_config.get("drafts_dir", "./output/drafts")
    archive_dir = base_dir / output_config.get("archive_dir", "./output/archive")
    reports_dir = base_dir / output_config.get("reports_dir", "./output/reports")

    # Step 1: Scrape
    platforms = [args.platform] if args.platform else None
    scrapers = get_scrapers(config, platforms)

    if not scrapers:
        logger.error("No platforms configured or selected. Check config.yaml")
        return

    all_posts = []
    for name, scraper in scrapers.items():
        logger.info(f"Scraping {name}...")
        try:
            posts = scraper.scrape(limit=args.limit)
            logger.info(f"  → {len(posts)} posts from {name}")

            # Filter security content if enabled
            if extraction_config.get("filter_security", True):
                posts = scraper.filter_security_content(posts)
                logger.info(f"  → {len(posts)} security-relevant posts after filtering")

            all_posts.extend(posts)
        except Exception as e:
            logger.error(f"  → Error scraping {name}: {e}")

    if not all_posts:
        logger.warning("No posts collected. Check platform configs and credentials.")
        return

    logger.info(f"\nTotal posts collected: {len(all_posts)}")

    # Step 2: Archive raw posts
    archive_path = write_archive(all_posts, str(archive_dir), campaign)
    logger.info(f"Archive saved: {archive_path}")

    # Step 3: Extract IOCs
    all_iocs = []
    combined_text = ""
    ioc_types = extraction_config.get("ioc_types", None)

    for post in all_posts:
        result = extract_iocs(
            post.content,
            source=post.url or f"{post.platform}/@{post.author}",
            timestamp=post.timestamp,
            types=ioc_types,
        )
        all_iocs.extend(result.iocs)
        combined_text += post.content + "\n\n"

    # Deduplicate IOCs globally
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        key = (ioc.type, ioc.value)
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)
    all_iocs = unique_iocs

    logger.info(f"IOCs extracted: {len(all_iocs)}")

    # Step 4: MITRE ATT&CK mapping
    min_conf = extraction_config.get("mitre_min_confidence", "medium")
    mitre_matches = map_techniques(combined_text, min_confidence=min_conf)
    logger.info(f"MITRE techniques mapped: {len(mitre_matches)}")

    # Step 5: Write outputs
    if all_iocs:
        # CSV to repo iocs/ directory
        campaign_ioc_dir = iocs_dir / campaign
        csv_path = write_ioc_csv(all_iocs, str(campaign_ioc_dir), campaign)
        logger.info(f"IOC CSV: {csv_path}")

        # Blog-compatible CSV
        blog_csv_path = write_blog_ioc_csv(all_iocs, str(blog_data_dir / campaign))
        logger.info(f"Blog IOC CSV: {blog_csv_path}")

        # STIX 2.1 bundle
        stix_path = write_stix_bundle(all_iocs, str(campaign_ioc_dir), campaign)
        logger.info(f"STIX bundle: {stix_path}")

    # Markdown summary
    summary_path = write_summary(
        all_posts, all_iocs, mitre_matches,
        str(reports_dir), campaign,
    )
    logger.info(f"Summary report: {summary_path}")

    # Blog draft (optional)
    if args.draft:
        draft_path = write_summary(
            all_posts, all_iocs, mitre_matches,
            str(drafts_dir), campaign,
            as_blog_draft=True,
        )
        logger.info(f"Blog draft: {draft_path}")

    # Final summary
    logger.info(
        f"\n{'='*60}\n"
        f"  SCRAPE COMPLETE — {campaign}\n"
        f"  Posts:      {len(all_posts)}\n"
        f"  IOCs:       {len(all_iocs)}\n"
        f"  Techniques: {len(mitre_matches)}\n"
        f"{'='*60}"
    )


def cmd_extract(args, config):
    """Extract IOCs from an existing JSON archive."""
    from extractors.ioc_extractor import extract_iocs
    from extractors.mitre_mapper import map_techniques
    from outputs.csv_writer import write_ioc_csv
    from outputs.stix_writer import write_stix_bundle

    logger = logging.getLogger("extract")

    if not args.input or not os.path.exists(args.input):
        logger.error(f"Input file not found: {args.input}")
        return

    with open(args.input, "r") as f:
        archive = json.load(f)

    posts = archive.get("posts", [])
    campaign = archive.get("metadata", {}).get("campaign", "extract")

    all_iocs = []
    for post in posts:
        result = extract_iocs(
            post["content"],
            source=post.get("url", ""),
            timestamp=post.get("timestamp", ""),
        )
        all_iocs.extend(result.iocs)

    logger.info(f"Extracted {len(all_iocs)} IOCs from {len(posts)} posts")

    # Output
    output_dir = args.output or "./output/extracted"
    csv_path = write_ioc_csv(all_iocs, output_dir, campaign)
    stix_path = write_stix_bundle(all_iocs, output_dir, campaign)

    logger.info(f"CSV: {csv_path}")
    logger.info(f"STIX: {stix_path}")


def cmd_test(args, config):
    """Test connectivity to all configured platforms."""
    logger = logging.getLogger("test")
    scrapers = get_scrapers(config)

    for name, scraper in scrapers.items():
        try:
            result = scraper.test_connection()
            status = "OK" if result else "FAILED"
            logger.info(f"  {name:>12}: {status}")
        except Exception as e:
            logger.info(f"  {name:>12}: ERROR — {e}")


def cmd_search(args, config):
    """Search across platforms for a specific topic, extract IOCs and generate a research brief."""
    from extractors.ioc_extractor import extract_iocs
    from extractors.mitre_mapper import map_techniques
    from outputs.csv_writer import write_ioc_csv
    from outputs.stix_writer import write_stix_bundle
    from outputs.markdown_writer import write_summary
    from outputs.json_archive import write_archive

    logger = logging.getLogger("search")

    keywords = args.keywords
    if not keywords:
        logger.error("No keywords provided. Usage: python scraper.py search 'trivy' 'supply chain'")
        return

    campaign = args.campaign or "search-" + "-".join(kw.replace(" ", "_") for kw in keywords[:3])
    output_config = config.get("output", {})
    extraction_config = config.get("extraction", {})

    base_dir = Path(__file__).parent
    iocs_dir = base_dir / output_config.get("iocs_dir", "./output/iocs")
    blog_data_dir = base_dir / output_config.get("blog_data_dir", "./output/blog")
    drafts_dir = base_dir / output_config.get("drafts_dir", "./output/drafts")
    archive_dir = base_dir / output_config.get("archive_dir", "./output/archive")
    reports_dir = base_dir / output_config.get("reports_dir", "./output/reports")

    logger.info(f"Searching for: {keywords}")
    logger.info(f"Campaign: {campaign}")

    # Step 1: Search across platforms
    platforms = [args.platform] if args.platform else None
    scrapers = get_scrapers(config, platforms)

    if not scrapers:
        logger.error("No platforms configured. Check config.yaml")
        return

    all_posts = []
    for name, scraper in scrapers.items():
        logger.info(f"Searching {name}...")
        try:
            posts = scraper.search(keywords, limit=args.limit)
            logger.info(f"  → {len(posts)} matching posts from {name}")
            all_posts.extend(posts)
        except Exception as e:
            logger.error(f"  → Error searching {name}: {e}")

    if not all_posts:
        logger.warning("No results found. Try broader keywords or different platforms.")
        return

    logger.info(f"\nTotal matching posts: {len(all_posts)}")

    # Step 2: Archive
    archive_path = write_archive(all_posts, str(archive_dir), campaign)
    logger.info(f"Archive: {archive_path}")

    # Step 3: Extract IOCs
    all_iocs = []
    combined_text = ""
    ioc_types = extraction_config.get("ioc_types", None)

    for post in all_posts:
        result = extract_iocs(
            post.content,
            source=post.url or f"{post.platform}/@{post.author}",
            timestamp=post.timestamp,
            types=ioc_types,
        )
        all_iocs.extend(result.iocs)
        combined_text += post.content + "\n\n"

    # Deduplicate
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        key = (ioc.type, ioc.value)
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)
    all_iocs = unique_iocs

    logger.info(f"IOCs extracted: {len(all_iocs)}")

    # Step 4: MITRE mapping
    min_conf = extraction_config.get("mitre_min_confidence", "medium")
    mitre_matches = map_techniques(combined_text, min_confidence=min_conf)
    logger.info(f"MITRE techniques: {len(mitre_matches)}")

    # Step 5: Outputs
    if all_iocs:
        campaign_ioc_dir = iocs_dir / campaign
        csv_path = write_ioc_csv(all_iocs, str(campaign_ioc_dir), campaign)
        logger.info(f"IOC CSV: {csv_path}")

        stix_path = write_stix_bundle(all_iocs, str(campaign_ioc_dir), campaign)
        logger.info(f"STIX: {stix_path}")

        blog_csv_path = write_ioc_csv(all_iocs, str(blog_data_dir / campaign), campaign)
        logger.info(f"Blog CSV: {blog_csv_path}")

    # Summary report
    summary_path = write_summary(
        all_posts, all_iocs, mitre_matches,
        str(reports_dir), campaign,
    )
    logger.info(f"Report: {summary_path}")

    # Blog draft
    if args.draft:
        draft_path = write_summary(
            all_posts, all_iocs, mitre_matches,
            str(drafts_dir), campaign,
            as_blog_draft=True,
        )
        logger.info(f"Blog draft: {draft_path}")

    # Print quick results to terminal
    print(f"\n{'='*60}")
    print(f"  SEARCH RESULTS — {' + '.join(keywords)}")
    print(f"  Posts found:  {len(all_posts)}")
    print(f"  IOCs:         {len(all_iocs)}")
    print(f"  Techniques:   {len(mitre_matches)}")
    print(f"{'='*60}")

    if all_iocs:
        print(f"\n  Top IOCs:")
        for ioc in all_iocs[:15]:
            print(f"    [{ioc.type:>8}] {ioc.defanged}")
        if len(all_iocs) > 15:
            print(f"    ... and {len(all_iocs) - 15} more (see CSV)")

    if mitre_matches:
        print(f"\n  ATT&CK Techniques:")
        for m in mitre_matches[:10]:
            print(f"    {m.technique_id} — {m.technique_name} ({m.confidence})")

    if all_posts:
        print(f"\n  Top sources:")
        for post in sorted(all_posts, key=lambda p: sum(p.engagement.values()) if p.engagement else 0, reverse=True)[:5]:
            preview = post.content[:100].replace("\n", " ").strip()
            print(f"    @{post.author} ({post.platform}): {preview}...")
            if post.url:
                print(f"      → {post.url}")

    print(f"\n  Full report: {summary_path}")
    print(f"{'='*60}\n")


def cmd_report(args, config):
    """Generate a report from an existing archive."""
    from extractors.ioc_extractor import extract_iocs
    from extractors.mitre_mapper import map_techniques
    from outputs.markdown_writer import write_summary
    from scrapers.base import ScrapedPost

    logger = logging.getLogger("report")

    if not args.input or not os.path.exists(args.input):
        logger.error(f"Input file not found: {args.input}")
        return

    with open(args.input, "r") as f:
        archive = json.load(f)

    campaign = archive.get("metadata", {}).get("campaign", "report")
    posts = []
    all_iocs = []
    combined_text = ""

    for p in archive.get("posts", []):
        post = ScrapedPost(
            platform=p["platform"],
            author=p["author"],
            content=p["content"],
            url=p.get("url", ""),
            timestamp=p.get("timestamp", ""),
            engagement=p.get("engagement", {}),
        )
        posts.append(post)
        result = extract_iocs(post.content, source=post.url)
        all_iocs.extend(result.iocs)
        combined_text += post.content + "\n\n"

    mitre_matches = map_techniques(combined_text)
    output_dir = args.output or "./output/reports"

    path = write_summary(posts, all_iocs, mitre_matches, output_dir, campaign,
                         as_blog_draft=args.draft)
    logger.info(f"Report written: {path}")


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel Scraper — multi-platform security intel collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to config YAML (default: config.local.yaml or config.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scrape
    sp_scrape = subparsers.add_parser("scrape", help="Scrape platforms and extract intel")
    sp_scrape.add_argument("--platform", "-p", choices=["twitter", "telegram", "reddit", "linkedin", "tweetfeed", "threatfox"],
                           help="Scrape a single platform (default: all configured)")
    sp_scrape.add_argument("--limit", "-l", type=int, default=50,
                           help="Max posts per account (default: 50)")
    sp_scrape.add_argument("--campaign", help="Campaign name (overrides config)")
    sp_scrape.add_argument("--draft", action="store_true",
                           help="Also generate a Jekyll blog draft")

    # search
    sp_search = subparsers.add_parser("search", help="Search platforms for a specific topic")
    sp_search.add_argument("keywords", nargs="+",
                           help="Search keywords (e.g., 'trivy' 'supply chain attack')")
    sp_search.add_argument("--platform", "-p", choices=["twitter", "telegram", "reddit", "linkedin", "tweetfeed", "threatfox"],
                           help="Search a single platform (default: all configured)")
    sp_search.add_argument("--limit", "-l", type=int, default=30,
                           help="Max results per platform (default: 30)")
    sp_search.add_argument("--campaign", help="Campaign name for output files")
    sp_search.add_argument("--draft", action="store_true",
                           help="Also generate a Jekyll blog draft")

    # extract
    sp_extract = subparsers.add_parser("extract", help="Extract IOCs from an archive file")
    sp_extract.add_argument("--input", "-i", required=True, help="Path to JSON archive")
    sp_extract.add_argument("--output", "-o", help="Output directory")

    # test
    subparsers.add_parser("test", help="Test platform connections")

    # report
    sp_report = subparsers.add_parser("report", help="Generate report from archive")
    sp_report.add_argument("--input", "-i", required=True, help="Path to JSON archive")
    sp_report.add_argument("--output", "-o", help="Output directory")
    sp_report.add_argument("--draft", action="store_true", help="Format as blog draft")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = load_config(args.config)
    setup_logging(config)

    commands = {
        "scrape": cmd_scrape,
        "search": cmd_search,
        "extract": cmd_extract,
        "test": cmd_test,
        "report": cmd_report,
    }

    commands[args.command](args, config)


if __name__ == "__main__":
    main()
