"""
Markdown Summary Writer — generates a structured markdown report
from scraped posts, extracted IOCs, and MITRE mappings.

Output can be used directly as a blog draft or research note.
"""

import os
from datetime import datetime


def write_summary(
    posts: list,
    iocs: list,
    mitre_matches: list,
    output_path: str,
    campaign_name: str = "scrape",
    as_blog_draft: bool = False,
) -> str:
    """
    Write a markdown summary of the scrape results.

    Args:
        posts: List of ScrapedPost objects.
        iocs: List of IOC objects.
        mitre_matches: List of MitreMatch objects.
        output_path: Directory to write the file.
        campaign_name: Identifier for the run.
        as_blog_draft: If True, format with Jekyll front matter.

    Returns:
        Path to the written markdown file.
    """
    os.makedirs(output_path, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d")
    date_str = datetime.utcnow().strftime("%Y-%m-%d")

    if as_blog_draft:
        filename = f"{date_str}-{campaign_name}.md"
    else:
        filename = f"summary-{campaign_name}-{timestamp}.md"

    filepath = os.path.join(output_path, filename)

    lines = []

    # Jekyll front matter (if blog draft)
    if as_blog_draft:
        mitre_yaml = ""
        for m in mitre_matches:
            mitre_yaml += f"\n  - id: {m.technique_id}\n    name: {m.technique_name}"

        lines.extend([
            "---",
            f'title: "Threat Intel Digest — {campaign_name}"',
            f"date: {date_str}",
            'author: "Prakhar Gupta"',
            "category: threat-intelligence",
            "tags:",
            "  - threat-intel",
            "  - automated-scrape",
            f"  - {campaign_name}",
            f'tldr: "Automated threat intel digest: {len(posts)} posts scraped, '
            f'{len(iocs)} IOCs extracted, {len(mitre_matches)} ATT&CK techniques mapped."',
            f"mitre_techniques:{mitre_yaml}",
            f'ioc_campaign: "{campaign_name}"',
            "severity: medium",
            "---",
            "",
        ])

    # Header
    lines.extend([
        f"# Threat Intel Scrape Summary — {campaign_name}",
        "",
        f"**Date:** {date_str}  ",
        f"**Posts collected:** {len(posts)}  ",
        f"**IOCs extracted:** {len(iocs)}  ",
        f"**MITRE techniques:** {len(mitre_matches)}  ",
        "",
    ])

    # Platform breakdown
    platform_counts = {}
    for p in posts:
        platform_counts[p.platform] = platform_counts.get(p.platform, 0) + 1

    if platform_counts:
        lines.extend([
            "## Sources",
            "",
            "| Platform | Posts |",
            "|----------|-------|",
        ])
        for platform, count in sorted(platform_counts.items()):
            lines.append(f"| {platform} | {count} |")
        lines.append("")

    # MITRE ATT&CK mappings
    if mitre_matches:
        lines.extend([
            "## MITRE ATT&CK Techniques Observed",
            "",
            "| Technique | Name | Tactic | Confidence |",
            "|-----------|------|--------|------------|",
        ])
        for m in mitre_matches:
            link = f"[{m.technique_id}](https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')})"
            lines.append(f"| {link} | {m.technique_name} | {m.tactic} | {m.confidence} |")
        lines.append("")

    # IOC summary
    if iocs:
        ioc_by_type = {}
        for ioc in iocs:
            ioc_by_type.setdefault(ioc.type, []).append(ioc)

        lines.extend([
            "## Indicators of Compromise",
            "",
        ])

        for ioc_type, type_iocs in sorted(ioc_by_type.items()):
            lines.append(f"### {ioc_type.upper()} ({len(type_iocs)})")
            lines.append("")
            lines.append("```")
            for ioc in type_iocs[:20]:  # Cap at 20 per type
                lines.append(ioc.defanged)
            if len(type_iocs) > 20:
                lines.append(f"... and {len(type_iocs) - 20} more (see CSV)")
            lines.append("```")
            lines.append("")

    # Key posts (top engagement)
    security_posts = [p for p in posts if p.content.strip()]
    if security_posts:
        # Sort by engagement if available
        def engagement_score(p):
            e = p.engagement
            return (
                e.get("likes", 0) + e.get("score", 0)
                + e.get("retweets", 0) * 2
                + e.get("comments", 0)
                + e.get("views", 0) / 1000
            )

        top_posts = sorted(security_posts, key=engagement_score, reverse=True)[:10]

        lines.extend([
            "## Notable Posts",
            "",
        ])

        for i, post in enumerate(top_posts, 1):
            preview = post.content[:300].replace("\n", " ").strip()
            if len(post.content) > 300:
                preview += "..."

            lines.append(f"### {i}. @{post.author} ({post.platform})")
            lines.append("")
            if post.url:
                lines.append(f"[Source]({post.url})")
                lines.append("")
            lines.append(f"> {preview}")
            lines.append("")

    # Footer
    lines.extend([
        "---",
        "",
        f"*Generated by threat-intel-scraper at {datetime.utcnow().isoformat()}Z*",
    ])

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filepath
