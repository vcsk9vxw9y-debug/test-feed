import calendar
import html
import re
import sqlite3
from datetime import datetime, timezone

import bleach
import feedparser
import requests

from classifier import classify_article


def clean_summary(raw):
    """Strip all HTML from a feed summary, decode entities, normalize whitespace.

    Feed summaries from third-party sources routinely include tracking pixels,
    <script> tags, style blocks, and malformed markup. We store plain text
    only — the frontend can present it safely without HTML escaping gymnastics.
    """
    if not raw:
        return ""
    stripped = bleach.clean(raw, tags=[], attributes={}, strip=True)
    decoded = html.unescape(stripped)
    return re.sub(r"\s+", " ", decoded).strip()


def normalize_published_date(entry):
    """Return an ISO 8601 UTC string for an RSS entry's publish date.

    Feeds publish dates in many formats (RFC 2822, RFC 3339, bespoke).
    ``feedparser`` normalizes them into a ``published_parsed`` struct_time
    expressed in UTC — we use ``calendar.timegm`` (UTC-aware) rather than
    ``time.mktime`` (local-time-aware) to avoid a TZ-offset shift on the
    host. Falls back to ``updated_parsed`` and finally to "now" if nothing
    usable is provided.
    """
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if not parsed:
            continue
        try:
            dt = datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc)
            return dt.isoformat()
        except (TypeError, ValueError, OverflowError):
            continue
    return datetime.now(timezone.utc).isoformat()

# FEEDS is the committed trust anchor for the Confidence signal.
# Every entry carries a source_tier (1/2/3) and a reason; the derivation
# from tier -> HIGH/MEDIUM/LOW is in confidence.py. A source that lands
# here without a tier falls back to LOW at runtime (fail-secure per Aegis B1).
# Re-tiering is a PR — no runtime override, no admin endpoint.
FEEDS = [
    # --- Core News ---
    {
        "url": "https://krebsonsecurity.com/feed/",
        "name": "Krebs on Security",
        "source_tier": 2,
        "reason": "Established independent investigative security journalism. High rigor, frequently breaks news.",
    },
    {
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "name": "The Hacker News",
        "source_tier": 2,
        "reason": "Established security journalism. Caveat: SEO-heavy and rewrite-reliant — often reframes other sources rather than primary reporting.",
    },
    {
        "url": "https://www.bleepingcomputer.com/feed/",
        "name": "Bleeping Computer",
        "source_tier": 2,
        "reason": "Established technical security journalism. Fast, technically literate, breaks news on ransomware and malware.",
    },
    {
        "url": "https://www.darkreading.com/rss.xml",
        "name": "Dark Reading",
        "source_tier": 2,
        "reason": "Established security journalism, enterprise-focused analysis.",
    },
    {
        "url": "https://feeds.feedburner.com/securityweek",
        "name": "SecurityWeek",
        "source_tier": 2,
        "reason": "Established security journalism with consistent editorial quality.",
    },
    {
        "url": "https://therecord.media/feed",
        "name": "The Record",
        "source_tier": 2,
        "reason": "Established security journalism (Recorded Future-owned), strong on nation-state reporting.",
    },
    # --- Government & Advisories ---
    {
        "url": "https://www.cisa.gov/cybersecurity-advisories/advisories.xml",
        "name": "CISA Alerts",
        "source_tier": 1,
        "reason": "US government cyber defense authority. Advisories are official and operationally authoritative.",
    },
    {
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "name": "US-CERT Alerts",
        "source_tier": 1,
        "reason": "US government CERT, authoritative advisories, operational directives.",
    },
    {
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        "name": "NCSC UK",
        "source_tier": 1,
        "reason": "UK government CERT, authoritative advisories for UK & allied operators.",
    },
    # --- Vendor Threat Intelligence ---
    {
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "name": "Unit42 Palo Alto",
        "source_tier": 1,
        "reason": "Top-tier threat intelligence research team with consistent primary analysis.",
    },
    {
        "url": "https://www.crowdstrike.com/blog/feed/",
        "name": "CrowdStrike Blog",
        "source_tier": 1,
        "reason": "Top-tier threat intelligence research. Caveat: mixed with commercial marketing, but the threat intel output itself is authoritative.",
    },
    {
        "url": "https://cloud.google.com/blog/topics/threat-intelligence/rss.xml",
        "name": "Google Mandiant",
        "source_tier": 1,
        "reason": "Industry-leading primary threat intelligence research. Nation-state attribution and campaign tracking.",
    },
    {
        "url": "http://feeds.feedburner.com/feedburner/Talos",
        "name": "Cisco Talos",
        "source_tier": 1,
        "reason": "Top-tier threat intelligence research with strong malware analysis track record.",
    },
    {
        "url": "https://research.checkpoint.com/feed/",
        "name": "Check Point Research",
        "source_tier": 2,
        "reason": "Vendor threat intelligence research. Good primary work but commercial context.",
    },
    {
        "url": "https://www.sentinelone.com/blog/feed/",
        "name": "SentinelOne",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Vendor threat intelligence research. Caveat: already filtered for noise via filter_uncategorized.",
    },
    {
        "url": "https://www.welivesecurity.com/feed/",
        "name": "ESET WeLiveSecurity",
        "source_tier": 2,
        "reason": "Vendor threat intelligence research, consistent technical malware reports.",
    },
    {
        "url": "https://msrc.microsoft.com/blog/feed/",
        "name": "Microsoft MSRC",
        "filter_uncategorized": True,
        "source_tier": 1,
        "reason": "First-party vendor PSIRT for Microsoft products. When they say something is exploited, it is.",
    },
    {
        "url": "https://www.malwarebytes.com/blog/feed/",
        "name": "Malwarebytes Labs",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Vendor threat intelligence research, consumer-threat focused.",
    },
    {
        "url": "https://www.recordedfuture.com/feed",
        "name": "Recorded Future",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Threat intelligence firm research. Caveat: commercial framing; quality of output is high.",
    },
    # --- Security Research ---
    {
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "name": "Google Project Zero",
        "source_tier": 1,
        "reason": "Gold-standard primary vulnerability research. Detailed, reproducible, responsibly disclosed.",
    },
    {
        "url": "https://security.googleblog.com/feeds/posts/default",
        "name": "Google Security Blog",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Mixed Google product security + primary research. When the content is research, it's authoritative; the feed is not pure-signal.",
    },
    {
        "url": "https://labs.watchtowr.com/rss/",
        "name": "watchTowr Labs",
        "filter_uncategorized": True,
        "source_tier": 1,
        "reason": "High-quality primary vulnerability research with fast disclosure cadence. Quality exception — newer brand, authoritative output.",
    },
    {
        "url": "https://www.zerodayinitiative.com/blog?format=rss",
        "name": "Zero Day Initiative",
        "source_tier": 1,
        "reason": "Authoritative vulnerability disclosure program, coordinates with vendors.",
    },
    {
        "url": "https://github.blog/tag/github-security-lab/feed/",
        "name": "GitHub Security Lab",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Primary vulnerability research focused on open-source software ecosystems.",
    },
    {
        "url": "https://portswigger.net/research/rss",
        "name": "PortSwigger Research",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Primary web application security research from the makers of Burp Suite. Niche-authoritative.",
    },
    {
        "url": "https://rhinosecuritylabs.com/feed/",
        "name": "Rhino Security Labs",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Primary research from smaller consulting firm, solid technical write-ups.",
    },
    {
        "url": "https://samcurry.net/api/feed.rss",
        "name": "Sam Curry",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Individual researcher with exceptional track record (car-hacking series, university hacks). Single-author caveat applies but quality is high.",
    },
    {
        "url": "https://www.dragos.com/blog/feed/",
        "name": "Dragos",
        "filter_uncategorized": True,
        "source_tier": 1,
        "reason": "Authoritative primary research in ICS/OT threat intelligence. The authority in that niche.",
    },
    {
        "url": "https://www.schneier.com/feed/atom",
        "name": "Schneier on Security",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Authoritative expert commentary and link blog. Analysis, not primary research.",
    },
    # --- AI Security ---
    {
        "url": "https://embracethered.com/blog/index.xml",
        "name": "Embrace The Red",
        "filter_uncategorized": True,
        "source_tier": 3,
        "reason": "Single-author blog on AI/LLM security. Quality is good, but single source in an emerging niche — corroboration matters.",
    },
    # --- Community ---
    {
        "url": "https://isc.sans.edu/rssfeed.xml",
        "name": "SANS Internet Storm Center",
        "filter_uncategorized": True,
        "source_tier": 2,
        "reason": "Handler diaries — expert practitioner analysis, not primary research but high-quality synthesis.",
    },
    {
        "url": "https://www.reddit.com/r/netsec/.rss",
        "name": "Reddit r/netsec",
        "filter_uncategorized": True,
        "source_tier": 3,
        "reason": "User-submitted link aggregator, no editorial review. Signal varies wildly by submitter.",
    },
    {
        "url": "https://www.reddit.com/r/cybersecurity/.rss",
        "name": "Reddit r/cybersecurity",
        "filter_uncategorized": True,
        "source_tier": 3,
        "reason": "User-submitted, mixed quality, no editorial review.",
    },
    {
        "url": "https://www.reddit.com/r/malware/.rss",
        "name": "Reddit r/malware",
        "filter_uncategorized": True,
        "source_tier": 3,
        "reason": "User-submitted, mixed quality, no editorial review.",
    },
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}


def fetch_all_feeds(db_path):
    now = datetime.now(timezone.utc)
    print(f"[{now}] Starting feed fetch...")
    total_new = 0

    with sqlite3.connect(db_path) as conn:
        for feed in FEEDS:
            try:
                print(f"  Fetching {feed['name']}...")

                response = requests.get(feed["url"], headers=HEADERS, timeout=15, allow_redirects=False)
                print(f"    HTTP status: {response.status_code}")

                if response.status_code != 200:
                    print(f"    Skipping - bad status code")
                    continue

                parsed = feedparser.parse(response.content)

                if parsed.bozo:
                    print(f"    Feed parse warning: {parsed.bozo_exception}")

                entries = parsed.entries
                print(f"    Found {len(entries)} entries")

                new_count = 0
                for entry in entries:
                    url = entry.get("link", "")
                    if not url:
                        continue

                    existing = conn.execute(
                        "SELECT id FROM articles WHERE url = ?", (url,)
                    ).fetchone()
                    if existing:
                        continue

                    title = entry.get("title", "No Title")
                    summary = clean_summary(entry.get("summary", ""))
                    published = normalize_published_date(entry)
                    # Classify against sanitized text so keyword patterns
                    # aren't distracted by HTML residue or entities.
                    category = classify_article(title, summary)

                    # Skip uncategorized articles from noisy feeds (e.g. Reddit)
                    if feed.get("filter_uncategorized") and category == "Uncategorized":
                        continue

                    result = conn.execute(
                        """INSERT OR IGNORE INTO articles
                           (title, summary, url, published_date, source_name, category)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (title, summary, url, published, feed["name"], category)
                    )
                    if result.rowcount > 0:
                        conn.execute(
                            "UPDATE stats SET value = value + 1 WHERE key = 'total_processed'"
                        )
                    new_count += 1

                conn.commit()
                total_new += new_count
                print(f"    Saved {new_count} new articles from {feed['name']}")

            except Exception as e:
                print(f"    ERROR fetching {feed['name']}: {type(e).__name__}: {e}")
                continue

    print(f"[{datetime.now(timezone.utc)}] Feed fetch complete. Total new articles: {total_new}")