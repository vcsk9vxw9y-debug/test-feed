import sqlite3
import feedparser
import requests
from datetime import datetime, timezone
from classifier import classify_article

FEEDS = [
    # --- Core News ---
    {"url": "https://krebsonsecurity.com/feed/", "name": "Krebs on Security"},
    {"url": "https://feeds.feedburner.com/TheHackersNews", "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/", "name": "Bleeping Computer"},
    {"url": "https://www.darkreading.com/rss.xml", "name": "Dark Reading"},
    {"url": "https://feeds.feedburner.com/securityweek", "name": "SecurityWeek"},
    {"url": "https://therecord.media/feed", "name": "The Record"},
    # --- Government & Advisories ---
    {"url": "https://www.cisa.gov/cybersecurity-advisories/advisories.xml", "name": "CISA Alerts"},
    {"url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "name": "US-CERT Alerts"},
    {"url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "name": "NCSC UK"},
    # --- Vendor Threat Intelligence ---
    {"url": "https://unit42.paloaltonetworks.com/feed/", "name": "Unit42 Palo Alto"},
    {"url": "https://www.crowdstrike.com/blog/feed/", "name": "CrowdStrike Blog"},
    {"url": "https://cloud.google.com/blog/topics/threat-intelligence/rss.xml", "name": "Google Mandiant"},
    {"url": "http://feeds.feedburner.com/feedburner/Talos", "name": "Cisco Talos"},
    {"url": "https://research.checkpoint.com/feed/", "name": "Check Point Research"},
    {"url": "https://www.sentinelone.com/blog/feed/", "name": "SentinelOne", "filter_uncategorized": True},
    {"url": "https://www.welivesecurity.com/feed/", "name": "ESET WeLiveSecurity"},
    {"url": "https://msrc.microsoft.com/blog/feed/", "name": "Microsoft MSRC", "filter_uncategorized": True},
    {"url": "https://www.malwarebytes.com/blog/feed/", "name": "Malwarebytes Labs", "filter_uncategorized": True},
    {"url": "https://www.recordedfuture.com/feed", "name": "Recorded Future", "filter_uncategorized": True},
    # --- Security Research ---
    {"url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "name": "Google Project Zero"},
    {"url": "https://security.googleblog.com/feeds/posts/default", "name": "Google Security Blog", "filter_uncategorized": True},
    {"url": "https://labs.watchtowr.com/rss/", "name": "watchTowr Labs", "filter_uncategorized": True},
    {"url": "https://www.zerodayinitiative.com/blog?format=rss", "name": "Zero Day Initiative"},
    {"url": "https://github.blog/tag/github-security-lab/feed/", "name": "GitHub Security Lab", "filter_uncategorized": True},
    {"url": "https://portswigger.net/research/rss", "name": "PortSwigger Research", "filter_uncategorized": True},
    {"url": "https://rhinosecuritylabs.com/feed/", "name": "Rhino Security Labs", "filter_uncategorized": True},
    {"url": "https://samcurry.net/api/feed.rss", "name": "Sam Curry", "filter_uncategorized": True},
    {"url": "https://www.dragos.com/blog/feed/", "name": "Dragos", "filter_uncategorized": True},
    {"url": "https://www.schneier.com/feed/atom", "name": "Schneier on Security", "filter_uncategorized": True},
    # --- AI Security ---
    {"url": "https://embracethered.com/blog/index.xml", "name": "Embrace The Red", "filter_uncategorized": True},
    # --- Community ---
    {"url": "https://isc.sans.edu/rssfeed.xml", "name": "SANS Internet Storm Center", "filter_uncategorized": True},
    {"url": "https://www.reddit.com/r/netsec/.rss", "name": "Reddit r/netsec", "filter_uncategorized": True},
    {"url": "https://www.reddit.com/r/cybersecurity/.rss", "name": "Reddit r/cybersecurity", "filter_uncategorized": True},
    {"url": "https://www.reddit.com/r/malware/.rss", "name": "Reddit r/malware", "filter_uncategorized": True},
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
                    summary = entry.get("summary", "")
                    published = entry.get("published", datetime.now(timezone.utc).isoformat())
                    category = classify_article(title, summary)

                    # Skip uncategorized articles from noisy feeds (e.g. Reddit)
                    if feed.get("filter_uncategorized") and category == "Uncategorized":
                        continue

                    conn.execute(
                        """INSERT OR IGNORE INTO articles
                           (title, summary, url, published_date, source_name, category)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (title, summary, url, published, feed["name"], category)
                    )
                    new_count += 1

                conn.commit()
                total_new += new_count
                print(f"    Saved {new_count} new articles from {feed['name']}")

            except Exception as e:
                print(f"    ERROR fetching {feed['name']}: {type(e).__name__}: {e}")
                continue

    print(f"[{datetime.now(timezone.utc)}] Feed fetch complete. Total new articles: {total_new}")