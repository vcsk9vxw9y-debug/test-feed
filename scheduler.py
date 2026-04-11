import sqlite3
import feedparser
import requests
from datetime import datetime
from classifier import classify_article

FEEDS = [
    # --- Core Sources ---
    {"url": "https://krebsonsecurity.com/feed/", "name": "Krebs on Security"},
    {"url": "https://feeds.feedburner.com/TheHackersNews", "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/", "name": "Bleeping Computer"},
    {"url": "https://www.cisa.gov/cybersecurity-advisories/advisories.xml", "name": "CISA Alerts"},
    {"url": "https://www.darkreading.com/rss.xml", "name": "Dark Reading"},
    {"url": "https://www.recordedfuture.com/feed", "name": "Recorded Future"},
    {"url": "https://www.schneier.com/feed/atom", "name": "Schneier on Security"},
    {"url": "https://feeds.feedburner.com/securityweek", "name": "SecurityWeek"},
    {"url": "https://unit42.paloaltonetworks.com/feed/", "name": "Unit42 Palo Alto"},
    {"url": "https://www.malwarebytes.com/blog/feed/", "name": "Malwarebytes Labs"},
    # --- v2: Research & Threat Intel ---
    {"url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "name": "Google Project Zero"},
    {"url": "https://isc.sans.edu/rssfeed.xml", "name": "SANS Internet Storm Center"},
    {"url": "https://www.crowdstrike.com/blog/feed/", "name": "CrowdStrike Blog"},
    {"url": "https://cloud.google.com/blog/topics/threat-intelligence/rss.xml", "name": "Google Mandiant"},
    {"url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "name": "NVD CVE Feed"},
    {"url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "name": "US-CERT Alerts"},
    # --- v2: Reddit Community Feeds ---
    {"url": "https://www.reddit.com/r/netsec/.rss", "name": "Reddit r/netsec"},
    {"url": "https://www.reddit.com/r/cybersecurity/.rss", "name": "Reddit r/cybersecurity"},
    {"url": "https://www.reddit.com/r/malware/.rss", "name": "Reddit r/malware"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}


def fetch_all_feeds(db_path):
    print(f"[{datetime.now()}] Starting feed fetch...")
    conn = sqlite3.connect(db_path)
    total_new = 0

    for feed in FEEDS:
        try:
            print(f"  Fetching {feed['name']}...")

            response = requests.get(feed["url"], headers=HEADERS, timeout=15)
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
                published = entry.get("published", str(datetime.now()))
                category = classify_article(title, summary)

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

    conn.close()
    print(f"[{datetime.now()}] Feed fetch complete. Total new articles: {total_new}")