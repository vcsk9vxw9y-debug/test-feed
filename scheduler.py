import calendar
import html
import os
import re
import sqlite3
from datetime import datetime, timezone

import bleach
import feedparser
import requests
import yaml

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
        "url": "https://www.securityweek.com/feed/",
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
    {
        "url": "https://decipher.sc/feed/",
        "name": "Decipher",
        "source_tier": 2,
        "reason": "Duo Security / Cisco-owned security journalism (Dennis Fisher, Lindsey O'Donnell-Welch). Primary reporting, no marketing funnel. Peer-quality with Dark Reading / The Record.",
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
        "url": "https://www.crowdstrike.com/en-us/blog/feed",
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
        "url": "https://www.welivesecurity.com/en/rss/feed/",
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
        "url": "https://www.malwarebytes.com/blog/feed/index.xml",
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
        "url": "https://projectzero.google/feed.xml",
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
        "url": "https://www.schneier.com/feed/atom/",
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


# --- Phrase exclusion filter -----------------------------------------------
# Operator-maintained phrase blocklist in config/exclusions.yml. Dropped at
# ingest (scheduler.fetch_all_feeds) and pruned from the DB at startup
# (app.init_db). Committed trust anchor — no runtime mutation.

EXCLUSIONS_PATH = os.path.join(os.path.dirname(__file__), "config", "exclusions.yml")


def load_exclusions(path=EXCLUSIONS_PATH):
    """Load per-source phrase blocklist from committed YAML.

    Schema: ``{<source_name>: [<phrase>, ...], ...}``
      - Keys must be ``str`` (match scheduler.FEEDS[*].name exactly).
      - Values must be ``list`` of non-empty ``str``.
      - Anything else is silently dropped during shape validation — we
        never raise from here; the caller must be able to trust the
        return value without a try/except.

    Fail-closed semantics: a missing file, malformed YAML, non-dict root,
    or any I/O error resolves to ``{}``. No exclusions means every article
    passes through. This is intentionally permissive: an attacker with
    repo write access could already delete the file entirely, so "empty
    dict on parse failure" doesn't create new attack surface. Operators
    who want tighter semantics can run the integrity test below.

    Phrases are lowercased once at load time so ``_is_excluded`` doesn't
    re-normalize per article.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except (FileNotFoundError, PermissionError, OSError, yaml.YAMLError):
        return {}

    if not isinstance(raw, dict):
        return {}

    clean = {}
    for source_name, phrases in raw.items():
        if not isinstance(source_name, str) or not source_name.strip():
            continue
        if not isinstance(phrases, list):
            continue
        valid = [
            p.lower()
            for p in phrases
            if isinstance(p, str) and p.strip()
        ]
        if valid:
            clean[source_name] = valid
    return clean


# Loaded once at import. Re-loads require a deploy — same pattern as FEEDS.
EXCLUSIONS = load_exclusions()


def _is_excluded(source_name, title, summary):
    """Return True if the article should be dropped per exclusions.yml.

    Case-insensitive substring match: phrases are lowercased at load
    time; title+summary are lowercased per call. Plain substring (not
    regex) to avoid ReDoS and keep the operator mental model simple —
    if the phrase appears anywhere in the text, the article is dropped.

    An unknown source or an empty phrase list returns False (pass
    through). ``None`` title/summary are coerced to empty strings.
    """
    phrases = EXCLUSIONS.get(source_name)
    if not phrases:
        return False
    haystack = f"{title or ''} {summary or ''}".lower()
    return any(p in haystack for p in phrases)


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

                    # Phrase exclusion (post-sanitize, pre-classify): drop
                    # articles whose source has a committed phrase blocklist
                    # and whose title/summary matches. Runs BEFORE the
                    # classifier so we don't burn cycles on content we're
                    # going to discard anyway. See config/exclusions.yml.
                    if _is_excluded(feed["name"], title, summary):
                        print(f"    Skipping (excluded phrase): {title[:80]}")
                        continue

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


# --- Reddit deletion prune -------------------------------------------------
# Reddit posts can be removed upstream by the author, a moderator, or Reddit
# admins (TOS-violation actions like `anti_evil_ops`) AFTER we've ingested
# them. We're a Tier 3 / LOW-confidence surface for Reddit to begin with —
# once upstream has removed the post, we remove it too, to avoid being the
# last place a doxxing / misinformation / TOS-violating post is still live.
#
# Design (per user approval 2026-04-19):
#   * Runs every scheduler tick, after fetch_all_feeds.
#   * Only checks articles with source_name LIKE '%reddit%' (case-insensitive).
#   * Skips articles younger than 4 hours (give upstream one tick to settle).
#   * Orders by `last_reddit_check_at ASC NULLS FIRST` so fresh posts are
#     checked first, then least-recently-checked. DB rotates through itself.
#   * Hard-caps at 200 articles per tick -> bounded runtime even at scale.
#   * SSRF defense: we do NOT fetch the URL stored in articles.url. We extract
#     the post ID with a strict regex ([a-z0-9]{4,10}) and reconstruct the
#     JSON URL against www.reddit.com ourselves. The DB URL is the trust
#     boundary; we never trust it for egress.
#   * Fails OPEN on transient errors (timeout, 5xx, 403, JSON parse issues)
#     so a flaky Reddit doesn't nuke the DB. Fails CLOSED (i.e. deletes)
#     only on definitive signals: HTTP 404, removed_by_category in the known
#     set, or [deleted] author+body pair.

REDDIT_JSON_HOST = "https://www.reddit.com"
REDDIT_POST_ID_RE = re.compile(r"/comments/([a-z0-9]{4,10})(?:/|$|\?)", re.IGNORECASE)
REDDIT_BATCH_LIMIT = 200
REDDIT_MIN_AGE_HOURS = 4
REDDIT_REQUEST_TIMEOUT = 5  # seconds per request
REDDIT_REQUEST_SPACING = 1.0  # seconds between requests (stay under 60/min)

# Reddit's `removed_by_category` values that indicate the post is GONE from
# the user's point of view. "reddit" and "anti_evil_ops" are admin / TOS
# actions — those are the ones we most urgently want out of our DB.
REDDIT_REMOVED_CATEGORIES = frozenset({
    "deleted",           # author deleted the post
    "moderator",         # mod removed
    "automod_filtered",  # automod caught (typically spam)
    "anti_evil_ops",     # Reddit admin: serious TOS violation
    "community_ops",     # Reddit admin: community action
    "reddit",            # Reddit admin: generic
    "copyright_takedown",
    "author",            # alternate encoding of author-deleted
})

# Respectful UA — identifies us so Reddit can throttle identifiably if we
# misbehave, rather than blanket-blocking all of Threat-Feed.
REDDIT_CHECK_HEADERS = {
    "User-Agent": "Threat-Feed/1.0 (+https://threat-feed.up.railway.app)",
    "Accept": "application/json",
}


def _extract_reddit_post_id(url):
    """Extract the base36 post ID from a Reddit URL, or return None.

    We deliberately do NOT return or fetch the input URL. The caller builds
    a fresh URL against www.reddit.com from the returned ID — this makes
    the egress path immune to a poisoned DB row.
    """
    if not url or not isinstance(url, str):
        return None
    m = REDDIT_POST_ID_RE.search(url)
    return m.group(1).lower() if m else None


def _classify_reddit_response(status_code, payload):
    """Decide whether a Reddit JSON response indicates a removed post.

    Returns ('delete', reason) to hard-delete, or (None, reason) to leave
    the row alone (fail-open on ambiguity).

    `payload` is the parsed JSON body or None if the body wasn't valid JSON.
    """
    # Definitive deletion signals first.
    if status_code == 404:
        return ("delete", "http_404")

    # Anything other than 200 is treated as transient. 403 (private sub,
    # rate-limited) is deliberately fail-open — private today, public
    # tomorrow; we don't want a rate-limit episode to wipe the feed.
    if status_code != 200:
        return (None, f"transient_status_{status_code}")

    if payload is None:
        return (None, "empty_or_invalid_json")

    # Reddit /comments/<id>.json returns a 2-element list: [listing, comments].
    # We want the first listing's first child's data. Require the exact shape
    # we expect — any deviation is schema drift, not a deletion signal. This
    # matters: falling back to default-empty on a missing key would mass-delete
    # the whole Reddit corpus the day Reddit changes their API envelope.
    try:
        listing = payload[0] if isinstance(payload, list) else payload
        if not isinstance(listing, dict) or "data" not in listing:
            return (None, "unexpected_shape")
        listing_data = listing["data"]
        if not isinstance(listing_data, dict) or "children" not in listing_data:
            return (None, "unexpected_shape")
        children = listing_data["children"]
        if not isinstance(children, list):
            return (None, "unexpected_shape")
        if not children:
            # Post scrubbed off the listing entirely — treat as deleted.
            # (Empty children is an explicit response shape, not schema drift.)
            return ("delete", "empty_listing")
        first_child = children[0]
        if not isinstance(first_child, dict) or "data" not in first_child:
            return (None, "unexpected_shape")
        data = first_child["data"]
        if not isinstance(data, dict):
            return (None, "unexpected_shape")
    except (AttributeError, IndexError, KeyError, TypeError):
        return (None, "unexpected_shape")

    removed = data.get("removed_by_category")
    if removed in REDDIT_REMOVED_CATEGORIES:
        return ("delete", f"removed_by_category:{removed}")

    author = data.get("author")
    selftext = data.get("selftext")
    if author == "[deleted]" and selftext in ("[deleted]", "[removed]"):
        return ("delete", "author_and_body_deleted")

    return (None, "live")


def _check_one_reddit_post(post_id):
    """Hit Reddit's JSON endpoint for a single post ID. Returns a decision.

    The URL is constructed against the trusted REDDIT_JSON_HOST — the
    post_id is the ONLY attacker-influenced input, and the regex that
    produced it guarantees it is `[a-z0-9]{4,10}` (so no path traversal,
    no URL-injection, no scheme override).

    Never raises: all exceptions fail-open with (None, reason).
    """
    target = f"{REDDIT_JSON_HOST}/comments/{post_id}.json"
    try:
        resp = requests.get(
            target,
            headers=REDDIT_CHECK_HEADERS,
            timeout=REDDIT_REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as e:
        return (None, f"request_error:{type(e).__name__}")

    payload = None
    if resp.status_code == 200:
        try:
            payload = resp.json()
        except ValueError:
            pass

    return _classify_reddit_response(resp.status_code, payload)


def prune_deleted_reddit_posts(db_path, now=None, sleep=None):
    """Remove Reddit articles whose upstream posts are deleted/removed.

    Parameters:
        db_path: SQLite path (same DB as fetch_all_feeds).
        now:     Optional datetime override for tests.
        sleep:   Optional sleep function override for tests (default: time.sleep).

    Returns a dict {checked, deleted, errors} for logging/observability.
    Fails open on any per-post error so one bad row never blocks the batch.
    """
    import time as _time
    if sleep is None:
        sleep = _time.sleep
    if now is None:
        now = datetime.now(timezone.utc)

    cutoff_iso = now.isoformat()

    checked = deleted = errors = 0
    conn = sqlite3.connect(db_path)
    try:
        # Candidates: Reddit source, at least 4h old, ordered so never-checked
        # rows come first, then oldest-checked. Batch-capped at 200/tick.
        rows = conn.execute(
            """
            SELECT id, url FROM articles
            WHERE LOWER(source_name) LIKE '%reddit%'
              AND datetime(COALESCE(published_date, created_at))
                  <= datetime(?, ?)
            ORDER BY last_reddit_check_at ASC NULLS FIRST,
                     COALESCE(published_date, created_at) DESC
            LIMIT ?
            """,
            (cutoff_iso, f"-{REDDIT_MIN_AGE_HOURS} hours", REDDIT_BATCH_LIMIT),
        ).fetchall()

        for idx, (article_id, url) in enumerate(rows):
            # Spacing between requests — skip before the VERY first call so
            # a single-item batch completes instantly.
            if idx > 0:
                sleep(REDDIT_REQUEST_SPACING)

            post_id = _extract_reddit_post_id(url)
            if not post_id:
                # Can't extract an ID — not a post-shaped Reddit URL (could be
                # a subreddit page, old.reddit.com variation with unusual
                # format, or something we don't recognize). Skip without
                # recording a check, so if the URL format is fixed later
                # we still process it.
                errors += 1
                continue

            decision, reason = _check_one_reddit_post(post_id)
            checked += 1

            if decision == "delete":
                conn.execute("DELETE FROM articles WHERE id = ?", (article_id,))
                deleted += 1
                print(f"    [reddit-prune] deleted id={article_id} reason={reason}")
            else:
                conn.execute(
                    "UPDATE articles SET last_reddit_check_at = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(), article_id),
                )

        conn.commit()
    finally:
        conn.close()

    print(
        f"[reddit-prune] checked={checked} deleted={deleted} errors={errors}"
    )
    return {"checked": checked, "deleted": deleted, "errors": errors}

    print(f"[{datetime.now(timezone.utc)}] Feed fetch complete. Total new articles: {total_new}")