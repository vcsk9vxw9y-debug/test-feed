import atexit
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape

import yaml
from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from classifier import classify_article
from confidence import build_source_info_index, resolve_confidence, UNSET
from scheduler import EXCLUSIONS, FEEDS, fetch_all_feeds, prune_deleted_reddit_posts

TOP_STORY_PATH = os.path.join(os.path.dirname(__file__), "config", "top_story.yml")
TOP_STORY_REQUIRED = ("title", "summary", "url", "source_name", "published_at")

app = Flask(__name__)

# Use Railway's persistent volume when available, otherwise local
DB_PATH = "/data/testfeed.db" if os.path.exists("/data") else "./testfeed.db"

# ---- Rate Limiting ----
# memory:// is correct for single-worker deployments.
# If workers > 1, replace with a Redis URI.
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["120 per minute"],  # Safety net for any undecorated route
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _run_reclassify_migration(conn, name):
    """One-way re-classification of Uncategorized rows, guarded by the
    ``migrations`` table.

    If the migration has already run, returns immediately. Otherwise,
    re-classifies every row currently labeled Uncategorized. Only promotes
    — a row whose new classification is still Uncategorized is left alone.
    Never demotes a row that has already been assigned a real category.

    The guarantee that matters: running any of these migrations repeatedly
    is a no-op (the `migrations` table tracks completion), and they can be
    safely chained — v1 -> v2 -> v3 on a fresh DB produces the same end
    state as running just v3 after v1 and v2 have already completed.

    Args:
        conn: Open sqlite3 connection (will be committed by the caller).
        name: Migration name, used as the primary key in `migrations`.
    """
    already_ran = conn.execute(
        "SELECT 1 FROM migrations WHERE name = ?", (name,)
    ).fetchone()
    if already_ran:
        return

    rows = conn.execute(
        "SELECT id, title, summary FROM articles WHERE category = 'Uncategorized'"
    ).fetchall()
    promoted = 0
    for row in rows:
        new_category = classify_article(row["title"], row["summary"])
        if new_category != "Uncategorized":
            conn.execute(
                "UPDATE articles SET category = ? WHERE id = ?",
                (new_category, row["id"]),
            )
            promoted += 1
    print(f"[{name}] promoted {promoted} articles")
    conn.execute(
        "INSERT INTO migrations (name, run_at) VALUES (?, ?)",
        (name, datetime.now(timezone.utc).isoformat()),
    )


def init_db():
    conn = get_db()
    try:
        # WAL mode: allows concurrent readers during background writes
        # (feed fetches). Sticky per-database — survives restarts once set.
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                summary TEXT,
                url TEXT UNIQUE NOT NULL,
                published_date TEXT,
                source_name TEXT,
                category TEXT DEFAULT 'Uncategorized',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Tracks one-time data migrations so they never run more than once
        conn.execute("""
            CREATE TABLE IF NOT EXISTS migrations (
                name TEXT PRIMARY KEY,
                run_at TEXT NOT NULL
            )
        """)

        # Idempotent column migration: last_reddit_check_at tracks the last
        # time prune_deleted_reddit_posts() looked at a given Reddit row, so
        # each tick rotates through the DB (oldest-checked first). SQLite has
        # no ADD COLUMN IF NOT EXISTS, so we check PRAGMA table_info and
        # only add when missing — safe to run on every startup.
        existing_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(articles)")
        }
        if "last_reddit_check_at" not in existing_cols:
            conn.execute(
                "ALTER TABLE articles ADD COLUMN last_reddit_check_at TEXT"
            )
            # Partial index narrows the rotation query to Reddit rows only —
            # no overhead for the other 30+ sources. Case-insensitive LIKE in
            # the query uses LOWER(source_name); the partial-index predicate
            # must match that form to be useful to the planner.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reddit_check "
                "ON articles(last_reddit_check_at) "
                "WHERE LOWER(source_name) LIKE '%reddit%'"
            )

        # Cumulative article counter — never decrements, survives pruning/cleanup
        conn.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                key   TEXT PRIMARY KEY,
                value INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Seed from current article count if not already set
        conn.execute("""
            INSERT OR IGNORE INTO stats (key, value)
            SELECT 'total_processed', COUNT(*) FROM articles
        """)

        # One-way re-classification of Uncategorized rows after keyword/
        # category changes. Each migration runs once (guarded by the
        # `migrations` table) and NEVER demotes a real category — if the
        # new classifier still returns Uncategorized, the row is left alone.
        # Safe to remove the oldest entries in the release after this ships.
        #
        #   v1: original keyword expansion
        #   v2: Industry/Policy addition
        #   v3: Consumer Awareness + broadened keywords (phishing scams,
        #       supply-chain plurals, mobile banking trojan, industry bodies,
        #       APT plurals)
        #   v4: cloud-dev platforms (vercel/netlify/heroku/supabase/fly.io),
        #       context.ai (AI Security), crypto exchange hacks,
        #       nginx-ui/secure-boot/maximum-severity framings,
        #       supply-chain editorial phrasing, q-day/quantum risk,
        #       ca privacy law
        #   v5: keyword expansion for new feed coverage (2026-04-19)
        #   v6: industrial automation (OT/ICS), DeFi hacks (SaaS Breach),
        #       novel/new malware + horabot/janelarat (Malware), AI
        #       hallucination + ai-mediated (AI Security), silver fox
        #       (Nation State/APT), supply chain attacks plural,
        #       surveillance program + cybersecurity rules (Industry/Policy),
        #       crypto-stealing (Mobile), recovery scammers plural (Consumer)
        #   v7: backdoor/backdoors (Malware), session theft (Identity),
        #       irs scam, dark web, brushing scam, hacked account,
        #       whatsapp scam (Consumer Awareness)
        #   v8: data wiper (Malware), propaganda/bot farm (Nation State),
        #       cyber resilience (Industry/Policy)
        for migration_name in (
            "reclassify_uncategorized_v1",
            "reclassify_uncategorized_v2",
            "reclassify_uncategorized_v3",
            "reclassify_uncategorized_v4",
            "reclassify_uncategorized_v5",
            "reclassify_uncategorized_v6",
            "reclassify_uncategorized_v7",
            "reclassify_uncategorized_v8",
        ):
            _run_reclassify_migration(conn, migration_name)

        # Startup prune: DELETE historical rows that would be excluded by
        # the current config/exclusions.yml. Idempotent — re-runs on every
        # deploy so a newly-added phrase also cleans pre-existing rows,
        # not just future ingests. Case-insensitive LIKE; parameterized
        # (EXCLUSIONS is a committed trust anchor, but defense-in-depth).
        pruned = 0
        for source_name, phrases in EXCLUSIONS.items():
            for phrase in phrases:
                pattern = f"%{phrase}%"
                result = conn.execute(
                    "DELETE FROM articles "
                    "WHERE source_name = ? AND ("
                    "LOWER(title) LIKE ? OR LOWER(COALESCE(summary, '')) LIKE ?"
                    ")",
                    (source_name, pattern, pattern),
                )
                pruned += result.rowcount
        if pruned:
            print(f"[exclusions] pruned {pruned} historical articles matching exclusions.yml")

        # One-time migration: prune articles older than 30 days.
        # Prevents historical backlog floods from feeds that expose their
        # full archive on first ingest (e.g. MSRC, Siemens ProductCERT).
        # The recurring _prune_old_articles job keeps the DB lean after
        # this initial cleanup.
        _prune_mig = "prune_articles_older_than_30d_v1"
        already_pruned = conn.execute(
            "SELECT 1 FROM migrations WHERE name = ?", (_prune_mig,)
        ).fetchone()
        if not already_pruned:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            result = conn.execute(
                "DELETE FROM articles WHERE COALESCE(published_date, created_at) < ?",
                (cutoff,),
            )
            print(f"[migration] {_prune_mig}: removed {result.rowcount} articles older than 30 days")
            conn.execute(
                "INSERT INTO migrations (name, run_at) VALUES (?, ?)",
                (_prune_mig, datetime.now(timezone.utc).isoformat()),
            )

        # One-time migration: remove all articles from the old MSRC Update
        # Guide CVE firehose. That feed ingested ~3k raw CVE advisories per
        # quarter — replaced by the curated Microsoft Security Blog feed.
        _msrc_mig = "remove_msrc_update_guide_articles_v1"
        already_msrc = conn.execute(
            "SELECT 1 FROM migrations WHERE name = ?", (_msrc_mig,)
        ).fetchone()
        if not already_msrc:
            result = conn.execute(
                "DELETE FROM articles WHERE source_name = ?",
                ("Microsoft MSRC",),
            )
            print(f"[migration] {_msrc_mig}: removed {result.rowcount} MSRC Update Guide articles")
            conn.execute(
                "INSERT INTO migrations (name, run_at) VALUES (?, ?)",
                (_msrc_mig, datetime.now(timezone.utc).isoformat()),
            )

        conn.commit()
    finally:
        conn.close()


def parse_since(value):
    """Validate a ?since= query parameter against common ISO 8601 formats.

    Returns (parsed_str, error_str). On success, error_str is None.
    On failure, parsed_str is None and error_str describes the problem.
    """
    if not value:
        return None, None

    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            datetime.strptime(value, fmt)
            return value, None
        except ValueError:
            continue

    return None, "Invalid 'since' value — use ISO 8601, e.g. 2026-04-17T00:00:00"


# ---- CORS allowlist (O(1) lookup, allocated once) ----
_CORS_PATHS = frozenset(("/api/articles", "/api/top-story", "/api/categories", "/feed.xml"))

# ---- Security Headers ----
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # HSTS: tell browsers to only use HTTPS for this origin.
    # 1 year max-age + includeSubDomains; not submitting to preload list yet
    # (that's a one-way commitment — revisit once the domain is stable).
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # ---- CORS for API / feed endpoints ----
    # Allow cross-origin reads so agents, browser extensions, and third-party
    # dashboards can call the JSON API and Atom feed directly. Scoped to the
    # public read-only surface — no credentials, no mutations, no side-effects.
    # Explicit allowlist — if a future /api/ route requires auth or
    # handles mutations, it must NOT inherit wildcard CORS. Update
    # _CORS_PATHS (module-level frozenset) when adding new endpoints.
    if request.path in _CORS_PATHS:
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Max-Age"] = "3600"

    return response


@app.route("/")
@limiter.limit("60 per minute")
def index():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT title, summary, url, published_date, created_at, "
            "source_name, category FROM articles "
            "ORDER BY COALESCE(published_date, created_at) DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()
    articles = [dict(r) for r in rows]
    # Sanitize URLs at the data layer — same scheme allowlist used for the
    # Atom feed (_safe_entry_url). Prevents javascript:/data: hrefs from
    # reaching the SSR template. The JS path has its own safeHref().
    for a in articles:
        a["url"] = _safe_entry_url(a.get("url"))
    resp = render_template("index.html", articles=articles)
    resp = app.make_response(resp)
    resp.headers["Cache-Control"] = "public, max-age=120"
    return resp


# Source -> {tier, reason} lookup, built once at startup from the committed
# FEEDS trust anchor. The /api/articles enrichment below is a dict get per
# article (O(1)), not a FEEDS linear scan.
SOURCE_INFO = build_source_info_index(FEEDS)


def _enrich_with_confidence(row_dict):
    """Attach confidence + confidence_reason to an article row.

    Confidence is derived from scheduler.py FEEDS source_tier via the
    resolve_confidence() helper, which also handles the CONFIDENCE_ENABLED
    kill-switch (env flag off -> UNSET, frontend renders "—" placeholder).
    """
    info = SOURCE_INFO.get(row_dict.get("source_name"))
    tier = info["tier"] if info else None
    confidence = resolve_confidence(tier)
    row_dict["confidence"] = confidence
    # Only surface the reason when the badge has a real value, and only from
    # the committed anchor — never a runtime-computed string.
    if confidence != UNSET and info is not None:
        row_dict["confidence_reason"] = info["reason"]
    else:
        row_dict["confidence_reason"] = None
    return row_dict


@app.route("/api/articles")
@limiter.limit("30 per minute")
def get_articles():
    category = request.args.get("category")
    since, error = parse_since(request.args.get("since"))

    if error:
        return jsonify({"error": error}), 400

    conditions, params = [], []

    if category and category != "All":
        conditions.append("category = ?")
        params.append(category)

    if since:
        conditions.append("COALESCE(published_date, created_at) >= ?")
        params.append(since)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    conn = get_db()
    try:
        rows = conn.execute(
            f"SELECT * FROM articles {where} "
            "ORDER BY COALESCE(published_date, created_at) DESC LIMIT 500",
            params,
        ).fetchall()
    finally:
        conn.close()

    resp = jsonify([_enrich_with_confidence(dict(row)) for row in rows])
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


def _load_top_story():
    """Read config/top_story.yml, validate, and return the payload.

    Fail-closed: any failure mode — missing file, bad YAML, missing required
    field, active != True — returns {"active": False}. The frontend treats
    that as "fall back to first-article-as-lead" and never renders partial
    Top Story state.

    Returns a dict suitable for jsonify()ing.
    """
    try:
        with open(TOP_STORY_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return {"active": False}

    if not isinstance(data, dict) or not data.get("active"):
        return {"active": False}

    missing = [k for k in TOP_STORY_REQUIRED if not data.get(k)]
    if missing:
        return {"active": False}

    # Defense-in-depth: the lead URL is operator-editable, but a stray
    # javascript:/data: URL in config/top_story.yml would reach clients
    # via the JSON API. Fail closed if the URL isn't a plain http(s) link.
    safe_url = _safe_entry_url(str(data["url"]))
    if not safe_url:
        return {"active": False}

    # Layer the Confidence for the lead card: same tier -> label derivation
    # as the regular article feed. Unknown source_name -> LOW (fail-secure).
    source_name = data.get("source_name")
    info = SOURCE_INFO.get(source_name)
    tier = info["tier"] if info else None
    confidence = resolve_confidence(tier)
    confidence_reason = info["reason"] if (info and confidence != UNSET) else None

    return {
        "active": True,
        "title": str(data["title"]),
        "summary": str(data["summary"]).strip(),
        "url": safe_url,
        "source_name": str(source_name),
        "published_at": str(data["published_at"]),
        "category": str(data.get("category") or "Uncategorized"),
        "key_points": [str(p) for p in (data.get("key_points") or [])][:5],
        "confidence": confidence,
        "confidence_reason": confidence_reason,
    }


@app.route("/api/top-story")
@limiter.limit("60 per minute")
def get_top_story():
    resp = jsonify(_load_top_story())
    resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


# NOTE: /api/stats (exposing cumulative total_processed) was removed in PR 3.
# See SECURITY.md — "Count disclosure policy". The `stats` table is kept
# for operator-side inspection via the SQLite CLI, but no public endpoint
# surfaces it.


@app.route("/api/categories")
@limiter.limit("60 per minute")
def get_categories():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT category, COUNT(*) as count FROM articles "
            "GROUP BY category ORDER BY count DESC"
        ).fetchall()
    finally:
        conn.close()

    resp = jsonify([dict(row) for row in rows])
    resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


# ---- Canonical site URL ----
# Used for absolute links in /feed.xml. NEVER derived from the Host header
# (attacker-controlled). Staging and production must each set their own
# canonical URL via the SITE_URL env var. Fail fast if unset rather than
# silently emitting prod URLs from a staging/dev deploy.
_SITE_URL_ENV = os.environ.get("SITE_URL", "").strip()
if not _SITE_URL_ENV:
    raise RuntimeError(
        "SITE_URL env var is required (e.g. https://threat-feed.up.railway.app "
        "for prod, http://localhost:5000 for local dev)."
    )
SITE_URL = _SITE_URL_ENV.rstrip("/")


# ---- Bot / agent / AI discoverability ----
# Three cheap static-ish responses that make the site readable to non-JS
# clients (traditional crawlers, LLM indexers, feed readers). Public by
# design — disclose no more than /, /api/articles, /api/top-story, and
# /api/categories already expose.

_ROBOTS_TXT = """\
User-agent: *
Allow: /

Sitemap: https://threat-feed.up.railway.app/sitemap.xml

# Machine-readable site description:
#   /llms.txt         — site overview for LLMs
#   /llms-full.txt    — full API reference for LLMs and agents
#   /feed.xml         — Atom 1.0 feed of aggregated headlines
#   /api/articles, /api/top-story, /api/categories — JSON
#   /.well-known/security.txt — responsible disclosure
"""

_LLMS_TXT = """\
# Threat-Feed

> Open-source aggregation of publicly available cybersecurity RSS feeds.
> Headlines and primary-source links only — no editorial commentary,
> no accounts, no cookies, no ads.

## What this site is

Threat-Feed ingests public RSS sources on a tiered schedule — priority
sources (government CERTs, top threat-intel teams) hourly, secondary
sources every 2 hours, community feeds every 4 hours. Each article is
classified by keyword (single-category, first-match-wins) and assigned a
confidence badge (HIGH / MEDIUM / LOW) from a committed source-tier map.
The front-end is a single-page client that reads three JSON endpoints.

## Machine-readable endpoints

- `/feed.xml` — Atom 1.0 feed of the 50 most-recent articles.
- `/api/articles` — JSON array of recent articles (up to 500). Supports
  `?category=<name>` and `?since=<ISO 8601 date>`.
- `/api/top-story` — JSON object for the operator-curated lead article.
  Returns `{"active": false}` when no lead is pinned.
- `/api/categories` — JSON array of category names with counts.

## Polling

Rate limits are per-IP. Well-behaved agents should stay well under these:

- `/feed.xml` — 30 requests per minute
- `/api/articles` — 30 requests per minute
- `/api/top-story` — 60 requests per minute
- `/api/categories` — 60 requests per minute
- `/robots.txt`, `/llms.txt`, `/llms-full.txt` — 60 requests per minute

Recommended polling interval: once every 15–30 minutes for `/feed.xml`
or `/api/articles`. Category counts change slowly — once per hour is
more than enough for `/api/categories`.

## Usage

Indexing and summarization are permitted. Republication of full article
bodies is prohibited — the site aggregates primary-source links; please
follow through to the original publisher.

## More detail

See `/llms-full.txt` for API response shapes, category list, and
query parameter documentation.
"""

_LLMS_FULL_TXT = """\
# Threat-Feed — Full Reference for LLMs and Agents

> Everything in /llms.txt plus API response shapes, the complete
> category list, and query parameter documentation.

## Site overview

Threat-Feed is an open-source cybersecurity RSS aggregator. It ingests
46 public RSS sources on a tiered schedule (hourly / 2h / 4h), classifies
each article by keyword into a single category, and assigns a confidence
badge (HIGH / MEDIUM / LOW) derived from the source tier. The front-end
is a static single-page client; all data is served via JSON endpoints.

No accounts, no cookies, no ads, no paywalls.

## Endpoints

### GET /api/articles

Returns up to 500 articles, newest first.

Query parameters:
  ?category=<name>    — filter by category (exact match, case-sensitive)
  ?since=<ISO 8601>   — only articles published on or after this date
                        Accepted formats: YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS,
                        YYYY-MM-DDTHH:MM:SSZ

Response shape (JSON array):
  [
    {
      "id": 42,
      "title": "...",
      "summary": "...",
      "url": "https://...",
      "published_date": "2026-04-23T14:00:00+00:00",
      "created_at": "2026-04-23 14:05:12",
      "source_name": "BleepingComputer",
      "category": "Ransomware",
      "confidence": "HIGH",
      "confidence_reason": "Tier-1 source: established security outlet"
    },
    ...
  ]

### GET /api/categories

Response shape (JSON array):
  [
    {"category": "Vulnerability/CVE", "count": 146},
    {"category": "Ransomware", "count": 32},
    ...
  ]

### GET /api/top-story

Response shape (JSON object):
  When active:
    {"active": true, "title": "...", "summary": "...", "url": "...",
     "source_name": "...", "published_at": "...", "category": "...",
     "key_points": ["...", "..."], "confidence": "HIGH",
     "confidence_reason": "..."}
  When inactive:
    {"active": false}

### GET /feed.xml

Atom 1.0 feed of the 50 most-recent articles.

## Categories

Vulnerability/CVE, OT/ICS, Malware/Infostealer, SaaS Breach,
AI Security, Nation State/APT, Ransomware, Cloud Breach, Supply Chain,
Identity & Access, Phishing & Social Engineering, Industry/Policy,
Consumer Awareness, Mobile Security, Uncategorized.

## Confidence badges

  HIGH   — Tier-1 sources: government CERTs, top threat-intel teams
  MEDIUM — Tier-2 sources: established journalism, vendor blogs
  LOW    — Tier-3 sources: community / Reddit

## Polling guidelines

Rate limits are per-IP:
  /feed.xml        — 30 req/min
  /api/articles    — 30 req/min
  /api/top-story   — 60 req/min
  /api/categories  — 60 req/min

Recommended: poll /feed.xml or /api/articles every 15-30 minutes.

## Usage policy

Indexing and summarization are permitted. Republication of full article
bodies is prohibited — follow through to the original publisher.

## Source code

https://github.com/vcsk9vxw9y-debug/test-feed
"""

_SECURITY_TXT = """\
# Security policy for Threat-Feed
# https://securitytxt.org/

Contact: https://github.com/vcsk9vxw9y-debug/test-feed/issues
Expires: 2027-04-23T00:00:00.000Z
Preferred-Languages: en
Canonical: https://threat-feed.up.railway.app/.well-known/security.txt
"""

_SITEMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://threat-feed.up.railway.app/</loc>
    <changefreq>hourly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://threat-feed.up.railway.app/feed.xml</loc>
    <changefreq>hourly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://threat-feed.up.railway.app/llms.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://threat-feed.up.railway.app/llms-full.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
</urlset>
"""


@app.route("/robots.txt")
@limiter.limit("60 per minute")
def robots_txt():
    response = app.response_class(_ROBOTS_TXT, mimetype="text/plain")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.route("/llms.txt")
@limiter.limit("60 per minute")
def llms_txt():
    response = app.response_class(_LLMS_TXT, mimetype="text/plain")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.route("/llms-full.txt")
@limiter.limit("60 per minute")
def llms_full_txt():
    response = app.response_class(_LLMS_FULL_TXT, mimetype="text/plain")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.route("/.well-known/security.txt")
@limiter.limit("60 per minute")
def security_txt():
    response = app.response_class(_SECURITY_TXT, mimetype="text/plain")
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@app.route("/sitemap.xml")
@limiter.limit("60 per minute")
def sitemap_xml():
    response = app.response_class(_SITEMAP_XML, mimetype="application/xml; charset=utf-8")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


def _cdata_safe(text):
    """CDATA sections cannot contain ']]>'. Split any such sequence so the
    resulting XML is well-formed regardless of article content."""
    if text is None:
        return ""
    return str(text).replace("]]>", "]]]]><![CDATA[>")


def _safe_entry_url(url):
    """Constrain Atom entry URLs to http/https with a populated netloc.

    Defense-in-depth for downstream feed readers: a poisoned upstream RSS
    feed could inject javascript: or data: URLs into articles.url. The
    frontend already does the equivalent in safeHref(); this closes the
    same gap on the machine-readable Atom surface. Returns empty string
    for anything that isn't a well-formed http(s) URL.
    """
    if not url or not isinstance(url, str):
        return ""
    parsed = urlparse(url)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return url
    return ""


def _build_atom_feed(rows):
    """Hand-rolled Atom 1.0 — no new dependency. Every article field goes
    through CDATA wrap + ]]> split so a hostile source feed cannot break
    the XML or smuggle markup into a consuming client."""

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        '<title>Threat-Feed — Open Source Threat Intelligence</title>',
        '<subtitle>Aggregated public-RSS cybersecurity headlines, updated hourly.</subtitle>',
        f'<id>{xml_escape(SITE_URL)}/</id>',
        f'<link href="{xml_escape(SITE_URL)}/" rel="alternate"/>',
        f'<link href="{xml_escape(SITE_URL)}/feed.xml" rel="self"/>',
        f'<updated>{now_iso}</updated>',
    ]
    for row in rows:
        updated = row.get("published_date") or row.get("created_at") or now_iso
        url = _safe_entry_url(str(row.get("url") or ""))
        source_name = row.get("source_name") or "unknown"
        category = row.get("category") or "Uncategorized"
        summary = row.get("summary") or ""
        parts.extend([
            '<entry>',
            f'<title><![CDATA[{_cdata_safe(row.get("title"))}]]></title>',
            f'<id>{xml_escape(url)}</id>',
            f'<link href="{xml_escape(url)}" rel="alternate"/>',
            f'<updated>{xml_escape(str(updated))}</updated>',
            f'<author><name><![CDATA[{_cdata_safe(source_name)}]]></name></author>',
            f'<category term="{xml_escape(str(category))}"/>',
            f'<summary type="html"><![CDATA[{_cdata_safe(summary)}]]></summary>',
            '</entry>',
        ])
    parts.append('</feed>')
    return "\n".join(parts)


@app.route("/feed.xml")
@limiter.limit("30 per minute")
def feed_xml():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT title, summary, url, published_date, created_at, "
            "source_name, category FROM articles "
            "ORDER BY COALESCE(published_date, created_at) DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()

    body = _build_atom_feed([dict(r) for r in rows])
    response = app.response_class(body, mimetype="application/atom+xml; charset=utf-8")
    response.headers["Cache-Control"] = "public, max-age=1200"
    return response


# Runs on every startup — gunicorn workers and direct python invocation alike
init_db()
fetch_all_feeds(DB_PATH)


def _fetch_tier(db_path, tier):
    """Fetch feeds for a single source tier. Each tier runs on its own
    APScheduler interval: T1 hourly, T2 every 2h, T3 every 4h.
    Defensive: a failure here never blocks other tiers or the prune job.
    """
    try:
        fetch_all_feeds(db_path, tier=tier)
    except Exception as e:
        print(f"[fetch-t{tier}] failed: {type(e).__name__}: {e}")


def _prune(db_path):
    """Independent Reddit prune job, runs every 2 hours.
    Decoupled from fetch so a slow tier-1 fetch never delays pruning.
    """
    try:
        prune_deleted_reddit_posts(db_path)
    except Exception as e:
        print(f"[prune] failed: {type(e).__name__}: {e}")


def _prune_old_articles(db_path):
    """Daily rolling prune — delete articles older than 30 days.
    Keeps the DB lean and category counts honest. The ingestion-side
    90-day guard in scheduler.py is a separate safety net against
    historical backlog floods on first ingest of a new feed.
    """
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        with sqlite3.connect(db_path) as conn:
            result = conn.execute(
                "DELETE FROM articles WHERE COALESCE(published_date, created_at) < ?",
                (cutoff,),
            )
            if result.rowcount:
                print(f"[prune-old] removed {result.rowcount} articles older than 30 days")
    except Exception as e:
        print(f"[prune-old] failed: {type(e).__name__}: {e}")


scheduler = BackgroundScheduler()
# Each job gets max_instances=1 to prevent self-overlap. Different jobs
# CAN run concurrently — they share SQLite with short transactions, no
# conflict. IDs are explicit for log clarity and APScheduler job management.
scheduler.add_job(_fetch_tier, "interval", hours=1, args=[DB_PATH, 1],
                  max_instances=1, id="fetch_t1")
scheduler.add_job(_fetch_tier, "interval", hours=2, args=[DB_PATH, 2],
                  max_instances=1, id="fetch_t2")
scheduler.add_job(_fetch_tier, "interval", hours=4, args=[DB_PATH, 3],
                  max_instances=1, id="fetch_t3")
scheduler.add_job(_prune, "interval", hours=2, args=[DB_PATH],
                  max_instances=1, id="reddit_prune")
scheduler.add_job(_prune_old_articles, "interval", hours=24, args=[DB_PATH],
                  max_instances=1, id="prune_old_articles")
scheduler.start()
atexit.register(lambda: scheduler.shutdown(wait=True))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
