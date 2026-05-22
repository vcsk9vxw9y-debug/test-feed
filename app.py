import atexit
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape

import json as json_module
import yaml
from flask import Flask, abort, jsonify, redirect, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from classifier import classify_article
from confidence import build_source_info_index, resolve_confidence, UNSET
from scheduler import EXCLUSIONS, FEEDS, fetch_all_feeds, prune_deleted_reddit_posts

TOP_STORY_PATH = os.path.join(os.path.dirname(__file__), "config", "top_story.yml")
TOP_STORY_REQUIRED = ("title", "summary", "url", "source_name", "published_at")
DAILY_BRIEFING_PATH = os.path.join(os.path.dirname(__file__), "config", "daily_briefing.yml")
DAILY_BRIEFING_REQUIRED = ("actions", "generated_at")
THREAT_CONTEXT_PATH = os.path.join(os.path.dirname(__file__), "config", "threat_context.yml")
THREAT_CONTEXT_REQUIRED = ("generated_at", "landscape_summary")

NOTABLE_ORGS_PATH = os.path.join(os.path.dirname(__file__), "config", "notable_orgs.yml")
# Every entry in notable_orgs.yml must carry these keys. Anything missing
# is silently rejected so a malformed YAML edit can't crash the spotlight.
_NOTABLE_ORG_REQUIRED = (
    "canonical", "platform", "sector", "aliases", "actor",
    "actor_cluster", "exposure_value", "exposure_unit",
    "severity", "fresh", "published_at", "appears_on",
)
# Allowlist for constrained string fields. Defense-in-depth — prevents a
# malformed entry from smuggling unexpected CSS class names into the
# template via actor_cluster or severity.
_NOTABLE_ORG_ACTOR_CLUSTERS = frozenset(
    ("shiny", "teampcp", "qilin", "lapsus", "unattrib")
)
_NOTABLE_ORG_SEVERITIES = frozenset(("critical", "high", "medium"))
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1}
# Defensive limits on aliases — guards against a typo'd or malicious YAML
# entry causing a pathological match storm.
#   Minimum length 4 chars: rejects 1-3 char aliases that would over-match
#   ("m" matches everything, "ai" matches half of 2026 coverage).
#   Maximum 32 aliases per entry: any legitimate org needs far fewer.
_NOTABLE_ORG_ALIAS_MIN_LEN = 4
_NOTABLE_ORG_ALIAS_MAX_COUNT = 32
# Hard ceiling on notable_orgs.yml size before yaml.safe_load. PyYAML's
# safe_load prevents arbitrary object construction but does NOT protect
# against YAML aliases / billion-laughs / pathologically large files.
# 1 MB is ~50x the largest plausible brand file. Files larger than this
# fail validation and the spotlight degrades to V1 behavior.
_NOTABLE_ORGS_MAX_BYTES = 1_048_576

# Hard ceiling on article count — prevents unbounded DB growth even if
# the 30-day rolling prune can't keep up (e.g., feed floods, new source
# onboarding bursts). Oldest articles beyond this cap are deleted.
MAX_ARTICLES = 2000

app = Flask(__name__)

# Use Railway's persistent volume when available, otherwise local
DB_PATH = "/data/testfeed.db" if os.path.exists("/data") else "./testfeed.db"

# ---- Domain redirect ----
# 301 redirect from the legacy Railway subdomain to the canonical domain.
# Preserves path + query string so bookmarks and API consumers land on the
# right page. The Railway deployment stays alive to serve this redirect.
OLD_RAILWAY_HOST = "threat-feed.up.railway.app"


@app.before_request
def redirect_old_domain():
    if request.host == OLD_RAILWAY_HOST:
        return redirect(
            f"https://threat-feed.ai{request.full_path}", code=301
        )


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
        #   v9: npm standalone (Supply Chain), autonomous agent/multi-agent/
        #       securing ai (AI Security), uac bypass/uac/elevate privileges
        #       (Vuln/CVE), account compromise (Identity), fake apps/fake
        #       wallet/seed phrase (Mobile), operational resilience/age
        #       verification/threat intelligence report/autonomous warfare/
        #       incident response (Industry/Policy), social engineering
        #       standalone (Phishing)
        #   v10: glassworm/lofystealer/grabbot/information-stealing (Malware),
        #        blackfile/ransom demands (Ransomware), foreign adversary
        #        (Nation State), ai governance/ai workforce/ai deployment
        #        (AI Security), openvsx/sleeper extension (Supply Chain),
        #        privacy fine/privacy laws/zero trust/election security
        #        (Industry/Policy), social media scam (Consumer Awareness)
        #   v11: source code breach/hacking forum (SaaS Breach),
        #        lpe/local privilege escalation/api flaw (Vuln/CVE),
        #        cyber spy (Nation State), stealer/etherrat (Malware),
        #        ai regulation/llm standalone (AI Security),
        #        play store/google play (Mobile Security),
        #        fbi warns/fcc/insider threat/sentenced/convicted/
        #        pleaded guilty (Industry/Policy),
        #        suspicious website (Consumer Awareness)
        #   v12: identity security (Identity & Access),
        #        weaponized ai/ai sbom (AI Security),
        #        identity spoofing (Phishing & Social Engineering),
        #        cyber policy/odni/director of national intelligence/
        #        voter data/indictment/arrested/end-to-end encryption/
        #        e2ee (Industry/Policy)
        for migration_name in (
            "reclassify_uncategorized_v1",
            "reclassify_uncategorized_v2",
            "reclassify_uncategorized_v3",
            "reclassify_uncategorized_v4",
            "reclassify_uncategorized_v5",
            "reclassify_uncategorized_v6",
            "reclassify_uncategorized_v7",
            "reclassify_uncategorized_v8",
            "reclassify_uncategorized_v9",
            "reclassify_uncategorized_v10",
            "reclassify_uncategorized_v11",
            "reclassify_uncategorized_v12",
        ):
            _run_reclassify_migration(conn, migration_name)

        # One-time category rename: Cloud Breach -> Cloud Security.
        # Broadens the category from incidents-only to all cloud security
        # topics (posture, misconfig, vulnerability, guidance).
        _rename = "rename_cloud_breach_to_cloud_security"
        if not conn.execute(
            "SELECT 1 FROM migrations WHERE name = ?", (_rename,)
        ).fetchone():
            result = conn.execute(
                "UPDATE articles SET category = 'Cloud Security' "
                "WHERE category = 'Cloud Breach'"
            )
            conn.execute(
                "INSERT INTO migrations (name, run_at) VALUES (?, ?)",
                (_rename, datetime.now(timezone.utc).isoformat()),
            )
            if result.rowcount:
                print(f"[migration] renamed {result.rowcount} 'Cloud Breach' -> 'Cloud Security'")

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
_CORS_PATHS = frozenset(("/api/articles", "/api/top-story", "/api/briefing", "/api/categories", "/api/threat-context", "/feed.xml"))

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

    # --- Markdown content negotiation (Cloudflare "Markdown for Agents") ---
    # When Accept: text/markdown is present, return a markdown representation
    # instead of HTML so LLM agents get structured, parseable content.
    if _wants_markdown():
        return _md_response(_homepage_to_markdown(articles))

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

    articles = [_enrich_with_confidence(dict(row)) for row in rows]

    if _wants_markdown():
        return _md_response(_articles_to_markdown(articles))

    resp = jsonify(articles)
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
    story = _load_top_story()

    if _wants_markdown():
        return _md_response(_top_story_to_markdown(story))

    resp = jsonify(story)
    resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


def _load_daily_briefing():
    """Read config/daily_briefing.yml, validate, and return the payload.

    Fail-closed: any failure mode — missing file, bad YAML, missing required
    field, active != True — returns {"active": False}. The frontend hides the
    briefing block entirely when active is false.

    generated_at is derived from the file's modification time, not the
    YAML field — so the timestamp always reflects when the briefing was
    actually written, regardless of what the generator stamps inside.
    """
    try:
        file_mtime = os.path.getmtime(DAILY_BRIEFING_PATH)
        with open(DAILY_BRIEFING_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return {"active": False}

    if not isinstance(data, dict) or not data.get("active"):
        return {"active": False}

    missing = [k for k in DAILY_BRIEFING_REQUIRED if not data.get(k)]
    if missing:
        return {"active": False}

    # Validate actions: each must have severity, title, description
    VALID_SEVERITIES = {"critical", "high", "medium"}
    raw_actions = data.get("actions") or []
    if not isinstance(raw_actions, list) or len(raw_actions) == 0:
        return {"active": False}

    actions = []
    for a in raw_actions:
        if not isinstance(a, dict):
            continue
        title = str(a.get("title", "")).strip()
        description = str(a.get("description", "")).strip()
        severity = str(a.get("severity", "medium")).strip().lower()
        if not title or not description:
            continue
        if severity not in VALID_SEVERITIES:
            severity = "medium"
        action_text = str(a.get("action", "")).strip()
        entry = {
            "severity": severity,
            "title": title[:200],
            "description": description[:500],
        }
        if action_text:
            entry["action"] = action_text[:200]
        actions.append(entry)

    if not actions:
        return {"active": False}

    # Validate stats (optional)
    raw_stats = data.get("stats") or []
    stats = []
    for s in raw_stats:
        if not isinstance(s, dict):
            continue
        label = str(s.get("label", "")).strip()
        if not label:
            continue
        stats.append({
            "label": label[:50],
            "value": int(s.get("value", 0)) if isinstance(s.get("value"), (int, float)) else 0,
            "hot": bool(s.get("hot", False)),
        })

    # Use file mtime as the authoritative generated_at timestamp.
    generated_at = datetime.fromtimestamp(file_mtime, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    return {
        "active": True,
        "generated_at": generated_at,
        "actions": actions[:8],
        "stats": stats[:6],
    }


@app.route("/api/briefing")
@limiter.limit("60 per minute")
def get_daily_briefing():
    briefing = _load_daily_briefing()

    if _wants_markdown():
        return _md_response(_briefing_to_markdown(briefing))

    resp = jsonify(briefing)
    resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


def _load_threat_context():
    """Read config/threat_context.yml, validate, and return the payload.

    Fail-closed: any failure mode — missing file, bad YAML, missing required
    field — returns {"active": False}. The endpoint is consumed by Aegis
    (CISO agent) for situational awareness; a missing context is safe.

    Strings are cast explicitly to prevent YAML-injection of non-string
    types into the JSON response.
    """
    try:
        if os.path.getsize(THREAT_CONTEXT_PATH) > 50_000:  # 50 KB sanity cap
            return {"active": False}
        with open(THREAT_CONTEXT_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return {"active": False}

    if not isinstance(data, dict):
        return {"active": False}

    missing = [k for k in THREAT_CONTEXT_REQUIRED if not data.get(k)]
    if missing:
        return {"active": False}

    # Sanitize list-of-dict sections: cast every value to str/int/bool.
    def _sanitize_list(raw, allowed_keys):
        """Return a list of dicts with only allowed_keys, values cast to str."""
        if not isinstance(raw, list):
            return []
        out = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            entry = {}
            for k in allowed_keys:
                v = item.get(k)
                if v is None:
                    continue
                if isinstance(v, bool):
                    entry[k] = v
                elif isinstance(v, (int, float)):
                    entry[k] = v
                else:
                    entry[k] = str(v)[:500]
            if entry:
                out.append(entry)
        return out

    stack_cves = _sanitize_list(
        data.get("stack_cves"),
        ("cve_id", "package", "affected_versions", "severity", "status",
         "summary", "source_url", "our_version", "action"),
    )
    trending = _sanitize_list(
        data.get("trending_techniques"),
        ("technique", "mitre_id", "relevance", "context"),
    )
    campaigns = _sanitize_list(
        data.get("active_campaigns"),
        ("name", "actor", "targets", "relevance_to_us", "summary"),
    )
    alerts = _sanitize_list(
        data.get("stack_alerts"),
        ("alert", "severity", "detail"),
    )

    return {
        "active": True,
        "generated_at": str(data["generated_at"]),
        "expires_at": str(data.get("expires_at", "")),
        "stack_cves": stack_cves[:20],
        "trending_techniques": trending[:10],
        "active_campaigns": campaigns[:10],
        "stack_alerts": alerts[:10],
        "landscape_summary": str(data["landscape_summary"]).strip()[:1000],
    }


@app.route("/api/threat-context")
@limiter.limit("60 per minute")
def get_threat_context():
    resp = jsonify(_load_threat_context())
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

    categories = [dict(row) for row in rows]

    if _wants_markdown():
        return _md_response(_categories_to_markdown(categories))

    resp = jsonify(categories)
    resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


# ============================================================
# Category Spotlight pages — /category/<slug>
# ============================================================
#
# Dedicated landing pages for high-volume threat categories with computed
# summary rollups in addition to the standard article list. Data is live
# from the articles table — independent of the editorial top_story /
# daily_briefing surfaces.
#
# Security boundary: the slug is validated against a fixed allowlist
# (_SPOTLIGHT_SLUGS). The category string sent to SQL is ALWAYS the
# allowlist value, never the raw slug. Unknown slugs return 404.
#
# Adding a new spotlight category = add an entry to _SPOTLIGHT_SLUGS.
# The slug becomes the URL segment; the value must match articles.category
# exactly (case-sensitive, since classifier.py emits exact strings).

_SPOTLIGHT_SLUGS = {
    "ransomware": "Ransomware",
    "saas-breach": "SaaS Breach",
}

# Hardcoded fallback for "notable victims" stat until
# config/notable_victims.yml ships (Noise Reduction Proposal 1).
# Articles in the Ransomware category from these sources are counted
# as notable-victim coverage (these outlets do editorial filtering
# before publishing).
# TODO(noise-reduction): replace with notable_victims.yml keyword match.
_NOTABLE_RANSOMWARE_SOURCES = frozenset((
    "Bleeping Computer",
    "BleepingComputer",
    "The Record",
    "SecurityWeek",
    "Dark Reading",
    "Krebs on Security",
    "CISA",
))

# Ransomware.live titles follow a stable format:
#   "🏴‍☠️ Qilin has just published a new victim : Acme Corp"
# We skip the emoji + whitespace prefix, then capture the group name.
# Anything that doesn't match falls back to "Unattributed" — we'd rather
# under-attribute than misattribute. The leading `[^A-Za-z0-9]{0,20}`
# is bounded to prevent ReDoS; group token is bounded too.
_RANSOMWARE_GROUP_RE = re.compile(
    r"^[^A-Za-z0-9]{0,20}([A-Za-z][A-Za-z0-9_\-\.]{0,39})\s+has\s+just\s+"
    r"published\s+a\s+new\s+victim",
    re.IGNORECASE,
)

# Defense-in-depth cap on article rows per spotlight page (the 30-day
# prune keeps category counts modest, but cap independently).
_SPOTLIGHT_ARTICLE_LIMIT = 200


# Source allowlist for group-name extraction. The Ransomware.live title
# format is structured ("<Group> has just published a new victim : X")
# and trusted *because the source is trusted*. Any other source publishing
# a title in that format could be a poisoned upstream feed planting fake
# attribution — we deliberately do not extract from arbitrary sources.
# Aegis: extends the trust boundary explicitly to the source level, not
# just the title format.
_RANSOMWARE_GROUP_TRUSTED_SOURCES = frozenset((
    "Ransomware.live",
))


def _extract_ransomware_group(title, source_name=None):
    """Return the threat-actor name from a Ransomware.live-style title,
    or 'Unattributed' if the title doesn't match the known pattern OR
    if the source is not on the trusted-extraction allowlist.

    The source allowlist guards against title-format poisoning from a
    compromised non-Ransomware.live RSS feed claiming attribution that
    didn't happen. source_name=None disables the source check (used by
    unit tests that pre-validate the title independently).

    Defensive: handles None, empty string, and non-matching titles.
    Normalizes capitalization so 'QILIN' and 'Qilin' roll up together.
    """
    if not title:
        return "Unattributed"
    # Source check (when caller provides one) — only Ransomware.live's
    # structured titles are trusted for group attribution.
    if source_name is not None and source_name not in _RANSOMWARE_GROUP_TRUSTED_SOURCES:
        return "Unattributed"
    match = _RANSOMWARE_GROUP_RE.match(title)
    if not match:
        return "Unattributed"
    return match.group(1).strip().title()


def _build_ransomware_summary(articles):
    """Group ransomware articles by extracted threat actor.

    Returns {"stats": {...}, "rows": [...]} where rows is sorted by
    claim count desc with 'Unattributed' always last regardless of
    count (visual hierarchy — known groups should lead).
    """
    groups = {}
    notable_count = 0
    for a in articles:
        if a.get("source_name") in _NOTABLE_RANSOMWARE_SOURCES:
            notable_count += 1
        # Pass source_name so extraction is restricted to trusted feeds.
        group_name = _extract_ransomware_group(
            a.get("title"), a.get("source_name")
        )
        if group_name not in groups:
            groups[group_name] = {
                "group": group_name,
                "count": 0,
                "victims": [],
            }
        groups[group_name]["count"] += 1
        groups[group_name]["victims"].append({
            "title": a.get("title") or "",
            "url": a.get("url") or "",
            "date": a.get("published_date") or a.get("created_at") or "",
            "source": a.get("source_name") or "",
        })

    rows = list(groups.values())
    rows.sort(key=lambda r: (r["group"] == "Unattributed", -r["count"]))

    stats = {
        "total_claims": len(articles),
        "active_groups": sum(1 for r in rows if r["group"] != "Unattributed"),
        "notable_victims": notable_count,
    }
    return {"stats": stats, "rows": rows}


def _load_notable_orgs():
    """Load and schema-validate config/notable_orgs.yml.

    Returns a list of validated org dicts, or [] on any of:
      - file missing
      - YAML parse error
      - top-level not a list
      - all entries fail validation

    Every entry must carry the keys in _NOTABLE_ORG_REQUIRED, with
    actor_cluster and severity constrained to the allowlists above.
    Aliases are normalized to lowercase + stripped, must be at least
    _NOTABLE_ORG_ALIAS_MIN_LEN characters, and capped at
    _NOTABLE_ORG_ALIAS_MAX_COUNT per entry.

    appears_on values are filtered against _SPOTLIGHT_SLUGS — unknown
    slugs are dropped so the template never renders a /category/<x>
    link to a non-existent spotlight page.

    JB: degrades gracefully — if the brand file is broken the
    spotlight page falls back to V1 behavior (rows=[]) rather than
    crashing the request.
    """
    if not os.path.exists(NOTABLE_ORGS_PATH):
        return []
    try:
        # Aegis: refuse to parse files larger than the hard ceiling. Defense
        # against pathologically large or aliased YAML — safe_load alone
        # does not guard against billion-laughs / quadratic-blowup attacks.
        if os.path.getsize(NOTABLE_ORGS_PATH) > _NOTABLE_ORGS_MAX_BYTES:
            return []
        with open(NOTABLE_ORGS_PATH, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or []
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, list):
        return []
    validated = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if not all(k in entry for k in _NOTABLE_ORG_REQUIRED):
            continue
        aliases_raw = entry.get("aliases") or []
        if not isinstance(aliases_raw, list):
            continue
        # Normalize + length-guard each alias, then cap the list at
        # _NOTABLE_ORG_ALIAS_MAX_COUNT. Short aliases (<4 chars) are dropped
        # because they would over-match against arbitrary article text.
        aliases = [
            a.lower().strip()
            for a in aliases_raw
            if isinstance(a, str) and len(a.strip()) >= _NOTABLE_ORG_ALIAS_MIN_LEN
        ]
        aliases = aliases[:_NOTABLE_ORG_ALIAS_MAX_COUNT]
        if not aliases:
            continue
        appears_on_raw = entry.get("appears_on") or []
        if not isinstance(appears_on_raw, list):
            continue
        # Filter appears_on against the actual spotlight allowlist so a
        # malformed YAML edit can never produce a link to a non-existent
        # spotlight page. Strings only; unknown slugs dropped silently.
        appears_on = [
            s for s in appears_on_raw
            if isinstance(s, str) and s in _SPOTLIGHT_SLUGS
        ]
        if entry.get("actor_cluster") not in _NOTABLE_ORG_ACTOR_CLUSTERS:
            continue
        if entry.get("severity") not in _NOTABLE_ORG_SEVERITIES:
            continue
        validated.append({
            "canonical": str(entry["canonical"]),
            "platform": str(entry["platform"]),
            "sector": str(entry["sector"]),
            "aliases": aliases,
            "actor": str(entry["actor"]),
            "actor_cluster": str(entry["actor_cluster"]),
            "exposure_value": str(entry["exposure_value"]),
            "exposure_unit": str(entry["exposure_unit"]),
            "severity": str(entry["severity"]),
            "fresh": bool(entry["fresh"]),
            "published_at": str(entry["published_at"]),
            "appears_on": appears_on,
        })
    return validated


def _build_saas_breach_summary(articles):
    """Build the SaaS Breach spotlight roster from notable_orgs.yml.

    For each org in the brand file whose appears_on list contains
    "saas-breach", count the articles whose title or summary contains
    any of the org's aliases (case-insensitive substring match). Orgs
    with zero matching articles are omitted — the roster shows only
    orgs with active coverage in the current article window.

    Returns {"stats": {...}, "rows": [...]} matching the template
    contract. Rows are ordered by severity (critical first), then
    published_at desc, then canonical asc.

    Backward-compat: if notable_orgs.yml is missing or invalid,
    returns rows=[] and basic stats — the template's
    {% if summary.rows %} guard suppresses the rollup section and
    the page renders as before.

    Scaling: matching is O(orgs * articles * aliases). With the current
    target of <50 orgs, <500 articles, <32 aliases each, that's <800K
    substring checks per page render — well under 100ms. If the brand
    file grows past ~100 orgs, consider precompiling aliases into a
    single combined regex per org, or switching to an inverted index.
    """
    orgs = [
        o for o in _load_notable_orgs()
        if "saas-breach" in o["appears_on"]
    ]

    # Precompute lowercase title+summary haystacks once per article.
    twenty_four_hours_ago = (
        datetime.now(timezone.utc) - timedelta(hours=24)
    ).date().isoformat()
    recent_24h_count = 0
    haystacks = []
    for a in articles:
        published = a.get("published_date") or a.get("created_at") or ""
        if published >= twenty_four_hours_ago:
            recent_24h_count += 1
        title = (a.get("title") or "").lower()
        summary = (a.get("summary") or "").lower()
        haystacks.append((a, title + " " + summary))

    rows = []
    matched_canonicals = set()
    for org in orgs:
        org_articles = []
        for a, hay in haystacks:
            if any(alias in hay for alias in org["aliases"]):
                org_articles.append({
                    "title": a.get("title") or "",
                    "url": a.get("url") or "",
                    "source": a.get("source_name") or "",
                    "date": a.get("published_date") or a.get("created_at") or "",
                })
        if not org_articles:
            continue
        matched_canonicals.add(org["canonical"])
        org_articles.sort(
            key=lambda v: v.get("date") or "", reverse=True
        )
        # Crossover handling (option B, inclusive): if this org appears on
        # ransomware too, surface a link in the template via also_in.
        also_in = [
            slug for slug in org["appears_on"] if slug != "saas-breach"
        ]
        # Qualitative exposure values ("codebase", "undisclosed") get
        # smaller label-style rendering so they don't break the column's
        # numeric rhythm. Holly call: number-and-unit pattern reads as data;
        # word-as-value styled like data reads like a bug.
        exposure_qualitative = not (
            org["exposure_value"] and org["exposure_value"][0].isdigit()
        )
        rows.append({
            "canonical": org["canonical"],
            "platform": org["platform"],
            "sector": org["sector"],
            "actor": org["actor"],
            "actor_cluster": org["actor_cluster"],
            "exposure_value": org["exposure_value"],
            "exposure_unit": org["exposure_unit"],
            "exposure_qualitative": exposure_qualitative,
            "severity": org["severity"],
            "fresh": org["fresh"],
            "published_at": org["published_at"],
            "article_count": len(org_articles),
            "articles": org_articles,
            "also_in": also_in,
        })

    # Stable-sort in reverse importance order so the final order is:
    # severity desc → published_at desc → canonical asc.
    rows.sort(key=lambda r: r["canonical"])
    rows.sort(key=lambda r: r["published_at"] or "", reverse=True)
    rows.sort(key=lambda r: -_SEVERITY_RANK.get(r["severity"], 0))

    distinct_actors = {
        r["actor"] for r in rows
        if r["actor"] and r["actor"] != "Unattributed"
    }

    stats = {
        "orgs_breached": len(matched_canonicals),
        "recent_24h": recent_24h_count,
        "active_actors": len(distinct_actors),
        "total_articles": len(articles),
    }
    return {"stats": stats, "rows": rows}


def _crossover_categories_for(primary_slug):
    """Return the set of article CATEGORIES (not slugs) needed for roster
    matching on primary_slug, given the orgs in notable_orgs.yml.

    Crossover orgs declare appears_on with multiple spotlight slugs. If an
    org appears_on both 'saas-breach' and 'ransomware', its coverage may be
    classified by the article classifier into Ransomware (because the
    Ransomware keywords fire first) — but we still want that coverage to
    surface on the SaaS Breach roster row for that org. This helper tells
    the route which article categories to query.

    Returns the primary category plus any extra category referenced by any
    roster org's appears_on. Always a subset of _SPOTLIGHT_SLUGS values, so
    SQL placeholders are bounded.
    """
    if primary_slug not in _SPOTLIGHT_SLUGS:
        return set()
    needed_slugs = {primary_slug}
    for org in _load_notable_orgs():
        if primary_slug in org["appears_on"]:
            needed_slugs.update(org["appears_on"])
    return {
        _SPOTLIGHT_SLUGS[s] for s in needed_slugs if s in _SPOTLIGHT_SLUGS
    }


def _category_to_markdown(category_name, articles, summary):
    """Markdown representation of a spotlight page for agent consumers."""
    lines = [
        f"# {category_name} — Spotlight\n",
        f"*{len(articles)} articles (most recent first)*\n",
    ]
    if summary and summary.get("stats"):
        lines.append("## Summary Stats\n")
        for key, value in summary["stats"].items():
            label = key.replace("_", " ").title()
            lines.append(f"- **{label}:** {value}")
        lines.append("")
    if summary and summary.get("rows"):
        lines.append("## Group Activity\n")
        for row in summary["rows"]:
            lines.append(
                f"- **{row['group']}** — {row['count']} "
                f"claim{'s' if row['count'] != 1 else ''}"
            )
        lines.append("")
    lines.append("## Articles\n")
    for a in articles:
        lines.append(f"### {a.get('title', 'Untitled')}\n")
        lines.append(f"- **Source:** {a.get('source_name', 'Unknown')}")
        published = a.get("published_date") or a.get("created_at") or ""
        lines.append(f"- **Published:** {published}")
        if a.get("url"):
            lines.append(f"- **URL:** {a['url']}")
        summary_text = a.get("summary", "")
        if summary_text:
            lines.append(f"\n{summary_text[:300]}")
        lines.append("")
    return "\n".join(lines)


@app.route("/category/<slug>")
@limiter.limit("60 per minute")
def category_spotlight(slug):
    """Spotlight landing page for a high-volume threat category.

    Slug is validated against a fixed allowlist (_SPOTLIGHT_SLUGS). The
    category string passed to SQL is the allowlist value, never the
    raw slug, so user input never reaches the query as data OR as an
    identifier. Unknown slugs return Flask's default 404 HTML page.
    """
    category = _SPOTLIGHT_SLUGS.get(slug)
    if category is None:
        abort(404)

    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT title, summary, url, published_date, created_at, "
            "source_name, category FROM articles WHERE category = ? "
            "ORDER BY COALESCE(published_date, created_at) DESC LIMIT ?",
            (category, _SPOTLIGHT_ARTICLE_LIMIT),
        ).fetchall()
    finally:
        conn.close()

    articles = [dict(row) for row in rows]
    # Same scheme allowlist as the homepage / Atom feed — prevents
    # javascript:/data: hrefs from reaching the SSR template.
    for a in articles:
        a["url"] = _safe_entry_url(a.get("url"))

    if slug == "ransomware":
        summary = _build_ransomware_summary(articles)
    elif slug == "saas-breach":
        # Crossover handling: an org with appears_on=['saas-breach', 'ransomware']
        # may have coverage that classified into Ransomware. Broaden the article
        # window for ROSTER matching so those rows render with their "also in
        # Ransomware" link. The article LIST below the divider keeps the narrow
        # category-filtered set above — that's still SaaS Breach articles only.
        crossover_cats = _crossover_categories_for(slug)
        if crossover_cats - {category}:
            conn = get_db()
            try:
                placeholders = ",".join("?" * len(crossover_cats))
                xrows = conn.execute(
                    f"SELECT title, summary, url, published_date, created_at, "
                    f"source_name, category FROM articles "
                    f"WHERE category IN ({placeholders}) "
                    f"ORDER BY COALESCE(published_date, created_at) DESC "
                    f"LIMIT ?",
                    (*sorted(crossover_cats), _SPOTLIGHT_ARTICLE_LIMIT * 2),
                ).fetchall()
            finally:
                conn.close()
            roster_articles = [dict(r) for r in xrows]
            for a in roster_articles:
                a["url"] = _safe_entry_url(a.get("url"))
        else:
            roster_articles = articles
        summary = _build_saas_breach_summary(roster_articles)
    else:
        # Unreachable given the allowlist guard above, but explicit > implicit
        summary = {"stats": {}, "rows": []}

    # is_capped tells the template whether the DB query hit the row limit.
    # Single source of truth — template no longer hard-codes the magic number.
    is_capped = len(articles) >= _SPOTLIGHT_ARTICLE_LIMIT

    if _wants_markdown():
        md_resp = _md_response(
            _category_to_markdown(category, articles, summary)
        )
        # Same URL serves HTML or markdown — Vary on Accept prevents a
        # shared cache from serving the wrong representation. The
        # _md_response helper is shared across routes that have the
        # same dual-representation pattern (homepage, /api/*) — those
        # have the same gap; tracked separately, out of Spotlight scope.
        md_resp.headers["Vary"] = "Accept"
        return md_resp

    resp = render_template(
        "category.html",
        category=category,
        slug=slug,
        articles=articles,
        summary=summary,
        is_capped=is_capped,
    )
    resp = app.make_response(resp)
    resp.headers["Cache-Control"] = "public, max-age=300"
    # Vary on Accept — same URL serves HTML or markdown depending on
    # the Accept header. Without this, a shared cache could serve the
    # wrong representation. Aegis: cheap defense-in-depth.
    resp.headers["Vary"] = "Accept"
    return resp


# ---- Canonical site URL ----
# Used for absolute links in /feed.xml. NEVER derived from the Host header
# (attacker-controlled). Staging and production must each set their own
# canonical URL via the SITE_URL env var. Fail fast if unset rather than
# silently emitting prod URLs from a staging/dev deploy.
_SITE_URL_ENV = os.environ.get("SITE_URL", "").strip()
if not _SITE_URL_ENV:
    raise RuntimeError(
        "SITE_URL env var is required (e.g. https://threat-feed.ai "
        "for prod, http://localhost:5000 for local dev)."
    )
SITE_URL = _SITE_URL_ENV.rstrip("/")


# ---- Content negotiation: Markdown for agents ----
# When Accept: text/markdown is present, API routes can return markdown
# instead of JSON. This lets LLM agents consume structured content without
# parsing JSON. HTML remains the default for browsers.


def _wants_markdown():
    """Return True if the client prefers text/markdown."""
    accept = request.headers.get("Accept", "")
    return "text/markdown" in accept


def _articles_to_markdown(articles):
    """Convert a list of article dicts to a readable markdown document."""
    lines = [f"# Threat-Feed Articles ({len(articles)} results)\n"]
    for a in articles:
        lines.append(f"## {a.get('title', 'Untitled')}\n")
        lines.append(f"- **Source:** {a.get('source_name', 'Unknown')}")
        lines.append(f"- **Category:** {a.get('category', 'Uncategorized')}")
        lines.append(
            f"- **Published:** {a.get('published_date', a.get('created_at', 'Unknown'))}"
        )
        lines.append(f"- **Confidence:** {a.get('confidence', 'N/A')}")
        lines.append(f"- **URL:** {a.get('url', '')}")
        summary = a.get("summary", "")
        if summary:
            lines.append(f"\n{summary[:300]}")
        lines.append("")
    return "\n".join(lines)


def _briefing_to_markdown(briefing):
    """Convert a briefing dict to markdown."""
    if not briefing.get("active"):
        return "# Daily Briefing\n\n*No active briefing.*\n"
    lines = [
        f"# Daily Briefing\n",
        f"*Generated: {briefing.get('generated_at', 'Unknown')}*\n",
        "## Action Items\n",
    ]
    for action in briefing.get("actions", []):
        sev = action.get("severity", "medium").upper()
        lines.append(f"### [{sev}] {action.get('title', '')}\n")
        lines.append(f"{action.get('description', '')}\n")
        if action.get("action"):
            lines.append(f"**Action:** {action['action']}\n")
    if briefing.get("stats"):
        lines.append("## Stats\n")
        for s in briefing["stats"]:
            hot = " 🔥" if s.get("hot") else ""
            lines.append(f"- **{s.get('label', '')}:** {s.get('value', 0)}{hot}")
    return "\n".join(lines)


def _top_story_to_markdown(story):
    """Convert a top story dict to markdown."""
    if not story.get("active"):
        return "# Top Story\n\n*No active top story.*\n"
    lines = [
        f"# Top Story: {story.get('title', '')}\n",
        f"- **Source:** {story.get('source_name', '')}",
        f"- **Category:** {story.get('category', '')}",
        f"- **Published:** {story.get('published_at', '')}",
        f"- **Confidence:** {story.get('confidence', '')}",
        f"- **URL:** {story.get('url', '')}\n",
        f"{story.get('summary', '')}\n",
    ]
    if story.get("key_points"):
        lines.append("## Key Points\n")
        for p in story["key_points"]:
            lines.append(f"- {p}")
    return "\n".join(lines)


def _homepage_to_markdown(articles):
    """Convert the homepage to a markdown document for agent consumption.

    Provides site context (what this is, available endpoints) plus the
    latest articles — everything an LLM agent needs in a single request.
    """
    lines = [
        "# Threat-Feed — Open Source Threat Intelligence\n",
        "Real-time cybersecurity news aggregated from 46 public RSS feeds,",
        "classified into 14 security categories. Updated hourly.\n",
        "## Available Endpoints\n",
        f"- **Articles API:** {SITE_URL}/api/articles"
        " (supports `?category=`, `?since=`)",
        f"- **Categories:** {SITE_URL}/api/categories",
        f"- **Top Story:** {SITE_URL}/api/top-story",
        f"- **Daily Briefing:** {SITE_URL}/api/briefing",
        f"- **Threat Context:** {SITE_URL}/api/threat-context",
        f"- **Atom Feed:** {SITE_URL}/feed.xml",
        f"- **API Catalog:** {SITE_URL}/api\n",
        "All API endpoints accept `Accept: text/markdown` for"
        " markdown-formatted responses.\n",
        f"## Latest Articles ({len(articles)} most recent)\n",
    ]
    for a in articles:
        title = a.get("title", "Untitled")
        url = a.get("url", "")
        source = a.get("source_name", "Unknown")
        category = a.get("category", "Uncategorized")
        published = a.get("published_date") or a.get("created_at", "Unknown")
        lines.append(f"### {title}\n")
        lines.append(f"- **Source:** {source}")
        lines.append(f"- **Category:** {category}")
        lines.append(f"- **Published:** {published}")
        if url:
            lines.append(f"- **URL:** {url}")
        summary = a.get("summary", "")
        if summary:
            lines.append(f"\n{summary[:300]}")
        lines.append("")
    return "\n".join(lines)


def _categories_to_markdown(categories):
    """Convert categories list to markdown."""
    lines = ["# Categories\n", "| Category | Count |", "|---|---|"]
    for c in categories:
        lines.append(f"| {c.get('category', '')} | {c.get('count', 0)} |")
    return "\n".join(lines)


def _md_response(content):
    """Return a text/markdown response with standard caching."""
    resp = app.response_class(content, mimetype="text/markdown; charset=utf-8")
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


# ---- API catalog and agent discovery ----

_API_CATALOG = {
    "name": "Threat-Feed API",
    "version": "1.0",
    "base_url": "https://threat-feed.ai",
    "description": "Real-time cybersecurity intelligence aggregator — 46 public RSS sources, keyword-classified, confidence-rated.",
    "content_negotiation": {
        "default": "application/json",
        "supported": ["application/json", "text/markdown"],
        "usage": "Set Accept: text/markdown header to receive markdown-formatted responses instead of JSON.",
    },
    "endpoints": [
        {
            "path": "/api/articles",
            "method": "GET",
            "description": "Search recent security articles by time range and category.",
            "parameters": {
                "since": {"type": "string", "format": "ISO 8601", "required": False, "description": "Only articles published on or after this date"},
                "category": {"type": "string", "required": False, "description": "Filter by exact category name"},
            },
            "rate_limit": "30/min",
            "response": "Array of article objects (up to 500)",
            "accepts": ["application/json", "text/markdown"],
        },
        {
            "path": "/api/top-story",
            "method": "GET",
            "description": "Operator-curated lead story with key points and confidence rating.",
            "parameters": {},
            "rate_limit": "60/min",
            "response": "Object with active flag, title, summary, key_points, confidence",
            "accepts": ["application/json", "text/markdown"],
        },
        {
            "path": "/api/briefing",
            "method": "GET",
            "description": "Daily threat briefing with prioritized action items and stats.",
            "parameters": {},
            "rate_limit": "60/min",
            "response": "Object with actions (severity/title/description/action) and stats",
            "accepts": ["application/json", "text/markdown"],
        },
        {
            "path": "/api/threat-context",
            "method": "GET",
            "description": "Rolling threat landscape context — active CVEs, trending techniques, campaigns.",
            "parameters": {},
            "rate_limit": "60/min",
            "response": "Object with landscape_summary, stack_cves, trending_techniques, active_campaigns",
            "accepts": ["application/json", "text/markdown"],
        },
        {
            "path": "/api/categories",
            "method": "GET",
            "description": "Category names with article counts.",
            "parameters": {},
            "rate_limit": "60/min",
            "response": "Array of {category, count} objects",
            "accepts": ["application/json", "text/markdown"],
        },
        {
            "path": "/feed.xml",
            "method": "GET",
            "description": "Atom 1.0 feed of the 50 most-recent articles.",
            "parameters": {},
            "rate_limit": "30/min",
            "response": "Atom XML",
            "accepts": ["application/atom+xml"],
        },
    ],
}

_AGENT_MANIFEST = {
    "schema_version": "1.0",
    "name": "Threat-Feed",
    "description": "Real-time cybersecurity intelligence aggregator. Ingests 46 public RSS sources hourly, classifies by threat category, assigns confidence ratings. No auth required.",
    "base_url": "https://threat-feed.ai",
    "capabilities": ["search", "briefing", "categorization", "threat-context", "feed"],
    "tools": [
        {
            "name": "search_articles",
            "description": "Search recent cybersecurity articles by time range and/or category. Returns up to 500 results sorted by recency.",
            "endpoint": "/api/articles",
            "method": "GET",
            "parameters": {
                "since": {"type": "string", "format": "ISO 8601", "description": "Cutoff date — only articles after this timestamp"},
                "category": {"type": "string", "description": "Exact category name to filter by"},
            },
            "accepts": ["application/json", "text/markdown"],
            "use_when": "Agent needs current threat intel, wants to check if a CVE or threat actor is being reported on, needs to assess today's threat landscape, or wants to verify a security claim against recent reporting.",
        },
        {
            "name": "get_top_story",
            "description": "Get the operator-curated lead story — the single most significant developing threat right now.",
            "endpoint": "/api/top-story",
            "method": "GET",
            "parameters": {},
            "accepts": ["application/json", "text/markdown"],
            "use_when": "Agent needs to know the single most important cybersecurity story right now, or wants to brief a user on the top threat.",
        },
        {
            "name": "get_briefing",
            "description": "Get the daily threat briefing — prioritized action items with severity ratings and stats.",
            "endpoint": "/api/briefing",
            "method": "GET",
            "parameters": {},
            "accepts": ["application/json", "text/markdown"],
            "use_when": "Agent needs a prioritized daily security digest, action items for a security team, or a quick threat summary for a morning briefing.",
        },
        {
            "name": "get_threat_context",
            "description": "Get rolling threat landscape context — active CVEs, trending attacker techniques, named campaigns, and stack-specific alerts.",
            "endpoint": "/api/threat-context",
            "method": "GET",
            "parameters": {},
            "accepts": ["application/json", "text/markdown"],
            "use_when": "Agent is performing security review, needs to understand the current threat landscape before making recommendations, or wants to correlate a finding against known active campaigns.",
        },
        {
            "name": "get_categories",
            "description": "Get all threat categories with article counts — shows the distribution of current reporting.",
            "endpoint": "/api/categories",
            "method": "GET",
            "parameters": {},
            "accepts": ["application/json", "text/markdown"],
            "use_when": "Agent wants to understand what types of threats are being most reported on, or needs to pick the right category filter for a search.",
        },
    ],
    "authentication": "none",
    "rate_limits": {
        "articles": "30 req/min",
        "other_endpoints": "60 req/min",
        "recommended_polling": "every 15-30 minutes",
    },
    "categories": [
        "Vulnerability/CVE", "OT/ICS", "Malware/Infostealer", "SaaS Breach",
        "AI Security", "Nation State/APT", "Ransomware", "Cloud Security",
        "Supply Chain", "Identity & Access", "Phishing & Social Engineering",
        "Industry/Policy", "Consumer Awareness", "Mobile Security", "Uncategorized",
    ],
    "confidence_levels": {
        "HIGH": "Tier-1: government CERTs, top threat-intel teams",
        "MEDIUM": "Tier-2: established journalism, vendor research blogs",
        "LOW": "Tier-3: community, Reddit, unverified OSINT",
    },
    "related_resources": {
        "llms_txt": "/llms.txt",
        "full_reference": "/llms-full.txt",
        "atom_feed": "/feed.xml",
        "api_catalog": "/api",
        "security_policy": "/.well-known/security.txt",
    },
}


@app.route("/api")
@limiter.limit("60 per minute")
def api_catalog():
    if _wants_markdown():
        lines = [
            "# Threat-Feed API Catalog\n",
            f"**Base URL:** {_API_CATALOG['base_url']}",
            f"**Description:** {_API_CATALOG['description']}\n",
            "## Content Negotiation\n",
            "Set `Accept: text/markdown` to receive markdown responses. Default is JSON.\n",
            "## Endpoints\n",
        ]
        for ep in _API_CATALOG["endpoints"]:
            lines.append(f"### `{ep['method']} {ep['path']}`\n")
            lines.append(f"{ep['description']}\n")
            if ep["parameters"]:
                lines.append("**Parameters:**\n")
                for k, v in ep["parameters"].items():
                    lines.append(f"- `{k}` ({v['type']}) — {v['description']}")
                lines.append("")
            lines.append(f"- Rate limit: {ep['rate_limit']}")
            lines.append(f"- Accepts: {', '.join(ep['accepts'])}\n")
        return _md_response("\n".join(lines))

    resp = jsonify(_API_CATALOG)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@app.route("/.well-known/agent.json")
@limiter.limit("60 per minute")
def agent_json():
    resp = app.response_class(
        json_module.dumps(_AGENT_MANIFEST, indent=2),
        mimetype="application/json",
    )
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


# ---- Bot / agent / AI discoverability ----
# Three cheap static-ish responses that make the site readable to non-JS
# clients (traditional crawlers, LLM indexers, feed readers). Public by
# design — disclose no more than /, /api/articles, /api/top-story, and
# /api/categories already expose.

_ROBOTS_TXT = """\
User-agent: *
Allow: /

Sitemap: https://threat-feed.ai/sitemap.xml

# Machine-readable site description:
#   /llms.txt              — site overview for LLMs
#   /llms-full.txt         — full API reference for LLMs and agents
#   /.well-known/agent.json — agent skill/tool discovery manifest
#   /api                   — API endpoint catalog (JSON or markdown)
#   /feed.xml              — Atom 1.0 feed of aggregated headlines
#   /api/articles, /api/top-story, /api/categories, /api/threat-context — JSON
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
- `/api/threat-context` — JSON object with rolling threat landscape context
  (active CVEs, trending techniques, campaigns, stack alerts). Returns
  `{"active": false}` when no context file is present.

## Polling

Rate limits are per-IP. Well-behaved agents should stay well under these:

- `/feed.xml` — 30 requests per minute
- `/api/articles` — 30 requests per minute
- `/api/top-story` — 60 requests per minute
- `/api/categories` — 60 requests per minute
- `/api/threat-context` — 60 requests per minute
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

### GET /api/threat-context

Rolling threat landscape context for agent consumption.

Response shape (JSON object):
  When active:
    {"active": true, "generated_at": "...", "expires_at": "...",
     "stack_cves": [...], "trending_techniques": [...],
     "active_campaigns": [...], "stack_alerts": [...],
     "landscape_summary": "..."}
  When inactive:
    {"active": false}

### GET /feed.xml

Atom 1.0 feed of the 50 most-recent articles.

## Categories

Vulnerability/CVE, OT/ICS, Malware/Infostealer, SaaS Breach,
AI Security, Nation State/APT, Ransomware, Cloud Security, Supply Chain,
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
  /api/top-story      — 60 req/min
  /api/categories     — 60 req/min
  /api/threat-context — 60 req/min

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
Canonical: https://threat-feed.ai/.well-known/security.txt
"""

_SITEMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://threat-feed.ai/</loc>
    <changefreq>hourly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://threat-feed.ai/feed.xml</loc>
    <changefreq>hourly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://threat-feed.ai/llms.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://threat-feed.ai/llms-full.txt</loc>
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


@app.route("/license")
@limiter.limit("60 per minute")
def license_page():
    license_path = os.path.join(os.path.dirname(__file__), "LICENSE")
    try:
        with open(license_path, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        text = "License file not found."
    response = app.response_class(text, mimetype="text/plain")
    response.headers["Cache-Control"] = "public, max-age=86400"
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
    """Daily rolling prune — delete articles older than 30 days, then
    enforce a hard ceiling (MAX_ARTICLES) on total article count.

    Two layers:
      1. Age-based: remove anything older than 30 days.
      2. Count-based: if total still exceeds MAX_ARTICLES, delete the
         oldest surplus so the DB never grows unbounded.

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

            # Hard ceiling — safety net against feed floods
            total = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
            if total > MAX_ARTICLES:
                surplus = total - MAX_ARTICLES
                conn.execute(
                    """DELETE FROM articles WHERE id IN (
                        SELECT id FROM articles
                        ORDER BY COALESCE(published_date, created_at) ASC
                        LIMIT ?
                    )""",
                    (surplus,),
                )
                print(
                    f"[prune-cap] removed {surplus} oldest articles "
                    f"(was {total}, cap {MAX_ARTICLES})"
                )
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
