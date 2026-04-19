import atexit
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from classifier import classify_article
from confidence import build_source_info_index, resolve_confidence, UNSET
from scheduler import FEEDS, fetch_all_feeds

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
    default_limits=[],  # No blanket limit — set per-route below
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
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

        # One-time: re-run the classifier against every Uncategorized article
        # after PR 1.5's keyword expansion. Only promotes rows out of
        # Uncategorized — never demotes a real category. Safe to remove in the
        # release after this one ships.
        already_ran = conn.execute(
            "SELECT 1 FROM migrations WHERE name = 'reclassify_uncategorized_v1'"
        ).fetchone()
        if not already_ran:
            rows = conn.execute(
                "SELECT id, title, summary FROM articles WHERE category = 'Uncategorized'"
            ).fetchall()
            reclassified = 0
            for row in rows:
                new_category = classify_article(row["title"], row["summary"])
                if new_category != "Uncategorized":
                    conn.execute(
                        "UPDATE articles SET category = ? WHERE id = ?",
                        (new_category, row["id"]),
                    )
                    reclassified += 1
            print(f"[reclassify_uncategorized_v1] promoted {reclassified} articles")
            conn.execute(
                "INSERT INTO migrations (name, run_at) VALUES (?, ?)",
                ("reclassify_uncategorized_v1", datetime.now(timezone.utc).isoformat()),
            )

        # One-time: re-run classifier against Uncategorized after PR 2's
        # Industry/Policy addition. Same one-way promotion guarantee as v1.
        already_ran_v2 = conn.execute(
            "SELECT 1 FROM migrations WHERE name = 'reclassify_uncategorized_v2'"
        ).fetchone()
        if not already_ran_v2:
            rows = conn.execute(
                "SELECT id, title, summary FROM articles WHERE category = 'Uncategorized'"
            ).fetchall()
            reclassified = 0
            for row in rows:
                new_category = classify_article(row["title"], row["summary"])
                if new_category != "Uncategorized":
                    conn.execute(
                        "UPDATE articles SET category = ? WHERE id = ?",
                        (new_category, row["id"]),
                    )
                    reclassified += 1
            print(f"[reclassify_uncategorized_v2] promoted {reclassified} articles")
            conn.execute(
                "INSERT INTO migrations (name, run_at) VALUES (?, ?)",
                ("reclassify_uncategorized_v2", datetime.now(timezone.utc).isoformat()),
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
    return response


@app.route("/")
def index():
    return render_template("index.html")


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

    return jsonify([_enrich_with_confidence(dict(row)) for row in rows])


@app.route("/api/stats")
@limiter.limit("60 per minute")
def get_stats():
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT value FROM stats WHERE key = 'total_processed'"
        ).fetchone()
    finally:
        conn.close()
    return jsonify({"total_processed": row["value"] if row else 0})


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

    return jsonify([dict(row) for row in rows])


# Runs on every startup — gunicorn workers and direct python invocation alike
init_db()
fetch_all_feeds(DB_PATH)

scheduler = BackgroundScheduler()
scheduler.add_job(fetch_all_feeds, "interval", hours=4, args=[DB_PATH])
scheduler.start()
atexit.register(lambda: scheduler.shutdown(wait=False))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
