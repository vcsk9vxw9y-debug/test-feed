import os
import sqlite3
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request
from apscheduler.schedulers.background import BackgroundScheduler
from scheduler import fetch_all_feeds

app = Flask(__name__)

# Use Railway's persistent volume when available, otherwise local
DB_PATH = "/data/testfeed.db" if os.path.exists("/data") else "./testfeed.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

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

    # One-time: purge uncategorized articles accumulated before feed-level
    # filtering was introduced. Safe to remove this block in the next release.
    already_ran = conn.execute(
        "SELECT 1 FROM migrations WHERE name = 'cleanup_uncategorized_v1'"
    ).fetchone()
    if not already_ran:
        conn.execute("DELETE FROM articles WHERE category = 'Uncategorized'")
        conn.execute(
            "INSERT INTO migrations (name, run_at) VALUES (?, ?)",
            ("cleanup_uncategorized_v1", datetime.now(timezone.utc).isoformat()),
        )

    conn.commit()
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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/articles")
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
    rows = conn.execute(
        f"SELECT * FROM articles {where} "
        "ORDER BY COALESCE(published_date, created_at) DESC LIMIT 500",
        params,
    ).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/categories")
def get_categories():
    conn = get_db()
    rows = conn.execute(
        "SELECT category, COUNT(*) as count FROM articles "
        "GROUP BY category ORDER BY count DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


# Runs on every startup — gunicorn workers and direct python invocation alike
init_db()
fetch_all_feeds(DB_PATH)

scheduler = BackgroundScheduler()
scheduler.add_job(fetch_all_feeds, "interval", hours=4, args=[DB_PATH])
scheduler.start()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
