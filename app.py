import os
import sqlite3
from flask import Flask, jsonify, render_template, request
from apscheduler.schedulers.background import BackgroundScheduler
from scheduler import fetch_all_feeds

app = Flask(__name__)

# Use /data for Railway persistent volume, fallback to local
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
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/articles")
def get_articles():
    category = request.args.get("category")
    conn = get_db()
    if category and category != "All":
        rows = conn.execute(
            "SELECT * FROM articles WHERE category = ? ORDER BY created_at DESC LIMIT 200",
            (category,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM articles ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route("/api/categories")
def get_categories():
    conn = get_db()
    rows = conn.execute(
        "SELECT category, COUNT(*) as count FROM articles GROUP BY category ORDER BY count DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


# This runs whether started by gunicorn or python directly
init_db()
fetch_all_feeds(DB_PATH)

scheduler = BackgroundScheduler()
scheduler.add_job(fetch_all_feeds, "interval", hours=4, args=[DB_PATH])
scheduler.start()


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
