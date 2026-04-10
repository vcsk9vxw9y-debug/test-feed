import os
import sqlite3

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Use /data for Railway persistent volume, fallback to local
DB_PATH = "/data/testfeed.db" if os.path.exists("/data") else "./testfeed.db"


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
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
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_articles_category_created_at "
        "ON articles(category, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_articles_published_date "
        "ON articles(published_date DESC)"
    )
    conn.commit()
    conn.close()


init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/articles")
def get_articles():
    category = request.args.get("category")
    conn = get_db()
    try:
        if category and category != "All":
            rows = conn.execute(
                """
                SELECT * FROM articles
                WHERE category = ?
                ORDER BY datetime(published_date) DESC, created_at DESC
                LIMIT 200
                """,
                (category,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM articles
                ORDER BY datetime(published_date) DESC, created_at DESC
                LIMIT 200
                """
            ).fetchall()
    finally:
        conn.close()
    return jsonify([dict(row) for row in rows])


@app.route("/api/categories")
def get_categories():
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT category, COUNT(*) as count
            FROM articles
            GROUP BY category
            ORDER BY count DESC, category ASC
            """
        ).fetchall()
    finally:
        conn.close()
    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
