"""Tests for scheduler.fetch_all_feeds.

Covers two recently-fixed bugs:

1. ``new_count`` must only increment on actual inserts — INSERT OR IGNORE
   on a duplicate URL should NOT bump the counter. Prior to the fix, the
   per-feed "Saved N new articles" log and stats counter diverged on dupes.

2. On exception during feed fetch, the log line must include the offending
   feed URL alongside the feed name, so operators can tell *which* endpoint
   is broken without cross-referencing FEEDS.
"""

import io
import os
import sqlite3
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scheduler  # noqa: E402

# Captured in tests/__init__.py before any test module stubs it.
_REAL_FETCH_ALL_FEEDS = scheduler._REAL_FETCH_ALL_FEEDS


SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    summary TEXT,
    url TEXT UNIQUE NOT NULL,
    published_date TEXT,
    source_name TEXT,
    category TEXT DEFAULT 'Uncategorized',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS stats (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO stats (key, value) VALUES ('total_processed', 0);
"""


def _make_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


class _FakeResponse:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content


class _FakeParsed:
    def __init__(self, entries):
        self.entries = entries
        self.bozo = 0
        self.bozo_exception = None


def _entry(url, title="T", summary="S"):
    return {
        "link": url,
        "title": title,
        "summary": summary,
        "published_parsed": None,
        "updated_parsed": None,
    }


class NewCountOnlyCountsInsertsTest(unittest.TestCase):
    """new_count must NOT increment when INSERT OR IGNORE skips a duplicate."""

    def setUp(self):
        self.db = "/tmp/testfeed_fetch_all_feeds.db"
        if os.path.exists(self.db):
            os.unlink(self.db)
        _make_db(self.db)

        self.feeds = [
            {
                "url": "https://example.test/feed",
                "name": "ExampleFeed",
                "source_tier": 2,
                "reason": "test",
            }
        ]

    def _run_once(self, entries):
        with patch.object(scheduler, "FEEDS", self.feeds), \
             patch.object(scheduler, "requests") as req, \
             patch.object(scheduler, "feedparser") as fp:
            req.get.return_value = _FakeResponse(200, b"<rss/>")
            fp.parse.return_value = _FakeParsed(entries)
            buf = io.StringIO()
            with redirect_stdout(buf):
                _REAL_FETCH_ALL_FEEDS(self.db)
            return buf.getvalue()

    def test_duplicate_second_pass_does_not_inflate_saved_count(self):
        entries = [_entry("https://example.test/a1")]

        # First pass: 1 insert.
        out1 = self._run_once(entries)
        self.assertIn("Saved 1 new articles", out1)

        # Second pass: same URL. Existing-row short-circuit on line ~496
        # skips the INSERT entirely, so new_count stays 0.
        out2 = self._run_once(entries)
        self.assertIn("Saved 0 new articles", out2)

        # Stats counter should also be 1, not 2.
        conn = sqlite3.connect(self.db)
        try:
            (value,) = conn.execute(
                "SELECT value FROM stats WHERE key = 'total_processed'"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(value, 1)


class ExceptionLogsFeedUrlTest(unittest.TestCase):
    """On fetch failure, the error log must include the feed URL, not just the name."""

    def setUp(self):
        self.db = "/tmp/testfeed_fetch_all_feeds_errlog.db"
        if os.path.exists(self.db):
            os.unlink(self.db)
        _make_db(self.db)

        self.feeds = [
            {
                "url": "https://broken.example/feed",
                "name": "BrokenSource",
                "source_tier": 3,
                "reason": "test",
            }
        ]

    def test_exception_log_includes_url(self):
        with patch.object(scheduler, "FEEDS", self.feeds), \
             patch.object(scheduler, "requests") as req:
            req.get.side_effect = RuntimeError("connection reset")
            buf = io.StringIO()
            with redirect_stdout(buf):
                _REAL_FETCH_ALL_FEEDS(self.db)
            output = buf.getvalue()

        self.assertIn("BrokenSource", output)
        self.assertIn("https://broken.example/feed", output)
        self.assertIn("RuntimeError", output)
        self.assertIn("connection reset", output)


if __name__ == "__main__":
    unittest.main()
