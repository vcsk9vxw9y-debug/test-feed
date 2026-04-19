"""
Smoke tests for /robots.txt.

Guarantees:
  * Route returns 200 with text/plain mimetype.
  * Body contains a standards-compliant User-agent: * directive.
  * Body does NOT leak internal paths or secrets (testfeed.db, /data/,
    /admin, .env, SQLite journal/WAL files).
  * Cache-Control is set so well-behaved crawlers don't hammer origin.

Run: python -m unittest tests.test_robots -v
"""

import os
import sqlite3
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Shared sandbox DB path across the three bot-readability test modules.
_TEST_DB = "/tmp/threat_feed_bot_readability_tests.db"

if os.path.exists(_TEST_DB):
    try:
        os.remove(_TEST_DB)
    except OSError:
        pass

_orig_connect = sqlite3.connect


def _redirect(path, *args, **kwargs):
    if path in ("./testfeed.db", "/data/testfeed.db"):
        path = _TEST_DB
    return _orig_connect(path, *args, **kwargs)


sqlite3.connect = _redirect

# Stub the feed fetcher so importing app doesn't trigger a real network run.
import scheduler  # noqa: E402
scheduler.fetch_all_feeds = lambda *a, **kw: None

from app import app, init_db  # noqa: E402
init_db()


class RobotsTxtTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_ok_and_plain_text(self):
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            resp.mimetype.startswith("text/plain"),
            f"expected text/plain, got {resp.mimetype!r}",
        )

    def test_contains_user_agent_all(self):
        resp = self.client.get("/robots.txt")
        self.assertIn(b"User-agent: *", resp.data)

    def test_no_sensitive_path_disclosure(self):
        # robots.txt is public — must not reveal internals that would help
        # an attacker enumerate the deployment.
        resp = self.client.get("/robots.txt")
        body = resp.data.lower()
        for forbidden in (
            b"testfeed.db",
            b"/data/",
            b"/admin",
            b".env",
            b"-journal",
            b"-wal",
            b"config/",
        ):
            self.assertNotIn(
                forbidden, body,
                f"robots.txt leaks sensitive token {forbidden!r}",
            )

    def test_cache_control_set(self):
        resp = self.client.get("/robots.txt")
        self.assertIn("max-age", resp.headers.get("Cache-Control", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
