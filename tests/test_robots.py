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

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.conftest import get_test_db, patch_db, get_app  # noqa: E402

_TEST_DB = get_test_db("robots")
patch_db(_TEST_DB)

app, init_db = get_app()
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
