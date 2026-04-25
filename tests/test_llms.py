"""
Smoke tests for /llms.txt — the LLM-readable site overview.

Guarantees:
  * Route returns 200 with text/plain mimetype.
  * Body advertises the three JSON API endpoints + /feed.xml so any LLM
    reading this file can discover the machine-readable surface.
  * Body does NOT leak internal paths, secrets, or admin surfaces.
  * Cache-Control is set.

Run: python -m unittest tests.test_llms -v
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.conftest import get_test_db, patch_db, get_app  # noqa: E402

_TEST_DB = get_test_db("llms")
patch_db(_TEST_DB)

app, init_db = get_app()
init_db()


class LlmsTxtTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_ok_and_plain_text(self):
        resp = self.client.get("/llms.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            resp.mimetype.startswith("text/plain"),
            f"expected text/plain, got {resp.mimetype!r}",
        )

    def test_advertises_every_public_endpoint(self):
        resp = self.client.get("/llms.txt")
        body = resp.data
        for endpoint in (
            b"/feed.xml",
            b"/api/articles",
            b"/api/top-story",
            b"/api/categories",
        ):
            self.assertIn(
                endpoint, body,
                f"llms.txt must advertise {endpoint!r} — otherwise LLMs can't discover it",
            )

    def test_states_republication_policy(self):
        # Editorial stance the operator chose — surface to any LLM that reads
        # the site so it's on the record, not implicit.
        resp = self.client.get("/llms.txt")
        self.assertIn(b"Republication", resp.data)

    def test_no_sensitive_path_disclosure(self):
        resp = self.client.get("/llms.txt")
        body = resp.data.lower()
        for forbidden in (
            b"testfeed.db",
            b"/data/",
            b"/admin",
            b".env",
            b"-journal",
            b"-wal",
            b"api_key",
            b"secret",
            b"password",
        ):
            self.assertNotIn(
                forbidden, body,
                f"llms.txt leaks sensitive token {forbidden!r}",
            )

    def test_cache_control_set(self):
        resp = self.client.get("/llms.txt")
        self.assertIn("max-age", resp.headers.get("Cache-Control", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
