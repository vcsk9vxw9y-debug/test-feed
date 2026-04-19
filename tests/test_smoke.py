"""
Smoke test — Flask test_client, no network, no real RSS fetch.

Port of the standalone smoke_task4.py into the unittest harness so CI can
run the whole suite with one command:

    python -m unittest discover -s tests -v

Strategy: the original app.py hard-codes its SQLite path and kicks off a
background RSS scheduler on import. This file:

  1. Monkey-patches ``sqlite3.connect`` before importing ``app`` so any
     connection to ``./testfeed.db`` or ``/data/testfeed.db`` is rerouted
     to ``/tmp/testfeed_smoke.db`` (the sandboxed bindfs can't do SQLite
     journaling in the repo dir).
  2. Stubs ``scheduler.fetch_all_feeds`` to a no-op so no real feeds are hit.
  3. Seeds a small fixture of three articles covering the Confidence
     mapping cases we care about: Tier 2 (The Hacker News -> MEDIUM) and
     two unknown sources (should fall back to LOW).
  4. Imports ``app`` once at module load; every test method uses the same
     Flask test_client.

What this covers:
  - v4.1 template markers (masthead, self-hosted style.css, etc.)
  - CSP hardening (no fonts.googleapis.com, self-only style/font)
  - Static asset routes (CSS, JS, woff2 fonts)
  - /api/articles JSON shape + Confidence derivation + fail-secure LOW
  - /api/top-story inactive default
  - CONFIDENCE_ENABLED=false kill-switch

What this does NOT cover:
  - Whether fonts visually render in a real browser
  - JS runtime behavior (unit-testing that would need a headless browser)
"""

import os
import sqlite3
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# --- Module-level setup must run BEFORE `import app` --------------------

SMOKE_DB = "/tmp/testfeed_smoke.db"
if os.path.exists(SMOKE_DB):
    os.unlink(SMOKE_DB)

# Redirect any connection the app opens to our throwaway /tmp DB.
_real_connect = sqlite3.connect


def _patched_connect(path, *a, **kw):
    if path in ("./testfeed.db", "/data/testfeed.db"):
        path = SMOKE_DB
    return _real_connect(path, *a, **kw)


sqlite3.connect = _patched_connect

# Stub the scheduler so importing app doesn't hit real RSS.
import scheduler as _real_scheduler  # noqa: E402

_real_scheduler.fetch_all_feeds = lambda *a, **kw: None

# Seed the fixture DB via the patched connect (lands at SMOKE_DB).
_seed = sqlite3.connect("./testfeed.db")
_seed.execute(
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
_seed.executemany(
    "INSERT OR IGNORE INTO articles "
    "(title, summary, url, published_date, source_name, category) "
    "VALUES (?,?,?,?,?,?)",
    [
        (
            "CVE-2026-1234: RCE in Acme Gateway",
            "Critical RCE affecting Acme Gateway versions before 4.2.",
            "https://example.test/a1",
            "2026-04-17T10:00:00Z",
            "The Hacker News",
            "Vulnerabilities",
        ),
        (
            "Ransomware group hits European bank",
            "LockBit affiliate claims breach of EuroBank.",
            "https://example.test/a2",
            "2026-04-17T09:00:00Z",
            "BleepingComputer",
            "Ransomware",
        ),
        (
            "CISA issues advisory on SCADA vendor",
            "New ICSA on Siemens S7 line.",
            "https://example.test/a3",
            "2026-04-17T08:00:00Z",
            "CISA",
            "OT/ICS/Critical Infra",
        ),
    ],
)
_seed.commit()
_seed.close()

# Now safe to import — init_db() will find the seeded articles table.
import app as app_module  # noqa: E402

_app = app_module.app
_app.config["TESTING"] = True
_client = _app.test_client()


class IndexTemplateTests(unittest.TestCase):
    """v4.1 visual port — template markers and removed count pill."""

    @classmethod
    def setUpClass(cls):
        cls.r = _client.get("/")
        cls.html = cls.r.get_data(as_text=True)

    def test_index_returns_200(self):
        self.assertEqual(self.r.status_code, 200)

    def test_masthead_present(self):
        self.assertIn('class="masthead"', self.html)

    def test_brand_slash_present(self):
        self.assertIn('<span class="slash">//</span>', self.html)

    def test_operational_indicator(self):
        self.assertIn(">Operational<", self.html)

    def test_self_hosted_stylesheet(self):
        self.assertIn('href="/static/style.css"', self.html)

    def test_main_js_deferred(self):
        self.assertIn('src="/static/main.js"', self.html)
        self.assertIn("defer", self.html)

    def test_lead_container_reserved(self):
        self.assertIn('id="lead-container"', self.html)
        self.assertIn("hidden", self.html)

    def test_article_list_section(self):
        self.assertIn('id="article-list"', self.html)

    def test_date_range_control(self):
        self.assertIn('id="date-range"', self.html)

    def test_source_filter_control(self):
        self.assertIn('id="source-filter"', self.html)

    def test_aegis_contributor_badge(self):
        self.assertIn('class="aegis"', self.html)

    def test_count_pill_removed(self):
        # PR 3 Task 4 removed the front-page article-count pill per the
        # count-disclosure policy. See SECURITY.md.
        self.assertNotIn("article-count", self.html)

    def test_no_google_fonts_reference(self):
        self.assertNotIn("fonts.googleapis.com", self.html)


class SecurityHeaderTests(unittest.TestCase):
    """Aegis B3 — the tightened CSP must not regress."""

    @classmethod
    def setUpClass(cls):
        cls.csp = _client.get("/").headers.get("Content-Security-Policy", "")

    def test_csp_header_present(self):
        self.assertTrue(self.csp)

    def test_csp_style_src_self_only(self):
        self.assertIn("style-src 'self';", self.csp)

    def test_csp_font_src_self_only(self):
        self.assertIn("font-src 'self';", self.csp)

    def test_csp_no_google_fonts(self):
        self.assertNotIn("fonts.googleapis.com", self.csp)

    def test_csp_no_gstatic(self):
        self.assertNotIn("fonts.gstatic.com", self.csp)

    def test_csp_default_src_none(self):
        self.assertIn("default-src 'none'", self.csp)


class StaticAssetTests(unittest.TestCase):
    """Self-hosted assets resolve and sniff correctly."""

    def _assert_asset(self, path, sniff):
        r = _client.get(path)
        self.assertEqual(r.status_code, 200, f"{path} -> {r.status_code}")
        self.assertIn(sniff, r.get_data(), f"{path} missing sniff {sniff!r}")

    def test_stylesheet(self):
        self._assert_asset("/static/style.css", b"--bg")

    def test_main_js(self):
        self._assert_asset("/static/main.js", b"categoryMap")

    def test_inter_font(self):
        self._assert_asset("/static/fonts/inter.woff2", b"wOF2")

    def test_jetbrains_font(self):
        self._assert_asset("/static/fonts/jetbrains.woff2", b"wOF2")


class ArticlesApiTests(unittest.TestCase):
    """Shape + Confidence derivation on the seeded fixture."""

    @classmethod
    def setUpClass(cls):
        cls.r = _client.get("/api/articles")
        cls.payload = cls.r.get_json()
        cls.articles = (
            cls.payload
            if isinstance(cls.payload, list)
            else cls.payload.get("articles", [])
        )
        cls.by_source = {a["source_name"]: a for a in cls.articles}

    def test_articles_returns_200(self):
        self.assertEqual(self.r.status_code, 200)

    def test_seeded_articles_present(self):
        self.assertIsInstance(self.articles, list)
        self.assertGreaterEqual(len(self.articles), 3)

    def test_article_has_expected_keys(self):
        expected = {"title", "url", "source_name", "category",
                    "confidence", "confidence_reason"}
        self.assertTrue(
            expected.issubset(self.articles[0].keys()),
            f"missing={expected - set(self.articles[0].keys())}",
        )

    def test_hacker_news_resolves_to_medium(self):
        # "The Hacker News" is Tier 2 in scheduler.FEEDS.
        thn = self.by_source.get("The Hacker News")
        self.assertIsNotNone(thn)
        self.assertEqual(thn["confidence"], "MEDIUM")

    def test_medium_article_has_nonempty_reason(self):
        thn = self.by_source.get("The Hacker News")
        self.assertTrue(thn.get("confidence_reason"))

    def test_unknown_source_resolves_to_low_fail_secure(self):
        # The seed intentionally uses "BleepingComputer" and "CISA" —
        # neither of those exact strings appears in FEEDS by that name
        # (the FEEDS entries use different canonical names). Both must
        # fall back to LOW per the fail-secure default.
        for name in ("BleepingComputer", "CISA"):
            with self.subTest(source=name):
                art = self.by_source.get(name)
                self.assertIsNotNone(art)
                self.assertEqual(art["confidence"], "LOW")


class TopStoryApiTests(unittest.TestCase):
    """The shipped YAML is active:false — the "nothing curated" state."""

    @classmethod
    def setUpClass(cls):
        cls.r = _client.get("/api/top-story")
        cls.payload = cls.r.get_json()

    def test_top_story_returns_200(self):
        self.assertEqual(self.r.status_code, 200)

    def test_top_story_payload_is_dict(self):
        self.assertIsInstance(self.payload, dict)

    def test_shipped_top_story_is_inactive(self):
        self.assertIs(self.payload.get("active"), False)

    def test_inactive_payload_has_no_leaked_fields(self):
        # Fail-closed: an inactive payload must surface ONLY {active: False}
        # — no title/summary/url leakage from a half-validated YAML.
        self.assertEqual(set(self.payload.keys()), {"active"})


class KillSwitchTests(unittest.TestCase):
    """CONFIDENCE_ENABLED=false -> every article emits UNSET."""

    def setUp(self):
        self._saved = os.environ.pop("CONFIDENCE_ENABLED", None)

    def tearDown(self):
        os.environ.pop("CONFIDENCE_ENABLED", None)
        if self._saved is not None:
            os.environ["CONFIDENCE_ENABLED"] = self._saved

    def test_disabled_flag_marks_all_articles_unset(self):
        os.environ["CONFIDENCE_ENABLED"] = "false"
        r = _client.get("/api/articles")
        data = r.get_json()
        articles = data if isinstance(data, list) else data.get("articles", [])
        self.assertTrue(articles)
        for a in articles:
            with self.subTest(source=a.get("source_name")):
                self.assertEqual(a.get("confidence"), "UNSET")


def tearDownModule():
    """Clean up the /tmp smoke DB after the whole module runs."""
    try:
        os.unlink(SMOKE_DB)
    except OSError:
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
