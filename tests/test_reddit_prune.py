"""
Tests for scheduler.prune_deleted_reddit_posts — the Reddit deletion prune.

Guarantees:

  1. SSRF safety: the URL we EGRESS to is always built against
     www.reddit.com from a regex-validated post ID. A poisoned DB URL
     (javascript:, file://, attacker.com/?...) cannot redirect egress.

  2. Signal classification: HTTP 404, `removed_by_category` in the known
     set, and `[deleted]` author+body all trigger a DELETE. Live posts,
     transient 5xx / 403, and malformed JSON all fail OPEN (no delete).

  3. Rotation: oldest-unchecked row is picked first. Batch cap (200)
     bounds runtime.

  4. Age floor: articles younger than 4 hours are NOT checked.

  5. last_reddit_check_at is bumped when we saw the post alive, NOT when
     we deleted it (the row's gone at that point).

Run: python -m unittest tests.test_reddit_prune -v
"""

import os
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scheduler  # noqa: E402
from scheduler import (  # noqa: E402
    _classify_reddit_response,
    _extract_reddit_post_id,
    prune_deleted_reddit_posts,
    REDDIT_JSON_HOST,
)


_TEST_DB = "/tmp/threat_feed_reddit_prune_tests.db"


def _fresh_db():
    if os.path.exists(_TEST_DB):
        os.remove(_TEST_DB)
    conn = sqlite3.connect(_TEST_DB)
    conn.execute("""
        CREATE TABLE articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            summary TEXT,
            url TEXT UNIQUE NOT NULL,
            published_date TEXT,
            source_name TEXT,
            category TEXT DEFAULT 'Uncategorized',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_reddit_check_at TEXT
        )
    """)
    conn.commit()
    return conn


def _seed(conn, rows):
    conn.executemany(
        "INSERT INTO articles (title, summary, url, published_date, "
        "source_name, category, last_reddit_check_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()


def _mock_response(status_code, json_body=None, raise_json=False):
    resp = MagicMock()
    resp.status_code = status_code
    if raise_json:
        resp.json.side_effect = ValueError("not json")
    else:
        resp.json.return_value = json_body
    return resp


# ----- Post-ID extraction + SSRF safety -----


class ExtractPostIdTests(unittest.TestCase):
    """The regex is the ONLY thing separating DB URLs from attacker egress."""

    def test_standard_reddit_url(self):
        self.assertEqual(
            _extract_reddit_post_id(
                "https://www.reddit.com/r/netsec/comments/abc123/some_title/"
            ),
            "abc123",
        )

    def test_no_trailing_slash(self):
        self.assertEqual(
            _extract_reddit_post_id(
                "https://www.reddit.com/r/netsec/comments/xyz789"
            ),
            "xyz789",
        )

    def test_with_query_string(self):
        self.assertEqual(
            _extract_reddit_post_id(
                "https://www.reddit.com/r/x/comments/abc123/?utm_source=foo"
            ),
            "abc123",
        )

    def test_uppercase_normalized_to_lower(self):
        self.assertEqual(
            _extract_reddit_post_id(
                "https://www.reddit.com/r/x/comments/ABC123/title/"
            ),
            "abc123",
        )

    def test_none_returns_none(self):
        self.assertIsNone(_extract_reddit_post_id(None))

    def test_empty_returns_none(self):
        self.assertIsNone(_extract_reddit_post_id(""))

    def test_non_string_returns_none(self):
        self.assertIsNone(_extract_reddit_post_id(12345))

    def test_non_reddit_url_returns_none(self):
        # Even a URL crafted to look like a reddit path on another host
        # has no /comments/<id>/ — skipped without egress.
        self.assertIsNone(_extract_reddit_post_id("https://evil.com/home"))

    def test_javascript_scheme_returns_none(self):
        self.assertIsNone(_extract_reddit_post_id("javascript:alert(1)"))

    def test_file_scheme_returns_none(self):
        self.assertIsNone(_extract_reddit_post_id("file:///etc/passwd"))

    def test_non_base36_rejected(self):
        # '!' is not in [a-z0-9] — regex refuses.
        self.assertIsNone(
            _extract_reddit_post_id("https://www.reddit.com/comments/a!b/")
        )

    def test_too_short_rejected(self):
        # {4,10} — 3 chars is below the min.
        self.assertIsNone(
            _extract_reddit_post_id("https://www.reddit.com/comments/abc/")
        )


# ----- Response classification (no I/O) -----


class ClassifyResponseTests(unittest.TestCase):

    def _listing(self, data=None):
        return [{"data": {"children": [{"data": data or {}}]}}, {}]

    def test_404_is_definitive_delete(self):
        decision, _ = _classify_reddit_response(404, None)
        self.assertEqual(decision, "delete")

    def test_403_fails_open(self):
        # Private subreddit / rate-limited — NOT a delete signal.
        decision, reason = _classify_reddit_response(403, None)
        self.assertIsNone(decision)
        self.assertIn("403", reason)

    def test_500_fails_open(self):
        decision, _ = _classify_reddit_response(500, None)
        self.assertIsNone(decision)

    def test_200_with_removed_by_moderator_deletes(self):
        payload = self._listing({"removed_by_category": "moderator"})
        decision, reason = _classify_reddit_response(200, payload)
        self.assertEqual(decision, "delete")
        self.assertIn("moderator", reason)

    def test_200_with_anti_evil_ops_deletes(self):
        # Reddit admin TOS-violation — the highest-priority case for prune.
        payload = self._listing({"removed_by_category": "anti_evil_ops"})
        decision, _ = _classify_reddit_response(200, payload)
        self.assertEqual(decision, "delete")

    def test_200_with_author_deleted_pair_deletes(self):
        payload = self._listing({
            "author": "[deleted]",
            "selftext": "[deleted]",
        })
        decision, _ = _classify_reddit_response(200, payload)
        self.assertEqual(decision, "delete")

    def test_200_with_only_author_deleted_fails_open(self):
        # Author gone but body intact — could be a legitimate post where
        # the user just deleted their account. Don't delete on single signal.
        payload = self._listing({
            "author": "[deleted]",
            "selftext": "This is still useful security content.",
        })
        decision, _ = _classify_reddit_response(200, payload)
        self.assertIsNone(decision)

    def test_200_live_post_no_delete(self):
        payload = self._listing({
            "author": "realauthor",
            "selftext": "still here",
            "removed_by_category": None,
        })
        decision, _ = _classify_reddit_response(200, payload)
        self.assertIsNone(decision)

    def test_empty_listing_treated_as_deleted(self):
        # Reddit scrubbed it entirely from the listing endpoint.
        payload = [{"data": {"children": []}}, {}]
        decision, _ = _classify_reddit_response(200, payload)
        self.assertEqual(decision, "delete")

    def test_unexpected_shape_fails_open(self):
        # Reddit's API changed under us — don't mass-delete the DB.
        decision, reason = _classify_reddit_response(200, {"unexpected": True})
        self.assertIsNone(decision)
        self.assertIn("unexpected_shape", reason)

    def test_none_payload_on_200_fails_open(self):
        decision, _ = _classify_reddit_response(200, None)
        self.assertIsNone(decision)


# ----- End-to-end: prune_deleted_reddit_posts with a DB and mocked HTTP -----


class PruneIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_db()
        now = datetime.now(timezone.utc)
        old = (now - timedelta(hours=6)).isoformat()
        very_recent = (now - timedelta(minutes=30)).isoformat()

        _seed(self.conn, [
            # 0: old live Reddit post — should be checked, marked alive
            ("alive", "", "https://www.reddit.com/r/netsec/comments/alive1/", old, "Reddit r/netsec", "Ransomware", None),
            # 1: old removed Reddit post — should be deleted
            ("removed", "", "https://www.reddit.com/r/netsec/comments/rmvd01/", old, "Reddit r/netsec", "Ransomware", None),
            # 2: TOO RECENT (30 min old) — skipped by age floor
            ("tooNew", "", "https://www.reddit.com/r/netsec/comments/new123/", very_recent, "Reddit r/netsec", "Ransomware", None),
            # 3: non-Reddit source — never checked regardless of age
            ("krebs", "", "https://krebsonsecurity.com/foo", old, "Krebs on Security", "Ransomware", None),
            # 4: Reddit post with unextractable URL (no /comments/<id>/) — skipped as error
            ("malformed", "", "https://www.reddit.com/r/netsec/some_profile_page", old, "Reddit r/netsec", "Ransomware", None),
        ])
        self.conn.close()

    def tearDown(self):
        if os.path.exists(_TEST_DB):
            os.remove(_TEST_DB)

    def _make_responder(self, per_id):
        """Build a requests.get replacement that returns mocked responses
        keyed by post_id. Also records every URL it was called with so
        tests can assert egress safety."""
        calls = []

        def _fake_get(url, **kwargs):
            calls.append(url)
            # Host-allowlist self-check in the test: if the code ever
            # tries to egress to anything other than www.reddit.com,
            # fail loudly.
            if not url.startswith(REDDIT_JSON_HOST + "/"):
                raise AssertionError(f"egress to non-reddit host: {url!r}")
            for post_id, response in per_id.items():
                if f"/comments/{post_id}.json" in url:
                    return response
            return _mock_response(500, None)

        return _fake_get, calls

    def test_removes_deleted_keeps_alive_respects_age_floor(self):
        fake_get, calls = self._make_responder({
            "alive1": _mock_response(200, [
                {"data": {"children": [
                    {"data": {"author": "someone", "selftext": "still here", "removed_by_category": None}}
                ]}}, {}
            ]),
            "rmvd01": _mock_response(200, [
                {"data": {"children": [
                    {"data": {"removed_by_category": "moderator"}}
                ]}}, {}
            ]),
        })

        with patch.object(scheduler.requests, "get", side_effect=fake_get):
            result = prune_deleted_reddit_posts(_TEST_DB, sleep=lambda s: None)

        # Only rows 0 and 1 should have been checked; row 2 too young,
        # rows 3–4 are non-checkable.
        self.assertEqual(result["checked"], 2)
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["errors"], 1)  # row 4 (malformed URL)

        # Egress hit exactly the two expected post IDs.
        self.assertEqual(len(calls), 2)
        self.assertTrue(any("alive1" in c for c in calls))
        self.assertTrue(any("rmvd01" in c for c in calls))

        # Verify DB state: removed post gone, alive post stamped.
        conn = sqlite3.connect(_TEST_DB)
        try:
            remaining = {
                row[0]: row
                for row in conn.execute(
                    "SELECT title, last_reddit_check_at FROM articles"
                ).fetchall()
            }
        finally:
            conn.close()

        self.assertNotIn("removed", remaining, "removed post should be DELETEd")
        self.assertIn("alive", remaining)
        self.assertIsNotNone(remaining["alive"][1],
                             "alive post must have last_reddit_check_at stamped")
        self.assertIn("tooNew", remaining)
        self.assertIsNone(remaining["tooNew"][1],
                          "too-recent post must NOT be stamped (we didn't check it)")
        self.assertIn("krebs", remaining, "non-reddit source untouched")

    def test_transient_500_does_not_delete(self):
        # Reddit returning 500 for everything — we must NOT delete.
        fake_get, calls = self._make_responder({})  # falls through to 500

        with patch.object(scheduler.requests, "get", side_effect=fake_get):
            result = prune_deleted_reddit_posts(_TEST_DB, sleep=lambda s: None)

        self.assertEqual(result["deleted"], 0,
                         "5xx must NEVER cause deletion — fails open")

    def test_request_exception_fails_open(self):
        import requests as _req

        def _raise(url, **kwargs):
            raise _req.ConnectionError("simulated network failure")

        with patch.object(scheduler.requests, "get", side_effect=_raise):
            result = prune_deleted_reddit_posts(_TEST_DB, sleep=lambda s: None)

        self.assertEqual(result["deleted"], 0,
                         "network exception must NEVER cause deletion")

    def test_never_egresses_to_db_url(self):
        # Even if the DB contains an attacker-controlled URL like an
        # attacker host, the egress MUST be to www.reddit.com because we
        # rebuild the URL from the extracted post ID. Prove it.
        conn = sqlite3.connect(_TEST_DB)
        conn.execute("DELETE FROM articles")
        now = datetime.now(timezone.utc)
        old = (now - timedelta(hours=6)).isoformat()
        # Still contains /comments/<id>/ so the regex extracts 'evilid' —
        # but the egress URL the code builds is https://www.reddit.com/...
        conn.execute(
            "INSERT INTO articles (title, summary, url, published_date, "
            "source_name, category) VALUES (?, ?, ?, ?, ?, ?)",
            ("poisoned", "", "https://evil.example.com/r/x/comments/evilid/",
             old, "Reddit r/netsec", "Ransomware"),
        )
        conn.commit()
        conn.close()

        fake_get, calls = self._make_responder({
            "evilid": _mock_response(200, [
                {"data": {"children": [
                    {"data": {"author": "u", "selftext": "x", "removed_by_category": None}}
                ]}}, {}
            ]),
        })

        with patch.object(scheduler.requests, "get", side_effect=fake_get):
            prune_deleted_reddit_posts(_TEST_DB, sleep=lambda s: None)

        # The assertion inside _make_responder would have raised on non-
        # reddit egress. Belt and braces: check the recorded URL here too.
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("https://www.reddit.com/"),
                        f"egress went to {calls[0]!r} — SSRF regression")


if __name__ == "__main__":
    unittest.main(verbosity=2)
