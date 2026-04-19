"""
Tests for /feed.xml — Atom 1.0 output.

Guarantees — the security-critical ones first:

  1. CDATA safety: a title that contains ']]>' or '<script>' must NOT
     break XML well-formedness and must NOT be parsed as markup by the
     consumer. The ']]>' sequence must be split into two CDATA sections.

  2. XML well-formedness: the response MUST parse with a strict XML
     parser. A hostile source feed cannot produce a feed.xml that
     crashes a standards-compliant reader.

  3. Size bound: at most 50 entries regardless of DB row count.

  4. Self-link + atom namespace are present so feed readers can
     correctly identify and subscribe.

  5. Cache-Control header is set.

Run: python -m unittest tests.test_feed_xml -v
"""

import os
import sqlite3
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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

import scheduler  # noqa: E402
scheduler.fetch_all_feeds = lambda *a, **kw: None

from app import app, init_db  # noqa: E402
init_db()

ATOM_NS = "{http://www.w3.org/2005/Atom}"


def _seed_articles(rows):
    """Insert raw rows directly into the sandbox DB used by the test app."""
    conn = _orig_connect(_TEST_DB)
    try:
        conn.executemany(
            "INSERT INTO articles (title, summary, url, published_date, "
            "source_name, category) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def _clear_articles():
    conn = _orig_connect(_TEST_DB)
    try:
        conn.execute("DELETE FROM articles")
        conn.commit()
    finally:
        conn.close()


class FeedXmlBasicTests(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        _clear_articles()
        _seed_articles([
            (
                "Benign article title",
                "benign summary body",
                "https://example.com/benign-1",
                "2026-04-19T00:00:00Z",
                "Unit42 Palo Alto",
                "Vulnerability/CVE",
            ),
        ])

    def test_ok_and_atom_mimetype(self):
        resp = self.client.get("/feed.xml")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            resp.mimetype.startswith("application/atom+xml"),
            f"expected application/atom+xml, got {resp.mimetype!r}",
        )

    def test_parses_as_valid_xml(self):
        resp = self.client.get("/feed.xml")
        # ET.fromstring raises on any well-formedness violation.
        root = ET.fromstring(resp.data)
        self.assertTrue(
            root.tag.endswith("feed"),
            f"root must be <feed>, got {root.tag!r}",
        )

    def test_atom_namespace_present(self):
        resp = self.client.get("/feed.xml")
        self.assertIn(b"http://www.w3.org/2005/Atom", resp.data)

    def test_self_link_present(self):
        resp = self.client.get("/feed.xml")
        root = ET.fromstring(resp.data)
        self_links = [
            link for link in root.findall(f"{ATOM_NS}link")
            if link.get("rel") == "self"
        ]
        self.assertEqual(
            len(self_links), 1,
            "Atom spec requires exactly one <link rel='self'>",
        )

    def test_cache_control_set(self):
        resp = self.client.get("/feed.xml")
        self.assertIn("max-age", resp.headers.get("Cache-Control", ""))

    def test_single_entry_round_trip(self):
        resp = self.client.get("/feed.xml")
        root = ET.fromstring(resp.data)
        entries = root.findall(f"{ATOM_NS}entry")
        self.assertEqual(len(entries), 1)
        title = entries[0].findtext(f"{ATOM_NS}title")
        self.assertEqual(title, "Benign article title")


class FeedXmlHostileContentTests(unittest.TestCase):
    """The security-critical tests — these are why we CDATA-wrap + split."""

    def setUp(self):
        self.client = app.test_client()
        _clear_articles()
        _seed_articles([
            (
                # <script> tags must survive literally as text, not parse
                # as markup. ']]>' must be split across two CDATA sections.
                "<script>alert(1)</script> and ]]> marker",
                "summary with ]]> inside and <img src=x onerror=y>",
                "https://example.com/hostile-1",
                "2026-04-19T00:00:00Z",
                "Unit42 Palo Alto",
                "Vulnerability/CVE",
            ),
        ])

    def test_xml_well_formed_despite_hostile_content(self):
        resp = self.client.get("/feed.xml")
        # The whole point: this must not raise even with ]]> and <script>
        # planted in the DB.
        ET.fromstring(resp.data)

    def test_cdata_split_on_bracket_sequence(self):
        # _cdata_safe turns ']]>' into ']]]]><![CDATA[>' so the wrap stays
        # well-formed. Verify that byte sequence appears in the response.
        resp = self.client.get("/feed.xml")
        self.assertIn(b"]]]]><![CDATA[>", resp.data)

    def test_script_tag_survives_literally(self):
        # Parsed title text must contain the literal <script> tag — because
        # it was CDATA-wrapped, not parsed as XML markup.
        resp = self.client.get("/feed.xml")
        root = ET.fromstring(resp.data)
        title = root.find(f"{ATOM_NS}entry/{ATOM_NS}title").text
        self.assertIn("<script>alert(1)</script>", title)
        self.assertIn("]]>", title)


class FeedXmlSizeBoundTests(unittest.TestCase):
    """Defense against a full-DB dump: feed must cap at 50 entries."""

    def setUp(self):
        self.client = app.test_client()
        _clear_articles()
        rows = [
            (
                f"Bulk article {i}",
                f"summary {i}",
                f"https://example.com/bulk-{i}",
                f"2026-04-{(i % 28) + 1:02d}T00:00:00Z",
                "Unit42 Palo Alto",
                "Vulnerability/CVE",
            )
            for i in range(75)
        ]
        _seed_articles(rows)

    def test_entry_count_capped_at_50(self):
        resp = self.client.get("/feed.xml")
        root = ET.fromstring(resp.data)
        entries = root.findall(f"{ATOM_NS}entry")
        self.assertLessEqual(
            len(entries), 50,
            f"feed.xml exposed {len(entries)} entries — the SQL LIMIT 50 is missing",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
