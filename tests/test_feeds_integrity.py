"""
Integrity tests for scheduler.FEEDS — the Confidence trust anchor.

A new feed added without source_tier/reason would resolve to LOW at
runtime (the fail-secure default), but that isn't what we want — it
would silently under-weight a reputable source. These tests fail loudly
at CI time so the operator fixes the tier/reason before merge.

Scope — every FEEDS entry must:
    * have a `url` (string, non-empty, http/https)
    * have a `name` (string, non-empty, unique across FEEDS)
    * have a `source_tier` (int literal 1, 2, or 3 — NOT bool, NOT str)
    * have a `reason` (string, non-empty)

Non-goals: we do NOT assert the *specific* tier of any source here —
re-tiering is an editorial PR, not a test regression. The point is the
*shape* contract, not the editorial content.

Run: python -m unittest tests.test_feeds_integrity -v
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scheduler import FEEDS  # noqa: E402


VALID_TIERS = {1, 2, 3}


class FeedsIntegrityTests(unittest.TestCase):

    def test_feeds_is_a_nonempty_list(self):
        self.assertIsInstance(FEEDS, list)
        self.assertGreater(len(FEEDS), 0)

    def test_every_feed_has_required_fields(self):
        required = {"url", "name", "source_tier", "reason"}
        for entry in FEEDS:
            with self.subTest(name=entry.get("name", "<unnamed>")):
                missing = required - set(entry.keys())
                self.assertFalse(
                    missing,
                    f"entry missing fields {missing}: {entry!r}",
                )

    def test_url_is_valid_http_string(self):
        for entry in FEEDS:
            with self.subTest(name=entry.get("name")):
                url = entry.get("url")
                self.assertIsInstance(url, str)
                self.assertTrue(url)
                self.assertTrue(
                    url.startswith(("http://", "https://")),
                    f"url must be http(s): {url!r}",
                )

    def test_name_is_nonempty_string(self):
        for entry in FEEDS:
            with self.subTest(url=entry.get("url")):
                name = entry.get("name")
                self.assertIsInstance(name, str)
                self.assertTrue(name.strip())

    def test_names_are_unique(self):
        # Duplicate names would collide in build_source_*_index — only the
        # first wins, and the duplicate's tier silently vanishes. Forbid.
        names = [e.get("name") for e in FEEDS]
        seen, dupes = set(), []
        for n in names:
            (dupes if n in seen else seen).add(n) if n in seen else seen.add(n)
            if names.count(n) > 1 and n not in dupes:
                dupes.append(n)
        self.assertEqual(dupes, [], f"duplicate feed names: {dupes}")

    def test_source_tier_is_exact_int_1_2_or_3(self):
        for entry in FEEDS:
            with self.subTest(name=entry.get("name")):
                tier = entry.get("source_tier")
                # Reject bool first — True == 1 would silently pass an
                # isinstance(tier, int) check.
                self.assertNotIsInstance(
                    tier, bool,
                    f"source_tier must be int, got bool: {entry!r}",
                )
                self.assertIsInstance(
                    tier, int,
                    f"source_tier must be int, got {type(tier).__name__}: {entry!r}",
                )
                self.assertIn(
                    tier, VALID_TIERS,
                    f"source_tier must be 1, 2, or 3, got {tier}: {entry!r}",
                )

    def test_reason_is_nonempty_string(self):
        for entry in FEEDS:
            with self.subTest(name=entry.get("name")):
                reason = entry.get("reason")
                self.assertIsInstance(reason, str)
                self.assertTrue(
                    reason.strip(),
                    f"reason must be non-empty: {entry!r}",
                )

    def test_tier_distribution_has_no_orphan_buckets(self):
        # Sanity: every tier bucket should have at least one source. If a
        # refactor accidentally drops all Tier 1 sources, we want a red
        # test, not a silent all-LOW feed.
        tiers_present = {entry["source_tier"] for entry in FEEDS}
        self.assertEqual(
            tiers_present, VALID_TIERS,
            f"expected all of {VALID_TIERS}, got {tiers_present}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
