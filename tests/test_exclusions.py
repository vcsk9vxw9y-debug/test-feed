"""
Tests for config/exclusions.yml — the phrase-based exclusion filter.

Three layers:

* ``load_exclusions()`` — YAML loader. Must fail-closed on every bad-input
  shape (missing file, malformed YAML, non-dict root, non-str keys,
  non-list values, non-str / empty phrases, empty phrase list). A loader
  that raised or returned ``None`` would crash the app on import; the
  contract is "always returns a dict, never raises".

* ``_is_excluded()`` — filter. Case-insensitive substring match against
  title + summary combined. Unknown source or empty phrase list passes
  through (returns False). ``None`` title/summary must not crash.

* Shipped YAML — guard rails on the committed config/exclusions.yml so
  an accidental deletion of the CrowdStrike entry fails the test rather
  than silently turning off the filter in prod.

Run: python -m unittest tests.test_exclusions -v
"""

import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scheduler  # noqa: E402
from scheduler import _is_excluded, load_exclusions  # noqa: E402


class LoadExclusionsTests(unittest.TestCase):
    """Shape contract for load_exclusions — always a dict, never raises."""

    def _write(self, body):
        """Write body to a throwaway YAML; auto-cleanup on test teardown."""
        tmp = tempfile.NamedTemporaryFile(
            suffix=".yml", delete=False, mode="w", encoding="utf-8"
        )
        tmp.write(body)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_valid_file_loads_lowercased(self):
        path = self._write(textwrap.dedent("""
            "CrowdStrike Blog":
              - Falcon
              - Charlotte
              - Flex
        """))
        result = load_exclusions(path)
        self.assertEqual(result["CrowdStrike Blog"], ["falcon", "charlotte", "flex"])

    def test_returns_dict_even_on_missing_file(self):
        result = load_exclusions("/definitely/does/not/exist.yml")
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    def test_malformed_yaml_returns_empty(self):
        # Deliberate syntax garbage.
        path = self._write("{: not valid yaml [[[\n  - broken\n: : :")
        self.assertEqual(load_exclusions(path), {})

    def test_non_dict_root_returns_empty(self):
        # A top-level list isn't the schema we want — drop it, don't guess.
        path = self._write("- just\n- a\n- list\n")
        self.assertEqual(load_exclusions(path), {})

    def test_scalar_root_returns_empty(self):
        path = self._write("'just a string'\n")
        self.assertEqual(load_exclusions(path), {})

    def test_empty_file_returns_empty(self):
        path = self._write("")
        self.assertEqual(load_exclusions(path), {})

    def test_non_str_source_key_dropped(self):
        path = self._write(textwrap.dedent("""
            123:
              - should-be-dropped
            "CrowdStrike Blog":
              - Falcon
        """))
        result = load_exclusions(path)
        self.assertNotIn(123, result)
        self.assertIn("CrowdStrike Blog", result)

    def test_empty_source_key_dropped(self):
        path = self._write(textwrap.dedent("""
            "":
              - orphan
            "CrowdStrike Blog":
              - Falcon
        """))
        result = load_exclusions(path)
        self.assertNotIn("", result)
        self.assertIn("CrowdStrike Blog", result)

    def test_non_list_value_dropped(self):
        # A bare string under a source is a config typo — we drop it
        # rather than splitting on whitespace or guessing intent.
        path = self._write(textwrap.dedent("""
            "CrowdStrike Blog": "Falcon,Charlotte"
            "Good Source":
              - phrase
        """))
        result = load_exclusions(path)
        self.assertNotIn("CrowdStrike Blog", result)
        self.assertIn("Good Source", result)

    def test_non_str_phrase_dropped(self):
        path = self._write(textwrap.dedent("""
            "CrowdStrike Blog":
              - Falcon
              - 123
              - ~
              - Flex
        """))
        result = load_exclusions(path)
        self.assertEqual(result["CrowdStrike Blog"], ["falcon", "flex"])

    def test_whitespace_phrase_dropped(self):
        path = self._write(textwrap.dedent("""
            "CrowdStrike Blog":
              - "   "
              - Falcon
        """))
        result = load_exclusions(path)
        self.assertEqual(result["CrowdStrike Blog"], ["falcon"])

    def test_empty_phrase_list_dropped_entirely(self):
        # A source with zero phrases contributes nothing — drop the key
        # so downstream callers can assume a non-empty list.
        path = self._write(textwrap.dedent("""
            "CrowdStrike Blog": []
            "Good Source":
              - phrase
        """))
        result = load_exclusions(path)
        self.assertNotIn("CrowdStrike Blog", result)
        self.assertIn("Good Source", result)

    def test_phrases_normalised_to_lowercase(self):
        path = self._write('"CrowdStrike Blog": [FALCON, Charlotte, flex]\n')
        result = load_exclusions(path)
        self.assertEqual(result["CrowdStrike Blog"], ["falcon", "charlotte", "flex"])


class IsExcludedTests(unittest.TestCase):
    """Filter semantics. Patches scheduler.EXCLUSIONS per test."""

    def setUp(self):
        self._saved = scheduler.EXCLUSIONS
        scheduler.EXCLUSIONS = {
            "CrowdStrike Blog": ["falcon", "charlotte", "flex"],
            "Empty Source": [],  # should never appear in practice (loader
                                 # drops it), but the filter must still
                                 # behave correctly if it did.
        }

    def tearDown(self):
        scheduler.EXCLUSIONS = self._saved

    # --- case sensitivity (Q3: case-insensitive) ---

    def test_lowercase_match_in_title(self):
        self.assertTrue(_is_excluded("CrowdStrike Blog", "new falcon release", ""))

    def test_mixed_case_match_in_title(self):
        self.assertTrue(_is_excluded("CrowdStrike Blog", "New Falcon Release", ""))

    def test_uppercase_match_in_title(self):
        self.assertTrue(_is_excluded("CrowdStrike Blog", "FALCON RELEASE", ""))

    # --- haystack placement ---

    def test_match_in_summary_only(self):
        self.assertTrue(_is_excluded(
            "CrowdStrike Blog",
            "Quarterly threat intel",
            "Charlotte AI now GA",
        ))

    def test_match_in_title_and_summary(self):
        self.assertTrue(_is_excluded(
            "CrowdStrike Blog",
            "Falcon platform announces",
            "Charlotte introduces new detections",
        ))

    def test_substring_inside_word_still_matches(self):
        # Substring semantics — "flex" matches "flexibility". The
        # operator picks phrases with this in mind; keeping it simple
        # avoids a word-boundary regex (and its ReDoS surface).
        self.assertTrue(_is_excluded("CrowdStrike Blog", "Flexibility update", ""))

    # --- pass-through ---

    def test_unrelated_title_passes(self):
        self.assertFalse(_is_excluded(
            "CrowdStrike Blog",
            "APT29 targets European banks",
            "Unit 42 observes new loader",
        ))

    def test_unknown_source_passes(self):
        # Even a title with "Falcon" in it passes through if the source
        # isn't in the exclusions — the filter is per-source, not global.
        self.assertFalse(_is_excluded(
            "The Hacker News",
            "Falcon 9 launches cybersecurity-themed payload",
            "",
        ))

    def test_empty_phrase_list_passes(self):
        self.assertFalse(_is_excluded(
            "Empty Source",
            "Falcon everywhere, Charlotte too",
            "Flex",
        ))

    # --- None / empty safety ---

    def test_none_title_and_summary_safe(self):
        self.assertFalse(_is_excluded("CrowdStrike Blog", None, None))

    def test_empty_strings_safe(self):
        self.assertFalse(_is_excluded("CrowdStrike Blog", "", ""))

    def test_none_summary_with_matching_title(self):
        self.assertTrue(_is_excluded("CrowdStrike Blog", "Falcon update", None))


class ShippedExclusionsYamlTests(unittest.TestCase):
    """Regression guard on config/exclusions.yml. If the operator removes
    the CrowdStrike entry by accident, fail the test — don't silently
    turn off the filter in prod."""

    def test_default_path_loads(self):
        shipped = load_exclusions()
        self.assertIsInstance(shipped, dict)

    def test_crowdstrike_entry_present(self):
        shipped = load_exclusions()
        self.assertIn(
            "CrowdStrike Blog", shipped,
            "config/exclusions.yml must carry a CrowdStrike Blog entry — "
            "removing it disables the product-marketing filter.",
        )

    def test_crowdstrike_phrases_include_known_noise(self):
        shipped = load_exclusions()
        phrases = shipped.get("CrowdStrike Blog", [])
        for expected in ("falcon", "charlotte", "flex"):
            with self.subTest(phrase=expected):
                self.assertIn(
                    expected, phrases,
                    f"expected '{expected}' in CrowdStrike Blog phrases",
                )

    def test_no_unexpected_certificate_phrase(self):
        # Q2 decision: "certificate" was explicitly dropped because it
        # would false-positive on legitimate intel (stolen code-signing
        # certificates, CA compromise). If someone re-adds it, that
        # should be a deliberate PR — this test flags accidental adds.
        shipped = load_exclusions()
        phrases = shipped.get("CrowdStrike Blog", [])
        self.assertNotIn("certificate", phrases)


if __name__ == "__main__":
    unittest.main(verbosity=2)
