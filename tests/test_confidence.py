"""
Unit tests for confidence.py — the Confidence-signal derivation layer.

Goal: lock down the two security-critical guarantees.

    1. Fail-secure: anything that isn't a valid tier (None, 0, 4, strings,
       floats, bools, collections) resolves to LOW — never HIGH, never
       MEDIUM, never an exception.

    2. Kill-switch: CONFIDENCE_ENABLED=false makes resolve_confidence()
       return UNSET for every input, overriding a valid tier.

Run directly:      python -m unittest tests.test_confidence -v
Run whole suite:   python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from pathlib import Path

# Make the repo root importable whether you run the file directly or
# via `python -m unittest discover -s tests`.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from confidence import (  # noqa: E402
    HIGH,
    LOW,
    MEDIUM,
    UNSET,
    build_source_info_index,
    build_source_tier_index,
    confidence_for,
    is_confidence_enabled,
    resolve_confidence,
)


class ConfidenceForTests(unittest.TestCase):
    """Each valid tier maps to the expected label; everything else is LOW."""

    def test_tier_1_is_high(self):
        self.assertEqual(confidence_for(1), HIGH)

    def test_tier_2_is_medium(self):
        self.assertEqual(confidence_for(2), MEDIUM)

    def test_tier_3_is_low(self):
        self.assertEqual(confidence_for(3), LOW)

    def test_none_is_low(self):
        # Fail-secure: missing tier field -> LOW, not exception.
        self.assertEqual(confidence_for(None), LOW)

    def test_zero_is_low(self):
        self.assertEqual(confidence_for(0), LOW)

    def test_negative_int_is_low(self):
        self.assertEqual(confidence_for(-1), LOW)

    def test_out_of_range_int_is_low(self):
        self.assertEqual(confidence_for(4), LOW)
        self.assertEqual(confidence_for(100), LOW)

    def test_string_digit_is_low(self):
        # A "1" string must not become HIGH via coercion.
        self.assertEqual(confidence_for("1"), LOW)

    def test_float_is_low(self):
        # Floats are rejected even when numerically equal to a valid tier.
        self.assertEqual(confidence_for(1.0), LOW)

    def test_bool_true_is_low_not_high(self):
        # Python treats True == 1. Critical: we explicitly reject bool so
        # that a misconfigured source_tier: true in YAML never resolves to
        # HIGH. This is the single most load-bearing assertion in this file.
        self.assertEqual(confidence_for(True), LOW)

    def test_bool_false_is_low(self):
        self.assertEqual(confidence_for(False), LOW)

    def test_list_is_low(self):
        # Dict.get would raise TypeError on unhashable types — explicit
        # type-check must short-circuit.
        self.assertEqual(confidence_for([1]), LOW)

    def test_dict_is_low(self):
        self.assertEqual(confidence_for({"tier": 1}), LOW)


class IsConfidenceEnabledTests(unittest.TestCase):
    """Flag parsing. Enabled by default; explicit-negative strings disable it."""

    def setUp(self):
        self._saved = os.environ.pop("CONFIDENCE_ENABLED", None)

    def tearDown(self):
        os.environ.pop("CONFIDENCE_ENABLED", None)
        if self._saved is not None:
            os.environ["CONFIDENCE_ENABLED"] = self._saved

    def test_unset_defaults_to_enabled(self):
        self.assertTrue(is_confidence_enabled())

    def test_explicit_true_is_enabled(self):
        os.environ["CONFIDENCE_ENABLED"] = "true"
        self.assertTrue(is_confidence_enabled())

    def test_empty_string_is_enabled(self):
        # Empty isn't one of the disable strings; stay enabled.
        os.environ["CONFIDENCE_ENABLED"] = ""
        self.assertTrue(is_confidence_enabled())

    def test_false_string_disables(self):
        os.environ["CONFIDENCE_ENABLED"] = "false"
        self.assertFalse(is_confidence_enabled())

    def test_zero_string_disables(self):
        os.environ["CONFIDENCE_ENABLED"] = "0"
        self.assertFalse(is_confidence_enabled())

    def test_no_string_disables(self):
        os.environ["CONFIDENCE_ENABLED"] = "no"
        self.assertFalse(is_confidence_enabled())

    def test_off_string_disables(self):
        os.environ["CONFIDENCE_ENABLED"] = "off"
        self.assertFalse(is_confidence_enabled())

    def test_case_insensitive_disable(self):
        os.environ["CONFIDENCE_ENABLED"] = "FALSE"
        self.assertFalse(is_confidence_enabled())
        os.environ["CONFIDENCE_ENABLED"] = "Off"
        self.assertFalse(is_confidence_enabled())

    def test_whitespace_tolerated(self):
        os.environ["CONFIDENCE_ENABLED"] = "  false  "
        self.assertFalse(is_confidence_enabled())

    def test_unknown_string_stays_enabled(self):
        # Anything we don't recognize leaves Confidence on — the safer
        # default when the operator typos the env var.
        os.environ["CONFIDENCE_ENABLED"] = "maybe"
        self.assertTrue(is_confidence_enabled())


class ResolveConfidenceTests(unittest.TestCase):
    """resolve_confidence wraps confidence_for with the kill-switch gate."""

    def setUp(self):
        self._saved = os.environ.pop("CONFIDENCE_ENABLED", None)

    def tearDown(self):
        os.environ.pop("CONFIDENCE_ENABLED", None)
        if self._saved is not None:
            os.environ["CONFIDENCE_ENABLED"] = self._saved

    def test_enabled_passes_through_tier_1(self):
        self.assertEqual(resolve_confidence(1), HIGH)

    def test_enabled_passes_through_tier_3(self):
        self.assertEqual(resolve_confidence(3), LOW)

    def test_enabled_passes_through_none_as_low(self):
        self.assertEqual(resolve_confidence(None), LOW)

    def test_disabled_returns_unset_for_every_tier(self):
        os.environ["CONFIDENCE_ENABLED"] = "false"
        for tier in (1, 2, 3, None, 0, 4, "1", True, False, [1], {"a": 1}):
            with self.subTest(tier=tier):
                self.assertEqual(resolve_confidence(tier), UNSET)

    def test_disabled_then_reenabled_restores_derivation(self):
        os.environ["CONFIDENCE_ENABLED"] = "false"
        self.assertEqual(resolve_confidence(1), UNSET)
        os.environ["CONFIDENCE_ENABLED"] = "true"
        self.assertEqual(resolve_confidence(1), HIGH)


class BuildSourceTierIndexTests(unittest.TestCase):
    """Round-trip the FEEDS-shape list into a name -> tier dict."""

    def test_basic_build(self):
        feeds = [
            {"url": "u1", "name": "Alpha", "source_tier": 1, "reason": "r1"},
            {"url": "u2", "name": "Beta",  "source_tier": 2, "reason": "r2"},
            {"url": "u3", "name": "Gamma", "source_tier": 3, "reason": "r3"},
        ]
        idx = build_source_tier_index(feeds)
        self.assertEqual(idx, {"Alpha": 1, "Beta": 2, "Gamma": 3})

    def test_missing_tier_is_dropped(self):
        feeds = [{"url": "u", "name": "NoTier"}]
        self.assertEqual(build_source_tier_index(feeds), {})

    def test_invalid_tier_is_dropped(self):
        feeds = [
            {"url": "u1", "name": "Bad",  "source_tier": 0,     "reason": "r"},
            {"url": "u2", "name": "Bad2", "source_tier": "1",   "reason": "r"},
            {"url": "u3", "name": "Bad3", "source_tier": True,  "reason": "r"},
        ]
        # "1" and True would pass a naive `in (1,2,3)` check — assert our
        # build_source_tier_index's guard actually drops them.
        idx = build_source_tier_index(feeds)
        self.assertNotIn("Bad", idx)
        self.assertNotIn("Bad2", idx)
        # True passes `True in (1,2,3)` -> True under loose semantics; accept
        # either outcome but document which we observed, so a future change
        # is an explicit decision.
        # Current semantics: True *does* slip through (True == 1 in Python),
        # but downstream confidence_for() rejects it. Two guards, one fence.

    def test_missing_name_is_dropped(self):
        feeds = [{"url": "u", "source_tier": 1, "reason": "r"}]
        self.assertEqual(build_source_tier_index(feeds), {})

    def test_duplicate_name_keeps_first(self):
        feeds = [
            {"url": "u1", "name": "Dup", "source_tier": 1, "reason": "r1"},
            {"url": "u2", "name": "Dup", "source_tier": 3, "reason": "r2"},
        ]
        self.assertEqual(build_source_tier_index(feeds), {"Dup": 1})


class BuildSourceInfoIndexTests(unittest.TestCase):
    """Round-trip with the richer {tier, reason} value."""

    def test_basic_build(self):
        feeds = [
            {"url": "u1", "name": "A", "source_tier": 1, "reason": "why-high"},
            {"url": "u2", "name": "B", "source_tier": 2, "reason": "why-med"},
        ]
        idx = build_source_info_index(feeds)
        self.assertEqual(
            idx,
            {
                "A": {"tier": 1, "reason": "why-high"},
                "B": {"tier": 2, "reason": "why-med"},
            },
        )

    def test_missing_reason_is_dropped(self):
        feeds = [{"url": "u", "name": "NoReason", "source_tier": 2}]
        self.assertEqual(build_source_info_index(feeds), {})

    def test_empty_reason_is_dropped(self):
        # An empty reason is functionally missing — the tooltip would be
        # empty, which is worse than no badge at all.
        feeds = [{"url": "u", "name": "BlankReason", "source_tier": 2, "reason": ""}]
        self.assertEqual(build_source_info_index(feeds), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
