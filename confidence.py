"""
Confidence signal — derivation + kill-switch.

The Confidence badge on each article tells the reader how much trust to
extend to the *source*, not how severe the threat is. Derivation is
deliberately trivial:

    Tier 1 -> HIGH    (government CERTs, vendor PSIRTs, gold-standard TI research)
    Tier 2 -> MEDIUM  (established journalism, vendor TI with commercial context)
    Tier 3 -> LOW     (single-author niche, user-submitted aggregators)
    anything else (None, unknown int, bogus string) -> LOW

The tier mapping lives in scheduler.py FEEDS as the committed trust anchor.
This module is the *rendering* layer — it never reads runtime state, never
hits the DB, never takes a DB connection. Pure function, unit-testable.

## Security posture (per Aegis review)

- **B1 (fail-secure):** an unknown or missing tier resolves to LOW, not HIGH,
  not an exception. A feed silently added to scheduler.py without a tier
  surfaces to readers as LOW-confidence rather than wrongly elevated.

- **S1 (kill-switch):** CONFIDENCE_ENABLED env var (default "true") gates
  whether the API payload carries the confidence field. When disabled the
  badge renders as the neutral "—" placeholder — no badge removal,
  because removal would look like a bug to regular readers.

- **No admin override, no runtime re-tier:** re-tiering a source is a PR
  that edits scheduler.py. Git blame is the audit trail. This module
  intentionally has no setter and no config file it reads from beyond the
  env flag.
"""

from __future__ import annotations

import os

# Public symbols for the API layer
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Sentinel returned when CONFIDENCE_ENABLED is false.
# The frontend renders this as the "—" placeholder.
UNSET = "UNSET"

_TIER_TO_CONFIDENCE = {
    1: HIGH,
    2: MEDIUM,
    3: LOW,
}


def confidence_for(tier):
    """Derive the Confidence label for a source_tier value.

    Pure function — no side effects, no I/O. Given a valid tier (1, 2, 3),
    returns the matching label. Any other input (None, 0, 4, "1", [], {})
    resolves to LOW per the fail-secure default.

    Args:
        tier: Integer source_tier from scheduler.py FEEDS, or None if the
              source is missing a tier entry.

    Returns:
        One of: HIGH, MEDIUM, LOW.
    """
    # bool is a subclass of int in Python (True == 1) — reject explicitly so
    # a bogus True never silently lands as HIGH. Everything non-int -> LOW.
    if not isinstance(tier, int) or isinstance(tier, bool):
        return LOW
    return _TIER_TO_CONFIDENCE.get(tier, LOW)


def is_confidence_enabled():
    """Read the CONFIDENCE_ENABLED kill-switch.

    Default is enabled (true). The env var must be explicitly set to one of
    the negative strings to disable — "false", "0", "no", "off" (case
    insensitive). Any other value, including empty string, counts as enabled.

    Returns:
        bool — True if Confidence is exposed in API payloads, False if the
        feature is killed and the API should emit UNSET instead.
    """
    raw = os.environ.get("CONFIDENCE_ENABLED", "true")
    return raw.strip().lower() not in {"false", "0", "no", "off"}


def resolve_confidence(tier):
    """End-to-end API helper: takes a tier, returns what to put on the wire.

    Wraps confidence_for() with the CONFIDENCE_ENABLED gate. When the flag
    is off this returns UNSET regardless of tier, so the client renders the
    "—" placeholder consistently.

    Args:
        tier: Integer source_tier or None.

    Returns:
        One of: HIGH, MEDIUM, LOW, UNSET.
    """
    if not is_confidence_enabled():
        return UNSET
    return confidence_for(tier)


def build_source_tier_index(feeds):
    """Build a {source_name: tier} lookup from the FEEDS list.

    Used once at app startup so per-article API responses don't have to
    linear-scan FEEDS. A name appearing twice in FEEDS (should never happen,
    but defensive) uses the first occurrence.

    Args:
        feeds: The FEEDS list from scheduler.py.

    Returns:
        Dict mapping source_name -> tier int. Sources missing source_tier
        are omitted, which means downstream lookups fall through to LOW.
    """
    index = {}
    for entry in feeds:
        name = entry.get("name")
        tier = entry.get("source_tier")
        if name and tier in (1, 2, 3) and name not in index:
            index[name] = tier
    return index
