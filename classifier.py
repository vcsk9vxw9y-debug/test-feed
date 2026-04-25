"""
Classifier — assign a category to an article based on keyword matching.

## Priority

The declaration order of categories in ``categories.yml`` IS the priority
order. Python 3.7+ guarantees dict insertion order is preserved, and
``yaml.safe_load`` on a YAML mapping returns a regular dict, so the YAML
file is the single source of truth:

    OT/ICS -> Cloud Security -> SaaS Breach -> Ransomware
    -> Identity & Access -> Vulnerability/CVE -> Nation State/APT
    -> Malware/Infostealer -> AI Security -> Phishing & Social Engineering
    -> Supply Chain -> Mobile Security -> Industry/Policy
    -> Consumer Awareness -> Uncategorized (fallback)

First-match-wins within a category; first-category-wins across categories.

## Security posture

- ``yaml.safe_load`` — no arbitrary object construction.
- ``re.escape`` on every keyword — keywords cannot inject regex syntax.
- Word-boundary lookarounds over a bounded ``[a-z0-9]`` character class —
  no variable-length backtracking, no ReDoS surface.
- Pure function (no I/O beyond one-time YAML load), deterministic.
"""

import os
import re

import yaml

CATEGORIES_PATH = os.path.join(os.path.dirname(__file__), "categories.yml")

_rules = None


def compile_keyword_pattern(keyword):
    escaped = re.escape(keyword.lower())
    return re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")


def load_rules():
    global _rules
    if _rules is None:
        with open(CATEGORIES_PATH, "r", encoding="utf-8") as f:
            raw_rules = yaml.safe_load(f) or {}

        _rules = {
            category: [compile_keyword_pattern(keyword) for keyword in keywords]
            for category, keywords in raw_rules.items()
        }

    return _rules


def classify_article(title, summary):
    """Return the first matching category in YAML declaration order.

    YAML declaration order IS priority — see module docstring. No hardcoded
    priority list, single source of truth.
    """
    rules = load_rules()
    text = f"{title or ''} {summary or ''}".lower()

    for category, patterns in rules.items():
        for pattern in patterns:
            if pattern.search(text):
                return category

    return "Uncategorized"
