import os
import re

import yaml

CATEGORIES_PATH = os.path.join(os.path.dirname(__file__), "categories.yml")

_rules = None


def compile_keyword_pattern(keyword):
    escaped = re.escape(keyword.lower())
    if re.fullmatch(r"[a-z0-9/.-]+", keyword.lower()):
        return re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")
    return re.compile(escaped)


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
    rules = load_rules()
    text = f"{title or ''} {summary or ''}".lower()

    # Priority order: OT/ICS first, then others, Uncategorized last
    priority = [
        "OT/ICS",
        "Cloud Breach",
        "SaaS Breach",
        "Ransomware",
        "Vulnerability/CVE",
        "Nation State/APT",
        "Malware/Infostealer",
        "AI Security",
        "Phishing & Social Engineering",
        "Supply Chain",
    ]
    remaining = [c for c in rules if c not in priority]

    for category in priority + remaining:
        patterns = rules.get(category, [])
        for pattern in patterns:
            if pattern.search(text):
                return category

    return "Uncategorized"
