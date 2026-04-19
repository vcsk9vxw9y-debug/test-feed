"""
Tests for classifier.py — priority-order classification.

Three layers:

* ``ClassifierPriorityTests`` — guards the "sharper category wins" contract.
  When multiple categories' keywords would match, the higher-priority
  category must win. Regression guard for the kind of drift that happens
  when a new category's keywords accidentally start poaching from more
  specific buckets.

* ``ConsumerAwarenessTests`` — locks down the ESET WeLiveSecurity scope
  for Consumer Awareness. Adding a consumer-scam keyword like "poshmark"
  needs to still land in Consumer Awareness after future keyword changes.
  If these start failing, someone's moved a keyword into a higher-priority
  category that shouldn't claim it.

* ``EnterpriseIntelIsolationTests`` — the post-Aegis-review guard.
  Enterprise-focused intel (retailer breaches, DOJ indictments, GDPR
  opt-outs, stolen-creds stories) MUST NOT fall into Consumer Awareness.
  Every case here traces back to a specific finding in the review —
  comments cite the finding ID (B1/B2/B3).

Run: python -m unittest tests.test_classifier -v
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from classifier import classify_article  # noqa: E402


class ClassifierPriorityTests(unittest.TestCase):
    """Sharper category must win over Consumer Awareness when both match."""

    def test_deepfake_scam_goes_to_ai_security(self):
        self.assertEqual(
            classify_article("Deepfake voice scam targets bank", ""),
            "AI Security",
        )

    def test_ransomware_with_phishing_goes_to_ransomware(self):
        self.assertEqual(
            classify_article("Ransomware crew runs tax scam phishing", ""),
            "Ransomware",
        )

    def test_phishing_kit_goes_to_phishing(self):
        # Phishing wins over Consumer Awareness even though "poshmark" is a
        # CA keyword — because "phishing kit" is sharper.
        self.assertEqual(
            classify_article("Phishing kit uses fake login for Poshmark", ""),
            "Phishing & Social Engineering",
        )

    def test_bec_scam_goes_to_phishing(self):
        # Generic "scam" is NOT in Phishing (it's in CA via type-specific
        # phrases), but "bec scam" is explicitly a Phishing keyword.
        self.assertEqual(
            classify_article("BEC scam drains payroll account", ""),
            "Phishing & Social Engineering",
        )

    def test_ot_ics_beats_everything(self):
        # OT/ICS is top of priority — verify it still wins over broader
        # Nation State/APT keywords for an energy-sector title.
        self.assertEqual(
            classify_article("Threat clusters linked to Iran target energy sector", ""),
            "OT/ICS",
        )

    def test_ransomware_beats_malware(self):
        # Ransomware is sharper than Malware/Infostealer.
        self.assertEqual(
            classify_article("LockBit deploys infostealer after ransom demand", ""),
            "Ransomware",
        )


class ConsumerAwarenessTests(unittest.TestCase):
    """Consumer Awareness catches ESET WeLiveSecurity-style content."""

    def test_poshmark_scam(self):
        self.assertEqual(
            classify_article("Poshmark scams: how to spot a fake buyer", ""),
            "Consumer Awareness",
        )

    def test_tax_season_scam(self):
        self.assertEqual(
            classify_article("Tax-season scam targets retirees", ""),
            "Consumer Awareness",
        )

    def test_romance_scam(self):
        self.assertEqual(
            classify_article("Romance scam on Tinder nets $40k", ""),
            "Consumer Awareness",
        )

    def test_parental_controls(self):
        self.assertEqual(
            classify_article("Parental controls for iPhone: a practical guide", ""),
            "Consumer Awareness",
        )

    def test_data_brokers(self):
        self.assertEqual(
            classify_article("Data brokers and your digital footprint", ""),
            "Consumer Awareness",
        )

    def test_password_tips(self):
        self.assertEqual(
            classify_article("Stay safe online: password tips for families", ""),
            "Consumer Awareness",
        )

    def test_identity_protection_service(self):
        # `identity protection` stays in CA (consumer-facing services);
        # `identity theft` (crime reporting) does NOT — belongs in
        # Industry/Policy territory via DOJ indictment keywords.
        self.assertEqual(
            classify_article("Identity protection service review for families", ""),
            "Consumer Awareness",
        )


class EnterpriseIntelIsolationTests(unittest.TestCase):
    """Enterprise intel must NOT fall into Consumer Awareness.

    Each case here traces to a specific Aegis review finding. If a test
    here starts failing, someone reintroduced a CA keyword that steals
    from a sharper category.
    """

    def test_b1_retailer_breach_goes_to_saas_breach(self):
        # B1: `personal data exposed` was miscategorizing as CA. Now lives
        # in SaaS Breach where major-retailer breach coverage belongs.
        self.assertEqual(
            classify_article("Personal data exposed in breach of major retailer", ""),
            "SaaS Breach",
        )

    def test_b2_doj_indictment_verb_form_goes_to_industry_policy(self):
        # B2: title uses verb form "indicted by DOJ" — `doj indictment` (noun)
        # missed it. Added verb-form keywords so Industry/Policy wins.
        self.assertEqual(
            classify_article("Identity theft ring indicted by DOJ", ""),
            "Industry/Policy",
        )

    def test_b2_stolen_credentials_goes_to_identity_access(self):
        # B2: `stolen credentials` is an Identity & Access concern, not CA.
        # SaaS Breach takes priority if it fires, otherwise Identity wins.
        got = classify_article("Credit freeze fraud traced to stolen credentials", "")
        self.assertIn(got, ("SaaS Breach", "Identity & Access"))
        self.assertNotEqual(got, "Consumer Awareness")

    def test_b3_gdpr_opt_out_goes_to_industry_policy(self):
        # B3: generic `opt out` was stealing GDPR/regulatory content from
        # Industry/Policy. Removed from CA; Industry/Policy wins via
        # `privacy law` / `data protection authority` or similar.
        got = classify_article("Opt out of data collection — new GDPR guidance", "")
        self.assertNotEqual(got, "Consumer Awareness")

    def test_generic_protect_your_org_does_not_land_in_consumer_awareness(self):
        # The "protect your" CA keyword is deliberately broad but last in
        # priority. Verify sharper categories still win on enterprise-framed
        # protection advice.
        self.assertEqual(
            classify_article("New advisory: how to protect your org from ransomware", ""),
            "Ransomware",
        )


class SanityTests(unittest.TestCase):
    """Basic invariants — the function doesn't crash on edge inputs."""

    def test_empty_strings(self):
        # No keyword matches -> Uncategorized fallback.
        self.assertEqual(classify_article("", ""), "Uncategorized")

    def test_none_inputs(self):
        # None-safe; classifier coerces to empty via f-string.
        self.assertEqual(classify_article(None, None), "Uncategorized")

    def test_case_insensitive_match(self):
        # Classifier lowercases haystack; keywords are also lowercase-compiled.
        self.assertEqual(
            classify_article("RANSOMWARE GANG HITS HOSPITAL", ""),
            "Ransomware",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
