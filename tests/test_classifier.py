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


class V4KeywordRegressionTests(unittest.TestCase):
    """Lock in the 2026-04-19 keyword expansion (v4 reclassify migration).

    Each case traces to a specific Uncategorized item observed in prod the
    day we added the keyword. If one of these starts failing, someone moved
    a keyword into a higher-priority category that shouldn't claim it — or
    a category's keyword list drifted. Fix at the source, don't weaken the
    test.
    """

    # --- Cloud dev / hosting platforms land in SaaS Breach ---

    def test_vercel_breach_is_saas(self):
        self.assertEqual(
            classify_article(
                "Vercel confirms breach as hackers claim to be selling stolen data",
                "Cloud development platform Vercel has disclosed a security incident.",
            ),
            "SaaS Breach",
        )

    def test_netlify_breach_is_saas(self):
        self.assertEqual(
            classify_article("Netlify acknowledges account-takeover campaign", ""),
            "SaaS Breach",
        )

    def test_supabase_is_saas(self):
        self.assertEqual(
            classify_article("Supabase discloses auth service breach", ""),
            "SaaS Breach",
        )

    def test_fly_io_is_saas(self):
        # Dotted vendor name — regex must escape the `.` correctly.
        self.assertEqual(
            classify_article("Fly.io rotates customer API keys after access incident", ""),
            "SaaS Breach",
        )

    # --- Crypto-exchange hacks land in SaaS Breach ---

    def test_crypto_exchange_hack(self):
        self.assertEqual(
            classify_article(
                "$13.74M Hack Shuts Down Sanctioned Grinex Exchange After Intelligence Claims",
                "Grinex, a Kyrgyzstan-incorporated cryptocurrency exchange, said it's suspending operations after a $13.74 million hack.",
            ),
            "SaaS Breach",
        )

    # --- Supply Chain broadening (editorial / analysis framings) ---

    def test_supply_chain_dependencies_editorial(self):
        # ESET WeLiveSecurity title that previously landed in Uncategorized.
        self.assertEqual(
            classify_article(
                "Supply chain dependencies: Have you checked your blind spot?",
                "Your biggest risk may be a vendor you trust. How can SMBs map their third-party blind spots?",
            ),
            "Supply Chain",
        )

    def test_digital_supply_chain_editorial(self):
        self.assertEqual(
            classify_article(
                "Navigating the Unique Security Risks of Asia's Digital Supply Chain",
                "Regulatory differences and interconnected digital ecosystems have created complex supply-chain risk.",
            ),
            "Supply Chain",
        )

    # --- Vulnerability/CVE framings we were missing ---

    def test_nginx_ui_critical_flaw(self):
        self.assertEqual(
            classify_article(
                "Critical MCP Integration Flaw Puts NGINX at Risk",
                "Attackers can abuse the near-maximum severity flaw in nginx-ui to restart, create, modify, and delete configuration files.",
            ),
            "Vulnerability/CVE",
        )

    def test_secure_boot_certificate_expiry(self):
        self.assertEqual(
            classify_article(
                "Microsoft's Original Windows Secure Boot Certificate Is Expiring",
                "The Secure Boot refresh is one of the largest coordinated security maintenance efforts across the Windows ecosystem.",
            ),
            "Vulnerability/CVE",
        )

    # --- Industry/Policy — quantum risk + CA privacy law ---

    def test_q_day_quantum_risk(self):
        self.assertEqual(
            classify_article(
                "Prepping for 'Q-Day': Why Quantum Risk Management Should Start Now",
                "Quantum computers are coming and it will take years to be fully quantum-safe.",
            ),
            "Industry/Policy",
        )

    def test_ca_privacy_law_opt_out(self):
        self.assertEqual(
            classify_article(
                "Audit: Big Tech Often Ignores CA Privacy Law Opt-Out Requests",
                "A California privacy law mandate is being ignored about half the time by major platforms.",
            ),
            "Industry/Policy",
        )

    # --- Priority invariants — the traps we set up and must keep honoring ---

    def test_vercel_plus_context_ai_stays_saas(self):
        # Both `vercel` (SaaS, prio 3) and `context.ai` (AI Security, prio 9)
        # match. SaaS Breach must win — the article's LEAD is the Vercel
        # compromise, not an AI-safety story about Context.ai itself.
        self.assertEqual(
            classify_article(
                "Vercel breach traced to compromised Context.ai AI developer tool",
                "Threat actors gained access via an employee's Context.ai account.",
            ),
            "SaaS Breach",
        )

    def test_standalone_context_ai_is_ai_security(self):
        # A standalone Context.ai-the-product story (no Vercel/SaaS vendor
        # named) must land in AI Security — otherwise we'd miss genuine AI
        # security coverage after putting context.ai only in SaaS.
        self.assertEqual(
            classify_article(
                "Context.ai patches jailbreak allowing prompt injection against coding agents",
                "Crafted repo files hijack the agent's tool calls.",
            ),
            "AI Security",
        )


class V6KeywordRegressionTests(unittest.TestCase):
    """Lock in the 2026-04-20 keyword expansion (v6 reclassify migration).

    Each case traces to a specific Uncategorized item observed in prod during
    the automated Aegis/Argus maintenance review. Fix at the source if any
    of these fail — don't weaken the test.
    """

    # --- OT/ICS: industrial automation ---

    def test_industrial_automation_is_ot_ics(self):
        self.assertEqual(
            classify_article(
                "Threat landscape for industrial automation systems in Q4 2025",
                "The report contains industrial threat statistics for Q4 2025.",
            ),
            "OT/ICS",
        )

    # --- Malware/Infostealer: novel malware, named campaigns ---

    def test_novel_malware_is_malware(self):
        self.assertEqual(
            classify_article(
                "New Campaign Targets Mac Users With Novel Malware",
                "The campaign targets high-value individuals in the cryptocurrency sector.",
            ),
            "Malware/Infostealer",
        )

    def test_horabot_is_malware(self):
        self.assertEqual(
            classify_article(
                "The SOC Files: Unpacking a new Horabot campaign in Mexico",
                "Kaspersky SOC analyzed a complex Horabot campaign.",
            ),
            "Malware/Infostealer",
        )

    def test_janelarat_is_malware(self):
        self.assertEqual(
            classify_article(
                "JanelaRAT: a financial threat targeting users in Latin America",
                "Kaspersky describes the latest JanelaRAT campaign.",
            ),
            "Malware/Infostealer",
        )

    # --- AI Security: hallucination + ai-mediated framings ---

    def test_ai_hallucination_is_ai_security(self):
        self.assertEqual(
            classify_article(
                "Ghost breaches: How AI-mediated narratives have become a new threat vector",
                "AI hallucinations are creating a new threat vector.",
            ),
            "AI Security",
        )

    def test_ai_use_in_malware_is_ai_security(self):
        self.assertEqual(
            classify_article(
                "Analyzing the Current State of AI Use in Malware",
                "Unit 42 research explores how AI is currently used in malware.",
            ),
            "AI Security",
        )

    # --- Nation State/APT: silver fox ---

    def test_silver_fox_is_nation_state(self):
        self.assertEqual(
            classify_article(
                "A cunning predator: How Silver Fox preys on Japanese firms",
                "Silver Fox is back in Japan, spoofing tax and HR emails.",
            ),
            "Nation State/APT",
        )

    # --- Supply Chain: plural fix ---

    def test_supply_chain_attacks_plural_is_supply_chain(self):
        self.assertEqual(
            classify_article(
                "We have observed a dizzying array of major supply chain attacks",
                "If we are all building on such shaky foundation, what can we do?",
            ),
            "Supply Chain",
        )

    # --- Industry/Policy: surveillance program, cybersecurity rules ---

    def test_surveillance_program_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "Senate Extends Surveillance Powers Until April 30",
                "The Senate approved a short-term renewal of a controversial surveillance program.",
            ),
            "Industry/Policy",
        )

    def test_cybersecurity_rules_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "Coast Guard's New Cybersecurity Rules Offer Lessons for CISOs",
                "The MTSA requires plans to protect OT systems and audits.",
            ),
            "Industry/Policy",
        )

    # --- Mobile Security: crypto-stealing ---

    def test_crypto_stealing_is_mobile_security(self):
        self.assertEqual(
            classify_article(
                "Apple App Store infiltrated by crypto-stealing wallet apps",
                "26 malicious apps impersonate popular wallets.",
            ),
            "Mobile Security",
        )

    # --- Consumer Awareness: recovery scammers plural ---

    def test_recovery_scammers_plural_is_consumer_awareness(self):
        self.assertEqual(
            classify_article(
                "Recovery scammers hit you when you're down",
                "If you've been a victim of fraud, you're likely already a lead on a sucker list.",
            ),
            "Consumer Awareness",
        )

    # --- SaaS Breach: DeFi hacks ---

    def test_defi_hack_is_saas_breach(self):
        self.assertEqual(
            classify_article(
                "The $285M Drift Protocol Heist Was '6 Months in the Making'",
                "During the largest DeFi hack of 2026, attackers drained millions.",
            ),
            "SaaS Breach",
        )

    # --- Priority: OT/ICS still beats Industry/Policy for Coast Guard ---

    def test_coast_guard_ot_cybersecurity_rules_priority(self):
        # "cybersecurity rules" (Industry/Policy) should NOT steal from OT/ICS
        # when OT-specific keywords are also present.
        self.assertEqual(
            classify_article(
                "Coast Guard's Cybersecurity Rules for OT on operational technology ships",
                "New rules mandate SCADA protections.",
            ),
            "OT/ICS",
        )


class V7KeywordRegressionTests(unittest.TestCase):
    """Lock in the 2026-04-20 keyword expansion (v7 reclassify migration).

    Focus: standalone backdoor (Malware), session theft (Identity & Access),
    and consumer-facing scam/hygiene keywords (Consumer Awareness).
    """

    # --- Malware/Infostealer: backdoor/backdoors ---

    def test_backdoor_is_malware(self):
        self.assertEqual(
            classify_article(
                "GhostRedirector poisons Windows servers: Backdoors with a side of Potatoes",
                "ESET researchers have identified a new threat actor targeting Windows servers with a passive C++ backdoor",
            ),
            "Malware/Infostealer",
        )

    def test_backdoor_does_not_steal_from_supply_chain(self):
        # "backdoored" is a Supply Chain keyword. The word-boundary pattern
        # for "backdoor" does NOT match "backdoored" (followed by 'e'),
        # so Supply Chain wins when only "backdoored" appears.
        self.assertEqual(
            classify_article("Backdoored npm package compromises CI servers", ""),
            "Supply Chain",
        )

    # --- Identity & Access: session theft ---

    def test_session_theft_is_identity_access(self):
        self.assertEqual(
            classify_article(
                "Google Rolls Out DBSC in Chrome 146 to Block Session Theft on Windows",
                "Google has made Device Bound Session Credentials generally available",
            ),
            "Identity & Access",
        )

    # --- Consumer Awareness: new keywords ---

    def test_irs_scams_is_consumer_awareness(self):
        self.assertEqual(
            classify_article("Taxing times: Top IRS scams to look out for in 2026", ""),
            "Consumer Awareness",
        )

    def test_dark_web_is_consumer_awareness(self):
        self.assertEqual(
            classify_article(
                "Your personal information is on the dark web. What happens next?",
                "If your data is on the dark web, it's probably only a matter of time",
            ),
            "Consumer Awareness",
        )

    def test_dark_web_does_not_steal_from_phishing(self):
        # Phishing (prio 10) is higher than Consumer Awareness (prio 14).
        self.assertEqual(
            classify_article(
                "Phishing campaign uses dark web data to craft targeted emails",
                "",
            ),
            "Phishing & Social Engineering",
        )

    def test_brushing_scam_is_consumer_awareness(self):
        self.assertEqual(
            classify_article(
                "A brush with online fraud: What are brushing scams?",
                "Have you ever received a package you never ordered?",
            ),
            "Consumer Awareness",
        )

    def test_hacked_account_goes_to_vuln_cve(self):
        # "hacked" (Vulnerability/CVE, priority 6) fires before "hacked account"
        # (Consumer Awareness, priority 14). This is a known priority conflict
        # introduced when standalone "hacked" was added to Vuln/CVE for cyber
        # incident language coverage. Acceptable trade-off: catching "Company X
        # hacked" in Vuln/CVE is more valuable than preserving the consumer
        # "hacked account" guide classification.
        self.assertEqual(
            classify_article(
                "A quick guide to recovering a hacked account",
                "What you do after an account is compromised",
            ),
            "Vulnerability/CVE",
        )

    def test_whatsapp_scam_is_consumer_awareness(self):
        self.assertEqual(
            classify_article(
                "The WhatsApp scam you didn't see coming",
                "How a fast-growing scam is tricking WhatsApp users",
            ),
            "Consumer Awareness",
        )


class V8KeywordRegressionTests(unittest.TestCase):
    """v8 keyword expansion — data wiper, propaganda, bot farm,
    cyber resilience."""

    # -- Malware/Infostealer: data wiper --
    def test_data_wiper_malware(self):
        self.assertEqual(
            classify_article(
                "New Lotus data wiper used against Venezuelan energy firms", ""
            ),
            "Malware/Infostealer",
        )

    # -- Nation State/APT: propaganda --
    def test_propaganda_nation_state(self):
        self.assertEqual(
            classify_article(
                "EU targets two Russian propaganda networks with new sanctions", ""
            ),
            "Nation State/APT",
        )

    # -- Nation State/APT: bot farm --
    def test_bot_farm_nation_state(self):
        self.assertEqual(
            classify_article(
                "Ukraine busts bot farm supplying fake Telegram accounts to Russian spies",
                "",
            ),
            "Nation State/APT",
        )

    # -- Industry/Policy: cyber resilience --
    def test_cyber_resilience_industry(self):
        self.assertEqual(
            classify_article(
                "One small step for Cyber Resilience Test Facilities",
                "helping organisations make informed risk-based decisions",
            ),
            "Industry/Policy",
        )

    # -- Priority conflict: data wiper in OT/ICS context stays OT/ICS --
    def test_data_wiper_ot_stays_ot(self):
        # OT/ICS (priority 1) beats Malware (priority 8)
        self.assertEqual(
            classify_article(
                "Data wiper hits critical infrastructure SCADA systems", ""
            ),
            "OT/ICS",
        )

    # -- Priority conflict: propaganda in nation-state context with CVE --
    def test_propaganda_with_exploit_stays_vuln(self):
        # Vulnerability/CVE (priority 6) beats Nation State (priority 7)
        self.assertEqual(
            classify_article(
                "Zero-day exploit used in propaganda campaign", ""
            ),
            "Vulnerability/CVE",
        )


class V11KeywordRegressionTests(unittest.TestCase):
    """v11 keyword expansion (Aegis maintenance 09-May-2026).

    Re-adds keywords lost in prior refactor + new keywords for current
    uncategorized articles.
    """

    # --- SaaS Breach: source code breach ---
    def test_source_code_breach_is_saas(self):
        self.assertEqual(
            classify_article(
                "Trellix Confirms Source Code Breach With Unauthorized Repository Access",
                "Trellix recently identified the compromise of its source code repository.",
            ),
            "SaaS Breach",
        )

    # --- Vulnerability/CVE: lpe, api flaw ---
    def test_lpe_is_vuln(self):
        self.assertEqual(
            classify_article(
                "A Copy Fail FAQ",
                "The latest branded bug is a slick, portable LPE in many Linux kernels.",
            ),
            "Vulnerability/CVE",
        )

    def test_api_flaw_is_vuln(self):
        self.assertEqual(
            classify_article(
                "A DOD contractor's API flaw exposed military course data",
                "Schemata's platform exposed names, emails, base assignments.",
            ),
            "Vulnerability/CVE",
        )

    # --- Malware/Infostealer: stealer standalone, etherrat ---
    def test_stealer_standalone_is_malware(self):
        self.assertEqual(
            classify_article(
                "Stealthy Deep#Door Stealer Targets Windows Machines, Credentials",
                "Deep#Door stealer is being used in intrusions targeting Windows.",
            ),
            "Malware/Infostealer",
        )

    def test_etherrat_is_malware(self):
        self.assertEqual(
            classify_article(
                "EtherRAT Distribution Spoofing Administrative Tools via GitHub Facades",
                "A sophisticated malicious campaign targeting enterprise administrators.",
            ),
            "Malware/Infostealer",
        )

    # --- AI Security: llm standalone ---
    def test_llm_standalone_is_ai_security(self):
        self.assertEqual(
            classify_article(
                "We Scanned 1 Million Exposed AI Services",
                "Businesses are moving fast to self-host LLM infrastructure.",
            ),
            "AI Security",
        )

    # --- Mobile Security: play store, google play ---
    def test_play_store_fraud_is_mobile(self):
        self.assertEqual(
            classify_article(
                "Fake Call History Apps Stole Payments From Users After 7.3M Play Store Downloads",
                "Fraudulent apps on the official Google Play Store for Android.",
            ),
            "Mobile Security",
        )

    # --- Industry/Policy: sentenced, convicted, pleaded guilty ---
    def test_sentenced_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "Crypto gang member gets 6.5 years for role in $230 million heist",
                "A 20-year-old California man was sentenced to 78 months in prison.",
            ),
            "Industry/Policy",
        )

    def test_convicted_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "Former govt contractor convicted for wiping dozens of federal databases",
                "A 34-year-old Virginia man was found guilty of conspiring to destroy databases.",
            ),
            "Industry/Policy",
        )

    def test_pleaded_guilty_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "Kingdom Market administrator given 16-year sentence",
                "Alan Bill pleaded guilty to a conspiracy to distribute controlled substances.",
            ),
            "Industry/Policy",
        )

    # --- Consumer Awareness: suspicious website ---
    def test_suspicious_websites_is_consumer_awareness(self):
        self.assertEqual(
            classify_article(
                "Websites with an undefined trust level: avoiding the trap",
                "We explain what suspicious websites are and how to distinguish a safe site.",
            ),
            "Consumer Awareness",
        )

    # --- Priority conflict guards ---
    def test_stealer_does_not_steal_from_ransomware(self):
        # Ransomware (prio 5) beats Malware (prio 8) even with "stealer"
        self.assertEqual(
            classify_article("LockBit deploys stealer before ransom demand", ""),
            "Ransomware",
        )

    def test_sentenced_does_not_steal_from_ransomware(self):
        # Ransomware keywords win over "sentenced" in Industry/Policy
        self.assertEqual(
            classify_article("Ransomware operator sentenced to 20 years", ""),
            "Ransomware",
        )

    def test_llm_does_not_steal_from_supply_chain(self):
        # Supply Chain (prio 11) beats AI Security (prio 9)?
        # Actually AI Security is higher prio. But "malicious package" is
        # in Supply Chain (prio 11). Let's verify "llm" in AI Security (prio 9)
        # correctly wins when both match.
        self.assertEqual(
            classify_article("Malicious npm package targets LLM deployments", ""),
            "AI Security",
        )

    def test_play_store_does_not_steal_from_malware(self):
        # Malware/Infostealer (prio 8) beats Mobile Security (prio 12)
        self.assertEqual(
            classify_article("Play Store trojan drops infostealer payload", ""),
            "Malware/Infostealer",
        )


class V12KeywordRegressionTests(unittest.TestCase):
    """v12 keyword expansion (Aegis maintenance 17-May-2026).

    Promotes 8 of 15 uncategorized articles via 12 new keywords across
    4 categories: Identity & Access, AI Security, Phishing & Social
    Engineering, Industry/Policy.
    """

    # --- Identity & Access: identity security ---
    def test_identity_security_is_identity_access(self):
        self.assertEqual(
            classify_article(
                "White House cyber official: identity security matters more than ever in the age of AI",
                "While AI tools present unique cybersecurity threats, they still rely on poor identity security.",
            ),
            "Identity & Access",
        )

    # --- AI Security: weaponized ai, ai sbom ---
    def test_weaponized_ai_is_ai_security(self):
        self.assertEqual(
            classify_article(
                "Weaponized AI: The new frontier of fraud and identity spoofing",
                "As fake identity fraud is projected to cause 40 billion in losses.",
            ),
            "AI Security",
        )

    def test_ai_sbom_is_ai_security(self):
        self.assertEqual(
            classify_article(
                "Major world economies spell out key elements of AI ingredients list",
                "G7 guidance on AI SBOM security is good but could use improvements.",
            ),
            "AI Security",
        )

    # --- Phishing & Social Engineering: identity spoofing ---
    def test_identity_spoofing_is_phishing(self):
        self.assertEqual(
            classify_article(
                "New identity spoofing technique bypasses email verification",
                "Attackers use identity spoofing to impersonate executives.",
            ),
            "Phishing & Social Engineering",
        )

    # --- Industry/Policy: cyber policy, odni, voter data, indictment, arrested, e2ee ---
    def test_cyber_policy_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "Pentagon cyber official calls advanced AI revolutionary warfare",
                "Principal deputy assistant secretary for cyber policy discussed cyber offense.",
            ),
            "Industry/Policy",
        )

    def test_odni_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "ODNI taps officials to coordinate response to foreign election threats",
                "Director of National Intelligence has tapped officials to monitor 2026 election threats.",
            ),
            "Industry/Policy",
        )

    def test_voter_data_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "DOJ releases legal rationale for nationwide voter data collection",
                "The memo claims a robust executive branch role vetting voter eligibility.",
            ),
            "Industry/Policy",
        )

    def test_indictment_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "Alleged Dream Market admin arrested in Germany after US indictment",
                "Court documents said Dream Market was launched in 2013.",
            ),
            "Industry/Policy",
        )

    def test_e2ee_is_industry_policy(self):
        self.assertEqual(
            classify_article(
                "iOS 26.5 Brings Default End-to-End Encrypted RCS Messaging",
                "Apple released iOS 26.5 with support for end-to-end encryption (E2EE).",
            ),
            "Industry/Policy",
        )

    # --- Priority conflict guards ---

    def test_arrested_does_not_steal_from_ransomware(self):
        # Ransomware (prio 5) beats "arrested" in Industry/Policy (prio 13)
        self.assertEqual(
            classify_article("Ransomware leader arrested by FBI", "The LockBit ransomware gang leader was arrested."),
            "Ransomware",
        )

    def test_indictment_does_not_steal_from_ransomware(self):
        # Ransomware keywords win over "indictment" in Industry/Policy
        self.assertEqual(
            classify_article("Grand jury indictment unsealed against ransomware operator", "The ransomware gang member faces federal charges."),
            "Ransomware",
        )

    def test_weaponized_ai_does_not_steal_from_malware(self):
        # Malware/Infostealer (prio 8) beats AI Security (prio 9)
        self.assertEqual(
            classify_article("New trojan uses weaponized ai for evasion", "The infostealer leverages weaponized ai to bypass detection."),
            "Malware/Infostealer",
        )

    def test_identity_security_vs_ai_security_priority(self):
        # Identity & Access (prio 4) beats AI Security (prio 9) when both match.
        # Known priority conflict: an article about AI attacks that also mentions
        # "identity security" will land in Identity & Access. Acceptable trade-off:
        # identity security articles are almost always about IAM, not AI attacks.
        self.assertEqual(
            classify_article(
                "AI-powered identity security threats emerge",
                "New prompt injection attacks target identity security systems using llm jailbreak techniques.",
            ),
            "Identity & Access",
        )

    def test_e2ee_does_not_steal_from_vulnerability(self):
        # Vulnerability/CVE (prio 6) beats Industry/Policy (prio 13)
        self.assertEqual(
            classify_article(
                "Critical vulnerability in end-to-end encryption library",
                "A zero-day exploit was found in the e2ee implementation.",
            ),
            "Vulnerability/CVE",
        )

    # --- Still Uncategorized (by design) ---
    def test_windows_driver_rollback_stays_uncategorized(self):
        self.assertEqual(
            classify_article(
                "Microsoft to automatically roll back faulty Windows drivers",
                "Microsoft is introducing a new capability for Windows Update.",
            ),
            "Uncategorized",
        )

    def test_dell_bsod_stays_uncategorized(self):
        self.assertEqual(
            classify_article(
                "Dell confirms its SupportAssist software causes Windows BSOD crashes",
                "Dell confirmed that its SupportAssist software is causing blue-screen crashes.",
            ),
            "Uncategorized",
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


class Stage1SaaSBreachExpansionTests(unittest.TestCase):
    """Lock in the 2026-05-18 SaaS Breach keyword expansion (Stage 1 of the
    category-pages roadmap).

    Three categories of test:
      1. Named SaaS-breach actors → SaaS Breach
      2. 2026 Q2 active campaigns (Canvas, Grafana, Trivy, TanStack/Mistral) →
         SaaS Breach
      3. New attack-pattern terms (OIDC theft, device-code phishing, MCP
         breach surface) → SaaS Breach

    Crossover guard: Shai-Hulud-family terms appear in SaaS Breach AND in
    Supply Chain via the existing `shai-hulud` keyword. SaaS Breach is
    priority 3 and Supply Chain is priority 11, so SaaS Breach must win
    when both fire. If this regresses, someone reshuffled category priority
    or moved a keyword.
    """

    # --- Named SaaS-breach threat actors ---

    def test_scattered_spider_is_saas_breach(self):
        self.assertEqual(
            classify_article(
                "Scattered Spider hits another casino with social-engineering campaign",
                "",
            ),
            "SaaS Breach",
        )

    def test_lapsus_dollar_is_saas_breach(self):
        # The `lapsus$` keyword with the literal $ — make sure the YAML
        # didn't drop it during parsing.
        self.assertEqual(
            classify_article("Lapsus$ resurfaces in extortion wave", ""),
            "SaaS Breach",
        )

    def test_octo_tempest_is_saas_breach(self):
        self.assertEqual(
            classify_article("Octo Tempest leverages stolen tokens against M365", ""),
            "SaaS Breach",
        )

    def test_uat_8616_is_saas_breach(self):
        # UAT-8616 is an APT actor. SaaS Breach (prio 3) wins over Nation
        # State/APT (prio 7) when both could fire — the SaaS Breach roster
        # tracks orgs hit, and the spotlight surfaces this row.
        self.assertEqual(
            classify_article("UAT-8616 SaaS abuse campaign expands", ""),
            "SaaS Breach",
        )

    # --- 2026 Q2 campaigns ---

    def test_canvas_breach_is_saas_breach(self):
        self.assertEqual(
            classify_article(
                "Canvas breach: ShinyHunters claim 275M student records",
                "",
            ),
            "SaaS Breach",
        )

    def test_instructure_breach_is_saas_breach(self):
        self.assertEqual(
            classify_article("Instructure breach impacts 8,809 institutions", ""),
            "SaaS Breach",
        )

    def test_grafana_token_breach_is_saas_breach(self):
        self.assertEqual(
            classify_article("Grafana token theft enables codebase exfiltration", ""),
            "SaaS Breach",
        )

    def test_medtronic_breach_is_saas_breach(self):
        self.assertEqual(
            classify_article("Medtronic breach exposes millions of records", ""),
            "SaaS Breach",
        )

    def test_trivy_breach_is_saas_breach(self):
        self.assertEqual(
            classify_article("Trivy breach compromises 1,000+ SaaS environments", ""),
            "SaaS Breach",
        )

    def test_tanstack_compromise_is_saas_breach(self):
        self.assertEqual(
            classify_article("TanStack compromise spans 169 npm packages", ""),
            "SaaS Breach",
        )

    # --- Crossover: Shai-Hulud must land in SaaS Breach, not Supply Chain ---

    def test_shai_hulud_is_saas_breach_not_supply_chain(self):
        # SaaS Breach priority (3) wins over Supply Chain priority (11).
        # If this fails, either category priority got reshuffled or
        # `shai-hulud` was removed from SaaS Breach.
        self.assertEqual(
            classify_article("Shai-Hulud worm spreads via npm tokens", ""),
            "SaaS Breach",
        )

    def test_mini_shai_hulud_is_saas_breach(self):
        self.assertEqual(
            classify_article("Mini Shai-Hulud poisons TanStack and Mistral AI", ""),
            "SaaS Breach",
        )

    def test_generic_supply_chain_still_works(self):
        # Regression guard: a generic supply-chain story with NO SaaS terms
        # should still land in Supply Chain. If we accidentally over-broadened
        # SaaS Breach keywords, this catches it.
        self.assertEqual(
            classify_article(
                "Open-source maintainers warn of expanding supply chain risk in package ecosystems",
                "",
            ),
            "Supply Chain",
        )

    # --- New attack-pattern terms ---

    def test_oidc_token_theft_is_saas_breach(self):
        self.assertEqual(
            classify_article("GitHub Actions token theft via OIDC abuse", ""),
            "SaaS Breach",
        )

    def test_pull_request_target_is_saas_breach(self):
        # The exact Actions trigger string — used in Mini Shai-Hulud coverage.
        self.assertEqual(
            classify_article("pull_request_target abuse poisons CI cache", ""),
            "SaaS Breach",
        )

    def test_device_code_phishing_is_saas_breach(self):
        self.assertEqual(
            classify_article(
                "Device-code phishing kit targets M365 accounts",
                "",
            ),
            "SaaS Breach",
        )

    def test_tycoon2fa_is_saas_breach(self):
        self.assertEqual(
            classify_article("Tycoon2FA evolves to bypass M365 MFA", ""),
            "SaaS Breach",
        )

    def test_consent_phishing_is_saas_breach(self):
        self.assertEqual(
            classify_article(
                "Consent phishing campaign abuses illicit consent grants",
                "",
            ),
            "SaaS Breach",
        )

    def test_mcp_server_breach_is_saas_breach(self):
        self.assertEqual(
            classify_article("MCP server breach exposes integration tokens", ""),
            "SaaS Breach",
        )

    def test_rag_pipeline_breach_is_saas_breach(self):
        self.assertEqual(
            classify_article(
                "RAG pipeline breach leaks internal corpus to attackers",
                "",
            ),
            "SaaS Breach",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
