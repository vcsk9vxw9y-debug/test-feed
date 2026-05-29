# Peter Parker Routine — AM Run Report
**Date:** 2026-05-29  
**Run:** AM (07:00 UTC)  
**Status:** ✅ COMPLETE — merged to main

---

## Top Story Decision: RETAIN + UPDATE (notes only)

**Incumbent:** Verizon DBIR 2026 — Vulnerability Exploitation Overtakes Stolen Credentials as #1 Breach Entry Point  
**Score:** 9.2/10  
**Source:** SecurityWeek  
**Published:** 2026-05-25

The DBIR's landmark structural finding (first-ever #1 breach vector shift in 19 years of DBIR history) remains the rotation ceiling. No Exchange CVE-2026-42897 post-deadline mass-exploitation surge was confirmed as of 07:00 UTC. Notes updated to reflect AM run, Exchange deadline TODAY, and four new challengers evaluated.

### Replacement Candidates Evaluated

| Candidate | Recency | Impact | Relevance | Quality | Novelty | Score | Decision |
|---|---|---|---|---|---|---|---|
| SymJack (AI coding agent MCP symlink attack, Adversa AI/SecurityWeek) | 8.5 | 7.5 | 8.5 | 9.0 | 9.0 | **8.3** | Below 9.0 threshold |
| CVE-2026-41089 Netlogon wormable CVSS 9.8 (May 12 Patch Tuesday, Day 17) | 6.0 | 9.5 | 7.5 | 8.5 | 7.5 | **7.8** | Old + not in CISA KEV yet |
| FortiClient CVE-2026-35616 EKZ infostealer (CVSS 9.1, CISA KEV Day 53) | 5.5 | 7.5 | 6.5 | 8.5 | 6.5 | **6.8** | Below threshold |
| Canvas/Instructure breach (ShinyHunters, 3.65TB, 275M users, ransom May 11) | 4.0 | 5.0 | 5.0 | 8.5 | 5.0 | **5.5** | 18 days old |

**REPLACE triggers for PM May 29:** Exchange post-deadline confirmed mass-exploitation wave, OR SymJack active campaign >50 confirmed victims, OR any breaking story ≥ 9.0.

---

## Daily Briefing Summary

| # | Severity | Title |
|---|---|---|
| 1 | **critical** | Exchange CVE-2026-42897 — CISA KEV Deadline EXPIRES TODAY (May 29 EOD) |
| 2 | **critical** | TrapDoor Supply Chain + AI Coding Assistant Poisoning — Campaign Day 10, 384+ Versions |
| 3 | **high** | SymJack — Malicious Repository Symlinks Install Attacker-Controlled MCP Servers |
| 4 | **high** | CVE-2026-41089 — Windows Netlogon Wormable CVSS 9.8, Day 17 Unpatched |
| 5 | **high** | FortiClient CVE-2026-35616 — EKZ Infostealer via Fake Fortinet Update, CISA KEV Day 53 |

**Stats:** Exchange KEV deadline=0 (🔥), TrapDoor versions=384 (🔥), Netlogon days since patch=17 (🔥), FortiClient KEV days=53 (🔥), PAN-OS dwell=50

---

## Threat Context Highlights for Aegis

### stack_cves with in_requirements: true (urgent — affects our running code)

| CVE | Package | Severity | Status |
|---|---|---|---|
| CVE-2026-27205 | flask==3.1.3 (in requirements.txt) | medium | ✅ **PATCHED** — our pinned 3.1.3 is confirmed fixed (affects ≤3.1.2 only). Verify Railway image layer. |

**No new in_requirements: true CVEs this run.** Flask 3.1.3 remains the only in_requirements hit and it is patched.

### New CVEs Added This Run

| CVE | Package | Severity | in_requirements |
|---|---|---|---|
| CVE-2026-41089 | Windows Netlogon (Server 2012-2025) | critical | false |
| CVE-2026-35616 | FortiClient EMS (endpoint security mgmt) | critical | false |

### New MITRE Techniques Trending

| Technique | MITRE ID | Summary |
|---|---|---|
| AI Coding Agent MCP Server Hijack via Repo Symlink Deception (SymJack) | T1195.001 | Malicious repos embed renamed symlinks → AI coding agent installs attacker-controlled MCP server during approved file-copy |
| Security Product Update Channel Weaponized for Browser Credential Theft (FortiClient EKZ) | T1072 | CVE-2026-35616 abuses EMS VPN scripting workflow to push EKZ infostealer disguised as legitimate Fortinet update |
| Wormable Domain Controller RCE via Netlogon Stack Overflow (CVE-2026-41089) | T1210 | CVSS 9.8 unauthenticated SYSTEM RCE on DCs, autonomous worm propagation same class as MS08-067/Zerologon |

### stack_intersection Alerts (new this run)

**NEW — SymJack direct Claude Code threat:** Adversa AI confirmed SymJack against Claude Code specifically. Malicious symlinks in repositories silently insert attacker-controlled MCP servers into Claude Code config during approved file operations. Update Claude Code to hardened build (symlink resolution before approval). Audit `~/.claude/mcp_servers` and all `.mcp.json` files for unexpected entries. INDEPENDENT of TrapDoor.

**UPDATED — Exchange CVE-2026-42897:** Deadline is TODAY May 29 EOD (was T-1 in previous run). OWA restriction to VPN/zero-trust is mandatory now. EEMS/EOMT gaps confirmed May 19 mean only post-May-19 verifications are valid.

### Landscape Summary Excerpt

> AM May 29 — Exchange CVE-2026-42897 CISA KEV deadline expires TODAY EOD with no permanent patch and confirmed EEMS/EOMT gaps since May 19; OWA restriction to VPN/zero-trust is the only reliable defense and is mandatory now for every on-premises Exchange deployment. SymJack (Adversa AI, SecurityWeek) is a new AI coding agent attack technique that uses renamed symlinks in malicious repositories to silently install attacker-controlled MCP servers during approved file operations — confirmed against Claude Code, Cursor, Copilot, Gemini CLI, Grok Build, and Codex CLI; hardened Claude Code builds resolve symlinks before approval, but unupdated installations remain exposed. CVE-2026-41089 Windows Netlogon (CVSS 9.8, wormable, May 12 Patch Tuesday — Day 17 unpatched) enables unauthenticated domain controller RCE with autonomous propagation in the same class as MS08-067; FortiClient CVE-2026-35616 (CISA KEV Day 53) EKZ infostealer campaign continues delivering browser credential theft via weaponized EMS update pushes; TrapDoor AI assistant poisoning campaign (Day 10, 34 packages/384+ versions across npm/PyPI/Crates.io) and all concurrent developer-targeting threats remain active and unresolved for our Python/Flask development stack.

---

## Staging Verify Results

| Check | Result |
|---|---|
| `curl` HTTP status: `https://web-staging-a0a9.up.railway.app/` | ✅ **200** |
| `/api/top-story` returns `active: true` + DBIR content | ✅ **PASS** |
| `/api/briefing` returns 5 actions + 5 stats with correct titles | ✅ **PASS** |
| `/api/articles?since=24h` returns non-empty JSON array | ✅ **PASS** (1 article) |
| Hero/briefing sections (JS-hydrated): API data correct | ✅ **PASS** |

All checks passed. No rendering errors, no 500s, no empty containers reported by API.

---

## Push Status

| Step | Result |
|---|---|
| `git push origin staging` | ✅ `cca3c87..7054e9a` |
| Staging verify | ✅ All checks passed |
| `git merge staging --ff-only` (to main) | ✅ Fast-forward |
| `git push origin main` | ✅ `d68909a..7054e9a` |
| Ended on `staging` branch | ✅ |

**Production SHA:** `7054e9a`  
**Merged to main:** Yes

---

## Notes for Aegis / Next Run

- **Exchange post-deadline watch:** May 29 EOD is today. Watch for confirmed mass-exploitation reporting from threat intel feeds (Mandiant, Recorded Future, Microsoft MSRC) as the day progresses. If a confirmed exploitation surge emerges PM run, REPLACE the DBIR top story.
- **SymJack:** Research disclosure as of this run — no active campaigns confirmed. Track for PM run; if weaponization reported (>50 victims), reconsider for top story.
- **CVE-2026-41089 Netlogon:** Not in CISA KEV as of AM run. CVSS 9.8 wormable DCs — if CISA adds to KEV or active exploitation is confirmed by PM, escalate.
- **TrapDoor Day 10:** Campaign still active, no takedown. Package count (34) has not yet crossed prior REPLACE threshold (>200 packages). Watch for expansion.
- **FortiClient CVE-2026-35616:** Added to threat_context this run. CISA KEV Day 53 — mature active campaign, monitor for new victim disclosures.
- **threat_context expires:** 2026-06-01T07:00:00Z (72h from this run)
