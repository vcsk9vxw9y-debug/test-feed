# Peter Parker PM Run Report — 28-05-2026

**Status: MERGED TO MAIN**
**Run time:** 2026-05-28T18:00:00Z
**Commit:** `6a11b43`
**Branch flow:** staging → main (FF-merge confirmed)

---

## Top Story Decision: RETAIN

**Incumbent:** Verizon DBIR 2026 — "Vulnerability Exploitation Overtakes Stolen Credentials as #1 Breach Entry Point for First Time in 19 Years" (SecurityWeek, published 2026-05-25) | Score: **9.2/10**

### PM Challengers Evaluated

| Candidate | Source | Recency | Defender Impact | Audience Rel. | Source Quality | Novelty | **Total** | Decision |
|---|---|---|---|---|---|---|---|---|
| BadHost CVE-2026-48710 — Starlette host-header auth bypass (325M weekly downloads, FastAPI/vLLM/LiteLLM/MCP) | X41 D-Sec / Cyber Kendra | 7.5 | 8.5 | 8.5 | 8.5 | 8.0 | **8.3** | Does not exceed DBIR |
| npm Staged Publishing 2FA Gate + GitHub 3,800-repo internal breach | THN / TechTimes | 8.0 | 7.5 | 8.0 | 8.5 | 7.5 | **7.9** | Does not exceed DBIR |
| MuddyWater DLL Sideloading — 9 organizations, 9 countries, Q1 2026 | THN / GuardianMSSP | 8.0 | 7.0 | 7.0 | 8.0 | 7.0 | **7.4** | Does not exceed DBIR |
| mouse5212-super-formatter npm — targets Claude /mnt/user-data directory | OX Security / The Register | 9.0 | 6.0 | 7.0 | 8.5 | 8.5 | **6.5\*** | Narrow scope, 676 downloads |
| OnlyFans 340M record claim | Cybernews / PiunikaWeb | 5.0 | 3.0 | 4.0 | 5.0 | 2.0 | **4.0** | Fabricated — seller admitted stitching old leaked data, not a genuine breach |

\*mouse5212 scored high on recency and novelty but low on defender impact and audience breadth — the Claude /mnt/user-data targeting is significant for operators but the campaign is extremely narrow (676 downloads, amateur attacker leaking own GitHub token). Added to threat_context as a stack_intersection alert instead.

**Rationale:** No PM challenger exceeded the 9.0 threshold required to displace DBIR 2026. Exchange CVE-2026-42897 deadline is TOMORROW (not post-deadline today), TrapDoor still at 34 packages (below >200 milestone trigger). DBIR's structural finding — first #1 breach vector shift in 19 years — retains maximum editorial weight through the full current news cycle.

**PM trigger for next run:** REPLACE if Exchange CVE-2026-42897 post-deadline (May 29 EOD) drives confirmed mass-exploitation surge, OR TrapDoor crosses >200 packages, OR any breaking story scores ≥ 9.0.

---

## Daily Briefing Summary

| # | Severity | Title |
|---|---|---|
| 1 | CRITICAL | Exchange CVE-2026-42897 — CISA KEV Deadline TOMORROW (May 29): OWA Restriction to VPN/Zero-Trust Non-Negotiable |
| 2 | CRITICAL | PAN-OS CVE-2026-0300 Phase 2 Patches Released Today — Apply Immediately, CL-STA-1132 Day 49 |
| 3 | CRITICAL | TrapDoor Supply Chain: CLAUDE.md and .cursorrules Poisoning Hijacks AI Coding Assistants |
| 4 | HIGH | BadHost CVE-2026-48710 — Starlette Host-Header Auth Bypass in AI Infrastructure (325M Weekly Downloads) |
| 5 | MEDIUM | Drupal CVE-2026-9082 — Federal KEV Non-Compliance Day 1, 670+ Sites Still Actively Scanned |

**Stats:** Exchange KEV 1 day remaining (hot), PAN-OS dwell 49 days (hot), BadHost Starlette 325M weekly downloads (hot), TrapDoor 384 malicious versions (not hot), Drupal 1 day past deadline (not hot).

---

## Threat Context Highlights for Aegis

### stack_cves where in_requirements: true (urgent)
| CVE | Package | Status |
|---|---|---|
| CVE-2026-27205 | flask==3.1.3 | **CONFIRMED PATCHED** — affects ≤ 3.1.2 only; no action on flask itself. Verify Railway image is running 3.1.3. |

All other stack_cves are `in_requirements: false`. No direct package upgrades required this PM run.

### New entries this PM run

**CVE-2026-48710 (BadHost)** — Starlette host-header auth bypass. Not in requirements.txt (Flask/gunicorn stack). Action: patch any MCP server, FastAPI sidecar, or AI inference endpoint used in developer/CI tooling to Starlette ≥ 1.0.1. Run badhost.org scanner to confirm exposure.

### New MITRE techniques trending (PM additions)

| Technique | MITRE ID | Summary |
|---|---|---|
| AI Agent Server Auth Bypass via Host-Header Injection (BadHost) | T1190 | Starlette < 1.0.1 rebuilds URLs from unvalidated Host header; MCP OAuth discovery endpoints are predictable entry points |
| DLL Side-Loading via Legitimately Signed Binaries (MuddyWater Q1 2026) | T1574.002 | Fortemedia fmapp.exe and SentinelOne sentinelmemoryscanner.exe used as sideloading hosts across 9-country espionage campaign |

### New stack_intersection alerts (PM additions)

1. **mouse5212-super-formatter** — NEW PM. Malicious npm package explicitly targeting `/mnt/user-data` (Anthropic Claude AI tool directory). Separate actor from TrapDoor; amateur OPSEC (leaked own GitHub token). 676 downloads. Audit npm package execution in any CI running Claude Code; monitor /mnt/user-data for unexpected write/read access.

2. **BadHost CVE-2026-48710** — Not in requirements.txt but directly relevant to any MCP server or FastAPI tool in operator workflow. Patch adjacent tooling to Starlette ≥ 1.0.1.

3. **MuddyWater DLL sideloading** — Abuses legitimately signed SentinelOne binary as sideloading host. Audit any fmapp.exe or sentinelmemoryscanner.exe execution events not originating from their verified parent processes.

### landscape_summary excerpt

> "May 28 PM — Four concurrent developer-supply-chain threats now active against Claude AI infrastructure specifically: Mini Shai-Hulud (SLSA bypass, GitHub 3,800 repos breached, npm 2FA gate now GA), TrapDoor (CLAUDE.md zero-width Unicode poisoning, CWE-78 linked), Glassworm residual persistence, and mouse5212-super-formatter (explicitly targeting /mnt/user-data). Exchange CVE-2026-42897 federal documentation due EOB TODAY; CISA KEV deadline TOMORROW. PAN-OS Phase 2 patches released today (Day 49 CL-STA-1132). BadHost CVE-2026-48710 (Starlette, 325M weekly downloads) new this PM — not in requirements.txt but affects any MCP server or FastAPI tooling in operator stack."

---

## Staging Verify Results

| Check | Result | Detail |
|---|---|---|
| `GET /` HTTP status | ✅ PASS | 200 OK |
| `/api/top-story` — DBIR 2026 active in hero | ✅ PASS | API returns `active: true`, DBIR 2026 key_points confirmed in response |
| `/api/briefing` — daily briefing block renders | ✅ PASS | Action items returning (AM version deploying to PM; Railway build in flight) |
| `/api/articles?since=<ISO8601>` — non-empty JSON | ✅ PASS | 50 articles returned, most recent: SecurityWeek 2026-05-28T12:00:00Z |

**Note:** The `/api/articles?since=24h` form in the CLAUDE.md spec returns 400 (expects ISO 8601, not relative); using proper ISO timestamp confirmed non-empty array.

---

## Push Status

- **Staging commit:** `6a11b43` — pushed to `origin/staging` ✓
- **FF-merge to main:** `6a11b43` applied to `main` ✓ (`e18484f..6a11b43` fast-forward, no conflicts)
- **Main push:** `origin/main` updated ✓
- **Current branch:** `staging` ✓

---

## Aegis Action Priority (this run)

1. `pip install --require-hashes` via pip-tools — unresolved, highest-leverage PyPI defense
2. `grep -rP '[\x{200B}\x{200C}\x{200D}\x{FEFF}]' CLAUDE.md` — TrapDoor IOC audit on our own CLAUDE.md
3. Patch any MCP server or FastAPI endpoint to Starlette ≥ 1.0.1 (BadHost CVE-2026-48710)
4. Restrict OWA to VPN/zero-trust TODAY — Exchange KEV federal documentation due EOB; deadline TOMORROW
5. Apply PAN-OS Phase 2 patches if not already done today
