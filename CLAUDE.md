# CLAUDE.md — Test-Feed Project

## Branch Rules — AUTHORITATIVE FOR ALL ROUTINES

Both the **Peter Parker** threat-feed routine and the **Aegis** maintenance routine commit directly to `staging`. The session-assigned development branch (e.g. `claude/vibrant-shannon-IbM0b`) is irrelevant for both — ignore it for any work in this repo.

| Work type | Branch |
|---|---|
| Peter Parker YAML updates (top_story, daily_briefing, threat_context) | `staging` |
| Aegis code changes (categories.yml, app.py, classifier, tests) | `staging` |
| Merging to production after verify passes | `main` via FF-merge from staging |

**Never commit to a `claude/*` session branch for either routine.**

---

## Peter Parker Routine — Git Flow

```bash
git checkout staging
git add config/top_story.yml config/daily_briefing.yml config/threat_context.yml
git commit -m "peter-parker <AM|PM> <date>: <1-line summary>"
git push -u origin staging

# After staging verify passes:
git checkout main
git merge staging --ff-only
git push origin main
git checkout staging          # always end here
```

## Aegis Maintenance Routine — Git Flow

```bash
git checkout staging
# make code changes (categories.yml, app.py, tests, etc.)
git add <files>
git commit -m "aegis-maintenance <date>: <1-line summary>"
git push -u origin staging

# After staging verify passes:
git checkout main
git merge staging --ff-only
git push origin main
git checkout staging          # always end here
```

---

## Staging Verify

Before merging to main, verify:
```bash
curl -sf -o /dev/null -w "%{http_code}" https://web-staging-a0a9.up.railway.app/
# Must return 200

curl -sf https://web-staging-a0a9.up.railway.app/api/articles?since=24h | head -c 200
# Must return non-empty JSON array
```

### Sandbox limitation (prior sessions)
The Anthropic cloud sandbox egress proxy blocked `*.up.railway.app` with `x-deny-reason: host_not_allowed`. This has been resolved — web access was updated to allow the Railway domain. If a future session still hits 403 on verify, check whether the allowlist change is active before treating it as a staging defect.

---

## Repo Overview

- **Stack:** Python/Flask, gunicorn, feedparser, APScheduler, PyYAML, bleach
- **Deploy:** Railway — `staging` branch → staging env; `main` branch → production
- **Peter Parker config files:** `config/top_story.yml`, `config/daily_briefing.yml`, `config/threat_context.yml`
- **Aegis code files:** `categories.yml`, `app.py`, `classifier.py`, `tests/`
- **Requirements:** `requirements.txt` — cross-referenced in threat_context.yml `stack_cves`
