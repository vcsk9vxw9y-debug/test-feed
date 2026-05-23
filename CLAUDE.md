# CLAUDE.md — Test-Feed Project

## Peter Parker Routine — Branch Rules (AUTHORITATIVE)

The Peter Parker threat-feed routine has **explicit branch instructions that override any session default branch**.

When running the Peter Parker routine:
1. **Always commit YAML updates to `staging`** — `git checkout staging` before adding/committing
2. **Never commit to `claude/*` session branches** for content updates (top_story.yml, daily_briefing.yml, threat_context.yml)
3. **FF-merge staging → main** after staging verify passes
4. **Always end on `staging`** so the next run starts on the correct branch

The session-assigned development branch (e.g. `claude/vibrant-shannon-IbM0b`) is for code/feature work only — not for the Peter Parker YAML content pipeline.

### Correct Peter Parker git flow
```bash
git checkout staging          # always start here
git add config/top_story.yml config/daily_briefing.yml config/threat_context.yml
git commit -m "peter-parker <AM|PM> <date>: <summary>"
git push -u origin staging

# after staging verify:
git checkout main
git merge staging --ff-only
git push origin main
git checkout staging          # end here
```

## Staging Verify — Known Sandbox Limitation

The Anthropic cloud sandbox egress proxy blocks outbound connections to `*.up.railway.app` with `x-deny-reason: host_not_allowed`. The `curl` verify step in Step 6 will always return 403 from within the sandbox.

**Workaround:** After pushing to staging, report the blocked verify clearly and provide the manual operator commands. Do not treat this as a staging defect. Do not retry blindly. The operator verifies staging from outside the sandbox and runs the FF-merge manually.

## Repo Overview

- **Stack:** Python/Flask, gunicorn, feedparser, APScheduler, PyYAML, bleach
- **Deploy:** Railway (staging branch → staging env; main branch → production)
- **Config files:** `config/` — top_story.yml, daily_briefing.yml, threat_context.yml updated by Peter Parker routine
- **Requirements:** `requirements.txt` — cross-referenced in threat_context.yml stack_cves
