# Top Story — operator guide

The Top Story hero at the top of the Threat-Feed front page is **curated**,
not auto-picked from the feed. Curation is an editorial act — the decision
of which story deserves the hero slot is a judgment call that deserves a
human in the loop and an auditable trail.

This document is the operator workflow for updating it.

## Design decisions (and why)

### 1. Curation, not ranking

The Top Story is not the highest-ranked article by some score. It is
whichever story the operator believes is the most important thing a reader
should see today — which requires editorial judgment no scoring function
can replicate.

### 2. Committed YAML, not an admin endpoint

`config/top_story.yml` is the single source of truth. Re-curation is a pull
request against that file. There is no admin UI, no runtime API to mutate
state, no session state, and no per-user Top Story.

The security rationale (Aegis S2): an admin endpoint is new attack surface
for a feature that doesn't need one. A PR against a committed file gets
the same benefits (change history, review, rollback) without any of the
runtime attack surface.

### 3. `active` flag, not silent fallback

When `active: false`, the frontend falls back to using the feed's first
article as the visual lead. This is the deliberate "nothing curated right
now" state — not an error condition. Operators can leave `active: false`
indefinitely with no ill effect.

When `active: true` but any required field is missing or invalid, the
backend treats the whole file as inactive and returns `{"active": false}`
from `/api/top-story`. Fail-closed — a malformed Top Story never renders
half-broken on the page.

## Schema

```yaml
active: true                                # required, bool
title: "CVE-2026-XXXX: RCE in ..."          # required, string
summary: >                                  # required, string (1–3 sentences)
    A single-paragraph summary the reader can act on without clicking through.
url: "https://vendor.example/advisory"      # required, string; primary source
source_name: "Vendor PSIRT"                 # required, string; must match a
                                            #   FEEDS[*].name when possible so
                                            #   the confidence badge resolves
published_at: "2026-04-18T14:00:00Z"        # required, ISO 8601 UTC
category: "Vulnerabilities"                 # required, matches categoryMap
key_points:                                 # optional, 3–5 bullets
  - "Single-fact bullet"
  - "Single-fact bullet"
  - "Single-fact bullet"
notes: |                                    # optional, operator-only
    Free-form context for future maintainers. Not rendered to readers.
```

## Workflow — curating a new Top Story

1. Identify the story. A Top Story is a primary-source item that deserves the
   hero slot for the day. If you find yourself reaching, leave the current
   one in place and flip `active: false` rather than curate something weak.

2. Open `config/top_story.yml`.

3. Update every required field with the primary source's own facts —
   **not** a secondary rewrite. Prefer vendor PSIRTs, government CERT
   advisories, and primary research blogs over aggregators.

4. Write 3–5 key points. Each one should be a verifiable, single-fact claim
   you'd be willing to defend. No speculation, no hedging, no editorializing.

5. Set `active: true`.

6. Commit. Suggested message format:

   ```
   top story: <short title>

   <1–2 sentences on why this story deserves the hero slot today>
   ```

7. Push. Railway auto-deploys on staging merge. The new Top Story is live at
   the next request — no service restart required.

## Workflow — retiring the current Top Story

Two options depending on urgency:

- **Clean retirement:** flip `active: false`, commit, push. The feed falls
  back to first-article-as-lead.
- **Replacement:** curate a new story using the workflow above. Replacing
  implicitly retires the old one — git history is the audit trail.

Never delete `config/top_story.yml` to "turn it off" — the file is part of
the committed contract and its absence is an error state, not a disabled
state.

## Security posture (per Aegis review)

- **S2 (no admin endpoint):** Curation happens through the PR flow. Any
  proposed runtime mutation mechanism is a regression.
- **No user-generated content:** Top Story fields are committed by operators
  and rendered directly. No sanitization bypass needed, but the frontend
  still uses `textContent` / escaped-HTML insertion as a defense-in-depth
  layer. A Top Story YAML field cannot cross the XSS boundary.
- **Fail-closed validation:** malformed YAML or missing required fields
  make the entire Top Story inactive rather than rendering partial state.

## Operational notes

- **No staleness auto-hide.** If the Top Story has been active for a week
  without update, it keeps rendering — that's an operator decision, not a
  service-level one. Periodic curation is the operator's responsibility.
  A dashboard or nag mechanism is a future add.
- **Source name + Confidence.** When the `source_name` matches a FEEDS
  entry, the lead card picks up that source's Confidence tier. When it
  doesn't match (custom name, pre-FEEDS source), the lead shows LOW by the
  fail-secure default.
- **Category must match categoryMap.** An unrecognized category renders
  with the neutral Uncategorized accent. Safe failure, but worth catching
  at PR review time.
