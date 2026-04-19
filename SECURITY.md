# Security Policy

Threat-Feed is a small, public, read-only aggregator. It has no user accounts,
no user-generated content, and no admin UI. The security posture below is
designed around those constraints — simpler is safer, and every feature that
*doesn't* exist is attack surface that isn't there.

This document captures the load-bearing decisions. Changes to any section
below should go through the same security review (`/aegis-ciso`) that the
original decision did.

## Reporting a vulnerability

If you believe you've found a security issue, please open a GitHub issue
titled `[security]` with enough detail to reproduce. For anything you'd
rather not disclose in public, contact the maintainer directly before
filing.

Please **do not** file a PR that demonstrates the issue against the public
repo without coordinating first.

## Count disclosure policy

The `/api/stats` endpoint that exposed a cumulative `total_processed`
counter was removed in PR 3. That counter is still maintained server-side
(in the `stats` table) for operator inspection via the SQLite CLI, but no
public endpoint surfaces it.

**Why it was removed (Aegis S4):** a monotonically-increasing public
counter leaks two things for free:

1. **Ingestion cadence** — an attacker watching the counter at interval *t*
   learns how many items we pulled in that interval, which indirectly
   discloses our fetch schedule and the current state of the upstream
   feeds.
2. **Service-age & uptime signal** — the absolute value of the counter
   correlates to how long the service has been continuously running, which
   is useful for planning availability attacks.

Neither of those is offset by a legitimate reader-facing use case. The
article list itself (`/api/articles`) is the product; a cumulative count
isn't.

**Forward guidance:** any future endpoint that would expose an internal
counter (article count, visitor count, fetch count, error count, retry
count, etc.) should assume "no" by default and require an explicit
justification before shipping. If a count absolutely must be surfaced, cap
it (`"500+"`) or bucket it coarsely rather than leaking the exact figure.

## Tier anchor — the trust model for Confidence

The Confidence badge on every article is derived from a `source_tier`
field on each entry in the `FEEDS` list in `scheduler.py`. That file is
**the trust anchor**. Re-tiering a source is a pull request against
`scheduler.py`, reviewed the same way any other code change is.

**Why committed and not runtime-configurable (Aegis B1 / B4):**

- A runtime-settable tier (env var, admin endpoint, DB column) would mean
  that a reader's view of *whether to trust a source* could change
  silently between deploys, without a reviewable paper trail.
- The committed file is the audit log. `git blame` on any feed row
  tells you who tiered it, when, and in what commit — which is exactly
  what you want when a reader asks "why is this source MEDIUM?"
- There is no surface area for a misconfigured env var or a compromised
  admin credential to flip a Tier 3 aggregator into Tier 1.

The derivation itself (`confidence_for(tier)` in `confidence.py`) is a
pure function. It fails secure: any unknown/None/invalid input returns
`LOW`, never `HIGH`.

**Kill switch (Aegis S1):** `CONFIDENCE_ENABLED=false` in the environment
causes every article to render with confidence `UNSET` (frontend shows
`—`). This is a belt-and-braces lever for operators if a widespread
mistier needs to be hidden pending fix-up, without blocking deploys.

## Top Story curation model

`config/top_story.yml` is a **committed file**, not an admin endpoint.
Updating the Top Story is a pull request. There is no runtime mutation
API, no session state, no per-user Top Story.

**Why no admin endpoint (Aegis S2):** an endpoint that can change what
the entire reader base sees on the front page is a high-value target.
A PR flow gets the same benefits (change history, review, rollback) with
zero runtime attack surface. The value of "faster edits" does not offset
the cost of a compromised-credential path to homepage defacement.

**Fail-closed validation:** when `active: true` but any required field
is missing or invalid, `/api/top-story` returns `{"active": false}` and
the frontend falls back to using the first feed article as the visual
lead. A malformed Top Story never renders half-broken. See
[`TOP_STORY.md`](./TOP_STORY.md) for the full operator workflow.

## Defense-in-depth measures

These are in place as additional layers — each is individually useful and
together they form the baseline assumption that any single layer can fail
without rendering the whole app insecure.

### Content Security Policy

Every response carries a strict CSP (`app.py` / `set_security_headers`):

```
default-src 'none';
script-src 'self';
style-src 'self';
font-src 'self';
connect-src 'self';
img-src 'self' data:;
frame-ancestors 'none';
base-uri 'self';
form-action 'none';
```

Notable: no `'unsafe-inline'`, no `'unsafe-eval'`, no third-party
font/script/style origins. Fonts are self-hosted (`/static/fonts/*.woff2`)
so there is no `fonts.googleapis.com` or `fonts.gstatic.com` in the
connect graph. CSP regressions — especially re-introducing a third-party
origin — must be called out in review (Aegis B3).

### Transport security

`Strict-Transport-Security: max-age=31536000; includeSubDomains` is
emitted on every response. Preload list submission is a one-way
commitment and is held off until the production domain is stable.

### Other headers

`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
`Referrer-Policy: strict-origin-when-cross-origin` are set on every
response.

### Rate limiting

Per-route limits (`flask-limiter`) on every public endpoint. `memory://`
storage is correct for the single-worker Railway deploy; if the service
is ever scaled to multiple workers, the storage URI must be moved to
Redis or another shared backend before the change goes live (or the
limit becomes per-worker and the ceiling silently multiplies).

### SQL safety

All queries use `sqlite3` parameter substitution — no string-formatted
query construction anywhere. The `/api/articles` filter builder
(`category`, `since`) composes the WHERE clause from a fixed vocabulary
and still parameterizes all values.

### Fail-secure defaults (the pattern)

The recurring pattern across this codebase is: **when in doubt, return
the safest visible state, not an error page or an empty view**.

- Unknown source name → Confidence `LOW`, not `HIGH`.
- Unknown category → neutral Uncategorized accent, not a crash.
- Malformed Top Story YAML → `{"active": false}`, not a broken hero.
- Missing feed field → row dropped, not surfaced with nulls.

The cost of a reader seeing a too-low Confidence badge is low; the cost
of a reader seeing a too-high one is not.

## What this app does *not* have (by design)

- **No authentication, no accounts, no sessions.** Nothing to steal, no
  session fixation, no password reset flow.
- **No write path from readers.** No comments, no uploads, no form
  submissions. `form-action 'none'` in the CSP is enforced because
  there are no forms to submit.
- **No third-party network origins at runtime.** No CDN, no analytics,
  no fonts service, no error reporter. Everything the page needs is
  served from `'self'`.
- **No admin UI.** Operator actions are commits.
- **No per-user state.** Every reader sees the same feed, ordered the
  same way, with the same Confidence derivations.

Each of these is a feature. Adding any of them is a PR that has to argue
for the attack surface it introduces.
