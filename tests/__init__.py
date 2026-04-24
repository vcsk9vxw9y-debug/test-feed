# Makes tests/ a package so `python -m unittest discover` finds the suite
# whether it's run from the repo root or from CI.

import os
import sys
from pathlib import Path

# app.py fails fast if SITE_URL is unset (see "Canonical site URL" block).
# Tests need a placeholder; real deploys set the env var explicitly.
os.environ.setdefault("SITE_URL", "http://localhost:5000")

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# test_feed_xml / test_smoke stub scheduler.fetch_all_feeds at import time
# so `import app` doesn't hit live RSS. Capture the real function here —
# this package __init__ runs before any test module imports — so tests that
# *do* exercise fetch_all_feeds can reach it via scheduler._REAL_FETCH_ALL_FEEDS.
import scheduler  # noqa: E402

if not hasattr(scheduler, "_REAL_FETCH_ALL_FEEDS"):
    scheduler._REAL_FETCH_ALL_FEEDS = scheduler.fetch_all_feeds
