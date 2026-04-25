"""
Shared test setup — patches sqlite3.connect once so every test module
routes DB access to an isolated per-module temp path.

Previously each test file did its own module-level monkey-patch of
sqlite3.connect, causing collisions when unittest discover imported
them all. This conftest centralizes the patch: each module calls
``get_test_db(name)`` to get a unique /tmp path, and ``patch_db(path)``
to install the redirect.

Usage in test modules:

    from tests.conftest import get_test_db, patch_db, get_app

    _TEST_DB = get_test_db("smoke")
    patch_db(_TEST_DB)

    app, init_db = get_app()
    init_db()
"""

import os
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_real_connect = sqlite3.connect
_current_test_db = None


def get_test_db(name):
    """Return a unique /tmp DB path for the given test module name."""
    path = f"/tmp/testfeed_{name}.db"
    if os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass
    return path


def patch_db(test_db_path):
    """Install the sqlite3.connect redirect for this test module.

    Any connection to the app's known DB paths (./testfeed.db or
    /data/testfeed.db) is rerouted to test_db_path. Other paths
    (e.g. :memory:) pass through unchanged.
    """
    global _current_test_db
    _current_test_db = test_db_path

    def _redirect(path, *args, **kwargs):
        if path in ("./testfeed.db", "/data/testfeed.db"):
            path = _current_test_db
        return _real_connect(path, *args, **kwargs)

    sqlite3.connect = _redirect


def get_app():
    """Import and return (app, init_db) after stubbing the scheduler.

    Must be called AFTER patch_db() so the app sees the redirected DB.
    """
    import scheduler
    scheduler.fetch_all_feeds = lambda *a, **kw: None

    from app import app, init_db
    return app, init_db


def real_connect(path, *args, **kwargs):
    """Direct access to the real sqlite3.connect (for seeding fixtures)."""
    return _real_connect(path, *args, **kwargs)
