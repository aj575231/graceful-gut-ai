"""Shared test configuration.

``app.main`` builds its application at import time, so the environment has to
be settled here -- before any test module imports it. The default posture for
the suite is local development with no shared secret configured; tests that
care about the security gate set their own environment and call
``create_app()`` to get an instance built under it.
"""

from __future__ import annotations

import os

os.environ["APP_ENV"] = "development"
os.environ.pop("GG_API_KEY", None)
