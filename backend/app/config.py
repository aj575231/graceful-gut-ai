"""Environment-driven configuration and security posture.

Every helper reads ``os.environ`` at call time rather than at import time, so
tests can monkeypatch the environment and deployed processes pick up their
configuration without import-order surprises.
"""

from __future__ import annotations

import os

#: The only ``APP_ENV`` value that relaxes security. Local development only --
#: it must never be set on a deployed function. See CLAUDE.md.
DEVELOPMENT = "development"

#: The secure, fail-closed posture. Every AWS deployment runs with this value,
#: regardless of which stage the deployment represents -- ``APP_ENV`` names a
#: security posture, not an environment tier. There is no third value: anything
#: other than ``development`` is treated exactly like ``production``.
PRODUCTION = "production"

#: Shared-secret header checked on every route that is not exempt.
API_KEY_HEADER = "X-GG-Key"

#: Routes reachable without the shared secret. ``/health`` is a liveness probe
#: relied on by the docker-compose healthcheck and any uptime monitor, and it
#: exposes no sensitive data.
PUBLIC_PATHS = frozenset({"/health"})


def app_env() -> str:
    """Return the current environment name, defaulting to a locked-down value.

    Defaulting to ``PRODUCTION`` means a missing ``APP_ENV`` fails closed.
    """
    return os.environ.get("APP_ENV", PRODUCTION).strip().lower()


def is_development() -> bool:
    return app_env() == DEVELOPMENT


def api_key() -> str:
    """Return the configured shared secret, or an empty string if unset."""
    return os.environ.get("GG_API_KEY", "").strip()


def openapi_url() -> str | None:
    """Serve the OpenAPI schema in local development only."""
    return "/openapi.json" if is_development() else None
