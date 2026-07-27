from __future__ import annotations

import hmac
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.config import (
    API_KEY_HEADER,
    PUBLIC_PATHS,
    is_development,
    openapi_url,
    resolve_api_key,
)
from app.secrets import SecretUnavailableError

logger = logging.getLogger(__name__)

APP_NAME = "Graceful Gut AI"
APP_VERSION = "0.1.0"

#: The one response for "the gate is enforced but no usable secret is
#: available". Deliberately opaque and identical for every cause: it names
#: neither the secret identifier nor which step of resolution failed, so a
#: caller cannot probe the configuration through it.
UNCONFIGURED_DETAIL = "Service is not configured for authenticated access."

# Development-only configuration.
# Production origins will be explicitly restricted later.
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp_utc: str


def service_unconfigured() -> JSONResponse:
    """The fail-closed response, identical for every resolution failure."""
    return JSONResponse(status_code=503, content={"detail": UNCONFIGURED_DETAIL})


async def require_api_key(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Gate every non-public route behind the ``X-GG-Key`` shared secret.

    The Function URL is ``AuthType: NONE``, so this is the only thing standing
    between the internet and the application. It fails closed: if the gate is
    enforced but no secret can be resolved -- unset identifier, Secrets Manager
    unreachable, malformed payload -- requests are refused rather than served
    openly.

    Deployed postures resolve the secret from Secrets Manager. That call is
    synchronous and briefly blocks the event loop, which is acceptable here:
    Powertools caches the result per warm container, so it happens at most once
    per cache window rather than once per request.
    """
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    try:
        expected = resolve_api_key()
    except SecretUnavailableError as exc:
        # The reason goes to CloudWatch and never to the caller. It carries no
        # secret value, no secret identifier, and no AWS response or traceback.
        logger.warning("Shared secret unavailable: %s", exc)
        return service_unconfigured()

    if not expected:
        # Reachable in development only: every other posture raises above
        # rather than returning an empty secret.
        if is_development():
            return await call_next(request)
        return service_unconfigured()

    provided = request.headers.get(API_KEY_HEADER, "")
    if not hmac.compare_digest(provided, expected):
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing or invalid API key."},
        )

    return await call_next(request)


def create_app() -> FastAPI:
    """Build the application, reading security posture from the environment.

    A factory rather than a bare module-level app so that tests can construct
    an instance under a specific ``APP_ENV`` -- ``openapi_url`` is fixed at
    construction time and cannot be monkeypatched afterwards.
    """
    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=openapi_url(),
    )

    # Added first, so it sits *inside* CORS: browser preflight requests carry
    # no X-GG-Key and must be answered by CORSMiddleware before reaching here.
    app.middleware("http")(require_api_key)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Content-Type", API_KEY_HEADER],
    )

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "service": APP_NAME,
            "message": "Graceful Gut AI service is running.",
        }

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="healthy",
            service=APP_NAME,
            version=APP_VERSION,
            timestamp_utc=datetime.now(UTC).isoformat(),
        )

    @app.get("/version")
    def version() -> dict[str, str]:
        return {
            "service": APP_NAME,
            "version": APP_VERSION,
        }

    return app


app = create_app()
