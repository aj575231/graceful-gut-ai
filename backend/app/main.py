from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.config import (
    API_KEY_HEADER,
    PUBLIC_PATHS,
    api_key,
    is_development,
    openapi_url,
)

APP_NAME = "Graceful Gut AI"
APP_VERSION = "0.1.0"

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


async def require_api_key(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Gate every non-public route behind the ``X-GG-Key`` shared secret.

    The Function URL is ``AuthType: NONE``, so this is the only thing standing
    between the internet and the application. It fails closed: if the gate is
    enforced but no secret is configured, requests are refused rather than
    served openly.
    """
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    expected = api_key()

    if not expected:
        if is_development():
            return await call_next(request)
        return JSONResponse(
            status_code=503,
            content={"detail": "Service is not configured for authenticated access."},
        )

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
