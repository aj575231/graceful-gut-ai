from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


APP_NAME = "Graceful Gut AI"
APP_VERSION = "0.1.0"

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
)

# Development-only configuration.
# Production origins will be explicitly restricted later.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Content-Type"],
)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp_utc: str


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
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/version")
def version() -> dict[str, str]:
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
    }
