"""Tests for the shared-secret gate, schema exposure, and CORS posture.

The Function URL is ``AuthType: NONE``, so these behaviours are the only thing
between the internet and the application.

A deployed posture resolves its key from Secrets Manager, so the fixtures here
install a fake-backed provider rather than setting ``GG_API_KEY`` -- which
production now ignores. Where the secret *comes from* is covered in
``test_secrets.py``; this module is about what the gate does with it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import API_KEY_HEADER, DEVELOPMENT, PRODUCTION
from app.main import ALLOWED_ORIGINS, create_app
from app.secrets import SECRET_ID_ENV

#: Not a secret. A fixed placeholder used only to exercise the comparison in
#: ``require_api_key``; real keys never appear in this repository.
PLACEHOLDER_KEY = "placeholder-not-a-real-key"

#: An identifier, not a secret value.
PLACEHOLDER_SECRET_ID = "graceful-gut-ai/dev/api-key-placeholder"


@pytest.fixture
def secured_client(
    monkeypatch: pytest.MonkeyPatch, install_secret: Callable[..., Any]
) -> TestClient:
    """A client for a deployed-style app: gate enforced, secret resolvable.

    Every AWS deployment runs ``APP_ENV=production``, so that is the posture
    under test here.
    """
    monkeypatch.setenv("APP_ENV", PRODUCTION)
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(json.dumps({"api_key": PLACEHOLDER_KEY}))
    return TestClient(create_app())


@pytest.fixture
def unconfigured_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A misconfigured deployment: gate enforced but no secret to resolve."""
    monkeypatch.setenv("APP_ENV", PRODUCTION)
    monkeypatch.delenv("GG_API_KEY", raising=False)
    monkeypatch.delenv(SECRET_ID_ENV, raising=False)
    return TestClient(create_app())


@pytest.fixture
def development_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Local development only -- never a deployed posture."""
    monkeypatch.setenv("APP_ENV", DEVELOPMENT)
    monkeypatch.delenv("GG_API_KEY", raising=False)
    return TestClient(create_app())


def test_health_is_reachable_without_a_key(secured_client: TestClient) -> None:
    """The healthcheck must never require the secret."""
    assert secured_client.get("/health").status_code == 200


def test_protected_route_rejects_missing_key(secured_client: TestClient) -> None:
    response = secured_client.get("/version")

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing or invalid API key."


def test_protected_route_rejects_wrong_key(secured_client: TestClient) -> None:
    response = secured_client.get("/version", headers={API_KEY_HEADER: "wrong"})

    assert response.status_code == 401


def test_protected_route_accepts_correct_key(secured_client: TestClient) -> None:
    response = secured_client.get("/version", headers={API_KEY_HEADER: PLACEHOLDER_KEY})

    assert response.status_code == 200
    assert response.json()["version"]


def test_root_is_protected(secured_client: TestClient) -> None:
    assert secured_client.get("/").status_code == 401


def test_gate_fails_closed_when_secret_is_missing(
    unconfigured_client: TestClient,
) -> None:
    """A deployment with no secret must refuse, not serve openly."""
    response = unconfigured_client.get("/version")

    assert response.status_code == 503

    # ...while the healthcheck still works, so the failure is observable.
    assert unconfigured_client.get("/health").status_code == 200


def test_development_allows_unauthenticated_access(
    development_client: TestClient,
) -> None:
    assert development_client.get("/version").status_code == 200


@pytest.mark.parametrize("value", ["dev", "staging", "prod", "Production", ""])
def test_only_development_relaxes_the_gate(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Any APP_ENV that is not exactly "development" must fail closed.

    "dev" is called out explicitly: it was previously used as the deployed
    value, and it must never again be mistaken for a relaxed posture.
    """
    monkeypatch.setenv("APP_ENV", value)
    monkeypatch.delenv("GG_API_KEY", raising=False)
    monkeypatch.delenv(SECRET_ID_ENV, raising=False)
    client = TestClient(create_app())

    assert client.get("/version").status_code == 503
    assert client.get("/openapi.json").status_code == 503


def test_unset_app_env_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("GG_API_KEY", raising=False)
    monkeypatch.delenv(SECRET_ID_ENV, raising=False)

    assert TestClient(create_app()).get("/version").status_code == 503


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_doc_uis_are_disabled(secured_client: TestClient, path: str) -> None:
    response = secured_client.get(path, headers={API_KEY_HEADER: PLACEHOLDER_KEY})

    assert response.status_code == 404


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/nope"])
def test_gate_does_not_leak_which_routes_exist(
    secured_client: TestClient, path: str
) -> None:
    """Unauthenticated requests get 401 whether or not the route exists.

    The gate runs before routing, so an anonymous caller cannot enumerate the
    application's surface by distinguishing 401 from 404.
    """
    assert secured_client.get(path).status_code == 401


def test_openapi_schema_is_hidden_outside_development(
    secured_client: TestClient,
) -> None:
    response = secured_client.get(
        "/openapi.json", headers={API_KEY_HEADER: PLACEHOLDER_KEY}
    )

    assert response.status_code == 404


def test_openapi_schema_is_served_in_development(
    development_client: TestClient,
) -> None:
    assert development_client.get("/openapi.json").status_code == 200


def test_cors_allow_list_has_no_wildcard() -> None:
    assert "*" not in ALLOWED_ORIGINS
    assert all(origin.startswith("http") for origin in ALLOWED_ORIGINS)


def test_cors_echoes_allowed_origin_without_credentials(
    secured_client: TestClient,
) -> None:
    origin = ALLOWED_ORIGINS[0]

    response = secured_client.get("/health", headers={"Origin": origin})

    assert response.headers["access-control-allow-origin"] == origin
    assert "access-control-allow-credentials" not in response.headers


def test_cors_rejects_unlisted_origin(secured_client: TestClient) -> None:
    response = secured_client.get(
        "/health", headers={"Origin": "https://evil.example.com"}
    )

    assert "access-control-allow-origin" not in response.headers
