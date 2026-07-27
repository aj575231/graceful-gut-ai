"""Tests for Secrets Manager resolution of the shared secret.

No test here constructs a real AWS client -- ``conftest.no_real_aws_clients``
turns any attempt into a failure. Cases that need Powertools' genuine caching
and JSON-transform behaviour go through the ``install_secret`` fixture, which
builds the real provider on a fake boto3 client; the rest replace
``app.secrets.fetch_secret`` outright.

The values below are fixed placeholders, not secrets. A real ``api_key`` never
appears in this repository, and none was created or retrieved to write these
tests.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import secrets
from app.config import API_KEY_HEADER, DEVELOPMENT, PRODUCTION
from app.main import UNCONFIGURED_DETAIL, create_app
from app.secrets import SECRET_ID_ENV, SecretUnavailableError

#: Not a secret. A recognisable placeholder, chosen so that a leak into a
#: response body or a log record is unmistakable when asserted against.
PLACEHOLDER_SECRET = "placeholder-secret-value-not-real"

#: Not a secret either -- an identifier, the kind of value ``GG_API_SECRET_ID``
#: legitimately holds. Asserted absent from client-facing output all the same.
PLACEHOLDER_SECRET_ID = "graceful-gut-ai/dev/api-key-placeholder"

#: The ``install_secret`` fixture from conftest, which returns the fake client
#: it installed so a test can count how often Powertools reached it.
InstallSecret = Callable[..., Any]


def secret_payload(value: object = PLACEHOLDER_SECRET) -> str:
    return json.dumps({"api_key": value})


def deployed_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A client in the deployed posture: gate enforced, secret from AWS."""
    monkeypatch.setenv("APP_ENV", PRODUCTION)
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    return TestClient(create_app())


# ---------------------------------------------------------------------------
# Posture: which source the key comes from
# ---------------------------------------------------------------------------


def test_development_reads_the_environment_without_touching_secrets_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local development must work with no AWS credentials at all."""
    monkeypatch.setenv("APP_ENV", DEVELOPMENT)
    monkeypatch.setenv("GG_API_KEY", PLACEHOLDER_SECRET)
    monkeypatch.delenv(SECRET_ID_ENV, raising=False)

    def explode(secret_id: str) -> object:
        raise AssertionError("development must not contact Secrets Manager")

    monkeypatch.setattr(secrets, "fetch_secret", explode)
    client = TestClient(create_app())

    assert (
        client.get("/version", headers={API_KEY_HEADER: PLACEHOLDER_SECRET}).status_code
        == 200
    )


def test_production_ignores_gg_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key left in the function's environment must not authenticate anyone.

    This is the point of the change: the deployed secret lives in Secrets
    Manager, so a stale ``GG_API_KEY`` on the function is inert.
    """
    monkeypatch.setenv("APP_ENV", PRODUCTION)
    monkeypatch.setenv("GG_API_KEY", PLACEHOLDER_SECRET)
    monkeypatch.delenv(SECRET_ID_ENV, raising=False)
    client = TestClient(create_app())

    response = client.get("/version", headers={API_KEY_HEADER: PLACEHOLDER_SECRET})

    assert response.status_code == 503
    assert response.json()["detail"] == UNCONFIGURED_DETAIL


def test_production_requires_the_secret_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(SECRET_ID_ENV, raising=False)

    with pytest.raises(SecretUnavailableError):
        secrets.resolve_secret_api_key()


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_secret_identifier_is_treated_as_unset(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, value)

    with pytest.raises(SecretUnavailableError):
        secrets.resolve_secret_api_key()


@pytest.mark.parametrize("value", ["dev", "staging", "prod", "Production", ""])
def test_every_non_development_posture_uses_secrets_manager(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret, value: str
) -> None:
    """``APP_ENV`` has two legal values; the rest must behave like production."""
    monkeypatch.setenv("APP_ENV", value)
    monkeypatch.setenv("GG_API_KEY", PLACEHOLDER_SECRET)
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(secret_payload("a-different-placeholder"))
    client = TestClient(create_app())

    # The environment key is ignored; only the Secrets Manager value works.
    assert (
        client.get("/version", headers={API_KEY_HEADER: PLACEHOLDER_SECRET}).status_code
        == 401
    )
    assert (
        client.get(
            "/version", headers={API_KEY_HEADER: "a-different-placeholder"}
        ).status_code
        == 200
    )


# ---------------------------------------------------------------------------
# Retrieval, through the real Powertools provider on a fake client
# ---------------------------------------------------------------------------


def test_successful_json_retrieval(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    fake = install_secret(secret_payload())

    assert secrets.resolve_secret_api_key() == PLACEHOLDER_SECRET
    assert fake.calls == [PLACEHOLDER_SECRET_ID]


def test_retrieval_is_cached_across_requests(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret
) -> None:
    """A burst of requests must cost one GetSecretValue call, not one each."""
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    fake = install_secret(secret_payload())
    client = deployed_client(monkeypatch)

    for _ in range(5):
        response = client.get("/version", headers={API_KEY_HEADER: PLACEHOLDER_SECRET})
        assert response.status_code == 200

    assert len(fake.calls) == 1


def test_missing_api_key_field_fails_closed(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(json.dumps({"other_field": "x"}))

    with pytest.raises(SecretUnavailableError):
        secrets.resolve_secret_api_key()


@pytest.mark.parametrize("value", ["", "   ", None, 12345, []])
def test_empty_or_non_string_api_key_fails_closed(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret, value: object
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(secret_payload(value))

    with pytest.raises(SecretUnavailableError):
        secrets.resolve_secret_api_key()


def test_malformed_json_fails_closed(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret("this is not json {")

    with pytest.raises(SecretUnavailableError):
        secrets.resolve_secret_api_key()


def test_json_scalar_payload_fails_closed(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret
) -> None:
    """Valid JSON that is not an object has no ``api_key`` to read."""
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(json.dumps("just-a-string"))

    with pytest.raises(SecretUnavailableError):
        secrets.resolve_secret_api_key()


def test_secrets_manager_access_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret
) -> None:
    """AccessDenied, throttling, and network errors all fail the same way."""
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(error=RuntimeError("AccessDeniedException: not authorized"))

    with pytest.raises(SecretUnavailableError):
        secrets.resolve_secret_api_key()


# ---------------------------------------------------------------------------
# Nothing sensitive reaches the client or the log
# ---------------------------------------------------------------------------


def leaky_error() -> RuntimeError:
    """An AWS-style error that quotes both the identifier and the value.

    Real ``botocore`` errors quote the secret ARN, and a transform error can
    quote the payload, so the sanitising has to be tested against the worst
    case rather than a tidy one.
    """
    return RuntimeError(
        f"AccessDenied on {PLACEHOLDER_SECRET_ID}: {PLACEHOLDER_SECRET}"
    )


def test_failure_response_is_opaque_and_uniform(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(error=leaky_error())
    client = deployed_client(monkeypatch)

    response = client.get("/version", headers={API_KEY_HEADER: "anything"})

    assert response.status_code == 503
    assert response.json() == {"detail": UNCONFIGURED_DETAIL}

    body = response.text
    assert PLACEHOLDER_SECRET not in body
    assert PLACEHOLDER_SECRET_ID not in body
    assert "AccessDenied" not in body
    assert "Traceback" not in body


def test_failure_log_carries_no_secret_or_identifier(
    monkeypatch: pytest.MonkeyPatch,
    install_secret: InstallSecret,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(error=leaky_error())
    client = deployed_client(monkeypatch)

    with caplog.at_level(logging.DEBUG):
        client.get("/version", headers={API_KEY_HEADER: "anything"})

    assert PLACEHOLDER_SECRET not in caplog.text
    assert PLACEHOLDER_SECRET_ID not in caplog.text
    # ...but the failure stays observable, or an operator cannot debug it.
    assert "Shared secret unavailable" in caplog.text


def test_successful_request_does_not_log_or_echo_the_secret(
    monkeypatch: pytest.MonkeyPatch,
    install_secret: InstallSecret,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(secret_payload())
    client = deployed_client(monkeypatch)

    with caplog.at_level(logging.DEBUG):
        ok = client.get("/version", headers={API_KEY_HEADER: PLACEHOLDER_SECRET})
        rejected = client.get("/version", headers={API_KEY_HEADER: "wrong"})
        health = client.get("/health")

    assert ok.status_code == 200
    assert rejected.status_code == 401
    assert health.status_code == 200

    for response in (ok, rejected, health):
        assert PLACEHOLDER_SECRET not in response.text
    assert PLACEHOLDER_SECRET not in caplog.text


# ---------------------------------------------------------------------------
# Existing boundaries, still intact under Secrets Manager
# ---------------------------------------------------------------------------


def test_health_stays_public_when_the_secret_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The liveness probe must not depend on Secrets Manager."""
    monkeypatch.setenv("APP_ENV", PRODUCTION)
    monkeypatch.delenv(SECRET_ID_ENV, raising=False)

    def explode(secret_id: str) -> object:
        raise AssertionError("/health must not resolve a secret")

    monkeypatch.setattr(secrets, "fetch_secret", explode)
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.parametrize("path", ["/", "/version", "/openapi.json", "/nope"])
def test_protected_routes_fail_closed_when_retrieval_fails(
    monkeypatch: pytest.MonkeyPatch, install_secret: InstallSecret, path: str
) -> None:
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(error=RuntimeError("unavailable"))
    client = deployed_client(monkeypatch)

    assert client.get(path).status_code == 503


def test_constructing_a_real_provider_is_blocked_in_tests() -> None:
    """Proves the no-AWS guard is live rather than assumed.

    If this ever stops raising, another test could reach AWS unnoticed.
    """
    secrets.set_provider(None)

    with pytest.raises(AssertionError, match="real AWS client"):
        secrets.get_provider()
