"""Guard the deployment script's unauthenticated smoke-test expectations.

``scripts/deploy-lambda.sh`` holds no shared secret and must never fetch one,
so every request its smoke test makes is unauthenticated. That constrains what
it is allowed to expect: the gate in ``app.main`` runs *before* route
resolution, so an anonymous caller receives 401 on every gated path regardless
of whether the route exists. Hiding the schema shows up as 404 only for an
authenticated caller.

The script previously expected 404 from an unkeyed ``/openapi.json``. That is
unsatisfiable against a correctly gated deployment -- it can only pass if the
gate leaks which routes exist -- and it failed the smoke test on an otherwise
healthy Phase 1D deployment. These tests pin the corrected expectation to the
application's actual behaviour so the two cannot drift apart again.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import PRODUCTION
from app.main import create_app
from app.secrets import SECRET_ID_ENV

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy-lambda.sh"

#: Not a secret -- a fixed placeholder, as in ``test_security.py``.
PLACEHOLDER_KEY = "placeholder-not-a-real-key"
PLACEHOLDER_SECRET_ID = "graceful-gut-ai/dev/api-key-placeholder"

#: ``[[ "${OPENAPI_CODE}" == "401" ]]`` -- the literal the script asserts.
OPENAPI_ASSERTION = re.compile(r'\[\[\s*"\$\{OPENAPI_CODE\}"\s*==\s*"(\d{3})"\s*\]\]')


@pytest.fixture(scope="module")
def script_source() -> str:
    return DEPLOY_SCRIPT.read_text(encoding="utf-8")


@pytest.fixture
def secured_client(
    monkeypatch: pytest.MonkeyPatch, install_secret: Callable[..., Any]
) -> TestClient:
    """A deployed-style app: gate enforced, secret resolvable."""
    monkeypatch.setenv("APP_ENV", PRODUCTION)
    monkeypatch.setenv(SECRET_ID_ENV, PLACEHOLDER_SECRET_ID)
    install_secret(json.dumps({"api_key": PLACEHOLDER_KEY}))
    return TestClient(create_app())


def expected_openapi_code(source: str) -> int:
    match = OPENAPI_ASSERTION.search(source)
    assert match is not None, (
        "could not find the /openapi.json status assertion in "
        "scripts/deploy-lambda.sh -- if it was restructured, update this test "
        "rather than dropping the expectation"
    )
    return int(match.group(1))


def test_script_expects_401_from_unkeyed_openapi(script_source: str) -> None:
    """401, not 404: the gate answers before routing does."""
    assert expected_openapi_code(script_source) == 401


def test_script_expectation_matches_application_behaviour(
    script_source: str, secured_client: TestClient
) -> None:
    """The real lock-in: tooling and application must agree.

    Asserting the literal alone would let the script stay correct while the
    application changed underneath it. Comparing against a live unkeyed
    request means either side drifting fails this test.
    """
    actual = secured_client.get("/openapi.json").status_code

    assert actual == expected_openapi_code(script_source)


def test_unkeyed_openapi_is_indistinguishable_from_an_unknown_route(
    secured_client: TestClient,
) -> None:
    """The reason the expectation is 401 -- no route enumeration."""
    known = secured_client.get("/openapi.json").status_code
    unknown = secured_client.get("/definitely-not-a-route").status_code

    assert known == unknown == 401


def test_script_accepts_401_from_unkeyed_version(script_source: str) -> None:
    """The ``/version`` probe distinguishes a resolved secret from a 503."""
    assert re.search(r"^\s*401\)\s*;;\s*$", script_source, re.MULTILINE)


def executable_lines(source: str) -> list[str]:
    """Drop comment lines, leaving what the shell actually runs.

    The header comment explains where the ``X-GG-Key`` value lives and why the
    script never fetches it, so matching the raw text would fail on the very
    documentation that records the constraint.
    """
    return [line for line in source.splitlines() if not line.strip().startswith("#")]


def test_script_never_sends_the_shared_secret(script_source: str) -> None:
    """A keyed request would mean the script had fetched the key."""
    keyed = [line for line in executable_lines(script_source) if "X-GG-Key" in line]

    assert keyed == []


def test_script_sends_no_request_headers(script_source: str) -> None:
    """The smoke test is unauthenticated by construction, not by omission."""
    assert "-H " not in script_source
    assert "--header" not in script_source


def test_script_never_invokes_secrets_manager(script_source: str) -> None:
    """It accepts the secret's identifier and never resolves the value.

    ``secretsmanager`` appears in comments and in guidance the script *prints*
    for an administrator, so matching the bare word would be a false positive.
    An actual invocation is what matters: a line that begins the command.
    """
    invocations = [
        line
        for line in script_source.splitlines()
        if line.strip().startswith("aws secretsmanager")
    ]

    assert invocations == []
