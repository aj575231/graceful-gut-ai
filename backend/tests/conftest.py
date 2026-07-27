"""Shared test configuration.

``app.main`` builds its application at import time, so the environment has to
be settled here -- before any test module imports it. The default posture for
the suite is local development with no shared secret configured; tests that
care about the security gate set their own environment and call
``create_app()`` to get an instance built under it.

Secret retrieval is the one code path that could reach AWS. It never does here:
``no_real_aws_clients`` makes constructing a client a failure, and tests that
need real Powertools behaviour get it through ``install_secret``, which builds
the genuine provider on a fake boto3 client.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import boto3
import pytest
from aws_lambda_powertools.utilities import parameters

from app import secrets

os.environ["APP_ENV"] = "development"
os.environ.pop("GG_API_KEY", None)
os.environ.pop("GG_API_SECRET_ID", None)


class FakeSecretsClient:
    """The one method of the boto3 Secrets Manager client Powertools calls.

    Counting calls is what makes the caching assertion meaningful: Powertools
    owns the cache, so the only honest way to prove caching works is to watch
    how often it reaches the client underneath.
    """

    def __init__(
        self, secret_string: str | None = None, error: Exception | None = None
    ) -> None:
        self.secret_string = secret_string
        self.error = error
        self.calls: list[str] = []

    def get_secret_value(self, **kwargs: str) -> dict[str, str]:
        self.calls.append(kwargs["SecretId"])
        if self.error is not None:
            raise self.error
        return {"SecretString": self.secret_string or ""}


@pytest.fixture(autouse=True)
def no_real_aws_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any attempt to build a real AWS client a loud test failure.

    A test that got there would need credentials, would cost money, and -- most
    importantly -- would be handling a real secret, which this repository does
    not do. Injected fake clients never go through ``Session.client``.
    """

    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(
            "a test tried to construct a real AWS client; install a fake one "
            "with the install_secret fixture instead"
        )

    monkeypatch.setattr(boto3.session.Session, "client", refuse)


@pytest.fixture(autouse=True)
def reset_secret_provider() -> Iterator[None]:
    """Clear the provider so no client or cached value leaks between tests."""
    secrets.set_provider(None)
    yield
    secrets.set_provider(None)


@pytest.fixture
def install_secret() -> Callable[..., FakeSecretsClient]:
    """Install the real Powertools provider on a fake client.

    Returns the fake so a test can assert on how many times it was called --
    the caching behaviour under test belongs to Powertools, not to us, so it
    has to be exercised through the real provider.
    """

    def install(
        secret_string: str | None = None, error: Exception | None = None
    ) -> FakeSecretsClient:
        client = FakeSecretsClient(secret_string, error)
        secrets.set_provider(parameters.SecretsProvider(boto3_client=client))
        return client

    return install
