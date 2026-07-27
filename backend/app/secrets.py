"""Resolve the shared secret from AWS Secrets Manager.

Deployed environments read the ``X-GG-Key`` shared secret from Secrets Manager
rather than from a Lambda environment variable, so the value never appears in
the function configuration, in ``aws lambda get-function-configuration`` output,
in a deployment script, or in this repository. Only the *identifier* --
``GG_API_SECRET_ID``, a secret name or ARN -- is configuration, and an
identifier is not sensitive.

Retrieval goes through the AWS Lambda Powertools parameters utility, which
caches a fetched secret per warm container: a burst of requests costs one
``GetSecretValue`` call rather than one per request.

Nothing here logs a secret value, returns one in an error, or embeds one in an
exception message. ``SecretUnavailableError`` carries a short, non-sensitive
reason meant for CloudWatch; the caller turns it into the existing opaque 503.
"""

from __future__ import annotations

import os
from typing import Any

#: Environment variable naming the secret -- a Secrets Manager name or ARN.
#: An identifier, never a value, so it is safe in scripts and configuration.
SECRET_ID_ENV = "GG_API_SECRET_ID"

#: The one field the secret's JSON payload must carry: ``{"api_key": "..."}``.
SECRET_FIELD = "api_key"

#: Seconds a fetched secret stays cached in a warm container. Long enough that
#: request bursts cost a single API call, short enough that a rotated key takes
#: effect without a redeploy and a withdrawn one is not served indefinitely.
CACHE_SECONDS = 300

#: Lazily constructed Powertools provider. Built on first use rather than at
#: import time, so importing this module -- which the whole test suite does --
#: never constructs a boto3 client or looks for AWS credentials.
_provider: Any = None


class SecretUnavailableError(Exception):
    """The shared secret could not be resolved.

    The message is a short reason for the log. It never contains the secret
    value, the secret identifier, or an AWS response.
    """


def set_provider(provider: Any) -> None:
    """Install the parameters provider, or clear it by passing ``None``.

    This is the injection seam the tests use: they pass a real Powertools
    provider built on a fake boto3 client, which exercises the genuine caching
    and JSON-transform behaviour without ever reaching AWS.
    """
    global _provider
    _provider = provider


def get_provider() -> Any:
    """Return the provider, constructing the AWS-backed one on first use."""
    global _provider
    if _provider is None:
        from aws_lambda_powertools.utilities import parameters

        _provider = parameters.SecretsProvider()
    return _provider


def fetch_secret(secret_id: str) -> Any:
    """Fetch and JSON-decode the secret, served from the cache when warm."""
    return get_provider().get(secret_id, transform="json", max_age=CACHE_SECONDS)


def secret_id() -> str:
    """Return the configured secret identifier, or an empty string if unset."""
    return os.environ.get(SECRET_ID_ENV, "").strip()


def resolve_secret_api_key() -> str:
    """Return the shared secret from Secrets Manager, or fail closed.

    Raises ``SecretUnavailableError`` when the identifier is unset, retrieval
    fails, the payload is not a JSON object, or ``api_key`` is missing, not a
    string, or empty. There is no fallback to the environment: a deployment
    that cannot reach its secret refuses requests rather than serving openly.
    """
    identifier = secret_id()
    if not identifier:
        raise SecretUnavailableError(f"{SECRET_ID_ENV} is not set")

    try:
        payload = fetch_secret(identifier)
    except Exception as exc:
        # Only the exception *type* is reported. An AWS error message quotes
        # the secret ARN, and a transform error can quote the payload itself,
        # so neither the message nor the traceback is allowed to propagate.
        raise SecretUnavailableError(
            f"secret retrieval failed ({type(exc).__name__})"
        ) from None

    if not isinstance(payload, dict):
        raise SecretUnavailableError("secret payload is not a JSON object")

    value = payload.get(SECRET_FIELD)
    if not isinstance(value, str) or not value.strip():
        raise SecretUnavailableError(f"secret has no non-empty {SECRET_FIELD!r}")

    return value.strip()
