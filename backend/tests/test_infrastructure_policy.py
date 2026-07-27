"""Guard the tracked IAM deployment policy document.

``infrastructure/claude-dev-deployment-policy.json`` is handed to IAM verbatim
once its placeholders are substituted, and IAM rejects any top-level property
that is not part of the policy language -- a stray ``_comment`` block makes the
whole document unapplyable. It is also the file that records which permissions
this host is deliberately *denied*, so a silent reintroduction of Function URL
administration would be a real privilege escalation rather than a lint problem.
Both invariants are cheap to assert and expensive to discover at apply time.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "infrastructure" / "claude-dev-deployment-policy.json"
SECRETS_POLICY_PATH = (
    REPO_ROOT / "infrastructure" / "lambda-execution-secrets-policy.json"
)

# An identity policy has exactly these two top-level elements. ``Id`` is legal
# in a *resource* policy but not here, and everything else -- ``_comment``
# above all -- is rejected by IAM.
EXPECTED_TOP_LEVEL_KEYS = {"Version", "Statement"}

# Function URL administration is administrator-only: these four decide who may
# reach the function, so the dev role must never hold them. See
# infrastructure/README.md and CLAUDE.md.
FORBIDDEN_ACTIONS = {
    "lambda:AddPermission",
    "lambda:RemovePermission",
    "lambda:CreateFunctionUrlConfig",
    "lambda:UpdateFunctionUrlConfig",
}

# Reading the shared secret is the Lambda execution role's job, not this
# host's. The dev role can deploy code and read logs; letting it also read the
# secret would put a live credential one API call away from a session that has
# no use for it. See infrastructure/README.md.
SECRET_READING_ACTIONS = {
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "secretsmanager:ListSecrets",
    "secretsmanager:DescribeSecret",
}

# The only action the execution role's secrets policy may grant.
EXPECTED_SECRETS_ACTIONS = {"secretsmanager:GetSecretValue"}

# Placeholders the apply-time rendering step knows how to substitute. Region is
# currently written literally; ``AWS_REGION`` is accepted so parameterising it
# later does not require touching this test.
PLACEHOLDER_PATTERN = re.compile(r"<([A-Z0-9_]+)>")
SUPPORTED_PLACEHOLDERS = {"AWS_ACCOUNT_ID", "AWS_REGION"}

# Synthetic values -- the real account ID is deliberately not checked in.
RENDER_VALUES = {"AWS_ACCOUNT_ID": "000000000000", "AWS_REGION": "us-east-2"}


def render(document: str, values: dict[str, str]) -> str:
    """Substitute ``<PLACEHOLDER>`` tokens the way an apply-time step would."""
    for name, value in values.items():
        document = document.replace(f"<{name}>", value)
    return document


def iter_actions(policy: dict[str, Any]) -> list[str]:
    """Flatten every ``Action`` entry, whether it is a string or a list."""
    actions: list[str] = []
    for statement in policy["Statement"]:
        action = statement["Action"]
        actions.extend([action] if isinstance(action, str) else action)
    return actions


@pytest.fixture(scope="module")
def raw_policy() -> str:
    return POLICY_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def policy(raw_policy: str) -> dict[str, Any]:
    return json.loads(raw_policy)


def test_policy_parses_as_json(policy: dict[str, Any]) -> None:
    assert isinstance(policy, dict)


def test_top_level_keys_are_exactly_version_and_statement(
    policy: dict[str, Any],
) -> None:
    assert set(policy) == EXPECTED_TOP_LEVEL_KEYS


def test_policy_version_is_the_current_policy_language(
    policy: dict[str, Any],
) -> None:
    assert policy["Version"] == "2012-10-17"


def test_every_statement_is_well_formed(policy: dict[str, Any]) -> None:
    assert policy["Statement"], "policy grants nothing"

    for statement in policy["Statement"]:
        assert set(statement) == {"Sid", "Effect", "Resource", "Action"}
        assert statement["Effect"] == "Allow"
        assert statement["Action"]


@pytest.mark.parametrize("forbidden", sorted(FORBIDDEN_ACTIONS))
def test_function_url_administration_stays_absent(
    policy: dict[str, Any], forbidden: str
) -> None:
    """Removing these was a deliberate privilege reduction -- keep it that way."""
    assert forbidden not in iter_actions(policy)


def test_no_wildcard_lambda_action_smuggles_in_url_administration(
    policy: dict[str, Any],
) -> None:
    """``lambda:*`` would grant all four forbidden actions without naming them."""
    for action in iter_actions(policy):
        assert action != "*"
        assert not (action.startswith("lambda:") and action.endswith("*"))


def test_deployment_and_inspection_permissions_are_retained(
    policy: dict[str, Any],
) -> None:
    """The read-only URL checks are kept so verification needs no admin creds."""
    actions = set(iter_actions(policy))
    assert {
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunctionUrlConfig",
        "lambda:GetPolicy",
    } <= actions


def test_placeholders_are_all_ones_the_renderer_knows(raw_policy: str) -> None:
    found = set(PLACEHOLDER_PATTERN.findall(raw_policy))
    assert found, "expected at least the account ID placeholder"
    assert found <= SUPPORTED_PLACEHOLDERS


def test_rendering_produces_a_valid_live_policy(raw_policy: str) -> None:
    rendered = json.loads(render(raw_policy, RENDER_VALUES))

    assert set(rendered) == EXPECTED_TOP_LEVEL_KEYS
    assert FORBIDDEN_ACTIONS.isdisjoint(iter_actions(rendered))

    resources = [s["Resource"] for s in rendered["Statement"]]
    scoped = [r for r in resources if r != "*"]
    assert scoped, "expected resource-scoped statements"
    for resource in scoped:
        assert resource.startswith("arn:aws:")
        assert RENDER_VALUES["AWS_ACCOUNT_ID"] in resource
        # IAM ARNs are global and carry no region, unlike lambda/logs ARNs.
        if not resource.startswith("arn:aws:iam:"):
            assert f":{RENDER_VALUES['AWS_REGION']}:" in resource


def test_no_unresolved_placeholders_remain_after_rendering(raw_policy: str) -> None:
    rendered = render(raw_policy, RENDER_VALUES)

    assert PLACEHOLDER_PATTERN.search(rendered) is None
    assert "<" not in rendered
    assert ">" not in rendered


@pytest.mark.parametrize("forbidden", sorted(SECRET_READING_ACTIONS))
def test_dev_role_cannot_read_the_shared_secret(
    policy: dict[str, Any], forbidden: str
) -> None:
    """The deploy host configures the secret's *identifier*, never its value.

    Phase 1D moved the shared secret into Secrets Manager so it stops appearing
    in the function's environment. That gain is undone if the role this host
    assumes can simply call GetSecretValue.
    """
    assert forbidden not in iter_actions(policy)


def test_no_secretsmanager_action_reaches_the_dev_role(
    policy: dict[str, Any],
) -> None:
    """Not just the named four -- the dev role holds no Secrets Manager access.

    A wildcard such as ``secretsmanager:*`` or ``secretsmanager:Get*`` would
    grant secret reading without ever naming the action.
    """
    for action in iter_actions(policy):
        assert not action.lower().startswith("secretsmanager:")


# ---------------------------------------------------------------------------
# The Lambda execution role's secrets policy
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def raw_secrets_policy() -> str:
    return SECRETS_POLICY_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def secrets_policy(raw_secrets_policy: str) -> dict[str, Any]:
    return json.loads(raw_secrets_policy)


def test_secrets_policy_is_pure_iam_policy_language(
    secrets_policy: dict[str, Any],
) -> None:
    """Same constraint as the deployment policy: IAM rejects extra keys."""
    assert set(secrets_policy) == EXPECTED_TOP_LEVEL_KEYS
    assert secrets_policy["Version"] == "2012-10-17"


def test_secrets_policy_grants_only_get_secret_value(
    secrets_policy: dict[str, Any],
) -> None:
    """Read one secret, nothing else. No create, update, rotate, or delete."""
    assert set(iter_actions(secrets_policy)) == EXPECTED_SECRETS_ACTIONS


def test_secrets_policy_is_scoped_to_the_api_key_secret(
    secrets_policy: dict[str, Any],
) -> None:
    """``*`` here would grant every secret in the account, not just this one."""
    for statement in secrets_policy["Statement"]:
        resource = statement["Resource"]
        assert statement["Effect"] == "Allow"
        assert resource != "*"
        assert resource.startswith("arn:aws:secretsmanager:")
        # Secrets Manager appends a random six-character suffix to a secret's
        # ARN, so the trailing wildcard is required for the name to match.
        assert resource.endswith(":secret:graceful-gut-ai/dev/api-key-*")


def test_secrets_policy_keeps_account_and_region_as_placeholders(
    raw_secrets_policy: str,
) -> None:
    """Neither the account ID nor the region is checked in."""
    found = set(PLACEHOLDER_PATTERN.findall(raw_secrets_policy))

    assert found == {"AWS_ACCOUNT_ID", "AWS_REGION"}
    assert found <= SUPPORTED_PLACEHOLDERS


def test_secrets_policy_renders_to_a_valid_live_policy(
    raw_secrets_policy: str,
) -> None:
    rendered_text = render(raw_secrets_policy, RENDER_VALUES)
    rendered = json.loads(rendered_text)

    assert PLACEHOLDER_PATTERN.search(rendered_text) is None
    assert "<" not in rendered_text
    assert ">" not in rendered_text
    assert set(rendered) == EXPECTED_TOP_LEVEL_KEYS

    for statement in rendered["Statement"]:
        resource = statement["Resource"]
        assert RENDER_VALUES["AWS_ACCOUNT_ID"] in resource
        assert f":{RENDER_VALUES['AWS_REGION']}:" in resource
