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
