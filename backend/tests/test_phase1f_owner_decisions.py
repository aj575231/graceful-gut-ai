"""Guards over the Phase 1F finalisation: the satisfied logging prerequisite,
the superseded blocked attempt, and owner decisions F1 to F4.

Phase 1F closed with two kinds of fact that a later reader will act on:

* **Account state** -- the one-time API Gateway CloudWatch logging prerequisite
  is satisfied, and the template has been validated against real CloudFormation.
* **Owner decisions** -- F1 to F4, approved 2026-07-29.

Both decay in the same direction. Documentation that records a prerequisite as
satisfied tends to lose the instruction to keep checking it; documentation that
records four settled decisions tends to grow into an implied launch approval.
These tests pin the parts that must not drift: the prerequisite is still
verified before every deployment, the blocked first attempt survives as history,
the successful attempt is the current status, F1 to F4 are recorded exactly, and
the launch blockers are still named as open.

Nothing here contacts AWS. Every assertion is a static read of a tracked file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

RUNBOOK = REPO_ROOT / "infrastructure" / "phase1f" / "administrator-runbook.md"
ADR = REPO_ROOT / "docs" / "architecture" / "phase1e-api-gateway-adr.md"
REPORT = REPO_ROOT / "docs" / "audits" / "phase1f-api-gateway-foundation-2026-07-28.md"
TEMPLATE = REPO_ROOT / "infrastructure" / "phase1f" / "template.yaml"
DRY_RUN = REPO_ROOT / "scripts" / "admin-dry-run.ps1"

RUNBOOK_TEXT = RUNBOOK.read_text(encoding="utf-8")
ADR_TEXT = ADR.read_text(encoding="utf-8")
REPORT_TEXT = REPORT.read_text(encoding="utf-8")
TEMPLATE_TEXT = TEMPLATE.read_text(encoding="utf-8")
DRY_RUN_TEXT = DRY_RUN.read_text(encoding="utf-8")

#: The three documents the owner decisions had to be recorded in.
DECISION_DOCS = {
    "administrator-runbook.md": RUNBOOK_TEXT,
    "phase1e-api-gateway-adr.md": ADR_TEXT,
    "phase1f-api-gateway-foundation-2026-07-28.md": REPORT_TEXT,
}

#: Every tracked file this module reads. Redaction applies to all of them.
ALL_TRACKED = dict(
    DECISION_DOCS,
    **{"template.yaml": TEMPLATE_TEXT, "admin-dry-run.ps1": DRY_RUN_TEXT},
)


def normalise(text: str) -> str:
    """Collapse Markdown emphasis, blockquote markers, and wrapping.

    Blockquote markers have to go before the whitespace collapse. Several of the
    superseded-claim notices in these documents are blockquotes, and a leading
    ``> `` on each wrapped line otherwise survives into the middle of the
    flattened phrase -- so a phrase that plainly reads correctly in the document
    fails to match.
    """
    without_quotes = re.sub(r"(?m)^\s*>\s?", "", text)
    return re.sub(r"\s+", " ", re.sub(r"[*_`~]", "", without_quotes))


RUNBOOK_FLAT = normalise(RUNBOOK_TEXT)
ADR_FLAT = normalise(ADR_TEXT)
REPORT_FLAT = normalise(REPORT_TEXT)
FLAT_DOCS = {
    "administrator-runbook.md": RUNBOOK_FLAT,
    "phase1e-api-gateway-adr.md": ADR_FLAT,
    "phase1f-api-gateway-foundation-2026-07-28.md": REPORT_FLAT,
}


# ---------------------------------------------------------------------------
# 1. The logging prerequisite is recorded as currently satisfied.
# ---------------------------------------------------------------------------


def test_the_runbook_records_the_logging_prerequisite_as_satisfied() -> None:
    assert "satisfied 2026-07-29" in RUNBOOK_FLAT
    assert "This prerequisite was satisfied on 2026-07-29" in RUNBOOK_FLAT


def test_the_runbook_records_what_the_prerequisite_run_created() -> None:
    """The four facts an administrator would otherwise have to re-derive from
    the account, and the one an auditor would ask for."""
    assert "GracefulGutAI-APIGatewayCloudWatchRole" in RUNBOOK_TEXT
    assert "apigateway.amazonaws.com" in RUNBOOK_TEXT
    assert "AmazonAPIGatewayPushToCloudWatchLogs" in RUNBOOK_TEXT
    assert "set and verified" in RUNBOOK_FLAT
    assert "us-east-2" in RUNBOOK_TEXT


def test_the_runbook_records_that_plan_mode_changed_nothing() -> None:
    """Plan-mode-first is the habit the helper exists to enforce. The record of
    it having been followed is what makes the habit stick."""
    assert "plan mode first" in RUNBOOK_FLAT.lower()
    assert "changed nothing" in RUNBOOK_FLAT


def test_the_runbook_records_the_iam_propagation_retries() -> None:
    """The single most misleading failure in the procedure: a correct role whose
    first account-level PATCH fails on propagation. Recording it stops the next
    administrator concluding the trust policy is wrong."""
    assert "IAM propagation required retries" in RUNBOOK_FLAT
    assert "retries succeeded" in RUNBOOK_FLAT
    assert "eventually consistent" in RUNBOOK_FLAT


# ---------------------------------------------------------------------------
# 2. The prerequisite is still verified before every deployment.
# ---------------------------------------------------------------------------


def test_the_prerequisite_check_survives_being_satisfied() -> None:
    """The failure mode: a satisfied prerequisite loses its check, and the next
    person to clear the region-wide singleton gets silent log loss."""
    assert "before every create and before every update" in RUNBOOK_FLAT
    assert "That is not a reason to stop checking it" in RUNBOOK_FLAT
    assert "still verified every time" in RUNBOOK_FLAT


def test_the_prerequisite_command_is_still_present() -> None:
    """The check is only kept if the command to run it is kept."""
    assert "aws apigateway get-account" in RUNBOOK_TEXT
    assert "cloudwatchRoleArn" in RUNBOOK_TEXT


def test_the_dry_run_script_still_enforces_the_prerequisite() -> None:
    """Documentation is not enforcement. The script must still fail closed on an
    unset account value, whatever the runbook now says about it."""
    assert "cloudwatchRoleArn" in DRY_RUN_TEXT
    assert "get-account" in DRY_RUN_TEXT


# ---------------------------------------------------------------------------
# 3 and 4. Blocked attempt as history; corrected attempt as current status.
# ---------------------------------------------------------------------------


def test_the_blocked_attempt_remains_present_as_history() -> None:
    assert "The first administrator attempt was BLOCKED" in RUNBOOK_TEXT
    assert "superseded history" in RUNBOOK_FLAT.lower()
    assert "kept because it is the reason the scripted workflow exists" in (
        RUNBOOK_FLAT
    )


def test_the_successful_attempt_is_the_current_status() -> None:
    assert "Current status" in RUNBOOK_TEXT
    assert "COMPLETED SUCCESSFULLY on 2026-07-29" in RUNBOOK_FLAT


def test_the_current_status_precedes_the_superseded_history() -> None:
    """Order is the whole guard. A reader who stops after the first status
    heading must land on the current one, not the blocked one."""
    current = RUNBOOK_TEXT.index("## Current status")
    blocked = RUNBOOK_TEXT.index("## The first administrator attempt was BLOCKED")

    assert current < blocked, "the blocked attempt is presented before the success"


@pytest.mark.parametrize(
    "fact",
    [
        "validate-template",
        "eleven",
        "never executed",
        "Removed",
        "no non-deleted stack remained",
    ],
)
def test_the_runbook_records_each_dry_run_outcome(fact: str) -> None:
    assert fact.lower() in RUNBOOK_FLAT.lower(), f"missing dry-run fact: {fact}"


def test_the_runbook_records_the_dry_run_parameter_values() -> None:
    """The three values a review may not be silent about."""
    assert "EnableEducationRoute" in RUNBOOK_TEXT
    assert "StageName" in RUNBOOK_TEXT
    assert "WafRateRuleAction" in RUNBOOK_TEXT


def test_no_infrastructure_is_claimed_to_exist() -> None:
    """Validated is not deployed. The distinction is the point of a dry run and
    the easiest thing to lose when the outcome is written up as a success."""
    assert "no infrastructure has been created" in RUNBOOK_FLAT
    assert "the dry run, not a deployment" in RUNBOOK_FLAT.lower()


# ---------------------------------------------------------------------------
# 5. F1 through F4 are recorded exactly.
# ---------------------------------------------------------------------------


def test_the_runbook_carries_an_owner_decisions_section() -> None:
    assert "Approved owner decisions" in RUNBOOK_TEXT
    for label in ("F1", "F2", "F3", "F4"):
        assert f"### {label}" in RUNBOOK_TEXT, f"{label} has no section"


def test_f1_is_recorded_exactly() -> None:
    """Scope is the decision. An unscoped "sampling approved" would licence
    retaining real users' IPs, which is not what was approved."""
    assert "Approved for private dev and count-mode validation using synthetic" in (
        RUNBOOK_FLAT
    )
    assert "Re-evaluate before accepting real public health questions" in RUNBOOK_FLAT

    # WAF logging was not approved and cannot be, since it cannot omit IP.
    assert "WAF logging remains off" in RUNBOOK_FLAT


def test_f2_is_recorded_exactly() -> None:
    assert "1 request per second" in RUNBOOK_FLAT
    assert "burst" in RUNBOOK_FLAT.lower()
    assert "100" in RUNBOOK_FLAT
    assert "backstop" in RUNBOOK_FLAT.lower()
    assert "Count is acceptable" in RUNBOOK_FLAT


def test_f3_is_recorded_exactly() -> None:
    assert "graceful-gut-ai-dev-infrastructure" in RUNBOOK_TEXT
    assert "StageName" in RUNBOOK_TEXT
    assert "dev" in RUNBOOK_TEXT


def test_f4_is_recorded_exactly() -> None:
    assert "AJ is the named administrator" in RUNBOOK_FLAT
    assert "Windows administrator session" in RUNBOOK_TEXT


def test_f2_matches_the_template_defaults_it_ratifies() -> None:
    """F2 approved the values the template already shipped. If a default drifts
    away from the approved value, the decision record silently becomes false."""
    assert re.search(
        r"EducationRouteRateLimit:\s*\n\s*Type: Number\s*\n\s*Default: 1\b",
        TEMPLATE_TEXT,
    ), "EducationRouteRateLimit default is no longer 1 rps"

    assert re.search(
        r"EducationRouteBurstLimit:\s*\n\s*Type: Number\s*\n\s*Default: 2\b",
        TEMPLATE_TEXT,
    ), "EducationRouteBurstLimit default is no longer 2"

    assert re.search(
        r"WafEducationRouteRateLimit:\s*\n\s*Type: Number\s*\n\s*Default: 100\b",
        TEMPLATE_TEXT,
    ), "WafEducationRouteRateLimit default is no longer the 100 backstop"


def test_f3_matches_the_stack_name_the_dry_run_script_uses() -> None:
    assert "graceful-gut-ai-dev-infrastructure" in DRY_RUN_TEXT


@pytest.mark.parametrize("name", sorted(DECISION_DOCS))
def test_every_decision_document_records_the_decisions(name: str) -> None:
    """F1 to F4 had to reach the runbook, the ADR, and the audit report. A
    decision recorded in one place is a decision the other two contradict."""
    text = FLAT_DOCS[name]

    for label in ("F1", "F2", "F3", "F4"):
        assert label in text, f"{label} is not recorded in {name}"


# ---------------------------------------------------------------------------
# 6. Block remains required before the education route is publicly enabled.
# ---------------------------------------------------------------------------


def test_block_is_still_required_before_public_education_traffic() -> None:
    assert "must be Block before public education traffic is enabled" in RUNBOOK_FLAT


def test_count_is_permitted_only_while_the_route_is_off() -> None:
    """The narrow licence F2 grants, and its boundary. Count mode is acceptable
    only because nothing public can reach the route."""
    assert "Count is acceptable while EnableEducationRoute=false" in RUNBOOK_FLAT
    assert "a rate rule in count protects nothing" in RUNBOOK_FLAT.lower()


def test_the_template_still_defaults_the_rate_action_to_count() -> None:
    assert re.search(
        r"WafRateRuleAction:\s*\n\s*Type: String\s*\n\s*Default: Count\b",
        TEMPLATE_TEXT,
    ), "WafRateRuleAction no longer defaults to Count"


def test_the_release_conditions_survive_the_owner_decisions() -> None:
    """The failure mode this guards: four approved decisions read, months later,
    as approval to launch. Each of these is still a prior condition."""
    section = RUNBOOK_TEXT[
        RUNBOOK_TEXT.index("## 6. Before the education route is ever enabled") :
    ]
    flat = normalise(section)

    assert "L1" in flat
    assert "L2" in flat
    assert "replacing X-GG-Key" in flat
    assert "Boundary enforcement in the request path" in flat
    assert "WafRateRuleAction=Block" in flat
    assert "Public production launch approval" in flat
    assert "F1 through F4 do not shorten this list" in flat


@pytest.mark.parametrize(
    "blocker",
    [
        "L1",
        "L2",
        "X-GG-Key",
        "boundary enforcement",
        "launch approval",
        "LambdaExecutionRole",
    ],
)
def test_the_runbook_names_each_unresolved_blocker(blocker: str) -> None:
    """None of these was resolved by F1 to F4, and each must still be findable
    as open in the document an administrator reads before deploying."""
    assert blocker.lower() in RUNBOOK_FLAT.lower(), f"{blocker} is not named"


def test_the_adr_does_not_present_the_launch_blockers_as_settled() -> None:
    assert "remain open and remain" in ADR_FLAT
    assert "launch-blocking" in ADR_FLAT
    assert "None of the four is a launch approval" in ADR_FLAT


def test_the_superseded_adr_rate_limits_are_marked_not_deleted() -> None:
    """The ADR's 40 and 60 per five minutes are not expressible in WAF. The rows
    stay, marked, so the correction is legible rather than invisible."""
    assert "Superseded by owner decision F2" in ADR_FLAT
    assert "will not accept a rate-based limit below" in ADR_FLAT


# ---------------------------------------------------------------------------
# 7. Redaction: nothing sensitive reaches a tracked file.
# ---------------------------------------------------------------------------

ACCOUNT_ID = re.compile(r"\b\d{12}\b")

#: An ARN carrying a literal account ID in the account field.
ARN_WITH_ACCOUNT = re.compile(r"arn:aws[a-z0-9-]*:[^\s:]*:[^\s:]*:\d{12}:")

#: A REST API ID: ten lowercase alphanumerics, required to carry **both** a digit
#: and a letter, and to sit next to a term that makes it an API ID.
#:
#: The digit requirement is what makes this usable. Without it the pattern matches
#: any ten-letter English word following the phrase "API ID" -- "substitute" and
#: "production" both did, in the template and in this report respectively. Ten
#: lowercase letters with no digit is far more likely to be prose than an
#: identifier. It is a heuristic: a real API ID of ten letters and no digits would
#: slip through, which is why the placeholder convention, and not this regex, is
#: the actual control.
API_ID_IN_CONTEXT = re.compile(
    r"(?:api[-_ ]?id|rest[-_ ]?api[-_ ]?id|execute-api)"
    r"\D{0,20}\b(?=[a-z0-9]{10}\b)(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{10}\b",
    re.IGNORECASE,
)


@pytest.mark.parametrize("name", sorted(ALL_TRACKED))
def test_no_account_id_is_committed(name: str) -> None:
    text = ALL_TRACKED[name]
    # Strip the detector regexes in this module's own siblings if ever inlined.
    assert not ACCOUNT_ID.search(text), f"{name} carries a 12-digit account ID"


@pytest.mark.parametrize("name", sorted(ALL_TRACKED))
def test_no_account_bearing_arn_is_committed(name: str) -> None:
    text = ALL_TRACKED[name]
    matches = ARN_WITH_ACCOUNT.findall(text)

    assert not matches, f"{name} carries an account-bearing ARN: {matches}"


@pytest.mark.parametrize("name", sorted(ALL_TRACKED))
def test_no_api_id_is_committed(name: str) -> None:
    text = ALL_TRACKED[name]
    matches = API_ID_IN_CONTEXT.findall(text)

    assert not matches, f"{name} may carry an API ID: {matches}"


@pytest.mark.parametrize("name", sorted(ALL_TRACKED))
def test_no_production_origin_is_committed(name: str) -> None:
    """The approved Squarespace origin is a runtime parameter. Only placeholders
    and example.com may appear in a tracked file."""
    text = ALL_TRACKED[name]

    for url in re.findall(r"https://[^\s`'\"<>)|]+", text):
        allowed = (
            "example.com" in url
            or "<" in url
            # A CloudFormation Sub expression, not a hostname: the template
            # builds the invoke URL from ${RestApi} and ${AWS::Region}, neither
            # of which resolves until deployment.
            or "${" in url
            or "*" in url
            or "localhost" in url
            or "127.0.0.1" in url
            or url.startswith("https://docs.")
            or "amazonaws.com" in url
            or "aws.amazon.com" in url
        )
        assert allowed, f"{name} carries a possible production origin: {url}"


@pytest.mark.parametrize("name", sorted(ALL_TRACKED))
def test_no_credential_or_secret_value_is_committed(name: str) -> None:
    text = ALL_TRACKED[name]
    lowered = text.lower()

    for marker in (
        "aws_secret_access_key",
        "aws_session_token",
        "-----begin",
        "secret-string",
        "authorization: bearer",
    ):
        assert marker not in lowered, f"{name} carries {marker}"


def test_the_secret_env_var_names_carry_no_values() -> None:
    """``GG_API_KEY`` and ``GG_API_SECRET_ID`` may be named. Neither may be
    followed by an assignment that looks like a real value."""
    for name, text in ALL_TRACKED.items():
        for match in re.finditer(r"GG_API_(?:KEY|SECRET_ID)\s*[=:]\s*(\S+)", text):
            value = match.group(1).strip("\"'`,")
            allowed = (
                value.startswith("<")
                or value.startswith("$")
                or value.startswith("graceful-gut-ai/")
                or value in {"", "None", "null", "-"}
            )
            assert allowed, f"{name} may carry a secret value: {value}"


def test_the_redaction_detectors_actually_match_something() -> None:
    """A scanner that silently matches nothing protects nothing. Each detector is
    proved against a planted input before it is trusted above."""
    assert ACCOUNT_ID.search("arn:aws:iam::123456789012:role/x")
    assert ARN_WITH_ACCOUNT.search("arn:aws:lambda:us-east-2:123456789012:function:f")
    assert API_ID_IN_CONTEXT.search("the api id is abcde12345 here")
    assert not API_ID_IN_CONTEXT.search("ordinary prose with no identifier at all")

    # The two false positives that forced the digit requirement. Both are prose
    # in tracked files, and a detector that flags them gets switched off.
    assert not API_ID_IN_CONTEXT.search("REST API ID. Needed to substitute later")
    assert not API_ID_IN_CONTEXT.search(
        "no account ID, full ARN, API ID, or production"
    )
