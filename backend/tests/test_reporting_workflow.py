"""Guard the mandatory task-completion reporting protocol.

The protocol in ``CLAUDE.md`` is the durable record of how work in this
repository gets documented: a terminal transcript is lost or scrolled past, and
the report is what an administrator, a clinician, or a future session actually
reads. A silently weakened protocol would not fail anything at the time -- it
would simply mean the next blocked task goes unrecorded -- so the invariants are
asserted here instead.

``scripts/pull-task-report.ps1`` is the Windows-side retrieval helper. Its
safety properties are the ones worth pinning: it must refuse a dirty working
tree, and it must pull fast-forward only. Both exist so that fetching a report
can never cost someone their uncommitted work or rewrite local history.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
HELPER = REPO_ROOT / "scripts" / "pull-task-report.ps1"

PROTOCOL_HEADING = "## Mandatory Task Completion Report Protocol"

#: The four outcomes a report must be able to record.
OUTCOMES = ("SUCCESS", "PARTIAL", "BLOCKED", "FAILED")

#: Credential names and secret shapes that must never appear in the helper.
FORBIDDEN_IN_HELPER = ("X-GG-Key", "GG_API_KEY", "AKIA", "api_key")
HEX_SECRET = re.compile(r"\b[0-9a-fA-F]{32,}\b")
ACCOUNT_ID = re.compile(r"\b\d{12}\b")


def normalise(text: str) -> str:
    """Collapse Markdown emphasis and wrapping for phrase matching."""
    unquoted = re.sub(r"(?m)^\s*>\s?", "", text)
    return re.sub(r"\s+", " ", re.sub(r"[*_`]", "", unquoted))


def claude_md() -> str:
    return normalise(CLAUDE_MD.read_text(encoding="utf-8"))


def protocol_section() -> str:
    """The protocol section only, so assertions cannot pass on other prose."""
    raw = CLAUDE_MD.read_text(encoding="utf-8")
    start = raw.index(PROTOCOL_HEADING)
    remainder = raw[start + len(PROTOCOL_HEADING) :]
    end = remainder.find("\n## ")
    return normalise(remainder if end == -1 else remainder[:end])


# ---------------------------------------------------------------------------
# CLAUDE.md carries the protocol.
# ---------------------------------------------------------------------------


def test_claude_md_contains_the_reporting_protocol() -> None:
    assert PROTOCOL_HEADING in CLAUDE_MD.read_text(encoding="utf-8")


def test_protocol_applies_unless_explicitly_overridden() -> None:
    section = protocol_section()

    assert "unless the user explicitly overrides it" in section


def test_all_four_outcomes_are_covered() -> None:
    section = protocol_section()

    for outcome in OUTCOMES:
        assert outcome in section, f"outcome {outcome} is not covered"


def test_report_required_for_every_result_including_no_code_changes() -> None:
    """Success is the easy case; the others are why the rule exists."""
    section = protocol_section()

    for phrase in (
        "succeeds",
        "partially succeeds",
        "is blocked",
        "fails verification",
        "makes no code changes",
    ):
        assert phrase in section, f"'{phrase}' is not required to produce a report"


def test_report_location_convention_is_specified() -> None:
    section = protocol_section()

    assert "docs/audits/<task-slug>-YYYY-MM-DD.md" in section
    assert "explicitly supplied by the task" in section


def test_duplicate_reports_are_discouraged() -> None:
    section = protocol_section()

    assert "Update an existing task report rather than creating a duplicate" in section


def test_required_report_fields_are_enumerated() -> None:
    section = protocol_section()

    for field in (
        "Outcome",
        "Branch name",
        "Task objective",
        "Starting commit",
        "Implementation commits",
        "Report commit",
        "Files added, modified, or deleted",
        "Tests and exact results",
        "Lint and formatting results",
        "Deployment status",
        "AWS resources created, read, modified, or deleted",
        "Security and privacy checks",
        "Blockers or unresolved findings",
        "Decisions required from AJ or Jenna",
        "Recommended next step",
        "Whether the branch was pushed",
    ):
        assert field in section, f"required report field missing: {field}"


def test_redaction_list_is_complete() -> None:
    section = protocol_section()

    for item in (
        "credentials",
        "tokens",
        "API keys",
        "account IDs",
        "instance IDs",
        "full ARNs",
        "private URLs",
        "authorization headers",
        "user health text",
        "PHI",
        "personal identifying information",
    ):
        assert item in section, f"redaction list omits: {item}"


def test_commit_hashes_are_explicitly_not_secrets() -> None:
    """Otherwise the redaction rule reads as forbidding the audit trail."""
    section = protocol_section()

    assert "are not secrets" in section


def test_commit_behaviour_is_specified() -> None:
    section = protocol_section()

    assert "Commit implementation work separately from the report" in section
    assert "Never mix unrelated changes" in section
    assert "Never merge to main unless explicitly instructed" in section


# ---------------------------------------------------------------------------
# The full report must not be pasted into the terminal.
# ---------------------------------------------------------------------------


def test_full_report_is_prohibited_from_the_final_response() -> None:
    section = protocol_section()

    assert "Do not paste the full report into the terminal" in section
    assert "at most 10 short lines" in section


def test_failed_push_does_not_licence_printing_the_report() -> None:
    section = protocol_section()

    assert "Do not print the entire report" in section
    assert "Keep the report saved locally" in section
    assert "exact local report path" in section


# ---------------------------------------------------------------------------
# The PowerShell helper.
# ---------------------------------------------------------------------------


def test_powershell_helper_exists() -> None:
    assert HELPER.is_file()


def test_helper_contains_no_credentials_or_project_secrets() -> None:
    text = HELPER.read_text(encoding="utf-8")

    for forbidden in FORBIDDEN_IN_HELPER:
        assert forbidden not in text, f"helper mentions {forbidden}"
    assert HEX_SECRET.findall(text) == []
    assert ACCOUNT_ID.findall(text) == []
    assert "lambda-url" not in text
    assert "amazonaws.com" not in text


def test_helper_pulls_fast_forward_only() -> None:
    """A fast-forward can add commits but never rewrite or discard them."""
    text = HELPER.read_text(encoding="utf-8")

    assert "--ff-only" in text
    assert "git pull" in text


def test_helper_checks_for_a_dirty_working_tree() -> None:
    text = HELPER.read_text(encoding="utf-8")

    assert "git status --porcelain" in text
    assert "Working tree is not clean" in text


def test_helper_supports_the_documented_parameters() -> None:
    text = HELPER.read_text(encoding="utf-8")

    for parameter in ("$Branch", "$ReportPath", "$NoOpen"):
        assert parameter in text, f"helper does not support {parameter}"
    assert "Mandatory = $true" in text, "-Branch must be mandatory"


def test_helper_never_force_updates_or_deletes() -> None:
    """The helper must not be able to destroy local work.

    Matching the bare word would be a false positive -- the helper's own error
    text mentions pushing. What matters is whether it *invokes* anything
    destructive, so the patterns below target commands, not prose.
    """
    text = HELPER.read_text(encoding="utf-8")

    destructive = re.compile(
        r"git\s+(reset|clean|push|rebase)\b"
        r"|--force\b"
        r"|--hard\b"
        r"|-Force\b"
        r"|Remove-Item"
        r"|checkout\s+--",
        re.IGNORECASE,
    )
    found = destructive.findall(text)

    assert found == [], f"helper invokes destructive operations: {found}"


def test_helper_usage_is_documented_in_claude_md() -> None:
    text = claude_md()

    assert "pull-task-report.ps1" in text
    assert "-Branch" in text
    assert "-NoOpen" in text
