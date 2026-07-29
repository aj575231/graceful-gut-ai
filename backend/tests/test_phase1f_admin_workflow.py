"""Guard the Phase 1F administrator workflow scripts.

The first administrator attempt at the Phase 1F dry run was performed by
pasting the runbook's commands into a Windows console. It failed, and the way
it failed is the reason these tests exist:

* A prerequisite check correctly reported that the account had no API Gateway
  CloudWatch role -- and the remaining commands were pasted and run anyway.
* The parameter file was passed as ``file:///C:/Users/...``, which the AWS CLI
  rejects as an invalid Windows path, so ``create-change-set`` never succeeded.
* No change set and no stack ever existed, so every later call failed for that
  reason rather than for anything to do with the template.
* The sequence nevertheless wrote a review file recording ``PASS`` and printed
  cleanup success for objects that had never been created.

The last one is the dangerous one. A dry run that fails loudly costs an
afternoon; a dry run that fails and reports success is read months later as
evidence the template was checked against real CloudFormation, when it never
has been.

``scripts/admin-dry-run.ps1`` and ``scripts/setup-apigw-cloudwatch-role.ps1``
replace the pasted sequence. These tests are static: they read the scripts as
text and assert the properties that make the failure unrepeatable. **Neither
script is executed here.** Both require administrator AWS credentials that this
host does not hold and must never hold, so their behaviour is pinned by
construction rather than by running them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"

DRY_RUN = SCRIPTS / "admin-dry-run.ps1"
ROLE_HELPER = SCRIPTS / "setup-apigw-cloudwatch-role.ps1"
RUNBOOK = REPO_ROOT / "infrastructure" / "phase1f" / "administrator-runbook.md"

DRY_RUN_TEXT = DRY_RUN.read_text(encoding="utf-8")
ROLE_HELPER_TEXT = ROLE_HELPER.read_text(encoding="utf-8")
RUNBOOK_TEXT = RUNBOOK.read_text(encoding="utf-8")

BOTH_SCRIPTS = {
    "admin-dry-run.ps1": DRY_RUN_TEXT,
    "setup-apigw-cloudwatch-role.ps1": ROLE_HELPER_TEXT,
}

#: The one managed policy the role helper is allowed to attach. It carries no
#: account ID -- ``arn:aws:iam::aws:policy/...`` -- so it is the single ARN
#: literal permitted in a tracked file.
MANAGED_POLICY_ARN = (
    "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
)

ACCOUNT_ID = re.compile(r"\b\d{12}\b")

#: An ARN with a literal account ID in the account field. The scripts build
#: ARNs from variables, so any match here is a hardcoded one.
ARN_WITH_ACCOUNT = re.compile(r"arn:aws[a-z0-9-]*:[^\s:]*:[^\s:]*:\d{12}:")


def normalise(text: str) -> str:
    """Collapse Markdown emphasis and wrapping for phrase matching."""
    return re.sub(r"\s+", " ", re.sub(r"[*_`]", "", text))


RUNBOOK_FLAT = normalise(RUNBOOK_TEXT)


def executable_lines(text: str) -> str:
    """The script with its comments removed.

    Several rules below -- "never build a three-slash file URI", "produce the
    word PASS in one place" -- are about what the script *does*. The comment
    blocks deliberately quote the wrong forms in order to warn about them, and
    a rule that could not tell the two apart would force the explanations out
    of the file. That would be the wrong trade: the explanation of why
    ``file:///C:/`` is wrong is the most valuable line in the script.
    """
    without_blocks = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)
    return "\n".join(
        line
        for line in without_blocks.splitlines()
        if not line.lstrip().startswith("#")
    )


BOTH_SCRIPTS_CODE = {name: executable_lines(t) for name, t in BOTH_SCRIPTS.items()}
DRY_RUN_CODE = BOTH_SCRIPTS_CODE["admin-dry-run.ps1"]


def test_the_comment_stripper_removes_block_and_line_comments() -> None:
    """A stripper that silently removed everything would make every rule below
    pass by matching nothing."""
    sample = "<#\n.SYNOPSIS\nfile:///C:/wrong\n#>\n# a line comment\n$real = 'kept'\n"
    stripped = executable_lines(sample)

    assert "$real = 'kept'" in stripped
    assert "file:///C:/wrong" not in stripped
    assert "a line comment" not in stripped


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_stripping_comments_leaves_a_substantial_script(name: str) -> None:
    code = BOTH_SCRIPTS_CODE[name]

    assert len(code) > 2000, (
        f"{name} is almost entirely comments, or the stripper ate it"
    )
    assert "param(" in code


# ---------------------------------------------------------------------------
# Both scripts exist and are shaped like the repository's other helper.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_the_script_exists_and_is_not_empty(name: str) -> None:
    assert BOTH_SCRIPTS[name].strip(), f"{name} is empty"


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_every_script_runs_under_strict_mode(name: str) -> None:
    """Strict mode turns a typo'd variable into an error instead of an empty
    string. A silently empty stack name is how a delete hits the wrong thing."""
    assert "Set-StrictMode -Version Latest" in BOTH_SCRIPTS[name]


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_script_sets_a_stop_preference_at_script_scope(name: str) -> None:
    """Documented in pull-task-report.ps1: under a 'Stop' preference, Windows
    PowerShell 5.1 turns a native command's ordinary stderr output into a
    terminating error, killing the run over a command that exited 0."""
    text = BOTH_SCRIPTS[name]

    assert not re.search(r"(?m)^\$ErrorActionPreference\s*=\s*'Stop'", text)


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_every_script_judges_native_commands_by_exit_code(name: str) -> None:
    text = BOTH_SCRIPTS[name]

    assert "$LASTEXITCODE" in text
    assert "Succeeded = ($exitCode -eq 0)" in text


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_every_script_is_documented_with_a_comment_based_help_block(
    name: str,
) -> None:
    text = BOTH_SCRIPTS[name]

    for section in (".SYNOPSIS", ".DESCRIPTION", ".PARAMETER", ".NOTES"):
        assert section in text, f"{name} has no {section}"


# ---------------------------------------------------------------------------
# The Windows file URI bug. This is the one that stopped the first attempt.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_script_ever_builds_a_three_slash_file_uri(name: str) -> None:
    """``file:///C:/...`` is what the AWS CLI rejects as an invalid Windows
    path, and what every URI-conversion helper produces.

    Checked against executable lines only. The help blocks quote the broken
    form on purpose, and that explanation is worth keeping.
    """
    code = BOTH_SCRIPTS_CODE[name]

    assert "file:///" not in code, f"{name} builds a three-slash file URI"


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_the_cli_file_argument_is_two_slashes_and_a_native_path(name: str) -> None:
    text = BOTH_SCRIPTS[name]

    assert 'return "file://$resolved"' in text, (
        f"{name} does not build the file:// argument from a resolved native path"
    )
    assert "[System.IO.Path]::GetFullPath($Path)" in text


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_script_converts_a_path_into_a_uri(name: str) -> None:
    """AbsoluteUri and System.Uri are the two ways this bug gets reintroduced."""
    code = BOTH_SCRIPTS_CODE[name]

    for forbidden in ("AbsoluteUri", "[System.Uri]::new", "New-Object System.Uri"):
        assert forbidden not in code, f"{name} converts a path to a URI via {forbidden}"


def test_the_runbook_documents_the_correct_windows_syntax() -> None:
    assert "file://C:\\" in RUNBOOK_TEXT, "the correct Windows form is not shown"
    assert "file:///C:/" in RUNBOOK_TEXT, "the rejected form is not shown as rejected"
    assert "not a URI" in RUNBOOK_FLAT


# ---------------------------------------------------------------------------
# Fail closed: abort on the first failure, never continue by hand.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_aborting_unwinds_rather_than_exiting_in_place(name: str) -> None:
    """Stop-Run throws so the throw reaches the finally block and cleanup runs.
    An `exit` in the middle of the run would skip it."""
    text = BOTH_SCRIPTS[name]

    assert "function Stop-Run" in text
    assert "throw (Hide-Sensitive -Text $Message)" in text


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_a_failed_aws_call_has_a_stopping_wrapper(name: str) -> None:
    text = BOTH_SCRIPTS[name]

    assert "function Invoke-AwsOrStop" in text
    assert "if (-not $result.Succeeded)" in text


def test_the_dry_run_stops_when_create_change_set_fails() -> None:
    """The failure that was walked past. Nothing below create-change-set may
    run, and in particular no review may be written."""
    create_index = DRY_RUN_TEXT.index("'cloudformation', 'create-change-set'")
    remainder = DRY_RUN_TEXT[create_index:]

    guard = remainder.index("if (-not $create.Succeeded)")
    stop = remainder.index("create-change-set failed")
    assert guard < stop

    # The stop happens before anything reads the change set back.
    describe = remainder.index("'cloudformation', 'describe-change-set'")
    assert stop < describe, "the run reaches describe-change-set before stopping"


def test_the_dry_run_stops_when_the_change_set_does_not_reach_create_complete() -> None:
    assert "$reachedComplete = " in DRY_RUN_TEXT
    assert "if (-not $reachedComplete)" in DRY_RUN_TEXT
    assert "No review file is written" in DRY_RUN_TEXT


def test_the_runbook_prohibits_continuing_by_hand_after_a_failure() -> None:
    assert "Do not continue by hand after a failure" in RUNBOOK_TEXT
    assert "Do not paste the individual commands" in RUNBOOK_FLAT
    assert "fix the reported cause and re-run the script" in RUNBOOK_FLAT


# ---------------------------------------------------------------------------
# PASS and REMOVED cannot be printed without a computed boolean.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_the_word_pass_is_produced_in_exactly_one_place(name: str) -> None:
    """The invariant that makes "never print PASS unless it passed" checkable.

    ConvertTo-Outcome takes a [bool] and is the only source of the literal, so
    the word cannot reach the terminal or the review without a boolean someone
    computed.
    """
    code = BOTH_SCRIPTS_CODE[name]

    assert code.count("'PASS'") == 1, (
        f"{name} produces the PASS literal in more than one place"
    )
    assert "function ConvertTo-Outcome" in code
    assert "param([Parameter(Mandatory = $true)][bool]$Passed)" in code

    # And it is inside that function, not somewhere else that happens to be the
    # only occurrence.
    start = code.index("function ConvertTo-Outcome")
    end = code.index("function ", start + 1)
    assert "'PASS'" in code[start:end]


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_bare_pass_string_is_written_to_the_terminal(name: str) -> None:
    """A Write-Host with PASS hardcoded in it would bypass ConvertTo-Outcome."""
    text = BOTH_SCRIPTS[name]

    offenders = [
        line
        for line in text.splitlines()
        if re.search(r"Write-Host.*\bPASS\b", line) and "PLAN ONLY" not in line
    ]
    assert not offenders, f"{name} prints PASS directly: {offenders}"


def test_the_word_removed_is_produced_in_exactly_one_place() -> None:
    """Cleanup success has the same problem as PASS and the same fix."""
    assert DRY_RUN_CODE.count("'REMOVED'") == 1
    assert "function ConvertTo-CleanupOutcome" in DRY_RUN_CODE


def test_cleanup_distinguishes_removed_from_never_created() -> None:
    """The failed attempt reported success for objects that never existed.
    'It was never there' is a different outcome and must read differently."""
    start = DRY_RUN_CODE.index("function ConvertTo-CleanupOutcome")
    end = DRY_RUN_CODE.index("function ", start + 1)
    body = DRY_RUN_CODE[start:end]

    assert "if (-not $Existed) { return 'NOT PRESENT' }" in body
    assert "if ($Removed) { return 'REMOVED' }" in body
    assert "STILL PRESENT" in body

    # It cannot be called without both facts.
    assert "[bool]$Existed" in body
    assert "[bool]$Removed" in body


def test_cleanup_reports_nothing_when_nothing_was_requested() -> None:
    assert "if (-not $script:ChangeSetRequested)" in DRY_RUN_TEXT
    assert "no CloudFormation object to remove" in DRY_RUN_TEXT


# ---------------------------------------------------------------------------
# The review is an artefact of a completed run, not of an attempted one.
# ---------------------------------------------------------------------------


def test_the_review_is_written_only_after_every_assertion_passes() -> None:
    """New-ReviewFile is called after Invoke-DryRun returns, and Invoke-DryRun
    stops rather than returning when any assertion fails."""
    dry_run_call = DRY_RUN_TEXT.index("$findings = Invoke-DryRun")
    review_call = DRY_RUN_TEXT.index("$reviewPath = New-ReviewFile")
    assert dry_run_call < review_call

    assert "if (-not ($resourcesOk -and $parametersOk))" in DRY_RUN_TEXT
    assert "No review file is written" in DRY_RUN_TEXT


def test_a_failed_run_says_so_instead_of_pointing_at_a_review() -> None:
    assert "No review was written for an incomplete run." in DRY_RUN_TEXT


def test_the_review_separates_the_four_stages() -> None:
    """One combined verdict hides which stage gave way -- and on the first
    attempt, three of the four had not run at all."""
    for stage in (
        "Template validation",
        "Change-set creation",
        "Resource list validation",
        "Parameter validation",
    ):
        assert f"'{stage}'" in DRY_RUN_TEXT or f"$results['{stage}']" in DRY_RUN_TEXT, (
            f"the review does not report '{stage}' separately"
        )


def test_the_review_records_that_the_change_set_was_not_executed() -> None:
    assert "Change set executed: NO" in DRY_RUN_TEXT


def test_the_review_records_cleanup_and_confirmed_absence() -> None:
    assert "function Add-CleanupSection" in DRY_RUN_TEXT
    assert "No non-deleted stack remains" in DRY_RUN_TEXT

    # Appended after cleanup runs, because the outcome is not known before.
    cleanup_call = DRY_RUN_TEXT.index("Add-CleanupSection -ChangeSetOutcome")
    assert cleanup_call > DRY_RUN_TEXT.index("function Invoke-Cleanup")


def test_the_review_is_scanned_for_leaks_before_it_is_written() -> None:
    """Fail closed: a match means no file, not a file with a warning on it."""
    assert "function Test-ReviewRedacted" in DRY_RUN_TEXT

    start = DRY_RUN_TEXT.index("function Test-ReviewRedacted")
    end = DRY_RUN_TEXT.index("function ", start + 1)
    body = DRY_RUN_TEXT[start:end]

    for pattern in (r"\b\d{12}\b", "arn:aws", "https?://", "AKIA"):
        assert pattern in body, f"the review scanner does not look for {pattern}"

    assert "if (-not (Test-ReviewRedacted -Content $content))" in DRY_RUN_TEXT


# ---------------------------------------------------------------------------
# The change set is created, read, and deleted. Never executed.
# ---------------------------------------------------------------------------


def test_the_dry_run_never_executes_a_change_set() -> None:
    """Asserted on the whole file, including comments and help text: the
    safest form of this rule is that the string is simply absent."""
    assert "execute-change-set" not in DRY_RUN_TEXT


def test_the_dry_run_creates_reads_and_deletes_the_change_set() -> None:
    for call in (
        "'cloudformation', 'validate-template'",
        "'cloudformation', 'create-change-set'",
        "'cloudformation', 'describe-change-set'",
        "'cloudformation', 'delete-change-set'",
    ):
        assert call in DRY_RUN_TEXT, f"{call} missing"


def test_the_dry_run_deletes_the_empty_stack_record_too() -> None:
    """delete-change-set leaves the REVIEW_IN_PROGRESS stack holding the name."""
    assert "'cloudformation', 'delete-stack'" in DRY_RUN_TEXT
    assert "REVIEW_IN_PROGRESS" in DRY_RUN_TEXT


def test_cleanup_runs_in_a_finally_block() -> None:
    """So it happens on the failure paths too, which is every path that
    matters -- the first attempt failed and cleaned up nothing."""
    finally_index = DRY_RUN_TEXT.rindex("finally {")
    assert "Invoke-Cleanup" in DRY_RUN_TEXT[finally_index:]


def test_the_change_set_flag_is_set_before_the_call_not_after() -> None:
    """A CREATE change set creates the stack record before the change set, so
    a failed create still leaves something to remove."""
    flag = DRY_RUN_TEXT.index("$script:ChangeSetRequested = $true")
    call = DRY_RUN_TEXT.index("'cloudformation', 'create-change-set'")
    assert flag < call


def test_stack_absence_is_confirmed_by_reading_it_back() -> None:
    assert "$stackAbsent = $after.Succeeded" in DRY_RUN_TEXT
    assert "Absence is confirmed by re-reading" in DRY_RUN_TEXT


# ---------------------------------------------------------------------------
# The completed parameter file never enters the repository.
# ---------------------------------------------------------------------------


def test_the_parameter_file_is_written_under_temp() -> None:
    assert "$tempRoot = $env:TEMP" in DRY_RUN_TEXT
    assert "[System.IO.Path]::GetTempPath()" in DRY_RUN_TEXT


def test_the_parameter_file_is_refused_if_temp_is_inside_the_repository() -> None:
    """A TEMP redirected into the checkout is the kind of local configuration
    nobody remembers setting, and the file carries the account ID."""
    assert "TEMP resolves to a path inside the repository" in DRY_RUN_TEXT
    assert "$tempCompare.StartsWith($repoCompare" in DRY_RUN_TEXT


def test_the_parameter_file_is_utf8_without_a_bom() -> None:
    assert "New-Object System.Text.UTF8Encoding($false)" in DRY_RUN_TEXT
    assert "[System.IO.File]::WriteAllText" in DRY_RUN_TEXT


def test_the_parameter_file_is_deleted_in_the_finally_block() -> None:
    cleanup_start = DRY_RUN_TEXT.index("function Invoke-Cleanup")
    cleanup_body = DRY_RUN_TEXT[cleanup_start:]

    assert "$script:ParameterFile" in cleanup_body
    assert "Remove-Item -LiteralPath $script:ParameterFile" in cleanup_body


def test_no_completed_parameter_file_is_tracked_in_the_repository() -> None:
    """Only the placeholder example is committed."""
    phase1f = REPO_ROOT / "infrastructure" / "phase1f"
    tracked = sorted(p.name for p in phase1f.glob("*.json"))

    assert tracked == ["parameters.example.json"], (
        f"unexpected JSON alongside the example parameter file: {tracked}"
    )

    example = json.loads(
        (phase1f / "parameters.example.json").read_text(encoding="utf-8")
    )
    values = [entry["ParameterValue"] for entry in example]
    assert not [v for v in values if ACCOUNT_ID.search(v)], (
        "the example parameter file carries a real account ID"
    )


# ---------------------------------------------------------------------------
# Prerequisites, including the one that failed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fragment",
    [
        "Repository working tree is clean",
        "Current branch is $RequiredBranch",
        "AWS profile '$Profile' resolves",
        "is Active and last update Successful",
        "API Gateway account CloudWatch role is configured in $Region",
        "No non-deleted stack named '$StackName' exists",
    ],
)
def test_every_prerequisite_is_checked(fragment: str) -> None:
    assert fragment in DRY_RUN_TEXT, f"prerequisite not checked: {fragment}"


def test_the_cloudwatch_role_is_required_and_stops_the_run() -> None:
    """This is the check that failed first and was then walked past."""
    assert "'apigateway', 'get-account'" in DRY_RUN_TEXT
    assert "$cwRoleConfigured = " in DRY_RUN_TEXT
    assert "if (-not $cwRoleConfigured)" in DRY_RUN_TEXT

    start = DRY_RUN_TEXT.index("if (-not $cwRoleConfigured)")
    end = DRY_RUN_TEXT.index('"@', start)
    body = DRY_RUN_TEXT[start:end]

    assert "setup-apigw-cloudwatch-role.ps1" in body, (
        "the failure does not point at the helper that fixes it"
    )
    assert "Do NOT continue by pasting" in body


def test_an_empty_or_none_cloudwatch_role_is_treated_as_unset() -> None:
    """`--output text` renders an unset value as the literal 'None', which is a
    non-empty string and would otherwise pass an emptiness check."""
    assert "($cwRoleValue -ne 'None')" in DRY_RUN_TEXT
    assert "($cwRoleValue -ne 'null')" in DRY_RUN_TEXT


def test_the_required_branch_is_the_phase_1f_branch() -> None:
    assert "$RequiredBranch = 'phase1f-api-gateway-foundation'" in DRY_RUN_TEXT


def test_the_documented_parameter_defaults_are_the_ones_declared() -> None:
    for declaration in (
        "[string]$Profile = 'graceful-gut-ai'",
        "[string]$Region = 'us-east-2'",
        "[string]$StackName = 'graceful-gut-ai-dev-infrastructure'",
        "[string]$FunctionName = 'graceful-gut-ai-dev-api'",
    ):
        assert declaration in DRY_RUN_TEXT, f"missing default: {declaration}"


def test_the_production_origin_is_mandatory_and_has_no_default() -> None:
    """It is an approved value, never a committed string."""
    match = re.search(
        r"\[Parameter\(Mandatory = \$true\)\]\s*"
        r"\[ValidateNotNullOrEmpty\(\)\]\s*"
        r"\[string\]\$ProductionOrigin\s*,",
        DRY_RUN_TEXT,
    )
    assert match, "ProductionOrigin is not a mandatory parameter without a default"


@pytest.mark.parametrize("name", ["ChangeSetName", "NoOpen"])
def test_the_optional_parameters_are_optional(name: str) -> None:
    assert f"[Parameter(Mandatory = $false)]\n    [switch]${name}" in DRY_RUN_TEXT or (
        f"[Parameter(Mandatory = $false)]\n    [string]${name}" in DRY_RUN_TEXT
    )


# ---------------------------------------------------------------------------
# The change set must match the reviewed design.
# ---------------------------------------------------------------------------


def test_the_expected_add_count_is_eleven() -> None:
    """The whole template minus the nine resources conditional on the education
    route. A twelfth Add means the route came on, or something was added
    without being reviewed."""
    start = DRY_RUN_TEXT.index("$ExpectedAdds = @(")
    end = DRY_RUN_TEXT.index(")", start)
    block = DRY_RUN_TEXT[start:end]

    logical_ids = re.findall(r"'([A-Za-z0-9]+)'", block)
    assert len(logical_ids) == 11, f"expected 11 logical IDs, found {len(logical_ids)}"


def test_the_expected_adds_are_the_templates_unconditional_resources() -> None:
    """Pinned against the template itself, so adding a resource to the template
    without updating the dry run fails here rather than in front of an
    administrator."""
    template = (REPO_ROOT / "infrastructure" / "phase1f" / "template.yaml").read_text(
        encoding="utf-8"
    )
    resources = template.split("\nResources:\n", 1)[1].split("\nOutputs:\n")[0]

    unconditional = set()
    for block in re.split(r"\n(?=  \S+:\n)", resources):
        name = re.match(r"\s*(\S+):", block)
        if not name or "Type: AWS::" not in block:
            continue
        if "Condition: EducationRouteEnabled" not in block:
            unconditional.add(name.group(1))

    start = DRY_RUN_TEXT.index("$ExpectedAdds = @(")
    end = DRY_RUN_TEXT.index(")", start)
    declared = set(re.findall(r"'([A-Za-z0-9]+)'", DRY_RUN_TEXT[start:end]))

    assert declared == unconditional, (
        f"dry run expects {sorted(declared)}; template has {sorted(unconditional)}"
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("EnableEducationRoute", "false"),
        ("StageName", "dev"),
        ("WafRateRuleAction", "Count"),
    ],
)
def test_the_asserted_parameter_values(key: str, value: str) -> None:
    """Each one turns something on that costs money, exposes free text, or
    disables a control."""
    assert f"'{key}'" in DRY_RUN_TEXT
    assert f"= '{value}'" in DRY_RUN_TEXT


def test_the_dry_run_rejects_resources_the_stack_must_never_manage() -> None:
    start = DRY_RUN_TEXT.index("$ForbiddenResourceTypes = @(")
    end = DRY_RUN_TEXT.index(")", start)
    block = DRY_RUN_TEXT[start:end]

    for forbidden in (
        "AWS::Lambda::Function",
        "AWS::Lambda::Url",
        "AWS::IAM::Role",
        "AWS::WAFv2::LoggingConfiguration",
        "AWS::Budgets::Budget",
    ):
        assert forbidden in block, f"{forbidden} is not rejected"


def test_every_change_must_be_an_add() -> None:
    """A CREATE change set that reports a Modify or Remove is describing a
    stack that already exists."""
    assert "Every change is an Add" in DRY_RUN_TEXT


# ---------------------------------------------------------------------------
# The role helper plans by default and writes only with -Apply.
# ---------------------------------------------------------------------------


def test_the_role_helper_takes_an_apply_switch() -> None:
    assert "[switch]$Apply" in ROLE_HELPER_TEXT


def test_the_role_helper_defaults_to_plan_only() -> None:
    assert "if (-not $Apply)" in ROLE_HELPER_TEXT
    assert "PLAN ONLY - nothing was changed" in ROLE_HELPER_TEXT


def test_the_role_helper_makes_no_write_before_the_apply_gate() -> None:
    """Every mutating call must appear after the plan-mode early exit, so plan
    mode cannot reach one however the branches fall."""
    gate = ROLE_HELPER_TEXT.index("if (-not $Apply)")

    for write_call in (
        "'iam', 'create-role'",
        "'iam', 'attach-role-policy'",
        "'apigateway', 'update-account'",
    ):
        assert ROLE_HELPER_TEXT.index(write_call) > gate, (
            f"{write_call} can run in plan mode"
        )


def test_the_role_helper_trusts_only_api_gateway() -> None:
    assert "$ExpectedTrustPrincipal = 'apigateway.amazonaws.com'" in ROLE_HELPER_TEXT

    start = ROLE_HELPER_TEXT.index("$trustDocument = @'")
    end = ROLE_HELPER_TEXT.index("'@", start)
    document = json.loads(ROLE_HELPER_TEXT[start + len("$trustDocument = @'") : end])

    statements = document["Statement"]
    assert len(statements) == 1
    assert statements[0]["Principal"] == {"Service": "apigateway.amazonaws.com"}
    assert statements[0]["Action"] == "sts:AssumeRole"
    assert statements[0]["Effect"] == "Allow"


def test_the_role_helper_attaches_only_the_approved_managed_policy() -> None:
    assert MANAGED_POLICY_ARN in ROLE_HELPER_TEXT

    attachments = re.findall(r"'--policy-arn',\s*(\S+)\)", ROLE_HELPER_TEXT)
    assert attachments == ["$ExpectedPolicyArn"], (
        f"unexpected policy attachment argument: {attachments}"
    )

    # No inline policy is ever written.
    for forbidden in ("put-role-policy", "put-user-policy", "create-policy"):
        assert forbidden not in ROLE_HELPER_TEXT


def test_the_role_helper_makes_no_other_iam_or_api_gateway_change() -> None:
    forbidden = (
        "delete-role",
        "detach-role-policy",
        "update-assume-role-policy",
        "create-user",
        "create-access-key",
        "create-rest-api",
        "delete-rest-api",
        "create-deployment",
        "update-stage",
    )
    for call in forbidden:
        assert call not in ROLE_HELPER_TEXT, f"the helper can call {call}"


def test_the_role_helper_refuses_to_adopt_an_unrecognised_role() -> None:
    """An existing role of the right name may be serving something else.
    Overwriting it is a silent privilege change to a resource this script does
    not own."""
    assert "function Test-RoleIsExpected" in ROLE_HELPER_TEXT
    assert "is not the role this script creates" in ROLE_HELPER_TEXT
    assert "It is NOT being modified" in ROLE_HELPER_TEXT

    start = ROLE_HELPER_TEXT.index("function Test-RoleIsExpected")
    end = ROLE_HELPER_TEXT.index("# ----", start)
    body = ROLE_HELPER_TEXT[start:end]

    assert "'iam', 'list-attached-role-policies'" in body
    assert "'iam', 'list-role-policies'" in body
    assert "the role carries inline policies" in body


def test_the_role_helper_verifies_the_final_setting_by_reading_it_back() -> None:
    assert "$finalArn = Get-CloudWatchRoleArn" in ROLE_HELPER_TEXT
    assert "$verified = ($finalArn -eq $targetArn)" in ROLE_HELPER_TEXT
    assert "if (-not $verified)" in ROLE_HELPER_TEXT


def test_the_role_helper_declares_the_documented_defaults() -> None:
    for declaration in (
        "[string]$Profile = 'graceful-gut-ai'",
        "[string]$Region = 'us-east-2'",
        "[string]$RoleName = 'GracefulGutAI-APIGatewayCloudWatchRole'",
    ):
        assert declaration in ROLE_HELPER_TEXT, f"missing default: {declaration}"


# ---------------------------------------------------------------------------
# Redaction. Nothing identifying is printed, saved, or committed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_script_contains_a_twelve_digit_account_id(name: str) -> None:
    text = BOTH_SCRIPTS[name]

    # The regex literals that *detect* account IDs are not account IDs.
    without_detectors = text.replace(r"\b\d{12}\b", "").replace(r"^\d{12}$", "")
    assert not ACCOUNT_ID.search(without_detectors), f"{name} carries an account ID"


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_script_hardcodes_an_account_bearing_arn(name: str) -> None:
    """The AWS-managed policy ARN is exempt: it has no account field."""
    text = BOTH_SCRIPTS[name].replace(MANAGED_POLICY_ARN, "")

    assert not ARN_WITH_ACCOUNT.search(text), f"{name} hardcodes an ARN with an account"


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_every_script_masks_account_ids_and_arns_before_printing(name: str) -> None:
    text = BOTH_SCRIPTS[name]

    assert "function Hide-Sensitive" in text
    assert "'<ARN>'" in text
    assert "'<AWS_ACCOUNT_ID>'" in text

    # Errors reach the terminal through the mask, not around it.
    assert (
        "[Console]::Error.WriteLine((Hide-Sensitive -Text $_.Exception.Message))"
        in text
    )


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_arns_are_masked_before_bare_account_ids(name: str) -> None:
    """Order matters: masking the account ID first leaves a half-masked ARN."""
    text = BOTH_SCRIPTS[name]
    start = text.index("function Hide-Sensitive")
    end = text.index("function ", start + 1)
    body = text[start:end]

    assert body.index("'<ARN>'") < body.index("'<AWS_ACCOUNT_ID>'")


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_script_carries_a_credential_or_secret(name: str) -> None:
    text = BOTH_SCRIPTS[name]

    # 'AKIA[0-9A-Z]{16}' is the review scanner's detector for an access key
    # ID, not an access key ID. Removing the detector before the check keeps
    # the rule honest without forbidding the scanner from existing.
    without_detectors = text.replace("AKIA[0-9A-Z]{16}", "")

    for forbidden in ("AKIA", "aws_secret_access_key", "GG_API_SECRET_ID"):
        assert forbidden not in without_detectors, f"{name} mentions {forbidden}"

    # X-GG-Key and GG_API_KEY appear only as things the review refuses to
    # contain, never as a value.
    assert not re.search(r"GG_API_KEY\s*=", text)
    assert not re.search(r"[0-9a-fA-F]{32,}", text), f"{name} carries a hex secret"


@pytest.mark.parametrize("name", sorted(BOTH_SCRIPTS))
def test_no_script_carries_a_live_url_or_sso_start_url(name: str) -> None:
    text = BOTH_SCRIPTS[name]

    urls = [u.rstrip(".") for u in re.findall(r"https?://[^\s\"'`)\]}>,]+", text)]
    allowed_placeholders = {
        "https://<approved-origin>",
        "https://example.com",
    }
    unexpected = [u for u in urls if u not in allowed_placeholders]
    assert not unexpected, f"{name} carries a URL: {unexpected}"

    assert "awsapps.com/start" not in text
    assert "sso_start_url" not in text


def test_the_review_records_no_api_id() -> None:
    """The dry run never reads an API ID -- the change set describes logical
    IDs, and the physical ID does not exist until the set is executed."""
    assert "PhysicalResourceId" not in DRY_RUN_TEXT
    assert "'RestApiId'" not in DRY_RUN_TEXT


# ---------------------------------------------------------------------------
# The runbook tells the truth about what happened.
# ---------------------------------------------------------------------------


def test_the_runbook_records_the_blocked_first_attempt() -> None:
    assert "The first administrator attempt was BLOCKED" in RUNBOOK_TEXT
    assert "no infrastructure has been created" in RUNBOOK_FLAT
    assert "no change set has ever existed" in RUNBOOK_FLAT


def test_the_runbook_records_that_the_pass_review_was_invalid() -> None:
    assert "That review was invalid and has been deleted" in RUNBOOK_FLAT


def test_the_runbook_does_not_claim_the_dry_run_passed() -> None:
    """The specific failure being guarded against: prose that a later reader
    takes as evidence the template was checked against real CloudFormation."""
    for claim in (
        "dry run passed",
        "dry run succeeded",
        "dry run completed successfully",
        "change set was reviewed and deleted successfully",
    ):
        assert claim not in RUNBOOK_FLAT.lower(), f"the runbook claims: {claim}"

    assert "that check has not been performed" in RUNBOOK_FLAT


def test_the_runbook_names_both_scripts_as_the_preferred_workflow() -> None:
    assert "Preferred Windows workflow" in RUNBOOK_TEXT
    assert "scripts/admin-dry-run.ps1" in RUNBOOK_TEXT
    assert "scripts/setup-apigw-cloudwatch-role.ps1" in RUNBOOK_TEXT


def test_the_runbook_corrects_the_validate_template_claim() -> None:
    """It was described as a local validation. It is an AWS API call: it needs
    credentials and cannot be run offline."""
    assert "NOT a local parse" in RUNBOOK_TEXT
    assert "this is an AWS API call" in RUNBOOK_FLAT
    assert "Validate the template locally" not in RUNBOOK_TEXT


def test_the_runbook_documents_the_empty_review_in_progress_stack() -> None:
    assert "A CREATE change set leaves an empty stack behind" in RUNBOOK_TEXT
    assert "Deleting the change set is not enough" in RUNBOOK_FLAT


def test_the_runbook_requires_both_deletions_and_a_confirmed_absence() -> None:
    section = RUNBOOK_TEXT[RUNBOOK_TEXT.index("A CREATE change set leaves an empty") :]

    assert "delete-change-set" in section
    assert "delete-stack" in section
    assert "Confirm absence by reading it back" in section
    assert "Deleting something that was never there is not a success" in normalise(
        section
    )
