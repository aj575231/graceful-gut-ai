"""Guards over the Phase 1G execution-role audit script.

``scripts/audit-lambda-execution-role.ps1`` audits an IAM role that this host
cannot read. It runs with administrator credentials, against live IAM, and its
whole value depends on two properties that cannot be checked by running it here:

* **It only ever reads.** An audit tool that can write is a change tool with a
  reassuring name, and the one place it would be pointed is the role that lets
  the function reach the shared secret.
* **It leaks nothing.** Its output is meant to be pasted into a task report, so
  an account ID, ARN, secret identifier, or URL in the review would travel
  straight into a document written to be shareable.

There is no PowerShell interpreter on this host and the script has never been
executed, so both properties are pinned statically instead. The strongest guard
here is not a keyword search: it parses the script's own ``$ReadOnlyOperations``
allow-list and every ``Invoke-AwsRead`` call site, and checks the two against
each other. A mutating call cannot be added without either failing this suite or
being added to the allow-list, where a separate test rejects it for not being a
read.

Nothing in this module contacts AWS. Every assertion is a static read of a file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

AUDIT = REPO_ROOT / "scripts" / "audit-lambda-execution-role.ps1"
AUDIT_TEXT = AUDIT.read_text(encoding="utf-8")


def executable_lines(text: str) -> str:
    """The script with its comments removed.

    Several rules below are about what the script *does*. Its comment blocks
    deliberately name the dangerous calls -- ``get-secret-value``, ``iam:*`` --
    in order to explain why they are refused, and a rule that could not tell a
    warning from a call would force those explanations out of the file. That
    trade is never worth making: the paragraph explaining why an audit must not
    read the secret is more valuable than the keyword it contains.
    """
    without_blocks = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)
    return "\n".join(
        line
        for line in without_blocks.splitlines()
        if not line.lstrip().startswith("#")
    )


AUDIT_CODE = executable_lines(AUDIT_TEXT)


def normalise(text: str) -> str:
    """Collapse emphasis and wrapping for phrase matching."""
    return re.sub(r"\s+", " ", re.sub(r"[*_`~]", "", text))


AUDIT_FLAT = normalise(AUDIT_TEXT)


def parse_list_literal(name: str) -> list[str]:
    """Pull a PowerShell ``$Name = @( 'a', 'b' )`` array of strings.

    Read from the script rather than duplicated here on purpose. A test that
    hardcoded its own copy of the allow-list would pass while the script's real
    list said something else.
    """
    match = re.search(
        r"\$" + re.escape(name) + r"\s*=\s*@\((.*?)\n\)", AUDIT_TEXT, re.DOTALL
    )
    assert match, f"${name} not found in the script"
    return re.findall(r"'([^']+)'", match.group(1))


READ_ONLY_OPERATIONS = parse_list_literal("ReadOnlyOperations")
FORBIDDEN_OPERATIONS = parse_list_literal("ForbiddenOperations")

#: Every AWS call the script makes, as (service, operation).
CALL_SITES = re.findall(
    r"Invoke-AwsRead\s+-Service\s+'([^']+)'\s+-Operation\s+'([^']+)'", AUDIT_TEXT
)

#: The nine reads the task specified.
EXPECTED_OPERATIONS = {
    "sts:get-caller-identity",
    "lambda:get-function-configuration",
    "iam:get-role",
    "iam:list-attached-role-policies",
    "iam:list-role-policies",
    "iam:get-role-policy",
    "iam:get-policy",
    "iam:get-policy-version",
    "secretsmanager:describe-secret",
}

#: CLI verbs that change something. An operation beginning with any of these is
#: a mutation whatever the service.
MUTATION_PREFIXES = (
    "create-",
    "update-",
    "put-",
    "attach-",
    "detach-",
    "delete-",
    "remove-",
    "add-",
    "tag-",
    "untag-",
    "set-",
    "modify-",
    "publish-",
    "invoke",
    "rotate-",
    "restore-",
    "replicate-",
    "enable-",
    "disable-",
)

#: The read verbs an audit is allowed to use.
READ_PREFIXES = ("get-", "list-", "describe-", "simulate-")


# ---------------------------------------------------------------------------
# The script exists and is shaped like the repository's other helpers.
# ---------------------------------------------------------------------------


def test_the_comment_stripper_removes_block_and_line_comments() -> None:
    """A stripper that silently removed everything would make every rule below
    pass by matching nothing."""
    sample = "<#\n.SYNOPSIS\nget-secret-value\n#>\n# a line comment\n$real = 'kept'\n"
    stripped = executable_lines(sample)

    assert "$real = 'kept'" in stripped
    assert "get-secret-value" not in stripped
    assert "a line comment" not in stripped


def test_stripping_comments_leaves_a_substantial_script() -> None:
    assert len(AUDIT_CODE) > 4000, (
        "the script is nearly all comments, or the stripper ate it"
    )
    assert "param(" in AUDIT_CODE


def test_the_script_runs_under_strict_mode() -> None:
    """Strict mode turns a typo'd variable into an error rather than a silent
    empty string -- which, in a policy classifier, would read as "no findings"."""
    assert "Set-StrictMode -Version Latest" in AUDIT_CODE


def test_the_script_documents_powershell_compatibility() -> None:
    assert "5.1" in AUDIT_TEXT
    assert "PowerShell 7" in AUDIT_TEXT


def test_the_script_explains_why_erroractionpreference_is_not_stop() -> None:
    """The trap that cost this repository a script before: under a 'Stop'
    preference, 5.1 turns a native command's first stderr line into a
    terminating error even when it exited 0."""
    assert "NativeCommandError" in AUDIT_TEXT
    assert "judged by exit code" in AUDIT_FLAT


# ---------------------------------------------------------------------------
# 1 and 2. The script is read-only, and every call is on an explicit allow-list.
# ---------------------------------------------------------------------------


def test_the_allow_list_is_exactly_the_specified_reads() -> None:
    assert set(READ_ONLY_OPERATIONS) == EXPECTED_OPERATIONS


def test_every_allow_listed_operation_is_a_read() -> None:
    """The allow-list is the single gate, so it is the single place a mutation
    could be smuggled in. Every entry must be a read verb."""
    for pair in READ_ONLY_OPERATIONS:
        service, _, operation = pair.partition(":")
        assert service, f"malformed allow-list entry: {pair}"
        assert operation.startswith(READ_PREFIXES), f"not a read operation: {pair}"


def test_no_allow_listed_operation_is_a_mutation() -> None:
    for pair in READ_ONLY_OPERATIONS:
        _, _, operation = pair.partition(":")
        assert not operation.startswith(MUTATION_PREFIXES), (
            f"mutating operation: {pair}"
        )


def test_every_aws_call_site_is_on_the_allow_list() -> None:
    """The load-bearing test. Adding a mutating call to this script fails here,
    or fails ``test_every_allow_listed_operation_is_a_read`` if the author also
    adds it to the allow-list. There is no third path."""
    assert CALL_SITES, (
        "no Invoke-AwsRead call sites found -- has the wrapper been renamed?"
    )

    for service, operation in CALL_SITES:
        pair = f"{service}:{operation}"
        assert pair in READ_ONLY_OPERATIONS, f"call site not on the allow-list: {pair}"


def test_every_allow_listed_operation_is_actually_used() -> None:
    """An allow-list entry with no call site is a permission granted for nothing,
    and it is how the list drifts into being broader than the script."""
    used = {f"{service}:{operation}" for service, operation in CALL_SITES}

    for pair in READ_ONLY_OPERATIONS:
        assert pair in used, f"allow-listed but never called: {pair}"


def test_the_wrapper_is_the_only_route_to_the_aws_cli() -> None:
    """One raw invocation, inside Invoke-AwsRead. A second would bypass both
    gates."""
    raw = re.findall(r"Invoke-Native\s+-Command\s+'aws'", AUDIT_CODE)

    assert len(raw) == 1, f"expected exactly one raw aws invocation, found {len(raw)}"


def test_the_wrapper_checks_the_allow_list_before_running_anything() -> None:
    wrapper = AUDIT_CODE[AUDIT_CODE.index("function Invoke-AwsRead") :]
    wrapper = wrapper[: wrapper.index("function ConvertFrom-AwsJson")]

    guard = wrapper.index("$ReadOnlyOperations -notcontains $pair")
    execute = wrapper.index("Invoke-Native -Command 'aws'")

    assert guard < execute, "the allow-list is checked after the call is made"


def test_no_mutating_aws_cli_verb_is_invoked() -> None:
    """A belt-and-braces scan of executable lines for a mutating CLI operation
    passed as an -Operation argument."""
    operations = re.findall(r"-Operation\s+'([^']+)'", AUDIT_CODE)

    for operation in operations:
        assert not operation.startswith(MUTATION_PREFIXES), (
            f"mutating call: {operation}"
        )


def test_the_script_states_that_it_is_permanently_read_only() -> None:
    assert "permanently read-only" in AUDIT_FLAT


# ---------------------------------------------------------------------------
# 3. Every AWS command's exit code is checked.
# ---------------------------------------------------------------------------


def test_the_native_wrapper_captures_the_exit_code() -> None:
    assert "$exitCode = $LASTEXITCODE" in AUDIT_CODE
    assert "Succeeded = ($exitCode -eq 0)" in AUDIT_CODE


def test_the_aws_wrapper_stops_the_run_on_a_nonzero_exit() -> None:
    assert "if (-not $result.Succeeded -and -not $AllowFailure)" in AUDIT_CODE

    wrapper = AUDIT_CODE[AUDIT_CODE.index("function Invoke-AwsRead") :]
    wrapper = wrapper[: wrapper.index("function ConvertFrom-AwsJson")]
    check = wrapper.index("-not $result.Succeeded")

    assert "Stop-Run" in wrapper[check:], "a failed call does not stop the run"


def test_success_is_judged_by_exit_code_and_not_by_output() -> None:
    """The failure this repository has already had once: judging an AWS call by
    whether text appeared rather than by how it exited."""
    assert "exit code is the only source of truth" in AUDIT_FLAT.lower()


def test_allowing_a_failure_must_be_requested_explicitly() -> None:
    """One call legitimately treats a nonzero exit as an answer -- "does this
    secret exist?" -- and it has to say so at the call site rather than the
    wrapper deciding for everyone. Exactly one call site may opt out."""
    assert "[switch]$AllowFailure" in AUDIT_CODE
    assert "-not $AllowFailure" in AUDIT_CODE

    opt_outs = re.findall(r"^\s*-AllowFailure\s*$", AUDIT_CODE, re.MULTILINE)
    assert len(opt_outs) == 1, (
        f"expected one call site to opt out of failing closed, found {len(opt_outs)}"
    )


# ---------------------------------------------------------------------------
# 4. Reading a secret value is forbidden.
# ---------------------------------------------------------------------------


def test_the_forbidden_list_names_both_secret_read_operations() -> None:
    assert set(FORBIDDEN_OPERATIONS) == {
        "secretsmanager:get-secret-value",
        "secretsmanager:batch-get-secret-value",
    }


def test_no_call_site_reads_a_secret_value() -> None:
    for service, operation in CALL_SITES:
        assert f"{service}:{operation}" not in FORBIDDEN_OPERATIONS


def test_the_forbidden_check_precedes_the_allow_list_check() -> None:
    """Ordering is the whole point: an attempt to read a secret value fails with
    that specific reason, not the generic "not allow-listed"."""
    wrapper = AUDIT_CODE[AUDIT_CODE.index("function Invoke-AwsRead") :]
    wrapper = wrapper[: wrapper.index("function ConvertFrom-AwsJson")]

    forbidden = wrapper.index("$ForbiddenOperations -contains $pair")
    allowed = wrapper.index("$ReadOnlyOperations -notcontains $pair")

    assert forbidden < allowed


def test_neither_secret_read_operation_is_on_the_allow_list() -> None:
    for operation in FORBIDDEN_OPERATIONS:
        assert operation not in READ_ONLY_OPERATIONS


def test_the_script_says_why_it_never_reads_the_secret() -> None:
    assert "never reads" in AUDIT_FLAT or "never read" in AUDIT_FLAT


# ---------------------------------------------------------------------------
# 5. ExpectedSecretName is mandatory and never printed.
# ---------------------------------------------------------------------------


def test_expected_secret_name_is_mandatory_with_no_default() -> None:
    start = AUDIT_TEXT.index("param(")
    block = AUDIT_TEXT[start : AUDIT_TEXT.index("Set-StrictMode")]
    declaration = re.search(
        r"\[Parameter\(Mandatory = \$true\)\]\s*"
        r"\[ValidateNotNullOrEmpty\(\)\]\s*"
        r"\[string\]\$ExpectedSecretName\s*[,)]",
        block,
    )

    assert declaration, "ExpectedSecretName is not mandatory, or carries a default"
    assert "$ExpectedSecretName =" not in block, (
        "ExpectedSecretName has a default value"
    )


def test_the_masker_covers_the_expected_secret_name() -> None:
    masker = AUDIT_TEXT[AUDIT_TEXT.index("function Hide-Sensitive") :]
    masker = masker[: masker.index("function Stop-Run")]

    assert "$ExpectedSecretName" in masker
    assert "<EXPECTED_SECRET>" in masker
    assert "[regex]::Escape($ExpectedSecretName)" in masker, (
        "a caller-supplied value is used as a regex without escaping"
    )


def test_the_secret_name_is_masked_before_arns_are() -> None:
    """Order matters. The secret name appears inside the secret's ARN, and also
    in plain error text. Masking ARNs first would cover the first case and leave
    the second exposed."""
    masker = AUDIT_TEXT[AUDIT_TEXT.index("function Hide-Sensitive") :]
    masker = masker[: masker.index("function Stop-Run")]

    secret = masker.index("[regex]::Escape($ExpectedSecretName)")
    arn = masker.index("'arn:aws[a-z0-9-]*")

    assert secret < arn


def test_the_review_scan_rejects_the_expected_secret_name() -> None:
    scan = AUDIT_TEXT[AUDIT_TEXT.index("function Test-ReviewRedacted") :]
    scan = scan[: scan.index("function New-ReviewFile")]

    assert "[regex]::Escape($ExpectedSecretName)" in scan
    assert "return $false" in scan


def test_the_secret_name_is_never_written_to_output_directly() -> None:
    """No Write-Host or review line may interpolate it. Every path to a terminal
    or a file goes through the masker or the pre-write scan."""
    for line in AUDIT_CODE.splitlines():
        stripped = line.strip()
        if "$ExpectedSecretName" not in stripped:
            continue

        allowed = (
            stripped.startswith("$masked")
            or "[regex]::Escape($ExpectedSecretName)" in stripped
            or "IsNullOrWhiteSpace($ExpectedSecretName)" in stripped
            or "--secret-id" in stripped
            or "[string]$ExpectedSecretName" in stripped
        )
        assert allowed, f"the secret name may reach output here: {stripped}"


def test_no_write_host_prints_the_secret_name() -> None:
    for line in AUDIT_CODE.splitlines():
        if "Write-Host" in line or "$lines.Add" in line:
            assert "$ExpectedSecretName" not in line, (
                f"prints the secret name: {line.strip()}"
            )


# ---------------------------------------------------------------------------
# 6. ARNs and account IDs are masked.
# ---------------------------------------------------------------------------


def test_the_masker_covers_arns_account_ids_and_urls() -> None:
    masker = AUDIT_TEXT[AUDIT_TEXT.index("function Hide-Sensitive") :]
    masker = masker[: masker.index("function Stop-Run")]

    assert "'arn:aws[a-z0-9-]*" in masker
    assert r"'\b\d{12}\b'" in masker
    assert "https?://" in masker
    assert "<AWS_ACCOUNT_ID>" in masker
    assert "<ARN>" in masker
    assert "<URL>" in masker


def test_arns_are_masked_before_bare_account_ids() -> None:
    """Otherwise the account ID inside an ARN is replaced first and what is left
    is a half-masked ARN, which is worse than either outcome alone."""
    masker = AUDIT_TEXT[AUDIT_TEXT.index("function Hide-Sensitive") :]
    masker = masker[: masker.index("function Stop-Run")]

    assert masker.index("'arn:aws[a-z0-9-]*") < masker.index(r"'\b\d{12}\b'")


def test_findings_and_errors_pass_through_the_masker() -> None:
    # Write-Classification is the single printer the four writers delegate to, so
    # masking there covers every classified line. Write-Detail prints on its own
    # and is checked with it.
    finding = AUDIT_CODE[AUDIT_CODE.index("function Write-Classification") :]
    finding = finding[: finding.index("function Write-Section")]

    assert "Hide-Sensitive" in finding, "finding text is printed unmasked"
    detail = AUDIT_CODE[AUDIT_CODE.index("function Write-Detail") :]
    detail = detail[: detail.index("function Write-Verdict")]
    assert "Hide-Sensitive" in detail, "detail text is printed unmasked"

    stop = AUDIT_CODE[AUDIT_CODE.index("function Stop-Run") :]
    stop = stop[: stop.index("function Invoke-Native")]
    assert "Hide-Sensitive" in stop, "the abort message is thrown unmasked"

    assert "[Console]::Error.WriteLine((Hide-Sensitive" in AUDIT_CODE, (
        "the terminal error path does not mask"
    )


def test_the_account_id_is_read_only_for_masking_and_never_printed() -> None:
    assert "masking only, never printed" in AUDIT_FLAT

    for line in AUDIT_CODE.splitlines():
        if "Write-Host" in line:
            assert "$script:AccountId" not in line
            assert "$accountId" not in line


def test_the_role_arn_is_never_printed() -> None:
    """Requirement 9. The comparison is made on the role name; the ARN carries
    the account ID and stays out of the output entirely."""
    assert "the ARN is never printed" in AUDIT_FLAT

    for line in AUDIT_CODE.splitlines():
        if "Write-Host" in line or "$lines.Add" in line:
            assert "$roleArn" not in line, f"prints the role ARN: {line.strip()}"


def test_environment_variables_are_never_fetched() -> None:
    """Stronger than masking them: the function configuration is queried
    server-side for three named fields, so Environment.Variables -- which carries
    GG_API_SECRET_ID -- never enters the process."""
    assert (
        "'--query', '{State:State,LastUpdateStatus:LastUpdateStatus,Role:Role}'"
        in AUDIT_CODE
    )
    assert "Environment.Variables" not in AUDIT_CODE
    assert "Environment" in AUDIT_FLAT  # the reasoning is recorded


def test_asking_for_the_environment_is_refused_by_the_wrapper() -> None:
    """The narrow query was previously a convention at one call site. It is now a
    gate: a query naming Environment is refused before the process starts, so the
    property survives someone editing that call site."""
    assert "$ForbiddenQueryFields = @(" in AUDIT_CODE
    fields = parse_list_literal("ForbiddenQueryFields")

    assert set(fields) == {"Environment", "SecretString", "SecretBinary"}

    wrapper = AUDIT_CODE[AUDIT_CODE.index("function Invoke-AwsRead") :]
    wrapper = wrapper[: wrapper.index("function ConvertFrom-AwsJson")]

    guard = wrapper.index("$ForbiddenQueryFields")
    execute = wrapper.index("Invoke-Native -Command 'aws'")
    assert guard < execute, "the query is inspected after the call is made"


def test_the_configuration_read_cannot_omit_its_query() -> None:
    """A --query is what keeps the response narrow, so calling the operation
    without one has to fail rather than fall back to the whole record."""
    required = parse_list_literal("QueryRequiredOperations")

    assert "lambda:get-function-configuration" in required
    assert "secretsmanager:describe-secret" in required

    for pair in required:
        assert pair in READ_ONLY_OPERATIONS, f"not an allow-listed read: {pair}"

    wrapper = AUDIT_CODE[AUDIT_CODE.index("function Invoke-AwsRead") :]
    wrapper = wrapper[: wrapper.index("function ConvertFrom-AwsJson")]
    assert (
        "$QueryRequiredOperations -contains $pair -and $null -eq $queryText" in wrapper
    )


def test_the_query_gate_reads_arguments_without_indexing_them() -> None:
    """The gate must not reintroduce the mistake it guards. Walking the argument
    list needs no length check and no index, so there is nothing to get wrong."""
    wrapper = AUDIT_CODE[AUDIT_CODE.index("function Invoke-AwsRead") :]
    wrapper = wrapper[: wrapper.index("function ConvertFrom-AwsJson")]

    assert "foreach ($argument in $Arguments)" in wrapper
    assert "$Arguments.Count" not in wrapper
    assert not re.search(r"\$Arguments\[\d+\]", wrapper)


# ---------------------------------------------------------------------------
# 7. Trust-policy checks are enforced.
# ---------------------------------------------------------------------------


def test_the_trust_policy_requires_only_the_lambda_service_principal() -> None:
    assert "$ExpectedTrustPrincipal = 'lambda.amazonaws.com'" in AUDIT_CODE
    assert "is the only trusted service principal" in AUDIT_FLAT


@pytest.mark.parametrize(
    "check",
    [
        "No AWS account principal",
        "No federated principal",
        "No wildcard principal",
        "No external ID condition",
        "No unexpected trust condition",
    ],
)
def test_each_trust_policy_check_is_present(check: str) -> None:
    assert check in AUDIT_TEXT, f"trust-policy check missing: {check}"


def test_the_trust_policy_inspects_every_principal_type() -> None:
    trust = AUDIT_TEXT[AUDIT_TEXT.index("function Test-TrustPolicy") :]
    trust = trust[: trust.index("function Get-AttachedPolicyDocuments")]

    for key in ("'Service'", "'AWS'", "'Federated'", "'CanonicalUser'"):
        assert key in trust, f"principal type not handled: {key}"

    assert "ExternalId" in trust
    assert "$sawWildcardPrincipal" in trust


def test_an_unrecognised_principal_type_is_reported_rather_than_ignored() -> None:
    """A principal type nobody thought of must not fall through as a pass."""
    trust = AUDIT_TEXT[AUDIT_TEXT.index("function Test-TrustPolicy") :]
    trust = trust[: trust.index("function Get-AttachedPolicyDocuments")]

    assert "Unrecognised trust principal type" in trust


# ---------------------------------------------------------------------------
# 8 and 9. Every attached and inline policy is inspected; versions are resolved.
# ---------------------------------------------------------------------------


def test_both_attached_and_inline_policies_are_listed() -> None:
    assert ("iam", "list-attached-role-policies") in CALL_SITES
    assert ("iam", "list-role-policies") in CALL_SITES


def test_every_attached_policy_document_is_resolved() -> None:
    attached = AUDIT_TEXT[AUDIT_TEXT.index("function Get-AttachedPolicyDocuments") :]
    attached = attached[: attached.index("function Get-InlinePolicyDocuments")]

    assert "foreach ($row in $rows)" in attached
    assert "-Operation 'get-policy'" in attached
    assert "-Operation 'get-policy-version'" in attached


def test_every_inline_policy_document_is_resolved() -> None:
    inline = AUDIT_TEXT[AUDIT_TEXT.index("function Get-InlinePolicyDocuments") :]
    inline = inline[: inline.index("function Get-ActionCategory")]

    assert "foreach ($name in $names)" in inline
    assert "-Operation 'get-role-policy'" in inline


def test_the_default_policy_version_is_resolved_rather_than_assumed() -> None:
    """Assuming v1 would audit a document that is no longer in effect on any
    policy that has ever been edited."""
    attached = AUDIT_TEXT[AUDIT_TEXT.index("function Get-AttachedPolicyDocuments") :]
    attached = attached[: attached.index("function Get-InlinePolicyDocuments")]

    assert "Policy.DefaultVersionId" in attached
    assert "'--version-id', $versionId" in attached
    assert "v1" in normalise(attached)  # the reasoning is recorded


def test_a_missing_default_version_stops_the_run() -> None:
    attached = AUDIT_TEXT[AUDIT_TEXT.index("function Get-AttachedPolicyDocuments") :]
    attached = attached[: attached.index("function Get-InlinePolicyDocuments")]

    assert "returned no default version ID" in attached


def test_both_policy_document_encodings_are_handled() -> None:
    """CLI v2 returns the document as an object; v1 returns it URL-encoded. Only
    handling the object form would make every statement list come back empty on
    a v1 install, and every check would pass having audited nothing."""
    decoder = AUDIT_TEXT[AUDIT_TEXT.index("function ConvertFrom-PolicyDocument") :]
    decoder = decoder[: decoder.index("function Test-HasProperty")]

    assert "UnescapeDataString" in decoder
    assert "$Document -is [string]" in decoder
    assert "Stop-Run" in decoder, "an unrecognised document form is treated as empty"


def test_scalar_and_array_policy_fields_are_both_handled() -> None:
    """Action, Resource, and Statement are each valid as a scalar or a list.
    Code that assumes a list silently skips single-value statements.

    The explicit ``$Value -is [string]`` branch the first version carried is
    gone: ``@($string)`` already yields a one-element array, so the branch was
    dead code that implied strings needed special handling when the real hazard
    was the function boundary. See the collection-handling section below.
    """
    assert AUDIT_CODE.count("Get-AsArray") >= 8
    assert "Write-Output -NoEnumerate @($Value)" in AUDIT_CODE


def test_the_expected_inline_policy_name_is_the_deployed_one() -> None:
    """The role carries one inline policy and 'GracefulGutAI-SecretAccess' is its
    name on the deployed role, established by the first successful live audit.

    The script expected 'GracefulGutAI-ReadApiKeySecret' until that run. That
    name is what the administrator *instructions* in CLAUDE.md, in
    infrastructure/README.md, and in the Phase 1D report tell an administrator to
    pass to put-role-policy -- an instruction, never a record of a run. Expecting
    it made the audit flag the correct deployed policy as a deviation, so the
    expectation moved to what is deployed. Nothing in AWS was renamed: the
    deployed policy grants exactly the expected secret read and only its name was
    undocumented.
    """
    assert "$ExpectedInlinePolicyName = 'GracefulGutAI-SecretAccess'" in AUDIT_CODE
    assert "$ExpectedInlinePolicyName = 'GracefulGutAI-ReadApiKeySecret'" not in (
        AUDIT_CODE
    )


def test_an_unexpected_inline_policy_is_flagged_for_review() -> None:
    inline = AUDIT_TEXT[AUDIT_TEXT.index("function Get-InlinePolicyDocuments") :]
    inline = inline[: inline.index("function Get-ActionCategory")]

    assert "not part of the documented setup" in inline


def test_an_unexpected_inline_policy_is_recorded_and_not_merely_printed() -> None:
    """The defect the first successful live audit exposed. The terminal reported
    the unrecognised policy name as a REVIEW and the review file reported
    ``Overall: PASS`` with ``REVIEW: 0``, because this branch printed a
    classification without recording a finding.

    Add-Finding is now the only way to emit a REVIEW, so the branch cannot print
    one without the review file seeing it.
    """
    inline = AUDIT_CODE[AUDIT_CODE.index("function Get-InlinePolicyDocuments") :]
    inline = inline[: inline.index("function Get-ActionCategory")]

    # The name check is an if/else: the canonical name is a step, any other name
    # is a recorded finding. Scoped to the branch, because the same function
    # records a separate REVIEW earlier for a role with no inline policy at all.
    branch = inline[
        inline.index("$expected = ($policyName -eq $ExpectedInlinePolicyName)") :
    ]

    step = branch.index('Write-Step -Name "Resolved inline policy:')
    recorded = branch.index("Add-Finding -Severity 'Review'")

    assert step < recorded, "the expected-name branch is not the Write-Step one"
    assert "not part of the documented setup" in branch[recorded:]
    assert "Write-Classification" not in branch, (
        "the branch prints a classification without recording it"
    )


# ---------------------------------------------------------------------------
# 10, 11, 12, 13. Dangerous grants are detected.
# ---------------------------------------------------------------------------


def test_action_and_service_wildcards_are_detected() -> None:
    assert 'Action "*" grants every action' in AUDIT_TEXT
    assert "Service-wide wildcard action" in AUDIT_TEXT
    assert r"'^[a-z0-9-]+:\*$'" in AUDIT_CODE, "no service-wildcard pattern"


def test_notaction_and_notresource_are_detected() -> None:
    assert "Statement uses NotAction" in AUDIT_TEXT
    assert "Statement uses NotResource" in AUDIT_TEXT
    assert "-Name 'NotAction'" in AUDIT_CODE
    assert "-Name 'NotResource'" in AUDIT_CODE


def test_a_principal_in_an_identity_policy_is_detected() -> None:
    assert 'Principal "*"' in AUDIT_TEXT
    assert "Permission policy contains a Principal" in AUDIT_TEXT


def test_passrole_and_assumerole_are_detected() -> None:
    assert "$lower -eq 'iam:passrole'" in AUDIT_CODE
    assert "$lower -eq 'sts:assumerole'" in AUDIT_CODE
    assert "iam:PassRole is granted" in AUDIT_TEXT
    assert "sts:AssumeRole is granted" in AUDIT_TEXT


def test_secrets_manager_write_actions_are_detected() -> None:
    verbs = parse_list_literal("SecretWriteVerbs")

    for verb in ("put", "update", "create", "delete", "rotate", "tag"):
        assert verb in verbs, f"Secrets Manager write verb not covered: {verb}"

    assert "Secrets Manager write or administrative action" in AUDIT_TEXT


def test_iam_write_actions_are_detected() -> None:
    verbs = parse_list_literal("IamWriteVerbs")

    for verb in ("create", "delete", "put", "attach", "detach", "update"):
        assert verb in verbs, f"IAM write verb not covered: {verb}"

    assert "IAM write action" in AUDIT_TEXT


def test_unrelated_services_are_detected() -> None:
    prefixes = parse_list_literal("UnrelatedServicePrefixes")

    for service in ("s3:", "dynamodb:", "sqs:", "sns:", "ec2:"):
        assert service in prefixes, f"unrelated service not covered: {service}"

    assert "Unrelated service permission" in AUDIT_TEXT


def test_sqs_and_sns_are_caught_despite_falling_outside_every_category() -> None:
    """They are not storage, database, or networking, so they land in 'Other'.
    The explicit unrelated-service list is what catches them, and it runs before
    the category switch."""
    prefixes = parse_list_literal("UnrelatedServicePrefixes")
    categories = re.search(
        r"\$ActionCategories = @\((.*?)\n\)", AUDIT_TEXT, re.DOTALL
    ).group(1)

    assert "sqs:" in prefixes
    assert "sns:" in prefixes
    assert "sqs:" not in categories
    assert "sns:" not in categories


def test_administration_of_the_managed_surfaces_is_detected() -> None:
    for title in (
        "Lambda administrative action",
        "Function URL permission",
        "API Gateway or WAF permission",
        "CloudFormation permission",
        "Storage or database permission",
        "Networking permission",
    ):
        assert title in AUDIT_TEXT, f"not detected: {title}"


def test_an_action_outside_every_category_fails_rather_than_passing() -> None:
    """The default branch is the one that decides whether an unknown permission
    is a finding or an oversight."""
    assert "Permission outside every expected category" in AUDIT_TEXT


def test_verb_matching_drops_the_service_prefix_first() -> None:
    """'secretsmanager:GetSecretValue' contains 'get', and a naive substring test
    for a verb against the whole action string misfires in both directions."""
    matcher = AUDIT_TEXT[AUDIT_TEXT.index("function Test-ActionVerb") :]
    matcher = matcher[: matcher.index("function Get-ResourceScope")]

    assert "-split ':', 2" in matcher
    assert "StartsWith" in matcher


def test_deny_statements_are_recorded_but_not_judged_as_grants() -> None:
    """A Deny cannot grant anything, so classifying its actions as permissions
    would invent findings out of a restriction."""
    assert "$denyCount++" in AUDIT_CODE
    assert "A Deny cannot grant anything" in AUDIT_TEXT


# ---------------------------------------------------------------------------
# 14. Normal Lambda logging access is not misclassified.
# ---------------------------------------------------------------------------


def test_resource_scope_is_described_rather_than_reduced_to_a_boolean() -> None:
    """Requirement 14 lives here. A wildcard resource means different things in
    different categories -- expected on logs:, a finding on secretsmanager: --
    so breadth is returned as a description and each category decides."""
    scope = AUDIT_TEXT[AUDIT_TEXT.index("function Get-ResourceScope") :]
    scope = scope[: scope.index("function Test-PolicyStatements")]

    for value in ("'wildcard'", "'expected secret'", "'prefix-scoped'", "'scoped'"):
        assert value in scope, f"scope description missing: {value}"

    assert "false failure" in normalise(scope)


def test_the_aws_managed_logging_policy_does_not_produce_a_false_failure() -> None:
    """AWSLambdaBasicExecutionRole scopes CreateLogGroup broadly. That is the
    normal shape of a working Lambda role and must not read as a finding."""
    assert "$scope -eq 'wildcard' -and -not $policy.IsAwsManaged" in AUDIT_CODE
    assert "$ExpectedManagedPolicyNames" in AUDIT_CODE
    assert "AWSLambdaBasicExecutionRole" in AUDIT_TEXT


def test_the_expected_log_actions_are_the_three_a_lambda_needs() -> None:
    actions = parse_list_literal("ExpectedLogActions")

    assert set(actions) == {
        "logs:createloggroup",
        "logs:createlogstream",
        "logs:putlogevents",
    }


def test_expected_log_writes_produce_no_finding() -> None:
    """The classifier must have a path where a normal log grant adds nothing at
    all -- not a PASS-labelled finding, but no finding."""
    classifier = AUDIT_TEXT[AUDIT_TEXT.index("'CloudWatch Logs' {") :]
    classifier = classifier[: classifier.index("'Secrets Manager' {")]

    assert "$ExpectedLogActions -contains $lower" in classifier


def test_kms_decrypt_is_judged_against_the_secrets_actual_key() -> None:
    """kms:Decrypt is legitimate only for a customer-managed key. Under the
    AWS-managed key Secrets Manager decrypts on the caller's behalf and the role
    needs no KMS grant, so judging KMS without reading the key would either
    invent a finding or miss one."""
    assert "UsesCustomerKey" in AUDIT_CODE
    assert "alias/aws/secretsmanager" in AUDIT_CODE
    assert "the secret uses the AWS-managed key" in AUDIT_TEXT


def test_the_expected_secret_grant_is_recognised_as_correct() -> None:
    classifier = AUDIT_TEXT[AUDIT_TEXT.index("'Secrets Manager' {") :]
    classifier = classifier[: classifier.index("'KMS' {")]

    assert "$scope -eq 'expected secret'" in classifier
    assert "is granted on every secret" in classifier


def test_the_secret_arn_suffix_is_accounted_for() -> None:
    """Secrets Manager appends a six-character suffix, so the documented grant
    ends in '-*'. Comparing full ARNs only would miss the intended match."""
    scope = AUDIT_TEXT[AUDIT_TEXT.index("function Get-ResourceScope") :]
    scope = scope[: scope.index("function Test-PolicyStatements")]

    assert "six-character suffix" in normalise(scope)
    assert "StartsWith($stem)" in scope


# ---------------------------------------------------------------------------
# 15 and 16. No review after a failure; a review only after every stage.
# ---------------------------------------------------------------------------


def test_a_failed_aws_call_throws_rather_than_returning() -> None:
    """Throwing is what makes "abort the whole audit" true: no later stage
    observes the failure and carries on with partial data."""
    stop = AUDIT_CODE[AUDIT_CODE.index("function Stop-Run") :]
    stop = stop[: stop.index("function Invoke-Native")]

    assert "throw" in stop


def test_the_review_is_gated_on_every_stage_completing() -> None:
    review = AUDIT_CODE[AUDIT_CODE.index("function New-ReviewFile") :]

    assert "if (-not $script:StagesCompleted)" in review
    assert "Refusing to write a review before every audit stage completed" in AUDIT_TEXT


#: The start of the script body. Anchored on a code line rather than the '# Main'
#: banner, because the comment-stripped copy has no comments left to find.
MAIN_ANCHOR = "Write-Host 'Phase 1G - Lambda execution role audit'"


def main_body(text: str) -> str:
    assert MAIN_ANCHOR in text, "the main-body anchor has moved"
    return text[text.index(MAIN_ANCHOR) :]


def test_the_completion_flag_is_set_after_the_last_stage() -> None:
    """If the flag were set early it would gate nothing, so its position is the
    guard rather than its existence."""
    main = main_body(AUDIT_CODE)

    permissions = main.index("$permissions = Test-PolicyStatements")
    flag = main.index("$script:StagesCompleted = $true")
    write = main.index("New-ReviewFile -Permissions")

    assert permissions < flag < write


def test_the_flag_starts_false() -> None:
    assert "$script:StagesCompleted = $false" in AUDIT_CODE


def test_the_review_path_is_only_reported_when_a_review_exists() -> None:
    """The failure this pattern exists to prevent: a cleanup or completion
    message printed unconditionally, for a file that was never written."""
    assert "if ([string]::IsNullOrWhiteSpace($script:ReviewFile))" in AUDIT_CODE
    assert "Audit did not complete. No review was written." in AUDIT_TEXT


def test_the_review_is_scanned_before_it_is_written() -> None:
    review = AUDIT_TEXT[AUDIT_TEXT.index("function New-ReviewFile") :]

    scan = review.index("Test-ReviewRedacted -Content $content")
    write = review.index("WriteAllText")

    assert scan < write, "the review is written before it is scanned"
    assert "was NOT written" in review


def test_a_redaction_match_produces_no_file_at_all() -> None:
    assert "match produces no file" in AUDIT_FLAT


def test_the_review_scan_covers_every_prohibited_class() -> None:
    scan = AUDIT_TEXT[AUDIT_TEXT.index("function Test-ReviewRedacted") :]
    scan = scan[: scan.index("function New-ReviewFile")]

    for pattern in (
        r"\b\d{12}\b",
        "arn:aws",
        "https?://",
        "AKIA",
        "GG_API_KEY",
        "X-GG-Key",
        "lambda-url",
        "execute-api",
    ):
        assert pattern in scan, f"review scan does not cover: {pattern}"


def test_the_review_goes_to_temp_and_never_into_the_checkout() -> None:
    main = main_body(AUDIT_CODE)

    assert "$env:TEMP" in main
    assert "GetTempPath" in main
    assert "StartsWith($resolvedRepo" in main
    assert "TEMP resolves to a path inside the repository" in AUDIT_TEXT


def test_no_correction_is_ever_applied() -> None:
    """Requirement 21. The script reports what an administrator should change
    and stops. An audit tool that repairs what it audits destroys the evidence."""
    assert "An administrator applies these. This script never does." in AUDIT_TEXT
    assert "applies no correction" in AUDIT_FLAT


def test_the_three_classifications_are_each_produced_in_one_place() -> None:
    """Same reasoning as the dry run's single PASS: a verdict word that can be
    printed from anywhere can be printed for a check that never ran."""
    for word in ("'PASS'", "'REVIEW'", "'FAIL'"):
        assert AUDIT_CODE.count(f"return {word}") == 1, (
            f"{word} is produced in more than one place"
        )

    assert "function ConvertTo-Classification" in AUDIT_CODE


def test_severity_combination_is_worst_wins() -> None:
    combiner = AUDIT_CODE[AUDIT_CODE.index("function Get-WorstSeverity") :]
    combiner = combiner[: combiner.index("function Write-Classification")]

    assert "'Fail'" in combiner
    assert "'Review'" in combiner
    fail = combiner.index("-contains 'Fail'")
    review = combiner.index("-contains 'Review'")
    assert fail < review, "Review would mask a Fail"


# ---------------------------------------------------------------------------
# One finding collection -- the terminal and the review cannot disagree
# ---------------------------------------------------------------------------
#
# The first successful live audit produced two artefacts about one run that did
# not agree. The terminal classified an inline policy under an unrecognised name
# as a REVIEW. The review file, generated seconds later by the same process,
# said `**Overall: PASS**` and `REVIEW: 0`.
#
# Neither artefact was internally inconsistent, which is what made it bad: from
# either one alone the run looked fine, and there was no way to tell which to
# believe without having both. The cause was structural rather than a wrong
# comparison -- findings lived in three places, and the renderer read two of
# them. The rules below hold the structure that replaced it: one collection, one
# way in, one computation of the verdict.


def test_there_is_exactly_one_finding_collection() -> None:
    """The three-way split is gone. $script:AuditFindings is the only place a
    finding lives, and the trust stage's private list and the permission stage's
    reassignment are both absent."""
    assert "$script:AuditFindings = New-Object" in AUDIT_CODE
    assert AUDIT_CODE.count("$script:AuditFindings = New-Object") == 1, (
        "the finding collection is created more than once"
    )
    assert "PermissionFindings" not in AUDIT_CODE, (
        "the permission stage still keeps its own finding list"
    )

    # It is never reassigned after startup. A stage that re-created it would
    # discard every finding recorded by the stages before it -- which is exactly
    # what the permission stage used to do.
    assignments = re.findall(r"\$script:AuditFindings\s*=", AUDIT_CODE)
    assert len(assignments) == 1, f"the collection is reassigned: {assignments}"


def test_add_finding_is_the_only_way_to_produce_a_review_or_a_fail() -> None:
    """Write-Classification is private by convention and Add-Finding is the only
    caller that can pass a non-Pass severity. A stage cannot print a REVIEW the
    review file has never heard of."""
    callers = re.findall(
        r"Write-Classification -Severity ('[A-Za-z]+'|\$\w+)", AUDIT_CODE
    )

    # Three call sites: Write-Step pins 'Pass', Add-Finding and Write-Verdict pass
    # a variable that ValidateSet has already constrained.
    assert sorted(callers) == ["$Severity", "$Severity", "'Pass'"], (
        f"unexpected Write-Classification call sites: {callers}"
    )

    step = FUNCTION_BODIES["Write-Step"]
    assert "Write-Classification -Severity 'Pass'" in step
    assert "$Severity" not in step, "Write-Step can emit something other than PASS"


def test_add_finding_records_and_prints_in_the_same_call() -> None:
    """The two cannot come apart. A finding that was printed but not recorded is
    the whole defect."""
    body = FUNCTION_BODIES["Add-Finding"]

    recorded = body.index("$script:AuditFindings.Add(")
    printed = body.index("Write-Classification -Severity $Severity")

    assert recorded < printed, "a finding is printed before it is recorded"


def test_add_finding_cannot_record_a_pass() -> None:
    """A findings table is for things an administrator has to decide about.
    Recording passes there buries the entries that need one, and it is why the
    per-category counts became plain numbers."""
    body = FUNCTION_BODIES["Add-Finding"]
    validate = body[body.index("ValidateSet") :]
    validate = validate[: validate.index(")")]

    assert "'Pass'" not in validate, "Add-Finding still accepts a Pass"
    assert "'Review'" in validate
    assert "'Fail'" in validate


def test_every_finding_records_the_stage_it_came_from() -> None:
    """So the review's Stages table is built from the findings rather than from a
    second set of severities kept alongside them."""
    body = FUNCTION_BODIES["Add-Finding"]

    assert "Stage      = [string]$script:Stage" in body


def test_the_overall_verdict_is_computed_in_exactly_one_place() -> None:
    """Two computations of "the overall result" is how a terminal and a file
    disagree even when both read correct data."""
    assert "function Get-OverallSeverity" in AUDIT_CODE

    callers = re.findall(r"=\s*Get-OverallSeverity", AUDIT_CODE)
    assert len(callers) == 2, f"expected the verdict stage and the renderer: {callers}"

    # And the old route is gone: nothing recombines per-stage severities by hand.
    assert "Get-WorstSeverity -Severities @($trust.Severity" not in AUDIT_CODE


def test_the_review_stage_table_is_built_from_the_finding_collection() -> None:
    """Not from four hand-written rows, two of which were the constant PASS. The
    inline-policy stage had no row at all, so its finding could not have shown up
    here however the run went."""
    assert "foreach ($stage in $AuditStages)" in REVIEW_BODY
    assert "Get-StageSeverity -Stage ([string]$stage)" in REVIEW_BODY


def test_the_declared_stages_are_the_stages_the_script_actually_runs() -> None:
    """$AuditStages is matched against a finding's recorded Stage by string, so a
    title that drifts from its Write-Section call silently scores that stage PASS
    forever."""
    declared = re.findall(
        r"^\s+'([^']+)',?$",
        AUDIT_CODE[AUDIT_CODE.index("$AuditStages = @(") :].split(")")[0],
        re.MULTILINE,
    )
    announced = re.findall(r"Write-Section '([^']+)'", AUDIT_CODE)

    assert declared, "no stages were parsed out of $AuditStages"

    # Verdict and Review announce themselves but record nothing, so they are the
    # only two sections allowed to be absent from the table.
    assert announced == [*declared, "Verdict", "Review"], (
        f"declared: {declared}\nannounced: {announced}"
    )


# --- The verdict-to-exit-code mapping --------------------------------------


def test_only_a_fail_exits_two() -> None:
    """PASS and REVIEW both completed the audit, so both exit 0. A REVIEW is a
    request for an administrator's judgement, not a failed run, and giving it a
    non-zero exit would make every future caller treat it as breakage."""
    main = main_body(AUDIT_CODE)

    assert "if ($overall -eq 'Fail') { $script:ExitCode = 2 }" in main
    assert main.count("$script:ExitCode = 2") == 1
    assert "'Review'" not in main[main.index("$script:ExitCode = 2") :]


def test_the_exit_code_starts_at_zero_and_is_set_in_three_places_only() -> None:
    codes = re.findall(r"\$script:ExitCode\s*=\s*(\d)", AUDIT_CODE)

    assert codes == ["0", "2", "1"], f"unexpected exit-code assignments: {codes}"


def test_an_incomplete_run_exits_one_and_writes_no_review() -> None:
    """Exit 1 is reserved for a run that did not finish. It is set in the catch
    block, which is reached before the review is ever written -- and the review is
    independently gated on the completion flag."""
    # The script body's catch, not one of the helpers' -- anchored past the main
    # body so an earlier try/catch inside a function cannot be picked up.
    main = main_body(AUDIT_CODE)
    catch = main[main.index("catch {") :]

    assert "$script:ExitCode = 1" in catch
    assert "New-ReviewFile" not in catch, "the catch block writes a review"
    assert "$script:StagesCompleted = $true" not in catch


# ---------------------------------------------------------------------------
# 17. No repository file carries a real identifier, credential, or URL.
# ---------------------------------------------------------------------------

#: Deliberately fake, and used in detector self-tests across the suite.
PLACEHOLDER_ACCOUNT_IDS = {"123456789012", "000000000000"}

# The detectors below need planted values to prove they match something, and
# this module is itself inside the scan. Every fixture is therefore assembled
# from fragments, so the matchable literal never appears in the file.
#
# The alternative -- exempting this module from the repository-wide scan -- would
# make the one file most likely to contain a realistic-looking identifier the one
# file nobody checks. Splitting the strings keeps the module in scope and keeps
# the fixtures real.
PLANTED_ACCOUNT_ID = "2109" + "87654321"
PLANTED_ROLE_ARN = f"arn:aws:lambda:us-east-2:{PLANTED_ACCOUNT_ID}:function:f"
PLANTED_ACCESS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
PLANTED_FUNCTION_URL_HOST = "abc.lambda-url." + "us-east-2.on.aws"
PLANTED_SECRET_PATH = "graceful-gut-ai" + "/dev/api-key"

TRACKED_SUFFIXES = {
    ".py",
    ".ps1",
    ".sh",
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".toml",
    ".cfg",
}

SKIP_DIRS = {".git", ".venv", "__pycache__", ".build", "node_modules", ".pytest_cache"}


def tracked_text_files() -> list[Path]:
    files: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in TRACKED_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


TRACKED_FILES = tracked_text_files()

#: The files Phase 1G authored. Held to the stricter rule: they may not carry a
#: secret identifier at all. Pre-existing files are not in scope for that rule --
#: CLAUDE.md records the secret NAME deliberately, and treats it as an
#: identifier rather than a credential. Changing that is not this task's call.
PHASE1G_FILES = [
    REPO_ROOT / "scripts" / "audit-lambda-execution-role.ps1",
    REPO_ROOT / "scripts" / "test-audit-lambda-execution-role-runtime.ps1",
    Path(__file__),
]


def test_the_repository_has_tracked_files_to_scan() -> None:
    """A scanner that silently matches nothing protects nothing."""
    assert len(TRACKED_FILES) > 20


def test_no_tracked_file_carries_a_real_account_id() -> None:
    offenders = []
    for path in TRACKED_FILES:
        for match in re.findall(r"\b\d{12}\b", path.read_text(encoding="utf-8")):
            if match not in PLACEHOLDER_ACCOUNT_IDS:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {match}")

    assert not offenders, f"real account IDs committed: {offenders}"


def test_no_tracked_file_carries_an_account_bearing_arn() -> None:
    pattern = re.compile(r"arn:aws[a-z0-9-]*:[^\s:]*:[^\s:]*:(\d{12}):")
    offenders = []

    for path in TRACKED_FILES:
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            if match.group(1) not in PLACEHOLDER_ACCOUNT_IDS:
                offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, f"account-bearing ARNs committed: {sorted(set(offenders))}"


def test_no_tracked_file_carries_an_access_key_or_token() -> None:
    offenders = []
    for path in TRACKED_FILES:
        text = path.read_text(encoding="utf-8")
        for pattern in (r"\bAKIA[0-9A-Z]{16}\b", r"\bASIA[0-9A-Z]{16}\b"):
            if re.search(pattern, text):
                offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, f"access keys committed: {sorted(set(offenders))}"


def test_no_tracked_file_carries_a_live_function_url_or_api_host() -> None:
    offenders = []
    for path in TRACKED_FILES:
        text = path.read_text(encoding="utf-8")

        for match in re.findall(r"[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws", text):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {match}")

        api_host = r"\b[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com"
        for match in re.findall(api_host, text):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {match}")

    assert not offenders, f"live endpoint hosts committed: {offenders}"


def test_no_phase1g_file_carries_a_secret_identifier() -> None:
    """The audit script takes the secret identifier as a mandatory parameter
    precisely so it is never committed. An example in a doc comment is the
    easiest way to undo that, and it is exactly what happened on the first draft
    of this script."""
    offenders = []
    for path in PHASE1G_FILES:
        text = path.read_text(encoding="utf-8")
        for match in re.findall(r"graceful-gut-ai/[a-z0-9/_-]+", text):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {match}")

    assert not offenders, f"secret identifiers in Phase 1G files: {offenders}"


def test_the_identifier_detectors_match_planted_inputs() -> None:
    """Each detector above is proved against a value it must catch, and against
    prose it must not."""
    assert re.search(r"\b\d{12}\b", f"account {PLANTED_ACCOUNT_ID} here")
    assert re.search(r"arn:aws[a-z0-9-]*:[^\s:]*:[^\s:]*:(\d{12}):", PLANTED_ROLE_ARN)
    assert re.search(r"\bAKIA[0-9A-Z]{16}\b", PLANTED_ACCESS_KEY)
    assert re.findall(
        r"[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws", PLANTED_FUNCTION_URL_HOST
    )
    assert re.findall(r"graceful-gut-ai/[a-z0-9/_-]+", PLANTED_SECRET_PATH)

    # The AWS-managed policy ARN carries no account field and must not trip it.
    assert not re.search(
        r"arn:aws[a-z0-9-]*:[^\s:]*:[^\s:]*:(\d{12}):",
        "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
    )


# ---------------------------------------------------------------------------
# Collection handling. Added after the first administrator run failed with
# "The property 'Count' cannot be found on this object."
#
# Root cause: a PowerShell function cannot return an array by writing
# `return @($x)`. The return value travels through the pipeline, which
# enumerates it -- a one-element array arrives at the caller as the bare
# element, and an empty array arrives as nothing. Get-AsArray, whose entire job
# was to guarantee an array, therefore returned a scalar whenever it was handed
# one item. The audited role has exactly one attached managed policy.
#
# The script cannot be executed here, so this section pins the fix two ways: a
# model of the PowerShell semantics that proves why the pattern is correct, and
# structural guards that every site actually uses that pattern.
# ---------------------------------------------------------------------------


class _Nothing:
    """The empty pipeline -- what PowerShell delivers for a 0-element return."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<nothing>"


NOTHING = _Nothing()


def ps_array_subexpression(value: object) -> object:
    """Model of PowerShell's ``@(...)`` array subexpression.

    Note the trap this models faithfully: ``@($null)`` is a **one**-element
    array containing $null, not an empty one. That is why the $null case has to
    be handled inside the normaliser and cannot be fixed by wrapping at the
    call site.
    """
    if isinstance(value, _Nothing):
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def ps_pipeline_return(value: object) -> object:
    """Model of what ``return <collection>`` actually delivers to a caller.

    PowerShell enumerates a function's return value. A 0-element collection
    delivers nothing at all; a 1-element collection delivers the bare element.
    This single behaviour is the whole bug.
    """
    if isinstance(value, list):
        if len(value) == 0:
            return NOTHING
        if len(value) == 1:
            return value[0]
    return value


class _PSObjectWrapper:
    """Model of the ``[psobject]`` Windows PowerShell 5.1 wraps -NoEnumerate in.

    The wrapper forwards property access to what it holds -- ``.Count`` on it
    reads the inner collection's Count -- but ``@(...)`` cannot see through it and
    collects it as a single item. That asymmetry is the whole of the second
    administrator failure: the length check read a Count of one, not three.
    """

    def __init__(self, inner: object) -> None:
        self.inner = inner

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<psobject {self.inner!r}>"


def ps_write_output_no_enumerate(value: object, *, wraps: bool) -> object:
    """Model of ``Write-Output -NoEnumerate``: the collection crosses whole.

    ``wraps`` selects the host. Windows PowerShell 5.1 adds a [psobject]
    wrapper; PowerShell 7 does not. Both are modelled because the script has to
    be correct on both and this host cannot determine which it is running on --
    there is no PowerShell interpreter here.
    """
    return _PSObjectWrapper(value) if wraps else value


def ps_cast_object_array(value: object) -> object:
    """Model of the ``[object[]]`` cast the call sites apply.

    A PowerShell conversion unwraps a [psobject] before converting, so the cast
    yields the underlying array on 5.1 and leaves a plain array untouched on 7.
    A scalar becomes a one-element array, which is also correct.
    """
    if isinstance(value, _PSObjectWrapper):
        value = value.inner
    if isinstance(value, _Nothing):
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def ps_count(value: object) -> int:
    """Model of ``.Count`` under ``Set-StrictMode -Version Latest``.

    A real collection has Count. A [psobject]-wrapped one forwards the property.
    A scalar object has no Count at all, and reading it raises the exact error the
    first administrator run saw.
    """
    if isinstance(value, _PSObjectWrapper):
        return ps_count(value.inner)
    if isinstance(value, list):
        return len(value)
    raise AttributeError("The property 'Count' cannot be found on this object.")


def broken_get_as_array(value: object) -> object:
    """The original normaliser: ``return @($Value)``. Defeated by the pipeline."""
    if value is None:
        return ps_pipeline_return([])
    return ps_pipeline_return(ps_array_subexpression(value))


def fixed_get_as_array(value: object, *, wraps: bool = False) -> object:
    """The corrected normaliser: ``Write-Output -NoEnumerate @($Value)``."""
    if value is None:
        return ps_write_output_no_enumerate([], wraps=wraps)
    return ps_write_output_no_enumerate(ps_array_subexpression(value), wraps=wraps)


def uncast_call_site(value: object, *, wraps: bool) -> object:
    """The previous call-site pattern: ``@(Get-AsArray -Value $x)``.

    Correct on PowerShell 7 and wrong on Windows PowerShell 5.1, where the
    [psobject] wrapper survives into the array subexpression.
    """
    return ps_array_subexpression(fixed_get_as_array(value, wraps=wraps))


def call_site(value: object, *, wraps: bool = False) -> object:
    """The corrected call-site pattern: ``@([object[]](Get-AsArray -Value $x))``."""
    return ps_array_subexpression(
        ps_cast_object_array(fixed_get_as_array(value, wraps=wraps))
    )


#: Both hosts the script must run on. The suite checks every normalisation
#: against both, because the script is deployed to a Windows administrator's
#: machine and this host cannot tell which one that will be.
HOSTS = ((False, "PowerShell 7"), (True, "Windows PowerShell 5.1"))


def counts_on_every_host(value: object) -> dict[str, int]:
    """Length the corrected call-site pattern yields, per host."""
    return {label: ps_count(call_site(value, wraps=wraps)) for wraps, label in HOSTS}


# --- The model is able to detect the bug -----------------------------------


def test_the_model_reproduces_the_administrator_failure() -> None:
    """A model that could not fail would prove nothing about the fix.

    The failure had two adjacent effects in the one-policy case, and which of
    them raised the reported error cannot be determined from here. Both are
    defects and both are fixed, so the distinction does not change the repair:

      * The outer one-element list of policies was unwrapped to the inner
        ``[PolicyName, PolicyArn]`` row. The loop then iterated over *fields*
        rather than over policies -- a silently wrong answer, not a crash.
      * Normalising one of those fields returned a bare string, and reading
        ``.Count`` from a scalar is what produces "The property 'Count' cannot
        be found on this object."
    """
    one_policy = [["AWSLambdaBasicExecutionRole", "arn-placeholder"]]

    delivered = broken_get_as_array(one_policy)

    # The outer list is gone: what arrives is the inner row.
    assert delivered == ["AWSLambdaBasicExecutionRole", "arn-placeholder"]
    assert ps_count(delivered) == 2, "iterating this yields fields, not policies"

    # Normalising a single field then delivers a bare scalar, which has no Count.
    field = broken_get_as_array(delivered[0])
    assert not isinstance(field, list)
    with pytest.raises(AttributeError, match="'Count' cannot be found"):
        ps_count(field)


def test_the_model_reproduces_the_scalar_case_directly() -> None:
    """The simplest form of the same defect: a one-element list of a scalar,
    which is exactly the shape of a single inline policy name."""
    delivered = broken_get_as_array(["GracefulGutAI-SecretAccess"])

    assert not isinstance(delivered, list)
    with pytest.raises(AttributeError, match="'Count' cannot be found"):
        ps_count(delivered)


def test_the_model_reproduces_the_zero_item_failure() -> None:
    """The zero-policy path was broken the same way and would have failed
    identically -- an empty return arrives as nothing, not as an empty array."""
    delivered = broken_get_as_array(None)

    assert isinstance(delivered, _Nothing)
    with pytest.raises(AttributeError, match="'Count' cannot be found"):
        ps_count(delivered)


def test_wrapping_the_call_site_alone_cannot_fix_the_null_case() -> None:
    """Why the $null branch lives inside the normaliser: @($null) has a Count of
    one, so a call-site wrap would turn "no policies" into "one null policy"."""
    assert ps_count(ps_array_subexpression(None)) == 1


# --- The fixed pattern handles zero, one, and many -------------------------


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("zero", None, 0),
        ("one", [["AWSLambdaBasicExecutionRole", "arn-placeholder"]], 1),
        (
            "many",
            [["PolicyA", "arn-a"], ["PolicyB", "arn-b"], ["PolicyC", "arn-c"]],
            3,
        ),
    ],
)
def test_attached_policies_normalise_for_zero_one_and_many(
    label: str, value: object, expected: int
) -> None:
    for host, actual in counts_on_every_host(value).items():
        assert actual == expected, f"attached policies: {label} on {host}"


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("zero", None, 0),
        ("one", ["GracefulGutAI-SecretAccess"], 1),
        ("many", ["GracefulGutAI-SecretAccess", "SomethingElse"], 2),
    ],
)
def test_inline_policies_normalise_for_zero_one_and_many(
    label: str, value: object, expected: int
) -> None:
    for host, actual in counts_on_every_host(value).items():
        assert actual == expected, f"inline policies: {label} on {host}"


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("zero", None, 0),
        ("one", {"Effect": "Allow", "Action": "logs:PutLogEvents"}, 1),
        (
            "many",
            [
                {"Effect": "Allow", "Action": "logs:PutLogEvents"},
                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue"},
            ],
            2,
        ),
    ],
)
def test_statements_normalise_for_zero_one_and_many(
    label: str, value: object, expected: int
) -> None:
    """A single-statement policy is the common shape for the inline secret grant,
    and it is the shape that would be skipped entirely by unnormalised code."""
    for host, actual in counts_on_every_host(value).items():
        assert actual == expected, f"statements: {label} on {host}"


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("scalar string", "secretsmanager:GetSecretValue", 1),
        (
            "array",
            ["logs:CreateLogStream", "logs:PutLogEvents"],
            2,
        ),
    ],
)
def test_action_normalises_as_scalar_and_as_array(
    label: str, value: object, expected: int
) -> None:
    for host, actual in counts_on_every_host(value).items():
        assert actual == expected, f"Action as {label} on {host}"


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("scalar string", "*", 1),
        ("array", ["arn-a", "arn-b"], 2),
    ],
)
def test_resource_normalises_as_scalar_and_as_array(
    label: str, value: object, expected: int
) -> None:
    for host, actual in counts_on_every_host(value).items():
        assert actual == expected, f"Resource as {label} on {host}"


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("scalar", "lambda.amazonaws.com", 1),
        ("array", ["lambda.amazonaws.com", "edgelambda.amazonaws.com"], 2),
    ],
)
def test_principal_service_normalises_as_scalar_and_as_array(
    label: str, value: object, expected: int
) -> None:
    """The trust-policy check compares the service-principal count against one.
    A scalar Service would have made that comparison unreachable."""
    for host, actual in counts_on_every_host(value).items():
        assert actual == expected, f"Principal.Service as {label} on {host}"


@pytest.mark.parametrize("count", [0, 1, 3])
def test_findings_and_corrections_count_safely_at_every_size(count: int) -> None:
    """Findings and corrections are a real List and a @()-wrapped Where-Object
    result respectively, so both count safely at zero, one, and many."""
    findings = [{"Severity": "Fail", "Correction": "x"} for _ in range(count)]

    assert ps_count(findings) == count
    corrections = ps_array_subexpression([f for f in findings if f["Correction"]])
    assert ps_count(corrections) == count


# --- The script actually uses the fixed pattern ----------------------------


def test_the_normaliser_uses_write_output_no_enumerate() -> None:
    helper = AUDIT_CODE[AUDIT_CODE.index("function Get-AsArray") :]
    helper = helper[: helper.index("function Get-CallerAccountId")]

    assert "Write-Output -NoEnumerate" in helper, (
        "the normaliser returns an array through the pipeline, which unwraps it"
    )
    # Read from the comment-stripped copy: the doc block quotes the defeated
    # pattern deliberately, to explain why it cannot be used.
    assert "return @(" not in helper, "the defeated `return @(...)` pattern is back"


def test_the_normaliser_handles_null_before_wrapping() -> None:
    """Order is the guard: @($null) has a Count of one, so the $null test must
    come first."""
    helper = AUDIT_CODE[AUDIT_CODE.index("function Get-AsArray") :]
    helper = helper[: helper.index("function Get-CallerAccountId")]

    null_branch = helper.index("$null -eq $Value")
    wrap = helper.index("Write-Output -NoEnumerate @($Value)")

    assert null_branch < wrap


def test_every_normaliser_call_site_is_wrapped_and_cast() -> None:
    """The second, independent layer, in the only form that works on both hosts.

    ``@(...)`` alone was the previous version. It fixes the one-item case on
    PowerShell 7 and does not fix it on Windows PowerShell 5.1, where the
    [psobject] wrapper -NoEnumerate adds survives into the array subexpression --
    which is the shape the second administrator failure reported. The
    ``[object[]]`` cast unwraps it, and is a no-op on a plain array, so the call
    site stops depending on which host it runs on.
    """
    offenders = []
    for line in AUDIT_CODE.splitlines():
        if "Get-AsArray -Value" not in line:
            continue
        if "@([object[]](Get-AsArray -Value" not in line:
            offenders.append(line.strip())

    assert not offenders, f"call sites without the wrap-and-cast: {offenders}"


def test_the_collection_returning_resolvers_are_wrapped_too() -> None:
    """Get-AttachedPolicyDocuments and Get-InlinePolicyDocuments return a List,
    and `return $list` is enumerated by the pipeline exactly as @() was."""
    assert "foreach ($policy in @(Get-AttachedPolicyDocuments))" in AUDIT_CODE
    assert "foreach ($policy in @(Get-InlinePolicyDocuments))" in AUDIT_CODE


def test_a_single_attached_policy_is_the_documented_failure_case() -> None:
    """Requirement: the one-policy case must be named in the script, so the next
    reader knows which shape broke it rather than rediscovering it."""
    assert "single attached managed policy" in AUDIT_FLAT
    assert "The property 'Count' cannot be found on this object." in AUDIT_TEXT


def test_strict_mode_was_not_disabled_to_solve_this() -> None:
    """The failure was a real defect that StrictMode surfaced. Turning StrictMode
    off would have hidden it and left the audit silently skipping policies."""
    assert "Set-StrictMode -Version Latest" in AUDIT_CODE
    assert "Set-StrictMode -Off" not in AUDIT_TEXT
    assert "-Version 1" not in AUDIT_TEXT


# --- Requirement 9: every .Count in the script is provably safe ------------

#: Receivers that are safe for a reason other than an inline @() wrap. Each entry
#: is a variable name mapped to why it is a real collection.
COUNT_RECEIVER_EXEMPTIONS = {
    # Declared [string[]], so PowerShell coerces even a scalar to an array.
    "$Severities": "type-constrained [string[]] parameter",
    # The -split operator returns [string[]]; operator assignment does not go
    # through the pipeline, so it is never unwrapped.
    "$parts": "assigned from the -split operator",
}

#: Assignment forms that produce a genuine collection.
SAFE_ASSIGNMENT_PATTERNS = (
    re.compile(r"=\s*@\("),
    re.compile(r"=\s*New-Object\s+System\.Collections\.Generic\.List"),
    re.compile(r"=\s*New-Object\s+System\.Collections\.ArrayList"),
    # A type-constrained declaration is stronger than a normalising wrapper, not
    # weaker: PowerShell coerces on this assignment and on every later one, so
    # the variable cannot become a scalar afterwards. This is the shape the
    # review path was rewritten into after the third administrator run.
    re.compile(r"^\s*\[(?:object|string)\[\]\]\s*\$"),
)

#: An assignment may carry a type constraint in front of the variable.
TYPE_CONSTRAINT = r"(?:\[[A-Za-z0-9_.\[\]]+\]\s*)?"


def function_bodies(code: str) -> dict[str, str]:
    """Split the executable script into ``name -> body``.

    Scoping matters. ``$fields`` and ``$pair`` are each used in two different
    functions with different types -- a normalised array in one, a plain string
    in the other. A whole-file search for their assignments mixes the two and
    reports a false violation, which is what the first version of this scan did.
    """
    bodies: dict[str, str] = {}
    parts = re.split(r"^function\s+([A-Za-z][A-Za-z0-9-]*)", code, flags=re.MULTILINE)

    # parts[0] is the top-level code before the first function.
    bodies["<script>"] = parts[0]
    for index in range(1, len(parts) - 1, 2):
        bodies[parts[index]] = parts[index + 1]
    return bodies


FUNCTION_BODIES = function_bodies(AUDIT_CODE)

COUNT_PATTERN = re.compile(r"(@\([^\n]*?\)|\$[A-Za-z_][A-Za-z0-9_:]*)\.Count")


def count_receivers() -> list[tuple[str, str]]:
    """Every expression that has .Count read from it, with its function name."""
    receivers = []
    for name, body in FUNCTION_BODIES.items():
        for match in COUNT_PATTERN.finditer(body):
            receivers.append((name, match.group(1)))
    return receivers


def test_the_function_splitter_finds_the_scripts_functions() -> None:
    """A splitter that returned one blob would make the scoped scan below no
    better than the unscoped one it replaced."""
    assert "Get-AsArray" in FUNCTION_BODIES
    assert "Get-AttachedPolicyDocuments" in FUNCTION_BODIES
    assert "Invoke-AwsRead" in FUNCTION_BODIES
    assert len(FUNCTION_BODIES) > 15

    # The scoping this exists for: a name reused across functions must resolve to
    # its own function's assignment. $values is normalised in both places, so a
    # whole-file search would happen to pass here -- and would report a false
    # violation the moment the two differed, which is what the first version of
    # this scan did with $pair.
    assert "$values = @([object[]](Get-AsArray" in FUNCTION_BODIES["Test-TrustPolicy"]
    assert "$values = @([object[]](Get-AsArray" in FUNCTION_BODIES["Get-ResourceScope"]
    assert '$pair = "${Service}:${Operation}"' in FUNCTION_BODIES["Invoke-AwsRead"]

    # And the positional $values that stopped the second run is gone entirely.
    assert "$values" not in FUNCTION_BODIES["Get-FunctionRoleName"]


def test_the_count_receiver_scan_finds_the_known_usages() -> None:
    """A scan that matched nothing would make the rule below vacuous.

    The floor is lower than it was before the fixed-record correction, and that is
    the improvement rather than a regression: the function-configuration and
    secret-metadata reads used to count fields to decide whether a response was
    complete, and both now validate named properties instead. Four ``.Count``
    usages were deleted because counting was the wrong question.
    """
    receivers = count_receivers()

    assert len(receivers) >= 12, f"only found {len(receivers)} .Count usages"

    # The collection sites -- where a length genuinely is data -- must still be
    # counted, so the rule below is not passing by having nothing left to check.
    counted = {receiver for _, receiver in receivers}
    for expected in ("$rows", "$names", "$actions", "$servicePrincipals"):
        assert expected in counted, f"the scan lost sight of {expected}"


def test_every_count_receiver_is_normalised_or_a_real_collection() -> None:
    """Requirement 9, enforced rather than asserted in prose.

    For each ``.Count`` in the script the receiver must be one of:

      * an inline ``@(...)`` subexpression,
      * a variable assigned -- **in the same function** -- from ``@(...)`` or a
        generic List, or
      * a named exemption with a recorded reason.

    A new ``.Count`` on an unvetted variable fails here. This is the check the
    first administrator run needed and did not have.
    """
    unproven = []

    for function_name, receiver in count_receivers():
        if receiver.startswith("@("):
            continue
        if receiver in COUNT_RECEIVER_EXEMPTIONS:
            continue

        # A $script: variable is declared at the top level, not in a function.
        scope = (
            FUNCTION_BODIES["<script>"]
            if receiver.startswith("$script:")
            else FUNCTION_BODIES[function_name]
        )

        assignments = [
            line
            for line in scope.splitlines()
            if re.search(
                r"^\s*" + TYPE_CONSTRAINT + re.escape(receiver) + r"\s*=[^=]", line
            )
        ]

        if not assignments:
            unproven.append(f"{function_name}: {receiver} has no assignment in scope")
            continue

        for line in assignments:
            if not any(p.search(line) for p in SAFE_ASSIGNMENT_PATTERNS):
                unproven.append(f"{function_name}: {receiver} unsafe -> {line.strip()}")

    assert not unproven, "unproven .Count receivers:\n" + "\n".join(unproven)


def test_the_receiver_scan_rejects_an_unsafe_assignment() -> None:
    """Proof the rule can fail. A receiver assigned from a bare function call --
    exactly the pattern that broke -- must not be accepted as safe."""
    unsafe = "    $rows = Get-AsArray -Value $thing"

    assert not any(p.search(unsafe) for p in SAFE_ASSIGNMENT_PATTERNS)

    safe = "    $rows = @(Get-AsArray -Value $thing)"
    assert any(p.search(safe) for p in SAFE_ASSIGNMENT_PATTERNS)


def test_every_index_access_is_guarded_by_a_count_check() -> None:
    """Indexing an unnormalised value fails the same way .Count does. Every
    literal index in the script must sit after a Count guard in its function."""
    functions = re.split(r"\nfunction ", AUDIT_CODE)
    offenders = []

    for body in functions:
        indexes = list(re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]", body))
        if not indexes:
            continue

        for match in indexes:
            name = match.group(1)
            guard = re.search(
                r"\$" + re.escape(name) + r"\.Count\s*-(?:lt|gt|ge|le|eq|ne)", body
            )
            if not guard or guard.start() > match.start():
                offenders.append(
                    f"${name}[{match.group(2)}] is indexed without a prior Count guard"
                )

    assert not offenders, "\n".join(offenders)


def test_the_fail_closed_behaviour_survived_the_fix() -> None:
    """The fix touched the data plumbing, not the safety properties. All four
    must still hold."""
    # Exit 1 when the audit cannot complete.
    assert "$script:ExitCode = 1" in AUDIT_CODE
    # No review after an incomplete audit.
    assert "if (-not $script:StagesCompleted)" in AUDIT_CODE
    # Never print PASS for an unfinished stage.
    assert AUDIT_CODE.count("return 'PASS'") == 1
    # Never apply a correction.
    assert "An administrator applies these. This script never does." in AUDIT_TEXT


# ---------------------------------------------------------------------------
# The second administrator failure. The first correction moved Get-AsArray onto
# `Write-Output -NoEnumerate`; the next run stopped with
#
#     The function configuration query returned fewer fields than expected.
#
# The root cause was a category error rather than a plumbing bug. The function
# configuration is a fixed-shape record -- State, LastUpdateStatus, Role -- and
# it was being requested as the positional list [State,LastUpdateStatus,Role]
# and then validated by length. Length is not a property of a fixed record, so
# the check was measuring the wrong thing; it read one where it wanted three
# because the [psobject] wrapper made the three fields arrive nested inside a
# single item.
#
# Two things follow, and this section pins both. Fixed-shape responses are now
# requested as JMESPath multiselect hashes and read by field name, so no length
# is involved anywhere. And the call sites that legitimately do handle
# collections got the [object[]] cast above, because the wrapper was a real
# defect there too -- it was simply not the one that produced the error message.
# ---------------------------------------------------------------------------


THREE_FIELD_RECORD = ["Active", "Successful", "arn-placeholder"]


def test_the_model_reproduces_the_second_administrator_failure() -> None:
    """The positional read, on the host the administrator was using.

    Three fields were requested and three were returned. What the length check
    saw was one, because ``@(...)`` collected the [psobject] wrapper as a single
    item instead of seeing the array inside it. The old guard was
    ``$values.Count -lt 3``, so this is exactly the reported abort.
    """
    delivered = uncast_call_site(THREE_FIELD_RECORD, wraps=True)

    assert ps_count(delivered) == 1, "the failure needs a nested single item"
    assert isinstance(delivered[0], _PSObjectWrapper), "the wrapper is the item"
    assert delivered[0].inner == THREE_FIELD_RECORD, "the fields are one level down"
    assert ps_count(delivered) < 3, "this is the abort the administrator saw"


def test_the_same_positional_read_would_have_passed_on_the_other_host() -> None:
    """Why this reached an administrator rather than a test. On PowerShell 7 the
    identical code returns three fields and the length check passes, so the defect
    is invisible on any host that does not add the wrapper."""
    delivered = uncast_call_site(THREE_FIELD_RECORD, wraps=False)

    assert ps_count(delivered) == 3


def test_the_collection_call_sites_were_affected_by_the_wrapper_too() -> None:
    """The error message named the function configuration, but the wrapper hit
    every call site. With one attached policy the uncast pattern yields a count of
    one -- the right number by accident -- whose single element is the whole list
    rather than a policy. The audit would have inspected a nested array instead of
    a policy, which is a wrong answer rather than a crash."""
    one_policy = [{"PolicyName": "AWSLambdaBasicExecutionRole", "PolicyArn": "arn"}]

    delivered = uncast_call_site(one_policy, wraps=True)

    assert ps_count(delivered) == 1
    assert isinstance(delivered[0], _PSObjectWrapper)
    assert delivered[0].inner == one_policy, "the element is the list, not a policy"

    # The corrected pattern hands back the policy itself, on both hosts.
    for wraps, label in HOSTS:
        rows = call_site(one_policy, wraps=wraps)
        assert ps_count(rows) == 1, label
        assert rows[0]["PolicyName"] == "AWSLambdaBasicExecutionRole", label


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("zero", None, 0),
        ("one", [{"PolicyName": "A", "PolicyArn": "arn-a"}], 1),
        (
            "many",
            [
                {"PolicyName": "A", "PolicyArn": "arn-a"},
                {"PolicyName": "B", "PolicyArn": "arn-b"},
            ],
            2,
        ),
    ],
)
def test_named_policy_rows_normalise_for_zero_one_and_many(
    label: str, value: object, expected: int
) -> None:
    """The zero/one/many guarantee, restated for the named-row shape the attached
    policy query now returns. The previous correction's property is preserved; only
    the shape of each row changed."""
    for host, actual in counts_on_every_host(value).items():
        assert actual == expected, f"named policy rows: {label} on {host}"


# --- A model of the fixed-record path, and of what it refuses ---------------


class StopRun(Exception):
    """Model of the script's Stop-Run: the whole audit aborts, no review."""


def ps_convert_from_json_record(payload: object) -> dict:
    """Model of ConvertFrom-AwsJsonRecord's guards.

    A JSON object crosses as a named record. A list, a scalar, or nothing at all
    stops the run -- a list in particular, because a list arriving here means some
    call site went back to a positional query.
    """
    if payload is None:
        raise StopRun("No record was returned.")
    if isinstance(payload, (str, bool, int, float)):
        raise StopRun("arrived as a single value where a named record was expected")
    if isinstance(payload, list):
        raise StopRun("arrived as a list where a single named record was expected")
    return payload


def get_required_field(record: dict, name: str) -> str:
    """Model of Get-RequiredField: present, non-null, a string, and non-empty."""
    if name not in record:
        raise StopRun(f"did not include the required field '{name}'")
    value = record[name]
    if value is None:
        raise StopRun(f"did not include the required field '{name}'")
    if not isinstance(value, str):
        raise StopRun(f"returned '{name}' as something other than a string")
    if not value.strip():
        raise StopRun(f"did not include the required field '{name}'")
    return value


CONFIGURATION_FIELDS = ("State", "LastUpdateStatus", "Role")

CLEAN_CONFIGURATION = {
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "Role": f"arn:aws:iam::{sorted(PLACEHOLDER_ACCOUNT_IDS)[0]}:role/ExampleRole",
}


def test_the_configuration_is_read_as_a_named_record() -> None:
    """No length, no index. Each field is fetched by the name it was asked for."""
    record = ps_convert_from_json_record(dict(CLEAN_CONFIGURATION))

    assert get_required_field(record, "State") == "Active"
    assert get_required_field(record, "LastUpdateStatus") == "Successful"
    assert get_required_field(record, "Role").endswith("/ExampleRole")


def test_a_named_record_is_immune_to_the_wrapper_that_broke_the_positional_read() -> (
    None
):
    """The point of the correction. A JSON object has no elements, so there is
    nothing for -NoEnumerate to wrap, nothing for the pipeline to enumerate, and
    no position for a field to move to -- on either host."""
    record = ps_convert_from_json_record(dict(CLEAN_CONFIGURATION))

    for wraps, label in HOSTS:
        delivered = fixed_get_as_array(record, wraps=wraps)
        # Even routed through the collection normaliser it stays one record, and
        # its fields are still reachable by name.
        recovered = ps_cast_object_array(delivered)
        assert len(recovered) == 1, label
        assert get_required_field(recovered[0], "State") == "Active", label


@pytest.mark.parametrize("missing", CONFIGURATION_FIELDS)
def test_an_absent_configuration_field_fails_and_names_itself(missing: str) -> None:
    """Requirement: missing State fails, missing LastUpdateStatus fails, missing
    Role fails -- and the message says which. The length check said the same
    sentence for all three, which is why the administrator could not tell what was
    wrong from the output."""
    record = {k: v for k, v in CLEAN_CONFIGURATION.items() if k != missing}

    with pytest.raises(StopRun) as raised:
        for field in CONFIGURATION_FIELDS:
            get_required_field(ps_convert_from_json_record(record), field)

    assert f"'{missing}'" in str(raised.value)


@pytest.mark.parametrize("nulled", CONFIGURATION_FIELDS)
def test_a_null_configuration_field_fails_like_an_absent_one(nulled: str) -> None:
    """A JMESPath query for a field the response does not carry returns JSON null
    rather than omitting the key, so present-but-null has to fail too. Both mean
    the audit does not know the value."""
    record = dict(CLEAN_CONFIGURATION)
    record[nulled] = None

    with pytest.raises(StopRun) as raised:
        for field in CONFIGURATION_FIELDS:
            get_required_field(ps_convert_from_json_record(record), field)

    assert f"'{nulled}'" in str(raised.value)


@pytest.mark.parametrize("bad", ["", "   "])
def test_an_empty_configuration_field_fails(bad: str) -> None:
    record = dict(CLEAN_CONFIGURATION)
    record["State"] = bad

    with pytest.raises(StopRun):
        get_required_field(ps_convert_from_json_record(record), "State")


def test_a_non_string_configuration_field_fails() -> None:
    """A field that arrives as a number or an object is not a state name, and
    coercing it would produce a comparison against a string that never matches."""
    record = dict(CLEAN_CONFIGURATION)
    record["State"] = {"Nested": "Active"}

    with pytest.raises(StopRun, match="other than a string"):
        get_required_field(ps_convert_from_json_record(record), "State")


def test_the_three_fields_are_validated_independently() -> None:
    """Independence is what the length check could not offer. A response carrying
    State and Role but not LastUpdateStatus has three keys' worth of positions and
    would have passed a length check while leaving one value empty."""
    record = dict(CLEAN_CONFIGURATION)
    record["LastUpdateStatus"] = None

    # State still reads fine -- the failure is specific to the field that is wrong.
    assert get_required_field(ps_convert_from_json_record(record), "State") == "Active"
    assert get_required_field(ps_convert_from_json_record(record), "Role")

    with pytest.raises(StopRun, match="LastUpdateStatus"):
        get_required_field(ps_convert_from_json_record(record), "LastUpdateStatus")


def test_the_old_positional_read_could_not_have_caught_that() -> None:
    """The same response, read positionally: three items arrive, the length check
    passes, and the empty middle field is cast to a string and compared. The audit
    would have reported "last update was not Successful" for a response that never
    said so."""
    positional = ["Active", None, "arn-placeholder"]

    assert ps_count(ps_array_subexpression(positional)) == 3, "length check passes"
    assert positional[1] is None, "and the field it needed is absent anyway"


def test_a_positional_response_is_refused_by_the_record_parser() -> None:
    """The guard that stops the mistake coming back. A call site edited back to
    '[Field,Field]' fails immediately rather than being indexed."""
    with pytest.raises(StopRun, match="arrived as a list"):
        ps_convert_from_json_record(THREE_FIELD_RECORD)


def test_a_bare_scalar_response_is_refused_by_the_record_parser() -> None:
    """'--output text' with a single-field query returns a bare value. It is not a
    record, and treating it as one would make every field read return nothing."""
    with pytest.raises(StopRun, match="single value"):
        ps_convert_from_json_record("Active")


# --- The script actually asks for named fields everywhere ------------------

#: Every fixed-shape read, with the multiselect hash it must request. Read as a
#: table so a new fixed-shape call cannot be added positionally without either
#: appearing here or failing the sweep below.
FIXED_RECORD_QUERIES = {
    "sts:get-caller-identity": "{Account:Account}",
    "lambda:get-function-configuration": (
        "{State:State,LastUpdateStatus:LastUpdateStatus,Role:Role}"
    ),
    "secretsmanager:describe-secret": "{Arn:ARN,KmsKeyId:KmsKeyId}",
    "iam:get-role": "{AssumeRolePolicyDocument:Role.AssumeRolePolicyDocument}",
    "iam:get-policy": "{DefaultVersionId:Policy.DefaultVersionId}",
    "iam:get-policy-version": "{Document:PolicyVersion.Document}",
    "iam:get-role-policy": "{PolicyDocument:PolicyDocument}",
}

#: The two genuine collections. Their length is data, so they are queried as
#: lists on purpose and normalised rather than validated by name.
COLLECTION_QUERIES = {
    "iam:list-attached-role-policies": (
        "AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}"
    ),
    "iam:list-role-policies": "PolicyNames",
}


@pytest.mark.parametrize(("pair", "query"), sorted(FIXED_RECORD_QUERIES.items()))
def test_every_fixed_record_read_asks_for_named_fields(pair: str, query: str) -> None:
    assert f"'--query', '{query}'" in AUDIT_CODE, f"{pair} does not ask by name"


def test_the_two_collection_reads_are_still_queried_as_collections() -> None:
    """The split has two sides and both must hold. Turning a list into a
    multiselect hash would lose the zero/one/many property the previous correction
    bought."""
    for pair, query in COLLECTION_QUERIES.items():
        assert f"'--query', '{query}'" in AUDIT_CODE, f"{pair} query changed"


def test_the_fixed_record_table_covers_every_non_collection_read() -> None:
    """A table that omitted a read would let that read stay positional."""
    covered = set(FIXED_RECORD_QUERIES) | set(COLLECTION_QUERIES)

    assert covered == set(READ_ONLY_OPERATIONS), (
        "a read is neither classified as a fixed record nor as a collection"
    )


def test_no_positional_multiselect_query_survives_anywhere() -> None:
    """The shape that broke the run, banned by construction. A JMESPath
    multiselect *list* is '[A,B]'; a hash is '{A:A,B:B}'. Only the hash is
    allowed, except inside the one collection projection that needs a list index.
    """
    offenders = re.findall(r"'--query',\s*'\[[^']*'", AUDIT_CODE)

    assert not offenders, f"positional multiselect queries: {offenders}"


def test_no_fixed_record_read_uses_text_output() -> None:
    """'--output text' returns a bare value with no field names in it, so a text
    read cannot be validated by name. Both former text reads -- the caller identity
    and the default policy version -- are JSON now."""
    assert "'--output', 'text'" not in AUDIT_CODE

    for query in FIXED_RECORD_QUERIES.values():
        index = AUDIT_CODE.index(f"'--query', '{query}'")
        following = AUDIT_CODE[index : index + 200]
        assert "'--output', 'json'" in following, f"{query} is not read as JSON"


def test_the_configuration_stage_has_no_length_or_index_logic_left() -> None:
    """Requirement: no positional field-count logic for the function
    configuration. The stage is checked as a whole rather than by grepping for the
    old lines, so an equivalent rewrite cannot slip back in."""
    stage = FUNCTION_BODIES["Get-FunctionRoleName"]

    assert ".Count" not in stage, "the configuration stage counts something again"
    assert not re.search(r"\$[A-Za-z_][A-Za-z0-9_]*\[\d+\]", stage), (
        "the configuration stage indexes by position again"
    )
    assert "Get-AsArray" not in stage, (
        "a fixed record is going through the collection normaliser again"
    )


def test_the_old_field_count_message_is_gone() -> None:
    """The message an administrator saw. Its absence is how a rerun proves it is
    running the corrected script."""
    # The comment-stripped copy: the doc block quotes the old message on purpose,
    # to record what an administrator saw and why it was the wrong question.
    assert "returned fewer fields than expected" not in AUDIT_CODE
    assert "returned fewer fields than expected" in AUDIT_TEXT, (
        "the failure this fix addresses is no longer recorded in the script"
    )


def test_the_secret_metadata_stage_has_no_index_logic_left() -> None:
    """describe-secret was read positionally by the same pattern and would have
    failed the same way. Named fields there too, with KmsKeyId optional because a
    null KmsKeyId is a real answer."""
    stage = FUNCTION_BODIES["Get-ExpectedSecret"]

    assert not re.search(r"\$[A-Za-z_][A-Za-z0-9_]*\[\d+\]", stage)
    assert "Get-RequiredField -Record $metadata -Name 'Arn'" in stage
    assert "Get-OptionalField -Record $metadata -Name 'KmsKeyId'" in stage


def test_each_configuration_field_has_its_own_validation_call() -> None:
    """Three separate calls, so three separate messages. One call reading three
    fields would collapse the diagnostic again."""
    stage = FUNCTION_BODIES["Get-FunctionRoleName"]

    for field in CONFIGURATION_FIELDS:
        assert f"Get-RequiredField -Record $configuration -Name '{field}'" in stage, (
            f"{field} is not validated on its own"
        )


def test_the_required_field_reader_rejects_every_unusable_value() -> None:
    """Absent, null, non-string, and empty all have to fail, and the script's own
    helper is the single place that decides so."""
    helper = AUDIT_CODE[AUDIT_CODE.index("function Get-RequiredField") :]
    helper = helper[: helper.index("function Get-OptionalField")]

    assert "Test-HasProperty -Object $Record -Name $Name" in helper
    assert "$null -eq $value" in helper
    assert "$value -isnot [string]" in helper
    assert "[string]::IsNullOrWhiteSpace($value)" in helper
    assert helper.count("Stop-Run") == 4, "a rejection path stopped stopping the run"


def test_the_record_parser_rejects_lists_scalars_and_nothing() -> None:
    parser = AUDIT_CODE[AUDIT_CODE.index("function ConvertFrom-AwsJsonRecord") :]
    parser = parser[: parser.index("function Get-RequiredField")]

    assert "$parsed -is [string] -or $parsed -is [System.ValueType]" in parser
    assert "$parsed -is [System.Collections.IEnumerable]" in parser
    assert "$null -eq $parsed" in parser

    # A string is an IEnumerable, so it has to be rejected as a scalar first or the
    # message would call it a list.
    assert parser.index("-is [string]") < parser.index("IEnumerable")


def test_the_record_parser_does_not_use_the_pipeline() -> None:
    """The pipeline is the mechanism that unwraps collections. A record parser
    that used it would be depending on the behaviour it exists to avoid."""
    parser = AUDIT_CODE[AUDIT_CODE.index("function ConvertFrom-AwsJsonRecord") :]
    parser = parser[: parser.index("function Get-RequiredField")]

    assert "ConvertFrom-Json -InputObject $Text" in parser
    assert "| ConvertFrom-Json" not in parser


def test_the_two_parsers_are_kept_separate() -> None:
    """One parser for records, one for collections, and no call site using the
    wrong one. This is the separation the correction is built on."""
    assert "function ConvertFrom-AwsJsonList" in AUDIT_CODE
    assert "function ConvertFrom-AwsJsonRecord" in AUDIT_CODE

    # The list parser is used only where a length is genuinely data.
    list_uses = re.findall(r"ConvertFrom-AwsJsonList -Text \$\w+\.Output", AUDIT_CODE)
    assert len(list_uses) == 2, f"expected two collection reads, found {len(list_uses)}"

    # Every list parse is normalised; none is read by field name.
    for line in AUDIT_CODE.splitlines():
        if "ConvertFrom-AwsJsonList" not in line or "function" in line:
            continue
        assert "Get-AsArray" in line, (
            f"a collection read is not normalised: {line.strip()}"
        )


# --- The role ARN is reduced to a name and never emitted --------------------


def script_role_arn_pattern() -> re.Pattern[str]:
    """The script's own role-ARN regex, translated to Python.

    Read from the script rather than restated, so this cannot pass against a
    pattern the script does not use. Only the named-group syntax differs.
    """
    helper = AUDIT_TEXT[AUDIT_TEXT.index("function Get-RoleNameFromArn") :]
    helper = helper[: helper.index("function Get-AsArray")]

    match = re.search(r"\$Arn,\s*'([^']+)'\)", helper)
    assert match, "the role-ARN pattern is not where this test expects it"

    return re.compile(match.group(1).replace("(?<name>", "(?P<name>"))


ROLE_ARN_PATTERN = script_role_arn_pattern()


def test_the_role_name_is_extracted_from_a_plain_role_arn() -> None:
    account = sorted(PLACEHOLDER_ACCOUNT_IDS)[0]
    match = ROLE_ARN_PATTERN.match(f"arn:aws:iam::{account}:role/ExampleRole")

    assert match and match.group("name") == "ExampleRole"


def test_the_role_name_is_the_last_segment_of_a_pathed_role_arn() -> None:
    """A pathed role is 'role/path/to/Name'. Taking the segment after 'role/'
    would return the path element instead of the name."""
    account = sorted(PLACEHOLDER_ACCOUNT_IDS)[0]
    match = ROLE_ARN_PATTERN.match(
        f"arn:aws:iam::{account}:role/service-role/deeper/ExampleRole"
    )

    assert match and match.group("name") == "ExampleRole"


@pytest.mark.parametrize(
    "arn",
    [
        "not-an-arn",
        "arn:aws:iam::123456789012:user/Someone",
        "arn:aws:lambda:us-east-2:123456789012:function:f",
        "arn:aws:iam::12345:role/TooShortAccount",
        "",
    ],
)
def test_a_value_that_is_not_a_role_arn_is_rejected(arn: str) -> None:
    assert not ROLE_ARN_PATTERN.match(arn)


def test_the_role_extraction_never_puts_the_value_in_its_message() -> None:
    """The ARN carries the account ID, so a failure message quoting the value
    would leak it to the terminal on exactly the run that went wrong."""
    helper = AUDIT_CODE[AUDIT_CODE.index("function Get-RoleNameFromArn") :]
    helper = helper[: helper.index("function Get-AsArray")]

    for line in helper.splitlines():
        if "Stop-Run" not in line:
            continue
        assert "$Arn" not in line, (
            f"the failure message carries the ARN: {line.strip()}"
        )


def test_the_configuration_stage_never_prints_or_writes_the_role_arn() -> None:
    stage = FUNCTION_BODIES["Get-FunctionRoleName"]

    for line in stage.splitlines():
        emits = (
            "Write-Host" in line
            or "Write-Step" in line
            or "Write-Detail" in line
            or "Add-Finding" in line
            or "$lines.Add" in line
        )
        if emits:
            assert "$roleArn" not in line, f"prints the role ARN: {line.strip()}"

    # It is used for exactly one thing: deriving the name.
    uses = [line for line in stage.splitlines() if "$roleArn" in line]
    assert len(uses) == 2, f"unexpected uses of the role ARN: {uses}"


def test_no_secret_value_can_enter_the_process() -> None:
    """Three independent controls, all of which must be present: the read is
    forbidden by name, it is absent from the allow-list, and no query may name the
    payload fields even on an allow-listed call."""
    for operation in ("get-secret-value", "batch-get-secret-value"):
        assert f"secretsmanager:{operation}" in FORBIDDEN_OPERATIONS
        assert f"secretsmanager:{operation}" not in READ_ONLY_OPERATIONS

    fields = parse_list_literal("ForbiddenQueryFields")
    assert "SecretString" in fields
    assert "SecretBinary" in fields

    # describe-secret returns metadata only, and only two named fields are asked
    # for. Neither is the value.
    assert "'--query', '{Arn:ARN,KmsKeyId:KmsKeyId}'" in AUDIT_CODE
    assert "SecretString" not in AUDIT_CODE.replace("'SecretString',", "")


# ---------------------------------------------------------------------------
# The runtime fixture harness.
#
# Everything above is a static read. That is what it can be: this host has no
# PowerShell interpreter, so no test here can prove the script *behaves*. Both
# administrator failures were behavioural, and both got as far as a live IAM
# audit before anyone saw them.
#
# scripts/test-audit-lambda-execution-role-runtime.ps1 is the missing half. It
# runs the real audit, on the administrator's own PowerShell, against a fake AWS
# CLI and deterministic fixtures. This section cannot run it either -- what it can
# do, and does, is prove the harness is isolated: that it cannot reach the real
# AWS CLI, cannot read a secret, cannot write into the checkout, and cannot leave
# its sandbox behind.
# ---------------------------------------------------------------------------

RUNTIME = REPO_ROOT / "scripts" / "test-audit-lambda-execution-role-runtime.ps1"
RUNTIME_TEXT = RUNTIME.read_text(encoding="utf-8")
RUNTIME_CODE = executable_lines(RUNTIME_TEXT)
RUNTIME_FLAT = normalise(RUNTIME_TEXT)

#: The shim's body, read out of the here-string it is stored in.
FAKE_CLI = re.search(r"\$FakeAwsShim = @'\n(.*?)\n'@", RUNTIME_TEXT, re.DOTALL)


def runtime_list_literal(name: str) -> list[str]:
    match = re.search(
        r"\$" + re.escape(name) + r"\s*=\s*@\((.*?)\n\)", RUNTIME_TEXT, re.DOTALL
    )
    assert match, f"${name} not found in the harness"
    return re.findall(r"'([^']+)'", match.group(1))


def test_the_runtime_harness_exists_and_is_substantial() -> None:
    assert RUNTIME.exists(), "the runtime harness is missing"
    assert len(RUNTIME_CODE.splitlines()) > 200


def test_the_harness_runs_under_strict_mode_on_both_hosts() -> None:
    """The harness has to be at least as strict as what it tests, and it has to
    run where the administrator is. A harness that only worked on PowerShell 7
    would have passed both failures this exists to catch."""
    assert "Set-StrictMode -Version Latest" in RUNTIME_CODE
    assert "Windows PowerShell 5.1 and PowerShell 7" in RUNTIME_FLAT


def test_the_harness_explains_why_erroractionpreference_is_not_stop() -> None:
    assert "NativeCommandError" in RUNTIME_TEXT


# --- Isolation: it cannot reach the real AWS CLI ----------------------------


def test_the_harness_writes_a_fake_cli_and_puts_it_first_on_path() -> None:
    """This is the isolation mechanism, and it is the whole basis of the claim
    that no AWS call is made: `aws` is resolved through PATH, so a fake `aws`
    ahead of everything else is what the audit finds."""
    assert "$FakeAwsShim" in RUNTIME_CODE
    assert "'aws.cmd'" in RUNTIME_CODE
    assert "Set-ProcessEnvironment -Name 'PATH'" in RUNTIME_CODE

    # Prepended, not appended: appending would let a real aws win.
    prepend = re.search(
        r"Set-ProcessEnvironment -Name 'PATH' -Value \(\$binDir \+", RUNTIME_CODE
    )
    assert prepend, "the fake CLI directory is not prepended to PATH"


def test_the_harness_never_invokes_a_real_aws_executable() -> None:
    """The harness itself must not call aws. The only thing it runs is the audit
    script, as a child process, and the audit reaches the fake CLI through PATH."""
    assert "Invoke-Native" not in RUNTIME_CODE
    assert "aws.exe" not in RUNTIME_TEXT
    assert not re.search(r"&\s*'?aws'?\s", RUNTIME_CODE)

    invocations = re.findall(r"^\s*\$captured = & (\S+)", RUNTIME_CODE, re.MULTILINE)
    assert invocations == ["$HostPath"], (
        f"the harness runs something other than a PowerShell host: {invocations}"
    )


def test_the_harness_clears_aws_credentials_for_the_child() -> None:
    """Belt and braces. If some path this harness did not anticipate reached a real
    CLI, it would find no credentials, no profile, no config file, and no instance
    metadata to fall back on."""
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
    ):
        assert f"Set-ProcessEnvironment -Name '{name}' -Value ''" in RUNTIME_CODE, (
            f"{name} is not cleared"
        )

    assert "-Name 'AWS_EC2_METADATA_DISABLED' -Value 'true'" in RUNTIME_CODE
    assert "'no-such-aws-config'" in RUNTIME_CODE
    assert "'no-such-aws-credentials'" in RUNTIME_CODE


def test_every_environment_variable_the_harness_touches_is_restored() -> None:
    """A harness that leaked a modified PATH or TEMP into the administrator's
    session would be a worse problem than the bug it found."""
    touched = set(runtime_list_literal("environmentNames"))

    assigned = set(
        re.findall(r"Set-ProcessEnvironment -Name '([A-Z_]+)'", RUNTIME_CODE)
    )
    unmanaged = assigned - touched
    assert not unmanaged, f"changed but never restored: {sorted(unmanaged)}"

    assert "PATH" in touched
    assert "TEMP" in touched
    restore = RUNTIME_CODE[RUNTIME_CODE.index("finally {") :]
    assert "foreach ($name in $environmentNames)" in restore


def test_the_fake_cli_refuses_both_secret_read_operations() -> None:
    """The audit refuses these before starting a process. The fake CLI refuses them
    again and records the attempt, so a run that somehow tried is visible in the
    harness output rather than being merely improbable."""
    assert FAKE_CLI, "the fake CLI body is not where this test expects it"
    shim = FAKE_CLI.group(1)

    assert 'if /I "%OPERATION%"=="get-secret-value" goto breach' in shim
    assert 'if /I "%OPERATION%"=="batch-get-secret-value" goto breach' in shim
    assert "exit /b 254" in shim

    # And the harness fails the run if the breach log ever appears.
    assert "a secret-value read was attempted" in RUNTIME_TEXT


def test_the_fake_cli_never_reads_the_query_it_was_given() -> None:
    """cmd.exe splits arguments on commas, so a shim that parsed the JMESPath query
    would be depending on tokenisation this harness cannot control. It stops at the
    service and the operation, which contain no delimiter."""
    assert FAKE_CLI
    shim = FAKE_CLI.group(1)

    assert "--query" not in shim
    assert "%*" not in shim, "forwarding the whole command line reintroduces the risk"
    assert "goto ready" in shim


def test_the_fake_cli_fails_closed_on_an_unexpected_call() -> None:
    """A call with no fixture must fail rather than return an empty document that
    the audit would parse as a policy with no statements."""
    assert FAKE_CLI
    shim = FAKE_CLI.group(1)

    assert "goto nofixture" in shim
    assert "exit /b 253" in shim
    assert "exit /b 252" in shim


def test_the_harness_asserts_every_aws_call_reached_the_fake_cli() -> None:
    """The strongest isolation statement the harness can make: each scenario knows
    exactly how many calls the audit should make, and a call that resolved to
    anything else would leave the log short."""
    assert "GG_FAKE_AWS_CALLLOG" in RUNTIME_CODE
    assert "ExpectedCalls" in RUNTIME_CODE
    assert "fake-CLI calls, logged" in RUNTIME_TEXT

    counts = [
        int(value) for value in re.findall(r"ExpectedCalls\s*=\s*(\d+)", RUNTIME_CODE)
    ]
    assert len(counts) == 9, f"expected nine scenarios to assert a count, got {counts}"
    assert all(count > 0 for count in counts)


# --- Isolation: it writes nothing into the repository -----------------------


def test_the_sandbox_is_created_under_the_system_temp_directory() -> None:
    assert "[System.IO.Path]::GetTempPath()" in RUNTIME_CODE
    assert "gg-phase1g-runtime-" in RUNTIME_CODE
    assert "[System.Guid]::NewGuid()" in RUNTIME_CODE


def test_the_sandbox_is_checked_against_the_repository_before_anything_is_written() -> (
    None
):
    """The same guard the audit applies to its review directory, applied earlier:
    before the sandbox is created, not after it is populated."""
    guard = RUNTIME_CODE.index("$resolvedSandbox.StartsWith($resolvedRepo")
    first_write = RUNTIME_CODE.index("New-Item -ItemType Directory")

    assert guard < first_write, "the sandbox is created before it is checked"


def test_the_harness_writes_nothing_next_to_itself_or_in_the_repository() -> None:
    """Every write target is built from $sandbox. A Join-Path against $PSScriptRoot
    or $repoRoot would put fixtures or logs in the checkout."""
    for line in RUNTIME_CODE.splitlines():
        if "Write-TextFile" not in line and "New-Item" not in line:
            continue
        assert "$PSScriptRoot" not in line, f"writes next to the script: {line.strip()}"
        assert "$repoRoot" not in line, f"writes into the repository: {line.strip()}"

    # $repoRoot is read for two reasons only: the guard above, and the sweep that
    # checks no generated review landed in the checkout.
    uses = [line.strip() for line in RUNTIME_CODE.splitlines() if "$repoRoot" in line]
    assert len(uses) == 3, f"unexpected uses of the repository root: {uses}"


def test_the_harness_sweeps_the_repository_for_generated_reviews() -> None:
    """Not a substitute for the guards above -- a check that they worked."""
    assert "generated review(s) landed in the checkout" in RUNTIME_TEXT
    assert "phase1g-execution-role-audit-*.md" in RUNTIME_CODE


def test_the_sandbox_is_removed_in_a_finally_block() -> None:
    """Whether the run passes, fails, or throws. A harness that only cleaned up on
    success would litter the temp directory on exactly the runs someone re-runs."""
    finally_block = RUNTIME_CODE[RUNTIME_CODE.index("finally {") :]

    assert "Remove-Item -LiteralPath $sandbox -Recurse -Force" in finally_block


def test_the_harness_has_no_cleanup_outside_the_finally_block() -> None:
    """One removal, in the one place that always runs."""
    removals = re.findall(r"Remove-Item[^\n]*\$sandbox", RUNTIME_CODE)

    assert len(removals) == 1, f"expected one sandbox removal, found {removals}"


# --- What the harness proves about the audit -------------------------------

#: The scenarios the task requires, keyed by the letter each is labelled with.
#:
#: G was added after the first successful live audit. The six before it all
#: exercised paths where the terminal and the review file agreed, so none of them
#: could have caught a finding that reached one and not the other.
REQUIRED_SCENARIOS = {
    "A": "clean expected role",
    "B": "zero attached managed policies",
    "C": "multiple attached managed policies",
    "D": "function configuration missing State",
    "E": "function configuration with a null Role",
    "F": "secret grant on every secret",
    "G": "inline policy under an unrecognised name",
    "H": "zero inline policies",
    "I": "several unrecognised inline policies",
}


def harness_scenario_names() -> list[str]:
    """Scenario labels only.

    Anchored on an indented bare ``Name`` key, so ``$FixtureSecretName = '...'``
    and its siblings at the top of the file are not mistaken for scenarios.
    """
    return re.findall(r"^\s+Name\s+=\s*'([^']+)'", RUNTIME_CODE, re.MULTILINE)


def harness_scenario_blocks() -> dict[str, str]:
    """Each scenario's declaration, keyed by its label.

    Split on the ``$scenarios.Add(@{`` that opens every one, so a rule can be
    applied to every scenario rather than to a literal line that happens to
    repeat. Counting identical lines silently stops covering any scenario that
    words its assertions differently.
    """
    blocks: dict[str, str] = {}

    for chunk in RUNTIME_CODE.split("$scenarios.Add(@{")[1:]:
        match = re.search(r"Name\s+=\s*'([^']+)'", chunk)
        assert match, f"a scenario block has no Name: {chunk[:120]}"
        blocks[match.group(1)] = chunk

    return blocks


def test_the_scenario_block_split_matches_the_declared_names() -> None:
    """Guards the splitter itself: every rule driven off it would pass on air if
    it silently found nothing."""
    assert sorted(harness_scenario_blocks()) == sorted(harness_scenario_names())


def test_the_harness_declares_exactly_the_required_scenarios() -> None:
    names = harness_scenario_names()

    assert len(names) == len(REQUIRED_SCENARIOS), f"scenarios found: {names}"

    for letter, description in REQUIRED_SCENARIOS.items():
        expected = f"{letter}. {description}"
        assert expected in names, f"missing scenario: {expected}"


def test_the_clean_scenario_reaches_the_end_and_writes_a_review() -> None:
    """Scenario A is the one that would have caught both administrator failures:
    it runs every stage, with one attached policy and one inline policy, and
    requires a review at the end."""
    block = RUNTIME_CODE[RUNTIME_CODE.index("'A. clean expected role'") :]
    block = block[: block.index("'B. zero attached")]

    assert "ExpectedExit   = 0" in block
    assert "ExpectReview   = $true" in block
    assert "Audit complete. Nothing was changed." in block
    assert "**Overall: PASS**" in block


def test_both_policy_lists_get_the_zero_one_and_many_treatment() -> None:
    """The rule B and C establish for attached policies, applied to the inline
    list too.

    It had it at the unit level -- ``test_inline_policies_normalise_for_zero_one
    _and_many`` -- but every *runtime* scenario fed the audit exactly one inline
    policy, so two branches had never actually executed: the empty list, which
    records a REVIEW of its own, and a list long enough for one stage to record
    more than one finding. Both were converted by the single-collection rewrite,
    and a converted branch that never runs is the shape of the last three
    failures in this phase.
    """
    blocks = harness_scenario_blocks()

    def override_of(key: str) -> dict[str, str]:
        """Each scenario's override of one fixture list, by scenario name.

        Sliced from the fixture key to ``ExpectedExit``, the field that always
        follows the Fixtures block, rather than by matching the quoting. Scenario
        C uses a here-string and the others use ordinary quotes, and a pattern
        that understood only one of those would quietly find nothing.
        """
        found = {}
        for name, block in blocks.items():
            if f"'{key}'" not in block:
                continue
            body = block[block.index(f"'{key}'") + len(key) + 2 :]
            found[name] = body[: body.index("ExpectedExit")]
        return found

    for key, label in (
        ("iam_list-attached-role-policies", "attached managed"),
        ("iam_list-role-policies", "inline"),
    ):
        overrides = override_of(key)
        assert overrides, f"no scenario overrides the {label} policy list at all"

        empty = [n for n, body in overrides.items() if re.search(r"=\s*'\[\]'", body)]
        assert empty, f"no scenario feeds zero {label} policies"

        several = [n for n, body in overrides.items() if "},{" in body or '","' in body]
        assert several, f"no scenario feeds several {label} policies"


def test_the_many_inline_scenario_records_more_than_one_finding() -> None:
    """The only scenario in which a single stage records two findings, which is
    exactly what the single-collection rewrite changed: the collection must
    accumulate the second rather than replace the first."""
    block = harness_scenario_blocks()["I. several unrecognised inline policies"]

    # Its own fixture, not just its expectations. Asserting only on the expected
    # counts would keep passing if the fixture were collapsed back to one policy,
    # leaving a scenario that asserts two findings against a role that has one.
    fixture = block[block.index("'iam_list-role-policies'") :]
    fixture = fixture[: fixture.index("ExpectedExit")]
    assert fixture.count("GracefulGutAI-") == 2, f"not a two-policy fixture: {fixture}"

    assert "FAIL: 0. REVIEW: 2." in block, "the review does not count two findings"
    assert block.count("Inline policy is not part of the documented setup") == 4, (
        "both findings are not asserted in both the terminal and the review"
    )
    assert "ExpectedExit   = 0" in block, "two REVIEWs is still not a failed run"


#: The two "the role is missing something" branches, and the finding each records.
#: Both printed without recording until the single-collection rewrite.
ZERO_POLICY_BRANCHES = (
    ("Get-AttachedPolicyDocuments", "No managed policy is attached"),
    ("Get-InlinePolicyDocuments", "No inline policy is present"),
)


@pytest.mark.parametrize(("function", "title"), ZERO_POLICY_BRANCHES)
def test_an_empty_policy_list_records_a_finding_rather_than_printing_one(
    function: str, title: str
) -> None:
    """Why a zero-policy scenario must expect REVIEW and not PASS.

    These two branches are the reason, and asserting on them is what keeps the
    harness expectation and the script from drifting apart again: if either ever
    goes back to printing without recording, this fails here rather than on an
    administrator's machine.
    """
    body = FUNCTION_BODIES[function]

    assert f"Add-Finding -Severity 'Review' -Title '{title}'" in body, (
        f"{function} does not record '{title}' as a finding"
    )


def test_no_zero_policy_scenario_expects_an_overall_pass() -> None:
    """Scenario B asserted ``**Overall: PASS**`` and failed on AJ's 2026-07-30
    harness run — the one failed assertion in the whole run.

    The expectation was correct for the script it was written against: the
    zero-policy branch printed a REVIEW and recorded nothing, so the review file
    really did say PASS. That made B a scenario that *pinned the
    terminal/review disagreement in place* rather than catching it, and it was
    the only one whose fixture exposed that disagreement without an unrecognised
    policy name being involved.

    A role that is missing a policy the audit expects produces a REVIEW in both
    artefacts or the two do not agree, which is the whole point of the rewrite.
    """
    blocks = harness_scenario_blocks()
    empty_list = re.compile(r"'iam_list-(?:attached-)?role-policies'\s*=\s*'\[\]'")

    zero = {name: block for name, block in blocks.items() if empty_list.search(block)}
    assert len(zero) == 2, f"expected the two zero-policy scenarios, got {sorted(zero)}"

    for name, block in zero.items():
        required = block[block.index("ReviewContains") :]
        prohibited = block[block.index("MustNotContain") :]
        prohibited = prohibited[: prohibited.index("ReviewContains")]

        assert "**Overall: PASS**" not in block, (
            f"{name} feeds an empty policy list and still expects an overall PASS"
        )
        assert "**Overall: REVIEW**" in required, f"{name} does not expect a REVIEW"
        assert "FAIL: 0. REVIEW: 1." in required, (
            f"{name} does not require the finding to be counted in the review"
        )
        assert "'Execution role audit: REVIEW'" in block, (
            f"{name} does not require the REVIEW verdict in the terminal"
        )
        assert "'Execution role audit: PASS'" in prohibited, (
            f"{name} tolerates a PASS verdict in the terminal"
        )
        assert "ExpectedExit   = 0" in block, f"{name} is not a completed run"


@pytest.mark.parametrize(
    ("scenario", "following"),
    [
        ("'B. zero attached managed policies'", "'C. multiple attached"),
        ("'C. multiple attached managed policies'", "'D. function configuration"),
    ],
)
def test_the_collection_scenarios_complete(scenario: str, following: str) -> None:
    """Zero and many, both expected to finish. The first administrator failure was
    a one-item collection and the zero-item path was broken the same way, so a
    harness that only covered "one" would not have caught it."""
    block = RUNTIME_CODE[RUNTIME_CODE.index(scenario) :]
    block = block[: block.index(following)]

    assert "ExpectReview   = $true" in block
    assert "ExpectedExit   = 0" in block


@pytest.mark.parametrize(
    ("scenario", "following", "field"),
    [
        (
            "'D. function configuration missing State'",
            "'E. function configuration",
            "State",
        ),
        ("'E. function configuration with a null Role'", "'F. secret grant", "Role"),
    ],
)
def test_the_incomplete_scenarios_fail_closed_and_write_no_review(
    scenario: str, following: str, field: str
) -> None:
    """The second failure's territory. Each names its own missing field, each exits
    1, and neither may write a review -- a review describing an audit that did not
    finish reads as a completed one."""
    block = RUNTIME_CODE[RUNTIME_CODE.index(scenario) :]
    block = block[: block.index(following)]

    assert "ExpectedExit   = 1" in block
    assert "ExpectReview   = $false" in block
    assert f"did not include the required field '{field}'" in block
    assert "Audit did not complete. No review was written." in block


def test_the_two_incomplete_scenarios_use_different_absent_shapes() -> None:
    """One omits the key, the other sets it to null. A JMESPath query for a field
    the response does not carry returns null rather than omitting it, so both
    shapes occur in practice and both must fail."""
    block = RUNTIME_CODE[
        RUNTIME_CODE.index("'D. function configuration missing State'") :
    ]
    missing_key = block[: block.index("'E. function configuration")]
    nulled = block[block.index("'E. function configuration") :]
    nulled = nulled[: nulled.index("'F. secret grant")]

    assert '"State"' not in missing_key, "scenario D still supplies State"
    assert '"Role":null' in nulled, "scenario E does not null the Role"


def test_the_incomplete_scenarios_reject_the_old_failure_message() -> None:
    """A rerun against the old script would abort with the field-count message.
    Asserting its absence is how the harness proves which script it ran."""
    block = RUNTIME_CODE[
        RUNTIME_CODE.index("'D. function configuration missing State'") :
    ]
    block = block[: block.index("'E. function configuration")]

    assert "returned fewer fields than expected" in block


def test_the_failing_scenario_completes_and_still_writes_a_review() -> None:
    """The distinction the review gate turns on: a *finding* is a completed audit
    and gets a review with exit 2. An *incomplete* audit gets neither."""
    block = RUNTIME_CODE[RUNTIME_CODE.index("'F. secret grant on every secret'") :]

    assert "ExpectedExit   = 2" in block
    assert "ExpectReview   = $true" in block
    assert "**Overall: FAIL**" in block


def test_the_harness_checks_the_written_review_for_leaks() -> None:
    """The audit scans the review before writing it. The harness checks the file
    that actually landed, which is a different statement and a stronger one."""
    assert "the written review leaked" in RUNTIME_TEXT
    assert "$PlaceholderAccountId, $FixtureSecretName" in RUNTIME_CODE


def test_the_harness_checks_the_terminal_output_for_the_account_id() -> None:
    assert "the account ID reached the terminal" in RUNTIME_TEXT


def test_the_harness_runs_the_audit_as_a_child_process() -> None:
    """The audit ends in `exit`, which would terminate the harness on the first
    scenario if it were dot-sourced -- and the exit code is what every scenario
    asserts."""
    assert "-File', $ScriptPath" in RUNTIME_CODE
    assert "$LASTEXITCODE" in RUNTIME_CODE
    assert "Get-Process -Id $PID" in RUNTIME_CODE
    assert "'-NoOpen'" in RUNTIME_CODE, "the audit would open an editor per scenario"


def test_the_harness_runs_the_same_powershell_host_it_was_started_with() -> None:
    """Testing the audit under PowerShell 7 while the administrator runs Windows
    PowerShell 5.1 would have passed both failures."""
    helper = RUNTIME_CODE[RUNTIME_CODE.index("function Get-PowerShellHostPath") :]
    helper = helper[: helper.index("function Invoke-ChildAudit")]

    assert "(Get-Process -Id $PID).Path" in helper
    assert "$PSHOME" in helper, "there is no fallback if the process path is empty"


def test_the_harness_exits_nonzero_when_any_scenario_fails() -> None:
    assert "$exitCode = 1" in RUNTIME_CODE
    assert "exit $exitCode" in RUNTIME_CODE

    tail = RUNTIME_CODE[RUNTIME_CODE.rindex("if ($script:Failures.Count -eq 0)") :]
    assert "$exitCode = 1" in tail, "a failure does not change the exit code"


def test_the_harness_makes_no_mutating_aws_call_of_any_kind() -> None:
    """The audit's allow-list gate applies to the audit. This checks the harness
    itself never names a mutating operation, in a fixture or anywhere else."""
    for prefix in MUTATION_PREFIXES:
        for match in re.findall(rf"\b{re.escape(prefix)}[a-z-]*\b", RUNTIME_CODE):
            # 'set-' appears as Set-Item-style cmdlet names and 'remove-' as
            # Remove-Item; neither is an AWS operation. AWS operations only ever
            # appear in this harness as a fixture filename, and those are reads.
            assert not match.startswith(("create-secret", "put-", "attach-")), (
                f"the harness names a mutating AWS operation: {match}"
            )

    for operation in ("put-role-policy", "attach-role-policy", "update-function"):
        assert operation not in RUNTIME_CODE, f"the harness names {operation}"


def test_the_harness_fixtures_only_use_the_placeholder_account_id() -> None:
    """The harness is in PHASE1G_FILES, so the repository-wide scans already reject
    a real identifier. This states the positive form: the fixtures use the
    documented placeholder and nothing else."""
    for match in re.findall(r"\b\d{12}\b", RUNTIME_TEXT):
        assert match in PLACEHOLDER_ACCOUNT_IDS, f"non-placeholder account ID: {match}"

    assert "$PlaceholderAccountId = '123456789012'" in RUNTIME_CODE
    assert "$FixtureSecretName = 'fixture-secret'" in RUNTIME_CODE


def test_the_harness_secret_name_is_obviously_not_a_live_identifier() -> None:
    """The audit takes the secret identifier as a mandatory parameter so it is
    never committed. A harness that hardcoded the real one would undo that."""
    assert "fixture-secret" in RUNTIME_CODE
    assert not re.search(r"graceful-gut-ai/[a-z0-9/_-]+", RUNTIME_TEXT)


def test_the_harness_fixtures_cover_every_allow_listed_read() -> None:
    """A fixture missing for an allow-listed read means the fake CLI returns 253
    and the scenario fails for the wrong reason."""
    fixtures = set(re.findall(r"\$fixtures\['([a-z-]+_[a-z-]+)'\]", RUNTIME_CODE))
    expected = {pair.replace(":", "_") for pair in READ_ONLY_OPERATIONS}

    assert fixtures == expected, (
        f"fixture set does not match the allow-list: "
        f"missing {sorted(expected - fixtures)}, extra {sorted(fixtures - expected)}"
    )


def test_the_fixtures_keep_records_and_collections_distinct() -> None:
    """The fixtures have to reproduce the shape the CLI returns, or the harness
    would prove nothing about the failure it exists to catch: a fixed record is a
    JSON object and the two collections are JSON arrays."""
    defined = set(re.findall(r"\$fixtures\['([a-z-]+_[a-z-]+)'\]", RUNTIME_CODE))

    for pair in COLLECTION_QUERIES:
        key = pair.replace(":", "_")
        assert key in defined, f"no fixture for the collection read {pair}"

    # The attached-policy fixture is an array of named rows -- both sides of the
    # split in one payload.
    assert '[{"PolicyName":"AWSLambdaBasicExecutionRole"' in RUNTIME_TEXT
    assert '["GracefulGutAI-SecretAccess"]' in RUNTIME_TEXT

    # And the function configuration fixture is an object with named fields.
    assert '{`"State`":`"Active`",`"LastUpdateStatus`":' in RUNTIME_TEXT


def test_the_harness_does_not_shadow_the_audit_as_the_thing_being_tested() -> None:
    """It runs the tracked script from its own directory. A harness carrying its
    own copy of the audit would pass while the real one stayed broken."""
    assert "Join-Path $PSScriptRoot 'audit-lambda-execution-role.ps1'" in RUNTIME_CODE
    assert "Audit script not found next to this harness" in RUNTIME_TEXT


# ---------------------------------------------------------------------------
# The review renderer -- the third administrator failure
# ---------------------------------------------------------------------------
#
# The third runtime harness run reached every correct verdict and then died in
# review generation with "Argument types do not match". That message is a .NET
# method-binding failure: an overloaded method was handed an argument whose
# runtime type was not the one the chosen overload takes. Under Windows
# PowerShell 5.1 the usual source in a script this shape is a collection -- a
# generic List, or an array inside the [psobject] wrapper that -NoEnumerate
# produces -- crossing a function boundary and then being formatted, joined, or
# passed to an overloaded .NET call.
#
# The harness itself exonerates most of the candidates. It runs on the same host
# and, before any scenario starts, already calls [System.IO.Path]::GetFullPath,
# String.StartsWith(String, StringComparison), List[string].Add, and
# [System.IO.File]::WriteAllText with a New-Object UTF8Encoding -- all of which
# worked. What it never did was join a *generic List* or index an ordered
# dictionary reached through a [psobject]-wrapped property, and both of those
# were unique to the audit's review path.
#
# So the correction is not a guess at one line. Every collection the renderer
# touches is converted to a plain, explicitly typed array before a single line is
# rendered, and the rules below hold that shape in place.

#: New-ReviewFile is the last function in the file, so its split body runs on
#: into the script body. Cut it back at the main-body anchor.
REVIEW_BODY = FUNCTION_BODIES["New-ReviewFile"]
REVIEW_BODY = REVIEW_BODY[: REVIEW_BODY.index(MAIN_ANCHOR)]

#: The review path is the renderer plus the main-body section that calls it.
REVIEW_MAIN = main_body(AUDIT_CODE)
REVIEW_MAIN = REVIEW_MAIN[REVIEW_MAIN.index("Write-Section 'Review'") :]
REVIEW_PATH = REVIEW_BODY + REVIEW_MAIN


def test_the_review_path_scan_is_not_vacuous() -> None:
    """Both halves must actually be found, or every rule below passes on air."""
    assert "$reviewLines" in REVIEW_BODY
    assert "WriteAllText" in REVIEW_BODY
    assert "New-ReviewFile -Permissions" in REVIEW_PATH
    assert len(REVIEW_BODY.splitlines()) > 40


def test_the_final_review_lines_are_an_explicit_string_array() -> None:
    """Requirement 5. The collection that is joined is a [string[]], and each of
    its elements was converted to [string] one at a time on the way in."""
    assert re.search(r"\[string\[\]\]\s*\$reviewLines\s*=\s*@\(", REVIEW_BODY), (
        "the review lines are not stored as an explicit [string[]]"
    )
    assert re.search(
        r"\$lines\s*\|\s*ForEach-Object\s*\{\s*\[string\]\$_\s*\}", REVIEW_BODY
    ), "review lines are not converted to [string] individually"


def test_the_review_text_is_produced_with_the_join_operator() -> None:
    """PowerShell's -join is not a .NET call and has no overloads to resolve
    between, which is the entire reason it is used here."""
    assert re.search(
        r"\[string\]\$content\s*=\s*\$reviewLines\s+-join\s+\[Environment\]::NewLine",
        REVIEW_BODY,
    ), "the review text is not joined from the normalised [string[]]"


def test_no_generic_list_is_joined_in_the_review_path() -> None:
    """The shape that failed: ``$lines -join ...`` where ``$lines`` is a
    ``List[string]``. The join receiver must be the normalised array."""
    joins = re.findall(r"(\$[A-Za-z_][A-Za-z0-9_]*)\s+-join\b", REVIEW_PATH)

    assert joins, "the review path no longer joins anything"
    for receiver in joins:
        assert receiver == "$reviewLines", (
            f"{receiver} is joined in the review path; only $reviewLines may be"
        )


def test_string_join_is_not_used_anywhere_in_the_script() -> None:
    """[string]::Join has four overloads -- string[], object[], IEnumerable<T>,
    and the ranged one -- and picking between them with a collection whose
    runtime type is not verified is exactly the failure being corrected."""
    assert "[string]::Join" not in AUDIT_CODE
    assert "[System.String]::Join" not in AUDIT_CODE


def test_no_generic_list_is_wrapped_in_an_array_subexpression_in_the_review() -> None:
    """``@($genericList)`` cannot see through a [psobject] wrapper -- that is what
    broke the second administrator run -- so the review path must not use it.

    Every generic List built in the renderer is converted with an explicit cast
    or with .ToArray() instead.
    """
    generic_lists = set(
        re.findall(
            r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*New-Object\s+System\.Collections\.Generic\.List",
            REVIEW_PATH,
        )
    )

    assert generic_lists, "the scan found no generic List to check"
    for name in generic_lists:
        assert f"@({name})" not in REVIEW_PATH, f"@({name}) survives in the review path"


def test_the_stage_results_are_normalised_before_anything_is_rendered() -> None:
    """Requirement 6. Each collection the renderer touches is turned into a plain
    [object[]] once, at the top, and nothing downstream sees the original.
    """
    pattern = r"\$policyRows\s*=\s*\[object\[\]\]" + re.escape("$Policies") + r"\s*\}"
    assert re.search(pattern, REVIEW_BODY), (
        "$policyRows is not normalised from $Policies with an [object[]] cast"
    )

    # The findings are copied element by element out of the script-scoped generic
    # List and handed on as a plain array, for the same 5.1 binding reason.
    assert (
        "foreach ($finding in $script:AuditFindings) { $findingList.Add($finding) }"
        in (REVIEW_BODY)
    )
    assert "[object[]]$allFindings = $findingList.ToArray()" in REVIEW_BODY


def test_the_renderer_takes_no_findings_verdict_or_severity_as_a_parameter() -> None:
    """The defect behind the terminal/review disagreement. The renderer used to be
    handed $Trust and $Permissions and to read .Findings and .Severity off them,
    so a finding recorded by any other stage could not reach the file. It now
    reads the one collection and calls the same two functions the terminal did.
    """
    # Cut at the first statement after the param block, not at the first ')' --
    # that one closes [Parameter(...)] on the very first parameter and would make
    # this rule pass without reading the signature at all.
    signature = REVIEW_BODY[: REVIEW_BODY.index("if (-not $script:StagesCompleted)")]

    assert signature.count("[Parameter(Mandatory = $true)]") == 4, (
        f"the renderer signature is not the expected four parameters:\n{signature}"
    )
    for gone in ("$Trust", "$Verdict"):
        assert gone not in signature, f"{gone} is still a renderer parameter"

    assert "$Trust.Findings" not in REVIEW_BODY
    assert "$Permissions.Findings" not in REVIEW_BODY
    assert "$Permissions.Severity" not in REVIEW_BODY
    assert "$overallSeverity = Get-OverallSeverity" in REVIEW_BODY


def test_the_normalisers_handle_the_null_case_before_casting() -> None:
    """``[object[]]$null`` is $null, not an empty array, so the guard is what
    makes the zero case behave. Same lesson as Get-AsArray.

    Only $policyRows is cast from a parameter now, so it is the only one that can
    be handed a $null. The findings come from a List this script owns, which is
    created at startup and never reassigned, so it cannot be null to begin with.
    """
    assert "[object[]]$policyRows = @()" in REVIEW_BODY, (
        "$policyRows has no empty-array default"
    )
    assert "if ($null -ne $Policies)" in REVIEW_BODY


def test_the_ordered_dictionary_is_no_longer_indexed_in_the_review() -> None:
    """An OrderedDictionary exposes two Item accessors -- one Int32, one Object --
    and resolving between them through a [psobject]-wrapped property is a choice
    the renderer should not have to make. Its enumerator yields both halves."""
    assert "$Permissions.CategoryCounts[" not in REVIEW_BODY
    assert "$Permissions.CategoryCounts.Keys" not in REVIEW_BODY
    assert (
        "foreach ($entry in $Permissions.CategoryCounts.GetEnumerator())" in REVIEW_BODY
    )
    assert (
        '$lines.Add("| $([string]$entry.Key) | $([int]$entry.Value) |")' in REVIEW_BODY
    )


def test_the_classifier_still_owns_the_category_counts() -> None:
    """The correction is confined to rendering. The permission classifier still
    builds the ordered dictionary and still counts into it by key."""
    classifier = FUNCTION_BODIES["Test-PolicyStatements"]

    assert "$categoryCounts = [ordered]@{}" in classifier
    assert "$categoryCounts[$category]" in classifier


def test_no_format_operator_is_used_in_the_review_path() -> None:
    """Requirement 13. The -f operator and [string]::Format both bind through
    .NET overload resolution and both mis-bind a [psobject]-wrapped array. The
    renderer uses string interpolation, which does neither."""
    assert not re.search(r"['\")\]]\s+-f\s+", REVIEW_PATH), (
        "a -f format operation survives in the review path"
    )
    assert "::Format(" not in REVIEW_PATH


def test_every_interpolated_review_value_is_explicitly_typed() -> None:
    """A subexpression inside a review line must produce a [string] or an [int],
    never whatever the property happened to hold. ConvertTo-Classification is
    exempt: it returns one of three literals and nothing else."""
    untyped = []

    for line in REVIEW_BODY.splitlines():
        if "$lines.Add(" not in line:
            continue
        for expression in re.findall(r"\$\((.*?)\)(?=[^)]*\")", line):
            if expression.startswith("ConvertTo-Classification"):
                continue
            if expression.startswith("[string]") or expression.startswith("[int]"):
                continue
            untyped.append(line.strip())

    assert not untyped, "untyped interpolation in a review line:\n" + "\n".join(untyped)


def test_the_file_write_receives_explicitly_typed_arguments() -> None:
    """WriteAllText has a two-argument and a three-argument overload. Naming the
    type of all three arguments leaves nothing for the binder to decide."""
    assert (
        "[System.IO.File]::WriteAllText([string]$path, [string]$content, "
        "[System.Text.Encoding]$utf8NoBom)" in REVIEW_BODY
    )


def test_the_review_path_does_not_use_write_output_noenumerate() -> None:
    """Requirement 7. -NoEnumerate is what put the [psobject] wrapper into the
    collection path in the first place; it must not be the fix here."""
    assert "-NoEnumerate" not in REVIEW_PATH


def test_the_normalisation_is_explained_where_it_lives() -> None:
    """A reader who deletes a cast because it looks redundant reproduces the
    failure. The reason has to be next to the code, not only in a report.

    ``REVIEW_BODY`` is the comment-stripped copy, so the explanation is looked for
    in the raw text of the same function.
    """
    raw = AUDIT_TEXT[AUDIT_TEXT.index("function New-ReviewFile") :]
    raw = raw[: raw.index(MAIN_ANCHOR)]

    assert "Argument types do not match" in raw, (
        "the renderer does not name the failure it was rewritten for"
    )
    assert "overload" in raw.lower()
    assert "psobject" in raw.lower()


# --- The failure diagnostic -------------------------------------------------


def test_the_script_emits_a_diagnostic_when_a_run_dies() -> None:
    """Requirement 10. Two administrator runs were spent turning a bare exception
    message into a location. The third one should not have to be."""
    main = main_body(AUDIT_CODE)

    assert "Get-SafeDiagnostic -ErrorRecord $_" in main
    assert "function Get-SafeDiagnostic" in AUDIT_CODE


def test_the_diagnostic_names_the_stage_the_function_the_line_and_the_type() -> None:
    diagnostic = FUNCTION_BODIES["Get-SafeDiagnostic"]

    assert "$ErrorRecord.Exception.GetType().FullName" in diagnostic
    assert "$ErrorRecord.InvocationInfo.ScriptLineNumber" in diagnostic
    assert "$script:Stage" in diagnostic
    assert "$ErrorRecord.ScriptStackTrace" in diagnostic

    # The literal is split across two source lines, so the four facts are
    # checked individually rather than as one run of text.
    for fact in (
        "stage='$stage'",
        "function='$functionName'",
        "line=$line",
        "exception=$exceptionType",
    ):
        assert fact in diagnostic, f"the diagnostic does not carry {fact}"


def test_the_diagnostic_drops_anything_that_looks_like_a_path() -> None:
    """PowerShell renders a stack frame as "at <function>, <full path>: line n".
    Taking the frame verbatim would put an absolute user path in the output."""
    diagnostic = FUNCTION_BODIES["Get-SafeDiagnostic"]

    assert "'^at\\s+([^,]+)'" in diagnostic, "the frame is not split at the comma"
    assert "-notmatch '[\\\\/:]'" in diagnostic, (
        "a path-shaped frame name is not rejected"
    )


def test_the_diagnostic_is_masked_before_it_is_printed() -> None:
    """Belt and braces: every input is argued to be safe, and the whole line still
    goes through the masker."""
    diagnostic = FUNCTION_BODIES["Get-SafeDiagnostic"]

    assert "return (Hide-Sensitive -Text $diagnostic)" in diagnostic


def test_the_stage_is_recorded_only_where_a_stage_begins() -> None:
    """One writer. A stage name set in two places drifts from the truth."""
    writes = re.findall(r"\$script:Stage\s*=", AUDIT_CODE)

    assert len(writes) == 2, (
        f"expected an initialiser and one writer, found {len(writes)}"
    )
    assert "$script:Stage = 'startup'" in AUDIT_CODE
    assert "$script:Stage = $Title" in FUNCTION_BODIES["Write-Section"]


def test_every_stage_name_is_a_literal_in_this_script() -> None:
    """The diagnostic prints the stage, so the stage must never be a value read
    from AWS, an identifier, or a path."""
    titles = re.findall(r"Write-Section\s+'([^']+)'", AUDIT_CODE)

    assert len(titles) >= 9, f"only found {len(titles)} stages"
    for title in titles:
        assert re.fullmatch(r"[A-Za-z][A-Za-z ]*", title), (
            f"suspicious stage name: {title}"
        )


def test_the_harness_surfaces_and_checks_the_child_diagnostic() -> None:
    """Requirement 10, on the harness side: it lifts the diagnostic to the top of
    a failure report and fails the scenario if the line carries a path."""
    assert "$_ -match 'DIAGNOSTIC:'" in RUNTIME_CODE
    assert "the failure diagnostic carried a path" in RUNTIME_TEXT
    assert re.search(r"\[string\[\]\]\$diagnostics\s*=\s*@\(", RUNTIME_CODE)


def test_the_completed_scenarios_require_no_diagnostic_at_all() -> None:
    """The regression guard for this failure. A, B, C, F, and G reach correct
    verdicts and must then finish; the earlier runs reached correct verdicts and
    died in review generation, and if that recurs they print a diagnostic.

    Driven off ``ExpectReview = $true`` rather than off a literal MustNotContain
    line, so a scenario that lists more prohibited strings than the others -- as A
    and G both do -- is still held to the rule.
    """
    completed = {
        name: block
        for name, block in harness_scenario_blocks().items()
        if "ExpectReview   = $true" in block
    }

    assert len(completed) == 7, f"completed scenarios found: {sorted(completed)}"

    for name, block in completed.items():
        prohibited = block[block.index("MustNotContain") :]
        prohibited = prohibited[: prohibited.index(")")]
        assert "'DIAGNOSTIC:'" in prohibited, f"{name} tolerates a diagnostic"
        assert "'Audit did not complete'" in prohibited, (
            f"{name} tolerates an incomplete audit"
        )


def test_the_incomplete_scenarios_require_the_diagnostic() -> None:
    """D and E stop on purpose, so they must produce one -- otherwise the guard
    above could pass with the diagnostic never being emitted at all."""
    assert RUNTIME_CODE.count("\"DIAGNOSTIC: stage='Function'\"") == 2
