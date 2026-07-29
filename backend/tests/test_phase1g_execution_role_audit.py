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
    finding = AUDIT_CODE[AUDIT_CODE.index("function Write-Finding") :]
    finding = finding[: finding.index("function Write-Section")]

    assert "Hide-Sensitive" in finding, "finding text is printed unmasked"

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
    server-side for three fields, so Environment.Variables -- which carries
    GG_API_SECRET_ID -- never enters the process."""
    assert "'--query', '[State,LastUpdateStatus,Role]'" in AUDIT_CODE
    assert "Environment.Variables" not in AUDIT_CODE
    assert "Environment" in AUDIT_FLAT  # the reasoning is recorded


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


def test_the_expected_inline_policy_name_is_the_documented_one() -> None:
    """CLAUDE.md has an administrator create this inline policy with
    put-role-policy, so its presence is expected rather than a deviation."""
    assert "$ExpectedInlinePolicyName = 'GracefulGutAI-ReadApiKeySecret'" in AUDIT_CODE


def test_an_unexpected_inline_policy_is_flagged_for_review() -> None:
    inline = AUDIT_TEXT[AUDIT_TEXT.index("function Get-InlinePolicyDocuments") :]
    inline = inline[: inline.index("function Get-ActionCategory")]

    assert "not part of the documented setup" in inline


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
    write = main.index("New-ReviewFile -Trust")

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
    combiner = combiner[: combiner.index("function Write-Finding")]

    assert "'Fail'" in combiner
    assert "'Review'" in combiner
    fail = combiner.index("-contains 'Fail'")
    review = combiner.index("-contains 'Review'")
    assert fail < review, "Review would mask a Fail"


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


def ps_write_output_no_enumerate(value: object) -> object:
    """Model of ``Write-Output -NoEnumerate``: the collection crosses whole."""
    return value


def ps_count(value: object) -> int:
    """Model of ``.Count`` under ``Set-StrictMode -Version Latest``.

    A real collection has Count. A scalar object does not, and reading it raises
    the exact error the administrator saw.
    """
    if isinstance(value, list):
        return len(value)
    raise AttributeError("The property 'Count' cannot be found on this object.")


def broken_get_as_array(value: object) -> object:
    """The original normaliser: ``return @($Value)``. Defeated by the pipeline."""
    if value is None:
        return ps_pipeline_return([])
    return ps_pipeline_return(ps_array_subexpression(value))


def fixed_get_as_array(value: object) -> object:
    """The corrected normaliser: ``Write-Output -NoEnumerate @($Value)``."""
    if value is None:
        return ps_write_output_no_enumerate([])
    return ps_write_output_no_enumerate(ps_array_subexpression(value))


def call_site(value: object) -> object:
    """The corrected call-site pattern: ``@(Get-AsArray -Value $x)``."""
    return ps_array_subexpression(fixed_get_as_array(value))


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
    delivered = broken_get_as_array(["GracefulGutAI-ReadApiKeySecret"])

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
    assert ps_count(call_site(value)) == expected, f"attached policies: {label}"


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("zero", None, 0),
        ("one", ["GracefulGutAI-ReadApiKeySecret"], 1),
        ("many", ["GracefulGutAI-ReadApiKeySecret", "SomethingElse"], 2),
    ],
)
def test_inline_policies_normalise_for_zero_one_and_many(
    label: str, value: object, expected: int
) -> None:
    assert ps_count(call_site(value)) == expected, f"inline policies: {label}"


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
    assert ps_count(call_site(value)) == expected, f"statements: {label}"


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
    assert ps_count(call_site(value)) == expected, f"Action as {label}"


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
    assert ps_count(call_site(value)) == expected, f"Resource as {label}"


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
    assert ps_count(call_site(value)) == expected, f"Principal.Service as {label}"


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


def test_every_normaliser_call_site_is_wrapped() -> None:
    """The second, independent layer. Either layer alone fixes the one-item case,
    so a regression has to defeat both to reach an administrator."""
    unwrapped = []
    for line in AUDIT_CODE.splitlines():
        if "Get-AsArray -Value" not in line:
            continue
        if "@(Get-AsArray -Value" not in line:
            unwrapped.append(line.strip())

    assert not unwrapped, f"unwrapped normaliser call sites: {unwrapped}"


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
)


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

    # The scoping this exists for: $pair is a normalised array in one function
    # and a plain string in another.
    assert "$pair = @(Get-AsArray" in FUNCTION_BODIES["Get-AttachedPolicyDocuments"]
    assert '$pair = "${Service}:${Operation}"' in FUNCTION_BODIES["Invoke-AwsRead"]


def test_the_count_receiver_scan_finds_the_known_usages() -> None:
    """A scan that matched nothing would make the rule below vacuous."""
    receivers = count_receivers()

    assert len(receivers) >= 15, f"only found {len(receivers)} .Count usages"


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
            if re.search(r"^\s*" + re.escape(receiver) + r"\s*=[^=]", line)
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
