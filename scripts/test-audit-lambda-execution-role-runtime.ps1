<#
.SYNOPSIS
    Run audit-lambda-execution-role.ps1 against deterministic fixture data, with
    a fake AWS CLI. Makes no AWS call and changes nothing.

.DESCRIPTION
    The audit script has now failed twice on an administrator's machine, both
    times on PowerShell semantics rather than on anything about IAM:

      1. Get-AsArray returned a scalar whenever it was handed one item, so the
         one-attached-policy case died on `.Count`.
      2. The fix for that made a fixed-shape record arrive nested, so the
         function-configuration stage stopped with "returned fewer fields than
         expected".

    Both were caught by an administrator running the real thing against real IAM,
    which is the most expensive place to find them and the slowest to iterate on.
    Neither was caught by the Python suite, because a static test can prove a
    pattern is present and cannot prove PowerShell then behaves as expected --
    there is no PowerShell interpreter on the host that suite runs on.

    This harness closes that gap. It runs the audit end to end, on the
    administrator's own PowerShell, against fixtures that stand in for AWS. What
    it proves is exactly the class of thing that broke: that a fixed record parses
    into named fields, that a collection works at zero, one, and many, that an
    incomplete audit writes no review, and that a completed failing audit does.

    It is isolated by construction rather than by intention:

      * A fake `aws` command is written into a sandbox directory and that
        directory is prepended to PATH, so `aws` resolves to the fake one.
      * The fake refuses get-secret-value and batch-get-secret-value outright and
         records the attempt, so a run that tried would be visible rather than
         merely unlikely.
      * AWS credential and configuration environment variables are cleared for
        the child process and AWS_CONFIG_FILE is pointed at a path that does not
        exist, so a real CLI reached by some path could not authenticate anyway.
      * Every call the audit makes is logged, and each scenario asserts the exact
         number of calls. A call that escaped to something else would leave the
         log short.
      * The sandbox lives under the system temp directory. It is checked against
        the repository root before anything is created, and removed in a finally
        block whether the run passes, fails, or throws.

    Fixture data carries no real identifier: the account ID is the documented
    placeholder, the secret is named 'fixture-secret', and no live URL, ARN, or
    credential appears anywhere in this file.

.PARAMETER ShowOutput
    Print each scenario's full captured output, not only failing scenarios'.

.EXAMPLE
    .\scripts\test-audit-lambda-execution-role-runtime.ps1

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7. Windows only: the
    fake CLI is a .cmd shim, which is how `aws` is resolved on the machine this
    audit is run from.

    Read-only with respect to AWS. This harness never contacts AWS, never reads a
    secret, and never modifies a Lambda function, Function URL, IAM role, or
    policy. Exits 0 when every scenario passes and 1 when any scenario fails.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ShowOutput
)

Set-StrictMode -Version Latest

# Not 'Stop', for the same reason the audit script does not set it: a native
# command writing an ordinary line to stderr becomes a terminating
# NativeCommandError under a 'Stop' preference on Windows PowerShell 5.1, which
# would kill this harness over a child process that exited perfectly well.
# Failure is judged by exit code.

# ---------------------------------------------------------------------------
# Fixture constants -- all deliberately fake
# ---------------------------------------------------------------------------

#: The documented placeholder. The repository's identifier scan allows this value
#: and rejects any other twelve-digit number, so a real account ID cannot be
#: pasted in here without failing the Python suite.
$PlaceholderAccountId = '123456789012'

#: Named so it is obviously not a live secret identifier. It is also what the
#: audit masks out of its own output, so it must not be a real name.
$FixtureSecretName = 'fixture-secret'

$FixtureRoleName = 'GracefulGutAI-LambdaExecutionRole'
$FixtureFunctionName = 'graceful-gut-ai-dev-api'
$FixtureRegion = 'us-east-2'
$FixtureProfile = 'fixture-profile'

# ---------------------------------------------------------------------------
# Fixture payloads
# ---------------------------------------------------------------------------

function Get-BaseFixtures {
    <#
    .SYNOPSIS
        The clean, expected role. Every scenario starts from this and overrides
        the one file it is about.

    .DESCRIPTION
        Keyed by '<service>_<operation>', which is the filename the fake CLI looks
        up. Building the set in one place means a scenario describes only its own
        deviation, so what each scenario is testing is readable rather than
        buried in a wall of duplicated JSON.

        Every payload is the *result of the audit's --query*, not a full AWS
        response, because that is what the audit receives. The fixed-shape ones
        are JSON objects with named fields and the two collections are JSON
        arrays, which is the distinction the second failure turned on.
    #>

    $secretArn = "arn:aws:secretsmanager:${FixtureRegion}:${PlaceholderAccountId}:secret:${FixtureSecretName}-AbCdEf"
    $roleArn = "arn:aws:iam::${PlaceholderAccountId}:role/${FixtureRoleName}"

    $fixtures = @{}

    $fixtures['sts_get-caller-identity'] = "{`"Account`":`"$PlaceholderAccountId`"}"

    $fixtures['lambda_get-function-configuration'] =
    "{`"State`":`"Active`",`"LastUpdateStatus`":`"Successful`",`"Role`":`"$roleArn`"}"

    # KmsKeyId null is the AWS-managed key, which is the real deployment's shape
    # and the one where a kms:Decrypt grant would be a finding.
    $fixtures['secretsmanager_describe-secret'] =
    "{`"Arn`":`"$secretArn`",`"KmsKeyId`":null}"

    $fixtures['iam_get-role'] = @'
{"AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}}
'@

    # One attached managed policy: the shape that broke the first run.
    $fixtures['iam_list-attached-role-policies'] = @'
[{"PolicyName":"AWSLambdaBasicExecutionRole","PolicyArn":"arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"}]
'@

    $fixtures['iam_get-policy'] = '{"DefaultVersionId":"v1"}'

    $fixtures['iam_get-policy-version'] = @'
{"Document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}}
'@

    # One inline policy, named the canonical one -- 'GracefulGutAI-SecretAccess',
    # the name the first successful live audit found deployed. It was
    # 'GracefulGutAI-ReadApiKeySecret' here until that run, which is the name the
    # setup instructions in CLAUDE.md use and which turned out never to have been
    # the deployed name. Scenario G covers any other name.
    $fixtures['iam_list-role-policies'] = '["GracefulGutAI-SecretAccess"]'

    $fixtures['iam_get-role-policy'] =
    "{`"PolicyDocument`":{`"Version`":`"2012-10-17`",`"Statement`":[{`"Effect`":`"Allow`",`"Action`":`"secretsmanager:GetSecretValue`",`"Resource`":`"arn:aws:secretsmanager:${FixtureRegion}:${PlaceholderAccountId}:secret:${FixtureSecretName}-*`"}]}}"

    return $fixtures
}

function New-FixtureSet {
    <#
    .SYNOPSIS
        The clean set with named overrides applied.
    #>
    param(
        [Parameter(Mandatory = $false)][hashtable]$Override = @{}
    )

    $fixtures = Get-BaseFixtures
    foreach ($key in $Override.Keys) {
        $fixtures[[string]$key] = [string]$Override[$key]
    }
    return $fixtures
}

# ---------------------------------------------------------------------------
# The fake AWS CLI
# ---------------------------------------------------------------------------

#: A .cmd shim, because that is how `aws` is found on Windows: PowerShell resolves
#: a bare command name through PATH and PATHEXT, and .CMD is on PATHEXT by
#: default. It parses only the leading arguments -- the two global flags, then the
#: service and the operation -- and never looks at the --query, so nothing here
#: depends on how cmd.exe tokenises a JMESPath expression.
$FakeAwsShim = @'
@echo off
setlocal EnableExtensions
set "FIXTURES=%GG_FAKE_AWS_FIXTURES%"
set "CALLLOG=%GG_FAKE_AWS_CALLLOG%"
set "BREACHLOG=%GG_FAKE_AWS_BREACHLOG%"
set "SERVICE="
set "OPERATION="

:parse
if "%~1"=="" goto ready
set "TOKEN=%~1"
if "%TOKEN%"=="--profile" (
    shift
    shift
    goto parse
)
if "%TOKEN%"=="--region" (
    shift
    shift
    goto parse
)
if not defined SERVICE (
    set "SERVICE=%TOKEN%"
    shift
    goto parse
)
if not defined OPERATION (
    set "OPERATION=%TOKEN%"
    shift
    goto parse
)
goto ready

:ready
if not defined SERVICE goto noroute
if not defined OPERATION goto noroute

if /I "%OPERATION%"=="get-secret-value" goto breach
if /I "%OPERATION%"=="batch-get-secret-value" goto breach

>>"%CALLLOG%" echo %SERVICE%:%OPERATION%

set "PAYLOAD=%FIXTURES%\%SERVICE%_%OPERATION%.json"
if not exist "%PAYLOAD%" goto nofixture
type "%PAYLOAD%"
exit /b 0

:nofixture
>&2 echo fake-aws: no fixture for %SERVICE%:%OPERATION%
exit /b 253

:noroute
>&2 echo fake-aws: could not determine the service and operation
exit /b 252

:breach
>>"%BREACHLOG%" echo %SERVICE%:%OPERATION%
>&2 echo fake-aws: refused a secret-value read
exit /b 254
'@

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    # No BOM: the shim emits fixtures with `type`, and a BOM would arrive at
    # ConvertFrom-Json as leading garbage.
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Set-ProcessEnvironment {
    <#
    .SYNOPSIS
        Set or clear a process environment variable.

    .DESCRIPTION
        [Environment]::SetEnvironmentVariable rather than Set-Item, because
        Set-Item rejects an empty value and clearing a variable is exactly what
        the credential neutering below needs to do.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][string]$Value
    )

    [System.Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

function Get-PowerShellHostPath {
    <#
    .SYNOPSIS
        The executable running this harness.

    .DESCRIPTION
        The audit is run as a child process rather than dot-sourced, for one
        decisive reason: it ends in `exit $script:ExitCode`. Called in-process that
        would terminate this harness on the first scenario, and the exit code is
        the single thing every scenario asserts.

        Running the *same* host is the point. A harness that tested the audit under
        PowerShell 7 while the administrator runs Windows PowerShell 5.1 would have
        passed both failures this exists to catch.
    #>

    $path = (Get-Process -Id $PID).Path
    if (-not [string]::IsNullOrWhiteSpace($path)) { return $path }

    # PSHOME is set on both hosts; the executable name differs.
    foreach ($name in @('pwsh.exe', 'powershell.exe')) {
        $candidate = Join-Path $PSHOME $name
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    throw 'Could not determine which PowerShell executable is running.'
}

function Invoke-ChildAudit {
    <#
    .SYNOPSIS
        Run the audit script once and return its exit code and output.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$HostPath,
        [Parameter(Mandatory = $true)][string]$ScriptPath
    )

    $arguments = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', $ScriptPath,
        '-ExpectedSecretName', $FixtureSecretName,
        '-Profile', $FixtureProfile,
        '-Region', $FixtureRegion,
        '-FunctionName', $FixtureFunctionName,
        '-RoleName', $FixtureRoleName,
        '-NoOpen'
    )

    $previousErrorAction = $ErrorActionPreference

    $nativePreference = Get-Variable -Name 'PSNativeCommandUseErrorActionPreference' `
        -Scope Global -ErrorAction SilentlyContinue
    $hasNativePreference = $null -ne $nativePreference
    $previousNativePreference = $false
    if ($hasNativePreference) {
        $previousNativePreference = $nativePreference.Value
    }

    try {
        $ErrorActionPreference = 'Continue'
        if ($hasNativePreference) {
            Set-Variable -Name 'PSNativeCommandUseErrorActionPreference' `
                -Scope Global -Value $false
        }

        $captured = & $HostPath @arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
        if ($hasNativePreference) {
            Set-Variable -Name 'PSNativeCommandUseErrorActionPreference' `
                -Scope Global -Value $previousNativePreference
        }
    }

    $lines = @()
    foreach ($item in $captured) {
        if ($null -ne $item) { $lines += $item.ToString() }
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = ($lines -join [Environment]::NewLine)
    }
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

function Get-Scenarios {
    <#
    .SYNOPSIS
        Every case this harness runs, in order.

    .DESCRIPTION
        The nine cover the two failure classes and the review-gating rules:

          A  the clean role -- one attached policy, one inline policy, the
             AWS-managed key, the expected trust policy. Proves the whole audit
             reaches the end and writes a review.
          B  zero attached policies.
          C  several attached policies.
          D  a function configuration missing State.
          E  a function configuration whose Role is null.
          F  a real security finding: the secret grant on every secret.
          G  an inline policy under an unrecognised name.
          H  zero inline policies.
          I  several inline policies, none of them recognised.

        B and C exist because "one" is not the interesting case on its own -- the
        first failure was a one-item collection, and a fix that handled one while
        breaking zero would look correct. D and E are the second failure's
        territory: each names a different required field, and each must fail with
        that field's own message rather than a shared one.

        H and I apply that same zero/one/many rule to the *inline* list, which
        had it only at the unit level. Every runtime scenario before them fed the
        audit exactly one inline policy, so two branches had never executed here:
        the empty list, which records a REVIEW of its own, and a list long enough
        for one stage to record more than one finding. Both are branches the
        single-collection rewrite changed.

        G is the third failure's territory, and it is the reason this harness
        gained a scenario rather than an assertion. The first successful live
        audit hit exactly this case -- an inline policy whose name was not the
        expected one -- and produced a terminal that said REVIEW and a review file
        that said `**Overall: PASS**` with `REVIEW: 0`. Both artefacts were
        internally consistent, so nothing short of comparing them could catch it.
        G asserts on the terminal *and* the file from one run, which is the only
        arrangement that can see the two disagree.

        ExpectedCalls is asserted exactly. It is how this harness knows every AWS
        call went to the fake CLI: a call that resolved to something else would
        leave the log short.
    #>

    $scenarios = New-Object System.Collections.Generic.List[object]

    # --- A: the clean, expected role ---------------------------------------
    $scenarios.Add(@{
            Name           = 'A. clean expected role'
            Fixtures       = New-FixtureSet
            ExpectedExit   = 0
            ExpectReview   = $true
            ExpectedCalls  = 9
            MustContain    = @(
                'Resolved AWS-managed policy: AWSLambdaBasicExecutionRole',
                'Resolved inline policy: GracefulGutAI-SecretAccess',
                'Secret encryption: AWS-managed key',
                'No least-privilege finding',
                'Execution role audit: PASS',
                'Audit complete. Nothing was changed.'
            )
            # Resolving the canonically named policy is a step, not a finding: it
            # prints PASS and must not raise a REVIEW anywhere.
            MustNotContain = @(
                'Audit did not complete',
                'DIAGNOSTIC:',
                'not part of the documented setup',
                'REVIEW'
            )
            ReviewContains = @(
                '**Overall: PASS**',
                'FAIL: 0. REVIEW: 0.',
                'AWSLambdaBasicExecutionRole'
            )
        })

    # --- B: zero attached policies -----------------------------------------
    # A role with no managed policy writes no logs, so the audit records a REVIEW
    # and the run's verdict is REVIEW. Exit stays 0 -- a REVIEW is a request for
    # an administrator's judgement, not a failed run.
    #
    # This scenario asserted `**Overall: PASS**` until 2026-07-30, and that
    # expectation was correct for the script it was written against: the
    # zero-policy branch *printed* a REVIEW and recorded nothing, so the review
    # file it produced genuinely did say PASS. B was pinning the terminal/review
    # disagreement in place rather than catching it, and it was the one scenario
    # whose fixture made that disagreement visible without an unrecognised policy
    # name being involved.
    #
    # It now asserts the finding in both artefacts, which is the rule every other
    # completed scenario follows.
    $scenarios.Add(@{
            Name           = 'B. zero attached managed policies'
            Fixtures       = New-FixtureSet -Override @{
                'iam_list-attached-role-policies' = '[]'
            }
            ExpectedExit   = 0
            ExpectReview   = $true
            ExpectedCalls  = 7
            MustContain    = @(
                'No managed policy is attached',
                'Execution role audit: REVIEW',
                'Audit complete. Nothing was changed.'
            )
            MustNotContain = @(
                'Audit did not complete',
                'DIAGNOSTIC:',
                'Execution role audit: PASS'
            )
            ReviewContains = @(
                '**Overall: REVIEW**',
                'FAIL: 0. REVIEW: 1.',
                '| Attached managed policies | REVIEW |',
                'No managed policy is attached'
            )
        })

    # --- C: several attached policies ---------------------------------------
    $scenarios.Add(@{
            Name           = 'C. multiple attached managed policies'
            Fixtures       = New-FixtureSet -Override @{
                'iam_list-attached-role-policies' = @"
[{"PolicyName":"AWSLambdaBasicExecutionRole","PolicyArn":"arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"},{"PolicyName":"GracefulGutAI-ExtraLogging","PolicyArn":"arn:aws:iam::${PlaceholderAccountId}:policy/GracefulGutAI-ExtraLogging"}]
"@
            }
            ExpectedExit   = 0
            ExpectReview   = $true
            ExpectedCalls  = 11
            MustContain    = @(
                'Resolved AWS-managed policy: AWSLambdaBasicExecutionRole',
                'Resolved customer-managed policy: GracefulGutAI-ExtraLogging',
                'Log write on unrestricted resource'
            )
            MustNotContain = @('Audit did not complete', 'DIAGNOSTIC:')
            ReviewContains = @('**Overall: REVIEW**', 'GracefulGutAI-ExtraLogging')
        })

    # --- D: the configuration is missing State ------------------------------
    # The key is absent entirely, which is the shape a changed API or a wrong
    # query produces.
    $scenarios.Add(@{
            Name           = 'D. function configuration missing State'
            Fixtures       = New-FixtureSet -Override @{
                'lambda_get-function-configuration' =
                "{`"LastUpdateStatus`":`"Successful`",`"Role`":`"arn:aws:iam::${PlaceholderAccountId}:role/${FixtureRoleName}`"}"
            }
            ExpectedExit   = 1
            ExpectReview   = $false
            ExpectedCalls  = 2
            MustContain    = @(
                "did not include the required field 'State'",
                'Audit did not complete. No review was written.',
                'Nothing was changed',
                "DIAGNOSTIC: stage='Function'"
            )
            MustNotContain = @(
                'Audit complete',
                'returned fewer fields than expected'
            )
            ReviewContains = @()
        })

    # --- E: the configuration's Role is null --------------------------------
    # Present-but-null, which is what a JMESPath query for a field the response
    # does not carry actually returns. Both shapes must fail, and each must name
    # its own field -- which is the whole point of the correction.
    $scenarios.Add(@{
            Name           = 'E. function configuration with a null Role'
            Fixtures       = New-FixtureSet -Override @{
                'lambda_get-function-configuration' =
                '{"State":"Active","LastUpdateStatus":"Successful","Role":null}'
            }
            ExpectedExit   = 1
            ExpectReview   = $false
            ExpectedCalls  = 2
            MustContain    = @(
                "did not include the required field 'Role'",
                'Audit did not complete. No review was written.',
                "DIAGNOSTIC: stage='Function'"
            )
            MustNotContain = @(
                'Audit complete',
                "did not include the required field 'State'"
            )
            ReviewContains = @()
        })

    # --- F: a real security finding -----------------------------------------
    $scenarios.Add(@{
            Name           = 'F. secret grant on every secret'
            Fixtures       = New-FixtureSet -Override @{
                'iam_get-role-policy' = @'
{"PolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}}
'@
            }
            ExpectedExit   = 2
            ExpectReview   = $true
            ExpectedCalls  = 9
            MustContain    = @(
                'is granted on every secret',
                'Execution role audit: FAIL',
                'Audit complete. Nothing was changed.'
            )
            MustNotContain = @('Audit did not complete', 'DIAGNOSTIC:')
            ReviewContains = @(
                '**Overall: FAIL**',
                'Scope Resource to the one expected secret ARN.'
            )
        })

    # --- G: an inline policy under an unrecognised name ----------------------
    # The live-audit case. The policy document is the clean one -- it grants
    # exactly the expected secret read -- so the *only* thing wrong is the name,
    # and a run that lost the finding would look completely clean. That is what
    # happened: the terminal classified it REVIEW and the review file said PASS.
    #
    # This is the one scenario that asserts the same finding in all five places
    # it has to appear, because any four of them agreeing is what the defect
    # looked like from either artefact alone:
    #
    #   terminal        MustContain, the REVIEW line
    #   REVIEW count    ReviewContains, 'FAIL: 0. REVIEW: 1.'
    #   findings table  ReviewContains, the row
    #   overall verdict ReviewContains and MustContain, REVIEW not PASS
    #   exit code       ExpectedExit 0 -- a REVIEW is not a failure
    $scenarios.Add(@{
            Name           = 'G. inline policy under an unrecognised name'
            Fixtures       = New-FixtureSet -Override @{
                'iam_list-role-policies' = '["GracefulGutAI-LegacyInlinePolicy"]'
            }
            ExpectedExit   = 0
            ExpectReview   = $true
            ExpectedCalls  = 9
            MustContain    = @(
                'Inline policy is not part of the documented setup: GracefulGutAI-LegacyInlinePolicy',
                "expected 'GracefulGutAI-SecretAccess'",
                'Execution role audit: REVIEW',
                'Audit complete. Nothing was changed.'
            )
            MustNotContain = @(
                'Audit did not complete',
                'DIAGNOSTIC:',
                'Execution role audit: PASS'
            )
            ReviewContains = @(
                '**Overall: REVIEW**',
                'FAIL: 0. REVIEW: 1.',
                '| Inline policies | REVIEW |',
                'Inline policy is not part of the documented setup: GracefulGutAI-LegacyInlinePolicy',
                '## Least-privilege corrections'
            )
        })

    # --- H: zero inline policies ---------------------------------------------
    # The inline side of the zero/one/many rule B and C apply to attached
    # policies. Until this scenario the inline list was only ever exercised with
    # exactly one entry, so the empty branch -- which records a REVIEW of its own,
    # and is one of the branches converted from a bare print -- had never run.
    #
    # One call fewer than A: nothing to read a document for.
    $scenarios.Add(@{
            Name           = 'H. zero inline policies'
            Fixtures       = New-FixtureSet -Override @{
                'iam_list-role-policies' = '[]'
            }
            ExpectedExit   = 0
            ExpectReview   = $true
            ExpectedCalls  = 8
            MustContain    = @(
                'No inline policy is present',
                'Execution role audit: REVIEW',
                'Audit complete. Nothing was changed.'
            )
            MustNotContain = @(
                'Audit did not complete',
                'DIAGNOSTIC:',
                'Resolved inline policy:',
                'Execution role audit: PASS'
            )
            ReviewContains = @(
                '**Overall: REVIEW**',
                'FAIL: 0. REVIEW: 1.',
                '| Inline policies | REVIEW |',
                'No inline policy is present'
            )
        })

    # --- I: several inline policies, none recognised -------------------------
    # "Many" for the inline list, and the only scenario in which one stage
    # records more than one finding. That combination is what the single-collection
    # rewrite actually changed, and nothing else here exercises it:
    #
    #   * the collection accumulates two findings rather than replacing one
    #   * Get-StageSeverity aggregates both under the same stage
    #   * the findings table renders two rows and the count reads REVIEW: 2
    #
    # Both documents are the clean secret grant, so the names remain the only
    # thing wrong and the count cannot be inflated by a permission finding.
    $scenarios.Add(@{
            Name           = 'I. several unrecognised inline policies'
            Fixtures       = New-FixtureSet -Override @{
                'iam_list-role-policies' = '["GracefulGutAI-LegacyInlinePolicy","GracefulGutAI-SecondLegacyPolicy"]'
            }
            ExpectedExit   = 0
            ExpectReview   = $true
            ExpectedCalls  = 10
            MustContain    = @(
                'Inline policy is not part of the documented setup: GracefulGutAI-LegacyInlinePolicy',
                'Inline policy is not part of the documented setup: GracefulGutAI-SecondLegacyPolicy',
                'Execution role audit: REVIEW',
                'Audit complete. Nothing was changed.'
            )
            MustNotContain = @(
                'Audit did not complete',
                'DIAGNOSTIC:',
                'Execution role audit: PASS',
                'No inline policy is present'
            )
            ReviewContains = @(
                '**Overall: REVIEW**',
                'FAIL: 0. REVIEW: 2.',
                '| Inline policies | REVIEW |',
                'Inline policy is not part of the documented setup: GracefulGutAI-LegacyInlinePolicy',
                'Inline policy is not part of the documented setup: GracefulGutAI-SecondLegacyPolicy'
            )
        })

    return $scenarios
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

$script:Failures = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param(
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $script:Failures.Add("$Scenario -- $Reason")
    Write-Host "    FAIL  $Reason" -ForegroundColor Red
}

function Write-Pass {
    param([Parameter(Mandatory = $true)][string]$Detail)

    Write-Host "    ok    $Detail" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'Phase 1G - execution-role audit runtime harness' -ForegroundColor White
Write-Host 'Fixture data only. No AWS call, no secret read, nothing changed.' -ForegroundColor DarkGray

$repoRoot = Split-Path -Parent $PSScriptRoot
$auditScript = Join-Path $PSScriptRoot 'audit-lambda-execution-role.ps1'

if (-not (Test-Path -LiteralPath $auditScript)) {
    [Console]::Error.WriteLine("Audit script not found next to this harness: $auditScript")
    exit 1
}

$tempRoot = [System.IO.Path]::GetTempPath()
$sandbox = Join-Path $tempRoot ("gg-phase1g-runtime-" + [System.Guid]::NewGuid().ToString('N'))

# Checked before anything is created. A sandbox inside the checkout would put
# fixtures, logs, and generated reviews where they could be committed.
$resolvedRepo = [System.IO.Path]::GetFullPath($repoRoot)
$resolvedSandbox = [System.IO.Path]::GetFullPath($sandbox)
if ($resolvedSandbox.StartsWith($resolvedRepo, [System.StringComparison]::OrdinalIgnoreCase)) {
    [Console]::Error.WriteLine(@"
The system temp directory resolves to a path inside the repository.

This harness writes fixtures, a fake CLI, and generated reviews, and none of them
may land in the checkout. Point TEMP outside the repository and re-run.
"@)
    exit 1
}

#: Every environment variable this harness changes, so the finally block can put
#: each one back exactly as it found it -- including "not set at all".
$environmentNames = @(
    'PATH', 'TEMP', 'TMP',
    'GG_FAKE_AWS_FIXTURES', 'GG_FAKE_AWS_CALLLOG', 'GG_FAKE_AWS_BREACHLOG',
    'AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_REGION', 'AWS_DEFAULT_REGION',
    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
    'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE',
    'AWS_EC2_METADATA_DISABLED'
)

$originalEnvironment = @{}
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [System.Environment]::GetEnvironmentVariable($name)
}

$exitCode = 0

try {
    $binDir = Join-Path $sandbox 'bin'
    $null = New-Item -ItemType Directory -Path $binDir -Force

    $breachLog = Join-Path $sandbox 'secret-read-attempts.log'
    Write-TextFile -Path (Join-Path $binDir 'aws.cmd') -Content $FakeAwsShim

    # The fake CLI first on PATH, so a bare `aws` resolves to it.
    Set-ProcessEnvironment -Name 'PATH' -Value ($binDir + [System.IO.Path]::PathSeparator + $originalEnvironment['PATH'])
    Set-ProcessEnvironment -Name 'GG_FAKE_AWS_BREACHLOG' -Value $breachLog

    # Belt and braces: even a real CLI reached by some path this harness did not
    # anticipate would have no credentials and no config file to read.
    Set-ProcessEnvironment -Name 'AWS_ACCESS_KEY_ID' -Value ''
    Set-ProcessEnvironment -Name 'AWS_SECRET_ACCESS_KEY' -Value ''
    Set-ProcessEnvironment -Name 'AWS_SESSION_TOKEN' -Value ''
    Set-ProcessEnvironment -Name 'AWS_PROFILE' -Value ''
    Set-ProcessEnvironment -Name 'AWS_DEFAULT_PROFILE' -Value ''
    Set-ProcessEnvironment -Name 'AWS_EC2_METADATA_DISABLED' -Value 'true'
    Set-ProcessEnvironment -Name 'AWS_CONFIG_FILE' -Value (Join-Path $sandbox 'no-such-aws-config')
    Set-ProcessEnvironment -Name 'AWS_SHARED_CREDENTIALS_FILE' -Value (Join-Path $sandbox 'no-such-aws-credentials')

    $hostPath = Get-PowerShellHostPath
    Write-Host ''
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    Write-Host "Sandbox:    $sandbox" -ForegroundColor DarkGray

    $index = 0
    foreach ($scenario in Get-Scenarios) {
        $index++
        $name = [string]$scenario['Name']
        Write-Host ''
        Write-Host "Scenario $name" -ForegroundColor Cyan

        $failuresBefore = $script:Failures.Count
        $scenarioDir = Join-Path $sandbox ("scenario-" + $index.ToString('00'))
        $fixtureDir = Join-Path $scenarioDir 'fixtures'
        $tempDir = Join-Path $scenarioDir 'temp'
        $null = New-Item -ItemType Directory -Path $fixtureDir -Force
        $null = New-Item -ItemType Directory -Path $tempDir -Force

        $fixtures = $scenario['Fixtures']
        foreach ($key in $fixtures.Keys) {
            Write-TextFile -Path (Join-Path $fixtureDir ("$key.json")) `
                -Content ([string]$fixtures[$key])
        }

        $callLog = Join-Path $scenarioDir 'aws-calls.log'
        Set-ProcessEnvironment -Name 'GG_FAKE_AWS_FIXTURES' -Value $fixtureDir
        Set-ProcessEnvironment -Name 'GG_FAKE_AWS_CALLLOG' -Value $callLog

        # The audit writes its review under TEMP and refuses a TEMP inside the
        # repository. Pointing it at the scenario directory is what lets this
        # harness see whether a review was written.
        Set-ProcessEnvironment -Name 'TEMP' -Value $tempDir
        Set-ProcessEnvironment -Name 'TMP' -Value $tempDir

        $run = Invoke-ChildAudit -HostPath $hostPath -ScriptPath $auditScript

        if ($ShowOutput) {
            Write-Host $run.Output -ForegroundColor DarkGray
        }

        # --- exit code ------------------------------------------------------
        $expectedExit = [int]$scenario['ExpectedExit']
        if ($run.ExitCode -eq $expectedExit) {
            Write-Pass "exit code $expectedExit"
        }
        else {
            Add-Failure -Scenario $name `
                -Reason "expected exit $expectedExit, got $($run.ExitCode)"
        }

        # --- the review, or its absence -------------------------------------
        $reviews = @(Get-ChildItem -Path $tempDir -Filter 'phase1g-execution-role-audit-*.md' `
                -File -ErrorAction SilentlyContinue)

        if ([bool]$scenario['ExpectReview']) {
            if ($reviews.Count -eq 1) {
                Write-Pass 'one review written'

                $reviewText = [System.IO.File]::ReadAllText($reviews[0].FullName)
                foreach ($needle in @($scenario['ReviewContains'])) {
                    if ($reviewText.Contains([string]$needle)) {
                        Write-Pass "review contains: $needle"
                    }
                    else {
                        Add-Failure -Scenario $name -Reason "review is missing: $needle"
                    }
                }

                # The review is written to be pasted into a task report. The audit
                # scans it before writing; this checks the file that actually
                # landed, which is a different and stronger statement.
                foreach ($pattern in @('arn:aws', $PlaceholderAccountId, $FixtureSecretName, 'https://')) {
                    if ($reviewText -match [regex]::Escape($pattern)) {
                        Add-Failure -Scenario $name `
                            -Reason "the written review leaked: $pattern"
                    }
                }
            }
            else {
                Add-Failure -Scenario $name `
                    -Reason "expected one review, found $($reviews.Count)"
            }
        }
        else {
            if ($reviews.Count -eq 0) {
                Write-Pass 'no review written for an incomplete audit'
            }
            else {
                Add-Failure -Scenario $name `
                    -Reason "an incomplete audit wrote $($reviews.Count) review(s)"
            }
        }

        # --- output content -------------------------------------------------
        foreach ($needle in @($scenario['MustContain'])) {
            if ($run.Output.Contains([string]$needle)) {
                Write-Pass "output contains: $needle"
            }
            else {
                Add-Failure -Scenario $name -Reason "output is missing: $needle"
            }
        }

        foreach ($needle in @($scenario['MustNotContain'])) {
            if ($run.Output.Contains([string]$needle)) {
                Add-Failure -Scenario $name -Reason "output should not contain: $needle"
            }
            else {
                Write-Pass "output omits: $needle"
            }
        }

        # --- every AWS call went to the fake CLI ----------------------------
        $calls = @()
        if (Test-Path -LiteralPath $callLog) {
            $calls = @(Get-Content -LiteralPath $callLog | Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                })
        }

        $expectedCalls = [int]$scenario['ExpectedCalls']
        if ($calls.Count -eq $expectedCalls) {
            Write-Pass "$expectedCalls AWS calls, all to the fake CLI"
        }
        else {
            Add-Failure -Scenario $name `
                -Reason "expected $expectedCalls fake-CLI calls, logged $($calls.Count)"
        }

        if ($calls.Count -gt 0 -and [string]$calls[0] -ne 'sts:get-caller-identity') {
            Add-Failure -Scenario $name `
                -Reason "first call was '$($calls[0])', not the caller-identity check"
        }

        # --- the audit did not print an unmasked identifier -----------------
        if ($run.Output -match [regex]::Escape($PlaceholderAccountId)) {
            Add-Failure -Scenario $name -Reason 'the account ID reached the terminal'
        }
        else {
            Write-Pass 'no account ID in the terminal output'
        }

        # --- the child's own failure diagnostic ------------------------------
        #
        # The audit prints one DIAGNOSTIC line when it dies, naming the stage, the
        # function, and the line. Three administrator runs were spent turning a bare
        # exception message into a location, so it is lifted to the top of the
        # failure report rather than left for someone to find in the captured
        # output. It is also checked for the one thing that could make it unsafe
        # to paste: an absolute path. The stage and function are literals from the
        # audit script and the line is an offset into it, so a path separator here
        # would mean the audit's own guard had failed.
        [string[]]$diagnostics = @(
            @($run.Output -split "`n") |
                ForEach-Object { [string]$_ } |
                Where-Object { $_ -match 'DIAGNOSTIC:' } |
                ForEach-Object { $_.Trim() }
        )

        foreach ($diagnostic in $diagnostics) {
            if ($diagnostic -match '[\\/]') {
                Add-Failure -Scenario $name `
                    -Reason 'the failure diagnostic carried a path'
            }
        }

        # A failing scenario prints what it saw, because a bare "expected 0, got 1"
        # is not enough to act on. A passing one stays quiet unless asked.
        if (-not $ShowOutput -and $script:Failures.Count -gt $failuresBefore) {
            foreach ($diagnostic in $diagnostics) {
                Write-Host "    $diagnostic" -ForegroundColor Yellow
            }
            Write-Host '    --- captured output ---' -ForegroundColor DarkGray
            Write-Host $run.Output -ForegroundColor DarkGray
        }
    }

    # --- global isolation checks --------------------------------------------
    Write-Host ''
    Write-Host 'Isolation' -ForegroundColor Cyan

    if (Test-Path -LiteralPath $breachLog) {
        Add-Failure -Scenario 'isolation' `
            -Reason 'a secret-value read was attempted and refused by the fake CLI'
    }
    else {
        Write-Pass 'no secret-value read was attempted'
    }

    $strays = @(Get-ChildItem -Path $repoRoot -Filter 'phase1g-execution-role-audit-*.md' `
            -Recurse -File -ErrorAction SilentlyContinue)
    if ($strays.Count -eq 0) {
        Write-Pass 'no review was written inside the repository'
    }
    else {
        Add-Failure -Scenario 'isolation' `
            -Reason "$($strays.Count) generated review(s) landed in the checkout"
    }
}
catch {
    Add-Failure -Scenario 'harness' -Reason $_.Exception.Message
}
finally {
    foreach ($name in $environmentNames) {
        Set-ProcessEnvironment -Name $name -Value ([string]$originalEnvironment[$name])
    }

    if (Test-Path -LiteralPath $sandbox) {
        Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
if ($script:Failures.Count -eq 0) {
    Write-Host 'All scenarios passed. Nothing was changed and no AWS call was made.' -ForegroundColor Green
}
else {
    Write-Host "$($script:Failures.Count) failure(s):" -ForegroundColor Red
    foreach ($failure in $script:Failures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    $exitCode = 1
}

exit $exitCode
