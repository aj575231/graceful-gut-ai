<#
.SYNOPSIS
    Administrator-only, one-time helper: configure the account-level API
    Gateway CloudWatch role for a region. Plans by default; writes only with
    -Apply.

.DESCRIPTION
    API Gateway writes access logs and execution logs through an account-wide,
    region-wide role rather than per-API credentials. Until it is set, a stage
    can be configured for both kinds of logging and produce nothing at all --
    no error, no warning, no log group entries. That is what stopped the first
    Phase 1F administrator dry run, and it is why admin-dry-run.ps1 now refuses
    to proceed without it.

    The setting is deliberately NOT in the Phase 1F template. It is a
    region-wide singleton shared by every API in the account, so a stack delete
    that owned it would silently switch logging off for all of them.

    Safety properties:

      * Plan by default. Without -Apply nothing is created, attached, or
        changed -- it reads the current state and prints what would differ.
      * It will not adopt a role it does not recognise. An existing role whose
        trust policy or attached policies are not exactly the expected ones
        stops the run, rather than being overwritten into the expected shape.
      * Exactly one trust principal, exactly one managed policy, one account
        setting. It makes no other IAM or API Gateway change.
      * Account IDs and ARNs are masked out of everything it prints.

.PARAMETER Profile
    AWS CLI profile. Default 'graceful-gut-ai'.

.PARAMETER Region
    AWS region. Default 'us-east-2'.

.PARAMETER RoleName
    IAM role name. Default 'GracefulGutAI-APIGatewayCloudWatchRole'.

.PARAMETER Apply
    Make the changes. Without it the script only reports.

.EXAMPLE
    .\scripts\setup-apigw-cloudwatch-role.ps1

.EXAMPLE
    .\scripts\setup-apigw-cloudwatch-role.ps1 -Apply

.NOTES
    Administrator credentials required. The Claude dev role holds no IAM write
    actions and no apigateway:PATCH on /account, and cannot run -Apply.

    Contains no credentials, account IDs, or secrets. The only ARN written into
    this file is the AWS-managed policy ARN, which is a public, account-
    independent constant.

    Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Profile = 'graceful-gut-ai',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Region = 'us-east-2',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$RoleName = 'GracefulGutAI-APIGatewayCloudWatchRole',

    [Parameter(Mandatory = $false)]
    [switch]$Apply
)

Set-StrictMode -Version Latest

# Not 'Stop' at script scope, for the reason documented in admin-dry-run.ps1
# and pull-task-report.ps1: native stderr output would become a terminating
# error on Windows PowerShell 5.1. Exit codes decide.

# The only principal allowed to assume this role.
$ExpectedTrustPrincipal = 'apigateway.amazonaws.com'

# The only policy allowed on it. AWS-managed, account-independent, and scoped
# to exactly the CloudWatch Logs actions API Gateway needs. A hand-written
# inline policy would be a larger surface for no benefit.
$ExpectedPolicyArn =
    'arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs'

$script:TrustPolicyFile = $null
$script:ExitCode = 0

# ---------------------------------------------------------------------------
# Output vocabulary
# ---------------------------------------------------------------------------

function ConvertTo-Outcome {
    <#
    .SYNOPSIS
        The single place the word 'PASS' is produced in this script.
    #>
    param([Parameter(Mandatory = $true)][bool]$Passed)

    if ($Passed) { return 'PASS' }
    return 'FAIL'
}

function Write-Check {
    param(
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][string]$Detail = ''
    )

    $outcome = ConvertTo-Outcome -Passed $Passed
    $colour = 'Red'
    if ($Passed) { $colour = 'Green' }

    Write-Host "  [$outcome] " -NoNewline -ForegroundColor $colour
    Write-Host $Name
    if (-not [string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host "         $Detail" -ForegroundColor DarkGray
    }
}

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)

    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan
}

function Write-Plan {
    param([Parameter(Mandatory = $true)][string]$Message)

    Write-Host "  would: $Message" -ForegroundColor Yellow
}

function Hide-Sensitive {
    <#
    .SYNOPSIS
        Mask account IDs and account-bearing ARNs out of printed text.

    .DESCRIPTION
        The role ARN this script reads and sets contains the account ID, and
        IAM error text quotes ARNs back verbatim. The AWS-managed policy ARN is
        exempt: it contains no account ID -- 'arn:aws:iam::aws:policy/...' --
        and masking it would hide the one detail a reviewer needs to confirm.
    #>
    param([Parameter(Mandatory = $false)][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $placeholder = '<<MANAGED_POLICY_ARN>>'
    $masked = $Text.Replace($ExpectedPolicyArn, $placeholder)
    $masked = [regex]::Replace($masked, 'arn:aws[a-z0-9-]*:[^\s"'',\]]+', '<ARN>')
    $masked = [regex]::Replace($masked, '\b\d{12}\b', '<AWS_ACCOUNT_ID>')
    return $masked.Replace($placeholder, $ExpectedPolicyArn)
}

function Stop-Run {
    param([Parameter(Mandatory = $true)][string]$Message)

    throw (Hide-Sensitive -Text $Message)
}

# ---------------------------------------------------------------------------
# AWS CLI
# ---------------------------------------------------------------------------

function Invoke-Aws {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

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

        $full = @('--profile', $Profile, '--region', $Region) + $Arguments
        $captured = & aws @full 2>&1
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
        ExitCode  = $exitCode
        Output    = ($lines -join [Environment]::NewLine)
        Succeeded = ($exitCode -eq 0)
    }
}

function Invoke-AwsOrStop {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    $result = Invoke-Aws -Arguments $Arguments
    if (-not $result.Succeeded) {
        Stop-Run -Message @"
$FailureMessage

aws exit code: $($result.ExitCode)
$($result.Output)
"@
    }
    return $result
}

function Get-CliFileArgument {
    <#
    .SYNOPSIS
        Build the AWS CLI file:// argument for a local path.

    .DESCRIPTION
        `file://` plus the native path. NOT a URI: converting to
        `file:///C:/...` is what the AWS CLI rejects as an invalid Windows
        path, and it is what broke the first administrator attempt.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [System.IO.Path]::GetFullPath($Path)
    return "file://$resolved"
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    # Set-Content -Encoding UTF8 writes a BOM on Windows PowerShell 5.1, and a
    # BOM makes the CLI's JSON parser fail on the first character.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

function Get-CloudWatchRoleArn {
    <#
    .SYNOPSIS
        The account's current API Gateway CloudWatch role ARN, or '' if unset.
    #>
    $result = Invoke-Aws -Arguments @(
        'apigateway', 'get-account', '--query', 'cloudwatchRoleArn', '--output', 'text')

    if (-not $result.Succeeded) {
        Stop-Run -Message @"
Could not read the API Gateway account settings in $Region.

aws exit code: $($result.ExitCode)
$($result.Output)
"@
    }

    $value = $result.Output.Trim()
    if ($value -eq 'None' -or $value -eq 'null') { return '' }
    return $value
}

function Test-RoleIsExpected {
    <#
    .SYNOPSIS
        Decide whether an existing role is the one this script would create.

    .DESCRIPTION
        An existing role of the right name is not automatically the right role.
        It may predate this project, be shared with something else, or carry
        extra policies someone attached deliberately. Overwriting it would be a
        silent privilege change to a resource this script does not own, so a
        mismatch stops the run and the operator decides.

        Expected shape, exactly: one trust statement, sts:AssumeRole, allowed,
        principal Service = apigateway.amazonaws.com; one attached managed
        policy; no inline policies.
    #>
    param([Parameter(Mandatory = $true)][string]$Role)

    $problems = New-Object System.Collections.Generic.List[string]

    $trust = Invoke-AwsOrStop -Arguments @(
        'iam', 'get-role', '--role-name', $Role,
        '--query', 'Role.AssumeRolePolicyDocument', '--output', 'json') `
        -FailureMessage "Could not read the trust policy of role '$Role'."

    $principals = @()
    $actions = @()
    $effects = @()
    $statementCount = 0
    try {
        $document = $trust.Output | ConvertFrom-Json
        foreach ($statement in @($document.Statement)) {
            $statementCount++
            foreach ($effect in @($statement.Effect)) { $effects += [string]$effect }
            foreach ($action in @($statement.Action)) { $actions += [string]$action }
            if ($null -ne $statement.Principal -and
                $null -ne $statement.Principal.PSObject.Properties['Service']) {
                foreach ($service in @($statement.Principal.Service)) {
                    $principals += [string]$service
                }
            }
            else {
                # A non-Service principal -- an account, a user, a federated
                # provider -- is exactly what must not be silently kept.
                $problems.Add('trust policy has a principal that is not a service principal')
            }
        }
    }
    catch {
        $problems.Add('trust policy could not be parsed')
    }

    if ($statementCount -ne 1) {
        $problems.Add("trust policy has $statementCount statements, expected 1")
    }
    $uniquePrincipals = @($principals | Sort-Object -Unique)
    if ($uniquePrincipals.Count -ne 1 -or $uniquePrincipals[0] -ne $ExpectedTrustPrincipal) {
        $problems.Add(
            "trust principals are '$($uniquePrincipals -join ', ')', expected only $ExpectedTrustPrincipal")
    }
    $uniqueActions = @($actions | Sort-Object -Unique)
    if ($uniqueActions.Count -ne 1 -or $uniqueActions[0] -ne 'sts:AssumeRole') {
        $problems.Add("trust actions are '$($uniqueActions -join ', ')', expected only sts:AssumeRole")
    }
    $uniqueEffects = @($effects | Sort-Object -Unique)
    if ($uniqueEffects.Count -ne 1 -or $uniqueEffects[0] -ne 'Allow') {
        $problems.Add("trust effects are '$($uniqueEffects -join ', ')', expected only Allow")
    }

    $attached = Invoke-AwsOrStop -Arguments @(
        'iam', 'list-attached-role-policies', '--role-name', $Role,
        '--query', 'AttachedPolicies[].PolicyArn', '--output', 'text') `
        -FailureMessage "Could not list attached policies of role '$Role'."

    $attachedArns = @()
    if (-not [string]::IsNullOrWhiteSpace($attached.Output)) {
        $attachedArns = @($attached.Output.Trim() -split '\s+' |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $unexpected = @($attachedArns | Where-Object { $_ -ne $ExpectedPolicyArn })
    if ($unexpected.Count -gt 0) {
        $problems.Add("$($unexpected.Count) unexpected managed policy attachment(s)")
    }

    $inline = Invoke-AwsOrStop -Arguments @(
        'iam', 'list-role-policies', '--role-name', $Role,
        '--query', 'PolicyNames', '--output', 'text') `
        -FailureMessage "Could not list inline policies of role '$Role'."
    if (-not [string]::IsNullOrWhiteSpace($inline.Output.Trim())) {
        $problems.Add('the role carries inline policies')
    }

    return [pscustomobject]@{
        Ok               = ($problems.Count -eq 0)
        Problems         = $problems
        HasExpectedPolicy = ($attachedArns -contains $ExpectedPolicyArn)
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'API Gateway account CloudWatch role' -ForegroundColor White
if ($Apply) {
    Write-Host 'Mode: APPLY - changes will be made.' -ForegroundColor Yellow
}
else {
    Write-Host 'Mode: PLAN - nothing will be changed. Re-run with -Apply to make changes.' `
        -ForegroundColor DarkGray
}

try {
    if (-not (Get-Command 'aws' -ErrorAction SilentlyContinue)) {
        Stop-Run -Message 'The aws command was not found on PATH. Nothing was changed.'
    }

    Write-Section 'Current state'

    $identity = Invoke-AwsOrStop -Arguments @(
        'sts', 'get-caller-identity', '--query', 'Account', '--output', 'text') `
        -FailureMessage "Could not resolve credentials for profile '$Profile'."
    Write-Check -Passed $true -Name "AWS profile '$Profile' resolves in $Region"

    $currentArn = Get-CloudWatchRoleArn
    $alreadyConfigured = -not [string]::IsNullOrWhiteSpace($currentArn)
    Write-Check -Passed $alreadyConfigured `
        -Name "Account CloudWatch role is configured in $Region" `
        -Detail $(if ($alreadyConfigured) { "currently: $(Hide-Sensitive -Text $currentArn)" } else { 'not set' })

    $roleLookup = Invoke-Aws -Arguments @(
        'iam', 'get-role', '--role-name', $RoleName, '--query', 'Role.RoleName', '--output', 'text')
    $roleExists = $roleLookup.Succeeded
    Write-Check -Passed $roleExists -Name "IAM role '$RoleName' exists" `
        -Detail $(if ($roleExists) { '' } else { 'would be created' })

    # An existing role is inspected before anything is decided about it.
    $roleUsable = $true
    $hasExpectedPolicy = $false
    if ($roleExists) {
        $inspection = Test-RoleIsExpected -Role $RoleName
        $roleUsable = $inspection.Ok
        $hasExpectedPolicy = $inspection.HasExpectedPolicy
        Write-Check -Passed $inspection.Ok -Name "Role '$RoleName' has the expected shape"
        foreach ($problem in $inspection.Problems) {
            Write-Host "         - $problem" -ForegroundColor Yellow
        }

        if (-not $inspection.Ok) {
            Stop-Run -Message @"
Role '$RoleName' already exists but is not the role this script creates.

It is NOT being modified. Overwriting a role this script does not own would be
a silent privilege change to something another system may depend on.

Review it yourself and either fix it deliberately or re-run with a different
-RoleName. Nothing was changed.
"@
        }
    }

    if ($alreadyConfigured -and $roleExists -and $roleUsable -and $hasExpectedPolicy) {
        Write-Section 'Result'
        Write-Check -Passed $true -Name 'Nothing to do - the prerequisite is already satisfied'
        Write-Host ''
        Write-Host 'You can now run the dry run:' -ForegroundColor DarkGray
        Write-Host '  .\scripts\admin-dry-run.ps1 -ProductionOrigin <approved-origin>' `
            -ForegroundColor DarkGray
        exit 0
    }

    # --- Plan ---------------------------------------------------------------

    Write-Section 'Plan'
    if (-not $roleExists) {
        Write-Plan "create IAM role '$RoleName' trusting only $ExpectedTrustPrincipal"
    }
    if (-not $hasExpectedPolicy) {
        Write-Plan "attach $ExpectedPolicyArn"
    }
    if (-not $alreadyConfigured) {
        Write-Plan "set the API Gateway account cloudwatchRoleArn in $Region"
    }
    Write-Host '  and nothing else. No other IAM or API Gateway change is made.' `
        -ForegroundColor DarkGray

    if (-not $Apply) {
        Write-Host ''
        Write-Host 'PLAN ONLY - nothing was changed. Re-run with -Apply to make these changes.' `
            -ForegroundColor Yellow
        exit 0
    }

    # --- Apply --------------------------------------------------------------

    Write-Section 'Apply'

    if (-not $roleExists) {
        $trustDocument = @'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "apigateway.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
'@
        $tempRoot = $env:TEMP
        if ([string]::IsNullOrWhiteSpace($tempRoot)) {
            $tempRoot = [System.IO.Path]::GetTempPath()
        }
        $script:TrustPolicyFile = Join-Path $tempRoot `
            "apigw-trust-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        Write-Utf8NoBom -Path $script:TrustPolicyFile -Content $trustDocument

        Invoke-AwsOrStop -Arguments @(
            'iam', 'create-role',
            '--role-name', $RoleName,
            '--description', 'Allows API Gateway to write access and execution logs to CloudWatch Logs',
            '--assume-role-policy-document', (Get-CliFileArgument -Path $script:TrustPolicyFile)) `
            -FailureMessage "Could not create role '$RoleName'." | Out-Null

        Write-Check -Passed $true -Name "Created role '$RoleName'"
    }

    if (-not $hasExpectedPolicy) {
        Invoke-AwsOrStop -Arguments @(
            'iam', 'attach-role-policy',
            '--role-name', $RoleName,
            '--policy-arn', $ExpectedPolicyArn) `
            -FailureMessage "Could not attach the managed policy to '$RoleName'." | Out-Null

        Write-Check -Passed $true -Name 'Attached the AWS managed policy' `
            -Detail $ExpectedPolicyArn
    }

    $roleArn = Invoke-AwsOrStop -Arguments @(
        'iam', 'get-role', '--role-name', $RoleName,
        '--query', 'Role.Arn', '--output', 'text') `
        -FailureMessage "Could not read the ARN of role '$RoleName'."
    $targetArn = $roleArn.Output.Trim()

    # A freshly created role is not immediately visible to API Gateway. The
    # update fails with a validation error rather than a retryable one, so a
    # bounded retry is the difference between working and looking broken.
    $configured = $false
    $lastOutput = ''
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        $update = Invoke-Aws -Arguments @(
            'apigateway', 'update-account',
            '--patch-operations', "op=replace,path=/cloudwatchRoleArn,value=$targetArn")
        if ($update.Succeeded) { $configured = $true; break }

        $lastOutput = $update.Output
        Write-Host "  attempt $attempt did not take; waiting for IAM to propagate..." `
            -ForegroundColor DarkGray
        Start-Sleep -Seconds 10
    }

    if (-not $configured) {
        Stop-Run -Message @"
Could not set the API Gateway account cloudwatchRoleArn in $Region after
several attempts.

$lastOutput

The role may exist and be correct; only the account setting is missing. Check
with:
  aws apigateway get-account --region $Region --query cloudwatchRoleArn
"@
    }

    # --- Verify -------------------------------------------------------------
    # Read the setting back rather than trusting the write. This is the whole
    # difference between the script and the sequence it replaces.

    Write-Section 'Verification'
    $finalArn = Get-CloudWatchRoleArn
    $verified = ($finalArn -eq $targetArn)
    Write-Check -Passed $verified -Name "Account cloudwatchRoleArn is set in $Region" `
        -Detail (Hide-Sensitive -Text $finalArn)

    if (-not $verified) {
        Stop-Run -Message @"
The account setting did not read back as the role that was just configured.
Nothing further was attempted.
"@
    }

    Write-Host ''
    Write-Host 'Prerequisite satisfied. You can now run the dry run:' -ForegroundColor Green
    Write-Host '  .\scripts\admin-dry-run.ps1 -ProductionOrigin <approved-origin>' `
        -ForegroundColor DarkGray
}
catch {
    Write-Host ''
    [Console]::Error.WriteLine((Hide-Sensitive -Text $_.Exception.Message))
    $script:ExitCode = 1
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($script:TrustPolicyFile) -and
        (Test-Path -LiteralPath $script:TrustPolicyFile)) {
        Remove-Item -LiteralPath $script:TrustPolicyFile -Force -ErrorAction SilentlyContinue
    }
}

exit $script:ExitCode
