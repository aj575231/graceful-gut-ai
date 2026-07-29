<#
.SYNOPSIS
    Administrator dry run of the Phase 1F infrastructure change set. Creates a
    change set, reviews it, and deletes it. Never executes it.

.DESCRIPTION
    This replaces the hand-pasted command sequence in the administrator
    runbook. The first attempt at that sequence failed in a way that a script
    prevents by construction, and every rule below exists because of a specific
    thing that went wrong:

      * A prerequisite check failed -- the account had no API Gateway
        CloudWatch role -- and the remaining commands were pasted and run
        anyway. This script aborts the whole run on the first failure. There is
        no command left for a human to paste next.

      * The parameter file was passed as `file:///C:/Users/...`, which the AWS
        CLI rejects as an invalid Windows path. The correct Windows form is
        `file://C:\path\to\file.json` -- two slashes, native separators, no
        URI conversion. See Get-CliFileArgument.

      * `create-change-set` therefore never succeeded, so no change set and no
        stack ever existed. The later describe and delete commands failed for
        that reason and not for any reason to do with the template.

      * Despite all of that, the pasted sequence still wrote a review file
        saying PASS and printed cleanup success messages unconditionally. This
        script routes every PASS through ConvertTo-Outcome and every cleanup
        result through ConvertTo-CleanupOutcome, so neither word can be
        printed without a boolean that was actually computed.

    What it does, in order: check six prerequisites, write a completed
    parameter file to TEMP, validate the template, create a CREATE change set,
    wait for it, assert its contents, write the review, then delete the change
    set and the empty stack record it leaves behind.

    It never executes a change set. The CLI verb that would do so does not
    appear anywhere in this file, which is the simplest form that rule can
    take: there is nothing to accidentally reach.

.PARAMETER Profile
    AWS CLI profile. Default 'graceful-gut-ai'.

.PARAMETER Region
    AWS region. Default 'us-east-2', which the deployment is pinned to.

.PARAMETER StackName
    CloudFormation stack name. Default 'graceful-gut-ai-dev-infrastructure'.
    A non-deleted stack of this name must NOT already exist.

.PARAMETER FunctionName
    The application Lambda this stack references but never manages. Default
    'graceful-gut-ai-dev-api'.

.PARAMETER ProductionOrigin
    Required. The exact approved https origin, e.g. https://example.com. No
    wildcard, no path, no port -- the template's AllowedPattern rejects those.
    It is a parameter and never a committed string, which is why there is no
    default.

.PARAMETER ChangeSetName
    Optional. Defaults to a timestamped 'phase1f-dry-run-...' name.

.PARAMETER NoOpen
    Print the review path without opening an editor.

.EXAMPLE
    .\scripts\admin-dry-run.ps1 -ProductionOrigin https://example.com

.EXAMPLE
    .\scripts\admin-dry-run.ps1 `
      -ProductionOrigin https://example.com `
      -StackName graceful-gut-ai-dev-infrastructure `
      -NoOpen

.NOTES
    Administrator only. The Claude dev role holds no cloudformation: actions on
    this stack and cannot run this script.

    Contains no credentials, account IDs, ARNs, API IDs, or URLs. The account
    ID is read at run time to build the function ARN, is written only to the
    TEMP parameter file, and is masked out of everything printed or saved.

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
    [string]$StackName = 'graceful-gut-ai-dev-infrastructure',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionName = 'graceful-gut-ai-dev-api',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ProductionOrigin,

    [Parameter(Mandatory = $false)]
    [string]$ChangeSetName,

    [Parameter(Mandatory = $false)]
    [switch]$NoOpen
)

Set-StrictMode -Version Latest

# $ErrorActionPreference is deliberately NOT 'Stop' at script scope. Native
# commands write ordinary progress to stderr, and under a 'Stop' preference
# Windows PowerShell 5.1 turns the first such line into a terminating
# NativeCommandError -- killing the run over a command that exited 0. Failure
# is judged by exit code, in Invoke-Aws. Same lesson as pull-task-report.ps1.

$RequiredBranch = 'phase1f-api-gateway-foundation'

# The eleven resources a CREATE change set must add while the education route
# is off. Eleven is the whole template minus the nine resources carrying
# Condition: EducationRouteEnabled. A twelfth Add means the route came on, or
# something was added to the template without being reviewed here.
$ExpectedAdds = @(
    'AccessLogGroup',
    'Deployment',
    'HealthGetInvokePermission',
    'HealthGetMethod',
    'HealthOptionsInvokePermission',
    'HealthOptionsMethod',
    'HealthResource',
    'RestApi',
    'Stage',
    'WebAcl',
    'WebAclAssociation'
)

# Parameter values the review is not allowed to be silent about. Each one is a
# thing that costs money, exposes free text, or turns a control off.
$RequiredParameters = [ordered]@{
    'EnableEducationRoute' = 'false'
    'StageName'            = 'dev'
    'WafRateRuleAction'    = 'Count'
}

# Resource types that must never appear in this stack's change set. The
# application is referenced by ARN, never managed.
$ForbiddenResourceTypes = @(
    'AWS::Lambda::Function',
    'AWS::Serverless::Function',
    'AWS::Lambda::Url',
    'AWS::Lambda::Alias',
    'AWS::Lambda::Version',
    'AWS::IAM::Role',
    'AWS::IAM::Policy',
    'AWS::WAFv2::LoggingConfiguration',
    'AWS::Budgets::Budget'
)

# Every stack status that is not "gone". A stack in any of these already holds
# the name and the dry run must not touch it.
$NonDeletedStackStatuses = @(
    'CREATE_IN_PROGRESS', 'CREATE_FAILED', 'CREATE_COMPLETE',
    'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE',
    'DELETE_IN_PROGRESS', 'DELETE_FAILED',
    'UPDATE_IN_PROGRESS', 'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
    'UPDATE_COMPLETE', 'UPDATE_FAILED',
    'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_FAILED',
    'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
    'UPDATE_ROLLBACK_COMPLETE',
    'REVIEW_IN_PROGRESS',
    'IMPORT_IN_PROGRESS', 'IMPORT_COMPLETE',
    'IMPORT_ROLLBACK_IN_PROGRESS', 'IMPORT_ROLLBACK_FAILED',
    'IMPORT_ROLLBACK_COMPLETE'
)

# --- State the finally block needs ----------------------------------------

$script:ParameterFile = $null
$script:ReviewFile = $null
$script:ChangeSetRequested = $false
$script:AccountId = $null
$script:ExitCode = 0

# ---------------------------------------------------------------------------
# Outcome vocabulary -- the single place either word can be produced
# ---------------------------------------------------------------------------

function ConvertTo-Outcome {
    <#
    .SYNOPSIS
        Turn a computed boolean into the only 'PASS' string in this script.

    .DESCRIPTION
        The failed manual attempt printed PASS for checks that had not run.
        Every pass/fail word printed to the terminal or written to the review
        comes through here, so the word cannot be emitted without a boolean
        someone actually computed. Grep the file: the literal appears once.
    #>
    param([Parameter(Mandatory = $true)][bool]$Passed)

    if ($Passed) { return 'PASS' }
    return 'FAIL'
}

function ConvertTo-CleanupOutcome {
    <#
    .SYNOPSIS
        Report cleanup honestly: removed, absent, or still there.

    .DESCRIPTION
        The failed attempt printed cleanup success for a change set and a stack
        that had never been created. 'REMOVED' is produced here and nowhere
        else, and only when the object was observed to exist and the delete
        call then succeeded. "It was never there" and "the delete failed" are
        different outcomes and read differently.
    #>
    param(
        [Parameter(Mandatory = $true)][bool]$Existed,
        [Parameter(Mandatory = $true)][bool]$Removed
    )

    if (-not $Existed) { return 'NOT PRESENT' }
    if ($Removed) { return 'REMOVED' }
    return 'STILL PRESENT - REMOVE IT BY HAND'
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

function Hide-Sensitive {
    <#
    .SYNOPSIS
        Mask account IDs and ARNs out of anything shown or saved.

    .DESCRIPTION
        AWS error text quotes back the ARN it was given, so an unmasked failure
        message would put the account ID on screen and into the review. ARNs
        are masked before bare account IDs, so the ID inside an ARN is covered
        by the ARN rule rather than leaving a half-masked ARN behind.
    #>
    param([Parameter(Mandatory = $false)][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $masked = [regex]::Replace($Text, 'arn:aws[a-z0-9-]*:[^\s"'',\]]+', '<ARN>')
    $masked = [regex]::Replace($masked, '\b\d{12}\b', '<AWS_ACCOUNT_ID>')
    return $masked
}

function Stop-Run {
    <#
    .SYNOPSIS
        Abort the run. Cleanup still happens; nothing continues.

    .DESCRIPTION
        Throwing rather than exiting is what makes "abort the entire script"
        true: the throw unwinds into the finally block, which removes the
        parameter file and any change set or empty stack record already
        created, and then the script ends. No later step observes the failure
        and carries on.
    #>
    param([Parameter(Mandatory = $true)][string]$Message)

    throw (Hide-Sensitive -Text $Message)
}

# ---------------------------------------------------------------------------
# Native command wrappers -- exit code is the only source of truth
# ---------------------------------------------------------------------------

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
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
        # 'Continue' makes a stderr line data rather than a terminating error.
        $ErrorActionPreference = 'Continue'
        if ($hasNativePreference) {
            Set-Variable -Name 'PSNativeCommandUseErrorActionPreference' `
                -Scope Global -Value $false
        }

        $captured = & $Command @Arguments 2>&1
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

function Invoke-Git {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    return Invoke-Native -Command 'git' -Arguments $Arguments
}

function Invoke-Aws {
    <#
    .SYNOPSIS
        Run the AWS CLI with the run's profile and region already applied.

    .DESCRIPTION
        Returns the result; it does not decide what a failure means. Callers
        that must abort use Invoke-AwsOrStop. The two are separate because a
        few calls -- "does this stack exist?" -- treat a nonzero exit as an
        answer rather than an error, and that distinction has to be explicit at
        the call site rather than buried here.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $full = @('--profile', $Profile, '--region', $Region) + $Arguments
    return Invoke-Native -Command 'aws' -Arguments $full
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
        This is the bug that stopped the first administrator attempt. The CLI
        wants `file://` followed by the path exactly as the operating system
        writes it:

            file://C:\Users\admin\AppData\Local\Temp\parameters.json

        It is NOT a URI. Converting it to a URI -- which is what
        [System.Uri]::new($path).AbsoluteUri and PowerShell's own path
        formatting both produce -- yields `file:///C:/Users/...`, with three
        slashes and forward separators. The CLI rejects that as an invalid
        Windows path, and create-change-set never runs.

        So: two slashes, native separators, no conversion. The path is fully
        resolved first, because a relative path here fails the same way.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [System.IO.Path]::GetFullPath($Path)
    return "file://$resolved"
}

function Write-Utf8NoBom {
    <#
    .SYNOPSIS
        Write text as UTF-8 without a byte order mark.

    .DESCRIPTION
        Set-Content -Encoding UTF8 emits a BOM on Windows PowerShell 5.1. A BOM
        at the head of a JSON file makes the AWS CLI's parser fail on the first
        character, which looks like a malformed parameter file rather than an
        encoding problem. The .NET call takes an explicit no-BOM encoder and
        behaves the same on 5.1 and 7.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

# ---------------------------------------------------------------------------
# Prerequisites -- all six, before anything is created
# ---------------------------------------------------------------------------

function Test-Prerequisites {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    Write-Section 'Prerequisites'

    # 1. The AWS CLI has to exist before any check that uses it.
    if (-not (Get-Command 'aws' -ErrorAction SilentlyContinue)) {
        Write-Check -Passed $false -Name 'AWS CLI is installed'
        Stop-Run -Message 'The aws command was not found on PATH. Nothing was changed.'
    }
    Write-Check -Passed $true -Name 'AWS CLI is installed'

    if (-not (Get-Command 'git' -ErrorAction SilentlyContinue)) {
        Write-Check -Passed $false -Name 'Git is installed'
        Stop-Run -Message 'The git command was not found on PATH. Nothing was changed.'
    }
    Write-Check -Passed $true -Name 'Git is installed'

    # 2. Clean working tree. A dry run reviews what is committed; an
    #    uncommitted template edit would be reviewed and then not be what
    #    anyone later reads out of Git.
    $status = Invoke-Git -Arguments @('status', '--porcelain')
    if (-not $status.Succeeded) {
        Write-Check -Passed $false -Name 'Repository working tree is clean'
        Stop-Run -Message 'Could not read Git status. Nothing was changed.'
    }
    $treeClean = [string]::IsNullOrWhiteSpace($status.Output)
    Write-Check -Passed $treeClean -Name 'Repository working tree is clean'
    if (-not $treeClean) {
        Stop-Run -Message @"
The working tree has uncommitted changes:
$($status.Output)

Commit or stash them first. The change set must describe committed template
content, or the review records something no one can retrieve later.
Nothing was changed.
"@
    }

    # 3. Right branch. The template under review is this branch's.
    $branch = Invoke-Git -Arguments @('rev-parse', '--abbrev-ref', 'HEAD')
    if (-not $branch.Succeeded) {
        Write-Check -Passed $false -Name "Current branch is $RequiredBranch"
        Stop-Run -Message 'Could not determine the current branch. Nothing was changed.'
    }
    $currentBranch = $branch.Output.Trim()
    $onBranch = ($currentBranch -eq $RequiredBranch)
    Write-Check -Passed $onBranch -Name "Current branch is $RequiredBranch" `
        -Detail "on '$currentBranch'"
    if (-not $onBranch) {
        Stop-Run -Message @"
This dry run reviews the template on '$RequiredBranch', but the checkout is on
'$currentBranch'. Nothing was changed.
"@
    }

    # 4. The profile resolves. This is also where the account ID comes from --
    #    it is needed to build the function ARN and is never printed.
    $identity = Invoke-Aws -Arguments @(
        'sts', 'get-caller-identity', '--query', 'Account', '--output', 'text')
    $identityOk = $identity.Succeeded -and
        ($identity.Output.Trim() -match '^\d{12}$')
    Write-Check -Passed $identityOk -Name "AWS profile '$Profile' resolves"
    if (-not $identityOk) {
        Stop-Run -Message @"
Could not resolve credentials for profile '$Profile' in $Region.

aws exit code: $($identity.ExitCode)
$($identity.Output)

If this is an SSO profile, log in first, then re-run this script. Do not run
the remaining commands by hand. Nothing was changed.
"@
    }
    $script:AccountId = $identity.Output.Trim()

    # 5. The application function is healthy. The stack references it by ARN
    #    and grants it invoke permissions; a function mid-update makes the
    #    change set describe something that is itself changing.
    $state = Invoke-Aws -Arguments @(
        'lambda', 'get-function-configuration',
        '--function-name', $FunctionName,
        '--query', '[State,LastUpdateStatus]', '--output', 'text')
    $functionHealthy = $false
    $stateDetail = ''
    if ($state.Succeeded) {
        $fields = $state.Output.Trim() -split '\s+'
        if ($fields.Count -ge 2) {
            $functionHealthy = ($fields[0] -eq 'Active') -and ($fields[1] -eq 'Successful')
            $stateDetail = "State=$($fields[0]) LastUpdateStatus=$($fields[1])"
        }
    }
    Write-Check -Passed $functionHealthy `
        -Name "Application function '$FunctionName' is Active and last update Successful" `
        -Detail $stateDetail
    if (-not $functionHealthy) {
        Stop-Run -Message @"
The application function is not in a reviewable state.

$stateDetail
$(Hide-Sensitive -Text $state.Output)

Nothing was changed.
"@
    }

    # 6. The account-level API Gateway CloudWatch role. This is the one that
    #    was missing on the first attempt. It is a region-wide singleton and is
    #    deliberately not in the template, so the stack cannot create it --
    #    without it the stage is configured for access and execution logging
    #    that is then never written, and nothing anywhere reports an error.
    $cwRole = Invoke-Aws -Arguments @(
        'apigateway', 'get-account',
        '--query', 'cloudwatchRoleArn', '--output', 'text')
    $cwRoleValue = ''
    if ($cwRole.Succeeded) { $cwRoleValue = $cwRole.Output.Trim() }
    $cwRoleConfigured = $cwRole.Succeeded -and
        (-not [string]::IsNullOrWhiteSpace($cwRoleValue)) -and
        ($cwRoleValue -ne 'None') -and
        ($cwRoleValue -ne 'null')
    Write-Check -Passed $cwRoleConfigured `
        -Name "API Gateway account CloudWatch role is configured in $Region"
    if (-not $cwRoleConfigured) {
        Stop-Run -Message @"
No API Gateway account-level CloudWatch role is configured in $Region.

The stage would be created with access logging and execution logging that
silently write nothing. This is an account-wide, one-time administrator
setting and the stack must not own it -- a stack delete would clear it for
every API in the region.

Fix it with the prerequisite helper, then re-run this script:

  .\scripts\setup-apigw-cloudwatch-role.ps1 -Region $Region
  .\scripts\setup-apigw-cloudwatch-role.ps1 -Region $Region -Apply

Do NOT continue by pasting the remaining commands. That is what happened on
the first attempt and it produced a review file claiming PASS for checks that
never ran. Nothing was changed.
"@
    }

    # 7. The stack name is free. A CREATE change set against an existing stack
    #    fails, and against an existing REVIEW_IN_PROGRESS record from an
    #    abandoned earlier run it would adopt someone else's leftovers.
    $existing = Invoke-AwsOrStop -Arguments (@(
            'cloudformation', 'list-stacks', '--stack-status-filter') +
        $NonDeletedStackStatuses +
        @('--query', "StackSummaries[?StackName=='$StackName'].StackStatus",
            '--output', 'text')) `
        -FailureMessage 'Could not list CloudFormation stacks.'

    $existingStatus = $existing.Output.Trim()
    $nameFree = [string]::IsNullOrWhiteSpace($existingStatus)
    Write-Check -Passed $nameFree -Name "No non-deleted stack named '$StackName' exists"
    if (-not $nameFree) {
        Stop-Run -Message @"
A stack named '$StackName' already exists with status: $existingStatus

This script only ever performs a CREATE dry run, and it will not touch a stack
it did not create. If that stack is an abandoned REVIEW_IN_PROGRESS record from
an earlier attempt, delete it deliberately and re-run. Nothing was changed.
"@
    }

    $repoRootShown = $RepoRoot
    Write-Host "  Repository: $repoRootShown" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Parameter file -- TEMP only, never the repository
# ---------------------------------------------------------------------------

function New-ParameterFile {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $tempRoot = $env:TEMP
    if ([string]::IsNullOrWhiteSpace($tempRoot)) {
        $tempRoot = [System.IO.Path]::GetTempPath()
    }
    $tempRoot = [System.IO.Path]::GetFullPath($tempRoot)

    # The completed file carries the account ID in the function ARN and the
    # approved production origin. Neither may ever land in the working tree,
    # where the next `git add -A` would commit it. Checked rather than assumed,
    # because a TEMP redirected inside the checkout is exactly the kind of
    # local configuration nobody remembers setting.
    $repoFull = [System.IO.Path]::GetFullPath($RepoRoot)
    $tempCompare = $tempRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $repoCompare = $repoFull.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($tempCompare.StartsWith($repoCompare, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Run -Message @"
TEMP resolves to a path inside the repository:
  $tempRoot

The completed parameter file carries the account ID and the production origin
and must never be written where Git can see it. Nothing was changed.
"@
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path $tempRoot "phase1f-parameters-$stamp.json"

    $parameters = @(
        @{ ParameterKey = 'ApplicationFunctionArn'
            ParameterValue = "arn:aws:lambda:$Region`:$($script:AccountId):function:$FunctionName" }
        @{ ParameterKey = 'StageName'; ParameterValue = 'dev' }
        @{ ParameterKey = 'AccessLogRetentionDays'; ParameterValue = '14' }
        @{ ParameterKey = 'ProductionOrigin'; ParameterValue = $ProductionOrigin }
        @{ ParameterKey = 'DevelopmentOrigin'; ParameterValue = '' }
        @{ ParameterKey = 'EnableEducationRoute'; ParameterValue = 'false' }
        @{ ParameterKey = 'StageThrottleRateLimit'; ParameterValue = '5' }
        @{ ParameterKey = 'StageThrottleBurstLimit'; ParameterValue = '10' }
        @{ ParameterKey = 'HealthRouteRateLimit'; ParameterValue = '20' }
        @{ ParameterKey = 'HealthRouteBurstLimit'; ParameterValue = '40' }
        @{ ParameterKey = 'EducationRouteRateLimit'; ParameterValue = '1' }
        @{ ParameterKey = 'EducationRouteBurstLimit'; ParameterValue = '2' }
        @{ ParameterKey = 'WafOverallRateLimit'; ParameterValue = '300' }
        @{ ParameterKey = 'WafEducationRouteRateLimit'; ParameterValue = '100' }
        @{ ParameterKey = 'WafRateRuleAction'; ParameterValue = 'Count' }
    )

    $json = ConvertTo-Json -InputObject $parameters -Depth 4
    Write-Utf8NoBom -Path $path -Content $json
    $script:ParameterFile = $path

    Write-Check -Passed (Test-Path -LiteralPath $path) `
        -Name 'Completed parameter file written outside the repository' `
        -Detail 'under TEMP, UTF-8 without BOM, deleted on exit'

    return $path
}

# ---------------------------------------------------------------------------
# The dry run
# ---------------------------------------------------------------------------

function Invoke-DryRun {
    param(
        [Parameter(Mandatory = $true)][string]$TemplatePath,
        [Parameter(Mandatory = $true)][string]$ParameterPath
    )

    $results = [ordered]@{}

    # --- Template validation -----------------------------------------------
    # Worth being clear about: this is an AWS API call, not a local parse. It
    # needs credentials, it counts against the account, and it is why this step
    # cannot be done offline.
    Write-Section 'Template validation (AWS API call)'
    $validate = Invoke-Aws -Arguments @(
        'cloudformation', 'validate-template',
        '--template-body', (Get-CliFileArgument -Path $TemplatePath))
    $results['Template validation'] = $validate.Succeeded
    Write-Check -Passed $validate.Succeeded -Name 'cloudformation validate-template'
    if (-not $validate.Succeeded) {
        Stop-Run -Message @"
Template validation failed. No change set was requested.

aws exit code: $($validate.ExitCode)
$($validate.Output)
"@
    }

    # --- Change-set creation -----------------------------------------------
    # From here on a stack record may exist even if the call fails: a CREATE
    # change set creates the stack in REVIEW_IN_PROGRESS first. The flag is set
    # before the call, not after, so the finally block cleans up a partial
    # failure too.
    Write-Section 'Change-set creation'
    $script:ChangeSetRequested = $true

    $create = Invoke-Aws -Arguments @(
        'cloudformation', 'create-change-set',
        '--stack-name', $StackName,
        '--change-set-name', $ChangeSetName,
        '--change-set-type', 'CREATE',
        '--template-body', (Get-CliFileArgument -Path $TemplatePath),
        '--parameters', (Get-CliFileArgument -Path $ParameterPath),
        '--tags',
        'Key=Project,Value=GracefulGutAI',
        'Key=Environment,Value=Development',
        'Key=Owner,Value=AJMoses',
        'Key=Business,Value=GracefulHealth')

    $results['Change-set creation'] = $create.Succeeded
    Write-Check -Passed $create.Succeeded -Name "create-change-set '$ChangeSetName'"
    if (-not $create.Succeeded) {
        Stop-Run -Message @"
create-change-set failed. Nothing is validated below this point, and no review
file is written -- there is no change set to review.

aws exit code: $($create.ExitCode)
$($create.Output)
"@
    }

    # Wait for CREATE_COMPLETE. The waiter exits nonzero when the change set
    # ends FAILED, which is the ordinary outcome for a template the account
    # will not accept -- so read the reason rather than the waiter's message.
    Write-Host '  Waiting for the change set to finish creating...' -ForegroundColor DarkGray
    $wait = Invoke-Aws -Arguments @(
        'cloudformation', 'wait', 'change-set-create-complete',
        '--stack-name', $StackName,
        '--change-set-name', $ChangeSetName)

    $status = Invoke-Aws -Arguments @(
        'cloudformation', 'describe-change-set',
        '--stack-name', $StackName,
        '--change-set-name', $ChangeSetName,
        '--query', '[Status,StatusReason]', '--output', 'text')

    $reachedComplete = $wait.Succeeded -and $status.Succeeded -and
        ($status.Output.Trim() -like 'CREATE_COMPLETE*')
    Write-Check -Passed $reachedComplete -Name 'Change set reached CREATE_COMPLETE'
    if (-not $reachedComplete) {
        Stop-Run -Message @"
The change set did not reach CREATE_COMPLETE. No review file is written.

$(Hide-Sensitive -Text $status.Output)
"@
    }

    # --- Resource list validation ------------------------------------------
    Write-Section 'Resource list validation'
    $changesJson = Invoke-AwsOrStop -Arguments @(
        'cloudformation', 'describe-change-set',
        '--stack-name', $StackName,
        '--change-set-name', $ChangeSetName,
        '--query', 'Changes[].ResourceChange.[Action,ResourceType,LogicalResourceId]',
        '--output', 'json') `
        -FailureMessage 'Could not read the change set contents.'

    $changes = @()
    $parsed = $changesJson.Output | ConvertFrom-Json
    if ($null -ne $parsed) {
        foreach ($row in @($parsed)) {
            $changes += [pscustomobject]@{
                Action    = [string]$row[0]
                Type      = [string]$row[1]
                LogicalId = [string]$row[2]
            }
        }
    }

    $actions = @($changes | ForEach-Object { $_.Action } | Sort-Object -Unique)
    $allAdd = ($actions.Count -eq 1) -and ($actions[0] -eq 'Add')
    Write-Check -Passed $allAdd -Name 'Every change is an Add' `
        -Detail ("actions: " + ($actions -join ', '))

    $addCount = @($changes | Where-Object { $_.Action -eq 'Add' }).Count
    $countRight = ($addCount -eq $ExpectedAdds.Count)
    Write-Check -Passed $countRight `
        -Name "Exactly $($ExpectedAdds.Count) Add actions with the education route off" `
        -Detail "found $addCount"

    $actualIds = @($changes | ForEach-Object { $_.LogicalId } | Sort-Object)
    $expectedIds = @($ExpectedAdds | Sort-Object)
    $idsMatch = (($actualIds -join '|') -eq ($expectedIds -join '|'))
    $idDetail = ''
    if (-not $idsMatch) {
        $unexpected = @($actualIds | Where-Object { $expectedIds -notcontains $_ })
        $missing = @($expectedIds | Where-Object { $actualIds -notcontains $_ })
        $idDetail = "unexpected: $($unexpected -join ', ') | missing: $($missing -join ', ')"
    }
    Write-Check -Passed $idsMatch -Name 'The resource set is exactly the reviewed one' `
        -Detail $idDetail

    $forbidden = @($changes |
            Where-Object { $ForbiddenResourceTypes -contains $_.Type } |
            ForEach-Object { $_.Type })
    $noForbidden = ($forbidden.Count -eq 0)
    Write-Check -Passed $noForbidden `
        -Name 'No Lambda function, URL, IAM, WAF logging, or budget resource' `
        -Detail ($forbidden -join ', ')

    $resourcesOk = $allAdd -and $countRight -and $idsMatch -and $noForbidden
    $results['Resource list validation'] = $resourcesOk

    # --- Parameter validation ----------------------------------------------
    Write-Section 'Parameter validation'
    $paramsJson = Invoke-AwsOrStop -Arguments @(
        'cloudformation', 'describe-change-set',
        '--stack-name', $StackName,
        '--change-set-name', $ChangeSetName,
        '--query', 'Parameters[].[ParameterKey,ParameterValue]',
        '--output', 'json') `
        -FailureMessage 'Could not read the change set parameters.'

    $resolvedParameters = @{}
    $parsedParams = $paramsJson.Output | ConvertFrom-Json
    if ($null -ne $parsedParams) {
        foreach ($row in @($parsedParams)) {
            $resolvedParameters[[string]$row[0]] = [string]$row[1]
        }
    }

    $parametersOk = $true
    foreach ($key in $RequiredParameters.Keys) {
        $expected = $RequiredParameters[$key]
        $actual = ''
        if ($resolvedParameters.ContainsKey($key)) { $actual = $resolvedParameters[$key] }
        $matched = ($actual -eq $expected)
        if (-not $matched) { $parametersOk = $false }
        Write-Check -Passed $matched -Name "$key = $expected" -Detail "resolved: '$actual'"
    }
    $results['Parameter validation'] = $parametersOk

    if (-not ($resourcesOk -and $parametersOk)) {
        Stop-Run -Message @"
The change set does not match the reviewed design. No review file is written --
a review that records a failure as a pass is worse than no review at all.

The change set and the empty stack record are being removed now.
"@
    }

    return [pscustomobject]@{
        Results     = $results
        AddCount    = $addCount
        LogicalIds  = $actualIds
        Parameters  = $RequiredParameters
    }
}

# ---------------------------------------------------------------------------
# Review -- written only when every assertion above passed
# ---------------------------------------------------------------------------

function Test-ReviewRedacted {
    <#
    .SYNOPSIS
        Refuse to write a review that leaks anything.

    .DESCRIPTION
        The review is meant to be pasted into a task report, so it is scanned
        before it is written rather than after. Fail closed: an unexpected
        match means no file, not a file with a warning on top.
    #>
    param([Parameter(Mandatory = $true)][string]$Content)

    $patterns = @(
        '\b\d{12}\b',
        'arn:aws',
        'https?://',
        'AKIA[0-9A-Z]{16}',
        '\bAWS_SECRET',
        '\bGG_API_KEY\b',
        '\bX-GG-Key\b'
    )

    foreach ($pattern in $patterns) {
        if ($Content -match $pattern) { return $false }
    }
    return $true
}

function New-ReviewFile {
    param(
        [Parameter(Mandatory = $true)]$Findings,
        [Parameter(Mandatory = $true)][string]$Directory
    )

    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $fileStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path $Directory "phase1f-dry-run-review-$fileStamp.md"

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Phase 1F administrator dry run - change set review')
    $lines.Add('')
    $lines.Add("Generated: $stamp")
    $lines.Add("Region: $Region")
    $lines.Add("Stack name: $StackName")
    $lines.Add("Change set: $ChangeSetName")
    $lines.Add('')
    $lines.Add('**Change set executed: NO.** This run only ever creates, reads, and')
    $lines.Add('deletes a change set. It never executes one, and no infrastructure')
    $lines.Add('was created by it.')
    $lines.Add('')
    $lines.Add('## Stages')
    $lines.Add('')
    $lines.Add('Each stage is reported separately because they fail for different')
    $lines.Add('reasons and a single combined verdict hides which one gave way.')
    $lines.Add('')
    $lines.Add('| Stage | Result |')
    $lines.Add('| --- | --- |')
    foreach ($stage in $Findings.Results.Keys) {
        $outcome = ConvertTo-Outcome -Passed ([bool]$Findings.Results[$stage])
        $lines.Add("| $stage | $outcome |")
    }
    $lines.Add('')
    $lines.Add('## Resources the change set would add')
    $lines.Add('')
    $lines.Add("Count: $($Findings.AddCount) (expected $($ExpectedAdds.Count) with the education route off)")
    $lines.Add('')
    foreach ($id in $Findings.LogicalIds) {
        $lines.Add("- $id")
    }
    $lines.Add('')
    $lines.Add('## Parameters asserted')
    $lines.Add('')
    $lines.Add('| Parameter | Required value |')
    $lines.Add('| --- | --- |')
    foreach ($key in $Findings.Parameters.Keys) {
        $lines.Add("| $key | $($Findings.Parameters[$key]) |")
    }
    $lines.Add('')
    $lines.Add('The remaining parameters are deliberately not reproduced here: the')
    $lines.Add('function ARN carries the account ID and the origin is a production')
    $lines.Add('address, and neither belongs in a document that gets pasted onward.')
    $lines.Add('')

    $content = ($lines -join [Environment]::NewLine)

    if (-not (Test-ReviewRedacted -Content $content)) {
        Stop-Run -Message @"
The generated review matched a redaction pattern (account ID, ARN, URL, or
credential name) and was NOT written. This is a bug in the script, not in the
change set. The change set and stack record are still cleaned up.
"@
    }

    Write-Utf8NoBom -Path $path -Content $content
    $script:ReviewFile = $path
    return $path
}

function Add-CleanupSection {
    <#
    .SYNOPSIS
        Append what cleanup actually did to an already-written review.

    .DESCRIPTION
        Appended afterwards rather than written up front, because the outcome
        is not known until the deletes have run and been confirmed. A review
        that predicts its own cleanup is exactly the failure this script exists
        to prevent.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ChangeSetOutcome,
        [Parameter(Mandatory = $true)][string]$StackOutcome,
        [Parameter(Mandatory = $true)][bool]$StackAbsent
    )

    if ([string]::IsNullOrWhiteSpace($script:ReviewFile)) { return }
    if (-not (Test-Path -LiteralPath $script:ReviewFile)) { return }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('## Cleanup')
    $lines.Add('')
    $lines.Add('| Object | Result |')
    $lines.Add('| --- | --- |')
    $lines.Add("| Unexecuted change set | $ChangeSetOutcome |")
    $lines.Add("| Empty REVIEW_IN_PROGRESS stack record | $StackOutcome |")
    $lines.Add("| No non-deleted stack remains | $(ConvertTo-Outcome -Passed $StackAbsent) |")
    $lines.Add('')
    $lines.Add('A CREATE change set creates the stack record in REVIEW_IN_PROGRESS')
    $lines.Add('before the change set itself exists, so deleting the change set alone')
    $lines.Add('leaves an empty stack holding the name. Both are removed.')
    $lines.Add('')

    $existing = [System.IO.File]::ReadAllText($script:ReviewFile)
    $content = $existing + [Environment]::NewLine + ($lines -join [Environment]::NewLine)

    if (-not (Test-ReviewRedacted -Content $content)) { return }
    Write-Utf8NoBom -Path $script:ReviewFile -Content $content
}

# ---------------------------------------------------------------------------
# Cleanup -- always runs, never claims more than it did
# ---------------------------------------------------------------------------

function Invoke-Cleanup {
    Write-Section 'Cleanup'

    # 1. The parameter file. It holds the account ID and the production origin,
    #    so it goes even if everything above failed.
    if (-not [string]::IsNullOrWhiteSpace($script:ParameterFile)) {
        $existed = Test-Path -LiteralPath $script:ParameterFile
        $removed = $false
        if ($existed) {
            Remove-Item -LiteralPath $script:ParameterFile -Force -ErrorAction SilentlyContinue
            $removed = -not (Test-Path -LiteralPath $script:ParameterFile)
        }
        $outcome = ConvertTo-CleanupOutcome -Existed $existed -Removed $removed
        Write-Host "  Parameter file: $outcome"
    }

    # Nothing was ever requested from CloudFormation, so there is nothing to
    # delete and nothing to claim. This is the branch the failed manual attempt
    # should have taken, and instead it printed success for both objects.
    if (-not $script:ChangeSetRequested) {
        Write-Host '  No change set was requested; no CloudFormation object to remove.' `
            -ForegroundColor DarkGray
        return
    }

    # 2. The change set. Existence is checked before deleting so the outcome
    #    can distinguish "removed" from "was never created".
    $describe = Invoke-Aws -Arguments @(
        'cloudformation', 'describe-change-set',
        '--stack-name', $StackName,
        '--change-set-name', $ChangeSetName,
        '--query', 'Status', '--output', 'text')
    $changeSetExisted = $describe.Succeeded
    $changeSetRemoved = $false
    if ($changeSetExisted) {
        $delete = Invoke-Aws -Arguments @(
            'cloudformation', 'delete-change-set',
            '--stack-name', $StackName,
            '--change-set-name', $ChangeSetName)
        if ($delete.Succeeded) {
            $confirm = Invoke-Aws -Arguments @(
                'cloudformation', 'describe-change-set',
                '--stack-name', $StackName,
                '--change-set-name', $ChangeSetName,
                '--query', 'Status', '--output', 'text')
            $changeSetRemoved = -not $confirm.Succeeded
        }
    }
    $changeSetOutcome = ConvertTo-CleanupOutcome -Existed $changeSetExisted -Removed $changeSetRemoved
    Write-Host "  Unexecuted change set: $changeSetOutcome"

    # 3. The empty stack record. A CREATE change set puts the stack into
    #    REVIEW_IN_PROGRESS with no resources; deleting the change set does not
    #    remove it, and it keeps holding the name until it is deleted too.
    $stackStatus = Invoke-Aws -Arguments (@(
            'cloudformation', 'list-stacks', '--stack-status-filter') +
        $NonDeletedStackStatuses +
        @('--query', "StackSummaries[?StackName=='$StackName'].StackStatus",
            '--output', 'text'))

    $stackExisted = $false
    if ($stackStatus.Succeeded) {
        $stackExisted = -not [string]::IsNullOrWhiteSpace($stackStatus.Output.Trim())
    }

    $stackRemoved = $false
    if ($stackExisted) {
        $deleteStack = Invoke-Aws -Arguments @(
            'cloudformation', 'delete-stack', '--stack-name', $StackName)
        if ($deleteStack.Succeeded) {
            Invoke-Aws -Arguments @(
                'cloudformation', 'wait', 'stack-delete-complete',
                '--stack-name', $StackName) | Out-Null
        }
    }
    $stackOutcome = ConvertTo-CleanupOutcome -Existed $stackExisted -Removed $stackRemoved

    # Absence is confirmed by re-reading, not inferred from the delete call.
    $after = Invoke-Aws -Arguments (@(
            'cloudformation', 'list-stacks', '--stack-status-filter') +
        $NonDeletedStackStatuses +
        @('--query', "StackSummaries[?StackName=='$StackName'].StackStatus",
            '--output', 'text'))
    $stackAbsent = $after.Succeeded -and
        [string]::IsNullOrWhiteSpace($after.Output.Trim())

    if ($stackExisted -and $stackAbsent) {
        $stackRemoved = $true
        $stackOutcome = ConvertTo-CleanupOutcome -Existed $stackExisted -Removed $stackRemoved
    }

    Write-Host "  Empty stack record: $stackOutcome"
    Write-Check -Passed $stackAbsent -Name "No non-deleted stack named '$StackName' remains"

    if (-not $stackAbsent) {
        [Console]::Error.WriteLine(
            "A stack named '$StackName' still exists. Remove it before re-running.")
        $script:ExitCode = 1
    }

    Add-CleanupSection -ChangeSetOutcome $changeSetOutcome `
        -StackOutcome $stackOutcome -StackAbsent $stackAbsent
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$repoRoot = Split-Path -Parent $PSScriptRoot
$templatePath = Join-Path $repoRoot 'infrastructure/phase1f/template.yaml'

if ([string]::IsNullOrWhiteSpace($ChangeSetName)) {
    $ChangeSetName = "phase1f-dry-run-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

Write-Host ''
Write-Host 'Phase 1F administrator dry run' -ForegroundColor White
Write-Host 'Creates a change set, reviews it, deletes it. Never executes it.' `
    -ForegroundColor DarkGray

try {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot '.git'))) {
        Stop-Run -Message "Not a Git repository: $repoRoot"
    }
    Set-Location $repoRoot

    if (-not (Test-Path -LiteralPath $templatePath)) {
        Stop-Run -Message "Template not found: infrastructure/phase1f/template.yaml"
    }

    Test-Prerequisites -RepoRoot $repoRoot

    Write-Section 'Parameter file'
    $parameterPath = New-ParameterFile -RepoRoot $repoRoot

    $findings = Invoke-DryRun -TemplatePath $templatePath -ParameterPath $parameterPath

    Write-Section 'Review'
    $tempRoot = $env:TEMP
    if ([string]::IsNullOrWhiteSpace($tempRoot)) {
        $tempRoot = [System.IO.Path]::GetTempPath()
    }
    $reviewPath = New-ReviewFile -Findings $findings -Directory $tempRoot
    Write-Host "  Written: $reviewPath" -ForegroundColor Green
}
catch {
    Write-Host ''
    [Console]::Error.WriteLine((Hide-Sensitive -Text $_.Exception.Message))
    $script:ExitCode = 1
}
finally {
    Invoke-Cleanup
}

Write-Host ''
if ($script:ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($script:ReviewFile)) {
    Write-Host 'Dry run complete. Nothing was created and nothing was executed.' `
        -ForegroundColor Green
    Write-Host "Review: $($script:ReviewFile)"

    if ($NoOpen) {
        Write-Host 'Not opened (-NoOpen).' -ForegroundColor DarkGray
    }
    else {
        try {
            Start-Process notepad.exe -ArgumentList $script:ReviewFile
        }
        catch {
            Write-Host 'Could not open Notepad; the path is shown above.' -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host 'Dry run did not complete. No review was written for an incomplete run.' `
        -ForegroundColor Yellow
    Write-Host 'Do not run the remaining commands by hand. Fix the cause and re-run.' `
        -ForegroundColor Yellow
}

exit $script:ExitCode
