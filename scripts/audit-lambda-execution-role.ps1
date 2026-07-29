<#
.SYNOPSIS
    Read-only administrator audit of the Lambda execution role. Reports
    findings and stops. It never changes anything.

.DESCRIPTION
    GracefulGutAI-LambdaExecutionRole has been carried as an unresolved finding
    since Phase 1D. The reason is structural rather than neglect: the Claude dev
    role holds iam:GetRole and iam:PassRole on that one role and nothing else, so
    its attached and inline policies cannot be read from the dev host at all.
    Auditing it needs administrator credentials, and this script is what an
    administrator runs.

    It is permanently read-only, and that is enforced rather than promised:

      * Every AWS call goes through Invoke-AwsRead, which checks the
        service:operation pair against $ReadOnlyOperations before running it and
        aborts on anything absent. Adding a mutating call is not a matter of
        someone noticing in review -- the script refuses to make it.

      * secretsmanager:get-secret-value and batch-get-secret-value are named on
        a separate forbidden list and rejected ahead of the allow-list check, so
        the failure is specific rather than generic. This audit inspects who may
        read the secret; it never reads it.

      * Nothing is corrected. Where the role is wrong, the script prints the
        least-privilege correction an administrator would apply and stops. An
        audit tool that repairs what it audits destroys the evidence and removes
        the human decision.

    What it does, in order: confirm the caller and the function, confirm the
    function's configured role is the role being audited, audit the trust
    policy, resolve every attached and inline policy document, classify every
    action into a service category, assess it against the documented
    least-privilege expectation, then write a redacted review under TEMP.

    On redaction: the review is written to be pasted into a task report, so it
    carries no ARN, no account ID, no secret name, no URL, and no environment
    variable value. Resource scope is reported as an assessment -- "scoped to the
    expected secret", "broad log scope", "wildcard" -- rather than as the literal
    ARN, which is how the audit stays useful without becoming the thing it warns
    about. The finished review is scanned before it is written, and a match means
    no file at all.

.PARAMETER Profile
    AWS CLI profile. Default 'graceful-gut-ai'.

.PARAMETER Region
    AWS region. Default 'us-east-2', which the deployment is pinned to.

.PARAMETER FunctionName
    The application Lambda whose execution role is being audited. Default
    'graceful-gut-ai-dev-api'.

.PARAMETER RoleName
    The role to audit. Default 'GracefulGutAI-LambdaExecutionRole'. The function
    must actually be configured with this role, or the run stops -- auditing a
    role nothing uses proves nothing.

.PARAMETER ExpectedSecretName
    Required. The name or ARN of the one secret the role is expected to be able
    to read. It has no default because it is the identifier of a live secret, and
    committing it would put a secret identifier in Git.

    It is used to resolve the secret's ARN and KMS key so that Secrets Manager
    and KMS grants can be assessed against the right resource. It is never
    printed and never written to the review: it is masked out of all output, and
    the pre-write scan rejects a review containing it.

.PARAMETER NoOpen
    Print the review path without opening an editor.

.EXAMPLE
    .\scripts\audit-lambda-execution-role.ps1 -ExpectedSecretName <secret-name>

.EXAMPLE
    .\scripts\audit-lambda-execution-role.ps1 `
      -ExpectedSecretName <secret-name> `
      -RoleName GracefulGutAI-LambdaExecutionRole `
      -NoOpen

.NOTES
    Administrator only. The Claude dev role cannot run this script: it holds no
    iam:ListAttachedRolePolicies, no iam:ListRolePolicies, no iam:GetRolePolicy,
    no iam:GetPolicy, and no secretsmanager: actions. That is deliberate, and it
    is the whole reason this finding has stayed open.

    Contains no credentials, account IDs, ARNs, API IDs, secret identifiers, or
    URLs. The account ID is read at run time only so it can be masked out of
    everything printed and saved.

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
    [string]$FunctionName = 'graceful-gut-ai-dev-api',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$RoleName = 'GracefulGutAI-LambdaExecutionRole',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedSecretName,

    [Parameter(Mandatory = $false)]
    [switch]$NoOpen
)

Set-StrictMode -Version Latest

# $ErrorActionPreference is deliberately NOT 'Stop' at script scope. Native
# commands write ordinary progress to stderr, and under a 'Stop' preference
# Windows PowerShell 5.1 turns the first such line into a terminating
# NativeCommandError -- killing the run over a command that exited 0. Failure is
# judged by exit code, in Invoke-Native. Same lesson as admin-dry-run.ps1.

# ---------------------------------------------------------------------------
# The read-only contract
# ---------------------------------------------------------------------------

#: Every AWS operation this script may perform. Invoke-AwsRead refuses anything
#: absent from this list, so the read-only property is enforced at run time and
#: not merely asserted in a comment. Each entry is 'service:cli-operation'.
$ReadOnlyOperations = @(
    'sts:get-caller-identity',
    'lambda:get-function-configuration',
    'iam:get-role',
    'iam:list-attached-role-policies',
    'iam:list-role-policies',
    'iam:get-role-policy',
    'iam:get-policy',
    'iam:get-policy-version',
    'secretsmanager:describe-secret'
)

#: Named separately from "not on the allow-list" so the refusal is specific. The
#: audit establishes who may read the secret. Reading it is a different act, and
#: no audit needs to perform it.
$ForbiddenOperations = @(
    'secretsmanager:get-secret-value',
    'secretsmanager:batch-get-secret-value'
)

# ---------------------------------------------------------------------------
# What the role is expected to look like
# ---------------------------------------------------------------------------

#: The inline policy the documented setup creates. CLAUDE.md has an administrator
#: run `iam put-role-policy --policy-name GracefulGutAI-ReadApiKeySecret`, which
#: makes an inline policy of that name part of the expected configuration rather
#: than a deviation. Any other inline policy is a REVIEW, not a pass.
$ExpectedInlinePolicyName = 'GracefulGutAI-ReadApiKeySecret'

#: The managed policy a Lambda execution role is normally given for logging.
$ExpectedManagedPolicyNames = @(
    'AWSLambdaBasicExecutionRole'
)

#: The only service principal that may appear in the trust policy.
$ExpectedTrustPrincipal = 'lambda.amazonaws.com'

#: Action prefix to category. Order matters: the first matching prefix wins, so
#: 'logs:' is tested before the broader buckets below it. Anything unmatched
#: falls through to 'Other', which is never expected on this role.
$ActionCategories = @(
    @{ Category = 'CloudWatch Logs';     Prefixes = @('logs:') },
    @{ Category = 'Secrets Manager';     Prefixes = @('secretsmanager:') },
    @{ Category = 'KMS';                 Prefixes = @('kms:') },
    @{ Category = 'Lambda';              Prefixes = @('lambda:') },
    @{ Category = 'IAM and STS';         Prefixes = @('iam:', 'sts:') },
    @{ Category = 'API Gateway and WAF'; Prefixes = @('apigateway:', 'execute-api:', 'wafv2:', 'waf:', 'waf-regional:') },
    @{ Category = 'CloudFormation';      Prefixes = @('cloudformation:') },
    @{ Category = 'Storage and database'; Prefixes = @('s3:', 's3express:', 'dynamodb:', 'rds:', 'rds-data:', 'efs:', 'elasticfilesystem:', 'elasticache:', 'redshift:', 'docdb:', 'timestream:') },
    @{ Category = 'Networking';          Prefixes = @('ec2:', 'elasticloadbalancing:', 'route53:', 'globalaccelerator:', 'directconnect:', 'networkmanager:') }
)

#: Services that have no business on this role at all, named explicitly because
#: requirement 13 names them. Some land in 'Other' rather than in a category
#: above -- SQS and SNS in particular -- and must still be caught.
$UnrelatedServicePrefixes = @(
    's3:', 'dynamodb:', 'sqs:', 'sns:', 'ec2:', 'rds:', 'kinesis:', 'firehose:',
    'states:', 'events:', 'scheduler:', 'ses:', 'ssm:', 'athena:', 'glue:',
    'sagemaker:', 'bedrock:', 'ecs:', 'eks:', 'ecr:', 'batch:', 'codebuild:'
)

#: CloudWatch Logs actions a Lambda legitimately needs to write its own logs.
$ExpectedLogActions = @(
    'logs:createloggroup',
    'logs:createlogstream',
    'logs:putlogevents'
)

#: Secrets Manager actions that are reads. GetSecretValue is the one the
#: application needs; DescribeSecret is harmless and sometimes present.
$ExpectedSecretActions = @(
    'secretsmanager:getsecretvalue',
    'secretsmanager:describesecret'
)

#: Secrets Manager verbs that write or administer. Any of these on an execution
#: role is a hard failure: the function reads one secret and never manages it.
$SecretWriteVerbs = @(
    'put', 'update', 'create', 'delete', 'restore', 'rotate', 'tag', 'untag',
    'replicate', 'cancel', 'remove', 'stop', 'validate'
)

#: IAM verbs that write. Present on an execution role, any of them is a
#: privilege-escalation path rather than an untidiness.
$IamWriteVerbs = @(
    'create', 'delete', 'put', 'attach', 'detach', 'update', 'add', 'remove',
    'tag', 'untag', 'set', 'change', 'enable', 'disable', 'upload', 'reset',
    'generate'
)

#: Lambda actions that administer the function or its URL.
$LambdaAdminVerbs = @(
    'create', 'delete', 'update', 'put', 'add', 'remove', 'publish', 'tag',
    'untag', 'enable', 'disable'
)

#: KMS actions that administer a key, as opposed to using one.
$KmsAdminVerbs = @(
    'create', 'delete', 'put', 'schedule', 'cancel', 'disable', 'enable',
    'update', 'tag', 'untag', 'replicate', 'import', 'retire', 'revoke'
)

# --- State the finally block and the review need ---------------------------

$script:ReviewFile = $null
$script:AccountId = $null
$script:ExpectedSecretArn = $null
$script:ExitCode = 0
$script:StagesCompleted = $false
$script:PermissionFindings = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# Outcome vocabulary -- the single place these words can be produced
# ---------------------------------------------------------------------------

function ConvertTo-Classification {
    <#
    .SYNOPSIS
        Turn a computed severity into the only PASS/REVIEW/FAIL strings here.

    .DESCRIPTION
        Three outcomes rather than two, because an audit that can only say pass
        or fail forces a judgement call into a binary and loses the middle case:
        a grant that is not a security hole but is not justified either. Those
        are exactly the findings an administrator should look at, and collapsing
        them into either bucket is how they get ignored.

        Every one of the three words printed or written comes through here, so
        none can be emitted without a severity someone actually computed. Grep
        the file: each literal appears once.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Pass', 'Review', 'Fail')]
        [string]$Severity
    )

    switch ($Severity) {
        'Pass'   { return 'PASS' }
        'Review' { return 'REVIEW' }
        default  { return 'FAIL' }
    }
}

function Get-WorstSeverity {
    <#
    .SYNOPSIS
        Combine severities. Fail beats Review beats Pass.
    #>
    param([Parameter(Mandatory = $false)][string[]]$Severities)

    if ($null -eq $Severities -or $Severities.Count -eq 0) { return 'Pass' }
    if ($Severities -contains 'Fail') { return 'Fail' }
    if ($Severities -contains 'Review') { return 'Review' }
    return 'Pass'
}

function Write-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Pass', 'Review', 'Fail')]
        [string]$Severity,

        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][string]$Detail = ''
    )

    $label = ConvertTo-Classification -Severity $Severity
    $colour = 'Green'
    if ($Severity -eq 'Review') { $colour = 'Yellow' }
    if ($Severity -eq 'Fail') { $colour = 'Red' }

    Write-Host "  [$label] " -NoNewline -ForegroundColor $colour
    Write-Host (Hide-Sensitive -Text $Name)
    if (-not [string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host "         $(Hide-Sensitive -Text $Detail)" -ForegroundColor DarkGray
    }
}

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)

    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan
}

function Add-Finding {
    <#
    .SYNOPSIS
        Append a permission finding to the run's collected list.

    .DESCRIPTION
        The list is script-scoped rather than passed in, and this function is
        top-level rather than nested inside the classifier. Both choices are
        deliberate: a function defined inside another function would reach the
        caller's $findings only through PowerShell's dynamic scoping, which works
        but is the kind of subtlety that cannot be verified on a host with no
        PowerShell interpreter. An explicit script-scoped list behaves
        identically on 5.1 and 7 and needs no reader to know that rule.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Pass', 'Review', 'Fail')]
        [string]$Severity,

        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $false)][string]$Where = '',
        [Parameter(Mandatory = $false)][string]$Correction = ''
    )

    $script:PermissionFindings.Add([pscustomobject]@{
            Severity   = $Severity
            Title      = $Title
            Where      = $Where
            Correction = $Correction
        })
}

function Hide-Sensitive {
    <#
    .SYNOPSIS
        Mask everything that must not reach a terminal or a review file.

    .DESCRIPTION
        AWS error text quotes back the ARN, role, and secret identifier it was
        given, so an unmasked failure message would put all three on screen. The
        order is deliberate:

          1. The expected secret name first, because it can appear inside an ARN
             and inside an error string, and masking it after the ARN rule would
             leave it exposed in the non-ARN cases.
          2. ARNs next, so the account ID inside an ARN is covered by the ARN
             rule rather than leaving a half-masked ARN behind.
          3. Bare account IDs last.

        The secret name is caller-supplied, so it is regex-escaped before use.
    #>
    param([Parameter(Mandatory = $false)][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $masked = $Text

    if (-not [string]::IsNullOrWhiteSpace($ExpectedSecretName)) {
        $masked = [regex]::Replace(
            $masked, [regex]::Escape($ExpectedSecretName), '<EXPECTED_SECRET>',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }

    $masked = [regex]::Replace($masked, 'arn:aws[a-z0-9-]*:[^\s"'',\]]+', '<ARN>')
    $masked = [regex]::Replace($masked, 'https?://[^\s"'',\]]+', '<URL>')
    $masked = [regex]::Replace($masked, '\b\d{12}\b', '<AWS_ACCOUNT_ID>')
    return $masked
}

function Stop-Run {
    <#
    .SYNOPSIS
        Abort the run. Nothing continues, and no review is written.

    .DESCRIPTION
        Throwing rather than exiting is what makes "abort the whole audit" true:
        the throw unwinds past every remaining stage to the single catch, so no
        later stage observes the failure and carries on with partial data. A
        review describing an audit that did not finish is worse than no review,
        because it reads as a completed one.
    #>
    param([Parameter(Mandatory = $true)][string]$Message)

    throw (Hide-Sensitive -Text $Message)
}

# ---------------------------------------------------------------------------
# Native command wrapper -- exit code is the only source of truth
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

function Invoke-AwsRead {
    <#
    .SYNOPSIS
        The only way this script talks to AWS, and it only ever reads.

    .DESCRIPTION
        The service and operation are separate parameters so the pair can be
        checked before the process starts. Two gates, in this order:

          1. The forbidden list, checked first so that an attempt to read a
             secret value fails with that specific reason rather than the
             generic one. get-secret-value is not merely absent from the
             allow-list; it is named and refused.

          2. The allow-list. Anything not on it is refused, which means a
             mutating call cannot be added to this script and quietly work --
             it fails on the first run, before it reaches AWS.

        Every call is judged by exit code. -AllowFailure exists for the one
        legitimate case where a nonzero exit is an answer rather than an error
        (does this secret exist?), and it has to be requested at the call site
        rather than assumed here.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @(),
        [Parameter(Mandatory = $false)][string]$FailureMessage = '',
        [Parameter(Mandatory = $false)][switch]$AllowFailure
    )

    $pair = "${Service}:${Operation}"

    if ($ForbiddenOperations -contains $pair) {
        Stop-Run -Message @"
Refused: $pair is on this script's forbidden list.

This audit establishes which principals may read the secret. It never reads
the secret itself, and no audit needs to.
"@
    }

    if ($ReadOnlyOperations -notcontains $pair) {
        Stop-Run -Message @"
Refused: $pair is not on this script's read-only allow-list.

This script is permanently read-only. If a new call is genuinely needed, it
must be a read, and it must be added to `$ReadOnlyOperations deliberately.
"@
    }

    $full = @('--profile', $Profile, '--region', $Region, $Service, $Operation) + $Arguments
    $result = Invoke-Native -Command 'aws' -Arguments $full

    if (-not $result.Succeeded -and -not $AllowFailure) {
        $message = $FailureMessage
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = "AWS call failed: $pair"
        }
        Stop-Run -Message @"
$message

aws exit code: $($result.ExitCode)
$($result.Output)
"@
    }

    return $result
}

function ConvertFrom-AwsJson {
    <#
    .SYNOPSIS
        Parse AWS CLI JSON output, failing closed on anything unparseable.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$What
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        Stop-Run -Message "Empty response where $What was expected."
    }

    try {
        return $Text | ConvertFrom-Json
    }
    catch {
        Stop-Run -Message "Could not parse $What as JSON."
    }
}

function ConvertFrom-PolicyDocument {
    <#
    .SYNOPSIS
        Return a policy document as an object, whichever form the CLI gave.

    .DESCRIPTION
        AWS CLI v2 returns an inline or versioned policy document as a JSON
        object. CLI v1 returns it URL-encoded, as a string. Handling only the
        object form would make this script silently audit nothing on a v1
        install: every statement list would come back empty and every check
        would pass. So both forms are handled, and an unrecognised one stops the
        run rather than being treated as an empty policy.
    #>
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)][string]$What
    )

    if ($Document -is [string]) {
        $text = $Document
        if ($text -match '%7[bB]' -or $text -match '%22') {
            $text = [System.Uri]::UnescapeDataString($text)
        }
        return ConvertFrom-AwsJson -Text $text -What $What
    }

    if ($null -eq $Document) {
        Stop-Run -Message "No policy document returned for $What."
    }

    return $Document
}

function Test-HasProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) { return $false }
    return [bool]($Object.PSObject.Properties.Name -contains $Name)
}

function Get-AsArray {
    <#
    .SYNOPSIS
        Normalise a field that IAM allows to be either a scalar or a list.

    .DESCRIPTION
        Action, Resource, and Statement are each valid as a single value or an
        array. Code that assumes an array skips single-value statements, which is
        the quiet way an audit passes a policy it never looked at.
    #>
    param([Parameter(Mandatory = $false)]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    return @($Value)
}

# ---------------------------------------------------------------------------
# Stage 1 -- caller and function
# ---------------------------------------------------------------------------

function Get-CallerAccountId {
    Write-Section 'Caller'

    $result = Invoke-AwsRead -Service 'sts' -Operation 'get-caller-identity' `
        -Arguments @('--query', 'Account', '--output', 'text') `
        -FailureMessage @"
Could not resolve the AWS caller identity.

The profile '$Profile' may be missing, expired, or unauthenticated. This script
needs administrator credentials: the Claude dev role cannot read this role's
policies and cannot run this audit.
"@

    $accountId = $result.Output.Trim()
    if ($accountId -notmatch '^\d{12}$') {
        Stop-Run -Message 'The caller identity did not resolve to an account ID.'
    }

    # Recorded only so Hide-Sensitive can mask it. It is never printed.
    $script:AccountId = $accountId
    Write-Finding -Severity 'Pass' -Name 'Caller identity resolved' `
        -Detail 'account ID read for masking only, never printed'

    return $accountId
}

function Get-FunctionRoleName {
    <#
    .SYNOPSIS
        Confirm the function is healthy and extract its configured role name.

    .DESCRIPTION
        Only three fields are requested. That is a privacy control rather than a
        performance one: the full configuration includes Environment.Variables,
        which carries GG_API_SECRET_ID. Querying server-side means the value
        never enters this process, which is stronger than fetching it and
        remembering to mask it.

        The role ARN is never printed. The role NAME is compared, because that is
        what the audit needs to establish, and the ARN would carry the account ID.
    #>
    Write-Section 'Function'

    $result = Invoke-AwsRead -Service 'lambda' -Operation 'get-function-configuration' `
        -Arguments @(
            '--function-name', $FunctionName,
            '--query', '[State,LastUpdateStatus,Role]',
            '--output', 'json'
        ) `
        -FailureMessage "Could not read the configuration of function '$FunctionName'."

    $fields = ConvertFrom-AwsJson -Text $result.Output -What 'the function configuration'
    $values = Get-AsArray -Value $fields
    if ($values.Count -lt 3) {
        Stop-Run -Message 'The function configuration query returned fewer fields than expected.'
    }

    $state = [string]$values[0]
    $lastUpdate = [string]$values[1]
    $roleArn = [string]$values[2]

    $isActive = ($state -eq 'Active')
    $stateSeverity = 'Fail'
    if ($isActive) { $stateSeverity = 'Pass' }
    Write-Finding -Severity $stateSeverity `
        -Name 'Function state is Active' -Detail "reported: $state"
    if (-not $isActive) {
        Stop-Run -Message "Function '$FunctionName' is not Active (state: $state)."
    }

    $isSuccessful = ($lastUpdate -eq 'Successful')
    $updateSeverity = 'Fail'
    if ($isSuccessful) { $updateSeverity = 'Pass' }
    Write-Finding -Severity $updateSeverity `
        -Name 'Last update status is Successful' -Detail "reported: $lastUpdate"
    if (-not $isSuccessful) {
        Stop-Run -Message "Function '$FunctionName' last update was not Successful (status: $lastUpdate)."
    }

    if ($roleArn -notmatch '^arn:aws[a-z0-9-]*:iam::\d{12}:role/') {
        Stop-Run -Message 'The function''s configured role is not a recognisable IAM role ARN.'
    }

    # Take the last path segment: service-linked and pathed roles carry slashes.
    $configuredRoleName = ($roleArn -split '/')[-1]

    $matchesExpected = ($configuredRoleName -eq $RoleName)
    $roleSeverity = 'Fail'
    if ($matchesExpected) { $roleSeverity = 'Pass' }
    Write-Finding -Severity $roleSeverity `
        -Name "Function's execution role is the role being audited" `
        -Detail 'compared by role name; the ARN is never printed'

    if (-not $matchesExpected) {
        Stop-Run -Message @"
The function is not configured with the role being audited.

Audited:   $RoleName
Configured: $configuredRoleName

Auditing a role the function does not use proves nothing. Re-run with
-RoleName set to the configured role, or investigate why it changed.
"@
    }

    return $configuredRoleName
}

# ---------------------------------------------------------------------------
# Stage 2 -- the expected secret, so grants can be judged against it
# ---------------------------------------------------------------------------

function Get-ExpectedSecret {
    <#
    .SYNOPSIS
        Resolve the expected secret's ARN and KMS key. Never its value.

    .DESCRIPTION
        Two things are needed to assess the role fairly. The ARN, so a
        Secrets Manager grant can be told apart from a grant on some other
        secret. And the KMS key, because kms:Decrypt is legitimate only when the
        secret is encrypted with a customer-managed key -- under the AWS-managed
        key, Secrets Manager handles decryption and the role needs no KMS grant
        at all. Judging KMS without knowing which key would either miss a real
        finding or invent one.

        describe-secret returns metadata only. The value is never fetched, and
        Invoke-AwsRead would refuse the attempt.
    #>
    Write-Section 'Expected secret'

    $result = Invoke-AwsRead -Service 'secretsmanager' -Operation 'describe-secret' `
        -Arguments @(
            '--secret-id', $ExpectedSecretName,
            '--query', '[ARN,KmsKeyId]',
            '--output', 'json'
        ) `
        -AllowFailure

    if (-not $result.Succeeded) {
        Write-Finding -Severity 'Fail' -Name 'Expected secret could not be described' `
            -Detail 'the identifier may be wrong, or the caller may lack secretsmanager:DescribeSecret'
        Stop-Run -Message @"
Could not describe the expected secret.

Metadata only was requested -- never the value. Check the identifier passed to
-ExpectedSecretName and that the caller holds secretsmanager:DescribeSecret.

aws exit code: $($result.ExitCode)
$($result.Output)
"@
    }

    $fields = Get-AsArray -Value (ConvertFrom-AwsJson -Text $result.Output -What 'the secret metadata')
    $arn = [string]$fields[0]
    $kmsKeyId = ''
    if ($fields.Count -gt 1 -and $null -ne $fields[1]) { $kmsKeyId = [string]$fields[1] }

    $script:ExpectedSecretArn = $arn

    # An empty KmsKeyId, or the service default alias, means the AWS-managed key.
    $usesCustomerKey = -not (
        [string]::IsNullOrWhiteSpace($kmsKeyId) -or
        $kmsKeyId -eq 'alias/aws/secretsmanager'
    )

    Write-Finding -Severity 'Pass' -Name 'Expected secret resolved (metadata only)' `
        -Detail 'the value was not read, and this script cannot read it'

    $keyDescription = 'AWS-managed key'
    if ($usesCustomerKey) { $keyDescription = 'customer-managed key' }
    Write-Finding -Severity 'Pass' -Name "Secret encryption: $keyDescription" `
        -Detail 'determines whether a kms:Decrypt grant is justified'

    return [pscustomobject]@{
        Arn             = $arn
        UsesCustomerKey = $usesCustomerKey
        KeyDescription  = $keyDescription
    }
}

# ---------------------------------------------------------------------------
# Stage 3 -- the trust policy
# ---------------------------------------------------------------------------

function Test-TrustPolicy {
    <#
    .SYNOPSIS
        Audit who may assume the role.

    .DESCRIPTION
        The trust policy is the one part of a role that decides who gets its
        permissions at all. A role whose permission policies are perfectly scoped
        but which trusts an arbitrary account is not a least-privilege role; it is
        a delegated one.
    #>
    Write-Section 'Trust policy'

    $result = Invoke-AwsRead -Service 'iam' -Operation 'get-role' `
        -Arguments @(
            '--role-name', $RoleName,
            '--query', 'Role.AssumeRolePolicyDocument',
            '--output', 'json'
        ) `
        -FailureMessage @"
Could not read role '$RoleName'.

Administrator credentials are required. The Claude dev role holds iam:GetRole on
this role but none of the policy-listing actions this audit needs.
"@

    $document = ConvertFrom-PolicyDocument `
        -Document (ConvertFrom-AwsJson -Text $result.Output -What 'the trust policy') `
        -What 'the trust policy'

    $findings = New-Object System.Collections.Generic.List[object]
    $servicePrincipals = New-Object System.Collections.Generic.List[string]

    if (-not (Test-HasProperty -Object $document -Name 'Statement')) {
        Stop-Run -Message 'The trust policy has no Statement array.'
    }

    $statements = Get-AsArray -Value $document.Statement
    $sawAccountPrincipal = $false
    $sawFederatedPrincipal = $false
    $sawWildcardPrincipal = $false
    $sawCondition = $false
    $sawExternalId = $false
    $sawNonAssumeAction = $false
    $sawDeny = $false

    foreach ($statement in $statements) {
        if (Test-HasProperty -Object $statement -Name 'Effect') {
            if ([string]$statement.Effect -eq 'Deny') { $sawDeny = $true }
        }

        foreach ($action in (Get-AsArray -Value $(
                    if (Test-HasProperty -Object $statement -Name 'Action') { $statement.Action } else { $null }))) {
            if ([string]$action -notmatch '^sts:AssumeRole$') { $sawNonAssumeAction = $true }
        }

        if (Test-HasProperty -Object $statement -Name 'Condition') {
            $sawCondition = $true
            $conditionText = ($statement.Condition | ConvertTo-Json -Depth 10 -Compress)
            if ($conditionText -match 'ExternalId') { $sawExternalId = $true }
        }

        if (-not (Test-HasProperty -Object $statement -Name 'Principal')) { continue }

        $principal = $statement.Principal

        if ($principal -is [string]) {
            if ([string]$principal -eq '*') { $sawWildcardPrincipal = $true }
            continue
        }

        foreach ($property in $principal.PSObject.Properties) {
            $key = $property.Name
            $values = Get-AsArray -Value $property.Value

            switch ($key) {
                'Service' {
                    foreach ($value in $values) {
                        $servicePrincipals.Add([string]$value)
                        if ([string]$value -eq '*') { $sawWildcardPrincipal = $true }
                    }
                }
                'AWS' {
                    $sawAccountPrincipal = $true
                    foreach ($value in $values) {
                        if ([string]$value -eq '*') { $sawWildcardPrincipal = $true }
                    }
                }
                'Federated' { $sawFederatedPrincipal = $true }
                'CanonicalUser' { $sawAccountPrincipal = $true }
                default {
                    $findings.Add([pscustomobject]@{
                            Severity = 'Review'
                            Title    = "Unrecognised trust principal type: $key"
                        })
                }
            }
        }
    }

    $onlyLambda = (
        $servicePrincipals.Count -eq 1 -and
        $servicePrincipals[0] -eq $ExpectedTrustPrincipal
    )
    $severity = 'Fail'
    if ($onlyLambda) { $severity = 'Pass' }
    Write-Finding -Severity $severity `
        -Name "$ExpectedTrustPrincipal is the only trusted service principal" `
        -Detail "service principals found: $($servicePrincipals.Count)"
    if (-not $onlyLambda) {
        $findings.Add([pscustomobject]@{
                Severity = 'Fail'
                Title    = "Trust policy does not trust exactly $ExpectedTrustPrincipal"
            })
    }

    $checks = @(
        @{ Bad = $sawAccountPrincipal;   Name = 'No AWS account principal';       Severity = 'Fail' },
        @{ Bad = $sawFederatedPrincipal; Name = 'No federated principal';         Severity = 'Fail' },
        @{ Bad = $sawWildcardPrincipal;  Name = 'No wildcard principal';          Severity = 'Fail' },
        @{ Bad = $sawExternalId;         Name = 'No external ID condition';       Severity = 'Fail' },
        @{ Bad = $sawCondition;          Name = 'No unexpected trust condition';  Severity = 'Review' },
        @{ Bad = $sawNonAssumeAction;    Name = 'Only sts:AssumeRole is granted';  Severity = 'Review' },
        @{ Bad = $sawDeny;               Name = 'No Deny statement in the trust policy'; Severity = 'Review' }
    )

    foreach ($check in $checks) {
        $bad = [bool]$check.Bad
        $found = 'Pass'
        if ($bad) { $found = [string]$check.Severity }
        Write-Finding -Severity $found -Name ([string]$check.Name)
        if ($bad) {
            $findings.Add([pscustomobject]@{
                    Severity = [string]$check.Severity
                    Title    = "Trust policy: $([string]$check.Name) -- violated"
                })
        }
    }

    return [pscustomobject]@{
        Findings          = $findings
        ServicePrincipals = $servicePrincipals
        Severity          = (Get-WorstSeverity -Severities @($findings | ForEach-Object { $_.Severity }))
    }
}

# ---------------------------------------------------------------------------
# Stage 4 -- resolve every policy document
# ---------------------------------------------------------------------------

function Get-AttachedPolicyDocuments {
    <#
    .SYNOPSIS
        List attached managed policies and resolve each one's default version.

    .DESCRIPTION
        Three calls per policy, and all three are necessary. list-attached gives
        names and ARNs but no document; get-policy gives the default version ID;
        get-policy-version gives the document for that version. Skipping the
        version resolution and assuming v1 is a real error mode -- an edited
        customer-managed policy has a later default version, and auditing v1
        would audit a document that is no longer in effect.
    #>
    Write-Section 'Attached managed policies'

    $result = Invoke-AwsRead -Service 'iam' -Operation 'list-attached-role-policies' `
        -Arguments @(
            '--role-name', $RoleName,
            '--query', 'AttachedPolicies[].[PolicyName,PolicyArn]',
            '--output', 'json'
        ) `
        -FailureMessage "Could not list attached policies for role '$RoleName'."

    $rows = Get-AsArray -Value (ConvertFrom-AwsJson -Text $result.Output -What 'the attached policy list')
    $policies = New-Object System.Collections.Generic.List[object]

    if ($rows.Count -eq 0) {
        Write-Finding -Severity 'Review' -Name 'No managed policy is attached' `
            -Detail 'a Lambda without log permissions writes no logs'
    }

    foreach ($row in $rows) {
        $pair = Get-AsArray -Value $row
        if ($pair.Count -lt 2) { continue }

        $policyName = [string]$pair[0]
        $policyArn = [string]$pair[1]

        # AWS-managed policies carry ':aws:' in place of an account ID.
        $isAwsManaged = ($policyArn -match '^arn:aws[a-z0-9-]*:iam::aws:policy/')

        $versionResult = Invoke-AwsRead -Service 'iam' -Operation 'get-policy' `
            -Arguments @(
                '--policy-arn', $policyArn,
                '--query', 'Policy.DefaultVersionId',
                '--output', 'text'
            ) `
            -FailureMessage "Could not read managed policy '$policyName'."

        $versionId = $versionResult.Output.Trim()
        if ([string]::IsNullOrWhiteSpace($versionId)) {
            Stop-Run -Message "Managed policy '$policyName' returned no default version ID."
        }

        $documentResult = Invoke-AwsRead -Service 'iam' -Operation 'get-policy-version' `
            -Arguments @(
                '--policy-arn', $policyArn,
                '--version-id', $versionId,
                '--query', 'PolicyVersion.Document',
                '--output', 'json'
            ) `
            -FailureMessage "Could not read version $versionId of policy '$policyName'."

        $document = ConvertFrom-PolicyDocument `
            -Document (ConvertFrom-AwsJson -Text $documentResult.Output -What "policy '$policyName'") `
            -What "policy '$policyName'"

        $kind = 'customer-managed'
        if ($isAwsManaged) { $kind = 'AWS-managed' }

        Write-Finding -Severity 'Pass' -Name "Resolved $kind policy: $policyName" `
            -Detail "default version $versionId"

        $policies.Add([pscustomobject]@{
                Name         = $policyName
                Kind         = $kind
                IsAwsManaged = $isAwsManaged
                VersionId    = $versionId
                Document     = $document
                Source       = "attached ($kind)"
            })
    }

    return $policies
}

function Get-InlinePolicyDocuments {
    <#
    .SYNOPSIS
        List and resolve every inline policy on the role.

    .DESCRIPTION
        Inline policies are expected here, not suspicious in themselves: the
        documented setup in CLAUDE.md creates one with put-role-policy for the
        secret grant. So the expected name passes and anything else is a REVIEW.
    #>
    Write-Section 'Inline policies'

    $result = Invoke-AwsRead -Service 'iam' -Operation 'list-role-policies' `
        -Arguments @(
            '--role-name', $RoleName,
            '--query', 'PolicyNames',
            '--output', 'json'
        ) `
        -FailureMessage "Could not list inline policies for role '$RoleName'."

    $names = Get-AsArray -Value (ConvertFrom-AwsJson -Text $result.Output -What 'the inline policy list')
    $policies = New-Object System.Collections.Generic.List[object]

    if ($names.Count -eq 0) {
        Write-Finding -Severity 'Review' -Name 'No inline policy is present' `
            -Detail "the documented setup creates '$ExpectedInlinePolicyName'"
    }

    foreach ($name in $names) {
        $policyName = [string]$name

        $documentResult = Invoke-AwsRead -Service 'iam' -Operation 'get-role-policy' `
            -Arguments @(
                '--role-name', $RoleName,
                '--policy-name', $policyName,
                '--query', 'PolicyDocument',
                '--output', 'json'
            ) `
            -FailureMessage "Could not read inline policy '$policyName'."

        $document = ConvertFrom-PolicyDocument `
            -Document (ConvertFrom-AwsJson -Text $documentResult.Output -What "inline policy '$policyName'") `
            -What "inline policy '$policyName'"

        $expected = ($policyName -eq $ExpectedInlinePolicyName)
        $severity = 'Review'
        if ($expected) { $severity = 'Pass' }
        Write-Finding -Severity $severity -Name "Resolved inline policy: $policyName" `
            -Detail $(if ($expected) { 'the documented secret-read policy' } else { 'not part of the documented setup' })

        $policies.Add([pscustomobject]@{
                Name         = $policyName
                Kind         = 'inline'
                IsAwsManaged = $false
                VersionId    = 'n/a'
                Document     = $document
                Source       = 'inline'
                Expected     = $expected
            })
    }

    return $policies
}

# ---------------------------------------------------------------------------
# Stage 5 -- classify and assess
# ---------------------------------------------------------------------------

function Get-ActionCategory {
    param([Parameter(Mandatory = $true)][string]$Action)

    $lower = $Action.ToLowerInvariant()
    if ($lower -eq '*') { return 'Other' }

    foreach ($entry in $ActionCategories) {
        foreach ($prefix in $entry.Prefixes) {
            if ($lower.StartsWith($prefix)) { return [string]$entry.Category }
        }
    }
    return 'Other'
}

function Test-ActionVerb {
    <#
    .SYNOPSIS
        Does an action's operation part begin with one of these verbs?

    .DESCRIPTION
        Matching on the operation rather than the whole string matters:
        'secretsmanager:GetSecretValue' contains 'get', but a naive substring
        test for 'put' against 'iam:PutRolePolicy' and against
        'lambda:GetFunctionUrlConfig' behaves quite differently. The service
        prefix is dropped first, then the verb is matched at the start.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string[]]$Verbs
    )

    $parts = $Action -split ':', 2
    if ($parts.Count -lt 2) { return $false }

    $operation = $parts[1].ToLowerInvariant()
    foreach ($verb in $Verbs) {
        if ($operation.StartsWith($verb.ToLowerInvariant())) { return $true }
    }
    return $false
}

function Get-ResourceScope {
    <#
    .SYNOPSIS
        Describe a statement's resource breadth without reproducing an ARN.

    .DESCRIPTION
        This is where requirement 14 lives. A Resource of '*' is not one thing:
        on logs: it is what the AWS-managed basic execution policy grants and is
        expected, while on secretsmanager: it is a finding. So breadth is
        returned as a description and the caller decides what it means in its own
        category. Returning a boolean 'isWildcard' would force every category to
        the same verdict, which is exactly the false failure the requirement
        warns about.
    #>
    param([Parameter(Mandatory = $false)]$Resource)

    $values = Get-AsArray -Value $Resource
    if ($values.Count -eq 0) { return 'unspecified' }

    $anyWildcard = $false
    $anyPartial = $false
    $matchesSecret = $false

    foreach ($value in $values) {
        $text = [string]$value
        if ($text -eq '*') { $anyWildcard = $true; continue }
        if ($text -match '\*') { $anyPartial = $true }

        if (-not [string]::IsNullOrWhiteSpace($script:ExpectedSecretArn)) {
            # Secrets Manager appends a six-character suffix to the ARN, so the
            # documented grant ends in '-*'. Compare on the stem.
            $stem = $script:ExpectedSecretArn -replace '.{7}$', ''
            if ($text -eq $script:ExpectedSecretArn) { $matchesSecret = $true }
            elseif ($stem.Length -gt 0 -and $text.StartsWith($stem)) { $matchesSecret = $true }
        }
    }

    if ($anyWildcard) { return 'wildcard' }
    if ($matchesSecret) { return 'expected secret' }
    if ($anyPartial) { return 'prefix-scoped' }
    return 'scoped'
}

function Test-PolicyStatements {
    <#
    .SYNOPSIS
        Classify every action and assess it against the expected posture.
    #>
    param(
        [Parameter(Mandatory = $true)]$Policies,
        [Parameter(Mandatory = $true)]$Secret
    )

    Write-Section 'Effective permissions'

    $script:PermissionFindings = New-Object System.Collections.Generic.List[object]
    $categoryCounts = [ordered]@{}
    foreach ($entry in $ActionCategories) { $categoryCounts[[string]$entry.Category] = 0 }
    $categoryCounts['Other'] = 0

    $actionCount = 0
    $statementCount = 0
    $denyCount = 0

    foreach ($policy in $Policies) {
        $document = $policy.Document
        $label = "$($policy.Name) [$($policy.Kind)]"

        if (-not (Test-HasProperty -Object $document -Name 'Statement')) {
            Add-Finding -Severity 'Fail' -Title 'Policy has no Statement array' -Where $label
            continue
        }

        foreach ($statement in (Get-AsArray -Value $document.Statement)) {
            $statementCount++

            $effect = 'Allow'
            if (Test-HasProperty -Object $statement -Name 'Effect') {
                $effect = [string]$statement.Effect
            }

            # NotAction and NotResource invert the meaning of a statement. In an
            # Allow they grant everything except what is listed, which is the
            # opposite of enumerable least privilege.
            if (Test-HasProperty -Object $statement -Name 'NotAction') {
                Add-Finding -Severity 'Fail' -Title 'Statement uses NotAction' -Where $label `
                    -Correction 'Replace NotAction with an explicit Action list.'
            }
            if (Test-HasProperty -Object $statement -Name 'NotResource') {
                Add-Finding -Severity 'Fail' -Title 'Statement uses NotResource' -Where $label `
                    -Correction 'Replace NotResource with an explicit Resource list.'
            }
            if (Test-HasProperty -Object $statement -Name 'Principal') {
                $principalText = ($statement.Principal | ConvertTo-Json -Depth 10 -Compress)
                $severity = 'Review'
                $title = 'Permission policy contains a Principal'
                if ($principalText -match '"\*"' -or $principalText -eq '"*"') {
                    $severity = 'Fail'
                    $title = 'Permission policy contains Principal "*"'
                }
                Add-Finding -Severity $severity -Title $title -Where $label `
                    -Correction 'Principal belongs in a resource or trust policy, not an identity policy.'
            }

            if ($effect -eq 'Deny') {
                $denyCount++
                # A Deny cannot grant anything, so it is recorded and not judged.
                continue
            }

            $scope = Get-ResourceScope -Resource $(
                if (Test-HasProperty -Object $statement -Name 'Resource') { $statement.Resource } else { $null })

            $actions = Get-AsArray -Value $(
                if (Test-HasProperty -Object $statement -Name 'Action') { $statement.Action } else { $null })

            if ($actions.Count -eq 0) {
                Add-Finding -Severity 'Review' -Title 'Allow statement grants no action' -Where $label
            }

            foreach ($rawAction in $actions) {
                $action = [string]$rawAction
                $actionCount++
                $lower = $action.ToLowerInvariant()

                $category = Get-ActionCategory -Action $action
                $categoryCounts[$category] = [int]$categoryCounts[$category] + 1

                # --- Structural findings, independent of category -------------
                if ($lower -eq '*') {
                    Add-Finding -Severity 'Fail' -Title 'Action "*" grants every action' -Where $label `
                        -Correction 'Replace with the specific actions the function needs.'
                    continue
                }

                if ($lower -match '^[a-z0-9-]+:\*$') {
                    Add-Finding -Severity 'Fail' -Title "Service-wide wildcard action: $action" -Where $label `
                        -Correction 'Name individual actions instead of a service wildcard.'
                    continue
                }

                if ($lower -eq 'iam:passrole') {
                    Add-Finding -Severity 'Fail' -Title 'iam:PassRole is granted' -Where $label `
                        -Correction 'Remove iam:PassRole. An execution role passes no roles.'
                    continue
                }

                if ($lower -eq 'sts:assumerole') {
                    Add-Finding -Severity 'Fail' -Title 'sts:AssumeRole is granted' -Where $label `
                        -Correction 'Remove sts:AssumeRole. The function assumes no other role.'
                    continue
                }

                # Checked before the category switch, because several of these
                # services fall through to 'Other' rather than into a named
                # category. Recording it here and then skipping the switch keeps
                # one action from producing two findings that say the same thing.
                $isUnrelated = $false
                foreach ($prefix in $UnrelatedServicePrefixes) {
                    if ($lower.StartsWith($prefix)) { $isUnrelated = $true; break }
                }
                if ($isUnrelated) {
                    Add-Finding -Severity 'Fail' `
                        -Title "Unrelated service permission: $action" -Where $label `
                        -Correction 'Remove. This service is not in the V1 data path.'
                    continue
                }

                # --- Category assessment --------------------------------------
                switch ($category) {
                    'CloudWatch Logs' {
                        if ($ExpectedLogActions -contains $lower) {
                            # Requirement 14: the AWS-managed basic execution
                            # policy scopes CreateLogGroup broadly. That is the
                            # normal, expected shape and must not read as a
                            # failure just because a wildcard appears.
                            if ($scope -eq 'wildcard' -and -not $policy.IsAwsManaged) {
                                Add-Finding -Severity 'Review' `
                                    -Title "Log write on unrestricted resource: $action" -Where $label `
                                    -Correction 'Scope to this function''s log group where practical.'
                            }
                        }
                        else {
                            Add-Finding -Severity 'Review' `
                                -Title "Log action beyond writing this function's logs: $action" -Where $label
                        }
                    }

                    'Secrets Manager' {
                        if (Test-ActionVerb -Action $action -Verbs $SecretWriteVerbs) {
                            Add-Finding -Severity 'Fail' `
                                -Title "Secrets Manager write or administrative action: $action" -Where $label `
                                -Correction 'Remove. The function reads one secret and never manages it.'
                        }
                        elseif ($ExpectedSecretActions -contains $lower) {
                            if ($scope -eq 'expected secret') {
                                # Exactly the documented grant.
                            }
                            elseif ($scope -eq 'wildcard') {
                                Add-Finding -Severity 'Fail' `
                                    -Title "$action is granted on every secret" -Where $label `
                                    -Correction 'Scope Resource to the one expected secret ARN.'
                            }
                            else {
                                Add-Finding -Severity 'Review' `
                                    -Title "$action is scoped to something other than the expected secret" -Where $label `
                                    -Correction 'Confirm the resource is the intended secret.'
                            }
                        }
                        else {
                            Add-Finding -Severity 'Review' `
                                -Title "Unexpected Secrets Manager action: $action" -Where $label
                        }
                    }

                    'KMS' {
                        if (Test-ActionVerb -Action $action -Verbs $KmsAdminVerbs) {
                            Add-Finding -Severity 'Fail' `
                                -Title "KMS administrative action: $action" -Where $label `
                                -Correction 'Remove. The function uses a key; it does not manage one.'
                        }
                        elseif ($lower -eq 'kms:decrypt') {
                            if (-not $Secret.UsesCustomerKey) {
                                Add-Finding -Severity 'Review' `
                                    -Title 'kms:Decrypt is granted but the secret uses the AWS-managed key' -Where $label `
                                    -Correction 'Remove kms:Decrypt; Secrets Manager decrypts under its own key.'
                            }
                            elseif ($scope -eq 'wildcard') {
                                Add-Finding -Severity 'Fail' `
                                    -Title 'kms:Decrypt is granted on every key' -Where $label `
                                    -Correction 'Scope to the single key encrypting the expected secret.'
                            }
                        }
                        else {
                            Add-Finding -Severity 'Review' -Title "Unexpected KMS action: $action" -Where $label
                        }
                    }

                    'Lambda' {
                        if (Test-ActionVerb -Action $action -Verbs $LambdaAdminVerbs) {
                            Add-Finding -Severity 'Fail' `
                                -Title "Lambda administrative action: $action" -Where $label `
                                -Correction 'Remove. The execution role must not administer the function.'
                        }
                        elseif ($lower -match 'functionurl') {
                            Add-Finding -Severity 'Fail' `
                                -Title "Function URL permission: $action" -Where $label `
                                -Correction 'Remove. Function URL administration is administrator-only.'
                        }
                        else {
                            Add-Finding -Severity 'Review' `
                                -Title "Lambda permission on the execution role: $action" -Where $label `
                                -Correction 'An execution role normally needs no lambda: permissions.'
                        }
                    }

                    'IAM and STS' {
                        if (Test-ActionVerb -Action $action -Verbs $IamWriteVerbs) {
                            Add-Finding -Severity 'Fail' `
                                -Title "IAM write action: $action" -Where $label `
                                -Correction 'Remove. This is a privilege-escalation path.'
                        }
                        else {
                            Add-Finding -Severity 'Review' `
                                -Title "IAM or STS read action: $action" -Where $label `
                                -Correction 'Remove unless the function genuinely inspects IAM.'
                        }
                    }

                    'API Gateway and WAF' {
                        Add-Finding -Severity 'Fail' `
                            -Title "API Gateway or WAF permission: $action" -Where $label `
                            -Correction 'Remove. Both are administered outside the function.'
                    }

                    'CloudFormation' {
                        Add-Finding -Severity 'Fail' `
                            -Title "CloudFormation permission: $action" -Where $label `
                            -Correction 'Remove. The function deploys nothing.'
                    }

                    'Storage and database' {
                        Add-Finding -Severity 'Fail' `
                            -Title "Storage or database permission: $action" -Where $label `
                            -Correction 'Remove. V1 persists nothing, by boundary.'
                    }

                    'Networking' {
                        Add-Finding -Severity 'Fail' `
                            -Title "Networking permission: $action" -Where $label `
                            -Correction 'Remove unless the function is moved into a VPC.'
                    }

                    default {
                        Add-Finding -Severity 'Fail' `
                            -Title "Permission outside every expected category: $action" -Where $label `
                            -Correction 'Remove, or justify and document it.'
                    }
                }
            }
        }
    }

    # Report the categories, then the findings. A category with a count of zero
    # is a positive result and is worth showing.
    foreach ($category in $categoryCounts.Keys) {
        $count = [int]$categoryCounts[$category]
        $severity = 'Pass'
        if ($count -gt 0 -and $category -notin @('CloudWatch Logs', 'Secrets Manager', 'KMS')) {
            $severity = 'Fail'
        }
        Write-Finding -Severity $severity -Name "$category actions: $count"
    }

    foreach ($finding in $script:PermissionFindings) {
        Write-Finding -Severity ([string]$finding.Severity) -Name ([string]$finding.Title) `
            -Detail ([string]$finding.Where)
    }

    if ($script:PermissionFindings.Count -eq 0) {
        Write-Finding -Severity 'Pass' -Name 'No least-privilege finding' `
            -Detail 'every granted action matched the expected posture'
    }

    return [pscustomobject]@{
        Findings       = $script:PermissionFindings
        CategoryCounts = $categoryCounts
        ActionCount    = $actionCount
        StatementCount = $statementCount
        DenyCount      = $denyCount
        Severity       = (Get-WorstSeverity -Severities @($script:PermissionFindings | ForEach-Object { $_.Severity }))
    }
}

# ---------------------------------------------------------------------------
# Review -- written only after every stage completed
# ---------------------------------------------------------------------------

function Test-ReviewRedacted {
    <#
    .SYNOPSIS
        Refuse to write a review that leaks anything.

    .DESCRIPTION
        The review exists to be pasted into a task report, so it is scanned
        before it is written rather than after. Fail closed: a match means no
        file, not a file with a warning at the top.

        The expected secret name is included in the pattern list. It is the one
        value a caller supplies that is a live identifier, and the whole point of
        taking it as a parameter rather than a constant is that it never lands in
        a tracked or shared file.
    #>
    param([Parameter(Mandatory = $true)][string]$Content)

    $patterns = @(
        '\b\d{12}\b',
        'arn:aws',
        'https?://',
        'AKIA[0-9A-Z]{16}',
        '\bASIA[0-9A-Z]{16}',
        '\bAWS_SECRET',
        '\bAWS_SESSION_TOKEN\b',
        '\bGG_API_KEY\b',
        '\bX-GG-Key\b',
        '\.lambda-url\.',
        'execute-api'
    )

    foreach ($pattern in $patterns) {
        if ($Content -match $pattern) { return $false }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedSecretName)) {
        if ($Content -match [regex]::Escape($ExpectedSecretName)) { return $false }
    }

    return $true
}

function New-ReviewFile {
    param(
        [Parameter(Mandatory = $true)]$Trust,
        [Parameter(Mandatory = $true)]$Permissions,
        [Parameter(Mandatory = $true)]$Policies,
        [Parameter(Mandatory = $true)]$Secret,
        [Parameter(Mandatory = $true)][string]$Verdict,
        [Parameter(Mandatory = $true)][string]$Directory
    )

    if (-not $script:StagesCompleted) {
        Stop-Run -Message 'Refusing to write a review before every audit stage completed.'
    }

    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $fileStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path $Directory "phase1g-execution-role-audit-$fileStamp.md"

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Phase 1G - Lambda execution role audit')
    $lines.Add('')
    $lines.Add("Generated: $stamp")
    $lines.Add("Region: $Region")
    $lines.Add("Role audited: $RoleName")
    $lines.Add("Function: $FunctionName")
    $lines.Add('')
    $lines.Add("**Overall: $Verdict**")
    $lines.Add('')
    $lines.Add('This audit is read-only. No IAM role, policy, function, or secret was')
    $lines.Add('created, modified, or deleted, and no secret value was read. Findings are')
    $lines.Add('reported for an administrator to act on; the script applies no correction.')
    $lines.Add('')
    $lines.Add('Resource scope is reported as an assessment rather than as an ARN, so this')
    $lines.Add('review carries no account ID, ARN, secret identifier, or URL and can be')
    $lines.Add('pasted into a task report as-is.')
    $lines.Add('')

    $lines.Add('## Stages')
    $lines.Add('')
    $lines.Add('| Stage | Result |')
    $lines.Add('| --- | --- |')
    $lines.Add("| Function healthy and role confirmed | $(ConvertTo-Classification -Severity 'Pass') |")
    $lines.Add("| Expected secret resolved (metadata only) | $(ConvertTo-Classification -Severity 'Pass') |")
    $lines.Add("| Trust policy | $(ConvertTo-Classification -Severity $Trust.Severity) |")
    $lines.Add("| Effective permissions | $(ConvertTo-Classification -Severity $Permissions.Severity) |")
    $lines.Add('')

    $lines.Add('## Policies inspected')
    $lines.Add('')
    $lines.Add('| Policy | Type | Version |')
    $lines.Add('| --- | --- | --- |')
    foreach ($policy in $Policies) {
        $lines.Add("| $($policy.Name) | $($policy.Kind) | $($policy.VersionId) |")
    }
    if (@($Policies).Count -eq 0) {
        $lines.Add('| (none) | - | - |')
    }
    $lines.Add('')
    $lines.Add("Secret encryption: $($Secret.KeyDescription).")
    $lines.Add('')

    $lines.Add('## Permission categories')
    $lines.Add('')
    $lines.Add('| Category | Actions |')
    $lines.Add('| --- | --- |')
    foreach ($category in $Permissions.CategoryCounts.Keys) {
        $lines.Add("| $category | $([int]$Permissions.CategoryCounts[$category]) |")
    }
    $lines.Add('')
    $lines.Add("Statements: $($Permissions.StatementCount). Actions: $($Permissions.ActionCount). Deny statements: $($Permissions.DenyCount).")
    $lines.Add('')

    $allFindings = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $Trust.Findings) { $allFindings.Add($finding) }
    foreach ($finding in $Permissions.Findings) { $allFindings.Add($finding) }

    $failCount = @($allFindings | Where-Object { $_.Severity -eq 'Fail' }).Count
    $reviewCount = @($allFindings | Where-Object { $_.Severity -eq 'Review' }).Count

    $lines.Add('## Findings')
    $lines.Add('')
    $lines.Add("$(ConvertTo-Classification -Severity 'Fail'): $failCount. $(ConvertTo-Classification -Severity 'Review'): $reviewCount.")
    $lines.Add('')

    if ($allFindings.Count -eq 0) {
        $lines.Add('None. Every granted action matched the expected least-privilege posture.')
        $lines.Add('')
    }
    else {
        $lines.Add('| Severity | Finding | Where |')
        $lines.Add('| --- | --- | --- |')
        foreach ($finding in $allFindings) {
            $label = ConvertTo-Classification -Severity ([string]$finding.Severity)
            $where = ''
            if (Test-HasProperty -Object $finding -Name 'Where') { $where = [string]$finding.Where }
            $lines.Add("| $label | $([string]$finding.Title) | $where |")
        }
        $lines.Add('')

        $corrections = @($allFindings |
                Where-Object { (Test-HasProperty -Object $_ -Name 'Correction') -and -not [string]::IsNullOrWhiteSpace($_.Correction) })

        if ($corrections.Count -gt 0) {
            $lines.Add('## Least-privilege corrections')
            $lines.Add('')
            $lines.Add('An administrator applies these. This script never does.')
            $lines.Add('')
            foreach ($finding in $corrections) {
                $lines.Add("- **$([string]$finding.Title)** -- $([string]$finding.Correction)")
            }
            $lines.Add('')
        }
    }

    $lines.Add('## Expected posture, for reference')
    $lines.Add('')
    $lines.Add('- CloudWatch Logs write permissions for this function.')
    $lines.Add('- Secrets Manager read on the single expected secret, and nothing else.')
    $lines.Add('- KMS decrypt only if that secret uses a customer-managed key.')
    $lines.Add('- No Secrets Manager write or administrative action.')
    $lines.Add('- No IAM write, no iam:PassRole, no sts:AssumeRole.')
    $lines.Add('- No Lambda, Function URL, API Gateway, WAF, or CloudFormation permission.')
    $lines.Add('- No S3, DynamoDB, SQS, SNS, EC2, or networking permission.')
    $lines.Add('')

    $content = ($lines -join [Environment]::NewLine)

    if (-not (Test-ReviewRedacted -Content $content)) {
        Stop-Run -Message @"
The generated review matched a redaction pattern, so it was NOT written.

This is the intended behaviour: the review is scanned before it is saved, and a
match produces no file rather than a file with a warning. Report the audit
verdict from the terminal output instead.
"@
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $content, $utf8NoBom)

    $script:ReviewFile = $path
    return $path
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'Phase 1G - Lambda execution role audit' -ForegroundColor White
Write-Host 'Read-only. Reports findings and stops. Changes nothing.' -ForegroundColor DarkGray

try {
    $null = Get-CallerAccountId
    $null = Get-FunctionRoleName
    $secret = Get-ExpectedSecret
    $trust = Test-TrustPolicy

    $policies = New-Object System.Collections.Generic.List[object]
    foreach ($policy in (Get-AttachedPolicyDocuments)) { $policies.Add($policy) }
    foreach ($policy in (Get-InlinePolicyDocuments)) { $policies.Add($policy) }

    $permissions = Test-PolicyStatements -Policies $policies -Secret $secret

    $overall = Get-WorstSeverity -Severities @($trust.Severity, $permissions.Severity)
    $verdict = ConvertTo-Classification -Severity $overall

    # Every stage returned. Only now may a review be written.
    $script:StagesCompleted = $true

    Write-Section 'Verdict'
    Write-Finding -Severity $overall -Name "Execution role audit: $verdict"

    Write-Section 'Review'
    $tempRoot = $env:TEMP
    if ([string]::IsNullOrWhiteSpace($tempRoot)) {
        $tempRoot = [System.IO.Path]::GetTempPath()
    }

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
    $resolvedRepo = [System.IO.Path]::GetFullPath($repoRoot)
    if ($resolvedTemp.StartsWith($resolvedRepo, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Run -Message @"
TEMP resolves to a path inside the repository.

The review would be written into the checkout and could be committed. Point TEMP
somewhere outside the repository and re-run.
"@
    }

    $reviewPath = New-ReviewFile -Trust $trust -Permissions $permissions `
        -Policies $policies -Secret $secret -Verdict $verdict -Directory $resolvedTemp

    Write-Host "  Written: $reviewPath" -ForegroundColor Green

    if ($overall -eq 'Fail') { $script:ExitCode = 2 }
}
catch {
    Write-Host ''
    [Console]::Error.WriteLine((Hide-Sensitive -Text $_.Exception.Message))
    $script:ExitCode = 1
}

Write-Host ''
if ([string]::IsNullOrWhiteSpace($script:ReviewFile)) {
    Write-Host 'Audit did not complete. No review was written.' -ForegroundColor Red
    Write-Host 'Nothing was changed -- this script only ever reads.' -ForegroundColor DarkGray
}
else {
    Write-Host 'Audit complete. Nothing was changed.' -ForegroundColor Green
    Write-Host "Review: $($script:ReviewFile)"

    if ($NoOpen) {
        Write-Host 'Not opened (-NoOpen).' -ForegroundColor DarkGray
    }
    else {
        try {
            Start-Process notepad.exe -ArgumentList $script:ReviewFile
        }
        catch {
            Write-Host 'Could not open an editor; the path is above.' -ForegroundColor DarkGray
        }
    }
}

exit $script:ExitCode
