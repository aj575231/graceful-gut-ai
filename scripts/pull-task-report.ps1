<#
.SYNOPSIS
    Fetch a Claude task branch and open its completion report.

.DESCRIPTION
    Every task in this repository writes a Markdown report under docs/audits/
    (see "Mandatory Task Completion Report Protocol" in CLAUDE.md). This script
    is the Windows-side counterpart: it moves the working copy to the task
    branch and opens the report, without ever putting local work at risk.

    Safety properties, in order of importance:

      * It refuses to run against a dirty working tree. Switching branches with
        uncommitted changes is how work gets lost, so the check comes first.
      * It uses `git pull --ff-only`. A fast-forward can add commits but can
        never rewrite or discard them, so a divergent branch fails loudly
        instead of being silently merged or rebased.
      * It never deletes, resets, checks out over, force-updates, or stashes
        anything.

    It exists so that retrieving a report is one command rather than a sequence
    of PowerShell blocks pasted into a console by hand.

.PARAMETER Branch
    Required. The task branch, e.g. phase1e-api-gateway-design. If it is
    already checked out, no switch is performed. If a local branch of that name
    exists it is used; otherwise a tracking branch is created from origin.

.PARAMETER ReportPath
    Optional. Repo-relative path to the report. When omitted, the most recently
    modified Markdown file under docs/audits/ is selected.

.PARAMETER NoOpen
    Print the report path without opening an editor.

.EXAMPLE
    .\scripts\pull-task-report.ps1 -Branch phase1e-api-gateway-design

.EXAMPLE
    .\scripts\pull-task-report.ps1 `
      -Branch phase1e-api-gateway-design `
      -ReportPath docs/audits/phase1e-api-gateway-design-2026-07-28.md

.NOTES
    Contains no credentials, secrets, account identifiers, or URLs. It needs
    only the Git remote the repository is already configured with.

    Compatible with Windows PowerShell 5.1 and PowerShell 7. See Invoke-Git for
    why native Git output needs care in both.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Branch,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath,

    [Parameter(Mandatory = $false)]
    [switch]$NoOpen
)

Set-StrictMode -Version Latest

# $ErrorActionPreference is deliberately NOT set to 'Stop' at script scope.
# Doing so is what broke this helper on Windows PowerShell 5.1 -- see Invoke-Git
# below. Failures are detected explicitly, from exit codes.

function Stop-WithMessage {
    param([string]$Message)

    # Written straight to the error stream rather than through Write-Error,
    # which under a 'Stop' preference raises a terminating error and buries the
    # message in an exception trace instead of exiting cleanly.
    [Console]::Error.WriteLine($Message)
    exit 1
}

function Invoke-Git {
    <#
    .SYNOPSIS
        Run Git and judge it by its exit code alone.

    .DESCRIPTION
        Git writes a great deal of ordinary, successful output to stderr:
        "Switched to branch 'x'", fetch and pull progress, "Already up to
        date." on some paths. None of it indicates failure.

        Windows PowerShell 5.1 converts a native command's stderr into
        ErrorRecord objects when 2>&1 is used. With $ErrorActionPreference set
        to 'Stop', the first such record becomes a terminating
        NativeCommandError -- so a Git command that exited 0 kills the script
        purely for having printed a status line. PowerShell 7.3+ adds
        $PSNativeCommandUseErrorActionPreference, which can turn a nonzero exit
        into a terminating error too.

        Both preferences are therefore set to a permissive value for the
        duration of the call and restored in a finally block, so this function
        cannot leak its own settings into the caller's session even if Git
        throws. The exit code is the single source of truth.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $previousErrorAction = $ErrorActionPreference

    $nativePreference = Get-Variable -Name 'PSNativeCommandUseErrorActionPreference' `
        -Scope Global -ErrorAction SilentlyContinue
    $hasNativePreference = $null -ne $nativePreference
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

        $captured = & git @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
        if ($hasNativePreference) {
            Set-Variable -Name 'PSNativeCommandUseErrorActionPreference' `
                -Scope Global -Value $previousNativePreference
        }
    }

    # Merged stderr arrives as ErrorRecord objects; flatten to plain text so
    # diagnostics read as Git wrote them.
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

function Invoke-GitOrStop {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    $result = Invoke-Git -Arguments $Arguments
    if (-not $result.Succeeded) {
        Stop-WithMessage @"
$FailureMessage

git exit code: $($result.ExitCode)
$($result.Output)
"@
    }
    return $result
}

# --- Locate the repository ------------------------------------------------
# Resolved from the script's own location so the command works from any
# directory, not only the repository root.

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $repoRoot '.git'))) {
    Stop-WithMessage "Not a Git repository: $repoRoot"
}
Set-Location $repoRoot

# --- Refuse to touch a dirty working tree ---------------------------------
# Checked before anything else. Nothing below is worth risking uncommitted
# work for. Never stashed, never discarded -- the user is told, and stops.

$status = Invoke-GitOrStop -Arguments @('status', '--porcelain') `
    -FailureMessage 'Could not read Git status.'

if (-not [string]::IsNullOrWhiteSpace($status.Output)) {
    Write-Host 'Working tree is not clean:' -ForegroundColor Yellow
    $status.Output -split "`n" | ForEach-Object { Write-Host "  $_" }
    Stop-WithMessage @'
Commit or stash your changes before running this script.
Nothing was changed. No branch was switched and no file was modified.
'@
}

# --- Fetch -----------------------------------------------------------------
# Writes progress to stderr on every run. Judged by exit code only.

Write-Host 'Fetching origin...' -ForegroundColor Cyan
Invoke-GitOrStop -Arguments @('fetch', 'origin') `
    -FailureMessage 'git fetch origin failed.' | Out-Null

# --- Switch to the branch, if not already on it ----------------------------

$current = Invoke-GitOrStop -Arguments @('rev-parse', '--abbrev-ref', 'HEAD') `
    -FailureMessage 'Could not determine the current branch.'
$currentBranch = $current.Output.Trim()

if ($currentBranch -eq $Branch) {
    Write-Host "Already on '$Branch'; no switch needed." -ForegroundColor DarkGray
}
else {
    $localRef = Invoke-Git -Arguments @(
        'show-ref', '--verify', '--quiet', "refs/heads/$Branch")

    if ($localRef.Succeeded) {
        Write-Host "Switching to local branch '$Branch'..." -ForegroundColor Cyan
        Invoke-GitOrStop -Arguments @('switch', $Branch) `
            -FailureMessage "Could not switch to '$Branch'." | Out-Null
    }
    else {
        $remoteRef = Invoke-Git -Arguments @(
            'show-ref', '--verify', '--quiet', "refs/remotes/origin/$Branch")

        if (-not $remoteRef.Succeeded) {
            Stop-WithMessage @"
Branch '$Branch' does not exist locally or on origin.
Check the name, or re-run if it was pushed just now.
Nothing was changed.
"@
        }

        Write-Host "Creating tracking branch '$Branch' from origin..." -ForegroundColor Cyan
        Invoke-GitOrStop -Arguments @('switch', '--track', "origin/$Branch") `
            -FailureMessage "Could not create a tracking branch for '$Branch'." | Out-Null
    }
}

# --- Fast-forward only -----------------------------------------------------
# --ff-only is deliberate: it can add commits but never rewrite them, so a
# divergent branch stops here rather than being merged or rebased silently.

Write-Host 'Pulling (fast-forward only)...' -ForegroundColor Cyan
$pull = Invoke-Git -Arguments @('pull', '--ff-only')
if (-not $pull.Succeeded) {
    Write-Host $pull.Output -ForegroundColor Yellow
    Stop-WithMessage @"
git pull --ff-only failed (exit code $($pull.ExitCode)).
The local branch has most likely diverged from origin.

Nothing was changed and no commit was lost. Resolve it yourself, so the
decision about which history to keep stays with you:
  git log --oneline --graph HEAD origin/$Branch
"@
}

# --- Select the report -----------------------------------------------------

if ($PSBoundParameters.ContainsKey('ReportPath') -and
    -not [string]::IsNullOrWhiteSpace($ReportPath)) {

    $resolved = Join-Path $repoRoot $ReportPath
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        Stop-WithMessage @"
Report not found on branch '$Branch': $ReportPath
The branch was switched and updated successfully; only the report path is wrong.
"@
    }
    $reportFile = Get-Item -LiteralPath $resolved
}
else {
    $auditsDir = Join-Path $repoRoot 'docs/audits'
    if (-not (Test-Path -LiteralPath $auditsDir)) {
        Stop-WithMessage "No docs/audits directory on branch '$Branch'."
    }

    $reportFile = Get-ChildItem -LiteralPath $auditsDir -Filter '*.md' -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $reportFile) {
        Stop-WithMessage "No Markdown reports found under docs/audits on '$Branch'."
    }
    Write-Host 'No -ReportPath given; selected the most recent report.' -ForegroundColor DarkGray
}

$relativePath = $reportFile.FullName.Substring($repoRoot.Length).TrimStart('\', '/')

Write-Host ''
Write-Host 'Report: ' -NoNewline -ForegroundColor Green
Write-Host $relativePath
Write-Host 'Full:   ' -NoNewline -ForegroundColor Green
Write-Host $reportFile.FullName

# --- Clipboard (best effort) ----------------------------------------------
# Set-Clipboard is absent in some hosts and remote sessions. Its absence must
# not fail the run.

if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
    try {
        Set-Clipboard -Value $reportFile.FullName
        Write-Host 'Path copied to clipboard.' -ForegroundColor DarkGray
    }
    catch {
        Write-Host 'Clipboard unavailable; path shown above.' -ForegroundColor DarkGray
    }
}

# --- Open ------------------------------------------------------------------

if ($NoOpen) {
    Write-Host 'Not opened (-NoOpen).' -ForegroundColor DarkGray
}
else {
    try {
        Start-Process notepad.exe -ArgumentList $reportFile.FullName
    }
    catch {
        Write-Host 'Could not open Notepad; the path is shown above.' -ForegroundColor Yellow
    }
}

exit 0
