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
      * It never deletes, resets, checks out over, or force-updates anything.

    It exists so that retrieving a report is one command rather than a sequence
    of PowerShell blocks pasted into a console by hand.

.PARAMETER Branch
    Required. The task branch, e.g. phase1e-api-gateway-design. If a local
    branch of that name exists it is used; otherwise a tracking branch is
    created from origin.

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
$ErrorActionPreference = 'Stop'

function Stop-WithMessage {
    param([string]$Message)
    Write-Error $Message
    exit 1
}

function Invoke-Git {
    param([string[]]$Arguments, [string]$FailureMessage)

    $output = & git @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Stop-WithMessage "$FailureMessage`n$output"
    }
    return $output
}

# --- Locate the repository ------------------------------------------------
# Resolve from the script's own location so the command works from any
# directory, not only the repository root.

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path (Join-Path $repoRoot '.git'))) {
    Stop-WithMessage "Not a Git repository: $repoRoot"
}
Set-Location $repoRoot

# --- Refuse to touch a dirty working tree ---------------------------------
# Checked before anything else. Nothing below is worth risking uncommitted
# work for.

$status = & git status --porcelain
if ($LASTEXITCODE -ne 0) {
    Stop-WithMessage 'Could not read Git status.'
}
if (-not [string]::IsNullOrWhiteSpace(($status | Out-String).Trim())) {
    Write-Host 'Working tree is not clean:' -ForegroundColor Yellow
    $status | ForEach-Object { Write-Host "  $_" }
    Stop-WithMessage @'
Commit or stash your changes before running this script.
Nothing was changed. No branch was switched and no file was modified.
'@
}

# --- Fetch -----------------------------------------------------------------

Write-Host "Fetching origin..." -ForegroundColor Cyan
Invoke-Git -Arguments @('fetch', 'origin') -FailureMessage 'git fetch origin failed.'

# --- Switch to the branch --------------------------------------------------
# Existing local branch, or a new tracking branch from origin. Never a force
# checkout.

$localExists = $false
& git show-ref --verify --quiet "refs/heads/$Branch"
if ($LASTEXITCODE -eq 0) { $localExists = $true }

if ($localExists) {
    Write-Host "Switching to local branch '$Branch'..." -ForegroundColor Cyan
    Invoke-Git -Arguments @('switch', $Branch) `
        -FailureMessage "Could not switch to '$Branch'."
}
else {
    & git show-ref --verify --quiet "refs/remotes/origin/$Branch"
    if ($LASTEXITCODE -ne 0) {
        Stop-WithMessage @"
Branch '$Branch' does not exist locally or on origin.
Check the name, or run 'git fetch origin' if it was pushed just now.
Nothing was changed.
"@
    }
    Write-Host "Creating tracking branch '$Branch' from origin..." -ForegroundColor Cyan
    Invoke-Git -Arguments @('switch', '--track', "origin/$Branch") `
        -FailureMessage "Could not create a tracking branch for '$Branch'."
}

# --- Fast-forward only -----------------------------------------------------
# --ff-only is deliberate: it can add commits but never rewrite them, so a
# divergent branch stops here rather than being merged or rebased silently.

Write-Host 'Pulling (fast-forward only)...' -ForegroundColor Cyan
$pull = & git pull --ff-only 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ($pull | Out-String) -ForegroundColor Yellow
    Stop-WithMessage @"
git pull --ff-only failed. The local branch has diverged from origin.

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
