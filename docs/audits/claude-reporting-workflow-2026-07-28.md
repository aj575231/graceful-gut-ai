# Claude task reporting workflow

**Date:** 2026-07-28
**Outcome:** `SUCCESS`
**Branch:** `chore/claude-report-workflow`
**Starting commit:** `302d97c` (`main`, fast-forwarded from origin before branching)
**Implementation commits:**
- `f4606ffe5a1f75df881eb45375d0055ff77cce71` — *Standardize Claude task reporting workflow*
- `9f59676a6a721726f42261f943e88a387272ad76` — *Fix PowerShell Git stderr handling*

**Report commits:** `85b0ee3` — *Document reporting workflow*; `837481b` — *Document report helper compatibility fix*; and the commit adding the Windows validation section below — *Record Windows report-helper validation*

This report is redacted by construction: no credential, password, token, API
key, secret value, secret identifier, account ID, instance ID, full ARN, private
URL, authorization header, health text, PHI, or personal identifying information
appears anywhere in it.

---

## Task objective

Create a permanent reporting workflow for every future Graceful Gut AI task: a
mandatory report protocol in `CLAUDE.md`, a Windows helper for retrieving
reports, and static tests locking both in. Repository workflow only.

---

## Outcome

`SUCCESS`. The protocol is written, the helper exists, thirty tests enforce
both, and all gates pass.

The helper was subsequently found to have a **Windows PowerShell failure** and
was corrected — see *Correction: PowerShell Git stderr handling* below.

That correction has since been **executed and confirmed on Windows**. The
previously recorded blocker — that the helper had never been run on its target
platform — is **closed**. See *Windows validation* below.

---

## Files changed

### Modified

| File | Change |
| --- | --- |
| `CLAUDE.md` | New section: **Mandatory Task Completion Report Protocol**, plus helper usage |

### Added

| File | Purpose |
| --- | --- |
| `scripts/pull-task-report.ps1` | Windows helper — fetch a task branch and open its report. Corrected for Windows PowerShell; see below |
| `backend/tests/test_reporting_workflow.py` | 30 static guards — 19 over the protocol and helper, 11 over the PowerShell correction |
| `docs/audits/claude-reporting-workflow-2026-07-28.md` | This report |

### Deleted

None.

**No application code was modified.** `backend/app/` is untouched, so the Lambda
package is unchanged and `CodeSha256` is unaffected.

---

## Work completed

### The protocol

Added to `CLAUDE.md` as a top-level section, applying to every future task
**unless the user explicitly overrides it**. Silence is not an override.

| Part | Requirement |
| --- | --- |
| **A** | A report is always written — including when a task partially succeeds, is blocked, fails verification, or changes no code at all |
| **B** | Location: the task-supplied path, else `docs/audits/<task-slug>-YYYY-MM-DD.md`. Update an existing report rather than duplicating it |
| **C** | Seventeen required fields, from outcome and starting commit through AWS resources touched, decisions needed, and whether the branch was pushed |
| **D** | Redaction by construction — never credentials, tokens, keys, secret values or identifiers, account or instance IDs, full ARNs, private URLs, authorization headers, health text, PHI, or PII |
| **E** | Implementation committed separately from the report; report last; a blocked task still commits a report; no unrelated changes; push after verification; never merge to `main` unless instructed |
| **F** | Final terminal response is at most **10 short lines** and must not reproduce the report |
| **G** | On push failure: keep the report locally, state the exact path and the precise blocker, do not print the report instead |

Two clarifications are load-bearing:

**Commit SHAs and hashes are not secrets.** Stated explicitly, because a
redaction list read too literally would strip the audit trail — `CodeSha256`
against a commit is precisely how a running deployment is tied back to source.

**"Nothing to report" is not a valid outcome.** A task that changed no code
still records what was investigated and why nothing changed. That is the case
where a missing report is most costly, because there is no diff to infer it
from later.

### Why the report, not the transcript

Recorded in `CLAUDE.md` itself so the rule carries its reason: the session that
did the work is not the durable record. A terminal transcript is lost, scrolled
past, or read by someone who was not there. The report is what an
administrator, a clinician, or a future session actually reads — which is also
why part F forbids pasting the report back into the terminal. Duplicating a long
document into the transcript buries the few lines the user needs to act on.

### The helper

`scripts/pull-task-report.ps1`, with `-Branch` (mandatory), `-ReportPath`
(optional), and `-NoOpen`.

Safety properties, in the order the script applies them:

1. **Refuses a dirty working tree** — checked before anything else, because
   switching branches over uncommitted changes is how work gets lost.
2. **`git pull --ff-only`** — a fast-forward can add commits but never rewrite
   or discard them. A divergent branch stops the script with the comparison
   command, rather than being merged or rebased silently. The decision about
   which history to keep stays with the user.
3. **Invokes nothing destructive** — no `reset`, `clean`, `push`, `rebase`,
   force flag, or file removal.

It also resolves the repository from the script's own location so it works from
any directory, creates a tracking branch only when no local branch exists,
copies the path to the clipboard when `Set-Clipboard` is available, and opens
Notepad unless `-NoOpen` is given. Clipboard absence is handled rather than
fatal — `Set-Clipboard` does not exist in every host.

It carries no credentials, secrets, account identifiers, or URLs; it needs only
the Git remote the repository is already configured with.

---

## Tests and exact results

Nineteen tests were added with the original helper, taking the suite from 92 to
**111**. The PowerShell correction added eleven more, for **30** tests in
`backend/tests/test_reporting_workflow.py` and **122** in the suite. The
correction's tests are listed in its own section below.

| Requirement | Tests |
| --- | --- |
| `CLAUDE.md` contains the protocol | `test_claude_md_contains_the_reporting_protocol`, `test_protocol_applies_unless_explicitly_overridden` |
| All four outcomes covered | `test_all_four_outcomes_are_covered` |
| Report required even with no code changes | `test_report_required_for_every_result_including_no_code_changes` |
| Location and duplication rules | `test_report_location_convention_is_specified`, `test_duplicate_reports_are_discouraged` |
| Required fields and redaction | `test_required_report_fields_are_enumerated`, `test_redaction_list_is_complete`, `test_commit_hashes_are_explicitly_not_secrets` |
| Commit behaviour | `test_commit_behaviour_is_specified` |
| Full report prohibited from the terminal | `test_full_report_is_prohibited_from_the_final_response`, `test_failed_push_does_not_licence_printing_the_report` |
| Helper exists | `test_powershell_helper_exists` |
| Helper carries no credentials or secrets | `test_helper_contains_no_credentials_or_project_secrets` |
| Helper uses `--ff-only` | `test_helper_pulls_fast_forward_only` |
| Helper checks for a dirty tree | `test_helper_checks_for_a_dirty_working_tree` |
| Helper supports `-Branch`, `-ReportPath`, `-NoOpen` | `test_helper_supports_the_documented_parameters` |
| Helper invokes nothing destructive | `test_helper_never_force_updates_or_deletes` |
| Usage documented | `test_helper_usage_is_documented_in_claude_md` |

Assertions match the protocol **section**, not the whole file, so they cannot
pass on unrelated prose elsewhere in `CLAUDE.md`. The destructive-command test
matches git *invocations* rather than bare words — the helper's own error text
mentions pushing, and a substring check flagged it as a false positive during
development.

### Gate results

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 111 passed (19 new) |
| `.venv/bin/ruff check backend/` | **PASS** |
| `.venv/bin/ruff format --check backend/` | **PASS** — 13 files formatted |
| `git diff --check` | **PASS** — no whitespace errors |

---

## Deployment status

**Not deployed.** This task changes repository workflow only. No build was
produced and no code was uploaded.

---

## AWS resources created, read, modified, or deleted

**None.** Zero AWS API calls of any kind. Nothing was deployed, IAM was not
modified, Secrets Manager was not accessed, no secret value was requested or
handled, and the live Function URL was not touched.

The only commands run were local: `git`, `pytest`, `ruff`, and file writes.

---

## Security and privacy checks

| Check | Result |
| --- | --- |
| Helper contains no credential names | **PASS** — asserted by test |
| Helper contains no secret-shaped values | **PASS** — no 32+ character hex runs |
| Helper contains no account IDs | **PASS** — no twelve-digit sequences |
| Helper contains no ARNs or private URLs | **PASS** |
| Helper cannot destroy local work | **PASS** — no destructive Git invocation |
| Protocol forbids secrets in reports | **PASS** — full redaction list asserted |
| Application behaviour unchanged | **PASS** — `backend/app/` untouched |
| This report redacted | **PASS** — scanned before commit |

---

## Correction: PowerShell Git stderr handling

**Correction commit:** `9f59676a6a721726f42261f943e88a387272ad76` — *Fix PowerShell Git stderr handling*

### The failure

The helper stopped on Git commands that had **succeeded**. It invoked Git as:

```powershell
$output = & git @Arguments 2>&1
```

under a script-scope `$ErrorActionPreference = 'Stop'`.

Windows PowerShell 5.1 converts a native command's stderr into `ErrorRecord`
objects when `2>&1` is used. Under a `Stop` preference the first such record
becomes a terminating `NativeCommandError`. Git writes a great deal of ordinary
successful output to stderr — `Switched to branch 'chore/claude-report-workflow'`
is written there, as is fetch and pull progress — so the helper died on a
command Git had exited `0` from.

This was not limited to `git switch`. `fetch` and `pull` write progress to
stderr on every run, so the wrapper itself had to be fixed regardless.

### The correction

| Change | Effect |
| --- | --- |
| Exit code is the only success signal | `$LASTEXITCODE`, never the presence of stderr text |
| `$ErrorActionPreference = 'Continue'` for the duration of the call | A stderr line is data, not a terminating error |
| `$PSNativeCommandUseErrorActionPreference = $false` where it exists | PowerShell 7.3+ does not turn a nonzero exit into a terminating error from the other direction |
| Both restored in a **`finally`** block | The wrapper cannot leak its own settings into the caller's session, even if Git throws |
| Merged stderr flattened to plain text | Diagnostics read as Git wrote them |
| `Invoke-GitOrStop` reports the message **and** the exit code | A genuine failure still fails clearly |
| Fatal messages written to `[Console]::Error` | `Write-Error` under a `Stop` preference raises a terminating error and buries the message in an exception trace instead of exiting cleanly |
| Current branch detected with `rev-parse` | An unnecessary `git switch` is skipped when the branch is already checked out |

The last item is worth having but is **not** the fix. The wrapper was the fault.

### What was deliberately not changed

- The **dirty-working-tree check** still runs first and still stops the script.
- The pull is still **`--ff-only`**.
- Nothing is deleted, reset, force-updated, or **stashed**.
- The `-Branch`, `-ReportPath`, and `-NoOpen` interface is unchanged.

### Tests added

Eleven, taking the suite from 111 to **122**:

| Test | Asserts |
| --- | --- |
| `test_git_is_judged_by_exit_code_not_stderr` | Success is read from `$LASTEXITCODE` |
| `test_error_action_preference_is_not_stop_at_script_scope` | The original cause cannot return |
| `test_native_command_preferences_are_made_permissive_for_the_call` | Both preferences are handled |
| `test_changed_preferences_are_restored_in_a_finally_block` | No preference leaks to the caller |
| `test_nonzero_exit_still_fails_with_diagnostics` | A real failure still fails, with the exit code |
| `test_write_error_is_not_used_for_fatal_messages` | Matched as an invocation, not a comment |
| `test_current_branch_detection_avoids_unnecessary_switching` | `rev-parse` guard present |
| `test_dirty_tree_check_is_not_weakened` | The guard still runs and still stops |
| `test_local_work_is_never_stashed_or_discarded` | No `git stash`, no force checkout |
| `test_fast_forward_only_pull_is_retained` | `--ff-only` retained |
| `test_documented_parameters_survive_the_fix` | Interface unchanged |

Three earlier assertions were matching Git invocations as bare strings
(`"git status --porcelain"`, `"git pull"`) and one matched `Write-Error` as a
bare word. The rewrite moved to array argument form, and the helper's comments
legitimately mention `Write-Error` while explaining why it is avoided. All four
now match commands rather than prose — the same false-positive class that
appeared twice in the Phase 1E review.

### Gate results after the correction

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 122 passed (11 new) |
| `.venv/bin/ruff check backend/` | **PASS** |
| `.venv/bin/ruff format --check backend/` | **PASS** — 13 files formatted |
| `git diff --check` | **PASS** |
| PowerShell structure | **PASS** — braces and parentheses balanced; no here-string terminator indented, which would be a parse error |

### Verified on Windows

At the time the correction was written, no PowerShell interpreter existed on
this Linux host, so the script was verified statically and by thirty content
assertions but had not been run. **That has since been done on Windows and the
correction holds.** The results are recorded in *Windows validation* below.

---

## Windows validation

The helper was executed on the target Windows platform. **Both the normal
retrieval paths and the dirty-working-tree refusal path passed.** This closes
the only blocker this task carried.

The run was performed by AJ on Windows and reported back to this session; the
results below are recorded as received. No PowerShell was executed on this Linux
host, which has no interpreter.

### Results

| Path exercised | Result |
| --- | --- |
| Explicit `-ReportPath` workflow | **PASS** — branch retrieved and the named report resolved |
| Automatic newest-report discovery with `-NoOpen` | **PASS** — most recent report under `docs/audits/` selected, path printed, no editor opened |
| `NativeCommandError` on successful Git commands | **NONE** — the original failure did not recur |
| Deliberately dirty working tree | **PASS** — helper refused to proceed and exited **nonzero** |
| Temporary probe file used to dirty the tree | Removed |
| Windows working tree after the run | Clean |

### What this confirms

**The stderr fix works on the platform it was written for.** The failure being
corrected was specific to how Windows PowerShell converts a native command's
stderr into `ErrorRecord` objects; no amount of static assertion could settle
it. `git fetch`, `git switch`, and `git pull` all write ordinary progress to
stderr, and none of them terminated the script.

**The safety guarantee is real, not just asserted.** The dirty-tree check was
the property most worth proving by execution, because a helper that switched
branches over uncommitted work would destroy exactly what it was written to
protect. It refused, and it refused with a nonzero exit status — so a caller
that chains on it stops rather than continuing against a half-completed run.
The probe file was removed and the tree left clean, so the check was exercised
without leaving residue.

**Both report-selection paths work.** The explicit `-ReportPath` form and the
newest-file fallback were each exercised; a failure in either would have made
the helper useless for its one purpose.

### Scope of this validation

This was a functional run of the retrieval paths, not an exhaustive matrix. Not
exercised: a divergent branch hitting the `--ff-only` failure, a missing branch
name, a missing report path, or a host without `Set-Clipboard`. Each of those is
covered by static assertion only. They are lower-risk — all three failure paths
stop the script rather than modify anything — but they remain unproven by
execution, and this report should not be read as saying otherwise.

### Gate results for this update

This update changes documentation only — no application code, no test, no
script, and no configuration was touched — so the gates are a regression check
rather than a verification of new behaviour.

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 122 passed, 0 failed (no tests added or changed) |
| `.venv/bin/ruff check backend/` | **PASS** — all checks passed |
| `.venv/bin/ruff format --check backend/` | **PASS** — 13 files already formatted |
| `git diff --check` | **PASS** — no whitespace errors |

---

## Blockers and unresolved findings

**None. The one blocker this task carried is closed.**

It was: *the PowerShell helper had not been executed*, because no PowerShell
interpreter exists on this Linux host. That was the same class of gap as the
documented Python 3.12/3.13 mismatch — the authority on whether it works is a
run on the target platform, not this host. The run has now happened on Windows
and both the normal paths and the dirty-tree refusal path passed, so the gap is
closed by execution rather than by assertion. See *Windows validation* above.

The residual, recorded rather than outstanding: the `--ff-only` divergence
path, the missing-branch path, the missing-report path, and clipboard absence
are still covered by static assertion only. All four stop the script instead of
modifying anything, so none of them can lose work — they are noted for accuracy,
not as pending items.

No other unresolved findings.

---

## Decisions required from AJ or Jenna

None. This task implements an instruction rather than choosing between options.

The decisions outstanding from earlier phases are unchanged and still open —
twelve from the Phase 1E ADR, including the two launch-blocking ones (legal and
compliance determination, and the model-provider data-flow determination).

---

## Recommended next step

1. **Merge `chore/claude-report-workflow` to `main`**, so the protocol applies
   to every subsequent task. This is now the top item: the Windows run was the
   last thing gating it, and it passed. Not done here — merging requires
   explicit instruction.
2. Note that `phase1e-api-gateway-design` is a separate unmerged branch. This
   branch was taken from `main` and does not contain it; the two do not
   conflict, but both are outstanding.

---

## Branch push

`chore/claude-report-workflow` was pushed to `origin` after verification. Push
status is recorded in the final terminal response.

Nothing was merged to `main`.
