# Phase 1G — Lambda execution-role audit tooling

**Date:** 2026-07-29, updated 2026-07-29 after the first administrator run,
updated 2026-07-30 after the second, again 2026-07-30 after the runtime harness
run, and again 2026-07-30 after the first successful harness run and live audit
**Outcome:** `PARTIAL` — tooling built, tested, committed, and **corrected four
times**: twice after failed administrator runs, once after a failed runtime
harness run, and once after the first **successful** harness run and live audit
exposed two defects that no crash could have surfaced. The corrected script has
not been rerun, so Phase 1G is **not** closed.
**First administrator audit attempt:** **INCOMPLETE.** It failed partway through
with a PowerShell collection-handling defect, wrote no review, and changed
nothing. See "Update — first administrator run was INCOMPLETE" below.
**Second administrator audit attempt:** **INCOMPLETE.** Caller identity passed;
the function stage then failed with `The function configuration query returned
fewer fields than expected.` Exit code `1`, no review written, no AWS resource
changed, no secret value read. See "Update 2 — second administrator run was
INCOMPLETE".
**Runtime harness run by AJ (Windows PowerShell 5.1):** **FAILED.** All six
scenarios reached their expected parsing and audit stages; D and E passed fully;
A, B, C and F reached **correct verdicts** and then failed during review
generation with `Argument types do not match`, writing no review and returning
exit `1`. Every AWS call went to the fake CLI, no real AWS call occurred, no
secret-value operation was attempted, and no review was written inside the
repository. See "Update 3 — runtime harness FAILED in review generation".
**Second runtime harness run by AJ:** **PASSED.** All scenarios reached their
expected verdicts, review generation worked, and no diagnostic was printed.
**First completed live execution-role audit:** **SUCCESS**, and it exposed two
defects that no crash could have surfaced — the terminal and the written review
disagreed about the same run, and the expected inline-policy name was one that
had never been deployed. The role itself resolved cleanly, with the secret grant
correctly scoped to a single secret. Both defects are corrected here; **no IAM
was changed**. See "Update 4" at the end.
**The audit itself:** **PERFORMED, but through the logic this update replaces.**
Finding **G1** is **substantially answered and formally open**: the corrected
script has **not** been rerun, by AJ or here.
**Branch:** `phase1g-lambda-execution-role-audit`

This report is redacted by construction. No account ID, instance ID, full ARN,
API ID, live Function URL, production domain, secret identifier, credential, or
secret value appears anywhere in it. Git commit SHAs are not secrets and are
recorded deliberately.

---

## Task objective

Create a fail-closed, read-only Windows administrator workflow for auditing the
existing `GracefulGutAI-LambdaExecutionRole` before the Phase 1F infrastructure
stack is deployed.

---

## Why this finding needed tooling rather than an afternoon

It has been carried since Phase 1D, through 1E and 1F, and each report recorded
it as unresolved "for want of credentials". That framing was accurate but
incomplete, and it is worth stating precisely because it explains why the answer
is a script and not a session:

`GracefulGutAI-ClaudeDevRole` holds `iam:GetRole` and `iam:PassRole` on this one
role and **nothing else**. It has no `iam:ListAttachedRolePolicies`, no
`iam:ListRolePolicies`, no `iam:GetRolePolicy`, no `iam:GetPolicy`, no
`iam:GetPolicyVersion`, and no `secretsmanager:` actions at all. So the role's
policies are not merely inconvenient to read from this host — they are
unreadable, by design, and that design is deliberate: Phase 1D moved the secret
out of the function's environment precisely so a session that can deploy code
cannot also read the live key or the grants that reach it.

The audit therefore has to run somewhere else, with credentials this host must
never hold. What this host **can** do is make that run correct, repeatable, and
safe — which is what was built.

---

## Constraints, and how each was met

| Constraint | Status |
| --- | --- |
| Repository work only | **Met** |
| No AWS call of any kind | **Met** — zero calls. Not `sts get-caller-identity`, not a `describe`, not a `get` |
| No deployment | **Met** |
| No IAM modification | **Met** — no IAM call at all, and the script cannot make one |
| No secret value retrieved | **Met** — no call, and the script refuses the operation by name |
| No API key retrieved | **Met** |
| Lambda function not modified | **Met** |
| Function URL not modified | **Met** |
| Not merged to `main` | **Met** |

Commands run were local only: `git`, `pytest`, `ruff`, `python`, and file writes.

---

## Commits

| Role | Commit | Message |
| --- | --- | --- |
| Starting point | `1515684` | *Record approved Phase 1F owner decisions* |
| Implementation and tests | `9bc7356` | *Build Phase 1G execution-role audit tooling* |
| This report | the final commit on the branch | *Document Phase 1G execution-role audit tooling* |

A report cannot quote its own hash, so the row above names the commit rather than
reproducing it.

---

## Files

### Added

| File | Contents |
| --- | --- |
| `scripts/audit-lambda-execution-role.ps1` | The read-only administrator audit: caller and function checks, trust-policy audit, full policy resolution, permission classification, least-privilege assessment, redacted review |
| `backend/tests/test_phase1g_execution_role_audit.py` | 90 static guards over that script |
| `docs/audits/phase1g-lambda-execution-role-audit-2026-07-29.md` | This report |

### Modified

| File | Change |
| --- | --- |
| `docs/audits/phase1f-api-gateway-foundation-2026-07-28.md` | The carried-forward execution-role finding now records that Phase 1G tooling exists. It is **still marked open** |

### Deleted

None.

**No application code was modified.** `backend/app/` is untouched, so the Lambda
package is unchanged and `CodeSha256` is unaffected. No template, no IAM policy
document, and no other script was changed.

---

## What the script does

Nine read calls, in five stages, then a review.

| Stage | Calls | What it establishes |
| --- | --- | --- |
| Caller | `sts get-caller-identity` | Credentials resolve. The account ID is read **only** so it can be masked out of output, and is never printed |
| Function | `lambda get-function-configuration` | The function is `Active` with `LastUpdateStatus` `Successful`, and its configured execution role **is** the role being audited |
| Expected secret | `secretsmanager describe-secret` | The secret's ARN and KMS key, so Secrets Manager and KMS grants can be judged against the right resource. Metadata only |
| Trust policy | `iam get-role` | Who may assume the role |
| Policies | `iam list-attached-role-policies`, `iam get-policy`, `iam get-policy-version`, `iam list-role-policies`, `iam get-role-policy` | Every attached and inline policy document, resolved in full |

### Read-only is enforced, not promised

Every AWS call goes through one wrapper, `Invoke-AwsRead`, which takes the
service and operation as separate parameters and checks the pair against
`$ReadOnlyOperations` **before the process starts**. Two gates, in this order:

1. **The forbidden list.** `secretsmanager:get-secret-value` and
   `secretsmanager:batch-get-secret-value` are named and refused first, so an
   attempt to read the secret fails with that specific reason rather than a
   generic "not allow-listed". This audit establishes *who may read* the secret.
   It never reads it.
2. **The allow-list.** Anything absent is refused. A mutating call cannot be
   added to this script and quietly work — it fails on the first run, before it
   reaches AWS.

There is exactly one raw AWS CLI invocation in the file, inside that wrapper. A
second would bypass both gates, and a test counts them.

### It corrects nothing

Where the role is wrong, the script prints the least-privilege correction an
administrator would apply, and stops. The review carries a
**Least-privilege corrections** section headed *"An administrator applies these.
This script never does."*

An audit tool that repairs what it audits destroys the evidence of what was
wrong, and removes the human decision about whether the current state was
intentional. Both matter more here than convenience: this is the role that
reaches the shared secret.

### Least-privilege posture it assesses against

| Expected | Not expected |
| --- | --- |
| CloudWatch Logs write for this function | Secrets Manager write or administrative actions |
| Secrets Manager read on the **single** expected secret | IAM write, `iam:PassRole`, `sts:AssumeRole` |
| KMS decrypt **only if** that secret uses a customer-managed key | Lambda or Function URL administration |
| | API Gateway or WAF administration |
| | CloudFormation permissions |
| | S3, DynamoDB, SQS, SNS, EC2, or networking permissions |

Actions are classified into the ten categories the task specified — CloudWatch
Logs, Secrets Manager, KMS, Lambda, IAM and STS, API Gateway and WAF,
CloudFormation, storage and database, networking, and other — and a count is
reported per category, including the zeroes. A category at zero is a positive
result and is worth showing.

Structural findings are flagged independently of category: `Action "*"`,
service-wide wildcards, `NotAction`, `NotResource`, `Principal "*"` in an
identity policy, `iam:PassRole`, `sts:AssumeRole`, and any unrelated service.

---

## Three judgement calls, stated rather than buried

### 1. `Resource: "*"` is assessed per category, not globally

This is the task's requirement 14, and it is the difference between a useful
audit and one that fails on every correctly configured role.

The AWS-managed `AWSLambdaBasicExecutionRole` grants `logs:CreateLogGroup` on a
broad log resource. That is the normal shape of a working Lambda role. A checker
that treated every `"*"` identically would report a failure on the single most
common, entirely correct configuration — and an audit that cries wolf on the
default gets switched off.

So `Get-ResourceScope` returns a **description** — `wildcard`,
`expected secret`, `prefix-scoped`, `scoped` — rather than a boolean, and each
category decides what that breadth means for itself. A wildcard on `logs:` in an
AWS-managed policy is expected and silent; a wildcard on `secretsmanager:` is a
hard failure. Returning a boolean would have forced both to the same verdict.

### 2. `kms:Decrypt` is judged against the secret's actual key

Under the AWS-managed key (`alias/aws/secretsmanager`, or no key recorded),
Secrets Manager decrypts on the caller's behalf and the role needs **no** KMS
grant at all. Under a customer-managed key it needs `kms:Decrypt` scoped to that
key.

Those are opposite verdicts on the same permission, so the script resolves
`KmsKeyId` from `describe-secret` before assessing KMS. Judging it without that
would either invent a finding on a correct role or miss a real one.

### 3. An inline policy is expected, not suspicious

`CLAUDE.md` has an administrator create the secret grant with
`iam put-role-policy --policy-name GracefulGutAI-ReadApiKeySecret`. That is an
**inline** policy, so its presence is part of the documented setup rather than a
deviation. The script treats that one name as expected and flags any other inline
policy for review.

Treating all inline policies as findings would have produced a guaranteed false
positive on a correctly built role — the same class of error as the wildcard
question above.

> **Superseded by Update 4 (2026-07-30).** The judgement call above holds — one
> named inline policy is expected and any other is a review — but the name it
> picked was wrong. `GracefulGutAI-ReadApiKeySecret` was read out of an
> administrator *instruction* and mistaken for a record of what had been run.
> The deployed policy is `GracefulGutAI-SecretAccess`, and this expectation is
> exactly why the first successful live audit flagged the correct role. See
> "Update 4" below.

---

## Redaction is by construction

| Risk | How it is handled |
| --- | --- |
| Environment variable values, including `GG_API_SECRET_ID` | **Never fetched.** The function configuration is queried server-side for three fields only, so `Environment.Variables` never enters the process. Stronger than masking it afterwards |
| The role ARN | **Never printed.** The role is compared by **name**; the ARN carries the account ID and stays out of all output |
| The account ID | Read once, so it can be masked. Never printed |
| Resource ARNs | Reported as an **assessment** — "scoped to the expected secret", "wildcard" — never as a literal ARN. This is what lets the review be both useful and shareable |
| `ExpectedSecretName` | Mandatory with no default, so it is never committed. Masked out of all output, and the pre-write scan rejects a review containing it |
| The finished review | Scanned **before** it is written, against twelve patterns. A match writes **no file** — not a file with a warning on top |
| The review's location | `%TEMP%` only, and the run refuses if `%TEMP%` resolves inside the checkout |

The masking order is deliberate: the expected secret name first (it appears both
inside ARNs and in plain error text), then ARNs, then bare account IDs — so the
account ID inside an ARN is covered by the ARN rule rather than leaving a
half-masked ARN behind. A test pins the ordering.

---

## Verification results

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 491 passed, 0 failed, 0 skipped (401 before this task, 90 added) |
| `backend/tests/test_phase1g_execution_role_audit.py` alone | **PASS** — 90 passed |
| `.venv/bin/ruff check backend/` | **PASS** — all checks passed |
| `.venv/bin/ruff format backend/` | 1 file reformatted |
| `.venv/bin/ruff format --check backend/` | **PASS** — 18 files already formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| AWS calls made | **Zero** |
| PowerShell syntax parse | **Not run** — no PowerShell interpreter on this host |
| Script executed | **No, not by this host** — deliberately; it needs administrator credentials this host does not hold. AJ ran it once on Windows and it failed partway through. See the update at the end |

Python 3.13 coverage is CI's, not the local venv's, as `CLAUDE.md` records.

### The 90 tests, and why they are shaped this way

The script cannot be executed here, so the tests are static. The weak version of
that is a keyword search, which proves almost nothing. The strongest guards here
instead **parse the script's own declarations and check them against each other**:

| Guard | How it works |
| --- | --- |
| Read-only | `$ReadOnlyOperations` is parsed out of the script — not duplicated in the test — and every `Invoke-AwsRead` call site is extracted. Every call site must be on the list, **and** every list entry must be a read verb, **and** every list entry must actually be used |
| No mutation | Every `-Operation` argument is checked against a list of mutating CLI verb prefixes |
| One route to AWS | Exactly one raw `aws` invocation may exist, inside the wrapper |
| Ordering | The forbidden-list check must precede the allow-list check; the allow-list check must precede the invocation; the review scan must precede the write; the completion flag must be set after the last stage and before the review |

Adding a mutating call fails the call-site test. Adding it to the allow-list too
fails the read-verb test. There is no third path.

### The tests were mutation-tested

A static suite that never fails is indistinguishable from no suite. Four
deliberate defects were injected and each was caught by the intended test:

| Injected defect | Caught by |
| --- | --- |
| A mutating call site (`iam attach-role-policy`) | `test_every_aws_call_site_is_on_the_allow_list`, `test_no_mutating_aws_cli_verb_is_invoked` |
| `secretsmanager:get-secret-value` added to the allow-list | `test_the_allow_list_is_exactly_the_specified_reads`, `test_neither_secret_read_operation_is_on_the_allow_list` |
| The role ARN printed to the terminal | `test_the_role_arn_is_never_printed` |
| The review written before the redaction scan | `test_the_review_is_scanned_before_it_is_written` |

The script was restored byte-identical afterwards and re-verified.

### Two defects in my own work, caught and fixed

Both are recorded because they are the kind of thing that otherwise ships:

| Defect | How it was caught | Fix |
| --- | --- | --- |
| The script's `.EXAMPLE` blocks carried a **live secret identifier** — exactly what taking it as a mandatory parameter was supposed to prevent | The Phase 1G redaction test | Replaced with a `<secret-name>` placeholder |
| The repository-wide scan flagged **its own detector fixtures** | The scan itself, on first run | The fixtures are now assembled from fragments, so the matchable literal never appears while the module stays **in scope** for the scan. Exempting the module would have made the file most likely to contain a realistic identifier the one file nobody checks |

Three further first-run failures were my own test bugs — a `# Main` anchor that
does not survive comment-stripping, and an `-AllowFailure` occurrence count that
was simply wrong — and were fixed rather than relaxed.

### One deliberate scoping decision in the redaction tests

The repository-wide scan forbids real account IDs, account-bearing ARNs, access
keys, and live endpoint hosts in **every** tracked file, and the repository is
clean on all four.

The stricter rule — no secret identifier at all — is applied to the **Phase 1G
files only**. `CLAUDE.md` records the secret *name* deliberately and treats it as
"an identifier, not a credential" that belongs in function configuration and
deployment scripts. That is a pre-existing, documented decision and is consistent
with the reporting protocol's separate rule about reports. Changing it was not
this task's call, and silently ignoring the difference would have been worse than
scoping the test and saying so.

---

## Deployment status

**Not deployed.** Nothing was uploaded, no stack was created, no change set was
created, and `CodeSha256` is unchanged because no application code was modified.

---

## AWS resources created, read, modified, or deleted

**None. Zero AWS API calls were made during this task.**

No IAM role, policy, or policy attachment was created, modified, or deleted. No
secret was created, described, or read. No Lambda function or Function URL was
touched. The script that will make read calls has never been run.

---

## Security and privacy checks

| Check | Result |
| --- | --- |
| No credential, token, or secret value in any added file | **PASS** — enforced by test |
| No secret identifier in the script, the tests, or this report | **PASS** — enforced by test; the first draft failed this and was fixed |
| No account ID or account-bearing ARN in any tracked file | **PASS** — enforced by repository-wide test |
| No access key or session token in any tracked file | **PASS** — enforced by test |
| No live Function URL or API host in any tracked file | **PASS** — enforced by test |
| The script cannot read a secret value | **PASS** — named on a forbidden list checked before the allow-list |
| The script cannot modify IAM | **PASS** — enforced at run time by the allow-list, and statically by four tests |
| The script cannot modify the function or its URL | **PASS** — same mechanism |
| Environment variable values never enter the process | **PASS** — server-side query of three fields |
| The role ARN is never printed | **PASS** — enforced by test |
| The review is scanned before it is written, and fails closed | **PASS** — enforced by test |
| The review never lands inside the checkout | **PASS** — `%TEMP%` only, refused if `%TEMP%` is inside the repository |
| No PHI, health text, or personal identifying information | **PASS** |
| Public free-text input still disabled | **PASS** — unchanged by this task |
| Merged to `main` | **No** |

---

## Blockers and unresolved findings

| # | Finding | Status |
| --- | --- | --- |
| **G1** | **The execution-role audit has not been performed.** This is the original Phase 1D finding and it is **still open** | The tooling exists and has been corrected after its first run. It closes when AJ reruns the script and supplies the review. **Do not record this finding as resolved before then** |
| **G2** | ~~The script has never been executed~~ → **it has now been run once, and it failed.** PowerShell is still not parsed on this host or in CI | The first run found a real defect, which is recorded and fixed in the update below. The unparsed-PowerShell half is finding **D** from Phase 1F, now covering three Windows helpers rather than two, and it is the gap that let this defect ship |
| **G3** | The expected-posture rules encode an assumption about what the role *should* hold | They follow `CLAUDE.md` and the Phase 1D design. If the role legitimately needs something else — a VPC attachment would need networking permissions — the script will report it as a finding, correctly, and the expectation is what needs updating |

Everything carried from Phase 1F remains open and unchanged: **L1** legal and
compliance, **L2** model-provider data flow, the **`X-GG-Key` replacement**,
**application boundary enforcement**, and **public production launch approval**.
Nothing in this task advanced or relaxed any of them.

---

## Decisions required from AJ or Jenna

**None to unblock this work.** One action is required, and it is not a decision:

| Item | Who | What |
| --- | --- | --- |
| Run the audit | **AJ** (owner decision F4 names AJ as the administrator) | `.\scripts\audit-lambda-execution-role.ps1 -ExpectedSecretName <secret-name>`, then paste the `%TEMP%` review into this report |

A decision only arises **if** the audit returns findings, at which point the
question is which corrections to apply. The script will have printed them; it
will not have applied any.

---

## Recommended next step

1. **AJ runs the script**, before the Phase 1F stack is deployed. It is read-only,
   changes nothing, and writes a redacted review under `%TEMP%`. Exit code `0`
   means `PASS`, `2` means at least one `FAIL`, `1` means the audit did not
   complete — and in that last case no review is written, deliberately.
2. **Paste the review into this report** and update finding **G1**. The review is
   written to be redacted already — no account ID, ARN, secret identifier, or URL
   — so it can be pasted as-is.
3. **Apply any corrections by hand**, deliberately, with the review as the record
   of what was changed and why.
4. **Then deploy the Phase 1F stack.** Auditing the execution role first is the
   cheaper order: the role is what the function uses to reach the secret, and a
   finding is easier to act on before there is an API in front of it.
5. Consider PowerShell parsing in CI (Phase 1F finding **D**). Three Windows
   helpers now exist and none is syntax-checked anywhere.

---

## Push

Implementation and tests committed separately from the reports, per the reporting
protocol. Both commits pushed to `origin/phase1g-lambda-execution-role-audit`.

**Nothing was merged to `main`.** Nothing was deployed. No AWS API call was made,
no IAM was modified, and no secret value was retrieved.

---
---

# Update — first administrator run was INCOMPLETE, script corrected

**Outcome of the first administrator audit attempt:** `INCOMPLETE`.
**Outcome of this session's work:** `SUCCESS` — defect found, fixed, and pinned.
**The audit:** still **NOT PERFORMED**. Finding **G1** remains **open**, and the
corrected script has **not yet been rerun by AJ**.

## What the first run actually did

Run on Windows by the administrator. Recorded exactly as reported:

| Stage | Result |
| --- | --- |
| Caller checks | **Passed** |
| Lambda state and role checks | **Passed** |
| Expected-secret metadata checks | **Passed** |
| Trust-policy checks | **Passed** |
| **Attached managed policies** | **Failed** — `The property 'Count' cannot be found on this object.` |

| Consequence | Result |
| --- | --- |
| Exit code | **1** |
| Review file | **None written** |
| AWS resources changed | **None** |
| Secret value read | **No** |
| Finding **G1** | **Still open** |

Four of the five stages passing is worth stating plainly: the caller resolved, the
function was confirmed `Active` and `Successful`, its configured execution role was
confirmed to be the role under audit, the expected secret resolved from metadata
alone, and the whole trust policy was audited. The defect is in the policy-
resolution plumbing, not in the audit's logic or its access model.

### The fail-closed design worked

This is the part that makes this a routine bug rather than an incident. Exit code
`1`, no review file, nothing changed — every one of the four safety properties held
under a failure that was never anticipated:

| Property | Held? |
| --- | --- |
| Exit non-zero when the audit cannot complete | **Yes** — `1` |
| Write no review after an incomplete audit | **Yes** — the `$script:StagesCompleted` gate was never reached |
| Never print `PASS` for an unfinished stage | **Yes** — the four completed stages reported their real results and nothing else did |
| Never apply a correction | **Yes** — the script has no mutating call to make |

Contrast the Phase 1F first attempt, which failed *and filed a review claiming
PASS*. That is the failure this design was built against, and here it behaved
correctly on the first try. A partial audit reported honestly as incomplete costs
one more run; a partial audit reported as a pass costs whatever is later built on
it.

## Root cause

**A PowerShell function cannot return an array by writing `return @($x)`.**

The return value travels through the pipeline, which *enumerates* it. A
one-element array arrives at the caller as the bare element. An empty array
arrives as nothing at all.

`Get-AsArray` existed for exactly one purpose — to guarantee that a value IAM
allows to be either a scalar or a list is always an array — and it ended with
`return @($Value)`. So it handed back a **scalar** whenever it was given one item
and **`$null`** whenever it was given none: precisely the two cases it was written
to eliminate. It defeated itself, and the helper's presence made every call site
*look* safe.

The audited role has a **single attached managed policy**, so the very first call
into the policy stage hit that path.

### Which line raised the error, honestly

Two adjacent effects follow from the same defect, and **which of them produced the
reported message cannot be determined from this host** — there is no PowerShell
interpreter here, and the run's output was a single line:

1. The outer one-element list of policies unwraps to the inner
   `[PolicyName, PolicyArn]` row. The loop then iterates over **fields rather than
   policies** — a silently wrong answer, not a crash.
2. Normalising one of those fields returns a bare string, and reading `.Count`
   from a scalar is what produces `The property 'Count' cannot be found on this
   object.`

A third path — a role with **zero** attached policies — was broken identically:
the empty return arrives as `$null`, and `$null.Count` raises the same error.

All three are defects of the same class, all three are fixed, and the distinction
does not change the repair. This report does not assert a line number it cannot
verify.

## The fix

Two independent layers, so a regression has to defeat both to reach an
administrator again.

| Layer | Change | Covers |
| --- | --- | --- |
| 1 | `Get-AsArray` now emits via **`Write-Output -NoEnumerate`**, which hands the array across the function boundary as a single object. Available since PowerShell 3.0, so 5.1 and 7 behave identically | The one-item and zero-item cases at the source |
| 2 | **Every call site wraps the result in `@(...)`** | The one-item case again, independently |

The `$null` case is handled **only** inside the helper, and deliberately so:
`@($null)` is a one-element array containing `$null`, so a call-site wrap cannot
fix it — it would turn "no policies" into "one null policy". The helper therefore
tests for `$null` *before* wrapping, and a test pins that ordering.

Two further defects of the same class were found by inspection and fixed at the
same time:

| Also fixed | Why it mattered |
| --- | --- |
| `Get-AttachedPolicyDocuments` and `Get-InlinePolicyDocuments` return a `List`, and `return $list` is enumerated by the pipeline exactly as `@()` was. Both call sites in `Main` are now wrapped | Latent: it happened to work because `foreach` tolerates a scalar, but it was the same bug waiting for a different use |
| The one index access without a preceding `Count` guard (`$fields[0]` in the secret stage) now has one | Indexing an unnormalised value fails the same way `.Count` does |

### StrictMode was not relaxed

The obvious way to make the error go away is `Set-StrictMode -Version 1.0`, and it
would have been wrong. StrictMode did not cause this defect; it **surfaced** it.
Without it, `$rows` silently becomes a scalar, the loop iterates over the wrong
things, and the audit reports that a role holds no policies worth flagging — which
is a false `PASS` on the one role in this system that reaches the shared secret.

A crash in a tool whose entire job is to be trusted is a far better outcome than a
confident wrong answer. A test now asserts StrictMode is still `Latest` and that
no relaxed variant appears anywhere in the file.

## Tests added

34 new guards, 124 total for Phase 1G. The script still cannot be executed here,
so the fix is pinned two ways.

### A model of the PowerShell semantics

A small model of the three behaviours involved — `@(...)`, pipeline enumeration on
return, and `.Count` under StrictMode — with the **original broken normaliser
included as a control**. The model reproduces the original failure, which is what
makes it evidence rather than decoration: a model that could not fail would prove
nothing about the fix.

| Modelled | Asserted |
| --- | --- |
| The broken normaliser on the one-policy shape | Unwraps to the inner row, so iteration yields fields not policies |
| The broken normaliser on a one-element list of a scalar | Returns a bare scalar, and `.Count` raises the reported error |
| The broken normaliser on nothing | Returns nothing, and `.Count` raises the reported error |
| `@($null)` | Has a `Count` of **1**, which is why the `$null` branch cannot live at the call site |
| The corrected pattern | Returns a real array of the right length for zero, one, and many |

### Zero, one, and many — for every shape the task named

| Shape | Cases |
| --- | --- |
| Attached managed policies | zero, one, many |
| Inline policies | zero, one, many |
| Statements | zero, one (the common shape of the inline secret grant), many |
| `Action` | scalar string, array |
| `Resource` | scalar string, array |
| `Principal.Service` | scalar, array |
| Findings and corrections | zero, one, many |

### Structural guards, including the requirement-9 scan

Every `.Count` receiver in the script is extracted and each must be provably one
of: an inline `@(...)` subexpression, a variable assigned **in the same function**
from `@(...)` or a generic `List`, or a named exemption with a recorded reason. Two
exemptions exist and both are justified in the test: `$Severities` is a
type-constrained `[string[]]` parameter, and `$parts` is assigned from the
`-split` operator, whose result is never pipeline-enumerated.

The scan is **scoped per function**, and that detail is the whole reason it works.
`$fields` and `$pair` are each a normalised array in one function and a plain
string in another. A whole-file search for their assignments mixes the two and
reports a false violation — which is exactly what the first version of this scan
did, on its first run, against the corrected script.

A companion test proves the rule can fail, by checking that a bare
`$rows = Get-AsArray -Value $thing` is rejected as unsafe while the wrapped form
is accepted.

### Mutation-tested again

| Injected defect | Caught by |
| --- | --- |
| Reverting `Get-AsArray` to `return @($Value)` | 3 tests, including the no-enumerate and null-ordering guards |
| Unwrapping the attached-policies call site | `test_every_normaliser_call_site_is_wrapped`, and the requirement-9 receiver scan |
| "Solving" it with `Set-StrictMode -Version 1.0` | `test_the_script_runs_under_strict_mode`, `test_strict_mode_was_not_disabled_to_solve_this` |
| Removing the new index guard | `test_every_index_access_is_guarded_by_a_count_check` |

The script was restored byte-identical after each, and the mutations were re-run
after `ruff format` to confirm the guards survived reformatting.

## What this says about the gap that let it ship

The original 90 tests were thorough about the script's **security** properties —
read-only enforcement, redaction, fail-closed ordering — and every one of those
held. They said nothing about whether the script would **run**, because a static
suite cannot execute PowerShell and the previous report recorded that limitation
as Phase 1F finding **D**.

That finding is no longer theoretical. It now has a concrete cost attached: one
failed administrator run. Three Windows helpers exist and none is syntax-checked
or executed anywhere before it reaches an administrator. The honest reading is
that the static tests were necessary and not sufficient, and the collection-shape
model added here is the closest a host without PowerShell can get to the missing
half.

## Verification results — after the fix

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 525 passed, 0 failed, 0 skipped (491 before this session, 34 added) |
| `backend/tests/test_phase1g_execution_role_audit.py` alone | **PASS** — 124 passed |
| `.venv/bin/ruff check backend/` | **PASS** — all checks passed |
| `.venv/bin/ruff format backend/` | 1 file reformatted |
| `.venv/bin/ruff format --check backend/` | **PASS** — 18 files already formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| AWS calls made by this session | **Zero** |
| Deployment | **Not performed** |
| PowerShell syntax parse | **Not run** — still no interpreter on this host |
| Corrected script executed | **No** — the rerun belongs to AJ |

## Files — this update

### Modified

| File | Change |
| --- | --- |
| `scripts/audit-lambda-execution-role.ps1` | `Get-AsArray` rewritten to use `Write-Output -NoEnumerate`; all 11 call sites wrapped in `@(...)`; both collection-returning resolvers wrapped in `Main`; one missing index guard added |
| `backend/tests/test_phase1g_execution_role_audit.py` | 34 guards added; one pre-existing test updated because the `[string]` branch it asserted is now correctly gone |
| `docs/audits/phase1g-lambda-execution-role-audit-2026-07-29.md` | This update, the header, and forward pointers on findings G1 and G2 |

No other file changed. No application code, no template, no IAM document, and no
other script. `backend/app/` is untouched and `CodeSha256` is unaffected.

## AWS resources created, read, modified, or deleted — this update

**None. Zero AWS API calls were made in this session.**

The administrator's own run made read calls only — the four completed stages — and
the failure occurred while reading. **No AWS resource was created, modified, or
deleted, and no secret value was read.** The script has no mutating call available
to it.

## Security and privacy checks — this update

| Check | Result |
| --- | --- |
| Read-only allow-list preserved, unchanged | **PASS** — still the same nine reads, enforced by `Invoke-AwsRead` |
| `get-secret-value` and `batch-get-secret-value` still forbidden | **PASS** — forbidden list unchanged and still checked first |
| No AWS mutation operation reachable | **PASS** — enforced at run time and by four static tests |
| Fail-closed behaviour preserved | **PASS** — all four properties re-asserted by test after the fix |
| StrictMode still `Latest` | **PASS** — enforced by test |
| No correction ever applied | **PASS** |
| No secret identifier, account ID, ARN, or URL in any changed file | **PASS** — enforced by the repository-wide scan |
| The reported error text quoted in this report | **Safe** — it is a PowerShell message and carries no identifier |
| Merged to `main` | **No** |

## Blockers and unresolved findings — this update

| # | Finding | Status |
| --- | --- | --- |
| **G1** | The execution-role audit has not been performed | **OPEN.** Unchanged. One failed run does not advance it, and neither does a fix. It closes when AJ reruns the script and supplies the review |
| **G2** | The script has now been run once and failed; PowerShell is still unparsed here and in CI | **OPEN**, and no longer theoretical — see the section above |
| **G3** | The expected-posture rules encode an assumption about what the role should hold | **OPEN.** Untouched by this fix |
| **G4** | **The corrected script is itself unexecuted.** The same limitation that let the first defect ship applies to the fix | **OPEN.** Mitigated as far as a host without PowerShell can: two independent layers, a semantics model that reproduces the original failure, a per-function scan over every `.Count`, and mutation testing. Not eliminated |

Everything carried from Phase 1F remains open and unchanged: **L1** legal and
compliance, **L2** model-provider data flow, the **`X-GG-Key` replacement**,
**application boundary enforcement**, and **public production launch approval**.

## Decisions required from AJ or Jenna — this update

**None.** One action is required and it is not a decision: rerun the corrected
script.

## Recommended next step

1. **AJ reruns the corrected script**, still before the Phase 1F stack is
   deployed. Read-only, changes nothing, writes a redacted review under `%TEMP%`.
   Exit `0` = `PASS`, `2` = at least one `FAIL`, `1` = the audit did not complete
   and no review was written.
2. **If it fails again, send the exact error and the stage it reached.** That is
   what made this fix precise, and the fail-closed design guarantees a failure
   costs nothing but the run.
3. **Paste the review into this report** and close finding **G1**.
4. **Then deploy the Phase 1F stack**, per its own recommended next step.
5. **Add PowerShell parsing to CI** — finding **D**, now with a measured cost.
   Even a parse-only check (`[System.Management.Automation.Language.Parser]::ParseFile`)
   on the three Windows helpers would be cheap, and a run against a mocked AWS CLI
   would have caught this specific defect outright.

## Push — this update

Implementation and tests committed separately from the report, per the reporting
protocol. Both commits pushed to `origin/phase1g-lambda-execution-role-audit`.

**Nothing was merged to `main`.** Nothing was deployed. No AWS API call was made,
no IAM was modified, and no secret value was retrieved.

---
---

# Update 2 — second administrator run was INCOMPLETE, script corrected again

**Date:** 2026-07-30
**Outcome of the second administrator audit attempt:** `INCOMPLETE`.
**Outcome of this session's work:** `SUCCESS` — root cause found, corrected, and
pinned by both static tests and a new runtime harness.
**The audit:** still **NOT PERFORMED**. Finding **G1** remains **open**, and the
corrected script has **not yet been rerun by AJ**.

## What the second run actually did

Run on Windows by the administrator, against the script as corrected by commit
`7cbab34`. Recorded exactly as reported:

| Stage | Result |
| --- | --- |
| Caller identity | **Passed** — resolved successfully |
| **Function configuration** | **Failed before its checks completed** — `The function configuration query returned fewer fields than expected.` |
| Expected-secret metadata | Not reached |
| Trust policy | Not reached |
| Attached managed policies | Not reached |
| Inline policies | Not reached |
| Effective permissions | Not reached |

| Consequence | Result |
| --- | --- |
| Exit code | **1** |
| Review file | **None written** |
| AWS resources created, read, modified, or deleted | **None modified**; two reads reached AWS (`sts:GetCallerIdentity`, `lambda:GetFunctionConfiguration`) |
| Secret value read | **No** |
| Finding **G1** | **Still open** |

Note the difference from the first run, because it is the useful signal. The first
run reached the *fifth* stage. This one failed at the *second*, one stage earlier
than the first attempt's furthest point — so the previous correction did not merely
fail to fix everything, it moved the failure earlier. That is what identified the
correction itself as the trigger.

### The fail-closed design held again

| Property | Held? |
| --- | --- |
| Exit non-zero when the audit cannot complete | **Yes** — `1` |
| Write no review after an incomplete audit | **Yes** — the `$script:StagesCompleted` gate was never reached |
| Never print `PASS` for an unfinished stage | **Yes** — only the caller stage reported, and it reported truthfully |
| Never apply a correction | **Yes** — the script has no mutating call to make |

Two failures in a row is a poor showing for the tooling. It is not a safety
incident: both times the script stopped, said so, wrote nothing, and changed
nothing. The cost has been administrator time, which is the thing this update is
meant to stop spending.

## Root cause

**A fixed-shape record was being handled as a variable-length collection.**

The failing code asked the CLI for a JMESPath multiselect *list* and then
validated the answer by counting it:

```
--query '[State,LastUpdateStatus,Role]'
...
$values = @(Get-AsArray -Value $fields)
if ($values.Count -lt 3) { Stop-Run ... }
```

`get-function-configuration` returns a record whose shape is known before the
call is made. Its length is not data. Counting it was measuring the wrong
property, and positional indexing meant every field's identity depended on
nothing being reordered or nested on the way in.

### Why the previous correction triggered it

`Write-Output -NoEnumerate` does hand a collection to the caller as a single
object, which is what the first fix needed. But **on Windows PowerShell 5.1 it
wraps that object in a `[psobject]`, and on PowerShell 7 it does not.** `@(...)`
at a call site cannot see through the wrapper: it collects the wrapper as one
item, producing a one-element array whose single element is the real array.

So `$values.Count` read **1** where the guard wanted 3 — three fields were
returned, and the length check could not see them. That is exactly the shape the
task description predicted: the three-field result wrapped as one nested item
while the stage expected three top-level fields.

Two things follow, and both are addressed:

1. The **fixed-record** reads should never have been length-checked at all. That
   is the primary correction.
2. The **collection** call sites were affected by the same wrapper. The error
   message named the function configuration, but with one attached managed policy
   the uncast pattern yields a count of 1 — the right number by accident — whose
   single element is the whole list rather than a policy. That is a wrong answer
   rather than a crash, which is worse, and it is fixed too.

### What was not done

Per the task's explicit prohibitions, and because each of these would have hidden
the defect rather than removed it:

| Rejected approach | Why |
| --- | --- |
| Disable or relax `StrictMode` | StrictMode surfaced both failures. Without it the first would have silently skipped policies. |
| Split text output on spaces | Reintroduces positional parsing with a worse delimiter. |
| Assume tab-separated output is stable | It is not a contract, and it carries no field names. |
| Unwrap every collection globally | Destroys the zero/one/many property the first correction bought. |
| Revert the attached-policy collection fix | The first defect was real. Reverting trades one failure for the other. |
| Use field counts to validate a fixed record | This is the defect, restated. |

## The fix

### 1. Fixed records are requested by name and read by name

Every non-collection read now asks for a JMESPath multiselect **hash** and is
parsed by `ConvertFrom-AwsJsonRecord` into one object with named properties:

| Read | Query |
| --- | --- |
| `sts:get-caller-identity` | `{Account:Account}` |
| `lambda:get-function-configuration` | `{State:State,LastUpdateStatus:LastUpdateStatus,Role:Role}` |
| `secretsmanager:describe-secret` | `{Arn:ARN,KmsKeyId:KmsKeyId}` |
| `iam:get-role` | `{AssumeRolePolicyDocument:Role.AssumeRolePolicyDocument}` |
| `iam:get-policy` | `{DefaultVersionId:Policy.DefaultVersionId}` |
| `iam:get-policy-version` | `{Document:PolicyVersion.Document}` |
| `iam:get-role-policy` | `{PolicyDocument:PolicyDocument}` |

A JSON object has no elements. There is nothing for `-NoEnumerate` to wrap,
nothing for the pipeline to enumerate, and no position for a field to move to, on
either host. `ConvertFrom-AwsJsonRecord` uses `-InputObject` rather than the
pipeline for the same reason, and stops the run if a list, a scalar, or nothing
arrives where a record was expected.

Two reads that used `--output text` — the caller identity and the default policy
version — are JSON now. Text output is a bare value with no field name in it, so
it cannot be validated by name.

### 2. Each required field is validated on its own

`Get-RequiredField` requires a field to be present, non-null, a string, and
non-empty, and names the field in its failure message. `State`,
`LastUpdateStatus`, and `Role` each get their own call, so a missing one says
which one.

That is the difference from what the administrator saw. "Returned fewer fields
than expected" said the same sentence whether `State`, `LastUpdateStatus`, or
`Role` was absent — and it also said it when all three were present and merely
arrived nested. A message that cannot distinguish a missing field from a misread
response is not a diagnostic.

`describe-secret`'s `KmsKeyId` is read with `Get-OptionalField` instead: it is
null whenever the secret uses the AWS-managed key, which is a real answer and the
shape the deployment actually has.

### 3. The role ARN is reduced to a name and never emitted

`Get-RoleNameFromArn` validates the ARN and extracts the role name with a named
capture group, so a pathed role (`role/path/to/Name`) yields the name rather than
a path element. The ARN carries the account ID, so no failure message from this
helper contains the value — only the name of the field that was wrong. The
configuration stage uses `$roleArn` for exactly two things: validating it and
deriving the name from it.

### 4. Collections stay collections, and their call sites became host-independent

The two genuine collections are unchanged in kind:

| Read | Query | Handling |
| --- | --- | --- |
| `iam:list-attached-role-policies` | `AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}` | list normalised by `Get-AsArray`; each **row** is a named record |
| `iam:list-role-policies` | `PolicyNames` | list normalised by `Get-AsArray` |

The attached-policy query shows both sides of the split in one call: the list's
length is data, and each row's shape is not. A malformed row now fails closed
instead of being skipped — the previous version's `continue` meant a policy could
be silently absent from the audit, which for an audit is the worst available
outcome.

Everything the first correction established is preserved: `Write-Output
-NoEnumerate`, the `$null` test before the wrap, zero/one/many support,
normalisation at the call site, and `StrictMode -Version Latest`.

Call sites additionally cast to `[object[]]` before the `@()` wrap. A PowerShell
conversion unwraps a `[psobject]` and leaves a plain array untouched, so
`@([object[]](Get-AsArray -Value $x))` is correct whether the host adds the
wrapper or not. **This host has no PowerShell interpreter and cannot settle which
behaviour applies by experiment, which is the reason not to depend on the
answer.** The cast is what removes the dependency rather than betting on it.

### 5. A third gate on `Invoke-AwsRead`: what a call may ask for

The narrow function-configuration query was previously a convention at one call
site. It is now enforced for every call:

- `lambda:get-function-configuration` and `secretsmanager:describe-secret` may
  not be invoked without a `--query`.
- No query may name `Environment`, `SecretString`, or `SecretBinary`.

`Environment.Variables` carries `GG_API_SECRET_ID`. Narrowing server-side keeps it
out of the process, which is stronger than fetching it and remembering to mask it
afterwards. The gate walks the argument list rather than indexing it, so it does
not reintroduce the mistake it guards against.

## The runtime harness — `scripts/test-audit-lambda-execution-role-runtime.ps1`

Both failures were behavioural, and neither was reachable from the host the Python
suite runs on. A static test can prove a pattern is present; it cannot prove
PowerShell then behaves as expected. Both defects therefore travelled all the way
to a live IAM audit before anyone saw them, which is the most expensive place to
find them and the slowest to iterate on.

The new harness runs the real audit end to end, on the administrator's own
PowerShell, against a fake AWS CLI and deterministic fixtures.

### Scenarios

| # | Scenario | Expected exit | Review written? | What it proves |
| --- | --- | --- | --- | --- |
| A | Clean expected role: one attached managed policy, one expected inline secret policy, AWS-managed Secrets Manager encryption, expected trust policy | `0` | **Yes** | The whole audit reaches the end and files a `PASS` review |
| B | Zero attached managed policies | `0` | Yes | The empty-collection path |
| C | Several attached managed policies | `0` | Yes | The many-collection path, and a per-policy `REVIEW` finding |
| D | Function configuration with `State` absent | `1` | **No** | A missing field fails, naming `State` |
| E | Function configuration with `Role` set to `null` | `1` | **No** | Present-but-null fails, naming `Role` |
| F | Secret grant on every secret | `2` | **Yes** | A completed audit with a real finding still files a review |

B and C exist because "one" is not the interesting case by itself — the first
failure was a one-item collection, and a fix that handled one while breaking zero
would look correct. D and E use different absent shapes on purpose: one omits the
key, the other sets it to `null`, which is what a JMESPath query for a field the
response does not carry actually returns. Both occur in practice and both must
fail, each naming its own field.

D and E also assert that `returned fewer fields than expected` does **not** appear
in the output. That is how a rerun proves which version of the script it ran.

### Isolation, by construction

| Control | Mechanism |
| --- | --- |
| No real AWS call | A fake `aws.cmd` is written into a sandbox and that directory is **prepended** to `PATH`, so a bare `aws` resolves to it |
| Proof every call was intercepted | The fake CLI logs each call; each scenario asserts the exact expected count, so a call that escaped would leave the log short |
| No secret value read | The fake CLI refuses `get-secret-value` and `batch-get-secret-value`, records the attempt, and the harness fails the run if that log ever appears |
| No credentials available | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and both profile variables are cleared for the child; `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` point at paths that do not exist; instance metadata is disabled |
| Nothing written in the repository | The sandbox is created under the system temp directory and checked against the repository root **before** anything is written; a final sweep confirms no generated review landed in the checkout |
| No leftovers | The sandbox is removed in a `finally` block, whether the run passes, fails, or throws — one removal, in the one place that always runs |
| Environment restored | Every variable the harness changes is recorded first and restored in the same `finally`, including "was not set" |
| Same host as the administrator | The audit runs as a child of the *current* PowerShell executable. Testing under PowerShell 7 while the administrator runs 5.1 would have passed both failures |

The audit is run as a child process rather than dot-sourced because it ends in
`exit`, which would terminate the harness on the first scenario — and the exit
code is what every scenario asserts.

Fixture data carries no real identifier: the account ID is the documented
placeholder the repository's identifier scan already allows — the scan rejects any
other twelve-digit number, so a real one cannot be substituted without failing the
Python suite. The secret is named `fixture-secret`, and no live
URL, ARN, secret name, or credential appears in the file. The harness also
verifies the review file that actually landed contains no ARN, account ID, secret
name, or URL — the audit scans the review before writing it, and this checks the
result, which is a different and stronger statement.

### The harness has not been executed

It cannot be, here. There is no PowerShell interpreter on this host — `pwsh` and
`powershell` are both absent — so the harness is **unrun**. What was verified
locally is that its brackets, braces, and here-string terminators balance, and
that its isolation properties hold structurally, via the tests below.

That is an honest limit and worth stating plainly: this update makes the *next*
administrator run diagnosable and cheap to iterate on, and gives AJ a way to
check the script before spending a live run on it. It does not prove the audit
now completes. Only running it does that, and running the harness is the cheap way
to find out.

## Tests added

`backend/tests/test_phase1g_execution_role_audit.py` grew from 127 to **214**
tests. Two new sections.

### The second failure, modelled

The PowerShell semantics model from the first correction gained a `[psobject]`
wrapper and a host parameter, so every collection normalisation is now checked
against **both** Windows PowerShell 5.1 and PowerShell 7. The model reproduces the
second failure before proving the fix:

- The positional read on the wrapping host yields a count of **1**, with the three
  real fields one level down — the reported abort.
- The identical code on the non-wrapping host yields **3** and passes, which is why
  the defect was invisible to anything not run on the administrator's machine.
- The one-attached-policy collection case yields the right count for the wrong
  reason, with the whole list as its single element.
- The `[object[]]` cast produces the correct array on both hosts, for zero, one,
  and many.

### The fixed-record path

A model of `ConvertFrom-AwsJsonRecord` and `Get-RequiredField` proves each
rejection: absent field, `null` field, empty and whitespace-only field, non-string
field, a positional list arriving where a record was expected, and a bare scalar.
Each configuration field is tested absent and `null` independently, and each must
name itself. One test shows what the old length check could not have caught — a
response carrying `State` and `Role` but a `null` `LastUpdateStatus` passes a
length check while leaving a value empty.

Structural guards then pin the script itself:

- Every one of the seven fixed-shape reads asks for its documented multiselect
  hash, and every one is read as JSON.
- The two collection reads are still queried as collections.
- The fixed-record and collection tables together must cover **every** entry on
  the allow-list, so a read cannot be added without being classified.
- No positional `'--query', '[...]'` survives anywhere.
- No `--output text` survives anywhere.
- `Get-FunctionRoleName` contains no `.Count`, no numeric index, and no
  `Get-AsArray` call at all.
- The old failure message is gone from the executable script — and still present
  in a comment, deliberately, so the next reader knows what it replaced.
- The role-ARN regex is read **out of the script** and tested against a plain role
  ARN, a pathed role ARN, a user ARN, a Lambda ARN, a short account ID, and an
  empty string.
- No `Stop-Run` in the role-name helper carries `$Arn`.

### The harness is isolated

Thirty-odd tests over the harness, including: the fake CLI is prepended to `PATH`
rather than appended; the harness invokes nothing but a PowerShell host; every
environment variable it changes is on the restore list; the fake CLI refuses both
secret reads and fails closed on an unknown call; the fake CLI never parses the
`--query` and never forwards `%*` (cmd.exe splits arguments on commas, so a shim
that read the JMESPath expression would depend on tokenisation the harness cannot
control); the sandbox guard precedes the first write; no write target is built
from `$PSScriptRoot` or the repository root; the sandbox removal is in the
`finally` and appears exactly once; all six required scenarios are declared; and
the fixture set matches the allow-list exactly.

### Preserved from the first correction

Every test from the first correction still runs and still passes: the
`-NoEnumerate` guard, the null-before-wrap ordering, the zero/one/many
parametrisations for attached policies, inline policies, statements, `Action`,
`Resource`, and `Principal.Service`, the requirement-9 `.Count`-receiver scan, and
the index-guard scan.

Two of those tests were adjusted rather than removed, and the reasons are
recorded in the tests themselves:

- The `.Count`-receiver floor dropped from 15 to 12, because four `.Count` usages
  were **deleted** — the function-configuration and secret-metadata reads no
  longer count anything. Fewer is the improvement. The test now also asserts the
  four remaining collection receivers by name, so it cannot pass by having nothing
  left to check.
- `test_every_normaliser_call_site_is_wrapped` became
  `test_every_normaliser_call_site_is_wrapped_and_cast`, requiring the
  `[object[]]` cast as well as the `@()`.

## Verification results — this update

| Check | Command | Result |
| --- | --- | --- |
| Full suite | `.venv/bin/python -m pytest -q` | **615 passed**, 2 warnings (pre-existing dependency deprecations) |
| Phase 1G suite | `.venv/bin/python -m pytest backend/tests/test_phase1g_execution_role_audit.py -q` | **214 passed** (was 127) |
| Lint | `.venv/bin/ruff check backend/` | **All checks passed** |
| Formatting | `.venv/bin/ruff format --check backend/` | **18 files already formatted** |
| Whitespace | `git diff --check` | **Clean** |
| PowerShell syntax | bracket, brace, and here-string balance, both scripts | **Balanced** |
| PowerShell execution | — | **Not possible.** No interpreter on this host; `pwsh` and `powershell` both absent |

## Files — this update

### Added

| File | Lines | Purpose |
| --- | --- | --- |
| `scripts/test-audit-lambda-execution-role-runtime.ps1` | 826 | Runtime fixture harness: six scenarios, fake AWS CLI, no AWS call |

### Modified

| File | Change |
| --- | --- |
| `scripts/audit-lambda-execution-role.ps1` | Fixed records requested and read by name; `ConvertFrom-AwsJson` split into `ConvertFrom-AwsJsonList` and `ConvertFrom-AwsJsonRecord`; `Get-RequiredField`, `Get-OptionalField`, and `Get-RoleNameFromArn` added; `[object[]]` cast at every normaliser call site; third `Invoke-AwsRead` gate on query content |
| `backend/tests/test_phase1g_execution_role_audit.py` | 127 → 214 tests; `[psobject]` wrapper and both hosts modelled; fixed-record section; harness-isolation section |
| `docs/audits/phase1g-lambda-execution-role-audit-2026-07-29.md` | This update |

### Deleted

None.

## Commits — this update

| Commit | What |
| --- | --- |
| `1515684` | Starting point on `main` (branch merge-base) |
| `9bc7356` | Build Phase 1G execution-role audit tooling (original) |
| `3ed894b` | Document Phase 1G execution-role audit tooling (original) |
| `7cbab34` | Fix Phase 1G PowerShell collection handling (first correction) |
| `9827dda` | Document incomplete Phase 1G audit attempt (first correction) |
| `0fe787d` | **Fix Phase 1G fixed-record parsing** (implementation + tests, this update) |
| _report commit_ | **Document incomplete Phase 1G audit** (this report update) |

## AWS resources created, read, modified, or deleted — this update

**None.** No AWS API call was made from this host during this task. Local work
only:

| Category | This session |
| --- | --- |
| Created | **None** |
| Read | **None** — no `aws` command was run |
| Modified | **None** |
| Deleted | **None** |
| Deployed | **None** |
| Secrets Manager accessed | **None** |
| Secret value retrieved | **None** |
| Lambda function or Function URL touched | **None** |

The two reads that did reach AWS were made by the administrator's own second run,
before this session, and are recorded in the table at the top of this update.

## Security and privacy checks — this update

| Check | Result |
| --- | --- |
| Allow-list unchanged | **Yes** — the same nine reads, verified against every call site by test |
| Forbidden secret reads still refused first | **Yes** — ahead of the allow-list check, so the refusal stays specific |
| New gate adds no capability | **Yes** — it only narrows what an allow-listed read may ask for |
| Secret value can enter the process | **No** — forbidden by name, absent from the allow-list, and its payload fields are refused in any query |
| Environment variables fetched | **Never** — enforced by the wrapper now, not only by convention at one call site |
| Full ARN or account ID in terminal output | **No** — masked; the role helper's failure messages carry the field name only |
| Full ARN or account ID in the review | **No** — scanned before writing, and the harness re-checks the file that landed |
| Real identifier in any tracked file | **No** — the harness is in the repository-wide identifier scan's strict list |
| Real secret identifier in a Phase 1G file | **No** — fixtures use `fixture-secret` |
| Fail-closed behaviour | **Preserved** — exit `1` when incomplete, no review after an incomplete audit, `PASS` produced in one place, no correction ever applied |
| `StrictMode -Version Latest` | **Preserved** |
| Product boundaries | **Untouched** — no endpoint, prompt, or copy changed |
| PHI or user health text | **None** — this task touches neither |

## Blockers and unresolved findings — this update

| Item | Status |
| --- | --- |
| **G1 — `GracefulGutAI-LambdaExecutionRole` unaudited** | **Open.** Carried since Phase 1D. The audit has now been attempted twice and completed zero times. |
| Twice-corrected script rerun by AJ | **Not done.** This is the blocking next action. |
| Runtime harness executed | **Not done.** No PowerShell interpreter on this host. Unrun, and stated as such above. |
| `GracefulGutAI-LambdaExecutionRole` attached policies | **Still unreadable from this host.** Unchanged and by design. |

### Honest assessment of the remaining risk

Two administrator runs have now failed on PowerShell semantics rather than on
anything about IAM. A third failure is possible, and the reason it is less likely
is not that the code has been read more carefully — it is that the harness makes
the failure mode reachable without administrator credentials. If a third defect of
this class exists, running the harness finds it in seconds on AJ's own machine.

There is one class this update cannot rule out: a PowerShell construct that
behaves differently on 5.1 and 7 in some path the harness does not exercise. The
mitigation is that the harness runs the *whole* audit rather than a unit of it, on
whichever host the administrator uses.

## Decisions required from AJ or Jenna — this update

**None.** No product, security, or architectural decision is required. This was a
defect correction plus test tooling, all local.

## Recommended next step

Run the harness first, then the audit. The harness needs no credentials, touches
no AWS, and takes seconds:

```powershell
git fetch origin
git checkout phase1g-lambda-execution-role-audit
git pull --ff-only

.\scripts\test-audit-lambda-execution-role-runtime.ps1
```

Exit code `0` and "All scenarios passed" means the audit's plumbing works on that
machine. If any scenario fails, send the output — it names the scenario, the
expectation, and the captured terminal text, which is everything needed to fix it
without another live run.

Then, with administrator credentials:

```powershell
.\scripts\audit-lambda-execution-role.ps1 -ExpectedSecretName <secret-name> -NoOpen
```

Exit `0` is a clean role, `2` is a completed audit with findings — both write a
review under `TEMP`. Exit `1` means it stopped again; send the terminal output.

Do not paste the secret identifier into this report or any other tracked file.

## Push — this update

Branch `phase1g-lambda-execution-role-audit` pushed to `origin`. **Not merged to
`main`**, per the task.

---

# Update 3 — runtime harness FAILED in review generation, renderer corrected

**Date:** 2026-07-30
**Outcome of AJ's runtime harness run:** `FAILED`.
**Outcome of this session's work:** `SUCCESS` — the failing path was rewritten to
a host-independent shape, pinned by regression tests, and mutation-tested.
**The audit:** still **NOT PERFORMED**. Finding **G1** remains **open**. The live
AWS audit was **not rerun**, and the corrected harness has **not yet been rerun
by AJ**.
**Branch:** `phase1g-lambda-execution-role-audit`
**Starting commit:** `827043e`
**Implementation commit:** `9eb1e05`

No AWS call was made during this Claude task. No IAM was modified, no Lambda
function or Function URL was touched, no Secrets Manager operation was attempted,
and nothing was deployed. All work was in the repository.

## What AJ's harness run actually did

The new Windows PowerShell 5.1 runtime harness was executed by AJ. **Process
result: FAILED.** Recorded exactly as reported.

The harness proved the previous two corrections work. These are now settled facts
about Windows PowerShell 5.1, not hopes:

| Proven by the run | Result |
| --- | --- |
| Function configuration parses correctly | **Yes** |
| Missing `State` fails, and names `State` | **Yes** |
| Missing `Role` fails, and names `Role` | **Yes** |
| Zero, one, and multiple attached-policy scenarios reach the verdict | **Yes** |
| Policy documents resolve correctly | **Yes** |
| Permission classification completes | **Yes** |
| `PASS`, `REVIEW`, and `FAIL` verdicts are calculated correctly | **Yes** |
| Every AWS call was intercepted by the fake CLI | **Yes** |
| No secret-value read was attempted | **Yes** |
| No review was written inside the repository | **Yes** |

The remaining failure is isolated to **review generation**.

| Scenario | Reached | Result |
| --- | --- | --- |
| A. clean expected role | Verdict, then `Review` | **Failed in review generation** |
| B. zero attached managed policies | Verdict, then `Review` | **Failed in review generation** |
| C. multiple attached managed policies | Verdict, then `Review` | **Failed in review generation** |
| D. configuration missing `State` | Function stage | **Passed** — every assertion |
| E. configuration with a null `Role` | Function stage | **Passed** — every assertion |
| F. secret grant on every secret | Verdict, then `Review` | **Failed in review generation** |

In every completed scenario — A, B, C and F — terminal output reached the
`Review` section header and then reported:

```
Argument types do not match
```

The script then correctly reported:

```
Audit did not complete. No review was written.
Nothing was changed -- this script only ever reads.
```

D and E, which intentionally stop before review generation, passed all of their
assertions.

### The fail-closed design held a third time

| Property | Held? |
| --- | --- |
| Exit non-zero when the audit cannot complete | **Yes** — completed scenarios returned `1` |
| Write no review after an incomplete run | **Yes** — the write is downstream of the failure |
| Never print `PASS` for an unfinished stage | **Yes** — every stage that reported, reported truthfully |
| Never apply a correction | **Yes** — the script has no mutating call to make |
| No real AWS call | **Yes** — every call reached the fake CLI |
| No secret-value operation attempted | **Yes** |
| No review written inside the repository | **Yes** |

Worth stating plainly: the verdicts were **already correct** in all four failing
scenarios. The audit logic reached the right answer and then could not write it
down.

## Root cause — what inspection supports, and what it does not

`Argument types do not match` is the message `System.Reflection` raises when a
method is invoked with an argument whose runtime type is not assignable to the
chosen overload's parameter type. In PowerShell it surfaces from a .NET method
call, not from PowerShell's own operators. On Windows PowerShell 5.1 the usual
source in a script of this shape is a **collection**: a generic `List`, or an
array inside the `[psobject]` wrapper that `Write-Output -NoEnumerate` produces,
crossing a function boundary and then being formatted, joined, or handed to a
.NET call that has more than one overload to pick from.

There is no PowerShell interpreter on this host, so the cause was narrowed by
inspection rather than by experiment.

### What the harness itself exonerates

This turned out to be the most useful evidence available, and it costs nothing:
the harness runs on the *same host*, and its own startup and fixture-writing code
already exercises several of the candidates. They ran successfully in AJ's run —
fixtures were written and all six scenarios started — so they are not the cause.

| Candidate expression | Status | Why |
| --- | --- | --- |
| `[System.IO.Path]::GetFullPath(...)` | **Exonerated** | The harness calls it twice at startup, before any scenario |
| `String.StartsWith(String, StringComparison)` | **Exonerated** | Same — harness startup, sandbox-vs-repository check |
| `List[string].Add(...)` | **Exonerated** | The harness's own failure list is a `List[string]` and recorded failures |
| `New-Object System.Text.UTF8Encoding($false)` | **Exonerated** | The harness constructs one and used it for every fixture |
| `[System.IO.File]::WriteAllText(path, text, encoding)` | **Exonerated** | Same — every fixture file was written with it |
| `-join` over a plain array | **Exonerated** | Used in both scripts' native-command wrappers, which ran |

### What is left, and is not exonerated

Two constructs were unique to the audit's review path.

| Candidate | Where | Why it is a Windows PowerShell 5.1 hazard |
| --- | --- | --- |
| `-join` applied to a **generic `List[string]`** | the review-line boundary | Every other join in either script is over a plain array. This one was over a generic collection |
| Indexing an `[ordered]` dictionary reached through a **`[psobject]`-wrapped parameter property** | the category table | `OrderedDictionary` exposes two `Item` accessors, one taking `Int32` and one taking `Object`. The permission classifier indexes the *same* dictionary successfully — but it holds it in a local variable, not through a parameter |

**Neither is named here as the cause.** Inspection cannot settle which one raised
the exception, and a guess recorded in a report is read as a finding later. What
inspection *does* support is that both are of the failing class, both are unique
to the failing path, and both can be removed without touching any logic the
harness proved correct.

So the correction does not target a line. It removes every shape in the review
path that can produce this class of failure, and adds the diagnostic that would
have identified the line in the first place.

## The fix

Confined to review rendering. The AWS parsing, policy resolution, permission
classification, trust-policy logic and verdict logic are **unchanged** — the
harness proved all of them work, and no test suggested a change was needed.

**`scripts/audit-lambda-execution-role.ps1`**

| Change | Why |
| --- | --- |
| Every stage result is converted once, at the top of `New-ReviewFile`, into a plain `[object[]]` | No generic `List` and no `[psobject]` wrapper reaches formatting, joining, or file writing |
| The `$null` case is guarded **before** the cast | `[object[]]$null` is `$null`, not an empty array — the same lesson as `Get-AsArray` |
| The category table iterates the dictionary's **enumerator** instead of indexing it | The enumerator yields key and value together, so there is no `Item` overload to resolve |
| Every interpolated value in a review line is cast to `[string]` or `[int]` | A subexpression must not emit whatever a property happened to hold |
| Findings are counted with an explicit loop rather than piped through `Where-Object` | Removes a pipeline whose output shape varies with the number of matches |
| Review lines are converted **individually** to `[string]`, stored as `[string[]]`, and joined with PowerShell's `-join` | This is the boundary the task named. `-join` is a PowerShell operator, not a .NET call, so there is no overload to resolve |
| `[string]::Join` is **not** used, and a test forbids it | Four overloads is the problem, not the solution |
| `WriteAllText` receives three explicitly typed arguments | Leaves the binder nothing to decide, even though this call is exonerated |
| No `@($genericList)` survives in the review path | `@(...)` cannot see through a `[psobject]` wrapper — that is what broke the second run |
| `Write-Output -NoEnumerate` is not used anywhere in the review path | It is what introduced the wrapper originally; it must not be the fix here |

**What was deliberately not changed:**

- `Set-StrictMode -Version Latest` — still on.
- The fixed-record JSON-object correction, and the zero/one/many collection
  handling. Both proven by this run; both untouched.
- The `[object[]]` collection normalisation where it is already required.
- The read-only AWS operation allow-list, the forbidden secret-value operations,
  and the narrow query-content gate.
- Fail-closed review scanning. **Redaction was not weakened to make the write
  succeed** — the scan still runs on the finished text before the write, and a
  match still produces no file rather than a file with a warning.
- No review after an incomplete audit; `exit 0` for `PASS`, `2` for a completed
  `FAIL`, `1` for an incomplete run.

## The failure diagnostic

Three administrator runs have now been spent turning a bare exception message
into a location. The audit now prints one line when it dies:

```
DIAGNOSTIC: stage='<stage>' function='<function>' line=<n> exception=<type>
```

The stage comes from `Write-Section`, which is the single place a stage begins,
so there is one writer and it is always a literal from the script. The line
number is an offset into the file. The exception type is a .NET type name.

What it must not carry is enforced rather than argued. A stack frame is the
fastest way to get an absolute user path into a report — PowerShell renders each
as `at <function>, <full script path>: line n` — so only the text before the
first comma is taken, and it is discarded entirely if it contains a path
separator or a colon. The whole line then goes through `Hide-Sensitive` anyway.
It carries no account ID, ARN, secret name, URL, credential, token,
environment-variable value, or absolute path.

**`scripts/test-audit-lambda-execution-role-runtime.ps1`** — all six scenarios
preserved. The harness now lifts the diagnostic to the top of a failure report
instead of leaving it in the captured output, and fails the scenario if the line
ever carries a path separator. Scenario expectations:

| Scenario | Exit | Review | Diagnostic |
| --- | --- | --- | --- |
| A. clean expected role | `0` | `PASS` review, completion message | **Must be absent** |
| B. zero attached managed policies | `0` | exactly one review; a `REVIEW` finding for the missing managed logging policy may be present | **Must be absent** |
| C. multiple attached managed policies | `0` | one review, correct verdict, completed audit | **Must be absent** |
| D. configuration missing `State` | `1` | none | **Must be present**, naming stage `Function` |
| E. configuration with a null `Role` | `1` | none | **Must be present**, naming stage `Function` |
| F. secret grant on every secret | `2` | one `FAIL` review, completed audit | **Must be absent** |

Requiring the diagnostic to be *absent* from the four completed scenarios is the
direct regression guard for this failure: if review generation dies again, those
scenarios fail on the diagnostic rather than on a downstream symptom. Requiring
it to be *present* in D and E stops that guard from passing by the diagnostic
never being emitted at all.

## Tests added

Twenty-four new tests in `backend/tests/test_phase1g_execution_role_audit.py`,
covering exactly what the task specified:

| Rule | Enforced |
| --- | --- |
| Final review lines are an explicit `[string[]]` | Yes |
| Each line is converted to `[string]` individually on the way in | Yes |
| The review text is produced with the `-join` operator | Yes |
| No generic `List` is passed directly to review joining | Yes — the join receiver must be the normalised array |
| `[string]::Join` is not used with an unverified collection | Yes — it is not used at all |
| No `@($genericList)` survives in the review path | Yes |
| No format operation receives a `[psobject]`-wrapped array | Yes — no `-f` and no `::Format(` in the path |
| Stage results are normalised with an `[object[]]` cast, `$null` guarded first | Yes |
| The ordered dictionary is no longer indexed in the review | Yes |
| The classifier still owns the category counts | Yes — the correction did not leak into it |
| Every interpolated review value is explicitly typed | Yes |
| `WriteAllText` receives explicitly typed arguments | Yes |
| `Write-Output -NoEnumerate` is absent from the review path | Yes |
| The review scan still occurs before the write | Yes — pre-existing test, still passing |
| Completed `PASS` and `FAIL` audits both write reviews; incomplete audits write none | Yes — scenario assertions, pre-existing and extended |
| The diagnostic names stage, function, line, and exception type | Yes |
| The diagnostic drops anything path-shaped, and is masked before printing | Yes |
| One writer for the stage, and every stage name is a literal | Yes |
| The previous fixed-record and collection tests remain intact | Yes — all still present and passing |

One existing guard was **widened rather than weakened**. The `.Count`-receiver
scan now accepts a type-constrained declaration such as `[object[]]$rows`. That
is a *stronger* proof that a variable is a collection than `@(...)` is, because
PowerShell enforces the constraint on every later assignment too, not just the
first.

### Mutation-tested

Six mutations were injected to confirm the new rules are not vacuous. Each was
caught by the intended test, and the script was restored after each:

| Mutation | Caught by |
| --- | --- |
| Join the generic `List` directly, as before the correction | 4 tests, including `test_no_generic_list_is_joined_in_the_review_path` |
| Re-index the ordered dictionary through the wrapped property | `test_the_ordered_dictionary_is_no_longer_indexed_in_the_review` |
| `[string]::Join` over the generic `List` | 3 tests, including `test_string_join_is_not_used_anywhere_in_the_script` |
| `@($genericList)` back in the review path | `test_no_generic_list_is_wrapped_in_an_array_subexpression_in_the_review` |
| Write the review before scanning it | `test_the_review_is_scanned_before_it_is_written` |
| Drop the failure diagnostic from the catch block | `test_the_script_emits_a_diagnostic_when_a_run_dies` |

## Verification results — this update

| Check | Result |
| --- | --- |
| `pytest` | **639 passed**, 0 failed, 2 warnings |
| Phase 1G module | **238 passed** (was 214) |
| `ruff check backend/` | **All checks passed** |
| `ruff format --check backend/` | **18 files already formatted** |
| `git diff --check` | **Clean** — no whitespace errors |
| Runtime harness executed here | **No.** No PowerShell interpreter on this host |
| Live audit executed here | **No.** Prohibited by the task, and impossible from the dev role |

## Files — this update

### Modified

| File | Change |
| --- | --- |
| `scripts/audit-lambda-execution-role.ps1` | Review renderer rewritten to a host-independent shape; `Get-SafeDiagnostic` added; stage recorded in `Write-Section`; diagnostic emitted from the catch block |
| `scripts/test-audit-lambda-execution-role-runtime.ps1` | Diagnostic surfaced and path-checked; six scenarios extended with diagnostic expectations |
| `backend/tests/test_phase1g_execution_role_audit.py` | 24 tests added; `.Count`-receiver scan widened to accept type-constrained declarations |
| `docs/audits/phase1g-lambda-execution-role-audit-2026-07-29.md` | This update |

No file was added or deleted.

## AWS resources created, read, modified, or deleted — this update

**None.** No AWS call of any kind was made during this Claude task — not a read,
not a write, not an identity check. No IAM was modified. No Lambda function or
Function URL was touched. No Secrets Manager operation was attempted and no
secret value was retrieved. Nothing was deployed.

AJ's harness run also made **no real AWS call**: every call was intercepted by
the fake CLI, and no secret-value operation was attempted.

## Security and privacy checks — this update

| Check | Result |
| --- | --- |
| Secret values in the diff | **None** |
| Secret identifiers in the diff or this report | **None** |
| Account IDs, instance IDs, full ARNs | **None** |
| Live Function URL or API endpoint | **None** |
| Credentials, tokens, authorization headers | **None** |
| Health text, PHI, or personal identifying information | **None** |
| Redaction weakened to make the write succeed | **No** — the scan is unchanged and still runs before the write |
| Read-only allow-list, forbidden secret operations, query gate | **Unchanged** |
| New diagnostic could leak a path, ARN, account ID, or env value | **No** — path-shaped frames dropped, whole line masked, tested |

## Blockers and unresolved findings — this update

| Item | Status |
| --- | --- |
| **G1 — `GracefulGutAI-LambdaExecutionRole` unaudited** | **Open.** Carried since Phase 1D. The live audit has been attempted twice and completed zero times, and was **not rerun** in this task |
| Corrected harness rerun by AJ | **Not done.** This is the blocking next action |
| Live AWS audit rerun | **Not done**, and out of scope for this task |
| Runtime harness executed here | **Not possible.** No PowerShell interpreter on this host |
| `GracefulGutAI-LambdaExecutionRole` attached policies | **Still unreadable from this host.** Unchanged and by design |

### Honest assessment of the remaining risk

The harness did its job: it moved a failure that previously cost an administrator
run into something reproducible on AJ's machine with no credentials and no AWS.
That is why this failure was diagnosed from a process exit rather than from a
live audit attempt.

What this update cannot claim is that it fixed *the* line. Without a PowerShell
interpreter here, the exact expression that raised `Argument types do not match`
is not knowable from inspection, which is why this report names candidates rather
than a culprit. The correction is defensible on different grounds: every
construct in the review path that belongs to the failing class is gone, replaced
with shapes that bind identically on 5.1 and 7.

If a fourth failure of this class exists, the diagnostic now names the stage, the
function, and the line on the first run — so the next report will not have to
reason about candidates at all.

## Decisions required from AJ or Jenna — this update

**None.** No product, security, or architectural decision is required. This was a
defect correction plus test tooling, all local to the repository.

## Recommended next step

Rerun the harness. It needs no credentials, touches no AWS, and takes seconds:

```powershell
git fetch origin
git checkout phase1g-lambda-execution-role-audit
git pull --ff-only

.\scripts\test-audit-lambda-execution-role-runtime.ps1
```

Exit `0` and "All scenarios passed" means review generation now works on that
machine. If any scenario fails, send the output — it now leads with the
`DIAGNOSTIC:` line naming the stage, function, and script line, which is enough
to fix it without another live run.

Then, with administrator credentials:

```powershell
.\scripts\audit-lambda-execution-role.ps1 -ExpectedSecretName <secret-name> -NoOpen
```

Exit `0` is a clean role, `2` is a completed audit with findings — both write a
review under `TEMP`. Exit `1` means it stopped again; send the terminal output
including the `DIAGNOSTIC:` line.

Do not paste the secret identifier into this report or any other tracked file.

## Push — this update

Branch `phase1g-lambda-execution-role-audit` pushed to `origin`. **Not merged to
`main`**, per the task.

---

# Update 4 — harness PASSED, live audit COMPLETED, two reconciliation defects fixed

**Date:** 2026-07-30
**Outcome of AJ's runtime harness run:** `SUCCESS` — all scenarios passed.
**Outcome of AJ's live execution-role audit:** `SUCCESS` — the audit completed
and wrote a review, for the first time in this phase.
**Outcome of this session's work:** `PARTIAL` — both defects the live run exposed
are corrected and pinned, but the corrected script has **not** been rerun, so
Phase 1G stays open.

**Branch:** `phase1g-lambda-execution-role-audit`
**Starting commit (this update):** `633be9f`
**Implementation commits:**
`01aa0c7` — *Reconcile Phase 1G policy naming and verdicts*
`4bdd82e` — *Extend zero/one/many coverage to the inline policy list*
**Report commit:** recorded in "Push — this update" below.

## What the two runs actually did

The harness ran to completion on AJ's Windows PowerShell 5.1 host. The renderer
rewrite from Update 3 held: every scenario reached its expected verdict, review
generation worked, no `DIAGNOSTIC:` line was printed, every AWS call went to the
fake CLI, no secret-value operation was attempted, and no review landed in the
checkout.

The live audit then ran with administrator credentials and **completed** — the
first time in this phase that it did. It resolved the trust policy, the attached
managed policy, the inline policy, and the effective permissions, and wrote a
review under `TEMP`. Nothing in AWS was changed.

Two things were wrong with what it produced. Neither is a crash, and that is why
neither of the three previous failures could have surfaced them.

## Defect 1 — the terminal and the review disagreed about the same run

The terminal reported:

```
[REVIEW] Resolved inline policy: <name>
         not part of the documented setup
```

The review file, generated seconds later by the same process, reported
`**Overall: PASS**` and `FAIL: 0. REVIEW: 0.`

Neither artefact was internally inconsistent. That is what makes this worse than
either being plainly wrong: read on its own, each one looked like a settled
result, and there was no way to tell which to act on without holding both up
together. An administrator who filed the review file — the durable artefact, the
one written to be pasted into a report — would have recorded a clean audit of a
role the audit had actually flagged.

### Root cause

Structural, not a wrong comparison. Findings lived in **three** places:

| Where | Who wrote to it | Did the review read it? |
| --- | --- | --- |
| `$script:PermissionFindings` | the permission stage | yes |
| a local `$findings` list | the trust stage | yes, via its return value |
| nowhere | the policy-resolution stages | **no — nothing was recorded at all** |

The inline-policy check called the old `Write-Finding`, which **printed** a
classification and returned. It recorded nothing, so no collection the renderer
read had ever heard of it. The renderer then computed its own counts and its own
overall verdict from the two collections it was handed, which is a second,
independent opinion about the same run.

Two further faults sat in the same design and would each have produced their own
disagreement:

- The permission stage **re-created** `$script:PermissionFindings` on entry,
  discarding anything recorded by the stages ahead of it.
- The stages table was four hand-written rows, two of them the constant `PASS`.
  Three stages that can produce a finding had no row at all — the inline-policy
  stage among them — so their result was invisible in the review whatever it was.

### The fix

One collection, one way in, one computation.

- **`$script:AuditFindings` is the only finding collection.** It is created once,
  never reassigned, and never reset mid-run.
- **`Add-Finding` is the only way in**, and it records and prints in the same
  call, so the two cannot come apart.
- **The old `Write-Finding` is split into four writers**, and only one of them can
  classify something as a problem:

| Writer | Emits | Records |
| --- | --- | --- |
| `Write-Step` | `PASS` only — it cannot express anything else | nothing |
| `Write-Detail` | an unclassified line, for counts | nothing |
| `Add-Finding` | `REVIEW` or `FAIL` | **yes** |
| `Write-Verdict` | the single overall line | nothing |

  `Write-Step` taking no severity parameter is the constraint doing the work: a
  stage reporting progress has no way to reach the terminal with a REVIEW without
  going through `Add-Finding`.

- **`Add-Finding` no longer accepts a `Pass`.** A findings table is for entries an
  administrator has to decide about; recording passes there buries them. The
  per-category permission counts became plain numbers for the same reason — they
  were being scored `PASS`/`FAIL` a second time, over permissions the individual
  findings had already judged.
- **The renderer takes no findings, no per-stage severity, and no verdict as an
  argument.** The `$Trust` and `$Verdict` parameters are gone rather than
  corrected. It reads the one collection and calls `Get-OverallSeverity` — the
  same function the Verdict stage calls.
- **The stages table is generated** from the findings, by the stage each was
  recorded under, against the seven stages the script actually announces. A test
  asserts those seven match the `Write-Section` titles, because a title that
  drifts would silently score its stage `PASS` forever.

### Verdicts and exit codes, single-sourced

Unchanged in intent; the point is that there is now one route to them.

| Findings | Overall | Exit |
| --- | --- | --- |
| no `FAIL`, no `REVIEW` | `PASS` | `0` |
| no `FAIL`, one or more `REVIEW` | `REVIEW` | `0` |
| one or more `FAIL` | `FAIL` | `2` |
| run did not complete | *(no verdict, no review)* | `1` |

A `REVIEW` exits `0` deliberately: it is a request for an administrator's
judgement, not a failed run, and a non-zero exit would train every future caller
to treat it as breakage. Resolving a canonically named policy whose document
parses is a **step**, not a finding — it prints `PASS` and creates no `REVIEW`.

## Defect 2 — the expected inline-policy name was never the deployed one

The audit expected `GracefulGutAI-ReadApiKeySecret`. The deployed role carries
its secret grant under **`GracefulGutAI-SecretAccess`**. So the `REVIEW` above was
raised against a role that is, in substance, correct.

### What the evidence supports

The live audit resolved the deployed policy and assessed it: it grants **exactly
one** Secrets Manager action, scoped to the expected secret, and nothing else. No
wildcard, no write, no second grant. The policy is right. Only its **name** was
undocumented here.

`GracefulGutAI-ReadApiKeySecret` appears in this repository in exactly three
places, and all three are the *same* administrator instruction — `CLAUDE.md`,
`infrastructure/README.md`, and the Phase 1D report. It appears in **no** commit
as a record that the command was run. The repository had been treating an
instruction as though it were a record.

### The correction is repository-only

**No IAM was modified. No AWS call was made during this task. No live policy was
renamed, and none should be.** Renaming a policy that grants the right thing,
purely to match a document that was never a record of anything, would be a live
IAM change made to protect a stale expectation. The document is what moved.

| File | Treatment |
| --- | --- |
| `scripts/audit-lambda-execution-role.ps1` | expects `GracefulGutAI-SecretAccess`; the reasoning is recorded next to the constant |
| `CLAUDE.md` | command names the deployed policy; a note records the old name as **superseded, not an alias** |
| `infrastructure/README.md` | same treatment |
| Phase 1D report | **wording left exactly as written**, with a superseded marker |
| "Judgement call 3" earlier in this report | **wording left as written**, with a superseded marker |

The two runnable commands were corrected because running the old one now would
add a **second** inline policy beside the working one, not replace it. The two
historical records keep their original wording, because rewriting them would
erase where the wrong expectation came from — which is the only part of this
worth remembering.

## The harness gained scenario G

Scenario G is an inline policy under an unrecognised name, with an otherwise
**clean** policy document — so the name is the only thing wrong, and a run that
loses the finding looks entirely clean. It asserts the same finding in every
place it has to appear, from a single run:

| Where | Assertion |
| --- | --- |
| terminal output | the `REVIEW` line naming the policy |
| REVIEW count | `FAIL: 0. REVIEW: 1.` in the review |
| stages table | the `Inline policies` row reads `REVIEW` |
| findings table | the row |
| corrections | the `## Least-privilege corrections` section |
| overall verdict | `**Overall: REVIEW**`, and not `PASS` |
| exit code | `0` — a `REVIEW` is not a failure |

Asserting on the terminal **and** the file from one run is the only arrangement
that can see the two disagree. Six scenarios that each checked one artefact could
not have caught this, however many of them there were.

Scenario A now also asserts the negative: a canonically named policy produces no
`REVIEW` **anywhere** in the terminal output.

## Scenarios H and I — zero/one/many for the inline list

A follow-up review of the collection handling found the zero/one/many rule had
only ever been applied to **attached managed** policies: zero in scenario B, one
in A, many in C. Every runtime scenario fed the audit **exactly one** inline
policy — G included. Two branches had therefore never executed at runtime, and
both had just been converted from bare prints by the work above:

- the **empty** inline list, which records a `REVIEW` of its own
- a list long enough for **one stage to record more than one finding**

The unit tests do cover inline policies for zero, one, and many. Normalisation
was never the missing part — *execution* was. A converted branch that has never
run is the shape of the last three failures in this phase, which is why this was
worth closing before the rerun rather than after it.

| Scenario | Feeds | Asserts |
| --- | --- | --- |
| **H** | zero inline policies | eight fake-CLI calls, `No inline policy is present` in terminal and review, overall `REVIEW`, exit `0`, and no `Resolved inline policy:` line at all |
| **I** | two inline policies, neither recognised | both findings in terminal and review, `FAIL: 0. REVIEW: 2.`, an `Inline policies` stage row of `REVIEW`, exit `0` |

Scenario I is the only one in which a single stage records two findings — exactly
what the single-collection rewrite changed. The collection must accumulate the
second rather than replace the first, `Get-StageSeverity` must aggregate both
under one stage, and the review must render two rows. Both of I's documents are
the clean secret grant, so the names stay the only thing wrong and a permission
finding cannot inflate the count.

Two tests pin the rule so the gap cannot quietly reopen: one asserts that **both**
policy lists have a zero scenario and a several scenario, read from each
scenario's own fixture rather than from a scenario count; the other asserts that
I really does declare two policies, since checking only its expected counts would
keep passing if the fixture were collapsed to one. Both were mutation-tested —
removing the empty fixture, and collapsing the two-policy fixture, each fail the
intended test and no other.

## What was deliberately left alone

| Preserved | Status |
| --- | --- |
| Scenarios A–F | **Unchanged**, apart from A's added negative assertion |
| Zero/one/many rule | **Extended**, not weakened — it now covers the inline list too (H, I) |
| Read-only AWS allow-list | **Unchanged** |
| Forbidden secret-value operations (`get-secret-value`, `batch-get-secret-value`) | **Unchanged** |
| Query gate on what a call may ask for | **Unchanged** |
| No AWS mutation of any kind | **Unchanged** |
| Pre-write redaction scan — a match writes **no file** | **Unchanged, not weakened** |
| `Set-StrictMode -Version Latest` | **Unchanged** |
| Fixed-record parsing and field-by-field validation | **Unchanged** |
| Review gated on every stage completing | **Unchanged** |
| The renderer's host-independent shape from Update 3 | **Unchanged** — it worked |

## Verification results — this update

| Check | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **655 passed**, 2 warnings |
| Phase 1G module | **254 passed** (was 238) |
| `ruff check backend/` | **All checks passed** |
| `ruff format --check backend/` | **18 files already formatted** |
| `git diff --check` | **Clean** — no whitespace errors |
| Runtime harness executed here | **No.** No PowerShell interpreter on this host |
| Live audit executed here | **No.** Prohibited by the task, and impossible from the dev role |

One test-quality fix went in alongside: the scenario rules were driven off counts
of identical literal lines, so a scenario that worded its assertions differently
silently stopped being covered. They are now driven off parsed scenario blocks,
with a guard test that fails if the parser finds nothing.

## Files — this update

### Modified

| File | Change |
| --- | --- |
| `scripts/audit-lambda-execution-role.ps1` | One finding collection; `Write-Finding` split into four writers; `Get-OverallSeverity` and `Get-StageSeverity` added; renderer reads the collection; stages table generated; expected inline-policy name corrected |
| `scripts/test-audit-lambda-execution-role-runtime.ps1` | Scenarios G, H and I added; base fixture uses the deployed policy name; scenario A asserts no spurious REVIEW |
| `backend/tests/test_phase1g_execution_role_audit.py` | 16 net tests added; scenario rules re-driven off parsed blocks |
| `CLAUDE.md` | Inline-policy name corrected; old name marked superseded |
| `infrastructure/README.md` | Same |
| `docs/audits/phase1d-secrets-manager-2026-07-27.md` | Superseded marker only; original wording preserved |
| `docs/audits/phase1g-lambda-execution-role-audit-2026-07-29.md` | This update, plus a superseded marker on judgement call 3 |

No file was added or deleted.

## AWS resources created, read, modified, or deleted — this update

**None.** No AWS call of any kind was made during this Claude task — not a read,
not a write, not an identity check. No IAM role or policy was created, modified,
renamed, or deleted. No Lambda function or Function URL was touched. No Secrets
Manager operation was attempted and **no secret value was read**. Nothing was
deployed and nothing was merged to `main`.

AJ's two runs are the AWS activity being reported on. The harness run made **no**
real AWS call — every call was intercepted by the fake CLI. The live audit made
**read-only** calls (`sts:GetCallerIdentity`, `lambda:GetFunctionConfiguration`,
`secretsmanager:DescribeSecret`, and the IAM policy-listing and policy-reading
operations) and **changed nothing**. No secret value was retrieved by either.

## Security and privacy checks — this update

| Check | Result |
| --- | --- |
| Secret **value** read, printed, or stored anywhere | **No** — still forbidden by name, absent from the allow-list, and blocked by the query gate |
| Secret **identifier** in this report or any tracked file | **No** |
| Account ID, ARN, instance ID, or URL in this report | **No** |
| Live inline-policy name in this report | **Yes, deliberately.** A policy name is not a credential, an identifier of a secret, or an ARN. Recording it is the entire point of this update, and the next session needs it to avoid repeating the defect |
| Redaction weakened to make anything pass | **No** — the pre-write scan is unchanged and still produces no file on a match |
| IAM modified to match a document | **No** — explicitly refused; the document moved instead |
| Read-only allow-list, forbidden operations, query gate, StrictMode | **Unchanged** |

## Blockers and unresolved findings — this update

| Item | Status |
| --- | --- |
| **G1 — `GracefulGutAI-LambdaExecutionRole` unaudited** | **Substantially answered, formally open.** The live audit completed and assessed the role, but it ran against the *uncorrected* script, so its written review carries the wrong overall verdict. A rerun is what closes this |
| Corrected harness rerun by AJ | **Not done.** No PowerShell on this host |
| Corrected live audit rerun by AJ | **Not done.** Prohibited by this task |
| Whether the deployed role has findings beyond the policy name | **Unknown from the corrected script.** The completed run reported none, but through the logic being replaced here |
| `GracefulGutAI-LambdaExecutionRole` attached policies | **Readable with administrator credentials** — demonstrated by the completed run. Still unreadable from this host, by design |

### Honest assessment of the remaining risk

The substance of the live audit is reassuring: the role resolved cleanly, the
secret grant is correctly scoped to one secret, and the only thing the audit
objected to was a name this repository had recorded wrongly. There is no evidence
of an over-privileged execution role.

What cannot be claimed is that the **corrected** script produces that same
result, because it has not been run. The completed audit exercised the logic this
update replaces. The correction is well covered by tests — 252 of them, including
a runtime scenario reproducing the exact disagreement — but a test asserting on
script text is not a run, and this phase has now been wrong about that three
times. Phase 1G stays open until a corrected run exists.

Nothing here is urgent. The deployed function is unaffected: this task changed no
code the Lambda executes, no configuration, and no IAM.

## Decisions required from AJ or Jenna — this update

One, and it is a confirmation rather than a choice.

**`GracefulGutAI-SecretAccess` is now recorded as the canonical inline-policy
name**, on the evidence that it is what the role carries and that the previous
name appears nowhere as a record of a run. If AJ knows of a deliberate reason the
role should instead carry `GracefulGutAI-ReadApiKeySecret` — an administrator
action taken outside this repository, or a second role in play — say so and this
reverses. Absent that, no action is needed and no IAM should be changed.

No product, security, or architectural decision is required.

## Recommended next step

Rerun the harness. No credentials, no AWS, seconds:

```powershell
git fetch origin
git checkout phase1g-lambda-execution-role-audit
git pull --ff-only

.\scripts\test-audit-lambda-execution-role-runtime.ps1
```

Exit `0` and "All scenarios passed" is the expected result. Scenarios G, H and I
are the new ones to watch: each must report `REVIEW` in **both** the terminal and
the review file, and I must report two findings in both.

Then rerun the live audit with administrator credentials:

```powershell
.\scripts\audit-lambda-execution-role.ps1 -ExpectedSecretName <secret-name> -NoOpen
```

**Exit `0` with `Execution role audit: PASS` is now the expected result** — the
inline policy the previous run flagged is the name the script expects. Compare
the terminal verdict against `**Overall:**` in the written review: they must
agree, and that agreement is what this update exists to produce.

Exit `2` means a genuine least-privilege finding; send the review's findings
table. Exit `1` means it stopped again; send the `DIAGNOSTIC:` line.

Do not paste the secret identifier into this report or any other tracked file.

## Push — this update

Branch `phase1g-lambda-execution-role-audit` pushed to `origin`. **Not merged to
`main`**, per the task.
