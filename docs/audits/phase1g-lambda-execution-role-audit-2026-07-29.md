# Phase 1G — Lambda execution-role audit tooling

**Date:** 2026-07-29
**Outcome:** `SUCCESS` — tooling built, tested, and committed.
**The audit itself:** **NOT PERFORMED.** The script has never been executed. The
`GracefulGutAI-LambdaExecutionRole` finding remains **open** and closes only when
AJ runs the script and supplies its review.
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
| Script executed | **No** — deliberately. It needs administrator credentials this host does not hold |

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
| **G1** | **The execution-role audit has not been performed.** This is the original Phase 1D finding and it is **still open** | The tooling now exists. It closes when AJ runs the script and supplies the review. **Do not record this finding as resolved before then** |
| **G2** | The script has never been executed, and PowerShell is not parsed on this host or in CI | By design for the first part: it needs administrator credentials this host must never hold. The second part is finding **D** from Phase 1F, now covering three Windows helpers rather than two |
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
