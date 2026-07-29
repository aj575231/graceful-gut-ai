# Phase 1F — API Gateway infrastructure foundation

**Date:** 2026-07-28, updated 2026-07-29
**Outcome:** `SUCCESS` — for the repository work in both sessions
**Administrator dry run:** `BLOCKED` — attempted 2026-07-29, produced no AWS
resources. See "Update — 2026-07-29" below.
**Branch:** `phase1f-api-gateway-foundation`

This report is redacted by construction. No account ID, instance ID, full ARN,
API ID, live Function URL, production domain, secret identifier, credential, or
secret value appears anywhere in it. Git commit SHAs are not secrets and are
recorded deliberately.

This report is **updated in place** rather than duplicated, per the reporting
protocol. The 2026-07-28 sections below record the original build and are
unchanged except where a specific claim was corrected; the 2026-07-29 update at
the end records the blocked administrator attempt and the workflow correction
that followed it.

---

## Confirmation: AWS was not touched

**No AWS resource was created, read, updated, or deleted during this task.**
Zero AWS API calls of any kind were made — not `sts get-caller-identity`, not a
`describe`, not a `get`. The task was scoped as infrastructure-as-code and
verification only, and the constraint was read as written: *read* is on the
prohibited list, so the session did not even confirm the account it was running
in.

| Constraint | Status |
| --- | --- |
| Create, read, update, or delete any AWS resource | **Not done** — no AWS API call |
| Deploy | **Not done** |
| Access Secrets Manager | **Not done** |
| Create or request an API key | **Not done** |
| Change the live Lambda Function URL | **Not done** |
| Enable public free-text traffic | **Not done** — route created only under a parameter that defaults to `false` |
| Add a model-provider call | **Not done** — no provider SDK, endpoint, or credential appears anywhere |
| Merge to `main` | **Not done** |

Commands run were local only: `git`, `pytest`, `ruff`, `python`, and file
writes.

---

## Task objective

Implement an administrator-controlled AWS SAM infrastructure foundation for the
public entry point — Regional REST API, WAF Web ACL attached to the stage,
IP-free access logging, and a disabled-by-default education route — that
**references** the existing application Lambda by parameter rather than
managing or replacing it, together with static tests locking in its invariants.

---

## Commits

| Role | Commit | Message |
| --- | --- | --- |
| Starting point | `6abbdbe57c5f066119bbbbc8808a195ec52c24d0` | *Merge Phase 1E API Gateway architecture* |
| Implementation and tests | `e6ec129129e1e0ace28ec02e204073fad30a27e5` | *Build Phase 1F API Gateway foundation* |
| This report | the final commit on the branch | *Document Phase 1F infrastructure foundation* |

A report cannot quote its own hash, so the row above names the commit rather
than reproducing it.

---

## Files

### Added

| File | Contents |
| --- | --- |
| `infrastructure/phase1f/template.yaml` | The infrastructure stack: REST API, explicit stage and deployment, request validation, WAF Web ACL and association, access log group, per-method Lambda invoke permissions |
| `infrastructure/phase1f/README.md` | What the stack owns and must never own; placeholder convention; the two design points that are easy to get wrong; known gaps |
| `infrastructure/phase1f/administrator-runbook.md` | Prerequisites, create, update, verification, rollback, kill switch, and the preconditions on ever enabling the education route |
| `infrastructure/phase1f/parameters.example.json` | Parameter file shape, placeholder values only |
| `backend/tests/test_phase1f_foundation.py` | 82 static and template guards |
| `docs/audits/phase1f-api-gateway-foundation-2026-07-28.md` | This report |

### Modified

| File | Change |
| --- | --- |
| `docs/audits/phase1e-api-gateway-design-2026-07-28.md` | Corrected the stale sentence naming the substantive commits — see below |

### Deleted

None.

**No application code was modified.** `backend/app/` is untouched, so the
Lambda package is unchanged and `CodeSha256` is unaffected.

---

## What was built

### The stack references the application; it cannot replace it

`ApplicationFunctionArn` is a parameter. The template declares no
`AWS::Lambda::Function`, no `AWS::Serverless::Function`, no alias, no version,
no `AWS::Lambda::Url`, and no reserved-concurrency property. A stack update — or
a stack **delete** — cannot replace, reconfigure, or remove the running
application. Reserved concurrency stays at `2` and stays with the application
deployment path, deliberately: setting it to `0` is the emergency kill switch
and must not wait for an administrator to be found.

### API surface

`GET /health` and its `OPTIONS` preflight, both wired to the same `AWS_PROXY`
integration. `POST /v1/education/ask` and its preflight exist only when
`EnableEducationRoute` is `true`, which it is not by default.

There is deliberately **no `{proxy+}` greedy path**. A proxy resource would
expose the application's entire route table — `/`, `/version`, and anything
added later — through one line of template, which is the opposite of a minimum
public surface. Nothing is served at the API root. No `/docs`, `/redoc`,
`/openapi.json`, administrative, debug, or clinical-scheduling path exists, and
a test asserts none can be added without failing the suite.

`OPTIONS` is wired to the Lambda rather than answered by a gateway MOCK
integration. On a REST API, `OPTIONS` is not automatic: unless it reaches the
integration, API Gateway answers it itself — typically `403` — and the preflight
fails before the application's CORS middleware is consulted. Wiring it through
also keeps CORS with exactly one owner.

### Request validation

`ValidateRequestBody` and `ValidateRequestParameters` are both on — validation
is off by default, and a model attached without it does nothing at all. The
JSON Schema requires `message`, caps it at 2,000 characters, and sets
`additionalProperties: false`. `Content-Type` is a required request parameter,
so a request omitting it is rejected by the validator rather than forwarded.

### WAF

Nine rules. The two that cannot produce a false positive on prose — a
4,096-byte body ceiling and a `GET`/`POST`/`OPTIONS` method allow-list — are
`Block` immediately. Everything else starts in `Count`: all five managed rule
groups, and both rate-based rules.

Count-first is not caution for its own sake. The Common Rule Set and SQLi rules
inspect request bodies with heuristics tuned for web payloads, and ordinary
descriptions of gut symptoms trip them — `Crohn's disease` contains the
apostrophe SQLi heuristics weight most heavily, and *"a sudden drop in
appetite"* contains a SQL keyword. Blocking a user describing their symptoms is
a product failure, not a security win.

`AWSManagedRulesAnonymousIpList` is `Count` and is not a promotion candidate.
Blocking VPN and Tor traffic on a gut-health service punishes exactly the users
most likely to want privacy while researching a sensitive symptom.

No geographic restriction, because `CLAUDE.md` limits clinical services to
Indiana and explicitly does **not** limit educational content, and this is the
educational endpoint. No CAPTCHA or Challenge action. No
`AWS::WAFv2::LoggingConfiguration` — WAF logs always carry the client IP and
cannot be configured to drop it, so enabling them would mean retaining IP
addresses by default.

The Web ACL is associated with the **stage**. A Web ACL that exists but is
associated with nothing inspects nothing while looking perfectly healthy in the
console, and a test asserts the association target.

### Access logging

The log format is written out rather than left at a default, because API
Gateway's common formats include `$context.identity.sourceIp`. It carries seven
fields and nothing else: request ID, timestamp, resource path, status,
integration status, latency, response length. Every one is server-generated or
an enumerated protocol value. A test parses the format and asserts the field set
matches exactly — not a superset, not a subset.

`DataTraceEnabled` is `false` on every method setting, including the
conditional one. Data-trace logging writes full request and response bodies to
CloudWatch; turned on, it would put user health text in a log the moment the
education route was enabled. `LoggingLevel` is `ERROR`, never `INFO`.

### CORS

Enforced in one place — the application — with the origins supplied as stack
parameters and published as a stack **output**, so configuration flows
infrastructure → application and never the reverse. The application path cannot
redefine what protects it.

`ProductionOrigin` has an `AllowedPattern` that structurally rejects a wildcard,
a path, a port, and plain `http`; the pattern is exercised directly by the
tests. `DevelopmentOrigin` is separately parameterized, optional, and permits
loopback — the one place plain `http` is acceptable, because it never leaves the
machine. The tracked CORS contract allows `Content-Type` and nothing else,
credentials `false`, `GET`/`POST`/`OPTIONS`, no exposed headers.

### Stack separation

The infrastructure stack owns the API, stage, WAF, log group, and the Lambda
resource-policy statements. The application path owns code, function
configuration, and reserved concurrency. The runbook drives every change through
an administrator-reviewed CloudFormation change set with an explicit review
checklist, and documents create, update, verification, rollback, and the kill
switch. **None of those procedures was executed.**

---

## Three corrections to the Phase 1E design

Each was found while building from the ADR, and each is recorded in the
template rather than only here. This continues the pattern the Phase 1E
correction review established: the expensive failures are the ones where a
control looks enforced in a design document and is absent in production.

| # | ADR as written | Correction |
| --- | --- | --- |
| 1 | WAF rate-based rule of 40 (dev) or 60 (beta) requests per five minutes on the chat route | **Not expressible.** AWS rejects a rate-based `Limit` below **100** per evaluation window. `MinValue: 100` on both rate parameters makes this fail at template validation rather than at apply time. A sub-100 effective limit needs API Gateway per-method throttling or an application-side counter |
| 2 | `PassthroughBehavior: NEVER` closes the content-type validation gap | **Inert on an `AWS_PROXY` integration.** Passthrough governs integrations that use `RequestTemplates`, and a proxy integration has none. Registering the model under **`$default`** is what actually stops a `text/plain` body reaching the function unvalidated. `NEVER` is still set as specified, and documented as a no-op |
| 3 | 4 KB body cap enforced by a WAF `SizeConstraintStatement` | Correct, but incomplete. A body past WAF's inspection limit **cannot be measured**, so the rule needs `OversizeHandling: MATCH`. With `CONTINUE` the very largest bodies — the ones the rule exists for — would pass unblocked |

Correction 3 is the same class of error as Phase 1E's own correction 2, one
layer down: a size control that is present, plausible, and silently incomplete
at exactly the input it was written for.

Two further points are recorded in the template and README as design notes
rather than corrections: the WAF body-inspection limit for **API Gateway** is
16 KB by default and configurable to 64 KB (the 8 KB figure applies to ALB and
AppSync), and it is set explicitly to `KB_16` so the value is reviewed rather
than inherited; and `AWS::ApiGateway::Deployment` is immutable, so the stack can
update successfully while callers still see the previous route configuration.

---

## Correction to the Phase 1E report

The Phase 1E audit stated that its two substantive commits were `bee683e` and
`82d045e`. That conflated the report with the work: `82d045e` is a report
commit and changed no design artefact, and the sentence left `8b5cd35` —
the commit carrying nine corrections, two of which would otherwise have
produced a broken design — unlisted. The architecture implementation commits are
**`bee683e` and `8b5cd35`**. Corrected in this task's report commit, with the
reason recorded in place rather than silently overwritten.

---

## Verification results

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 235 passed, 0 failed, 0 skipped (153 before this task, 82 added) |
| `backend/tests/test_phase1f_foundation.py` alone | **PASS** — 82 passed |
| `.venv/bin/ruff check backend/` | **PASS** — all checks passed |
| `.venv/bin/ruff format backend/` | 1 file reformatted |
| `.venv/bin/ruff format --check backend/` | **PASS** — 15 files already formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| Template parses under a CloudFormation-aware YAML loader | **PASS** |
| `parameters.example.json` parses and covers every parameter | **PASS** |
| Deployment | **Not performed** — out of scope |
| `aws cloudformation validate-template` | **Not run** — it is an AWS API call, and this task made none |

Python 3.13 coverage is CI's, not the local venv's, as `CLAUDE.md` records.

### The 82 tests

| Area | Guards |
| --- | --- |
| Template validity | required and recognised top-level sections, well-formed resource types, no dangling `Ref`, every condition defined and used, every parameter used, the transform generates nothing |
| Redaction | no twelve-digit account ID, no literal URL, domain, or API ID, placeholders in the example parameter file — plus a self-test proving the URL detector catches a planted address |
| No browser-visible secret | the CORS contract offers no credential header; no credential name in the template; and a **tripwire** that fails the moment a non-loopback origin is added to the application while `X-GG-Key` is still in its allowed headers — with a synthetic self-test, since it has nothing to fire on today |
| CORS | no wildcard (asserted by exercising the parameter patterns against `*`, `https://*.…`, and a path), credentials `false`, methods limited, origins exported not imported |
| Education route | disabled by default, every one of its nine resources conditional, the condition true only for the exact string |
| Request validation | body and parameters validated, `maxLength` 2000, `additionalProperties: false`, model under both `application/json` and `$default`, `Content-Type` required, `PassthroughBehavior: NEVER` |
| WAF | 4,096-byte size rule with `OversizeHandling: MATCH`, `KB_16` inspection limit for `API_GATEWAY`, method allow-list, all five managed groups in `Count`, anonymous-IP rule not `Block`, no logging configuration, no geo rule, no CAPTCHA or Challenge, rate limits parameterized above the AWS floor, association targets the stage |
| Logging | permitted field set matched exactly, forbidden tokens absent, `DataTraceEnabled: false` on every setting including conditional ones, retention bounded at 30 days |
| Lambda and separation | no function/alias/version/URL resource, ARN parameter constrained, every permission `SourceArn`-scoped to this API, stage, and method with no wildcard, no reserved concurrency, no IAM, no budget |
| Surface | prohibited routes absent, nothing at the root, no greedy proxy, only `GET`/`POST`/`OPTIONS`, every method anonymous and proxying to the referenced function, preflight on every public resource, stage and deployment both explicit, API regional |
| Documentation | runbook covers change sets, create, update, verification, rollback, and the kill switch, and records that none was executed |

Two guards are tested against synthetic inputs first, because both would
otherwise pass by matching nothing: the credential-header tripwire and the URL
detector. A scanner that silently matches nothing protects nothing — the same
reasoning that produced the detector self-tests in Phase 1E.

---

## Deployment status

**Not deployed.** Nothing was uploaded, no stack was created, no change set was
created, and `CodeSha256` is unchanged because no application code was
modified.

---

## AWS resources created, read, modified, or deleted

**None.** Zero AWS API calls were made during this task.

---

## Security and privacy checks

| Check | Result |
| --- | --- |
| No credential, token, or secret value in any added file | **PASS** |
| No secret identifier in this report | **PASS** |
| No account ID, instance ID, full ARN, or API ID committed | **PASS** — enforced by test |
| No production domain or live URL committed | **PASS** — enforced by test; the origin is a deployment-time parameter |
| No wildcard CORS origin possible | **PASS** — structurally rejected by the parameter pattern |
| `X-GG-Key` never offered to a browser | **PASS** — plus a tripwire for the future |
| Access logs carry no IP, user agent, header, query string, or body | **PASS** — field set asserted exactly |
| Request and response bodies never logged | **PASS** — `DataTraceEnabled: false` everywhere |
| No WAF logging resource | **PASS** |
| No PHI path introduced | **PASS** — no storage, no persistence, no third-party call added |
| Public free-text input still disabled | **PASS** — route conditional, default `false` |
| Fail-closed preserved | **PASS** — application `503`/`401` behaviour untouched |

### One privacy trade-off, made deliberately

WAF **sampled requests** are enabled. AWS retains a sample — including client IP
and request fragments — for roughly three hours, and it cannot be redacted. This
is the only mechanism by which a count-mode rollout can be reviewed before a
rule is promoted to `Block`, so disabling it would make the entire count-first
plan inert. It is bounded, it is recorded in the template beside the setting,
and it is distinct from WAF *logging*, which is absent precisely because it
cannot omit IP at all. It sits against open decision 4 and should be confirmed
rather than inherited.

---

## Blockers and unresolved findings

No blockers. The task completed in full. Five findings are carried forward:

| # | Finding | Why it matters |
| --- | --- | --- |
| 1 | **Rate rules ship in `Count`** | A rate rule in `Count` protects nothing. `WafRateRuleAction` must be `Block` before the education route carries public traffic, and the education route is the only one that costs model spend |
| 2 | **WAF cannot express the ADR's chat-route rate limits** | The 100-per-window floor is an AWS constraint, not a tuning choice. A tighter effective limit requires API Gateway per-method throttling or an application-side counter — an owner decision |
| 3 | **The application still lists `X-GG-Key` in its CORS allowed headers** | Harmless today, because the only configured origins are loopback. It becomes a real exposure the moment a production origin is added. Not changed here — this task was scoped to infrastructure — but a tripwire test now fails the suite if both conditions hold at once. **This is application work that must land before any public origin is configured** |
| 4 | **Redeployment is a manual step** | `AWS::ApiGateway::Deployment` is immutable, so a stack update can succeed while callers still see the old routes. The runbook makes `create-deployment` explicit; it is the most likely way to conclude a change is live when it is not |
| 5 | **`GracefulGutAI-LambdaExecutionRole` remains unaudited** | Carried forward from Phase 1D and 1E. Its attached policies are not readable from the dev role and need administrator credentials to review |

---

## Decisions required from AJ and Jenna

The twelve open decisions in the Phase 1E ADR are unchanged and none was
decided here. Phase 1F adds four that follow directly from building the stack:

| # | Decision | Recommendation |
| --- | --- | --- |
| **F1** | **Are WAF sampled requests acceptable**, given ~3 hours of IP retention that cannot be redacted? | **Yes, keep them.** They are the only way to review a count-mode rollout. This refines open decision 4, which previously treated WAF logging and sampling together |
| **F2** | **What is the effective chat-route rate limit**, now that WAF cannot go below 100 per window? | Per-method API Gateway throttling at 1–2 rps as the primary control, with the WAF rule at the 100 floor as a backstop |
| **F3** | **What stage name and what stack name** should the first deployment use? | `dev` and a `graceful-gut-ai-dev-infrastructure`-style name; one stage per stack |
| **F4** | **Who executes the change sets?** | Named administrator, not this host. The runbook is written for that person and the dev role holds none of the required actions |

The two launch-blocking determinations from Phase 1E — **L1 legal and
compliance**, **L2 model-provider data flow** — remain open and remain
launch-blocking. Nothing in this task advanced or relaxed either.

---

## What Phase 1F does not do

- It does not create infrastructure. The template exists; nothing is applied.
- It does not enable public free-text input. `EnableEducationRoute` defaults to
  `false`, and turning it on does not by itself satisfy the `CLAUDE.md` release
  gate — L1, L2, an authentication decision replacing `X-GG-Key`, and boundary
  enforcement in the request path all come first.
- It does not retire the Function URL. That is a separate administrator
  sequence with its own rollback.
- It does not resolve the `X-GG-Key` replacement.
- It does not create AWS Budgets.
- It does not implement the application-side controls the design depends on:
  byte-size and character-length checks, `415` for an unsupported content type,
  boundary enforcement on every response, or the static emergency guidance.
  Those are Phase 2 application work.

---

## Recommended next step

**Owner review of F1–F4 and the Phase 1E decision list, then an administrator
dry run of the create change set** — `create-change-set` followed by
`describe-change-set`, reviewed against the checklist in the runbook, and
**deleted rather than executed**. That exercises the template against real
CloudFormation validation and the account's real constraints while creating
nothing, and it is the cheapest way to find a template error before it matters.

The account-level API Gateway CloudWatch role (runbook prerequisite 2) is the
most likely first-attempt failure and is worth confirming before the dry run.

> **2026-07-29:** that prediction was correct, and the dry run was attempted and
> blocked on exactly that prerequisite. See the update below. The recommended
> next step is now the one at the end of this report.

---

## Push

The implementation commit was pushed to `origin` and the branch tracks
`origin/phase1f-api-gateway-foundation`; the push created the remote branch and
reported no errors. The report commit is pushed as the final action of this
task.

Nothing was merged to `main`. Nothing was deployed. No AWS resource was created,
read, updated, or deleted.

---
---

# Update — 2026-07-29: blocked administrator dry run, workflow corrected

**Outcome of this session's work:** `SUCCESS` — repository only.
**Outcome of the administrator dry run it responds to:** `BLOCKED`.

## What the administrator attempt actually did

The dry run recommended above was attempted on Windows by pasting the runbook's
commands into a console. It did not complete. Recorded exactly:

| # | What happened |
| --- | --- |
| 1 | `aws apigateway get-account` returned **no `cloudwatchRoleArn`** — runbook prerequisite 2 was not satisfied in the region |
| 2 | The prerequisite check **correctly raised an error** — and the remaining commands were pasted and executed separately anyway |
| 3 | The generated parameter file URI was `file:///C:/Users/...` |
| 4 | The AWS CLI **rejected it as an invalid Windows path** |
| 5 | **`create-change-set` never succeeded.** No CloudFormation stack and no change set ever existed |
| 6 | The later validation and deletion calls failed **because the stack did not exist**, not for any reason to do with the template |
| 7 | The pasted commands nevertheless **wrote a review file recording `PASS`** and printed **unconditional cleanup success messages** |
| 8 | **No CloudFormation resources were created or modified.** None |

The invalid `PASS` review from that attempt was deleted. It is not in this
repository, was never committed, and must not be treated as evidence of
anything. **The template has still never been checked against real
CloudFormation.**

Item 7 is the one that mattered most. A dry run that fails loudly costs an
afternoon. A dry run that fails and files a passing review is read months later
as proof the template was validated, and the cost lands then.

## What this session changed

Repository work only. **No AWS API call of any kind was made in this session**
— not `sts get-caller-identity`, not a `describe`, not a `get`. The two new
scripts were **written, not executed**: both require administrator credentials
this host does not hold and must never hold, so their behaviour is pinned by
static tests rather than by running them.

### Added

| File | Contents |
| --- | --- |
| `scripts/admin-dry-run.ps1` | The whole dry run as one fail-closed script: six prerequisites, parameter file, `validate-template`, a CREATE change set, assertions, review, and cleanup of both objects it creates |
| `scripts/setup-apigw-cloudwatch-role.ps1` | Administrator-only, one-time prerequisite helper for the account-level API Gateway CloudWatch role. Plan by default; writes only with `-Apply` |
| `backend/tests/test_phase1f_admin_workflow.py` | 100 static guards over both scripts and the runbook |

### Modified

| File | Change |
| --- | --- |
| `infrastructure/phase1f/administrator-runbook.md` | Records the blocked attempt; names the two scripts as the preferred Windows workflow; corrects the `validate-template` claim; documents Windows parameter-file syntax and the empty `REVIEW_IN_PROGRESS` stack; prohibits continuing by hand after a failure |
| `docs/audits/phase1f-api-gateway-foundation-2026-07-28.md` | This update |

No application code was modified. `backend/app/` is untouched and `CodeSha256`
is unaffected.

## How each failure is now prevented

| Failure | Correction |
| --- | --- |
| Continuing past a failed prerequisite | `admin-dry-run.ps1` aborts the entire run on the first failure. Failures `throw`, which unwinds into the `finally` block — there is no next command left for anyone to paste |
| Judging a call by whether output appeared | Every AWS call returns an exit code and is checked. `Invoke-AwsOrStop` stops the run on a nonzero one |
| The `file:///C:/` URI | `Get-CliFileArgument` returns `file://` plus the resolved native path. Tests forbid `file:///` in executable lines and forbid `AbsoluteUri` and `System.Uri` outright — those are how the bug returns |
| Validating after a failed creation | The run stops between `create-change-set` and anything that reads the change set back. A test asserts the guard precedes the first `describe-change-set` |
| Executing a change set | The CLI verb does not appear anywhere in the file, and a test asserts its absence across the whole text |
| Unconditional `PASS` | The literal is produced in exactly one function, `ConvertTo-Outcome`, which takes a `[bool]`. Tests assert one occurrence in executable code and that no `Write-Host` prints the word directly |
| Unconditional cleanup success | `ConvertTo-CleanupOutcome` takes `-Existed` and `-Removed` and distinguishes `REMOVED`, `NOT PRESENT`, and `STILL PRESENT`. Deleting something that was never there is not reported as a success |
| A review for a run that did not finish | The review is written only after every assertion passes, and is scanned for account IDs, ARNs, URLs, and credential names before it is written — a match means no file |
| The empty `REVIEW_IN_PROGRESS` stack | Cleanup deletes the change set **and** the stack record, then confirms absence by re-reading rather than inferring it from an exit code |
| A parameter file left in the repository | Written under `%TEMP%`, UTF-8 without BOM, deleted in a `finally` block. The script refuses to run if `%TEMP%` resolves inside the checkout |

### Prerequisites the script now enforces before anything is created

Working tree clean; branch is `phase1f-api-gateway-foundation`; the AWS profile
resolves; the application function is `Active` with `LastUpdateStatus`
`Successful`; the account-level API Gateway CloudWatch role is configured in the
region; and no non-deleted stack already holds the requested stack name. An
unset `cloudwatchRoleArn` renders as the literal `None` under `--output text`,
which is a non-empty string — the check treats `None` and `null` as unset, and a
test pins that.

### What the dry run asserts about the change set

Every change is an `Add`; there are exactly **eleven**, which is the template's
twenty resources minus the nine conditional on the education route; the logical
IDs are exactly the reviewed set; no `AWS::Lambda::Function`, `AWS::Lambda::Url`,
IAM, WAF-logging, or budget resource appears; and `EnableEducationRoute=false`,
`StageName=dev`, `WafRateRuleAction=Count`. The eleven expected IDs are pinned
against the template itself, so adding a resource without updating the dry run
fails in the test suite rather than in front of an administrator.

### The role helper

Plan by default — without `-Apply` it reads the current state and reports what
would differ. A test asserts every mutating call appears after the plan-mode
early exit, so plan mode cannot reach one however the branches fall. In apply
mode it creates one role trusting **only** `apigateway.amazonaws.com`, attaches
**only** the AWS-managed `AmazonAPIGatewayPushToCloudWatchLogs` policy, sets the
account value, and reads it back to verify. If a role of that name already
exists with a different trust policy, extra attached policies, or inline
policies, it **stops rather than overwriting it** — a role this procedure does
not own may be serving something else.

Account IDs and ARNs are masked out of everything both scripts print, ARNs
before bare account IDs so no half-masked ARN survives. The AWS-managed policy
ARN is deliberately exempt: it contains no account field, and masking it would
hide the one detail a reviewer needs.

## Verification results — 2026-07-29

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 335 passed, 0 failed, 0 skipped (235 before this session, 100 added) |
| `backend/tests/test_phase1f_admin_workflow.py` alone | **PASS** — 100 passed |
| `.venv/bin/ruff check backend/` | **PASS** — all checks passed |
| `.venv/bin/ruff format backend/` | 1 file reformatted |
| `.venv/bin/ruff format --check backend/` | **PASS** — 16 files already formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| PowerShell syntax parse | **Not run** — no PowerShell interpreter on this host. The scripts are guarded by static tests and are unexecuted; a first run belongs to the administrator |
| Either new script executed | **No** — deliberately. Both need administrator credentials this host does not hold |
| `aws cloudformation validate-template` | **Not run** — it is an AWS API call, and this session made none |

Eleven of the new tests failed on first run and were the reason for four script
changes and one runbook rewording, rather than being relaxed to fit. Two of
them are self-tests — the comment stripper and the "substantial script after
stripping" check — because a text scanner that silently matches nothing protects
nothing. That is the same reasoning behind the URL-detector and
credential-tripwire self-tests from the original Phase 1F suite.

## AWS resources created, read, modified, or deleted — 2026-07-29

**None.** Zero AWS API calls were made in this session. The administrator
attempt that this session responds to also created and modified **no**
CloudFormation resources: no stack, no change set, no API, no WAF Web ACL, no
log group. The only account-level fact it established is that
`cloudwatchRoleArn` is unset in the region.

## Security and privacy checks — 2026-07-29

| Check | Result |
| --- | --- |
| No credential, token, or secret value in either script | **PASS** — enforced by test |
| No twelve-digit account ID in either script | **PASS** — enforced by test, with detector regexes excluded so the rule stays honest |
| No hardcoded account-bearing ARN | **PASS** — enforced by test; the AWS-managed policy ARN is the one exempt literal and carries no account field |
| No live URL or SSO start URL in either script | **PASS** — enforced by test; only `https://example.com` and `<approved-origin>` placeholders |
| No API ID read or recorded | **PASS** — a change set describes logical IDs; the physical ID does not exist until it is executed |
| Production origin is a parameter, never committed | **PASS** — mandatory parameter with no default, enforced by test |
| Completed parameter file never enters Git | **PASS** — `%TEMP%` only, refused if `%TEMP%` is inside the checkout, deleted in `finally` |
| Review is scanned for leaks before it is written | **PASS** — fail closed: a match writes no file |
| Terminal errors pass through the mask | **PASS** — enforced by test |
| No IAM created or modified by this session | **PASS** — the helper was written, not run |
| No Secrets Manager access | **PASS** — neither script contains a `secretsmanager:` call |
| No PHI path introduced | **PASS** |
| Public free-text input still disabled | **PASS** — unchanged; the dry run asserts `EnableEducationRoute=false` |

## Blockers and unresolved findings — 2026-07-29

| # | Finding | Status |
| --- | --- | --- |
| **A** | **The account-level API Gateway CloudWatch role is not configured in the region.** This is the original blocker and it is unresolved | Administrator action. `setup-apigw-cloudwatch-role.ps1 -Apply` does it; this host holds no IAM write and no `apigateway:PATCH` on `/account` and cannot |
| **B** | **The template has never been validated against real CloudFormation.** Every check on it to date is static | Cleared by running `admin-dry-run.ps1` once A is done |
| **C** | Neither new script has ever been executed | By design. First run is the administrator's, and it should be the plan-mode helper |
| **D** | PowerShell syntax is not parsed anywhere in CI | The repository has no PowerShell linting for `pull-task-report.ps1` either. Worth adding if the Windows helper set keeps growing — see the next-step note |

Findings 1–5 from the 2026-07-28 section are unchanged and still open.

## Decisions required from AJ or Jenna — 2026-07-29

None new. F1–F4 and the twelve Phase 1E open decisions are unchanged, and L1
and L2 remain launch-blocking. This session corrected a workflow; it decided
nothing about the product.

One judgement call was made and is flagged rather than buried: the second script
is named `scripts/setup-apigw-cloudwatch-role.ps1`. The task named the file
partially; this name follows the repository's verb-noun script convention.
Rename it if you prefer a different one — the runbook and tests reference it in
three places.

## Recommended next step

1. **Administrator runs `.\scripts\setup-apigw-cloudwatch-role.ps1`** with no
   switch first. It changes nothing and reports what it would do.
2. **Then `-Apply`**, which resolves blocker A.
3. **Then `.\scripts\admin-dry-run.ps1 -ProductionOrigin <approved-origin>`**,
   which resolves blocker B and produces a review file under `%TEMP%`.
4. Paste that review into this report. It is written to be redacted already —
   no account ID, ARN, API ID, or URL — so it can be pasted as-is.

If any step stops, **fix the reported cause and re-run the script**. Do not
paste the individual commands to get past the step that failed. That is what
turned a correctly-detected missing prerequisite into a review claiming PASS.

## Push — 2026-07-29

Implementation and report committed separately. The branch was pushed to
`origin/phase1f-api-gateway-foundation`. **Nothing was merged to `main`.**
Nothing was deployed. No AWS resource was created, read, updated, or deleted,
and no IAM or Secrets Manager call was made.
