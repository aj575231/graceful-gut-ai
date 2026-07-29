# Phase 1F — API Gateway infrastructure foundation

**Date:** 2026-07-28, updated twice on 2026-07-29
**Outcome:** `SUCCESS` — for the repository work in every session
**Administrator dry run:** `SUCCESS` — completed 2026-07-29 on the corrected
Windows workflow, after a first attempt the same day was `BLOCKED`. The dry run
itself created no CloudFormation stack and no template resource; its one-time
logging prerequisite did make three AWS changes, itemised below. See
"Update — 2026-07-29 (later)" at the end of this report.
**Branch:** `phase1f-api-gateway-foundation`

This report is redacted by construction. No account ID, instance ID, full ARN,
API ID, live Function URL, production domain, secret identifier, credential, or
secret value appears anywhere in it. Git commit SHAs are not secrets and are
recorded deliberately.

This report is **updated in place** rather than duplicated, per the reporting
protocol. It now carries three sessions in chronological order, and the earlier
sections are preserved as an audit trail rather than rewritten:

| Section | Records |
| --- | --- |
| 2026-07-28 | The original build of the template, runbook, and static tests |
| Update — 2026-07-29 | The **blocked** first administrator attempt and the workflow correction that followed it. Retained in full: the failure is why the corrected workflow exists |
| Update — 2026-07-29 (later) | The **successful** administrator validation on the corrected workflow |
| Update — 2026-07-29 (final) | Documentation finalised and owner decisions **F1–F4 approved** — this update |

Where a superseded claim appears in an earlier section it is marked in place and
pointed forward, never deleted.

---

## Confirmation: AWS was not touched

> **Scope of this section — read before quoting it.** It covers the **Claude
> sessions** that produced this repository work, all three of which made zero
> AWS API calls. It does **not** cover the administrator's own work. The
> administrator's successful validation of 2026-07-29 did change three things in
> AWS, itemised precisely under "AWS resources created, read, modified, or
> deleted — 2026-07-29 (later)". Do not read this section as a claim that AWS was
> untouched across the whole of Phase 1F.

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
> **All four were approved on 2026-07-29.** The recommendations below are what
> was put to the owner; the approved wording — which narrows F1 and F2 rather than
> adopting them verbatim — is in the final update at the end of this report.

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

> **2026-07-29:** that prediction was correct. The dry run was attempted and
> blocked on exactly that prerequisite (first update below), the prerequisite was
> then satisfied by the helper script, and the dry run **completed successfully**
> on the second attempt (second update below). The recommended next step is now
> the one at the end of this report.

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

> **Superseded later the same day, and kept deliberately.** The blocked attempt
> recorded here is the reason the corrected scripted workflow exists, so it stays
> in the record in full. Both blockers it raised — the missing account-level
> `cloudwatchRoleArn` (finding **A**) and the template never having been
> validated against real CloudFormation (finding **B**) — were **resolved** in
> the update that follows this one, as was finding **C**. Nothing in this section
> should be read as the current state.

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

> That last sentence describes the account **at the time of the blocked
> attempt**. `cloudwatchRoleArn` was configured later the same day by the
> administrator; see the AWS accounting in the update below.

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
| **A** | **The account-level API Gateway CloudWatch role is not configured in the region.** This is the original blocker and it is unresolved | ~~Administrator action~~ → **RESOLVED 2026-07-29**, see the update below. `setup-apigw-cloudwatch-role.ps1 -Apply` did it; this host holds no IAM write and no `apigateway:PATCH` on `/account` and cannot |
| **B** | **The template has never been validated against real CloudFormation.** Every check on it to date is static | ~~Cleared by running `admin-dry-run.ps1` once A is done~~ → **RESOLVED 2026-07-29**: `admin-dry-run.ps1` ran and CloudFormation accepted the template and built a change set from it |
| **C** | Neither new script has ever been executed | ~~By design~~ → **RESOLVED 2026-07-29**: both were executed on Windows by the administrator, the helper in plan mode first, exactly as intended |
| **D** | PowerShell syntax is not parsed anywhere in CI | **Still open.** The repository has no PowerShell linting for `pull-task-report.ps1` either. Both scripts have now run successfully on Windows, which is stronger evidence than a linter, but it is one run on one machine — see the next-step note |

Findings 1–5 from the 2026-07-28 section were unchanged as of this update. Their
current status is in the update below; **finding 3 — `X-GG-Key` in the
application's CORS allowed headers — remains open and remains a prerequisite for
any public origin.**

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

> **All four steps were carried out on 2026-07-29 and all four succeeded.** The
> instruction above was followed as written — the workflow was driven entirely
> through the two scripts, with no command pasted by hand. Results in the update
> below.

## Push — 2026-07-29

Implementation and report committed separately. The branch was pushed to
`origin/phase1f-api-gateway-foundation`. **Nothing was merged to `main`.**
Nothing was deployed. No AWS resource was created, read, updated, or deleted,
and no IAM or Secrets Manager call was made.

---
---

# Update — 2026-07-29 (later): administrator validation completed successfully

**Outcome of the administrator validation:** `SUCCESS`.
**Outcome of this session's work:** `SUCCESS` — documentation and verification
only, no code or infrastructure change.
**Branch:** `phase1f-api-gateway-foundation`.

This update closes the loop opened by the blocked attempt above. The corrected
scripted workflow was run on Windows by the administrator and completed: the
one-time logging prerequisite was satisfied, and the template was validated
against real CloudFormation for the first time.

## Provenance of the facts in this section

Everything below is the **administrator's reported result**, recorded as supplied.
This session made **zero AWS API calls** and therefore confirmed none of it
against the account independently — that separation is the point of the access
model, not a gap in it. The facts are recorded as an administrator attestation,
and a reader who needs account-level proof should re-read the account with
administrator credentials rather than treat this report as the source of truth.

## Step 1 — the one-time API Gateway logging prerequisite

`scripts/setup-apigw-cloudwatch-role.ps1`, run on Windows.

| # | Step | Result |
| --- | --- | --- |
| 1 | Run with **no switch** — plan mode | **PASS.** Reported what it would do and **made no changes**, which is exactly the designed behaviour and the reason plan mode is the default |
| 2 | Run with **`-Apply`** | **PASS.** Created the role, attached the policy, and set the account value |
| 3 | Read-back verification | **PASS.** The account-level value was confirmed present after the write |

What apply mode actually created and changed:

| Item | Detail |
| --- | --- |
| IAM role | **`GracefulGutAI-APIGatewayCloudWatchRole`** — one role, created new |
| Trust policy | Trusts **only** `apigateway.amazonaws.com`. No other principal, no account-wide trust |
| Attached policy | **Only** the AWS-managed `AmazonAPIGatewayPushToCloudWatchLogs`. No customer-managed policy, no inline policy, no additional attachment |
| Account setting | The API Gateway account-level `cloudwatchRoleArn`, set in **`us-east-2`** |

The role name is recorded because it is an identifier, not a credential, and the
repository already names its other roles. The role **ARN** is not recorded, per
the redaction rule.

### IAM propagation needed retries, and the script handled it

The account-level `PATCH` initially failed because the newly created role had not
yet propagated — IAM is eventually consistent, and API Gateway validates that it
can assume the role at the moment the account setting is written. The script
**retried and succeeded**, and the final verification passed.

This is worth recording rather than glossing: it is the single most likely reason
a hand-run version of this procedure would appear to fail on a correctly created
role. An administrator who had pasted the commands would most likely have seen
one failure and concluded the trust policy was wrong.

## Step 2 — the administrator dry run

`scripts/admin-dry-run.ps1`, executed on Windows.

`-ProductionOrigin` was supplied **at runtime** by the administrator. It is
deliberately **not reproduced anywhere in this report**, consistent with the
redaction rule and with the template's design: the origin is a deployment-time
parameter with no default and is never committed.

### Every assertion the run makes

| Gate | Result |
| --- | --- |
| `aws cloudformation validate-template` — the template against real CloudFormation | **PASS** |
| CREATE change-set creation | **PASS** |
| Resource-list validation — every change is an `Add`, count and logical IDs exactly as pinned | **PASS** |
| Parameter validation — the three values the review may not be silent about | **PASS** |

### The change set CloudFormation proposed

**Eleven `Add` actions and nothing else** — no `Modify`, no `Remove`. Eleven is
the template's twenty resources minus the nine conditional on the education
route, and it matched the set pinned in the script exactly:

| # | Logical resource |
| --- | --- |
| 1 | `AccessLogGroup` |
| 2 | `Deployment` |
| 3 | `HealthGetInvokePermission` |
| 4 | `HealthGetMethod` |
| 5 | `HealthOptionsInvokePermission` |
| 6 | `HealthOptionsMethod` |
| 7 | `HealthResource` |
| 8 | `RestApi` |
| 9 | `Stage` |
| 10 | `WebAcl` |
| 11 | `WebAclAssociation` |

No `AWS::Lambda::Function`, no `AWS::Lambda::Url`, no IAM resource, no
WAF-logging resource, and no budget resource appeared — the forbidden-type
assertion held. The application Lambda is referenced by ARN and was not proposed
for management, replacement, or reconfiguration.

Parameters confirmed in the change set:

| Parameter | Value | Why it is asserted |
| --- | --- | --- |
| `EnableEducationRoute` | **`false`** | Public free-text input stays unaccepted. This is the value that keeps the nine conditional resources out of the eleven |
| `StageName` | **`dev`** | One stage per stack |
| `WafRateRuleAction` | **`Count`** | The count-first rollout, and a reminder that rate limiting is not yet enforcing |

### Nothing was created, and cleanup was verified rather than assumed

| Step | Result |
| --- | --- |
| Change set **executed**? | **No — never executed.** The CLI verb does not exist anywhere in the script |
| Unexecuted change set | **Removed** |
| The empty `REVIEW_IN_PROGRESS` stack record | **Removed** |
| Final verification | **PASS — no non-deleted stack remained** |

The `REVIEW_IN_PROGRESS` record is the stack shell CloudFormation creates when a
CREATE change set is made but never executed. Removing it is why the account is
left as it was found, and re-reading to confirm absence — rather than trusting the
delete call's exit code — is the correction made after the blocked attempt.

**No API, stage, WAF Web ACL, log group, Lambda permission, or any other
template resource was created.** The template has now been validated by
CloudFormation without anything being built from it, which is precisely what a
dry run is for.

## AWS resources created, read, modified, or deleted — 2026-07-29 (later)

This accounting is deliberately precise, and it does **not** claim that AWS was
untouched across the administrator process. Three things were changed, all by the
one-time logging prerequisite:

| # | Change | Resource |
| --- | --- | --- |
| 1 | **Created** | One IAM role, `GracefulGutAI-APIGatewayCloudWatchRole` |
| 2 | **Attached** | One approved AWS-managed policy, `AmazonAPIGatewayPushToCloudWatchLogs`, to that role |
| 3 | **Modified** | The regional API Gateway account-level `cloudwatchRoleArn` setting in `us-east-2` |

And what the CloudFormation dry run itself left behind:

| Category | Result |
| --- | --- |
| CloudFormation stack | **None** — the `REVIEW_IN_PROGRESS` record was removed and absence was verified |
| Change set | **None** — created, described, removed |
| Any resource declared in the template | **None** |

| Actor | AWS calls | Notes |
| --- | --- | --- |
| **This session (Claude)** | **Zero** | No `sts get-caller-identity`, no `describe`, no `get`. No IAM call, no Secrets Manager call, no deployment |
| Administrator | The prerequisite and dry-run calls above | Performed off this host with administrator credentials, as the access model requires |

The three prerequisite changes are all **scoped to CloudWatch log delivery for
API Gateway**. None of them grants access to the application function, its
secret, or any data path. The role is not assumable by this host, and this host
gained no permission from any of it.

## Findings resolved by this validation

| # | Finding | Status |
| --- | --- | --- |
| **A** | The account-level API Gateway CloudWatch role is not configured in the region | **RESOLVED.** Role created, policy attached, account value set in `us-east-2`, read back and verified |
| **B** | The template has never been validated against real CloudFormation | **RESOLVED.** `validate-template` passed and CloudFormation built an eleven-`Add` change set from it, matching the pinned resource list and parameters exactly |
| **C** | Neither new script has ever been executed | **RESOLVED.** Both ran on Windows, the helper in plan mode first. Plan mode changed nothing, which independently confirms the plan-mode guard the static tests assert |

The blocked attempt's finding **D** — PowerShell is not syntax-checked in CI —
**remains open**. A successful run on one Windows machine is better evidence than
a linter, but it is not coverage.

## Findings that remain open — nothing here resolves them

The dry run validated a template. It did not build infrastructure, and it
resolved no product, legal, or application question. These are **explicitly not
resolved** and remain launch-blocking:

| # | Blocker | Status and why it is untouched |
| --- | --- | --- |
| **L1** | **Legal and compliance determination** | **OPEN — launch-blocking.** Carried from Phase 1E. A validated CloudFormation template is not a compliance review, and nothing in this task went near one |
| **L2** | **Model-provider data-flow determination** | **OPEN — launch-blocking.** No provider SDK, endpoint, or credential exists anywhere in this repository. The determination of what leaves the account, to whom, and under what terms has not been made |
| **3** | **Browser authentication — the `X-GG-Key` replacement** | **OPEN — launch-blocking.** `X-GG-Key` is still one static shared secret with no per-caller identity, no revocation, and no rate limiting, and the application still lists it in its CORS allowed headers. Harmless only while every configured origin is loopback. A real authentication decision — API Gateway keys with usage plans, a signed short-lived token, or `AuthType: AWS_IAM` — has still not been made, and the tripwire test will fail the suite the moment a non-loopback origin is added while the header remains |
| **4** | **Application boundary enforcement in the request path** | **OPEN — launch-blocking.** The `CLAUDE.md` product boundaries are still enforced in prompt text and documentation, not on every response in the request path. No byte-size or character-length check, no `415` handling, no static emergency guidance. Phase 2 application work, not started |
| **5** | **Public production launch approval** | **OPEN.** Not given, not requested, and not implied by this validation. The `CLAUDE.md` release gate is unsatisfied: API Gateway is **not** in front of the function — the template is validated but nothing is applied, and the raw Function URL is still the entry point |

The four Phase 1F findings carried from 2026-07-28 also stand:

| # | Finding | Status |
| --- | --- | --- |
| 1 | WAF rate rules ship in `Count` | **Open.** Confirmed by the dry run itself — `WafRateRuleAction=Count` is one of the three asserted parameters. A rate rule in `Count` protects nothing |
| 2 | WAF cannot express the ADR's chat-route rate limits | **Open.** An AWS floor of 100 per window, not a tuning choice. Decision **F2** |
| 4 | Redeployment is a manual step | **Open.** `AWS::ApiGateway::Deployment` is immutable; a stack update can succeed while callers still see old routes |
| 5 | `GracefulGutAI-LambdaExecutionRole` remains unaudited | **Open.** Carried from Phase 1D and 1E. Note that the administrator now demonstrably holds credentials sufficient to review it — this is the cheapest moment to close a finding that has been carried three phases |

## What this validation does and does not establish

| It establishes | It does not establish |
| --- | --- |
| The template is syntactically and semantically acceptable to CloudFormation | That the stack works — nothing was built or exercised |
| The resource set is exactly the eleven reviewed, with no surprise twelfth | That the WAF rules behave correctly on real traffic; they have inspected nothing |
| The education route is genuinely off by default, in CloudFormation's own reading of the template | That the route is safe to turn on. It is not — L1, L2, authentication, and boundary enforcement all come first |
| The scripted Windows workflow works end to end, including its cleanup | That it works on any machine but the one it ran on |
| The account's logging prerequisite is satisfied | That access logging is active. It cannot be until a stage exists |

## Verification results — 2026-07-29 (later)

Documentation-only session; the gates were run to prove nothing regressed.

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 335 passed, 0 failed, 0 skipped. Unchanged from the previous session, as expected for a report-only change |
| `.venv/bin/ruff check backend/` | **PASS** — all checks passed |
| `.venv/bin/ruff format --check backend/` | **PASS** — 16 files already formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| AWS calls made by this session | **Zero** |
| Deployment | **Not performed** |

The 335 tests include the 100 static guards over both PowerShell scripts. Those
guards were written before either script had ever run; the successful run is the
first evidence that what they pin is also what works.

## Files — 2026-07-29 (later)

| File | Change |
| --- | --- |
| `docs/audits/phase1f-api-gateway-foundation-2026-07-28.md` | Updated in place — this section, the header outcome, the audit-trail note, and forward pointers on the superseded claims in the earlier sections |

No other file was added, modified, or deleted. No application code, no template,
no script, and no test changed. `backend/app/` is untouched and `CodeSha256` is
unaffected. No IAM document in `infrastructure/` was modified.

The `infrastructure/phase1f/administrator-runbook.md` still describes the
logging role as an unsatisfied prerequisite and still records the blocked
attempt. That is **stale but harmless** — re-running the helper in plan mode is
idempotent and reports the role already correct. It was left unchanged because
this task was scoped to the report, and because the runbook's wording is pinned
by static tests that a wording change would need to move deliberately. See the
next step.

## Security and privacy checks — 2026-07-29 (later)

| Check | Result |
| --- | --- |
| No credential, token, or secret value in this update | **PASS** |
| No secret identifier | **PASS** |
| No account ID, instance ID, or full ARN | **PASS** — one IAM role **name** and one AWS-managed policy **name** are recorded; neither carries an account field |
| `ProductionOrigin` value not reproduced | **PASS** — supplied at runtime, recorded only as "supplied at runtime" |
| No live Function URL, API ID, or production domain | **PASS** — a change set exposes logical IDs only; no physical API ID exists until execution, and it was never executed |
| No PHI, health text, or personal identifying information | **PASS** |
| Secrets Manager accessed | **No** — not by this session, and not by either script |
| IAM modified by this session | **No** — the three IAM/account changes recorded above were the administrator's |
| Public free-text input still disabled | **PASS** — `EnableEducationRoute=false`, confirmed by CloudFormation itself |
| Fail-closed behaviour preserved | **PASS** — the application's `503`/`401` handling is untouched |
| Merged to `main` | **No** |

## Decisions required from AJ or Jenna — 2026-07-29 (later)

Nothing new was decided here and nothing new is raised. The queue is unchanged
and is now the only thing standing between the validated template and a first
stack:

| Decision | Status |
| --- | --- |
| **F1** WAF sampled requests acceptable? | ~~Open~~ → **APPROVED 2026-07-29**, scoped. See the final update |
| **F2** Effective chat-route rate limit, given the 100-per-window floor | ~~Open~~ → **APPROVED 2026-07-29**. See the final update |
| **F3** Stage name and stack name for the first deployment | ~~Partly answered by use~~ → **APPROVED 2026-07-29**, and confirmed explicitly rather than inherited from the dry run's choice |
| **F4** Who executes the change sets | ~~Answered in practice~~ → **APPROVED 2026-07-29**. AJ is named |
| The twelve Phase 1E open decisions | Open |
| **L1** legal and compliance | **Open — launch-blocking** |
| **L2** model-provider data flow | **Open — launch-blocking** |

## Recommended next step

1. **Decide F1–F4**, particularly F2, before any stack is created. The rate-limit
   decision is the one that costs money if it is wrong, and `Count` mode means it
   is currently not enforced at all.
2. **Refresh `administrator-runbook.md`** so prerequisite 2 reads as satisfied
   and the blocked attempt reads as history. Small, deliberate, and it needs the
   pinned test wording moved with it — a separate task, not a drive-by edit.
3. **Close finding 5** — audit `GracefulGutAI-LambdaExecutionRole`'s attached
   policies. It has been carried since Phase 1D purely for want of credentials,
   and the credentials are demonstrably available now.
4. **Then, and only when F1–F4 are decided, execute the CREATE change set** for
   the `dev` stage with the education route off. That is the first step that
   actually builds infrastructure, and it is reversible via the runbook's
   rollback.
5. **Do not treat that stack as a public launch.** The route stays off. L1, L2,
   the `X-GG-Key` replacement, and boundary enforcement in the request path are
   all still required by the `CLAUDE.md` release gate, and none of them moved
   today.

## Push — 2026-07-29 (later)

Report-only change, committed as a single report commit and pushed to
`origin/phase1f-api-gateway-foundation`. **Nothing was merged to `main`.**
Nothing was deployed. This session made no AWS API call, no IAM change, and no
Secrets Manager access.

---
---

# Update — 2026-07-29 (final): documentation finalised, owner decisions F1–F4 approved

**Outcome:** `SUCCESS` — documentation, decision record, and tests.
**Branch:** `phase1f-api-gateway-foundation`.

Two things closed in this session. The runbook still described the API Gateway
CloudWatch prerequisite as unsatisfied and the administrator dry run as only
blocked — stale since the successful run earlier the same day. And **F1 through
F4 were approved by the owner**, so they are now recorded as decisions rather
than as questions.

Repository work only. **No AWS API call of any kind was made** — not
`sts get-caller-identity`, not a `describe`, not a `get`. No deployment, no IAM
change, no Secrets Manager access, no merge to `main`.

## The approved owner decisions, as approved

Recorded verbatim in `infrastructure/phase1f/administrator-runbook.md` section
0b, which is the document an administrator actually reads before deploying.

### F1 — WAF sampled requests

> **Approved for private dev and count-mode validation using synthetic traffic.
> Re-evaluate before accepting real public health questions.**

This is **narrower than the recommendation** that was put forward, and the
narrowing is the substance. The Phase 1F recommendation was "yes, keep them";
what was approved is bounded by traffic type. The ~3 hours of unredactable IP
retention now applies to requests the administrator generates, not to a member of
the public describing a symptom — which is what made the trade-off cheap enough to
accept. The approval does not carry forward: it expires when real questions
arrive, and condition 9 of runbook section 6 now enforces a fresh decision before
the education route accepts public traffic.

WAF **logging** remains **off** and unapproved. Unlike access logs it cannot omit
the client IP at all, so it was never part of this decision.

### F2 — rate limiting

| Control | Approved | Template parameter | Shipped default |
| --- | --- | --- | --- |
| Education route throttle, steady | **1 request per second** | `EducationRouteRateLimit` | `1` ✓ |
| Education route throttle, burst | **2** | `EducationRouteBurstLimit` | `2` ✓ |
| WAF rate-based rule, education route | **100** / 5 min, as a broader backstop | `WafEducationRouteRateLimit` | `100` ✓ |
| WAF rate-rule action while the route is off | **`Count` acceptable** | `WafRateRuleAction` | `Count` ✓ |

**`WafRateRuleAction` must be `Block` before public education traffic is
enabled.** `Count` is licensed only while `EnableEducationRoute=false`, and that
is a release condition rather than a preference: a rate rule in `Count` protects
nothing, and the education route is the only one that costs model spend.

Per-method API Gateway throttling at 1 rps / burst 2 is the **primary** control;
the WAF rule at 100 is a **backstop**, and 100 is the AWS floor rather than a
chosen number. This supersedes the Phase 1E proposal of 40 and 60 requests per
five minutes, which AWS will not accept.

### F3 — names for the first deployment

| Item | Approved |
| --- | --- |
| `StageName` | **`dev`** |
| Stack name | **`graceful-gut-ai-dev-infrastructure`** |

### F4 — who executes change sets

**AJ is the named administrator** responsible for reviewing and executing
infrastructure change sets, from the Windows administrator session. Not this
host and not any Claude session: `GracefulGutAI-ClaudeDevRole` holds none of the
required actions, by design.

## Three of the four ratify what the repository already shipped

Worth stating plainly, because it changes what remains to be done: **F2 and F3
approved values that were already the defaults in the tracked template and
script.** F4 confirms the split the runbook was already written around.

| Decision | Required a change? |
| --- | --- |
| F1 | **No code change.** It scopes an operational practice and adds release condition 9 |
| F2 | **No template change** — `EducationRouteRateLimit=1`, `EducationRouteBurstLimit=2`, `WafEducationRouteRateLimit=100`, `WafRateRuleAction=Count` were already the defaults |
| F3 | **No script change** — `admin-dry-run.ps1` already defaults `StackName` to the approved name, and the dry run ran with `StageName=dev` |
| F4 | **No change** — the runbook was already written for a named administrator |

So no infrastructure artefact was modified to satisfy these decisions. That is a
good outcome rather than a suspicious one — the dry run had already executed with
these exact values, so approving them ratifies a configuration that has been
validated by CloudFormation rather than one that has only been argued for.

The corresponding risk is now **drift**: a default could move and silently
falsify the decision record. Four tests pin the approved values against the
template and script, so a drifting default fails the suite instead of quietly
contradicting this report.

## What was corrected in the documentation

### `infrastructure/phase1f/administrator-runbook.md`

| Change | Why |
| --- | --- |
| New **current-status** section: the dry run `COMPLETED SUCCESSFULLY` on 2026-07-29, with the eleven `Add` actions, the three asserted parameters, the unexecuted and removed change set, the removed `REVIEW_IN_PROGRESS` record, and no stack remaining | The document opened by declaring the dry run incomplete. That was the first thing an administrator read, and it was wrong |
| The current status is placed **before** the blocked attempt | A reader who stops after the first status heading must land on the current one. A test asserts the ordering |
| Prerequisite 2 recorded as **satisfied 2026-07-29**, with the role name, its single trust principal, its single attached managed policy, and the verified `us-east-2` account value | These are the facts an administrator would otherwise re-derive from the account, and an auditor would ask for |
| The **IAM propagation retries** recorded explicitly | The most misleading failure in the procedure. A correctly created role's first account-level `PATCH` can fail on propagation, and the natural conclusion — a bad trust policy — is wrong. A hand-run version would stop there |
| Prerequisite check kept **mandatory before every create and every update** | Satisfied is not retired. It is a region-wide singleton living outside this stack, anything in the account can clear or repoint it, and the failure mode is silent: the stage is configured for logging and never writes any |
| The blocked first attempt preserved, marked **superseded history** | It is the reason the scripted workflow exists. Deleting it would delete the rationale |
| Two now-false sentences inside that history corrected in place, not removed | "The template has still never been checked" and prerequisite 2 "was not satisfied" both became false. Each now carries a **Resolved 2026-07-29** marker beside the original claim |
| New **section 0b** recording F1–F4, and a closing note that they decide nothing about launch | The decisions belong where the change set is reviewed, not only in an audit report |
| Section 6 release conditions extended to **ten**, adding the F1 sampling re-evaluation and explicit public launch approval | Approving four infrastructure decisions is the most likely thing to be misread as approval to launch |

### `docs/architecture/phase1e-api-gateway-adr.md`

| Change | Why |
| --- | --- |
| The chat-route rate-limit rows of §3 marked **superseded by F2**, struck through rather than deleted, with the approved arrangement stated beside them | The ADR proposed 40 and 60 per five minutes. AWS will not accept a rate-based limit below 100, so the rows cannot stand — but deleting them hides the correction |
| §7's sampling recommendation annotated with F1's scope | That is where the sampling default lives |
| New **Phase 1F owner decisions** block in §15, plus F1 and F2 recorded against open decisions 4 and 2 | Those two rows were the open questions F1 and F2 partly answer. Leaving them unmarked would leave the ADR contradicting the runbook |
| An explicit statement that **none of the four is a launch approval** | Same reason as the runbook change |

Neither `template.yaml` nor either PowerShell script was modified. No
application code was modified: `backend/app/` is untouched and `CodeSha256` is
unaffected.

## Two pinned test assertions were changed deliberately

Both tests were correct when written and became wrong when the dry run succeeded.
They were changed rather than worked around, and the reason is recorded in each
docstring — a test that pins a sentence the documentation must no longer contain
would force the documentation to lie.

| Test | Assertion | Why it had to change |
| --- | --- | --- |
| `test_the_runbook_records_the_blocked_first_attempt` | `"no change set has ever existed"` | **Stopped being true.** The corrected dry run created a change set, reviewed it, and removed it. The load-bearing claim — `no infrastructure has been created` — is still asserted, because it is still true |
| `test_the_runbook_does_not_claim_the_dry_run_passed` → `test_the_runbook_does_not_overclaim_what_the_dry_run_established` | Forbade `"dry run succeeded"`; required `"that check has not been performed"` | **Inverted, not deleted.** The risk it guarded — prose read as evidence of validation that never happened — is gone, because the validation happened. The live risk is the opposite: a validated template read as a *deployed* one. The test now requires the success to be recorded and forbids nine specific overclaims, including `the stack exists`, `infrastructure has been deployed`, and `launch approved` |

Nothing else in the existing suite needed changing. The other 333 tests passed
untouched, including every guard over the two PowerShell scripts.

## Tests added

66 new guards in `backend/tests/test_phase1f_owner_decisions.py`, covering
exactly the seven things this task was asked to lock in:

| Area | Guards |
| --- | --- |
| Prerequisite recorded as satisfied | The 2026-07-29 date, the role name, its single trust principal, its single managed policy, the verified account value, that plan mode changed nothing, and the IAM propagation retries |
| Prerequisite still verified before deployment | "before every create and before every update", "That is not a reason to stop checking it", the `get-account` command still present, and the dry-run script still enforcing it — documentation is not enforcement |
| Blocked attempt present as history | The heading, the superseded marker, the rationale for keeping it, and the two failure modes it teaches |
| Successful attempt is the current status | The status heading, `COMPLETED SUCCESSFULLY on 2026-07-29`, each dry-run outcome, the three parameter values, and **ordering** — current status must precede the superseded history |
| F1–F4 recorded exactly | A section per decision; F1's synthetic-traffic scope and re-evaluation clause; F2's 1 rps, burst, 100 backstop, and conditional `Count`; F3's stage and stack name; F4 naming AJ — plus a guard that all four reach the runbook, the ADR, **and** this report |
| `Block` required before public traffic | The requirement sentence, the narrow `Count` licence and its boundary, the template's `Count` default, and every release condition in section 6 surviving — L1, L2, `X-GG-Key`, boundary enforcement, `Block`, and launch approval |
| Redaction | No account ID, account-bearing ARN, API ID, production origin, or credential marker in any of the five tracked files, and no value beside a secret env-var name |
| Drift | F2's four approved values pinned against `template.yaml`; F3's stack name pinned against `admin-dry-run.ps1` |

Five of the new tests failed on first run. Three were my own defects and were
fixed rather than relaxed:

| Failure | Cause | Fix |
| --- | --- | --- |
| Two phrase assertions against the ADR and runbook | `normalise` collapsed whitespace but left Markdown **blockquote markers**, so a `> ` from each wrapped line survived into the middle of the flattened phrase. Phrases that read correctly in the document could not match | Strip blockquote markers before collapsing whitespace |
| One assertion compared a capitalised needle against a lowercased haystack | Straightforward test bug | Lowercase the needle |
| API-ID detector flagged `template.yaml` and this report | The pattern matched any **ten-letter English word** after the phrase "API ID" — `substitute` and `production` both qualify | Require the candidate to carry both a digit and a letter, with the heuristic's limits documented and the two false positives pinned as self-tests |
| Production-origin detector flagged `template.yaml` | It read the CloudFormation `Sub` expression `https://${RestApi}.execute-api.${AWS::Region}...` as a hostname | Allow `${` interpolation, as with the `<placeholder>` convention |

The detector self-test now proves each pattern catches a planted account ID, ARN,
and API ID, **and** that it does not catch the two prose phrases that defeated
it. A scanner that silently matches nothing protects nothing; a scanner that
matches ordinary prose gets switched off, which is the same failure by a
different route.

## Verification results — 2026-07-29 (final)

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 401 passed, 0 failed, 0 skipped (335 before this session, 66 added) |
| `backend/tests/test_phase1f_owner_decisions.py` alone | **PASS** — 66 passed |
| `.venv/bin/ruff check backend/` | **PASS** — all checks passed |
| `.venv/bin/ruff format backend/` | 1 file reformatted |
| `.venv/bin/ruff format --check backend/` | **PASS** — 17 files already formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| AWS calls made by this session | **Zero** |
| Deployment | **Not performed** |

Python 3.13 coverage is CI's, not the local venv's, as `CLAUDE.md` records.

## Files — 2026-07-29 (final)

### Added

| File | Contents |
| --- | --- |
| `backend/tests/test_phase1f_owner_decisions.py` | 66 guards over the satisfied prerequisite, the preserved history, F1–F4, the `Block` release condition, and redaction |

### Modified

| File | Change |
| --- | --- |
| `infrastructure/phase1f/administrator-runbook.md` | Current-status section, satisfied prerequisite with the retry note, preserved and marked history, section 0b recording F1–F4, ten release conditions |
| `docs/architecture/phase1e-api-gateway-adr.md` | F2 supersedes the chat-route rate limits; F1 annotates the sampling default; F1–F4 recorded in §15 against decisions 2 and 4 |
| `backend/tests/test_phase1f_admin_workflow.py` | Two pinned assertions changed deliberately, with the reason in each docstring |
| `docs/audits/phase1f-api-gateway-foundation-2026-07-28.md` | This update, the header, and forward pointers on the two superseded decision tables |

### Deleted

None.

## AWS resources created, read, modified, or deleted — 2026-07-29 (final)

**None. Zero AWS API calls were made in this session.**

The three AWS changes recorded in this report remain the administrator's, from
the earlier logging prerequisite: one IAM role created, one approved AWS-managed
policy attached, and the regional API Gateway account `cloudwatchRoleArn`
modified. Nothing in this session added to that list, and the CloudFormation dry
run itself still leaves no stack and no template resource.

## Security and privacy checks — 2026-07-29 (final)

| Check | Result |
| --- | --- |
| No credential, token, or secret value in any changed file | **PASS** — enforced by test across five tracked files |
| No account ID or account-bearing ARN | **PASS** — enforced by test. One IAM role **name** and one AWS-managed policy **name** appear; neither carries an account field |
| No API ID | **PASS** — enforced by test, with the detector's heuristic documented |
| No production origin | **PASS** — enforced by test; `ProductionOrigin` remains a runtime parameter with no default, and the value the administrator supplied is not reproduced anywhere |
| No live Function URL or private URL | **PASS** |
| Stack name committed | **Deliberate.** F3 approved `graceful-gut-ai-dev-infrastructure`; a stack name is an identifier, not a credential, and the repository already records the function name |
| No PHI, health text, or personal identifying information | **PASS** |
| Secrets Manager accessed | **No** |
| IAM modified | **No** |
| Public free-text input still disabled | **PASS** — `EnableEducationRoute` default `false`, unchanged, and now guarded by a test that the release conditions survive |
| Merged to `main` | **No** |

## Findings and blockers — 2026-07-29 (final)

Approving F1–F4 resolved **no** blocker. Nothing here is newly closed.

| # | Item | Status |
| --- | --- | --- |
| **L1** | Legal and compliance determination | **OPEN — launch-blocking** |
| **L2** | Model-provider data-flow determination | **OPEN — launch-blocking** |
| **3** | Browser authentication / the `X-GG-Key` replacement | **OPEN — launch-blocking.** Still one static shared secret, still listed in the application's CORS allowed headers, still safe only while every configured origin is loopback |
| **4** | Application boundary enforcement in the request path | **OPEN — launch-blocking.** Still enforced in prompt text and documentation, not on every response |
| **5** | Public production launch approval | **OPEN — not given.** The `CLAUDE.md` release gate is unsatisfied: API Gateway is validated but **not applied**, and the raw Function URL is still the entry point |
| **6** | `GracefulGutAI-LambdaExecutionRole` audit | **OPEN.** Carried from Phase 1D and 1E. An earlier update recommended closing it while administrator credentials were available; that recommendation stands and the audit has **not** been done |
| **1** | WAF rate rules ship in `Count` | **Open, now bounded.** F2 licenses `Count` only while the route is off and requires `Block` before public traffic |
| **2** | WAF cannot express the ADR's chat-route rate limits | **Closed as a decision, permanent as a constraint.** F2 settles what to do about the 100-per-window floor; the floor itself is an AWS fact |
| **4′** | Redeployment is a manual step | **Open.** `AWS::ApiGateway::Deployment` is immutable; a stack update can succeed while callers still see old routes |
| **D** | PowerShell is not syntax-checked in CI | **Open.** Both scripts have now run successfully on Windows, which is stronger evidence than a linter but is still one run on one machine |

## Decisions required from AJ or Jenna — 2026-07-29 (final)

**F1–F4 are decided and no new infrastructure decision is raised.** What remains
is not a preference queue:

| Item | What closing it actually requires |
| --- | --- |
| **L1** legal and compliance | An external determination — not a selection between options. Launch-blocking |
| **L2** model-provider data flow | A review of what leaves the account, to whom, and under what terms, including whether a BAA is needed and available. Launch-blocking |
| `X-GG-Key` replacement | An authentication decision: API Gateway keys with usage plans, a signed short-lived token, or `AuthType: AWS_IAM` — then implemented |
| Boundary enforcement | Phase 2 application work, not started |
| The twelve Phase 1E open decisions | Unchanged, except 2 and 4, now partly answered by F2 and F1 |
| Public launch approval | Downstream of all of the above |

The `LambdaExecutionRole` audit needs administrator credentials rather than a
decision, and is the cheapest item on this list.

## Recommended next step

1. **Execute the CREATE change set** for the `dev` stage with the education route
   off, as `graceful-gut-ai-dev-infrastructure`, per F3 and F4. Everything
   required to do this safely is now decided, validated, and documented: the
   template passed CloudFormation, the eleven resources are pinned, the
   prerequisite is satisfied, and the runbook's review checklist and rollback are
   written. It is reversible.
2. **Re-verify prerequisite 2 first**, as section 0 now requires. It is one
   read-only call and the failure it prevents is silent.
3. **Audit `GracefulGutAI-LambdaExecutionRole`** while administrator credentials
   are to hand. Carried since Phase 1D for want of credentials only.
4. **Do not enable the education route.** Runbook section 6 lists ten prior
   conditions and F1–F4 satisfied none of them. L1, L2, the `X-GG-Key`
   replacement, boundary enforcement, the F1 sampling re-evaluation, and explicit
   launch approval are all still required.
5. Optionally add PowerShell parsing to CI (finding **D**) if the Windows helper
   set grows further.

## Push — 2026-07-29 (final)

Documentation and tests committed separately from this report, per the reporting
protocol. Both commits pushed to `origin/phase1f-api-gateway-foundation`.
**Nothing was merged to `main`.** Nothing was deployed. No AWS API call, no IAM
change, and no Secrets Manager access.
