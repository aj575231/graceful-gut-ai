# Administrator runbook — Phase 1F infrastructure stack

Every procedure below is an **administrator** action. None of them was executed
by the session that wrote this file, and none of them may be executed by the
Claude dev host: `GracefulGutAI-ClaudeDevRole` holds no `wafv2:` actions, no
API Gateway create or delete, no IAM write, no `cloudformation:` on this stack,
and no Function URL administration. A session that finds a setting wrong should
**report it and stop**, not attempt a repair.

Placeholders are filled in at the point of use and never committed:
`<AWS_ACCOUNT_ID>`, `<API_ID>`, `<PARAMETERS_FILE>`,
`<SQUARESPACE_PRODUCTION_ORIGIN>`.

`<STACK_NAME>` is the one exception: owner decision **F3** approved
`graceful-gut-ai-dev-infrastructure`, and a stack name is an identifier rather
than a credential, so it is recorded in section 0b.

Region is `us-east-2` throughout.

---

## Current status — the corrected dry run SUCCEEDED

**Status of the Phase 1F dry run: COMPLETED SUCCESSFULLY on 2026-07-29**, driven
end to end through the two scripts in the next section rather than by hand.

| Item | Status as of 2026-07-29 |
| --- | --- |
| One-time API Gateway CloudWatch logging prerequisite (prerequisite 2) | **Satisfied** — see section 0 |
| `aws cloudformation validate-template` | **Passed** |
| CREATE change-set creation | **Passed** |
| Change-set contents | **Exactly eleven `Add` actions**, matching the reviewed set |
| `EnableEducationRoute` | `false` |
| `StageName` | `dev` |
| `WafRateRuleAction` | `Count` |
| Change set executed? | **No — never executed** |
| The change set afterwards | **Removed** |
| The empty `REVIEW_IN_PROGRESS` stack record | **Removed** |
| Stack remaining afterwards | **None** — no non-deleted stack remained |

**The template is now validated against real CloudFormation, and no
infrastructure has been created.** Both are true at once, and that is precisely
what a dry run is for: the eleven resources were proposed, reviewed, and
discarded. No API, no stage, no WAF Web ACL, no log group, and no Lambda
permission exists.

The procedures in sections 1 through 5 have still **never been executed**. What
succeeded on 2026-07-29 was the dry run, not a deployment.

---

## The first administrator attempt was BLOCKED — superseded history

> **Superseded on 2026-07-29 by the successful run recorded above.** This section
> is kept because it is the reason the scripted workflow exists, not because it
> describes the current state. Every blocker named in it has since been cleared.
> Do not read it as the status of anything.

The first attempt, on Windows, ran the commands in this file by hand and failed
in four steps that are worth reading before running anything here, because three
of them are properties of the procedure rather than of the account:

1. `aws apigateway get-account` returned no `cloudwatchRoleArn` — prerequisite 2
   below was not satisfied at that time. The check itself worked and raised an
   error. **Resolved 2026-07-29**; the prerequisite is now satisfied, and
   section 0 records how.
2. **The remaining commands were pasted and executed separately anyway.** A
   failed prerequisite in a pasted sequence stops nothing; the next command is
   already on the clipboard.
3. The parameter file was passed as `file:///C:/Users/...`. The AWS CLI rejects
   that as an invalid Windows path — see "Parameter files on Windows" below —
   so `create-change-set` never succeeded.
4. Because no change set and no stack were created, the later `describe` and
   `delete` calls failed for that reason and not for any reason to do with the
   template. As of that attempt, the template had still never been checked
   against real CloudFormation. **Resolved 2026-07-29** — it has been checked
   since, and it passed.

The attempt nevertheless **wrote a review file recording PASS and printed
cleanup success messages**, for stages that had not run and objects that had
never existed. That review was invalid and has been deleted. It is evidence of
nothing, and it must not be confused with the successful 2026-07-29 run: the
evidence that the template validates is that run, recorded above, and not the
deleted file.

The two scripts in the next section exist so that none of steps 2 through 4 can
happen again. **Use them instead of pasting the commands below.** They are what
made the 2026-07-29 run succeed.

---

## Preferred Windows workflow — use the scripts

The commands in sections 1 through 5 remain the reference for what is being
done and why. On Windows, run them through these two scripts instead of by
hand. Both are PowerShell 5.1 and 7 compatible.

| Script | Purpose |
| --- | --- |
| `scripts/setup-apigw-cloudwatch-role.ps1` | One-time prerequisite: the account-level API Gateway CloudWatch role. Plans by default; changes nothing without `-Apply` |
| `scripts/admin-dry-run.ps1` | The full dry run: prerequisites, parameter file, `validate-template`, a CREATE change set, assertions, review, and cleanup of both objects it creates |

```powershell
# 1. Prerequisite. Plan first -- this reads and reports, and changes nothing.
.\scripts\setup-apigw-cloudwatch-role.ps1
.\scripts\setup-apigw-cloudwatch-role.ps1 -Apply

# 2. The dry run. Creates a change set, reviews it, deletes it.
#    It never executes a change set.
.\scripts\admin-dry-run.ps1 -ProductionOrigin https://<approved-origin>
```

What `admin-dry-run.ps1` enforces that a pasted sequence cannot:

- **It aborts the entire run on the first failure.** There is no next command
  for anyone to paste. A failed prerequisite ends the script.
- It checks **every** AWS call by exit code, not by whether output appeared.
- It never continues into change-set validation after `create-change-set`
  fails, and **writes no review file for a run that did not complete**.
- It never calls `execute-change-set` — the string does not appear in the file.
- `PASS` is produced in exactly one function, from a boolean that was actually
  computed. `REMOVED` is produced in exactly one function, and only when the
  object was observed to exist and was then confirmed gone.
- It deletes the completed parameter file in a `finally` block, so it goes even
  when the run fails.

### Do not continue by hand after a failure

If either script stops, **fix the reported cause and re-run the script**. Do
not paste the individual commands to get past the step that failed. That is
precisely what turned a correctly-detected missing prerequisite into a review
file claiming PASS. A failed step means the run has no result, not that the run
needs help continuing.

---

## 0. Prerequisites

**Confirm every one of these before every create and before every update — not
only before the first one.** Two are account-scoped and are the usual cause of a
first-attempt failure.

Prerequisite 2 is currently satisfied (2026-07-29). **That is not a reason to
stop checking it.** It is a region-wide singleton that lives outside this stack,
so anything else in the account can clear or repoint it, and the failure it
produces is silent: the stage is configured for logging and simply never writes
any. The check costs one read-only API call. Keep it.

| # | Prerequisite | Why |
| --- | --- | --- |
| 1 | The application Lambda exists and is healthy | This stack references it by ARN and never creates it |
| 2 | An account-level API Gateway CloudWatch role is configured for the region — **satisfied 2026-07-29, still verified every time** | Access logging and execution logging silently do nothing without it. It is a **region-wide singleton** and is deliberately not declared in the template — a stack delete would clear it for every API in the region |
| 3 | The Secrets Manager secret exists and the execution role can read it | Phase 1D. Unrelated to this stack, but a gated route returns `503` without it |
| 4 | A parameter file exists **outside** the repository | Copy `parameters.example.json`, fill it in, keep the filled copy out of Git |
| 5 | The exact production origin has been approved by the owner | It is a `ProductionOrigin` parameter value, never a committed string |

Prerequisite 2 in detail: setting it writes an account-wide value, so it is done
once, deliberately, and outside this stack.

```bash
aws apigateway get-account --region us-east-2 --query cloudwatchRoleArn --output text
```

An empty result means access logs and execution logs will be configured on the
stage and never written. **This is the check that failed on the first attempt.**
It was the expected first-attempt failure, not a surprise, and
`scripts/setup-apigw-cloudwatch-role.ps1` exists to satisfy it:

```powershell
.\scripts\setup-apigw-cloudwatch-role.ps1          # plan: reports, changes nothing
.\scripts\setup-apigw-cloudwatch-role.ps1 -Apply   # creates the role and sets the account value
```

It creates one role trusting only `apigateway.amazonaws.com`, attaches only
`arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs`,
sets the account value, and reads it back to verify. If a role of that name
already exists with a different trust policy or extra attached policies, it
**stops rather than overwriting it** — a role this procedure does not own may be
serving something else.

#### This prerequisite was satisfied on 2026-07-29

Run on Windows by the administrator: plan mode first, which reported what it
would do and **changed nothing**, then `-Apply`.

| Item | Result |
| --- | --- |
| IAM role | **`GracefulGutAI-APIGatewayCloudWatchRole`** created |
| Trust policy | Trusts **only** `apigateway.amazonaws.com` |
| Attached policies | **Only** `AmazonAPIGatewayPushToCloudWatchLogs`. No customer-managed policy, no inline policy |
| Account value | The `us-east-2` API Gateway `cloudwatchRoleArn` was **set and verified** by read-back |

**IAM propagation required retries, and the retries succeeded.** The account-level
`PATCH` initially failed because the newly created role had not yet propagated —
API Gateway checks that it can assume the role at the moment the account value is
written, and IAM is eventually consistent. The script retried and the final
verification passed.

Expect this on any fresh run, and do not misread it. A hand-run version of this
procedure would show one failure on a correctly created role, and the natural
conclusion — that the trust policy is wrong — is the wrong one. If it does not
clear on retry, check the trust policy before assuming propagation.

The role ARN is not recorded here. The role **name** is an identifier, not a
credential; the ARN carries the account ID and is never committed.

---

## 0a. Parameter files on Windows

This is a small syntax detail that cost the whole first attempt, so it gets its
own section.

The AWS CLI's `file://` prefix takes **a path, not a URI**. On Windows that
means two slashes and native separators:

| | |
| --- | --- |
| **Correct** | `--parameters file://C:\Users\you\AppData\Local\Temp\parameters.json` |
| **Rejected** | `--parameters file:///C:/Users/you/AppData/Local/Temp/parameters.json` |

The rejected form is what PowerShell produces if the path is converted to a URI
— `[System.Uri]::new($path).AbsoluteUri` and several path-formatting helpers all
yield `file:///C:/...` with three slashes and forward separators. The CLI
reports it as an invalid Windows path, and `create-change-set` never runs. Do
not convert the path; pass it as the operating system writes it.

Two further rules for the completed parameter file:

- **It never goes inside the repository.** It carries the account ID in the
  function ARN and the approved production origin. Write it under `%TEMP%` and
  delete it afterwards. `admin-dry-run.ps1` writes it to `%TEMP%`, refuses to
  run if `%TEMP%` resolves inside the checkout, and deletes it in a `finally`
  block.
- **UTF-8 without a byte order mark.** `Set-Content -Encoding UTF8` on Windows
  PowerShell 5.1 writes a BOM, and a BOM makes the CLI's JSON parser fail on the
  first character — which reads like a malformed parameter file rather than an
  encoding problem.

---

## 0b. Approved owner decisions — F1 to F4

Approved by the owner on 2026-07-29. These are the values a change set is
reviewed against; they are no longer open questions.

### F1 — WAF sampled requests

**Approved for private dev and count-mode validation using synthetic traffic.
Re-evaluate before accepting real public health questions.**

The approval is scoped to synthetic traffic, which is what makes it cheap: the
~3 hours of unredactable IP retention applies to test requests generated by the
administrator, not to a member of the public describing a symptom. That scoping
is the decision, and it expires the moment real questions arrive. **Sampling must
be re-evaluated before the education route accepts public traffic** — it does not
carry forward automatically.

This refines Phase 1E open decision 4. WAF **logging** remains **off** and is not
approved; unlike access logs it cannot omit the client IP at all.

### F2 — rate limiting

| Control | Approved value | Template parameter |
| --- | --- | --- |
| Education route throttle, steady | **1 request per second** | `EducationRouteRateLimit` |
| Education route throttle, burst | **2** | `EducationRouteBurstLimit` |
| WAF rate-based rule, education route | **100** per five minutes, as a broader backstop | `WafEducationRouteRateLimit` |
| WAF rate-rule action, while the route is off | **`Count` is acceptable** while `EnableEducationRoute=false` | `WafRateRuleAction` |

**`WafRateRuleAction` must be `Block` before public education traffic is
enabled.** A rate rule in `Count` protects nothing, and the education route is
the only one that costs model spend. This is a release condition, not a
preference — see section 6, condition 5.

Per-method API Gateway throttling is the **primary** control at 1 rps / burst 2;
the WAF rule at 100 is a **backstop**, and 100 is the AWS floor rather than a
chosen number. This supersedes the Phase 1E proposal of 40 and 60 requests per
five minutes for the chat route, which AWS will not accept as a rate-based limit.

### F3 — names for the first deployment

| Item | Approved value |
| --- | --- |
| `StageName` | **`dev`** |
| Stack name | **`graceful-gut-ai-dev-infrastructure`** |

`<STACK_NAME>` in the commands below resolves to the approved stack name. It is
an identifier, not a credential, so it is recorded here rather than left as a
fill-in-at-use placeholder. The remaining placeholders — `<AWS_ACCOUNT_ID>`,
`<API_ID>`, `<PARAMETERS_FILE>`, `<SQUARESPACE_PRODUCTION_ORIGIN>` — are still
never committed.

### F4 — who executes change sets

**AJ is the named administrator** responsible for reviewing and executing
infrastructure change sets, from the Windows administrator session.

Not this host, and not any Claude session: `GracefulGutAI-ClaudeDevRole` holds
none of the required actions, by design. Review and execution are one
accountable person's job.

### What F1 to F4 do not decide

They are infrastructure decisions. None of them is a launch approval, and each of
the following remains **open** and, where marked, launch-blocking:

| Item | Status |
| --- | --- |
| **L1** legal and compliance determination | **Open — launch-blocking** |
| **L2** model-provider data-flow determination | **Open — launch-blocking** |
| Browser authentication / the `X-GG-Key` replacement | **Open — launch-blocking** |
| Application boundary enforcement in the request path | **Open — launch-blocking** |
| Public production launch approval | **Open — not given** |
| `GracefulGutAI-LambdaExecutionRole` audit | **Open** — carried from Phase 1D |

---

## 1. Create — never without a reviewed change set

The stack is never created with `deploy` or `create-stack`. A change set makes
the diff explicit before anything is applied, and that reviewable artefact is
the whole basis of the administrator/application split.

```bash
# 1a. Validate the template. NOT a local parse -- this is an AWS API call.
#     It requires credentials, it is billable API activity, and it cannot be
#     run offline or without a resolved profile. It creates nothing.
aws cloudformation validate-template \
  --region us-east-2 \
  --template-body file://infrastructure/phase1f/template.yaml

# 1b. Create the change set. CREATE type, because the stack does not exist yet.
aws cloudformation create-change-set \
  --region us-east-2 \
  --stack-name <STACK_NAME> \
  --change-set-name phase1f-create \
  --change-set-type CREATE \
  --template-body file://infrastructure/phase1f/template.yaml \
  --parameters file://<PARAMETERS_FILE> \
  --tags Key=Project,Value=GracefulGutAI Key=Environment,Value=Development \
         Key=Owner,Value=AJMoses Key=Business,Value=GracefulHealth

# 1c. Read the change set. This is the review step; do not skip it.
aws cloudformation describe-change-set \
  --region us-east-2 \
  --stack-name <STACK_NAME> \
  --change-set-name phase1f-create \
  --query 'Changes[].ResourceChange.{Action:Action,Type:ResourceType,Id:LogicalResourceId,Replace:Replacement}' \
  --output table
```

**Review checklist — every line must hold before executing:**

- No `AWS::Lambda::Function` appears. The application is referenced, not managed.
- No `AWS::Lambda::Url` or function-URL resource appears.
- Every `AWS::Lambda::Permission` is `apigateway.amazonaws.com` with a
  `SourceArn` naming this API, this stage, and one method.
- `EnableEducationRoute` is `false` unless the release gate is genuinely
  satisfied — legal determination, model-provider determination, an
  authentication decision replacing `X-GG-Key`, and boundary enforcement in the
  request path.
- `ProductionOrigin` is an exact `https` origin. No wildcard, no path, no port.
- The Web ACL association targets the **stage**, not the API.
- No `AWS::WAFv2::LoggingConfiguration` appears.
- No `AWS::Budgets::Budget` appears.

### A CREATE change set leaves an empty stack behind

`--change-set-type CREATE` creates the stack record **before** the change set
exists, in status `REVIEW_IN_PROGRESS`, holding no resources. This has two
consequences that the first attempt would have run into next:

- **Deleting the change set is not enough.** `delete-change-set` removes the
  change set and leaves the empty `REVIEW_IN_PROGRESS` stack record holding the
  stack name. The next `create-change-set --change-set-type CREATE` with that
  name then fails, and the cause is not obvious.
- **The record can exist even when `create-change-set` failed.** The stack is
  created first, so a change set that fails to build still leaves the record.

A dry run that is not executed must therefore delete **both**:

```bash
# 1. The unexecuted change set.
aws cloudformation delete-change-set \
  --region us-east-2 \
  --stack-name <STACK_NAME> \
  --change-set-name phase1f-create

# 2. The empty stack record it left behind.
aws cloudformation delete-stack \
  --region us-east-2 --stack-name <STACK_NAME>

aws cloudformation wait stack-delete-complete \
  --region us-east-2 --stack-name <STACK_NAME>

# 3. Confirm absence by reading it back. Do not infer it from step 2 exiting 0.
aws cloudformation list-stacks \
  --region us-east-2 \
  --stack-status-filter CREATE_COMPLETE REVIEW_IN_PROGRESS CREATE_FAILED \
                        ROLLBACK_COMPLETE DELETE_FAILED \
  --query "StackSummaries[?StackName=='<STACK_NAME>'].StackStatus" --output text
```

An empty result from step 3 is the only evidence that cleanup worked. Deleting
something that was never there is not a success, and must not be reported as
one — `admin-dry-run.ps1` distinguishes `REMOVED` from `NOT PRESENT` for exactly
this reason.

Then, and only then — and **not** during a dry run:

```bash
aws cloudformation execute-change-set \
  --region us-east-2 \
  --stack-name <STACK_NAME> \
  --change-set-name phase1f-create

aws cloudformation wait stack-create-complete \
  --region us-east-2 --stack-name <STACK_NAME>
```

### After create

Record the outputs. `RestApiId` is what substitutes `<API_ID>` in
`infrastructure/phase1e/apigateway-invoke-lambda.json` and
`infrastructure/phase1e/deployment-automation-policy.json`.

```bash
aws cloudformation describe-stacks \
  --region us-east-2 --stack-name <STACK_NAME> \
  --query 'Stacks[0].Outputs' --output table
```

The API is created but **not announced and not linked from any site**. Nothing
points at it until the Function URL retirement sequence in the ADR says so.

---

## 2. Update — same discipline, plus one thing CloudFormation will not do

```bash
aws cloudformation create-change-set \
  --region us-east-2 \
  --stack-name <STACK_NAME> \
  --change-set-name phase1f-update-<short-description> \
  --template-body file://infrastructure/phase1f/template.yaml \
  --parameters file://<PARAMETERS_FILE>

aws cloudformation describe-change-set \
  --region us-east-2 --stack-name <STACK_NAME> \
  --change-set-name phase1f-update-<short-description> \
  --query 'Changes[].ResourceChange.{Action:Action,Type:ResourceType,Id:LogicalResourceId,Replace:Replacement}' \
  --output table
```

Run the same review checklist. Pay particular attention to any change showing
`Replace: True` on `RestApi` — that issues a new API ID and invalidates every
`SourceArn` and every reference to the old ID.

### A route change does not reach callers on its own

`AWS::ApiGateway::Deployment` is immutable. CloudFormation will not replace it
when a method, model, or validator changes, so **the stack can update
successfully while callers still see the previous route configuration**. This is
the most likely way to conclude a change is live when it is not.

After any change to a resource, method, model, validator, or integration —
including turning `EnableEducationRoute` on — create a deployment explicitly:

```bash
aws apigateway create-deployment \
  --region us-east-2 \
  --rest-api-id <API_ID> \
  --stage-name dev \
  --description "phase1f-update-<short-description>"
```

This is the one API Gateway write the restricted deployment role already holds
(`apigateway:POST` on `/restapis/<API_ID>/deployments`) — it ships a
configuration an administrator already approved, which is why it is delegated.

---

## 3. Verification — read-only, and available to any session

Every check here uses a read action the dev role retains. None of them changes
anything.

```bash
# The Web ACL is associated with the STAGE. An unassociated ACL inspects
# nothing while looking perfectly healthy in the console.
aws wafv2 get-web-acl-for-resource \
  --region us-east-2 \
  --resource-arn arn:aws:apigateway:us-east-2::/restapis/<API_ID>/stages/dev \
  --query 'WebACL.Name' --output text

# Every managed rule group is still in Count, and AnonymousIpList is not Block.
aws wafv2 get-web-acl \
  --region us-east-2 --scope REGIONAL \
  --name <WEB_ACL_NAME> --id <WEB_ACL_ID> \
  --query 'WebACL.Rules[].{Name:Name,Override:OverrideAction,Action:Action}' \
  --output table

# WAF logging is absent. An empty result is the expected, correct outcome.
aws wafv2 get-logging-configuration \
  --region us-east-2 \
  --resource-arn <WEB_ACL_ARN> 2>&1 | head -5

# The access log format carries no IP, no headers, no query string, no body.
aws apigateway get-stage \
  --region us-east-2 --rest-api-id <API_ID> --stage-name dev \
  --query 'accessLogSettings.format' --output text

# Data-trace logging is off on every method setting. Anything but `false` here
# means request and response bodies are being written to CloudWatch.
aws apigateway get-stage \
  --region us-east-2 --rest-api-id <API_ID> --stage-name dev \
  --query 'methodSettings.*.dataTraceEnabled' --output text

# The public surface is exactly what the template declares.
aws apigateway get-resources \
  --region us-east-2 --rest-api-id <API_ID> \
  --query 'items[].{Path:path,Methods:resourceMethods}' --output table

# The application function's reserved concurrency is untouched.
aws lambda get-function-concurrency \
  --region us-east-2 --function-name graceful-gut-ai-dev-api
```

Expected results: `/health` with `GET` and `OPTIONS`; no `/`, no `/version`,
no `/docs`, no `/redoc`, no `/openapi.json`, no `{proxy+}`, and no
`/v1/education/ask` while the route is disabled. Reserved concurrency `2`.

Live behaviour checks — `429` past the documented rate, CORS from an allowed
and a disallowed origin, preflight answered by the application rather than by
API Gateway returning `403` — belong to the verification stage of the ADR
migration sequence and require the stack to exist. They are not part of this
task.

---

## 4. Rollback

Ordered by how much they give back and how fast.

| Situation | Action |
| --- | --- |
| Change set looks wrong before execution | `delete-change-set`, then `delete-stack` for the empty `REVIEW_IN_PROGRESS` record — nothing was applied, but both objects must go |
| Update failed mid-flight | CloudFormation rolls back automatically; confirm with `describe-stack-events` and read the first `*_FAILED` reason, not the last |
| Update succeeded but behaves wrongly | Create a change set restoring the previous template revision from Git, review, execute, then **create a new deployment** — the rollback has the same immutability problem as the change |
| A WAF rule blocks legitimate traffic | Set the offending group's `OverrideAction` back to `Count`, or exclude the specific rule IDs. **Never disable a whole rule group** and never disassociate the Web ACL |
| Throttles too tight | Raise the throttle parameters and update. Values are parameters precisely so this needs no template edit |
| The API itself must go away | `delete-stack`. It removes the API, stage, Web ACL, association, log group, and the Lambda permissions. It does **not** touch the application function, its code, its configuration, or its reserved concurrency |

`delete-stack` is safe with respect to the application by construction — the
function is a parameter, not a resource. The access log group is deleted with
the stack; its contents carry no identifying information by design, so nothing
requiring retention is lost.

### Rollback that must not happen

Restoring access by re-opening the Function URL is a **separate** procedure with
its own rules: re-apply the two specific conditioned statements tracked in
`infrastructure/lambda-url-resource-policy.json`, both of them, never the
unconditioned broader `lambda:InvokeFunction`, and always with
`--invoked-via-function-url`. Verify with `aws lambda get-policy` first — policy
caching keeps the URL working for roughly 10–20 seconds after a change, and a
single immediate `curl` has already misled one audit in this repository into
taking the dev URL down.

---

## 5. Emergency kill switch

Fastest first. The first one is the primary switch and the only hard bound.

```bash
# 1. Reserved concurrency to 0. Immediate, total, one command, fully
#    reversible. The function returns errors rather than serving requests --
#    that is the intended behaviour of a kill switch, and it fails closed.
aws lambda put-function-concurrency \
  --region us-east-2 \
  --function-name graceful-gut-ai-dev-api \
  --reserved-concurrent-executions 0

# Restore. 2 is the current value and this stack does not change it.
aws lambda put-function-concurrency \
  --region us-east-2 \
  --function-name graceful-gut-ai-dev-api \
  --reserved-concurrent-executions 2
```

This lives with the **application** deployment path, not with the
administrator, and that is deliberate: a cost emergency must not wait for
someone to be found. `lambda:PutFunctionConcurrency` and
`lambda:DeleteFunctionConcurrency` on this one function are already held by the
dev role.

Slower alternatives, in order: add a `Block`-all WAF rule scoped to the chat
route so `/health` stays reachable; then disable or delete the stage, which is
slowest to restore.

Throttles and quotas are **not** a kill switch. API Gateway throttling and WAF
rate-based rules are best-effort, applied across a distributed system,
approximate at the boundary, and they do not guarantee a maximum bill. The only
hard bounds are reserved concurrency, the per-request token cap, and the
switches above.

---

## 6. Before the education route is ever enabled

`EnableEducationRoute=true` creates the route. It does not make launching it
acceptable. All of the following are prior conditions, and none is satisfied by
this stack:

1. **L1 — legal and compliance determination.** Launch-blocking.
2. **L2 — model-provider data-flow determination.** Launch-blocking.
3. **A real authentication decision** replacing `X-GG-Key`.
4. **Boundary enforcement in the request path** — educational only, no
   diagnosis, no prescribing, no lab interpretation, enforced in code on every
   response rather than in prompt text alone.
5. **`WafRateRuleAction=Block`.** A rate rule in `Count` protects nothing, and
   the education route is the only one that costs model spend. Owner decision
   **F2** permits `Count` only while `EnableEducationRoute=false`, and requires
   `Block` before public education traffic is enabled.
6. Managed rule groups reviewed against a corpus of realistic gut-health
   phrasings, with specific rule IDs excluded — never a whole group disabled.
7. A monthly budget, from which throttles, token caps, and alarm thresholds are
   derived rather than guessed.
8. A new deployment created after the update, or the route exists in the
   template and not to callers.
9. **WAF sampled requests re-evaluated.** Owner decision **F1** approved sampling
   for private dev and count-mode validation on **synthetic** traffic only, and
   requires a fresh decision before real public health questions are accepted.
10. **Public production launch approval, explicitly given.** It has not been.
    Approving F1 through F4 was an infrastructure decision and is not a launch
    approval.

**F1 through F4 do not shorten this list.** They settled how the stack is
configured; conditions 1, 2, 3, 4, 9, and 10 are all still open.
