# Administrator runbook — Phase 1F infrastructure stack

Every procedure below is an **administrator** action. None of them was executed
by the session that wrote this file, and none of them may be executed by the
Claude dev host: `GracefulGutAI-ClaudeDevRole` holds no `wafv2:` actions, no
API Gateway create or delete, no IAM write, no `cloudformation:` on this stack,
and no Function URL administration. A session that finds a setting wrong should
**report it and stop**, not attempt a repair.

Placeholders are filled in at the point of use and never committed:
`<AWS_ACCOUNT_ID>`, `<STACK_NAME>`, `<API_ID>`, `<PARAMETERS_FILE>`,
`<SQUARESPACE_PRODUCTION_ORIGIN>`.

Region is `us-east-2` throughout.

---

## The first administrator attempt was BLOCKED

**Status of the Phase 1F dry run: not completed. No CloudFormation stack and no
change set has ever existed for this template, and no infrastructure has been
created.**

The first attempt, on Windows, ran the commands in this file by hand and failed
in four steps that are worth reading before the second attempt, because three
of them are properties of the procedure rather than of the account:

1. `aws apigateway get-account` returned no `cloudwatchRoleArn` — prerequisite 2
   below was not satisfied. The check itself worked and raised an error.
2. **The remaining commands were pasted and executed separately anyway.** A
   failed prerequisite in a pasted sequence stops nothing; the next command is
   already on the clipboard.
3. The parameter file was passed as `file:///C:/Users/...`. The AWS CLI rejects
   that as an invalid Windows path — see "Parameter files on Windows" below —
   so `create-change-set` never succeeded.
4. Because no change set and no stack were created, the later `describe` and
   `delete` calls failed for that reason and not for any reason to do with the
   template. The template has still never been checked against real
   CloudFormation.

The attempt nevertheless **wrote a review file recording PASS and printed
cleanup success messages**, for stages that had not run and objects that had
never existed. That review was invalid and has been deleted. Nothing in this
repository should be read as evidence that the template has been checked
against real CloudFormation — that check has not been performed.

The two scripts in the next section exist so that none of steps 2 through 4 can
happen again. **Use them instead of pasting the commands below.**

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

Confirm each before the first `create-change-set`. Two of them are
account-scoped and are the usual cause of a first-attempt failure.

| # | Prerequisite | Why |
| --- | --- | --- |
| 1 | The application Lambda exists and is healthy | This stack references it by ARN and never creates it |
| 2 | An account-level API Gateway CloudWatch role is configured for the region | Access logging and execution logging silently do nothing without it. It is a **region-wide singleton** and is deliberately not declared in the template — a stack delete would clear it for every API in the region |
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
It is the expected first-attempt failure, not a surprise, and
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
5. `WafRateRuleAction=Block`. A rate rule in `Count` protects nothing, and the
   education route is the only one that costs model spend.
6. Managed rule groups reviewed against a corpus of realistic gut-health
   phrasings, with specific rule IDs excluded — never a whole group disabled.
7. A monthly budget, from which throttles, token caps, and alarm thresholds are
   derived rather than guessed.
8. A new deployment created after the update, or the route exists in the
   template and not to callers.
