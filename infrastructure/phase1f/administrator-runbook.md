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
stage and never written.

---

## 1. Create — never without a reviewed change set

The stack is never created with `deploy` or `create-stack`. A change set makes
the diff explicit before anything is applied, and that reviewable artefact is
the whole basis of the administrator/application split.

```bash
# 1a. Validate the template locally. Reads nothing, changes nothing.
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

Then, and only then:

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
| Change set looks wrong before execution | `aws cloudformation delete-change-set` — nothing was applied |
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
