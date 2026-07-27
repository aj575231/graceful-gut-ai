# CLAUDE.md — Graceful Gut AI

Standing brief for any session working in this repository. Read this before
making changes.

---

## Boundaries

These are product constraints, not style preferences. They govern every
endpoint, prompt, and piece of copy in this repository. Do not weaken, reword,
or "helpfully" work around them without an explicit decision from the owner.

- **Educational only.** The product provides general gut-health education.
- **No diagnosis.** It must not diagnose, rule out, or suggest a specific
  condition for an individual.
- **No medication, supplement, treatment, or dosage recommendations.** Not for
  named products, not for generic categories, not "many people find X helpful."
- **No interpretation of personal lab results.** It must not read, score, or
  explain a user's own labs, imaging, or test values.
- **No clinician-patient relationship** is created by any interaction with the
  product.
- **Not primary, emergency, or urgent care.** Urgent or emergency symptoms must
  be directed to appropriate live care, never triaged by the product.
- **V1 collects no identifying health data.** No account-linked symptom
  histories, no uploads, no intake forms.
- **No PHI.** Nothing in this system is a HIPAA-covered data path. Do not add
  storage, logging, or third-party calls that would make it one.
- **No secrets in Git.** Credentials live in environment variables or AWS
  configuration only. See "Secrets" below.
- **Clinical scheduling stays separate** from the educational conversation.
  They are distinct systems and must not be merged into one flow.
- **Clinical services are limited to eligible Indiana patients.** Educational
  content is not geographically limited; clinical services are.

---

## Architecture

FastAPI application deployed as a **ZIP-package AWS Lambda** behind a Lambda
Function URL. `mangum` adapts ASGI to the Lambda event model.

```
backend/app/main.py            FastAPI app, CORS, security middleware, routes
backend/app/config.py          environment/security helpers (read per request)
backend/app/secrets.py         Secrets Manager retrieval of the shared secret
backend/app/lambda_handler.py  Mangum(app, lifespan="off") -> `handler`
backend/tests/                 pytest suite
scripts/build-lambda.sh        reproducible ZIP build into .build/
scripts/deploy-lambda.sh       build + update-function-code + smoke test
infrastructure/                IAM and resource policy documents (reference)
```

### AWS resources (dev)

Account IDs and the live Function URL are **not** recorded in this repository.
Read them from AWS when you need them:

```bash
aws sts get-caller-identity --query Account --output text
aws lambda get-function-url-config \
  --function-name graceful-gut-ai-dev-api --region us-east-2 \
  --query FunctionUrl --output text
```

| Item | Value |
| --- | --- |
| Account | not stored here — see command above |
| Region | `us-east-2` |
| Function | `graceful-gut-ai-dev-api` |
| Handler | `app.lambda_handler.handler` |
| Runtime | `python3.13`, `x86_64`, 512 MB, 15 s timeout |
| Package type | `Zip` |
| Reserved concurrency | 2 |
| Log retention | 14 days |
| Function URL | not stored here — see command above |
| `APP_ENV` | `production` (every AWS deployment) |
| `GG_API_SECRET_ID` | secret name or ARN — required on every deployment |
| Tags | `Project=GracefulGutAI`, `Environment=Development`, `Owner=AJMoses`, `Business=GracefulHealth` |

This host deploys using the instance role `GracefulGutAI-ClaudeDevRole`, whose
permissions are documented in `infrastructure/claude-dev-deployment-policy.json`.
The Lambda's own execution role is `GracefulGutAI-LambdaExecutionRole`; its
attached policies are **not readable** from the dev role and must be reviewed
separately with appropriate credentials.

---

## Security model

The Function URL is `AuthType: NONE`. Access is controlled in application code
by a **shared secret header**, not by IAM. This was a deliberate trade-off to
keep `curl` testing easy while the product has no user-facing endpoints.

- Header: `X-GG-Key`, compared with `hmac.compare_digest` — constant-time, so a
  wrong key cannot be recovered by timing the rejection.
- **Where the expected value comes from depends on the posture, and the two
  sources never mix.** `development` reads `GG_API_KEY` from the local
  environment. Every other posture ignores `GG_API_KEY` entirely and reads the
  secret from AWS Secrets Manager. There is no fallback in either direction.
- `/health` is **always exempt** — the `docker-compose` healthcheck and any
  uptime probe depend on it. It never resolves a secret, so it stays up when
  Secrets Manager does not.
- **Fail closed:** when the gate is enforced and no secret can be resolved,
  requests return **503**, never an open endpoint.

### The shared secret lives in Secrets Manager

Deployed postures read the key from Secrets Manager, so it never appears in the
function's environment, in `get-function-configuration` output, in a deployment
script, or in this repository.

| Item | Value |
| --- | --- |
| Identifier env var | `GG_API_SECRET_ID` — a secret **name or ARN** |
| Secret payload | JSON: `{"api_key": "<value>"}` |
| Retrieval | AWS Lambda Powertools parameters utility, `transform="json"` |
| Cache | 300 s per warm container, so a request burst costs one API call |
| Execution-role permission | `secretsmanager:GetSecretValue` on that one secret |

`GG_API_SECRET_ID` is an **identifier, not a credential**. It belongs in
function configuration, deployment scripts, and CI output. The value it points
at belongs in none of those.

Resolution fails closed on every fault — identifier unset, retrieval denied or
throttled, payload not JSON, `api_key` missing, empty, or not a string. Each
one produces the **same** opaque 503. The response body never carries the
secret identifier, the AWS error, a stack trace, or the value; the log records
a short reason and an exception *type* only, never the value. `backend/app/secrets.py`
holds this logic, and `backend/tests/test_secrets.py` covers every failure mode.

The Powertools provider is injectable (`app.secrets.set_provider`) so tests
exercise real caching and JSON-transform behaviour against a fake boto3 client.
`backend/tests/conftest.py` turns any attempt to construct a real AWS client
into a test failure: **the suite never reaches AWS and never handles a real
secret.**

### `APP_ENV` — exactly two values

`APP_ENV` names a **security posture**, not a deployment tier. There are two
legal values and no others:

| Value | Where | Behaviour |
| --- | --- | --- |
| `production` | **every** AWS deployment, whatever stage it represents | gate enforced, secret from Secrets Manager, `GG_API_KEY` ignored, `/openapi.json` hidden, fails closed |
| `development` | local machines only — never a deployed function | secret from `GG_API_KEY`, permits unauthenticated access when it is unset, exposes `/openapi.json`, never contacts AWS |

- `development` is the **only** value that relaxes security, and the only one
  that reads `GG_API_KEY`. Setting `GG_API_KEY` on a deployed function does not
  grant access — it just leaves a credential in plain text for no benefit.
  `scripts/deploy-lambda.sh` fails the run if it finds one.
- Anything else — including a missing `APP_ENV` — is treated as `production`.
  That is a safety net, not a supported configuration.
- **`dev` is retired.** It was previously set on the deployed function. Do not
  reintroduce it; `backend/tests/test_security.py` asserts it fails closed, and
  `scripts/deploy-lambda.sh` fails the deploy if a function reports
  `APP_ENV=development`.

### `X-GG-Key` is temporary, internal-only

`X-GG-Key` is **temporary internal-development protection**, not a public
authentication mechanism. It is a single shared static secret with no
per-caller identity, no revocation, and no rate limiting. Moving it into
Secrets Manager changed **where the value is stored** and nothing else: it is
still one static key shared by every caller.

- **It must never be embedded in any client-visible surface.** Not in
  Squarespace JavaScript, not in any other browser-side or mobile code, not in
  an iframe configuration, not in a URL or query string, not in a template, and
  not in any file served to a client. Anything shipped to a browser is public:
  the key would be readable in page source, dev tools, and network traces, and
  would hand any visitor full access to every non-public route.
- Storing it in Secrets Manager does **not** make it safe to ship to a client.
  A key read from Secrets Manager and then rendered into a page is exactly as
  exposed as one pasted there by hand.
- It is for `curl`, CI-adjacent checks, and internal development only.
- It is not a substitute for the public-endpoint controls below.

### Required milestone before any public endpoint

Before this service accepts **free-text input from the public** — that is,
before Phase 2's educational conversation endpoint is exposed to real users or
wired to the Squarespace site — the following must be in place. This is a
release gate, not a recommendation:

1. **API Gateway in front of the function.** Retire the raw Function URL as the
   public entry point. API Gateway is what makes the remaining controls
   possible; the Function URL offers none of them.
2. **Server-side abuse controls**, enforced at the edge and in application
   code, never in the browser:
   - throttling and quotas — per-IP and per-key rate limits, burst caps
   - request size limits and input length caps on free-text fields
   - AWS WAF with managed rule sets and a rate-based rule
   - abuse and cost monitoring: CloudWatch alarms on request volume, error
     rate, and model spend, with a hard concurrency ceiling
   - structured request logging that records **no** free-text content, in line
     with the no-PHI boundary above
3. **A real authentication decision** to replace `X-GG-Key`: API Gateway keys
   with usage plans, a signed short-lived token issued server-side, or
   `AuthType: AWS_IAM` — chosen and implemented, not deferred again.
4. **Boundary enforcement in the request path** — the product constraints at
   the top of this file enforced on every response, not only in prompt text.

Until all four are done, the endpoint stays internal and free-text input stays
unaccepted.

### Function URL administration is administrator-only

Everything that decides **who can reach this function** is off-limits to this
host. `GracefulGutAI-ClaudeDevRole` holds none of the four actions below and
gets `AccessDeniedException` on any of them:

| Change | Action withheld |
| --- | --- |
| Create a Function URL | `lambda:CreateFunctionUrlConfig` |
| Change the URL's `AuthType` or CORS configuration | `lambda:UpdateFunctionUrlConfig` |
| Add a resource-policy statement | `lambda:AddPermission` |
| Remove a resource-policy statement | `lambda:RemovePermission` |

All four require **administrator credentials** and are performed outside this
host. The reason is the security model: `AuthType: NONE` is what makes the
endpoint anonymous, CORS decides which origins a browser may call it from, and
the resource policy grants `Principal: '*'`. A host that can deploy code should
not also be able to change who is allowed to run it.

**Inspection is fully retained.** `lambda:GetFunctionUrlConfig` reads the URL,
`AuthType`, and CORS; `lambda:GetPolicy` reads the resource policy back. A
session can verify every one of these settings — it just cannot change them. A
session that finds the URL returning 403, or the `AuthType` or CORS wrong,
should report it and stop, not attempt a repair.

#### Resource policy — two statements, both required

The reference copy is `infrastructure/lambda-url-resource-policy.json`. The
live policy needs **both** of these; the URL returns a steady 403 on every
route if either is missing:

| Sid | Action | Condition |
| --- | --- | --- |
| `GracefulGutPublicInvokeUrl` | `lambda:InvokeFunctionUrl` | function URL auth type `NONE` |
| `GracefulGutPublicInvokeFunction` | `lambda:InvokeFunction` | `lambda:InvokedViaFunctionUrl` |

Both statements grant `Principal: '*'`, which is why applying, repairing, or
removing either one is an administrator action, per the rule above. The commands
an administrator runs:

```bash
aws lambda add-permission \
  --function-name graceful-gut-ai-dev-api --region us-east-2 \
  --statement-id GracefulGutPublicInvokeUrl \
  --action lambda:InvokeFunctionUrl --principal '*' \
  --function-url-auth-type NONE

aws lambda add-permission \
  --function-name graceful-gut-ai-dev-api --region us-east-2 \
  --statement-id GracefulGutPublicInvokeFunction \
  --action lambda:InvokeFunction --principal '*' \
  --invoked-via-function-url
```

The `InvokedViaFunctionUrl` condition **is** supported by the AWS CLI, via
`--invoked-via-function-url`. Earlier notes in this repository claimed it was
not and that CloudFormation, Terraform, or the console were required; that was
wrong. There is no reason to grant the unconditioned, broader
`lambda:InvokeFunction` permission — always pass the flag.

A previous audit also claimed the second statement was redundant and removed
it, taking the dev URL down. It appears healthy for ~10–20 seconds after
removal because of policy caching, which is what misled that audit. Verify with
`aws lambda get-policy`, not with a single immediate `curl`.

### Dev-role permissions — what this host may and may not do

`infrastructure/claude-dev-deployment-policy.json` is the reference copy of the
policy on `GracefulGutAI-ClaudeDevRole`. It is scoped to exactly this:

| Capability | Actions | Resource |
| --- | --- | --- |
| Identity check | `sts:GetCallerIdentity` | `*` |
| Inspect the function | `lambda:GetFunction`, `GetFunctionConfiguration`, `GetFunctionUrlConfig`, `GetPolicy`, `ListTags` | the dev function only |
| Update code and configuration | `lambda:UpdateFunctionCode`, `UpdateFunctionConfiguration`, `PutFunctionConcurrency`, `DeleteFunctionConcurrency` | the dev function only |
| Invoke | `lambda:InvokeFunction` | the dev function only |
| Read and configure logs | `logs:DescribeLogStreams`, `FilterLogEvents`, `GetLogEvents`, `PutRetentionPolicy`, `TagLogGroup`, `TagResource`, `ListTagsForResource` (plus `DescribeLogGroups` on `*`, which cannot be resource-scoped) | the function's log group only |
| Pass the execution role | `iam:GetRole`, `iam:PassRole` | `GracefulGutAI-LambdaExecutionRole` only |

`lambda:AddPermission`, `lambda:RemovePermission`,
`lambda:CreateFunctionUrlConfig`, and `lambda:UpdateFunctionUrlConfig` were all
**removed** — Function URL administration is administrator-only, as described
above. Do not add them back. The read-only counterparts,
`lambda:GetFunctionUrlConfig` and `lambda:GetPolicy`, are deliberately kept so
verification still works without admin credentials.

**This role holds no Secrets Manager permissions at all**, and must not be
given any. It can point the function at a secret — `GG_API_SECRET_ID` is an
identifier and goes in via `lambda:UpdateFunctionConfiguration` — but it cannot
read the value. Granting `secretsmanager:GetSecretValue` here would undo the
point of Phase 1D: the secret moved out of the function's environment precisely
so that a session which can deploy code cannot also read the live key. Reading
the secret is the **Lambda execution role's** job, not this host's.
`backend/tests/test_infrastructure_policy.py` fails if any `secretsmanager:`
action appears in the dev policy, wildcards included.

Note that `iam:PassRole` is scoped to a single role, so this host cannot attach
a more privileged execution role to the function. `GracefulGutAI-LambdaExecutionRole`'s
own attached policies are not readable from the dev role and remain unaudited —
review them separately with admin credentials.

#### The tracked policy file is pure IAM policy language

`claude-dev-deployment-policy.json` contains **only** `Version` and `Statement`.
IAM rejects unknown top-level properties, so a `_comment` block — which that file
used to carry — makes the document unapplyable as written. Explanatory text
belongs in `infrastructure/README.md`, which is also where the placeholder
convention is recorded: `<AWS_ACCOUNT_ID>` is substituted at apply time, and the
region is written literally as `us-east-2` because the deployment is pinned to
one region.

`backend/tests/test_infrastructure_policy.py` enforces this. It fails if the
top-level keys are anything but `Version` and `Statement`, if any of the four
administrator-only actions reappears (including via a `lambda:*` wildcard), or if
rendering the placeholders leaves anything unresolved.

---

## Secrets

Never commit secret values. `.env` is gitignored; `.env.example` documents the
variable **names** only.

| Variable | Where it lives | Purpose |
| --- | --- | --- |
| `APP_ENV` | Lambda env vars / `.env` / `docker-compose.yml` | selects the security posture |
| `GG_API_SECRET_ID` | Lambda env vars | **identifier** of the Secrets Manager secret — not a credential |
| `GG_API_KEY` | `.env` on a local machine only | shared secret for `X-GG-Key` under `APP_ENV=development`; ignored everywhere else |

No real shared-secret value may appear in Git, shell scripts, test fixtures,
documentation, audit reports, Lambda environment variables, or the deployment
ZIP. On a deployment it lives in Secrets Manager and nowhere else.

Point the function at its secret — no credential passes through this step, so
this host can do it:

```bash
export GG_API_SECRET_ID=graceful-gut-ai/dev/api-key
bash scripts/deploy-lambda.sh --configure
```

Write the value itself directly into the secret. Generate it yourself and do
not paste the output into any file in this repository:

```bash
openssl rand -hex 32

aws secretsmanager put-secret-value \
  --secret-id graceful-gut-ai/dev/api-key --region us-east-2 \
  --secret-string '{"api_key":"<your-key>"}'
```

Rotate by rerunning `put-secret-value` with a new value. The running function
picks it up within the 300-second cache window — no redeploy, no configuration
change. That is a real improvement on the previous scheme, but it is still one
static key shared by all callers, which is why `X-GG-Key` still cannot serve a
public endpoint.

Also keep account IDs, instance IDs, and live Function URLs out of the
repository — read them from AWS at the point of use.

### Administrator actions for the secret

Creating the secret and granting the execution role access are **outside this
host's permissions** — the dev role holds no `secretsmanager:*` and no IAM
write actions. An administrator runs these once:

```bash
# 1. Create the secret. Generate the key yourself; it is never stored here.
aws secretsmanager create-secret \
  --name graceful-gut-ai/dev/api-key --region us-east-2 \
  --description "X-GG-Key shared secret for graceful-gut-ai-dev-api" \
  --secret-string '{"api_key":"<your-key>"}'

# 2. Let the execution role read that one secret, and nothing else.
#    Substitute <AWS_ACCOUNT_ID> and <AWS_REGION> first.
aws iam put-role-policy \
  --role-name GracefulGutAI-LambdaExecutionRole \
  --policy-name GracefulGutAI-ReadApiKeySecret \
  --policy-document file://infrastructure/lambda-execution-secrets-policy.json
```

Until both are done, a deployed function returns 503 on every gated route —
correctly, since it cannot resolve a secret.

---

## Working on this repo

### Local development

```bash
.venv/bin/python -m pytest -v
.venv/bin/ruff check backend/
.venv/bin/ruff format --check backend/
.venv/bin/uvicorn app.main:app --app-dir backend --reload
```

### Python version — an intentional mismatch

The local `.venv` is **Python 3.12**; Lambda runs **Python 3.13**. No 3.13
interpreter (nor pyenv, uv, or Docker) is installed on this host, so 3.13 is
covered by **CI instead** — `.github/workflows/ci.yml` runs the suite on 3.13
for every push and PR. This mismatch is deliberate. Treat CI, not the local
venv, as the authority on whether the code runs on the deployed runtime.

`scripts/build-lambda.sh` cross-builds 3.13 `manylinux2014_x86_64` wheels using
the local 3.12 pip, so building a correct package does **not** require a local
3.13 interpreter.

### Deploying

```bash
bash scripts/deploy-lambda.sh              # build + validate only, NO upload
bash scripts/deploy-lambda.sh --configure  # set APP_ENV + GG_API_SECRET_ID
bash scripts/deploy-lambda.sh --deploy     # validate, upload, smoke test
```

**Uploading is opt-in.** The bare invocation builds the package, validates the
live configuration, and stops. Only `--deploy` sends code.

Validation runs before any upload and fails on: `APP_ENV` not `production`,
`GG_API_SECRET_ID` unset, or a stale `GG_API_KEY` still present in the
function's environment. A failed smoke test prints the pre-deploy `CodeSha256`
and `RevisionId` with the rollback command. Record the `CodeSha256` alongside
the commit so a deployment can always be tied back to source.

The script never reads, prints, or logs the secret value and never calls
`secretsmanager:GetSecretValue` — it accepts only the identifier. The smoke
test makes no keyed request; an unauthenticated `401` is the stronger signal
anyway, since it proves the function reached Secrets Manager and found a usable
`api_key`, where `503` means resolution failed.

Deploy is **manual on purpose** — CI holds no AWS credentials.

### Docker and ECR — not the deploy path

`Dockerfile` and `docker-compose.yml` exist for **local development only**.
Docker is not installed on this host and the deployed function is a ZIP
package, not a container. `infrastructure/ecr-lifecycle-policy.json` is
**reserved for a possible future container migration** and is not in use. Do
not assume ECR is live.

---

## Project phases

- **Phase 1 (current)** — foundation: health/version endpoints, reproducible
  build and deploy, CI, documented boundaries and access control.
- **Phase 2** — the educational conversation endpoint. Not started. Nothing in
  this repo may accept free-text user input until the four items in
  "Required milestone before any public endpoint" above are complete: API
  Gateway, server-side abuse controls, a real authentication decision
  replacing `X-GG-Key`, and boundary enforcement in the request path.
