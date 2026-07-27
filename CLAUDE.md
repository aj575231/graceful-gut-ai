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

- Header: `X-GG-Key`, compared against env var `GG_API_KEY` using
  `hmac.compare_digest`.
- `/health` is **always exempt** — the `docker-compose` healthcheck and any
  uptime probe depend on it. It exposes no sensitive data.
- **Fail closed:** when the gate is enforced and `GG_API_KEY` is unset, requests
  return **503**, never an open endpoint.

### `APP_ENV` — exactly two values

`APP_ENV` names a **security posture**, not a deployment tier. There are two
legal values and no others:

| Value | Where | Behaviour |
| --- | --- | --- |
| `production` | **every** AWS deployment, whatever stage it represents | gate enforced, `/openapi.json` hidden, fails closed |
| `development` | local machines only — never a deployed function | permits unauthenticated access when no key is set, exposes `/openapi.json` |

- `development` is the **only** value that relaxes security.
- Anything else — including a missing `APP_ENV` — is treated as `production`.
  That is a safety net, not a supported configuration.
- **`dev` is retired.** It was previously set on the deployed function. Do not
  reintroduce it; `backend/tests/test_security.py` asserts it fails closed, and
  `scripts/deploy-lambda.sh` fails the deploy if a function reports
  `APP_ENV=development`.

### `X-GG-Key` is temporary, internal-only

`X-GG-Key` is **temporary internal-development protection**, not a public
authentication mechanism. It is a single shared static secret with no rotation,
no per-caller identity, no revocation, and no rate limiting.

- **It must never be embedded in the Squarespace browser client**, or in any
  other browser-side or mobile code. Anything shipped to a browser is public:
  the key would be readable in page source, dev tools, and network traces, and
  would hand any visitor full access to every non-public route.
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
| `GG_API_KEY` | Lambda env vars / `.env` | shared secret for `X-GG-Key` |

No real `GG_API_KEY` value may appear in Git, shell scripts, test fixtures,
documentation, audit reports, or the deployment ZIP. Generate one yourself and
set it directly on the function:

```bash
# generate a key; do not paste the output into any file in this repository
openssl rand -hex 32

aws lambda update-function-configuration \
  --function-name graceful-gut-ai-dev-api --region us-east-2 \
  --environment 'Variables={APP_ENV=production,GG_API_KEY=<your-key>}'
```

Also keep account IDs, instance IDs, and live Function URLs out of the
repository — read them from AWS at the point of use.

Rotate the key by rerunning the command with a new value; there is no other
rotation mechanism, which is one reason `X-GG-Key` cannot serve a public
endpoint.

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
bash scripts/deploy-lambda.sh
```

This builds `.build/lambda.zip`, uploads it, prints the resulting
`CodeSha256`, and smoke-tests the live URL. Record the `CodeSha256` alongside
the commit so a deployment can always be tied back to source.

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
