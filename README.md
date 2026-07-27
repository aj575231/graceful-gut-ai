# Graceful Gut AI

A gut-health **education** service. The backend is a FastAPI application
deployed as an AWS Lambda ZIP package behind a Lambda Function URL.

This repository is at **Phase 1**: the foundation — health and version
endpoints, a reproducible build and deploy path, CI, and documented product
boundaries. The educational conversation endpoint (Phase 2) does not exist yet.

---

## What this product does and does not do

Graceful Gut AI provides **general gut-health education only**.

It does **not**:

- diagnose conditions or tell you what you have
- recommend medications, supplements, treatments, or dosages
- interpret your personal lab results, imaging, or test values
- create a clinician-patient relationship
- serve as primary, emergency, or urgent care

If you have urgent or severe symptoms, contact a qualified healthcare provider
or emergency services. Nothing here is a substitute for individual medical
advice.

Version 1 collects no identifying health information and stores no protected
health information. Clinical scheduling is a separate system from the
educational content, and clinical services are available only to eligible
Indiana patients.

The full, binding version of these constraints lives in [`CLAUDE.md`](CLAUDE.md).

---

## Endpoints

| Route | Auth | Description |
| --- | --- | --- |
| `GET /health` | none | liveness probe — status, service, version, UTC timestamp |
| `GET /version` | `X-GG-Key` | service name and version |
| `GET /` | `X-GG-Key` | service banner |

`/docs` and `/redoc` are disabled. `/openapi.json` is served only when
`APP_ENV=development`.

### Environments

`APP_ENV` selects a **security posture**, not a deployment tier. There are
exactly two values:

| Value | Where | Behaviour |
| --- | --- | --- |
| `production` | every AWS deployment | gate enforced, secret read from Secrets Manager, `/openapi.json` hidden, fails closed |
| `development` | local machines only | secret read from `GG_API_KEY`, unauthenticated access allowed when that is unset, `/openapi.json` exposed, never contacts AWS |

Anything else — including a missing value, or the retired value `dev` — is
treated as `production`. Never set `APP_ENV=development` on a deployed
function; `scripts/deploy-lambda.sh` fails the deploy if it finds one.

### Authentication

All routes except `/health` require a shared secret header:

```bash
curl -H "X-GG-Key: $GG_API_KEY" "$FUNCTION_URL/version"
```

Where that secret comes from depends on the posture, and the two sources never
mix:

| Posture | Source | Notes |
| --- | --- | --- |
| `development` | `GG_API_KEY` environment variable | local only; needs no AWS credentials |
| everything else | AWS Secrets Manager, named by `GG_API_SECRET_ID` | `GG_API_KEY` is ignored entirely |

The secret is a JSON document with exactly one field:

```json
{ "api_key": "<the shared secret>" }
```

`GG_API_SECRET_ID` holds the secret's **name or ARN** — an identifier, not a
credential, so it belongs in function configuration and deployment scripts. The
value it points at does not: no real key belongs in Git, in a script, in a test,
or in documentation. Generate one with `openssl rand -hex 32` and put it
straight into Secrets Manager.

Retrieval goes through AWS Lambda Powertools, which caches the secret for five
minutes per warm container, so a burst of requests costs one `GetSecretValue`
call. The execution role needs `secretsmanager:GetSecretValue` on that one
secret and nothing more —
see [`infrastructure/lambda-execution-secrets-policy.json`](infrastructure/lambda-execution-secrets-policy.json).

**Resolution fails closed.** If `GG_API_SECRET_ID` is unset, Secrets Manager is
unreachable, the payload is not JSON, or `api_key` is missing or empty, every
gated route returns `503` with an opaque body. The response never names the
secret identifier, the AWS error, or the cause, and the secret value is never
logged.

> **`X-GG-Key` is temporary internal-development protection.**
> It is one static shared secret with no per-caller identity, no revocation, and
> no rate limiting; rotation means writing a new value into Secrets Manager.
> **It must never be embedded in Squarespace JavaScript**, in any other
> browser-side or mobile code, in an iframe configuration, in a URL or query
> string, or in any client-visible file. Anything shipped to a browser is
> public: the key would be readable in page source, dev tools, and network
> traces, handing any visitor full access to every non-public route. Moving it
> into Secrets Manager keeps it out of the function's configuration — it does
> **not** make it safe to ship to a client. Use it for `curl` and internal
> development only.

### Before this endpoint can be public

Phase 2's conversation endpoint must not accept free-text input from the public
until all of the following are in place:

1. **API Gateway** in front of the Lambda, replacing the raw Function URL as
   the public entry point.
2. **Server-side abuse controls**: per-IP and per-key throttling and quotas,
   request-size and input-length caps, AWS WAF with a rate-based rule, and
   CloudWatch alarms on request volume, error rate, and spend — all enforced
   server-side, never in the browser.
3. **A real authentication mechanism** replacing `X-GG-Key` (API Gateway keys
   with usage plans, server-issued short-lived tokens, or `AuthType: AWS_IAM`).
4. **Product boundaries enforced in the request path**, not just in prompt text.

See CLAUDE.md for the binding version of this gate.

---

## Local development

Requires Python 3.12+ and the checked-out repository.

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
cp .env.example .env          # then fill in GG_API_KEY

# run the API
.venv/bin/uvicorn app.main:app --app-dir backend --reload

# tests and lint
.venv/bin/python -m pytest -v
.venv/bin/ruff check backend/
.venv/bin/ruff format --check backend/
```

### Docker (optional, local only)

```bash
docker compose up --build     # serves on http://localhost:8000
```

Docker is a **local convenience only**. The deployed function is a ZIP package,
not a container, and `infrastructure/ecr-lifecycle-policy.json` is reserved for
a possible future container migration — it is not in use.

### A note on Python versions

The local virtualenv runs Python 3.12; Lambda runs Python 3.13. That gap is
covered by CI, which runs the full suite on 3.13 for every push and pull
request. The build script cross-builds 3.13 wheels regardless of the local
interpreter, so you do not need 3.13 installed to produce a correct package.

---

## Build and deploy

```bash
bash scripts/build-lambda.sh              # -> .build/lambda.zip
bash scripts/deploy-lambda.sh             # build + validate config, NO upload
bash scripts/deploy-lambda.sh --deploy    # validate, upload, smoke test
```

**Deploying is opt-in.** With no arguments the script builds the package,
checks the function's live configuration, and stops without uploading anything.
Only `--deploy` uploads code. Deployment is manual and requires AWS credentials
for `us-east-2`; CI holds no AWS credentials and never deploys. Record the
printed `CodeSha256` with the commit it was built from.

Validation runs **before** any upload and fails the run if `APP_ENV` is not
`production`, if `GG_API_SECRET_ID` is unset, or if a stale `GG_API_KEY` is
still sitting in the function's environment. If a deploy's smoke test fails,
the script prints the previous `CodeSha256` and `RevisionId` along with the
rollback command.

The script never reads, prints, or logs the secret value, and it never calls
`secretsmanager:GetSecretValue`. Point the function at its secret — an
identifier only, no credential involved:

```bash
export GG_API_SECRET_ID=graceful-gut-ai/dev/api-key
bash scripts/deploy-lambda.sh --configure
```

That sets `APP_ENV=production` and `GG_API_SECRET_ID`, and clears any stale
`GG_API_KEY`. The secret **value** is written separately, by an administrator,
and never passes through this repository:

```bash
aws secretsmanager put-secret-value \
  --secret-id graceful-gut-ai/dev/api-key --region us-east-2 \
  --secret-string '{"api_key":"<your-key>"}'
```

Rotation is the same command with a new value — the running function picks it
up within the five-minute cache window, with no redeploy.

The account ID and the live Function URL are deliberately not checked in. Read
them from AWS when you need them:

```bash
aws sts get-caller-identity --query Account --output text
aws lambda get-function-url-config \
  --function-name graceful-gut-ai-dev-api --region us-east-2 \
  --query FunctionUrl --output text
```

---

## Repository layout

```
backend/app/          FastAPI application, config helpers, Lambda handler
backend/tests/        pytest suite
scripts/              build and deploy scripts
infrastructure/       IAM and resource policy documents (reference copies)
.github/workflows/    CI
CLAUDE.md             standing brief and binding product boundaries
```
