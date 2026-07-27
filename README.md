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
| `production` | every AWS deployment | gate enforced, `/openapi.json` hidden, fails closed |
| `development` | local machines only | unauthenticated access allowed when no key is set, `/openapi.json` exposed |

Anything else — including a missing value, or the retired value `dev` — is
treated as `production`. Never set `APP_ENV=development` on a deployed
function; `scripts/deploy-lambda.sh` fails the deploy if it finds one.

### Authentication

All routes except `/health` require a shared secret header:

```bash
curl -H "X-GG-Key: $GG_API_KEY" "$FUNCTION_URL/version"
```

Set `GG_API_KEY` in your environment (see `.env.example`); generate a value
with `openssl rand -hex 32`. No real key belongs in Git, in a script, in a
test, or in documentation. Under `APP_ENV=development` with no key set, the
header is not required — local development only.

> **`X-GG-Key` is temporary internal-development protection.**
> It is one static shared secret with no rotation, no per-caller identity, and
> no rate limiting. **Do not embed it in the Squarespace browser client** or any
> other browser-side code — anything shipped to a browser is public, and the key
> would be visible in page source and network traces to every visitor. Use it
> for `curl` and internal development only.

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
bash scripts/build-lambda.sh    # -> .build/lambda.zip
bash scripts/deploy-lambda.sh   # build, upload, print CodeSha256, smoke test
```

Deployment is manual and requires AWS credentials for `us-east-2`. CI holds no
AWS credentials and never deploys. Record the printed `CodeSha256` with the
commit it was built from.

Set the function's environment before the first deploy — `APP_ENV` defaults to
`production` and fails closed, so a function with no `GG_API_KEY` returns 503
on every gated route:

```bash
aws lambda update-function-configuration \
  --function-name graceful-gut-ai-dev-api --region us-east-2 \
  --environment 'Variables={APP_ENV=production,GG_API_KEY=<your-key>}'
```

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
