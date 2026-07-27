# Phase 1D — AWS Secrets Manager integration

**Date:** 2026-07-27
**Branch:** `phase1d-secrets-manager`
**Implementation commit:** `3c98b1c` — *Add Secrets Manager API key integration*
**Scope:** move the temporary internal-development `X-GG-Key` shared secret out
of the Lambda environment and into AWS Secrets Manager.

This report is redacted by construction: no account ID, instance ID, live
Function URL, credential, token, or secret value appears anywhere in it.

---

## Summary

Deployed postures now resolve the shared secret from Secrets Manager at request
time. `GG_API_KEY` survives only as a local-development convenience and is
ignored everywhere else. Every resolution failure fails closed to the existing
opaque 503.

Nothing was deployed. No AWS resource was created, modified, or read.

---

## Files changed

### Added

| File | Purpose |
| --- | --- |
| `backend/app/secrets.py` | Secrets Manager retrieval, JSON validation, fail-closed error type, injectable provider |
| `backend/tests/test_secrets.py` | 30 tests covering posture, retrieval, caching, every failure mode, and leak paths |
| `infrastructure/lambda-execution-secrets-policy.json` | Execution-role reference policy — `GetSecretValue` on one secret |

### Modified

| File | Change |
| --- | --- |
| `backend/app/config.py` | `resolve_api_key()` dispatches on posture; `api_key()` documented as development-only |
| `backend/app/main.py` | Middleware resolves through `resolve_api_key()`, maps `SecretUnavailableError` to the existing 503, logs a sanitised reason |
| `backend/tests/conftest.py` | Blocks real AWS client construction suite-wide; `install_secret` fixture builds the real provider on a fake client |
| `backend/tests/test_security.py` | Deployed-posture fixtures resolve via Secrets Manager rather than `GG_API_KEY` |
| `backend/tests/test_infrastructure_policy.py` | Dev role proven free of Secrets Manager access; new execution-role policy validated |
| `backend/requirements.txt` | `aws-lambda-powertools`, `boto3` |
| `backend/requirements-lambda.txt` | `aws-lambda-powertools` (boto3 comes from the runtime) |
| `scripts/deploy-lambda.sh` | Opt-in deploy, pre-upload validation, identifier-only, rollback details |
| `scripts/build-lambda.sh` | Package verification requires `app/secrets.py` and Powertools |
| `README.md`, `CLAUDE.md`, `.env.example`, `infrastructure/README.md`, `docker-compose.yml` | Documentation |

`backend/requirements-dev.txt` is unchanged — it includes `requirements.txt`,
so CI installs both new packages.

---

## Dependency version pinned

| Package | Version | Where | Notes |
| --- | --- | --- | --- |
| `aws-lambda-powertools` | `3.31.1` | `requirements.txt`, `requirements-lambda.txt` | pure-Python wheel, Python 3.13 compatible; cross-builds cleanly for `manylinux2014_x86_64` |
| `boto3` | `1.43.56` | `requirements.txt` only | deliberately **excluded** from the Lambda package — the Python 3.13 runtime provides it, and Powertools imports it from there |

Confirmed present in the built package: `aws_lambda_powertools/` is now a
build-time assertion in `scripts/build-lambda.sh`, so a package missing it fails
the build rather than failing closed silently at runtime.

---

## Configuration behavior

### New environment variable

`GG_API_SECRET_ID` — the secret's **name or ARN**. An identifier, not a
credential: safe in function configuration, deployment scripts, and CI output.

### Secret format

```json
{ "api_key": "<value>" }
```

### Posture matrix

| `APP_ENV` | Secret source | `GG_API_KEY` | `GG_API_SECRET_ID` | AWS credentials |
| --- | --- | --- | --- | --- |
| `development` | local environment | read | ignored | never required |
| `production` and every other value | Secrets Manager | **ignored** | **required** | required |

`development` is local-only and remains the sole value that relaxes security.
There is no fallback in either direction: a deployed posture that cannot reach
its secret does not fall back to the environment.

### Caching

Retrieval goes through the Powertools parameters utility with
`transform="json"` and `max_age=300`. A warm container serves a burst of
requests from cache at the cost of one `GetSecretValue` call.

### Fail-closed conditions

All of the following return the pre-existing 503 with body
`{"detail": "Service is not configured for authenticated access."}`:

- `GG_API_SECRET_ID` unset, empty, or whitespace
- `GetSecretValue` fails for any reason — access denied, throttling, network, missing secret
- payload is not valid JSON
- payload is valid JSON but not an object
- `api_key` missing, empty, whitespace, or not a string

### Non-disclosure

- The 503 body is byte-identical for every cause. A caller cannot distinguish
  "no identifier configured" from "access denied" from "malformed payload".
- The response never carries the secret identifier, the AWS error message, a
  stack trace, or the value.
- The log records a short reason and an exception **type** only — the original
  exception is suppressed with `raise ... from None` because botocore errors
  quote the secret ARN and transform errors can quote the payload.
- Tests assert the placeholder value and identifier are absent from response
  bodies and from captured logs at `DEBUG` level.

### Preserved behavior

- `/health` is still public, still returns 200, and resolves no secret — it
  stays up when Secrets Manager does not.
- Constant-time comparison (`hmac.compare_digest`) is unchanged.
- Unauthenticated requests still get 401 for both real and non-existent routes,
  so the gate leaks no route inventory.
- `/openapi.json`, `/docs`, `/redoc` exposure rules unchanged.
- CORS allow-list unchanged.

---

## IAM permission required

The **Lambda execution role** (`GracefulGutAI-LambdaExecutionRole`) needs
exactly one new action, in `infrastructure/lambda-execution-secrets-policy.json`:

| Action | Resource |
| --- | --- |
| `secretsmanager:GetSecretValue` | `arn:aws:secretsmanager:<AWS_REGION>:<AWS_ACCOUNT_ID>:secret:graceful-gut-ai/dev/api-key-*` |

Both placeholders are retained in Git; neither the account ID nor the region is
checked in. The trailing `-*` is required — Secrets Manager appends a random
six-character suffix to a secret's ARN, and a policy naming the bare secret
matches nothing.

**The Claude EC2 dev role was NOT granted Secrets Manager access.** It can point
the function at a secret (`GG_API_SECRET_ID` goes in via
`lambda:UpdateFunctionConfiguration`) but cannot read the value. That separation
is the point of the change: a host that can deploy code should not also be able
to read the live key. `infrastructure/claude-dev-deployment-policy.json` is
unchanged, and two new tests fail if any `secretsmanager:` action appears in it,
wildcards included.

---

## Test results

```
$ .venv/bin/python -m pytest -q
85 passed, 2 warnings in 0.83s

$ .venv/bin/ruff check backend/
All checks passed!

$ .venv/bin/ruff format --check backend/
11 files already formatted
```

The two warnings are pre-existing and unrelated (a Starlette `TestClient`
deprecation and a Mangum event-loop deprecation).

Suite grew from 45 tests to 85: `test_secrets.py` adds 30 and
`test_infrastructure_policy.py` goes from 13 to 23. `test_security.py` stays at
24 — its deployed-posture fixtures now resolve through Secrets Manager, but the
gate behaviour they assert is deliberately unchanged. Required coverage, all
passing:

| Requirement | Test |
| --- | --- |
| development reads `GG_API_KEY` without contacting Secrets Manager | `test_development_reads_the_environment_without_touching_secrets_manager` |
| production ignores `GG_API_KEY` | `test_production_ignores_gg_api_key`, `test_every_non_development_posture_uses_secrets_manager` |
| production requires `GG_API_SECRET_ID` | `test_production_requires_the_secret_identifier`, `test_blank_secret_identifier_is_treated_as_unset` |
| successful JSON-secret retrieval | `test_successful_json_retrieval` |
| missing `api_key` | `test_missing_api_key_field_fails_closed` |
| empty `api_key` | `test_empty_or_non_string_api_key_fails_closed` |
| malformed JSON | `test_malformed_json_fails_closed`, `test_json_scalar_payload_fails_closed` |
| Secrets Manager access failure | `test_secrets_manager_access_failure_fails_closed` |
| secret values absent from responses and logs | `test_failure_response_is_opaque_and_uniform`, `test_failure_log_carries_no_secret_or_identifier`, `test_successful_request_does_not_log_or_echo_the_secret` |
| retrieval is cached | `test_retrieval_is_cached_across_requests` |
| `/health` remains public | `test_health_stays_public_when_the_secret_is_unavailable` |
| protected routes remain fail closed | `test_protected_routes_fail_closed_when_retrieval_fails` |
| no real AWS calls occur | `no_real_aws_clients` (autouse, suite-wide) + `test_constructing_a_real_provider_is_blocked_in_tests` |
| Claude dev policy holds no secret-reading permission | `test_dev_role_cannot_read_the_shared_secret`, `test_no_secretsmanager_action_reaches_the_dev_role` |

**No test contacts AWS.** `backend/tests/conftest.py` patches
`boto3.session.Session.client` to raise for the whole suite, and one test
asserts that guard is live rather than assumed. Tests needing genuine Powertools
caching and transform behaviour construct the real provider on a fake boto3
client, which never goes through `Session.client`.

The caching assertion is behavioural rather than nominal: five successive
authenticated requests are made and the fake client is asserted to have been
called exactly once.

---

## Build hashes

`scripts/build-lambda.sh` run twice from a clean tree:

```
build 1: c2ddbfc9df2f3ad5b4d5f34721b73af431ba13b04151287d72a7268c6cc95e5e
build 2: c2ddbfc9df2f3ad5b4d5f34721b73af431ba13b04151287d72a7268c6cc95e5e
```

**Identical.** Reproducibility holds with the new dependency. Package: 610
entries, 3.7 MB (was 356 entries before Powertools). All entries forward-slash,
no `bin/`, no `.exe`.

`git diff --check` — clean. `git status --short` — no build artifacts staged or
tracked; `.build/` remains gitignored.

---

## Redaction check

Every change was scanned for real account IDs, instance IDs, full Function URLs,
credentials, secrets, tokens, PHI, and build artifacts. Findings: **none**.

- The only 12-digit sequences are the synthetic `000000000000` already used in
  test fixtures and the `<AWS_ACCOUNT_ID>` placeholder.
- No `i-*` instance ID, no `*.lambda-url.*.on.aws` host, no `AKIA`/`ASIA` key,
  no private-key block, no 32+ character hex string.
- Test values are fixed, obviously-fake placeholders:
  `placeholder-secret-value-not-real` and
  `graceful-gut-ai/dev/api-key-placeholder`.
- No PHI or medical conversation data was added. Phase 2 remains unstarted and
  the service still accepts no free-text input.

---

## Remaining administrator actions

None of these are possible from this host — it holds no `secretsmanager:*` and
no IAM write actions. All require administrator credentials, run elsewhere.

1. **Create the secret.**
   ```bash
   aws secretsmanager create-secret \
     --name graceful-gut-ai/dev/api-key --region us-east-2 \
     --description "X-GG-Key shared secret for graceful-gut-ai-dev-api" \
     --secret-string '{"api_key":"<generate-your-own>"}'
   ```
   Generate the value with `openssl rand -hex 32`. It must not be pasted into
   any file in this repository.

2. **Attach the execution-role policy**, after substituting `<AWS_REGION>` and
   `<AWS_ACCOUNT_ID>`.
   ```bash
   aws iam put-role-policy \
     --role-name GracefulGutAI-LambdaExecutionRole \
     --policy-name GracefulGutAI-ReadApiKeySecret \
     --policy-document file://infrastructure/lambda-execution-secrets-policy.json
   ```

3. **Audit the execution role's existing policies.** They are still not readable
   from the dev role and remain unaudited — carried over from the Phase 1
   remediation report, not introduced here.

4. **Rotate the current `GG_API_KEY` value.** It has been sitting in the
   function's environment in plain text, readable via the console and
   `get-function-configuration`. The value that goes into Secrets Manager should
   be a **new** one, not the existing key moved across.

---

## Remaining blockers before deployment

Deployment is blocked until, in order:

1. The secret exists and the execution role can read it (administrator actions
   1 and 2 above). Until then a deployed function returns 503 on every gated
   route — correctly, but the service is down.
2. `GG_API_SECRET_ID` and `APP_ENV=production` are set on the function:
   `export GG_API_SECRET_ID=... && bash scripts/deploy-lambda.sh --configure`.
   This also clears the stale `GG_API_KEY`. Within this host's permissions, but
   it modifies AWS, so it was **not** run.
3. `bash scripts/deploy-lambda.sh` (validation only) passes.
4. CI passes on Python 3.13 for this branch. The local venv is 3.12; CI remains
   the authority on the deployed runtime. Powertools 3.31.1 and boto3 1.43.56
   are both Python 3.13 compatible, but that is unverified on 3.13 locally.
5. `bash scripts/deploy-lambda.sh --deploy` is run deliberately.

Ordering matters: deploying the code before step 1 takes the dev URL down until
the secret exists.

Unrelated and unchanged: the Phase 2 public-endpoint gate (API Gateway,
server-side abuse controls, a real authentication decision replacing
`X-GG-Key`, and boundary enforcement in the request path) is untouched by this
work. **Moving the key into Secrets Manager does not partially satisfy item 3 of
that gate** — it is still one static shared key with no per-caller identity, no
revocation, and no rate limiting. Rotation improved: writing a new value takes
effect within the 300-second cache window with no redeploy.

`X-GG-Key` remains temporary internal-development protection. It must never be
embedded in Squarespace JavaScript, any other browser-side or mobile code, an
iframe configuration, a URL or query string, or any client-visible file. Reading
it from Secrets Manager and then rendering it into a page would be exactly as
exposed as pasting it there by hand.

---

## Confirmations

**No AWS resource was created, modified, or deleted.** No secret was created,
no policy attached, no function configuration changed, no code deployed. The
only AWS-adjacent commands run in this session were `bash -n` syntax checks and
`scripts/deploy-lambda.sh --help` / an invalid-argument run, both of which exit
before any `aws` invocation. No `aws` CLI command was executed at all.

**No secret value was created, retrieved, displayed, logged, or stored.** No
`openssl rand` was run, no `GetSecretValue` call was made, no real `api_key`
was handled. Every secret-shaped string in the diff is a fixed, obviously-fake
placeholder in a test file. No administrator credentials were requested or used.
