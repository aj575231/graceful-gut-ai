# Phase 1D — live deployment to the dev Lambda

**Date:** 2026-07-27
**Branch:** `main`
**Host:** Linux EC2 checkout, assumed role `GracefulGutAI-ClaudeDevRole`
**Scope:** deploy the merged Phase 1D Secrets Manager integration to the dev
function, verify it, and correct a stale deployment-script expectation found
during verification.

This report is redacted by construction: no account ID, instance ID, full ARN,
live Function URL, secret identifier, token, credential, or secret value
appears anywhere in it.

---

## Summary

The Phase 1D application code is deployed and healthy. `/health` returns 200,
every gated route returns 401 to an unauthenticated caller, and no route
returns 503 — which confirms the function reached Secrets Manager and found a
usable `api_key`, since a resolution failure would fail closed to 503.

One defect was found, and it was in the deployment tooling rather than in the
application: `scripts/deploy-lambda.sh` asserted that an unkeyed
`GET /openapi.json` returns 404. That assertion is unsatisfiable against a
correctly gated deployment, so the smoke test failed on an otherwise healthy
deploy. It has been corrected and pinned by tests.

The correction touches no application code. The Lambda ZIP is byte-identical
before and after it, and `CodeSha256` is unchanged.

No key was retrieved, displayed, logged, or requested at any point. No keyed
request was made — that test is reserved for the administrator.

---

## Commits — three distinct things

| Role | Commit | Message |
| --- | --- | --- |
| Deployed application code | `77ef7e1beca540cf21b6f98eae019d7ec4d37b0b` | *Merge Phase 1D Secrets Manager integration* |
| Deployment-script correction | `af825992ec653adf564cb3b54fde9b424a5c37e8` | *Fix unauthenticated OpenAPI smoke-test expectation* |
| This report | the commit adding this file | *Document successful Phase 1D live deployment* |

**Only `77ef7e1` is running on the function.** The correction commit changes
`scripts/deploy-lambda.sh` and adds `backend/tests/test_deploy_script.py`;
neither is part of the deployment package, which contains `backend/app/` and
its dependencies only. The report commit changes documentation alone.

---

## Artifact — did the ZIP or CodeSha256 change?

**No.** Both are identical before and after the tooling correction.

| Measurement | Value |
| --- | --- |
| ZIP SHA-256 (before correction) | `4f6cd172d5b765c4fd2c8aa0c77a8ad5b7f7f3e9ff7ecd3ca76fb1d196d50582` |
| ZIP SHA-256 (after correction) | `4f6cd172d5b765c4fd2c8aa0c77a8ad5b7f7f3e9ff7ecd3ca76fb1d196d50582` |
| Deployed `CodeSha256` | `T2zRctW3ZcT9LIqgx3qK1bf38+n/fs08p2+x0ZbVBYI=` |
| `CodeSha256` before this deployment | `FedFPCaxMb0dIUUFEhqkkmgmpCUSRJvKchwausbg+w4=` |
| Package contents | 610 entries, all forward-slash, no `bin/` or `.exe` |

The ZIP was built five times across this task — three before the correction and
two after — and every build produced the same SHA-256. Reproducibility holds,
and the byte-identical hash is the evidence that the correction changed no
application behaviour.

`CodeSha256` did change once, from `FedFPCa…` to `T2zRctW3…`, when the Phase 1D
application code was first uploaded. That is the intended deployment. It did
not change again.

**Rollback anchor:** the function ran `CodeSha256`
`FedFPCaxMb0dIUUFEhqkkmgmpCUSRJvKchwausbg+w4=` (RevisionId
`edfe76c3-20d4-4083-8318-9c1b5c53b62e`) before this deployment.

---

## Pre-deployment gates

| Gate | Result |
| --- | --- |
| `pytest -q` (before correction) | **PASS** — 85 passed |
| `pytest -q` (after correction) | **PASS** — 92 passed (7 new) |
| `ruff check backend/` | **PASS** |
| `ruff format --check backend/` | **PASS** — 12 files formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| `bash -n scripts/deploy-lambda.sh` | **PASS** — syntax valid |
| Build reproducibility | **PASS** — identical SHA-256 across all builds |

### Live configuration

Verified by reading the function configuration. Values are withheld; only the
pass/fail outcome is recorded.

| Requirement | Result |
| --- | --- |
| `APP_ENV=production` | **PASS** |
| `GG_API_SECRET_ID` configured | **PASS** — identifier withheld |
| `GG_API_KEY` absent | **PASS** — no credential in the environment |
| Execution role unchanged | **PASS** — `GracefulGutAI-LambdaExecutionRole` |
| Caller identity | **PASS** — `GracefulGutAI-ClaudeDevRole` |
| Runtime / architecture / package | `python3.13`, `x86_64`, `Zip` |
| Handler | `app.lambda_handler.handler` |
| Memory / timeout | 512 MB / 15 s |

### Artifact integrity

The deployed `CodeSha256` was compared against a locally computed
base64 SHA-256 of the tested ZIP. **PASS** — the artifact running on the
function is the artifact that passed the gates.

---

## Endpoint verification

All requests unauthenticated. No keyed request was made.

| Route | Expected | Actual | Result |
| --- | --- | --- | --- |
| `/health` | 200 | 200 | **PASS** |
| `/version` (no key) | 401 | 401 | **PASS** |
| `/openapi.json` (no key) | 401 | 401 | **PASS** |
| `/` (no key) | 401 | 401 | **PASS** |
| `/docs` (no key) | 401 | 401 | **PASS** |
| `/redoc` (no key) | 401 | 401 | **PASS** |
| `/nope` (nonexistent) | 401 | 401 | **PASS** |
| Any route returning 503 | none | none | **PASS** |

`/health` returned a well-formed body reporting `status: healthy` and service
version `0.1.0`, confirming it stays available without resolving a secret.

The identical 401 on `/openapi.json`, `/docs`, `/redoc`, and a route that does
not exist is the gate behaving correctly: an anonymous caller cannot enumerate
the application surface.

The 401 on `/version` is the positive signal for Secrets Manager. A 503 would
mean resolution failed; 401 means the secret was fetched, parsed as JSON, and
found to carry a usable `api_key`.

---

## The tooling defect

### What failed

`scripts/deploy-lambda.sh` exited 1 on a healthy deployment:

```
FAIL: /openapi.json expected 404
```

### Why the expectation was wrong

The script holds no shared secret and must never fetch one, so every request
its smoke test makes is unauthenticated. The gate runs *before* route
resolution, so an anonymous caller receives 401 on every gated path regardless
of whether the route exists. The schema being hidden surfaces as 404 only for
an *authenticated* caller — which the script cannot test and must not attempt.

The 404 expectation could therefore only have passed if the gate leaked which
routes exist. It contradicted the application's own test suite, where
`test_security.py::test_gate_does_not_leak_which_routes_exist` has asserted 401
for an unkeyed `/openapi.json` all along.

### The correction

`scripts/deploy-lambda.sh` now expects **401** from the unkeyed
`/openapi.json` probe, with a comment recording why 404 is wrong. The probe's
output label was changed to `GET /openapi.json (no key)` so the report cannot
be misread as an authenticated result.

Application behaviour was not touched.

### Test coverage added

`backend/tests/test_deploy_script.py` — 7 tests:

| Test | Guards |
| --- | --- |
| `test_script_expects_401_from_unkeyed_openapi` | the literal expectation cannot drift back to 404 |
| `test_script_expectation_matches_application_behaviour` | the script's expected code equals what the application actually returns |
| `test_unkeyed_openapi_is_indistinguishable_from_an_unknown_route` | the no-enumeration property the 401 exists to preserve |
| `test_script_accepts_401_from_unkeyed_version` | the `/version` probe still distinguishes a resolved secret from a 503 |
| `test_script_never_sends_the_shared_secret` | no executable line sends `X-GG-Key` |
| `test_script_sends_no_request_headers` | the smoke test is unauthenticated by construction |
| `test_script_never_invokes_secrets_manager` | no `aws secretsmanager` invocation |

The second test is the meaningful one. Asserting the literal alone would let
the script stay self-consistent while the application changed underneath it;
comparing against a live unkeyed response means either side drifting fails the
suite.

### Re-verification

`scripts/deploy-lambda.sh` has no endpoint-verification-only mode — `--check`
validates configuration but does not run the smoke test. It was not redesigned.
Because the tested ZIP was byte-identical to the already deployed ZIP,
re-running `--deploy` was safe: it re-uploaded identical bytes, left
`CodeSha256` unchanged, and exercised the corrected assertion end to end.

The script exited **0**.

RevisionId advanced from `2a21572a-3a27-44af-9526-0d0144366dd7` to
`42241842-bf90-41e6-b5b2-9863cff22701` on that re-upload, as AWS issues a new
revision for any code update. The code itself is unchanged.

---

## CloudWatch log verification

Log group filtered from the moment of deployment forward.

| Check | Result |
| --- | --- |
| Application errors | **PASS** — none |
| Stack traces / `Traceback` | **PASS** — none |
| `ERROR` / `CRITICAL` records | **PASS** — none |
| Secret values | **PASS** — none |
| Credential material (`api_key`, `SecretString`) | **PASS** — none |
| Secret identifiers / secret ARNs | **PASS** — none |
| Secrets Manager retrieval details | **PASS** — no `GetSecretValue`, `secretsmanager`, or `AccessDenied` records |

Only standard Lambda lifecycle records were present: `INIT_START`, `START`,
`END`, and `REPORT`.

The timing pattern independently corroborates that secret retrieval works and
is cached as designed: the first gated request took ~1.2 s, the next ~2 ms.
Powertools caches for 300 s per warm container, so a burst costs one API call.
Nothing about the retrieval — not the identifier, not the outcome — was logged.

---

## Constraints observed

- No application behaviour changed. Proven by the byte-identical ZIP.
- No IAM, Secrets Manager, Lambda configuration, Function URL configuration,
  resource policy, EC2, ECR, or other AWS resource was created or modified.
  The only mutating call was `lambda:UpdateFunctionCode`.
- `secretsmanager:GetSecretValue` was never called. The dev role holds no
  Secrets Manager permission and none was sought.
- The API key was never retrieved, displayed, logged, or requested.
- No keyed request was made. **Authenticated verification remains outstanding
  and is the administrator's to perform.**
- No account ID, instance ID, full ARN, Function URL, or secret identifier was
  printed to the session or written to this report.

---

## Outstanding

1. **Authenticated smoke test.** A keyed request to `/version` should return
   200, and a keyed `/openapi.json` should return 404. Administrator only.
2. **`GracefulGutAI-LambdaExecutionRole` remains unaudited.** Its attached
   policies are not readable from the dev role. Review separately with
   administrator credentials.
3. **The four public-endpoint prerequisites are unchanged and unmet** — API
   Gateway, server-side abuse controls, a real authentication decision
   replacing `X-GG-Key`, and boundary enforcement in the request path. Until
   all four are complete the endpoint stays internal and free-text input stays
   unaccepted. Nothing in this deployment advances or weakens that gate.

---

## Verdict

**Deployment successful.** The Phase 1D application is live on the dev
function, fails closed, resolves its shared secret from Secrets Manager, and
leaks nothing to logs. The one failure encountered was a stale expectation in
the deployment tooling; it is fixed, explained, and covered by tests that tie
it to real application behaviour.
