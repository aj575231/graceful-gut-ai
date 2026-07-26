# Graceful Gut AI — Phase 1 Audit Remediation Report

## Status

All six workstreams implemented and verified locally. **One live infrastructure change is currently broken and requires your intervention.** Nothing has been deployed or committed.

---

## CRITICAL — Dev Function URL is down (403)

**Severity: Critical (active outage, dev environment)**

The approved plan, inherited from the prior audit, stated that the `GracefulGutPublicInvokeFunction` resource-policy statement was redundant and safe to remove. **That claim was wrong.** After removing it, the Function URL returns 403 on every route.

The mis-audit is explained by a policy caching effect: immediately after removal, `/health` continued returning 200 for roughly 10–20 seconds on the stale cached policy, then flipped to a steady 403. Both the original audit and my first verification check landed inside that window.

**I cannot restore it.** The restore requires `lambda:AddPermission` with `--principal '*'`, which the permission classifier blocked on two attempts.

**Action required — run this yourself:**

```bash
aws lambda add-permission \
  --function-name graceful-gut-ai-dev-api --region us-east-2 \
  --statement-id GracefulGutPublicInvokeFunction \
  --action lambda:InvokeFunction --principal '*' \
  --invoked-via-function-url
```

This restores the statement at **exactly** its original scope, including
`Condition: {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}`, so the
anonymous grant stays limited to requests arriving through the Function URL.

> **Correction (2026-07-26 remediation).** An earlier revision of this report
> stated that the `AddPermission` API exposes no parameter for the
> `InvokedViaFunctionUrl` condition, that the restore would therefore be
> broader than the original, and that re-applying the condition required
> CloudFormation, Terraform, or the console. **All of that was wrong.** The
> AWS CLI supports the condition directly via the
> `--invoked-via-function-url` flag (verified against `aws-cli/2.36.8`:
> `aws lambda add-permission help` lists
> `[--invoked-via-function-url | --no-invoked-via-function-url]`). No IaC
> tooling is needed, there is no scope-widening caveat, and there is no
> follow-up task to narrow the grant later. The confusion arose from
> `--function-url-auth-type` being the wrong flag for the
> `lambda:InvokeFunction` action; the correct flag is
> `--invoked-via-function-url`. Never apply the unconditioned form.

The full, corrected policy — **two statements, both required** — is recorded in
`infrastructure/lambda-url-resource-policy.json`:

| Sid | Action | Condition | CLI flag |
| --- | --- | --- | --- |
| `GracefulGutPublicInvokeUrl` | `lambda:InvokeFunctionUrl` | function URL auth type `NONE` | `--function-url-auth-type NONE` |
| `GracefulGutPublicInvokeFunction` | `lambda:InvokeFunction` | `lambda:InvokedViaFunctionUrl` | `--invoked-via-function-url` |

---

## Workstream results

| # | Workstream | Status |
| --- | --- | --- |
| 1 | Boundaries encoded in `CLAUDE.md` + `README.md` | Complete |
| 2 | Reproducible build/deploy scripts + CI | Complete |
| 3 | Version drift closed (pinning) | Complete |
| 4 | Access and hygiene | Complete **except** the policy statement above |
| 5 | Container-vs-ZIP ambiguity documented | Complete |
| 6 | Test suite strengthened | Complete |

---

## Verification results

**Tests: 3 → 26, all passing.**

```
26 passed, 2 warnings
```

**Lint and format:** `ruff check backend/` and `ruff format --check backend/` both clean (previously 3 errors and 2 files needing reformat, all BOM-related).

**Build package:**

- Byte-reproducible — identical `sha256` across two consecutive runs
- 287 entries, **zero backslash paths** (previously 355 of 356)
- No `bin/` directory, no `.exe` launchers (previously shipped `bin\fastapi.exe`, `bin\idna.exe`)
- Packaged `app/` byte-identical to the repository working tree
- `pydantic_core` correctly cross-built as `cpython-313-x86_64-linux-gnu.so` for the deployed runtime

**BOM removal:** all 7 tracked files stripped (`.gitignore`, `backend/.dockerignore`, `backend/Dockerfile`, `backend/app/main.py`, `backend/requirements.txt`, `backend/tests/test_health.py`, `docker-compose.yml`). Re-scan returns clean. No CRLF line endings remain in tracked files.

**Ignore rules:** `lambda.zip`, `credentials`, `.aws/config`, `pkg.tar.gz`, and `.env` now correctly ignored; `.env.example` correctly tracked.

**Dependency alignment:** local venv reinstalled against pinned versions — `fastapi==0.139.2`, `pydantic==2.13.4`, `uvicorn[standard]==0.51.0`, `mangum==0.21.0`, `httpx==0.28.1`, `pytest==8.4.2`, `ruff==0.16.0`. Local FastAPI/pydantic now match the deployed Lambda exactly (previously 0.140.0 local vs 0.139.2 deployed).

---

## Deviations from the approved plan

Both deviations were forced by the plan being factually wrong.

1. **The `GracefulGutPublicInvokeFunction` statement is not redundant.** Documented above.

2. **`/docs` returns 401, not 404, without a valid key.** The plan assumed 404. The security middleware runs before routing, so any non-public path returns 401 regardless of whether the route exists. This is the better behavior — it prevents route enumeration — so I kept it and added `test_gate_does_not_leak_which_routes_exist` asserting 401 across `/docs`, `/redoc`, `/openapi.json`, and a nonexistent path.

---

## Security model as implemented

The Function URL remains `AuthType: NONE`; access control lives in application code.

- Header `X-GG-Key` compared against env var `GG_API_KEY` using `hmac.compare_digest`
- `/health` always exempt — the docker-compose healthcheck and uptime probes depend on it, and it exposes no sensitive data
- `APP_ENV` has exactly two supported values: `production` (every AWS deployment — secure and fail-closed) and `development` (local only). The value `dev` is retired.
- `APP_ENV` defaults to `production` when unset, so a missing variable **fails closed**; any unrecognized value is likewise treated as `production`
- `APP_ENV=development` is the only value that relaxes security; it permits unauthenticated access when no key is set and exposes `/openapi.json`
- When the gate is enforced and `GG_API_KEY` is unset, requests return **503** rather than serving openly
- CORS sits outside the gate so browser preflight requests, which carry no key, are answered correctly
- `openapi_url` is fixed at construction time, so `create_app()` is a factory allowing tests to build instances under specific environments

---

## Recommendations

**Immediate:**

1. Run the `add-permission` command above — with `--invoked-via-function-url` — to restore the dev endpoint. It lands at the original scope; no follow-up narrowing step is needed.
2. Confirm both required statements are present with `aws lambda get-policy --function-name graceful-gut-ai-dev-api`. Do not verify with a single immediate `curl`: policy caching keeps the URL answering for ~10–20 seconds after a change.

**Before deploying the new code:**

3. Set `APP_ENV` and `GG_API_KEY` on the function **before** uploading. Deploying first would return 503 on every route until the environment variables land, since `APP_ENV` defaults to `production` and fails closed.
   ```bash
   aws lambda update-function-configuration \
     --function-name graceful-gut-ai-dev-api --region us-east-2 \
     --environment 'Variables={APP_ENV=production,GG_API_KEY=<your-key>}'
   ```
   Generate the secret yourself with `openssl rand -hex 32` and do not record the value anywhere in the repository. Use `APP_ENV=production` on **every** AWS deployment — never `development`, and never the retired value `dev`.
4. Then run `bash scripts/deploy-lambda.sh` and record the printed `CodeSha256` alongside the commit.

**Follow-up:**

5. Drop `lambda:AddPermission` from `infrastructure/claude-dev-deployment-policy.json` once the URL resource policy is final — it currently lets this host re-open the function to any principal.
6. Apply the updated `claude-dev-deployment-policy.json` (adds `logs:ListTagsForResource`, which log-group tag verification needs) with admin credentials. The repository copy is documentation only; the dev role cannot modify IAM.
7. Review `GracefulGutAI-LambdaExecutionRole` separately with appropriate credentials — its attached policies are not readable from the dev role and were out of scope.
8. **Public-endpoint milestone.** Before Phase 2 accepts free-text input from the public, the service must move behind **API Gateway** with **server-side abuse controls** — per-IP and per-key throttling and quotas, request-size and input-length caps, AWS WAF with a rate-based rule, and CloudWatch alarms on volume, error rate, and spend — plus a real authentication mechanism replacing `X-GG-Key` and boundary enforcement in the request path. `X-GG-Key` is temporary internal-development protection only: one static shared secret, no rotation, no per-caller identity, no rate limiting. It must never be embedded in the Squarespace browser client or any other browser-side code, where it would be readable by every visitor. See the binding gate in `CLAUDE.md`.

---

## Outstanding

- **Nothing is deployed.** The new code — which is what actually closes the public `/openapi.json` and adds the `X-GG-Key` gate — is built but not uploaded.
- **Nothing is committed.** The working tree holds all changes.

---

## Environment reference

| Item | Value |
| --- | --- |
| Account | `<redacted>` |
| Region | `us-east-2` |
| Function | `graceful-gut-ai-dev-api` |
| Handler | `app.lambda_handler.handler` |
| Runtime | `python3.13`, `x86_64`, 512 MB, 15 s timeout |
| Package type | `Zip` |
| Reserved concurrency | 2 |
| Log retention | 14 days |
| Function URL | `https://<redacted>.lambda-url.us-east-2.on.aws/` |
| Deploy role | `GracefulGutAI-ClaudeDevRole` (instance `<redacted>`) |
| Execution role | `GracefulGutAI-LambdaExecutionRole` (not readable from dev role) |
| Tags | `Project=GracefulGutAI`, `Environment=Development`, `Owner=AJMoses`, `Business=GracefulHealth` |
| Local Python | 3.12.3 — no 3.13, pyenv, uv, or Docker on host; 3.13 covered by CI |
