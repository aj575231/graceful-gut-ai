# Graceful Gut AI — Phase 1 Remediation, Final Report

**Date:** 2026-07-26
**Branch:** `phase1-remediation`
**Nothing was deployed. No AWS resource was created, modified, or deleted.**

This report closes out the corrections applied to the previously uncommitted
Phase 1 audit remediation work.

---

## What was corrected

### 1. The AWS CLI *can* apply the `InvokedViaFunctionUrl` condition

The prior audit stated that `AddPermission` exposes no parameter for
`Condition: {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}`, that restoring
the statement would therefore grant broader access than the original, and that
re-applying the condition required CloudFormation, Terraform, or the console.

**That was wrong.** Verified against the installed `aws-cli/2.36.8`:

```
aws lambda add-permission help
  [--function-url-auth-type <value>]
  [--invoked-via-function-url | --no-invoked-via-function-url]
```

The condition is applied directly with `--invoked-via-function-url`. There is
no scope-widening caveat, no IaC requirement, and no follow-up task to narrow
the grant later. The original confusion came from reaching for
`--function-url-auth-type`, which is the wrong flag for the
`lambda:InvokeFunction` action.

Corrected in `docs/audits/phase1-infrastructure-audit-2026-07-26.md` (with an
explicit correction notice preserving the record), `CLAUDE.md`, and
`infrastructure/lambda-url-resource-policy.json`.

### 2. Lambda permissions — two statements, both required

`infrastructure/lambda-url-resource-policy.json` previously asserted that
"exactly ONE statement is required" and had had the second statement removed —
the change that took the dev URL to a steady 403. It now documents both:

| Sid | Action | Condition | CLI flag |
| --- | --- | --- | --- |
| `GracefulGutPublicInvokeUrl` | `lambda:InvokeFunctionUrl` | function URL auth type `NONE` | `--function-url-auth-type NONE` |
| `GracefulGutPublicInvokeFunction` | `lambda:InvokeFunction` | `lambda:InvokedViaFunctionUrl` | `--invoked-via-function-url` |

Both the policy file and `CLAUDE.md` now warn that the endpoint appears healthy
for ~10–20 seconds after a policy change because of caching, and that
verification must use `aws lambda get-policy`, not a single immediate `curl`.

### 3. `APP_ENV` standardized on two values

| Value | Where | Behaviour |
| --- | --- | --- |
| `production` | **every** AWS deployment | gate enforced, `/openapi.json` hidden, fails closed |
| `development` | local machines only | unauthenticated access when no key is set, `/openapi.json` exposed |

`APP_ENV` names a security posture, not a deployment tier. The value `dev` is
retired. Anything unrecognized — including a missing value — is treated as
`production`, as a safety net rather than a supported configuration.

Enforced, not just documented:

- `backend/app/config.py` exports a `PRODUCTION` constant; the default is
  `PRODUCTION`.
- `backend/tests/test_security.py` runs its deployed-posture fixtures under
  `production`, and two new tests assert that `dev`, `staging`, `prod`,
  `Production`, `""`, and an unset variable all fail closed with 503.
- `scripts/deploy-lambda.sh` now **fails the deploy** (non-zero exit) when a
  function reports `APP_ENV=development`, and warns on any unrecognized value.
  It previously only printed a warning.
- Aligned across `README.md`, `CLAUDE.md`, `.env.example`, and the audit report.

### 4. No real `GG_API_KEY` anywhere

No key was generated or embedded. `.env.example` carries an empty value and
instructs the reader to generate their own with `openssl rand -hex 32` and keep
it out of Git, scripts, tests, documentation, and the deployment package. The
test fixture constant was renamed `SECRET` → `PLACEHOLDER_KEY`
(`"placeholder-not-a-real-key"`) so it cannot be mistaken for a live value.
`scripts/deploy-lambda.sh` neither generates nor prints a secret.

### 5. `X-GG-Key` documented as temporary and internal-only

`README.md`, `CLAUDE.md`, the resource-policy file, and the audit report now
state that `X-GG-Key` is temporary internal-development protection: one static
shared secret, no rotation, no per-caller identity, no revocation, no rate
limiting. **It must never be embedded in the Squarespace browser client** or any
other browser-side code — anything shipped to a browser is readable by every
visitor in page source and network traces.

### 6. Public-endpoint milestone documented as a release gate

Recorded in `CLAUDE.md` (binding), `README.md`, and the audit report. Before any
public free-text input is accepted:

1. **API Gateway** in front of the Lambda, retiring the raw Function URL as the
   public entry point.
2. **Server-side abuse controls**: per-IP and per-key throttling and quotas,
   request-size and input-length caps, AWS WAF with managed rules and a
   rate-based rule, CloudWatch alarms on request volume, error rate, and spend,
   a hard concurrency ceiling, and request logging that records no free-text
   content (no-PHI boundary).
3. **A real authentication mechanism** replacing `X-GG-Key`.
4. **Product boundaries enforced in the request path**, not only in prompt text.

### 7. Sensitive data removed

| Item | Found in | Action |
| --- | --- | --- |
| AWS account ID | `CLAUDE.md`, `README.md`, `backend/tests/test_lambda_handler.py`, both `infrastructure/*.json` policies | replaced with `<AWS_ACCOUNT_ID>` placeholder; test uses synthetic `000000000000` |
| Live Function URL | `CLAUDE.md`, `README.md`, `backend/tests/test_lambda_handler.py` (3 places) | replaced with a synthetic host; docs now show the `aws lambda get-function-url-config` command instead |
| Instance IDs, `AKIA`/`ASIA` keys, private keys, tokens | — | none present |
| Patient data / PHI | — | none present; the service stores none by design |
| Build packages | `.build/lambda.zip` | already gitignored; confirmed untracked and confirmed to contain no `.env`, credentials, account ID, or URL |

Final scan of the working tree and of the built ZIP for account IDs, the URL
ID, instance IDs, and AWS key patterns returned **clean**.

---

## Verification results

All run locally on Python 3.12; CI covers the deployed 3.13 runtime.

| Check | Result |
| --- | --- |
| `python -m pytest -q` | **32 passed**, 2 warnings (was 26) |
| `ruff check backend/` | **All checks passed!** |
| `ruff format --check backend/` | **8 files already formatted** |
| Reproducible build | **Byte-identical** across two consecutive runs |
| `git diff --check` | clean, no whitespace errors |
| `git status --short` | clean after commit |

Reproducible build detail — two consecutive `scripts/build-lambda.sh` runs:

```
BUILD 1: c533de8455a5e435d36cf227f74ff39d3c31b255e7e3340b61c6b039d8ccf6dd
BUILD 2: c533de8455a5e435d36cf227f74ff39d3c31b255e7e3340b61c6b039d8ccf6dd
REPRODUCIBLE: identical sha256
```

287 entries, all forward-slash names, no `bin/` directory, no `.exe` launchers,
application modules present.

The two pytest warnings are upstream deprecations, not defects: a Starlette
`TestClient`/`httpx` notice and a Mangum `asyncio.get_event_loop()` notice.

---

## Files changed

23 files in commit `940ffba`:

```
.env.example                                          .gitignore
.github/workflows/ci.yml                              CLAUDE.md
README.md                                             docker-compose.yml
pyproject.toml
backend/.dockerignore                                 backend/Dockerfile
backend/app/config.py                                 backend/app/lambda_handler.py
backend/app/main.py                                   backend/requirements.txt
backend/requirements-dev.txt                          backend/tests/conftest.py
backend/tests/test_health.py                          backend/tests/test_lambda_handler.py
backend/tests/test_security.py
infrastructure/claude-dev-deployment-policy.json
infrastructure/lambda-url-resource-policy.json
scripts/build-lambda.sh                               scripts/deploy-lambda.sh
docs/audits/phase1-infrastructure-audit-2026-07-26.md
```

---

## Remaining blockers before deployment

1. **The dev Function URL is still down (403).** Both permission statements
   must be applied. This requires `lambda:AddPermission` with
   `--principal '*'`, which the permission classifier blocks — **run it
   yourself**:

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

   Confirm with `aws lambda get-policy`, not with an immediate `curl`.

2. **Function environment must be set before the code is uploaded.** `APP_ENV`
   defaults to `production` and fails closed, so deploying first returns 503 on
   every gated route until the variables land. Generate the key yourself and do
   not record it anywhere in the repository:

   ```bash
   openssl rand -hex 32

   aws lambda update-function-configuration \
     --function-name graceful-gut-ai-dev-api --region us-east-2 \
     --environment 'Variables={APP_ENV=production,GG_API_KEY=<your-key>}'
   ```

3. **The new code is built but not deployed.** It is what actually closes the
   public `/openapi.json` and adds the `X-GG-Key` gate. Run
   `bash scripts/deploy-lambda.sh` and record the printed `CodeSha256` with the
   commit it was built from.

4. **Git history still contains the account ID and Function URL.** The
   redactions apply to the working tree from this commit forward; earlier
   commits on `main` retain both values. Neither is a credential, but if the
   repository is ever made public, rewrite history or rotate the URL first.

5. **IAM follow-ups, unchanged and still open.**
   - Drop `lambda:AddPermission` from
     `infrastructure/claude-dev-deployment-policy.json` once the URL policy is
     stable — it currently lets this host re-open the function to any principal.
   - Apply the updated `claude-dev-deployment-policy.json` with admin
     credentials; the repository copy is documentation only.
   - Review `GracefulGutAI-LambdaExecutionRole` separately — its attached
     policies are not readable from the dev role and remain unaudited.

6. **Public launch remains gated** on the API Gateway and abuse-control
   milestone in section 6 above. `X-GG-Key` is not sufficient for a
   browser-facing client and must not be shipped to one.

### Minor, noted not fixed

`scripts/deploy-lambda.sh` passes `GG_API_KEY` to `curl` via `-H` during the
smoke test, so the value is briefly visible in the local process list. It is
never written to a file or printed. Worth revisiting if the script ever runs on
a shared host.
