# Phase 1E — API Gateway and abuse-protection architecture review

**Date:** 2026-07-28
**Branch:** `phase1e-api-gateway-design`
**Design commit:** `bee683e074066a0ac381f65b93dcd4eef3c7ae2e` — *Design Phase 1E API Gateway architecture*
**Scope:** design, documentation, and test planning only.

This report is redacted by construction: no account ID, instance ID, full ARN,
live Function URL, secret identifier, token, credential, or secret value
appears anywhere in it.

---

## Confirmation: AWS was not modified

No AWS resource was created, modified, or read during Phase 1E. Specifically:

| Constraint | Status |
| --- | --- |
| Create or modify AWS resources | **Not done** — zero AWS API calls of any kind |
| Deploy Lambda code | **Not done** |
| Modify IAM | **Not done** — the policies added are reference documents, unapplied |
| Access Secrets Manager | **Not done** |
| Request the API key | **Not done** |
| Enable public free-text input | **Not done** — the route is designed, not implemented |
| Change the live Lambda Function URL | **Not done** |

The only commands run were local: `pytest`, `ruff`, `git`, and file writes.

---

## Recommended architecture

> **Regional REST API (API Gateway v1) with an AWS WAF Web ACL attached to the
> stage, serving an anonymous public beta with no user accounts and no client
> authentication.**

### Primary reasons

1. **WAF attaches natively to a REST API stage.** An HTTP API cannot have a Web
   ACL associated directly. Choosing it would require a CloudFront distribution
   whose only purpose is hosting the Web ACL, plus origin-cloaking work to stop
   callers reaching the API endpoint directly and bypassing WAF entirely. That
   is permanent infrastructure bought for nothing.
2. **REST API has native request validation; HTTP API has none.** A JSON Schema
   model rejects oversized bodies, over-length messages, and wrong content types
   at the edge — costing one API Gateway request and **zero** Lambda invocations
   and **zero** model spend. For an anonymous endpoint calling a paid model,
   that is the single most effective denial-of-wallet control available.
3. **The design is honest about authentication.** Squarespace is a public
   browser client and cannot hold a secret. The recommendation therefore ships
   **no** authentication on the public route, rather than embedding a
   client-visible token and describing it as security.
4. **Cost difference is immaterial.** ~$2.50 per million requests separates the
   options; model spend dominates the bill by orders of magnitude.

### The conceptual split the design rests on

Authentication asks *who is this caller?* and requires a secret the caller can
keep. Abuse control asks *is this traffic acceptable?* and requires nothing from
the caller. A public browser client can be constrained but not authenticated.
Phase 1E therefore invests entirely in abuse controls.

**CORS is not a security control.** It is browser-enforced only; `curl` ignores
it. It stops other websites driving our API through a visitor's browser, and
nothing else.

### Accounts

**Recommended: no accounts for the public beta.** Accounts would collect an
email address — identifying information — and account-linked history is exactly
the account-linked symptom history V1 prohibits. They would also fail to solve
the problem they appear to solve, since anyone can create one. Flagged for owner
decision.

---

## Files changed

### Added — architecture

| File | Contents |
| --- | --- |
| `docs/architecture/phase1e-api-gateway-adr.md` | The ADR: options A/B/C, recommendation, WAF plan, throttling, API surface, boundaries, logging, CORS, Function URL retirement, IAM design, IaC recommendation, cost controls, test plan, migration sequence, open decisions |

### Added — reference policies (proposed, unapplied)

| File | Contents |
| --- | --- |
| `infrastructure/phase1e/README.md` | Placeholder convention and scoping notes |
| `infrastructure/phase1e/apigateway-invoke-lambda.json` | Lambda resource policy — only this API may invoke, scoped by `SourceArn` |
| `infrastructure/phase1e/deployment-automation-policy.json` | Deployment role — explicit `Deny` on Function URL admin, all `wafv2:`, API deletion, all `secretsmanager:` |
| `infrastructure/phase1e/waf-administration-policy.json` | Administrator-only WAF management |
| `infrastructure/phase1e/log-access-policy.json` | Read logs; `Deny` on writing or deleting log content |
| `infrastructure/phase1e/administrator-only-actions.md` | Enumerated actions no automation role may hold |

### Added — tests

| File | Contents |
| --- | --- |
| `backend/tests/test_phase1e_design.py` | 17 static guards |

### Added — this report

| File | Contents |
| --- | --- |
| `docs/audits/phase1e-api-gateway-design-2026-07-28.md` | This document |

**No application code was modified.** `backend/app/` is untouched, so the Lambda
package is unchanged and `CodeSha256` is unaffected.

---

## Tests added

17 tests in `backend/tests/test_phase1e_design.py`, taking the suite from 92 to
**109**.

| Requirement | Tests |
| --- | --- |
| Infrastructure templates contain no real account IDs | `test_no_real_account_ids_are_committed` (parametrised over `infrastructure/` and `docs/architecture/`), `test_phase1e_policies_use_placeholders_and_parse` |
| No browser-facing file contains `X-GG-Key` or `GG_API_KEY` | `test_no_browser_facing_file_contains_a_credential_name` |
| No browser-facing file contains a secret value | `test_no_browser_facing_file_contains_a_secret_value` |
| CORS never uses `*` for protected routes | `test_cors_origins_are_never_a_wildcard`, `test_non_loopback_cors_origins_are_https`, `test_cors_does_not_allow_credentials`, `test_design_forbids_wildcard_origins` |
| Logging configuration excludes request and response bodies | `test_logging_design_forbids_request_and_response_bodies`, `test_application_never_logs_a_request_or_response_body` |
| Function URL not described as the final public endpoint | `test_function_url_is_not_described_as_the_final_public_endpoint`, `test_architecture_docs_mentioning_the_function_url_plan_its_retirement` |
| Detector self-tests | `test_credential_detector_catches_a_planted_key`, `test_secret_detector_catches_a_planted_value`, `test_secret_detector_ignores_ordinary_text`, `test_browser_facing_discovery_finds_known_suffixes` |

### Why the detectors are themselves tested

The repository ships **no** browser-facing files today. A scan across zero files
passes trivially while protecting nothing, and would keep passing if the scanner
were later broken. The four detector self-tests plant a synthetic `embed.js`
carrying a credential and a 64-character hex value and assert the scanner
catches both — so the guards are known to work before there is anything real for
them to guard.

The secret detector never echoes a suspected value in a failure message; it
prints an eight-character prefix only.

---

## Verification results

| Gate | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **PASS** — 109 passed (17 new) |
| `.venv/bin/ruff check backend/` | **PASS** |
| `.venv/bin/ruff format --check backend/` | **PASS** — 13 files formatted |
| `git diff --check` | **PASS** — no whitespace errors |
| JSON validity of all four reference policies | **PASS** |
| Deployment | **Not performed** — explicitly out of scope |

---

## Decisions required from AJ and Jenna

None of these should be decided by Claude. Each changes the design materially.

| # | Decision | Recommendation |
| --- | --- | --- |
| 1 | **Does the public beta require accounts?** | **No** — accounts collect identifying data and create the account-linked history V1 prohibits |
| 2 | **Acceptable anonymous usage limit** | 60 chat requests / 5 min / IP; 2 rps steady, burst 5 |
| 3 | **Exact Squarespace production origin** | Placeholder until supplied; must be `https` |
| 4 | **May IP addresses be retained in WAF or access logs?** | API Gateway access logs IP-free; **WAF logging off** — WAF logs cannot omit client IP |
| 5 | **Data-retention period** | 14 days application logs; 30 days maximum for security logs |
| 6 | **Emergency-routing language** | Clinician-authored, prominent, never triage — highest-risk copy in the product |
| 7 | **Will any conversation history exist?** | **No history in beta** — multi-turn context changes the data-path analysis |
| 8 | **Monthly AWS and model budget** | Required before launch; every throttle, token cap, and alarm threshold depends on it |
| 9 | **Indiana-only limitations and wording** | Educational unrestricted, clinical Indiana-only; wording needs clinician sign-off |
| 10 | Daily-cap mechanism | Global counter storing no identifiers |
| 11 | Promote WAF `AnonymousIpList` to block? | **No — count only.** Blocking VPN/Tor users on a gut-health service harms exactly the privacy-seeking users it should serve |
| 12 | Reserved concurrency for beta | 5–10, up from the current 2 |

### The two most consequential

**Decision 4 (IP retention)** is a genuine conflict, not a preference. API
Gateway access log format is configurable, so IP can be omitted. **WAF logging
cannot omit client IP**, and sampled requests retain IP and partial request data
for roughly three hours. Enabling WAF logging therefore means accepting IP
retention — which collides with the no-identifying-information boundary. Rate
limiting still works with WAF logging disabled; the decision is about
**retention**, not capability.

**Decision 8 (budget)** blocks quantitative work. Reserved concurrency, token
caps, throttle values, and alarm thresholds are all derived from an acceptable
monthly spend. Until that number exists, the values in the ADR are conservative
guesses.

---

## Findings worth flagging

### WAF will block legitimate health language unless configured carefully

The Common Rule Set and SQLi rules inspect request bodies with heuristics tuned
for web payloads. Ordinary descriptions of gut symptoms trip them:

- **`Crohn's disease`** contains the apostrophe SQLi heuristics weight most
  heavily — as does most possessive or contracted English.
- **SQL keywords that are also English words:** *"a sudden **drop** in
  appetite"*, *"I **select** foods carefully"*, *"pain near the **union** of the
  stomach and oesophagus"*.
- Comparison phrasing such as *"less than <2 weeks"* can read as markup to XSS
  heuristics.

This is why the WAF rollout is **count-first**: run against a corpus of
realistic phrasings, record which rule IDs fire, and exclude those specific rule
IDs — never disable a whole rule group. Blocking a user describing their
symptoms is a product failure, not a security win.

### Geographic restriction would contradict a stated product boundary

`CLAUDE.md` states that educational content is **not** geographically limited
and only clinical services are Indiana-only. The endpoint under design is the
educational one, so geo-blocking is not justified. A rate-based rule is the
better instrument for concentrated abuse.

### Throttles are not cost ceilings

Stated plainly in the ADR because it is the most consequential caveat: API
Gateway throttles and usage-plan quotas are **best-effort**, applied across a
distributed system, approximate at the boundary, and do **not** guarantee a
maximum bill. WAF rate-based rules act with evaluation lag. The only hard bounds
are Lambda reserved concurrency, the per-request token cap, and the kill switch.

### `/version` should stop being public

It offers a visitor nothing and leaks build detail useful only for
fingerprinting. Recommended to stay gated. Its diagnostic role — a `401`
distinguishing a healthy deployment from a `503` — works better when it is not
public.

### Function URL rollback must not reopen access broadly

Rollback re-applies the **two specific statements** already tracked in
`infrastructure/lambda-url-resource-policy.json`, both conditioned. It never
means granting the unconditioned, broader `lambda:InvokeFunction`. Removal
verification must use `aws lambda get-policy` first — policy caching keeps the
URL working for roughly 10–20 seconds after removal, and a single immediate
`curl` misled a previous audit into taking the dev URL down.

---

## What Phase 1E does not do

- It does not enable public free-text input. That remains blocked until the
  `CLAUDE.md` release gate is satisfied in full.
- It does not create infrastructure. The SAM template is recommended, not
  written.
- It does not resolve the `X-GG-Key` replacement for machine clients — usage
  plans with API keys are proposed for machine callers only, never the browser.
- It does not audit `GracefulGutAI-LambdaExecutionRole`, whose attached policies
  remain unreadable from the dev role.

---

## Verdict

The architecture is decided and documented, the invariants that can be enforced
statically are enforced, and the twelve decisions that require product and
clinical judgement are isolated and named rather than assumed. No AWS resource
was touched. The next step is owner review of the decisions above — in
particular the budget and the IP-retention question, which together determine
most of the remaining quantitative design.
