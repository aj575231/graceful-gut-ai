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
   model rejects over-length messages and unexpected fields at the edge, and
   the method configuration rejects unsupported content types — costing one API
   Gateway request and **zero** Lambda invocations and **zero** model spend.
   Body *size* is capped separately by a WAF rule; see correction 2 below.
3. **The design is honest about authentication.** A public browser client
   cannot safely keep a permanent shared client secret, so the recommendation
   ships no such secret. The anonymous beta has **no** authentication because
   it has **no accounts** — a product decision, not a technical limit.
4. **Cost difference is immaterial.** ~$2.50 per million requests separates the
   options; model spend dominates the bill by orders of magnitude.

### The conceptual split the design rests on

Authentication asks *who is this caller?* and requires a per-user credential
obtained through a flow. Abuse control asks *is this traffic acceptable?* and
requires nothing from the caller. Browsers **can** be authenticated — through
flows that issue short-lived credentials and embed no secret — but the
anonymous beta has no accounts, so there is no user to authenticate and abuse
control is the whole of the defence. If accounts are later adopted, the path is
Cognito or another OIDC provider using the authorization-code flow with PKCE.

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
| `backend/tests/test_phase1e_design.py` | 31 static guards — 17 original, 14 added by the correction review |

### Added — this report

| File | Contents |
| --- | --- |
| `docs/audits/phase1e-api-gateway-design-2026-07-28.md` | This document |

**No application code was modified.** `backend/app/` is untouched, so the Lambda
package is unchanged and `CodeSha256` is unaffected.

---

## Tests added

31 tests in `backend/tests/test_phase1e_design.py`, taking the suite from 92 to
**123** — 17 added with the original design, 14 more locking in the corrections
below.

| Requirement | Tests |
| --- | --- |
| Infrastructure templates contain no real account IDs | `test_no_real_account_ids_are_committed` (parametrised over `infrastructure/` and `docs/architecture/`), `test_phase1e_policies_use_placeholders_and_parse` |
| No browser-facing file contains `X-GG-Key` or `GG_API_KEY` | `test_no_browser_facing_file_contains_a_credential_name` |
| No browser-facing file contains a secret value | `test_no_browser_facing_file_contains_a_secret_value` |
| CORS never uses `*` for protected routes | `test_cors_origins_are_never_a_wildcard`, `test_non_loopback_cors_origins_are_https`, `test_cors_does_not_allow_credentials`, `test_design_forbids_wildcard_origins` |
| Logging configuration excludes request and response bodies | `test_logging_design_forbids_request_and_response_bodies`, `test_application_never_logs_a_request_or_response_body` |
| Function URL not described as the final public endpoint | `test_function_url_is_not_described_as_the_final_public_endpoint`, `test_architecture_docs_mentioning_the_function_url_plan_its_retirement` |
| Detector self-tests | `test_credential_detector_catches_a_planted_key`, `test_secret_detector_catches_a_planted_value`, `test_secret_detector_ignores_ordinary_text`, `test_browser_facing_discovery_finds_known_suffixes` |
| **Corrections locked in (14)** | `test_waf_body_inspection_limit_is_stated_for_api_gateway`, `test_body_size_cap_is_a_waf_rule_not_request_validation`, `test_application_checks_both_byte_size_and_character_length`, `test_unsupported_content_types_are_rejected_explicitly`, `test_request_model_validation_skip_is_documented`, `test_adr_does_not_claim_browsers_cannot_be_authenticated`, `test_future_accounts_have_a_named_authentication_path`, `test_preflight_expectation_matches_starlette`, `test_options_routing_caveat_is_documented`, `test_emergency_routing_does_not_claim_a_bypass`, `test_emergency_guidance_is_static_and_in_every_failure_path`, `test_legal_review_is_launch_blocking_and_hipaa_is_not_settled`, `test_model_provider_data_flow_decision_is_complete`, `test_infrastructure_and_application_stacks_are_separated` |

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
| `.venv/bin/python -m pytest -q` | **PASS** — 123 passed (31 new across both commits) |
| `.venv/bin/ruff check backend/` | **PASS** |
| `.venv/bin/ruff format --check backend/` | **PASS** — 13 files formatted |
| Re-run after corrections | **PASS** — all gates green on `8b5cd35` |
| `git diff --check` | **PASS** — no whitespace errors |
| JSON validity of all four reference policies | **PASS** |
| Deployment | **Not performed** — explicitly out of scope |

---

## Commit hashes and push

| Role | Commit | Message |
| --- | --- | --- |
| Design and tests | `bee683e074066a0ac381f65b93dcd4eef3c7ae2e` | *Design Phase 1E API Gateway architecture* |
| This report | `82d045e` | *Document Phase 1E architecture review* |
| This report — commit-hash record added | `9436c86` | *Record Phase 1E commit hashes and push confirmation* |
| Corrections to the ADR and tests | `8b5cd3560b0ccdcbb980a68ddd293d0635860190` | *Correct Phase 1E architecture assumptions* |
| This report — correction review added | the commit adding this section | *Document Phase 1E correction review* |

A report cannot contain its own commit hash, so the row above names the commit
that added this section rather than quoting it.

The two commits that changed the architecture are `bee683e` and `8b5cd35` —
the design, and the corrections that followed the review. `82d045e` is a
**report** commit and changed no design artefact. An earlier version of this
sentence named `bee683e` and `82d045e` as the substantive pair, which conflated
the report with the work and left `8b5cd35` — the commit carrying nine
corrections, two of which would otherwise have produced a broken design —
unlisted. Corrected in Phase 1F.

**Branch:** `phase1e-api-gateway-design`, pushed to `origin` and tracking
`origin/phase1e-api-gateway-design`. The initial push created the remote branch
and reported no errors.

Nothing was merged to `main`. Nothing was deployed.

---

## Decisions required from AJ and Jenna

None of these should be decided by Claude. Each changes the design materially.

Two decisions added by the correction review are **launch-blocking** — the
endpoint must not accept public traffic until both are resolved.

| # | Decision | Status |
| --- | --- | --- |
| **L1** | **Legal and compliance determination** — HIPAA, business-associate obligations, the **FTC Health Breach Notification Rule**, state law, privacy policy, and consent | **Launch-blocking.** Requires qualified legal review. The ADR no longer asserts the service is outside HIPAA |
| **L2** | **Model-provider data-flow determination** — provider, BAA availability, retention, training use, subprocessors, region, zero-data-retention terms, deletion, breach handling, maximum content transmitted | **Launch-blocking.** Free text leaves our infrastructure the moment it reaches a provider; our no-persistence boundary says nothing about what they retain |

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

## Correction review

A review of the ADR after it was written found nine incorrect or incomplete
claims. Two of them would have produced a broken or dangerous design if built
from. All are corrected in `8b5cd35`, and fourteen tests lock them in.

| # | Claim as written | Correction |
| --- | --- | --- |
| 1 | WAF inspects the first **8 KB** of a request body for regional resources | For **API Gateway** the default is **16 KB**, configurable to **64 KB**. The 8 KB figure applies to **ALB and AppSync** |
| 2 | The 4 KB body cap is enforced by **API Gateway request validation** | Request validation **cannot** cap body size — JSON Schema has no body-size keyword. The cap is a **WAF `SizeConstraintStatement`** over 4,096 bytes |
| 3 | Message length enforced by schema and application | Unchanged, but the application must check **UTF-8 byte size *and* character length separately** — 2,000 multi-byte characters can exceed 4,096 bytes |
| 4 | Content type "required `application/json`" | Rejection is now **explicitly configured**, and the ADR records that API Gateway **skips request-model validation when no model matches the content type** unless `$default` or passthrough blocking (`NEVER`) is set, and "Validate body" is enabled |
| 5 | "A public browser client cannot keep a secret, so it **cannot be authenticated**" | Browsers **can** be authenticated. What they cannot safely keep is a **permanent shared client secret**. The beta has no authentication because it has **no accounts**; future accounts would use **Cognito/OIDC authorization-code flow with PKCE** |
| 6 | Allowed preflight returns **`204`** | Starlette's `CORSMiddleware` returns **`200`**. Also added: `OPTIONS` does not reach the application on a REST API unless the resource uses `ANY` on a proxy path or defines `OPTIONS` explicitly |
| 7 | Emergency path "**must not be gated** behind a challenge, a rate limit response, or a degraded-mode fallback" | **Not implementable.** WAF and API Gateway act before anything reads the message. Emergency guidance now never depends on a successful API call |
| 8 | "a system explicitly designed to be **outside HIPAA's scope**" | Removed. The ADR no longer states this as settled fact; a **launch-blocking legal review** is added instead |
| 9 | AWS SAM recommended, single deployment path implied | Split into an **administrator-controlled infrastructure stack** and a **restricted application path**, with administrator-reviewed change sets |

### The two that mattered most

**Emergency routing (7).** The original wording promised something the
architecture cannot deliver. WAF and API Gateway act on a request before any
code reads its content, so nothing at the edge can know a message is urgent.
Building a bypass that inspected content ahead of the abuse controls would be
both a security hole and unreliable exactly when the service is under load —
which is when someone in an emergency most needs the guidance.

The corrected design inverts it: emergency guidance **never depends on a
successful API call**. It is permanently visible in the Squarespace page,
rendered independently of any request, and repeated in every `403`, `429`,
`5xx`, and timeout fallback. `/health` stays outside chat-route challenge
rules. The guidance is therefore present precisely when the API is throttled,
blocked, failing, or down.

**Body-size enforcement (2).** The cap was assigned to a mechanism that cannot
implement it. Had it been built as written, the 4 KB limit would silently not
have existed — the most expensive kind of control failure, because it looks
enforced in the design document and is absent in production. Three layers now
each do a job the others cannot: WAF blocks oversized bodies at the edge, the
schema caps message length, and the application checks both byte size and
character length.

### On HIPAA (8)

The repository is *designed* so that no HIPAA-covered data path exists — no
accounts, no persistence, no identifying data, no logged content. That design
intent is recorded in `CLAUDE.md` and is unchanged. What the ADR should not
have done is convert that intent into a legal conclusion. Whether it holds is a
question for counsel, and being outside HIPAA would not end the analysis: the
**FTC Health Breach Notification Rule** reaches consumer health applications
that are *not* HIPAA-covered, which is the position this product would be in.

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
