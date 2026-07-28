# ADR: Phase 1E — public API Gateway and abuse-protection architecture

**Status:** Proposed — awaiting owner approval
**Date:** 2026-07-28
**Branch:** `phase1e-api-gateway-design`
**Scope:** design, documentation, and test planning only. No AWS resource was
created, modified, or read for this document. No Lambda code was deployed. No
IAM was changed. Secrets Manager was not accessed. The API key was not
requested. Public free-text input is **not** enabled by this ADR.

Placeholders are used throughout for values that must not be committed:
`<AWS_ACCOUNT_ID>`, `<API_ID>`, `<SQUARESPACE_PRODUCTION_ORIGIN>`,
`<WEB_ACL_NAME>`. The region is written literally as `us-east-2`, matching the
convention in `infrastructure/README.md`.

---

## Verified starting state

Taken as given for this design:

- Phase 1D deployed successfully.
- The function runs `APP_ENV=production`.
- The shared secret is retrieved from AWS Secrets Manager at request time.
- `GG_API_KEY` is absent from the Lambda environment.
- The Claude EC2 role cannot retrieve the secret.
- `/health` is public.
- Protected routes require `X-GG-Key` **temporarily**.
- The direct Function URL is still active — and is **not** the final public
  endpoint. Retiring it is part of this plan (§9).
- Public Squarespace free-text input remains prohibited.
- No PHI, identifying information, transcripts, or message bodies may be stored
  or logged.

---

## 1. Architecture decision record

### The constraint that drives everything

Squarespace is a **public browser client**. Every byte it receives is readable
by every visitor through page source, dev tools, and network traces. Therefore
no API key, shared secret, AWS credential, signing secret, or privileged token
may be embedded in JavaScript, HTML, iframe configuration, URLs, browser
storage, or downloadable files.

This is not a preference about where to put a secret. It means **the public
beta has no client authentication at all**, and the design must be honest about
that rather than shipping a token and calling it security.

### Authentication is not an abuse control

These are different problems and conflating them is the main way designs like
this go wrong.

| | Authentication | Abuse control |
| --- | --- | --- |
| Question answered | *Who is this caller?* | *Is this traffic acceptable?* |
| Requires | a secret the caller can keep | nothing from the caller |
| Possible in a public browser? | **No** | **Yes** |
| Examples | API key, JWT, SigV4, session cookie | WAF, rate limits, size caps, concurrency ceiling, budgets |
| Failure mode | impersonation | cost and availability damage |

A public browser client cannot keep a secret, so it cannot be authenticated.
What it *can* be is constrained. Phase 1E therefore invests entirely in abuse
controls and deliberately ships **no** authentication on the public route.

`X-GG-Key` does not survive this transition. It is a single static shared
secret with no per-caller identity, no revocation, and no rate limiting. It
stays for internal and machine callers during migration and is removed from the
public path (§9).

**CORS is not a security control.** It is enforced by browsers only. `curl`,
scripts, and every non-browser client ignore it entirely. CORS stops *other
websites* from using a visitor's browser as a proxy to our API; it does nothing
against direct calls. Treating it as protection is a category error.

### Option A — Regional REST API (API Gateway v1)

| Aspect | Assessment |
| --- | --- |
| WAF | **Attaches directly to the API stage.** No extra infrastructure. |
| Request validation | **Native.** JSON Schema models reject oversized/malformed bodies *before* Lambda runs. |
| Throttling | Stage-level and per-method; usage plans for keyed clients. |
| Usage plans / API keys | Available — for **machine clients only**, never the browser. |
| Authorizers | Lambda authorizer (TOKEN/REQUEST) or Cognito user pool. Not needed for an anonymous beta. |
| Cost | ~$3.50 per million requests. |
| Integration timeout | 29 s default. Our Lambda timeout is 15 s, comfortably inside. |

The request-validation capability matters more than it first appears. A body
rejected at the edge costs one API Gateway request and **zero** Lambda
invocations and **zero** model spend. That is the cheapest possible place to
enforce the size and length caps in §3.

### Option B — HTTP API (API Gateway v2)

| Aspect | Assessment |
| --- | --- |
| WAF | **Not supported directly.** This is the decisive gap. |
| Request validation | **None.** Every malformed or oversized body reaches Lambda. |
| Throttling | Stage-level and route-level. |
| Authorizers | Native JWT authorizer; Lambda authorizer. |
| Cost | ~$1.00 per million requests. |

**Additional architecture required for WAF-level protection:** an Amazon
CloudFront distribution in front of the HTTP API, with the Web ACL associated
to the distribution (`CLOUDFRONT` scope) rather than to the API. That means:

- another distribution to configure, secure, and pay for;
- a second TLS termination point and caching layer we do not otherwise want;
- origin-cloaking work, because the HTTP API endpoint stays publicly reachable
  and would bypass CloudFront — and therefore bypass WAF — unless a shared
  secret header or similar is enforced at the origin (an origin-side secret is
  fine; it never reaches the browser);
- WAF rules written against CloudFront-scope request shapes;
- a longer change-propagation cycle for every WAF adjustment.

That is a substantial amount of infrastructure whose only purpose is to host a
control Option A gets by attaching a Web ACL to a stage. The per-million cost
saving is immaterial next to model spend.

### Option C — simpler secure alternative, no secret in Squarespace

The question worth asking: can we satisfy the requirements *without* API
Gateway at all?

**C1. Function URL + `AuthType: NONE` + application-side controls only.**
Rejected. This is essentially today's state. It offers no WAF, no request
validation, no managed throttling, no usage plans, and no way to rate-limit
before code runs. `CLAUDE.md` already names API Gateway as a release gate.

**C2. Function URL behind CloudFront + WAF.** Technically workable and
cheaper, but inherits every drawback of Option B — a distribution existing only
to host WAF, plus origin cloaking to stop bypass — while *also* giving up
request validation. Strictly worse than Option A.

**C3. Static-only educational content, no API.** Publish the educational
material as Squarespace pages with no free-text endpoint. This genuinely
satisfies every constraint with near-zero attack surface and near-zero cost. It
is the right answer if the conversational endpoint is not yet worth its risk
budget — and it is worth stating plainly as the alternative to launching. It is
not a way to *ship* Phase 2, only a way to defer it.

**C4. Server-side origin proxy on Squarespace.** Not available; Squarespace
does not offer server-side code execution suitable for holding a secret.

None of C1–C4 beats Option A on the stated requirements while still shipping a
conversational endpoint.

### Recommendation

> **Adopt Option A: a Regional REST API with an AWS WAF Web ACL attached to the
> stage, serving an anonymous public beta with no client authentication and no
> user accounts.**

Primary reasons:

1. **WAF attaches natively to the stage.** Option B requires a CloudFront
   distribution whose sole job is hosting the Web ACL, plus origin cloaking to
   prevent bypass. That is real, permanent complexity bought for nothing.
2. **Native request validation rejects abuse before Lambda or the model runs.**
   Size caps, length caps, and content-type enforcement at the edge are the
   single most effective denial-of-wallet control available, and Option B has
   none.
3. **Honest security posture.** A public browser client cannot hold a secret,
   so the design provides no authentication and says so, rather than shipping a
   client-visible token and describing it as one.
4. **Cost difference is immaterial.** ~$2.50 per million requests separates the
   options. Model spend dominates the bill by orders of magnitude, and §12's
   controls target that.

### Do users need accounts initially?

**Recommendation: no accounts for the public beta.** *(Owner decision — §15.)*

Accounts would require collecting an email address, which is identifying
information. Account-linked conversation history is precisely the
account-linked symptom history that `CLAUDE.md` prohibits in V1, and it would
turn a system explicitly designed to be outside HIPAA's scope into one holding
a health-data path. Accounts also add password reset, session management,
credential storage, and breach exposure — a large surface added to *reduce*
abuse, when abuse is better handled by controls that need no identity at all.

Accounts would also not solve the problem they appear to solve: anyone can
create one, so an account is a speed bump for automated abuse, not a barrier.

### How anonymous requests are protected

Without pretending anything client-visible is secret, defence is layered so
that no single control is load-bearing:

| Layer | Control | Runs before Lambda? | Bounds cost? |
| --- | --- | --- | --- |
| 1 | WAF managed rules, IP reputation, rate-based rules | Yes | Partly |
| 2 | API Gateway stage and per-route throttling | Yes | Partly |
| 3 | Request validation — schema, size, length, content type | Yes | Partly |
| 4 | Application-side validation and boundary enforcement | No | Partly |
| 5 | Lambda reserved concurrency | — | **Yes, hard** |
| 6 | Per-request model token caps and timeout | No | Yes, per request |
| 7 | Budgets, alarms, kill switch | — | Yes, after the fact |

If a client-visible challenge token is ever introduced (WAF CAPTCHA or
Challenge, §2), it is documented as an **abuse control that raises the cost of
automation**, never as authentication. It is visible to the user's browser and
therefore visible to an attacker.

---

## 2. AWS WAF plan

WAF is deployed **count-first**. Every rule starts in `Count` mode, sampled
traffic is reviewed, and rules move to `Block` only once they demonstrably do
not fire on legitimate traffic. Blocking a user describing their symptoms is a
product failure, not a security win.

### Rule groups and rollout

| # | Rule | Initial | Target | Notes |
| --- | --- | --- | --- | --- |
| 1 | `AWSManagedRulesAmazonIpReputationList` | Count | **Block** | Lowest false-positive risk. First to promote. |
| 2 | `AWSManagedRulesKnownBadInputsRuleSet` | Count | **Block** | Targets exploit payloads, not prose. Safe to promote early. |
| 3 | `AWSManagedRulesCommonRuleSet` | Count | Block **with exclusions** | Highest false-positive risk on health prose. See below. |
| 4 | `AWSManagedRulesSQLiRuleSet` | Count | Block with exclusions | Apostrophes and SQL keywords occur in ordinary English. |
| 5 | Rate-based rule, per source IP | Count | **Block** | See §3 for values. |
| 6 | Request-method restriction | **Block** immediately | Block | Allow only `GET`, `POST`, `OPTIONS`. Deny the rest. |
| 7 | `AWSManagedRulesAnonymousIpList` | Count | **Count only** | See below — deliberately not promoted. |
| 8 | CAPTCHA / Challenge on the chat route | Not deployed | Conditional | Only if abuse is observed. See below. |
| 9 | Geographic restriction | Not deployed | Conditional | Not justified today. See below. |

### Exclusions needed for legitimate health-language input

This is the part most likely to break the product if it is skipped. The Common
Rule Set and SQLi rules inspect the request body with heuristics tuned for web
application payloads, and ordinary descriptions of gut symptoms trip them:

- **Apostrophes.** `Crohn's disease` contains the exact character SQLi
  heuristics weight most heavily. So does `it's been worse`, and most possessive
  or contracted English.
- **SQL keywords that are also English words.** A user writing *"a sudden
  **drop** in appetite"*, *"I **select** foods carefully"*, *"pain near the
  **union** of the stomach and oesophagus"*, or *"**alter**nating constipation
  and diarrhoea"* is writing prose, not an injection.
- **Angle brackets and comparison language.** *"less than <2 weeks"* can read
  as markup to XSS heuristics.
- **Long free text.** `SizeRestrictions_BODY` in the Common Rule Set fires on
  bodies above its threshold; our caps (§3) keep us far below it, but the rule
  must still be verified in count mode.

Plan: run rules 3 and 4 in count mode against a corpus of realistic
gut-health phrasings, record which rule IDs fire, and exclude those specific
rule IDs — never disable a whole rule group. Application-side input handling,
not WAF, is the correct defence against prompt manipulation (§13).

**WAF body inspection limit:** for regional resources WAF inspects roughly the
first 8 KB of a request body by default. Our maximum body (§3) is well under
that, so no oversize-handling configuration is required — but the caps must be
enforced by request validation regardless, because WAF's limit is not a size
control.

### Anonymous IP list — deliberately count-only

Blocking VPN, proxy, and Tor traffic on a **gut-health** service punishes
exactly the users most likely to want privacy while researching an embarrassing
or sensitive symptom. That is a real product harm for a modest abuse gain. Keep
the rule in count mode for visibility and do not promote it without an explicit
owner decision.

### Geographic restriction — not justified today

`CLAUDE.md` is explicit: **educational content is not geographically limited;
clinical services are.** The endpoint under design is the educational one, so
geo-restriction would contradict a stated product boundary. It is reasonable to
revisit *only* if telemetry shows concentrated abuse from regions with no
plausible user base, and even then a rate-based rule is the better instrument.

### CAPTCHA / challenge — conditional, not at launch

WAF `Challenge` (silent, browser-based) is preferable to `CAPTCHA`
(interactive) for a health product, where accessibility matters and an
interactive puzzle in front of someone seeking urgent guidance is harmful.
Deploy neither at launch. If automated abuse appears, apply `Challenge` to the
chat route only, never to `/health`, and never in a path that could delay
emergency routing.

### Logging note

WAF logging and sampled requests capture the client IP address and portions of
the request, which collides with the no-PHI and no-identifying-information
boundaries. See §7 and the open decision in §15.

---

## 3. API Gateway throttling and request limits

### Throttle values

Conservative by design. These are starting points to be raised on evidence, not
targets to be met.

| Scope | Dev | Public beta | Rationale |
| --- | --- | --- | --- |
| Stage rate (steady) | 5 rps | 10 rps | Whole API ceiling. |
| Stage burst | 10 | 20 | Absorbs page-load spikes. |
| `GET /health` | 20 rps / burst 40 | 20 rps / burst 40 | Cheap, no model spend, needed by uptime probes. |
| `GET /version` | 2 rps / burst 5 | 2 rps / burst 5 | Remains gated (§4). |
| `POST /v1/education/ask` | **1 rps / burst 2** | **2 rps / burst 5** | The only route that costs model spend. Tightest limit. |
| WAF rate-based, per IP, whole API | 300 / 5 min | 300 / 5 min | Catches crude flooding. |
| WAF rate-based, per IP, chat route | 40 / 5 min | 60 / 5 min | ~12 messages/minute sustained — well above human use. |

WAF rate-based rules evaluate over a rolling five-minute window and act with
some lag; they are a blunt instrument against sustained flooding, not a precise
per-user quota.

### Request size and length caps

| Limit | Value | Enforced where |
| --- | --- | --- |
| Maximum request body | **4 KB** | API Gateway request validation **and** application |
| Maximum user message length | **2,000 characters** | JSON Schema `maxLength` **and** application |
| Maximum fields per request | schema-fixed, `additionalProperties: false` | JSON Schema |
| Required content type | `application/json` only | API Gateway and application |
| Maximum response tokens | see §12 | Application |
| Per-request timeout | 15 s Lambda / 29 s API Gateway ceiling | Both |

Enforcing in both places is deliberate. The edge check is the cheap one; the
application check is the one that still holds if the endpoint is ever reached
by another path. Neither is redundant.

### Response behaviour

| Condition | Status | Body |
| --- | --- | --- |
| Throttled | `429` with `Retry-After` | Generic. No quota internals. |
| Body too large | `413` | Generic. |
| Message too long | `400` | States the character limit only. |
| Wrong content type | `415` | Generic. |
| Malformed JSON | `400` | Generic. No parser detail. |
| Secret unresolvable (internal routes) | `503` | Opaque, as today. |
| WAF block | `403` | WAF default. Never echoes the matched rule. |

No error response reveals which rule fired, which limit was hit, or anything
about internal structure.

### These are best-effort, not cost ceilings

Stated plainly because it is the most consequential caveat in this document:

> **API Gateway throttles and usage-plan quotas are best-effort. They are
> applied across a distributed system, they are approximate at the boundary,
> and they do not guarantee a maximum bill.** WAF rate-based rules act with
> evaluation lag and are also approximate.

The only controls that place a **hard** bound on spend are Lambda reserved
concurrency (§12), the per-request token cap, and the kill switch. Budgets and
alarms are detective, not preventive — they tell you after money is spent.

---

## 4. API design — minimum public surface

| Route | Method | Public in beta? | Auth | Notes |
| --- | --- | --- | --- | --- |
| `/health` | GET | **Yes** | None | Already public. Minimal body. Never resolves a secret. |
| `/version` | GET | **No — keep gated** | Internal | Recommended below. |
| `/v1/education/ask` | POST | **Yes, when Phase 2 ships** | None (anonymous) | The single free-text route. **Not enabled by this ADR.** |
| `OPTIONS` on public routes | OPTIONS | Yes | None | CORS preflight only (§8). |

**Not exposed, at any stage:** `/docs`, `/redoc`, `/openapi.json`, any
administrative endpoint, and any clinical scheduling endpoint. `CLAUDE.md`
requires clinical scheduling to remain a separate system; it must not appear in
this API's surface at all.

### Why `/version` should stay gated

It offers no value to a public visitor and leaks build and deployment detail
that only helps someone fingerprinting the service. Keeping it gated costs
nothing. Its current role — proving the secret resolved, because a `401` there
distinguishes a healthy deployment from a `503` — is an internal diagnostic and
works better when the route is not public.

### Why `/v1/education/ask` rather than `/v1/chat`

The route name is user-visible and shapes expectations. `chat` implies an
open-ended assistant; `education/ask` states the boundary in the URL itself.
Naming is a small thing that makes the product's limits self-describing.

**This route is designed here and not implemented.** Free-text input stays
prohibited until every item in the `CLAUDE.md` release gate is complete.

---

## 5. Health-information boundaries in the request path

The boundaries in `CLAUDE.md` are enforced **in code on every response**, not
only in prompt text. A prompt is guidance; a response filter is a control.

- Educational and routing-only.
- **No diagnosis** — no naming, ruling out, or suggesting a condition for an
  individual.
- **No prescribing** — no medication, supplement, treatment, or dosage
  recommendation, including generic categories and "many people find X helpful".
- **No treatment plan.**
- **No lab interpretation** — no reading, scoring, or explaining a user's own
  labs, imaging, or test values.
- **No clinician-patient relationship** is created.
- **Emergency and red-flag routing stays prominent.** Urgent symptoms are
  directed to live care immediately and are never triaged by the product. This
  path must not be gated behind a challenge, a rate limit response, or a
  degraded-mode fallback.
- **Clinical services are limited to eligible Indiana patients**; educational
  content is not geographically limited. Wording is an owner decision (§15).

### User-facing input warning

Before the input field and in the placeholder, users are warned not to submit
names, dates of birth, addresses, phone numbers, email addresses, medical
record numbers, insurance information, photographs, or other identifying
details.

The warning is necessary but **not sufficient** — users will paste identifying
detail anyway. The system is therefore designed so that doing so is not
harmful: nothing is persisted (below), and nothing containing message content
is logged (§7).

### No persistence by default

Requests and responses are **not persisted**. No transcript store, no
conversation history, no analytics payloads containing message text, no
third-party call that would carry content into another system's storage.

Conversation history — even in-session — is an open decision (§15). Any
multi-turn context would have to live client-side or in a short-lived
server-side cache, and either choice needs an explicit decision because it
changes the data-path analysis materially.

---

## 6. *(merged into §5 and §7 — no separate section)*

---

## 7. Logging and observability

### Fields permitted

| Field | Example | Why it is safe |
| --- | --- | --- |
| Generated request ID | `01J...` (server-generated) | Correlates logs without identifying anyone. |
| Timestamp | ISO 8601 UTC | No user data. |
| Route | `POST /v1/education/ask` | Fixed set of values. |
| Status | `200`, `429` | No user data. |
| Latency | `142 ms` | No user data. |
| Error category | `validation_failed`, `secret_unavailable` | Enumerated. Never free text. |
| Validation result | `body_too_large` | Enumerated. Never echoes the body. |

### Fields forbidden

- request or response bodies, in whole or in part;
- headers containing credentials, including `X-GG-Key` and `Authorization`;
- query strings containing user data;
- **IP addresses** unless required and explicitly approved;
- **user agent** unless required and explicitly approved;
- secret identifiers, API keys, authorization tokens;
- any health text;
- any identifying information.

Error logs record a short reason and an exception **type** only — never a
value, never a stack trace containing request data. This matches what
`backend/app/secrets.py` already does.

### The conflict that must be decided

Two AWS-side log sources capture client IP **by default**, which the list above
forbids without approval:

| Source | What it captures | Mitigation |
| --- | --- | --- |
| API Gateway access logs | `$context.identity.sourceIp` and more | The log format is fully configurable — omit the IP field. |
| WAF logs | Client IP, headers, URI, and request fragments | Field redaction is configurable; IP cannot be removed from WAF logs. |
| WAF sampled requests | IP and partial request data, retained ~3 hours | Cannot be disabled while sampling is on. |

So: API Gateway access logs **can** be made IP-free by choosing the format.
WAF logging **cannot**. Enabling WAF logging therefore means accepting IP
retention, and that is an owner decision (§15), not a default to drift into.

Rate-based rules still function with WAF logging disabled — WAF acts on IP
internally either way. The decision is only about **retention**, not about
whether abuse controls work.

Recommended default until decided: API Gateway access logs with an IP-free
format; WAF logging **off**; sampled requests reviewed in the console during
the count-mode rollout and not exported.

Retention: CloudWatch log retention is currently 14 days. Recommend 14 days for
application logs and 30 days maximum for anything security-relevant. Owner
decision (§15).

---

## 8. CORS

### Configuration

| Setting | Value |
| --- | --- |
| Allowed origins | `<SQUARESPACE_PRODUCTION_ORIGIN>` plus separately approved development origins |
| Wildcard `*` | **Never** on protected routes, and never with credentials |
| `allow_credentials` | **`false`** — already the case in `backend/app/main.py` |
| Allowed methods | `GET`, `POST`, `OPTIONS` — nothing else |
| Allowed headers | `Content-Type` only on public routes |
| Exposed headers | none |
| Preflight max-age | 600 s |

`X-GG-Key` must **not** appear in the allowed-headers list for public routes.
Allowing it would invite a browser client to send it, which is exactly the
outcome every part of this design exists to prevent.

The exact production domain is **not committed**. It is written as
`<SQUARESPACE_PRODUCTION_ORIGIN>` in Git and substituted at apply time, the same
convention `infrastructure/README.md` records for `<AWS_ACCOUNT_ID>`. The exact
domain is an owner decision (§15).

### Where CORS is enforced

Enforce it in **one** place: the application, which already has
`CORSMiddleware` configured and tested. Configuring CORS in both API Gateway
and the application creates two sources of truth that drift, and the failure
mode — a preflight answered by the gateway with a policy the application does
not share — is confusing to diagnose. API Gateway passes `OPTIONS` through to
the Lambda proxy integration, so the application answers preflight directly.

### Preflight behaviour

A compliant `OPTIONS` request from an allowed origin returns `204` with the
allowed methods, allowed headers, and max-age. From a disallowed origin it
returns without the `Access-Control-Allow-Origin` header, so the browser blocks
the follow-up request. Tests in §13.

### Restating the limit

CORS restricts **browsers**. It is not an access control. Every non-browser
client ignores it. It appears in this design to stop other websites from
driving our API through a visitor's browser — nothing more.

---

## 9. Direct Function URL retirement

The Function URL is a development entry point, **not** the final public
endpoint. It is retired in stages, and at no point is the service left with
both entry points publicly usable and unmonitored.

| Stage | Action | Who | Reversible? |
| --- | --- | --- | --- |
| 1 | Create the REST API, stage, and Web ACL. Not announced, not linked from any site. | Administrator | Yes — delete |
| 2 | Grant API Gateway permission to invoke the function, scoped by `SourceArn` to `<API_ID>` | Administrator | Yes — remove permission |
| 3 | Exercise every route through API Gateway while `X-GG-Key` is still enforced | Claude / verification | n/a |
| 4 | Verify WAF is attached, rules are in count mode, and sampled traffic looks correct | Verification | n/a |
| 5 | Verify throttling by driving the documented limits and observing `429` | Verification | n/a |
| 6 | Verify CORS and preflight from the production origin and a disallowed origin | Verification | n/a |
| 7 | Run the anonymous and authenticated security tests in §13 | Verification | n/a |
| 8 | Repoint the Squarespace site to the API Gateway origin | Administrator | Yes — repoint back |
| 9 | Remove the two public Function URL resource-policy statements, **or** delete the Function URL config | **Administrator only** | Yes — see rollback |
| 10 | Prove direct invocation no longer works: the Function URL returns `403` on every route | Verification | n/a |

### Verification detail that has burned this repo before

`CLAUDE.md` records it, and it applies directly to stage 10: after removing a
resource-policy statement the URL keeps working for roughly 10–20 seconds
because of policy caching. A single immediate `curl` returning `200` proves
nothing. **Verify with `aws lambda get-policy`**, then confirm with `curl`
after the cache expires. A previous audit drew the wrong conclusion from
exactly this and took the dev URL down.

### Rollback without reopening broadly

Rollback re-applies **the two specific statements already documented** in
`infrastructure/lambda-url-resource-policy.json` — `GracefulGutPublicInvokeUrl`
(conditioned on function URL auth type `NONE`) and
`GracefulGutPublicInvokeFunction` (conditioned on `lambda:InvokedViaFunctionUrl`).

Both are required; the URL returns a steady `403` on every route if either is
missing. Rollback never means granting the unconditioned, broader
`lambda:InvokeFunction`, and never means widening the principal. The
`--invoked-via-function-url` flag **is** supported by the AWS CLI and must
always be passed.

Rollback is an **administrator** action. This host holds none of
`lambda:AddPermission`, `lambda:RemovePermission`,
`lambda:CreateFunctionUrlConfig`, or `lambda:UpdateFunctionUrlConfig`, and must
not be granted them.

Prefer **removing the statements** over **deleting the Function URL config**:
statements are re-addable from a tracked file in seconds, whereas recreating a
URL config issues a new hostname.

---

## 10. IAM design — least-privilege reference policies

Five separate policies, each scoped to one job. Reference documents only —
**nothing is applied by this ADR.** All identifiers are placeholdered.

| Policy | Principal | Purpose | Applied by |
| --- | --- | --- | --- |
| `apigateway-invoke-lambda.json` | `apigateway.amazonaws.com` | Lambda **resource** policy allowing only this API to invoke the function, scoped by `SourceArn` | Administrator |
| `deployment-automation-policy.json` | deployment role | Update function code/config; create a deployment of an existing API. **No** create/delete of APIs, **no** WAF, **no** IAM, **no** Secrets Manager | Administrator |
| `waf-administration-policy.json` | administrator | Manage the Web ACL and its association | Administrator |
| `log-access-policy.json` | dev/observability role | Read the specific log groups; set retention | Administrator |
| `administrator-only-actions.md` | — | The enumerated list of actions no automation role may hold | — |

### Principles carried forward

- **The dev role gets no Secrets Manager permission, ever.** Reading the secret
  is the execution role's job. `backend/tests/test_infrastructure_policy.py`
  fails if any `secretsmanager:` action appears in the dev policy.
- **Function URL administration stays administrator-only.** The same four
  actions remain withheld. Add `wafv2:*` and API Gateway create/delete to that
  list — a role that can deploy code must not also be able to remove the
  protections in front of it.
- **`iam:PassRole` stays scoped to a single role**, so no automation can attach
  a more privileged execution role.
- **Policy files contain only `Version` and `Statement`.** IAM rejects unknown
  top-level properties; a `_comment` block makes a document unapplyable.
  Explanation goes in `infrastructure/README.md`.

### Still unaudited

`GracefulGutAI-LambdaExecutionRole`'s attached policies are not readable from
the dev role and remain unaudited. Review with administrator credentials before
the public beta.

---

## 11. Infrastructure as code

**Recommendation: AWS SAM.**

| Option | Assessment |
| --- | --- |
| **AWS SAM** | **Recommended.** Models Lambda + REST API + stage + throttling in a few dozen lines. Deploys through CloudFormation, so state lives in AWS with no separate store. `AWS::WAFv2::WebACL` and `AWS::WAFv2::WebACLAssociation` sit in the same template. Consumes a prebuilt ZIP directly, so `scripts/build-lambda.sh` and its reproducible-hash property survive unchanged. |
| Raw CloudFormation | Same engine, more boilerplate for the API. SAM transforms to it anyway. |
| AWS CDK | Powerful, but adds Node/Python tooling, a bootstrap stack, and synthesised-template indirection for one function and one API. |
| Terraform | Excellent tool, wrong fit here: a state file to store, lock, and secure, plus another credential path, for a single-function deployment. |
| Continue with shell scripts | Does not scale to API Gateway, stages, WAF, and their associations. |

Adopting SAM means the deployment story becomes: build the ZIP reproducibly as
today, then `sam deploy` a template that references it. The existing validation
in `scripts/deploy-lambda.sh` — `APP_ENV`, `GG_API_SECRET_ID`, no stale
`GG_API_KEY` — should be preserved as a pre-deploy check rather than discarded.

**No infrastructure is created by this ADR.**

---

## 12. Cost and denial-of-wallet controls

An anonymous endpoint that calls a paid model is a denial-of-wallet target. The
attacker's goal is not downtime; it is the bill.

| # | Control | Type | Bounds spend? |
| --- | --- | --- | --- |
| 1 | **Lambda reserved concurrency** | Preventive | **Hard ceiling.** The single most important control. Currently 2; recommend 5–10 for beta. |
| 2 | Maximum model tokens per request (input **and** output) | Preventive | Yes, per request |
| 3 | Per-request timeout — 15 s Lambda | Preventive | Yes, per request |
| 4 | API Gateway throttling | Preventive | Best-effort only |
| 5 | WAF rate-based rules | Preventive | Best-effort only |
| 6 | Request validation — 4 KB body, 2,000 characters | Preventive | Yes — caps input tokens |
| 7 | Daily request cap | Preventive | Needs a counter store — see below |
| 8 | AWS Budgets with alerts at 50 / 80 / 100 % | **Detective** | No — reports after the fact |
| 9 | CloudWatch alarms on invocation count, error rate, throttle count | Detective | No |
| 10 | Model-cost reporting — per-day spend, tagged `Project=GracefulGutAI` | Detective | No |
| 11 | **Emergency kill switch** | Corrective | **Yes, immediate** |
| 12 | Fail-closed behaviour | Preventive | Yes |

### Maximum spend per request

Bounded by: max input tokens (from the 2,000-character cap, roughly 500 tokens
plus system prompt) × input price, plus max output tokens (a hard
`max_tokens`) × output price. Multiply by reserved concurrency and requests per
second to derive a worst-case hourly figure — that number, not the throttle
values, is the honest ceiling and should be computed before launch.

### The daily cap needs a decision

A true daily cap requires shared state — DynamoDB or similar — because Lambda
containers do not share counters. That adds a component, and any per-IP daily
counter would store IP addresses, colliding with §7. Options: a global
(non-per-user) daily counter that stores no identifiers; rely on budget alarms
plus the kill switch; or accept per-IP storage with an explicit decision.
Recommend the global counter. Owner decision (§15).

### Emergency kill switch

Fastest first:

1. **Set Lambda reserved concurrency to 0.** Immediate, total, one command,
   fully reversible. The primary switch.
2. Add a WAF `Block`-all rule to the Web ACL. Fast, keeps `/health` reachable
   if scoped by route.
3. Disable or delete the API Gateway stage. Slower to restore.

Reserved concurrency at 0 makes the function return errors rather than serve
requests — that is the intended behaviour of a kill switch, and it fails closed.

### Fail-closed

Every failure path returns an error rather than an open endpoint: unresolvable
secret → `503`, validation failure → `4xx`, throttle → `429`, WAF match →
`403`, kill switch → error. There is no configuration in which a fault produces
an unprotected, unmetered endpoint.

---

## 13. Test plan

Tests marked **static** are implemented on this branch. Tests marked
**planned** are specified here and implemented when the infrastructure exists —
several cannot be written before there is an API to test.

| # | Test | Kind | Asserts |
| --- | --- | --- | --- |
| 1 | Allowed origin accepted | Planned | `Access-Control-Allow-Origin` matches the configured origin exactly |
| 2 | Disallowed origin rejected | Planned | No ACAO header returned |
| 3 | `OPTIONS` preflight | Planned | `204`, correct methods/headers/max-age |
| 4 | Wildcard origin never used | **Static** | No `*` in the origin configuration |
| 5 | Credentials disabled | **Static** | `allow_credentials=False` |
| 6 | Oversized body | Planned | `413`, Lambda not invoked |
| 7 | Excessive message length | Planned | `400`, states the limit only |
| 8 | Invalid content type | Planned | `415` |
| 9 | Malformed JSON | Planned | `400`, no parser detail leaked |
| 10 | Unicode and emoji input | Planned | Handled correctly; length counted in characters |
| 11 | Rate limiting | Planned | `429` with `Retry-After` past the documented rate |
| 12 | WAF count mode | Planned | Legitimate health phrasings produce zero blocks |
| 13 | WAF block mode | Planned | Known bad inputs blocked; health corpus still passes |
| 14 | No client-visible secret | **Static** | No browser-facing file contains `X-GG-Key`, `GG_API_KEY`, or a secret-shaped value |
| 15 | Logging excludes bodies | **Static** | No logging configuration references request/response bodies |
| 16 | Function URL rejected after retirement | Planned | `403` on every route — verified via `get-policy`, then `curl` after cache expiry |
| 17 | Anonymous endpoint behaviour | Planned | Public routes work with no credential; gated routes return `401` |
| 18 | Authenticated behaviour | Planned | Only if accounts are adopted (§15) |
| 19 | Emergency language routing | Planned | Red-flag phrasings produce prominent live-care routing, never triage |
| 20 | Boundary enforcement | Planned | No diagnosis, prescribing, treatment plan, or lab interpretation in any response |
| 21 | Injection and prompt-manipulation resistance | Planned | Instruction-override attempts do not breach the boundaries in §5 |
| 22 | Infrastructure templates carry no real account IDs | **Static** | Placeholders only |
| 23 | Function URL not described as final endpoint | **Static** | Documentation describes it as temporary and names its retirement |
| 24 | Rollback | Planned | Re-applying the two statements restores service; no broader permission granted |

Tests 19–21 are the ones that matter most for a health product and the hardest
to automate well. They need a curated corpus reviewed by AJ and Jenna, not
assertions invented by an engineer or by Claude.

---

## 14. Migration sequence by actor

Every action, separated by who performs it.

### Claude development actions

1. Author the SAM template, WAF rule definitions, and reference IAM policies as
   tracked files with placeholders.
2. Implement request validation, size and length caps, and structured logging
   in application code.
3. Implement boundary enforcement in the request path.
4. Write the tests in §13 that do not require live infrastructure.
5. Update `CLAUDE.md`, `infrastructure/README.md`, and `.env.example`.
6. Prepare verification scripts that make **no** keyed request and never fetch
   a secret.

### Administrator-only AWS actions

1. Create the REST API, stage, and deployment.
2. Create the WAF Web ACL and associate it with the stage.
3. Add the Lambda resource-policy statement for API Gateway, scoped by
   `SourceArn`.
4. Create or update any IAM role or policy.
5. Create the secret and grant the execution role access (already done in 1D).
6. Remove the public Function URL resource-policy statements, or delete the
   Function URL config.
7. Configure AWS Budgets and budget actions.
8. Operate the kill switch.
9. Repoint the Squarespace site.

### Automated deployment actions

1. Build the ZIP reproducibly and record its SHA-256.
2. Validate live configuration — `APP_ENV=production`, `GG_API_SECRET_ID` set,
   no stale `GG_API_KEY`.
3. `sam deploy` against the existing stack.
4. Create an API Gateway deployment for the stage.
5. Smoke test unauthenticated routes only.
6. Record `CodeSha256` against the Git commit.

### Verification actions

1. Confirm WAF is associated and in the expected mode.
2. Drive documented throttle limits and observe `429`.
3. Confirm CORS from the production origin and a disallowed origin.
4. Confirm the boundary and emergency-routing tests pass.
5. Confirm logs contain no bodies, IPs, headers, or health text.
6. Confirm the Function URL returns `403` — via `get-policy` first, then
   `curl` after cache expiry.
7. Confirm no browser-facing file contains a secret.

### Rollback actions

1. Repoint the site to the previous origin.
2. Re-apply the two documented Function URL statements — administrator, scoped,
   never broader.
3. Redeploy the previous `CodeSha256`.
4. Set WAF rules back to count mode if a rule blocks legitimate traffic.
5. Raise throttles if limits prove too tight.
6. Set reserved concurrency to 0 if cost runs away, then diagnose.

---

## 15. Open decisions requiring AJ and Jenna's approval

None of these should be decided by Claude. Each changes the design materially.

| # | Decision | Recommendation | Why it needs an owner |
| --- | --- | --- | --- |
| 1 | **Does the public beta require accounts?** | **No accounts** | Accounts collect identifying data and create the account-linked history V1 prohibits. Reverses a core product boundary. |
| 2 | **Acceptable anonymous usage limit** | 60 chat requests / 5 min / IP; 2 rps steady | Trades user experience against cost exposure. A business call. |
| 3 | **Exact Squarespace production origin** | Placeholder until supplied | Needed for CORS. Must not be committed until approved. |
| 4 | **May IP addresses be retained in WAF or access logs?** | API Gateway logs IP-free; WAF logging **off** | WAF logging cannot omit IP. Retention is a privacy decision, not a technical default. |
| 5 | **Data-retention period** | 14 days application, 30 days security maximum | Privacy posture and any future compliance commitment. |
| 6 | **Emergency-routing language** | Clinician-authored, prominent, never triage | Must be written or approved by a clinician. Highest-risk copy in the product. |
| 7 | **Will any conversation history exist?** | **No history in beta** | Multi-turn context changes the data-path analysis and may create a health-data path. |
| 8 | **Monthly AWS and model budget** | Needed before launch | Sets reserved concurrency, token caps, throttles, and alarm thresholds. Every §12 number depends on it. |
| 9 | **Indiana-only limitations and wording** | Educational unrestricted; clinical Indiana-only | `CLAUDE.md` distinguishes these. The user-facing wording needs owner and clinician sign-off. |
| 10 | Daily-cap mechanism | Global counter storing no identifiers | Adds a component; per-IP alternative would store IPs. |
| 11 | Promote `AnonymousIpList` to block? | **No — count only** | Blocking VPN/Tor users on a gut-health service harms privacy-seeking users. |
| 12 | Reserved concurrency for beta | 5–10 | Directly bounds both availability and worst-case spend. |

---

## Summary

Adopt a **Regional REST API with WAF attached to the stage**, serving an
**anonymous** public beta with **no accounts** and **no client authentication**,
defended by layered abuse controls whose only hard cost ceiling is Lambda
reserved concurrency. Retire the direct Function URL in stages, with rollback
that re-applies two documented statements rather than reopening access broadly.

Nothing in this ADR enables public free-text input. That remains blocked until
the `CLAUDE.md` release gate is fully satisfied and the decisions in §15 are
made.
