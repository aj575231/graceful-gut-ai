# Graceful Gut AI — IAM Deployment Policy Syntax Hotfix

**Date:** 2026-07-27
**Branch:** `fix/iam-policy-syntax`
**Commit:** `bbb04de`
**Nothing was deployed. No AWS resource was created, modified, or deleted.**

A narrow hotfix to the tracked reference copy of the dev-role IAM policy,
`infrastructure/claude-dev-deployment-policy.json`.

---

## The defect

The file carried a 23-line top-level `_comment` array holding explanatory prose.
`_comment` is not part of the IAM policy language, and IAM rejects unknown
top-level properties, so the document could not be handed to
`aws iam put-role-policy` / `create-policy` as written — the commentary had to be
hand-stripped at apply time. That is a silent trap: the file reads as
apply-ready, and the failure only surfaces under administrator credentials, at
the moment someone is trying to change permissions.

An identity policy has exactly two legal top-level elements, `Version` and
`Statement`. (`Id` is legal in a *resource* policy, not here.)

---

## What changed

| File | Change |
| --- | --- |
| `infrastructure/claude-dev-deployment-policy.json` | −23 lines, **deletion-only** — `_comment` removed |
| `infrastructure/README.md` | new, +106 — the explanatory text, relocated |
| `backend/tests/test_infrastructure_policy.py` | new, +158 — 13 tests |
| `CLAUDE.md` | +15 — records the constraint, points at the README |

Totals: 4 files changed, 279 insertions, 23 deletions.

### The policy diff is deletion-only

`git diff` on the JSON shows **no added lines**. `Version` and `Statement` are
therefore byte-identical to the previous copy, which preserves both invariants
that matter:

- The four administrator-only actions remain **absent**: `lambda:AddPermission`,
  `lambda:RemovePermission`, `lambda:CreateFunctionUrlConfig`,
  `lambda:UpdateFunctionUrlConfig`.
- The `<AWS_ACCOUNT_ID>` placeholder is preserved in all three resource-scoped
  ARNs (lambda function, log group, execution role).

### Explanatory text relocated

The prose removed from the JSON now lives in `infrastructure/README.md`, which
documents: the placeholder convention; why Function URL administration is
administrator-only and which four actions that withholds; that read-only
inspection (`lambda:GetFunctionUrlConfig`, `lambda:GetPolicy`) is deliberately
retained so verification needs no admin credentials; and the two-statement
requirement for the Function URL resource policy, including the caching
behaviour that misled an earlier audit into removing the second statement.

`CLAUDE.md` gains a short subsection under "Dev-role permissions" stating that
the tracked file is pure policy language and pointing at the README and the
test module.

---

## Tests added

`backend/tests/test_infrastructure_policy.py` — 13 tests, all against the
tracked file on disk:

| Requirement | Test |
| --- | --- |
| Parses as JSON | `test_policy_parses_as_json` |
| Top-level keys are exactly `Version` and `Statement` | `test_top_level_keys_are_exactly_version_and_statement` |
| Forbidden actions absent | `test_function_url_administration_stays_absent`, parametrized — one case per action |
| No wildcard smuggling | `test_no_wildcard_lambda_action_smuggles_in_url_administration` — rejects `*` and any `lambda:…*` |
| Placeholders render into a valid live policy | `test_rendering_produces_a_valid_live_policy` |
| No unresolved placeholders after rendering | `test_no_unresolved_placeholders_remain_after_rendering` |
| Supporting shape checks | `test_policy_version_is_the_current_policy_language`, `test_every_statement_is_well_formed`, `test_deployment_and_inspection_permissions_are_retained`, `test_placeholders_are_all_ones_the_renderer_knows` |

The wildcard test is not in the original requirement list. It was added because
asserting the four action *strings* are absent is defeated by a single
`lambda:*` entry, which would grant all four without naming any of them.

Rendering uses synthetic values only — a placeholder account ID of all zeros.
No real account ID appears in the test, the policy, or this report.

### Mutation check

The suite was verified to actually catch a regression rather than passing
vacuously. Reintroducing `_comment` and adding `lambda:AddPermission` to the
policy failed 3 tests:

```
FAILED test_top_level_keys_are_exactly_version_and_statement
FAILED test_function_url_administration_stays_absent[lambda:AddPermission]
FAILED test_rendering_produces_a_valid_live_policy
3 failed, 10 passed
```

The file was then restored and the module returned to 13 passed.

---

## Verification results

Run on the local Python 3.12 venv. Per CLAUDE.md, CI is the authority for the
deployed 3.13 runtime.

```
$ python -m pytest -q
45 passed, 2 warnings in 0.59s

$ ruff check backend/
All checks passed!

$ ruff format --check backend/
9 files already formatted

$ git diff --check
(no output, exit 0)
```

The two warnings are pre-existing dependency deprecations (Starlette's
`TestClient` httpx notice and a Mangum event-loop notice), unrelated to this
change.

---

## Confirmation: no AWS resources were modified

**No `aws` CLI command was executed in this session.** No Lambda code was
deployed, no function configuration was changed, no IAM policy was applied, and
no Function URL or resource-policy statement was touched.

This is consistent with the standing access model: the dev role cannot modify
IAM at all, and Function URL administration is administrator-only. The file in
this repository is a reference copy — applying the corrected document still
requires administrator credentials, run outside this host. **Until an
administrator applies it, the live attached policy is unchanged**, and the
correction exists only in Git.

---

## Follow-ups, not done here

1. **Region is not a placeholder.** The hotfix brief referred to "account and
   region placeholders", but the file only ever had `<AWS_ACCOUNT_ID>`; the
   region is written literally as `us-east-2` in the lambda and logs ARNs. It was
   left as-is, because parameterizing it would have changed `Statement` content
   beyond the scope of this hotfix and could break whatever external apply step
   consumes the file. The test renderer already accepts an `AWS_REGION`
   placeholder, so introducing one later is a two-line change.

2. **`infrastructure/lambda-url-resource-policy.json` has the same defect** — a
   ~60-line top-level `_comment`. It is out of scope for this hotfix and was not
   modified. Its explanatory text is already mirrored in the new
   `infrastructure/README.md`, so stripping the block is a clean follow-up
   commit. Note that file's top-level `Id` **is** valid in a resource policy and
   should be kept.

3. **The live attached policy remains unverified against this copy.** The dev
   role cannot read IAM, so whether the deployed role's inline policy matches
   this file is unknown from here and needs an administrator to confirm. The
   execution role's own attached policies likewise remain unaudited.
