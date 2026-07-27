# `infrastructure/` — reference policy documents

These files are **reference copies**, not a live apply path. Nothing in this
repository applies them: this host's role (`GracefulGutAI-ClaudeDevRole`) cannot
modify IAM, and Function URL administration is administrator-only. Applying any
of them requires administrator credentials, run outside this host.

## Placeholder convention

Account IDs are deliberately not stored in this repository. Policy documents use
angle-bracket placeholders that are substituted at apply time:

| Placeholder | Substitute with |
| --- | --- |
| `<AWS_ACCOUNT_ID>` | the real account ID — `aws sts get-caller-identity --query Account --output text` |
| `<AWS_REGION>` | `us-east-2` |

The region is usually **not** a placeholder: `us-east-2` is written literally
into the Lambda and CloudWatch Logs ARNs in `claude-dev-deployment-policy.json`
because the deployment is pinned to that one region (see CLAUDE.md).

`lambda-execution-secrets-policy.json` is the exception — it uses
`<AWS_REGION>`, because a Secrets Manager ARN is the one place where a
copy-paste into the wrong region silently grants access to a *different*
secret than the reader expects. Making the region an explicit substitution step
forces the operator to look at it. `backend/tests/test_infrastructure_policy.py`
accepts both conventions and asserts that this file keeps both placeholders.

A rendered document must contain **no** remaining `<...>` placeholders before it
is applied. The test suite asserts both halves of that: every placeholder in the
tracked file is one the renderer knows, and nothing angle-bracketed survives
rendering.

## `claude-dev-deployment-policy.json`

The identity policy attached to `GracefulGutAI-ClaudeDevRole` — the role this
host deploys with. The tracked file contains **only** IAM policy-language
elements (`Version` and `Statement`), so it can be passed straight to
`aws iam put-role-policy` / `create-policy` without preprocessing. Explanatory
commentary lives here rather than in the JSON, because IAM rejects unknown
top-level properties such as `_comment`.

What the policy grants is tabulated in CLAUDE.md under "Dev-role permissions —
what this host may and may not do". The parts that matter most:

**Function URL administration is administrator-only.** This role deliberately
holds **none** of:

- `lambda:AddPermission`
- `lambda:RemovePermission`
- `lambda:CreateFunctionUrlConfig`
- `lambda:UpdateFunctionUrlConfig`

Those four decide *who can reach the function at all* — the resource policy
grants `Principal: '*'`, and `AuthType: NONE` is what makes the endpoint
anonymous — so a host that can deploy code must not also be able to change them.
Creating a Function URL, or changing its `AuthType`, CORS configuration, or
resource-based policy, requires administrator credentials.
`backend/tests/test_infrastructure_policy.py` fails if any of the four is
reintroduced.

**Inspection is fully retained.** `lambda:GetFunctionUrlConfig` reads the URL,
`AuthType`, and CORS; `lambda:GetPolicy` reads the resource policy back. A
session can verify every one of those settings without administrator
credentials — it just cannot change them. A session that finds the URL returning
403, or the `AuthType` or CORS wrong, should report it and stop, not attempt a
repair.

**No Secrets Manager access.** The role holds no `secretsmanager:` action, and
must not be given one. This host can point the function at a secret —
`GG_API_SECRET_ID` is an identifier, set through
`lambda:UpdateFunctionConfiguration` — but it cannot read the value. That
separation is the whole point of moving the shared secret out of the function's
environment: a session that can deploy code should not also be able to read the
live key. The test suite fails if any `secretsmanager:` action appears here,
including under a wildcard.

`iam:PassRole` is scoped to `GracefulGutAI-LambdaExecutionRole` alone, so this
host cannot attach a more privileged execution role to the function. That
execution role's own attached policies are not readable from the dev role and
remain unaudited — review them separately with administrator credentials.

## `lambda-execution-secrets-policy.json`

The identity policy that lets **`GracefulGutAI-LambdaExecutionRole`** — the
function's own role, not this host's — read the `X-GG-Key` shared secret at
request time. It grants exactly one action:

| Action | Resource |
| --- | --- |
| `secretsmanager:GetSecretValue` | `arn:aws:secretsmanager:<AWS_REGION>:<AWS_ACCOUNT_ID>:secret:graceful-gut-ai/dev/api-key-*` |

No create, update, rotate, delete, list, or describe. No second secret: the
resource is scoped to one name, and `*` in that position would grant every
secret in the account.

The trailing `-*` is **required**, not sloppiness. Secrets Manager appends a
random six-character suffix to a secret's ARN, so a policy naming the bare
`...:secret:graceful-gut-ai/dev/api-key` matches nothing and the function
returns 503 on every gated route.

Applying it requires administrator credentials — this host holds no IAM write
actions:

```bash
aws iam put-role-policy \
  --role-name GracefulGutAI-LambdaExecutionRole \
  --policy-name GracefulGutAI-ReadApiKeySecret \
  --policy-document file://infrastructure/lambda-execution-secrets-policy.json
```

Substitute both placeholders first. The secret itself is created separately,
also by an administrator; the exact commands are in CLAUDE.md under
"Administrator actions for the secret". No secret value belongs in this
repository at any point in that process.

## `lambda-url-resource-policy.json`

The intended resource-based policy for the `graceful-gut-ai-dev-api` Function
URL. **Two** statements are required, and both must be present for the URL to
serve traffic:

1. `GracefulGutPublicInvokeUrl` — `lambda:InvokeFunctionUrl`, conditioned on the
   function URL auth type being `NONE`. Authorizes the URL itself.
2. `GracefulGutPublicInvokeFunction` — `lambda:InvokeFunction`, conditioned on
   `lambda:InvokedViaFunctionUrl`. Authorizes the underlying invoke and narrows
   it to requests that actually arrive through the Function URL.

A previous audit claimed statement 2 was redundant and removed it, taking the
dev URL down. Without it the URL returns a steady 403 on every route; it only
*appears* healthy for ~10–20 seconds after removal because of policy caching.
Verify with `aws lambda get-policy`, not with a single immediate `curl`.

The live policy is managed with `aws lambda add-permission` /
`remove-permission`. The `InvokedViaFunctionUrl` condition is supported directly
by the `--invoked-via-function-url` flag, so CloudFormation, Terraform, and the
console are **not** required for it. The exact administrator commands are in
CLAUDE.md under "Resource policy — two statements, both required".

`AuthType` is `NONE`, so this policy intentionally allows anonymous callers to
reach the URL. Access control is enforced in application code by the `X-GG-Key`
shared-secret header, which is temporary internal-development protection only
and must never be shipped to a browser client. Before any public, browser-facing
client — and before Phase 2 accepts free-text input — this endpoint must move
behind API Gateway with server-side abuse controls. See the Phase 2
public-endpoint gate in CLAUDE.md.

## Other files

| File | Status |
| --- | --- |
| `claude-dev-trust-policy.json` | trust policy for the dev role |
| `lambda-execution-secrets-policy.json` | documented above — `GetSecretValue` on the one API-key secret |
| `lambda-trust-policy.json` | trust policy for the Lambda execution role |
| `claude-dev-user-data.sh` | dev host bootstrap |
| `ecr-lifecycle-policy.json` | **reserved** for a possible future container migration — ECR is not in use; the deployed function is a ZIP package |
