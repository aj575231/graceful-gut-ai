# Administrator-only actions

Actions that decide **who can reach the application**, **what inspects the
traffic**, or **what the application can read**. No automation role — including
`GracefulGutAI-ClaudeDevRole` and any future deployment role — may hold any of
them.

The principle is unchanged from Phase 1: *a host that can deploy code should not
also be able to change who is allowed to run it, or remove the controls in front
of it.*

## Function URL administration

Already withheld and documented in `CLAUDE.md`. Carried forward unchanged.

| Action | Why |
| --- | --- |
| `lambda:CreateFunctionUrlConfig` | creates an anonymous entry point |
| `lambda:UpdateFunctionUrlConfig` | changes `AuthType` and CORS |
| `lambda:DeleteFunctionUrlConfig` | removes the entry point |
| `lambda:AddPermission` | grants `Principal: '*'` |
| `lambda:RemovePermission` | revokes it, taking the URL down |

## API Gateway administration

| Action | Why |
| --- | --- |
| `apigateway:POST` on `/restapis` | creates a new public entry point |
| `apigateway:DELETE` on any resource | removes the API, a stage, or a method |
| `apigateway:PATCH` on stage throttle settings | raises or removes rate limits |
| `apigateway:PUT` on method authorization | changes who may call a route |

Creating a **deployment** of an existing API is different and is delegated to
deployment automation — it ships a configuration that an administrator already
approved.

## WAF administration

| Action | Why |
| --- | --- |
| `wafv2:CreateWebACL` / `UpdateWebACL` / `DeleteWebACL` | defines or removes the rules |
| `wafv2:AssociateWebACL` / `DisassociateWebACL` | attaches or detaches protection from the stage |
| `wafv2:PutLoggingConfiguration` | decides whether client IPs are retained |

`DisassociateWebACL` is the single most dangerous action in this list: it
silently removes every managed rule, rate limit, and method restriction while
leaving the API serving traffic normally.

## Secrets Manager

| Action | Why |
| --- | --- |
| `secretsmanager:GetSecretValue` | reads the live shared secret |
| `secretsmanager:PutSecretValue` | rotates it |
| `secretsmanager:CreateSecret` / `DeleteSecret` | creates or destroys it |
| `secretsmanager:*` | all of the above |

Reading the secret is the **Lambda execution role's** job. Granting it to a
deployment role would undo Phase 1D: the secret moved out of the function
environment precisely so a session that can deploy code cannot also read the
live key. `backend/tests/test_infrastructure_policy.py` fails if any
`secretsmanager:` action appears in the dev policy.

## IAM

| Action | Why |
| --- | --- |
| `iam:CreateRole`, `AttachRolePolicy`, `PutRolePolicy` | grants new privilege |
| `iam:PassRole` on any role but the one application execution role | attaches a more privileged role to the function |

## Cost controls

| Action | Why |
| --- | --- |
| `budgets:*` | removes the spend alarm |
| `lambda:PutFunctionConcurrency` on other functions | removes a hard cost ceiling elsewhere |

Reserved concurrency on **this** function is delegated to deployment
automation, because setting it to `0` is the emergency kill switch and must not
require waiting for an administrator.

## Verification is fully retained

Every administrator-only action above has a read-only counterpart that
automation **does** hold: `lambda:GetPolicy`, `lambda:GetFunctionUrlConfig`,
`apigateway:GET`, `wafv2:GetWebACL`, `wafv2:GetWebACLForResource`,
`wafv2:GetSampledRequests`.

A session can verify every one of these settings. It just cannot change them. A
session that finds a setting wrong should **report it and stop**, not attempt a
repair.
