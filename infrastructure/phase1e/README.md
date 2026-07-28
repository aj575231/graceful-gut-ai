# Phase 1E reference policies — proposed, not applied

Every file in this directory is a **reference document supporting
`docs/architecture/phase1e-api-gateway-adr.md`**. None of it has been applied.
No AWS resource was created, modified, or read to produce it.

## Placeholder convention

Same convention as `infrastructure/README.md`: `<PLACEHOLDER>` tokens are
substituted at apply time and the real values are never committed.

| Placeholder | Meaning |
| --- | --- |
| `<AWS_ACCOUNT_ID>` | the AWS account ID — read from AWS at the point of use |
| `<API_ID>` | the API Gateway REST API ID, once an administrator creates it |
| `<WEB_ACL_NAME>` | the WAF Web ACL name |
| `<WEB_ACL_ID>` | the WAF Web ACL ID |

The region is written literally as `us-east-2`, because the deployment is
pinned to one region.

`backend/tests/test_phase1e_design.py` fails if a real twelve-digit account ID
appears in any of these files.

## The files

| File | Kind | Applied by |
| --- | --- | --- |
| `apigateway-invoke-lambda.json` | Lambda **resource** policy — lets only this API invoke the function, scoped by `SourceArn` | Administrator |
| `deployment-automation-policy.json` | Identity policy for deployment automation | Administrator |
| `waf-administration-policy.json` | Identity policy for WAF administration | Administrator |
| `log-access-policy.json` | Identity policy for reading logs | Administrator |
| `administrator-only-actions.md` | The enumerated list of actions no automation role may hold | — |

## Why the policy documents carry no `_comment`

IAM rejects unknown top-level properties, so a `_comment` block makes a
document unapplyable as written — the failure this repository already hit once
and fixed in `bbb04de`. Explanation lives here instead. The files contain only
`Version`, `Statement`, and — for the resource policy, where it is legal — `Id`.

## Scoping notes

**`deployment-automation-policy.json`** carries an explicit `Deny` for the
actions that would let a deployment role remove the protections in front of the
application: Function URL administration, all of `wafv2:`, API Gateway
deletion, and all of `secretsmanager:`. A role that can ship code must not also
be able to disable the WAF that inspects the traffic reaching it, or read the
secret it deploys against.

Its API Gateway grant is deliberately narrow — `GET` and `POST` against the
deployments and stages of one API. Creating or deleting an API is an
administrator action.

**`log-access-policy.json`** denies write and delete on log content. Reading
logs to diagnose a deployment is routine; altering the record is not.

**`waf-administration-policy.json`** is an **administrator** policy. It is
written out so the boundary is explicit, not so it can be attached to an
automation role.

## Still unaudited

`GracefulGutAI-LambdaExecutionRole`'s attached policies are not readable from
the dev role and remain unaudited. Review with administrator credentials before
the public beta.
