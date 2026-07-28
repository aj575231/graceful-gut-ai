#!/usr/bin/env bash
#
# Build, validate, and (only when explicitly asked) deploy the dev Lambda.
#
# Deployment is deliberately manual: CI holds no AWS credentials. Record the
# CodeSha256 printed at the end alongside the commit it was built from, so a
# running deployment can always be traced back to source.
#
# THIS SCRIPT NEVER HANDLES THE SHARED SECRET.
# The X-GG-Key value lives in AWS Secrets Manager and is read at request time
# by the Lambda execution role. This script accepts only GG_API_SECRET_ID --
# the secret's *name or ARN*, which is configuration, not a credential. It
# never reads, writes, prints, or logs the secret value, and it never calls
# secretsmanager:GetSecretValue. Nothing here needs to know the key.
#
# APP_ENV=production is required on every AWS deployment -- it is the secure,
# fail-closed posture, and the only posture that reads the secret from Secrets
# Manager. "development" is for local use only and is rejected below. The
# retired value "dev" must not be used.
#
# Usage:
#   bash scripts/deploy-lambda.sh              # build + validate, NO deploy
#   bash scripts/deploy-lambda.sh --check      # same, explicitly
#   bash scripts/deploy-lambda.sh --configure  # set APP_ENV + GG_API_SECRET_ID
#   bash scripts/deploy-lambda.sh --deploy     # validate, then upload code
#
# The default stops before uploading anything. Deploying is opt-in.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP_PATH="${REPO_ROOT}/.build/lambda.zip"

FUNCTION_NAME="${FUNCTION_NAME:-graceful-gut-ai-dev-api}"
AWS_REGION="${AWS_REGION:-us-east-2}"

MODE="check"
case "${1:-}" in
  ""|--check) MODE="check" ;;
  --configure) MODE="configure" ;;
  --deploy) MODE="deploy" ;;
  -h|--help)
    sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "Unknown argument: $1" >&2
    echo "Usage: $0 [--check | --configure | --deploy]" >&2
    exit 2
    ;;
esac

aws_lambda() {
  aws lambda "$1" --function-name "${FUNCTION_NAME}" --region "${AWS_REGION}" \
    "${@:2}"
}

config_value() {
  # Prints an empty string rather than "None" when the variable is unset.
  local value
  value="$(aws_lambda get-function-configuration \
    --output text --query "Environment.Variables.$1" 2>/dev/null || true)"
  [[ "${value}" == "None" ]] && value=""
  printf '%s' "${value}"
}

# ---------------------------------------------------------------------------
# --configure: point the function at its secret. No secret value involved.
# ---------------------------------------------------------------------------

if [[ "${MODE}" == "configure" ]]; then
  if [[ -z "${GG_API_SECRET_ID:-}" ]]; then
    echo "FAIL: set GG_API_SECRET_ID to the secret's name or ARN first, e.g." >&2
    echo "      export GG_API_SECRET_ID=graceful-gut-ai/dev/api-key" >&2
    echo "      That is an identifier, not the key. Never export the key." >&2
    exit 1
  fi

  echo "==> Setting APP_ENV=production and GG_API_SECRET_ID on ${FUNCTION_NAME}"
  echo "    (this also clears any stale GG_API_KEY left in the environment)"
  aws_lambda update-function-configuration \
    --environment \
    "Variables={APP_ENV=production,GG_API_SECRET_ID=${GG_API_SECRET_ID}}" \
    --output text --query 'LastUpdateStatus'
  aws lambda wait function-updated \
    --function-name "${FUNCTION_NAME}" --region "${AWS_REGION}"
  echo "    Done. The secret VALUE is set separately, by an administrator:"
  echo "      aws secretsmanager put-secret-value --secret-id <id> \\"
  echo "        --secret-string '{\"api_key\":\"<key>\"}'"
  exit 0
fi

# ---------------------------------------------------------------------------
# Build first: a package that will not build should never reach validation.
# ---------------------------------------------------------------------------

bash "${REPO_ROOT}/scripts/build-lambda.sh"

# ---------------------------------------------------------------------------
# Validate the live configuration BEFORE any code is uploaded.
# ---------------------------------------------------------------------------

echo "==> Validating configuration on ${FUNCTION_NAME} (${AWS_REGION})"
CONFIG_FAILED=0

DEPLOYED_APP_ENV="$(config_value APP_ENV)"
case "${DEPLOYED_APP_ENV}" in
  production)
    echo "    APP_ENV=production"
    ;;
  development)
    echo "    FAIL: APP_ENV=development on a deployed function -- the shared"
    echo "          secret gate is relaxed and /openapi.json is exposed."
    echo "          Run: bash scripts/deploy-lambda.sh --configure"
    CONFIG_FAILED=1
    ;;
  "")
    echo "    FAIL: APP_ENV is not set. It defaults to production and fails"
    echo "          closed, but a deployed function must set it explicitly."
    echo "          Run: bash scripts/deploy-lambda.sh --configure"
    CONFIG_FAILED=1
    ;;
  *)
    echo "    FAIL: APP_ENV=${DEPLOYED_APP_ENV} is not a supported value. Use"
    echo "          production on every AWS deployment."
    CONFIG_FAILED=1
    ;;
esac

# Only presence is reported. The identifier is not a secret, but an ARN embeds
# the account ID, and deploy output gets pasted into reports.
if [[ -n "$(config_value GG_API_SECRET_ID)" ]]; then
  echo "    GG_API_SECRET_ID is set"
else
  echo "    FAIL: GG_API_SECRET_ID is not set. A production posture reads the"
  echo "          shared secret from Secrets Manager and has no fallback, so"
  echo "          every gated route would return 503."
  echo "          Run: bash scripts/deploy-lambda.sh --configure"
  CONFIG_FAILED=1
fi

if [[ -n "$(config_value GG_API_KEY)" ]]; then
  echo "    FAIL: GG_API_KEY is still set on the function. Production ignores"
  echo "          it, so it is a live credential sitting in plain text in the"
  echo "          function configuration for no benefit."
  echo "          Remove it: bash scripts/deploy-lambda.sh --configure"
  echo "          Then rotate it -- it has been readable through the console"
  echo "          and through get-function-configuration."
  CONFIG_FAILED=1
fi

if [[ "${CONFIG_FAILED}" != "0" ]]; then
  echo
  echo "==> Configuration invalid. No code was uploaded."
  exit 1
fi

# Captured before the upload so a bad deploy has somewhere to go back to.
PREVIOUS_CODE_SHA="$(aws_lambda get-function-configuration \
  --output text --query 'CodeSha256')"
PREVIOUS_REVISION="$(aws_lambda get-function-configuration \
  --output text --query 'RevisionId')"

echo "    Current CodeSha256: ${PREVIOUS_CODE_SHA}"
echo "    Current RevisionId: ${PREVIOUS_REVISION}"

if [[ "${MODE}" == "check" ]]; then
  echo
  echo "==> Check complete. Nothing was uploaded and nothing was modified."
  echo "    Package: ${ZIP_PATH}"
  echo "    To deploy: bash scripts/deploy-lambda.sh --deploy"
  exit 0
fi

# ---------------------------------------------------------------------------
# --deploy only past this point.
# ---------------------------------------------------------------------------

echo "==> Uploading to ${FUNCTION_NAME} (${AWS_REGION})"
aws_lambda update-function-code \
  --zip-file "fileb://${ZIP_PATH}" \
  --output text --query 'LastUpdateStatus'

echo "==> Waiting for the update to settle"
aws lambda wait function-updated \
  --function-name "${FUNCTION_NAME}" --region "${AWS_REGION}"

CODE_SHA="$(aws_lambda get-function-configuration --output text --query 'CodeSha256')"
GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
GIT_DIRTY=""
if ! git -C "${REPO_ROOT}" diff --quiet HEAD 2>/dev/null; then
  GIT_DIRTY=" (working tree dirty)"
fi

FUNCTION_URL="$(aws lambda get-function-url-config \
  --function-name "${FUNCTION_NAME}" --region "${AWS_REGION}" \
  --output text --query 'FunctionUrl')"
FUNCTION_URL="${FUNCTION_URL%/}"

echo "==> Smoke testing ${FUNCTION_URL}"

status_of() {
  curl --silent --show-error --max-time 20 \
    --output /dev/null --write-out '%{http_code}' "$@"
}

HEALTH_CODE="$(status_of "${FUNCTION_URL}/health")"
echo "    GET /health            -> ${HEALTH_CODE}"

# No keyed request: this script holds no key and must not fetch one. A 401 is
# the stronger signal anyway -- it proves the function reached Secrets Manager,
# parsed the JSON, and found a usable api_key. A 503 means resolution failed.
UNAUTH_CODE="$(status_of "${FUNCTION_URL}/version")"
echo "    GET /version (no key)  -> ${UNAUTH_CODE}"

# Also unkeyed, and the expected answer is 401 rather than 404. The shared
# secret gate runs BEFORE route resolution, so an anonymous caller gets the
# same 401 whether or not the route exists -- that is what stops the surface
# being enumerated by telling 401 from 404. The schema being hidden shows up
# as a 404 only for an authenticated caller, which this script cannot and must
# not test: it holds no key. test_security.py::test_gate_does_not_leak_which_
# routes_exist pins the application behaviour; test_deploy_script.py pins the
# expectation below so it cannot drift back to 404.
OPENAPI_CODE="$(status_of "${FUNCTION_URL}/openapi.json")"
echo "    GET /openapi.json (no key) -> ${OPENAPI_CODE}"

echo
echo "==> Deployed"
echo "    CodeSha256: ${CODE_SHA}"
echo "    Git commit: ${GIT_SHA}${GIT_DIRTY}"

FAILED=0
[[ "${HEALTH_CODE}" == "200" ]] || { echo "    FAIL: /health expected 200"; FAILED=1; }
[[ "${OPENAPI_CODE}" == "401" ]] \
  || { echo "    FAIL: /openapi.json without a key expected 401, got ${OPENAPI_CODE}"; FAILED=1; }

case "${UNAUTH_CODE}" in
  401) ;;
  503)
    echo "    FAIL: /version returned 503 -- the function could not resolve the"
    echo "          secret. Check that GG_API_SECRET_ID names an existing"
    echo "          secret, that its JSON is {\"api_key\": \"...\"} with a"
    echo "          non-empty value, and that the execution role holds"
    echo "          secretsmanager:GetSecretValue on it (see"
    echo "          infrastructure/lambda-execution-secrets-policy.json)."
    FAILED=1
    ;;
  *)
    echo "    FAIL: /version without a key expected 401, got ${UNAUTH_CODE}"
    FAILED=1
    ;;
esac

if [[ "${FAILED}" != "0" ]]; then
  echo
  echo "==> Smoke test failed. To roll back, redeploy the previous commit:"
  echo "      git checkout <previous-commit>"
  echo "      bash scripts/deploy-lambda.sh --deploy"
  echo "    The function was running CodeSha256 ${PREVIOUS_CODE_SHA}"
  echo "    (RevisionId ${PREVIOUS_REVISION}) before this deploy."
fi

exit "${FAILED}"
