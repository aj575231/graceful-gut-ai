#!/usr/bin/env bash
#
# Build, upload, and smoke-test the dev Lambda.
#
# Deployment is deliberately manual: CI holds no AWS credentials. Record the
# CodeSha256 printed at the end alongside the commit it was built from, so a
# running deployment can always be traced back to source.
#
# This script never handles, generates, or prints the shared secret, and no
# secret value belongs in this file. Set it once, out of band, substituting a
# key you generate yourself with 'openssl rand -hex 32':
#
#   aws lambda update-function-configuration \
#     --function-name graceful-gut-ai-dev-api --region us-east-2 \
#     --environment 'Variables={APP_ENV=production,GG_API_KEY=<your-key>}'
#
# APP_ENV=production is required on every AWS deployment -- it is the secure,
# fail-closed posture. "development" is for local use only and is rejected
# below. The retired value "dev" must not be used.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP_PATH="${REPO_ROOT}/.build/lambda.zip"

FUNCTION_NAME="${FUNCTION_NAME:-graceful-gut-ai-dev-api}"
AWS_REGION="${AWS_REGION:-us-east-2}"

aws_lambda() {
  aws lambda "$1" --function-name "${FUNCTION_NAME}" --region "${AWS_REGION}" \
    "${@:2}"
}

bash "${REPO_ROOT}/scripts/build-lambda.sh"

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

echo "==> Checking environment configuration"
ENV_FAILED=0
DEPLOYED_APP_ENV="$(aws_lambda get-function-configuration \
  --output text --query 'Environment.Variables.APP_ENV' 2>/dev/null || true)"
case "${DEPLOYED_APP_ENV}" in
  production)
    echo "    APP_ENV=production"
    ;;
  development)
    echo "    FAIL: APP_ENV=development on a deployed function -- the shared"
    echo "          secret gate is relaxed and /openapi.json is exposed."
    echo "          Set APP_ENV=production before serving traffic."
    ENV_FAILED=1
    ;;
  ""|None)
    echo "    WARNING: APP_ENV is not set on the function. It defaults to"
    echo "             production and fails closed, but set it explicitly."
    ;;
  *)
    echo "    WARNING: APP_ENV=${DEPLOYED_APP_ENV} is not a supported value."
    echo "             Use production on every AWS deployment. Any other value"
    echo "             is treated as production, but do not rely on that."
    ;;
esac

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

if [[ -n "${GG_API_KEY:-}" ]]; then
  VERSION_CODE="$(status_of -H "X-GG-Key: ${GG_API_KEY}" "${FUNCTION_URL}/version")"
  echo "    GET /version (keyed)   -> ${VERSION_CODE}"
else
  VERSION_CODE="skipped"
  echo "    GET /version           -> skipped (GG_API_KEY not set locally)"
fi

UNAUTH_CODE="$(status_of "${FUNCTION_URL}/version")"
echo "    GET /version (no key)  -> ${UNAUTH_CODE}"

OPENAPI_CODE="$(status_of "${FUNCTION_URL}/openapi.json")"
echo "    GET /openapi.json      -> ${OPENAPI_CODE}"

echo
echo "==> Deployed"
echo "    CodeSha256: ${CODE_SHA}"
echo "    Git commit: ${GIT_SHA}${GIT_DIRTY}"

FAILED="${ENV_FAILED}"
[[ "${HEALTH_CODE}" == "200" ]] || { echo "    FAIL: /health expected 200"; FAILED=1; }
[[ "${UNAUTH_CODE}" == "401" || "${UNAUTH_CODE}" == "503" ]] \
  || { echo "    FAIL: /version without a key expected 401/503"; FAILED=1; }
[[ "${OPENAPI_CODE}" == "404" ]] \
  || { echo "    FAIL: /openapi.json expected 404"; FAILED=1; }
if [[ "${VERSION_CODE}" != "skipped" && "${VERSION_CODE}" != "200" ]]; then
  echo "    FAIL: /version with a key expected 200"
  FAILED=1
fi

exit "${FAILED}"
