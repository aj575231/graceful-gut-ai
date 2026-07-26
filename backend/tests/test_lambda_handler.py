"""Exercise the real Mangum adapter with Lambda Function URL events.

Asserting the handler is merely callable would not catch an adapter or payload
format regression, which is the failure mode that actually takes the deployed
service down.
"""

from __future__ import annotations

import json
from typing import Any

from app.lambda_handler import handler
from app.main import APP_NAME

# A synthetic Function URL host. The real deployed URL is deliberately not
# checked in -- nothing here depends on its actual value.
URL_ID = "examplefunctionurlid00000000000"
DOMAIN = f"{URL_ID}.lambda-url.us-east-2.on.aws"


def function_url_event(path: str, method: str = "GET") -> dict[str, Any]:
    """Build a payload format 2.0 event of the shape a Function URL sends."""
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {
            "host": DOMAIN,
            "user-agent": "pytest",
            "x-forwarded-proto": "https",
            "x-forwarded-port": "443",
        },
        "requestContext": {
            "accountId": "anonymous",
            "apiId": URL_ID,
            "domainName": DOMAIN,
            "domainPrefix": URL_ID,
            "http": {
                "method": method,
                "path": path,
                "protocol": "HTTP/1.1",
                "sourceIp": "203.0.113.10",
                "userAgent": "pytest",
            },
            "requestId": "00000000-0000-4000-8000-000000000000",
            "routeKey": "$default",
            "stage": "$default",
            "time": "26/Jul/2026:00:00:00 +0000",
            "timeEpoch": 1785110400000,
        },
        "isBase64Encoded": False,
    }


class FakeLambdaContext:
    function_name = "graceful-gut-ai-dev-api"
    memory_limit_in_mb = 512
    # Synthetic account ID -- the real one is not checked in.
    invoked_function_arn = (
        "arn:aws:lambda:us-east-2:000000000000:function:graceful-gut-ai-dev-api"
    )
    aws_request_id = "00000000-0000-4000-8000-000000000000"

    def get_remaining_time_in_millis(self) -> int:
        return 15_000


def test_handler_serves_health_through_mangum() -> None:
    response = handler(function_url_event("/health"), FakeLambdaContext())

    assert response["statusCode"] == 200

    payload = json.loads(response["body"])
    assert payload["status"] == "healthy"
    assert payload["service"] == APP_NAME


def test_handler_serves_version_through_mangum() -> None:
    response = handler(function_url_event("/version"), FakeLambdaContext())

    assert response["statusCode"] == 200
    assert json.loads(response["body"])["service"] == APP_NAME


def test_handler_returns_404_for_unknown_route() -> None:
    response = handler(function_url_event("/no-such-route"), FakeLambdaContext())

    assert response["statusCode"] == 404
