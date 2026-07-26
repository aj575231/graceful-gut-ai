from fastapi.testclient import TestClient

from app.main import APP_NAME, APP_VERSION, HealthResponse, app

client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["service"] == APP_NAME
    assert payload["version"] == APP_VERSION
    assert payload["timestamp_utc"]


def test_health_payload_matches_schema() -> None:
    """The response must validate against HealthResponse with no extra keys."""
    payload = client.get("/health").json()

    model = HealthResponse.model_validate(payload)

    assert set(payload) == set(HealthResponse.model_fields)
    assert model.status == "healthy"


def test_version_endpoint() -> None:
    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {
        "service": APP_NAME,
        "version": APP_VERSION,
    }


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["service"] == APP_NAME


def test_unknown_route_returns_404() -> None:
    assert client.get("/no-such-route").status_code == 404
