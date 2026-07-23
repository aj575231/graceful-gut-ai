from fastapi.testclient import TestClient

from app.main import APP_NAME, APP_VERSION, app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["service"] == APP_NAME
    assert payload["version"] == APP_VERSION
    assert payload["timestamp_utc"]


def test_version_endpoint() -> None:
    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {
        "service": APP_NAME,
        "version": APP_VERSION,
    }
