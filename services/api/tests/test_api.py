from fastapi.testclient import TestClient

from sleep_api.main import app


client = TestClient(app)
headers = {"X-Organization-ID": "org-demo"}


def test_health_is_public() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_devices_are_tenant_scoped() -> None:
    response = client.get("/v1/devices", headers=headers)
    assert response.status_code == 200
    assert {device["id"] for device in response.json()} == {"prod-web-01", "finance-db-01"}

    other_tenant = client.get("/v1/devices", headers={"X-Organization-ID": "org-other"})
    assert other_tenant.status_code == 200
    assert other_tenant.json() == []


def test_device_routes_require_tenant_header() -> None:
    response = client.get("/v1/devices/prod-web-01/cves")
    assert response.status_code == 422


def test_safe_probe_is_queued_for_existing_finding() -> None:
    response = client.post(
        "/v1/devices/prod-web-01/cves/CVE-2024-6387/probes",
        headers=headers,
        json={"probe": "safe"},
    )
    assert response.status_code == 202
    assert response.json()["status"] == "queued"


def test_probe_cannot_cross_tenant_boundary() -> None:
    response = client.post(
        "/v1/devices/prod-web-01/cves/CVE-2024-6387/probes",
        headers={"X-Organization-ID": "org-other"},
        json={"probe": "safe"},
    )
    assert response.status_code == 404
