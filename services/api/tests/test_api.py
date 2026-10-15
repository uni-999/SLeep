from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from sleep_api.database import Base, get_session
from sleep_api.db_models import (
    CveFindingRecord,
    DeviceRecord,
    InventorySnapshotRecord,
    OrganizationRecord,
    ProbeJobRecord,
)
from sleep_api.main import app
from sleep_api.seed import seed_demo


@pytest.fixture
def api() -> Iterator[tuple[TestClient, sessionmaker[Session]]]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    testing_sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    with testing_sessions() as session:
        seed_demo(session)

    def override_session() -> Iterator[Session]:
        with testing_sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        yield client, testing_sessions
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_health_is_public(api: tuple[TestClient, sessionmaker[Session]]) -> None:
    client, _ = api
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_checks_database(api: tuple[TestClient, sessionmaker[Session]]) -> None:
    client, _ = api
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_readiness_reports_an_unavailable_database(api: tuple[TestClient, sessionmaker[Session]]) -> None:
    client, _ = api
    unreachable = create_engine("sqlite+pysqlite:////nonexistent-directory/sleep.db")

    def unavailable_session() -> Iterator[Session]:
        with Session(unreachable) as session:
            yield session

    app.dependency_overrides[get_session] = unavailable_session
    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {"detail": "Database is not available"}


def test_devices_are_tenant_scoped(api: tuple[TestClient, sessionmaker[Session]]) -> None:
    client, _ = api
    response = client.get("/v1/devices", headers={"X-Organization-ID": "org-demo"})
    assert response.status_code == 200
    assert {device["id"] for device in response.json()} == {"prod-web-01", "finance-db-01"}

    other_tenant = client.get("/v1/devices", headers={"X-Organization-ID": "org-other"})
    assert other_tenant.status_code == 200
    assert other_tenant.json() == []


def test_device_routes_require_tenant_header(api: tuple[TestClient, sessionmaker[Session]]) -> None:
    client, _ = api
    response = client.get("/v1/devices/prod-web-01/cves")
    assert response.status_code == 422


def test_cves_and_events_are_loaded_from_database(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_sessions = api
    headers = {"X-Organization-ID": "org-demo"}

    cves = client.get("/v1/devices/prod-web-01/cves", headers=headers)
    events = client.get("/v1/devices/prod-web-01/events", headers=headers)

    assert cves.status_code == 200
    assert cves.json()[0]["id"] == "CVE-2024-6387"
    assert events.status_code == 200
    assert events.json()[0]["id"] == "evt-01842"
    with testing_sessions() as session:
        assert session.scalar(select(func.count()).select_from(InventorySnapshotRecord)) == 1


def test_safe_probe_is_persisted(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_sessions = api
    response = client.post(
        "/v1/devices/prod-web-01/cves/CVE-2024-6387/probes",
        headers={"X-Organization-ID": "org-demo"},
        json={"probe": "safe"},
    )
    assert response.status_code == 202
    assert response.json()["status"] == "queued"

    with testing_sessions() as session:
        job = session.scalar(select(ProbeJobRecord))
        assert job is not None
        assert job.id == response.json()["id"]
        assert job.organization_id == "org-demo"


def test_probe_cannot_cross_tenant_boundary(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_sessions = api
    response = client.post(
        "/v1/devices/prod-web-01/cves/CVE-2024-6387/probes",
        headers={"X-Organization-ID": "org-other"},
        json={"probe": "safe"},
    )
    assert response.status_code == 404
    with testing_sessions() as session:
        assert session.scalar(select(func.count()).select_from(ProbeJobRecord)) == 0


def test_database_rejects_cross_tenant_device_reference(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    _, testing_sessions = api
    with testing_sessions() as session:
        device = session.scalar(
            select(DeviceRecord).where(DeviceRecord.external_id == "prod-web-01")
        )
        assert device is not None
        session.add(OrganizationRecord(id="org-other", name="Other organization"))
        session.commit()
        session.add(
            InventorySnapshotRecord(
                organization_id="org-other",
                device_id=device.id,
                content_hash="0" * 64,
                schema_version=1,
                inventory={},
                collected_at=device.last_seen_at,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


def test_database_rejects_probe_for_cve_on_another_device(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    _, testing_sessions = api
    with testing_sessions() as session:
        target_device = session.scalar(
            select(DeviceRecord).where(DeviceRecord.external_id == "finance-db-01")
        )
        finding = session.scalar(select(CveFindingRecord))
        assert target_device is not None
        assert finding is not None
        session.add(
            ProbeJobRecord(
                id="probe-mismatched-device",
                organization_id="org-demo",
                device_id=target_device.id,
                cve_finding_id=finding.id,
                probe="safe",
                status="queued",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


def test_database_rejects_invalid_domain_value(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    _, testing_sessions = api
    with testing_sessions() as session:
        device = session.scalar(
            select(DeviceRecord).where(DeviceRecord.external_id == "prod-web-01")
        )
        assert device is not None
        device.risk_score = 101
        with pytest.raises(IntegrityError):
            session.commit()


DEMO_HEADERS = {"X-Organization-ID": "org-demo"}
OTHER_HEADERS = {"X-Organization-ID": "org-other"}


def add_finding(session: Session, device: DeviceRecord, cve_id: str, severity: str) -> None:
    session.add(
        CveFindingRecord(
            organization_id=device.organization_id,
            device_id=device.id,
            cve_id=cve_id,
            title="Test finding",
            component="test-component",
            installed_version="1.0",
            fixed_version="1.1",
            severity=severity,
            cvss_score=5.0,
            epss_probability=0.1,
            exposure="Internal",
            confidence=0.9,
            evidence=[],
            recommended_action="Update the component.",
            detected_at=device.last_seen_at,
        )
    )


@pytest.mark.parametrize(
    "path",
    [
        "/v1/devices/prod-web-01",
        "/v1/devices/prod-web-01/cves",
        "/v1/devices/prod-web-01/events",
    ],
)
def test_device_resources_are_hidden_from_other_tenant(
    api: tuple[TestClient, sessionmaker[Session]],
    path: str,
) -> None:
    client, _ = api
    response = client.get(path, headers=OTHER_HEADERS)
    assert response.status_code == 404


def test_same_external_device_id_is_isolated_between_tenants(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_sessions = api
    with testing_sessions() as session:
        session.add(OrganizationRecord(id="org-other", name="Other organization"))
        session.flush()
        device = DeviceRecord(
            organization_id="org-other",
            external_id="prod-web-01",
            name="prod-web-01",
            platform="Debian 12",
            role="Other tenant web",
            address="10.99.0.1",
            status="online",
            risk_score=10,
            last_seen_at=datetime.now(UTC),
        )
        session.add(device)
        session.flush()
        add_finding(session, device, "CVE-2026-0001", "low")
        session.commit()

    other_cves = client.get("/v1/devices/prod-web-01/cves", headers=OTHER_HEADERS)
    demo_cves = client.get("/v1/devices/prod-web-01/cves", headers=DEMO_HEADERS)
    other_events = client.get("/v1/devices/prod-web-01/events", headers=OTHER_HEADERS)
    other_device = client.get("/v1/devices/prod-web-01", headers=OTHER_HEADERS)

    assert [item["id"] for item in other_cves.json()] == ["CVE-2026-0001"]
    assert [item["id"] for item in demo_cves.json()] == ["CVE-2024-6387"]
    assert other_events.json() == []
    assert other_device.json()["platform"] == "Debian 12"
    assert other_device.json()["cve_count"] == 1
    assert other_device.json()["critical_cve_count"] == 0


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/devices/missing-device"),
        ("GET", "/v1/devices/missing-device/cves"),
        ("GET", "/v1/devices/missing-device/events"),
        ("POST", "/v1/devices/missing-device/cves/CVE-2024-6387/probes"),
        ("POST", "/v1/devices/prod-web-01/cves/CVE-0000-0000/probes"),
    ],
)
def test_unknown_resources_return_404(
    api: tuple[TestClient, sessionmaker[Session]],
    method: str,
    path: str,
) -> None:
    client, _ = api
    response = client.request(method, path, headers=DEMO_HEADERS, json={"probe": "safe"} if method == "POST" else None)
    assert response.status_code == 404


@pytest.mark.parametrize(
    ("query", "expected_status", "expected_ids"),
    [
        ("severity=critical", 200, ["CVE-2024-6387"]),
        ("severity=low", 200, []),
        ("severity=urgent", 422, None),
    ],
)
def test_cve_severity_filter(
    api: tuple[TestClient, sessionmaker[Session]],
    query: str,
    expected_status: int,
    expected_ids: list[str] | None,
) -> None:
    client, _ = api
    response = client.get(f"/v1/devices/prod-web-01/cves?{query}", headers=DEMO_HEADERS)
    assert response.status_code == expected_status
    if expected_ids is not None:
        assert [item["id"] for item in response.json()] == expected_ids


@pytest.mark.parametrize(
    ("query", "expected_status", "expected_ids"),
    [
        ("event_type=auth", 200, ["evt-01842"]),
        ("event_type=network", 200, []),
        ("event_type=login", 422, None),
    ],
)
def test_event_type_filter(
    api: tuple[TestClient, sessionmaker[Session]],
    query: str,
    expected_status: int,
    expected_ids: list[str] | None,
) -> None:
    client, _ = api
    response = client.get(f"/v1/devices/prod-web-01/events?{query}", headers=DEMO_HEADERS)
    assert response.status_code == expected_status
    if expected_ids is not None:
        assert [item["id"] for item in response.json()] == expected_ids


def test_device_cve_counters_are_derived_from_findings(
    api: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, testing_sessions = api

    def counters() -> dict[str, tuple[int, int]]:
        response = client.get("/v1/devices", headers=DEMO_HEADERS)
        assert response.status_code == 200
        return {item["id"]: (item["cve_count"], item["critical_cve_count"]) for item in response.json()}

    assert counters() == {"prod-web-01": (1, 1), "finance-db-01": (0, 0)}

    with testing_sessions() as session:
        web = session.scalar(select(DeviceRecord).where(DeviceRecord.external_id == "prod-web-01"))
        database = session.scalar(select(DeviceRecord).where(DeviceRecord.external_id == "finance-db-01"))
        assert web is not None
        assert database is not None
        add_finding(session, web, "CVE-2026-0002", "high")
        add_finding(session, database, "CVE-2026-0003", "critical")
        session.commit()

    assert counters() == {"prod-web-01": (2, 1), "finance-db-01": (1, 1)}
    single = client.get("/v1/devices/finance-db-01", headers=DEMO_HEADERS).json()
    assert (single["cve_count"], single["critical_cve_count"]) == (1, 1)


def test_seed_is_idempotent(api: tuple[TestClient, sessionmaker[Session]]) -> None:
    _, testing_sessions = api
    with testing_sessions() as session:
        assert seed_demo(session) is False
        assert session.scalar(select(func.count()).select_from(OrganizationRecord)) == 1
        assert session.scalar(select(func.count()).select_from(DeviceRecord)) == 2
        assert session.scalar(select(func.count()).select_from(CveFindingRecord)) == 1
        assert session.scalar(select(func.count()).select_from(InventorySnapshotRecord)) == 1
