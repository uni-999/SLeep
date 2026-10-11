from collections.abc import Iterator

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
