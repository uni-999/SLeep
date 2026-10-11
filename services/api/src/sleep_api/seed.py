from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import SessionLocal
from .db_models import (
    CveFindingRecord,
    DeviceRecord,
    InventorySnapshotRecord,
    OrganizationRecord,
    SecurityEventRecord,
    UserRecord,
)


DEMO_ORGANIZATION_ID = "org-demo"


def seed_demo(session: Session) -> bool:
    if session.scalar(select(OrganizationRecord.id).where(OrganizationRecord.id == DEMO_ORGANIZATION_ID)):
        return False

    now = datetime.now(UTC)
    organization = OrganizationRecord(id=DEMO_ORGANIZATION_ID, name="Demo organization")
    user = UserRecord(
        organization_id=DEMO_ORGANIZATION_ID,
        email="soc@example.local",
        display_name="SOC Analyst",
        role="soc_analyst",
    )
    web_device = DeviceRecord(
        organization_id=DEMO_ORGANIZATION_ID,
        external_id="prod-web-01",
        name="prod-web-01",
        platform="Ubuntu 22.04",
        role="Веб-приложение",
        address="10.24.3.18",
        status="online",
        risk_score=78,
        last_seen_at=now - timedelta(seconds=18),
    )
    database_device = DeviceRecord(
        organization_id=DEMO_ORGANIZATION_ID,
        external_id="finance-db-01",
        name="finance-db-01",
        platform="Windows Server 2022",
        role="База данных",
        address="10.24.8.4",
        status="online",
        risk_score=41,
        last_seen_at=now - timedelta(seconds=31),
    )
    session.add(organization)
    session.flush()
    session.add_all([user, web_device, database_device])
    session.flush()

    session.add(
        InventorySnapshotRecord(
            organization_id=DEMO_ORGANIZATION_ID,
            device_id=web_device.id,
            content_hash="c7b497451810c03f0eef7e3d762f84327b147fa2f873b3d4b02419944245d03b",
            schema_version=1,
            inventory={
                "packages": [{"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.7"}],
                "ports": [{"protocol": "tcp", "port": 22, "process": "sshd"}],
            },
            collected_at=now - timedelta(minutes=24),
        )
    )
    session.add(
        CveFindingRecord(
            organization_id=DEMO_ORGANIZATION_ID,
            device_id=web_device.id,
            cve_id="CVE-2024-6387",
            title="Race condition в OpenSSH server",
            component="openssh-server",
            installed_version="1:8.9p1-3ubuntu0.7",
            fixed_version="1:8.9p1-3ubuntu0.10",
            severity="critical",
            cvss_score=8.1,
            epss_probability=0.0094,
            exposure="Доступен из внешнего сегмента",
            confidence=0.96,
            evidence=[
                {"kind": "process", "summary": "sshd запущен от root", "source": "agent"},
                {"kind": "network", "summary": "TCP/22 доступен через edge-firewall", "source": "cloud-probe"},
                {"kind": "package", "summary": "Версия пакета ниже исправленной", "source": "inventory"},
            ],
            recommended_action="Обновить openssh-server и перезапустить sshd в согласованное окно.",
            detected_at=now - timedelta(days=2),
            updated_at=now - timedelta(minutes=24),
        )
    )
    session.add(
        SecurityEventRecord(
            organization_id=DEMO_ORGANIZATION_ID,
            device_id=web_device.id,
            external_id="evt-01842",
            event_type="auth",
            severity="high",
            title="Серия неуспешных SSH-входов",
            summary="Попытки входа под root и deploy с одного внешнего адреса.",
            actor="185.17.42.91",
            correlation_key="auth:failed:185.17.42.91:root,deploy",
            first_seen_at=now - timedelta(minutes=5),
            last_seen_at=now - timedelta(minutes=2),
            record_count=487,
            raw_record_refs=["lake://demo/auth/1842"],
        )
    )
    session.commit()
    return True


def main() -> None:
    with SessionLocal() as session:
        created = seed_demo(session)
    print("Demo data created" if created else "Demo data already exists")


if __name__ == "__main__":
    main()
