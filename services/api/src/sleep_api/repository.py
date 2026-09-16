from datetime import UTC, datetime, timedelta
from uuid import uuid4

from .models import (
    CveFinding,
    Device,
    DeviceStatus,
    EventType,
    Evidence,
    ProbeJob,
    SecurityEvent,
    Severity,
)


DEMO_ORGANIZATION_ID = "org-demo"
NOW = datetime.now(UTC)


class DemoRepository:
    """Temporary repository that fixes the API contract before persistence lands."""

    def __init__(self) -> None:
        self.devices = [
            Device(
                id="prod-web-01",
                organization_id=DEMO_ORGANIZATION_ID,
                name="prod-web-01",
                platform="Ubuntu 22.04",
                role="Веб-приложение",
                address="10.24.3.18",
                status=DeviceStatus.ONLINE,
                risk_score=78,
                cve_count=4,
                critical_cve_count=1,
                last_seen_at=NOW - timedelta(seconds=18),
            ),
            Device(
                id="finance-db-01",
                organization_id=DEMO_ORGANIZATION_ID,
                name="finance-db-01",
                platform="Windows Server 2022",
                role="База данных",
                address="10.24.8.4",
                status=DeviceStatus.ONLINE,
                risk_score=41,
                cve_count=0,
                critical_cve_count=0,
                last_seen_at=NOW - timedelta(seconds=31),
            ),
        ]
        self.cves = [
            CveFinding(
                id="CVE-2024-6387",
                organization_id=DEMO_ORGANIZATION_ID,
                device_id="prod-web-01",
                title="Race condition в OpenSSH server",
                component="openssh-server",
                installed_version="1:8.9p1-3ubuntu0.7",
                fixed_version="1:8.9p1-3ubuntu0.10",
                severity=Severity.CRITICAL,
                cvss_score=8.1,
                epss_probability=0.0094,
                exposure="Доступен из внешнего сегмента",
                confidence=0.96,
                evidence=[
                    Evidence(kind="process", summary="sshd запущен от root", source="agent"),
                    Evidence(kind="network", summary="TCP/22 доступен через edge-firewall", source="cloud-probe"),
                    Evidence(kind="package", summary="Версия пакета ниже исправленной", source="inventory"),
                ],
                recommended_action="Обновить openssh-server и перезапустить sshd в согласованное окно.",
                detected_at=NOW - timedelta(days=2),
                updated_at=NOW - timedelta(minutes=24),
            )
        ]
        self.events = [
            SecurityEvent(
                id="evt-01842",
                organization_id=DEMO_ORGANIZATION_ID,
                device_id="prod-web-01",
                event_type=EventType.AUTH,
                severity=Severity.HIGH,
                title="Серия неуспешных SSH-входов",
                summary="Попытки входа под root и deploy с одного внешнего адреса.",
                actor="185.17.42.91",
                correlation_key="auth:failed:185.17.42.91:root,deploy",
                first_seen_at=NOW - timedelta(minutes=5),
                last_seen_at=NOW - timedelta(minutes=2),
                record_count=487,
                raw_record_refs=["lake://demo/auth/1842"],
            )
        ]
        self.probe_jobs: list[ProbeJob] = []

    def list_devices(self, organization_id: str) -> list[Device]:
        return [item for item in self.devices if item.organization_id == organization_id]

    def get_device(self, organization_id: str, device_id: str) -> Device | None:
        return next((item for item in self.devices if item.organization_id == organization_id and item.id == device_id), None)

    def list_cves(self, organization_id: str, device_id: str, severity: Severity | None) -> list[CveFinding]:
        return [
            item for item in self.cves
            if item.organization_id == organization_id
            and item.device_id == device_id
            and (severity is None or item.severity == severity)
        ]

    def get_cve(self, organization_id: str, device_id: str, cve_id: str) -> CveFinding | None:
        return next((item for item in self.list_cves(organization_id, device_id, None) if item.id == cve_id), None)

    def list_events(self, organization_id: str, device_id: str, event_type: EventType | None) -> list[SecurityEvent]:
        return [
            item for item in self.events
            if item.organization_id == organization_id
            and item.device_id == device_id
            and (event_type is None or item.event_type == event_type)
        ]

    def queue_probe(self, organization_id: str, device_id: str, cve_id: str, probe: str) -> ProbeJob:
        job = ProbeJob(
            id=f"probe-{uuid4()}",
            organization_id=organization_id,
            device_id=device_id,
            cve_id=cve_id,
            probe=probe,
            status="queued",
            created_at=datetime.now(UTC),
        )
        self.probe_jobs.append(job)
        return job


repository = DemoRepository()
