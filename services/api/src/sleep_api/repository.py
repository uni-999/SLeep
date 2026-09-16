from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db_models import CveFindingRecord, DeviceRecord, ProbeJobRecord, SecurityEventRecord
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


class SqlRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_devices(self, organization_id: str) -> list[Device]:
        records = self.session.scalars(
            select(DeviceRecord)
            .where(DeviceRecord.organization_id == organization_id)
            .order_by(DeviceRecord.name)
        ).all()
        return [self._device(record) for record in records]

    def get_device(self, organization_id: str, device_id: str) -> Device | None:
        record = self._device_record(organization_id, device_id)
        return self._device(record) if record else None

    def list_cves(
        self,
        organization_id: str,
        device_id: str,
        severity: Severity | None,
    ) -> list[CveFinding]:
        device = self._device_record(organization_id, device_id)
        if device is None:
            return []

        statement = (
            select(CveFindingRecord)
            .where(
                CveFindingRecord.organization_id == organization_id,
                CveFindingRecord.device_id == device.id,
            )
            .order_by(CveFindingRecord.cvss_score.desc(), CveFindingRecord.cve_id)
        )
        if severity is not None:
            statement = statement.where(CveFindingRecord.severity == severity.value)

        return [self._cve(record, device.external_id) for record in self.session.scalars(statement).all()]

    def get_cve(
        self,
        organization_id: str,
        device_id: str,
        cve_id: str,
    ) -> CveFinding | None:
        device = self._device_record(organization_id, device_id)
        if device is None:
            return None
        record = self.session.scalar(
            select(CveFindingRecord).where(
                CveFindingRecord.organization_id == organization_id,
                CveFindingRecord.device_id == device.id,
                CveFindingRecord.cve_id == cve_id,
            )
        )
        return self._cve(record, device.external_id) if record else None

    def list_events(
        self,
        organization_id: str,
        device_id: str,
        event_type: EventType | None,
    ) -> list[SecurityEvent]:
        device = self._device_record(organization_id, device_id)
        if device is None:
            return []

        statement = (
            select(SecurityEventRecord)
            .where(
                SecurityEventRecord.organization_id == organization_id,
                SecurityEventRecord.device_id == device.id,
            )
            .order_by(SecurityEventRecord.last_seen_at.desc())
        )
        if event_type is not None:
            statement = statement.where(SecurityEventRecord.event_type == event_type.value)

        return [self._event(record, device.external_id) for record in self.session.scalars(statement).all()]

    def queue_probe(
        self,
        organization_id: str,
        device_id: str,
        cve_id: str,
        probe: str,
    ) -> ProbeJob:
        device = self._device_record(organization_id, device_id)
        if device is None:
            raise ValueError("Device not found")
        finding = self.session.scalar(
            select(CveFindingRecord).where(
                CveFindingRecord.organization_id == organization_id,
                CveFindingRecord.device_id == device.id,
                CveFindingRecord.cve_id == cve_id,
            )
        )
        if finding is None:
            raise ValueError("CVE finding not found")

        record = ProbeJobRecord(
            id=f"probe-{uuid4()}",
            organization_id=organization_id,
            device_id=device.id,
            cve_finding_id=finding.id,
            probe=probe,
            status="queued",
            created_at=datetime.now(UTC),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return ProbeJob(
            id=record.id,
            organization_id=record.organization_id,
            device_id=device.external_id,
            cve_id=finding.cve_id,
            probe=record.probe,
            status=record.status,
            created_at=record.created_at,
        )

    def _device_record(self, organization_id: str, device_id: str) -> DeviceRecord | None:
        return self.session.scalar(
            select(DeviceRecord).where(
                DeviceRecord.organization_id == organization_id,
                DeviceRecord.external_id == device_id,
            )
        )

    @staticmethod
    def _device(record: DeviceRecord) -> Device:
        return Device(
            id=record.external_id,
            organization_id=record.organization_id,
            name=record.name,
            platform=record.platform,
            role=record.role,
            address=record.address,
            status=DeviceStatus(record.status),
            risk_score=record.risk_score,
            cve_count=record.cve_count,
            critical_cve_count=record.critical_cve_count,
            last_seen_at=record.last_seen_at,
        )

    @staticmethod
    def _cve(record: CveFindingRecord, device_external_id: str) -> CveFinding:
        return CveFinding(
            id=record.cve_id,
            organization_id=record.organization_id,
            device_id=device_external_id,
            title=record.title,
            component=record.component,
            installed_version=record.installed_version,
            fixed_version=record.fixed_version,
            severity=Severity(record.severity),
            cvss_score=record.cvss_score,
            epss_probability=record.epss_probability,
            exposure=record.exposure,
            confidence=record.confidence,
            evidence=[Evidence.model_validate(item) for item in record.evidence],
            recommended_action=record.recommended_action,
            detected_at=record.detected_at,
            updated_at=record.updated_at,
        )

    @staticmethod
    def _event(record: SecurityEventRecord, device_external_id: str) -> SecurityEvent:
        return SecurityEvent(
            id=record.external_id,
            organization_id=record.organization_id,
            device_id=device_external_id,
            event_type=EventType(record.event_type),
            severity=Severity(record.severity),
            title=record.title,
            summary=record.summary,
            actor=record.actor,
            correlation_key=record.correlation_key,
            first_seen_at=record.first_seen_at,
            last_seen_at=record.last_seen_at,
            record_count=record.record_count,
            raw_record_refs=record.raw_record_refs,
        )
