from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class DeviceStatus(StrEnum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventType(StrEnum):
    AUTH = "auth"
    PROCESS = "process"
    NETWORK = "network"
    PACKAGE = "package"
    SERVICE = "service"


class Device(BaseModel):
    id: str
    organization_id: str
    name: str
    platform: str
    role: str
    address: str
    status: DeviceStatus
    risk_score: int = Field(ge=0, le=100)
    cve_count: int = Field(ge=0)
    critical_cve_count: int = Field(ge=0)
    last_seen_at: datetime


class Evidence(BaseModel):
    kind: str
    summary: str
    source: str


class CveFinding(BaseModel):
    id: str
    organization_id: str
    device_id: str
    title: str
    component: str
    installed_version: str
    fixed_version: str | None
    severity: Severity
    cvss_score: float = Field(ge=0, le=10)
    epss_probability: float = Field(ge=0, le=1)
    exposure: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[Evidence]
    recommended_action: str
    detected_at: datetime
    updated_at: datetime


class SecurityEvent(BaseModel):
    id: str
    organization_id: str
    device_id: str
    event_type: EventType
    severity: Severity
    title: str
    summary: str
    actor: str | None
    correlation_key: str
    first_seen_at: datetime
    last_seen_at: datetime
    record_count: int = Field(ge=1)
    raw_record_refs: list[str]


class ProbeRequest(BaseModel):
    probe: str = Field(default="safe", pattern="^safe$")


class ProbeJob(BaseModel):
    id: str
    organization_id: str
    device_id: str
    cve_id: str
    probe: str
    status: str
    created_at: datetime
