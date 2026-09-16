import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

from .models import CveFinding, Device, EventType, ProbeJob, ProbeRequest, SecurityEvent, Severity
from .repository import repository


app = FastAPI(
    title="SLeep API",
    version="0.1.0",
    description="Tenant-scoped API for devices, CVE findings, events, and safe probes.",
    root_path=os.getenv("SLEEP_ROOT_PATH", ""),
)


def organization_id(x_organization_id: Annotated[str, Header()]) -> str:
    if not x_organization_id.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Organization header is empty")
    return x_organization_id


OrganizationId = Annotated[str, Depends(organization_id)]


def require_device(org_id: str, device_id: str) -> Device:
    device = repository.get_device(org_id, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/devices", response_model=list[Device])
def list_devices(org_id: OrganizationId) -> list[Device]:
    return repository.list_devices(org_id)


@app.get("/v1/devices/{device_id}", response_model=Device)
def get_device(device_id: str, org_id: OrganizationId) -> Device:
    return require_device(org_id, device_id)


@app.get("/v1/devices/{device_id}/cves", response_model=list[CveFinding])
def list_cves(
    device_id: str,
    org_id: OrganizationId,
    severity: Annotated[Severity | None, Query()] = None,
) -> list[CveFinding]:
    require_device(org_id, device_id)
    return repository.list_cves(org_id, device_id, severity)


@app.get("/v1/devices/{device_id}/events", response_model=list[SecurityEvent])
def list_events(
    device_id: str,
    org_id: OrganizationId,
    event_type: Annotated[EventType | None, Query()] = None,
) -> list[SecurityEvent]:
    require_device(org_id, device_id)
    return repository.list_events(org_id, device_id, event_type)


@app.post(
    "/v1/devices/{device_id}/cves/{cve_id}/probes",
    response_model=ProbeJob,
    status_code=status.HTTP_202_ACCEPTED,
)
def queue_probe(device_id: str, cve_id: str, request: ProbeRequest, org_id: OrganizationId) -> ProbeJob:
    require_device(org_id, device_id)
    if repository.get_cve(org_id, device_id, cve_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE finding not found")
    return repository.queue_probe(org_id, device_id, cve_id, request.probe)
