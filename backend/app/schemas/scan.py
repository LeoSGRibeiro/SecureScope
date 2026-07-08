from pydantic import BaseModel, field_validator
from datetime import datetime
from uuid import UUID
from typing import Any
from app.models.scan import ScanStatus, ScanType, Severity
from app.core.intrusive import ALL_MODULES


class ScanCreate(BaseModel):
    target_id: UUID
    scan_type: ScanType = ScanType.full
    modules: list[str] | None = None

    @field_validator("modules")
    @classmethod
    def valid_modules(cls, v):
        if v:
            invalid = set(v) - ALL_MODULES
            if invalid:
                raise ValueError(f"Invalid modules: {invalid}")
        return v


class VulnerabilityOut(BaseModel):
    model_config = {"from_attributes": True}
    id: UUID
    title: str
    description: str
    severity: Severity
    category: str
    module: str
    cvss_score: float | None
    cve: str | None
    owasp_category: str | None
    affected_url: str | None
    evidence: dict | None
    recommendation: str | None
    references: list | None
    is_false_positive: bool
    created_at: datetime


class ScanOut(BaseModel):
    model_config = {"from_attributes": True}
    id: UUID
    target_id: UUID
    owner_id: UUID
    status: ScanStatus
    scan_type: ScanType
    modules: list | None
    risk_score: float | None
    findings_count: int
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ScanDetail(ScanOut):
    vulnerabilities: list[VulnerabilityOut] = []


class ScanStats(BaseModel):
    total_scans: int
    scans_by_status: dict[str, int]
    vulnerabilities_by_severity: dict[str, int]
    average_risk_score: float
    recent_scans: list[ScanOut]
