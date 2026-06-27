import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, Enum as SAEnum, Float, Integer, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum
from app.core.database import Base


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ScanType(str, enum.Enum):
    full = "full"
    headers = "headers"
    tls = "tls"
    cookies = "cookies"
    cors = "cors"
    fingerprint = "fingerprint"
    subdomains = "subdomains"
    exposure = "exposure"
    owasp = "owasp"
    port_scan = "port_scan"


class Severity(str, enum.Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.pending)
    scan_type: Mapped[ScanType] = mapped_column(SAEnum(ScanType), default=ScanType.full)
    modules: Mapped[dict] = mapped_column(JSON, default=list)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    target = relationship("Target", back_populates="scans")
    owner = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    evidences = relationship("Evidence", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    module: Mapped[str] = mapped_column(String(100), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    affected_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="vulnerabilities")


class Evidence(Base):
    __tablename__ = "evidences"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # screenshot, headers, response, dns
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[dict] = mapped_column(JSON, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="evidences")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="audit_logs")
