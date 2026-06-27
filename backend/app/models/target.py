import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Text, Enum as SAEnum, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum
from app.core.database import Base


class TargetType(str, enum.Enum):
    url = "url"
    domain = "domain"
    subdomain = "subdomain"
    ip = "ip"


class TargetCriticality(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    type: Mapped[TargetType] = mapped_column(SAEnum(TargetType), default=TargetType.url)
    criticality: Mapped[TargetCriticality] = mapped_column(SAEnum(TargetCriticality), default=TargetCriticality.medium)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array as text
    scope_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    organization: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    scans = relationship("Scan", back_populates="target", lazy="select")
