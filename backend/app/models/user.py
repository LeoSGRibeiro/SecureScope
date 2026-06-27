import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Enum as SAEnum, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum
from app.core.database import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.analyst)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    ethics_accepted: Mapped[bool] = mapped_column(Boolean, default=False)
    ethics_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    scans = relationship("Scan", back_populates="owner", lazy="select")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="select")
