from pydantic import BaseModel, field_validator
from datetime import datetime
from uuid import UUID
from app.models.target import TargetType, TargetCriticality
import re


URL_PATTERN = re.compile(
    r"^(https?://)?"
    r"(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}|localhost|\d{1,3}(\.\d{1,3}){3})"
    r"(:\d+)?(/.*)?$"
)

BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
}


class TargetCreate(BaseModel):
    name: str
    value: str
    type: TargetType = TargetType.url
    criticality: TargetCriticality = TargetCriticality.medium
    description: str | None = None
    tags: str | None = None
    scope_notes: str | None = None
    organization: str | None = None
    authorization_confirmed: bool = False

    @field_validator("value")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not URL_PATTERN.match(v):
            raise ValueError("Invalid URL or domain format")
        # Anti-SSRF: block internal/private addresses
        lower = v.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if lower in BLOCKED_HOSTS:
            raise ValueError("Internal/private addresses are not permitted as scan targets")
        # Block RFC-1918 ranges
        import ipaddress
        try:
            ip = ipaddress.ip_address(lower)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError("Private/internal IP addresses cannot be used as scan targets")
        except ValueError as e:
            if "is not a valid IPv4 address" not in str(e) and "does not appear to be" not in str(e):
                raise
        return v

    @field_validator("authorization_confirmed")
    @classmethod
    def must_confirm_auth(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must confirm you are authorized to test this target")
        return v


class TargetOut(BaseModel):
    model_config = {"from_attributes": True}
    id: UUID
    name: str
    value: str
    type: TargetType
    criticality: TargetCriticality
    description: str | None
    tags: str | None
    organization: str | None
    authorization_confirmed: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime


class TargetUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    tags: str | None = None
    criticality: TargetCriticality | None = None
    scope_notes: str | None = None
    is_active: bool | None = None
