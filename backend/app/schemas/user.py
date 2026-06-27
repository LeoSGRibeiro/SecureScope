from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime
from uuid import UUID
from app.models.user import UserRole


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: str | None = None

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("username")
    @classmethod
    def valid_username(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric (hyphens/underscores allowed)")
        return v.lower()


class UserLogin(BaseModel):
    username: str
    password: str
    ethics_accepted: bool = False


class UserOut(BaseModel):
    model_config = {"from_attributes": True}
    id: UUID
    email: str
    username: str
    full_name: str | None
    role: UserRole
    is_active: bool
    ethics_accepted: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


class EthicsAcceptance(BaseModel):
    accepted: bool
    acknowledgement: str

    @field_validator("acknowledgement")
    @classmethod
    def check_ack(cls, v: str) -> str:
        required = "i confirm i have authorization"
        if required not in v.lower():
            raise ValueError("Acknowledgement must confirm authorization")
        return v
