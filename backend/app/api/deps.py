from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
import uuid
from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User, UserRole
from app.models.scan import AuditLog

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def require_role(*roles: UserRole):
    async def inner(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return inner


async def log_audit(
    db: AsyncSession,
    user_id: UUID | None,
    action: str,
    resource: str | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    extra: dict | None = None,
):
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        ip_address=ip_address,
        extra=extra,
    )
    db.add(entry)
    await db.commit()
