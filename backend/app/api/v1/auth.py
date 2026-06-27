from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, UserOut, TokenResponse, EthicsAcceptance
from app.api.deps import get_current_user, log_audit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=201)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(
        select(User).where((User.email == payload.email) | (User.username == payload.username))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email or username already registered")

    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if not user.ethics_accepted:
        if not payload.ethics_accepted:
            raise HTTPException(status_code=403, detail="Ethics agreement not accepted. Please accept the terms first.")
        user.ethics_accepted = True
        user.ethics_accepted_at = datetime.now(timezone.utc)

    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    await log_audit(db, user.id, "login", ip_address=request.client.host if request.client else None)

    return TokenResponse(
        access_token=create_access_token(user.id, {"role": user.role.value}),
        refresh_token=create_refresh_token(user.id),
        user=user,
    )


@router.post("/accept-ethics")
async def accept_ethics(
    payload: EthicsAcceptance,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.accepted:
        raise HTTPException(status_code=400, detail="Ethics acceptance required")
    current_user.ethics_accepted = True
    current_user.ethics_accepted_at = datetime.now(timezone.utc)
    await db.commit()
    await log_audit(db, current_user.id, "ethics_accepted", ip_address=request.client.host if request.client else None)
    return {"message": "Ethics agreement accepted"}


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
