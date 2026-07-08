from datetime import datetime, timezone, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.intrusive import PASSIVE_MODULES
from app.models.scheduled_scan import ScheduledScan
from app.models.user import User

router = APIRouter(prefix="/scheduled-scans", tags=["scheduled-scans"])

_DEFAULT_MODULES = list(PASSIVE_MODULES)


class ScheduledScanCreate(BaseModel):
    url: str
    email_to: str
    modules: list[str] = _DEFAULT_MODULES
    interval_days: int = 7

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url cannot be empty")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

    @field_validator("interval_days")
    @classmethod
    def positive_interval(cls, v: int) -> int:
        if v < 1:
            raise ValueError("interval_days must be >= 1")
        return v


class ScheduledScanToggle(BaseModel):
    is_active: bool


class ScheduledScanOut(BaseModel):
    id: UUID
    url: str
    modules: list[str]
    email_to: str
    interval_days: int
    is_active: bool
    last_run_at: datetime | None
    next_run_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


@router.post("/", response_model=ScheduledScanOut, status_code=201)
async def create_scheduled_scan(
    payload: ScheduledScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    sched = ScheduledScan(
        url=payload.url,
        modules=payload.modules,
        email_to=payload.email_to,
        interval_days=payload.interval_days,
        owner_id=current_user.id,
        next_run_at=now + timedelta(days=payload.interval_days),
    )
    db.add(sched)
    await db.commit()
    await db.refresh(sched)
    return sched


@router.get("/", response_model=list[ScheduledScanOut])
async def list_scheduled_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScheduledScan)
        .where(ScheduledScan.owner_id == current_user.id)
        .order_by(ScheduledScan.created_at.desc())
    )
    return result.scalars().all()


@router.patch("/{scheduled_scan_id}", response_model=ScheduledScanOut)
async def toggle_scheduled_scan(
    scheduled_scan_id: UUID,
    payload: ScheduledScanToggle,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == scheduled_scan_id,
            ScheduledScan.owner_id == current_user.id,
        )
    )
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(404, detail="Scheduled scan not found")
    sched.is_active = payload.is_active
    await db.commit()
    await db.refresh(sched)
    return sched


@router.delete("/{scheduled_scan_id}", status_code=204)
async def delete_scheduled_scan(
    scheduled_scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == scheduled_scan_id,
            ScheduledScan.owner_id == current_user.id,
        )
    )
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(404, detail="Scheduled scan not found")
    await db.delete(sched)
    await db.commit()
