from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from uuid import UUID
from app.core.database import get_db
from app.models.user import User
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetOut, TargetUpdate
from app.api.deps import get_current_user

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("/", response_model=list[TargetOut])
async def list_targets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=200),
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = select(Target).where(Target.owner_id == current_user.id, Target.is_active == True)
    if search:
        q = q.where(Target.name.ilike(f"%{search}%") | Target.value.ilike(f"%{search}%"))
    q = q.offset(skip).limit(limit).order_by(Target.created_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=TargetOut, status_code=201)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = Target(**payload.model_dump(), owner_id=current_user.id)
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.owner_id == current_user.id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, detail="Target not found")
    return target


@router.patch("/{target_id}", response_model=TargetOut)
async def update_target(
    target_id: UUID,
    payload: TargetUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.owner_id == current_user.id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, detail="Target not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(target, field, value)
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.owner_id == current_user.id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, detail="Target not found")
    target.is_active = False
    await db.commit()
