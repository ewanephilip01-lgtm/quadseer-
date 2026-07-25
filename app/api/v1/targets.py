"""
Target API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List

from app.core.database import get_db
from app.api.v1.auth import get_current_user, get_current_admin
from app.models.user import User
from app.models.target import Target

router = APIRouter(tags=["Targets"])


class CreateTargetRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target_type: str = "domain"
    metadata: Optional[dict] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    id: int
    name: str
    domain: str
    description: Optional[str]
    target_type: str
    metadata: dict
    is_active: bool
    last_scan_at: Optional[str]
    created_at: str


@router.post("/", response_model=TargetResponse)
async def create_target(
    req: CreateTargetRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = Target(
        user_id=user.id,
        name=req.name,
        domain=req.domain.lower().strip(),
        description=req.description,
        target_type=req.target_type,
        metadata=req.metadata,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return _target_to_response(target)


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.user_id == user.id).order_by(Target.created_at.desc())
    )
    targets = result.scalars().all()
    return [_target_to_response(t) for t in targets]


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.user_id == user.id)
    )
    target = result.scalar_one_or_none()

    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    return _target_to_response(target)


@router.delete("/{target_id}")
async def delete_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.user_id == user.id)
    )
    target = result.scalar_one_or_none()

    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    await db.delete(target)
    await db.commit()
    return {"message": "Target deleted"}


def _target_to_response(target: Target) -> dict:
    return {
        "id": target.id,
        "name": target.name,
        "domain": target.domain,
        "description": target.description,
        "target_type": target.target_type,
        "metadata": target.target_metadata or {},
        "is_active": target.is_active,
        "last_scan_at": target.last_scan_at.isoformat() if target.last_scan_at else None,
        "created_at": target.created_at.isoformat() if target.created_at else None,
    }
