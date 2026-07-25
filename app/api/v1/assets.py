"""Asset inventory and EASM endpoints."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.db.session import get_db
from app.api.v1.auth import get_current_user
from app.models.user import User
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetRead, AssetStats, ReconRequest
from app.services.recon_service import ReconService
from app.tasks.recon_tasks import run_recon_task

router = APIRouter()


@router.get("/assets", response_model=List[AssetRead])
async def list_assets(
    target_id: int = None,
    asset_type: str = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List assets with optional filtering."""
    stmt = select(Asset).where(Asset.owner_id == current_user.id)
    if target_id:
        stmt = stmt.where(Asset.target_id == target_id)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    stmt = stmt.order_by(Asset.risk_score.desc(), Asset.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/assets/{asset_id}", response_model=AssetRead)
async def get_asset(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a single asset by ID."""
    result = await db.execute(
        select(Asset).where((Asset.id == asset_id) & (Asset.owner_id == current_user.id))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("/assets", response_model=AssetRead)
async def create_asset(
    asset_in: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually add an asset to inventory."""
    asset = Asset(
        name=asset_in.name,
        value=asset_in.value,
        asset_type=asset_in.asset_type,
        target_id=asset_in.target_id,
        owner_id=current_user.id,
        source=asset_in.source,
        confidence=asset_in.confidence,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


@router.post("/assets/recon")
async def start_recon(
    recon_in: ReconRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start asset discovery/reconnaissance for a target."""
    from app.models.target import Target
    result = await db.execute(select(Target).where((Target.id == recon_in.target_id) & (Target.owner_id == current_user.id)))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Queue recon task
    task = run_recon_task.delay(recon_in.target_id, current_user.id)

    return {
        "message": "Reconnaissance started",
        "target_id": recon_in.target_id,
        "task_id": task.id,
        "scan_depth": recon_in.scan_depth,
    }


@router.get("/assets/stats/{target_id}", response_model=AssetStats)
async def get_asset_stats(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get asset statistics for a target."""
    service = ReconService(db)
    return await service.get_asset_stats(target_id, current_user.id)


@router.get("/assets/inventory/{target_id}", response_model=List[AssetRead])
async def get_inventory(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get full asset inventory for a target."""
    service = ReconService(db)
    return await service.get_asset_inventory(target_id, current_user.id)
