"""Monitoring routes with Celery Beat integration."""
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.monitor import Monitor, MonitorRun
from app.schemas import MonitorCreate, MonitorResponse, MonitorRunResponse
from app.worker import run_monitor_task

router = APIRouter(prefix="/api/monitors", tags=["Monitoring"])

@router.post("/", response_model=MonitorResponse)
async def create_monitor(
    monitor_data: MonitorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new continuous monitor."""
    monitor = Monitor(
        owner_id=current_user.id,
        name=monitor_data.name,
        target=monitor_data.target,
        monitor_type=monitor_data.monitor_type,
        interval=monitor_data.interval,
        notify_email=monitor_data.notify_email,
        notify_slack=monitor_data.notify_slack,
        slack_webhook_url=monitor_data.slack_webhook_url,
        alert_on_critical=monitor_data.alert_on_critical,
        alert_on_high=monitor_data.alert_on_high,
        alert_on_change=monitor_data.alert_on_change,
    )
    db.add(monitor)
    await db.commit()
    await db.refresh(monitor)
    return monitor

@router.get("/", response_model=List[MonitorResponse])
async def list_monitors(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all monitors for current user."""
    result = await db.execute(
        select(Monitor).where(Monitor.owner_id == current_user.id).order_by(desc(Monitor.created_at))
    )
    return result.scalars().all()

@router.get("/{monitor_id}", response_model=MonitorResponse)
async def get_monitor(
    monitor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get monitor details."""
    result = await db.execute(
        select(Monitor).where(Monitor.id == monitor_id, Monitor.owner_id == current_user.id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return monitor

@router.get("/{monitor_id}/runs", response_model=List[MonitorRunResponse])
async def get_monitor_runs(
    monitor_id: UUID,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get monitor execution history."""
    result = await db.execute(
        select(MonitorRun)
        .where(MonitorRun.monitor_id == monitor_id)
        .order_by(desc(MonitorRun.started_at))
        .limit(limit)
    )
    return result.scalars().all()

@router.put("/{monitor_id}", response_model=MonitorResponse)
async def update_monitor(
    monitor_id: UUID,
    monitor_data: MonitorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update monitor configuration."""
    result = await db.execute(
        select(Monitor).where(Monitor.id == monitor_id, Monitor.owner_id == current_user.id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    for field, value in monitor_data.model_dump().items():
        setattr(monitor, field, value)

    await db.commit()
    await db.refresh(monitor)
    return monitor

@router.delete("/{monitor_id}")
async def delete_monitor(
    monitor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a monitor."""
    result = await db.execute(
        select(Monitor).where(Monitor.id == monitor_id, Monitor.owner_id == current_user.id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    await db.delete(monitor)
    await db.commit()
    return {"message": "Monitor deleted"}

@router.post("/{monitor_id}/run")
async def trigger_monitor_run(
    monitor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Manually trigger a monitor run."""
    result = await db.execute(
        select(Monitor).where(Monitor.id == monitor_id, Monitor.owner_id == current_user.id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    run_monitor_task.delay(str(monitor_id))
    return {"message": "Monitor run queued", "monitor_id": str(monitor_id)}
