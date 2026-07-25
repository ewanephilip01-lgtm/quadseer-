"""
Admin API endpoints for configuration and user management.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List

from app.core.database import get_db
from app.api.v1.auth import get_current_admin
from app.models.user import User
from app.models.target import Target
from app.models.system_config import SystemConfig
from app.models.scan import Scan
from app.models.finding import Finding
from app.core.config import ConfigManager, initialize_default_configs

router = APIRouter(tags=["Admin"])


class ConfigUpdateRequest(BaseModel):
    config_value: str
    config_type: Optional[str] = "string"
    description: Optional[str] = ""


@router.get("/configs")
async def list_configs(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    result = await db.execute(select(SystemConfig).order_by(SystemConfig.config_key))
    configs = result.scalars().all()
    return [_config_to_response(c) for c in configs]


@router.get("/configs/{key}")
async def get_config(
    key: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.config_key == key)
    )
    config = result.scalar_one_or_none()

    if config is None:
        raise HTTPException(status_code=404, detail="Config not found")

    return _config_to_response(config)


@router.put("/configs/{key}")
async def update_config(
    key: str,
    req: ConfigUpdateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.config_key == key)
    )
    config = result.scalar_one_or_none()

    if config is None:
        config = SystemConfig(
            config_key=key,
            config_value=req.config_value,
            config_type=req.config_type or "string",
            description=req.description or "",
        )
        db.add(config)
    else:
        config.config_value = req.config_value
        config.config_type = req.config_type or config.config_type
        if req.description:
            config.description = req.description

    await db.commit()
    await db.refresh(config)

    ConfigManager.clear_cache()

    return _config_to_response(config)


@router.post("/configs/initialize")
async def initialize_configs(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    await initialize_default_configs()
    return {"message": "Default configurations initialized"}


@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
    skip: int = 0,
    limit: int = 100,
):
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).offset(skip).limit(limit)
    )
    users = result.scalars().all()
    return [{
        "id": u.id,
        "email": u.email,
        "username": u.username,
        "full_name": u.full_name,
        "is_active": u.is_active,
        "is_admin": u.is_admin,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    } for u in users]


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    user_count = await db.execute(select(func.count(User.id)))
    total_users = user_count.scalar()

    target_count = await db.execute(select(func.count(Target.id)))
    total_targets = target_count.scalar()

    scan_count = await db.execute(select(func.count(Scan.id)))
    total_scans = scan_count.scalar()

    finding_count = await db.execute(select(func.count(Finding.id)))
    total_findings = finding_count.scalar()

    scan_status = await db.execute(
        select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
    )
    scans_by_status = {s.value: c for s, c in scan_status.all()}

    finding_severity = await db.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    )
    findings_by_severity = {s.value: c for s, c in finding_severity.all()}

    return {
        "total_users": total_users,
        "total_targets": total_targets,
        "total_scans": total_scans,
        "total_findings": total_findings,
        "scans_by_status": scans_by_status,
        "findings_by_severity": findings_by_severity,
    }


def _config_to_response(config: SystemConfig) -> dict:
    return {
        "id": config.id,
        "config_key": config.config_key,
        "config_value": config.config_value,
        "config_type": config.config_type,
        "description": config.description,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }
