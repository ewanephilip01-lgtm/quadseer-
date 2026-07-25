"""Admin backoffice routes."""
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.database import get_db
from app.auth import get_current_active_superuser
from app.models.user import User
from app.models.scan import Scan
from app.models.monitor import Monitor
from app.models.billing import Plan, Subscription
from app.models.audit import AuditLog
from app.models.api_key import ApiKey
from app.schemas import UserResponse, PlanResponse

router = APIRouter(prefix="/api/admin", tags=["Admin"])

@router.get("/stats")
async def admin_stats(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_active_superuser),
):
    """Get admin dashboard stats."""
    user_count = await db.scalar(select(func.count(User.id)))
    scan_count = await db.scalar(select(func.count(Scan.id)))
    monitor_count = await db.scalar(select(func.count(Monitor.id)))
    active_subs = await db.scalar(select(func.count(Subscription.id)).where(Subscription.status == "active"))

    return {
        "total_users": user_count,
        "total_scans": scan_count,
        "total_monitors": monitor_count,
        "active_subscriptions": active_subs,
    }

@router.get("/users", response_model=List[UserResponse])
async def list_all_users(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_active_superuser),
):
    """List all users."""
    result = await db.execute(select(User).limit(limit).order_by(desc(User.created_at)))
    return result.scalars().all()

@router.put("/users/{user_id}/toggle")
async def toggle_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_active_superuser),
):
    """Toggle user active status."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = not user.is_active
    await db.commit()
    return {"message": f"User {'activated' if user.is_active else 'deactivated'}", "is_active": user.is_active}

@router.get("/audit-logs")
async def list_audit_logs(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_active_superuser),
):
    """List audit logs."""
    result = await db.execute(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit))
    return result.scalars().all()

@router.post("/plans")
async def create_plan(
    plan_data: dict,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_active_superuser),
):
    """Create a new plan."""
    from slugify import slugify
    plan = Plan(
        name=plan_data["name"],
        slug=slugify(plan_data["name"]),
        description=plan_data.get("description"),
        price_monthly=plan_data["price_monthly"],
        price_yearly=plan_data["price_yearly"],
        max_scans_per_month=plan_data.get("max_scans_per_month", 10),
        max_monitors=plan_data.get("max_monitors", 5),
        max_users=plan_data.get("max_users", 1),
        features=plan_data.get("features", []),
        is_popular=plan_data.get("is_popular", False),
    )
    db.add(plan)
    await db.commit()
    await db.refresh(plan)
    return plan

@router.get("/api-keys")
async def list_all_api_keys(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_active_superuser),
):
    """List all API keys."""
    result = await db.execute(select(ApiKey).order_by(desc(ApiKey.created_at)))
    return result.scalars().all()
