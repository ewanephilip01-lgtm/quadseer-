"""Dashboard data endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta
from app.db.session import get_db
from app.api.v1.auth import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.models.target import Target
from app.models.report import Report
from app.models.threat_actor import ThreatActor

router = APIRouter()


@router.get("/dashboard/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan_result = await db.execute(select(func.count(Scan.id)).where(Scan.owner_id == current_user.id))
    active_scans_result = await db.execute(select(func.count(Scan.id)).where((Scan.owner_id == current_user.id) & (Scan.status.in_(["pending", "queued", "running"]))))
    target_result = await db.execute(select(func.count(Target.id)).where(Target.owner_id == current_user.id))
    report_result = await db.execute(select(func.count(Report.id)).where(Report.owner_id == current_user.id))
    findings_result = await db.execute(select(func.sum(Scan.findings_count)).where(Scan.owner_id == current_user.id))
    threat_result = await db.execute(select(func.count(ThreatActor.id)).where(ThreatActor.is_active == True))
    return {
        "scans": {"total": scan_result.scalar(), "active": active_scans_result.scalar(), "completed": scan_result.scalar() - active_scans_result.scalar()},
        "targets": target_result.scalar(),
        "reports": report_result.scalar(),
        "findings": findings_result.scalar() or 0,
        "threat_actors": threat_result.scalar(),
    }


@router.get("/dashboard/recent-scans")
async def recent_scans(limit: int = 5, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Scan).where(Scan.owner_id == current_user.id).order_by(Scan.created_at.desc()).limit(limit))
    scans = result.scalars().all()
    return [{"id": s.id, "name": s.name, "status": s.status, "progress": s.progress, "findings_count": s.findings_count,
             "created_at": s.created_at.isoformat() if s.created_at else None} for s in scans]
