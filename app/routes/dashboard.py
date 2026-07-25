"""Dashboard API with stats, timeline, MITRE, and geo data."""
from datetime import datetime, timedelta
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanFinding
from app.models.monitor import Monitor
from app.models.alert import AlertLog, AlertRule
from app.models.billing import Subscription
from app.schemas import DashboardResponse, DashboardStats, ThreatTimelineItem, MitreStats, GeoThreatPoint, ScanListResponse, AlertLogResponse

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/", response_model=DashboardResponse)
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get full dashboard data."""

    # Stats
    total_scans = await db.scalar(select(func.count(Scan.id)).where(Scan.owner_id == current_user.id))
    total_monitors = await db.scalar(select(func.count(Monitor.id)).where(Monitor.owner_id == current_user.id))
    active_monitors = await db.scalar(
        select(func.count(Monitor.id)).where(Monitor.owner_id == current_user.id, Monitor.is_active == True)
    )

    findings_result = await db.execute(
        select(ScanFinding).join(Scan).where(Scan.owner_id == current_user.id)
    )
    all_findings = findings_result.scalars().all()

    total_findings = len(all_findings)
    critical_findings = sum(1 for f in all_findings if f.severity == "critical")
    high_findings = sum(1 for f in all_findings if f.severity == "high")

    open_alerts = await db.scalar(
        select(func.count(AlertLog.id))
        .join(AlertRule)
        .where(AlertRule.owner_id == current_user.id, AlertLog.status == "pending")
    )

    sub_result = await db.execute(
        select(Subscription).where(Subscription.user_id == current_user.id).order_by(desc(Subscription.created_at))
    )
    sub = sub_result.scalar_one_or_none()

    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    scans_this_month = await db.scalar(
        select(func.count(Scan.id)).where(Scan.owner_id == current_user.id, Scan.created_at >= month_start)
    )
    monitors_this_month = await db.scalar(
        select(func.count(Monitor.id)).where(Monitor.owner_id == current_user.id, Monitor.created_at >= month_start)
    )

    stats = DashboardStats(
        total_scans=total_scans or 0,
        total_monitors=total_monitors or 0,
        active_monitors=active_monitors or 0,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        open_alerts=open_alerts or 0,
        subscription_status=sub.status if sub else "none",
        scans_this_month=scans_this_month or 0,
        monitors_this_month=monitors_this_month or 0,
    )

    # Recent scans
    scans_result = await db.execute(
        select(Scan).where(Scan.owner_id == current_user.id).order_by(desc(Scan.created_at)).limit(10)
    )
    recent_scans = [
        ScanListResponse.model_validate(s) for s in scans_result.scalars().all()
    ]

    # Threat timeline (last 30 days)
    timeline = []
    for i in range(30):
        day = datetime.utcnow() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count = await db.scalar(
            select(func.count(ScanFinding.id))
            .join(Scan)
            .where(Scan.owner_id == current_user.id, ScanFinding.created_at >= day_start, ScanFinding.created_at < day_end)
        )
        if count:
            timeline.append(ThreatTimelineItem(date=day_start.strftime("%Y-%m-%d"), count=count, severity="mixed"))

    # MITRE stats
    mitre_result = await db.execute(
        select(ScanFinding.mitre_tactic, func.count(ScanFinding.id))
        .join(Scan)
        .where(Scan.owner_id == current_user.id, ScanFinding.mitre_tactic != None)
        .group_by(ScanFinding.mitre_tactic)
    )
    mitre_stats = []
    for tactic, count in mitre_result.all():
        tech_result = await db.execute(
            select(ScanFinding.mitre_technique, func.count(ScanFinding.id))
            .join(Scan)
            .where(Scan.owner_id == current_user.id, ScanFinding.mitre_tactic == tactic, ScanFinding.mitre_technique != None)
            .group_by(ScanFinding.mitre_technique)
        )
        techniques = [{"name": t, "count": c} for t, c in tech_result.all()]
        mitre_stats.append(MitreStats(tactic=tactic, count=count, techniques=techniques))

    # Geo threats
    geo_result = await db.execute(
        select(ScanFinding.latitude, ScanFinding.longitude, func.count(ScanFinding.id), ScanFinding.country, ScanFinding.city, ScanFinding.severity)
        .join(Scan)
        .where(Scan.owner_id == current_user.id, ScanFinding.latitude != None, ScanFinding.longitude != None)
        .group_by(ScanFinding.latitude, ScanFinding.longitude, ScanFinding.country, ScanFinding.city, ScanFinding.severity)
    )
    geo_threats = [
        GeoThreatPoint(lat=lat, lon=lon, count=count, country=country or "Unknown", city=city, severity=severity)
        for lat, lon, count, country, city, severity in geo_result.all()
    ]

    # Recent alerts
    alerts_result = await db.execute(
        select(AlertLog)
        .join(AlertRule)
        .where(AlertRule.owner_id == current_user.id)
        .order_by(desc(AlertLog.created_at))
        .limit(10)
    )
    recent_alerts = [AlertLogResponse.model_validate(a) for a in alerts_result.scalars().all()]

    return DashboardResponse(
        stats=stats,
        recent_scans=recent_scans,
        threat_timeline=timeline,
        mitre_stats=mitre_stats,
        geo_threats=geo_threats,
        recent_alerts=recent_alerts,
    )

@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get quick stats for KPI cards."""
    total_scans = await db.scalar(select(func.count(Scan.id)).where(Scan.owner_id == current_user.id))
    active_monitors = await db.scalar(
        select(func.count(Monitor.id)).where(Monitor.owner_id == current_user.id, Monitor.is_active == True)
    )
    critical = await db.scalar(
        select(func.count(ScanFinding.id))
        .join(Scan)
        .where(Scan.owner_id == current_user.id, ScanFinding.severity == "critical")
    )
    return {
        "total_scans": total_scans or 0,
        "active_monitors": active_monitors or 0,
        "critical_findings": critical or 0,
    }
