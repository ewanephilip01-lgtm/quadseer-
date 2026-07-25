"""Subdomain enumeration API routes."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding

router = APIRouter(prefix="/api/subdomains", tags=["Subdomains"])


@router.get("/{target_id}")
async def get_subdomains(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all discovered subdomains for a target from the latest subdomain scan."""
    result = await db.execute(
        select(Scan)
        .where(
            Scan.target_id == target_id,
            Scan.scan_type == "subdomain",
            Scan.status == "completed"
        )
        .order_by(desc(Scan.created_at))
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="No subdomain scan found for this target")

    result2 = await db.execute(
        select(Finding)
        .where(
            Finding.scan_id == scan.id,
            Finding.source == "subdomain_enum"
        )
    )
    aggregate = result2.scalar_one_or_none()

    if not aggregate or not aggregate.raw_data:
        return {"target_id": str(target_id), "subdomains": [], "total": 0}

    raw = aggregate.raw_data
    return {
        "target_id": str(target_id),
        "scan_id": str(scan.id),
        "scanned_at": scan.created_at.isoformat() if scan.created_at else None,
        "total": raw.get("total", 0),
        "from_ct": raw.get("from_ct", 0),
        "from_brute": raw.get("from_brute", 0),
        "subdomains": raw.get("all_subdomains", [])
    }
