from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from app.core.database import get_db
from app.core.auth import get_current_user
from app.models import User, Scan, Finding

router = APIRouter(prefix="/subdomains", tags=["subdomains"])


@router.get("/{target_id}")
def get_subdomains(
    target_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all discovered subdomains for a target from the latest subdomain scan.
    """
    # Find the latest completed subdomain scan for this target
    scan = db.query(Scan).filter(
        Scan.target_id == target_id,
        Scan.scan_type == "subdomain",
        Scan.status == "completed"
    ).order_by(Scan.created_at.desc()).first()

    if not scan:
        raise HTTPException(status_code=404, detail="No subdomain scan found for this target")

    # Find the aggregate finding with all_subdomains
    aggregate = db.query(Finding).filter(
        Finding.scan_id == scan.id,
        Finding.source == "subdomain_enum"
    ).first()

    if not aggregate or not aggregate.raw_data:
        return {"target_id": target_id, "subdomains": [], "total": 0}

    raw = aggregate.raw_data
    return {
        "target_id": target_id,
        "scan_id": scan.id,
        "scanned_at": scan.created_at.isoformat(),
        "total": raw.get("total", 0),
        "from_ct": raw.get("from_ct", 0),
        "from_brute": raw.get("from_brute", 0),
        "subdomains": raw.get("all_subdomains", [])
    }
