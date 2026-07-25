from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.core.auth import get_current_user
from app.models import User, Scan, Target, Finding
from app.schemas import ScanCreate, ScanResponse, ScanStatus
from app.services import (
    breach_service,
    ransomware_service,
    darkweb_scan_target,
    recon_scan_target,
    subdomain_scan_target,
)

router = APIRouter(prefix="/scans", tags=["scans"])

SCAN_TYPES = {
    "breach": "Breach Checker",
    "ransomware": "Ransomware Tracker",
    "darkweb": "Dark Web Monitor",
    "reconnaissance": "Reconnaissance",
    "subdomain": "Subdomain Enumeration",   # NEW
    "vulnerability": "Vulnerability Scan",
    "certificate": "Certificate Transparency",
    "typosquatting": "Typosquatting Detection",
}


@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_in: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target = db.query(Target).filter(
        Target.id == scan_in.target_id,
        Target.owner_id == current_user.id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if scan_in.scan_type not in SCAN_TYPES:
        raise HTTPException(status_code=400, detail="Invalid scan type")

    scan = Scan(
        target_id=scan_in.target_id,
        scan_type=scan_in.scan_type,
        status=ScanStatus.pending,
        created_by=current_user.id
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Execute synchronously (as per current architecture)
    await execute_scan(scan.id, db)

    db.refresh(scan)
    return scan


async def execute_scan(scan_id: int, db: Session):
    """Synchronous scan execution — no background tasks."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    scan.status = ScanStatus.running
    db.commit()

    try:
        if scan.scan_type == "breach":
            await breach_service.scan_target(scan, db)
        elif scan.scan_type == "ransomware":
            await ransomware_service.scan_target(scan, db)
        elif scan.scan_type == "darkweb":
            await darkweb_scan_target(scan, db)   # FIXED: direct call, no circular import
        elif scan.scan_type == "reconnaissance":
            await recon_scan_target(scan, db)
        elif scan.scan_type == "subdomain":      # NEW
            await subdomain_scan_target(scan, db)
        else:
            # Placeholder for unimplemented scan types
            from app.models import Finding
            db.add(Finding(
                scan_id=scan.id,
                title=f"{scan.scan_type} scan not yet implemented",
                description="This scan type is on the roadmap. Check back in a future release.",
                severity="info",
                source=scan.scan_type,
                confidence="high"
            ))
            db.commit()

        scan.status = ScanStatus.completed

    except Exception as e:
        scan.status = ScanStatus.failed
        scan.error_message = str(e)
        db.add(Finding(
            scan_id=scan.id,
            title="Scan Execution Failed",
            description=str(e),
            severity="critical",
            source="system",
            confidence="high"
        ))

    db.commit()


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(Scan).join(Target).filter(
        Target.owner_id == current_user.id
    ).order_by(Scan.created_at.desc()).all()


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).join(Target).filter(
        Scan.id == scan_id,
        Target.owner_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).join(Target).filter(
        Scan.id == scan_id,
        Target.owner_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.query(Finding).filter(Finding.scan_id == scan_id).delete()
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}
