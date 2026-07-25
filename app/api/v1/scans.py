"""
Scan API endpoints - supports all Phase 1 and Phase 2 scan types.
Runs scans SYNCHRONOUSLY in the endpoint (blocks HTTP request).
Scans are fast enough (< 30s) that this is acceptable.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List

from app.core.database import get_db
from app.api.v1.auth import get_current_user, get_current_admin
from app.models.user import User
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.target import Target
from app.models.finding import Finding, FindingSeverity, FindingType
from app.tasks.scan_tasks import run_scan_task

router = APIRouter(tags=["Scans"])


class CreateScanRequest(BaseModel):
    target_id: int
    scan_type: ScanType = Field(..., description="Type of scan to run")
    config: Optional[dict] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    id: int
    target_id: int
    scan_type: str
    status: str
    config: dict
    results_summary: dict
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    target_id: int
    finding_type: str
    severity: str
    title: str
    description: Optional[str]
    source: Optional[str]
    source_reference: Optional[str]
    risk_score: float
    confidence: float
    status: str
    discovered_at: str


@router.post("/", response_model=ScanResponse)
async def create_scan(
    req: CreateScanRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Verify target exists and belongs to user (or user is admin)
    result = await db.execute(select(Target).where(Target.id == req.target_id))
    target = result.scalar_one_or_none()

    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    if target.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized for this target")

    scan = Scan(
        target_id=req.target_id,
        user_id=user.id,
        scan_type=req.scan_type,
        status=ScanStatus.PENDING,
        config=req.config,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Run scan SYNCHRONOUSLY - await it directly
    # This blocks the HTTP request but guarantees execution
    # Scans typically take 5-30 seconds
    try:
        await run_scan_task(scan.id)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Scan failed: {e}")
        # Scan status already updated to FAILED inside run_scan_task

    # Refresh scan to get updated status
    await db.refresh(scan)
    return _scan_to_response(scan)


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
):
    if user.is_admin:
        result = await db.execute(
            select(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
        )
    else:
        result = await db.execute(
            select(Scan).where(Scan.user_id == user.id)
            .order_by(Scan.created_at.desc()).offset(skip).limit(limit)
        )

    scans = result.scalars().all()
    return [_scan_to_response(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return _scan_to_response(scan)


@router.get("/{scan_id}/results", response_model=List[FindingResponse])
async def get_scan_results(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc())
    )
    findings = result.scalars().all()

    return [_finding_to_response(f) for f in findings]


@router.get("/{scan_id}/findings/summary")
async def get_findings_summary(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = result.scalars().all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    type_counts = {}
    total_risk = 0.0

    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
        type_counts[f.finding_type.value] = type_counts.get(f.finding_type.value, 0) + 1
        total_risk += f.risk_score

    return {
        "total_findings": len(findings),
        "severity_breakdown": severity_counts,
        "type_breakdown": type_counts,
        "total_risk_score": round(total_risk, 2),
        "average_risk_score": round(total_risk / len(findings), 2) if findings else 0,
    }


def _scan_to_response(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "scan_type": scan.scan_type.value,
        "status": scan.status.value,
        "config": scan.config or {},
        "results_summary": scan.results_summary or {},
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


def _finding_to_response(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "target_id": finding.target_id,
        "finding_type": finding.finding_type.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "source": finding.source,
        "source_reference": finding.source_reference,
        "risk_score": finding.risk_score,
        "confidence": finding.confidence,
        "status": finding.status,
        "discovered_at": finding.discovered_at.isoformat() if finding.discovered_at else None,
    }
