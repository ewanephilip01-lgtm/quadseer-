"""
Report generation and download endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.api.v1.auth import get_current_user, get_current_admin
from app.models.user import User
from app.models.scan import Scan
from app.models.report import Report
from app.models.finding import Finding

router = APIRouter(tags=["Reports"])


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Report).where(Report.id == report_id)
    )
    report = result.scalar_one_or_none()

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # In real implementation, read file and return
    return {"message": "PDF download would be served here", "report_id": report_id}


@router.get("/{report_id}/metadata")
async def get_report_metadata(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Report).where(Report.id == report_id)
    )
    report = result.scalar_one_or_none()

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": report.id,
        "scan_id": report.scan_id,
        "title": report.title,
        "report_type": report.report_type,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }
