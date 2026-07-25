"""Report generation and download routes."""
import os
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.report import Report, ReportStatus
from app.schemas import ReportCreate, ReportResponse
from app.services.reports import report_service

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    report_data: ReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Queue a report generation."""
    report = Report(
        owner_id=current_user.id,
        name=report_data.name,
        description=report_data.description,
        report_format=report_data.report_format,
        scan_id=report_data.scan_id,
        filters=report_data.filters,
        status=ReportStatus.PENDING,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Generate in background
    from app.worker import generate_report_task
    generate_report_task.delay(str(report.id))

    return report

@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List generated reports."""
    result = await db.execute(
        select(Report).where(Report.owner_id == current_user.id).order_by(desc(Report.created_at))
    )
    return result.scalars().all()

@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download a generated report."""
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.owner_id == current_user.id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != ReportStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Report not ready")
    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    media_types = {"pdf": "application/pdf", "csv": "text/csv", "json": "application/json", "markdown": "text/markdown"}
    ext = report.file_path.split(".")[-1]

    return FileResponse(
        report.file_path,
        media_type=media_types.get(ext, "application/octet-stream"),
        filename=f"quadseer_report_{report.name}.{ext}"
    )

@router.delete("/{report_id}")
async def delete_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a report."""
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.owner_id == current_user.id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.file_path and os.path.exists(report.file_path):
        os.remove(report.file_path)

    await db.delete(report)
    await db.commit()
    return {"message": "Report deleted"}
