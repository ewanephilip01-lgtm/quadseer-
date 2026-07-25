"""Scan orchestration service."""
import asyncio
import random
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.scan import Scan, ScanStatus, ScanResult
from app.services.websocket_notifier import notify_scan_progress


async def create_scan(db: AsyncSession, name: str, scan_type: str, target_id: int, owner_id: int, config: dict) -> Scan:
    scan = Scan(
        name=name,
        scan_type=scan_type,
        status=ScanStatus.QUEUED,
        target_id=target_id,
        owner_id=owner_id,
        config=config,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def get_scan(db: AsyncSession, scan_id: int) -> Optional[Scan]:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def list_scans(db: AsyncSession, owner_id: int, skip: int = 0, limit: int = 50):
    result = await db.execute(
        select(Scan).where(Scan.owner_id == owner_id).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()


async def update_scan_progress(db: AsyncSession, scan_id: int, progress: float, status: ScanStatus = None):
    stmt = update(Scan).where(Scan.id == scan_id)
    values = {"progress": progress}
    if status:
        values["status"] = status
        if status == ScanStatus.RUNNING and progress == 0:
            values["started_at"] = datetime.utcnow()
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            values["completed_at"] = datetime.utcnow()
    stmt = stmt.values(**values)
    await db.execute(stmt)
    await db.commit()
    await notify_scan_progress(scan_id, progress, status.value if status else "running")


async def add_scan_result(db: AsyncSession, scan_id: int, severity: str, category: str, 
                          title: str, description: str, **kwargs) -> ScanResult:
    result = ScanResult(
        scan_id=scan_id,
        severity=severity,
        category=category,
        title=title,
        description=description,
        **kwargs
    )
    db.add(result)
    scan = await get_scan(db, scan_id)
    if scan:
        scan.findings_count += 1
        if severity == "critical":
            scan.critical_count += 1
        elif severity == "high":
            scan.high_count += 1
        elif severity == "medium":
            scan.medium_count += 1
        elif severity == "low":
            scan.low_count += 1
        else:
            scan.info_count += 1
    await db.commit()
    return result


async def execute_mock_scan(db: AsyncSession, scan_id: int):
    """Simulated scan execution for demo purposes."""
    await update_scan_progress(db, scan_id, 0.0, ScanStatus.RUNNING)

    stages = [
        (10, "Initializing reconnaissance..."),
        (25, "DNS enumeration in progress..."),
        (40, "Port scanning target hosts..."),
        (55, "Service fingerprinting..."),
        (70, "Vulnerability correlation..."),
        (85, "Threat intelligence enrichment..."),
        (95, "Finalizing report generation..."),
        (100, "Scan completed."),
    ]

    for progress, message in stages:
        await asyncio.sleep(random.uniform(0.5, 1.5))
        await update_scan_progress(db, scan_id, progress)
        await notify_scan_progress(scan_id, progress, "running", message)

    mock_findings = [
        ("high", "ssl", "TLS 1.0/1.1 Enabled", "The server supports deprecated TLS versions.", "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+.", 7.5),
        ("medium", "headers", "Missing Security Headers", "X-Content-Type-Options and X-Frame-Options are absent.", "Add security headers to all responses.", 5.3),
        ("medium", "dns", "SPF Record Missing", "No SPF TXT record found for the domain.", "Configure SPF record to prevent email spoofing.", 4.3),
        ("low", "info", "Open Ports Detected", "Ports 80, 443, and 8080 are accessible.", "Review exposed ports and close unnecessary services.", 2.1),
        ("info", "recon", "Technology Stack Identified", "Server: nginx/1.24.0, PHP/8.2 detected.", "Keep software updated with latest patches.", 0.0),
    ]

    for sev, cat, title, desc, rem, cvss in mock_findings:
        await add_scan_result(db, scan_id, sev, cat, title, desc, remediation=rem, cvss_score=cvss)

    await update_scan_progress(db, scan_id, 100.0, ScanStatus.COMPLETED)
    await notify_scan_progress(scan_id, 100.0, "completed", "Scan finished successfully.")
