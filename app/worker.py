"""Celery worker with Beat scheduler, real scanning, and email alerts."""
import os
import asyncio
from datetime import datetime, timedelta
from uuid import UUID

from celery import Celery
from celery.schedules import crontab
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from app.config import get_settings
from app.models.scan import Scan, ScanFinding, ScanStatus
from app.models.monitor import Monitor, MonitorRun
from app.models.alert import AlertRule, AlertLog
from app.models.report import Report, ReportStatus
from app.services.scanner import scanner_service
from app.services.email import email_service
from app.services.slack import slack_service
from app.services.reports import report_service

settings = get_settings()

# Celery app configuration
celery_app = Celery(
    "quadseer",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.worker"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "check-due-monitors": {
            "task": "app.worker.check_due_monitors",
            "schedule": crontab(minute=0),
        },
    },
)

# Async DB engine for tasks
engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def get_event_loop():
    """Get or create event loop for async operations in Celery."""
    try:
        return asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


@celery_app.task(bind=True, max_retries=3)
def run_scan_task(self, scan_id: str):
    """Execute a scan with real nmap/OSINT and notify on completion."""
    loop = get_event_loop()
    return loop.run_until_complete(_run_scan_async(scan_id))


async def _run_scan_async(scan_id: str):
    """Async scan execution."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            return {"error": "Scan not found"}

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.progress = 10
        await db.commit()

        try:
            if scan.scan_type == "attack_surface":
                results = await scanner_service.run_attack_surface_scan(scan.target)
            elif scan.scan_type == "brand_protection":
                results = await scanner_service.run_brand_protection_scan(scan.target)
            elif scan.scan_type == "credential_leak":
                results = await scanner_service.run_credential_leak_scan(scan.target)
            elif scan.scan_type == "dark_web":
                results = await scanner_service.run_dark_web_scan(scan.target)
            else:
                results = {"findings": [], "risk_score": 0, "mitre_tactics": [], "mitre_techniques": [], "geo_locations": []}

            scan.progress = 80
            await db.commit()

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for f_data in results.get("findings", []):
                finding = ScanFinding(
                    scan_id=scan.id,
                    title=f_data["title"],
                    description=f_data.get("description"),
                    severity=f_data.get("severity", "info"),
                    category=f_data.get("category"),
                    cve_id=f_data.get("cve_id"),
                    port=f_data.get("port"),
                    service=f_data.get("service"),
                    banner=f_data.get("banner"),
                    evidence=f_data.get("evidence"),
                    remediation=f_data.get("remediation"),
                    ip_address=f_data.get("ip_address"),
                    country=f_data.get("country"),
                    city=f_data.get("city"),
                    latitude=f_data.get("latitude"),
                    longitude=f_data.get("longitude"),
                    mitre_tactic=f_data.get("mitre_tactic"),
                    mitre_technique=f_data.get("mitre_technique"),
                )
                db.add(finding)
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

            scan.status = ScanStatus.COMPLETED
            scan.progress = 100
            scan.risk_score = results.get("risk_score", 0)
            scan.findings_count = len(results.get("findings", []))
            scan.critical_count = severity_counts.get("critical", 0)
            scan.high_count = severity_counts.get("high", 0)
            scan.medium_count = severity_counts.get("medium", 0)
            scan.low_count = severity_counts.get("low", 0)
            scan.info_count = severity_counts.get("info", 0)
            scan.mitre_tactics = results.get("mitre_tactics", [])
            scan.mitre_techniques = results.get("mitre_techniques", [])
            scan.geo_locations = results.get("geo_locations", [])
            scan.raw_results = results.get("raw_osint", {})
            scan.completed_at = datetime.utcnow()

            await db.commit()
            await _trigger_scan_alerts(db, scan)

            return {"scan_id": scan_id, "status": "completed", "findings": len(results.get("findings", []))}

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.progress = 0
            await db.commit()
            raise self.retry(exc=e, countdown=60)


@celery_app.task
def run_monitor_task(monitor_id: str):
    """Execute a monitor check."""
    loop = get_event_loop()
    return loop.run_until_complete(_run_monitor_async(monitor_id))


async def _run_monitor_async(monitor_id: str):
    """Async monitor execution."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Monitor).where(Monitor.id == UUID(monitor_id)))
        monitor = result.scalar_one_or_none()
        if not monitor or not monitor.is_active:
            return {"error": "Monitor not found or inactive"}

        run = MonitorRun(monitor_id=monitor.id, status="running")
        db.add(run)
        await db.commit()

        try:
            if monitor.monitor_type in ["domain", "ip"]:
                results = await scanner_service.run_attack_surface_scan(monitor.target)
            elif monitor.monitor_type == "brand":
                results = await scanner_service.run_brand_protection_scan(monitor.target)
            elif monitor.monitor_type == "credential":
                results = await scanner_service.run_credential_leak_scan(monitor.target)
            else:
                results = {"findings": [], "risk_score": 0}

            current_fp = hash(str(sorted([f["title"] for f in results.get("findings", [])])))
            new_findings = 0
            if monitor.baseline_fingerprint and monitor.baseline_fingerprint != str(current_fp):
                new_findings = len(results.get("findings", []))

            monitor.baseline_fingerprint = str(current_fp)
            monitor.last_run_at = datetime.utcnow()
            monitor.next_run_at = datetime.utcnow() + timedelta(hours={"hourly": 1, "daily": 24, "weekly": 168, "monthly": 720}.get(monitor.interval, 24))

            run.status = "completed"
            run.findings_count = len(results.get("findings", []))
            run.new_findings_count = new_findings
            run.raw_results = results
            run.diff_results = {"new_since_last": new_findings}
            run.completed_at = datetime.utcnow()

            await db.commit()

            if monitor.notify_email:
                await email_service.send_alert_email(
                    [monitor.owner.email],
                    f"Monitor Alert: {monitor.name}",
                    f"Monitor check completed for {monitor.target}. {len(results.get('findings', []))} findings, {new_findings} new.",
                    findings=results.get("findings", [])[:5],
                )

            if monitor.notify_slack and monitor.slack_webhook_url:
                await slack_service.send_scan_complete(
                    monitor.slack_webhook_url,
                    monitor.monitor_type,
                    monitor.target,
                    results.get("risk_score", 0),
                    len(results.get("findings", [])),
                )

            return {"monitor_id": monitor_id, "findings": len(results.get("findings", [])), "new": new_findings}

        except Exception as e:
            run.status = "failed"
            run.completed_at = datetime.utcnow()
            await db.commit()
            return {"error": str(e)}


@celery_app.task
def check_due_monitors():
    """Celery Beat task: Check and queue due monitors every hour."""
    loop = get_event_loop()
    return loop.run_until_complete(_check_due_monitors_async())


async def _check_due_monitors_async():
    """Find monitors due for execution and queue them."""
    async with AsyncSessionLocal() as db:
        now = datetime.utcnow()
        result = await db.execute(
            select(Monitor)
            .where(Monitor.is_active == True)
            .where((Monitor.next_run_at == None) | (Monitor.next_run_at <= now))
        )
        due_monitors = result.scalars().all()

        queued = 0
        for monitor in due_monitors:
            run_monitor_task.delay(str(monitor.id))
            monitor.next_run_at = now + timedelta(hours={"hourly": 1, "daily": 24, "weekly": 168, "monthly": 720}.get(monitor.interval, 24))
            queued += 1

        await db.commit()
        return {"queued": queued, "checked_at": now.isoformat()}


@celery_app.task
def generate_report_task(report_id: str):
    """Generate a report in background."""
    loop = get_event_loop()
    return loop.run_until_complete(_generate_report_async(report_id))


async def _generate_report_async(report_id: str):
    """Async report generation."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Report).where(Report.id == UUID(report_id)))
        report = result.scalar_one_or_none()
        if not report:
            return {"error": "Report not found"}

        report.status = ReportStatus.GENERATING
        await db.commit()

        try:
            file_path = await report_service.generate_report(
                db, UUID(report_id), report.scan_id, report.report_format.value, report.filters
            )

            report.status = ReportStatus.COMPLETED
            report.file_path = file_path
            report.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            report.completed_at = datetime.utcnow()
            await db.commit()

            return {"report_id": report_id, "status": "completed", "path": file_path}
        except Exception as e:
            report.status = ReportStatus.FAILED
            await db.commit()
            return {"error": str(e)}


async def _trigger_scan_alerts(db, scan):
    """Trigger alert rules for a completed scan."""
    result = await db.execute(
        select(AlertRule).where(AlertRule.owner_id == scan.owner_id, AlertRule.is_active == True, AlertRule.trigger_on_scan == True)
    )
    rules = result.scalars().all()

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    scan_max_severity = max(
        [severity_order.get(f.severity, 0) for f in scan.findings] or [0]
    )

    for rule in rules:
        rule_min = severity_order.get(rule.min_severity, 0)
        if scan_max_severity < rule_min:
            continue

        if rule.scan_types and scan.scan_type not in rule.scan_types:
            continue

        findings = [f for f in scan.findings if severity_order.get(f.severity, 0) >= rule_min]

        if rule.channel_email and rule.email_recipients:
            await email_service.send_alert_email(
                rule.email_recipients,
                f"Alert: {scan.scan_type.replace('_', ' ').title()} Scan - {scan.target}",
                f"Scan completed with {len(findings)} findings matching your alert criteria.",
                findings=[{"title": f.title, "severity": f.severity, "description": f.description} for f in findings[:10]],
            )

            log = AlertLog(
                rule_id=rule.id,
                channel="email",
                status="sent",
                recipient=", ".join(rule.email_recipients),
                subject=f"Alert: {scan.scan_type} Scan",
                related_scan_id=scan.id,
                sent_at=datetime.utcnow(),
            )
            db.add(log)

        if rule.channel_slack and rule.slack_webhook_url:
            await slack_service.send_alert(
                rule.slack_webhook_url,
                f"Scan Alert: {scan.target}",
                f"{scan.scan_type.replace('_', ' ').title()} scan found {len(findings)} issues",
                severity="high" if scan_max_severity >= 3 else "medium",
                findings=[{"title": f.title, "severity": f.severity} for f in findings[:5]],
                scan_url=f"{settings.APP_URL}/scan/{scan.id}",
            )

            log = AlertLog(
                rule_id=rule.id,
                channel="slack",
                status="sent",
                recipient=rule.slack_webhook_url,
                subject=f"Slack Alert: {scan.target}",
                related_scan_id=scan.id,
                sent_at=datetime.utcnow(),
            )
            db.add(log)

    await db.commit()
