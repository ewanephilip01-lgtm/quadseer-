"""
Scan task execution - pure async functions, no Celery dependency.
Called from API endpoints via threading.Thread with isolated event loop.
"""
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import async_session
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.target import Target
from app.models.finding import Finding, FindingSeverity, FindingType

logger = logging.getLogger(__name__)


async def get_scan_and_target(scan_id: int, db: AsyncSession):
    """Get scan and target objects from DB."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")

    result = await db.execute(
        select(Target).where(Target.id == scan.target_id)
    )
    target = result.scalar_one_or_none()

    return scan, target


async def run_scan_task(scan_id: int):
    """
    Main scan execution function. Pure async - caller manages event loop.
    """
    async with async_session() as db:
        try:
            scan, target = await get_scan_and_target(scan_id, db)

            # Update status to running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()

            logger.info(f"Starting {scan.scan_type.value} scan for {target.domain} (scan_id={scan_id})")

            # Dispatch to appropriate handler
            if scan.scan_type == ScanType.BREACH:
                findings = await _run_breach_scan(scan, target, db)
            elif scan.scan_type == ScanType.RANSOMWARE:
                findings = await _run_ransomware_scan(scan, target, db)
            elif scan.scan_type == ScanType.DARKWEB:
                findings = await _run_darkweb_scan(scan, target, db)
            elif scan.scan_type == ScanType.RECONNAISSANCE:
                findings = await _run_recon_scan(scan, target, db)
            elif scan.scan_type == ScanType.DNS:
                findings = await _run_dns_scan(scan, target, db)
            elif scan.scan_type == ScanType.SSL:
                findings = await _run_ssl_scan(scan, target, db)
            elif scan.scan_type == ScanType.PORT:
                findings = await _run_port_scan(scan, target, db)
            elif scan.scan_type == ScanType.TECH:
                findings = await _run_tech_scan(scan, target, db)
            else:
                findings = []
                logger.warning(f"Unknown scan type: {scan.scan_type}")

            # Update scan status
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.results_summary = {
                "findings_count": len(findings),
                "critical": sum(1 for f in findings if f.severity.value == "critical"),
                "high": sum(1 for f in findings if f.severity.value == "high"),
                "medium": sum(1 for f in findings if f.severity.value == "medium"),
                "low": sum(1 for f in findings if f.severity.value == "low"),
                "info": sum(1 for f in findings if f.severity.value == "info"),
            }
            await db.commit()

            logger.info(f"Scan {scan_id} completed with {len(findings)} findings")
            return {"status": "completed", "findings": len(findings)}

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            await db.commit()
            return {"status": "failed", "error": str(e)}


# ========== Phase 2 Scan Handlers ==========

async def _run_breach_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run breach checker scan."""
    from app.services.breach_checker import breach_service
    try:
        findings = await breach_service.scan_target(target.domain, scan, db)
        await breach_service.close()
        return findings
    except Exception as e:
        logger.error(f"Breach scan failed: {e}")
        raise


async def _run_ransomware_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run ransomware tracker scan."""
    from app.services.ransomware_tracker import ransomware_service
    try:
        findings = await ransomware_service.scan_target(target.domain, scan, db)
        await ransomware_service.close()
        return findings
    except Exception as e:
        logger.error(f"Ransomware scan failed: {e}")
        raise


async def _run_darkweb_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run dark web monitor scan."""
    from app.services.darkweb_monitor import darkweb_service
    try:
        findings = await darkweb_service.scan_target(target.domain, scan, db)
        await darkweb_service.close()
        return findings
    except Exception as e:
        logger.error(f"Dark web scan failed: {e}")
        raise


# ========== Phase 1 Scan Handlers ==========

async def _run_recon_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run comprehensive reconnaissance scan."""
    findings = []
    findings.extend(await _run_dns_scan(scan, target, db))
    findings.extend(await _run_port_scan(scan, target, db))
    findings.extend(await _run_ssl_scan(scan, target, db))
    findings.extend(await _run_tech_scan(scan, target, db))
    return findings


async def _run_dns_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run DNS enumeration scan."""
    import dns.resolver
    from app.models.finding import Finding, FindingSeverity, FindingType

    findings = []
    domain = target.domain
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = [str(r) for r in answers]
            if records:
                finding = Finding(
                    scan_id=scan.id,
                    target_id=target.id,
                    finding_type=FindingType.DNS_RECORD,
                    severity=FindingSeverity.INFO,
                    title=f"DNS {rtype} record found",
                    description=f"Found {len(records)} {rtype} record(s) for {domain}",
                    source="dns",
                    extracted_data={"type": rtype, "records": records},
                    risk_score=0.0,
                    confidence=1.0,
                )
                findings.append(finding)
                db.add(finding)
        except Exception:
            continue

    await db.commit()
    return findings


async def _run_port_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run basic port scan."""
    import socket
    from app.models.finding import Finding, FindingSeverity, FindingType

    findings = []
    domain = target.domain
    top_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]

    try:
        ip = socket.gethostbyname(domain)
    except:
        return findings

    for port in top_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                services = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
                    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
                service = services.get(port, "Unknown")
                severity = FindingSeverity.HIGH if port in [21, 23, 445, 3389] else FindingSeverity.MEDIUM

                finding = Finding(
                    scan_id=scan.id,
                    target_id=target.id,
                    finding_type=FindingType.OPEN_PORT,
                    severity=severity,
                    title=f"Open port: {port}/{service}",
                    description=f"Port {port} ({service}) is open on {domain} ({ip})",
                    source="port_scan",
                    extracted_data={"port": port, "service": service, "ip": ip},
                    risk_score=5.0 if severity == FindingSeverity.HIGH else 3.0,
                    confidence=1.0,
                )
                findings.append(finding)
                db.add(finding)
        except:
            continue

    await db.commit()
    return findings


async def _run_ssl_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run SSL/TLS certificate scan."""
    import ssl
    import socket
    import datetime as dt
    from app.models.finding import Finding, FindingSeverity, FindingType

    findings = []
    domain = target.domain

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                not_after = cert.get("notAfter")
                if not_after:
                    expiry = ssl.cert_time_to_seconds(not_after)
                    days_until = (expiry - dt.datetime.utcnow().timestamp()) / 86400

                    if days_until < 0:
                        severity = FindingSeverity.CRITICAL
                        title = "SSL certificate EXPIRED"
                    elif days_until < 7:
                        severity = FindingSeverity.CRITICAL
                        title = f"SSL certificate expires in {int(days_until)} days"
                    elif days_until < 30:
                        severity = FindingSeverity.HIGH
                        title = f"SSL certificate expires in {int(days_until)} days"
                    else:
                        severity = FindingSeverity.INFO
                        title = f"SSL certificate valid for {int(days_until)} days"

                    finding = Finding(
                        scan_id=scan.id,
                        target_id=target.id,
                        finding_type=FindingType.SSL_CERT,
                        severity=severity,
                        title=title,
                        description=f"SSL certificate for {domain}. Valid until: {not_after}. TLS: {version}.",
                        source="ssl",
                        extracted_data={
                            "subject": str(cert.get("subject")),
                            "issuer": str(cert.get("issuer")),
                            "not_after": not_after,
                            "tls_version": version,
                            "days_until_expiry": days_until,
                        },
                        risk_score=9.0 if severity == FindingSeverity.CRITICAL else (7.0 if severity == FindingSeverity.HIGH else 0.0),
                        confidence=1.0,
                    )
                    findings.append(finding)
                    db.add(finding)

                if version in ["TLSv1", "TLSv1.1"]:
                    finding = Finding(
                        scan_id=scan.id,
                        target_id=target.id,
                        finding_type=FindingType.SSL_ISSUE,
                        severity=FindingSeverity.HIGH,
                        title=f"Weak TLS version: {version}",
                        description=f"{domain} uses deprecated {version}. Upgrade to TLS 1.2+.",
                        source="ssl",
                        extracted_data={"tls_version": version},
                        risk_score=7.0,
                        confidence=1.0,
                    )
                    findings.append(finding)
                    db.add(finding)

    except Exception as e:
        finding = Finding(
            scan_id=scan.id,
            target_id=target.id,
            finding_type=FindingType.SSL_ISSUE,
            severity=FindingSeverity.HIGH,
            title="SSL/TLS connection failed",
            description=f"Could not connect to {domain}:443 - {str(e)}",
            source="ssl",
            extracted_data={"error": str(e)},
            risk_score=5.0,
            confidence=0.8,
        )
        findings.append(finding)
        db.add(finding)

    await db.commit()
    return findings


async def _run_tech_scan(scan: Scan, target: Target, db: AsyncSession) -> list:
    """Run technology fingerprinting scan."""
    import httpx
    from app.models.finding import Finding, FindingSeverity, FindingType

    findings = []
    domain = target.domain

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(f"https://{domain}")
            headers = dict(resp.headers)
            body = resp.text[:5000]

            techs = []
            server = headers.get("server", "")
            if server:
                techs.append(f"Server: {server}")

            powered = headers.get("x-powered-by", "")
            if powered:
                techs.append(f"Powered-By: {powered}")

            if "cloudflare" in headers.get("cf-ray", "").lower():
                techs.append("CDN: Cloudflare")

            frameworks = {
                "WordPress": ["/wp-content/", "wp-includes"],
                "Drupal": ["/sites/default/", "drupal"],
                "Joomla": ["/media/jui/", "joomla"],
                "React": ["reactroot", "data-reactroot"],
                "Angular": ["ng-app", "angular"],
                "Vue.js": ["vue", "v-app"],
                "Laravel": ["laravel_session", "csrf-token"],
                "Django": ["csrftoken", "django"],
            }

            for framework, indicators in frameworks.items():
                for indicator in indicators:
                    if indicator.lower() in body.lower():
                        techs.append(f"Framework: {framework}")
                        break

            if techs:
                finding = Finding(
                    scan_id=scan.id,
                    target_id=target.id,
                    finding_type=FindingType.TECH_STACK,
                    severity=FindingSeverity.INFO,
                    title=f"Technology detected: {len(techs)} stack(s)",
                    description=f"Detected on {domain}: " + "; ".join(techs),
                    source="tech_fingerprint",
                    extracted_data={"technologies": techs, "headers": headers},
                    risk_score=0.0,
                    confidence=0.8,
                )
                findings.append(finding)
                db.add(finding)

    except Exception as e:
        finding = Finding(
            scan_id=scan.id,
            target_id=target.id,
            finding_type=FindingType.TECH_STACK,
            severity=FindingSeverity.INFO,
            title="Technology detection failed",
            description=f"Could not fingerprint {domain}: {str(e)}",
            source="tech_fingerprint",
            extracted_data={"error": str(e)},
            risk_score=0.0,
            confidence=0.0,
        )
        findings.append(finding)
        db.add(finding)

    await db.commit()
    return findings
