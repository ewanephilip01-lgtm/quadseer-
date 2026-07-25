"""
Dark Web Monitor Service — FIXED for QUADSEER v3.1
"""
import httpx
import logging
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingType
from app.core.config import ConfigManager

logger = logging.getLogger(__name__)


async def darkweb_scan_target(scan: Scan, db: AsyncSession):
    """
    Dark web monitoring scan for a target domain.
    Searches DeHashed for leaked credentials associated with the domain.
    """
    target = scan.target.target if hasattr(scan, "target") else "unknown"
    findings = []

    # Load credentials from DB config (async)
    dehashed_email = await ConfigManager.get("dehashed_email", "")
    dehashed_key = await ConfigManager.get("dehashed_api_key", "")

    # ── DeHashed Search ──
    if dehashed_email and dehashed_key:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                auth = httpx.BasicAuth(dehashed_email, dehashed_key)
                query = f"email:@{target}"
                response = await client.get(
                    "https://api.dehashed.com/search",
                    params={"query": query, "size": 100},
                    auth=auth,
                    headers={"Accept": "application/json"}
                )

                if response.status_code == 200:
                    data = response.json()
                    entries = data.get("entries", [])
                    for entry in entries:
                        email = entry.get("email", "unknown")
                        username = entry.get("username", "N/A")
                        password = entry.get("password", "")
                        severity = FindingSeverity.CRITICAL if password else FindingSeverity.HIGH

                        finding = Finding(
                            scan_id=scan.id,
                            target_id=scan.target_id,
                            finding_type=FindingType.DARKWEB_MENTION,
                            severity=severity,
                            title=f"Dark Web Credential Leak: {email}",
                            description=(
                                f"Credential found on dark web sources. "
                                f"Username: {username}, "
                                f"Password: {password[:3]}***" if password else "Password: N/A"
                            ),
                            source="dehashed",
                            raw_data=entry,
                            risk_score=9.0 if password else 7.0,
                            confidence=1.0,
                        )
                        findings.append(finding)

                    if not entries:
                        findings.append(Finding(
                            scan_id=scan.id,
                            target_id=scan.target_id,
                            finding_type=FindingType.DARKWEB_MENTION,
                            severity=FindingSeverity.INFO,
                            title="No Dark Web Leaks Found",
                            description=f"DeHashed returned 0 leaked credentials for @{target}.",
                            source="dehashed",
                            confidence=1.0,
                        ))

                elif response.status_code == 401:
                    findings.append(Finding(
                        scan_id=scan.id,
                        target_id=scan.target_id,
                        finding_type=FindingType.DARKWEB_MENTION,
                        severity=FindingSeverity.WARNING,
                        title="DeHashed API Authentication Failed",
                        description="Invalid DeHashed credentials. Check admin settings.",
                        source="dehashed",
                        confidence=1.0,
                    ))
                else:
                    findings.append(Finding(
                        scan_id=scan.id,
                        target_id=scan.target_id,
                        finding_type=FindingType.DARKWEB_MENTION,
                        severity=FindingSeverity.WARNING,
                        title="DeHashed API Error",
                        description=f"HTTP {response.status_code}: {response.text[:200]}",
                        source="dehashed",
                        confidence=1.0,
                    ))

        except httpx.TimeoutException:
            findings.append(Finding(
                scan_id=scan.id,
                target_id=scan.target_id,
                finding_type=FindingType.DARKWEB_MENTION,
                severity=FindingSeverity.WARNING,
                title="DeHashed Timeout",
                description="Request to DeHashed API timed out after 30s.",
                source="dehashed",
                confidence=1.0,
            ))
        except Exception as e:
            logger.error(f"DeHashed search error: {e}")
            findings.append(Finding(
                scan_id=scan.id,
                target_id=scan.target_id,
                finding_type=FindingType.DARKWEB_MENTION,
                severity=FindingSeverity.WARNING,
                title="DeHashed Search Error",
                description=str(e),
                source="dehashed",
                confidence=1.0,
            ))
    else:
        findings.append(Finding(
            scan_id=scan.id,
            target_id=scan.target_id,
            finding_type=FindingType.DARKWEB_MENTION,
            severity=FindingSeverity.INFO,
            title="DeHashed Not Configured",
            description="Add DeHashed credentials in admin settings for dark web monitoring.",
            source="dehashed",
            confidence=1.0,
        ))

    # ── Tor / Onion Mention Monitoring (placeholder) ──
    findings.append(Finding(
        scan_id=scan.id,
        target_id=scan.target_id,
        finding_type=FindingType.DARKWEB_MENTION,
        severity=FindingSeverity.INFO,
        title="Onion Site Monitoring",
        description="Onion site monitoring requires Tor proxy configuration. Add TOR_PROXY_URL to environment.",
        source="tor_monitor",
        confidence=0.5,
    ))

    for f in findings:
        db.add(f)
    await db.commit()

    return findings
