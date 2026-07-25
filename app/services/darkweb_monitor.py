import httpx
from sqlalchemy.orm import Session
from app.models import Scan, Finding
from app.core.config import get_settings

settings = get_settings()


async def darkweb_scan_target(scan: Scan, db: Session):
    """
    Dark web monitoring scan for a target domain.
    Searches DeHashed for leaked credentials associated with the domain.
    FIXED: Removed circular import from breach_checker.py
    """
    target = scan.target.target
    findings = []

    # ── DeHashed Search (inlined, no cross-module import) ──
    if settings.dehashed_username and settings.dehashed_api_key:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                auth = httpx.BasicAuth(
                    settings.dehashed_username,
                    settings.dehashed_api_key
                )
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
                        severity = "critical" if password else "high"

                        finding = Finding(
                            scan_id=scan.id,
                            title=f"Dark Web Credential Leak: {email}",
                            description=(
                                f"Credential found on dark web sources. "
                                f"Username: {username}, "
                                f"Password: {password[:3]}***" if password else "Password: N/A"
                            ),
                            severity=severity,
                            source="dehashed",
                            raw_data=entry,
                            confidence="high"
                        )
                        findings.append(finding)

                    if not entries:
                        findings.append(Finding(
                            scan_id=scan.id,
                            title="No Dark Web Leaks Found",
                            description=f"DeHashed returned 0 leaked credentials for @{target}.",
                            severity="info",
                            source="dehashed",
                            confidence="high"
                        ))

                elif response.status_code == 401:
                    findings.append(Finding(
                        scan_id=scan.id,
                        title="DeHashed API Authentication Failed",
                        description="Invalid DeHashed credentials. Check admin settings.",
                        severity="warning",
                        source="dehashed",
                        confidence="high"
                    ))
                else:
                    findings.append(Finding(
                        scan_id=scan.id,
                        title="DeHashed API Error",
                        description=f"HTTP {response.status_code}: {response.text[:200]}",
                        severity="warning",
                        source="dehashed",
                        confidence="high"
                    ))

        except httpx.TimeoutException:
            findings.append(Finding(
                scan_id=scan.id,
                title="DeHashed Timeout",
                description="Request to DeHashed API timed out after 30s.",
                severity="warning",
                source="dehashed",
                confidence="high"
            ))
        except Exception as e:
            findings.append(Finding(
                scan_id=scan.id,
                title="DeHashed Search Error",
                description=str(e),
                severity="warning",
                source="dehashed",
                confidence="high"
            ))
    else:
        findings.append(Finding(
            scan_id=scan.id,
            title="DeHashed Not Configured",
            description="Add DeHashed credentials in admin settings for dark web monitoring.",
            severity="info",
            source="dehashed",
            confidence="high"
        ))

    # ── Tor / Onion Mention Monitoring (placeholder) ──
    # Real onion scraping requires Tor proxy infrastructure
    findings.append(Finding(
        scan_id=scan.id,
        title="Onion Site Monitoring",
        description="Onion site monitoring requires Tor proxy configuration. Add TOR_PROXY_URL to environment.",
        severity="info",
        source="tor_monitor",
        confidence="medium"
    ))

    db.add_all(findings)
    db.commit()

    return findings
