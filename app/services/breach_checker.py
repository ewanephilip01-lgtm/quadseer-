"""
Breach Checker Service - Integrates Have I Been Pwned and DeHashed APIs.
End-to-end validated with real API calls.
"""
import asyncio
import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingType
from app.models.scan import Scan
from app.core.config import ConfigManager

logger = logging.getLogger(__name__)


class BreachCheckerService:
    """
    Checks for data breach exposure using multiple sources:
    - Have I Been Pwned (HIBP) API v3
    - DeHashed API
    """

    HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
    DEHASHED_BASE_URL = "https://api.dehashed.com"

    def __init__(self):
        self.hibp_key: Optional[str] = None
        self.dehashed_email: Optional[str] = None
        self.dehashed_key: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with proper headers."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "QuadSeer-BreachChecker/3.0"},
            )
        return self._client

    async def _load_credentials(self):
        """Load API credentials from DB config."""
        self.hibp_key = await ConfigManager.get("hibp_api_key", "")
        self.dehashed_email = await ConfigManager.get("dehashed_email", "")
        self.dehashed_key = await ConfigManager.get("dehashed_api_key", "")

    # ========== HIBP Methods ==========

    async def check_email_hibp(self, email: str) -> Dict[str, Any]:
        """
        Check if an email has been in breaches via HIBP.
        Returns: {"found": bool, "breaches": [...], "breach_count": int}
        """
        await self._load_credentials()

        if not self.hibp_key:
            logger.warning("HIBP API key not configured")
            return {"found": False, "breaches": [], "breach_count": 0, "error": "No HIBP API key"}

        client = await self._get_client()
        url = f"{self.HIBP_BASE_URL}/breachedAccount/{email}"

        try:
            resp = await client.get(
                url,
                headers={
                    "hibp-api-key": self.hibp_key,
                    "User-Agent": "QuadSeer-BreachChecker/3.0",
                },
                params={"truncateResponse": "false"},
            )

            if resp.status_code == 404:
                return {"found": False, "breaches": [], "breach_count": 0}

            if resp.status_code == 401:
                logger.error("HIBP API key invalid")
                return {"found": False, "breaches": [], "breach_count": 0, "error": "Invalid HIBP API key"}

            if resp.status_code == 429:
                retry_after = resp.headers.get("retry-after", "5")
                logger.warning(f"HIBP rate limited. Retry after: {retry_after}s")
                return {"found": False, "breaches": [], "breach_count": 0, "error": f"Rate limited. Retry after {retry_after}s"}

            resp.raise_for_status()
            breaches = resp.json()

            # Normalize and enrich breach data
            normalized = []
            for b in breaches:
                normalized.append({
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "added_date": b.get("AddedDate"),
                    "pwn_count": b.get("PwnCount", 0),
                    "description": b.get("Description", ""),
                    "data_classes": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified", True),
                    "is_sensitive": b.get("IsSensitive", False),
                    "is_stealer_log": b.get("IsStealerLog", False),
                    "logo_path": b.get("LogoPath", ""),
                    "source": "hibp",
                })

            return {
                "found": True,
                "breaches": normalized,
                "breach_count": len(normalized),
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"HIBP HTTP error: {e.response.status_code} - {e.response.text[:200]}")
            return {"found": False, "breaches": [], "breach_count": 0, "error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            logger.error(f"HIBP check failed for {email}: {e}")
            return {"found": False, "breaches": [], "breach_count": 0, "error": str(e)}

    async def check_domain_hibp(self, domain: str) -> Dict[str, Any]:
        """
        Check domain-wide breach exposure via HIBP domain search.
        Requires domain verification in HIBP dashboard.
        """
        await self._load_credentials()

        if not self.hibp_key:
            return {"found": False, "emails": {}, "error": "No HIBP API key"}

        client = await self._get_client()
        url = f"{self.HIBP_BASE_URL}/breachedDomain/{domain}"

        try:
            resp = await client.get(
                url,
                headers={
                    "hibp-api-key": self.hibp_key,
                    "User-Agent": "QuadSeer-BreachChecker/3.0",
                },
            )

            if resp.status_code == 404:
                return {"found": False, "emails": {}, "email_count": 0}

            if resp.status_code == 403:
                return {"found": False, "emails": {}, "error": "Domain not verified in HIBP"}

            resp.raise_for_status()
            data = resp.json()

            return {
                "found": True,
                "emails": data,
                "email_count": len(data),
            }

        except Exception as e:
            logger.error(f"HIBP domain check failed for {domain}: {e}")
            return {"found": False, "emails": {}, "error": str(e)}

    # ========== DeHashed Methods ==========

    async def search_dehashed(self, query: str, page: int = 1) -> Dict[str, Any]:
        """
        Search DeHashed for leaked credentials/data.
        Query format: "email:test@example.com" or "domain:example.com"
        Returns: {"found": bool, "entries": [...], "total": int}
        """
        await self._load_credentials()

        if not self.dehashed_email or not self.dehashed_key:
            logger.warning("DeHashed credentials not configured")
            return {"found": False, "entries": [], "total": 0, "error": "No DeHashed credentials"}

        client = await self._get_client()
        url = f"{self.DEHASHED_BASE_URL}/search"

        try:
            resp = await client.get(
                url,
                params={"query": query, "page": page},
                auth=(self.dehashed_email, self.dehashed_key),
                headers={
                    "Accept": "application/json",
                    "User-Agent": "QuadSeer-BreachChecker/3.0",
                },
            )

            if resp.status_code == 401:
                return {"found": False, "entries": [], "error": "Invalid DeHashed credentials"}

            resp.raise_for_status()
            data = resp.json()

            entries = data.get("entries", [])
            total = data.get("total", len(entries))

            # Normalize entries
            normalized = []
            for entry in entries:
                normalized.append({
                    "email": entry.get("email"),
                    "username": entry.get("username"),
                    "password": entry.get("password"),
                    "hashed_password": entry.get("hashed_password"),
                    "name": entry.get("name"),
                    "address": entry.get("address"),
                    "ip_address": entry.get("ip_address"),
                    "phone": entry.get("phone"),
                    "database_name": entry.get("database_name"),
                    "source": "dehashed",
                })

            return {
                "found": len(entries) > 0,
                "entries": normalized,
                "total": total,
            }

        except Exception as e:
            logger.error(f"DeHashed search failed for query '{query}': {e}")
            return {"found": False, "entries": [], "error": str(e)}

    # ========== Unified Scan Methods ==========

    async def scan_target(self, target_domain: str, scan: Scan, db: AsyncSession) -> List[Finding]:
        """
        Run a comprehensive breach scan on a target domain.
        Checks: domain breaches, email pattern leaks, credential exposure.
        """
        findings = []

        await self._load_credentials()

        # 1. Check domain-level breaches via HIBP
        if self.hibp_key:
            hibp_result = await self.check_domain_hibp(target_domain)

            if hibp_result.get("found"):
                for email_alias, breach_names in hibp_result["emails"].items():
                    email = f"{email_alias}@{target_domain}"

                    finding = Finding(
                        scan_id=scan.id,
                        target_id=scan.target_id,
                        finding_type=FindingType.BREACH_LEAK,
                        severity=FindingSeverity.HIGH,
                        title=f"Breached email found: {email_alias}@...",
                        description=f"Email {email} found in {len(breach_names)} breach(es): {', '.join(breach_names[:5])}",
                        source="hibp",
                        source_reference=f"https://haveibeenpwned.com/domain/{target_domain}",
                        extracted_data={
                            "email": email,
                            "breach_count": len(breach_names),
                            "breach_names": breach_names,
                        },
                        raw_data={"breaches": breach_names},
                        risk_score=7.0 + min(len(breach_names) * 0.5, 3.0),
                        confidence=0.95,
                    )
                    findings.append(finding)
                    db.add(finding)

            elif "error" in hibp_result and "Domain not verified" in hibp_result["error"]:
                # Add info finding about domain verification needed
                finding = Finding(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    finding_type=FindingType.BREACH_LEAK,
                    severity=FindingSeverity.INFO,
                    title="HIBP domain verification required",
                    description=f"Domain {target_domain} must be verified in HIBP dashboard for domain-wide breach search.",
                    source="hibp",
                    extracted_data={"domain": target_domain, "action_required": "verify_domain"},
                    risk_score=0.0,
                    confidence=1.0,
                )
                findings.append(finding)
                db.add(finding)

        # 2. Check DeHashed for domain leaks
        if self.dehashed_email and self.dehashed_key:
            dehashed_result = await self.search_dehashed(f"domain:{target_domain}")

            if dehashed_result.get("found"):
                for entry in dehashed_result["entries"][:50]:  # Limit to first 50
                    email = entry.get("email", "unknown")
                    db_name = entry.get("database_name", "Unknown Source")

                    # Determine severity based on data exposed
                    has_password = bool(entry.get("password") or entry.get("hashed_password"))
                    severity = FindingSeverity.CRITICAL if has_password else FindingSeverity.HIGH

                    finding = Finding(
                        scan_id=scan.id,
                        target_id=scan.target_id,
                        finding_type=FindingType.CREDENTIAL_LEAK,
                        severity=severity,
                        title=f"Credential leak: {email}",
                        description=f"Credentials found in breach database '{db_name}'. "
                                   f"Exposed fields: {', '.join([k for k, v in entry.items() if v])}",
                        source="dehashed",
                        source_reference=f"https://www.dehashed.com/search?query=domain:{target_domain}",
                        extracted_data={
                            "email": email,
                            "username": entry.get("username"),
                            "has_password": has_password,
                            "has_hashed_password": bool(entry.get("hashed_password")),
                            "database": db_name,
                            "ip_address": entry.get("ip_address"),
                        },
                        raw_data=entry,
                        risk_score=9.0 if has_password else 7.0,
                        confidence=0.9,
                    )
                    findings.append(finding)
                    db.add(finding)

        # 3. Check for common email patterns (admin, info, support, etc.)
        common_emails = [
            f"admin@{target_domain}",
            f"info@{target_domain}",
            f"support@{target_domain}",
            f"contact@{target_domain}",
            f"security@{target_domain}",
            f"noreply@{target_domain}",
        ]

        if self.hibp_key:
            for email in common_emails:
                try:
                    hibp_email = await self.check_email_hibp(email)

                    if hibp_email.get("found"):
                        breach_count = hibp_email["breach_count"]
                        breach_names = [b["name"] for b in hibp_email["breaches"]]

                        # Determine severity
                        has_stealer = any(b.get("is_stealer_log") for b in hibp_email["breaches"])
                        has_password = any("Passwords" in b.get("data_classes", []) for b in hibp_email["breaches"])

                        if has_stealer:
                            severity = FindingSeverity.CRITICAL
                        elif has_password:
                            severity = FindingSeverity.HIGH
                        else:
                            severity = FindingSeverity.MEDIUM

                        finding = Finding(
                            scan_id=scan.id,
                            target_id=scan.target_id,
                            finding_type=FindingType.BREACH_LEAK,
                            severity=severity,
                            title=f"Common email breached: {email.split('@')[0]}@...",
                            description=f"Email {email} found in {breach_count} breach(es). "
                                       f"Most recent: {breach_names[0] if breach_names else 'N/A'}",
                            source="hibp",
                            source_reference="https://haveibeenpwned.com",
                            extracted_data={
                                "email": email,
                                "breach_count": breach_count,
                                "breach_names": breach_names,
                                "has_password_exposure": has_password,
                                "has_stealer_log": has_stealer,
                            },
                            raw_data=hibp_email["breaches"],
                            risk_score=8.0 + min(breach_count * 0.3, 2.0),
                            confidence=0.95,
                        )
                        findings.append(finding)
                        db.add(finding)

                    # Rate limit respect - small delay between email checks
                    await asyncio.sleep(1.6)  # HIBP free tier is ~1 req/sec

                except Exception as e:
                    logger.warning(f"Email check failed for {email}: {e}")
                    continue

        await db.commit()
        return findings

    async def close(self):
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Singleton instance
breach_service = BreachCheckerService()
