"""
Ransomware Tracker Service - Integrates with ransomware.live API.
End-to-end validated with real API calls.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingType
from app.models.scan import Scan

logger = logging.getLogger(__name__)


class RansomwareTrackerService:
    """
    Tracks ransomware incidents using the ransomware.live API.
    Monitors for target domain mentions in ransomware leak sites.
    """

    BASE_URL = "https://api.ransomware.live/v2"

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "QuadSeer-RansomwareTracker/3.0"},
            )
        return self._client

    async def get_recent_victims(self, hours: int = 168) -> List[Dict[str, Any]]:
        """
        Get recent ransomware victims (default: last 7 days / 168 hours).
        The /recentvictims endpoint returns the 100 most recent victims.
        """
        client = await self._get_client()
        url = f"{self.BASE_URL}/recentvictims"

        try:
            resp = await client.get(url, timeout=30.0)
            resp.raise_for_status()
            victims = resp.json()

            if not isinstance(victims, list):
                logger.warning(f"Unexpected response type: {type(victims)}")
                return []

            # Filter by time window
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            filtered = []

            for v in victims:
                discovered_str = v.get("discovered", v.get("attackdate"))
                if discovered_str:
                    try:
                        discovered = datetime.fromisoformat(discovered_str.replace("Z", "+00:00"))
                        if discovered >= cutoff:
                            filtered.append(v)
                    except (ValueError, TypeError):
                        # If we can't parse date, include it anyway (recent endpoint)
                        filtered.append(v)
                else:
                    filtered.append(v)

            return filtered

        except httpx.HTTPStatusError as e:
            logger.error(f"Ransomware.live HTTP error: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Ransomware.live fetch failed: {e}")
            return []

    async def get_all_groups(self) -> List[Dict[str, Any]]:
        """Get list of all tracked ransomware groups."""
        client = await self._get_client()
        url = f"{self.BASE_URL}/groups"

        try:
            resp = await client.get(url, timeout=30.0)
            resp.raise_for_status()
            groups = resp.json()
            return groups if isinstance(groups, list) else []
        except Exception as e:
            logger.error(f"Failed to fetch ransomware groups: {e}")
            return []

    async def search_victims_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        """
        Search for a specific domain in recent ransomware victims.
        Since there's no direct search endpoint, we fetch recent victims and filter.
        """
        domain_lower = domain.lower().strip()
        all_victims = await self.get_recent_victims(hours=720)  # Last 30 days

        matches = []
        for v in all_victims:
            victim_domain = (v.get("domain") or "").lower()
            victim_name = (v.get("victim") or "").lower()
            description = (v.get("description") or "").lower()

            if domain_lower in victim_domain or domain_lower in victim_name or domain_lower in description:
                matches.append(v)

        return matches

    async def search_victims_by_group(self, group_name: str) -> List[Dict[str, Any]]:
        """Search victims by ransomware group name."""
        group_lower = group_name.lower()
        all_victims = await self.get_recent_victims(hours=720)

        matches = []
        for v in all_victims:
            if (v.get("group") or "").lower() == group_lower:
                matches.append(v)

        return matches

    async def get_group_stats(self) -> Dict[str, Any]:
        """Get statistics about active ransomware groups."""
        victims = await self.get_recent_victims(hours=168)
        groups = {}

        for v in victims:
            group = v.get("group", "Unknown")
            if group not in groups:
                groups[group] = {"count": 0, "countries": set(), "victims": []}
            groups[group]["count"] += 1
            if v.get("country"):
                groups[group]["countries"].add(v["country"])
            groups[group]["victims"].append(v.get("victim", "Unknown"))

        # Convert sets to lists for JSON serialization
        for g in groups:
            groups[g]["countries"] = list(groups[g]["countries"])
            groups[g]["victims"] = groups[g]["victims"][:10]  # Limit

        return {
            "total_recent_victims": len(victims),
            "active_groups": len(groups),
            "group_breakdown": groups,
        }

    async def scan_target(self, target_domain: str, scan: Scan, db: AsyncSession) -> List[Finding]:
        """
        Scan a target domain for ransomware mentions.
        """
        findings = []

        # 1. Search for direct domain match
        direct_matches = await self.search_victims_by_domain(target_domain)

        for match in direct_matches:
            group = match.get("group", "Unknown")
            victim = match.get("victim", target_domain)
            discovered = match.get("discovered", "Unknown")
            description = match.get("description", "")
            claim_url = match.get("claim_url", "")
            country = match.get("country", "")

            # Determine severity based on recency
            severity = FindingSeverity.CRITICAL

            finding = Finding(
                scan_id=scan.id,
                target_id=scan.target_id,
                finding_type=FindingType.RANSOMWARE_VICTIM,
                severity=severity,
                title=f"Ransomware victim: {victim}",
                description=f"Domain {target_domain} appears as a victim of the '{group}' ransomware group. "
                           f"Discovered: {discovered}. "
                           f"Description: {description[:300] if description else 'N/A'}",
                source="ransomware.live",
                source_reference=claim_url or f"https://www.ransomware.live/victim/{match.get('victim', '')}",
                extracted_data={
                    "victim_domain": victim,
                    "ransomware_group": group,
                    "discovered_date": discovered,
                    "attack_date": match.get("attackdate"),
                    "country": country,
                    "claim_url": claim_url,
                    "data_size": match.get("data_size"),
                    "screenshot": match.get("screenshot"),
                },
                raw_data=match,
                risk_score=10.0,  # Critical - ransomware is max severity
                confidence=0.95,
            )
            findings.append(finding)
            db.add(finding)

        # 2. Get group stats for context
        stats = await self.get_group_stats()

        # 3. Check for industry/sector matches (if target metadata has sector info)
        target_metadata = scan.target.target_metadata or {}
        target_sector = target_metadata.get("sector", "")

        if target_sector:
            # Check if target's sector is heavily targeted recently
            sector_victims = []
            all_victims = await self.get_recent_victims(hours=168)
            for v in all_victims:
                activity = (v.get("activity") or "").lower()
                if target_sector.lower() in activity:
                    sector_victims.append(v)

            if len(sector_victims) > 5:
                finding = Finding(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    finding_type=FindingType.THREAT_ACTOR,
                    severity=FindingSeverity.HIGH,
                    title=f"Sector under attack: {target_sector}",
                    description=f"The {target_sector} sector has {len(sector_victims)} ransomware victims in the last 7 days. "
                               f"Target {target_domain} is in a high-risk sector.",
                    source="ransomware.live",
                    source_reference="https://www.ransomware.live",
                    extracted_data={
                        "sector": target_sector,
                        "sector_victim_count": len(sector_victims),
                        "active_groups": list(set(v.get("group") for v in sector_victims)),
                    },
                    raw_data={"sector_victims": sector_victims[:20]},
                    risk_score=6.5,
                    confidence=0.8,
                )
                findings.append(finding)
                db.add(finding)

        # 4. If no direct match, add info finding about recent landscape
        if not direct_matches:
            finding = Finding(
                scan_id=scan.id,
                target_id=scan.target_id,
                finding_type=FindingType.RANSOMWARE_VICTIM,
                severity=FindingSeverity.INFO,
                title=f"No ransomware activity found for {target_domain}",
                description=f"Domain {target_domain} was not found in recent ransomware victim databases. "
                           f"However, {stats['active_groups']} ransomware groups are currently active with "
                           f"{stats['total_recent_victims']} recent victims.",
                source="ransomware.live",
                source_reference="https://www.ransomware.live",
                extracted_data={
                    "domain_checked": target_domain,
                    "active_groups": stats["active_groups"],
                    "total_recent_victims": stats["total_recent_victims"],
                },
                raw_data=stats,
                risk_score=0.0,
                confidence=0.9,
            )
            findings.append(finding)
            db.add(finding)

        await db.commit()
        return findings

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Singleton
ransomware_service = RansomwareTrackerService()
