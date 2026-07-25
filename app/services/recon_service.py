"""External Attack Surface Management — Asset Discovery Engine.

Orchestrates multiple reconnaissance modules to discover and inventory
all internet-facing assets associated with a target.
"""
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.target import Target
from app.models.asset import Asset, AssetType, AssetStatus
from app.services.dns_enum import DNSEnumerator
from app.services.port_scanner import PortScanner
from app.services.ssl_monitor import SSLMonitor
from app.services.tech_fingerprint import TechnologyFingerprinter
from app.services.shodan_client import ShodanClient
from app.services.censys_client import CensysClient
from app.services.websocket_notifier import notify_scan_progress


class ReconService:
    """Main EASM orchestrator."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.dns = DNSEnumerator()
        self.port_scanner = PortScanner()
        self.ssl = SSLMonitor()
        self.tech = TechnologyFingerprinter()
        self.shodan = ShodanClient()
        self.censys = CensysClient()

    async def discover_assets(self, target_id: int, owner_id: int, 
                            scan_id: Optional[int] = None) -> List[Asset]:
        """Full asset discovery pipeline for a target."""

        result = await self.db.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one_or_none()
        if not target:
            raise ValueError(f"Target {target_id} not found")

        assets = []
        value = target.value

        # Phase 1: DNS Enumeration
        if scan_id:
            await notify_scan_progress(scan_id, 5, "running", "Starting DNS enumeration...")
        dns_assets = await self._dns_phase(target, owner_id)
        assets.extend(dns_assets)

        # Phase 2: Port Scanning
        if scan_id:
            await notify_scan_progress(scan_id, 25, "running", "Port scanning discovered hosts...")
        hosts = [a.value for a in dns_assets if a.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP)]
        if target.target_type.value == "ip":
            hosts.append(value)
        port_assets = await self._port_phase(target, hosts, owner_id)
        assets.extend(port_assets)

        # Phase 3: SSL Certificate Analysis
        if scan_id:
            await notify_scan_progress(scan_id, 45, "running", "Analyzing SSL certificates...")
        ssl_assets = await self._ssl_phase(target, hosts, owner_id)
        assets.extend(ssl_assets)

        # Phase 4: Technology Fingerprinting
        if scan_id:
            await notify_scan_progress(scan_id, 60, "running", "Fingerprinting technologies...")
        web_hosts = [a.value for a in port_assets if a.ports and any(p.get("service") in ("http", "https") for p in a.ports)]
        tech_assets = await self._tech_phase(target, web_hosts, owner_id)
        assets.extend(tech_assets)

        # Phase 5: External Intelligence
        if scan_id:
            await notify_scan_progress(scan_id, 80, "running", "Querying external intelligence...")
        intel_assets = await self._intel_phase(target, value, owner_id)
        assets.extend(intel_assets)

        # Phase 6: Risk Scoring
        if scan_id:
            await notify_scan_progress(scan_id, 95, "running", "Calculating risk scores...")
        await self._score_assets(assets)

        for asset in assets:
            self.db.add(asset)
        await self.db.commit()

        if scan_id:
            await notify_scan_progress(scan_id, 100, "completed", f"Discovered {len(assets)} assets")

        return assets

    async def _dns_phase(self, target: Target, owner_id: int) -> List[Asset]:
        """DNS enumeration phase."""
        assets = []
        value = target.value

        assets.append(Asset(
            name=target.name,
            value=value,
            asset_type=AssetType.DOMAIN,
            target_id=target.id,
            owner_id=owner_id,
            source="dns_enum",
            confidence=1.0,
        ))

        subdomains = await self.dns.enumerate_subdomains(value)
        for sub in subdomains:
            assets.append(Asset(
                name=sub,
                value=sub,
                asset_type=AssetType.SUBDOMAIN,
                target_id=target.id,
                owner_id=owner_id,
                source="dns_enum",
                confidence=0.9,
                parent_id=assets[0].id if assets else None,
            ))

        records = await self.dns.get_dns_records(value)
        for rtype, values in records.items():
            for val in values:
                if rtype == "A" or rtype == "AAAA":
                    assets.append(Asset(
                        name=f"{value} ({rtype})",
                        value=val,
                        asset_type=AssetType.IP,
                        target_id=target.id,
                        owner_id=owner_id,
                        source="dns_enum",
                        confidence=1.0,
                        enrichment_data={"dns_record_type": rtype},
                    ))
                elif rtype == "MX":
                    assets.append(Asset(
                        name=f"MX: {val}",
                        value=val,
                        asset_type=AssetType.SERVICE,
                        target_id=target.id,
                        owner_id=owner_id,
                        source="dns_enum",
                        confidence=0.95,
                        enrichment_data={"service_type": "mail", "dns_record_type": rtype},
                    ))

        return assets

    async def _port_phase(self, target: Target, hosts: List[str], owner_id: int) -> List[Asset]:
        """Port scanning phase."""
        assets = []

        for host in hosts:
            ip = await self.dns.resolve_host(host)
            if not ip:
                continue

            open_ports = await self.port_scanner.scan_host(ip, ports="top100")

            if open_ports:
                port_data = []
                for port_info in open_ports:
                    port_data.append({
                        "port": port_info["port"],
                        "service": port_info.get("service", "unknown"),
                        "banner": port_info.get("banner", "")[:500],
                        "state": port_info.get("state", "open"),
                    })

                assets.append(Asset(
                    name=f"Host: {host}",
                    value=ip,
                    asset_type=AssetType.IP,
                    target_id=target.id,
                    owner_id=owner_id,
                    source="port_scan",
                    confidence=1.0,
                    ports=port_data,
                    enrichment_data={"original_host": host, "scan_type": "top100"},
                ))

                for pd in port_data:
                    if pd["service"] in ("http", "https"):
                        assets.append(Asset(
                            name=f"{host}:{pd['port']}",
                            value=f"{'https' if pd['port'] == 443 else 'http'}://{host}:{pd['port']}",
                            asset_type=AssetType.WEB_APP,
                            target_id=target.id,
                            owner_id=owner_id,
                            source="port_scan",
                            confidence=1.0,
                            ports=[pd],
                        ))

        return assets

    async def _ssl_phase(self, target: Target, hosts: List[str], owner_id: int) -> List[Asset]:
        """SSL certificate analysis phase."""
        assets = []

        for host in hosts:
            ssl_info = await self.ssl.analyze_certificate(host, port=443)
            if ssl_info:
                risk_factors = []
                if ssl_info.get("expired"):
                    risk_factors.append("expired_ssl")
                if ssl_info.get("self_signed"):
                    risk_factors.append("self_signed_cert")
                if ssl_info.get("weak_cipher"):
                    risk_factors.append("weak_ssl_cipher")
                if ssl_info.get("tls_version") in ("TLSv1", "TLSv1.1"):
                    risk_factors.append("deprecated_tls")

                assets.append(Asset(
                    name=f"SSL: {host}",
                    value=host,
                    asset_type=AssetType.CERTIFICATE,
                    target_id=target.id,
                    owner_id=owner_id,
                    source="ssl_cert",
                    confidence=1.0,
                    ssl_info=ssl_info,
                    risk_factors=risk_factors,
                    risk_score=min(len(risk_factors) * 15, 100),
                ))

        return assets

    async def _tech_phase(self, target: Target, web_hosts: List[str], owner_id: int) -> List[Asset]:
        """Technology fingerprinting phase."""
        assets = []

        for url in web_hosts:
            if not url.startswith("http"):
                url = f"http://{url}"

            fingerprint = await self.tech.fingerprint(url)
            if fingerprint:
                assets.append(Asset(
                    name=f"Tech: {url}",
                    value=url,
                    asset_type=AssetType.WEB_APP,
                    target_id=target.id,
                    owner_id=owner_id,
                    source="tech_fingerprint",
                    confidence=0.85,
                    technologies=fingerprint.get("technologies", []),
                    headers=fingerprint.get("headers", {}),
                    enrichment_data={
                        "server": fingerprint.get("server"),
                        "framework": fingerprint.get("framework"),
                        "cms": fingerprint.get("cms"),
                    },
                ))

        return assets

    async def _intel_phase(self, target: Target, query: str, owner_id: int) -> List[Asset]:
        """External intelligence phase."""
        assets = []

        shodan_results = await self.shodan.search_host(query)
        for result in shodan_results:
            assets.append(Asset(
                name=f"Shodan: {result.get('ip_str', query)}",
                value=result.get("ip_str", query),
                asset_type=AssetType.IP,
                target_id=target.id,
                owner_id=owner_id,
                source="shodan",
                confidence=0.9,
                ports=result.get("ports", []),
                technologies=result.get("tags", []),
                geo_location=result.get("location", {}),
                enrichment_data={"shodan_data": result},
            ))

        censys_results = await self.censys.search_host(query)
        for result in censys_results:
            assets.append(Asset(
                name=f"Censys: {result.get('ip', query)}",
                value=result.get("ip", query),
                asset_type=AssetType.IP,
                target_id=target.id,
                owner_id=owner_id,
                source="censys",
                confidence=0.9,
                enrichment_data={"censys_data": result},
            ))

        return assets

    async def _score_assets(self, assets: List[Asset]):
        """Calculate risk scores for all assets."""
        for asset in assets:
            score = 0
            factors = asset.risk_factors or []

            if asset.ssl_info:
                if asset.ssl_info.get("expired"):
                    score += 25
                if asset.ssl_info.get("self_signed"):
                    score += 20
                if asset.ssl_info.get("tls_version") in ("TLSv1", "TLSv1.1"):
                    score += 15

            if asset.ports:
                risky_ports = [3389, 22, 21, 23, 445, 135, 3306, 5432, 27017, 6379, 9200]
                for p in asset.ports:
                    if p.get("port") in risky_ports:
                        score += 10
                        factors.append(f"exposed_service_{p['port']}")

            if asset.technologies:
                old_tech = ["Apache/1.", "nginx/1.0", "IIS/6", "PHP/5.", "Windows-NT/5"]
                for tech in asset.technologies:
                    for old in old_tech:
                        if old in tech:
                            score += 10
                            factors.append(f"outdated_tech:{tech}")

            asset.risk_score = min(score, 100)
            asset.risk_factors = list(set(factors))

    async def get_asset_inventory(self, target_id: int, owner_id: int) -> List[Asset]:
        """Get full asset inventory for a target."""
        result = await self.db.execute(
            select(Asset)
            .where((Asset.target_id == target_id) & (Asset.owner_id == owner_id))
            .order_by(Asset.risk_score.desc(), Asset.created_at.desc())
        )
        return result.scalars().all()

    async def get_asset_stats(self, target_id: int, owner_id: int) -> Dict[str, Any]:
        """Get asset statistics."""
        from sqlalchemy import func

        total = await self.db.execute(
            select(func.count(Asset.id)).where((Asset.target_id == target_id) & (Asset.owner_id == owner_id))
        )
        high_risk = await self.db.execute(
            select(func.count(Asset.id)).where(
                (Asset.target_id == target_id) & (Asset.owner_id == owner_id) & (Asset.risk_score >= 50)
            )
        )

        by_type = await self.db.execute(
            select(Asset.asset_type, func.count(Asset.id))
            .where((Asset.target_id == target_id) & (Asset.owner_id == owner_id))
            .group_by(Asset.asset_type)
        )

        return {
            "total_assets": total.scalar(),
            "high_risk_assets": high_risk.scalar(),
            "by_type": {t.value: c for t, c in by_type.all()},
        }
