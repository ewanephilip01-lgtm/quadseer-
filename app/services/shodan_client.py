"""Shodan API client for external intelligence."""
import os
from typing import List, Dict, Any, Optional
import httpx
from app.core.config import settings


class ShodanClient:
    """Shodan InternetDB and API client."""

    BASE_URL = "https://api.shodan.io"
    INTERNETDB_URL = "https://internetdb.shodan.io"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")

    async def search_host(self, query: str) -> List[Dict[str, Any]]:
        """Search Shodan for a host/IP/domain.

        Uses InternetDB (free, no API key) for basic info,
        falls back to Shodan API if key is available.
        """
        results = []

        # Try InternetDB first (free, no auth)
        internetdb = await self._internetdb_lookup(query)
        if internetdb:
            results.append(internetdb)

        # If API key available, get detailed info
        if self.api_key:
            detailed = await self._api_host_lookup(query)
            if detailed:
                results.append(detailed)

        return results

    async def _internetdb_lookup(self, query: str) -> Optional[Dict[str, Any]]:
        """Query Shodan InternetDB (free, no API key required)."""
        try:
            # Resolve domain to IP if needed
            import socket
            try:
                ip = socket.gethostbyname(query)
            except socket.gaierror:
                ip = query

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.INTERNETDB_URL}/{ip}")
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "ip_str": ip,
                        "ports": [{"port": p, "service": "unknown"} for p in data.get("ports", [])],
                        "tags": data.get("tags", []),
                        "vulns": data.get("vulns", []),
                        "hostnames": data.get("hostnames", []),
                        "source": "shodan_internetdb",
                        "location": {},
                    }
        except Exception:
            pass
        return None

    async def _api_host_lookup(self, query: str) -> Optional[Dict[str, Any]]:
        """Query Shodan API (requires API key)."""
        try:
            import socket
            try:
                ip = socket.gethostbyname(query)
            except socket.gaierror:
                ip = query

            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.BASE_URL}/shodan/host/{ip}",
                    params={"key": self.api_key}
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "ip_str": data.get("ip_str", ip),
                        "ports": [{"port": d.get("port"), "service": d.get("product", "unknown"), "banner": d.get("data", "")[:200]} 
                                 for d in data.get("data", [])],
                        "tags": data.get("tags", []),
                        "vulns": list(data.get("vulns", {}).keys()),
                        "hostnames": data.get("hostnames", []),
                        "location": {
                            "country": data.get("country_name"),
                            "city": data.get("city"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                            "asn": data.get("asn"),
                            "org": data.get("org"),
                        },
                        "os": data.get("os"),
                        "isp": data.get("isp"),
                        "last_update": data.get("last_update"),
                        "source": "shodan_api",
                    }
        except Exception:
            pass
        return None

    async def search_query(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Perform Shodan search query (requires API key)."""
        if not self.api_key:
            return []

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.BASE_URL}/shodan/host/search",
                    params={"key": self.api_key, "query": query, "limit": limit}
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("matches", [])
        except Exception:
            pass
        return []
