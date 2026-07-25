"""Censys API client for external intelligence."""
import os
import base64
from typing import List, Dict, Any, Optional
import httpx


class CensysClient:
    """Censys Search API v2 client."""

    BASE_URL = "https://search.censys.io/api/v2"

    def __init__(self, api_id: str = None, api_secret: str = None):
        self.api_id = api_id or os.getenv("CENSYS_API_ID")
        self.api_secret = api_secret or os.getenv("CENSYS_API_SECRET")

    def _get_auth(self) -> tuple:
        """Get HTTP Basic Auth credentials."""
        return (self.api_id, self.api_secret)

    async def search_host(self, query: str) -> List[Dict[str, Any]]:
        """Search Censys for hosts matching query."""
        if not self.api_id or not self.api_secret:
            return []

        results = []

        # Try hosts search
        hosts = await self._search_hosts(query)
        results.extend(hosts)

        # Try certificates search
        certs = await self._search_certificates(query)
        results.extend(certs)

        return results

    async def _search_hosts(self, query: str) -> List[Dict[str, Any]]:
        """Search Censys hosts index."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.BASE_URL}/hosts/search",
                    auth=self._get_auth(),
                    params={"q": query, "per_page": 20}
                )
                if response.status_code == 200:
                    data = response.json()
                    return [{
                        "ip": r.get("ip"),
                        "services": [s.get("service_name", "unknown") for s in r.get("services", [])],
                        "ports": [s.get("port") for s in r.get("services", [])],
                        "location": r.get("location", {}),
                        "autonomous_system": r.get("autonomous_system", {}),
                        "operating_system": r.get("operating_system", {}),
                        "source": "censys_hosts",
                    } for r in data.get("result", {}).get("hits", [])]
        except Exception:
            pass
        return []

    async def _search_certificates(self, query: str) -> List[Dict[str, Any]]:
        """Search Censys certificates index."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.BASE_URL}/certificates/search",
                    auth=self._get_auth(),
                    params={"q": query, "per_page": 10}
                )
                if response.status_code == 200:
                    data = response.json()
                    return [{
                        "fingerprint": r.get("fingerprint_sha256"),
                        "names": r.get("names", []),
                        "parsed": r.get("parsed", {}),
                        "source": "censys_certs",
                    } for r in data.get("result", {}).get("hits", [])]
        except Exception:
            pass
        return []

    async def view_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get detailed host information."""
        if not self.api_id or not self.api_secret:
            return None

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"{self.BASE_URL}/hosts/{ip}",
                    auth=self._get_auth()
                )
                if response.status_code == 200:
                    return response.json().get("result", {})
        except Exception:
            pass
        return None
