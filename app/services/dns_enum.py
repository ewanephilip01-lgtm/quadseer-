"""DNS enumeration service — subdomain discovery and record analysis."""
import asyncio
import socket
from typing import List, Dict, Any, Optional
import dns.resolver
import dns.zone
import dns.query


class DNSEnumerator:
    """DNS enumeration for asset discovery."""

    # Common subdomain wordlist
    SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "localhost", "admin", "portal", "api", "app",
        "blog", "shop", "store", "cdn", "media", "static", "assets", "img",
        "dev", "test", "staging", "demo", "beta", "alpha", "v1", "v2", "v3",
        "secure", "vpn", "remote", "webmail", "email", "mx", "ns1", "ns2",
        "dns", "smtp", "pop", "imap", "webdisk", "cpanel", "whm", "webmin",
        "git", "gitlab", "github", "jenkins", "ci", "build", "deploy",
        "grafana", "prometheus", "kibana", "elastic", "db", "database",
        "mysql", "postgres", "mongo", "redis", "cache", "queue", "worker",
        "internal", "intranet", "extranet", "private", "corp", "enterprise",
        "support", "help", "docs", "wiki", "kb", "status", "monitor",
        "logs", "backup", "archive", "old", "legacy", "temp", "tmp",
    ]

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def enumerate_subdomains(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """Brute force subdomain enumeration."""
        words = wordlist or self.SUBDOMAIN_WORDLIST
        subdomains = set()

        # Try each wordlist entry
        tasks = [self._resolve_subdomain(f"{word}.{domain}") for word in words]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str):
                subdomains.add(result)

        # Certificate Transparency log search (simulated — real implementation would use crt.sh API)
        ct_subdomains = await self._query_ct_logs(domain)
        subdomains.update(ct_subdomains)

        return sorted(list(subdomains))

    async def _resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Try to resolve a subdomain. Return subdomain if exists."""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.resolver.resolve, subdomain, "A")
            return subdomain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return None
        except Exception:
            return None

    async def _query_ct_logs(self, domain: str) -> List[str]:
        """Query Certificate Transparency logs via crt.sh (simplified)."""
        # In production: Use httpx to query https://crt.sh/?q=%.{domain}&output=json
        # For now, return empty — implement when external APIs are configured
        return []

    async def get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get all DNS records for a domain."""
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]

        for rtype in record_types:
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(None, self.resolver.resolve, domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except Exception:
                pass

        return records

    async def resolve_host(self, host: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, host)
            return result
        except socket.gaierror:
            return None

    async def reverse_dns(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return result[0]
        except socket.herror:
            return None

    async def check_zone_transfer(self, domain: str) -> List[str]:
        """Check for DNS zone transfer vulnerability."""
        vuln_records = []
        try:
            # Get NS records
            ns_records = await self.get_dns_records(domain)
            ns_servers = ns_records.get("NS", [])

            for ns in ns_servers:
                try:
                    loop = asyncio.get_event_loop()
                    zone = await loop.run_in_executor(None, dns.zone.from_xfr, dns.query.xfr(ns, domain))
                    # If we get here, zone transfer succeeded — major vulnerability
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            vuln_records.append(f"{name} {rdataset.rdtype} {rdataset}")
                except Exception:
                    pass
        except Exception:
            pass

        return vuln_records
