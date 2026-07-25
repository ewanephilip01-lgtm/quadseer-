"""
DNS Reconnaissance Service
"""
import dns.resolver
import dns.zone
import socket
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class DNSReconService:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def recon_domain(self, domain: str) -> List[Dict[str, Any]]:
        findings = []

        # A records
        try:
            answers = self.resolver.resolve(domain, 'A')
            for rdata in answers:
                findings.append({
                    "type": "dns_a",
                    "asset": domain,
                    "details": f"A record: {rdata.address}",
                    "ip": rdata.address
                })
        except Exception as e:
            logger.debug(f"No A records for {domain}: {e}")

        # MX records
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                findings.append({
                    "type": "dns_mx",
                    "asset": domain,
                    "details": f"MX record: {rdata.exchange} (priority {rdata.preference})",
                    "exchange": str(rdata.exchange),
                    "priority": rdata.preference
                })
        except Exception as e:
            logger.debug(f"No MX records for {domain}: {e}")

        # NS records
        try:
            answers = self.resolver.resolve(domain, 'NS')
            for rdata in answers:
                findings.append({
                    "type": "dns_ns",
                    "asset": domain,
                    "details": f"NS record: {rdata.target}",
                    "nameserver": str(rdata.target)
                })
        except Exception as e:
            logger.debug(f"No NS records for {domain}: {e}")

        # TXT records (SPF, DMARC)
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata)
                if 'v=spf1' in txt:
                    findings.append({
                        "type": "dns_spf",
                        "asset": domain,
                        "details": f"SPF record found",
                        "record": txt
                    })
                elif 'v=DMARC1' in txt:
                    findings.append({
                        "type": "dns_dmarc",
                        "asset": domain,
                        "details": f"DMARC record found",
                        "record": txt
                    })
                else:
                    findings.append({
                        "type": "dns_txt",
                        "asset": domain,
                        "details": f"TXT record: {txt[:100]}",
                        "record": txt
                    })
        except Exception as e:
            logger.debug(f"No TXT records for {domain}: {e}")

        # Subdomain enumeration (common subdomains)
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'dev', 'staging', 'test']
        for sub in common_subs:
            sub_domain = f"{sub}.{domain}"
            try:
                answers = self.resolver.resolve(sub_domain, 'A')
                for rdata in answers:
                    findings.append({
                        "type": "dns_subdomain",
                        "asset": sub_domain,
                        "details": f"Subdomain found: {sub_domain} -> {rdata.address}",
                        "subdomain": sub_domain,
                        "ip": rdata.address
                    })
            except Exception:
                pass

        return findings
