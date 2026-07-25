"""
Threat Intelligence Service
"""
import requests
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'QuadSeer/3.0 Threat Intelligence Scanner'
        })

    async def check_threats(self, domain: str) -> List[Dict[str, Any]]:
        findings = []

        # Check URLVoid/URLhaus style checks (simulated)
        # In production, integrate with real threat intel APIs

        # Check for suspicious patterns in domain
        suspicious = ['phishing', 'malware', 'botnet', 'c2']
        domain_lower = domain.lower()

        for pattern in suspicious:
            if pattern in domain_lower:
                findings.append({
                    "type": "suspicious_domain",
                    "severity": "medium",
                    "details": f"Domain contains suspicious pattern: '{pattern}'",
                    "pattern": pattern
                })

        # Check for subdomain takeover indicators
        takeover_indicators = ['github.io', 'herokuapp.com', 'azurewebsites.net', 
                               'cloudfront.net', 's3.amazonaws.com']
        for indicator in takeover_indicators:
            if indicator in domain_lower:
                findings.append({
                    "type": "subdomain_takeover_risk",
                    "severity": "low",
                    "details": f"Domain uses third-party service: {indicator} - check for takeover risk",
                    "service": indicator
                })

        return findings
