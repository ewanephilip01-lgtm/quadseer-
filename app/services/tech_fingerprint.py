"""
Technology Fingerprinting Service
"""
import requests
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class TechFingerprintService:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    async def fingerprint(self, domain: str) -> List[Dict[str, Any]]:
        findings = []
        url = f"https://{domain}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            headers = response.headers

            # Server header
            server = headers.get('Server', '')
            if server:
                findings.append({
                    "type": "server_header",
                    "technology": "Web Server",
                    "version": server,
                    "details": f"Server: {server}"
                })

            # X-Powered-By
            powered = headers.get('X-Powered-By', '')
            if powered:
                findings.append({
                    "type": "powered_by",
                    "technology": powered.split('/')[0] if '/' in powered else powered,
                    "version": powered.split('/')[1] if '/' in powered else "",
                    "details": f"X-Powered-By: {powered}"
                })

            # Framework detection from headers
            frameworks = {
                'X-Drupal-Cache': 'Drupal',
                'X-Generator': 'CMS',
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC'
            }

            for header, tech in frameworks.items():
                if header in headers:
                    findings.append({
                        "type": "framework",
                        "technology": tech,
                        "version": headers.get(header, ""),
                        "details": f"{header}: {headers[header]}"
                    })

            # Cookie analysis
            cookies = response.cookies
            for cookie in cookies:
                if 'wordpress' in cookie.name.lower():
                    findings.append({
                        "type": "cms",
                        "technology": "WordPress",
                        "version": "",
                        "details": f"WordPress cookie detected: {cookie.name}"
                    })
                elif 'django' in cookie.name.lower():
                    findings.append({
                        "type": "framework",
                        "technology": "Django",
                        "version": "",
                        "details": f"Django cookie detected: {cookie.name}"
                    })

        except requests.exceptions.SSLError:
            findings.append({
                "type": "ssl_error",
                "technology": "SSL",
                "version": "",
                "details": "SSL certificate verification failed"
            })
        except requests.exceptions.RequestException as e:
            logger.debug(f"Could not fingerprint {domain}: {e}")

        return findings
