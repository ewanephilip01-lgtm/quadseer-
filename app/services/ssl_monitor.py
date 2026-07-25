"""
SSL/TLS Certificate Monitoring Service
Fixed: Uses ssl stdlib with proper error handling instead of relying solely on pyopenssl
"""
import ssl
import socket
import datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class SSLMonitorService:
    """Service for analyzing SSL/TLS certificates."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def analyze_certificate(self, domain: str, port: int = 443) -> List[Dict[str, Any]]:
        """
        Analyze SSL certificate for a domain.
        Uses stdlib ssl module with fallback handling.
        """
        findings = []

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We want to analyze even expired/invalid certs

            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    if not cert:
                        findings.append({
                            "type": "ssl_error",
                            "severity": "medium",
                            "details": f"No certificate presented by {domain}:{port}",
                            "domain": domain,
                            "port": port
                        })
                        return findings

                    # Parse certificate info
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))

                    not_after = cert.get("notAfter")
                    not_before = cert.get("notBefore")

                    # Calculate days until expiry
                    expiry_date = self._parse_date(not_after)
                    days_until_expiry = (expiry_date - datetime.datetime.utcnow()).days

                    # Build finding
                    finding = {
                        "type": "ssl_certificate",
                        "domain": domain,
                        "port": port,
                        "subject": subject.get("commonName", "N/A"),
                        "issuer": issuer.get("commonName", "N/A"),
                        "not_before": not_before,
                        "not_after": not_after,
                        "expiry_date": expiry_date.isoformat() if expiry_date else None,
                        "days_until_expiry": days_until_expiry,
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else "N/A",
                        "san": cert.get("subjectAltName", []),
                        "serial_number": cert.get("serialNumber"),
                    }

                    # Determine severity based on certificate status
                    if days_until_expiry < 0:
                        finding["severity"] = "critical"
                        finding["details"] = f"Certificate EXPIRED {abs(days_until_expiry)} days ago"
                    elif days_until_expiry < 7:
                        finding["severity"] = "critical"
                        finding["details"] = f"Certificate expires in {days_until_expiry} days - IMMEDIATE ACTION REQUIRED"
                    elif days_until_expiry < 30:
                        finding["severity"] = "high"
                        finding["details"] = f"Certificate expires in {days_until_expiry} days - renewal recommended"
                    else:
                        finding["severity"] = "info"
                        finding["details"] = f"Certificate valid for {days_until_expiry} days"

                    # Check for weak TLS version
                    if version in ["TLSv1", "TLSv1.1"]:
                        finding["severity"] = "high"
                        finding["details"] += " | Weak TLS version detected"

                    # Check for self-signed
                    if subject.get("commonName") == issuer.get("commonName"):
                        finding["severity"] = "medium"
                        finding["details"] += " | Self-signed certificate detected"

                    findings.append(finding)

        except socket.timeout:
            logger.warning(f"SSL connection timeout for {domain}:{port}")
            findings.append({
                "type": "ssl_error",
                "severity": "medium",
                "details": f"Connection timeout analyzing SSL for {domain}:{port}",
                "domain": domain,
                "port": port
            })
        except socket.gaierror:
            logger.warning(f"Could not resolve {domain}")
            findings.append({
                "type": "ssl_error",
                "severity": "info",
                "details": f"Could not resolve domain {domain}",
                "domain": domain,
                "port": port
            })
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {domain}: {e}")
            findings.append({
                "type": "ssl_error",
                "severity": "medium",
                "details": f"SSL handshake failed: {str(e)}",
                "domain": domain,
                "port": port
            })
        except ConnectionRefusedError:
            findings.append({
                "type": "ssl_error",
                "severity": "info",
                "details": f"Connection refused on port {port} for {domain}",
                "domain": domain,
                "port": port
            })
        except Exception as e:
            logger.error(f"Unexpected error analyzing SSL for {domain}: {e}")
            findings.append({
                "type": "ssl_error",
                "severity": "low",
                "details": f"Error analyzing SSL: {str(e)}",
                "domain": domain,
                "port": port
            })

        return findings

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime.datetime]:
        """Parse SSL certificate date string."""
        if not date_str:
            return None
        try:
            # SSL date format: 'Mar 15 12:00:00 2024 GMT'
            return datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            try:
                return datetime.datetime.strptime(date_str, "%Y%m%d%H%M%SZ")
            except ValueError:
                return None

    async def check_cipher_strength(self, domain: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check cipher suite strength."""
        findings = []
        weak_ciphers = [
            "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5",
            "aNULL", "eNULL"
        ]

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in weak_ciphers:
                            if weak.lower() in cipher_name.lower():
                                findings.append({
                                    "type": "weak_cipher",
                                    "severity": "high",
                                    "details": f"Weak cipher detected: {cipher_name}",
                                    "cipher": cipher_name,
                                    "domain": domain
                                })
                                break
        except Exception as e:
            logger.debug(f"Could not check cipher strength for {domain}: {e}")

        return findings
