"""
Port Scanning Service
"""
import socket
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class PortScanService:
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    async def scan_target(self, domain: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())

        findings = []

        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            logger.warning(f"Could not resolve {domain}")
            return findings

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    service = self.COMMON_PORTS.get(port, "Unknown")
                    findings.append({
                        "type": "open_port",
                        "port": port,
                        "service": service,
                        "ip": ip,
                        "details": f"Port {port} ({service}) is open on {domain}"
                    })
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")

        return findings
