"""
Finding model for storing scan results across all Phase 2 services.
"""
import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum, JSON, Float
from sqlalchemy.orm import relationship

from app.core.database import Base


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, enum.Enum):
    # ASM findings
    DNS_RECORD = "dns_record"
    OPEN_PORT = "open_port"
    SSL_CERT = "ssl_cert"
    SSL_ISSUE = "ssl_issue"
    TECH_STACK = "tech_stack"
    SUBDOMAIN = "subdomain"
    VULNERABILITY = "vulnerability"

    # CTI findings
    DARKWEB_MENTION = "darkweb_mention"
    BREACH_LEAK = "breach_leak"
    RANSOMWARE_VICTIM = "ransomware_victim"
    THREAT_ACTOR = "threat_actor"
    MALWARE_IOC = "malware_ioc"
    PHISHING_DOMAIN = "phishing_domain"

    # Brand protection
    TYPO_SQUAT = "typosquat"
    BRAND_IMPERSONATION = "brand_impersonation"
    EXECUTIVE_EXPOSURE = "executive_exposure"
    CREDENTIAL_LEAK = "credential_leak"
    SOURCE_CODE_LEAK = "source_code_leak"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)

    finding_type = Column(Enum(FindingType), nullable=False, index=True)
    severity = Column(Enum(FindingSeverity), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)

    # Source information
    source = Column(String(100))  # e.g., "hibp", "dehashed", "ransomware.live", "darkweb"
    source_reference = Column(String(500))  # URL, ID, or reference

    # Structured data specific to finding type
    raw_data = Column(JSON)  # Complete raw response/data
    extracted_data = Column(JSON)  # Normalized extracted fields

    # Risk scoring
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=1.0)  # 0.0 to 1.0

    # Status tracking
    status = Column(String(50), default="open")  # open, acknowledged, resolved, false_positive
    assigned_to = Column(String(100))

    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    target = relationship("Target", back_populates="findings")
