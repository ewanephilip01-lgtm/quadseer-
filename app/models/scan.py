"""
Scan model with Phase 2 scan types.
"""
import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    # Phase 1 - ASM
    RECONNAISSANCE = "reconnaissance"
    DNS = "dns"
    PORT = "port"
    SSL = "ssl"
    TECH = "tech"

    # Phase 2 - CTI
    DARKWEB = "darkweb"
    BREACH = "breach"
    RANSOMWARE = "ransomware"
    THREAT_INTEL = "threat_intel"

    # Phase 2 - Brand Protection
    BRAND_MONITOR = "brand_monitor"
    EXECUTIVE_PROTECTION = "executive_protection"

    # Phase 3 - Advanced
    VULNERABILITY = "vulnerability"
    SUBDOMAIN = "subdomain"
    PHISHING = "phishing"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)

    # Configuration
    config = Column(JSON, default=dict)  # Scan-specific options

    # Results
    results_summary = Column(JSON, default=dict)
    error_message = Column(Text)

    # Timing
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="scans")
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan")
