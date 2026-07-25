"""
Dark Web Finding Model
Stores findings from dark web monitoring, breach checks, and ransomware tracking.
Phase 2 implementation.
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Text, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class DarkWebFinding(Base):
    __tablename__ = "darkweb_findings"

    id = Column(Integer, primary_key=True, index=True)

    # Finding classification
    finding_type = Column(String(50), nullable=False)  # credentials_leak, data_exposure, ransomware_victim, breach_notification
    severity = Column(String(20), default="low")  # critical, high, medium, low, info
    confidence = Column(String(20), default="medium")  # high, medium, low

    # Target information
    target_domain = Column(String(255), nullable=False, index=True)
    asset = Column(String(500), nullable=True)  # Specific asset (email, IP, URL)

    # Finding details
    title = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    details = Column(Text, nullable=True)

    # Source information
    source = Column(String(100), nullable=False)  # haveibeenpwned, dehashed, ransomware.live, darkweb_forum, paste_site
    source_url = Column(String(1000), nullable=True)

    # Raw data
    raw_data = Column(JSON, nullable=True)

    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)
    reported_at = Column(DateTime, nullable=True)  # When the finding was first reported externally

    # Relationships
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Status tracking
    status = Column(String(50), default="open")  # open, acknowledged, resolved, false_positive
    resolution_notes = Column(Text, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Risk scoring
    risk_score = Column(Float, nullable=True)  # 0-100 calculated risk score


class BreachNotification(Base):
    __tablename__ = "breach_notifications"

    id = Column(Integer, primary_key=True, index=True)

    # Breach details
    breach_name = Column(String(200), nullable=False)
    breach_date = Column(DateTime, nullable=True)
    description = Column(Text, nullable=True)

    # Affected data
    compromised_data_types = Column(JSON, default=list)  # ["emails", "passwords", "names", "phone_numbers"]
    affected_accounts = Column(Integer, nullable=True)  # Number of affected accounts

    # Source
    source = Column(String(100), nullable=False)  # haveibeenpwned, etc.
    source_url = Column(String(1000), nullable=True)

    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Status
    status = Column(String(50), default="active")  # active, resolved, expired
