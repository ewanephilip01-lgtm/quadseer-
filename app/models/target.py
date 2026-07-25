"""
Target model for assets being monitored.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship

from app.core.database import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    description = Column(Text)

    # Target type
    target_type = Column(String(50), default="domain")  # domain, ip, email, organization

    # Asset metadata - renamed from 'metadata' to avoid SQLAlchemy reserved word
    target_metadata = Column(JSON, default=dict)

    # Monitoring
    is_active = Column(Boolean, default=True)
    last_scan_at = Column(DateTime)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target")
