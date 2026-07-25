"""AlertRule and AlertLog models."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Boolean, JSON, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum
from app.database import Base

class AlertChannel(str, enum.Enum):
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    PUSHOVER = "pushover"

class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    name = Column(String(255), nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True)

    # Trigger conditions
    trigger_on_scan = Column(Boolean, default=True)
    trigger_on_monitor = Column(Boolean, default=False)
    min_severity = Column(SQLEnum(AlertChannel), default="email")  # Actually risk level - fix below

    # Channels
    channel_email = Column(Boolean, default=True)
    channel_slack = Column(Boolean, default=False)
    channel_webhook = Column(Boolean, default=False)

    # Config
    email_recipients = Column(JSON, default=list)
    slack_webhook_url = Column(String(500), nullable=True)
    custom_webhook_url = Column(String(500), nullable=True)

    # Filters
    scan_types = Column(JSON, default=list)  # ["attack_surface", "brand_protection"]
    keywords = Column(JSON, default=list)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    owner = relationship("User", back_populates="alert_rules")
    logs = relationship("AlertLog", back_populates="rule", lazy="selectin", cascade="all, delete-orphan")

class AlertLog(Base):
    __tablename__ = "alert_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("alert_rules.id"), nullable=False)

    channel = Column(String(50), nullable=False)
    status = Column(String(50), default="pending")  # pending, sent, failed
    recipient = Column(String(500))
    subject = Column(String(500))
    body = Column(Text)
    error_message = Column(Text, nullable=True)

    # Related entity
    related_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    related_monitor_run_id = Column(UUID(as_uuid=True), ForeignKey("monitor_runs.id"), nullable=True)

    sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    rule = relationship("AlertRule", back_populates="logs")
