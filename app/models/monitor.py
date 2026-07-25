"""Monitor and MonitorRun models."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Boolean, JSON, ForeignKey, Enum as SQLEnum, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum
from app.database import Base

class MonitorInterval(str, enum.Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

class Monitor(Base):
    __tablename__ = "monitors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    name = Column(String(255), nullable=False)
    target = Column(String(500), nullable=False)
    monitor_type = Column(String(50), nullable=False)  # domain, ip, brand, credential
    interval = Column(SQLEnum(MonitorInterval), default=MonitorInterval.DAILY)

    is_active = Column(Boolean, default=True)
    notify_email = Column(Boolean, default=True)
    notify_slack = Column(Boolean, default=False)
    slack_webhook_url = Column(String(500), nullable=True)

    # Alert thresholds
    alert_on_critical = Column(Boolean, default=True)
    alert_on_high = Column(Boolean, default=True)
    alert_on_change = Column(Boolean, default=True)

    # Schedule (for Celery Beat)
    cron_expression = Column(String(100), nullable=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)

    # Baseline fingerprint for change detection
    baseline_fingerprint = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    owner = relationship("User", back_populates="monitors")
    runs = relationship("MonitorRun", back_populates="monitor", lazy="selectin", cascade="all, delete-orphan")

class MonitorRun(Base):
    __tablename__ = "monitor_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    monitor_id = Column(UUID(as_uuid=True), ForeignKey("monitors.id"), nullable=False)

    status = Column(String(50), default="pending")
    findings_count = Column(Integer, default=0)
    new_findings_count = Column(Integer, default=0)  # Changed from baseline

    raw_results = Column(JSON, default=dict)
    diff_results = Column(JSON, default=dict)  # What changed since last run

    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    monitor = relationship("Monitor", back_populates="runs")
