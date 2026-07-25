"""Audit log model."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from app.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    action = Column(String(100), nullable=False)  # login, scan_created, alert_triggered, etc.
    entity_type = Column(String(100), nullable=False)  # user, scan, monitor, alert
    entity_id = Column(UUID(as_uuid=True), nullable=True)

    description = Column(Text)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    before_state = Column(JSON, nullable=True)
    after_state = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="audit_logs")
