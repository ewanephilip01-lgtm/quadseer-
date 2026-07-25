"""
Threat Actor model
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text
from datetime import datetime
from app.core.database import Base


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    aliases = Column(JSON, default=list)
    description = Column(Text, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    motivation = Column(String(200), nullable=True)
    sophistication = Column(String(50), nullable=True)  # low, medium, high
    active = Column(String(20), default="active")  # active, inactive, unknown
    iocs = Column(JSON, default=list)  # Indicators of Compromise
    ttps = Column(JSON, default=list)  # Tactics, Techniques, Procedures
    sources = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
