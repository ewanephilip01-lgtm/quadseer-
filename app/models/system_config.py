"""
System configuration stored in database.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON

from app.core.database import Base


class SystemConfig(Base):
    __tablename__ = "system_configs"

    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String(100), unique=True, nullable=False, index=True)
    config_value = Column(Text)
    config_type = Column(String(50), default="string")  # string, json, int, bool, secret
    description = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
