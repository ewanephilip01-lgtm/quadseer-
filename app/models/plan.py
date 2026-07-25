"""
Subscription Plan model
"""
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class Plan(Base):
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(String(500), nullable=True)
    price = Column(Float, default=0.0)
    max_targets = Column(Integer, default=3)
    max_scans_per_month = Column(Integer, default=10)
    features = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="plan")
