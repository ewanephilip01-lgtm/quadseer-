"""
Report model for scan reports.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    report_type = Column(String(50), default="pdf")
    title = Column(String(255))
    file_path = Column(String(500))

    report_metadata = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="reports")
