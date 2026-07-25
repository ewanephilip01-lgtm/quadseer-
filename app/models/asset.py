"""Discovered asset model for EASM."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean, Float, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum
from app.db.base import Base


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    CLOUD_RESOURCE = "cloud_resource"
    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"


class AssetStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    RISKY = "risky"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    value = Column(String(512), nullable=False)
    asset_type = Column(SQLEnum(AssetType), default=AssetType.DOMAIN)
    status = Column(SQLEnum(AssetStatus), default=AssetStatus.ACTIVE)

    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    source = Column(String(50))
    confidence = Column(Float, default=1.0)

    ports = Column(JSON, default=list)
    technologies = Column(JSON, default=list)
    headers = Column(JSON, default=dict)
    ssl_info = Column(JSON, default=dict)
    geo_location = Column(JSON, default=dict)

    risk_score = Column(Float, default=0.0)
    risk_factors = Column(JSON, default=list)

    parent_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    owner_id = Column(Integer, ForeignKey("users.id"))

    parent = relationship("Asset", remote_side=[id], backref="children")
    target = relationship("Target", backref="assets")
    owner = relationship("User")

    enrichment_data = Column(JSON, default=dict)
    screenshots = Column(JSON, default=list)

    is_monitored = Column(Boolean, default=True)
    monitor_interval_hours = Column(Integer, default=24)
    last_scan_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
