"""Threat Intelligence models: ThreatActor, IOC, YARARule."""
import uuid
from datetime import datetime
from sqlalchemy import Integer, Column, String, Text, DateTime, Boolean, JSON, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum
from app.database import Base

class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"

class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    name = Column(String(255), nullable=False, unique=True)
    aliases = Column(JSON, default=list)
    description = Column(Text)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # Attribution
    country = Column(String(100), nullable=True)
    motivation = Column(String(255), nullable=True)
    sophistication = Column(String(50), nullable=True)  # low, medium, high, strategic

    # MITRE
    mitre_group_id = Column(String(50), nullable=True)
    tactics = Column(JSON, default=list)
    techniques = Column(JSON, default=list)

    # Sources
    sources = Column(JSON, default=list)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    iocs = relationship("IOC", back_populates="threat_actor", lazy="selectin")
    yara_rules = relationship("YARARule", back_populates="threat_actor", lazy="selectin")

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_actor_id = Column(UUID(as_uuid=True), ForeignKey("threat_actors.id"), nullable=True)

    value = Column(String(500), nullable=False)
    ioc_type = Column(SQLEnum(IOCType), nullable=False)

    # Context
    description = Column(Text)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    confidence = Column(String(20), default="medium")  # low, medium, high

    # Enrichment
    virustotal_score = Column(Integer, nullable=True)
    abuseipdb_score = Column(Integer, nullable=True)

    # Source
    source = Column(String(255), nullable=True)
    source_url = Column(String(500), nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    threat_actor = relationship("ThreatActor", back_populates="iocs")

class YARARule(Base):
    __tablename__ = "yara_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_actor_id = Column(UUID(as_uuid=True), ForeignKey("threat_actors.id"), nullable=True)

    name = Column(String(255), nullable=False)
    description = Column(Text)
    rule_content = Column(Text, nullable=False)

    # Metadata
    tags = Column(JSON, default=list)
    author = Column(String(255), nullable=True)
    version = Column(String(50), default="1.0")

    # Stats
    match_count = Column(Integer, default=0)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    threat_actor = relationship("ThreatActor", back_populates="yara_rules")
