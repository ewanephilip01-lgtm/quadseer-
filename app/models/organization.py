"""Multi-tenant Organization models."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum
from app.database import Base

class OrganizationRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    description = Column(Text)

    # Billing
    billing_email = Column(String(255), nullable=True)

    # Limits
    max_users = Column(Integer, default=10)

    # SAML/SSO (NEW)
    saml_enabled = Column(Boolean, default=False)
    saml_entity_id = Column(String(500), nullable=True)
    saml_sso_url = Column(String(500), nullable=True)
    saml_x509_cert = Column(Text, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    members = relationship("User", back_populates="organization", lazy="selectin")

class OrganizationMember(Base):
    __tablename__ = "organization_members"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role = Column(SQLEnum(OrganizationRole), default=OrganizationRole.MEMBER)

    invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    invited_at = Column(DateTime, nullable=True)
    joined_at = Column(DateTime, default=datetime.utcnow)

    created_at = Column(DateTime, default=datetime.utcnow)
