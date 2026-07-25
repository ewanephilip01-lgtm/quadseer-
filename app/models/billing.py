"""Billing models: Plan, Subscription, Payment."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Boolean, JSON, ForeignKey, Numeric, Integer, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum
from app.database import Base

class PlanInterval(str, enum.Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"

class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    CANCELLED = "cancelled"
    PAST_DUE = "past_due"
    TRIAL = "trial"
    EXPIRED = "expired"

class Plan(Base):
    __tablename__ = "plans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    price_monthly = Column(Numeric(10, 2), nullable=False)
    price_yearly = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(3), default="USD")

    # Limits
    max_scans_per_month = Column(Integer, default=10)
    max_monitors = Column(Integer, default=5)
    max_users = Column(Integer, default=1)
    max_api_calls_per_day = Column(Integer, default=100)

    # Features
    features = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    is_popular = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    subscriptions = relationship("Subscription", back_populates="plan", lazy="selectin")

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    plan_id = Column(UUID(as_uuid=True), ForeignKey("plans.id"), nullable=False)

    status = Column(SQLEnum(SubscriptionStatus), default=SubscriptionStatus.TRIAL)
    interval = Column(SQLEnum(PlanInterval), default=PlanInterval.MONTHLY)

    # Flutterwave
    flutterwave_tx_ref = Column(String(255), nullable=True)
    flutterwave_subscription_id = Column(String(255), nullable=True)

    # Stripe (NEW)
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)

    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    cancel_at_period_end = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="subscriptions")
    plan = relationship("Plan", back_populates="subscriptions")
    payments = relationship("Payment", back_populates="subscription", lazy="selectin")

class Payment(Base):
    __tablename__ = "payments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subscription_id = Column(UUID(as_uuid=True), ForeignKey("subscriptions.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(3), default="USD")
    status = Column(String(50), default="pending")

    # Provider
    provider = Column(String(50), default="flutterwave")  # flutterwave, stripe
    provider_tx_id = Column(String(255), nullable=True)
    provider_ref = Column(String(255), nullable=True)

    metadata_json = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    subscription = relationship("Subscription", back_populates="payments")
