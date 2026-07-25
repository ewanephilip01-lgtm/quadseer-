"""Pydantic schemas for request/response validation."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, ConfigDict

# ============= USER SCHEMAS =============
class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=72)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(UserBase):
    id: UUID
    is_active: bool
    is_superuser: bool
    organization_id: Optional[UUID] = None
    role: str = "member"
    created_at: datetime
    last_login: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

# ============= SCAN SCHEMAS =============
class ScanCreate(BaseModel):
    scan_type: str = Field(..., pattern="^(attack_surface|brand_protection|credential_leak|dark_web|malware)$")
    target: str = Field(..., min_length=1, max_length=500)

class ScanFindingResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    severity: str
    category: Optional[str] = None
    cve_id: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    remediation: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ScanResponse(BaseModel):
    id: UUID
    owner_id: UUID
    scan_type: str
    target: str
    status: str
    progress: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float
    raw_results: Dict[str, Any]
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    geo_locations: List[Dict[str, Any]] = []
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings: List[ScanFindingResponse] = []
    model_config = ConfigDict(from_attributes=True)

class ScanListResponse(BaseModel):
    id: UUID
    scan_type: str
    target: str
    status: str
    progress: int
    risk_score: float
    findings_count: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ============= MONITOR SCHEMAS =============
class MonitorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    target: str = Field(..., min_length=1, max_length=500)
    monitor_type: str = Field(..., pattern="^(domain|ip|brand|credential|dark_web)$")
    interval: str = Field(default="daily", pattern="^(hourly|daily|weekly|monthly)$")
    notify_email: bool = True
    notify_slack: bool = False
    slack_webhook_url: Optional[str] = None
    alert_on_critical: bool = True
    alert_on_high: bool = True
    alert_on_change: bool = True

class MonitorResponse(BaseModel):
    id: UUID
    owner_id: UUID
    name: str
    target: str
    monitor_type: str
    interval: str
    is_active: bool
    notify_email: bool
    notify_slack: bool
    slack_webhook_url: Optional[str] = None
    alert_on_critical: bool
    alert_on_high: bool
    alert_on_change: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class MonitorRunResponse(BaseModel):
    id: UUID
    monitor_id: UUID
    status: str
    findings_count: int
    new_findings_count: int
    raw_results: Dict[str, Any]
    diff_results: Dict[str, Any]
    started_at: datetime
    completed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

# ============= ALERT SCHEMAS =============
class AlertRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    trigger_on_scan: bool = True
    trigger_on_monitor: bool = False
    min_severity: str = Field(default="medium", pattern="^(critical|high|medium|low|info)$")
    channel_email: bool = True
    channel_slack: bool = False
    channel_webhook: bool = False
    email_recipients: List[str] = []
    slack_webhook_url: Optional[str] = None
    custom_webhook_url: Optional[str] = None
    scan_types: List[str] = []
    keywords: List[str] = []

class AlertRuleResponse(BaseModel):
    id: UUID
    owner_id: UUID
    name: str
    description: Optional[str] = None
    is_active: bool
    trigger_on_scan: bool
    trigger_on_monitor: bool
    min_severity: str
    channel_email: bool
    channel_slack: bool
    channel_webhook: bool
    email_recipients: List[str]
    slack_webhook_url: Optional[str] = None
    custom_webhook_url: Optional[str] = None
    scan_types: List[str]
    keywords: List[str]
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class AlertLogResponse(BaseModel):
    id: UUID
    rule_id: UUID
    channel: str
    status: str
    recipient: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    error_message: Optional[str] = None
    sent_at: Optional[datetime] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ============= BILLING SCHEMAS =============
class PlanResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: Optional[str] = None
    price_monthly: float
    price_yearly: float
    currency: str
    max_scans_per_month: int
    max_monitors: int
    max_users: int
    max_api_calls_per_day: int
    features: List[str]
    is_active: bool
    is_popular: bool
    model_config = ConfigDict(from_attributes=True)

class SubscriptionResponse(BaseModel):
    id: UUID
    user_id: UUID
    plan_id: UUID
    status: str
    interval: str
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: bool
    created_at: datetime
    plan: Optional[PlanResponse] = None
    model_config = ConfigDict(from_attributes=True)

class PaymentResponse(BaseModel):
    id: UUID
    subscription_id: UUID
    amount: float
    currency: str
    status: str
    provider: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class CheckoutRequest(BaseModel):
    plan_id: UUID
    interval: str = Field(default="monthly", pattern="^(monthly|yearly)$")
    email: EmailStr

class CheckoutResponse(BaseModel):
    payment_link: Optional[str] = None
    transaction_ref: str
    public_key: str
    message: str

# ============= ORGANIZATION SCHEMAS =============
class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    billing_email: Optional[EmailStr] = None

class OrganizationResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: Optional[str] = None
    billing_email: Optional[str] = None
    max_users: int
    saml_enabled: bool
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ============= THREAT INTEL SCHEMAS =============
class OrganizationMemberResponse(BaseModel):
    id: UUID
    organization_id: UUID
    user_id: UUID
    role: str
    joined_at: datetime
    model_config = ConfigDict(from_attributes=True)
class ThreatActorResponse(BaseModel):
    id: UUID
    name: str
    aliases: List[str]
    description: Optional[str] = None
    country: Optional[str] = None
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    mitre_group_id: Optional[str] = None
    tactics: List[str]
    techniques: List[str]
    sources: List[str]
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class IOCResponse(BaseModel):
    id: UUID
    threat_actor_id: Optional[UUID] = None
    value: str
    ioc_type: str
    description: Optional[str] = None
    confidence: str
    source: Optional[str] = None
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class YARARuleResponse(BaseModel):
    id: UUID
    threat_actor_id: Optional[UUID] = None
    name: str
    description: Optional[str] = None
    rule_content: str
    tags: List[str]
    author: Optional[str] = None
    version: str
    match_count: int
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ============= REPORT SCHEMAS =============
class ReportCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    report_format: str = Field(default="pdf", pattern="^(pdf|csv|json|markdown)$")
    scan_id: Optional[UUID] = None
    filters: Dict[str, Any] = {}

class ReportResponse(BaseModel):
    id: UUID
    owner_id: UUID
    scan_id: Optional[UUID] = None
    name: str
    description: Optional[str] = None
    report_format: str
    status: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    summary: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

# ============= DASHBOARD SCHEMAS =============
class DashboardStats(BaseModel):
    total_scans: int
    total_monitors: int
    active_monitors: int
    total_findings: int
    critical_findings: int
    high_findings: int
    open_alerts: int
    subscription_status: str
    scans_this_month: int
    monitors_this_month: int

class ThreatTimelineItem(BaseModel):
    date: str
    count: int
    severity: str

class MitreStats(BaseModel):
    tactic: str
    count: int
    techniques: List[Dict[str, Any]]

class GeoThreatPoint(BaseModel):
    lat: float
    lon: float
    count: int
    severity: str
    country: str
    city: Optional[str] = None

class DashboardResponse(BaseModel):
    stats: DashboardStats
    recent_scans: List[ScanListResponse]
    threat_timeline: List[ThreatTimelineItem]
    mitre_stats: List[MitreStats]
    geo_threats: List[GeoThreatPoint]
    recent_alerts: List[AlertLogResponse]
