"""Asset Pydantic schemas."""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    value: str = Field(..., min_length=1, max_length=512)
    asset_type: str = "domain"
    status: str = "active"


class AssetCreate(AssetBase):
    target_id: int
    source: str = "manual"
    confidence: float = 1.0


class AssetRead(AssetBase):
    id: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source: str
    confidence: float
    ports: List[Dict[str, Any]]
    technologies: List[str]
    headers: Dict[str, Any]
    ssl_info: Dict[str, Any]
    geo_location: Dict[str, Any]
    risk_score: float
    risk_factors: List[str]
    enrichment_data: Dict[str, Any]
    screenshots: List[str]
    is_monitored: bool
    monitor_interval_hours: int
    last_scan_at: Optional[datetime] = None
    parent_id: Optional[int] = None
    target_id: int
    owner_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetStats(BaseModel):
    total_assets: int
    high_risk_assets: int
    by_type: Dict[str, int]


class ReconRequest(BaseModel):
    target_id: int
    scan_depth: str = "standard"  # quick, standard, deep
