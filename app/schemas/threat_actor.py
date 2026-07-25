"""Threat Actor schemas."""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any


class ThreatActorBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    aliases: List[str] = []
    origin: Optional[str] = None
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    threat_level: float = Field(0.0, ge=0.0, le=10.0)
    description: Optional[str] = None


class ThreatActorCreate(ThreatActorBase):
    tactics: List[str] = []
    techniques: List[str] = []
    targets: List[str] = []
    iocs: List[Dict[str, Any]] = []
    sources: List[str] = []


class ThreatActorRead(ThreatActorBase):
    id: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tactics: List[str]
    techniques: List[str]
    targets: List[str]
    iocs: List[Dict[str, Any]]
    sources: List[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
