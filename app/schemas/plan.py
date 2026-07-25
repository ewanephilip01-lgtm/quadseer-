"""Plan schemas."""
from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional


class PlanRead(BaseModel):
    id: int
    name: str
    slug: str
    description: Optional[str] = None
    price_monthly: float
    price_yearly: float
    max_targets: int
    max_scans_monthly: int
    max_users: int
    features: List[str]
    is_active: bool
    is_default: bool
    created_at: datetime

    class Config:
        from_attributes = True
