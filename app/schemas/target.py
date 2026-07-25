from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class TargetCreate(BaseModel):
    domain: str
    description: Optional[str] = None

class TargetResponse(BaseModel):
    id: int
    domain: str
    description: Optional[str]
    ip_address: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
