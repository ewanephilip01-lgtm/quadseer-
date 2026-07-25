from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class ScanCreate(BaseModel):
    target_id: int
    scan_types: List[str]  # ["dns", "port", "ssl", "tech", "threat"]

class ScanResponse(BaseModel):
    id: int
    scan_type: str
    status: str
    total_findings: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

class ScanResultResponse(BaseModel):
    id: int
    finding_type: str
    severity: str
    asset: Optional[str]
    details: Optional[str]
    raw_data: Optional[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True
