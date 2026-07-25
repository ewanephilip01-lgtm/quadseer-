"""Report schemas."""
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class ReportCreate(BaseModel):
    title: str
    description: Optional[str] = None
    format: str = "pdf"
    scan_ids: List[int]
    template: str = "default"


class ReportRead(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    format: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    scan_ids: List[int]
    template: str
    generated_at: Optional[datetime] = None
    created_at: datetime
    owner_id: int

    class Config:
        from_attributes = True
