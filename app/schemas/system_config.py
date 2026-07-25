"""
System Configuration Schemas
"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class ConfigItem(BaseModel):
    """Single configuration item."""
    key: str
    value: Optional[str] = None
    value_type: str = "string"
    label: Optional[str] = None
    description: Optional[str] = None
    placeholder: Optional[str] = None
    input_type: str = "text"
    options: Optional[List[Dict[str, str]]] = None
    required: bool = False
    is_sensitive: bool = False
    is_editable: bool = True
    is_active: bool = True


class ConfigCategory(BaseModel):
    """Configuration category with items."""
    name: str
    label: str
    description: Optional[str] = None
    items: List[ConfigItem]


class ConfigUpdateRequest(BaseModel):
    """Request to update a config value."""
    value: str


class ConfigBulkUpdateRequest(BaseModel):
    """Request to update multiple configs at once."""
    configs: Dict[str, str]


class ConfigResponse(BaseModel):
    """Config response with metadata."""
    key: str
    value: Optional[str]
    label: Optional[str]
    description: Optional[str]
    category: str
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
