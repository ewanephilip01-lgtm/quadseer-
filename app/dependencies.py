"""Shared dependencies."""
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.auth import get_current_user, get_current_active_superuser
from app.models.user import User

__all__ = ["get_db", "get_current_user", "get_current_active_superuser", "AsyncSession", "User"]
