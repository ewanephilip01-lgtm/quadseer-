"""
Health check endpoint - standalone, no DB dependency to avoid fragility.
"""
from fastapi import APIRouter
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import engine

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("")
async def health_check():
    """Health check endpoint."""
    db_status = "healthy"

    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        db_status = "unhealthy"

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "database": db_status,
        "version": "3.0.0",
    }
