"""
Health check endpoint - standalone, no DB dependency to avoid fragility.
"""
from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "quadseer-api",
        "version": "3.0.0",
    }
