"""
Database configuration with async support and connection pooling.
"""
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://quadseer:quadseer_secret@db:5432/quadseer"
)

try:
    engine = create_async_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        echo=False,
    )
    logger.info("Database engine created")
except Exception as e:
    logger.error(f"Failed to create database engine: {e}")
    engine = None

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
) if engine else None

Base = declarative_base()


async def get_db():
    """Dependency for FastAPI to get DB session."""
    if async_session is None:
        raise Exception("Database not configured")
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def test_connection():
    """Test database connectivity with retries."""
    if engine is None:
        return False
    import asyncio
    for attempt in range(10):
        try:
            async with engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                row = result.fetchone()
                if row and row[0] == 1:
                    logger.info("Database connection successful")
                    return True
        except Exception as e:
            logger.warning(f"DB connection attempt {attempt + 1}/10 failed: {e}")
            await asyncio.sleep(2 ** attempt)
    logger.error("Database connection failed after 10 attempts")
    return False


async def create_tables():
    """Create all database tables."""
    if engine is None:
        logger.error("Cannot create tables - engine not available")
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")
