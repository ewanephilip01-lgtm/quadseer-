#!/usr/bin/env python3
"""
Seed script to initialize database with admin user and default configs.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from sqlalchemy import text, select

from app.core.database import async_session, engine, create_tables, Base
from app.core.security import hash_password
from app.core.config import initialize_default_configs
from app.models.user import User


async def reset_database():
    """Drop all tables and recreate them."""
    print("Dropping all existing tables...")
    async with engine.begin() as conn:
        # Get all table names
        result = await conn.execute(text("""
            SELECT tablename FROM pg_tables WHERE schemaname = 'public'
        """))
        tables = [row[0] for row in result.fetchall()]

        # Drop each table
        for table in tables:
            await conn.execute(text(f'DROP TABLE IF EXISTS "{table}" CASCADE'))
            print(f"  Dropped table: {table}")

    print("Recreating tables from models...")
    await create_tables()
    print("Tables recreated successfully.")


async def seed():
    print("=== QuadSeer Database Seed ===")

    # Always reset in development to ensure schema matches models
    await reset_database()

    async with async_session() as db:
        print("\nCreating admin user...")
        admin = User(
            email="admin@quadseer.local",
            username="admin",
            hashed_password=hash_password("admin123"),
            full_name="System Administrator",
            is_active=True,
            is_admin=True,
        )
        db.add(admin)
        await db.commit()
        print("  ✓ Admin: admin@quadseer.local / admin123")

        print("\nInitializing default configurations...")
        await initialize_default_configs()
        print("  ✓ 25+ config fields initialized")

        print("\n=== Seed Complete ===")
        print("Open http://localhost:8000 and login with the credentials above.")


if __name__ == "__main__":
    asyncio.run(seed())
