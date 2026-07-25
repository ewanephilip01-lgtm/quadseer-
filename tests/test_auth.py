"""Authentication tests."""
import pytest
from httpx import AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_register_user():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/api/v1/auth/register", json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "testpassword123"
        })
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
