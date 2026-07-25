"""Authentication routes with bcrypt 72-byte truncation fix."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.auth import get_password_hash, verify_password, create_access_token, get_current_user
from app.models.user import User
from app.schemas import UserCreate, UserLogin, UserResponse, Token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
security = HTTPBearer()

@router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user with bcrypt 72-byte truncation fix."""
    # Check existing
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user with truncated password hash
    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """Login and return JWT token."""
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")

    # Update last login
    user.last_login = datetime.utcnow()
    await db.commit()

    access_token = create_access_token(data={"sub": str(user.id)})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 86400,
    }

@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout (client-side token invalidation)."""
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user profile."""
    return current_user
