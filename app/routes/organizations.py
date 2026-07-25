"""Multi-tenant Organization routes with RBAC."""
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.organization import Organization, OrganizationMember, OrganizationRole
from app.schemas import OrganizationCreate, OrganizationResponse, OrganizationMemberResponse
from slugify import slugify

router = APIRouter(prefix="/api/organizations", tags=["Organizations"])

@router.post("/", response_model=OrganizationResponse)
async def create_organization(
    org_data: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new organization."""
    if current_user.organization_id:
        raise HTTPException(status_code=400, detail="User already belongs to an organization")

    org = Organization(
        name=org_data.name,
        slug=slugify(org_data.name),
        description=org_data.description,
        billing_email=org_data.billing_email,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)

    # Set user as owner
    current_user.organization_id = org.id
    current_user.role = "owner"
    await db.commit()

    return org

@router.get("/", response_model=List[OrganizationResponse])
async def list_organizations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List organizations (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Admin access required")
    result = await db.execute(select(Organization).order_by(desc(Organization.created_at)))
    return result.scalars().all()

@router.get("/my", response_model=OrganizationResponse)
async def get_my_organization(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current user's organization."""
    if not current_user.organization_id:
        raise HTTPException(status_code=404, detail="Not in an organization")

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org

@router.get("/my/members", response_model=List[dict])
async def get_organization_members(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get members of current user's organization."""
    if not current_user.organization_id:
        raise HTTPException(status_code=404, detail="Not in an organization")

    result = await db.execute(
        select(User).where(User.organization_id == current_user.organization_id)
    )
    members = result.scalars().all()
    return [
        {
            "id": str(m.id),
            "email": m.email,
            "full_name": m.full_name,
            "role": m.role,
            "is_active": m.is_active,
            "joined_at": m.created_at,
        }
        for m in members
    ]

@router.post("/invite")
async def invite_member(
    email: str,
    role: str = "member",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Invite a user to organization."""
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Not in an organization")
    if current_user.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Find user by email
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.organization_id:
        raise HTTPException(status_code=400, detail="User already in an organization")

    user.organization_id = current_user.organization_id
    user.role = role
    await db.commit()

    return {"message": f"Invited {email} as {role}"}

@router.delete("/members/{user_id}")
async def remove_member(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove member from organization."""
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Not in an organization")
    if current_user.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(
        select(User).where(User.id == user_id, User.organization_id == current_user.organization_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Member not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot remove yourself")

    user.organization_id = None
    user.role = "member"
    await db.commit()
    return {"message": "Member removed"}
