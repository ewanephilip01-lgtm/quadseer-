"""Scan routes with real execution and Celery result safety."""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.auth import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanType, ScanStatus
from app.schemas import ScanCreate, ScanResponse, ScanListResponse
from app.worker import run_scan_task

router = APIRouter(prefix="/api/scans", tags=["Scans"])

scan_ws_connections: dict = {}

@router.post("/launch", response_model=ScanResponse)
async def launch_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        scan_type_enum = ScanType(scan_data.scan_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan_type. Must be one of: {[t.value for t in ScanType]}"
        )

    scan = Scan(
        user_id=current_user.id,
        scan_type=scan_type_enum,
        target=scan_data.target,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    run_scan_task.delay(str(scan.id))
    return scan

@router.get("/", response_model=List[ScanListResponse])
async def list_scans(
    scan_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Scan).where(Scan.user_id == current_user.id)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    if status:
        query = query.where(Scan.status == status)
    query = query.order_by(desc(Scan.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.findings))
        .where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan.status, Scan.started_at, Scan.completed_at)
        .where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()
    return {"message": "Scan deleted"}

@router.websocket("/ws/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in scan_ws_connections:
        scan_ws_connections[scan_id] = []
    scan_ws_connections[scan_id].append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "pong", "scan_id": scan_id})
    except WebSocketDisconnect:
        scan_ws_connections[scan_id].remove(websocket)
        if not scan_ws_connections[scan_id]:
            del scan_ws_connections[scan_id]

async def notify_scan_update(scan_id: str, data: dict):
    if scan_id in scan_ws_connections:
        for ws in scan_ws_connections[scan_id]:
            try:
                await ws.send_json({"type": "scan_update", "payload": data})
            except:
                pass