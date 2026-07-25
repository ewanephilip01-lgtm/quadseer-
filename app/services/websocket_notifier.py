"""WebSocket notification service for scan progress."""
import json
import asyncio
from typing import Dict, Set

scan_connections: Dict[int, Set] = {}


async def register_ws_connection(scan_id: int, websocket):
    if scan_id not in scan_connections:
        scan_connections[scan_id] = set()
    scan_connections[scan_id].add(websocket)


async def unregister_ws_connection(scan_id: int, websocket):
    if scan_id in scan_connections:
        scan_connections[scan_id].discard(websocket)
        if not scan_connections[scan_id]:
            del scan_connections[scan_id]


async def notify_scan_progress(scan_id: int, progress: float, status: str, message: str = None):
    if scan_id not in scan_connections:
        return
    payload = {
        "scan_id": scan_id,
        "progress": progress,
        "status": status,
        "message": message or f"Progress: {progress}%",
        "timestamp": asyncio.get_event_loop().time(),
    }
    dead_connections = set()
    for ws in scan_connections[scan_id]:
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead_connections.add(ws)
    for ws in dead_connections:
        scan_connections[scan_id].discard(ws)
