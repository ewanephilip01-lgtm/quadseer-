"""WebSocket endpoint for real-time scan progress updates.

Fully wired: clients connect to /ws/scan/{scan_id} and receive
live progress updates broadcast from the scan execution service.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.websocket_notifier import register_ws_connection, unregister_ws_connection

scan_progress_ws = APIRouter()


@scan_progress_ws.websocket("/scan/{scan_id}")
async def scan_progress_websocket(websocket: WebSocket, scan_id: int):
    """WebSocket endpoint for live scan progress.

    Usage:
        const ws = new WebSocket('ws://localhost:8000/ws/scan/1');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log(data.progress + '% — ' + data.message);
        };
    """
    await websocket.accept()
    await register_ws_connection(scan_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await unregister_ws_connection(scan_id, websocket)
    except Exception:
        await unregister_ws_connection(scan_id, websocket)
