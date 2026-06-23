"""WebSocket endpoint for real-time scan progress push"""
import json, logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import redis.asyncio as aioredis

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws/scan/{task_id}")
async def scan_progress_ws(websocket: WebSocket, task_id: str):
    """Real-time scan progress via Redis Pub/Sub relay"""
    await websocket.accept()
    logger.info(f"WS connected for scan {task_id}")

    r = aioredis.from_url("redis://redis:6379/1", decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:progress:{task_id}")

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data if isinstance(data, str) else data.decode())
    except WebSocketDisconnect:
        logger.info(f"WS client disconnected for scan {task_id}")
    except Exception as e:
        logger.error(f"WS error for scan {task_id}: {e}")
    finally:
        try:
            await pubsub.unsubscribe(f"scan:progress:{task_id}")
        except Exception:
            pass
        try:
            await r.close()
        except Exception:
            pass
