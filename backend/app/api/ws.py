"""WebSocket endpoint for real-time scan progress push"""
import json, logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
import redis.asyncio as aioredis

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws/scan/{task_id}")
async def scan_progress_ws(websocket: WebSocket, task_id: str, token: str = ""):
    """Real-time scan progress via Redis Pub/Sub relay"""
    # Validate token
    from app.api.deps import get_current_user
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials
    try:
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token) if token else None
        if not creds:
            # Try to get token from query params
            token_from_query = websocket.query_params.get("token", "")
            if token_from_query:
                creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_from_query)
        if creds:
            from jose import jwt
            from app.config import settings
            payload = jwt.decode(creds.credentials, settings.JWT_SECRET, algorithms=["HS256"])
            logger.info(f"WS authenticated user {payload.get('sub')}")
    except Exception as e:
        logger.warning(f"WS auth failed (continuing): {e}")

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
