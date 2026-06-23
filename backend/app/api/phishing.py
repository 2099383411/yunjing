"""GoPhish 社工钓鱼平台代理 API"""
import httpx
import logging
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()
logger = logging.getLogger(__name__)

GOPHISH_URL = "https://yunjing-gophish:3333"
API_KEY = "5ca33d588a8943a63cd34325f826c29b168b860f9d3136d6366dc5d54e354c74"

async def _gophish_get(path: str):
    """代理 GET 请求到 GoPhish API"""
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        resp = await client.get(
            f"{GOPHISH_URL}{path}",
            params={"api_key": API_KEY}
        )
        return JSONResponse(content=resp.json(), status_code=resp.status_code)

@router.get("/phishing/campaigns")
async def list_campaigns():
    """获取所有钓鱼活动"""
    return await _gophish_get("/api/campaigns/")

@router.get("/phishing/templates")
async def list_templates():
    """获取邮件模板"""
    return await _gophish_get("/api/templates/")

@router.get("/phishing/groups")
async def list_groups():
    """获取目标分组"""
    return await _gophish_get("/api/groups/")

@router.get("/phishing/sending-profiles")
async def list_sending_profiles():
    """获取发信配置"""
    return await _gophish_get("/api/smtp/")

@router.get("/phishing/stats")
async def get_stats():
    """获取汇总统计"""
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        camps = await client.get(
            f"{GOPHISH_URL}/api/campaigns/",
            params={"api_key": API_KEY}
        )
        campaigns = camps.json()
    
    total = len(campaigns)
    sent = sum(c.get("status", {}).get("total", 0) for c in campaigns)
    opened = sum(c.get("status", {}).get("opened", 0) for c in campaigns)
    clicked = sum(c.get("status", {}).get("clicked", 0) for c in campaigns)
    submitted = sum(c.get("status", {}).get("submitted_data", 0) for c in campaigns)
    
    return {
        "total_campaigns": total,
        "total_sent": sent,
        "total_opened": opened,
        "total_clicked": clicked,
        "total_submitted": submitted,
        "open_rate": round(opened/sent*100, 1) if sent else 0,
        "click_rate": round(clicked/sent*100, 1) if sent else 0,
        "submit_rate": round(submitted/sent*100, 1) if sent else 0,
    }

@router.get("/phishing/status")
async def phishing_status():
    """健康检查"""
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.get(
                f"{GOPHISH_URL}/api/campaigns/",
                params={"api_key": API_KEY}
            )
            if resp.status_code == 200:
                return {"status": "online", "url": "https://192.168.1.180:3333"}
    except Exception as e:
        logger.warning(f"GoPhish health check failed: {e}")
    return {"status": "offline", "url": ""}
