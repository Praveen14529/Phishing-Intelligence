"""Routes — stats.py"""
from fastapi import APIRouter
from services.database import get_stats

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats():
    stats = await get_stats()
    return {"success": True, "data": stats}
