"""Routes — history.py"""
from fastapi import APIRouter, HTTPException, Query
from services.database import get_history, get_detection

router = APIRouter()


@router.get("/history")
async def get_detection_history(limit: int = Query(default=20, ge=1, le=100)):
    history = await get_history(limit=limit)
    items = []
    for doc in history:
        items.append({
            "id": str(doc.get("_id", "")),
            "query_domain": doc.get("query_domain", ""),
            "overall_risk_level": doc.get("overall_risk_level", "safe"),
            "overall_risk_score": doc.get("overall_risk_score", 0),
            "high_risk_count": doc.get("high_risk_count", 0),
            "total_variants_existing": doc.get("total_variants_existing", 0),
            "scanned_at": doc.get("scanned_at"),
        })
    return {"success": True, "data": items}


@router.get("/detection/{detection_id}")
async def get_single_detection(detection_id: str):
    doc = await get_detection(detection_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Detection not found")
    return {"success": True, "data": doc}
