"""
MongoDB service with in-memory fallback.
Works even without MongoDB installed.
"""
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

_memory_store: List[Dict] = []
_collection = None


async def init_db():
    global _collection
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        from config import settings
        client = AsyncIOMotorClient(
            settings.mongodb_url,
            serverSelectionTimeoutMS=3000
        )
        await client.admin.command("ping")
        db = client[settings.mongodb_db]
        _collection = db["detections"]
        await _collection.create_index("query_domain")
        await _collection.create_index("scanned_at")
        logger.info("✅ MongoDB connected.")
    except Exception as e:
        logger.warning(f"⚠ MongoDB unavailable, using in-memory store: {e}")
        _collection = None


async def save_detection(result: Dict) -> str:
    from bson import ObjectId
    if _collection is not None:
        try:
            res = await _collection.insert_one(result)
            return str(res.inserted_id)
        except Exception as e:
            logger.error(f"DB save error: {e}")
    _id = str(len(_memory_store) + 1)
    result["_id"] = _id
    _memory_store.append(result)
    return _id


async def get_detection(detection_id: str) -> Optional[Dict]:
    from bson import ObjectId
    if _collection is not None:
        try:
            doc = await _collection.find_one({"_id": ObjectId(detection_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception:
            pass
    return next(
        (d for d in _memory_store if d.get("_id") == detection_id), None
    )


async def get_history(limit: Optional[int] = 20) -> List[Dict]:
    if _collection is not None:
        try:
            cursor = _collection.find().sort("scanned_at", -1)
            if limit is not None:
                cursor = cursor.limit(limit)
            docs = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                docs.append(doc)
            return docs
        except Exception as e:
            logger.error(f"DB history error: {e}")
    history = sorted(
        _memory_store,
        key=lambda x: x.get("scanned_at", ""),
        reverse=True
    )
    return history if limit is None else history[:limit]


async def get_stats() -> Dict[str, Any]:
    history = await get_history(limit=None)
    total_scans = len(history)
    total_domains = sum(d.get("total_variants_existing", 0) for d in history)
    high_risk = sum(d.get("high_risk_count", 0) for d in history)

    risk_dist: Dict[str, int] = {
        "safe": 0, "low": 0, "medium": 0, "high": 0, "critical": 0
    }
    domain_counts: Dict[str, int] = {}
    scans_by_date: Dict[str, int] = {}

    for doc in history:
        level = doc.get("overall_risk_level", "safe")
        risk_dist[level] = risk_dist.get(level, 0) + 1

        domain = doc.get("query_domain", "")
        domain_counts[domain] = domain_counts.get(domain, 0) + 1

        dt = doc.get("scanned_at")
        if isinstance(dt, datetime):
            date_str = dt.strftime("%Y-%m-%d")
        elif isinstance(dt, str):
            date_str = dt[:10]
        else:
            date_str = "unknown"
        scans_by_date[date_str] = scans_by_date.get(date_str, 0) + 1

    top_domains = [
        {"domain": k, "scans": v}
        for k, v in sorted(
            domain_counts.items(), key=lambda x: -x[1]
        )[:5]
    ]
    scans_over_time = [
        {"date": k, "count": v}
        for k, v in sorted(scans_by_date.items())
    ]

    return {
        "total_scans": total_scans,
        "total_domains_detected": total_domains,
        "high_risk_domains": high_risk,
        "risk_distribution": risk_dist,
        "top_targeted_domains": top_domains,
        "scans_over_time": scans_over_time,
    }
