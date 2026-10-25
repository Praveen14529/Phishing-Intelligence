"""Routes — detect.py"""
from fastapi import APIRouter, HTTPException  # type: ignore[import]
import logging
from models.schemas import DetectionRequest, DetectionResponse
from services.detector import run_detection
from services.database import save_detection
from services.domain_validation import normalize_domain

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/detect", response_model=DetectionResponse)
async def detect_phishing(request: DetectionRequest):
    try:
        domain = normalize_domain(request.domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    try:
        result = await run_detection(domain, deep_scan=request.deep_scan)
        doc = result.model_dump()
        doc["scanned_at"] = result.scanned_at
        detection_id = await save_detection(doc)
        result.id = detection_id
        return DetectionResponse(success=True, data=result)
    except Exception as e:
        logger.exception(f"Detection failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
