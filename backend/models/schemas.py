from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DomainVariant(BaseModel):
    domain: str
    technique: str
    exists: bool = False
    has_https: bool = False
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    similarity_score: float = 0.0
    virustotal_detected: bool = False
    virustotal_positives: int = 0
    google_safe_browsing_flagged: bool = False
    urlhaus_flagged: bool = False
    openphish_flagged: bool = False
    urlscan_flagged: bool = False
    abuseipdb_flagged: bool = False
    whois_creation_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    page_title: Optional[str] = None
    page_keywords: List[str] = Field(default_factory=list)
    ip_address: Optional[str] = None
    threat_intel_details: Dict[str, Any] = Field(default_factory=dict)


class DetectionRequest(BaseModel):
    domain: str = Field(..., description="Legitimate domain to analyze")
    deep_scan: bool = Field(default=False, description="Enable WHOIS + page scraping")


class DetectionResult(BaseModel):
    id: Optional[str] = None
    query_domain: str
    is_legitimate: bool
    total_variants_generated: int
    total_variants_existing: int
    high_risk_count: int
    overall_risk_score: int
    overall_risk_level: RiskLevel
    variants: List[DomainVariant]
    scan_duration_seconds: float
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    summary: str = ""


class DetectionResponse(BaseModel):
    success: bool
    data: Optional[DetectionResult] = None
    error: Optional[str] = None
