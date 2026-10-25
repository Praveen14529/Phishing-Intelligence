"""
Detection Orchestrator
Coordinates all services to produce a full phishing detection report.
"""
import asyncio
import logging
import time
from datetime import datetime
from typing import List

from models.schemas import DetectionResult, DomainVariant, RiskLevel
from services.domain_generator import generate_all_variants, calculate_similarity
from services.dns_checker import batch_dns_check, check_https
from services.threat_intel import check_all_threat_intel
from services.scraper import get_whois_info, scrape_page_metadata
from services.risk_scorer import compute_risk_score, determine_overall_risk
from config import settings

logger = logging.getLogger(__name__)

RISK_SUMMARIES = {
    RiskLevel.SAFE:     "No significant phishing threats detected.",
    RiskLevel.LOW:      "Minor suspicious variants found. Monitor for changes.",
    RiskLevel.MEDIUM:   "Moderate risk: several lookalike domains exist.",
    RiskLevel.HIGH:     "High risk: multiple dangerous impersonation domains detected.",
    RiskLevel.CRITICAL: "CRITICAL: Active phishing infrastructure detected! Immediate action recommended.",
}


async def run_detection(domain: str, deep_scan: bool = False) -> DetectionResult:
    """
    Full detection pipeline:
    1. Generate domain variants
    2. DNS batch check
    3. Threat intel (VirusTotal, Google, URLhaus, OpenPhish, URLScan, AbuseIPDB)
    4. Optional WHOIS + scraping (deep_scan=True)
    5. Risk scoring
    6. Assemble result
    """
    start = time.time()

    # ── Step 1: Generate variants ──────────────────────────────────────────
    raw_variants = generate_all_variants(
        domain, max_variants=settings.max_domain_variants
    )
    domain_list = [v["domain"] for v in raw_variants]
    technique_map = {v["domain"]: v["technique"] for v in raw_variants}

    # ── Step 2: DNS batch check ────────────────────────────────────────────
    dns_results = await batch_dns_check(
        domain_list, concurrency=settings.dns_concurrency
    )
    existing_domains = [
        d for d, (exists, _) in dns_results.items() if exists
    ]
    logger.info(
        f"[{domain}] {len(domain_list)} variants generated, "
        f"{len(existing_domains)} resolve via DNS"
    )

    # ── Step 3: Threat intel (top 10 existing domains) ────────────────────
    threat_targets = existing_domains[:10]
    threat_semaphore = asyncio.Semaphore(3)

    async def get_threat_intel(d: str):
        async with threat_semaphore:
            ip = dns_results.get(d, (False, None))[1]
            result = await check_all_threat_intel(d, ip)
            return d, result

    threat_results_raw = await asyncio.gather(
        *[get_threat_intel(d) for d in threat_targets],
        return_exceptions=True
    )
    threat_map = {
        d: t for d, t in threat_results_raw
        if not isinstance(t, Exception)
    }

    # ── Step 4: HTTPS + optional WHOIS/scrape ─────────────────────────────
    https_results = {}
    whois_results = {}
    scrape_results = {}

    if existing_domains:
        https_list = await asyncio.gather(
            *[check_https(d) for d in existing_domains[:20]],
            return_exceptions=True
        )
        https_results = {
            d: (r if not isinstance(r, Exception) else False)
            for d, r in zip(existing_domains[:20], https_list)
        }

        if deep_scan:
            top5 = existing_domains[:5]
            whois_list = await asyncio.gather(
                *[get_whois_info(d) for d in top5],
                return_exceptions=True
            )
            scrape_list = await asyncio.gather(
                *[scrape_page_metadata(d) for d in top5],
                return_exceptions=True
            )
            whois_results = {
                d: (w if not isinstance(w, Exception) else {})
                for d, w in zip(top5, whois_list)
            }
            scrape_results = {
                d: (s if not isinstance(s, Exception) else {})
                for d, s in zip(top5, scrape_list)
            }

    # ── Step 5: Build DomainVariant objects with risk scores ──────────────
    variants: List[DomainVariant] = []

    for v in raw_variants:
        d = v["domain"]
        exists, ip = dns_results.get(d, (False, None))
        has_https = https_results.get(d, False)
        similarity = calculate_similarity(domain, d)
        intel = threat_map.get(d, {})
        whois = whois_results.get(d, {})
        scrape = scrape_results.get(d, {})

        risk = compute_risk_score(
            domain=d,
            similarity_score=similarity,
            has_https=has_https,
            virustotal=intel.get("virustotal", {}),
            google_safe_browsing=intel.get("google_safe_browsing", {}),
            urlhaus=intel.get("urlhaus", {}),
            openphish=intel.get("openphish", {}),
            urlscan=intel.get("urlscan", {}),
            abuseipdb=intel.get("abuseipdb", {}),
            whois=whois,
        )

        variants.append(DomainVariant(
            domain=d,
            technique=technique_map.get(d, "unknown"),
            exists=exists,
            has_https=has_https,
            risk_score=risk["score"],
            risk_level=risk["level"],
            similarity_score=similarity,
            virustotal_detected=intel.get("virustotal", {}).get("detected", False),
            virustotal_positives=intel.get("virustotal", {}).get("positives", 0),
            google_safe_browsing_flagged=intel.get("google_safe_browsing", {}).get("flagged", False),
            urlhaus_flagged=intel.get("urlhaus", {}).get("flagged", False),
            openphish_flagged=intel.get("openphish", {}).get("flagged", False),
            urlscan_flagged=intel.get("urlscan", {}).get("flagged", False),
            abuseipdb_flagged=intel.get("abuseipdb", {}).get("flagged", False),
            whois_creation_date=whois.get("creation_date"),
            domain_age_days=whois.get("age_days"),
            page_title=scrape.get("title", ""),
            page_keywords=scrape.get("keywords", []),
            ip_address=ip,
            threat_intel_details={
                "factors": risk.get("factors", []),
                "virustotal": intel.get("virustotal", {}),
                "google_safe_browsing": intel.get("google_safe_browsing", {}),
                "urlhaus": intel.get("urlhaus", {}),
                "openphish": intel.get("openphish", {}),
                "urlscan": intel.get("urlscan", {}),
                "abuseipdb": intel.get("abuseipdb", {}),
            },
        ))

    # Sort: existing first, then by risk score desc
    variants.sort(key=lambda x: (not x.exists, -x.risk_score))

    # ── Step 6: Overall risk ───────────────────────────────────────────────
    overall = determine_overall_risk(variants)
    existing_count = sum(1 for v in variants if v.exists)
    high_risk = sum(
        1 for v in variants
        if v.exists and v.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    )
    duration = round(time.time() - start, 2)

    return DetectionResult(
        query_domain=domain,
        is_legitimate=True,
        total_variants_generated=len(variants),
        total_variants_existing=existing_count,
        high_risk_count=high_risk,
        overall_risk_score=overall["score"],
        overall_risk_level=overall["level"],
        variants=variants,
        scan_duration_seconds=duration,
        scanned_at=datetime.utcnow(),
        summary=RISK_SUMMARIES.get(overall["level"], ""),
    )
