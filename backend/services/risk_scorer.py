"""
Risk Scoring Engine
Computes 0-100 risk score using all threat intel signals.
"""
from typing import Any, Dict
from models.schemas import RiskLevel

WEIGHTS = {
    "virustotal_detected": 35,
    "google_flagged": 25,
    "urlhaus_flagged": 20,
    "openphish_flagged": 15,
    "urlscan_flagged": 10,
    "abuseipdb_flagged": 10,
    "no_https": 5,
    "newly_registered": 10,
    "very_new": 5,
    "high_similarity": 8,
    "phishing_keyword": 7,
}

PHISHING_KEYWORDS = [
    "login", "secure", "signin", "verify", "account", "update",
    "confirm", "password", "credential", "banking", "paypal",
    "support", "helpdesk", "recovery", "reset", "service"
]


def compute_risk_score(
    domain: str,
    similarity_score: float,
    has_https: bool,
    virustotal: Dict[str, Any],
    google_safe_browsing: Dict[str, Any],
    urlhaus: Dict[str, Any],
    openphish: Dict[str, Any],
    urlscan: Dict[str, Any],
    abuseipdb: Dict[str, Any],
    whois: Dict[str, Any],
) -> Dict[str, Any]:
    score = 0
    factors = []

    # VirusTotal
    vt_positives = virustotal.get("positives", 0)
    if virustotal.get("detected") or vt_positives > 0:
        score += WEIGHTS["virustotal_detected"]
        factors.append(f"VirusTotal: {vt_positives} engines flagged")

    # Google Safe Browsing
    if google_safe_browsing.get("flagged"):
        score += WEIGHTS["google_flagged"]
        threats = google_safe_browsing.get("threat_types", [])
        factors.append(
            f"Google Safe Browsing: {', '.join(threats) or 'flagged'}"
        )

    # URLhaus
    if urlhaus.get("flagged"):
        score += WEIGHTS["urlhaus_flagged"]
        active = urlhaus.get("active_malware_urls", 0)
        factors.append(f"URLhaus: {active} active malware URLs")

    # OpenPhish
    if openphish.get("flagged"):
        score += WEIGHTS["openphish_flagged"]
        factors.append("OpenPhish: confirmed phishing URL")

    # URLScan
    if urlscan.get("flagged"):
        score += WEIGHTS["urlscan_flagged"]
        factors.append(
            f"URLScan: {urlscan.get('malicious_scans', 0)} malicious scans"
        )

    # AbuseIPDB
    if abuseipdb.get("flagged"):
        score += WEIGHTS["abuseipdb_flagged"]
        factors.append(
            f"AbuseIPDB: IP score {abuseipdb.get('abuse_score', 0)}"
        )

    # HTTPS
    if not has_https:
        score += WEIGHTS["no_https"]
        factors.append("No HTTPS")

    # Domain age
    age_days = whois.get("age_days")
    if age_days is not None:
        if age_days < 30:
            score += WEIGHTS["newly_registered"]
            factors.append(f"Newly registered ({age_days} days old)")
        elif age_days < 90:
            score += WEIGHTS["very_new"]
            factors.append(f"Recently registered ({age_days} days old)")

    # Similarity
    if similarity_score >= 0.85:
        score += WEIGHTS["high_similarity"]
        factors.append(
            f"High similarity to target ({similarity_score:.0%})"
        )

    # Phishing keywords
    lower = domain.lower()
    matched = [kw for kw in PHISHING_KEYWORDS if kw in lower]
    if matched:
        score += WEIGHTS["phishing_keyword"]
        factors.append(f"Phishing keywords: {', '.join(matched[:3])}")

    score = min(score, 100)

    if score == 0:
        level = RiskLevel.SAFE
    elif score <= 15:
        level = RiskLevel.LOW
    elif score <= 40:
        level = RiskLevel.MEDIUM
    elif score <= 70:
        level = RiskLevel.HIGH
    else:
        level = RiskLevel.CRITICAL

    return {"score": score, "level": level, "factors": factors}


def determine_overall_risk(variants) -> Dict[str, Any]:
    scores = [v.risk_score for v in variants if v.exists]
    if not scores:
        return {"score": 0, "level": RiskLevel.SAFE}

    avg = sum(scores) / len(scores)
    peak = max(scores)
    overall = min(int(avg * 0.4 + peak * 0.6), 100)

    if overall == 0:
        level = RiskLevel.SAFE
    elif overall <= 15:
        level = RiskLevel.LOW
    elif overall <= 40:
        level = RiskLevel.MEDIUM
    elif overall <= 70:
        level = RiskLevel.HIGH
    else:
        level = RiskLevel.CRITICAL

    return {"score": overall, "level": level}
