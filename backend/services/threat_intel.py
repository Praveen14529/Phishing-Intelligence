"""
Threat Intelligence Service
Uses: VirusTotal, Google Safe Browsing, URLhaus,
      OpenPhish, URLScan.io, AbuseIPDB
PhishTank has been REMOVED (registration closed).
URLhaus + OpenPhish require NO API keys.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
import aiohttp

from config import settings

logger = logging.getLogger(__name__)

# Cache OpenPhish feed in memory
_openphish_cache: List[str] = []
_openphish_loaded = False


# ─────────────────────────────────────────────
#  VirusTotal
# ─────────────────────────────────────────────

async def check_virustotal(domain: str) -> Dict[str, Any]:
    if not settings.virustotal_api_key:
        return _mock_virustotal(domain)

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = (
                        data.get("data", {})
                            .get("attributes", {})
                            .get("last_analysis_stats", {})
                    )
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    return {
                        "detected": (malicious + suspicious) > 0,
                        "positives": malicious + suspicious,
                        "total_engines": sum(stats.values()),
                        "source": "virustotal"
                    }
                elif resp.status == 404:
                    return {
                        "detected": False, "positives": 0,
                        "total_engines": 0, "source": "virustotal"
                    }
    except Exception as e:
        logger.warning(f"VirusTotal error [{domain}]: {e}")

    return {"detected": False, "positives": 0,
            "total_engines": 0, "source": "virustotal"}


def _mock_virustotal(domain: str) -> Dict[str, Any]:
    keywords = ["login", "secure", "signin", "verify",
                "account", "update", "paypal", "apple"]
    detected = any(k in domain for k in keywords)
    return {
        "detected": detected,
        "positives": 3 if detected else 0,
        "total_engines": 72,
        "source": "virustotal_mock"
    }


# ─────────────────────────────────────────────
#  Google Safe Browsing
# ─────────────────────────────────────────────

async def check_google_safe_browsing(domain: str) -> Dict[str, Any]:
    if not settings.google_safe_browsing_api_key:
        return _mock_google_safe_browsing(domain)

    url = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.google_safe_browsing_api_key}"
    )
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": f"http://{domain}"},
                {"url": f"https://{domain}"},
            ]
        }
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()
                matches = data.get("matches", [])
                return {
                    "flagged": len(matches) > 0,
                    "threat_types": list(
                        {m.get("threatType") for m in matches}
                    ),
                    "source": "google_safe_browsing"
                }
    except Exception as e:
        logger.warning(f"Google Safe Browsing error [{domain}]: {e}")

    return {"flagged": False, "threat_types": [],
            "source": "google_safe_browsing"}


def _mock_google_safe_browsing(domain: str) -> Dict[str, Any]:
    patterns = ["phish", "malware", "hack", "-secure-", "login-"]
    flagged = any(p in domain for p in patterns)
    return {
        "flagged": flagged,
        "threat_types": ["SOCIAL_ENGINEERING"] if flagged else [],
        "source": "google_safe_browsing_mock"
    }


# ─────────────────────────────────────────────
#  URLhaus — NO API KEY NEEDED
# ─────────────────────────────────────────────

async def check_urlhaus(domain: str) -> Dict[str, Any]:
    """
    Check domain against URLhaus malware database.
    No API key required. https://urlhaus-api.abuse.ch
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()
                if data.get("query_status") == "is_host":
                    urls = data.get("urls", [])
                    active = [u for u in urls
                              if u.get("url_status") == "online"]
                    return {
                        "flagged": True,
                        "active_malware_urls": len(active),
                        "total_malware_urls": len(urls),
                        "tags": data.get("tags", []),
                        "source": "urlhaus"
                    }
    except Exception as e:
        logger.warning(f"URLhaus error [{domain}]: {e}")

    return {
        "flagged": False, "active_malware_urls": 0,
        "total_malware_urls": 0, "tags": [], "source": "urlhaus"
    }


# ─────────────────────────────────────────────
#  OpenPhish — NO API KEY NEEDED
# ─────────────────────────────────────────────

async def _load_openphish_feed() -> List[str]:
    global _openphish_cache, _openphish_loaded
    if _openphish_loaded:
        return _openphish_cache
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://openphish.com/feed.txt",
                timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    _openphish_cache = [
                        line.strip()
                        for line in text.splitlines()
                        if line.strip()
                    ]
                    _openphish_loaded = True
                    logger.info(
                        f"OpenPhish feed: {len(_openphish_cache)} URLs loaded"
                    )
    except Exception as e:
        logger.warning(f"OpenPhish feed error: {e}")
    return _openphish_cache


async def check_openphish(domain: str) -> Dict[str, Any]:
    """
    Check domain against OpenPhish phishing feed.
    No API key required. https://openphish.com
    """
    try:
        feed = await _load_openphish_feed()
        normalized_domain = domain.lower().rstrip(".")
        flagged = any(
            (hostname := (urlsplit(url).hostname or "").lower().rstrip("."))
            == normalized_domain
            or hostname.endswith(f".{normalized_domain}")
            for url in feed
        )
        return {"flagged": flagged, "source": "openphish"}
    except Exception as e:
        logger.warning(f"OpenPhish error [{domain}]: {e}")
        return {"flagged": False, "source": "openphish"}


# ─────────────────────────────────────────────
#  URLScan.io — FREE API KEY
#  https://urlscan.io → Sign up → API Key
# ─────────────────────────────────────────────

async def check_urlscan(domain: str) -> Dict[str, Any]:
    if not settings.urlscan_api_key:
        return _mock_urlscan(domain)

    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
    headers = {"API-Key": settings.urlscan_api_key}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("results", [])
                    malicious = [
                        r for r in results
                        if r.get("verdicts", {})
                           .get("overall", {})
                           .get("malicious", False)
                    ]
                    return {
                        "flagged": len(malicious) > 0,
                        "total_scans": len(results),
                        "malicious_scans": len(malicious),
                        "source": "urlscan"
                    }
    except Exception as e:
        logger.warning(f"URLScan error [{domain}]: {e}")

    return {"flagged": False, "total_scans": 0,
            "malicious_scans": 0, "source": "urlscan"}


def _mock_urlscan(domain: str) -> Dict[str, Any]:
    keywords = ["login", "secure", "verify", "account", "update"]
    flagged = any(k in domain for k in keywords)
    return {
        "flagged": flagged,
        "total_scans": 2 if flagged else 0,
        "malicious_scans": 1 if flagged else 0,
        "source": "urlscan_mock"
    }


# ─────────────────────────────────────────────
#  AbuseIPDB — FREE API KEY
#  https://abuseipdb.com → Sign up → API Key
# ─────────────────────────────────────────────

async def check_abuseipdb(ip_address: str) -> Dict[str, Any]:
    if not ip_address or not settings.abuseipdb_api_key:
        return {"flagged": False, "abuse_score": 0, "source": "abuseipdb"}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json"
                },
                params={"ipAddress": ip_address, "maxAgeInDays": 90},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    score = data.get("data", {}).get(
                        "abuseConfidenceScore", 0
                    )
                    return {
                        "flagged": score > 25,
                        "abuse_score": score,
                        "total_reports": data.get(
                            "data", {}
                        ).get("totalReports", 0),
                        "source": "abuseipdb"
                    }
    except Exception as e:
        logger.warning(f"AbuseIPDB error [{ip_address}]: {e}")

    return {"flagged": False, "abuse_score": 0, "source": "abuseipdb"}


# ─────────────────────────────────────────────
#  Combined — runs all checks concurrently
# ─────────────────────────────────────────────

async def check_all_threat_intel(
    domain: str,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """Run all threat intel checks concurrently."""
    tasks = [
        check_virustotal(domain),
        check_google_safe_browsing(domain),
        check_urlhaus(domain),
        check_openphish(domain),
        check_urlscan(domain),
    ]
    keys = [
        "virustotal", "google_safe_browsing",
        "urlhaus", "openphish", "urlscan"
    ]

    if ip_address:
        tasks.append(check_abuseipdb(ip_address))
        keys.append("abuseipdb")

    results = await asyncio.gather(*tasks, return_exceptions=True)

    output = {}
    for key, result in zip(keys, results):
        if isinstance(result, Exception):
            logger.error(f"{key} failed: {result}")
            output[key] = {"flagged": False, "source": key}
        else:
            output[key] = result

    return output
