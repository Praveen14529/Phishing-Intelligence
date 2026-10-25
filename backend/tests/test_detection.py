"""
PhishGuard v2 — Test Suite
Run: pytest tests/ -v
"""
import pytest
import asyncio


# ── Domain Generator ───────────────────────────────────────────────────────

def test_generate_variants_basic():
    from services.domain_generator import generate_all_variants
    variants = generate_all_variants("youtube.com")
    domains = [v["domain"] for v in variants]
    assert len(domains) > 0
    assert "youtube.com" not in domains


def test_generate_variants_respects_limit():
    from services.domain_generator import generate_all_variants
    assert len(generate_all_variants("youtube.com", max_variants=3)) == 3


def test_generate_omission():
    from services.domain_generator import generate_all_variants
    variants = generate_all_variants("google.com")
    domains = [v["domain"] for v in variants]
    assert any("gogle" in d for d in domains)


def test_generate_repetition():
    from services.domain_generator import generate_all_variants
    variants = generate_all_variants("apple.com")
    domains = [v["domain"] for v in variants]
    assert any("appple" in d or "aapple" in d for d in domains)


def test_generate_tld_variation():
    from services.domain_generator import generate_all_variants
    variants = generate_all_variants("paypal.com")
    tld_variants = [v for v in variants if v["technique"] == "tld-variation"]
    assert len(tld_variants) > 0


def test_similarity_identical():
    from services.domain_generator import calculate_similarity
    assert calculate_similarity("youtube.com", "youtube.com") == 1.0


def test_similarity_close():
    from services.domain_generator import calculate_similarity
    assert calculate_similarity("youtube.com", "youtubee.com") > 0.8


def test_similarity_different():
    from services.domain_generator import calculate_similarity
    assert calculate_similarity("youtube.com", "amazon.com") < 0.5


# ── Risk Scorer ────────────────────────────────────────────────────────────

def test_risk_score_clean():
    from services.risk_scorer import compute_risk_score
    result = compute_risk_score(
        domain="youtubee.com", similarity_score=0.9, has_https=True,
        virustotal={"detected": False, "positives": 0},
        google_safe_browsing={"flagged": False},
        urlhaus={"flagged": False},
        openphish={"flagged": False},
        urlscan={"flagged": False},
        abuseipdb={"flagged": False},
        whois={"age_days": 500},
    )
    assert 0 <= result["score"] <= 100
    assert result["level"] in ["safe", "low", "medium", "high", "critical"]


def test_risk_score_high():
    from services.risk_scorer import compute_risk_score
    result = compute_risk_score(
        domain="paypal-login-secure.com", similarity_score=0.95, has_https=False,
        virustotal={"detected": True, "positives": 10},
        google_safe_browsing={"flagged": True, "threat_types": ["SOCIAL_ENGINEERING"]},
        urlhaus={"flagged": True, "active_malware_urls": 3},
        openphish={"flagged": True},
        urlscan={"flagged": True, "malicious_scans": 2},
        abuseipdb={"flagged": True, "abuse_score": 85},
        whois={"age_days": 5},
    )
    assert result["score"] >= 70
    assert result["level"] in ["high", "critical"]


def test_risk_score_no_https_adds_points():
    from services.risk_scorer import compute_risk_score
    empty = {"detected": False, "positives": 0, "flagged": False}
    with_https = compute_risk_score(
        domain="x.com", similarity_score=0.5, has_https=True,
        virustotal=empty, google_safe_browsing=empty,
        urlhaus=empty, openphish=empty, urlscan=empty,
        abuseipdb=empty, whois={},
    )
    without_https = compute_risk_score(
        domain="x.com", similarity_score=0.5, has_https=False,
        virustotal=empty, google_safe_browsing=empty,
        urlhaus=empty, openphish=empty, urlscan=empty,
        abuseipdb=empty, whois={},
    )
    assert without_https["score"] > with_https["score"]


def test_urlhaus_adds_risk():
    from services.risk_scorer import compute_risk_score
    empty = {"detected": False, "positives": 0, "flagged": False}
    without = compute_risk_score(
        domain="x.com", similarity_score=0.5, has_https=True,
        virustotal=empty, google_safe_browsing=empty,
        urlhaus={"flagged": False}, openphish=empty,
        urlscan=empty, abuseipdb=empty, whois={},
    )
    with_urlhaus = compute_risk_score(
        domain="x.com", similarity_score=0.5, has_https=True,
        virustotal=empty, google_safe_browsing=empty,
        urlhaus={"flagged": True, "active_malware_urls": 2},
        openphish=empty, urlscan=empty, abuseipdb=empty, whois={},
    )
    assert with_urlhaus["score"] > without["score"]


# ── DNS ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dns_check_real_domain():
    from services.dns_checker import check_domain_dns
    exists, ip = await check_domain_dns("google.com")
    assert isinstance(exists, bool)
    if exists:
        assert ip is not None


@pytest.mark.asyncio
async def test_dns_check_fake_domain():
    from services.dns_checker import check_domain_dns
    exists, ip = await check_domain_dns(
        "this-domain-definitely-does-not-exist-99999.com"
    )
    assert exists is False


@pytest.mark.asyncio
async def test_batch_dns_check_skips_failed_lookup(monkeypatch):
    from services import dns_checker

    async def check_domain(domain):
        if domain == "broken.example":
            raise RuntimeError("lookup failed")
        return True, "192.0.2.1"

    monkeypatch.setattr(dns_checker, "check_domain_dns", check_domain)
    result = await dns_checker.batch_dns_check(
        ["broken.example", "working.example"]
    )

    assert result == {"working.example": (True, "192.0.2.1")}


# ── Threat Intel Mocks ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_virustotal_mock_suspicious():
    from services.threat_intel import check_virustotal
    result = await check_virustotal("login-secure-paypal.com")
    assert "detected" in result
    assert "source" in result


@pytest.mark.asyncio
async def test_google_safe_browsing_mock():
    from services.threat_intel import check_google_safe_browsing
    result = await check_google_safe_browsing("phish-example.com")
    assert "flagged" in result


@pytest.mark.asyncio
async def test_urlhaus_returns_dict():
    from services.threat_intel import check_urlhaus
    result = await check_urlhaus("example.com")
    assert "flagged" in result
    assert "source" in result


@pytest.mark.asyncio
async def test_openphish_returns_dict():
    from services.threat_intel import check_openphish
    result = await check_openphish("example.com")
    assert "flagged" in result
    assert "source" in result


# ── Full Pipeline ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_detection_pipeline():
    from services.detector import run_detection
    result = await run_detection("example.com", deep_scan=False)
    assert result.query_domain == "example.com"
    assert result.total_variants_generated > 0
    assert 0 <= result.overall_risk_score <= 100
    assert len(result.variants) > 0
    assert result.overall_risk_level in [
        "safe", "low", "medium", "high", "critical"
    ]
