"""
WHOIS & Web Scraping Service
"""
import asyncio
import logging
from datetime import datetime
from typing import Any, Dict

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


async def get_whois_info(domain: str) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    try:
        import whois
        result = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, domain),
            timeout=10.0
        )
        creation = result.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        age_days = None
        creation_str = None
        if creation and isinstance(creation, datetime):
            age_days = (datetime.utcnow() - creation).days
            creation_str = creation.strftime("%Y-%m-%d")

        return {
            "creation_date": creation_str,
            "age_days": age_days,
            "registrar": getattr(result, "registrar", None),
            "country": getattr(result, "country", None),
        }
    except asyncio.TimeoutError:
        logger.warning(f"WHOIS timeout: {domain}")
    except Exception as e:
        logger.debug(f"WHOIS error [{domain}]: {e}")

    return {
        "creation_date": None, "age_days": None,
        "registrar": None, "country": None
    }


async def scrape_page_metadata(domain: str) -> Dict[str, Any]:
    for scheme in ["https", "http"]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{scheme}://{domain}",
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=True,
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; PhishBot/2.0)"
                    }
                ) as resp:
                    if resp.status >= 500:
                        continue
                    html = await resp.text(errors="ignore")
                    soup = BeautifulSoup(html, "html.parser")

                    title = (
                        soup.title.string.strip()
                        if soup.title else ""
                    )

                    meta_kw = soup.find(
                        "meta", attrs={"name": "keywords"}
                    )
                    keywords = []
                    if meta_kw:
                        keywords = [
                            k.strip()
                            for k in meta_kw.get("content", "").split(",")
                            if k.strip()
                        ][:10]

                    return {
                        "title": title[:200],
                        "keywords": keywords,
                        "final_url": str(resp.url),
                    }
        except Exception as e:
            logger.debug(f"Scrape error [{domain}] ({scheme}): {e}")

    return {"title": "", "keywords": [], "final_url": ""}
