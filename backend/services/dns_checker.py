"""
Async DNS Resolution Service
"""
import asyncio
import logging
import socket
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


async def check_domain_dns(domain: str) -> Tuple[bool, Optional[str]]:
    loop = asyncio.get_event_loop()
    try:
        ip = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, domain),
            timeout=5.0
        )
        return True, ip
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return False, None


async def check_https(domain: str) -> bool:
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://{domain}",
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=True,
            ) as resp:
                return resp.status < 500
    except Exception:
        return False


async def batch_dns_check(
    domains: List[str],
    concurrency: int = 20
) -> Dict[str, Tuple[bool, Optional[str]]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def _check(domain: str):
        async with semaphore:
            exists, ip = await check_domain_dns(domain)
            return domain, exists, ip

    results = await asyncio.gather(
        *[_check(d) for d in domains],
        return_exceptions=True
    )

    checked: Dict[str, Tuple[bool, Optional[str]]] = {}
    for result in results:
        if isinstance(result, Exception):
            continue
        domain, exists, ip = result
        checked[domain] = (exists, ip)
    return checked
