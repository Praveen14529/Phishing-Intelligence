import ipaddress
import re
from urllib.parse import urlsplit


def normalize_domain(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("Invalid domain format")

    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in a domain")

    try:
        parsed.port
        hostname = parsed.hostname
    except ValueError as error:
        raise ValueError("Invalid domain format") from error

    if not hostname:
        raise ValueError("Invalid domain format")

    hostname = hostname[:-1] if hostname.endswith(".") else hostname
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid domain format") from error

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("A domain name is required, not an IP address")

    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise ValueError("Invalid domain format")

    return hostname