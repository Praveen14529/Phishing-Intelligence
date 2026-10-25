from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True

    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db: str = "phishing_intelligence"

    # Threat Intel API Keys
    virustotal_api_key: Optional[str] = None
    google_safe_browsing_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None       # https://urlscan.io
    abuseipdb_api_key: Optional[str] = None     # https://abuseipdb.com
    # URLhaus and OpenPhish require NO keys

    request_timeout: int = 10
    dns_concurrency: int = 20
    max_domain_variants: int = 50

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
