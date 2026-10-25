"""
PhishGuard — Phishing Intelligence Dashboard
FastAPI Backend Entry Point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from routes.detect import router as detect_router
from routes.history import router as history_router
from routes.stats import router as stats_router
from services.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="PhishGuard — Phishing Intelligence Dashboard API",
    description=(
        "Detect fake and phishing domains using typosquatting analysis, "
        "DNS checks, URLhaus, OpenPhish, URLScan, AbuseIPDB, VirusTotal "
        "and Google Safe Browsing."
    ),
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(detect_router, prefix="/api/v1", tags=["Detection"])
app.include_router(history_router, prefix="/api/v1", tags=["History"])
app.include_router(stats_router, prefix="/api/v1", tags=["Statistics"])


@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
