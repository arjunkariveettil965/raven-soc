from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.api import actions, analyst, coverage, health, incidents, scenarios
from backend.settings import settings


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="API layer for the local RAVEN-SOC simulation and Analyst pipeline.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


@app.on_event("startup")
def log_startup() -> None:
    logger.info("RAVEN-SOC API startup complete.")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled API error at %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error."},
    )


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "status": "available",
        "version": settings.version,
    }


api_prefix = "/api/v1"
app.include_router(health.router, prefix=api_prefix)
app.include_router(scenarios.router, prefix=api_prefix)
app.include_router(coverage.router, prefix=api_prefix)
app.include_router(incidents.router, prefix=api_prefix)
app.include_router(analyst.router, prefix=api_prefix)
app.include_router(actions.router, prefix=api_prefix)
