from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api import actions, analyst, coverage, health, incidents, live, runs, scenarios
from backend.dependencies import incident_repository
from backend.settings import settings


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    incident_repository.initialize()
    logger.info("RAVEN-SOC API startup complete.")
    yield
    logger.info("RAVEN-SOC API shutdown complete.")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="API layer for the local RAVEN-SOC simulation and Analyst pipeline.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Accept", "Authorization", "Content-Type"],
)


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
app.include_router(runs.router, prefix=api_prefix)
app.include_router(incidents.router, prefix=api_prefix)
app.include_router(analyst.router, prefix=api_prefix)
app.include_router(actions.router, prefix=api_prefix)
app.include_router(live.router, prefix=api_prefix)
