from __future__ import annotations

from fastapi import APIRouter

from backend.services.coverage_service import get_coverage


router = APIRouter(prefix="/coverage", tags=["coverage"])


@router.get("")
def coverage() -> dict[str, object]:
    return get_coverage()
