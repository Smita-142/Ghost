from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.graph_service import create_triage_case, list_triage_cases, update_triage_case

router = APIRouter(prefix="/api")


class CaseCreatePayload(BaseModel):
    vulnerability_id: str
    title: str
    priority: str
    assigned_to: str | None = None
    analyst_notes: str | None = None
    recommended_action: str | None = None
    status: str = "open"


class CaseUpdatePayload(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    analyst_notes: str | None = None
    recommended_action: str | None = None
    title: str | None = None
    priority: str | None = None


@router.get("/cases")
def get_cases() -> list[dict]:
    try:
        return list_triage_cases()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Triage case query failed because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.post("/cases")
def create_case(payload: CaseCreatePayload) -> dict:
    try:
        body = payload.model_dump()
        data = create_triage_case(body)
        return data
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Triage case creation failed because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.patch("/cases/{case_id}")
def update_case(case_id: str, payload: CaseUpdatePayload) -> dict:
    try:
        data = update_triage_case(case_id, payload.model_dump(exclude_none=True))
        if data is None:
            raise HTTPException(status_code=404, detail={"message": "Triage case not found."})
        return data
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Triage case update failed because FalkorDB is unreachable.", "error": str(exc)}) from exc
