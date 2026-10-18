from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.models.schemas import TriageRequest, TriageResult
from app.config import get_settings
from app.services.graph_service import (
    fetch_related_vulnerabilities,
    fetch_service_analysis,
    fetch_vulnerability_by_id,
    fetch_vulnerability_impact,
    fetch_vulnerabilities,
)
from app.services.triage_agent import generate_triage_result

router = APIRouter(prefix="/api")


@router.get("/vulnerabilities")
def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    package: str | None = None,
) -> dict:
    try:
        selected_source = source or get_settings().vuln_data_mode
        data = fetch_vulnerabilities(search=search, severity=severity, status=status, page=page, page_size=page_size, source=None if selected_source.lower() == "all" else selected_source, package=package)
        return data
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Vulnerability inventory is unavailable because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.post("/vulnerabilities/refresh")
def refresh_vulnerabilities(days: int = Query(30, ge=1, le=120), cve_id: str | None = None, include_osv: bool = True) -> dict:
    """Explicitly synchronize external intelligence; dashboard requests never trigger ingestion."""
    try:
        from app.services.vulnerability_sync import synchronize_vulnerabilities
        return synchronize_vulnerabilities(days=days, cve_id=cve_id, include_osv=include_osv)
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"message": "Vulnerability synchronization failed.", "error": str(exc)}) from exc


@router.get("/vulnerabilities/{vulnerability_id}")
def get_vulnerability(vulnerability_id: str) -> dict:
    try:
        row = fetch_vulnerability_by_id(vulnerability_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"message": "Vulnerability not found."})
        return row
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Vulnerability lookup failed because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.get("/vulnerabilities/{vulnerability_id}/impact")
def get_vulnerability_impact(vulnerability_id: str) -> dict:
    try:
        impact = fetch_vulnerability_impact(vulnerability_id)
        return impact
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Impact analysis failed because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.get("/vulnerabilities/{vulnerability_id}/related")
def get_related_vulnerabilities(vulnerability_id: str) -> list[dict]:
    try:
        return fetch_related_vulnerabilities(vulnerability_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Related vulnerability analysis failed because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.get("/services/{service_id}")
def get_service_analysis(service_id: str) -> dict:
    try:
        return fetch_service_analysis(service_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Service analysis failed because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.post("/triage/{vulnerability_id}/analyze", response_model=TriageResult)
def analyze_vulnerability(vulnerability_id: str, payload: TriageRequest | None = None):
    try:
        vulnerability = fetch_vulnerability_by_id(vulnerability_id)
        if vulnerability is None:
            raise HTTPException(status_code=404, detail={"message": "Vulnerability not found."})
        impact = fetch_vulnerability_impact(vulnerability_id)
        result = generate_triage_result(vulnerability, impact)
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Triage analysis failed because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.get("/reports/export")
def export_report() -> str:
    try:
        from app.services.graph_service import export_vulnerability_report_csv

        return export_vulnerability_report_csv()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"message": "Report generation failed because FalkorDB is unreachable.", "error": str(exc)}) from exc
