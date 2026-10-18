from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services.graph_service import dashboard_severity_distribution, dashboard_summary

router = APIRouter(prefix="/api")


@router.get("/dashboard/summary")
def get_dashboard_summary() -> dict:
    try:
        return dashboard_summary()
    except Exception as exc:  # pragma: no cover - fallback for missing DB
        raise HTTPException(status_code=503, detail={"message": "Dashboard data is unavailable because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.get("/dashboard/severity-distribution")
def get_dashboard_severity_distribution() -> list[dict]:
    try:
        return dashboard_severity_distribution()
    except Exception as exc:  # pragma: no cover - fallback for missing DB
        raise HTTPException(status_code=503, detail={"message": "Severity distribution is unavailable because FalkorDB is unreachable.", "error": str(exc)}) from exc


@router.get("/dashboard/risk-trends")
def get_dashboard_risk_trends() -> list[dict]:
    try:
        rows = dashboard_severity_distribution()
        return [{"label": item["severity"], "value": item["count"]} for item in rows]
    except Exception as exc:  # pragma: no cover - fallback for missing DB
        raise HTTPException(status_code=503, detail={"message": "Trend data is unavailable because FalkorDB is unreachable.", "error": str(exc)}) from exc
