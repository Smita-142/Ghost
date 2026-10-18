from fastapi import APIRouter, HTTPException

from app.db.connection import check_health

router = APIRouter(prefix="/api")


@router.get("/health")
def get_health() -> dict:
    db_status = check_health()
    return {
        "status": "ok" if db_status.get("connected") else "degraded",
        "version": "1.0.0",
        "database": db_status,
    }


@router.get("/health/database")
def get_database_health() -> dict:
    db_status = check_health()
    if not db_status.get("connected"):
        raise HTTPException(status_code=503, detail={"database": db_status, "message": "FalkorDB is unavailable."})
    return {"status": "healthy", "database": db_status}
