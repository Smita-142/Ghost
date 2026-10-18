from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routes.cases import router as cases_router
from app.routes.dashboard import router as dashboard_router
from app.routes.health import router as health_router
from app.routes.vulnerabilities import router as vulnerabilities_router

settings = get_settings()
app = FastAPI(title="VulnGraph AI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(dashboard_router)
app.include_router(vulnerabilities_router)
app.include_router(cases_router)


@app.get("/")
def read_root():
    return {"message": "VulnGraph AI backend is running."}
