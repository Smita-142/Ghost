from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.config import get_settings
from app.routes.cases import router as cases_router
from app.routes.dashboard import router as dashboard_router
from app.routes.health import router as health_router
from app.routes.vulnerabilities import router as vulnerabilities_router

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-seed demo data if the graph is empty
    try:
        from app.db.connection import get_graph
        graph = get_graph()
        result = graph.query("MATCH (v:Vulnerability) RETURN count(v) AS cnt")
        count = result.result_set[0][0] if result.result_set else 0
        if count == 0:
            logger.info("Empty graph detected — seeding demo data...")
            from app.seed import seed_graph
            seed_result = seed_graph()
            logger.info("Seeded: %s", seed_result)
        else:
            logger.info("Graph already has %d vulnerabilities, skipping seed.", count)
    except Exception as exc:
        logger.warning("Auto-seed skipped: %s", exc)
    yield


app = FastAPI(title="VulnGraph AI", version="1.0.0", lifespan=lifespan)

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

