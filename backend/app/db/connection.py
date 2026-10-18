"""FalkorDB connection management for VulnGraph AI."""
import logging
from typing import Optional
import falkordb
from app.config import get_settings

logger = logging.getLogger(__name__)

_client: Optional[falkordb.FalkorDB] = None
_graph: Optional[falkordb.Graph] = None


def get_client() -> falkordb.FalkorDB:
    global _client
    if _client is None:
        settings = get_settings()
        try:
            kwargs: dict = {
                "host": settings.falkordb_host,
                "port": settings.falkordb_port,
            }
            if settings.falkordb_username:
                kwargs["username"] = settings.falkordb_username
            if settings.falkordb_password:
                kwargs["password"] = settings.falkordb_password
            _client = falkordb.FalkorDB(**kwargs)
            logger.info(
                "Connected to FalkorDB at %s:%s",
                settings.falkordb_host,
                settings.falkordb_port,
            )
        except Exception as exc:
            logger.error("Failed to connect to FalkorDB: %s", exc)
            raise
    return _client


def get_graph() -> falkordb.Graph:
    global _graph
    if _graph is None:
        settings = get_settings()
        client = get_client()
        _graph = client.select_graph(settings.falkordb_graph_name)
    return _graph


def reset_connection() -> None:
    """Reset the cached connection (useful after failures or in tests)."""
    global _client, _graph
    _client = None
    _graph = None


def check_health() -> dict:
    """Return a dict describing database health."""
    try:
        graph = get_graph()
        result = graph.query("RETURN 1 AS ping")
        return {"status": "healthy", "connected": True, "detail": "FalkorDB reachable"}
    except Exception as exc:
        return {
            "status": "unhealthy",
            "connected": False,
            "detail": str(exc),
        }


def run_query(cypher: str, params: dict | None = None):
    """Execute a Cypher query and return the result set."""
    graph = get_graph()
    if params:
        return graph.query(cypher, params)
    return graph.query(cypher)
