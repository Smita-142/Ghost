from pydantic_settings import BaseSettings
from functools import lru_cache
import os


class Settings(BaseSettings):
    # FalkorDB
    falkordb_host: str = "localhost"
    falkordb_port: int = 6379
    falkordb_username: str = ""
    falkordb_password: str = ""
    falkordb_graph_name: str = "vulngraph"
    falkordb_ssl: bool = False

    # Public vulnerability intelligence. Demo remains the explicit offline default.
    vuln_data_mode: str = "demo"
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_timeout_seconds: float = 30.0
    nvd_page_size: int = 2000
    nvd_request_interval_seconds: float = 6.0
    osv_base_url: str = "https://api.osv.dev/v1"
    osv_timeout_seconds: float = 20.0

    # API
    api_cors_origins: list[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
    ]

    # LLM (optional)
    llm_provider: str = "none"  # "openai", "anthropic", "none"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    # App
    app_env: str = "development"
    debug: bool = True

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
