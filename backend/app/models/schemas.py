"""Pydantic schemas for VulnGraph AI."""
from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum


# ─── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class VulnStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Priority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ─── Node schemas ─────────────────────────────────────────────────────────────

class VulnerabilityBase(BaseModel):
    cve_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    status: VulnStatus = VulnStatus.OPEN
    exploit_available: bool = False
    source: str = "synthetic_fixture"
    record_type: str = "synthetic_fixture"
    last_synchronized_at: Optional[str] = None
    affected_package_mapping: str = "unavailable"
    references: List[dict[str, Any]] = []
    affected_products: List[dict[str, Any]] = []


class Vulnerability(VulnerabilityBase):
    id: str
    risk_score: Optional[float] = None
    priority: Optional[Priority] = None

    class Config:
        from_attributes = True


class Package(BaseModel):
    id: str
    name: str
    version: str
    ecosystem: str
    direct_dependency: bool = True
    criticality: str = "medium"


class Service(BaseModel):
    id: str
    name: str
    environment: str
    owner: str
    criticality: str
    internet_facing: bool
    business_unit: str


class Exposure(BaseModel):
    id: str
    type: str
    internet_accessible: bool
    authentication_required: bool
    network_zone: str
    description: str


class DataAsset(BaseModel):
    id: str
    name: str
    data_classification: str
    business_criticality: str
    description: str


class TriageCase(BaseModel):
    id: str
    title: str
    priority: Priority
    status: CaseStatus
    assigned_to: Optional[str] = None
    created_at: str
    updated_at: str
    analyst_notes: Optional[str] = None
    recommended_action: Optional[str] = None
    vulnerability_id: Optional[str] = None


# ─── Request schemas ──────────────────────────────────────────────────────────

class CreateCaseRequest(BaseModel):
    vulnerability_id: str
    title: str
    priority: Priority
    assigned_to: Optional[str] = None
    analyst_notes: Optional[str] = None
    recommended_action: Optional[str] = None


class UpdateCaseRequest(BaseModel):
    status: Optional[CaseStatus] = None
    analyst_notes: Optional[str] = None
    recommended_action: Optional[str] = None
    assigned_to: Optional[str] = None


class TriageRequest(BaseModel):
    vulnerability_id: str


class InvestigateRequest(BaseModel):
    vulnerability_id: str
    question: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    vulnerability_id: Optional[str] = None
    conversation_id: Optional[str] = None


# ─── Response schemas ─────────────────────────────────────────────────────────

class RiskFactor(BaseModel):
    factor: str
    contribution: float
    detail: str


class EvidencePath(BaseModel):
    path: List[str]
    relationship_types: List[str]
    risk_significance: str


class TriageResult(BaseModel):
    vulnerability_id: str
    priority: Priority
    risk_score: float
    summary: str
    reasoning: str
    evidence_paths: List[EvidencePath] = []
    affected_packages: List[Package] = []
    affected_services: List[Service] = []
    exposures: List[Exposure] = []
    reachable_assets: List[DataAsset] = []
    recommended_actions: List[str] = []
    remediation: str
    confidence: str
    limitations: List[str] = []
    risk_factors: List[RiskFactor] = []


class DashboardSummary(BaseModel):
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    internet_facing_services: int
    sensitive_data_exposed: int
    open_cases: int
    resolved_cases: int
    critical_risk_vulns: int


class SeverityDistribution(BaseModel):
    severity: str
    count: int


class ImpactAnalysis(BaseModel):
    vulnerability: Vulnerability
    affected_packages: List[Package]
    affected_services: List[Service]
    exposures: List[Exposure]
    reachable_assets: List[DataAsset]
    risk_score: float
    priority: Priority
    evidence_paths: List[EvidencePath] = []


class VulnerabilityListResponse(BaseModel):
    items: List[Vulnerability]
    total: int
    page: int
    page_size: int
    pages: int


class ChatMessage(BaseModel):
    role: str  # "user" | "assistant"
    content: str
    timestamp: Optional[str] = None


class ChatResponse(BaseModel):
    message: str
    conversation_id: str
    vulnerability_context: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str = "1.0.0"
    database: dict
