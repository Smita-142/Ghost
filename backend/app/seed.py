"""
Seed data for VulnGraph AI.
All CVE-IDs are clearly labelled synthetic demo data.
Run with: python -m app.seed
"""
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.connection import get_graph

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

VULNERABILITIES = [
    {"id": "vuln-001", "cve_id": "CVE-2024-DEMO-001", "title": "Remote Code Execution in express-validator", "description": "Improper input sanitization allows remote code execution via crafted HTTP requests.", "severity": "critical", "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "published_date": "2024-01-15", "modified_date": "2024-02-01", "status": "open", "exploit_available": True, "source": "demo"},
    {"id": "vuln-002", "cve_id": "CVE-2024-DEMO-002", "title": "SQL Injection in sequelize ORM", "description": "Parameterized query bypass allows SQL injection in dynamic WHERE clauses.", "severity": "critical", "cvss_score": 9.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "published_date": "2024-02-10", "modified_date": "2024-03-05", "status": "investigating", "exploit_available": True, "source": "demo"},
    {"id": "vuln-003", "cve_id": "CVE-2024-DEMO-003", "title": "Prototype Pollution in lodash", "description": "Merge operations allow prototype pollution leading to denial of service or property injection.", "severity": "high", "cvss_score": 7.4, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", "published_date": "2024-01-20", "modified_date": "2024-01-25", "status": "open", "exploit_available": False, "source": "demo"},
    {"id": "vuln-004", "cve_id": "CVE-2024-DEMO-004", "title": "Path Traversal in multer upload handler", "description": "Insufficient filename sanitization allows attackers to write files outside the intended directory.", "severity": "high", "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "published_date": "2024-03-01", "modified_date": "2024-03-10", "status": "open", "exploit_available": True, "source": "demo"},
    {"id": "vuln-005", "cve_id": "CVE-2024-DEMO-005", "title": "SSRF in axios HTTP client", "description": "Unvalidated URL redirection allows Server-Side Request Forgery attacks against internal services.", "severity": "high", "cvss_score": 7.2, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "published_date": "2024-02-22", "modified_date": "2024-03-01", "status": "open", "exploit_available": False, "source": "demo"},
    {"id": "vuln-006", "cve_id": "CVE-2024-DEMO-006", "title": "Denial of Service in jsonwebtoken", "description": "Algorithm confusion attack allows forged JWT tokens causing authentication bypass.", "severity": "critical", "cvss_score": 9.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "published_date": "2024-01-05", "modified_date": "2024-01-20", "status": "mitigated", "exploit_available": True, "source": "demo"},
    {"id": "vuln-007", "cve_id": "CVE-2024-DEMO-007", "title": "Insecure Deserialization in node-serialize", "description": "Deserializing untrusted data can lead to arbitrary code execution.", "severity": "critical", "cvss_score": 9.6, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "published_date": "2024-03-15", "modified_date": "2024-03-20", "status": "open", "exploit_available": True, "source": "demo"},
    {"id": "vuln-008", "cve_id": "CVE-2024-DEMO-008", "title": "XSS via DOMPurify bypass in React rendering", "description": "Certain SVG payloads bypass sanitization when rendered in dangerouslySetInnerHTML context.", "severity": "medium", "cvss_score": 6.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "published_date": "2024-02-01", "modified_date": "2024-02-14", "status": "open", "exploit_available": False, "source": "demo"},
    {"id": "vuln-009", "cve_id": "CVE-2024-DEMO-009", "title": "Command Injection in node-gyp build scripts", "description": "Unsanitized environment variables passed to shell commands allow command injection.", "severity": "high", "cvss_score": 7.8, "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "published_date": "2024-01-30", "modified_date": "2024-02-05", "status": "resolved", "exploit_available": False, "source": "demo"},
    {"id": "vuln-010", "cve_id": "CVE-2024-DEMO-010", "title": "Timing Attack in bcrypt comparison", "description": "Non-constant-time comparison in password verification allows timing-based enumeration.", "severity": "medium", "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "published_date": "2024-03-05", "modified_date": "2024-03-08", "status": "open", "exploit_available": False, "source": "demo"},
    {"id": "vuln-011", "cve_id": "CVE-2024-DEMO-011", "title": "ReDoS in validator.js email regex", "description": "Crafted email strings cause catastrophic backtracking leading to denial of service.", "severity": "medium", "cvss_score": 5.9, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", "published_date": "2024-02-18", "modified_date": "2024-02-20", "status": "open", "exploit_available": False, "source": "demo"},
    {"id": "vuln-012", "cve_id": "CVE-2024-DEMO-012", "title": "Open Redirect in passport.js callback", "description": "Insufficient validation of redirect_uri allows open redirect attacks post-authentication.", "severity": "low", "cvss_score": 3.7, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "published_date": "2024-01-10", "modified_date": "2024-01-12", "status": "open", "exploit_available": False, "source": "demo"},
    {"id": "vuln-013", "cve_id": "CVE-2024-DEMO-013", "title": "Heap Buffer Overflow in sharp image processing", "description": "Malicious JPEG files trigger heap overflow in native bindings, potential RCE.", "severity": "critical", "cvss_score": 8.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "published_date": "2024-03-20", "modified_date": "2024-03-22", "status": "investigating", "exploit_available": True, "source": "demo"},
    {"id": "vuln-014", "cve_id": "CVE-2024-DEMO-014", "title": "IDOR in REST API user endpoint", "description": "Missing object-level authorization allows users to access other users' data.", "severity": "high", "cvss_score": 7.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "published_date": "2024-02-28", "modified_date": "2024-03-02", "status": "open", "exploit_available": False, "source": "demo"},
    {"id": "vuln-015", "cve_id": "CVE-2024-DEMO-015", "title": "Memory Leak in socket.io connection handler", "description": "Event listeners not properly cleaned up on disconnect cause memory exhaustion under load.", "severity": "low", "cvss_score": 3.1, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", "published_date": "2024-01-25", "modified_date": "2024-01-28", "status": "resolved", "exploit_available": False, "source": "demo"},
]

PACKAGES = [
    {"id": "pkg-001", "name": "express-validator", "version": "7.1.0", "ecosystem": "npm", "direct_dependency": True, "criticality": "high"},
    {"id": "pkg-002", "name": "sequelize", "version": "6.37.3", "ecosystem": "npm", "direct_dependency": True, "criticality": "high"},
    {"id": "pkg-003", "name": "lodash", "version": "4.17.21", "ecosystem": "npm", "direct_dependency": True, "criticality": "medium"},
    {"id": "pkg-004", "name": "multer", "version": "1.4.5", "ecosystem": "npm", "direct_dependency": True, "criticality": "medium"},
    {"id": "pkg-005", "name": "axios", "version": "1.6.7", "ecosystem": "npm", "direct_dependency": True, "criticality": "high"},
    {"id": "pkg-006", "name": "jsonwebtoken", "version": "9.0.0", "ecosystem": "npm", "direct_dependency": True, "criticality": "high"},
    {"id": "pkg-007", "name": "node-serialize", "version": "0.0.1", "ecosystem": "npm", "direct_dependency": False, "criticality": "critical"},
    {"id": "pkg-008", "name": "dompurify", "version": "3.1.0", "ecosystem": "npm", "direct_dependency": True, "criticality": "medium"},
    {"id": "pkg-009", "name": "sharp", "version": "0.33.4", "ecosystem": "npm", "direct_dependency": True, "criticality": "high"},
    {"id": "pkg-010", "name": "bcrypt", "version": "5.1.1", "ecosystem": "npm", "direct_dependency": True, "criticality": "medium"},
    {"id": "pkg-011", "name": "validator", "version": "13.7.0", "ecosystem": "npm", "direct_dependency": True, "criticality": "medium"},
    {"id": "pkg-012", "name": "passport", "version": "0.7.0", "ecosystem": "npm", "direct_dependency": True, "criticality": "low"},
]

SERVICES = [
    {"id": "svc-001", "name": "gateway-api", "environment": "production", "owner": "Platform", "criticality": "critical", "internet_facing": True, "business_unit": "Customer Experience"},
    {"id": "svc-002", "name": "billing-service", "environment": "production", "owner": "Finance", "criticality": "critical", "internet_facing": False, "business_unit": "Financial Systems"},
    {"id": "svc-003", "name": "identity-provider", "environment": "production", "owner": "Security", "criticality": "critical", "internet_facing": True, "business_unit": "Identity"},
    {"id": "svc-004", "name": "media-processor", "environment": "production", "owner": "Media", "criticality": "high", "internet_facing": True, "business_unit": "Media"},
    {"id": "svc-005", "name": "admin-console", "environment": "production", "owner": "Operations", "criticality": "high", "internet_facing": True, "business_unit": "Operations"},
    {"id": "svc-006", "name": "notification-worker", "environment": "production", "owner": "Product", "criticality": "medium", "internet_facing": False, "business_unit": "Customer Experience"},
]

EXPOSURES = [
    {"id": "exp-001", "type": "Public API", "internet_accessible": True, "authentication_required": True, "network_zone": "DMZ", "description": "Public API endpoint exposed to the internet."},
    {"id": "exp-002", "type": "Database Port", "internet_accessible": False, "authentication_required": True, "network_zone": "Private", "description": "Internal database access path."},
    {"id": "exp-003", "type": "OIDC Callback", "internet_accessible": True, "authentication_required": False, "network_zone": "DMZ", "description": "Authentication callback endpoint served publicly."},
    {"id": "exp-004", "type": "Upload Endpoint", "internet_accessible": True, "authentication_required": True, "network_zone": "DMZ", "description": "File upload endpoint for managed content."},
    {"id": "exp-005", "type": "Admin Console", "internet_accessible": True, "authentication_required": True, "network_zone": "DMZ", "description": "Privileged administrative portal."},
    {"id": "exp-006", "type": "Internal Queue", "internet_accessible": False, "authentication_required": True, "network_zone": "Private", "description": "Application queue listener and worker endpoint."},
]

DATA_ASSETS = [
    {"id": "asset-001", "name": "Customer PII", "data_classification": "Sensitive", "business_criticality": "critical", "description": "Customer personal data with identity and contact details."},
    {"id": "asset-002", "name": "Payment Ledger", "data_classification": "Confidential", "business_criticality": "critical", "description": "Finance ledger and payment reconciliation data."},
    {"id": "asset-003", "name": "Internal JWT Secrets", "data_classification": "Restricted", "business_criticality": "critical", "description": "Authentication secrets for platform services."},
    {"id": "asset-004", "name": "Profile Images", "data_classification": "Internal", "business_criticality": "medium", "description": "Customer-uploaded media and thumbnails."},
    {"id": "asset-005", "name": "Admin Audit Logs", "data_classification": "Sensitive", "business_criticality": "high", "description": "Operational audit trails and account logging."},
    {"id": "asset-006", "name": "Billing Metadata", "data_classification": "Confidential", "business_criticality": "high", "description": "Invoices, tax records, and customer billing context."},
]

TRIAGE_CASES = [
    {"id": "case-001", "title": "Investigate gateway API RCE path", "priority": "CRITICAL", "status": "open", "assigned_to": "A. Patel", "analyst_notes": "Critical path to customer data via public API.", "recommended_action": "Patch and isolate the gateway API."},
    {"id": "case-002", "title": "Review identity provider auth bypass", "priority": "HIGH", "status": "investigating", "assigned_to": "M. Chen", "analyst_notes": "JWT algorithm confusion against identity service.", "recommended_action": "Rotate signing secrets and validate algorithms."},
    {"id": "case-003", "title": "Media pipeline file upload validation", "priority": "MEDIUM", "status": "resolved", "assigned_to": "J. Smith", "analyst_notes": "Mitigated by stricter filename validation and sandboxing.", "recommended_action": "Keep upload controls in place and monitor for anomalies."},
]

TRIAGE_CASE_TO_VULN = {"case-001": "vuln-001", "case-002": "vuln-006", "case-003": "vuln-004"}

VULNERABILITY_TO_PACKAGE = {
    "vuln-001": ["pkg-001"],
    "vuln-002": ["pkg-002"],
    "vuln-003": ["pkg-003"],
    "vuln-004": ["pkg-004"],
    "vuln-005": ["pkg-005"],
    "vuln-006": ["pkg-006"],
    "vuln-007": ["pkg-007"],
    "vuln-008": ["pkg-008"],
    "vuln-009": ["pkg-009"],
    "vuln-010": ["pkg-010"],
    "vuln-011": ["pkg-011"],
    "vuln-012": ["pkg-012"],
    "vuln-013": ["pkg-009"],
    "vuln-014": ["pkg-002"],
    "vuln-015": ["pkg-006"],
}

PACKAGE_TO_SERVICE = {
    "pkg-001": ["svc-001"],
    "pkg-002": ["svc-001", "svc-002"],
    "pkg-003": ["svc-005"],
    "pkg-004": ["svc-004"],
    "pkg-005": ["svc-001"],
    "pkg-006": ["svc-003"],
    "pkg-007": ["svc-005"],
    "pkg-008": ["svc-005"],
    "pkg-009": ["svc-004"],
    "pkg-010": ["svc-003"],
    "pkg-011": ["svc-006"],
    "pkg-012": ["svc-003"],
}

SERVICE_TO_EXPOSURE = {
    "svc-001": ["exp-001"],
    "svc-002": ["exp-002"],
    "svc-003": ["exp-003"],
    "svc-004": ["exp-004"],
    "svc-005": ["exp-005"],
    "svc-006": ["exp-006"],
}

SERVICE_TO_ASSET = {
    "svc-001": ["asset-001", "asset-003"],
    "svc-002": ["asset-002", "asset-006"],
    "svc-003": ["asset-003", "asset-005"],
    "svc-004": ["asset-004"],
    "svc-005": ["asset-005"],
    "svc-006": ["asset-001"],
}


def _merge_node(graph, label: str, node_id: str, properties: dict):
    graph.query(f"MERGE (n:{label} {{id: $id}}) SET n += $props", {"id": node_id, "props": properties})


def _merge_relationship(graph, start_label: str, start_id: str, rel_name: str, end_label: str, end_id: str):
    graph.query(
        f"MATCH (a:{start_label} {{id: $start_id}}), (b:{end_label} {{id: $end_id}}) MERGE (a)-[r:{rel_name}]->(b) SET r.source = 'synthetic_fixture', r.mapping_status = 'inferred_simulation'",
        {"start_id": start_id, "end_id": end_id},
    )


def seed_graph() -> dict:
    graph = get_graph()
    # Keep imported NVD/OSV intelligence and any authorized inventory intact.
    graph.query("MATCH (n) WHERE n.source IN ['demo', 'synthetic_fixture'] DETACH DELETE n")

    for vulnerability in VULNERABILITIES:
        vulnerability["source"] = "synthetic_fixture"
        vulnerability["record_type"] = "synthetic_fixture"
        vulnerability["affected_package_mapping"] = "inferred"
        vulnerability["last_synchronized_at"] = None
        _merge_node(graph, "Vulnerability", vulnerability["id"], vulnerability)
    for package in PACKAGES:
        package.update(source="synthetic_fixture", record_type="simulated_environment_entity", simulation=True)
        _merge_node(graph, "Package", package["id"], package)
    for service in SERVICES:
        service.update(source="synthetic_fixture", record_type="simulated_environment_entity", simulation=True)
        _merge_node(graph, "Service", service["id"], service)
    for exposure in EXPOSURES:
        exposure.update(source="synthetic_fixture", record_type="simulated_environment_entity", simulation=True)
        _merge_node(graph, "Exposure", exposure["id"], exposure)
    for asset in DATA_ASSETS:
        asset.update(source="synthetic_fixture", record_type="simulated_environment_entity", simulation=True)
        _merge_node(graph, "DataAsset", asset["id"], asset)
    for case in TRIAGE_CASES:
        case.update(source="synthetic_fixture", record_type="simulated_environment_entity", simulation=True)
        _merge_node(graph, "TriageCase", case["id"], case)

    for vulnerability_id, package_ids in VULNERABILITY_TO_PACKAGE.items():
        for package_id in package_ids:
            _merge_relationship(graph, "Vulnerability", vulnerability_id, "AFFECTS_PACKAGE", "Package", package_id)

    for package_id, service_ids in PACKAGE_TO_SERVICE.items():
        for service_id in service_ids:
            _merge_relationship(graph, "Package", package_id, "USED_BY", "Service", service_id)

    for service_id, exposure_ids in SERVICE_TO_EXPOSURE.items():
        for exposure_id in exposure_ids:
            _merge_relationship(graph, "Service", service_id, "HAS_EXPOSURE", "Exposure", exposure_id)

    for service_id, asset_ids in SERVICE_TO_ASSET.items():
        for asset_id in asset_ids:
            _merge_relationship(graph, "Service", service_id, "ACCESS_TO", "DataAsset", asset_id)

    for case_id, vulnerability_id in TRIAGE_CASE_TO_VULN.items():
        _merge_relationship(graph, "Vulnerability", vulnerability_id, "HAS_CASE", "TriageCase", case_id)

    return {
        "vulnerabilities": len(VULNERABILITIES),
        "packages": len(PACKAGES),
        "services": len(SERVICES),
        "exposures": len(EXPOSURES),
        "assets": len(DATA_ASSETS),
        "cases": len(TRIAGE_CASES),
    }


if __name__ == "__main__":
    result = seed_graph()
    logger.info(
        "Seeded graph with %s vulnerabilities, %s packages, %s services, %s exposures, %s assets, and %s cases.",
        result["vulnerabilities"],
        result["packages"],
        result["services"],
        result["exposures"],
        result["assets"],
        result["cases"],
    )
