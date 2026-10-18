"""FalkorDB-backed graph queries for vulnerability analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.db.connection import get_graph


def _as_plain(value: Any) -> Any:
    if hasattr(value, "properties"):
        props = dict(value.properties)
        labels_value = getattr(value, "labels", [])
        labels = list(labels_value() if callable(labels_value) else labels_value)
        if isinstance(labels, list) and labels:
            props["labels"] = labels
        if hasattr(value, "id"):
            props.setdefault("node_id", value.id)
        return props
    if isinstance(value, list):
        return [_as_plain(item) for item in value]
    if isinstance(value, tuple):
        return [_as_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _as_plain(val) for key, val in value.items()}
    return value


def _records_to_rows(records: Any) -> list[dict[str, Any]]:
    if hasattr(records, "result_set"):
        header = getattr(records, "header", [])
        column_names = [
            str(column[1]) if isinstance(column, (list, tuple)) and len(column) > 1 else str(column)
            for column in header
        ]
        if not column_names and records.result_set:
            raise ValueError("FalkorDB returned rows without column names.")
        records = [dict(zip(column_names, record)) for record in records.result_set]

    rows: list[dict[str, Any]] = []
    for record in records:
        if hasattr(record, "data"):
            row = record.data()
        elif isinstance(record, dict):
            row = record
        else:
            row = dict(record)
        rows.append(_as_plain(row))
    return rows


def fetch_vulnerabilities(search: str | None = None, severity: str | None = None, status: str | None = None, page: int = 1, page_size: int = 20, source: str | None = None, package: str | None = None) -> dict[str, Any]:
    graph = get_graph()
    query = "MATCH (v:Vulnerability) OPTIONAL MATCH (v)-[:HAS_CASE]->(c:TriageCase) RETURN v AS vulnerability, collect(DISTINCT c) AS cases ORDER BY v.published_date DESC"
    rows = _records_to_rows(graph.query(query))

    vuln_rows: list[dict[str, Any]] = []
    for row in rows:
        vuln = row.get("vulnerability", {})
        cases = row.get("cases", [])
        if search:
            search_term = search.lower()
            haystack = " ".join(
                [
                    str(vuln.get("title", "")),
                    str(vuln.get("cve_id", "")),
                    str(vuln.get("description", "")),
                ]
            ).lower()
            if search_term not in haystack:
                continue
        if severity and str(vuln.get("severity", "")).lower() != severity.lower():
            continue
        if source and str(vuln.get("source", "synthetic_fixture")).lower() != source.lower():
            continue
        if package:
            package_text = " ".join(str(item) for item in vuln.get("package_mapping_evidence", [])).lower()
            product_text = " ".join(str(item) for item in vuln.get("affected_products", [])).lower()
            if package.lower() not in package_text and package.lower() not in product_text:
                continue
        if status and str(vuln.get("status", "")).lower() != status.lower():
            continue
        vuln_rows.append({**vuln, "cases": cases})

    total = len(vuln_rows)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = vuln_rows[start:end]
    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


def fetch_vulnerability_by_id(vulnerability_id: str) -> dict[str, Any] | None:
    graph = get_graph()
    query = "MATCH (v:Vulnerability {id: $id}) OPTIONAL MATCH (v)-[:HAS_CASE]->(c:TriageCase) RETURN v AS vulnerability, collect(DISTINCT c) AS cases LIMIT 1"
    rows = _records_to_rows(graph.query(query, {"id": vulnerability_id}))
    if not rows:
        return None
    row = rows[0]
    vuln = row.get("vulnerability", {})
    return {**vuln, "cases": row.get("cases", [])}


def fetch_vulnerability_impact(vulnerability_id: str) -> dict[str, Any]:
    graph = get_graph()
    direct_package_query = "MATCH (v:Vulnerability {id: $id})-[:AFFECTS_PACKAGE]->(p:Package) RETURN DISTINCT p AS package"
    package_query = """
        MATCH (v:Vulnerability {id: $id})-[:AFFECTS_PACKAGE]->(p:Package)-[:USED_BY]->(s:Service)
        RETURN DISTINCT p AS package, s AS service
    """
    exposure_query = """
        MATCH (v:Vulnerability {id: $id})-[:AFFECTS_PACKAGE]->(p:Package)-[:USED_BY]->(s:Service)-[:HAS_EXPOSURE]->(e:Exposure)
        RETURN DISTINCT p AS package, s AS service, e AS exposure
    """
    asset_query = """
        MATCH (v:Vulnerability {id: $id})-[:AFFECTS_PACKAGE]->(p:Package)-[:USED_BY]->(s:Service)-[:ACCESS_TO]->(a:DataAsset)
        RETURN DISTINCT p AS package, s AS service, a AS asset
    """
    path_query = """
        MATCH path = (v:Vulnerability {id: $id})-[:AFFECTS_PACKAGE]->(p:Package)-[:USED_BY]->(s:Service)
        OPTIONAL MATCH (s)-[:HAS_EXPOSURE]->(e:Exposure)
        OPTIONAL MATCH (s)-[:ACCESS_TO]->(a:DataAsset)
        RETURN path, p, s, e, a
    """

    package_rows = _records_to_rows(graph.query(package_query, {"id": vulnerability_id}))
    direct_package_rows = _records_to_rows(graph.query(direct_package_query, {"id": vulnerability_id}))
    exposure_rows = _records_to_rows(graph.query(exposure_query, {"id": vulnerability_id}))
    asset_rows = _records_to_rows(graph.query(asset_query, {"id": vulnerability_id}))
    path_rows = _records_to_rows(graph.query(path_query, {"id": vulnerability_id}))

    packages = []
    services = []
    exposures = []
    assets = []
    evidence_paths = []

    for row in direct_package_rows:
        pkg = row.get("package", {})
        if pkg and pkg not in packages:
            packages.append(pkg)

    for row in package_rows:
        pkg = row.get("package", {})
        service = row.get("service", {})
        if pkg and pkg not in packages:
            packages.append(pkg)
        if service and service not in services:
            services.append(service)

    for row in exposure_rows:
        exp = row.get("exposure", {})
        if exp and exp not in exposures:
            exposures.append(exp)
        service = row.get("service", {})
        if service and service not in services:
            services.append(service)

    for row in asset_rows:
        asset = row.get("asset", {})
        if asset and asset not in assets:
            assets.append(asset)
        service = row.get("service", {})
        if service and service not in services:
            services.append(service)

    seen_paths: set[tuple[str, ...]] = set()
    for row in path_rows:
        path = [vulnerability_id]
        relationship_types = []
        for key, relationship_type in (
            ("p", "AFFECTS_PACKAGE"),
            ("s", "USED_BY"),
            ("e", "HAS_EXPOSURE"),
            ("a", "ACCESS_TO"),
        ):
            node = row.get(key)
            if not isinstance(node, dict):
                continue
            name = node.get("name") or node.get("title") or node.get("type") or node.get("description") or node.get("id")
            if name is None:
                continue
            path.append(str(name))
            relationship_types.append(relationship_type)
        path_key = tuple(path)
        if len(path) > 1 and path_key not in seen_paths:
            seen_paths.add(path_key)
            evidence_paths.append({
                "path": path,
                "relationship_types": relationship_types,
                "risk_significance": "Graph traversal found a path through simulated environment context; this is scenario context, not proof that the public CVE exists in that service.",
            })

    case_row = _records_to_rows(graph.query("MATCH (v:Vulnerability {id: $id})-[:HAS_CASE]->(c:TriageCase) RETURN c LIMIT 1", {"id": vulnerability_id}))
    case_exists = bool(case_row)
    case_status = case_row[0].get("status") if case_row else None

    return {
        "packages": packages,
        "services": services,
        "exposures": exposures,
        "assets": assets,
        "evidence_paths": evidence_paths or ([{
            "path": [vulnerability_id],
            "relationship_types": [],
            "risk_significance": "No verified package or simulated environment path is recorded for this vulnerability.",
        }] if not packages else [{"path": [vulnerability_id, str(packages[0].get("name", packages[0].get("id", "package")))], "relationship_types": ["AFFECTS_PACKAGE"], "risk_significance": "A vulnerability-to-package relationship is recorded from source evidence; no service impact is asserted."}]),
        "case_exists": case_exists,
        "case_status": case_status,
    }


def fetch_related_vulnerabilities(vulnerability_id: str) -> list[dict[str, Any]]:
    graph = get_graph()
    query = """
        MATCH (v:Vulnerability {id: $id})-[:AFFECTS_PACKAGE]->(p:Package)<-[:AFFECTS_PACKAGE]-(related:Vulnerability)
        WHERE related.id <> $id
        RETURN DISTINCT related AS vulnerability, collect(DISTINCT p) AS shared_packages
    """
    rows = _records_to_rows(graph.query(query, {"id": vulnerability_id}))
    return [
        {
            **row.get("vulnerability", {}),
            "shared_packages": row.get("shared_packages", []),
        }
        for row in rows
    ]


def fetch_service_analysis(service_id: str) -> dict[str, Any]:
    graph = get_graph()
    query = """
        MATCH (s:Service {id: $id})
        OPTIONAL MATCH (s)-[:USED_BY]->(p:Package)
        OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS_PACKAGE]->(p)
        OPTIONAL MATCH (s)-[:HAS_EXPOSURE]->(e:Exposure)
        OPTIONAL MATCH (s)-[:ACCESS_TO]->(a:DataAsset)
        RETURN DISTINCT s AS service, collect(DISTINCT p) AS packages, collect(DISTINCT v) AS vulnerabilities, collect(DISTINCT e) AS exposures, collect(DISTINCT a) AS assets
    """
    rows = _records_to_rows(graph.query(query, {"id": service_id}))
    if not rows:
        return {"service": None, "packages": [], "vulnerabilities": [], "exposures": [], "assets": []}
    row = rows[0]
    return {
        "service": row.get("service"),
        "packages": row.get("packages", []),
        "vulnerabilities": row.get("vulnerabilities", []),
        "exposures": row.get("exposures", []),
        "assets": row.get("assets", []),
    }


def dashboard_summary() -> dict[str, Any]:
    graph = get_graph()
    queries = {
        "total_vulnerabilities": "MATCH (v:Vulnerability) RETURN count(v) AS value",
        "critical_count": "MATCH (v:Vulnerability) WHERE toLower(v.severity) = 'critical' RETURN count(v) AS value",
        "high_count": "MATCH (v:Vulnerability) WHERE toLower(v.severity) = 'high' RETURN count(v) AS value",
        "medium_count": "MATCH (v:Vulnerability) WHERE toLower(v.severity) = 'medium' RETURN count(v) AS value",
        "low_count": "MATCH (v:Vulnerability) WHERE toLower(v.severity) = 'low' RETURN count(v) AS value",
        "internet_facing_services": "MATCH (s:Service) WHERE s.internet_facing = true RETURN count(DISTINCT s) AS value",
        "sensitive_data_exposed": "MATCH (s:Service)-[:ACCESS_TO]->(a:DataAsset) WHERE toLower(a.business_criticality) IN ['critical', 'high'] RETURN count(DISTINCT a) AS value",
        "open_cases": "MATCH (c:TriageCase) WHERE toLower(c.status) = 'open' RETURN count(c) AS value",
        "resolved_cases": "MATCH (c:TriageCase) WHERE toLower(c.status) = 'resolved' RETURN count(c) AS value",
        "critical_risk_vulns": "MATCH (v:Vulnerability) WHERE toFloat(v.cvss_score) >= 9.0 RETURN count(v) AS value",
    }
    summary: dict[str, Any] = {}
    for key, query in queries.items():
        rows = _records_to_rows(graph.query(query))
        value = rows[0].get("value", 0) if rows else 0
        summary[key] = int(value) if isinstance(value, (int, float)) else 0
    return {
        "total_vulnerabilities": summary["total_vulnerabilities"],
        "critical_count": summary["critical_count"],
        "high_count": summary["high_count"],
        "medium_count": summary["medium_count"],
        "low_count": summary["low_count"],
        "internet_facing_services": summary["internet_facing_services"],
        "sensitive_data_exposed": summary["sensitive_data_exposed"],
        "open_cases": summary["open_cases"],
        "resolved_cases": summary["resolved_cases"],
        "critical_risk_vulns": summary["critical_risk_vulns"],
    }


def dashboard_severity_distribution() -> list[dict[str, Any]]:
    graph = get_graph()
    query = "MATCH (v:Vulnerability) RETURN toLower(v.severity) AS severity, count(v) AS count ORDER BY severity"
    rows = _records_to_rows(graph.query(query))
    distribution = []
    for row in rows:
        distribution.append({"severity": row.get("severity", "unknown"), "count": row.get("count", 0)})
    return distribution


def create_triage_case(payload: dict[str, Any]) -> dict[str, Any]:
    graph = get_graph()
    case_id = payload.get("id") or f"case-{uuid4().hex}"
    now = datetime.now(timezone.utc).isoformat()
    query = """
        MERGE (c:TriageCase {id: $id})
        SET c.title = $title,
            c.priority = $priority,
            c.status = $status,
            c.assigned_to = $assigned_to,
            c.analyst_notes = $analyst_notes,
            c.recommended_action = $recommended_action,
            c.created_at = $now,
            c.updated_at = $now
        WITH c
        MATCH (v:Vulnerability {id: $vulnerability_id})
        MERGE (v)-[:HAS_CASE]->(c)
        RETURN c AS case_data
    """
    rows = _records_to_rows(graph.query(query, {
        "id": case_id,
        "title": payload.get("title"),
        "priority": payload.get("priority"),
        "status": payload.get("status", "open"),
        "assigned_to": payload.get("assigned_to"),
        "analyst_notes": payload.get("analyst_notes"),
        "recommended_action": payload.get("recommended_action"),
        "vulnerability_id": payload.get("vulnerability_id"),
        "now": now,
    }))
    case_data = rows[0].get("case_data", {}) if rows else {}
    return case_data


def list_triage_cases() -> list[dict[str, Any]]:
    graph = get_graph()
    query = "MATCH (c:TriageCase) RETURN c AS case_data ORDER BY c.updated_at DESC"
    rows = _records_to_rows(graph.query(query))
    return [row.get("case_data", {}) for row in rows]


def update_triage_case(case_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    graph = get_graph()
    fields = []
    params: dict[str, Any] = {"id": case_id}
    for field, value in updates.items():
        if value is None:
            continue
        if field in {"status", "assigned_to", "analyst_notes", "recommended_action", "priority", "title"}:
            fields.append(f"c.{field} = ${field}")
            params[field] = value
    if not fields:
        return None
    params["updated_at"] = datetime.now(timezone.utc).isoformat()
    fields.append("c.updated_at = $updated_at")
    query = f"MATCH (c:TriageCase {{id: $id}}) SET {', '.join(fields)} RETURN c AS case_data"
    rows = _records_to_rows(graph.query(query, params))
    if not rows:
        return None
    return rows[0].get("case_data", {})


def export_vulnerability_report_csv() -> str:
    rows = fetch_vulnerabilities()["items"]
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "cve_id", "title", "severity", "cvss_score", "status", "exploit_available"])
    for row in rows:
        writer.writerow([
            row.get("id", ""),
            row.get("cve_id", ""),
            row.get("title", ""),
            row.get("severity", ""),
            row.get("cvss_score", ""),
            row.get("status", ""),
            row.get("exploit_available", ""),
        ])
    return buffer.getvalue()
