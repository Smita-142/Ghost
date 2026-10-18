"""Contextual risk calculations for vulnerability evidence."""

from __future__ import annotations

from typing import Any

SEVERITY_PRIORITY = {
    "CRITICAL": 80,
    "HIGH": 60,
    "MEDIUM": 35,
    "LOW": 0,
}


def _service_criticality_value(service: dict[str, Any] | None) -> int:
    if not service:
        return 0
    criticality = (service.get("criticality") or "medium").lower()
    mapping = {"critical": 10, "high": 8, "medium": 5, "low": 2}
    return mapping.get(criticality, 5)


def _critical_asset_count(assets: list[dict[str, Any]]) -> int:
    count = 0
    for asset in assets:
        if (asset.get("business_criticality") or "medium").lower() in {"critical", "high"}:
            count += 1
    return count


def compute_contextual_risk(vulnerability: dict[str, Any], impact: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compute a 0-100 contextual score and priority using graph evidence."""
    impact = impact or {}
    services = impact.get("services", []) or []
    exposures = impact.get("exposures", []) or []
    reachable_assets = impact.get("assets", []) or []
    evidence_paths = impact.get("evidence_paths", []) or []
    has_case = bool(impact.get("case_exists"))
    mitigation_active = impact.get("case_status") in {"mitigated", "resolved"}

    cvss_score = float(vulnerability.get("cvss_score", 0.0) or 0.0)
    exploit_value = vulnerability.get("exploit_available")
    exploit_available = exploit_value is True
    internet_facing = any((service.get("internet_facing") is True) for service in services)
    critical_asset_count = _critical_asset_count(reachable_assets)
    service_criticality = max((_service_criticality_value(service) for service in services), default=0)
    affected_service_count = len({service.get("id") for service in services if service.get("id")})

    base_contribution = min(40.0, (cvss_score / 10.0) * 40.0)
    exploit_contribution = 15.0 if exploit_available else 0.0
    internet_contribution = 15.0 if internet_facing else 0.0
    critical_asset_contribution = min(15.0, critical_asset_count * 7.5)
    service_contribution = min(10.0, float(service_criticality) / 10.0 * 10.0)
    breadth_contribution = min(5.0, max(0.0, affected_service_count - 1) * 2.5)
    exposure_contribution = 0.0
    if exposures:
        exposure_contribution = min(5.0, len(exposures) * 2.5)

    if has_case and not mitigation_active:
        case_contribution = 4.0
    elif mitigation_active:
        case_contribution = -8.0
    else:
        case_contribution = 0.0

    score = (
        base_contribution
        + exploit_contribution
        + internet_contribution
        + critical_asset_contribution
        + service_contribution
        + breadth_contribution
        + exposure_contribution
        + case_contribution
    )
    score = max(0.0, min(100.0, round(score, 1)))

    if score >= 80:
        priority = "CRITICAL"
    elif score >= 60:
        priority = "HIGH"
    elif score >= 35:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    factors = [
        {
            "factor": "Base CVSS",
            "contribution": round(base_contribution, 1),
            "detail": f"CVSS {cvss_score:.1f} contributes {base_contribution:.1f} to the contextual score.",
        },
        {
            "factor": "Exploit availability",
            "contribution": round(exploit_contribution, 1),
            "detail": "Known exploit availability increases urgency when a public exploit exists." if exploit_available else "Exploit availability is not recorded in this vulnerability source." if exploit_value is None else "The fixture records no known exploit signal.",
        },
        {
            "factor": "Internet exposure",
            "contribution": round(internet_contribution, 1),
            "detail": "The affected service is internet-facing, increasing exposure risk." if internet_facing else "No direct internet-facing service path was identified in the graph.",
        },
        {
            "factor": "Critical asset reachability",
            "contribution": round(critical_asset_contribution, 1),
            "detail": f"{critical_asset_count} high-value data asset(s) are reachable along the graph path." if critical_asset_count else "No high-value asset reachability was found in the current evidence set.",
        },
        {
            "factor": "Service criticality",
            "contribution": round(service_contribution, 1),
            "detail": f"The affected service criticality contributes {service_contribution:.1f} to the score." if services else "No service criticality was identified for the affected path.",
        },
        {
            "factor": "Affected-service breadth",
            "contribution": round(breadth_contribution, 1),
            "detail": f"{affected_service_count} service(s) are affected by this vulnerability." if affected_service_count else "No multi-service impact was identified.",
        },
        {
            "factor": "Exposure breadth",
            "contribution": round(exposure_contribution, 1),
            "detail": f"{len(exposures)} exposure path(s) were discovered." if exposures else "No direct exposure path was discovered.",
        },
        {
            "factor": "Triage status",
            "contribution": round(case_contribution, 1),
            "detail": "An active triage case is already reducing immediate urgency." if mitigation_active else "No mitigation or case status was found to lower the risk signal." if not has_case else "An active triage case exists, increasing urgency until it is resolved.",
        },
    ]

    summary = (
        f"{vulnerability.get('title', 'Vulnerability')} has a contextual risk score of {score:.1f} and priority {priority}."
    )

    if internet_facing or critical_asset_count:
        summary += " The graph shows a route from a vulnerable package to an internet-facing or sensitive asset path."
    elif not services:
        summary += " No direct production service path was found, which reduces the immediate exploit impact."

    reasoning = (
        "CVSS comes from the vulnerability record. Service exposure and asset criticality come from the configured graph context; "
        "when that context is simulated, this priority is a scenario-based assessment and does not prove real-world exploitability."
    )

    return {
        "priority": priority,
        "risk_score": score,
        "summary": summary,
        "reasoning": reasoning,
        "risk_factors": factors,
        "evidence_paths": evidence_paths,
        "affected_services": services,
        "exposures": exposures,
        "reachable_assets": reachable_assets,
    }


def classify_priority(score: float) -> str:
    if score >= SEVERITY_PRIORITY["CRITICAL"]:
        return "CRITICAL"
    if score >= SEVERITY_PRIORITY["HIGH"]:
        return "HIGH"
    if score >= SEVERITY_PRIORITY["MEDIUM"]:
        return "MEDIUM"
    return "LOW"
