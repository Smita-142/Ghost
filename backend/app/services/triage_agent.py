"""Evidence-grounded triage agent for vulnerability investigations."""

from __future__ import annotations

from typing import Any

from app.models.schemas import Priority, RiskFactor, TriageResult
from app.services.risk_engine import compute_contextual_risk


def _build_recommended_actions(services: list[dict[str, Any]], assets: list[dict[str, Any]], exposures: list[dict[str, Any]]) -> list[str]:
    actions = []
    if services:
        actions.append("Patch or upgrade the affected package in the vulnerable production services.")
    if exposures:
        actions.append("Reduce the internet-facing exposure or add compensating controls around the affected service.")
    if assets:
        actions.append("Validate the data-flow path to sensitive assets and apply segmentation or monitoring controls.")
    actions.append("Create or update a triage case and confirm the mitigation plan with the service owner.")
    return actions


def generate_triage_result(vulnerability: dict[str, Any], impact: dict[str, Any]) -> TriageResult:
    risk = compute_contextual_risk(vulnerability, impact)
    severity = (vulnerability.get("severity") or "medium").upper()
    details = risk["risk_factors"]
    risk_factors = [RiskFactor(factor=item["factor"], contribution=float(item["contribution"]), detail=item["detail"]) for item in details]

    packages = impact.get("packages", [])
    services = impact.get("services", [])
    exposures = impact.get("exposures", [])
    reachable_assets = impact.get("assets", [])
    evidence_paths = impact.get("evidence_paths", [])

    summary = (
        f"{vulnerability.get('title', 'Vulnerability')} presents a {risk['priority'].lower()} contextual risk because the graph shows "
        f"{len(services)} affected service(s) with {len(exposures)} exposure path(s) and {len(reachable_assets)} reachable sensitive asset(s)."
    )

    reasoning = (
        "The graph contains a path from the affected package through environment context. The final priority combines sourced CVSS with "
        "service criticality, internet exposure, and reachable assets. Simulated context makes this a scenario-based assessment, not proof of real-world exploitability."
        if services or reachable_assets
        else "No service impact is asserted without a package-to-service relationship. Contextual priority is limited to the available sourced vulnerability metadata."
    )

    remediation = "Patching the vulnerable package and restricting the exposed service path are the primary remediation steps."
    recommended_actions = _build_recommended_actions(services, reachable_assets, exposures)

    return TriageResult(
        vulnerability_id=str(vulnerability.get("id", "")),
        priority=Priority[risk["priority"]],
        risk_score=float(risk["risk_score"]),
        summary=summary,
        reasoning=reasoning,
        evidence_paths=evidence_paths,
        affected_packages=[{**pkg, "id": pkg.get("id", ""), "name": pkg.get("name", ""), "version": pkg.get("version", ""), "ecosystem": pkg.get("ecosystem", "unknown"), "direct_dependency": pkg.get("direct_dependency", True), "criticality": pkg.get("criticality", "medium")} for pkg in packages],
        affected_services=[{**svc, "id": svc.get("id", ""), "name": svc.get("name", ""), "environment": svc.get("environment", "prod"), "owner": svc.get("owner", "unknown"), "criticality": svc.get("criticality", "medium"), "internet_facing": bool(svc.get("internet_facing", False)), "business_unit": svc.get("business_unit", "unknown")} for svc in services],
        exposures=[{**exp, "id": exp.get("id", ""), "type": exp.get("type", "network"), "internet_accessible": bool(exp.get("internet_accessible", False)), "authentication_required": bool(exp.get("authentication_required", True)), "network_zone": exp.get("network_zone", "unknown"), "description": exp.get("description", "No description available.")} for exp in exposures],
        reachable_assets=[{**asset, "id": asset.get("id", ""), "name": asset.get("name", ""), "data_classification": asset.get("data_classification", "internal"), "business_criticality": asset.get("business_criticality", "medium"), "description": asset.get("description", "No description available.")} for asset in reachable_assets],
        recommended_actions=recommended_actions,
        remediation=remediation,
        confidence="medium" if risk["risk_score"] >= 55 else "low",
        limitations=["Environment services, exposures, and assets are simulated unless explicitly sourced from an authorized environment.", "Contextual priority is a scenario-based assessment and does not prove real-world exploitability.", "Analysis may not include unmodeled dependencies or external asset metadata."],
        risk_factors=risk_factors,
    )
