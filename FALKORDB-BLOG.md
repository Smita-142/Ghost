# From CVE Lists to Attack Paths: Building VulnGraph AI with FalkorDB

Vulnerability dashboards are good at showing how many issues exist. They are less helpful when the urgent question is: **which issue can reach something important in this environment?**

That question motivated VulnGraph AI, a graph-backed vulnerability triage demo built with FastAPI, React, and FalkorDB. Instead of treating each vulnerability as a disconnected row, the application follows relationships between vulnerabilities, packages, services, exposures, and data assets. It then presents the graph evidence behind its contextual prioritization.

## Why use a graph?

A package's risk depends on where it is used and what those services can reach. In VulnGraph AI, the graph models:

- `Vulnerability` nodes and `AFFECTS_PACKAGE` relationships to `Package` nodes
- `USED_BY` relationships from packages to `Service` nodes
- `HAS_EXPOSURE` relationships from services to `Exposure` nodes
- `ACCESS_TO` relationships from services to `DataAsset` nodes
- `HAS_CASE` relationships from vulnerabilities to persistent `TriageCase` nodes

This turns a vulnerability review into a connected-path query. For example, selecting the demo sharp vulnerability follows the stored path from the affected package to the media-processing service, its upload exposure, and a reachable profile-images asset. The interface displays results returned by the API rather than inventing a path by joining unrelated records in the browser.

## Problems we solved

One challenge was getting traversal direction right. Graph relationships have direction, and an incorrect arrow in a Cypher pattern can silently omit valid service connections. We checked the stored edge orientation and corrected the package-to-service traversal so impact results reflect actual graph relationships. We also verified the empty-path case so vulnerabilities without a reachable asset do not get a fabricated impact path.

Another challenge was making the application compatible with actual FalkorDB query results. The backend needed to normalize the driver's result structure consistently before converting records into API responses. We traced the inventory, impact, and case APIs through to their Cypher queries and verified them against the running database.

Triage persistence mattered too. Cases are graph nodes, connected to vulnerabilities with `HAS_CASE`, rather than browser-only state. We exercised case creation and updates through the API and checked that the records remained after a backend restart. We then configured a named Docker volume at FalkorDB's data directory, enabled AOF and RDB persistence, and tested a fresh FalkorDB container against that volume. The graph retained 48 nodes, 46 relationships, and all three existing cases.

## Explainable prioritization, not a magic number

The application combines base CVSS information with contextual signals such as exploit availability, service exposure, service criticality, reachable assets, and triage state. The result is a normalized priority score used to help focus review. It is not a probability of exploitation, and a public CVE record is not proof that a package is installed or that an asset is exposed.

That distinction is important in this demo: its vulnerability records and infrastructure are clearly labelled as synthetic fixtures unless public data has been explicitly imported. Simulated services, exposures, and assets are not presented as a real organization's inventory.

## What we learned

The most useful graph work was not drawing nodes; it was validating what each edge means, checking query direction, and making the UI show the database's evidence faithfully. We also learned that persistence needs to be tested at the database-container boundary: a backend restart alone does not prove that graph data survives replacement of the database container.

FalkorDB gave us a natural way to express multi-hop relationships in Cypher and keep triage cases alongside the evidence they refer to. For a small team, that makes the path from an alert to an operationally relevant explanation easier to inspect and demo.

VulnGraph AI is a prototype, not a replacement for verified asset inventory, vulnerability validation, or security review. Its goal is to demonstrate how graph relationships can make vulnerability prioritization more contextual, traceable, and explainable.
