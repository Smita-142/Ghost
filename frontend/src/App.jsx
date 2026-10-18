import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

async function fetchJson(url, options) {
  const response = await fetch(url, options)
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: 'Request failed.' }))
    const message = typeof payload.detail === 'string'
      ? payload.detail
      : payload.detail?.message || 'Request failed.'
    throw new Error(message)
  }
  return response.json()
}

function App() {
  const [summary, setSummary] = useState(null)
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [impact, setImpact] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [loadingInventory, setLoadingInventory] = useState(true)
  const [loadingImpact, setLoadingImpact] = useState(false)
  const [error, setError] = useState('')
  const [isLive, setIsLive] = useState(false)
  const [sourceFilter, setSourceFilter] = useState('demo')
  const [severityFilter, setSeverityFilter] = useState('')
  const [searchFilter, setSearchFilter] = useState('')
  const [packageFilter, setPackageFilter] = useState('')
  const [syncing, setSyncing] = useState(false)

  useEffect(() => {
    let cancelled = false

    async function loadInventory() {
      try {
        const [summaryData, vulnerabilityData] = await Promise.all([
          fetchJson(`${API_BASE}/api/dashboard/summary`),
          fetchJson(`${API_BASE}/api/vulnerabilities?page=1&page_size=100&source=${encodeURIComponent(sourceFilter)}`),
        ])
        if (cancelled) return
        const items = vulnerabilityData.items || []
        setSummary(summaryData)
        setVulnerabilities(items)
        setSelectedId((current) => items.some((item) => item.id === current) ? current : items[0]?.id || '')
        setLoadingImpact(items.length > 0)
        setIsLive(true)
        setError('')
      } catch (loadError) {
        if (!cancelled) {
          setError(`Could not load live graph data: ${loadError.message}`)
          setIsLive(false)
        }
      } finally {
        if (!cancelled) setLoadingInventory(false)
      }
    }

    loadInventory()
    return () => { cancelled = true }
  }, [sourceFilter])

  async function applyFilters() {
    setLoadingInventory(true)
    try {
      const params = new URLSearchParams({ page: '1', page_size: '100', source: sourceFilter })
      if (severityFilter) params.set('severity', severityFilter)
      if (searchFilter) params.set('search', searchFilter)
      if (packageFilter) params.set('package', packageFilter)
      const data = await fetchJson(`${API_BASE}/api/vulnerabilities?${params}`)
      const items = data.items || []
      setVulnerabilities(items)
      setSelectedId(items[0]?.id || '')
      setImpact(null)
      setAnalysis(null)
    } catch (loadError) {
      setError(`Could not load filtered vulnerability data: ${loadError.message}`)
    } finally {
      setLoadingInventory(false)
    }
  }

  async function refreshVulnerabilityData() {
    setSyncing(true)
    try {
      const result = await fetchJson(`${API_BASE}/api/vulnerabilities/refresh?days=30`, { method: 'POST' })
      setError(`Synchronized ${result.imported} NVD record(s); ${result.osv_package_mappings} verified OSV package mapping(s).`)
      setSourceFilter('NVD')
    } catch (syncError) {
      setError(`Vulnerability refresh failed: ${syncError.message}`)
    } finally {
      setSyncing(false)
    }
  }

  useEffect(() => {
    if (!selectedId) return undefined

    let cancelled = false
    async function loadImpact() {
      try {
        const [impactData, analysisData] = await Promise.all([
          fetchJson(`${API_BASE}/api/vulnerabilities/${encodeURIComponent(selectedId)}/impact`),
          fetchJson(`${API_BASE}/api/triage/${encodeURIComponent(selectedId)}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vulnerability_id: selectedId }),
          }),
        ])
        if (cancelled) return
        setImpact(impactData)
        setAnalysis(analysisData)
        setError('')
      } catch (loadError) {
        if (!cancelled) {
          setImpact(null)
          setAnalysis(null)
          setError(`Could not load graph analysis: ${loadError.message}`)
        }
      } finally {
        if (!cancelled) setLoadingImpact(false)
      }
    }

    loadImpact()
    return () => { cancelled = true }
  }, [selectedId])

  useEffect(() => {
    const elements = document.querySelectorAll('.reveal')
    if (!('IntersectionObserver' in window)) {
      elements.forEach((element) => element.classList.add('in'))
      return undefined
    }
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in')
          observer.unobserve(entry.target)
        }
      })
    }, { threshold: 0.12 })
    elements.forEach((element) => observer.observe(element))
    return () => observer.disconnect()
  }, [vulnerabilities.length])

  const selectedVulnerability = useMemo(
    () => vulnerabilities.find((item) => item.id === selectedId),
    [selectedId, vulnerabilities],
  )

  const chain = useMemo(() => {
    if (!selectedVulnerability || !impact) return []
    const evidencePath = impact.evidence_paths?.[0]
    const nodeTypes = ['Vulnerability', 'Package', 'Service', 'Exposure', 'Data asset']
    return (evidencePath?.path || [selectedVulnerability.id]).map((name, index) => ({
      type: nodeTypes[index] || 'Connected node',
      name: index === 0 ? selectedVulnerability.cve_id || name : name,
      edge: evidencePath?.relationship_types?.[index - 1] || null,
    }))
  }, [impact, selectedVulnerability])

  const query = selectedVulnerability
    ? `MATCH (v:Vulnerability {id: $id})-[:AFFECTS_PACKAGE]->(p:Package)\nOPTIONAL MATCH (p)-[:USED_BY]->(s:Service)\nOPTIONAL MATCH (s)-[:HAS_EXPOSURE]->(e:Exposure)\nOPTIONAL MATCH (s)-[:ACCESS_TO]->(a:DataAsset)\nRETURN v, p, s, e, a`
    : 'Select a vulnerability to inspect its graph path.'

  return (
    <div className="site-shell">
      <nav className="site-nav">
        <a className="wordmark" href="#top" aria-label="ghost home">ghost<span className="wordmark-dot">.</span></a>
        <div className="nav-links mono">
          <a className="nav-secondary" href="#how">How it works</a>
          <a className="nav-secondary" href="#demo">Live path</a>
          <a href="#demo">Open triage</a>
        </div>
      </nav>

      <main id="top">
        <section className="hero-section">
          <p className="mono hero-kicker">Agent / Security triage / FalkorDB</p>
          <h1 className="hero-title">
            <span><i>Fix what</i></span>
            <span><i>actually</i></span>
            <span><i>matters.</i></span>
          </h1>
          <div className="hero-bottom">
            <p>Thousands of CVE alerts, a handful of real risks. ghost follows each vulnerability through your <b>packages, services and data</b> on a graph, ranks by blast radius, and shows the path behind every call.</p>
            <div className="hero-actions">
              <a className="button button-dark mono" href="#demo">See a live path</a>
              <a className="button button-outline mono" href="#how">How it works</a>
            </div>
          </div>
          <div className={`live-indicator mono ${isLive ? 'connected' : ''}`} role="status">
            <span className="status-dot" />
            {loadingInventory ? 'Connecting to FalkorDB' : isLive ? 'Live graph connected' : 'Graph connection unavailable'}
          </div>
        </section>

        <div className="ticker mono" aria-label="Vulnerability graph process">
          <div>
            {Array.from({ length: 2 }, (_, index) => (
              <span className="ticker-set" key={index}>
                <span>CVE → Package → Service → Exposure → Data</span><span aria-hidden="true">●</span>
                <span>Multi-hop reasoning</span><span aria-hidden="true">●</span>
                <span>Explainable by design</span><span aria-hidden="true">●</span>
              </span>
            ))}
          </div>
        </div>

        <section className="content-section" id="how">
          <p className="mono section-label reveal">01 / Method</p>
          <h2 className="section-heading reveal">Four hops from alert to action</h2>
          {summary && (
            <div className="metrics-strip reveal" aria-label="Live vulnerability metrics">
              <div><span className="mono">Vulnerabilities</span><b>{summary.total_vulnerabilities}</b></div>
              <div><span className="mono">Critical</span><b>{summary.critical_count}</b></div>
              <div><span className="mono">Internet-facing</span><b>{summary.internet_facing_services}</b></div>
              <div><span className="mono">Open cases</span><b>{summary.open_cases}</b></div>
            </div>
          )}
          <div className="method-grid reveal">
            <article className="method-cell">
              <span className="method-number">01</span>
              <div><h3>Ingest</h3><p>Vulnerabilities and software inventory become connected nodes: packages, services, exposures and data assets.</p></div>
            </article>
            <article className="method-cell">
              <span className="method-number">02</span>
              <div><h3>Traverse</h3><p>FalkorDB follows graph relationships from a vulnerability to affected software and the services that depend on it.</p></div>
            </article>
            <article className="method-cell">
              <span className="method-number">03</span>
              <div><h3>Rank</h3><p>Contextual risk uses CVSS alongside exploitability, exposure, service criticality and reachable assets.</p></div>
            </article>
            <article className="method-cell">
              <span className="method-number">04</span>
              <div><h3>Act</h3><p>Review evidence-backed paths and recommended remediation before updating the triage queue.</p></div>
            </article>
          </div>
        </section>

        <section className="content-section live-section" id="demo">
          <p className="mono section-label reveal">02 / Live path</p>
          <h2 className="section-heading reveal">Every answer shows its work</h2>
          {error && <div className="error-banner" role="alert">{error}</div>}
          <div className="live-workspace reveal">
            <div className="vulnerability-list" aria-label="Vulnerability inventory">
              <div className="inventory-filters">
                <label>Source<select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}><option value="demo">Demo fixtures</option><option value="NVD">NVD public CVEs</option><option value="all">All sources</option></select></label>
                <label>Severity<select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'unknown'].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                <label>Search CVE / text<input value={searchFilter} onChange={(event) => setSearchFilter(event.target.value)} placeholder="CVE ID or description" /></label>
                <label>Affected package<input value={packageFilter} onChange={(event) => setPackageFilter(event.target.value)} placeholder="Package name" /></label>
                <button type="button" onClick={applyFilters}>Apply filters</button>
                <button type="button" onClick={refreshVulnerabilityData} disabled={syncing}>{syncing ? 'Syncing NVD…' : 'Refresh NVD / OSV'}</button>
              </div>
              {loadingInventory && <p className="list-message">Loading graph inventory…</p>}
              {!loadingInventory && vulnerabilities.length === 0 && (
                <p className="list-message">{error ? 'Live vulnerabilities are unavailable.' : 'No vulnerabilities found in the graph.'}</p>
              )}
              {vulnerabilities.map((vulnerability) => (
                <button
                  className={`vulnerability-option ${selectedId === vulnerability.id ? 'active' : ''}`}
                  type="button"
                  key={vulnerability.id}
                  onClick={() => {
                    if (selectedId !== vulnerability.id) setLoadingImpact(true)
                    setSelectedId(vulnerability.id)
                  }}
                  aria-pressed={selectedId === vulnerability.id}
                >
                  <b>{vulnerability.cve_id || vulnerability.id}</b>
                  <small className="mono">{vulnerability.title}</small>
                  <span className={`severity-label severity-${String(vulnerability.severity || 'low').toLowerCase()}`}>
                    {vulnerability.severity || 'Unknown'} · {vulnerability.cvss_score == null ? 'CVSS unavailable' : `CVSS ${Number(vulnerability.cvss_score).toFixed(1)}`}
                  </span>
                </button>
              ))}
            </div>

            <div className="analysis-panel" aria-live="polite">
              <div className="analysis-heading">
                <span className="mono">Graph evidence</span>
                {selectedVulnerability && <span className="mono selected-cve">{selectedVulnerability.cve_id || selectedVulnerability.id}</span>}
              </div>
              {loadingImpact ? (
                <p className="analysis-message">Traversing FalkorDB graph…</p>
              ) : !selectedVulnerability || !impact || !analysis ? (
                <p className="analysis-message">Select a vulnerability to load its live impact path and contextual risk analysis.</p>
              ) : (
                <>
                  <div className="graph-chain">
                    {chain.map((node, index) => (
                      <div className="chain-step" key={`${node.type}-${node.name}-${index}`}>
                        {node.edge && <div className="chain-edge mono">↓ {node.edge}</div>}
                        <div className="chain-node">
                          <span className="node-type mono">{node.type}</span>
                          <b>{node.name}</b>
                        </div>
                      </div>
                    ))}
                    {chain.length === 1 && (
                      <p className="no-path-note">No downstream package or service path is currently recorded for this vulnerability.</p>
                    )}
                  </div>
                  <div className="risk-verdict">
                    <div>
                      <span className="mono">Contextual risk score</span>
                      <p><b>{Number(analysis.risk_score).toFixed(0)}</b><span className="mono"> / 100 · {analysis.priority}</span></p>
                    </div>
                    <span className="mono verdict-status">
                      {impact.case_exists ? `Triage case · ${impact.case_status || 'open'}` : 'Analysis ready · no case opened'}
                    </span>
                  </div>
                  <div className="provenance-panel">
                    <b>{selectedVulnerability.source || 'synthetic_fixture'} · {selectedVulnerability.record_type || 'record type unavailable'}</b>
                    <span>Last synchronized: {selectedVulnerability.last_synchronized_at || 'demo fixture'}</span>
                    <span>Package mapping: {selectedVulnerability.affected_package_mapping || 'unavailable'}</span>
                    {selectedVulnerability.source === 'NVD' && <span>Public CVE metadata does not prove that a simulated service is vulnerable. Priority uses scenario-based environment context.</span>}
                    {!!selectedVulnerability.references?.length && <div>Evidence: {selectedVulnerability.references.slice(0, 5).map((reference) => <a key={reference.url} href={reference.url} target="_blank" rel="noreferrer">{reference.url}</a>)}</div>}
                    {!!selectedVulnerability.affected_products?.length && <span>NVD affected products: {selectedVulnerability.affected_products.slice(0, 4).map((product) => product.cpe).join(', ')}</span>}
                  </div>
                  <p className="analysis-summary">{analysis.summary}</p>
                  <pre className="query-block"><code>{query}</code></pre>
                  {!!analysis.recommended_actions?.length && (
                    <div className="action-list">
                      <h3 className="mono">Recommended next steps</h3>
                      <ul>{analysis.recommended_actions.map((action) => <li key={action}>{action}</li>)}</ul>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
          {summary && (
            <p className="inventory-caption mono">
              Showing {vulnerabilities.length} of {summary.total_vulnerabilities} graph vulnerabilities
            </p>
          )}
        </section>

        <section className="cta-section" id="start">
          <p className="mono section-label reveal">03 / Start</p>
          <h2 className="section-heading reveal">Stop triaging blind.</h2>
          <p className="cta-copy reveal">Explore the live vulnerability inventory and inspect the evidence path behind each priority.</p>
          <a className="button button-dark mono reveal" href="#demo">Explore live triage</a>
        </section>
      </main>

      <footer className="site-footer mono">
        <span>© 2026 ghost</span>
        <span>Graph-backed vulnerability triage · FalkorDB</span>
      </footer>
    </div>
  )
}

export default App
