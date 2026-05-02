import { useState, useEffect, useRef } from 'react'
import './App.css'

const BUILD_VERSION = 'v5.0 OWASP'
const SCAN_TIMEOUT_MS = 120000

const SEVERITY_LABEL = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
}

const STATIC_REMEDIATIONS = {
  'SQL Injection':
    'Use parameterised queries / prepared statements for every user-supplied value. Validate inputs (allow-list, length, type). Apply least-privilege DB accounts. Layer a WAF.',
  'Reflected XSS':
    'Apply context-aware output encoding. Use auto-escaping templating. Avoid dangerouslySetInnerHTML. Add a strict CSP without unsafe-inline.',
  'Missing Security Headers':
    'Set Strict-Transport-Security, X-Frame-Options (or CSP frame-ancestors), X-Content-Type-Options: nosniff, Referrer-Policy, and a baseline Content-Security-Policy.',
  'Insecure Cookie':
    'Set Secure, HttpOnly, and SameSite (Lax or Strict) on every session cookie. Scope Domain/Path narrowly.',
  'Sensitive File Exposure':
    'Remove backups and dotfiles from the deployed artefact. Block dotfile access at the web server / CDN. Rotate any leaked credentials immediately.',
  'CORS Misconfiguration':
    'Never combine ACAO=* with credentials=true. Reflect a known origin only after allow-listing. Restrict methods and headers to the minimum required.',
  'Clickjacking':
    'Set X-Frame-Options: DENY (or SAMEORIGIN) and a CSP frame-ancestors directive on all sensitive pages.',
  'Information Disclosure':
    'Strip Server, X-Powered-By, and version banners. Disable detailed stack traces in production. Audit HTML and JS for leaked emails and internal hostnames.',
  'Weak SSL/TLS':
    'Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3). Use a modern cipher suite. Renew certificates well before expiry; automate via ACME.',
  'Weak CSP':
    'Start from default-src \'self\'. Add only required origins. Avoid \'unsafe-inline\' and \'unsafe-eval\'. Use nonces for legitimate inline scripts.',
}

function logTypeFromLevel(level) {
  switch (level) {
    case 'CRITICAL':
    case 'ERROR':
      return 'danger'
    case 'WARNING':
      return 'warning'
    case 'SUCCESS':
      return 'success'
    case 'SCANNING':
      return 'info'
    default:
      return 'info'
  }
}

function App() {
  const [targetUrl, setTargetUrl] = useState('')
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [scanState, setScanState] = useState('idle') // 'idle' | 'scanning' | 'completed'
  const [logs, setLogs] = useState([])
  const [scanResult, setScanResult] = useState(null)
  const [scanError, setScanError] = useState(null)
  const [history, setHistory] = useState([])
  const [showRemediation, setShowRemediation] = useState(null)
  const [progress, setProgress] = useState({ current: 0, total: 0, label: '' })

  const terminalRef = useRef(null)
  const eventSourceRef = useRef(null)
  const timeoutRef = useRef(null)
  const findingsRef = useRef([])
  const summaryRef = useRef(null)

  const refreshHistory = () => {
    fetch('/api/history?limit=20')
      .then((r) => (r.ok ? r.json() : { entries: [] }))
      .then((d) => setHistory(Array.isArray(d.entries) ? d.entries : []))
      .catch(() => { /* offline / cold start — keep current list */ })
  }

  useEffect(() => {
    refreshHistory()
  }, [])

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [logs])

  useEffect(() => () => closeStream(), [])

  function closeStream() {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
      timeoutRef.current = null
    }
  }

  function appendLog(level, text) {
    setLogs((prev) => [
      ...prev,
      {
        time: new Date().toLocaleTimeString(),
        text,
        type: logTypeFromLevel(level),
      },
    ])
  }

  function finishScan(errorMessage = null) {
    closeStream()
    const summary = summaryRef.current
    if (errorMessage) {
      setScanError(errorMessage)
      setScanState('completed')
      return
    }
    if (summary) {
      const merged = { ...summary, findings: findingsRef.current }
      setScanResult(merged)
      // Backend persists each completed scan; pull the canonical list back so
      // sidebar + scan id stay in sync across reloads and between deploys.
      refreshHistory()
    } else {
      setScanError('Scan ended without a final summary.')
    }
    setScanState('completed')
  }

  const runAudit = () => {
    if (!targetUrl) {
      alert('Please enter a target URL before scanning.')
      return
    }
    if (!isAuthorized) {
      alert('You must check the consent box to proceed.')
      return
    }

    closeStream()
    findingsRef.current = []
    summaryRef.current = null

    setScanState('scanning')
    setLogs([])
    setScanError(null)
    setScanResult(null)
    setProgress({ current: 0, total: 0, label: '' })

    const params = new URLSearchParams({ url: targetUrl, consent: 'true' })
    const es = new EventSource(`/api/scan/stream?${params.toString()}`)
    eventSourceRef.current = es

    timeoutRef.current = setTimeout(() => {
      finishScan(`Scan exceeded ${SCAN_TIMEOUT_MS / 1000}s — connection closed.`)
    }, SCAN_TIMEOUT_MS)

    es.onmessage = (event) => {
      let data
      try {
        data = JSON.parse(event.data)
      } catch {
        return
      }
      if (data.type === 'log') {
        appendLog(data.level || 'INFO', data.text)
      } else if (data.type === 'finding') {
        findingsRef.current = [...findingsRef.current, data]
      } else if (data.type === 'progress') {
        setProgress({
          current: data.current,
          total: data.total,
          label: data.label,
        })
      } else if (data.type === 'done') {
        summaryRef.current = data.summary
      } else if (data.type === 'error') {
        appendLog('ERROR', data.message || 'Scan rejected')
        setScanError(data.message || 'Scan rejected')
      }
    }

    es.addEventListener('end', () => finishScan())

    es.onerror = () => {
      // EventSource fires onerror also on graceful close after `event: end`.
      // If we already have a summary, treat it as success; otherwise it's a real failure.
      if (summaryRef.current) {
        finishScan()
      } else {
        finishScan('Connection to scanner lost. The target may be unreachable or the server timed out.')
      }
    }
  }

  const cancelScan = () => {
    finishScan('Scan cancelled by user.')
  }

  const newScan = () => {
    setScanState('idle')
    setLogs([])
    setScanResult(null)
    setScanError(null)
    setProgress({ current: 0, total: 0, label: '' })
  }

  const renderRiskColor = (level) => {
    switch (level) {
      case 'Critical':
        return 'var(--color-danger)'
      case 'High':
        return '#FF6B35'
      case 'Medium':
        return '#FFB300'
      case 'Low':
      case 'Hardenable':
        return '#FFD54F'
      case 'Secure':
        return 'var(--color-success)'
      default:
        return 'var(--color-text-muted, #888)'
    }
  }

  const score = scanResult?.score ?? 100
  const summaryCounts = scanResult?.counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 }

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-title">SCAN HISTORY</span>
        </div>
        <div className="history-list">
          {history.length === 0 ? (
            <div className="history-empty">No recent scans</div>
          ) : (
            history.map((item) => {
              const url = item.target_url || item.url || ''
              const risk = item.risk_level || item.risk || ''
              const when = item.created_at
                ? new Date(item.created_at).toLocaleDateString()
                : (item.date || '').split(',')[0]
              return (
                <div key={item.id ?? url + when} className="history-item" onClick={() => setTargetUrl(url)}>
                  <div className="history-url">{url}</div>
                  <div className="history-meta">
                    <span className={`risk-tag ${risk.toLowerCase()}`}>{risk}</span>
                    <span className="history-date">{when}</span>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </aside>

      <div className="app-container">
        <header className="header">
          <div className="logo">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
            <span className="logo-text">SENTINEL<span className="text-primary">AI</span></span>
          </div>
          <h1 className="hero-title">Intelligent Security <span className="title-highlight">Scanner</span></h1>
          <p className="hero-subtitle">Adaptive AI-powered detection across ten OWASP categories — runs entirely in your browser, no external tools required.</p>
          <div className="legal-banner">
            <strong>Authorised testing only.</strong> Unauthorised scanning may violate the
            <a href="https://www.legislation.gov.uk/ukpga/1990/18/contents" target="_blank" rel="noopener noreferrer"> Computer Misuse Act 1990</a>
            {' '}and equivalent laws in your jurisdiction. By using this tool you confirm you have explicit permission from the system owner.
          </div>
        </header>

        <main className="action-center">
          <div className="input-row">
            <div className="input-group">
              <input
                type="url"
                className="target-input"
                placeholder="https://example.com/login"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={scanState !== 'idle'}
                onKeyDown={(e) => { if (e.key === 'Enter' && scanState === 'idle') runAudit() }}
              />
            </div>
            {scanState !== 'scanning' ? (
              <button
                className={`scan-button ${scanState !== 'idle' ? 'loading' : ''}`}
                onClick={runAudit}
                disabled={scanState !== 'idle'}
              >
                {scanState === 'idle' ? 'START INTELLIGENT SCAN' : 'SCAN COMPLETE'}
              </button>
            ) : (
              <button className="scan-button cancel" onClick={cancelScan}>
                CANCEL
              </button>
            )}
          </div>

          <div className="disclaimer-group">
            <input
              type="checkbox"
              id="auth-check"
              checked={isAuthorized}
              onChange={(e) => setIsAuthorized(e.target.checked)}
              disabled={scanState !== 'idle'}
              className="checkbox-custom"
            />
            <label htmlFor="auth-check" className="disclaimer-label">
              I confirm I have explicit authorisation to scan this target and accept full legal responsibility for the testing.
            </label>
          </div>
          <p className="legal-fineprint">
            Scans of government, healthcare, law-enforcement, military, and major financial domains are refused. Each scan is recorded in a server-side audit log for accountability.
          </p>

          {(scanState !== 'idle') && (
            <div className={`scanner-terminal visible`} ref={terminalRef}>
              <div className="terminal-header">
                <div className="terminal-dots"><span/><span/><span/></div>
                <span className="terminal-title">SentinelAI Engine Log</span>
                {progress.total > 0 && (
                  <span className="progress-pill">
                    {progress.current}/{progress.total} · {progress.label}
                  </span>
                )}
              </div>
              <div className="terminal-body">
                {logs.map((log, i) => (
                  <div key={i} className="log-line">
                    <span className="log-time">{log.time}</span>
                    <span className={`log-text ${log.type}`}>{log.text}</span>
                  </div>
                ))}
                {scanState === 'scanning' && <div className="cursor-blink" />}
              </div>
            </div>
          )}

          {scanState === 'completed' && scanError && (
            <div className="error-banner">
              <strong>Scan error:</strong> {scanError}
              <button className="reset-btn" onClick={newScan}>NEW SCAN</button>
            </div>
          )}

          {scanState === 'completed' && scanResult && (
            <div className="results-dashboard">
              <div className="dashboard-top">
                <div className="score-section">
                  <div className="score-circle" style={{ '--score': `${score}%` }}>
                    <div className="score-value">{score}</div>
                    <div className="score-label">SECURITY SCORE</div>
                  </div>
                </div>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="card-label">Risk Level</div>
                    <div className="card-value" style={{ color: renderRiskColor(scanResult.risk_level) }}>
                      {scanResult.risk_level}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="card-label">Status</div>
                    <div className="card-value">{scanResult.status}</div>
                  </div>
                  <div className="summary-card">
                    <div className="card-label">Total Findings</div>
                    <div className="card-value">{scanResult.findings_total ?? scanResult.findings?.length ?? 0}</div>
                  </div>
                </div>
              </div>

              <div className="severity-bar">
                {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                  <div key={sev} className={`sev-pill sev-${sev}`}>
                    <span className="sev-count">{summaryCounts[sev] || 0}</span>
                    <span className="sev-label">{SEVERITY_LABEL[sev]}</span>
                  </div>
                ))}
              </div>

              {scanResult.findings && scanResult.findings.length > 0 ? (
                <div className="findings-section">
                  <h3>DETECTION DETAILS</h3>
                  {scanResult.findings.map((finding, idx) => (
                    <div key={idx} className={`finding-card sev-border-${finding.severity || 'info'}`}>
                      <div className="finding-header">
                        <span className="finding-type">{finding.category}</span>
                        <span className={`sev-badge sev-${finding.severity || 'info'}`}>
                          {SEVERITY_LABEL[finding.severity || 'info']}
                        </span>
                      </div>
                      <div className="finding-body">
                        {finding.title && <p className="finding-title"><strong>{finding.title}</strong></p>}
                        {finding.evidence && (
                          <p className="finding-evidence"><code className="font-mono">{finding.evidence}</code></p>
                        )}
                        <button className="remedy-btn" onClick={() => setShowRemediation(idx)}>
                          VIEW REMEDIATION
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="findings-section">
                  <p className="findings-clean">No vulnerabilities detected across the ten OWASP-aligned checks. Continue to monitor and re-scan after deployments.</p>
                </div>
              )}

              <button className="reset-btn" onClick={newScan}>NEW SCAN</button>
            </div>
          )}
        </main>

        {showRemediation !== null && scanResult?.findings?.[showRemediation] && (
          <div className="modal-overlay" onClick={() => setShowRemediation(null)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>REMEDIATION GUIDE</h3>
                <button className="close-btn" onClick={() => setShowRemediation(null)}>&times;</button>
              </div>
              <div className="modal-body">
                <div className="markdown-content">
                  <p><strong>{scanResult.findings[showRemediation].category}</strong> — {scanResult.findings[showRemediation].title}</p>
                  <pre className="remedy-code">
                    {STATIC_REMEDIATIONS[scanResult.findings[showRemediation].remediation_key
                      || scanResult.findings[showRemediation].category]
                      || 'Refer to OWASP guidance for remediation steps.'}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        <footer className="footer">
          SentinelAI Security — Build {BUILD_VERSION} — 10 OWASP categories scanned in your browser
        </footer>
      </div>
    </div>
  )
}

export default App
