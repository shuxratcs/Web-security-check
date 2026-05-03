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

// Points deducted from the 100-point score per severity level
const SEVERITY_PENALTY = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 1,
  info: 0,
}

// Plain-language explanations for non-technical users (entrepreneurs)
const HUMAN_DESCRIPTIONS = {
  'SQL Injection': {
    what: 'An attacker could insert malicious database commands through your website\'s forms or URL, potentially stealing all your customer data.',
    risk: 'Your database (customer names, emails, passwords, payment info) could be fully compromised.',
    who: 'Any visitor to your website could exploit this without special tools.',
  },
  'Reflected XSS': {
    what: 'An attacker could inject malicious scripts into your website that run in your customers\' browsers.',
    risk: 'Attackers can steal login sessions, redirect users to phishing sites, or deface your website.',
    who: 'Attackers trick your users by sending them a specially crafted link to your site.',
  },
  'Missing Security Headers': {
    what: 'Your server is not sending recommended security instructions to visitors\' browsers.',
    risk: 'Without these headers, browsers cannot enforce important protections for your users.',
    who: 'This is a hardening recommendation — it makes other attacks easier if missing.',
  },
  'Insecure Cookie': {
    what: 'Your website\'s login cookies are missing important security flags.',
    risk: 'User sessions could be hijacked over insecure connections or by malicious scripts.',
    who: 'An attacker on the same WiFi network or a malicious script on your page.',
  },
  'Sensitive File Exposure': {
    what: 'Configuration files, backups, or source code are publicly accessible on your server.',
    risk: 'These files may contain database passwords, API keys, or other secrets.',
    who: 'Anyone who knows the common file paths can access these directly.',
  },
  'CORS Misconfiguration': {
    what: 'Your API allows requests from any website, which could let attackers steal data.',
    risk: 'A malicious website could make requests to your API on behalf of logged-in users.',
    who: 'An attacker hosting a malicious website that your users visit.',
  },
  'Clickjacking': {
    what: 'Your website can be embedded inside another website using invisible frames.',
    risk: 'Attackers can trick users into clicking buttons on your site without their knowledge.',
    who: 'An attacker creates a fake page with your site hidden behind it.',
  },
  'Information Disclosure': {
    what: 'Your server reveals technical details (software versions, emails, error messages) to visitors.',
    risk: 'Attackers use this information to find known vulnerabilities specific to your software.',
    who: 'Any visitor can see this information in your page source or HTTP headers.',
  },
  'Weak SSL/TLS': {
    what: 'Your website\'s encryption (HTTPS) is either missing, outdated, or misconfigured.',
    risk: 'Data transmitted between your users and your server could be intercepted.',
    who: 'Anyone on the same network (e.g. public WiFi) can intercept unencrypted traffic.',
  },
  'Weak CSP': {
    what: 'Your Content Security Policy is missing or too permissive.',
    risk: 'Without CSP, browsers cannot block injected malicious scripts on your site.',
    who: 'Attackers who find any way to inject content into your pages.',
  },
  'Vulnerable / Outdated Component': {
    what: 'Your server or website uses software with known security vulnerabilities.',
    risk: 'Attackers have pre-built tools to exploit these specific software versions.',
    who: 'Automated scanners actively search the internet for outdated software.',
  },
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
  'Outdated Component':
    'Update all server software, frameworks, and libraries to the latest stable versions. Subscribe to security advisories for your stack.',
  'Vulnerable / Outdated Component':
    'Update all server software, frameworks, and libraries to the latest stable versions. Subscribe to security advisories for your stack.',
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

  // Generate a downloadable text report
  function generateReport() {
    if (!scanResult) return
    const lines = []
    lines.push('═══════════════════════════════════════════════════════════════')
    lines.push('                    SentinelAI Security Report                ')
    lines.push('═══════════════════════════════════════════════════════════════')
    lines.push('')
    lines.push(`Target:         ${targetUrl}`)
    lines.push(`Date:           ${new Date().toLocaleString()}`)
    lines.push(`Security Score: ${scanResult.score}/100`)
    lines.push(`Risk Level:     ${scanResult.risk_level}`)
    lines.push(`Status:         ${scanResult.status}`)
    lines.push(`Total Findings: ${scanResult.findings_total ?? scanResult.findings?.length ?? 0}`)
    lines.push('')
    lines.push('───────────────────────────────────────────────────────────────')
    lines.push('  SEVERITY BREAKDOWN')
    lines.push('───────────────────────────────────────────────────────────────')
    const c = scanResult.counts || {}
    lines.push(`  Critical: ${c.critical || 0}   High: ${c.high || 0}   Medium: ${c.medium || 0}   Low: ${c.low || 0}   Info: ${c.info || 0}`)
    lines.push('')

    if (scanResult.findings && scanResult.findings.length > 0) {
      lines.push('───────────────────────────────────────────────────────────────')
      lines.push('  DETAILED FINDINGS')
      lines.push('───────────────────────────────────────────────────────────────')
      scanResult.findings.forEach((f, i) => {
        const sev = (f.severity || 'info').toUpperCase()
        const penalty = SEVERITY_PENALTY[f.severity || 'info']
        const desc = HUMAN_DESCRIPTIONS[f.category] || HUMAN_DESCRIPTIONS[f.remediation_key]
        const remedy = STATIC_REMEDIATIONS[f.remediation_key || f.category]
        lines.push('')
        lines.push(`  #${i + 1}  [${sev}]  ${f.category}`)
        lines.push(`  Issue: ${f.title}`)
        if (f.evidence) lines.push(`  Evidence: ${f.evidence}`)
        lines.push(`  Score Impact: -${penalty} points`)
        if (desc) {
          lines.push(`  What it means: ${desc.what}`)
          lines.push(`  Business risk: ${desc.risk}`)
        }
        if (remedy) {
          lines.push(`  How to fix: ${remedy}`)
        }
        lines.push('  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -')
      })
    } else {
      lines.push('')
      lines.push('  ✓ No vulnerabilities detected. Your site passed all checks.')
    }

    lines.push('')
    lines.push('───────────────────────────────────────────────────────────────')
    lines.push('  RESPONSIBLE DISCLOSURE NOTICE')
    lines.push('───────────────────────────────────────────────────────────────')
    lines.push('  If vulnerabilities were found, we recommend:')
    lines.push('  1. Fix the issues according to the remediation guidance above.')
    lines.push('  2. If this is not your website, responsibly disclose the')
    lines.push('     findings to the site owner.')
    lines.push('  3. Do NOT exploit or publicly share vulnerabilities.')
    lines.push('')
    lines.push('  Reference: NCSC Vulnerability Disclosure Toolkit')
    lines.push('  https://www.ncsc.gov.uk/information/vulnerability-disclosure-toolkit')
    lines.push('')
    lines.push('═══════════════════════════════════════════════════════════════')
    lines.push(`  Generated by SentinelAI ${BUILD_VERSION}`)
    lines.push('  OWASP Top 10 aligned security scanner')
    lines.push('═══════════════════════════════════════════════════════════════')

    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    const hostname = new URL(targetUrl).hostname.replace(/\./g, '_')
    a.href = url
    a.download = `SentinelAI_Report_${hostname}_${new Date().toISOString().slice(0,10)}.txt`
    a.click()
    URL.revokeObjectURL(url)
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

              <div className="report-actions">
                <button className="download-btn" onClick={generateReport} id="download-report">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                  </svg>
                  DOWNLOAD FULL REPORT
                </button>
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
                  <p className="findings-explainer">Each finding shows what was detected, why it matters for your business, and how many points it deducted from your security score.</p>
                  {scanResult.findings.map((finding, idx) => {
                    const sev = finding.severity || 'info'
                    const penalty = SEVERITY_PENALTY[sev]
                    const humanDesc = HUMAN_DESCRIPTIONS[finding.category] || HUMAN_DESCRIPTIONS[finding.remediation_key]
                    return (
                      <div key={idx} className={`finding-card sev-border-${sev}`}>
                        <div className="finding-header">
                          <span className="finding-type">{finding.category}</span>
                          <div className="finding-header-right">
                            {penalty > 0 && (
                              <span className="penalty-badge">−{penalty} pts</span>
                            )}
                            <span className={`sev-badge sev-${sev}`}>
                              {SEVERITY_LABEL[sev]}
                            </span>
                          </div>
                        </div>
                        <div className="finding-body">
                          {finding.title && <p className="finding-title"><strong>{finding.title}</strong></p>}

                          {humanDesc && (
                            <div className="finding-explanation">
                              <div className="explanation-row">
                                <span className="explanation-icon">💡</span>
                                <div>
                                  <span className="explanation-label">What this means:</span>
                                  <span className="explanation-text">{humanDesc.what}</span>
                                </div>
                              </div>
                              <div className="explanation-row">
                                <span className="explanation-icon">⚠️</span>
                                <div>
                                  <span className="explanation-label">Business risk:</span>
                                  <span className="explanation-text">{humanDesc.risk}</span>
                                </div>
                              </div>
                              {humanDesc.who && (
                                <div className="explanation-row">
                                  <span className="explanation-icon">👤</span>
                                  <div>
                                    <span className="explanation-label">Who can exploit it:</span>
                                    <span className="explanation-text">{humanDesc.who}</span>
                                  </div>
                                </div>
                              )}
                            </div>
                          )}

                          {finding.evidence && (
                            <details className="evidence-details">
                              <summary>Technical evidence</summary>
                              <p className="finding-evidence"><code className="font-mono">{finding.evidence}</code></p>
                            </details>
                          )}
                          <button className="remedy-btn" onClick={() => setShowRemediation(idx)}>
                            VIEW FIX INSTRUCTIONS
                          </button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="findings-section">
                  <p className="findings-clean">✓ No vulnerabilities detected across the ten OWASP-aligned checks. Your website demonstrates strong security practices. Continue to monitor and re-scan after deployments.</p>
                </div>
              )}

              <div className="disclosure-note">
                <strong>Responsible Disclosure:</strong> If vulnerabilities were found on a website you do not own, we recommend reporting them to the site owner following the <a href="https://www.ncsc.gov.uk/information/vulnerability-disclosure-toolkit" target="_blank" rel="noopener noreferrer">NCSC Vulnerability Disclosure Toolkit</a> guidelines. Do not exploit or publicly share vulnerabilities.
              </div>

              <div className="results-actions">
                <button className="download-btn" onClick={generateReport}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                  </svg>
                  DOWNLOAD REPORT
                </button>
                <button className="reset-btn" onClick={newScan}>NEW SCAN</button>
              </div>
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
