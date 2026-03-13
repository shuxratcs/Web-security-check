import { useState, useEffect, useRef } from 'react'
import './App.css'

// Removed static SCAN_MESSAGES array as it is now driven by backend

function App() {
  const [targetUrl, setTargetUrl] = useState('');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [scanState, setScanState] = useState('idle'); // 'idle' | 'scanning' | 'completed'
  const [logs, setLogs] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const terminalRef = useRef(null);
  
  // Use relative path in prod (same server), but localhost:8000 in local dev
  const API_BASE = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000' : '');
  const API_ENDPOINT = API_BASE ? `${API_BASE}/api/scan` : '/api/scan';

  // Auto-scroll terminal when new logs arrive
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const runAudit = async () => {
    if (!targetUrl || !isAuthorized) return;

    setScanState('scanning');
    setLogs([]);

    try {
      // 1. Fetch real logic/logs from the backend
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: targetUrl,
          consent: isAuthorized
        })
      });

      const data = await response.json();

      if (data.status !== "error") {
        const backendLogs = data.details || [];

        // 2. Start the visual animation of scanning logs from backend
        let messageIndex = 0;
        const intervalId = setInterval(() => {
          if (messageIndex < backendLogs.length) {
            const text = backendLogs[messageIndex];
            let type = 'info';
            if (text.includes('[SUCCESS]')) type = 'success';
            if (text.includes('[SCANNING]')) type = 'warning';

            setLogs(prev => [...prev, {
              time: new Date().toISOString().split('T')[1].substring(0, 12),
              text: text,
              type: type
            }]);
            messageIndex++;
          } else {
            clearInterval(intervalId);
            setScanResult(data);
            setScanState('completed');
          }
        }, 50); // 50ms per simulated log line for visual effect

      } else {
        console.error("Scan error:", data.message);
        setScanState('idle');
      }
    } catch (error) {
      console.warn("Backend hook unfulfilled:", error);
      setScanState('idle');
    }
  };

  return (
    <div className="app-container">
      {/* Header & Hero Section */}
      <header className="header">
        <h1 className="hero-title">
          Is Your Platform <span className="title-highlight">Vulnerable?</span><br />
          Scan for SQLi in Seconds with AI.
        </h1>
        <p className="hero-subtitle">
          Automated OWASP Top-10 detection powered by intelligent scanning algorithms.<br />
          Fast. Accurate. Reliable.
        </p>
      </header>

      {/* Main Action Center */}
      <main className="action-center">
        <div className="input-group">
          <input
            type="url"
            className="target-input"
            placeholder="https://your-target-website.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            disabled={scanState !== 'idle'}
          />
        </div>

        <div className="disclaimer-group">
          <input
            type="checkbox"
            id="auth-check"
            className="checkbox-custom"
            checked={isAuthorized}
            onChange={(e) => setIsAuthorized(e.target.checked)}
            disabled={scanState !== 'idle'}
          />
          <label htmlFor="auth-check" className="disclaimer-label">
            <strong>Mandatory:</strong> I confirm that I have authorized permission to scan this target and I accept full legal responsibility for the testing.
          </label>
        </div>

        <button
          className="scan-button"
          onClick={runAudit}
          disabled={!isAuthorized || !targetUrl || scanState !== 'idle'}
        >
          {scanState === 'idle' ? 'RUN SECURITY AUDIT' :
            scanState === 'scanning' ? 'SCAN IN PROGRESS...' : 'AUDIT COMPLETED'}
        </button>

        {/* Scanning Animation */}
        {scanState !== 'idle' && (
          <div className="scanner-terminal" ref={terminalRef}>
            {logs.map((log, i) => (
              <div key={i} className="log-line">
                <span className="log-time">[{log.time}]</span>
                <span className={`log-text ${log.type}`}>
                  {log.text}
                </span>
              </div>
            ))}
            {scanState === 'scanning' && (
              <div className="log-line">
                <span className="cursor-blink"></span>
              </div>
            )}
          </div>
        )}

        {/* Results Dashboard MVP */}
        {scanState === 'completed' && (
          <div className="results-dashboard">
            {scanResult?.status === 'Vulnerable' && (
              <div style={{ background: 'var(--color-danger)', color: '#000', padding: '1.5rem', textAlign: 'center', fontWeight: '900', fontSize: '1.5rem', marginBottom: '2rem', border: '2px solid #fff', borderRadius: '8px', textTransform: 'uppercase', letterSpacing: '4px', boxShadow: '0 0 20px var(--color-danger)' }}>
                ⚠ CRITICAL VULNERABILITY DETECTED
              </div>
            )}
            <div className="results-header">
              <h3 className="results-title">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
                Audit Report Summary
              </h3>
              <span className="status-badge complete">SCAN FINISHED</span>
            </div>

            <div className="results-grid">
              <div className="result-card critical">
                <div className="card-label">Risk Score</div>
                <div className="card-value critical">{scanResult?.risk_level || "Low"}</div>
              </div>
              <div className="result-card high">
                <div className="card-label">Primary Vulnerability</div>
                <div className="card-value">
                  {scanResult?.findings?.length > 0
                    ? `SQL Injection (${scanResult.findings.length} vectors found)`
                    : "None Detected"}
                </div>
              </div>
              <div className="result-card secure">
                <div className="card-label">System Status</div>
                <div className="card-value secure">{scanResult?.status || "Logged"}</div>
              </div>
            </div>

            {scanResult?.findings && scanResult.findings.length > 0 && (
              <div style={{ marginTop: '2rem', background: 'var(--color-surface-elevated)', padding: '1.5rem', borderRadius: '8px', borderLeft: '4px solid var(--color-danger)' }}>
                <h4 style={{ margin: '0 0 1rem 0', color: '#fff', fontSize: '1.1rem' }}>Vulnerable Injection Vectors:</h4>
                <ul style={{ listStyleType: 'none', padding: 0, margin: 0 }}>
                  {scanResult.findings.map((f, i) => (
                    <li key={i} style={{ marginBottom: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: 'var(--color-danger)' }}>
                      <strong>Payload:</strong> {f.payload}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

export default App
