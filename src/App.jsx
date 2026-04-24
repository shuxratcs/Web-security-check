import { useState, useEffect, useRef } from 'react'
import './App.css'

const BUILD_VERSION = 'v4.0 MVP+';

function App() {
  const [targetUrl, setTargetUrl] = useState('');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [scanState, setScanState] = useState('idle'); // 'idle' | 'scanning' | 'completed'
  const [logs, setLogs] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [history, setHistory] = useState([]);
  const [showRemediation, setShowRemediation] = useState(null);
  const terminalRef = useRef(null);
  
  const API_ENDPOINT = '/api/scan';

  // Load history from localStorage on mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('sentinel_history');
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error("Failed to load history", e);
      }
    }
  }, []);

  // Auto-scroll terminal when new logs arrive
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const runAudit = async () => {
    if (!targetUrl) {
      alert("Please enter a target URL before scanning.");
      return;
    }
    if (!isAuthorized) {
      alert("You must check the mandatory consent checkbox to proceed.");
      return;
    }

    setScanState('scanning');
    setLogs([]);
    setScanError(null);
    setScanResult(null);

    try {
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, consent: isAuthorized })
      });

      const data = await response.json();

      if (data.status !== "error") {
        const backendLogs = data.details || [];
        let messageIndex = 0;
        
        // Visual simulation of log flow
        const intervalId = setInterval(() => {
          if (messageIndex < backendLogs.length) {
            const text = backendLogs[messageIndex];
            let type = 'info';
            if (text.includes('[SUCCESS]')) type = 'success';
            if (text.includes('[SCANNING]')) type = 'warning';
            if (text.includes('[WARNING]')) type = 'warning';
            if (text.includes('[CRITICAL]')) type = 'danger';
            if (text.includes('[ERROR]')) type = 'danger';

            setLogs(prev => [...prev, {
              time: new Date().toLocaleTimeString(),
              text: text,
              type: type
            }]);
            messageIndex++;
          } else {
            clearInterval(intervalId);
            setScanResult(data);
            setScanState('completed');
            
            // Add to history
            const newHistory = [{
              url: targetUrl,
              date: new Date().toLocaleString(),
              status: data.status,
              risk: data.risk_level
            }, ...history].slice(0, 10);
            setHistory(newHistory);
            localStorage.setItem('sentinel_history', JSON.stringify(newHistory));
          }
        }, 80);

      } else {
        setScanError(data.message || 'Scan returned an error.');
        setLogs(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          text: `[ERROR] ${data.message || 'Unknown server error'}`,
          type: 'danger'
        }]);
        setScanState('completed');
      }
    } catch (error) {
      setScanError(error?.message || String(error));
      setLogs(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        text: `[FATAL] Connection failed: ${error?.message}`,
        type: 'danger'
      }]);
      setScanState('completed');
    }
  };

  const calculateScore = () => {
    if (!scanResult) return 100;
    if (scanResult.status === 'Vulnerable') {
      return Math.max(0, 100 - (scanResult.findings.length * 25));
    }
    return 100;
  };

  return (
    <div className="app-layout">
      {/* Sidebar for History */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-title">SCAN HISTORY</span>
        </div>
        <div className="history-list">
          {history.length === 0 ? (
            <div className="history-empty">No recent scans</div>
          ) : (
            history.map((item, i) => (
              <div key={i} className="history-item" onClick={() => setTargetUrl(item.url)}>
                <div className="history-url">{item.url}</div>
                <div className="history-meta">
                  <span className={`risk-tag ${item.risk.toLowerCase()}`}>{item.risk}</span>
                  <span className="history-date">{item.date.split(',')[0]}</span>
                </div>
              </div>
            ))
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
          <p className="hero-subtitle">Adaptive AI-powered vulnerability detection for modern web applications.</p>
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
              />
            </div>
            <button
              className={`scan-button ${scanState !== 'idle' ? 'loading' : ''}`}
              onClick={runAudit}
              disabled={scanState !== 'idle'}
            >
              {scanState === 'idle' ? 'START INTELLIGENT SCAN' : 
               scanState === 'scanning' ? 'ANALYZING...' : 'SCAN COMPLETE'}
            </button>
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
              I have authorized permission to scan this target.
            </label>
          </div>

          {/* Terminal View */}
          <div className={`scanner-terminal ${scanState !== 'idle' ? 'visible' : ''}`} ref={terminalRef}>
            <div className="terminal-header">
              <div className="terminal-dots"><span/><span/><span/></div>
              <span className="terminal-title">SentinelAI Engine Log</span>
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

          {/* Enhanced Results Dashboard */}
          {scanState === 'completed' && scanResult && (
            <div className="results-dashboard">
              <div className="dashboard-top">
                <div className="score-section">
                  <div className="score-circle" style={{'--score': `${calculateScore()}%`}}>
                    <div className="score-value">{calculateScore()}</div>
                    <div className="score-label">SECURITY SCORE</div>
                  </div>
                </div>
                <div className="summary-grid">
                  <div className="summary-card">
                    <div className="card-label">Tech Stack</div>
                    <div className="card-value text-primary">{scanResult.tech_stack || "Unknown"}</div>
                  </div>
                  <div className="summary-card">
                    <div className="card-label">Risk Level</div>
                    <div className="card-value" style={{color: scanResult.risk_level === 'Critical' ? 'var(--color-danger)' : 'var(--color-success)'}}>
                      {scanResult.risk_level}
                    </div>
                  </div>
                  <div className="summary-card">
                    <div className="card-label">Vulnerabilities</div>
                    <div className="card-value">{scanResult.findings.length}</div>
                  </div>
                </div>
              </div>

              {scanResult.findings.length > 0 && (
                <div className="findings-section">
                  <h3>DETECTION DETAILS</h3>
                  {scanResult.findings.map((finding, idx) => (
                    <div key={idx} className="finding-card">
                      <div className="finding-header">
                        <span className="finding-type">{finding.type}</span>
                        <span className="finding-conf">Confidence: {finding.confidence}%</span>
                      </div>
                      <div className="finding-body">
                        <p><strong>URL:</strong> {finding.url}</p>
                        <p><strong>Payload:</strong> <code className="font-mono">{finding.payload}</code></p>
                        <p className="finding-reason"><strong>AI Logic:</strong> {finding.reason}</p>
                        <button className="remedy-btn" onClick={() => setShowRemediation(idx)}>
                          VIEW REMEDIATION CODE
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <button className="reset-btn" onClick={() => setScanState('idle')}>NEW SCAN</button>
            </div>
          )}
        </main>

        {/* Remediation Modal */}
        {showRemediation !== null && (
          <div className="modal-overlay" onClick={() => setShowRemediation(null)}>
            <div className="modal-content" onClick={e => e.stopPropagation()}>
              <div className="modal-header">
                <h3>REMEDIATION GUIDE</h3>
                <button className="close-btn" onClick={() => setShowRemediation(null)}>&times;</button>
              </div>
              <div className="modal-body">
                <div className="markdown-content">
                  {scanResult.findings[showRemediation].remediation ? (
                    <pre className="remedy-code">
                      {scanResult.findings[showRemediation].remediation}
                    </pre>
                  ) : (
                    "Generating fix..."
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        <footer className="footer">
          SentinelAI Security — Build {BUILD_VERSION} — Powered by Google Gemini Pro
        </footer>
      </div>
    </div>
  )
}

export default App
