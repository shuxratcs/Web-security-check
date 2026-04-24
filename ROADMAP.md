# Roadmap: SentinelAI MVP+

## Phase 1: Smart Backend Foundation
- [ ] Install new dependencies (`google-generativeai`, `beautifulsoup4`, `python-dotenv`)
- [ ] Configure Environment (Gemini API Key)
- [ ] Modularize `scanner.py` into `crawler.py`, `ai_engine.py`, and `reporter.py`

## Phase 2: AI-Powered Core
- [ ] Implement `AI Recon`: Extract forms and inputs, use LLM to identify tech stack.
- [ ] Implement `Adaptive Payloads`: AI generates payloads based on input context.
- [ ] Implement `AI Judge`: Send suspicious responses to LLM for verification.

## Phase 3: Remediation & Reporting
- [ ] Implement `Remediation Service`: AI generates code fixes for vulnerabilities.
- [ ] Implement `Report Generation`: Create structured scan summaries.

## Phase 4: UI Overhaul
- [ ] Implement Real-time Logs in the React frontend.
- [ ] Add Security Score chart and Scan History dashboard.
- [ ] Polish aesthetics (Glassmorphism, dark mode, smooth transitions).
