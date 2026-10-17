# Lab 44: ExtensionGuard — Browser Extension Security & Manifest V3 Audit Lab

An interactive security lab simulating modern browser extension security in Chrome/Chromium Manifest V3 environments, covering permission overprivileging, exposed web resources, content script DOM XSS, and defense-in-depth hardening.

## 🎯 Objectives
1. **Stage 1 (Manifest V3 Permission Audit)**: Audit `manifest.json` for excessive high-risk permissions (`<all_urls>`, `webRequestBlocking`, `cookies`) and inspect ephemeral background service worker behavior.
2. **Stage 2 (Web Accessible Resources Leak)**: Exploit wildcard origin matching in `web_accessible_resources` to exfiltrate master authentication tokens from `assets/auth_config.json`.
3. **Stage 3 (Content Script DOM XSS & Sniffing)**: Exploit unsafe `innerHTML` DOM sinks in `content.js` via cross-window messages and analyze password input event interception.
4. **Stage 4 (DNR Ruleset & Extension CSP Hardening)**: Migrate blocking network inspection to Declarative Net Request (DNR), enforce isolated worlds, and establish strict Extension Content Security Policies.

## 🚀 Quick Start

### Local Run (Python)
```bash
cd labs/44_browser_extension_security_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8044
```

### Docker Run
```bash
docker-compose up -d --build
```
Navigate to `http://127.0.0.1:8044` in your browser.

## 🧪 Test Execution
```bash
pytest -v labs/44_browser_extension_security_lab/tests/
```
