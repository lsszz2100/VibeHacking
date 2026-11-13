---
name: remote-chrome-publisher
description: Automates web form submissions, product launches (e.g., Product Hunt), and technical announcements (e.g., Reddit) by connecting to an authenticated Windows Chrome remote debugging session (127.0.0.1:9222) via chrome-devtools MCP tools. Use this skill whenever headless or sandbox browsers fail due to Cloudflare, bot detection, SSO, or 2FA requirements.
---

# Remote Chrome Publisher Skill

Connects directly to an existing, authenticated user Chrome browser running on Windows with remote debugging enabled (`--remote-debugging-port=9222`). This bypasses SSO, 2FA, and bot challenges (Cloudflare, reCAPTCHA) natively while executing deterministic form submissions.

---

## 1. When to Use This Skill

- 🚀 **Product Hunt Launch**: Publishing VibeHacking new releases, media assets, maker comments, and metadata.
- 📢 **Community Announcements**: Submitting technical posts to Reddit (`r/netsec`, `r/cybersecurity`) or Hacker News.
- 🛡️ **Bot/SSO Bypass**: Any external website submission where standard Puppeteer/Playwright headless sessions are blocked by 2FA or Cloudflare Turnstile.

---

## 2. Architecture & Directory Layout

```
.agents/skills/remote-chrome-publisher/
├── SKILL.md                          # Main skill instructions (this file)
├── scripts/
│   └── check_session.py              # Port 9222 connectivity & tab inspector
├── references/
│   ├── producthunt_flow.md           # Product Hunt form selectors & submission steps
│   └── reddit_flow.md                # Technical subreddit guidelines & posting flow
└── assets/
    └── producthunt_payload.json      # Structured launch payload with latest metrics
```

---

## 3. Workflow Steps

### Step 1: Verify Remote Debugging Session
Always run the session checker before attempting browser actions:
```bash
python .agents/skills/remote-chrome-publisher/scripts/check_session.py
```
If connection fails (`Connection refused`), instruct the user to launch Chrome with:
```cmd
start chrome.exe --remote-debugging-port=9222 --user-data-dir="C:\ChromeDebug"
```

### Step 2: Select Flow Reference
- For Product Hunt: Read [references/producthunt_flow.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/.agents/skills/remote-chrome-publisher/references/producthunt_flow.md)
- For Reddit: Read [references/reddit_flow.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/.agents/skills/remote-chrome-publisher/references/reddit_flow.md)

### Step 3: Load Metadata Payload
Load pre-validated metrics and descriptions from [assets/producthunt_payload.json](file:///mnt/d/바이브해킹%20자료/vibe-hacking/.agents/skills/remote-chrome-publisher/assets/producthunt_payload.json).

### Step 4: Execute via `chrome-devtools` MCP
1. `call_mcp_tool(ServerName="chrome-devtools", ToolName="navigate_page", ...)`
2. `call_mcp_tool(ServerName="chrome-devtools", ToolName="fill", ...)`
3. `call_mcp_tool(ServerName="chrome-devtools", ToolName="upload_file", ...)`
4. `call_mcp_tool(ServerName="chrome-devtools", ToolName="take_screenshot", ...)` to provide visual feedback before irreversible submit actions.

---

## 4. Safety & Compliance Invariants
1. **PII Masking**: Never inject personal phone numbers, secret API keys, or raw passwords into public submission fields.
2. **Deterministic Inputs**: All metrics (number of sections, labs, tracks, wargame count) must strictly match the repository SSOT.
3. **Approval Gate**: Take a screenshot and present it to the user before pressing final submit buttons on irreversible production platforms.
