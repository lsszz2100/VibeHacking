# Product Hunt Launch Automation Flow

This guide defines the deterministic automated launch flow using the `chrome-devtools` MCP server connected to an authenticated Windows Chrome debugging instance (`127.0.0.1:9222`).

---

## 1. Prerequisites Check
1. Start Windows Chrome with debugging port enabled:
   ```cmd
   start chrome.exe --remote-debugging-port=9222 --user-data-dir="C:\ChromeDebug"
   ```
2. Verify connectivity:
   ```bash
   python scripts/check_session.py
   ```
3. Ensure you are logged into your Product Hunt account on this Chrome profile (SSO / 2FA bypassed naturally).

---

## 2. DevTools MCP Automation Steps

### Step 1: Navigate to Post Form
- Call `mcp_chrome-devtools_navigate_page`:
  - `url`: `https://www.producthunt.com/posts/new`
- Wait for page load:
  - Call `mcp_chrome-devtools_wait_for` (e.g. selector `input[name="name"]` or `textarea`).

### Step 2: Fill Primary Metadata
Read values from `assets/producthunt_payload.json`:
- **Product Name**:
  - Selector: `input[name="name"]`, `input[placeholder*="Name of the product"]`
  - Value: `VibeHacking`
- **Tagline**:
  - Selector: `input[name="tagline"]`, `input[placeholder*="Short tagline"]`
  - Value: `AI-Driven Cybersecurity & Hands-on Reverse Engineering Platform`
- **URL**:
  - Selector: `input[name="url"]`, `input[placeholder*="https://"]`
  - Value: `https://lsszz2100.github.io/vibe-hacking/`
- **Description**:
  - Selector: `textarea[name="description"]`
  - Value: Copied from `product.description`

### Step 3: Select Topics
- Click topic search input: `input[placeholder*="Search for a topic"]`
- Type topic name (e.g. `Cybersecurity`, `Open Source`), press Enter or click matched dropdown item.

### Step 4: Upload Media Assets
- Using `mcp_chrome-devtools_upload_file`:
  - Locate file upload input elements (`input[type="file"]`).
  - Provide absolute file paths to project assets (banners, logos, screenshots).

### Step 5: Maker Comment
- When prompted for "First Comment", input content from `product.first_comment`.

### Step 6: Review & Final Submission
- Capture page snapshot (`mcp_chrome-devtools_take_screenshot`) for human review.
- Request user confirmation or invoke submit button (`button[type="submit"]`) if instructed.
