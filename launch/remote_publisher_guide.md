# Remote Chrome Automation & Unmanned Publishing Protocol

## 1. Overview & Enterprise Principle

According to the enterprise security memory and automation standards:
- External marketing and launch platforms (Product Hunt, Reddit, LinkedIn, Twitter) employ aggressive bot detection, Cloudflare Turnstile, SSO, and 2FA gates.
- Headless virtual browsers frequently trigger account bans or CAPTCHA blocks.
- **SSOT Standard [Method A]**: The user starts their local Windows Chrome session with remote debugging enabled (`--remote-debugging-port=9222`). The AI agent attaches via the `chrome-devtools` MCP to execute form population, screenshot uploading, and final submission seamlessly without bot friction.

---

## 2. Windows Chrome Debugging Port Setup

Run the following command in Windows Command Prompt (`cmd.exe`) or PowerShell to launch an authenticated Chrome session:

```cmd
:: Close any running Chrome instances first (optional, or run with a dedicated debugging profile)
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="C:\ChromeDebugProfile"
```

> [!TIP]
> If you already have your Product Hunt or Reddit accounts logged in under your default Chrome profile, you can open Chrome with:
> `"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222`

---

## 3. Connecting `chrome-devtools` MCP

Once Chrome is running on port 9222:
1. Ensure the `chrome-devtools` MCP server is enabled in Antigravity or configured in MCP settings:
   ```json
   {
     "mcpServers": {
       "chrome-devtools": {
         "command": "npx",
         "args": ["-y", "@modelcontextprotocol/server-chrome-devtools", "--port", "9222"]
       }
     }
   }
   ```
2. The AI agent executes:
   - `list_pages` to find active tabs.
   - `navigate_page` to go to `https://www.producthunt.com/posts/new` or `https://www.reddit.com/r/netsec/submit`.
   - `take_snapshot` / `evaluate_script` to locate input fields.
   - `fill_form` / `type_text` to fill title, description, and tags directly from [launch/producthunt/launch_brief.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/launch/producthunt/launch_brief.md) and [launch/reddit/reddit_post.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/launch/reddit/reddit_post.md).
   - `upload_file` to attach product screenshots from `release/` or `wargame/assets/`.
   - `click` on the submit button.

---

## 4. Reddit Unmanned API Execution [Method B]

For automated background publishing to Reddit when user intervention is not desired:
- Utilize Reddit API `script` application credentials (`client_id`, `client_secret`, `username`, `password`, `user_agent`).
- Script template:
  ```python
  import praw

  reddit = praw.Reddit(
      client_id="YOUR_CLIENT_ID",
      client_secret="YOUR_CLIENT_SECRET",
      user_agent="VibeHacking-LaunchBot/2.14.0",
      username="YOUR_REDDIT_USERNAME",
      password="YOUR_REDDIT_PASSWORD"
  )

  subreddit = reddit.subreddit("netsec")
  subreddit.submit(
      title="VibeHacking: Open-source cybersecurity bible (75 sections, 63 labs) & browser-based terminal wargame with 2,625 challenges",
      url="https://github.com/lsszz2100/VibeHacking"
  )
  ```

---

## 5. Execution Checklist

- [x] Launch assets compiled in [launch/producthunt/launch_brief.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/launch/producthunt/launch_brief.md)
- [x] Reddit multi-community posts compiled in [launch/reddit/reddit_post.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/launch/reddit/reddit_post.md)
- [x] Social share URLs verified with [tools/promo_kit.py](file:///mnt/d/바이브해킹%20자료/vibe-hacking/tools/promo_kit.py)
- [ ] Connect Chrome on port 9222 upon user prompt for live one-click submission
