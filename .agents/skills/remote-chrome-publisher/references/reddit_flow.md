# Reddit Promotion & Community Sharing Protocol

This guide outlines the promotional posting protocol across technical subreddits while respecting community rules, self-promotion guidelines, and anti-spam filters.

---

## 1. Target Subreddits & Rules

| Subreddit | Allowed Content | Rules to Keep in Mind |
| :--- | :--- | :--- |
| **r/netsec** | High-quality technical articles, whitepapers, novel tools | Direct links to tools/curriculum. Must be original, non-commercial technical work. |
| **r/cybersecurity** | Education, career advice, lab walk-throughs | Saturday Self-Promo thread or high-value educational posts. |
| **r/ReverseEngineering** | RE tutorials, binaries, disassembler workflows | In-depth technical breakdown only. Focus on Ghidra/radare2 labs. |
| **r/crypto** | Cryptanalysis, cryptographic labs | Focus on Section 04 / Lab 04 (Padding Oracle, RSA math). |

---

## 2. Dual-Channel Execution

### Channel A: Direct API (Headless Background)
If `REDDIT_CLIENT_ID` and `REDDIT_CLIENT_SECRET` (script app) are configured in the environment:
- Uses `PRAW` (Python Reddit API Wrapper) or direct OAuth2 token.
- Completely silent, no browser window required.

### Channel B: Authenticated Chrome Remote Session (Port 9222)
When API credentials are not available or 2FA prevents token generation:
1. Verify session: `python scripts/check_session.py`
2. Open target subreddit submission URL:
   `https://www.reddit.com/r/{target_sub}/submit`
3. DevTools fills:
   - Title: `[Release/Free Tool] VibeHacking - Open Source 56 Docker Labs & 2,380 Wargames Platform`
   - Body/URL: Technical breakdown and GitHub repository link.
   - Flair selection: `Tool` or `Resource`.
4. Capture screenshot before posting.
