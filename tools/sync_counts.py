#!/usr/bin/env python3
from pathlib import Path

p = Path("wargame/README.md")
text = p.read_text(encoding="utf-8")
text = text.replace("| `perimeter` 외곽 | **0** | 378 | 40% |", "| `perimeter` 외곽 | **0** | 385 | 40% |")
text = text.replace("| `webserver` 웹서버 | **1** | 587 | 60% |", "| `webserver` 웹서버 | **1** | 594 | 60% |")
text = text.replace("| `internal` 내부망 | **2** | 739 | 60% |", "| `internal` 내부망 | **2** | 746 | 60% |")
text = text.replace("| `vault` 금고 | **3** | 729 | 58% |", "| `vault` 금고 | **3** | 736 | 58% |")
text = text.replace("| `core` 코어 | **4** | 682 | 71% |", "| `core` 코어 | **4** | 689 | 71% |")
p.write_text(text, encoding="utf-8")

docs = [
    "README.md", "README.en.md", "README.ja.md", "README.zh.md",
    "USAGE.md", "AI_LEARNING.md", "COMMERCIAL.md", "AGENTS.md",
    "launch/producthunt/launch_brief.md", "launch/reddit/reddit_post.md"
]

for fname in docs:
    fp = Path(fname)
    if fp.exists():
        c = fp.read_text(encoding="utf-8")
        c = c.replace("3115", "3150")
        c = c.replace("89개 트랙", "90개 트랙")
        c = c.replace("89 tracks", "90 tracks")
        c = c.replace("89 트랙", "90 트랙")
        c = c.replace("77개 랩", "78개 랩")
        c = c.replace("77개 실습", "78개 실습")
        c = c.replace("77개 골든", "78개 골든")
        c = c.replace("77 labs", "78 labs")
        c = c.replace("77 Labs", "78 Labs")
        c = c.replace("43대 단독", "44대 단독")
        c = c.replace("43대 시뮬레이터", "44대 시뮬레이터")
        c = c.replace("43 simulators", "44 simulators")
        c = c.replace("43 Simulators", "44 Simulators")
        c = c.replace("v2.27.0", "v2.28.0")
        fp.write_text(c, encoding="utf-8")

print("[+] Successfully updated doc counts across all documents.")
