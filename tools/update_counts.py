#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 1. wargame/index.html
html_path = ROOT / "wargame" / "index.html"
html = html_path.read_text(encoding="utf-8")
html = html.replace("0/2100", "0/2135")
html_path.write_text(html, encoding="utf-8")
print("Updated wargame/index.html")

# 2. wargame/README.md
wg_readme_path = ROOT / "wargame" / "README.md"
wg_readme = wg_readme_path.read_text(encoding="utf-8")
wg_readme = wg_readme.replace("2100", "2135")
wg_readme = wg_readme.replace("| `perimeter` 외곽 | **0** | 215 | 40% |", "| `perimeter` 외곽 | **0** | 217 | 40% |")
wg_readme = wg_readme.replace("| `webserver` 웹서버 | **1** | 376 | 60% |", "| `webserver` 웹서버 | **1** | 384 | 60% |")
wg_readme = wg_readme.replace("| `internal` 내부망 | **2** | 496 | 60% |", "| `internal` 내부망 | **2** | 508 | 60% |")
wg_readme = wg_readme.replace("| `vault` 금고 | **3** | 518 | 58% |", "| `vault` 금고 | **3** | 526 | 58% |")
wg_readme = wg_readme.replace("| `core` 코어 | **4** | 495 | 72% |", "| `core` 코어 | **4** | 500 | 71% |")
wg_readme_path.write_text(wg_readme, encoding="utf-8")
print("Updated wargame/README.md")

# 3. README.md
readme_path = ROOT / "README.md"
rm = readme_path.read_text(encoding="utf-8")
rm = rm.replace("2100 문제", "2135 문제")
rm = rm.replace("터미널_침투·2100 문제", "터미널_침투·2135 문제")
readme_path.write_text(rm, encoding="utf-8")
print("Updated README.md")

# 4. README.en.md
rm_en_path = ROOT / "README.en.md"
rm_en = rm_en_path.read_text(encoding="utf-8")
rm_en = rm_en.replace("2100 challenges", "2135 challenges")
rm_en = rm_en.replace("Terminal_Infiltration·2100_Challenges", "Terminal_Infiltration·2135_Challenges")
rm_en_path.write_text(rm_en, encoding="utf-8")
print("Updated README.en.md")

# 5. README.ja.md
rm_ja_path = ROOT / "README.ja.md"
rm_ja = rm_ja_path.read_text(encoding="utf-8")
rm_ja = rm_ja.replace("2100 問", "2135 問")
rm_ja = rm_ja.replace("ターミナル潜入·2100_問", "ターミナル潜入·2135_問")
rm_ja_path.write_text(rm_ja, encoding="utf-8")
print("Updated README.ja.md")

# 6. README.zh.md
rm_zh_path = ROOT / "README.zh.md"
rm_zh = rm_zh_path.read_text(encoding="utf-8")
rm_zh = rm_zh.replace("2100 道挑战", "2135 道挑战")
rm_zh = rm_zh.replace("终端渗透·2100_题", "终端渗透·2135_题")
rm_zh_path.write_text(rm_zh, encoding="utf-8")
print("Updated README.zh.md")

# 7. USAGE.md
usage_path = ROOT / "USAGE.md"
usage = usage_path.read_text(encoding="utf-8")
usage = usage.replace("2100 문제", "2135 문제")
usage = usage.replace("2100 challenges", "2135 challenges")
usage_path.write_text(usage, encoding="utf-8")
print("Updated USAGE.md")

# 8. AI_LEARNING.md
ai_path = ROOT / "AI_LEARNING.md"
ai = ai_path.read_text(encoding="utf-8")
ai = ai.replace("2100 문제", "2135 문제")
ai = ai.replace("2100 challenges", "2135 challenges")
ai = ai.replace("2100 問", "2135 問")
ai = ai.replace("2100 题", "2135 题")
ai_path.write_text(ai, encoding="utf-8")
print("Updated AI_LEARNING.md")

# 9. _navbar.md & docs/_sidebar.md & _sidebar.md
for fpath in [ROOT / "_navbar.md", ROOT / "_sidebar.md", ROOT / "docs" / "_sidebar.md"]:
    if fpath.exists():
        c = fpath.read_text(encoding="utf-8")
        c = c.replace("2,100제", "2,135제")
        c = c.replace("2,100", "2,135")
        fpath.write_text(c, encoding="utf-8")
        print(f"Updated {fpath.name}")
