#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 1. wargame/index.html
html_path = ROOT / "wargame" / "index.html"
html = html_path.read_text(encoding="utf-8")
html = html.replace("0/2170", "0/2205")
html_path.write_text(html, encoding="utf-8")
print("Updated wargame/index.html")

# 2. wargame/README.md
wg_readme_path = ROOT / "wargame" / "README.md"
wg_readme = wg_readme_path.read_text(encoding="utf-8")
wg_readme = wg_readme.replace("2170", "2205")
wg_readme = wg_readme.replace("| `perimeter` 외곽 | **0** | 219 | 40% |", "| `perimeter` 외곽 | **0** | 221 | 40% |")
wg_readme = wg_readme.replace("| `webserver` 웹서버 | **1** | 392 | 60% |", "| `webserver` 웹서버 | **1** | 400 | 60% |")
wg_readme = wg_readme.replace("| `internal` 내부망 | **2** | 520 | 60% |", "| `internal` 내부망 | **2** | 532 | 60% |")
wg_readme = wg_readme.replace("| `vault` 금고 | **3** | 534 | 58% |", "| `vault` 금고 | **3** | 542 | 58% |")
wg_readme = wg_readme.replace("| `core` 코어 | **4** | 505 | 71% |", "| `core` 코어 | **4** | 510 | 71% |")
wg_readme_path.write_text(wg_readme, encoding="utf-8")
print("Updated wargame/README.md")

# 3. README.md
readme_path = ROOT / "README.md"
rm = readme_path.read_text(encoding="utf-8")
rm = rm.replace("2170 문제", "2205 문제")
rm = rm.replace("터미널_침투·2170 문제", "터미널_침투·2205 문제")
rm = rm.replace("2170", "2205")
readme_path.write_text(rm, encoding="utf-8")
print("Updated README.md")

# 4. README.en.md
rm_en_path = ROOT / "README.en.md"
rm_en = rm_en_path.read_text(encoding="utf-8")
rm_en = rm_en.replace("2170 challenges", "2205 challenges")
rm_en = rm_en.replace("Terminal_Infiltration·2170_Challenges", "Terminal_Infiltration·2205_Challenges")
rm_en = rm_en.replace("2170", "2205")
rm_en_path.write_text(rm_en, encoding="utf-8")
print("Updated README.en.md")

# 5. README.ja.md
rm_ja_path = ROOT / "README.ja.md"
rm_ja = rm_ja_path.read_text(encoding="utf-8")
rm_ja = rm_ja.replace("2170 問", "2205 問")
rm_ja = rm_ja.replace("ターミナル潜入·2170_問", "ターミナル潜入·2205_問")
rm_ja = rm_ja.replace("2170", "2205")
rm_ja_path.write_text(rm_ja, encoding="utf-8")
print("Updated README.ja.md")

# 6. README.zh.md
rm_zh_path = ROOT / "README.zh.md"
rm_zh = rm_zh_path.read_text(encoding="utf-8")
rm_zh = rm_zh.replace("2170 道挑战", "2205 道挑战")
rm_zh = rm_zh.replace("终端渗透·2170_题", "终端渗透·2205_题")
rm_zh = rm_zh.replace("2170", "2205")
rm_zh_path.write_text(rm_zh, encoding="utf-8")
print("Updated README.zh.md")

# 7. USAGE.md
usage_path = ROOT / "USAGE.md"
usage = usage_path.read_text(encoding="utf-8")
usage = usage.replace("2170 문제", "2205 문제")
usage = usage.replace("2170 challenges", "2205 challenges")
usage = usage.replace("2170", "2205")
usage_path.write_text(usage, encoding="utf-8")
print("Updated USAGE.md")

# 8. AI_LEARNING.md
ai_path = ROOT / "AI_LEARNING.md"
ai = ai_path.read_text(encoding="utf-8")
ai = ai.replace("2170 문제", "2205 문제")
ai = ai.replace("2170 challenges", "2205 challenges")
ai = ai.replace("2170 問", "2205 問")
ai = ai.replace("2170 题", "2205 题")
ai = ai.replace("2170", "2205")
ai_path.write_text(ai, encoding="utf-8")
print("Updated AI_LEARNING.md")

# 9. _navbar.md & docs/_sidebar.md & _sidebar.md
for fpath in [ROOT / "_navbar.md", ROOT / "_sidebar.md", ROOT / "docs" / "_sidebar.md"]:
    if fpath.exists():
        c = fpath.read_text(encoding="utf-8")
        c = c.replace("2,170제", "2,205제")
        c = c.replace("2,170", "2,205")
        fpath.write_text(c, encoding="utf-8")
        print(f"Updated {fpath.name}")
