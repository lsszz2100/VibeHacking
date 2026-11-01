#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 1. wargame/index.html
html_path = ROOT / "wargame" / "index.html"
html = html_path.read_text(encoding="utf-8")
html = html.replace("0/2205", "0/2240")
html_path.write_text(html, encoding="utf-8")
print("Updated wargame/index.html")

# 2. wargame/README.md
wg_readme_path = ROOT / "wargame" / "README.md"
wg_readme = wg_readme_path.read_text(encoding="utf-8")
wg_readme = wg_readme.replace("2205", "2240")
wg_readme = wg_readme.replace("| `perimeter` 외곽 | **0** | 221 | 40% |", "| `perimeter` 외곽 | **0** | 223 | 40% |")
wg_readme = wg_readme.replace("| `webserver` 웹서버 | **1** | 400 | 60% |", "| `webserver` 웹서버 | **1** | 408 | 60% |")
wg_readme = wg_readme.replace("| `internal` 내부망 | **2** | 532 | 60% |", "| `internal` 내부망 | **2** | 544 | 60% |")
wg_readme = wg_readme.replace("| `vault` 금고 | **3** | 542 | 58% |", "| `vault` 금고 | **3** | 550 | 58% |")
wg_readme = wg_readme.replace("| `core` 코어 | **4** | 510 | 71% |", "| `core` 코어 | **4** | 515 | 71% |")

c2tunnel_entry = '| `c2tunnel` 📡 C2 터널링 & 은닉 채널 (5) | 고엔트로피 DNS 청크 분석 파이프라인 · 다중 홉 역방향 프록시 피보팅 전면 차단 · 패킷 간격 분산 분석 지터 비콘 언마스킹 · 인라인 심층 패킷 검사 오케스트레이션 · 전사 은닉 채널 방어 캡스톤 / high-entropy DNS chunk analysis pipeline, multi-hop reverse proxy pivoting containment, inter-arrival variance beacon unmasking, inline deep packet inspection orchestration, and enterprise covert channel defense capstone |'
if '| `c2tunnel`' not in wg_readme:
    wg_readme = wg_readme.replace(
        '| `ebpfruntime` 🐝 eBPF 런타임 보안 (5)',
        c2tunnel_entry + '\n| `ebpfruntime` 🐝 eBPF 런타임 보안 (5)'
    )

if 'eBPF 런타임 보안 & 옵저버빌리티 35' in wg_readme and 'C2 터널링 & 은닉 채널 35' not in wg_readme:
    wg_readme = wg_readme.replace(
        'eBPF 런타임 보안 & 옵저버빌리티 35',
        'eBPF 런타임 보안 & 옵저버빌리티 35 · C2 터널링 & 은닉 채널 35'
    )
if 'eBPF runtime security & observability 35' in wg_readme and 'C2 tunneling & covert channels 35' not in wg_readme:
    wg_readme = wg_readme.replace(
        'eBPF runtime security & observability 35',
        'eBPF runtime security & observability 35 · C2 tunneling & covert channels 35'
    )
elif 'AI agent & MCP tool security 35);' in wg_readme:
    wg_readme = wg_readme.replace(
        'AI agent & MCP tool security 35);',
        'AI agent & MCP tool security 35 · SANS DFIR artifact hunting 35 · eBPF runtime security 35 · C2 tunneling & covert channels 35);'
    )

wg_readme_path.write_text(wg_readme, encoding="utf-8")
print("Updated wargame/README.md")

# 3. README.md
readme_path = ROOT / "README.md"
rm = readme_path.read_text(encoding="utf-8")
rm = rm.replace("2205 문제", "2240 문제")
rm = rm.replace("터미널_침투·2205 문제", "터미널_침투·2240 문제")
rm = rm.replace("2,205문제", "2,240문제")
rm = rm.replace("2,205", "2,240")
rm = rm.replace("2205", "2240")
readme_path.write_text(rm, encoding="utf-8")
print("Updated README.md")

# 4. README.en.md
rm_en_path = ROOT / "README.en.md"
rm_en = rm_en_path.read_text(encoding="utf-8")
rm_en = rm_en.replace("2205 challenges", "2240 challenges")
rm_en = rm_en.replace("Terminal_Infiltration·2205_Challenges", "Terminal_Infiltration·2240_Challenges")
rm_en = rm_en.replace("2,205 challenges", "2,240 challenges")
rm_en = rm_en.replace("2,205", "2,240")
rm_en = rm_en.replace("2205", "2240")
rm_en_path.write_text(rm_en, encoding="utf-8")
print("Updated README.en.md")

# 5. README.ja.md
rm_ja_path = ROOT / "README.ja.md"
rm_ja = rm_ja_path.read_text(encoding="utf-8")
rm_ja = rm_ja.replace("2205 問", "2240 問")
rm_ja = rm_ja.replace("ターミナル潜入·2205_問", "ターミナル潜入·2240_問")
rm_ja = rm_ja.replace("2,205", "2,240")
rm_ja = rm_ja.replace("2205", "2240")
rm_ja_path.write_text(rm_ja, encoding="utf-8")
print("Updated README.ja.md")

# 6. README.zh.md
rm_zh_path = ROOT / "README.zh.md"
rm_zh = rm_zh_path.read_text(encoding="utf-8")
rm_zh = rm_zh.replace("2205 道挑战", "2240 道挑战")
rm_zh = rm_zh.replace("终端渗透·2205_题", "终端渗透·2240_题")
rm_zh = rm_zh.replace("2,205", "2,240")
rm_zh = rm_zh.replace("2205", "2240")
rm_zh_path.write_text(rm_zh, encoding="utf-8")
print("Updated README.zh.md")

# 7. USAGE.md
usage_path = ROOT / "USAGE.md"
usage = usage_path.read_text(encoding="utf-8")
usage = usage.replace("2205 문제", "2240 문제")
usage = usage.replace("2205 challenges", "2240 challenges")
usage = usage.replace("2,205", "2,240")
usage = usage.replace("2205", "2240")
usage_path.write_text(usage, encoding="utf-8")
print("Updated USAGE.md")

# 8. AI_LEARNING.md
ai_path = ROOT / "AI_LEARNING.md"
ai = ai_path.read_text(encoding="utf-8")
ai = ai.replace("2205 문제", "2240 문제")
ai = ai.replace("2205 challenges", "2240 challenges")
ai = ai.replace("2205 問", "2240 問")
ai = ai.replace("2205 题", "2240 题")
ai = ai.replace("2,205", "2,240")
ai = ai.replace("2205", "2240")
ai_path.write_text(ai, encoding="utf-8")
print("Updated AI_LEARNING.md")

# 9. _navbar.md & docs/_sidebar.md & _sidebar.md
for fpath in [ROOT / "_navbar.md", ROOT / "_sidebar.md", ROOT / "docs" / "_sidebar.md"]:
    if fpath.exists():
        c = fpath.read_text(encoding="utf-8")
        c = c.replace("2,205제", "2,240제")
        c = c.replace("2,205", "2,240")
        fpath.write_text(c, encoding="utf-8")
        print(f"Updated {fpath.name}")
