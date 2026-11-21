#!/usr/bin/env python3
"""
Sync all documentation files to v2.22.0:
- 72 Labs, 84 Tracks, 2,940 Challenges, 38 Simulators
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def main():
    # 1. Update wargame/README.md
    wg_readme = REPO_ROOT / "wargame" / "README.md"
    txt = wg_readme.read_text(encoding="utf-8")
    txt = txt.replace("총 **2905문제**", "총 **2940문제**")
    txt = txt.replace("총 **2905 문제**", "총 **2940 문제**")
    txt = txt.replace("Total **2905 challenges**", "Total **2940 challenges**")
    txt = txt.replace("83개 섹션 주제", "84개 섹션 주제")
    txt = txt.replace("83 tracks", "84 tracks")
    txt = txt.replace("83개 트랙", "84개 트랙")
    
    # Tier table counts
    txt = txt.replace("| `perimeter` 외곽 | **0** | 336 |", "| `perimeter` 외곽 | **0** | 343 |")
    txt = txt.replace("| `webserver` 웹서버 | **1** | 545 |", "| `webserver` 웹서버 | **1** | 552 |")
    txt = txt.replace("| `internal` 내부망 | **2** | 697 |", "| `internal` 내부망 | **2** | 704 |")
    txt = txt.replace("| `vault` 금고 | **3** | 687 |", "| `vault` 금고 | **3** | 694 |")
    txt = txt.replace("| `core` 코어 | **4** | 640 |", "| `core` 코어 | **4** | 647 |")
    
    # Add track in the list of categories in line 531 & 533
    if "AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 35" not in txt:
        txt = txt.replace(
            "AI 가속기 GPU 사이드채널 & VRAM 격리 방어 35)",
            "AI 가속기 GPU 사이드채널 & VRAM 격리 방어 35 · AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 35)"
        )
    if "agent long-term memory & knowledge graph defense 35" not in txt:
        txt = txt.replace(
            "hardware GPU acceleration sidechannel & VRAM isolation defense 35)",
            "hardware GPU acceleration sidechannel & VRAM isolation defense 35 · agent long-term memory & knowledge graph defense 35)"
        )
    
    wg_readme.write_text(txt, encoding="utf-8")
    print("[+] Updated wargame/README.md")

    # 2. Update README.md, README.en.md, README.ja.md, README.zh.md
    for lang, fname in [
        ("ko", "README.md"),
        ("en", "README.en.md"),
        ("ja", "README.ja.md"),
        ("zh", "README.zh.md"),
    ]:
        fpath = REPO_ROOT / fname
        if not fpath.exists():
            continue
        c = fpath.read_text(encoding="utf-8")
        c = re.sub(r'2905_문제', '2940_문제', c)
        c = re.sub(r'2905\s*문제를', '2940 문제를', c)
        c = re.sub(r'terminal_infiltration·2905', 'terminal_infiltration·2940', c)
        c = re.sub(r'challenges-2905-', 'challenges-2940-', c)
        c = re.sub(r'challenges-2905\b', 'challenges-2940', c)
        c = re.sub(r'\b2905\s*문제\b', '2940 문제', c)
        c = re.sub(r'\b2905\s*challenges\b', '2940 challenges', c)
        c = re.sub(r'2905\s*問', '2940 問', c)
        c = re.sub(r'\b2905\s*道挑战\b', '2940 道挑战', c)
        c = re.sub(r'\b71\s*개\s*골든\s*실습\s*랩\b', '72개 골든 실습 랩', c)
        c = re.sub(r'\b71\s*Hands-on\s*Labs\b', '72 Hands-on Labs', c)
        c = re.sub(r'\b71\s*개\s*실습\s*랩\b', '72개 실습 랩', c)
        c = re.sub(r'\b83\s*개\s*기술\s*트랙\b', '84개 기술 트랙', c)
        c = re.sub(r'\b83\s*Technical\s*Tracks\b', '84 Technical Tracks', c)
        c = re.sub(r'\b83\s*개\s*트랙\b', '84개 트랙', c)
        c = re.sub(r'\b83\s*tracks\b', '84 tracks', c)
        c = re.sub(r'83\s*个赛道', '84 个赛道', c)
        c = re.sub(r'79\s*トラック', '84 トラック', c)
        c = re.sub(r'\b37\s*대\s*보안\s*시뮬레이터\b', '38대 보안 시뮬레이터', c)
        c = re.sub(r'\b37\s*Interactive\s*Simulators\b', '38 Interactive Simulators', c)
        c = re.sub(r'\bv2\.21\.0\b', 'v2.22.0', c)
        fpath.write_text(c, encoding="utf-8")
        print(f"[+] Updated {fname}")

    # 3. Update USAGE.md
    usage_path = REPO_ROOT / "USAGE.md"
    if usage_path.exists():
        u = usage_path.read_text(encoding="utf-8")
        u = re.sub(r'\b2905\s*문제\b', '2940 문제', u)
        u = re.sub(r'\b2905\s*challenges\b', '2940 challenges', u)
        u = re.sub(r'\b71\s*개\s*랩\b', '72개 랩', u)
        u = re.sub(r'\b83\s*개\s*트랙\b', '84개 트랙', u)
        u = re.sub(r'\b37\s*개\s*시뮬레이터\b', '38개 시뮬레이터', u)
        u = re.sub(r'\bv2\.21\.0\b', 'v2.22.0', u)
        usage_path.write_text(u, encoding="utf-8")
        print("[+] Updated USAGE.md")

    # 4. Update AI_LEARNING.md
    ai_learn_path = REPO_ROOT / "AI_LEARNING.md"
    if ai_learn_path.exists():
        al = ai_learn_path.read_text(encoding="utf-8")
        al = re.sub(r'\b2905\s*문제\b', '2940 문제', al)
        al = re.sub(r'\b2905\s*challenges\b', '2940 challenges', al)
        al = re.sub(r'2905\s*問', '2940 問', al)
        al = re.sub(r'2905\s*题', '2940 题', al)
        al = re.sub(r'\b71\s*개\s*랩\b', '72개 랩', al)
        al = re.sub(r'\b83\s*개\s*트랙\b', '84개 트랙', al)
        al = re.sub(r'\bv2\.21\.0\b', 'v2.22.0', al)
        ai_learn_path.write_text(al, encoding="utf-8")
        print("[+] Updated AI_LEARNING.md")

if __name__ == "__main__":
    main()
