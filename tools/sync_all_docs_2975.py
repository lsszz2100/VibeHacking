#!/usr/bin/env python3
"""
Sync all documentation files to v2.23.0:
- 73 Labs, 85 Tracks, 2,975 Challenges, 39 Simulators
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def main():
    # 1. Update wargame/README.md
    wg_readme = REPO_ROOT / "wargame" / "README.md"
    txt = wg_readme.read_text(encoding="utf-8")
    txt = txt.replace("총 **2940문제**", "총 **2975문제**")
    txt = txt.replace("총 **2940 문제**", "총 **2975 문제**")
    txt = txt.replace("Total **2940 challenges**", "Total **2975 challenges**")
    txt = txt.replace("84개 섹션 주제", "85개 섹션 주제")
    txt = txt.replace("84 tracks", "85 tracks")
    txt = txt.replace("84개 트랙", "85개 트랙")
    
    # Tier table counts
    txt = txt.replace("| `perimeter` 외곽 | **0** | 343 |", "| `perimeter` 외곽 | **0** | 350 |")
    txt = txt.replace("| `webserver` 웹서버 | **1** | 552 |", "| `webserver` 웹서버 | **1** | 559 |")
    txt = txt.replace("| `internal` 내부망 | **2** | 704 |", "| `internal` 내부망 | **2** | 711 |")
    txt = txt.replace("| `vault` 금고 | **3** | 694 |", "| `vault` 금고 | **3** | 701 |")
    txt = txt.replace("| `core` 코어 | **4** | 647 |", "| `core` 코어 | **4** | 654 |")
    
    # Add track in the list of categories in line 536 & 538
    if "실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어 35" not in txt:
        txt = txt.replace(
            "AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 35)",
            "AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 35 · 실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어 35)"
        )
    if "silicon photonics optical interconnect & QKD mesh defense 35" not in txt:
        txt = txt.replace(
            "agent long-term memory & knowledge graph defense 35)",
            "agent long-term memory & knowledge graph defense 35 · silicon photonics optical interconnect & QKD mesh defense 35)"
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
        c = re.sub(r'2940_문제', '2975_문제', c)
        c = re.sub(r'2940\s*문제를', '2975 문제를', c)
        c = re.sub(r'terminal_infiltration·2940', 'terminal_infiltration·2975', c)
        c = re.sub(r'challenges-2940-', 'challenges-2975-', c)
        c = re.sub(r'challenges-2940\b', 'challenges-2975', c)
        c = re.sub(r'\b2940\s*문제\b', '2975 문제', c)
        c = re.sub(r'\b2940\s*challenges\b', '2975 challenges', c)
        c = re.sub(r'2940\s*問', '2975 問', c)
        c = re.sub(r'\b2940\s*道挑战\b', '2975 道挑战', c)
        c = re.sub(r'\b72\s*개\s*골든\s*실습\s*랩\b', '73개 골든 실습 랩', c)
        c = re.sub(r'\b72\s*Hands-on\s*Labs\b', '73 Hands-on Labs', c)
        c = re.sub(r'\b72\s*개\s*실습\s*랩\b', '73개 실습 랩', c)
        c = re.sub(r'\b84\s*개\s*기술\s*트랙\b', '85개 기술 트랙', c)
        c = re.sub(r'\b84\s*Technical\s*Tracks\b', '85 Technical Tracks', c)
        c = re.sub(r'\b84\s*개\s*트랙\b', '85개 트랙', c)
        c = re.sub(r'\b84\s*tracks\b', '85 tracks', c)
        c = re.sub(r'84\s*个赛道', '85 个赛道', c)
        c = re.sub(r'84\s*トラック', '85 トラック', c)
        c = re.sub(r'\b38\s*대\s*보안\s*시뮬레이터\b', '39대 보안 시뮬레이터', c)
        c = re.sub(r'\b38\s*Interactive\s*Simulators\b', '39 Interactive Simulators', c)
        c = re.sub(r'\bv2\.22\.0\b', 'v2.23.0', c)
        fpath.write_text(c, encoding="utf-8")
        print(f"[+] Updated {fname}")

    # 3. Update USAGE.md
    usage_path = REPO_ROOT / "USAGE.md"
    if usage_path.exists():
        u = usage_path.read_text(encoding="utf-8")
        u = re.sub(r'\b2940\s*문제\b', '2975 문제', u)
        u = re.sub(r'\b2940\s*challenges\b', '2975 challenges', u)
        u = re.sub(r'\b72\s*개\s*랩\b', '73개 랩', u)
        u = re.sub(r'\b84\s*개\s*트랙\b', '85개 트랙', u)
        u = re.sub(r'\b38\s*개\s*시뮬레이터\b', '39개 시뮬레이터', u)
        u = re.sub(r'\bv2\.22\.0\b', 'v2.23.0', u)
        usage_path.write_text(u, encoding="utf-8")
        print("[+] Updated USAGE.md")

    # 4. Update AI_LEARNING.md
    ai_learn_path = REPO_ROOT / "AI_LEARNING.md"
    if ai_learn_path.exists():
        al = ai_learn_path.read_text(encoding="utf-8")
        al = re.sub(r'\b2940\s*문제\b', '2975 문제', al)
        al = re.sub(r'\b2940\s*challenges\b', '2975 challenges', al)
        al = re.sub(r'2940\s*問', '2975 問', al)
        al = re.sub(r'2940\s*题', '2975 题', al)
        al = re.sub(r'\b72\s*개\s*랩\b', '73개 랩', al)
        al = re.sub(r'\b84\s*개\s*트랙\b', '85개 트랙', al)
        al = re.sub(r'\bv2\.22\.0\b', 'v2.23.0', al)
        ai_learn_path.write_text(al, encoding="utf-8")
        print("[+] Updated AI_LEARNING.md")

    # 5. Update launch assets
    ph_brief = REPO_ROOT / "launch" / "producthunt" / "launch_brief.md"
    if ph_brief.exists():
        pht = ph_brief.read_text(encoding="utf-8")
        pht = re.sub(r'\b2940\b', '2975', pht)
        pht = re.sub(r'\b2,940\b', '2,975', pht)
        pht = re.sub(r'\b72\b', '73', pht)
        pht = re.sub(r'\b84\b', '85', pht)
        pht = re.sub(r'\b38\b', '39', pht)
        pht = re.sub(r'\bv2\.22\.0\b', 'v2.23.0', pht)
        ph_brief.write_text(pht, encoding="utf-8")
        print("[+] Updated launch/producthunt/launch_brief.md")

    reddit_post = REPO_ROOT / "launch" / "reddit" / "reddit_post.md"
    if reddit_post.exists():
        rdt = reddit_post.read_text(encoding="utf-8")
        rdt = re.sub(r'\b2940\b', '2975', rdt)
        rdt = re.sub(r'\b2,940\b', '2,975', rdt)
        rdt = re.sub(r'\b72\b', '73', rdt)
        rdt = re.sub(r'\b84\b', '85', rdt)
        rdt = re.sub(r'\b38\b', '39', rdt)
        rdt = re.sub(r'\bv2\.22\.0\b', 'v2.23.0', rdt)
        reddit_post.write_text(rdt, encoding="utf-8")
        print("[+] Updated launch/reddit/reddit_post.md")

if __name__ == "__main__":
    main()
