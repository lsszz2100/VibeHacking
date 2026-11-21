#!/usr/bin/env python3
"""
Sync all enterprise docs to milestone v2.25.0:
- 75 Hands-on Labs (was 74)
- 87 Technical Tracks (was 86)
- 3,045 Wargame Challenges (was 3,010)
- 41 Interactive Web Simulators (was 40)
- Release v2.25.0 (was v2.24.0)
"""

import re
from pathlib import Path

ROOT = Path("/mnt/d/바이브해킹 자료/vibe-hacking")

TARGET_DOCS = [
    ROOT / "README.md",
    ROOT / "README.en.md",
    ROOT / "README.ja.md",
    ROOT / "README.zh.md",
    ROOT / "USAGE.md",
    ROOT / "AI_LEARNING.md",
    ROOT / "portal" / "static" / "index.html",
]

def sync_doc(doc_path: Path):
    if not doc_path.exists():
        print(f"[-] Skip missing {doc_path}")
        return
    text = doc_path.read_text(encoding="utf-8")
    orig = text

    # Version
    text = text.replace("v2.24.0", "v2.25.0")
    text = text.replace("v2_24_0", "v2_25_0")
    text = text.replace("2.24.0", "2.25.0")

    # Wargame count (3010 -> 3045, 3,010 -> 3,045)
    text = text.replace("3,010", "3,045")
    text = text.replace("3010", "3045")

    # Tracks (86 -> 87)
    text = text.replace("86개 트랙", "87개 트랙")
    text = text.replace("86 tracks", "87 tracks")
    text = text.replace("86 specialized tracks", "87 specialized tracks")
    text = text.replace("86개의 전문 트랙", "87개의 전문 트랙")
    text = text.replace("86 전문 트랙", "87 전문 트랙")
    text = text.replace("86トラック", "87トラック")
    text = text.replace("86个专业赛道", "87个专业赛道")
    text = text.replace("86个赛道", "87个赛道")
    text = text.replace("tracks-86", "tracks-87")
    text = text.replace("tracks·86", "tracks·87")

    # Labs (74 -> 75)
    text = text.replace("74개 골든 실습 랩", "75개 골든 실습 랩")
    text = text.replace("74개 랩", "75개 랩")
    text = text.replace("74개 실습 랩", "75개 실습 랩")
    text = text.replace("74 Hands-on Labs", "75 Hands-on Labs")
    text = text.replace("74 hands-on labs", "75 hands-on labs")
    text = text.replace("74 golden labs", "75 golden labs")
    text = text.replace("74 Golden Labs", "75 Golden Labs")
    text = text.replace("74個のハンズオンラボ", "75個のハンズオンラボ")
    text = text.replace("74个实战靶场", "75个实战靶场")
    text = text.replace("labs-74", "labs-75")
    text = text.replace("labs·74", "labs·75")

    # Simulators (40 -> 41)
    text = text.replace("40개 시뮬레이터", "41개 시뮬레이터")
    text = text.replace("40대 시뮬레이터", "41대 시뮬레이터")
    text = text.replace("40대 보안 시뮬레이터", "41대 보안 시뮬레이터")
    text = text.replace("40 Interactive Simulators", "41 Interactive Simulators")
    text = text.replace("40 web simulators", "41 web simulators")
    text = text.replace("40 Web Simulators", "41 Web Simulators")
    text = text.replace("40個のシミュレータ", "41個のシミュレータ")
    text = text.replace("40个仿真器", "41个仿真器")
    text = text.replace("simulators-40", "simulators-41")
    text = text.replace("simulators·40", "simulators·41")

    # Shields badges
    text = re.sub(r'wargame-3010%20challenges', 'wargame-3045%20challenges', text)
    text = re.sub(r'wargame-3010', 'wargame-3045', text)
    text = re.sub(r'challenges-3010', 'challenges-3045', text)
    text = re.sub(r'challenges·3010', 'challenges·3045', text)

    if text != orig:
        doc_path.write_text(text, encoding="utf-8")
        print(f"[+] Updated {doc_path.name}")
    else:
        print(f"[-] No change needed in {doc_path.name}")

def main():
    print("[*] Synchronizing all docs to 3,045 challenges / 75 labs / 87 tracks / 41 simulators / v2.25.0...")
    for doc in TARGET_DOCS:
        sync_doc(doc)
    print("[+] All target docs synchronized.")

if __name__ == "__main__":
    main()
