#!/usr/bin/env python3
"""
Sync all enterprise docs to milestone v2.24.0:
- 74 Hands-on Labs (was 73)
- 86 Technical Tracks (was 85)
- 3,010 Wargame Challenges (was 2,975)
- 40 Interactive Web Simulators (was 39)
- Release v2.24.0 (was v2.23.0)
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
    ROOT / "portal" / "static" / "docs" / "index.html",
]

def sync_doc(doc_path: Path):
    if not doc_path.exists():
        print(f"[-] Skip missing {doc_path}")
        return
    text = doc_path.read_text(encoding="utf-8")
    orig = text

    # Version
    text = text.replace("v2.23.0", "v2.24.0")
    text = text.replace("v2_23_0", "v2_24_0")
    text = text.replace("2.23.0", "2.24.0")

    # Wargame count (2975 -> 3010, 2,975 -> 3,010)
    text = text.replace("2,975", "3,010")
    text = text.replace("2975", "3010")

    # Tracks (85 -> 86)
    text = text.replace("85개 트랙", "86개 트랙")
    text = text.replace("85 tracks", "86 tracks")
    text = text.replace("85 specialized tracks", "86 specialized tracks")
    text = text.replace("85개의 전문 트랙", "86개의 전문 트랙")
    text = text.replace("85 전문 트랙", "86 전문 트랙")
    text = text.replace("85トラック", "86トラック")
    text = text.replace("85个专业赛道", "86个专业赛道")
    text = text.replace("85个赛道", "86个赛道")
    text = text.replace("tracks-85", "tracks-86")
    text = text.replace("tracks·85", "tracks·86")

    # Labs (73 -> 74)
    text = text.replace("73개 골든 실습 랩", "74개 골든 실습 랩")
    text = text.replace("73개 랩", "74개 랩")
    text = text.replace("73개 실습 랩", "74개 실습 랩")
    text = text.replace("73 Hands-on Labs", "74 Hands-on Labs")
    text = text.replace("73 hands-on labs", "74 hands-on labs")
    text = text.replace("73 golden labs", "74 golden labs")
    text = text.replace("73 Golden Labs", "74 Golden Labs")
    text = text.replace("73個のハンズオンラボ", "74個のハンズオンラボ")
    text = text.replace("73个实战靶场", "74个实战靶场")
    text = text.replace("labs-73", "labs-74")
    text = text.replace("labs·73", "labs·74")

    # Simulators (39 -> 40)
    text = text.replace("39개 시뮬레이터", "40개 시뮬레이터")
    text = text.replace("39대 시뮬레이터", "40대 시뮬레이터")
    text = text.replace("39대 보안 시뮬레이터", "40대 보안 시뮬레이터")
    text = text.replace("39 Interactive Simulators", "40 Interactive Simulators")
    text = text.replace("39 web simulators", "40 web simulators")
    text = text.replace("39 Web Simulators", "40 Web Simulators")
    text = text.replace("39個のシミュレータ", "40個のシミュレータ")
    text = text.replace("39个仿真器", "40个仿真器")
    text = text.replace("simulators-39", "simulators-40")
    text = text.replace("simulators·39", "simulators·40")

    # Shields badges
    text = re.sub(r'wargame-2975%20challenges', 'wargame-3010%20challenges', text)
    text = re.sub(r'wargame-2975', 'wargame-3010', text)
    text = re.sub(r'challenges-2975', 'challenges-3010', text)
    text = re.sub(r'challenges·2975', 'challenges·3010', text)

    if text != orig:
        doc_path.write_text(text, encoding="utf-8")
        print(f"[+] Updated {doc_path.name}")
    else:
        print(f"[-] No change needed in {doc_path.name}")

def main():
    print("[*] Synchronizing all docs to 3,010 challenges / 74 labs / 86 tracks / 40 simulators / v2.24.0...")
    for doc in TARGET_DOCS:
        sync_doc(doc)
    print("[+] All target docs synchronized.")

if __name__ == "__main__":
    main()
