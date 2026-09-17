#!/usr/bin/env python3
"""
tools/sync_section_readmes.py
75개 전 섹션의 README.md 디렉토리 인덱스 자동 생성 및 동기화 스크립트.
"""

from __future__ import annotations
import os
import re
import sys
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))
from vhack import SECTIONS, LABS

def clean_text(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    text = text.replace("**", "").replace("`", "").strip()
    return text

def parse_file_info(filepath: Path) -> tuple[str, str]:
    """마크다운 파일에서 제목과 핵심 설명을 추출한다."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    title = ""
    for line in lines[:35]:
        ls = line.strip()
        if ls.startswith("# ") and not ls.startswith("# 0."):
            t = ls[2:].strip()
            t = re.sub(r"^[0-9]+[._\s\-]*", "", t)
            title = clean_text(t)
            break

    summary = ""
    # Look for explanation in sections
    for i, line in enumerate(lines[:90]):
        ls = line.strip()
        if ls.startswith("### ") or ls.startswith("## 0.") or ls.startswith("## "):
            for next_l in lines[i+1:i+15]:
                nl = next_l.strip()
                if nl and not nl.startswith(("#", "```", ">", "-", "*", "|", "<")):
                    summary = clean_text(nl)
                    break
            if summary:
                break

    if not summary:
        for line in lines[:60]:
            ls = line.strip()
            if ls and not ls.startswith(("#", "```", ">", "|", "-", "*", "<")) and len(ls) > 20:
                summary = clean_text(ls)
                break

    if not title:
        title = filepath.stem.replace("_", " ").title()
    if not summary:
        summary = f"{title} 심화 학습 및 실습"

    if len(summary) > 105:
        summary = summary[:102] + "..."

    return title, summary

def main():
    sec_to_labs: dict[int, list[tuple[str, str]]] = {}
    for lab_id, lab_info in LABS.items():
        for s_num in lab_info.get("related", []):
            sec_to_labs.setdefault(s_num, []).append((lab_id, lab_info["name"]))

    section_dirs = sorted([d for d in REPO_ROOT.iterdir() if d.is_dir() and d.name[:2].isdigit()])

    created_count = 0
    updated_count = 0
    skipped_count = 0

    for s_dir in section_dirs:
        sec_num = int(s_dir.name[:2])
        meta = SECTIONS.get(sec_num, {"name": s_dir.name[3:], "ko": s_dir.name[3:], "emoji": "📁"})
        
        md_files = sorted([f for f in s_dir.glob("*.md") if f.name != "README.md"])
        if not md_files:
            continue

        file_infos = [(f.name, *parse_file_info(f)) for f in md_files]
        readme_path = s_dir / "README.md"

        if not readme_path.exists():
            # 새 README.md 생성
            lines = [
                f"# {sec_num:02d}. {meta['ko']} ({meta['name']})",
                "",
                f"> {meta['emoji']} **VibeHacking 교재 섹션 {sec_num:02d}**",
                f"> - **CLI 학습**: `python3 vhack.py study {sec_num}`",
            ]

            if sec_num in sec_to_labs:
                lab_links = ", ".join([f"[Lab {lid}: {lname}](../labs/)" for lid, lname in sec_to_labs[sec_num]])
                lines.append(f"> - **연계 실습 랩**: {lab_links}")

            lines.extend([
                "",
                "## 📚 목차",
                "",
                "| 파일 | 제목 / 핵심 내용 |",
                "|:-----|:-----------------|",
            ])

            for fname, title, summary in file_infos:
                lines.append(f"| [{fname}](./{fname}) | **{title}** — {summary} |")

            lines.extend([
                "",
                "## 🎯 학습 목표",
                "",
            ])
            for _, title, _ in file_infos[:4]:
                lines.append(f"- {title} 원리 및 실전 공격/방어 기법 습득")
            lines.append("- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화")

            lines.extend([
                "",
                "## 💡 실습 및 연계 학습",
                "",
                f"- 터미널에서 전체 내용 읽기: `python3 vhack.py study {sec_num} 1`",
                "- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이",
                "",
            ])

            readme_path.write_text("\n".join(lines), encoding="utf-8")
            created_count += 1
            print(f"[+] Created README.md for Section {sec_num:02d} ({meta['ko']})")
        else:
            # 기존 README.md에 누락된 파일이 있는지 확인
            existing_content = readme_path.read_text(encoding="utf-8")
            missing_files = [f for f in md_files if f.name not in existing_content]

            if missing_files:
                # 테이블 끝에 누락된 파일 행 추가
                table_additions = []
                for fname, title, summary in file_infos:
                    if fname in [mf.name for mf in missing_files]:
                        table_additions.append(f"| [{fname}](./{fname}) | **{title}** — {summary} |")

                # 목차 테이블 위치 탐색
                lines = existing_content.splitlines()
                table_idx = -1
                for idx, l in enumerate(lines):
                    if l.startswith("|") and ("---" in l or ":---" in l):
                        table_idx = idx
                        break

                if table_idx != -1:
                    # Find end of table
                    end_idx = table_idx + 1
                    while end_idx < len(lines) and lines[end_idx].strip().startswith("|"):
                        end_idx += 1
                    for add_line in table_additions:
                        lines.insert(end_idx, add_line)
                        end_idx += 1
                    readme_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    updated_count += 1
                    print(f"[*] Updated README.md for Section {sec_num:02d} (added {len(missing_files)} files)")
                else:
                    skipped_count += 1
            else:
                skipped_count += 1

    print(f"\nDone: Created {created_count}, Updated {updated_count}, Up-to-date {skipped_count}")

if __name__ == "__main__":
    main()
