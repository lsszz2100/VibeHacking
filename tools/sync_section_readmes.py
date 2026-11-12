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
            # Remove "제NN장 ... : " prefix if present
            t = re.sub(r"^제\s*\d+\s*장\s*[^:]*:\s*", "", t)
            t = re.sub(r"^[0-9]+[._\s\-]*", "", t)
            title = clean_text(t)
            break

    summary = ""
    in_code = False
    skip_section = False
    candidate_lines = []

    for line in lines[:150]:
        ls = line.strip()
        if ls.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue

        if ls.startswith("## ") or ls.startswith("### "):
            header_title = ls.lstrip("#").strip().lower()
            if any(k in header_title for k in ["실습 환경", "준비", "환경 구축", "사전 요구", "prerequisite", "setup", "lab setup"]):
                skip_section = True
            else:
                skip_section = False
            continue

        if skip_section:
            continue

        if ls.startswith(("#", ">", "<", "|", "- [ ]", "1.", "2.", "3.", "4.", "5.")):
            continue

        if any(cmd in ls for cmd in ["pip install", "docker run", "docker pull", "sudo apt", "npm i", "npm install", "git clone"]):
            continue

        cl = clean_text(ls)
        if len(cl) > 20 and not cl.startswith(("$", "#", "http://", "https://")):
            candidate_lines.append(cl)

    if candidate_lines:
        summary = candidate_lines[0]

    if not title:
        title = filepath.stem.replace("_", " ").title()
    if not summary:
        summary = f"{title} 원리 및 실전 공격/방어 기법"

    if len(summary) > 95:
        summary = summary[:92] + "..."

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
            # 기존 README.md 확인 및 코드 누출/누락 파일 수정
            existing_content = readme_path.read_text(encoding="utf-8")
            lines = existing_content.splitlines()
            file_map = {fname: (title, summary) for fname, title, summary in file_infos}
            
            modified = False
            # 1. 기존 테이블 행 중 코드가 들어간 행이나 잘못된 행 감지 및 교체
            new_lines = []
            table_found = False
            for line in lines:
                m = re.match(r"^\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|\s*(.*)$", line)
                if m:
                    fname = m.group(1).strip()
                    desc = m.group(3).strip()
                    if fname in file_map:
                        # 설명 부분에 설치 명령어/코드가 들어있는지 확인
                        has_code_leak = any(cmd in desc for cmd in [
                            "pip install", "docker run", "docker pull", "sudo apt", "npm i", "git clone"
                        ])
                        if has_code_leak:
                            t, s = file_map[fname]
                            new_line = f"| [{fname}](./{fname}) | **{t}** — {s} |"
                            new_lines.append(new_line)
                            modified = True
                            continue
                new_lines.append(line)
            lines = new_lines

            # 2. 누락된 파일 추가
            current_text = "\n".join(lines)
            missing_files = [f for f in md_files if f.name not in current_text]
            if missing_files:
                table_additions = []
                for fname, title, summary in file_infos:
                    if fname in [mf.name for mf in missing_files]:
                        table_additions.append(f"| [{fname}](./{fname}) | **{title}** — {summary} |")

                table_idx = -1
                for idx, l in enumerate(lines):
                    if l.startswith("|") and ("---" in l or ":---" in l):
                        table_idx = idx
                        break

                if table_idx != -1:
                    end_idx = table_idx + 1
                    while end_idx < len(lines) and lines[end_idx].strip().startswith("|"):
                        end_idx += 1
                    for add_line in table_additions:
                        lines.insert(end_idx, add_line)
                        end_idx += 1
                    modified = True

            if modified:
                readme_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                updated_count += 1
                print(f"[*] Updated README.md for Section {sec_num:02d} ({meta['ko']})")
            else:
                skipped_count += 1

    print(f"\nDone: Created {created_count}, Updated {updated_count}, Up-to-date {skipped_count}")

if __name__ == "__main__":
    main()
