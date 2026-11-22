#!/usr/bin/env python3
"""
tools/book_builder.py — VibeHacking e-Book / PDF Publication Compiler
75개 섹션 / 492개 챕터 마크다운 교재를 하나의 완결된 단행본(e-Book / Master Markdown / Standalone HTML)으로 자동 컴파일합니다.

사용법:
    python3 tools/book_builder.py --sample         # 샘플 에디션 빌드 (기초 3개 섹션)
    python3 tools/book_builder.py --full           # 전체 75개 섹션 마스터 e-Book 빌드
    python3 tools/book_builder.py --sections 1,2,5 # 특정 섹션 지정 빌드
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "build" / "books"

VERSION = "v2.27.0"
TITLE = "VibeHacking: 실전 사이버보안 완전 정복 바이블"
SUBTITLE = "75개 섹션 · 77개 핸즈온 랩 · 89개 트랙 3,115제 워게임 통합 마스터 교재"
AUTHOR = "VibeHacking Research Lab & lsszz2100"

def get_section_dirs() -> list[tuple[int, Path]]:
    """01_... ~ 75_... 디렉토리를 번호순으로 수집합니다."""
    sections = []
    for entry in REPO_ROOT.iterdir():
        if entry.is_dir():
            m = re.match(r"^(\d{2})_(.+)$", entry.name)
            if m:
                sec_num = int(m.group(1))
                sections.append((sec_num, entry))
    sections.sort(key=lambda x: x[0])
    return sections

def get_chapter_files(sec_dir: Path) -> list[Path]:
    """한 섹션 내부의 챕터 마크다운 파일들을 번호순으로 수집합니다."""
    ch_files = []
    for f in sec_dir.iterdir():
        if f.is_file() and f.suffix == ".md" and f.name.lower() != "readme.md":
            ch_files.append(f)
    ch_files.sort(key=lambda p: p.name)
    return ch_files

def extract_chapter_title(md_path: Path) -> str:
    """마크다운 파일의 첫 번째 H1(# ) 제목을 추출합니다."""
    try:
        with open(md_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_s = line.strip()
                if line_s.startswith("# "):
                    return line_s[2:].strip()
    except Exception:
        pass
    return md_path.stem.replace("_", " ").title()

def build_cover_markdown(sample_mode: bool) -> str:
    """단행본 표지 및 서지 정보를 마크다운으로 생성합니다."""
    now_str = datetime.now().strftime("%Y-%m-%d")
    edition_label = "샘플 프리뷰 에디션 (Sample Preview Edition)" if sample_mode else "정식 마스터 통합본 (Full Master Edition)"
    
    return f"""# {TITLE}
## {SUBTITLE}

<div style="text-align: center; margin: 40px 0; border: 2px solid #00f0ff; padding: 25px; border-radius: 8px; background: #0d1117; color: #c9d1d9;">
  <h2 style="color: #00f0ff; margin-top: 0;">OFFICIAL CURRICULUM MANUAL & E-BOOK</h2>
  <p><strong>버전:</strong> {VERSION} | <strong>발행일:</strong> {now_str}</p>
  <p><strong>에디션:</strong> {edition_label}</p>
  <p><strong>저자 및 편찬:</strong> {AUTHOR}</p>
  <p><strong>라이선스:</strong> Open Source (Community) & B2B Commercial Enterprise (<a href="https://github.com/lsszz2100/VibeHacking">GitHub</a>)</p>
</div>

---

### 서문 (Abstract & Manifesto)

현대 사이버 위협 환경은 전통적인 네트워크·시스템 경계 침투를 넘어, **클라우드 네이티브 컨테이너 탈출**, **EDR 커널 텔레메트리 우회**, **AI 에이전트 장기 메모리 오염(Prompt/RAG Poisoning)**, **포스트 양자 암호(PQC) 전이**, **실리콘 포토닉스/QKD 광 인터커넥트**, 그리고 **저궤도 위성 광통신(SatCom Laser QKD)**에 이르는 다차원 복합 전장으로 진화했습니다.

본 교재는 단순한 이론 나열을 단호히 거부하며, **모든 보안 개념을 '공격 원리(Offensive Exploitation)'와 '방어 메커니즘(Defensive Remediation)'의 상호작용**으로 설명합니다.

- **75개 심층 이론/실무 섹션** (총 492개 실전 보안 챕터)
- **77개 프로덕션급 격리 실습 환경** (`labs/01` ~ `labs/77`, 127.0.0.1 로컬 바인딩 격리)
- **89개 세부 트랙 / 3,115개 브라우저 터미널 워게임** (검증 게이트 100% 무결점 통과)
- **43대 대화형 아키텍처 시뮬레이터** (노코드/로우코드 시각화 실습)
- **Agent-Eval 2.0 프론티어 AI 모델 보안 역량 벤치마크 엔진** 탑재

<div style="page-break-after: always;"></div>

"""

def build_toc_markdown(sections_to_build: list[tuple[int, Path, list[Path]]]) -> str:
    """전체 목차(TOC)를 생성합니다."""
    toc_lines = ["## 📚 전체 목차 (Table of Contents)\n\n"]
    for sec_num, sec_dir, ch_files in sections_to_build:
        sec_name = sec_dir.name
        toc_lines.append(f"### [섹션 {sec_num:02d}: {sec_name}](#sec-{sec_num:02d})\n")
        for idx, ch in enumerate(ch_files, 1):
            title = extract_chapter_title(ch)
            anchor = f"ch-{sec_num:02d}-{idx:02d}"
            toc_lines.append(f"- [{idx:02d}. {title}](#{anchor})\n")
        toc_lines.append("\n")
    toc_lines.append('<div style="page-break-after: always;"></div>\n\n')
    return "".join(toc_lines)

def build_enterprise_appendix() -> str:
    """부록: 엔터프라이즈 B2B 도입 가이드 및 윤리 지침을 생성합니다."""
    comm_path = REPO_ROOT / "COMMERCIAL.md"
    comm_content = ""
    if comm_path.exists():
        try:
            with open(comm_path, "r", encoding="utf-8") as f:
                comm_content = f.read()
        except Exception:
            pass

    return f"""

<div style="page-break-after: always;"></div>

# 부록: 엔터프라이즈 B2B 안내 및 법적 윤리 준칙

{comm_content}

---

## 법적 면책 조항 및 윤리 준칙 (Disclaimer & Ethics)
1. 본 교재에 수록된 모든 공격 기법, 익스플로잇 코드 및 분석 절차는 **오직 방어 역량 강화, 취약점 패치 및 사전 보안 점검**을 목적으로 작성되었습니다.
2. 사전 서면 인가(Written Authorization)를 받지 않은 타인의 정보통신망, 서버, 클라우드 자산 및 AI 모델에 대한 침투 시도는 정보통신망법 및 각국 형법에 의해 엄격히 처벌받습니다.
3. 실습 시 반드시 본 교재에서 제공하는 Docker 로컬 격리 환경(`127.0.0.1`) 및 승인된 워게임 터미널만을 사용하여 주십시오.
"""

def compile_markdown_chunks_to_html(chunks: list[str], title: str) -> str:
    """마크다운 청크들을 순차 변환하여 고성능으로 독립 실행형 HTML을 생성합니다."""
    html_snippets = []
    try:
        import markdown
        md = markdown.Markdown(extensions=['tables', 'fenced_code'])
        for chunk in chunks:
            html_snippets.append(md.convert(chunk))
            md.reset()
        html_body = "\n".join(html_snippets)
    except ImportError:
        lines = []
        in_code = False
        full_text = "\n".join(chunks)
        for line in full_text.splitlines():
            if line.startswith("```"):
                in_code = not in_code
                lines.append("<pre><code>" if in_code else "</code></pre>")
                continue
            if in_code:
                lines.append(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
                continue
            if line.startswith("# "):
                lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                lines.append(f"<h3>{line[4:]}</h3>")
            elif line.strip() == "---":
                lines.append("<hr>")
            elif line.strip():
                lines.append(f"<p>{line}</p>")
        html_body = "\n".join(lines)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  @media print {{
    body {{ background: #fff !important; color: #111 !important; }}
    .no-print {{ display: none; }}
    pre, code {{ background: #f6f8fa !important; color: #24292e !important; border: 1px solid #d1d5da; }}
    div[style*="page-break-after: always"] {{ page-break-after: always !important; }}
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.65;
    background-color: #0d1117;
    color: #c9d1d9;
    max-width: 960px;
    margin: 0 auto;
    padding: 30px 20px;
  }}
  h1, h2, h3, h4 {{ color: #58a6ff; margin-top: 1.5em; border-bottom: 1px solid #21262d; padding-bottom: 0.3em; }}
  h1 {{ font-size: 2.2em; color: #79c0ff; text-align: center; }}
  h2 {{ font-size: 1.6em; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  pre {{
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 16px;
    overflow-x: auto;
    font-size: 0.9em;
  }}
  code {{
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
    background-color: rgba(110,118,129,0.4);
    padding: 0.2em 0.4em;
    border-radius: 3px;
    font-size: 85%;
  }}
  pre code {{ background: transparent; padding: 0; }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 20px 0;
  }}
  table, th, td {{
    border: 1px solid #30363d;
    padding: 10px 14px;
  }}
  th {{ background-color: #161b22; color: #58a6ff; }}
  hr {{ border: 0; height: 1px; background: #30363d; margin: 30px 0; }}
  blockquote {{
    border-left: 4px solid #1f6feb;
    margin: 1.5em 0;
    padding: 0 1em;
    color: #8b949e;
  }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

def build_book(sample_mode: bool = False, specific_sections: list[int] | None = None) -> tuple[Path, Path, int, int]:
    """교재 빌드를 수행하여 (md_path, html_path, sec_count, ch_count)를 반환합니다."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_sections = get_section_dirs()

    if sample_mode:
        target_secs = all_sections[:3]  # 기초 3개 섹션
        suffix = "-sample"
    elif specific_sections:
        target_secs = [s for s in all_sections if s[0] in specific_sections]
        suffix = "-custom"
    else:
        target_secs = all_sections
        suffix = ""

    sections_to_build: list[tuple[int, Path, list[Path]]] = []
    total_chapters = 0

    for sec_num, sec_dir in target_secs:
        ch_files = get_chapter_files(sec_dir)
        total_chapters += len(ch_files)
        sections_to_build.append((sec_num, sec_dir, ch_files))

    # 마스터 마크다운 조립
    md_parts = [build_cover_markdown(sample_mode)]
    md_parts.append(build_toc_markdown(sections_to_build))

    for sec_num, sec_dir, ch_files in sections_to_build:
        sec_anchor = f"sec-{sec_num:02d}"
        md_parts.append(f'<div id="{sec_anchor}"></div>\n\n# 섹션 {sec_num:02d}: {sec_dir.name.replace("_", " ")}\n\n---\n\n')
        
        # README가 있으면 섹션 서론으로 포함
        sec_readme = sec_dir / "README.md"
        if sec_readme.exists():
            try:
                with open(sec_readme, "r", encoding="utf-8", errors="ignore") as f:
                    readme_text = f.read()
                    # H1 태그를 H2로 강등하여 계층 구조 유지
                    readme_text = re.sub(r"^#\s+(.+)$", r"## \1", readme_text, flags=re.MULTILINE)
                    md_parts.append(readme_text + "\n\n")
            except Exception:
                pass

        for idx, ch in enumerate(ch_files, 1):
            ch_anchor = f"ch-{sec_num:02d}-{idx:02d}"
            try:
                with open(ch, "r", encoding="utf-8", errors="ignore") as f:
                    ch_text = f.read()
                    # 챕터 시작 시 앵커 및 구분선 추가
                    md_parts.append(f'<div id="{ch_anchor}"></div>\n\n')
                    md_parts.append(ch_text + '\n\n<div style="page-break-after: always;"></div>\n\n')
            except Exception as e:
                print(f"[Warning] Failed reading {ch}: {e}")

    # 부록 추가
    md_parts.append(build_enterprise_appendix())

    full_markdown = "".join(md_parts)
    
    out_md_path = OUTPUT_DIR / f"vibe-hacking-curriculum-{VERSION}{suffix}.md"
    out_html_path = OUTPUT_DIR / f"vibe-hacking-curriculum-{VERSION}{suffix}.html"

    with open(out_md_path, "w", encoding="utf-8") as f:
        f.write(full_markdown)

    html_content = compile_markdown_chunks_to_html(md_parts, f"{TITLE} ({VERSION})")
    with open(out_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return out_md_path, out_html_path, len(sections_to_build), total_chapters

def main():
    parser = argparse.ArgumentParser(description="VibeHacking e-Book / PDF Publication Compiler")
    parser.add_argument("--sample", action="store_true", help="기초 3개 섹션 샘플 에디션 빌드")
    parser.add_argument("--full", action="store_true", help="전체 75개 섹션 마스터 e-Book 빌드")
    parser.add_argument("--sections", type=str, help="특정 섹션 번호 쉼표 구분 (예: 1,2,5)")
    args = parser.parse_args()

    specific = None
    if args.sections:
        specific = [int(s.strip()) for s in args.sections.split(",") if s.strip().isdigit()]

    sample = args.sample or (not args.full and not specific)

    print(f"[*] Starting VibeHacking Publication Compiler ({VERSION})...")
    md_path, html_path, sec_count, ch_count = build_book(sample_mode=sample, specific_sections=specific)

    size_md_kb = md_path.stat().st_size / 1024
    size_html_kb = html_path.stat().st_size / 1024

    mode_label = "SAMPLE" if sample else "FULL MASTER"
    print(f"[✓] {mode_label} Build Complete!")
    print(f"    - Included Sections: {sec_count} sections")
    print(f"    - Included Chapters: {ch_count} chapters")
    print(f"    - Master Markdown:   {md_path} ({size_md_kb:.1f} KB)")
    print(f"    - Standalone HTML:   {html_path} ({size_html_kb:.1f} KB)")
    print(f"[+] To print or convert to PDF, open the HTML in Chrome and press Ctrl+P (Save as PDF).")

if __name__ == "__main__":
    main()
