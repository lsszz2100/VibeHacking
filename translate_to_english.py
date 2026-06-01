#!/usr/bin/env python3
"""
Adds English translation sections to Korean cybersecurity MD files.
Usage: ANTHROPIC_API_KEY=sk-... python3 translate_to_english.py [--start N] [--file PATH]

Skips files already containing <a name="english">.
Adds language-toggle header and English section to each file.
"""
import argparse
import os
import sys
import time
from pathlib import Path

try:
    import anthropic
except ImportError:
    sys.exit("[!] Install anthropic: pip3 install anthropic --break-system-packages")

HEADER = """> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

"""

ENGLISH_ANCHOR = '\n\n---\n\n<a name="english"></a>\n\n'

TRANSLATE_PROMPT = """You are a technical cybersecurity document translator.
Translate the following Korean cybersecurity/networking document to English.

Rules:
- Translate ALL Korean text to English
- Keep ALL code blocks, commands, and technical terms as-is
- Keep ALL ASCII diagrams as-is
- Keep ALL table structure but translate Korean headers/content to English
- Translate Korean comments inside code blocks (after #)
- Maintain the same markdown structure (headings, lists, etc.)
- Be technically accurate - this is for security professionals
- Do NOT add extra explanations, just translate
- The output should be the complete English version of the document

Document to translate:
"""

def get_files_needing_translation(base_dir: Path) -> list[Path]:
    files = []
    for md in sorted(base_dir.rglob("*.md")):
        name = md.name
        if name.startswith("README") or name in ("SECURITY.md", "GITHUB_SETUP.md"):
            continue
        content = md.read_text(encoding="utf-8", errors="replace")
        if '<a name="english">' not in content:
            files.append(md)
    return files


def translate_content(client: anthropic.Anthropic, korean_content: str, file_path: Path) -> str:
    print(f"  Translating: {file_path.name} ({len(korean_content)} chars)...")

    # Split long content if needed (max ~150K chars per API call)
    max_chunk = 120_000
    if len(korean_content) <= max_chunk:
        chunks = [korean_content]
    else:
        # Split at section boundaries
        lines = korean_content.split('\n')
        chunks = []
        current = []
        current_len = 0
        for line in lines:
            current.append(line)
            current_len += len(line) + 1
            if current_len >= max_chunk and line.startswith('## '):
                chunks.append('\n'.join(current))
                current = []
                current_len = 0
        if current:
            chunks.append('\n'.join(current))

    translated_parts = []
    for i, chunk in enumerate(chunks):
        if len(chunks) > 1:
            print(f"    Part {i+1}/{len(chunks)}...")

        for attempt in range(3):
            try:
                response = client.messages.create(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=8000,
                    messages=[{
                        "role": "user",
                        "content": TRANSLATE_PROMPT + chunk
                    }]
                )
                translated_parts.append(response.content[0].text)
                break
            except anthropic.RateLimitError:
                wait = (attempt + 1) * 30
                print(f"    Rate limit hit, waiting {wait}s...")
                time.sleep(wait)
            except anthropic.APIError as e:
                print(f"    API error: {e}, attempt {attempt+1}/3")
                time.sleep(10)
        else:
            print(f"    [!] Failed to translate chunk {i+1}, using placeholder")
            translated_parts.append(f"[Translation failed for this section]\n\n{chunk}")

    return '\n'.join(translated_parts)


def process_file(client: anthropic.Anthropic, file_path: Path) -> bool:
    content = file_path.read_text(encoding="utf-8", errors="replace")

    # Already has English
    if '<a name="english">' in content:
        return False

    # Add header if missing
    if '🌐 **Language' not in content:
        # Add header at top, Korean anchor before first heading
        if content.startswith('#'):
            # Find where first heading is
            lines = content.split('\n')
            content = HEADER + content
        else:
            content = HEADER + content
    elif '<a name="한국어">' not in content:
        # Has header but no Korean anchor - add it before first heading
        content = content.replace('---\n\n', '---\n\n<a name="한국어"></a>\n\n', 1)

    # Get the Korean content (everything after the header/anchor setup)
    korean_start = 0
    if '<a name="한국어">' in content:
        idx = content.index('<a name="한국어">') + len('<a name="한국어">')
        # Skip to next line
        korean_start = content.index('\n', idx) + 1

    korean_body = content[korean_start:] if korean_start > 0 else content

    # Translate
    english_content = translate_content(client, korean_body, file_path)

    # Reconstruct file
    if korean_start > 0:
        new_content = content[:korean_start] + korean_body + ENGLISH_ANCHOR + english_content
    else:
        new_content = HEADER + content + ENGLISH_ANCHOR + english_content

    file_path.write_text(new_content, encoding="utf-8")
    print(f"  [OK] {file_path.relative_to(file_path.parent.parent)}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Add English translations to Korean MD files")
    parser.add_argument("--start", type=int, default=0, help="Start from file index N (0-based)")
    parser.add_argument("--file", type=str, default=None, help="Process single file")
    parser.add_argument("--dry-run", action="store_true", help="Show files without processing")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key and not args.dry_run:
        sys.exit("[!] Set ANTHROPIC_API_KEY environment variable")

    base_dir = Path(__file__).parent
    client = anthropic.Anthropic(api_key=api_key) if not args.dry_run else None

    if args.file:
        files = [Path(args.file)]
    else:
        files = get_files_needing_translation(base_dir)

    print(f"Files needing English translation: {len(files)}")

    if args.dry_run:
        for i, f in enumerate(files):
            print(f"  [{i:3d}] {f.relative_to(base_dir)}")
        return

    files = files[args.start:]
    print(f"Starting from index {args.start}, processing {len(files)} files\n")

    success = 0
    failed = []

    for i, file_path in enumerate(files):
        print(f"[{i + args.start + 1}/{len(files) + args.start}] {file_path.relative_to(base_dir)}")
        try:
            if process_file(client, file_path):
                success += 1
            else:
                print(f"  [SKIP] Already has English")
        except KeyboardInterrupt:
            print(f"\n\nInterrupted at index {i + args.start}")
            print(f"Resume with: --start {i + args.start}")
            break
        except Exception as e:
            print(f"  [ERROR] {e}")
            failed.append(file_path)

        # Small delay to avoid rate limits
        time.sleep(0.5)

    print(f"\n=== Done: {success} translated, {len(failed)} failed ===")
    if failed:
        print("Failed files:")
        for f in failed:
            print(f"  {f}")


if __name__ == "__main__":
    main()
