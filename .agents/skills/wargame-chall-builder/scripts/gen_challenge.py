#!/usr/bin/env python3
"""
gen_challenge.py — VibeHacking Wargame Challenge Generator & Validator
Calculates SHA-256 answer hashes, verifies anti-leak invariants,
validates fmt specifications, and formats code snippets for challenges.js.
"""

import argparse
import hashlib
import json
import re
import sys

APPROVED_FMT_BASES = [
    "한 단어 / one word",
    "두 단어 / two words",
    "세 단어 / three words",
    "네 단어 / four words",
    "숫자 / number",
    "명령어 / command",
    "헤더 접미사 / header suffix",
    "경로 / path",
    "포트 번호 / port number",
    "도메인 / domain",
    "CVE 번호 / CVE identifier",
    "IP 주소 / IP address",
    "MAC 주소 / MAC address",
    "파일 이름 / filename",
    "레지스트리 키 / registry key",
    "JSON 속성 / JSON property",
    "함수 이름 / function name",
    "옵션 플래그 / option flag",
    "단일 문자 / single character",
    "시스템 콜 / syscall",
    "어셈블리 니모닉 / assembly mnemonic",
    "환경 변수 / environment variable",
]

def hash_answer(answer: str, ci: bool = True) -> str:
    cleaned = answer.strip()
    if ci:
        cleaned = cleaned.lower()
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()

def check_leak(answer: str, text: str) -> bool:
    """Check if the answer appears as a standalone token in the text."""
    ans_clean = answer.strip().lower()
    if len(ans_clean) < 3:
        return False
    # Check for direct substring or word boundary match
    pattern = r"\b" + re.escape(ans_clean) + r"\b"
    return bool(re.search(pattern, text.lower()))

def validate_challenge(data: dict) -> list[str]:
    errors = []
    required = ["id", "tier", "cat", "track", "points", "answer", "fmt", "title", "prompt", "hints"]
    for field in required:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    if errors:
        return errors

    ans = data["answer"].strip()
    ci = data.get("ci", True)
    
    # Check leak in prompt
    for lang in ["ko", "en"]:
        prompt_txt = data["prompt"].get(lang, "")
        if check_leak(ans, prompt_txt):
            errors.append(f"Answer '{ans}' leaked in prompt.{lang}!")
        
        # Check leak in hints
        hints_list = data["hints"].get(lang, [])
        if len(hints_list) < 2:
            errors.append(f"hints.{lang} must contain at least 2 hints (current: {len(hints_list)})")
        for idx, h in enumerate(hints_list):
            if check_leak(ans, h):
                errors.append(f"Answer '{ans}' leaked in hints.{lang}[{idx}]!")

    # Check fmt
    fmt = data.get("fmt", "")
    has_approved_base = any(fmt.startswith(base) for base in APPROVED_FMT_BASES)
    if not has_approved_base:
        errors.append(f"fmt '{fmt}' does not start with an approved base notation.")

    # Check tier range
    tier = data.get("tier", -1)
    if tier not in range(5):
        errors.append(f"tier must be 0, 1, 2, 3, or 4 (got {tier})")

    return errors

def build_challenge_snippet(data: dict) -> str:
    ans = data["answer"].strip()
    ci = data.get("ci", True)
    ans_hash = hash_answer(ans, ci=ci)

    obj = {
        "id": data["id"],
        "tier": data["tier"],
        "cat": data["cat"],
        "track": data["track"],
        "points": data["points"],
        "ci": ci,
        "hash": ans_hash,
        "fmt": data["fmt"],
        "title": data["title"],
        "prompt": data["prompt"],
        "hints": data["hints"],
    }
    return json.dumps(obj, ensure_ascii=False, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Generate and validate VibeHacking wargame challenge snippets.")
    parser.add_argument("--json-input", help="Path to JSON file containing challenge definition")
    parser.add_argument("--interactive", action="store_true", help="Interactive prompt to generate challenge")
    parser.add_argument("--answer", help="Plaintext answer to hash")
    parser.add_argument("--ci", action="store_true", default=True, help="Case-insensitive flag (default: true)")
    args = parser.parse_args()

    if args.answer:
        h = hash_answer(args.answer, ci=args.ci)
        print(f"Answer: {args.answer}")
        print(f"CI: {args.ci}")
        print(f"SHA-256: {h}")
        print(f"Recommended length pinning: ({len(args.answer.strip())}글자 / {len(args.answer.strip())} chars)")
        return

    if args.json_input:
        with open(args.json_input, "r", encoding="utf-8") as f:
            data = json.load(f)
        errors = validate_challenge(data)
        if errors:
            print("❌ Validation Errors:")
            for err in errors:
                print(f"  - {err}")
            sys.exit(1)
        print("✅ Validation OK!")
        print(build_challenge_snippet(data))
        return

    parser.print_help()

if __name__ == "__main__":
    main()
