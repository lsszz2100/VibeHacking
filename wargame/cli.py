"""
VibeHacking Terminal Native Wargame Client (TUI / CLI).
Allows playing all 35 tracks and 1,225 challenges directly in terminal.
"""

from __future__ import annotations
import os
import sys
import json
import re
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_JS = REPO_ROOT / "wargame" / "assets" / "challenges.js"
PROGRESS_FILE = Path.home() / ".vhack_wargame_progress.json"

# ANSI Colors
def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def cyan(t: str) -> str: return _c("36", t)
def green(t: str) -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def red(t: str) -> str: return _c("31", t)
def bold(t: str) -> str: return _c("1", t)
def dim(t: str) -> str: return _c("2", t)
def magenta(t: str) -> str: return _c("35", t)


def load_wargame_db() -> Tuple[List[dict], List[dict], List[dict]]:
    """challenges.js 파일에서 TIERS, TRACKS, CHALLENGES 로드"""
    if not CHALLENGES_JS.exists():
        raise FileNotFoundError(f"Challenges DB not found: {CHALLENGES_JS}")

    content = CHALLENGES_JS.read_text(encoding="utf-8")

    # Extract TIERS
    t_start = content.find("const TIERS = ") + len("const TIERS = ")
    t_end = content.find("\n];\n", t_start)
    raw_tiers = re.sub(r"^\s*//.*$", "", content[t_start:t_end + 2].strip(), flags=re.MULTILINE)
    tiers = json.loads(raw_tiers, strict=False)

    # Extract TRACKS
    tr_start = content.find("const TRACKS = ") + len("const TRACKS = ")
    tr_end = content.find("\n];\n", tr_start)
    raw_tracks = re.sub(r"^\s*//.*$", "", content[tr_start:tr_end + 2].strip(), flags=re.MULTILINE)
    tracks = json.loads(raw_tracks, strict=False)

    # Extract CHALLENGES
    c_start = content.find("const CHALLENGES = ") + len("const CHALLENGES = ")
    c_end = content.find("\n];\n", c_start)
    raw_challenges = re.sub(r"^\s*//.*$", "", content[c_start:c_end + 2].strip(), flags=re.MULTILINE)
    challenges = json.loads(raw_challenges, strict=False)

    return tiers, tracks, challenges


def load_user_progress() -> dict:
    """사용자의 로컬 워게임 진행도 로드"""
    if PROGRESS_FILE.exists():
        try:
            return json.loads(PROGRESS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"solved": [], "total_score": 0, "history": []}


def save_user_progress(progress: dict) -> None:
    """사용자의 로컬 워게임 진행도 저장"""
    try:
        PROGRESS_FILE.write_text(json.dumps(progress, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(yellow(f"경고: 진행도 저장 실패: {e}"), file=sys.stderr)


def verify_flag(challenge: dict, flag_input: str) -> bool:
    """플래그 해시 검증 (case-insensitive 및 다양한 형식 지원)"""
    candidate = flag_input.strip()
    if not candidate:
        return False

    expected_hash = challenge["hash"]
    is_ci = challenge.get("ci", False)

    candidates = [candidate]
    if is_ci:
        candidates.append(candidate.lower())

    for c in candidates:
        h = hashlib.sha256(c.encode("utf-8")).hexdigest()
        if h == expected_hash:
            return True

    return False


def submit_flag_cli(chal_id: str, flag: str, lang: str = "ko") -> Tuple[bool, str]:
    """CLI에서 특정 챌린지에 플래그 제출"""
    _, _, challenges = load_wargame_db()
    ch = next((c for c in challenges if c["id"] == chal_id), None)
    if not ch:
        return False, f"Challenge ID '{chal_id}'를 찾을 수 없습니다."

    progress = load_user_progress()
    if chal_id in progress["solved"]:
        return True, f"이미 해결한 문제입니다! (Challenge: {chal_id})"

    if verify_flag(ch, flag):
        progress["solved"].append(chal_id)
        pts = ch.get("points", 10)
        progress["total_score"] = progress.get("total_score", 0) + pts
        progress.setdefault("history", []).append({
            "chal_id": chal_id,
            "time": int(time.time()),
            "points": pts,
        })
        save_user_progress(progress)
        title = ch["title"].get(lang) or ch["title"].get("ko") or chal_id
        return True, f"🎉 정답입니다! [{title}] 문제를 해결하여 +{pts}점을 획득했습니다! (총 점수: {progress['total_score']}점)"
    else:
        return False, "❌ 잘못된 플래그입니다. 다시 시도하세요!"


def print_tracks_summary() -> None:
    """35개 전체 트랙 목록 및 사용자 진행도 출력"""
    tiers, tracks, challenges = load_wargame_db()
    progress = load_user_progress()
    solved_set = set(progress.get("solved", []))

    print(bold(cyan("\n🎮 VibeHacking Wargame — 35개 트랙 로드맵\n")))
    print(f"  {bold('ID'):<14} {bold('트랙 명칭'):<32} {bold('진행도'):<15} {bold('배점')}")
    print("  " + "─" * 70)

    total_solved = 0
    total_points = 0

    for idx, t in enumerate(tracks, 1):
        tid = t["id"]
        t_chals = [c for c in challenges if c.get("track") == tid]
        t_solved = sum(1 for c in t_chals if c["id"] in solved_set)
        t_pts = sum(c.get("points", 0) for c in t_chals if c["id"] in solved_set)
        total_solved += t_solved
        total_points += t_pts

        pct = (t_solved / len(t_chals) * 100) if t_chals else 0
        prog_bar = f"{t_solved:2d}/{len(t_chals):2d} ({pct:3.0f}%)"
        icon_name = f"{t.get('icon', '📁')} {t.get('ko', tid)}"
        
        status_color = green if t_solved == len(t_chals) and len(t_chals) > 0 else (yellow if t_solved > 0 else dim)
        print(f"  [{idx:02d}] {tid:<10} {icon_name:<30} {status_color(prog_bar)}  {t_pts} pts")

    print("  " + "─" * 70)
    all_pct = (total_solved / len(challenges) * 100) if challenges else 0
    print(bold(f"  전체 진행도: {green(str(total_solved))} / {len(challenges)} 문제 ({all_pct:.1f}%) | 총 획득 점수: {bold(yellow(str(total_points)))} pts\n"))


def print_challenge_info(ch: dict, lang: str = "ko") -> None:
    """챌린지 상세 지문 및 힌트 출력"""
    progress = load_user_progress()
    is_solved = ch["id"] in progress.get("solved", [])
    status_tag = green(" [SOLVED ✓] ") if is_solved else yellow(" [UNSOLVED] ")

    title = ch["title"].get(lang) or ch["title"].get("ko") or ch["id"]
    prompt = ch["prompt"].get(lang) or ch["prompt"].get("ko") or ""
    hints = ch["hints"].get(lang) or ch["hints"].get("ko") or []

    print(bold(cyan("\n" + "═" * 72)))
    print(f"  {bold(title)} {status_tag}")
    print(f"  • ID: {dim(ch['id'])} | 트랙: {bold(ch.get('track', 'general'))} | 티어: Tier {ch.get('tier', 0)} | 배점: {yellow(str(ch.get('points', 10)))} pts")
    print(f"  • 플래그 포맷: {magenta(ch.get('fmt', 'FLAG{...}'))}")
    print("═" * 72)
    print(f"\n{bold('📖 문제 지문:')}\n")
    for line in prompt.strip().split("\n"):
        print(f"  {line}")

    if hints:
        print(f"\n{bold('💡 힌트:')}")
        for i, h in enumerate(hints, 1):
            print(f"  {i}. {dim(h)}")
    print("\n" + "─" * 72)


def search_challenges(query: str, lang: str = "ko") -> None:
    """키워드로 문제 검색"""
    _, _, challenges = load_wargame_db()
    progress = load_user_progress()
    solved_set = set(progress.get("solved", []))

    q = query.strip().lower()
    matches = []
    for c in challenges:
        title = (c["title"].get("ko", "") + " " + c["title"].get("en", "")).lower()
        prompt = (c["prompt"].get("ko", "") + " " + c["prompt"].get("en", "")).lower()
        cid = c["id"].lower()
        if q in title or q in prompt or q in cid:
            matches.append(c)

    print(bold(cyan(f"\n🔍 '{query}' 검색 결과: 총 {len(matches)}건 발견\n")))
    if not matches:
        print(dim("  일치하는 문제가 없습니다.\n"))
        return

    for c in matches[:25]:
        solved = "✓" if c["id"] in solved_set else " "
        title = c["title"].get(lang) or c["title"].get("ko") or c["id"]
        print(f"  [{green(solved)}] {c['id']:<34} Tier {c.get('tier', 0)} ({c.get('points', 10)}pt) - {title}")
    if len(matches) > 25:
        print(dim(f"  ... 외 {len(matches) - 25}건 생략 (더 자세한 검색어를 입력하세요)"))
    print()


def interactive_play() -> None:
    """대화형 터미널 워게임 REPL 인터페이스"""
    tiers, tracks, challenges = load_wargame_db()
    tracks_by_id = {t["id"]: t for t in tracks}
    tracks_by_num = {f"{i+1}": t for i, t in enumerate(tracks)}

    print(bold(cyan("\n🕹️  VibeHacking 터미널 워게임 아레나 (CLI Mode)")))
    print(dim(f"  35개 트랙 · {len(challenges)}개 암호/해킹 챌린지 · 오프라인 진행도 자동 저장\n"))

    while True:
        try:
            print(f"\n{bold('[메뉴]')}")
            print(f"  {cyan('1~35')} : 트랙 선택 및 문제 풀이")
            print(f"  {cyan('list')} : 35개 트랙 진행도 종합 요약표")
            print(f"  {cyan('find <단어>')} : 키워드로 문제 검색")
            print(f"  {cyan('q')} : 종료\n")

            choice = input(bold("선택 > ")).strip()
            if not choice or choice.lower() in ["q", "quit", "exit"]:
                print(dim("\n워게임을 종료합니다. Happy Hacking!\n"))
                break

            if choice.lower() == "list":
                print_tracks_summary()
                continue

            if choice.lower().startswith("find "):
                query = choice[5:].strip()
                search_challenges(query)
                continue

            selected_track = None
            if choice in tracks_by_num:
                selected_track = tracks_by_num[choice]
            elif choice.lower() in tracks_by_id:
                selected_track = tracks_by_id[choice.lower()]

            if not selected_track:
                print(red("올바른 트랙 번호나 메뉴를 입력하세요."))
                continue

            # Track Challenge View
            tid = selected_track["id"]
            track_chals = [c for c in challenges if c.get("track") == tid]

            while True:
                progress = load_user_progress()
                solved_set = set(progress.get("solved", []))
                print(bold(cyan(f"\n📂 [{selected_track.get('icon', '')} {selected_track.get('ko', tid)}] 트랙 문제 목록 ({len(track_chals)}제)\n")))
                for idx, c in enumerate(track_chals, 1):
                    tag = green("[✓ SOLVED]") if c["id"] in solved_set else dim("[  TODO  ]")
                    title = c["title"].get("ko") or c["title"].get("en") or c["id"]
                    print(f"  {idx:2d}. {tag} {c['id']:<32} Tier {c.get('tier', 0)} ({c.get('points', 10):2d}pt) : {title}")

                print(f"\n  {dim('문제 번호(1~')}{dim(str(len(track_chals)))}{dim(') 선택, 또는 b: 뒤로가기')}")
                sub_choice = input(bold("문제 선택 > ")).strip()
                if sub_choice.lower() in ["b", "back", "q"]:
                    break

                if not sub_choice.isdigit() or not (1 <= int(sub_choice) <= len(track_chals)):
                    print(red("올바른 문제 번호를 입력하세요."))
                    continue

                ch = track_chals[int(sub_choice) - 1]
                print_challenge_info(ch)

                # Flag submission loop
                while True:
                    flag_input = input(bold("\n🚩 플래그 입력 (Enter 누르면 목록으로 복귀) > ")).strip()
                    if not flag_input:
                        break

                    ok, msg = submit_flag_cli(ch["id"], flag_input)
                    if ok:
                        print(green(f"\n{msg}\n"))
                        break
                    else:
                        print(red(f"\n{msg}"))

        except (KeyboardInterrupt, EOFError):
            print(dim("\n\n워게임을 종료합니다.\n"))
            break
