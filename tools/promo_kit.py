#!/usr/bin/env python3
"""
VibeHacking Web Promotion Toolkit (홍보 자동화 도구).

Generates tailored promotion copy, one-click social share intents,
and automates webhook broadcasts to Discord/Slack security communities.
"""

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Dict

SITE_URL = "https://lsszz2100.github.io/VibeHacking/"
WARGAME_URL = "https://lsszz2100.github.io/VibeHacking/wargame/"
REPO_URL = "https://github.com/lsszz2100/VibeHacking"

PROMO_TEMPLATES = {
    "geeknews": {
        "title": "VibeHacking 2.0 — 실전 사이버보안 바이블 & 2,415제 브라우저 터미널 워게임",
        "url": SITE_URL,
        "body": """안녕하세요, 사이버보안 완전 정복 오픈소스 프로젝트 VibeHacking 2.0을 공유합니다.

- 📖 75개 섹션 종합 바이블 (리버싱, 시스템해킹, EDR 우회, 웹/API, AI 모델 탈옥 및 방어)
- 🔬 57개 도커 핸즈온 실습 랩 (원클릭 환경 구성 및 자동 채점 지원)
- 🎮 브라우저 터미널 워게임 (69개 트랙, 2,415개 단계별 침투 챌린지, 25대 취약점 시뮬레이터 탑재)
- 🌐 GitHub Pages 포털: https://lsszz2100.github.io/VibeHacking/
- 💻 GitHub 저장소: https://github.com/lsszz2100/VibeHacking

설치 없이 브라우저에서 바로 즐길 수 있는 터미널 워게임과 실전 보안 교재를 무료로 이용하실 수 있습니다."""
    },
    "producthunt": {
        "name": "VibeHacking 2.0",
        "tagline": "Open-source cybersecurity bible & 2,415-challenge browser wargame",
        "url": SITE_URL,
        "topics": "Developer Tools, Open Source, Education, Security",
        "description": """VibeHacking is an all-in-one open-source offensive & defensive cybersecurity mastery platform.

Features:
• 75 In-Depth Sections: Binary exploitation, reverse engineering, kernel internals, EDR telemetry evasion, cloud/Kubernetes security, AI red teaming, and Zero Trust architectures.
• 57 Reproducible Docker Labs: Ready-to-deploy hands-on testing environments with automated validation.
• In-Browser Terminal Wargame: 69 tracks with 2,415 progressive challenges and 25 interactive security architecture simulators (BGP, OAuth2, DBShield, TLS, Cache, K8s, CAN Bus, EDRShield, PQCMigrate, eBPFShield, AntiReversingShield).
• 100% Free & Open Source under MIT License. No installation required to play.""",
        "maker_comment": """Hey Product Hunt community! 👋

We built VibeHacking to solve a major pain point in learning cybersecurity: the friction of heavy virtual machines, outdated tutorials, and disconnected theory.

With VibeHacking, you can open your browser, enter an authentic simulated Linux terminal, and immediately start solving progressive penetration testing challenges across 69 specialized tracks. Coupled with 75 complete textbook sections and 57 Docker labs, it bridges the gap from zero knowledge to industry-grade offensive & defensive security.

We'd love to hear your feedback, bug reports, and challenge suggestions! Let us know what you think! 🚀"""
    },
    "reddit_netsec": {
        "title": "VibeHacking: Open-source cybersecurity bible (75 sections, 57 labs) & browser-based terminal wargame with 2,415 challenges",
        "url": REPO_URL,
        "body": """VibeHacking is an open-source offensive & defensive cybersecurity resource hub and hands-on wargame.

Key Highlights:
* 75 Comprehensive Sections: Binary reversing, exploit development, kernel exploitation, EDR telemetry bypass, cloud/k8s security, AI security, and zero-trust.
* 57 Docker Hands-on Labs: Self-contained reproducible vulnerable lab environments with automated regression tests.
* In-Browser Infiltration Wargame: A full terminal simulation covering 69 tracks with 2,415 progressive challenges and 25 interactive simulators (BGP, OAuth2, DBShield, TLS, Cache, K8s, CanBus, EDRShield, PQCMigrate, eBPFShield, AntiReversingShield).
* Live Portal: https://lsszz2100.github.io/VibeHacking/
* Interactive Wargame: https://lsszz2100.github.io/VibeHacking/wargame/
* GitHub Repository: https://github.com/lsszz2100/VibeHacking"""
    },
    "reddit_cybersecurity": {
        "title": "A free, open-source 75-chapter cybersecurity curriculum & interactive browser terminal wargame (2,415 challenges)",
        "url": SITE_URL,
        "body": """Hey r/cybersecurity,

Wanted to share an open-source cybersecurity education and training resource we've built: VibeHacking.

Everything is completely free and browser-accessible without needing to spin up heavy VMs just to get started:
1. Complete Curriculum (75 Sections): Covers foundations, network protocols, system internals, binary analysis, web vulnerabilities, Active Directory, cloud security, and modern AI red teaming.
2. 57 Reproducible Docker Labs: Practical vulnerable targets with automated testing scripts.
3. Interactive Browser Terminal Wargame: 69 tracks and 2,415 progressive challenges simulating real shell environments (`connect`, `cat`, `submit`, privilege escalation).
4. Interactive Architecture Simulators: 25 real-time visualizers for OAuth2 flows, TLS handshakes, BGP hijacking, PQC lattice KEM, EDR detection bypass, and AntiReversingShield.

* Website & Wargame: https://lsszz2100.github.io/VibeHacking/
* GitHub (MIT): https://github.com/lsszz2100/VibeHacking

Feedback and contributions are always welcome!"""
    },
    "reddit_sideproject": {
        "title": "I built an open-source terminal wargame with 2,415 challenges and a 75-chapter cybersecurity guide",
        "url": SITE_URL,
        "body": """Hey r/SideProject,

I spent months building VibeHacking, an open-source cybersecurity learning portal with a fully functional browser-based terminal wargame.

What you can do:
- Solve 2,415 progressive hacking & security challenges directly in an interactive browser terminal (no local software setup needed).
- Study 75 full chapters ranging from reverse engineering to AI security.
- Explore 25 interactive security architecture simulators (OAuth 2.0, TLS, K8s, EDR, PQC, eBPF, AntiReversingShield).
- Run 57 Docker hands-on labs locally.

Check it out live: https://lsszz2100.github.io/VibeHacking/
Source Code: https://github.com/lsszz2100/VibeHacking

Would love to get your thoughts and feedback!"""
    },
    "twitter": {
        "text": """🔥 실전 사이버보안 오픈소스 바이블 & 워게임 [VibeHacking 2.0]
💻 75개 섹션 보안 교재
🔬 57개 핸즈온 실습 랩
🎮 69개 트랙 2,415제 브라우저 터미널 워게임 + 25대 EDR/보안 시뮬레이터

지금 브라우저에서 바로 침투 실습을 시작해보세요! 🚀
👉 https://lsszz2100.github.io/VibeHacking/

#보안 #해킹 #CTF #Wargame #Cybersecurity #EDR #Infosec #DevSecOps"""
    },
    "disquiet": {
        "title": "설치 없이 브라우저에서 즐기는 2,415제 사이버보안 워게임 & 교재 포털",
        "url": SITE_URL,
        "body": """보안 공부를 시작할 때 환경 구축의 번거로움 없이, 브라우저 가짜 셸 터미널(`connect`, `cat`, `submit`)로 단계별 침투를 실습할 수 있는 VibeHacking 워게임을 소개합니다.

총 75개 섹션 교재와 57개 랩, 2,415개 워게임 챌린지가 모두 오픈소스로 공개되어 있습니다!"""
    }
}

def get_share_intents() -> Dict[str, str]:
    """Generate one-click social share intent URLs."""
    tw_text = urllib.parse.quote(PROMO_TEMPLATES["twitter"]["text"])
    tw_url = f"https://twitter.com/intent/tweet?text={tw_text}"

    reddit_netsec_title = urllib.parse.quote(PROMO_TEMPLATES["reddit_netsec"]["title"])
    reddit_netsec_url = f"https://www.reddit.com/r/netsec/submit?url={urllib.parse.quote(REPO_URL)}&title={reddit_netsec_title}"

    reddit_cyber_title = urllib.parse.quote(PROMO_TEMPLATES["reddit_cybersecurity"]["title"])
    reddit_cyber_url = f"https://www.reddit.com/r/cybersecurity/submit?url={urllib.parse.quote(SITE_URL)}&title={reddit_cyber_title}"

    reddit_side_title = urllib.parse.quote(PROMO_TEMPLATES["reddit_sideproject"]["title"])
    reddit_side_url = f"https://www.reddit.com/r/SideProject/submit?url={urllib.parse.quote(SITE_URL)}&title={reddit_side_title}"

    ph_url = "https://www.producthunt.com/posts/new"

    linkedin_url = f"https://www.linkedin.com/sharing/share-offsite/?url={urllib.parse.quote(SITE_URL)}"

    fb_url = f"https://www.facebook.com/sharer/sharer.php?u={urllib.parse.quote(SITE_URL)}"

    return {
        "Twitter / X": tw_url,
        "Reddit (r/netsec)": reddit_netsec_url,
        "Reddit (r/cybersecurity)": reddit_cyber_url,
        "Reddit (r/SideProject)": reddit_side_url,
        "Product Hunt New Launch": ph_url,
        "LinkedIn": linkedin_url,
        "Facebook": fb_url,
    }

def broadcast_discord_webhook(webhook_url: str) -> bool:
    """Send an embed message to a Discord security/dev channel via webhook."""
    payload = {
        "username": "VibeHacking Broadcast",
        "avatar_url": "https://raw.githubusercontent.com/lsszz2100/VibeHacking/main/wargame/assets/og-preview.svg",
        "embeds": [
            {
                "title": "⚡ VibeHacking 2.0 — 실전 사이버보안 바이블 & 워게임 공개",
                "description": "브라우저에서 설치 없이 즐기는 67트랙 2,345제 침투 워게임과 75개 챕터 보안 바이블",
                "url": SITE_URL,
                "color": 2621323,  # #27ff8b in decimal
                "fields": [
                    {"name": "📚 종합 교재", "value": "75개 섹션 (리버싱, 익스플로잇, EDR, AI)", "inline": True},
                    {"name": "🔬 실습 랩", "value": "55개 핸즈온 랩 (도커 기반)", "inline": True},
                    {"name": "🎮 터미널 워게임", "value": "2,345개 챌린지 + 23대 시뮬레이터", "inline": True},
                ],
                "footer": {"text": "VibeHacking Open Source Project"}
            }
        ]
    }
    data = json.dumps(payload).encode("utf-8")
    try:
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "VibeHacking-Promo/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] Discord broadcast sent successfully (HTTP {resp.status})")
            return resp.status in (200, 204)
    except Exception as e:
        print(f"[-] Discord broadcast failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="VibeHacking Social Promotion & Broadcast Toolkit")
    parser.add_argument("--platform", choices=["all", "producthunt", "reddit", "geeknews", "twitter", "disquiet"], default="all")
    parser.add_argument("--broadcast", action="store_true", help="Broadcast to Discord webhook if DISCORD_WEBHOOK_URL env is set.")
    parser.add_argument("--print-links", action="store_true", help="Print one-click social share links.")
    args = parser.parse_args()

    print("=" * 65)
    print(" VibeHacking Promotion Automation Toolkit")
    print("=" * 65)

    intents = get_share_intents()
    print("\n[★] 원클릭 소셜 공유 URL (클릭 시 브라우저에서 즉시 공유 화면 오픈):")
    for plat, link in intents.items():
        print(f"  - {plat.ljust(25)}: {link}")

    if args.platform in ("all", "producthunt"):
        print("\n" + "=" * 30 + " Product Hunt Launch Kit " + "=" * 30)
        ph = PROMO_TEMPLATES["producthunt"]
        print(f"Product Name: {ph['name']}")
        print(f"Tagline:      {ph['tagline']}")
        print(f"Website URL:  {ph['url']}")
        print(f"Topics:       {ph['topics']}")
        print(f"\n[Description]\n{ph['description']}")
        print(f"\n[Maker First Comment]\n{ph['maker_comment']}")

    if args.platform in ("all", "reddit"):
        print("\n" + "=" * 30 + " Reddit r/netsec 포스팅 문안 " + "=" * 30)
        print(f"Title: {PROMO_TEMPLATES['reddit_netsec']['title']}")
        print(f"URL:   {PROMO_TEMPLATES['reddit_netsec']['url']}")
        print(f"\n{PROMO_TEMPLATES['reddit_netsec']['body']}")

        print("\n" + "=" * 30 + " Reddit r/cybersecurity 포스팅 문안 " + "=" * 30)
        print(f"Title: {PROMO_TEMPLATES['reddit_cybersecurity']['title']}")
        print(f"URL:   {PROMO_TEMPLATES['reddit_cybersecurity']['url']}")
        print(f"\n{PROMO_TEMPLATES['reddit_cybersecurity']['body']}")

        print("\n" + "=" * 30 + " Reddit r/SideProject 포스팅 문안 " + "=" * 30)
        print(f"Title: {PROMO_TEMPLATES['reddit_sideproject']['title']}")
        print(f"URL:   {PROMO_TEMPLATES['reddit_sideproject']['url']}")
        print(f"\n{PROMO_TEMPLATES['reddit_sideproject']['body']}")

    if args.platform in ("all", "geeknews"):
        print("\n" + "=" * 30 + " GeekNews 등록 문안 " + "=" * 30)
        print(f"제목: {PROMO_TEMPLATES['geeknews']['title']}")
        print(f"URL:  {PROMO_TEMPLATES['geeknews']['url']}")
        print(f"\n{PROMO_TEMPLATES['geeknews']['body']}")

    if args.platform in ("all", "twitter"):
        print("\n" + "=" * 30 + " X / Twitter 홍보 트윗 " + "=" * 30)
        print(PROMO_TEMPLATES["twitter"]["text"])

    if args.platform in ("all", "disquiet"):
        print("\n" + "=" * 30 + " 디스콰이엇(Disquiet) 소개글 " + "=" * 30)
        print(f"제목: {PROMO_TEMPLATES['disquiet']['title']}")
        print(f"\n{PROMO_TEMPLATES['disquiet']['body']}")

    # Webhook broadcast
    if args.broadcast:
        webhook = os.getenv("DISCORD_WEBHOOK_URL")
        if webhook:
            print("\n[*] Sending Discord broadcast...")
            broadcast_discord_webhook(webhook)
        else:
            print("\n[-] DISCORD_WEBHOOK_URL environment variable is not set. Skipped broadcast.")

    print("\n" + "=" * 65)

if __name__ == "__main__":
    main()
