# 46. CTF 기법 (CTF_Techniques)

> 🚩 **VibeHacking 교재 섹션 46**
> - **CLI 학습**: `python3 vhack.py study 46`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_ctf_methodology_and_tools.md](./01_ctf_methodology_and_tools.md) | **CTF 방법론과 도구 체계** — CTF(Capture The Flag)는 보안 기술을 겨루는 해킹 대회다. 참가자들은 의도적으로 취약하게 설계된 시스템이나 암호화된 파일에서 "플래그(flag)"라는 특정 문자열을 찾... |
| [02_pwn_and_rev_ctf.md](./02_pwn_and_rev_ctf.md) | **PWN과 REV CTF 기법** — PWN(Pwnable)은 실행 파일(바이너리)의 메모리 취약점을 찾아 악용하는 CTF 분야다. 스택 오버플로우, 힙 오버플로우 등을 이용해 프로그램 흐름을 제어하고 쉘(명령 실행 권한... |
| [03_web_and_crypto_ctf.md](./03_web_and_crypto_ctf.md) | **Web과 Crypto CTF 기법** — Web CTF는 웹사이트나 API 서버의 취약점을 찾아 플래그를 획득하는 분야다. SQL 인젝션, XSS, 인증 우회 등 실제 웹 해킹 기술을 사용한다. Crypto CTF는 잘못 구... |
| [04_ctf_automation_and_frameworks.md](./04_ctf_automation_and_frameworks.md) | **CTF 자동화와 프레임워크** — CTF 문제는 같은 단계를 수천 번 반복해야 하는 경우가 많다(Blind SQLi, 브루트포스, 심볼릭 실행 등). 자동화 도구와 프레임워크를 활용하면 수작업으로 수일이 걸릴 작업을 ... |
| [05_ctf_writeup_methodology.md](./05_ctf_writeup_methodology.md) | **CTF 라이트업 작성 방법론** — 라이트업(Writeup)은 CTF 문제를 어떻게 풀었는지 단계별로 기록한 문서다. 대회가 끝난 후 커뮤니티에 공유하는 것이 CTF 문화의 핵심이다. 좋은 라이트업은 "왜 그 접근법을 ... |
| [06_advanced_ctf_practical_lab.md](./06_advanced_ctf_practical_lab.md) | **고급 CTF 실습 랩 — Pwn·Crypto·Forensics·Misc 종합** — 커널 CTF 문제는 일반적으로 QEMU로 실행되는 커스텀 리눅스 이미지와 취약한 커널 모듈을 제공한다. |

## 🎯 학습 목표

- CTF 방법론과 도구 체계 원리 및 실전 공격/방어 기법 습득
- PWN과 REV CTF 기법 원리 및 실전 공격/방어 기법 습득
- Web과 Crypto CTF 기법 원리 및 실전 공격/방어 기법 습득
- CTF 자동화와 프레임워크 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 46 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
