# 60. 브라우저 보안 (Browser_Security)

> 🌍 **VibeHacking 교재 섹션 60**
> - **CLI 학습**: `python3 vhack.py study 60`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_browser_attack_surface.md](./01_browser_attack_surface.md) | **브라우저 공격 표면 분석** — 브라우저 공격 표면은 악의적인 웹 페이지나 파일이 브라우저를 통해 사용자의 시스템을 공격할 수 있는 모든 진입점의 집합이다. JavaScript 엔진, 렌더링 엔진, PDF 파서, 오... |
| [02_javascript_engine_exploitation.md](./02_javascript_engine_exploitation.md) | **JavaScript 엔진 익스플로잇** — JavaScript 엔진(V8, SpiderMonkey 등)은 웹 페이지의 JS 코드를 실행하는 복잡한 소프트웨어이다. JIT(Just-In-Time) 컴파일러, 가비지 컬렉터 등 고... |
| [03_sandbox_escape.md](./03_sandbox_escape.md) | **브라우저 샌드박스 탈출** — 브라우저 샌드박스는 악성 웹 페이지가 렌더러 프로세스를 장악하더라도 OS나 다른 프로세스에 접근하지 못하도록 격리하는 보안 경계이다. 샌드박스 탈출(Sandbox Escape)은 이 ... |
| [04_browser_extension_advanced.md](./04_browser_extension_advanced.md) | **브라우저 확장프로그램 심화 공격** — 브라우저 확장프로그램은 브라우저에 추가 기능을 제공하지만, 과도한 권한을 가진 악성 확장은 모든 웹 페이지의 내용을 읽고 수정하거나, 사용자 입력을 가로채거나, 쿠키와 비밀번호를 탈취... |
| [05_browser_security_hardening.md](./05_browser_security_hardening.md) | **브라우저 보안 강화** — 브라우저 보안 강화는 기본 설정 상태의 브라우저에 추가적인 보안 설정과 정책을 적용하여 공격 표면을 최소화하는 활동이다. 개인 사용자부터 대기업 엔터프라이즈 환경까지, CSP(콘텐츠 ... |
| [06_browser_security_ctf_lab.md](./06_browser_security_ctf_lab.md) | **브라우저 보안 CTF 실습 랩** — 브라우저 보안 취약점을 CTF 형식으로 학습한다. XSS, CSRF, 콘텐츠 보안 정책 우회, 확장 프로그램 취약점을 실습한다. |

## 🎯 학습 목표

- 브라우저 공격 표면 분석 원리 및 실전 공격/방어 기법 습득
- JavaScript 엔진 익스플로잇 원리 및 실전 공격/방어 기법 습득
- 브라우저 샌드박스 탈출 원리 및 실전 공격/방어 기법 습득
- 브라우저 확장프로그램 심화 공격 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 60 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
