# 28. 모바일 해킹 (Mobile_Hacking)

> 📱 **VibeHacking 교재 섹션 28**
> - **CLI 학습**: `python3 vhack.py study 28`
> - **연계 실습 랩**: [Lab 07: 모바일 보안 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_android_pentesting.md](./01_android_pentesting.md) | **Android 펜테스팅** — Android 펜테스팅은 Android 앱과 기기의 보안 취약점을 체계적으로 찾아내는 과정이다. APK 파일을 역공학하여 소스코드를 분석하고(정적 분석), 실제 앱을 실행하면서 동적으... |
| [02_ios_pentesting.md](./02_ios_pentesting.md) | **iOS 펜테스팅** — iOS 펜테스팅은 Apple iPhone/iPad 앱의 보안 취약점을 분석하는 과정이다. Android보다 폐쇄적인 생태계(탈옥 필요, 코드 서명 강제)이지만, 분석 방법은 유사하다.... |
| [03_mobile_traffic_analysis.md](./03_mobile_traffic_analysis.md) | **모바일 트래픽 분석** — 모바일 트래픽 분석은 스마트폰 앱이 서버와 주고받는 네트워크 데이터를 캡처하고 분석하는 과정이다. 앱이 어떤 API를 호출하는지, 어떤 데이터를 전송하는지, 인증 토큰을 어떻게 처리하... |
| [04_Mobile_Malware_Analysis.md](./04_Mobile_Malware_Analysis.md) | **모바일 악성코드 분석 (Android/iOS)** — 모바일 악성코드 분석은 의심스러운 앱의 악성 행위를 식별하는 과정이다. 정적 분석(실행 없이 코드 분석)과 동적 분석(실제 실행하면서 행위 관찰)을 병행한다. 악성코드 분석을 배우면 ... |
| [05_mobile_app_security_testing.md](./05_mobile_app_security_testing.md) | **모바일 앱 보안 테스트 — 자동화 분석·런타임 후킹·API 감사** — 모바일 앱 보안 테스트는 앱의 설계부터 구현, 배포까지 전 과정에서 보안 취약점을 찾아내는 체계적인 평가 과정이다. OWASP Mobile Security Testing Guide(M... |
| [06_mobile_ctf_lab.md](./06_mobile_ctf_lab.md) | **모바일 해킹 CTF 실습 랩** — pip install androguard frida-tools objection |
| [07_frida_android_dynamic_analysis_deepdive.md](./07_frida_android_dynamic_analysis_deepdive.md) | **제28장 모바일 해킹 심층: 안드로이드 악성코드 분석 & Frida 동적 후킹 (Deep-dive)** — 현대 안드로이드 악성코드(Banker, Spyware, Ransomware)는 단순한 Java 코드 레벨의 악의적 행위를 넘어, 탐지 회피(Anti-Analysis), 난독화(Obfu... |

## 🎯 학습 목표

- Android 펜테스팅 원리 및 실전 공격/방어 기법 습득
- iOS 펜테스팅 원리 및 실전 공격/방어 기법 습득
- 모바일 트래픽 분석 원리 및 실전 공격/방어 기법 습득
- 모바일 악성코드 분석 (Android/iOS) 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 28 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
