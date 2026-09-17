# 54. 액티브 디렉토리 공격 (Active_Directory_Attacks)

> 🏢 **VibeHacking 교재 섹션 54**
> - **CLI 학습**: `python3 vhack.py study 54`
> - **연계 실습 랩**: [Lab 11: Active Directory & Kerberos 침투 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_ad_enumeration.md](./01_ad_enumeration.md) | **Active Directory 열거 — BloodHound·LDAP·자동화** — Active Directory(AD)를 처음 접하면 복잡하게 느껴진다. 가장 쉬운 비유는 "회사 전화번호부 + 출입 통제 시스템"이다. |
| [02_kerberos_attacks.md](./02_kerberos_attacks.md) | **Kerberos 공격 — Kerberoasting·AS-REP Roasting·티켓 공격** — Windows 기업 환경 표준: |
| [03_lateral_movement_ad.md](./03_lateral_movement_ad.md) | **AD 횡이동 — NTLM 릴레이·DCSync·PsExec·원격 실행** — 공격 흐름: |
| [04_ad_persistence.md](./04_ad_persistence.md) | **AD 지속성 — Golden Ticket·ACL 조작·탐지 CLI** — 레드팀 작전에서 지속성: |
| [05_ad_defense_and_detection.md](./05_ad_defense_and_detection.md) | **Active Directory 방어 및 탐지** — AD = 기업 IT 인프라의 핵심: |
| [06_ad_ctf_lab.md](./06_ad_ctf_lab.md) | **Active Directory CTF 실습 랩** — Kerberoasting, Pass-the-Hash, BloodHound 분석, DCSync 공격을 실습하는 CTF 환경입니다. |

## 🎯 학습 목표

- Active Directory 열거 — BloodHound·LDAP·자동화 원리 및 실전 공격/방어 기법 습득
- Kerberos 공격 — Kerberoasting·AS-REP Roasting·티켓 공격 원리 및 실전 공격/방어 기법 습득
- AD 횡이동 — NTLM 릴레이·DCSync·PsExec·원격 실행 원리 및 실전 공격/방어 기법 습득
- AD 지속성 — Golden Ticket·ACL 조작·탐지 CLI 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 54 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
