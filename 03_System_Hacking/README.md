# 03. 시스템 해킹

## 목차

| 파일 | 내용 |
|------|------|
| [01_password_cracking.md](./01_password_cracking.md) | 해시 기초, John/Hashcat, Windows SAM 크랙 |
| [02_buffer_overflow.md](./02_buffer_overflow.md) | BOF 원리, 스택 구조, 실전 익스플로잇 |
| [03_active_directory_attack.md](./03_active_directory_attack.md) | **Active Directory 공격 완전 가이드** — Active Directory(AD)는 Microsoft가 개발한 네트워크 디렉토리 서비스로, 기업 내 모든 사용자, 컴퓨터, 프린터, 정책을 중앙에서 관리합니다. 전 세계 기업의 9... |
| [04_kerberos_delegation_attacks.md](./04_kerberos_delegation_attacks.md) | **Kerberos 위임 공격 완전 가이드** — Kerberos는 네트워크에서 신원을 증명하는 티켓 기반 인증 시스템입니다. '위임(Delegation)'은 서비스가 사용자를 대신해 다른 서비스에 접근할 수 있게 허용하는 기능인데,... |
| [05_system_defense_and_detection.md](./05_system_defense_and_detection.md) | **시스템 공격 탐지 및 방어** — 현대 운영체제는 메모리 기반 공격을 방어하기 위해 여러 하드웨어/소프트웨어 기반 보호 기법을 사용한다. |
| [06_system_ctf_lab.md](./06_system_ctf_lab.md) | **CTF 스타일 시스템 해킹 실습** — docker run -it --rm \ |
| [08_windows_seh_and_driver_exploit_deepdive.md](./08_windows_seh_and_driver_exploit_deepdive.md) | **제3장 시스템 해킹 심층: 윈도우 SEH 덮어쓰기 & 커널 드라이버 취약점 (Deep-dive)** — Windows 운영체제는 프로그램 실행 중 발생하는 예외(0으로 나누기, 접근 위반 ACCESS_VIOLATION 등)를 처리하기 위해 SEH (Structured Exception ... |

## 학습 목표
- 해시 알고리즘과 패스워드 크래킹 기법
- Buffer Overflow 취약점 이해 및 익스플로잇
- SetUID 취약점으로 권한 상승
- 보호 기법(ASLR, NX, Canary) 이해
