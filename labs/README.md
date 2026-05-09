# CTF 스타일 취약 환경 번들 — 바이브 해킹 Labs

이 디렉토리는 사이버보안 학습을 위한 **CTF 스타일 취약 환경**을 모아둔 번들입니다.
각 랩은 Docker Compose로 독립적으로 실행 가능하며, 실제 공격/방어 기술을 안전하게 실습할 수 있습니다.

---

## 환경 요구사항

| 항목 | 최소 버전 | 권장 |
|------|-----------|------|
| Docker Engine | 20.10+ | 24.x |
| Docker Compose | v2.0+ (또는 docker-compose v1.29+) | v2.x |
| 사용 가능한 RAM | 4 GB | 8 GB 이상 |
| 디스크 공간 | 10 GB | 20 GB 이상 |
| 운영체제 | Linux / macOS / WSL2 | Ubuntu 22.04 |

### 설치 확인

```bash
docker --version
docker compose version
# 또는 구버전
docker-compose --version
```

---

## 랩 목록

| # | 랩 이름 | 핵심 주제 | 난이도 |
|---|---------|-----------|--------|
| 01 | [웹 해킹 랩](./01_web_hacking_lab/) | SQLi, XSS, CSRF, IDOR, 인증 우회 | ★★☆ |
| 02 | [바이너리 익스플로잇 랩](./02_pwn_lab/) | BOF, ret2libc, ROP, 포맷스트링, 힙 | ★★★ |
| 03 | [네트워크 해킹 랩](./03_network_lab/) | 포트 스캔, 크리덴셜 공격, 피벗 | ★★☆ |
| 04 | [클라우드/컨테이너 보안 랩](./04_cloud_container_lab/) | K8s, IMDS, 컨테이너 탈출 | ★★★ |
| 05 | [전체 시나리오 통합 랩](./05_full_scenario_lab/) | APT 체인, 내부망 침투, 데이터 탈취 | ★★★★ |

---

## 각 랩 학습 목표

### 01. 웹 해킹 랩
- OWASP Top 10 취약점을 직접 실습
- SQL 인젝션을 통한 데이터 추출 및 인증 우회
- XSS(Reflected, Stored, DOM)의 원리와 방어책 이해
- Burp Suite를 활용한 웹 트래픽 분석 및 조작
- DVWA, Juice Shop, WebGoat 등 검증된 취약 환경 활용

### 02. 바이너리 익스플로잇 랩
- x86/x64 스택 구조 및 스택 오버플로우 원리 이해
- NX, ASLR, PIE, RELRO 등 메모리 보호 기법 학습
- ret2libc 및 ROP 가젯 체이닝 기법 습득
- 포맷 스트링 취약점을 활용한 메모리 읽기/쓰기
- tcache poisoning을 통한 힙 익스플로잇

### 03. 네트워크 해킹 랩
- nmap을 이용한 네트워크 스캔 및 서비스 핑거프린팅
- 취약한 서비스(SSH, FTP, Telnet) 크리덴셜 공격
- DNS zone transfer 취약점 및 SMTP 릴레이 남용
- 피벗(pivoting)을 통한 내부 네트워크 접근

### 04. 클라우드/컨테이너 보안 랩
- AWS IMDS(Instance Metadata Service) 취약점 실습
- SSRF를 통한 클라우드 자격증명 탈취
- Docker 컨테이너 권한 남용 및 탈출(escape) 기법
- 취약한 컨테이너 레지스트리 악용

### 05. 전체 시나리오 통합 랩
- APT(Advanced Persistent Threat) 공격 체인 시뮬레이션
- 외부 웹 → SSRF → 내부망 이동 → 데이터베이스 침투
- LDAP 열거 및 SMB/FTP 파일 서버 접근
- 전체 침투 테스트 보고서 작성 실습

---

## 빠른 시작 가이드

### 특정 랩 시작

```bash
# 01 웹 해킹 랩 시작
./start_lab.sh 01

# 02 바이너리 익스플로잇 랩 시작
./start_lab.sh 02

# 특정 랩 직접 실행
cd labs/01_web_hacking_lab
docker compose up -d

# 로그 확인
docker compose logs -f
```

### 전체 랩 정리

```bash
./stop_all.sh
```

### 개별 랩 종료

```bash
cd labs/01_web_hacking_lab
docker compose down

# 볼륨까지 삭제
docker compose down -v
```

---

## 주의사항

> **경고**: 이 랩은 의도적으로 취약하게 설계되어 있습니다.
> - **로컬 또는 격리된 환경**에서만 실행하세요.
> - 인터넷에 노출된 서버에 절대 배포하지 마세요.
> - 학습 목적 외의 용도로 사용하지 마세요.
> - 실습 후 반드시 컨테이너를 종료하세요.

---

## 추천 도구

| 도구 | 용도 | 설치 |
|------|------|------|
| Burp Suite Community | 웹 프록시 | https://portswigger.net |
| pwntools | 바이너리 익스플로잇 | `pip install pwntools` |
| nmap | 네트워크 스캔 | `apt install nmap` |
| Wireshark | 패킷 분석 | https://wireshark.org |
| GDB + pwndbg | 디버거 | https://github.com/pwndbg/pwndbg |
| sqlmap | SQLi 자동화 | `apt install sqlmap` |

---

## 참고 자료

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CTFtime](https://ctftime.org) — CTF 대회 일정
- [pwn.college](https://pwn.college) — 바이너리 익스플로잇 학습
- [HackTheBox](https://hackthebox.com) — 실전 모의해킹 플랫폼
- [TryHackMe](https://tryhackme.com) — 가이드형 사이버보안 학습
