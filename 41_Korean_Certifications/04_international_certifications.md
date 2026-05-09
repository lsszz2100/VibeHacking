# 국제 보안 자격증 비교 및 대비 가이드

## 자격증 개요 및 비교

### 주요 국제 자격증 비교표

| 자격증 | 발급 기관 | 난이도 | 비용(USD) | 시험 방식 | 갱신 주기 | 대상 |
|--------|----------|--------|-----------|----------|---------|------|
| CISSP | (ISC)² | 상 | $749 | CAT, 최대 175문항 | 3년 (CPE 120점) | 경력 5년+ 보안 전문가 |
| CEH | EC-Council | 중 | $950~$1,199 | 125문항 4시간 | 3년 (ECE 120점) | 침투 테스터, 보안 분석가 |
| OSCP | Offensive Security | 상 | $1,499 | 24시간 실기 | 없음 (종신) | 침투 테스터 |
| OSED | Offensive Security | 최상 | $1,499 | 48시간 실기 | 없음 (종신) | 익스플로잇 개발자 |
| OSWE | Offensive Security | 상 | $1,499 | 48시간 실기 | 없음 (종신) | 웹 앱 해커 |
| Security+ | CompTIA | 하 | $404 | 90문항 90분 | 3년 (CE 50점) | 입문자, 취업 준비생 |
| CISM | ISACA | 중상 | $575 | 150문항 4시간 | 3년 (CPE 120점) | 보안 관리자 |

---

## CISSP (Certified Information Systems Security Professional)

### 시험 개요

**주관**: (ISC)² (국제정보시스템보안인증컨소시엄)
**시험 방식**: CAT(Computer Adaptive Testing) - 영어 시험 기준
- 문항 수: 125~175문항 (최소 합격 시 125문항, 최대 175문항)
- 시험 시간: 4시간
- 합격 기준: 700/1000점
- 응시 언어: 영어(CAT), 한국어(선형 250문항 6시간)

**응시 자격**: 정보보안 분야 5년 경력 (CISSP 도메인 중 2개 이상 해당)
- 경력 부족 시 Associate of (ISC)² 로 합격 후 경력 보완

### 8개 도메인 핵심 요약

#### 도메인 1: 보안 및 위험 관리 (Security and Risk Management)
**출제 비중: 15%**

- **CIA 트라이어드**: 기밀성, 무결성, 가용성
- **거버넌스**: 정보보안 전략, CISO 역할, 이사회 보고
- **컴플라이언스**: SOX, HIPAA, GDPR, PCI-DSS
- **위험 관리 프레임워크**: NIST RMF, ISO 27005
- **위협 모델링**: STRIDE, DREAD, PASTA
- **비즈니스 연속성**: BCP/DRP, RTO/RPO, BIA(비즈니스 영향 분석)

핵심 공식:
- ALE = SLE × ARO (연간 예상 손실)
- 위험 = 위협 × 취약점 × 자산 가치

#### 도메인 2: 자산 보안 (Asset Security)
**출제 비중: 10%**

- 데이터 분류: 정부(기밀/비밀/내부/공개), 민간(기밀/내부/공개)
- 데이터 소유자 vs 관리자 vs 보관자 역할 구분
- 데이터 수명주기: 생성→저장→사용→공유→보관→파기
- 파기 방법: 삭제(Clearing), 덮어쓰기(Purging), 물리적 파기(Destroying)
- 개인정보 보호: GDPR, 가명처리, 익명화

#### 도메인 3: 보안 아키텍처 및 엔지니어링 (Security Architecture and Engineering)
**출제 비중: 13%**

- **보안 모델**:
  - Bell-LaPadula: 기밀성 (No Read Up, No Write Down)
  - Biba: 무결성 (No Read Down, No Write Up)
  - Clark-Wilson: 상용 환경 무결성
  - Chinese Wall(Brewer-Nash): 이해 충돌 방지
- **시스템 평가**: Common Criteria (CC), EAL 1~7
- **암호화**: 대칭/비대칭, 해시, PKI, 양자 내성 암호
- **물리 보안**: 자물쇠, 맨트랩, 생체인식, CPTED

#### 도메인 4: 통신 및 네트워크 보안 (Communication and Network Security)
**출제 비중: 13%**

- OSI 7계층 각 계층별 프로토콜 및 보안
- 네트워크 장비: 라우터, 스위치, 방화벽, IDS/IPS
- 무선 보안: WPA3, EAP, 802.1X
- VPN: IPsec, SSL/TLS, SD-WAN
- 네트워크 공격: DDoS, MITM, 스니핑, 스푸핑

#### 도메인 5: 신원 및 접근 관리 (Identity and Access Management)
**출제 비중: 13%**

- **접근 제어 모델**: DAC, MAC, RBAC, ABAC
- **인증**: 지식(패스워드), 소유(OTP), 존재(생체)
- **MFA**: 두 가지 이상 인증 요소 조합
- **SSO**: Kerberos, SAML, OAuth 2.0, OIDC
- **권한 부여**: 최소 권한, 직무 분리, 필요 시 알기(Need to Know)
- **계정 관리**: 프로비저닝, 주기적 검토, 디프로비저닝

#### 도메인 6: 보안 평가 및 테스트 (Security Assessment and Testing)
**출제 비중: 12%**

- **취약점 평가**: Nessus, OpenVAS, CVSS 점수
- **침투 테스트 단계**: 정찰 → 스캐닝 → 접근 획득 → 권한 유지 → 흔적 제거
- **감사**: 보안 감사, 로그 검토, 코드 검토
- **소프트웨어 테스트**: 단위, 통합, 회귀, 퍼징
- **SOC 보고서**: SOC 1 (재무), SOC 2 (보안), SOC 3 (공개)

#### 도메인 7: 보안 운영 (Security Operations)
**출제 비중: 13%**

- **사고 대응**: 준비→탐지→격리→제거→복구→교훈
- **디지털 포렌식**: 증거 수집, 연계 보관성, 법적 증거력
- **재해 복구**: 핫/웜/콜드 사이트, 데이터 미러링
- **보안 운영 센터(SOC)**: SIEM, SOAR, 위협 인텔리전스
- **변경 관리**: RFC, 변경 승인 위원회(CAB)

#### 도메인 8: 소프트웨어 개발 보안 (Software Development Security)
**출제 비중: 11%**

- **SDLC 보안**: 보안 요구사항 → 보안 설계 → 시큐어 코딩 → 보안 테스트
- **소프트웨어 취약점**: OWASP, 버퍼 오버플로우, 인젝션
- **DevSecOps**: 보안을 CICD 파이프라인에 통합
- **코드 검토**: SAST(정적), DAST(동적), SCA(구성요소 분석)
- **API 보안**: 인증, 속도 제한, 입력 검증

### CISSP CAT 시험 전략

1. **Think Like a Manager**: 관리자 관점에서 답변 (기술적 해결보다 프로세스 우선)
2. **Best Answer, Not Perfect Answer**: 보기 4개 중 가장 적절한 답
3. **CIA 트라이어드 우선순위**: 문제에서 제시하는 보안 목표 파악
4. **시간 관리**: 125문항 4시간 = 문항당 약 2분
5. **약어 완전 숙지**: 도메인별 핵심 약어 200개 이상

---

## CEH (Certified Ethical Hacker)

### 시험 개요

**주관**: EC-Council
**시험**: 125문항 4시간, 70% 이상 합격
**실기(선택)**: CEH Practical - 6시간, 20개 실습 과제

### 핵심 모듈별 내용

#### 모듈 1-5: 기초 및 정찰
- 해킹 단계: 정찰→스캐닝→열거→취약점 평가→공격→사후 공격
- 수동 정찰: WHOIS, DNS 조회, 소셜 미디어 OSINT
- 능동 정찰: Nmap, Ping Sweep, 포트 스캔
- 열거: NetBIOS, SNMP, LDAP, NFS, SMB 열거

#### 모듈 6-10: 시스템 해킹
- 패스워드 공격: 무차별 대입, 사전 공격, 레인보우 테이블
- 권한 상승: 수평적(동급 권한 획득), 수직적(관리자 권한 획득)
- 백도어: 넷캣, 메타스플로잇 페이로드
- 흔적 제거: 로그 삭제, 타임스탬프 조작

#### 모듈 11-15: 네트워크 및 웹 해킹
- 스니핑: Wireshark, tcpdump, Ettercap
- 소셜 엔지니어링: 피싱, 스피어피싱, 비싱
- DoS/DDoS: SYN Flood, Smurf, HTTP Flood
- 세션 하이재킹: 시퀀스 번호 예측, 쿠키 탈취
- 웹 서버 공격: 디렉터리 탐색, 취약점 스캐닝

#### 모듈 16-20: 고급 기법
- SQL 인젝션: Union 기반, Blind, 시간 기반
- XSS/CSRF
- 암호화 공격: 무차별 대입, 패딩 오라클
- 클라우드 해킹: 잘못된 설정, IAM 취약점
- IoT 해킹: 기본 자격증명, 펌웨어 분석

### CEH 실습 환경 구성

```bash
# Kali Linux 기반 실습 환경
# VirtualBox 또는 VMware에 설치 권장

# 필수 도구 목록
nmap          # 네트워크 스캐닝
metasploit    # 익스플로잇 프레임워크
wireshark     # 패킷 분석
burpsuite     # 웹 프록시
sqlmap        # SQL 인젝션 자동화
nikto         # 웹 취약점 스캐너
john          # 패스워드 크래킹
hashcat       # GPU 패스워드 크래킹
hydra         # 온라인 패스워드 공격
aircrack-ng   # 무선 보안 도구
```

---

## Offensive Security 자격증

### OSCP (Offensive Security Certified Professional)

**코스**: PEN-200 (PWK - Penetration Testing with Kali Linux)
**시험**: 24시간 CTF 형식 + 24시간 보고서 작성
- 6대의 서버 침투 (70점 이상 합격)
- 각 서버: Low Privilege Shell + Root/System = 최대 10점씩 (보너스 포인트 포함)

**학습 핵심 내용:**
- Active Directory 공격: Kerberoasting, Pass-the-Hash, BloodHound
- 버퍼 오버플로우: 32비트 Windows/Linux 스택 기반 BOF
- 웹 애플리케이션 취약점 실습
- 권한 상승: Linux (SUID, sudo, cron), Windows (서비스, 레지스트리)
- 피벗팅: Proxychains, SSH 터널링
- AV 우회: 인코딩, 패킹, 케이스 변환

**OSCP 합격 전략:**
1. HTB(HackTheBox) 또는 THM(TryHackMe) 50개 이상 문제 풀기
2. PWK 랩 머신 최대한 많이 풀기 (최소 30대 권장)
3. TryHackMe OSCP 전용 학습 경로 이수
4. 보고서 작성 연습 (전문적인 침투 테스트 보고서 형식)
5. 공개 CVE 익스플로잇 직접 수정하여 사용 연습

### OSED (Offensive Security Exploit Developer)

**코스**: EXP-301
**시험**: 48시간 실기

**핵심 내용:**
- Windows x86 스택 기반 버퍼 오버플로우
- SEH(Structured Exception Handling) 기반 익스플로잇
- 우회 기법: ASLR, DEP/NX, Stack Canary
- ROP(Return Oriented Programming) 체인 구성
- 포맷 스트링 취약점 익스플로잇
- 커스텀 셸코드 작성

### OSWE (Offensive Security Web Expert)

**코스**: WEB-300 (Advanced Web Attacks and Exploitation)
**시험**: 48시간 실기 + 24시간 보고서

**핵심 내용:**
- 화이트박스 웹 침투 테스트 (소스 코드 분석)
- 인증 우회: 세션 관리 취약점, 암호화 취약점
- 고급 SQL 인젝션 (Blind, OOB)
- 서버 측 취약점: SSRF, XXE, 역직렬화
- 소스 코드 감사: PHP, Java, Python, C# 애플리케이션
- 도구 없이 수동으로 익스플로잇 개발

---

## CompTIA Security+

### 시험 개요

**주관**: CompTIA
**시험**: 최대 90문항, 90분, 750/900점 합격
**응시 자격**: 없음 (CompTIA Network+ 및 2년 경력 권장)

### 핵심 도메인

| 도메인 | 비중 | 핵심 내용 |
|--------|------|----------|
| 일반적 위협·공격·취약점 | 24% | 사회공학, 악성코드, 취약점 유형 |
| 아키텍처·설계 | 21% | 보안 모델, 클라우드, 가상화 |
| 구현 | 25% | 암호화, PKI, 인증, 네트워크 보안 |
| 운영 및 사고 대응 | 16% | 침투 테스트, 포렌식, 사고 대응 |
| 거버넌스·위험·컴플라이언스 | 14% | 정책, 법규, 위험 관리 |

### CompTIA Security+ 취업 연계

- 미국 DoD(국방부) 8570 컴플라이언스 인정
- 한국 금융권, IT 기업 채용 우대
- CISSP 취득 전 기초 자격증으로 적합
- 평균 준비 기간: 1~3개월

---

## CISM (Certified Information Security Manager)

### 시험 개요

**주관**: ISACA
**시험**: 150문항, 4시간, 450/800점 합격
**응시 자격**: 정보보안 관리 5년 경력 (3년 특정 영역)

### 4개 도메인

1. **정보보안 거버넌스 (17%)**: 보안 전략, 거버넌스 프레임워크
2. **정보보안 위험 관리 (20%)**: 위험 식별, 평가, 대응, 모니터링
3. **정보보안 프로그램 (33%)**: 보안 프로그램 수립 및 운영
4. **사고 관리 (30%)**: 침해사고 계획, 대응, 복구

---

## 자격증 공부 진도 관리 Python CLI

```python
#!/usr/bin/env python3
"""
국제 보안 자격증 공부 진도 관리 CLI 도구
사용법: python3 cert_tracker.py [--cert CERT] [--add] [--status] [--stats]
"""

import argparse
import json
import sys
import datetime
from pathlib import Path
from typing import Optional

CERT_CURRICULUM: dict[str, dict] = {
    "CISSP": {
        "description": "Certified Information Systems Security Professional",
        "issuer": "(ISC)²",
        "domains": [
            {"id": "D1", "name": "보안 및 위험 관리", "weight": 15, "topics": ["CIA", "거버넌스", "위험 관리", "BCP/DRP", "윤리"]},
            {"id": "D2", "name": "자산 보안", "weight": 10, "topics": ["데이터 분류", "소유권", "개인정보", "데이터 수명주기"]},
            {"id": "D3", "name": "보안 아키텍처 및 엔지니어링", "weight": 13, "topics": ["보안 모델", "시스템 평가", "암호화", "물리 보안"]},
            {"id": "D4", "name": "통신 및 네트워크 보안", "weight": 13, "topics": ["OSI 모델", "프로토콜", "방화벽", "VPN", "무선"]},
            {"id": "D5", "name": "신원 및 접근 관리", "weight": 13, "topics": ["접근 제어 모델", "인증", "SSO", "계정 관리"]},
            {"id": "D6", "name": "보안 평가 및 테스트", "weight": 12, "topics": ["취약점 평가", "침투 테스트", "감사", "SOC 보고서"]},
            {"id": "D7", "name": "보안 운영", "weight": 13, "topics": ["사고 대응", "포렌식", "재해 복구", "변경 관리", "SOC"]},
            {"id": "D8", "name": "소프트웨어 개발 보안", "weight": 11, "topics": ["SDLC", "OWASP", "DevSecOps", "코드 검토"]},
        ],
        "exam_cost": 749,
        "renewal_years": 3,
        "renewal_credits": 120,
    },
    "CEH": {
        "description": "Certified Ethical Hacker",
        "issuer": "EC-Council",
        "domains": [
            {"id": "M01", "name": "윤리적 해킹 소개", "weight": 5, "topics": ["해킹 단계", "법적 이슈", "정찰 유형"]},
            {"id": "M02", "name": "풋프린팅 및 정찰", "weight": 8, "topics": ["WHOIS", "DNS", "OSINT", "Maltego"]},
            {"id": "M03", "name": "네트워크 스캐닝", "weight": 7, "topics": ["Nmap", "포트 스캔", "OS 탐지", "서비스 열거"]},
            {"id": "M04", "name": "열거", "weight": 6, "topics": ["NetBIOS", "SNMP", "LDAP", "SMB", "NFS"]},
            {"id": "M05", "name": "취약점 분석", "weight": 6, "topics": ["CVSS", "Nessus", "OpenVAS", "CVE"]},
            {"id": "M06", "name": "시스템 해킹", "weight": 10, "topics": ["패스워드 공격", "권한 상승", "백도어", "흔적 제거"]},
            {"id": "M07", "name": "악성코드", "weight": 7, "topics": ["트로이목마", "바이러스", "웜", "랜섬웨어", "분석"]},
            {"id": "M08", "name": "스니핑", "weight": 5, "topics": ["Wireshark", "ARP 스푸핑", "Ettercap", "SSL 스트립"]},
            {"id": "M09", "name": "소셜 엔지니어링", "weight": 5, "topics": ["피싱", "스피어피싱", "비싱", "SE 도구킷"]},
            {"id": "M10", "name": "DoS/DDoS", "weight": 6, "topics": ["SYN Flood", "Smurf", "HTTP Flood", "봇넷"]},
            {"id": "M11", "name": "세션 하이재킹", "weight": 5, "topics": ["TCP 하이재킹", "쿠키 탈취", "토큰 공격"]},
            {"id": "M12", "name": "IDS/IPS/방화벽 우회", "weight": 5, "topics": ["패킷 단편화", "터널링", "프록시 우회"]},
            {"id": "M13", "name": "웹 서버 해킹", "weight": 6, "topics": ["배너 그래빙", "취약점 스캔", "패스워드 크래킹"]},
            {"id": "M14", "name": "웹 앱 해킹", "weight": 8, "topics": ["OWASP", "SQL 인젝션", "XSS", "CSRF", "Burp Suite"]},
            {"id": "M15", "name": "SQL 인젝션", "weight": 5, "topics": ["Union 기반", "Blind", "시간 기반", "sqlmap"]},
            {"id": "M16", "name": "무선 네트워크 해킹", "weight": 5, "topics": ["WPA2 크래킹", "Evil Twin", "aircrack-ng"]},
            {"id": "M17", "name": "모바일 플랫폼 해킹", "weight": 4, "topics": ["Android APK 분석", "iOS 취약점"]},
            {"id": "M18", "name": "IoT 해킹", "weight": 4, "topics": ["기본 자격증명", "펌웨어", "MQTT"]},
            {"id": "M19", "name": "클라우드 컴퓨팅", "weight": 4, "topics": ["AWS 보안", "컨테이너", "서버리스 취약점"]},
            {"id": "M20", "name": "암호화", "weight": 5, "topics": ["대칭/비대칭", "PKI", "스테가노그래피"]},
        ],
        "exam_cost": 950,
        "renewal_years": 3,
        "renewal_credits": 120,
    },
    "OSCP": {
        "description": "Offensive Security Certified Professional",
        "issuer": "Offensive Security",
        "domains": [
            {"id": "S01", "name": "정보 수집", "weight": 10, "topics": ["능동 스캐닝", "수동 정찰", "서비스 열거"]},
            {"id": "S02", "name": "취약점 스캐닝", "weight": 8, "topics": ["Nmap NSE", "Nikto", "취약점 식별"]},
            {"id": "S03", "name": "웹 애플리케이션 공격", "weight": 15, "topics": ["SQL 인젝션", "파일 업로드", "LFI/RFI", "명령어 인젝션"]},
            {"id": "S04", "name": "버퍼 오버플로우", "weight": 15, "topics": ["스택 BOF", "Immunity Debugger", "mona.py", "셸코드"]},
            {"id": "S05", "name": "클라이언트 공격", "weight": 8, "topics": ["브라우저 익스플로잇", "악성 문서", "소셜 엔지니어링"]},
            {"id": "S06", "name": "공개 익스플로잇", "weight": 10, "topics": ["ExploitDB", "Metasploit", "익스플로잇 수정"]},
            {"id": "S07", "name": "권한 상승", "weight": 15, "topics": ["Linux SUID", "sudo 오설정", "Windows 서비스", "레지스트리"]},
            {"id": "S08", "name": "패스워드 공격", "weight": 7, "topics": ["해시 크래킹", "온라인 공격", "서비스 인증 공격"]},
            {"id": "S09", "name": "터널링 및 피벗팅", "weight": 7, "topics": ["SSH 터널", "Proxychains", "네트워크 피벗"]},
            {"id": "S10", "name": "Active Directory", "weight": 15, "topics": ["BloodHound", "Kerberoasting", "Pass-the-Hash", "AS-REP Roasting"]},
        ],
        "exam_cost": 1499,
        "renewal_years": 0,
        "renewal_credits": 0,
    },
    "Security+": {
        "description": "CompTIA Security+",
        "issuer": "CompTIA",
        "domains": [
            {"id": "1.0", "name": "일반적 위협·공격·취약점", "weight": 24, "topics": ["사회공학", "악성코드", "앱 취약점", "네트워크 공격"]},
            {"id": "2.0", "name": "아키텍처·설계", "weight": 21, "topics": ["보안 개념", "가상화", "클라우드", "임베디드 시스템"]},
            {"id": "3.0", "name": "구현", "weight": 25, "topics": ["PKI", "인증", "네트워크 보안", "무선", "클라우드 보안"]},
            {"id": "4.0", "name": "운영 및 사고 대응", "weight": 16, "topics": ["취약점 관리", "침투 테스트", "포렌식", "사고 대응"]},
            {"id": "5.0", "name": "거버넌스·위험·컴플라이언스", "weight": 14, "topics": ["정책", "위험 관리", "개인정보", "컴플라이언스"]},
        ],
        "exam_cost": 404,
        "renewal_years": 3,
        "renewal_credits": 50,
    },
}

PROGRESS_FILE = Path.home() / ".cert_study_progress.json"


def load_progress() -> dict:
    if PROGRESS_FILE.exists():
        try:
            with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_progress(data: dict) -> None:
    try:
        with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"저장 실패: {e}", file=sys.stderr)


def update_progress(cert: str) -> None:
    if cert not in CERT_CURRICULUM:
        print(f"'{cert}'은(는) 지원하지 않는 자격증입니다.")
        print(f"지원 자격증: {', '.join(CERT_CURRICULUM.keys())}")
        return

    progress = load_progress()
    if cert not in progress:
        progress[cert] = {"domains": {}, "start_date": datetime.datetime.now().isoformat()[:10]}

    cert_data = CERT_CURRICULUM[cert]
    print(f"\n{'='*70}")
    print(f" {cert} - {cert_data['description']} 학습 진도 업데이트")
    print(f"{'='*70}\n")
    print("완료 상태: [0] 미시작  [1] 학습 중  [2] 완료  [Enter] 유지\n")

    for domain in cert_data["domains"]:
        domain_id = domain["id"]
        current = progress[cert]["domains"].get(domain_id, {}).get("status", 0)
        status_label = ["미시작", "학습 중", "완료"][current]

        print(f"[{domain_id}] {domain['name']} (출제 비중: {domain['weight']}%)")
        print(f"  핵심 주제: {', '.join(domain['topics'])}")
        print(f"  현재 상태: {status_label}")

        choice = input("  진도 상태 (0/1/2/Enter=유지): ").strip()
        if choice in ("0", "1", "2"):
            new_status = int(choice)
            progress[cert]["domains"][domain_id] = {
                "name": domain["name"],
                "status": new_status,
                "updated": datetime.datetime.now().isoformat()[:16],
            }
        print()

    save_progress(progress)
    print("진도가 저장되었습니다.")


def show_status(cert: Optional[str]) -> None:
    progress = load_progress()

    if not progress:
        print("저장된 진도 데이터가 없습니다.")
        return

    certs_to_show = [cert] if cert and cert in progress else list(progress.keys())

    for cert_name in certs_to_show:
        if cert_name not in CERT_CURRICULUM:
            continue

        cert_data = CERT_CURRICULUM[cert_name]
        cert_progress = progress.get(cert_name, {})
        domains_progress = cert_progress.get("domains", {})

        completed = sum(1 for d in domains_progress.values() if d.get("status") == 2)
        in_progress = sum(1 for d in domains_progress.values() if d.get("status") == 1)
        total_domains = len(cert_data["domains"])

        completion_rate = (completed / total_domains * 100) if total_domains > 0 else 0

        print(f"\n{'='*70}")
        print(f" {cert_name} - {cert_data['description']}")
        print(f" 발급: {cert_data['issuer']} | 비용: ${cert_data['exam_cost']}")
        print(f" 시작일: {cert_progress.get('start_date', '미기록')}")
        print(f" 전체 진도: {completion_rate:.1f}% (완료 {completed}/{total_domains} 도메인)")
        print(f"{'='*70}\n")

        for domain in cert_data["domains"]:
            domain_id = domain["id"]
            d_info = domains_progress.get(domain_id, {})
            status = d_info.get("status", 0)
            icons = ["⬜", "🔄", "✅"]
            print(f"  {icons[status]} [{domain_id}] {domain['name']} ({domain['weight']}%)")


def show_statistics() -> None:
    progress = load_progress()

    if not progress:
        print("저장된 데이터가 없습니다.")
        return

    print(f"\n{'='*70}")
    print(" 전체 자격증 학습 통계")
    print(f" 기준 일시: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*70}\n")

    for cert_name, cert_progress in progress.items():
        if cert_name not in CERT_CURRICULUM:
            continue

        cert_data = CERT_CURRICULUM[cert_name]
        total_domains = len(cert_data["domains"])
        domains_progress = cert_progress.get("domains", {})
        completed = sum(1 for d in domains_progress.values() if d.get("status") == 2)
        rate = (completed / total_domains * 100) if total_domains > 0 else 0

        bar_len = 30
        filled = int(bar_len * rate / 100)
        bar = "█" * filled + "░" * (bar_len - filled)

        print(f"[{cert_name}] {bar} {rate:.0f}% ({completed}/{total_domains})")
        print(f"  시작일: {cert_progress.get('start_date', '미기록')}")


def list_certs() -> None:
    print("\n지원하는 자격증 목록:")
    for cert_name, cert_data in CERT_CURRICULUM.items():
        renewal = f"{cert_data['renewal_years']}년" if cert_data["renewal_years"] > 0 else "종신"
        print(f"  - {cert_name}: {cert_data['description']}")
        print(f"    발급: {cert_data['issuer']} | 비용: ${cert_data['exam_cost']} | 갱신: {renewal}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="국제 보안 자격증 공부 진도 관리 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 cert_tracker.py --list                   # 지원 자격증 목록
  python3 cert_tracker.py --add --cert CISSP       # CISSP 진도 업데이트
  python3 cert_tracker.py --add --cert Security+   # Security+ 진도 업데이트
  python3 cert_tracker.py --status                 # 전체 진도 현황
  python3 cert_tracker.py --status --cert OSCP     # OSCP 진도만 확인
  python3 cert_tracker.py --stats                  # 통계 요약
        """,
    )
    parser.add_argument("--cert", "-c", type=str, help="자격증 선택 (CISSP/CEH/OSCP/Security+)")
    parser.add_argument("--add", "-a", action="store_true", help="학습 진도 업데이트")
    parser.add_argument("--status", "-s", action="store_true", help="진도 현황 확인")
    parser.add_argument("--stats", action="store_true", help="전체 통계 확인")
    parser.add_argument("--list", "-l", action="store_true", help="자격증 목록 출력")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list:
        list_certs()
        return

    if args.add:
        if not args.cert:
            print("--cert 옵션으로 자격증을 지정하세요.")
            print(f"지원: {', '.join(CERT_CURRICULUM.keys())}")
            sys.exit(1)
        update_progress(args.cert)
        return

    if args.status:
        show_status(args.cert)
        return

    if args.stats:
        show_statistics()
        return

    parser = argparse.ArgumentParser()
    parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 자격증 취득 로드맵

### 입문 단계 (0~1년 경력)
1. **CompTIA Security+**: 기초 개념 정립, 취업 연계
2. **CEH**: 공격 기법 이해, 침투 테스트 입문
3. **정보보안기사**: 한국 취업 우대, 법적 자격

### 중급 단계 (2~4년 경력)
1. **OSCP**: 실전 침투 테스트 역량 증명
2. **CISM**: 관리자 역할로 전환 시 취득

### 고급 단계 (5년+ 경력)
1. **CISSP**: 보안 전문가 최고 인증
2. **OSED/OSWE**: 익스플로잇 개발 전문가

### 비용 및 준비 기간 요약

| 자격증 | 준비 기간 | 총 예산(USD) | 취업 활용도 |
|--------|----------|------------|-----------|
| Security+ | 1~3개월 | ~$500 | 높음 (미국/글로벌) |
| 정보보안기사 | 3~6개월 | ~$100 (한화) | 높음 (한국) |
| CEH | 2~4개월 | ~$1,500 | 중간 |
| OSCP | 3~6개월 | ~$1,500~2,500 | 매우 높음 (기술직) |
| CISSP | 6~12개월 | ~$1,000 | 높음 (관리직) |
