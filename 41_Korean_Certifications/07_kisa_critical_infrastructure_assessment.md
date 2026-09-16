> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 주요정보통신기반시설 기술적 취약점 분석·평가 실무 완전 가이드

## 0. 개요 및 법적 근거

### 주요정보통신기반시설 취약점 분석·평가란?

**주요정보통신기반시설 기술적 취약점 분석·평가**는 「정보통신기반 보호법」 제9조(취약점의 분석·평가) 및 과학기술정보통신부·한국인터넷진흥원(KISA)의 고시 기준에 따라 국가 안보 및 국민 생활에 중대한 영향을 미치는 기반시설(금융, 통신, 에너지, 교통, 의료 등)의 전자적 침해사고 예방을 위해 시스템 전반의 보안 취약점을 체계적으로 점검하고 개선하는 법정 의무 진단 제도입니다.

```
[주요정보통신기반시설 취약점 평가 체계]
┌────────────────────────────────────────────────────────────────────────┐
│ 1. 유닉스/리눅스 서버 (Unix Server)       : U-01 ~ U-72 (계정/파일/서비스/패치/로그) │
│ 2. 윈도우 서버 (Windows Server)          : W-01 ~ W-28 (계정/공유/서비스/로그)     │
│ 3. 네트워크 장비 (Cisco/Juniper/L2~L4)   : N-01 ~ N-20 (원격접속/SNMP/라우팅/필터)│
│ 4. 보안 장비 (방화벽/IPS/WAF/VPN)         : S-01 ~ S-15 (정책관리/관리자접근/감사)   │
│ 5. 데이터베이스 (Oracle/MSSQL/MySQL/Postgre): D-01 ~ D-30 (계정/권한/리스너/암호화)  │
│ 6. 웹 애플리케이션 (Web Vulnerability)    : WEB-01 ~ WEB-28 (인젝션/인증/설정오류)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 1. 리눅스 / 유닉스 서버 점검 항목 (Unix / Linux Hardening)

### 핵심 5대 진단 영역 및 배점 기준
- **상(Critical)**: 원격 코드 실행, 관리자 권한 탈취, 루트 직접 로그인 허용 등 침해 위협이 직접적인 항목
- **중(High)**: 권한 상승, 정보 노출, 비인가 서비스 실행 등 잠재적 침해 위협 항목
- **하(Medium)**: 보안 정책 미비, 로깅 및 감사 설정 미흡 등 간접적 위협 항목

### 주요 핵심 점검 항목 상세 (U-01 ~ U-04)

| 항목 코드 | 점검 항목명 | 중요도 | 양호 기준 | 취약 기준 |
|:---|:---|:---:|:---|:---|
| **U-01** | root 계정 원격 접속 제한 | 상 | Telnet/SSH 등 원격 접속 시 root 직접 접속이 차단되어 있는 경우 | root 직접 접속이 허용되어 있는 경우 |
| **U-02** | 패스워드 복잡성 규정 설정 | 상 | 영문/숫자/특수문자 조합 최소 8자리 이상 및 복잡도 설정 완료 | 패스워드 복잡성 정책이 미설정된 경우 |
| **U-03** | 계정 잠금 임계값 설정 | 상 | 5회 이하 로그인 실패 시 계정이 잠기도록 설정된 경우 | 계정 잠금 임계값이 5회 초과이거나 미설정된 경우 |
| **U-04** | 패스워드 파일 보호 (/etc/shadow) | 상 | shadow 패스워드를 사용하고 `/etc/shadow` 권한이 400 또는 000인 경우 | shadow 파일을 사용하지 않거나 타 사용자가 읽을 수 있는 경우 |

### 진단 쉘 스크립트 실무 예제 (Automated Audit Script)

```bash
#!/usr/bin/env bash
# kisa_unix_audit_sample.sh - 주요정보통신기반시설 기술적 취약점 점검 샘플 스크립트

echo "=== [KISA 주요정보통신기반시설 취약점 자동 점검] ==="

# [U-01] root 계정 원격 접속 제한 점검
echo -n "[U-01] root 계정 원격 접속 제한: "
if grep -Eq "^PermitRootLogin[[:space:]]+(no|without-password|prohibit-password)" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[양호] PermitRootLogin 설정이 no/prohibit-password 로 제한되어 있습니다."
else
    echo "[취약] PermitRootLogin 설정이 yes 이거나 주석 처리되어 있어 root 직접 원격 로그인이 가능합니다."
fi

# [U-02] 패스워드 복잡성 설정 점검
echo -n "[U-02] 패스워드 복잡성 규정: "
PW_MINLEN=$(grep -E "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ -n "$PW_MINLEN" ] && [ "$PW_MINLEN" -ge 8 ]; then
    echo "[양호] PASS_MIN_LEN = $PW_MINLEN (8자리 이상)"
else
    echo "[취약] PASS_MIN_LEN 미설정 또는 8자리 미만"
fi

# [U-04] /etc/shadow 파일 권한 점검
echo -n "[U-04] /etc/shadow 파일 권한: "
SHADOW_PERM=$(stat -c "%a" /etc/shadow 2>/dev/null)
if [ "$SHADOW_PERM" = "400" ] || [ "$SHADOW_PERM" = "000" ]; then
    echo "[양호] /etc/shadow 퍼미션: $SHADOW_PERM"
else
    echo "[취약] /etc/shadow 퍼미션 취약 ($SHADOW_PERM) - 권한 400(000)으로 축소 필요"
fi
```

---

## 2. 윈도우 서버 점검 항목 (Windows Server Audit)

### 주요 핵심 점검 항목 (W-01 ~ W-05)

| 항목 코드 | 점검 항목명 | 중요도 | 양호 기준 | 권장 조치 방안 |
|:---|:---|:---:|:---|:---|
| **W-01** | Administrator 계정 이름 변경 | 상 | 기본 Administrator 계정명이 고유 명칭으로 변경된 경우 | 로컬 보안 정책(secpol.msc) → 계정: Administrator 계정 이름 바꾸기 |
| **W-02** | Guest 계정 상태 | 상 | Guest 계정이 비활성화(사용 안 함)된 경우 | `net user guest /active:no` |
| **W-03** | 계정 잠금 임계값 설정 | 상 | 계정 잠금 임계값이 5회 이하로 구성된 경우 | 로컬 보안 정책 → 계정 잠금 정책 → 계정 잠금 임계값: 5회 이하 |
| **W-04** | 불필요한 서비스 제거 | 상 | Alerter, Telnet, Simple TCP/IP, Remote Registry 등 비인가 서비스 중지 | `services.msc` 또는 PowerShell 스크립트로 서비스 정지/비활성화 |
| **W-05** | 기본 공유(Admin$, C$ 등) 제거 | 중 | 관리 목적 기본 공유가 레지스트리를 통해 자동 생성 중단된 경우 | `AutoShareServer` 및 `AutoShareWks` REG_DWORD 값 0 설정 |

### PowerShell 진단 스크립트 예제

```powershell
# Windows Hardening Check (PowerShell)
Write-Host "=== [KISA Windows 서버 취약점 점검] ===" -ForegroundColor Cyan

# W-02 Guest 계정 상태 점검
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest.Enabled -eq $false) {
    Write-Host "[W-02 Guest 계정] [양호] Guest 계정이 비활성화 상태입니다." -ForegroundColor Green
} else {
    Write-Host "[W-02 Guest 계정] [취약] Guest 계정이 활성화되어 있습니다." -ForegroundColor Red
}

# W-05 기본 공유 상태 점검
$smbShares = Get-SmbShare | Where-Object { $_.Name -like "*$" -and $_.Name -notin @("IPC$") }
if ($smbShares) {
    Write-Host "[W-05 기본 공유] [취약] 관리 목적 드라이브 기본 공유($($smbShares.Name -join ', '))가 활성화되어 있습니다." -ForegroundColor Red
} else {
    Write-Host "[W-05 기본 공유] [양호] 드라이브 기본 공유가 비활성화되어 있습니다." -ForegroundColor Green
}
```

---

## 3. 네트워크 및 보안 장비 점검 항목 (Network & Security Devices)

1. **N-01 원격 터미널 접속 보안 (SSH v2 강제)**
   - Telnet(평문 전송) 전면 비활성화, SSH v2 암호화 터미널 사용
   - Cisco IOS: `crypto key generate rsa`, `ip ssh version 2`, `transport input ssh`
2. **N-02 SNMP 커뮤니티 스트링 보안**
   - 기본 커뮤니티 스트링(`public`, `private`) 제거 및 최소 10자리 이상 복합 문자열 설정
   - 가급적 SHA 인증 및 AES 암호화를 지원하는 SNMPv3 적용
3. **N-03 VTY 접근 제어 (ACL 적용)**
   - 관리자 접속 허용 IP를 제한하는 Access Control List(ACL) 구성
   - `access-list 10 permit 192.168.10.0 0.0.0.255`, `line vty 0 4 -> access-class 10 in`
4. **N-04 로깅 및 시스로그(Syslog) 전송**
   - NTP 동기화 후 원격 중앙 SIEM/Syslog 서버로 `logging trap informational` 전송

---

## 4. 데이터베이스 점검 항목 (Database Security: Oracle, MySQL)

1. **D-01 기본 관리자 계정 패스워드 변경 (SYS, SYSTEM, root, sa)**
   - 기본 패스워드(change_on_install, manager 등) 및 널 패스워드 원천 차단
2. **D-02 원격 접속 리스너 보안 (Oracle Listener)**
   - 리스너 패스워드 설정(`ADMIN_RESTRICTIONS_listener=ON`) 및 프로토콜 필터링
3. **D-03 공용 권한(PUBLIC) 남용 방지**
   - 위험한 패키지(`UTL_FILE`, `UTL_HTTP`, `UTL_TCP`, `DBMS_LOB`)의 PUBLIC 실행 권한 REVOKE

---

<a name="english"></a>

# Technical Vulnerability Assessment & Hardening Guide for Critical Information Infrastructure (KISA Benchmark)

## 1. Regulatory Overview
In accordance with South Korea's Critical Information Infrastructure Protection Act (Article 9), government agencies and critical private infrastructure operators must perform rigorous technical vulnerability audits across 6 major technology domains:
1. **Unix/Linux Operating Systems** (U-01 to U-72)
2. **Windows Server Operating Systems** (W-01 to W-28)
3. **Network Infrastructure** (Cisco, Juniper switches/routers)
4. **Security Appliances** (Firewall, IPS, VPN)
5. **Database Management Systems** (Oracle, MSSQL, MySQL, PostgreSQL)
6. **Web Applications** (OWASP & KISA Web Top 28)

## 2. Hardening Verification Matrix
- **Privilege Separation**: Disable direct root/Administrator remote logins.
- **Access Control & ACL**: Enforce SSH v2, restrict VTY management lines to jump boxes.
- **Audit & Logging**: Forward all security event logs (auth, syslog, auditd) to remote immutable SIEM collectors.
