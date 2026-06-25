> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# PAM 및 인증 강화 — 계정·접근 통제

## 0. 초보자를 위한 개념 이해

### PAM이란?

**PAM(Pluggable Authentication Modules, 플러그인 가능한 인증 모듈)**은 Linux에서 인증 방법을 유연하게 관리하는 프레임워크입니다.

**비유:** 건물 출입 시스템
```
건물 출입:
  키카드 확인
  → 지문 인식
  → 방문 목적 확인
  → 출입 기록 저장
  
PAM:
  비밀번호 확인 (pam_unix)
  → OTP 확인 (pam_google_authenticator)
  → 계정 잠금 여부 (pam_tally2)
  → 세션 로그 기록 (pam_lastlog)
```

**PAM이 없었을 때의 문제:**
```
옛날 방식:
  각 프로그램(ssh, login, sudo)이 직접 인증 코드 포함
  → 인증 방식 변경 시 모든 프로그램 수정 필요
  
PAM 도입 후:
  모든 프로그램이 PAM 라이브러리를 호출
  → PAM 설정만 바꾸면 모든 프로그램의 인증 방식 변경
```

### 왜 PAM 설정이 보안에 중요한가?

```
잘못된 PAM 설정의 결과:
  - 비밀번호 복잡도 없음 → 브루트포스 취약
  - 계정 잠금 없음 → 무한 시도 가능
  - 로그 없음 → 침해 발생해도 모름
  - OTP 없음 → 비밀번호 유출 시 즉시 침해

올바른 PAM 설정:
  - 최소 12자, 복잡도 요구
  - 5회 실패 시 계정 잠금
  - 모든 로그인 시도 기록
  - sudo 사용 시 MFA 적용
```

### 주요 PAM 모듈

| 모듈 | 기능 |
|------|------|
| `pam_unix` | 기본 유닉스 비밀번호 인증 |
| `pam_tally2` | 로그인 실패 횟수 추적, 계정 잠금 |
| `pam_faillock` | `pam_tally2` 후계자 (최신 배포판) |
| `pam_pwquality` | 비밀번호 복잡도 정책 |
| `pam_google_authenticator` | Google OTP(TOTP) 지원 |
| `pam_access` | IP/호스트 기반 접근 제어 |
| `pam_limits` | 리소스 제한 (파일 수, 프로세스 수) |

---

## 1. PAM (Pluggable Authentication Modules) 개요

```
PAM 구조:
  애플리케이션 (ssh, login, sudo...)
      ↓
  PAM 라이브러리 (/lib/security/)
      ↓
  설정 파일 (/etc/pam.d/서비스명)
      ↓
  모듈 체인 실행 (순서 중요)

4가지 관리 그룹:
  auth     → 인증 (패스워드, 지문, OTP)
  account  → 계정 상태 확인 (만료, 잠금)
  session  → 세션 설정/해제 (로그, 환경)
  password → 패스워드 변경 정책

제어 플래그:
  required   → 실패해도 계속, 최종에서 실패 반환
  requisite  → 실패 시 즉시 반환 (빠른 거부)
  sufficient → 성공 시 이후 모듈 건너뜀
  optional   → 결과에 영향 없음
```

---

## 2. 패스워드 정책 강화

### 2-1. pam_pwquality 설정

PAM 설정으로 Linux 인증 정책을 강화합니다. 패스워드 복잡도, 계정 잠금, 로그인 시도 제한 등을 구성합니다.

```bash
# 설치
apt install libpam-pwquality  # Debian
dnf install libpwquality      # RHEL

# /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14          # 최소 14자
minclass = 4         # 대문자/소문자/숫자/특수문자 모두 필수
maxrepeat = 3        # 같은 문자 3회 연속 금지
maxclassrepeat = 4   # 같은 종류 문자 4회 연속 금지
gecoscheck = 1       # 계정 이름 포함 금지
dcredit = -1         # 숫자 최소 1개
ucredit = -1         # 대문자 최소 1개
lcredit = -1         # 소문자 최소 1개
ocredit = -1         # 특수문자 최소 1개
dictcheck = 1        # 사전 단어 금지
usercheck = 1        # 사용자명 포함 금지
EOF

# /etc/pam.d/common-password (Ubuntu)
# /etc/pam.d/system-auth (RHEL)
# password requisite pam_pwquality.so retry=3
```

### 2-2. 패스워드 이력 및 만료 정책

pam_pwhistory.so로 이전에 사용한 비밀번호의 재사용을 차단합니다. remember=5로 최근 5개 비밀번호와 동일한 것을 사용하지 못하게 합니다.

```bash
# /etc/pam.d/common-password에 이력 추가
# password required pam_pwhistory.so remember=12 use_authtok

# /etc/login.defs — 패스워드 만료 정책
cat >> /etc/login.defs << 'EOF'
PASS_MAX_DAYS   90    # 최대 90일
PASS_MIN_DAYS   1     # 최소 1일 (변경 후 즉시 재변경 방지)
PASS_WARN_AGE   14    # 만료 14일 전 경고
EOF

# 기존 계정에 만료 정책 적용
chage -M 90 -m 1 -W 14 username

# 계정 상태 확인
chage -l username
```

### 2-3. 계정 잠금 정책 (pam_faillock)

PAM 설정으로 Linux 인증 정책을 강화합니다. 패스워드 복잡도, 계정 잠금, 로그인 시도 제한 등을 구성합니다.

```bash
# /etc/pam.d/common-auth 상단에 추가 (Ubuntu 20.04+)
# auth required pam_faillock.so preauth silent deny=5 unlock_time=900
# auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900

# /etc/security/faillock.conf
cat > /etc/security/faillock.conf << 'EOF'
deny = 5               # 5회 실패 시 잠금
unlock_time = 900      # 15분 후 자동 해제
fail_interval = 900    # 15분 내 실패 횟수 카운트
even_deny_root         # root 계정도 적용
EOF

# 잠금 상태 확인
faillock --user username

# 수동 잠금 해제
faillock --user username --reset
```

---

## 3. SSH 인증 강화

### 3-1. SSH 키 인증 전용 설정

SSH 키 기반 인증을 설정합니다. 비밀번호 대신 공개키/개인키 쌍을 사용하여 더 안전하게 원격 서버에 접속할 수 있습니다.

```bash
# /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config << 'EOF'

# 인증 방식
PasswordAuthentication no      # 패스워드 인증 비활성화
PubkeyAuthentication yes       # 키 인증만 허용
PermitRootLogin no             # root 직접 로그인 금지
AuthorizedKeysFile .ssh/authorized_keys

# 접속 제한
AllowUsers admin deploy        # 허용 사용자 화이트리스트
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 10

# 기능 제한
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# 보안 강화
Protocol 2
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no

# 강력한 암호 알고리즘만 허용
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF

sshd -t && systemctl reload sshd
```

### 3-2. SSH 2FA (Google Authenticator)


SSH에 OTP(One-Time Password) 2단계 인증을 추가하는 설정입니다. Google Authenticator PAM 모듈을 설치하고 `sshd_config`에서 `ChallengeResponseAuthentication yes`를 설정하면 패스워드+OTP 인증이 적용됩니다.

```bash
# 설치
apt install libpam-google-authenticator

# 사용자별 설정
google-authenticator
# → QR코드 스캔 (앱에 등록)
# → 시크릿 키, 비상 코드 저장

# /etc/pam.d/sshd 상단에 추가
# auth required pam_google_authenticator.so

# /etc/ssh/sshd_config
# ChallengeResponseAuthentication yes
# AuthenticationMethods publickey,keyboard-interactive

systemctl reload sshd
```

---

## 4. sudo 보안 강화

sudoers 파일로 sudo 권한을 세밀하게 제어합니다. visudo로만 편집해야 문법 오류를 방지할 수 있으며 최소 권한 원칙을 적용합니다.

```bash
# /etc/sudoers (visudo 사용 필수)

# 기본 원칙: 최소 권한
# admin 그룹만 sudo 허용
%admin ALL=(ALL:ALL) ALL

# 특정 명령만 허용
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx

# root 쉘 획득 금지
Defaults noexec          # 명령 내 쉘 실행 금지
Defaults requiretty      # TTY 없으면 sudo 불가
Defaults use_pty         # PTY 할당 (로깅 개선)
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output  # 입출력 전체 로깅
Defaults passwd_timeout=1       # 패스워드 입력 1분 타임아웃
Defaults timestamp_timeout=5    # 인증 캐시 5분

# sudo 남용 탐지
Defaults syslog=auth
```

---

## 5. 계정 및 세션 보안

불필요한 시스템 계정을 잠그고 셸 접속을 차단합니다. /sbin/nologin이나 /bin/false를 셸로 설정하여 로그인을 방지합니다.

```bash
# 불필요 시스템 계정 잠금
for user in games news uucp proxy www-data backup list irc gnats; do
  usermod -L -s /usr/sbin/nologin $user 2>/dev/null
done

# 빈 패스워드 계정 탐지
awk -F: '($2 == "" ) { print $1 }' /etc/shadow

# UID 0 계정 탐지 (root 외 금지)
awk -F: '($3 == 0) { print $1 }' /etc/passwd

# 로그인 불필요 계정 nologin 설정
usermod -s /usr/sbin/nologin serviceaccount

# 세션 타임아웃 설정
cat >> /etc/profile.d/timeout.sh << 'EOF'
TMOUT=600           # 10분 무활동 시 자동 로그아웃
readonly TMOUT
export TMOUT
EOF

# /etc/security/limits.conf — 리소스 제한
cat >> /etc/security/limits.conf << 'EOF'
*    hard    nofile    65536
*    soft    nofile    65536
*    hard    nproc     1024
*    soft    nproc     1024
@users hard  maxlogins 3     # 동시 로그인 3개 제한
EOF
```

---

## 6. 감사 로깅 (auditd)

auditd 감사 데몬을 설치하고 시작합니다. 파일 접근, 명령어 실행, 권한 변경 등 보안 이벤트를 로그로 기록합니다.

```bash
# auditd 설치 및 시작
apt install auditd audispd-plugins
systemctl enable --now auditd

# /etc/audit/rules.d/hardening.rules
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# 버퍼 크기 및 실패 동작
-b 8192
-f 1

# 시스템 시간 변경 감사
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change

# 사용자/그룹 파일 변경 감사
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd-config

# 로그인 감사
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins

# 권한 상승 감사
-a always,exit -F arch=b64 -S setuid -k setuid
-a always,exit -F arch=b64 -S setgid -k setgid

# 파일 삭제 감사
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat \
  -F auid>=1000 -F auid!=4294967295 -k delete

# 커널 모듈 로딩 감사
-w /sbin/insmod  -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# 네트워크 설정 변경
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale

# 규칙 잠금 (재부팅 전까지 변경 불가)
-e 2
EOF

augenrules --load
systemctl restart auditd
```

```bash
# 감사 로그 조회
ausearch -k identity -ts today     # 오늘 계정 변경 이벤트
ausearch -k sshd-config -ts recent # SSH 설정 변경
ausearch -ua 0 -ts today           # root의 오늘 활동
aureport --summary                 # 전체 요약
aureport --failed                  # 실패 이벤트만
```

---

## 7. 자동화 점검 도구

```python
import subprocess
import pwd
import spwd
import os
import stat
import argparse
from pathlib import Path

def check_empty_passwords() -> list[str]:
    risky = []
    try:
        for entry in spwd.getspall():
            if entry.sp_pwd in ("", "!!", None):
                risky.append(entry.sp_nam)
    except PermissionError:
        risky.append("[root 권한 필요]")
    return risky

def check_uid_zero() -> list[str]:
    return [p.pw_name for p in pwd.getpwall() if p.pw_uid == 0 and p.pw_name != "root"]

def check_suid_files() -> list[str]:
    suid_files = []
    safe_suid = {"/usr/bin/sudo", "/usr/bin/passwd", "/bin/su",
                 "/usr/bin/newgrp", "/usr/bin/gpasswd"}
    try:
        result = subprocess.run(
            ["find", "/", "-type", "f", "-perm", "-4000",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            capture_output=True, text=True, timeout=30
        )
        for f in result.stdout.splitlines():
            if f not in safe_suid:
                suid_files.append(f)
    except subprocess.TimeoutExpired:
        suid_files.append("[타임아웃]")
    return suid_files

def check_world_writable() -> list[str]:
    try:
        result = subprocess.run(
            ["find", "/etc", "/usr", "/bin", "/sbin",
             "-type", "f", "-perm", "-o+w"],
            capture_output=True, text=True, timeout=20
        )
        return result.stdout.splitlines()
    except Exception:
        return []

def check_password_policy() -> list[str]:
    issues = []
    login_defs = Path("/etc/login.defs").read_text()
    if "PASS_MAX_DAYS" not in login_defs:
        issues.append("PASS_MAX_DAYS 미설정")
    else:
        for line in login_defs.splitlines():
            if line.startswith("PASS_MAX_DAYS"):
                days = int(line.split()[1])
                if days > 90:
                    issues.append(f"PASS_MAX_DAYS={days} (90 이하 권장)")
    return issues

def run_audit() -> None:
    print("\n" + "=" * 50)
    print("리눅스 보안 감사 결과")
    print("=" * 50)

    empty_pw = check_empty_passwords()
    print(f"\n[빈 패스워드 계정]: {empty_pw or '없음'}")

    uid_zero = check_uid_zero()
    if uid_zero:
        print(f"\n[!] UID 0 비-root 계정: {uid_zero}")
    else:
        print("\n[UID 0]: root만 존재 (정상)")

    suid = check_suid_files()
    if suid:
        print(f"\n[!] 비표준 SUID 파일 {len(suid)}개:")
        for f in suid[:10]:
            print(f"  {f}")

    ww = check_world_writable()
    if ww:
        print(f"\n[!] 전체 쓰기 가능 파일 {len(ww)}개:")
        for f in ww[:10]:
            print(f"  {f}")

    pw_issues = check_password_policy()
    if pw_issues:
        print(f"\n[!] 패스워드 정책 문제:")
        for i in pw_issues:
            print(f"  {i}")

    print()

if __name__ == "__main__":
    run_audit()
```

<!-- detect-validate-26 -->
## 인증 강화 검증 — 정책이 실제로 강제되는가

PAM·패스워드 정책은 *설정 파일에 적었는가*가 아니라 **로그인 경로에서 실제 강제되는가**로 판정한다. 패스워드 복잡도, 계정 잠금, 로그인 실패 로깅이 런타임에 작동하는지 직접 확인한다. 검증은 **소유·테스트 계정**에서만.

### 통제 → 실패 모드 → 검증 방법 → 양호 신호

| 통제 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 패스워드 복잡도 | 약한 암호 통과 | pwquality 규칙 적용 확인 | minlen/minclass 강제 |
| 계정 잠금 | 무제한 브루트포스 | faillock 카운트 | N회 실패 후 잠금 |
| 로그인 실패 로깅 | 무로그 침해 | auth.log/journald | 실패 시 로그 라인 |
| root 직접 로그인 | 책임추적 불가 | PermitRootLogin no | 콘솔 외 root 차단 |

### 방어 검증 (직접 확인)

```bash
# 1) pwquality 정책이 실제 적용됐는지 — 약한 암호 거부를 테스트 계정에서 확인
grep -E '^(minlen|minclass|dcredit|ucredit)' /etc/security/pwquality.conf
# 2) 계정 잠금이 강제되는지 — faillock 설정/현재 실패 카운트 확인
command -v faillock >/dev/null && sudo faillock --user testuser 2>/dev/null | tail -3
```

> 검증은 반드시 **소유·테스트 계정**에서만 한다. "정책을 적었다"와 "약한 암호가 실제 거부된다"는 다르다 — 실패 시도로 잠금·로그를 직접 확인한다([[01_Linux_Basics]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# PAM and Authentication Hardening — Account and Access Control

## 1. PAM (Pluggable Authentication Modules) Overview

```
PAM Architecture:
  Application (ssh, login, sudo...)
      ↓
  PAM Library (/lib/security/)
      ↓
  Configuration files (/etc/pam.d/<service>)
      ↓
  Module chain execution (order matters)

4 Management Groups:
  auth     → Authentication (password, fingerprint, OTP)
  account  → Account status (expiry, lock)
  session  → Session setup/teardown (logging, environment)
  password → Password change policy

Control Flags:
  required   → Continues on failure, returns failure at end
  requisite  → Returns immediately on failure (fast reject)
  sufficient → Skips remaining modules on success
  optional   → Result has no effect
```

---

## 2. Password Policy Hardening

### 2-1. pam_pwquality Configuration

Configure Linux authentication policies via PAM. Set up password complexity, account lockout, and login attempt limits.

```bash
# Install
apt install libpam-pwquality  # Debian
dnf install libpwquality      # RHEL

# /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14          # Minimum 14 characters
minclass = 4         # All of: uppercase/lowercase/digits/special chars
maxrepeat = 3        # No more than 3 consecutive identical characters
maxclassrepeat = 4   # No more than 4 consecutive characters of same class
gecoscheck = 1       # Prohibit use of account name
dcredit = -1         # Minimum 1 digit
ucredit = -1         # Minimum 1 uppercase
lcredit = -1         # Minimum 1 lowercase
ocredit = -1         # Minimum 1 special character
dictcheck = 1        # Prohibit dictionary words
usercheck = 1        # Prohibit username inclusion
EOF

# /etc/pam.d/common-password (Ubuntu)
# /etc/pam.d/system-auth (RHEL)
# password requisite pam_pwquality.so retry=3
```

### 2-2. Password History and Expiry Policy

Use pam_pwhistory.so to block reuse of previously used passwords. Setting remember=5 prevents reuse of the last 5 passwords.

```bash
# Add history to /etc/pam.d/common-password
# password required pam_pwhistory.so remember=12 use_authtok

# /etc/login.defs — password expiry policy
cat >> /etc/login.defs << 'EOF'
PASS_MAX_DAYS   90    # Maximum 90 days
PASS_MIN_DAYS   1     # Minimum 1 day (prevent immediate re-change)
PASS_WARN_AGE   14    # Warn 14 days before expiry
EOF

# Apply expiry policy to existing accounts
chage -M 90 -m 1 -W 14 username

# Check account status
chage -l username
```

### 2-3. Account Lockout Policy (pam_faillock)

Configure Linux authentication policies via PAM. Set up password complexity, account lockout, and login attempt limits.

```bash
# Add to top of /etc/pam.d/common-auth (Ubuntu 20.04+)
# auth required pam_faillock.so preauth silent deny=5 unlock_time=900
# auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900

# /etc/security/faillock.conf
cat > /etc/security/faillock.conf << 'EOF'
deny = 5               # Lock after 5 failures
unlock_time = 900      # Auto-unlock after 15 minutes
fail_interval = 900    # Count failures within 15 minutes
even_deny_root         # Apply to root account too
EOF

# Check lock status
faillock --user username

# Manually unlock
faillock --user username --reset
```

---

## 3. SSH Authentication Hardening

### 3-1. SSH Key-Only Authentication

Configure SSH key-based authentication. Use public/private key pairs instead of passwords for more secure remote server access.

```bash
# /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config << 'EOF'

# Authentication methods
PasswordAuthentication no      # Disable password authentication
PubkeyAuthentication yes       # Allow only key authentication
PermitRootLogin no             # Prohibit direct root login
AuthorizedKeysFile .ssh/authorized_keys

# Access restrictions
AllowUsers admin deploy        # Whitelist of allowed users
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 10

# Feature restrictions
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# Security hardening
Protocol 2
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no

# Allow only strong cryptographic algorithms
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF

sshd -t && systemctl reload sshd
```

### 3-2. SSH 2FA (Google Authenticator)

Add OTP (One-Time Password) two-factor authentication to SSH. Install the Google Authenticator PAM module and set `ChallengeResponseAuthentication yes` in `sshd_config` to apply password+OTP authentication.

```bash
# Install
apt install libpam-google-authenticator

# Configure per user
google-authenticator
# → Scan QR code (register in app)
# → Save secret key and emergency codes

# Add to top of /etc/pam.d/sshd
# auth required pam_google_authenticator.so

# /etc/ssh/sshd_config
# ChallengeResponseAuthentication yes
# AuthenticationMethods publickey,keyboard-interactive

systemctl reload sshd
```

---

## 4. sudo Security Hardening

Control sudo privileges precisely via the sudoers file. Only edit with visudo to prevent syntax errors, and apply the principle of least privilege.

```bash
# /etc/sudoers (must use visudo)

# Basic principle: least privilege
# Only allow sudo for admin group
%admin ALL=(ALL:ALL) ALL

# Allow only specific commands
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx

# Prevent obtaining root shell
Defaults noexec          # Prohibit shell execution within commands
Defaults requiretty      # sudo not allowed without TTY
Defaults use_pty         # Allocate PTY (improved logging)
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output  # Log all input/output
Defaults passwd_timeout=1       # 1-minute password input timeout
Defaults timestamp_timeout=5    # 5-minute authentication cache

# Detect sudo abuse
Defaults syslog=auth
```

---

## 5. Account and Session Security

Lock unnecessary system accounts and block shell access. Set shell to /sbin/nologin or /bin/false to prevent login.

```bash
# Lock unnecessary system accounts
for user in games news uucp proxy www-data backup list irc gnats; do
  usermod -L -s /usr/sbin/nologin $user 2>/dev/null
done

# Detect accounts with empty passwords
awk -F: '($2 == "" ) { print $1 }' /etc/shadow

# Detect UID 0 accounts (only root should have UID 0)
awk -F: '($3 == 0) { print $1 }' /etc/passwd

# Set nologin for service accounts
usermod -s /usr/sbin/nologin serviceaccount

# Session timeout
cat >> /etc/profile.d/timeout.sh << 'EOF'
TMOUT=600           # Auto-logout after 10 minutes of inactivity
readonly TMOUT
export TMOUT
EOF

# /etc/security/limits.conf — resource limits
cat >> /etc/security/limits.conf << 'EOF'
*    hard    nofile    65536
*    soft    nofile    65536
*    hard    nproc     1024
*    soft    nproc     1024
@users hard  maxlogins 3     # Limit to 3 simultaneous logins
EOF
```

---

## 6. Audit Logging (auditd)

Install and start the auditd daemon. Log security events such as file access, command execution, and privilege changes.

```bash
# Install and start auditd
apt install auditd audispd-plugins
systemctl enable --now auditd

# /etc/audit/rules.d/hardening.rules
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Buffer size and failure behavior
-b 8192
-f 1

# Audit system time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change

# Audit user/group file changes
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd-config

# Audit logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins

# Audit privilege escalation
-a always,exit -F arch=b64 -S setuid -k setuid
-a always,exit -F arch=b64 -S setgid -k setgid

# Audit file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat \
  -F auid>=1000 -F auid!=4294967295 -k delete

# Audit kernel module loading
-w /sbin/insmod  -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Audit network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale

# Lock rules (no changes until reboot)
-e 2
EOF

augenrules --load
systemctl restart auditd
```

```bash
# Query audit logs
ausearch -k identity -ts today     # Today's account change events
ausearch -k sshd-config -ts recent # SSH config changes
ausearch -ua 0 -ts today           # root activity today
aureport --summary                 # Overall summary
aureport --failed                  # Failed events only
```

---

## 7. Automated Audit Tool

```python
import subprocess
import pwd
import spwd
import os
import stat
import argparse
from pathlib import Path

def check_empty_passwords() -> list[str]:
    risky = []
    try:
        for entry in spwd.getspall():
            if entry.sp_pwd in ("", "!!", None):
                risky.append(entry.sp_nam)
    except PermissionError:
        risky.append("[root privileges required]")
    return risky

def check_uid_zero() -> list[str]:
    return [p.pw_name for p in pwd.getpwall() if p.pw_uid == 0 and p.pw_name != "root"]

def check_suid_files() -> list[str]:
    suid_files = []
    safe_suid = {"/usr/bin/sudo", "/usr/bin/passwd", "/bin/su",
                 "/usr/bin/newgrp", "/usr/bin/gpasswd"}
    try:
        result = subprocess.run(
            ["find", "/", "-type", "f", "-perm", "-4000",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            capture_output=True, text=True, timeout=30
        )
        for f in result.stdout.splitlines():
            if f not in safe_suid:
                suid_files.append(f)
    except subprocess.TimeoutExpired:
        suid_files.append("[timeout]")
    return suid_files

def check_world_writable() -> list[str]:
    try:
        result = subprocess.run(
            ["find", "/etc", "/usr", "/bin", "/sbin",
             "-type", "f", "-perm", "-o+w"],
            capture_output=True, text=True, timeout=20
        )
        return result.stdout.splitlines()
    except Exception:
        return []

def check_password_policy() -> list[str]:
    issues = []
    login_defs = Path("/etc/login.defs").read_text()
    if "PASS_MAX_DAYS" not in login_defs:
        issues.append("PASS_MAX_DAYS not configured")
    else:
        for line in login_defs.splitlines():
            if line.startswith("PASS_MAX_DAYS"):
                days = int(line.split()[1])
                if days > 90:
                    issues.append(f"PASS_MAX_DAYS={days} (90 or less recommended)")
    return issues

def run_audit() -> None:
    print("\n" + "=" * 50)
    print("Linux Security Audit Results")
    print("=" * 50)

    empty_pw = check_empty_passwords()
    print(f"\n[Empty Password Accounts]: {empty_pw or 'None'}")

    uid_zero = check_uid_zero()
    if uid_zero:
        print(f"\n[!] Non-root UID 0 accounts: {uid_zero}")
    else:
        print("\n[UID 0]: Only root exists (normal)")

    suid = check_suid_files()
    if suid:
        print(f"\n[!] Non-standard SUID files ({len(suid)}):")
        for f in suid[:10]:
            print(f"  {f}")

    ww = check_world_writable()
    if ww:
        print(f"\n[!] World-writable files ({len(ww)}):")
        for f in ww[:10]:
            print(f"  {f}")

    pw_issues = check_password_policy()
    if pw_issues:
        print(f"\n[!] Password policy issues:")
        for i in pw_issues:
            print(f"  {i}")

    print()

if __name__ == "__main__":
    run_audit()
```

<!-- detect-validate-26 -->
## Auth-Hardening Validation — Is the Policy Actually Enforced?

PAM and password policy are judged not by *whether they are written in a config file* but by **whether they are actually enforced on the login path**. Verify that password complexity, account lockout, and failed-login logging work at runtime. Validate only on **owned / test accounts**.

### Control -> Failure mode -> Validation method -> Healthy signal

| Control | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Password complexity | Weak password passes | Confirm pwquality rules | minlen/minclass enforced |
| Account lockout | Unlimited brute force | faillock counter | Lock after N failures |
| Failed-login logging | Silent compromise | auth.log/journald | Log line on failure |
| Direct root login | No accountability | PermitRootLogin no | root blocked except console |

### Defense validation (verify directly)

```bash
# 1) Whether pwquality is actually applied — confirm weak-password rejection on a test account
grep -E '^(minlen|minclass|dcredit|ucredit)' /etc/security/pwquality.conf
# 2) Whether lockout is enforced — check faillock config / current failure count
command -v faillock >/dev/null && sudo faillock --user testuser 2>/dev/null | tail -3
```

> Validate only on **owned / test accounts**. "The policy is written" differs from "a weak password is actually rejected" — confirm lockout and logs via failed attempts directly ([[01_Linux_Basics]], [[13_SOC_Blue_Team]]).
