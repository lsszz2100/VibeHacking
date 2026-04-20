# PAM 및 인증 강화 — 계정·접근 통제

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
