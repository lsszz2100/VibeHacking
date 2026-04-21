# Linux 필수 명령어 완전 정리

## 1. 파일 및 디렉토리 조작

### 기본 탐색

리눅스 파일시스템 탐색에 가장 기본이 되는 명령어들입니다. `pwd`로 현재 위치를 확인하고 `ls -al`로 숨김 파일을 포함한 전체 목록을 출력하며, `find`는 조건(이름, 권한 등)에 따라 파일을 검색할 때 사용합니다.

```bash
pwd                    # 현재 디렉토리 확인
ls -al                 # 숨김 파일 포함 상세 목록
ls -alh                # 사람이 읽기 쉬운 파일 크기
cd /var/log            # 절대 경로로 이동
cd ..                  # 상위 디렉토리
cd ~                   # 홈 디렉토리
find / -name "*.conf"  # 전체 시스템에서 파일 검색
find / -perm -4000     # SetUID 파일 검색 (보안 감사에 매우 중요)
locate passwd          # 데이터베이스 기반 빠른 파일 검색
```

### 파일 조작

파일과 디렉토리를 복사·이동·삭제하는 기본 명령어입니다. `rm -rf`는 되돌릴 수 없으므로 경로를 반드시 확인하고 실행해야 하며, `ln -s`로 심볼릭 링크를 만들어 설정 파일 관리에 활용합니다.

```bash
cp -r src/ dst/        # 디렉토리 재귀 복사
mv oldname newname     # 파일 이동/이름 변경
rm -rf dirName         # 디렉토리 강제 삭제 (주의!)
mkdir -p a/b/c         # 중첩 디렉토리 일괄 생성
touch filename         # 빈 파일 생성 또는 타임스탬프 갱신
ln -s /etc/passwd sym  # 심볼릭 링크 생성
```

### 파일 내용 확인

파일 내용을 읽고 검색하는 명령어들입니다. `tail -f`는 로그를 실시간으로 모니터링할 때 필수이며, `grep`과 `awk`는 침투테스트 시 로그 파싱·자격증명 추출 등에 자주 조합해 사용합니다.

```bash
cat /etc/passwd        # 파일 전체 출력
head -20 /etc/log      # 앞 20줄 출력
tail -f /var/log/syslog  # 실시간 로그 모니터링 (F 옵션 중요)
less /etc/passwd       # 페이지 단위 보기
grep "root" /etc/passwd  # 특정 문자열 검색
grep -r "password" /etc/  # 디렉토리 재귀 검색
grep -i "error" /var/log/syslog  # 대소문자 무시
awk -F: '{print $1}' /etc/passwd  # 필드 구분자로 파싱
```

---

## 2. 사용자 및 권한 관리

### 사용자 계정 관리

리눅스 사용자 계정을 생성·수정·삭제하는 명령어입니다. `usermod -aG sudo`는 계정에 관리자 권한을 부여하고, `last`·`lastlog`는 로그인 이력 포렌식에 활용합니다.

```bash
useradd username       # 사용자 추가
useradd -m -s /bin/bash username  # 홈 디렉토리와 쉘 지정
passwd username        # 비밀번호 설정
userdel -r username    # 사용자 삭제 (홈 디렉토리 포함)
usermod -aG sudo username  # sudo 그룹에 추가
id username            # UID, GID, 그룹 정보 확인
who                    # 현재 로그인 사용자
w                      # 로그인 사용자 및 작업 상태
last                   # 로그인 이력
lastlog                # 마지막 로그인 시간
```

### 파일 권한

파일 접근 권한을 설정하는 명령어입니다. 숫자(8진수)로 `소유자/그룹/기타` 권한을 한 번에 지정할 수 있으며, 웹 서버 파일은 644~755 범위로 관리하는 것이 기본 보안 원칙입니다.

```bash
chmod 755 file         # rwxr-xr-x
chmod 644 file         # rw-r--r--
chmod +x script.sh     # 실행 권한 추가
chown root:root file   # 소유자/그룹 변경
chown -R www-data /var/www  # 재귀적 소유자 변경
```

#### 권한 숫자 계산

리눅스 파일 권한은 r(읽기)=4, w(쓰기)=2, x(실행)=1의 합으로 표현됩니다. 예를 들어 755는 소유자에게 전체 권한, 그룹과 기타 사용자에게 읽기·실행만 허용한 것입니다.

```
r(읽기)  = 4
w(쓰기)  = 2
x(실행)  = 1

755 = rwx(7) r-x(5) r-x(5)  → 소유자: 전체, 그룹/기타: 읽기+실행
644 = rw-(6) r--(4) r--(4)  → 소유자: 읽기+쓰기, 나머지: 읽기만
```

### SetUID / SetGID (보안 핵심)

SetUID(SUID)가 설정된 파일은 실행 시 파일 소유자의 권한으로 동작합니다. 공격자는 `find / -perm -4000`으로 SUID 파일을 전수조사하여 권한 상승 경로로 악용할 수 있으므로, 불필요한 SUID 비트는 반드시 제거해야 합니다.

```bash
# SetUID: 파일 실행 시 소유자 권한으로 실행
chmod 4755 file        # SetUID 설정
chmod u+s file         # 동일

# SetGID: 파일 실행 시 그룹 권한으로 실행
chmod 2755 file        # SetGID 설정

# 시스템 내 SetUID 파일 전수조사 (해킹 시 필수)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# 대표적인 SetUID 파일들
ls -la /usr/bin/passwd   # passwd는 root 권한으로 shadow 수정
ls -la /bin/su
ls -la /usr/bin/sudo
```

---

## 3. 프로세스 관리


실행 중인 프로세스를 확인하고 제어하는 명령어들입니다. 침투 후 내부 정찰 시 `ps aux`로 실행 중인 서비스를 파악하고, `nohup command &`로 세션 종료 후에도 백도어를 유지하는 기법에도 활용됩니다.

```bash
ps aux                 # 전체 프로세스 목록
ps -ef | grep apache   # 특정 프로세스 검색
top                    # 실시간 프로세스 모니터링
htop                   # 향상된 프로세스 모니터링
kill -9 PID            # 강제 종료
killall apache2        # 이름으로 프로세스 종료
nice -n 10 process     # 우선순위 낮춰 실행
nohup command &        # 터미널 종료 후에도 실행 유지
```

---

## 4. 네트워크 명령어


네트워크 상태를 확인하는 명령어들입니다. `netstat -antp`나 `ss -tuln`으로 열린 포트와 연결을 확인하고, `curl`·`wget`은 침투 테스트 시 파일 다운로드나 HTTP 헤더 수집에 활용합니다.

```bash
ifconfig               # 네트워크 인터페이스 정보 (구버전)
ip addr show           # 네트워크 인터페이스 정보 (신버전)
ip route show          # 라우팅 테이블
netstat -tuln          # 열린 포트 확인
netstat -antp          # 연결 상태 및 PID 확인
ss -tuln               # netstat 대체 (더 빠름)
ping -c 4 8.8.8.8      # 연결 테스트
traceroute 8.8.8.8     # 경로 추적
nslookup google.com    # DNS 조회
dig google.com         # 상세 DNS 조회
dig +short google.com  # 간단한 IP 조회
host google.com        # 호스트 정보 조회
curl -I http://site.com  # HTTP 헤더만 조회
wget http://site.com/file  # 파일 다운로드
```

---

## 5. 아카이브 및 압축


파일을 압축·해제하는 명령어입니다. `tar`의 옵션 조합을 외워두면 데이터 수집 및 전송, 포렌식 이미지 보존 등 다양한 상황에서 활용할 수 있습니다.

```bash
tar -czvf archive.tar.gz dir/    # gzip 압축
tar -xzvf archive.tar.gz         # gzip 해제
tar -cjvf archive.tar.bz2 dir/   # bzip2 압축 (높은 압축률)
tar -xjvf archive.tar.bz2        # bzip2 해제
zip -r archive.zip dir/          # zip 압축
unzip archive.zip                # zip 해제
unzip -P password archive.zip    # 암호화된 zip 해제
```

---

## 6. 패키지 관리

### Debian/Ubuntu/Kali 계열

Debian/Ubuntu/Kali 계열 리눅스의 패키지 관리 명령어입니다. `apt-get update`로 저장소 목록을 갱신한 후 `apt-get install`로 도구를 설치하며, 침투테스트 환경 구성 시 반드시 숙지해야 합니다.

```bash
apt-get update              # 패키지 목록 갱신
apt-get upgrade             # 설치된 패키지 업그레이드
apt-get install nmap        # 패키지 설치
apt-get remove nmap         # 패키지 제거
apt-get autoremove          # 불필요한 패키지 제거
dpkg -l | grep nmap         # 설치 여부 확인
```

### RedHat/CentOS/Fedora 계열

RedHat/CentOS/Fedora 계열 리눅스의 패키지 관리 명령어입니다. 엔터프라이즈 환경에서는 RHEL 계열이 많으므로 `yum` 또는 `dnf` 명령어 사용법도 함께 익혀두는 것이 좋습니다.

```bash
yum update                  # 패키지 업데이트
yum install nmap            # 패키지 설치
rpm -qa | grep nmap         # 설치 확인
```

---

## 7. 텍스트 처리 (보안 분석에 필수)


로그 파일과 텍스트 데이터를 분석하는 파이프라인 명령어입니다. `grep | awk | sort | uniq -c` 조합은 공격 IP 추출, 접근 패턴 파악 등 보안 분석에서 가장 많이 사용하는 원라이너입니다.

```bash
# 로그에서 특정 IP만 추출
grep "192.168" access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# 비밀번호 파일에서 UID가 0인 계정 찾기 (루트 권한 계정)
awk -F: '$3==0 {print}' /etc/passwd

# sed로 문자열 치환
sed -i 's/old_text/new_text/g' file.txt

# cut으로 필드 추출
cut -d: -f1 /etc/passwd      # 사용자명만 추출
cut -d: -f1,3 /etc/passwd    # 사용자명과 UID 추출

# 중복 제거 및 정렬
cat list.txt | sort | uniq   # 정렬 후 중복 제거
cat list.txt | sort | uniq -c | sort -rn  # 빈도수 포함

# 파이프라인을 활용한 복잡한 분석
cat /var/log/auth.log | grep "Failed" | awk '{print $11}' | sort | uniq -c | sort -rn | head -10
```

---

## 8. 시스템 정보 수집 (해킹 후 내부 정찰)


시스템 침투 후 내부 정찰(Post-Exploitation) 단계에서 수집하는 정보들입니다. 커널 버전, 환경변수, 크론 작업 목록은 권한 상승 취약점을 찾는 첫 번째 단계입니다.

```bash
uname -a               # 커널 버전 및 시스템 정보
cat /etc/os-release    # OS 버전
hostname               # 호스트명
cat /etc/hostname
env                    # 환경변수 전체 출력
echo $PATH             # PATH 확인
cat /proc/cpuinfo      # CPU 정보
free -h                # 메모리 사용량
df -h                  # 디스크 사용량
mount                  # 마운트된 파일시스템
lsblk                  # 블록 장치 목록
dmesg | tail -50       # 커널 메시지
cat /etc/crontab       # 크론 작업 확인 (권한 상승 경로)
ls -la /etc/cron.d/    # 크론 작업 디렉토리
sudo -l                # sudo 가능한 명령어 목록 (권한 상승 벡터)
```

---

## 9. SSH 및 원격 접속


SSH 원격 접속 및 파일 전송 명령어입니다. 포트 포워딩(`-L`, `-R`, `-D`)은 방화벽을 우회하여 내부망에 접근하거나 SOCKS 프록시를 구성할 때 핵심적으로 활용됩니다.

```bash
ssh user@192.168.1.100          # SSH 접속
ssh -p 2222 user@host           # 포트 지정
ssh -i ~/.ssh/id_rsa user@host  # 키 파일로 접속
ssh -L 8080:localhost:80 user@host  # 로컬 포트 포워딩
ssh -R 4444:localhost:22 user@host  # 리버스 포트 포워딩
ssh -D 1080 user@host           # SOCKS 프록시
scp file.txt user@host:/tmp/    # 파일 복사
scp -r dir/ user@host:/tmp/     # 디렉토리 복사
rsync -avz dir/ user@host:/tmp/ # 동기화 방식 복사
```

### SSH 키 생성 및 관리

SSH 공개키/개인키 쌍을 생성하고 서버에 등록하는 과정입니다. `ed25519` 알고리즘은 RSA보다 짧은 키로 높은 보안성을 제공하며, 패스워드 없는 키 기반 인증은 자동화 스크립트에서도 자주 사용됩니다.

```bash
ssh-keygen -t rsa -b 4096 -C "email@example.com"
ssh-keygen -t ed25519          # 더 안전한 알고리즘

# 공개키를 서버에 등록
ssh-copy-id user@host
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

# known_hosts 관리
ssh-keyscan host >> ~/.ssh/known_hosts
```

---

## 10. 로그 분석 (포렌식/보안 감사)


리눅스 시스템의 주요 로그 파일 위치와 분석 명령어입니다. 포렌식 및 보안 감사 시 `/var/log/auth.log`의 실패 로그인 패턴을 분석하면 브루트포스 공격 출처를 특정할 수 있습니다.

```bash
# 주요 로그 파일
/var/log/auth.log         # 인증 관련 (로그인, sudo)
/var/log/syslog           # 시스템 전반
/var/log/kern.log         # 커널 메시지
/var/log/apache2/access.log   # 웹 서버 접근 로그
/var/log/apache2/error.log    # 웹 서버 오류 로그
/var/log/mysql/error.log  # MySQL 오류

# 실패한 로그인 시도 추적
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# 성공한 로그인 추적
grep "Accepted" /var/log/auth.log

# su 사용 이력
grep "session opened for user root" /var/log/auth.log
```

### SSH 로그 분석기 (Python)


리눅스 시스템의 주요 로그 파일 위치와 분석 명령어입니다. 포렌식 및 보안 감사 시 `/var/log/auth.log`의 실패 로그인 패턴을 분석하면 브루트포스 공격 출처를 특정할 수 있습니다.

```python
#!/usr/bin/env python3
"""
SSH 인증 로그 분석기 — auth.log에서 공격 패턴 탐지
"""
import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


LOG_PATTERNS = {
    "failed": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
    ),
    "accepted": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted (\w+) for (\S+) from ([\d.]+)"
    ),
    "invalid": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\S+) from ([\d.]+)"
    ),
}


def parse_log(log_path: Path, threshold: int) -> None:
    failed_by_ip: Counter = Counter()
    failed_by_user: Counter = Counter()
    accepted: list[tuple[str, str, str, str]] = []
    invalid_users: list[tuple[str, str, str]] = []
    hourly_failed: defaultdict[str, int] = defaultdict(int)

    try:
        with log_path.open("r", errors="replace") as fh:
            for line in fh:
                if m := LOG_PATTERNS["failed"].search(line):
                    ts, user, ip = m.group(1), m.group(2), m.group(3)
                    failed_by_ip[ip] += 1
                    failed_by_user[user] += 1
                    hour = ts.rsplit(":", 1)[0]
                    hourly_failed[hour] += 1

                elif m := LOG_PATTERNS["accepted"].search(line):
                    accepted.append((m.group(1), m.group(3), m.group(2), m.group(4)))

                elif m := LOG_PATTERNS["invalid"].search(line):
                    invalid_users.append((m.group(1), m.group(2), m.group(3)))

    except FileNotFoundError:
        sys.exit(f"[!] 로그 파일을 찾을 수 없습니다: {log_path}")
    except PermissionError:
        sys.exit(f"[!] 파일 읽기 권한이 없습니다 (sudo로 실행하세요): {log_path}")

    print("=" * 60)
    print("  SSH 공격 분석 보고서")
    print(f"  생성 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    print(f"\n[*] 실패한 로그인 — 공격 IP Top 15 (임계값: {threshold}회)")
    found = False
    for ip, count in failed_by_ip.most_common(15):
        marker = "  [!] 잠재적 공격자" if count >= threshold else ""
        print(f"    {count:>6}회  {ip}{marker}")
        found = True
    if not found:
        print("    (데이터 없음)")

    print("\n[*] 실패한 로그인 — 타겟 계정 Top 10")
    for user, count in failed_by_user.most_common(10):
        print(f"    {count:>6}회  {user}")

    print("\n[*] 성공한 로그인")
    if accepted:
        for ts, user, method, ip in accepted[-20:]:  # 최근 20건
            print(f"    {ts}  {user}@{ip}  [{method}]")
    else:
        print("    (기록 없음)")

    print("\n[*] 존재하지 않는 계정 접근 시도 (최근 10건)")
    for ts, user, ip in invalid_users[-10:]:
        print(f"    {ts}  user={user}  from={ip}")

    print("\n[*] 시간대별 실패 통계 (상위 5구간)")
    for hour, count in sorted(hourly_failed.items(), key=lambda x: -x[1])[:5]:
        bar = "█" * min(count // 5, 40)
        print(f"    {hour}  {count:>4}회  {bar}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH auth.log 분석기 — 공격 IP 및 패턴 탐지"
    )
    parser.add_argument(
        "-f", "--file",
        default="/var/log/auth.log",
        help="분석할 로그 파일 경로 (기본값: /var/log/auth.log)",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=10,
        help="공격자로 판단하는 최소 실패 횟수 (기본값: 10)",
    )
    args = parser.parse_args()
    parse_log(Path(args.file), args.threshold)


if __name__ == "__main__":
    main()
```

---

## 11. 사용자 계정 보안 관리 (심화)

### /etc/passwd 구조 이해
```
root:x:0:0:root:/root:/bin/bash
 │   │ │ │  │     │       └── 로그인 쉘
 │   │ │ │  │     └── 홈 디렉토리
 │   │ │ │  └── GECOS (설명)
 │   │ │ └── GID (그룹 ID)
 │   │ └── UID (사용자 ID)
 │   └── 패스워드 필드 (x = shadow 파일 참조)
 └── 사용자명
```

### /etc/shadow 구조 이해
```
root:$6$salt$hash:15285:0:99999:7:::
      │              │   │   │   └── 비활성화 기간
      │              │   │   └── 최대 사용 기간 (99999 = 무제한)
      │              │   └── 최소 사용 기간
      │              └── 마지막 변경일 (1970-01-01 기준 일수)
      └── 해시 ($6$ = SHA-512)
```

### 해시 알고리즘 식별
```
$1$  → MD5
$2a$ → Blowfish (bcrypt)
$5$  → SHA-256
$6$  → SHA-512 (리눅스 기본)
```

### shadow 파일과 passwd 파일 병합 (크랙용)

`unshadow`는 `/etc/passwd`와 `/etc/shadow`를 병합하여 John the Ripper가 읽을 수 있는 형식으로 만드는 도구입니다. 해시 파일을 획득한 후 오프라인에서 사전 공격이나 무차별 대입 공격으로 패스워드를 복구할 때 사용합니다.

```bash
# unshadow — passwd와 shadow를 합쳐 John the Ripper 형식으로
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt
john --wordlist=wordlist.txt combined.txt
john --show combined.txt  # 크랙된 결과 출력
```

### 계정 잠금 및 상태 확인
```bash
passwd -l username      # 계정 잠금
passwd -u username      # 잠금 해제
passwd -S username      # 계정 상태 확인
chage -l username       # 비밀번호 만료 정보 확인
chage -M 90 username    # 최대 90일마다 변경 강제
chage -E 2025-12-31 username  # 계정 만료일 설정
```

### UID 0 계정 탐지 (루트 권한 백도어 탐지)
```bash
# UID가 0인 계정 전수 확인 (root 외에 있으면 위험)
awk -F: '$3==0 {print $1}' /etc/passwd

# 로그인 쉘이 있는 계정만 확인
awk -F: '$7 !~ /nologin|false/ {print $1, $7}' /etc/passwd
```

---

## 12. Linux PAM (Pluggable Authentication Modules)

### PAM 개요
```
PAM = 리눅스 인증 시스템의 핵심 모듈
위치: /etc/pam.d/
설정 형식: [type] [control] [module] [arguments]
```

### PAM 타입
```
auth     → 사용자 신원 확인 (비밀번호 검증)
account  → 계정 조건 확인 (만료, 시간 제한 등)
password → 비밀번호 업데이트 규칙
session  → 로그인/로그아웃 시 환경 설정
```

### PAM 컨트롤 플래그
```
required   → 실패해도 계속 진행, 최종적으로 실패
requisite  → 실패 즉시 중단
sufficient → 성공하면 이후 생략
optional   → 결과가 최종 판단에 영향 없음
```

### 주요 PAM 모듈

#### pam_tally2 — 로그인 실패 횟수 제한

`pam_tally2`는 로그인 실패 횟수를 누적하여 일정 횟수 초과 시 계정을 잠그는 PAM 모듈입니다. `deny=5`로 5회 실패 시 잠금, `unlock_time=600`으로 600초 후 자동 해제하도록 설정할 수 있습니다.

```bash
# /etc/pam.d/login 또는 /etc/pam.d/sshd 에 추가
auth required pam_tally2.so deny=5 unlock_time=600 onerr=fail

# 현재 실패 횟수 확인
pam_tally2 --user=username

# 수동으로 카운터 초기화
pam_tally2 --user=username --reset
```

#### pam_time — 시간 기반 접근 제어

`pam_time`은 시간과 터미널 유형에 따라 사용자 접근을 제한하는 PAM 모듈입니다. `/etc/security/time.conf`에서 특정 서비스에 대해 허용 요일·시간대를 세밀하게 제어할 수 있습니다.

```bash
# /etc/security/time.conf 설정 예시
# 서비스;터미널;사용자;시간
login;*;username;Mo-Fr0900-1800   # 월~금 09:00~18:00만 허용
sshd;*;ALL;Al0000-2400            # 모든 시간 허용

# /etc/pam.d/login 에 추가
account required pam_time.so
```

#### pam_access — 호스트 기반 접근 제어

`pam_access`는 호스트 주소 기반으로 접근을 제어하는 PAM 모듈입니다. `/etc/security/access.conf`에서 허용/거부 규칙을 설정하며, root 계정의 원격 접속을 내부망 IP로만 제한하는 데 자주 활용됩니다.

```bash
# /etc/security/access.conf 설정
# 형식: + 또는 - : 사용자 : 호스트/IP
+:root:192.168.1.0/24     # 내부망에서만 root 허용
-:root:ALL                # 그 외 root 거부
+:ALL:LOCAL               # 로컬 로그인은 모두 허용
-:ALL:ALL                 # 나머지 전부 거부

# /etc/pam.d/sshd 에 추가
account required pam_access.so
```

#### pam_pwquality — 비밀번호 복잡도 정책

`pam_pwquality`는 패스워드 복잡도 정책을 강제하는 PAM 모듈입니다. 최소 길이, 문자 클래스(대소문자·숫자·특수문자), 연속 반복 제한 등을 설정하여 취약한 패스워드 사용을 방지합니다.

```bash
# /etc/security/pwquality.conf
minlen = 12           # 최소 12자
minclass = 3          # 최소 3가지 문자 클래스
maxrepeat = 3         # 동일 문자 최대 3회 반복
dcredit = -1          # 숫자 최소 1개
ucredit = -1          # 대문자 최소 1개
lcredit = -1          # 소문자 최소 1개
ocredit = -1          # 특수문자 최소 1개

# /etc/pam.d/common-password 에 추가
password requisite pam_pwquality.so retry=3
```

---

## 13. 방화벽 설정 (iptables)

### iptables 기본 구조
```
테이블: filter, nat, mangle, raw
체인:
  INPUT   → 들어오는 패킷 (서버로 향하는)
  OUTPUT  → 나가는 패킷 (서버에서 나가는)
  FORWARD → 통과하는 패킷 (라우터 역할 시)

규칙 평가: 위에서 아래로 순서대로, 매칭되면 즉시 적용
기본 정책: ACCEPT 또는 DROP
```

### 기본 iptables 명령어

iptables로 Linux 방화벽 규칙을 설정합니다. 인바운드/아웃바운드 트래픽을 제어하고 불필요한 서비스 접근을 차단합니다.

```bash
# 현재 규칙 확인
iptables -L -n -v          # 기본 (filter 테이블)
iptables -L -n -v --line-numbers  # 줄 번호 포함

# 규칙 추가
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH 허용
iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # HTTP 허용
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS 허용

# 특정 IP 허용/차단
iptables -A INPUT -s 192.168.1.100 -j ACCEPT    # 특정 IP 허용
iptables -A INPUT -s 10.0.0.0/8 -j DROP         # 대역 차단

# 기본 정책 설정 (화이트리스트 방식)
iptables -P INPUT DROP     # 기본적으로 모두 차단
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT  # 나가는 것은 허용

# 이미 연결된 세션 유지 (필수)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT   # 루프백 허용

# 규칙 삭제
iptables -D INPUT 3        # 3번 규칙 삭제
iptables -F                # 전체 초기화 (주의!)

# 규칙 저장 및 복원
iptables-save > /etc/iptables/rules.v4
iptables-restore < /etc/iptables/rules.v4
```

### 기본 서버 보안 정책 예시

배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# 기본 서버 방화벽 설정 스크립트

# 기존 규칙 초기화
iptables -F
iptables -X

# 기본 정책: 차단
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 루프백 및 기존 연결 허용
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH 허용 (관리용)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# 웹 서비스 허용
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP (ping) 허용
iptables -A INPUT -p icmp -j ACCEPT

# 로그 기록 후 차단
iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 4
iptables -A INPUT -j DROP

echo "[+] 방화벽 규칙 적용 완료"
iptables -L -n -v
```

### nftables (iptables 후속)

nftables는 iptables의 후속으로 리눅스 커널 3.13 이후에 도입된 차세대 패킷 필터링 프레임워크입니다. 단일 명령어로 IPv4/IPv6를 동시에 처리할 수 있으며, `nft list ruleset`으로 전체 규칙을 확인합니다.

```bash
# 현재 규칙 확인
nft list ruleset

# 기본 설정
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }

# SSH 허용
nft add rule inet filter input tcp dport 22 accept

# 규칙 저장
nft list ruleset > /etc/nftables.conf
```

---

## 리눅스 서버 기본 보안 정책

### SSH 브루트포스 방어 — /etc/passwd 계정 관리
```bash
# 사용하지 않는 계정 비활성화 (앞에 # 추가)
# /etc/passwd 파일에서 쉘이 /bin/bash 인 미사용 계정 확인
grep "/bin/bash\|/bin/sh" /etc/passwd

# 미사용 계정 로그인 차단 (쉘을 nologin으로 변경)
usermod -s /sbin/nologin [계정명]

# 또는 /etc/passwd에서 직접 주석 처리
# rpm:x:37:37::/var/lib/rpm:/bin/bash
# → #rpm:x:37:37::/var/lib/rpm:/bin/bash

# 강력한 패스워드 정책 (브루트포스 방어):
# - 특수문자 조합
# - 사전 파일에 없는 문자열
# - 8자 이상 권장
```

### PortSentry — 포트 스캔 탐지 및 자동 차단

PortSentry는 포트 스캔을 실시간으로 탐지하고 공격자 IP를 자동으로 차단하는 도구입니다. `hosts.deny`나 `iptables`를 통해 스캔을 감지한 즉시 해당 IP를 차단하여 공격 조기 차단에 효과적입니다.

```bash
# PortSentry 설정 파일
# /etc/portsentry/portsentry.conf

# 스텔스 모드 설정 (TCP/UDP)
BLOCK_UDP="1"
BLOCK_TCP="1"

# 공격자 자동 차단 (hosts.deny 추가)
KILL_ROUTE="/sbin/route add -host $TARGET$ reject"
# 또는 iptables로 차단
KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"

# 차단된 IP 확인
cat /etc/hosts.deny | grep "ALL:"

# PortSentry 실행 (스텔스 모드)
portsentry -stcp   # TCP 스텔스 스캔 탐지
portsentry -sudp   # UDP 스텔스 스캔 탐지
```

### chkrootkit — 백도어 탐지

`chkrootkit`은 시스템에 설치된 루트킷(rootkit)을 탐지하는 도구입니다. 스니퍼 탐지, 백도어 바인드 쉘, 커널 모듈 루트킷 등을 검사하며, INFECTED 결과가 나오면 즉시 네트워크 차단 후 포렌식 이미지를 생성해야 합니다.

```bash
# 설치
apt-get install chkrootkit
# 또는
yum install chkrootkit

# 전체 시스템 루트킷 검사
chkrootkit

# 특정 테스트만 실행
chkrootkit sniffer    # 스니퍼 탐지
chkrootkit bindshell  # 백도어 바인드 쉘 탐지
chkrootkit lkm        # 커널 모듈 루트킷 탐지

# 주기적 실행 (cron)
echo "0 3 * * * root /usr/sbin/chkrootkit 2>&1 | mail -s 'chkrootkit report' admin@example.com" >> /etc/crontab

# INFECTED 결과 시 조치:
# 1. 네트워크 즉시 분리
# 2. 포렌식 이미지 생성
# 3. 클린 시스템에서 재구축 고려
```

### 파일 퍼미션 강화
```bash
# 주요 설정 파일 권한 제한
chmod 600 /etc/shadow         # root만 읽기
chmod 644 /etc/passwd         # 모두 읽기, root만 쓰기
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 700 /root                # root 홈 디렉토리

# 불필요한 SUID 비트 제거
find / -perm -4000 -type f 2>/dev/null  # SUID 파일 목록
chmod u-s /path/to/suspicious_file

# World-writable 파일/디렉토리 탐지
find / -perm -o+w -type f 2>/dev/null | grep -v proc
find / -perm -o+w -type d 2>/dev/null | grep -v proc

# 소유자 없는 파일 탐지 (공격자가 만든 임시 파일)
find / -nouser -print 2>/dev/null
find / -nogroup -print 2>/dev/null
```

### 파일 무결성 검사 도구 (Python)

```python
#!/usr/bin/env python3
"""
파일 무결성 검사기 — 중요 파일의 해시를 기록하고 변경 감지
"""
import argparse
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional


CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
]


def compute_hash(file_path: Path, algorithm: str = "sha256") -> Optional[str]:
    """파일 해시 계산. 읽기 실패 시 None 반환."""
    hasher = hashlib.new(algorithm)
    try:
        with file_path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def scan_directory(target_dir: Path, algorithm: str, workers: int) -> dict[str, str]:
    """디렉토리를 병렬로 스캔하여 {경로: 해시} 딕셔너리 반환."""
    files = [p for p in target_dir.rglob("*") if p.is_file()]
    results: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_path = {pool.submit(compute_hash, f, algorithm): f for f in files}
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            digest = future.result()
            if digest is not None:
                results[str(path)] = digest

    return results


def create_baseline(target_dir: Path, baseline_file: Path, algorithm: str, workers: int) -> None:
    """기준선(baseline) 해시 데이터베이스 생성."""
    print(f"[*] 기준선 생성 중: {target_dir}")
    hashes = scan_directory(target_dir, algorithm, workers)

    # 중요 시스템 파일 추가
    for path_str in CRITICAL_PATHS:
        p = Path(path_str)
        if p.exists():
            digest = compute_hash(p, algorithm)
            if digest:
                hashes[path_str] = digest

    baseline = {
        "created_at": datetime.now().isoformat(),
        "algorithm": algorithm,
        "target": str(target_dir),
        "files": hashes,
    }
    baseline_file.write_text(json.dumps(baseline, indent=2, ensure_ascii=False))
    print(f"[+] 기준선 저장 완료: {baseline_file}  ({len(hashes)}개 파일)")


def verify_integrity(baseline_file: Path, workers: int) -> int:
    """기준선과 현재 상태를 비교하여 변경 사항 보고. 변경 수 반환."""
    if not baseline_file.exists():
        sys.exit(f"[!] 기준선 파일이 없습니다: {baseline_file}")

    baseline = json.loads(baseline_file.read_text())
    algorithm: str = baseline["algorithm"]
    saved: dict[str, str] = baseline["files"]

    print(f"[*] 무결성 검사 시작  (기준선: {baseline['created_at']})")

    target_dir = Path(baseline["target"])
    current = scan_directory(target_dir, algorithm, workers)

    # 중요 시스템 파일 재검사
    for path_str in CRITICAL_PATHS:
        p = Path(path_str)
        if p.exists():
            digest = compute_hash(p, algorithm)
            if digest:
                current[path_str] = digest

    changes = 0
    new_files = set(current) - set(saved)
    deleted_files = set(saved) - set(current)
    modified_files = {
        p for p in set(current) & set(saved) if current[p] != saved[p]
    }

    for path in sorted(modified_files):
        print(f"  [변경] {path}")
        print(f"         이전: {saved[path]}")
        print(f"         현재: {current[path]}")
        changes += 1

    for path in sorted(new_files):
        print(f"  [추가] {path}")
        changes += 1

    for path in sorted(deleted_files):
        print(f"  [삭제] {path}")
        changes += 1

    status = "이상 없음" if changes == 0 else f"{changes}건 변경 감지"
    print(f"\n[{'OK' if changes == 0 else '!'}] 검사 완료: {status}")
    return changes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="파일 무결성 검사기 (hashlib 기반)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""사용 예시:
  sudo python3 file_integrity.py create -d /etc -b /root/etc_baseline.json
  sudo python3 file_integrity.py verify -b /root/etc_baseline.json
        """,
    )
    parser.add_argument(
        "action", choices=["create", "verify"],
        help="create: 기준선 생성 / verify: 무결성 검증",
    )
    parser.add_argument("-d", "--directory", default="/etc", help="검사 대상 디렉토리")
    parser.add_argument("-b", "--baseline", default="baseline.json", help="기준선 파일 경로")
    parser.add_argument("-a", "--algorithm", default="sha256",
                        choices=["md5", "sha1", "sha256", "sha512"],
                        help="해시 알고리즘 (기본값: sha256)")
    parser.add_argument("-w", "--workers", type=int, default=8, help="병렬 스레드 수")

    args = parser.parse_args()

    if args.action == "create":
        create_baseline(Path(args.directory), Path(args.baseline), args.algorithm, args.workers)
    else:
        changes = verify_integrity(Path(args.baseline), args.workers)
        sys.exit(1 if changes > 0 else 0)


if __name__ == "__main__":
    main()
```

### Apache httpd.conf 보안 설정 핵심
```apache
# 서버 정보 숨기기
ServerSignature Off
ServerTokens Prod

# 디렉토리 리스팅 비활성화
Options -Indexes

# 심볼릭 링크 따라가기 비활성화
Options -FollowSymLinks

# 불필요한 HTTP 메서드 비활성화
<LimitExcept GET POST>
    Deny from all
</LimitExcept>

# .htaccess 파일 Override 비활성화 (성능 + 보안)
AllowOverride None

# CGI 실행 금지 (필요한 경우만 허용)
Options -ExecCGI

# 파일 포함 방지
Options -Includes
```

### PHP 보안 설정 (php.ini)

PHP 실행 환경의 보안 강화 설정입니다. `display_errors = Off`로 오류 정보 노출을 막고, `allow_url_include = Off`로 원격 파일 인클루전(RFI) 공격을 방지합니다. `disable_functions`로 위험한 시스템 함수 실행도 제한합니다.

```ini
# 오류 정보 외부 노출 방지
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log

# 원격 파일 포함 비활성화 (RFI 방지)
allow_url_include = Off
allow_url_fopen = Off

# 파일 업로드 제한
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 20

# 위험한 함수 비활성화
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,
                    curl_exec,curl_multi_exec,parse_ini_file,show_source

# PHP 버전 정보 숨기기
expose_php = Off

# 세션 보안
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
```
