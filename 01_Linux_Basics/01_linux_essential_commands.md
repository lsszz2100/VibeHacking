# Linux 필수 명령어 완전 정리

## 1. 파일 및 디렉토리 조작

### 기본 탐색
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
```bash
cp -r src/ dst/        # 디렉토리 재귀 복사
mv oldname newname     # 파일 이동/이름 변경
rm -rf dirName         # 디렉토리 강제 삭제 (주의!)
mkdir -p a/b/c         # 중첩 디렉토리 일괄 생성
touch filename         # 빈 파일 생성 또는 타임스탬프 갱신
ln -s /etc/passwd sym  # 심볼릭 링크 생성
```

### 파일 내용 확인
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
```bash
chmod 755 file         # rwxr-xr-x
chmod 644 file         # rw-r--r--
chmod +x script.sh     # 실행 권한 추가
chown root:root file   # 소유자/그룹 변경
chown -R www-data /var/www  # 재귀적 소유자 변경
```

#### 권한 숫자 계산
```
r(읽기)  = 4
w(쓰기)  = 2
x(실행)  = 1

755 = rwx(7) r-x(5) r-x(5)  → 소유자: 전체, 그룹/기타: 읽기+실행
644 = rw-(6) r--(4) r--(4)  → 소유자: 읽기+쓰기, 나머지: 읽기만
```

### SetUID / SetGID (보안 핵심)
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
```bash
apt-get update              # 패키지 목록 갱신
apt-get upgrade             # 설치된 패키지 업그레이드
apt-get install nmap        # 패키지 설치
apt-get remove nmap         # 패키지 제거
apt-get autoremove          # 불필요한 패키지 제거
dpkg -l | grep nmap         # 설치 여부 확인
```

### RedHat/CentOS/Fedora 계열
```bash
yum update                  # 패키지 업데이트
yum install nmap            # 패키지 설치
rpm -qa | grep nmap         # 설치 확인
```

---

## 7. 텍스트 처리 (보안 분석에 필수)

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
