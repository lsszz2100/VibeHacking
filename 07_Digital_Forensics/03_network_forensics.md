# 네트워크 포렌식 — 패킷 분석 및 침해 대응

## 1. 네트워크 포렌식 개요

```
네트워크 포렌식 = 네트워크 트래픽에서 증거 수집 및 분석

수집 방법:
1. PCAP 파일 분석 (사전 캡처된 패킷)
2. NetFlow/IPFIX 분석 (요약 트래픽 데이터)
3. 방화벽/IDS 로그 분석
4. DNS 로그 분석

분석 목표:
✔ C&C 서버 통신 탐지
✔ 데이터 유출 탐지
✔ 측면 이동 탐지
✔ 악성 도메인/IP 식별
✔ 프로토콜 이상 탐지
```

---

## 2. Wireshark 실전 분석

### 2-1. 기본 필터

```wireshark
# IP 필터
ip.addr == 192.168.1.1          # 해당 IP 관련 모든 패킷
ip.src == 192.168.1.1           # 출발지 IP
ip.dst == 10.0.0.1              # 목적지 IP
ip.addr == 192.168.1.0/24       # 서브넷

# 포트 필터
tcp.port == 80                  # HTTP
tcp.port == 443                 # HTTPS
tcp.dstport == 4444             # 역방향 쉘 포트 (의심)
udp.port == 53                  # DNS

# 프로토콜 필터
http                            # HTTP
dns                             # DNS
ftp                             # FTP
ssh                             # SSH
smtp                            # 이메일
icmp                            # ICMP (핑)

# 조합 필터
ip.src == 192.168.1.100 && tcp.dstport == 80
http.request.method == "POST"
http && ip.dst != 192.168.1.1   # 외부 HTTP

# 패킷 내용 검색
frame contains "password"
tcp contains "cmd.exe"
http.request.uri contains "/shell"
```

### 2-2. HTTP 분석

```wireshark
# HTTP 요청
http.request
http.request.method == "GET"
http.request.method == "POST"
http.request.uri contains "login"
http.request.uri contains ".php?cmd="   # 웹쉘 의심

# HTTP 응답
http.response.code == 200
http.response.code == 404
http.response.code >= 400       # 에러 응답

# HTTP 헤더
http.user_agent contains "curl"        # 자동화 도구
http.user_agent contains "sqlmap"      # SQL Injection 도구
http.cookie contains "PHPSESSID"

# 파일 다운로드 재조립
# File → Export Objects → HTTP → 저장
```

### 2-3. DNS 분석

```wireshark
# DNS 쿼리
dns.flags.response == 0         # DNS 요청만
dns.flags.response == 1         # DNS 응답만
dns.qry.name contains ".onion"  # 토르 도메인
dns.qry.name matches ".*[0-9]{5,}.*"  # 의심 도메인 (긴 숫자)

# DNS 터널링 탐지
dns.qry.name.len > 50          # 비정상적으로 긴 도메인
# DNS 터널링: 데이터를 DNS 쿼리 서브도메인에 인코딩
# 예: aGVsbG8gd29ybGQ=.attacker.com (Base64 데이터)
```

### 2-4. 악성 트래픽 패턴

```wireshark
# 포트 스캔 탐지 (SYN 스캔)
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == [스캐너IP]

# 역방향 쉘 (비표준 포트 연결)
tcp.dstport > 1024 && tcp.dstport < 65535 && !tcp.port == 443

# 대용량 데이터 유출
# Statistics → Conversations → TCP → Sort by Bytes
# 비정상적으로 큰 전송량 확인

# Beaconing (C&C 주기적 통신) 탐지
# Statistics → IO Graphs → 규칙적인 패턴 확인
```

---

## 3. NetworkMiner 분석

```
NetworkMiner = PCAP 파일 파싱 GUI 도구

주요 탭:
Hosts     → 통신에 참여한 모든 호스트
Files     → 전송된 파일 자동 추출 (HTTP, SMB, FTP)
Images    → 전송된 이미지 파일
Messages  → 이메일, 채팅
Credentials → 캡처된 자격증명 (평문)
Sessions  → 세션 목록
DNS       → DNS 쿼리 목록
```

---

## 4. tcpdump 실전

```bash
# 기본 캡처
tcpdump -i eth0 -w capture.pcap

# 특정 호스트
tcpdump -i eth0 host 192.168.1.1 -w capture.pcap

# 특정 포트
tcpdump -i eth0 port 80 -w capture.pcap
tcpdump -i eth0 'port 80 or port 443' -w capture.pcap

# 특정 네트워크
tcpdump -i eth0 net 192.168.1.0/24 -w capture.pcap

# 파일 크기/개수 제한
tcpdump -i eth0 -C 100 -W 10 -w capture.pcap  # 100MB씩 10개 순환

# PCAP 읽기
tcpdump -r capture.pcap
tcpdump -r capture.pcap -n -A  # ASCII 출력
tcpdump -r capture.pcap 'tcp port 80' | head -50
```

---

## 5. 침해 지표(IOC) 분석

### 네트워크 IOC 유형
```
IP 주소 (C&C 서버, 공격자)
도메인 (악성 도메인)
URL (악성 URL, 피싱 페이지)
파일 해시 (악성 파일)
User-Agent (악성 도구 식별자)
JA3 해시 (TLS 클라이언트 지문)
```

### IOC 추출 자동화

```python
# PCAP에서 IOC 자동 추출
import dpkt
import socket

def extract_iocs(pcap_file):
    iocs = {'ips': set(), 'domains': set(), 'urls': set()}
    
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                
                ip = eth.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                iocs['ips'].add(dst)
                
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    # HTTP 파싱
                    if tcp.dport == 80 and len(tcp.data) > 0:
                        try:
                            req = dpkt.http.Request(tcp.data)
                            iocs['urls'].add(f"http://{req.headers.get('host', dst)}{req.uri}")
                        except:
                            pass
                    
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    # DNS 파싱
                    if udp.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            for q in dns.qd:
                                iocs['domains'].add(q.name.decode())
                        except:
                            pass
            except:
                continue
    
    return iocs

iocs = extract_iocs('capture.pcap')
print("의심 IP:", iocs['ips'])
print("접근 도메인:", iocs['domains'])
print("요청 URL:", iocs['urls'])
```

---

## 6. Zeek (Bro) 네트워크 분석

```bash
# 설치
sudo apt install zeek

# PCAP 분석
zeek -r capture.pcap

# 생성되는 로그 파일:
# conn.log    → 모든 연결 (소스, 목적지, 포트, 바이트)
# http.log    → HTTP 요청/응답
# dns.log     → DNS 쿼리
# ssl.log     → TLS/SSL 세션
# files.log   → 전송된 파일
# weird.log   → 이상 프로토콜 동작

# conn.log 분석 (쉼표 구분)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes | sort -k7 -rn | head -20

# DNS 쿼리 목록
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20

# HTTPS 연결 (JA3 지문)
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name ja3
```

---

## 7. Suricata IDS 규칙

```bash
# 설치
sudo apt install suricata

# PCAP 분석
suricata -r capture.pcap -l output/

# 규칙 작성 예시
# fast.log에서 경고 확인

# 기본 규칙 예시
# 역방향 쉘 탐지
alert tcp any any -> any 4444 (msg:"Suspicious Reverse Shell - Port 4444"; sid:100001;)

# Meterpreter 트래픽 탐지 (Metasploit)
alert tcp any any -> any any (msg:"Meterpreter HTTPS"; 
  content:"METERPRETER"; nocase; sid:100002;)

# 웹쉘 접근 탐지
alert http any any -> any any (msg:"Webshell Access - cmd parameter";
  http.uri; content:"cmd="; nocase; sid:100003;)

# DNS 터널링 탐지
alert dns any any -> any any (msg:"Long DNS Query - Possible Tunneling";
  dns.query; dsize:>100; sid:100004;)

# 포트 스캔 탐지 (Threshold)
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected";
  flags:S; threshold: type both, track by_src, count 20, seconds 60;
  sid:100005;)
```

---

## 8. 이메일 포렌식

### 이메일 헤더 분석

```
From:      발신자 (위조 가능)
To:        수신자
Subject:   제목
Date:      발송 시간
Message-ID: 고유 메시지 ID
Received:  경유한 메일 서버 체인 (역순으로 읽음 → 원본 서버 확인)
X-Originating-IP: 실제 발신자 IP (일부 서버)
DKIM-Signature: 도메인 서명
SPF:       발신 서버 검증
DMARC:     SPF/DKIM 정책
```

```bash
# 이메일 헤더 분석 도구
# Google Admin Toolbox: https://toolbox.googleapps.com/apps/messageheader/
# MX Toolbox: https://mxtoolbox.com/EmailHeaders.aspx

# 스피어피싱 분석 체크리스트
□ Received 헤더의 실제 발신 IP
□ Reply-To가 From과 다른지 확인
□ 링크 도메인 (표시 텍스트 vs 실제 URL)
□ 첨부파일 해시 → VirusTotal
□ 도메인 타이포스쿼팅 확인
```

---

## 9. 실전 시나리오: APT 침해 조사

### 단계별 조사

```
1단계: 초기 유입 (Initial Access) 확인
- 스피어피싱 이메일 로그
- 웹 서버 액세스 로그 (웹 익스플로잇)
- VPN/RDP 인증 실패 로그

2단계: 실행 (Execution) 확인
- Prefetch에서 비정상 프로세스 실행
- 이벤트 ID 4688 (프로세스 생성)
- PowerShell 로그 (4104) - 인코딩된 명령

3단계: 지속성 (Persistence) 확인
- 레지스트리 Run 키
- 예약 작업
- 서비스 생성 (이벤트 7045)

4단계: 내부 이동 (Lateral Movement) 확인
- 이벤트 ID 4624 Type 3 (네트워크 로그인)
- SMB 트래픽
- PsExec 흔적

5단계: 정보 수집 및 유출 (Exfiltration) 확인
- 대용량 외부 전송
- 클라우드 스토리지 업로드
- DNS 터널링

6단계: C&C 통신 확인
- 주기적 아웃바운드 연결
- 비표준 포트 사용
- TLS/SSL 암호화된 통신 → JA3 지문
```

---

## 10. 방화벽/IDS 로그 분석

### 로그 분석 기본

```bash
# Apache 액세스 로그 분석
# SQL Injection 시도 탐지
grep -E "UNION|SELECT|INSERT|DROP|OR%201=1" access.log

# 웹쉘 접근 시도
grep -E "cmd=|shell=|exec=|eval\(" access.log

# 스캐너 User-Agent
grep -Ei "nikto|nmap|masscan|sqlmap|acunetix|nessus" access.log

# 브루트포스 (동일 IP 다수 요청)
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# 404 에러 다수 (디렉토리 열거)
grep " 404 " access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# 응답 크기 이상 (데이터 유출)
awk '{print $10, $7}' access.log | sort -rn | head -20  # 응답 크기 큰 URL

# 특정 시간대 분석
grep "01/Jan/2024:14:" access.log | wc -l
```

### fail2ban 로그 분석

```bash
# SSH 브루트포스 차단 기록
grep "Ban\|Unban" /var/log/fail2ban.log

# 차단된 IP 목록
grep "Ban " /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn

# 현재 차단 상태
fail2ban-client status sshd
```

---

## 11. Blue Team 기본 네트워크 도구

### ping / tracert / pathping
```bash
# 기본 연결 확인
ping -c 4 192.168.1.1              # Linux
ping 192.168.1.1                   # Windows

# 경로 추적
traceroute 8.8.8.8                 # Linux
tracert 8.8.8.8                    # Windows

# traceroute + 통계 결합 (Windows)
# pathping: 각 홉에서 패킷 손실률 통계 제공
pathping 8.8.8.8

# WinMTR: traceroute + ping 실시간 통합
# → 경로별 지연 및 패킷 손실 실시간 확인
```

### nslookup / DNS 분석
```bash
# 기본 쿼리
nslookup example.com
nslookup -querytype=mx example.com    # MX 레코드 (메일 서버)
nslookup -querytype=txt example.com   # TXT 레코드 (SPF, DMARC)
nslookup -querytype=ns example.com    # NS 레코드 (네임서버)

# 역방향 조회 (IP → 도메인)
nslookup 8.8.8.8

# dig (Linux 심화)
dig example.com ANY          # 모든 레코드
dig @8.8.8.8 example.com    # 특정 DNS 서버 조회
dig +trace example.com       # 재귀 추적
```

### NetStat 활용
```bash
# 활성 연결 목록
netstat -an        # 모든 연결 (숫자 표시)
netstat -antp      # TCP + PID 포함 (Linux)
netstat -ano       # Windows (PID 포함)

# 통계 정보 확인
netstat -s         # 프로토콜별 통계

# 포트가 열려있는지 확인
netstat -an | grep :80
netstat -an | grep LISTEN
```

### OSSEC — 로그 기반 침입 탐지
```bash
# OSSEC 설치 (서버 모드)
./install.sh

# 에이전트 등록
/var/ossec/bin/manage_agents

# OSSEC 주요 기능:
# - 로그 분석 (syslog, event log)
# - 파일 무결성 모니터링 (FIM)
# - 루트킷 탐지
# - 실시간 알림

# 로그 위치
/var/ossec/logs/ossec.log      # 주 로그
/var/ossec/logs/alerts/        # 알림 로그

# 규칙 경로
/var/ossec/rules/              # 기본 탐지 규칙

# 에이전트 상태 확인
/var/ossec/bin/agent_control -l

# OSSEC 알림 예시 (ID 1002 = 알 수 없는 오류):
# Rule: 1002 (level 2) -> 'Unknown problem somewhere in the system.'
```

### inSSIDer / 무선 네트워크 보안
```
IEEE 802.11 표준:
  802.11a: 5GHz, 54 Mbps
  802.11b: 2.4GHz, 11 Mbps
  802.11g: 2.4GHz, 54 Mbps
  802.11n: 2.4/5GHz, 300+ Mbps
  802.11ac: 5GHz, 1+ Gbps
  802.11ax: Wi-Fi 6, 다중 사용자 최적화

무선 보안 취약점:
  - WEP: 취약 (사용 금지)
  - WPA: 취약점 존재
  - WPA2: KRACK 취약점 (패치 필요)
  - WPA3: 현재 권장 표준

무선 네트워크 모니터링 도구:
  - inSSIDer: Wi-Fi 신호 시각화
  - Wireless Network Watcher: 연결된 장치 목록
  - Wireshark: 무선 패킷 캡처

기업 무선 보안:
  - WPA2-Enterprise (802.1X + RADIUS 인증)
  - 손님 네트워크 분리 (VLAN)
  - 무선 침입 탐지 (WIDS)
```

---

## 12. CIS 컨트롤 v7 상위 6개 (Blue Team 필수)

### CIS Basic Controls — Top 6
```
1. 허가된 및 비허가된 장치 인벤토리 (Hardware Inventory)
   - 모든 하드웨어 자산 목록 유지
   - 비허가 장치 즉시 탐지 및 차단
   - 네트워크 스캐닝으로 알 수 없는 장치 식별
   - 도구: Nmap, 네트워크 접근 제어(NAC)

2. 허가된 및 비허가된 소프트웨어 인벤토리 (Software Inventory)
   - 모든 소프트웨어 목록 유지
   - 비허가 소프트웨어 실행 차단 (화이트리스트)
   - 도구: SCCM, Ansible, Puppet

3. 지속적인 취약점 평가 및 교정 (Vulnerability Management)
   - 정기 취약점 스캔 실행
   - CVSS 기반 우선순위 패치 적용
   - 도구: Nessus, OpenVAS, Nexpose

4. 관리자 권한의 통제된 사용 (Controlled Use of Admin Privileges)
   - 최소 권한 원칙 적용
   - 관리자 계정 일상 업무에 사용 금지
   - MFA 강제, 특권 접근 관리(PAM)

5. 모바일 장치, 노트북, 워크스테이션 하드웨어/소프트웨어 보안 설정 유지
   - CIS 벤치마크 기반 하드닝 적용
   - 기본 패스워드 변경, 불필요한 서비스 비활성화
   - 도구: CIS-CAT, Lynis

6. 감사 로그 유지, 모니터링, 분석
   - 모든 중요 시스템의 로그 수집
   - 중앙 집중식 로그 관리 (SIEM)
   - 로그 보존 기간 정책 수립 (최소 1년 권장)
   - 도구: Splunk, ELK Stack, Graylog
```
