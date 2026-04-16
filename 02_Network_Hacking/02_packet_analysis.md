# 패킷 분석 — Wireshark & tcpdump 실전 가이드

## 1. 패킷 분석 기초

### 패킷 캡처 도구 비교
| 도구 | 환경 | 특징 |
|------|------|------|
| Wireshark | GUI | 강력한 필터링, 프로토콜 디코딩 |
| tcpdump | CLI | 가볍고 빠름, 스크립트 연동 |
| tshark | CLI | Wireshark CLI 버전 |
| Zeek (Bro) | CLI | 고급 네트워크 분석 |
| NetworkMiner | GUI | 포렌식 특화 |

---

## 2. tcpdump 완전 가이드

### 기본 사용법
```bash
# 기본 캡처 (eth0 인터페이스)
tcpdump -i eth0

# 모든 인터페이스
tcpdump -i any

# 특정 호스트 필터
tcpdump -i eth0 host 192.168.1.100

# 특정 포트 필터
tcpdump -i eth0 port 80
tcpdump -i eth0 port 443
tcpdump -i eth0 'port 80 or port 443'

# 특정 프로토콜
tcpdump -i eth0 icmp
tcpdump -i eth0 tcp
tcpdump -i eth0 udp

# 출발지/목적지 필터
tcpdump -i eth0 src host 192.168.1.100
tcpdump -i eth0 dst host 192.168.1.1
tcpdump -i eth0 src port 80
```

### 고급 필터링
```bash
# TCP SYN 패킷만 캡처 (포트 스캔 탐지)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# SYN/ACK 패킷 (스캔 응답)
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)'

# RST 패킷만 (연결 거부)
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'

# HTTP GET 요청만
tcpdump -i eth0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# DNS 쿼리 캡처
tcpdump -i eth0 -n port 53

# ICMP Echo Request만 (ping 모니터링)
tcpdump -i eth0 'icmp[icmptype]=icmp-echo'

# 대용량 패킷 탐지 (DoS 징조)
tcpdump -i eth0 'ip[2:2] > 1000'
```

### 파일 저장 및 읽기
```bash
# pcap 파일로 저장
tcpdump -i eth0 -w capture.pcap

# 저장된 파일 읽기
tcpdump -r capture.pcap

# 특정 시간 동안 캡처 (60초)
timeout 60 tcpdump -i eth0 -w capture.pcap

# 파일 크기 제한 (100MB씩 회전)
tcpdump -i eth0 -w capture-%Y%m%d-%H%M%S.pcap -C 100 -G 3600
```

### 출력 형식 옵션
```bash
tcpdump -i eth0 -n      # IP 주소를 숫자로 표시 (DNS 조회 안 함)
tcpdump -i eth0 -nn     # IP와 포트 모두 숫자로
tcpdump -i eth0 -v      # 상세 출력
tcpdump -i eth0 -vv     # 더 상세한 출력
tcpdump -i eth0 -A      # ASCII로 페이로드 출력
tcpdump -i eth0 -X      # Hex + ASCII 출력
tcpdump -i eth0 -xx     # 이더넷 헤더 포함 Hex 출력
tcpdump -i eth0 -e      # MAC 주소 표시
tcpdump -i eth0 -c 100  # 100개 패킷 캡처 후 종료
```

---

## 3. Wireshark 실전 사용법

### 주요 디스플레이 필터

#### 기본 필터
```
ip.addr == 192.168.1.100      # 특정 IP
ip.src == 192.168.1.100       # 출발지 IP
ip.dst == 192.168.1.100       # 목적지 IP
tcp.port == 80                # 포트 번호
tcp.dstport == 443            # 목적지 포트
udp.port == 53                # UDP 포트

# AND / OR / NOT
ip.src == 192.168.1.1 && tcp.port == 80
ip.addr == 192.168.1.1 || ip.addr == 10.0.0.1
!arp                          # ARP 패킷 제외
```

#### 프로토콜 필터
```
http                          # HTTP 프로토콜
https or ssl or tls           # HTTPS/TLS
dns                           # DNS
arp                           # ARP
icmp                          # ICMP (ping 등)
smtp                          # 이메일
ftp                           # FTP
ssh                           # SSH
```

#### TCP 플래그 필터
```
tcp.flags.syn == 1            # SYN 패킷
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN only (포트 스캔 탐지)
tcp.flags.rst == 1            # RST 패킷
tcp.flags.fin == 1            # FIN 패킷
tcp.analysis.retransmission   # 재전송 패킷
```

#### HTTP 분석
```
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200     # 성공 응답
http.response.code == 404     # 페이지 없음
http.response.code == 500     # 서버 오류
http.request.uri contains "admin"  # URI에 admin 포함
http contains "password"      # 패킷 내 password 문자열
```

### Follow TCP Stream (평문 분석의 핵심)
1. HTTP 패킷 우클릭 → Follow → TCP Stream
2. FTP, Telnet, HTTP 평문 내용 전체 복원 가능
3. 자격 증명, 파일 내용 등 확인 가능

### Statistics 활용
```
Statistics → Protocol Hierarchy    # 프로토콜 비율 분석
Statistics → Conversations         # 통신 세션 목록
Statistics → IO Graph              # 트래픽 그래프
Statistics → HTTP → Requests       # HTTP 요청 목록
```

---

## 4. 패킷 캡처로 알 수 있는 것들

### FTP 크리덴셜 추출
```bash
# tcpdump로 FTP 크리덴셜 캡처
tcpdump -i eth0 -A 'tcp port 21'

# Wireshark 필터
ftp contains "USER" or ftp contains "PASS"

# 출력 예시:
# USER admin
# PASS password123
```

### HTTP 기본 인증 크리덴셜
```bash
# HTTP Authorization 헤더 캡처
tcpdump -i eth0 -A 'tcp port 80' | grep -i "authorization:"

# Base64 디코딩
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d
# admin:password
```

### DNS 쿼리 분석 (C2 통신 탐지)
```bash
# 비정상적으로 많은 DNS 쿼리 탐지
tcpdump -i eth0 -n port 53 | awk '{print $9}' | sort | uniq -c | sort -rn | head -20

# DNS 터널링 탐지 (긴 서브도메인)
tshark -r capture.pcap -T fields -e dns.qry.name | awk 'length > 50' | sort | uniq
```

---

## 5. Wireshark 색상 규칙 이해

| 색상 | 의미 |
|------|------|
| 검정 배경 빨간 글씨 | 오류 패킷 (체크섬 불일치 등) |
| 파란 배경 | DNS, ARP 등 일반 정보 |
| 연두색 | HTTP 트래픽 |
| 회색 | TCP 트래픽 |
| 노란색 | 경고 (재전송, 순서 오류) |
| 보라색 | TCP RST, FIN |

---

## 6. 실전 패킷 분석 시나리오

### 시나리오 1: 포트 스캔 탐지
```
증상: 대량의 SYN 패킷, 대부분 RST로 응답

Wireshark 필터:
  tcp.flags.syn == 1 && tcp.flags.ack == 0

분석 포인트:
  1. 출발지 IP가 동일하고 목적지 포트가 순차적으로 변함
  2. 짧은 시간 내 수백~수천 개의 SYN 패킷
  3. SYN/RST 응답 비율이 높음 (닫힌 포트)
  4. SYN/SYN+ACK 응답 = 열린 포트
```

### 시나리오 2: ARP 스푸핑 탐지
```
증상: 동일 IP에 대해 서로 다른 MAC 주소의 ARP Reply

Wireshark 필터:
  arp.opcode == 2  (ARP Reply만)

분석 포인트:
  1. 동일 IP에 대해 두 개 이상의 MAC 주소가 응답
  2. 짧은 간격으로 연속적인 ARP Reply
  3. 특히 게이트웨이 IP에 대한 이중 응답 주시
```

### 시나리오 3: 비밀번호 스니핑
```
캡처 환경: 스위치 환경에서는 미러링(SPAN) 포트 필요
           허브 환경에서는 바로 캡처 가능

Wireshark 필터 (FTP):
  ftp.request.command == "USER" or ftp.request.command == "PASS"

Wireshark 필터 (HTTP 폼):
  http.request.method == "POST" && http contains "password"

tshark 자동 추출:
  tshark -r capture.pcap -Y "ftp.request.command" -T fields -e ftp.request.arg
```

---

## 7. SSH 터널링 & 포트 포워딩

### 로컬 포트 포워딩
```bash
# 로컬 8080 → 서버의 80포트 (방화벽 우회)
ssh -L 8080:localhost:80 user@server.com

# 내부망 서버 접근 (점프 호스트)
ssh -L 3389:internal.host:3389 user@jumphost.com

# 브라우저에서 http://localhost:8080 으로 접속
```

### 리버스 포트 포워딩 (방화벽 우회)
```bash
# 서버의 2222 → 로컬 22 (NAT 뒤에 있는 서버에 접근)
ssh -R 2222:localhost:22 user@public.server.com

# 공개 서버에서 내부 서버 SSH 접근
ssh -p 2222 localhost
```

### SOCKS 프록시 (동적 포트 포워딩)
```bash
# SSH를 통한 SOCKS5 프록시 생성
ssh -D 1080 user@server.com

# ProxyChains 설정 (/etc/proxychains.conf)
# socks5 127.0.0.1 1080

# ProxyChains를 통한 도구 사용
proxychains nmap -sT 10.0.0.1
proxychains curl http://internal.site/
```
