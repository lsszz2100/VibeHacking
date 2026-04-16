# OSI 7계층 & TCP/IP — 네트워크 해킹의 기초

## 1. OSI 7계층 모델

```
┌─────────────────────────────────────────────┐
│  7. 응용 계층  (Application)   HTTP, FTP, SMTP │
│  6. 표현 계층  (Presentation)  SSL, ASCII, JPEG│
│  5. 세션 계층  (Session)       NetBIOS, RPC    │
│  4. 전송 계층  (Transport)     TCP, UDP        │
│  3. 네트워크   (Network)       IP, ICMP, ARP   │
│  2. 데이터링크 (Data Link)     Ethernet, MAC   │
│  1. 물리 계층  (Physical)      Cable, Hub      │
└─────────────────────────────────────────────┘
```

| 계층 | 이름 | 데이터 단위 | 주요 프로토콜 | 해킹 관련 |
|------|------|------------|-------------|---------|
| 7 | 응용 | 메시지 | HTTP, FTP, SSH, DNS | 웹 해킹, 취약점 악용 |
| 6 | 표현 | 메시지 | TLS/SSL, MIME | SSL Strip, POODLE |
| 5 | 세션 | 메시지 | NetBIOS, RPC | 세션 하이재킹 |
| 4 | 전송 | 세그먼트 | TCP, UDP | SYN Flood, UDP Flood |
| 3 | 네트워크 | 패킷 | IP, ICMP, ARP | IP 스푸핑, ICMP Flood |
| 2 | 데이터링크 | 프레임 | Ethernet, PPP | ARP 스푸핑, MAC Flood |
| 1 | 물리 | 비트 | Cable, Wi-Fi | 도청(Tapping), 전파 방해 |

---

## 2. TCP/IP 4계층 모델

```
┌────────────────────────────────────────────┐
│  4. 응용 계층  HTTP, FTP, SMTP, DNS         │
│  3. 전송 계층  TCP, UDP                     │
│  2. 인터넷     IP, ICMP, ARP               │
│  1. 네트워크   Ethernet, Wi-Fi             │
└────────────────────────────────────────────┘
```

---

## 3. TCP 3-Way Handshake (핵심 개념)

```
Client                    Server
  │                          │
  │──── SYN ────────────────►│  (1) 연결 요청
  │                          │      SEQ=100, SYN
  │◄─── SYN + ACK ──────────│  (2) 연결 수락
  │                          │      SEQ=300, ACK=101
  │──── ACK ────────────────►│  (3) 확인
  │                          │      ACK=301
  │                          │
  │ [데이터 교환 시작]         │
```

### TCP Flags
| 플래그 | 이름 | 의미 |
|--------|------|------|
| SYN | Synchronize | 연결 시작 |
| ACK | Acknowledge | 수신 확인 |
| FIN | Finish | 정상 종료 |
| RST | Reset | 강제 종료/거부 |
| PSH | Push | 즉시 전달 |
| URG | Urgent | 긴급 데이터 |

### TCP 4-Way Disconnect
```
Client                    Server
  │                          │
  │──── FIN ────────────────►│  (1) 종료 요청
  │◄─── ACK ────────────────│  (2) 수신 확인
  │◄─── FIN ────────────────│  (3) 서버도 종료
  │──── ACK ────────────────►│  (4) 최종 확인
```

---

## 4. IP 주소 체계

### IPv4 클래스 분류
| 클래스 | 범위 | 기본 서브넷 마스크 | 용도 |
|-------|------|-----------------|------|
| A | 1.0.0.0 ~ 126.255.255.255 | 255.0.0.0 (/8) | 대형 조직 |
| B | 128.0.0.0 ~ 191.255.255.255 | 255.255.0.0 (/16) | 중형 조직 |
| C | 192.0.0.0 ~ 223.255.255.255 | 255.255.255.0 (/24) | 소형 조직 |
| D | 224.0.0.0 ~ 239.255.255.255 | - | 멀티캐스트 |
| E | 240.0.0.0 ~ 255.255.255.255 | - | 연구용 |

### 사설 IP 대역 (Private IP)
```
10.0.0.0    ~ 10.255.255.255  (클래스 A)
172.16.0.0  ~ 172.31.255.255  (클래스 B)
192.168.0.0 ~ 192.168.255.255 (클래스 C)
```

### 서브넷 마스크 계산
```
예시: 192.168.1.0/24

서브넷 마스크: 255.255.255.0
네트워크 주소: 192.168.1.0    (첫 번째 주소)
브로드캐스트:  192.168.1.255  (마지막 주소)
사용 가능 IP:  192.168.1.1 ~ 192.168.1.254 (254개)
```

```
예시: 192.168.1.0/26 (8의 배수가 아닌 서브넷)

서브넷 마스크: 255.255.255.192
네트워크 주소: 192.168.1.0
브로드캐스트:  192.168.1.63
사용 가능 IP:  192.168.1.1 ~ 192.168.1.62 (62개)

26비트 = 11111111.11111111.11111111.11000000 = /26
          255     . 255    . 255    . 192
```

---

## 5. 주요 프로토콜 포트 번호

| 포트 | 프로토콜 | 서비스 | 해킹 관련 |
|------|----------|--------|---------|
| 20/21 | TCP | FTP | 평문 전송, 익명 접속 취약 |
| 22 | TCP | SSH | 브루트포스, 키 취약점 |
| 23 | TCP | Telnet | 완전 평문 전송 (위험) |
| 25 | TCP | SMTP | 메일 스푸핑, 릴레이 |
| 53 | TCP/UDP | DNS | DNS 스푸핑, Zone Transfer |
| 80 | TCP | HTTP | 웹 공격 전반 |
| 110 | TCP | POP3 | 평문 메일 |
| 139/445 | TCP | SMB | EternalBlue, 랜섬웨어 |
| 443 | TCP | HTTPS | SSL 관련 취약점 |
| 1433 | TCP | MSSQL | SQL 인젝션 |
| 1521 | TCP | Oracle | SQL 인젝션 |
| 3306 | TCP | MySQL | SQL 인젝션, 파일 읽기 |
| 3389 | TCP | RDP | 브루트포스, BlueKeep |
| 4444 | TCP | Metasploit | 기본 페이로드 포트 |
| 8080 | TCP | HTTP Alt | 웹 프록시 |

---

## 6. ARP 프로토콜 (ARP 스푸핑의 기초)

### ARP 동작 원리
```
Host A (192.168.1.10)                    Host B (192.168.1.20)
         │                                        │
         │  ARP Request (Broadcast)               │
         │  "Who has 192.168.1.20? Tell .1.10"   │
         │────────────────────────────────────────►│
         │                                        │
         │  ARP Reply (Unicast)                   │
         │  "192.168.1.20 is at AA:BB:CC:DD:EE:FF"│
         │◄────────────────────────────────────────│
```

### ARP 스푸핑 (중간자 공격)
```
정상 상태:
  Host A → [MAC:B] → Host B

ARP 스푸핑 후:
  Attacker가 Host A에게: "Host B는 나다 (Attacker MAC)"
  Attacker가 Host B에게: "Host A는 나다 (Attacker MAC)"
  
  Host A → [MAC:Attacker] → Attacker → [MAC:B] → Host B
                            (모든 트래픽 도청 가능)
```

```bash
# ARP 스푸핑 실행 (ettercap)
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# arpspoof 활용
echo 1 > /proc/sys/net/ipv4/ip_forward  # IP 포워딩 활성화
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1  # 피해자에게 ARP 조작
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100  # 게이트웨이에게 ARP 조작
```

---

## 7. DNS 프로토콜 (DNS 공격의 기초)

### DNS 레코드 타입
| 레코드 | 설명 | 예시 |
|-------|------|------|
| A | IPv4 주소 | example.com → 1.2.3.4 |
| AAAA | IPv6 주소 | example.com → ::1 |
| MX | 메일 서버 | mail.example.com |
| CNAME | 별칭 | www → example.com |
| NS | 네임서버 | ns1.example.com |
| PTR | 역방향 조회 | 1.2.3.4 → example.com |
| TXT | 텍스트 정보 | SPF, DMARC 레코드 |
| SOA | 존 권한 정보 | 시작 권한 레코드 |

### DNS 열거 (Zone Transfer 취약점)
```bash
# Zone Transfer 시도 (취약한 설정에서 전체 레코드 덤프)
dig @ns1.example.com example.com AXFR
host -t axfr example.com ns1.example.com
nmap --script dns-zone-transfer -p 53 example.com

# DNS 서브도메인 브루트포싱
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt
fierce --domain example.com
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Zone Transfer 방어 설정 (BIND)
```
// named.conf
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer { none; };  // Zone Transfer 차단
};
```

---

## 8. 라우팅 프로토콜

### 정적 라우팅 vs 동적 라우팅
| 구분 | 정적 | 동적 |
|------|------|------|
| 설정 | 관리자가 수동 | 라우팅 프로토콜 자동 |
| 안정성 | 높음 | 변경에 자동 대응 |
| 프로토콜 | 없음 | RIP, OSPF, EIGRP, BGP |

### OSPF vs EIGRP
| 항목 | OSPF | EIGRP |
|------|------|-------|
| 타입 | 링크 상태 | 하이브리드 |
| 알고리즘 | Dijkstra (SPF) | DUAL |
| 표준 | Open Standard | Cisco 독점 |
| 메트릭 | 비용 (Cost) | 복합 메트릭 |

### Cisco 라우터 기본 설정
```
Router> enable
Router# configure terminal
Router(config)# interface FastEthernet 0/0
Router(config-if)# ip address 192.168.1.1 255.255.255.0
Router(config-if)# no shutdown
Router(config-if)# exit

# 정적 라우팅
Router(config)# ip route 10.0.0.0 255.0.0.0 192.168.1.254

# OSPF 설정
Router(config)# router ospf 1
Router(config-router)# network 192.168.1.0 0.0.0.255 area 0
```
