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

---

## 9. 서브넷팅 & 슈퍼넷팅 심화

### 서브넷팅 계산 공식
```
서브넷 수     = 2^(빌린 비트 수)
호스트 수     = 2^(남은 호스트 비트 수) - 2
블록 크기     = 256 - (마지막 옥텟 서브넷 마스크 값)
```

### 8의 배수가 아닌 서브넷 계산 (VLSM)
```
예시: 192.168.10.0/27

비트 분석:
  /27 = 11111111.11111111.11111111.11100000
       = 255.255.255.224

블록 크기: 256 - 224 = 32
서브넷 목록:
  192.168.10.0   ~ 192.168.10.31   (NW: .0,   BC: .31,  사용: .1~.30)
  192.168.10.32  ~ 192.168.10.63   (NW: .32,  BC: .63,  사용: .33~.62)
  192.168.10.64  ~ 192.168.10.95   (NW: .64,  BC: .95,  사용: .65~.94)
  192.168.10.96  ~ 192.168.10.127  (NW: .96,  BC: .127, 사용: .97~.126)
  ... (총 8개 서브넷, 각 30 호스트)
```

```
예시: 172.16.0.0/20

비트 분석:
  /20 = 11111111.11111111.11110000.00000000
       = 255.255.240.0

블록 크기 (3번째 옥텟): 256 - 240 = 16
서브넷 목록:
  172.16.0.0   ~ 172.16.15.255   (4094 호스트)
  172.16.16.0  ~ 172.16.31.255   (4094 호스트)
  172.16.32.0  ~ 172.16.47.255   (4094 호스트)
  ...
```

### VLSM (Variable Length Subnet Mask) 설계 예시
```
요구사항:
  네트워크 A: 100대 호스트 필요 → /25 (126 호스트)
  네트워크 B: 50대 호스트 필요  → /26 (62 호스트)
  네트워크 C: 20대 호스트 필요  → /27 (30 호스트)
  네트워크 D: 10대 호스트 필요  → /28 (14 호스트)

기준 네트워크: 192.168.1.0/24 할당
  A: 192.168.1.0/25   (192.168.1.1 ~ .126,  BC: .127)
  B: 192.168.1.128/26 (192.168.1.129 ~ .190, BC: .191)
  C: 192.168.1.192/27 (192.168.1.193 ~ .222, BC: .223)
  D: 192.168.1.224/28 (192.168.1.225 ~ .238, BC: .239)
  남는 공간: 192.168.1.240/28 (미래 확장용)
```

### 슈퍼넷팅 (Supernetting / CIDR)
```
목적: 여러 네트워크를 하나의 큰 블록으로 묶어 라우팅 테이블 축소

예시: 4개 C클래스 네트워크를 /22로 묶기
  192.168.0.0/24
  192.168.1.0/24
  192.168.2.0/24
  192.168.3.0/24
  
  → 192.168.0.0/22 (슈퍼넷)
  
조건: 연속된 네트워크이고 2의 제곱수 단위여야 함
비트 분석: 
  192.168.00000000.0 ←
  192.168.00000001.0   → 처음 22비트 동일
  192.168.00000010.0
  192.168.00000011.0 ←
```

---

## 10. EIGRP 및 OSPF 상세 설정

### EIGRP 설정
```
Router(config)# router eigrp 100           # AS 번호 100
Router(config-router)# network 192.168.1.0
Router(config-router)# network 10.0.0.0 0.255.255.255  # 와일드카드 마스크
Router(config-router)# no auto-summary     # 자동 요약 비활성화 (중요!)
Router(config-router)# passive-interface FastEthernet0/0  # 이 인터페이스로 광고 X

# 대역폭/지연 메트릭 조정
Router(config-if)# bandwidth 1000          # kbps 단위
Router(config-if)# delay 1                 # 10마이크로초 단위

# EIGRP 확인 명령어
Router# show ip eigrp neighbors            # 이웃 라우터 확인
Router# show ip eigrp topology             # 토폴로지 테이블
Router# show ip route eigrp               # EIGRP 라우팅 경로
```

### OSPF 상세 설정
```
Router(config)# router ospf 1
Router(config-router)# router-id 1.1.1.1  # 라우터 ID 수동 설정
Router(config-router)# network 192.168.1.0 0.0.0.255 area 0
Router(config-router)# network 10.0.0.0 0.0.0.3 area 1

# OSPF 타이머 조정 (빠른 수렴)
Router(config-if)# ip ospf hello-interval 5    # Hello 패킷 간격(초)
Router(config-if)# ip ospf dead-interval 20    # Dead 타이머(초)

# OSPF 비용(Cost) 조정
Router(config-if)# ip ospf cost 10

# OSPF 확인 명령어
Router# show ip ospf neighbor             # 이웃 관계 확인
Router# show ip ospf database            # LSDB 확인
Router# show ip route ospf              # OSPF 경로 확인
Router# debug ip ospf events            # 실시간 이벤트 디버그
```

---

## 11. Access Control List (ACL) — 트래픽 제어

### Standard ACL (표준, 출발지 IP만 제어)
```
# Standard ACL 생성 (번호 1-99, 1300-1999)
Router(config)# access-list 10 deny   192.168.1.100 0.0.0.0   # 특정 호스트 차단
Router(config)# access-list 10 deny   192.168.2.0   0.0.0.255  # 서브넷 차단
Router(config)# access-list 10 permit any                       # 나머지 허용

# 인터페이스에 적용 (목적지에 가깝게)
Router(config-if)# ip access-group 10 out

# Named Standard ACL
Router(config)# ip access-list standard BLOCK_HR
Router(config-std-nacl)# deny   10.1.1.0 0.0.0.255
Router(config-std-nacl)# permit any
```

### Extended ACL (확장, 출발지/목적지/프로토콜/포트 제어)
```
# Extended ACL 생성 (번호 100-199, 2000-2699)
# 형식: access-list <번호> <permit|deny> <프로토콜> <출발지> <목적지> [포트]

# HTTP만 허용
Router(config)# access-list 101 permit tcp any any eq 80
Router(config)# access-list 101 permit tcp any any eq 443
Router(config)# access-list 101 deny   ip  any any

# FTP 차단
Router(config)# access-list 102 deny tcp 192.168.1.0 0.0.0.255 any eq 21
Router(config)# access-list 102 permit ip any any

# Telnet 차단, SSH 허용
Router(config)# access-list 103 deny   tcp any any eq 23
Router(config)# access-list 103 permit tcp any any eq 22
Router(config)# access-list 103 permit ip any any

# 인터페이스에 적용 (출발지에 가깝게)
Router(config-if)# ip access-group 101 in

# ACL 확인
Router# show access-lists
Router# show ip interface FastEthernet0/0  # 적용된 ACL 확인
```

### ACL 해킹 관점
```
취약점:
1. implicit deny all 때문에 마지막에 permit any 누락 시 전체 차단
2. ACL 순서가 중요 (top-down 방식) → 앞에 광범위한 permit이 있으면 뒤 deny 무시
3. Standard ACL을 출발지에 적용 → 의도치 않은 트래픽 차단
4. 반사 ACL (Reflexive ACL) 미사용 시 리버스 트래픽 차단 가능

우회 기법:
- IP 스푸핑으로 허용된 출발지 IP 위장
- 허용된 포트 사용 (예: DNS 포트 53으로 터널링)
- IP 단편화로 포트 번호 숨기기
```

---

## 12. STP (Spanning-Tree Protocol)

### STP 동작 원리
```
목적: 스위치 루프 방지 (브로드캐스트 스톰 예방)

동작 과정:
1. Root Bridge 선출 (가장 낮은 Bridge ID = Priority + MAC)
2. 각 스위치의 Root Port 선정 (Root Bridge까지 가장 빠른 경로)
3. 각 세그먼트의 Designated Port 선정
4. 나머지 포트는 Blocking 상태로 전환

포트 상태 전환:
  Blocking → Listening (15초) → Learning (15초) → Forwarding
  총 수렴 시간: 약 30~50초
```

### STP 공격 벡터
```
# STP 루트 하이재킹 (BPDU 조작)
공격자가 낮은 Bridge Priority로 Root Bridge 선출 유도
→ 모든 트래픽이 공격자 스위치를 경유
→ MITM 공격 가능

# Yersinia로 STP 공격
yersinia -I   # 대화형 모드
# STP 메뉴에서 → claiming root role 선택

방어:
Router(config-if)# spanning-tree portfast           # 엣지 포트 즉시 포워딩
Router(config-if)# spanning-tree bpduguard enable   # BPDU 수신 시 포트 차단
Router(config)# spanning-tree portfast bpduguard default
```

---

## 13. VLAN (Virtual LAN)

### VLAN 기본 설정
```
# VLAN 생성
Switch(config)# vlan 10
Switch(config-vlan)# name Engineering
Switch(config)# vlan 20
Switch(config-vlan)# name Sales

# Access 포트 설정 (단일 VLAN)
Switch(config)# interface FastEthernet 0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10

# Trunk 포트 설정 (여러 VLAN 통과)
Switch(config)# interface GigabitEthernet 0/1
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk encapsulation dot1q   # 802.1Q 태깅
Switch(config-if)# switchport trunk allowed vlan 10,20   # 허용할 VLAN

# VLAN 확인
Switch# show vlan brief
Switch# show interfaces trunk
```

### VLAN 공격 (VLAN Hopping)
```
공격 1: Switch Spoofing
- 공격자 포트가 Trunk로 협상되도록 유도
- Dynamic Trunking Protocol(DTP) 악용

방어:
Switch(config-if)# switchport mode access          # 강제로 access 모드
Switch(config-if)# switchport nonegotiate          # DTP 비활성화

공격 2: Double Tagging (이중 태깅)
- 공격자가 두 개의 VLAN 태그 삽입
- 첫 번째 태그는 Native VLAN, 두 번째는 목표 VLAN
- Native VLAN과 다른 VLAN으로 패킷 전달

방어:
Switch(config-if)# switchport trunk native vlan 999  # Native VLAN 변경
Switch(config)# vlan 999
Switch(config-vlan)# name UNUSED_NATIVE             # 사용하지 않는 VLAN으로
```

### Inter-VLAN 라우팅 (Router-on-a-Stick)
```
# 라우터 서브인터페이스 설정
Router(config)# interface FastEthernet0/0.10
Router(config-subif)# encapsulation dot1q 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0

Router(config)# interface FastEthernet0/0.20
Router(config-subif)# encapsulation dot1q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0
```

---

## 14. DNS 보안 심화

### DNS Zone Transfer 보안 설정

#### BIND (named.conf) 설정
```
// 특정 슬레이브 서버만 Zone Transfer 허용
zone "example.com" IN {
    type master;
    file "/var/named/example.com.zone";
    allow-transfer { 192.168.1.2; };    // 슬레이브 서버 IP만 허용
    also-notify   { 192.168.1.2; };
};

// 재귀 쿼리 제한 (외부에서 내부 정보 수집 방지)
options {
    allow-recursion { 192.168.0.0/24; };  // 내부 네트워크만 재귀 허용
    allow-query     { any; };
    allow-transfer  { none; };            // 기본값: 모두 차단
};
```

#### TSIG (Transaction Signature) — 인증된 Zone Transfer
```
# TSIG 키 생성
dnssec-keygen -a HMAC-MD5 -b 128 -n HOST transfer-key

# named.conf에 TSIG 설정
key "transfer-key" {
    algorithm hmac-md5;
    secret "base64encodedkey==";
};

server 192.168.1.2 {
    keys { transfer-key; };
};
```

### DNS 스푸핑 & 캐시 포이즈닝 방어
```
# DNSSEC 활성화 (응답 무결성 검증)
# 존 서명
dnssec-signzone -A -3 random -N INCREMENT -o example.com -t example.com.zone

# named.conf DNSSEC 활성화
options {
    dnssec-enable yes;
    dnssec-validation yes;
    dnssec-lookaside auto;
};

# DNS 캐시 포이즈닝 방지
options {
    query-source address * port *;     # 랜덤 소스 포트 (기본값)
    minimal-responses yes;
};
```

### SPF (Sender Policy Framework) 레코드
```
# DNS TXT 레코드로 SPF 설정 (메일 스푸핑 방지)
# example.com. IN TXT "v=spf1 ip4:192.168.1.0/24 include:_spf.google.com -all"

# 항목 설명:
# v=spf1          : SPF 버전
# ip4:192.168.1.0/24 : 허용된 발송 IP 대역
# include:domain  : 다른 도메인의 SPF 포함
# ~all            : SoftFail (스팸으로 표시하되 거부 X)
# -all            : HardFail (완전 거부)
# +all            : 모두 허용 (위험!)

# Postfix에서 SPF 검사 활성화
apt-get install postfix-policyd-spf-python
# /etc/postfix/main.cf 추가:
# smtpd_recipient_restrictions = check_policy_service unix:private/policy-spf

# qmail SPF 설정
# /var/qmail/control/spfbehavior 파일 생성
echo "2" > /var/qmail/control/spfbehavior
# 0=무시, 1=헤더추가, 2=소프트실패거부, 3=하드실패거부
```

### DNS 서버 설치 및 설정 (BIND)
```bash
# BIND 설치
apt-get install bind9 bind9utils

# 설정 파일 위치
# /etc/bind/named.conf          : 메인 설정
# /etc/bind/named.conf.options  : 옵션
# /etc/bind/named.conf.local    : 존 선언
# /var/cache/bind/              : 존 파일

# 정방향 조회 존 파일 예시 (/var/cache/bind/example.com.zone)
$TTL 86400
@   IN SOA ns1.example.com. admin.example.com. (
        2024041801  ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        86400 )     ; Minimum TTL

@   IN NS  ns1.example.com.
@   IN NS  ns2.example.com.
@   IN MX  10 mail.example.com.
@   IN A   192.168.1.10
www IN A   192.168.1.10
ns1 IN A   192.168.1.1
ns2 IN A   192.168.1.2
mail IN A  192.168.1.5

# 설정 검증
named-checkconf
named-checkzone example.com /var/cache/bind/example.com.zone

# 서비스 재시작
systemctl restart bind9
```

---

## 15. Cisco IOS — 장비 접근 및 기초 명령어

### 접근 방법
```
Console Port    → 직접 연결, 초기 설정 시 사용
Auxiliary Port  → 모뎀을 통한 원격 접속
Virtual Terminal (Telnet/SSH) → 원격 CLI 접속
TFTP / HTTP     → 설정 백업 및 배포
```

### IOS 실행 모드
```
Router>          # User Mode (제한된 명령어, show 일부만 가능)
Router#          # Privileged Mode (모든 명령어 사용)
Router(config)#  # Global Configuration Mode
Router(config-if)# # Interface Configuration Mode
Router(config-router)# # Routing Protocol Mode
```

### 기본 초기 설정 흐름
```
Router> enable
Router# configure terminal
Router(config)# hostname R1
Router(config)# enable secret cisco123          # 암호화된 Privileged 패스워드
Router(config)# service password-encryption     # 모든 평문 패스워드 암호화
Router(config)# no ip domain-lookup             # DNS 조회로 인한 명령어 지연 제거
Router(config)# line console 0
Router(config-line)# password console123
Router(config-line)# login
Router(config-line)# logging synchronous        # 콘솔 메시지 방해 방지
Router(config)# line vty 0 4
Router(config-line)# password vtypass
Router(config-line)# login
Router(config)# banner motd # Unauthorized access prohibited #

# 설정 저장
Router# copy running-config startup-config
Router# write memory          # 또는 wr (단축키)

# 설정 확인
Router# show running-config
Router# show interfaces
Router# show ip interface brief     # 인터페이스 IP 상태 요약
Router# show version                # IOS 버전 및 하드웨어 정보
```

### Cisco 스위치 기본 동작 (Layer 2)
```
스위치 핵심 동작 5단계:
1. Learning   - 수신 프레임의 Source MAC을 MAC 테이블에 등록
2. Flooding   - 목적지 MAC 모를 경우, 수신 포트 제외 전체 포트로 전송
3. Forwarding - 목적지 MAC이 테이블에 있으면 해당 포트로만 전송
4. Filtering  - 발신/수신이 동일 포트이면 전송 차단
5. Aging      - 300초 동안 미사용 MAC 테이블 항목 삭제

# MAC 테이블 확인
Switch# show mac address-table
Switch# show mac address-table aging-time

# 스위칭 방식
Cut-through     : 목적지 MAC 확인 즉시 전송 (빠름, 에러 검사 없음)
Store-and-Forward : 전체 프레임 수신 후 CRC 검사 후 전송 (느림, 안정적)
Fragment-Free   : 첫 64바이트 검사 후 전송 (Runt Frame 필터링)
```

---

## 16. 라우팅 테이블 상세 해석

### show ip route 출력 해석
```
R1# show ip route

Gateway of last resort is 13.13.12.2 to network 0.0.0.0

     13.0.0.0/24 is subnetted, 3 subnets
C       13.13.10.0 is directly connected, FastEthernet0/0
C       13.13.12.0 is directly connected, Serial1/0
S       13.13.30.0 [1/0] via 13.13.12.2
R       13.13.20.0 [120/2] via 13.13.12.2, 00:00:13, Serial1/0
D       172.16.1.0 [90/183451] via 10.1.1.1

코드 의미:
  C = Connected (직접 연결)
  S = Static (정적 경로)
  R = RIP
  D = EIGRP
  O = OSPF
  B = BGP
  S* = Static Default Route

[1/0] = [Administrative Distance / Metric]
  1   = Static Route AD
  120 = RIP AD
  90  = EIGRP (내부) AD
  110 = OSPF AD
  
via 13.13.12.2 = 다음 홉(Next-Hop) IP 주소
00:00:13       = 마지막 업데이트 이후 경과 시간
Serial1/0      = 출력 인터페이스
```

### 라우팅 테이블 검색 우선순위
```
1. Longest Match Rule (더 구체적인 경로 우선)
   예: 목적지 172.16.1.1 → 172.16.1.0/25 (더 구체적) vs 172.16.1.0/24
   → 172.16.1.0/25 선택

2. Administrative Distance (신뢰도, 낮을수록 우선)
   D 172.16.1.0 [90/...]  vs  R 172.16.1.0 [120/...]
   → EIGRP (90) 선택

3. Metric (메트릭 낮을수록 우선)
   D 172.16.1.0 [90/231245]  vs  D 172.16.1.0 [90/183451]
   → 183451 선택 (더 낮음)
```

### Cisco 라우터 데이터 처리 방식 3가지
```
① Process Switching   : 매 패킷마다 라우팅 테이블 검색 (가장 느림)
② Fast Switching      : 첫 패킷만 검색 후 캐시에 저장, 이후 캐시 참조
③ CEF (Cisco Express Forwarding) : 라우팅 테이블 전체를 처음부터 캐시화 (가장 빠름)
```

### RIP 설정 (참고 - 구형 프로토콜)
```
Router(config)# router rip
Router(config-router)# version 2              # RIPv2 (서브넷 마스크 지원)
Router(config-router)# network 13.0.0.0
Router(config-router)# no auto-summary

# RIP 확인
Router# show ip route rip
Router# debug ip rip                          # RIP 업데이트 실시간 확인
```

---

## 17. VTP (VLAN Trunking Protocol)

### VTP 개요 및 모드
```
목적: 여러 스위치에서 VLAN 정보를 자동으로 동기화

VTP 모드:
  Server      - VLAN 생성/수정/삭제 가능, NVRAM에 저장, 광고 전송
  Client      - VLAN 생성/수정/삭제 불가, 광고 수신 및 동기화, NVRAM 미저장
  Transparent - VLAN 독자 관리, 광고 전달하지만 동기화 안 함, NVRAM에 저장

# VTP 설정
Switch(config)# vtp mode server
Switch(config)# vtp domain COMPANY
Switch(config)# vtp password vtp123

# VTP 확인
Switch# show vtp status
Switch# show vtp counters
```

### VTP 보안 취약점
```
위험: VTP Revision Number가 높은 스위치가 연결되면
      기존 VLAN 설정이 덮어쓰여질 수 있음 (VLAN 삭제 위험)

공격 시나리오:
  공격자 스위치를 높은 Revision Number로 네트워크에 연결
  → 전체 스위치 VLAN 설정 초기화

방어:
Switch(config)# vtp mode transparent       # Transparent 모드로 VTP 비활성화
Switch(config)# vtp password 강력한패스워드
# 또는 VTP 버전 3 사용 (기본 패스워드 미설정 시 영향 없음)
```

### 802.1Q 프레임 구조
```
원본 이더넷 프레임에 4바이트 태그 삽입:
  TPID (2byte) : 0x8100 (802.1Q 식별)
  TCI  (2byte) : Priority(3bit, QoS) + CFI(1bit) + VLAN ID(12bit, 0~4095)

Native VLAN: 태그 없이 전송되는 VLAN (기본값 VLAN 1)
  → 보안 위험: Double Tagging 공격의 기반
  → 권장: Native VLAN을 사용하지 않는 전용 VLAN으로 변경

ISL (Inter-Switch Link): Cisco 독점 트렁킹 방식 (구형, 802.1Q로 대체됨)
```

---

## 18. SSH 고급 설정 및 보안

### SSH 서버 보안 강화 (/etc/ssh/sshd_config)
```
# 기본 보안 설정
Port 2222                          # 기본 포트 변경
PermitRootLogin no                 # root 직접 로그인 차단
PasswordAuthentication no          # 패스워드 인증 비활성화
PubkeyAuthentication yes           # 공개키 인증만 허용
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3                     # 최대 인증 시도 횟수
LoginGraceTime 30                  # 로그인 제한 시간(초)
X11Forwarding no                   # X11 포워딩 비활성화
AllowUsers alice bob               # 특정 사용자만 허용
Protocol 2                         # SSHv2만 허용

# 서비스 재시작
systemctl restart sshd
```

### SSH 키 기반 인증 설정
```bash
# 클라이언트에서 키 생성
ssh-keygen -t ed25519 -C "attacker@kali"        # Ed25519 (권장)
ssh-keygen -t rsa -b 4096 -C "user@example.com"  # RSA 4096비트

# 서버에 공개키 등록
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
# 또는 수동으로
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 특정 키로만 접속
ssh -i ~/.ssh/id_ed25519 user@server
```

### SSH 포트 포워딩 심화
```bash
# 로컬 포트 포워딩 (-L)
# 내 로컬 포트 → 원격 서버를 통해 → 목적지
ssh -L [로컬IP:]로컬포트:목적지호스트:목적지포트 user@SSH서버

# 예시: 내부망 DB 접근 (점프 호스트 활용)
ssh -L 5432:db.internal:5432 user@jumphost.example.com
# → localhost:5432 접속 시 db.internal:5432로 연결

# 리버스 포트 포워딩 (-R)
# 원격 서버 포트 → 내 로컬로 역방향 연결
ssh -R [원격IP:]원격포트:로컬호스트:로컬포트 user@SSH서버

# 예시: NAT 뒤 서버 외부 노출
ssh -R 0.0.0.0:8080:localhost:80 user@public.server
# → public.server:8080 접속 시 내 로컬 80포트로 연결

# SOCKS5 동적 포트 포워딩 (-D)
ssh -D 1080 -C -N user@server   # -C: 압축, -N: 명령 실행 없음
# → 모든 트래픽을 SSH 터널을 통해 프록시

# 영구적 SSH 터널 (autossh)
apt-get install autossh
autossh -M 20000 -f -N -L 8080:localhost:80 user@server
# -M: 모니터링 포트, -f: 백그라운드 실행

# ProxyJump (다단계 점프)
ssh -J user1@jumphost1,user2@jumphost2 user3@target
# ~/.ssh/config 설정
Host target
    HostName 10.0.0.100
    User admin
    ProxyJump jumphost

Host jumphost
    HostName public.server.com
    User user
    Port 22
```

---

## 19. Zone Transfer 공격 실전 절차

### Zone Transfer 취약점 확인 절차
```bash
# Step 1: 도메인의 네임서버 확인
whois target.com
# 또는
nslookup -type=NS target.com
dig NS target.com

# Step 2: 각 네임서버에 Zone Transfer 시도
dig @ns1.target.com target.com AXFR
dig @ns2.target.com target.com AXFR

# 성공 시 출력 예시:
# target.com.        1800 IN SOA  ns1.target.com. ...
# target.com.        1800 IN MX   10 mail.target.com.
# admin.target.com.  300  IN A    192.168.1.10    ← 내부 서버 IP 노출
# dev.target.com.    300  IN A    10.0.0.5        ← 개발 서버 IP 노출
# vpn.target.com.    300  IN A    203.x.x.x       ← VPN 서버 노출
# db.target.com.     300  IN A    192.168.1.100   ← DB 서버 노출

# host 명령어로도 시도
host -t AXFR target.com ns1.target.com

# nmap NSE 스크립트
nmap --script dns-zone-transfer -p 53 ns1.target.com
```

### Zone Transfer가 허용된 경우 정보 수집
```bash
# 수집 가능한 정보:
# - 내부 서버 IP 대역
# - 개발/스테이징 서버 위치
# - 방화벽, 로드밸런서 등 보안 장비 IP
# - 메일 서버, VPN 서버 정보
# - 인트라넷 서버 도메인

# 자동화된 정보 수집
dig @ns1.target.com target.com AXFR | grep " A " | awk '{print $1, $5}' | sort

# IP 대역 추출
dig @ns1.target.com target.com AXFR | grep " A " | awk '{print $5}' | \
    sed 's/\.[0-9]*$//' | sort -u
```

### Zone Transfer 방어 방법 우선순위
```
1순위: named.conf allow-transfer 설정
  zone "example.com" {
      allow-transfer { 192.168.1.2; };  // slave IP만
  };

2순위: ACL로 53번 TCP 제한 (Zone Transfer는 TCP 사용)
  // UDP 53 = 일반 DNS 쿼리 (허용)
  // TCP 53 = Zone Transfer (Slave에서만 허용)
  iptables -A INPUT -p tcp --dport 53 -s 192.168.1.2 -j ACCEPT
  iptables -A INPUT -p tcp --dport 53 -j DROP

3순위: TSIG 인증 (암호화 키 기반)
  → Slave 서버와 공유 키로 Zone Transfer 인증

점검 체크리스트:
  [ ] ns1과 ns2 모두 Zone Transfer 차단 확인
  [ ] dig AXFR 명령으로 외부에서 테스트
  [ ] 내부 서버 도메인이 외부 Zone에 없는지 확인
  [ ] Split DNS 구성 (내부/외부 다른 Zone 파일)
```

### Split DNS (내부/외부 분리)
```bash
# named.conf — 뷰를 이용한 Split DNS
view "internal" {
    match-clients { 192.168.0.0/24; };
    zone "example.com" {
        type master;
        file "/etc/bind/internal/db.example.com";
        # 내부 존 파일: 내부 서버 IP 포함
    };
};

view "external" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "/etc/bind/external/db.example.com";
        allow-transfer { none; };
        # 외부 존 파일: 공개 서버 IP만 포함
    };
};
```

---

## 20. 서브넷 마스크 빠른 계산 레퍼런스

### /25 ~ /31 마스크 빠른 표
| CIDR | 마스크 | 블록 크기 | 서브넷 수 | 호스트 수 | 네트워크 시작 주소 패턴 |
|------|--------|---------|---------|---------|---------------------|
| /25 | 255.255.255.128 | 128 | 2  | 126 | .0, .128 |
| /26 | 255.255.255.192 | 64  | 4  | 62  | .0, .64, .128, .192 |
| /27 | 255.255.255.224 | 32  | 8  | 30  | .0, .32, .64, .96, .128, .160, .192, .224 |
| /28 | 255.255.255.240 | 16  | 16 | 14  | .0, .16, .32, ..., .240 |
| /29 | 255.255.255.248 | 8   | 32 | 6   | .0, .8, .16, ..., .248 |
| /30 | 255.255.255.252 | 4   | 64 | 2   | .0, .4, .8, ..., .252 (P2P 링크) |
| /31 | 255.255.255.254 | 2   | 128 | 0  | .0, .2, .4, ... (RFC 3021, P2P 전용) |

### B클래스 비표준 서브넷
| CIDR | 마스크 | 블록 크기 (3번째 옥텟) | 호스트 수 |
|------|--------|---------------------|---------|
| /17 | 255.255.128.0 | 128 | 32766 |
| /18 | 255.255.192.0 | 64  | 16382 |
| /19 | 255.255.224.0 | 32  | 8190 |
| /20 | 255.255.240.0 | 16  | 4094 |
| /21 | 255.255.248.0 | 8   | 2046 |
| /22 | 255.255.252.0 | 4   | 1022 |
| /23 | 255.255.254.0 | 2   | 510 |

### 서브넷 계산 5단계 (실전)
```
예제: IP 192.168.1.50/26 → 해당 서브넷 정보 구하기

Step 1: 마스크 확인
  /26 = 255.255.255.192  (마지막 옥텟 = 11000000 = 192)

Step 2: 블록 크기 계산
  블록 크기 = 256 - 192 = 64

Step 3: 해당 블록 찾기
  64의 배수: 0, 64, 128, 192, 256
  50은 0~63 구간 → 네트워크 주소 = 192.168.1.0

Step 4: 브로드캐스트 주소
  다음 블록 시작 - 1 = 64 - 1 = 63 → 브로드캐스트 = 192.168.1.63

Step 5: 호스트 범위
  192.168.1.1 ~ 192.168.1.62 (62개)
  
결론: 192.168.1.50/26은 192.168.1.0/26 서브넷 (NW:.0, BC:.63, 호스트:.1~.62)
```

### Supernetting 조건 확인
```
4개 네트워크를 하나로 묶으려면:
  1. 연속된 네트워크여야 함
  2. 2의 제곱수 단위여야 함
  3. 첫 번째 네트워크의 4배 단위 경계에서 시작해야 함

예시: 192.168.4.0/24 ~ 192.168.7.0/24 를 /22로 묶기
  4개 네트워크 → /24 - 2비트 = /22
  비트 검증:
    192.168.00000100.0  ←
    192.168.00000101.0     처음 22비트 동일
    192.168.00000110.0     → 슈퍼넷: 192.168.4.0/22
    192.168.00000111.0  ←
```
