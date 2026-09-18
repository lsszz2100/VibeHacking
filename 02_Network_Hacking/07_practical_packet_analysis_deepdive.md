> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 실전 패킷 분석 심화 — 와이어샤크 프로토콜 해부 및 패킷 포렌식

## 0. 초보자를 위한 개념 이해

### 실전 패킷 분석(Practical Packet Analysis)이란?

실전 패킷 분석은 네트워크 케이블과 무선 전파를 오가는 바이트 스트림을 직접 캡처하고, 프로토콜 사양(RFC)에 따라 비트 단위로 해체(Dissection)하여 이상 징후, 데이터 유출, 침입 시도를 식별하는 기술입니다. 단순히 GUI 도구를 열어보는 것을 넘어 TCP 윈도우 스케일링, 재전송 타이머, 핸드셰이크 상태 전이, 암호화 세션 키 바인딩을 이해함으로써 정교한 침해 사고를 규명합니다.

```
실전 패킷 분석 핵심 워크플로우:

  [1. 트래픽 캡처] ───> [2. 프로토콜 디코딩] ───> [3. 세션 재구성] ───> [4. 이상 탐지/추출]
     tcpdump /             Ethernet / IP /           TCP Stream /          C2 비컨, 자격증명,
     tshark                TCP / TLS / DNS           HTTP Flow             유출 파일 Carving
```

---

## 1. TCP 프로토콜 심층 분석 및 세션 이상 징후

### 1.1 TCP 3-Way Handshake & 상태 머신 해부

TCP 연결은 클라이언트와 서버 간의 엄격한 순서 번호(Sequence Number) 및 확인 응답 번호(Acknowledgment Number) 교환으로 시작됩니다.

```
       클라이언트 (Client)                                서버 (Server)
               │                                                │
               │────── SYN (Seq=X, Win=65535, MSS=1460, WS=8) ───>│  [SYN-RCVD]
               │                                                │
 [SYN-SENT]    │<───── SYN+ACK (Seq=Y, Ack=X+1, Win=28960, WS=7)─│
               │                                                │
 [ESTABLISHED] │────── ACK (Seq=X+1, Ack=Y+1, Win=65535) ───────>│  [ESTABLISHED]
               │                                                │
```

#### TCP 옵션(Options) 분석
1. **MSS (Maximum Segment Size)**: 수신 가능한 단일 TCP 페이로드의 최대 크기 (일반적으로 MTU 1500 - 40 = 1460 바이트).
2. **Window Scale (WS, RFC 7323)**: 16비트 Window 크기 필드($2^{16} = 65,535$)의 한계를 극복하기 위해 승수($2^S$)를 지정 (최대 14, 최대 1GB 버퍼).
3. **SACK Permitted (Selective ACK)**: 유실된 세그먼트 블록만 선별적으로 재전송 가능하도록 허용.

### 1.2 TCP 이상 현상과 공격 징후 탐지

| Wireshark Expert Info | 원인 및 공격 징후 | 분석 디스플레이 필터 |
|-----------------------|-------------------|----------------------|
| `TCP Retransmission` | 패킷 유실 또는 공격자의 대역폭 고갈(DDoS) | `tcp.analysis.retransmission` |
| `TCP Fast Retransmission` | 3개의 중복 ACK(Duplicate ACK) 수신 시 즉시 재전송 | `tcp.analysis.fast_retransmission` |
| `TCP Out-of-Order` | 비순차 세그먼트 수신 (경로 비대칭 or 패킷 인젝션) | `tcp.analysis.out_of_order` |
| `TCP ZeroWindow` | 수신 호스트 버퍼 고갈 (소진 공격 또는 처리 지연) | `tcp.analysis.zero_window` |
| `TCP RST (Reset)` | 비정상 세션 강제 종료 (방화벽 차단 or 세션 하이재킹) | `tcp.flags.reset == 1` |

---

## 2. ARP 스푸핑 및 네트워크 중간자(MITM) 분석

### 2.1 ARP 캐시 포이즈닝 원리
공격자는 대상 호스트와 게이트웨이에 지속적으로 가짜 ARP 응답(Gratuitous ARP / Unsolicited ARP Reply)을 전송하여 호스트의 ARP 캐시 테이블을 변조합니다.

```
[피해자 PC: 192.168.1.100]           [공격자: 192.168.1.50]           [게이트웨이: 192.168.1.1]
  MAC: AA:AA:AA:AA:AA:AA              MAC: BB:BB:BB:BB:BB:BB              MAC: CC:CC:CC:CC:CC:CC
           │                                    │                                    │
           │<── ARP Reply: 192.168.1.1 is BB ───│                                    │
           │                                    │─── ARP Reply: 192.168.1.100 is BB ─>│
           ▼                                                                         ▼
 [ARP 캐시 변조: 192.168.1.1 -> BB]                         [ARP 캐시 변조: 192.168.1.100 -> BB]
```

### 2.2 Wireshark 탐지 필터
```wireshark
# 동일한 IP에 대해 서로 다른 MAC 주소가 응답하는 중복 ARP 탐지
arp.duplicate-address-frame or arp.duplicate-address-detected

# 요청(Opcode 1) 없이 전달되는 비정상 단독 응답(Opcode 2) 필터링
arp.opcode == 2 and not arp.dst.proto_ipv4
```

---

## 3. DNS 터널링 및 은닉 C2 통신 탐지

공격자는 방화벽을 우회하기 위해 DNS 쿼리 질의명(Subdomain) 또는 TXT 레코드에 데이터를 인코딩하여 외부 C2 서버와 통신합니다.

### 3.1 DNS 터널링 트래픽의 특징
1. **서브도메인 길이 비정상 증가**: 일반적인 도메인보다 매우 긴 레이블 (예: `aW5maWx0cmF0aW9u.c2VjcmV0.attacker.com`).
2. **높은 섀넌 엔트로피(Entropy)**: Base64/Base32/Hex 인코딩된 난수성 문자열.
3. **희귀 DNS 레코드 질의 급증**: TXT, NULL, CNAME 질의 다수 발생.

### 3.2 Python Scapy 기반 DNS 엔트로피 및 터널링 탐지기

```python
#!/usr/bin/env python3
"""DNS 터널링 및 비정상 엔트로피 탐지 스크립트."""
from __future__ import annotations
import math
import collections
from scapy.all import rdpcap, DNSQR

def shannon_entropy(data: str) -> float:
    """문자열의 섀넌 엔트로피 계산 (비트/문자)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = collections.Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def analyze_dns_tunneling(pcap_path: str, entropy_threshold: float = 3.8, len_threshold: int = 35) -> None:
    packets = rdpcap(pcap_path)
    suspects = []
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            labels = qname.split(".")
            if len(labels) >= 2:
                subdomain = labels[0]
                ent = shannon_entropy(subdomain)
                if len(subdomain) > len_threshold and ent > entropy_threshold:
                    suspects.append((qname, len(subdomain), round(ent, 2)))
    
    print(f"[*] 분석 완료: 의심 도메인 {len(suspects)}건 발견")
    for q, l, e in suspects[:10]:
        print(f"  [!] 의심 쿼리: {q} (길이: {l}, 엔트로피: {e})")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_dns_tunneling(sys.argv[1])
    else:
        print("사용법: python3 analyze_dns.py <target.pcap>")
```

---

## 4. SSL/TLS 핸드셰이크 해부 및 복호화 실무

### 4.1 TLS 1.2 vs TLS 1.3 핸드셰이크 비교

```
TLS 1.2 Handshake (2-RTT)                 TLS 1.3 Handshake (1-RTT)
Client                 Server             Client                 Server
  │                      │                  │                      │
  │─── ClientHello ─────>│                  │── ClientHello+KeyShare─>│
  │                      │                  │                      │
  │<── ServerHello ──────│                  │<─ ServerHello+KeyShare ─│
  │<── Certificate ──────│                  │<─ {EncryptedExtensions}─│
  │<── ServerKeyExchange │                  │<─ {Certificate} ────────│
  │<── ServerHelloDone ──│                  │<─ {CertVerify} ─────────│
  │                      │                  │<─ {Finished} ───────────│
  │─── ClientKeyExchange>│                  │                      │
  │─── [ChangeCipher] ──>│                  │─── {Finished} ───────>│
  │─── Finished ────────>│                  │                      │
  │                      │                  │<── [ApplicationData] ──>│
  │<── [ApplicationData]─│
```

### 4.2 Wireshark SSLKEYLOGFILE 연동 복호화
1. 브라우저 또는 클라이언트 환경 변수 설정:
   ```bash
   export SSLKEYLOGFILE=/tmp/tls_keylog.log
   curl -k https://target-internal.corp/admin
   ```
2. Wireshark 설정:
   - `Preferences` -> `Protocols` -> `TLS` -> `(Pre)-Master-Secret log filename` -> `/tmp/tls_keylog.log` 지정.
   - HTTPS 패킷이 즉시 HTTP 프로토콜로 디코딩되어 URI, Header, POST 데이터가 평문으로 표시됨.

---

## 5. 네트워크 패킷 카빙 (Packet Carving)

캡처된 PCAP 내부의 TCP 스트림을 재조합하여 전송된 파일(PE 실행파일, PDF, 이미지 등)을 복원하는 기법입니다.

### 5.1 Scapy 기반 TCP 스트림 파일 추출기

```python
#!/usr/bin/env python3
"""PCAP TCP 스트림에서 HTTP 전송 파일 Carving."""
from __future__ import annotations
import os
from scapy.all import rdpcap, TCP, Raw

def carve_http_files(pcap_path: str, output_dir: str = "carved_files") -> None:
    os.makedirs(output_dir, exist_ok=True)
    packets = rdpcap(pcap_path)
    streams: dict[str, bytearray] = collections.defaultdict(bytearray)

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            ip = pkt["IP"]
            tcp = pkt[TCP]
            flow_id = f"{ip.src}_{tcp.sport}_to_{ip.dst}_{tcp.dport}"
            streams[flow_id].extend(pkt[Raw].load)

    file_idx = 1
    for flow_id, payload in streams.items():
        # HTTP 응답 분리 (200 OK)
        if b"HTTP/1." in payload and b"\r\n\r\n" in payload:
            header, body = payload.split(b"\r\n\r\n", 1)
            # 매직 바이트 검사 (PE: MZ, PDF: %PDF, PNG: \x89PNG)
            ext = ".bin"
            if body.startswith(b"MZ"):
                ext = ".exe"
            elif body.startswith(b"%PDF"):
                ext = ".pdf"
            elif body.startswith(b"\x89PNG"):
                ext = ".png"
            
            if ext != ".bin":
                out_path = os.path.join(output_dir, f"extracted_{file_idx}{ext}")
                with open(out_path, "wb") as f:
                    f.write(body)
                print(f"[+] 파일 복원 성공: {out_path} ({len(body)} bytes, Stream: {flow_id})")
                file_idx += 1

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        carve_http_files(sys.argv[1])
    else:
        print("사용법: python3 carve_pcap.py <traffic.pcap>")
```

---

<a name="english"></a>

# Practical Packet Analysis Deep Dive — Protocol Dissection & Network Forensics

## 0. Conceptual Foundation

### What is Practical Packet Analysis?

Practical Packet Analysis is the discipline of capturing and dissecting raw network byte streams according to RFC specifications. It goes far beyond superficial inspection, scrutinizing TCP window scaling, retransmission metrics, state machine transitions, and cryptographic key associations to detect advanced adversary tradecraft, exfiltration channels, and lateral movement.

```
Core Packet Analysis Pipeline:

  [Capture Phase]  ───> [Dissection Phase] ───> [Reassembly Phase] ───> [Threat Hunting]
    tcpdump / tshark       Ethernet/IP/TCP         TCP Stream Following     C2 Beaconing, Exfil,
                           Headers Decoded         HTTP/TLS Payload Carve   Credential Extraction
```

---

## 1. Deep Dive: TCP Protocol & Session Anomalies

### 1.1 TCP Three-Way Handshake & State Dynamics

A TCP connection relies on synchronized Sequence and Acknowledgment numbers:
- **SYN**: Client announces Initial Sequence Number (ISN), Window size, and Options (MSS, WS, SACK).
- **SYN-ACK**: Server acknowledges client ISN ($Ack = X+1$) and supplies its own ($Seq = Y$).
- **ACK**: Client acknowledges server ISN ($Ack = Y+1$). Session enters `ESTABLISHED`.

### 1.2 TCP Fault Signatures & Wireshark Filter Matrix

| Anomaly Indicator | Root Cause / Malicious Attribution | Wireshark Display Filter |
|-------------------|------------------------------------|--------------------------|
| `TCP Retransmission` | Buffer exhaustion, packet loss, or network DoS | `tcp.analysis.retransmission` |
| `Fast Retransmission` | 3 duplicate ACKs indicating selective drop | `tcp.analysis.fast_retransmission` |
| `Out-of-Order` | Asymmetric routing or malicious packet injection | `tcp.analysis.out_of_order` |
| `ZeroWindow` | Target stack buffer starvation or slow-read attack | `tcp.analysis.zero_window` |
| `RST Injection` | Blind reset injection or deep-packet firewall drop | `tcp.flags.reset == 1` |

---

## 2. ARP Poisoning & Man-In-The-Middle (MITM) Forensics

In an ARP spoofing attack, an adversary broadcasts forged Gratuitous ARP packets to rewrite the victim's and gateway's ARP tables with the attacker's MAC address.

### Detection via Wireshark
- **Duplicate IP assignment detection**:
  ```wireshark
  arp.duplicate-address-frame or arp.duplicate-address-detected
  ```
- **Unsolicited ARP replies**:
  ```wireshark
  arp.opcode == 2 and not arp.dst.proto_ipv4
  ```

---

## 3. DNS Tunneling & Covert C2 Channel Hunting

Adversaries encode structured telemetry or command output into DNS query labels (subdomains) or retrieve staged payloads via TXT / NULL record answers.

### Key Behavioral Attributes:
1. **Subdomain Length Anomaly**: Queries exceeding 35-50 characters.
2. **Elevated Shannon Entropy**: Randomness indicator exceeding 3.8 bits/char.
3. **High Query Volume & Distinct Hostnames**: Algorithmic Domain Generation (DGA) or incremental tunneling sequences.

---

## 4. TLS Session Decryption Architecture

### Decryption with SSLKEYLOGFILE
Setting `SSLKEYLOGFILE=/path/to/keys.log` instructs TLS client libraries (NSS, OpenSSL, BoringSSL) to write the Client Random and Pre-Master Secret pairs to disk.
In Wireshark:
1. Navigate to **Edit -> Preferences -> Protocols -> TLS**.
2. Assign **(Pre)-Master-Secret log filename** to the key log file.
3. Wireshark automatically derives symmetric session keys ($K_{enc}, K_{mac}$) and renders HTTP/2 / HTTP/1.1 traffic in cleartext.

---

## 5. Automated Packet Carving Engine

By reconstituting reassembled TCP payload sequences, security analysts can carve transmitted binaries, maldocs, and exfiltrated archives directly from `.pcap` files using magic bytes (`MZ`, `%PDF`, `\x89PNG`, `PK\x03\x04`).
