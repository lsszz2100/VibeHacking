> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# IoT 보안 강화 — 펌웨어 서명·네트워크 격리·디바이스 감사

## 0. 초보자를 위한 개념 이해

### IoT 보안 강화란?

IoT 보안 강화(Hardening)는 기기 공격 면을 최소화하여 침해 가능성을 줄이는 체계적인 과정이다. 단순히 보안 패치를 적용하는 것을 넘어, 펌웨어 무결성 검증, 네트워크 분리, 최소 권한 원칙 적용, 기본 설정 변경 등을 포함한다.

**왜 배우는가:**
```
IoT 보안 강화의 효과

강화 전:
  기기  →  인터넷 직접 노출
  기기  →  기본 자격증명
  기기  →  모든 포트 개방
  기기  →  서명 없는 펌웨어 업데이트

강화 후:
  기기  →  VLAN 분리 (다른 기기 침해 방지)
  기기  →  강한 자격증명 + MFA
  기기  →  필요 포트만 개방
  기기  →  서명 검증 후에만 업데이트
```

### 핵심 개념 정리

```
IoT 보안 강화 4대 영역

1. 펌웨어 보안
   - 보안 부팅(Secure Boot): 서명된 펌웨어만 실행
   - 암호화 업데이트: TLS + 코드 서명 검증
   - 디버그 인터페이스 비활성화: UART/JTAG 잠금

2. 네트워크 보안
   - VLAN 분리: IoT 전용 네트워크 세그먼트
   - 방화벽: 필요한 포트/IP만 허용
   - 암호화: TLS 1.2+, MQTT over TLS

3. 인증/접근 제어
   - 기본 자격증명 즉시 변경
   - 인증서 기반 인증
   - 최소 권한 원칙

4. 모니터링
   - 디바이스 인벤토리 유지
   - 이상 트래픽 탐지
   - 정기 취약점 스캔
```

### 필요한 도구 및 환경
- **nmap**: 기기 노출 포트 점검
- **OpenWRT**: 공유기 보안 강화 펌웨어
- **Wireshark**: 기기 트래픽 분석

### 기초 실습 예제
```bash
# 1. 네트워크의 IoT 기기 인벤토리 작성
nmap -T4 -sn 192.168.1.0/24      # 기기 목록
nmap -T4 -sV 192.168.1.100       # 특정 기기 서비스 확인

# 2. 불필요한 서비스 확인
nmap -p 23,80,8080,8443,1883 192.168.1.100
# 텔넷(23)이 열려있으면 즉시 비활성화 필요

# 3. 기본 자격증명 변경 여부 점검 스크립트
python3 - <<'EOF'
import socket
DEVICE_IP = "192.168.1.100"
TELNET_PORT = 23
try:
    s = socket.create_connection((DEVICE_IP, TELNET_PORT), timeout=2)
    print(f"[경고] {DEVICE_IP}:23 텔넷 포트 열림 — 즉시 비활성화 필요!")
    s.close()
except:
    print(f"[양호] {DEVICE_IP}:23 텔넷 닫혀있음")
EOF
```

---

## 1. IoT 보안 취약점 구조

```
IoT 디바이스 공격 표면
    │
    ├── 펌웨어
    │     - 하드코딩된 자격증명
    │     - 서명 없는 업데이트
    │     - 디버그 인터페이스 활성화 (UART/JTAG)
    │
    ├── 네트워크
    │     - 평문 프로토콜 (Telnet, HTTP, MQTT)
    │     - UPnP 자동 노출
    │     - 기본 포트 오픈
    │
    ├── 클라우드 API
    │     - 약한 인증 (API 키 하드코딩)
    │     - IDOR — 디바이스 ID 예측 가능
    │
    └── 모바일 앱
          - 로컬 저장된 자격증명
          - 인증서 고정 미적용
```

---

## 2. IoT 위협 환경 개요 — 초보자를 위한 설명

### IoT란 무엇인가?

IoT(Internet of Things)는 인터넷에 연결된 모든 "스마트" 기기를 말한다. 스마트 TV, 가정용 공유기, IP 카메라, 스마트 전구, 산업용 센서, 의료 기기까지 포함된다.

**비유:** IoT 기기는 잠금장치 없는 집의 창문과 같다. 편의를 위해 열려 있지만, 누군가가 침입할 수 있다. 보안 강화란 창문에 자물쇠를 다는 것이다.

### IoT 기기가 특히 취약한 이유

```
전통적인 PC 보안:
  - 강력한 CPU → 암호화 오버헤드 처리 가능
  - 정기적인 OS 업데이트 가능
  - 보안 소프트웨어 설치 가능
  - 사용자가 보안 경고에 반응

IoT 기기 제약:
  - 낮은 성능 CPU (8~32비트 마이크로컨트롤러)
  - 업데이트 메커니즘 없거나 불편
  - OS 없거나 경량 RTOS
  - 설치 후 방치 (set-and-forget)
  - 배터리 제약 → 암호화 전력 소모 최소화
```

### 실제 IoT 침해 사례

| 사건 | 연도 | 영향 | 원인 |
|------|------|------|------|
| Mirai 봇넷 | 2016 | 1Tbps DDoS | 기본 자격증명 |
| Ring 카메라 해킹 | 2019 | 가정 감시 | 재사용 패스워드 |
| Tesla 원격 제어 | 2020 | 자동차 제어 | API 취약점 |
| 의료 기기 해킹 | 2021 | 인슐린 펌프 조작 | 무선 프로토콜 취약점 |
| 스마트 빌딩 HVAC | 2023 | 에너지 인프라 접근 | 기본 인증정보 |

---

## 3. OWASP IoT Top 10 방어 체크리스트

OWASP(Open Web Application Security Project)는 IoT 기기의 가장 위험한 10가지 취약점을 정의했다.

```
OWASP IoT Top 10 (2018, 현재도 유효)

I1  ─ 취약한 추측 가능한 기본 패스워드
       방어: 첫 부팅 시 강제 변경, 디바이스별 고유 기본값

I2  ─ 안전하지 않은 네트워크 서비스
       방어: 불필요한 포트 닫기, TLS 강제, 방화벽 설정

I3  ─ 안전하지 않은 생태계 인터페이스
       방어: API 인증 강화, HTTPS 전용, 입력값 검증

I4  ─ 안전한 업데이트 메커니즘 부재
       방어: 서명된 펌웨어, 무결성 검증, 롤백 방지

I5  ─ 오래되거나 안전하지 않은 컴포넌트
       방어: SBOM 관리, 정기 패치, EOL 컴포넌트 교체

I6  ─ 프라이버시 보호 부족
       방어: 데이터 최소화, 암호화 저장, 전송 암호화

I7  ─ 안전하지 않은 데이터 전송 및 저장
       방어: TLS 1.2+, AES-256 저장, 민감 데이터 최소화

I8  ─ 디바이스 관리 부재
       방어: 원격 관리 프로토콜 보안, 자산 인벤토리 관리

I9  ─ 안전하지 않은 기본 설정
       방어: 보안 기본값, 불필요한 서비스 비활성화

I10 ─ 물리적 강화 부족
       방어: JTAG/UART 비활성화, 하드웨어 퓨즈, 탬퍼 감지
```

### OWASP IoT 방어 체크리스트 (실행 가능한 항목)

```
[ ] 기본 자격증명 변경 강제
    - 첫 부팅 시 새 패스워드 설정 없이 기능 잠금
    - 디바이스별 고유 기본 패스워드 사용 (시리얼 번호 기반)

[ ] 불필요한 서비스 비활성화
    - Telnet 완전 제거 (SSH 대체)
    - FTP 제거 (SFTP 또는 HTTPS 대체)
    - UPnP 비활성화 (자동 포트 개방 차단)
    - SNMP v1/v2 비활성화 (SNMPv3 사용)

[ ] 펌웨어 서명 및 업데이트 보안
    - RSA-2048 또는 ECDSA P-256으로 펌웨어 서명
    - 업데이트 전 서명 검증
    - 다운그레이드 공격 방지 (버전 카운터)

[ ] 네트워크 격리
    - IoT 전용 VLAN 생성
    - 인터넷 직접 접근 차단 (프록시 경유)
    - 디바이스 간 통신 최소화

[ ] 암호화 통신
    - MQTT → MQTT over TLS (포트 8883)
    - HTTP → HTTPS (TLS 1.2 이상)
    - CoAP → DTLS (CoAPS)

[ ] 로깅 및 모니터링
    - 인증 실패 로그
    - 비정상 트래픽 패턴 탐지
    - 정기적인 보안 감사
```

---

## 4. 펌웨어 보안 모범 사례

### 펌웨어란?

펌웨어는 IoT 기기에 내장된 소프트웨어다. 전구를 제어하는 코드, 온도 센서를 읽는 코드 등이 펌웨어에 해당한다.

**비유:** 펌웨어는 기기의 "뇌"다. 이 뇌가 해킹당하면 기기 전체가 공격자의 통제하에 들어간다.

### 시큐어 부트 체인 설명

```
시큐어 부트 (Secure Boot) 흐름도

전원 켜기
    │
    ▼
ROM 부트로더 (변경 불가, 제조사 서명)
    │
    │ 1단계: 1차 부트로더 서명 검증
    ▼
1차 부트로더 (플래시 메모리)
    │
    │ 2단계: 2차 부트로더 서명 검증
    ▼
2차 부트로더 (U-Boot 등)
    │
    │ 3단계: 커널 서명 검증
    ▼
Linux 커널 / RTOS
    │
    │ 4단계: 루트 파일시스템 무결성 검증 (dm-verity)
    ▼
애플리케이션 실행

각 단계에서:
  - 이전 단계가 서명 검증에 실패하면 부팅 중단
  - 공격자가 펌웨어를 수정해도 서명 없으면 실행 불가
  - 하드웨어 보안 키(OTP 퓨즈)에 루트 공개키 저장
```

### 시큐어 부트 구현 예시 (U-Boot)

```bash
# U-Boot 시큐어 부트 설정 예시

# 1. 키 쌍 생성
openssl genrsa -out dev.key 2048
openssl req -batch -new -x509 -key dev.key -out dev.crt

# 2. 펌웨어 이미지 서명
mkimage -f kernel.its -k keys/ -K u-boot.dtb -r kernel.itb

# 3. U-Boot 설정 (Kconfig)
CONFIG_FIT=y
CONFIG_FIT_SIGNATURE=y
CONFIG_RSA=y
CONFIG_OF_CONTROL=y
CONFIG_DEFAULT_DEVICE_TREE="my-board"

# 4. OTP 퓨즈 설정 (실제 하드웨어에서)
# 주의: 한번 퓨즈를 태우면 되돌릴 수 없음!
fuse prog 0 3 0x02000000  # HAB 보안 설정

# 5. dm-verity로 루트파일시스템 무결성
veritysetup format /dev/mmcblk0p2 /dev/mmcblk0p3 > verity_info.txt
# 루트 해시를 U-Boot 환경에 저장
```

### 하드코딩 자격증명 방지

```
나쁜 예 (하드코딩):
  password = "admin123"
  api_key = "AIzaSyB..."

좋은 예 (보안 저장소):
  1. 하드웨어 보안 모듈 (HSM/TPM)
     - STM32의 TrustZone
     - Raspberry Pi의 TPM 칩
     - AWS IoT의 X.509 인증서

  2. 환경 변수 + 암호화
     - /etc/device.conf 파일을 AES로 암호화
     - 부팅 시 하드웨어 키로 복호화

  3. 인증서 기반 인증 (패스워드 대체)
     - 각 기기에 고유 X.509 인증서 발급
     - 패스워드 없이 인증서로 서버 인증
```

---

## 5. IoT 네트워크 격리 — VLAN 설정

### VLAN이란?

VLAN(Virtual LAN)은 물리적으로 같은 네트워크에 있어도 논리적으로 분리된 네트워크처럼 만드는 기술이다.

**비유:** 같은 사무실 건물에서 영업팀과 개발팀이 각자의 방에서 일하는 것과 같다. 물리적으로 같은 건물이지만 서로 다른 공간으로 격리되어 있다.

```
가정/사무실 IoT VLAN 구성 예시

인터넷
    │
    ▼
라우터/방화벽
    │
    ├── VLAN 10: 업무 PC (192.168.10.0/24)
    │     - 파일 서버, 프린터 접근 허용
    │     - IoT 기기 접근 차단
    │
    ├── VLAN 20: IoT 기기 (192.168.20.0/24)
    │     - 스마트 전구, 카메라, 센서
    │     - 인터넷 → 특정 클라우드 서버만 허용
    │     - 업무 VLAN 접근 완전 차단
    │
    └── VLAN 30: 게스트 Wi-Fi (192.168.30.0/24)
          - 인터넷만 허용
          - 다른 VLAN 완전 차단
```

### 리눅스 iptables로 IoT VLAN 방화벽 설정

```bash
#!/bin/bash
# IoT VLAN 방화벽 규칙 설정

# 변수 정의
IOT_VLAN="eth0.20"
MGMT_VLAN="eth0.10"
WAN="eth0"

# 기본 정책: 모두 차단
iptables -P FORWARD DROP

# IoT → 인터넷: 허용 (HTTPS만)
iptables -A FORWARD -i $IOT_VLAN -o $WAN -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -i $IOT_VLAN -o $WAN -p tcp --dport 8883 -j ACCEPT  # MQTT-TLS

# IoT → 업무 네트워크: 완전 차단
iptables -A FORWARD -i $IOT_VLAN -o $MGMT_VLAN -j DROP

# 업무 → IoT: 관리 트래픽만 허용 (SSH)
iptables -A FORWARD -i $MGMT_VLAN -o $IOT_VLAN -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -i $MGMT_VLAN -o $IOT_VLAN -j DROP

# 상태 추적 (기존 연결 유지)
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 로깅: 차단된 패킷 기록
iptables -A FORWARD -j LOG --log-prefix "IoT-BLOCKED: "
```

---

## 6. 인증서 기반 IoT 기기 인증

### X.509 인증서란?

인증서는 "내가 진짜 이 기기입니다"를 증명하는 디지털 신분증이다.

```
인증서 기반 IoT 인증 흐름

제조 단계:
  1. 제조사 CA(인증기관) 생성
  2. 각 기기에 고유 키 쌍 생성
  3. 기기 인증서에 CA 서명
  4. 개인키를 보안 저장소(TPM)에 저장

운영 단계:
  기기 → 서버: "연결하겠습니다. 제 인증서입니다."
  서버: CA 서명 검증 → 인증서 유효 → 연결 허용
  
  패스워드 없이도 기기 신원 확인 가능!
```

### Python으로 IoT PKI 구현

```python
#!/usr/bin/env python3
"""IoT PKI — 디바이스 인증서 발급 및 검증."""

import argparse
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def create_ca(ca_dir: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """IoT 루트 CA 생성."""
    ca_dir.mkdir(parents=True, exist_ok=True)

    # ECDSA P-256 키 (IoT에 적합 — RSA보다 경량)
    ca_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT Device CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "IoT Root CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 저장
    (ca_dir / "ca.key").write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (ca_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] CA 생성 완료: {ca_dir}/ca.key, {ca_dir}/ca.crt")
    return ca_key, ca_cert


def issue_device_cert(
    device_id: str,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    out_dir: Path,
) -> None:
    """개별 IoT 기기 인증서 발급."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # 기기 키 생성
    dev_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"device-{device_id}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT Devices"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, device_id),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(dev_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(f"device-{device_id}.iot.local")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 기기 파일 저장
    prefix = out_dir / f"device_{device_id}"
    prefix.with_suffix(".key").write_bytes(
        dev_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    prefix.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] 기기 {device_id} 인증서 발급: {prefix}.key/.crt")


def verify_device_cert(cert_path: Path, ca_cert_path: Path) -> bool:
    """기기 인증서 유효성 검증."""
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
        print(f"[-] 인증서 만료됨")
        return False

    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ECDSA(hashes.SHA256()),
        )
        print(f"[+] 인증서 검증 성공: {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        return True
    except Exception as e:
        print(f"[-] 인증서 검증 실패: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT PKI 관리")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ca_p = sub.add_parser("create-ca", help="루트 CA 생성")
    ca_p.add_argument("--dir", type=Path, default=Path("./pki"))

    issue_p = sub.add_parser("issue", help="기기 인증서 발급")
    issue_p.add_argument("device_id", help="기기 고유 ID (예: SN-001)")
    issue_p.add_argument("--ca-dir", type=Path, default=Path("./pki"))
    issue_p.add_argument("--out", type=Path, default=Path("./certs"))

    verify_p = sub.add_parser("verify", help="인증서 검증")
    verify_p.add_argument("cert", type=Path)
    verify_p.add_argument("--ca", type=Path, default=Path("./pki/ca.crt"))

    args = parser.parse_args()

    match args.cmd:
        case "create-ca":
            create_ca(args.dir)
        case "issue":
            ca_key_path = args.ca_dir / "ca.key"
            ca_crt_path = args.ca_dir / "ca.crt"
            if not ca_key_path.exists():
                print("[-] CA가 없습니다. 먼저 create-ca 실행")
                return
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            ca_key = load_pem_private_key(ca_key_path.read_bytes(), password=None)
            ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())
            issue_device_cert(args.device_id, ca_key, ca_cert, args.out)
        case "verify":
            verify_device_cert(args.cert, args.ca)


if __name__ == "__main__":
    main()
```

---

## 7. IoT 디바이스 자동 감사 CLI

```python
#!/usr/bin/env python3
"""IoT 디바이스 보안 감사 — 네트워크 노출·서비스·자격증명 탐지."""

import argparse
import asyncio
import json
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import httpx


IOT_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("root", "root"), ("root", ""), ("root", "toor"),
    ("user", "user"), ("guest", "guest"),
    ("admin", "1234"), ("admin", "123456"),
    ("support", "support"), ("Administrator", "admin"),
]

IOT_COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP",
    443: "HTTPS", 554: "RTSP", 1883: "MQTT",
    5683: "CoAP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8883: "MQTT-TLS", 9000: "API", 49152: "UPnP",
}


@dataclass
class DeviceAuditResult:
    ip: str
    open_ports: list[dict] = field(default_factory=list)
    default_creds: list[dict] = field(default_factory=list)
    http_issues: list[str] = field(default_factory=list)
    telnet_open: bool = False
    mqtt_open: bool = False
    risk_score: int = 0


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_iot_ports(ip: str) -> list[dict]:
    open_ports = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(scan_port, ip, port): (port, svc)
            for port, svc in IOT_COMMON_PORTS.items()
        }
        for future in as_completed(futures):
            port, svc = futures[future]
            if future.result():
                open_ports.append({"port": port, "service": svc})
    return sorted(open_ports, key=lambda x: x["port"])


def test_default_credentials(ip: str, port: int = 80) -> list[dict]:
    """HTTP Basic Auth / Form 기반 기본 자격증명 테스트."""
    found = []
    endpoints = ["/", "/admin", "/login", "/cgi-bin/login.cgi"]

    with httpx.Client(verify=False, timeout=5) as client:
        for user, passwd in IOT_DEFAULT_CREDS[:8]:
            for endpoint in endpoints:
                try:
                    resp = client.get(
                        f"http://{ip}:{port}{endpoint}",
                        auth=(user, passwd),
                    )
                    if resp.status_code == 200 and "login" not in resp.url.path.lower():
                        found.append({
                            "username": user, "password": passwd,
                            "endpoint": endpoint, "status": resp.status_code,
                        })
                        break
                except httpx.RequestError:
                    pass

    return found


def check_http_security(ip: str, port: int = 80) -> list[str]:
    """HTTP 보안 헤더 및 설정 점검."""
    issues = []
    try:
        with httpx.Client(verify=False, timeout=5) as client:
            resp = client.get(f"http://{ip}:{port}/")
            headers = resp.headers

            required_headers = [
                ("X-Frame-Options", "클릭재킹 방어 헤더 없음"),
                ("X-Content-Type-Options", "MIME 스니핑 방어 헤더 없음"),
                ("Content-Security-Policy", "CSP 헤더 없음"),
            ]
            for header, issue in required_headers:
                if header.lower() not in {k.lower() for k in headers}:
                    issues.append(issue)

            server = headers.get("server", "")
            if server:
                issues.append(f"서버 정보 노출: {server}")

            if resp.url.scheme == "http":
                issues.append("HTTPS 미적용 (평문 전송)")
    except httpx.RequestError:
        pass

    return issues


def check_mqtt_security(ip: str, port: int = 1883) -> list[str]:
    """MQTT 브로커 보안 점검 — 익명 접속 가능 여부."""
    issues = []
    try:
        # MQTT CONNECT 패킷 (익명)
        protocol = b"MQTT"
        connect_flags = 0x02  # Clean session
        keepalive = 60

        payload = (
            b"\x00\x10"  # Protocol name length
            + protocol
            + b"\x04"    # Protocol level (MQTT 3.1.1)
            + bytes([connect_flags])
            + struct.pack(">H", keepalive)
            + b"\x00\x08anonymous"  # Client ID
        )
        fixed_header = bytes([0x10, len(payload)])
        packet = fixed_header + payload

        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.sendall(packet)
            response = sock.recv(4)
            # CONNACK: 0x20 0x02 0x00 0x00 (성공)
            if len(response) >= 4 and response[0] == 0x20 and response[3] == 0x00:
                issues.append("MQTT 익명 접속 허용 — 인증 없음")
    except OSError:
        pass

    return issues


def audit_device(ip: str) -> DeviceAuditResult:
    result = DeviceAuditResult(ip=ip)
    result.open_ports = scan_iot_ports(ip)

    open_port_nums = {p["port"] for p in result.open_ports}

    # Telnet 오픈 여부
    if 23 in open_port_nums:
        result.telnet_open = True
        result.risk_score += 30

    # MQTT 보안
    if 1883 in open_port_nums:
        result.mqtt_open = True
        result.risk_score += 15

    # HTTP 감사
    for port in [80, 8080]:
        if port in open_port_nums:
            result.http_issues = check_http_security(ip, port)
            result.risk_score += len(result.http_issues) * 5

            creds = test_default_credentials(ip, port)
            result.default_creds.extend(creds)
            result.risk_score += len(creds) * 40
            break

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT 디바이스 보안 감사")
    sub = parser.add_subparsers(dest="cmd", required=True)

    audit_p = sub.add_parser("audit", help="단일 디바이스 감사")
    audit_p.add_argument("ip")
    audit_p.add_argument("-o", "--output", type=Path)

    scan_p = sub.add_parser("scan", help="서브넷 IoT 스캔")
    scan_p.add_argument("targets", help="IP 목록 파일")
    scan_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "audit":
            result = audit_device(args.ip)
            print(f"\n=== IoT 감사: {args.ip} ===")
            print(f"오픈 포트: {[p['port'] for p in result.open_ports]}")
            if result.telnet_open:
                print("[!!] Telnet 오픈 — 즉각 비활성화 필요")
            if result.default_creds:
                print(f"[!!] 기본 자격증명 사용: {result.default_creds}")
            if result.http_issues:
                print(f"[!] HTTP 보안 이슈: {result.http_issues}")
            print(f"위험 점수: {result.risk_score}/100")
            if args.output:
                args.output.write_text(json.dumps(vars(result), indent=2, ensure_ascii=False))

        case "scan":
            ips = Path(args.targets).read_text().splitlines()
            ips = [ip.strip() for ip in ips if ip.strip()]
            results = []
            for ip in ips:
                r = audit_device(ip)
                results.append(vars(r))
                print(f"{ip}: 점수={r.risk_score}, 포트={len(r.open_ports)}개")
            if args.output:
                args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 8. IoT 펌웨어 무결성 검증

```python
#!/usr/bin/env python3
"""IoT 펌웨어 보안 점검 — 서명 검증·하드코딩 자격증명·취약 설정 탐지."""

import argparse
import hashlib
import re
import subprocess
from pathlib import Path


CREDENTIAL_PATTERNS = [
    (r'password\s*=\s*["\']([^"\']{4,})["\']', "하드코딩 패스워드"),
    (r'passwd\s*=\s*["\']([^"\']{4,})["\']', "하드코딩 passwd"),
    (r'api[_-]?key\s*=\s*["\']([A-Za-z0-9+/]{16,})["\']', "하드코딩 API 키"),
    (r'secret\s*=\s*["\']([^"\']{8,})["\']', "하드코딩 시크릿"),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "하드코딩 개인키"),
    (r'admin:(\$[1-6]\$[^\s:]+)', "하드코딩 패스워드 해시"),
]

DANGEROUS_FUNCTIONS = [
    "system(", "popen(", "exec(", "execve(",
    "strcpy(", "strcat(", "sprintf(", "gets(",
    "scanf(", "vsprintf(", "mktemp(",
]


def extract_firmware(firmware_path: Path, out_dir: Path) -> bool:
    """binwalk으로 펌웨어 추출."""
    try:
        result = subprocess.run(
            ["binwalk", "-e", "--directory", str(out_dir), str(firmware_path)],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("binwalk 설치 필요: sudo apt install binwalk")
        return False
    except subprocess.TimeoutExpired:
        print("추출 타임아웃")
        return False


def scan_for_credentials(search_dir: Path) -> list[dict]:
    """추출된 펌웨어에서 하드코딩 자격증명 탐지."""
    findings = []

    for filepath in search_dir.rglob("*"):
        if not filepath.is_file():
            continue
        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            continue

        for pattern, desc in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "file": str(filepath.relative_to(search_dir)),
                    "type": desc,
                    "matches": matches[:3],
                })

    return findings


def scan_dangerous_functions(search_dir: Path) -> list[dict]:
    """C 소스/바이너리에서 위험 함수 탐지."""
    findings = []

    for filepath in search_dir.rglob("*"):
        if not filepath.is_file() or filepath.suffix not in (".c", ".cpp", ".h", ""):
            continue
        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            continue

        for func in DANGEROUS_FUNCTIONS:
            if func in content:
                count = content.count(func)
                findings.append({
                    "file": str(filepath.relative_to(search_dir)),
                    "function": func.rstrip("("),
                    "count": count,
                })

    return findings


def verify_firmware_signature(firmware_path: Path, pubkey_path: Path | None) -> dict:
    """펌웨어 서명 검증."""
    fw_hash = hashlib.sha256(firmware_path.read_bytes()).hexdigest()
    result = {"firmware": str(firmware_path), "sha256": fw_hash}

    if pubkey_path:
        sig_path = firmware_path.with_suffix(".sig")
        if not sig_path.exists():
            result["signed"] = False
            result["detail"] = "서명 파일 없음"
            return result
        try:
            verify = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(pubkey_path),
                 "-signature", str(sig_path), str(firmware_path)],
                capture_output=True, text=True,
            )
            result["signed"] = "Verified OK" in verify.stdout
            result["detail"] = verify.stdout.strip()
        except FileNotFoundError:
            result["signed"] = None
            result["detail"] = "openssl 없음"
    else:
        result["signed"] = None
        result["detail"] = "공개키 미제공"

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT 펌웨어 보안 점검")
    sub = parser.add_subparsers(dest="cmd", required=True)

    extract_p = sub.add_parser("extract", help="펌웨어 추출")
    extract_p.add_argument("firmware", type=Path)
    extract_p.add_argument("-o", "--output", type=Path, default=Path("./extracted"))

    creds_p = sub.add_parser("creds", help="자격증명 탐지")
    creds_p.add_argument("dir", type=Path, help="추출된 펌웨어 디렉터리")

    funcs_p = sub.add_parser("funcs", help="위험 함수 탐지")
    funcs_p.add_argument("dir", type=Path)

    verify_p = sub.add_parser("verify", help="서명 검증")
    verify_p.add_argument("firmware", type=Path)
    verify_p.add_argument("--pubkey", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "extract":
            print(f"[*] 추출: {args.firmware}")
            success = extract_firmware(args.firmware, args.output)
            print(f"[{'+'  if success else '-'}] {'성공' if success else '실패'}: {args.output}")

        case "creds":
            findings = scan_for_credentials(args.dir)
            print(f"[!] 하드코딩 자격증명 {len(findings)}개:")
            for f in findings:
                print(f"  {f['file']}: {f['type']} — {f['matches']}")

        case "funcs":
            findings = scan_dangerous_functions(args.dir)
            print(f"[!] 위험 함수 {len(findings)}개:")
            for f in findings:
                print(f"  {f['file']}: {f['function']}() × {f['count']}")

        case "verify":
            result = verify_firmware_signature(args.firmware, args.pubkey)
            print(f"SHA256: {result['sha256']}")
            print(f"서명: {result.get('signed')} — {result.get('detail')}")


if __name__ == "__main__":
    main()
```

---

## 9. IoT 모니터링 및 이상 탐지

### 왜 모니터링이 중요한가?

IoT 기기는 24시간 운영되며 공격자가 오랜 기간 은밀하게 악용할 수 있다. 모니터링은 이상 행동을 조기에 탐지하는 "경보 시스템"이다.

```python
#!/usr/bin/env python3
"""IoT 네트워크 이상 탐지 — 트래픽 기준선 vs 현재 비교."""

import argparse
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrafficBaseline:
    """정상 트래픽 기준선."""
    device_ip: str
    avg_bytes_per_min: float = 0.0
    avg_connections_per_min: float = 0.0
    known_dest_ips: set[str] = field(default_factory=set)
    known_ports: set[int] = field(default_factory=set)
    active_hours: list[int] = field(default_factory=lambda: list(range(6, 23)))


@dataclass
class AnomalyAlert:
    device_ip: str
    alert_type: str
    description: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    timestamp: float = field(default_factory=time.time)


def detect_anomalies(
    device_ip: str,
    current_traffic: dict,
    baseline: TrafficBaseline,
) -> list[AnomalyAlert]:
    """현재 트래픽을 기준선과 비교해 이상 탐지."""
    alerts: list[AnomalyAlert] = []

    # 1. 트래픽 볼륨 급증
    current_bytes = current_traffic.get("bytes_per_min", 0)
    if baseline.avg_bytes_per_min > 0:
        ratio = current_bytes / baseline.avg_bytes_per_min
        if ratio > 10:
            alerts.append(AnomalyAlert(
                device_ip=device_ip,
                alert_type="TRAFFIC_SPIKE",
                description=f"트래픽 {ratio:.1f}배 증가 — 데이터 유출 의심",
                severity="HIGH",
            ))
        elif ratio > 3:
            alerts.append(AnomalyAlert(
                device_ip=device_ip,
                alert_type="TRAFFIC_INCREASE",
                description=f"트래픽 {ratio:.1f}배 증가",
                severity="MEDIUM",
            ))

    # 2. 새로운 목적지 IP 접근
    new_dests = set(current_traffic.get("dest_ips", [])) - baseline.known_dest_ips
    for dest in new_dests:
        alerts.append(AnomalyAlert(
            device_ip=device_ip,
            alert_type="NEW_DESTINATION",
            description=f"새로운 목적지 IP: {dest} — C2 통신 가능성",
            severity="MEDIUM" if not dest.startswith("192.168.") else "LOW",
        ))

    # 3. 비정상 포트 접근
    current_ports = set(current_traffic.get("dest_ports", []))
    unusual_ports = current_ports - baseline.known_ports
    malicious_ports = {4444, 6666, 1337, 31337, 8888}  # 흔한 백도어 포트
    for port in unusual_ports:
        severity = "CRITICAL" if port in malicious_ports else "MEDIUM"
        alerts.append(AnomalyAlert(
            device_ip=device_ip,
            alert_type="UNUSUAL_PORT",
            description=f"비정상 포트 통신: {port}",
            severity=severity,
        ))

    # 4. 비활성 시간대 활동
    current_hour = time.localtime().tm_hour
    if current_hour not in baseline.active_hours:
        if current_traffic.get("connections_per_min", 0) > 5:
            alerts.append(AnomalyAlert(
                device_ip=device_ip,
                alert_type="OFF_HOURS_ACTIVITY",
                description=f"비활성 시간대({current_hour}시) 네트워크 활동",
                severity="MEDIUM",
            ))

    return alerts


def run_monitoring_demo() -> None:
    """모니터링 데모 — 가상 시나리오."""
    # 정상 기준선
    baseline = TrafficBaseline(
        device_ip="192.168.20.10",
        avg_bytes_per_min=5000,
        avg_connections_per_min=3,
        known_dest_ips={"192.168.1.1", "8.8.8.8", "mqtt-broker.local"},
        known_ports={80, 443, 8883},
        active_hours=list(range(7, 22)),
    )

    # 시나리오 1: 정상 트래픽
    normal_traffic = {
        "bytes_per_min": 4800,
        "connections_per_min": 3,
        "dest_ips": ["192.168.1.1", "mqtt-broker.local"],
        "dest_ports": [8883],
    }

    # 시나리오 2: 악성 트래픽 (데이터 유출 + C2)
    malicious_traffic = {
        "bytes_per_min": 85000,
        "connections_per_min": 20,
        "dest_ips": ["192.168.1.1", "185.220.101.45", "203.0.113.99"],
        "dest_ports": [8883, 4444, 443],
    }

    print("=== IoT 이상 탐지 데모 ===\n")

    print("[*] 시나리오 1: 정상 트래픽")
    alerts = detect_anomalies("192.168.20.10", normal_traffic, baseline)
    if alerts:
        for a in alerts:
            print(f"  [{a.severity}] {a.alert_type}: {a.description}")
    else:
        print("  [+] 이상 없음 — 정상 범위")

    print("\n[*] 시나리오 2: 악성 트래픽 (데이터 유출 + C2)")
    alerts = detect_anomalies("192.168.20.10", malicious_traffic, baseline)
    for a in alerts:
        print(f"  [{a.severity}] {a.alert_type}: {a.description}")


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT 이상 탐지")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="이상 탐지 데모")

    check_p = sub.add_parser("check", help="트래픽 검사")
    check_p.add_argument("device_ip")
    check_p.add_argument("--traffic", type=Path, help="트래픽 JSON 파일")
    check_p.add_argument("--baseline", type=Path, help="기준선 JSON 파일")

    args = parser.parse_args()

    match args.cmd:
        case "demo":
            run_monitoring_demo()
        case "check":
            if not args.traffic or not args.baseline:
                print("--traffic 및 --baseline 파일 필요")
                return
            traffic = json.loads(args.traffic.read_text())
            bl_data = json.loads(args.baseline.read_text())
            baseline = TrafficBaseline(
                device_ip=bl_data["device_ip"],
                avg_bytes_per_min=bl_data.get("avg_bytes_per_min", 0),
                avg_connections_per_min=bl_data.get("avg_connections_per_min", 0),
                known_dest_ips=set(bl_data.get("known_dest_ips", [])),
                known_ports=set(bl_data.get("known_ports", [])),
            )
            alerts = detect_anomalies(args.device_ip, traffic, baseline)
            for a in alerts:
                print(f"[{a.severity}] {a.alert_type}: {a.description}")
            if not alerts:
                print("[+] 이상 탐지 없음")


if __name__ == "__main__":
    main()
```

---

## 10. IoT 보안 강화 대책

| 취약점 | 강화 방법 | 도구/표준 |
|--------|-----------|-----------|
| 기본 자격증명 | 최초 부팅 시 변경 강제 | OWASP IoT Top 10 |
| 서명 없는 업데이트 | RSA/EC 기반 펌웨어 서명 | U-Boot verified boot |
| Telnet/평문 | SSH/TLS 전용 사용 | OpenSSH, mbedTLS |
| MQTT 익명 | 인증서 + ACL 설정 | Mosquitto TLS |
| 디버그 포트 | JTAG/UART 물리 비활성화 | 하드웨어 퓨즈 |
| 하드코딩 자격증명 | 환경 변수/HSM 사용 | SOPS, AWS IoT Core |
| 네트워크 격리 | VLAN 분리 + 방화벽 | 802.1Q, iptables |
| 인증서 없는 통신 | X.509 인증서 기반 mTLS | AWS IoT, Azure IoT Hub |
| 모니터링 부재 | 이상 탐지 시스템 구축 | ELK Stack, Grafana |

---

## 11. 단계별 IoT 보안 강화 로드맵

```
단계 1 (즉시): 기본 보안
  ├── 기본 자격증명 모두 변경
  ├── Telnet 비활성화 → SSH 사용
  ├── 불필요한 서비스/포트 닫기
  └── 펌웨어 최신 버전 업데이트

단계 2 (1주 내): 네트워크 격리
  ├── IoT 전용 VLAN 생성
  ├── 방화벽 규칙으로 트래픽 제한
  ├── UPnP 비활성화
  └── DNS 필터링 (광고/악성 도메인 차단)

단계 3 (1개월 내): 인증 강화
  ├── PKI 구축 (CA + 디바이스 인증서)
  ├── MQTT TLS 인증서 인증
  ├── API 키 → JWT/인증서 교체
  └── MFA 적용 (관리 인터페이스)

단계 4 (지속): 모니터링 및 감사
  ├── 트래픽 기준선 수집
  ├── 이상 탐지 시스템 운영
  ├── 정기 펌웨어 감사
  └── 사고 대응 계획 수립
```

---

<a name="english"></a>

# IoT Security Hardening — Firmware Signing, Network Isolation, Device Auditing

## 1. IoT Security Vulnerability Structure

```
IoT Device Attack Surface
    │
    ├── Firmware
    │     - Hardcoded credentials
    │     - Updates without signing
    │     - Debug interfaces enabled (UART/JTAG)
    │
    ├── Network
    │     - Plaintext protocols (Telnet, HTTP, MQTT)
    │     - UPnP auto-exposure
    │     - Default ports open
    │
    ├── Cloud API
    │     - Weak authentication (hardcoded API keys)
    │     - IDOR — predictable device IDs
    │
    └── Mobile App
          - Locally stored credentials
          - No certificate pinning
```

---

## 2. IoT Threat Landscape Overview — Beginner's Guide

### What Is IoT?

IoT (Internet of Things) refers to every "smart" device connected to the internet: smart TVs, home routers, IP cameras, smart bulbs, industrial sensors, and medical devices.

**Analogy:** IoT devices are like windows in a house left unlocked for convenience. Security hardening means installing locks on those windows.

### Why IoT Devices Are Especially Vulnerable

```
Traditional PC Security:
  - Powerful CPU handles encryption overhead
  - Regular OS updates available
  - Security software installable
  - Users respond to security warnings

IoT Device Constraints:
  - Low-power CPU (8-32 bit microcontrollers)
  - No or inconvenient update mechanism
  - No OS or lightweight RTOS
  - Set-and-forget deployment
  - Battery constraints minimize crypto power draw
```

### Real-World IoT Breach Examples

| Incident | Year | Impact | Root Cause |
|----------|------|--------|------------|
| Mirai Botnet | 2016 | 1 Tbps DDoS | Default credentials |
| Ring Camera Hacks | 2019 | Home surveillance | Reused passwords |
| Tesla Remote Control | 2020 | Vehicle control | API vulnerability |
| Medical Device Hacks | 2021 | Insulin pump manipulation | Wireless protocol flaws |
| Smart Building HVAC | 2023 | Energy infrastructure access | Default credentials |

---

## 3. OWASP IoT Top 10 Defense Checklist

```
OWASP IoT Top 10 (2018, still highly relevant)

I1 - Weak/Guessable/Hardcoded Passwords
     Defense: Force change on first boot, device-unique defaults

I2 - Insecure Network Services
     Defense: Close unnecessary ports, enforce TLS, configure firewall

I3 - Insecure Ecosystem Interfaces
     Defense: Strengthen API auth, HTTPS only, validate input

I4 - Lack of Secure Update Mechanism
     Defense: Signed firmware, integrity verification, anti-rollback

I5 - Use of Insecure or Outdated Components
     Defense: SBOM management, regular patching, replace EOL components

I6 - Insufficient Privacy Protection
     Defense: Data minimization, encrypted storage, transport encryption

I7 - Insecure Data Transfer and Storage
     Defense: TLS 1.2+, AES-256 at rest, minimize sensitive data

I8 - Lack of Device Management
     Defense: Secure remote management, asset inventory

I9 - Insecure Default Settings
     Defense: Secure defaults, disable unnecessary services

I10 - Lack of Physical Hardening
     Defense: Disable JTAG/UART, hardware fuses, tamper detection
```

### Actionable Defense Checklist

```
[ ] Force default credential change
    - Lock functionality until new password set on first boot
    - Use device-unique defaults (serial number based)

[ ] Disable unnecessary services
    - Remove Telnet entirely (replace with SSH)
    - Remove FTP (replace with SFTP or HTTPS)
    - Disable UPnP (blocks automatic port opening)
    - Disable SNMP v1/v2 (use SNMPv3)

[ ] Firmware signing and update security
    - Sign firmware with RSA-2048 or ECDSA P-256
    - Verify signature before applying update
    - Prevent downgrade attacks (version counter)

[ ] Network isolation
    - Create dedicated IoT VLAN
    - Block direct internet access (route through proxy)
    - Minimize device-to-device communication

[ ] Encrypted communications
    - MQTT → MQTT over TLS (port 8883)
    - HTTP → HTTPS (TLS 1.2 or higher)
    - CoAP → DTLS (CoAPS)

[ ] Logging and monitoring
    - Log authentication failures
    - Detect abnormal traffic patterns
    - Conduct regular security audits
```

---

## 4. Firmware Security Best Practices

### Secure Boot Chain Explanation

```
Secure Boot Flow Diagram

Power On
    │
    ▼
ROM Bootloader (immutable, manufacturer-signed)
    │
    │ Step 1: Verify first-stage bootloader signature
    ▼
First-Stage Bootloader (flash memory)
    │
    │ Step 2: Verify second-stage bootloader signature
    ▼
Second-Stage Bootloader (U-Boot, etc.)
    │
    │ Step 3: Verify kernel signature
    ▼
Linux Kernel / RTOS
    │
    │ Step 4: Verify root filesystem integrity (dm-verity)
    ▼
Application Execution

At each stage:
  - If the previous stage fails signature verification, boot halts
  - Even if an attacker modifies firmware, unsigned code won't run
  - Root public key stored in hardware security key (OTP fuse)
```

### Preventing Hardcoded Credentials

```
Bad Practice (hardcoded):
  password = "admin123"
  api_key = "AIzaSyB..."

Good Practice (secure storage):
  1. Hardware Security Module (HSM/TPM)
     - STM32's TrustZone
     - Raspberry Pi TPM chip
     - AWS IoT X.509 certificates

  2. Environment variables + encryption
     - AES-encrypt /etc/device.conf
     - Decrypt at boot using hardware key

  3. Certificate-based auth (replaces passwords)
     - Issue unique X.509 cert per device
     - Authenticate to server using cert, no password needed
```

---

## 5. IoT Network Isolation — VLAN Setup

### What Is a VLAN?

A VLAN (Virtual LAN) creates logically separate networks even when devices share the same physical infrastructure.

**Analogy:** Imagine different teams in the same office building working in separate rooms. Same building, but isolated spaces.

```
Home/Office IoT VLAN Configuration Example

Internet
    │
    ▼
Router/Firewall
    │
    ├── VLAN 10: Work PCs (192.168.10.0/24)
    │     - File server, printer access allowed
    │     - IoT device access blocked
    │
    ├── VLAN 20: IoT Devices (192.168.20.0/24)
    │     - Smart bulbs, cameras, sensors
    │     - Internet → only specific cloud servers allowed
    │     - Work VLAN access completely blocked
    │
    └── VLAN 30: Guest Wi-Fi (192.168.30.0/24)
          - Internet access only
          - All other VLANs completely blocked
```

---

## 6. Certificate-Based IoT Device Authentication

### X.509 Certificate Authentication Flow

```
Certificate-Based IoT Authentication

Manufacturing Phase:
  1. Create manufacturer CA (Certificate Authority)
  2. Generate unique key pair per device
  3. Sign device certificate with CA
  4. Store private key in secure storage (TPM)

Operational Phase:
  Device → Server: "I want to connect. Here is my certificate."
  Server: Verifies CA signature → Certificate valid → Connection allowed
  
  Device identity confirmed without passwords!
```

### Python IoT PKI Implementation

The PKI tool creates a root CA, issues individual device certificates, and verifies them. Key features:
- Uses ECDSA P-256 (lighter than RSA — ideal for constrained IoT devices)
- 1-year device certificate lifetime (reissue regularly)
- Certificate includes device serial number in SAN (Subject Alternative Name)

```bash
# Usage examples:
python3 iot_pki.py create-ca --dir ./pki
python3 iot_pki.py issue SN-001 --ca-dir ./pki --out ./certs
python3 iot_pki.py verify ./certs/device_SN-001.crt --ca ./pki/ca.crt
```

---

## 7. IoT Monitoring and Anomaly Detection

### Why Monitoring Matters

IoT devices run 24/7 and attackers can silently abuse them for extended periods. Monitoring acts as an "alarm system" to detect abnormal behavior early.

### Anomaly Detection Logic

The monitoring tool establishes a traffic baseline for each device and compares current traffic against it:

| Alert Type | Trigger | Severity |
|------------|---------|----------|
| TRAFFIC_SPIKE | >10x normal volume | HIGH |
| TRAFFIC_INCREASE | 3-10x normal volume | MEDIUM |
| NEW_DESTINATION | Unknown external IP | MEDIUM/HIGH |
| UNUSUAL_PORT | Known backdoor port (4444, 1337, 31337) | CRITICAL |
| OFF_HOURS_ACTIVITY | Active during sleep hours | MEDIUM |

```bash
# Run monitoring demo
python3 iot_monitor.py demo

# Check specific device traffic
python3 iot_monitor.py check 192.168.20.10 \
    --traffic current_traffic.json \
    --baseline baseline.json
```

---

## 8. Key Hardening Measures Summary

| Vulnerability | Countermeasure | Recommended Tool |
|--------------|---------------|-----------------|
| Default credentials | Force change on first boot | OWASP IoT Top 10 |
| Unsigned updates | RSA/EC firmware signing | U-Boot verified boot |
| Telnet/plaintext | SSH/TLS only | OpenSSH, mbedTLS |
| Anonymous MQTT | Certificate + ACL | Mosquitto TLS |
| Debug ports | Physically disable JTAG/UART | Hardware fuses |
| Hardcoded credentials | Use env variables/HSM | SOPS, AWS IoT Core |
| No network isolation | VLAN separation + firewall | 802.1Q, iptables |
| No certificate auth | X.509 mTLS | AWS IoT, Azure IoT Hub |
| No monitoring | Anomaly detection system | ELK Stack, Grafana |

---

## 9. Step-by-Step IoT Security Hardening Roadmap

```
Phase 1 (Immediate): Basic Security
  ├── Change all default credentials
  ├── Disable Telnet → use SSH
  ├── Close unnecessary services/ports
  └── Update firmware to latest version

Phase 2 (Within 1 week): Network Isolation
  ├── Create dedicated IoT VLAN
  ├── Restrict traffic with firewall rules
  ├── Disable UPnP
  └── DNS filtering (block ads/malicious domains)

Phase 3 (Within 1 month): Authentication Hardening
  ├── Build PKI (CA + device certificates)
  ├── MQTT TLS certificate authentication
  ├── Replace API keys with JWT/certificates
  └── Apply MFA (management interfaces)

Phase 4 (Ongoing): Monitoring and Auditing
  ├── Collect traffic baselines
  ├── Operate anomaly detection system
  ├── Regular firmware audits
  └── Develop incident response plan
```
