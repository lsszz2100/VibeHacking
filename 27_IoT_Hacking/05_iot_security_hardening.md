# IoT 보안 강화 — 펌웨어 서명·네트워크 격리·디바이스 감사

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

## 2. IoT 디바이스 자동 감사 CLI

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

## 3. IoT 펌웨어 무결성 검증

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

## 4. IoT 보안 강화 대책

| 취약점 | 강화 방법 | 도구/표준 |
|--------|-----------|-----------|
| 기본 자격증명 | 최초 부팅 시 변경 강제 | OWASP IoT Top 10 |
| 서명 없는 업데이트 | RSA/EC 기반 펌웨어 서명 | U-Boot verified boot |
| Telnet/평문 | SSH/TLS 전용 사용 | OpenSSH, mbedTLS |
| MQTT 익명 | 인증서 + ACL 설정 | Mosquitto TLS |
| 디버그 포트 | JTAG/UART 물리 비활성화 | 하드웨어 퓨즈 |
| 하드코딩 자격증명 | 환경 변수/HSM 사용 | SOPS, AWS IoT Core |
| 네트워크 격리 | VLAN 분리 + 방화벽 | 802.1Q, iptables |
