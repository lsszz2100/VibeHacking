# 하드웨어 보안 평가 — 디바이스 감사·물리 보안·탬퍼 방지

## 1. 하드웨어 보안 평가 프레임워크

```
하드웨어 보안 평가
    │
    ├── 외부 인터페이스 분석
    │     UART, JTAG, SPI, I2C, USB, PCIe
    │
    ├── 펌웨어 보안
    │     암호화 여부, 서명 검증, 디버그 모드
    │
    ├── 물리 보안
    │     탬퍼 감지, 에폭시 충진, 메시 쉴드
    │
    ├── 사이드채널 저항성
    │     전력 분석, 타이밍, 전자기
    │
    └── 암호화 구현
          HSM/TPM, 키 저장, 부팅 체인
```

---

## 2. 하드웨어 인터페이스 자동 탐지

```python
#!/usr/bin/env python3
"""하드웨어 인터페이스 탐지·분석 자동화 CLI."""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class InterfaceResult:
    interface_type: str
    port: str
    detected: bool
    baud_rate: int | None = None
    protocol: str | None = None
    notes: str = ""


def detect_uart_ports() -> list[InterfaceResult]:
    """사용 가능한 UART/시리얼 포트 탐지."""
    results = []
    uart_paths = list(Path("/dev").glob("ttyUSB*")) + \
                 list(Path("/dev").glob("ttyACM*")) + \
                 list(Path("/dev").glob("ttyS[0-9]"))

    for port in uart_paths:
        results.append(InterfaceResult(
            interface_type="UART",
            port=str(port),
            detected=True,
            notes="시리얼 포트 존재",
        ))

    return results


def probe_uart_baud(port: str, test_bauds: list[int] | None = None) -> int | None:
    """UART 자동 보레이트 탐지."""
    if test_bauds is None:
        test_bauds = [9600, 19200, 38400, 57600, 115200, 230400, 460800]

    try:
        import serial  # pyserial
    except ImportError:
        print("pyserial 설치 필요: pip install pyserial")
        return None

    for baud in test_bauds:
        try:
            with serial.Serial(port, baud, timeout=1) as ser:
                data = ser.read(64)
                # 출력 가능한 ASCII 비율이 높으면 올바른 보레이트
                printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (0x0a, 0x0d))
                if len(data) > 0 and printable / len(data) > 0.7:
                    return baud
        except Exception:
            pass

    return None


def detect_jtag_via_openocd(interface_cfg: str, target_cfg: str) -> dict:
    """OpenOCD로 JTAG 디바이스 탐지."""
    try:
        result = subprocess.run(
            [
                "openocd",
                "-f", interface_cfg,
                "-f", target_cfg,
                "-c", "init; scan_chain; exit",
            ],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        detected = "tap/device found" in output.lower() or "idcode" in output.lower()
        return {
            "detected": detected,
            "output": output[:500],
        }
    except FileNotFoundError:
        return {"detected": False, "error": "openocd 미설치"}
    except subprocess.TimeoutExpired:
        return {"detected": False, "error": "타임아웃"}


def scan_usb_devices() -> list[dict]:
    """연결된 USB 디바이스 목록."""
    devices = []
    try:
        result = subprocess.run(
            ["lsusb"], capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 6:
                devices.append({
                    "bus": parts[1],
                    "device": parts[3].rstrip(":"),
                    "id": parts[5] if len(parts) > 5 else "",
                    "name": " ".join(parts[6:]) if len(parts) > 6 else "",
                })
    except FileNotFoundError:
        pass
    return devices


def check_spi_flash(device: str = "/dev/spidev0.0") -> dict:
    """SPI 플래시 존재 여부 확인."""
    result = {"device": device, "accessible": Path(device).exists()}
    if result["accessible"]:
        try:
            # flashrom으로 플래시 칩 탐지
            probe = subprocess.run(
                ["flashrom", "-p", f"linux_spi:dev={device}", "--flash-name"],
                capture_output=True, text=True, timeout=15,
            )
            result["chip"] = probe.stdout.strip()
            result["detected"] = probe.returncode == 0
        except FileNotFoundError:
            result["error"] = "flashrom 미설치"
    return result


def generate_hardware_report(results: dict, output: Path | None) -> None:
    print("\n=== 하드웨어 인터페이스 탐지 결과 ===\n")

    uart_ports = results.get("uart_ports", [])
    if uart_ports:
        print(f"[+] UART 포트 {len(uart_ports)}개 발견:")
        for p in uart_ports:
            print(f"  {p['port']}")
            if p.get("baud_rate"):
                print(f"    보레이트: {p['baud_rate']}")
    else:
        print("[-] UART 포트 미발견")

    usb_devices = results.get("usb_devices", [])
    print(f"\n[+] USB 디바이스 {len(usb_devices)}개:")
    for dev in usb_devices[:5]:
        print(f"  {dev['id']} — {dev['name']}")

    spi = results.get("spi", {})
    if spi.get("detected"):
        print(f"\n[+] SPI 플래시 탐지: {spi.get('chip')}")

    if output:
        output.write_text(json.dumps(results, indent=2, ensure_ascii=False))
        print(f"\n[+] 결과 저장: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="하드웨어 인터페이스 탐지")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="전체 인터페이스 스캔")
    scan_p.add_argument("-o", "--output", type=Path)

    uart_p = sub.add_parser("uart", help="UART 보레이트 탐지")
    uart_p.add_argument("port", help="포트 (예: /dev/ttyUSB0)")

    jtag_p = sub.add_parser("jtag", help="JTAG 탐지")
    jtag_p.add_argument("--interface", default="interface/ftdi/ft232r.cfg")
    jtag_p.add_argument("--target", default="target/stm32f1x.cfg")

    args = parser.parse_args()

    match args.cmd:
        case "scan":
            results = {
                "uart_ports": [vars(r) for r in detect_uart_ports()],
                "usb_devices": scan_usb_devices(),
                "spi": check_spi_flash(),
            }
            generate_hardware_report(results, getattr(args, "output", None))

        case "uart":
            print(f"[*] {args.port} 보레이트 탐지 중...")
            baud = probe_uart_baud(args.port)
            if baud:
                print(f"[+] 보레이트: {baud}")
            else:
                print("[-] 보레이트 탐지 실패")

        case "jtag":
            result = detect_jtag_via_openocd(args.interface, args.target)
            if result["detected"]:
                print("[+] JTAG 디바이스 탐지")
            else:
                print(f"[-] JTAG 미탐지: {result.get('error', result.get('output', ''))[:200]}")


if __name__ == "__main__":
    main()
```

---

## 3. TPM/HSM 보안 점검

```bash
# TPM 존재 및 버전 확인
ls /dev/tpm* 2>/dev/null && echo "TPM 존재" || echo "TPM 없음"
cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null
tpm2_getcap properties-fixed 2>/dev/null | head -20

# TPM 제조사·펌웨어 정보
tpm2_getcap properties-fixed 2>/dev/null | grep -E "TPM2_PT_(MANUFACTURER|VENDOR|FIRMWARE)"

# Secure Boot 상태
mokutil --sb-state 2>/dev/null
efivar --list 2>/dev/null | grep -i secure

# 부팅 체인 검증
dmesg | grep -i "secure boot\|tpm\|measured boot"

# 디스크 암호화 상태
lsblk -f | grep -E "crypto_LUKS|BitLocker"
```

---

## 4. 하드웨어 보안 평가 체크리스트

| 항목 | 점검 방법 | 통과 기준 |
|------|-----------|-----------|
| JTAG/UART 비활성화 | 핀 물리 점검 + 통신 시도 | 응답 없음 |
| 펌웨어 서명 | 서명 파일 + 공개키 검증 | RSA/EC 서명 확인 |
| 부팅 체인 | Secure Boot 상태 확인 | Secure Boot 활성화 |
| 디버그 포트 | JTAG/SWD 전압 측정 | 핀 비활성 또는 제거 |
| 탬퍼 감지 | 물리 검사 | 에폭시/메시 존재 |
| 민감 키 저장 | 소스 코드 분석 | HSM/TPM 사용 |
| SPI 플래시 | flashrom 읽기 시도 | 암호화 또는 읽기 불가 |
| 사이드채널 | ChipWhisperer 분석 | 마스킹 적용 확인 |
