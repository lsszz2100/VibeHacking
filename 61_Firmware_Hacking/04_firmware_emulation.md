> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 펌웨어 에뮬레이션

## 0. 초보자를 위한 개념 이해

### 에뮬레이션이란?

**에뮬레이션(Emulation)**은 한 하드웨어/소프트웨어 환경을 다른 환경에서 모사하는 것입니다.

```
실제 실행:          에뮬레이션:
  ARM CPU            x86 PC에서
  → ARM 코드 실행    → QEMU가 ARM CPU 흉내내기
                     → ARM 코드를 x86으로 변환 실행
```

**왜 에뮬레이션이 필요한가?**
```
문제: 펌웨어 분석 시 실제 장치가 없으면?
  - 장치를 사서 분석? → 비쌈, 위험
  - 코드만 보면? → 동적 동작 파악 어려움
  
해결책: 에뮬레이션
  - 실제 장치 없이 펌웨어 실행
  - 웹 인터페이스 테스트 가능
  - 취약점 동적 탐지 가능
  - 네트워크 서비스 인터랙션 테스트
```

### 에뮬레이션 도구 비교

| 도구 | 에뮬레이션 유형 | 장점 | 단점 |
|------|----------------|------|------|
| **QEMU** | 완전 시스템/사용자 모드 | 다양한 아키텍처 지원 | 설정 복잡 |
| **Firmadyne** | 시스템 에뮬레이션 | 자동화 | 성공률 약 30% |
| **FirmAE** | 시스템 에뮬레이션 | Firmadyne 개선 | 여전히 실패 케이스 있음 |
| **GDBServer** | 디버깅 | 단계별 실행 가능 | 별도 GDB 클라이언트 필요 |

### 에뮬레이션의 한계

```
완벽한 에뮬레이션은 어려운 이유:
  - 독점 하드웨어 레지스터 (정보 없음)
  - GPIO, I2C, SPI 같은 하드웨어 인터페이스
  - 커스텀 드라이버 (누락된 커널 모듈)
  - 암호화된 펌웨어 (복호화 키 없음)
  
대안:
  - 부분 에뮬레이션 (특정 바이너리만)
  - 실제 하드웨어 (JTAG으로 디버그)
  - 하이브리드 접근 (코드 패치로 에뮬레이션 우회)
```

---

## 에뮬레이션 개요

실제 하드웨어 없이 펌웨어를 실행하는 방법. 네트워크 서비스 테스트, 동적 분석, 퍼징에 필수적이다.

```
에뮬레이션 레벨
├── 시스템 에뮬레이션 — 전체 하드웨어 플랫폼 (QEMU)
├── 사용자 에뮬레이션 — 단일 바이너리 (QEMU usermode)
└── 부분 에뮬레이션 — 특정 컴포넌트 (Firmadyne, FirmAE)
```

## QEMU 사용자 모드 에뮬레이션

### ARM 바이너리 실행
```bash
# 필요 패키지
sudo apt install qemu-user-static binfmt-support

# ARM 바이너리 단독 실행
qemu-arm-static -L squashfs-root/ squashfs-root/bin/busybox

# chroot 환경에서 실행 (더 완전한 환경)
sudo cp $(which qemu-arm-static) squashfs-root/usr/bin/
sudo chroot squashfs-root/ /bin/sh

# chroot 내에서
ls /
/usr/sbin/httpd &   # 웹서버 시작
netstat -tlnp       # 열린 포트 확인
```

### MIPS 바이너리 실행
```bash
# MIPS 빅엔디안
qemu-mips-static -L squashfs-root/ squashfs-root/usr/sbin/httpd

# MIPS 리틀엔디안 (EL)
qemu-mipsel-static -L squashfs-root/ squashfs-root/usr/sbin/httpd

# chroot MIPS
sudo cp $(which qemu-mips-static) squashfs-root/usr/bin/
sudo chroot squashfs-root/ /usr/sbin/httpd -f /etc/httpd.conf
```

## Firmadyne / FirmAE

### Firmadyne 설치 및 사용
```bash
git clone --recursive https://github.com/firmadyne/firmadyne.git
cd firmadyne

# 설정
sudo ./setup.sh
sudo -u postgres createdb -O firmadyne firmware

# 펌웨어 추출 및 분석
python3 extractor/extractor.py \
    -b Netgear \
    -sql 127.0.0.1 \
    -np -nk \
    firmware.bin \
    images/

# 에뮬레이션
sudo ./scratch/1/run.sh   # 이미지 ID 1로 에뮬레이션
```

### FirmAE (개선된 Firmadyne)
```bash
git clone https://github.com/pr0v3rbs/FirmAE.git
cd FirmAE && ./download.sh && ./install.sh

# 실행
sudo ./run.sh -r brand firmware.bin  # 전체 에뮬레이션
sudo ./run.sh -a brand firmware.bin  # 분석 모드
sudo ./run.sh -d brand firmware.bin  # 디버그 모드
```

## QEMU 시스템 에뮬레이션

```bash
# ARM 라즈베리파이 이미지 에뮬레이션 예시
qemu-system-arm \
    -machine versatilepb \
    -cpu arm1176 \
    -m 256 \
    -kernel kernel.img \
    -dtb bcm2708-rpi-b.dtb \
    -drive file=rootfs.img,format=raw \
    -append "root=/dev/sda2 console=ttyAMA0" \
    -serial stdio \
    -net nic \
    -net user,hostfwd=tcp::8080-:80

# MIPS 라우터 에뮬레이션
qemu-system-mips \
    -M malta \
    -kernel vmlinux \
    -drive file=rootfs.img,format=raw \
    -append "root=/dev/hda console=tty0" \
    -net nic,model=pcnet \
    -net user,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22 \
    -nographic
```

## 에뮬레이션 자동화 도구

```python
#!/usr/bin/env python3
"""펌웨어 에뮬레이션 자동화 및 서비스 탐지."""

import argparse
import subprocess
import time
import socket
import sys
from pathlib import Path
from dataclasses import dataclass


QEMU_BINS = {
    "arm":    "qemu-arm-static",
    "armeb":  "qemu-armeb-static",
    "mips":   "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "mips64": "qemu-mips64-static",
    "ppc":    "qemu-ppc-static",
    "x86_64": None,  # 네이티브
}

COMMON_SERVICES = [
    ("http",   80),
    ("https",  443),
    ("telnet", 23),
    ("ssh",    22),
    ("ftp",    21),
    ("upnp",   1900),
    ("http-alt", 8080),
    ("http-alt", 8888),
]


@dataclass
class EmulationResult:
    binary: str
    arch: str
    exit_code: int
    stdout: str
    stderr: str
    open_ports: list[int]


def detect_arch(binary: Path) -> str:
    result = subprocess.run(
        ["file", "-b", str(binary)], capture_output=True, text=True
    )
    out = result.stdout.lower()
    if "aarch64" in out or "arm64" in out:
        return "arm64"
    if "arm" in out:
        return "armeb" if "big-endian" in out else "arm"
    if "mips" in out:
        return "mips" if "big-endian" in out else "mipsel"
    if "powerpc" in out or "ppc" in out:
        return "ppc"
    if "x86-64" in out or "x86_64" in out:
        return "x86_64"
    return "unknown"


def prepare_chroot(root: Path, arch: str) -> bool:
    qemu_bin = QEMU_BINS.get(arch)
    if not qemu_bin:
        return True  # 네이티브

    qemu_path = Path("/usr/bin") / qemu_bin
    if not qemu_path.exists():
        qemu_path = Path("/usr/bin/qemu-arm-static")
        if not qemu_path.exists():
            print(f"[!] QEMU 없음: {qemu_bin}")
            return False

    dest = root / "usr" / "bin" / qemu_bin
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        import shutil
        shutil.copy2(str(qemu_path), str(dest))
    return True


def scan_ports(host: str = "127.0.0.1", timeout: float = 0.5) -> list[int]:
    open_ports: list[int] = []
    for _, port in COMMON_SERVICES:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except (ConnectionRefusedError, OSError, TimeoutError):
            pass
    return open_ports


def run_binary_in_chroot(
    root: Path,
    binary: str,
    arch: str,
    timeout: int = 10,
) -> EmulationResult:
    qemu_bin = QEMU_BINS.get(arch)

    if qemu_bin:
        cmd = ["sudo", "chroot", str(root), f"/usr/bin/{qemu_bin}", binary]
    else:
        cmd = ["sudo", "chroot", str(root), binary]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ports = scan_ports()
        return EmulationResult(
            binary=binary,
            arch=arch,
            exit_code=result.returncode,
            stdout=result.stdout[:1000],
            stderr=result.stderr[:1000],
            open_ports=ports,
        )
    except subprocess.TimeoutExpired:
        ports = scan_ports()
        return EmulationResult(
            binary=binary,
            arch=arch,
            exit_code=-1,
            stdout="(타임아웃 — 서비스 실행 중일 수 있음)",
            stderr="",
            open_ports=ports,
        )


def test_http_service(port: int = 80) -> dict[str, str]:
    import urllib.request
    results: dict[str, str] = {}
    endpoints = ["/", "/cgi-bin/", "/admin/", "/index.html", "/login.html"]

    for ep in endpoints:
        try:
            url = f"http://127.0.0.1:{port}{ep}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                results[ep] = f"{resp.status} {resp.reason}"
        except Exception as e:
            results[ep] = str(e)[:50]
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="펌웨어 에뮬레이션 자동화")
    parser.add_argument("root", type=Path, help="펌웨어 루트 파일시스템")
    parser.add_argument("-b", "--binary",
                        default="/usr/sbin/httpd",
                        help="실행할 바이너리 (기본: /usr/sbin/httpd)")
    parser.add_argument("--arch", help="아키텍처 강제 지정 (arm/mips/mipsel)")
    parser.add_argument("--http-test", action="store_true",
                        help="HTTP 서비스 엔드포인트 테스트")
    parser.add_argument("-t", "--timeout", type=int, default=15)
    args = parser.parse_args()

    if not args.root.exists():
        print(f"[!] 루트 디렉토리 없음: {args.root}", file=sys.stderr)
        sys.exit(1)

    binary_path = args.root / args.binary.lstrip("/")
    if not binary_path.exists():
        print(f"[!] 바이너리 없음: {binary_path}", file=sys.stderr)
        alternatives = list(args.root.rglob("httpd")) + \
                       list(args.root.rglob("lighttpd")) + \
                       list(args.root.rglob("uhttpd"))
        if alternatives:
            print(f"[*] 대안 발견: {alternatives[0]}")
            binary_path = alternatives[0]
            args.binary = "/" + str(binary_path.relative_to(args.root))
        else:
            sys.exit(1)

    arch = args.arch or detect_arch(binary_path)
    print(f"[*] 아키텍처: {arch}")
    print(f"[*] 바이너리: {args.binary}")

    print(f"[*] chroot 환경 준비...")
    if not prepare_chroot(args.root, arch):
        sys.exit(1)

    print(f"[*] 에뮬레이션 시작 (타임아웃: {args.timeout}s)...")
    result = run_binary_in_chroot(args.root, args.binary, arch, args.timeout)

    print(f"\n{'='*60}")
    print(f"종료 코드: {result.exit_code}")
    if result.stdout:
        print(f"STDOUT: {result.stdout[:300]}")
    if result.stderr:
        print(f"STDERR: {result.stderr[:300]}")

    if result.open_ports:
        print(f"\n[+] 열린 포트: {result.open_ports}")
        if args.http_test and 80 in result.open_ports:
            print("\n[*] HTTP 엔드포인트 테스트:")
            http_results = test_http_service(80)
            for ep, status in http_results.items():
                print(f"    {ep:30s} → {status}")
    else:
        print("\n[-] 열린 포트 없음")


if __name__ == "__main__":
    main()
```

## 동적 디버깅

```bash
# QEMU + GDB 원격 디버깅
# 터미널 1: QEMU 실행 (gdbserver 내장)
sudo chroot squashfs-root/ \
    qemu-arm-static -g 1234 /usr/sbin/httpd

# 터미널 2: GDB 연결
gdb-multiarch squashfs-root/usr/sbin/httpd
(gdb) target remote :1234
(gdb) break *0x10000   # 시작점에 중단점
(gdb) continue

# 함수에 중단점
(gdb) break strcpy
(gdb) info registers
(gdb) x/20x $sp        # 스택 덤프
```

## 네트워크 인터페이스 설정

```bash
# tap 인터페이스로 실제 네트워크 에뮬레이션
sudo ip tuntap add tap0 mode tap
sudo ip addr add 192.168.100.1/24 dev tap0
sudo ip link set tap0 up

# QEMU에 tap 연결
qemu-system-arm \
    -M versatilepb \
    -kernel kernel.img \
    -drive file=rootfs.img,format=raw \
    -net nic \
    -net tap,ifname=tap0,script=no,downscript=no \
    -nographic

# 에뮬레이션된 장치 스캔
nmap -sV 192.168.100.0/24
```

다음 파일에서 발견된 취약점을 실제로 익스플로잇하는 방법을 다룬다.


<!-- detect-validate-61 -->
## 에뮬레이션 검증 — 에뮬레이션이 실제 하드웨어와 일치하는가

펌웨어 에뮬레이션은 *부팅에 성공했다*가 아니라 **에뮬레이션이 실제 하드웨어 동작(주변장치·NVRAM·네트워크)을 충실히 재현하고, 분석 결과가 실기와 어긋나지 않는가**로 판정한다. 검증은 **소유 펌웨어**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 부팅 충실도 | 가짜 부팅 | 서비스 기동 확인 | 실서비스 동작 |
| 주변장치 | NVRAM/하드웨어 미흡 | 누락 주변장치 점검 | 핵심 페리페럴 재현 |
| 네트워크 | 인터페이스 부재 | 서비스 포트 확인 | 웹/관리 서비스 응답 |
| 동작 일치 | 실기와 괴리 | 실기 vs 에뮬 비교 | 동작 일치 확인 |

### 방어 검증 (직접 확인)

```bash
# 1) 에뮬레이션된 펌웨어가 실제 서비스를 띄우는지(웹/관리 포트) — 소유 펌웨어에서만
sudo firmadyne/... 2>/dev/null; nmap -Pn -p 80,443,23,22 127.0.0.1 2>/dev/null | grep -E 'open|closed' || echo "use FirmAE/firmadyne and probe emulated services"
# 2) 에뮬 환경 프로세스가 펌웨어 바이너리를 실제 실행 중인지
ps aux 2>/dev/null | grep -Ei 'qemu|httpd|lighttpd|busybox' | grep -v grep | head
```

> 검증은 반드시 **소유 펌웨어**에서만 한다. "부팅에 성공했다"와 "실기와 일치한다"는 다르다 — 서비스 기동·실기 비교로 직접 확인한다([[03_System_Hacking]], [[27_IoT_Hacking]]).

**최신 기법·통제 (2025–2026):**
- QEMU/qiling·FirmAE로 동적분석 — 검증: 에뮬레이션 결과가 실기기와 교차확인되는가([[65_Reverse_Engineering_Advanced]])
- 안전한 격리 — 통제되는지 확인

---

<a name="english"></a>

# Firmware Emulation

## Emulation Overview

Methods for running firmware without actual hardware. Essential for network service testing, dynamic analysis, and fuzzing.

```
Emulation Levels
├── System emulation — Full hardware platform (QEMU)
├── User emulation — Single binary (QEMU usermode)
└── Partial emulation — Specific components (Firmadyne, FirmAE)
```

## QEMU User Mode Emulation

### Running ARM Binaries
```bash
# Required packages
sudo apt install qemu-user-static binfmt-support

# Run ARM binary standalone
qemu-arm-static -L squashfs-root/ squashfs-root/bin/busybox

# Run in chroot environment (more complete environment)
sudo cp $(which qemu-arm-static) squashfs-root/usr/bin/
sudo chroot squashfs-root/ /bin/sh

# Inside chroot
ls /
/usr/sbin/httpd &   # Start web server
netstat -tlnp       # Check open ports
```

### Running MIPS Binaries
```bash
# MIPS big-endian
qemu-mips-static -L squashfs-root/ squashfs-root/usr/sbin/httpd

# MIPS little-endian (EL)
qemu-mipsel-static -L squashfs-root/ squashfs-root/usr/sbin/httpd

# chroot MIPS
sudo cp $(which qemu-mips-static) squashfs-root/usr/bin/
sudo chroot squashfs-root/ /usr/sbin/httpd -f /etc/httpd.conf
```

## Firmadyne / FirmAE

### Firmadyne Installation and Usage
```bash
git clone --recursive https://github.com/firmadyne/firmadyne.git
cd firmadyne

# Setup
sudo ./setup.sh
sudo -u postgres createdb -O firmadyne firmware

# Firmware extraction and analysis
python3 extractor/extractor.py \
    -b Netgear \
    -sql 127.0.0.1 \
    -np -nk \
    firmware.bin \
    images/

# Emulation
sudo ./scratch/1/run.sh   # Emulate with image ID 1
```

### FirmAE (Improved Firmadyne)
```bash
git clone https://github.com/pr0v3rbs/FirmAE.git
cd FirmAE && ./download.sh && ./install.sh

# Run
sudo ./run.sh -r brand firmware.bin  # Full emulation
sudo ./run.sh -a brand firmware.bin  # Analysis mode
sudo ./run.sh -d brand firmware.bin  # Debug mode
```

## QEMU System Emulation

```bash
# ARM Raspberry Pi image emulation example
qemu-system-arm \
    -machine versatilepb \
    -cpu arm1176 \
    -m 256 \
    -kernel kernel.img \
    -dtb bcm2708-rpi-b.dtb \
    -drive file=rootfs.img,format=raw \
    -append "root=/dev/sda2 console=ttyAMA0" \
    -serial stdio \
    -net nic \
    -net user,hostfwd=tcp::8080-:80

# MIPS router emulation
qemu-system-mips \
    -M malta \
    -kernel vmlinux \
    -drive file=rootfs.img,format=raw \
    -append "root=/dev/hda console=tty0" \
    -net nic,model=pcnet \
    -net user,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22 \
    -nographic
```

## Emulation Automation Tool

```python
#!/usr/bin/env python3
"""Firmware emulation automation and service detection."""

import argparse
import subprocess
import time
import socket
import sys
from pathlib import Path
from dataclasses import dataclass


QEMU_BINS = {
    "arm":    "qemu-arm-static",
    "armeb":  "qemu-armeb-static",
    "mips":   "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "mips64": "qemu-mips64-static",
    "ppc":    "qemu-ppc-static",
    "x86_64": None,  # Native
}

COMMON_SERVICES = [
    ("http",   80),
    ("https",  443),
    ("telnet", 23),
    ("ssh",    22),
    ("ftp",    21),
    ("upnp",   1900),
    ("http-alt", 8080),
    ("http-alt", 8888),
]


@dataclass
class EmulationResult:
    binary: str
    arch: str
    exit_code: int
    stdout: str
    stderr: str
    open_ports: list[int]


def detect_arch(binary: Path) -> str:
    result = subprocess.run(["file", "-b", str(binary)], capture_output=True, text=True)
    out = result.stdout.lower()
    if "aarch64" in out or "arm64" in out:
        return "arm64"
    if "arm" in out:
        return "armeb" if "big-endian" in out else "arm"
    if "mips" in out:
        return "mips" if "big-endian" in out else "mipsel"
    if "powerpc" in out or "ppc" in out:
        return "ppc"
    if "x86-64" in out or "x86_64" in out:
        return "x86_64"
    return "unknown"


def prepare_chroot(root: Path, arch: str) -> bool:
    qemu_bin = QEMU_BINS.get(arch)
    if not qemu_bin:
        return True  # Native

    qemu_path = Path("/usr/bin") / qemu_bin
    if not qemu_path.exists():
        qemu_path = Path("/usr/bin/qemu-arm-static")
        if not qemu_path.exists():
            print(f"[!] QEMU not found: {qemu_bin}")
            return False

    dest = root / "usr" / "bin" / qemu_bin
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        import shutil
        shutil.copy2(str(qemu_path), str(dest))
    return True


def scan_ports(host: str = "127.0.0.1", timeout: float = 0.5) -> list[int]:
    open_ports: list[int] = []
    for _, port in COMMON_SERVICES:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except (ConnectionRefusedError, OSError, TimeoutError):
            pass
    return open_ports


def run_binary_in_chroot(root: Path, binary: str, arch: str, timeout: int = 10) -> EmulationResult:
    qemu_bin = QEMU_BINS.get(arch)
    if qemu_bin:
        cmd = ["sudo", "chroot", str(root), f"/usr/bin/{qemu_bin}", binary]
    else:
        cmd = ["sudo", "chroot", str(root), binary]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ports = scan_ports()
        return EmulationResult(
            binary=binary, arch=arch, exit_code=result.returncode,
            stdout=result.stdout[:1000], stderr=result.stderr[:1000], open_ports=ports,
        )
    except subprocess.TimeoutExpired:
        ports = scan_ports()
        return EmulationResult(
            binary=binary, arch=arch, exit_code=-1,
            stdout="(Timeout — service may be running)", stderr="", open_ports=ports,
        )


def test_http_service(port: int = 80) -> dict[str, str]:
    import urllib.request
    results: dict[str, str] = {}
    endpoints = ["/", "/cgi-bin/", "/admin/", "/index.html", "/login.html"]
    for ep in endpoints:
        try:
            url = f"http://127.0.0.1:{port}{ep}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                results[ep] = f"{resp.status} {resp.reason}"
        except Exception as e:
            results[ep] = str(e)[:50]
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Firmware emulation automation")
    parser.add_argument("root", type=Path, help="Firmware root filesystem")
    parser.add_argument("-b", "--binary", default="/usr/sbin/httpd",
                        help="Binary to execute (default: /usr/sbin/httpd)")
    parser.add_argument("--arch", help="Force architecture (arm/mips/mipsel)")
    parser.add_argument("--http-test", action="store_true", help="Test HTTP service endpoints")
    parser.add_argument("-t", "--timeout", type=int, default=15)
    args = parser.parse_args()

    if not args.root.exists():
        print(f"[!] Root directory not found: {args.root}", file=sys.stderr)
        sys.exit(1)

    binary_path = args.root / args.binary.lstrip("/")
    if not binary_path.exists():
        print(f"[!] Binary not found: {binary_path}", file=sys.stderr)
        alternatives = list(args.root.rglob("httpd")) + \
                       list(args.root.rglob("lighttpd")) + \
                       list(args.root.rglob("uhttpd"))
        if alternatives:
            print(f"[*] Alternative found: {alternatives[0]}")
            binary_path = alternatives[0]
            args.binary = "/" + str(binary_path.relative_to(args.root))
        else:
            sys.exit(1)

    arch = args.arch or detect_arch(binary_path)
    print(f"[*] Architecture: {arch}")
    print(f"[*] Binary: {args.binary}")
    print(f"[*] Preparing chroot environment...")
    if not prepare_chroot(args.root, arch):
        sys.exit(1)

    print(f"[*] Starting emulation (timeout: {args.timeout}s)...")
    result = run_binary_in_chroot(args.root, args.binary, arch, args.timeout)

    print(f"\n{'='*60}")
    print(f"Exit code: {result.exit_code}")
    if result.stdout:
        print(f"STDOUT: {result.stdout[:300]}")
    if result.stderr:
        print(f"STDERR: {result.stderr[:300]}")

    if result.open_ports:
        print(f"\n[+] Open ports: {result.open_ports}")
        if args.http_test and 80 in result.open_ports:
            print("\n[*] HTTP endpoint test:")
            http_results = test_http_service(80)
            for ep, status in http_results.items():
                print(f"    {ep:30s} → {status}")
    else:
        print("\n[-] No open ports")


if __name__ == "__main__":
    main()
```

## Dynamic Debugging

```bash
# QEMU + GDB remote debugging
# Terminal 1: Run QEMU (with built-in gdbserver)
sudo chroot squashfs-root/ \
    qemu-arm-static -g 1234 /usr/sbin/httpd

# Terminal 2: Connect GDB
gdb-multiarch squashfs-root/usr/sbin/httpd
(gdb) target remote :1234
(gdb) break *0x10000   # Breakpoint at start
(gdb) continue

# Breakpoint at function
(gdb) break strcpy
(gdb) info registers
(gdb) x/20x $sp        # Stack dump
```

## Network Interface Setup

```bash
# Real network emulation with tap interface
sudo ip tuntap add tap0 mode tap
sudo ip addr add 192.168.100.1/24 dev tap0
sudo ip link set tap0 up

# Attach tap to QEMU
qemu-system-arm \
    -M versatilepb \
    -kernel kernel.img \
    -drive file=rootfs.img,format=raw \
    -net nic \
    -net tap,ifname=tap0,script=no,downscript=no \
    -nographic

# Scan emulated device
nmap -sV 192.168.100.0/24
```

The next file covers methods for actually exploiting discovered vulnerabilities.

<!-- detect-validate-61 -->
## Emulation Validation — Does the Emulation Actually Match Real Hardware?

Firmware emulation is judged not by *having booted* but by **whether it faithfully reproduces real hardware behavior (peripherals, NVRAM, network) so analysis results do not diverge from the physical device**. Validate only on **owned firmware**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Boot fidelity | Fake boot | Confirm services start | Real services run |
| Peripherals | NVRAM/HW missing | Check missing peripherals | Key peripherals reproduced |
| Network | No interface | Check service ports | Web/mgmt service responds |
| Behavior match | Diverges from device | Compare device vs emu | Behavior matches |

### Defense validation (verify directly)

```bash
# 1) Whether the emulated firmware actually brings up services (web/mgmt ports) — owned firmware only
sudo firmadyne/... 2>/dev/null; nmap -Pn -p 80,443,23,22 127.0.0.1 2>/dev/null | grep -E 'open|closed' || echo "use FirmAE/firmadyne and probe emulated services"
# 2) Whether emulation processes are actually running the firmware binaries
ps aux 2>/dev/null | grep -Ei 'qemu|httpd|lighttpd|busybox' | grep -v grep | head
```

> Validate only on **owned firmware**. "Booted successfully" differs from "matches the real device" — confirm directly via service bring-up and device comparison ([[03_System_Hacking]], [[27_IoT_Hacking]]).
