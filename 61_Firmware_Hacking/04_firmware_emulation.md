# 펌웨어 에뮬레이션

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
        # 대안 탐색
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
