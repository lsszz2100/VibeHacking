> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 펌웨어 역공학 (Firmware Reverse Engineering)

## 개념 소개

임베디드 펌웨어 역공학은 라우터, IP 카메라, IoT 기기 등의 펌웨어 이미지를 분석하여 숨겨진 취약점, 하드코딩된 비밀번호, 백도어를 찾는 기술입니다. 마치 가전제품을 분해해서 내부 회로를 들여다보는 것과 같습니다.

---

## 핵심 기술 및 도구

### 펌웨어 추출 방법

| 방법 | 도구 | 난이도 |
|---|---|---|
| HTTP/TFTP 업데이트 인터셉트 | Wireshark | 낮음 |
| 제조사 공식 다운로드 | wget | 낮음 |
| UART/JTAG 디버그 포트 | OpenOCD | 중간 |
| Flash 칩 직접 덤프 | flashrom | 높음 |

### 주요 분석 도구

- **binwalk**: 펌웨어 내 파일시스템/아카이브 탐지 및 추출
- **Ghidra / IDA Pro**: MIPS, ARM 디스어셈블리
- **firmwalker**: 하드코딩 시크릿 스캔 스크립트
- **FACT**: 자동화된 펌웨어 분석 플랫폼
- **qemu-user**: MIPS/ARM 바이너리 에뮬레이션

### 주요 아키텍처

| 아키텍처 | 주요 기기 | 엔디안 |
|---|---|---|
| MIPS32 | 가정용 라우터 | Big/Little |
| ARM Cortex-A | 스마트폰, NAS | Little |
| ARM Cortex-M | MCU, 센서 | Little |
| PowerPC | 산업 장비 | Big |

### 하드코딩 시크릿 유형

- 기본 관리자 패스워드 (`admin:admin`)
- 백도어 계정 (`support:support`)
- 하드코딩 SSH 키
- API 키 및 AWS 자격증명
- 암호화 키 및 IV 값

---

## Python 실습: 펌웨어 엔트로피 분석기 + 하드코딩 시크릿 스캐너

```python
#!/usr/bin/env python3
"""
펌웨어 이미지에서 엔트로피 분석과 하드코딩 시크릿을 탐지합니다.
binwalk 없이 순수 Python으로 구현.
"""

import argparse
import math
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecretFinding:
    offset: int
    finding_type: str
    value: str
    severity: str  # 'HIGH', 'MEDIUM', 'LOW'


@dataclass
class EntropyRegion:
    offset: int
    size: int
    entropy: float
    region_type: str  # 'compressed', 'encrypted', 'code', 'data'


@dataclass
class FirmwareReport:
    file_path: Path
    file_size: int
    overall_entropy: float
    magic_signatures: list[str] = field(default_factory=list)
    entropy_regions: list[EntropyRegion] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    architecture_hints: list[str] = field(default_factory=list)


# 파일시스템/아카이브 매직 바이트
MAGIC_SIGNATURES: dict[str, bytes] = {
    "SquashFS": b"sqsh",
    "SquashFS-LE": b"hsqs",
    "JFFS2": b"\x19\x85",
    "gzip": b"\x1f\x8b",
    "bzip2": b"BZh",
    "lzma": b"\x5d\x00\x00",
    "7zip": b"7z\xbc\xaf",
    "ZIP": b"PK\x03\x04",
    "UBI": b"UBI#",
    "CPIO": b"070701",
    "ELF": b"\x7fELF",
    "U-Boot": b"\x27\x05\x19\x56",
}

# 아키텍처 힌트 패턴 (문자열 기반)
ARCH_HINTS: dict[str, bytes] = {
    "MIPS": b"mips",
    "ARM": b"arm",
    "PowerPC": b"powerpc",
    "AArch64": b"aarch64",
    "x86": b"i386",
}

# 하드코딩 시크릿 패턴
SECRET_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    ("AWS 액세스 키", "HIGH", re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS"),
    ("패스워드 필드", "HIGH", re.compile(rb"password[=:\"'\s]{1,3}[^\s\"']{4,32}", re.IGNORECASE), "CRED"),
    ("기본 자격증명", "HIGH", re.compile(rb"(admin|root):([a-zA-Z0-9!@#$]{4,20})"), "CRED"),
    ("SSH 개인키 헤더", "HIGH", re.compile(rb"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----"), "KEY"),
    ("API 키 패턴", "MEDIUM", re.compile(rb"api[_-]?key[=:\"'\s]{1,3}[a-zA-Z0-9]{16,64}", re.IGNORECASE), "API"),
    ("IP 주소", "LOW", re.compile(rb"\b(192\.168\.\d{1,3}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"), "IP"),
    ("URL 자격증명", "MEDIUM", re.compile(rb"https?://[^:]+:[^@]{4,32}@"), "URL"),
]


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def classify_region(entropy: float) -> str:
    if entropy > 7.5:
        return "encrypted"
    elif entropy > 6.8:
        return "compressed"
    elif entropy > 4.0:
        return "code"
    else:
        return "data"


def analyze_entropy_map(data: bytes, block_size: int = 512) -> list[EntropyRegion]:
    """파일을 블록으로 나누어 엔트로피 맵을 생성합니다."""
    regions: list[EntropyRegion] = []
    prev_type = ""
    prev_start = 0
    prev_entropy = 0.0

    for offset in range(0, len(data), block_size):
        block = data[offset : offset + block_size]
        entropy = calculate_entropy(block)
        rtype = classify_region(entropy)

        if rtype != prev_type and offset > 0:
            regions.append(
                EntropyRegion(
                    offset=prev_start,
                    size=offset - prev_start,
                    entropy=round(prev_entropy, 3),
                    region_type=prev_type,
                )
            )
            prev_start = offset
        prev_entropy = entropy
        prev_type = rtype

    if prev_type:
        regions.append(
            EntropyRegion(
                offset=prev_start,
                size=len(data) - prev_start,
                entropy=round(prev_entropy, 3),
                region_type=prev_type,
            )
        )
    return regions


def scan_magic_signatures(data: bytes) -> list[str]:
    """알려진 파일시스템/아카이브 시그니처를 탐지합니다."""
    found: list[str] = []
    for name, sig in MAGIC_SIGNATURES.items():
        pos = data.find(sig)
        if pos != -1:
            found.append(f"{name} @ 0x{pos:08X}")
    return found


def scan_secrets(data: bytes) -> list[SecretFinding]:
    """하드코딩된 시크릿 패턴을 스캔합니다."""
    findings: list[SecretFinding] = []
    for name, severity, pattern, _ in SECRET_PATTERNS:
        for match in pattern.finditer(data):
            val = match.group(0)[:64].decode("ascii", errors="replace")
            findings.append(
                SecretFinding(
                    offset=match.start(),
                    finding_type=name,
                    value=val,
                    severity=severity,
                )
            )
    return findings[:50]  # 최대 50개


def detect_arch_hints(data: bytes) -> list[str]:
    hints: list[str] = []
    for arch, pattern in ARCH_HINTS.items():
        if pattern.lower() in data.lower():
            hints.append(arch)
    return hints


def analyze_firmware(file_path: Path) -> FirmwareReport | None:
    try:
        data = file_path.read_bytes()
    except OSError as e:
        print(f"[오류] {e}")
        return None

    report = FirmwareReport(
        file_path=file_path,
        file_size=len(data),
        overall_entropy=round(calculate_entropy(data), 4),
    )
    report.magic_signatures = scan_magic_signatures(data)
    report.entropy_regions = analyze_entropy_map(data)
    report.secrets = scan_secrets(data)
    report.architecture_hints = detect_arch_hints(data)
    return report


def print_report(report: FirmwareReport) -> None:
    print(f"\n{'='*65}")
    print(f"파일: {report.file_path.name}  ({report.file_size:,} bytes)")
    print(f"전체 엔트로피: {report.overall_entropy:.4f}")
    print(f"{'='*65}")

    if report.architecture_hints:
        print(f"아키텍처 힌트: {', '.join(report.architecture_hints)}")

    if report.magic_signatures:
        print(f"\n[파일시스템/아카이브 시그니처]")
        for sig in report.magic_signatures:
            print(f"  {sig}")

    print(f"\n[엔트로피 영역] 총 {len(report.entropy_regions)}개")
    for region in report.entropy_regions[:8]:
        bar = "█" * int(region.entropy)
        print(
            f"  0x{region.offset:08X}  {region.size:>8,}B  "
            f"{region.entropy:.3f} {bar:<8} [{region.region_type}]"
        )

    high = [s for s in report.secrets if s.severity == "HIGH"]
    med = [s for s in report.secrets if s.severity == "MEDIUM"]
    print(f"\n[하드코딩 시크릿] HIGH:{len(high)}  MEDIUM:{len(med)}")
    for sec in report.secrets[:10]:
        print(f"  [{sec.severity}] 0x{sec.offset:08X}  {sec.finding_type}")
        print(f"          {sec.value[:60]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="펌웨어 엔트로피 분석기 + 시크릿 스캐너")
    parser.add_argument("files", nargs="+", type=Path, help="분석할 펌웨어 이미지")
    args = parser.parse_args()
    for fp in args.files:
        if not fp.exists():
            print(f"파일 없음: {fp}")
            continue
        report = analyze_firmware(fp)
        if report:
            print_report(report)


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **IoT 보안 감사**: 출시 전 펌웨어에서 하드코딩 자격증명 사전 탐지
2. **취약점 연구**: NVRAM 설정 추출 후 telnet/SSH 기본 계정 확인
3. **사고 대응**: 침해된 라우터 펌웨어에서 백도어 코드 탐지

---

## 심화: binwalk 추출 → 루트파일시스템 분석 워크플로우

```bash
# 1. 파일시스템·아카이브 식별 및 재귀 추출
binwalk -Me firmware.bin
#   → _firmware.bin.extracted/ 에 squashfs-root 등 생성

# 2. 추출 실패 시 수동: 오프셋 잘라내기 후 unsquashfs
binwalk firmware.bin                       # SquashFS 오프셋 확인
dd if=firmware.bin bs=1 skip=<offset> of=fs.sqsh
unsquashfs fs.sqsh

# 3. 루트파일시스템에서 시크릿·백도어 스캔
grep -rIn "password" squashfs-root/etc/
firmwalker.sh squashfs-root/               # 하드코딩 시크릿 자동 스캔
ls -l squashfs-root/etc/{passwd,shadow}    # 기본 계정 확인
```

> 추출 후 우선 확인 대상: `/etc/passwd`·`/etc/shadow`(약한 해시), `/etc/init.d`(부팅 시 실행), `/www`·`/cgi-bin`(웹 취약점), 하드코딩 키·인증서.

---

## 펌웨어 에뮬레이션 (QEMU)

실기기 없이 펌웨어 바이너리를 실행해 동적 분석한다.

```bash
# MIPS 바이너리 단일 실행 (user-mode)
qemu-mipsel -L squashfs-root ./squashfs-root/usr/sbin/httpd

# 전체 시스템 에뮬레이션 (network 포함) — firmadyne/FirmAE 활용
./run.sh firmadyne firmware.bin            # NVRAM·네트워크 자동 구성
```

| 에뮬레이션 수준 | 도구 | 용도 |
|---|---|---|
| user-mode | `qemu-mipsel`/`qemu-arm` | 단일 바이너리 동작 확인 |
| system-mode | QEMU + 커널 | 부팅·서비스 기동 |
| 자동화 | firmadyne / FirmAE | NVRAM·네트워크 자동 구성 |

---

## 공격-방어 공방 매트릭스

| 보호 기법 (벤더) | 분석 방해 | 분석가 대응 | 잔여 리스크 |
|---|---|---|---|
| 펌웨어 암호화 | binwalk 추출 차단(엔트로피 7.5+) | 부트로더 키 추출·UART 덤프 | 높음 |
| 시리얼 콘솔 비활성 | UART 접근 차단 | JTAG·플래시 직접 덤프 | 높음 |
| 시큐어 부트 | 변조 펌웨어 거부 | 서명 우회·다운그레이드 공격 | 높음 |
| 문자열 난독화 | grep 시크릿 탐지 회피 | 런타임 메모리 덤프·복호 루틴 분석 | 중간 |
| 압축 파일시스템 | 단순 grep 무력화 | unsquashfs/jefferson 추출 후 스캔 | 낮음 |

---

## 빠른 자가진단 체크리스트

- [ ] `binwalk -Me`로 파일시스템을 재귀 추출했는가?
- [ ] 추출 실패 시 오프셋 기반 수동 추출을 시도했는가?
- [ ] `/etc/passwd`·`shadow`·init 스크립트의 하드코딩 계정을 점검했는가?
- [ ] firmwalker로 키·인증서·API 시크릿을 스캔했는가?
- [ ] QEMU로 핵심 서비스(httpd 등)를 에뮬레이션해 동적 검증했는가?
- [ ] 암호화 펌웨어는 부트로더/UART 경로로 평문 확보를 시도했는가?

---

## 요약

| 항목 | 내용 |
|---|---|
| 주요 아키텍처 | MIPS, ARM, PowerPC |
| 핵심 도구 | binwalk, firmwalker, Ghidra |
| 탐지 대상 | 기본 자격증명, 백도어, API 키 |
| 엔트로피 기준 | 7.5+ 암호화, 6.8+ 압축 |
| 에뮬레이션 | QEMU, firmadyne, FirmAE |

---

<!-- detect-validate-65 -->
## 안티분석 탐지와 분석 검증

펌웨어 분석에서 "추출했다 / 시크릿을 찾았다"는 출발점일 뿐이다. **추출 파일시스템이 온전한지**, **발견한 시크릿이 실제 작동하는지**를 검증하지 않으면 잘못된 결론(가짜 키·죽은 백도어)으로 이어진다.

### 안티분석 → 통제 → 검증 → 통과 기준

| 방해 요소 | 적용 통제 | 검증 방법(직접 확인) | 통과 기준 |
|---|---|---|---|
| 펌웨어 암호화 | 부트로더/UART로 평문 확보 | 추출본 엔트로피 재측정 | 엔트로피가 압축/평문 수준으로 하락 |
| 압축 파일시스템 | unsquashfs/jefferson 추출 | 루트FS가 마운트·탐색 가능한지 | `/etc`·바이너리 정상 노출 |
| 시크릿 진위 불명 | 동적 에뮬레이션(QEMU/FirmAE) | 추출 키·계정으로 서비스 인증 시도 | 실제 인증 성공/실패 확인 |

### 분석 검증 (직접 확인)

```bash
# 추출 루트파일시스템이 진짜 온전한지 마운트·구조로 확인
binwalk -Me firmware.bin
ls -l _firmware.bin.extracted/squashfs-root/{etc,bin,sbin} 2>/dev/null
file _firmware.bin.extracted/squashfs-root/bin/busybox    # 아키텍처/정상 ELF 확인
# 통과: /etc·init 스크립트·정상 ELF가 보이면 추출 성공
# 실패: 깨진 디렉터리/엔트로피 그대로면 암호화 상태 — 부트로더/UART 경로 재시도
```

> 검증은 **소유·허가된 기기와 격리 환경에서만** 수행한다. "찾았다"가 아니라 "마운트되고 인증된다"를 확인해야 펌웨어 분석 결론을 신뢰할 수 있다([[06_Malware_Analysis]]).

---

<a name="english"></a>

# Firmware Reverse Engineering

## Concept Overview

Firmware reverse engineering analyzes firmware images from routers, IP cameras, and IoT devices to find hidden vulnerabilities, hardcoded passwords, and backdoors — like disassembling an appliance to inspect its internal circuitry.

---

## Core Tools and Techniques

### Extraction Methods

| Method | Tool | Difficulty |
|---|---|---|
| HTTP/TFTP update intercept | Wireshark | Low |
| Vendor official download | wget | Low |
| UART/JTAG debug port | OpenOCD | Medium |
| Flash chip direct dump | flashrom | High |

### Common Secret Types Found

- Default admin passwords (`admin:admin`)
- Backdoor accounts (`support:support`)
- Hardcoded SSH keys
- API keys and AWS credentials
- Encryption keys and IV values

---

## Summary Table

| Item | Details |
|---|---|
| Key architectures | MIPS, ARM, PowerPC |
| Core tools | binwalk, firmwalker, Ghidra |
| Detection targets | Default credentials, backdoors, API keys |
| Entropy thresholds | 7.5+ encrypted, 6.8+ compressed |
| Emulation | QEMU, firmadyne, FirmAE |

---

## Deep Dive: binwalk Extraction → Root Filesystem Analysis

```bash
# 1. Identify filesystems/archives and recursively extract
binwalk -Me firmware.bin
#   → creates squashfs-root etc. under _firmware.bin.extracted/

# 2. If extraction fails, carve manually then unsquashfs
binwalk firmware.bin                       # find SquashFS offset
dd if=firmware.bin bs=1 skip=<offset> of=fs.sqsh
unsquashfs fs.sqsh

# 3. Scan the root filesystem for secrets/backdoors
grep -rIn "password" squashfs-root/etc/
firmwalker.sh squashfs-root/               # auto-scan hardcoded secrets
ls -l squashfs-root/etc/{passwd,shadow}    # check default accounts
```

> Priority targets after extraction: `/etc/passwd`/`/etc/shadow` (weak hashes), `/etc/init.d` (boot-time execution), `/www`/`/cgi-bin` (web vulns), hardcoded keys/certs.

---

## Firmware Emulation (QEMU)

Run firmware binaries without real hardware for dynamic analysis.

```bash
# Single MIPS binary (user-mode)
qemu-mipsel -L squashfs-root ./squashfs-root/usr/sbin/httpd

# Full-system emulation (with network) — via firmadyne/FirmAE
./run.sh firmadyne firmware.bin            # auto NVRAM/network setup
```

| Emulation Level | Tool | Purpose |
|---|---|---|
| user-mode | `qemu-mipsel`/`qemu-arm` | Verify single binary behavior |
| system-mode | QEMU + kernel | Boot/service startup |
| automated | firmadyne / FirmAE | Auto NVRAM/network config |

---

## Attack–Defense Matrix

| Protection (Vendor) | Analysis Impact | Analyst Response | Residual Risk |
|---|---|---|---|
| Firmware encryption | Blocks binwalk (entropy 7.5+) | Extract bootloader key / UART dump | High |
| Disabled serial console | Blocks UART access | JTAG / direct flash dump | High |
| Secure boot | Rejects modified firmware | Signature bypass / downgrade attack | High |
| String obfuscation | Evades grep secret scan | Runtime memory dump / decrypt routine | Medium |
| Compressed filesystem | Defeats plain grep | unsquashfs/jefferson then scan | Low |

---

## Quick Self-Assessment Checklist

- [ ] Did you recursively extract the filesystem with `binwalk -Me`?
- [ ] On extraction failure, did you try offset-based manual carving?
- [ ] Did you check `/etc/passwd`/`shadow` and init scripts for hardcoded accounts?
- [ ] Did you scan keys/certs/API secrets with firmwalker?
- [ ] Did you emulate core services (e.g., httpd) with QEMU for dynamic checks?
- [ ] For encrypted firmware, did you try the bootloader/UART path to obtain plaintext?

---

## Anti-Analysis Detection and Analysis Validation

In firmware analysis, "I extracted it / I found secrets" is only a starting point. Without verifying the **extracted filesystem is intact** and the **found secrets actually work**, you reach wrong conclusions (fake keys, dead backdoors).

### Anti-analysis -> control -> validation -> pass criterion

| Obstacle | Applied control | Validation (verify yourself) | Pass criterion |
|---|---|---|---|
| Firmware encryption | Obtain plaintext via bootloader/UART | Re-measure extracted entropy | Entropy drops to compressed/plaintext level |
| Compressed filesystem | unsquashfs/jefferson extraction | Can the rootfs mount and be browsed? | `/etc` and binaries appear normally |
| Secret authenticity unknown | Dynamic emulation (QEMU/FirmAE) | Try the extracted key/account against the service | Real auth success/failure confirmed |

### Analysis validation (verify yourself)

```bash
# Confirm the extracted rootfs is genuinely intact via mount/structure
binwalk -Me firmware.bin
ls -l _firmware.bin.extracted/squashfs-root/{etc,bin,sbin} 2>/dev/null
file _firmware.bin.extracted/squashfs-root/bin/busybox    # check arch / valid ELF
# Pass: /etc, init scripts, and valid ELFs appear -> extraction succeeded
# Fail: broken dirs / unchanged entropy means it's still encrypted - retry the bootloader/UART path
```

> Run validation only on **devices you own/are authorized for, in an isolated environment**. Trust your firmware conclusions only after confirming "it mounts and authenticates", not merely "I found it" (see [[06_Malware_Analysis]]).
