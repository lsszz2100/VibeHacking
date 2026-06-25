> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 02 — Firmware Analysis

## 0. 초보자를 위한 개념 이해

### 펌웨어 분석이란?

펌웨어(Firmware)는 하드웨어 장치에 내장된 소프트웨어로, 공유기·IP 카메라·스마트 가전 등 임베디드 기기의 운영체제와 애플리케이션이 담겨 있다. 펌웨어 분석(Firmware Analysis)은 이 바이너리 파일을 추출해 구조를 파악하고, 취약한 설정·하드코딩된 비밀번호·취약한 라이브러리 버전 등을 찾아내는 과정이다. 소프트웨어 분석과 달리 소스 코드가 없는 상태에서 바이너리만으로 분석해야 한다.

**왜 배우는가:**
```
[펌웨어 분석으로 발견 가능한 취약점]

 펌웨어 바이너리 (.bin/.img)
        ↓
  binwalk로 파일시스템 추출
        ↓
 ┌──────────────────────────┐
 │ 발견 가능한 취약점 목록  │
 │  - 하드코딩된 비밀번호   │
 │  - 비활성화된 텔넷 서비스│
 │  - 오래된 OpenSSL 버전   │
 │  - 디버그 계정 (admin/  │
 │    admin, root/없음 등)  │
 │  - 개인키·인증서         │
 │  - 취약한 웹 인터페이스  │
 └──────────────────────────┘
```

### 핵심 개념 정리

```
[펌웨어 분석 주요 단계]

1. 획득 (Acquisition)
   - UART/JTAG로 실행 중인 기기에서 덤프
   - SPI 클립으로 플래시 칩 직접 읽기
   - 제조사 업데이트 서버에서 다운로드
   - MITM으로 OTA 업데이트 가로채기

2. 식별 (Identification)
   - file, binwalk -B 로 포맷 확인
   - 엔트로피 분석: 높음=암호화/압축, 낮음=평문

3. 추출 (Extraction)
   - binwalk -e : 자동 추출
   - unsquashfs : SquashFS 파일시스템 추출
   - jefferson : JFFS2 파일시스템 추출

4. 분석 (Analysis)
   - grep -r "password" : 하드코딩 자격증명 검색
   - strings : 바이너리 내 문자열 추출
   - readelf / objdump : ELF 바이너리 구조 분석

5. 에뮬레이션 (Emulation)
   - QEMU : ARM/MIPS 바이너리 실행
   - firmadyne/EMBA : 자동화 분석 프레임워크
```

### 필요한 도구 및 환경
- **binwalk**: 펌웨어 서명 스캔 및 추출 (`pip install binwalk`)
- **squashfs-tools**: `unsquashfs` 명령어로 파일시스템 추출
- **QEMU**: ARM/MIPS/MIPS64 아키텍처 에뮬레이션
- **firmwalker**: 펌웨어 내 민감 파일 자동 검색 스크립트
- **Ghidra / radare2**: 역어셈블/역컴파일 분석

### 기초 실습 예제
```python
import subprocess
import os
from pathlib import Path

def analyze_firmware(firmware_path: str, output_dir: str = "./extracted"):
    """펌웨어 파일의 기본 정보를 분석하고 추출을 시도한다."""

    fw = Path(firmware_path)
    if not fw.exists():
        print(f"[-] 파일 없음: {firmware_path}")
        return

    # 1단계: 파일 기본 정보
    print(f"[*] 파일 크기: {fw.stat().st_size:,} bytes")

    # 2단계: binwalk 서명 스캔
    print("\n[*] binwalk 서명 스캔 중...")
    result = subprocess.run(
        ['binwalk', str(fw)],
        capture_output=True, text=True
    )
    print(result.stdout)

    # 3단계: 엔트로피 분석
    print("[*] 엔트로피 분석 중 (암호화/압축 구간 탐지)...")
    subprocess.run(['binwalk', '-E', str(fw)])

    # 4단계: 자동 추출 (주의: 용량 클 수 있음)
    os.makedirs(output_dir, exist_ok=True)
    print(f"\n[*] {output_dir} 에 추출 시도...")
    subprocess.run(['binwalk', '-e', '-C', output_dir, str(fw)])

    # 5단계: 하드코딩 자격증명 검색
    print("\n[*] 민감 키워드 검색...")
    keywords = ['password', 'passwd', 'secret', 'admin', 'root', 'token']
    for kw in keywords:
        result = subprocess.run(
            ['grep', '-r', '-i', '--include=*', kw, output_dir],
            capture_output=True, text=True
        )
        if result.stdout:
            print(f"[!] '{kw}' 발견:\n{result.stdout[:200]}")

# 사용 예시 (합법적으로 취득한 펌웨어만 사용)
# analyze_firmware("router_firmware.bin")
```

---

## 1. binwalk 심화 분석

### 1.1 서명 스캔 및 엔트로피 분석

```bash
# 기본 서명 스캔
binwalk firmware.bin

# 엔트로피 분석 (암호화/압축 영역 식별)
binwalk -E firmware.bin
# 높은 엔트로피(>0.9) → 암호화 또는 압축 데이터
# 낮은 엔트로피(<0.5) → 평문 데이터, 파일시스템

# 상세 서명 스캔
binwalk -B --magic /usr/share/binwalk/magic/* firmware.bin

# 원시 압축 스트림 스캔
binwalk -z firmware.bin

# 특정 파일타입만 스캔
binwalk --include="filesystem" firmware.bin

# 오프셋 기반 분석
binwalk -O 0x100000 firmware.bin   # 특정 오프셋부터 시작

# CSV 출력
binwalk --csv firmware.bin > analysis.csv

# JSON 출력 (스크립팅 활용)
binwalk --log=binwalk_log.txt firmware.bin
```

### 1.2 파일시스템 추출

```bash
# 자동 재귀 추출 (권장)
binwalk -Me firmware.bin
# _firmware.bin.extracted/ 디렉터리 생성

# squashfs 수동 추출
binwalk firmware.bin | grep -i squash
# 예: 오프셋 0x100000 에서 squashfs 발견

dd if=firmware.bin of=squashfs.bin bs=1 skip=$((0x100000))
sudo unsquashfs squashfs.bin
# → squashfs-root/ 생성

# cramfs 추출
dd if=firmware.bin of=cramfs.bin bs=1 skip=$((0x200000)) count=$((0x100000))
mkdir cramfs_mount
sudo mount -t cramfs cramfs.bin cramfs_mount/

# JFFS2 추출
dd if=firmware.bin of=jffs2.bin bs=1 skip=$((0x300000))
modprobe mtdram total_size=32768 erase_size=64
modprobe mtdblock
sudo dd if=jffs2.bin of=/dev/mtd0
mkdir jffs2_mount
sudo mount -t jffs2 /dev/mtdblock0 jffs2_mount/

# YAFFS2 추출 (NAND 플래시)
sudo apt install -y unyaffs
unyaffs yaffs2.bin output_dir/

# ext2/ext3/ext4 추출
file firmware.bin
sudo mount -o loop,ro firmware_ext.bin /mnt/fw/

# UBI/UBIFS (임베디드 플래시)
sudo modprobe ubi mtd=0
sudo ubiattach /dev/ubi_ctrl -m 0
sudo mount -t ubifs /dev/ubi0_0 /mnt/ubifs/
```

### 1.3 멀티 파티션 펌웨어 분석

```bash
# 펌웨어 레이아웃 추출
binwalk -e firmware.bin

# 부트로더 분리
dd if=firmware.bin of=bootloader.bin bs=1 count=$((0x40000))

# 커널 + 루트fs 분리
dd if=firmware.bin of=kernel_rootfs.bin bs=1 skip=$((0x40000))

# TRX 헤더 분석 (Broadcom 라우터)
python3 - << 'EOF'
import struct
with open("firmware.bin", "rb") as f:
    magic, length, crc, version = struct.unpack("<4sIIH", f.read(14))
    offsets = struct.unpack("<3I", f.read(12))
    print(f"Magic: {magic}")
    print(f"Length: {length:#010x}")
    print(f"Version: {version}")
    for i, off in enumerate(offsets):
        if off:
            print(f"Partition {i+1} offset: {off:#010x}")
EOF

# Ubiquiti UNIFI 펌웨어 파싱
binwalk -e fwupdate.bin
# → header.tar.gz 내부에 kernel + rootfs

# Netgear .img 파싱
dd if=netgear.img of=fs.bin bs=1 skip=58  # 헤더 크기 확인 후 조정
```

---

## 2. Ghidra 정적 분석

### 2.1 Ghidra 자동화 스크립팅

```bash
# Ghidra headless 분석
GHIDRA_HOME=/opt/ghidra

# 프로젝트 생성 및 분석
$GHIDRA_HOME/support/analyzeHeadless \
  /tmp/ghidra_project MyProject \
  -import squashfs-root/usr/sbin/httpd \
  -postScript FindHardcodedSecrets.java \
  -scriptPath /opt/ghidra_scripts/ \
  -log /tmp/ghidra_analysis.log

# FindHardcodedSecrets.java 예시 스크립트 위치:
# $GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts/
```

```java
// FindHardcodedSecrets.java
// Ghidra 스크립트 — 하드코딩된 문자열 검색
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class FindHardcodedSecrets extends GhidraScript {

    private static final String[] PATTERNS = {
        "password", "passwd", "secret", "apikey", "api_key",
        "token", "credential", "admin", "root", "default",
        "private_key", "-----BEGIN", "Authorization",
    };

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        AddressFactory af = currentProgram.getAddressFactory();

        println("=== 하드코딩 크리덴셜 검색 시작 ===");

        for (String pattern : PATTERNS) {
            byte[] searchBytes = pattern.getBytes("UTF-8");
            Address start = af.getAddressSet().getMinAddress();
            Address found = mem.findBytes(start, searchBytes, null, true, monitor);

            while (found != null && !monitor.isCancelled()) {
                // 해당 주소 주변 문자열 추출
                String context = extractString(mem, found, 128);
                println(String.format("[%s] @ %s: %s",
                    pattern, found.toString(), context));

                // 참조 함수 찾기
                ReferenceManager refMgr = currentProgram.getReferenceManager();
                for (Reference ref : refMgr.getReferencesTo(found)) {
                    Function func = getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        println("  Referenced from: " + func.getName() +
                                " @ " + ref.getFromAddress());
                    }
                }

                found = mem.findBytes(
                    found.add(1), searchBytes, null, true, monitor
                );
            }
        }
    }

    private String extractString(Memory mem, Address addr, int maxLen) {
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < maxLen; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0) break;
                if (b >= 0x20 && b <= 0x7E) sb.append((char) b);
                else sb.append('.');
            }
        } catch (Exception ignored) {}
        return sb.toString();
    }
}
```

### 2.2 Ghidra Python 스크립트 (Jython)

```python
# Ghidra 내부 Script Manager에서 실행
# 파일: find_crypto_constants.py

from ghidra.program.model.listing import *
from ghidra.program.model.scalar import Scalar

# AES S-Box 첫 번째 값 (0x63)을 포함한 상수 블록 탐색
AES_SBOX_START = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]

def search_byte_sequence(target_bytes):
    mem = currentProgram.getMemory()
    needle = bytes(target_bytes)
    addr = currentProgram.getAddressFactory().getAddressSet().getMinAddress()
    
    results = []
    found = mem.findBytes(addr, needle, None, True, monitor)
    while found:
        results.append(found)
        found = mem.findBytes(found.add(1), needle, None, True, monitor)
    return results

hits = search_byte_sequence(AES_SBOX_START)
for h in hits:
    print(f"AES S-Box 의심 위치: {h}")
    func = getFunctionContaining(h)
    if func:
        print(f"  함수: {func.getName()}")
```

---

## 3. radare2 / r2 스크립팅

### 3.1 r2 커맨드라인 분석

```bash
# 바이너리 열기 (자동 분석)
r2 -A squashfs-root/usr/sbin/httpd

# 기본 정보
[0x00400000]> i      # 파일 정보
[0x00400000]> iI     # 파일 상세 정보
[0x00400000]> ii     # 임포트 목록
[0x00400000]> is     # 심볼 목록
[0x00400000]> iz     # 데이터 섹션 문자열
[0x00400000]> izz    # 전체 바이너리 문자열

# 함수 목록
[0x00400000]> afl    # 모든 함수
[0x00400000]> afl~strcmp    # strcmp 관련 함수 필터

# 특정 함수로 이동
[0x00400000]> s sym.check_password
[0x00400000]> pdf    # 함수 디스어셈블

# 교차 참조
[0x00400000]> axt 0x00401234   # 특정 주소를 참조하는 곳
[0x00400000]> axf 0x00401234   # 특정 주소에서 참조하는 곳

# 문자열 검색
[0x00400000]> / admin
[0x00400000]> / password

# 패턴 검색 (16진수)
[0x00400000]> /x 50617373776f7264  # "Password" hex

# 함수 그래프
[0x00400000]> VV    # 그래프 뷰
[0x00400000]> agf   # ASCII 그래프

# 바이너리 비교 (두 펌웨어 버전)
r2 -c "diff" -A firmware_v1.bin
[0x00000000]> r2diff firmware_v2.bin
```

### 3.2 r2pipe Python 스크립팅

```bash
pip3 install r2pipe
```

```python
#!/usr/bin/env python3
# r2_analyze.py - radare2 자동화 분석

import r2pipe
import json
import sys
from pathlib import Path


def analyze_binary(binary_path: str) -> dict:
    r2 = r2pipe.open(binary_path, flags=["-2"])  # stderr 억제
    try:
        r2.cmd("aaa")  # 전체 분석

        # 임포트 목록
        imports = json.loads(r2.cmd("iij") or "[]")

        # 위험 함수 사용 여부
        dangerous_funcs = [
            "strcpy", "strcat", "sprintf", "gets",
            "system", "popen", "execve", "execl",
        ]
        found_dangerous = [
            imp["name"] for imp in imports
            if any(d in imp.get("name", "") for d in dangerous_funcs)
        ]

        # 전체 문자열
        strings = json.loads(r2.cmd("izzj") or "[]")
        credential_strings = [
            s for s in strings
            if any(kw in s.get("string", "").lower()
                   for kw in ["password", "secret", "admin", "root", "key"])
        ]

        # 함수 목록
        functions = json.loads(r2.cmd("aflj") or "[]")

        return {
            "path": binary_path,
            "dangerous_imports": found_dangerous,
            "credential_strings": credential_strings[:20],
            "function_count": len(functions),
        }
    finally:
        r2.quit()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    result = analyze_binary(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False))
```

### 3.3 radare2 에뮬레이션 (ESIL)

```bash
# MIPS 바이너리 ESIL 에뮬레이션
r2 -A mips_binary

# ESIL 에뮬레이션 초기화
[0x00000000]> aei     # ESIL VM 초기화
[0x00000000]> aeim    # 스택 메모리 맵
[0x00000000]> aeip    # EIP를 현재 시크로 설정

# 단계별 실행
[0x00000000]> aes     # 단일 스텝
[0x00000000]> aes 10  # 10스텝 실행

# 레지스터 확인
[0x00000000]> aer     # 모든 레지스터
[0x00000000]> aer a0  # MIPS a0 레지스터
```

---

## 4. 하드코딩 크리덴셜 탐지

### 4.1 파일시스템 내 크리덴셜 검색

```bash
# 추출된 루트 파일시스템으로 이동
cd squashfs-root/

# /etc/passwd, /etc/shadow 확인
cat etc/passwd
cat etc/shadow

# 기본 크리덴셜 패턴 검색
grep -r "password" etc/ --include="*.conf" --include="*.cfg" -l
grep -r "passwd" etc/ -l
grep -rE "admin|root|default" etc/shadow

# 설정 파일에서 크리덴셜
grep -rE "(password|passwd|secret|token|key)\s*[=:]" \
  etc/ var/ usr/etc/ --include="*.conf" --include="*.cfg" \
  --include="*.ini" --include="*.xml" -h

# 바이너리에서 평문 비밀번호 검색
find . -type f -executable | while read f; do
  result=$(strings "$f" 2>/dev/null | grep -iE "password|passwd|secret" | head -3)
  if [ -n "$result" ]; then
    echo "=== $f ==="; echo "$result"
  fi
done

# Base64로 인코딩된 크리덴셜 탐색
grep -rE "[A-Za-z0-9+/]{20,}={0,2}" etc/ usr/etc/ \
  --include="*.conf" | while read line; do
  encoded=$(echo "$line" | grep -oE "[A-Za-z0-9+/]{20,}={0,2}" | head -1)
  decoded=$(echo "$encoded" | base64 -d 2>/dev/null | strings)
  if echo "$decoded" | grep -qiE "password|admin|secret"; then
    echo "가능한 Base64 크리덴셜: $encoded → $decoded"
  fi
done
```

### 4.2 cve-2020-9054 유사 취약점 패턴

```bash
# Zyxel 하드코딩 계정 패턴
grep -r "zyfwp\|PrOw" squashfs-root/
grep -r "supervisor\|1234\|admin" squashfs-root/etc/

# Netgear 알려진 기본 크리덴셜 탐지
grep -r "password\|Passw0rd\|netgear1" squashfs-root/

# 웹 인터페이스 PHP/CGI에서 하드코딩 체크
find squashfs-root/ -name "*.php" -o -name "*.cgi" | \
  xargs grep -lE "md5\(|sha1\(|strcmp\(" 2>/dev/null

# 인증 우회 패턴 탐지
grep -rE "strcmp.*password|memcmp.*passwd|strncmp.*secret" \
  squashfs-root/usr/sbin/ squashfs-root/usr/bin/
```

### 4.3 백도어 식별

```bash
# 바인드 셸 / 리버스 셸 패턴
grep -rE "/bin/sh|/bin/bash|nc -e|netcat|/dev/tcp" \
  squashfs-root/etc/init.d/ squashfs-root/etc/rc.d/

# crontab 백도어
cat squashfs-root/etc/crontab
ls squashfs-root/etc/cron*/

# 숨겨진 사용자 계정
awk -F: '$3 == 0 { print }' squashfs-root/etc/passwd  # UID 0 계정

# SUID 바이너리 (권한상승 벡터)
find squashfs-root/ -perm -4000 -type f 2>/dev/null

# 의심스러운 init 스크립트
grep -rE "wget|curl|tftp|nc |ncat" squashfs-root/etc/init.d/

# 패키지로 위장한 악성코드 (이름과 기능 불일치)
file squashfs-root/usr/bin/* | grep -v "ELF\|script\|POSIX"
```

---

## 5. Python 도구 — 펌웨어 엔트로피 분석 + 문자열 추출 CLI

```python
#!/usr/bin/env python3
"""
Firmware Entropy Analyzer & String Extractor

Usage:
    python3 firmware_analyzer.py -f firmware.bin
    python3 firmware_analyzer.py -f firmware.bin --entropy --plot
    python3 firmware_analyzer.py -f firmware.bin --strings --min-len 8
    python3 firmware_analyzer.py -f firmware.bin --strings --filter creds
    python3 firmware_analyzer.py -f firmware.bin --full --output report.json
    python3 firmware_analyzer.py -d squashfs-root/ --scan-dir
"""

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
import struct
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# 크리덴셜 관련 정규식 패턴
CRED_PATTERNS: dict[str, re.Pattern] = {
    "password":    re.compile(rb"(?i)pass(?:word|wd|phrase)[^\x00]{0,3}[=:\s]([^\x00\n]{4,64})"),
    "username":    re.compile(rb"(?i)(?:user(?:name)?|login|account)[^\x00]{0,3}[=:\s]([^\x00\n]{3,32})"),
    "api_key":     re.compile(rb"(?i)(?:api[-_]?key|apikey|access[-_]?key)[^\x00]{0,3}[=:\s]([^\x00\n]{8,64})"),
    "token":       re.compile(rb"(?i)(?:token|bearer|secret)[^\x00]{0,3}[=:\s]([^\x00\n]{8,128})"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "aws_key":     re.compile(rb"AKIA[0-9A-Z]{16}"),
    "url_creds":   re.compile(rb"https?://[^:@\s]{3,32}:[^@\s]{3,64}@"),
    "base64_blob": re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"),
    "md5_hash":    re.compile(rb"\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}"),
    "sha512_crypt": re.compile(rb"\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}"),
}

# 알려진 파일 매직 바이트
FILE_SIGNATURES: list[tuple[bytes, str, int]] = [
    (b"\x1f\x8b",             "gzip",          0),
    (b"\xfd7zXZ\x00",         "xz",            0),
    (b"BZh",                  "bzip2",         0),
    (b"\x27\x05\x19\x56",     "uImage",        0),
    (b"\x68\x73\x71\x73",     "squashfs-le",   0),
    (b"\x73\x71\x73\x68",     "squashfs-be",   0),
    (b"\x42\x43",             "cramfs",        0),
    (b"\x85\x19\x03\x20",     "jffs2-le",      0),
    (b"\x20\x03\x19\x85",     "jffs2-be",      0),
    (b"\x7fELF",              "ELF",           0),
    (b"MZ",                   "PE/DOS",        0),
    (b"\x89PNG",              "PNG",           0),
    (b"PK\x03\x04",           "ZIP",           0),
    (b"-----BEGIN ",          "PEM",           0),
]


@dataclass
class ChunkAnalysis:
    offset: int
    size: int
    entropy: float
    file_type: Optional[str]
    is_encrypted: bool
    is_compressed: bool


@dataclass
class StringMatch:
    offset: int
    length: int
    value: str
    category: str
    encoding: str


@dataclass
class FirmwareReport:
    path: str
    size: int
    md5: str
    sha256: str
    overall_entropy: float
    chunk_analyses: list[ChunkAnalysis] = field(default_factory=list)
    credential_matches: list[StringMatch] = field(default_factory=list)
    all_strings: list[StringMatch] = field(default_factory=list)
    embedded_signatures: list[dict] = field(default_factory=list)
    suspicious_sections: list[dict] = field(default_factory=list)


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_file_signature(data: bytes) -> Optional[str]:
    for magic, name, offset in FILE_SIGNATURES:
        if len(data) > offset + len(magic):
            if data[offset : offset + len(magic)] == magic:
                return name
    return None


def extract_strings(
    data: bytes,
    min_len: int = 6,
    encoding: str = "ascii",
) -> list[StringMatch]:
    results: list[StringMatch] = []
    if encoding == "ascii":
        pattern = re.compile(
            rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}"
        )
        for m in pattern.finditer(data):
            val = m.group().decode("ascii", errors="replace")
            results.append(StringMatch(
                offset=m.start(),
                length=len(m.group()),
                value=val,
                category="plain",
                encoding="ascii",
            ))
    elif encoding == "utf16le":
        # UTF-16 LE 문자열 추출
        i = 0
        while i < len(data) - 1:
            chars = []
            j = i
            while j + 1 < len(data):
                word = struct.unpack_from("<H", data, j)[0]
                if 0x20 <= word <= 0x7E:
                    chars.append(chr(word))
                    j += 2
                else:
                    break
            if len(chars) >= min_len:
                val = "".join(chars)
                results.append(StringMatch(
                    offset=i,
                    length=j - i,
                    value=val,
                    category="plain",
                    encoding="utf16le",
                ))
                i = j
            else:
                i += 1
    return results


def find_credential_patterns(
    data: bytes,
    chunk_offset: int = 0,
) -> list[StringMatch]:
    results: list[StringMatch] = []
    for category, pattern in CRED_PATTERNS.items():
        for m in pattern.finditer(data):
            try:
                val = m.group(0).decode("utf-8", errors="replace")
            except Exception:
                val = repr(m.group(0))
            results.append(StringMatch(
                offset=chunk_offset + m.start(),
                length=len(m.group(0)),
                value=val[:200],
                category=category,
                encoding="detected",
            ))
    return results


def analyze_chunk(
    data: bytes,
    offset: int,
    chunk_size: int = 4096,
) -> ChunkAnalysis:
    chunk = data[offset : offset + chunk_size]
    ent = calculate_entropy(chunk)
    ftype = detect_file_signature(chunk)
    return ChunkAnalysis(
        offset=offset,
        size=len(chunk),
        entropy=ent,
        file_type=ftype,
        is_encrypted=(ent > 7.5),
        is_compressed=(6.5 < ent <= 7.5),
    )


def analyze_firmware_chunks(
    data: bytes,
    chunk_size: int = 4096,
    workers: int = 4,
) -> list[ChunkAnalysis]:
    offsets = list(range(0, len(data), chunk_size))
    results: list[ChunkAnalysis] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(analyze_chunk, data, off, chunk_size): off
            for off in offsets
        }
        for future in concurrent.futures.as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:
                off = future_map[future]
                print(f"[!] 청크 분석 실패 offset={off}: {exc}", file=sys.stderr)

    return sorted(results, key=lambda c: c.offset)


def find_embedded_signatures(data: bytes) -> list[dict]:
    found: list[dict] = []
    for magic, name, _ in FILE_SIGNATURES:
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            found.append({
                "offset": idx,
                "hex_offset": hex(idx),
                "type": name,
                "entropy_at_offset": calculate_entropy(data[idx : idx + 512]),
            })
            pos = idx + 1
    return found


def scan_directory(
    root_path: str,
    workers: int = 4,
    min_str_len: int = 8,
) -> list[dict]:
    root = Path(root_path)
    files = [f for f in root.rglob("*") if f.is_file() and not f.is_symlink()]
    results: list[dict] = []

    INTERESTING_EXTS = {
        ".conf", ".cfg", ".ini", ".xml", ".json",
        ".sh", ".php", ".cgi", ".lua", ".py",
    }
    INTERESTING_PATHS = [
        "etc/", "var/", "usr/etc/", "tmp/",
    ]

    def scan_file(fpath: Path) -> dict:
        try:
            data = fpath.read_bytes()
        except (OSError, PermissionError) as exc:
            return {"path": str(fpath), "error": str(exc)}

        creds = find_credential_patterns(data)
        is_interesting = (
            fpath.suffix in INTERESTING_EXTS
            or any(p in str(fpath) for p in INTERESTING_PATHS)
            or len(creds) > 0
        )
        if not is_interesting:
            return {}

        return {
            "path": str(fpath),
            "size": len(data),
            "entropy": calculate_entropy(data),
            "credentials_found": len(creds),
            "credential_details": [asdict(c) for c in creds[:10]],
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_file, f): f for f in files}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result()
                if r:
                    results.append(r)
            except Exception as exc:
                print(f"[!] 파일 스캔 오류: {exc}", file=sys.stderr)

    return [r for r in results if r.get("credentials_found", 0) > 0
            or r.get("entropy", 0) > 7.0]


def plot_entropy(
    chunks: list[ChunkAnalysis],
    output_path: str,
    firmware_size: int,
) -> None:
    if not HAS_MATPLOTLIB:
        print("[!] matplotlib 미설치. 그래프 생성 건너뜀", file=sys.stderr)
        return

    offsets = [c.offset for c in chunks]
    entropies = [c.entropy for c in chunks]

    fig, ax = plt.subplots(figsize=(16, 4))
    ax.fill_between(offsets, entropies, alpha=0.6, color="steelblue")
    ax.axhline(y=7.5, color="red", linestyle="--", alpha=0.7, label="암호화 임계값 (7.5)")
    ax.axhline(y=6.5, color="orange", linestyle="--", alpha=0.7, label="압축 임계값 (6.5)")

    # 파일시스템 경계 표시
    for chunk in chunks:
        if chunk.file_type:
            ax.axvline(x=chunk.offset, color="green", alpha=0.5, linewidth=1)
            ax.text(chunk.offset, 7.8, chunk.file_type,
                    rotation=90, fontsize=8, color="green")

    ax.set_xlabel("파일 오프셋 (bytes)")
    ax.set_ylabel("엔트로피 (bits/byte)")
    ax.set_title(f"펌웨어 엔트로피 분석 (크기: {firmware_size / 1024 / 1024:.1f} MB)")
    ax.set_ylim(0, 8.5)
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"[+] 엔트로피 그래프 저장: {output_path}")


def compute_hashes(data: bytes) -> tuple[str, str]:
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Firmware Entropy Analyzer & String Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s -f firmware.bin
  %(prog)s -f firmware.bin --entropy --chunk-size 2048
  %(prog)s -f firmware.bin --strings --min-len 8 --filter creds
  %(prog)s -f firmware.bin --full --plot --output report.json
  %(prog)s -d squashfs-root/ --scan-dir -w 8
  %(prog)s -f firmware.bin --signatures
        """,
    )
    parser.add_argument(
        "-f", "--firmware",
        metavar="FILE",
        help="분석할 펌웨어 바이너리 경로",
    )
    parser.add_argument(
        "-d", "--directory",
        metavar="DIR",
        help="추출된 파일시스템 디렉터리 경로",
    )
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="청크별 엔트로피 분석 수행",
    )
    parser.add_argument(
        "--strings",
        action="store_true",
        help="문자열 추출 수행",
    )
    parser.add_argument(
        "--filter",
        choices=["creds", "all", "urls", "hashes"],
        default="creds",
        help="문자열 필터 유형 (기본: creds)",
    )
    parser.add_argument(
        "--signatures",
        action="store_true",
        help="내장 파일 서명 탐지",
    )
    parser.add_argument(
        "--scan-dir",
        action="store_true",
        help="디렉터리 전체 크리덴셜 스캔 (-d 와 함께 사용)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="전체 분석 수행 (entropy + strings + signatures)",
    )
    parser.add_argument(
        "--plot",
        action="store_true",
        help="엔트로피 그래프 PNG 생성",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=4096,
        metavar="N",
        help="엔트로피 분석 청크 크기 바이트 (기본: 4096)",
    )
    parser.add_argument(
        "--min-len",
        type=int,
        default=6,
        metavar="N",
        help="추출할 최소 문자열 길이 (기본: 6)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="결과를 JSON 파일로 저장",
    )
    parser.add_argument(
        "--plot-output",
        metavar="FILE",
        default="entropy_plot.png",
        help="엔트로피 그래프 출력 파일 (기본: entropy_plot.png)",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=4,
        metavar="N",
        help="병렬 워커 수 (기본: 4)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="상세 출력",
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    if not args.firmware and not args.directory:
        parser.error("-f/--firmware 또는 -d/--directory 가 필요합니다")

    report_data: dict = {}

    # 디렉터리 스캔 모드
    if args.directory and args.scan_dir:
        print(f"[*] 디렉터리 스캔: {args.directory}")
        dir_results = scan_directory(
            args.directory,
            workers=args.workers,
            min_str_len=args.min_len,
        )
        print(f"\n[+] 흥미로운 파일 {len(dir_results)}개 발견:\n")
        for r in dir_results:
            print(f"  {r['path']}")
            print(f"    크기: {r.get('size', 0)} bytes | "
                  f"엔트로피: {r.get('entropy', 0):.3f} | "
                  f"크리덴셜: {r.get('credentials_found', 0)}개")
            for cd in r.get("credential_details", [])[:3]:
                print(f"    [{cd['category']}] {cd['value'][:80]!r}")
        report_data["directory_scan"] = dir_results

    # 펌웨어 파일 분석
    if args.firmware:
        fw_path = Path(args.firmware)
        if not fw_path.exists():
            print(f"[!] 파일 없음: {fw_path}", file=sys.stderr)
            return 1

        print(f"[*] 펌웨어 로드: {fw_path} ({fw_path.stat().st_size / 1024:.1f} KB)")
        data = fw_path.read_bytes()
        md5, sha256 = compute_hashes(data)
        overall_entropy = calculate_entropy(data)

        print(f"    MD5   : {md5}")
        print(f"    SHA256: {sha256}")
        print(f"    전체 엔트로피: {overall_entropy:.4f} bits/byte")

        report_data["firmware"] = {
            "path": str(fw_path),
            "size": len(data),
            "md5": md5,
            "sha256": sha256,
            "overall_entropy": overall_entropy,
        }

        # 엔트로피 분석
        if args.entropy or args.full:
            print(f"\n[*] 청크 엔트로피 분석 (chunk={args.chunk_size}, workers={args.workers})")
            chunks = analyze_firmware_chunks(data, args.chunk_size, args.workers)
            high_entropy = [c for c in chunks if c.is_encrypted]
            mid_entropy  = [c for c in chunks if c.is_compressed]
            sig_chunks   = [c for c in chunks if c.file_type]

            print(f"    암호화 의심 청크: {len(high_entropy)}")
            print(f"    압축 의심 청크:   {len(mid_entropy)}")
            print(f"    서명 감지 청크:   {len(sig_chunks)}")

            if args.verbose:
                for c in sig_chunks:
                    print(f"      오프셋 {c.offset:#010x}: {c.file_type} "
                          f"(엔트로피={c.entropy})")

            if args.plot or args.full:
                plot_entropy(chunks, args.plot_output, len(data))

            report_data["chunks"] = [asdict(c) for c in chunks]

        # 서명 탐지
        if args.signatures or args.full:
            print("\n[*] 내장 파일 서명 탐지")
            sigs = find_embedded_signatures(data)
            for s in sigs:
                print(f"    {s['type']:20s} @ {s['hex_offset']} "
                      f"(엔트로피={s['entropy_at_offset']:.3f})")
            report_data["signatures"] = sigs

        # 문자열 추출
        if args.strings or args.full:
            print(f"\n[*] 문자열 추출 (min_len={args.min_len}, filter={args.filter})")
            if args.filter in ("creds", "all"):
                creds = find_credential_patterns(data)
                print(f"\n  [크리덴셜 패턴 {len(creds)}개 발견]")
                for c in creds[:30]:
                    print(f"    [{c.category}] @ {c.offset:#010x}: {c.value[:80]!r}")
                report_data["credentials"] = [asdict(c) for c in creds]

            if args.filter == "all":
                strings = extract_strings(data, min_len=args.min_len)
                print(f"\n  [전체 ASCII 문자열: {len(strings)}개]")
                if args.verbose:
                    for s in strings[:50]:
                        print(f"    {s.offset:#010x}: {s.value[:80]!r}")
                report_data["all_strings_count"] = len(strings)

    # JSON 출력
    if args.output and report_data:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(report_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] 보고서 저장: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. 알려진 취약 펌웨어 재현

### 6.1 CVE-2020-9054 (Zyxel NAS 하드코딩 계정)

```bash
# Zyxel NAS326 펌웨어에서 하드코딩 계정 추출
binwalk -e V5.21\(AAZF.7\)C0.bin
cd _V5.21\(AAZF.7\)C0.bin.extracted/squashfs-root/

# 하드코딩 계정 위치
cat etc/passwd | grep zyfwp
# zyfwp:$1$QNgcHkPb$4E0mEyFJXFhKqKh6UGAZ50:0:0::/home/zyfwp:/bin/sh

# 비밀번호 크랙 (알려진 평문: PrOw!aN_fXp)
echo '$1$QNgcHkPb$4E0mEyFJXFhKqKh6UGAZ50' > zyfwp_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zyfwp_hash.txt
```

### 6.2 CVE-2022-27255 (Realtek eCos UDP 스택 오버플로)

```bash
# Realtek SDK 펌웨어 추출 후 취약 함수 탐지
grep -r "SDP_Open\|SDP_ConnectedInd" squashfs-root/ 2>/dev/null

# r2로 스택 오버플로 패턴 탐지
r2 -A squashfs-root/bin/miniigd
[0x00000000]> afl~SDP
[0x00000000]> s sym.SDP_Open
[0x00000000]> pdf
# 취약 함수: gets() 또는 strcpy() 사용 확인
```

### 6.3 CVE-2021-35395 (Realtek SDK 다중 취약점)

```bash
# UPnP 서비스 분석
find squashfs-root/ -name "miniupnpd" -o -name "upnpd" | \
  xargs strings | grep -E "strcpy|sprintf|gets"

# 취약 HTTP 파라미터 처리 확인
r2 -A squashfs-root/usr/sbin/miniupnpd
[0x00000000]> / NewRemoteHost
[0x00000000]> axt 0x<발견된 주소>
```

---

## 7. 동적 분석 — QEMU 에뮬레이션

```bash
# MIPS 펌웨어 에뮬레이션
sudo apt install -y qemu-system-mips qemu-user-static

# chroot 환경 준비
cp /usr/bin/qemu-mipsel-static squashfs-root/usr/bin/
cp /usr/bin/qemu-mips-static squashfs-root/usr/bin/

# 특정 바이너리 직접 에뮬레이션
sudo chroot squashfs-root/ /usr/bin/qemu-mipsel-static \
  /bin/ls /

# 웹 서버 에뮬레이션 (네트워크 포함)
sudo chroot squashfs-root/ /usr/bin/qemu-mipsel-static \
  /usr/sbin/httpd &

# strace로 시스템 콜 추적
sudo chroot squashfs-root/ /usr/bin/qemu-mipsel-static \
  -strace /usr/sbin/httpd 2>&1 | grep -E "open|read|write|connect"

# Firmadyne를 이용한 전체 에뮬레이션
git clone https://github.com/firmata/firmatas
cd firmatas
./run.sh firmware.bin
```

---

## 8. 패치 비교 분석

```bash
# 두 펌웨어 버전의 바이너리 비교
# 방법 1: bindiff 활용 (Ghidra 플러그인)
# Ghidra → Tools → BinDiff

# 방법 2: r2 diff
r2diff firmware_v1/usr/sbin/httpd firmware_v2/usr/sbin/httpd

# 방법 3: Python bindiff 스크립트
python3 - << 'EOF'
import hashlib
from pathlib import Path

def compare_firmwares(dir1: str, dir2: str) -> None:
    p1, p2 = Path(dir1), Path(dir2)
    files1 = {f.relative_to(p1): f for f in p1.rglob("*") if f.is_file()}
    files2 = {f.relative_to(p2): f for f in p2.rglob("*") if f.is_file()}

    new_files = set(files2.keys()) - set(files1.keys())
    removed_files = set(files1.keys()) - set(files2.keys())
    common = set(files1.keys()) & set(files2.keys())

    changed = []
    for rel in common:
        h1 = hashlib.md5(files1[rel].read_bytes()).hexdigest()
        h2 = hashlib.md5(files2[rel].read_bytes()).hexdigest()
        if h1 != h2:
            changed.append(rel)

    print(f"신규 파일: {len(new_files)}")
    for f in sorted(new_files): print(f"  + {f}")
    print(f"\n삭제 파일: {len(removed_files)}")
    for f in sorted(removed_files): print(f"  - {f}")
    print(f"\n변경 파일: {len(changed)}")
    for f in sorted(changed): print(f"  ~ {f}")

compare_firmwares("squashfs-root-v1", "squashfs-root-v2")
EOF
```

---

<!-- detect-validate-34 -->
## 펌웨어 시크릿 노출 탐지와 빌드 검증

펌웨어 분석은 *추출·정적분석·하드코딩 크리덴셜·디버그 심볼*로 키·계정·취약점을 찾는다. 방어자는 **출하 이미지에 시크릿이 없고 빌드가 강화됐는지**를 검증해야 한다. 검증은 **소유 펌웨어 빌드**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| binwalk 추출 | 비암호화 파일시스템 | 이미지 서명·암호화 | 평문 squashfs 추출 |
| 하드코딩 크리덴셜 | 임베디드 비번/키 | 빌드 시 시크릿 스캔 | passwd/private key 문자열 |
| 디버그 심볼 | 빌드 메타 누출 | 릴리스 스트립 | 심볼/경로 잔존 |
| 알려진 CVE 컴포넌트 | 구버전 라이브러리 | SBOM·버전 게이트 | 취약 버전 문자열 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 펌웨어 이미지의 하드코딩 시크릿 — 키/계정/토큰 잔존
binwalk -e owned_firmware.bin 2>/dev/null && grep -rIiE 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|password=|api[_-]?key' _owned_firmware.bin.extracted/ | head
# 2) 알려진 취약 컴포넌트 버전 표면 — 임베디드 바이너리 버전 문자열
strings -n 6 _owned_firmware.bin.extracted/usr/sbin/dropbear 2>/dev/null | grep -iE 'dropbear|openssl|busybox' | head
```

> 펌웨어 강화는 *이미지에 비밀이 없는가*다 — "부팅된다"와 "private key·하드코딩 비번이 없고 디버그 심볼이 스트립되며 취약 버전이 없다"는 다르다. 소유 빌드에서 시크릿·버전 표면을 직접 확인한다([[61_Firmware_Hacking]], [[18_DevSecOps]], [[06_Malware_Analysis]]).

---

<a name="english"></a>

# 02 — Firmware Analysis

## 1. Advanced binwalk Analysis

### 1.1 Signature Scanning and Entropy Analysis

```bash
# Basic signature scan
binwalk firmware.bin
```

## Overview

Firmware analysis for hardware hacking shares many tools with IoT firmware analysis (see section 27/02), but hardware-specific considerations include:

- **Physical extraction methods**: SPI/JTAG/UART-based dumps
- **Proprietary formats**: Custom bootloaders, encrypted firmware
- **Diff analysis**: Comparing firmware versions to find changes and patches
- **QEMU emulation**: Running extracted binaries for dynamic analysis

## Key Analysis Steps

1. **Signature scan** with binwalk to identify components
2. **Entropy analysis** to detect encrypted/compressed regions
3. **Filesystem extraction** and mount
4. **Static analysis**: strings, Ghidra/radare2, checksec
5. **Firmware diff**: Compare versions to find security patches
6. **Dynamic analysis**: QEMU emulation, GDB debugging

## Firmware Diff Analysis

Comparing firmware versions is valuable for:
- Understanding what vulnerabilities were fixed
- Finding regression vulnerabilities
- Mapping security patch history

```python
# New files
print(f"New files: {len(new_files)}")
for f in sorted(new_files): print(f"  + {f}")
print(f"\nRemoved files: {len(removed_files)}")
for f in sorted(removed_files): print(f"  - {f}")
print(f"\nChanged files: {len(changed)}")
for f in sorted(changed): print(f"  ~ {f}")

compare_firmwares("squashfs-root-v1", "squashfs-root-v2")
```


<!-- detect-validate-34 -->
## Firmware Secret Exposure Detection and Build Validation

Firmware analysis finds keys, accounts, and bugs via *extraction, static analysis, hardcoded credentials, and debug symbols*. Defenders must verify **whether shipped images are free of secrets and the build is hardened**. Validate only on **owned firmware builds**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| binwalk extraction | Unencrypted filesystem | Sign/encrypt image | Plaintext squashfs extracted |
| Hardcoded credentials | Embedded password/key | Secret-scan at build | passwd/private key strings |
| Debug symbols | Build metadata leak | Strip release | Symbols/paths remain |
| Known-CVE component | Outdated library | SBOM, version gate | Vulnerable version string |

### Defense validation (verify directly)

```bash
# 1) Hardcoded secrets in owned firmware image — keys/accounts/tokens remaining
binwalk -e owned_firmware.bin 2>/dev/null && grep -rIiE 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|password=|api[_-]?key' _owned_firmware.bin.extracted/ | head
# 2) Known-vulnerable component version surface — embedded binary version strings
strings -n 6 _owned_firmware.bin.extracted/usr/sbin/dropbear 2>/dev/null | grep -iE 'dropbear|openssl|busybox' | head
```

> Firmware hardening is *whether the image is free of secrets* -- "it boots" differs from "no private key or hardcoded password, debug symbols stripped, no vulnerable versions". Confirm the secret/version surface on owned builds directly ([[61_Firmware_Hacking]], [[18_DevSecOps]], [[06_Malware_Analysis]]).
