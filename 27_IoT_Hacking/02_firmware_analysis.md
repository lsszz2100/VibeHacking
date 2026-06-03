> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 02. 펌웨어 분석 심화 (Firmware Analysis)

## 0. 초보자를 위한 개념 이해

### 펌웨어 분석이란?

펌웨어(Firmware)는 IoT 기기의 하드웨어를 제어하는 소프트웨어로, 기기의 ROM/플래시 메모리에 저장된다. 스마트폰의 OS처럼 기기 동작의 근본이 된다. 펌웨어 분석은 이 바이너리 파일을 추출·분해하여 하드코딩된 자격증명, 백도어, 취약한 라이브러리, 개인키 등 보안 취약점을 찾는 과정이다.

**왜 배우는가:**
```
펌웨어 분석으로 발견 가능한 취약점

[하드코딩된 자격증명]
  admin / supersecret123
  SSH 개인키 /etc/dropbear/dropbear_rsa_host_key
  → 모든 동일 모델 기기에 동일한 키 사용!

[취약한 라이브러리]
  OpenSSL 1.0.1e (CVE-2014-0160 Heartbleed 포함)
  BusyBox 1.22.1 (구버전, 알려진 취약점)

[디버그 인터페이스]
  루트 셸을 자동 실행하는 init 스크립트
  텔넷 데몬 기본 활성화
```

### 핵심 개념 정리

```
펌웨어 분석 흐름

[수집] → [구조 분석] → [파일시스템 추출] → [정적 분석] → [동적 분석]

도구별 역할:
  binwalk     - 펌웨어 구조 파악, 파일시스템 추출
  strings     - 바이너리에서 텍스트 문자열 추출
  Ghidra/IDA  - 바이너리 역어셈블/디컴파일
  QEMU        - 다른 아키텍처(MIPS, ARM) 에뮬레이션
  firmwalker  - 추출된 파일시스템에서 자격증명·키 자동 탐색
```

### 필요한 도구 및 환경
- **binwalk**: `pip install binwalk` 또는 `apt install binwalk`
- **strings**: GNU binutils 기본 포함
- **QEMU**: ARM/MIPS 에뮬레이션 (`apt install qemu-user-static`)
- **Ghidra**: NSA 오픈소스 역공학 도구 (ghidra.sre.org)

### 기초 실습 예제
```bash
# 1. binwalk로 펌웨어 구조 파악
binwalk firmware.bin

# 출력 예시:
# DECIMAL  HEXADECIMAL  DESCRIPTION
# 0        0x0          TRX firmware header
# 28       0x1C         LZMA compressed data
# 1048576  0x100000     Squashfs filesystem

# 2. 파일시스템 자동 추출
binwalk -e firmware.bin
# 추출 결과: _firmware.bin.extracted/ 디렉토리 생성

# 3. 하드코딩된 자격증명 탐색
cd _firmware.bin.extracted/squashfs-root/
grep -r "password" etc/ --include="*.conf" 2>/dev/null
grep -r "passwd" etc/ 2>/dev/null | grep -v "^Binary"
cat etc/passwd    # 계정 목록
cat etc/shadow    # 해시 (존재 시)

# 4. 개인키/인증서 탐색
find . -name "*.pem" -o -name "*.key" -o -name "*.crt" 2>/dev/null
strings $(find . -type f -name "*.bin") | grep "BEGIN RSA"
```

---

## 개요

펌웨어 분석은 IoT 보안 평가의 핵심이다. binwalk로 구조를 파악하고, 파일시스템을 추출한 뒤,
정적 분석(strings, Ghidra)과 동적 분석(QEMU 에뮬레이션)을 병행한다.
목표: 하드코딩된 자격증명, 개인키, 취약한 설정, 백도어 탐지.

---

## 1. 펌웨어 수집 경로

```bash
# 1. 공개 소스 — 제조사 웹사이트 다운로드
wget https://www.vendor.com/firmware/router_v1.0.bin

# 2. 기기 자체에서 추출 — UART/SSH 접근 후
dd if=/dev/mtd0 of=/tmp/firmware.bin bs=1M
# 또는
cat /proc/mtd                # MTD 파티션 목록 확인
dd if=/dev/mtdblock0 of=/tmp/boot.bin

# 3. OTA 업데이트 트래픽 캡처 (MITM)
mitmproxy --mode transparent --listen-port 8080
# Burp Suite로 HTTP OTA 업데이트 인터셉트

# 4. SPI 플래시 직접 덤프
flashrom -p ch341a_spi -r firmware_dump.bin
binwalk --dd='.*' firmware_dump.bin  # 모든 시그니처 추출

# 5. JTAG 메모리 덤프 (OpenOCD)
openocd -f interface/jlink.cfg -f target/at91sam9.cfg
# telnet localhost 4444
# > dump_image /tmp/full_dump.bin 0x20000000 0x4000000
```

---

## 2. binwalk 심화 분석

### 2.1 분석 단계별 명령어

```bash
# 단계 1: 파일 유형 및 구조 파악
binwalk firmware.bin

# 단계 2: 엔트로피 분석 (암호화 영역 = 높은 엔트로피)
binwalk --entropy firmware.bin
binwalk -E --save firmware.bin  # PNG 그래프 저장

# 단계 3: 16진수 + 원시 시그니처 스캔
binwalk --raw='\x68\x73\x71\x73' firmware.bin  # squashfs 매직바이트

# 단계 4: 추출 (DD 모드 — 모든 매칭 추출)
binwalk --dd='.*' firmware.bin

# 단계 5: 재귀 추출 (중첩 압축 처리)
binwalk -Me firmware.bin  # -M: 재귀, -e: 추출

# 단계 6: 특정 오프셋에서 수동 추출
dd if=firmware.bin bs=1 skip=1048576 of=squashfs.img
unsquashfs squashfs.img

# 로그 저장
binwalk -Me firmware.bin 2>&1 | tee binwalk_output.log
```

### 2.2 파일시스템별 처리

```bash
# SquashFS
unsquashfs -d ./squashfs_root squashfs.img
file squashfs.img
# 비표준 SquashFS (LZMA 압축, 수정된 매직)
sasquatch squashfs.img  # firmware-mod-kit의 sasquatch

# CramFS
fsck.cramfs cramfs.img
mount -o loop,ro cramfs.img /mnt/cramfs

# JFFS2 (NAND 플래시)
jefferson jffs2.img -d /tmp/jffs2_extracted

# YAFFS2
unyaffs yaffs2.img /tmp/yaffs2_extracted

# ext2/3/4
e2fsck -f ext4.img
mount -o loop,ro ext4.img /mnt/ext4

# UBIFS
ubireader_extract_images ubifs.img
ubireader_extract_files ubifs.img

# initramfs/cpio
mkdir /tmp/initramfs && cd /tmp/initramfs
zcat initramfs.cpio.gz | cpio -idmv
# 또는
cpio -idmv < initramfs.cpio

# 압축 유형 자동 판별
file firmware.bin
strings firmware.bin | grep -E "(squashfs|cramfs|jffs2|ext[234])"
```

---

## 3. 정적 분석

### 3.1 strings 분석

```bash
# 기본 strings 분석
strings -n 8 squashfs_root/bin/busybox | head -100

# 자격증명 패턴 검색
strings firmware.bin | grep -iE \
    "(password|passwd|secret|key|token|api_key|private)" | sort -u

# IP 주소 추출
strings firmware.bin | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u

# URL 추출
strings firmware.bin | grep -oE 'https?://[^\s"]+' | sort -u

# Base64 인코딩 데이터
strings firmware.bin | grep -oE '[A-Za-z0-9+/]{30,}={0,2}' | \
    while read b64; do
        decoded=$(echo "$b64" | base64 -d 2>/dev/null | strings -n 4)
        [ -n "$decoded" ] && echo "B64: $b64 → $decoded"
    done

# 파일시스템 내 모든 바이너리 strings 덤프
find squashfs_root/ -type f -executable | \
    xargs -I{} strings -n 8 {} 2>/dev/null | \
    grep -iE "(admin|root|pass|key|secret)" | sort -u
```

### 3.2 Ghidra 분석

```bash
# Ghidra headless 분석 (자동화)
$GHIDRA_HOME/support/analyzeHeadless \
    /tmp/ghidra_project MyProject \
    -import squashfs_root/usr/sbin/httpd \
    -postScript PrintFunctionNames.java \
    -scriptPath /path/to/scripts \
    -deleteProject

# 일반적인 취약 함수 검색 스크립트 (Ghidra Python)
# GhidraScript로 system() / strcpy() / sprintf() 호출 탐색:
# from ghidra.app.script import GhidraScript
# refs = getReferencesTo(toAddr(0x...))

# radare2 대안
r2 -A squashfs_root/bin/busybox
# > afl            — 함수 목록
# > pdf @sym.main  — main 함수 디스어셈블
# > /ca system     — system() 호출 위치 검색
# > iz             — 문자열 목록

# rizin (radare2 포크)
rizin -A squashfs_root/usr/sbin/httpd
# > afl~http       — http 관련 함수
# > pdg @sym.handle_cgi  — Ghidra 스타일 디컴파일
```

### 3.3 인증서 및 키 탐지

```bash
# PEM 형식 키/인증서 탐색
grep -rl "BEGIN PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|BEGIN EC PRIVATE KEY" squashfs_root/

# SSH 호스트 키
find squashfs_root/ -name "ssh_host_*" -o -name "*.pem" -o -name "*.key"

# SSL 인증서
find squashfs_root/ -name "*.crt" -o -name "*.cer" -exec openssl x509 -in {} -text -noout \; 2>/dev/null

# 하드코딩된 AWS 자격증명
grep -rn "AKIA[0-9A-Z]{16}" squashfs_root/

# JWT 시크릿
grep -rn "jwt.secret\|JWT_SECRET\|jwt_key" squashfs_root/ --include="*.conf" --include="*.json" --include="*.lua"
```

---

## 4. 엔트로피 분석

```bash
# ent 도구로 엔트로피 측정
ent firmware.bin

# Shannon 엔트로피 계산 (Python 원라이너)
python3 -c "
import math, sys
data = open('firmware.bin','rb').read()
freq = {}
for b in data: freq[b] = freq.get(b,0)+1
n = len(data)
h = -sum((c/n)*math.log2(c/n) for c in freq.values())
print(f'엔트로피: {h:.4f} bits/byte')
print(f'최대: 8.0 bits/byte (완전 암호화/압축)')
print(f'분류: {\"암호화됨\" if h > 7.5 else \"압축됨\" if h > 6.5 else \"평문/구조적\"}')"
```

---

## 5. Python CLI 도구 — 펌웨어 자동 분석기

```python
#!/usr/bin/env python3
"""
Firmware Auto-Analyzer — binwalk 래퍼 + 하드코딩 자격증명 탐지
사용법: python3 firmware_analyzer.py analyze --firmware router.bin --output /tmp/results
"""

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── 데이터 클래스 ─────────────────────────────────────────────────────────────

@dataclass
class CredentialFinding:
    file_path: str
    line_number: int
    pattern_name: str
    matched_text: str
    context: str
    severity: str  # critical / high / medium / low
    confidence: float  # 0.0 ~ 1.0


@dataclass
class EntropyBlock:
    offset: int
    size: int
    entropy: float
    classification: str  # encrypted / compressed / plaintext / structured


@dataclass
class BinwalkResult:
    offset: int
    hex_offset: str
    description: str
    size: Optional[int] = None


@dataclass
class FirmwareAnalysisReport:
    firmware_path: str
    file_size: int
    sha256: str
    md5: str
    overall_entropy: float
    entropy_classification: str
    binwalk_findings: list[BinwalkResult] = field(default_factory=list)
    extracted_paths: list[str] = field(default_factory=list)
    credential_findings: list[CredentialFinding] = field(default_factory=list)
    private_keys: list[str] = field(default_factory=list)
    urls_found: list[str] = field(default_factory=list)
    ips_found: list[str] = field(default_factory=list)
    entropy_blocks: list[EntropyBlock] = field(default_factory=list)
    risk_summary: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ── 엔트로피 분석기 ───────────────────────────────────────────────────────────

class EntropyAnalyzer:
    BLOCK_SIZE = 256  # bytes per analysis block

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq: dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def classify_entropy(h: float) -> str:
        if h > 7.5:
            return "encrypted"
        elif h > 6.5:
            return "compressed"
        elif h > 4.0:
            return "structured"
        else:
            return "plaintext"

    def analyze_file(self, path: Path, sample_size: int = 8192) -> tuple[float, str]:
        try:
            data = path.read_bytes()
            # 고르게 샘플링
            if len(data) > sample_size:
                step = len(data) // sample_size
                sampled = bytes(data[i] for i in range(0, len(data), step))[:sample_size]
            else:
                sampled = data
            h = self.shannon_entropy(sampled)
            return h, self.classify_entropy(h)
        except OSError as exc:
            return 0.0, f"error: {exc}"

    def analyze_blocks(self, path: Path, block_size: int = 4096) -> list[EntropyBlock]:
        blocks: list[EntropyBlock] = []
        try:
            with open(path, "rb") as fp:
                offset = 0
                while True:
                    chunk = fp.read(block_size)
                    if not chunk:
                        break
                    h = self.shannon_entropy(chunk)
                    blocks.append(EntropyBlock(
                        offset=offset,
                        size=len(chunk),
                        entropy=round(h, 4),
                        classification=self.classify_entropy(h),
                    ))
                    offset += len(chunk)
        except OSError:
            pass
        return blocks


# ── 자격증명 탐지기 ───────────────────────────────────────────────────────────

class CredentialDetector:
    """파일시스템 내 하드코딩 자격증명 탐지"""

    PATTERNS: list[tuple[str, str, str, float]] = [
        # (이름, 패턴, 심각도, 신뢰도)
        ("hardcoded_password",
         r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})',
         "critical", 0.85),
        ("default_admin_cred",
         r'(?i)(?:admin|root|user)\s*[=:]\s*["\']?([^\s"\']{3,})',
         "high", 0.70),
        ("aws_access_key",
         r'AKIA[0-9A-Z]{16}',
         "critical", 0.99),
        ("aws_secret_key",
         r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+]{40})["\']',
         "critical", 0.95),
        ("private_key_pem",
         r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
         "critical", 0.99),
        ("jwt_secret",
         r'(?i)jwt.{0,10}secret\s*[=:]\s*["\']?([^\s"\']{8,})',
         "critical", 0.90),
        ("api_key_generic",
         r'(?i)api.?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',
         "high", 0.75),
        ("bearer_token",
         r'Bearer\s+([A-Za-z0-9\-._~+/]{20,})',
         "high", 0.80),
        ("hardcoded_ip_cred",
         r'(?i)(?:telnet|ssh|ftp)://([^:]+):([^@\s]+)@',
         "critical", 0.95),
        ("shadow_hash",
         r'(?:root|admin):[^:*!]{8,}:\d+:\d+',
         "critical", 0.90),
        ("base64_credential",
         r'(?i)(?:auth|credential|secret)\s*[=:]\s*["\']?([A-Za-z0-9+/]{20,}={0,2})',
         "medium", 0.60),
        ("mqtt_credential",
         r'(?i)mqtt.{0,20}(?:user|pass)\s*[=:]\s*["\']?([^\s"\']{4,})',
         "high", 0.80),
        ("snmp_community",
         r'(?i)community\s*[=:]\s*["\']?(public|private|community|admin|snmp)',
         "medium", 0.85),
        ("telnet_banner_cred",
         r'(?i)(?:login|password):\s*([^\n\r]{3,20})\s*(?:default|preset|factory)',
         "critical", 0.80),
    ]

    # 바이너리/텍스트 혼합 파일도 분석
    SKIP_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
        ".mp3", ".mp4", ".avi", ".so", ".ko", ".pyc",
    }

    def __init__(self, max_file_size: int = 10 * 1024 * 1024):
        self.max_file_size = max_file_size
        self._compiled = [
            (name, re.compile(pat, re.MULTILINE), sev, conf)
            for name, pat, sev, conf in self.PATTERNS
        ]

    def scan_file(self, path: Path) -> list[CredentialFinding]:
        if path.suffix.lower() in self.SKIP_EXTENSIONS:
            return []
        if path.stat().st_size > self.max_file_size:
            return []

        try:
            raw = path.read_bytes()
            # UTF-8 시도, 실패 시 latin-1
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
        except OSError:
            return []

        findings: list[CredentialFinding] = []
        lines = text.splitlines()

        for pat_name, compiled, severity, confidence in self._compiled:
            for match in compiled.finditer(text):
                # 라인 번호 계산
                line_no = text[:match.start()].count("\n") + 1
                context_start = max(0, line_no - 2)
                context_end = min(len(lines), line_no + 2)
                context = "\n".join(lines[context_start:context_end])

                # 화이트리스트 필터 (예: 플레이스홀더)
                matched = match.group(0)
                if any(ph in matched.lower() for ph in [
                    "your_password", "xxx", "changeme", "placeholder",
                    "${", "%(", "example", "todo", "fixme"
                ]):
                    confidence *= 0.3

                findings.append(CredentialFinding(
                    file_path=str(path),
                    line_number=line_no,
                    pattern_name=pat_name,
                    matched_text=matched[:200],
                    context=context[:500],
                    severity=severity,
                    confidence=round(confidence, 2),
                ))

        return findings

    def scan_directory(
        self, root: Path, workers: int = 4
    ) -> list[CredentialFinding]:
        all_files = [
            f for f in root.rglob("*")
            if f.is_file() and not f.is_symlink()
        ]
        print(f"  [*] {len(all_files)}개 파일 스캔 중 (워커: {workers})...")

        all_findings: list[CredentialFinding] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.scan_file, f): f for f in all_files}
            for fut in as_completed(futures):
                result = fut.result()
                all_findings.extend(result)

        # 신뢰도 낮은 결과 필터링
        return [f for f in all_findings if f.confidence >= 0.5]


# ── binwalk 래퍼 ──────────────────────────────────────────────────────────────

class BinwalkWrapper:
    """subprocess로 binwalk 실행 및 결과 파싱"""

    def __init__(self):
        if not shutil.which("binwalk"):
            print("[!] binwalk 미설치: sudo apt install binwalk", file=sys.stderr)
            sys.exit(1)

    def scan(self, firmware_path: Path) -> list[BinwalkResult]:
        cmd = ["binwalk", str(firmware_path)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
        except subprocess.TimeoutExpired:
            print("[!] binwalk 스캔 타임아웃", file=sys.stderr)
            return []
        except FileNotFoundError:
            print("[!] binwalk 실행 파일 없음", file=sys.stderr)
            return []

        return self._parse_output(result.stdout)

    def _parse_output(self, output: str) -> list[BinwalkResult]:
        results: list[BinwalkResult] = []
        # 헤더/공백 줄 건너뛰기
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("DECIMAL") or line.startswith("-"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                offset = int(parts[0])
                hex_off = parts[1]
                description = parts[2]
                results.append(BinwalkResult(
                    offset=offset,
                    hex_offset=hex_off,
                    description=description,
                ))
            except ValueError:
                continue
        return results

    def extract(self, firmware_path: Path, output_dir: Path) -> bool:
        cmd = [
            "binwalk",
            "--extract",
            "--matryoshka",     # 재귀 추출
            "--directory", str(output_dir),
            "--run-as=root",
            str(firmware_path),
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"[!] binwalk 추출 오류: {exc}", file=sys.stderr)
            return False

    def entropy_analysis(self, firmware_path: Path) -> str:
        cmd = ["binwalk", "--entropy", str(firmware_path)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""


# ── 추가 정적 분석 ────────────────────────────────────────────────────────────

class StaticAnalyzer:
    """추출된 파일시스템의 정적 분석"""

    URL_PATTERN = re.compile(r'https?://[^\s"\'<>]{10,}')
    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    PRIVATE_KEY_PATTERN = re.compile(
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
        r'.*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        re.DOTALL,
    )

    def find_private_keys(self, root: Path) -> list[str]:
        findings: list[str] = []
        for f in root.rglob("*"):
            if not f.is_file() or f.stat().st_size > 100_000:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
                if self.PRIVATE_KEY_PATTERN.search(text):
                    findings.append(str(f))
            except OSError:
                pass
        return findings

    def extract_urls(self, root: Path) -> list[str]:
        urls: set[str] = set()
        for f in root.rglob("*"):
            if not f.is_file() or f.stat().st_size > 5_000_000:
                continue
            try:
                text = f.read_bytes().decode("latin-1")
                for url in self.URL_PATTERN.findall(text):
                    urls.add(url[:300])
            except OSError:
                pass
        return sorted(urls)

    def extract_ips(self, root: Path) -> list[str]:
        ips: set[str] = set()
        SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "255.255.255.0"}
        for f in root.rglob("*"):
            if not f.is_file() or f.stat().st_size > 5_000_000:
                continue
            try:
                text = f.read_bytes().decode("latin-1")
                for ip in self.IP_PATTERN.findall(text):
                    if ip not in SKIP_IPS:
                        parts = ip.split(".")
                        if all(0 <= int(p) <= 255 for p in parts):
                            ips.add(ip)
            except (OSError, ValueError):
                pass
        return sorted(ips)

    def find_shadow_passwd(self, root: Path) -> list[str]:
        """passwd/shadow 파일 탐색"""
        targets = ["etc/passwd", "etc/shadow", "etc/shadow-", "etc/passwd-"]
        found: list[str] = []
        for rel in targets:
            candidate = root / rel
            if candidate.exists():
                found.append(str(candidate))
        return found


# ── 메인 분석기 ───────────────────────────────────────────────────────────────

class FirmwareAnalyzer:
    def __init__(self, workers: int = 4):
        self.workers = workers
        self.binwalk = BinwalkWrapper()
        self.entropy = EntropyAnalyzer()
        self.cred_detector = CredentialDetector()
        self.static = StaticAnalyzer()

    def _hash_file(self, path: Path) -> tuple[str, str]:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(path, "rb") as fp:
            for chunk in iter(lambda: fp.read(65536), b""):
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest(), md5.hexdigest()

    def analyze(
        self,
        firmware_path: Path,
        output_dir: Path,
        skip_extract: bool = False,
    ) -> FirmwareAnalysisReport:
        print(f"\n[펌웨어 분석 시작] {firmware_path.name}")
        print(f"{'='*60}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. 기본 정보
        print("[1/6] 기본 정보 수집...")
        file_size = firmware_path.stat().st_size
        sha256, md5 = self._hash_file(firmware_path)
        overall_entropy, entropy_class = self.entropy.analyze_file(firmware_path)

        report = FirmwareAnalysisReport(
            firmware_path=str(firmware_path),
            file_size=file_size,
            sha256=sha256,
            md5=md5,
            overall_entropy=round(overall_entropy, 4),
            entropy_classification=entropy_class,
        )

        print(f"  크기: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
        print(f"  SHA256: {sha256[:16]}...")
        print(f"  엔트로피: {overall_entropy:.4f} ({entropy_class})")

        # 2. binwalk 스캔
        print("[2/6] binwalk 구조 분석...")
        report.binwalk_findings = self.binwalk.scan(firmware_path)
        print(f"  발견: {len(report.binwalk_findings)}개 구조체")
        for bf in report.binwalk_findings[:10]:
            print(f"    0x{bf.hex_offset:>8} — {bf.description[:70]}")

        # 3. 엔트로피 블록 분석
        print("[3/6] 블록별 엔트로피 분석...")
        report.entropy_blocks = self.entropy.analyze_blocks(firmware_path, 4096)
        encrypted_blocks = [b for b in report.entropy_blocks if b.classification == "encrypted"]
        print(f"  총 블록: {len(report.entropy_blocks)}, 암호화 블록: {len(encrypted_blocks)}")

        # 4. 파일시스템 추출
        extract_dir = output_dir / "extracted"
        if not skip_extract:
            print("[4/6] 파일시스템 추출 (binwalk -Me)...")
            success = self.binwalk.extract(firmware_path, extract_dir)
            if success:
                extracted = [str(p) for p in extract_dir.rglob("*") if p.is_dir()]
                report.extracted_paths = extracted
                print(f"  추출 완료: {extract_dir}")
            else:
                print("  [!] 추출 실패 또는 추출 가능한 파일시스템 없음")
                report.errors.append("binwalk 추출 실패")
        else:
            print("[4/6] 추출 건너뜀 (--skip-extract)")
            if extract_dir.exists():
                report.extracted_paths = [str(extract_dir)]

        # 5. 자격증명 스캔
        print("[5/6] 하드코딩 자격증명 스캔...")
        scan_roots: list[Path] = []

        if extract_dir.exists():
            scan_roots.append(extract_dir)
        else:
            # 추출 실패 시 원본 펌웨어 strings 분석
            scan_roots.append(firmware_path.parent)

        for scan_root in scan_roots:
            if scan_root.is_dir():
                findings = self.cred_detector.scan_directory(
                    scan_root, workers=self.workers
                )
                report.credential_findings.extend(findings)

        # 심각도별 집계
        severity_counts: dict[str, int] = {}
        for cf in report.credential_findings:
            severity_counts[cf.severity] = severity_counts.get(cf.severity, 0) + 1
        report.risk_summary = severity_counts

        print(f"  자격증명 발견: {len(report.credential_findings)}개")
        for sev, cnt in sorted(severity_counts.items()):
            print(f"    {sev.upper():10}: {cnt}개")

        # 6. 정적 분석 (키, URL, IP)
        print("[6/6] 정적 분석 (키/URL/IP)...")
        if extract_dir.exists():
            report.private_keys = self.static.find_private_keys(extract_dir)
            report.urls_found = self.static.extract_urls(extract_dir)[:100]
            report.ips_found = self.static.extract_ips(extract_dir)[:100]
            shadow_files = self.static.find_shadow_passwd(extract_dir)
            if shadow_files:
                print(f"  [!] passwd/shadow 파일 발견: {shadow_files}")
                report.errors.extend([f"shadow/passwd: {p}" for p in shadow_files])

        print(f"  개인키 파일: {len(report.private_keys)}개")
        print(f"  URL: {len(report.urls_found)}개")
        print(f"  IP: {len(report.ips_found)}개")

        return report


# ── 출력 포맷터 ───────────────────────────────────────────────────────────────

def print_report(report: FirmwareAnalysisReport) -> None:
    print(f"\n{'='*70}")
    print(f"펌웨어 분석 리포트: {Path(report.firmware_path).name}")
    print(f"{'='*70}")
    print(f"파일 크기 : {report.file_size:,} bytes")
    print(f"SHA256    : {report.sha256}")
    print(f"MD5       : {report.md5}")
    print(f"엔트로피  : {report.overall_entropy} ({report.entropy_classification})")

    print(f"\n[binwalk 발견 ({len(report.binwalk_findings)}개)]")
    for bf in report.binwalk_findings[:20]:
        print(f"  0x{bf.hex_offset:>8} {bf.description[:65]}")

    if report.credential_findings:
        print(f"\n[하드코딩 자격증명 ({len(report.credential_findings)}개)]")
        for cf in sorted(report.credential_findings,
                          key=lambda x: x.severity, reverse=False)[:30]:
            print(f"  [{cf.severity.upper():8}] [{cf.confidence:.0%}] "
                  f"{cf.pattern_name}")
            print(f"           파일: {cf.file_path}")
            print(f"           라인: {cf.line_number}")
            print(f"           매칭: {cf.matched_text[:80]}")

    if report.private_keys:
        print(f"\n[개인 키 파일 ({len(report.private_keys)}개)] ← 즉시 교체 필요!")
        for pk in report.private_keys:
            print(f"  {pk}")

    if report.urls_found:
        print(f"\n[발견된 URL (최대 20개)]")
        for url in report.urls_found[:20]:
            print(f"  {url}")

    print(f"\n[위험 요약]")
    for sev in ["critical", "high", "medium", "low"]:
        cnt = report.risk_summary.get(sev, 0)
        if cnt:
            print(f"  {sev.upper():10}: {cnt}개")

    if report.errors:
        print(f"\n[오류/참고]")
        for e in report.errors:
            print(f"  - {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firmware_analyzer",
        description="펌웨어 자동 분석기 — binwalk + 자격증명 탐지",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze 서브커맨드
    p_analyze = sub.add_parser("analyze", help="펌웨어 전체 분석")
    p_analyze.add_argument("--firmware", required=True, help="펌웨어 파일 경로")
    p_analyze.add_argument("--output", default="/tmp/fw_analysis", help="결과 저장 디렉터리")
    p_analyze.add_argument("--workers", type=int, default=4, help="병렬 스캔 워커 수")
    p_analyze.add_argument("--skip-extract", action="store_true", help="파일시스템 추출 건너뜀")
    p_analyze.add_argument("--save-json", help="JSON 리포트 저장 경로")
    p_analyze.add_argument("--save-report", help="텍스트 리포트 저장 경로")

    # cred-scan 서브커맨드 (이미 추출된 디렉터리 대상)
    p_cred = sub.add_parser("cred-scan", help="디렉터리 자격증명 스캔만 실행")
    p_cred.add_argument("--directory", required=True, help="스캔할 루트 디렉터리")
    p_cred.add_argument("--workers", type=int, default=4)
    p_cred.add_argument("--min-confidence", type=float, default=0.5,
                        help="최소 신뢰도 필터 (0.0~1.0)")
    p_cred.add_argument("--output", choices=["text", "json"], default="text")
    p_cred.add_argument("--save", help="결과 저장 경로")

    # entropy 서브커맨드
    p_entropy = sub.add_parser("entropy", help="엔트로피 분석만 실행")
    p_entropy.add_argument("--firmware", required=True)
    p_entropy.add_argument("--block-size", type=int, default=4096)
    p_entropy.add_argument("--output", choices=["text", "json"], default="text")

    return parser


def cmd_analyze(args: argparse.Namespace) -> None:
    fw_path = Path(args.firmware)
    if not fw_path.exists():
        print(f"[!] 파일 없음: {fw_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output)
    analyzer = FirmwareAnalyzer(workers=args.workers)
    report = analyzer.analyze(fw_path, out_dir, skip_extract=args.skip_extract)
    print_report(report)

    if args.save_json:
        with open(args.save_json, "w", encoding="utf-8") as fp:
            json.dump(asdict(report), fp, ensure_ascii=False, indent=2)
        print(f"\n[*] JSON 리포트 저장: {args.save_json}")

    if args.save_report:
        # 텍스트 리포트를 파일로 저장
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(report)
        with open(args.save_report, "w", encoding="utf-8") as fp:
            fp.write(buf.getvalue())
        print(f"[*] 텍스트 리포트 저장: {args.save_report}")


def cmd_cred_scan(args: argparse.Namespace) -> None:
    root = Path(args.directory)
    if not root.is_dir():
        print(f"[!] 디렉터리 없음: {root}", file=sys.stderr)
        sys.exit(1)

    detector = CredentialDetector()
    findings = detector.scan_directory(root, workers=args.workers)
    findings = [f for f in findings if f.confidence >= args.min_confidence]

    if args.output == "json":
        print(json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2))
    else:
        print(f"\n[자격증명 스캔 결과] {len(findings)}개 발견")
        for f in sorted(findings, key=lambda x: x.severity):
            print(f"\n  [{f.severity.upper()}] {f.pattern_name} (신뢰도: {f.confidence:.0%})")
            print(f"  파일: {f.file_path}:{f.line_number}")
            print(f"  매칭: {f.matched_text[:100]}")

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fp:
            json.dump([asdict(f) for f in findings], fp, ensure_ascii=False, indent=2)
        print(f"\n[*] 결과 저장: {args.save}")


def cmd_entropy(args: argparse.Namespace) -> None:
    fw_path = Path(args.firmware)
    if not fw_path.exists():
        print(f"[!] 파일 없음: {fw_path}", file=sys.stderr)
        sys.exit(1)

    analyzer = EntropyAnalyzer()
    overall, classification = analyzer.analyze_file(fw_path)
    blocks = analyzer.analyze_blocks(fw_path, args.block_size)

    if args.output == "json":
        data = {
            "file": str(fw_path),
            "overall_entropy": round(overall, 4),
            "classification": classification,
            "blocks": [asdict(b) for b in blocks],
        }
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(f"파일: {fw_path.name}")
        print(f"전체 엔트로피: {overall:.4f} bits/byte ({classification})")
        print(f"블록 수: {len(blocks)}")
        by_class: dict[str, int] = {}
        for b in blocks:
            by_class[b.classification] = by_class.get(b.classification, 0) + 1
        for cls, cnt in sorted(by_class.items()):
            pct = cnt / len(blocks) * 100 if blocks else 0
            print(f"  {cls:12}: {cnt:5}블록 ({pct:5.1f}%)")

        # 암호화 영역 위치 출력
        encrypted = [b for b in blocks if b.classification == "encrypted"]
        if encrypted:
            print(f"\n암호화 블록 위치 (처음 10개):")
            for b in encrypted[:10]:
                print(f"  오프셋 0x{b.offset:08X} ~ 0x{b.offset+b.size:08X} "
                      f"(엔트로피: {b.entropy:.4f})")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    dispatch = {
        "analyze": cmd_analyze,
        "cred-scan": cmd_cred_scan,
        "entropy": cmd_entropy,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
```

---

## 6. 실행 예시

```bash
# 설치
pip install binwalk  # 또는 sudo apt install binwalk

# 전체 펌웨어 분석 (추출 + 자격증명 스캔 + 정적 분석)
python3 firmware_analyzer.py analyze \
    --firmware /tmp/router_v2.3.bin \
    --output /tmp/fw_results \
    --workers 8 \
    --save-json /tmp/fw_report.json

# 이미 추출된 디렉터리만 자격증명 스캔
python3 firmware_analyzer.py cred-scan \
    --directory /tmp/fw_results/extracted \
    --workers 4 \
    --min-confidence 0.7 \
    --output text \
    --save /tmp/creds.json

# 엔트로피 분석만 (블록 크기 1024 bytes)
python3 firmware_analyzer.py entropy \
    --firmware /tmp/encrypted_fw.bin \
    --block-size 1024 \
    --output json > entropy_report.json

# 결과 JSON에서 critical 항목만 추출
python3 -c "
import json
with open('/tmp/fw_report.json') as f:
    r = json.load(f)
crits = [c for c in r['credential_findings'] if c['severity'] == 'critical']
print(f'Critical 자격증명: {len(crits)}개')
for c in crits:
    print(f'  {c[\"file_path\"]}:{c[\"line_number\"]} — {c[\"matched_text\"][:80]}')
"
```

---

## 7. 분석 워크플로 체크리스트

```
단계 1: 수집
□ 제조사 사이트에서 최신 펌웨어 다운로드
□ SHA256/MD5 해시 기록
□ 파일 유형 확인 (file firmware.bin)

단계 2: 구조 분석
□ binwalk 스캔 — 파일시스템 유형, 압축 방식
□ 엔트로피 분석 — 암호화/압축 영역 식별
□ 16진수 뷰어로 매직바이트 확인

단계 3: 추출
□ binwalk -Me 실행
□ 추출된 파일시스템 유형 확인 (squashfs/cramfs/jffs2)
□ 수동 마운트 시도 (자동 추출 실패 시)

단계 4: 정적 분석
□ etc/passwd, etc/shadow 내용 확인
□ 웹 서버 설정 파일 (httpd.conf, nginx.conf)
□ 네트워크 설정 (ifconfig, ip 스크립트)
□ 시작 스크립트 (init.d/*, rc.local)

단계 5: 자격증명 탐지
□ strings + grep으로 password 패턴 검색
□ 개인키/인증서 파일 탐색
□ 하드코딩된 IP 주소 및 도메인
□ API 키 / JWT 시크릿

단계 6: 바이너리 분석
□ httpd / telnetd / sshd 바이너리 분석
□ Ghidra/radare2로 취약 함수 호출 탐색 (system, strcpy, sprintf)
□ command injection 취약점 (CGI 핸들러)

단계 7: 동적 분석
□ QEMU로 바이너리 에뮬레이션
□ firmwalker로 자동 파일 분석
□ FACT (Firmware Analysis and Comparison Tool) 활용
```

---

## 8. 유용한 보조 도구

```bash
# firmwalker — 자동 흥미 파일 탐색
git clone https://github.com/craigz28/firmwalker.git
cd firmwalker && bash firmwalker.sh /tmp/squashfs_root

# FACT — 웹 기반 펌웨어 분석 플랫폼
git clone https://github.com/fkie-cad/FACT_core
cd FACT_core && sudo ./install/install.sh

# EMBA — 임베디드 리눅스 분석기
git clone https://github.com/e-m-b-a/emba.git
cd emba && sudo ./emba.sh -f /tmp/firmware.bin -l /tmp/emba_log

# qemu-user-static으로 ARM 바이너리 실행
sudo apt install qemu-user-static
qemu-arm-static -L /tmp/squashfs_root /tmp/squashfs_root/usr/sbin/httpd

# checksec — 바이너리 보안 기능 확인
checksec --file=/tmp/squashfs_root/usr/sbin/httpd
# RELRO, STACK CANARY, NX, PIE, RPATH 확인

# strings + grep 자동화
strings -n 8 squashfs_root/usr/bin/cli | \
    grep -iE "(password|secret|admin|root|key)" | \
    sort -u > /tmp/cli_strings.txt
```

---

<a name="english"></a>

# 02. Advanced Firmware Analysis

## Overview

Firmware analysis is central to IoT security assessment. Understand the structure with binwalk, extract the filesystem, then combine static analysis (strings, Ghidra) with dynamic analysis (QEMU emulation). Goals: detect hardcoded credentials, private keys, weak configurations, and backdoors.

---

## 1. Firmware Collection Methods

```bash
# 1. Public source — download from vendor website
wget https://www.vendor.com/firmware/router_v1.0.bin

# 2. Extract from device — after UART/SSH access
dd if=/dev/mtd0 of=/tmp/firmware.bin bs=1M
# Or
cat /proc/mtd                # Check MTD partition list
dd if=/dev/mtdblock0 of=/tmp/boot.bin

# 3. Capture OTA update traffic (MITM)
mitmproxy --mode transparent --listen-port 8080
# Intercept HTTP OTA updates with Burp Suite

# 4. Direct SPI flash dump
flashrom -p ch341a_spi -r firmware_dump.bin
binwalk --dd='.*' firmware_dump.bin  # Extract all signatures

# 5. JTAG memory dump (OpenOCD)
openocd -f interface/jlink.cfg -f target/at91sam9.cfg
# telnet localhost 4444
# > dump_image /tmp/full_dump.bin 0x20000000 0x4000000
```

---

## 2. Advanced binwalk Analysis

### 2.1 Step-by-Step Analysis Commands

```bash
# Step 1: Identify file type and structure
binwalk firmware.bin

# Step 2: Entropy analysis (encrypted area = high entropy)
binwalk --entropy firmware.bin
binwalk -E --save firmware.bin  # Save PNG graph

# Step 3: Hex + raw signature scan
binwalk --raw='\x68\x73\x71\x73' firmware.bin  # squashfs magic bytes

# Step 4: Extraction (DD mode — extract all matches)
binwalk --dd='.*' firmware.bin

# Step 5: Recursive extraction (handle nested compression)
binwalk -Me firmware.bin  # -M: recursive, -e: extract

# Step 6: Manual extraction from specific offset
dd if=firmware.bin bs=1 skip=1048576 of=squashfs.img
unsquashfs squashfs.img

# Save log
binwalk -Me firmware.bin 2>&1 | tee binwalk_output.log
```

### 2.2 Handling Different Filesystems

```bash
# SquashFS
unsquashfs -d ./squashfs_root squashfs.img
file squashfs.img
# Non-standard SquashFS (LZMA compressed, modified magic)
sasquatch squashfs.img  # sasquatch from firmware-mod-kit

# CramFS
fsck.cramfs cramfs.img
mount -o loop,ro cramfs.img /mnt/cramfs

# JFFS2 (NAND flash)
jefferson jffs2.img -d /tmp/jffs2_extracted

# YAFFS2
unyaffs yaffs2.img /tmp/yaffs2_extracted

# ext2/3/4
e2fsck -f ext4.img
mount -o loop,ro ext4.img /mnt/ext4

# UBIFS
ubireader_extract_images ubifs.img
ubireader_extract_files ubifs.img

# initramfs/cpio
mkdir /tmp/initramfs && cd /tmp/initramfs
zcat initramfs.cpio.gz | cpio -idmv
# Or
cpio -idmv < initramfs.cpio

# Auto-detect compression type
file firmware.bin
strings firmware.bin | grep -E "(squashfs|cramfs|jffs2|ext[234])"
```

---

## 3. Static Analysis

### 3.1 strings Analysis

```bash
# Basic strings analysis
strings -n 8 squashfs_root/bin/busybox | head -100

# Search for credential patterns
strings firmware.bin | grep -iE \
    "(password|passwd|secret|key|token|api_key|private)" | sort -u

# Extract IP addresses
strings firmware.bin | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u

# Extract URLs
strings firmware.bin | grep -oE 'https?://[^\s"]+' | sort -u

# Base64 encoded data
strings firmware.bin | grep -oE '[A-Za-z0-9+/]{30,}={0,2}' | \
    while read b64; do
        decoded=$(echo "$b64" | base64 -d 2>/dev/null | strings -n 4)
        [ -n "$decoded" ] && echo "B64: $b64 → $decoded"
    done

# Dump strings from all binaries in filesystem
find squashfs_root/ -type f -executable | \
    xargs -I{} strings -n 8 {} 2>/dev/null | \
    grep -iE "(admin|root|pass|key|secret)" | sort -u
```

### 3.2 Ghidra Analysis

```bash
# Ghidra headless analysis (automated)
$GHIDRA_HOME/support/analyzeHeadless \
    /tmp/ghidra_project MyProject \
    -import squashfs_root/usr/sbin/httpd \
    -postScript PrintFunctionNames.java \
    -scriptPath /path/to/scripts \
    -deleteProject

# Search for common vulnerable functions (Ghidra Python)
# Find system() / strcpy() / sprintf() calls via GhidraScript:
# from ghidra.app.script import GhidraScript
# refs = getReferencesTo(toAddr(0x...))

# radare2 alternative
r2 -A squashfs_root/bin/busybox
# > afl            — function list
# > pdf @sym.main  — disassemble main function
# > /ca system     — find system() call locations
# > iz             — string list

# rizin (radare2 fork)
rizin -A squashfs_root/usr/sbin/httpd
# > afl~http       — http-related functions
# > pdg @sym.handle_cgi  — Ghidra-style decompile
```

### 3.3 Certificate and Key Detection

```bash
# Search for PEM-format keys/certificates
grep -rl "BEGIN PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|BEGIN EC PRIVATE KEY" squashfs_root/

# SSH host keys
find squashfs_root/ -name "ssh_host_*" -o -name "*.pem" -o -name "*.key"

# SSL certificates
find squashfs_root/ -name "*.crt" -o -name "*.cer" -exec openssl x509 -in {} -text -noout \; 2>/dev/null

# Hardcoded AWS credentials
grep -rn "AKIA[0-9A-Z]{16}" squashfs_root/

# JWT secrets
grep -rn "jwt.secret\|JWT_SECRET\|jwt_key" squashfs_root/ --include="*.conf" --include="*.json" --include="*.lua"
```

---

## 4. Entropy Analysis

```bash
# Measure entropy with ent tool
ent firmware.bin

# Calculate Shannon entropy (Python one-liner)
python3 -c "
import math, sys
data = open('firmware.bin','rb').read()
freq = {}
for b in data: freq[b] = freq.get(b,0)+1
n = len(data)
h = -sum((c/n)*math.log2(c/n) for c in freq.values())
print(f'Entropy: {h:.4f} bits/byte')
print(f'Maximum: 8.0 bits/byte (fully encrypted/compressed)')
print(f'Classification: {\"encrypted\" if h > 7.5 else \"compressed\" if h > 6.5 else \"plaintext/structured\"}')"
```

---

## 6. Usage Examples

```bash
# Install
pip install binwalk  # or sudo apt install binwalk

# Full firmware analysis (extraction + credential scan + static analysis)
python3 firmware_analyzer.py analyze \
    --firmware /tmp/router_v2.3.bin \
    --output /tmp/fw_results \
    --workers 8 \
    --save-json /tmp/fw_report.json

# Credential scan on already-extracted directory
python3 firmware_analyzer.py cred-scan \
    --directory /tmp/fw_results/extracted \
    --workers 4 \
    --min-confidence 0.7 \
    --output text \
    --save /tmp/creds.json

# Entropy analysis only (block size 1024 bytes)
python3 firmware_analyzer.py entropy \
    --firmware /tmp/encrypted_fw.bin \
    --block-size 1024 \
    --output json > entropy_report.json

# Extract only critical items from result JSON
python3 -c "
import json
with open('/tmp/fw_report.json') as f:
    r = json.load(f)
crits = [c for c in r['credential_findings'] if c['severity'] == 'critical']
print(f'Critical credentials: {len(crits)}')
for c in crits:
    print(f'  {c[\"file_path\"]}:{c[\"line_number\"]} — {c[\"matched_text\"][:80]}')
"
```

---

## 7. Analysis Workflow Checklist

```
Step 1: Collection
□ Download latest firmware from vendor site
□ Record SHA256/MD5 hash
□ Verify file type (file firmware.bin)

Step 2: Structure Analysis
□ binwalk scan — filesystem type, compression method
□ Entropy analysis — identify encrypted/compressed regions
□ Check magic bytes with hex viewer

Step 3: Extraction
□ Run binwalk -Me
□ Verify extracted filesystem type (squashfs/cramfs/jffs2)
□ Try manual mounting (if automatic extraction fails)

Step 4: Static Analysis
□ Check etc/passwd, etc/shadow contents
□ Web server config files (httpd.conf, nginx.conf)
□ Network configuration (ifconfig, ip scripts)
□ Startup scripts (init.d/*, rc.local)

Step 5: Credential Detection
□ Search for password patterns with strings + grep
□ Search for private key/certificate files
□ Hardcoded IP addresses and domains
□ API keys / JWT secrets

Step 6: Binary Analysis
□ Analyze httpd / telnetd / sshd binaries
□ Search for vulnerable function calls with Ghidra/radare2 (system, strcpy, sprintf)
□ Command injection vulnerabilities (CGI handlers)

Step 7: Dynamic Analysis
□ Emulate binaries with QEMU
□ Automated file analysis with firmwalker
□ Use FACT (Firmware Analysis and Comparison Tool)
```

---

## 8. Useful Auxiliary Tools

```bash
# firmwalker — automated interesting file search
git clone https://github.com/craigz28/firmwalker.git
cd firmwalker && bash firmwalker.sh /tmp/squashfs_root

# FACT — web-based firmware analysis platform
git clone https://github.com/fkie-cad/FACT_core
cd FACT_core && sudo ./install/install.sh

# EMBA — embedded Linux analyzer
git clone https://github.com/e-m-b-a/emba.git
cd emba && sudo ./emba.sh -f /tmp/firmware.bin -l /tmp/emba_log

# Run ARM binaries with qemu-user-static
sudo apt install qemu-user-static
qemu-arm-static -L /tmp/squashfs_root /tmp/squashfs_root/usr/sbin/httpd

# checksec — check binary security features
checksec --file=/tmp/squashfs_root/usr/sbin/httpd
# Check RELRO, STACK CANARY, NX, PIE, RPATH

# strings + grep automation
strings -n 8 squashfs_root/usr/bin/cli | \
    grep -iE "(password|secret|admin|root|key)" | \
    sort -u > /tmp/cli_strings.txt
```
