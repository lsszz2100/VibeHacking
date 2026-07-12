> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# 포렌식 자동화 및 도구

## 1. 주요 포렌식 자동화 도구

### 1.1 Autopsy

Autopsy는 The Sleuth Kit(TSK) 기반의 오픈소스 디지털 포렌식 플랫폼이다. GUI 환경에서 디스크 이미지를 분석하고, 삭제된 파일 복구, 타임라인 분석, 키워드 검색, 해시 검증 등의 기능을 자동으로 수행한다.

주요 기능:
- 삭제된 파일 자동 복구
- 웹 아티팩트(브라우저 기록, 쿠키) 자동 추출
- 이메일 분석 및 첨부 파일 추출
- 해시 데이터베이스(NSRL) 대조로 알려진 파일 필터링
- 타임라인 시각화 (MAC times 기반)

```bash
# Autopsy CLI 모드 실행 예시
autopsy --nogui --case /cases/investigation01 --image /evidence/disk.dd
```

### 1.2 SIFT Workstation

SANS Institute가 제공하는 Ubuntu 기반 포렌식 분석 환경이다. Volatility, log2timeline, The Sleuth Kit, Plaso 등 핵심 포렌식 도구가 사전 구성되어 있다.

```bash
# SIFT 설치 (Ubuntu 20.04+)
sudo apt install -y curl
curl -Lo sift-cli https://github.com/teamdfir/sift-cli/releases/latest/download/sift-cli-linux
chmod +x sift-cli
sudo ./sift-cli install
```

### 1.3 KAPE (Kroll Artifact Parser and Extractor)

KAPE는 Windows 아티팩트를 빠르게 수집하고 파싱하는 도구다. Targets(수집 대상)와 Modules(파싱 모듈)을 조합해 자동화된 수집 파이프라인을 구성한다.

```bash
# KAPE 실행 예시 (Windows)
kape.exe --tsource C:\ --tdest D:\collected --target !SANS_Triage --mdest D:\parsed --module !EZParser
```

KAPE Targets 구조:
```
Targets/
  Compound/
    !SANS_Triage.tkape        # 트리아지 수집
  Windows/
    EventLogs.tkape           # 이벤트 로그
    Prefetch.tkape            # Prefetch 파일
    $MFT.tkape                # MFT 수집
```

---

## 2. 타임라인 분석 자동화 — log2timeline / Plaso

Plaso(log2timeline의 후속)는 다양한 로그와 아티팩트를 파싱해 통합 슈퍼타임라인을 생성한다.

### 2.1 기본 워크플로우

```bash
# 1단계: 이미지에서 타임라인 생성
log2timeline.py --storage-file timeline.plaso /evidence/disk.dd

# 2단계: 필터링 및 정렬
psort.py -o l2tcsv -w output.csv timeline.plaso

# 3단계: 특정 시간 범위 필터
psort.py -o l2tcsv -w filtered.csv timeline.plaso "date > '2025-01-01' AND date < '2025-06-01'"
```

### 2.2 특정 파서만 사용

```bash
# 레지스트리 + 이벤트 로그만 파싱
log2timeline.py --parsers winreg,winevtx --storage-file partial.plaso /evidence/disk.dd
```

### 2.3 타임라인 분석 기준점

| 이벤트 유형 | 포렌식 의미 |
|------------|------------|
| 파일 생성 시간 (B) | 최초 생성 또는 복사 시점 |
| 파일 수정 시간 (M) | 마지막 내용 변경 시점 |
| 파일 접근 시간 (A) | 마지막 열람 시점 |
| 파일 변경 시간 (C) | 메타데이터(권한/소유자) 변경 |

---

## 3. 해시 검증 및 체인 오브 커스터디 자동화

### 3.1 증거 무결성 검증 원칙

디지털 포렌식에서 **체인 오브 커스터디(Chain of Custody)**는 증거가 수집된 시점부터 분석, 법정 제출까지 모든 이동·처리 이력을 기록하는 절차다. 해시값은 이 무결성의 핵심 증거다.

```bash
# MD5, SHA1, SHA256 동시 계산
md5sum /evidence/disk.dd > hashes.txt
sha1sum /evidence/disk.dd >> hashes.txt
sha256sum /evidence/disk.dd >> hashes.txt

# dcfldd로 이미징과 동시에 해시 계산
dcfldd if=/dev/sdb hash=md5,sha256 hashlog=hash.log of=/evidence/disk.dd
```

### 3.2 체인 오브 커스터디 자동 기록

```python
import hashlib
import json
import datetime
from pathlib import Path

def compute_hashes(file_path: str) -> dict[str, str]:
    """파일의 MD5/SHA1/SHA256 해시를 계산한다."""
    algorithms = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    path = Path(file_path)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for algo in algorithms.values():
                algo.update(chunk)
    return {name: algo.hexdigest() for name, algo in algorithms.items()}

def create_custody_record(evidence_path: str, examiner: str, case_id: str) -> dict:
    """체인 오브 커스터디 레코드를 생성한다."""
    path = Path(evidence_path)
    hashes = compute_hashes(evidence_path)
    return {
        "case_id": case_id,
        "examiner": examiner,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "evidence": {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "hashes": hashes,
        },
        "events": [
            {
                "action": "acquired",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "note": "Initial acquisition hash verification",
            }
        ],
    }
```

---

## 4. Python 이미지 아티팩트 자동 추출 도구

아래 코드는 디스크 이미지 파일에서 자동으로 파일 시스템 아티팩트를 추출하는 CLI 도구다.

```python
#!/usr/bin/env python3
"""
forensics_extractor.py
디스크 이미지에서 포렌식 아티팩트를 자동 추출하는 도구.

사용법:
    python forensics_extractor.py --image disk.dd --output ./results
    python forensics_extractor.py --image disk.E01 --output ./results --format json
"""

import argparse
import hashlib
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── 핵심 유틸리티 ──────────────────────────────────────────────────────────────

def compute_sha256(file_path: Path) -> str:
    """파일의 SHA-256 해시를 반환한다."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: list[str], capture: bool = True) -> tuple[int, str, str]:
    """외부 명령을 실행하고 (returncode, stdout, stderr)를 반환한다."""
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


# ── 파티션 탐지 ────────────────────────────────────────────────────────────────

def list_partitions(image_path: Path) -> list[dict]:
    """mmls로 이미지의 파티션 목록을 반환한다."""
    rc, stdout, stderr = run_cmd(["mmls", str(image_path)])
    if rc != 0:
        logger.error("mmls 실패: %s", stderr.strip())
        return []

    partitions = []
    for line in stdout.splitlines():
        parts = line.split()
        # mmls 출력: 번호 타입 시작 끝 크기 설명
        if len(parts) >= 5 and parts[0].endswith(":"):
            try:
                partitions.append({
                    "index": int(parts[0].rstrip(":")),
                    "slot": parts[1],
                    "start": int(parts[2]),
                    "end": int(parts[3]),
                    "length": int(parts[4]),
                    "description": " ".join(parts[5:]) if len(parts) > 5 else "",
                })
            except ValueError:
                continue
    return partitions


# ── 파일 목록 수집 ─────────────────────────────────────────────────────────────

def list_files(image_path: Path, offset: int) -> list[dict]:
    """fls로 특정 파티션의 파일 목록을 반환한다."""
    rc, stdout, stderr = run_cmd([
        "fls", "-r", "-o", str(offset), str(image_path)
    ])
    if rc != 0:
        logger.warning("fls 오류 (offset=%d): %s", offset, stderr.strip())
        return []

    files = []
    for line in stdout.splitlines():
        # fls 출력: 타입/플래그 inode 파일명
        parts = line.split("\t", 1)
        if len(parts) == 2:
            meta, name = parts
            files.append({
                "meta": meta.strip(),
                "name": name.strip(),
                "deleted": "*" in meta,
            })
    return files


# ── 삭제 파일 추출 ─────────────────────────────────────────────────────────────

def extract_deleted_files(
    image_path: Path,
    offset: int,
    output_dir: Path,
) -> list[dict]:
    """삭제된 파일을 icat으로 복구하고 경로 목록을 반환한다."""
    files = list_files(image_path, offset)
    deleted = [f for f in files if f["deleted"]]
    recovered = []

    output_dir.mkdir(parents=True, exist_ok=True)

    for entry in deleted:
        meta = entry["meta"]
        # inode 번호 추출 (예: "d/d *123:")
        inode = None
        for part in meta.split():
            token = part.lstrip("*").rstrip(":")
            if token.isdigit():
                inode = token
                break
        if inode is None:
            continue

        safe_name = entry["name"].replace("/", "_")
        out_file = output_dir / f"recovered_{inode}_{safe_name}"

        rc, stdout, _ = run_cmd([
            "icat", "-o", str(offset), str(image_path), inode
        ])
        if rc == 0 and stdout:
            out_file.write_text(stdout)
            recovered.append({
                "inode": inode,
                "original_name": entry["name"],
                "recovered_path": str(out_file),
            })
            logger.info("복구: %s → %s", entry["name"], out_file.name)

    return recovered


# ── 문자열 추출 ────────────────────────────────────────────────────────────────

def extract_strings_from_image(
    image_path: Path,
    output_dir: Path,
    min_length: int = 8,
) -> Path:
    """이미지 전체에서 출력 가능한 문자열을 추출한다."""
    out_file = output_dir / "strings.txt"
    rc, stdout, _ = run_cmd(["strings", f"-n{min_length}", str(image_path)])
    if rc == 0:
        out_file.write_text(stdout)
        logger.info("문자열 추출 완료: %d 줄", stdout.count("\n"))
    return out_file


# ── 보고서 생성 ────────────────────────────────────────────────────────────────

def generate_report(
    image_path: Path,
    partitions: list[dict],
    recovered_files: list[dict],
    output_dir: Path,
    fmt: str,
) -> Path:
    """분석 결과를 JSON 또는 텍스트 보고서로 저장한다."""
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "image": {
            "path": str(image_path),
            "sha256": compute_sha256(image_path),
            "size_bytes": image_path.stat().st_size,
        },
        "partitions": partitions,
        "recovered_files_count": len(recovered_files),
        "recovered_files": recovered_files,
    }

    if fmt == "json":
        out_file = output_dir / "report.json"
        out_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        out_file = output_dir / "report.txt"
        lines = [
            "=== 포렌식 추출 보고서 ===",
            f"생성 시각  : {report['generated_at']}",
            f"이미지     : {report['image']['path']}",
            f"SHA-256    : {report['image']['sha256']}",
            f"크기       : {report['image']['size_bytes']:,} bytes",
            f"파티션 수  : {len(partitions)}",
            f"복구 파일  : {len(recovered_files)}개",
            "",
        ]
        for rf in recovered_files:
            lines.append(f"  [{rf['inode']}] {rf['original_name']} → {rf['recovered_path']}")
        out_file.write_text("\n".join(lines))

    logger.info("보고서 저장: %s", out_file)
    return out_file


# ── 메인 ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="디스크 이미지에서 포렌식 아티팩트를 자동 추출한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python forensics_extractor.py --image disk.dd --output ./results
  python forensics_extractor.py --image disk.E01 --output ./results --format json
  python forensics_extractor.py --image disk.dd --output ./out --partition 2
        """,
    )
    parser.add_argument(
        "--image", "-i",
        required=True,
        help="분석할 디스크 이미지 경로 (raw, E01 등)",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="결과 저장 디렉터리",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "text"],
        default="text",
        dest="format",
        help="보고서 형식 (기본: text)",
    )
    parser.add_argument(
        "--partition", "-p",
        type=int,
        default=None,
        help="분석할 파티션 인덱스 (미지정 시 모든 파티션)",
    )
    parser.add_argument(
        "--strings",
        action="store_true",
        help="이미지 전체 문자열 추출 포함",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    image_path = Path(args.image)
    if not image_path.exists():
        logger.error("이미지 파일을 찾을 수 없음: %s", args.image)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("이미지 분석 시작: %s", image_path)

    # 파티션 탐지
    partitions = list_partitions(image_path)
    logger.info("파티션 %d개 발견", len(partitions))

    # 분석 대상 파티션 필터
    if args.partition is not None:
        partitions = [p for p in partitions if p["index"] == args.partition]

    # 삭제 파일 복구
    all_recovered: list[dict] = []
    for part in partitions:
        if part["length"] < 2048:          # 너무 작은 파티션 건너뜀
            continue
        recovered_dir = output_dir / f"partition_{part['index']}"
        recovered = extract_deleted_files(image_path, part["start"], recovered_dir)
        all_recovered.extend(recovered)

    # 문자열 추출 (옵션)
    if args.strings:
        extract_strings_from_image(image_path, output_dir)

    # 보고서 생성
    generate_report(image_path, partitions, all_recovered, output_dir, args.format)
    logger.info("분석 완료. 결과: %s", output_dir)


if __name__ == "__main__":
    main()
```

---

## 5. 도구 비교표

| 도구 | 유형 | 강점 | 주요 용도 |
|------|------|------|----------|
| Autopsy | GUI/CLI | 직관적 인터페이스 | 종합 디스크 분석 |
| KAPE | CLI | 빠른 트리아지 | 현장 수집 자동화 |
| Plaso | CLI/Python | 멀티소스 타임라인 | 사건 재구성 |
| Volatility | CLI/Python | 메모리 분석 | RAM 아티팩트 |
| The Sleuth Kit | CLI | 저수준 파일시스템 | 스크립트 통합 |

---

## 6. 참고 자료

- libewf (Expert Witness Format 라이브러리): https://github.com/libyal/libewf

---

<!-- detect-validate-07 -->
## 포렌식 자동화 검증과 재현성

자동화 파이프라인은 *결과를 생성함*과 *법정에서 재현·신뢰 가능함*이 다르다. 분석자는 **각 함정이 어떤 결과를 낳는가**와 **입출력 무결성·도구 교차·재현 결정성을 실제로 검증했는가**를 확인해야 한다.

### 자동화 함정 → 영향 → 검증 방법 → 측정 신호

| 자동화 함정 | 영향 | 검증 방법 | 측정 신호 |
|---|---|---|---|
| 단일 도구 출력 맹신 | 파서 오류 전파 | 2개 도구 교차(plaso↔tsk) | 출력 불일치 행 |
| 무결성 미검증 파이프라인 | 증거 변조 미탐 | 입출력 sha256 매니페스트 | 해시 불일치 |
| 타임존/시계 오정렬 | 타임라인 왜곡 | UTC 정규화 검증 | 이벤트 시각 편차 |
| 재현 불가 스크립트 | 법정 신뢰성 결여 | 동일 입력 재실행 결정성 | 재실행 산출물 diff |

### 자동화 검증 (직접 확인)

```bash
# "생성됨"을 신뢰하지 말 것 — 입출력 무결성·도구 교차·재현 결정성을 측정(소유/허가 증거만)
sha256sum evidence/* > manifest.sha256 && sha256sum -c manifest.sha256   # 파이프라인 전후 무결성
# 단일 파서를 단정하지 말고 두 도구의 타임라인을 교차검증
log2timeline.py --status_view none plaso.dump disk.img >/dev/null 2>&1
fls -m / -r disk.img > body.txt
# 동일 입력 재실행 결정성: 두 번 돌린 산출물 해시가 같아야 재현 가능
diff <(sha256sum run1/timeline.csv | cut -d' ' -f1) <(sha256sum run2/timeline.csv | cut -d' ' -f1) && echo "reproducible"
```

> 자동화 결과가 "생성됨"과 "법정에서 재현·신뢰 가능함"은 다르다. 입출력 해시 매니페스트·도구 교차·재현 결정성을 검증하고, 단일 도구 출력을 단정하지 말아야 증거로 신뢰할 수 있다([[44_Incident_Response_DFIR]], [[10_Pentest_Methodology]], [[75_Red_Team_Reporting]]).

**최신 기법·통제 (2025–2026):**
- 자동 트리아지(KAPE·Velociraptor·Plaso)로 대규모 대응 — 검증: 자동 산출물이 수동 재현으로 확인되는가([[44_Incident_Response_DFIR]])
- 타임라인·아티팩트 상관 자동화 — 결론이 증거로 뒷받침되는지 확인

---

<a name="english"></a>
# Forensics Automation and Tools

## 1. Major Forensic Automation Tools

### 1.1 Autopsy

Autopsy is an open-source digital forensics platform built on The Sleuth Kit (TSK). It automates disk image analysis through a GUI, performing deleted file recovery, timeline analysis, keyword search, and hash verification.

Key features:
- Automatic deleted file recovery
- Web artifact extraction (browser history, cookies)
- Email analysis and attachment extraction
- Known-file filtering via NSRL hash database
- Timeline visualization based on MAC times

```bash
# Run Autopsy in CLI mode
autopsy --nogui --case /cases/investigation01 --image /evidence/disk.dd
```

### 1.2 SIFT Workstation

A Ubuntu-based forensic analysis environment provided by the SANS Institute. It comes pre-configured with Volatility, log2timeline, The Sleuth Kit, Plaso, and other core forensic tools.

```bash
# Install SIFT on Ubuntu 20.04+
sudo apt install -y curl
curl -Lo sift-cli https://github.com/teamdfir/sift-cli/releases/latest/download/sift-cli-linux
chmod +x sift-cli
sudo ./sift-cli install
```

### 1.3 KAPE (Kroll Artifact Parser and Extractor)

KAPE rapidly collects and parses Windows artifacts. It combines Targets (collection definitions) and Modules (parsing modules) to build automated collection pipelines.

```bash
# KAPE usage example (Windows)
kape.exe --tsource C:\ --tdest D:\collected --target !SANS_Triage --mdest D:\parsed --module !EZParser
```

---

## 2. Timeline Analysis Automation — log2timeline / Plaso

Plaso (successor to log2timeline) parses various logs and artifacts to create a unified super-timeline.

### 2.1 Basic Workflow

```bash
# Step 1: Generate timeline from image
log2timeline.py --storage-file timeline.plaso /evidence/disk.dd

# Step 2: Filter and sort
psort.py -o l2tcsv -w output.csv timeline.plaso

# Step 3: Filter by time range
psort.py -o l2tcsv -w filtered.csv timeline.plaso "date > '2025-01-01' AND date < '2025-06-01'"
```

### 2.2 Using Specific Parsers Only

```bash
# Parse only Registry + Event Logs
log2timeline.py --parsers winreg,winevtx --storage-file partial.plaso /evidence/disk.dd
```

### 2.3 Timeline Analysis Reference Points

| Event Type | Forensic Meaning |
|-----------|-----------------|
| File Birth time (B) | Initial creation or copy point |
| File Modified time (M) | Last content change |
| File Accessed time (A) | Last read access |
| File Changed time (C) | Metadata (permissions/owner) change |

---

## 3. Hash Verification and Chain of Custody Automation

### 3.1 Evidence Integrity Verification

In digital forensics, the **Chain of Custody** documents all movement and handling of evidence from collection through analysis to court submission. Hash values are the core proof of integrity.

```bash
# Compute MD5, SHA1, SHA256 simultaneously
md5sum /evidence/disk.dd > hashes.txt
sha1sum /evidence/disk.dd >> hashes.txt
sha256sum /evidence/disk.dd >> hashes.txt

# Image and hash simultaneously with dcfldd
dcfldd if=/dev/sdb hash=md5,sha256 hashlog=hash.log of=/evidence/disk.dd
```

### 3.2 Automated Chain of Custody Logging

```python
import hashlib
import json
import datetime
from pathlib import Path

def compute_hashes(file_path: str) -> dict[str, str]:
    """Compute MD5/SHA1/SHA256 hashes of a file."""
    algorithms = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    path = Path(file_path)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for algo in algorithms.values():
                algo.update(chunk)
    return {name: algo.hexdigest() for name, algo in algorithms.items()}

def create_custody_record(evidence_path: str, examiner: str, case_id: str) -> dict:
    """Create a chain of custody record."""
    path = Path(evidence_path)
    hashes = compute_hashes(evidence_path)
    return {
        "case_id": case_id,
        "examiner": examiner,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "evidence": {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "hashes": hashes,
        },
        "events": [
            {
                "action": "acquired",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "note": "Initial acquisition hash verification",
            }
        ],
    }
```

---

## 4. Python Image Artifact Extraction Tool

The code in Section 4 (Korean section) implements a full CLI tool for automated artifact extraction from disk images using `--image` and `--output` arguments. Key functions:

- `list_partitions()` — uses `mmls` to enumerate partitions
- `list_files()` — uses `fls` to list files including deleted entries
- `extract_deleted_files()` — uses `icat` to recover deleted file content
- `extract_strings_from_image()` — extracts printable strings
- `generate_report()` — produces JSON or plaintext report with SHA-256 integrity hash

```bash
# Usage
python forensics_extractor.py --image disk.dd --output ./results
python forensics_extractor.py --image disk.E01 --output ./results --format json
python forensics_extractor.py --image disk.dd --output ./out --partition 2 --strings
```

---

## 5. Tool Comparison

| Tool | Type | Strength | Primary Use |
|------|------|----------|------------|
| Autopsy | GUI/CLI | Intuitive interface | Comprehensive disk analysis |
| KAPE | CLI | Fast triage | Field collection automation |
| Plaso | CLI/Python | Multi-source timeline | Incident reconstruction |
| Volatility | CLI/Python | Memory analysis | RAM artifacts |
| The Sleuth Kit | CLI | Low-level filesystem | Script integration |

---

## 6. References

- libewf (Expert Witness Format library): https://github.com/libyal/libewf

<!-- detect-validate-07 -->
## Forensic Automation Validation and Reproducibility

An automation pipeline *producing results* differs from those results being *reproducible and trustworthy in court*. The analyst must confirm **what outcome each pitfall produces** and **whether I/O integrity, tool cross-check, and re-run determinism were actually validated**.

### Automation pitfall -> Impact -> Validation method -> Measured signal

| Automation pitfall | Impact | Validation method | Measured signal |
|---|---|---|---|
| Trusting a single tool output | Parser errors propagate | Cross two tools (plaso vs tsk) | Mismatched output rows |
| Integrity-unchecked pipeline | Tampering goes undetected | I/O sha256 manifest | Hash mismatch |
| Timezone/clock misalignment | Timeline distortion | Verify UTC normalization | Event-time skew |
| Non-reproducible script | Lacks legal trust | Re-run determinism on same input | Re-run output diff |

### Automation validation (verify directly)

```bash
# Do not trust "produced" — measure I/O integrity, tool cross-check, and re-run determinism (owned/authorized evidence only)
sha256sum evidence/* > manifest.sha256 && sha256sum -c manifest.sha256   # pre/post-pipeline integrity
# Do not trust a single parser — cross-validate timelines from two tools
log2timeline.py --status_view none plaso.dump disk.img >/dev/null 2>&1
fls -m / -r disk.img > body.txt
# Re-run determinism on identical input: output hashes from two runs must match to be reproducible
diff <(sha256sum run1/timeline.csv | cut -d' ' -f1) <(sha256sum run2/timeline.csv | cut -d' ' -f1) && echo "reproducible"
```

> Automation *producing* results differs from those results being *reproducible and trustworthy in court*. Validate I/O hash manifests, tool cross-checks, and re-run determinism, and never trust a single tool output, before relying on it as evidence ([[44_Incident_Response_DFIR]], [[10_Pentest_Methodology]], [[75_Red_Team_Reporting]]).
