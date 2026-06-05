> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 코드 난독화와 언패킹 (Obfuscation and Unpacking)

## 개념 소개

난독화는 코드를 "읽기 어렵게" 변환하는 기술입니다. 마치 암호 편지처럼, 원본 내용은 그대로지만 외부에서는 무슨 말인지 알 수 없게 만듭니다. 패커(Packer)는 실행 파일을 압축/암호화하여 분석을 어렵게 하고, 실행 시 메모리에서 복원합니다.

---

## 주요 난독화 기법

### 1. 패커 기반 난독화

| 패커 | 특징 | 탐지 방법 |
|---|---|---|
| UPX | 가장 흔한 오픈소스 패커 | 섹션명 `UPX0`, `UPX1` |
| MPRESS | .NET, PE 지원 | 엔트로피 > 7.0 |
| Themida | 상용 VM 기반 패커 | 복잡한 VM 코드 |
| ASPack | 고전 패커 | 높은 엔트로피 |

### 2. 코드 기반 난독화 기법

- **XOR 인코딩**: 각 바이트를 키값과 XOR → 간단하지만 널리 사용
- **ROL/ROR 인코딩**: 비트 회전으로 바이트 변환
- **삽입 죽은 코드(Junk Code)**: 실행되지 않는 무의미한 명령 삽입
- **스파게티 코드**: 무작위 JMP 명령으로 흐름 분산
- **VM 기반 난독화**: 자체 가상머신으로 명령 실행 (Themida, VMProtect)

### 3. 언패킹 방법론

**OEP (Original Entry Point) 찾기**:
1. 실행 파일을 디버거에서 실행
2. 스택 브레이크포인트 설정 (`ESP law`)
3. POPAD 이후 첫 JMP → OEP
4. OEP에서 메모리 덤프 → IAT 재구성

**IAT (Import Address Table) 재구성**:
- Scylla, ImportREC 도구 사용
- 메모리에서 실제 API 주소를 추적

---

## Python 실습: XOR/ROL 난독화 바이트 패턴 자동 탐지기

```python
#!/usr/bin/env python3
"""
바이너리 파일에서 XOR/ROL 난독화 패턴과 엔트로피를 분석하는 도구
"""

import argparse
import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class EntropyBlock:
    offset: int
    size: int
    entropy: float
    is_suspicious: bool


@dataclass
class XorPattern:
    key: int
    count: int
    sample_offsets: list[int] = field(default_factory=list)


@dataclass
class ObfuscationReport:
    file_path: Path
    file_size: int
    overall_entropy: float
    high_entropy_blocks: list[EntropyBlock] = field(default_factory=list)
    xor_patterns: list[XorPattern] = field(default_factory=list)
    rol_score: int = 0
    packer_signatures: list[str] = field(default_factory=list)


# 알려진 패커 시그니처
PACKER_SIGNATURES: dict[str, bytes] = {
    "UPX": b"UPX0",
    "UPX1": b"UPX1",
    "MPRESS": b"MPRESS1",
    "ASPack": b"\x60\xE8\x00\x00\x00\x00\x5D\x81",
}


def calculate_entropy(data: bytes) -> float:
    """Shannon 엔트로피를 계산합니다. 값이 높을수록 압축/암호화 가능성 높음."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum(
        (c / total) * math.log2(c / total) for c in counts.values() if c > 0
    )
    return round(entropy, 4)


def analyze_entropy_blocks(data: bytes, block_size: int = 256) -> list[EntropyBlock]:
    """파일을 블록으로 나누어 엔트로피를 분석합니다."""
    blocks: list[EntropyBlock] = []
    for offset in range(0, len(data), block_size):
        block = data[offset : offset + block_size]
        if len(block) < 16:
            continue
        entropy = calculate_entropy(block)
        blocks.append(
            EntropyBlock(
                offset=offset,
                size=len(block),
                entropy=entropy,
                is_suspicious=entropy > 7.0,
            )
        )
    return blocks


def detect_xor_encoding(data: bytes, sample_size: int = 4096) -> list[XorPattern]:
    """단일 바이트 XOR 키를 탐지합니다."""
    sample = data[:sample_size]
    patterns: list[XorPattern] = []

    # 각 XOR 키에 대해 디코딩 후 printable 비율 확인
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in sample)
        printable = sum(1 for b in decoded if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
        ratio = printable / len(decoded) if decoded else 0

        # 가독성이 높아지면 XOR 키 후보
        if ratio > 0.6:
            offsets: list[int] = []
            for i in range(min(len(sample), 100)):
                if sample[i] ^ key in range(0x20, 0x7F):
                    offsets.append(i)
            patterns.append(XorPattern(key=key, count=len(offsets), sample_offsets=offsets[:5]))

    return sorted(patterns, key=lambda p: p.count, reverse=True)[:5]


def detect_rol_pattern(data: bytes) -> int:
    """ROL(Rotate Left) 패턴 스코어를 반환합니다."""
    score = 0
    # x86 ROL 명령: 0xC0, 0xC1 (Grp2) + ModRM 패턴
    rol_opcodes = [bytes([0xC0]), bytes([0xC1, 0xC0]), bytes([0xD0]), bytes([0xD2])]
    for opcode in rol_opcodes:
        count = data.count(opcode)
        if count > 10:
            score += count
    return score


def detect_packer_signatures(data: bytes) -> list[str]:
    """알려진 패커 시그니처를 탐지합니다."""
    found: list[str] = []
    for name, sig in PACKER_SIGNATURES.items():
        if sig in data:
            found.append(name)
    return found


def analyze_file(file_path: Path) -> ObfuscationReport | None:
    """파일 전체를 분석합니다."""
    try:
        data = file_path.read_bytes()
    except OSError as e:
        print(f"[오류] {file_path}: {e}")
        return None

    report = ObfuscationReport(
        file_path=file_path,
        file_size=len(data),
        overall_entropy=calculate_entropy(data),
    )

    report.high_entropy_blocks = [
        b for b in analyze_entropy_blocks(data) if b.is_suspicious
    ]
    report.xor_patterns = detect_xor_encoding(data)
    report.rol_score = detect_rol_pattern(data)
    report.packer_signatures = detect_packer_signatures(data)

    return report


def print_report(report: ObfuscationReport, verbose: bool = False) -> None:
    """분석 결과를 출력합니다."""
    print(f"\n{'='*60}")
    print(f"파일: {report.file_path.name}  ({report.file_size:,} bytes)")
    print(f"전체 엔트로피: {report.overall_entropy:.4f} / 8.0")
    print(f"{'='*60}")

    # 엔트로피 판정
    if report.overall_entropy > 7.2:
        print("  → 고엔트로피: 패킹/암호화 강력 의심")
    elif report.overall_entropy > 6.5:
        print("  → 중간 엔트로피: 일부 압축 가능성")
    else:
        print("  → 낮은 엔트로피: 평문 코드일 가능성")

    if report.packer_signatures:
        print(f"\n[패커 시그니처] {', '.join(report.packer_signatures)}")

    if report.high_entropy_blocks:
        print(f"\n[고엔트로피 블록] {len(report.high_entropy_blocks)}개")
        if verbose:
            for blk in report.high_entropy_blocks[:5]:
                print(f"  오프셋 0x{blk.offset:08X}: 엔트로피 {blk.entropy:.3f}")

    if report.xor_patterns:
        top = report.xor_patterns[0]
        print(f"\n[XOR 키 후보] 0x{top.key:02X} (가독성 매칭 {top.count}개)")

    if report.rol_score > 50:
        print(f"\n[ROL 패턴] 스코어 {report.rol_score} - ROL 기반 난독화 가능성")

    verdict_score = (
        (1 if report.overall_entropy > 7.2 else 0)
        + len(report.packer_signatures)
        + (1 if len(report.high_entropy_blocks) > 3 else 0)
        + (1 if report.xor_patterns else 0)
    )
    print(f"\n종합 판정 점수: {verdict_score}/5")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="바이너리 난독화 패턴 분석기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="+", type=Path, help="분석할 파일")
    parser.add_argument("--verbose", "-v", action="store_true", help="상세 블록 정보 출력")
    args = parser.parse_args()

    for fp in args.files:
        if not fp.exists():
            print(f"[오류] 파일 없음: {fp}")
            continue
        report = analyze_file(fp)
        if report:
            print_report(report, verbose=args.verbose)


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **SOC 분석**: 수신된 악성 첨부 파일에서 패킹 여부 빠르게 판단
2. **멀웨어 분류**: 엔트로피 프로필 기반으로 패커 종류 자동 분류
3. **취약점 연구**: 상용 소프트웨어의 보호 레이어 이해

---

## 요약

| 기법 | 탐지 단서 | 분석 도구 |
|---|---|---|
| UPX 패킹 | 섹션명 `UPX0/1` | `upx -d` |
| XOR 인코딩 | 엔트로피 편차 | 수동 키 탐색 |
| VM 난독화 | 복잡한 디스패처 루프 | Themida 분석 플러그인 |
| 정크 코드 | 비율적으로 많은 JMP | IDA 그래프 분석 |

---

<a name="english"></a>

# Code Obfuscation and Unpacking

## Concept Overview

Obfuscation transforms code to make it "hard to read," like a coded letter — the content is intact but meaningless to outsiders. Packers compress or encrypt executables to hinder analysis, decompressing them in memory at runtime.

---

## Core Techniques

### Packer-Based Obfuscation

| Packer | Characteristics | Detection |
|---|---|---|
| UPX | Most common open-source | Section names `UPX0`, `UPX1` |
| MPRESS | .NET/PE support | Entropy > 7.0 |
| Themida | Commercial VM packer | Complex VM dispatcher |
| ASPack | Classic packer | High entropy sections |

### Code-Level Obfuscation

- **XOR encoding**: Each byte XOR'd with a key value
- **ROL/ROR encoding**: Byte transformation via bit rotation
- **Junk code insertion**: Non-executing meaningless instructions
- **Spaghetti code**: Random JMP instructions to scatter flow
- **VM-based**: Own virtual machine interprets custom opcodes

### Unpacking Methodology

**Finding OEP (Original Entry Point)**:
1. Run the file in a debugger
2. Set stack breakpoint (`ESP law`)
3. After POPAD, first JMP → OEP
4. Dump memory at OEP → reconstruct IAT

---

## Summary Table

| Technique | Detection Clue | Analysis Tool |
|---|---|---|
| UPX packing | Section names `UPX0/1` | `upx -d` |
| XOR encoding | Entropy variance | Manual key search |
| VM obfuscation | Complex dispatcher loop | Themida plugins |
| Junk code | Excessive JMP ratio | IDA graph view |
