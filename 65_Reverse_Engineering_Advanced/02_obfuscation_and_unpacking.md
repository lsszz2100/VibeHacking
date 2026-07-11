> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 코드 난독화와 언패킹 (Obfuscation and Unpacking)

## 실습 환경 준비

> 이 문서의 Python 예제는 대부분 **Python 3.10+ 표준 라이브러리**(엔트로피 계산 등)만으로 실행됩니다. 아래 도구는 실제 패킹 바이너리 언패킹 실습에 필요합니다.

```bash
# UPX 패킹/언패킹
sudo apt install upx-ucl

# Ghidra(역공학·디컴파일): https://ghidra-sre.org  (JDK 17+ 필요)
# Detect It Easy(패커/컴파일러 식별): https://github.com/horsicq/Detect-It-Easy
# Windows 동적 언패킹: x64dbg + Scylla(메모리 덤프/IAT 복원)
```

> ⚠️ **격리 필수**: 패킹된 샘플(특히 악성 의심)은 네트워크 차단된 VM/컨테이너에서만 다루세요.
> 🧪 연계 랩: `vhack lab start 02` (취약 바이너리로 정적/동적 분석 연습)

---

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

## 심화: 수동 언패킹 단계별 절차 (UPX 변종)

`upx -d`가 거부되는 변종(섹션명 변경·헤더 손상)은 디버거로 수동 덤프해야 합니다.

```
1. 진입점에서 PUSHAD 확인 (UPX 스텁 시작) → ESP 값 기록
2. ESP에 하드웨어 BP (4바이트, 쓰기→읽기) 설정
3. 실행(F9) → POPAD가 레지스터 복원하면서 BP 히트
4. 근처 첫 'JMP far' 또는 'JMP <낮은 주소>' → OEP로 점프
5. F7로 OEP 도착 → Scylla "Dump" → "IAT Autosearch" → "Fix Dump"
6. 재구성된 IAT로 정적 분석 가능
```

> **자동 덤프 한계**: VM 패커(Themida/VMProtect)는 OEP가 명확하지 않음. 이 경우 OEP 덤프 대신 행위 기반(API 호출 로그) 분석으로 전환한다.

---

## 엔트로피 판정 가이드

| 전체 엔트로피 | 해석 | 권장 조치 |
|---|---|---|
| < 6.0 | 평문 코드/데이터 | 일반 정적 분석 |
| 6.0 ~ 7.0 | 부분 압축·리소스 | 섹션별 엔트로피 재확인 |
| 7.0 ~ 7.2 | 패킹 의심 | 패커 시그니처 스캔 |
| > 7.2 | 압축/암호화 강력 의심 | 동적 언패킹 필요 |

> 주의: 엔트로피만으로 단정 금지. 정상 설치파일(이미 압축된 리소스)도 7.0을 넘는다. 반드시 섹션명·임포트 테이블과 교차 검증.

---

## 공격-방어 공방 매트릭스

| 보호 기법 (방어자) | 분석 방해 효과 | 분석가 대응 | 잔여 리스크 |
|---|---|---|---|
| UPX 단순 패킹 | 정적 문자열 은닉 | `upx -d` 또는 ESP law 덤프 | 낮음 |
| 섹션명 변조 UPX | 자동 언패커 무력화 | 수동 PUSHAD/POPAD 추적 | 중간 |
| XOR/ROL 스트링 암호화 | 문자열 정적 추출 차단 | 키 브루트포스 + 런타임 덤프 | 낮음 |
| 정크/스파게티 코드 | 그래프 가독성 저하 | 디컴파일러 + 데드코드 제거 | 중간 |
| VM 기반 (VMProtect) | 명령 의미 은폐 | 핸들러 추적·바이트코드 리프팅 | 높음 |
| 안티덤프(메모리 페이지 보호) | 메모리 덤프 차단 | 페이지 권한 패치 후 덤프 | 높음 |

---

## 빠른 자가진단 체크리스트

- [ ] 전체·섹션별 엔트로피를 측정하고 임계값과 비교했는가?
- [ ] 알려진 패커 시그니처(UPX0/1·MPRESS·ASPack)를 스캔했는가?
- [ ] 자동 언패킹(`upx -d`) 실패 시 ESP law 수동 덤프를 시도했는가?
- [ ] OEP 도달 후 IAT를 재구성(Scylla)했는가?
- [ ] VM 패커로 판단되면 행위 기반 분석으로 전환했는가?
- [ ] 언패킹 결과 바이너리에서 원본 문자열·임포트가 복원됐는지 확인했는가?

---

## 요약

| 기법 | 탐지 단서 | 분석 도구 |
|---|---|---|
| UPX 패킹 | 섹션명 `UPX0/1` | `upx -d` |
| XOR 인코딩 | 엔트로피 편차 | 수동 키 탐색 |
| VM 난독화 | 복잡한 디스패처 루프 | Themida 분석 플러그인 |
| 정크 코드 | 비율적으로 많은 JMP | IDA 그래프 분석 |
| 안티덤프 | 메모리 페이지 보호 | 페이지 권한 패치 |

---

<!-- detect-validate-65 -->
## 안티분석 탐지와 분석 검증

언패킹의 가장 흔한 실수는 "덤프를 떴다 = 끝났다"는 착각이다. **덤프가 실제로 원본인지**(OEP·IAT·문자열 복원)를 검증하지 않으면 깨진 바이너리를 분석하게 된다.

### 안티분석 → 통제 → 검증 → 통과 기준

| 우회 대상 | 적용 통제 | 검증 방법(직접 확인) | 통과 기준 |
|---|---|---|---|
| 패킹(UPX/ASPack) | `upx -d`·ESP law 덤프 | 덤프 엔트로피 재측정·문자열 추출 | 엔트로피 하락 + 평문 문자열 노출 |
| IAT 파괴 | Scylla로 IAT 재구성 | 임포트 테이블이 정상 모듈로 해석되는지 | API 이름이 정상 resolve |
| 안티덤프(페이지 보호) | 페이지 권한 패치 후 덤프 | 덤프본이 디스어셈블/실행되는지 | OEP에서 정상 디스어셈블 |

### 분석 검증 (직접 확인)

```bash
# 언패킹 전후 엔트로피·문자열로 '진짜 풀렸는지' 측정
python3 -c "import math,collections,sys; d=open(sys.argv[1],'rb').read(); \
c=collections.Counter(d); e=-sum(n/len(d)*math.log2(n/len(d)) for n in c.values()); \
print(f'{sys.argv[1]}: entropy={e:.2f}')" packed.bin unpacked.bin
strings -n 6 unpacked.bin | grep -iE 'http|reg|cmd|\.dll' | head
# 통과: unpacked의 엔트로피가 packed보다 뚜렷이 낮고 평문 API/문자열이 보임
# 실패: 엔트로피가 그대로면 덤프가 여전히 압축/암호화 상태 — 재언패킹 필요
```

> 검증은 **분석용 격리 환경에서만** 수행한다. "덤프했다"가 아니라 "원본 코드·임포트가 복원됐다"를 엔트로피·문자열·IAT로 확인해야 분석이 의미를 가진다([[06_Malware_Analysis]]).

**최신 기법·통제 (2025–2026):**
- 상용 프로텍터(VMProtect/Themida)·컨트롤플로우 평탄화·문자열 암호화가 표준 — 정적 언패킹 대신 심볼릭/컨콜릭 실행·에뮬레이션으로 원본 복원. 검증: 덤프 후 IAT 재구성·엔트로피 정상화·문자열 복원 여부 확인
- AI 보조 역난독화(디컴파일러 LLM 플러그인)가 실전화 — 자동 복원 결과는 반드시 동적 재현으로 교차검증(환각 방지)

---

<a name="english"></a>

# Code Obfuscation and Unpacking

## Lab Environment Setup

> Most Python examples here run on the **Python 3.10+ standard library** (entropy math, etc.). The tools below are for unpacking real packed binaries.

```bash
sudo apt install upx-ucl        # UPX pack/unpack
# Ghidra (decompiler): https://ghidra-sre.org  (JDK 17+)
# Detect It Easy (packer/compiler ID): https://github.com/horsicq/Detect-It-Easy
# Windows manual unpacking: x64dbg + Scylla (memory dump / IAT rebuild)
```

> ⚠️ **Isolation required**: handle packed (possibly malicious) samples only in a network-isolated VM/container.
> 🧪 Related lab: `vhack lab start 02`

---

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
| Anti-dump | Protected memory pages | Patch page permissions |

---

## Deep Dive: Manual Unpacking Steps (UPX Variant)

For variants where `upx -d` fails (renamed sections, corrupted header), dump manually in a debugger.

```
1. Confirm PUSHAD at entry (UPX stub start) → record ESP value
2. Set a hardware BP (4 bytes, write→read) on ESP
3. Run (F9) → BP hits when POPAD restores registers
4. The nearby first 'JMP far' or 'JMP <lower address>' → jumps to OEP
5. Step (F7) to OEP → Scylla "Dump" → "IAT Autosearch" → "Fix Dump"
6. Static analysis now possible with reconstructed IAT
```

> **Auto-dump limit**: VM packers (Themida/VMProtect) have no clear OEP. Switch to behavior-based (API call log) analysis instead of OEP dumping.

---

## Entropy Decision Guide

| Overall Entropy | Interpretation | Recommended Action |
|---|---|---|
| < 6.0 | Plaintext code/data | Normal static analysis |
| 6.0 ~ 7.0 | Partial compression / resources | Re-check per-section entropy |
| 7.0 ~ 7.2 | Packing suspected | Scan packer signatures |
| > 7.2 | Strong compression/encryption | Dynamic unpacking required |

> Caution: never conclude from entropy alone. Legitimate installers (already-compressed resources) also exceed 7.0. Always cross-check with section names and the import table.

---

## Attack–Defense Matrix

| Protection (Defender) | Analysis Impact | Analyst Response | Residual Risk |
|---|---|---|---|
| UPX simple packing | Hides static strings | `upx -d` or ESP-law dump | Low |
| Section-renamed UPX | Defeats auto-unpackers | Manual PUSHAD/POPAD trace | Medium |
| XOR/ROL string crypto | Blocks static extraction | Key brute force + runtime dump | Low |
| Junk/spaghetti code | Reduces graph readability | Decompiler + dead-code removal | Medium |
| VM-based (VMProtect) | Hides instruction meaning | Handler tracing / bytecode lifting | High |
| Anti-dump (page protection) | Blocks memory dump | Patch page permissions, then dump | High |

---

## Quick Self-Assessment Checklist

- [ ] Did you measure overall and per-section entropy against thresholds?
- [ ] Did you scan known packer signatures (UPX0/1, MPRESS, ASPack)?
- [ ] On `upx -d` failure, did you try a manual ESP-law dump?
- [ ] After reaching OEP, did you reconstruct the IAT (Scylla)?
- [ ] If identified as a VM packer, did you switch to behavior-based analysis?
- [ ] Did you verify original strings/imports were restored in the unpacked binary?

---

## Anti-Analysis Detection and Analysis Validation

The most common unpacking mistake is "I dumped it = done." Without verifying the dump is **actually the original** (OEP, IAT, restored strings), you end up analyzing a broken binary.

### Anti-analysis -> control -> validation -> pass criterion

| Bypass target | Applied control | Validation (verify yourself) | Pass criterion |
|---|---|---|---|
| Packing (UPX/ASPack) | `upx -d` / ESP-law dump | Re-measure dump entropy, extract strings | Entropy drops + plaintext strings appear |
| Broken IAT | Rebuild IAT with Scylla | Do imports resolve to real modules? | API names resolve cleanly |
| Anti-dump (page protection) | Patch page perms, then dump | Does the dump disassemble/run? | Clean disassembly at OEP |

### Analysis validation (verify yourself)

```bash
# Measure whether it "really unpacked" via entropy/strings before vs after
python3 -c "import math,collections,sys; d=open(sys.argv[1],'rb').read(); \
c=collections.Counter(d); e=-sum(n/len(d)*math.log2(n/len(d)) for n in c.values()); \
print(f'{sys.argv[1]}: entropy={e:.2f}')" packed.bin unpacked.bin
strings -n 6 unpacked.bin | grep -iE 'http|reg|cmd|\.dll' | head
# Pass: unpacked entropy is clearly lower than packed and plaintext API/strings appear
# Fail: if entropy is unchanged, the dump is still compressed/encrypted - re-unpack
```

> Run validation only in an **isolated analysis environment**. Confirm "the original code/imports are restored" via entropy/strings/IAT, not merely "I dumped it" (see [[06_Malware_Analysis]]).
