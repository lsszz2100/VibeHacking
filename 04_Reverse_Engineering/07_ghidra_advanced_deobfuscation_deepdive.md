> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Ghidra 기반 심층 리버스 엔지니어링 & 제어 흐름 평탄화(CFF) 난독화 해제

> 🏢 **연계 실습 랩**: [Lab 30: GhidraRev - Binary Analysis & Advanced Deobfuscation Security Lab](../../labs/30_ghidra_deobfuscation_lab)  
> 🎯 **관련 워게임 트랙**: `ghidra` (Ghidra 역공학 & 고급 난독화 해제 35제)

---

## 0. 개요 및 왜 Ghidra 기반 난독화 해제인가?

현대 소프트웨어 역공학(Reverse Engineering) 환경에서 악성코드 분석가와 보안 연구원이 마주하는 가장 큰 장벽은 상용 프로텍터(VMProtect, Themida)나 OLLVM(Goron, Hikari) 계열의 컴파일러 기반 **코드 난독화(Code Obfuscation)**입니다. 

그중에서도 **제어 흐름 평탄화(Control Flow Flattening, CFF)**는 함수의 정상적인 if-else 분기와 루프 구조를 완전히 파괴하고, 모든 기본 블록(Basic Block)을 거대한 `switch-case` 상태 머신 디스패처 아래로 수평 재배치하여 전통적인 정적 디컴파일러의 가독성을 극단적으로 떨어뜨립니다.

```
+-----------------------------------------------------------------------------------+
|                        제어 흐름 평탄화(CFF) 구조 비교 다이어그램                  |
+-----------------------------------------------------------------------------------+

 [ 정상 제어 흐름 (Normal CFG) ]
             ┌───────────┐
             │  Block A  │
             └─────┬─────┘
           ┌───────┴───────┐
           ▼               ▼
     ┌───────────┐   ┌───────────┐
     │  Block B  │   │  Block C  │
     └─────┬─────┘   └─────┬─────┘
           └───────┬───────┘
                   ▼
             ┌───────────┐
             │  Block D  │
             └───────────┘

 [ 평탄화된 제어 흐름 (Flattened CFG w/ Dispatcher) ]
                   ┌───────────┐
                   │  Block A  │ (state = 10)
                   └─────┬─────┘
                         ▼
        ┌───────────────────────────────────┐
        │  Central Dispatcher: switch(state)│ ◄──────────┐
        └─┬──────────────┬──────────────┬───┘            │
          │ (case 10)    │ (case 40)    │ (case 25)      │
          ▼              ▼              ▼                │
    ┌───────────┐  ┌───────────┐  ┌───────────┐          │
    │  Block B  │  │  Block C  │  │  Block D  │          │
    │(state=40) │  │(state=25) │  │(state=90) │──────────┘
    └───────────┘  └───────────┘  └───────────┘
```

본 심층 분석에서는 오픈소스 역공학 프레임워크인 **NSA Ghidra**의 P-Code 중간 언어 구조, Headless 분석 자동화, 그리고 CFF 상태 전이 역산 및 불투명 술어(Opaque Predicate) 제거를 통한 완전한 디플래트닝(Deflattening) 원리와 실전 기법을 해부합니다.

---

## 1. Ghidra 아키텍처 및 P-Code 중간 표현 (IR)

### 1.1 Sleigh와 P-Code 엔진

Ghidra의 디컴파일러 엔진은 기계어 바이트를 직접 C 코드로 변환하지 않고, 2단계 중간 표현 과정을 거칩니다:

1. **Sleigh 언어**: 대상 CPU 아키텍처(x86, x86_64, ARM, MIPS, RISC-V)의 명령어 집합을 정밀하게 정의하는 명세 언어.
2. **P-Code (Processor Code)**: 레지스터 기반의 가상 머신 연산자 집합(약 40개의 마이크로 오퍼레이션)으로, 모든 아키텍처 명령어를 일관된 RISC 스타일 기본 연산(`COPY`, `LOAD`, `STORE`, `INT_ADD`, `INT_XOR`, `BRANCH`, `CBRANCH`, `CALL`)으로 정규화합니다.

```
x86_64:  xor eax, eax
P-Code:  eax = INT_XOR eax, eax
         ZF  = INT_EQUAL eax, 0
         SF  = INT_SLESS eax, 0
```

### 1.2 Ghidra Headless Analyzer 자동화

대규모 바이너리 펌웨어나 수백 개의 스트립트(Stripped) 라이브러리를 일괄 분석할 때 GUI 대신 `analyzeHeadless` CLI 유틸리티를 활용합니다:

```bash
# Ghidra Headless CLI 실행 기본 형식
$GHIDRA_HOME/support/analyzeHeadless \
    /tmp/ghidra_projects MyProject \
    -import /path/to/target_binary.elf \
    -postScript RecoverSymbols.py \
    -overwrite
```

#### Headless 심볼 복원 스크립트 (Python/Jython)
```python
# RecoverSymbols.py - Ghidra FlatProgramAPI 기반 심볼 복원
from ghidra.program.model.symbol import SourceType

def run():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    
    # x86_64 함수 프롤로그 시그니처: push rbp; mov rbp, rsp (55 48 89 E5)
    prologue_pattern = b"\x55\x48\x89\xe5"
    
    mem = currentProgram.getMemory()
    text_sec = mem.getBlock(".text")
    addr = text_sec.getStart()
    
    print("[*] Scanning .text section for function prologues...")
    while addr < text_sec.getEnd():
        found = mem.findBytes(addr, text_sec.getEnd(), prologue_pattern, None)
        if not found:
            break
        fn = fm.getFunctionAt(found)
        if fn is None:
            fn = createFunction(found, None)
        print("  [+] Found function at %s: %s" % (found, fn.getName()))
        addr = found.add(4)
```

---

## 2. 제어 흐름 난독화 기법 해부

### 2.1 제어 흐름 평탄화 (Control Flow Flattening)의 메커니즘
OLLVM의 CFF 변환 패스는 함수를 다음과 같은 구성요소로 재편합니다:
- **기본 블록 분할**: 원본 함수의 분기/루프를 여러 개의 독립된 Basic Block으로 조각냅니다.
- **상태 변수 도입 (`state`)**: 각 블록의 실행 순서를 결정하는 가상 상태 변수를 스택 또는 레지스터에 할당합니다.
- **루프 & 스위치 디스패처**: 모든 블록을 하나의 거대한 `while (state != EXIT)` 루프와 `switch (state)` 문 아래로 종속시킵니다.
- **가짜 분기 및 셔플링**: 블록들의 물리적 메모리 주소 배치를 뒤섞어 정적 디컴파일 시 제어 흐름 그래프(CFG)가 폭발적으로 복잡해지도록 만듭니다.

### 2.2 불투명 술어 (Opaque Predicates)
컴파일러는 실행 시점에는 항상 특정 결과(`True` 또는 `False`)로 평가되지만, 정적 분석 도구 입장에서는 복잡한 분기 조건문처럼 보이는 코드를 삽입합니다:
- **수학적 불투명 술어**:
  $$\forall y \in \mathbb{Z}, \quad y(y + 1) \pmod 2 \equiv 0$$
  연속된 두 정수의 곱은 항상 짝수이므로, 이 조건문은 정적 분석 도구에는 분기문으로 보이지만 런타임에는 항상 참이 됩니다.
- **포인터 앨리어싱 불투명 술어**: 전역 포인터 배열의 특정 인덱스를 참조하여 디컴파일러의 데이터 흐름 분석을 교란합니다.

---

## 3. 실전 CFF 디플래트닝(Deflattening) 알고리즘

### 3.1 상태 전이 그래프 역산 3단계
1. **디스패처 블록 식별**:
   - `switch(state)` 분기를 수행하는 메인 디스패처(Dispatcher) 및 선행 블록(Pre-dispatcher)을 특정합니다.
2. **관련 기본 블록(Relevant Basic Blocks) 분류**:
   - 디스패처에서 분기되어 실제 원본 코드를 수행하는 블록과, 단순 상태 갱신 블록을 분류합니다.
3. **기호 실행(Symbolic Execution)을 통한 전이 경로 복원**:
   - 각 블록의 끝에서 `state` 변수에 쓰여지는 다음 상수값 또는 조건부 전이값(`state = cond ? stateA : stateB`)을 역산합니다.

### 3.2 Python 기반 Ghidra P-Code 디플래트너 개념 구현
```python
def deflatten_cfg(function):
    """Ghidra Function CFG에서 CFF 상태 머신을 추출하고 평탄화를 해제합니다."""
    cfg = get_function_cfg(function)
    dispatcher = find_dispatcher_node(cfg)
    state_reg = find_state_variable(dispatcher)
    
    transitions = {}
    for block in cfg.get_relevant_blocks():
        # 각 블록 종료 시점의 state 레지스터 쓰기 추적
        next_state = symbolic_trace_register(block, state_reg)
        transitions[block.start_addr] = next_state
        print(f"[+] Block @ {block.start_addr:#x} -> Next State: {next_state}")
        
    return transitions
```

---

## 4. 안티 탬퍼링 무결성 검증 & 바이너리 패칭 기법

### 4.1 자체 체크섬(Self-Hashing) 검증 원리
많은 상용 보안 모듈은 런타임 시작 시 메모리에 로드된 자신의 `.text` 섹션을 해싱(SHA-256 또는 CRC32)하여 컴파일 시점의 정적 해시 테이블과 비교합니다:

```c
int verify_text_section_checksum() {
    uint8_t *text_start = (uint8_t *)&_start;
    size_t text_size = 0x1000;
    uint32_t current_crc = compute_crc32(text_start, text_size);
    if (current_crc != EXPECTED_TEXT_CRC32) {
        abort(); // 무결성 위조 감지 시 즉시 종료
    }
    return 1;
}
```

### 4.2 인라인 패칭 및 무결성 우회
- **바이너리 패치**: 가상 주소 `0x00401337`의 조건부 점프(`74 18` - `jz`)를 `90 90` (`nop nop`) 또는 `eb 18` (`jmp short`)로 치환하여 인증 검사를 무력화합니다.
- **체크섬 우회**: `verify_text_section_checksum` 함수의 반환값을 항상 `1`로 강제하거나, 체크섬 계산 대상 메모리 범위를 분리(Shadow Memory 기법)하여 원본 바이트를 읽도록 리다이렉트합니다.

---

## 5. 방어자 관점의 바이너리 하드닝 (Defense & Hardening)

1. **하드웨어 지원 Control Flow Integrity (CFI)**:
   - Intel CET(Shadow Stack & Indirect Branch Tracking, IBT) 및 ARM Branch Target Identification(BTI)을 활성화하여 간접 분기 목적지가 `ENDBR64`로 시작하지 않거나 ROP 체이닝 시 즉시 예외를 발생시킵니다.
2. **강력한 코드 서명(Code Signing & Authenticode)**:
   - OS 커널 레벨에서 바이너리 로드 시 RSA-4096 / SHA-256 디지털 서명을 강제하여 1바이트라도 변경된 바이너리는 실행을 원천 차단합니다.
3. **가상화 난독화(Virtualization Obfuscation)**:
   - CFF 단독 사용 대신, 고유의 가상 명령어 집합(Custom Bytecode VM)을 구성하여 명령어 인터프리터 루프 내에서 연산을 수행하도록 캡슐화합니다.

---

<a name="english"></a>

# Advanced Reverse Engineering with Ghidra & Control Flow Flattening (CFF) Deobfuscation

> 🏢 **Hands-on Lab**: [Lab 30: GhidraRev - Binary Analysis & Advanced Deobfuscation Security Lab](../../labs/30_ghidra_deobfuscation_lab)  
> 🎯 **Associated Wargame Track**: `ghidra` (Ghidra Reverse Engineering & Advanced Deobfuscation - 35 Challenges)

---

## 0. Introduction & Motivation

In modern binary reverse engineering, security analysts frequently confront binaries protected by state-of-the-art obfuscators (e.g., VMProtect, Themida, OLLVM). 

Among these techniques, **Control Flow Flattening (CFF)** represents one of the most effective structural transformations. It dismantles natural nested loops and conditional branches, placing all basic blocks under a single centralized `switch-case` dispatcher loop controlled by an artificial state variable.

In this deepdive, we dissect Ghidra's P-Code intermediate representation, Headless Analyzer scripting, and practical algorithms for deflattening obfuscated control flow graphs and bypassing self-integrity checks.

---

## 1. Ghidra Architecture & P-Code Intermediate Representation

- **Sleigh Language**: Formal processor specification language translating machine code bytes into micro-operations.
- **P-Code Engine**: A unified register-based virtual machine instruction set (approximately 40 micro-operations) normalizing complex x86/ARM semantics into atomic primitives.
- **Headless Analyzer Automation**: Automated symbol recovery, xref tracing, and decompiler pipeline execution via CLI scripting (`analyzeHeadless`).

---

## 2. Control Flow Flattening & Opaque Predicates

- **CFF Dispatcher Loop**: All basic blocks execute conditionally inside `while (state != EXIT) { switch (state) { ... } }`.
- **Opaque Predicates**: Branch conditions invariant at runtime (e.g., $\forall y, y(y+1) \equiv 0 \pmod 2$) inserted to break decompiler heuristics.

---

## 3. Practical Deflattening & Anti-Tamper Bypass

- **Symbolic Execution Tracing**: Extracting basic block state transitions to reconstruct the original control flow graph.
- **Binary Patching**: Converting conditional jumps (`74 18` jz) to NOPs (`90 90`) or unconditional jumps (`eb 18` jmp).
- **Integrity Check Bypassing**: Defeating self-checksum verification via shadow memory or return value spoofing.

---

## 4. Defensive Hardening

- **Control Flow Integrity (CFI)**: Intel CET / ARM BTI enforcement against illegal indirect branches.
- **Mandatory Authenticode Code Signing**: Kernel-level verification preventing tampered binary execution.
