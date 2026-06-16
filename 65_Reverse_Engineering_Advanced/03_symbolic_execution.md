> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 심볼릭 실행 (Symbolic Execution)

## 개념 소개

심볼릭 실행은 프로그램의 입력값을 "구체적인 숫자" 대신 "기호(Symbol)"로 처리하는 분석 기법입니다. 마치 수학 방정식을 풀 듯, 특정 경로에 도달하기 위해 어떤 입력이 필요한지를 자동으로 계산합니다.

예시: `if (x > 5 && x < 10)` 분기에 들어가려면 → x의 조건: `5 < x < 10`

---

## 핵심 개념

### 심볼릭 상태

| 구성요소 | 설명 |
|---|---|
| 심볼릭 변수 | 구체값 대신 `α`, `β` 같은 기호로 표현 |
| 경로 조건 (PC) | 현재 경로에 도달하기 위한 제약 조건들의 집합 |
| 제약 풀기 (SMT) | Z3 같은 솔버로 조건을 만족하는 입력값 계산 |

### 주요 도구

- **angr**: Python 기반, CTF/바이너리 분석에 많이 사용
- **KLEE**: LLVM IR 기반 심볼릭 실행 엔진
- **Manticore**: Trail of Bits 개발, EVM/ELF 지원
- **SAGE**: Microsoft 내부 도구

### 경로 폭발 문제 (Path Explosion)

루프와 조건이 많을수록 탐색 경로가 지수적으로 증가합니다.

```
if A:        → 2개 경로
  if B:      → 4개 경로
    if C:    → 8개 경로
      ...    → 2^n 경로
```

**해결책**: 경계 조건 설정, 함수 요약 (function summary), 상태 합병 (state merging)

---

## Python 실습: 간단한 심볼릭 실행 시뮬레이터 (수동 BFS)

```python
#!/usr/bin/env python3
"""
Z3 없이 순수 Python으로 구현한 간단한 심볼릭 실행 시뮬레이터
정수 조건 분기를 BFS로 탐색하여 경로 조건을 추적합니다.
"""

import argparse
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Constraint:
    """단일 제약 조건: variable op value"""
    variable: str
    operator: str  # '>', '<', '>=', '<=', '==', '!='
    value: int

    def check(self, val: int) -> bool:
        ops = {
            '>': val > self.value,
            '<': val < self.value,
            '>=': val >= self.value,
            '<=': val <= self.value,
            '==': val == self.value,
            '!=': val != self.value,
        }
        return ops.get(self.operator, False)

    def __str__(self) -> str:
        return f"{self.variable} {self.operator} {self.value}"


@dataclass
class SymbolicState:
    """심볼릭 실행 상태"""
    pc: int  # Program Counter (명령 인덱스)
    path_conditions: list[Constraint] = field(default_factory=list)
    variables: dict[str, int | str] = field(default_factory=dict)
    path_taken: list[str] = field(default_factory=list)

    def clone(self) -> "SymbolicState":
        return SymbolicState(
            pc=self.pc,
            path_conditions=self.path_conditions.copy(),
            variables=self.variables.copy(),
            path_taken=self.path_taken.copy(),
        )


@dataclass
class Instruction:
    """간단한 명령 표현"""
    itype: str   # 'assign', 'branch', 'target', 'print'
    args: list[Any] = field(default_factory=list)


def is_satisfiable(conditions: list[Constraint], candidate_range: range) -> int | None:
    """제약 조건을 모두 만족하는 정수값을 브루트포스로 찾습니다."""
    if not conditions:
        return candidate_range.start
    for val in candidate_range:
        if all(c.check(val) for c in conditions):
            return val
    return None


class SymbolicEngine:
    """BFS 기반 간단한 심볼릭 실행 엔진"""

    def __init__(self, program: list[Instruction], search_range: range = range(-100, 101)):
        self.program = program
        self.search_range = search_range
        self.explored_paths: list[tuple[list[str], list[Constraint]]] = []
        self.max_paths = 32

    def run(self) -> None:
        """BFS로 모든 경로를 탐색합니다."""
        initial_state = SymbolicState(pc=0)
        queue: deque[SymbolicState] = deque([initial_state])

        while queue and len(self.explored_paths) < self.max_paths:
            state = queue.popleft()

            if state.pc >= len(self.program):
                self.explored_paths.append(
                    (state.path_taken.copy(), state.path_conditions.copy())
                )
                continue

            instr = self.program[state.pc]
            self._execute(instr, state, queue)

    def _execute(
        self, instr: Instruction, state: SymbolicState, queue: deque[SymbolicState]
    ) -> None:
        if instr.itype == "assign":
            var_name, value = instr.args
            state.variables[var_name] = value
            state.pc += 1
            queue.append(state)

        elif instr.itype == "branch":
            # args: [variable, operator, value, true_target, false_target]
            var, op, val, true_tgt, false_tgt = instr.args

            # True 브랜치
            true_state = state.clone()
            true_cond = Constraint(variable=var, operator=op, value=val)
            true_state.path_conditions.append(true_cond)
            true_state.path_taken.append(f"IF {true_cond} → 참")
            true_state.pc = true_tgt
            # 만족 가능 여부 확인
            if is_satisfiable(true_state.path_conditions, self.search_range) is not None:
                queue.append(true_state)

            # False 브랜치
            neg_op = {">" : "<=", "<": ">=", ">=": "<", "<=": ">", "==": "!=", "!=": "=="}
            false_state = state.clone()
            false_cond = Constraint(variable=var, operator=neg_op.get(op, op), value=val)
            false_state.path_conditions.append(false_cond)
            false_state.path_taken.append(f"IF {true_cond} → 거짓")
            false_state.pc = false_tgt
            if is_satisfiable(false_state.path_conditions, self.search_range) is not None:
                queue.append(false_state)

        elif instr.itype == "target":
            state.pc += 1
            queue.append(state)

        elif instr.itype == "print":
            msg = instr.args[0]
            state.path_taken.append(f"출력: {msg}")
            state.pc += 1
            queue.append(state)

        else:
            state.pc += 1
            queue.append(state)


def build_sample_program() -> list[Instruction]:
    """
    예시 프로그램 (의사코드):
      x = symbolic
      if x > 5:      → pc1
        if x < 10:   → pc2
          print("secret!")
        else:
          print("too big")
      else:
        print("too small")
    """
    return [
        Instruction("assign", ["x", "symbolic"]),          # pc 0
        Instruction("branch", ["x", ">", 5, 2, 5]),        # pc 1: x > 5?
        Instruction("branch", ["x", "<", 10, 3, 4]),       # pc 2: x < 10?
        Instruction("print", ["[목표] secret 경로 도달!"]),  # pc 3
        Instruction("print", ["[경로] x >= 10"]),           # pc 4
        Instruction("print", ["[경로] x <= 5"]),            # pc 5
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="간단한 심볼릭 실행 시뮬레이터 (BFS 기반)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--range-min", type=int, default=-50, help="탐색 정수 범위 최솟값"
    )
    parser.add_argument(
        "--range-max", type=int, default=50, help="탐색 정수 범위 최댓값"
    )
    parser.add_argument("--max-paths", type=int, default=16, help="최대 탐색 경로 수")
    args = parser.parse_args()

    program = build_sample_program()
    engine = SymbolicEngine(
        program=program,
        search_range=range(args.range_min, args.range_max + 1),
    )
    engine.max_paths = args.max_paths
    engine.run()

    print(f"\n총 {len(engine.explored_paths)}개 경로 발견\n{'='*60}")
    for i, (steps, conditions) in enumerate(engine.explored_paths, 1):
        print(f"\n[경로 {i}]")
        for step in steps:
            print(f"  {step}")
        if conditions:
            sat_val = is_satisfiable(conditions, engine.search_range)
            cond_str = " AND ".join(str(c) for c in conditions)
            print(f"  제약 조건: {cond_str}")
            print(f"  입력 예시: x = {sat_val}")


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **CTF 바이너리 크랙미**: 패스워드 검증 로직에서 올바른 입력값 자동 계산
2. **퍼징 시드 생성**: 심볼릭 실행으로 각 분기를 트리거하는 입력 자동 생성
3. **취약점 경로 탐색**: 특정 취약 코드에 도달하는 입력 조건 역산

---

## 심화: angr 실전 — 크랙미 자동 풀이

위 시뮬레이터는 개념용이고, 실제 바이너리는 angr로 푼다. 다음은 "정답 출력 vs 실패 출력"을 기준으로 입력을 역산하는 전형적 패턴이다.

```python
import angr, claripy

proj = angr.Project("./crackme", auto_load_libs=False)

# 16바이트 심볼릭 입력 (stdin)
flag_len = 16
flag = claripy.BVS("flag", flag_len * 8)

state = proj.factory.entry_state(
    stdin=flag,
    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                 angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
)
# 출력 가능한 ASCII로 제약 → 탐색 공간 축소
for byte in flag.chop(8):
    state.solver.add(byte >= 0x20, byte <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),   # 성공 분기
    avoid=lambda s: b"Wrong" in s.posix.dumps(1),     # 실패 분기 가지치기
)

if simgr.found:
    print("FLAG:", simgr.found[0].posix.dumps(0))
```

> 핵심: `avoid`로 실패 경로를 즉시 버려 경로 폭발을 억제하고, 입력 바이트 제약으로 솔버 부담을 줄인다.

---

## 경로 폭발 완화 기법 비교

| 기법 | 원리 | 장점 | 한계 |
|---|---|---|---|
| `find`/`avoid` 가지치기 | 목표·실패 분기로 탐색 제한 | 구현 단순 | 목표를 미리 알아야 함 |
| 함수 요약 (hook) | 복잡 함수를 모델로 대체 | 라이브러리 호출 회피 | 요약 작성 비용 |
| 상태 합병 (veritesting) | 동일 지점 상태 통합 | 경로 수 급감 | 제약식 복잡도 증가 |
| 동시 실행 (concolic) | 구체값+심볼릭 병행 | 깊은 경로 도달 | 커버리지 누락 가능 |
| 루프 바운드 | 반복 횟수 상한 | 무한 루프 방지 | 깊은 버그 누락 |

---

## 언제 심볼릭 실행을 쓸까 (적용 판단)

```
입력 → 출력 관계가 명확한 검증 로직인가?
   ├─ 예: 짧은 입력, 분기 명확 ──► 심볼릭 실행 적합 (크랙미·키 검증)
   └─ 아니오
        ├─ 암호 연산·해시 포함 ──► 부적합 (제약식 폭발) → 퍼징 권장
        ├─ 거대한 상태공간     ──► concolic + 커버리지 가이드 퍼징 병행
        └─ 네트워크/시간 의존  ──► 동적 분석·후킹 우선
```

---

## 빠른 자가진단 체크리스트

- [ ] 목표 분기(성공/취약)와 회피 분기를 명확히 정의했는가?
- [ ] 입력 길이·문자 범위 제약으로 탐색 공간을 줄였는가?
- [ ] 해시·암호 루틴은 hook으로 우회하거나 심볼릭 대상에서 제외했는가?
- [ ] 경로 폭발 시 veritesting/concolic 전환을 고려했는가?
- [ ] 솔버 결과를 실제 바이너리에 입력해 검증했는가?

---

## 요약

| 개념 | 설명 |
|---|---|
| 심볼릭 변수 | 구체값 없는 추상 입력 표현 |
| 경로 조건 | 해당 경로 도달을 위한 제약 집합 |
| SMT 풀기 | Z3 등으로 제약 만족 입력 계산 |
| 경로 폭발 | 지수적 경로 증가 문제 |
| angr/KLEE | 실용 심볼릭 실행 프레임워크 |
| `find`/`avoid` | 목표·실패 분기 기반 가지치기 |

---

<a name="english"></a>

# Symbolic Execution

## Concept Overview

Symbolic execution analyzes programs by treating input values as "symbols" rather than concrete numbers — like solving a math equation to determine what inputs are needed to reach a specific execution path.

---

## Core Concepts

| Component | Description |
|---|---|
| Symbolic variable | Input represented as abstract symbol (α, β) |
| Path condition (PC) | Set of constraints to reach current path |
| Constraint solving | Use SMT solver (Z3) to find satisfying inputs |

### Key Tools

- **angr**: Python-based, popular for CTF/binary analysis
- **KLEE**: LLVM IR-based symbolic execution engine
- **Manticore**: Trail of Bits, supports EVM/ELF
- **SAGE**: Microsoft internal tool

### Path Explosion Problem

Conditions and loops cause exponential growth in the number of paths.

**Solutions**: Bound conditions, function summarization, state merging.

---

## Practical Applications

1. **CTF crackme**: Automatically compute correct password inputs
2. **Fuzzing seed generation**: Produce inputs that trigger each branch
3. **Vulnerability path finding**: Reverse-compute inputs reaching vulnerable code

---

## Summary Table

| Concept | Description |
|---|---|
| Symbolic variable | Abstract input without concrete value |
| Path condition | Constraint set for reaching a path |
| SMT solving | Compute satisfying inputs via Z3 etc. |
| Path explosion | Exponential growth of paths |
| angr/KLEE | Practical symbolic execution frameworks |
| `find`/`avoid` | Pruning by target/failure branches |

---

## Deep Dive: angr in Practice — Solving a Crackme

The simulator above is conceptual; real binaries are solved with angr. The typical pattern reverse-computes input using "success output vs failure output."

```python
import angr, claripy

proj = angr.Project("./crackme", auto_load_libs=False)

flag_len = 16
flag = claripy.BVS("flag", flag_len * 8)

state = proj.factory.entry_state(
    stdin=flag,
    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                 angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
)
# Constrain to printable ASCII → shrink search space
for byte in flag.chop(8):
    state.solver.add(byte >= 0x20, byte <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),   # success branch
    avoid=lambda s: b"Wrong" in s.posix.dumps(1),     # prune failure branch
)

if simgr.found:
    print("FLAG:", simgr.found[0].posix.dumps(0))
```

> Key: `avoid` drops failure paths immediately to curb path explosion, and byte constraints reduce solver load.

---

## Path Explosion Mitigation Comparison

| Technique | Principle | Pro | Limit |
|---|---|---|---|
| `find`/`avoid` pruning | Limit search by target/failure | Simple | Must know the goal |
| Function summary (hook) | Replace complex func with model | Avoids library calls | Cost to write summary |
| State merging (veritesting) | Merge states at same point | Sharp drop in path count | Higher constraint complexity |
| Concolic execution | Concrete + symbolic together | Reaches deep paths | May miss coverage |
| Loop bounding | Cap iteration count | Prevents infinite loops | May miss deep bugs |

---

## When to Use Symbolic Execution

```
Is input→output a clear verification logic?
   ├─ Yes: short input, clear branches ──► Good fit (crackme / key check)
   └─ No
        ├─ Crypto/hash involved ──► Poor fit (constraint blowup) → prefer fuzzing
        ├─ Huge state space     ──► Concolic + coverage-guided fuzzing
        └─ Network/time-dependent ──► Prefer dynamic analysis / hooking
```

---

## Quick Self-Assessment Checklist

- [ ] Did you clearly define target (success/vuln) and avoid branches?
- [ ] Did you shrink the search space with input length/charset constraints?
- [ ] Did you hook around or exclude hash/crypto routines from symbolic targets?
- [ ] On path explosion, did you consider veritesting/concolic?
- [ ] Did you verify solver output against the real binary?
