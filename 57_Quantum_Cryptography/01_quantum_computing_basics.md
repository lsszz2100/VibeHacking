# 57-1. 양자 컴퓨팅 기초와 암호학에 대한 영향

## 개요

양자 컴퓨팅은 양자역학의 원리(중첩, 얽힘, 간섭)를 활용하여 특정 유형의 계산을 고전 컴퓨터보다 지수적으로 빠르게 수행하는 패러다임이다. 특히 인수분해와 이산 로그 문제에 대한 양자 알고리즘의 존재는 현재 공개키 암호 체계 전반을 위협한다.

---

## 1. 양자 컴퓨팅 핵심 개념

### 1.1 큐비트(Qubit)

고전 비트는 0 또는 1만 표현한다. 큐비트는 0과 1의 **중첩(superposition)** 상태를 동시에 가질 수 있다. 측정 시에만 하나의 값으로 붕괴한다.

수학적으로 큐비트 상태는 다음과 같이 표현한다:

```
|ψ⟩ = α|0⟩ + β|1⟩
```

여기서 |α|² + |β|² = 1이며, α, β는 복소수 진폭이다.

### 1.2 핵심 양자 현상 비교 표

| 개념 | 정의 | 암호학적 의미 | 구현 예시 |
|------|------|--------------|----------|
| **중첩(Superposition)** | 큐비트가 동시에 여러 상태에 존재 | 병렬 계산 가능 → 탐색 가속 | n큐비트로 2ⁿ 상태 동시 표현 |
| **얽힘(Entanglement)** | 둘 이상의 큐비트가 비국소적으로 상관 | QKD의 보안 기반, 도청 탐지 | EPR 쌍, Bell 상태 |
| **간섭(Interference)** | 진폭의 보강/소멸 간섭 | 올바른 답의 진폭을 증폭 | 그로버 알고리즘 핵심 |
| **측정(Measurement)** | 관측 시 중첩 붕괴 | 양자 정보 복제 불가 기반 | 0 또는 1로 확률적 붕괴 |
| **노-클로닝(No-cloning)** | 미지의 양자 상태 복사 불가 | 도청 탐지의 이론적 근거 | QKD 보안 원리 |

### 1.3 양자 게이트

양자 게이트는 큐비트에 적용되는 유니터리 변환이다. 대표적인 게이트:

| 게이트 | 역할 | 행렬 표현 |
|--------|------|----------|
| **Hadamard (H)** | 중첩 생성 | 1/√2 [[1,1],[1,-1]] |
| **CNOT** | 제어 NOT, 얽힘 생성 | [[1,0,0,0],[0,1,0,0],[0,0,0,1],[0,0,1,0]] |
| **Toffoli** | 3큐비트 제어 게이트 | 고전 AND의 양자 버전 |
| **Phase (S, T)** | 위상 회전 | 그로버 반사 연산에 사용 |

---

## 2. 쇼어 알고리즘(Shor's Algorithm)과 RSA 붕괴

### 2.1 RSA 보안의 전제

RSA는 큰 수 N = p × q의 소인수분해가 어렵다는 가정에 기반한다. 2048비트 RSA를 고전 컴퓨터로 분해하려면 현재 기술로 수십억 년이 소요된다.

### 2.2 쇼어 알고리즘의 동작 원리

쇼어 알고리즘은 양자 푸리에 변환(QFT)을 활용하여 함수의 주기를 효율적으로 찾는다.

**단계별 절차:**

1. **목표**: N을 소인수분해 (N = p × q)
2. **랜덤 선택**: 1 < a < N인 정수 a를 무작위 선택
3. **GCD 확인**: gcd(a, N) ≠ 1이면 약수 발견 (종료)
4. **주기 탐색 (양자 부분)**: f(x) = aˣ mod N의 주기 r을 QFT로 탐색
5. **주기 활용**: r이 짝수이고 aʳ/² ≠ -1 mod N이면,
   - p = gcd(aʳ/² + 1, N)
   - q = gcd(aʳ/² - 1, N)

**복잡도 비교:**

| 알고리즘 | 복잡도 | 2048비트 RSA 분해 시간 |
|----------|--------|----------------------|
| 일반 수체 체 (고전) | O(exp(n^(1/3))) | 수십억 년 |
| 쇼어 알고리즘 (양자) | O(n³) 다항식 | 수 시간 (충분한 큐비트 시) |

### 2.3 필요 큐비트 수

RSA-2048 분해에는 약 **4,000~20,000개의 논리적 큐비트**가 필요하다. 오류 수정을 포함하면 수백만 개의 물리적 큐비트가 필요하다. 현재 최고 수준의 양자 컴퓨터는 약 1,000~2,000 물리적 큐비트 수준이다.

---

## 3. 그로버 알고리즘(Grover's Algorithm)과 대칭키 보안

### 3.1 그로버 알고리즘 개요

그로버 알고리즘은 정렬되지 않은 데이터베이스에서 특정 항목을 탐색하는 양자 알고리즘이다.

- **고전 탐색**: O(N) - 최악의 경우 N번 시도
- **그로버 탐색**: O(√N) - 제곱근 속도 향상

### 3.2 대칭키 암호에 대한 영향

| 알고리즘 | 현재 키 길이 | 그로버 공격 후 유효 보안 강도 | 권장 대응 |
|---------|------------|---------------------------|----------|
| AES-128 | 128비트 | 64비트 (취약) | AES-256으로 교체 |
| AES-256 | 256비트 | 128비트 (안전) | 현재 키 유지 |
| 3DES-168 | 168비트 | 84비트 (취약) | 즉시 교체 |
| ChaCha20-256 | 256비트 | 128비트 (안전) | 현재 키 유지 |
| SHA-256 | 256비트 출력 | 128비트 충돌저항 | 안전 유지 |
| SHA-512 | 512비트 출력 | 256비트 충돌저항 | 안전 유지 |

**핵심**: 그로버 알고리즘은 대칭키 보안을 절반으로 줄인다. 따라서 양자 시대에는 최소 256비트 대칭키가 필요하다.

### 3.3 해시 함수에 대한 영향

- **원상 공격 (Preimage)**: O(√N) → SHA-256은 2¹²⁸ 수준으로 유지
- **충돌 공격**: 생일 공격 + 그로버 = O(N^(1/3)) → SHA-256 충돌은 2⁸⁵ 수준

---

## 4. 양자 우위(Quantum Advantage) 달성 현황

### 4.1 주요 기관별 현황 표

| 기관 | 시스템명 | 큐비트 수 | 달성 내용 | 연도 | 암호학적 위협도 |
|------|---------|----------|----------|------|--------------|
| **Google** | Sycamore | 53큐비트 | 랜덤 회로 샘플링에서 양자우위 주장 | 2019 | 낮음 (특수 문제) |
| **Google** | Willow | 105큐비트 | 오류 수정 개선, RCS 10²⁵배 빠름 | 2024 | 낮음 (오류율 높음) |
| **IBM** | Osprey | 433큐비트 | 최대 큐비트 수 달성 | 2022 | 낮음 (충분한 오류수정 미흡) |
| **IBM** | Heron | 133큐비트 | 오류율 개선 집중 | 2023 | 낮음 |
| **IBM** | 목표 | 100,000큐비트 | 2033년 장기 로드맵 | 2033(목표) | 중간 |
| **중국 USTC** | 九章(Jiuzhang) | 76광자 모드 | 가우시안 보손 샘플링 | 2020 | 낮음 (특수 문제) |
| **중국 USTC** | 祖冲之(Zuchongzhi) | 66큐비트 | 랜덤 회로 샘플링 | 2021 | 낮음 |
| **중국 BAIDU** | Qianshi | 10큐비트 | 상업용 클라우드 서비스 | 2022 | 낮음 |
| **IonQ** | Forte | 32 AQ | 알고리즘 큐비트 기준 | 2023 | 낮음 |
| **Quantinuum** | H2 | 32큐비트 | 트랩 이온, 낮은 오류율 | 2023 | 낮음 |

### 4.2 CRQC(Cryptographically Relevant Quantum Computer) 예측

| 예측 기관 | CRQC 달성 예상 시기 | 근거 |
|----------|------------------|------|
| NIST | 2030년 이후 | 오류 수정 기술 성숙 필요 |
| NSA | 불확실, 2030~2040년대 | 기술 발전 속도 불확실성 |
| ENISA (EU) | 2030년 이후 | 물리적 큐비트 규모 확대 필요 |
| Mosca 정리 | x + y > z이면 즉시 대응 | 보안 수명 + 마이그레이션 시간 |

---

## 5. Python CLI: 그로버 알고리즘 시뮬레이터

```python
#!/usr/bin/env python3
"""
그로버 알고리즘 양자 탐색 시뮬레이터
고전 컴퓨터에서 진폭 증폭 과정을 수치 시뮬레이션
"""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np


@dataclass
class GroverState:
    """그로버 알고리즘의 양자 상태를 표현하는 데이터 클래스"""
    n_bits: int
    target: int
    amplitudes: np.ndarray = field(init=False)
    n_states: int = field(init=False)
    iteration_history: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.n_states = 2 ** self.n_bits
        if not (0 <= self.target < self.n_states):
            raise ValueError(
                f"타겟 인덱스 {self.target}이 범위를 벗어났습니다. "
                f"유효 범위: 0 ~ {self.n_states - 1}"
            )
        # 균등 중첩 초기화: 모든 상태에 동일한 진폭
        initial_amplitude = 1.0 / math.sqrt(self.n_states)
        self.amplitudes = np.full(self.n_states, initial_amplitude, dtype=complex)

    def oracle(self) -> None:
        """
        오라클 연산자: 타겟 상태의 위상을 반전
        |target⟩ → -|target⟩
        """
        self.amplitudes[self.target] *= -1

    def diffusion(self) -> None:
        """
        그로버 확산 연산자 (반전 about average)
        2|ψ⟩⟨ψ| - I 적용
        """
        mean_amplitude = np.mean(self.amplitudes)
        self.amplitudes = 2 * mean_amplitude - self.amplitudes

    def get_probabilities(self) -> np.ndarray:
        """각 상태의 측정 확률 계산"""
        return np.abs(self.amplitudes) ** 2

    def get_target_probability(self) -> float:
        """타겟 상태의 측정 확률"""
        return float(np.abs(self.amplitudes[self.target]) ** 2)

    def record_state(self, iteration: int) -> None:
        """현재 상태를 기록"""
        self.iteration_history.append({
            "iteration": iteration,
            "target_amplitude": float(np.real(self.amplitudes[self.target])),
            "target_probability": self.get_target_probability(),
            "max_non_target_prob": float(
                np.max(np.abs(self.amplitudes[
                    [i for i in range(self.n_states) if i != self.target]
                ])) ** 2
            ),
        })


def calculate_optimal_iterations(n_states: int) -> int:
    """최적 반복 횟수 계산: π/4 * √N"""
    return max(1, round(math.pi / 4 * math.sqrt(n_states)))


def visualize_amplitudes(
    amplitudes: np.ndarray,
    target: int,
    iteration: int,
    width: int = 60
) -> None:
    """진폭 분포를 ASCII 바 차트로 시각화"""
    n_states = len(amplitudes)
    probabilities = np.abs(amplitudes) ** 2
    max_prob = float(np.max(probabilities))

    print(f"\n  반복 {iteration}회 후 상태 분포 (상위 8개 상태):")
    print(f"  {'상태':>6}  {'확률':>8}  {'진폭 (실수)':>12}  {'막대그래프'}")
    print(f"  {'-'*65}")

    # 상위 8개 상태 + 타겟 포함하여 표시
    top_indices = np.argsort(probabilities)[::-1][:8].tolist()
    if target not in top_indices:
        top_indices.append(target)
        top_indices = sorted(set(top_indices))

    for idx in sorted(top_indices):
        prob = float(probabilities[idx])
        amp_real = float(np.real(amplitudes[idx]))
        bar_len = int((prob / max(max_prob, 1e-10)) * width)
        bar = "█" * bar_len
        marker = " ★ 타겟" if idx == target else ""
        print(f"  |{idx:>4}⟩  {prob:>8.4f}  {amp_real:>+12.6f}  {bar}{marker}")


def print_summary_table(history: list[dict]) -> None:
    """반복별 결과 요약 표 출력"""
    print("\n" + "=" * 65)
    print("  반복별 타겟 상태 진폭 증폭 추이")
    print("=" * 65)
    print(f"  {'반복':>4}  {'타겟 진폭':>12}  {'타겟 확률':>10}  {'비타겟 최대확률':>14}")
    print(f"  {'-'*59}")

    for record in history:
        it = record["iteration"]
        amp = record["target_amplitude"]
        prob = record["target_probability"]
        other = record["max_non_target_prob"]
        print(f"  {it:>4}  {amp:>+12.6f}  {prob:>10.4f}  {other:>14.6f}")

    print("=" * 65)


def run_grover_simulation(args: argparse.Namespace) -> int:
    """그로버 알고리즘 시뮬레이션 실행"""
    n_bits: int = args.n_bits
    target: int = args.target
    iterations: Optional[int] = args.iterations
    verbose: bool = args.verbose

    print("=" * 65)
    print("  그로버 알고리즘 양자 탐색 시뮬레이터")
    print("=" * 65)

    # 상태 공간 크기 계산
    n_states = 2 ** n_bits
    optimal_iters = calculate_optimal_iterations(n_states)

    if iterations is None:
        iterations = optimal_iters

    print(f"\n  설정 정보:")
    print(f"  - 큐비트 수      : {n_bits}개")
    print(f"  - 상태 공간 크기 : {n_states}개 ({2}^{n_bits})")
    print(f"  - 탐색 타겟      : |{target}⟩")
    print(f"  - 최적 반복 횟수 : {optimal_iters}회")
    print(f"  - 실행 반복 횟수 : {iterations}회")

    # 고전 탐색 vs 양자 탐색 비교
    classical_avg = n_states / 2
    print(f"\n  복잡도 비교:")
    print(f"  - 고전 선형 탐색 (평균): {classical_avg:.0f}회 시도")
    print(f"  - 그로버 양자 탐색     : {optimal_iters}회 반복")
    print(f"  - 속도 향상            : {classical_avg / optimal_iters:.1f}배")

    # 초기 상태 설정
    try:
        state = GroverState(n_bits=n_bits, target=target)
    except ValueError as e:
        print(f"\n오류: {e}", file=sys.stderr)
        return 1

    # 초기 상태 기록
    state.record_state(0)

    if verbose:
        print(f"\n  초기 상태 (균등 중첩):")
        print(f"  모든 상태의 초기 확률 = {1.0/n_states:.6f}")

    # 그로버 반복 실행
    print(f"\n  그로버 반복 실행 중...")

    for i in range(1, iterations + 1):
        state.oracle()       # 단계 1: 오라클 적용
        state.diffusion()    # 단계 2: 확산 연산자 적용
        state.record_state(i)

        if verbose and (i <= 5 or i == iterations):
            visualize_amplitudes(state.amplitudes, target, i)

    # 최종 결과
    final_prob = state.get_target_probability()
    probabilities = state.get_probabilities()

    print(f"\n  최종 결과 ({iterations}회 반복 후):")
    print(f"  - 타겟 |{target}⟩ 측정 확률 : {final_prob:.4f} ({final_prob*100:.2f}%)")
    print(f"  - 성공 임계값 (90%)        : {'달성' if final_prob >= 0.9 else '미달성'}")

    # 측정 시뮬레이션 (100회)
    measured_samples = np.random.choice(
        n_states, size=100, p=probabilities / probabilities.sum()
    )
    correct_count = int(np.sum(measured_samples == target))
    print(f"  - 측정 시뮬레이션 (100회) : {correct_count}회 타겟 측정")

    # 요약 표 출력
    print_summary_table(state.iteration_history)

    # 최고 확률 달성 반복 찾기
    best_iter = max(
        state.iteration_history,
        key=lambda r: r["target_probability"]
    )
    print(f"\n  최고 성공 확률 달성 시점:")
    print(f"  - 반복 {best_iter['iteration']}회: {best_iter['target_probability']:.4f} ({best_iter['target_probability']*100:.2f}%)")

    # 최종 확률 분포 시각화
    print(f"\n  최종 확률 분포 (상위 상태):")
    top_states = np.argsort(probabilities)[::-1][:5]
    for idx in top_states:
        prob = float(probabilities[idx])
        bar = "█" * int(prob * 40)
        marker = " ← 타겟" if idx == target else ""
        print(f"  |{idx:>4}⟩ : {prob:.4f} {bar}{marker}")

    print("\n  시뮬레이션 완료.")
    return 0


def parse_arguments() -> argparse.Namespace:
    """명령행 인수 파싱"""
    parser = argparse.ArgumentParser(
        prog="grover_simulator",
        description="그로버 양자 탐색 알고리즘 시뮬레이터 - 고전 컴퓨터에서 진폭 증폭 과정 시각화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python 01_quantum_computing_basics.py --n-bits 4 --target 7
  python 01_quantum_computing_basics.py --n-bits 8 --target 42 --iterations 12
  python 01_quantum_computing_basics.py --n-bits 3 --target 5 --verbose

참고:
  - n-bits=N이면 2^N개의 상태 공간을 탐색합니다.
  - 최적 반복 횟수는 π/4 * √(2^N)입니다.
  - numpy가 필요합니다: pip install numpy
        """
    )
    parser.add_argument(
        "--n-bits",
        type=int,
        default=4,
        metavar="N",
        help="큐비트 수 (기본값: 4, 탐색 공간: 2^N개 상태)"
    )
    parser.add_argument(
        "--target",
        type=int,
        default=7,
        metavar="INDEX",
        help="탐색할 타겟 상태의 인덱스 (기본값: 7)"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        metavar="K",
        help="그로버 반복 횟수 (기본값: 최적값 자동 계산)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="반복별 상세 진폭 분포 시각화 출력"
    )
    return parser.parse_args()


def main() -> None:
    """메인 진입점"""
    args = parse_arguments()

    # 입력값 검증
    if args.n_bits < 1:
        print("오류: --n-bits는 1 이상이어야 합니다.", file=sys.stderr)
        sys.exit(1)
    if args.n_bits > 20:
        print(
            f"경고: --n-bits={args.n_bits}이면 {2**args.n_bits:,}개 상태로 메모리가 부족할 수 있습니다.",
            file=sys.stderr
        )
        if args.n_bits > 25:
            print("오류: --n-bits는 최대 25까지 지원합니다.", file=sys.stderr)
            sys.exit(1)
    if args.iterations is not None and args.iterations < 1:
        print("오류: --iterations는 1 이상이어야 합니다.", file=sys.stderr)
        sys.exit(1)

    try:
        exit_code = run_grover_simulation(args)
        sys.exit(exit_code)
    except MemoryError:
        print(
            f"\n오류: 메모리 부족. --n-bits를 줄이세요 (현재: {args.n_bits}).",
            file=sys.stderr
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n시뮬레이션이 사용자에 의해 중단되었습니다.")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

---

## 6. 양자 컴퓨팅 하드웨어 기술 비교

### 6.1 주요 물리적 구현 방식

| 구현 방식 | 대표 기업 | 큐비트 수명 | 게이트 충실도 | 확장성 | 현재 수준 |
|----------|----------|-----------|------------|--------|----------|
| **초전도 큐비트** | IBM, Google | 수십~수백 μs | 99.9% (2큐비트) | 중간 | 가장 성숙 |
| **트랩 이온** | IonQ, Quantinuum | 수 초~분 | 99.9%+ | 낮음 | 높은 충실도 |
| **광자** | PsiQuantum, Xanadu | 극히 짧음 | 낮음 | 높음 | 초기 단계 |
| **중성 원자** | Atom Computing | 수 초 | 99%+ | 높음 | 빠른 성장 |
| **토폴로지컬** | Microsoft | 이론적 무한 | 이론적 완벽 | 높음 | 아직 미성숙 |

### 6.2 양자 오류 수정(QEC)의 중요성

양자 컴퓨터의 가장 큰 과제는 **디코히어런스(decoherence)** 와 **게이트 오류**이다. 암호학적으로 의미 있는 계산(RSA 분해)을 위해서는:

- **물리적 큐비트**: 현재 수준의 오류율(0.1~1%)을 가진 큐비트
- **논리적 큐비트**: 오류 수정 코드로 보호된 큐비트 (1개 논리 큐비트 ≈ 1,000개 물리 큐비트)
- **RSA-2048 분해**: 약 4,000개 논리 큐비트 → 약 400만~4,000만 개 물리 큐비트 필요

---

## 7. 양자 위협 타임라인과 대응 전략

### 7.1 Mosca 정리 (박사 Michele Mosca)

```
현재 암호화 데이터의 보안 수명 (x년)
+ PQC 마이그레이션 소요 시간 (y년)
> CRQC 완성까지 남은 시간 (z년)
→ 이 조건이 성립하면 지금 당장 마이그레이션 시작 필요
```

### 7.2 조직 유형별 대응 우선순위

| 조직 유형 | 데이터 보안 수명 | 마이그레이션 복잡도 | 권장 시작 시기 |
|----------|---------------|-----------------|--------------|
| 국방/정보기관 | 25년 이상 | 매우 높음 | 즉시 (이미 시작) |
| 금융기관 | 10~15년 | 높음 | 2025~2026년 |
| 의료기관 | 15~30년 | 중간 | 2026~2027년 |
| 일반 기업 | 5~10년 | 낮음~중간 | 2027~2030년 |
| 소비자 서비스 | 1~5년 | 낮음 | 표준 교체 주기 |

---

## 8. 참고 및 추가 학습 자료

- NIST SP 800-209: 양자 컴퓨팅과 암호학에 대한 가이드
- NIST IR 8413: 포스트 양자 암호 표준화 3라운드 후보 상태 보고서
- Google AI Quantum 팀 논문 (2019, Nature): "Quantum supremacy using a programmable superconducting processor"
- IBM 양자 로드맵: ibm.com/quantum/roadmap
- 중국 과기대 Jiuzhang 논문 (2020, Science): 276큐비트 광자 샘플링
