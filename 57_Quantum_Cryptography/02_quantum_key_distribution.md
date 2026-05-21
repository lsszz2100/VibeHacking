# 57-2. 양자 키 분배(QKD): 원리, 프로토콜, 실제 구현

## 개요

양자 키 분배(Quantum Key Distribution, QKD)는 양자역학의 법칙을 이용하여 도청이 물리적으로 탐지되는 비밀 키 공유 방식이다. 고전 암호에서 비밀 채널 없이 키를 안전하게 교환하는 것과 달리, QKD는 **정보-이론적 보안(information-theoretic security)** 을 제공한다.

---

## 1. QKD의 이론적 기반

### 1.1 노-클로닝 정리(No-Cloning Theorem)

**정의**: 미지의 양자 상태를 완벽하게 복사하는 것은 양자역학적으로 불가능하다.

**증명 개요**:
- 선형 연산자 U가 |ψ⟩|0⟩ → |ψ⟩|ψ⟩를 수행한다고 가정
- 두 상태 |ψ⟩, |φ⟩에 대해 ⟨φ|ψ⟩ = ⟨φ|ψ⟩²가 성립해야 함
- 이는 ⟨φ|ψ⟩ = 0 또는 1일 때만 가능 → 일반적으로 불가능

**암호학적 의미**: 도청자(Eve)가 양자 채널의 큐비트를 복사하여 측정하고 원본을 전달하는 것이 불가능하다. 측정 행위 자체가 양자 상태를 교란시켜 탐지된다.

### 1.2 하이젠베르크 불확정성 원리

공액 관측량(예: X 기저와 Z 기저)을 동시에 정확히 측정할 수 없다. BB84에서 대각 기저를 모르면 측정 시 오류가 발생한다.

---

## 2. QKD 프로토콜 비교

### 2.1 주요 프로토콜 특성 비교 표

| 특성 | BB84 | B92 | E91 (에케르트) | SARG04 | Twin-Field QKD |
|------|------|-----|--------------|--------|---------------|
| **제안 연도** | 1984 | 1992 | 1991 | 2004 | 2018 |
| **제안자** | Bennett, Brassard | Bennett | Ekert | Scarani 외 | Lucamarini 외 |
| **큐비트 수** | 4개 상태 | 2개 상태 | 얽힌 쌍 | 4개 상태 | 간섭 기반 |
| **보안 근거** | 노-클로닝 | 노-클로닝 | Bell 부등식 | 비모호성 | 위상 코딩 |
| **효율** | 25~50% | 25% | 25% | 25% | ~50% |
| **PNS 공격 저항** | 낮음 | 낮음 | 중간 | 높음 | 높음 |
| **거리 제한** | ~100km | ~50km | ~100km | ~100km | ~600km |
| **구현 복잡도** | 낮음 | 매우 낮음 | 높음 | 낮음 | 매우 높음 |

### 2.2 BB84 프로토콜 상세

BB84는 가장 널리 구현된 QKD 프로토콜이다.

**사용 기저와 상태:**

| 기저 | 비트 0 | 비트 1 | 기호 |
|------|--------|--------|------|
| Z 기저 (직선) | 수평 편광 →  | 수직 편광 ↑ | + |
| X 기저 (대각) | 45° 편광 ↗ | 135° 편광 ↖ | × |

**프로토콜 단계:**

1. Alice가 랜덤 비트열과 랜덤 기저를 선택하여 광자 전송
2. Bob이 랜덤 기저를 선택하여 측정
3. 공개 채널에서 기저 비교 (sifting)
4. 기저가 일치한 비트만 유지 (키의 약 50%)
5. 샘플링으로 QBER 추정
6. QBER이 임계값(일반적으로 11%) 이하면 계속 진행
7. 오류 수정(Error Correction)으로 불일치 제거
8. 프라이버시 증폭(Privacy Amplification)으로 키 압축

### 2.3 E91 프로토콜 (얽힘 기반)

Ekert가 제안한 E91은 EPR 쌍의 양자 얽힘을 활용한다.

- **Bell 부등식 위반**을 도청 탐지에 사용
- 도청 시 얽힘이 파괴되어 Bell 부등식이 위반되지 않음
- 고전 상관관계로 위장한 공격을 탐지 가능
- 디바이스 독립적 QKD(DI-QKD)의 이론적 기반

---

## 3. QKD 실제 구현 사례

### 3.1 주요 QKD 네트워크 현황

| 프로젝트명 | 국가 | 규모 | 특징 | 상태 |
|-----------|------|------|------|------|
| **미우시우스 위성(墨子)** | 중국 | 위성-지상 1,200km | 세계 최초 위성 QKD | 2016년 운영 |
| **베이징-상하이 QKD 간선** | 중국 | 2,000km 지상망 | 32개 중계 노드 | 2017년 완성 |
| **SECOQC 프로젝트** | 유럽 | 빈, 6개 노드 | 다중 프로토콜 통합 | 2008년 데모 |
| **도쿄 QKD 네트워크** | 일본 | 도쿄 대도시권 | NTT, Toshiba 참여 | 2010년 이후 운영 |
| **영국 QKD 네트워크** | 영국 | 브리스톨-바스 | 표준화 연구 목적 | 진행 중 |
| **SK텔레콤 QKD** | 한국 | 서울 일부 구간 | 상용 서비스 시작 | 2023년~ |
| **미 국방부 QKD** | 미국 | 기밀 군 네트워크 | NSA 참여 | 비공개 |

### 3.2 미우시우스(墨子) 위성 상세

2016년 중국 과기대가 발사한 세계 최초 QKD 전용 위성:

- **궤도**: 약 500km 저궤도
- **달성 거리**: 위성-지상 1,203km QKD 성공 (2020년)
- **키 생성률**: 약 1.1 kbps (지상 기준)
- **주요 실험**: 베이징-빈 화상회의 양자 암호화 통신 (2017)
- **한계**: 낮과 대기 산란으로 야간에만 운용 가능

---

## 4. QKD의 한계와 도전

### 4.1 기술적 한계

| 제약 사항 | 원인 | 현재 해결책 |
|----------|------|-----------|
| **거리 제한** | 광섬유 손실, 광자 흡수 | 신뢰할 수 있는 중계기 사용 |
| **낮은 키 생성률** | 단일 광자 검출 효율 | 고효율 SPD, 멀티플렉싱 |
| **고가의 장비** | 단일 광자 광원/검출기 | 집적 광학 칩 연구 중 |
| **중계기 취약점** | 신뢰 중계기 필요 | 양자 중계기 연구 중 |
| **인증 채널 필요** | 공개 채널 도청 방지 | 기존 PKI 또는 사전 공유 키 |

### 4.2 공격 유형

실제 QKD 구현에 대한 알려진 공격:

| 공격 유형 | 대상 | 설명 |
|----------|------|------|
| PNS (Photon Number Splitting) | BB84 약한 레이저 | 다광자 펄스에서 광자 분리 후 보관 |
| 시간-이동 공격 | 측정 장치 | 검출기 타이밍 취약점 악용 |
| 트로이 목마 공격 | Alice 장치 | 장치에 빛을 쏴 상태 정보 추출 |
| 검출기 블라인딩 | Bob 장치 | 강한 빛으로 검출기를 고전적으로 제어 |
| MDI-QKD로 해결 | 모든 검출기 공격 | 검출기를 신뢰하지 않는 프로토콜 |

---

## 5. Python CLI: BB84 프로토콜 시뮬레이터

```python
#!/usr/bin/env python3
"""
BB84 양자 키 분배 프로토콜 시뮬레이터
Alice, Bob, Eve(도청자)의 역할을 시뮬레이션하여 QBER 계산
"""

from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class QuantumChannel:
    """
    양자 채널: Alice에서 Bob으로 큐비트 전송.
    채널 잡음과 Eve의 도청을 시뮬레이션.
    """
    channel_noise: float       # 채널 고유 오류율
    eve_present: bool          # Eve 도청 여부
    eve_intercept_rate: float  # Eve가 차단하는 큐비트 비율

    def transmit(
        self,
        bit: int,
        alice_basis: int
    ) -> tuple[int, int]:
        """
        큐비트 전송 시뮬레이션.
        Returns: (수신된 비트, 수신된 기저)
        기저: 0=Z기저(직선), 1=X기저(대각)
        """
        received_bit = bit
        received_basis = alice_basis

        # Eve 도청 시뮬레이션
        if self.eve_present and random.random() < self.eve_intercept_rate:
            # Eve가 랜덤 기저로 측정 후 재전송
            eve_basis = random.randint(0, 1)
            if eve_basis != alice_basis:
                # 기저 불일치 시 50% 확률로 비트 오류 발생
                received_bit = random.randint(0, 1)

        # 채널 잡음 적용
        if random.random() < self.channel_noise:
            received_bit = 1 - received_bit

        return received_bit, received_basis


@dataclass
class Alice:
    """Alice: 키를 전송하는 측"""
    key_length: int
    bits: list[int] = field(default_factory=list)
    bases: list[int] = field(default_factory=list)

    def prepare_qubits(self) -> None:
        """랜덤 비트와 기저 생성"""
        self.bits = [random.randint(0, 1) for _ in range(self.key_length)]
        self.bases = [random.randint(0, 1) for _ in range(self.key_length)]

    def sift_key(self, bob_bases: list[int]) -> list[int]:
        """Bob과 기저가 일치하는 인덱스의 비트만 선택"""
        return [
            self.bits[i]
            for i in range(self.key_length)
            if self.bases[i] == bob_bases[i]
        ]

    def sift_indices(self, bob_bases: list[int]) -> list[int]:
        """기저 일치 인덱스 목록 반환"""
        return [
            i for i in range(self.key_length)
            if self.bases[i] == bob_bases[i]
        ]


@dataclass
class Bob:
    """Bob: 키를 수신하는 측"""
    key_length: int
    bases: list[int] = field(default_factory=list)
    received_bits: list[int] = field(default_factory=list)

    def choose_bases(self) -> None:
        """랜덤 기저 선택"""
        self.bases = [random.randint(0, 1) for _ in range(self.key_length)]

    def measure(
        self,
        channel: QuantumChannel,
        alice_bits: list[int],
        alice_bases: list[int]
    ) -> None:
        """채널을 통해 수신된 큐비트 측정"""
        self.received_bits = []
        for i in range(self.key_length):
            received_bit, _ = channel.transmit(alice_bits[i], alice_bases[i])
            # Bob이 자신의 기저로 측정 (기저 불일치 시 랜덤 결과)
            if self.bases[i] != alice_bases[i]:
                # 기저 불일치: 측정 결과가 의미 없음 (랜덤)
                received_bit = random.randint(0, 1)
            self.received_bits.append(received_bit)

    def sift_key(self, alice_bases: list[int]) -> list[int]:
        """Alice와 기저가 일치하는 인덱스의 비트만 선택"""
        return [
            self.received_bits[i]
            for i in range(self.key_length)
            if alice_bases[i] == self.bases[i]
        ]


@dataclass
class Eve:
    """Eve: 도청자 (선택적)"""
    intercept_rate: float
    intercepted_count: int = 0
    correct_guess_count: int = 0

    def intercept(
        self,
        bit: int,
        alice_basis: int
    ) -> tuple[int, int]:
        """
        큐비트 차단 및 재전송 시뮬레이션.
        Returns: (Eve가 측정한 비트, Eve가 사용한 기저)
        """
        if random.random() < self.intercept_rate:
            self.intercepted_count += 1
            eve_basis = random.randint(0, 1)
            if eve_basis == alice_basis:
                self.correct_guess_count += 1
                return bit, eve_basis
            else:
                # 잘못된 기저로 측정 → 랜덤 결과
                return random.randint(0, 1), eve_basis
        return bit, alice_basis


def calculate_qber(
    alice_sifted: list[int],
    bob_sifted: list[int],
    sample_size: Optional[int] = None
) -> tuple[float, int, int]:
    """
    QBER(Quantum Bit Error Rate) 계산.
    Returns: (QBER, 오류 수, 비교한 비트 수)
    """
    if len(alice_sifted) != len(bob_sifted):
        raise ValueError("Alice와 Bob의 sifted key 길이가 다릅니다.")

    if len(alice_sifted) == 0:
        return 0.0, 0, 0

    if sample_size is None:
        sample_size = len(alice_sifted)

    sample_size = min(sample_size, len(alice_sifted))
    indices = random.sample(range(len(alice_sifted)), sample_size)

    errors = sum(
        1 for i in indices
        if alice_sifted[i] != bob_sifted[i]
    )
    qber = errors / sample_size if sample_size > 0 else 0.0
    return qber, errors, sample_size


def privacy_amplification(
    sifted_key: list[int],
    qber: float,
    sample_ratio: float = 0.5
) -> list[int]:
    """
    프라이버시 증폭 시뮬레이션.
    Eve가 알 수 있는 정보를 고려하여 키를 압축.
    실제로는 2-universal hash 함수를 사용함.
    """
    # 단순화된 구현: 연속 비트의 XOR
    amplified = []
    step = max(1, int(1 / (1 - qber))) if qber < 1 else len(sifted_key)
    for i in range(0, len(sifted_key) - step + 1, step):
        xor_bit = 0
        for j in range(step):
            xor_bit ^= sifted_key[i + j]
        amplified.append(xor_bit)
    return amplified


def print_protocol_visualization(
    alice: Alice,
    bob: Bob,
    alice_sifted: list[int],
    bob_sifted: list[int],
    max_display: int = 20
) -> None:
    """BB84 프로토콜 과정 시각화 (처음 N개 비트)"""
    basis_symbol = {0: "+", 1: "×"}  # Z기저, X기저
    display_n = min(max_display, alice.key_length)

    print("\n  BB84 프로토콜 단계별 시각화 (처음 {}개 비트):".format(display_n))
    print(f"  {'번호':>4}  {'Alice 비트':>9}  {'Alice 기저':>9}  "
          f"{'Bob 기저':>8}  {'Bob 수신':>8}  {'기저일치':>7}  {'Bob 비트':>8}")
    print(f"  {'-'*72}")

    match_count = 0
    for i in range(display_n):
        a_bit = alice.bits[i]
        a_basis = basis_symbol[alice.bases[i]]
        b_basis = basis_symbol[bob.bases[i]]
        b_recv = bob.received_bits[i]
        match = alice.bases[i] == bob.bases[i]
        if match:
            match_count += 1
        match_str = "O" if match else "-"
        b_sifted_str = str(b_recv) if match else "-"

        print(
            f"  {i+1:>4}  {a_bit:>9}  {a_basis:>9}  "
            f"{b_basis:>8}  {b_recv:>8}  {match_str:>7}  {b_sifted_str:>8}"
        )

    print(f"\n  표시된 {display_n}개 비트 중 기저 일치: {match_count}개")


def print_qber_interpretation(qber: float) -> str:
    """QBER 값 해석"""
    if qber < 0.05:
        return "정상 (도청 없음, 낮은 채널 잡음)"
    elif qber < 0.11:
        return "주의 (약간의 잡음 또는 제한적 도청 가능성)"
    elif qber < 0.15:
        return "경고 (도청 강력 의심, 키 사용 재고 권장)"
    else:
        return "위험 (도청 거의 확실, 키 폐기 필요)"


def run_bb84_simulation(args: argparse.Namespace) -> int:
    """BB84 시뮬레이션 메인 실행"""
    key_length: int = args.key_length
    error_rate: float = args.error_rate
    channel_noise: float = args.channel_noise
    eve_present: bool = args.eve
    eve_intercept: float = args.eve_intercept_rate
    verbose: bool = args.verbose

    print("=" * 68)
    print("  BB84 양자 키 분배 프로토콜 시뮬레이터")
    print("=" * 68)
    print(f"\n  파라미터 설정:")
    print(f"  - 목표 키 길이     : {key_length} 비트")
    print(f"  - 채널 잡음율      : {channel_noise:.1%}")
    print(f"  - 도청자(Eve)      : {'존재' if eve_present else '없음'}")
    if eve_present:
        print(f"  - Eve 차단율      : {eve_intercept:.1%}")

    random.seed(args.seed if hasattr(args, "seed") and args.seed else None)

    # 전송할 총 큐비트 수 (기저 불일치로 약 50%가 버려짐)
    raw_length = key_length * 4  # 여유있게 4배 생성

    # Alice 초기화 및 큐비트 준비
    alice = Alice(key_length=raw_length)
    alice.prepare_qubits()

    # Bob 초기화 및 기저 선택
    bob = Bob(key_length=raw_length)
    bob.choose_bases()

    # 양자 채널 설정
    channel = QuantumChannel(
        channel_noise=channel_noise,
        eve_present=eve_present,
        eve_intercept_rate=eve_intercept
    )

    print(f"\n  전송 단계:")
    print(f"  - 총 전송 큐비트 수 : {raw_length}개")

    # Bob이 측정
    bob.measure(channel, alice.bits, alice.bases)

    # 기저 비교 (sifting)
    alice_sifted = alice.sift_key(bob.bases)
    bob_sifted = bob.sift_key(alice.bases)
    sift_indices = alice.sift_indices(bob.bases)

    sifted_length = len(alice_sifted)
    sift_ratio = sifted_length / raw_length

    print(f"  - 기저 일치 (sifted): {sifted_length}개 ({sift_ratio:.1%})")

    if sifted_length == 0:
        print("오류: sifted key가 비어 있습니다. key-length를 늘리세요.", file=sys.stderr)
        return 1

    # QBER 계산 (전체의 25%를 샘플로 사용)
    sample_n = max(10, sifted_length // 4)
    qber, errors, compared = calculate_qber(alice_sifted, bob_sifted, sample_n)

    print(f"\n  QBER 측정 결과:")
    print(f"  - 샘플 비트 수     : {compared}개")
    print(f"  - 오류 비트 수     : {errors}개")
    print(f"  - QBER             : {qber:.4f} ({qber:.2%})")
    print(f"  - 판정             : {print_qber_interpretation(qber)}")

    # BB84 임계값 (11%) 확인
    QBER_THRESHOLD = 0.11
    if qber > QBER_THRESHOLD:
        print(f"\n  경고: QBER {qber:.2%}가 임계값 {QBER_THRESHOLD:.0%}을 초과합니다!")
        print(f"  도청이 탐지되었거나 채널 품질이 너무 나쁩니다.")
        print(f"  이 키는 사용하지 않아야 합니다.")
        if not args.force:
            print("  시뮬레이션을 계속하려면 --force 옵션을 사용하세요.")
            return 1

    # 최종 키 생성 (샘플 비트 제거)
    # 실제로는 오류 수정 + 프라이버시 증폭 필요
    remaining_sifted = alice_sifted[compared:]
    bob_remaining = bob_sifted[compared:]

    # 프라이버시 증폭 시뮬레이션
    final_key = privacy_amplification(remaining_sifted, qber)
    final_key_length = len(final_key)

    print(f"\n  최종 키 생성:")
    print(f"  - 샘플 후 남은 비트 : {len(remaining_sifted)}개")
    print(f"  - 프라이버시 증폭 후: {final_key_length}비트")

    key_efficiency = final_key_length / raw_length
    print(f"  - 전체 효율         : {key_efficiency:.2%} (전송 큐비트 대비)")

    # 키 일부 출력
    if final_key_length > 0:
        display_n = min(32, final_key_length)
        key_str = "".join(str(b) for b in final_key[:display_n])
        print(f"  - 최종 키 (앞 {display_n}비트): {key_str}{'...' if final_key_length > display_n else ''}")

    # 상세 시각화
    if verbose:
        print_protocol_visualization(alice, bob, alice_sifted, bob_sifted)

    # Eve 탐지 요약
    if eve_present:
        print(f"\n  Eve 도청 분석:")
        print(f"  - Eve 차단율       : {eve_intercept:.1%}")
        expected_qber_from_eve = eve_intercept * 0.25
        print(f"  - Eve로 인한 예상 QBER: {expected_qber_from_eve:.2%}")
        print(f"  - 실제 측정 QBER  : {qber:.2%}")
        detected = qber > 0.03
        print(f"  - Eve 탐지 결과   : {'탐지됨' if detected else '탐지 실패 (운 좋게 통과)'}")

    # 요약 통계
    print("\n" + "=" * 68)
    print("  시뮬레이션 요약")
    print("=" * 68)
    rows = [
        ("전송 큐비트", f"{raw_length}개"),
        ("Sifted 키", f"{sifted_length}개"),
        ("QBER 샘플", f"{compared}개"),
        ("QBER", f"{qber:.2%}"),
        ("최종 키 길이", f"{final_key_length}비트"),
        ("도청 탐지", "O" if eve_present and qber > 0.03 else "X" if eve_present else "해당없음"),
    ]
    for label, value in rows:
        print(f"  {label:>12} : {value}")

    print("\n  시뮬레이션 완료.")
    return 0


def parse_arguments() -> argparse.Namespace:
    """명령행 인수 파싱"""
    parser = argparse.ArgumentParser(
        prog="bb84_simulator",
        description="BB84 양자 키 분배 프로토콜 시뮬레이터",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python 02_quantum_key_distribution.py --key-length 256
  python 02_quantum_key_distribution.py --key-length 512 --channel-noise 0.02
  python 02_quantum_key_distribution.py --key-length 1024 --eve --eve-intercept-rate 0.5
  python 02_quantum_key_distribution.py --key-length 256 --verbose

QBER 기준:
  < 5%   : 정상 (도청 없음)
  5~11%  : 주의 (약한 도청 또는 잡음)
  > 11%  : 위험 (키 폐기 권장)
        """
    )
    parser.add_argument(
        "--key-length",
        type=int,
        default=256,
        metavar="N",
        help="목표 최종 키 길이 (비트, 기본값: 256)"
    )
    parser.add_argument(
        "--error-rate",
        type=float,
        default=0.0,
        metavar="R",
        help="QBER 임계값 재정의 (기본값: 0.0, 표준 11%% 사용)"
    )
    parser.add_argument(
        "--channel-noise",
        type=float,
        default=0.01,
        metavar="N",
        help="채널 비트 오류율 (기본값: 0.01 = 1%%)"
    )
    parser.add_argument(
        "--eve",
        action="store_true",
        help="도청자 Eve 활성화"
    )
    parser.add_argument(
        "--eve-intercept-rate",
        type=float,
        default=0.5,
        metavar="R",
        help="Eve의 큐비트 차단 비율 (기본값: 0.5 = 50%%)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="QBER이 임계값을 초과해도 시뮬레이션 계속"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="프로토콜 단계별 상세 시각화 출력"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="랜덤 시드 (재현성을 위해 사용)"
    )
    return parser.parse_args()


def main() -> None:
    """메인 진입점"""
    args = parse_arguments()

    # 입력값 검증
    if args.key_length < 10:
        print("오류: --key-length는 10 이상이어야 합니다.", file=sys.stderr)
        sys.exit(1)
    if not (0.0 <= args.channel_noise <= 0.5):
        print("오류: --channel-noise는 0.0~0.5 범위여야 합니다.", file=sys.stderr)
        sys.exit(1)
    if not (0.0 <= args.eve_intercept_rate <= 1.0):
        print("오류: --eve-intercept-rate는 0.0~1.0 범위여야 합니다.", file=sys.stderr)
        sys.exit(1)

    try:
        exit_code = run_bb84_simulation(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n시뮬레이션이 중단되었습니다.")
        sys.exit(0)
    except Exception as e:
        print(f"\n예상치 못한 오류: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 6. QKD와 고전 암호의 비교

| 특성 | QKD | 고전 DH/ECDH | 사전 공유 키 |
|------|-----|-------------|------------|
| **보안 근거** | 양자역학 법칙 | 수학적 어려움 | 물리적 키 배달 |
| **양자 컴퓨터 저항** | 완전 | 없음 (쇼어로 붕괴) | 완전 |
| **도청 탐지** | 자동 (QBER) | 불가 | 불가 |
| **장거리 지원** | 제한적 (~수백km) | 무제한 | 무제한 |
| **구현 비용** | 매우 높음 | 낮음 | 중간 |
| **배포 용이성** | 전용 인프라 필요 | 소프트웨어만 | 물리 전달 필요 |
| **표준화** | 미성숙 | NIST, IETF | - |
| **미래 보안** | 영속적 | PQC로 교체 필요 | 영속적 |

---

## 7. 하이브리드 QKD 아키텍처

실용적인 배포에서는 QKD를 단독으로 사용하기보다 기존 암호와 결합한 **하이브리드 아키텍처**를 사용한다:

```
[Alice] ─── QKD 채널 (광섬유/위성) ─── [Bob]
   │                                      │
   └── QKD 키 → AES-256 암호화 → 데이터 ──┘
                    ↑
              추가로 PQC 알고리즘으로
              QKD 채널 인증
```

**계층별 역할:**
1. **QKD 계층**: 물리적으로 안전한 랜덤 키 생성
2. **PQC 계층**: QKD 공개 채널(인증 채널) 보호
3. **대칭 계층**: AES-256으로 실제 데이터 암호화

이 구조는 QKD 장애 시에도 PQC로 폴백할 수 있어 실용성이 높다.
