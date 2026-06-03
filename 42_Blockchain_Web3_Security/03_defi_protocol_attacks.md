> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# DeFi 프로토콜 공격 기법

## 학습 목표

이 문서를 완료하면 다음을 할 수 있다:

- 블록체인, 스마트 컨트랙트, DeFi가 무엇인지 초보자에게 설명할 수 있다
- Flash Loan이 왜 담보 없이 수억 달러를 빌릴 수 있는지 원리를 이해한다
- 오라클 조작 공격이 어떻게 가격을 속여 자금을 탈취하는지 설명한다
- MEV(최대 추출 가능 가치)와 샌드위치 공격의 메커니즘을 분석한다
- 실제 해킹 사례(bZx, Euler, Nomad, Poly Network, Ronin)를 분석하고 공통 패턴을 추출한다
- Python + Web3.py로 온체인 공격 트랜잭션을 추적하고 분석한다
- DeFi 프로토콜 보안 감사 체크리스트를 활용할 수 있다

---

## DeFi 기초 개념 — 해킹을 이해하기 전에 알아야 할 것들

### 블록체인이란?

블록체인은 **여러 컴퓨터(노드)가 동일한 장부를 공유하는 분산 데이터베이스**다. 은행은 자체 서버에 "A가 B에게 100만원 보냈다"는 기록을 관리하지만, 블록체인은 수천 개의 노드가 동일한 기록을 동시에 보유한다. 한 기록을 바꾸려면 전체 네트워크의 51% 이상을 동시에 장악해야 하므로 사실상 변조가 불가능하다.

**현실 세계 비유:** 은행 장부는 금고에 잠긴 단 한 권의 책이다. 블록체인 장부는 전국 수천 명이 동일한 내용을 동시에 기록하는 공개 원장이다. 한 명의 기록을 바꾸려면 나머지 수천 명의 기록도 동시에 바꿔야 한다.

```
은행 방식:           블록체인 방식:
[은행 서버]          [노드1] [노드2] [노드3] ... [노드N]
    ↑                   ↑       ↑       ↑            ↑
  단일 장부           모두 동일한 장부를 보유 (분산)
  (중앙화)                      (탈중앙화)

  서버 해킹 = 기록 조작 가능    51% 이상 동시 장악 필요 = 사실상 불가능
```

**핵심 특성:**
- **불변성(Immutability)**: 한번 기록된 트랜잭션은 수정 불가
- **투명성(Transparency)**: 모든 트랜잭션이 누구에게나 공개
- **즉시 최종성(Instant Finality)**: 트랜잭션 확정 후 취소 불가

**가스(Gas)란?** 이더리움에서 모든 연산은 가스라는 수수료를 소모한다. 복잡한 스마트 컨트랙트 호출일수록 더 많은 가스가 필요하다. 가스비가 높을수록 마이너/검증자가 해당 트랜잭션을 먼저 처리한다. 이 가스비 경쟁이 MEV 공격의 핵심 메커니즘이다.

**지갑과 프라이빗 키:** 블록체인에서 자산의 소유권은 프라이빗 키로 증명된다. 프라이빗 키를 잃으면 자산에 영구적으로 접근 불가능하다. "Not your keys, not your crypto"라는 격언이 있을 만큼 키 관리가 중요하다.

### 스마트 컨트랙트란?

스마트 컨트랙트는 **블록체인에 배포된 자동 실행 프로그램**이다. 일반 계약서는 변호사나 법원이 집행하지만, 스마트 컨트랙트는 조건이 충족되면 코드가 자동으로 실행된다.

**자판기 비유:** 스마트 컨트랙트는 자판기와 같다. 동전을 넣으면(조건 충족) 자동으로 음료가 나온다(코드 실행). 사람이 개입할 필요가 없고, 규칙을 어길 수도 없다. 단, 자판기 자체에 결함이 있으면 이를 악용할 수 있다.

**부동산 계약 비유:**
- 일반 계약: "매수인이 3억원을 지불하면 소유권을 이전한다" → 법원이 집행
- 스마트 컨트랙트: 동일한 조건이지만 코드가 자동으로 ETH를 받아 소유권 NFT를 전송

```solidity
// 단순한 에스크로 스마트 컨트랙트 예시
// 이 코드가 블록체인에 배포되면 누구도 수정하거나 중단시킬 수 없다
contract Escrow {
    address public buyer;
    address public seller;
    uint256 public price;

    // 매수인이 ETH를 보내면 자동으로 판매자에게 전달
    // "require"는 조건 검사 — 실패하면 트랜잭션 전체 취소
    function release() external payable {
        require(msg.sender == buyer, "구매자만 호출 가능");
        require(msg.value == price, "금액 불일치");
        payable(seller).transfer(msg.value);  // 자동 실행, 인간 개입 없음
    }
}
```

**스마트 컨트랙트의 특성:**
- 배포 후 코드 변경 불가 (Immutable) — 버그가 있어도 수정 어려움
- 누구나 코드를 읽을 수 있음 (공개 소스) — 공격자도 취약점을 찾을 수 있음
- 24시간 자동 실행 — 관리자 개입 없이 돌아감

### DeFi란? — "은행 없는 은행"

**DeFi(탈중앙화 금융)는 은행 없는 금융 서비스다 — 코드가 은행 역할을 한다.**

전통 금융에서는 은행이 대출, 이자, 환전을 처리하고 수수료를 가져간다. DeFi는 이 모든 기능을 스마트 컨트랙트로 대체한다. 은행 계좌가 없어도, 신용 점수가 없어도, 신분증이 없어도 DeFi를 이용할 수 있다. 인터넷과 이더리움 지갑만 있으면 된다.

| 전통 금융 | DeFi 등가물 | 설명 |
|-----------|------------|------|
| 은행 대출 | Aave, Compound | 담보를 맡기고 다른 토큰 대출 |
| 외환 거래소 | Uniswap, Curve | 토큰 간 자동 환전 (AMM 방식) |
| 파생상품 거래 | dYdX, GMX | 레버리지 거래, 무기한 선물 |
| 투자 펀드 | Yearn Finance | 자동 수익 최적화 |
| 이자 농사 | 다양한 프로토콜 | 유동성 제공의 대가로 이자 수취 |

**DeFi 규모:** 2021년 최고점 기준 TVL(Total Value Locked) $180B 이상. 이 모든 자금이 스마트 컨트랙트 코드에 잠겨 있다.

### DeFi의 핵심 특성: 컴포저빌리티 ("돈의 레고")

DeFi의 가장 강력한 특성이자 가장 위험한 특성은 **컴포저빌리티(Composability)**다. 각 DeFi 프로토콜은 레고 블록처럼 서로 조합할 수 있다.

```
[Aave에서 ETH 차용] → [Uniswap에서 ETH→USDC 환전] → [Curve에서 USDC 유동성 공급]
→ [Yearn으로 이자 최적화] → [Compound에서 담보로 사용] → 모두 한 트랜잭션에!
```

이것이 Flash Loan 공격의 기반이다. 여러 프로토콜을 한 트랜잭션에서 조합하면 엄청난 자금력을 순간적으로 만들 수 있다.

---

## 왜 DeFi는 해킹 타겟인가?

### 이유 1: 코드는 불변이다 — 버그도 영구적

전통 소프트웨어는 취약점 발견 시 패치를 배포하면 된다. DeFi 스마트 컨트랙트는 **배포 후 수정이 거의 불가능**하다. 일부 프록시 패턴(upgradeable contracts)을 사용하지만, 이 또한 별도의 공격 표면이 된다.

```
전통 웹 서비스:      버그 발견 → 코드 수정 → 서버 재배포 (몇 시간)
DeFi 스마트 컨트랙트: 버그 발견 → ??? (이미 $100M이 컨트랙트에 잠겨 있음)
```

**결과:** 개발자들은 배포 전 완벽한 코드를 작성해야 한다는 압박을 받는다. 실제로는 감사를 통과했음에도 복잡한 상호작용에서 버그가 발견된다.

### 이유 2: 즉시 최종성 — 되돌릴 수 없다

은행 이체는 며칠의 처리 기간이 있고, 사기가 탐지되면 취소 가능하다. 블록체인 트랜잭션은 **확정되면 영구적**이다. 해커가 $197M을 탈취해도 사법 기관이 트랜잭션을 취소할 방법이 없다.

유일한 예외: DAO 해킹(2016) 때 이더리움 커뮤니티는 하드포크로 트랜잭션을 되돌렸다. 이것이 Ethereum(ETH)과 Ethereum Classic(ETC)이 분리된 이유다.

### 이유 3: 컴포저빌리티 — 공격 표면이 지수적으로 증가

프로토콜 A, B, C가 각각 안전해도, A+B+C의 조합에서 새로운 취약점이 생길 수 있다. Flash Loan은 이 컴포저빌리티를 악용해 단 하나의 트랜잭션에서 수억 달러를 빌려 공격하는 것을 가능하게 한다.

### 이유 4: 오픈소스 = 공격자도 코드를 볼 수 있다

모든 스마트 컨트랙트 코드는 블록체인에 공개된다. 보안 감사 보고서도 종종 공개된다. 공격자들은 감사 보고서의 "낮은 위험도" 취약점들을 조합해 심각한 공격을 설계하기도 한다.

### 이유 5: 대규모 자금이 집중되어 있다

단일 DeFi 프로토콜에 수억 달러에서 수십억 달러의 자금이 잠겨 있다. 은행 강도는 현금 운반의 물리적 한계가 있지만, DeFi 해킹은 성공 즉시 전 세계 어느 지갑으로도 순간 이동이 가능하다. 이 비율 대비 보안 투자는 항상 부족하다.

---

## 1. Flash Loan 공격

Flash Loan은 같은 트랜잭션 내에서 무담보 대출 → 사용 → 상환이 가능한 DeFi 기능이다. 단독으로는 무해하지만, 가격 조작이나 거버넌스 공격에 악용된다.

### 1.1 원자성(Atomicity)이란 무엇인가?

Flash Loan을 이해하려면 먼저 **트랜잭션 원자성**을 이해해야 한다.

데이터베이스에서 "원자적 트랜잭션"이란 **전부 성공하거나 전부 실패하는 트랜잭션**이다. 중간 상태가 없다.

```
예시: 계좌 이체
  1단계: A 계좌에서 100만원 차감
  2단계: B 계좌에 100만원 추가

  만약 2단계에서 오류 발생 → 1단계도 취소 (돈이 사라지지 않음)
  이것이 원자성이다.
  
  원자성 없이는? → A에서 돈이 사라졌는데 B에게 도달하지 않는 상황 가능
```

블록체인의 스마트 컨트랙트 트랜잭션도 원자적이다. **모든 단계가 성공해야 트랜잭션이 확정**되고, 하나라도 실패하면 모든 상태 변경이 되돌아간다(revert).

### 1.2 Flash Loan이 작동하는 원리

Flash Loan은 원자성을 활용한 특수 대출이다.

```
단일 트랜잭션 내 실행 순서:
┌─────────────────────────────────────────────────────┐
│  1. Aave 프로토콜에서 10,000 ETH 차용 (수수료 0.09%) │
│  2. 차용 자금으로 원하는 작업 실행                   │
│     (아비트리지, 가격 조작, 청산 등)                 │
│  3. 원금 + 수수료 상환                               │
│                                                     │
│  상환 성공 → 트랜잭션 확정 (이익 확보)               │
│  상환 실패 → 전체 revert (대출 자체가 없었던 일)     │
└─────────────────────────────────────────────────────┘
```

**왜 이게 위험한가?**

일반 대출은 담보가 필요하다. 1억원을 빌리려면 1억원 상당의 자산을 담보로 맡겨야 한다. Flash Loan은 담보가 없다. **같은 트랜잭션 내에서 갚기만 하면 된다.**

이것이 의미하는 바: 자본금이 1원도 없는 사람이 단 하나의 트랜잭션으로 수천억원의 자금력을 가질 수 있다. 이 자금으로 시장을 조작하고 이익을 내면, 원금을 갚고도 막대한 수익이 남는다.

**Flash Loan이 항상 나쁜 건 아니다:**
- **아비트리지:** 거래소 간 가격 차이를 이용한 무위험 이익 — 시장 가격을 균일하게 만드는 긍정적 역할
- **담보 교체:** 담보 자산을 갑작스럽게 교체할 때 Flash Loan으로 일시 자금 확보
- **청산:** 건강하지 않은 포지션을 청산하는 데 사용 — 프로토콜의 안정성 유지

### 1.3 Flash Loan 공격 흐름 (상세 다이어그램)

```
공격자 지갑 (자본금 = $0에 가까움)
    │
    │  ══════ 단일 이더리움 트랜잭션 시작 ══════
    ▼
[공격자가 배포한 스마트 컨트랙트]
    │
    │ Step 1: Flash Loan 요청
    ├─→ [Aave 프로토콜]
    │       │ "10,000 ETH 빌려줘 (이 트랜잭션 안에서 갚을게)"
    │       └─→ 10,000 ETH 전송 ────→ [공격 컨트랙트]
    │                                  (현재 공격 컨트랙트 잔액: 10,000 ETH)
    │
    │ Step 2: 가격 조작
    ├─→ [Uniswap V2 풀]
    │       │ "10,000 ETH로 타겟 토큰 대량 매수"
    │       └─→ 토큰 가격 300% 급등 (수요 급증)
    │           (Uniswap의 AMM 공식: x*y=k에 의해 가격 폭등)
    │
    │ Step 3: 조작된 가격 활용 공격
    ├─→ [취약한 DeFi 프로토콜]
    │       │ Uniswap spot price를 오라클로 사용하는 프로토콜
    │       │ "토큰 담보로 대출해줘" (조작된 가격 기준)
    │       └─→ 실제 가치의 3배 자금 대출 실행 ───→ [공격 컨트랙트]
    │
    │ Step 4: 가격 정상화
    ├─→ [Uniswap V2 풀]
    │       │ "아까 산 토큰 다시 매도"
    │       └─→ 가격 정상화
    │
    │ Step 5: Flash Loan 상환
    ├─→ [Aave 프로토콜]
    │       │ 10,000 ETH + 수수료(9 ETH) 상환
    │       └─→ 상환 완료 ✓
    │
    │ Step 6: 이익 회수
    └─→ [공격자 지갑]
            대출로 탈취한 자금 - Flash Loan 수수료 = 순이익
    
    ══════ 트랜잭션 확정 (수초 이내) ══════
    
    결과: 자본금 $0으로 시작해서 수백만 달러 획득
```

### 1.4 bZx 해킹 (2020, $350K — 최초의 Flash Loan 공격)

bZx 공격은 Flash Loan 공격의 역사적 시작점이다. 당시에는 Flash Loan 자체가 새로운 개념이었고, 이 공격 이후 DeFi 업계 전체가 충격을 받았다.

```
공격 날짜: 2020년 2월 15일 (첫 번째 공격)
피해액: $350,000 (당시 기준)
역사적 의미: 최초의 Flash Loan 공격, DeFi 보안의 패러다임 변화

공격 시퀀스 (각 단계 설명):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1단계: dYdX에서 10,000 ETH Flash Loan 획득
   └─ dYdX는 당시 Flash Loan을 무료로 제공했음

2단계: Compound에서 112 WBTC 차용 (ETH 담보)
   └─ 정상적인 담보 대출 — 여기까지는 합법

3단계: bZx에서 5,500 ETH로 WBTC short 포지션 오픈
   └─ bZx는 Uniswap에서 WBTC를 높은 슬리피지로 매수
   └─ Uniswap의 WBTC/ETH 가격이 급락

4단계: Compound 포지션 청산
   └─ WBTC 가격이 Uniswap에서 하락 = Compound 담보 가치 하락
   └─ 조작된 가격 기준으로 Compound 청산 실행 → 이익
   
5단계: dYdX Flash Loan 상환

핵심 취약점:
  bZx가 Uniswap spot price를 직접 오라클로 사용
  → 단일 트랜잭션으로 가격 조작 가능
  → 가격 조작과 동시에 그 가격을 신뢰하는 프로토콜 공격

영향:
  이 공격 이후 DeFi 업계 전체가 오라클 설계를 재검토
  TWAP(시간 가중 평균 가격) 사용이 표준이 됨
  "Flash Loan 공격"이라는 새로운 공격 카테고리 확립
```

### 1.5 Euler Finance 해킹 분석 (2023, $197M)

```
공격 날짜: 2023년 3월 13일
피해액: $197,000,000 (역대 최대 Flash Loan 공격 중 하나)
특이사항: 공격자가 나중에 자금의 대부분을 반환

공격 시퀀스:
1. Aave에서 30M DAI Flash Loan
2. EUL 토큰 대량 매수 → eDAI 민팅 (2배 레버리지)
3. 버그 있는 donateToReserves() 호출
   → 준비금(reserve)에 자산 기증 → 자신의 부채 증가
   → 헬스 팩터(건강 지수)가 청산 가능 수준으로 하락
4. 두 번째 공격 컨트랙트가 청산 실행
   → 청산 보너스(10-20%) 포함 자산 획득
5. Flash Loan 상환, 나머지는 이익

핵심 버그:
  donateToReserves()가 호출 후 헬스 팩터 체크를 하지 않음
  정상적인 흐름: 자산 기증 → 헬스 팩터 확인 → 청산 여부 결정
  버그 흐름: 자산 기증 → [체크 없음] → 청산 가능 상태 방치
  
결말:
  공격자가 $177M 반환 (신원 추적 및 협상)
  Euler Finance는 프로토콜을 일시 정지하고 재감사 실시
```

### 1.6 Python 공격 시뮬레이션 추적기

```python
#!/usr/bin/env python3
"""DeFi 공격 트랜잭션 추적 및 분석 CLI

사용법:
  python3 defi_tracker.py analyze 0xabc...def --attacker 0x123...456 --rpc https://...
  python3 defi_tracker.py scan --start 16000000 --end 16001000 --rpc https://...
"""

import argparse
import json
import sys
from decimal import Decimal
from typing import Optional
from web3 import Web3
from web3.types import TxData


# 주요 DeFi 컨트랙트 주소 (Ethereum Mainnet)
KNOWN_PROTOCOLS = {
    "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9": "Aave V2 LendingPool",
    "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2": "Aave V3 Pool",
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8": "Balancer Vault",
    "0x1F98431c8aD98523631AE4a59f267346ea31F984": "Uniswap V3 Factory",
    "0x00000000219ab540356cBB839Cbe05303d7705Fa": "ETH2 Deposit Contract",
}

# Flash Loan 관련 이벤트 시그니처 (keccak256 해시)
# 이 해시값들은 각 프로토콜의 FlashLoan 이벤트 ABI의 keccak256 해시
FLASH_LOAN_SIG = {
    "0x631042c832b07452973831137f2d73e395028b44b250de141e1b9f64f1fe27bb": "Aave FlashLoan",
    "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19e3a20427eec8bf53283b6fb8e95f0": "Balancer FlashLoan",
}


def get_tx_trace(w3: Web3, tx_hash: str) -> Optional[dict]:
    """debug_traceTransaction으로 내부 호출 추적 (아카이브 노드 필요)
    
    일반 RPC 노드는 현재 상태만 보관하지만,
    아카이브 노드는 모든 과거 블록 상태를 보관해 과거 잔액 조회가 가능하다.
    """
    try:
        return w3.manager.request_blocking(
            "debug_traceTransaction",
            [tx_hash, {"tracer": "callTracer"}]
        )
    except Exception as e:
        print(f"[!] trace 불가 (아카이브 노드 필요): {e}", file=sys.stderr)
        return None


def decode_flash_loan_events(w3: Web3, tx_hash: str) -> list[dict]:
    """트랜잭션 수신증(receipt)에서 Flash Loan 이벤트 디코딩
    
    이더리움 이벤트는 로그로 저장되며, topics[0]은 이벤트 시그니처 해시다.
    우리가 알고 있는 Flash Loan 이벤트 시그니처와 비교해 탐지한다.
    """
    events = []
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        for log in receipt['logs']:
            topic0 = log['topics'][0].hex() if log['topics'] else ''
            if topic0 in FLASH_LOAN_SIG:
                events.append({
                    'type': FLASH_LOAN_SIG[topic0],
                    'contract': log['address'],
                    'data': log['data'].hex(),
                })
    except Exception as e:
        print(f"[!] 이벤트 디코딩 실패: {e}", file=sys.stderr)
    return events


def calculate_profit_loss(w3: Web3, tx_hash: str, attacker: str) -> dict:
    """공격자 ETH/토큰 손익 계산
    
    블록 실행 전후 잔액 차이로 순이익을 계산한다.
    가스비를 제외해야 실제 공격으로 인한 이익만 계산된다.
    아카이브 노드가 필요 (과거 블록 잔액 조회).
    """
    try:
        tx = w3.eth.get_transaction(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        block = tx['blockNumber']

        # 블록 실행 전 잔액 vs 실행 후 잔액
        eth_before = w3.eth.get_balance(attacker, block_identifier=block - 1)
        eth_after = w3.eth.get_balance(attacker, block_identifier=block)
        gas_cost = receipt['gasUsed'] * tx.get('gasPrice', 0)

        eth_profit = eth_after - eth_before + gas_cost  # 가스 제외 순이익

        return {
            'eth_profit_wei': eth_profit,
            'eth_profit': float(Web3.from_wei(abs(eth_profit), 'ether')),
            'profit_direction': 'gain' if eth_profit > 0 else 'loss',
            'gas_cost_eth': float(Web3.from_wei(gas_cost, 'ether')),
        }
    except Exception as e:
        return {'error': str(e)}


def analyze_defi_attack(w3: Web3, tx_hash: str, attacker: Optional[str] = None) -> None:
    """DeFi 공격 트랜잭션 종합 분석"""
    print(f"\n{'='*65}")
    print(f"DeFi 공격 트랜잭션 분석")
    print(f"Hash: {tx_hash}")
    print(f"{'='*65}\n")

    try:
        tx = w3.eth.get_transaction(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except Exception as e:
        print(f"[!] 트랜잭션 조회 실패: {e}")
        return

    # 기본 정보
    print("[기본 정보]")
    print(f"  블록      : {tx.get('blockNumber')}")
    print(f"  발신자    : {tx['from']}")
    to_name = KNOWN_PROTOCOLS.get(tx.get('to', ''), tx.get('to', 'N/A'))
    print(f"  수신자    : {to_name}")
    print(f"  ETH 전송  : {float(Web3.from_wei(tx['value'], 'ether')):.4f} ETH")
    print(f"  가스 사용 : {receipt['gasUsed']:,}")
    # 가스 사용량이 많을수록 복잡한 트랜잭션 — DeFi 공격은 보통 수십만 단위
    print(f"  상태      : {'성공' if receipt['status'] == 1 else '실패'}")

    # Flash Loan 탐지
    flash_events = decode_flash_loan_events(w3, tx_hash)
    if flash_events:
        print(f"\n[Flash Loan 탐지 — {len(flash_events)}건]")
        for e in flash_events:
            print(f"  프로토콜: {e['type']}")
            print(f"  컨트랙트: {e['contract']}")
    else:
        print("\n[Flash Loan] 탐지 없음")

    # 손익 분석 (공격자 주소 제공 시)
    if attacker:
        print(f"\n[손익 분석] 주소: {attacker}")
        pnl = calculate_profit_loss(w3, tx_hash, attacker)
        if 'error' not in pnl:
            direction = "이익" if pnl['profit_direction'] == 'gain' else "손실"
            print(f"  ETH {direction}: {pnl['eth_profit']:.4f} ETH")
            print(f"  가스 비용: {pnl['gas_cost_eth']:.4f} ETH")
        else:
            print(f"  분석 실패 (아카이브 노드 필요): {pnl['error']}")


def scan_flash_loan_txs(w3: Web3, start_block: int, end_block: int) -> list[str]:
    """블록 범위에서 Flash Loan 트랜잭션 탐색 (이벤트 필터 방식)
    
    이더리움 이벤트 필터를 사용해 특정 블록 범위에서
    알려진 Flash Loan 이벤트 시그니처를 가진 트랜잭션을 찾는다.
    """
    flash_hashes = []
    for sig in FLASH_LOAN_SIG:
        try:
            logs = w3.eth.get_logs({
                'fromBlock': start_block,
                'toBlock': end_block,
                'topics': [sig],
            })
            for log in logs:
                flash_hashes.append(log['transactionHash'].hex())
        except Exception as e:
            print(f"[!] 로그 조회 실패: {e}", file=sys.stderr)

    return list(set(flash_hashes))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DeFi 공격 트랜잭션 분석 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s analyze 0xabc...def --rpc https://mainnet.infura.io/v3/KEY
  %(prog)s analyze 0xabc...def --attacker 0x123...456 --rpc https://...
  %(prog)s scan --start 16000000 --end 16001000 --rpc https://...
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="단일 트랜잭션 분석")
    analyze_p.add_argument("tx_hash", help="트랜잭션 해시")
    analyze_p.add_argument("--attacker", help="공격자 주소 (손익 계산용)")
    analyze_p.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY",
                           help="Ethereum RPC 엔드포인트")

    scan_p = sub.add_parser("scan", help="블록 범위 Flash Loan 스캔")
    scan_p.add_argument("--start", type=int, required=True, help="시작 블록 번호")
    scan_p.add_argument("--end", type=int, required=True, help="끝 블록 번호")
    scan_p.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY",
                        help="Ethereum RPC 엔드포인트")

    args = parser.parse_args()
    w3 = Web3(Web3.HTTPProvider(args.rpc))

    if not w3.is_connected():
        print("[!] RPC 연결 실패", file=sys.stderr)
        sys.exit(1)

    if args.command == "analyze":
        analyze_defi_attack(w3, args.tx_hash, args.attacker)

    elif args.command == "scan":
        print(f"[*] Flash Loan 스캔: 블록 {args.start}~{args.end}")
        hashes = scan_flash_loan_txs(w3, args.start, args.end)
        print(f"[+] 발견: {len(hashes)}건")
        for h in hashes:
            print(f"  {h}")


if __name__ == "__main__":
    main()
```

---

## 2. 오라클 가격 조작 공격

### 2.1 오라클이란? — "DeFi의 눈"

스마트 컨트랙트는 블록체인 외부 정보를 직접 볼 수 없다. ETH의 현재 달러 가격, 금 시세, 날씨 등 실세계 데이터가 필요하면 **오라클(Oracle)**이라는 중간 서비스를 통해 데이터를 가져온다.

**오라클의 종류:**
- **온체인 오라클 (Spot Price):** Uniswap 같은 DEX의 현재 가격을 직접 읽음 → 조작 쉬움
- **TWAP (Time-Weighted Average Price):** 시간 가중 평균 가격 → 단기 조작 어려움
- **Chainlink:** 여러 외부 가격 데이터 제공자가 합의한 가격 → 가장 안전

```
Spot Price 문제:
  현재 ETH 가격 = DEX의 현재 준비금 비율
  만약 Flash Loan으로 ETH 대량 매수 → DEX 가격 급등
  → 같은 트랜잭션에서 조작된 가격을 오라클로 신뢰하는 프로토콜 공격 가능
  
TWAP의 방어 원리:
  30분 평균 가격을 사용 → 단 1개 블록(~12초)에서 조작해도 의미 없음
  1000% 가격을 30분 동안 유지하려면 막대한 자본이 계속 묶여 있어야 함
  → 비경제적 (이자 손실 > 공격 이익)
```

### 2.2 CREAM Finance 공격 (2021, ~$130M)

```
공격 개요: Spot Price 오라클 조작

공격 시퀀스:
1. Flash Loan으로 대량 ETH 확보
2. Uniswap ETH/crETH 풀에서 대량 ETH 매수
   → crETH 가격이 Uniswap에서 급등 (예: 300% 상승)
3. Cream Finance가 조작된 Uniswap spot price를 신뢰
   → 조작된 가격 기준으로 최대 담보 대출 실행
   → 실제 가치보다 3배 많은 자금 대출 가능
4. 대출 자금 인출 후 crETH 매도 → 가격 정상화
5. Flash Loan 상환
6. 담보보다 많은 자산 탈취 완료

핵심 교훈:
  단일 DEX의 spot price는 단일 트랜잭션으로 조작 가능
  → 최소 TWAP 30분 이상, 또는 Chainlink 사용 필수
```

### 2.3 Compound 오라클 사건 (2021)

```
사건 유형: 오라클 가격 편차 (의도적 조작은 아님)

발생 경위:
  Compound는 Coinbase Pro API를 단일 오라클로 사용
  DAI/USD 가격이 Coinbase에서 일시적으로 $1.30으로 폭등
  (정상 가격: $1.00)
  
결과:
  Compound에서 DAI 담보로 과도한 대출 실행
  자동 청산 봇들이 대거 청산 실행
  정상적인 사용자들이 예상치 못한 청산 피해
  총 피해: ~$100M 규모 청산

교훈:
  단일 오라클 의존은 위험
  여러 오라클 소스의 중앙값(median) 사용 필요
  가격 급변 시 circuit breaker(서킷 브레이커) 필요
```

### 2.4 방어: 안전한 오라클 설계

```solidity
// 취약: spot price 사용
function getPrice() external view returns (uint256) {
    (uint112 r0, uint112 r1,) = uniswapPair.getReserves();
    return r0 * 1e18 / r1;  // 즉시 조작 가능
}

// 안전: Chainlink 가격 피드
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface priceFeed;

function getPrice() external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    // stale price 체크 (1시간 이상 업데이트 없으면 거부)
    require(block.timestamp - updatedAt < 3600, "stale price");
    require(price > 0, "invalid price");
    return uint256(price);
}

// 더 안전: 여러 오라클 평균 + 편차 체크
function getSafePrice() external view returns (uint256) {
    uint256 chainlinkPrice = getChainlinkPrice();
    uint256 twapPrice = getUniswapTWAP(1800);  // 30분 TWAP

    // 두 가격의 편차가 10% 이상이면 거부 (이상 상황)
    uint256 deviation = chainlinkPrice > twapPrice
        ? ((chainlinkPrice - twapPrice) * 100) / twapPrice
        : ((twapPrice - chainlinkPrice) * 100) / chainlinkPrice;

    require(deviation < 10, "price deviation too high");
    return (chainlinkPrice + twapPrice) / 2;  // 평균값 사용
}
```

---

## 3. MEV (Maximal Extractable Value) — 블록체인의 보이지 않는 세금

### 3.1 멤풀(Mempool)이란?

트랜잭션을 블록체인에 제출하면 즉시 블록에 포함되지 않는다. 블록에 포함되기 전까지 **멤풀(Memory Pool)**이라는 대기실에 머문다.

```
사용자가 트랜잭션 제출
         ↓
[멤풀 — 공개된 대기실]  ← 모든 노드가 이 내용을 볼 수 있음
         ↓                (어떤 주소가 어떤 토큰을 얼마나 스왑하는지 다 보임)
마이너/검증자가 트랜잭션 선택 (보통 가스비 높은 순)
         ↓
블록에 포함 → 확정

멤풀은 공개다 → MEV 봇들이 24시간 모니터링
피해자가 큰 스왑을 하려 한다 → 봇이 감지 → 샌드위치 공격
```

**멤풀은 공개다.** 누구나 아직 처리되지 않은 트랜잭션의 내용을 볼 수 있다. MEV 봇들은 이 멤풀을 24시간 모니터링하며 이익 기회를 찾는다.

### 3.2 트랜잭션 순서 조작 — 마이너의 특권

블록에 트랜잭션을 포함시키는 순서를 결정하는 사람은 마이너(PoW) 또는 검증자(PoS)다. 이 순서를 조작해 추출할 수 있는 최대 이익이 **MEV(Maximal Extractable Value)**다.

**MEV 유형:**
- **아비트리지:** A 거래소보다 B 거래소 가격이 높을 때 끼어들어 차익 실현
- **청산:** 담보가 부족한 포지션을 청산하는 트랜잭션을 앞질러 청산 보너스 획득
- **샌드위치 공격:** 피해자의 대형 스왑 트랜잭션을 앞뒤로 끼워 이익 추출
- **JIT(Just-In-Time) 유동성:** 대형 스왑 직전에 유동성을 공급해 수수료를 독점하고 직후 회수

### 3.3 샌드위치 공격 — 상세 메커니즘

```
상황: 피해자가 멤풀에 "1,000 ETH → USDC" 스왑 트랜잭션 제출
      (슬리피지 허용 0.5%)
      
AMM 원리: 유동성 풀에서 x*y=k 공식으로 가격 결정
         대량 매수 → 해당 토큰 가격 상승 (수요 증가)

봇의 행동:

[전 단계] 봇이 멤풀에서 피해자 트랜잭션 감지
           ↓
[1] 프론트런 (Front-run):
    봇이 먼저 "100 ETH 매수" 트랜잭션 제출
    - 가스비를 피해자보다 높게 설정 (마이너 우선 처리 유도)
    - 이로 인해 ETH 가격 상승 (예: $1000 → $1050)
    ─────────────────────────────────────────────
    블록 순서: [봇 프론트런 tx] → [피해자 tx] → [봇 백런 tx]
    ─────────────────────────────────────────────
           ↓
[2] 피해자 트랜잭션 실행:
    - 이미 가격이 올라간 상태에서 ETH 매수
    - 허용 슬리피지 내에서 손해 보며 스왑
    - 피해자가 받는 USDC 감소
           ↓
[3] 백런 (Back-run):
    봇이 "100 ETH 매도"
    - 피해자 때문에 ETH 가격이 더 오른 상태
    - 높은 가격에 매도 → 차익 실현
           ↓
[결과] 봇의 순이익 = (매도 가격 - 매수 가격) × 수량 - 가스비
      피해자의 손해 = 슬리피지만큼 손해 + 기회비용
```

실제 데이터: MEV-Explore 통계에 따르면 이더리움에서 MEV로 추출된 누적 금액은 수십억 달러에 달한다.

### 3.4 Flashbots MEV 방어

```python
# MEV 방지: Flashbots Private RPC 사용
# 트랜잭션이 공개 멤풀에 노출되지 않음
# 마이너와 직접 번들로 제출

# 일반 방식 (취약)
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/KEY"))
w3.eth.send_transaction(tx)  # 멤풀에 공개됨 → MEV 봇 먹잇감

# Flashbots 방식 (MEV 방어)
w3_private = Web3(Web3.HTTPProvider("https://rpc.flashbots.net"))
# 트랜잭션이 공개 멤풀 우회 → Flashbots 릴레이를 통해 마이너에게 직접 전달

# 추가 방어 전략:
# 1. 슬리피지 허용치를 최소화 (공격 채산성 감소)
# 2. DEX 애그리게이터 사용 (분할 라우팅으로 MEV 감소)
# 3. CoW Protocol(Coincidence of Wants) 사용 — P2P 매칭
```

---

## 4. 실제 DeFi 해킹 사례 — 추가 분석

### 4.1 Nomad Bridge 해킹 (2022, $190M) — 역사상 가장 독특한 해킹

```
날짜: 2022년 8월 1일
피해액: $190,000,000
특이점: 단 한 명의 공격자가 아닌, 수백 명의 '편승자'가 함께 탈취

공격 원리:
  Nomad Bridge는 체인 간 자산 이전 브리지
  업그레이드 중 잘못된 초기화:
    prove() 함수에서 신뢰할 수 있는 루트 값이 0x0으로 설정됨
    → 어떤 메시지든 "루트가 0x0이다"라고 증명하면 유효로 간주
    → 아무 메시지나 '복사-붙여넣기'하여 자산 탈취 가능

진행 과정:
  1. 첫 공격자가 취약점 발견, 트랜잭션으로 자산 탈취
  2. 다른 사람들이 이 트랜잭션을 보고 단순히 복사
  3. 토큰 주소만 바꿔서 같은 트랜잭션 재전송
  4. 수백 명이 순서대로 자산을 가져감 (무정부 상태)

이 사례가 특별한 이유:
  고급 해킹 기술 불필요 — 트랜잭션 복사만으로 가능
  "화이트햇" 해커들도 일부 자금 보호를 명목으로 참여
  법적으로 해커와 구분이 어려운 회색 지대
```

### 4.2 Poly Network 해킹 (2021, $611M — 역대 최대 DeFi 해킹)

```
날짜: 2021년 8월 10일
피해액: $611,000,000 (당시 역대 최대 크립토 해킹)
결말: 공격자가 자금 전액 반환 (놀라운 결말)

배경:
  Poly Network는 여러 블록체인(이더리움, BSC, Polygon)을 연결하는
  크로스체인 프로토콜이다.
  
취약점: 크로스체인 메시지 검증 로직 결함

공격 원리:
  Poly Network는 크로스체인 자산 이전을 처리하는 특수 컨트랙트를 사용
  이 컨트랙트에는 크로스체인 메시지를 처리하는 Keeper 주소가 있음
  
  공격자가 발견한 것:
  EthCrossChainManager 컨트랙트의 verifyHeaderAndExecuteTx() 함수
  → 이 함수는 크로스체인 메시지를 받아 특정 함수를 실행
  → 메시지 파라미터를 조작해 임의의 함수 호출 가능
  
  구체적 공격:
  1. BSC에서 조작된 크로스체인 메시지 생성
     "EthCrossChainData 컨트랙트의 Keeper를 공격자 주소로 변경하라"
  2. 이 메시지가 이더리움의 EthCrossChainManager에 전달
  3. putCurEpochConPubKeyBytes() 함수가 공격자 주소를 Keeper로 등록
  4. 공격자가 Keeper 권한으로 자금 인출

각 체인별 피해:
  이더리움: $273M
  BSC: $253M
  Polygon: $85M

놀라운 결말:
  공격자는 해킹 직후 온체인 메시지로 소통
  "재미로 한 것, 이 규모의 해킹을 감당할 준비가 안 됨"
  며칠 후 $611M 전액 반환
  Poly Network는 공격자에게 "화이트햇 버그바운티" $500K 제안
  
교훈:
  크로스체인 프로토콜은 체인 간 신뢰 경계를 명확히 해야 함
  임의 함수 호출을 허용하는 메시지 처리 로직은 극히 위험
  접근 제어가 프로토콜의 핵심 보안 메커니즘
```

### 4.3 Ronin Bridge 해킹 (2022, $625M — 역대 최대 크립토 해킹)

```
날짜: 2022년 3월 23일 (발견: 2022년 3월 29일)
피해액: $625,000,000 (ETH 173,600개 + USDC 25.5M)
공격자: Lazarus Group (북한 국가 지원 해킹 조직)

배경:
  Ronin은 인기 블록체인 게임 Axie Infinity의 사이드체인
  Sky Mavis가 운영, 최고점 기준 수백만 사용자

Ronin 검증자 시스템:
  Ronin은 9개의 검증자(validator) 노드로 구성
  자산 인출에는 9개 중 5개(과반수) 서명이 필요 (멀티시그)
  이 설계가 중앙화 위험을 내포

공격 원리: 사회공학 + 검증자 키 탈취

공격 과정:
  Phase 1 (준비):
    Lazarus Group이 Axie Infinity 개발자들을 타겟팅
    링크드인에서 가짜 고액 연봉 채용 제안
    지원자에게 악성코드가 포함된 PDF "채용 공고" 전송
    Sky Mavis 직원 클릭 → 내부 시스템 접근 확보
    
  Phase 2 (키 탈취):
    내부 시스템에서 Sky Mavis 소유의 4개 검증자 키 탈취
    (Sky Mavis가 직접 운영하는 검증자 4개)
    
  Phase 3 (5번째 키):
    Axie DAO 검증자 — 별도 조직이 운영
    과거 Sky Mavis에 위임된 서명 권한이 취소되지 않음
    (Gas-free RPC로 인해 임시 부여된 권한이 방치됨)
    이 5번째 키도 탈취 → 과반수(5/9) 확보
    
  Phase 4 (자금 인출):
    5개 검증자 서명으로 173,600 ETH 인출 (2회 트랜잭션)
    6일 후에야 발견 (모니터링 부재)

피해 규모 맥락:
  당시 역대 최대 크립토 해킹
  Axie Infinity 생태계 붕괴, 사용자 엑소더스
  
대응:
  미국 재무부 OFAC이 Lazarus Group 관련 주소 제재
  Binance 등 거래소가 해당 주소 동결 협조
  Ronin은 $625M 중 상당 부분을 투자자 지원으로 보전

교훈:
  멀티시그는 검증자 키가 독립적으로 분리되어야 의미 있음
  권한 위임은 사용 후 반드시 취소해야 함
  사이드체인의 중앙화는 치명적 단일 실패 지점(SPOF)
  소셜 엔지니어링이 기술적 취약점만큼 위험
  모니터링 없는 대규모 자금 관리는 위험
```

### 4.4 해킹 사례 비교표

| 프로토콜 | 날짜 | 피해액 | 공격 유형 | 핵심 취약점 |
|---------|------|--------|----------|------------|
| bZx | 2020.02 | $350K | Flash Loan + 오라클 조작 | Spot price 신뢰 |
| Cream Finance | 2021.10 | $130M | Flash Loan + 오라클 조작 | Spot price 신뢰 |
| Compound | 2021.11 | $100M | 오라클 편차 | 단일 오라클 의존 |
| Poly Network | 2021.08 | $611M | 크로스체인 로직 버그 | 임의 함수 호출 허용 |
| Nomad Bridge | 2022.08 | $190M | 로직 버그 | 잘못된 초기화 |
| Ronin Bridge | 2022.03 | $625M | 검증자 키 탈취 | 중앙화된 멀티시그 |
| Euler Finance | 2023.03 | $197M | Flash Loan + 로직 버그 | 건강지수 체크 미흡 |

---

## 5. MEV 더 깊이 이해하기 — 블록체인 경제학

### 5.1 MEV의 경제 규모

MEV는 단순한 해킹이 아니다. 이더리움 생태계에서 구조적으로 발생하는 경제적 가치 추출이다.

```
MEV 유형별 규모 (2020-2023 누적 추정):
  아비트리지:      $500M+  (가장 큰 비중)
  청산:           $200M+
  샌드위치 공격:   $100M+
  기타:           $100M+
  총계:           $1B+ 이상

MEV 추출자:
  - 개인 MEV 봇 운영자 (대부분의 수익)
  - 마이너/검증자 (블록 구성 권한 활용)
  - Flashbots 등 MEV 인프라 제공자
```

### 5.2 MEV가 사용자에게 미치는 영향

**일반 DeFi 사용자 관점:**
- 대형 스왑 시 예상보다 나쁜 가격 받음 (샌드위치 공격)
- 청산 기준점 바로 위에서 포지션 유지 시 MEV 봇 먹잇감
- 인기 있는 NFT 민팅 시 가스 경쟁에서 뒤처짐

**MEV의 양면성:**
```
긍정적 측면:
  - 아비트리지 MEV → 거래소 간 가격 균일화 기여
  - 청산 MEV → 프로토콜의 담보 건전성 유지
  
부정적 측면:
  - 샌드위치 공격 → 일반 사용자 직접 피해
  - 가스 전쟁 → 네트워크 혼잡
  - 블록 재구성 동기 → 합의 안전성 위협
```

---

## 6. DeFi 보안 감사 방법론

### 6.1 감사 전 준비

스마트 컨트랙트 보안 감사는 일반 소프트웨어 보안 감사와 다르다. DeFi 특유의 공격 벡터를 이해하고 체계적으로 접근해야 한다.

```
감사 준비 체크리스트:
  □ 프로토콜 문서 및 설계 명세 확보
  □ 이전 감사 보고서 검토 (재감사인 경우)
  □ 유사 프로토콜 해킹 사례 연구
  □ 개발팀과 프로토콜 철학 인터뷰
  □ 테스트 환경 구성 (Hardhat/Foundry 포크 테스트)
```

### 6.2 수동 코드 리뷰 절차

```
1단계: 아키텍처 분석
  - 프로토콜의 전체 상태 머신 파악
  - 외부 호출(external call) 경로 추적
  - 권한 모델 (access control) 검토
  - 업그레이더빌리티 패턴 확인

2단계: 비즈니스 로직 검증
  - 경제적 불변량(invariant) 식별
    예: "총 담보 >= 총 대출" 항상 참이어야 함
  - 경계값 케이스 테스트
  - 정수 오버플로우/언더플로우 확인

3단계: DeFi 특화 취약점 점검
  - 재진입(Reentrancy) 공격 가능성
  - Flash Loan 공격 표면
  - 오라클 조작 가능성
  - 청산 메커니즘 건전성

4단계: 자동화 도구 실행
  - Slither: 정적 분석
  - Echidna: 퍼징 테스트
  - Manticore: 심볼릭 실행
  - Mythril: 취약점 패턴 탐지
```

### 6.3 자동화 감사 도구 사용

```bash
# Slither로 정적 분석
slither contracts/ --detect reentrancy-eth,oracle-manipulation \
  --json report.json

# 중앙화 위험 탐지
slither token.sol --detect centralization-risk,suicidal,controlled-delegatecall

# Echidna 퍼징 테스트 (invariant 검증)
# 설정 파일 작성 후:
echidna-test contracts/Protocol.sol --config echidna.yaml

# Foundry 포크 테스트 (실제 메인넷 상태에서 테스트)
forge test --fork-url https://mainnet.infura.io/v3/KEY \
  --match-test testFlashLoanScenario -vvv
```

---

## 7. Rug Pull 패턴 탐지

| 패턴 | 설명 | 탐지 방법 |
|------|------|----------|
| Mint 권한 | owner가 토큰 무한 민팅 가능 | 코드 감사: `onlyOwner` + `mint()` |
| 거래 금지 | owner가 전송 비활성화 | `transferAllowed` 변수 확인 |
| 숨겨진 수수료 | 전송 시 90% 소각 | 전송 함수 세금 로직 확인 |
| LP 회수 | 유동성 갑작스런 제거 | LP 토큰 잠금 여부 확인 |
| 소유권 미포기 | Ownable에서 소유권 유지 | `owner()` 주소 확인 |
| 시간 잠금 없음 | 관리자 기능에 타임락 없음 | 업그레이드 딜레이 확인 |
| 백도어 함수 | 숨겨진 drain() 등 함수 | 모든 외부 함수 목록화 |

```bash
# Slither로 중앙화 위험 탐지
slither token.sol --detect centralization-risk,suicidal,controlled-delegatecall

# 토큰 민팅 권한 확인
slither token.sol --detect arbitrary-send-eth,controlled-delegatecall

# 소유권 확인 (온체인)
cast call TOKEN_ADDRESS "owner()(address)" --rpc-url https://mainnet.infura.io/v3/KEY
```

---

## 8. 스마트 컨트랙트 취약점 체크리스트

### 8.1 재진입(Reentrancy) 취약점

```
취약한 패턴:
  1. 외부 컨트랙트 호출
  2. 상태 변경
  
  공격자가 1번 호출 중 다시 이 함수 재호출 가능
  → 상태가 아직 변경 전이므로 중복 인출 가능

안전한 패턴 (Checks-Effects-Interactions):
  1. 검사 (require 조건 확인)
  2. 상태 변경 (잔액 차감 등)
  3. 외부 호출 (ETH 전송)
  
  상태를 먼저 변경 → 재진입해도 이미 0이므로 인출 불가
```

### 8.2 완전한 취약점 체크리스트

```
[ ] 재진입 공격 (Reentrancy)
    - CEI 패턴 준수 확인
    - ReentrancyGuard 사용 여부

[ ] 정수 오버플로우/언더플로우
    - Solidity 0.8.0+ 사용 (내장 체크)
    - SafeMath 라이브러리 사용 여부

[ ] 오라클 조작
    - Spot price 사용 금지
    - TWAP 또는 Chainlink 사용
    - 다중 오라클 소스 및 편차 체크

[ ] Flash Loan 취약점
    - 단일 트랜잭션 가격 조작 방어
    - 상태 변경 전 잔액 체크

[ ] 접근 제어 (Access Control)
    - onlyOwner 함수 목록화
    - 타임락 적용 여부
    - 다중 서명 요구사항

[ ] 청산 메커니즘
    - 건강지수 체크 완전성
    - 청산 루프 gas limit 안전성

[ ] 업그레이더빌리티
    - 프록시 패턴 보안성
    - 스토리지 충돌 가능성
    - 초기화 함수 재호출 방지

[ ] 경제 모델
    - 인플레이션/디플레이션 로직
    - 청산 cascade 시나리오
    - 극단적 시장 상황 시뮬레이션
    
[ ] 크로스체인 (브리지 프로토콜)
    - 메시지 검증 로직 완전성
    - 임의 함수 호출 방지
    - 검증자 키 분리 및 독립성
    - 권한 위임 취소 메커니즘
```

---

<a name="english"></a>

# DeFi Protocol Attack Techniques

## Learning Objectives

After completing this document, you will be able to:

- Explain blockchain, smart contracts, and DeFi to a complete beginner using plain language
- Understand why Flash Loans can borrow hundreds of millions without collateral
- Describe how oracle manipulation tricks protocols into releasing excess funds
- Analyze MEV and sandwich attack mechanics in detail
- Identify common patterns across real DeFi hacks (bZx, Euler, Nomad, Poly Network, Ronin)
- Use Python + Web3.py to trace and analyze on-chain attack transactions
- Apply a DeFi protocol security audit checklist

---

## DeFi Fundamentals — What You Need to Know Before Studying Attacks

### What is a Blockchain?

A blockchain is a **distributed database where thousands of computers share the same ledger**. A bank keeps its records on its own servers — if those servers are compromised, the records can be altered. A blockchain has thousands of nodes simultaneously holding identical records. To alter a record, you would need to control more than 51% of the network simultaneously, which is practically impossible.

**Real-world analogy:** A bank ledger is a single book locked in a vault. A blockchain ledger is the same content simultaneously recorded by thousands of people across the world. To change one person's record, you must change all the others at the same time.

```
Centralized (bank):          Decentralized (blockchain):
[Bank Server]                [Node1] [Node2] [Node3] ... [NodeN]
     ↑                           ↑       ↑       ↑            ↑
 Single ledger               All hold identical ledgers
 (hack one server =          (must compromise 51%+ simultaneously)
  can manipulate records)
```

**Key properties:**
- **Immutability**: Recorded transactions cannot be modified
- **Transparency**: All transactions are publicly visible to anyone
- **Instant Finality**: Once confirmed, transactions cannot be reversed

**What is Gas?** On Ethereum, every computation consumes "gas" — a fee paid to validators. More complex smart contract calls consume more gas. Higher gas fees cause miners/validators to prioritize those transactions. This gas fee competition is central to MEV attacks.

**Wallets and Private Keys:** On a blockchain, ownership of assets is proven by a private key. Lose the private key and you permanently lose access to the assets. "Not your keys, not your crypto" is a cardinal rule.

### What is a Smart Contract?

A smart contract is an **automatically executing program deployed on a blockchain**. Ordinary contracts require lawyers or courts to enforce them. Smart contracts execute automatically when conditions are met — the code itself is the enforcement mechanism.

**Vending machine analogy:** A smart contract works like a vending machine. Insert a coin (meet the condition) and a drink comes out (code executes) automatically. No human needs to be involved, and the rules cannot be bent. However, if the vending machine itself has a flaw, that flaw can be exploited.

**Real estate analogy:**
- Normal contract: "Transfer ownership when buyer pays $300,000" — enforced by courts
- Smart contract: Same condition, but code automatically receives ETH and transfers the ownership NFT — no human needed

```solidity
// Simple escrow smart contract example
// Once deployed to the blockchain, nobody can modify or stop this
contract Escrow {
    address public buyer;
    address public seller;
    uint256 public price;

    // When buyer sends ETH, it's automatically forwarded to the seller
    // "require" checks conditions — if false, the entire transaction reverts
    function release() external payable {
        require(msg.sender == buyer, "Only buyer can call this");
        require(msg.value == price, "Incorrect amount");
        payable(seller).transfer(msg.value);  // Executes automatically, no human
    }
}
```

**Smart contract properties that matter for security:**
- Deployed code cannot be changed (Immutable) — bugs are permanent
- Anyone can read the code — attackers scan for vulnerabilities
- Runs 24/7 without any human intervention

### What is DeFi? — "Banking Without Banks"

**DeFi (Decentralized Finance) is financial services without a bank — code plays the role of the bank.**

Traditional finance relies on banks for loans, interest, and currency exchange, with banks collecting fees as intermediaries. DeFi replaces all these functions with smart contracts. No bank account, no credit score, and no identity documents are required. An internet connection and an Ethereum wallet are enough.

| Traditional Finance | DeFi Equivalent | Description |
|---------------------|----------------|-------------|
| Bank loans | Aave, Compound | Deposit collateral, borrow another token |
| Currency exchange | Uniswap, Curve | Automated token swaps (AMM model) |
| Derivatives trading | dYdX, GMX | Leveraged trading, perpetual futures |
| Investment funds | Yearn Finance | Automated yield optimization |
| Yield farming | Various protocols | Earn interest by providing liquidity |

**DeFi scale:** At its 2021 peak, TVL (Total Value Locked) exceeded $180 billion. All of this money sits locked in smart contract code — making it one of the highest-value attack surfaces in the world.

### Composability — "Money Legos"

DeFi protocols can be combined like Lego blocks. Each protocol is designed to interoperate with others. This is DeFi's greatest strength and its greatest attack surface.

```
[Borrow ETH from Aave]
    → [Swap ETH→USDC on Uniswap]
        → [Supply USDC to Curve]
            → [Optimize yield with Yearn]
                → [Use as collateral on Compound]
                    → All within a single transaction!
```

This composability is the foundation of Flash Loan attacks. Combining multiple protocols in one transaction creates enormous, temporary purchasing power.

---

## Why is DeFi a Hacker's Target?

### Reason 1: Code is Immutable — Bugs are Permanent

Traditional software can be patched when vulnerabilities are found. DeFi smart contracts **cannot be modified after deployment**. Some use upgradeable proxy patterns, but these introduce their own attack surfaces.

```
Traditional web service: Bug found → Fix code → Redeploy (hours)
DeFi smart contract:     Bug found → ??? (there is already $100M locked in the contract)
```

Developers face enormous pressure to write perfect code before deployment. In practice, bugs still emerge through complex protocol interactions even after passing audits.

### Reason 2: Instant Finality — No Chargebacks

Bank transfers have processing windows during which fraud can be reversed. Blockchain transactions are **permanent once confirmed**. Even if a hacker steals $625M, law enforcement has no mechanism to reverse the transaction.

The one exception: After the 2016 DAO hack, the Ethereum community executed a hard fork to reverse transactions — which is why Ethereum (ETH) and Ethereum Classic (ETC) exist as separate chains today. The community has never done this since.

### Reason 3: Composability — Attack Surface Grows Exponentially

Protocols A, B, and C may each be individually secure, but their combination A+B+C may introduce new vulnerabilities. Flash Loans exploit this composability to weaponize hundreds of millions of dollars in a single transaction.

### Reason 4: Open Source — Attackers Can Read the Code Too

All smart contract code is public on the blockchain. Security audit reports are often published as well. Attackers sometimes combine "low severity" findings from audit reports to design high-impact attacks.

### Reason 5: Massive Funds Concentrated in Code

A single DeFi protocol can hold billions of dollars. A traditional bank robbery is physically constrained — DeFi hacks can move hundreds of millions globally in seconds. Security investment rarely keeps pace with the value at stake.

---

## 1. Flash Loan Attacks

### 1.1 What is Transaction Atomicity?

To understand Flash Loans, you must first understand **transaction atomicity**.

An atomic transaction is one that either **completely succeeds or completely fails** — there is no intermediate state.

```
Example: Bank transfer
  Step 1: Deduct 1,000,000 KRW from account A
  Step 2: Add 1,000,000 KRW to account B

  If step 2 fails → step 1 is also rolled back (money doesn't disappear)
  This is atomicity.
  
  Without atomicity → money could disappear from A but never arrive at B
```

Blockchain smart contract transactions are atomic. **All steps must succeed** for the transaction to be finalized. If any step fails, all state changes revert as if nothing happened.

### 1.2 How Flash Loans Work

Flash Loans are special loans that exploit atomicity.

```
Executed within a single atomic transaction:
┌──────────────────────────────────────────────────────────┐
│  1. Borrow 10,000 ETH from Aave (fee: 0.09%)            │
│  2. Execute desired operations with borrowed funds       │
│     (arbitrage, price manipulation, liquidation, etc.)  │
│  3. Repay principal + fee                               │
│                                                         │
│  Repayment success → transaction finalizes (profit kept)│
│  Repayment failure → entire revert (loan never happened)│
└──────────────────────────────────────────────────────────┘
```

**Why is this dangerous?**

Normal loans require collateral. To borrow $100M, you must pledge $100M in assets. Flash Loans require no collateral — you only need to repay within the same transaction.

This means: someone with zero capital can have hundreds of millions of dollars in purchasing power for a single transaction. If they manipulate the market and profit enough to repay the principal and fee, they keep the difference.

**Flash Loans are not inherently evil:**
- **Arbitrage:** Exploiting price differences between exchanges — helps equalize market prices
- **Collateral swaps:** Temporarily replace one collateral type with another in one atomic step
- **Liquidations:** Help maintain protocol health by liquidating undercollateralized positions

### 1.3 Flash Loan Attack Flow — ASCII Diagram

```
Attacker wallet (starting capital ≈ $0)
    │
    │  ════════ Single Ethereum Transaction Begins ════════
    ▼
[Attacker's deployed smart contract]
    │
    │ Step 1: Request Flash Loan
    ├─→ [Aave Protocol]
    │       │ "Lend me 10,000 ETH (I'll repay within this transaction)"
    │       └─→ 10,000 ETH transferred ────→ [Attack Contract]
    │                                   (contract balance: 10,000 ETH)
    │
    │ Step 2: Manipulate price
    ├─→ [Uniswap V2 Pool]
    │       │ "Buy target token with 10,000 ETH (mass purchase)"
    │       └─→ Token price spikes +300%
    │           (AMM formula x*y=k: large buy → price explodes)
    │
    │ Step 3: Exploit the manipulated price
    ├─→ [Vulnerable DeFi Protocol]
    │       │ Protocol uses Uniswap spot price as its oracle
    │       │ "Give me a loan with token as collateral"
    │       └─→ Loan issued at 3x real value ───→ [Attack Contract]
    │
    │ Step 4: Normalize price
    ├─→ [Uniswap V2 Pool]
    │       │ "Sell the tokens I bought earlier"
    │       └─→ Price returns to normal
    │
    │ Step 5: Repay Flash Loan
    ├─→ [Aave Protocol]
    │       │ Repay 10,000 ETH + fee (9 ETH)
    │       └─→ Repayment confirmed ✓
    │
    │ Step 6: Collect profit
    └─→ [Attacker wallet]
            Stolen loan proceeds - Flash Loan fee = net profit
    
    ════════ Transaction Finalizes (within seconds) ════════
    
    Result: Started with ~$0, walked away with millions
```

### 1.4 bZx Hack (2020, $350K — The First Flash Loan Attack)

```
Date: February 15, 2020
Loss: $350,000
Historical significance: The first Flash Loan attack; changed DeFi security forever

Attack sequence (with explanation of each step):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 1: Borrow 10,000 ETH Flash Loan from dYdX
   └─ dYdX offered free Flash Loans at the time

Step 2: Borrow 112 WBTC from Compound (ETH as collateral)
   └─ Normal collateralized loan — legitimate up to here

Step 3: Open WBTC short position on bZx using 5,500 ETH
   └─ bZx buys WBTC from Uniswap with high slippage
   └─ WBTC/ETH price drops sharply on Uniswap

Step 4: Liquidate Compound position
   └─ WBTC price fell on Uniswap = Compound collateral value fell
   └─ Execute Compound liquidation at manipulated price → profit

Step 5: Repay dYdX Flash Loan

Root cause:
  bZx used Uniswap spot price directly as its oracle
  → Price can be manipulated within a single transaction
  → Manipulating price and attacking a protocol that trusts that price
    all happen in the same atomic transaction

Impact:
  After this attack, the entire DeFi industry reconsidered oracle design
  TWAP (Time-Weighted Average Price) became the new standard
  "Flash Loan attack" established as a new attack category
```

### 1.5 Euler Finance Hack (2023, $197M)

```
Date: March 13, 2023
Loss: $197,000,000
Notable: Attacker later returned most of the funds

Attack sequence:
1. Flash Loan 30M DAI from Aave
2. Mass buy EUL tokens → mint eDAI (2x leverage)
3. Call the buggy donateToReserves()
   → Donate assets to reserve → own debt increases
   → Health factor drops to liquidatable level
4. Second attack contract executes liquidation
   → Obtains assets including liquidation bonus (10-20%)
5. Repay Flash Loan, keep remainder as profit

Core bug:
  donateToReserves() did not check health factor after execution
  Normal flow: donate → check health factor → decide liquidation
  Buggy flow:  donate → [no check] → liquidatable state persists

Outcome:
  Attacker returned $177M (identity tracked, negotiations occurred)
  Euler Finance paused protocol and conducted re-audit
```

### 1.6 Python Attack Simulation Tracker

```python
#!/usr/bin/env python3
"""DeFi Attack Transaction Tracker and Analysis CLI

Usage:
  python3 defi_tracker.py analyze 0xabc...def --attacker 0x123...456 --rpc https://...
  python3 defi_tracker.py scan --start 16000000 --end 16001000 --rpc https://...
"""

import argparse
import sys
from typing import Optional
from web3 import Web3


# Known DeFi protocol contract addresses (Ethereum Mainnet)
KNOWN_PROTOCOLS = {
    "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9": "Aave V2 LendingPool",
    "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2": "Aave V3 Pool",
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8": "Balancer Vault",
    "0x1F98431c8aD98523631AE4a59f267346ea31F984": "Uniswap V3 Factory",
}

# Flash Loan event signatures (keccak256 hashes of event ABI)
# These are the topic0 values emitted when a Flash Loan executes
FLASH_LOAN_SIG = {
    "0x631042c832b07452973831137f2d73e395028b44b250de141e1b9f64f1fe27bb": "Aave FlashLoan",
    "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19e3a20427eec8bf53283b6fb8e95f0": "Balancer FlashLoan",
}


def decode_flash_loan_events(w3: Web3, tx_hash: str) -> list[dict]:
    """Decode Flash Loan events from a transaction receipt.
    
    Ethereum events are stored as logs. topics[0] is the event signature hash.
    We compare against known Flash Loan event signatures to detect them.
    """
    events = []
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        for log in receipt['logs']:
            topic0 = log['topics'][0].hex() if log['topics'] else ''
            if topic0 in FLASH_LOAN_SIG:
                events.append({
                    'type': FLASH_LOAN_SIG[topic0],
                    'contract': log['address'],
                    'data': log['data'].hex(),
                })
    except Exception as e:
        print(f"[!] Event decoding failed: {e}", file=sys.stderr)
    return events


def calculate_profit_loss(w3: Web3, tx_hash: str, attacker: str) -> dict:
    """Calculate ETH profit/loss for the attacker address.
    
    Compares balance before and after the block containing the transaction.
    Gas costs are subtracted to show profit from the attack itself.
    Requires an archive node (needs historical state queries).
    """
    try:
        tx = w3.eth.get_transaction(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        block = tx['blockNumber']

        # Balance before block vs after block
        eth_before = w3.eth.get_balance(attacker, block_identifier=block - 1)
        eth_after = w3.eth.get_balance(attacker, block_identifier=block)
        gas_cost = receipt['gasUsed'] * tx.get('gasPrice', 0)
        # Add gas cost back to get profit excluding gas
        eth_profit = eth_after - eth_before + gas_cost

        return {
            'eth_profit': float(Web3.from_wei(abs(eth_profit), 'ether')),
            'profit_direction': 'gain' if eth_profit > 0 else 'loss',
            'gas_cost_eth': float(Web3.from_wei(gas_cost, 'ether')),
        }
    except Exception as e:
        return {'error': str(e)}


def analyze_defi_attack(w3: Web3, tx_hash: str, attacker: Optional[str] = None) -> None:
    """Comprehensive analysis of a DeFi attack transaction."""
    print(f"\n{'='*65}")
    print(f"DeFi Attack Transaction Analysis")
    print(f"Hash: {tx_hash}")
    print(f"{'='*65}\n")

    try:
        tx = w3.eth.get_transaction(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except Exception as e:
        print(f"[!] Transaction lookup failed: {e}")
        return

    print("[Basic Info]")
    print(f"  Block     : {tx.get('blockNumber')}")
    print(f"  From      : {tx['from']}")
    to_name = KNOWN_PROTOCOLS.get(tx.get('to', ''), tx.get('to', 'N/A'))
    print(f"  To        : {to_name}")
    print(f"  ETH value : {float(Web3.from_wei(tx['value'], 'ether')):.4f} ETH")
    print(f"  Gas used  : {receipt['gasUsed']:,}")
    # High gas usage (>500k) often indicates complex DeFi interactions
    print(f"  Status    : {'Success' if receipt['status'] == 1 else 'Failed'}")

    flash_events = decode_flash_loan_events(w3, tx_hash)
    if flash_events:
        print(f"\n[Flash Loan Detected — {len(flash_events)} event(s)]")
        for e in flash_events:
            print(f"  Protocol : {e['type']}")
            print(f"  Contract : {e['contract']}")
    else:
        print("\n[Flash Loan] None detected")

    if attacker:
        print(f"\n[Profit/Loss Analysis] Address: {attacker}")
        pnl = calculate_profit_loss(w3, tx_hash, attacker)
        if 'error' not in pnl:
            direction = "Gain" if pnl['profit_direction'] == 'gain' else "Loss"
            print(f"  ETH {direction} : {pnl['eth_profit']:.4f} ETH")
            print(f"  Gas Cost : {pnl['gas_cost_eth']:.4f} ETH")
        else:
            print(f"  Analysis failed (archive node required): {pnl['error']}")


def scan_flash_loan_txs(w3: Web3, start_block: int, end_block: int) -> list[str]:
    """Scan a block range for Flash Loan transactions using event filters.
    
    Uses Ethereum event log filters to find transactions containing
    known Flash Loan event signatures within the specified block range.
    """
    flash_hashes: list[str] = []
    for sig in FLASH_LOAN_SIG:
        try:
            logs = w3.eth.get_logs({
                'fromBlock': start_block,
                'toBlock': end_block,
                'topics': [sig],
            })
            for log in logs:
                flash_hashes.append(log['transactionHash'].hex())
        except Exception as e:
            print(f"[!] Log query failed: {e}", file=sys.stderr)
    return list(set(flash_hashes))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DeFi Attack Transaction Analysis CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze 0xabc...def --rpc https://mainnet.infura.io/v3/KEY
  %(prog)s analyze 0xabc...def --attacker 0x123...456
  %(prog)s scan --start 16000000 --end 16001000 --rpc https://...
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze a single transaction")
    analyze_p.add_argument("tx_hash", help="Transaction hash")
    analyze_p.add_argument("--attacker", help="Attacker address (for P&L calculation)")
    analyze_p.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY",
                           help="Ethereum RPC endpoint")

    scan_p = sub.add_parser("scan", help="Scan a block range for Flash Loans")
    scan_p.add_argument("--start", type=int, required=True, help="Start block number")
    scan_p.add_argument("--end", type=int, required=True, help="End block number")
    scan_p.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY",
                        help="Ethereum RPC endpoint")

    args = parser.parse_args()
    w3 = Web3(Web3.HTTPProvider(args.rpc))

    if not w3.is_connected():
        print("[!] RPC connection failed", file=sys.stderr)
        sys.exit(1)

    if args.command == "analyze":
        analyze_defi_attack(w3, args.tx_hash, args.attacker)
    elif args.command == "scan":
        print(f"[*] Scanning for Flash Loans: blocks {args.start} to {args.end}")
        hashes = scan_flash_loan_txs(w3, args.start, args.end)
        print(f"[+] Found: {len(hashes)} transaction(s)")
        for h in hashes:
            print(f"  {h}")


if __name__ == "__main__":
    main()
```

---

## 2. Oracle Price Manipulation Attacks

### 2.1 What is an Oracle? — "The Eyes of DeFi"

Smart contracts cannot directly access data outside the blockchain. To get the current USD price of ETH, a stock price, or any real-world data, they rely on **oracles** — bridge services that bring external data on-chain.

**Oracle types:**
- **On-chain Oracle (Spot Price):** Reads the current price directly from a DEX like Uniswap — easily manipulated within a single transaction
- **TWAP (Time-Weighted Average Price):** Averages price over time (e.g., 30 minutes) — short-term manipulation is economically impractical
- **Chainlink:** Aggregates from multiple independent external data providers — most manipulation-resistant

```
Spot price vulnerability:
  Current ETH price = current reserve ratio in a DEX pool
  Flash Loan → mass buy ETH → DEX price spikes in one transaction
  → In that same transaction, attack any protocol trusting this price

Why TWAP defends against this:
  Uses 30-minute average price → manipulating one block (~12 seconds) is useless
  Sustaining 1000% price for 30 minutes requires massive capital locked up the whole time
  → Economically irrational (interest losses > attack gains)
```

### 2.2 CREAM Finance Attack (2021, ~$130M)

```
Attack type: Spot price oracle manipulation

Sequence:
1. Flash Loan large ETH amount
2. Mass buy ETH in Uniswap ETH/crETH pool
   → crETH price spikes on Uniswap (e.g., +300%)
3. Cream Finance trusts the manipulated Uniswap spot price
   → Execute maximum collateral loan based on fake price
   → Borrow 3x more than actual collateral value
4. Withdraw loan funds, sell crETH, price normalizes
5. Repay Flash Loan
6. Walk away with far more than the collateral was worth

Key lesson:
  A single DEX's spot price can be manipulated in one transaction
  → TWAP of at least 30 minutes or Chainlink is required for any lending protocol
```

### 2.3 Defense: Safe Oracle Design

```solidity
// Vulnerable: spot price usage
function getPrice() external view returns (uint256) {
    (uint112 r0, uint112 r1,) = uniswapPair.getReserves();
    return r0 * 1e18 / r1;  // Instantly manipulable via Flash Loan
}

// Safe: Chainlink price feed
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface priceFeed;

function getPrice() external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    // Reject stale price (no update in over 1 hour = something is wrong)
    require(block.timestamp - updatedAt < 3600, "stale price");
    require(price > 0, "invalid price");
    return uint256(price);
}

// Safest: multiple oracles + deviation check
function getSafePrice() external view returns (uint256) {
    uint256 chainlinkPrice = getChainlinkPrice();
    uint256 twapPrice = getUniswapTWAP(1800);  // 30-minute TWAP

    // If two oracles deviate by more than 10%, reject (anomaly)
    uint256 deviation = chainlinkPrice > twapPrice
        ? ((chainlinkPrice - twapPrice) * 100) / twapPrice
        : ((twapPrice - chainlinkPrice) * 100) / chainlinkPrice;

    require(deviation < 10, "price deviation too high");
    return (chainlinkPrice + twapPrice) / 2;
}
```

---

## 3. MEV (Maximal Extractable Value) — The Invisible Tax on Blockchain

### 3.1 The Mempool: A Public Waiting Room

When a transaction is submitted to the blockchain, it does not immediately enter a block. It waits in the **mempool (Memory Pool)** — a publicly visible queue.

```
User submits transaction
         ↓
[Mempool — public waiting room]  ← All nodes can see the contents
         ↓                         (who is swapping what token for how much)
Miner/validator selects transactions (usually by gas fee, highest first)
         ↓
Included in block → Finalized

The mempool is public → MEV bots monitor it 24/7
Victim about to make a large swap → bot detects it → sandwich attack
```

### 3.2 Transaction Ordering — The Miner's Privilege

The person who decides the order of transactions in a block is the miner (PoW) or validator (PoS). The maximum profit extractable by manipulating this ordering is **MEV (Maximal Extractable Value)**.

**MEV types:**
- **Arbitrage:** When price differs between exchanges, insert a trade to capture the spread
- **Liquidation:** Race to liquidate undercollateralized positions and collect the liquidation bonus
- **Sandwich attack:** Wrap a victim's large swap with buy-before and sell-after transactions
- **Just-in-time (JIT) liquidity:** Add liquidity just before a large swap to collect fees, then remove it

### 3.3 Sandwich Attack — Detailed Mechanism

```
Scenario: Victim submits "swap 1,000 ETH → USDC" to the mempool
          (0.5% slippage tolerance allowed)

AMM principle: In a liquidity pool, price is set by x*y=k formula.
               Large buy → that token's price rises (demand spike).

Bot's actions:

[Detection] Bot sees victim's transaction in the mempool
                ↓
[1] Front-run:
    Bot submits "buy 100 ETH" with higher gas than victim
    - Higher gas → miner processes bot's tx first
    - ETH price rises (e.g., $1,000 → $1,050)
    ─────────────────────────────────────────────────────
    Block order: [bot front-run tx] → [victim tx] → [bot back-run tx]
    ─────────────────────────────────────────────────────
                ↓
[2] Victim's transaction executes:
    - Buys ETH at the already-inflated price
    - Receives fewer USDC than expected
    - But still within the 0.5% slippage tolerance (transaction doesn't revert)
                ↓
[3] Back-run:
    Bot sells 100 ETH
    - Price has risen further due to victim's large purchase
    - Sell at elevated price → realize the spread as profit
                ↓
[Result]
  Bot profit  = (sell price - buy price) × quantity - gas fees
  Victim loss = slippage impact + opportunity cost (received less USDC than fair price)
```

According to MEV-Explore data, cumulative MEV extracted on Ethereum has reached into the billions of dollars.

### 3.4 MEV Defense Strategies

```python
# MEV prevention using Flashbots Private RPC
# Transactions bypass the public mempool entirely

# Normal approach (vulnerable): exposed to the mempool
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/KEY"))
w3.eth.send_transaction(tx)  # Goes to public mempool → MEV bot target

# Flashbots approach (protected): goes directly to validators via private relay
# The transaction is never visible in the public mempool
w3_private = Web3(Web3.HTTPProvider("https://rpc.flashbots.net"))

# Additional defenses:
# 1. Minimize slippage tolerance (reduces sandwich attack profitability)
# 2. Use DEX aggregators (split routing across multiple pools reduces MEV)
# 3. Use CoW Protocol (peer-to-peer matching bypasses AMM entirely)
# 4. Use limit orders instead of market orders where possible
```

---

## 4. Real DeFi Hack Case Studies

### 4.1 Nomad Bridge Hack (2022, $190M) — The Copy-Paste Attack

```
Date: August 1, 2022
Loss: $190,000,000
Unique aspect: Not one attacker — hundreds of people copied the exploit

Root cause:
  Nomad Bridge is a cross-chain asset transfer bridge.
  During an upgrade, incorrect initialization set the trusted root to 0x0.
  Any message claiming "root is 0x0" was accepted as valid.
  → Anyone could copy an existing exploit transaction,
    change only the token address, and drain additional funds.

Progression:
  1. First attacker discovers the vulnerability and drains funds
  2. Others see the transaction on-chain and simply copy it
  3. Change only the token address → resend → receive funds
  4. Hundreds of people drain the bridge systematically (anarchy)

Why this case is significant:
  No advanced hacking skill required — copy-paste was enough
  "White hat" hackers also participated, claiming to protect funds
  Legal ambiguity: extremely difficult to distinguish hackers from opportunists
```

### 4.2 Poly Network Hack (2021, $611M — Largest DeFi Hack)

```
Date: August 10, 2021
Loss: $611,000,000 (largest crypto hack at the time)
Outcome: Attacker returned ALL funds (stunning conclusion)

Background:
  Poly Network is a cross-chain protocol connecting Ethereum, BSC, and Polygon.

Vulnerability: Flawed cross-chain message validation logic

Root cause:
  Poly Network uses a special contract to process cross-chain asset transfers.
  This contract has a "Keeper" address authorized to process cross-chain messages.
  
  What the attacker found:
  The EthCrossChainManager contract's verifyHeaderAndExecuteTx() function
  → Accepts a cross-chain message and executes a function based on it
  → By crafting malicious message parameters, arbitrary functions could be called
  
  Specific attack:
  1. Craft a malicious cross-chain message on BSC:
     "Change the Keeper in EthCrossChainData to the attacker's address"
  2. This message is relayed to EthCrossChainManager on Ethereum
  3. putCurEpochConPubKeyBytes() registers the attacker's address as Keeper
  4. Attacker uses Keeper authority to withdraw funds

Losses by chain:
  Ethereum: $273M
  BSC:      $253M
  Polygon:  $85M

Surprising outcome:
  Attacker communicated via on-chain messages after the hack
  "Did it for fun, not ready to handle this scale"
  Returned all $611M over several days
  Poly Network offered attacker a "white hat bug bounty" of $500K

Key lessons:
  Cross-chain protocols must clearly define trust boundaries between chains
  Message processing logic that allows arbitrary function calls is extremely dangerous
  Access control is the core security mechanism for bridge protocols
```

### 4.3 Ronin Bridge Hack (2022, $625M — Largest Crypto Hack)

```
Date: March 23, 2022 (discovered: March 29, 2022)
Loss: $625,000,000 (173,600 ETH + $25.5M USDC)
Attacker: Lazarus Group (North Korean state-sponsored hacking group)

Background:
  Ronin is the sidechain for Axie Infinity, a wildly popular blockchain game.
  Sky Mavis operated it, with millions of users at peak.

Ronin's validator system:
  Ronin used 9 validator nodes to secure the bridge.
  Withdrawals required 5 of 9 validator signatures (multisig majority).
  This design had a critical centralization flaw.

Attack vector: Social engineering + validator key theft

Phase 1 (Preparation):
  Lazarus Group targeted Axie Infinity developers on LinkedIn.
  Fake high-salary job offers were sent to Sky Mavis employees.
  Applicants received malicious PDFs disguised as "job offer documents."
  One Sky Mavis employee opened it → internal system access obtained.

Phase 2 (Key theft):
  From inside the network, 4 validator private keys were stolen.
  (Sky Mavis directly operated 4 of the 9 validators.)

Phase 3 (The 5th key):
  The Axie DAO operated the 5th validator independently.
  However: Sky Mavis had been temporarily granted signing authority in the past.
  This permission had never been revoked.
  (Legacy from "Gas-free RPC" feature — temporary permission left active)
  The 5th key was also compromised → majority (5/9) achieved.

Phase 4 (Draining funds):
  Used 5 validator signatures to authorize withdrawals.
  173,600 ETH drained in just 2 transactions.
  Not discovered for 6 days (no monitoring).

Context:
  Largest crypto hack in history at the time.
  Axie Infinity ecosystem collapsed; massive user exodus.

Response:
  US Treasury OFAC sanctioned Lazarus Group-linked addresses.
  Exchanges including Binance cooperated to freeze associated addresses.
  Ronin compensated users through investor support.

Key lessons:
  Multisig only provides security if validator keys are genuinely independent.
  Delegated signing authority must be explicitly revoked after use.
  Sidechains with centralized validator sets are a single point of failure (SPOF).
  Social engineering is as dangerous as any technical vulnerability.
  Large funds without real-time monitoring is an unacceptable risk.
```

### 4.4 Hack Comparison Table

| Protocol | Date | Loss | Attack Type | Core Vulnerability |
|----------|------|------|-------------|-------------------|
| bZx | Feb 2020 | $350K | Flash Loan + Oracle | Spot price trust |
| CREAM Finance | Oct 2021 | $130M | Flash Loan + Oracle | Spot price trust |
| Compound | Nov 2021 | $100M | Oracle deviation | Single oracle dependency |
| Poly Network | Aug 2021 | $611M | Cross-chain logic bug | Arbitrary function call |
| Nomad Bridge | Aug 2022 | $190M | Logic bug | Incorrect initialization |
| Ronin Bridge | Mar 2022 | $625M | Validator key theft | Centralized multisig |
| Euler Finance | Mar 2023 | $197M | Flash Loan + Logic | Missing health check |

---

## 5. MEV Deep Dive — Blockchain Economics

### 5.1 The Scale of MEV

MEV is not simply "hacking" — it is value that is structurally extracted from the Ethereum ecosystem.

```
MEV by type (2020–2023 cumulative estimates):
  Arbitrage:       $500M+  (largest share)
  Liquidations:    $200M+
  Sandwich attacks: $100M+
  Other:           $100M+
  Total:           $1B+

Who extracts MEV:
  - Individual MEV bot operators (most of the profit)
  - Miners/validators (exploiting block construction authority)
  - MEV infrastructure providers like Flashbots
```

### 5.2 How MEV Affects Users

**From a regular DeFi user's perspective:**
- Large swaps receive worse prices than expected (sandwich attacks)
- Positions held just above the liquidation threshold become MEV bot targets
- Popular NFT mints trigger gas wars that price out ordinary users

**The dual nature of MEV:**
```
Positive aspects:
  - Arbitrage MEV → equalizes prices across exchanges (market efficiency)
  - Liquidation MEV → maintains collateral health in lending protocols

Negative aspects:
  - Sandwich attacks → direct financial harm to users
  - Gas wars → network congestion and high fees
  - Block reorg incentives → threatens consensus security
```

---

## 6. DeFi Security Audit Methodology

### 6.1 Pre-Audit Preparation

Smart contract security auditing differs fundamentally from traditional software security auditing. DeFi-specific attack vectors require dedicated expertise and systematic methodology.

```
Pre-audit checklist:
  □ Obtain protocol documentation and design specification
  □ Review previous audit reports (for re-audits)
  □ Study hack case studies for similar protocols
  □ Interview development team about protocol philosophy
  □ Set up test environment (Hardhat/Foundry fork testing)
```

### 6.2 Manual Code Review Process

```
Step 1: Architecture analysis
  - Map the complete state machine of the protocol
  - Trace all external call paths
  - Review the access control model
  - Check upgradeability patterns (proxy admin, timelock)

Step 2: Business logic verification
  - Identify economic invariants
    Example: "total collateral >= total debt" must always hold
  - Test boundary value cases
  - Check for integer overflow/underflow
  - Verify token accounting is consistent

Step 3: DeFi-specific vulnerability checks
  - Reentrancy attack surface
  - Flash Loan attack surface
  - Oracle manipulation potential
  - Liquidation mechanism soundness
  - Cross-chain message validation (for bridges)

Step 4: Automated tooling
  - Slither: static analysis — catches common patterns quickly
  - Echidna: property-based fuzzing — generates inputs that break invariants
  - Manticore: symbolic execution — explores all code paths mathematically
  - Mythril: vulnerability pattern detection
```

### 6.3 Automated Audit Tools

```bash
# Static analysis with Slither
slither contracts/ --detect reentrancy-eth,oracle-manipulation --json report.json

# Centralization risk detection
slither token.sol --detect centralization-risk,suicidal,controlled-delegatecall

# Property-based fuzz testing with Echidna
# Write invariant functions (echidna_*) then run:
echidna-test contracts/Protocol.sol --config echidna.yaml

# Fork testing against real mainnet state (Foundry)
# Tests run against a live fork — catches real-world interactions
forge test --fork-url https://mainnet.infura.io/v3/KEY \
  --match-test testFlashLoanScenario -vvv
```

---

## 7. Rug Pull Pattern Detection

| Pattern | Description | Detection Method |
|---------|-------------|-----------------|
| Mint authority | Owner can mint unlimited tokens | Code audit: `onlyOwner` + `mint()` |
| Transfer ban | Owner can disable transfers | Check `transferAllowed` variable |
| Hidden fees | 90% burn on transfer | Check tax logic in transfer function |
| LP withdrawal | Sudden liquidity removal | Check LP token lock status |
| Ownership not renounced | Owner maintained in Ownable | Check `owner()` address on-chain |
| No timelock | Admin functions have no delay | Check upgrade delay requirements |
| Backdoor functions | Hidden `drain()` etc. | Enumerate all external functions |

```bash
# Detect centralization risks
slither token.sol --detect centralization-risk,suicidal,controlled-delegatecall

# Check token ownership on-chain
cast call TOKEN_ADDRESS "owner()(address)" --rpc-url https://mainnet.infura.io/v3/KEY
```

---

## 8. Smart Contract Vulnerability Checklist

### 8.1 Reentrancy

```
Vulnerable pattern:
  1. External contract call
  2. State update

  Attacker can re-enter this function during step 1.
  State has not yet been updated → can withdraw multiple times.

Safe pattern (Checks-Effects-Interactions):
  1. Checks (require condition validation)
  2. Effects (update state — deduct balance)
  3. Interactions (external call — send ETH)

  State is updated first → reentry finds balance already zero.
```

### 8.2 Complete Vulnerability Checklist

```
[ ] Reentrancy
    - Checks-Effects-Interactions pattern followed
    - ReentrancyGuard modifier used where needed

[ ] Integer overflow/underflow
    - Solidity 0.8.0+ used (built-in overflow protection)
    - Or SafeMath library applied for older versions

[ ] Oracle manipulation
    - No spot price usage for any critical calculation
    - TWAP or Chainlink price feeds used
    - Multiple oracle sources with deviation checks implemented

[ ] Flash Loan surface
    - Single-transaction price manipulation mitigated
    - Balance checks before state changes
    - Health factor checked after every state-changing operation

[ ] Access control
    - All privileged functions inventoried
    - Timelocks applied to critical operations (minimum 24–48 hours)
    - Multisig requirements enforced with independent key holders

[ ] Liquidation mechanism
    - Health factor checks complete and correct
    - Liquidation loop safe under gas limits
    - No liquidation cascade risk under extreme market conditions

[ ] Upgradeability
    - Proxy pattern security verified
    - Storage collision risk assessed
    - Initializer replay prevented

[ ] Economic model
    - Inflation/deflation logic reviewed
    - Liquidation cascade scenarios tested
    - Extreme market conditions simulated (price drops of 80%+)

[ ] Cross-chain (bridge protocols)
    - Message validation logic is complete
    - No arbitrary function calls permitted via messages
    - Validator keys are genuinely independent
    - Delegated signing authority has revocation mechanism
    - Monitoring alerts for large unexpected withdrawals
```
