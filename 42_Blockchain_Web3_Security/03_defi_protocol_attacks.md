> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# DeFi 프로토콜 공격 기법

DeFi(탈중앙화 금융)는 스마트 컨트랙트 위에 구축된 금융 프로토콜로, 2020년 이후 수십억 달러 규모의 해킹이 발생했다. Flash Loan, 오라클 조작, MEV 등 DeFi 특유의 공격 벡터를 분석한다.

---

## 1. Flash Loan 공격

Flash Loan은 같은 트랜잭션 내에서 무담보 대출 → 사용 → 상환이 가능한 DeFi 기능이다. 단독으로는 무해하지만, 가격 조작이나 거버넌스 공격에 악용된다.

### 1.1 Flash Loan 원리

```
단일 트랜잭션 내 실행:
1. 프로토콜에서 X ETH 차용 (수수료 없거나 매우 낮음)
2. 차용한 자금으로 공격 실행 (가격 조작, 아비트리지 등)
3. 이익 + 수수료 상환
4. 상환 실패 시 → 전체 트랜잭션 revert (손실 없음)
```

### 1.2 Euler Finance 해킹 분석 (2023, $197M)

```
공격 요약:
1. Aave에서 30M DAI Flash Loan
2. EUL 토큰 대량 매수 → eDAI 민팅
3. 버그 있는 donateToReserves() 호출
   → 청산 가능한 포지션 인위적 생성
4. 자기 포지션 청산 → 이익 추출
5. Flash Loan 상환

핵심 버그: donateToReserves()가 건강 지수(health factor) 체크를 우회
```

### 1.3 Python 공격 시뮬레이션 추적기

```python
#!/usr/bin/env python3
"""DeFi 공격 트랜잭션 추적 및 분석 CLI"""

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

# Flash Loan 관련 이벤트 시그니처
FLASH_LOAN_SIG = {
    "0x631042c832b07452973831137f2d73e395028b44b250de141e1b9f64f1fe27bb": "Aave FlashLoan",
    "0x0d7d75e01ab95780d3cd1c8ec0dd6c2ce19e3a20427eec8bf53283b6fb8e95f0": "Balancer FlashLoan",
}


def get_tx_trace(w3: Web3, tx_hash: str) -> Optional[dict]:
    """debug_traceTransaction으로 내부 호출 추적 (아카이브 노드 필요)"""
    try:
        return w3.manager.request_blocking(
            "debug_traceTransaction",
            [tx_hash, {"tracer": "callTracer"}]
        )
    except Exception as e:
        print(f"[!] trace 불가 (아카이브 노드 필요): {e}", file=sys.stderr)
        return None


def decode_flash_loan_events(w3: Web3, tx_hash: str) -> list[dict]:
    """Flash Loan 이벤트 디코딩"""
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
    """공격자 ETH/토큰 손익 계산"""
    try:
        tx = w3.eth.get_transaction(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        block = tx['blockNumber']

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
    print(f"[기본 정보]")
    print(f"  블록      : {tx.get('blockNumber')}")
    print(f"  발신자    : {tx['from']}")
    to_name = KNOWN_PROTOCOLS.get(tx.get('to', ''), tx.get('to', 'N/A'))
    print(f"  수신자    : {to_name}")
    print(f"  ETH 전송  : {float(Web3.from_wei(tx['value'], 'ether')):.4f} ETH")
    print(f"  가스 사용 : {receipt['gasUsed']:,}")
    print(f"  상태      : {'성공' if receipt['status'] == 1 else '실패'}")

    # Flash Loan 탐지
    flash_events = decode_flash_loan_events(w3, tx_hash)
    if flash_events:
        print(f"\n[Flash Loan 탐지 — {len(flash_events)}건]")
        for e in flash_events:
            print(f"  프로토콜: {e['type']}")
            print(f"  컨트랙트: {e['contract']}")
    else:
        print(f"\n[Flash Loan] 탐지 없음")

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
    """블록 범위에서 Flash Loan 트랜잭션 탐색 (이벤트 필터 방식)"""
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
    parser = argparse.ArgumentParser(description="DeFi 공격 트랜잭션 분석 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="단일 트랜잭션 분석")
    analyze_p.add_argument("tx_hash", help="트랜잭션 해시")
    analyze_p.add_argument("--attacker", help="공격자 주소 (손익 계산용)")
    analyze_p.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY")

    scan_p = sub.add_parser("scan", help="블록 범위 Flash Loan 스캔")
    scan_p.add_argument("--start", type=int, required=True)
    scan_p.add_argument("--end", type=int, required=True)
    scan_p.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY")

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

### 2.1 원리

DeFi 프로토콜은 자산 가격을 온체인 오라클에서 읽는다. TWAP이 아닌 spot price를 사용하면 단일 블록 내 조작이 가능하다.

```
공격 시나리오 (CREAM Finance 2021):
1. Uniswap ETH/crETH 풀에서 대량 ETH 매수 → crETH 가격 급등
2. 조작된 가격으로 Cream에서 담보 대출 최대화
3. 대출 자금 인출 → crETH 매도 → 가격 정상화
4. 담보보다 많은 자산 탈취 (약 $130M)
```

### 2.2 방어: Chainlink TWAP

```solidity
// 취약: spot price 사용
function getPrice() external view returns (uint256) {
    (uint112 r0, uint112 r1,) = uniswapPair.getReserves();
    return r0 * 1e18 / r1;  // ❌ 즉시 조작 가능
}

// 안전: Chainlink 가격 피드
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface priceFeed;

function getPrice() external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < 3600, "stale price");
    require(price > 0, "invalid price");
    return uint256(price);
}
```

---

## 3. MEV (Maximal Extractable Value)

### 3.1 샌드위치 공격

```
피해자 트랜잭션: USDC → ETH 대량 스왑 (슬리피지 0.5%)
공격자 봇:
  [1] 프론트런: ETH 매수 (가격 상승)
  [2] 피해자 트랜잭션 실행 (높은 가격에 매수)
  [3] 백런: ETH 매도 (이익 실현)
```

### 3.2 Flashbots MEV 방어

```python
# MEV 방지: Flashbots Private RPC 사용
# 트랜잭션이 mempool에 노출되지 않음

w3_private = Web3(Web3.HTTPProvider("https://rpc.flashbots.net"))
# 일반 send_transaction 대신 Flashbots bundle 제출
```

---

## 4. Rug Pull 패턴 탐지

| 패턴 | 설명 | 탐지 방법 |
|------|------|----------|
| Mint 권한 | owner가 토큰 무한 민팅 가능 | 코드 감사: `onlyOwner` + `mint()` |
| 거래 금지 | owner가 전송 비활성화 | `transferAllowed` 변수 확인 |
| 숨겨진 수수료 | 전송 시 90% 소각 | 전송 함수 세금 로직 확인 |
| LP 회수 | 유동성 갑작스런 제거 | LP 토큰 잠금 여부 확인 |
| 소유권 미포기 | Ownable에서 소유권 유지 | `owner()` 주소 확인 |

```bash
# Slither로 중앙화 위험 탐지
slither token.sol --detect centralization-risk,suicidal,controlled-delegatecall
```

---

<a name="english"></a>

# DeFi Protocol Attack Techniques

DeFi (Decentralized Finance) is a financial protocol built on smart contracts that has suffered billions of dollars in hacks since 2020. This document analyzes DeFi-specific attack vectors including Flash Loans, oracle manipulation, and MEV.

---

## 1. Flash Loan Attacks

Flash Loans allow uncollateralized borrowing, usage, and repayment within the same transaction. They are harmless alone, but can be exploited for price manipulation or governance attacks.

### 1.1 Flash Loan Principles

```
Executed within a single transaction:
1. Borrow X ETH from protocol (no fee or very low)
2. Execute attack with borrowed funds (price manipulation, arbitrage, etc.)
3. Repay principal + fee
4. On repayment failure → entire transaction reverts (no loss)
```

### 1.2 Euler Finance Hack Analysis (2023, $197M)

```
Attack Summary:
1. Flash Loan 30M DAI from Aave
2. Mass buy EUL tokens → mint eDAI
3. Call buggy donateToReserves()
   → Artificially create liquidatable position
4. Self-liquidate → extract profit
5. Repay Flash Loan

Core Bug: donateToReserves() bypassed health factor check
```

---

## 2. Oracle Price Manipulation Attacks

### 2.1 Principle

DeFi protocols read asset prices from on-chain oracles. Using spot price instead of TWAP allows manipulation within a single block.

```
Attack Scenario (CREAM Finance 2021):
1. Mass buy ETH from Uniswap ETH/crETH pool → crETH price skyrockets
2. Maximize collateral loan from Cream using manipulated price
3. Withdraw loan funds → sell crETH → price normalizes
4. Steal more assets than collateral (~$130M)
```

### 2.2 Defense: Chainlink TWAP

```solidity
// Vulnerable: spot price usage
function getPrice() external view returns (uint256) {
    (uint112 r0, uint112 r1,) = uniswapPair.getReserves();
    return r0 * 1e18 / r1;  // ❌ Instantly manipulable
}

// Safe: Chainlink price feed
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface priceFeed;

function getPrice() external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < 3600, "stale price");
    require(price > 0, "invalid price");
    return uint256(price);
}
```

---

## 3. MEV (Maximal Extractable Value)

### 3.1 Sandwich Attack

```
Victim transaction: USDC → ETH large swap (0.5% slippage)
Attacker bot:
  [1] Front-run: Buy ETH (price rises)
  [2] Victim transaction executes (buys at higher price)
  [3] Back-run: Sell ETH (realize profit)
```

### 3.2 Flashbots MEV Defense

```python
# MEV prevention: Use Flashbots Private RPC
# Transactions are not exposed to the mempool
w3_private = Web3(Web3.HTTPProvider("https://rpc.flashbots.net"))
# Submit Flashbots bundle instead of regular send_transaction
```

---

## 4. Rug Pull Pattern Detection

| Pattern | Description | Detection Method |
|---------|-------------|-----------------|
| Mint authority | Owner can mint unlimited tokens | Code audit: `onlyOwner` + `mint()` |
| Transfer ban | Owner can disable transfers | Check `transferAllowed` variable |
| Hidden fees | 90% burn on transfer | Check tax logic in transfer function |
| LP withdrawal | Sudden liquidity removal | Check LP token lock status |
| Ownership not renounced | Owner maintained in Ownable | Check `owner()` address |

```bash
# Detect centralization risks with Slither
slither token.sol --detect centralization-risk,suicidal,controlled-delegatecall
```
