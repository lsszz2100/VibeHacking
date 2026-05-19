# Web3 사고 대응

DeFi 익스플로잇, NFT 러그풀, 스마트 컨트랙트 해킹 발생 시 온체인 포렌식과 피해 최소화를 위한 신속 대응 절차를 다룬다. 블록체인 특성상 트랜잭션 불변성으로 인해 사전 방어와 신속한 피해 확산 차단이 핵심이다.

---

## 1. Web3 사고 대응 프레임워크

### 1.1 사고 분류

| 사고 유형 | 특징 | 대응 긴급도 |
|----------|------|-----------|
| 스마트 컨트랙트 취약점 익스플로잇 | 즉각적 자금 탈취 | 즉시 (분 단위) |
| 프라이빗 키 탈취 | 지갑 전체 탈취 | 즉시 |
| 플래시론 공격 | 단일 트랜잭션 내 완결 | 사후 분석 |
| 거버넌스 공격 | 투표 조작으로 악성 제안 통과 | 수 시간 내 |
| 오라클 조작 | 가격 피드 조작으로 청산 유발 | 즉시 |
| 러그풀 | 개발팀 의도적 자금 탈취 | 사후 추적 |

### 1.2 초동 대응 5분 체크리스트

```bash
# 1. 의심 트랜잭션 확인
curl -s "https://api.etherscan.io/api?module=account&action=txlist\
&address=VICTIM_CONTRACT&sort=desc&apikey=YourApiKey" | \
  python3 -c "import sys,json; txs=json.load(sys.stdin)['result'][:5]; \
  [print(f'{t[\"timeStamp\"]}: {t[\"hash\"][:20]}... value={int(t[\"value\"])/1e18:.2f}ETH') for t in txs]"

# 2. 컨트랙트 자금 현황 확인
cast balance CONTRACT_ADDRESS --rpc-url $RPC_URL

# 3. 의심 주소 OFAC 차단 목록 확인
# Chainalysis, TRM Labs API 조회

# 4. Pause 기능 있으면 즉시 실행
cast send CONTRACT_ADDRESS "pause()" --private-key $ADMIN_KEY --rpc-url $RPC_URL

# 5. 커뮤니티/팀 긴급 알림
```

---

## 2. 온체인 포렌식

### 2.1 트랜잭션 역추적

```python
#!/usr/bin/env python3
"""Web3 사고 온체인 포렌식 도구"""
import argparse
from dataclasses import dataclass, field
from typing import Optional

from web3 import Web3
from web3.types import TxData


@dataclass
class AttackTrace:
    attacker_address: str
    victim_contract: str
    attack_tx: str
    profit_wei: int = 0
    fund_source: Optional[str] = None
    steps: list[str] = field(default_factory=list)


def trace_attack(
    w3: Web3,
    attack_tx_hash: str,
    victim_contract: str,
) -> AttackTrace:
    tx = w3.eth.get_transaction(attack_tx_hash)
    receipt = w3.eth.get_transaction_receipt(attack_tx_hash)

    trace = AttackTrace(
        attacker_address=tx["from"],
        victim_contract=victim_contract,
        attack_tx=attack_tx_hash,
    )

    # 공격 블록 전후 잔액 비교
    block = tx["blockNumber"]
    attacker = tx["from"]

    before_balance = w3.eth.get_balance(attacker, block_identifier=block - 1)
    after_balance = w3.eth.get_balance(attacker, block_identifier=block)
    trace.profit_wei = after_balance - before_balance

    trace.steps.append(f"공격자 주소: {attacker}")
    trace.steps.append(f"피해 컨트랙트: {victim_contract}")
    trace.steps.append(f"공격 TX: {attack_tx_hash}")
    trace.steps.append(f"이익: {w3.from_wei(max(0, trace.profit_wei), 'ether'):.4f} ETH")
    trace.steps.append(f"가스 사용: {receipt['gasUsed']:,}")
    trace.steps.append(f"블록: {block}")

    return trace


def find_fund_source(w3: Web3, address: str, max_depth: int = 5) -> list[str]:
    """공격자 자금 출처 역추적 (Tornado Cash 등 믹서 확인)"""
    TORNADO_CASH_ADDRESSES = {
        "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # 0.1 ETH
        "0xbbd2135536d618b9c1ec56a4f3660fa0bc5ca9c1",  # 1 ETH
        "0x12d66f87a04a9e220c9d8ad67e5e18c9eb41e4c4",  # 10 ETH
    }

    path = []
    current = address.lower()

    for _ in range(max_depth):
        txs = w3.eth.get_transaction_count(current)
        if not txs:
            break
        path.append(current)
        if current in TORNADO_CASH_ADDRESSES:
            path.append("[Tornado Cash 믹서 감지]")
            break

    return path


def analyze_event_logs(w3: Web3, contract_address: str, from_block: int, to_block: int) -> list[dict]:
    """사고 전후 이벤트 로그 분석"""
    logs = w3.eth.get_logs({
        "fromBlock": from_block,
        "toBlock": to_block,
        "address": contract_address,
    })

    events = []
    for log in logs:
        events.append({
            "block": log["blockNumber"],
            "tx": log["transactionHash"].hex(),
            "topics": [t.hex() for t in log["topics"]],
            "data": log["data"].hex() if log["data"] else "",
        })

    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Web3 사고 포렌식")
    parser.add_argument("--rpc", required=True, help="RPC URL")
    parser.add_argument("--tx", help="공격 트랜잭션 해시")
    parser.add_argument("--contract", help="피해 컨트랙트 주소")
    parser.add_argument("--from-block", type=int)
    parser.add_argument("--to-block", type=int)
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))

    if args.tx and args.contract:
        trace = trace_attack(w3, args.tx, args.contract)
        for step in trace.steps:
            print(f"[+] {step}")

    if args.contract and args.from_block and args.to_block:
        events = analyze_event_logs(w3, args.contract, args.from_block, args.to_block)
        print(f"\n[+] 이벤트 로그 {len(events)}건:")
        for e in events[:10]:
            print(f"  블록 {e['block']}: {e['tx'][:20]}...")


if __name__ == "__main__":
    main()
```

### 2.2 Dune Analytics 쿼리 (SQL)

```sql
-- DeFi 프로토콜 비정상 대규모 인출 탐지
SELECT
  block_time,
  tx_hash,
  "from",
  "to",
  value / 1e18 AS eth_value,
  gas_used
FROM ethereum.transactions
WHERE
  block_time >= NOW() - INTERVAL '24 hours'
  AND "to" = LOWER('0xVICTIM_CONTRACT')
  AND value / 1e18 > 100  -- 100 ETH 이상 인출
ORDER BY value DESC
LIMIT 50;

-- 플래시론 공격 패턴 (동일 블록 내 대규모 차입+상환)
SELECT
  block_number,
  COUNT(*) AS tx_count,
  SUM(value) / 1e18 AS total_eth
FROM ethereum.transactions
WHERE block_number BETWEEN 19000000 AND 19000010
GROUP BY block_number
HAVING COUNT(*) > 5 AND SUM(value) / 1e18 > 1000;
```

---

## 3. 피해 확산 차단

### 3.1 컨트랙트 긴급 정지 (Pause 패턴)

```solidity
// 보안 패턴: Pausable 컨트랙트
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureVault is Pausable, AccessControl {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // 일일 인출 한도
    mapping(address => uint256) public dailyWithdrawn;
    mapping(address => uint256) public lastWithdrawDay;
    uint256 public constant DAILY_LIMIT = 10 ether;

    event EmergencyPause(address indexed by, string reason);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    // 가디언이 긴급 정지
    function emergencyPause(string calldata reason) external onlyRole(GUARDIAN_ROLE) {
        _pause();
        emit EmergencyPause(msg.sender, reason);
    }

    function withdraw(uint256 amount) external whenNotPaused {
        uint256 today = block.timestamp / 86400;
        if (lastWithdrawDay[msg.sender] != today) {
            dailyWithdrawn[msg.sender] = 0;
            lastWithdrawDay[msg.sender] = today;
        }

        require(
            dailyWithdrawn[msg.sender] + amount <= DAILY_LIMIT,
            "일일 한도 초과"
        );
        dailyWithdrawn[msg.sender] += amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "전송 실패");
    }
}
```

### 3.2 화이트햇 구조 작전

```python
#!/usr/bin/env python3
"""화이트햇 — 공격자보다 먼저 취약한 자금 안전 지갑으로 이동"""
import argparse
import time

from web3 import Web3
from web3.middleware import geth_poa_middleware


def whitehat_rescue(
    rpc_url: str,
    private_key: str,
    vulnerable_contract: str,
    safe_wallet: str,
    withdraw_abi: list,
    max_gas_price_gwei: int = 500,
) -> str:
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    account = w3.eth.account.from_key(private_key)
    contract = w3.eth.contract(address=vulnerable_contract, abi=withdraw_abi)

    gas_price = w3.eth.gas_price
    if gas_price > w3.to_wei(max_gas_price_gwei, "gwei"):
        raise ValueError(f"가스 가격 너무 높음: {w3.from_wei(gas_price, 'gwei'):.0f} gwei")

    # 자금 인출 트랜잭션 구성
    tx = contract.functions.withdrawAll(safe_wallet).build_transaction({
        "from": account.address,
        "gas": 200_000,
        "gasPrice": gas_price,
        "nonce": w3.eth.get_transaction_count(account.address),
    })

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    print(f"[+] 구조 TX 전송: {tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt["status"] == 1:
        print(f"[+] 구조 성공! 블록: {receipt['blockNumber']}")
    else:
        print("[-] 트랜잭션 실패")

    return tx_hash.hex()


def main() -> None:
    parser = argparse.ArgumentParser(description="화이트햇 구조 도구")
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--key", required=True, help="개인키")
    parser.add_argument("--contract", required=True, help="취약 컨트랙트")
    parser.add_argument("--safe-wallet", required=True, help="안전 지갑")
    args = parser.parse_args()

    print("[!] 주의: 반드시 화이트햇 활동임을 프로토콜 팀에 미리 알릴 것")
    whitehat_rescue(args.rpc, args.key, args.contract, args.safe_wallet, [])


if __name__ == "__main__":
    main()
```

---

## 4. 사고 후 복구 절차

### 4.1 피해 집계 및 보고

```python
#!/usr/bin/env python3
"""DeFi 사고 피해액 집계"""
import argparse
from decimal import Decimal

import requests


def get_eth_price() -> Decimal:
    resp = requests.get(
        "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
        timeout=10,
    )
    return Decimal(str(resp.json()["ethereum"]["usd"]))


def calculate_loss(
    stolen_eth: Decimal,
    stolen_tokens: dict[str, Decimal],  # token: amount
    token_prices: dict[str, Decimal],
) -> dict:
    eth_price = get_eth_price()
    eth_usd = stolen_eth * eth_price

    token_usd = sum(
        amount * token_prices.get(token, Decimal(0))
        for token, amount in stolen_tokens.items()
    )

    total_usd = eth_usd + token_usd

    return {
        "eth_stolen": float(stolen_eth),
        "eth_usd": float(eth_usd),
        "token_usd": float(token_usd),
        "total_usd": float(total_usd),
        "eth_price": float(eth_price),
    }


def generate_incident_report(
    protocol: str,
    attack_type: str,
    attack_tx: str,
    loss: dict,
    timeline: list[str],
) -> str:
    report = f"""# {protocol} 보안 사고 보고서

## 요약
- 공격 유형: {attack_type}
- 피해액: ${loss['total_usd']:,.0f} USD (ETH {loss['eth_stolen']:.2f})
- 공격 TX: {attack_tx}

## 타임라인
"""
    for event in timeline:
        report += f"- {event}\n"

    report += f"""
## 피해 내역
| 항목 | 수량 | USD 환산 |
|------|------|---------|
| ETH | {loss['eth_stolen']:.2f} ETH | ${loss['eth_usd']:,.0f} |
| 토큰 | - | ${loss['token_usd']:,.0f} |
| **합계** | - | **${loss['total_usd']:,.0f}** |

## 대응 조치
- [ ] 컨트랙트 긴급 정지
- [ ] 거래소 출금 주소 블락 요청
- [ ] 온체인 추적 개시
- [ ] 법적 조치 검토
- [ ] 커뮤니티 공개 공지
"""
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="DeFi 사고 보고서 생성")
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--attack-type", required=True)
    parser.add_argument("--attack-tx", required=True)
    parser.add_argument("--eth-stolen", type=float, default=0)
    args = parser.parse_args()

    loss = calculate_loss(
        stolen_eth=Decimal(str(args.eth_stolen)),
        stolen_tokens={},
        token_prices={},
    )

    report = generate_incident_report(
        args.protocol,
        args.attack_type,
        args.attack_tx,
        loss,
        ["공격 탐지", "컨트랙트 정지", "포렌식 시작"],
    )
    print(report)


if __name__ == "__main__":
    main()
```

---

## 5. 거래소 협조 요청

| 거래소 | 연락처 | 대응 시간 |
|--------|--------|----------|
| Binance | law_enforcement@binance.com | 24~48h |
| Coinbase | compliance@coinbase.com | 24~72h |
| Kraken | support@kraken.com | 24~48h |
| OKX | legal@okx.com | 24~48h |

### 5.1 요청 시 포함해야 할 정보

```
1. 공격 트랜잭션 해시 목록
2. 공격자 지갑 주소
3. 자금 이동 경로 (온체인 추적 결과)
4. 피해 금액 및 토큰 종류
5. 법적 근거 (경찰 신고 접수번호 등)
6. 담당자 연락처 및 소속 법인
```
