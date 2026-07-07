> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Web3 사고 대응

## 0. 초보자를 위한 개념 이해

### Web3 사고 대응이란?

**Web3 사고 대응(Incident Response)**은 스마트 컨트랙트 해킹, DeFi 프로토콜 공격 발생 시 피해를 최소화하고 원인을 분석하는 절차입니다. 블록체인의 불변성 때문에 전통 사고 대응과 큰 차이가 있습니다.

**블록체인 특수성:**
```
전통 IT 사고 대응:
  침해 발견 → 시스템 격리 → 패치 → 복구
  (데이터 복구 가능)

Web3 사고 대응:
  침해 발견 → (스마트 컨트랙트 정지 가능한 경우)
  → 자금 이동 추적 → 법적 조치
  (이미 전송된 자금은 복구 불가)

골든 아워:
  공격 발생 → 수 분~수 시간 내 추가 피해 차단이 핵심
  공격 진행 중: Pause 함수 실행으로 추가 출금 차단
```

### 사고 대응 절차

```
1. 탐지 (Detection)
   - 온체인 모니터링 알림 (Forta, OpenZeppelin Defender)
   - 비정상 대규모 트랜잭션 감지

2. 분석 (Analysis)
   - Etherscan으로 공격 트랜잭션 확인
   - Tenderly로 트랜잭션 재현·디버깅
   - 공격 경로 파악

3. 격리 (Containment)
   - Emergency Pause 기능 실행
   - 추가 자금 이동 차단
   - 영향받은 풀 잠금

4. 추적 (Tracking)
   - 공격자 지갑 모니터링
   - 믹서(Tornado Cash 등) 사용 여부 확인
   - 거래소에 지갑 차단 요청
```

### 필요한 도구
- **Forta**: 온체인 위협 탐지 모니터링
- **Etherscan**: 트랜잭션 내역 분석
- **OpenZeppelin Defender**: 긴급 대응 자동화

### 기초 실습 예제
```python
# 공격자 지갑 자금 이동 추적
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_KEY"))

attacker_address = "0xAttackerAddress..."

# 특정 주소의 최근 트랜잭션 조회
block = w3.eth.get_block('latest')
for tx_hash in block['transactions'][:10]:
    tx = w3.eth.get_transaction(tx_hash)
    if tx['from'].lower() == attacker_address.lower():
        print(f"공격자 트랜잭션: {tx_hash.hex()}")
        print(f"  → {tx['to']}: {w3.from_wei(tx['value'], 'ether')} ETH")
```

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

## 4.5 온체인 자금 추적 자동화 — 믹서·브릿지 경유 추적

공격자는 탈취 자금을 곧바로 현금화하지 않고 (1) Tornado Cash류 믹서로 자금 출처를 흐리거나, (2) 체인 간 브릿지로 자금을 다른 블록체인으로 이동시켜 추적을 어렵게 만든다. 거래소 협조 요청(5절) 시 "자금이 지금 어디 있는가"를 최대한 구체적으로 제시할수록 거래소의 동결 조치가 빨라지므로, 자금 이동을 자동으로 추적하는 파이프라인이 초동 대응 속도를 좌우한다.

```python
#!/usr/bin/env python3
"""공격자 지갑에서 시작해 여러 홉의 자금 이동을 재귀 추적, 믹서/브릿지 통과 여부를 표시."""
import requests
from dataclasses import dataclass, field

KNOWN_MIXER_ADDRESSES = {
    "0x8589427373d6d84e98730d7795d8f6f8731fda0": "Tornado Cash (0.1 ETH pool)",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash Router",
}
KNOWN_BRIDGE_ADDRESSES = {
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole Bridge",
    "0x8484ef722627bf18ca5ae6bcf031c23e6e922b45": "Multichain Router",
}


@dataclass
class FundHop:
    tx_hash: str
    from_addr: str
    to_addr: str
    amount: float
    flag: str = ""


def trace_fund_movement(start_address: str, api_key: str, max_hops: int = 5) -> list[FundHop]:
    """Etherscan류 API로 지갑의 아웃바운드 트랜잭션을 홉 단위로 추적 (개념 코드)."""
    hops: list[FundHop] = []
    current = start_address

    for hop_num in range(max_hops):
        resp = requests.get(
            "https://api.etherscan.io/api",
            params={
                "module": "account", "action": "txlist", "address": current,
                "sort": "asc", "apikey": api_key,
            },
            timeout=10,
        )
        txs = resp.json().get("result", [])
        outgoing = [tx for tx in txs if tx["from"].lower() == current.lower()]
        if not outgoing:
            break

        latest = max(outgoing, key=lambda t: int(t["value"]))
        to_addr = latest["to"].lower()
        flag = ""
        if to_addr in KNOWN_MIXER_ADDRESSES:
            flag = f"믹서 통과: {KNOWN_MIXER_ADDRESSES[to_addr]}"
        elif to_addr in KNOWN_BRIDGE_ADDRESSES:
            flag = f"브릿지 통과: {KNOWN_BRIDGE_ADDRESSES[to_addr]}"

        hops.append(FundHop(
            tx_hash=latest["hash"], from_addr=current, to_addr=to_addr,
            amount=int(latest["value"]) / 1e18, flag=flag,
        ))
        current = to_addr

        if flag:
            break  # 믹서 진입 시 온체인 추적은 사실상 여기서 단절

    return hops


if __name__ == "__main__":
    hops = trace_fund_movement("0xATTACKER_WALLET", api_key="YOUR_ETHERSCAN_KEY")
    for h in hops:
        print(f"{h.tx_hash[:10]}... {h.from_addr[:10]} -> {h.to_addr[:10]} ({h.amount} ETH) {h.flag}")
```

**한계와 실전 대응**: 믹서 진입 이후에는 순수 온체인 데이터만으로는 자금 경로가 끊긴 것으로 보이지만, (1) 믹서 출금 시점과 금액 패턴을 입금 기록과 대조하는 타이밍 상관분석, (2) Chainalysis Reactor·TRM Labs 같은 상용 분석 도구의 클러스터링 휴리스틱, (3) 다수 거래소가 공유하는 제재 대상 주소 데이터베이스 대조를 병행해야 실질적 회수 가능성이 생긴다. 무엇보다 **자금이 거래소로 입금되는 순간이 유일하게 동결 가능한 지점**이므로, 이 추적 파이프라인의 목적은 "그 순간을 예측해 해당 거래소에 선제 통보하는 것"임을 잊지 말아야 한다.

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

---

<!-- detect-validate-42 -->
## Web3 사고 대응 검증 (설정됨 ≠ 작동함)

Web3 사고 대응은 *온체인 포렌식·피해 확산 차단·복구·거래소 협조*로 구성된다. "대응 절차가 있다"는 문서와 "추적·차단이 실제로 작동한다"는 다르다 — 각 절차를 소유 자산/테스트넷에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 온체인 추적 | 자금 흐름 따라가나? | 공격자 주소→믹서 경로 | 단일 hop만 |
| 긴급 정지 | pause 작동하나? | 컨트랙트 정지 즉시 반영 | pause 권한 부재 |
| 자금 동결 | 차단 가능? | 토큰 freeze/blacklist | 불변 토큰 미차단 |
| 증거 보존 | tx 무결성? | 블록 해시 고정 보존 | 스크린샷만 |

### 대응 검증 (직접 확인)

```bash
# 1) 소유 컨트랙트에 긴급 정지 경로가 있는지 — pause/circuit breaker 부재면 차단 불가 신호
grep -rnE 'function pause|whenNotPaused|circuitBreaker|emergencyStop' contracts/ | head || echo "긴급정지 경로 미발견(대응 갭)"
# 2) 온체인 자금 흐름 추적(소유/테스트 주소) — 공격자→믹서 다중 hop 경로 보존
cast logs --from-block latest --address 0xVICTIM 'Transfer(address,address,uint256)' 2>/dev/null | head
```

> Web3 사고 대응은 *추적·차단이 작동하는가*다 — "IR 절차가 있다"와 "자금 흐름이 추적되고 긴급 정지가 즉시 반영되며 tx 증거가 보존된다"는 다르다. 각 절차를 소유 자산/테스트넷에서 직접 검증한다([[44_Incident_Response_DFIR]], [[07_Digital_Forensics]], [[12_Bug_Bounty]]).

---

<a name="english"></a>

# Web3 Incident Response

This document covers on-chain forensics and rapid response procedures to minimize damage when DeFi exploits, NFT rug pulls, or smart contract hacks occur. Due to blockchain's transaction immutability, pre-emptive defense and rapid containment of damage spread are the key priorities.

---

## 1. Web3 Incident Response Framework

### 1.1 Incident Classification

| Incident Type | Characteristics | Response Urgency |
|--------------|----------------|-----------------|
| Smart contract vulnerability exploit | Immediate fund theft | Immediate (minutes) |
| Private key theft | Entire wallet taken | Immediate |
| Flash loan attack | Completed within single transaction | Post-analysis |
| Governance attack | Malicious proposal passes through vote manipulation | Within hours |
| Oracle manipulation | Liquidation triggered by price feed manipulation | Immediate |
| Rug pull | Development team intentionally drains funds | Post-investigation |

### 1.2 Initial Response 5-Minute Checklist

```bash
# 1. Check suspicious transactions
curl -s "https://api.etherscan.io/api?module=account&action=txlist\
&address=VICTIM_CONTRACT&sort=desc&apikey=YourApiKey" | \
  python3 -c "import sys,json; txs=json.load(sys.stdin)['result'][:5]; \
  [print(f'{t[\"timeStamp\"]}: {t[\"hash\"][:20]}... value={int(t[\"value\"])/1e18:.2f}ETH') for t in txs]"

# 2. Check contract funds
cast balance CONTRACT_ADDRESS --rpc-url $RPC_URL

# 3. Check suspicious address against OFAC blocklist
# Query Chainalysis, TRM Labs API

# 4. If Pause function exists, execute immediately
cast send CONTRACT_ADDRESS "pause()" --private-key $ADMIN_KEY --rpc-url $RPC_URL

# 5. Emergency alert to community/team
```

---

## 2. On-Chain Forensics

### 2.1 Transaction Backtracing

The forensic tool traces attack transactions on-chain, reconstructs attacker fund flow, and calculates profit/loss for post-incident analysis.

### 2.2 Dune Analytics Query (SQL)

```sql
-- Detect abnormal large withdrawals from DeFi protocol
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
  AND value / 1e18 > 100  -- 100+ ETH withdrawals
ORDER BY value DESC
LIMIT 50;

-- Flash loan attack pattern (large borrow+repay in same block)
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

## 3. Containment of Damage Spread

### 3.1 Emergency Contract Pause (Pause Pattern)

```solidity
// Security pattern: Pausable contract
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureVault is Pausable, AccessControl {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // Daily withdrawal limit
    mapping(address => uint256) public dailyWithdrawn;
    mapping(address => uint256) public lastWithdrawDay;
    uint256 public constant DAILY_LIMIT = 10 ether;

    event EmergencyPause(address indexed by, string reason);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    // Guardian triggers emergency pause
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
            "Daily limit exceeded"
        );
        dailyWithdrawn[msg.sender] += amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
```

### 3.2 Whitehat Rescue Operation

Move vulnerable funds to a safe wallet before the attacker can drain them. Always notify the protocol team in advance that this is a whitehat action.

---

## 4. Post-Incident Recovery Procedures

### 4.1 Damage Assessment and Reporting

Calculate total losses in ETH and tokens, generate incident report including attack timeline, affected amounts, and countermeasures.

---

## 4.5 On-Chain Fund Tracing Automation — Following Funds Through Mixers and Bridges

Rather than cashing out stolen funds immediately, attackers often (1) obscure their origin through a mixer like Tornado Cash, or (2) move funds to a different blockchain via a cross-chain bridge to make tracing harder. The more specific "where are the funds right now" information you can provide when requesting exchange cooperation (section 5), the faster an exchange can freeze them -- so a pipeline that automatically traces fund movement determines how fast your initial response can move.

```python
#!/usr/bin/env python3
"""Recursively trace fund movement across multiple hops starting from an attacker's wallet, flagging mixer/bridge transit."""
import requests
from dataclasses import dataclass, field

KNOWN_MIXER_ADDRESSES = {
    "0x8589427373d6d84e98730d7795d8f6f8731fda0": "Tornado Cash (0.1 ETH pool)",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash Router",
}
KNOWN_BRIDGE_ADDRESSES = {
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole Bridge",
    "0x8484ef722627bf18ca5ae6bcf031c23e6e922b45": "Multichain Router",
}


@dataclass
class FundHop:
    tx_hash: str
    from_addr: str
    to_addr: str
    amount: float
    flag: str = ""


def trace_fund_movement(start_address: str, api_key: str, max_hops: int = 5) -> list[FundHop]:
    """Trace a wallet's outbound transactions hop-by-hop via an Etherscan-style API (conceptual code)."""
    hops: list[FundHop] = []
    current = start_address

    for hop_num in range(max_hops):
        resp = requests.get(
            "https://api.etherscan.io/api",
            params={
                "module": "account", "action": "txlist", "address": current,
                "sort": "asc", "apikey": api_key,
            },
            timeout=10,
        )
        txs = resp.json().get("result", [])
        outgoing = [tx for tx in txs if tx["from"].lower() == current.lower()]
        if not outgoing:
            break

        latest = max(outgoing, key=lambda t: int(t["value"]))
        to_addr = latest["to"].lower()
        flag = ""
        if to_addr in KNOWN_MIXER_ADDRESSES:
            flag = f"Passed through mixer: {KNOWN_MIXER_ADDRESSES[to_addr]}"
        elif to_addr in KNOWN_BRIDGE_ADDRESSES:
            flag = f"Passed through bridge: {KNOWN_BRIDGE_ADDRESSES[to_addr]}"

        hops.append(FundHop(
            tx_hash=latest["hash"], from_addr=current, to_addr=to_addr,
            amount=int(latest["value"]) / 1e18, flag=flag,
        ))
        current = to_addr

        if flag:
            break  # once funds enter a mixer, on-chain tracing effectively breaks here

    return hops


if __name__ == "__main__":
    hops = trace_fund_movement("0xATTACKER_WALLET", api_key="YOUR_ETHERSCAN_KEY")
    for h in hops:
        print(f"{h.tx_hash[:10]}... {h.from_addr[:10]} -> {h.to_addr[:10]} ({h.amount} ETH) {h.flag}")
```

**Limitations and practical response**: once funds enter a mixer, pure on-chain data alone makes the trail look severed -- getting any real chance of recovery requires combining (1) timing-correlation analysis matching a mixer's withdrawal timing and amount patterns against deposit records, (2) the clustering heuristics of commercial analysis tools like Chainalysis Reactor or TRM Labs, and (3) cross-referencing the sanctioned-address databases shared among many exchanges. Above all, remember that **the moment funds land in an exchange deposit is the only point where a freeze is possible** -- the whole point of this tracing pipeline is to predict that moment and pre-notify the relevant exchange.

---

## 5. Exchange Cooperation Requests

| Exchange | Contact | Response Time |
|----------|---------|--------------|
| Binance | law_enforcement@binance.com | 24~48h |
| Coinbase | compliance@coinbase.com | 24~72h |
| Kraken | support@kraken.com | 24~48h |
| OKX | legal@okx.com | 24~48h |

### 5.1 Information to Include in Request

```
1. List of attack transaction hashes
2. Attacker wallet address
3. Fund movement path (on-chain tracking results)
4. Damage amount and token types
5. Legal basis (police report number, etc.)
6. Contact information and affiliated legal entity
```

<!-- detect-validate-42 -->
## Web3 Incident Response Validation (Configured != Working)

Web3 incident response comprises *on-chain forensics, blast-radius containment, recovery, and exchange cooperation*. "We have a procedure" differs from "tracing/containment actually works" -- validate each step on owned assets/testnets.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| On-chain tracing | Follow fund flow? | Attacker addr -> mixer path | Single hop only |
| Emergency stop | Does pause work? | Contract halts immediately | No pause authority |
| Fund freezing | Can block? | Token freeze/blacklist | Immutable token uncontainable |
| Evidence preservation | Tx integrity? | Block hash fixed/preserved | Screenshots only |

### Response validation (verify directly)

```bash
# 1) Whether the owned contract has an emergency-stop path — absent pause/circuit breaker signals no containment
grep -rnE 'function pause|whenNotPaused|circuitBreaker|emergencyStop' contracts/ | head || echo "no emergency-stop path found (response gap)"
# 2) On-chain fund-flow tracing (owned/test address) — preserve the attacker->mixer multi-hop path
cast logs --from-block latest --address 0xVICTIM 'Transfer(address,address,uint256)' 2>/dev/null | head
```

> Web3 incident response is *whether tracing/containment works* -- "we have an IR procedure" differs from "fund flow is traced, emergency stop takes effect immediately, and tx evidence is preserved". Validate each step on owned assets/testnets directly ([[44_Incident_Response_DFIR]], [[07_Digital_Forensics]], [[12_Bug_Bounty]]).
