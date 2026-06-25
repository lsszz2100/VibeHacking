> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 블록체인 기초와 위협 모델

## 0. 초보자를 위한 개념 이해

### 블록체인이란?

**블록체인(Blockchain)**은 여러 컴퓨터에 동시에 기록되는 분산 데이터베이스입니다. 한 곳에서 데이터를 바꾸려면 전체 네트워크의 51% 이상을 동시에 바꿔야 하므로 변조가 매우 어렵습니다.

**보안 관점 왜 중요한가:**
```
블록체인의 특성과 보안 영향:

불변성 (Immutable):
  → 버그 있는 스마트 컨트랙트도 수정 불가
  → 공격 성공 시 피해 영구화

탈중앙화 (Decentralized):
  → 중앙 관리자 없음 → 침해 신고·대응 어려움
  → 피해자 구제 매우 어려움

투명성 (Transparent):
  → 모든 트랜잭션 공개 → 공격 추적 가능
  → 동시에 공격자 익명성 보장 (주소만 표시)

실제 피해:
  2022년 Ronin 브릿지: $625M 탈취
  2021년 Poly Network: $611M 탈취
  → 전통 금융보다 빠른 자금 이동, 추적 어려움
```

### 핵심 개념 정리

```
스마트 컨트랙트:
  블록체인 위에서 자동 실행되는 코드
  조건 충족 시 자동으로 자산 이동
  Ethereum: Solidity 언어로 작성

EVM (Ethereum Virtual Machine):
  Ethereum의 코드 실행 환경
  모든 노드에서 동일하게 실행 보장

DeFi (탈중앙화 금융):
  스마트 컨트랙트로 구현된 금융 서비스
  대출, 거래소, 이자 농사 등
  → 대규모 자금 = 공격자 주요 표적
```

### 필요한 도구
- **Remix IDE**: Solidity 코드 작성·테스트 (브라우저 기반)
- **Hardhat/Foundry**: 스마트 컨트랙트 개발·테스트 프레임워크
- **Web3.py / Ethers.js**: 블록체인 상호작용 라이브러리

### 기초 실습 예제
```python
# Web3.py로 블록체인 기본 정보 조회
from web3 import Web3

# Ethereum 메인넷 연결 (Infura 등 노드 제공자 사용)
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_KEY"))

if w3.is_connected():
    block = w3.eth.get_block('latest')
    print(f"최신 블록 번호: {block.number}")
    print(f"타임스탬프: {block.timestamp}")
    print(f"트랜잭션 수: {len(block.transactions)}")
```

---

## 1. 블록체인 아키텍처

### 1.1 UTXO vs 계정 모델

| 특성 | UTXO (Bitcoin) | 계정 모델 (Ethereum) |
|------|---------------|----------------------|
| 잔액 표현 | 미사용 출력의 합 | 계정 상태 |
| 병렬 처리 | 우수 (독립적 UTXO) | 제한적 (nonce 순서) |
| 스마트 컨트랙트 | 제한적 (Script) | 네이티브 지원 (EVM) |
| 개인정보 | 상대적으로 높음 | 낮음 (계정 주소 재사용) |
| 공격 표면 | 이중 지불, UTXO 먼지 공격 | 리엔트런시, 경쟁 조건 |

```
Bitcoin UTXO 트랜잭션 구조:
Input:  [이전_TxID + 출력_인덱스 + 서명 스크립트]
Output: [금액 + 잠금 스크립트(ScriptPubKey)]

Ethereum 트랜잭션 구조:
{nonce, gasPrice, gasLimit, to, value, data, v, r, s}
```

### 1.2 Merkle Tree와 SPV 공격

```
           Root Hash
          /          \
      H(AB)          H(CD)
     /     \        /    \
   H(A)   H(B)   H(C)   H(D)
    A       B      C      D
```

**SPV(Simple Payment Verification) 취약점:**
- 라이트 노드는 블록 헤더만 검증 → 유효하지 않은 머클 증명 제출 가능
- 이클립스 공격으로 라이트 노드를 격리하면 위조 트랜잭션 주입 가능

### 1.3 합의 알고리즘 보안 특성

| 합의 방식 | 대표 체인 | 공격 저항성 | 주요 취약점 |
|-----------|----------|------------|------------|
| PoW (작업증명) | Bitcoin | 51% 해시파워 필요 | 51% 공격, 셀피시 마이닝 |
| PoS (지분증명) | Ethereum | 51% 지분 필요 | 장거리 공격, Nothing-at-Stake |
| DPoS | EOS, TRON | 대표자 담합 위험 | 카르텔 형성, 검열 |
| PBFT | Hyperledger | 1/3 이상 비잔틴 노드 허용 | 네트워크 파티션 |

---

## 2. 이더리움 EVM 내부 구조

### 2.1 EVM 아키텍처

```
EVM 컴포넌트:
┌─────────────────────────────────────┐
│  스택 (Stack)   - 최대 1024 항목     │
│  메모리 (Memory) - 휘발성, 바이트 배열│
│  스토리지 (Storage) - 영구, 키-값    │
│  콜데이터 (Calldata) - 읽기 전용     │
│  반환데이터 (Returndata)             │
└─────────────────────────────────────┘

주요 오피코드:
SLOAD  (0x54) - 스토리지 읽기 (100 gas cold, 100 hot)
SSTORE (0x55) - 스토리지 쓰기 (20000 gas 신규, 2900 수정)
CALL   (0xF1) - 외부 호출 (재진입 공격 진입점)
DELEGATECALL (0xF4) - 컨텍스트 유지 호출 (프록시 패턴)
SELFDESTRUCT (0xFF) - 컨트랙트 파괴 + ETH 전송
```

### 2.2 스토리지 레이아웃

솔리디티 상태 변수는 슬롯 0부터 32바이트 단위로 저장된다.

```solidity
contract StorageLayout {
    uint256 public slot0;           // 슬롯 0
    address public slot1;           // 슬롯 1 (20바이트, 패딩 12바이트)
    bool    public flag;            // 슬롯 1 (패킹: address와 같은 슬롯)
    uint256[3] public arr;          // 슬롯 2,3,4
    mapping(address => uint256) balances; // 슬롯 5 (키: keccak256(key||slot))
}
```

```python
# 스토리지 슬롯 계산 예시
import web3
from eth_abi import encode

def mapping_slot(key: str, slot: int) -> str:
    """매핑 슬롯 주소 계산"""
    encoded = encode(['address', 'uint256'], [key, slot])
    return web3.Web3.keccak(encoded).hex()

def dynamic_array_slot(slot: int, index: int) -> int:
    """동적 배열 원소 슬롯 계산"""
    base = int(web3.Web3.keccak(slot.to_bytes(32, 'big')).hex(), 16)
    return base + index
```

### 2.3 ABI 인코딩 구조

```
함수 셀렉터: keccak256("transfer(address,uint256)")[:4]
            = 0xa9059cbb

인코딩 예시: transfer(0xABCD...1234, 1000)
0xa9059cbb                                                           <- 셀렉터
000000000000000000000000ABCD...1234                                  <- address (32바이트 패딩)
00000000000000000000000000000000000000000000000000000000000003E8    <- uint256 1000
```

---

## 3. 네트워크 레벨 공격

### 3.1 51% 공격 (이중 지불)

```
공격 시나리오:
1. 공격자가 전체 해시파워의 51% 이상 확보
2. 거래소에 1 BTC 입금 → 출금 후 교환
3. 비밀리에 더 긴 대안 체인 채굴
4. 거래소 확인 후 대안 체인 공개 → 원래 입금 트랜잭션 무효화

방어:
- 거래소: 대형 입금에 더 많은 확인 수 요구 (Bitcoin: 6 블록)
- 체인: Checkpointing, GHOST 프로토콜
```

### 3.2 셀피시 마이닝 (Selfish Mining)

```
정상 채굴:                    셀피시 마이닝:
블록 발견 → 즉시 공개          블록 발견 → 비밀 유지 → 유리할 때 공개
                               → 네트워크가 낭비 블록 만들도록 유도
```

25% 이상 해시파워만 있으면 이론적으로 수익 가능 (Eyal & Sirer, 2014).

### 3.3 이클립스 공격 (Eclipse Attack)

공격자가 피해 노드의 모든 P2P 연결을 점유하여 고립시키는 공격.

```
공격 조건 (Bitcoin P2P 기준):
- 피해 노드 재시작 유도
- 117개 아웃바운드 연결 슬롯 전부 공격자 노드로 채우기

영향:
- 0-confirmation 이중 지불 노출
- 라이트 클라이언트에 위조 트랜잭션 주입
- 마이닝 파워 낭비 유도

방어:
- 연결 다양화 (AS 레벨 다양성)
- Feeler 연결로 새 노드 탐색
```

### 3.4 트랜잭션 말리어빌리티 (Malleability)

```
원본 TxID: a1b2c3...
서명 변조: r, s → r, -s mod n (동일한 유효 서명)
변조 TxID: x9y8z7...  ← 다른 TxID지만 동일 트랜잭션

Bitcoin: SegWit으로 해결 (서명을 TxID 계산에서 분리)
Ethereum: EIP-2 (s 값을 절반 이하로 제한)
```

---

## 4. 블록체인 트랜잭션 분석 CLI

```python
#!/usr/bin/env python3
"""블록체인 트랜잭션 분석 도구"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Optional
from web3 import Web3
from web3.types import TxData


@dataclass
class TxAnalysis:
    tx_hash: str
    from_addr: str
    to_addr: Optional[str]
    value_eth: float
    gas_used: Optional[int]
    gas_price_gwei: float
    input_data: str
    function_selector: Optional[str]
    is_contract_creation: bool
    block_number: Optional[int]


def connect_rpc(rpc_url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"[!] RPC 연결 실패: {rpc_url}", file=sys.stderr)
        sys.exit(1)
    return w3


def analyze_tx(w3: Web3, tx_hash: str) -> TxAnalysis:
    try:
        tx: TxData = w3.eth.get_transaction(tx_hash)
    except Exception as e:
        print(f"[!] 트랜잭션 조회 실패: {e}", file=sys.stderr)
        sys.exit(1)

    receipt = None
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except Exception:
        pass

    input_data = tx.get('input', b'').hex()
    func_selector = input_data[2:10] if len(input_data) > 10 else None

    return TxAnalysis(
        tx_hash=tx_hash,
        from_addr=tx['from'],
        to_addr=tx.get('to'),
        value_eth=float(Web3.from_wei(tx['value'], 'ether')),
        gas_used=receipt['gasUsed'] if receipt else None,
        gas_price_gwei=float(Web3.from_wei(tx.get('gasPrice', 0), 'gwei')),
        input_data=input_data[:66] + '...' if len(input_data) > 66 else input_data,
        function_selector=func_selector,
        is_contract_creation=(tx.get('to') is None),
        block_number=tx.get('blockNumber'),
    )


def scan_address_txs(w3: Web3, address: str, start_block: int, end_block: int) -> list[dict]:
    """주소의 트랜잭션 이력 스캔 (블록 범위)"""
    results = []
    address = Web3.to_checksum_address(address)

    print(f"[*] 블록 {start_block}~{end_block} 스캔 중...")
    for block_num in range(start_block, min(end_block + 1, start_block + 100)):
        try:
            block = w3.eth.get_block(block_num, full_transactions=True)
            for tx in block['transactions']:
                if tx['from'].lower() == address.lower() or (
                    tx.get('to') and tx['to'].lower() == address.lower()
                ):
                    results.append({
                        'hash': tx['hash'].hex(),
                        'block': block_num,
                        'from': tx['from'],
                        'to': tx.get('to', 'Contract Creation'),
                        'value_eth': float(Web3.from_wei(tx['value'], 'ether')),
                    })
        except Exception:
            continue

    return results


def detect_suspicious_patterns(w3: Web3, tx_hash: str) -> list[str]:
    """의심스러운 트랜잭션 패턴 탐지"""
    warnings = []

    try:
        tx = w3.eth.get_transaction(tx_hash)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except Exception as e:
        return [f"조회 실패: {e}"]

    # 높은 가스 가격 (MEV/프론트러닝 징후)
    gas_price_gwei = float(Web3.from_wei(tx.get('gasPrice', 0), 'gwei'))
    if gas_price_gwei > 100:
        warnings.append(f"높은 가스 가격: {gas_price_gwei:.1f} Gwei (MEV/긴급 트랜잭션 의심)")

    # 실패한 트랜잭션
    if receipt and receipt['status'] == 0:
        warnings.append("트랜잭션 실패 (revert) — 잘못된 입력 또는 재진입 방어 트리거")

    # 컨트랙트 생성
    if tx.get('to') is None:
        warnings.append("컨트랙트 배포 트랜잭션")

    # 대용량 input data (복잡한 호출)
    input_len = len(tx.get('input', b''))
    if input_len > 1000:
        warnings.append(f"대용량 calldata: {input_len} bytes")

    # 0 value + input data (순수 컨트랙트 호출)
    if tx['value'] == 0 and input_len > 4:
        warnings.append("ETH 없는 컨트랙트 호출 (토큰 전송 또는 관리 함수)")

    return warnings


def main() -> None:
    parser = argparse.ArgumentParser(description="블록체인 트랜잭션 분석 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # 트랜잭션 분석
    tx_parser = sub.add_parser("tx", help="트랜잭션 상세 분석")
    tx_parser.add_argument("hash", help="트랜잭션 해시 (0x...)")
    tx_parser.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY", help="RPC URL")
    tx_parser.add_argument("--json", action="store_true", help="JSON 출력")

    # 주소 스캔
    scan_parser = sub.add_parser("scan", help="주소 트랜잭션 스캔")
    scan_parser.add_argument("address", help="이더리움 주소")
    scan_parser.add_argument("--start", type=int, required=True, help="시작 블록")
    scan_parser.add_argument("--end", type=int, required=True, help="종료 블록")
    scan_parser.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY")

    # 의심 패턴 탐지
    detect_parser = sub.add_parser("detect", help="의심 패턴 탐지")
    detect_parser.add_argument("hash", help="트랜잭션 해시")
    detect_parser.add_argument("--rpc", default="https://mainnet.infura.io/v3/YOUR_KEY")

    args = parser.parse_args()
    w3 = connect_rpc(args.rpc)
    chain_id = w3.eth.chain_id
    print(f"[+] 연결됨: Chain ID {chain_id}, 최신 블록 {w3.eth.block_number}")

    if args.command == "tx":
        analysis = analyze_tx(w3, args.hash)
        if args.json:
            print(json.dumps(analysis.__dict__, indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"TxHash  : {analysis.tx_hash}")
            print(f"Block   : {analysis.block_number}")
            print(f"From    : {analysis.from_addr}")
            print(f"To      : {analysis.to_addr or 'Contract Creation'}")
            print(f"Value   : {analysis.value_eth:.6f} ETH")
            print(f"Gas     : {analysis.gas_used or 'pending'}")
            print(f"GasPrice: {analysis.gas_price_gwei:.2f} Gwei")
            print(f"Selector: 0x{analysis.function_selector or 'N/A'}")
            print(f"Input   : {analysis.input_data}")

    elif args.command == "scan":
        txs = scan_address_txs(w3, args.address, args.start, args.end)
        print(f"\n[+] 발견된 트랜잭션: {len(txs)}개")
        for tx in txs:
            print(f"  {tx['block']} | {tx['hash'][:20]}... | {tx['value_eth']:.4f} ETH")

    elif args.command == "detect":
        warnings = detect_suspicious_patterns(w3, args.hash)
        if warnings:
            print(f"\n[!] 의심 패턴 {len(warnings)}개 발견:")
            for w in warnings:
                print(f"  ⚠  {w}")
        else:
            print("[+] 의심 패턴 없음")


if __name__ == "__main__":
    main()
```

**사용 예시:**
```bash
# 트랜잭션 분석
python analyzer.py tx 0xabc123... --rpc https://mainnet.infura.io/v3/KEY

# 주소 스캔
python analyzer.py scan 0xDEAD... --start 19000000 --end 19000100 --rpc $RPC

# 의심 패턴 탐지
python analyzer.py detect 0xabc123... --json
```

---

## 5. 위협 모델 요약

| 공격 유형 | 공격자 요구 조건 | 영향 | 현실적 위험도 |
|-----------|-----------------|------|--------------|
| 51% 공격 | 51%+ 해시파워/지분 | 이중 지불, 검열 | 소형 체인에서 높음 |
| 이클립스 공격 | 다수 IP 제어 | 노드 고립, 사기 | 중간 |
| 셀피시 마이닝 | 25%+ 해시파워 | 수익 증대 | 낮음 |
| 트랜잭션 말리어빌리티 | 없음 | TxID 변조 | SegWit 이후 낮음 |
| MEV/프론트러닝 | MEV 봇 운영 | 사용자 손실 | 현재 높음 |
| 스마트 컨트랙트 취약점 | 코드 분석 능력 | 자금 탈취 | 높음 |

---

<!-- detect-validate-42 -->
## 블록체인 위협 탐지와 노드/트랜잭션 무결성 검증

블록체인 위협 모델은 *네트워크 레벨 공격(이클립스·시빌·라우팅)·트랜잭션 변조·노드 노출*을 다룬다. 방어자는 **노드가 안전 구성되고 비정상 피어/트랜잭션이 탐지되는가**를 검증해야 한다. 검증은 **소유 노드/테스트넷**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 이클립스 공격 | 피어 다양성 부족 | 고정 피어·다양화 | 단일 ASN 피어 집중 |
| 시빌 공격 | 신원 비용 낮음 | 평판·스테이크 | 신규 노드 폭증 |
| RPC 노출 | 인증 없는 RPC | 인증·바인드 제한 | 외부서 eth_* 호출 |
| 트랜잭션 변조 | 서명 검증 부재 | 서명·논스 검증 | 비정상 nonce/from |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 노드 RPC가 외부에 노출됐는지 — 인증 없이 eth_accounts 응답 시 노출 신호
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' http://node.internal:8545 2>/dev/null | head -c 200; echo
# 2) 피어 다양성 점검(소유 노드) — 단일 ASN/IP 대역 집중이 이클립스 표면 신호
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}' http://node.internal:8545 2>/dev/null | jq -r '.result[]?.network.remoteAddress' 2>/dev/null | cut -d: -f1 | sort | uniq -c | sort -rn | head
```

> 블록체인 방어는 *노드/트랜잭션이 안전한가*다 — "체인이 동기화된다"와 "RPC가 인증되고 피어가 다양하며 비정상 nonce가 탐지된다"는 다르다. 소유 노드/테스트넷에서 직접 확인한다([[02_Network_Hacking]], [[16_Cryptography]], [[12_Bug_Bounty]]).

---

<a name="english"></a>

# Blockchain Fundamentals and Threat Models

Blockchain is a distributed ledger technology with immutability, decentralization, and transparency as its core properties. From a security perspective, these properties create new attack surfaces. This document covers blockchain security fundamentals from EVM architecture to network-level attacks.

---

## 1. Blockchain Architecture

### 1.1 UTXO vs. Account Model

| Property | UTXO (Bitcoin) | Account Model (Ethereum) |
|----------|---------------|--------------------------|
| Balance representation | Sum of unspent outputs | Account state |
| Parallel processing | Excellent (independent UTXOs) | Limited (nonce ordering) |
| Smart contracts | Limited (Script) | Native support (EVM) |
| Privacy | Relatively higher | Lower (account address reuse) |
| Attack surface | Double spending, UTXO dust attacks | Reentrancy, race conditions |

```
Bitcoin UTXO Transaction Structure:
Input:  [Previous TxID + output index + signature script]
Output: [Amount + locking script (ScriptPubKey)]

Ethereum Transaction Structure:
{nonce, gasPrice, gasLimit, to, value, data, v, r, s}
```

### 1.2 Merkle Trees and SPV Attacks

```
           Root Hash
          /          \
      H(AB)          H(CD)
     /     \        /    \
   H(A)   H(B)   H(C)   H(D)
    A       B      C      D
```

**SPV (Simple Payment Verification) vulnerabilities:**
- Light nodes only verify block headers → invalid Merkle proofs can be submitted
- Isolating a light node via an eclipse attack allows injection of forged transactions

### 1.3 Security Properties of Consensus Algorithms

| Consensus | Representative Chain | Attack Resistance | Key Vulnerabilities |
|-----------|---------------------|-------------------|---------------------|
| PoW (Proof of Work) | Bitcoin | Requires 51%+ hashpower | 51% attack, selfish mining |
| PoS (Proof of Stake) | Ethereum | Requires 51%+ stake | Long-range attacks, nothing-at-stake |
| DPoS | EOS, TRON | Risk of delegate collusion | Cartel formation, censorship |
| PBFT | Hyperledger | Tolerates up to 1/3 Byzantine nodes | Network partitions |

---

## 2. Ethereum EVM Internal Structure

### 2.1 EVM Architecture

```
EVM Components:
┌─────────────────────────────────────┐
│  Stack        - up to 1024 items    │
│  Memory       - volatile, byte array│
│  Storage      - persistent, key-val │
│  Calldata     - read-only           │
│  Returndata                         │
└─────────────────────────────────────┘

Key Opcodes:
SLOAD  (0x54) - storage read (100 gas cold, 100 hot)
SSTORE (0x55) - storage write (20000 gas new, 2900 modify)
CALL   (0xF1) - external call (reentrancy attack entry point)
DELEGATECALL (0xF4) - context-preserving call (proxy pattern)
SELFDESTRUCT (0xFF) - destroy contract + transfer ETH
```

### 2.2 Storage Layout

Solidity state variables are stored sequentially starting from slot 0 in 32-byte units.

```solidity
contract StorageLayout {
    uint256 public slot0;           // Slot 0
    address public slot1;           // Slot 1 (20 bytes, 12-byte padding)
    bool    public flag;            // Slot 1 (packed with address)
    uint256[3] public arr;          // Slots 2, 3, 4
    mapping(address => uint256) balances; // Slot 5 (key: keccak256(key||slot))
}
```

### 2.3 ABI Encoding Structure

```
Function selector: keccak256("transfer(address,uint256)")[:4]
                 = 0xa9059cbb

Encoding example: transfer(0xABCD...1234, 1000)
0xa9059cbb                                                           <- selector
000000000000000000000000ABCD...1234                                  <- address (32-byte padded)
00000000000000000000000000000000000000000000000000000000000003E8    <- uint256 1000
```

---

## 3. Network-Level Attacks

### 3.1 51% Attack (Double Spending)

```
Attack scenario:
1. Attacker acquires 51%+ of total hashpower
2. Deposits 1 BTC to exchange → withdraws and converts
3. Secretly mines a longer alternative chain
4. After exchange confirms deposit, publishes alternative chain → invalidates original deposit tx

Defenses:
- Exchanges: require more confirmations for large deposits (Bitcoin: 6 blocks)
- Chains: Checkpointing, GHOST protocol
```

### 3.2 Selfish Mining

```
Normal mining:               Selfish mining:
Find block → publish immediately   Find block → keep secret → publish when advantageous
                                   → Induces network to waste blocks
```

Theoretically profitable with just 25%+ hashpower (Eyal & Sirer, 2014).

### 3.3 Eclipse Attack

An attack where the attacker occupies all P2P connections of the victim node to isolate it.

```
Attack conditions (Bitcoin P2P):
- Induce victim node to restart
- Fill all 117 outbound connection slots with attacker nodes

Impact:
- Exposure to 0-confirmation double spending
- Injection of forged transactions to light clients
- Inducing mining power wastage

Defenses:
- Diversify connections (AS-level diversity)
- Use Feeler connections to discover new nodes
```

### 3.4 Transaction Malleability

```
Original TxID: a1b2c3...
Signature modification: r, s → r, -s mod n (same valid signature)
Modified TxID: x9y8z7...  ← different TxID but same transaction

Bitcoin: resolved by SegWit (separates signature from TxID calculation)
Ethereum: EIP-2 (restricts s value to half or less)
```

---

## 4. Blockchain Transaction Analysis CLI

```python
#!/usr/bin/env python3
"""Blockchain transaction analysis tool"""
# (See Korean section above for full implementation)
```

**Usage examples:**
```bash
# Transaction analysis
python analyzer.py tx 0xabc123... --rpc https://mainnet.infura.io/v3/KEY

# Address scan
python analyzer.py scan 0xDEAD... --start 19000000 --end 19000100 --rpc $RPC

# Suspicious pattern detection
python analyzer.py detect 0xabc123... --json
```

---

## 5. Threat Model Summary

| Attack Type | Attacker Requirements | Impact | Real-World Risk |
|-------------|----------------------|--------|-----------------|
| 51% attack | 51%+ hashpower/stake | Double spending, censorship | High on small chains |
| Eclipse attack | Control of many IPs | Node isolation, fraud | Medium |
| Selfish mining | 25%+ hashpower | Increased profit | Low |
| Transaction malleability | None | TxID forgery | Low since SegWit |
| MEV/front-running | Operating MEV bots | User losses | Currently high |
| Smart contract vulnerabilities | Code analysis skills | Fund theft | High |

<!-- detect-validate-42 -->
## Blockchain Threat Detection and Node/Transaction Integrity Validation

The blockchain threat model covers *network-level attacks (eclipse, Sybil, routing), transaction tampering, and node exposure*. Defenders must verify **whether nodes are securely configured and anomalous peers/transactions are detected**. Validate only on **owned nodes/testnets**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Eclipse attack | Low peer diversity | Static/diverse peers | Single-ASN peer concentration |
| Sybil attack | Cheap identity | Reputation, stake | New-node surge |
| RPC exposure | Unauthenticated RPC | Auth, bind restriction | External eth_* calls |
| Transaction tampering | No signature check | Signature/nonce verify | Anomalous nonce/from |

### Defense validation (verify directly)

```bash
# 1) Whether the owned node RPC is externally exposed — an eth_accounts response without auth signals exposure
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' http://node.internal:8545 2>/dev/null | head -c 200; echo
# 2) Peer-diversity check (owned node) — single-ASN/IP-range concentration signals an eclipse surface
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}' http://node.internal:8545 2>/dev/null | jq -r '.result[]?.network.remoteAddress' 2>/dev/null | cut -d: -f1 | sort | uniq -c | sort -rn | head
```

> Blockchain defense is *whether nodes/transactions are safe* -- "the chain syncs" differs from "RPC is authenticated, peers are diverse, and anomalous nonces are detected". Confirm on owned nodes/testnets directly ([[02_Network_Hacking]], [[16_Cryptography]], [[12_Bug_Bounty]]).
