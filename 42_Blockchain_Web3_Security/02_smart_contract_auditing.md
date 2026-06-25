> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 스마트 컨트랙트 감사

## 0. 초보자를 위한 개념 이해

### 스마트 컨트랙트 감사란?

**스마트 컨트랙트 감사(Smart Contract Audit)**는 블록체인에 배포하기 전에 코드의 취약점을 찾아내는 보안 리뷰입니다. 한번 배포하면 수정이 불가능하므로 배포 전 감사가 필수입니다.

**왜 중요한가:**
```
스마트 컨트랙트 특수성:

일반 소프트웨어:     버그 발견 → 패치 배포 → 해결
스마트 컨트랙트:     버그 발견 → (수정 불가!) → 자금 영구 손실

2023년 DeFi 해킹:
  총 피해액 ~$1.7B
  주요 원인:
    - 재진입 공격(Reentrancy): 40%
    - 로직 오류: 25%
    - 오라클 조작: 20%
```

### 주요 취약점 유형

```
1. 재진입 공격 (Reentrancy)
   withdraw()가 잔액 차감 전 외부 호출 허용
   → 반복 출금 가능
   → The DAO 해킹 원인 (2016, $60M)

2. 정수 오버플로 (Integer Overflow)
   uint8 max=255, +1 = 0 (오버플로)
   → Solidity 0.8+ 기본 방어, 이전 버전 취약

3. 접근 제어 오류
   owner()만 실행 가능한 함수에 modifier 누락
   → 누구나 관리자 권한 실행 가능

4. 타임스탬프 조작
   block.timestamp를 난수 생성에 사용
   → 채굴자가 조작 가능
```

### 필요한 도구
- **Slither**: Python 기반 정적 분석 (Trail of Bits)
- **Mythril**: 심볼릭 실행 분석 도구
- **Foundry/Forge**: 단위 테스트 + 퍼징

### 기초 실습 예제
```bash
# Slither로 스마트 컨트랙트 자동 분석
pip install slither-analyzer

# 분석 실행
slither vulnerable_contract.sol

# 출력 예시:
# VulnerableContract.withdraw() (line 15)
# Reentrancy in VulnerableContract.withdraw()
# State variables written after the call(s):
#   - balances[msg.sender] = 0
```

---

## 1. 핵심 취약점 분류 (SWC 기반)

### 1.1 재진입 공격 (Reentrancy) — SWC-107

```solidity
// 취약한 코드 (Checks-Effects-Interactions 패턴 위반)
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        
        // ❌ 상태 변경 전에 외부 호출 → 재진입 가능
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        
        balances[msg.sender] -= amount;  // 이미 재진입 후에 실행
    }
}

// 수정된 코드 (CEI 패턴)
contract SecureBank {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        
        // ✅ 상태 먼저 변경 (Checks-Effects-Interactions)
        balances[msg.sender] -= amount;
        
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
```

**공격 컨트랙트 구조:**
```solidity
contract Attacker {
    VulnerableBank target;
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
    
    receive() external payable {
        // 잔액이 있으면 계속 재진입
        if (address(target).balance >= msg.value) {
            target.withdraw(msg.value);
        }
    }
}
```

### 1.2 정수 오버플로우/언더플로우 — SWC-101

```solidity
// Solidity 0.8.x 이전: 체크 없는 산술
contract OldToken {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) external {
        // ❌ uint256 언더플로우: 잔액이 1일 때 2 빼면 2^256-1
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

// 해결: SafeMath 또는 Solidity 0.8.x 기본 체크
// Solidity 0.8.x: 오버플로우 시 자동 revert
// unchecked {} 블록 내에서는 체크 생략 (가스 최적화 시 주의)
```

### 1.3 tx.origin 인증 우회 — SWC-115

```solidity
// 취약: tx.origin은 원본 EOA, msg.sender는 직접 호출자
contract VulnerableWallet {
    address owner;
    
    function transfer(address to, uint256 amount) external {
        // ❌ 악의적 컨트랙트가 중간에 호출하면 tx.origin은 여전히 owner
        require(tx.origin == owner, "not owner");
        payable(to).transfer(amount);
    }
}

// 피싱 공격: 피해자가 악성 컨트랙트 호출
// → 악성 컨트랙트 → VulnerableWallet.transfer()
// → tx.origin == 피해자(owner) ✓, msg.sender == 악성컨트랙트

// 수정: msg.sender 사용
require(msg.sender == owner, "not owner");
```

### 1.4 delegatecall 오용 — SWC-112

```solidity
// 취약한 프록시 패턴
contract Proxy {
    address public implementation;
    address public owner;
    
    // ❌ 슬롯 충돌: implementation의 슬롯 0 = Proxy의 슬롯 0 (implementation)
    // 공격자가 implementation 컨트랙트에서 슬롯 0 덮어쓰기 가능
    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
```

**Parity Multisig 해킹 (2017, $30M):** 초기화 함수가 external로 노출되어 공격자가 owner를 탈취.

### 1.5 접근 제어 미흡 — SWC-105

```solidity
// 취약: 초기화 함수에 접근 제어 없음
contract VulnerableToken {
    address public owner;
    bool initialized;
    
    // ❌ 누구나 호출 가능한 초기화
    function initialize(address _owner) external {
        owner = _owner;
        initialized = true;
    }
}
```

### 1.6 기타 주요 취약점 목록

| SWC ID | 취약점명 | 설명 |
|--------|---------|------|
| SWC-103 | Floating Pragma | 컴파일러 버전 고정 안 됨 |
| SWC-104 | Unchecked Call Return | call() 반환값 미확인 |
| SWC-106 | Unprotected SELFDESTRUCT | 임의 파괴 가능 |
| SWC-108 | State Variable Default Visibility | 기본 internal 착각 |
| SWC-110 | Assert Violation | 불변식 위반 |
| SWC-116 | Block Timestamp Manipulation | block.timestamp 조작 |
| SWC-120 | Weak Sources of Randomness | blockhash 기반 난수 |
| SWC-127 | Arbitrary Jump | 함수 포인터 조작 |
| SWC-135 | Code With No Effects | 죽은 코드 |

---

## 2. 자동화 감사 도구

### 2.1 Slither

```bash
# 설치
pip install slither-analyzer

# 기본 감사
slither contract.sol

# 특정 감지자만 실행
slither contract.sol --detect reentrancy-eth,controlled-delegatecall

# JSON 출력
slither contract.sol --json output.json

# 상속 그래프 출력
slither contract.sol --print inheritance-graph

# 함수 요약
slither contract.sol --print function-summary

# 변수 읽기/쓰기 추적
slither contract.sol --print variable-order
```

### 2.2 Mythril

```bash
# 설치
pip install mythril

# 심볼릭 실행 분석
myth analyze contract.sol --solv 0.8.19

# 온체인 컨트랙트 분석
myth analyze -a 0xContractAddress --rpc https://mainnet.infura.io/v3/KEY

# 실행 깊이 설정
myth analyze contract.sol --max-depth 12 --execution-timeout 300

# JSON 보고서
myth analyze contract.sol -o json
```

### 2.3 Echidna (Fuzzing)

```solidity
// Echidna 퍼징 속성 정의
contract TokenFuzz {
    Token token;
    
    constructor() { token = new Token(); }
    
    // 불변식: 총 공급량은 변하지 않아야 한다
    function echidna_total_supply_constant() public view returns (bool) {
        return token.totalSupply() == 1_000_000 * 1e18;
    }
    
    // 불변식: 잔액 합산 <= 총 공급량
    function echidna_balance_leq_supply() public view returns (bool) {
        return token.balanceOf(address(this)) <= token.totalSupply();
    }
}
```

```bash
# Echidna 실행
echidna-test TokenFuzz.sol --contract TokenFuzz --test-mode assertion
```

---

## 3. Slither 결과 파싱 감사 자동화 CLI

```python
#!/usr/bin/env python3
"""Slither 감사 결과 파싱 및 리포트 생성 CLI"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Optimization": 4}
SEVERITY_COLOR = {
    "High": "\033[91m",
    "Medium": "\033[93m",
    "Low": "\033[94m",
    "Informational": "\033[96m",
    "Optimization": "\033[92m",
}
RESET = "\033[0m"


@dataclass
class Finding:
    detector: str
    impact: str
    confidence: str
    description: str
    elements: list[dict] = field(default_factory=list)

    @property
    def location(self) -> str:
        locs = []
        for e in self.elements:
            if e.get('type') == 'function':
                name = e.get('name', '?')
                src = e.get('source_mapping', {})
                filename = src.get('filename_short', '')
                lines = src.get('lines', [])
                line_str = f":{lines[0]}" if lines else ""
                locs.append(f"{filename}{line_str}:{name}()")
        return ", ".join(locs) if locs else "N/A"


def run_slither(target: str, timeout: int = 120) -> dict:
    """Slither 실행 후 JSON 결과 반환"""
    cmd = ["slither", target, "--json", "-"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
        return {"results": {"detectors": []}, "error": result.stderr}
    except subprocess.TimeoutExpired:
        print(f"[!] Slither 타임아웃 ({timeout}s)", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("[!] slither가 설치되어 있지 않습니다: pip install slither-analyzer", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] JSON 파싱 실패: {e}", file=sys.stderr)
        sys.exit(1)


def parse_findings(slither_output: dict) -> list[Finding]:
    findings = []
    detectors = slither_output.get("results", {}).get("detectors", [])

    for d in detectors:
        findings.append(Finding(
            detector=d.get("check", "unknown"),
            impact=d.get("impact", "Unknown"),
            confidence=d.get("confidence", "Unknown"),
            description=d.get("description", "").strip(),
            elements=d.get("elements", []),
        ))

    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.impact, 99))


def print_report(findings: list[Finding], target: str, min_severity: str = "Informational") -> None:
    min_order = SEVERITY_ORDER.get(min_severity, 99)

    filtered = [f for f in findings if SEVERITY_ORDER.get(f.impact, 99) <= min_order]

    print(f"\n{'='*70}")
    print(f"Slither 감사 보고서 | {target} | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*70}")

    counts: dict[str, int] = {}
    for f in filtered:
        counts[f.impact] = counts.get(f.impact, 0) + 1

    print("\n[요약]")
    for sev in ["High", "Medium", "Low", "Informational", "Optimization"]:
        c = counts.get(sev, 0)
        color = SEVERITY_COLOR.get(sev, "")
        if c:
            print(f"  {color}{sev:<15}{RESET}: {c}개")

    print(f"\n[발견사항 상세 — {len(filtered)}개]\n")
    for i, f in enumerate(filtered, 1):
        color = SEVERITY_COLOR.get(f.impact, "")
        print(f"  [{i:02d}] {color}[{f.impact}]{RESET} {f.detector}")
        print(f"       신뢰도: {f.confidence}")
        print(f"       위치  : {f.location}")
        # 설명 줄바꿈 처리
        desc_lines = f.description.replace('\t', ' ').split('\n')
        for line in desc_lines[:3]:  # 최대 3줄
            if line.strip():
                print(f"       설명  : {line.strip()[:100]}")
        print()


def export_markdown(findings: list[Finding], target: str, output_path: str) -> None:
    lines = [
        f"# 스마트 컨트랙트 감사 보고서",
        f"",
        f"**대상:** `{target}`  ",
        f"**일시:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**도구:** Slither",
        f"",
        f"## 요약",
        f"",
        f"| 심각도 | 개수 |",
        f"|--------|------|",
    ]

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.impact] = counts.get(f.impact, 0) + 1

    for sev in ["High", "Medium", "Low", "Informational"]:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")

    lines += ["", "## 발견사항", ""]
    for i, f in enumerate(findings, 1):
        lines += [
            f"### [{i}] {f.detector} — {f.impact}",
            f"",
            f"- **신뢰도:** {f.confidence}",
            f"- **위치:** `{f.location}`",
            f"",
            f"```",
            f.description[:500],
            f"```",
            f"",
        ]

    Path(output_path).write_text('\n'.join(lines), encoding='utf-8')
    print(f"[+] 마크다운 보고서 저장: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="스마트 컨트랙트 Slither 감사 CLI")
    parser.add_argument("target", help="감사 대상 (.sol 파일 또는 디렉토리)")
    parser.add_argument("--min-severity", default="Low",
                        choices=["High", "Medium", "Low", "Informational", "Optimization"],
                        help="최소 심각도 필터 (기본: Low)")
    parser.add_argument("--export-md", metavar="FILE", help="마크다운 보고서 출력 파일")
    parser.add_argument("--timeout", type=int, default=120, help="Slither 실행 타임아웃 (초)")

    args = parser.parse_args()

    print(f"[*] Slither 실행 중: {args.target}")
    output = run_slither(args.target, args.timeout)

    if "error" in output and output["error"]:
        print(f"[!] Slither 경고/오류:\n{output['error'][:500]}", file=sys.stderr)

    findings = parse_findings(output)
    print_report(findings, args.target, args.min_severity)

    if args.export_md:
        export_markdown(findings, args.target, args.export_md)


if __name__ == "__main__":
    main()
```

**사용 예시:**
```bash
# 기본 감사
python audit.py contracts/Token.sol

# Medium 이상만 표시
python audit.py contracts/ --min-severity Medium

# 마크다운 보고서 생성
python audit.py contracts/Token.sol --export-md report.md
```

---

## 4. Foundry PoC 작성 패턴

```solidity
// 재진입 공격 PoC (Foundry Test)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/VulnerableBank.sol";

contract ReentrancyPoC is Test {
    VulnerableBank bank;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        bank = new VulnerableBank();
        deal(victim, 10 ether);
        vm.prank(victim);
        bank.deposit{value: 10 ether}();
        deal(attacker, 1 ether);
    }

    function test_reentrancy() public {
        AttackContract atk = new AttackContract(address(bank));
        deal(address(atk), 1 ether);
        
        uint256 bankBefore = address(bank).balance;
        atk.attack{value: 1 ether}();
        uint256 stolen = bankBefore - address(bank).balance;
        
        console.log("탈취된 금액:", stolen / 1e18, "ETH");
        assertGt(stolen, 1 ether, "재진입 공격 성공");
    }
}
```

```bash
# 실행
forge test -vvv --match-test test_reentrancy
```

---

## 5. 감사 체크리스트

| 카테고리 | 확인 항목 | 도구 |
|---------|----------|------|
| 재진입 | 외부 호출 전 상태 변경 여부 | Slither (reentrancy-eth) |
| 접근 제어 | 민감 함수 modifier 확인 | Slither (suicidal, controlled-delegatecall) |
| 산술 | unchecked 블록 오용 | Slither (integer-overflow) |
| 가스 | 루프 내 SSTORE, DoS 가능성 | 수동 검토 |
| 업그레이드 | 프록시 슬롯 충돌 검사 | Slither (uninitialized-local) |
| 랜덤 | block.timestamp/blockhash 의존 | Slither (weak-prng) |
| 이벤트 | 중요 상태 변경 이벤트 발생 여부 | 수동 검토 |
| 입력 검증 | 주소 0 체크, 범위 검사 | 수동 검토 |

---

<!-- detect-validate-42 -->
## 스마트 컨트랙트 취약점 탐지와 악용가능성 검증

스마트 컨트랙트 감사는 *재진입·정수 오버플로·접근제어·언체크 외부호출(SWC)*을 Slither/Foundry로 찾는다. 정적 도구 결과는 오탐이 많으므로 분석자는 **발견이 실제 도달·악용 가능한지**를 검증해야 한다. 검증은 **소유 컨트랙트/포크 테스트넷**에서만.

### 취약점 → 노리는 약점 → 1차 통제 → 검증(악용가능성)

| 취약점 | 노리는 약점 | 1차 통제 | 검증(악용가능성) |
|---|---|---|---|
| 재진입 | 상태변경 전 외부호출 | CEI·nonReentrant | PoC로 자금 인출 재현 |
| 접근제어 누락 | 권한 검사 부재 | onlyOwner·역할 | 비권한 계정 호출 성공 |
| 언체크 외부호출 | 반환값 무시 | require 검사 | 실패호출 무시 재현 |
| 정수 문제 | 오버/언더플로 | SafeMath·^0.8 | 경계값 PoC |

### 감사 검증 (직접 확인)

```bash
# 1) 소유 컨트랙트 정적 분석 — 재진입/접근제어 발견 후 도달성 판단(오탐 제거)
slither contracts/Vault.sol --detect reentrancy-eth,arbitrary-send-eth 2>/dev/null | grep -iE 'reentrancy|arbitrary' | head
# 2) 발견을 PoC로 악용 재현 — 포크 테스트넷에서 익스플로잇 테스트가 통과하면 실제 취약 신호
forge test --match-test testReentrancyExploit -vv 2>/dev/null | grep -iE 'PASS|FAIL|\[' | head
```

> 컨트랙트 감사는 *발견이 악용 가능한가*다 — "Slither가 경고했다"와 "그 경로가 도달 가능하고 PoC로 자금이 빠진다"는 다르다. 소유 컨트랙트/포크에서 악용가능성을 직접 검증한다([[12_Bug_Bounty]], [[74_Code_Auditing]], [[30_Vulnerability_Research]]).

---

<a name="english"></a>

# Smart Contract Auditing

Smart contracts cannot be modified once deployed. Vulnerabilities can result in hundreds of millions of dollars in stolen assets, and this has happened repeatedly in practice. This document covers the major vulnerability classifications in smart contracts, automated audit tools, and Python-based audit pipelines.

---

## 1. Core Vulnerability Classification (SWC-based)

### 1.1 Reentrancy Attack — SWC-107

The Checks-Effects-Interactions (CEI) pattern violation enables attackers to repeatedly call back into a function before state changes are committed.

**Vulnerable code:**
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");
    // ❌ External call before state change → reentrancy possible
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
    balances[msg.sender] -= amount;  // Already re-entered by now
}
```

**Secure code (CEI pattern):**
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");
    // ✅ State change first (Checks-Effects-Interactions)
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
}
```

### 1.2 Integer Overflow/Underflow — SWC-101

In Solidity versions prior to 0.8.x, arithmetic lacks overflow/underflow checks. The solution is to use SafeMath or Solidity 0.8.x (which has built-in checks).

### 1.3 tx.origin Authentication Bypass — SWC-115

`tx.origin` is the original EOA, while `msg.sender` is the direct caller. Using `tx.origin` for authentication allows phishing attacks via malicious intermediary contracts.

**Fix:** Use `msg.sender` instead of `tx.origin`.

### 1.4 delegatecall Misuse — SWC-112

Storage slot collision in proxy patterns can allow attackers to overwrite critical contract state, as seen in the Parity Multisig Hack (2017, $30M).

### 1.5 Insufficient Access Control — SWC-105

Initialization functions exposed as `external` without access control allow anyone to claim ownership.

### 1.6 Other Key Vulnerabilities

| SWC ID | Vulnerability | Description |
|--------|--------------|-------------|
| SWC-103 | Floating Pragma | Compiler version not fixed |
| SWC-104 | Unchecked Call Return | call() return value not checked |
| SWC-106 | Unprotected SELFDESTRUCT | Arbitrary destruction possible |
| SWC-116 | Block Timestamp Manipulation | block.timestamp can be manipulated |
| SWC-120 | Weak Sources of Randomness | blockhash-based randomness |

---

## 2. Automated Audit Tools

### 2.1 Slither

```bash
# Install
pip install slither-analyzer

# Basic audit
slither contract.sol

# Run specific detectors only
slither contract.sol --detect reentrancy-eth,controlled-delegatecall

# JSON output
slither contract.sol --json output.json

# Print inheritance graph
slither contract.sol --print inheritance-graph

# Print function summary
slither contract.sol --print function-summary
```

### 2.2 Mythril

```bash
# Install
pip install mythril

# Symbolic execution analysis
myth analyze contract.sol --solv 0.8.19

# Analyze on-chain contract
myth analyze -a 0xContractAddress --rpc https://mainnet.infura.io/v3/KEY

# JSON report
myth analyze contract.sol -o json
```

### 2.3 Echidna (Fuzzing)

Echidna uses property-based testing to find invariant violations in smart contracts. Define invariants as functions that return bool, then let Echidna try to falsify them.

---

## 3. Foundry PoC Patterns

```solidity
// Reentrancy Attack PoC (Foundry Test)
contract ReentrancyPoC is Test {
    VulnerableBank bank;

    function setUp() public {
        bank = new VulnerableBank();
        deal(makeAddr("victim"), 10 ether);
        vm.prank(makeAddr("victim"));
        bank.deposit{value: 10 ether}();
    }

    function test_reentrancy() public {
        AttackContract atk = new AttackContract(address(bank));
        deal(address(atk), 1 ether);
        
        uint256 bankBefore = address(bank).balance;
        atk.attack{value: 1 ether}();
        uint256 stolen = bankBefore - address(bank).balance;
        
        console.log("Stolen:", stolen / 1e18, "ETH");
        assertGt(stolen, 1 ether, "Reentrancy attack succeeded");
    }
}
```

```bash
# Run
forge test -vvv --match-test test_reentrancy
```

---

## 4. Audit Checklist

| Category | Check Item | Tool |
|----------|-----------|------|
| Reentrancy | State change before external call | Slither (reentrancy-eth) |
| Access control | Sensitive function modifier check | Slither (suicidal, controlled-delegatecall) |
| Arithmetic | unchecked block misuse | Slither (integer-overflow) |
| Gas | SSTORE in loop, DoS possibility | Manual review |
| Upgrade | Proxy slot collision check | Slither (uninitialized-local) |
| Randomness | block.timestamp/blockhash dependency | Slither (weak-prng) |
| Events | Key state change events emitted | Manual review |
| Input validation | Zero address check, range validation | Manual review |

<!-- detect-validate-42 -->
## Smart-Contract Vulnerability Detection and Exploitability Validation

Smart-contract auditing finds *reentrancy, integer overflow, access control, and unchecked external calls (SWC)* with Slither/Foundry. Static-tool results are noisy, so the analyst must verify **whether a finding is actually reachable and exploitable**. Validate only on **owned contracts/forked testnets**.

### Vulnerability -> Targeted weakness -> Primary control -> Validation (exploitability)

| Vulnerability | Targeted weakness | Primary control | Validation (exploitability) |
|---|---|---|---|
| Reentrancy | External call before state change | CEI, nonReentrant | Reproduce fund drain via PoC |
| Missing access control | No authorization check | onlyOwner, roles | Unauthorized account call succeeds |
| Unchecked external call | Ignored return value | require check | Reproduce ignored failed call |
| Integer issue | Over/underflow | SafeMath, ^0.8 | Boundary-value PoC |

### Audit validation (verify directly)

```bash
# 1) Static analysis on an owned contract — judge reachability after a reentrancy/access finding (remove FPs)
slither contracts/Vault.sol --detect reentrancy-eth,arbitrary-send-eth 2>/dev/null | grep -iE 'reentrancy|arbitrary' | head
# 2) Reproduce the finding as a PoC — a passing exploit test on a forked testnet signals a real vulnerability
forge test --match-test testReentrancyExploit -vv 2>/dev/null | grep -iE 'PASS|FAIL|\[' | head
```

> Contract auditing is *whether a finding is exploitable* -- "Slither warned" differs from "that path is reachable and a PoC drains funds". Validate exploitability on owned contracts/forks directly ([[12_Bug_Bounty]], [[74_Code_Auditing]], [[30_Vulnerability_Research]]).
