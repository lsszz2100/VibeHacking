# 스마트 컨트랙트 감사

스마트 컨트랙트는 한번 배포하면 수정이 불가능하다. 취약점이 있으면 수억 달러의 자산이 탈취될 수 있고, 이는 실제로 반복적으로 발생해왔다. 이 문서는 스마트 컨트랙트의 주요 취약점 분류, 자동화 감사 도구, Python 기반 감사 파이프라인을 다룬다.

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
