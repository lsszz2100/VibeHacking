# Web3 & 스마트 컨트랙트 보안 랩 (15_web3_smart_contract_lab)

> 💡 **교재 및 워게임 연계 안내**:
> - **연계 교재**: [42장 블록체인 및 Web3 보안](../../42_Blockchain_Web3_Security/06_blockchain_ctf_lab.md)
> - **워게임 트랙**: 워게임 터미널(`wargame/`) `web3` 트랙 (35개 문제)
> - **CLI 간편 실행**: `vhack lab start 15` 또는 `python3 vhack.py lab start 15` (접속: `http://localhost:8015`)
> - **테스트 실행**: `vhack lab test 15`

이 랩은 이더리움(EVM) 스마트 컨트랙트 및 탈중앙화 금융(DeFi) 프로토콜에서 발생하는
핵심 보안 취약점 4가지를 대화형 시뮬레이터와 Foundry/Cast CLI 환경을 통해 실습합니다.

---

## 서비스 구성

| 서비스 | 컨테이너명 | 포트 | 설명 |
|--------|------------|------|------|
| Web3 Security Simulator | `web3_smart_contract_lab` | 8015 | ChainDefend EVM 노드 & 웹 대시보드 |

**외부 접근 주소:**
- 웹 콘솔 & 대시보드: `http://localhost:8015`
- API 상태 확인: `http://localhost:8015/status`

---

## 4대 실습 시나리오 및 플래그 획득

### 1단계: Reentrancy (재진입 공격)
- **개념**: 외부 호출(`call.value`) 후 상태 변수(`balances[msg.sender]`)를 갱신하는 CEI(Checks-Effects-Interactions) 위반 취약점.
- **공격 목표**: 악성 수신 컨트랙트의 `fallback()` 함수를 통한 재귀 호출로 Vault 내 10 ETH 전액 탈취.
- **방어 기법**: ReentrancyGuard(`nonReentrant` 모디파이어) 및 Checks-Effects-Interactions 패턴 적용.
- **플래그 형식**: `FLAG{REENTRANCY_CHECK_EFFECT_INTERACTION_8831}`

### 2단계: Token Batch Overflow (정수 오버플로)
- **개념**: `receivers.length * value` 연산 시 256비트 부호 없는 정수(uint256)의 최대값 초과로 0으로 래핑(wrap-around)되는 취약점.
- **공격 목표**: 2개 수신 주소에 `0x8000000000000000000000000000000000000000000000000000000000000000` (2^255) 전송하여 검증을 우회하고 무제한 토큰 발행.
- **방어 기법**: Solidity 0.8+ 내장 정수 오버플로 체크 또는 OpenZeppelin SafeMath 사용.
- **플래그 형식**: `FLAG{ARITHMETIC_TOKEN_BATCH_OVERFLOW_4412}`

### 3단계: tx.origin Phishing (접근 제어 우회)
- **개념**: 관리자 권한 검증 시 `msg.sender` 대신 트랜잭션 최초 발신자인 `tx.origin`을 참조하여 발생하는 피싱 공격.
- **공격 목표**: 관리자를 유인하여 악성 중개 컨트랙트를 호출하게 만들고, Governance 컨트랙트의 소유권을 공격자로 이전.
- **방어 기법**: 인증 시 반드시 `msg.sender == owner`로 직접 호출자 검증.
- **플래그 형식**: `FLAG{TX_ORIGIN_PHISHING_OWNERSHIP_HIJACK_5920}`

### 4단계: Flash Loan AMM Price Manipulation (가격 오라클 조작)
- **개념**: 순간적으로 거액을 대출받을 수 있는 플래시론(Flash Loan)을 사용하여 탈중앙화 거래소(AMM)의 현물 가격 풀을 일시 왜곡.
- **공격 목표**: Skewed Oracle을 참조하는 취약한 대출 프로토콜에서 헐값의 담보로 프로토콜 자금 대량 탈취 후 차익 실현.
- **방어 기법**: 시간 가중 평균 가격(TWAP) 오라클 또는 Chainlink 탈중앙화 분산 오라클 사용.
- **플래그 형식**: `FLAG{FLASH_LOAN_ORACLE_MANIPULATION_PWN_7139}`

---

## 터미널 시뮬레이터 명령어

웹 대시보드 하단 터미널에서 다음 명령어를 실행할 수 있습니다:
```bash
help                         # 사용 가능한 명령어 안내
ls                           # 취약 컨트랙트 소스 파일 목록
cat ReentrancyVault.sol      # 금고 컨트랙트 코드 조회
cat TokenBank.sol            # 토큰 뱅크 컨트랙트 코드 조회
cat Governance.sol           # 거버넌스 컨트랙트 코드 조회
forge test                   # Foundry 스마트 컨트랙트 테스트 스위트 실행
cast balance 0xVault         # 컨트랙트 및 지갑 잔고 조회
status                       # 챌린지 클리어 진행도 확인
```
