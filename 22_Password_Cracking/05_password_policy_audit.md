# 패스워드 정책 감사 — 약한 정책 탐지·해시 강도 분석·권고사항

## 1. 패스워드 보안 감사 개요

```
패스워드 정책 감사
    │
    ├── 정책 분석
    │     - 최소 길이, 복잡도 요구사항
    │     - 만료 주기, 이력 관리
    │     - 계정 잠금 정책
    │
    ├── 해시 알고리즘 감사
    │     - 약한 해시 탐지 (MD5, SHA-1, LM)
    │     - 솔트 사용 여부
    │     - 반복 횟수 (bcrypt cost, PBKDF2 iterations)
    │
    └── 실제 패스워드 강도 분석
          - 덤프된 해시 크래킹 시도율
          - 공통 패스워드 패턴
          - 엔트로피 측정
```

---

## 2. 패스워드 정책 감사 CLI

```python
#!/usr/bin/env python3
"""패스워드 정책 감사 — 설정 분석 및 취약점 리포트 생성."""

import argparse
import json
import math
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PolicyCheck:
    name: str
    passed: bool
    current_value: str
    recommended: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    detail: str


@dataclass
class PolicyAuditReport:
    platform: str
    checks: list[PolicyCheck] = field(default_factory=list)

    def score(self) -> int:
        if not self.checks:
            return 0
        passed = sum(1 for c in self.checks if c.passed)
        return int(passed / len(self.checks) * 100)

    def critical_failures(self) -> list[PolicyCheck]:
        return [c for c in self.checks if not c.passed and c.severity == "CRITICAL"]


def audit_linux_pam_policy(pam_dir: Path = Path("/etc/pam.d")) -> PolicyAuditReport:
    """Linux PAM 패스워드 정책 감사."""
    report = PolicyAuditReport(platform="Linux PAM")

    # /etc/login.defs 파싱
    login_defs = Path("/etc/login.defs")
    defs: dict[str, str] = {}
    if login_defs.exists():
        for line in login_defs.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    defs[parts[0]] = parts[1]

    # 최소 길이
    min_len = int(defs.get("PASS_MIN_LEN", "0"))
    report.checks.append(PolicyCheck(
        name="최소 패스워드 길이",
        passed=min_len >= 12,
        current_value=str(min_len),
        recommended="12자 이상",
        severity="CRITICAL",
        detail=f"현재 {min_len}자 — NIST SP 800-63B 권고: 최소 8자, 권장 12자+",
    ))

    # 만료 기간
    max_days = int(defs.get("PASS_MAX_DAYS", "99999"))
    report.checks.append(PolicyCheck(
        name="패스워드 만료 기간",
        passed=max_days <= 365,
        current_value=f"{max_days}일",
        recommended="90~365일",
        severity="HIGH",
        detail=f"현재 {max_days}일 — 주기적 변경 강제 필요",
    ))

    # 최소 사용 기간
    min_days = int(defs.get("PASS_MIN_DAYS", "0"))
    report.checks.append(PolicyCheck(
        name="최소 사용 기간",
        passed=min_days >= 1,
        current_value=f"{min_days}일",
        recommended="1일 이상",
        severity="MEDIUM",
        detail="즉각 재변경 방지",
    ))

    # pwquality.conf 확인
    pwquality = Path("/etc/security/pwquality.conf")
    if pwquality.exists():
        content = pwquality.read_text()
        has_minlen = "minlen" in content
        has_dcredit = "dcredit" in content
        has_ucredit = "ucredit" in content
        has_retry = "retry" in content

        report.checks.append(PolicyCheck(
            name="복잡도 요구사항 (pwquality)",
            passed=has_minlen and (has_dcredit or has_ucredit),
            current_value="설정됨" if has_minlen else "미설정",
            recommended="minlen, dcredit, ucredit, retry 설정",
            severity="HIGH",
            detail="숫자·대문자 포함 요구 설정",
        ))
    else:
        report.checks.append(PolicyCheck(
            name="복잡도 요구사항 (pwquality)",
            passed=False,
            current_value="미설치",
            recommended="libpam-pwquality 설치 및 설정",
            severity="HIGH",
            detail="패스워드 복잡도 강제 모듈 없음",
        ))

    # /etc/shadow 해시 알고리즘 확인
    shadow = Path("/etc/shadow")
    if shadow.exists():
        try:
            content = shadow.read_text()
            hash_types: dict[str, int] = {}
            for line in content.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1].startswith("$"):
                    algo = parts[1].split("$")[1]
                    hash_types[algo] = hash_types.get(algo, 0) + 1

            weak_algos = {k: v for k, v in hash_types.items() if k in ("1", "2a", "5")}
            report.checks.append(PolicyCheck(
                name="패스워드 해시 알고리즘",
                passed=not weak_algos,
                current_value=str(hash_types),
                recommended="$6$ (SHA-512) 또는 $y$ (yescrypt)",
                severity="CRITICAL",
                detail=f"약한 알고리즘 사용: {weak_algos}" if weak_algos else "강한 알고리즘 사용 중",
            ))
        except PermissionError:
            report.checks.append(PolicyCheck(
                name="패스워드 해시 알고리즘",
                passed=True,
                current_value="권한 없음",
                recommended="루트 권한으로 재실행",
                severity="LOW",
                detail="/etc/shadow 접근 불가",
            ))

    return report


def audit_password_hashes(hash_file: Path) -> dict:
    """해시 파일에서 알고리즘 분포 및 약점 분석."""
    algorithm_counts: dict[str, int] = {}
    total = 0
    weak_users: list[str] = []

    HASH_PATTERNS = {
        r"^\$1\$": "MD5-crypt (약함)",
        r"^\$2[aby]\$": "bcrypt",
        r"^\$5\$": "SHA-256-crypt",
        r"^\$6\$": "SHA-512-crypt",
        r"^\$y\$": "yescrypt (강함)",
        r"^[a-fA-F0-9]{32}$": "MD5 (매우 약함)",
        r"^[a-fA-F0-9]{40}$": "SHA-1 (약함)",
        r"^[a-fA-F0-9]{64}$": "SHA-256 (솔트 없음, 약함)",
        r"^[A-Z0-9]{13}$": "DES-crypt (매우 약함)",
    }

    for line in hash_file.read_text().splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        user = parts[0]
        hash_val = parts[1] if len(parts) >= 2 else ""

        if hash_val in ("", "!", "*", "x"):
            continue

        total += 1
        detected = False
        for pattern, algo_name in HASH_PATTERNS.items():
            if re.match(pattern, hash_val):
                algorithm_counts[algo_name] = algorithm_counts.get(algo_name, 0) + 1
                if "약함" in algo_name or "매우 약함" in algo_name:
                    weak_users.append(user)
                detected = True
                break

        if not detected:
            algorithm_counts["Unknown"] = algorithm_counts.get("Unknown", 0) + 1

    return {
        "total_accounts": total,
        "algorithm_distribution": algorithm_counts,
        "weak_hash_users": weak_users[:20],
        "weak_hash_count": len(weak_users),
        "weak_hash_pct": round(len(weak_users) / total * 100, 1) if total else 0,
    }


def calculate_password_entropy(password: str) -> float:
    """패스워드 엔트로피 계산 (비트)."""
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32

    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def analyze_password_list(wordlist: Path, top_n: int = 20) -> dict:
    """패스워드 목록 강도 분석."""
    from collections import Counter

    passwords = wordlist.read_text(errors="ignore").splitlines()
    passwords = [p.strip() for p in passwords if p.strip()]

    entropies = [calculate_password_entropy(p) for p in passwords]

    length_dist = Counter(len(p) for p in passwords)
    weak_passwords = [p for p in passwords if len(p) < 8]

    common_patterns = Counter()
    for p in passwords:
        if re.match(r"^[a-z]+\d+$", p, re.IGNORECASE):
            common_patterns["단어+숫자"] += 1
        elif re.match(r"^\d+$", p):
            common_patterns["숫자만"] += 1
        elif re.match(r"^[a-zA-Z]+$", p):
            common_patterns["문자만"] += 1
        elif len(set(p)) <= 3:
            common_patterns["반복 문자"] += 1

    return {
        "total": len(passwords),
        "avg_entropy_bits": round(sum(entropies) / len(entropies), 1) if entropies else 0,
        "min_entropy": round(min(entropies), 1) if entropies else 0,
        "weak_count": len(weak_passwords),
        "weak_pct": round(len(weak_passwords) / len(passwords) * 100, 1) if passwords else 0,
        "length_distribution": dict(sorted(length_dist.items())),
        "common_patterns": dict(common_patterns),
        "weakest_examples": sorted(passwords, key=len)[:top_n],
    }


def generate_report(report: PolicyAuditReport, output: Path | None = None) -> None:
    score = report.score()
    criticals = report.critical_failures()

    print(f"\n=== 패스워드 정책 감사 — {report.platform} ===")
    print(f"종합 점수: {score}/100\n")

    for check in report.checks:
        icon = "[+]" if check.passed else "[-]"
        sev = f"[{check.severity}]" if not check.passed else ""
        print(f"{icon} {sev} {check.name}")
        print(f"    현재: {check.current_value} | 권장: {check.recommended}")
        if not check.passed:
            print(f"    {check.detail}")

    if criticals:
        print(f"\n[!!] 치명적 실패 {len(criticals)}개 — 즉각 조치 필요:")
        for c in criticals:
            print(f"  • {c.name}: {c.detail}")

    if output:
        result = {
            "platform": report.platform,
            "score": score,
            "checks": [vars(c) for c in report.checks],
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="패스워드 정책 감사")
    sub = parser.add_subparsers(dest="cmd", required=True)

    linux_p = sub.add_parser("linux", help="Linux PAM 정책 감사")
    linux_p.add_argument("-o", "--output", type=Path)

    hash_p = sub.add_parser("hashes", help="해시 파일 분석")
    hash_p.add_argument("file", type=Path, help="/etc/shadow 또는 해시 파일")
    hash_p.add_argument("-o", "--output", type=Path)

    wordlist_p = sub.add_parser("wordlist", help="패스워드 목록 강도 분석")
    wordlist_p.add_argument("file", type=Path)
    wordlist_p.add_argument("--top", type=int, default=10)

    entropy_p = sub.add_parser("entropy", help="단일 패스워드 엔트로피 계산")
    entropy_p.add_argument("password")

    args = parser.parse_args()

    match args.cmd:
        case "linux":
            report = audit_linux_pam_policy()
            generate_report(report, getattr(args, "output", None))

        case "hashes":
            result = audit_password_hashes(args.file)
            print(f"총 계정: {result['total_accounts']}")
            print(f"약한 해시: {result['weak_hash_count']}개 ({result['weak_hash_pct']}%)")
            print(f"알고리즘 분포: {result['algorithm_distribution']}")
            if result["weak_hash_users"]:
                print(f"약한 해시 사용자: {result['weak_hash_users'][:10]}")
            if getattr(args, "output", None):
                args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))

        case "wordlist":
            result = analyze_password_list(args.file, args.top)
            print(f"총 패스워드: {result['total']}")
            print(f"평균 엔트로피: {result['avg_entropy_bits']} bits")
            print(f"약한 패스워드 (8자 미만): {result['weak_count']}개 ({result['weak_pct']}%)")
            print(f"패턴 분포: {result['common_patterns']}")

        case "entropy":
            entropy = calculate_password_entropy(args.password)
            strength = (
                "매우 약함" if entropy < 28 else
                "약함" if entropy < 36 else
                "보통" if entropy < 60 else
                "강함" if entropy < 128 else "매우 강함"
            )
            print(f"엔트로피: {entropy:.1f} bits — {strength}")
            print(f"길이: {len(args.password)}자")


if __name__ == "__main__":
    main()
```

---

## 3. 패스워드 정책 권고사항

| 항목 | 최소 | 권장 | 근거 |
|------|------|------|------|
| 최소 길이 | 8자 | 15자+ | NIST SP 800-63B |
| 복잡도 | 권장 안 함 | 패스프레이즈 | NIST 개정판 |
| 만료 주기 | 침해 시만 | 비활성화 | NIST 개정판 |
| 해시 알고리즘 | SHA-512 | bcrypt/yescrypt | 브루트포스 저항성 |
| MFA | 권장 | 필수 | 크리덴셜 스터핑 방어 |
| 계정 잠금 | 10회 | 5회 | 브루트포스 방어 |
| Have I Been Pwned | 권장 | 필수 | 유출 패스워드 차단 |

---

<a name="english"></a>

# Password Policy Audit — Weak Policy Detection, Hash Strength Analysis, and Recommendations

## 1. Password Security Audit Overview

```
Password Policy Audit
    │
    ├── Policy Analysis
    │     - Minimum length, complexity requirements
    │     - Expiration cycle, history management
    │     - Account lockout policy
    │
    ├── Hash Algorithm Audit
    │     - Weak hash detection (MD5, SHA-1, LM)
    │     - Salt usage verification
    │     - Iteration count (bcrypt cost, PBKDF2 iterations)
    │
    └── Actual Password Strength Analysis
          - Cracking success rate on dumped hashes
          - Common password patterns
          - Entropy measurement
```

---

## 2. Password Policy Audit CLI

```python
#!/usr/bin/env python3
"""Password Policy Audit — Configuration Analysis and Vulnerability Report Generation."""

import argparse
import json
import math
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PolicyCheck:
    name: str
    passed: bool
    current_value: str
    recommended: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    detail: str


@dataclass
class PolicyAuditReport:
    platform: str
    checks: list[PolicyCheck] = field(default_factory=list)

    def score(self) -> int:
        if not self.checks:
            return 0
        passed = sum(1 for c in self.checks if c.passed)
        return int(passed / len(self.checks) * 100)

    def critical_failures(self) -> list[PolicyCheck]:
        return [c for c in self.checks if not c.passed and c.severity == "CRITICAL"]


def audit_linux_pam_policy(pam_dir: Path = Path("/etc/pam.d")) -> PolicyAuditReport:
    """Linux PAM password policy audit."""
    report = PolicyAuditReport(platform="Linux PAM")

    # Parse /etc/login.defs
    login_defs = Path("/etc/login.defs")
    defs: dict[str, str] = {}
    if login_defs.exists():
        for line in login_defs.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    defs[parts[0]] = parts[1]

    # Minimum length
    min_len = int(defs.get("PASS_MIN_LEN", "0"))
    report.checks.append(PolicyCheck(
        name="Minimum Password Length",
        passed=min_len >= 12,
        current_value=str(min_len),
        recommended="12 characters or more",
        severity="CRITICAL",
        detail=f"Current: {min_len} chars — NIST SP 800-63B: minimum 8, recommended 12+",
    ))

    # Expiration period
    max_days = int(defs.get("PASS_MAX_DAYS", "99999"))
    report.checks.append(PolicyCheck(
        name="Password Expiration Period",
        passed=max_days <= 365,
        current_value=f"{max_days} days",
        recommended="90-365 days",
        severity="HIGH",
        detail=f"Current: {max_days} days — Periodic change enforcement required",
    ))

    # Minimum usage period
    min_days = int(defs.get("PASS_MIN_DAYS", "0"))
    report.checks.append(PolicyCheck(
        name="Minimum Usage Period",
        passed=min_days >= 1,
        current_value=f"{min_days} days",
        recommended="1 day or more",
        severity="MEDIUM",
        detail="Prevents immediate re-change",
    ))

    # Check pwquality.conf
    pwquality = Path("/etc/security/pwquality.conf")
    if pwquality.exists():
        content = pwquality.read_text()
        has_minlen = "minlen" in content
        has_dcredit = "dcredit" in content
        has_ucredit = "ucredit" in content
        has_retry = "retry" in content

        report.checks.append(PolicyCheck(
            name="Complexity Requirements (pwquality)",
            passed=has_minlen and (has_dcredit or has_ucredit),
            current_value="Configured" if has_minlen else "Not configured",
            recommended="Set minlen, dcredit, ucredit, retry",
            severity="HIGH",
            detail="Require digits and uppercase letters",
        ))
    else:
        report.checks.append(PolicyCheck(
            name="Complexity Requirements (pwquality)",
            passed=False,
            current_value="Not installed",
            recommended="Install and configure libpam-pwquality",
            severity="HIGH",
            detail="No password complexity enforcement module",
        ))

    # Check /etc/shadow hash algorithm
    shadow = Path("/etc/shadow")
    if shadow.exists():
        try:
            content = shadow.read_text()
            hash_types: dict[str, int] = {}
            for line in content.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1].startswith("$"):
                    algo = parts[1].split("$")[1]
                    hash_types[algo] = hash_types.get(algo, 0) + 1

            weak_algos = {k: v for k, v in hash_types.items() if k in ("1", "2a", "5")}
            report.checks.append(PolicyCheck(
                name="Password Hash Algorithm",
                passed=not weak_algos,
                current_value=str(hash_types),
                recommended="$6$ (SHA-512) or $y$ (yescrypt)",
                severity="CRITICAL",
                detail=f"Weak algorithm in use: {weak_algos}" if weak_algos else "Strong algorithm in use",
            ))
        except PermissionError:
            report.checks.append(PolicyCheck(
                name="Password Hash Algorithm",
                passed=True,
                current_value="No permission",
                recommended="Re-run with root privileges",
                severity="LOW",
                detail="Cannot access /etc/shadow",
            ))

    return report


def audit_password_hashes(hash_file: Path) -> dict:
    """Analyze algorithm distribution and weaknesses in a hash file."""
    algorithm_counts: dict[str, int] = {}
    total = 0
    weak_users: list[str] = []

    HASH_PATTERNS = {
        r"^\$1\$": "MD5-crypt (Weak)",
        r"^\$2[aby]\$": "bcrypt",
        r"^\$5\$": "SHA-256-crypt",
        r"^\$6\$": "SHA-512-crypt",
        r"^\$y\$": "yescrypt (Strong)",
        r"^[a-fA-F0-9]{32}$": "MD5 (Very Weak)",
        r"^[a-fA-F0-9]{40}$": "SHA-1 (Weak)",
        r"^[a-fA-F0-9]{64}$": "SHA-256 (No salt, Weak)",
        r"^[A-Z0-9]{13}$": "DES-crypt (Very Weak)",
    }

    for line in hash_file.read_text().splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        user = parts[0]
        hash_val = parts[1] if len(parts) >= 2 else ""

        if hash_val in ("", "!", "*", "x"):
            continue

        total += 1
        detected = False
        for pattern, algo_name in HASH_PATTERNS.items():
            if re.match(pattern, hash_val):
                algorithm_counts[algo_name] = algorithm_counts.get(algo_name, 0) + 1
                if "Weak" in algo_name:
                    weak_users.append(user)
                detected = True
                break

        if not detected:
            algorithm_counts["Unknown"] = algorithm_counts.get("Unknown", 0) + 1

    return {
        "total_accounts": total,
        "algorithm_distribution": algorithm_counts,
        "weak_hash_users": weak_users[:20],
        "weak_hash_count": len(weak_users),
        "weak_hash_pct": round(len(weak_users) / total * 100, 1) if total else 0,
    }


def calculate_password_entropy(password: str) -> float:
    """Calculate password entropy (bits)."""
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32

    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def analyze_password_list(wordlist: Path, top_n: int = 20) -> dict:
    """Analyze strength of a password list."""
    from collections import Counter

    passwords = wordlist.read_text(errors="ignore").splitlines()
    passwords = [p.strip() for p in passwords if p.strip()]

    entropies = [calculate_password_entropy(p) for p in passwords]
    length_dist = Counter(len(p) for p in passwords)
    weak_passwords = [p for p in passwords if len(p) < 8]

    common_patterns = Counter()
    for p in passwords:
        if re.match(r"^[a-z]+\d+$", p, re.IGNORECASE):
            common_patterns["Word+Digits"] += 1
        elif re.match(r"^\d+$", p):
            common_patterns["Digits only"] += 1
        elif re.match(r"^[a-zA-Z]+$", p):
            common_patterns["Letters only"] += 1
        elif len(set(p)) <= 3:
            common_patterns["Repeated chars"] += 1

    return {
        "total": len(passwords),
        "avg_entropy_bits": round(sum(entropies) / len(entropies), 1) if entropies else 0,
        "min_entropy": round(min(entropies), 1) if entropies else 0,
        "weak_count": len(weak_passwords),
        "weak_pct": round(len(weak_passwords) / len(passwords) * 100, 1) if passwords else 0,
        "length_distribution": dict(sorted(length_dist.items())),
        "common_patterns": dict(common_patterns),
        "weakest_examples": sorted(passwords, key=len)[:top_n],
    }


def generate_report(report: PolicyAuditReport, output: Path | None = None) -> None:
    score = report.score()
    criticals = report.critical_failures()

    print(f"\n=== Password Policy Audit — {report.platform} ===")
    print(f"Overall Score: {score}/100\n")

    for check in report.checks:
        icon = "[+]" if check.passed else "[-]"
        sev = f"[{check.severity}]" if not check.passed else ""
        print(f"{icon} {sev} {check.name}")
        print(f"    Current: {check.current_value} | Recommended: {check.recommended}")
        if not check.passed:
            print(f"    {check.detail}")

    if criticals:
        print(f"\n[!!] {len(criticals)} Critical Failures — Immediate action required:")
        for c in criticals:
            print(f"  • {c.name}: {c.detail}")

    if output:
        result = {
            "platform": report.platform,
            "score": score,
            "checks": [vars(c) for c in report.checks],
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Password Policy Audit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    linux_p = sub.add_parser("linux", help="Linux PAM policy audit")
    linux_p.add_argument("-o", "--output", type=Path)

    hash_p = sub.add_parser("hashes", help="Hash file analysis")
    hash_p.add_argument("file", type=Path, help="/etc/shadow or hash file")
    hash_p.add_argument("-o", "--output", type=Path)

    wordlist_p = sub.add_parser("wordlist", help="Password list strength analysis")
    wordlist_p.add_argument("file", type=Path)
    wordlist_p.add_argument("--top", type=int, default=10)

    entropy_p = sub.add_parser("entropy", help="Single password entropy calculation")
    entropy_p.add_argument("password")

    args = parser.parse_args()

    match args.cmd:
        case "linux":
            report = audit_linux_pam_policy()
            generate_report(report, getattr(args, "output", None))

        case "hashes":
            result = audit_password_hashes(args.file)
            print(f"Total accounts: {result['total_accounts']}")
            print(f"Weak hashes: {result['weak_hash_count']} ({result['weak_hash_pct']}%)")
            print(f"Algorithm distribution: {result['algorithm_distribution']}")
            if result["weak_hash_users"]:
                print(f"Weak hash users: {result['weak_hash_users'][:10]}")
            if getattr(args, "output", None):
                args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))

        case "wordlist":
            result = analyze_password_list(args.file, args.top)
            print(f"Total passwords: {result['total']}")
            print(f"Average entropy: {result['avg_entropy_bits']} bits")
            print(f"Weak passwords (< 8 chars): {result['weak_count']} ({result['weak_pct']}%)")
            print(f"Pattern distribution: {result['common_patterns']}")

        case "entropy":
            entropy = calculate_password_entropy(args.password)
            strength = (
                "Very Weak" if entropy < 28 else
                "Weak" if entropy < 36 else
                "Moderate" if entropy < 60 else
                "Strong" if entropy < 128 else "Very Strong"
            )
            print(f"Entropy: {entropy:.1f} bits — {strength}")
            print(f"Length: {len(args.password)} characters")


if __name__ == "__main__":
    main()
```

---

## 3. Password Policy Recommendations

| Item | Minimum | Recommended | Rationale |
|------|---------|-------------|-----------|
| Minimum Length | 8 chars | 15+ chars | NIST SP 800-63B |
| Complexity | Not recommended | Passphrase | NIST revised guidance |
| Expiration Cycle | On breach only | Disable | NIST revised guidance |
| Hash Algorithm | SHA-512 | bcrypt/yescrypt | Brute-force resistance |
| MFA | Recommended | Mandatory | Credential stuffing defense |
| Account Lockout | 10 attempts | 5 attempts | Brute-force defense |
| Have I Been Pwned | Recommended | Mandatory | Block leaked passwords |
