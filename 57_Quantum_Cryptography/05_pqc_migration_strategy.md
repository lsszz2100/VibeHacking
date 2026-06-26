> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 57-5. PQC 마이그레이션 전략: 암호화 자산 인벤토리부터 전환까지

## 0. 초보자를 위한 개념 이해

### PQC 마이그레이션이란?

PQC 마이그레이션은 기업이나 조직의 기존 암호 시스템(RSA, ECC 등)을 양자 컴퓨터에 안전한 새 표준(ML-KEM, ML-DSA 등)으로 전환하는 프로세스이다. 단순히 알고리즘 하나를 교체하는 것이 아니라, 시스템 전반에 퍼져 있는 모든 암호화 사용처를 찾아내고 우선순위를 정해 체계적으로 교체해야 하는 대규모 프로젝트이다.

**왜 배우는가:**
```
[HNDL 공격: 지금 당장 위험한 이유]

지금(2025):
  공격자 → 암호화된 데이터 수집 저장 → "나중에 해독하겠다"

미래(2030~?):
  충분한 큐비트의 양자 컴퓨터 완성
  → 저장해둔 2025년 암호문 해독
  → 의료기록, 금융 거래, 국가 기밀 노출

결론: 지금 전송되는 민감한 데이터는 이미 위험에 처해 있음
      → PQC 마이그레이션은 "미래의 문제"가 아닌 "지금의 문제"

[마이그레이션 4단계]
1. 인벤토리 → 2. 우선순위 지정 → 3. 하이브리드 전환 → 4. 완전 PQC
```

### 핵심 개념 정리

```
주요 용어:
- CBOM(Cryptography Bill of Materials): 소프트웨어 내 모든 암호화 컴포넌트 목록
- HNDL(Harvest Now, Decrypt Later): 현재 데이터를 수집해 양자 컴퓨터로 나중에 해독
- 암호 민첩성(Crypto Agility): 알고리즘을 코드 변경 없이 쉽게 교체할 수 있는 설계
- 하이브리드 암호: 기존 알고리즘 + PQC를 동시에 사용 (전환기 안전장치)
- TLS 1.3 PQC: ML-KEM을 X25519와 함께 사용하는 하이브리드 키 교환
- PKI 갱신: CA 인증서 체계 전반을 ML-DSA 기반으로 교체하는 작업
- 레거시 호환: 구형 시스템이 PQC를 지원할 때까지 공존하는 전환 기간
```

### 필요한 도구 및 환경
- **Python 3.10+**: subprocess, json, pathlib
- **Syft / cdxgen**: SBOM(소프트웨어 구성 요소 목록) 생성 도구
- **cbomkit**: 암호화 사용처 스캐닝 도구 (IBM 제공)
- **OpenSSL 3.4+**: PQC 알고리즘 지원 버전

### 기초 실습 예제
```python
import subprocess
import json
import re
from pathlib import Path

def scan_crypto_usage(directory: str) -> dict:
    """
    소스코드에서 암호화 라이브러리 사용처를 스캔하는 기본 도구
    실제 환경에서는 cbomkit, semgrep 등 전문 도구 사용 권장
    """
    findings = {
        "rsa_usage": [],
        "ecdh_usage": [],
        "aes_usage": [],
        "tls_config": [],
        "hardcoded_keys": [],
    }

    # 스캔할 패턴 (실제 코드에서 취약한 암호화 사용 탐지)
    patterns = {
        "rsa_usage": [
            r"RSA\.generate\(",           # Python cryptography
            r"new RSA\.",                  # Node.js
            r"openssl_pkey_new.*rsa",      # PHP
            r"KeyPairGenerator.*RSA",      # Java
        ],
        "ecdh_usage": [
            r"ECDH\(",
            r"ec\.generate_private_key",
            r"secp256r1|secp384r1|P-256",
        ],
        "tls_config": [
            r"ssl\.SSLContext|ssl\.wrap_socket",
            r"TLSv1\.|SSLv",              # 구버전 TLS
            r"PROTOCOL_TLS",
        ],
    }

    scan_dir = Path(directory)
    file_count = 0

    for filepath in scan_dir.rglob("*.py"):  # Python 파일 스캔 (확장 가능)
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            file_count += 1
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        findings[category].append({
                            "file": str(filepath),
                            "pattern": pattern,
                            "count": len(matches)
                        })
        except Exception:
            pass

    return {"scanned_files": file_count, "findings": findings}

def generate_migration_priority(scan_results: dict) -> list:
    """
    스캔 결과를 바탕으로 마이그레이션 우선순위 생성
    """
    priorities = []

    findings = scan_results.get("findings", {})

    if findings.get("rsa_usage"):
        priorities.append({
            "priority": "높음",
            "category": "RSA 키 교환/서명",
            "action": "ML-KEM-768 (키 교환) + ML-DSA-65 (서명)으로 교체",
            "files": [f["file"] for f in findings["rsa_usage"]][:3],
        })
    if findings.get("ecdh_usage"):
        priorities.append({
            "priority": "높음",
            "category": "ECDH 키 교환",
            "action": "하이브리드: X25519 + ML-KEM-768으로 전환",
            "files": [f["file"] for f in findings["ecdh_usage"]][:3],
        })
    if findings.get("tls_config"):
        priorities.append({
            "priority": "중간",
            "category": "TLS 설정",
            "action": "TLS 1.3 + PQC 키 교환 활성화",
            "files": [f["file"] for f in findings["tls_config"]][:3],
        })

    return priorities

# 현재 디렉토리 스캔 예시
import tempfile, os
print("=== PQC 마이그레이션 스캐너 ===")
results = scan_crypto_usage(".")
print(f"스캔된 파일 수: {results['scanned_files']}")
priorities = generate_migration_priority(results)
if priorities:
    print("\n[마이그레이션 우선순위]")
    for p in priorities:
        print(f"  [{p['priority']}] {p['category']}: {p['action']}")
else:
    print("RSA/ECC 사용처 미발견 (이미 PQC 준비되었거나 암호화 미사용)")
```

---

## 개요

포스트 양자 암호(PQC) 마이그레이션은 단순한 알고리즘 교체가 아니라 조직 전반의 암호화 거버넌스 재구축이다. NIST가 2024년 8월 FIPS 203/204/205를 확정한 이후, 기업과 정부기관은 체계적 전환 계획 수립이 요구된다. 특히 "지금 수집해서 나중에 복호화(Harvest Now, Decrypt Later, HNDL)" 공격에 대비하려면 즉시 암호화 인벤토리 작업을 시작해야 한다.

---

## 1. 암호화 자산 인벤토리(Cryptographic Asset Inventory) 방법론

### 1.1 인벤토리의 필요성

조직은 어디에 어떤 암호화가 사용되는지 파악하지 못하면 마이그레이션 범위를 알 수 없다. 암호화 인벤토리는 다음을 포함해야 한다:

- 사용 중인 알고리즘 (RSA, ECDSA, ECDH, AES, SHA 등)
- 키 길이 및 파라미터
- 사용 위치 (코드, 설정 파일, HSM, 클라우드 KMS 등)
- 데이터 보안 수명 (얼마나 오래 비밀이어야 하나)
- 의존 시스템 (어떤 서비스가 이 키를 사용하나)

### 1.2 CBOM(Cryptographic Bill of Materials)

소프트웨어 SBOM(Software Bill of Materials)의 암호화 버전:

| 항목 | 수집 내용 | 위험 분류 |
|------|---------|---------|
| 알고리즘 명칭 | RSA-2048, ECDSA-P256, AES-128 등 | 양자 위협 여부 |
| 키 크기 | 비트 단위 | 부족한 크기 탐지 |
| 사용 용도 | 서명, 암호화, 키 교환, MAC | 교체 우선순위 |
| 데이터 민감도 | 기밀, 내부, 공개 | HNDL 위험 평가 |
| 사용 위치 | 파일 경로, 라이브러리명, API | 영향 범위 측정 |
| 유효 기간 | 인증서 만료일 | 교체 타이밍 |
| 표준 의존성 | TLS 1.2, 레거시 API | 호환성 영향 |

### 1.3 탐지 방법론

**정적 분석:**
- 소스 코드 스캔 (AST, 정규식)
- 설정 파일 분석 (openssl.cnf, nginx.conf 등)
- 의존성 분석 (cryptography, pycryptodome 버전)

**동적 분석:**
- 네트워크 트래픽 캡처 및 TLS 협상 분석
- HSM/KMS API 로그 분석
- 런타임 암호화 함수 호출 추적

**문서 기반:**
- 아키텍처 설계 문서 검토
- 보안 정책 및 표준 문서 검토
- 서드파티 감사 보고서 검토

---

## 2. 취약한 RSA/ECC 사용처 탐지 방법

### 2.1 양자 취약 알고리즘 목록

| 알고리즘 | 취약 여부 | 대체 PQC 알고리즘 | 우선순위 |
|---------|---------|----------------|--------|
| RSA (모든 키 길이) | 완전 취약 | ML-KEM + ML-DSA | 최高 |
| ECDH (모든 곡선) | 완전 취약 | ML-KEM | 최高 |
| ECDSA (모든 곡선) | 완전 취약 | ML-DSA 또는 SLH-DSA | 최高 |
| DSA (DLP 기반) | 완전 취약 | ML-DSA | 高 |
| DH (Diffie-Hellman) | 완전 취약 | ML-KEM | 高 |
| AES-128 | 부분 취약 | AES-256 | 중간 |
| SHA-1 | 이미 취약 (고전) | SHA-256 이상 | 高 (즉시) |
| MD5 | 이미 취약 (고전) | SHA-256 이상 | 高 (즉시) |
| AES-256 | 안전 | 유지 | 낮음 |
| SHA-256/384/512 | 안전 | 유지 | 낮음 |

### 2.2 코드에서의 탐지 패턴

**Python 코드에서의 취약한 패턴:**
```python
# 취약한 패턴들
from Crypto.PublicKey import RSA          # pycryptodome
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
import ssl; ssl.PROTOCOL_TLS             # 기본 설정 (RSA 허용)
paramiko.RSAKey                           # SSH RSA 키
jose.rsa                                  # JWT RS256

# 안전한 패턴
from cryptography.hazmat.primitives.asymmetric import x25519  # 단기적
```

---

## 3. 하이브리드 암호화 전환 단계별 로드맵

### 3.1 전환 단계 표

| 단계 | 기간 | 주요 활동 | 산출물 |
|------|------|---------|-------|
| **0. 준비** | 즉시~3개월 | CBOM 구축, 리스크 평가, 팀 교육 | 암호화 인벤토리, 리스크 레지스터 |
| **1. 파일럿** | 3~6개월 | 비핵심 시스템에 PQC 테스트 적용 | 기술 검증 보고서 |
| **2. 하이브리드** | 6~18개월 | 핵심 시스템에 하이브리드 모드 도입 | 하이브리드 TLS 배포 |
| **3. PQC 우선** | 18~36개월 | PQC를 기본, 고전을 폴백으로 변경 | PQC 기본 정책 |
| **4. PQC 전용** | 36~60개월 | 고전 알고리즘 완전 제거 | 완전 PQC 인프라 |
| **5. 검증** | 지속 | 주기적 암호화 감사, 새 위협 모니터링 | 연간 감사 보고서 |

### 3.2 시스템 유형별 전환 우선순위

| 시스템 유형 | 데이터 수명 | HNDL 위험 | 전환 우선순위 | 권장 시작 |
|-----------|-----------|---------|------------|---------|
| 기밀 정보 전송 (정부, 군) | 25년 이상 | 최高 | 최高 | 즉시 |
| 금융 거래 기록 | 15~20년 | 高 | 高 | 2025년 |
| 의료 기록 (HIPAA) | 10~30년 | 高 | 高 | 2026년 |
| 장기 계약 문서 서명 | 10~15년 | 중간 | 高 | 2026년 |
| 일반 웹 TLS (HTTPS) | 1~3년 | 낮음 | 중간 | 2027년 |
| 소프트웨어 업데이트 서명 | 5~10년 | 중간 | 중간 | 2027년 |
| 단기 세션 키 | <1일 | 매우 낮음 | 낮음 | 2028~2030년 |

### 3.3 하이브리드 모드 구현 예시

```
TLS 1.3 하이브리드:
  KeyShare: [x25519, X25519MLKEM768]
  서버 서명: ECDSA-P256 + ML-DSA-65
  → 둘 중 하나만 안전해도 전체 안전
```

---

## 4. Python CLI: 코드베이스 암호화 취약점 스캐너

```python
#!/usr/bin/env python3
"""
코드베이스 암호화 취약점 스캐너
Python AST 분석 및 패턴 매칭으로 RSA/ECC 취약한 사용처를 탐지하고
파일별 위험 점수를 산출
"""

from __future__ import annotations

import ast
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# 취약한 패턴 정의
VULNERABLE_PATTERNS = {
    # 임포트 패턴
    "imports": {
        "rsa_import_cryptography": {
            "pattern": r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+.*rsa",
            "risk": 9,
            "category": "RSA",
            "description": "cryptography 라이브러리 RSA 사용",
            "recommendation": "ML-KEM (FIPS 203) 또는 하이브리드 모드로 교체",
        },
        "ec_import_cryptography": {
            "pattern": r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+.*\bec\b",
            "risk": 9,
            "category": "ECC",
            "description": "cryptography 라이브러리 ECC (ECDH/ECDSA) 사용",
            "recommendation": "ML-KEM/ML-DSA (FIPS 203/204)로 교체",
        },
        "pycrypto_rsa": {
            "pattern": r"from\s+Crypto\.PublicKey\s+import\s+RSA",
            "risk": 10,
            "category": "RSA",
            "description": "PyCrypto/PyCryptodome RSA 사용",
            "recommendation": "cryptography 라이브러리로 이전 후 PQC 교체",
        },
        "pycrypto_ecc": {
            "pattern": r"from\s+Crypto\.PublicKey\s+import\s+ECC",
            "risk": 9,
            "category": "ECC",
            "description": "PyCryptodome ECC 사용",
            "recommendation": "ML-DSA (FIPS 204)로 교체",
        },
        "paramiko_rsa": {
            "pattern": r"paramiko\.(RSAKey|DSSKey|ECDSAKey)",
            "risk": 8,
            "category": "RSA/ECDSA",
            "description": "Paramiko SSH RSA/ECDSA 키 사용",
            "recommendation": "OpenSSH PQC 지원 시 교체 (2025년 이후)",
        },
        "jose_rsa": {
            "pattern": r"(RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512)",
            "risk": 7,
            "category": "RSA/ECDSA",
            "description": "JWT RSA/ECDSA 서명 알고리즘 사용",
            "recommendation": "양자 안전 JWT 표준 채택 시 교체",
        },
        "ssl_legacy": {
            "pattern": r"ssl\.(PROTOCOL_TLSv1|PROTOCOL_TLSv1_1|PROTOCOL_TLSv1_2|PROTOCOL_SSLv2|PROTOCOL_SSLv3)",
            "risk": 8,
            "category": "TLS",
            "description": "레거시 TLS/SSL 프로토콜 지정",
            "recommendation": "TLS 1.3 + 하이브리드 PQC KEM 사용",
        },
        "hashlib_md5_sha1": {
            "pattern": r"hashlib\.(md5|sha1)\s*\(",
            "risk": 6,
            "category": "Hash",
            "description": "고전적으로 취약한 해시(MD5/SHA-1) 사용",
            "recommendation": "SHA-256 이상으로 즉시 교체",
        },
        "aes_128": {
            "pattern": r"algorithms\.AES\(.*\[.{16}\]\)|AES\.new\(.*\).{16}[,\)]",
            "risk": 4,
            "category": "AES",
            "description": "AES-128 사용 (그로버 알고리즘으로 64비트 수준)",
            "recommendation": "AES-256으로 교체 권장",
        },
        "m2crypto": {
            "pattern": r"from\s+M2Crypto\s+import|import\s+M2Crypto",
            "risk": 7,
            "category": "RSA/ECC",
            "description": "M2Crypto (레거시 OpenSSL 바인딩) 사용",
            "recommendation": "cryptography 라이브러리로 교체 후 PQC 마이그레이션",
        },
        "pyopenssl_rsa": {
            "pattern": r"OpenSSL\.crypto\.(TYPE_RSA|load_privatekey|dump_privatekey)",
            "risk": 8,
            "category": "RSA",
            "description": "PyOpenSSL RSA 키 조작",
            "recommendation": "PQC 전환 계획 수립 필요",
        },
    },
    # AST 기반 패턴 (함수 호출 감지)
    "ast_calls": {
        "rsa_generate": {
            "modules": {"rsa", "RSA"},
            "functions": {"generate", "generate_private_key", "importKey", "import_key"},
            "risk": 10,
            "category": "RSA",
            "description": "RSA 키 생성",
        },
        "ec_generate": {
            "modules": {"ec", "ECC"},
            "functions": {"generate_private_key", "generate", "construct"},
            "risk": 9,
            "category": "ECC",
            "description": "ECC 키 생성",
        },
        "dh_generate": {
            "modules": {"dh"},
            "functions": {"generate_parameters", "generate_private_key"},
            "risk": 9,
            "category": "DH",
            "description": "DH 파라미터/키 생성",
        },
    }
}


@dataclass
class Finding:
    """단일 취약점 발견 사항"""
    file_path: Path
    line_number: int
    column: int
    pattern_name: str
    category: str
    description: str
    risk_score: int           # 1~10 (10이 가장 위험)
    matched_text: str
    recommendation: str
    context_lines: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.risk_score >= 9:
            return "CRITICAL"
        elif self.risk_score >= 7:
            return "HIGH"
        elif self.risk_score >= 5:
            return "MEDIUM"
        else:
            return "LOW"


@dataclass
class FileScanResult:
    """파일 단위 스캔 결과"""
    file_path: Path
    findings: list[Finding] = field(default_factory=list)
    scan_error: Optional[str] = None
    lines_scanned: int = 0

    @property
    def risk_score(self) -> float:
        """파일 전체 위험 점수 (0~10)"""
        if not self.findings:
            return 0.0
        scores = [f.risk_score for f in self.findings]
        # 최고 점수 + 중복 패널티
        max_score = max(scores)
        additional = sum(s * 0.1 for s in sorted(scores, reverse=True)[1:])
        return min(10.0, max_score + additional)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")


def get_context_lines(
    source_lines: list[str],
    line_number: int,
    context: int = 2
) -> list[str]:
    """주변 컨텍스트 라인 추출"""
    start = max(0, line_number - context - 1)
    end = min(len(source_lines), line_number + context)
    return [
        f"  {'>' if i == line_number - 1 else ' '} {i+1:4}: {source_lines[i].rstrip()}"
        for i in range(start, end)
    ]


def scan_with_regex(
    file_path: Path,
    source: str,
    source_lines: list[str]
) -> list[Finding]:
    """정규식 패턴으로 취약점 탐지"""
    findings: list[Finding] = []

    for pattern_name, info in VULNERABLE_PATTERNS["imports"].items():
        regex = re.compile(info["pattern"], re.MULTILINE | re.IGNORECASE)
        for match in regex.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            col = match.start() - source[:match.start()].rfind("\n") - 1
            findings.append(Finding(
                file_path=file_path,
                line_number=line_num,
                column=col,
                pattern_name=pattern_name,
                category=info["category"],
                description=info["description"],
                risk_score=info["risk"],
                matched_text=match.group(0)[:100],
                recommendation=info["recommendation"],
                context_lines=get_context_lines(source_lines, line_num),
            ))

    return findings


def scan_with_ast(
    file_path: Path,
    source: str,
    source_lines: list[str]
) -> list[Finding]:
    """Python AST로 함수 호출 패턴 탐지"""
    findings: list[Finding] = []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as e:
        return findings

    # 임포트된 모듈명 추적
    imported_modules: dict[str, str] = {}  # alias -> original
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imported_modules[name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                name = alias.asname or alias.name
                imported_modules[name] = f"{module}.{alias.name}"

    # 함수 호출 탐지
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        module_name: Optional[str] = None
        func_name: Optional[str] = None

        if isinstance(func, ast.Attribute):
            func_name = func.attr
            if isinstance(func.value, ast.Name):
                module_name = func.value.id
            elif isinstance(func.value, ast.Attribute):
                module_name = func.value.attr
        elif isinstance(func, ast.Name):
            func_name = func.id

        if module_name is None or func_name is None:
            continue

        for pattern_name, info in VULNERABLE_PATTERNS["ast_calls"].items():
            if (module_name in info["modules"] and
                    func_name in info["functions"]):
                line_num = node.lineno
                col = node.col_offset
                matched = f"{module_name}.{func_name}(...)"
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    pattern_name=pattern_name,
                    category=info["category"],
                    description=info["description"],
                    risk_score=info["risk"],
                    matched_text=matched,
                    recommendation=info.get("recommendation",
                                           "PQC 알고리즘으로 교체 검토"),
                    context_lines=get_context_lines(source_lines, line_num),
                ))

    return findings


def scan_file(file_path: Path) -> FileScanResult:
    """단일 파일 스캔"""
    result = FileScanResult(file_path=file_path)

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        source_lines = source.splitlines()
        result.lines_scanned = len(source_lines)
    except OSError as e:
        result.scan_error = str(e)
        return result

    # 정규식 스캔
    regex_findings = scan_with_regex(file_path, source, source_lines)
    result.findings.extend(regex_findings)

    # Python 파일만 AST 스캔
    if file_path.suffix == ".py":
        ast_findings = scan_with_ast(file_path, source, source_lines)
        # 중복 제거: 같은 라인의 동일 카테고리 발견은 병합
        existing_lines = {(f.line_number, f.category) for f in result.findings}
        for f in ast_findings:
            if (f.line_number, f.category) not in existing_lines:
                result.findings.append(f)
                existing_lines.add((f.line_number, f.category))

    return result


def collect_python_files(
    path: Path,
    recursive: bool,
    extensions: tuple[str, ...] = (".py", ".pyx", ".pxi")
) -> list[Path]:
    """스캔 대상 파일 수집"""
    files: list[Path] = []

    if path.is_file():
        if path.suffix in extensions:
            files.append(path)
    elif path.is_dir():
        if recursive:
            for ext in extensions:
                files.extend(path.rglob(f"*{ext}"))
        else:
            for ext in extensions:
                files.extend(path.glob(f"*{ext}"))

    # 정렬하여 결정론적 순서 보장
    return sorted(set(files))


def format_json_output(
    all_results: list[FileScanResult],
    stats: dict
) -> str:
    """JSON 형식 출력 생성"""
    output = {
        "scanner": "PQC Crypto Vulnerability Scanner",
        "statistics": stats,
        "files": []
    }

    for result in all_results:
        if not result.findings and not result.scan_error:
            continue
        file_data: dict[str, Any] = {
            "path": str(result.file_path),
            "risk_score": round(result.risk_score, 2),
            "lines_scanned": result.lines_scanned,
            "findings_count": len(result.findings),
        }
        if result.scan_error:
            file_data["error"] = result.scan_error
        if result.findings:
            file_data["findings"] = [
                {
                    "line": f.line_number,
                    "column": f.column,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                    "category": f.category,
                    "description": f.description,
                    "matched_text": f.matched_text,
                    "recommendation": f.recommendation,
                }
                for f in sorted(result.findings, key=lambda x: x.line_number)
            ]
        output["files"].append(file_data)

    return json.dumps(output, indent=2, ensure_ascii=False)


def format_text_output(
    all_results: list[FileScanResult],
    stats: dict,
    verbose: bool
) -> None:
    """텍스트 형식 출력"""
    print("\n" + "=" * 72)
    print("  PQC 암호화 취약점 스캔 결과")
    print("=" * 72)

    # 발견 사항이 있는 파일만 출력
    flagged_results = [r for r in all_results if r.findings]
    flagged_results.sort(key=lambda r: r.risk_score, reverse=True)

    for result in flagged_results:
        print(f"\n  파일: {result.file_path}")
        print(f"  위험 점수: {result.risk_score:.1f}/10.0  "
              f"| CRITICAL: {result.critical_count}  HIGH: {result.high_count}  "
              f"| 발견 수: {len(result.findings)}개")
        print(f"  {'-'*68}")

        for finding in sorted(result.findings, key=lambda f: f.line_number):
            sev_color = {
                "CRITICAL": "[!!!]",
                "HIGH":     "[ !! ]",
                "MEDIUM":   "[ !  ]",
                "LOW":      "[  . ]",
            }.get(finding.severity, "[    ]")

            print(
                f"\n  {sev_color} [{finding.severity}] L{finding.line_number}:"
                f"{finding.column} | {finding.category} | 위험도:{finding.risk_score}/10"
            )
            print(f"  설명: {finding.description}")
            print(f"  탐지: {finding.matched_text[:80]}")
            print(f"  권장: {finding.recommendation}")

            if verbose and finding.context_lines:
                print("  코드:")
                for ctx_line in finding.context_lines:
                    print(ctx_line)

    # 통계 요약
    print("\n" + "=" * 72)
    print("  스캔 요약 통계")
    print("=" * 72)
    stat_rows = [
        ("스캔한 파일 수",    stats["total_files"]),
        ("오류 발생 파일",    stats["error_files"]),
        ("취약점 발견 파일",  stats["flagged_files"]),
        ("총 발견 수",        stats["total_findings"]),
        ("CRITICAL",         stats["critical_count"]),
        ("HIGH",             stats["high_count"]),
        ("MEDIUM",           stats["medium_count"]),
        ("LOW",              stats["low_count"]),
        ("총 스캔 라인 수",   f"{stats['total_lines']:,}"),
    ]
    for label, value in stat_rows:
        print(f"  {label:<20}: {value}")

    # 카테고리별 요약
    if stats.get("by_category"):
        print(f"\n  카테고리별 발견 수:")
        for cat, count in sorted(
            stats["by_category"].items(), key=lambda x: x[1], reverse=True
        ):
            bar = "█" * min(count, 30)
            print(f"  {cat:<12}: {count:>4}  {bar}")

    # 위험 파일 Top 5
    if flagged_results:
        print(f"\n  위험도 상위 5개 파일:")
        for i, r in enumerate(flagged_results[:5], 1):
            print(
                f"  {i}. [{r.risk_score:>4.1f}] {r.file_path.name} "
                f"({len(r.findings)}건)"
            )

    print("\n  스캔 완료.")


def run_scanner(args: argparse.Namespace) -> int:
    """스캐너 메인 실행"""
    scan_path = Path(args.path)
    recursive: bool = args.recursive
    output_format: str = args.output_format
    output_file: Optional[str] = args.output
    verbose: bool = args.verbose
    min_risk: int = args.min_risk

    print("=" * 72)
    print("  코드베이스 PQC 암호화 취약점 스캐너")
    print("=" * 72)
    print(f"\n  스캔 경로     : {scan_path}")
    print(f"  재귀 탐색     : {'예' if recursive else '아니오'}")
    print(f"  출력 형식     : {output_format}")
    print(f"  최소 위험도   : {min_risk}/10")

    if not scan_path.exists():
        print(f"\n오류: 경로가 존재하지 않습니다: {scan_path}", file=sys.stderr)
        return 1

    # 파일 수집
    files = collect_python_files(scan_path, recursive)
    if not files:
        print("\n경고: 스캔할 Python 파일이 없습니다.")
        return 0

    print(f"\n  {len(files)}개 파일 스캔 중...\n")

    # 스캔 실행
    all_results: list[FileScanResult] = []
    for i, fp in enumerate(files, 1):
        result = scan_file(fp)
        if result.findings:
            # 최소 위험도 필터링
            result.findings = [
                f for f in result.findings if f.risk_score >= min_risk
            ]
        all_results.append(result)

        if verbose:
            status = f"{len(result.findings)}건" if result.findings else "이상없음"
            print(f"  [{i:>4}/{len(files)}] {fp.name}: {status}")

    # 통계 계산
    all_findings = [f for r in all_results for f in r.findings]
    by_category: dict[str, int] = {}
    for f in all_findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1

    stats = {
        "total_files": len(all_results),
        "error_files": sum(1 for r in all_results if r.scan_error),
        "flagged_files": sum(1 for r in all_results if r.findings),
        "total_findings": len(all_findings),
        "critical_count": sum(1 for f in all_findings if f.severity == "CRITICAL"),
        "high_count": sum(1 for f in all_findings if f.severity == "HIGH"),
        "medium_count": sum(1 for f in all_findings if f.severity == "MEDIUM"),
        "low_count": sum(1 for f in all_findings if f.severity == "LOW"),
        "total_lines": sum(r.lines_scanned for r in all_results),
        "by_category": by_category,
    }

    # 출력 생성
    if output_format == "json":
        json_output = format_json_output(all_results, stats)
        if output_file:
            Path(output_file).write_text(json_output, encoding="utf-8")
            print(f"\n  JSON 결과 저장: {output_file}")
        else:
            print(json_output)
    else:
        format_text_output(all_results, stats, verbose)
        if output_file:
            # 텍스트 출력을 파일로 리디렉션하는 것은 사용자의 몫
            print(f"\n  텍스트 형식은 stdout 출력만 지원합니다.")

    # 종료 코드: CRITICAL 발견 시 1 반환
    if stats["critical_count"] > 0:
        return 1
    return 0


def parse_arguments() -> argparse.Namespace:
    """명령행 인수 파싱"""
    parser = argparse.ArgumentParser(
        prog="pqc_scanner",
        description="코드베이스 PQC 암호화 취약점 스캐너 - RSA/ECC 취약한 사용 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python 05_pqc_migration_strategy.py --path ./myproject
  python 05_pqc_migration_strategy.py --path ./src --recursive --output-format json
  python 05_pqc_migration_strategy.py --path ./app.py --verbose
  python 05_pqc_migration_strategy.py --path . --recursive --min-risk 7

탐지 대상:
  - cryptography 라이브러리 RSA/ECC/DH 사용
  - PyCryptodome RSA/ECC 사용
  - Paramiko RSA/ECDSA 키
  - JWT RSA/ECDSA 서명 알고리즘 (RS256, ES256 등)
  - 레거시 TLS 프로토콜
  - MD5/SHA-1 해시 사용
        """
    )
    parser.add_argument(
        "--path",
        default=".",
        help="스캔할 경로 (파일 또는 디렉토리, 기본값: 현재 디렉토리)"
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="하위 디렉토리 재귀 탐색"
    )
    parser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본값: text)"
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="결과를 파일로 저장 (JSON 형식에서만 지원)"
    )
    parser.add_argument(
        "--min-risk",
        type=int,
        default=1,
        choices=range(1, 11),
        metavar="N",
        help="보고할 최소 위험 점수 1~10 (기본값: 1)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="상세 출력 (코드 컨텍스트 포함)"
    )
    return parser.parse_args()


def main() -> None:
    """메인 진입점"""
    args = parse_arguments()

    try:
        exit_code = run_scanner(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n스캔이 중단되었습니다.")
        sys.exit(0)
    except Exception as e:
        print(f"\n예상치 못한 오류: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 5. 마이그레이션 위험 관리

### 5.1 주요 마이그레이션 리스크 표

| 위험 요소 | 영향 | 발생 가능성 | 대응 전략 |
|---------|------|-----------|---------|
| **하위 호환성 파괴** | 서비스 중단 | 높음 | 하이브리드 모드 단계적 전환 |
| **성능 저하** | 응답 시간 증가 | 중간 | 성능 벤치마크 선행, 캐싱 최적화 |
| **인증서 크기 증가** | 네트워크 지연 | 높음 | CDN 최적화, HTTP/3 활용 |
| **레거시 시스템 지원** | 일부 클라이언트 실패 | 높음 | 이중 스택 운영 기간 설정 |
| **HSM/KMS PQC 미지원** | 키 관리 불가 | 중간 | 벤더 로드맵 확인, 소프트웨어 HSM 임시 사용 |
| **규정 준수 공백** | 감사 실패 | 낮음 | NIST/ISO 표준 추적, 전환 증거 문서화 |
| **새 알고리즘 취약점** | 보안 실패 | 낮음 | 하이브리드 모드 유지, 모니터링 |

### 5.2 긴급 대응 시나리오 (CRQC 조기 출현 시)

만약 예상보다 일찍 암호학적으로 유의미한 양자 컴퓨터(CRQC)가 등장한다면:

1. **즉시 (24시간 내)**: 모든 장기 비밀 데이터의 키 교환 중단 또는 PQC 전환
2. **단기 (1주일 내)**: 인증서 갱신, TLS에 PQC KEM 활성화
3. **중기 (1개월 내)**: 전체 PKI 재발급, 코드 서명 키 교체
4. **장기 (6개월 내)**: 레거시 RSA/ECC 완전 제거

### 5.3 조직별 PQC 거버넌스 체계

| 역할 | 책임 |
|------|------|
| **CISO** | PQC 전환 예산 승인, 이사회 보고 |
| **암호화 담당자** | CBOM 관리, 알고리즘 선택 기준 수립 |
| **개발팀** | 코드베이스 스캔, 라이브러리 업데이트 |
| **인프라팀** | TLS 설정, PKI 인프라 업그레이드 |
| **컴플라이언스** | 규정 준수 추적, 감사 대응 |
| **벤더 관리** | 서드파티 PQC 지원 계획 확인 |

---

## 6. 하이브리드 TLS 구성 예시

### 6.1 Nginx + OpenSSL 3.x PQC 설정 (개념적)

```nginx
# /etc/nginx/nginx.conf (개념적 예시 - OQS-OpenSSL 사용 시)
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

# 하이브리드 KEM 그룹 (X25519 + ML-KEM-768)
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;

# PQC 인증서 (ML-DSA-65)
ssl_certificate /etc/ssl/pqc/ml-dsa-65-cert.pem;
ssl_certificate_key /etc/ssl/pqc/ml-dsa-65-key.pem;

# 고전 인증서 폴백 (하이브리드 기간)
ssl_certificate /etc/ssl/classic/ecdsa-p256-cert.pem;
ssl_certificate_key /etc/ssl/classic/ecdsa-p256-key.pem;
```

### 6.2 Python requests 라이브러리 PQC 활성화 (개념적)

```python
# 현재 requests는 PQC 미지원 - 미래 지원 시 예상 코드
import requests

# 하이브리드 TLS 어댑터 (liboqs-python 사용 시)
session = requests.Session()
# session.mount('https://', OQSAdapter(kem='X25519MLKEM768'))
response = session.get('https://example.com')
```

실제 Python에서의 PQC-TLS는 현재 `liboqs` 라이브러리를 통해 실험적으로 가능하다:
- `pip install liboqs-python`
- OpenSSL 포크(OQS-OpenSSL) 필요


<!-- detect-validate-57 -->
## PQC 마이그레이션 검증 — 크립토-어질리티가 실제로 동작하는가

마이그레이션은 *로드맵을 그렸다*가 아니라 **알고리즘을 코드 수정 없이 교체할 수 있고(크립토-어질리티), 하이브리드 모드가 실제 운영 트래픽에 적용되며, 롤백 경로가 검증됐는가**로 판정한다. 검증은 **소유 환경**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 크립토-어질리티 | 알고리즘 하드코딩 | 설정 교체 테스트 | 무중단 알고리즘 변경 |
| 하이브리드 배포 | 일부만 적용 | 운영 트래픽 표본 | 대상 트래픽 PQC |
| 롤백 | 폴백 불가 | 롤백 리허설 | 안전 복귀 확인 |
| 인벤토리 추적 | 진행률 미측정 | 자산별 상태 집계 | 마이그레이션율 가시 |

### 방어 검증 (직접 확인)

```bash
# 1) 운영 트래픽 표본에서 실제 PQC/하이브리드 협상 비율 — 소유 환경에서만
ss -tnp 2>/dev/null | wc -l; echo "sample handshakes via your TLS telemetry for negotiated group share"
# 2) 알고리즘이 설정으로 교체 가능한지(하드코딩 아닌지) 점검
grep -rEni 'kem|group|x25519|mlkem|cipher' /etc/*/tls*.conf 2>/dev/null | head
```

> 검증은 반드시 **소유 환경**에서만 한다. "로드맵이 있다"와 "어질리티·하이브리드가 실제 동작한다"는 다르다 — 설정 교체·트래픽 표본으로 직접 확인한다([[18_DevSecOps]], [[14_Cloud_Security]]).

---

<a name="english"></a>

# 57-5. PQC Migration Strategy: From Cryptographic Asset Inventory to Full Transition

## Overview

Post-Quantum Cryptography (PQC) migration is not a simple algorithm swap—it is a complete rebuild of an organization's cryptographic governance. After NIST finalized FIPS 203/204/205 in August 2024, enterprises and government agencies are required to establish systematic transition plans. In particular, to defend against "Harvest Now, Decrypt Later (HNDL)" attacks, organizations must begin cryptographic inventory work immediately.

---

## 1. Cryptographic Asset Inventory Methodology

### 1.1 Why Inventory Is Necessary

Without knowing where and what cryptography is used, organizations cannot determine the scope of migration. A cryptographic inventory must include:

- Algorithms in use (RSA, ECDSA, ECDH, AES, SHA, etc.)
- Key lengths and parameters
- Locations of use (code, config files, HSM, cloud KMS, etc.)
- Data security lifetime (how long must this remain secret?)
- Dependent systems (which services use this key?)

### 1.2 CBOM (Cryptographic Bill of Materials)

The cryptographic equivalent of a Software Bill of Materials (SBOM):

| Item | Collected Data | Risk Classification |
|------|---------------|---------------------|
| Algorithm name | RSA-2048, ECDSA-P256, AES-128, etc. | Quantum vulnerability |
| Key size | In bits | Insufficient size detection |
| Usage purpose | Signing, encryption, key exchange, MAC | Replacement priority |
| Data sensitivity | Confidential, internal, public | HNDL risk assessment |
| Location of use | File paths, library names, APIs | Impact scope measurement |
| Validity period | Certificate expiration date | Replacement timing |
| Standard dependencies | TLS 1.2, legacy APIs | Compatibility impact |

### 1.3 Detection Methodology

**Static Analysis:**
- Source code scanning (AST, regex)
- Configuration file analysis (openssl.cnf, nginx.conf, etc.)
- Dependency analysis (cryptography, pycryptodome versions)

**Dynamic Analysis:**
- Network traffic capture and TLS negotiation analysis
- HSM/KMS API log analysis
- Runtime cryptographic function call tracing

**Document-Based:**
- Architecture design document review
- Security policy and standard document review
- Third-party audit report review

---

## 2. Detecting Vulnerable RSA/ECC Usage

### 2.1 Quantum-Vulnerable Algorithm List

| Algorithm | Vulnerability | Replacement PQC Algorithm | Priority |
|-----------|---------------|--------------------------|----------|
| RSA (all key lengths) | Fully vulnerable | ML-KEM + ML-DSA | Critical |
| ECDH (all curves) | Fully vulnerable | ML-KEM | Critical |
| ECDSA (all curves) | Fully vulnerable | ML-DSA or SLH-DSA | Critical |
| DSA (DLP-based) | Fully vulnerable | ML-DSA | High |
| DH (Diffie-Hellman) | Fully vulnerable | ML-KEM | High |
| AES-128 | Partially vulnerable | AES-256 | Medium |
| SHA-1 | Already broken (classical) | SHA-256+ | High (immediate) |
| MD5 | Already broken (classical) | SHA-256+ | High (immediate) |
| AES-256 | Safe | Retain | Low |
| SHA-256/384/512 | Safe | Retain | Low |

### 2.2 Vulnerable Patterns in Code

**Vulnerable patterns in Python code:**
```python
# Vulnerable patterns
from Crypto.PublicKey import RSA          # pycryptodome
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
import ssl; ssl.PROTOCOL_TLS             # default settings (allows RSA)
paramiko.RSAKey                           # SSH RSA key
jose.rsa                                  # JWT RS256

# Safe pattern (short-term)
from cryptography.hazmat.primitives.asymmetric import x25519
```

---

## 3. Phased Hybrid Cryptography Migration Roadmap

### 3.1 Migration Phase Table

| Phase | Timeline | Key Activities | Deliverables |
|-------|----------|----------------|--------------|
| **0. Preparation** | Immediate–3 months | Build CBOM, risk assessment, team training | Cryptographic inventory, risk register |
| **1. Pilot** | 3–6 months | Apply PQC testing to non-critical systems | Technical validation report |
| **2. Hybrid** | 6–18 months | Deploy hybrid mode to critical systems | Hybrid TLS deployment |
| **3. PQC-first** | 18–36 months | PQC as default, classical as fallback | PQC default policy |
| **4. PQC-only** | 36–60 months | Full removal of classical algorithms | Complete PQC infrastructure |
| **5. Verification** | Ongoing | Periodic crypto audits, new threat monitoring | Annual audit reports |

### 3.2 Transition Priority by System Type

| System Type | Data Lifetime | HNDL Risk | Transition Priority | Recommended Start |
|-------------|--------------|-----------|--------------------|--------------------|
| Classified communications (gov, military) | 25+ years | Critical | Critical | Immediate |
| Financial transaction records | 15–20 years | High | High | 2025 |
| Medical records (HIPAA) | 10–30 years | High | High | 2026 |
| Long-term contract document signing | 10–15 years | Medium | High | 2026 |
| General web TLS (HTTPS) | 1–3 years | Low | Medium | 2027 |
| Software update signing | 5–10 years | Medium | Medium | 2027 |
| Short-term session keys | <1 day | Very Low | Low | 2028–2030 |

### 3.3 Hybrid Mode Implementation Example

```
TLS 1.3 Hybrid:
  KeyShare: [x25519, X25519MLKEM768]
  Server signature: ECDSA-P256 + ML-DSA-65
  → Secure as long as either one remains secure
```

---

## 4. Python CLI: Codebase Cryptographic Vulnerability Scanner

See the Korean section for full Python code listing.

---

## 5. Migration Risk Management

### 5.1 Key Migration Risk Table

| Risk Factor | Impact | Likelihood | Mitigation Strategy |
|-------------|--------|------------|---------------------|
| **Backward compatibility breaks** | Service disruption | High | Staged hybrid mode transition |
| **Performance degradation** | Increased response time | Medium | Run performance benchmarks first, optimize caching |
| **Increased certificate sizes** | Network latency | High | CDN optimization, HTTP/3 utilization |
| **Legacy system support** | Some client failures | High | Set dual-stack operation period |
| **HSM/KMS lacks PQC support** | Key management impossible | Medium | Check vendor roadmap, use software HSM temporarily |
| **Regulatory compliance gaps** | Audit failure | Low | Track NIST/ISO standards, document transition evidence |
| **New algorithm vulnerabilities** | Security failure | Low | Maintain hybrid mode, monitor |

### 5.2 Emergency Response Scenario (if CRQC appears early)

If a Cryptographically Relevant Quantum Computer (CRQC) emerges earlier than expected:

1. **Immediate (within 24 hours)**: Stop key exchange for all long-term secret data, or transition to PQC
2. **Short-term (within 1 week)**: Renew certificates, activate PQC KEM in TLS
3. **Medium-term (within 1 month)**: Reissue entire PKI, rotate code signing keys
4. **Long-term (within 6 months)**: Completely remove legacy RSA/ECC

### 5.3 Organizational PQC Governance Structure

| Role | Responsibility |
|------|----------------|
| **CISO** | Approve PQC transition budget, report to board |
| **Crypto Officer** | Manage CBOM, establish algorithm selection criteria |
| **Development Team** | Scan codebase, update libraries |
| **Infrastructure Team** | TLS configuration, PKI infrastructure upgrade |
| **Compliance** | Track regulatory requirements, prepare for audits |
| **Vendor Management** | Confirm third-party PQC support plans |

---

## 6. Hybrid TLS Configuration Examples

### 6.1 Nginx + OpenSSL 3.x PQC Configuration (Conceptual)

```nginx
# /etc/nginx/nginx.conf (conceptual example — using OQS-OpenSSL)
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

# Hybrid KEM group (X25519 + ML-KEM-768)
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;

# PQC certificate (ML-DSA-65)
ssl_certificate /etc/ssl/pqc/ml-dsa-65-cert.pem;
ssl_certificate_key /etc/ssl/pqc/ml-dsa-65-key.pem;

# Classical certificate fallback (during hybrid period)
ssl_certificate /etc/ssl/classic/ecdsa-p256-cert.pem;
ssl_certificate_key /etc/ssl/classic/ecdsa-p256-key.pem;
```

### 6.2 Python requests Library PQC Activation (Conceptual)

```python
# Currently requests does not support PQC — expected code when supported
import requests

# Hybrid TLS adapter (using liboqs-python)
session = requests.Session()
# session.mount('https://', OQSAdapter(kem='X25519MLKEM768'))
response = session.get('https://example.com')
```

PQC-TLS in actual Python is currently experimentally possible via the `liboqs` library:
- `pip install liboqs-python`
- Requires OpenSSL fork (OQS-OpenSSL)

<!-- detect-validate-57 -->
## PQC Migration Validation — Does Crypto-Agility Actually Work?

Migration is judged not by *having drawn a roadmap* but by **whether algorithms can be swapped without code changes (crypto-agility), hybrid mode is actually applied to production traffic, and the rollback path is verified**. Validate only on **owned environments**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Crypto-agility | Hardcoded algorithm | Swap via config | Zero-downtime algo change |
| Hybrid rollout | Partial only | Sample prod traffic | Target traffic on PQC |
| Rollback | No fallback | Rehearse rollback | Safe revert confirmed |
| Inventory tracking | Progress unmeasured | Aggregate per-asset state | Migration rate visible |

### Defense validation (verify directly)

```bash
# 1) Negotiated PQC/hybrid share across a production traffic sample — owned environment only
ss -tnp 2>/dev/null | wc -l; echo "sample handshakes via your TLS telemetry for negotiated group share"
# 2) Whether the algorithm is swappable by config (not hardcoded)
grep -rEni 'kem|group|x25519|mlkem|cipher' /etc/*/tls*.conf 2>/dev/null | head
```

> Validate only on **owned environments**. "Having a roadmap" differs from "agility and hybrid actually work" — confirm directly via config swap and traffic sampling ([[18_DevSecOps]], [[14_Cloud_Security]]).
