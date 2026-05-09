# 오픈소스 백도어 삽입 기법

## 개요

오픈소스 생태계를 표적으로 하는 공급망 공격은 단일 취약점이 수백만 개 시스템에 영향을 미칠 수 있어 매우 파급력이 크다. XZ Utils 사례(CVE-2024-3094)는 2년에 걸친 정교한 사회공학과 기술적 백도어를 조합한 역대 가장 정교한 공급망 공격이다.

---

## XZ Utils 백도어 사례 분석 (CVE-2024-3094)

### 공격 타임라인

```
2021년 10월:
  Jia Tan(@JiaT75) 계정 생성, xz-utils 프로젝트에 기여 시작

2022-2023년:
  꾸준한 정상적 기여로 신뢰 확보
  기존 메인테이너를 압박 (번아웃 공격)
  공동 메인테이너 권한 획득

2024년 2월:
  악성 빌드 스크립트를 tarball에 숨김 (git 소스에는 없음)
  backdoored xz-utils 5.6.0/5.6.1 릴리즈

2024년 3월 29일:
  Andres Freund (Microsoft)가 SSH 로그인 지연 이상으로 발견
  CVE-2024-3094 공개

공격 목표:
  systemd를 통해 OpenSSH에 접근
  특정 RSA 키로 인증 없이 SSH 로그인 가능
```

### 백도어 삽입 기법

```bash
# 악성 코드가 숨겨진 위치: tarball의 테스트 파일
# tests/files/bad-3-corrupt_lzma2.xz (바이너리)

# build-to-host.m4에서 악성 스크립트 추출
# configure 시 악성 코드가 liblzma에 삽입됨

# 탐지: liblzma 바이너리에 예상치 못한 IFUNC resolvers 발견
# OpenSSH sshd가 liblzma를 간접 로드 (systemd 경유)

# 영향받는 버전
# xz-utils 5.6.0 및 5.6.1
# Fedora 41/rawhide, Debian Sid/Testing, openSUSE Tumbleweed 등

# 취약 버전 확인
xz --version | grep -E "^xz \(XZ Utils\) 5\.6\."
strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 | grep "5.6"

# 백도어 탐지 스크립트 (Openwall 제공)
# https://www.openwall.com/lists/oss-security/2024/03/29/4
```

### 백도어 동작 원리

```c
// 개략적인 동작 (실제 백도어는 IFUNC resolver에 숨겨짐)
// sshd가 RSA_public_decrypt 호출 시 후킹됨

// 공격자의 ED448 공개키로 서명된 명령을 실행
// 특정 RSA N값이 포함된 인증 시도 → 실제 RSA 검증 건너뜀 → 명령 실행

// 탐지를 피하기 위한 기법:
// 1. git 소스에는 악성 코드 없음 (tarball에만 존재)
// 2. 테스트 파일로 위장한 바이너리
// 3. 멀티스테이지 난독화된 빌드 스크립트
// 4. 조건부 실행 (SystemD 환경에서만)
```

---

## 오픈소스 프로젝트 신뢰 확보 후 백도어 삽입

### 사회공학 기반 기여자 위협

```
단계 1: 정상 기여 (버그 수정, 문서화, 테스트)
단계 2: 신뢰 구축 (지속적 기여, 리뷰 참여)
단계 3: 메인테이너 압박 (번아웃, 가짜 계정으로 압력)
단계 4: 권한 확보 (커밋 권한, PyPI/npm 퍼블리싱)
단계 5: 악성 커밋 삽입 (난독화, 작은 변경으로 위장)
```

### 코드에 백도어를 숨기는 기법

```python
# 기법 1: 유니코드 공백 문자를 이용한 논리 변조
# (CVE-2021-42574 - Trojan Source)
# 코드 리뷰에서는 정상으로 보이지만 컴파일러/인터프리터는 다르게 해석

# 예시: 오른쪽에서 왼쪽으로 읽는 유니코드 (RLO)
# 코드 리뷰에서: admin_check(user) // Check if admin
# 실제:          admin_check(user) // Check if not_admin

# 탐지:
grep -rn $'‮‏‎‍⁦⁧⁨⁩‫‪' .
```

```python
# 기법 2: 조건부 악성 코드 (시간/환경 기반)
import os
import time

def legitimate_function(data):
    # 정상적인 처리
    result = process(data)
    
    # 숨겨진 백도어: 특정 조건에서만 활성화
    if (
        os.getenv("CI") is None  # CI 환경이 아닐 때
        and int(time.strftime("%d")) > 20  # 매달 21일 이후
        and os.path.exists("/var/run/sshd.pid")  # SSH 데몬 실행 중
    ):
        _beacon()  # 비콘 전송
    
    return result


# 기법 3: 빌드 스크립트에 숨기기
# setup.py, Makefile, CMakeLists.txt의 설치 훅
```

```bash
# 기법 4: 테스트 파일로 위장한 페이로드
# 바이너리 데이터를 tests/fixtures/에 숨김
# 빌드 시 자동으로 실행되는 스크립트가 추출/실행

# Makefile 예시 (악성)
check:
	@python3 -c "import base64; exec(base64.b64decode(open('tests/fixtures/data.bin').read()))"
	@echo "Tests passed"
```

---

## GitHub Actions 워크플로 오염

### 공격 경로: CI/CD 파이프라인 탈취

```yaml
# 취약한 GitHub Actions 워크플로: pull_request_target + 외부 코드 실행
name: CI
on:
  pull_request_target:  # 위험! fork PR도 메인 레포 권한으로 실행

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # PR 코드 체크아웃
      - run: npm ci
      - run: npm test  # 공격자의 코드가 CI 시크릿에 접근 가능
```

### 안전한 설정

```yaml
# 안전한 워크플로: pull_request 사용 (외부 PR은 권한 없음)
name: CI (Safe)
on:
  pull_request:  # 외부 fork PR은 시크릿 없이 실행됨

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

### 외부 Actions 공급망 공격

```yaml
# 취약: 태그 참조 (태그를 옮길 수 있음)
- uses: actions/some-action@v1  # v1 태그가 변경될 수 있음

# 취약: 브랜치 참조
- uses: some-org/action@main

# 안전: SHA 고정
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

---

## 컴파일러 백도어 (Ken Thompson의 "Trusting Trust")

1984년 Ken Thompson의 Turing Award 강연에서 제시한 개념:

```c
/*
 * 컴파일러 자체에 백도어를 심는 메타 공격
 * 
 * 단계 1: login 프로그램에 백도어를 인식하는 코드를 컴파일러에 삽입
 * 단계 2: 백도어 삽입 코드를 컴파일러 자신을 컴파일하는 코드에 삽입
 * 단계 3: 컴파일러 소스에서 악성 코드를 제거
 * 
 * 결과: 컴파일된 컴파일러 바이너리가 login 컴파일 시 백도어를 삽입
 *        소스 코드를 아무리 감사해도 발견 불가
 */

// 의사코드: login 컴파일 시 추가되는 코드
if (compiling_login) {
    // 패스워드 "letmein"으로도 로그인 가능하게
    insert_backdoor();
}
```

### 현실적 대응: Reproducible Builds

```bash
# Debian Reproducible Builds: 두 개의 독립적 빌드가 동일 바이너리 생성
# https://reproducible-builds.org/

# 특정 바이너리가 재현 가능한지 확인
sha256sum /usr/bin/gcc
# 다른 환경에서 빌드한 gcc와 해시 비교

# SOURCE_DATE_EPOCH 설정으로 타임스탬프 고정
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
make
```

---

## Python: Git Diff 보안 분석 도구

```python
#!/usr/bin/env python3
"""
Git Security Analyzer - PR/커밋의 보안 위험 요소 탐지
사용법: python3 git_security.py --repo . --pr-branch feature/new-feature
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


# 고위험 패턴: 백도어 삽입 징후
CRITICAL_PATTERNS = {
    "Eval/Exec": re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
    "Base64 실행": re.compile(r"base64[^;]*decode[^;]*exec|exec[^;]*base64", re.IGNORECASE),
    "셸 실행": re.compile(r"subprocess\.(?:call|run|Popen)|os\.system|os\.popen"),
    "소켓 연결": re.compile(r"socket\.connect|socket\.create_connection"),
    "Trojan Source": re.compile(r"[‪-‮​-‏⁦-⁩]"),
    "메모리 접근": re.compile(r"ctypes\.(cdll|windll|CDLL)|mmap\.mmap"),
}

MEDIUM_PATTERNS = {
    "HTTP 요청": re.compile(r"urllib\.request|requests\.(get|post)|http\.client"),
    "파일 실행 권한": re.compile(r"os\.chmod.*0o[7][5-7][5-7]|chmod.*\+x"),
    "환경변수 접근": re.compile(r"os\.environ|os\.getenv"),
    "DNS 조회": re.compile(r"socket\.gethostbyname|socket\.getaddrinfo"),
    "암호화": re.compile(r"import\s+(?:Crypto|cryptography|nacl|bcrypt)"),
}

SUSPICIOUS_FILES = {
    ".github/workflows/*.yml",
    "setup.py",
    "setup.cfg",
    "Makefile",
    "CMakeLists.txt",
    "*.sh",
    "configure.ac",
    "*.m4",
}


@dataclass
class SecurityFinding:
    severity: str
    file_path: str
    line_number: int
    pattern_name: str
    line_content: str


def get_diff(repo_path: Path, base: str, head: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "diff", base, head],
        capture_output=True, text=True, timeout=60, errors="replace",
    )
    return result.stdout


def analyze_diff(diff_text: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    current_file = ""
    line_num = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            current_file = match.group(1) if match else ""
            continue

        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            line_num = int(match.group(1)) if match else 0
            continue

        if not line.startswith("+") or line.startswith("+++"):
            if not line.startswith("+"):
                line_num += 1
            continue

        content = line[1:]

        # CRITICAL 패턴 검사
        for name, pattern in CRITICAL_PATTERNS.items():
            if pattern.search(content):
                findings.append(SecurityFinding(
                    severity="CRITICAL",
                    file_path=current_file,
                    line_number=line_num,
                    pattern_name=name,
                    line_content=content.strip()[:100],
                ))

        # MEDIUM 패턴 검사
        for name, pattern in MEDIUM_PATTERNS.items():
            if pattern.search(content):
                findings.append(SecurityFinding(
                    severity="MEDIUM",
                    file_path=current_file,
                    line_number=line_num,
                    pattern_name=name,
                    line_content=content.strip()[:100],
                ))

        line_num += 1

    return findings


def check_suspicious_files(diff_text: str) -> list[str]:
    """수정된 고위험 파일 목록"""
    modified_suspicious: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            if match:
                filepath = match.group(1)
                # 의심 파일 패턴 확인
                for pattern in [
                    r"\.github/workflows/",
                    r"setup\.py$",
                    r"Makefile$",
                    r"configure\.ac$",
                    r"\.m4$",
                    r"CMakeLists\.txt$",
                    r"/\.travis\.yml$",
                    r"Dockerfile$",
                ]:
                    if re.search(pattern, filepath):
                        modified_suspicious.append(filepath)

    return list(set(modified_suspicious))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Git Security Analyzer - 커밋/PR 보안 위험 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 git_security.py --repo . --base main --head feature-branch
  python3 git_security.py --repo . --commit abc1234
  python3 git_security.py --repo . --base HEAD~5 --head HEAD
        """,
    )
    parser.add_argument("--repo", type=Path, default=Path("."), help="레포 경로")
    parser.add_argument("--base", default="main", help="비교 기준 브랜치/커밋")
    parser.add_argument("--head", default="HEAD", help="분석할 브랜치/커밋")
    parser.add_argument("--commit", help="단일 커밋 분석")

    args = parser.parse_args()

    if args.commit:
        diff = get_diff(args.repo, f"{args.commit}^", args.commit)
        print(f"[*] 커밋 분석: {args.commit}")
    else:
        diff = get_diff(args.repo, args.base, args.head)
        print(f"[*] 브랜치 비교: {args.base}...{args.head}")

    findings = analyze_diff(diff)
    suspicious_files = check_suspicious_files(diff)

    if suspicious_files:
        print(f"\n⚠ 수정된 고위험 파일:")
        for f in suspicious_files:
            print(f"  - {f}")

    critical = [f for f in findings if f.severity == "CRITICAL"]
    medium = [f for f in findings if f.severity == "MEDIUM"]

    print(f"\n보안 발견사항: 심각 {len(critical)}개, 중간 {len(medium)}개")

    if critical:
        print(f"\n🔴 심각 (CRITICAL):")
        for f in critical:
            print(f"  [{f.pattern_name}] {f.file_path}:{f.line_number}")
            print(f"    {f.line_content}")

    if medium:
        print(f"\n🟡 중간 (MEDIUM):")
        for f in medium[:10]:
            print(f"  [{f.pattern_name}] {f.file_path}:{f.line_number}")

    sys.exit(1 if critical else 0)


if __name__ == "__main__":
    main()
```

---

## 방어 체크리스트

### 오픈소스 기여자 관리
- [ ] 새 기여자의 이전 기여 이력 검토
- [ ] 메인테이너 권한 부여 시 다중 리뷰
- [ ] 크리티컬 변경사항에 여러 메인테이너 승인 필수
- [ ] 봇/가짜 계정이 압박하는 패턴 인식

### 빌드/배포 보안
- [ ] Reproducible Builds 적용
- [ ] tarball과 git 소스 비교 (diff 확인)
- [ ] CI/CD 파이프라인 최소 권한
- [ ] 외부 GitHub Actions SHA 고정
- [ ] 코드 서명 (Sigstore/cosign)

### 탐지
- [ ] 바이너리 파일이 테스트 디렉토리에 추가되는 경우 경보
- [ ] 빌드 스크립트 변경 감사
- [ ] 런타임 행동 분석 (eBPF 기반 Falco 등)

| 공격 기법 | 탐지 방법 |
|-----------|-----------|
| Trojan Source | Unicode 비표준 문자 grep |
| 빌드 스크립트 백도어 | tarball vs git diff |
| CI/CD 오염 | Actions SHA 핀닝, 권한 최소화 |
| 신뢰 기반 사회공학 | 기여자 배경 조사, 다중 승인 |
| XZ 스타일 | liblzma IFUNC 분석, 재현 빌드 |
