> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# DevSecOps CTF 실습 랩

## 실습 환경 준비

### Docker 환경 구성

```bash
# 실습용 네트워크 생성
docker network create devsecops-lab --subnet=172.31.0.0/24

# Gitea (코드 저장소 시뮬레이션)
docker run -d --name gitea \
  --network devsecops-lab \
  --ip 172.31.0.10 \
  -p 3000:3000 \
  -e GITEA__security__SECRET_KEY=supersecretkey12345 \
  gitea/gitea:latest 2>/dev/null || \
docker run -d --name gitea \
  --network devsecops-lab \
  --ip 172.31.0.10 \
  -p 3000:3000 \
  ubuntu:22.04 tail -f /dev/null

# Jenkins (CI/CD 파이프라인 시뮬레이션)
docker run -d --name jenkins \
  --network devsecops-lab \
  --ip 172.31.0.20 \
  -p 8080:8080 \
  -e JENKINS_OPTS="--httpPort=8080" \
  jenkins/jenkins:lts 2>/dev/null || \
docker run -d --name jenkins \
  --network devsecops-lab \
  --ip 172.31.0.20 \
  -p 8081:8080 \
  ubuntu:22.04 tail -f /dev/null

# 취약한 컨테이너 이미지 시뮬레이션
docker run -d --name vuln-registry \
  --network devsecops-lab \
  --ip 172.31.0.30 \
  ubuntu:20.04 tail -f /dev/null

# 도구 설치
docker exec gitea bash -c "apt-get update -q && apt-get install -y -q python3 python3-pip git curl 2>/dev/null; pip3 install truffleHog detect-secrets gitpython 2>/dev/null" || true
```

### 필수 Python 패키지

```bash
pip install gitpython detect-secrets truffleHog requests pyyaml semgrep bandit
```

### 디렉터리 구조

```
devsecops_ctf_lab/
├── secret_scanner.py      # 실습 1: 시크릿 스캐닝
├── pipeline_auditor.py    # 실습 2: CI/CD 파이프라인 감사
├── image_scanner.py       # 실습 3: 컨테이너 이미지 취약점
├── sast_bypass.py         # 실습 4: SAST 우회 탐지
└── sample_repos/
    ├── leaked_creds/
    └── vulnerable_pipeline/
```

---

## 실습 1: 코드 저장소 시크릿 스캐닝

### 목표

Git 저장소 히스토리를 분석하여 실수로 커밋된 API 키, 패스워드, 인증 토큰을 찾아내고 숨겨진 플래그를 추출하라.

**플래그 형식**: `CTF{s3cr3t_l34k3d_1n_g1t_h1st0ry}`

### 시나리오

개발팀의 내부 Git 저장소에 민감한 자격 증명이 노출되었다는 제보가 들어왔다. 저장소 히스토리에는 삭제된 커밋들도 포함되어 있으며, 플래그는 과거 커밋 중 하나에 숨겨진 AWS 시크릿 키 형태로 저장되어 있다.

### 힌트

1. `git log --all --oneline`으로 전체 히스토리를 확인하라
2. `git diff <commit1> <commit2>`로 변경사항을 비교하라
3. AWS 액세스 키 형식: `AKIA[0-9A-Z]{16}`
4. TruffleHog 또는 detect-secrets를 활용하라
5. `.gitignore`에 추가했더라도 히스토리에는 남아 있다

### 풀이

**Step 1: 취약한 저장소 생성**

```bash
# 테스트용 저장소 생성
mkdir -p /tmp/ctf_repo && cd /tmp/ctf_repo
git init
git config user.email "dev@corp.local"
git config user.name "Developer"

# 정상 커밋
echo "# My Application" > README.md
git add README.md && git commit -m "Initial commit"

# 시크릿 포함 커밋 (실수 시뮬레이션)
cat > config.py << 'EOF'
# Application configuration
DATABASE_URL = "postgresql://admin:password@db.corp.local/myapp"
AWS_ACCESS_KEY_ID = "FAKEKEYEXAMPLE000000"
AWS_SECRET_ACCESS_KEY = "wJalrXUtn/CTF{s3cr3t_l34k3d_1n_g1t_h1st0ry}/EXAMPLEKEY"
STRIPE_API_KEY = "FAKE_STRIPE_KEY_FOR_CTF_LAB_ONLY"
EOF
git add config.py && git commit -m "Add configuration"

# 시크릿 삭제 (히스토리에는 남음)
cat > config.py << 'EOF'
# Application configuration - secrets removed
DATABASE_URL = os.environ.get("DATABASE_URL")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
EOF
git add config.py && git commit -m "Remove hardcoded secrets"

echo "[+] 취약한 저장소 생성 완료: /tmp/ctf_repo"
```

**Step 2: 시크릿 스캐닝 스크립트**

```python
#!/usr/bin/env python3
"""
secret_scanner.py — Git 저장소 시크릿 스캐닝 CLI
사용: python3 secret_scanner.py --repo /tmp/ctf_repo
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False


# 시크릿 패턴 정의
SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key":       r"AKIA[0-9A-Z]{16}",
    "aws_secret_key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "generic_api_key":      r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][0-9a-zA-Z\-_]{20,}['\"]",
    "stripe_live":          r"sk_live_[0-9a-zA-Z]{24,}",
    "github_token":         r"ghp_[0-9a-zA-Z]{36}",
    "private_key_header":   r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "db_password":          r"(?i)(db[_-]?pass|database[_-]?password)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "ctf_flag":             r"CTF\{[^}]+\}",
}


@dataclass
class SecretFinding:
    commit_hash: str
    commit_message: str
    file_path: str
    line_content: str
    secret_type: str
    matched_value: str


def scan_commit_diff(repo: "git.Repo", commit: "git.Commit") -> list[SecretFinding]:  # type: ignore[name-defined]
    """단일 커밋의 diff에서 시크릿 탐지"""
    findings: list[SecretFinding] = []
    if not commit.parents:
        return findings

    for parent in commit.parents:
        try:
            diff = parent.diff(commit, create_patch=True)
        except Exception:
            continue
        for change in diff:
            if change.diff is None:
                continue
            try:
                diff_text = change.diff.decode("utf-8", errors="ignore")
            except AttributeError:
                diff_text = str(change.diff)

            for line in diff_text.splitlines():
                if not line.startswith("+"):
                    continue
                for secret_type, pattern in SECRET_PATTERNS.items():
                    match = re.search(pattern, line)
                    if match:
                        findings.append(SecretFinding(
                            commit_hash=commit.hexsha[:8],
                            commit_message=commit.message.strip()[:60],
                            file_path=change.b_path or change.a_path or "unknown",
                            line_content=line[1:].strip()[:120],
                            secret_type=secret_type,
                            matched_value=match.group(0)[:80],
                        ))
    return findings


def scan_all_commits(repo_path: str) -> list[SecretFinding]:
    """저장소의 모든 커밋 스캔"""
    if not GIT_AVAILABLE:
        print("[!] gitpython 미설치: pip install gitpython", file=sys.stderr)
        return []

    try:
        repo = git.Repo(repo_path)
    except git.InvalidGitRepositoryError:
        print(f"[!] 유효하지 않은 Git 저장소: {repo_path}", file=sys.stderr)
        return []

    all_findings: list[SecretFinding] = []
    commits = list(repo.iter_commits("--all"))
    print(f"[*] 총 {len(commits)}개 커밋 분석 중...")

    for commit in commits:
        findings = scan_commit_diff(repo, commit)
        all_findings.extend(findings)

    return all_findings


def scan_filesystem(directory: str) -> list[SecretFinding]:
    """현재 파일시스템 스캔 (gitpython 없이)"""
    findings: list[SecretFinding] = []
    base = Path(directory)
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv"}

    for path in base.rglob("*"):
        if any(skip in path.parts for skip in skip_dirs):
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for i, line in enumerate(text.splitlines(), 1):
            for secret_type, pattern in SECRET_PATTERNS.items():
                match = re.search(pattern, line)
                if match:
                    findings.append(SecretFinding(
                        commit_hash="filesystem",
                        commit_message=f"Line {i}",
                        file_path=str(path.relative_to(base)),
                        line_content=line.strip()[:120],
                        secret_type=secret_type,
                        matched_value=match.group(0)[:80],
                    ))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Git 저장소 시크릿 스캐닝 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 secret_scanner.py --repo /tmp/ctf_repo\n"
               "  python3 secret_scanner.py --repo /tmp/ctf_repo --filesystem-only",
    )
    parser.add_argument("--repo", default=".", help="Git 저장소 경로 (기본값: .)")
    parser.add_argument("--filesystem-only", action="store_true",
                        help="파일시스템만 스캔 (히스토리 제외)")
    parser.add_argument("--output", help="결과 저장 파일 (없으면 stdout)")
    args = parser.parse_args()

    print(f"[*] 스캔 대상: {args.repo}")
    print("=" * 60)

    if args.filesystem_only:
        findings = scan_filesystem(args.repo)
    else:
        findings = scan_all_commits(args.repo)
        if not findings:
            print("[*] 히스토리 스캔 실패, 파일시스템 스캔으로 전환")
            findings = scan_filesystem(args.repo)

    if not findings:
        print("[-] 시크릿 미발견")
        return

    flags: list[str] = []
    for f in findings:
        print(f"\n[!] {f.secret_type.upper()}")
        print(f"    커밋: {f.commit_hash} | {f.commit_message}")
        print(f"    파일: {f.file_path}")
        print(f"    내용: {f.line_content}")
        print(f"    매칭: {f.matched_value}")
        if "CTF{" in f.matched_value:
            flags.append(f.matched_value)

    print(f"\n[*] 총 {len(findings)}개 시크릿 발견")
    if flags:
        for flag in flags:
            ctf_match = re.search(r"CTF\{[^}]+\}", flag)
            if ctf_match:
                print(f"\n[+] 플래그: {ctf_match.group(0)}")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
cd /tmp && git clone ctf_repo ctf_repo_clone 2>/dev/null || true
python3 secret_scanner.py --repo /tmp/ctf_repo
```

---

## 실습 2: CI/CD 파이프라인 보안 감사

### 목표

취약한 Jenkins 파이프라인 설정 파일을 분석하여 명령어 인젝션 취약점과 하드코딩된 자격 증명을 찾아 플래그를 추출하라.

**플래그 형식**: `CTF{c1cd_p1p3l1n3_1nj3ct10n}`

### 시나리오

내부 CI/CD 시스템의 Jenkinsfile을 검토하던 중 파이프라인 정의에서 외부 입력을 직접 쉘 명령어에 삽입하는 취약점을 발견했다. 이를 악용하여 빌드 환경에서 플래그를 읽어라.

### 힌트

1. `parameters` 블록에서 사용자 입력을 받아 `sh` 스텝에 직접 사용하는 패턴을 확인하라
2. Jenkins 공유 라이브러리의 `@NonCPS` 메서드를 검사하라
3. 빌드 환경 변수에 자격 증명이 하드코딩되어 있을 수 있다
4. `withCredentials` 블록 외부에서 사용되는 비밀값을 확인하라
5. 파이프라인 스크립트의 `eval()` 사용을 확인하라

### 풀이

**Step 1: 취약한 Jenkinsfile 생성**

```bash
mkdir -p /tmp/ctf_pipeline
cat > /tmp/ctf_pipeline/Jenkinsfile << 'JENKINSEOF'
pipeline {
    agent any
    environment {
        // 하드코딩된 자격 증명 (취약점 1)
        DB_PASSWORD = "sup3r_s3cr3t_db_p4ss"
        DEPLOY_KEY  = "CTF{c1cd_p1p3l1n3_1nj3ct10n}"
        AWS_KEY     = "FAKEKEYEXAMPLE000000"
    }
    parameters {
        string(name: 'BRANCH_NAME', defaultValue: 'main', description: 'Branch to build')
        string(name: 'BUILD_ARGS', defaultValue: '', description: 'Additional build args')
    }
    stages {
        stage('Checkout') {
            steps {
                // 사용자 입력 직접 주입 (취약점 2: 명령어 인젝션)
                sh "git checkout ${params.BRANCH_NAME}"
                sh "make build ${params.BUILD_ARGS}"  // 취약점!
            }
        }
        stage('Test') {
            steps {
                sh 'python3 -m pytest tests/'
            }
        }
        stage('Deploy') {
            steps {
                // 자격 증명을 로그에 출력 (취약점 3)
                sh "echo Deploying with key: ${env.DEPLOY_KEY}"
                sh "curl -H 'Authorization: Bearer ${env.AWS_KEY}' https://api.example.com/deploy"
            }
        }
    }
}
JENKINSEOF
echo "[+] 취약한 Jenkinsfile 생성: /tmp/ctf_pipeline/Jenkinsfile"
```

**Step 2: 파이프라인 감사 스크립트**

```python
#!/usr/bin/env python3
"""
pipeline_auditor.py — CI/CD 파이프라인 보안 감사 CLI
사용: python3 pipeline_auditor.py --file /tmp/ctf_pipeline/Jenkinsfile
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PipelineIssue:
    severity: str       # HIGH / MEDIUM / LOW
    issue_type: str
    description: str
    line_number: int
    snippet: str
    flag_found: str = ""


# 취약점 패턴
VULN_PATTERNS: list[tuple[str, str, str, str]] = [
    # (severity, issue_type, description, pattern)
    ("HIGH",   "command_injection",
     "사용자 입력을 쉘 명령어에 직접 삽입",
     r'sh\s+["\'].*\$\{params\.[^}]+\}.*["\']'),
    ("HIGH",   "hardcoded_secret",
     "환경 변수에 하드코딩된 자격 증명",
     r'(?i)(password|secret|key|token)\s*=\s*["\'][^"\']{6,}["\']'),
    ("HIGH",   "ctf_flag",
     "CTF 플래그 발견",
     r'CTF\{[^}]+\}'),
    ("MEDIUM", "credential_in_log",
     "로그에 자격 증명 출력",
     r'echo.*\$\{env\.(PASSWORD|KEY|SECRET|TOKEN)[^}]*\}'),
    ("MEDIUM", "aws_key_pattern",
     "AWS 액세스 키 패턴",
     r'AKIA[0-9A-Z]{16}'),
    ("LOW",    "missing_credentials_binding",
     "withCredentials 블록 없이 자격 증명 사용",
     r'env\.(PASSWORD|KEY|SECRET|TOKEN)'),
]


def audit_pipeline_file(file_path: str) -> list[PipelineIssue]:
    """파이프라인 파일 감사"""
    path = Path(file_path)
    if not path.exists():
        print(f"[!] 파일 없음: {file_path}", file=sys.stderr)
        return []

    content = path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()
    issues: list[PipelineIssue] = []

    for lineno, line in enumerate(lines, 1):
        for severity, issue_type, description, pattern in VULN_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                flag = ""
                if "CTF{" in match.group(0):
                    flag = match.group(0)
                elif "CTF{" in line:
                    flag_match = re.search(r"CTF\{[^}]+\}", line)
                    flag = flag_match.group(0) if flag_match else ""

                issues.append(PipelineIssue(
                    severity=severity,
                    issue_type=issue_type,
                    description=description,
                    line_number=lineno,
                    snippet=line.strip()[:120],
                    flag_found=flag,
                ))

    return issues


def audit_directory(directory: str) -> list[PipelineIssue]:
    """디렉터리의 모든 파이프라인 파일 감사"""
    pipeline_files = [
        "Jenkinsfile", ".gitlab-ci.yml", ".github/workflows/*.yml",
        "azure-pipelines.yml", ".circleci/config.yml", "bitbucket-pipelines.yml"
    ]
    all_issues: list[PipelineIssue] = []
    base = Path(directory)

    for pattern in pipeline_files:
        for path in base.rglob(pattern.split("/")[-1]):
            print(f"[*] 감사 중: {path}")
            issues = audit_pipeline_file(str(path))
            all_issues.extend(issues)

    return all_issues


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CI/CD 파이프라인 보안 감사 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 pipeline_auditor.py --file /tmp/ctf_pipeline/Jenkinsfile\n"
               "  python3 pipeline_auditor.py --dir /tmp/ctf_pipeline",
    )
    parser.add_argument("--file", help="단일 파이프라인 파일 경로")
    parser.add_argument("--dir", help="디렉터리 경로 (재귀 스캔)")
    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.error("--file 또는 --dir 중 하나를 지정하세요")

    print("[*] CI/CD 파이프라인 보안 감사 시작")
    print("=" * 60)

    issues: list[PipelineIssue] = []
    if args.file:
        issues = audit_pipeline_file(args.file)
    else:
        issues = audit_directory(args.dir)

    if not issues:
        print("[-] 취약점 미발견")
        return

    # 심각도별 분류
    high = [i for i in issues if i.severity == "HIGH"]
    medium = [i for i in issues if i.severity == "MEDIUM"]
    low = [i for i in issues if i.severity == "LOW"]

    for severity_group, label in [(high, "HIGH"), (medium, "MEDIUM"), (low, "LOW")]:
        if severity_group:
            print(f"\n=== [{label}] ===")
            for issue in severity_group:
                print(f"  L{issue.line_number}: [{issue.issue_type}] {issue.description}")
                print(f"           → {issue.snippet}")
                if issue.flag_found:
                    print(f"           [FLAG] {issue.flag_found}")

    flags = [i.flag_found for i in issues if i.flag_found]
    print(f"\n[*] 총 {len(issues)}개 이슈 (HIGH:{len(high)}, MEDIUM:{len(medium)}, LOW:{len(low)})")
    if flags:
        unique_flags = list(dict.fromkeys(flags))
        for flag in unique_flags:
            print(f"\n[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
python3 pipeline_auditor.py --file /tmp/ctf_pipeline/Jenkinsfile
```

---

## 실습 3: 컨테이너 이미지 취약점 분석

### 목표

Docker 이미지를 분석하여 레이어에 숨겨진 시크릿, 설정 오류, 알려진 취약점을 찾아 플래그를 획득하라.

**플래그 형식**: `CTF{c0nt41n3r_1m4g3_s3cr3t_3xp0s3d}`

### 시나리오

내부 레지스트리에 배포된 컨테이너 이미지에 민감한 데이터가 포함되어 있다는 제보가 있다. `docker history`, `docker inspect`, 레이어 추출 기법으로 숨겨진 자격 증명과 플래그를 찾아라.

### 힌트

1. `docker history --no-trunc <image>`로 레이어 명령어를 확인하라
2. `docker save` 후 tar 아카이브를 분석하라
3. 삭제된 파일도 이전 레이어에 남아 있다
4. Dockerfile의 `RUN` 명령어에 자격 증명이 포함될 수 있다
5. 환경 변수(`ENV`)에 시크릿이 설정될 수 있다

### 풀이

**Step 1: 취약한 이미지 빌드**

```bash
# 취약한 Dockerfile 생성
mkdir -p /tmp/vuln_image
cat > /tmp/vuln_image/Dockerfile << 'DOCKEREOF'
FROM ubuntu:20.04
# 빌드 단계에서 자격 증명 노출 (취약점)
RUN echo "DB_PASS=s3cr3t_p4ssword" > /root/.env
RUN echo "API_KEY=CTF{c0nt41n3r_1m4g3_s3cr3t_3xp0s3d}" >> /root/.env
# 이후 삭제 시도 (레이어에는 남음)
RUN rm /root/.env
ENV APP_SECRET="never_hardcode_in_env"
EXPOSE 8080
CMD ["sleep", "infinity"]
DOCKEREOF

# 이미지 빌드
cd /tmp/vuln_image && docker build -t vuln-app:ctf . 2>/dev/null || \
  echo "[!] Docker build 실패 - 분석 스크립트로 시뮬레이션 진행"
```

**Step 2: 이미지 분석 스크립트**

```python
#!/usr/bin/env python3
"""
image_scanner.py — 컨테이너 이미지 취약점 분석 CLI
사용: python3 image_scanner.py --image vuln-app:ctf
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Iterator


SECRET_PATTERNS = {
    "ctf_flag":     r"CTF\{[^}]+\}",
    "password":     r"(?i)pass(?:word)?\s*[=:]\s*\S+",
    "api_key":      r"(?i)api[_-]?key\s*[=:]\s*\S+",
    "aws_key":      r"AKIA[0-9A-Z]{16}",
    "private_key":  r"-----BEGIN .{0,30}PRIVATE KEY-----",
    "token":        r"(?i)token\s*[=:]\s*[a-zA-Z0-9\-_]{20,}",
}


def run_docker(args: list[str]) -> tuple[int, str, str]:
    """Docker 명령어 실행"""
    try:
        result = subprocess.run(
            ["docker"] + args, capture_output=True, text=True, timeout=60
        )
        return result.returncode, result.stdout, result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return -1, "", str(e)


def get_image_history(image: str) -> list[str]:
    """이미지 레이어 히스토리 추출"""
    rc, stdout, stderr = run_docker(["history", "--no-trunc", "--format",
                                      "{{.CreatedBy}}", image])
    if rc != 0:
        return []
    return [line for line in stdout.splitlines() if line.strip()]


def get_image_env(image: str) -> dict[str, str]:
    """이미지 환경 변수 추출"""
    rc, stdout, _ = run_docker(["inspect", "--format",
                                 "{{json .Config.Env}}", image])
    if rc != 0:
        return {}
    try:
        env_list: list[str] = json.loads(stdout.strip())
        return dict(item.split("=", 1) for item in env_list if "=" in item)
    except (json.JSONDecodeError, ValueError):
        return {}


def extract_layers(image: str, workdir: str) -> list[Path]:
    """이미지 레이어 추출"""
    tar_path = Path(workdir) / "image.tar"
    rc, _, err = run_docker(["save", "-o", str(tar_path), image])
    if rc != 0:
        return []

    extract_path = Path(workdir) / "layers"
    extract_path.mkdir(exist_ok=True)

    with tarfile.open(tar_path) as tf:
        tf.extractall(str(extract_path))

    return list(extract_path.rglob("layer.tar"))


def scan_layer_for_secrets(layer_tar: Path) -> list[tuple[str, str, str]]:
    """단일 레이어에서 시크릿 검색"""
    findings: list[tuple[str, str, str]] = []
    try:
        with tarfile.open(str(layer_tar)) as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8", errors="ignore")
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        for match in re.finditer(pattern, content):
                            findings.append((
                                member.name,
                                secret_type,
                                match.group(0)[:100],
                            ))
                except Exception:
                    continue
    except tarfile.TarError:
        pass
    return findings


def scan_history_for_secrets(history: list[str]) -> list[tuple[str, str]]:
    """레이어 히스토리 명령어에서 시크릿 검색"""
    findings: list[tuple[str, str]] = []
    for cmd in history:
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, cmd):
                findings.append((secret_type, match.group(0)[:100]))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="컨테이너 이미지 취약점 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 image_scanner.py --image vuln-app:ctf\n"
               "  python3 image_scanner.py --image ubuntu:20.04 --layers",
    )
    parser.add_argument("--image", required=True, help="분석할 Docker 이미지")
    parser.add_argument("--layers", action="store_true",
                        help="모든 레이어 추출 및 분석 (느림)")
    args = parser.parse_args()

    print(f"[*] 이미지 분석 중: {args.image}")
    print("=" * 60)
    found_flags: list[str] = []

    # 1. 히스토리 분석
    print("\n[1] 레이어 히스토리 분석...")
    history = get_image_history(args.image)
    if history:
        history_findings = scan_history_for_secrets(history)
        for secret_type, value in history_findings:
            print(f"    [!] {secret_type}: {value}")
            if "CTF{" in value:
                flag_match = re.search(r"CTF\{[^}]+\}", value)
                if flag_match:
                    found_flags.append(flag_match.group(0))
    else:
        print("    [!] Docker 미사용 환경 - 시뮬레이션 모드")
        # 시뮬레이션
        sim_history = [
            "/bin/sh -c echo 'DB_PASS=s3cr3t' > /root/.env",
            "/bin/sh -c echo 'API_KEY=CTF{c0nt41n3r_1m4g3_s3cr3t_3xp0s3d}' >> /root/.env",
            "/bin/sh -c rm /root/.env",
        ]
        for cmd in sim_history:
            print(f"    CMD: {cmd[:80]}")
            for secret_type, pattern in SECRET_PATTERNS.items():
                m = re.search(pattern, cmd)
                if m:
                    print(f"         [!] {secret_type}: {m.group(0)}")
                    if "CTF{" in m.group(0):
                        found_flags.append(m.group(0))

    # 2. 환경 변수 분석
    print("\n[2] 환경 변수 분석...")
    env_vars = get_image_env(args.image)
    for key, value in env_vars.items():
        for secret_type, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, f"{key}={value}"):
                print(f"    [!] ENV {key}={value[:60]}")

    # 3. 레이어 추출 분석 (옵션)
    if args.layers:
        print("\n[3] 레이어 파일시스템 분석...")
        with tempfile.TemporaryDirectory() as tmpdir:
            layers = extract_layers(args.image, tmpdir)
            if layers:
                for layer in layers:
                    findings = scan_layer_for_secrets(layer)
                    for file_path, secret_type, value in findings:
                        print(f"    [!] {file_path} | {secret_type}: {value}")
                        if "CTF{" in value:
                            found_flags.append(
                                re.search(r"CTF\{[^}]+\}", value).group(0))
            else:
                print("    [!] 레이어 추출 실패 (Docker 권한 확인)")

    # 플래그 출력
    if found_flags:
        unique = list(dict.fromkeys(found_flags))
        for flag in unique:
            print(f"\n[+] 플래그: {flag}")
    else:
        print("\n[-] 플래그 미발견")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
# 이미지 분석
python3 image_scanner.py --image vuln-app:ctf

# 레이어 상세 분석
python3 image_scanner.py --image vuln-app:ctf --layers
```

---

## 실습 4: SAST 우회 패턴 탐지

### 목표

정적 분석 도구(SAST)를 우회하도록 설계된 악성 코드 패턴을 분석하고, 난독화된 코드에서 플래그를 추출하라.

**플래그 형식**: `CTF{s4st_byp4ss_d3t3ct3d_4nd_r3v3rs3d}`

### 시나리오

보안 감사 중 코드베이스에서 SAST 도구를 우회하기 위해 문자열 분할, 동적 실행, 인코딩 등을 활용한 악성 코드가 발견되었다. 난독화를 해제하고 실제 실행 명령어와 플래그를 복원하라.

### 힌트

1. 문자열 연결(`"cmd" + "line"`) 패턴을 확인하라
2. Base64 인코딩된 문자열을 디코딩하라
3. `exec()`, `eval()`, `__import__()` 사용을 탐지하라
4. 변수 이름이 정상처럼 보이지만 실제로는 악성일 수 있다
5. 바이트 리터럴(`b'\x41\x50\x49'`)을 디코딩하라

### 풀이

**Step 1: 난독화된 악성 코드 샘플 생성**

```bash
cat > /tmp/obfuscated_malware.py << 'PYEOF'
# Legitimate-looking configuration module
import base64 as _b64
import os as _os

# "Database connection helper"
_c = lambda *a: "".join(a)
_db_host = _c("172", ".", "16", ".", "0", ".", "1")
_db_user = _c("adm", "in")

# Encoded configuration
_cfg = _b64.b64decode(
    "Q1RGe3M0c3RfYnlwNHNzX2QzdDNjdDNkXzRuZF9yM3YzcnMzZH0="
).decode()

# "Metrics collection"
_beacon_data = bytes([
    0x43, 0x54, 0x46, 0x7b, 0x73, 0x34,
    0x73, 0x74, 0x5f, 0x62, 0x79, 0x70
]).decode("utf-8", errors="ignore")

def get_config():
    """Returns application configuration"""
    return {"host": _db_host, "user": _db_user, "_internal": _cfg}
PYEOF
echo "[+] 난독화 샘플 생성: /tmp/obfuscated_malware.py"
```

**Step 2: SAST 우회 탐지 스크립트**

```python
#!/usr/bin/env python3
"""
sast_bypass.py — SAST 우회 패턴 탐지 및 난독화 해제 CLI
사용: python3 sast_bypass.py --file /tmp/obfuscated_malware.py
"""

import argparse
import ast
import base64
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ObfuscationFinding:
    technique: str
    line_number: int
    original: str
    decoded: str


SAST_BYPASS_PATTERNS: list[tuple[str, str]] = [
    ("base64_string",       r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']'),
    ("dynamic_exec",        r'\b(exec|eval|compile|__import__)\s*\('),
    ("hex_bytes",           r'bytes\(\s*\[(?:\s*0x[0-9a-fA-F]{2}\s*,?\s*){4,}\]\s*\)'),
    ("string_concat",       r'["\'][^"\']{2,}["\'](?:\s*\+\s*["\'][^"\']{2,}["\']){2,}'),
    ("lambda_obfuscation",  r'lambda\s*\*?\w+\s*:\s*["\']\.join'),
    ("os_system_call",      r'_os\.(system|popen|execvp?|execle?)\s*\('),
    ("ctf_flag",            r'CTF\{[^}]+\}'),
]


def decode_base64_strings(content: str) -> list[ObfuscationFinding]:
    """Base64 인코딩된 문자열 탐지 및 디코딩"""
    findings: list[ObfuscationFinding] = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, 1):
        for match in re.finditer(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']', line):
            candidate = match.group(1)
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                if any(c.isprintable() for c in decoded) and len(decoded) > 4:
                    findings.append(ObfuscationFinding(
                        technique="base64",
                        line_number=lineno,
                        original=candidate[:40],
                        decoded=decoded[:80],
                    ))
            except Exception:
                continue
    return findings


def decode_hex_bytes(content: str) -> list[ObfuscationFinding]:
    """16진수 바이트 배열 탐지 및 디코딩"""
    findings: list[ObfuscationFinding] = []
    lines = content.splitlines()

    pattern = re.compile(
        r'bytes\(\s*\[((?:\s*0x[0-9a-fA-F]{2}\s*,?\s*)+)\]\s*\)'
    )
    for lineno, line in enumerate(lines, 1):
        for match in pattern.finditer(line):
            hex_values = re.findall(r'0x([0-9a-fA-F]{2})', match.group(1))
            try:
                decoded = bytes(int(h, 16) for h in hex_values).decode(
                    "utf-8", errors="ignore")
                findings.append(ObfuscationFinding(
                    technique="hex_bytes",
                    line_number=lineno,
                    original=match.group(0)[:60],
                    decoded=decoded,
                ))
            except Exception:
                continue
    return findings


def scan_ast_for_dangerous_calls(content: str) -> list[ObfuscationFinding]:
    """AST 분석으로 위험한 함수 호출 탐지"""
    findings: list[ObfuscationFinding] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    dangerous = {"exec", "eval", "compile", "__import__", "subprocess", "os.system"}

    class DangerVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in dangerous:
                findings.append(ObfuscationFinding(
                    technique="dangerous_call",
                    line_number=node.lineno,
                    original=func_name,
                    decoded=f"위험한 함수 호출: {func_name}()",
                ))
            self.generic_visit(node)

    DangerVisitor().visit(tree)
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SAST 우회 패턴 탐지 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 sast_bypass.py --file /tmp/obfuscated_malware.py\n"
               "  python3 sast_bypass.py --file app.py --deep",
    )
    parser.add_argument("--file", required=True, help="분석할 Python 파일")
    parser.add_argument("--deep", action="store_true",
                        help="AST 기반 심층 분석 포함")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] 파일 없음: {args.file}", file=sys.stderr)
        sys.exit(1)

    content = path.read_text(encoding="utf-8", errors="ignore")
    print(f"[*] 분석 중: {args.file} ({len(content.splitlines())}줄)")
    print("=" * 60)

    all_findings: list[ObfuscationFinding] = []

    print("\n[1] Base64 인코딩 탐지...")
    b64_findings = decode_base64_strings(content)
    all_findings.extend(b64_findings)
    for f in b64_findings:
        print(f"    L{f.line_number}: {f.original} → {f.decoded}")

    print("\n[2] 16진수 바이트 탐지...")
    hex_findings = decode_hex_bytes(content)
    all_findings.extend(hex_findings)
    for f in hex_findings:
        print(f"    L{f.line_number}: {f.decoded}")

    print("\n[3] 패턴 기반 탐지...")
    for technique, pattern in SAST_BYPASS_PATTERNS:
        for lineno, line in enumerate(content.splitlines(), 1):
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                all_findings.append(ObfuscationFinding(
                    technique=technique,
                    line_number=lineno,
                    original=m.group(0)[:60],
                    decoded=line.strip()[:80],
                ))
                print(f"    L{lineno} [{technique}]: {m.group(0)[:60]}")

    if args.deep:
        print("\n[4] AST 심층 분석...")
        ast_findings = scan_ast_for_dangerous_calls(content)
        all_findings.extend(ast_findings)
        for f in ast_findings:
            print(f"    L{f.line_number}: {f.decoded}")

    # 플래그 추출
    flags: list[str] = []
    for f in all_findings:
        for text in [f.original, f.decoded]:
            flag_match = re.search(r"CTF\{[^}]+\}", text)
            if flag_match:
                flags.append(flag_match.group(0))

    print(f"\n[*] 총 {len(all_findings)}개 이슈 발견")
    if flags:
        unique = list(dict.fromkeys(flags))
        for flag in unique:
            print(f"\n[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
python3 sast_bypass.py --file /tmp/obfuscated_malware.py --deep
```

**예상 출력:**
```
[1] Base64 인코딩 탐지...
    L12: Q1RGe3M0c3RfYn... → CTF{s4st_byp4ss_d3t3ct3d_4nd_r3v3rs3d}

[+] 플래그: CTF{s4st_byp4ss_d3t3ct3d_4nd_r3v3rs3d}
```

---

## 환경 정리

```bash
docker stop gitea jenkins vuln-registry 2>/dev/null
docker rm gitea jenkins vuln-registry 2>/dev/null
docker network rm devsecops-lab 2>/dev/null
docker rmi vuln-app:ctf 2>/dev/null
rm -rf /tmp/ctf_repo /tmp/ctf_pipeline /tmp/vuln_image /tmp/obfuscated_malware.py
```

---

<a name="english"></a>

# DevSecOps CTF Practice Lab

## Lab Environment Setup

```bash
docker network create devsecops-lab --subnet=172.31.0.0/24

docker run -d --name gitea --network devsecops-lab --ip 172.31.0.10 \
  -p 3000:3000 ubuntu:22.04 tail -f /dev/null

docker run -d --name jenkins --network devsecops-lab --ip 172.31.0.20 \
  -p 8081:8080 ubuntu:22.04 tail -f /dev/null

pip install gitpython detect-secrets truffleHog requests pyyaml bandit
```

---

## Challenge 1: Code Repository Secret Scanning

### Objective

Analyze the Git repository history to find accidentally committed API keys, passwords, and authentication tokens, then extract the hidden flag.

**Flag format**: `CTF{s3cr3t_l34k3d_1n_g1t_h1st0ry}`

### Scenario

A report came in that sensitive credentials were exposed in an internal Git repository. The repository history includes deleted commits, and the flag is stored as an AWS secret key in one of the past commits.

### Solution

```bash
# Create vulnerable test repository
mkdir -p /tmp/ctf_repo && cd /tmp/ctf_repo
git init
git config user.email "dev@corp.local" && git config user.name "Developer"
echo "# App" > README.md && git add README.md && git commit -m "Initial"

cat > config.py << 'EOF'
AWS_ACCESS_KEY_ID = "FAKEKEYEXAMPLE000000"
AWS_SECRET_ACCESS_KEY = "wJalrXUtn/CTF{s3cr3t_l34k3d_1n_g1t_h1st0ry}/KEY"
EOF
git add config.py && git commit -m "Add config"
echo "AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')" > config.py
git add config.py && git commit -m "Remove hardcoded secrets"

# Scan
python3 secret_scanner.py --repo /tmp/ctf_repo
```

**Expected output:**
```
[!] CTF_FLAG
    Commit: abc123 | Add config
    File: config.py
    Match: CTF{s3cr3t_l34k3d_1n_g1t_h1st0ry}

[+] Flag: CTF{s3cr3t_l34k3d_1n_g1t_h1st0ry}
```

---

## Challenge 2: CI/CD Pipeline Security Audit

### Objective

Analyze a vulnerable Jenkins pipeline configuration file to find command injection vulnerabilities and hardcoded credentials, then extract the flag.

**Flag format**: `CTF{c1cd_p1p3l1n3_1nj3ct10n}`

### Solution

```bash
# Create vulnerable Jenkinsfile
mkdir -p /tmp/ctf_pipeline
cat > /tmp/ctf_pipeline/Jenkinsfile << 'EOF'
pipeline {
    environment {
        DEPLOY_KEY = "CTF{c1cd_p1p3l1n3_1nj3ct10n}"
        AWS_KEY    = "FAKEKEYEXAMPLE000000"
    }
    parameters {
        string(name: 'BUILD_ARGS', defaultValue: '')
    }
    stages {
        stage('Build') {
            steps {
                sh "make build ${params.BUILD_ARGS}"  // injection!
                sh "echo Deploying with: ${env.DEPLOY_KEY}"
            }
        }
    }
}
EOF

python3 pipeline_auditor.py --file /tmp/ctf_pipeline/Jenkinsfile
```

---

## Challenge 3: Container Image Vulnerability Analysis

### Objective

Analyze a Docker image to find secrets hidden in layers, misconfigurations, and known vulnerabilities, then retrieve the flag.

**Flag format**: `CTF{c0nt41n3r_1m4g3_s3cr3t_3xp0s3d}`

### Solution

```bash
# Build vulnerable image
mkdir -p /tmp/vuln_image
cat > /tmp/vuln_image/Dockerfile << 'EOF'
FROM ubuntu:20.04
RUN echo "API_KEY=CTF{c0nt41n3r_1m4g3_s3cr3t_3xp0s3d}" > /root/.env
RUN rm /root/.env
ENV APP_SECRET="never_hardcode_in_env"
CMD ["sleep", "infinity"]
EOF
docker build -t vuln-app:ctf /tmp/vuln_image

# Analyze
python3 image_scanner.py --image vuln-app:ctf --layers
```

**Key insight:** Even after `RUN rm /root/.env`, the file exists in the previous layer and can be recovered by extracting the image tar.

---

## Challenge 4: SAST Bypass Pattern Detection

### Objective

Analyze malicious code designed to bypass static analysis tools (SAST) and extract the flag from obfuscated code.

**Flag format**: `CTF{s4st_byp4ss_d3t3ct3d_4nd_r3v3rs3d}`

### Solution

```bash
# Create obfuscated sample
cat > /tmp/obfuscated_malware.py << 'EOF'
import base64 as _b64
_cfg = _b64.b64decode(
    "Q1RGe3M0c3RfYnlwNHNzX2QzdDNjdDNkXzRuZF9yM3YzcnMzZH0="
).decode()
EOF

# Detect and decode
python3 sast_bypass.py --file /tmp/obfuscated_malware.py --deep
```

**Expected output:**
```
[1] Base64 encoding detected...
    L3: Q1RGe3M0c3RfYn... → CTF{s4st_byp4ss_d3t3ct3d_4nd_r3v3rs3d}

[+] Flag: CTF{s4st_byp4ss_d3t3ct3d_4nd_r3v3rs3d}
```

---

## Cleanup

```bash
docker stop gitea jenkins vuln-registry 2>/dev/null
docker rm gitea jenkins vuln-registry 2>/dev/null
docker network rm devsecops-lab 2>/dev/null
docker rmi vuln-app:ctf 2>/dev/null
rm -rf /tmp/ctf_repo /tmp/ctf_pipeline /tmp/vuln_image /tmp/obfuscated_malware.py
```
