> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서버리스 사고 대응

## 0. 초보자를 위한 개념 이해

### 사고 대응(Incident Response, IR)이란?

**보안 사고 대응**은 해킹, 데이터 유출, 악성코드 감염 등 보안 사고가 발생했을 때 체계적으로 대처하는 절차입니다.

**사고 대응의 6단계 (NIST 기준):**
```
1. 준비 (Preparation)
   - 도구, 절차, 팀 준비
   - 모니터링 시스템 구축

2. 탐지 및 분석 (Detection & Analysis)
   - 이상 징후 발견
   - 공격 범위 파악

3. 격리 (Containment)
   - 피해 확산 방지
   - 증거 보존

4. 제거 (Eradication)
   - 공격자 제거
   - 취약점 패치

5. 복구 (Recovery)
   - 정상 운영 재개
   - 모니터링 강화

6. 사후 검토 (Post-Incident Activity)
   - 원인 분석
   - 재발 방지
```

### 왜 서버리스 IR이 다른가?

**전통적인 서버에서의 IR:**
- 서버에 SSH로 접속해서 로그 확인
- 메모리 덤프로 실행 중인 프로세스 분석
- 파일시스템에서 악성 파일 찾기
- 네트워크 연결 목록 확인

**서버리스에서의 IR:**
- 함수 실행 후 환경이 사라짐 (포렌식 기회 극히 제한)
- CloudWatch Logs가 유일한 증거
- IAM 권한 분석으로 피해 범위 파악
- 함수 격리 = 동시성 0으로 설정 (SSH 없음)

**비유:** 
- 전통 서버 = 범죄 현장이 그대로 남아 있어 수사관이 직접 조사 가능
- 서버리스 = 범죄 후 현장이 사라짐 → CCTV(CloudWatch) 기록만 남음

---

## 1. 서버리스 보안 사고 특성

### 1.1 전통적 IR vs 서버리스 IR

```
전통 서버 IR:
  ✓ 메모리 덤프 가능 → 실행 중 악성코드 분석
  ✓ 파일시스템 포렌식 → 악성 파일 찾기
  ✓ 프로세스 목록 → 실행 중인 악성 프로세스 탐지
  ✓ 네트워크 연결 → 실시간 C2 통신 확인
  ✗ 인프라 유지 비용 높음
  ✗ 서버 패치 직접 관리

서버리스 IR:
  ✗ 함수 실행 후 환경 소멸 → 메모리 포렌식 불가
  ✗ 에페머럴(일시적) 실행 환경 → 파일시스템 포렌식 불가
  ✓ 로그가 CloudWatch/Stackdriver에 자동 보존
  ✓ API Gateway 접근 로그 완전 수집 가능
  ✓ IAM 권한 분석으로 피해 범위 파악
  ✓ CloudTrail로 모든 API 호출 기록
```

**서버리스 IR의 핵심:** 로그와 CloudTrail이 전부입니다.  
따라서 사고 발생 전에 로깅을 완벽하게 구성해 두어야 합니다.

### 1.2 공격 벡터 분류

```
1. 코드 인젝션:
   - 이벤트 파라미터를 통한 명령어 인젝션
     (예: S3 파일명에 "; rm -rf /" 삽입)
   - 역직렬화 취약점
     (예: Python pickle 역직렬화로 임의 코드 실행)
   - 의존성 취약점 (npm, pip 패키지)
     (예: log4j, lodash 등 취약한 버전 사용)

2. 권한 오남용:
   - 과도한 IAM 권한 (Lambda 실행 역할에 s3:* 부여 등)
   - SSRF로 IMDSv1 자격증명 탈취
     (http://169.254.169.254/latest/meta-data/iam/security-credentials/)
   - 환경 변수에 저장된 시크릿 노출
     (DB 비밀번호, API 키 등)

3. 공급망 공격:
   - 악성 Lambda Layer
     (공식 Layer처럼 위장한 악성 코드)
   - 취약한 컨테이너 이미지
     (Lambda 컨테이너 이미지에 취약한 OS 사용)
   - 3rd party 의존성 포이즈닝
     (PyPI, npm 패키지에 악성 코드 삽입)
```

---

## 2. AWS Lambda 사고 대응

### 2.1 초동 분석 자동화

**초동 분석이란?** 사고 발생 직후 빠르게 상황을 파악하는 첫 단계입니다.  
Lambda 환경에서는 수십~수백 개의 함수를 수동으로 확인하기 어려우므로, 자동화가 필수입니다.

```python
#!/usr/bin/env python3
"""AWS Lambda 보안 사고 자동 분석.

기능:
1. 전체 Lambda 함수 스캔 (의심 설정 탐지)
2. CloudWatch 로그 분석 (오류/이상 패턴)
3. IAM 역할 권한 분석 (과도한 권한 탐지)
4. 의심 함수 자동 격리 (동시성 0 설정)
5. 데이터 유출 패턴 탐지

사용법:
  python3 lambda_ir.py --region ap-northeast-2 audit
  python3 lambda_ir.py logs my-function --hours 48
  python3 lambda_ir.py isolate compromised-function
"""

import argparse
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

import boto3


class LambdaIncidentResponder:
    """Lambda 사고 대응 자동화 클래스."""
    
    def __init__(self, region: str = "ap-northeast-2", profile: Optional[str] = None) -> None:
        session = boto3.Session(profile_name=profile)
        self.lambda_client = session.client("lambda", region_name=region)
        self.logs_client = session.client("logs", region_name=region)
        self.iam_client = session.client("iam")
        self.region = region

    def list_suspicious_functions(self) -> list[dict]:
        """전체 Lambda 함수 스캔 — 의심스러운 설정 탐지.
        
        탐지 항목:
        - VPC 미적용: 공개 인터넷에서 민감 리소스 접근 가능
        - 긴 타임아웃: 장시간 실행 → 데이터 유출, C2 통신 가능
        - 민감 환경 변수: 코드에 시크릿 하드코딩
        - 인증 없는 함수 URL: 누구나 직접 호출 가능
        """
        suspicious = []
        paginator = self.lambda_client.get_paginator("list_functions")

        for page in paginator.paginate():
            for func in page["Functions"]:
                flags = []

                # 탐지 1: VPC 미적용
                # VPC 없으면 함수가 인터넷에 직접 노출
                if not func.get("VpcConfig", {}).get("VpcId"):
                    flags.append("VPC 미적용 (인터넷 노출)")

                # 탐지 2: 긴 타임아웃 (15분 = 최대 900초)
                # 300초(5분) 이상이면 장시간 실행 가능 → 데이터 유출 시간 충분
                if func.get("Timeout", 0) > 300:
                    flags.append(f"긴 타임아웃: {func['Timeout']}초 (데이터 유출 위험)")

                # 탐지 3: 민감한 이름의 환경 변수
                # "SECRET", "KEY", "PASSWORD", "TOKEN", "CREDENTIAL"이 포함된 키
                if func.get("Environment", {}).get("Variables"):
                    env_keys = list(func["Environment"]["Variables"].keys())
                    sensitive_keywords = ["secret", "key", "password", "token", "credential", "api_key"]
                    suspicious_keys = [
                        k for k in env_keys
                        if any(s in k.lower() for s in sensitive_keywords)
                    ]
                    if suspicious_keys:
                        flags.append(f"민감 환경변수 키: {suspicious_keys}")

                # 탐지 4: 인증 없는 함수 URL
                # AuthType이 NONE = 인터넷 어디서나 직접 호출 가능
                try:
                    url_config = self.lambda_client.get_function_url_config(
                        FunctionName=func["FunctionName"]
                    )
                    if url_config.get("AuthType") == "NONE":
                        flags.append("인증 없는 함수 URL (공개 접근 가능!)")
                except Exception:
                    pass  # 함수 URL 미설정 시 예외 무시

                if flags:
                    suspicious.append({
                        "function_name": func["FunctionName"],
                        "runtime": func.get("Runtime", ""),
                        "role": func.get("Role", ""),
                        "last_modified": func.get("LastModified", ""),
                        "flags": flags,
                        "risk_count": len(flags),
                    })

        # 위험 항목이 많은 순서로 정렬
        return sorted(suspicious, key=lambda x: x["risk_count"], reverse=True)

    def get_cloudwatch_logs(
        self,
        function_name: str,
        hours_back: int = 24,
        filter_pattern: str = "ERROR",
    ) -> list[dict]:
        """CloudWatch Logs에서 특정 패턴의 로그 이벤트 조회.
        
        Args:
            function_name: Lambda 함수 이름
            hours_back: 몇 시간 전부터 조회할지
            filter_pattern: CloudWatch Logs 필터 패턴
                           (예: "ERROR", "Exception", "CRITICAL")
        """
        log_group = f"/aws/lambda/{function_name}"
        # 밀리초 단위 타임스탬프 계산
        start_time = int((datetime.now(timezone.utc) - timedelta(hours=hours_back)).timestamp() * 1000)
        end_time = int(datetime.now(timezone.utc).timestamp() * 1000)

        events = []
        try:
            response = self.logs_client.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                filterPattern=filter_pattern,
            )
            events = response.get("events", [])
        except self.logs_client.exceptions.ResourceNotFoundException:
            print(f"[-] 로그 그룹 없음: {log_group}")

        return events

    def analyze_iam_role(self, role_arn: str) -> dict:
        """Lambda 실행 역할의 과도한 권한 분석.
        
        IAM 역할에 너무 넓은 권한이 있으면:
        - 함수가 침해된 경우 공격자가 모든 권한 사용 가능
        - 다른 계정/서비스로 피벗(lateral movement) 가능
        """
        role_name = role_arn.split("/")[-1]

        findings = {
            "role_name": role_name,
            "overprivileged": [],
            "dangerous_actions": [],
        }

        try:
            # 연결된 관리형 정책 목록
            policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            # 인라인 정책 목록
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)

            # 위험한 액션 패턴 (AWS에서 광범위한 권한을 의미)
            dangerous_actions = [
                "iam:*",              # IAM 전체 = 새 관리자 계정 생성 가능
                "s3:*",               # S3 전체 = 모든 버킷 읽기/쓰기/삭제
                "ec2:*",              # EC2 전체 = 인스턴스 생성/종료
                "sts:AssumeRole",     # 다른 역할 가장 가능 = 권한 상승
                "secretsmanager:*",   # 모든 시크릿 접근
                "ssm:*",              # Parameter Store 전체 접근
                "lambda:*",           # Lambda 전체 = 다른 함수 수정 가능
            ]

            # 위험한 관리형 정책 확인
            for policy in policies["AttachedPolicies"]:
                if policy["PolicyName"] in (
                    "AdministratorAccess",  # 최고 관리자 권한
                    "AmazonS3FullAccess",   # S3 전체 접근
                    "IAMFullAccess",         # IAM 전체 = 권한 에스컬레이션 가능
                    "PowerUserAccess"        # 거의 관리자 수준
                ):
                    findings["overprivileged"].append(
                        f"과도한 관리형 정책: {policy['PolicyName']}"
                    )

            findings["dangerous_actions"] = dangerous_actions

        except Exception as e:
            findings["error"] = str(e)

        return findings

    def isolate_function(self, function_name: str) -> dict:
        """의심 Lambda 함수 격리.
        
        격리 단계:
        1. 동시성 0 설정 → 새로운 호출 즉시 차단
        2. 이벤트 소스 매핑 비활성화 → 트리거 차단
        3. 코드 스냅샷 URL 기록 → 포렌식용 보존
        
        주의: 격리 후에도 현재 실행 중인 호출은 완료됩니다.
        즉시 중단하려면 타임아웃을 1초로 줄이는 방법도 있습니다.
        """
        actions_taken = []
        timestamp = datetime.now(timezone.utc).isoformat()

        # 1단계: 예약 동시성을 0으로 → 새 호출 즉시 차단
        # (AWS가 새 실행 환경을 생성하지 않음)
        try:
            self.lambda_client.put_function_concurrency(
                FunctionName=function_name,
                ReservedConcurrentExecutions=0,
            )
            actions_taken.append("✓ 동시성 0으로 설정 (새 호출 즉시 차단)")
        except Exception as e:
            actions_taken.append(f"✗ 동시성 설정 실패: {e}")

        # 2단계: 이벤트 소스 매핑 비활성화
        # (SQS, Kinesis, DynamoDB 트리거 차단)
        try:
            mappings = self.lambda_client.list_event_source_mappings(
                FunctionName=function_name
            )
            for mapping in mappings["EventSourceMappings"]:
                self.lambda_client.update_event_source_mapping(
                    UUID=mapping["UUID"],
                    Enabled=False,
                )
            count = len(mappings["EventSourceMappings"])
            actions_taken.append(f"✓ {count}개 트리거 비활성화")
        except Exception as e:
            actions_taken.append(f"✗ 트리거 비활성화 실패: {e}")

        # 3단계: 코드 스냅샷 URL 기록
        # (포렌식을 위해 현재 코드 버전 다운로드 가능)
        try:
            config = self.lambda_client.get_function(FunctionName=function_name)
            code_url = config["Code"].get("Location", "")
            actions_taken.append(f"✓ 코드 URL 기록됨 (10분 유효): {code_url[:80]}...")
        except Exception as e:
            actions_taken.append(f"✗ 코드 스냅샷 실패: {e}")

        return {
            "function": function_name,
            "timestamp": timestamp,
            "status": "isolated",
            "actions": actions_taken,
        }

    def search_exfiltration_patterns(self, function_name: str) -> list[dict]:
        """로그에서 데이터 유출 패턴 탐지.
        
        탐지 패턴:
        - 외부 HTTP 요청 (curl, wget, requests.post)
        - 쉘 명령 실행 (subprocess.run, os.system)
        - 코드 동적 실행 (eval, exec)
        - 난독화 패턴 (base64 디코딩 후 실행)
        """
        suspicious_patterns = [
            "curl.*http",           # curl로 외부 서버 통신
            "wget.*http",           # wget으로 파일 다운로드
            "requests\\.post",      # Python requests로 POST 요청
            "subprocess\\.run",     # 서브프로세스 실행
            "os\\.system",          # OS 명령 직접 실행
            "eval\\(",              # 동적 코드 평가 (위험)
            "__import__",           # 동적 모듈 임포트 (난독화 기법)
            "base64\\.b64decode",   # base64 디코딩 (페이로드 난독화)
            "exec\\(",              # 코드 실행
        ]

        findings = []
        # 여러 패턴을 OR로 결합
        pattern_str = "|".join(suspicious_patterns)
        # 최근 72시간의 로그에서 탐지
        events = self.get_cloudwatch_logs(function_name, hours_back=72, filter_pattern=pattern_str)

        for event in events[:20]:  # 최대 20개만 반환
            findings.append({
                "timestamp": datetime.fromtimestamp(event["timestamp"] / 1000).isoformat(),
                "message": event["message"][:300],
                "severity": "HIGH",  # 이 패턴들은 모두 높은 위험도
            })

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lambda 사고 대응 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
명령어:
  audit    전체 함수 보안 감사 (의심 설정 탐지)
  logs     CloudWatch 로그 분석
  isolate  의심 함수 격리

예시:
  python3 lambda_ir.py --region ap-northeast-2 audit
  python3 lambda_ir.py logs my-function --hours 48
  python3 lambda_ir.py isolate compromised-function --profile security-role
        """
    )
    parser.add_argument("--region", default="ap-northeast-2", help="AWS 리전")
    parser.add_argument("--profile", default=None, help="AWS 프로파일 이름")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("audit", help="전체 함수 보안 감사")

    logs_p = subparsers.add_parser("logs", help="CloudWatch 로그 분석")
    logs_p.add_argument("function_name", help="Lambda 함수 이름")
    logs_p.add_argument("--hours", type=int, default=24, help="몇 시간 전부터 조회 (기본: 24)")
    logs_p.add_argument("--pattern", default="ERROR", help="CloudWatch 필터 패턴 (기본: ERROR)")

    isolate_p = subparsers.add_parser("isolate", help="함수 격리")
    isolate_p.add_argument("function_name", help="격리할 Lambda 함수 이름")

    exfil_p = subparsers.add_parser("exfil", help="데이터 유출 패턴 탐지")
    exfil_p.add_argument("function_name", help="분석할 Lambda 함수 이름")

    args = parser.parse_args()
    responder = LambdaIncidentResponder(args.region, args.profile)

    if args.command == "audit":
        print("[*] 전체 Lambda 함수 보안 감사 시작...")
        suspicious = responder.list_suspicious_functions()
        print(f"\n[+] 의심 함수: {len(suspicious)}개\n")
        for f in suspicious:
            print(f"  함수: {f['function_name']} (런타임: {f['runtime']})")
            print(f"  역할: {f['role']}")
            for flag in f['flags']:
                print(f"    ⚠️  {flag}")
            print()

    elif args.command == "logs":
        print(f"[*] CloudWatch 로그 분석: {args.function_name} (최근 {args.hours}시간)")
        events = responder.get_cloudwatch_logs(
            args.function_name, args.hours, args.pattern
        )
        print(f"[+] {len(events)}개 이벤트 발견")
        for e in events[:30]:  # 최대 30개 출력
            ts = datetime.fromtimestamp(e["timestamp"] / 1000).strftime("%Y-%m-%d %H:%M:%S")
            print(f"  [{ts}] {e.get('message', '').strip()[:150]}")

    elif args.command == "isolate":
        print(f"[!] 함수 격리 시작: {args.function_name}")
        print("    주의: 이 작업은 되돌리기 어렵습니다!")
        confirm = input("계속하시겠습니까? (yes/no): ")
        if confirm.lower() != "yes":
            print("격리 취소됨")
            return
        result = responder.isolate_function(args.function_name)
        print(f"\n[+] 격리 완료: {args.function_name}")
        print(f"    시간: {result['timestamp']}")
        for action in result["actions"]:
            print(f"    {action}")

    elif args.command == "exfil":
        print(f"[*] 데이터 유출 패턴 탐지: {args.function_name}")
        findings = responder.search_exfiltration_patterns(args.function_name)
        if findings:
            print(f"[!] {len(findings)}개 의심 이벤트 발견!")
            for f in findings:
                print(f"\n  [{f['severity']}] {f['timestamp']}")
                print(f"  로그: {f['message']}")
        else:
            print("[+] 의심스러운 데이터 유출 패턴 없음")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 3. SSRF를 통한 IMDSv1 자격증명 탈취 탐지

### SSRF와 IMDSv1이란?

**SSRF (Server-Side Request Forgery):**  
서버가 공격자가 지정한 URL로 요청을 보내도록 유도하는 공격입니다.

**IMDS (Instance Metadata Service):**  
EC2/Lambda가 자신의 IAM 자격증명을 가져오는 내부 서비스입니다.  
URL: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

**공격 시나리오:**
```
1. 공격자가 URL 파라미터에 IMDS 주소 삽입:
   POST /api/process
   {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"}

2. Lambda 함수가 해당 URL로 요청을 보냄

3. IMDS가 IAM 자격증명을 반환:
   {
     "AccessKeyId": "ASIA...",
     "SecretAccessKey": "...",
     "Token": "..."
   }

4. 공격자가 자격증명을 획득해 AWS 권한 탈취
```

**방어법 (IMDSv2):**  
IMDSv2는 먼저 PUT 요청으로 토큰을 받은 다음 그 토큰으로 메타데이터를 요청해야 합니다. SSRF로는 PUT 요청을 하기 어려우므로 공격이 차단됩니다.

```python
#!/usr/bin/env python3
"""서버리스 SSRF/IMDSv1 공격 탐지.

Lambda 함수 핸들러에 인라인으로 삽입해서 사용합니다.
"""

import re
from dataclasses import dataclass
from typing import Optional


# AWS IMDSv1 관련 패턴
IMDS_PATTERNS = [
    r"169\.254\.169\.254",                           # AWS IMDS IP
    r"metadata\.google\.internal",                    # GCP 메타데이터
    r"169\.254\.169\.254.*latest/meta-data",         # AWS 메타데이터 경로
    r"169\.254\.169\.254.*iam/security-credentials", # IAM 자격증명 경로 (가장 위험!)
    r"169\.254\.169\.254.*latest/user-data",         # 사용자 데이터 (민감 정보 가능)
]

# SSRF 트리거 파라미터 패턴
# 이 파라미터들은 URL을 받아서 서버가 요청을 보내도록 유도
SSRF_TRIGGER_PATTERNS = [
    r"url=https?://",       # url= 파라미터
    r"redirect=https?://",  # redirect= 파라미터
    r"next=https?://",      # next= 파라미터
    r"callback=https?://",  # callback= 파라미터
    r"fetch=https?://",     # fetch= 파라미터
    r"proxy=https?://",     # proxy= 파라미터
    r"load=https?://",      # load= 파라미터
    r"uri=https?://",       # uri= 파라미터
]


@dataclass
class SSRFDetectionResult:
    """SSRF 탐지 결과."""
    detected: bool
    findings: list[str]
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL


def analyze_lambda_event(event: dict) -> SSRFDetectionResult:
    """Lambda 이벤트 파라미터에서 SSRF 시도 탐지.
    
    이벤트 전체를 문자열로 변환해서 패턴 매칭.
    (실제 운영에서는 더 정밀한 파싱 권장)
    """
    findings = []
    event_str = str(event)  # 이벤트 전체를 문자열로 변환
    
    # IMDS 접근 시도 탐지 (가장 위험)
    for pattern in IMDS_PATTERNS:
        if re.search(pattern, event_str, re.IGNORECASE):
            findings.append(f"[CRITICAL] IMDS 접근 시도: {pattern}")
    
    # SSRF 트리거 파라미터 탐지
    for pattern in SSRF_TRIGGER_PATTERNS:
        matches = re.findall(pattern, event_str, re.IGNORECASE)
        if matches:
            findings.append(f"[MEDIUM] SSRF 트리거 파라미터: {matches[0]}")
    
    if not findings:
        return SSRFDetectionResult(detected=False, findings=[], severity="NONE")
    
    # 심각도 결정
    severity = "CRITICAL" if any("[CRITICAL]" in f for f in findings) else "MEDIUM"
    return SSRFDetectionResult(detected=True, findings=findings, severity=severity)


def secure_lambda_handler(event: dict, context) -> dict:
    """SSRF 탐지가 포함된 안전한 Lambda 핸들러 예시.
    
    모든 입력에 대해 SSRF 패턴을 확인하고
    의심스러운 요청은 즉시 거부합니다.
    """
    # 모든 요청에서 SSRF 패턴 확인
    ssrf_result = analyze_lambda_event(event)
    
    if ssrf_result.detected:
        # CloudWatch에 보안 알림 로깅
        print(f"[SECURITY ALERT] SSRF 시도 탐지 — 심각도: {ssrf_result.severity}")
        for finding in ssrf_result.findings:
            print(f"  {finding}")
        
        # 공격 시도 즉시 차단
        return {
            "statusCode": 400,
            "body": '{"error": "Invalid request"}',
            "headers": {"Content-Type": "application/json"}
        }
    
    # 정상 처리
    return {
        "statusCode": 200,
        "body": '{"status": "ok"}',
        "headers": {"Content-Type": "application/json"}
    }
```

**IMDSv2 강제 적용 방법:**
```bash
# Lambda에서 IMDSv2만 사용하도록 강제
aws lambda update-function-configuration \
  --function-name my-function \
  --snap-start-response ApplyOn=None \
  --no-fail-on-warnings

# EC2 인스턴스에서 IMDSv2 강제
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-endpoint enabled
```

---

## 4. 서버리스 보안 모니터링

### 4.1 CloudTrail 이상 탐지

**CloudTrail이란?** AWS 계정에서 발생하는 모든 API 호출을 기록하는 서비스입니다.  
"누가, 언제, 어디서, 무엇을 했는가"를 추적할 수 있습니다.

```python
#!/usr/bin/env python3
"""CloudTrail에서 Lambda 관련 이상 행위 탐지.

외부 IP에서의 Lambda 설정 변경은 공격 또는 내부자 위협의 신호입니다.
정기적으로 실행하거나 EventBridge로 실시간 탐지를 설정하세요.
"""

import argparse
import json
from datetime import datetime, timedelta, timezone

import boto3


# 모니터링할 Lambda API 액션
# 이 액션들이 외부 IP에서 실행되면 즉시 조사 필요
SUSPICIOUS_LAMBDA_ACTIONS = {
    "UpdateFunctionCode":        "HIGH",   # 코드 변조 (백도어 삽입 가능)
    "AddPermission":             "HIGH",   # 무단 호출 권한 추가
    "CreateEventSourceMapping":  "MEDIUM", # 새 트리거 추가 (지속성 확보)
    "PutFunctionConcurrency":    "MEDIUM", # 동시성 변경 (DoS 준비)
    "DeleteFunction":            "MEDIUM", # 함수 삭제 (증거 인멸)
    "TagResource":               "LOW",    # 태그 변경 (분류 조작)
    "PublishLayerVersion":       "HIGH",   # 새 Layer 게시 (악성 레이어)
    "UpdateFunctionConfiguration": "HIGH", # 설정 변경 (환경 변수 수정)
}

# 내부 IP 대역 (이 IP에서의 변경은 덜 의심스러움)
INTERNAL_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", 
                         "172.19.", "172.20.", "192.168.", "127.")


def is_internal_ip(ip: str) -> bool:
    """IP 주소가 내부(RFC 1918) 대역인지 확인."""
    return any(ip.startswith(prefix) for prefix in INTERNAL_IP_PREFIXES)


def detect_lambda_anomalies(region: str, hours_back: int = 24) -> list[dict]:
    """CloudTrail에서 Lambda 관련 이상 행위 탐지."""
    ct = boto3.client("cloudtrail", region_name=region)
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

    findings = []
    
    for action, risk in SUSPICIOUS_LAMBDA_ACTIONS.items():
        try:
            resp = ct.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": action}
                ],
                StartTime=start_time,
            )
            
            for event in resp["Events"]:
                record = json.loads(event.get("CloudTrailEvent", "{}"))
                source_ip = record.get("sourceIPAddress", "")
                user = record.get("userIdentity", {})
                user_name = user.get("userName", user.get("principalId", "unknown"))
                user_type = user.get("type", "")
                
                # 외부 IP에서의 변경만 보고
                if not is_internal_ip(source_ip) and source_ip not in ("AWS Internal", ""):
                    resource_name = (event.get("Resources") or [{}])[0].get("ResourceName", "")
                    
                    findings.append({
                        "action": action,
                        "time": event["EventTime"].isoformat(),
                        "user": user_name,
                        "user_type": user_type,
                        "source_ip": source_ip,
                        "resource": resource_name,
                        "risk": risk,
                    })
                    
        except Exception:
            continue

    # 위험도 순 정렬
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(findings, key=lambda x: risk_order.get(x["risk"], 3))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lambda CloudTrail 이상 탐지",
        epilog="예시: python3 cloudtrail_monitor.py --region ap-northeast-2 --hours 48"
    )
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--hours", type=int, default=24, help="몇 시간 전부터 분석 (기본: 24)")
    parser.add_argument("--min-risk", choices=["HIGH", "MEDIUM", "LOW"], default="MEDIUM")
    args = parser.parse_args()

    print(f"[*] CloudTrail 분석 중... (최근 {args.hours}시간, {args.region} 리전)")
    findings = detect_lambda_anomalies(args.region, args.hours)
    
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    min_level = risk_order[args.min_risk]
    filtered = [f for f in findings if risk_order.get(f["risk"], 3) <= min_level]
    
    print(f"[+] 의심 활동: {len(filtered)}건\n")
    
    for f in filtered:
        icon = "🔴" if f["risk"] == "HIGH" else "🟡" if f["risk"] == "MEDIUM" else "🟢"
        print(f"  {icon} [{f['risk']}] {f['action']}")
        print(f"       사용자: {f['user']} ({f['user_type']})")
        print(f"       IP: {f['source_ip']}")
        print(f"       리소스: {f['resource']}")
        print(f"       시간: {f['time']}")
        print()


if __name__ == "__main__":
    main()
```

---

## 5. 서버리스 IR 플레이북

### P1: 데이터 유출 의심 대응 절차

```
[1단계] 즉각 탐지 및 평가
  □ CloudWatch Logs에서 외부 HTTP 요청 패턴 검색
    검색어: "curl http | wget http | requests.post | urllib"
  □ VPC Flow Logs에서 비정상 아웃바운드 확인
    (평소에 없던 외부 IP로의 대량 트래픽)
  □ GuardDuty 알림 확인

[2단계] 격리
  □ 의심 함수 동시성 0 설정 (새 호출 즉시 차단)
    aws lambda put-function-concurrency \
      --function-name FUNCTION_NAME \
      --reserved-concurrent-executions 0
  □ 관련 API Gateway 스테이지 비활성화

[3단계] 증거 수집
  □ 함수 코드 다운로드 (포렌식 스냅샷)
  □ 환경 변수 목록 기록
  □ CloudTrail 로그 S3로 내보내기
  □ CloudWatch Logs 내보내기

[4단계] 원인 분석
  □ CloudTrail에서 환경 변수 변경 이력 확인
  □ Secrets Manager 접근 로그 확인
  □ 어떤 데이터가 유출됐는지 파악

[5단계] 복구
  □ 노출된 자격증명 즉시 교체
  □ 취약점 패치 후 재배포
  □ 모니터링 강화
```

### P2: 코드 변조 의심 대응 절차

```
[1단계] 탐지
  □ CloudTrail UpdateFunctionCode 이벤트 확인
    - 누가, 어디서, 언제 코드를 변경했는가?
    - 정상적인 CI/CD 파이프라인에서의 변경인가?
  □ Lambda 버전 히스토리 확인

[2단계] 증거 수집
  □ 현재 함수 코드 다운로드 (포렌식 스냅샷)
    aws lambda get-function --function-name FUNC_NAME \
      --query 'Code.Location' --output text
  □ 이전 버전 코드 다운로드

[3단계] 분석
  □ 현재 코드와 이전 버전 diff 비교
  □ 추가된 코드에서 의심스러운 패턴 탐지:
    - base64_decode + exec 조합
    - 외부 URL 하드코딩
    - 환경 변수 수집 후 외부 전송
  □ 배포 파이프라인 무결성 확인

[4단계] 격리 및 복구
  □ 변조된 함수 격리
  □ 검증된 이전 버전으로 롤백
  □ IAM 권한 감사 및 축소
  □ 코드 서명 적용
```

### P3: 자격증명 탈취 의심 대응 절차

```
[1단계] 탐지
  □ CloudTrail AssumeRole 이상 접근 탐지
    (평소에 사용하지 않던 역할을 갑자기 가정)
  □ GuardDuty "Credentials used from unusual IP" 알림 확인
  □ IMDSv2 적용 여부 확인

[2단계] 즉각 대응 (자격증명 탈취는 분 단위 대응 필요)
  □ 탈취된 IAM 액세스 키 즉시 비활성화
    aws iam update-access-key \
      --access-key-id AKIA... \
      --status Inactive
  □ 관련 IAM 역할에 Deny All 인라인 정책 추가 (임시 차단)
  □ 새 자격증명 발급

[3단계] 피해 범위 파악
  □ CloudTrail에서 탈취된 자격증명으로 수행된 모든 작업 확인
  □ 어떤 서비스에 접근했는가?
  □ 어떤 데이터를 읽었는가?
  □ 새로운 리소스를 생성했는가? (암호화폐 채굴 등)

[4단계] 복구 및 강화
  □ IMDSv2 강제 적용
  □ 최소 권한 원칙 재점검
  □ 자격증명 자동 로테이션 설정
```

**위협별 요약 대응표:**

| 위협 | 탐지 방법 | 즉각 대응 | 장기 방어 |
|------|---------|---------|---------|
| IMDSv1 SSRF | CloudTrail + GuardDuty | IMDSv1 비활성화 | IMDSv2 강제 |
| 환경 변수 시크릿 | 코드 검토 + SAST | 노출된 키 교체 | Secrets Manager 전환 |
| 과도한 IAM | IAM Access Analyzer | Deny 정책 추가 | 최소 권한 원칙 |
| 함수 코드 변조 | CloudTrail 알림 | 이전 버전 롤백 | 코드 서명 적용 |
| 의존성 취약점 | AWS Inspector | 취약 패키지 제거 | CI/CD SAST 통합 |

---

## 6. 자동화된 대응 (AWS Config + Lambda)

**반복되는 IR 작업을 자동화하면 대응 시간을 크게 단축할 수 있습니다.**

```python
#!/usr/bin/env python3
"""AWS Config 규칙 위반 시 자동으로 Lambda 설정 수정.

예: X-Ray 추적이 비활성화된 함수를 자동으로 활성화
"""

import json
import boto3


def remediate_xray_tracing(function_name: str, region: str) -> None:
    """X-Ray 추적 자동 활성화."""
    client = boto3.client("lambda", region_name=region)
    
    client.update_function_configuration(
        FunctionName=function_name,
        TracingConfig={"Mode": "Active"},
    )
    print(f"[+] X-Ray 추적 활성화: {function_name}")


def lambda_handler(event: dict, context) -> dict:
    """AWS Config 규칙 위반 시 자동 수정 핸들러.
    
    EventBridge를 통해 Config 규칙 위반 이벤트를 받아 처리.
    """
    # Config 이벤트에서 위반 함수 정보 추출
    detail = event.get("detail", {})
    rule_name = detail.get("configRuleName", "")
    resource_id = detail.get("resourceId", "")
    region = event.get("region", "ap-northeast-2")
    
    if rule_name == "lambda-xray-tracing-enabled" and resource_id:
        remediate_xray_tracing(resource_id, region)
        return {"statusCode": 200, "body": f"Remediated: {resource_id}"}
    
    return {"statusCode": 200, "body": "No remediation needed"}
```

---

<a name="english"></a>

# Serverless Incident Response

## 0. Beginner Concepts

### What is Incident Response?

**Security Incident Response** is the systematic process for handling security incidents like hacking, data breaches, and malware infections.

**The 6-phase NIST IR cycle:**
1. **Preparation** — Tools, procedures, and team ready
2. **Detection & Analysis** — Find anomalies, assess scope
3. **Containment** — Stop the spread, preserve evidence
4. **Eradication** — Remove the attacker, patch vulnerability
5. **Recovery** — Resume normal operations, strengthen monitoring
6. **Post-Incident Activity** — Root cause analysis, prevent recurrence

### Why Serverless IR is Different

**Traditional server IR:**
- SSH into server and review logs
- Memory dump to analyze running processes
- Filesystem forensics to find malicious files
- Check network connection list

**Serverless IR:**
- Execution environment disappears after function runs (minimal forensic opportunity)
- CloudWatch Logs is your primary evidence
- IAM permission analysis to determine blast radius
- Function isolation = set concurrency to 0 (no SSH)

**Analogy:**
- Traditional server = crime scene remains intact for investigators
- Serverless = crime scene disappears → only CCTV footage (CloudWatch) remains

---

## 1. Serverless Security Incident Characteristics

### 1.1 Traditional IR vs Serverless IR

| Capability | Traditional Server | Serverless |
|------------|-------------------|------------|
| Memory dump | ✓ Full access | ✗ Environment destroyed after execution |
| Filesystem forensics | ✓ Full access | ✗ Ephemeral environment |
| Process listing | ✓ Available | ✗ Not accessible |
| Network connections | ✓ Real-time view | ✗ Limited |
| Log preservation | Manual setup | ✓ Automatic (CloudWatch) |
| API access logs | Varies | ✓ Complete (API Gateway) |
| Blast radius assessment | Complex | ✓ IAM analysis gives clear picture |
| Isolation mechanism | Network ACLs, shutdown | ✓ Concurrency = 0 |

**Key insight:** In serverless IR, logs and CloudTrail are everything. You must configure comprehensive logging before incidents occur.

### 1.2 Attack Vector Classification

**Code Injection:**
- Command injection via event parameters
- Deserialization vulnerabilities (Python pickle, etc.)
- Dependency vulnerabilities (npm, pip packages with CVEs)

**Privilege Abuse:**
- Excessive IAM permissions on Lambda execution role
- SSRF to steal IMDSv1 credentials from `http://169.254.169.254/...`
- Secrets exposed in environment variables

**Supply Chain:**
- Malicious Lambda Layers (disguised as legitimate layers)
- Vulnerable container images (outdated OS in Lambda container)
- Third-party dependency poisoning (malicious code in PyPI/npm packages)

---

## 2. AWS Lambda Incident Response

### 2.1 Initial Response Automation

The `LambdaIncidentResponder` class provides four key capabilities:

**`list_suspicious_functions()`** — Scans all Lambda functions for suspicious configurations:
- Missing VPC (internet-exposed)
- Timeout > 300 seconds (long enough for data exfiltration)
- Environment variable keys containing "secret", "key", "password", "token", or "credential"
- Function URLs with `AuthType = "NONE"` (publicly accessible without authentication)

**`get_cloudwatch_logs()`** — Fetches and filters CloudWatch Logs with configurable time window and filter patterns.

**`isolate_function()`** — Three-step isolation:
1. Sets `ReservedConcurrentExecutions = 0` (blocks all new invocations immediately)
2. Disables all EventSourceMappings (SQS, Kinesis, DynamoDB triggers)
3. Records the function code download URL for forensic snapshot (valid for 10 minutes)

**`search_exfiltration_patterns()`** — Searches 72 hours of logs for data exfiltration indicators: outbound HTTP calls (curl, wget, requests), subprocess execution, eval/exec usage, base64 decoding.

**Usage:**
```bash
# Audit all functions for suspicious configurations
python3 lambda_ir.py --region us-east-1 audit

# Analyze logs for specific function (last 48 hours)
python3 lambda_ir.py logs my-function --hours 48 --pattern "ERROR"

# Isolate suspicious function (requires confirmation)
python3 lambda_ir.py isolate compromised-function

# Search for data exfiltration patterns
python3 lambda_ir.py exfil suspicious-function
```

---

## 3. SSRF / IMDSv1 Credential Theft Detection

### What is SSRF + IMDSv1?

**SSRF (Server-Side Request Forgery):** An attack where the server makes requests to a URL specified by the attacker.

**IMDS (Instance Metadata Service):** An internal AWS service at `169.254.169.254` that provides IAM credentials to Lambda/EC2 instances.

**Attack scenario:**
1. Attacker injects the IMDS URL as a parameter: `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"}`
2. Lambda function makes a request to that URL
3. IMDS returns IAM credentials (AccessKeyId, SecretAccessKey, Token)
4. Attacker now has full Lambda role permissions in AWS

**Defense — IMDSv2:** Requires a PUT request to obtain a session token before accessing metadata. SSRF attacks typically can't make PUT requests, blocking the attack.

The SSRF detector checks every Lambda event for patterns indicating IMDS access attempts or common SSRF trigger parameters (`url=`, `redirect=`, `callback=`, `proxy=`, etc.).

---

## 4. Serverless Security Monitoring

### 4.1 CloudTrail Anomaly Detection

**What is CloudTrail?** An AWS service that records every API call in your account — who did what, when, and from where.

The CloudTrail monitor tracks seven high-risk Lambda API calls and flags any that originate from non-RFC1918 IP addresses:

| Action | Risk | Security Concern |
|--------|------|-----------------|
| `UpdateFunctionCode` | HIGH | Backdoor insertion |
| `AddPermission` | HIGH | Unauthorized trigger addition |
| `PublishLayerVersion` | HIGH | Malicious layer deployment |
| `UpdateFunctionConfiguration` | HIGH | Env var modification (secret theft) |
| `CreateEventSourceMapping` | MEDIUM | New trigger for persistence |
| `PutFunctionConcurrency` | MEDIUM | DoS attack preparation |
| `DeleteFunction` | MEDIUM | Evidence destruction |

---

## 5. Serverless IR Playbook

**P1: Suspected Data Exfiltration**
```
Step 1: Detection
  □ Search CloudWatch Logs for outbound HTTP patterns
  □ Check VPC Flow Logs for unusual outbound traffic
  □ Review GuardDuty alerts

Step 2: Containment
  □ Set suspect function concurrency to 0
  □ Disable associated API Gateway stage

Step 3: Evidence Collection
  □ Download function code (forensic snapshot)
  □ Record environment variable list
  □ Export CloudTrail logs to S3

Step 4: Analysis
  □ Check CloudTrail for environment variable modification history
  □ Review Secrets Manager access logs
  □ Determine what data was exfiltrated
```

**P2: Suspected Code Tampering**
```
Step 1: Detection
  □ Review CloudTrail UpdateFunctionCode events
  □ Who changed the code? When? From where?
  □ Was it through the legitimate CI/CD pipeline?

Step 2: Analysis
  □ Download current function code
  □ Diff against previous version
  □ Look for: base64+exec combos, hardcoded external URLs,
    environment variable collection/exfiltration

Step 3: Recovery
  □ Isolate compromised function
  □ Roll back to verified previous version
  □ Apply code signing
```

**P3: Suspected Credential Theft**
```
Step 1: Detection
  □ Detect anomalous AssumeRole calls in CloudTrail
  □ Check GuardDuty "Credentials from unusual IP" alerts
  □ Verify IMDSv2 enforcement status

Step 2: Immediate Response (minutes matter!)
  □ Immediately disable stolen IAM access key
  □ Add Deny All inline policy to affected role
  □ Issue new credentials

Step 3: Blast Radius Assessment
  □ Identify all actions performed with stolen credentials
  □ Which services were accessed?
  □ Were any new resources created? (cryptomining, persistence)
```

**Threat Summary Table:**

| Threat | Detection | Immediate Response | Long-term Defense |
|--------|-----------|-------------------|-------------------|
| IMDSv1 SSRF | CloudTrail + GuardDuty | Disable IMDSv1 | Enforce IMDSv2 |
| Secrets in env vars | Code review + SAST | Rotate exposed keys | Use Secrets Manager |
| Excessive IAM | IAM Access Analyzer | Add Deny policy | Apply least privilege |
| Function code tampering | CloudTrail alert | Roll back version | Apply code signing |
| Dependency vulnerabilities | AWS Inspector | Remove vulnerable packages | CI/CD SAST integration |
