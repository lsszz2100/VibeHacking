# 클라우드 침해 대응 CTF 실습 랩

## 랩 개요

AWS/Azure/GCP 클라우드 환경의 침해 사고를 CTF 형식으로 재현한다. 로그 분석, 포렌식, 위협 헌팅 기법을 실습한다.

## 시나리오 환경 설정

```python
#!/usr/bin/env python3
"""클라우드 침해 시나리오 CTF 환경 생성기."""

import argparse
import json
import random
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path


def generate_aws_cloudtrail_scenario() -> list[dict]:
    """AWS CloudTrail 침해 시나리오 로그 생성."""
    base_time = datetime.now(timezone.utc) - timedelta(hours=6)
    logs = []

    def ts(offset_minutes: int) -> str:
        return (base_time + timedelta(minutes=offset_minutes)).isoformat()

    attacker_ip = "203.0.113.42"
    victim_account = "123456789012"

    scenario = [
        # 1. 비정상 로그인 시도
        {
            "eventTime": ts(0),
            "eventName": "ConsoleLogin",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "responseElements": {"ConsoleLogin": "Failure"},
            "additionalEventData": {"MFAUsed": "No"},
        },
        # 2. 성공한 루트 로그인 (MFA 없음)
        {
            "eventTime": ts(2),
            "eventName": "ConsoleLogin",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"},
        },
        # 3. IAM 사용자 열거
        {
            "eventTime": ts(3),
            "eventName": "ListUsers",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": None,
        },
        # 4. 백도어 IAM 사용자 생성
        {
            "eventTime": ts(5),
            "eventName": "CreateUser",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": {"userName": "svc-backup-2024"},
        },
        # 5. 관리자 권한 부여
        {
            "eventTime": ts(6),
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": {
                "userName": "svc-backup-2024",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
        # 6. 액세스 키 생성
        {
            "eventTime": ts(7),
            "eventName": "CreateAccessKey",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": {"userName": "svc-backup-2024"},
            "responseElements": {
                "accessKey": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "status": "Active",
                }
            },
        },
        # 7. S3 버킷 열거
        {
            "eventTime": ts(10),
            "eventName": "ListBuckets",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "svc-backup-2024",
            },
        },
        # 8. 민감한 버킷 접근
        {
            "eventTime": ts(12),
            "eventName": "GetObject",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "svc-backup-2024",
            },
            "requestParameters": {
                "bucketName": "prod-customer-data-confidential",
                "key": "2024/customer_pii_export.csv",
            },
        },
        # 9. 데이터 대량 다운로드
        {
            "eventTime": ts(13),
            "eventName": "GetObject",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "svc-backup-2024",
            },
            "requestParameters": {
                "bucketName": "prod-customer-data-confidential",
                "key": "2024/financial_records.xlsx",
            },
        },
        # 10. 흔적 지우기 시도 (CloudTrail 비활성화)
        {
            "eventTime": ts(20),
            "eventName": "StopLogging",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "svc-backup-2024",
            },
            "requestParameters": {
                "name": "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/management-events"
            },
        },
    ]

    # 정상 트래픽도 섞기
    normal_users = ["alice", "bob", "charlie"]
    for i in range(30):
        user = random.choice(normal_users)
        logs.append({
            "eventTime": ts(random.randint(0, 30)),
            "eventName": random.choice(["DescribeInstances", "ListBuckets", "GetObject"]),
            "sourceIPAddress": f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            "userIdentity": {"type": "IAMUser", "userName": user},
        })

    logs.extend(scenario)
    logs.sort(key=lambda x: x["eventTime"])
    return logs


class CloudIRCTFAnalyzer:
    """클라우드 침해 로그 CTF 분석기."""

    def __init__(self, logs: list[dict]):
        self.logs = logs
        self.findings: list[dict] = []
        self.flags: list[str] = []

    def find_initial_access(self) -> dict | None:
        """초기 접근 이벤트 탐지."""
        for log in self.logs:
            if (log["eventName"] == "ConsoleLogin"
                    and log.get("responseElements", {}).get("ConsoleLogin") == "Success"
                    and log.get("additionalEventData", {}).get("MFAUsed") == "No"
                    and log.get("userIdentity", {}).get("type") == "Root"):
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "initial_access",
                    "description": "루트 계정 MFA 없이 로그인",
                    "event": log,
                    "flag": "CTF{root_login_no_mfa_detected}",
                })
                self.flags.append("CTF{root_login_no_mfa_detected}")
                return log
        return None

    def find_persistence(self) -> list[dict]:
        """지속성 메커니즘 탐지."""
        persistence = []
        for log in self.logs:
            if log["eventName"] in ("CreateUser", "CreateAccessKey"):
                attacker_ip = "203.0.113.42"
                if log.get("sourceIPAddress") == attacker_ip:
                    user = log.get("requestParameters", {}).get("userName", "")
                    finding = {
                        "severity": "HIGH",
                        "type": "persistence",
                        "description": f"백도어 사용자 생성: {user}",
                        "event": log,
                    }
                    if log["eventName"] == "AttachUserPolicy" or user:
                        finding["flag"] = "CTF{backdoor_iam_user_created}"
                        self.flags.append("CTF{backdoor_iam_user_created}")
                    persistence.append(finding)
        return persistence

    def find_data_exfiltration(self) -> list[dict]:
        """데이터 유출 탐지."""
        exfil = []
        sensitive_patterns = ["pii", "confidential", "financial", "customer"]
        for log in self.logs:
            if log["eventName"] == "GetObject":
                key = log.get("requestParameters", {}).get("key", "")
                bucket = log.get("requestParameters", {}).get("bucketName", "")
                if any(p in key.lower() or p in bucket.lower()
                       for p in sensitive_patterns):
                    exfil.append({
                        "severity": "CRITICAL",
                        "type": "exfiltration",
                        "description": f"민감 데이터 접근: s3://{bucket}/{key}",
                        "event": log,
                        "flag": "CTF{sensitive_data_exfiltrated}",
                    })
                    self.flags.append("CTF{sensitive_data_exfiltrated}")
        return exfil

    def find_defense_evasion(self) -> dict | None:
        """방어 우회 탐지 (로깅 비활성화)."""
        for log in self.logs:
            if log["eventName"] == "StopLogging":
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "defense_evasion",
                    "description": "CloudTrail 로깅 비활성화 시도",
                    "event": log,
                    "flag": "CTF{cloudtrail_stopped_attacker}",
                })
                self.flags.append("CTF{cloudtrail_stopped_attacker}")
                return log
        return None

    def run_analysis(self) -> dict:
        """전체 분석 실행."""
        print("[*] 클라우드 침해 로그 분석 시작")
        print(f"[*] 총 이벤트: {len(self.logs)}개")

        initial = self.find_initial_access()
        persistence = self.find_persistence()
        exfil = self.find_data_exfiltration()
        evasion = self.find_defense_evasion()

        unique_flags = list(set(self.flags))

        print(f"\n{'='*60}")
        print(f"클라우드 침해 분석 보고서")
        print(f"{'='*60}")

        if initial:
            print(f"\n[CRITICAL] 초기 접근:")
            print(f"  {initial['eventTime']}: 루트 계정 MFA 없이 로그인")
            print(f"  출처: {initial['sourceIPAddress']}")

        if persistence:
            print(f"\n[HIGH] 지속성 ({len(persistence)}개):")
            for p in persistence:
                desc = p["description"]
                ts = p["event"]["eventTime"]
                print(f"  {ts}: {desc}")

        if exfil:
            print(f"\n[CRITICAL] 데이터 유출 ({len(exfil)}개):")
            for e in exfil:
                print(f"  {e['event']['eventTime']}: {e['description']}")

        if evasion:
            print(f"\n[CRITICAL] 방어 우회:")
            print(f"  {evasion['eventTime']}: CloudTrail 로깅 비활성화")

        print(f"\n{'='*60}")
        print(f"획득 가능 플래그 ({len(unique_flags)}개):")
        for i, flag in enumerate(unique_flags, 1):
            print(f"  {i}. {flag}")

        return {
            "total_events": len(self.logs),
            "findings": len(self.findings),
            "flags": unique_flags,
            "attacker_ip": "203.0.113.42",
            "attack_duration_min": 20,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="클라우드 IR CTF 랩")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="침해 시나리오 로그 생성")
    gen.add_argument("-o", "--output", type=Path, default=Path("cloudtrail_ctf.json"))

    analyze = sub.add_parser("analyze", help="로그 파일 분석")
    analyze.add_argument("log_file", type=Path)

    sub.add_parser("demo", help="전체 데모 실행")

    args = parser.parse_args()

    if args.cmd == "generate":
        logs = generate_aws_cloudtrail_scenario()
        args.output.write_text(json.dumps(logs, indent=2))
        print(f"[+] 시나리오 로그 생성: {args.output} ({len(logs)}개 이벤트)")

    elif args.cmd == "analyze":
        if not args.log_file.exists():
            print(f"[!] 파일 없음: {args.log_file}")
            return
        logs = json.loads(args.log_file.read_text())
        analyzer = CloudIRCTFAnalyzer(logs)
        result = analyzer.run_analysis()

    elif args.cmd == "demo":
        logs = generate_aws_cloudtrail_scenario()
        analyzer = CloudIRCTFAnalyzer(logs)
        analyzer.run_analysis()


if __name__ == "__main__":
    main()
```

## 실습 과제

```
CloudTrail 분석 챌린지
☐ 초기 침입 시간과 출처 IP 파악
☐ 생성된 백도어 계정명 확인
☐ 유출된 S3 버킷 및 파일 목록 추출
☐ 공격자가 로깅을 끈 시간 파악
☐ 공격 타임라인 전체 재구성

심화 과제
☐ GuardDuty 탐지 결과 분석
☐ VPC Flow Log에서 C2 통신 탐지
☐ 람다 함수 악용 흔적 찾기
☐ CloudTrail 로그 무결성 검증
```

클라우드 IR에서 가장 중요한 것은 **로그 보존과 빠른 가시성 확보**다. 공격자가 로그를 삭제하기 전에 별도 저장소에 실시간 복제해야 한다.
