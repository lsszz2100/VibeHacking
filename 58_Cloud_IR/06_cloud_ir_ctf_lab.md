> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 클라우드 침해 대응 CTF 실습 랩

---

## 학습 목표

이 실습을 마치면 다음을 할 수 있다:

1. **CloudTrail 로그를 읽고** 공격자의 행동 순서를 시간 순으로 재구성한다
2. **CTF 플래그 형식**을 이해하고 로그에서 침해 증거를 추출한다
3. **AWS 핵심 보안 서비스** — CloudTrail, IAM, S3 — 의 역할과 관계를 설명한다
4. **10단계 공격 체인**의 각 단계가 왜 위험한지 설명한다
5. **침해 후 방어 체크리스트**를 적용해 재발을 막는다

---

## CTF란 무엇인가?

### 완전 초보자를 위한 설명

CTF(Capture The Flag)는 **보안 경진대회**다. 참가자는 주어진 시스템이나 파일에서 숨겨진 **"플래그"** — 보통 `CTF{...}` 형태의 문자열 — 를 찾아내야 한다. 플래그를 더 많이, 더 빨리 찾을수록 점수가 높다.

```
플래그 예시:
  CTF{root_login_no_mfa_detected}
  CTF{backdoor_iam_user_created}
  CTF{sensitive_data_exfiltrated}
  CTF{cloudtrail_stopped_attacker}
```

**왜 CTF 형식으로 배우는가?**
- 실제 침해 사고를 그대로 재현하면 법적·윤리적 문제가 있다
- CTF는 "안전한 모의 범행 현장"을 제공한다
- 플래그를 찾는 과정이 실제 포렌식 분석과 동일한 사고 과정을 요구한다
- 성취감이 있어서 학습 동기 유지에 좋다

### 이 실습의 시나리오

어느 회사의 AWS 환경에 공격자가 침입했다. 공격자는 루트 계정을 탈취하고, 백도어를 만들고, 고객 데이터를 빼갔다. 당신은 **사고 대응 분석가(Incident Responder)**로서 CloudTrail 로그를 분석해 공격자의 행동을 추적해야 한다.

---

## AWS 핵심 개념 설명

### CloudTrail — "AWS의 CCTV"

CloudTrail은 AWS 계정에서 일어나는 **모든 API 호출을 기록**하는 서비스다.

```
실생활 비유:
  건물 입구에 CCTV가 설치되어 있다.
  누가(who), 언제(when), 어디서(from where),
  무슨 문(which door)을 열었는지 모두 기록한다.

  CloudTrail은 AWS에서 일어나는 모든 행동을 이렇게 기록한다.
  "alice가 2024-01-15 09:23:11에 서울에서 S3 버킷을 열었다."
```

CloudTrail 로그 하나의 구조:

```json
{
  "eventTime": "2024-01-15T09:23:11Z",   // 언제
  "eventName": "GetObject",               // 무엇을 했나
  "sourceIPAddress": "203.0.113.42",      // 어디서
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alice"                   // 누가
  },
  "requestParameters": {
    "bucketName": "my-bucket",            // 어떤 리소스에
    "key": "sensitive-file.csv"
  }
}
```

**왜 중요한가?** 공격자가 AWS에서 무언가를 하면 반드시 CloudTrail에 흔적이 남는다. 침해 조사의 출발점이다.

---

### IAM — "AWS의 출입통제 시스템"

IAM(Identity and Access Management)은 **누가 무엇을 할 수 있는지** 관리하는 시스템이다.

```
실생활 비유:
  회사 건물의 출입 카드 시스템과 같다.
  - 직원 카드(IAM 사용자): 이름이 적힌 개인 카드
  - 역할 카드(IAM Role): 특정 업무용 공유 카드 ("배달원 전용 출입")
  - 권한(Policy): 어떤 문을 열 수 있는지 목록
  - 관리자 권한(AdministratorAccess): 모든 문을 열 수 있는 마스터키
```

IAM 핵심 개념:

| 개념 | 설명 | 실생활 비유 |
|------|------|------------|
| IAM 사용자 | AWS를 사용하는 개인 계정 | 직원 사번 카드 |
| IAM 역할(Role) | 서비스나 함수가 사용하는 임시 자격증명 | 택시 기사용 임시 출입증 |
| 정책(Policy) | 허용/거부 규칙 목록 | 출입 가능 구역 목록 |
| 액세스 키 | API 호출용 ID + 비밀번호 | 프로그램이 사용하는 카드 번호 |
| 루트 계정 | AWS 계정의 최고 관리자 | 건물주 (모든 권한) |

---

### S3 — "AWS의 파일 보관함"

S3(Simple Storage Service)는 AWS의 **파일 저장소**다. 사진, 문서, 데이터베이스 백업 등 어떤 파일이든 저장할 수 있다.

```
실생활 비유:
  구글 드라이브나 dropbox와 비슷하다.
  하지만 기업에서는 S3에 고객 개인정보, 재무 데이터,
  백업 파일 등 매우 민감한 데이터를 보관한다.
  
  공격자 입장에서 S3는 "금고"다 — 여기에 가치 있는 데이터가 있다.
```

**버킷(Bucket)**: 파일들을 담는 컨테이너. 버킷 이름은 전 세계에서 유일해야 한다.

---

### 루트 계정 vs IAM 사용자 — 결정적 차이

```
루트 계정:
  - AWS 계정을 처음 만들 때 생성되는 최고 관리자
  - 아무것도 제한할 수 없음 (정책으로도 막을 수 없음)
  - 신용카드 변경, 계정 삭제 같은 최고 수준 작업 가능
  - 일상적인 작업에는 절대 사용하면 안 됨
  - 반드시 MFA(이중인증)을 설정해야 함

IAM 사용자:
  - 루트 계정이 만들어 주는 "직원 계정"
  - 필요한 권한만 부여 가능 (최소 권한 원칙)
  - 루트 계정보다 훨씬 제한적
  - MFA도 설정 가능하지만 선택사항
```

**루트 계정이 탈취되면?** — 공격자는 AWS 계정에 대한 완전한 제어권을 갖는다. 모든 데이터 삭제, 모든 리소스 생성, 요금 폭탄 유발 등 무엇이든 가능하다.

---

## 공격 시나리오 단계별 해설

이 실습에서 재현하는 공격은 **10단계**로 이루어진다. 각 단계가 왜 위험한지 이해하는 것이 중요하다.

```
공격자 IP:    203.0.113.42  (외부 공격자)
피해 계정:    AWS 계정 123456789012
공격 시작:    T+0분 (기준 시각)
공격 완료:    T+20분 (단 20분 만에 완료)
```

---

### Step 1: 루트 계정 로그인 실패 (T+0분)

```json
{
  "eventName": "ConsoleLogin",
  "userIdentity": {"type": "Root"},
  "responseElements": {"ConsoleLogin": "Failure"},
  "additionalEventData": {"MFAUsed": "No"}
}
```

**무슨 일인가?** 공격자가 루트 계정의 비밀번호를 시도했지만 실패했다.

**왜 위험한가?**
- 루트 계정 로그인 시도 자체가 비정상이다 (루트는 일상적으로 사용하지 않음)
- MFAUsed가 "No"라는 것은 MFA가 설정조차 안 되어 있다는 뜻
- 비밀번호만 알면 로그인 가능하다는 신호

**탐지 포인트:** 루트 계정의 ConsoleLogin 이벤트가 보이면 즉시 조사해야 한다.

---

### Step 2: 루트 계정 로그인 성공 — MFA 없음 (T+2분)

```json
{
  "eventName": "ConsoleLogin",
  "userIdentity": {"type": "Root"},
  "responseElements": {"ConsoleLogin": "Success"},
  "additionalEventData": {"MFAUsed": "No"}
}
```

**무슨 일인가?** 2분 후 공격자가 루트 계정 로그인에 성공했다.

**왜 위험한가?**
- MFA 없이 루트 로그인 성공 = 비밀번호 하나가 전체 AWS 계정을 열어줌
- 공격자는 이제 모든 것을 할 수 있다
- 이 시점부터 공격이 본격화된다

**실제 사례:** 2019년 Capital One 침해 사고는 잘못 설정된 IAM 역할에서 시작되었다. 루트 탈취는 그보다 훨씬 심각하다.

**플래그:** `CTF{root_login_no_mfa_detected}` — 이 이벤트를 찾으면 첫 번째 플래그 획득

---

### Step 3: IAM 사용자 열거 — 정찰 단계 (T+3분)

```json
{
  "eventName": "ListUsers",
  "userIdentity": {"type": "Root"}
}
```

**무슨 일인가?** 공격자가 이 AWS 계정에 어떤 사용자들이 있는지 목록을 조회했다.

**왜 위험한가?**
- 정찰(Reconnaissance) 단계다
- 공격자는 어떤 사용자가 있는지 파악해 더 자연스러운 이름의 백도어를 만든다
- "svc-backup-2024" 같은 이름은 실제 서비스 계정처럼 보이도록 의도된 것

**비유:** 강도가 집에 침입하기 전에 가족 구성원을 파악하는 것과 같다.

---

### Step 4: 백도어 IAM 사용자 생성 (T+5분)

```json
{
  "eventName": "CreateUser",
  "requestParameters": {"userName": "svc-backup-2024"}
}
```

**무슨 일인가?** 공격자가 새로운 IAM 사용자를 생성했다.

**왜 위험한가?**
- **지속성(Persistence)** 확보 단계다
- 루트 계정 비밀번호가 나중에 바뀌더라도, 이 새 계정으로 계속 접근 가능
- `svc-backup-2024`라는 이름은 "서비스 계정"처럼 보여서 의심받지 않도록 설계됨
- IT 팀이 수동으로 사용자 목록을 검토하지 않으면 발견하기 어려움

---

### Step 5: 관리자 권한 부여 (T+6분)

```json
{
  "eventName": "AttachUserPolicy",
  "requestParameters": {
    "userName": "svc-backup-2024",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  }
}
```

**무슨 일인가?** 방금 만든 백도어 계정에 최고 권한(AdministratorAccess)을 부여했다.

**왜 위험한가?**
- AdministratorAccess = AWS 계정에서 모든 것을 할 수 있는 권한
- 이제 `svc-backup-2024`는 루트와 거의 동일한 권한을 갖는다
- 공격자는 루트 계정 없이도 계속 공격 가능

---

### Step 6: 액세스 키 생성 (T+7분)

```json
{
  "eventName": "CreateAccessKey",
  "requestParameters": {"userName": "svc-backup-2024"},
  "responseElements": {
    "accessKey": {
      "accessKeyId": "FAKEKEYEXAMPLE000000",
      "status": "Active"
    }
  }
}
```

**무슨 일인가?** 백도어 계정의 API 액세스 키를 생성했다.

**왜 위험한가?**
- 액세스 키는 **프로그램적 접근**을 가능하게 한다
- AWS 콘솔(웹 UI) 없이도 커맨드라인이나 스크립트로 AWS를 제어 가능
- 이 키를 공격자 서버에 저장해 두면 언제든 AWS에 접근 가능
- 매우 빠른 대량 데이터 다운로드가 가능해진다

**비유:** 집 열쇠의 복사본을 만드는 것과 같다.

**플래그:** `CTF{backdoor_iam_user_created}` — Steps 4-6을 분석해 획득

---

### Step 7: S3 버킷 열거 (T+10분)

```json
{
  "eventName": "ListBuckets",
  "userIdentity": {"type": "IAMUser", "userName": "svc-backup-2024"}
}
```

**무슨 일인가?** 이제 백도어 계정으로 전환해 S3 버킷 목록을 조회했다.

**왜 위험한가?**
- 루트 계정 사용을 최소화해 탐지를 피하려는 전술
- S3 버킷 목록에서 민감한 데이터가 있을 버킷을 식별한다
- `prod-customer-data-confidential` 같은 이름은 즉시 표적이 된다

---

### Step 8-9: 민감 데이터 다운로드 (T+12~13분)

```json
{
  "eventName": "GetObject",
  "requestParameters": {
    "bucketName": "prod-customer-data-confidential",
    "key": "2024/customer_pii_export.csv"
  }
}
```

**무슨 일인가?** 고객 개인정보(PII)와 재무 기록을 다운로드했다.

**왜 위험한가?**
- 이것이 공격의 **최종 목표**다 — 데이터 유출(Exfiltration)
- PII(개인 식별 정보): 이름, 주소, 이메일, 주민번호 등
- 재무 기록: 신용카드 정보, 계좌 정보 등
- GDPR, 개인정보보호법 위반으로 수억 원의 과태료 가능성

**플래그:** `CTF{sensitive_data_exfiltrated}` — GetObject 이벤트와 민감 파일명을 찾으면 획득

---

### Step 10: CloudTrail 로깅 비활성화 — 흔적 지우기 (T+20분)

```json
{
  "eventName": "StopLogging",
  "requestParameters": {
    "name": "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/management-events"
  }
}
```

**무슨 일인가?** CloudTrail 로깅을 비활성화해 이후 행동이 기록되지 않도록 했다.

**왜 위험한가?**
- 이후 공격 행동이 로그에 남지 않는다
- 포렌식 분석을 방해한다
- 하지만 역설적으로 **이 StopLogging 이벤트 자체가 가장 큰 증거**다

**중요한 포인트:** StopLogging은 로그에 남는다. 따라서 이것을 탐지하는 것이 가능하다. 그러나 이 이후의 행동은 알 수 없다.

**실무 대응:** CloudTrail 로그를 S3에 저장할 때, 그 S3 버킷은 별도의 계정에 보관하고 삭제 방지(MFA Delete)를 설정해야 한다.

**플래그:** `CTF{cloudtrail_stopped_attacker}` — StopLogging 이벤트 탐지 시 획득

---

## 플래그 설명

이 실습에서 획득 가능한 플래그는 총 4개다:

| 플래그 | 의미 | 탐지 방법 |
|--------|------|-----------|
| `CTF{root_login_no_mfa_detected}` | 루트 계정이 MFA 없이 로그인됨 | ConsoleLogin + Root + MFAUsed=No + Success |
| `CTF{backdoor_iam_user_created}` | 백도어 IAM 계정 생성 | CreateUser + 공격자 IP |
| `CTF{sensitive_data_exfiltrated}` | 민감 데이터 유출 | GetObject + 민감 버킷/파일명 |
| `CTF{cloudtrail_stopped_attacker}` | 로그 삭제 시도 | StopLogging 이벤트 |

---

## 랩 개요

AWS 환경의 침해 사고를 CTF 형식으로 재현한다. 로그 분석, 포렌식, 위협 헌팅 기법을 실습한다.

## 시나리오 환경 설정

```python
#!/usr/bin/env python3
"""
클라우드 침해 시나리오 CTF 환경 생성기.

이 스크립트는 3가지 서브커맨드를 제공한다:
  generate  — 시뮬레이션된 CloudTrail 로그 파일을 생성한다
  analyze   — 생성된 로그 파일에서 침해 이벤트를 탐지한다
  demo      — generate + analyze를 한 번에 실행한다

사용 예시:
  python3 06_cloud_ir_ctf_lab.py demo
  python3 06_cloud_ir_ctf_lab.py generate -o my_logs.json
  python3 06_cloud_ir_ctf_lab.py analyze my_logs.json
"""

import argparse
import json
import random
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path


def generate_aws_cloudtrail_scenario() -> list[dict]:
    """
    AWS CloudTrail 침해 시나리오 로그 생성.

    실제 침해 사고에서 관찰되는 10단계 공격 패턴을 재현한다.
    정상 트래픽 30개와 공격 이벤트 10개를 섞어 실제 환경을 시뮬레이션한다.
    """
    # 기준 시각: 지금으로부터 6시간 전 (공격이 6시간 전에 시작된 것처럼)
    base_time = datetime.now(timezone.utc) - timedelta(hours=6)
    logs = []

    def ts(offset_minutes: int) -> str:
        """기준 시각에서 offset_minutes분 후의 ISO 8601 타임스탬프를 반환."""
        return (base_time + timedelta(minutes=offset_minutes)).isoformat()

    # 공격자 IP: 203.0.113.x는 RFC 5737에 따른 문서용 예약 주소
    attacker_ip = "203.0.113.42"
    # 피해 AWS 계정 번호 (12자리 숫자)
    victim_account = "123456789012"

    # 10단계 공격 시나리오
    # 각 이벤트는 실제 CloudTrail 로그의 핵심 필드를 포함
    scenario = [
        # Step 1: 루트 계정 로그인 실패 (T+0분)
        # 공격자가 처음에는 비밀번호를 틀림 — 비정상 신호
        {
            "eventTime": ts(0),
            "eventName": "ConsoleLogin",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "responseElements": {"ConsoleLogin": "Failure"},
            "additionalEventData": {"MFAUsed": "No"},
        },
        # Step 2: 루트 계정 로그인 성공 — MFA 없음 (T+2분)
        # MFAUsed=No는 이 계정에 MFA가 설정되지 않았다는 뜻 — 심각한 취약점
        {
            "eventTime": ts(2),
            "eventName": "ConsoleLogin",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"},
        },
        # Step 3: IAM 사용자 열거 (T+3분)
        # 어떤 계정이 있는지 파악하는 정찰 단계
        {
            "eventTime": ts(3),
            "eventName": "ListUsers",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": None,
        },
        # Step 4: 백도어 IAM 사용자 생성 (T+5분)
        # "svc-backup-2024" — 서비스 계정처럼 보이도록 의도된 이름
        {
            "eventTime": ts(5),
            "eventName": "CreateUser",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": {"userName": "svc-backup-2024"},
        },
        # Step 5: 관리자 권한 부여 (T+6분)
        # AdministratorAccess = AWS에서 모든 것을 할 수 있는 최고 권한
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
        # Step 6: 액세스 키 생성 (T+7분)
        # 액세스 키 = 프로그램에서 AWS API를 호출할 수 있는 자격증명
        # 콘솔 없이도 AWS를 완전히 제어할 수 있게 됨
        {
            "eventTime": ts(7),
            "eventName": "CreateAccessKey",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": {"userName": "svc-backup-2024"},
            "responseElements": {
                "accessKey": {
                    "accessKeyId": "FAKEKEYEXAMPLE000000",
                    "status": "Active",
                }
            },
        },
        # Step 7: S3 버킷 열거 (T+10분)
        # 이제 백도어 계정으로 전환 — 루트 사용을 줄여 탐지 회피
        {
            "eventTime": ts(10),
            "eventName": "ListBuckets",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "svc-backup-2024",
            },
        },
        # Step 8: 민감한 버킷 접근 — 고객 PII (T+12분)
        # PII = Personally Identifiable Information (개인 식별 정보)
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
        # Step 9: 재무 데이터 다운로드 (T+13분)
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
        # Step 10: CloudTrail 로깅 비활성화 — 흔적 지우기 (T+20분)
        # 이후 행동이 기록되지 않도록 로깅을 끔
        # 역설적으로 이 StopLogging 이벤트 자체가 가장 중요한 증거가 됨
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

    # 정상 트래픽 30개를 섞어서 실제 환경처럼 노이즈를 추가
    # 실제 포렌식에서는 수만 건의 정상 로그 사이에서 공격을 찾아야 함
    normal_users = ["alice", "bob", "charlie"]
    for i in range(30):
        user = random.choice(normal_users)
        logs.append({
            "eventTime": ts(random.randint(0, 30)),
            "eventName": random.choice(["DescribeInstances", "ListBuckets", "GetObject"]),
            "sourceIPAddress": f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            "userIdentity": {"type": "IAMUser", "userName": user},
        })

    # 공격 이벤트를 추가하고 시간순으로 정렬
    logs.extend(scenario)
    logs.sort(key=lambda x: x["eventTime"])
    return logs


class CloudIRCTFAnalyzer:
    """
    클라우드 침해 로그 CTF 분석기.

    CloudTrail 로그에서 4가지 유형의 침해 이벤트를 탐지한다:
      1. 초기 접근 (Initial Access) — MFA 없는 루트 로그인
      2. 지속성 (Persistence) — 백도어 계정 생성
      3. 데이터 유출 (Exfiltration) — 민감 S3 데이터 접근
      4. 방어 우회 (Defense Evasion) — CloudTrail 비활성화
    """

    def __init__(self, logs: list[dict]):
        self.logs = logs
        # 탐지된 침해 이벤트 목록
        self.findings: list[dict] = []
        # 획득된 CTF 플래그 목록
        self.flags: list[str] = []

    def find_initial_access(self) -> dict | None:
        """
        초기 접근 이벤트 탐지.

        탐지 조건:
          - 이벤트명: ConsoleLogin
          - 결과: Success
          - MFA: 사용 안 함
          - 사용자 유형: Root
        이 조합은 매우 위험한 신호다 — 루트가 MFA 없이 로그인됨.
        """
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
        """
        지속성 메커니즘 탐지.

        탐지 조건:
          - 이벤트명: CreateUser 또는 CreateAccessKey
          - 출처 IP: 공격자 IP (203.0.113.42)
        공격자 IP에서 계정 생성이 일어나면 백도어 생성 의심.
        """
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
        """
        데이터 유출 탐지.

        탐지 조건:
          - 이벤트명: GetObject (S3에서 파일 다운로드)
          - 버킷명 또는 파일명에 민감 키워드 포함:
            pii, confidential, financial, customer
        민감 데이터에 접근한 경우 유출 의심.
        """
        exfil = []
        # 민감 데이터를 나타내는 키워드 패턴
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
        """
        방어 우회 탐지 (로깅 비활성화).

        탐지 조건:
          - 이벤트명: StopLogging
        CloudTrail을 끄려는 시도는 명백한 공격 신호다.
        정당한 업무에서 로깅을 끄는 경우는 극히 드물다.
        """
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
        """
        전체 분석 실행.

        4가지 탐지 함수를 순서대로 실행하고 결과를 종합해 보고서를 출력한다.
        실제 SIEM(Security Information and Event Management) 시스템의
        동작 방식을 단순화해 구현한 것이다.
        """
        print("[*] 클라우드 침해 로그 분석 시작")
        print(f"[*] 총 이벤트: {len(self.logs)}개")

        # 각 탐지 함수 실행 — MITRE ATT&CK 프레임워크 전술 순서
        initial = self.find_initial_access()      # TA0001: Initial Access
        persistence = self.find_persistence()      # TA0003: Persistence
        exfil = self.find_data_exfiltration()      # TA0010: Exfiltration
        evasion = self.find_defense_evasion()      # TA0005: Defense Evasion

        # 중복 플래그 제거 (같은 이벤트가 여러 번 탐지될 수 있음)
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
    parser = argparse.ArgumentParser(
        description="클라우드 IR CTF 랩 — AWS CloudTrail 침해 시나리오 실습",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 06_cloud_ir_ctf_lab.py demo
  python3 06_cloud_ir_ctf_lab.py generate -o cloudtrail_ctf.json
  python3 06_cloud_ir_ctf_lab.py analyze cloudtrail_ctf.json
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # generate: 침해 시나리오 로그 파일 생성
    gen = sub.add_parser("generate", help="침해 시나리오 로그 생성")
    gen.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("cloudtrail_ctf.json"),
        help="출력 파일 경로 (기본값: cloudtrail_ctf.json)",
    )

    # analyze: 기존 로그 파일 분석
    analyze = sub.add_parser("analyze", help="로그 파일 분석")
    analyze.add_argument("log_file", type=Path, help="분석할 JSON 로그 파일")

    # demo: 생성 + 분석을 한 번에
    sub.add_parser("demo", help="전체 데모 실행 (generate + analyze)")

    args = parser.parse_args()

    if args.cmd == "generate":
        logs = generate_aws_cloudtrail_scenario()
        args.output.write_text(json.dumps(logs, indent=2, ensure_ascii=False))
        print(f"[+] 시나리오 로그 생성: {args.output} ({len(logs)}개 이벤트)")
        print(f"[+] 이제 다음 명령으로 분석하세요:")
        print(f"    python3 06_cloud_ir_ctf_lab.py analyze {args.output}")

    elif args.cmd == "analyze":
        if not args.log_file.exists():
            print(f"[!] 파일 없음: {args.log_file}")
            print(f"    먼저 generate 명령으로 로그를 생성하세요.")
            return
        logs = json.loads(args.log_file.read_text())
        analyzer = CloudIRCTFAnalyzer(logs)
        analyzer.run_analysis()

    elif args.cmd == "demo":
        print("[*] 침해 시나리오 로그 생성 중...")
        logs = generate_aws_cloudtrail_scenario()
        print(f"[+] {len(logs)}개 이벤트 생성 완료 (공격 10개 + 정상 30개)")
        print()
        analyzer = CloudIRCTFAnalyzer(logs)
        analyzer.run_analysis()


if __name__ == "__main__":
    main()
```

---

## 실습 과제

```
CloudTrail 분석 챌린지
☐ 초기 침입 시간과 출처 IP 파악
  힌트: ConsoleLogin 이벤트에서 Root 계정의 Success 응답을 찾아라
  힌트: additionalEventData.MFAUsed 필드를 확인하라

☐ 생성된 백도어 계정명 확인
  힌트: CreateUser 이벤트를 찾아 requestParameters.userName을 확인하라
  힌트: 공격자 IP(203.0.113.42)에서 발생한 이벤트만 필터링하라

☐ 유출된 S3 버킷 및 파일 목록 추출
  힌트: GetObject 이벤트를 모두 찾아라
  힌트: 버킷명에 "confidential"이 포함된 것을 집중 조사하라

☐ 공격자가 로깅을 끈 시간 파악
  힌트: StopLogging 이벤트의 eventTime을 확인하라

☐ 공격 타임라인 전체 재구성
  힌트: 공격자 IP(203.0.113.42)로 필터링해 시간순으로 정렬하라
  힌트: 총 공격 소요 시간은 몇 분인가?

심화 과제
☐ GuardDuty 탐지 결과 분석
  힌트: GuardDuty는 RootUsage, UnauthorizedAccess 등의 찾기를 생성한다
  힌트: 실제 AWS GuardDuty 콘솔에서 Findings 메뉴를 탐색해보라

☐ VPC Flow Log에서 C2 통신 탐지
  힌트: 공격자 IP(203.0.113.42)와의 연결 패턴을 분석하라
  힌트: 비정상적인 아웃바운드 트래픽 패턴에 주목하라

☐ 람다 함수 악용 흔적 찾기
  힌트: CreateFunction, UpdateFunctionCode 이벤트를 조사하라

☐ CloudTrail 로그 무결성 검증
  힌트: CloudTrail은 SHA-256 해시로 로그 무결성을 검증할 수 있다
  힌트: aws cloudtrail validate-logs 명령을 사용하라
```

---

## 방어 체크리스트

다음 10가지를 모두 구현하면 이번 실습에서 재현된 공격의 대부분을 막거나 탐지할 수 있다:

| # | 항목 | 구현 방법 | 막는 공격 |
|---|------|-----------|-----------|
| 1 | **루트 계정 MFA 필수 설정** | AWS 콘솔 → 보안 자격증명 → MFA 활성화 | Steps 1-2 |
| 2 | **루트 계정 일상 사용 금지** | SCP로 루트 계정 콘솔 로그인 차단 | Steps 1-6 |
| 3 | **루트 로그인 알림 설정** | CloudWatch Alarm → ConsoleLogin + Root | Steps 1-2 |
| 4 | **IAM 사용자 생성 알림** | CloudTrail + EventBridge → CreateUser 이벤트 | Steps 3-4 |
| 5 | **권한 부여 알림** | AttachUserPolicy, PutUserPolicy 이벤트 모니터링 | Step 5 |
| 6 | **S3 버킷 접근 로깅** | S3 서버 접근 로깅 + S3 이벤트 알림 | Steps 7-9 |
| 7 | **AWS GuardDuty 활성화** | GuardDuty → 자동으로 이상 행동 탐지 | Steps 1-9 |
| 8 | **CloudTrail 로그 별도 계정 보관** | 별도 보안 계정의 S3에 로그 저장 | Step 10 |
| 9 | **S3 MFA Delete 설정** | 로그 버킷에 MFA Delete 활성화 | Step 10 |
| 10 | **최소 권한 원칙 적용** | IAM Access Analyzer 사용, 사용하지 않는 권한 제거 | Steps 4-9 |

클라우드 IR에서 가장 중요한 것은 **로그 보존과 빠른 가시성 확보**다. 공격자가 로그를 삭제하기 전에 별도 저장소에 실시간 복제해야 한다.

---

<a name="english"></a>

# Cloud Incident Response CTF Lab

---

## Learning Objectives

After completing this lab, you will be able to:

1. **Read CloudTrail logs** and reconstruct attacker actions in chronological order
2. **Understand CTF flag format** and extract evidence of compromise from logs
3. **Explain the role** of AWS core security services — CloudTrail, IAM, S3
4. **Describe why each step** of the 10-step attack chain is dangerous
5. **Apply the post-compromise defense checklist** to prevent recurrence

---

## What is CTF?

### Explanation for Complete Beginners

CTF (Capture The Flag) is a **security competition**. Participants must find hidden **"flags"** — usually strings in the format `CTF{...}` — inside given systems or files. More flags found, faster, means a higher score.

```
Example flags:
  CTF{root_login_no_mfa_detected}
  CTF{backdoor_iam_user_created}
  CTF{sensitive_data_exfiltrated}
  CTF{cloudtrail_stopped_attacker}
```

**Why learn through CTF format?**
- Recreating real breaches directly would be illegal and unethical
- CTF provides a "safe mock crime scene"
- Finding flags requires the same thought process as real forensic analysis
- The sense of achievement keeps learners motivated

### Scenario for This Lab

An attacker has broken into a company's AWS environment. The attacker hijacked the root account, created a backdoor, and exfiltrated customer data. You are an **Incident Responder** tasked with analyzing CloudTrail logs to trace the attacker's actions.

---

## AWS Core Concepts Explained

### CloudTrail — "AWS's CCTV"

CloudTrail is a service that **records every API call** made in an AWS account.

```
Real-world analogy:
  Think of a building with a security camera at every door.
  It records who (who), when (when), from where (where),
  and which door (which resource) was accessed.

  CloudTrail does exactly this for AWS.
  "alice accessed an S3 bucket from Seoul at 2024-01-15 09:23:11."
```

Structure of a single CloudTrail log entry:

```json
{
  "eventTime": "2024-01-15T09:23:11Z",   // When
  "eventName": "GetObject",               // What action was taken
  "sourceIPAddress": "203.0.113.42",      // From where
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alice"                   // Who
  },
  "requestParameters": {
    "bucketName": "my-bucket",            // On which resource
    "key": "sensitive-file.csv"
  }
}
```

**Why does it matter?** When an attacker does anything in AWS, CloudTrail leaves a trace. It is the starting point for breach investigations.

---

### IAM — "AWS's Access Control System"

IAM (Identity and Access Management) controls **who can do what**.

```
Real-world analogy:
  Think of a corporate building's access card system.
  - Employee card (IAM User): a personal card with your name on it
  - Role card (IAM Role): a shared card for a specific job ("delivery only")
  - Permissions (Policy): the list of doors you can open
  - Admin access (AdministratorAccess): a master key that opens every door
```

IAM Core Concepts:

| Concept | Description | Real-world analogy |
|---------|-------------|-------------------|
| IAM User | Personal account for AWS access | Employee ID card |
| IAM Role | Temporary credentials for services | Temporary contractor badge |
| Policy | List of allow/deny rules | List of permitted areas |
| Access Key | ID + secret for API calls | Card number for programs |
| Root Account | Supreme administrator of AWS account | Building owner (all access) |

---

### S3 — "AWS's File Storage"

S3 (Simple Storage Service) is AWS's **file storage**. It can store any file — photos, documents, database backups.

```
Real-world analogy:
  Similar to Google Drive or Dropbox.
  But in enterprise environments, S3 holds extremely sensitive data:
  customer PII, financial data, backup files.
  
  From an attacker's perspective, S3 is the "vault" —
  that's where the valuable data lives.
```

**Bucket**: A container for files. Bucket names must be globally unique across all of AWS.

---

### Root Account vs IAM User — The Critical Difference

```
Root Account:
  - Created when an AWS account is first set up; the supreme administrator
  - Cannot be restricted by any policy
  - Can change credit card info, delete the account, etc.
  - Should NEVER be used for everyday tasks
  - Must have MFA (multi-factor authentication) enabled

IAM User:
  - A "staff account" created by the root account
  - Can be granted only the permissions needed (principle of least privilege)
  - Far more limited than the root account
  - MFA can be configured (but is optional by default)
```

**If the root account is compromised?** — The attacker gains complete control over the AWS account: deleting all data, creating any resource, causing enormous bills — anything is possible.

---

## Attack Scenario Step-by-Step Walkthrough

This lab reproduces an attack in **10 steps**. Understanding why each step is dangerous is key.

```
Attacker IP:    203.0.113.42  (external attacker)
Victim account: AWS account 123456789012
Attack start:   T+0 min (reference time)
Attack end:     T+20 min (completed in only 20 minutes)
```

---

### Step 1: Root Account Login Failure (T+0 min)

```json
{
  "eventName": "ConsoleLogin",
  "userIdentity": {"type": "Root"},
  "responseElements": {"ConsoleLogin": "Failure"},
  "additionalEventData": {"MFAUsed": "No"}
}
```

**What happened?** The attacker tried the root account password but failed.

**Why is it dangerous?**
- A root account login attempt itself is abnormal (root should never be used daily)
- `MFAUsed: "No"` means MFA is not even set up on this account
- It signals that only the password stands between the attacker and full control

**Detection point:** Any ConsoleLogin event for the Root account should trigger an immediate investigation.

---

### Step 2: Root Account Login Success — No MFA (T+2 min)

```json
{
  "eventName": "ConsoleLogin",
  "userIdentity": {"type": "Root"},
  "responseElements": {"ConsoleLogin": "Success"},
  "additionalEventData": {"MFAUsed": "No"}
}
```

**What happened?** Two minutes later, the attacker successfully logged into the root account.

**Why is it dangerous?**
- No MFA + successful root login = one password opens the entire AWS account
- The attacker now has the ability to do anything
- From this point the attack escalates rapidly

**Real-world example:** The 2019 Capital One breach started from a misconfigured IAM role. Root account compromise is far more severe.

**Flag:** `CTF{root_login_no_mfa_detected}` — find this event to claim the first flag

---

### Step 3: IAM User Enumeration — Reconnaissance (T+3 min)

```json
{
  "eventName": "ListUsers",
  "userIdentity": {"type": "Root"}
}
```

**What happened?** The attacker listed all IAM users in the account.

**Why is it dangerous?**
- This is the **Reconnaissance** phase
- The attacker learns what user names exist in order to create a believable backdoor name
- The name "svc-backup-2024" is intentionally chosen to look like a legitimate service account

**Analogy:** Like a burglar scoping out the household members before breaking in.

---

### Step 4: Backdoor IAM User Creation (T+5 min)

```json
{
  "eventName": "CreateUser",
  "requestParameters": {"userName": "svc-backup-2024"}
}
```

**What happened?** The attacker created a new IAM user.

**Why is it dangerous?**
- This is the **Persistence** phase
- Even if the root password is changed later, the attacker retains access via this new account
- The name `svc-backup-2024` looks like a service account to avoid suspicion
- Hard to detect unless the IT team manually reviews the user list

---

### Step 5: Grant Administrator Access (T+6 min)

```json
{
  "eventName": "AttachUserPolicy",
  "requestParameters": {
    "userName": "svc-backup-2024",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  }
}
```

**What happened?** The newly created backdoor account received AdministratorAccess — the highest privilege in AWS.

**Why is it dangerous?**
- AdministratorAccess = permission to do everything in the AWS account
- `svc-backup-2024` now has essentially the same powers as root
- The attacker can continue the attack without using the root account

---

### Step 6: Access Key Creation (T+7 min)

```json
{
  "eventName": "CreateAccessKey",
  "requestParameters": {"userName": "svc-backup-2024"},
  "responseElements": {
    "accessKey": {
      "accessKeyId": "FAKEKEYEXAMPLE000000",
      "status": "Active"
    }
  }
}
```

**What happened?** An API access key was created for the backdoor account.

**Why is it dangerous?**
- Access keys enable **programmatic access** — no web console needed
- The attacker can control AWS via command-line scripts stored on their server
- Enables rapid bulk data downloads without browser limitations

**Analogy:** Like making a copy of the house key.

**Flag:** `CTF{backdoor_iam_user_created}` — analyze Steps 4–6 to claim this flag

---

### Step 7: S3 Bucket Enumeration (T+10 min)

```json
{
  "eventName": "ListBuckets",
  "userIdentity": {"type": "IAMUser", "userName": "svc-backup-2024"}
}
```

**What happened?** The attacker switched to the backdoor account and listed all S3 buckets.

**Why is it dangerous?**
- Switching away from root minimizes its usage, reducing detection chances
- The bucket list reveals which buckets likely hold sensitive data
- Names like `prod-customer-data-confidential` immediately become targets

---

### Steps 8–9: Sensitive Data Download (T+12–13 min)

```json
{
  "eventName": "GetObject",
  "requestParameters": {
    "bucketName": "prod-customer-data-confidential",
    "key": "2024/customer_pii_export.csv"
  }
}
```

**What happened?** Customer PII (Personally Identifiable Information) and financial records were downloaded.

**Why is it dangerous?**
- This is the **final objective** of the attack — data exfiltration
- PII: names, addresses, email, social security numbers, etc.
- Financial records: credit card info, account details, etc.
- Potential for massive fines under GDPR, CCPA, or local privacy laws

**Flag:** `CTF{sensitive_data_exfiltrated}` — find the GetObject events with sensitive file names

---

### Step 10: Disable CloudTrail Logging — Cover Tracks (T+20 min)

```json
{
  "eventName": "StopLogging",
  "requestParameters": {
    "name": "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/management-events"
  }
}
```

**What happened?** CloudTrail logging was disabled so that subsequent actions are not recorded.

**Why is it dangerous?**
- Actions taken after this point leave no trace
- Hampers forensic analysis
- But paradoxically, **the StopLogging event itself is the most important piece of evidence**

**Key insight:** StopLogging itself is logged. So detecting it is possible. But everything that happens after this is unknown.

**Operational response:** CloudTrail logs stored in S3 should be kept in a separate security account with MFA Delete enabled, so attackers cannot delete them.

**Flag:** `CTF{cloudtrail_stopped_attacker}` — detect the StopLogging event to claim this flag

---

## Flag Summary

There are 4 flags available in this lab:

| Flag | Meaning | How to detect |
|------|---------|---------------|
| `CTF{root_login_no_mfa_detected}` | Root logged in without MFA | ConsoleLogin + Root + MFAUsed=No + Success |
| `CTF{backdoor_iam_user_created}` | Backdoor IAM account created | CreateUser + attacker IP |
| `CTF{sensitive_data_exfiltrated}` | Sensitive data exfiltrated | GetObject + sensitive bucket/file name |
| `CTF{cloudtrail_stopped_attacker}` | Log deletion attempted | StopLogging event |

---

## Lab Overview

Recreate cloud security incidents in AWS/Azure/GCP environments in CTF format. Practice log analysis, forensics, and threat hunting techniques.

## Scenario Environment Setup

```python
#!/usr/bin/env python3
"""
Cloud Incident Response CTF Lab — AWS CloudTrail breach scenario.

Sub-commands:
  generate  — Generate simulated CloudTrail log file
  analyze   — Detect breach events in a generated log file
  demo      — Run generate + analyze in one step

Usage examples:
  python3 06_cloud_ir_ctf_lab.py demo
  python3 06_cloud_ir_ctf_lab.py generate -o my_logs.json
  python3 06_cloud_ir_ctf_lab.py analyze my_logs.json
"""

import argparse
import json
import random
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path


def generate_aws_cloudtrail_scenario() -> list[dict]:
    """
    Generate AWS CloudTrail breach scenario logs.

    Reproduces a 10-step attack pattern observed in real-world breaches.
    Mixes 30 normal traffic events with 10 attack events to simulate a real environment.
    """
    # Base time: 6 hours ago (simulating an attack that started 6 hours back)
    base_time = datetime.now(timezone.utc) - timedelta(hours=6)
    logs = []

    def ts(offset_minutes: int) -> str:
        """Return ISO 8601 timestamp offset_minutes after the base time."""
        return (base_time + timedelta(minutes=offset_minutes)).isoformat()

    # 203.0.113.x is RFC 5737 documentation-reserved address space
    attacker_ip = "203.0.113.42"
    victim_account = "123456789012"

    # 10-step attack scenario
    scenario = [
        # Step 1: Root account login failure (T+0 min)
        # Attacker tries the password but fails — first anomalous signal
        {
            "eventTime": ts(0),
            "eventName": "ConsoleLogin",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "responseElements": {"ConsoleLogin": "Failure"},
            "additionalEventData": {"MFAUsed": "No"},
        },
        # Step 2: Root account login success — no MFA (T+2 min)
        # MFAUsed=No means MFA is not even configured — critical vulnerability
        {
            "eventTime": ts(2),
            "eventName": "ConsoleLogin",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"},
        },
        # Step 3: IAM user enumeration (T+3 min)
        # Reconnaissance — understand what accounts exist before creating a backdoor
        {
            "eventTime": ts(3),
            "eventName": "ListUsers",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": None,
        },
        # Step 4: Backdoor IAM user creation (T+5 min)
        # "svc-backup-2024" is designed to look like a legitimate service account
        {
            "eventTime": ts(5),
            "eventName": "CreateUser",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": {"userName": "svc-backup-2024"},
        },
        # Step 5: Grant administrator access (T+6 min)
        # AdministratorAccess = highest privilege in AWS; effectively equals root
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
        # Step 6: Access key creation (T+7 min)
        # Access key = credentials for programmatic AWS API access
        # No console needed — scripts can fully control AWS with this key
        {
            "eventTime": ts(7),
            "eventName": "CreateAccessKey",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {"type": "Root"},
            "requestParameters": {"userName": "svc-backup-2024"},
            "responseElements": {
                "accessKey": {
                    "accessKeyId": "FAKEKEYEXAMPLE000000",
                    "status": "Active",
                }
            },
        },
        # Step 7: S3 bucket enumeration (T+10 min)
        # Switch to backdoor account — reduces root usage to avoid detection
        {
            "eventTime": ts(10),
            "eventName": "ListBuckets",
            "sourceIPAddress": attacker_ip,
            "userIdentity": {
                "type": "IAMUser",
                "userName": "svc-backup-2024",
            },
        },
        # Step 8: Access sensitive bucket — customer PII (T+12 min)
        # PII = Personally Identifiable Information
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
        # Step 9: Download financial data (T+13 min)
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
        # Step 10: Disable CloudTrail logging — cover tracks (T+20 min)
        # Subsequent actions will not be recorded
        # But this StopLogging event itself is the most important evidence
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

    # Mix in 30 normal traffic events to add noise, simulating a real environment
    # In real forensics, you need to find attacks among tens of thousands of normal logs
    normal_users = ["alice", "bob", "charlie"]
    for i in range(30):
        user = random.choice(normal_users)
        logs.append({
            "eventTime": ts(random.randint(0, 30)),
            "eventName": random.choice(["DescribeInstances", "ListBuckets", "GetObject"]),
            "sourceIPAddress": f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
            "userIdentity": {"type": "IAMUser", "userName": user},
        })

    # Add attack events and sort chronologically
    logs.extend(scenario)
    logs.sort(key=lambda x: x["eventTime"])
    return logs


class CloudIRCTFAnalyzer:
    """
    Cloud breach log CTF analyzer.

    Detects 4 categories of breach events in CloudTrail logs:
      1. Initial Access — root login without MFA
      2. Persistence — backdoor account creation
      3. Exfiltration — access to sensitive S3 data
      4. Defense Evasion — disabling CloudTrail
    """

    def __init__(self, logs: list[dict]):
        self.logs = logs
        # List of detected breach events
        self.findings: list[dict] = []
        # List of captured CTF flags
        self.flags: list[str] = []

    def find_initial_access(self) -> dict | None:
        """
        Detect initial access events.

        Detection criteria:
          - Event name: ConsoleLogin
          - Result: Success
          - MFA: not used
          - User type: Root
        This combination is a critical signal — root logged in without MFA.
        """
        for log in self.logs:
            if (log["eventName"] == "ConsoleLogin"
                    and log.get("responseElements", {}).get("ConsoleLogin") == "Success"
                    and log.get("additionalEventData", {}).get("MFAUsed") == "No"
                    and log.get("userIdentity", {}).get("type") == "Root"):
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "initial_access",
                    "description": "Root account login without MFA",
                    "event": log,
                    "flag": "CTF{root_login_no_mfa_detected}",
                })
                self.flags.append("CTF{root_login_no_mfa_detected}")
                return log
        return None

    def find_persistence(self) -> list[dict]:
        """
        Detect persistence mechanisms.

        Detection criteria:
          - Event name: CreateUser or CreateAccessKey
          - Source IP: attacker IP (203.0.113.42)
        Account creation from the attacker IP indicates backdoor creation.
        """
        persistence = []
        for log in self.logs:
            if log["eventName"] in ("CreateUser", "CreateAccessKey"):
                attacker_ip = "203.0.113.42"
                if log.get("sourceIPAddress") == attacker_ip:
                    user = log.get("requestParameters", {}).get("userName", "")
                    finding = {
                        "severity": "HIGH",
                        "type": "persistence",
                        "description": f"Backdoor user created: {user}",
                        "event": log,
                    }
                    if log["eventName"] == "AttachUserPolicy" or user:
                        finding["flag"] = "CTF{backdoor_iam_user_created}"
                        self.flags.append("CTF{backdoor_iam_user_created}")
                    persistence.append(finding)
        return persistence

    def find_data_exfiltration(self) -> list[dict]:
        """
        Detect data exfiltration.

        Detection criteria:
          - Event name: GetObject (download file from S3)
          - Bucket name or file name contains sensitive keywords:
            pii, confidential, financial, customer
        Access to sensitive data is flagged as suspected exfiltration.
        """
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
                        "description": f"Sensitive data accessed: s3://{bucket}/{key}",
                        "event": log,
                        "flag": "CTF{sensitive_data_exfiltrated}",
                    })
                    self.flags.append("CTF{sensitive_data_exfiltrated}")
        return exfil

    def find_defense_evasion(self) -> dict | None:
        """
        Detect defense evasion (logging disabled).

        Detection criteria:
          - Event name: StopLogging
        Attempting to disable CloudTrail is a clear attack signal.
        Legitimate operations almost never turn off logging.
        """
        for log in self.logs:
            if log["eventName"] == "StopLogging":
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "defense_evasion",
                    "description": "CloudTrail logging disable attempt",
                    "event": log,
                    "flag": "CTF{cloudtrail_stopped_attacker}",
                })
                self.flags.append("CTF{cloudtrail_stopped_attacker}")
                return log
        return None

    def run_analysis(self) -> dict:
        """
        Run complete analysis.

        Executes 4 detection functions in sequence and synthesizes results
        into a report. This is a simplified implementation of how a real
        SIEM (Security Information and Event Management) system works.
        """
        print("[*] Starting cloud breach log analysis")
        print(f"[*] Total events: {len(self.logs)}")

        # Run each detection function — following MITRE ATT&CK tactic order
        initial = self.find_initial_access()      # TA0001: Initial Access
        persistence = self.find_persistence()      # TA0003: Persistence
        exfil = self.find_data_exfiltration()      # TA0010: Exfiltration
        evasion = self.find_defense_evasion()      # TA0005: Defense Evasion

        # Deduplicate flags (same event may be detected multiple times)
        unique_flags = list(set(self.flags))

        print(f"\n{'='*60}")
        print(f"Cloud Breach Analysis Report")
        print(f"{'='*60}")

        if initial:
            print(f"\n[CRITICAL] Initial Access:")
            print(f"  {initial['eventTime']}: Root account login without MFA")
            print(f"  Source: {initial['sourceIPAddress']}")

        if persistence:
            print(f"\n[HIGH] Persistence ({len(persistence)} events):")
            for p in persistence:
                desc = p["description"]
                ts = p["event"]["eventTime"]
                print(f"  {ts}: {desc}")

        if exfil:
            print(f"\n[CRITICAL] Data Exfiltration ({len(exfil)} events):")
            for e in exfil:
                print(f"  {e['event']['eventTime']}: {e['description']}")

        if evasion:
            print(f"\n[CRITICAL] Defense Evasion:")
            print(f"  {evasion['eventTime']}: CloudTrail logging disabled")

        print(f"\n{'='*60}")
        print(f"Captured flags ({len(unique_flags)} total):")
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
    parser = argparse.ArgumentParser(
        description="Cloud IR CTF Lab — AWS CloudTrail breach scenario practice",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python3 06_cloud_ir_ctf_lab.py demo
  python3 06_cloud_ir_ctf_lab.py generate -o cloudtrail_ctf.json
  python3 06_cloud_ir_ctf_lab.py analyze cloudtrail_ctf.json
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # generate: create breach scenario log file
    gen = sub.add_parser("generate", help="Generate breach scenario logs")
    gen.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("cloudtrail_ctf.json"),
        help="Output file path (default: cloudtrail_ctf.json)",
    )

    # analyze: analyze an existing log file
    analyze = sub.add_parser("analyze", help="Analyze a log file")
    analyze.add_argument("log_file", type=Path, help="JSON log file to analyze")

    # demo: generate + analyze in one step
    sub.add_parser("demo", help="Run full demo (generate + analyze)")

    args = parser.parse_args()

    if args.cmd == "generate":
        logs = generate_aws_cloudtrail_scenario()
        args.output.write_text(json.dumps(logs, indent=2, ensure_ascii=False))
        print(f"[+] Scenario logs generated: {args.output} ({len(logs)} events)")
        print(f"[+] Analyze them with:")
        print(f"    python3 06_cloud_ir_ctf_lab.py analyze {args.output}")

    elif args.cmd == "analyze":
        if not args.log_file.exists():
            print(f"[!] File not found: {args.log_file}")
            print(f"    Run generate first to create log files.")
            return
        logs = json.loads(args.log_file.read_text())
        analyzer = CloudIRCTFAnalyzer(logs)
        analyzer.run_analysis()

    elif args.cmd == "demo":
        print("[*] Generating breach scenario logs...")
        logs = generate_aws_cloudtrail_scenario()
        print(f"[+] {len(logs)} events generated (10 attack + 30 normal)")
        print()
        analyzer = CloudIRCTFAnalyzer(logs)
        analyzer.run_analysis()


if __name__ == "__main__":
    main()
```

---

## Practice Exercises

```
CloudTrail Analysis Challenges
☐ Identify initial intrusion time and source IP
  Hint: Look for ConsoleLogin events with Root account and Success response
  Hint: Check the additionalEventData.MFAUsed field

☐ Confirm name of created backdoor account
  Hint: Find the CreateUser event and check requestParameters.userName
  Hint: Filter for events from the attacker IP (203.0.113.42)

☐ Extract list of exfiltrated S3 buckets and files
  Hint: Find all GetObject events
  Hint: Focus on buckets with "confidential" in the name

☐ Identify the time attacker disabled logging
  Hint: Check the eventTime of the StopLogging event

☐ Reconstruct complete attack timeline
  Hint: Filter by attacker IP (203.0.113.42) and sort chronologically
  Hint: How many minutes did the complete attack take?

Advanced Exercises
☐ Analyze GuardDuty detection results
  Hint: GuardDuty generates findings like RootUsage and UnauthorizedAccess
  Hint: Explore the Findings menu in the real AWS GuardDuty console

☐ Detect C2 communication from VPC Flow Logs
  Hint: Analyze connection patterns with attacker IP (203.0.113.42)
  Hint: Look for unusual outbound traffic patterns

☐ Find traces of Lambda function abuse
  Hint: Investigate CreateFunction and UpdateFunctionCode events

☐ Verify integrity of CloudTrail logs
  Hint: CloudTrail uses SHA-256 hashes for log integrity verification
  Hint: Use the "aws cloudtrail validate-logs" command
```

---

## Defense Checklist

Implementing all 10 items below would prevent or detect most of the attacks reproduced in this lab:

| # | Item | How to implement | Attack prevented |
|---|------|-----------------|-----------------|
| 1 | **Require MFA on root account** | AWS Console → Security credentials → Activate MFA | Steps 1-2 |
| 2 | **Never use root for daily tasks** | Use SCP to block root console login | Steps 1-6 |
| 3 | **Alert on root logins** | CloudWatch Alarm → ConsoleLogin + Root | Steps 1-2 |
| 4 | **Alert on IAM user creation** | CloudTrail + EventBridge → CreateUser event | Steps 3-4 |
| 5 | **Alert on privilege escalation** | Monitor AttachUserPolicy, PutUserPolicy events | Step 5 |
| 6 | **Enable S3 access logging** | S3 server access logging + S3 event notifications | Steps 7-9 |
| 7 | **Enable AWS GuardDuty** | GuardDuty → automatically detects anomalous behavior | Steps 1-9 |
| 8 | **Store CloudTrail logs in a separate account** | Logs stored in a separate security account's S3 | Step 10 |
| 9 | **Enable S3 MFA Delete on log buckets** | Activate MFA Delete on the logging bucket | Step 10 |
| 10 | **Apply principle of least privilege** | Use IAM Access Analyzer, remove unused permissions | Steps 4-9 |

The most important aspects of cloud IR are **log preservation and rapid visibility**. Logs must be replicated in real-time to a separate storage location before attackers can delete them.
