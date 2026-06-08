> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 CTF 스타일 실습 랩

## 이 랩에 대하여

이 랩은 지금까지 배운 레드팀 보고 개념을 CTF(Capture The Flag) 스타일로 실습하는 공간입니다. 각 실습은 다음 구조를 따릅니다:

```
목표   — 이 실습으로 무엇을 배우는가
시나리오 — 실제 상황 설명
힌트   — 막혔을 때 참고
풀이   — 완성된 답안
```

도구를 마스터하는 것보다, **"왜 이 방식인가?"**를 이해하는 것이 목표입니다.

---

## 실습 1: MITRE ATT&CK 기법 매핑 연습

### 목표
공격 시나리오를 읽고 각 행동을 MITRE ATT&CK 기법 ID에 매핑하는 능력을 기릅니다.

### 시나리오: 가상의 해킹 사건 "Project Neptune"

```
[공격 로그 요약]

Day 1 - 2024-03-01
  09:15 — 공격자가 회사 홈페이지에서 임원 이메일 주소를 수집함
  14:30 — 공격자가 회사 채용 공고에서 기술 스택 목록을 확인함

Day 3 - 2024-03-03
  10:02 — "계약서_최종본.docm" 파일이 첨부된 이메일이 수신됨 (재무팀 김모씨)
  10:47 — 수신자가 파일을 열고 매크로를 활성화함
  10:48 — cmd.exe가 PowerShell 프로세스를 생성함
  10:49 — PowerShell이 외부 IP(203.0.113.42)로 HTTPS 연결 시도

Day 4 - 2024-03-04
  14:22 — 새로운 로컬 관리자 계정 "svc_backup2"가 생성됨
  14:25 — 작업 스케줄러에 새 작업이 등록됨 (C:\Temp\update.exe 실행)
  15:10 — procdump.exe로 lsass.dmp 파일 생성됨

Day 5 - 2024-03-05
  09:30 — SMB를 통해 서버 SERVER02에 접근함
  09:35 — SERVER02에서 C:\Finance\Q4_Report.xlsx 파일이 복사됨
  11:00 — 복사된 파일이 외부 클라우드 스토리지로 업로드됨
```

### 힌트

```
힌트 1: 홈페이지에서 이메일 수집 → T15xx 계열 (정찰)
힌트 2: .docm 매크로 파일 첨부 이메일 → T1566 계열
힌트 3: PowerShell 실행 → T1059 계열
힌트 4: 외부 IP 연결 → T1071 또는 T1102 계열
힌트 5: 로컬 관리자 계정 생성 → T1136 계열
힌트 6: 작업 스케줄러 등록 → T1053 계열
힌트 7: lsass 덤프 → T1003 계열
힌트 8: SMB 원격 접근 → T1021 계열
힌트 9: 클라우드 스토리지 유출 → T1567 계열
```

### 풀이

```python
#!/usr/bin/env python3
"""
실습 1 풀이: ATT&CK 매핑
"""

from dataclasses import dataclass
from typing import List


@dataclass
class AttackEvent:
    timestamp: str
    action: str
    technique_id: str
    technique_name: str
    tactic: str


SOLUTION: List[AttackEvent] = [
    AttackEvent("Day1 09:15", "홈페이지에서 임원 이메일 수집",
                "T1591.002", "Gather Victim Org Information: Email Addresses", "Reconnaissance"),
    AttackEvent("Day1 14:30", "채용공고에서 기술 스택 확인",
                "T1591.004", "Gather Victim Org Information: Identify Roles", "Reconnaissance"),
    AttackEvent("Day3 10:02", ".docm 첨부 스피어피싱 이메일",
                "T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    AttackEvent("Day3 10:48", "cmd.exe → PowerShell 프로세스 생성",
                "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    AttackEvent("Day3 10:49", "외부 IP로 HTTPS C2 연결",
                "T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    AttackEvent("Day4 14:22", "새 로컬 관리자 계정 생성",
                "T1136.001", "Create Account: Local Account", "Persistence"),
    AttackEvent("Day4 14:25", "작업 스케줄러에 악성 작업 등록",
                "T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence"),
    AttackEvent("Day4 15:10", "procdump로 LSASS 메모리 덤프",
                "T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    AttackEvent("Day5 09:30", "SMB로 SERVER02 원격 접근",
                "T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    AttackEvent("Day5 09:35", "재무 보고서 파일 복사",
                "T1005", "Data from Local System", "Collection"),
    AttackEvent("Day5 11:00", "클라우드 스토리지로 파일 업로드",
                "T1567.002", "Exfiltration Over Web Service: Cloud Storage", "Exfiltration"),
]


def print_solution() -> None:
    print("=" * 70)
    print("실습 1 풀이: Project Neptune ATT&CK 매핑")
    print("=" * 70)
    print(f"{'시간':<15} {'전술':<25} {'기법 ID':<15} {'기법명':<35}")
    print("-" * 95)
    for event in SOLUTION:
        print(f"{event.timestamp:<15} {event.tactic:<25} {event.technique_id:<15} {event.technique_name:<35}")
    print(f"\n총 {len(SOLUTION)}개 이벤트 매핑 완료")


if __name__ == "__main__":
    print_solution()
```

**채점 기준**:
- 9~11개 정답: 우수
- 6~8개 정답: 양호
- 5개 이하: ATT&CK 문서 추가 학습 필요

---

## 실습 2: 레드팀 보고서 작성

### 목표
샘플 발견사항을 기반으로 실제 레드팀 보고서 섹션을 작성합니다.

### 시나리오: 가상 회사 "CloudStore Inc." 레드팀 결과

다음 정보가 주어집니다:

```
[발견사항 데이터]

발견 1:
  - 시스템: web01.cloudstore.example.com
  - 취약점: 로그인 페이지 SQL Injection
  - 달성: 사용자 DB 전체 덤프 (15만 건)
  - 탐지: 미탐지 (WAF 없음)
  - CVSS: ?  (계산 필요)

발견 2:
  - 시스템: admin.cloudstore.example.com
  - 취약점: 기본 관리자 계정 (admin/admin123)
  - 달성: 관리자 패널 완전 장악
  - 탐지: 미탐지
  - CVSS: ?  (계산 필요)

발견 3:
  - 시스템: 내부 문서 서버 192.168.10.50
  - 취약점: 미패치 SMBGhost (CVE-2020-0796)
  - 달성: 원격 코드 실행
  - 탐지: 탐지됨 (EDR 경보, 4시간 후)
  - CVSS: ?  (계산 필요)
```

### 힌트

```
CVSS 계산 힌트:
  발견 1: SQL Injection → 공격 벡터: Network, 인증 불필요, 데이터 기밀성: High
         → CVSS ~ 9.8 (Critical)
  발견 2: 기본 계정 → 공격 벡터: Network, 저난이도, 완전 제어
         → CVSS ~ 9.8 (Critical)
  발견 3: SMBGhost → 원격 코드 실행, 인증 불필요
         → CVSS ~ 10.0 (Critical)

보고서 힌트:
  - 경영진 요약: "15만 명 고객 데이터 유출 위험"을 비즈니스 언어로
  - 각 발견사항: 공격 경로, 증거, 수정 권고사항 포함
  - 우선순위: 모두 Critical이므로 즉각 조치 필요
```

### 풀이

```python
#!/usr/bin/env python3
"""
실습 2 풀이: 보고서 작성
이 코드를 실행하면 샘플 보고서가 생성됩니다.
"""

import sys
from dataclasses import dataclass, field
from datetime import date
from typing import List


@dataclass
class Finding:
    fid: str
    title: str
    severity: str
    cvss: float
    system: str
    description: str
    path: str
    remediation: str

    def render(self) -> str:
        return (
            f"\n### {self.fid}: {self.title}\n\n"
            f"**위험도**: {self.severity} (CVSS: {self.cvss})\n"
            f"**시스템**: `{self.system}`\n\n"
            f"**설명**: {self.description}\n\n"
            f"**공격 경로**:\n```\n{self.path}\n```\n\n"
            f"**수정 권고사항**: {self.remediation}\n"
        )


SAMPLE_FINDINGS: List[Finding] = [
    Finding(
        fid="F-001",
        title="로그인 페이지 SQL Injection으로 고객 DB 전체 노출",
        severity="Critical",
        cvss=9.8,
        system="web01.cloudstore.example.com",
        description=(
            "로그인 폼의 username 파라미터에 SQL Injection 취약점이 존재합니다. "
            "이를 이용해 15만 명의 고객 이름, 이메일, 비밀번호 해시에 접근했습니다. "
            "WAF(웹 방화벽)가 없어 탐지되지 않았습니다."
        ),
        path="공격자 → 로그인 페이지 → UNION 기반 SQL Injection → users 테이블 전체 덤프",
        remediation=(
            "1. (즉시) 해당 페이지 오프라인 또는 WAF 긴급 차단 규칙 적용\n"
            "2. (48시간) 파라미터화된 쿼리(Prepared Statement)로 코드 수정\n"
            "3. (1주) 모든 입력값 검증 코드 전수 감사\n"
            "4. (1개월) WAF 도입 및 SQL Injection 규칙 활성화"
        ),
    ),
    Finding(
        fid="F-002",
        title="관리자 패널 기본 계정으로 완전 장악 가능",
        severity="Critical",
        cvss=9.8,
        system="admin.cloudstore.example.com",
        description=(
            "관리자 패널이 기본 계정(admin/admin123)으로 접근 가능합니다. "
            "로그인 후 전체 시스템 설정, 사용자 데이터, 결제 정보에 접근했습니다."
        ),
        path="공격자 → /admin 페이지 → 기본 계정 로그인 → 전체 관리자 권한",
        remediation=(
            "1. (즉시) 기본 계정 비밀번호 강력한 임시 비밀번호로 변경\n"
            "2. (24시간) 관리자 패널 IP 화이트리스트 적용\n"
            "3. (1주) 관리자 계정 MFA 적용\n"
            "4. (2주) 비밀번호 정책 강화 (최소 16자, 복잡도)"
        ),
    ),
    Finding(
        fid="F-003",
        title="SMBGhost 취약점으로 내부 서버 원격 코드 실행",
        severity="Critical",
        cvss=10.0,
        system="192.168.10.50 (내부 문서 서버)",
        description=(
            "CVE-2020-0796 (SMBGhost) 취약점이 패치되지 않아 "
            "원격에서 SYSTEM 권한으로 코드를 실행할 수 있었습니다. "
            "EDR이 4시간 후 탐지했으나 이미 파일 시스템에 접근한 후였습니다."
        ),
        path="내부망 접근 → SMBGhost 익스플로잇 → SYSTEM 권한 RCE → 문서 서버 완전 장악",
        remediation=(
            "1. (즉시) KB4551762 패치 적용\n"
            "2. (즉시) SMBv3.1.1 압축 기능 비활성화 (임시 조치)\n"
            "3. (1주) 내부망 SMB 포트(445) 접근 제어 강화\n"
            "4. (1개월) 취약점 관리 프로세스 수립"
        ),
    ),
]


def generate_report(findings: List[Finding]) -> str:
    critical_count = sum(1 for f in findings if f.severity == "Critical")
    lines = [
        "# CloudStore Inc. 레드팀 침투 테스트 보고서",
        "",
        f"**보고일**: {date.today()}",
        f"**기밀등급**: CONFIDENTIAL",
        "",
        "---",
        "",
        "## 경영진 요약",
        "",
        f"레드팀은 CloudStore Inc. 의 외부 및 내부 시스템을 대상으로 침투 테스트를 수행하였습니다.",
        f"총 **{len(findings)}개**의 심각한 보안 취약점이 발견되었으며, 이 중 **{critical_count}개**는",
        "즉각적인 조치가 필요한 **Critical** 등급입니다.",
        "",
        "**핵심 위험 사항**:",
        "- 약 15만 명의 고객 개인정보가 외부 공격자에게 노출될 수 있습니다.",
        "- 관리자 시스템 전체가 단순한 기본 비밀번호로 접근 가능합니다.",
        "- 내부 서버가 2020년 이후 알려진 취약점으로 원격 장악 가능합니다.",
        "",
        "**즉각 조치 없이 발생 가능한 결과**:",
        "- 개인정보보호법 위반 (최대 전년도 매출액 3%)",
        "- 고객 신뢰도 하락 및 서비스 중단",
        "- 랜섬웨어 공격 피해 가능성",
        "",
        "---",
        "",
        "## 발견사항 요약",
        "",
        f"| 번호 | 제목 | 위험도 | CVSS |",
        f"|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.fid} | {f.title[:40]} | {f.severity} | {f.cvss} |")
    lines += ["", "---", "", "## 발견사항 상세"]
    for f in findings:
        lines.append(f.render())
    return "\n".join(lines)


if __name__ == "__main__":
    output_path = sys.argv[1] if len(sys.argv) > 1 else None
    report = generate_report(SAMPLE_FINDINGS)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fp:
            fp.write(report)
        print(f"보고서 저장됨: {output_path}")
    else:
        print(report)
```

**실습 목표 달성 여부 확인**:
```
[ ] 3개 발견사항에 올바른 CVSS 점수 부여
[ ] 경영진 요약을 비즈니스 언어로 작성
[ ] 각 발견사항에 구체적 수정 권고사항 포함
[ ] 우선순위 순서로 발견사항 정렬
```

---

## 실습 3: 킬 체인 기반 공격 시뮬레이션 계획 수립

### 목표
주어진 조건에서 킬 체인 7단계를 모두 포함한 레드팀 작전 계획을 수립합니다.

### 시나리오: 가상 기업 "MediCloud" 레드팀 의뢰

```
고객사: MediCloud (클라우드 기반 의료 기록 서비스)
범위: 외부 공개 웹 서비스 + 내부 데이터 서버
크라운 쥬얼: 환자 의료 기록 데이터베이스 (DB-PROD-01)
기간: 21일
제약: 의료 장비 시스템 제외, DDoS 금지
목표: DB-PROD-01의 patient_records 테이블 접근 여부 확인
```

### 힌트

```
단계별 힌트:

1단계 정찰:
  - OSINT: LinkedIn, 회사 홈페이지, Shodan
  - 목적: 직원 이메일, 사용 기술, 열린 포트 파악

2단계 무기화:
  - 스피어피싱 미끼: "의료 소프트웨어 업데이트 알림"
  - 페이로드: Office 매크로 또는 LNK 파일

3단계 전달:
  - 스피어피싱 → IT 관리자 또는 개발자 타겟
  - 클릭 유도 문구: "긴급 보안 패치 적용 필요"

4단계 실행:
  - 매크로 실행 → PowerShell 임플란트

5단계 설치:
  - 레지스트리 또는 작업 스케줄러 지속성

6단계 C2:
  - HTTPS 기반 C2 (80/443 포트 사용)
  - 비콘 간격: 60~300초

7단계 목표 달성:
  - 내부 정찰 → DB-PROD-01 식별
  - 자격 증명 탈취 → DB 접근
```

### 풀이

```python
#!/usr/bin/env python3
"""
실습 3 풀이: MediCloud 레드팀 작전 계획 수립
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import List


@dataclass
class KillChainStep:
    step: int
    name: str
    duration_days: int
    objectives: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    att_ck_ids: List[str] = field(default_factory=list)
    deliverables: List[str] = field(default_factory=list)


MEDICLOUD_PLAN: List[KillChainStep] = [
    KillChainStep(
        step=1,
        name="Reconnaissance (정찰)",
        duration_days=3,
        objectives=[
            "MediCloud 직원 이메일 주소 수집",
            "외부 공개 포트 및 서비스 식별",
            "사용 기술 스택 파악",
        ],
        techniques=[
            "LinkedIn 직원 검색 (IT 팀, 개발팀)",
            "Shodan으로 공개 IP 서비스 스캔",
            "회사 홈페이지 채용 공고 분석",
            "Google Dorking: site:medicloud.example",
        ],
        att_ck_ids=["T1591.002", "T1596.005", "T1593.001"],
        deliverables=["직원 이메일 목록 10~20명", "공개 서비스 목록", "피싱 타겟 선정"],
    ),
    KillChainStep(
        step=2,
        name="Weaponization (무기화)",
        duration_days=2,
        objectives=[
            "스피어피싱 페이로드 제작",
            "C2 인프라 준비",
        ],
        techniques=[
            "Office 매크로 임플란트 제작",
            "미끼 문서: '긴급 보안 패치 안내서.docm'",
            "C2 서버 구축 (HTTPS, 443 포트)",
            "도메인 타이포스쿼팅: medicloud-updates.com",
        ],
        att_ck_ids=["T1587.001", "T1583.001"],
        deliverables=["악성 .docm 파일", "C2 서버 준비 완료", "피싱 이메일 초안"],
    ),
    KillChainStep(
        step=3,
        name="Delivery (전달)",
        duration_days=3,
        objectives=[
            "IT 관리자 또는 개발자에게 피싱 이메일 발송",
            "클릭률 30% 이상 목표",
        ],
        techniques=[
            "스피어피싱: IT 팀장 타겟",
            "이메일 제목: '[긴급] MediCloud 보안 업데이트 필수 적용'",
            "발신자 스푸핑: security@medicloud-notify.com",
        ],
        att_ck_ids=["T1566.001"],
        deliverables=["피싱 이메일 발송 로그", "클릭 여부 확인"],
    ),
    KillChainStep(
        step=4,
        name="Exploitation (실행)",
        duration_days=2,
        objectives=["매크로 실행을 통한 초기 코드 실행"],
        techniques=[
            "VBA 매크로 → PowerShell 다운로더",
            "User Account Control 우회 (T1548.002)",
            "AMSI 우회 기법 적용",
        ],
        att_ck_ids=["T1059.001", "T1548.002", "T1562.001"],
        deliverables=["초기 셸 획득 확인"],
    ),
    KillChainStep(
        step=5,
        name="Installation (설치)",
        duration_days=2,
        objectives=["지속성 메커니즘 설치", "탐지 회피"],
        techniques=[
            "작업 스케줄러에 임플란트 등록",
            "레지스트리 Run 키 추가",
            "파일 타임스탬프 위조 (Timestomping)",
        ],
        att_ck_ids=["T1053.005", "T1547.001", "T1070.006"],
        deliverables=["시스템 재시작 후에도 C2 연결 유지 확인"],
    ),
    KillChainStep(
        step=6,
        name="Command & Control (C2 통신)",
        duration_days=3,
        objectives=["안정적인 C2 채널 유지", "탐지 회피"],
        techniques=[
            "HTTPS C2 (443 포트, 정상 TLS 인증서)",
            "비콘 간격: 120초 ± 30초 지터",
            "HTTP 헤더 위장 (User-Agent 조작)",
        ],
        att_ck_ids=["T1071.001", "T1573.002", "T1008"],
        deliverables=["7일 이상 C2 채널 유지", "블루팀 미탐지 확인"],
    ),
    KillChainStep(
        step=7,
        name="Actions on Objectives (목표 달성)",
        duration_days=6,
        objectives=[
            "DB-PROD-01 식별 및 접근",
            "patient_records 테이블 접근 증명",
        ],
        techniques=[
            "내부 정찰: nmap 스캔, Active Directory 열거",
            "자격 증명 탈취: LSASS 덤프 또는 Kerberoasting",
            "데이터베이스 서버 접근 (DB 관리 계정 탈취)",
            "SELECT COUNT(*) FROM patient_records 실행 (증거 수집)",
        ],
        att_ck_ids=["T1046", "T1003.001", "T1558.003", "T1005"],
        deliverables=[
            "DB-PROD-01 접근 증명 스크린샷",
            "patient_records 행 수 쿼리 결과",
            "전체 공격 경로 문서화",
        ],
    ),
]


def generate_plan(
    operation_name: str,
    start_date: date,
    steps: List[KillChainStep],
) -> str:
    lines = [
        f"# 레드팀 작전 계획: {operation_name}",
        f"",
        f"**고객사**: MediCloud",
        f"**크라운 쥬얼**: DB-PROD-01 (patient_records 테이블)",
        f"**시작일**: {start_date}",
        f"",
        f"---",
        f"",
        f"## 킬 체인 7단계 계획",
        f"",
    ]

    current = start_date
    for step in steps:
        end = current + timedelta(days=step.duration_days - 1)
        lines += [
            f"### Step {step.step}: {step.name}",
            f"**기간**: {current} ~ {end} ({step.duration_days}일)",
            f"",
            f"**목표**:",
        ]
        for obj in step.objectives:
            lines.append(f"- {obj}")
        lines += ["", f"**기법**:"]
        for tech in step.techniques:
            lines.append(f"- {tech}")
        lines += ["", f"**ATT&CK 기법 ID**: {', '.join(step.att_ck_ids)}"]
        lines += ["", f"**산출물**:"]
        for d in step.deliverables:
            lines.append(f"- [ ] {d}")
        lines += ["", "---", ""]
        current = end + timedelta(days=1)

    total = sum(s.duration_days for s in steps)
    lines += [
        f"## 작전 요약",
        f"",
        f"- **총 기간**: {total}일",
        f"- **크라운 쥬얼 목표일**: {start_date + timedelta(days=total - 1)}",
        f"- **성공 기준**: patient_records 테이블 행 수 쿼리 실행 스크린샷",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MediCloud 레드팀 작전 계획 생성기")
    parser.add_argument("--name", default="Operation MediCloud", help="작전 이름")
    parser.add_argument("--start", default=str(date.today()), help="시작일 YYYY-MM-DD")
    parser.add_argument("--output", help="출력 파일 경로")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        start = date.fromisoformat(args.start)
    except ValueError:
        print(f"날짜 형식 오류: {args.start}", file=sys.stderr)
        sys.exit(1)

    plan = generate_plan(args.name, start, MEDICLOUD_PLAN)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(plan)
        print(f"작전 계획 저장됨: {args.output}")
    else:
        print(plan)


if __name__ == "__main__":
    main()
```

**실습 달성 체크포인트**:
```
[ ] 킬 체인 7단계 모두 포함
[ ] 각 단계에 ATT&CK 기법 ID 매핑
[ ] MediCloud 특수 제약(의료 장비 제외, DDoS 금지) 반영
[ ] 크라운 쥬얼(DB-PROD-01) 접근이 마지막 단계에 위치
[ ] 각 단계에 측정 가능한 산출물(Deliverable) 정의
```

---

## Docker 환경 설정

실습 환경을 Docker로 격리하여 구성합니다.

```dockerfile
# Dockerfile — 레드팀 보고서 실습 환경
FROM python:3.11-slim

WORKDIR /lab

# 시스템 패키지 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python 의존성
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 실습 파일 복사
COPY *.py ./

# 비루트 사용자 생성
RUN useradd -m -u 1000 student
USER student

CMD ["python3", "--version"]
```

```yaml
# docker-compose.yml
version: "3.9"
services:
  redteam-lab:
    build: .
    container_name: redteam_reporting_lab
    volumes:
      - ./output:/lab/output
    environment:
      - PYTHONDONTWRITEBYTECODE=1
      - PYTHONUNBUFFERED=1
    command: >
      sh -c "
        echo '=== 레드팀 보고서 실습 랩 시작 ===' &&
        python3 04_report_writing.py --demo --output /lab/output/report.md &&
        python3 02_operation_planning.py --name 'Operation Demo' --start 2024-01-01 --output /lab/output/timeline.md &&
        echo '생성된 파일:' &&
        ls /lab/output/
      "
```

```bash
# Docker 환경 실행
docker compose up --build

# 직접 실행
docker run --rm -v $(pwd)/output:/lab/output redteam-lab \
  python3 04_report_writing.py --demo --output /lab/output/report.md

# requirements.txt 내용
# (이 실습은 표준 라이브러리만 사용하므로 별도 패키지 불필요)
```

---

## 전체 실습 채점표

| 실습 | 항목 | 점수 |
|---|---|---|
| 실습 1 | ATT&CK 매핑 9개 이상 정답 | 30점 |
| 실습 1 | 모든 11개 정답 | 40점 |
| 실습 2 | CVSS 점수 적절히 배정 | 20점 |
| 실습 2 | 경영진 요약 비즈니스 언어 사용 | 20점 |
| 실습 2 | 실행 가능한 수정 권고사항 | 20점 |
| 실습 3 | 킬 체인 7단계 모두 포함 | 30점 |
| 실습 3 | 각 단계 ATT&CK 매핑 | 30점 |
| 실습 3 | 제약 조건 준수 | 10점 |

**80점 이상**: 레드팀 보고 전문가 수준  
**60~79점**: 실무 투입 가능 수준  
**60점 미만**: 이전 섹션 복습 후 재도전

---

<a name="english"></a>

# Red Team CTF Style Practice Lab

## About This Lab

This lab provides hands-on practice for the red team reporting concepts covered so far, in a CTF (Capture The Flag) style. Each exercise follows this structure:

```
Objective   — What you learn from this exercise
Scenario    — Real-world situation description
Hints       — Reference when stuck
Solution    — Completed answer
```

The goal is not to master tools, but to understand **"why this approach?"**

---

## Exercise 1: MITRE ATT&CK Technique Mapping

### Objective
Build the ability to read an attack scenario and map each action to MITRE ATT&CK technique IDs.

### Scenario: Hypothetical Incident "Project Neptune"

```
[Attack Log Summary]

Day 1 - 2024-03-01
  09:15 — Attacker collected executive email addresses from the company website
  14:30 — Attacker reviewed the technology stack from job postings

Day 3 - 2024-03-03
  10:02 — Email received with "Contract_Final.docm" attachment (Finance dept, Kim)
  10:47 — Recipient opened the file and enabled macros
  10:48 — cmd.exe spawned a PowerShell process
  10:49 — PowerShell attempted HTTPS connection to external IP (203.0.113.42)

Day 4 - 2024-03-04
  14:22 — New local admin account "svc_backup2" created
  14:25 — New scheduled task registered (runs C:\Temp\update.exe)
  15:10 — procdump.exe created lsass.dmp file

Day 5 - 2024-03-05
  09:30 — SERVER02 accessed via SMB
  09:35 — C:\Finance\Q4_Report.xlsx copied from SERVER02
  11:00 — Copied file uploaded to external cloud storage
```

### Hints

```
Hint 1: Email collection from website → T15xx series (Reconnaissance)
Hint 2: .docm macro attachment email → T1566 series
Hint 3: PowerShell execution → T1059 series
Hint 4: External IP connection → T1071 or T1102 series
Hint 5: Local admin account creation → T1136 series
Hint 6: Scheduled task registration → T1053 series
Hint 7: LSASS dump → T1003 series
Hint 8: SMB remote access → T1021 series
Hint 9: Cloud storage exfiltration → T1567 series
```

### Solution

```python
#!/usr/bin/env python3
"""Exercise 1 Solution: ATT&CK Mapping"""

from dataclasses import dataclass
from typing import List


@dataclass
class AttackEvent:
    timestamp: str
    action: str
    technique_id: str
    technique_name: str
    tactic: str


SOLUTION: List[AttackEvent] = [
    AttackEvent("Day1 09:15", "Collected executive emails from website",
                "T1591.002", "Gather Victim Org Information: Email Addresses", "Reconnaissance"),
    AttackEvent("Day1 14:30", "Reviewed tech stack from job postings",
                "T1591.004", "Gather Victim Org Information: Identify Roles", "Reconnaissance"),
    AttackEvent("Day3 10:02", ".docm attachment spearphishing email",
                "T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    AttackEvent("Day3 10:48", "cmd.exe spawned PowerShell process",
                "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    AttackEvent("Day3 10:49", "HTTPS C2 connection to external IP",
                "T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    AttackEvent("Day4 14:22", "Created new local admin account",
                "T1136.001", "Create Account: Local Account", "Persistence"),
    AttackEvent("Day4 14:25", "Registered malicious scheduled task",
                "T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence"),
    AttackEvent("Day4 15:10", "LSASS memory dump via procdump",
                "T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    AttackEvent("Day5 09:30", "Remote access to SERVER02 via SMB",
                "T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    AttackEvent("Day5 09:35", "Copied financial report file",
                "T1005", "Data from Local System", "Collection"),
    AttackEvent("Day5 11:00", "Uploaded file to external cloud storage",
                "T1567.002", "Exfiltration Over Web Service: Cloud Storage", "Exfiltration"),
]


def print_solution() -> None:
    print("=" * 75)
    print("Exercise 1 Solution: Project Neptune ATT&CK Mapping")
    print("=" * 75)
    print(f"{'Time':<15} {'Tactic':<25} {'Technique ID':<15} {'Technique Name':<35}")
    print("-" * 95)
    for event in SOLUTION:
        print(f"{event.timestamp:<15} {event.tactic:<25} {event.technique_id:<15} {event.technique_name:<35}")
    print(f"\n{len(SOLUTION)} events mapped in total.")


if __name__ == "__main__":
    print_solution()
```

**Scoring**:
- 9–11 correct: Excellent
- 6–8 correct: Good
- 5 or fewer: Review ATT&CK documentation

---

## Exercise 2: Red Team Report Writing

### Objective
Write an actual red team report section based on sample findings.

### Scenario: Hypothetical Company "CloudStore Inc." Red Team Results

```
[Finding Data]

Finding 1:
  System: web01.cloudstore.example.com
  Vulnerability: SQL Injection on login page
  Achieved: Full DB dump (150,000 users)
  Detected: No (no WAF)
  CVSS: ? (calculate)

Finding 2:
  System: admin.cloudstore.example.com
  Vulnerability: Default admin credentials (admin/admin123)
  Achieved: Full admin panel takeover
  Detected: No
  CVSS: ? (calculate)

Finding 3:
  System: Internal document server 192.168.10.50
  Vulnerability: Unpatched SMBGhost (CVE-2020-0796)
  Achieved: Remote code execution
  Detected: Yes (EDR alert, 4 hours later)
  CVSS: ? (calculate)
```

### Hints

```
CVSS calculation hints:
  Finding 1: SQL Injection → Attack Vector: Network, No Auth required, Confidentiality: High
             → CVSS ~9.8 (Critical)
  Finding 2: Default credentials → Network access, low complexity, full control
             → CVSS ~9.8 (Critical)
  Finding 3: SMBGhost → Remote code execution, no authentication required
             → CVSS ~10.0 (Critical)

Report hints:
  - Executive Summary: "150,000 customer records at risk" in business language
  - Each finding: Include attack path, evidence, and remediation recommendations
  - Priority: All Critical — immediate action required
```

### Solution

```python
#!/usr/bin/env python3
"""Exercise 2 Solution: CloudStore Inc. Report"""

import sys
from dataclasses import dataclass, field
from datetime import date
from typing import List


@dataclass
class Finding:
    fid: str
    title: str
    severity: str
    cvss: float
    system: str
    description: str
    path: str
    remediation: str

    def render(self) -> str:
        return (
            f"\n### {self.fid}: {self.title}\n\n"
            f"**Severity**: {self.severity} (CVSS: {self.cvss})\n"
            f"**System**: `{self.system}`\n\n"
            f"**Description**: {self.description}\n\n"
            f"**Attack Path**:\n```\n{self.path}\n```\n\n"
            f"**Remediation**: {self.remediation}\n"
        )


SAMPLE_FINDINGS: List[Finding] = [
    Finding(
        fid="F-001",
        title="SQL Injection Exposes Entire Customer Database",
        severity="Critical",
        cvss=9.8,
        system="web01.cloudstore.example.com",
        description=(
            "A SQL injection vulnerability exists in the username parameter of the login form. "
            "This was exploited to access the names, emails, and password hashes of 150,000 customers. "
            "No WAF was present, so the attack went undetected."
        ),
        path="Attacker → Login page → UNION-based SQL injection → Full users table dump",
        remediation=(
            "1. (Immediate) Take page offline or apply emergency WAF block rule\n"
            "2. (48 hours) Refactor code to use parameterized queries\n"
            "3. (1 week) Audit all input validation across the codebase\n"
            "4. (1 month) Deploy WAF with SQL injection rules"
        ),
    ),
    Finding(
        fid="F-002",
        title="Admin Panel Fully Accessible with Default Credentials",
        severity="Critical",
        cvss=9.8,
        system="admin.cloudstore.example.com",
        description=(
            "The admin panel is accessible with default credentials (admin/admin123). "
            "After login, full access to system settings, user data, and payment information was achieved."
        ),
        path="Attacker → /admin page → Default credential login → Full admin access",
        remediation=(
            "1. (Immediate) Change default password to a strong temporary password\n"
            "2. (24 hours) Apply IP whitelist to admin panel\n"
            "3. (1 week) Enforce MFA on admin accounts\n"
            "4. (2 weeks) Strengthen password policy (minimum 16 characters)"
        ),
    ),
    Finding(
        fid="F-003",
        title="SMBGhost Vulnerability Allows Remote Code Execution on Internal Server",
        severity="Critical",
        cvss=10.0,
        system="192.168.10.50 (internal document server)",
        description=(
            "CVE-2020-0796 (SMBGhost) is unpatched, allowing remote SYSTEM-level code execution. "
            "EDR alerted 4 hours later, but the filesystem was already compromised."
        ),
        path="Internal network access → SMBGhost exploit → SYSTEM RCE → Full server takeover",
        remediation=(
            "1. (Immediate) Apply KB4551762 patch\n"
            "2. (Immediate) Disable SMBv3.1.1 compression (temporary mitigation)\n"
            "3. (1 week) Tighten internal network SMB port (445) access controls\n"
            "4. (1 month) Establish a vulnerability management process"
        ),
    ),
]


def generate_report(findings: List[Finding]) -> str:
    critical = sum(1 for f in findings if f.severity == "Critical")
    lines = [
        "# CloudStore Inc. Red Team Penetration Test Report",
        f"**Date**: {date.today()}",
        "**Classification**: CONFIDENTIAL",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"The red team conducted a penetration test of CloudStore Inc.'s external and internal systems.",
        f"A total of **{len(findings)}** critical security vulnerabilities were found,",
        f"all of which are rated **Critical** and require immediate action.",
        "",
        "**Key Risks**:",
        "- ~150,000 customer records may be exposed to external attackers.",
        "- The entire admin system is accessible with a trivial default password.",
        "- An internal server is exploitable via a vulnerability known since 2020.",
        "",
        "**Potential Consequences Without Immediate Action**:",
        "- GDPR / data protection regulation violations",
        "- Customer trust erosion and service downtime",
        "- Risk of ransomware attack",
        "",
        "---",
        "",
        "## Finding Summary",
        "",
        "| ID | Title | Severity | CVSS |",
        "|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.fid} | {f.title[:40]} | {f.severity} | {f.cvss} |")
    lines += ["", "---", "", "## Finding Details"]
    for f in findings:
        lines.append(f.render())
    return "\n".join(lines)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else None
    report = generate_report(SAMPLE_FINDINGS)
    if out:
        with open(out, "w", encoding="utf-8") as fp:
            fp.write(report)
        print(f"Report saved: {out}")
    else:
        print(report)
```

---

## Exercise 3: Kill Chain-Based Attack Simulation Planning

### Objective
Create a complete red team operation plan covering all 7 kill chain stages under the given constraints.

### Scenario: "MediCloud" Red Team Engagement

```
Client: MediCloud (cloud-based medical records service)
Scope: External web services + internal data server
Crown Jewel: Patient medical records database (DB-PROD-01)
Duration: 21 days
Constraints: Exclude medical device systems; no DDoS
Objective: Confirm whether patient_records table in DB-PROD-01 can be accessed
```

### Hints

```
Stage-by-stage hints:

Stage 1 - Reconnaissance:
  OSINT: LinkedIn, company website, Shodan
  Goal: Employee emails, technology stack, open ports

Stage 2 - Weaponization:
  Lure: "Medical software update notification"
  Payload: Office macro or LNK file

Stage 3 - Delivery:
  Spearphishing → Target IT admins or developers
  Subject: "Urgent Security Patch Required"

Stage 4 - Exploitation:
  Macro execution → PowerShell implant

Stage 5 - Installation:
  Registry or scheduled task persistence

Stage 6 - C2:
  HTTPS-based C2 (ports 80/443)
  Beacon interval: 60–300 seconds

Stage 7 - Actions on Objectives:
  Internal recon → Identify DB-PROD-01
  Credential theft → DB access
```

The solution code is identical in structure to the Korean version above — refer to the `MEDICLOUD_PLAN` dataclass implementation.

---

## Docker Environment Setup

```dockerfile
# Dockerfile — Red Team Reporting Lab
FROM python:3.11-slim
WORKDIR /lab
RUN apt-get update && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*
COPY *.py ./
RUN useradd -m -u 1000 student && chown -R student:student /lab
USER student
CMD ["python3", "--version"]
```

```yaml
# docker-compose.yml
version: "3.9"
services:
  redteam-lab:
    build: .
    container_name: redteam_reporting_lab
    volumes:
      - ./output:/lab/output
    command: >
      sh -c "
        echo '=== Red Team Reporting Lab Started ===' &&
        python3 04_report_writing.py --demo --output /lab/output/report.md &&
        python3 02_operation_planning.py --name 'Operation Demo' --start 2024-01-01 --output /lab/output/timeline.md &&
        echo 'Generated files:' &&
        ls /lab/output/
      "
```

```bash
# Run with Docker
docker compose up --build

# Run directly
docker run --rm -v $(pwd)/output:/lab/output redteam-lab \
  python3 04_report_writing.py --demo --output /lab/output/report.md
```

---

## Complete Lab Scoring Sheet

| Exercise | Item | Points |
|---|---|---|
| Exercise 1 | 9+ correct ATT&CK mappings | 30 pts |
| Exercise 1 | All 11 correct | 40 pts |
| Exercise 2 | CVSS scores correctly assigned | 20 pts |
| Exercise 2 | Executive Summary in business language | 20 pts |
| Exercise 2 | Actionable remediation recommendations | 20 pts |
| Exercise 3 | All 7 kill chain stages included | 30 pts |
| Exercise 3 | ATT&CK mapping per stage | 30 pts |
| Exercise 3 | Constraints respected | 10 pts |

**80+**: Red Team Reporting Expert level  
**60–79**: Ready for real-world deployment  
**Below 60**: Review previous sections and retry
