> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 리포팅 — 결과 분석·익스플로잇 체인 문서화·경영진 보고서

## 0. 초보자를 위한 개념 이해

### 레드팀 리포팅이란?

**레드팀 리포팅**은 침투 테스트나 레드팀 작전 결과를 고객(조직)에게 전달하는 공식 문서 작성 과정입니다.

```
왜 리포팅이 중요한가:
  아무리 뛰어난 해킹 기술도,
  결과를 제대로 전달하지 못하면 → 가치 없음

  좋은 리포트 = 고객이 취약점을 이해하고 수정할 수 있도록 돕는 것
```

**두 가지 독자를 위한 두 가지 섹션:**
```
경영진 섹션:
  대상: CISO, CEO, 이사회
  내용: 비즈니스 위험, 전체 보안 점수, 즉각 대응 필요 사항
  언어: 기술 용어 최소화, 비즈니스 영향 중심
  길이: 1~2페이지

기술 섹션:
  대상: 보안팀, 개발팀, IT팀
  내용: 취약점 세부 사항, 재현 방법, 코드 예시
  언어: 기술적으로 정확하게
  길이: 상세하게
```

### 좋은 리포트 vs 나쁜 리포트

```
나쁜 리포트:
  "취약점 발견: SQL 인젝션"
  → 어디서? 어떻게? 영향은? 수정 방법은?
  → 아무것도 모름

좋은 리포트:
  취약점: SQL 인젝션
  위치: https://example.com/search?q=
  심각도: 높음 (CVSS 9.8)
  영향: 전체 고객 데이터베이스 접근, 인증 우회 가능
  재현 방법:
    1. https://example.com/search?q=' OR '1'='1 접속
    2. 모든 사용자 목록 노출 확인
  증거: [스크린샷]
  수정 방법: 파라미터화 쿼리 사용 (예시 코드 포함)
  수정 기한 권고: 즉시 (Critical)
```

### CVSS 점수 이해하기

**CVSS(Common Vulnerability Scoring System)**는 취약점의 심각도를 0~10점으로 수치화하는 표준 체계입니다.

```
CVSS v3.1 점수:
  0.0       : 없음
  0.1~3.9   : 낮음 (Low)
  4.0~6.9   : 중간 (Medium)
  7.0~8.9   : 높음 (High)
  9.0~10.0  : 치명적 (Critical)

주요 계산 요소:
  공격 벡터 (네트워크 > 인접 > 로컬 > 물리)
  공격 복잡도 (낮음 > 높음)
  필요 권한 (없음 > 낮음 > 높음)
  사용자 상호작용 (없음 > 필요)
  기밀성/무결성/가용성 영향 (높음/낮음/없음)

예시:
  원격 코드 실행, 인증 불필요 → CVSS 10.0 (치명적)
  로컬 정보 노출, 로그인 필요 → CVSS 3.5 (낮음)
```

---

## 1. 레드팀 보고서 구조

```
레드팀 리포트
    │
    ├── 경영진 요약 (Executive Summary)
    │     - 전체 보안 수준 평가 (등급)
    │     - 핵심 위험 사항 3~5개
    │     - 즉각 조치 권고사항
    │
    ├── 기술 상세 (Technical Details)
    │     - 공격 타임라인
    │     - 익스플로잇 체인 다이어그램
    │     - 발견된 취약점 목록 (CVSS)
    │     - PoC 스크린샷·코드
    │
    └── 개선 권고사항 (Recommendations)
          - 즉각 조치 (Critical/High)
          - 단기 계획 (Medium)
          - 장기 로드맵 (Low)
```

---

## 2. 레드팀 결과 집계 CLI

```python
#!/usr/bin/env python3
"""레드팀 결과 집계 — 취약점 목록에서 리포트 자동 생성."""

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


CVSS_SEVERITY = {
    (9.0, 10.0): "Critical",
    (7.0, 8.9): "High",
    (4.0, 6.9): "Medium",
    (0.1, 3.9): "Low",
    (0.0, 0.0): "Informational",
}

MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Impact",
]


def cvss_to_severity(score: float) -> str:
    for (low, high), label in CVSS_SEVERITY.items():
        if low <= score <= high:
            return label
    return "Unknown"


@dataclass
class Finding:
    id: str
    title: str
    cvss: float
    tactic: str
    technique_id: str
    affected_systems: list[str]
    description: str
    evidence: str
    remediation: str
    severity: str = field(init=False)

    def __post_init__(self) -> None:
        self.severity = cvss_to_severity(self.cvss)


def load_findings(findings_file: Path) -> list[Finding]:
    data = json.loads(findings_file.read_text())
    return [Finding(**item) for item in data]


def generate_executive_summary(findings: list[Finding]) -> str:
    severity_counts = Counter(f.severity for f in findings)
    total = len(findings)

    lines = [
        "## 경영진 요약",
        "",
        f"**평가 기간**: {datetime.now().strftime('%Y-%m-%d')} 기준",
        f"**총 발견 사항**: {total}개",
        "",
        "### 심각도별 분류",
    ]

    for severity in ["Critical", "High", "Medium", "Low", "Informational"]:
        count = severity_counts.get(severity, 0)
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
                "Low": "🔵", "Informational": "⚪"}.get(severity, "")
        lines.append(f"- **{severity}**: {count}개")

    # 최고 위험 발견 사항
    critical_high = [f for f in findings if f.severity in ("Critical", "High")]
    critical_high.sort(key=lambda x: x.cvss, reverse=True)

    if critical_high:
        lines += [
            "",
            "### 핵심 위험 사항",
        ]
        for f in critical_high[:5]:
            lines.append(f"- **[{f.severity} | CVSS {f.cvss}]** {f.title}")
            lines.append(f"  - 영향 시스템: {', '.join(f.affected_systems[:3])}")

    # 전체 보안 등급
    if severity_counts.get("Critical", 0) > 0:
        grade = "F (심각)"
    elif severity_counts.get("High", 0) > 2:
        grade = "D (취약)"
    elif severity_counts.get("High", 0) > 0:
        grade = "C (개선 필요)"
    elif severity_counts.get("Medium", 0) > 3:
        grade = "B (보통)"
    else:
        grade = "A (양호)"

    lines.insert(3, f"**전체 보안 등급**: {grade}")

    return "\n".join(lines)


def generate_attack_timeline(findings: list[Finding]) -> str:
    tactic_order = {t: i for i, t in enumerate(MITRE_TACTICS)}
    sorted_findings = sorted(
        findings,
        key=lambda f: tactic_order.get(f.tactic, 99),
    )

    lines = ["## 공격 타임라인 (ATT&CK 전술 순)", ""]
    tactic_groups: dict[str, list[Finding]] = defaultdict(list)
    for f in sorted_findings:
        tactic_groups[f.tactic].append(f)

    for tactic in MITRE_TACTICS:
        group = tactic_groups.get(tactic, [])
        if group:
            lines.append(f"### {tactic}")
            for f in group:
                lines.append(f"- [{f.technique_id}] **{f.title}** (CVSS {f.cvss})")
                lines.append(f"  - {f.description[:100]}...")
            lines.append("")

    return "\n".join(lines)


def generate_remediation_plan(findings: list[Finding]) -> str:
    urgent = [f for f in findings if f.severity in ("Critical", "High")]
    medium = [f for f in findings if f.severity == "Medium"]
    low = [f for f in findings if f.severity in ("Low", "Informational")]

    lines = ["## 개선 권고사항", ""]

    if urgent:
        lines.append("### 즉각 조치 (48시간 내)")
        for f in sorted(urgent, key=lambda x: x.cvss, reverse=True):
            lines.append(f"- **{f.title}** [CVSS {f.cvss}]")
            lines.append(f"  - {f.remediation}")
        lines.append("")

    if medium:
        lines.append("### 단기 계획 (30일 내)")
        for f in medium:
            lines.append(f"- {f.title}: {f.remediation}")
        lines.append("")

    if low:
        lines.append("### 장기 로드맵 (90일 내)")
        for f in low:
            lines.append(f"- {f.title}")

    return "\n".join(lines)


def generate_full_report(findings: list[Finding], output: Path) -> None:
    sections = [
        f"# 레드팀 평가 보고서\n\n**생성일**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        generate_executive_summary(findings),
        generate_attack_timeline(findings),
        generate_remediation_plan(findings),
    ]

    report = "\n\n---\n\n".join(sections)
    output.write_text(report, encoding="utf-8")
    print(f"[+] 보고서 생성: {output} ({len(report)}자)")


def create_sample_findings(output: Path) -> None:
    """샘플 취약점 데이터 생성."""
    samples = [
        {
            "id": "RT-001",
            "title": "초기 접근 — VPN 기본 자격증명",
            "cvss": 9.8,
            "tactic": "Initial Access",
            "technique_id": "T1078",
            "affected_systems": ["vpn.example.com"],
            "description": "VPN 게이트웨이에서 기본 관리자 자격증명 발견",
            "evidence": "admin:admin123 로그인 성공",
            "remediation": "즉시 패스워드 변경, MFA 강제 적용",
        },
        {
            "id": "RT-002",
            "title": "내부망 횡이동 — PtH 공격",
            "cvss": 8.5,
            "tactic": "Lateral Movement",
            "technique_id": "T1550.002",
            "affected_systems": ["DC01", "FILE-SERVER-01", "HR-PC-05"],
            "description": "NTLM 해시로 도메인 내 횡이동 성공",
            "evidence": "mimikatz sekurlsa::pth 실행 성공",
            "remediation": "Credential Guard 활성화, NTLM 비활성화",
        },
        {
            "id": "RT-003",
            "title": "도메인 어드민 획득 — Kerberoasting",
            "cvss": 9.0,
            "tactic": "Credential Access",
            "technique_id": "T1558.003",
            "affected_systems": ["CORP\\svc_backup"],
            "description": "서비스 계정 SPN에서 TGS 요청 후 오프라인 크랙",
            "evidence": "Hashcat으로 48시간 내 패스워드 크랙",
            "remediation": "서비스 계정 패스워드 복잡도 강화, 관리형 서비스 계정(gMSA) 사용",
        },
        {
            "id": "RT-004",
            "title": "데이터 유출 — S3 공개 버킷",
            "cvss": 7.5,
            "tactic": "Exfiltration",
            "technique_id": "T1567",
            "affected_systems": ["s3://company-backup-2024"],
            "description": "공개 설정된 S3 버킷에서 고객 데이터 접근 가능",
            "evidence": "aws s3 ls s3://company-backup-2024 (인증 없이 접근)",
            "remediation": "S3 Block Public Access 활성화, 버킷 정책 검토",
        },
        {
            "id": "RT-005",
            "title": "Jenkins 취약한 설정",
            "cvss": 5.3,
            "tactic": "Discovery",
            "technique_id": "T1082",
            "affected_systems": ["ci.internal.example.com"],
            "description": "Jenkins 관리 콘솔 인증 없이 접근 가능",
            "evidence": "/script 경로로 Groovy 코드 실행 시도",
            "remediation": "Jenkins 접근 제어 강화, 내부망 격리",
        },
    ]
    output.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"[+] 샘플 데이터: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="레드팀 보고서 생성기")
    sub = parser.add_subparsers(dest="cmd", required=True)

    report_p = sub.add_parser("report", help="보고서 생성")
    report_p.add_argument("findings", type=Path, help="취약점 JSON 파일")
    report_p.add_argument("-o", "--output", type=Path, default=Path("redteam_report.md"))

    sample_p = sub.add_parser("sample", help="샘플 취약점 데이터 생성")
    sample_p.add_argument("-o", "--output", type=Path, default=Path("findings_sample.json"))

    summary_p = sub.add_parser("summary", help="요약만 출력")
    summary_p.add_argument("findings", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "report":
            findings = load_findings(args.findings)
            generate_full_report(findings, args.output)
        case "sample":
            create_sample_findings(args.output)
        case "summary":
            findings = load_findings(args.findings)
            print(generate_executive_summary(findings))


if __name__ == "__main__":
    main()
```

---

## 3. 익스플로잇 체인 문서화

```python
#!/usr/bin/env python3
"""익스플로잇 체인 다이어그램 생성 — Mermaid flowchart 자동 생성."""

import argparse
import json
from pathlib import Path


def findings_to_mermaid(findings: list[dict]) -> str:
    """취약점 목록에서 Mermaid 공격 체인 다이어그램 생성."""
    from collections import defaultdict

    tactic_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Impact",
    ]

    tactic_map: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        tactic_map[f["tactic"]].append(f)

    lines = ["flowchart TD"]
    prev_node = None

    for tactic in tactic_order:
        group = tactic_map.get(tactic, [])
        if not group:
            continue

        for finding in group:
            node_id = finding["id"].replace("-", "_")
            severity = finding.get("severity", "Medium")
            style = {
                "Critical": ":::critical",
                "High": ":::high",
                "Medium": ":::medium",
                "Low": ":::low",
            }.get(severity, "")

            label = f"{finding['id']}: {finding['title'][:40]}"
            lines.append(f'    {node_id}["{label}\\n{tactic}"]' + style)

            if prev_node:
                lines.append(f"    {prev_node} --> {node_id}")
            prev_node = node_id

    lines += [
        "    classDef critical fill:#ff4444,color:#fff",
        "    classDef high fill:#ff8800,color:#fff",
        "    classDef medium fill:#ffcc00,color:#000",
        "    classDef low fill:#4488ff,color:#fff",
    ]

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="익스플로잇 체인 다이어그램")
    parser.add_argument("findings", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("chain.mmd"))
    args = parser.parse_args()

    data = json.loads(args.findings.read_text())
    diagram = findings_to_mermaid(data)
    args.output.write_text(diagram)
    print(f"[+] Mermaid 다이어그램: {args.output}")
    print("\n렌더링: https://mermaid.live 에 붙여넣기")


if __name__ == "__main__":
    main()
```

---

## 4. 레드팀 리포트 품질 체크리스트

| 항목 | 확인 |
|------|------|
| 모든 발견 사항에 CVSS 점수 포함 | |
| ATT&CK 기법 ID (Txx.xxx) 매핑 | |
| 재현 가능한 PoC 포함 | |
| 영향 받는 시스템 명시 | |
| 스크린샷/증거 첨부 | |
| 구체적 수정 방법 제시 | |
| 경영진 요약 (기술 용어 최소화) | |
| 공격 타임라인 포함 | |
| 탐지 가능성 평가 | |
| 비즈니스 영향 분석 | |

---

<!-- detect-validate-17 -->
## 레드팀 리포트의 검증과 증거 무결성

이 문서는 리포팅을 다루므로, 여기서는 *무엇을 보고하는가*를 넘어 **각 발견이 재현 가능한가**와 **증거가 변조 없이 보존됐는가**를 검증하는 데 집중한다(섹션 75 와 상호보완). 검증 불가한 주장은 보고서 신뢰를 무너뜨린다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 보고 요소 | 검증 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 발견(취약점) | 재현 가능한가? | PoC 재현 단계·성공률 | 일회성/환경의존 주장 |
| 익스플로잇 체인 | 각 단계가 입증되나? | 단계별 증거·타임스탬프 | 비약된 인과 |
| 영향도 | 과대/과소 아닌가? | 도달성·자산가치 근거 | CVSS 단독 과신 |
| 증거 | 변조 없는가? | 해시 매니페스트 검증 | 출처/체인 누락 |

### 방어 검증 (직접 확인)

```bash
# 증거 무결성: 산출물 해시를 고정해 보고서 PoC 의 재현성·무결성 보장(소유 데이터)
sha256sum evidence/*.pcap evidence/*.log evidence/*.png > evidence/MANIFEST.sha256 2>/dev/null
sha256sum -c evidence/MANIFEST.sha256        # 변조 없으면 전부 OK
# 각 발견은 독립 환경에서 PoC 재현 단계를 다시 실행해 성공해야 '검증됨'으로 보고
```

> 보고와 증거 취급은 **승인된 교전 범위·RoE** 안에서만. 보고서의 가치는 화려한 발견이 아니라 **재현 가능성과 증거 무결성**이다 — 발견을 독립 재현하고 증거 해시를 검증해 신뢰를 확보한다([[75_Red_Team_Reporting]], [[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- ATT&CK 매핑·재현 증거·탐지 델타가 표준 — 주장마다 아티팩트·UTC 타임스탬프. 검증: 파인딩이 재현 절차로 뒷받침되는가([[75_Red_Team_Reporting]])
- AI 보조 보고 — 사실오류·과장 없이 증거 근거인지 사람검증

---

<a name="english"></a>

# Red Team Reporting — Results Analysis, Exploit Chain Documentation, Executive Reports

## 1. Red Team Report Structure

```
Red Team Assessment Report Structure:

1. Executive Summary (2-3 pages)
   - Overall risk assessment
   - Key findings summary
   - Business impact
   - Priority recommendations

2. Methodology
   - Scope and objectives
   - Timeline
   - Tools used
   - Attack scenarios tested

3. Findings
   - Attack narrative (chronological)
   - Each vulnerability detailed
   - Exploit chains documented
   - ATT&CK technique mapping

4. Evidence
   - Screenshots
   - Log excerpts
   - PoC code
   - Network captures

5. Recommendations
   - Prioritized remediation list
   - 30/60/90 day roadmap
   - Quick wins vs long-term fixes

6. Appendices
   - Complete findings list
   - Tool output
   - IOCs generated
```

---

## 2. Exploit Chain Documentation

```markdown
## Attack Chain: Initial Access → Domain Compromise

### Summary
Starting from a phishing email, attacker gained domain admin
privileges within 4 hours using a 5-step attack chain.

### Attack Timeline

**Step 1: Initial Access (T1566.001 - Spear Phishing)**
- Time: 2024-01-15 09:23 UTC
- Vector: Email with malicious macro document
- Target: finance@target.com
- Result: Code execution as user "jsmith"
- Evidence: [Screenshot 1]

**Step 2: Persistence (T1053.005 - Scheduled Task)**
- Time: 2024-01-15 09:25 UTC
- Command: `schtasks /create /tn "WindowsUpdate" /tr "C:\temp\beacon.exe"`
- Result: Persistence established
- Detection: No alert triggered

**Step 3: Credential Dumping (T1003.001 - LSASS)**
- Time: 2024-01-15 09:31 UTC
- Tool: Mimikatz via process injection
- Result: 3 domain accounts harvested including IT admin
- Credentials obtained: IT-admin NTLM hash

**Step 4: Lateral Movement (T1021.002 - SMB)**
- Time: 2024-01-15 10:15 UTC
- Method: Pass-the-Hash to file server FS01
- Target: \\FS01\ADMIN$
- Result: SYSTEM access on FS01

**Step 5: Domain Privilege Escalation (T1078.002 - Domain Account)**
- Time: 2024-01-15 11:45 UTC
- Method: DCSync attack via Domain Replication rights
- Result: Domain Administrator hash extracted
- Impact: Complete Active Directory compromise
```

---

## 3. Executive Summary Writing

```
Executive Summary Template:

RISK RATING: CRITICAL

During the [DATE] red team assessment of [COMPANY], our team successfully:
- Gained initial access within [X] hours
- Escalated to Domain Administrator privileges
- Accessed [sensitive data/systems]
- Maintained undetected presence for [X] days

KEY FINDINGS:
  1. Phishing resistance is insufficient — 34% click rate
  2. Credential theft detection gap — no SIEM alert triggered
  3. Lateral movement unchecked — moved across 15 systems undetected
  4. Critical data accessible without MFA — [database/system]

BUSINESS IMPACT:
  If this were a real attack:
  - Customer PII exposure: ~50,000 records
  - Financial fraud risk: Wire transfer approval bypassed
  - Regulatory penalties: GDPR/PCI DSS non-compliance

IMMEDIATE ACTIONS REQUIRED:
  1. Deploy EDR with behavioral detection
  2. Enable MFA on all privileged accounts
  3. Implement network segmentation
  4. Conduct phishing awareness training
```

---

## 4. AI-Assisted Report Generation

```python
import anthropic

client = anthropic.Anthropic()

def generate_finding_writeup(finding_data: dict) -> str:
    """Generate professional finding writeup from raw data"""
    
    prompt = f"""
Write a professional penetration testing finding based on the following data.
Format as a standalone finding section for inclusion in a security report.

Finding Data:
- Title: {finding_data.get('title')}
- Severity: {finding_data.get('severity')}
- CVSS Score: {finding_data.get('cvss')}
- Location: {finding_data.get('location')}
- Technical Details: {finding_data.get('technical_details')}
- Evidence: {finding_data.get('evidence_description')}

Write the finding with:
1. Clear description (technical but readable)
2. Business impact statement
3. Step-by-step reproduction
4. Specific remediation recommendation
5. References (OWASP, CWE, CVE if applicable)

Tone: Professional, objective, constructive
"""
    
    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return resp.content[0].text

def generate_executive_summary(findings: list, engagement_info: dict) -> str:
    """Generate executive summary from findings"""
    
    critical = [f for f in findings if f.get('severity') == 'Critical']
    high = [f for f in findings if f.get('severity') == 'High']
    
    prompt = f"""
Write an executive summary for a red team assessment report.

Engagement: {engagement_info.get('company')} - {engagement_info.get('dates')}
Scope: {engagement_info.get('scope')}
Objectives: {engagement_info.get('objectives')}

Key Statistics:
- Critical findings: {len(critical)}
- High findings: {len(high)}
- Total findings: {len(findings)}
- Objectives achieved: {engagement_info.get('objectives_achieved')}

Critical Findings:
{chr(10).join([f"- {f['title']}: {f.get('impact', '')}" for f in critical])}

Write 2-3 pages max. Non-technical audience. Focus on business risk.
"""
    
    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=3000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return resp.content[0].text
```

---

## 5. Report Quality Checklist

| Checklist Item | Status |
|---------------|--------|
| ATT&CK technique ID mapping (Txx.xxx) | |
| Reproducible PoC included | |
| Affected systems specified | |
| Screenshots/evidence attached | |
| Specific remediation methods provided | |
| Executive summary (minimize technical jargon) | |
| Attack timeline included | |
| Detectability assessment | |
| Business impact analysis | |

<!-- detect-validate-17 -->
## Validation and Evidence Integrity of Red Team Reports

Since this document covers reporting, here we go beyond *what to report* to verify **whether each finding is reproducible** and **whether evidence is preserved without tampering** (complements section 75). Unverifiable claims destroy report credibility.

### Attack -> Layer -> Control (defender) -> Detection signal

| Report element | Validation question | Measured signal | Pitfall |
|---|---|---|---|
| Finding (vuln) | Is it reproducible? | PoC repro steps, success rate | One-off/environment-dependent claims |
| Exploit chain | Is each step proven? | Per-step evidence, timestamps | Hand-waved causality |
| Impact | Not over/under-stated? | Reachability, asset-value basis | Over-trusting CVSS alone |
| Evidence | Untampered? | Hash manifest verification | Missing provenance/chain |

### Defense validation (verify directly)

```bash
# Evidence integrity: pin artifact hashes to guarantee PoC reproducibility/integrity (own data)
sha256sum evidence/*.pcap evidence/*.log evidence/*.png > evidence/MANIFEST.sha256 2>/dev/null
sha256sum -c evidence/MANIFEST.sha256        # all OK if untampered
# Each finding should be re-run via its PoC steps in an independent environment to be reported as 'validated'
```

> Handle reporting and evidence only within **the authorized engagement scope / RoE**. A report's value is not flashy findings but **reproducibility and evidence integrity** — independently reproduce findings and verify evidence hashes to earn trust ([[75_Red_Team_Reporting]], [[68_Purple_Team]]).
