> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# 웹 보안 도구와 자동화

Burp Suite, OWASP ZAP, ffuf, SQLMap 등 웹 보안 실무에서 가장 많이 쓰이는 도구들의 핵심 기능과 고급 옵션을 정리한다. 마지막 섹션에서는 Python으로 스캔 결과를 파싱해 HTML 보고서를 자동 생성하는 CLI 도구를 구현한다.

---

## 1. Burp Suite 핵심 기능

### 1.1 프록시 설정

```
브라우저 HTTP 프록시: 127.0.0.1:8080
CA 인증서 설치: http://burpsuite (브라우저에서 접속) → 다운로드
```

**FoxyProxy(Firefox 확장) 설정값**

| 항목 | 값 |
|------|----|
| Proxy type | HTTP |
| IP/Host | 127.0.0.1 |
| Port | 8080 |

### 1.2 Intruder — 자동화된 페이로드 공격

Intruder는 요청의 특정 위치에 페이로드를 삽입해 반복 공격을 수행한다.

**Attack Type 선택**

| 타입 | 설명 | 사용 시나리오 |
|------|------|--------------|
| Sniper | 위치 1개씩 순서대로 | 단일 파라미터 브루트포스 |
| Battering ram | 모든 위치에 동일 페이로드 | username=admin&password=admin |
| Pitchfork | 위치별 페이로드 1:1 대응 | credential stuffing |
| Cluster bomb | 모든 조합 (카르테시안 곱) | 아이디+패스워드 조합 |

**Payload 설정 예시 (비밀번호 브루트포스)**

```
Position: §password§
Payload type: Simple list
Payload list: /usr/share/wordlists/rockyou.txt

Grep-Match 설정:
  - "incorrect password"  → 실패 응답 식별
  - "Welcome back"        → 성공 응답 식별
```

### 1.3 Repeater — 수동 요청 조작

```
단축키: Ctrl+R (요청을 Repeater로 전송)
용도: SQL 인젝션, XSS, IDOR 수동 검증

Send 전략:
  1. 원본 요청 전송 → 정상 응답 기록
  2. 파라미터 조작 → 응답 비교
  3. 에러 메시지, 응답 크기 차이 분석
```

**유용한 Repeater 팁**

```http
# IDOR 확인 예시
GET /api/users/1001/profile HTTP/1.1
Host: target.com
Authorization: Bearer <victim_token>

# → 200 OK 시 IDOR 존재
# → 403 Forbidden 시 접근 제어 적용됨
```

### 1.4 Scanner (Pro 버전) — 자동 취약점 스캐너

```
Active Scan: 실제 페이로드 전송 (서버에 영향)
Passive Scan: 트래픽 분석만 (서버에 영향 없음)

스캔 항목:
  - SQL Injection
  - XSS (Reflected / Stored / DOM)
  - SSRF, XXE, Path Traversal
  - Information Disclosure
  - Clickjacking, CORS Misconfiguration
```

**커뮤니티 버전 대안 — Burp Extensions (BApp Store)**

| 확장 | 기능 |
|------|------|
| Param Miner | 숨겨진 파라미터 발견 |
| JS Link Finder | JS에서 엔드포인트 추출 |
| Turbo Intruder | 고속 Intruder (Python 스크립트) |
| AuthMatrix | 권한 매핑 자동화 |
| Retire.js | 취약한 JS 라이브러리 탐지 |

---

## 2. OWASP ZAP 자동 스캔 설정

### 2.1 CLI로 자동 스캔

```bash
# 설치 (Docker)
docker pull zaproxy/zap-stable

# 기본 자동 스캔
docker run --rm zaproxy/zap-stable zap-baseline.py \
  -t https://target.com \
  -r zap_report.html

# 전체 스캔 (더 공격적)
docker run --rm zaproxy/zap-stable zap-full-scan.py \
  -t https://target.com \
  -r zap_full_report.html \
  -J zap_report.json

# API 스캔 (OpenAPI 명세 활용)
docker run --rm zaproxy/zap-stable zap-api-scan.py \
  -t https://target.com/swagger.json \
  -f openapi \
  -r api_scan_report.html
```

### 2.2 ZAP Python API

```python
from zapv2 import ZAPv2

zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8090'})

# 스파이더링 시작
target = "http://target.com"
zap.spider.scan(target)

# 액티브 스캔
scan_id = zap.ascan.scan(target)

# 알림 가져오기
alerts = zap.core.alerts(baseurl=target)
for alert in alerts:
    print(f"[{alert['risk']}] {alert['name']}: {alert['url']}")
```

### 2.3 ZAP 자동화 프레임워크 (YAML)

```yaml
# zap_automation.yaml
env:
  contexts:
    - name: "target"
      urls:
        - "https://target.com"
  parameters:
    failOnError: true

jobs:
  - type: spider
    parameters:
      context: "target"
      maxDuration: 5

  - type: activeScan
    parameters:
      context: "target"
      policy: "Default Policy"

  - type: report
    parameters:
      template: "risk-confidence-html"
      reportFile: "/output/report.html"
```

```bash
docker run --rm -v $(pwd):/output zaproxy/zap-stable \
  zap.sh -cmd -autorun /output/zap_automation.yaml
```

---

## 3. ffuf / gobuster 디렉토리·파라미터 퍼징

### 3.1 ffuf (Fuzz Faster U Fool)

```bash
# 디렉토리 퍼징
ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,302,403 \
     -t 50

# 파라미터 발견 (GET)
ffuf -w params.txt \
     -u "https://target.com/search?FUZZ=test" \
     -fw 42   # 단어 수 42개인 응답 필터링

# POST 데이터 퍼징
ffuf -w /path/to/passwords.txt \
     -u https://target.com/login \
     -X POST \
     -d "username=admin&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fc 200 \
     -fs 1234

# 서브도메인 열거
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u https://FUZZ.target.com \
     -mc 200,301

# 다중 워드리스트 (Pitchfork)
ffuf -w users.txt:USER -w passwords.txt:PASS \
     -u https://target.com/login \
     -X POST \
     -d "user=USER&pass=PASS" \
     -mode pitchfork

# 결과 저장
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -o results.json -of json
```

### 3.2 gobuster

```bash
# 디렉토리 모드
gobuster dir \
  -u https://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak \
  -t 30 \
  -o gobuster_out.txt

# DNS 서브도메인 모드
gobuster dns \
  -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50

# VHOST 모드
gobuster vhost \
  -u https://target.com \
  -w subdomains.txt \
  --append-domain
```

---

## 4. SQLMap 고급 옵션

### 4.1 기본 사용법

```bash
# GET 파라미터 탐지
sqlmap -u "https://target.com/item?id=1" --dbs

# POST 요청
sqlmap -u "https://target.com/login" \
       --data="username=admin&password=test" \
       --dbs

# Burp Suite 요청 파일 활용
sqlmap -r request.txt --dbs
```

### 4.2 고급 옵션

```bash
# --level: 테스트 깊이 (1-5, 기본 1)
# --risk: 위험도 (1-3, 기본 1, 3은 OR/AND 기반 time-blind)
sqlmap -u "https://target.com/item?id=1" \
       --level=5 \
       --risk=3 \
       --dbs

# --tamper: WAF 우회 스크립트
sqlmap -u "https://target.com/item?id=1" \
       --tamper=space2comment,randomcase,charunicodeescape \
       --dbs

# 주요 tamper 스크립트
# space2comment    : 공백 → /**/
# randomcase       : 대소문자 무작위화
# charunicodeescape: 유니코드 이스케이프
# between          : > 연산자 → BETWEEN
# equaltolike      : = 연산자 → LIKE
# hex2char         : 문자열 → CHAR()
# apostrophemask   : ' → %EF%BC%87

# 특정 DB, 테이블, 컬럼 덤프
sqlmap -u "https://target.com/item?id=1" \
       -D mydb -T users -C username,password \
       --dump

# 쿠키 기반 세션
sqlmap -u "https://target.com/profile" \
       --cookie="PHPSESSID=abcdef1234" \
       --dbs

# 운영체제 셸 시도 (적절한 권한 필요)
sqlmap -u "https://target.com/item?id=1" \
       --os-shell

# HTTP 헤더 인젝션
sqlmap -u "https://target.com/" \
       -p "X-Forwarded-For" \
       --headers="X-Forwarded-For: 1*"
```

### 4.3 WAF 우회 전략

| 전략 | SQLMap 옵션 | 설명 |
|------|-------------|------|
| 인코딩 | `--tamper=charunicodeescape` | 유니코드 우회 |
| 주석 | `--tamper=space2comment` | 공백 우회 |
| 대소문자 | `--tamper=randomcase` | 필터 우회 |
| 시간 지연 | `--technique=T` | Time-based Blind |
| 느린 속도 | `--delay=2 --safe-freq=3` | 속도 제한 우회 |
| User-Agent 변경 | `--random-agent` | 차단 우회 |

---

## 5. Python 웹 취약점 스캔 결과 파싱 + HTML 보고서 생성

아래 도구는 ZAP JSON 결과, SQLMap 출력, ffuf JSON 결과를 파싱해 통합 HTML 보고서를 생성한다.

```python
#!/usr/bin/env python3
"""
web_report_gen.py — 웹 취약점 스캔 결과 → HTML 보고서 생성 CLI
Python 3.10+ 필요, 외부 의존성 없음 (표준 라이브러리만 사용)

사용:
  python3 web_report_gen.py --zap zap.json --ffuf ffuf.json \
                            --sqlmap sqlmap.txt --output report.html
"""

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────
# 데이터 구조
# ──────────────────────────────────────────────

@dataclass
class Finding:
    tool: str
    severity: str          # Critical / High / Medium / Low / Info
    title: str
    url: str
    description: str
    evidence: str = ""
    recommendation: str = ""


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High":     "#e74c3c",
    "Medium":   "#e67e22",
    "Low":      "#f1c40f",
    "Info":     "#3498db",
}


# ──────────────────────────────────────────────
# 파서
# ──────────────────────────────────────────────

def parse_zap_json(path: Path) -> list[Finding]:
    """ZAP JSON 결과 파일 파싱."""
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[WARN] ZAP 파일 파싱 실패: {e}", file=sys.stderr)
        return findings

    # ZAP JSON 구조: {"site": [{"alerts": [...]}]} 또는 {"alerts": [...]}
    alerts: list[dict] = []
    if isinstance(data, dict):
        for site in data.get("site", []):
            alerts.extend(site.get("alerts", []))
        alerts.extend(data.get("alerts", []))
    elif isinstance(data, list):
        alerts = data

    zap_risk_map = {
        "3": "High", "2": "Medium", "1": "Low", "0": "Info",
        "High": "High", "Medium": "Medium", "Low": "Low",
        "Informational": "Info", "Critical": "Critical",
    }

    for alert in alerts:
        risk_raw = str(alert.get("riskcode", alert.get("risk", "0")))
        severity = zap_risk_map.get(risk_raw, "Info")
        instances = alert.get("instances", [{}])
        url = instances[0].get("uri", alert.get("url", "-")) if instances else "-"
        findings.append(Finding(
            tool="OWASP ZAP",
            severity=severity,
            title=alert.get("name", "Unknown"),
            url=url,
            description=re.sub(r"<[^>]+>", "", alert.get("description", "")),
            evidence=alert.get("evidence", ""),
            recommendation=re.sub(r"<[^>]+>", "", alert.get("solution", "")),
        ))
    return findings


def parse_ffuf_json(path: Path) -> list[Finding]:
    """ffuf JSON 결과 파일 파싱."""
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[WARN] ffuf 파일 파싱 실패: {e}", file=sys.stderr)
        return findings

    results = data.get("results", [])
    for r in results:
        status = r.get("status", 0)
        severity = "Low"
        if status in (200, 201):
            severity = "Medium"
        elif status in (301, 302):
            severity = "Low"
        elif status == 403:
            severity = "Info"

        findings.append(Finding(
            tool="ffuf",
            severity=severity,
            title=f"발견된 경로: {r.get('input', {}).get('FUZZ', r.get('url', '-'))}",
            url=r.get("url", "-"),
            description=f"HTTP {status} 응답, 크기: {r.get('length', 0)} bytes, "
                        f"단어 수: {r.get('words', 0)}, 줄 수: {r.get('lines', 0)}",
            evidence=f"Status: {status}",
        ))
    return findings


def parse_sqlmap_text(path: Path) -> list[Finding]:
    """SQLMap 콘솔 출력 텍스트 파싱."""
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        print(f"[WARN] SQLMap 파일 파싱 실패: {e}", file=sys.stderr)
        return findings

    # 인젝션 포인트 탐지
    injection_pattern = re.compile(
        r"Parameter:\s+(.+?)\s+\((.+?)\).*?Type:\s+(.+?)[\r\n]",
        re.DOTALL,
    )
    for match in injection_pattern.finditer(text):
        param, method, inj_type = match.groups()
        # URL 추출
        url_match = re.search(r"Target URL:\s+(\S+)", text)
        url = url_match.group(1) if url_match else "-"
        findings.append(Finding(
            tool="SQLMap",
            severity="High",
            title=f"SQL 인젝션: 파라미터 '{param.strip()}'",
            url=url,
            description=f"인젝션 타입: {inj_type.strip()}, HTTP 메서드: {method.strip()}",
            evidence=match.group(0)[:200],
            recommendation="파라미터화된 쿼리(Prepared Statement) 사용, 입력값 검증/이스케이프",
        ))

    # DB 이름 노출
    db_pattern = re.compile(r"available databases.*?:\s*\[\*\]\s+(.+?)(?=\n\[\*\]|\Z)", re.DOTALL)
    db_match = db_pattern.search(text)
    if db_match:
        dbs_raw = db_match.group(0)
        dbs = re.findall(r"\[\*\]\s+(\S+)", dbs_raw)
        if dbs:
            url_match = re.search(r"Target URL:\s+(\S+)", text)
            url = url_match.group(1) if url_match else "-"
            findings.append(Finding(
                tool="SQLMap",
                severity="Critical",
                title="데이터베이스 목록 노출",
                url=url,
                description=f"열거된 DB: {', '.join(dbs)}",
                recommendation="데이터베이스 권한 최소화, SQL 인젝션 즉시 수정",
            ))

    return findings


# ──────────────────────────────────────────────
# HTML 보고서 생성
# ──────────────────────────────────────────────

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>웹 취약점 스캔 보고서</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#f4f4f4; color:#333; margin:0; padding:20px; }}
  h1 {{ background:#2c3e50; color:#fff; padding:20px; border-radius:6px; }}
  h2 {{ color:#2c3e50; border-bottom:2px solid #2c3e50; padding-bottom:6px; }}
  .summary {{ display:flex; gap:12px; flex-wrap:wrap; margin:20px 0; }}
  .badge {{ padding:10px 20px; border-radius:6px; color:#fff; font-weight:bold; font-size:1.1em; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:6px;
           box-shadow:0 1px 4px rgba(0,0,0,0.1); margin-bottom:30px; }}
  th {{ background:#2c3e50; color:#fff; padding:10px; text-align:left; }}
  td {{ padding:9px 10px; border-bottom:1px solid #eee; vertical-align:top; }}
  tr:hover {{ background:#f9f9f9; }}
  .sev {{ display:inline-block; padding:2px 10px; border-radius:4px; color:#fff;
          font-size:0.85em; font-weight:bold; }}
  .meta {{ color:#777; font-size:0.85em; margin-bottom:20px; }}
  pre {{ background:#f8f8f8; padding:8px; border-radius:4px; font-size:0.82em;
        overflow-x:auto; white-space:pre-wrap; word-break:break-all; }}
  a {{ color:#2980b9; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
</style>
</head>
<body>
<h1>웹 취약점 스캔 보고서</h1>
<p class="meta">생성 일시: {generated_at} | 총 발견: {total}개</p>

<h2>요약</h2>
<div class="summary">
{summary_badges}
</div>

<h2>발견 항목 상세</h2>
<table>
<tr>
  <th>#</th>
  <th>심각도</th>
  <th>도구</th>
  <th>제목</th>
  <th>URL</th>
  <th>설명 / 권고사항</th>
</tr>
{rows}
</table>
</body>
</html>
"""


def severity_badge(severity: str, count: int) -> str:
    color = SEVERITY_COLORS.get(severity, "#95a5a6")
    return (
        f'<div class="badge" style="background:{color}">'
        f"{severity}: {count}</div>"
    )


def finding_row(idx: int, f: Finding) -> str:
    color = SEVERITY_COLORS.get(f.severity, "#95a5a6")
    sev_html = (
        f'<span class="sev" style="background:{color}">'
        f"{html.escape(f.severity)}</span>"
    )
    url_html = (
        f'<a href="{html.escape(f.url)}" target="_blank">'
        f"{html.escape(f.url[:80])}{'…' if len(f.url) > 80 else ''}</a>"
    )
    desc_parts: list[str] = []
    if f.description:
        desc_parts.append(html.escape(f.description))
    if f.evidence:
        desc_parts.append(f"<pre>{html.escape(f.evidence[:300])}</pre>")
    if f.recommendation:
        desc_parts.append(
            f"<b>권고:</b> {html.escape(f.recommendation[:200])}"
        )
    desc_html = "<br>".join(desc_parts)
    return (
        f"<tr><td>{idx}</td><td>{sev_html}</td>"
        f"<td>{html.escape(f.tool)}</td>"
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{url_html}</td>"
        f"<td>{desc_html}</td></tr>"
    )


def generate_html_report(findings: list[Finding], output: Path) -> None:
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # 요약 집계
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    badges = "\n".join(
        severity_badge(sev, cnt)
        for sev, cnt in counts.items()
        if cnt > 0
    )
    rows = "\n".join(finding_row(i + 1, f) for i, f in enumerate(findings))

    html_content = HTML_TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(findings),
        summary_badges=badges,
        rows=rows if rows else "<tr><td colspan='6'>발견된 취약점 없음</td></tr>",
    )
    output.write_text(html_content, encoding="utf-8")
    print(f"[OK] 보고서 생성 완료: {output.resolve()}")


# ──────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web_report_gen",
        description="웹 취약점 스캔 결과 → HTML 보고서 생성",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 web_report_gen.py --zap zap.json --output report.html
  python3 web_report_gen.py --ffuf ffuf.json --sqlmap sqlmap.txt -o full_report.html
  python3 web_report_gen.py --zap zap.json --ffuf ffuf.json --sqlmap sqlmap.txt -o all.html
        """,
    )
    parser.add_argument("--zap",     type=Path, help="ZAP JSON 결과 파일 경로")
    parser.add_argument("--ffuf",    type=Path, help="ffuf JSON 결과 파일 경로")
    parser.add_argument("--sqlmap",  type=Path, help="SQLMap 텍스트 출력 파일 경로")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("vulnerability_report.html"),
        help="출력 HTML 파일 경로 (기본: vulnerability_report.html)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not any([args.zap, args.ffuf, args.sqlmap]):
        parser.error("최소 하나의 입력 파일(--zap, --ffuf, --sqlmap)이 필요합니다.")

    findings: list[Finding] = []

    if args.zap:
        zap_findings = parse_zap_json(args.zap)
        print(f"[ZAP]    {len(zap_findings)}개 항목 로드")
        findings.extend(zap_findings)

    if args.ffuf:
        ffuf_findings = parse_ffuf_json(args.ffuf)
        print(f"[ffuf]   {len(ffuf_findings)}개 항목 로드")
        findings.extend(ffuf_findings)

    if args.sqlmap:
        sqlmap_findings = parse_sqlmap_text(args.sqlmap)
        print(f"[SQLMap] {len(sqlmap_findings)}개 항목 로드")
        findings.extend(sqlmap_findings)

    print(f"[INFO] 총 {len(findings)}개 항목으로 보고서 생성 중...")
    generate_html_report(findings, args.output)


if __name__ == "__main__":
    main()
```

### 실행 예시

```bash
# ZAP 결과만 보고서 생성
python3 web_report_gen.py --zap zap_results.json -o report.html

# ZAP + ffuf + SQLMap 통합 보고서
python3 web_report_gen.py \
  --zap zap.json \
  --ffuf ffuf.json \
  --sqlmap sqlmap_output.txt \
  -o full_report.html

# ZAP JSON 출력 방법
docker run --rm zaproxy/zap-stable zap-baseline.py \
  -t https://target.com -J zap.json
```

---

## 6. 도구 비교 및 실무 조합 전략

| 단계 | 도구 | 목적 |
|------|------|------|
| 정찰 | ffuf / gobuster | 숨겨진 경로·파라미터 발견 |
| 프록시 | Burp Suite | 트래픽 가로채기·수동 조작 |
| 자동 스캔 | OWASP ZAP | 포괄적 취약점 자동 탐지 |
| SQL 인젝션 | SQLMap | 자동 SQL 인젝션 확인·추출 |
| 보고서 | web_report_gen.py | 통합 HTML 보고서 생성 |

---

## 참고 자료

- [ffuf GitHub](https://github.com/ffuf/ffuf) — 고속 웹 퍼저, 사용법 및 예제 포함

---

<a name="english"></a>
# Web Security Tools and Automation

This section covers the essential web security tools used in real-world pentesting: Burp Suite, OWASP ZAP, ffuf, gobuster, and SQLMap. The final section provides a Python CLI that parses scan results and generates a consolidated HTML report.

---

## 1. Burp Suite Core Features

### 1.1 Proxy Setup

```
Browser HTTP proxy: 127.0.0.1:8080
CA cert: browse to http://burpsuite → download and install
```

### 1.2 Intruder Attack Types

| Type | Description | Use Case |
|------|-------------|----------|
| Sniper | One position at a time | Single-parameter brute force |
| Battering ram | Same payload to all positions | username=admin&password=admin |
| Pitchfork | Paired payloads per position | Credential stuffing |
| Cluster bomb | Cartesian product | Username + password combos |

### 1.3 Repeater

```
Shortcut: Ctrl+R  — send request to Repeater
Strategy: send baseline → modify parameter → compare responses
Look for: error messages, response size differences, timing differences
```

### 1.4 Useful BApp Extensions (Community Edition)

| Extension | Function |
|-----------|----------|
| Param Miner | Discover hidden parameters |
| JS Link Finder | Extract endpoints from JS |
| Turbo Intruder | High-speed Intruder with Python scripting |
| AuthMatrix | Automate authorization matrix |
| Retire.js | Detect vulnerable JS libraries |

---

## 2. OWASP ZAP Automated Scanning

```bash
# Baseline scan (passive + spider)
docker run --rm zaproxy/zap-stable zap-baseline.py \
  -t https://target.com -r report.html

# Full active scan
docker run --rm zaproxy/zap-stable zap-full-scan.py \
  -t https://target.com -r full_report.html -J report.json

# API scan with OpenAPI spec
docker run --rm zaproxy/zap-stable zap-api-scan.py \
  -t https://target.com/swagger.json -f openapi -r api_report.html
```

---

## 3. ffuf / gobuster Fuzzing

```bash
# Directory fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u https://target.com/FUZZ -mc 200,301,302,403

# Parameter discovery
ffuf -w params.txt -u "https://target.com/search?FUZZ=test" -fw 42

# POST login brute force
ffuf -w passwords.txt -u https://target.com/login \
     -X POST -d "username=admin&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" -fc 200

# Subdomain enumeration
ffuf -w subdomains.txt -u https://FUZZ.target.com -mc 200,301

# gobuster with extensions
gobuster dir -u https://target.com \
  -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak
```

---

## 4. SQLMap Advanced Options

```bash
# Detect SQL injection and list databases
sqlmap -u "https://target.com/item?id=1" --dbs

# Use saved Burp request
sqlmap -r request.txt --dbs

# Increase depth and risk
sqlmap -u "https://target.com/item?id=1" --level=5 --risk=3 --dbs

# WAF bypass with tamper scripts
sqlmap -u "https://target.com/item?id=1" \
       --tamper=space2comment,randomcase,charunicodeescape --dbs

# Dump specific table columns
sqlmap -u "https://target.com/item?id=1" \
       -D mydb -T users -C username,password --dump
```

**Key tamper scripts**

| Script | Effect |
|--------|--------|
| `space2comment` | Replace spaces with `/**/` |
| `randomcase` | Randomize keyword case |
| `charunicodeescape` | Unicode-escape characters |
| `between` | Replace `>` with `BETWEEN` |
| `apostrophemask` | Replace `'` with `%EF%BC%87` |

---

## 5. Python Report Generator

The `web_report_gen.py` script (full source in the Korean section) parses ZAP JSON, ffuf JSON, and SQLMap text output, then produces a color-coded HTML report. Key design points:

- **Python 3.10+** with full type hints — no external dependencies (stdlib only)
- **argparse** CLI with `--zap`, `--ffuf`, `--sqlmap`, `--output`
- Findings sorted by severity (Critical → High → Medium → Low → Info)
- Self-contained HTML with inline CSS — opens in any browser

```bash
# ZAP only
python3 web_report_gen.py --zap zap.json -o report.html

# Full combined report
python3 web_report_gen.py \
  --zap zap.json --ffuf ffuf.json --sqlmap sqlmap.txt -o all.html
```

---

## Tool Combination Strategy

| Phase | Tool | Purpose |
|-------|------|---------|
| Recon | ffuf / gobuster | Discover hidden paths and parameters |
| Proxy | Burp Suite | Intercept and manipulate traffic |
| Auto scan | OWASP ZAP | Comprehensive automated detection |
| SQL injection | SQLMap | Automated SQL injection verification |
| Reporting | web_report_gen.py | Consolidated HTML report |

---

## References

- [ffuf GitHub](https://github.com/ffuf/ffuf) — High-speed web fuzzer with extensive usage examples and documentation
