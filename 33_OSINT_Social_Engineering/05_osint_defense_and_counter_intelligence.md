> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# OSINT 방어 및 대항 인텔리전스 — 디지털 발자국 최소화·소셜 엔지니어링 인식·피싱 방어

## 0. 초보자를 위한 개념 이해

### OSINT 방어란?

OSINT(Open Source Intelligence)는 공개된 정보를 수집하는 기법입니다. 공격자는 공격 전에 표적의 이메일, 소셜 미디어, 직원 정보, 기술 스택을 OSINT로 수집합니다. 방어자는 공개 정보를 최소화하고 수집된 정보를 모니터링해야 합니다.

```
OSINT 공격자의 정보 수집 흐름:

  조직 식별:
    LinkedIn     → 임직원 명단, 직책, 기술 스택
    GitHub       → 소스 코드, 하드코딩된 자격증명
    Shodan       → 인터넷에 노출된 서비스/버전
    WhatsMyName  → 사용자명으로 SNS 계정 찾기

  표적 프로파일링:
    이메일 형식 추측 → hunter.io, clearbit
    조직 기술 스택  → Wappalyzer, BuiltWith
    인프라 정보    → DNS 레코드, SSL 인증서

  소셜 엔지니어링 준비:
    직원 이름+직책 → 임원 사칭 이메일 작성
    내부 프로젝트명 → 신뢰도 높은 피싱 제작
    내부 연락처    → 비쉬(Vishing) 스크립트 작성
```

---

## 1. 디지털 발자국 최소화

### 1.1 조직 디지털 발자국 감사

```python
#!/usr/bin/env python3
"""
조직 디지털 발자국 자동 감사 도구.
DNS, Shodan, GitHub, crt.sh 등에서 노출 정보 수집.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class ExposureFinding:
    source: str
    type: str
    value: str
    risk: str  # High/Medium/Low/Info
    recommendation: str


def check_dns_exposure(domain: str) -> list[ExposureFinding]:
    """DNS 레코드에서 내부 인프라 정보 노출 확인."""
    findings: list[ExposureFinding] = []

    # 서브도메인 추측 (일반적인 관리용 서브도메인)
    sensitive_subdomains = [
        "admin", "internal", "vpn", "mail", "webmail", "intranet",
        "dev", "staging", "test", "backup", "mgmt", "monitor",
        "jira", "confluence", "gitlab", "jenkins", "sonar",
    ]

    for sub in sensitive_subdomains:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            findings.append(ExposureFinding(
                source="DNS",
                type="Sensitive Subdomain",
                value=f"{fqdn} → {ip}",
                risk="Medium",
                recommendation=f"내부 전용 서비스 '{fqdn}'는 VPN 뒤에 배치하고 공개 DNS에서 제거",
            ))
            log.info("서브도메인 발견: %s → %s", fqdn, ip)
        except socket.gaierror:
            pass

    # SPF/DMARC 레코드 확인
    try:
        import subprocess
        for record_type in ["TXT"]:
            result = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True, text=True, timeout=5, check=False
            )
            txt_records = result.stdout.strip()
            if "v=spf1" not in txt_records:
                findings.append(ExposureFinding(
                    source="DNS",
                    type="Missing SPF Record",
                    value=domain,
                    risk="High",
                    recommendation="SPF 레코드 추가로 이메일 스푸핑 방지",
                ))
            if "v=DMARC1" not in txt_records:
                findings.append(ExposureFinding(
                    source="DNS",
                    type="Missing DMARC Record",
                    value=f"_dmarc.{domain}",
                    risk="High",
                    recommendation="DMARC 정책 설정 (p=quarantine 이상)",
                ))
    except Exception as exc:
        log.debug("DNS 조회 실패: %s", exc)

    return findings


def check_certificate_transparency(domain: str) -> list[ExposureFinding]:
    """
    crt.sh Certificate Transparency 로그에서
    서브도메인 노출 확인.
    """
    findings: list[ExposureFinding] = []
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAudit/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        unique_names: set[str] = set()
        for cert in data:
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    unique_names.add(name)

        for name in sorted(unique_names)[:20]:  # 최대 20개
            findings.append(ExposureFinding(
                source="crt.sh",
                type="CT Log Subdomain",
                value=name,
                risk="Info",
                recommendation="인증서 발급 내역을 공격자가 수집 가능. 내부 서비스는 내부 CA 사용 고려",
            ))

        log.info("crt.sh에서 %d개 서브도메인 발견", len(unique_names))
    except Exception as exc:
        log.error("crt.sh 조회 실패: %s", exc)

    return findings


def check_github_secrets(org_name: str, github_token: str = "") -> list[ExposureFinding]:
    """
    GitHub 공개 저장소에서 민감 정보 노출 확인.
    GitHub API 토큰은 환경 변수 GITHUB_TOKEN에서 로드.
    """
    findings: list[ExposureFinding] = []
    import os

    token = github_token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        log.warning("GITHUB_TOKEN 없음 — GitHub 감사 건너뜀")
        return findings

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SecurityAudit/1.0",
    }

    # 위험 파일 패턴
    dangerous_files = [
        ".env", "*.pem", "*.key", "*.p12", "*.pfx",
        "config.yml", "secrets.yml", "credentials.json",
        ".aws/credentials", "*.tfvars",
    ]

    # 조직 저장소 목록 조회
    url = f"https://api.github.com/orgs/{org_name}/repos?per_page=50&type=public"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            repos = json.loads(resp.read())

        for repo in repos:
            repo_name = repo["name"]
            # 각 위험 파일 패턴 검색
            for pattern in [".env", "id_rsa", "secrets"]:
                search_url = (
                    f"https://api.github.com/search/code"
                    f"?q=filename:{pattern}+repo:{org_name}/{repo_name}"
                )
                try:
                    sreq = urllib.request.Request(search_url, headers=headers)
                    with urllib.request.urlopen(sreq, timeout=5) as sresp:
                        sdata = json.loads(sresp.read())
                        if sdata.get("total_count", 0) > 0:
                            findings.append(ExposureFinding(
                                source="GitHub",
                                type="Sensitive File in Public Repo",
                                value=f"{org_name}/{repo_name}: {pattern}",
                                risk="Critical",
                                recommendation="민감 파일을 저장소에서 제거하고 git-filter-repo로 히스토리 정리",
                            ))
                except Exception:
                    pass

    except Exception as exc:
        log.error("GitHub API 조회 실패: %s", exc)

    return findings


def audit_digital_footprint(
    domain: str,
    org_name: str = "",
) -> list[ExposureFinding]:
    """전체 디지털 발자국 감사 실행."""
    all_findings: list[ExposureFinding] = []

    log.info("도메인 DNS 감사: %s", domain)
    all_findings.extend(check_dns_exposure(domain))

    log.info("인증서 투명성 로그 확인: %s", domain)
    all_findings.extend(check_certificate_transparency(domain))

    if org_name:
        log.info("GitHub 조직 감사: %s", org_name)
        all_findings.extend(check_github_secrets(org_name))

    # 위험도별 분류
    by_risk = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
    for f in all_findings:
        by_risk[f.risk].append(f)

    print(f"\n{'='*60}")
    print(f"디지털 발자국 감사 결과: {domain}")
    print(f"{'='*60}")
    for risk, items in by_risk.items():
        if items:
            print(f"\n[{risk}] {len(items)}개 발견")
            for item in items:
                print(f"  • [{item.source}] {item.type}: {item.value[:60]}")
                print(f"    → {item.recommendation[:80]}")

    return all_findings
```

---

## 2. 소셜 엔지니어링 인식 훈련 자동화

### 2.1 피싱 시뮬레이션 및 인식 훈련

```python
#!/usr/bin/env python3
"""
피싱 시뮬레이션 플랫폼 보조 도구.
실제 피싱 아님 — 내부 훈련용 이메일 메타데이터만 생성.
"""
from __future__ import annotations

import hashlib
import random
import string
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class PhishingSimulation:
    campaign_name: str
    target_department: str
    template_type: str  # credential/malware/urgency/pretexting
    send_date: str
    tracking_id: str


def generate_phishing_templates() -> dict[str, str]:
    """
    다양한 피싱 유형 설명 (실제 HTML 아님 — 교육용 텍스트).
    각 유형별 인식 포인트 제공.
    """
    templates = {
        "credential_harvest": """
[피싱 유형: 자격증명 수집]

흔한 시나리오:
  제목: "중요: Microsoft 365 계정 보안 경고"
  발신: it-support@micros0ft-support.com  ← 도메인 스푸핑 주의!
  
  내용: "귀하의 계정이 의심스러운 위치에서 접속되었습니다.
         24시간 내 확인하지 않으면 계정이 잠깁니다."
  링크: https://login.microsoftonline.com.evil.com/...  ← 도메인 끝 확인!

[인식 포인트]
  ✓ 발신자 이메일 도메인 정확히 확인
  ✓ 링크 호버 시 실제 URL 확인
  ✓ SSL 인증서가 있어도 피싱 사이트일 수 있음
  ✓ 긴급성을 강조하면 의심
  ✓ 의심스러우면 직접 서비스 사이트 접속
""",
        "ceo_fraud": """
[피싱 유형: CEO 사기 (BEC - Business Email Compromise)]

흔한 시나리오:
  발신: ceo@company.com  ← 스푸핑 또는 유사 도메인
  수신: 재무팀 담당자
  제목: "긴급 이체 요청"
  
  내용: "오늘 오후 3시까지 계좌번호 123-456-789로 5000만원 이체 부탁드립니다.
         중요한 거래입니다. 이 이메일 외 다른 채널로 확인하지 마세요."

[인식 포인트]
  ✓ 전화로 직접 확인 (이메일로만 요청하는 이체는 의심)
  ✓ "다른 채널 확인 금지" → 강력한 사기 신호
  ✓ DMARC 확인으로 발신 도메인 인증
  ✓ 이체 요청은 반드시 이중 승인 절차
""",
        "usb_drop": """
[피싱 유형: USB 드롭 공격]

흔한 시나리오:
  회사 주차장/화장실에 USB 드라이브 방치
  라벨: "2026 급여 내역" 또는 "직원 성과 평가"
  
  내용: autorun.inf 또는 .lnk 파일로 악성코드 실행

[인식 포인트]
  ✓ 출처 불명 USB/저장장치 절대 연결 금지
  ✓ 미확인 USB는 보안팀에 즉시 제출
  ✓ USB AutoRun 정책 비활성화
""",
    }
    return templates


def calculate_phishing_susceptibility_score(
    click_rate: float,
    report_rate: float,
    credential_submit_rate: float,
) -> dict[str, object]:
    """
    피싱 시뮬레이션 결과 기반 조직 취약도 점수.
    낮을수록 좋음 (0=매우 좋음, 100=매우 위험).
    """
    # 클릭율 40%, 보고율 -20% (보고할수록 감점), 자격증명 제출율 40%
    raw_score = (click_rate * 40) + (credential_submit_rate * 40) - (report_rate * 20)
    score = max(0, min(100, raw_score))

    if score < 20:
        level = "우수 (인식 수준 높음)"
        action = "분기별 훈련 유지"
    elif score < 40:
        level = "양호 (개선 여지 있음)"
        action = "월별 훈련 실시 및 취약 부서 집중 교육"
    elif score < 60:
        level = "주의 (훈련 강화 필요)"
        action = "격주 훈련 및 필수 보안 교육 이수"
    else:
        level = "위험 (즉각 조치 필요)"
        action = "즉시 전 직원 교육 및 기술적 통제 강화"

    return {
        "score": round(score, 1),
        "level": level,
        "action": action,
        "click_rate_pct": click_rate * 100,
        "report_rate_pct": report_rate * 100,
        "submit_rate_pct": credential_submit_rate * 100,
    }
```

---

## 3. 이메일 보안 자동화

```python
#!/usr/bin/env python3
"""
이메일 보안 헤더 분석 및 피싱 감지.
이메일 헤더에서 SPF/DKIM/DMARC 검증 결과 파싱.
"""
from __future__ import annotations

import email
import re
from email.parser import HeaderParser
from pathlib import Path


def analyze_email_headers(raw_email: str) -> dict[str, object]:
    """
    이메일 헤더에서 보안 관련 정보 추출.
    SPF, DKIM, DMARC 검증 결과 파싱.
    """
    parser = HeaderParser()
    msg = parser.parsestr(raw_email)

    result: dict[str, object] = {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "suspicious_indicators": [],
    }

    # Authentication-Results 헤더 파싱
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        # SPF
        spf_match = re.search(r"spf=(\w+)", auth_results, re.IGNORECASE)
        if spf_match:
            result["spf"] = spf_match.group(1).lower()

        # DKIM
        dkim_match = re.search(r"dkim=(\w+)", auth_results, re.IGNORECASE)
        if dkim_match:
            result["dkim"] = dkim_match.group(1).lower()

        # DMARC
        dmarc_match = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)
        if dmarc_match:
            result["dmarc"] = dmarc_match.group(1).lower()

    # 의심 지표 확인
    indicators: list[str] = []

    # SPF/DKIM 실패
    if result["spf"] == "fail":
        indicators.append("SPF 검증 실패 — 발신 서버 인증 안됨")
    if result["dkim"] == "fail":
        indicators.append("DKIM 서명 검증 실패 — 이메일 무결성 의심")
    if result["dmarc"] == "fail":
        indicators.append("DMARC 정책 위반 — 도메인 인증 실패")

    # From과 Reply-To 불일치
    from_domain = re.search(r"@([\w.-]+)", result["from"])
    reply_domain = re.search(r"@([\w.-]+)", result["reply_to"])
    if from_domain and reply_domain:
        if from_domain.group(1).lower() != reply_domain.group(1).lower():
            indicators.append(
                f"From({from_domain.group(1)})과 Reply-To({reply_domain.group(1)}) 도메인 불일치"
            )

    result["suspicious_indicators"] = indicators
    result["risk"] = "High" if len(indicators) >= 2 else "Medium" if indicators else "Low"

    return result


def check_domain_age_and_reputation(domain: str) -> dict:
    """
    도메인 WHOIS 기반 신규 도메인 감지.
    신규 도메인(30일 이내)은 피싱 위험 높음.
    실제 구현에서는 python-whois 라이브러리 사용 권장.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=10, check=False
        )
        whois_text = result.stdout

        # Creation Date 파싱
        date_patterns = [
            r"Creation Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"created:\s*(.+)",
        ]
        creation_date = None
        for pattern in date_patterns:
            m = re.search(pattern, whois_text, re.IGNORECASE)
            if m:
                creation_date = m.group(1).strip()[:10]
                break

        return {
            "domain": domain,
            "creation_date": creation_date or "unknown",
            "note": "30일 이내 신규 도메인은 피싱 위험 높음",
        }
    except Exception as exc:
        return {"domain": domain, "error": str(exc)}


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        raw = Path(sys.argv[1]).read_text()
        analysis = analyze_email_headers(raw)
        print(f"From:  {analysis['from']}")
        print(f"SPF:   {analysis['spf']}")
        print(f"DKIM:  {analysis['dkim']}")
        print(f"DMARC: {analysis['dmarc']}")
        print(f"위험도: {analysis['risk']}")
        for ind in analysis['suspicious_indicators']:
            print(f"  ⚠ {ind}")
```

---

## 3.5 AI 딥페이크 음성 피싱(Vishing) 탐지와 대응

2절의 소셜 엔지니어링 인식 훈련은 주로 텍스트 기반 피싱을 다루지만, 생성형 AI 음성 복제(단 몇 초 분량의 공개 음성 샘플로 특정인의 목소리를 합성)가 대중화되면서 "CEO 목소리로 걸려온 긴급 송금 요청 전화" 같은 **AI 딥페이크 보이스피싱**이 실전 위협이 됐다. 텍스트 피싱과 달리 피해자가 "익숙한 목소리"를 직접 듣고 즉각적인 신뢰·긴급성 압박을 느끼기 때문에 방어가 훨씬 어렵다.

```
[공격 시나리오]
1. 공격자가 유튜브 인터뷰, 컨퍼런스 발표 영상 등에서 대상 임원의 음성 샘플 수집(OSINT)
2. 음성 복제 서비스로 해당 임원 목소리의 TTS 모델 생성
3. 재무 담당자에게 "지금 급하게 해외 송금이 필요하다"는 내용으로 전화(또는 음성메시지)
4. 정상 승인 절차를 우회하도록 긴급성·권위를 이용해 압박
```

```python
#!/usr/bin/env python3
"""통화 녹음 파일에서 AI 생성 음성 특유의 아티팩트 기초 점검 (보조 신호일 뿐, 단독 판정 금지)."""
import numpy as np
import librosa


def analyze_voice_artifacts(audio_path: str) -> dict:
    y, sr = librosa.load(audio_path, sr=None)

    # 1. 배경 잡음 스펙트럼 — 실제 통화는 환경 노이즈(에어컨, 타이핑 등)가 섞이지만
    #    합성 음성은 배경이 부자연스럽게 깨끗하거나 반복적인 경우가 있다.
    spectral_flatness = float(np.mean(librosa.feature.spectral_flatness(y=y)))

    # 2. 피치 미세변동(jitter) — 실제 발성은 미세한 떨림이 있으나
    #    일부 TTS 모델은 이 부분이 부자연스럽게 안정적이다.
    pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
    pitch_values = pitches[magnitudes > np.median(magnitudes)]
    pitch_std = float(np.std(pitch_values)) if len(pitch_values) > 0 else 0.0

    suspicion_flags = []
    if spectral_flatness < 0.05:
        suspicion_flags.append("배경 노이즈가 부자연스럽게 낮음")
    if pitch_std < 5.0:
        suspicion_flags.append("피치 변동성이 부자연스럽게 낮음(합성 음성 가능성)")

    return {
        "spectral_flatness": spectral_flatness,
        "pitch_std": pitch_std,
        "suspicion_flags": suspicion_flags,
    }


if __name__ == "__main__":
    result = analyze_voice_artifacts("call_recording.wav")
    print(f"결과: {result}")
```

**대응 체계 (기술보다 프로세스가 핵심)**:
1. **음성만으로 승인 금지**: 송금·권한 변경 같은 민감 요청은 반드시 별도 채널(사내 메신저, 콜백 — 상대가 준 번호가 아닌 사전 등록된 번호로 재발신)로 재확인
2. **코드워드 사전 합의**: 경영진·재무팀 간 긴급 상황용 구두 암호를 미리 정해, 전화상에서 확인
3. **긴급성 자체를 경보 신호로**: "지금 당장", "비밀 유지" 같은 압박 문구는 정상 업무 요청보다 사기 시도일 확률이 훨씬 높다는 점을 훈련에 포함
4. **임원 음성 노출 최소화**: 공개 인터뷰·컨퍼런스 영상에서 장시간 발화 노출을 최소화하는 것도 근본적으로 복제 재료 자체를 줄이는 효과가 있다

딥페이크 탐지 기술(위 코드처럼)은 계속 발전하는 생성 모델과의 군비경쟁이라 신뢰도가 낮으므로, 실무에서는 기술적 탐지보다 "음성만으로는 절대 승인하지 않는다"는 절차적 통제가 훨씬 견고한 방어선이다.

---

## 4. 참고 자료

- **Have I Been Pwned**: https://haveibeenpwned.com/
- **Google Workspace DMARC 가이드**: https://support.google.com/a/answer/2466580
- **SANS 소셜 엔지니어링 인식**: https://www.sans.org/security-awareness-training/

---

<!-- detect-validate-33 -->
## OSINT 방어·대항 인텔 작동 검증과 회귀

OSINT 방어는 *조치했다*가 아니라 *발자국이 실제로 줄고 정찰이 탐지되는가*로 가치가 갈린다. 방어자는 **노출 최소화·인식·탐지가 회귀 없이 동작하는가**를 검증해야 한다. 검증은 **소유 자산**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 발자국 최소화 | 노출이 실제 줄었나? | 공개 노출 항목 추세 | 캐시/아카이브 잔존 |
| 메타데이터 제거 | 문서가 깨끗한가? | 메타 검출 0 | 일부 문서 누락 |
| 인식 훈련 | 보고율이 오르나? | 보고/클릭 추세 | 일회성 측정 |
| 정찰 탐지 | 도킹/스캔을 잡나? | 도킹 알림 | 외부 정찰 불가시성 |

### 방어 검증 (직접 확인)

```bash
# 1) 발자국 회귀 — 이전 대비 공개 노출 항목이 줄었는지(소유 도메인, crt.sh 추세)
curl -s "https://crt.sh/?q=%25.example.com&output=json" 2>/dev/null | jq -r '.[].name_value' | sort -u | wc -l
# 2) 문서 메타데이터 잔존 점검(소유 배포본) — 메타가 남아 있으면 회귀
exiftool -Author -Creator -GPSPosition published/*.pdf 2>/dev/null | grep -iE "author|creator|gps" | head
```

> OSINT 방어 검증은 *조치했는가*가 아니라 *발자국이 줄고 정찰이 보이는가*다 — "노출 줄였다"와 "공개 항목 수가 추세로 감소하고 배포 문서에 메타가 안 남는다"는 다르다. 소유 도메인·문서에서 노출 추세·메타 잔존을 직접 확인한다([[25_Threat_Intelligence]], [[10_Pentest_Methodology]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- 노출면 관리(자산·유출 모니터링)·디셉션이 방어 — 검증: 노출 자산이 실제 감축되는가([[40_Threat_Hunting]])
- 임직원 인식·데이터 최소화 — 강제되는지 확인

---

<a name="english"></a>

# OSINT Defense and Counter-Intelligence — Digital Footprint Reduction, Social Engineering Awareness, Phishing Defense

## Overview

Before attacking, adversaries conduct OSINT reconnaissance. Defense requires minimizing the publicly available information about your organization and detecting when you're being researched.

## OSINT Attack Surface Categories

| Category | Data Exposed | Reduction Method |
|----------|-------------|-----------------|
| DNS/Subdomains | Internal services | Remove from public DNS, use internal CA |
| Certificate Transparency | Subdomains | Wildcard certs, internal CA |
| LinkedIn/GitHub | Employee info, tech stack | Access policies, secret scanning |
| WHOIS | Contact info, registrar | Privacy protection service |
| Shodan | Open ports, versions | Firewall, remove unnecessary exposure |
| Job listings | Tech stack, salary | Generalize technology mentions |

## Email Security Controls

```
SPF:    Authorizes sending mail servers  →  v=spf1 include:_spf.google.com ~all
DKIM:   Cryptographic signing            →  Prevents content tampering
DMARC:  Policy enforcement              →  p=quarantine or p=reject

All three working together blocks spoofing of your domain.
```

## Quick Start

```bash
# Check your domain's email security
python3 footprint_audit.py example.com

# Analyze suspicious email headers
python3 email_analyzer.py suspicious_email.eml

# Calculate phishing susceptibility score
python3 phishing_score.py --click-rate 0.15 --report-rate 0.05 --submit-rate 0.08
```

## AI Deepfake Voice Phishing (Vishing) Detection and Response

Social-engineering awareness training (the earlier sections in this chapter) mostly covers text-based phishing, but as generative AI voice cloning has gone mainstream — synthesizing a specific person's voice from just a few seconds of public audio — **AI deepfake vishing**, like an urgent wire-transfer call in the "CEO's voice," has become a real-world threat. Unlike text phishing, it's much harder to defend against because the victim hears a familiar voice directly and feels immediate trust and urgency pressure.

```
[Attack Scenario]
1. Attacker collects voice samples of a target executive from YouTube interviews, conference talks, etc. (OSINT)
2. A voice-cloning service builds a TTS model of that executive's voice
3. Calls (or leaves a voicemail for) a finance staffer claiming an urgent overseas wire transfer is needed
4. Uses urgency and authority to pressure the target into bypassing the normal approval process
```

```python
#!/usr/bin/env python3
"""Basic check for artifacts typical of AI-generated speech in a call recording (a supporting signal only -- never decide alone)."""
import numpy as np
import librosa


def analyze_voice_artifacts(audio_path: str) -> dict:
    y, sr = librosa.load(audio_path, sr=None)

    # 1. Background-noise spectrum -- a real phone call usually has ambient noise mixed in
    #    (AC hum, typing, etc.), while synthesized speech sometimes has an unnaturally
    #    clean or repetitive background.
    spectral_flatness = float(np.mean(librosa.feature.spectral_flatness(y=y)))

    # 2. Pitch micro-variation (jitter) -- real speech has subtle natural wavering,
    #    while some TTS models produce pitch that's unnaturally stable.
    pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
    pitch_values = pitches[magnitudes > np.median(magnitudes)]
    pitch_std = float(np.std(pitch_values)) if len(pitch_values) > 0 else 0.0

    suspicion_flags = []
    if spectral_flatness < 0.05:
        suspicion_flags.append("Background noise unnaturally low")
    if pitch_std < 5.0:
        suspicion_flags.append("Pitch variability unnaturally low (possible synthesized speech)")

    return {
        "spectral_flatness": spectral_flatness,
        "pitch_std": pitch_std,
        "suspicion_flags": suspicion_flags,
    }


if __name__ == "__main__":
    result = analyze_voice_artifacts("call_recording.wav")
    print(f"Result: {result}")
```

**Response framework (process matters more than technology here)**:
1. **Never approve on voice alone**: sensitive requests like wire transfers or permission changes must always be re-confirmed through a separate channel (internal messenger, or a callback to a pre-registered number — never a number the caller provides)
2. **Pre-agreed code words**: set up a verbal passphrase in advance between executives and finance for emergency situations, and confirm it on the call
3. **Treat urgency itself as an alarm signal**: train staff that pressure phrases like "right now" or "keep this confidential" are far more indicative of fraud than a normal business request
4. **Minimize executive voice exposure**: reducing the amount of public interview/conference footage that exposes an executive's voice for extended periods also cuts down the raw material available for cloning

Deepfake detection technology (like the code above) is in an arms race against continually improving generative models, so its reliability is limited — in practice, a procedural control like "never approve based on voice alone" is a far more solid line of defense than technical detection.

## References

- Have I Been Pwned: https://haveibeenpwned.com/
- Google DMARC guide: https://support.google.com/a/answer/2466580
- SANS security awareness: https://www.sans.org/security-awareness-training/

<!-- detect-validate-33 -->
## OSINT Defense and Counter-Intelligence Effectiveness Validation and Regression

OSINT defense's value comes not from *whether you acted* but from *whether the footprint actually shrinks and recon is detected*. Defenders must verify **whether exposure minimization, awareness, and detection work without regression**. Validate only on **owned assets**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| Footprint minimization | Did exposure actually shrink? | Public-exposure item trend | Cache/archive remnants |
| Metadata stripping | Are documents clean? | Zero metadata detections | Some documents missed |
| Awareness training | Does report rate rise? | Report/click trend | One-off measurement |
| Recon detection | Does it catch dorking/scans? | Dorking alerts | External-recon invisibility |

### Defense validation (verify directly)

```bash
# 1) Footprint regression — whether public-exposure items shrank vs before (owned domain, crt.sh trend)
curl -s "https://crt.sh/?q=%25.example.com&output=json" 2>/dev/null | jq -r '.[].name_value' | sort -u | wc -l
# 2) Document-metadata remnant check (owned published set) — remaining metadata is a regression
exiftool -Author -Creator -GPSPosition published/*.pdf 2>/dev/null | grep -iE "author|creator|gps" | head
```

> OSINT-defense validation is *whether the footprint shrinks and recon is visible*, not *whether you acted* -- "we reduced exposure" differs from "public-item count trends down and published documents carry no metadata". Confirm exposure trend and metadata remnants on owned domains/documents directly ([[25_Threat_Intelligence]], [[10_Pentest_Methodology]], [[13_SOC_Blue_Team]]).
