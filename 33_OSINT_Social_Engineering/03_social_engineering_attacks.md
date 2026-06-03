> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 33-03. 사회공학 공격 기법 — 피싱·비싱·프리텍스팅의 설계와 측정

## 0. 초보자를 위한 개념 이해

### 사회공학이란?

**사회공학(Social Engineering)**은 기술적 취약점이 아닌 **사람의 심리**를 이용해 정보를 빼내거나 시스템 접근을 얻는 공격입니다. 최고의 방화벽도 직원이 비밀번호를 알려주면 소용없습니다.

**왜 배우는가:**
```
보안 통계:
  침해 사고의 약 90%는 피싱/사회공학이 최초 진입점

기술 보안만으로 부족한 이유:
  아무리 강한 시스템도 ──사람을 속이면──▶ 무력화

  사례:
  - 직원에게 "IT팀인데 비밀번호 알려주세요" → 통함
  - 가짜 로그인 페이지로 유도 → 자격증명 수집
  - USB 드롭 → 궁금한 직원이 꽂음
```

### 핵심 공격 유형

```
피싱(Phishing):
  이메일로 가짜 링크 전송 → 자격증명 수집
  스피어피싱: 특정 대상 맞춤형
  웨일링: C레벨 임원 대상

비싱(Vishing):
  전화로 속임 ("은행 보안팀입니다...")

스미싱(Smishing):
  SMS 문자 + 가짜 링크

프리텍스팅(Pretexting):
  가짜 시나리오 구성 ("배달 기사입니다, 서명해 주세요")
  건물 진입, 정보 수집에 활용

심리 트리거:
  긴급성: "지금 즉시 확인 안 하면 계정 삭제!"
  권위: "CEO 지시입니다"
  희소성: "오늘만 가능"
  호혜성: 무언가 제공 후 요청
```

### 필요한 도구
- **GoPhish**: 피싱 캠페인 시뮬레이션 프레임워크
- **Social Engineering Toolkit (SET)**: 사회공학 자동화
- **Evilginx2**: 피싱 + MFA 우회

### 기초 실습 예제
```python
# 피싱 캠페인 효과 분석 (GoPhish 결과 분석)
phish_results = {
    "emails_sent": 100,
    "emails_opened": 45,
    "links_clicked": 23,
    "creds_submitted": 8,
}

open_rate = phish_results["emails_opened"] / phish_results["emails_sent"] * 100
click_rate = phish_results["links_clicked"] / phish_results["emails_sent"] * 100
cred_rate = phish_results["creds_submitted"] / phish_results["emails_sent"] * 100

print(f"이메일 열람률: {open_rate:.1f}%")
print(f"링크 클릭률:  {click_rate:.1f}%")
print(f"자격증명 제출: {cred_rate:.1f}%")
print(f"보안 인식 교육 필요 직원: {phish_results['creds_submitted']}명")
```

---

## 들어가기 전에 — 톤에 대한 안내

이 문서는 모의해킹 컨설턴트가 **계약된 범위 안에서** 사회공학 평가를 수행할 때 참고할 수 있도록 작성되었다. 본문에 등장하는 시나리오·스크립트·페르소나는 모두 합법적 평가(red team engagement, phishing simulation)의 맥락에서 해석되어야 한다.

사회공학은 결국 사람을 속이는 일이다. 잘못 설계된 캠페인은 직원을 자책하게 만들고, 보복성 인사로 이어지며, 심한 경우 우울·자살 등 심각한 결과를 부른다. 컨설턴트의 윤리는 "표적을 망신 주지 않기"에서 시작한다. 캠페인이 끝난 뒤 디브리핑을 어떻게 할지부터 설계하지 않으면 이 문서의 어떤 기법도 써서는 안 된다.

---

## 1. 사회공학의 정의와 사이클

사회공학(social engineering)은 **사람의 신뢰·습관·인지 편향을 이용하여 정보 자산이나 물리 자산에 접근하는 행위**다. 기술 익스플로잇과의 차이는 표적이 코드가 아니라 인간이라는 점이며, 따라서 패치가 아니라 교육·절차·문화로 대응한다.

### 1.1 5단계 사이클

| 단계 | 한국어 | 핵심 활동 | KPI 후보 |
| --- | --- | --- | --- |
| Reconnaissance | 정찰 | OSINT, 조직도/도메인/이메일 패턴 수집 | 유효 이메일 수, 핵심 표적(VIP) 식별 정확도 |
| Rapport building | 관계 형성 | 페르소나 수립, 사전 접촉(연결 요청·인사) | 응답률, 대화 지속 시간 |
| Exploitation | 익스플로잇 | 페이로드 전달(링크/첨부/통화/방문) | 클릭률, 자격증명 입력률, 통화 응답 후 정보 누설률 |
| Closing | 종결 | 목적 달성 후 자연스러운 이탈, 의심 회피 | 신고율(낮을수록 성공), 평균 대화 종료까지 시간 |
| Cover-up | 흔적 제거 | 로그/이메일 회수, 도메인 만료, 통화 번호 폐기 | 평균 탐지까지 시간(MTTD), 잔존 흔적 수 |

각 단계의 KPI는 캠페인 종료 보고서에 반드시 들어가야 한다. "재미있는 시나리오를 만들었다"가 아니라 "정찰 → 익스플로잇 전환율이 18%였다"가 이해당사자(CISO/감사실)에게 가치 있는 산출물이다.

### 1.2 윤리·법적 기본기

- 한국에서 단순 OSINT는 합법이지만, 이메일을 보내 자격증명을 수집하는 순간 **정보통신망법** 상 부정접근 시도가 될 수 있다. 따라서 SOW(작업 명세서)에 표적 도메인·기간·허용된 페이로드 종류·디브리핑 방식을 못 박아야 한다.
- 통화 녹음은 한국에서 일방 동의 원칙이 적용되지만, 평가 대상자의 **음성 데이터를 외부 클라우드 STT에 업로드**하는 순간 개인정보처리 위탁 이슈가 생긴다. 사내 STT나 즉시 폐기 정책을 준비할 것.
- 직원 명예를 훼손할 가능성이 있는 모든 산출물(누가 클릭했는가)은 **개인 식별 불가** 형태로 보고하는 것이 원칙. 부서/직급 단위까지만.

---

## 2. 심리 트리거 — Cialdini 6원칙과 보안 맥락

사회공학 스크립트는 6가지 일반화된 설득 원칙을 골고루 활용한다. 어느 하나에 의존하면 어색해진다.

| 원칙 | 핵심 작동 방식 | 피싱/비싱 시나리오 매핑 | 한국 맥락에서의 강화 포인트 |
| --- | --- | --- | --- |
| 호혜성(Reciprocity) | 무엇을 받으면 돌려줘야 한다는 압박 | "사내 복지 포인트 지급 안내" 메일, 통화 시 "도와드리려고 미리 확인 중" 멘트 | 명절 상여·복지몰 알림이 잘 먹힘 |
| 일관성(Commitment) | 한번 동의한 입장을 유지하려는 경향 | 짧은 설문 응답 → 자격증명 입력 유도, 작은 정보(생년월일) → 큰 정보(OTP) 단계적 요구 | "방금 본인 확인 됐습니다" 멘트로 일관성 압박 |
| 사회적 증거(Social proof) | 다른 사람도 그렇게 한다는 신호 | "팀 5명 중 4명이 이미 완료한 보안 점검" 메일, 사내 공지 사칭 | 카카오톡 단톡방 캡처 위조가 효과적 |
| 권위(Authority) | 직위·전문성에 대한 복종 | CEO/CISO 사칭 BEC, 국세청·금감원 사칭 비싱 | 군대 문화의 잔재로 직급/연차 압박이 잘 통함 |
| 호감(Liking) | 친근감/유사성에 대한 약한 거절 | LinkedIn 동향에 같은 학교·동향 키워드 삽입, 통화 시 사투리 매칭 | 동문/동향 키워드 매우 강력 |
| 희소성(Scarcity) | 시간·기회 제약 | "30분 내 인증하지 않으면 계정 잠금", "오늘까지 송금" | 분기 마감·국세 신고 시즌과 결합 시 폭발적 |

**현실 팁:** 좋은 스피어피싱 메일은 한 번에 보통 2~3개 원칙을 결합한다. 예) 권위(CISO 명의) + 희소성(오늘 23시까지) + 일관성(어제 받은 보안 공지의 후속 조치). 이 결합이 자연스러우려면 1단계 정찰이 견고해야 한다.

### 2.1 심리 원칙별 탐지 신호

```
각 원칙이 활성화될 때 인식해야 할 경보 신호:

호혜성: "무료로 드립니다", "당신을 위해 준비했습니다"
  → 경보: 아무 이유 없는 선물/혜택, 대가를 요구하지 않는 것처럼 보임

일관성: "방금 확인하셨죠?", "이미 동의하셨으니..."
  → 경보: 이미 한 행동을 근거로 추가 요청

사회적 증거: "다들 이미 했습니다", "팀원들이 모두..."
  → 경보: 확인 불가한 "모두가 한다" 주장

권위: "경영진 지시사항", "법무팀 요청", "보안팀입니다"
  → 경보: 신원 확인 없이 권위 주장, 직접 확인 요청 시 거부

호감: "같은 동문이시죠?", "저도 경상도 출신입니다"
  → 경보: 갑자기 공통점을 강조하는 낯선 사람

희소성: "오늘까지", "30분 안에", "마지막 기회"
  → 경보: 확인할 시간을 주지 않는 인위적 긴급함
```

---

## 3. 피싱(이메일)

### 3.1 분류

- **대량 피싱(bulk phishing):** 동일 본문을 수천~수만 명에게. 클릭률은 낮지만 광범위. 2026년에는 메일 게이트웨이가 거의 다 잡아낸다.
- **스피어피싱(spear phishing):** 표적을 좁혀 개인화. 부서·프로젝트·상사 이름까지 등장.
- **웨일링(whaling):** C-level 한 명을 노린 형태. 직접 경유보다는 비서/재무팀 우회가 흔함.
- **BEC(Business Email Compromise):** 거래처/내부 임원 사칭으로 송금·세금계산서 변조 유도. 첨부 악성코드 없는 경우가 많아 탐지 난이도 ↑.

### 3.2 피싱 이메일 해부학 — 구성 요소별 분석

```
[실제 피싱 이메일 구조 분해]

발신자 주소:  ceo@examp1e-corp.com  ← "l"을 "1"로 교체 (비주얼 스푸핑)
             또는 ceo@example.com.attackerdomain.com (서브도메인 속임수)

제목:        [긴급] 분기 마감 승인 요청 — 오늘 18시까지
             ↑ 희소성 + 권위 결합

헤더 from:   "최고경영자 김OO" <ceo@examp1e-corp.com>
             ↑ 표시명은 실제 이름, 이메일 주소만 다름

본문 구조:
  ┌─────────────────────────────────────────┐
  │ [회사 로고 이미지 — 픽셀 단위 복제]      │
  │                                         │
  │ 안녕하세요 [이름] 님,                   │ ← 개인화
  │                                         │
  │ 분기 결산 관련하여 긴급 승인이 필요합니다. │ ← 권위 + 희소성
  │ 어제 공지드린 보안 업그레이드 건으로      │ ← 일관성 (실제 없는 공지)
  │ 계정 재인증이 필요합니다.               │
  │                                         │
  │ [지금 승인하기] ← 버튼 (실제 URL 숨김)  │
  │                                         │
  │ 18:00까지 완료하지 않으면 계정이 잠깁니다 │ ← 희소성 강화
  │                                         │
  │ 최고경영자 김OO                         │
  │ 직통: 010-xxxx-xxxx                    │
  └─────────────────────────────────────────┘

탐지 체크리스트:
  [ ] 발신 주소의 도메인 철자 확인 (hover over)
  [ ] 링크 버튼에 마우스 올려 실제 URL 확인
  [ ] 회사 공식 채널로 해당 공지 확인
  [ ] 긴급함이 생각할 시간을 주지 않는가?
```

### 3.3 스피어피싱 vs 비싱 vs 스미싱 비교표

| 구분 | 스피어피싱 | 비싱(Vishing) | 스미싱(Smishing) |
|------|-----------|---------------|------------------|
| 채널 | 이메일 | 전화 음성 | SMS/문자 |
| 개인화 수준 | 높음 (이름, 프로젝트, 상사 이름) | 중간~높음 | 낮음~중간 |
| 기술 장벽 | 낮음 (메일 발송) | 중간 (발신번호 스푸핑) | 낮음 (문자 발송) |
| 탐지 난이도 | 중간 (헤더 분석 가능) | 높음 (실시간, 기록 없음) | 낮음 (SMS 필터) |
| 성공률 | 15~25% | 40~60% | 5~10% |
| 주요 대상 | 일반 직원, 재무팀 | IT 헬프데스크, 임원 비서 | 불특정 다수 |
| 특징 | 대량 발송 가능 | 즉각 반응 유도 | URL 클릭 유도 |
| 방어 핵심 | 게이트웨이 + 교육 | 검증 절차 + 정책 | 링크 클릭 금지 교육 |

### 3.4 BEC (Business Email Compromise) 플레이북

BEC는 단순 피싱보다 훨씬 위험합니다. 악성코드 없이 합법적인 이메일처럼 보이기 때문입니다.

```
BEC 공격 플레이북 (방어 이해용):

단계 1 — 정찰 (2~4주)
  ■ 대상 기업 LinkedIn에서 임원 이름, 직위 파악
  ■ 공개된 재무 보고서에서 거래 패턴 파악
  ■ 도메인 등록 이력: 유사 도메인 등록 (타이포스쿼팅)
    예: example.com → examp1e.com, example-corp.com

단계 2 — 진입 (1~3일)
  ■ 옵션 A: 임원 이메일 계정 직접 침해 (자격증명 탈취)
  ■ 옵션 B: 유사 도메인으로 사칭 이메일 발송
  ■ 옵션 C: 합법적 거래처 이메일 계정 침해 후 내부 대화 삽입

단계 3 — 익스플로잇 (타이밍이 핵심)
  ■ 분기 마감 1~3일 전 공격 (재무팀 바쁠 때)
  ■ 임원 출장/휴가 중 (확인 어려울 때)
  ■ "계좌가 변경됐다" 또는 "긴급 송금 요청"
  ■ 금액: 처음에는 소액으로 테스트, 성공 시 대액

단계 4 — 은폐
  ■ 피해자가 인식하기 전 최대한 긴 시간 유지
  ■ 추가 이메일로 "잘 받았습니다" 확인 위조
  ■ 국제 계좌 → 다중 이체로 추적 어렵게

방어:
  ■ 모든 계좌 변경은 저장된 전화번호로 콜백 확인 (필수)
  ■ 일정 금액 이상 송금은 2명 이상 승인 (듀얼 컨트롤)
  ■ 외부 도메인 이메일에 "[외부]" 배너 자동 추가
  ■ 도메인 모니터링: 유사 도메인 등록 알림 서비스
```

### 3.5 한국 BEC 패턴 (2024~2026 관찰)

1. **거래처 메일 도용/유사 도메인 등록**
   - `kim@samplecorp.co.kr` → `kim@samp1ecorp.co.kr` (l→1) 또는 `samplecorp-kr.com` 등록.
   - 주로 거래 시점(월말, 분기말)에 "계좌가 변경됐다"는 후속 메일.
2. **해외 본사 ↔ 한국 법인 사이의 영어 메일 사슬에 끼어들기**
   - 표적이 영어가 익숙하지 않다는 점을 이용. 본사 임원 사칭으로 한국 재무팀에 송금 지시.
3. **계약서 첨부 변조**
   - 정상 계약서를 가로채 PDF 내 계좌번호만 변조 후 재전송.
4. **외부 메일 경고 우회**
   - 회사 정책으로 외부 메일에는 "[외부]" 배너가 붙는다는 것을 알고, 회신 형태(Re: ...)로 위장하거나 사내 중계 메일을 가로채는 방식.

> 운영 권고: 송금/계좌 변경 요청은 메일이 아닌 **음성 콜백(저장된 번호로)** 으로만 확정한다는 정책이 가장 효과적이다. 캠페인 결과 보고에 이 정책의 부재 여부를 반드시 적자.

### 3.6 첨부 vs 링크 vs OAuth 동의 — 2026년 비중

| 페이로드 유형 | 2020년 비중 | 2026년 비중(추정) | 비고 |
| --- | --- | --- | --- |
| 매크로 첨부(.docm/.xlsm) | 높음 | 낮음 | MOTW + 매크로 차단 정책으로 거의 사장 |
| ISO/IMG/.lnk 묶음 | 중 | 중 | 여전히 일부 환경에서 동작. EDR 시그니처 누적 |
| HTML smuggling | 중 | 중상 | 메일 게이트웨이 통과율 좋음 |
| OneNote, .svg | 낮음 | 중 | 2023~2025 사이에 급증, 정책 차단 진행 중 |
| 자격증명 수집 링크 | 높음 | 높음 | 여전히 주류. MFA로 가치 ↓ |
| **OAuth 동의 피싱** | 매우 낮음 | 높음 | M365/Google Workspace 환경에서 MFA 무력화 |

OAuth 동의 피싱(consent phishing)은 사용자에게 **악성 앱에 메일/드라이브 권한을 위임**하도록 유도하는 방식으로, 비밀번호도 MFA도 건드리지 않고 그 결과 토큰을 가져간다. 2026년 시점에서 매우 효율적인 이유:

1. MFA가 거의 모든 곳에 깔렸기 때문에 자격증명만 훔쳐도 쓸 수 없다.
2. 피해자는 "회사가 도입한 새 협업 앱"이라고 착각한다(권위 + 일관성).
3. 토큰은 비밀번호보다 회수 절차가 느리다(테넌트 관리자 개입 필요).

### 3.7 시나리오 설계 워크시트

```markdown
## 피싱 시나리오 설계서

| 항목 | 내용 |
| --- | --- |
| 캠페인 ID | SE-2026Q2-PH-003 |
| 대상 부서/규모 | 재무팀 22명 |
| 사용 트리거(주/보조) | 권위(CFO) / 희소성(분기 마감 D-1) |
| 발신 도메인 | finops-notice[.]example-corp[.]kr (lookalike) |
| 본문 핵심 메시지 | "분기 결산용 송금 승인 요청 — 23시까지 검토" |
| 페이로드 | M365 OAuth 동의 (Mail.Read 범위) |
| 클로져(자연 이탈) | "오늘 자정까지 검토하시면 됩니다" |
| 디브리핑 계획 | 캠페인 종료 24시간 내 부서장 → 팀원 순 안내, 익명 통계만 공유 |
| 윤리 체크 | 개인 비방 X / 가족 사칭 X / 의료 정보 X |
```

이 워크시트를 SOW에 첨부물로 합의 후 진행하는 것을 강력 권고한다.

---

## 4. 스피어피싱 페이로드 결정

페이로드 선택은 단지 "무엇이 잘 터지는가"가 아니라 **목적-위험-탐지 가능성**의 3축에서 결정된다.

### 4.1 첨부형 페이로드 옵션 비교

| 옵션 | 2026년 가용성 | 표적 환경 가정 | 리스크 |
| --- | --- | --- | --- |
| `.docm/.xlsm` 매크로 | 거의 차단 | 구식 환경에서만 의미 | 통계적 의미 거의 없음 |
| HTML smuggling (.html) | 양호 | 메일 게이트웨이 통과율 ↑ | 사용자가 브라우저로 열게 유도해야 |
| `.iso/.img` + .lnk | 중 | MOTW 우회 가능한 빌드 환경 | 최근 EDR이 잘 잡음 |
| `.svg` 안에 스크립트/링크 | 중상 | 이미지인 줄 안다는 인지 편향 활용 | 정책 차단 점차 확산 |
| OneNote `.one` | 중 | 협업 도구 친숙도 활용 | MS가 임베드 객체 차단 강화 |
| PDF + 외부 링크 | 양호 | 첨부+링크 결합 | 사용자가 브라우저로 이동해야 |

### 4.2 링크형 페이로드 옵션

- **자격증명 수집(credential harvesting):** 가장 흔함. 표적 회사의 SSO 페이지를 픽셀 단위 모사. MFA 우회를 노리려면 **AiTM(Adversary-in-the-Middle) 프록시**(예: 합법 평가 도구로서의 Evilginx) 사용 시 SOW에 명시.
- **OAuth 동의:** 표적이 M365/Google인 경우 토큰 탈취가 자격증명보다 가치가 훨씬 큼.
- **드라이브-바이(drive-by):** 브라우저/플러그인 익스플로잇. 2026년 메인스트림 브라우저 상대로는 거의 불가능에 가깝고 보통 제외.

### 4.3 왜 2026년에는 OAuth 동의가 효율적인가

- MFA 보급률이 한국 대기업 기준 90%대에 진입(추정). 자격증명 단독 가치가 떨어짐.
- 메일 게이트웨이가 첨부 IOC 시그니처 데이터베이스를 잘 갖춤. 첨부형은 차단되거나 격리됨.
- 반면 동의 화면은 **합법적 OAuth 플로우** 위에서 진행되므로 URL/도메인 평판이 깨끗하다.
- 사용자 입장에서 "Mail.Read" 같은 권한 텍스트는 읽기 어렵고 "허용" 버튼이 시각적으로 강조됨.

방어 측면에서는 (a) 관리자 동의 강제, (b) 검증된 게시자만 허용, (c) 위험 권한(Mail.Read, Files.Read.All)에 대한 알림이 핵심.

---

## 5. 비싱(전화)

### 5.1 주요 시나리오

- **콜센터 사칭:** 카드사·통신사·은행 사칭. 표적이 받은 SMS의 콜백 번호를 위조한 형태.
- **헬프데스크 사칭:** 외부에서 사내 IT 헬프데스크를 가장하여 직원의 MFA 토큰 재등록을 유도. 2022년 통신 플랫폼 업체 침해 사건과 2023년 미국 카지노 그룹 침해 사건의 핵심 벡터.
- **CEO 사칭(보이스 클로닝):** 공개된 인터뷰/기조연설 음성을 학습한 모델로 임원 음성을 합성하여 재무팀에 송금 지시.

### 5.2 프리텍스트 통화 스크립트 구조

```
성공적인 비싱 통화의 구조 (방어 인식용):

[오프닝 — 권위 확립, 5~10초]
"안녕하세요, OOO씨 맞으시죠? 저는 IT 보안팀 박OO입니다."
→ 이름을 먼저 부름으로써 본인을 알고 있다는 신호

[배경 설정 — 신뢰 구축, 20~30초]
"어제 보내드린 보안 공지 메일 확인하셨나요?
 이번 주 분기 점검 건으로 계정 확인이 필요한 분들께 연락드리고 있습니다."
→ 있을 법한 선행 이벤트 참조 (공지 실제 없어도 모호하게 언급)

[사회적 증거 삽입, 10~15초]
"팀원 분들은 대부분 오전에 완료하셨는데, 오후에 연락드리는 분들이 몇 분 남아서요."
→ 동료들이 이미 했다는 암시

[익스플로잇 — 핵심 요청, 30~60초]
"지금 인증 앱에 알림이 하나 올 텐데, 거기서 승인 눌러주시면 5분 내 완료됩니다."
→ 실제로는 공격자가 로그인 시도 중 — MFA 푸시 폭격

[클로저 — 의심 최소화]
"확인됐습니다. 감사합니다. 점검 완료 처리해 드릴게요. 좋은 하루 되세요."
→ 자연스러운 종료, 피해자가 의심할 시간 없음

[즉시 중단해야 할 신호]
- "직접 IT팀 번호로 확인해볼게요" → 검증 시도 (성공적인 방어)
- 표적이 흥분하거나 운다 → 윤리적 즉시 중단
- 표적이 다른 사람을 부른다 → 사회적 검증 시도
```

### 5.3 보이스 클로닝 — 2024~2026의 도구 수준

- 2024년 영국 엔지니어링 회사 사례에서 화상 회의의 다수 인물을 합성으로 재현해 약 350억 원대 송금이 발생했다고 보도되었다.
- 2026년 기준, 공개·반공개 모델로 **30초 분량 음성**만 있어도 자연스러운 한국어 합성이 가능. 화상까지 가짜로 만드는 것은 여전히 비용이 들지만, 음성 단독은 사실상 보편화.
- 방어 권고: "음성으로 송금 지시" 자체를 정책으로 금지. 두 명 이상의 결재자 + 별도 채널 콜백.

### 5.4 비싱 스크립트 워크시트

```markdown
## 비싱 스크립트 (헬프데스크 사칭 예시 — 평가용)

[전제 정찰]
- 표적: 김OO 차장 (재무팀, 입사 8년차)
- 사내 헬프데스크 호칭: "IT 지원실"
- 사용 중인 MFA: Authenticator 앱
- 최근 공지: "분기 보안 점검 안내" (4월 둘째 주)

[스크립트 흐름]
1. 인사 + 권위 신호
   "안녕하세요 차장님, IT 지원실 박OO입니다. 어제 보내드린 분기 보안 점검 건으로 확인 차 연락드렸습니다."
   → 일관성 트리거: 표적은 공지를 본 적 있음.

2. 사회적 증거
   "재무팀에서 이미 절반 이상 마치셨고, 차장님 계정만 점검 결과가 올라와 있지 않아서요."
   → 사회적 증거 + 약한 압박.

3. 호혜성
   "원래는 직접 방문해서 봐드려야 하는데, 바쁘실 것 같아서 5분 안에 끝내드리려고 합니다."

4. 익스플로잇
   "지금 인증 앱에 알림 하나 보내드릴 텐데, '승인' 눌러주시면 됩니다."
   → MFA 푸시 폭격(MFA fatigue) 또는 재등록 유도.

5. 클로져
   "감사합니다, 점검 완료 처리하겠습니다. 즐거운 하루 되세요."
   → 자연스럽게 종료. 의심 발생 시간 최소화.

[중단 트리거 — 즉시 종료해야 할 신호]
- 표적이 별도 채널로 확인하겠다고 함
- 표적이 가족·건강 관련 어려움을 언급
- 표적이 흥분/공포 반응을 보임 (윤리적 중단)
```

평가팀 내부적으로 "중단 트리거"는 사전에 합의해야 한다. 사람이 우는 상황까지 가서 데이터를 얻는 것은 평가가 아니라 가해다.

### 5.5 콜백 피싱(reverse vishing)

- 메일을 먼저 보낸다: "구독 결제 완료, 취소는 이 번호로."
- 표적이 직접 전화를 건다 → 신뢰도 ↑(자기 결정 편향).
- 통화에서 원격 지원 도구 설치/자격증명 누설 유도.
- 한국에서는 카드사·쇼핑몰 사칭으로 자주 등장.

---

## 6. 스미싱·메신저 피싱

### 6.1 한국에서 자주 보이는 사칭 카테고리

| 사칭 주체 | 트리거 메시지 예 | 결합되는 추가 채널 |
| --- | --- | --- |
| 택배사 | "주소 불명으로 반송 예정, 확인 요망" | 가짜 앱 설치 유도 |
| 정부24/국세청 | "민원 처리 결과 안내" | 가짜 포털 자격증명 수집 |
| 건강보험공단 | "환급금 신청 안내" | 본인인증 페이지 모사 |
| 카카오/네이버 | "로그인 알림, 본인이 아니면 차단" | OAuth 동의/계정 탈취 |
| 통신사 | "요금 미납 안내, 회선 정지 예정" | 콜백으로 비싱 결합 |

### 6.2 QR 피싱(quishing)

- 메일/포스터/식당 테이블에 붙은 QR을 가짜로 교체하거나 메일 본문에 QR 이미지로 링크를 숨김.
- 메일 게이트웨이가 텍스트 URL은 검사해도 QR 안의 URL은 못 읽는 경우가 많음(2026년에는 OCR 기반 검사 도입 진행 중).
- 사용자는 모바일로 스캔하므로 **회사 EDR이 보이지 않는 디바이스**에서 자격증명을 입력하게 됨.

### 6.3 카카오톡 1:1 피싱

- 가족·지인 사칭("폰 떨어뜨려서 새 번호야, 급한 송금 좀 부탁")이 한국에서 매우 빈번.
- 회사 내부에서는 **가짜 친구추가 → 그룹 초대 → 사내 단톡 분위기 모사** 의 흐름이 발견됨.
- 카카오워크/팀즈/슬랙 같은 사내 메신저로 침입한 뒤 1:1로 송금/링크 클릭을 유도하는 변종도 있음(계정 한 개만 탈취되면 효과 큼).

### 6.4 평가 시 주의

- 한국에서 가족 사칭 스미싱을 **모의로 보내는 것은 거의 모든 경우 부적절**하다. 트라우마를 유발한다.
- 회사 평가 범위에서는 회사 메신저/회사 도메인 안에서만 진행. 개인 기기·개인 번호로의 발송은 SOW에 명시되지 않으면 금지.

---

## 7. 프리텍스팅(페르소나 만들기)

프리텍스팅(pretexting)은 **공격자가 들고 가는 가짜 정체성과 그 정체성을 뒷받침하는 디테일의 묶음**이다.

### 7.1 페르소나 구성 요소

- 이름·소속·직급
- 사용하는 사내 용어("결재 상신", "TF", "월말 마감")
- 알고 있어야 할 프로젝트명 1~2개(공개 보도 자료에서 인용)
- 알고 있어야 할 사람 이름(상사·동료) — 단, 부정확하면 즉시 의심 받음
- 메일 서명·전화 발신번호 등 채널 일관성

### 7.2 디테일을 자연스럽게 흘리는 법

1. **먼저 듣고 나중에 말한다.** 표적이 먼저 정보를 노출하면 그것을 받아 쓰면 된다.
2. **약한 디테일부터.** "이번에 OO 프로젝트 때문에 정신 없으시죠?" → 표적이 부정/긍정으로 반응하면 보정.
3. **모르는 척 자연스럽게 빠진다.** "아 그 부분은 제가 영업팀이라 잘 모르는데"는 권위와 동시에 회피를 만든다.
4. **상호 검증 가능 신호.** 사내 인트라넷 양식, 결재 화면 캡처(공개 보도에서 발췌)는 신뢰도를 폭증시킨다.

### 7.3 물리 사회공학용 프리텍스팅

| 페르소나 | 통하는 시간대/장소 | 무엇으로 보강하는가 |
| --- | --- | --- |
| 택배기사 | 평일 오전, 1층 로비 | 박스, 송장, 모자 |
| 복합기/정수기 점검 기사 | 평일 점심 직전 | 공구 가방, 작업복, 가짜 작업지시서 |
| 면접자 | 인사팀 인터뷰 시간대 | 이력서 출력본, 안내 메일 캡처 |
| 신규 입사자 | 월요일 오전 | "오늘 첫 출근인데 출입증이 아직..." |

### 7.4 윤리·법적 한계

- **계약서 없는 물리 사회공학 절대 금지.** 출입 카드 복제, 사무실 진입은 한국에서 형사처벌 가능.
- **응급 사칭(소방관·경찰·의사) 금지.** 직군 사칭은 별도 처벌 조항이 있고 윤리적으로도 선을 넘는다.
- **개인 가족 사칭 금지.** 부모·자녀 위급 가장은 어떤 경우에도 평가 범위에서 제외.
- 평가 종료 후 **"임원 미팅"으로 이름 붙은 디브리핑 세션**을 따로 잡고, 표적이 어떻게 대응했는지 익명으로 토론.

---

## 8. 물리적·하이브리드 공격

### 8.1 USB drop / BadUSB

- **USB drop:** 회사 주차장·로비에 USB를 떨어뜨려두고 누가 PC에 꽂는지 본다. 2026년에도 약 5~15% 수준의 시도가 발생한다는 업계 보고가 꾸준하다.
- **BadUSB / HID 공격:** USB가 키보드인 척 등장하여 정해진 키 시퀀스(파워셸 다운로드 → 실행)를 입력. Rubber Ducky류 도구가 표준.
- 방어: USB 포트 정책(읽기 전용/차단), HID 화이트리스트, EDR이 빠르게 생성되는 셸을 탐지.

### 8.2 Evil Maid

- 호텔/공유 오피스에 잠시 자리를 비운 사이 노트북 BIOS·디스크에 백도어 심기.
- 풀디스크 암호화 + 시큐어 부트 + TPM 측정 정도가 기본 방어. 평가에서 evil maid 시뮬레이션은 호텔 룸 키 정책까지 포함한 SOW가 필요.

### 8.3 WiFi 사회공학

- **Karma/Evil Twin:** 회사 SSID와 같은 이름의 가짜 AP를 띄워 클라이언트가 자동 접속하게 유도.
- 캡티브 포털을 회사 SSO 화면으로 모사하면 자격증명 수집과 결합 가능.
- 평가 시 해당 평가가 **회사 부지 안 무선 영역**에 한정되도록 SOW에 위치(좌표/층) 명시.

### 8.4 출입증 스푸핑

- 저주파(125 kHz) RFID 카드(EM4100, HID Prox류)는 여전히 많은 한국 사옥에서 사용. Proxmark류 장비로 짧은 거리에서 클로닝 가능.
- 13.56 MHz 카드(MIFARE Classic 일부 변종)도 약점이 있음.
- 모바일 출입증/생체+RFID 결합으로 점진 이행 중.
- 평가 시 "어디까지 들어가는가"는 매우 민감 — 보통 **1차 출입문 인증 성공 여부**까지만 검증하고 즉시 노출.

---

## 9. 방어 인식 교육 설계

### 9.1 효과적인 피싱 인식 훈련 프레임워크

```
단계 1 — 기준선 측정 (첫 번째 캠페인)
  ■ 아무것도 모르는 상태에서 클릭률/신고율 측정
  ■ 부서별, 직급별 결과 집계
  ■ 절대 개인 식별 정보로 보고서 작성 금지

단계 2 — 타깃 교육 실시
  ■ 전체 대상: 5분 마이크로 러닝 (즉시 피드백형)
  ■ 고위험군(재무, 임원 비서): 1:1 심화 교육
  ■ 핵심 메시지: "의심스러우면 신고 버튼 누르기"
  ■ 절대 금지: "왜 클릭했어요?" 비난

단계 3 — 재측정 (90일 후)
  ■ 동일 난이도 또는 약간 높은 난이도로 재시도
  ■ 기준선 대비 개선율 측정

단계 4 — 지속적 강화 (분기 1회 + 무작위)
  ■ 시나리오 다양화: 계절/이벤트 반영
  ■ 신고 문화 강화: 신고자에게 즉각 긍정 피드백
```

### 9.2 신고 보고 템플릿

직원이 의심스러운 이메일을 발견했을 때 사용하는 표준 보고 양식입니다.

```
[피싱 의심 신고 양식]

신고 일시: ____년 ____월 ____일 ____시
신고자 소속/이름: _________________________ (보안팀만 확인, 집계 시 익명화)

[의심 이메일 정보]
발신자 이메일: _________________________________
이메일 제목: ___________________________________
수신 시각: _____________________________________
첨부파일 여부: □ 없음  □ 있음 (파일명: _______________)
링크 클릭 여부: □ 클릭 안 함  □ 클릭함  □ 정보 입력함

[의심 이유 체크]
□ 발신자 주소가 이상함
□ 링크 URL이 의심스러움
□ 긴급함을 강조함
□ 개인정보/자격증명 요구
□ 맞춤법 오류
□ 알 수 없는 첨부파일
□ 기타: _______________________________________

[조치 사항]
□ 이메일 삭제함
□ 이메일 그대로 보관 중 (포렌식 용도)
□ 이미 링크 클릭/정보 입력함 → 즉시 보안팀 연락 필요

[보안팀 연락처]
이메일: security@company.com
내선: 보안팀 (내선 ####)
긴급 핫라인: 010-####-####
```

---

## 10. 피싱 시뮬레이션 Python 도구

```python
#!/usr/bin/env python3
"""
phishing_sim_tracker.py — 피싱 시뮬레이션 결과 추적 및 분석 도구

사용법:
  # CSV 데이터 분석 및 보고서 생성
  python3 phishing_sim_tracker.py analyze campaign.csv
  
  # 특정 부서 상세 분석
  python3 phishing_sim_tracker.py analyze campaign.csv --dept 재무팀
  
  # JSON 출력
  python3 phishing_sim_tracker.py analyze campaign.csv --json

CSV 형식:
  dept,level,delivered,opened,clicked,submitted,reported
  재무팀,부장,1,1,0,0,1
  ...
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── 데이터 모델 ────────────────────────────────────────────────────────────────

@dataclass
class TargetRecord:
    """개인 수준 — 집계 시 익명화 처리"""
    dept: str
    level: str
    delivered: int
    opened: int
    clicked: int
    submitted: int
    reported: int


@dataclass
class DeptStats:
    dept: str
    delivered: int = 0
    clicked: int = 0
    submitted: int = 0
    reported: int = 0

    @property
    def click_rate(self) -> float:
        return self.clicked / self.delivered if self.delivered else 0.0

    @property
    def submit_rate(self) -> float:
        return self.submitted / self.delivered if self.delivered else 0.0

    @property
    def report_rate(self) -> float:
        return self.reported / self.delivered if self.delivered else 0.0

    @property
    def risk_level(self) -> str:
        """부서 위험 수준 판정"""
        if self.click_rate >= 0.3:
            return "HIGH"
        elif self.click_rate >= 0.15:
            return "MEDIUM"
        return "LOW"


@dataclass
class CampaignSummary:
    total_delivered: int = 0
    total_clicked: int = 0
    total_submitted: int = 0
    total_reported: int = 0
    dept_stats: dict[str, DeptStats] = field(default_factory=dict)

    @property
    def overall_click_rate(self) -> float:
        return self.total_clicked / self.total_delivered if self.total_delivered else 0.0

    @property
    def overall_submit_rate(self) -> float:
        return self.total_submitted / self.total_delivered if self.total_delivered else 0.0

    @property
    def overall_report_rate(self) -> float:
        return self.total_reported / self.total_delivered if self.total_delivered else 0.0


# ── 데이터 로딩 ────────────────────────────────────────────────────────────────

def load_campaign_csv(path: Path) -> list[TargetRecord]:
    records = []
    required_cols = {"dept", "level", "delivered", "clicked", "submitted", "reported"}

    with path.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV 파일이 비어있거나 헤더가 없습니다")

        actual_cols = set(reader.fieldnames)
        missing = required_cols - actual_cols
        if missing:
            raise ValueError(f"누락된 컬럼: {missing}")

        for i, row in enumerate(reader, 2):
            try:
                records.append(TargetRecord(
                    dept=row["dept"].strip(),
                    level=row["level"].strip(),
                    delivered=int(row["delivered"]),
                    opened=int(row.get("opened", 0)),
                    clicked=int(row["clicked"]),
                    submitted=int(row["submitted"]),
                    reported=int(row["reported"]),
                ))
            except (ValueError, KeyError) as e:
                print(f"[경고] 행 {i} 건너뜀: {e}", file=sys.stderr)

    return records


# ── 분석 ───────────────────────────────────────────────────────────────────────

def aggregate_by_dept(
    records: list[TargetRecord],
    filter_dept: Optional[str] = None,
) -> CampaignSummary:
    summary = CampaignSummary()

    for record in records:
        if filter_dept and record.dept != filter_dept:
            continue

        summary.total_delivered += record.delivered
        summary.total_clicked   += record.clicked
        summary.total_submitted += record.submitted
        summary.total_reported  += record.reported

        dept = summary.dept_stats.setdefault(record.dept, DeptStats(dept=record.dept))
        dept.delivered += record.delivered
        dept.clicked   += record.clicked
        dept.submitted += record.submitted
        dept.reported  += record.reported

    return summary


def generate_recommendations(summary: CampaignSummary) -> list[str]:
    """캠페인 결과 기반 개선 권고사항 생성"""
    recs = []

    if summary.overall_click_rate > 0.20:
        recs.append(
            f"[긴급] 전체 클릭률 {summary.overall_click_rate:.1%} — "
            f"즉각적인 인식 교육 실시 필요"
        )

    if summary.overall_submit_rate > 0.05:
        recs.append(
            f"[위험] 자격증명 입력률 {summary.overall_submit_rate:.1%} — "
            f"MFA 즉시 점검 및 계정 보안 강화"
        )

    if summary.overall_report_rate < 0.10:
        recs.append(
            f"[개선] 신고율 {summary.overall_report_rate:.1%} — "
            f"신고 버튼 가시성 개선 및 신고 장려 문화 조성"
        )
    elif summary.overall_report_rate >= 0.30:
        recs.append(
            f"[우수] 신고율 {summary.overall_report_rate:.1%} — "
            f"보안 인식 문화가 양호합니다"
        )

    # 고위험 부서 식별
    high_risk_depts = [
        s for s in summary.dept_stats.values()
        if s.risk_level == "HIGH"
    ]
    if high_risk_depts:
        dept_names = ", ".join(s.dept for s in high_risk_depts)
        recs.append(f"[우선교육] 고위험 부서: {dept_names} — 맞춤형 심화 교육 필요")

    if not recs:
        recs.append("[양호] 전반적으로 보안 인식 수준이 적절합니다. 분기 1회 정기 훈련 유지.")

    return recs


# ── 출력 ───────────────────────────────────────────────────────────────────────

def print_text_report(summary: CampaignSummary, recs: list[str]) -> None:
    border = "=" * 65
    print(f"\n{border}")
    print(f"  피싱 시뮬레이션 캠페인 결과 보고")
    print(f"  [주의] 본 보고서는 부서 단위 집계만 포함. 개인 식별 불가")
    print(border)
    print(f"\n[전체 요약]")
    print(f"  발송:           {summary.total_delivered:>6,}건")
    print(f"  클릭:           {summary.total_clicked:>6,}건  ({summary.overall_click_rate:.1%})")
    print(f"  자격증명 입력:  {summary.total_submitted:>6,}건  ({summary.overall_submit_rate:.1%})")
    print(f"  신고:           {summary.total_reported:>6,}건  ({summary.overall_report_rate:.1%})")

    print(f"\n[부서별 결과] (클릭률 내림차순)")
    print(f"  {'부서':<12} {'발송':>6} {'클릭률':>8} {'입력률':>8} {'신고율':>8} {'위험'}")
    print(f"  {'-'*60}")

    sorted_depts = sorted(
        summary.dept_stats.values(),
        key=lambda s: s.click_rate,
        reverse=True,
    )
    for s in sorted_depts:
        print(
            f"  {s.dept:<12} {s.delivered:>6,} "
            f"{s.click_rate:>7.1%} "
            f"{s.submit_rate:>7.1%} "
            f"{s.report_rate:>7.1%} "
            f"  {s.risk_level}"
        )

    print(f"\n[권고사항]")
    for rec in recs:
        print(f"  → {rec}")
    print()


def print_json_report(summary: CampaignSummary, recs: list[str]) -> None:
    output = {
        "summary": {
            "total_delivered": summary.total_delivered,
            "total_clicked": summary.total_clicked,
            "total_submitted": summary.total_submitted,
            "total_reported": summary.total_reported,
            "overall_click_rate": round(summary.overall_click_rate, 4),
            "overall_submit_rate": round(summary.overall_submit_rate, 4),
            "overall_report_rate": round(summary.overall_report_rate, 4),
        },
        "by_department": [
            {
                "dept": s.dept,
                "delivered": s.delivered,
                "click_rate": round(s.click_rate, 4),
                "submit_rate": round(s.submit_rate, 4),
                "report_rate": round(s.report_rate, 4),
                "risk_level": s.risk_level,
            }
            for s in sorted(summary.dept_stats.values(), key=lambda x: x.click_rate, reverse=True)
        ],
        "recommendations": recs,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="피싱 시뮬레이션 결과 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 phishing_sim_tracker.py analyze campaign.csv
  python3 phishing_sim_tracker.py analyze campaign.csv --dept 재무팀
  python3 phishing_sim_tracker.py analyze campaign.csv --json

CSV 형식 (헤더 필수):
  dept,level,delivered,clicked,submitted,reported
  재무팀,부장,1,1,0,0
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    analyze_p = sub.add_parser("analyze", help="캠페인 CSV 분석")
    analyze_p.add_argument("csv", type=Path, help="캠페인 결과 CSV 파일")
    analyze_p.add_argument(
        "--dept", default=None,
        help="특정 부서만 분석 (기본: 전체)"
    )
    analyze_p.add_argument(
        "--json", action="store_true",
        help="JSON 형식으로 출력"
    )
    analyze_p.add_argument(
        "--fail-if-click-above", type=float, default=None,
        help="클릭률이 이 값 초과 시 비정상 종료 (CI/CD 연동용, 예: 0.20)"
    )

    args = parser.parse_args()

    if args.cmd == "analyze":
        if not args.csv.exists():
            print(f"[오류] 파일 없음: {args.csv}", file=sys.stderr)
            sys.exit(1)

        records = load_campaign_csv(args.csv)
        if not records:
            print("[오류] 유효한 데이터가 없습니다", file=sys.stderr)
            sys.exit(1)

        summary = aggregate_by_dept(records, filter_dept=args.dept)
        recs = generate_recommendations(summary)

        if args.json:
            print_json_report(summary, recs)
        else:
            print_text_report(summary, recs)

        if args.fail_if_click_above and summary.overall_click_rate > args.fail_if_click_above:
            sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 11. 사회공학 캠페인 측정 지표

평가 산출물의 가치는 **측정 가능한 결과**에 있다. 직관적 표현("많이 클릭했다")이 아니라 수치로 만들어야 환류가 된다.

### 11.1 핵심 지표

| 지표 | 정의 | 해석 가이드 |
| --- | --- | --- |
| 도달률(delivery rate) | 발송 대비 수신 메일함 도달 | 70% 이하라면 게이트웨이 잘 막는 편 |
| 열람률(open rate) | 도달 대비 본문 열람 | 픽셀 비콘 의존, 모바일 차단으로 부정확 |
| 클릭률(click rate, CTR) | 도달 대비 링크 클릭 | 부서별 차이가 큰 지표 |
| 자격증명 입력률 | 클릭 대비 폼 제출 | 진짜 위험 신호. 5% 넘으면 빨간불 |
| MFA 우회 성공률 | 자격증명 제출 중 추가 OTP 제공 비율 | AiTM 평가 시만 측정 |
| 신고율(report rate) | 도달 대비 신고 버튼 사용 | 높을수록 좋다. 30% 이상이면 문화 좋음 |
| 평균 응답 시간(MTTR) | 발송 시각 ↔ 첫 신고 시각 | 분 단위로 좁아질수록 좋음 |
| 부서별 편차 | 부서 간 클릭률 표준편차 | 편차가 크면 교육 우선순위 명확 |

### 11.2 부서/직급 차이를 보는 KPI 대시보드(예시)

아래는 캠페인 결과 CSV에서 부서별 클릭률·신고율을 시각화하는 짧은 Python 3.10+ 스크립트다. 실제 운영 환경에서는 개인 식별자를 제거한 집계 CSV만 다루는 것을 원칙으로 한다.

```python
# se_dashboard.py — Python 3.10+
# 입력: campaign.csv (columns: dept, level, delivered, clicked, submitted, reported)
# 출력: PNG 두 장 (부서별 클릭률, 부서별 신고율)
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt


@dataclass(slots=True)
class DeptStats:
    dept: str
    delivered: int = 0
    clicked: int = 0
    submitted: int = 0
    reported: int = 0

    @property
    def click_rate(self) -> float:
        return self.clicked / self.delivered if self.delivered else 0.0

    @property
    def report_rate(self) -> float:
        return self.reported / self.delivered if self.delivered else 0.0


def load(path: Path) -> dict[str, DeptStats]:
    stats: dict[str, DeptStats] = {}
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            d = stats.setdefault(row["dept"], DeptStats(dept=row["dept"]))
            d.delivered += int(row["delivered"])
            d.clicked += int(row["clicked"])
            d.submitted += int(row["submitted"])
            d.reported += int(row["reported"])
    return stats


def plot(stats: dict[str, DeptStats], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    depts = sorted(stats.values(), key=lambda s: s.click_rate, reverse=True)

    names = [s.dept for s in depts]
    click_rates = [s.click_rate * 100 for s in depts]
    report_rates = [s.report_rate * 100 for s in depts]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, click_rates)
    ax.set_ylabel("Click rate (%)")
    ax.set_title("Phishing click rate by department")
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    fig.savefig(out_dir / "click_rate.png", dpi=140)

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, report_rates)
    ax.set_ylabel("Report rate (%)")
    ax.set_title("Phishing report rate by department")
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    fig.savefig(out_dir / "report_rate.png", dpi=140)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SE campaign KPI dashboard")
    parser.add_argument("csv", type=Path, help="aggregated campaign CSV")
    parser.add_argument("--out", type=Path, default=Path("./out"))
    args = parser.parse_args()

    stats = load(args.csv)
    plot(stats, args.out)
    print(f"saved 2 charts to {args.out.resolve()}")


if __name__ == "__main__":
    main()
```

### 11.3 무엇을 보고서에 적을 것인가

- 부서/직급 단위까지만 공개. 개인 단위 수치는 절대 공유하지 않는다.
- 클릭률만 단독으로 보지 말 것 — **신고율과 짝**으로 본다. "클릭률 18% / 신고율 4%"보다 "클릭률 18% / 신고율 32%"가 훨씬 건강한 조직이다.
- 시간축 트렌드. 분기별로 같은 부서의 변화를 추적해야 교육 효과가 보인다.
- 캠페인이 끝난 뒤 "걸린 직원이 누구냐"를 캐묻는 임원에게는 **익명 보고를 원칙으로 한다는 점을 SOW 단계에서 합의**해두는 것이 컨설턴트의 의무다.

---

## 12. 방어 측 시점

### 12.1 직원 인식 교육 디자인

- **연 1회 한 시간짜리 영상**은 효과가 미미하다는 것이 업계 컨센서스. 짧고 자주(분기 1회 5~10분 시뮬레이션)가 더 효과적.
- 시뮬레이션 직후 **마이크로 러닝**(2~3분 영상/카드)으로 즉시 피드백.
- 신고 버튼을 **원클릭**(아웃룩/Gmail 플러그인)으로 만들어 마찰을 줄인다.
- 신고자에게 즉각적 긍정 피드백("신고 잘 해주셨어요"). 클릭한 사람에게는 비난이 아닌 학습 콘텐츠.

### 12.2 SOC가 봐야 할 시그널

- 자격증명 수집 도메인 패턴: 신규 등록(<7일) + 회사명/제품명 포함 lookalike.
- 사용자가 외부 링크 클릭 후 **회사 SSO와 매우 유사한 도메인**에서 입력 폼 제출.
- M365/Google Workspace의 **OAuth 동의 이벤트**:
  - `Mail.Read`, `Mail.ReadWrite`, `Files.Read.All`, `offline_access` 같은 위험 범위.
  - 게시자 미검증(unverified publisher).
  - 관리자가 모르는 신규 앱 ID.
- 헬프데스크/IT 지원실 호칭으로 **사용자가 직접 MFA 재등록을 요청**한 케이스(이상 행위 큐로).
- 계좌 변경/송금 요청 메일에서의 **회신 주소 변경**(Reply-To와 From 도메인 불일치).

### 12.3 한국 정보보안기사 실기 관점의 통제 항목

- 메일 게이트웨이의 SPF/DKIM/DMARC 적용 상태. p=quarantine 또는 p=reject까지 가는지.
- 외부 메일 배너/외부 발신자 자동 표기.
- 첨부 파일 정책(매크로 차단, 격리 분석).
- MFA 적용 범위(VPN·SSO·관리자 콘솔 모두 포함하는가).
- 관리자 동의 전용 OAuth 정책.
- 사회공학 모의훈련 절차와 결과 보고 양식.
- 인식 교육 이수율과 지표(KPI 정의서 보유 여부).

### 12.4 정책으로 막는 것이 가장 싸다

기술 통제로 막기 어려운 사회공학 시나리오 중 다수는 **단순한 정책 한 줄**로 막힌다.

- "송금/계좌 변경은 메일·메신저로 확정하지 않는다. 등록된 번호로 콜백."
- "MFA 재등록은 헬프데스크 직접 방문 또는 영상 통화 후만 가능."
- "외부에서 받은 OAuth 동의 요청은 IT 보안팀 사전 승인 필수."

이 세 줄을 그대로 게시하는 것만으로도 BEC·헬프데스크 사칭·OAuth 동의 피싱의 상당 부분을 차단할 수 있다.

---

## 13. 마무리 — 다음 문서 예고

이 문서는 시나리오·심리·측정의 관점에서 사회공학을 다뤘다. 그러나 실제 캠페인을 운영하려면 **메일 인프라**(도메인 등록, 메일 서버, 평판, SPF/DKIM/DMARC 정합), **랜딩 페이지 호스팅**, **EDR/메일 게이트웨이 회피** 같은 운영적 디테일이 필요하다.

다음 문서 **33-04. 피싱 인프라와 회피 — 도메인·메일 서버·랜딩 페이지의 운영**에서 이어진다.

---

### 부록 A — 사회공학 평가 SOW 체크리스트(요약)

- [ ] 평가 기간 시작/종료 일시 (분 단위까지)
- [ ] 표적 도메인·부서·인원 범위
- [ ] 허용된 채널(메일/SMS/전화/물리/메신저)
- [ ] 금지 페르소나(가족 사칭/응급 사칭/의료 정보)
- [ ] 페이로드 종류(자격증명 수집/OAuth 동의/AiTM 사용 여부)
- [ ] 데이터 보관·폐기 기간
- [ ] 디브리핑 일정과 양식
- [ ] 보고 단위(부서/직급/익명)
- [ ] 비상 중단(stop) 절차와 연락책임자
- [ ] 법무·인사·CISO 사전 승인 서명

### 부록 B — 평가 종료 후 24시간 내 해야 하는 일

1. 사용한 도메인·전화번호·발신 인프라의 **즉시 비활성화**.
2. 수집된 자격증명·토큰의 **즉시 무력화 요청**(고객 IT가 비밀번호/토큰 회수).
3. 캠페인 메트릭 집계(개인 식별자 제거 후).
4. 디브리핑 메일 또는 사내 공지 초안 전달.
5. 평가팀 내부 회고: 무엇이 윤리적 경계에 닿았는가, 다음에 어떻게 다르게 할 것인가.

사회공학은 사람을 도구처럼 보이게 만들지만, 평가의 목적은 사람을 보호하는 데 있다. 측정·교육·정책 세 축이 같이 움직여야 의미가 있다.

### 부록 C — 자주 마주치는 윤리 딜레마와 권고 응답

| 상황 | 컨설턴트 권고 응답 |
| --- | --- |
| 임원이 "누가 클릭했는지 명단 달라"고 함 | SOW 합의대로 익명 집계만 제공. 인사적 불이익 방지가 합의 사항임을 환기 |
| 표적이 통화 중 울거나 패닉 반응 | 즉시 시나리오 종료, 평가임을 정중히 고지, 기록은 익명화 후 폐기 |
| 가족 사칭 시나리오를 고객사가 요청 | 거절. 트라우마 위험과 법적 리스크를 설명하고 대안(권위/희소성 결합) 제시 |
| 평가 중 진짜 침해 흔적을 발견 | 평가 즉시 중단, 사전 합의된 비상 연락망으로 IR 트리거 |
| 표적이 평가 사실을 사전에 누군가에게 들어 알고 있음 | 부서 단위로 배제하거나 캠페인을 다른 시나리오로 교체. 데이터 오염 방지 |
| 고객사가 결과 수치를 부풀려 달라고 요청 | 거절. 컨설턴트 명의의 보고서는 사실에만 기반함을 명시 |

### 부록 D — 시뮬레이션 결과 해석 시 흔한 실수

- **"클릭률이 낮다 = 문화가 좋다"는 단순 해석.** 시나리오 난이도가 낮았을 수 있다. 동일한 표적군에 대해 분기별로 난이도를 조정하면서 추적해야 의미가 있다.
- **"신고율 100%를 목표로 하자"는 비현실적 목표.** 신고율은 30~50%만 되어도 글로벌 상위권이다. 100%는 신고 채널의 노이즈를 의미할 수 있다.
- **부서별 비교만 하는 보고서.** 신입/경력/직군별 인지 차이가 더 설명력이 있을 수 있다.
- **단발성 캠페인.** 1년에 한 번 점검하는 것은 점검이 아니라 의례다. 분기 1회 + 무작위 시점 1회 추가가 최소선.
- **공격자 관점만 적힌 보고서.** "이렇게 뚫었다"만 적고 "이렇게 막을 수 있다"가 없는 보고서는 절반짜리.

---

<a name="english"></a>

# 33-03. Social Engineering Attack Techniques — Design and Measurement of Phishing, Vishing, and Pretexting

> One-line summary: Attacks targeting people are scenarios, not technology. Scenarios are the product of reconnaissance data and psychological triggers, and results must be fed back through measurement and education.

## Before We Begin — A Note on Tone

This document is written for penetration testing consultants to reference when conducting social engineering assessments **within a contracted scope**. All scenarios, scripts, and personas in this document must be interpreted in the context of lawful assessments (red team engagements, phishing simulations).

Social engineering ultimately involves deceiving people. A poorly designed campaign causes employees to self-blame, leads to retaliatory HR actions, and in severe cases can lead to serious consequences including depression and self-harm. A consultant's ethics begin with "not shaming the target." If you haven't designed the post-campaign debriefing before starting, you should not use any technique in this document.

---

## 1. Social Engineering Psychology — The Six Principles

Social engineering scripts exploit six generalized principles of persuasion. Relying on just one makes the scenario feel awkward.

| Principle | How It Works | Phishing/Vishing Mapping | Defense Signal |
| --- | --- | --- | --- |
| Reciprocity | Pressure to return what was received | "Employee benefit points" mail, "I'm already checking to help you" | Unexplained gifts/benefits |
| Commitment | Tendency to stay consistent with prior agreement | Short survey → credential input; small info (DOB) → big info (OTP) | Being pressured using past agreement |
| Social Proof | Signal that others are doing it | "4 of 5 team members already completed this check" | Unverifiable "everyone is doing it" claims |
| Authority | Compliance with rank or expertise | CEO/CISO impersonation BEC, government agency vishing | Authority claims without identity verification |
| Liking | Weak resistance to friendly/similar people | Same school/hometown keywords in LinkedIn outreach | Strangers suddenly emphasizing shared traits |
| Scarcity | Time or opportunity constraints | "Account locked in 30 minutes," "Send today" | Artificial urgency that prevents verification |

---

## 2. Key Attack Techniques Overview

- **Phishing**: Email-based attacks using deceptive messages
- **Spear Phishing**: Targeted phishing using personalized reconnaissance data
- **Whaling**: Spear phishing targeting C-level executives
- **BEC (Business Email Compromise)**: Executive/vendor impersonation for financial fraud
- **Vishing**: Voice-based social engineering (phone calls)
- **Smishing**: SMS-based phishing
- **Pretexting**: Creating a fabricated identity/scenario to gain trust
- **Quishing**: QR code-based phishing that bypasses email URL filters

---

## 3. Phishing Email Anatomy

Understanding the structure of a phishing email helps both attackers who design them and defenders who need to spot them.

```
[Phishing Email Dissection]

Sender:      ceo@examp1e-corp.com  ← "l" replaced with "1" (visual spoofing)
             OR ceo@example.com.attackerdomain.com (subdomain trick)

Subject:     [URGENT] Q4 Approval Required — Due 6PM Today
             ↑ Scarcity + Authority combined

Display Name: "CEO John Smith" <ceo@examp1e-corp.com>
              ↑ Real name shown, only email domain differs

Body Structure:
  ┌─────────────────────────────────────────────┐
  │ [Company logo — pixel-perfect copy]          │
  │                                             │
  │ Hi [Name],                    ← personalized│
  │                                             │
  │ Urgent approval needed for Q4 reconciliation│ ← authority + scarcity
  │ Account re-authentication required per      │ ← commitment (fake prior notice)
  │ yesterday's security announcement.          │
  │                                             │
  │ [Approve Now]  ← button hiding real URL     │
  │                                             │
  │ Account will be locked if not done by 18:00 │ ← scarcity amplified
  │                                             │
  │ CEO, John Smith                             │
  │ Direct: +1-555-xxx-xxxx                     │
  └─────────────────────────────────────────────┘

Detection Checklist:
  [ ] Check sender domain spelling carefully (hover)
  [ ] Hover over button to see real destination URL
  [ ] Verify announcement through official company channels
  [ ] Does the urgency prevent you from thinking?
```

---

## 4. Spear Phishing vs Vishing vs Smishing Comparison

| Aspect | Spear Phishing | Vishing | Smishing |
|--------|---------------|---------|---------|
| Channel | Email | Phone/Voice | SMS |
| Personalization | High (name, projects, manager) | Medium-High | Low-Medium |
| Technical barrier | Low (email sending) | Medium (caller ID spoofing) | Low |
| Detection difficulty | Medium (header analysis possible) | High (real-time, no record) | Low (SMS filters) |
| Success rate | 15-25% | 40-60% | 5-10% |
| Primary targets | General employees, finance | IT helpdesk, executive assistants | General public |
| Key defense | Gateway + training | Verification procedure + policy | No-click education |

---

## 5. BEC (Business Email Compromise) Playbook

BEC is far more dangerous than ordinary phishing because it looks legitimate — no malware attachments.

```
BEC Attack Playbook (for defensive understanding):

Phase 1 — Reconnaissance (2-4 weeks)
  ■ Map executives, titles from LinkedIn
  ■ Study transaction patterns from public financial reports
  ■ Register lookalike domain (typosquatting)
    e.g.: example.com → examp1e.com, example-corp.com

Phase 2 — Entry (1-3 days)
  ■ Option A: Directly compromise executive email account
  ■ Option B: Send impersonation email from lookalike domain
  ■ Option C: Compromise legitimate vendor email, inject into conversation

Phase 3 — Exploitation (timing is critical)
  ■ Attack 1-3 days before quarter end (finance team overwhelmed)
  ■ During executive travel/vacation (verification harder)
  ■ "Account number has changed" or "urgent wire transfer"
  ■ Amount: start small to test, then escalate

Phase 4 — Concealment
  ■ Maintain access as long as possible before victim notices
  ■ Forge "payment received" confirmation emails
  ■ International account → multiple transfers to complicate tracing

Defense:
  ■ All account changes confirmed by callback to SAVED number (mandatory)
  ■ Transfers above threshold require 2+ approvers (dual control)
  ■ Auto-append "[EXTERNAL]" banner to all external emails
  ■ Domain monitoring: alerts for lookalike domain registrations
```

---

## 6. Vishing Pretext Call Script Structure

```
Successful vishing call structure (for defensive awareness):

[Opening — Establish authority, 5-10 seconds]
"Hello, is this [Name]? This is Alex from IT Security."
→ Using their name signals you know who they are

[Background — Build credibility, 20-30 seconds]
"Did you see the security notification email we sent yesterday?
 We're reaching out to people whose accounts need verification
 as part of this quarter's security review."
→ References a plausible prior event (doesn't need to be real)

[Social proof injection, 10-15 seconds]
"Most of your team completed this in the morning — we're just
 following up with the remaining few this afternoon."
→ Implies colleagues already complied

[Exploitation — Core request, 30-60 seconds]
"You'll receive a notification in your auth app — just tap
 Approve and we'll have you done in under 5 minutes."
→ Attacker is actually attempting login — MFA push bombing

[Closer — Minimize suspicion]
"All set. Thank you so much. Have a great afternoon!"
→ Natural exit, victim has no time to reconsider

[Stop signals — Immediate termination required]
- "Let me call the IT number I have on file" → successful defense
- Target becomes upset or distressed → ethical immediate stop
- Target asks to consult with another person → social verification
```

---

## 7. Defense Awareness Training Framework

### Effective Phishing Awareness Program Design

```
Phase 1 — Baseline Measurement (first campaign)
  ■ Measure click rate / report rate with no prior training
  ■ Aggregate by department and seniority level
  ■ Never create individual-identifying reports

Phase 2 — Targeted Training
  ■ All staff: 5-minute micro-learning with immediate feedback
  ■ High-risk groups (finance, executive assistants): 1:1 deep training
  ■ Core message: "If in doubt, click the Report button"
  ■ Strictly forbidden: shaming people who clicked

Phase 3 — Re-measurement (90 days later)
  ■ Run same or slightly harder scenario
  ■ Measure improvement vs. baseline

Phase 4 — Continuous Reinforcement (quarterly + random)
  ■ Vary scenarios: tie to seasons/events
  ■ Reward reporters: immediate positive feedback
```

### Incident Reporting Template

```
[Suspicious Email Report Form]

Date/Time of Report: ________________
Reporter Department: ________________ (security team only, anonymized in aggregate)

[Suspicious Email Information]
Sender Email: _______________________________________
Email Subject: ______________________________________
Time Received: ______________________________________
Attachment: [ ] None  [ ] Present (filename: _____________)
Link Clicked: [ ] No  [ ] Yes  [ ] Yes, entered information

[Reason for Suspicion]
[ ] Sender address looks wrong
[ ] Link URL looks suspicious
[ ] Urgency/pressure to act immediately
[ ] Requesting credentials or personal information
[ ] Spelling/grammar errors
[ ] Unknown or unexpected attachment
[ ] Other: _________________________________________

[Action Taken]
[ ] Deleted the email
[ ] Preserved the email (for forensics)
[ ] Already clicked link / submitted information → Contact security team immediately

[Security Team Contact]
Email: security@company.com
Extension: Security Team (ext. ####)
Emergency Hotline: +1-555-####-####
```

---

## 8. Phishing Simulation Python Tool

```python
#!/usr/bin/env python3
"""
phishing_sim_tracker.py — Phishing simulation result tracking and analysis

Usage:
  python3 phishing_sim_tracker.py analyze campaign.csv
  python3 phishing_sim_tracker.py analyze campaign.csv --dept Finance
  python3 phishing_sim_tracker.py analyze campaign.csv --json

CSV format (headers required):
  dept,level,delivered,clicked,submitted,reported
  Finance,Manager,1,1,0,0
  ...
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TargetRecord:
    dept: str
    level: str
    delivered: int
    opened: int
    clicked: int
    submitted: int
    reported: int


@dataclass
class DeptStats:
    dept: str
    delivered: int = 0
    clicked: int = 0
    submitted: int = 0
    reported: int = 0

    @property
    def click_rate(self) -> float:
        return self.clicked / self.delivered if self.delivered else 0.0

    @property
    def submit_rate(self) -> float:
        return self.submitted / self.delivered if self.delivered else 0.0

    @property
    def report_rate(self) -> float:
        return self.reported / self.delivered if self.delivered else 0.0

    @property
    def risk_level(self) -> str:
        if self.click_rate >= 0.3:
            return "HIGH"
        elif self.click_rate >= 0.15:
            return "MEDIUM"
        return "LOW"


@dataclass
class CampaignSummary:
    total_delivered: int = 0
    total_clicked: int = 0
    total_submitted: int = 0
    total_reported: int = 0
    dept_stats: dict[str, DeptStats] = field(default_factory=dict)

    @property
    def overall_click_rate(self) -> float:
        return self.total_clicked / self.total_delivered if self.total_delivered else 0.0

    @property
    def overall_submit_rate(self) -> float:
        return self.total_submitted / self.total_delivered if self.total_delivered else 0.0

    @property
    def overall_report_rate(self) -> float:
        return self.total_reported / self.total_delivered if self.total_delivered else 0.0


def load_campaign_csv(path: Path) -> list[TargetRecord]:
    records = []
    with path.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 2):
            try:
                records.append(TargetRecord(
                    dept=row["dept"].strip(),
                    level=row["level"].strip(),
                    delivered=int(row["delivered"]),
                    opened=int(row.get("opened", 0)),
                    clicked=int(row["clicked"]),
                    submitted=int(row["submitted"]),
                    reported=int(row["reported"]),
                ))
            except (ValueError, KeyError) as e:
                print(f"[Warning] Skipping row {i}: {e}", file=sys.stderr)
    return records


def aggregate_by_dept(
    records: list[TargetRecord],
    filter_dept: Optional[str] = None,
) -> CampaignSummary:
    summary = CampaignSummary()
    for record in records:
        if filter_dept and record.dept != filter_dept:
            continue
        summary.total_delivered += record.delivered
        summary.total_clicked   += record.clicked
        summary.total_submitted += record.submitted
        summary.total_reported  += record.reported
        dept = summary.dept_stats.setdefault(record.dept, DeptStats(dept=record.dept))
        dept.delivered += record.delivered
        dept.clicked   += record.clicked
        dept.submitted += record.submitted
        dept.reported  += record.reported
    return summary


def generate_recommendations(summary: CampaignSummary) -> list[str]:
    recs = []
    if summary.overall_click_rate > 0.20:
        recs.append(
            f"[URGENT] Overall click rate {summary.overall_click_rate:.1%} — "
            f"Immediate awareness training required"
        )
    if summary.overall_submit_rate > 0.05:
        recs.append(
            f"[CRITICAL] Credential submission rate {summary.overall_submit_rate:.1%} — "
            f"Review MFA coverage and account security immediately"
        )
    if summary.overall_report_rate < 0.10:
        recs.append(
            f"[IMPROVE] Report rate {summary.overall_report_rate:.1%} — "
            f"Improve report button visibility and promote reporting culture"
        )
    elif summary.overall_report_rate >= 0.30:
        recs.append(
            f"[GOOD] Report rate {summary.overall_report_rate:.1%} — "
            f"Security awareness culture is healthy"
        )
    high_risk = [s for s in summary.dept_stats.values() if s.risk_level == "HIGH"]
    if high_risk:
        names = ", ".join(s.dept for s in high_risk)
        recs.append(f"[PRIORITY TRAINING] High-risk departments: {names}")
    if not recs:
        recs.append("[GOOD] Overall security awareness level is adequate. Maintain quarterly drills.")
    return recs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phishing simulation result analysis tool"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    analyze_p = sub.add_parser("analyze", help="Analyze campaign CSV")
    analyze_p.add_argument("csv", type=Path)
    analyze_p.add_argument("--dept", default=None)
    analyze_p.add_argument("--json", action="store_true")
    analyze_p.add_argument("--fail-if-click-above", type=float, default=None)
    args = parser.parse_args()

    if args.cmd == "analyze":
        records = load_campaign_csv(args.csv)
        summary = aggregate_by_dept(records, filter_dept=args.dept)
        recs = generate_recommendations(summary)

        if args.json:
            output = {
                "summary": {
                    "total_delivered": summary.total_delivered,
                    "overall_click_rate": round(summary.overall_click_rate, 4),
                    "overall_submit_rate": round(summary.overall_submit_rate, 4),
                    "overall_report_rate": round(summary.overall_report_rate, 4),
                },
                "by_department": [
                    {"dept": s.dept, "click_rate": round(s.click_rate, 4),
                     "risk_level": s.risk_level}
                    for s in sorted(summary.dept_stats.values(),
                                    key=lambda x: x.click_rate, reverse=True)
                ],
                "recommendations": recs,
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"\nPhishing Campaign Results (department-level only — no individual identification)")
            print(f"Total delivered: {summary.total_delivered:,}")
            print(f"Click rate:      {summary.overall_click_rate:.1%}")
            print(f"Submit rate:     {summary.overall_submit_rate:.1%}")
            print(f"Report rate:     {summary.overall_report_rate:.1%}")
            print(f"\nRecommendations:")
            for rec in recs:
                print(f"  → {rec}")

        if args.fail_if_click_above and summary.overall_click_rate > args.fail_if_click_above:
            sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 9. Measurement and Feedback Loop

A social engineering assessment without measurement is just half the job:

| Metric | Definition | Interpretation |
|--------|-----------|----------------|
| Delivery rate | Mail reaching inbox vs. sent | Below 70% means gateway is effective |
| Click rate (CTR) | Clicks vs. delivered | Key risk indicator by department |
| Credential submit rate | Form submissions vs. delivered | Real danger sign — flag at >5% |
| Report rate | Reports vs. delivered | Higher is better — 30%+ is excellent |
| Mean time to first report | Time from send to first report | Shorter is better |

---

## 10. Defense Policy — Three Lines That Stop Most Attacks

Many social engineering scenarios that are technically hard to block are stopped by simple policy:

1. **"Wire transfers and account changes are never confirmed by email or messenger. Callback to a saved number only."**
2. **"MFA re-enrollment requires in-person helpdesk visit or video call."**
3. **"Any OAuth consent request received externally requires prior IT Security team approval."**

Posting just these three lines can block a significant portion of BEC, helpdesk impersonation, and OAuth consent phishing attacks.

---

Finally, a social engineering assessment is **borrowing people's trust to assess trust**. When the assessment ends, targets should feel "the company was trying to educate me, and I can respond better next time" — not "I was stupid." An assessment that fails to achieve this is a failure no matter how impressive the report numbers are.
