> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 한국 정보보안 관련 법령 완전 정리

## 0. 초보자를 위한 개념 이해

### 정보보안 법령이란?

**정보보안 법령**은 개인정보 보호, 정보통신 보안, 금융 보안 등 분야별로 조직이 지켜야 할 의무사항을 규정한 법률입니다. 보안 담당자는 관련 법령을 이해하고 컴플라이언스를 유지해야 합니다.

**왜 배우는가:**
```
법령 위반 시 결과:
  개인정보보호법 위반 → 최대 3억원 과징금
  정보통신망법 위반 → 형사처벌 가능
  ISMS 미인증 (의무 대상) → 과태료

보안 담당자 필수:
  - 어떤 법이 우리 조직에 적용되는가
  - 어떤 기술적·관리적 조치가 필요한가
```

### 핵심 법령 정리

```
한국 정보보안 법령 체계:

1. 개인정보보호법 (PIPL)
   - 적용: 개인정보 처리하는 모든 기관·기업
   - 핵심: 수집 최소화, 동의 획득, 파기 의무
   - 감독: 개인정보보호위원회

2. 정보통신망법
   - 적용: 정보통신서비스 제공자
   - 핵심: 침해 방지 기술적 조치
   - 감독: 방송통신위원회

3. 정보보안관리체계 (ISMS-P)
   - 의무 대상: 매출 100억 이상, 사용자 100만 이상
   - 인증: 3년마다 갱신
   - 통제 항목: 80여 가지

4. 전자금융거래법
   - 적용: 금융기관·전자금융업자
   - 핵심: 이상 거래 탐지, 암호화 의무
```

### 필요한 도구
- **개인정보보호 포털**: 법령 정보 검색
- **KISA 가이드라인**: 기술적 보호 조치 기준
- **ISO 27001**: 국제 정보보안 표준 (ISMS 참고)

### 기초 개념 예제
```
ISMS-P 인증 단계:

1. 인증 범위 정의
   어떤 시스템/서비스가 인증 대상인가?

2. 갭 분석
   현재 보안 수준 vs 인증 기준 비교

3. 보완 조치
   미흡한 항목 개선

4. 심사 신청
   KISA 또는 인증기관에 신청

5. 현장 심사
   서류 검토 + 현장 인터뷰

6. 인증서 발급
   → 유효기간 3년, 매년 사후 심사
```

---

## 정보보안 법령 체계 개요

한국의 정보보안 관련 법령은 크게 개인정보 보호, 정보통신 보안, 금융 보안, 클라우드·인프라 보안 영역으로 구분된다. 각 법령은 특정 주체와 상황에 맞는 의무를 부과하며, 위반 시 과태료 및 형사처벌이 병과될 수 있다.

### 주요 법령 체계

```
정보보안 관련 법령
├── 개인정보보호법 (개인정보보호위원회)
├── 정보통신망 이용촉진 및 정보보호 등에 관한 법률 (정보통신망법)
│   └── 주관: 과학기술정보통신부, 방송통신위원회
├── 전자금융거래법 (금융위원회)
├── 클라우드컴퓨팅 발전 및 이용자 보호에 관한 법률 (클라우드컴퓨팅법)
├── 국가정보화 기본법
├── 전자서명법
└── 신용정보의 이용 및 보호에 관한 법률 (신용정보법)
```

---

## 정보통신망법 핵심 조항

### 법률 정식 명칭
정보통신망 이용촉진 및 정보보호 등에 관한 법률

### 주요 적용 대상
- 정보통신서비스 제공자 (포털, SNS, 쇼핑몰 등)
- 정보통신망을 이용하여 서비스를 제공하는 사업자

### 핵심 조항 요약

#### 제22조: 개인정보의 수집·이용 동의
- 이용자의 동의 없이 개인정보 수집·이용 금지
- 동의 시 고지 사항: 수집 항목, 이용 목적, 보유 기간, 거부 권리
- 필수/선택 항목 구분하여 동의 받을 것

#### 제24조: 개인정보의 제3자 제공 금지
- 이용자 동의 없이 제3자 제공 금지
- 예외: 법률 규정, 수사기관 요청(영장 필요), 급박한 위험

#### 제28조: 개인정보의 보호 조치
정보통신서비스 제공자의 의무 보호 조치:
1. **관리적 조치**: 내부 관리 계획 수립, 임직원 교육
2. **기술적 조치**: 접근 제어, 암호화, 접속 기록 보관
3. **물리적 조치**: 서버실 출입 통제, 잠금 장치

#### 제28조의2: 개인정보의 암호화
- 주민등록번호, 비밀번호, 바이오정보 암호화 의무
- 고유식별정보 저장 시 암호화 필수

#### 제45조: 정보보호 조치
정보통신서비스 제공자는 다음 조치를 이행해야 한다:
- 정보보호 최고책임자(CISO) 지정
- 정보보호 관리체계(ISMS) 인증 (의무 대상)
- 취약점 점검 및 보완

#### 제45조의3: 정보보호 최고책임자(CISO) 지정
- CISO 지정 의무 대상: 매출액 100억 원 이상 정보통신서비스 제공자
- CISO 자격 요건: 정보보호 관련 학위 또는 경력
- CISO는 안전행정부 장관에게 신고

#### 제47조: 정보보호 관리체계(ISMS) 인증
의무 인증 대상:
- 정보통신서비스 제공자: 매출액 100억 원 이상 또는 일평균 이용자 100만 명 이상
- 집적정보통신시설(IDC) 운영자
- 클라우드 컴퓨팅 서비스 제공자 (일부)

#### 제48조: 침해사고 신고
- **신고 의무**: 침해사고 발생 시 지체없이(24시간 이내) KISA 신고
- 신고 내용: 피해 현황, 발생 원인, 조치 사항
- 신고 방법: 인터넷침해대응센터(KISA 118), 온라인 신고

#### 제48조의4: 침해사고의 원인 분석
- 대규모 침해사고 발생 시 KISA의 원인 분석 지원 요청 가능
- 정부는 침해사고 원인 분석을 위한 조사 가능

#### 제49조의2: 악성 프로그램 유포 금지
- 악성 프로그램 제작, 유포, 수입, 유통 금지
- 타인의 정보시스템에 무단으로 악성 프로그램을 전달하거나 유포 금지

#### 제50조~제52조: 스팸 및 광고성 정보 전송
- 수신자 동의 없이 영리 목적 광고 전송 금지
- 야간(오후 9시~오전 8시) 광고 전송 금지
- 수신 거부 방법 명시 의무

---

## 개인정보보호법 주요 내용

### 법률 적용 범위
- 개인정보를 처리하는 공공기관, 기업, 단체, 개인 모두 적용
- 5인 이상 사업장은 원칙적으로 모두 적용

### 개인정보 처리 원칙 (제3조)

1. **수집 제한 원칙**: 목적에 필요한 최소한의 개인정보만 수집
2. **목적 명확화 원칙**: 수집 목적 명확히 특정
3. **목적 외 이용·제공 금지**: 수집 목적 범위 내에서만 처리
4. **정확성 원칙**: 개인정보를 최신 상태로 정확하게 유지
5. **안전성 확보 원칙**: 유출·변조·훼손 방지를 위한 안전 조치
6. **투명성 원칙**: 처리 방침 공개, 열람·수정 권리 보장
7. **사생활 최소 침해 원칙**: 개인의 사생활 최소한으로 침해

### 정보주체의 권리 (제4조)

| 권리 | 내용 |
|------|------|
| 열람권 | 자신의 개인정보 처리 현황 열람 요구 |
| 정정·삭제권 | 부정확한 개인정보 정정 또는 삭제 요구 |
| 처리 정지권 | 개인정보 처리 정지 요구 |
| 손해배상청구권 | 개인정보 침해로 인한 손해 배상 청구 |
| 동의 철회권 | 개인정보 수집·이용·제공 동의 언제든지 철회 |

### 2023년 개정 주요 내용

#### 1. 개인정보 유출 신고 기준 강화
- **개정 전**: 1만 명 이상 유출 시 정부 기관 신고
- **개정 후**: **1천 명 이상** 개인정보 유출 시 **72시간 이내** 개인정보보호위원회에 신고
- 즉각적인 정보주체 통지 의무

#### 2. 이동의 자유 권리 도입 (개인정보 이동권)
- 정보주체는 자신의 개인정보를 다른 사업자에게 전송 요구 가능
- 금융, 의료 등 분야별 단계적 시행

#### 3. 자동화된 의사결정 거부권
- 알고리즘, AI 기반 완전 자동화된 의사결정에 대한 거부 또는 설명 요구 권리

#### 4. 아동 개인정보 특례 강화
- 만 14세 미만 아동의 개인정보: 법정대리인 동의 필수
- 아동 맞춤형 개인정보 처리방침 작성 의무

#### 5. 과징금 기준 강화
- 개정 전: 위반 행위 관련 매출액 3% 이하
- 개정 후: 전체 매출액 **3%** 이하 (상한 상향, 억제 효과 강화)

### 민감정보 처리 제한 (제23조)

민감정보 항목:
- 사상·신념
- 노동조합·정당 가입·탈퇴
- 정치적 견해
- 건강·성생활 정보
- 유전정보
- 범죄경력 정보
- **생체정보** (2020년 추가): 지문, 홍채, 얼굴 등

처리 조건: 별도 동의 또는 법률 특별 규정

### 고유식별정보 처리 제한 (제24조)

고유식별정보 항목:
- 주민등록번호
- 여권번호
- 운전면허번호
- 외국인등록번호

처리 조건: 별도 동의 또는 법령 규정
저장 시: **암호화 필수** (복호화 가능한 암호화 허용, 단방향 해시 외)

### 개인정보 파기 (제21조)
- 보유 기간 경과 또는 처리 목적 달성 시 **5일 이내** 파기
- 파기 방법: 전자적 파일 - 복원 불가능한 방법, 서면 - 파쇄·소각

---

## 전자금융거래법 보안 요구사항

### 적용 대상
- 금융회사 (은행, 증권사, 보험사, 카드사)
- 전자금융업자 (간편결제, 전자화폐, P2P 금융)

### 주요 보안 의무

#### 전자금융거래 보안 요구사항 (제21조)

1. **접근 제어**: 인터넷뱅킹 등 접근 권한 제한
2. **암호화**: 금융정보 전송·저장 시 암호화
3. **인증**: 공인전자서명, OTP, 생체인증 등 강화 인증
4. **이상 거래 탐지**: FDS(Fraud Detection System) 운영
5. **로그 보관**: 거래 로그 5년 이상 보관

#### 망분리 의무 (전자금융감독규정)

**물리적 망분리 의무 대상:**
- 자산 2조 원 이상 금융회사
- 일평균 이용자 100만 명 이상 전자금융업자

**논리적 망분리 허용 대상:**
- 소규모 금융기관 (자산 2조 원 미만)
- 핀테크 기업 (일정 요건 충족 시)

**망분리 기준:**
- 업무망(내부망)과 인터넷망(외부망) 완전 분리
- 데이터 이동 시 전용 단방향 시스템 사용
- 개발·테스트 환경과 운영 환경 분리

#### 전자금융 사기 예방 시스템 (FDS)
- 이상 거래 실시간 탐지 및 차단
- 비정상 접속 패턴 모니터링 (다중 접속, 해외 접속 등)
- 고액 이체 시 추가 인증

#### 보안 프로그램 설치 강제 금지
- 2023년부터 금융기관의 보안 프로그램 강제 설치 금지
- 대신 표준 인증 방식으로 전환 유도

---

## 클라우드컴퓨팅법

### 법률 정식 명칭
클라우드컴퓨팅 발전 및 이용자 보호에 관한 법률

### 클라우드 서비스 보안 의무

#### 공공기관 클라우드 이용 기준 (제20조의2)
- 공공기관은 클라우드 서비스 이용 가능
- **국가 클라우드 보안 인증(CSAP)** 필수
- 민감정보: 전용(Private) 또는 하이브리드 클라우드

#### CSAP(Cloud Security Assurance Program) 등급

| 등급 | 대상 | 요구 수준 |
|------|------|----------|
| 상 | 비밀 이상 정보 처리 | 물리적 망분리, 전용 클라우드 |
| 중 | 민감 공공데이터 | 논리적 망분리, 전용 존 |
| 하 | 일반 공공데이터 | 표준 보안 요구사항 |

#### 클라우드 서비스 제공자 의무
- 이용자 데이터의 국내 저장 (별도 동의 없이 해외 이전 금지)
- 서비스 중단 시 이용자에게 사전 통지 (30일 전)
- 계약 종료 시 이용자 데이터 반환 또는 파기

---

## 망분리 의무화 대상 및 기준

### 망분리 관련 법령 근거

| 법령 | 대상 | 기준 |
|------|------|------|
| 전자금융감독규정 | 금융회사, 전자금융업자 | 자산 2조 원 또는 이용자 100만 명 이상 |
| 개인정보보호법 시행령 | 개인정보처리자 | 100만 명 이상 개인정보 처리 |
| 정보통신망법 | 정보통신서비스 제공자 | 일정 규모 이상 사업자 |
| 공공기관 정보보안 지침 | 공공기관 | 전 공공기관 (단계별 적용) |

### 망분리 구현 방식

#### 물리적 망분리
- 업무용 PC와 인터넷용 PC 별도 구비
- 네트워크 케이블, 스위치 완전 분리
- 정보 이동 시 승인된 매체 사용 (USB 등)
- 비용: 높음 / 보안성: 최상

#### 논리적 망분리 (VDI 방식)
- 하나의 PC에서 가상 데스크탑 환경으로 분리
- 업무망 가상 머신과 인터넷망 완전 분리
- 데이터 복사·붙여넣기 제한
- 비용: 중간 / 보안성: 높음

### 망분리 의무 위반 시 제재
- 전자금융감독규정 위반: 기관 경고, 임원 문책
- 개인정보보호법 위반: 과태료 최대 3천만 원
- 반복 위반: 영업 정지, 인가 취소 가능

---

## 과태료 및 형사처벌 기준

### 개인정보보호법 과태료 및 처벌

#### 형사처벌 (벌칙)

| 위반 사항 | 처벌 |
|----------|------|
| 개인정보 불법 수집·처리 | 5년 이하 징역 또는 5천만 원 이하 벌금 |
| 동의 없이 민감정보 처리 | 5년 이하 징역 또는 5천만 원 이하 벌금 |
| 개인정보 불법 제3자 제공 | 5년 이하 징역 또는 5천만 원 이하 벌금 |
| 개인정보 유출 신고 미이행 | 3천만 원 이하 과태료 |
| 안전 조치 의무 미이행 | 3천만 원 이하 과태료 |
| 열람 요구 거부 | 3천만 원 이하 과태료 |

#### 과징금
- **개인정보 대규모 유출** 또는 **안전 조치 미이행**으로 인한 침해
- 전체 매출액의 **3%** 이하 (2023년 개정으로 상향)
- 최소 300만 원 이상

### 정보통신망법 과태료 및 처벌

| 위반 사항 | 처벌 |
|----------|------|
| 악성 프로그램 유포 | 7년 이하 징역 또는 7천만 원 이하 벌금 |
| 정보통신망 침해 | 5년 이하 징역 또는 5천만 원 이하 벌금 |
| 침해사고 신고 미이행 | 1천만 원 이하 과태료 |
| ISMS 인증 미취득 (의무 대상) | 3천만 원 이하 과태료 |
| 스팸 발송 (무단) | 3천만 원 이하 과태료 |

### 전자금융거래법 처벌

| 위반 사항 | 처벌 |
|----------|------|
| 전자금융 사기 | 10년 이하 징역 또는 1억 원 이하 벌금 |
| 보안 취약점 고의 방치 | 기관 제재, 임원 문책 |
| 망분리 의무 미이행 | 기관 경고, 최대 영업 정지 |

### 양벌 규정
- 법인의 임직원이 법인 업무와 관련하여 위반 시, **임직원 처벌과 별개로 법인에도 벌금 부과**
- 단, 법인이 위반 방지를 위해 상당한 주의와 감독을 게을리하지 않은 경우 면제

---

## Python CLI: 법령 조항 키워드 검색 및 퀴즈 도구

```python
#!/usr/bin/env python3
"""
한국 정보보안 법령 키워드 검색 및 퀴즈 CLI 도구
사용법: python3 law_tool.py [--search KEYWORD] [--quiz] [--law LAW_NAME]
"""

import argparse
import json
import random
import sys
import datetime
from pathlib import Path
from typing import Optional

LAW_DATABASE: dict[str, list[dict]] = {
    "개인정보보호법": [
        {
            "article": "제3조",
            "title": "개인정보 처리 원칙",
            "content": "수집 제한, 목적 명확화, 목적 외 이용 금지, 정확성, 안전성, 투명성, 사생활 최소 침해 원칙",
            "keywords": ["수집 제한", "목적 명확화", "안전성", "투명성"],
            "penalty": "원칙 위반 시 행정 처분",
        },
        {
            "article": "제4조",
            "title": "정보주체의 권리",
            "content": "열람권, 정정·삭제권, 처리 정지권, 손해배상청구권, 동의 철회권",
            "keywords": ["열람권", "삭제권", "처리 정지권", "손해배상"],
            "penalty": "권리 보장 거부 시 과태료 3천만 원 이하",
        },
        {
            "article": "제21조",
            "title": "개인정보의 파기",
            "content": "보유 기간 경과 또는 처리 목적 달성 시 5일 이내 파기. 전자파일은 복원 불가능한 방법, 서면은 파쇄·소각",
            "keywords": ["파기", "5일 이내", "복원 불가", "파쇄"],
            "penalty": "미이행 시 과태료 3천만 원 이하",
        },
        {
            "article": "제23조",
            "title": "민감정보의 처리 제한",
            "content": "사상·신념, 노동조합, 정치적 견해, 건강·성생활, 유전정보, 범죄경력, 생체정보는 별도 동의 필요",
            "keywords": ["민감정보", "별도 동의", "생체정보", "유전정보"],
            "penalty": "위반 시 5년 이하 징역 또는 5천만 원 이하 벌금",
        },
        {
            "article": "제24조",
            "title": "고유식별정보의 처리 제한",
            "content": "주민번호, 여권번호, 운전면허번호, 외국인등록번호는 별도 동의 또는 법령 근거 필요. 저장 시 암호화 의무",
            "keywords": ["주민번호", "고유식별정보", "별도 동의", "암호화"],
            "penalty": "위반 시 5년 이하 징역 또는 5천만 원 이하 벌금",
        },
        {
            "article": "제34조",
            "title": "개인정보 유출 통지·신고",
            "content": "1천 명 이상 유출 시 72시간 이내 개인정보보호위원회 신고. 정보주체에게 지체없이 통지",
            "keywords": ["유출 신고", "72시간", "1천 명", "통지"],
            "penalty": "신고 미이행 시 과태료 3천만 원 이하",
        },
        {
            "article": "제35조",
            "title": "개인정보의 열람",
            "content": "정보주체는 개인정보처리자에게 자신의 개인정보 열람을 요구할 수 있음. 10일 이내 조치",
            "keywords": ["열람 요구", "10일 이내", "거부 사유"],
            "penalty": "거부 시 과태료 3천만 원 이하",
        },
        {
            "article": "제39조의4",
            "title": "법정 손해배상",
            "content": "개인정보 유출 등으로 피해를 입은 경우 300만 원 이하의 범위에서 손해 증명 없이 손해배상 청구 가능",
            "keywords": ["법정 손해배상", "300만 원", "증명 불필요"],
            "penalty": "법원 판결에 따른 손해배상",
        },
    ],
    "정보통신망법": [
        {
            "article": "제22조",
            "title": "개인정보의 수집·이용 동의",
            "content": "이용자 동의 없이 개인정보 수집·이용 금지. 수집 항목, 이용 목적, 보유 기간, 거부 권리 고지",
            "keywords": ["동의", "수집 항목", "이용 목적", "보유 기간"],
            "penalty": "위반 시 5년 이하 징역 또는 5천만 원 이하 벌금",
        },
        {
            "article": "제28조",
            "title": "개인정보의 보호 조치",
            "content": "관리적 조치(내부 관리 계획), 기술적 조치(접근 제어, 암호화, 로그 보관), 물리적 조치(서버실 통제)",
            "keywords": ["관리적 조치", "기술적 조치", "물리적 조치", "암호화"],
            "penalty": "미이행 시 과태료 2천만 원 이하",
        },
        {
            "article": "제45조의3",
            "title": "정보보호 최고책임자(CISO) 지정",
            "content": "매출액 100억 원 이상 정보통신서비스 제공자는 CISO 지정 의무. CISO 자격 요건 명시",
            "keywords": ["CISO", "최고책임자", "100억 원", "지정 의무"],
            "penalty": "미지정 시 과태료 3천만 원 이하",
        },
        {
            "article": "제47조",
            "title": "정보보호 관리체계 인증(ISMS)",
            "content": "매출액 100억 원 이상 또는 일평균 이용자 100만 명 이상 정보통신서비스 제공자는 ISMS 인증 의무",
            "keywords": ["ISMS 인증", "100억 원", "100만 명", "의무 대상"],
            "penalty": "미인증 시 과태료 3천만 원 이하",
        },
        {
            "article": "제48조",
            "title": "침해사고 신고",
            "content": "침해사고 발생 시 24시간 이내 KISA 신고 의무. 피해 현황, 발생 원인, 조치 사항 포함",
            "keywords": ["침해사고 신고", "24시간", "KISA", "118"],
            "penalty": "미신고 시 과태료 1천만 원 이하",
        },
        {
            "article": "제49조의2",
            "title": "악성 프로그램 유포 금지",
            "content": "악성 프로그램 제작, 유포, 수입, 유통 금지. 타인의 정보시스템에 악성 프로그램 전달·유포 금지",
            "keywords": ["악성 프로그램", "유포 금지", "제작 금지"],
            "penalty": "7년 이하 징역 또는 7천만 원 이하 벌금",
        },
    ],
    "전자금융거래법": [
        {
            "article": "제21조",
            "title": "전자금융거래 안전성 확보",
            "content": "금융회사는 접근 제어, 암호화, 인증, FDS 등 전자금융거래 보안 조치 이행 의무",
            "keywords": ["접근 제어", "암호화", "FDS", "인증"],
            "penalty": "미이행 시 기관 제재, 임원 문책",
        },
        {
            "article": "제21조의2",
            "title": "이용자 정보 보호 조치",
            "content": "금융회사는 이용자의 금융정보를 안전하게 보관하고, 분실·도난 시 이용자 보호 책임",
            "keywords": ["이용자 정보", "금융정보", "보호 책임"],
            "penalty": "손해배상 책임, 행정 제재",
        },
        {
            "article": "제34조",
            "title": "침해사고 신고",
            "content": "전자금융거래 침해사고 발생 시 금융위원회 및 금융감독원에 즉시 신고",
            "keywords": ["침해사고", "금융위원회", "금융감독원", "즉시 신고"],
            "penalty": "미신고 시 행정 제재",
        },
    ],
    "클라우드컴퓨팅법": [
        {
            "article": "제23조",
            "title": "이용자 보호 조치",
            "content": "클라우드 서비스 제공자는 이용자 데이터 보호, 서비스 중단 30일 전 통지 의무",
            "keywords": ["이용자 보호", "서비스 중단", "30일 전 통지"],
            "penalty": "위반 시 과태료",
        },
        {
            "article": "제24조",
            "title": "국내 데이터 처리",
            "content": "이용자 동의 없이 개인정보 국외 이전 금지. 계약 종료 시 데이터 반환 또는 파기",
            "keywords": ["국외 이전", "동의", "데이터 반환", "파기"],
            "penalty": "위반 시 손해배상 및 행정 제재",
        },
    ],
}

LAW_QUIZ: list[dict] = [
    {
        "question": "개인정보보호법상 개인정보 유출 신고 기준 인원 수는?",
        "answer": "1천 명",
        "keywords": ["1천 명", "1000명"],
        "law": "개인정보보호법",
        "article": "제34조",
    },
    {
        "question": "개인정보 유출 사고 발생 시 개인정보보호위원회 신고 기한은?",
        "answer": "72시간 이내",
        "keywords": ["72시간"],
        "law": "개인정보보호법",
        "article": "제34조",
    },
    {
        "question": "정보통신망법상 침해사고 신고 기관과 신고 기한은?",
        "answer": "KISA, 24시간 이내",
        "keywords": ["KISA", "24시간"],
        "law": "정보통신망법",
        "article": "제48조",
    },
    {
        "question": "개인정보보호법상 보유 기간 경과 후 개인정보 파기 기한은?",
        "answer": "5일 이내",
        "keywords": ["5일"],
        "law": "개인정보보호법",
        "article": "제21조",
    },
    {
        "question": "정보통신망법상 ISMS 인증 의무 대상의 매출액 기준은?",
        "answer": "100억 원 이상",
        "keywords": ["100억"],
        "law": "정보통신망법",
        "article": "제47조",
    },
    {
        "question": "개인정보보호법상 법정 손해배상 상한 금액은?",
        "answer": "300만 원",
        "keywords": ["300만"],
        "law": "개인정보보호법",
        "article": "제39조의4",
    },
    {
        "question": "정보통신망법상 악성 프로그램 유포죄의 최대 처벌은?",
        "answer": "7년 이하 징역 또는 7천만 원 이하 벌금",
        "keywords": ["7년", "7천만"],
        "law": "정보통신망법",
        "article": "제49조의2",
    },
    {
        "question": "클라우드컴퓨팅법상 서비스 중단 시 이용자 사전 통지 기한은?",
        "answer": "30일 전",
        "keywords": ["30일"],
        "law": "클라우드컴퓨팅법",
        "article": "제23조",
    },
    {
        "question": "개인정보보호법 2023년 개정으로 변경된 과징금 상한 기준은?",
        "answer": "전체 매출액의 3%",
        "keywords": ["전체 매출액", "3%"],
        "law": "개인정보보호법",
        "article": "과징금 조항",
    },
    {
        "question": "전자금융감독규정상 물리적 망분리 의무 기준(자산 기준)은?",
        "answer": "자산 2조 원 이상",
        "keywords": ["2조 원"],
        "law": "전자금융감독규정",
        "article": "망분리 조항",
    },
    {
        "question": "개인정보보호법상 고유식별정보에 해당하지 않는 것은 무엇인가? (주민번호/여권번호/운전면허번호/이메일주소)",
        "answer": "이메일주소",
        "keywords": ["이메일주소", "이메일"],
        "law": "개인정보보호법",
        "article": "제24조",
    },
    {
        "question": "개인정보보호법상 만 14세 미만 아동의 개인정보 수집 시 필요한 동의는?",
        "answer": "법정대리인 동의",
        "keywords": ["법정대리인", "법정 대리인"],
        "law": "개인정보보호법",
        "article": "제22조",
    },
]

QUIZ_HISTORY_FILE = Path.home() / ".law_quiz_history.json"


def load_history() -> list:
    if QUIZ_HISTORY_FILE.exists():
        try:
            with open(QUIZ_HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_history(entry: dict) -> None:
    history = load_history()
    history.append(entry)
    try:
        with open(QUIZ_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history[-50:], f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"저장 실패: {e}", file=sys.stderr)


def search_law(keyword: str, law_filter: Optional[str] = None) -> None:
    results = []
    search_db = {law_filter: LAW_DATABASE[law_filter]} if law_filter and law_filter in LAW_DATABASE else LAW_DATABASE

    for law_name, articles in search_db.items():
        for article in articles:
            if (
                keyword.lower() in article["title"].lower()
                or keyword.lower() in article["content"].lower()
                or any(keyword.lower() in kw.lower() for kw in article["keywords"])
            ):
                results.append({"law": law_name, **article})

    if not results:
        print(f"'{keyword}'에 해당하는 조항을 찾을 수 없습니다.")
        return

    print(f"\n{'='*70}")
    print(f" 검색 결과: '{keyword}' — {len(results)}개 조항 발견")
    print(f"{'='*70}\n")

    for r in results:
        print(f"[{r['law']}] {r['article']} {r['title']}")
        print(f"  내용: {r['content']}")
        print(f"  키워드: {', '.join(r['keywords'])}")
        print(f"  처벌: {r['penalty']}")
        print()


def run_law_quiz(count: int, law_filter: Optional[str]) -> None:
    pool = [q for q in LAW_QUIZ if not law_filter or q["law"] == law_filter]

    if not pool:
        print(f"'{law_filter}'에 해당하는 퀴즈가 없습니다.")
        return

    random.shuffle(pool)
    selected = pool[:min(count, len(pool))]

    correct = 0
    print(f"\n{'='*70}")
    print(f" 정보보안 법령 퀴즈 (총 {len(selected)}문제)")
    print(f"{'='*70}\n")

    wrong_list = []
    for i, q in enumerate(selected, 1):
        print(f"[{i}/{len(selected)}] [{q['law']}] {q['article']}")
        print(f"문제: {q['question']}")
        answer = input("정답: ").strip()

        is_correct = any(kw.lower() in answer.lower() for kw in q["keywords"])
        if is_correct:
            print("정답입니다!\n")
            correct += 1
        else:
            print(f"오답! 정답: {q['answer']}\n")
            wrong_list.append(q)

    print(f"\n{'='*70}")
    print(f" 결과: {correct}/{len(selected)} ({correct/len(selected)*100:.1f}%)")
    print(f"{'='*70}")

    if wrong_list:
        print("\n오답 정리:")
        for q in wrong_list:
            print(f"  [{q['law']}] {q['article']}: {q['answer']}")

    save_history({
        "date": datetime.datetime.now().isoformat()[:16],
        "total": len(selected),
        "correct": correct,
        "law_filter": law_filter or "전체",
    })


def list_laws() -> None:
    print("\n수록된 법령 목록:")
    for law_name, articles in LAW_DATABASE.items():
        print(f"  - {law_name} ({len(articles)}개 조항)")

    print("\n퀴즈 법령 목록:")
    law_names = sorted(set(q["law"] for q in LAW_QUIZ))
    for law in law_names:
        count = sum(1 for q in LAW_QUIZ if q["law"] == law)
        print(f"  - {law} ({count}개 문제)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="한국 정보보안 법령 키워드 검색 및 퀴즈 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 law_tool.py --search 침해사고           # '침해사고' 키워드 검색
  python3 law_tool.py --search 암호화 --law 개인정보보호법  # 특정 법령 내 검색
  python3 law_tool.py --quiz                      # 전체 법령 퀴즈 10문제
  python3 law_tool.py --quiz --law 개인정보보호법  # 개인정보보호법 퀴즈
  python3 law_tool.py --quiz --count 5            # 5문제 출제
  python3 law_tool.py --list                      # 법령 목록 확인
        """,
    )
    parser.add_argument("--search", "-s", type=str, help="검색할 키워드")
    parser.add_argument("--law", "-l", type=str, help="특정 법령 선택")
    parser.add_argument("--quiz", "-q", action="store_true", help="법령 퀴즈 시작")
    parser.add_argument("--count", "-n", type=int, default=10, help="퀴즈 문제 수 (기본: 10)")
    parser.add_argument("--list", action="store_true", help="법령 목록 출력")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list:
        list_laws()
        return

    if args.search:
        search_law(args.search, args.law)
        return

    if args.quiz:
        run_law_quiz(args.count, args.law)
        return

    print("사용법: python3 law_tool.py --help")
    list_laws()


if __name__ == "__main__":
    main()
```

---

## 법령 암기 핵심 요약표

### 신고 기한 비교표

| 상황 | 법령 | 기한 | 신고 기관 |
|------|------|------|----------|
| 개인정보 유출 (1천 명 이상) | 개인정보보호법 제34조 | 72시간 이내 | 개인정보보호위원회 |
| 침해사고 신고 | 정보통신망법 제48조 | 24시간 이내 | KISA (118) |
| 개인정보 파기 | 개인정보보호법 제21조 | 5일 이내 | 자체 처리 |
| 유출 정보주체 통지 | 개인정보보호법 제34조 | 지체없이 | 정보주체 직접 |
| 클라우드 서비스 중단 통지 | 클라우드컴퓨팅법 제23조 | 30일 전 | 이용자 |

### 처벌 수위 비교표

| 위반 행위 | 법령 | 최대 처벌 |
|---------|------|---------|
| 악성 프로그램 유포 | 정보통신망법 제49조의2 | 7년 징역 / 7천만 원 벌금 |
| 개인정보 불법 처리 | 개인정보보호법 | 5년 징역 / 5천만 원 벌금 |
| 전자금융 사기 | 전자금융거래법 | 10년 징역 / 1억 원 벌금 |
| 침해사고 신고 미이행 | 정보통신망법 | 과태료 1천만 원 이하 |
| ISMS 인증 미취득 | 정보통신망법 제47조 | 과태료 3천만 원 이하 |
| 개인정보 안전 조치 미이행 | 개인정보보호법 | 과태료 3천만 원 이하 |

---

## 시험 빈출 법령 조항 암기 포인트

1. **개인정보 유출 신고 기준**: "1천 명" 이상, "72시간" 이내
2. **침해사고 신고**: KISA, "24시간" 이내, 정보통신망법 제48조
3. **개인정보 파기**: 보유 기간 경과 후 "5일" 이내
4. **법정 손해배상**: "300만 원" 이하 (증명 없이 청구 가능)
5. **ISMS 의무 대상**: 매출액 "100억 원" 또는 이용자 "100만 명"
6. **망분리 의무 기준**: 금융회사 자산 "2조 원" 이상
7. **민감정보 처리**: "별도 동의" 또는 법률 특별 규정
8. **클라우드 서비스 중단**: "30일 전" 이용자 통지
9. **과징금 상한**: 전체 매출액의 "3%" (2023년 개정)
10. **아동 개인정보**: 만 "14세" 미만, 법정대리인 동의

<!-- detect-validate-41 -->
## 컴플라이언스 검증 — 법적 의무가 실제로 이행되는가

법령 준수는 *조항을 읽었는가*가 아니라 **개인정보보호법·정보통신망법 등의 의무가 실제 시스템·절차로 이행되고 증적이 있는가**로 판정된다. 표본 의무를 증적으로 확인한다. 확인은 **소유·승인 시스템**에서만.

### 의무 → 형식적 준수 → 증적 검증 → 양호 신호

| 의무 | 형식적 준수 | 증적 검증 | 양호 신호 |
|---|---|---|---|
| 개인정보 암호화 | 정책만 | 저장 암호화 확인 | 민감정보 평문 0 |
| 접근기록 보존 | 수집 주장 | 보존기간 확인 | 법정기간 보존 |
| 안전조치 | 규정만 | 실제 통제 확인 | 통제 작동 |
| 파기 | 절차 서술 | 파기 로그 확인 | 만료 데이터 파기 |

### 검증 (직접 확인)

```bash
# 1) "개인정보 암호화" 의무 — 저장소에 평문 주민번호 패턴이 없는지 표본 확인. 소유 시스템에서
grep -rEn '[0-9]{6}-[1-4][0-9]{6}' /data/sample 2>/dev/null | head   # 매치=평문 노출 점검 필요
# 2) "접근기록 보존" 의무 — 접근 로그가 법정 기간(예: 180일) 이상 보존되는지
find /var/log -name 'access*.log*' -mtime +180 2>/dev/null | head
```

> 확인은 반드시 **소유·승인 시스템**에서만 한다. "조항을 읽었다"와 "의무가 실제 이행되고 증적이 있다"는 다르다 — 표본 의무를 증적으로 직접 확인한다([[07_Digital_Forensics]], [[26_Linux_Hardening]]).

**최신 기준 (2025–2026):**
- 개인정보보호법 개정으로 마이데이터·자동화된 결정에 대한 대응권·과징금(전체 매출 기준) 강화 — 암호화·파기뿐 아니라 **처리정지/이의제기 절차**의 실제 이행 증적까지 확인
- 국외 이전·클라우드 위탁 시 안전조치·계약 증적을 표본으로 확인 — 정책 문서만으로는 불충분하며 실제 이전 내역과 대조

---

<a name="english"></a>

# Korean Information Security Laws and Compliance — Complete Guide

## Overview of the Information Security Legal Framework

Korea's information security laws are broadly categorized into personal data protection, telecommunications security, financial security, and cloud/infrastructure security. Each law imposes specific obligations on defined entities and situations; violations may result in administrative fines and criminal penalties applied concurrently.

### Key Legal Framework

```
Information Security Laws
├── Personal Information Protection Act (PIPA) — Personal Information Protection Commission
├── Act on Promotion of Information and Communications Network Utilization and Information Protection (Network Act)
│   └── Oversight: Ministry of Science and ICT, Korea Communications Commission
├── Electronic Financial Transactions Act — Financial Services Commission
├── Act on the Development of Cloud Computing and Protection of Its Users (Cloud Act)
├── Framework Act on National Informatization
├── Digital Signature Act
└── Credit Information Use and Protection Act
```

---

## Key Provisions of the Network Act

### Full Official Title
Act on Promotion of Information and Communications Network Utilization and Information Protection, etc.

### Primary Subjects
- Information and communications service providers (portals, SNS, online shopping malls, etc.)
- Business operators providing services via information and communications networks

### Summary of Key Provisions

#### Article 22: Consent for Collection and Use of Personal Information
- Prohibition on collecting or using personal information without user consent
- Required disclosures at time of consent: items collected, purpose of use, retention period, right to refuse
- Mandatory separation of required vs. optional items when obtaining consent

#### Article 24: Prohibition on Third-Party Provision of Personal Information
- Prohibition on providing personal information to third parties without user consent
- Exceptions: statutory requirements, law enforcement requests (warrant required), imminent danger

#### Article 28: Personal Information Protection Measures
Mandatory protective measures for service providers:
1. **Administrative measures**: establishment of internal management plans, employee training
2. **Technical measures**: access control, encryption, retention of access logs
3. **Physical measures**: server room access control, locking devices

#### Article 28-2: Encryption of Personal Information
- Mandatory encryption of resident registration numbers, passwords, and biometric information
- Encryption required when storing unique identification information

#### Article 45: Information Security Measures
Information and communications service providers must implement the following:
- Designation of a Chief Information Security Officer (CISO)
- Certification of an Information Security Management System (ISMS) (for mandatory subjects)
- Vulnerability inspection and remediation

#### Article 45-3: Designation of CISO
- Mandatory designation applies to service providers with annual revenue of KRW 10 billion or more
- CISO qualification requirements: degree or career experience in information security
- CISO must be reported to the Minister of the Interior and Safety

#### Article 47: ISMS Certification
Mandatory certification subjects:
- Service providers with annual revenue of KRW 10 billion or more, or average daily users of 1 million or more
- Operators of co-located data centers (IDC)
- Some cloud computing service providers

#### Article 48: Incident Reporting
- **Reporting obligation**: report to KISA without delay (within 24 hours) upon occurrence of an intrusion incident
- Report contents: damage status, cause of incident, measures taken
- Reporting method: Internet Incident Response Center (KISA 118), online reporting

#### Article 48-4: Root Cause Analysis of Incidents
- In large-scale incidents, KISA support may be requested for root cause analysis
- Government may conduct investigations for root cause analysis

#### Article 49-2: Prohibition on Distribution of Malicious Programs
- Prohibition on creating, distributing, importing, or circulating malicious programs
- Prohibition on delivering or distributing malicious programs to others' information systems without authorization

#### Articles 50–52: Spam and Advertising Information Transmission
- Prohibition on transmitting commercial advertisements without recipient consent
- Prohibition on sending advertisements at night (9 PM–8 AM)
- Mandatory indication of opt-out method

---

## Key Provisions of the Personal Information Protection Act (PIPA)

### Scope of Application
- Applies to all public institutions, enterprises, organizations, and individuals processing personal information
- In principle, applies to all workplaces with 5 or more employees

### Personal Information Processing Principles (Article 3)

1. **Principle of collection limitation**: collect only the minimum personal information necessary for the purpose
2. **Principle of purpose specification**: clearly specify the purpose of collection
3. **Prohibition on use beyond the specified purpose**: process only within the scope of the collection purpose
4. **Accuracy principle**: maintain personal information accurately and up-to-date
5. **Security principle**: implement safety measures to prevent leakage, alteration, or destruction
6. **Transparency principle**: disclose processing policies, guarantee right to access and correction
7. **Minimum privacy infringement principle**: infringe on personal privacy to the minimum extent necessary

### Rights of Data Subjects (Article 4)

| Right | Content |
|-------|---------|
| Right of access | Demand to review the status of one's personal information processing |
| Right to rectification and erasure | Demand correction or deletion of inaccurate personal information |
| Right to restriction of processing | Demand to stop processing of personal information |
| Right to damages | Claim compensation for damages caused by personal information violations |
| Right to withdraw consent | Withdraw consent for collection, use, or provision at any time |

### Key 2023 Amendments

#### 1. Stricter Breach Notification Standards
- **Before amendment**: notify government agencies when 10,000 or more records are breached
- **After amendment**: notify the Personal Information Protection Commission within **72 hours** when **1,000 or more** records are breached
- Obligation to immediately notify data subjects

#### 2. Introduction of Data Portability Rights
- Data subjects may request transmission of their personal information to other businesses
- Phased implementation by sector (finance, healthcare, etc.)

#### 3. Right to Refuse Automated Decision-Making
- Right to refuse or demand explanation for fully automated decisions based on algorithms and AI

#### 4. Strengthened Special Rules for Children's Personal Information
- Personal information of children under 14: legal guardian consent is mandatory
- Obligation to prepare child-friendly personal information processing policies

#### 5. Stricter Administrative Fine Standards
- Before amendment: up to 3% of revenue related to the violation
- After amendment: up to **3%** of total revenue (raised cap for stronger deterrence)

### Restrictions on Processing Sensitive Information (Article 23)

Sensitive information items:
- Political views, religious beliefs
- Joining or withdrawing from labor unions or political parties
- Political opinions
- Health and sex life information
- Genetic information
- Criminal history
- **Biometric information** (added 2020): fingerprints, iris, facial data, etc.

Processing conditions: separate consent or special statutory provisions

### Restrictions on Processing Unique Identification Information (Article 24)

Unique identification information items:
- Resident registration number
- Passport number
- Driver's license number
- Alien registration number

Processing conditions: separate consent or statutory provisions
When stored: **encryption mandatory** (reversible encryption permitted, excluding one-way hash)

### Disposal of Personal Information (Article 21)
- Dispose **within 5 days** after retention period expires or processing purpose is achieved
- Disposal method: electronic files — irreversible method; paper documents — shredding or incineration

---

## Electronic Financial Transactions Act — Security Requirements

### Applicable Entities
- Financial companies (banks, securities firms, insurance companies, card companies)
- Electronic financial business operators (simple payment, electronic money, P2P finance)

### Key Security Obligations

#### Electronic Financial Transaction Security Requirements (Article 21)

1. **Access control**: restrict access rights for internet banking, etc.
2. **Encryption**: encrypt financial information during transmission and storage
3. **Authentication**: enhanced authentication including authorized electronic signatures, OTP, biometric authentication
4. **Abnormal transaction detection**: operate a Fraud Detection System (FDS)
5. **Log retention**: retain transaction logs for 5 years or more

#### Network Separation Obligations (Electronic Financial Supervisory Regulations)

**Entities required to implement physical network separation:**
- Financial companies with assets of KRW 2 trillion or more
- Electronic financial business operators with average daily users of 1 million or more

**Entities permitted to use logical network separation:**
- Small financial institutions (assets under KRW 2 trillion)
- Fintech companies (when meeting certain conditions)

**Network separation standards:**
- Complete separation of business network (internal) and internet network (external)
- Use of dedicated one-way systems for data transfer
- Separation of development/test environments from production environment

#### Electronic Financial Fraud Prevention System (FDS)
- Real-time detection and blocking of abnormal transactions
- Monitoring of abnormal access patterns (multiple logins, overseas access, etc.)
- Additional authentication for high-value transfers

#### Prohibition on Mandatory Security Program Installation
- From 2023, financial institutions are prohibited from forcing users to install security programs
- Transition to standard authentication methods is encouraged

---

## Cloud Computing Act

### Full Official Title
Act on the Development of Cloud Computing and Protection of Its Users

### Cloud Service Security Obligations

#### Standards for Public Institution Cloud Use (Article 20-2)
- Public institutions may use cloud services
- **Cloud Security Assurance Program (CSAP)** certification is mandatory
- Sensitive information: dedicated (private) or hybrid cloud

#### CSAP Rating Levels

| Level | Target | Requirement Level |
|-------|--------|-------------------|
| High | Processing of classified information or above | Physical network separation, dedicated cloud |
| Medium | Sensitive public data | Logical network separation, dedicated zone |
| Low | General public data | Standard security requirements |

#### Cloud Service Provider Obligations
- Domestic storage of user data (overseas transfer without separate consent is prohibited)
- Prior notification to users before service interruption (30 days in advance)
- Return or destruction of user data upon contract termination

---

## Scope and Standards for Mandatory Network Separation

### Legal Basis for Network Separation

| Law | Subject | Standard |
|-----|---------|----------|
| Electronic Financial Supervisory Regulations | Financial companies, e-finance operators | Assets KRW 2 trillion or users 1 million+ |
| PIPA Enforcement Decree | Personal information processors | Processing 1 million+ individuals' data |
| Network Act | Information and communications service providers | Businesses above a certain scale |
| Public Institution Information Security Guidelines | Public institutions | All public institutions (phased application) |

### Network Separation Implementation Methods

#### Physical Network Separation
- Separate business PCs and internet PCs
- Complete separation of network cables and switches
- Use of authorized media for data transfer (USB, etc.)
- Cost: High / Security: Highest

#### Logical Network Separation (VDI Method)
- Separation into virtual desktop environments on a single PC
- Complete separation of business network VMs and internet network
- Restrictions on copying and pasting data
- Cost: Medium / Security: High

### Penalties for Violations of Network Separation Obligations
- Violation of Electronic Financial Supervisory Regulations: institutional warning, officer disciplinary action
- Violation of PIPA: administrative fines up to KRW 30 million
- Repeated violations: possible suspension of business or revocation of license

---

## Standards for Administrative Fines and Criminal Penalties

### PIPA Administrative Fines and Penalties

#### Criminal Penalties

| Violation | Penalty |
|-----------|---------|
| Illegal collection or processing of personal information | Up to 5 years imprisonment or KRW 50 million fine |
| Processing sensitive information without consent | Up to 5 years imprisonment or KRW 50 million fine |
| Illegal provision of personal information to third parties | Up to 5 years imprisonment or KRW 50 million fine |
| Failure to report breach | Administrative fine up to KRW 30 million |
| Failure to implement security measures | Administrative fine up to KRW 30 million |
| Refusal of access request | Administrative fine up to KRW 30 million |

#### Administrative Fines
- **Large-scale data breach** or **failure to implement security measures** resulting in infringement
- Up to **3%** of total revenue (increased by 2023 amendment)
- Minimum KRW 3 million

### Network Act Administrative Fines and Penalties

| Violation | Penalty |
|-----------|---------|
| Distribution of malicious programs | Up to 7 years imprisonment or KRW 70 million fine |
| Intrusion into information and communications networks | Up to 5 years imprisonment or KRW 50 million fine |
| Failure to report intrusion incidents | Administrative fine up to KRW 10 million |
| Failure to obtain ISMS certification (mandatory subjects) | Administrative fine up to KRW 30 million |
| Sending spam (unauthorized) | Administrative fine up to KRW 30 million |

### Electronic Financial Transactions Act Penalties

| Violation | Penalty |
|-----------|---------|
| Electronic financial fraud | Up to 10 years imprisonment or KRW 100 million fine |
| Intentional neglect of security vulnerabilities | Institutional sanctions, officer disciplinary action |
| Failure to implement network separation obligations | Institutional warning, up to suspension of business |

### Joint Penalty Rule
- When an officer or employee violates the law in connection with corporate business, **fines are imposed on the corporation separately from penalties on the individual**
- Exception: if the corporation has not neglected reasonable care and supervision to prevent violations

---

## Python CLI: Law Keyword Search and Quiz Tool

```python
#!/usr/bin/env python3
"""
Korean Information Security Law Keyword Search and Quiz CLI Tool
Usage: python3 law_tool.py [--search KEYWORD] [--quiz] [--law LAW_NAME]
"""
# (See Korean section above for full implementation)
```

---

## Key Summary Tables for Memorization

### Notification Deadline Comparison

| Situation | Law | Deadline | Reporting Body |
|-----------|-----|----------|----------------|
| Personal data breach (1,000+ records) | PIPA Article 34 | Within 72 hours | Personal Information Protection Commission |
| Intrusion incident reporting | Network Act Article 48 | Within 24 hours | KISA (118) |
| Personal information disposal | PIPA Article 21 | Within 5 days | Self-handled |
| Notification to data subjects after breach | PIPA Article 34 | Without delay | Data subjects directly |
| Cloud service interruption notice | Cloud Act Article 23 | 30 days in advance | Users |

### Penalty Severity Comparison

| Violation | Law | Maximum Penalty |
|-----------|-----|----------------|
| Distribution of malicious programs | Network Act Article 49-2 | 7 years / KRW 70 million fine |
| Illegal personal data processing | PIPA | 5 years / KRW 50 million fine |
| Electronic financial fraud | Electronic Financial Transactions Act | 10 years / KRW 100 million fine |
| Failure to report intrusion incident | Network Act | Administrative fine up to KRW 10 million |
| Failure to obtain ISMS certification | Network Act Article 47 | Administrative fine up to KRW 30 million |
| Failure to implement personal data security measures | PIPA | Administrative fine up to KRW 30 million |

---

## Key Memorization Points for Frequently Tested Provisions

1. **Personal data breach notification threshold**: "1,000" or more, within "72 hours"
2. **Intrusion incident reporting**: KISA, within "24 hours", Network Act Article 48
3. **Personal information disposal**: within "5 days" after retention period expires
4. **Statutory damages**: up to "KRW 3 million" (can be claimed without proof of damage)
5. **Mandatory ISMS subjects**: annual revenue "KRW 10 billion" or users "1 million"
6. **Network separation obligation threshold**: financial company assets "KRW 2 trillion" or more
7. **Sensitive information processing**: "separate consent" or special statutory provisions
8. **Cloud service interruption**: notify users "30 days" in advance
9. **Administrative fine cap**: "3%" of total revenue (2023 amendment)
10. **Children's personal information**: under "14 years" of age, legal guardian consent required

<!-- detect-validate-41 -->
## Compliance Validation — Are Legal Obligations Actually Met?

Legal compliance is judged not by *whether you read the clause* but by **whether obligations under the Personal Information Protection Act, Network Act, etc. are actually implemented in systems/procedures with evidence**. Check sample obligations with evidence. Verify only on **owned / authorized systems**.

### Obligation -> Formal compliance -> Evidence validation -> Healthy signal

| Obligation | Formal compliance | Evidence validation | Healthy signal |
|---|---|---|---|
| PII encryption | Policy only | Confirm at-rest encryption | Zero plaintext sensitive data |
| Access-log retention | Claimed collected | Check retention | Retained for legal period |
| Safeguards | Regulation only | Verify real control | Control operates |
| Disposal | Describe procedure | Check disposal log | Expired data destroyed |

### Validation (verify directly)

```bash
# 1) "PII encryption" obligation — sample-check no plaintext resident-number pattern in storage. Owned systems
grep -rEn '[0-9]{6}-[1-4][0-9]{6}' /data/sample 2>/dev/null | head   # match => investigate plaintext exposure
# 2) "Access-log retention" obligation — whether access logs are retained for the legal period (e.g., 180 days)
find /var/log -name 'access*.log*' -mtime +180 2>/dev/null | head
```

> Verify only on **owned / authorized systems**. "Read the clause" differs from "the obligation is actually met with evidence" — check sample obligations with evidence directly ([[07_Digital_Forensics]], [[26_Linux_Hardening]]).
