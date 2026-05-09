# 정보보안기사 필기 완전 정복

## 시험 개요

정보보안기사는 한국인터넷진흥원(KISA)이 주관하고 한국산업인력공단이 시행하는 국가기술자격 시험이다.
정보보안 분야의 전문 지식과 기술을 검증하며, 정부기관 및 기업의 보안 담당자 채용 시 우대 자격이다.

### 시험 구성

| 구분 | 과목 수 | 문항 수 | 시간 | 합격 기준 |
|------|---------|---------|------|-----------|
| 필기 | 5과목 | 100문항 (과목당 20문항) | 150분 | 과목당 40점 이상, 평균 60점 이상 |
| 실기 | 1과목 | 단답형+서술형 | 180분 | 60점 이상 |

### 필기 5개 과목

1. 시스템 보안
2. 네트워크 보안
3. 애플리케이션 보안
4. 정보보안 일반
5. 정보보안 관리 및 법규

---

## 과목 1: 시스템 보안

### 핵심 개념 요약

#### 운영체제 보안
- **커널(Kernel)**: OS의 핵심, 하드웨어와 소프트웨어 사이 인터페이스
- **접근 제어 모델**: DAC(임의적), MAC(강제적), RBAC(역할기반), ABAC(속성기반)
- **프로세스 격리**: 메모리 보호, 가상 주소 공간, 샌드박스
- **setuid/setgid**: 실행 시 파일 소유자 권한으로 실행되는 특수 권한 비트

#### 인증과 접근통제
- **인증 3요소**: 지식(패스워드), 소유(OTP 토큰), 존재(생체정보)
- **SSO(Single Sign-On)**: 한 번 인증으로 여러 시스템 접근
- **Kerberos**: 티켓 기반 네트워크 인증 프로토콜 (KDC, TGT, 서비스 티켓)
- **PAM(Pluggable Authentication Module)**: 리눅스 모듈형 인증 프레임워크

#### 취약점과 공격 기법
- **버퍼 오버플로우**: 스택/힙 오버플로우, NOP 슬레드, ROP 체인
- **포맷 스트링 공격**: printf 계열 함수의 %n, %x 포맷 지정자 악용
- **레이스 컨디션(TOCTOU)**: 시간 차이를 이용한 공유 자원 경쟁 공격
- **권한 상승**: 로컬 취약점을 이용한 root 권한 획득

### 빈출 키워드 30개

1. **DAC(Discretionary Access Control)** — 자원 소유자가 접근 권한 결정
2. **MAC(Mandatory Access Control)** — 시스템 정책에 따라 강제 접근 제어
3. **RBAC(Role-Based Access Control)** — 역할에 따른 접근 권한 부여
4. **TCB(Trusted Computing Base)** — 보안 정책 시행을 담당하는 시스템 요소
5. **보안 커널** — TCB의 핵심, 참조 모니터 구현체
6. **참조 모니터(Reference Monitor)** — 모든 접근 요청을 중재하는 개념
7. **버퍼 오버플로우** — 경계 미검증으로 인한 메모리 침범
8. **스택 오버플로우** — 스택 영역 초과 데이터 입력으로 리턴 주소 변조
9. **힙 오버플로우** — 동적 할당 메모리 영역 침범
10. **NOP 슬레드** — 셸코드 실행 유도용 No-Operation 명령어 나열
11. **ROP(Return Oriented Programming)** — 기존 코드 조각 재활용 공격
12. **ASLR(Address Space Layout Randomization)** — 메모리 주소 무작위화
13. **DEP/NX(Data Execution Prevention)** — 데이터 영역 코드 실행 방지
14. **Stack Canary** — 리턴 주소 변조 탐지용 감시 값
15. **setuid 비트** — 실행 파일 소유자 권한으로 실행
16. **레이스 컨디션** — 경쟁 조건을 이용한 권한 우회
17. **심볼릭 링크 공격** — 심볼릭 링크를 이용한 파일 조작
18. **Kerberos** — 대칭키 기반 네트워크 인증 프로토콜
19. **TGT(Ticket Granting Ticket)** — Kerberos 인증 초기 발급 티켓
20. **KDC(Key Distribution Center)** — Kerberos 핵심 서버
21. **PAM** — 리눅스 모듈형 인증 시스템
22. **chroot jail** — 루트 디렉터리 변경으로 프로세스 격리
23. **SELinux** — 강제 접근 제어 기반 리눅스 보안 모듈
24. **AppArmor** — 경로 기반 MAC 시스템
25. **Sudo** — 특정 명령어에 대한 관리자 권한 위임
26. **umask** — 파일 생성 시 기본 권한 마스크
27. **감사 로그(Audit Log)** — 시스템 이벤트 기록 및 추적
28. **코드 인젝션** — 악의적 코드를 취약한 프로그램에 삽입 실행
29. **포맷 스트링** — printf 포맷 지정자를 이용한 메모리 읽기/쓰기
30. **권한 분리(Privilege Separation)** — 최소 권한 원칙에 따른 프로세스 분리

---

## 과목 2: 네트워크 보안

### 핵심 개념 요약

#### 네트워크 프로토콜 보안
- **TCP/IP 취약점**: IP 스푸핑, SYN 플러딩, 세션 하이재킹
- **ARP 스푸핑**: ARP 테이블 변조로 트래픽 가로채기
- **DNS 스푸핑**: DNS 응답 변조로 잘못된 IP 반환
- **DHCP 스타베이션**: DHCP 주소 풀 고갈 공격

#### 방화벽과 VPN
- **패킷 필터링**: IP/포트 기반 트래픽 차단 (1세대)
- **상태 검사(Stateful Inspection)**: 연결 상태 추적 필터링 (3세대)
- **NGFW**: 애플리케이션 인식 및 사용자 기반 정책
- **SSL/TLS VPN**: 웹 브라우저 기반 VPN
- **IPsec VPN**: 터널 모드(전체 패킷 암호화) vs 전송 모드(페이로드 암호화)

#### 침입탐지/방지 시스템
- **시그니처 기반 IDS**: 알려진 패턴 매칭, 오탐 낮음 미탐 높음
- **이상 탐지(Anomaly)**: 정상 기준 이탈 탐지, 미탐 낮음 오탐 높음
- **HIDS**: 호스트 기반 (로그, 파일 무결성)
- **NIDS**: 네트워크 기반 (패킷 캡처 분석)

### 빈출 키워드 30개

1. **ARP 스푸핑** — MAC 주소 위조로 중간자 공격 수행
2. **IP 스푸핑** — 출발지 IP 주소 위조
3. **SYN Flooding** — 3-way 핸드셰이크 미완성으로 서버 자원 고갈
4. **TCP 세션 하이재킹** — 시퀀스 번호 예측으로 세션 탈취
5. **DNS 스푸핑** — 위조 DNS 응답으로 악성 IP 반환
6. **DNS 캐시 포이즈닝** — DNS 캐시에 허위 정보 삽입
7. **스니핑(Sniffing)** — 네트워크 패킷 도청
8. **MITM(Man in the Middle)** — 통신 중간 개입 공격
9. **DoS/DDoS** — 서비스 거부/분산 서비스 거부 공격
10. **ICMP Flood** — ICMP 패킷 대량 발송 공격
11. **Smurf Attack** — 브로드캐스트를 이용한 증폭 공격
12. **Teardrop Attack** — 분열 패킷 재조합 오류 유발
13. **Land Attack** — 출발지=목적지 IP로 무한 루프 유발
14. **패킷 필터링 방화벽** — IP/포트 기반 접근 제어
15. **상태 기반 방화벽** — 연결 상태 추적 접근 제어
16. **프록시 방화벽** — 애플리케이션 레벨 게이트웨이
17. **NGFW(차세대 방화벽)** — DPI + 애플리케이션 인식
18. **IPsec** — 네트워크 계층 암호화 프로토콜
19. **AH(Authentication Header)** — 인증만 제공 (암호화 없음)
20. **ESP(Encapsulating Security Payload)** — 암호화 + 인증
21. **SSL/TLS** — 전송 계층 암호화 프로토콜
22. **IDS(침입탐지)** — 공격 탐지 후 경보 (차단 불가)
23. **IPS(침입방지)** — 공격 탐지 즉시 차단
24. **시그니처 탐지** — 알려진 공격 패턴 매칭
25. **이상 탐지** — 정상 행위 기준 이탈 탐지
26. **허니팟(Honeypot)** — 공격자 유인용 가상 취약 시스템
27. **VPN 터널 모드** — 전체 IP 패킷 암호화
28. **NAT(Network Address Translation)** — 내부 IP 외부 IP 변환
29. **DMZ(비무장지대)** — 내외부 네트워크 중간 완충 구간
30. **포트 스캐닝** — 열린 포트 탐색 (Nmap SYN/FIN/NULL 스캔)

---

## 과목 3: 애플리케이션 보안

### 핵심 개념 요약

#### 웹 보안
- **OWASP Top 10**: SQL Injection, XSS, IDOR, SSRF 등
- **SQL 인젝션**: 입력값에 SQL 구문 삽입, 쿼리 변조
- **XSS(크로스사이트 스크립팅)**: 반사형, 저장형, DOM 기반
- **CSRF**: 피해자 브라우저를 이용한 위조 요청 전송

#### 암호화 응용
- **HTTPS**: TLS 위에서 동작하는 HTTP
- **인증서**: X.509 구조, CA, 인증서 체인
- **세션 관리**: 세션 토큰 보안, 쿠키 속성(HttpOnly, Secure, SameSite)
- **JWT(JSON Web Token)**: Header.Payload.Signature 구조

### 빈출 키워드 30개

1. **SQL 인젝션** — 입력값에 SQL 구문 삽입으로 DB 조작
2. **블라인드 SQL 인젝션** — 오류/시간 차이로 데이터 추출
3. **Stored XSS** — DB에 악성 스크립트 저장 후 출력 시 실행
4. **Reflected XSS** — URL 파라미터의 스크립트가 즉시 반사
5. **DOM XSS** — 클라이언트 측 DOM 조작으로 스크립트 실행
6. **CSRF** — 피해자 세션으로 위조 요청 전송
7. **SSRF** — 서버를 중간자로 이용한 내부 자원 접근
8. **XXE(XML External Entity)** — XML 파서 취약점으로 파일 읽기
9. **IDOR(Insecure Direct Object Reference)** — 객체 참조 변조로 무단 접근
10. **파일 업로드 취약점** — 악성 파일 업로드 후 실행
11. **경로 탐색(Path Traversal)** — ../를 이용한 상위 디렉터리 접근
12. **OWASP Top 10** — 웹 애플리케이션 주요 10대 취약점 목록
13. **입력 유효성 검사** — 화이트리스트 기반 입력 필터링
14. **출력 인코딩** — HTML 특수문자 이스케이프 처리
15. **Prepared Statement** — SQL 인젝션 방어용 파라미터화 쿼리
16. **CSP(Content Security Policy)** — XSS 방어용 콘텐츠 출처 정책
17. **HTTPS** — TLS 기반 암호화 HTTP 통신
18. **X.509** — 디지털 인증서 표준 형식
19. **PKI(공개키 기반구조)** — CA, 인증서, CRL 기반 신뢰 체계
20. **OTP(일회용 패스워드)** — TOTP/HOTP 기반 2차 인증
21. **세션 고정(Session Fixation)** — 인증 전 세션 ID 강제 사용
22. **세션 하이재킹** — 유효한 세션 토큰 탈취 및 재사용
23. **JWT** — JSON 기반 서명된 인증 토큰
24. **HttpOnly 쿠키** — JavaScript에서 쿠키 접근 차단
25. **SameSite 쿠키** — 크로스사이트 요청 시 쿠키 전송 제한
26. **클릭재킹(Clickjacking)** — 투명 iframe으로 클릭 유도
27. **X-Frame-Options** — iframe 삽입 방어 HTTP 헤더
28. **HSTS** — HTTP를 HTTPS로 강제 리다이렉션
29. **API 보안** — 인증, 속도 제한, 입력 검증
30. **WAF(웹 애플리케이션 방화벽)** — 웹 공격 탐지 및 차단

---

## 과목 4: 정보보안 일반

### 핵심 개념 요약

#### 암호학
- **대칭키 암호**: AES, DES, 3DES, SEED, ARIA (같은 키로 암호화/복호화)
- **비대칭키 암호**: RSA, ECC (공개키 암호화, 개인키 복호화)
- **해시 함수**: MD5(128bit), SHA-1(160bit), SHA-256(256bit)
- **디지털 서명**: 개인키로 서명, 공개키로 검증 (무결성 + 부인방지)

#### 보안 원칙
- **기밀성(Confidentiality)**: 허가된 자만 정보 접근
- **무결성(Integrity)**: 정보의 변조 방지 및 탐지
- **가용성(Availability)**: 필요 시 정보 서비스 이용 가능
- **부인방지(Non-repudiation)**: 행위 사실 부인 불가

### 빈출 키워드 30개

1. **CIA 트라이어드** — 기밀성, 무결성, 가용성 3대 보안 목표
2. **AES** — 128/192/256비트 키, 현재 표준 대칭키 알고리즘
3. **DES** — 56비트 키, 현재 취약하여 사용 지양
4. **3DES** — DES를 3번 적용, 112/168비트 보안 강도
5. **SEED** — 한국 표준 대칭키 알고리즘 (128비트)
6. **ARIA** — 한국 표준 경량 대칭키 알고리즘
7. **RSA** — 소인수분해 기반 공개키 암호
8. **ECC(타원곡선)** — 짧은 키로 높은 보안 강도
9. **Diffie-Hellman** — 키 교환 프로토콜 (전방향 비밀성)
10. **MD5** — 128비트 해시, 충돌 취약점으로 사용 지양
11. **SHA-1** — 160비트 해시, 충돌 발견으로 사용 지양
12. **SHA-256** — 256비트 해시, 현재 표준 사용
13. **HMAC** — 해시 기반 메시지 인증 코드
14. **디지털 서명** — 개인키 서명 + 공개키 검증
15. **PKI** — 공개키 기반구조, CA 신뢰 체계
16. **CRL(인증서 폐지 목록)** — 만료 전 폐지된 인증서 목록
17. **OCSP** — 실시간 인증서 상태 확인 프로토콜
18. **스테가노그래피** — 데이터를 다른 데이터 속에 은닉
19. **워터마킹** — 저작권 보호용 데이터 삽입
20. **난수 생성기** — PRNG vs TRNG (보안용은 CSPRNG)
21. **살로미 원칙** — 알고리즘 공개, 키만 비밀 유지
22. **키 관리** — 생성, 배포, 저장, 폐기 생명주기
23. **HSM(하드웨어 보안 모듈)** — 키 저장 및 연산 전용 장치
24. **PFS(완전 전방향 비밀성)** — 세션 키 노출 시 과거 세션 보호
25. **블록 암호 운용 모드** — ECB, CBC, CTR, GCM
26. **CBC 모드** — 이전 암호문 블록을 다음 블록과 XOR
27. **GCM 모드** — 인증 태그 포함 인증 암호화
28. **패딩** — 블록 크기 맞춤 (PKCS#7)
29. **키 유도 함수(KDF)** — 패스워드에서 안전한 키 생성 (PBKDF2, bcrypt)
30. **솔트(Salt)** — 해시 공격 방어용 임의 데이터 추가

---

## 과목 5: 정보보안 관리 및 법규

### 핵심 개념 요약

#### 정보보안 관리
- **ISMS**: 정보보호관리체계 (ISO 27001 기반)
- **위험 관리**: 자산 식별 → 위협/취약점 분석 → 위험 평가 → 대응
- **BCP/DRP**: 업무연속성계획 / 재해복구계획
- **RPO/RTO**: 목표 복구 시점 / 목표 복구 시간

#### 관련 법규
- **정보통신망법**: 개인정보 보호, 침해사고 신고 의무
- **개인정보보호법**: 개인정보 처리 원칙, 정보주체 권리
- **전자서명법**: 전자서명의 법적 효력

### 빈출 키워드 30개

1. **ISMS** — 정보보호관리체계 (ISO/IEC 27001)
2. **ISMS-P** — ISMS + 개인정보보호 통합 인증
3. **위험 분석** — 자산, 위협, 취약점, 영향도 분석
4. **정량적 위험 분석** — 금전적 손실로 위험 수치화 (ALE = SLE × ARO)
5. **정성적 위험 분석** — 전문가 판단으로 위험 등급화
6. **SLE(단일 예상 손실)** — 1회 사고 시 예상 손실액
7. **ARO(연간 발생 빈도)** — 위협이 연간 발생하는 횟수
8. **ALE(연간 예상 손실)** — SLE × ARO
9. **잔여 위험** — 대책 적용 후 남은 위험
10. **BCP(업무연속성계획)** — 재해 시에도 핵심 업무 지속 계획
11. **DRP(재해복구계획)** — IT 시스템 복구 상세 계획
12. **RPO(목표 복구 시점)** — 허용 가능한 데이터 손실 시점
13. **RTO(목표 복구 시간)** — 서비스 복구까지 허용 시간
14. **핫 사이트** — 즉시 전환 가능한 완전 운영 백업 사이트
15. **웜 사이트** — 수 시간 내 전환 가능한 부분 준비 백업 사이트
16. **콜드 사이트** — 수 일 내 전환, 장비만 준비된 사이트
17. **정보보안 정책** — 조직의 최상위 보안 방향 문서
18. **정보보안 지침** — 정책 실행을 위한 세부 규정
19. **보안 절차서** — 지침의 구체적 실행 방법
20. **개인정보보호법** — 개인정보 수집, 처리, 파기 규정
21. **정보통신망법** — 정보통신 서비스 제공자 보안 의무
22. **침해사고** — 해킹, DDoS, 악성코드 감염 등 보안 사건
23. **침해사고 신고 의무** — 24시간 내 KISA 신고
24. **개인정보 영향평가** — 개인정보 처리 시스템 위험 사전 평가
25. **망분리** — 업무망과 인터넷망 물리적/논리적 분리
26. **보안 감사** — 보안 정책 준수 여부 확인 검토
27. **취약점 점검** — 시스템의 보안 약점 주기적 진단
28. **보안 교육** — 임직원 보안 인식 제고 프로그램
29. **사회공학 공격** — 기술이 아닌 사람을 대상으로 한 기만 공격
30. **내부자 위협** — 권한을 가진 내부 사용자에 의한 보안 위협

---

## 암기 팁과 출제 패턴 분석

### 과목별 출제 비중 분석

| 과목 | 주요 출제 영역 | 암기 전략 |
|------|--------------|-----------|
| 시스템 보안 | 접근 제어 모델, 버퍼 오버플로우, 리눅스 보안 | DAC/MAC/RBAC 비교표 암기 |
| 네트워크 보안 | DDoS 유형, 방화벽 세대, IPsec | 공격 유형별 특징 구분 |
| 애플리케이션 | OWASP, SQL 인젝션, XSS | 공격 원리와 대응 세트로 암기 |
| 정보보안 일반 | 암호 알고리즘, 해시, PKI | 알고리즘별 키 길이, 특징 표 작성 |
| 관리 및 법규 | 위험 분석, ISMS, 법령 | 공식(ALE = SLE × ARO) 필수 암기 |

### 고빈도 출제 패턴

1. **비교 문제**: DAC vs MAC, IDS vs IPS, 대칭키 vs 비대칭키
2. **특징 서술 문제**: 특정 프로토콜/알고리즘의 특징 4가지 중 올바른 것
3. **계산 문제**: ALE, SLE, ARO 상호 계산
4. **법령 적용 문제**: 특정 상황에서 어떤 법령 적용되는지
5. **약어 풀이**: 약어의 정확한 영문 전체 명칭

---

## Python CLI: 과목별 키워드 퀴즈 도구

```python
#!/usr/bin/env python3
"""
정보보안기사 필기 키워드 퀴즈 CLI 도구
사용법: python3 quiz_tool.py [--subject SUBJECT] [--count N] [--wrong-only]
"""

import argparse
import json
import random
import sys
import os
import datetime
from pathlib import Path
from typing import Optional

QUIZ_DATA: dict[str, list[dict]] = {
    "시스템보안": [
        {"term": "DAC", "definition": "자원 소유자가 접근 권한을 결정하는 임의적 접근 제어"},
        {"term": "MAC", "definition": "시스템 정책에 따라 강제적으로 접근을 제어하는 방식"},
        {"term": "RBAC", "definition": "사용자의 역할(Role)에 따라 접근 권한을 부여하는 방식"},
        {"term": "버퍼 오버플로우", "definition": "경계값 미검증으로 인해 메모리 인접 영역을 침범하는 공격"},
        {"term": "스택 카나리", "definition": "리턴 주소 변조 탐지를 위해 삽입하는 감시 값"},
        {"term": "ASLR", "definition": "메모리 주소를 무작위로 배치하여 공격을 어렵게 하는 기법"},
        {"term": "DEP/NX", "definition": "데이터 영역에서 코드 실행을 방지하는 보호 기법"},
        {"term": "setuid", "definition": "실행 시 파일 소유자의 권한으로 프로세스가 실행되는 특수 비트"},
        {"term": "레이스 컨디션", "definition": "공유 자원에 대한 경쟁 조건을 이용한 보안 취약점"},
        {"term": "chroot", "definition": "루트 디렉터리를 변경하여 프로세스를 격리하는 기법"},
        {"term": "SELinux", "definition": "강제 접근 제어 기반의 리눅스 보안 모듈"},
        {"term": "Kerberos", "definition": "티켓 기반의 네트워크 인증 프로토콜 (KDC, TGT 사용)"},
        {"term": "PAM", "definition": "리눅스의 모듈형 인증 프레임워크"},
        {"term": "포맷 스트링", "definition": "printf 계열 함수의 포맷 지정자를 악용한 메모리 조작 공격"},
        {"term": "ROP", "definition": "기존 코드 조각(가젯)을 재활용하여 DEP를 우회하는 공격 기법"},
    ],
    "네트워크보안": [
        {"term": "ARP 스푸핑", "definition": "MAC 주소를 위조하여 네트워크 트래픽을 가로채는 공격"},
        {"term": "IP 스푸핑", "definition": "패킷의 출발지 IP 주소를 위조하는 기법"},
        {"term": "SYN Flooding", "definition": "대량의 SYN 패킷을 전송하여 서버 연결 대기 큐를 고갈시키는 DoS 공격"},
        {"term": "DNS 캐시 포이즈닝", "definition": "DNS 캐시에 허위 정보를 삽입하여 잘못된 IP로 유도하는 공격"},
        {"term": "스머프 공격", "definition": "브로드캐스트를 이용하여 공격 트래픽을 증폭시키는 DDoS 공격"},
        {"term": "허니팟", "definition": "공격자를 유인하기 위해 의도적으로 취약하게 구성한 시스템"},
        {"term": "IPsec ESP", "definition": "네트워크 패킷의 암호화와 인증을 제공하는 IPsec 프로토콜"},
        {"term": "IPsec AH", "definition": "패킷 인증만 제공하고 암호화는 하지 않는 IPsec 프로토콜"},
        {"term": "NGFW", "definition": "애플리케이션 인식 및 사용자 기반 정책을 지원하는 차세대 방화벽"},
        {"term": "DMZ", "definition": "내부망과 외부망 사이의 중간 네트워크 구간"},
        {"term": "Stateful Inspection", "definition": "연결 상태를 추적하여 패킷을 필터링하는 방화벽 기술"},
        {"term": "NIDS", "definition": "네트워크 트래픽을 분석하여 침입을 탐지하는 시스템"},
        {"term": "이상 탐지", "definition": "정상 행위 기준에서 벗어난 이상 행위를 탐지하는 방식"},
    ],
    "애플리케이션보안": [
        {"term": "SQL 인젝션", "definition": "입력값에 SQL 구문을 삽입하여 데이터베이스를 비정상적으로 조작하는 공격"},
        {"term": "Stored XSS", "definition": "악성 스크립트를 서버(DB)에 저장하여 다른 사용자에게 실행시키는 공격"},
        {"term": "CSRF", "definition": "피해자의 인증된 세션을 이용하여 위조 요청을 전송하는 공격"},
        {"term": "SSRF", "definition": "서버를 중간자로 이용하여 내부 자원에 접근하는 공격"},
        {"term": "XXE", "definition": "XML 외부 엔티티를 악용하여 서버 파일을 읽거나 SSRF를 수행하는 공격"},
        {"term": "IDOR", "definition": "객체 참조값을 변조하여 다른 사용자의 자원에 무단 접근하는 취약점"},
        {"term": "CSP", "definition": "허용된 출처의 콘텐츠만 실행하도록 제한하는 HTTP 보안 헤더"},
        {"term": "Prepared Statement", "definition": "파라미터화된 쿼리로 SQL 인젝션을 방어하는 기법"},
        {"term": "HttpOnly", "definition": "JavaScript에서 쿠키에 접근하지 못하도록 차단하는 쿠키 속성"},
        {"term": "WAF", "definition": "웹 애플리케이션에 대한 공격을 탐지하고 차단하는 보안 장비"},
        {"term": "JWT", "definition": "JSON 형식의 서명된 인증 토큰 (Header.Payload.Signature)"},
        {"term": "경로 탐색", "definition": "../를 이용하여 허용된 디렉터리 외부에 접근하는 취약점"},
    ],
    "정보보안일반": [
        {"term": "AES", "definition": "128/192/256비트 키를 사용하는 현재 표준 대칭키 암호 알고리즘"},
        {"term": "RSA", "definition": "소인수분해 난제에 기반한 공개키 암호 알고리즘"},
        {"term": "SHA-256", "definition": "256비트 출력을 생성하는 현재 권장 해시 알고리즘"},
        {"term": "HMAC", "definition": "해시 함수와 공유 비밀키를 결합한 메시지 인증 코드"},
        {"term": "디지털 서명", "definition": "개인키로 서명하고 공개키로 검증하여 무결성과 부인방지를 제공"},
        {"term": "PKI", "definition": "CA, 인증서, CRL을 기반으로 공개키의 신뢰성을 보장하는 체계"},
        {"term": "PFS", "definition": "세션 키가 노출되어도 과거 세션의 기밀성을 보호하는 특성"},
        {"term": "GCM 모드", "definition": "인증 태그를 포함하여 암호화와 인증을 동시에 제공하는 블록 암호 모드"},
        {"term": "PBKDF2", "definition": "패스워드에서 안전한 암호화 키를 유도하는 함수"},
        {"term": "솔트", "definition": "패스워드 해시 공격을 방어하기 위해 추가하는 임의의 데이터"},
        {"term": "ECC", "definition": "타원곡선 수학에 기반한 공개키 암호 (짧은 키로 높은 보안 강도)"},
        {"term": "Diffie-Hellman", "definition": "안전하지 않은 채널에서 공유 비밀키를 교환하는 프로토콜"},
    ],
    "관리및법규": [
        {"term": "ALE", "definition": "연간 예상 손실액 = SLE × ARO"},
        {"term": "SLE", "definition": "단일 보안 사고 발생 시 예상되는 손실액"},
        {"term": "ARO", "definition": "특정 위협이 1년 동안 발생할 것으로 예상되는 횟수"},
        {"term": "BCP", "definition": "재해 시에도 핵심 비즈니스 기능을 지속하기 위한 계획"},
        {"term": "RPO", "definition": "재해 발생 시 허용 가능한 최대 데이터 손실 시점"},
        {"term": "RTO", "definition": "재해 발생 후 서비스를 복구해야 하는 목표 시간"},
        {"term": "핫 사이트", "definition": "즉시 서비스 전환이 가능한 완전히 운영 중인 백업 사이트"},
        {"term": "잔여 위험", "definition": "보안 대책 적용 후에도 남아있는 위험"},
        {"term": "ISMS-P", "definition": "정보보호와 개인정보보호를 통합한 관리체계 인증"},
        {"term": "망분리", "definition": "업무망과 인터넷망을 물리적 또는 논리적으로 분리하는 보안 조치"},
        {"term": "침해사고 신고", "definition": "침해사고 발생 시 24시간 내 KISA에 신고해야 하는 법적 의무"},
        {"term": "개인정보 영향평가", "definition": "개인정보 처리 시스템 구축 전 위험도를 사전에 평가하는 제도"},
    ],
}

WRONG_NOTE_FILE = Path.home() / ".security_quiz_wrong_notes.json"


def load_wrong_notes() -> dict:
    if WRONG_NOTE_FILE.exists():
        try:
            with open(WRONG_NOTE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_wrong_notes(notes: dict) -> None:
    try:
        with open(WRONG_NOTE_FILE, "w", encoding="utf-8") as f:
            json.dump(notes, f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"오답 노트 저장 실패: {e}", file=sys.stderr)


def get_questions(subject: Optional[str], count: int, wrong_only: bool) -> list[dict]:
    wrong_notes = load_wrong_notes()

    if wrong_only:
        pool = [
            {"subject": subj, **item}
            for subj, items in QUIZ_DATA.items()
            for item in items
            if item["term"] in wrong_notes
        ]
    elif subject and subject in QUIZ_DATA:
        pool = [{"subject": subject, **item} for item in QUIZ_DATA[subject]]
    else:
        pool = [
            {"subject": subj, **item}
            for subj, items in QUIZ_DATA.items()
            for item in items
        ]

    if not pool:
        print("출제할 문제가 없습니다.", file=sys.stderr)
        sys.exit(1)

    random.shuffle(pool)
    return pool[:min(count, len(pool))]


def run_quiz(questions: list[dict]) -> tuple[int, int, list[str]]:
    correct = 0
    total = len(questions)
    wrong_terms: list[str] = []
    wrong_notes = load_wrong_notes()

    print(f"\n{'='*60}")
    print(f" 정보보안기사 키워드 퀴즈 시작 (총 {total}문제)")
    print(f"{'='*60}\n")

    for i, q in enumerate(questions, 1):
        print(f"[{i}/{total}] 과목: {q['subject']}")
        print(f"설명: {q['definition']}")
        answer = input("정답 입력 (모르면 Enter): ").strip()

        if answer.lower() == q["term"].lower() or answer == q["term"]:
            print("정답입니다!\n")
            correct += 1
            if q["term"] in wrong_notes:
                wrong_notes[q["term"]]["correct_count"] = (
                    wrong_notes[q["term"]].get("correct_count", 0) + 1
                )
                if wrong_notes[q["term"]]["correct_count"] >= 3:
                    del wrong_notes[q["term"]]
        else:
            print(f"오답! 정답: {q['term']}\n")
            wrong_terms.append(q["term"])
            wrong_notes[q["term"]] = {
                "definition": q["definition"],
                "subject": q["subject"],
                "last_wrong": datetime.datetime.now().isoformat(),
                "wrong_count": wrong_notes.get(q["term"], {}).get("wrong_count", 0) + 1,
                "correct_count": 0,
            }

    save_wrong_notes(wrong_notes)
    return correct, total, wrong_terms


def show_wrong_notes() -> None:
    notes = load_wrong_notes()
    if not notes:
        print("저장된 오답 노트가 없습니다.")
        return

    print(f"\n{'='*60}")
    print(f" 오답 노트 ({len(notes)}개 항목)")
    print(f"{'='*60}\n")

    for term, info in sorted(notes.items(), key=lambda x: x[1].get("wrong_count", 0), reverse=True):
        print(f"용어: {term}")
        print(f"  과목: {info.get('subject', '미분류')}")
        print(f"  정의: {info.get('definition', '')}")
        print(f"  오답 횟수: {info.get('wrong_count', 0)}")
        print(f"  마지막 오답: {info.get('last_wrong', '알 수 없음')[:10]}")
        print()


def list_subjects() -> None:
    print("\n사용 가능한 과목:")
    for subj, items in QUIZ_DATA.items():
        print(f"  - {subj} ({len(items)}개 키워드)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="정보보안기사 필기 키워드 퀴즈 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 quiz_tool.py                          # 전체 과목 랜덤 10문제
  python3 quiz_tool.py --subject 시스템보안      # 시스템보안 과목만
  python3 quiz_tool.py --count 20               # 20문제 출제
  python3 quiz_tool.py --wrong-only             # 오답 노트만 출제
  python3 quiz_tool.py --show-notes             # 오답 노트 확인
  python3 quiz_tool.py --list-subjects          # 과목 목록 확인
        """,
    )
    parser.add_argument("--subject", "-s", type=str, help="특정 과목 선택")
    parser.add_argument("--count", "-n", type=int, default=10, help="출제 문제 수 (기본: 10)")
    parser.add_argument("--wrong-only", "-w", action="store_true", help="오답 노트 문제만 출제")
    parser.add_argument("--show-notes", action="store_true", help="오답 노트 내용 출력")
    parser.add_argument("--list-subjects", "-l", action="store_true", help="과목 목록 출력")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_subjects:
        list_subjects()
        return

    if args.show_notes:
        show_wrong_notes()
        return

    questions = get_questions(args.subject, args.count, args.wrong_only)
    correct, total, wrong_terms = run_quiz(questions)

    print(f"\n{'='*60}")
    print(f" 퀴즈 결과: {correct}/{total} ({correct/total*100:.1f}%)")
    print(f"{'='*60}")

    if wrong_terms:
        print(f"\n오답 목록 ({len(wrong_terms)}개):")
        for term in wrong_terms:
            print(f"  - {term}")
        print(f"\n오답 노트가 {WRONG_NOTE_FILE}에 저장되었습니다.")
    else:
        print("\n모든 문제를 맞혔습니다!")

    if correct / total >= 0.8:
        print("합격권입니다! 계속 유지하세요.")
    elif correct / total >= 0.6:
        print("아슬아슬합니다. 오답 노트를 복습하세요.")
    else:
        print("기초부터 다시 공부하는 것을 권장합니다.")


if __name__ == "__main__":
    main()
```

---

## 시험 준비 체크리스트

- [ ] 5과목 핵심 키워드 전체 암기 완료
- [ ] 과목당 모의고사 3회 이상 풀기
- [ ] 오답 노트 키워드 3회 이상 반복 학습
- [ ] 법령 조항 번호 및 핵심 내용 암기
- [ ] 암호 알고리즘 비교표 완성
- [ ] 공격 유형별 원리와 대응 방법 세트 암기
- [ ] ALE 계산 문제 5문제 이상 직접 풀기
- [ ] 최신 기출문제 분석 및 출제 경향 파악
