> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 모델링 실전 연습

## 목차
1. [전자상거래 웹앱 위협 모델링](#전자상거래-웹앱-위협-모델링)
2. [모바일 뱅킹 앱 위협 모델링](#모바일-뱅킹-앱-위협-모델링)
3. [Kubernetes 클러스터 위협 모델링](#kubernetes-클러스터-위협-모델링)
4. [완화 통제 도출](#완화-통제-도출)
5. [위협 → 보안 요구사항 → 테스트 케이스 연계](#위협--보안-요구사항--테스트-케이스-연계)
6. [전체 워크플로우 CLI 도구](#전체-워크플로우-cli-도구)

---

## 전자상거래 웹앱 위협 모델링

### 시스템 아키텍처

```
[클라이언트]
  ├── 웹 브라우저 (React SPA)
  └── 모바일 앱 (iOS/Android)
         │ HTTPS/TLS 1.3
         ↓
[CDN/WAF] ← Cloudflare / AWS CloudFront
         │
         ↓
[Load Balancer] ── AWS ALB
         │
         ↓
[API Gateway] ── Kong / AWS API Gateway
  ├── Rate Limiting
  ├── JWT 검증
  └── 요청 로깅
         │
         ├──────────────────────┬───────────────────────┐
         ↓                      ↓                       ↓
[인증 서비스]           [상품 서비스]            [주문 서비스]
 Python/FastAPI          Python/FastAPI           Python/FastAPI
         │                      │                       │
         ↓                      ↓                       ↓
[사용자 DB]             [상품 DB]               [주문 DB]
 PostgreSQL              PostgreSQL               PostgreSQL
         │
         ├──[Redis 세션 캐시]
         └──[AWS S3 파일 저장소]
                                          ↓
                              [결제 서비스] ── Stripe API
```

### DFD 신뢰 경계

```
신뢰 경계 정의:
TB-01: 인터넷 (신뢰도 0) ↔ CDN/WAF (신뢰도 1)
TB-02: CDN/WAF ↔ API Gateway (신뢰도 2)
TB-03: API Gateway ↔ 마이크로서비스 (신뢰도 3)
TB-04: 마이크로서비스 ↔ 데이터베이스 (신뢰도 4)
TB-05: 내부 서비스 ↔ 외부 결제 서비스 (신뢰도 1)
```

### STRIDE 분석 매트릭스

```
컴포넌트: 인증 서비스 (/api/v1/auth)

┌──────┬────────────────────────────────────┬──────────┬──────────────────────────────────────┐
│STRIDE│ 위협 시나리오                        │ 심각도   │ 완화 방안                             │
├──────┼────────────────────────────────────┼──────────┼──────────────────────────────────────┤
│  S   │ JWT 알고리즘 혼동 공격 (alg:none)    │ Critical │ 알고리즘 명시적 허용 목록 검증         │
│  S   │ 탈취된 Refresh Token 재사용          │ High     │ Refresh Token Rotation + 블랙리스트   │
│  T   │ 비밀번호 재설정 링크 토큰 예측       │ High     │ CSPRNG로 토큰 생성, 만료 시간 설정    │
│  R   │ 로그인/로그아웃 이벤트 감사 미비     │ Medium   │ 모든 인증 이벤트 구조화 로그           │
│  I   │ 에러 응답에 계정 존재 여부 노출      │ Medium   │ "잘못된 이메일 또는 비밀번호" 통일     │
│  I   │ 디버그 로그에 Access Token 기록     │ High     │ 민감 데이터 로그 마스킹               │
│  D   │ 로그인 API 브루트포스               │ High     │ 5회 실패 후 잠금, IP Rate Limiting    │
│  D   │ 대량 계정 생성 (Account Stuffing)   │ Medium   │ CAPTCHA, 이메일 인증 필수             │
│  E   │ IDOR로 타 사용자 프로필 수정        │ Critical │ 서버 측 소유권 검증                   │
│  E   │ 관리자 비밀번호 재설정 API 노출     │ Critical │ 관리자 API RBAC + IP 화이트리스트     │
└──────┴────────────────────────────────────┴──────────┴──────────────────────────────────────┘

컴포넌트: 주문 서비스 (/api/v1/orders)

┌──────┬────────────────────────────────────┬──────────┬──────────────────────────────────────┐
│STRIDE│ 위협 시나리오                        │ 심각도   │ 완화 방안                             │
├──────┼────────────────────────────────────┼──────────┼──────────────────────────────────────┤
│  S   │ 타 사용자 주문 조회 (IDOR)           │ High     │ 주문 소유자 서버 측 검증              │
│  T   │ 주문 금액 파라미터 변조              │ Critical │ 서버 측 금액 재계산, 서명된 카트      │
│  T   │ 쿠폰 코드 중복 사용                 │ High     │ 쿠폰 원자적 사용 처리 (Redis 락)      │
│  R   │ 주문 생성/취소 이력 비감사           │ Medium   │ 이벤트 소싱 패턴 적용                │
│  I   │ 주문 목록 API에서 타 사용자 데이터  │ High     │ 쿼리에 user_id 필터 강제              │
│  D   │ 재고 0인 상품 대량 주문 시도         │ Medium   │ 재고 검증 로직 강화, Rate Limiting    │
│  E   │ 결제 없이 주문 확정 상태 변경       │ Critical │ 결제 서비스 콜백 검증, 상태 머신      │
└──────┴────────────────────────────────────┴──────────┴──────────────────────────────────────┘
```

### 공격 트리: 결제 정보 탈취

```
[결제 정보 탈취]
     (OR)
     ├── [전송 중 탈취] (AND)
     │       ├── {MITM 위치 확보: ARP Spoofing}
     │       └── {SSL Strip 또는 인증서 위조}
     │
     ├── [저장된 데이터 탈취] (OR)
     │       ├── [DB 직접 접근] (OR)
     │       │       ├── {SQL Injection → DB 덤프}
     │       │       │     확률: 0.3 (WAF 우회 성공률)
     │       │       └── {자격증명 탈취 후 DB 직접 연결}
     │       │             확률: 0.1
     │       └── {S3 버킷 퍼블릭 노출}
     │               확률: 0.05
     │
     └── [애플리케이션 레이어] (OR)
             ├── {결제 API 응답에 카드번호 포함}
             │     확률: 0.2
             └── {로그 파일에 카드번호 기록}
                   확률: 0.15
```

### Kill Chain 매핑

```
시나리오: SQL Injection으로 내부망 침투

1. Reconnaissance (정찰)
   - subfinder -d example.com → 서브도메인 열거
   - nuclei -t technologies/ -u https://shop.example.com → 기술 스택 탐지
   - waybackurls shop.example.com | gf sqli → 잠재적 SQLI 엔드포인트

2. Weaponization
   - sqlmap 자동화 스크립트 준비
   - UNION-based injection 페이로드

3. Delivery
   - GET /api/products?category=1' OR '1'='1
   - POST /api/search {"q": "'; SELECT version()--"}

4. Exploitation
   sqlmap -u "https://shop.example.com/api/products?id=1" \
     --dbms=postgresql --batch --level=3 --risk=2

5. Installation
   - xp_cmdshell 또는 COPY TO/FROM 파일 작성으로 웹쉘 배치

6. C2
   - DNS over HTTPS 터널링
   - 합법적 서비스(Pastebin) 통한 C2

7. Actions on Objectives
   - SELECT card_number, cvv FROM payment_methods
   - 데이터 압축 후 HTTPS로 외부 전송
```

---

## 모바일 뱅킹 앱 위협 모델링

### 시스템 구성

```
[모바일 앱]
  ├── iOS (Swift)
  └── Android (Kotlin)
       │
       │ HTTPS + Certificate Pinning
       ↓
[모바일 API Gateway]
  ├── 기기 인증 (Device Fingerprint)
  ├── mTLS
  └── API Key 검증
       │
       ├──[계좌 서비스]──[계좌 DB]
       ├──[이체 서비스]──[이체 DB]
       ├──[알림 서비스]──[APNs/FCM]
       └──[인증 서비스]──[사용자 DB]
                              │
                         [HSM] (Hardware Security Module)
                         [키 관리 서비스]
```

### OWASP MASVS 기반 위협 분석

```
MASVS (Mobile Application Security Verification Standard)

Level 1 (기본): MASVS-L1
Level 2 (고급): MASVS-L2 (뱅킹 앱 필수)
R (복원력): MASVS-R (루팅/탈옥 감지)

위협 영역:
┌─────────────────────┬──────────────────────────────────────────┐
│ 영역                │ 위협 시나리오                             │
├─────────────────────┼──────────────────────────────────────────┤
│ 아키텍처/설계       │ 백엔드 API 직접 노출, 내부 URL 하드코딩  │
│ 데이터 저장         │ SharedPreferences에 인증 토큰 평문 저장  │
│ 암호화              │ 취약한 알고리즘 (MD5, DES) 사용          │
│ 인증                │ 생체인증 우회, PIN 추측 허용             │
│ 네트워크 통신       │ Certificate Pinning 미적용               │
│ 플랫폼 상호작용     │ Intent 스누핑, 클립보드 민감정보 노출    │
│ 코드 품질           │ 디버그 로그 프로덕션 노출                │
│ 변조 방지           │ 루팅/탈옥 기기에서 앱 실행 허용          │
└─────────────────────┴──────────────────────────────────────────┘
```

### STRIDE 분석 (모바일 뱅킹)

```
영역: 이체 서비스

┌──────┬──────────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│STRIDE│ 위협                                      │ 심각도   │ 완화                                │
├──────┼──────────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│  S   │ 다른 기기에서 세션 토큰 재사용            │ Critical │ 기기 바인딩 토큰, 기기 변경 알림    │
│  S   │ 딥링크를 통한 CSRF 이체                  │ High     │ 이체 재확인 (OTP/생체인증)          │
│  T   │ SSL Pinning 우회 후 이체 금액 변조        │ Critical │ 요청 서명 (HMAC + 타임스탬프)       │
│  T   │ 로컬 DB(SQLite) 직접 수정                │ High     │ SQLCipher로 DB 암호화               │
│  R   │ 이체 트랜잭션 ID 중복 사용 (Replay)      │ Critical │ 이체 요청에 Nonce 포함, 24시간 유효 │
│  I   │ 로그캣에 계좌번호 기록                   │ High     │ ProGuard + 민감 로그 제거           │
│  I   │ 스크린샷으로 계좌 정보 캡처              │ Medium   │ FLAG_SECURE 설정                    │
│  D   │ 생체인증 서버 장애 시 서비스 전체 중단   │ High     │ 대체 인증(PIN) 폴백                 │
│  E   │ 루팅 기기에서 Frida로 인증 우회          │ Critical │ 루팅 감지 + 서버 측 검증            │
│  E   │ 앱 변조 후 서명 검증 우회                │ Critical │ 앱 무결성 검사, Play Integrity API  │
└──────┴──────────────────────────────────────────┴──────────┴─────────────────────────────────────┘
```

### 모바일 보안 테스트 명령어

```bash
# MobSF (Mobile Security Framework) 정적 분석
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# APK 수동 분석
apktool d app.apk -o decompiled/
grep -r "password\|secret\|api_key\|token" decompiled/ --include="*.xml" --include="*.smali"

# SSL Pinning 확인 (Android)
grep -r "CertificatePinner\|TrustManager\|pinCertificate" decompiled/

# jadx로 APK 역컴파일
jadx -d output/ app.apk
find output/ -name "*.java" | xargs grep -l "http://"

# frida를 통한 런타임 분석
pip3 install frida-tools
frida-ps -U  # 연결된 기기 프로세스 목록

# SSL Pinning 우회 스크립트
frida -U -f com.example.bankapp \
  --codeshare 0xdea/frida-scripts/api-monitor \
  -l ssl_pinning_bypass.js

# Burp Suite Certificate Pinning 우회 (루팅 기기)
adb push burp_cert.der /sdcard/
adb shell "su -c 'cp /sdcard/burp_cert.der /system/etc/security/cacerts/'"

# drozer 동적 분석
drozer console connect
dz> run app.package.attacksurface com.example.bankapp
dz> run app.activity.info -a com.example.bankapp
dz> run app.provider.finduri com.example.bankapp
```

---

## Kubernetes 클러스터 위협 모델링

### 클러스터 아키텍처

```
[개발자/운영자]
  ├── kubectl (OIDC 인증)
  └── Helm
         │
         ↓
[Control Plane]
  ├── kube-apiserver (6443/TCP)
  ├── etcd (2379-2380/TCP, 암호화된 내부)
  ├── kube-scheduler
  └── kube-controller-manager
         │
         ↓
[Worker Nodes]
  ├── kubelet (10250/TCP)
  ├── kube-proxy
  ├── containerd/CRI-O
  └── Pods
         ├── 애플리케이션 Pod
         ├── 모니터링 Pod (Prometheus/Grafana)
         └── Ingress Controller (NGINX)

[Add-ons]
  ├── Istio Service Mesh (mTLS)
  ├── OPA Gatekeeper (정책)
  ├── Falco (런타임 보안)
  └── Vault (시크릿 관리)
```

### STRIDE 분석 (Kubernetes)

```
컴포넌트: kube-apiserver

┌──────┬──────────────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│STRIDE│ 위협                                          │ 심각도   │ 완화                                │
├──────┼──────────────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│  S   │ 서비스 어카운트 토큰 탈취 후 API 접근        │ Critical │ 단기 토큰 (1h), Projected Volumes   │
│  S   │ 익명 API 접근 (--anonymous-auth=true)        │ Critical │ 익명 인증 비활성화                  │
│  T   │ etcd 직접 접근으로 Secret 수정               │ Critical │ etcd 암호화, 네트워크 격리          │
│  R   │ API 감사 로그(Audit Log) 미설정              │ High     │ Audit Policy 설정, SIEM 연동        │
│  I   │ 네임스페이스 간 Secret 열람                  │ High     │ RBAC 최소 권한, NetworkPolicy       │
│  D   │ 대량 API 요청으로 kube-apiserver 과부하      │ High     │ API Priority and Fairness 설정      │
│  E   │ ClusterRole escalation via RBAC              │ Critical │ RBAC 권한 감사, OPA 정책            │
└──────┴──────────────────────────────────────────────┴──────────┴─────────────────────────────────────┘

컴포넌트: 컨테이너 런타임 / Pod

┌──────┬──────────────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│STRIDE│ 위협                                          │ 심각도   │ 완화                                │
├──────┼──────────────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│  S   │ 취약한 컨테이너 이미지로 위장                │ High     │ 이미지 서명 검증 (cosign, Notary)   │
│  T   │ 컨테이너 내부에서 호스트 파일시스템 수정     │ Critical │ privileged: false, readOnlyRoot     │
│  I   │ 환경변수로 Secret 전달 (k8s secret → env)   │ High     │ Vault 사이드카, CSI Secret 드라이버 │
│  D   │ 리소스 제한 미설정으로 OOM/CPU 소진         │ High     │ LimitRange, ResourceQuota 설정      │
│  E   │ hostPID/hostNetwork로 호스트 접근           │ Critical │ PodSecurityAdmission, PSP           │
│  E   │ SSRF로 IMDS 접근 (169.254.169.254)          │ Critical │ NetworkPolicy, IMDSv2 강제          │
└──────┴──────────────────────────────────────────────┴──────────┴─────────────────────────────────────┘
```

### K8s 보안 설정 명령어

```bash
# CIS Kubernetes Benchmark 검사
docker run --rm \
  --pid=host \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  -v /usr/bin/kubectl:/usr/bin/kubectl:ro \
  aquasec/kube-bench:latest

# kube-score (매니페스트 정적 분석)
kube-score score deployment.yaml
kube-score score --output-format ci k8s/

# Trivy로 K8s 클러스터 스캔
trivy k8s --report all cluster

# Falco 런타임 규칙 확인
kubectl get configmap falco-config -n falco -o yaml

# RBAC 분석
kubectl auth can-i --list --as=system:serviceaccount:default:myapp
kubectl get clusterrolebindings -o json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    subjects = item.get('subjects', [])
    role = item.get('roleRef', {}).get('name', '')
    for s in subjects:
        if s.get('name') != 'system:masters':
            print(f'{name}: {s[\"name\"]} → {role}')
"

# Secret 암호화 확인
kubectl get secret mysecret -o jsonpath='{.data.password}' | base64 -d

# NetworkPolicy 검증
kubectl get networkpolicies -A
kubectl describe networkpolicy default-deny-all

# Pod Security Standards 확인
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

# Audit Log 설정 확인
kubectl get pod kube-apiserver-* -n kube-system -o yaml | \
  grep -A5 audit
```

---

## 완화 통제 도출

### 완화 통제 분류 체계

```
통제 유형:
┌──────────────┬──────────────────────────────────────┐
│ 유형         │ 설명                                  │
├──────────────┼──────────────────────────────────────┤
│ 예방 통제    │ 위협 발생을 사전에 방지               │
│ 탐지 통제    │ 위협 발생을 실시간으로 탐지           │
│ 교정 통제    │ 위협 발생 후 피해 최소화/복구         │
│ 억제 통제    │ 공격자 의지를 꺾는 통제 (법적 경고)  │
└──────────────┴──────────────────────────────────────┘

STRIDE → 완화 통제 매핑:

Spoofing 완화:
  예방: MFA, 강력한 비밀번호 정책, mTLS
  탐지: 비정상 로그인 탐지, SIEM 알럿
  교정: 자동 계정 잠금, 강제 로그아웃

Tampering 완화:
  예방: 입력 검증, 파라미터화 쿼리, WAF
  탐지: FIM (파일 무결성 모니터링), DB 감사
  교정: 자동 롤백, 백업 복구

Repudiation 완화:
  예방: 디지털 서명 요구, 세션 바인딩
  탐지: 중앙화된 감사 로그, SIEM
  교정: 포렌식 분석, 로그 보존

Information Disclosure 완화:
  예방: 암호화 (전송/저장), RBAC, 최소 권한
  탐지: DLP 솔루션, 비정상 쿼리 탐지
  교정: 데이터 분류, 노출 범위 확인

Denial of Service 완화:
  예방: Rate Limiting, 자원 제한, 캐싱
  탐지: 이상 트래픽 탐지, APM 모니터링
  교정: Auto Scaling, DDoS 방어 서비스

Elevation of Privilege 완화:
  예방: 최소 권한, RBAC, 입력 검증
  탐지: 권한 변경 모니터링, UEBA
  교정: 권한 회수, 침해 격리
```

### NIST 800-53 통제와 매핑

```
위협 → NIST 통제 매핑:

Spoofing:
  IA-2: Identification and Authentication (Organizational Users)
  IA-3: Device Identification and Authentication
  SC-8: Transmission Confidentiality and Integrity

Tampering:
  SI-10: Information Input Validation
  SI-7: Software, Firmware, and Information Integrity
  SC-28: Protection of Information at Rest

Repudiation:
  AU-2: Event Logging
  AU-9: Protection of Audit Information
  AU-12: Audit Record Generation

Information Disclosure:
  SC-8: Transmission Confidentiality and Integrity
  SC-28: Protection of Information at Rest
  AC-3: Access Enforcement

Denial of Service:
  SC-5: Denial-of-Service Protection
  SI-13: Predictable Failure Prevention
  CP-10: Information System Recovery and Reconstitution

Elevation of Privilege:
  AC-6: Least Privilege
  AC-3: Access Enforcement
  CM-7: Least Functionality
```

---

## 위협 → 보안 요구사항 → 테스트 케이스 연계

### 연계 매핑 구조

```
위협 T001 (SQL Injection)
    ↓
보안 요구사항 SR-001
    "모든 DB 쿼리는 파라미터화 쿼리 또는 ORM을 사용해야 한다"
    ↓
테스트 케이스 TC-001
    "SQLI 페이로드로 각 입력 필드 테스트"
    ↓
자동화 테스트 (pytest + httpx)
    ↓
CI/CD 파이프라인에서 지속 실행
```

### 보안 요구사항 예시 (전자상거래)

```
SR-AUTH-001: 비밀번호 정책
  - 최소 12자 이상
  - 대/소문자, 숫자, 특수문자 포함
  - 최근 10개 비밀번호 재사용 금지
  - 90일 강제 변경
  출처 위협: T001 (스푸핑 - 약한 비밀번호 브루트포스)

SR-AUTH-002: MFA 적용
  - 민감 작업 (이체, 비밀번호 변경) 시 MFA 필수
  - TOTP 또는 SMS OTP 지원
  출처 위협: T002 (스푸핑 - 자격증명 탈취 후 로그인)

SR-INPUT-001: 입력 검증
  - 모든 입력값 서버 측 검증
  - SQL 특수문자 파라미터화 처리
  - 파일 업로드: 파일 유형, 크기 제한
  출처 위협: T003 (변조 - SQL Injection)

SR-API-001: API 설계
  - GUID/UUID 기반 리소스 식별자 사용
  - 모든 API 요청에 인가 검사 필수
  - 응답에 불필요한 내부 정보 포함 금지
  출처 위협: T004 (권한 상승 - IDOR)

SR-LOG-001: 감사 로깅
  - 로그인/로그아웃/실패 이벤트 기록
  - 중요 데이터 접근 기록
  - 로그 변조 방지 (WORM 스토리지)
  - 로그 보존 기간: 1년
  출처 위협: T005 (부인 - 행위 추적 불가)
```

### 보안 테스트 케이스 예시

```python
# security_tests/test_auth_security.py
import pytest
import httpx

BASE_URL = "http://localhost:8000"

class TestAuthenticationSecurity:
    """SR-AUTH-001, SR-AUTH-002 테스트"""

    def test_brute_force_protection(self):
        """TC-AUTH-001: 5회 실패 후 계정 잠금"""
        client = httpx.Client()
        for i in range(5):
            resp = client.post(f"{BASE_URL}/api/auth/login", json={
                "email": "test@example.com",
                "password": f"wrong_password_{i}"
            })
        # 6번째 시도는 잠금 응답
        resp = client.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@example.com",
            "password": "any_password"
        })
        assert resp.status_code == 429  # Too Many Requests

    def test_jwt_algorithm_confusion(self):
        """TC-AUTH-002: JWT alg:none 공격 방어"""
        # 서명 없는 JWT 생성
        import base64
        header = base64.b64encode(
            b'{"alg":"none","typ":"JWT"}'
        ).rstrip(b'=').decode()
        payload = base64.b64encode(
            b'{"sub":"admin","role":"admin"}'
        ).rstrip(b'=').decode()
        fake_jwt = f"{header}.{payload}."

        resp = httpx.get(
            f"{BASE_URL}/api/admin/users",
            headers={"Authorization": f"Bearer {fake_jwt}"}
        )
        assert resp.status_code == 401

    def test_error_message_enumeration(self):
        """TC-AUTH-003: 계정 존재 여부 노출 금지"""
        r1 = httpx.post(f"{BASE_URL}/api/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "password123"
        })
        r2 = httpx.post(f"{BASE_URL}/api/auth/login", json={
            "email": "existing@example.com",
            "password": "wrong_password"
        })
        # 동일한 에러 메시지여야 함
        assert r1.json().get("message") == r2.json().get("message")
        assert r1.status_code == r2.status_code == 401


class TestInputValidation:
    """SR-INPUT-001 테스트"""

    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM users",
        "1' AND SLEEP(5)--",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
    ]

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_sqli_in_search(self, payload: str):
        """TC-INPUT-001: 검색 API SQLI 방어"""
        resp = httpx.get(
            f"{BASE_URL}/api/products",
            params={"q": payload}
        )
        # 정상 응답 (400 또는 빈 결과)이어야 함
        assert resp.status_code in (200, 400)
        # DB 에러 메시지가 노출되지 않아야 함
        body = resp.text.lower()
        for keyword in ["sql", "syntax error", "postgresql", "mysql"]:
            assert keyword not in body

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_in_review(self, payload: str):
        """TC-INPUT-002: 리뷰 API XSS 방어"""
        resp = httpx.post(
            f"{BASE_URL}/api/reviews",
            json={"product_id": 1, "content": payload, "rating": 5},
            headers={"Authorization": "Bearer valid_token_here"}
        )
        if resp.status_code == 201:
            # 저장된 내용에 스크립트가 이스케이프되어야 함
            review_id = resp.json()["id"]
            get_resp = httpx.get(f"{BASE_URL}/api/reviews/{review_id}")
            assert "<script>" not in get_resp.text
```

---

## 전체 워크플로우 CLI 도구

```python
#!/usr/bin/env python3
"""
위협 모델링 전체 워크플로우 CLI 도구

DFD 입력 → STRIDE 분석 → DREAD 점수 → 보고서 생성

사용법:
    python3 threat_modeling_cli.py init --name "전자상거래" --output model.json
    python3 threat_modeling_cli.py add-element --model model.json --interactive
    python3 threat_modeling_cli.py analyze --model model.json --method stride
    python3 threat_modeling_cli.py score --model model.json --method dread
    python3 threat_modeling_cli.py report --model model.json --format html --output report.html
    python3 threat_modeling_cli.py full-pipeline --name "쇼핑몰" --system ecommerce
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


# ─── 데이터 모델 ─────────────────────────────────────────────────────────────

class ElementType(str, Enum):
    PROCESS = "Process"
    DATA_FLOW = "DataFlow"
    DATA_STORE = "DataStore"
    EXTERNAL_ENTITY = "ExternalEntity"


class StrideCategory(str, Enum):
    S = "Spoofing"
    T = "Tampering"
    R = "Repudiation"
    I = "Information Disclosure"
    D = "Denial of Service"
    E = "Elevation of Privilege"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class DREADScore:
    damage: int = 5
    reproducibility: int = 5
    exploitability: int = 5
    affected_users: int = 5
    discoverability: int = 5

    @property
    def total(self) -> float:
        return (self.damage + self.reproducibility + self.exploitability
                + self.affected_users + self.discoverability) / 5.0

    @property
    def severity(self) -> Severity:
        t = self.total
        if t >= 8.0:
            return Severity.CRITICAL
        elif t >= 6.0:
            return Severity.HIGH
        elif t >= 3.0:
            return Severity.MEDIUM
        return Severity.LOW


@dataclass
class DFDElement:
    id: str
    name: str
    element_type: ElementType
    description: str = ""
    technologies: list[str] = field(default_factory=list)
    trust_boundary: Optional[str] = None


@dataclass
class TrustBoundary:
    id: str
    name: str
    from_zone: str
    to_zone: str


@dataclass
class Threat:
    id: str
    stride_category: StrideCategory
    title: str
    description: str
    affected_element_id: str
    attack_scenario: str
    impact: str
    dread: DREADScore = field(default_factory=DREADScore)
    mitigations: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    security_requirements: list[str] = field(default_factory=list)
    test_cases: list[str] = field(default_factory=list)
    status: str = "Open"

    @property
    def severity(self) -> Severity:
        return self.dread.severity


@dataclass
class ThreatModel:
    name: str
    description: str
    version: str = "1.0"
    created_at: str = ""
    elements: list[DFDElement] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "created_at": self.created_at,
            "elements": [
                {
                    "id": e.id,
                    "name": e.name,
                    "element_type": e.element_type.value,
                    "description": e.description,
                    "technologies": e.technologies,
                    "trust_boundary": e.trust_boundary,
                }
                for e in self.elements
            ],
            "trust_boundaries": [
                {
                    "id": b.id,
                    "name": b.name,
                    "from_zone": b.from_zone,
                    "to_zone": b.to_zone,
                }
                for b in self.trust_boundaries
            ],
            "threats": [
                {
                    "id": t.id,
                    "stride_category": t.stride_category.value,
                    "title": t.title,
                    "description": t.description,
                    "affected_element_id": t.affected_element_id,
                    "attack_scenario": t.attack_scenario,
                    "impact": t.impact,
                    "dread": {
                        "damage": t.dread.damage,
                        "reproducibility": t.dread.reproducibility,
                        "exploitability": t.dread.exploitability,
                        "affected_users": t.dread.affected_users,
                        "discoverability": t.dread.discoverability,
                        "total": round(t.dread.total, 1),
                        "severity": t.dread.severity.value,
                    },
                    "mitigations": t.mitigations,
                    "mitre_techniques": t.mitre_techniques,
                    "security_requirements": t.security_requirements,
                    "test_cases": t.test_cases,
                    "status": t.status,
                }
                for t in self.threats
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatModel":
        model = cls(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            created_at=data.get("created_at", ""),
        )
        for e in data.get("elements", []):
            model.elements.append(DFDElement(
                id=e["id"],
                name=e["name"],
                element_type=ElementType(e["element_type"]),
                description=e.get("description", ""),
                technologies=e.get("technologies", []),
                trust_boundary=e.get("trust_boundary"),
            ))
        for b in data.get("trust_boundaries", []):
            model.trust_boundaries.append(TrustBoundary(
                id=b["id"], name=b["name"],
                from_zone=b["from_zone"], to_zone=b["to_zone"],
            ))
        for t in data.get("threats", []):
            dread_d = t.get("dread", {})
            dread = DREADScore(
                damage=dread_d.get("damage", 5),
                reproducibility=dread_d.get("reproducibility", 5),
                exploitability=dread_d.get("exploitability", 5),
                affected_users=dread_d.get("affected_users", 5),
                discoverability=dread_d.get("discoverability", 5),
            )
            model.threats.append(Threat(
                id=t["id"],
                stride_category=StrideCategory(t["stride_category"]),
                title=t["title"],
                description=t.get("description", ""),
                affected_element_id=t.get("affected_element_id", ""),
                attack_scenario=t.get("attack_scenario", ""),
                impact=t.get("impact", ""),
                dread=dread,
                mitigations=t.get("mitigations", []),
                mitre_techniques=t.get("mitre_techniques", []),
                security_requirements=t.get("security_requirements", []),
                test_cases=t.get("test_cases", []),
                status=t.get("status", "Open"),
            ))
        return model

    def get_summary(self) -> dict:
        total = len(self.threats)
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_stride: dict[str, int] = {c.value: 0 for c in StrideCategory}
        open_count = 0

        for t in self.threats:
            by_severity[t.severity.value] += 1
            by_stride[t.stride_category.value] += 1
            if t.status == "Open":
                open_count += 1

        avg_dread = (
            sum(t.dread.total for t in self.threats) / total
            if total > 0 else 0
        )

        return {
            "total_threats": total,
            "total_elements": len(self.elements),
            "open_threats": open_count,
            "mitigated_threats": total - open_count,
            "average_dread_score": round(avg_dread, 1),
            "by_severity": by_severity,
            "by_stride": by_stride,
        }


# ─── STRIDE 자동 분석 엔진 ───────────────────────────────────────────────────

ELEMENT_STRIDE_MAP: dict[ElementType, list[StrideCategory]] = {
    ElementType.PROCESS: list(StrideCategory),
    ElementType.DATA_FLOW: [StrideCategory.T, StrideCategory.I, StrideCategory.D],
    ElementType.DATA_STORE: [StrideCategory.T, StrideCategory.R, StrideCategory.I, StrideCategory.D],
    ElementType.EXTERNAL_ENTITY: [StrideCategory.S, StrideCategory.R],
}

STRIDE_MITIGATIONS: dict[StrideCategory, list[str]] = {
    StrideCategory.S: ["강력한 인증 (MFA)", "세션 관리 강화", "mTLS 서비스 간 인증"],
    StrideCategory.T: ["입력 검증 (화이트리스트)", "디지털 서명", "WAF 배포"],
    StrideCategory.R: ["불변 감사 로그", "디지털 서명", "SIEM 연동"],
    StrideCategory.I: ["최소 권한 원칙", "전송/저장 암호화", "API 응답 최소화"],
    StrideCategory.D: ["Rate Limiting", "자원 제한 설정", "CDN/DDoS 방어"],
    StrideCategory.E: ["최소 권한 원칙", "서버 측 인가 검증", "권한 분리"],
}

STRIDE_TEST_CASES: dict[StrideCategory, list[str]] = {
    StrideCategory.S: [
        "탈취된 세션 토큰으로 API 접근 시도",
        "JWT alg:none 공격 테스트",
        "피싱 페이지 후 토큰 재사용 테스트",
    ],
    StrideCategory.T: [
        "숨겨진 필드 변조 테스트",
        "SQL Injection 페이로드 모든 입력에 적용",
        "파일 업로드 매직 바이트 변조",
    ],
    StrideCategory.R: [
        "감사 로그 생성 여부 확인",
        "로그 삭제 시도 후 SIEM 알럿 확인",
        "중요 작업의 타임스탬프 정확성 검증",
    ],
    StrideCategory.I: [
        "에러 응답에 내부 정보 노출 여부",
        "인증 없는 민감 API 접근 시도",
        "디렉토리 리스팅 및 민감 파일 접근",
    ],
    StrideCategory.D: [
        "Rate Limit 한계치 초과 요청 테스트",
        "대용량 페이로드 전송 테스트",
        "동시 요청 스트레스 테스트",
    ],
    StrideCategory.E: [
        "낮은 권한 사용자로 관리자 API 접근",
        "IDOR로 타 사용자 리소스 접근",
        "역할 파라미터 변조 테스트",
    ],
}


def auto_stride_analyze(model: ThreatModel) -> int:
    """STRIDE per Element 자동 분석"""
    threat_counter = len(model.threats)
    added = 0

    for element in model.elements:
        categories = ELEMENT_STRIDE_MAP.get(element.element_type, [])
        for cat in categories:
            threat_counter += 1
            threat = Threat(
                id=f"T{threat_counter:04d}",
                stride_category=cat,
                title=f"[{cat.value[:1]}] {element.name} - {cat.value}",
                description=f"{element.name} ({element.element_type.value})에서 발생 가능한 {cat.value} 위협",
                affected_element_id=element.id,
                attack_scenario=f"공격자가 {element.name}을 통해 {cat.value} 공격 수행",
                impact=f"{cat.value}으로 인한 보안 속성 침해",
                dread=DREADScore(),
                mitigations=STRIDE_MITIGATIONS.get(cat, []),
                security_requirements=[
                    f"SR-{cat.value[:1]}-{threat_counter:03d}: "
                    f"{element.name}에 대한 {cat.value} 방어 요구사항"
                ],
                test_cases=STRIDE_TEST_CASES.get(cat, []),
            )
            model.threats.append(threat)
            added += 1

    return added


# ─── 보고서 생성 ─────────────────────────────────────────────────────────────

def generate_html_report(model: ThreatModel) -> str:
    summary = model.get_summary()

    severity_colors = {
        "Critical": "#dc3545", "High": "#fd7e14",
        "Medium": "#ffc107", "Low": "#28a745",
    }

    sorted_threats = sorted(
        model.threats,
        key=lambda t: -t.dread.total
    )

    threat_rows = []
    for t in sorted_threats:
        sev_color = severity_colors.get(t.severity.value, "#333")
        mit_html = "<br>".join(f"• {m}" for m in t.mitigations[:3])
        req_html = "<br>".join(f"• {r}" for r in t.security_requirements[:2])
        tc_html = "<br>".join(f"• {tc}" for tc in t.test_cases[:2])

        threat_rows.append(
            f"<tr>"
            f"<td><code>{t.id}</code></td>"
            f"<td><strong>{t.stride_category.value[0]}</strong></td>"
            f"<td>{t.title}</td>"
            f"<td><span style='color:{sev_color};font-weight:bold'>"
            f"{t.severity.value}</span><br>"
            f"<small>DREAD: {t.dread.total:.1f}</small></td>"
            f"<td><small>{t.attack_scenario}</small></td>"
            f"<td><small>{mit_html}</small></td>"
            f"<td><small>{req_html}</small></td>"
            f"<td><small>{tc_html}</small></td>"
            f"<td>{t.status}</td>"
            f"</tr>"
        )

    # 요약 카드
    cards = []
    for sev in Severity:
        count = summary["by_severity"].get(sev.value, 0)
        color = severity_colors.get(sev.value, "#333")
        cards.append(
            f"<div style='display:inline-block;margin:8px;padding:15px;"
            f"border:2px solid {color};border-radius:8px;text-align:center;"
            f"min-width:110px;background:{color}18'>"
            f"<div style='font-size:2.2em;font-weight:bold;color:{color}'>{count}</div>"
            f"<div style='font-size:0.8em;color:#555'>{sev.value}</div>"
            f"</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>위협 모델 보고서: {model.name}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Malgun Gothic', sans-serif; background: #f5f7fb; color: #333; margin: 0; }}
  .header {{ background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
             color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0 0 8px; font-size: 1.6em; }}
  .header .meta {{ color: #aaa; font-size: 0.85em; }}
  .container {{ padding: 20px 40px; }}
  .card {{ background: white; border-radius: 10px; padding: 20px;
           margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); }}
  .card h2 {{ font-size: 1.1em; color: #444; margin-bottom: 15px;
              border-left: 4px solid #007bff; padding-left: 10px; }}
  .stat-row {{ display: flex; align-items: center; gap: 15px; flex-wrap: wrap; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82em; }}
  th {{ background: #2d3748; color: white; padding: 10px 8px;
        text-align: left; font-weight: 600; white-space: nowrap; }}
  td {{ padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  tr:hover {{ background: #f0f4ff; }}
  code {{ background: #e9ecef; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }}
</style>
</head>
<body>
<div class="header">
  <h1>위협 모델 보고서: {model.name}</h1>
  <div class="meta">
    생성: {datetime.now().strftime('%Y-%m-%d %H:%M')} |
    버전: {model.version} |
    총 위협: {summary['total_threats']}개 |
    평균 DREAD: {summary['average_dread_score']}
  </div>
</div>

<div class="container">
  <div class="card">
    <h2>위협 심각도 분포</h2>
    <div class="stat-row">
      {''.join(cards)}
      <div style="margin-left:auto;text-align:right;color:#666">
        <div>미해결: <strong style="color:#dc3545">{summary['open_threats']}</strong></div>
        <div>완화됨: <strong style="color:#28a745">{summary['mitigated_threats']}</strong></div>
        <div>DFD 요소: <strong>{summary['total_elements']}</strong></div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>위협 목록 (DREAD 점수 기준 정렬)</h2>
    <div style="overflow-x:auto">
    <table>
    <tr>
      <th>ID</th><th>STRIDE</th><th>위협명</th><th>심각도/DREAD</th>
      <th>공격 시나리오</th><th>완화 방안</th><th>보안 요구사항</th>
      <th>테스트 케이스</th><th>상태</th>
    </tr>
    {''.join(threat_rows)}
    </table>
    </div>
  </div>
</div>
</body>
</html>"""


def generate_json_report(model: ThreatModel) -> str:
    data = model.to_dict()
    data["report_metadata"] = {
        "generated_at": datetime.now().isoformat(),
        "summary": model.get_summary(),
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ─── CLI 명령 처리 ───────────────────────────────────────────────────────────

def cmd_init(args: argparse.Namespace) -> int:
    model = ThreatModel(
        name=args.name,
        description=args.description or "",
    )
    output = args.output
    output.write_text(
        json.dumps(model.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"위협 모델 초기화 완료: {output}")
    return 0


def cmd_add_element(args: argparse.Namespace) -> int:
    data = json.loads(args.model.read_text(encoding="utf-8"))
    model = ThreatModel.from_dict(data)

    if args.interactive:
        print("\n=== DFD 요소 추가 ===")
        type_map = {
            "1": ElementType.PROCESS,
            "2": ElementType.DATA_FLOW,
            "3": ElementType.DATA_STORE,
            "4": ElementType.EXTERNAL_ENTITY,
        }

        while True:
            name = input("\n요소 이름 (빈 줄로 종료): ").strip()
            if not name:
                break

            print("유형: 1=Process, 2=DataFlow, 3=DataStore, 4=ExternalEntity")
            choice = input("선택: ").strip()
            elem_type = type_map.get(choice, ElementType.PROCESS)
            desc = input("설명: ").strip()
            techs = input("기술 스택 (쉼표 구분): ").strip()

            elem_id = f"E{len(model.elements) + 1:03d}"
            model.elements.append(DFDElement(
                id=elem_id,
                name=name,
                element_type=elem_type,
                description=desc,
                technologies=[t.strip() for t in techs.split(",") if t.strip()],
            ))
            print(f"추가됨: {elem_id} - {name} ({elem_type.value})")
    else:
        elem_id = f"E{len(model.elements) + 1:03d}"
        model.elements.append(DFDElement(
            id=elem_id,
            name=args.name,
            element_type=ElementType(args.type),
            description=args.description or "",
        ))
        print(f"요소 추가됨: {elem_id} - {args.name}")

    args.model.write_text(
        json.dumps(model.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    data = json.loads(args.model.read_text(encoding="utf-8"))
    model = ThreatModel.from_dict(data)

    added = auto_stride_analyze(model)
    print(f"STRIDE 분석 완료: {added}개 위협 생성됨")
    print(f"총 위협: {len(model.threats)}")

    args.model.write_text(
        json.dumps(model.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """대화형 DREAD 점수 입력"""
    data = json.loads(args.model.read_text(encoding="utf-8"))
    model = ThreatModel.from_dict(data)

    unscored = [t for t in model.threats if t.dread.total == 5.0]
    print(f"점수 미부여 위협: {len(unscored)}개")

    for t in unscored:
        print(f"\n[{t.id}] {t.title}")
        print(f"  공격 시나리오: {t.attack_scenario}")
        print("  DREAD 점수 입력 (0-10, Enter=기본값 5):")

        for attr in ["damage", "reproducibility", "exploitability",
                     "affected_users", "discoverability"]:
            label_map = {
                "damage": "D - 피해 규모",
                "reproducibility": "R - 재현 용이성",
                "exploitability": "E - 익스플로잇 난이도",
                "affected_users": "A - 영향 사용자",
                "discoverability": "D - 발견 용이성",
            }
            while True:
                try:
                    val_str = input(f"    {label_map[attr]}: ").strip()
                    val = int(val_str) if val_str else 5
                    if 0 <= val <= 10:
                        setattr(t.dread, attr, val)
                        break
                    print("    0-10 범위로 입력하세요.")
                except ValueError:
                    print("    숫자를 입력하세요.")

        print(f"  → DREAD: {t.dread.total:.1f} ({t.dread.severity.value})")

    args.model.write_text(
        json.dumps(model.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"\n점수 저장 완료: {args.model}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    data = json.loads(args.model.read_text(encoding="utf-8"))
    model = ThreatModel.from_dict(data)

    if args.format == "html":
        content = generate_html_report(model)
    else:
        content = generate_json_report(model)

    output = args.output or Path(f"report.{args.format}")
    output.write_text(content, encoding="utf-8")

    summary = model.get_summary()
    print(f"보고서 생성 완료: {output}")
    print(f"  총 위협: {summary['total_threats']}")
    print(f"  Critical: {summary['by_severity']['Critical']}")
    print(f"  High: {summary['by_severity']['High']}")
    print(f"  평균 DREAD: {summary['average_dread_score']}")
    return 0


def cmd_full_pipeline(args: argparse.Namespace) -> int:
    """전체 파이프라인 실행"""
    print(f"\n=== 위협 모델링 파이프라인 시작: {args.name} ===\n")

    # 1. 모델 초기화
    model = ThreatModel(
        name=args.name,
        description=f"{args.name} 위협 모델",
    )

    # 2. 시스템별 요소 추가
    if args.system == "ecommerce":
        elements = [
            DFDElement("E001", "웹 브라우저", ElementType.EXTERNAL_ENTITY, "사용자 브라우저"),
            DFDElement("P001", "API Gateway", ElementType.PROCESS, "요청 라우팅", ["Kong"]),
            DFDElement("P002", "인증 서비스", ElementType.PROCESS, "JWT 인증", ["FastAPI"]),
            DFDElement("P003", "주문 서비스", ElementType.PROCESS, "주문 처리", ["FastAPI"]),
            DFDElement("P004", "결제 서비스", ElementType.PROCESS, "결제 처리", ["FastAPI"]),
            DFDElement("DS001", "사용자 DB", ElementType.DATA_STORE, "사용자 데이터", ["PostgreSQL"]),
            DFDElement("DS002", "주문 DB", ElementType.DATA_STORE, "주문 데이터", ["PostgreSQL"]),
            DFDElement("DS003", "세션 캐시", ElementType.DATA_STORE, "세션 토큰", ["Redis"]),
            DFDElement("DF001", "HTTPS 통신", ElementType.DATA_FLOW, "TLS 1.3"),
            DFDElement("E002", "결제 게이트웨이", ElementType.EXTERNAL_ENTITY, "Stripe API"),
        ]
    elif args.system == "kubernetes":
        elements = [
            DFDElement("E001", "kubectl 사용자", ElementType.EXTERNAL_ENTITY, "K8s 관리자"),
            DFDElement("P001", "kube-apiserver", ElementType.PROCESS, "K8s API", ["Go"]),
            DFDElement("P002", "kubelet", ElementType.PROCESS, "노드 에이전트"),
            DFDElement("P003", "앱 Pod", ElementType.PROCESS, "워크로드", ["Docker"]),
            DFDElement("DS001", "etcd", ElementType.DATA_STORE, "클러스터 상태"),
            DFDElement("DS002", "K8s Secret", ElementType.DATA_STORE, "민감 정보"),
            DFDElement("DF001", "API 통신", ElementType.DATA_FLOW, "mTLS"),
        ]
    else:
        print(f"알 수 없는 시스템: {args.system}", file=sys.stderr)
        return 1

    for elem in elements:
        model.elements.append(elem)
    print(f"1. DFD 요소 추가: {len(model.elements)}개")

    # 3. STRIDE 자동 분석
    added = auto_stride_analyze(model)
    print(f"2. STRIDE 분석: {added}개 위협 생성")

    # 4. DREAD 점수 (기본값 적용 - 실제로는 대화형 입력)
    print(f"3. DREAD 점수 적용 (기본값: 5.0)")

    # 5. 보고서 생성
    output_dir = Path(args.output_dir) if args.output_dir else Path(".")
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"{args.name.replace(' ', '_')}_model.json"
    html_path = output_dir / f"{args.name.replace(' ', '_')}_report.html"

    json_path.write_text(
        generate_json_report(model), encoding="utf-8"
    )
    html_path.write_text(
        generate_html_report(model), encoding="utf-8"
    )

    summary = model.get_summary()
    print(f"\n4. 보고서 생성 완료")
    print(f"   JSON: {json_path}")
    print(f"   HTML: {html_path}")
    print(f"\n=== 분석 결과 요약 ===")
    print(f"  총 위협: {summary['total_threats']}")
    for sev in Severity:
        count = summary['by_severity'].get(sev.value, 0)
        if count > 0:
            print(f"  {sev.value}: {count}건")

    return 0


# ─── argparse 설정 ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="위협 모델링 전체 워크플로우 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
명령어:
  init           새 위협 모델 초기화
  add-element    DFD 요소 추가
  analyze        STRIDE 자동 분석
  score          DREAD 점수 대화형 입력
  report         보고서 생성
  full-pipeline  전체 파이프라인 한 번에 실행

예시:
  %(prog)s init --name "쇼핑몰" --output model.json
  %(prog)s add-element --model model.json --interactive
  %(prog)s analyze --model model.json
  %(prog)s report --model model.json --format html --output report.html
  %(prog)s full-pipeline --name "전자상거래" --system ecommerce
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="위협 모델 초기화")
    p_init.add_argument("--name", required=True, help="모델 이름")
    p_init.add_argument("--description", default="", help="모델 설명")
    p_init.add_argument("--output", type=Path, default=Path("model.json"))

    # add-element
    p_add = sub.add_parser("add-element", help="DFD 요소 추가")
    p_add.add_argument("--model", type=Path, required=True)
    p_add.add_argument("--interactive", action="store_true")
    p_add.add_argument("--name")
    p_add.add_argument("--type", choices=[e.value for e in ElementType])
    p_add.add_argument("--description", default="")

    # analyze
    p_analyze = sub.add_parser("analyze", help="STRIDE 자동 분석")
    p_analyze.add_argument("--model", type=Path, required=True)
    p_analyze.add_argument("--method", choices=["stride"], default="stride")

    # score
    p_score = sub.add_parser("score", help="DREAD 점수 입력")
    p_score.add_argument("--model", type=Path, required=True)
    p_score.add_argument("--method", choices=["dread"], default="dread")

    # report
    p_report = sub.add_parser("report", help="보고서 생성")
    p_report.add_argument("--model", type=Path, required=True)
    p_report.add_argument("--format", choices=["html", "json"], default="html")
    p_report.add_argument("--output", type=Path)

    # full-pipeline
    p_full = sub.add_parser("full-pipeline", help="전체 파이프라인")
    p_full.add_argument("--name", required=True)
    p_full.add_argument("--system", choices=["ecommerce", "kubernetes"], required=True)
    p_full.add_argument("--output-dir", default=".")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    handlers = {
        "init": cmd_init,
        "add-element": cmd_add_element,
        "analyze": cmd_analyze,
        "score": cmd_score,
        "report": cmd_report,
        "full-pipeline": cmd_full_pipeline,
    }

    handler = handlers.get(args.command)
    if handler is None:
        print(f"알 수 없는 명령어: {args.command}", file=sys.stderr)
        return 1

    try:
        return handler(args)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 전체 워크플로우 실행 예시

```bash
# 1. 전체 파이프라인 (한 번에 실행)
python3 threat_modeling_cli.py full-pipeline \
  --name "전자상거래" \
  --system ecommerce \
  --output-dir ./ecom_threat_model

# 2. 단계별 실행
# 모델 초기화
python3 threat_modeling_cli.py init \
  --name "뱅킹 앱" \
  --description "모바일 뱅킹 앱 위협 모델" \
  --output banking_model.json

# 요소 추가 (대화형)
python3 threat_modeling_cli.py add-element \
  --model banking_model.json \
  --interactive

# STRIDE 자동 분석
python3 threat_modeling_cli.py analyze \
  --model banking_model.json

# DREAD 점수 입력 (대화형)
python3 threat_modeling_cli.py score \
  --model banking_model.json

# HTML 보고서 생성
python3 threat_modeling_cli.py report \
  --model banking_model.json \
  --format html \
  --output banking_report.html

# Kubernetes 파이프라인
python3 threat_modeling_cli.py full-pipeline \
  --name "K8s 클러스터" \
  --system kubernetes \
  --output-dir ./k8s_threats
```

### 산출물 구조

```
출력 디렉토리:
ecom_threat_model/
├── 전자상거래_model.json      ← 구조화된 위협 모델 데이터
└── 전자상거래_report.html     ← 시각적 HTML 보고서

k8s_threats/
├── K8s_클러스터_model.json
└── K8s_클러스터_report.html
```

---

## 참고 자료

- [OWASP MASVS](https://mobile-security.gitbook.io/masvs/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [OWASP Top 10 API Security Risks](https://owasp.org/www-project-api-security/)
- [Shostack, A. - Threat Modeling: Designing for Security (2014)]
- [NIST SP 800-154 - Data-Centric System Threat Modeling]
- [MITRE ATT&CK for Mobile](https://attack.mitre.org/matrices/mobile/)

---

<a name="english"></a>

# Threat Modeling Practice Exercises

## Table of Contents
1. [E-Commerce Web App Threat Modeling](#e-commerce-web-app-threat-modeling)
2. [Mobile Banking App Threat Modeling](#mobile-banking-app-threat-modeling)
3. [Kubernetes Cluster Threat Modeling](#kubernetes-cluster-threat-modeling)
4. [Deriving Mitigation Controls](#deriving-mitigation-controls)
5. [Threat → Security Requirement → Test Case Linkage](#threat--security-requirement--test-case-linkage)
6. [Full Workflow CLI Tool](#full-workflow-cli-tool)

---

## E-Commerce Web App Threat Modeling

### System Architecture

```
[Client]
  ├── Web Browser (React SPA)
  └── Mobile App (iOS/Android)
         │ HTTPS/TLS 1.3
         ↓
[CDN/WAF] ← Cloudflare / AWS CloudFront
         │
         ↓
[Load Balancer] ── AWS ALB
         │
         ↓
[API Gateway] ── Kong / AWS API Gateway
  ├── Rate Limiting
  ├── JWT Validation
  └── Request Logging
         │
         ├──────────────────────┬───────────────────────┐
         ↓                      ↓                       ↓
[Auth Service]          [Product Service]        [Order Service]
 Python/FastAPI          Python/FastAPI           Python/FastAPI
         │                      │                       │
         ↓                      ↓                       ↓
[User DB]               [Product DB]             [Order DB]
 PostgreSQL              PostgreSQL               PostgreSQL
         │
         ├──[Redis Session Cache]
         └──[AWS S3 File Storage]
                                          ↓
                              [Payment Service] ── Stripe API
```

### DFD Trust Boundaries

```
Trust Boundary Definitions:
TB-01: Internet (Trust Level 0) ↔ CDN/WAF (Trust Level 1)
TB-02: CDN/WAF ↔ API Gateway (Trust Level 2)
TB-03: API Gateway ↔ Microservices (Trust Level 3)
TB-04: Microservices ↔ Databases (Trust Level 4)
TB-05: Internal Services ↔ External Payment Service (Trust Level 1)
```

### STRIDE Analysis Matrix

```
Component: Authentication Service (/api/v1/auth)

┌──────┬────────────────────────────────────┬──────────┬──────────────────────────────────────┐
│STRIDE│ Threat Scenario                     │ Severity │ Mitigation                           │
├──────┼────────────────────────────────────┼──────────┼──────────────────────────────────────┤
│  S   │ JWT algorithm confusion (alg:none)  │ Critical │ Explicit algorithm allowlist          │
│  S   │ Stolen refresh token reuse          │ High     │ Refresh Token Rotation + blacklist    │
│  T   │ Password reset token prediction     │ High     │ CSPRNG token gen, expiry enforcement  │
│  R   │ Missing login/logout audit logs     │ Medium   │ Structured logging for all auth events│
│  I   │ Account existence revealed in error │ Medium   │ Unified "invalid email or password"   │
│  I   │ Access token logged in debug logs   │ High     │ Sensitive data log masking            │
│  D   │ Brute force on login API            │ High     │ Lockout after 5 fails, IP rate limit  │
│  D   │ Mass account creation (stuffing)    │ Medium   │ CAPTCHA, mandatory email verification │
│  E   │ IDOR to modify other user profiles  │ Critical │ Server-side ownership validation      │
│  E   │ Exposed admin password reset API    │ Critical │ Admin API RBAC + IP whitelist         │
└──────┴────────────────────────────────────┴──────────┴──────────────────────────────────────┘

Component: Order Service (/api/v1/orders)

┌──────┬────────────────────────────────────┬──────────┬──────────────────────────────────────┐
│STRIDE│ Threat Scenario                     │ Severity │ Mitigation                           │
├──────┼────────────────────────────────────┼──────────┼──────────────────────────────────────┤
│  S   │ IDOR to view other user's orders    │ High     │ Server-side order owner validation    │
│  T   │ Order amount parameter tampering    │ Critical │ Server-side recalculation, signed cart│
│  T   │ Duplicate coupon code usage         │ High     │ Atomic coupon handling (Redis lock)   │
│  R   │ No audit trail for order events     │ Medium   │ Apply event sourcing pattern          │
│  I   │ Other user's data in order list API │ High     │ Force user_id filter on queries       │
│  D   │ Mass order attempts on zero stock   │ Medium   │ Inventory validation, rate limiting   │
│  E   │ Order status change without payment │ Critical │ Payment callback validation, state machine│
└──────┴────────────────────────────────────┴──────────┴──────────────────────────────────────┘
```

### Attack Tree: Payment Data Theft

```
[Payment Data Theft]
     (OR)
     ├── [In-Transit Theft] (AND)
     │       ├── {Obtain MITM Position: ARP Spoofing}
     │       └── {SSL Strip or Certificate Forgery}
     │
     ├── [Stored Data Theft] (OR)
     │       ├── [Direct DB Access] (OR)
     │       │       ├── {SQL Injection → DB Dump}
     │       │       │     Probability: 0.3 (WAF bypass rate)
     │       │       └── {Credential theft → Direct DB connection}
     │       │             Probability: 0.1
     │       └── {S3 Bucket Public Exposure}
     │               Probability: 0.05
     │
     └── [Application Layer] (OR)
             ├── {Card number included in payment API response}
             │     Probability: 0.2
             └── {Card number logged in log files}
                   Probability: 0.15
```

### Kill Chain Mapping

```
Scenario: Internal Network Breach via SQL Injection

1. Reconnaissance
   - subfinder -d example.com → subdomain enumeration
   - nuclei -t technologies/ -u https://shop.example.com → tech stack detection
   - waybackurls shop.example.com | gf sqli → potential SQLI endpoints

2. Weaponization
   - Prepare sqlmap automation script
   - UNION-based injection payloads

3. Delivery
   - GET /api/products?category=1' OR '1'='1
   - POST /api/search {"q": "'; SELECT version()--"}

4. Exploitation
   sqlmap -u "https://shop.example.com/api/products?id=1" \
     --dbms=postgresql --batch --level=3 --risk=2

5. Installation
   - Deploy webshell via xp_cmdshell or COPY TO/FROM file write

6. C2
   - DNS over HTTPS tunneling
   - C2 via legitimate services (Pastebin)

7. Actions on Objectives
   - SELECT card_number, cvv FROM payment_methods
   - Compress data and exfiltrate via HTTPS
```

---

## Mobile Banking App Threat Modeling

### System Architecture

```
[Mobile App]
  ├── iOS (Swift)
  └── Android (Kotlin)
       │
       │ HTTPS + Certificate Pinning
       ↓
[Mobile API Gateway]
  ├── Device Authentication (Device Fingerprint)
  ├── mTLS
  └── API Key Validation
       │
       ├──[Account Service]──[Account DB]
       ├──[Transfer Service]──[Transfer DB]
       ├──[Notification Service]──[APNs/FCM]
       └──[Auth Service]──[User DB]
                              │
                         [HSM] (Hardware Security Module)
                         [Key Management Service]
```

### OWASP MASVS-Based Threat Analysis

```
MASVS (Mobile Application Security Verification Standard)

Level 1 (Basic): MASVS-L1
Level 2 (Advanced): MASVS-L2 (required for banking apps)
R (Resilience): MASVS-R (root/jailbreak detection)

Threat Areas:
┌─────────────────────┬──────────────────────────────────────────┐
│ Area                │ Threat Scenario                          │
├─────────────────────┼──────────────────────────────────────────┤
│ Architecture/Design │ Direct backend API exposure, hardcoded URLs│
│ Data Storage        │ Auth tokens stored in plaintext SharedPrefs│
│ Cryptography        │ Weak algorithms (MD5, DES) used          │
│ Authentication      │ Biometric bypass, PIN guessing allowed   │
│ Network Comms       │ Certificate pinning not implemented      │
│ Platform Interaction│ Intent snooping, clipboard data exposure │
│ Code Quality        │ Debug logs exposed in production         │
│ Tamper Resistance   │ App runs on rooted/jailbroken devices    │
└─────────────────────┴──────────────────────────────────────────┘
```

### STRIDE Analysis (Mobile Banking)

```
Area: Transfer Service

┌──────┬──────────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│STRIDE│ Threat                                    │ Severity │ Mitigation                          │
├──────┼──────────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│  S   │ Session token reuse from another device  │ Critical │ Device-bound tokens, change alerts  │
│  S   │ CSRF transfer via deep link              │ High     │ Transfer reconfirmation (OTP/biometric)│
│  T   │ Transfer amount tampering after pinning  │ Critical │ Request signing (HMAC + timestamp)  │
│  T   │ Local SQLite DB modification             │ High     │ Encrypt DB with SQLCipher           │
│  R   │ Transfer transaction ID replay           │ Critical │ Include Nonce in request, 24h validity│
│  I   │ Account numbers logged in logcat         │ High     │ ProGuard + remove sensitive logs    │
│  I   │ Account info captured in screenshot      │ Medium   │ Set FLAG_SECURE                     │
│  D   │ Full outage when biometric server fails  │ High     │ Fallback to PIN authentication      │
│  E   │ Auth bypass with Frida on rooted device  │ Critical │ Root detection + server-side check  │
│  E   │ Signature check bypass after app tamper  │ Critical │ App integrity check, Play Integrity │
└──────┴──────────────────────────────────────────┴──────────┴─────────────────────────────────────┘
```

### Mobile Security Testing Commands

```bash
# MobSF (Mobile Security Framework) static analysis
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Manual APK analysis
apktool d app.apk -o decompiled/
grep -r "password\|secret\|api_key\|token" decompiled/ --include="*.xml" --include="*.smali"

# Check SSL Pinning (Android)
grep -r "CertificatePinner\|TrustManager\|pinCertificate" decompiled/

# Decompile APK with jadx
jadx -d output/ app.apk
find output/ -name "*.java" | xargs grep -l "http://"

# Runtime analysis with frida
pip3 install frida-tools
frida-ps -U  # List processes on connected device

# SSL Pinning bypass script
frida -U -f com.example.bankapp \
  --codeshare 0xdea/frida-scripts/api-monitor \
  -l ssl_pinning_bypass.js

# Burp Suite Certificate Pinning bypass (rooted device)
adb push burp_cert.der /sdcard/
adb shell "su -c 'cp /sdcard/burp_cert.der /system/etc/security/cacerts/'"

# drozer dynamic analysis
drozer console connect
dz> run app.package.attacksurface com.example.bankapp
dz> run app.activity.info -a com.example.bankapp
dz> run app.provider.finduri com.example.bankapp
```

---

## Kubernetes Cluster Threat Modeling

### Cluster Architecture

```
[Developers/Operators]
  ├── kubectl (OIDC auth)
  └── Helm
         │
         ↓
[Control Plane]
  ├── kube-apiserver (6443/TCP)
  ├── etcd (2379-2380/TCP, encrypted internal)
  ├── kube-scheduler
  └── kube-controller-manager
         │
         ↓
[Worker Nodes]
  ├── kubelet (10250/TCP)
  ├── kube-proxy
  ├── containerd/CRI-O
  └── Pods
         ├── Application Pods
         ├── Monitoring Pods (Prometheus/Grafana)
         └── Ingress Controller (NGINX)

[Add-ons]
  ├── Istio Service Mesh (mTLS)
  ├── OPA Gatekeeper (policy enforcement)
  ├── Falco (runtime security)
  └── Vault (secret management)
```

### STRIDE Analysis (Kubernetes)

```
Component: kube-apiserver

┌──────┬──────────────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│STRIDE│ Threat                                        │ Severity │ Mitigation                          │
├──────┼──────────────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│  S   │ Stolen service account token used for API    │ Critical │ Short-lived tokens (1h), Projected Volumes│
│  S   │ Anonymous API access (--anonymous-auth=true) │ Critical │ Disable anonymous authentication     │
│  T   │ Direct etcd access to modify Secrets         │ Critical │ Encrypt etcd, network isolation     │
│  R   │ Audit Log not configured                     │ High     │ Configure Audit Policy, SIEM integration│
│  I   │ Cross-namespace Secret access                │ High     │ RBAC least privilege, NetworkPolicy │
│  D   │ Mass API requests overloading kube-apiserver │ High     │ API Priority and Fairness settings  │
│  E   │ ClusterRole escalation via RBAC              │ Critical │ RBAC permission audit, OPA policy   │
└──────┴──────────────────────────────────────────────┴──────────┴─────────────────────────────────────┘

Component: Container Runtime / Pod

┌──────┬──────────────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│STRIDE│ Threat                                        │ Severity │ Mitigation                          │
├──────┼──────────────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│  S   │ Masquerading as a legitimate container image │ High     │ Image signing verification (cosign, Notary)│
│  T   │ Host filesystem modification from container  │ Critical │ privileged: false, readOnlyRoot     │
│  I   │ Secrets passed as environment variables      │ High     │ Vault sidecar, CSI Secret driver    │
│  D   │ OOM/CPU exhaustion due to no resource limits │ High     │ LimitRange, ResourceQuota           │
│  E   │ Host access via hostPID/hostNetwork          │ Critical │ PodSecurityAdmission, PSP           │
│  E   │ SSRF to IMDS (169.254.169.254)               │ Critical │ NetworkPolicy, enforce IMDSv2       │
└──────┴──────────────────────────────────────────────┴──────────┴─────────────────────────────────────┘
```

### K8s Security Configuration Commands

```bash
# CIS Kubernetes Benchmark scan
docker run --rm \
  --pid=host \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  -v /usr/bin/kubectl:/usr/bin/kubectl:ro \
  aquasec/kube-bench:latest

# kube-score (static manifest analysis)
kube-score score deployment.yaml
kube-score score --output-format ci k8s/

# Scan K8s cluster with Trivy
trivy k8s --report all cluster

# Check Falco runtime rules
kubectl get configmap falco-config -n falco -o yaml

# RBAC analysis
kubectl auth can-i --list --as=system:serviceaccount:default:myapp
kubectl get clusterrolebindings -o json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    subjects = item.get('subjects', [])
    role = item.get('roleRef', {}).get('name', '')
    for s in subjects:
        if s.get('name') != 'system:masters':
            print(f'{name}: {s[\"name\"]} → {role}')
"

# Verify Secret encryption
kubectl get secret mysecret -o jsonpath='{.data.password}' | base64 -d

# Verify NetworkPolicy
kubectl get networkpolicies -A
kubectl describe networkpolicy default-deny-all

# Check Pod Security Standards
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

# Check Audit Log configuration
kubectl get pod kube-apiserver-* -n kube-system -o yaml | \
  grep -A5 audit
```

---

## Deriving Mitigation Controls

### Mitigation Control Classification Framework

```
Control Types:
┌──────────────┬──────────────────────────────────────┐
│ Type         │ Description                          │
├──────────────┼──────────────────────────────────────┤
│ Preventive   │ Prevent threats from occurring       │
│ Detective    │ Detect threats in real time          │
│ Corrective   │ Minimize damage / recover after event│
│ Deterrent    │ Discourage attacker intent (legal)   │
└──────────────┴──────────────────────────────────────┘

STRIDE → Mitigation Control Mapping:

Spoofing Mitigations:
  Preventive: MFA, strong password policy, mTLS
  Detective: Anomalous login detection, SIEM alerts
  Corrective: Automatic account lockout, forced logout

Tampering Mitigations:
  Preventive: Input validation, parameterized queries, WAF
  Detective: FIM (File Integrity Monitoring), DB audit
  Corrective: Automatic rollback, backup recovery

Repudiation Mitigations:
  Preventive: Require digital signatures, session binding
  Detective: Centralized audit logs, SIEM
  Corrective: Forensic analysis, log retention

Information Disclosure Mitigations:
  Preventive: Encryption (transit/rest), RBAC, least privilege
  Detective: DLP solutions, anomalous query detection
  Corrective: Data classification, exposure scope assessment

Denial of Service Mitigations:
  Preventive: Rate limiting, resource limits, caching
  Detective: Anomaly traffic detection, APM monitoring
  Corrective: Auto Scaling, DDoS protection services

Elevation of Privilege Mitigations:
  Preventive: Least privilege, RBAC, input validation
  Detective: Privilege change monitoring, UEBA
  Corrective: Permission revocation, breach isolation
```

### NIST 800-53 Control Mapping

```
Threat → NIST Control Mapping:

Spoofing:
  IA-2: Identification and Authentication (Organizational Users)
  IA-3: Device Identification and Authentication
  SC-8: Transmission Confidentiality and Integrity

Tampering:
  SI-10: Information Input Validation
  SI-7: Software, Firmware, and Information Integrity
  SC-28: Protection of Information at Rest

Repudiation:
  AU-2: Event Logging
  AU-9: Protection of Audit Information
  AU-12: Audit Record Generation

Information Disclosure:
  SC-8: Transmission Confidentiality and Integrity
  SC-28: Protection of Information at Rest
  AC-3: Access Enforcement

Denial of Service:
  SC-5: Denial-of-Service Protection
  SI-13: Predictable Failure Prevention
  CP-10: Information System Recovery and Reconstitution

Elevation of Privilege:
  AC-6: Least Privilege
  AC-3: Access Enforcement
  CM-7: Least Functionality
```

---

## Threat → Security Requirement → Test Case Linkage

### Linkage Mapping Structure

```
Threat T001 (SQL Injection)
    ↓
Security Requirement SR-001
    "All DB queries must use parameterized queries or ORM"
    ↓
Test Case TC-001
    "Test each input field with SQLI payloads"
    ↓
Automated Tests (pytest + httpx)
    ↓
Continuous execution in CI/CD pipeline
```

### Security Requirement Examples (E-Commerce)

```
SR-AUTH-001: Password Policy
  - Minimum 12 characters
  - Must include upper/lowercase, numbers, special chars
  - Prohibit reuse of last 10 passwords
  - Mandatory 90-day rotation
  Source threat: T001 (Spoofing - weak password brute force)

SR-AUTH-002: MFA Enforcement
  - MFA required for sensitive actions (transfer, password change)
  - Support TOTP or SMS OTP
  Source threat: T002 (Spoofing - login after credential theft)

SR-INPUT-001: Input Validation
  - Server-side validation for all inputs
  - Parameterize SQL special characters
  - File upload: restrict type and size
  Source threat: T003 (Tampering - SQL Injection)

SR-API-001: API Design
  - Use GUID/UUID-based resource identifiers
  - Authorization check required on all API requests
  - Do not include unnecessary internal info in responses
  Source threat: T004 (Elevation of Privilege - IDOR)

SR-LOG-001: Audit Logging
  - Log login/logout/failure events
  - Log access to sensitive data
  - Tamper-resistant logging (WORM storage)
  - Log retention period: 1 year
  Source threat: T005 (Repudiation - untracked actions)
```

### Security Test Case Examples

```python
# security_tests/test_auth_security.py
import pytest
import httpx

BASE_URL = "http://localhost:8000"

class TestAuthenticationSecurity:
    """Tests for SR-AUTH-001, SR-AUTH-002"""

    def test_brute_force_protection(self):
        """TC-AUTH-001: Account lockout after 5 failed attempts"""
        client = httpx.Client()
        for i in range(5):
            resp = client.post(f"{BASE_URL}/api/auth/login", json={
                "email": "test@example.com",
                "password": f"wrong_password_{i}"
            })
        # 6th attempt should receive lockout response
        resp = client.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@example.com",
            "password": "any_password"
        })
        assert resp.status_code == 429  # Too Many Requests

    def test_jwt_algorithm_confusion(self):
        """TC-AUTH-002: Defend against JWT alg:none attack"""
        # Generate unsigned JWT
        import base64
        header = base64.b64encode(
            b'{"alg":"none","typ":"JWT"}'
        ).rstrip(b'=').decode()
        payload = base64.b64encode(
            b'{"sub":"admin","role":"admin"}'
        ).rstrip(b'=').decode()
        fake_jwt = f"{header}.{payload}."

        resp = httpx.get(
            f"{BASE_URL}/api/admin/users",
            headers={"Authorization": f"Bearer {fake_jwt}"}
        )
        assert resp.status_code == 401

    def test_error_message_enumeration(self):
        """TC-AUTH-003: Prevent account existence disclosure"""
        r1 = httpx.post(f"{BASE_URL}/api/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "password123"
        })
        r2 = httpx.post(f"{BASE_URL}/api/auth/login", json={
            "email": "existing@example.com",
            "password": "wrong_password"
        })
        # Should return identical error messages
        assert r1.json().get("message") == r2.json().get("message")
        assert r1.status_code == r2.status_code == 401


class TestInputValidation:
    """Tests for SR-INPUT-001"""

    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM users",
        "1' AND SLEEP(5)--",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
    ]

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_sqli_in_search(self, payload: str):
        """TC-INPUT-001: SQLI defense in search API"""
        resp = httpx.get(
            f"{BASE_URL}/api/products",
            params={"q": payload}
        )
        # Should return normal response (400 or empty result)
        assert resp.status_code in (200, 400)
        # DB error messages must not be exposed
        body = resp.text.lower()
        for keyword in ["sql", "syntax error", "postgresql", "mysql"]:
            assert keyword not in body

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_in_review(self, payload: str):
        """TC-INPUT-002: XSS defense in review API"""
        resp = httpx.post(
            f"{BASE_URL}/api/reviews",
            json={"product_id": 1, "content": payload, "rating": 5},
            headers={"Authorization": "Bearer valid_token_here"}
        )
        if resp.status_code == 201:
            # Stored content must have scripts escaped
            review_id = resp.json()["id"]
            get_resp = httpx.get(f"{BASE_URL}/api/reviews/{review_id}")
            assert "<script>" not in get_resp.text
```

---

## Full Workflow CLI Tool

```python
#!/usr/bin/env python3
"""
Threat Modeling Full Workflow CLI Tool

DFD input → STRIDE analysis → DREAD scoring → Report generation

Usage:
    python3 threat_modeling_cli.py init --name "E-Commerce" --output model.json
    python3 threat_modeling_cli.py add-element --model model.json --interactive
    python3 threat_modeling_cli.py analyze --model model.json --method stride
    python3 threat_modeling_cli.py score --model model.json --method dread
    python3 threat_modeling_cli.py report --model model.json --format html --output report.html
    python3 threat_modeling_cli.py full-pipeline --name "Shopping Mall" --system ecommerce
"""

# (Code is identical to Korean section above; see full implementation there)
```

### Full Workflow Execution Examples

```bash
# 1. Full pipeline (run all at once)
python3 threat_modeling_cli.py full-pipeline \
  --name "E-Commerce" \
  --system ecommerce \
  --output-dir ./ecom_threat_model

# 2. Step-by-step execution
# Initialize model
python3 threat_modeling_cli.py init \
  --name "Banking App" \
  --description "Mobile banking app threat model" \
  --output banking_model.json

# Add elements (interactive)
python3 threat_modeling_cli.py add-element \
  --model banking_model.json \
  --interactive

# STRIDE auto analysis
python3 threat_modeling_cli.py analyze \
  --model banking_model.json

# DREAD scoring (interactive)
python3 threat_modeling_cli.py score \
  --model banking_model.json

# Generate HTML report
python3 threat_modeling_cli.py report \
  --model banking_model.json \
  --format html \
  --output banking_report.html

# Kubernetes pipeline
python3 threat_modeling_cli.py full-pipeline \
  --name "K8s Cluster" \
  --system kubernetes \
  --output-dir ./k8s_threats
```

### Output Structure

```
Output directory:
ecom_threat_model/
├── E-Commerce_model.json      ← Structured threat model data
└── E-Commerce_report.html     ← Visual HTML report

k8s_threats/
├── K8s_Cluster_model.json
└── K8s_Cluster_report.html
```

---

## References

- [OWASP MASVS](https://mobile-security.gitbook.io/masvs/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [OWASP Top 10 API Security Risks](https://owasp.org/www-project-api-security/)
- [Shostack, A. - Threat Modeling: Designing for Security (2014)]
- [NIST SP 800-154 - Data-Centric System Threat Modeling]
- [MITRE ATT&CK for Mobile](https://attack.mitre.org/matrices/mobile/)
