> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# OPSEC 인프라 관리

> **목적**: 교육, 연구, CTF, 공인된 레드팀 작전 환경에서의 학습용 자료

## 0. 초보자를 위한 개념 이해

### OPSEC 인프라 관리란?

OPSEC(Operations Security, 작전 보안)은 레드팀 작전 중 공격자(레드팀)의 신원, 위치, 방법론이 방어자(블루팀)에게 노출되지 않도록 관리하는 원칙이다. 실제 APT 공격자들이 사용하는 은폐 기법을 레드팀이 적용해 블루팀이 실전과 같은 탐지 훈련을 할 수 있게 한다.

**왜 배우는가:**
```
OPSEC이 없는 레드팀의 문제:

  시나리오: 레드팀이 회사 내부망 침투 시뮬레이션
    나쁜 OPSEC:
      - 레드팀 VPN IP가 C2에 직접 연결
      - 블루팀이 "저 IP는 우리 레드팀이네" → 탐지 무의미
      - Metasploit 기본 설정 그대로 사용 → 즉시 탐지

    좋은 OPSEC:
      - 실제 APT처럼 CDN/리다이렉터 사용
      - 커스텀 에이전트로 시그니처 변경
      - 블루팀이 진짜 APT처럼 대응 훈련 가능

  OPSEC이 중요한 또 다른 이유:
    - 레드팀 인프라 노출 → 사고 조사 시 증거 오염
    - 고객사 기밀 정보를 안전하게 보호해야 할 책임
    - 레드팀 TTP 노출 → 다음 작전에서 블루팀이 준비됨
```

### 핵심 개념 정리

```
OPSEC 5단계 프로세스:

1. 중요 정보 식별 (Critical Information)
   - 팀서버 실제 IP
   - 레드팀 운영자 신원
   - 사용 중인 C2 프레임워크 종류
   - 작전 일정 및 범위

2. 위협 분석 (Threat Analysis)
   - 블루팀의 SIEM/EDR 탐지 능력
   - 네트워크 트래픽 분석 도구
   - 포렌식 팀의 역량

3. 취약점 분석 (Vulnerability Analysis)
   - DNS 리버스 룩업으로 팀서버 발견 가능성
   - 디폴트 에이전트 User-Agent 탐지 가능성
   - 인증서의 CN(Common Name) 노출

4. 위험 평가 (Risk Assessment)
   - 각 취약점 발견 시 작전에 미치는 영향

5. 대응책 적용 (Countermeasures)
   - 팀서버 IP 보호: CDN/리다이렉터
   - User-Agent 커스터마이징
   - 인증서 정보 최소화
```

### 필요한 도구 및 환경
- **ProtonVPN / Mullvad**: 레드팀 운영자 IP 보호
- **Whois Privacy**: 도메인 등록 정보 보호
- **Let's Encrypt**: 의심스럽지 않은 TLS 인증서
- **Terraform / Ansible**: 인프라 코드화 (빠른 재배포/폐기)
- **Pass (Password Store)**: 작전 자격증명 암호화 관리

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
OPSEC 체크리스트 자동 점검 도구
레드팀 작전 시작 전 OPSEC 요소를 점검한다.
"""
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class OpsecCheckItem:
    """OPSEC 점검 항목"""
    category: str
    item: str
    status: str = "미점검"  # 완료, 미완, 미점검, 해당없음
    notes: str = ""


def create_opsec_checklist() -> list[OpsecCheckItem]:
    """레드팀 작전 전 OPSEC 체크리스트를 생성한다."""
    return [
        # 인프라 보호
        OpsecCheckItem("인프라", "팀서버 IP가 공개 WHOIS에 노출되지 않는가"),
        OpsecCheckItem("인프라", "리다이렉터와 팀서버 사이 VPN/전용선 연결 확인"),
        OpsecCheckItem("인프라", "팀서버 SSH 기본 포트(22) 변경 여부"),
        OpsecCheckItem("인프라", "팀서버 방화벽: 리다이렉터 IP만 허용"),
        # C2 설정
        OpsecCheckItem("C2", "에이전트 User-Agent 커스터마이징 완료"),
        OpsecCheckItem("C2", "비콘 Sleep 간격 및 Jitter 설정 확인"),
        OpsecCheckItem("C2", "C2 도메인 Categorization 확인 (의심 카테고리 아닌가)"),
        OpsecCheckItem("C2", "C2 트래픽이 정상 업무 트래픽과 유사한 포트 사용"),
        # 운영자 보호
        OpsecCheckItem("운영자", "레드팀 운영자 VPN 연결 상태 확인"),
        OpsecCheckItem("운영자", "작전 전용 장비 사용 (개인 장비 금지)"),
        OpsecCheckItem("운영자", "작전 정보 암호화 저장"),
        # 법적 보호
        OpsecCheckItem("법적", "서명된 작전 범위(Rules of Engagement) 문서 보관"),
        OpsecCheckItem("법적", "긴급 연락처 목록 준비 (고객사 보안팀, 법무팀)"),
        OpsecCheckItem("법적", "작전 종료 후 데이터 삭제 계획 수립"),
    ]


def check_domain_exposure(domain: str) -> dict:
    """도메인의 기본적인 노출 상태를 확인한다."""
    result = {"도메인": domain, "점검결과": []}

    # DNS 조회
    try:
        ip = socket.gethostbyname(domain)
        result["점검결과"].append({"항목": "DNS 해석", "결과": f"IP: {ip}", "상태": "확인됨"})
    except socket.gaierror:
        result["점검결과"].append({"항목": "DNS 해석", "결과": "해석 불가", "상태": "주의"})

    return result


def generate_opsec_report(checklist: list[OpsecCheckItem]) -> dict:
    """OPSEC 체크리스트 보고서를 생성한다."""
    completed = sum(1 for item in checklist if item.status == "완료")
    pending = sum(1 for item in checklist if item.status == "미완")
    not_checked = sum(1 for item in checklist if item.status == "미점검")

    categories: dict[str, list] = {}
    for item in checklist:
        if item.category not in categories:
            categories[item.category] = []
        categories[item.category].append({
            "항목": item.item,
            "상태": item.status,
            "메모": item.notes,
        })

    readiness = (completed / len(checklist) * 100) if checklist else 0

    return {
        "점검일시": datetime.now().isoformat(),
        "작전준비도": f"{readiness:.0f}%",
        "요약": {"완료": completed, "미완": pending, "미점검": not_checked},
        "카테고리별": categories,
        "권고": "모든 항목 완료 후 작전 시작" if readiness < 100 else "작전 시작 가능",
    }


if __name__ == "__main__":
    checklist = create_opsec_checklist()

    # 일부 항목 완료 처리 시뮬레이션
    for item in checklist[:5]:
        item.status = "완료"
    checklist[5].status = "미완"
    checklist[5].notes = "도메인 카테고리 변경 신청 중 (3일 소요 예상)"

    report = generate_opsec_report(checklist)
    print(json.dumps(report, ensure_ascii=False, indent=2))
```

---

## 1. OPSEC 원칙

### 1.1 OPSEC(작전 보안) 개요

OPSEC(Operations Security)은 군사 전술에서 유래한 개념으로, 적이 우리의 작전 정보를 수집하고 분석하는 것을 방해하는 프로세스다.

```
OPSEC 5단계 프로세스:

1단계: 핵심 정보 식별 (Critical Information)
  - 공격자 실제 IP
  - C2 서버 위치
  - 사용 중인 도구/기법
  - 공격 타이밍/일정
  - 내부 협력자 정보

2단계: 위협 분석 (Threat Analysis)
  - 블루팀 역량 파악
  - EDR/SIEM/SOAR 솔루션
  - 위협 인텔리전스 팀 존재 여부
  - 네트워크 모니터링 수준

3단계: 취약성 분석 (Vulnerability Analysis)
  - 어디서 정보가 노출될 수 있는가
  - Certificate Transparency 로그
  - WHOIS 정보
  - 도메인 등록 패턴
  - VPS 재사용

4단계: 위험 평가 (Risk Assessment)
  - 노출 가능성 × 영향도
  - 우선순위 결정

5단계: 대응 조치 (Countermeasures)
  - 기술적 조치
  - 절차적 조치
  - 물리적 조치
```

### 1.2 레드팀 OPSEC 실패 사례 유형

```
일반적인 OPSEC 실패:

1. 인프라 재사용
   - 이전 작전에 사용한 IP/도메인 재활용
   - 같은 IP에서 여러 고객 대상 작업
   - → 교차 오염(Cross-contamination) 위험

2. 메타데이터 노출
   - 도메인 등록 시 실명 사용
   - SSL 인증서에 실제 정보 기입
   - GitHub 커밋 이메일
   - → 귀속(Attribution) 가능해짐

3. 도구 서명(Toolmark)
   - 기본 Cobalt Strike 설정 그대로 사용
   - 알려진 C2 프레임워크 기본 포트
   - 수정 없이 사용한 오픈소스 도구
   - → 자동 탐지 가능

4. 타이밍 패턴
   - 업무 시간(9-6시)에만 활동
   - 시간대가 고정적 (공격자 위치 추정 가능)
   - 규칙적인 비커닝 패턴

5. 로그 미관리
   - VPS 제공업체 로그 방치
   - C2 서버 접속 로그 보존
   - 작전 후 정리 미실시
```

---

## 2. 공격자 인프라 분리

### 2.1 Long Haul vs Short Haul C2

```
Short Haul C2 (단기 C2):
  용도: 초기 침투, 빠른 명령 실행
  특징:
  - 빠른 응답 시간 (수 초)
  - 노이즈 많음 (탐지 위험 높음)
  - 탐지 시 빠르게 교체
  - 예: Metasploit/meterpreter, 빠른 Beacon sleep

Long Haul C2 (장기 C2):
  용도: 지속적 접근(Persistence) 유지
  특징:
  - 느린 응답 (수 시간 단위 비커닝)
  - 최소한의 트래픽
  - 장기간 탐지 회피 목적
  - 예: DNS C2, 수 시간 sleep Beacon

아키텍처:
  초기 접근
      │
      ├─► Short Haul C2 (빠른 작업용)
      │     └─ 탐지 시 교체
      │
      └─► Long Haul C2 (지속 접근용)
            └─ 절대 노출 안 되도록 관리
```

### 2.2 인프라 분리 레이어

```
레이어 1: 작전(Operational) 인프라
  - 실제 공격 도구 실행
  - 팀서버, 익스플로잇 서버
  - 절대 직접 노출 금지

레이어 2: 스테이징(Staging) 인프라
  - 페이로드 호스팅
  - 초기 콜백 수신
  - 리다이렉터와 연결

레이어 3: 포워더(Forwarder) 인프라
  - 공개 인터넷에 노출
  - 빠른 교체 가능 (저렴한 VPS)
  - 필터링 레이어 역할

각 레이어 간 통신:
  - VPN 또는 SSH 터널로 암호화
  - 화이트리스트 기반 방화벽
  - 단방향 통신 원칙
```

---

## 3. VPS 선택 및 익명 구매 전략

### 3.1 VPS 제공업체 선택 기준

```
고려 사항:

1. 남용 처리(Abuse) 정책
   - 신속한 차단 여부 (AWS, GCP: 빠름)
   - 비교적 느린 대응 업체 선호
   - 검토: OVH, Hetzner, Vultr, Linode

2. 법적 관할권
   - 미국 밖 업체 고려 (MLAT 소요 시간)
   - 주요 고려 국가: 네덜란드, 루마니아, 아이슬란드

3. 결제 추적 가능성
   - 암호화폐 결제 지원 여부
   - Bitcoin (조심), Monero (더 익명)
   - 선불 기프트카드 (추적 주의)

4. 등록 요구 사항
   - KYC(Know Your Customer) 요구 여부
   - 이메일 전용 등록 vs 신분증 요구

5. 네트워크 품질
   - 낮은 레이턴시
   - 대역폭 제한 없음
   - 리버스 DNS 커스터마이징 가능
```

### 3.2 VPS 초기 설정 하드닝

```bash
# 새 VPS 최초 설정 스크립트 (Debian/Ubuntu)

# 1. 기본 업데이트
apt-get update && apt-get upgrade -y

# 2. 불필요한 서비스 비활성화
systemctl disable avahi-daemon
systemctl disable cups
systemctl stop avahi-daemon cups

# 3. SSH 하드닝
cat >> /etc/ssh/sshd_config << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers operator
EOF

# 4. 새 운영자 계정 생성 (root 비활성화)
useradd -m -s /bin/bash operator
mkdir -p /home/operator/.ssh
# SSH 공개키 추가
echo "ssh-ed25519 AAAA... operator@redteam" > /home/operator/.ssh/authorized_keys
chmod 700 /home/operator/.ssh
chmod 600 /home/operator/.ssh/authorized_keys
chown -R operator:operator /home/operator/.ssh

# 5. 방화벽 설정 (UFW)
ufw default deny incoming
ufw default allow outgoing
ufw allow from <운영자IP> to any port 22
ufw allow 443/tcp
ufw allow 80/tcp
ufw enable

# 6. 호스트명 변경 (의심 방지)
hostnamectl set-hostname mail.example.com

# 7. Fail2ban 설치 (브루트포스 방어)
apt-get install fail2ban -y
systemctl enable fail2ban

# 8. 시간대 설정 (UTC)
timedatectl set-timezone UTC

# 9. 시스템 로그 최소화
echo "*.* stop" >> /etc/rsyslog.conf
systemctl restart rsyslog
```

---

## 4. 도메인 카테고리화 및 신뢰도

### 4.1 도메인 선택 전략

```
목표: 차단/탐지 회피를 위한 "신뢰할 수 있어 보이는" 도메인

전략 1: 시뮬링크(Typosquatting) 도메인
  - microsoft-updates.com (실제: microsoft.com)
  - windowsupdate-cdn.net
  - 위험: 즉시 식별 가능, 법적 문제

전략 2: 일반 비즈니스 도메인
  - cloudsync-services.com
  - api-gateway-prod.net
  - data-analytics-hub.com
  → 기업 환경에서 정상으로 보임

전략 3: 만료 도메인 (Expired Domain) 활용
  - 과거 합법적 사이트가 사용하던 도메인
  - 이미 신뢰 카테고리에 등록됨
  - 검색: expireddomains.net, domcop.com

전략 4: 도메인 에이징 (Domain Aging)
  - 미리 도메인 등록 (수개월 전)
  - 초기에는 실제 정상 콘텐츠 게시
  - 작전 시에 C2로 전환
  → 도메인 생성일 검사 우회
```

### 4.2 도메인 카테고리 등록

```
목표 카테고리 (방화벽 기본 허용):
  - Business/Corporate
  - Technology
  - CDN/Hosting
  - Software Updates
  - News/Information

카테고리 등록 방법:
  1. Symantec (BlueCoat) 사이트 카테고리 조회
     → sitereview.symantec.com

  2. Fortiguard URL 카테고리
     → fortiguard.com/webfilter

  3. Palo Alto URL Filtering
     → urlfiltering.paloaltonetworks.com

  4. McAfee WebAdvisor
     → siteadvisor.com

각 사이트에서 "재분류 요청" 기능 활용:
  → 합법적 콘텐츠 게시 후 재분류 신청
  → 처리 기간: 수일 ~ 수주

자동화 도구:
  - Chameleon (도메인 카테고리 체크)
  - Goddi (다중 공급업체 확인)
```

### 4.3 DNS 레코드 설정

```bash
# 신뢰도 높이는 DNS 설정

# SPF 레코드 (이메일 스푸핑 방어용, 정상 도메인처럼 보임)
@ TXT "v=spf1 include:_spf.google.com ~all"

# MX 레코드 (이메일 서비스 존재처럼)
@ MX 10 mail.example.com.

# A 레코드 (메인 도메인)
@ A 1.2.3.4

# www CNAME (정상 웹사이트처럼)
www CNAME @

# 리다이렉터 서브도메인
cdn A 5.6.7.8
api A 5.6.7.8
updates A 5.6.7.8
```

---

## 5. 로그 관리 및 증거 처리

### 5.1 로그 최소화 설정

```bash
# Nginx 로그 최소화
# /etc/nginx/nginx.conf
http {
    access_log off;           # 접근 로그 비활성화
    error_log /dev/null;      # 에러 로그 /dev/null로
}

# Apache 로그 최소화
# /etc/apache2/apache2.conf
CustomLog /dev/null combined
ErrorLog /dev/null

# Bash 히스토리 비활성화
export HISTFILE=/dev/null
export HISTSIZE=0
unset HISTFILE

# 또는 .bashrc에 추가
echo "export HISTFILE=/dev/null" >> ~/.bashrc
echo "unset HISTFILE" >> ~/.bashrc

# Systemd 저널 최소화
# /etc/systemd/journald.conf
[Journal]
Storage=none
Compress=no
```

### 5.2 작전 후 정리 체크리스트

```bash
# 작전 종료 후 정리 스크립트 (개념)

# 1. 에이전트/임플란트 자삭 트리거
# (에이전트에 self-destruct 명령 전송)

# 2. C2 서버 로그 삭제
rm -rf /var/log/*
journalctl --vacuum-time=1s
> /root/.bash_history
> /home/operator/.bash_history

# 3. 임시 파일 삭제
rm -rf /tmp/*
rm -rf /dev/shm/*

# 4. 페이로드 파일 삭제
find /opt/c2/ -name "*.exe" -delete
find /opt/c2/ -name "*.dll" -delete
find /opt/c2/ -name "*.bin" -delete

# 5. 데이터 안전 삭제 (복구 불가)
shred -u /path/to/sensitive/file
srm -rf /path/to/directory  # secure-delete 패키지

# 6. 방화벽 규칙 초기화
iptables -F
iptables -t nat -F

# 7. VPS 삭제 (가능하면)
# → 클라우드 API로 인스턴스 완전 삭제
```

---

## 6. HTTPS 인증서 OPSEC

### 6.1 Certificate Transparency (CT) 로그

```
CT 로그란:
  - 모든 공개 신뢰 CA가 발급한 인증서의 공개 기록
  - crt.sh, censys.io 등에서 검색 가능
  - 인증서 발급 즉시 공개됨

OPSEC 위험:
  - 새 도메인/서브도메인 발급 → 즉시 CT 로그에 기록
  - 방어자가 와일드카드 모니터링으로 탐지 가능
  - 예: *.target-company.com 을 구독 → 피싱 도메인 발견

대응 방법:
  1. CT 로그 검색으로 방어자 시각 이해
     → crt.sh에서 자신의 도메인 확인

  2. 자체 서명 인증서 사용 (내부용)
     → CT 로그에 기록 안 됨
     → 에이전트에서 인증서 검증 비활성화 필요

  3. Let's Encrypt 대신 사설 CA 사용
     → 내부 CA 구축

  4. 인증서 투명성 정책 검토
     → --preferred-challenges dns 챌린지로 검증
```

### 6.2 자체 서명 인증서 생성

```bash
# 루트 CA 생성
openssl genrsa -out root-ca.key 4096
openssl req -new -x509 \
  -key root-ca.key \
  -out root-ca.crt \
  -days 3650 \
  -subj "/C=US/ST=California/L=San Francisco/O=Tech Corp/CN=Root CA"

# 서버 키 및 CSR 생성
openssl genrsa -out server.key 2048
openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Tech Corp/CN=updates.legitimate-cdn.com"

# SAN(Subject Alternative Name) 확장 포함 서명
cat > server.ext << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = updates.legitimate-cdn.com
DNS.2 = api.legitimate-cdn.com
DNS.3 = *.legitimate-cdn.com
IP.1 = 10.0.0.5
EOF

openssl x509 -req \
  -in server.csr \
  -CA root-ca.crt \
  -CAkey root-ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extfile server.ext

# 에이전트에서 핀닝으로 이 CA만 신뢰하도록 설정
```

---

## 7. Cobalt Strike Malleable C2 프로파일

### 7.1 프로파일 개념

```
Malleable C2 Profile은 Beacon의 네트워크 트래픽 외형을
완전히 커스터마이징할 수 있는 설정 파일이다.

변경 가능한 요소:
  - HTTP 메서드 (GET/POST)
  - URI 경로
  - HTTP 헤더 (Host, Cookie, User-Agent 등)
  - 데이터 인코딩 방식 (base64, xor, netbios 등)
  - 페이로드 위치 (URI 파라미터, 헤더, 바디)
  - Sleep 시간 및 Jitter
  - 프로세스 생성 방식
  - 메모리 권한 설정
```

### 7.2 프로파일 구조 예시

```
# Office365 트래픽으로 위장하는 프로파일 개념

set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set sleeptime "30000";   # 30초
set jitter    "20";      # ±20%
set maxdns    "255";
set dns_idle  "8.8.4.4";

https-certificate {
    set CN "outlook.microsoft.com";
    set O  "Microsoft Corporation";
    set C  "US";
    set ST "Washington";
    set L  "Redmond";
}

http-get {
    set uri "/owa/auth/logon.aspx /ecp/default.aspx";
    
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Connection" "keep-alive";
        
        metadata {
            base64url;
            parameter "session";
        }
    }
    
    server {
        header "Content-Type" "text/html; charset=utf-8";
        header "Server" "Microsoft-IIS/10.0";
        header "X-Powered-By" "ASP.NET";
        
        output {
            base64url;
            prepend "<!DOCTYPE html><html><head>";
            append "</head><body></body></html>";
            print;
        }
    }
}

http-post {
    set uri "/owa/auth/oauthtoken";
    
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        
        id {
            base64url;
            parameter "client_id";
        }
        
        output {
            base64url;
            parameter "code";
        }
    }
    
    server {
        header "Content-Type" "application/json";
        
        output {
            base64url;
            print;
        }
    }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\svchost.exe";
    set spawnto_x64 "%windir%\\system32\\svchost.exe";
    set obfuscate    "true";
    set smartinject  "true";
}

process-inject {
    set allocator "NtMapViewOfSection";
    set min_alloc "16700";
    set userwx    "false";
    
    transform-x64 {
        prepend "\x90\x90\x90";  # NOP 슬레드
    }
    
    execute {
        CreateThread;
        NtQueueApcThread;
        CreateRemoteThread;
    }
}
```

### 7.3 프로파일 검증

```bash
# c2lint으로 프로파일 검증 (Cobalt Strike 포함)
./c2lint profile.c2

# 프로파일 없이 직접 테스트
curl -v -A "Mozilla/5.0 ..." \
  http://teamserver.local/owa/auth/logon.aspx?session=dGVzdA==

# Malleable C2 프로파일 모음
# https://github.com/rsmudge/Malleable-C2-Profiles
# https://github.com/threatexpress/malleable-c2
```

---

## 8. Python OPSEC 체크리스트 자동화

```python
#!/usr/bin/env python3
"""
레드팀 인프라 OPSEC 자동 점검 스크립트
교육/CTF 환경 전용
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class CheckResult:
    name: str
    severity: Severity
    passed: bool
    message: str
    recommendation: str = ""


@dataclass
class OpsecReport:
    target: str
    checks: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.checks.append(result)

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.checks),
            "passed": sum(1 for c in self.checks if c.passed),
            "failed": sum(1 for c in self.checks if not c.passed),
            "critical": sum(1 for c in self.checks if not c.passed and c.severity == Severity.CRITICAL),
            "high":     sum(1 for c in self.checks if not c.passed and c.severity == Severity.HIGH),
        }

    def print_report(self) -> None:
        print(f"\n{'='*60}")
        print(f"OPSEC 점검 보고서: {self.target}")
        print(f"{'='*60}")

        for check in self.checks:
            icon = "✓" if check.passed else "✗"
            status = "PASS" if check.passed else f"FAIL [{check.severity.value}]"
            print(f"\n[{icon}] {check.name}: {status}")
            print(f"    └─ {check.message}")
            if not check.passed and check.recommendation:
                print(f"    [권고] {check.recommendation}")

        s = self.summary()
        print(f"\n{'='*60}")
        print(f"결과 요약: {s['passed']}/{s['total']} 통과")
        print(f"실패: CRITICAL={s['critical']}, HIGH={s['high']}")
        print(f"{'='*60}\n")


def check_whois_privacy(domain: str) -> CheckResult:
    """WHOIS 개인정보 보호 확인 (간이 DNS 기반)"""
    try:
        socket.gethostbyname(domain)
        # 실제로는 whois 쿼리 필요 (python-whois 라이브러리)
        return CheckResult(
            name="WHOIS 프라이버시",
            severity=Severity.HIGH,
            passed=False,
            message=f"{domain}: WHOIS 정보 직접 확인 필요",
            recommendation="도메인 등록 시 Privacy Protection 활성화 필수 (Namecheap, Cloudflare 등)",
        )
    except socket.gaierror:
        return CheckResult(
            name="WHOIS 프라이버시",
            severity=Severity.HIGH,
            passed=False,
            message=f"{domain}: DNS 해석 실패",
            recommendation="도메인 DNS 설정 확인",
        )


def check_ssl_certificate(host: str, port: int = 443) -> CheckResult:
    """SSL 인증서 정보 점검"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        # 인증서 Subject 확인
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        cn = subject.get("commonName", "")
        org = subject.get("organizationName", "")
        issuer_cn = issuer.get("commonName", "")

        issues = []
        if "localhost" in cn.lower():
            issues.append("CN에 localhost 포함")
        if "test" in cn.lower() or "dev" in cn.lower():
            issues.append(f"테스트/개발 CN: {cn}")
        if "Let's Encrypt" in issuer_cn:
            issues.append("Let's Encrypt 인증서 (CT 로그에 기록됨)")

        if issues:
            return CheckResult(
                name="SSL 인증서 OPSEC",
                severity=Severity.MEDIUM,
                passed=False,
                message=f"{host}: {', '.join(issues)}",
                recommendation="신뢰할 수 있는 CA 또는 자체 CA 인증서 사용, CT 로그 모니터링",
            )

        return CheckResult(
            name="SSL 인증서 OPSEC",
            severity=Severity.MEDIUM,
            passed=True,
            message=f"{host}: 인증서 기본 점검 통과 (CN={cn})",
        )

    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
        return CheckResult(
            name="SSL 인증서 OPSEC",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"{host}:{port} SSL 연결 실패: {e}",
            recommendation="SSL 설정 확인",
        )


def check_default_ports(host: str) -> CheckResult:
    """알려진 C2 기본 포트 노출 확인"""
    known_c2_ports = {
        50050: "Cobalt Strike 팀서버",
        4444: "Metasploit 기본 핸들러",
        8888: "Sliver 기본 mTLS",
        40056: "Havoc 팀서버",
        55553: "Armitage",
        8443: "일반 C2 HTTPS 대체",
    }

    exposed_ports: list[str] = []
    for port, service in known_c2_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                exposed_ports.append(f"{port}({service})")
        except OSError:
            pass

    if exposed_ports:
        return CheckResult(
            name="C2 기본 포트 노출",
            severity=Severity.CRITICAL,
            passed=False,
            message=f"알려진 C2 포트 발견: {', '.join(exposed_ports)}",
            recommendation="비표준 포트 사용 또는 방화벽으로 제한 (운영자 IP만 허용)",
        )

    return CheckResult(
        name="C2 기본 포트 노출",
        severity=Severity.CRITICAL,
        passed=True,
        message=f"{host}: 알려진 C2 기본 포트 미노출",
    )


def check_http_headers(host: str, port: int = 80) -> CheckResult:
    """HTTP 응답 헤더 점검 (C2 서버 식별 정보 노출)"""
    suspicious_headers = [
        ("server", ["cobalt strike", "metasploit", "havoc", "sliver"]),
        ("x-powered-by", ["python", "ruby", "go/", "node"]),
    ]

    try:
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{host}:{port}/"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            headers = dict(resp.headers)

        issues = []
        for header_name, keywords in suspicious_headers:
            val = headers.get(header_name, "").lower()
            if any(kw in val for kw in keywords):
                issues.append(f"{header_name}: {headers.get(header_name)}")

        if issues:
            return CheckResult(
                name="HTTP 응답 헤더",
                severity=Severity.HIGH,
                passed=False,
                message=f"C2 도구 식별 가능한 헤더: {issues}",
                recommendation="Server 헤더를 Apache/nginx 등으로 위장",
            )

        return CheckResult(
            name="HTTP 응답 헤더",
            severity=Severity.HIGH,
            passed=True,
            message=f"{host}: 응답 헤더 기본 점검 통과",
        )

    except Exception as e:
        return CheckResult(
            name="HTTP 응답 헤더",
            severity=Severity.HIGH,
            passed=False,
            message=f"HTTP 연결 실패: {e}",
            recommendation="HTTP/HTTPS 서비스 상태 확인",
        )


def check_domain_age(domain: str) -> CheckResult:
    """도메인 등록 나이 확인 (간이 버전)"""
    # 실제 구현에서는 whois 라이브러리 필요
    # 여기서는 개념적 체크
    return CheckResult(
        name="도메인 에이징",
        severity=Severity.MEDIUM,
        passed=False,
        message=f"{domain}: 도메인 등록 기간 직접 확인 필요",
        recommendation="도메인은 최소 1개월 전 등록 권장. whois 도구로 확인: whois " + domain,
    )


def check_reverse_dns(ip: str) -> CheckResult:
    """역방향 DNS 설정 점검"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        suspicious = any(
            kw in hostname.lower()
            for kw in ["vps", "cloud", "dedicated", "server", "host", "ip"]
        )
        if suspicious:
            return CheckResult(
                name="역방향 DNS",
                severity=Severity.LOW,
                passed=False,
                message=f"{ip} → {hostname} (호스팅 제공업체 노출)",
                recommendation="PTR 레코드를 합법적 도메인으로 변경",
            )
        return CheckResult(
            name="역방향 DNS",
            severity=Severity.LOW,
            passed=True,
            message=f"{ip} → {hostname}",
        )
    except socket.herror:
        return CheckResult(
            name="역방향 DNS",
            severity=Severity.LOW,
            passed=False,
            message=f"{ip}: 역방향 DNS 없음",
            recommendation="PTR 레코드 설정 또는 VPS 제공업체에 rDNS 변경 요청",
        )


def check_cdn_detection(host: str) -> CheckResult:
    """CDN/클라우드 서비스 직접 노출 확인"""
    try:
        ip = socket.gethostbyname(host)
        addr = ipaddress.IPv4Address(ip)

        # 알려진 클라우드 대역 (간략화)
        cloud_ranges = {
            "AWS": [
                ipaddress.IPv4Network("52.0.0.0/6"),
                ipaddress.IPv4Network("18.128.0.0/9"),
            ],
            "GCP": [
                ipaddress.IPv4Network("34.64.0.0/10"),
                ipaddress.IPv4Network("35.184.0.0/13"),
            ],
            "Azure": [
                ipaddress.IPv4Network("20.0.0.0/8"),
            ],
        }

        for provider, ranges in cloud_ranges.items():
            if any(addr in net for net in ranges):
                return CheckResult(
                    name="클라우드 제공업체 노출",
                    severity=Severity.MEDIUM,
                    passed=False,
                    message=f"{host} ({ip}): {provider} IP 대역",
                    recommendation="CDN 뒤에 숨기거나 덜 알려진 VPS 제공업체 사용",
                )

        return CheckResult(
            name="클라우드 제공업체 노출",
            severity=Severity.MEDIUM,
            passed=True,
            message=f"{host} ({ip}): 주요 클라우드 대역 아님",
        )
    except socket.gaierror as e:
        return CheckResult(
            name="클라우드 제공업체 노출",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"DNS 해석 실패: {e}",
        )


def run_opsec_checks(target: str, port: int) -> OpsecReport:
    """전체 OPSEC 점검 실행"""
    report = OpsecReport(target=target)

    # IP인지 도메인인지 판별
    is_ip = False
    try:
        ipaddress.IPv4Address(target)
        is_ip = True
    except ValueError:
        pass

    print(f"[*] OPSEC 점검 시작: {target}:{port}")

    if not is_ip:
        print("[*] WHOIS 개인정보 보호 확인...")
        report.add(check_whois_privacy(target))

        print("[*] 도메인 에이징 확인...")
        report.add(check_domain_age(target))

        print("[*] CDN 탐지...")
        report.add(check_cdn_detection(target))

        # IP 변환
        try:
            ip = socket.gethostbyname(target)
            print(f"[*] 역방향 DNS 확인 ({ip})...")
            report.add(check_reverse_dns(ip))
        except socket.gaierror:
            pass
    else:
        print(f"[*] 역방향 DNS 확인...")
        report.add(check_reverse_dns(target))

    print("[*] SSL 인증서 점검...")
    report.add(check_ssl_certificate(target, 443))

    print("[*] C2 기본 포트 점검...")
    report.add(check_default_ports(target))

    print("[*] HTTP 응답 헤더 점검...")
    report.add(check_http_headers(target, port))

    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="레드팀 인프라 OPSEC 자동 점검 (CTF/교육 전용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 opsec_check.py --target redirector.example.com
  python3 opsec_check.py --target 1.2.3.4 --port 443
  python3 opsec_check.py --target c2.example.com --output report.json
        """,
    )
    parser.add_argument("--target", required=True, help="점검할 호스트/도메인/IP")
    parser.add_argument("--port", type=int, default=80, help="HTTP 포트 (기본: 80)")
    parser.add_argument("--output", help="결과를 JSON 파일로 저장")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_opsec_checks(args.target, args.port)
    report.print_report()

    if args.output:
        data = {
            "target": report.target,
            "summary": report.summary(),
            "checks": [
                {
                    "name": c.name,
                    "severity": c.severity.value,
                    "passed": c.passed,
                    "message": c.message,
                    "recommendation": c.recommendation,
                }
                for c in report.checks
            ],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] 결과 저장: {args.output}")

    # 실패한 CRITICAL 항목 있으면 비정상 종료
    s = report.summary()
    if s["critical"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 참고 자료

- MITRE ATT&CK: Defense Evasion (TA0005)
- "Advanced Threat Tactics" - Raphael Mudge
- "Red Team Development and Operations" - Joe Vest & James Tubberville
- Certificate Transparency: crt.sh
- OPSEC 5단계 미 해군 교범 (OPNAVINST 3070.1)

---

<a name="english"></a>

# OPSEC Infrastructure Management

> **Purpose**: Learning material for educational, research, CTF, and authorized red team operation environments

---

## 1. OPSEC Principles

### 1.1 Overview of OPSEC (Operations Security)

OPSEC (Operations Security) is a concept originating from military tactics — it is the process of preventing adversaries from collecting and analyzing information about our operations.

```
OPSEC 5-Step Process:

Step 1: Critical Information Identification
  - Attacker's real IP address
  - C2 server location
  - Tools/techniques in use
  - Attack timing/schedule
  - Internal collaborator information

Step 2: Threat Analysis
  - Assess blue team capabilities
  - EDR/SIEM/SOAR solutions in use
  - Presence of threat intelligence team
  - Level of network monitoring

Step 3: Vulnerability Analysis
  - Where can information be exposed?
  - Certificate Transparency logs
  - WHOIS information
  - Domain registration patterns
  - VPS reuse

Step 4: Risk Assessment
  - Likelihood of exposure × impact
  - Prioritization

Step 5: Countermeasures
  - Technical measures
  - Procedural measures
  - Physical measures
```

### 1.2 Common Red Team OPSEC Failure Patterns

```
Common OPSEC Failures:

1. Infrastructure Reuse
   - Reusing IPs/domains from previous operations
   - Working against multiple clients from the same IP
   - → Risk of cross-contamination

2. Metadata Exposure
   - Using real name during domain registration
   - Entering real information in SSL certificates
   - GitHub commit email addresses
   - → Makes attribution possible

3. Tool Signatures (Toolmarks)
   - Using default Cobalt Strike configuration as-is
   - Known C2 framework default ports
   - Open-source tools used without modification
   - → Enables automatic detection

4. Timing Patterns
   - Active only during business hours (9am-6pm)
   - Fixed timezone (allows attacker location inference)
   - Regular beaconing patterns

5. Neglected Log Management
   - VPS provider logs left unattended
   - C2 server access logs retained
   - No post-operation cleanup
```

---

## 2. Attacker Infrastructure Separation

### 2.1 Long Haul vs Short Haul C2

```
Short Haul C2:
  Purpose: Initial compromise, rapid command execution
  Characteristics:
  - Fast response time (seconds)
  - High noise (greater detection risk)
  - Quick replacement upon detection
  - Examples: Metasploit/meterpreter, fast Beacon sleep

Long Haul C2:
  Purpose: Maintaining persistent access
  Characteristics:
  - Slow response (beaconing in hours)
  - Minimal traffic
  - Goal is long-term detection evasion
  - Examples: DNS C2, multi-hour sleep Beacons

Architecture:
  Initial Access
      │
      ├─► Short Haul C2 (for fast tasks)
      │     └─ Replace upon detection
      │
      └─► Long Haul C2 (for persistent access)
            └─ Managed to never be exposed
```

### 2.2 Infrastructure Separation Layers

```
Layer 1: Operational Infrastructure
  - Runs actual attack tools
  - Team servers, exploit servers
  - Never directly exposed

Layer 2: Staging Infrastructure
  - Hosts payloads
  - Receives initial callbacks
  - Connected to redirectors

Layer 3: Forwarder Infrastructure
  - Exposed to the public internet
  - Quickly replaceable (cheap VPS)
  - Acts as a filtering layer

Communication between layers:
  - Encrypted via VPN or SSH tunnel
  - Whitelist-based firewalls
  - One-directional communication principle
```

---

## 3. VPS Selection and Anonymous Purchase Strategy

### 3.1 VPS Provider Selection Criteria

```
Considerations:

1. Abuse Handling Policy
   - Speed of suspension (AWS, GCP: fast)
   - Prefer providers with slower response times
   - Review: OVH, Hetzner, Vultr, Linode

2. Legal Jurisdiction
   - Consider providers outside the US (MLAT processing time)
   - Key countries to consider: Netherlands, Romania, Iceland

3. Payment Traceability
   - Whether cryptocurrency payment is supported
   - Bitcoin (use with caution), Monero (more anonymous)
   - Prepaid gift cards (beware of tracking)

4. Registration Requirements
   - Whether KYC (Know Your Customer) is required
   - Email-only registration vs. ID requirement

5. Network Quality
   - Low latency
   - No bandwidth limits
   - Reverse DNS customization available
```

### 3.2 VPS Initial Setup Hardening

```bash
# Initial setup script for new VPS (Debian/Ubuntu)

# 1. Basic update
apt-get update && apt-get upgrade -y

# 2. Disable unnecessary services
systemctl disable avahi-daemon
systemctl disable cups
systemctl stop avahi-daemon cups

# 3. SSH hardening
cat >> /etc/ssh/sshd_config << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers operator
EOF

# 4. Create new operator account (disable root)
useradd -m -s /bin/bash operator
mkdir -p /home/operator/.ssh
# Add SSH public key
echo "ssh-ed25519 AAAA... operator@redteam" > /home/operator/.ssh/authorized_keys
chmod 700 /home/operator/.ssh
chmod 600 /home/operator/.ssh/authorized_keys
chown -R operator:operator /home/operator/.ssh

# 5. Firewall configuration (UFW)
ufw default deny incoming
ufw default allow outgoing
ufw allow from <operator-IP> to any port 22
ufw allow 443/tcp
ufw allow 80/tcp
ufw enable

# 6. Change hostname (to avoid suspicion)
hostnamectl set-hostname mail.example.com

# 7. Install Fail2ban (brute-force defense)
apt-get install fail2ban -y
systemctl enable fail2ban

# 8. Set timezone (UTC)
timedatectl set-timezone UTC

# 9. Minimize system logs
echo "*.* stop" >> /etc/rsyslog.conf
systemctl restart rsyslog
```

---

## 4. Domain Categorization and Reputation

### 4.1 Domain Selection Strategy

```
Goal: "Trustworthy-looking" domains to evade blocking/detection

Strategy 1: Typosquatting Domains
  - microsoft-updates.com (actual: microsoft.com)
  - windowsupdate-cdn.net
  - Risk: Immediately identifiable, legal issues

Strategy 2: Generic Business Domains
  - cloudsync-services.com
  - api-gateway-prod.net
  - data-analytics-hub.com
  → Appear normal in corporate environments

Strategy 3: Expired Domain Reuse
  - Domains previously used by legitimate sites
  - Already registered in trusted categories
  - Search: expireddomains.net, domcop.com

Strategy 4: Domain Aging
  - Register domain in advance (months ahead)
  - Initially publish actual legitimate content
  - Convert to C2 at operation time
  → Bypasses domain creation date checks
```

### 4.2 Domain Category Registration

```
Target Categories (allowed by default in firewalls):
  - Business/Corporate
  - Technology
  - CDN/Hosting
  - Software Updates
  - News/Information

How to register categories:
  1. Symantec (BlueCoat) site category lookup
     → sitereview.symantec.com

  2. Fortiguard URL category
     → fortiguard.com/webfilter

  3. Palo Alto URL Filtering
     → urlfiltering.paloaltonetworks.com

  4. McAfee WebAdvisor
     → siteadvisor.com

Use "re-categorization request" feature on each site:
  → Submit after publishing legitimate content
  → Processing time: days to weeks

Automation tools:
  - Chameleon (domain category check)
  - Goddi (multi-vendor verification)
```

### 4.3 DNS Record Configuration

```bash
# DNS settings to increase credibility

# SPF record (for email spoofing defense, makes domain look legitimate)
@ TXT "v=spf1 include:_spf.google.com ~all"

# MX record (makes it look like email service exists)
@ MX 10 mail.example.com.

# A record (main domain)
@ A 1.2.3.4

# www CNAME (makes it look like a normal website)
www CNAME @

# Redirector subdomains
cdn A 5.6.7.8
api A 5.6.7.8
updates A 5.6.7.8
```

---

## 5. Log Management and Evidence Handling

### 5.1 Log Minimization Configuration

```bash
# Nginx log minimization
# /etc/nginx/nginx.conf
http {
    access_log off;           # Disable access logs
    error_log /dev/null;      # Send error logs to /dev/null
}

# Apache log minimization
# /etc/apache2/apache2.conf
CustomLog /dev/null combined
ErrorLog /dev/null

# Disable Bash history
export HISTFILE=/dev/null
export HISTSIZE=0
unset HISTFILE

# Or add to .bashrc
echo "export HISTFILE=/dev/null" >> ~/.bashrc
echo "unset HISTFILE" >> ~/.bashrc

# Minimize systemd journal
# /etc/systemd/journald.conf
[Journal]
Storage=none
Compress=no
```

### 5.2 Post-Operation Cleanup Checklist

```bash
# Post-operation cleanup script (conceptual)

# 1. Trigger agent/implant self-destruct
# (Send self-destruct command to agents)

# 2. Delete C2 server logs
rm -rf /var/log/*
journalctl --vacuum-time=1s
> /root/.bash_history
> /home/operator/.bash_history

# 3. Delete temporary files
rm -rf /tmp/*
rm -rf /dev/shm/*

# 4. Delete payload files
find /opt/c2/ -name "*.exe" -delete
find /opt/c2/ -name "*.dll" -delete
find /opt/c2/ -name "*.bin" -delete

# 5. Secure deletion of data (non-recoverable)
shred -u /path/to/sensitive/file
srm -rf /path/to/directory  # secure-delete package

# 6. Reset firewall rules
iptables -F
iptables -t nat -F

# 7. Delete VPS (if possible)
# → Completely delete instance via cloud API
```

---

## 6. HTTPS Certificate OPSEC

### 6.1 Certificate Transparency (CT) Logs

```
What are CT logs:
  - Public records of all certificates issued by publicly trusted CAs
  - Searchable via crt.sh, censys.io, etc.
  - Published immediately upon certificate issuance

OPSEC risks:
  - New domain/subdomain issued → immediately recorded in CT logs
  - Defenders can detect via wildcard monitoring
  - Example: Subscribe to *.target-company.com → discover phishing domain

Countermeasures:
  1. Use CT log searches to understand defender's perspective
     → Check your own domain on crt.sh

  2. Use self-signed certificates (for internal use)
     → Not recorded in CT logs
     → Agent must have certificate validation disabled

  3. Use private CA instead of Let's Encrypt
     → Build internal CA

  4. Review certificate transparency policies
     → Validate with --preferred-challenges dns challenge
```

### 6.2 Self-Signed Certificate Generation

```bash
# Generate root CA
openssl genrsa -out root-ca.key 4096
openssl req -new -x509 \
  -key root-ca.key \
  -out root-ca.crt \
  -days 3650 \
  -subj "/C=US/ST=California/L=San Francisco/O=Tech Corp/CN=Root CA"

# Generate server key and CSR
openssl genrsa -out server.key 2048
openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Tech Corp/CN=updates.legitimate-cdn.com"

# Sign with SAN (Subject Alternative Name) extension
cat > server.ext << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = updates.legitimate-cdn.com
DNS.2 = api.legitimate-cdn.com
DNS.3 = *.legitimate-cdn.com
IP.1 = 10.0.0.5
EOF

openssl x509 -req \
  -in server.csr \
  -CA root-ca.crt \
  -CAkey root-ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extfile server.ext

# Configure agent to trust only this CA via pinning
```

---

## 7. Cobalt Strike Malleable C2 Profile

### 7.1 Profile Concept

```
A Malleable C2 Profile is a configuration file that allows
complete customization of Beacon's network traffic appearance.

Customizable elements:
  - HTTP methods (GET/POST)
  - URI paths
  - HTTP headers (Host, Cookie, User-Agent, etc.)
  - Data encoding methods (base64, xor, netbios, etc.)
  - Payload location (URI parameters, headers, body)
  - Sleep time and Jitter
  - Process creation method
  - Memory permission settings
```

### 7.2 Profile Structure Example

```
# Profile concept for disguising as Office365 traffic

set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set sleeptime "30000";   # 30 seconds
set jitter    "20";      # ±20%
set maxdns    "255";
set dns_idle  "8.8.4.4";

https-certificate {
    set CN "outlook.microsoft.com";
    set O  "Microsoft Corporation";
    set C  "US";
    set ST "Washington";
    set L  "Redmond";
}

http-get {
    set uri "/owa/auth/logon.aspx /ecp/default.aspx";
    
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Connection" "keep-alive";
        
        metadata {
            base64url;
            parameter "session";
        }
    }
    
    server {
        header "Content-Type" "text/html; charset=utf-8";
        header "Server" "Microsoft-IIS/10.0";
        header "X-Powered-By" "ASP.NET";
        
        output {
            base64url;
            prepend "<!DOCTYPE html><html><head>";
            append "</head><body></body></html>";
            print;
        }
    }
}

http-post {
    set uri "/owa/auth/oauthtoken";
    
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        
        id {
            base64url;
            parameter "client_id";
        }
        
        output {
            base64url;
            parameter "code";
        }
    }
    
    server {
        header "Content-Type" "application/json";
        
        output {
            base64url;
            print;
        }
    }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\svchost.exe";
    set spawnto_x64 "%windir%\\system32\\svchost.exe";
    set obfuscate    "true";
    set smartinject  "true";
}

process-inject {
    set allocator "NtMapViewOfSection";
    set min_alloc "16700";
    set userwx    "false";
    
    transform-x64 {
        prepend "\x90\x90\x90";  # NOP sled
    }
    
    execute {
        CreateThread;
        NtQueueApcThread;
        CreateRemoteThread;
    }
}
```

### 7.3 Profile Validation

```bash
# Validate profile with c2lint (included with Cobalt Strike)
./c2lint profile.c2

# Direct testing without profile
curl -v -A "Mozilla/5.0 ..." \
  http://teamserver.local/owa/auth/logon.aspx?session=dGVzdA==

# Malleable C2 profile collections
# https://github.com/rsmudge/Malleable-C2-Profiles
# https://github.com/threatexpress/malleable-c2
```

---

## 8. Python OPSEC Checklist Automation

```python
#!/usr/bin/env python3
"""
Red team infrastructure OPSEC automated check script
For educational/CTF environments only
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class CheckResult:
    name: str
    severity: Severity
    passed: bool
    message: str
    recommendation: str = ""


@dataclass
class OpsecReport:
    target: str
    checks: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.checks.append(result)

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.checks),
            "passed": sum(1 for c in self.checks if c.passed),
            "failed": sum(1 for c in self.checks if not c.passed),
            "critical": sum(1 for c in self.checks if not c.passed and c.severity == Severity.CRITICAL),
            "high":     sum(1 for c in self.checks if not c.passed and c.severity == Severity.HIGH),
        }

    def print_report(self) -> None:
        print(f"\n{'='*60}")
        print(f"OPSEC Check Report: {self.target}")
        print(f"{'='*60}")

        for check in self.checks:
            icon = "✓" if check.passed else "✗"
            status = "PASS" if check.passed else f"FAIL [{check.severity.value}]"
            print(f"\n[{icon}] {check.name}: {status}")
            print(f"    └─ {check.message}")
            if not check.passed and check.recommendation:
                print(f"    [Recommendation] {check.recommendation}")

        s = self.summary()
        print(f"\n{'='*60}")
        print(f"Summary: {s['passed']}/{s['total']} passed")
        print(f"Failures: CRITICAL={s['critical']}, HIGH={s['high']}")
        print(f"{'='*60}\n")


def check_whois_privacy(domain: str) -> CheckResult:
    """Check WHOIS privacy protection (simplified DNS-based)"""
    try:
        socket.gethostbyname(domain)
        # Actual implementation requires whois query (python-whois library)
        return CheckResult(
            name="WHOIS Privacy",
            severity=Severity.HIGH,
            passed=False,
            message=f"{domain}: Manual WHOIS verification required",
            recommendation="Enable Privacy Protection during domain registration (Namecheap, Cloudflare, etc.)",
        )
    except socket.gaierror:
        return CheckResult(
            name="WHOIS Privacy",
            severity=Severity.HIGH,
            passed=False,
            message=f"{domain}: DNS resolution failed",
            recommendation="Check domain DNS configuration",
        )


def check_ssl_certificate(host: str, port: int = 443) -> CheckResult:
    """Check SSL certificate information"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        # Check certificate subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        cn = subject.get("commonName", "")
        org = subject.get("organizationName", "")
        issuer_cn = issuer.get("commonName", "")

        issues = []
        if "localhost" in cn.lower():
            issues.append("CN contains localhost")
        if "test" in cn.lower() or "dev" in cn.lower():
            issues.append(f"Test/development CN: {cn}")
        if "Let's Encrypt" in issuer_cn:
            issues.append("Let's Encrypt certificate (recorded in CT logs)")

        if issues:
            return CheckResult(
                name="SSL Certificate OPSEC",
                severity=Severity.MEDIUM,
                passed=False,
                message=f"{host}: {', '.join(issues)}",
                recommendation="Use a trusted CA or self-signed CA certificate, monitor CT logs",
            )

        return CheckResult(
            name="SSL Certificate OPSEC",
            severity=Severity.MEDIUM,
            passed=True,
            message=f"{host}: Certificate basic check passed (CN={cn})",
        )

    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
        return CheckResult(
            name="SSL Certificate OPSEC",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"{host}:{port} SSL connection failed: {e}",
            recommendation="Check SSL configuration",
        )


def check_default_ports(host: str) -> CheckResult:
    """Check for exposure of known C2 default ports"""
    known_c2_ports = {
        50050: "Cobalt Strike team server",
        4444: "Metasploit default handler",
        8888: "Sliver default mTLS",
        40056: "Havoc team server",
        55553: "Armitage",
        8443: "Generic C2 HTTPS alternative",
    }

    exposed_ports: list[str] = []
    for port, service in known_c2_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                exposed_ports.append(f"{port}({service})")
        except OSError:
            pass

    if exposed_ports:
        return CheckResult(
            name="C2 Default Port Exposure",
            severity=Severity.CRITICAL,
            passed=False,
            message=f"Known C2 ports found: {', '.join(exposed_ports)}",
            recommendation="Use non-standard ports or restrict with firewall (allow operator IP only)",
        )

    return CheckResult(
        name="C2 Default Port Exposure",
        severity=Severity.CRITICAL,
        passed=True,
        message=f"{host}: No known C2 default ports exposed",
    )


def check_http_headers(host: str, port: int = 80) -> CheckResult:
    """Check HTTP response headers (C2 server identification information exposure)"""
    suspicious_headers = [
        ("server", ["cobalt strike", "metasploit", "havoc", "sliver"]),
        ("x-powered-by", ["python", "ruby", "go/", "node"]),
    ]

    try:
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{host}:{port}/"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            headers = dict(resp.headers)

        issues = []
        for header_name, keywords in suspicious_headers:
            val = headers.get(header_name, "").lower()
            if any(kw in val for kw in keywords):
                issues.append(f"{header_name}: {headers.get(header_name)}")

        if issues:
            return CheckResult(
                name="HTTP Response Headers",
                severity=Severity.HIGH,
                passed=False,
                message=f"Headers that can identify C2 tools: {issues}",
                recommendation="Disguise Server header as Apache/nginx/etc.",
            )

        return CheckResult(
            name="HTTP Response Headers",
            severity=Severity.HIGH,
            passed=True,
            message=f"{host}: Response header basic check passed",
        )

    except Exception as e:
        return CheckResult(
            name="HTTP Response Headers",
            severity=Severity.HIGH,
            passed=False,
            message=f"HTTP connection failed: {e}",
            recommendation="Check HTTP/HTTPS service status",
        )


def check_domain_age(domain: str) -> CheckResult:
    """Check domain registration age (simplified version)"""
    # Actual implementation requires whois library
    # This is a conceptual check
    return CheckResult(
        name="Domain Aging",
        severity=Severity.MEDIUM,
        passed=False,
        message=f"{domain}: Manual verification of domain registration period required",
        recommendation="Domain should be registered at least 1 month in advance. Check with whois tool: whois " + domain,
    )


def check_reverse_dns(ip: str) -> CheckResult:
    """Check reverse DNS configuration"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        suspicious = any(
            kw in hostname.lower()
            for kw in ["vps", "cloud", "dedicated", "server", "host", "ip"]
        )
        if suspicious:
            return CheckResult(
                name="Reverse DNS",
                severity=Severity.LOW,
                passed=False,
                message=f"{ip} → {hostname} (hosting provider exposed)",
                recommendation="Change PTR record to a legitimate domain",
            )
        return CheckResult(
            name="Reverse DNS",
            severity=Severity.LOW,
            passed=True,
            message=f"{ip} → {hostname}",
        )
    except socket.herror:
        return CheckResult(
            name="Reverse DNS",
            severity=Severity.LOW,
            passed=False,
            message=f"{ip}: No reverse DNS found",
            recommendation="Set PTR record or request rDNS change from VPS provider",
        )


def check_cdn_detection(host: str) -> CheckResult:
    """Check for direct CDN/cloud service exposure"""
    try:
        ip = socket.gethostbyname(host)
        addr = ipaddress.IPv4Address(ip)

        # Known cloud ranges (simplified)
        cloud_ranges = {
            "AWS": [
                ipaddress.IPv4Network("52.0.0.0/6"),
                ipaddress.IPv4Network("18.128.0.0/9"),
            ],
            "GCP": [
                ipaddress.IPv4Network("34.64.0.0/10"),
                ipaddress.IPv4Network("35.184.0.0/13"),
            ],
            "Azure": [
                ipaddress.IPv4Network("20.0.0.0/8"),
            ],
        }

        for provider, ranges in cloud_ranges.items():
            if any(addr in net for net in ranges):
                return CheckResult(
                    name="Cloud Provider Exposure",
                    severity=Severity.MEDIUM,
                    passed=False,
                    message=f"{host} ({ip}): {provider} IP range",
                    recommendation="Hide behind a CDN or use a less well-known VPS provider",
                )

        return CheckResult(
            name="Cloud Provider Exposure",
            severity=Severity.MEDIUM,
            passed=True,
            message=f"{host} ({ip}): Not in major cloud ranges",
        )
    except socket.gaierror as e:
        return CheckResult(
            name="Cloud Provider Exposure",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"DNS resolution failed: {e}",
        )


def run_opsec_checks(target: str, port: int) -> OpsecReport:
    """Run all OPSEC checks"""
    report = OpsecReport(target=target)

    # Determine if target is IP or domain
    is_ip = False
    try:
        ipaddress.IPv4Address(target)
        is_ip = True
    except ValueError:
        pass

    print(f"[*] Starting OPSEC checks: {target}:{port}")

    if not is_ip:
        print("[*] Checking WHOIS privacy...")
        report.add(check_whois_privacy(target))

        print("[*] Checking domain aging...")
        report.add(check_domain_age(target))

        print("[*] Checking CDN detection...")
        report.add(check_cdn_detection(target))

        # Resolve IP
        try:
            ip = socket.gethostbyname(target)
            print(f"[*] Checking reverse DNS ({ip})...")
            report.add(check_reverse_dns(ip))
        except socket.gaierror:
            pass
    else:
        print(f"[*] Checking reverse DNS...")
        report.add(check_reverse_dns(target))

    print("[*] Checking SSL certificate...")
    report.add(check_ssl_certificate(target, 443))

    print("[*] Checking C2 default ports...")
    report.add(check_default_ports(target))

    print("[*] Checking HTTP response headers...")
    report.add(check_http_headers(target, port))

    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Red team infrastructure OPSEC automated check (CTF/educational only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python3 opsec_check.py --target redirector.example.com
  python3 opsec_check.py --target 1.2.3.4 --port 443
  python3 opsec_check.py --target c2.example.com --output report.json
        """,
    )
    parser.add_argument("--target", required=True, help="Host/domain/IP to check")
    parser.add_argument("--port", type=int, default=80, help="HTTP port (default: 80)")
    parser.add_argument("--output", help="Save results to JSON file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_opsec_checks(args.target, args.port)
    report.print_report()

    if args.output:
        data = {
            "target": report.target,
            "summary": report.summary(),
            "checks": [
                {
                    "name": c.name,
                    "severity": c.severity.value,
                    "passed": c.passed,
                    "message": c.message,
                    "recommendation": c.recommendation,
                }
                for c in report.checks
            ],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] Results saved: {args.output}")

    # Exit with error if any CRITICAL items failed
    s = report.summary()
    if s["critical"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## References

- MITRE ATT&CK: Defense Evasion (TA0005)
- "Advanced Threat Tactics" - Raphael Mudge
- "Red Team Development and Operations" - Joe Vest & James Tubberville
- Certificate Transparency: crt.sh
- OPSEC 5-Step Process - U.S. Navy Manual (OPNAVINST 3070.1)
