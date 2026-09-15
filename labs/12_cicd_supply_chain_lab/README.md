# Lab 12: CI/CD 파이프라인 침투 및 소프트웨어 공급망 보안 실습 랩 (PipePoison)

## 1. 랩 개요 (Overview)

현대 데브옵스(DevOps) 및 클라우드 네이티브 환경에서 소프트웨어 공급망(Software Supply Chain)은 공격자들의 최우선 표적이 되었습니다. SolarWinds Orion 공급망 공격, Codecov Bash Uploader 침해, XZ Utils 백도어 삽입, 수많은 PyPI/NPM 의존성 혼동(Dependency Confusion) 및 타이포스쿼팅 사태는 단 한 번의 CI/CD 인프라 장악이 전 세계 수천 개 고객사로의 2차 침투로 직결될 수 있음을 증명했습니다.

**PipePoison 랩**은 엔터프라이즈 CI/CD 인프라(OctoCorp DevOps)의 핵심 파이프라인을 모델링하여, 소스 코드 제출부터 릴리스 패키징 및 클러스터 배포에 이르는 전체 SDLC 수명주기에서 발생하는 4대 공급망 침투 기법을 직접 시뮬레이션하고 방어 통제를 검증할 수 있는 핸즈온 실습 환경입니다.

- **서비스 포트**: `8012` (웹 대시보드 및 CI/CD REST API)
- **컨테이너 이름**: `cicd_supply_chain_lab`
- **난이도**: ★★★☆
- **연계 교재**: [18장 DevSecOps CTF 실습 랩](../../18_DevSecOps/06_devsecops_ctf_lab.md), [35장 공급망 공격 CTF 실습 랩](../../35_Supply_Chain_Attacks/06_supply_chain_ctf_lab.md)
- **관련 워게임 트랙**: `supplychain` (35개 문제)
- **CLI 간편 실행**: `python3 vhack.py lab start 12`

---

## 2. 4단계 공급망 침투 킬체인 (Kill Chain Stages)

```
[1. Attacker PR] ──(pull_request_target)──> [2. Self-Hosted Runner]
        │                                           │
        │ Command Injection (PPE)                   │ pip install (Dependency Confusion)
        ▼                                           ▼
[Runner Environment RCE]                   [Malicious Package Hook]
        │                                           │
        ├───────────────── Secrets Exfiltration ────┤
        ▼ (Stage 3)
[Vault Master Token & Cloud Keys]
        │
        ▼ (Stage 4)
[Release Packaging Phase] ──(Unsigned Binary Tamper)──> [Staging Cluster Owned]
```

### 1단계: Poisoned Pipeline Execution (PPE) / 워크플로우 인젝션
- **공격 기법**: 위험한 `pull_request_target` 이벤트 트리거 및 검증되지 않은 PR 메타데이터 인터폴레이션(`${{ github.event.pull_request.title }}`) 악용
- **취약 원인**: 외부 기여자의 풀 리퀘스트를 포크(fork) 환경에서 검증 없이 메인 러너 컨텍스트로 실행하거나, 셸 스크립트 인라인 평가 시 이스케이프 없이 문자열을 결합하여 커맨드 인젝션(RCE) 발생
- **획득 플래그**: `FLAG{PPE_WORKFLOW_INJECTION_RUNNER_ESCAPE_9182}`

### 2단계: Dependency Confusion & Typosquatting (의존성 혼동)
- **공격 기법**: 사내 비공개 패키지명(`octocorp-crypto-vault`)과 동일한 이름을 공용 패키지 인덱스(PyPI)에 초고버전(`99.0.0`)으로 선점 배포
- **취약 원인**: `--extra-index-url`을 통한 의존성 조회 시 내부/공용 저장소 간 우선순위가 명시되지 않아, 시맨틱 버저닝에 의해 공용 저장소의 악성 패키지가 자동 다운로드되어 `setup.py` / `preinstall` 훅을 통해 러너 환경 장악
- **획득 플래그**: `FLAG{DEPENDENCY_CONFUSION_PREINSTALL_TAKEOVER_4821}`

### 3단계: CI/CD Secrets Exfiltration (러너 시크릿 탈취)
- **공격 기법**: 러너 환경변수에 주입된 마스터 `VAULT_TOKEN`, `AWS_ACCESS_KEY_ID`, `DOCKER_REGISTRY_TOKEN` 탈취
- **취약 원인**: CI/CD 로그 마스킹(`***`)은 단순 출력 필터링에 불과하므로, Base64/Hex 인코딩 및 외부 아티팩트/수집기(Out-of-band Collector)로의 HTTP 패킷 전송을 통해 엔터프라이즈 HashiCorp Vault의 루트 토큰 탈취
- **획득 플래그**: `FLAG{RUNNER_SECRETS_EXFIL_VAULT_TOKEN_7394}`

### 4단계: Release Artifact Backdooring & SLSA Provenance Tampering (릴리스 변조)
- **공격 기법**: 빌드 산출물(`auth-service-v2.3.9.tar.gz`)에 관리자 인증 우회 백도어(`backdoor_admin`)를 삽입하고 배포 파이프라인 우회
- **취약 원인**: 암호학적 서명(Sigstore Cosign) 및 불변 빌드 증적(SLSA Level 3 Provenance) 부재로 인해, 컴파일/패키징 단계에서 변조된 아티팩트가 스테이징 클러스터의 어드미션 컨트롤러를 그대로 통과하여 침해 배포 완료
- **획득 플래그**: `FLAG{SUPPLY_CHAIN_BACKDOOR_SLSA_BYPASS_8841}`

---

## 3. 방어 및 공급망 하드닝 가이드 (Defensive Hardening)

본 랩의 웹 콘솔 또는 `/api/security/policies` API를 통해 다음 4대 방어 정책을 활성화하고 익스플로잇 방어 효과를 실증할 수 있습니다:

1. **`sanitize_pr_inputs` (Stage 1 방어)**:
   - `pull_request_target` 사용을 엄격히 제한하고 읽기 전용 권한(`permissions: contents: read`) 강제.
   - 워크플로우 셸 스크립트 작성 시 컨텍스트 표현식 인라인 삽입 대신 환경변수(`env: PR_TITLE: ${{ ... }}`)를 통하도록 강제하여 커맨드 인젝션 원천 차단.

2. **`scoped_registries_only` (Stage 2 방어)**:
   - 내부 패키지에 전용 네임스페이스(`@octocorp/` 또는 `octocorp-*`)를 적용하고 저장소 스코핑을 강제.
   - `requirements.txt`에 `--require-hashes`를 적용하여 해시 핀(Hash Pinning)되지 않은 패키지 설치 차단.

3. **`oidc_short_lived_tokens` (Stage 3 방어)**:
   - CI/CD 러너에 장기 보관 정적 토큰(Static Vault Token / AWS IAM Secret) 주입을 전면 금지.
   - GitHub Actions / GitLab CI의 OIDC(OpenID Connect) 연동을 통해 수 분 내 만료되는 단기 임시 자격 증명만 허용.

4. **`enforce_slsa_signatures` (Stage 4 방어)**:
   - SLSA(Supply-chain Levels for Software Artifacts) v1.0 Level 3 규격을 적용하여 격리된 빌드 환경 보장.
   - Sigstore Cosign 및 Rekor 투명성 로그를 통한 암호학적 아티팩트 서명 검증이 없는 패키지는 쿠버네티스 어드미션 컨트롤러에서 배포 차단.

---

## 4. 환경 실행 및 검증 (Execution & Verification)

### Docker Compose로 실행
```bash
cd labs/12_cicd_supply_chain_lab
docker compose up -d --build

# 서비스 접속: http://localhost:8012
# 종료: docker compose down
```

### 로컬 파이썬으로 실행
```bash
cd labs/12_cicd_supply_chain_lab/app
python3 -m uvicorn main:app --host 0.0.0.0 --port 8012
```

### 자동 익스플로잇 PoC 스크립트 실행
```bash
python3 labs/12_cicd_supply_chain_lab/app/exploit_cicd.py http://localhost:8012
```

### 단위/통합 테스트 스위트 실행
```bash
pytest labs/12_cicd_supply_chain_lab/tests/test_cicd_lab.py -v
```
