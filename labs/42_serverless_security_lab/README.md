# Lab 42: ServerlessGuard — 서버리스 클라우드 보안 & 이벤트 인젝션 실전 랩

## 📌 개요
- **랩 ID**: `42`
- **디렉토리**: `labs/42_serverless_security_lab/`
- **코드네임**: `ServerlessGuard`
- **포트**: `8042` (`http://localhost:8042`)
- **난이도**: ★★★★★
- **관련 섹션**: `53_Serverless_Security`, `14_Cloud_Security`, `48_Threat_Modeling`
- **핵심 표준**: AWS Lambda Security Architecture / Ephemeral Storage Security / IAM Least Privilege / Cloud Event-Driven Threat Modeling

---

## 🎯 학습 목표
1. **Serverless Event Injection & Deserialization 분석**: S3 `ObjectCreated` 이벤트 메타데이터(`s3.object.key`)를 신뢰하여 서브프로세스 셸 명령어를 동적 실행할 때 발생하는 RCE 취약점 익스플로잇 및 방어.
2. **Warm Container /tmp 영속성 & 시크릿 카빙**: 서버리스 실행 환경(컨테이너) 재사용 메커니즘을 분석하여 `/tmp` 디렉터리에 잔존하는 이전 요청의 세션 토큰(`AWS_SESSION_TOKEN`) 및 민감 설정 카빙.
3. **과도한 IAM 실행 권한 & STS AssumeRole 상승**: Lambda Execution Role에 부여된 과도한 와일드카드(`sts:AssumeRole`, `iam:PassRole`) 권한을 악용하여 엔터프라이즈 관리자 역할(`CorpCloudAdminRole`)로 수직 권한 상승.
4. **서버리스 런타임 하드닝 & 최소 권한 강제**: 읽기 전용 루트 파일시스템, 호출 간 `/tmp` 스크러빙, 엄격한 JSON Schema 입력 검증, 그리고 ARN 스코핑 기반 IAM 최소 권한 정책(`s3:GetObject` 한정) 강제.

---

## 🚀 빠른 시작
```bash
# 단독 실행
cd labs/42_serverless_security_lab
docker compose up -d

# vhack CLI를 통한 제어 및 테스트
python vhack.py lab start 42
python vhack.py lab test 42
python vhack.py solve 42
```

---

## 🔬 실습 단계 및 플래그 안내
1. **Stage 1 (Event Injection & Deserialization Pollution)**: `POST /api/stage1/invoke-event`
   - 플래그: `FLAG{serverless_event_injection_s3_key_rce_pwned}`
2. **Stage 2 (Warm Container /tmp State Leak)**: `POST /api/stage2/dump-secrets`
   - 플래그: `FLAG{serverless_warm_container_tmp_persistence_token_leaked}`
3. **Stage 3 (Overprivileged IAM Execution Role & STS Escalation)**: `POST /api/stage3/escalate-iam`
   - 플래그: `FLAG{serverless_iam_overprivileged_role_escalated}`
4. **Stage 4 (Serverless Runtime Hardening & Least Privilege)**: `POST /api/stage4/harden-runtime`
   - 플래그: `FLAG{serverless_hardened_least_privilege_runtime_secured}`
