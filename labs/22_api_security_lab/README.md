# Lab 22: APIGuard — API Security & Modern Auth 랩

## 1. 개요 (Overview)
- **대상**: REST API, GraphQL 엔드포인트, JWT 기반 인증 시스템
- **주요 표준**: OWASP API Security Top 10 (2023)
  - `API1:2023` Broken Object Level Authorization (BOLA / IDOR)
  - `API5:2023` Broken Function Level Authorization (BFLA)
  - `API8:2023` Security Misconfiguration (GraphQL Introspection)
  - `API2:2023` Broken Authentication (JWT `none` Algorithm Confusion)
- **포트**: `8022`
- **웹 대시보드**: `http://localhost:8022/`

---

## 2. 미션 및 플래그 획득 시나리오

### Mission 1: BOLA / IDOR & BFLA 권한 상승
1. 일반 계정(`alice`)으로 로그인하여 자신의 주문(`order_1001`)을 조회합니다.
2. 타인의 VIP 주문 `order_9999`를 권한 검증 없이 직접 조회(BOLA)합니다.
3. 클라이언트 제어 헤더인 `X-Admin-Role: internal_sec`를 포함하여 `/api/v1/admin/export_users` 엔드포인트를 호출(BFLA)하고 사용자 DB 및 플래그를 획득합니다.
- **플래그 1**: `FLAG{bola_idor_bfla_api_privilege_escalated_4822}`

### Mission 2: GraphQL Introspection & Batching 악용
1. `/graphql` 엔드포인트에 `__schema` 인트로스펙션 쿼리를 전송하여 감추어진 `systemSecrets` 필드를 식별합니다.
2. `query { systemSecrets { masterApiKey flag } }`를 실행하여 민감 마스터 API 키와 플래그를 추출합니다.
- **플래그 2**: `FLAG{graphql_introspection_batching_bypass_7193}`

### Mission 3: JWT 'none' 알고리즘 서명 우회 & 권한 탈취
1. `/api/v1/auth/sample_token`에서 일반 사용자 JWT를 확인합니다.
2. 헤더의 `alg`를 `none`으로 변조하고, 페이로드의 `role`을 `admin`으로 설정한 뒤 서명을 제거한 무서명 토큰(`header.payload.`)을 생성합니다.
3. `/api/v1/auth/jwt_verify`에 Bearer 토큰으로 전송하여 서명 검증을 우회하고 관리자 플래그를 획득합니다.
- **플래그 3**: `FLAG{jwt_alg_none_jwks_confusion_pwned_8842}`

---

## 3. 방어 대책 (Remediation)
1. **BOLA/BFLA 방어**:
   - 세션/JWT 토큰의 사용자 식별자(`sub`)와 요청 대상 리소스의 소유권을 DB 쿼리 레벨에서 반드시 대조 (`WHERE id = ? AND owner_id = ?`).
   - 헤더 기반의 권한 인증(`X-Admin-Role`)을 금지하고, 서버 서명된 RBAC/ABAC 토큰 검증 적용.
2. **GraphQL 보안 강화**:
   - 프로덕션 환경에서 Schema Introspection 비활성화 (`introspection=False`).
   - Query Depth Limit 및 Complexity Limit을 적용하여 자원 고갈 공격 차단.
3. **JWT 안전한 검증**:
   - `alg: none`을 라이브러리 차원에서 명시적으로 거부(`algorithms=['HS256', 'RS256']` 화이트리스트).
   - 비대칭키와 대칭키 간의 알고리즘 혼동 공격 방지를 위해 키 식별자(`kid`) 및 공개키/비밀키 타입을 엄격히 분리.
