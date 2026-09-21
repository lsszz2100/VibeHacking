#!/usr/bin/env python3
"""Script to add 36th track 'apisec' (35 challenges, 1260 milestone) to VibeHacking wargame."""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WG_DIR = REPO_ROOT / "wargame"

CHALLENGES_SPEC = [
    # Tier 0 (2)
    (0, "t0_apisec_rest_methods", 10, "apisec_rest_methods_v1",
     "HTTP 메서드와 RESTful API 기초", "HTTP Methods & RESTful API Basics",
     "REST 아키텍처의 핵심 HTTP 메서드(GET, POST, PUT, DELETE, PATCH) 분석 챌린지입니다.\n지정된 식별자 `apisec_rest_methods_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_rest_methods_v1\") 앞 20자리}`",
     "Analyze standard HTTP methods (GET, POST, PUT, DELETE, PATCH) in REST architecture.\nCompute the first 20 hex characters of SHA256(\"apisec_rest_methods_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_rest_methods_v1\") first 20 hex}`",
     ["식별자 `apisec_rest_methods_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_rest_methods_v1\").", "Wrap in `FLAG{...}` format."]),

    (0, "t0_apisec_json_syntax", 20, "apisec_json_syntax_v1",
     "JSON 데이터 교환 포맷 및 파싱", "JSON Data Interchange & Parsing",
     "현대 API 통신의 표준 데이터 포맷인 JSON(JavaScript Object Notation) 구조 분석 챌린지입니다.\n지정된 식별자 `apisec_json_syntax_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_json_syntax_v1\") 앞 20자리}`",
     "Examine JSON structure used as the ubiquitous payload format in modern web APIs.\nCompute the first 20 hex characters of SHA256(\"apisec_json_syntax_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_json_syntax_v1\") first 20 hex}`",
     ["식별자 `apisec_json_syntax_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_json_syntax_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 1 (6)
    (1, "t1_apisec_bearer_token", 30, "apisec_bearer_token_v1",
     "Authorization 헤더와 Bearer 토큰", "Authorization Header & Bearer Token",
     "HTTP Authorization 헤더를 통한 Bearer 토큰 전송 규격(RFC 6750) 분석 챌린지입니다.\n지정된 식별자 `apisec_bearer_token_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_bearer_token_v1\") 앞 20자리}`",
     "Investigate RFC 6750 Bearer Token usage in HTTP Authorization headers.\nCompute the first 20 hex characters of SHA256(\"apisec_bearer_token_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_bearer_token_v1\") first 20 hex}`",
     ["식별자 `apisec_bearer_token_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_bearer_token_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_apisec_api_key_header", 40, "apisec_api_key_header_v1",
     "X-API-Key 헤더 인증 취약점", "X-API-Key Header Authentication Flaws",
     "정적 API 키 전송 방식의 한계와 URL 쿼리 스트링 노출 위험성 분석 챌린지입니다.\n지정된 식별자 `apisec_api_key_header_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_api_key_header_v1\") 앞 20자리}`",
     "Analyze risks of static API key leaks in query strings and headers.\nCompute the first 20 hex characters of SHA256(\"apisec_api_key_header_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_api_key_header_v1\") first 20 hex}`",
     ["식별자 `apisec_api_key_header_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_api_key_header_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_apisec_cors_wildcard", 50, "apisec_cors_wildcard_v1",
     "CORS Origin 와일드카드 오설정", "CORS Wildcard Misconfiguration",
     "Access-Control-Allow-Origin: * 및 자격 증명(Credentials) 허용 오설정 분석 챌린지입니다.\n지정된 식별자 `apisec_cors_wildcard_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_cors_wildcard_v1\") 앞 20자리}`",
     "Inspect cross-origin resource sharing (CORS) wildcard exposure and credential leaks.\nCompute the first 20 hex characters of SHA256(\"apisec_cors_wildcard_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_cors_wildcard_v1\") first 20 hex}`",
     ["식별자 `apisec_cors_wildcard_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_cors_wildcard_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_apisec_rate_limiting", 60, "apisec_rate_limiting_v1",
     "HTTP 429와 Rate Limiting 부재", "Lack of Rate Limiting & HTTP 429",
     "API 엔드포인트에 요청 빈도 제한(Rate Limiting)이 누락되어 발생하는 무차별 대입 공격 분석 챌린지입니다.\n지정된 식별자 `apisec_rate_limiting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_rate_limiting_v1\") 앞 20자리}`",
     "Evaluate vulnerability of unrestricted endpoints lacking 429 Too Many Requests limits.\nCompute the first 20 hex characters of SHA256(\"apisec_rate_limiting_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_rate_limiting_v1\") first 20 hex}`",
     ["식별자 `apisec_rate_limiting_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_rate_limiting_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_apisec_mass_assignment", 70, "apisec_mass_assignment_v1",
     "Mass Assignment 객체 자동 바인딩", "Mass Assignment Vulnerability",
     "클라이언트 JSON 요청 파라미터가 백엔드 도메인 모델에 무검증 자동 매핑되는 취약점 분석 챌린지입니다.\n지정된 식별자 `apisec_mass_assignment_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_mass_assignment_v1\") 앞 20자리}`",
     "Analyze blind parameter binding leading to unauthorized property mutation.\nCompute the first 20 hex characters of SHA256(\"apisec_mass_assignment_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_mass_assignment_v1\") first 20 hex}`",
     ["식별자 `apisec_mass_assignment_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_mass_assignment_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_apisec_openapi_spec", 80, "apisec_openapi_spec_v1",
     "Swagger & OpenAPI 스펙 노출", "Swagger & OpenAPI Spec Exposure",
     "공개된 `/swagger.json` 또는 `/openapi.json` 명세서를 통한 비공개 엔드포인트 정찰 챌린지입니다.\n지정된 식별자 `apisec_openapi_spec_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_openapi_spec_v1\") 앞 20자리}`",
     "Perform API reconnaissance via publicly accessible Swagger / OpenAPI definition endpoints.\nCompute the first 20 hex characters of SHA256(\"apisec_openapi_spec_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_openapi_spec_v1\") first 20 hex}`",
     ["식별자 `apisec_openapi_spec_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_openapi_spec_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 2 (12)
    (2, "t2_apisec_bola_idor_orders", 100, "apisec_bola_idor_orders_v1",
     "BOLA / IDOR 객체 수준 권한 검증 누락", "BOLA / IDOR Object Level Authorization",
     "OWASP API1 BOLA 취약점을 악용하여 다른 사용자의 주문 식별자를 직접 변조해 열람하는 챌린지입니다.\n지정된 식별자 `apisec_bola_idor_orders_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_bola_idor_orders_v1\") 앞 20자리}`",
     "Exploit broken object-level authorization by modifying order resource identifiers.\nCompute the first 20 hex characters of SHA256(\"apisec_bola_idor_orders_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_bola_idor_orders_v1\") first 20 hex}`",
     ["식별자 `apisec_bola_idor_orders_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_bola_idor_orders_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_bfla_admin_header", 110, "apisec_bfla_admin_header_v1",
     "BFLA 커스텀 헤더 주입 권한 상승", "BFLA Custom Header Privilege Escalation",
     "OWASP API5 BFLA 취약점을 악용하여 클라이언트 커스텀 헤더(`X-Admin-Role`)로 관리자 기능을 호출하는 챌린지입니다.\n지정된 식별자 `apisec_bfla_admin_header_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_bfla_admin_header_v1\") 앞 20자리}`",
     "Exploit broken function-level authorization by injecting custom admin assertion headers.\nCompute the first 20 hex characters of SHA256(\"apisec_bfla_admin_header_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_bfla_admin_header_v1\") first 20 hex}`",
     ["식별자 `apisec_bfla_admin_header_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_bfla_admin_header_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_graphql_schema_intro", 120, "apisec_graphql_schema_intro_v1",
     "GraphQL Schema Introspection 분석", "GraphQL Schema Introspection Analysis",
     "운영 환경에서 비활성화되지 않은 `__schema` 메타 쿼리를 실행하여 숨겨진 타입을 탐색하는 챌린지입니다.\n지정된 식별자 `apisec_graphql_schema_intro_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_graphql_schema_intro_v1\") 앞 20자리}`",
     "Extract full GraphQL schemas using __schema introspection queries in production.\nCompute the first 20 hex characters of SHA256(\"apisec_graphql_schema_intro_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_graphql_schema_intro_v1\") first 20 hex}`",
     ["식별자 `apisec_graphql_schema_intro_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_graphql_schema_intro_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_graphql_query_depth", 130, "apisec_graphql_query_depth_v1",
     "GraphQL 중첩 쿼리 Depth DoS", "GraphQL Nested Query Depth DoS",
     "순환 참조 관계의 필드를 무한 중첩 질의하여 서버 CPU와 메모리를 고갈시키는 공격 분석 챌린지입니다.\n지정된 식별자 `apisec_graphql_query_depth_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_graphql_query_depth_v1\") 앞 20자리}`",
     "Trigger resource exhaustion by exploiting cyclic relationships without query depth limiting.\nCompute the first 20 hex characters of SHA256(\"apisec_graphql_query_depth_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_graphql_query_depth_v1\") first 20 hex}`",
     ["식별자 `apisec_graphql_query_depth_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_graphql_query_depth_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_jwt_none_algorithm", 140, "apisec_jwt_none_algorithm_v1",
     "JWT alg: none 서명 우회 취약점", "JWT alg: none Signature Bypass",
     "JWT 헤더의 알고리즘을 `none`으로 설정하고 서명부를 비워 무결성 검증을 무력화하는 챌린지입니다.\n지정된 식별자 `apisec_jwt_none_algorithm_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_jwt_none_algorithm_v1\") 앞 20자리}`",
     "Bypass JWT token validation by setting alg header to 'none' and stripping signatures.\nCompute the first 20 hex characters of SHA256(\"apisec_jwt_none_algorithm_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_jwt_none_algorithm_v1\") first 20 hex}`",
     ["식별자 `apisec_jwt_none_algorithm_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_jwt_none_algorithm_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_jwt_claim_tampering", 150, "apisec_jwt_claim_tampering_v1",
     "JWT 클레임 변조 및 권한 탈취", "JWT Claim Tampering & Privilege Theft",
     "서명 검증이 미흡한 JWT의 페이로드에서 `role: admin` 클레임을 조작하여 관리자 권한을 획득하는 챌린지입니다.\n지정된 식별자 `apisec_jwt_claim_tampering_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_jwt_claim_tampering_v1\") 앞 20자리}`",
     "Tamper with JWT claims like role to gain unauthorized administrative privileges.\nCompute the first 20 hex characters of SHA256(\"apisec_jwt_claim_tampering_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_jwt_claim_tampering_v1\") first 20 hex}`",
     ["식별자 `apisec_jwt_claim_tampering_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_jwt_claim_tampering_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_graphql_batching_brute", 160, "apisec_graphql_batching_brute_v1",
     "GraphQL 배치 쿼리 무차별 대입", "GraphQL Batching Query Brute Force",
     "단일 HTTP POST 요청에 수백 개의 별칭(Alias) 또는 배열 쿼리를 포함하여 Rate Limit을 우회하는 챌린지입니다.\n지정된 식별자 `apisec_graphql_batching_brute_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_graphql_batching_brute_v1\") 앞 20자리}`",
     "Bypass HTTP-level rate limiting using GraphQL query batching and field aliases.\nCompute the first 20 hex characters of SHA256(\"apisec_graphql_batching_brute_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_graphql_batching_brute_v1\") first 20 hex}`",
     ["식별자 `apisec_graphql_batching_brute_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_graphql_batching_brute_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_oauth2_redirect_uri", 170, "apisec_oauth2_redirect_uri_v1",
     "OAuth2 Redirect URI 탈취 취약점", "OAuth2 Redirect URI Hijacking",
     "인가 서버의 리다이렉트 URI 유효성 검증 미흡으로 인가 코드(Code)가 공격자 서버로 유출되는 챌린지입니다.\n지정된 식별자 `apisec_oauth2_redirect_uri_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_oauth2_redirect_uri_v1\") 앞 20자리}`",
     "Hijack OAuth2 authorization codes due to loose redirect_uri regex validation.\nCompute the first 20 hex characters of SHA256(\"apisec_oauth2_redirect_uri_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_oauth2_redirect_uri_v1\") first 20 hex}`",
     ["식별자 `apisec_oauth2_redirect_uri_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_oauth2_redirect_uri_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_ssrf_webhook", 180, "apisec_ssrf_webhook_v1",
     "웹훅 등록을 통한 클라우드 SSRF", "Webhook Registration Cloud SSRF",
     "사용자 입력 웹훅 URL에 내부 IP 필터링이 누락되어 클라우드 메타데이터(169.254.169.254)를 탈취하는 챌린지입니다.\n지정된 식별자 `apisec_ssrf_webhook_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_ssrf_webhook_v1\") 앞 20자리}`",
     "Exploit webhook endpoints to trigger SSRF against cloud instance metadata services.\nCompute the first 20 hex characters of SHA256(\"apisec_ssrf_webhook_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_ssrf_webhook_v1\") first 20 hex}`",
     ["식별자 `apisec_ssrf_webhook_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_ssrf_webhook_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_api_versioning_leak", 190, "apisec_api_versioning_leak_v1",
     "레거시 API 엔드포인트 방치 취약점", "Unpatched Legacy API Version Exposure",
     "새 버전(`/v2/`)에서는 패치되었으나 구버전(`/v1/`)에 방치된 인증 결함을 공략하는 챌린지입니다.\n지정된 식별자 `apisec_api_versioning_leak_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_api_versioning_leak_v1\") 앞 20자리}`",
     "Exploit security regressions in deprecated but unretired legacy API endpoints.\nCompute the first 20 hex characters of SHA256(\"apisec_api_versioning_leak_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_api_versioning_leak_v1\") first 20 hex}`",
     ["식별자 `apisec_api_versioning_leak_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_api_versioning_leak_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_jwt_weak_hmac_secret", 200, "apisec_jwt_weak_hmac_secret_v1",
     "JWT 취약한 대칭 비밀키 오프라인 크랙", "Offline Cracking of Weak JWT HMAC Secrets",
     "사전 공격(Dictionary Attack)에 취약한 짧은 비밀키로 서명된 HS256 JWT를 복구하는 챌린지입니다.\n지정된 식별자 `apisec_jwt_weak_hmac_secret_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_jwt_weak_hmac_secret_v1\") 앞 20자리}`",
     "Recover weak HMAC secret keys through offline dictionary cracking with hashcat.\nCompute the first 20 hex characters of SHA256(\"apisec_jwt_weak_hmac_secret_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_jwt_weak_hmac_secret_v1\") first 20 hex}`",
     ["식별자 `apisec_jwt_weak_hmac_secret_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_jwt_weak_hmac_secret_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_apisec_lack_of_resource_limits", 210, "apisec_lack_of_resource_limits_v1",
     "페이지네이션 부재와 자원 고갈", "Lack of Resource Limits & Pagination",
     "`limit` 파라미터 상한이 지정되지 않아 수백만 건의 레코드를 한 번에 조회해 서버를 마비시키는 챌린지입니다.\n지정된 식별자 `apisec_lack_of_resource_limits_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_lack_of_resource_limits_v1\") 앞 20자리}`",
     "Cause severe backend latency or memory exhaustion by requesting unbounded page sizes.\nCompute the first 20 hex characters of SHA256(\"apisec_lack_of_resource_limits_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_lack_of_resource_limits_v1\") first 20 hex}`",
     ["식별자 `apisec_lack_of_resource_limits_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_lack_of_resource_limits_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 3 (10)
    (3, "t3_apisec_jwt_jwks_spoofing", 230, "apisec_jwt_jwks_spoofing_v1",
     "JWT jku 헤더 스푸핑 공격", "JWT jku Header JWKS Spoofing",
     "JWT 헤더의 `jku`(JWK Set URL)를 공격자가 제어하는 공개키 서버로 위조하여 임의 서명을 검증시키는 챌린지입니다.\n지정된 식별자 `apisec_jwt_jwks_spoofing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_jwt_jwks_spoofing_v1\") 앞 20자리}`",
     "Spoof JWKS URL in jku headers to force the server to verify tokens with attacker public keys.\nCompute the first 20 hex characters of SHA256(\"apisec_jwt_jwks_spoofing_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_jwt_jwks_spoofing_v1\") first 20 hex}`",
     ["식별자 `apisec_jwt_jwks_spoofing_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_jwt_jwks_spoofing_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_jwt_key_confusion_rs256_hs256", 250, "apisec_jwt_key_confusion_rs256_hs256_v1",
     "RS256 vs HS256 알고리즘 혼동 공격", "RS256 vs HS256 Algorithm Confusion",
     "비대칭 RSA 공개키를 대칭 HMAC 비밀키로 착각하도록 알고리즘을 변조하여 서명 위조에 성공하는 챌린지입니다.\n지정된 식별자 `apisec_jwt_key_confusion_rs256_hs256_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_jwt_key_confusion_rs256_hs256_v1\") 앞 20자리}`",
     "Sign HMAC tokens using public RSA keys due to algorithm confusion vulnerabilities.\nCompute the first 20 hex characters of SHA256(\"apisec_jwt_key_confusion_rs256_hs256_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_jwt_key_confusion_rs256_hs256_v1\") first 20 hex}`",
     ["식별자 `apisec_jwt_key_confusion_rs256_hs256_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_jwt_key_confusion_rs256_hs256_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_jwt_kid_path_traversal", 270, "apisec_jwt_kid_path_traversal_v1",
     "JWT kid 헤더 디렉토리 트래버설", "JWT kid Header Directory Traversal",
     "`kid`(Key ID) 파라미터의 파일 경로 탐색 취약점을 악용하여 `/dev/null` 빈 파일로 비밀키를 고정시키는 챌린지입니다.\n지정된 식별자 `apisec_jwt_kid_path_traversal_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_jwt_kid_path_traversal_v1\") 앞 20자리}`",
     "Exploit path traversal in kid headers to force verification with empty files like /dev/null.\nCompute the first 20 hex characters of SHA256(\"apisec_jwt_kid_path_traversal_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_jwt_kid_path_traversal_v1\") first 20 hex}`",
     ["식별자 `apisec_jwt_kid_path_traversal_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_jwt_kid_path_traversal_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_graphql_field_duplication", 290, "apisec_graphql_field_duplication_v1",
     "GraphQL 필드 중복 연산 고갈 DoS", "GraphQL Field Duplication DoS",
     "동일한 무거운 계산 필드를 수천 번 중복 호출하여 백엔드 리졸버 쓰레드를 독점하는 챌린지입니다.\n지정된 식별자 `apisec_graphql_field_duplication_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_graphql_field_duplication_v1\") 앞 20자리}`",
     "Exhaust backend compute capacity by repeating heavy fields thousands of times in a query.\nCompute the first 20 hex characters of SHA256(\"apisec_graphql_field_duplication_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_graphql_field_duplication_v1\") first 20 hex}`",
     ["식별자 `apisec_graphql_field_duplication_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_graphql_field_duplication_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_oauth2_pkce_downgrade", 310, "apisec_oauth2_pkce_downgrade_v1",
     "OAuth2 PKCE 다운그레이드 공격", "OAuth2 PKCE Downgrade Attack",
     "클라이언트가 전송한 code_challenge 검증을 서버가 선택적으로 생략하여 인가 코드를 가로채는 챌린지입니다.\n지정된 식별자 `apisec_oauth2_pkce_downgrade_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_oauth2_pkce_downgrade_v1\") 앞 20자리}`",
     "Downgrade PKCE verification requirements in OAuth2 flows to intercept authorization codes.\nCompute the first 20 hex characters of SHA256(\"apisec_oauth2_pkce_downgrade_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_oauth2_pkce_downgrade_v1\") first 20 hex}`",
     ["식별자 `apisec_oauth2_pkce_downgrade_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_oauth2_pkce_downgrade_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_rest_api_smuggling", 330, "apisec_rest_api_smuggling_v1",
     "API 게이트웨이 HTTP Request Smuggling", "API Gateway HTTP Request Smuggling",
     "프론트엔드 프록시와 백엔드 API 서버 간 Content-Length / Transfer-Encoding 해석 불일치를 공략하는 챌린지입니다.\n지정된 식별자 `apisec_rest_api_smuggling_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_rest_api_smuggling_v1\") 앞 20자리}`",
     "Smuggle hidden API requests through HTTP parsing discrepancies between reverse proxies.\nCompute the first 20 hex characters of SHA256(\"apisec_rest_api_smuggling_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_rest_api_smuggling_v1\") first 20 hex}`",
     ["식별자 `apisec_rest_api_smuggling_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_rest_api_smuggling_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_grpc_reflection_abuse", 350, "apisec_grpc_reflection_abuse_v1",
     "gRPC Server Reflection 정찰 및 익스플로잇", "gRPC Server Reflection Recon & Exploit",
     "운영 환경에 노출된 gRPC Reflection API를 사용하여 Protobuf 스키마를 복원하고 비인가 RPC를 호출하는 챌린지입니다.\n지정된 식별자 `apisec_grpc_reflection_abuse_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_grpc_reflection_abuse_v1\") 앞 20자리}`",
     "Dump internal Protobuf definitions via gRPC reflection and execute unauthenticated RPCs.\nCompute the first 20 hex characters of SHA256(\"apisec_grpc_reflection_abuse_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_grpc_reflection_abuse_v1\") first 20 hex}`",
     ["식별자 `apisec_grpc_reflection_abuse_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_grpc_reflection_abuse_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_websocket_hijacking", 370, "apisec_websocket_hijacking_v1",
     "CSWSH 실시간 웹소켓 세션 탈취", "Cross-Site WebSocket Hijacking (CSWSH)",
     "웹소켓 핸드셰이크 시 Origin 헤더 및 CSRF 토큰 검증 부재를 악용하여 실시간 스트림 데이터를 가로채는 챌린지입니다.\n지정된 식별자 `apisec_websocket_hijacking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_websocket_hijacking_v1\") 앞 20자리}`",
     "Hijack full-duplex WebSocket connections lacking Origin header validation.\nCompute the first 20 hex characters of SHA256(\"apisec_websocket_hijacking_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_websocket_hijacking_v1\") first 20 hex}`",
     ["식별자 `apisec_websocket_hijacking_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_websocket_hijacking_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_graphql_directive_overload", 390, "apisec_graphql_directive_overload_v1",
     "GraphQL @skip/@include 지시어 필터 우회", "GraphQL Directive Filter Bypass",
     "WAF나 복잡도 계산 엔진이 정적 쿼리만을 검사할 때 동적 지시어를 활용해 비인가 데이터를 우회 획득하는 챌린지입니다.\n지정된 식별자 `apisec_graphql_directive_overload_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_graphql_directive_overload_v1\") 앞 20자리}`",
     "Bypass query inspection rules by manipulating dynamic directives like @skip and @include.\nCompute the first 20 hex characters of SHA256(\"apisec_graphql_directive_overload_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_graphql_directive_overload_v1\") first 20 hex}`",
     ["식별자 `apisec_graphql_directive_overload_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_graphql_directive_overload_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_apisec_token_side_jacking", 410, "apisec_token_side_jacking_v1",
     "DPoP 부재와 토큰 사이드재킹 공격", "Token Side-Jacking & Lack of DPoP",
     "발행된 베어러 토큰이 특정 클라이언트 키에 바인딩(DPoP/mTLS)되지 않아 발생하는 세션 가로채기 분석 챌린지입니다.\n지정된 식별자 `apisec_token_side_jacking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_token_side_jacking_v1\") 앞 20자리}`",
     "Exploit sender-constraining gaps (lack of DPoP / mTLS) to replay stolen access tokens.\nCompute the first 20 hex characters of SHA256(\"apisec_token_side_jacking_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_token_side_jacking_v1\") first 20 hex}`",
     ["식별자 `apisec_token_side_jacking_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_token_side_jacking_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 4 (5)
    (4, "t4_apisec_graphql_engine_rce", 450, "apisec_graphql_engine_rce_v1",
     "GraphQL 리졸버 템플릿 인젝션(SSTI) RCE", "GraphQL Resolver SSTI to RCE",
     "리졸버 내부의 동적 문자열 템플릿 처리 취약점을 공략하여 서버 셸 명령을 원격 실행하는 챌린지입니다.\n지정된 식별자 `apisec_graphql_engine_rce_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_graphql_engine_rce_v1\") 앞 20자리}`",
     "Achieve remote code execution via Server-Side Template Injection within GraphQL resolvers.\nCompute the first 20 hex characters of SHA256(\"apisec_graphql_engine_rce_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_graphql_engine_rce_v1\") first 20 hex}`",
     ["식별자 `apisec_graphql_engine_rce_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_graphql_engine_rce_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_apisec_distributed_graphql_apollo_federation", 470, "apisec_distributed_graphql_apollo_federation_v1",
     "Apollo Federation 분산 게이트웨이 침투", "Apollo Federation Subgraph Impersonation",
     "분산 서브그래프 간 내부 통신 헤더를 위조하여 게이트웨이 인증을 우회하고 백엔드 서비스를 장악하는 챌린지입니다.\n지정된 식별자 `apisec_distributed_graphql_apollo_federation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_distributed_graphql_apollo_federation_v1\") 앞 20자리}`",
     "Impersonate internal federated subgraph routers to bypass edge gateway authorization checks.\nCompute the first 20 hex characters of SHA256(\"apisec_distributed_graphql_apollo_federation_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_distributed_graphql_apollo_federation_v1\") first 20 hex}`",
     ["식별자 `apisec_distributed_graphql_apollo_federation_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_distributed_graphql_apollo_federation_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_apisec_enterprise_api_gateway_bypass", 480, "apisec_enterprise_api_gateway_bypass_v1",
     "엔터프라이즈 API 게이트웨이 라우트 불일치 우회", "Enterprise API Gateway Routing Mismatch Bypass",
     "Kong / Envoy API Gateway와 업스트림 서비스 간 URL 정규화(Normalization) 차이를 악용한 ACL 우회 챌린지입니다.\n지정된 식별자 `apisec_enterprise_api_gateway_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_enterprise_api_gateway_bypass_v1\") 앞 20자리}`",
     "Exploit path normalization differences between edge API gateways and upstream application servers.\nCompute the first 20 hex characters of SHA256(\"apisec_enterprise_api_gateway_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_enterprise_api_gateway_bypass_v1\") first 20 hex}`",
     ["식별자 `apisec_enterprise_api_gateway_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_enterprise_api_gateway_bypass_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_apisec_zero_trust_api_mesh_defense", 490, "apisec_zero_trust_api_mesh_defense_v1",
     "서비스 메시 mTLS & 제로 트러스트 API 방어", "Service Mesh mTLS & Zero Trust API Defense",
     "Istio / Linkerd 서비스 메시 환경에서 Spiffe ID 기반 mTLS 상호 인증과 세분화된 인가 정책(AuthorizationPolicy) 구축 챌린지입니다.\n지정된 식별자 `apisec_zero_trust_api_mesh_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_zero_trust_api_mesh_defense_v1\") 앞 20자리}`",
     "Establish end-to-end zero-trust API protection using service mesh mTLS and Spiffe/Spire identities.\nCompute the first 20 hex characters of SHA256(\"apisec_zero_trust_api_mesh_defense_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_zero_trust_api_mesh_defense_v1\") first 20 hex}`",
     ["식별자 `apisec_zero_trust_api_mesh_defense_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_zero_trust_api_mesh_defense_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_apisec_modern_auth_capstone_pwn", 500, "apisec_modern_auth_capstone_pwn_v1",
     "API 보안 캡스톤: BOLA + GraphQL + JWT 풀체인 장악", "API Security Capstone: Full Chain Exploitation",
     "BOLA 취약점으로 획득한 메타데이터와 GraphQL 스키마 인트로스펙션, JWT 서명 우회를 결합한 최종 엔드포인트 장악 챌린지입니다.\n지정된 식별자 `apisec_modern_auth_capstone_pwn_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"apisec_modern_auth_capstone_pwn_v1\") 앞 20자리}`",
     "Execute a full-chain kill scenario combining BOLA, GraphQL introspection, and forged JWTs.\nCompute the first 20 hex characters of SHA256(\"apisec_modern_auth_capstone_pwn_v1\").\n\nFormat: `FLAG{SHA256(\"apisec_modern_auth_capstone_pwn_v1\") first 20 hex}`",
     ["식별자 `apisec_modern_auth_capstone_pwn_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"apisec_modern_auth_capstone_pwn_v1\").", "Wrap in `FLAG{...}` format."]),
]


def make_flag_and_hash(identifier: str):
    h = hashlib.sha256(identifier.encode()).hexdigest()[:20]
    flag = f"FLAG{{{h}}}"
    flag_hash = hashlib.sha256(flag.encode()).hexdigest()
    return flag, flag_hash


def build_challenge_objects():
    chals = []
    ids = []
    for tier, cid, pts, ident, t_ko, t_en, p_ko, p_en, h_ko, h_en in CHALLENGES_SPEC:
        _, flag_hash = make_flag_and_hash(ident)
        chals.append({
            "id": cid,
            "tier": tier,
            "cat": "apisec",
            "track": "apisec",
            "points": pts,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {"ko": t_ko, "en": t_en},
            "prompt": {"ko": p_ko, "en": p_en},
            "hints": {"ko": h_ko, "en": h_en},
            "hash": flag_hash
        })
        ids.append(cid)
    return chals, ids


def main():
    chals, ids = build_challenge_objects()
    print(f"Generated {len(chals)} challenges for track 'apisec'")

    # 1. Update wargame/assets/challenges.js
    cjs_path = WG_DIR / "assets" / "challenges.js"
    cjs_text = cjs_path.read_text(encoding="utf-8")

    # Add track definition if not present
    if '"id": "apisec"' not in cjs_text:
        track_def = """,
  {
      "id": "apisec",
      "icon": "🌐",
      "ko": "API 보안·REST·GraphQL·JWT",
      "en": "API Security & Modern Auth",
      "desc_ko": "OWASP API Top 10·BOLA/IDOR·BFLA 권한 상승·GraphQL 인트로스펙션 및 배치 공격·JWT None 알고리즘·OAuth2 취약점.",
      "desc_en": "OWASP API Top 10, BOLA/IDOR, BFLA privilege escalation, GraphQL introspection & batching abuse, JWT None algorithm, OAuth2 flaws."
  }"""
        cjs_text = re.sub(r'(\{\s*"id":\s*"carcan"[\s\S]*?\n\s*\})', r'\1' + track_def, cjs_text)

    # Add challenges to CHALLENGES array
    if chals[0]["id"] not in cjs_text:
        chals_json = json.dumps(chals, ensure_ascii=False, indent=2)
        # Strip outer brackets and insert before the last ];
        inner = chals_json.strip()[1:-1].strip()
        last_bracket_idx = cjs_text.rfind('];')
        if last_bracket_idx != -1:
            cjs_text = cjs_text[:last_bracket_idx].rstrip() + ',\n' + inner + '\n];\n'

    cjs_path.write_text(cjs_text, encoding="utf-8")
    print("Updated wargame/assets/challenges.js")

    # 2. Update wargame/scripts/solve-derivable.js
    sd_path = WG_DIR / "scripts" / "solve-derivable.js"
    sd_text = sd_path.read_text(encoding="utf-8")
    if ids[0] not in sd_text:
        formatted_ids = ',\n  '.join(f'"{i}"' for i in ids)
        sd_text = sd_text.replace(
            '"t4_carcan_zero_trust_in_vehicle_ids"',
            f'"t4_carcan_zero_trust_in_vehicle_ids",\n  {formatted_ids}'
        )
        sd_path.write_text(sd_text, encoding="utf-8")
        print("Updated wargame/scripts/solve-derivable.js")

    # 3. Update wargame/index.html
    idx_path = WG_DIR / "index.html"
    idx_text = idx_path.read_text(encoding="utf-8")
    idx_text = re.sub(r'0/1225', '0/1260', idx_text)
    if 'data-track="apisec"' not in idx_text:
        idx_text = idx_text.replace(
            '<button class="track-btn" data-track="carcan" onclick="filterTrack(\'carcan\')">🚗 차량</button>',
            '<button class="track-btn" data-track="carcan" onclick="filterTrack(\'carcan\')">🚗 차량</button>\n      <button class="track-btn" data-track="apisec" onclick="filterTrack(\'apisec\')">🌐 API보안</button>'
        )
    idx_path.write_text(idx_text, encoding="utf-8")
    print("Updated wargame/index.html")

    # 4. Update wargame/README.md
    wgr_path = WG_DIR / "README.md"
    wgr_text = wgr_path.read_text(encoding="utf-8")
    wgr_text = wgr_text.replace("총 **1,225문제**", "총 **1,260문제**")
    wgr_text = wgr_text.replace("Total **1,225 challenges**", "Total **1,260 challenges**")

    # Tier table counts:
    # Tier 0: 70 -> 72
    # Tier 1: 210 -> 216
    # Tier 2: 420 -> 432
    # Tier 3: 350 -> 360
    # Tier 4: 175 -> 180
    wgr_text = re.sub(r'(\| `perimeter` \| 0 \(입문\) \| )70( \|)', r'\g<1>72\2', wgr_text)
    wgr_text = re.sub(r'(\| `webserver` \| 1 \(기초\) \| )210( \|)', r'\g<1>216\2', wgr_text)
    wgr_text = re.sub(r'(\| `internal` \| 2 \(중급\) \| )420( \|)', r'\g<1>432\2', wgr_text)
    wgr_text = re.sub(r'(\| `vault` \| 3 \(고급\) \| )350( \|)', r'\g<1>360\2', wgr_text)
    wgr_text = re.sub(r'(\| `core` \| 4 \(마스터\) \| )175( \|)', r'\g<1>180\2', wgr_text)

    # Add apisec track row to tracks table
    if '`apisec`' not in wgr_text:
        carcan_row = '| `carcan` | 🚗 차량 보안·CAN Bus·UDS | CAN 2.0 중재 ID·OBD-II PID 질의·UDS 진단 세션 및 펌웨어 플래싱·ISO-TP 흐름 제어·SecOC 인증 방어 | 35 |'
        apisec_row = '| `apisec` | 🌐 API 보안·REST·GraphQL·JWT | OWASP API Top 10·BOLA/IDOR·BFLA 권한 상승·GraphQL 인트로스펙션 및 배치 공격·JWT None 알고리즘·OAuth2 취약점 | 35 |'
        wgr_text = wgr_text.replace(carcan_row, carcan_row + '\n' + apisec_row)

    wgr_path.write_text(wgr_text, encoding="utf-8")
    print("Updated wargame/README.md")

    # 5. Update root docs
    root_docs = ['README.md', 'README.en.md', 'README.ja.md', 'README.zh.md', 'USAGE.md', 'AI_LEARNING.md']
    for doc in root_docs:
        dp = REPO_ROOT / doc
        if not dp.exists():
            continue
        dt = dp.read_text(encoding="utf-8")
        dt = dt.replace("1,225", "1,260")
        dt = dt.replace("1225", "1260")
        dp.write_text(dt, encoding="utf-8")
        print(f"Updated {doc} with 1,260 count")


if __name__ == "__main__":
    main()
