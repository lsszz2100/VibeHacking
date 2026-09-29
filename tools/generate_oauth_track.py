#!/usr/bin/env python3
"""
Generates the 45th Wargame Track: 'oauth' (OAuth 2.0 & OIDC SSO Exploitation - 35 Challenges)
Integrates cleanly into challenges.js, index.html, solve-derivable.js, and README.md.
"""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_JS = REPO_ROOT / "wargame" / "assets" / "challenges.js"
INDEX_HTML = REPO_ROOT / "wargame" / "index.html"
SOLVE_DERIVABLE_JS = REPO_ROOT / "wargame" / "scripts" / "solve-derivable.js"
WARGAME_README = REPO_ROOT / "wargame" / "README.md"
CLI_TEST = REPO_ROOT / "wargame" / "tests" / "test_cli.py"

TRACK_INFO = {
    "id": "oauth",
    "icon": "🔑",
    "ko": "OAuth 2.0·OIDC SSO 취약점",
    "en": "OAuth 2.0 & OIDC SSO Exploitation",
    "desc_ko": "OAuth 2.0 인가 코드 도청·Redirect URI 정규식 우회·PKCE S256 다운그레이드·JWT RS256/HS256 Key Confusion 및 SSO 계정 탈취.",
    "desc_en": "OAuth 2.0 authorization code interception, redirect URI regex bypass, PKCE S256 downgrade, JWT RS256/HS256 key confusion, and SSO account takeover."
}

RAW_CHALLENGES = [
    # Tier 0 (입문: 7 challenges, points 20~35)
    (0, "t0_oauth_rfc6749_roles", 25,
     "OAuth 2.0 프레임워크 4대 역할 및 인가 위임 모델",
     "OAuth 2.0 Framework Four Roles & Authorization Delegation Model",
     "OAuth 2.0(RFC 6749)에서 정의하는 4대 기본 역할(Resource Owner, Client, Authorization Server, Resource Server)과 토큰 기반 위임 모델을 분석합니다.\n지정된 식별자 `oauth_rfc6749_roles_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_rfc6749_roles_v1\") 앞 20자리}`",
     "Analyze the four core roles (Resource Owner, Client, Authorization Server, Resource Server) and token delegation model defined in RFC 6749.\nCompute the first 20 hex characters of SHA256(\"oauth_rfc6749_roles_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_rfc6749_roles_v1\") first 20 hex}`",
     ["RFC 6749 1.1 Roles 명세를 확인하세요.", "식별자 `oauth_rfc6749_roles_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review RFC 6749 1.1 Roles specification.", "Compute first 20 hex characters of SHA256(\"oauth_rfc6749_roles_v1\")."]),

    (0, "t0_oauth_grant_types", 25,
     "OAuth 2.0 핵심 Grant Types 인가 흐름 비교",
     "OAuth 2.0 Core Grant Types Comparison",
     "Authorization Code, Implicit, Resource Owner Password, Client Credentials 4개 기본 인가 방식의 보안 특성을 분석합니다.\n지정된 식별자 `oauth_grant_types_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_grant_types_v1\") 앞 20자리}`",
     "Compare security properties across the four fundamental OAuth 2.0 grant types.\nCompute the first 20 hex characters of SHA256(\"oauth_grant_types_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_grant_types_v1\") first 20 hex}`",
     ["Authorization Code Flow(front-channel -> back-channel) 보안 구조를 학습하세요.", "식별자 `oauth_grant_types_v1`의 해시 앞 20자리를 추출하세요."],
     ["Learn Authorization Code front-to-back channel architecture.", "Extract first 20 hex chars of SHA256(\"oauth_grant_types_v1\")."]),

    (0, "t0_oidc_core_idtoken", 30,
     "OpenID Connect Core 1.0 ID 토큰 구조 및 클레임",
     "OpenID Connect Core 1.0 ID Token Structure & Claims",
     "OAuth 2.0 기반의 인증 계층인 OIDC Core 1.0의 ID Token(JWT) 구조 및 필수 클레임(iss, sub, aud, exp, iat)을 분석합니다.\n지정된 식별자 `oidc_core_idtoken_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_core_idtoken_v1\") 앞 20자리}`",
     "Inspect OpenID Connect Core 1.0 identity layer atop OAuth 2.0 and standard ID Token JWT claims.\nCompute the first 20 hex characters of SHA256(\"oidc_core_idtoken_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_core_idtoken_v1\") first 20 hex}`",
     ["ID Token의 필수 클레임 규격을 검토하세요.", "식별자 `oidc_core_idtoken_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine mandatory ID Token claims in OIDC Core 1.0.", "Submit first 20 hex of SHA256(\"oidc_core_idtoken_v1\")."]),

    (0, "t0_oauth_redirect_uri_concept", 30,
     "Redirect URI 사전 등록 및 유효성 검증 원칙",
     "Redirect URI Pre-Registration & Validation Principles",
     "Authorization Server가 인가 응답을 전달하는 유일한 신뢰 통로인 redirect_uri의 화이트리스트 검증 원칙을 분석합니다.\n지정된 식별자 `oauth_redirect_uri_concept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_redirect_uri_concept_v1\") 앞 20자리}`",
     "Analyze strict whitelist validation requirements for redirect_uri transmitting authorization credentials.\nCompute the first 20 hex characters of SHA256(\"oauth_redirect_uri_concept_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_redirect_uri_concept_v1\") first 20 hex}`",
     ["정규식 부분 일치가 아닌 완전 일치(Exact Match) 검증의 중요성을 확인하세요.", "식별자 `oauth_redirect_uri_concept_v1`의 해시 앞 20자리를 제출하세요."],
     ["Understand the need for exact string matching over regex.", "Extract first 20 hex chars of SHA256(\"oauth_redirect_uri_concept_v1\")."]) ,

    (0, "t0_oauth_state_parameter", 30,
     "OAuth 2.0 State 파라미터와 CSRF 방어 메커니즘",
     "OAuth 2.0 State Parameter & CSRF Mitigation",
     "클라이언트 세션과 인가 요청을 암호학적으로 바인딩하여 CSRF를 차단하는 state 파라미터 구조를 분석합니다.\n지정된 식별자 `oauth_state_parameter_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_state_parameter_v1\") 앞 20자리}`",
     "Study the opaque cryptographically random state parameter binding authorization requests to browser sessions.\nCompute the first 20 hex characters of SHA256(\"oauth_state_parameter_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_state_parameter_v1\") first 20 hex}`",
     ["state 파라미터가 누락되면 타인의 계정이 희생자 세션에 바인딩될 수 있습니다.", "식별자 `oauth_state_parameter_v1`의 해시 앞 20자리를 추출하세요."],
     ["State prevents cross-site login CSRF.", "Submit first 20 hex of SHA256(\"oauth_state_parameter_v1\")."]),

    (0, "t0_oauth_pkce_rfc7636", 35,
     "PKCE (RFC 7636) 인가 코드 탈취 방어 아키텍처",
     "PKCE (RFC 7636) Authorization Code Defense Architecture",
     "모바일 및 SPA 등 공개 클라이언트에서 인가 코드 가로채기를 차단하는 Proof Key for Code Exchange 규격을 분석합니다.\n지정된 식별자 `oauth_pkce_rfc7636_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_pkce_rfc7636_v1\") 앞 20자리}`",
     "Analyze Proof Key for Code Exchange (RFC 7636) preventing authorization code interception on public clients.\nCompute the first 20 hex characters of SHA256(\"oauth_pkce_rfc7636_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_pkce_rfc7636_v1\") first 20 hex}`",
     ["code_verifier(고엔트로피 난수)와 code_challenge(SHA256)의 해시 약속 구조를 학습하세요.", "식별자 `oauth_pkce_rfc7636_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review S256 code challenge generation and validation.", "Extract first 20 hex chars of SHA256(\"oauth_pkce_rfc7636_v1\")."]),

    (0, "t0_oidc_discovery_jwks", 35,
     "OIDC Discovery 및 JWKS 공개키 메타데이터",
     "OIDC Discovery & JWKS Public Key Metadata",
     "/.well-known/openid-configuration 메타데이터와 /jwks.json 엔드포인트를 통한 IDP 공개키 배포 구조를 분석합니다.\n지정된 식별자 `oidc_discovery_jwks_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_discovery_jwks_v1\") 앞 20자리}`",
     "Examine OIDC Discovery endpoint metadata and JSON Web Key Set (JWKS) public key distribution.\nCompute the first 20 hex characters of SHA256(\"oidc_discovery_jwks_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_discovery_jwks_v1\") first 20 hex}`",
     ["jwks_uri, authorization_endpoint, token_endpoint 등의 표준 메타데이터를 확인하세요.", "식별자 `oidc_discovery_jwks_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect standard OpenID Connect configuration discovery keys.", "Submit first 20 hex of SHA256(\"oidc_discovery_jwks_v1\")."]),

    # Tier 1 (기초: 7 challenges, points 40~65)
    (1, "t1_oauth_redirect_subdomain_flaw", 45,
     "Redirect URI 서브도메인 정규식 누락 취약점",
     "Redirect URI Subdomain Regex Omission Vulnerability",
     "미흡한 정규식(`^https://client\\.example\\.com`)으로 인해 공격자 서브도메인(`client.example.com.attacker.com`)으로 인가 코드가 누출되는 취약점을 분석합니다.\n지정된 식별자 `oauth_redirect_subdomain_flaw_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_redirect_subdomain_flaw_v1\") 앞 20자리}`",
     "Exploit unanchored regex validations allowing attacker-controlled subdomains to receive authorization codes.\nCompute the first 20 hex characters of SHA256(\"oauth_redirect_subdomain_flaw_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_redirect_subdomain_flaw_v1\") first 20 hex}`",
     ["도메인 경계 문자(/ 또는 $) 누락 취약점을 분석하세요.", "식별자 `oauth_redirect_subdomain_flaw_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect regex domain boundary validation omissions.", "Extract first 20 hex chars of SHA256(\"oauth_redirect_subdomain_flaw_v1\")."]),

    (1, "t1_oauth_redirect_path_traversal", 45,
     "Redirect URI 경로 순회 및 오픈 리다이렉트 연계",
     "Redirect URI Path Traversal & Open Redirect Chaining",
     "정상 콜백 URL에 디렉터리 순회(`../`)를 결합하여 사이트 내 오픈 리다이렉트 경로로 인가 코드를 전달시키는 공격을 분석합니다.\n지정된 식별자 `oauth_redirect_path_traversal_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_redirect_path_traversal_v1\") 앞 20자리}`",
     "Chain path traversal sequences (`../`) within redirect_uri pointing to open redirectors to leak authorization codes.\nCompute the first 20 hex characters of SHA256(\"oauth_redirect_path_traversal_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_redirect_path_traversal_v1\") first 20 hex}`",
     ["/callback/../../logout?redirect=attacker.com 형태의 연계 체인을 학습하세요.", "식별자 `oauth_redirect_path_traversal_v1`의 해시 앞 20자리를 추출하세요."],
     ["Study chaining path normalization flaws with open redirectors.", "Submit first 20 hex of SHA256(\"oauth_redirect_path_traversal_v1\")."]),

    (1, "t1_oauth_redirect_param_pollution", 50,
     "HTTP 매개변수 오염(HPP) 기반 Redirect URI 조작",
     "HTTP Parameter Pollution (HPP) Redirect URI Tampering",
     "동일한 redirect_uri 파라미터를 복수 전송(HPP)하거나 특수문자 파싱 차이를 악용하여 검증을 우회하는 기법을 분석합니다.\n지정된 식별자 `oauth_redirect_param_pollution_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_redirect_param_pollution_v1\") 앞 20자리}`",
     "Bypass redirect URI checks by injecting duplicate query parameters (HPP) parsed differently across gateway and app.\nCompute the first 20 hex characters of SHA256(\"oauth_redirect_param_pollution_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_redirect_param_pollution_v1\") first 20 hex}`",
     ["파서 간 첫 번째 vs 마지막 파라미터 우선순위 차이를 점검하세요.", "식별자 `oauth_redirect_param_pollution_v1`의 해시 앞 20자리를 제출하세요."],
     ["Analyze parser discrepancy in duplicate query parameter handling.", "Extract first 20 hex chars of SHA256(\"oauth_redirect_param_pollution_v1\")."]),

    (1, "t1_oauth_csrf_state_omission", 55,
     "State 파라미터 부재에 따른 로그인 CSRF 계정 탈취",
     "Missing State Parameter Login CSRF Account Takeover",
     "state 파라미터가 없거나 고정되어 공격자의 인가 코드를 피해자 브라우저에 강제 주입하여 계정을 연동시키는 CSRF 공격을 분석합니다.\n지정된 식별자 `oauth_csrf_state_omission_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_csrf_state_omission_v1\") 앞 20자리}`",
     "Perform Login CSRF injecting attacker authorization codes into victim browser sessions lacking state parameter binding.\nCompute the first 20 hex characters of SHA256(\"oauth_csrf_state_omission_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_csrf_state_omission_v1\") first 20 hex}`",
     ["희생자가 결제나 개인정보를 등록하면 공격자 계정에 귀속되는 위협을 분석하세요.", "식별자 `oauth_csrf_state_omission_v1`의 해시 앞 20자리를 추출하세요."],
     ["Understand victim data binding to attacker profile on login CSRF.", "Submit first 20 hex of SHA256(\"oauth_csrf_state_omission_v1\")."]),

    (1, "t1_oauth_token_leak_referrer", 55,
     "Implicit 흐름 URL 프래그먼트 및 Referer 토큰 누출",
     "Implicit Flow URL Fragment & Referer Token Leakage",
     "Implicit Grant(`response_type=token`) 사용 시 URI 프래그먼트(#access_token)가 서드파티 스크립트나 Referer 헤더로 노출되는 취약점을 분석합니다.\n지정된 식별자 `oauth_token_leak_referrer_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_token_leak_referrer_v1\") 앞 20자리}`",
     "Analyze access token leakage via Referer request headers and third-party scripts during Implicit Flow fragment transmission.\nCompute the first 20 hex characters of SHA256(\"oauth_token_leak_referrer_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_token_leak_referrer_v1\") first 20 hex}`",
     ["OAuth 2.1에서 Implicit Flow가 완전히 폐기(deprecated)된 이유를 학습하세요.", "식별자 `oauth_token_leak_referrer_v1`의 해시 앞 20자리를 제출하세요."],
     ["Learn why OAuth 2.1 strictly deprecates the Implicit Grant.", "Extract first 20 hex chars of SHA256(\"oauth_token_leak_referrer_v1\")."]),

    (1, "t1_oauth_scope_escalation", 60,
     "OAuth 스코프 동의 우회 및 비인가 권한 상승",
     "OAuth Scope Consent Bypass & Privilege Escalation",
     "사용자 동의 화면에 표시되지 않은 관리자 스코프(`scope=admin write`)를 강제 삽입하여 발급받는 인가 취약점을 분석합니다.\n지정된 식별자 `oauth_scope_escalation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_scope_escalation_v1\") 앞 20자리}`",
     "Exploit authorization servers granting high-privilege scopes (scope=admin) omitted from user consent prompts.\nCompute the first 20 hex characters of SHA256(\"oauth_scope_escalation_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_scope_escalation_v1\") first 20 hex}`", ["토큰 엔드포인트의 스코프 재검증 결함을 확인하세요.", "식별자 `oauth_scope_escalation_v1`의 해시 앞 20자리를 추출하세요."],
     ["Check token endpoint scope re-validation deficiencies.", "Submit first 20 hex of SHA256(\"oauth_scope_escalation_v1\")."]),

    (1, "t1_oidc_jwt_none_alg", 65,
     "OIDC ID 토큰 서명 미검증 (alg: none) 서명 위조",
     "OIDC ID Token Unsigned (alg: none) Signature Bypass",
     "OIDC 서명 검증 라이브러리의 취약점으로 인해 `alg: none` 헤더를 가진 위조 ID Token이 무조건 신뢰되는 결함을 분석합니다.\n지정된 식별자 `oidc_jwt_none_alg_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_jwt_none_alg_v1\") 앞 20자리}`",
     "Bypass OIDC identity verification by forging arbitrary admin claims inside ID Tokens with `alg: none` header.\nCompute the first 20 hex characters of SHA256(\"oidc_jwt_none_alg_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_jwt_none_alg_v1\") first 20 hex}`",
     ["빈 서명부(`header.payload.`)를 파싱하는 검증 라이브러리 결함을 분석하세요.", "식별자 `oidc_jwt_none_alg_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect token parser flaws accepting empty signature segments.", "Extract first 20 hex chars of SHA256(\"oidc_jwt_none_alg_v1\")."]),

    # Tier 2 (중급: 7 challenges, points 75~120)
    (2, "t2_oauth_pkce_downgrade_plain", 80,
     "PKCE S256에서 plain 방식 강제 다운그레이드 공격",
     "PKCE S256 to plain Method Downgrade Attack",
     "클라이언트가 S256을 요청하더라도 서버가 하위 호환성을 이유로 `code_challenge_method=plain`을 허용할 때 발생하는 다운그레이드 취약점을 분석합니다.\n지정된 식별자 `oauth_pkce_downgrade_plain_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_pkce_downgrade_plain_v1\") 앞 20자리}`",
     "Force PKCE downgrade to `plain` method on vulnerable servers to bypass cryptographic challenge hashes.\nCompute the first 20 hex characters of SHA256(\"oauth_pkce_downgrade_plain_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_pkce_downgrade_plain_v1\") first 20 hex}`",
     ["RFC 7636에서 plain 방식이 금지되거나 엄격히 제한되어야 하는 이유를 학습하세요.", "식별자 `oauth_pkce_downgrade_plain_v1`의 해시 앞 20자리를 추출하세요."],
     ["Understand strict requirement for S256 code challenge method.", "Submit first 20 hex of SHA256(\"oauth_pkce_downgrade_plain_v1\")."]),

    (2, "t2_oauth_pkce_omission_bypass", 85,
     "PKCE 검증 인자 생략을 통한 인가 코드 탈취 주입",
     "PKCE Verification Argument Omission Attack",
     "인가 엔드포인트에서 생성된 code_challenge를 토큰 엔드포인트 교환 시 code_verifier 파라미터 없이도 성공시키는 서버 로직 결함을 분석합니다.\n지정된 식별자 `oauth_pkce_omission_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_pkce_omission_bypass_v1\") 앞 20자리}`",
     "Exploit server logic flaw treating missing `code_verifier` parameters as legacy clients and bypassing validation.\nCompute the first 20 hex characters of SHA256(\"oauth_pkce_omission_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_pkce_omission_bypass_v1\") first 20 hex}`",
     ["code_challenge가 바인딩된 인가 코드는 code_verifier 없이 절대 교환될 수 없어야 합니다.", "식별자 `oauth_pkce_omission_bypass_v1`의 해시 앞 20자리를 제출하세요."],
     ["Enforce mandatory verifier matching when challenge was registered.", "Extract first 20 hex chars of SHA256(\"oauth_pkce_omission_bypass_v1\")."]),

    (2, "t2_oauth_key_confusion_rs256_hs256", 90,
     "JWT RS256 공개키를 HS256 비밀키로 오인하는 키 혼동 공격",
     "JWT RS256 Public Key to HS256 Secret Key Confusion",
     "서버의 RS256 RSA 공개키(PEM)를 HMAC-SHA256의 대칭 비밀키로 악용하여 임의의 관리자 ID 토큰을 위조하는 Key Confusion 취약점을 분석합니다.\n지정된 식별자 `oauth_key_confusion_rs256_hs256_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_key_confusion_rs256_hs256_v1\") 앞 20자리}`",
     "Forge administrator ID Tokens by abusing the RS256 public key PEM string as an HMAC-SHA256 symmetric secret key.\nCompute the first 20 hex characters of SHA256(\"oauth_key_confusion_rs256_hs256_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_key_confusion_rs256_hs256_v1\") first 20 hex}`",
     ["공개키 문자열 전체를 바이너리 바이트로 변환하여 HS256 서명을 생성하는 기법을 학습하세요.", "식별자 `oauth_key_confusion_rs256_hs256_v1`의 해시 앞 20자리를 추출하세요."],
     ["Learn signing with public key bytes as HMAC secret key.", "Submit first 20 hex of SHA256(\"oauth_key_confusion_rs256_hs256_v1\")."]),

    (2, "t2_oidc_kid_header_injection", 95,
     "JWT Key ID (kid) 헤더 조작 및 디렉터리 순회 공격",
     "JWT Key ID (kid) Header Manipulation & Path Traversal",
     "JWT 헤더의 kid 파라미터에 디렉터리 순회(`/dev/null` 또는 알려진 고정 파일)를 삽입하여 빈 키로 서명을 위조하는 공격을 분석합니다.\n지정된 식별자 `oidc_kid_header_injection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_kid_header_injection_v1\") 앞 20자리}`",
     "Inject path traversal payloads (`../../../../dev/null`) into the JWT `kid` header to verify signatures against empty keys.\nCompute the first 20 hex characters of SHA256(\"oidc_kid_header_injection_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_kid_header_injection_v1\") first 20 hex}`",
     ["kid 파라미터가 데이터베이스 조회나 파일 시스템 경로에 직접 연결될 때의 위험을 분석하세요.", "식별자 `oidc_kid_header_injection_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect filesystem and SQL injection hazards in kid handling.", "Extract first 20 hex chars of SHA256(\"oidc_kid_header_injection_v1\")."]),

    (2, "t2_oidc_jku_spoofing", 100,
     "JWK Set URL (jku) 헤더 스푸핑 및 악성 공개키 주입",
     "JWK Set URL (jku) Header Spoofing & Malicious JWKS",
     "JWT 헤더의 jku(JWK Set URL)를 공격자가 제어하는 외부 서버로 변경하여 임의의 개인키로 서명된 토큰을 검증시키는 취약점을 분석합니다.\n지정된 식별자 `oidc_jku_spoofing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_jku_spoofing_v1\") 앞 20자리}`",
     "Spoof the `jku` header parameter pointing to an attacker-controlled JWKS to authenticate self-signed forged tokens.\nCompute the first 20 hex characters of SHA256(\"oidc_jku_spoofing_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_jku_spoofing_v1\") first 20 hex}`",
     ["jku 도메인 화이트리스트 검증 부재가 초래하는 위협을 분석하세요.", "식별자 `oidc_jku_spoofing_v1`의 해시 앞 20자리를 추출하세요."],
     ["Enforce strict domain whitelist checks for jku endpoints.", "Submit first 20 hex of SHA256(\"oidc_jku_spoofing_v1\")."]),

    (2, "t2_oauth_code_replay_attack", 110,
     "인가 코드 일회용 무결성 결함 및 다중 교환 공격",
     "Authorization Code One-Time Use Flaw & Multiple Exchange",
     "발급된 인가 코드(Authorization Code)가 사용 즉시 무효화되지 않아 네트워크 스니핑이나 로그를 통해 다중 토큰을 교환하는 공격을 분석합니다.\n지정된 식별자 `oauth_code_replay_attack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_code_replay_attack_v1\") 앞 20자리}`",
     "Exploit authorization servers failing to invalidate authorization codes immediately upon first exchange.\nCompute the first 20 hex characters of SHA256(\"oauth_code_replay_attack_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_code_replay_attack_v1\") first 20 hex}`",
     ["RFC 6749 4.1.2 규격의 일회용 인가 코드 폐기 원칙을 확인하세요.", "식별자 `oauth_code_replay_attack_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review RFC 6749 requirements for immediate one-time code revocation.", "Extract first 20 hex chars of SHA256(\"oauth_code_replay_attack_v1\")."]),

    (2, "t2_oauth_implicit_account_takeover", 120,
     "모바일 Custom URL Scheme 하이재킹 및 토큰 가로채기",
     "Mobile Custom URL Scheme Hijacking & Token Interception",
     "모바일 앱에 등록된 동일한 커스텀 URL 스킴(myapp://oauth)을 악성 앱이 가로채어 Implicit 토큰을 탈취하는 취약점을 분석합니다.\n지정된 식별자 `oauth_implicit_account_takeover_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_implicit_account_takeover_v1\") 앞 20자리}`",
     "Hijack custom mobile URL schemes (e.g. `myapp://oauth`) to intercept access tokens returned via Implicit flow.\nCompute the first 20 hex characters of SHA256(\"oauth_implicit_account_takeover_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_implicit_account_takeover_v1\") first 20 hex}`",
     ["Android App Links 및 iOS Universal Links를 통한 도메인 소유권 증명 방어를 학습하세요.", "식별자 `oauth_implicit_account_takeover_v1`의 해시 앞 20자리를 추출하세요."],
     ["Learn App Links and Universal Links cryptographically bound to web domains.", "Submit first 20 hex of SHA256(\"oauth_implicit_account_takeover_v1\")."]),

    # Tier 3 (고급: 7 challenges, points 140~220)
    (3, "t3_oauth_ssrf_token_endpoint", 150,
     "OIDC 백엔드 토큰 교환 엔드포인트 SSRF 공격",
     "OIDC Backend Token Endpoint SSRF Exploitation",
     "클라이언트 백엔드가 토큰 교환을 수행할 때 공격자가 제공한 악성 토큰 엔드포인트 URL을 신뢰하여 내부망으로 요청을 전송하는 SSRF를 분석합니다.\n지정된 식별자 `oauth_ssrf_token_endpoint_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_ssrf_token_endpoint_v1\") 앞 20자리}`",
     "Exploit server-side token exchange routines trusting dynamic or untrusted token endpoints to achieve SSRF.\nCompute the first 20 hex characters of SHA256(\"oauth_ssrf_token_endpoint_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_ssrf_token_endpoint_v1\") first 20 hex}`",
     ["내부 클라우드 메타데이터(169.254.169.254) 또는 인트라넷 서비스 접근 위험을 점검하세요.", "식별자 `oauth_ssrf_token_endpoint_v1`의 해시 앞 20자리를 제출하세요."],
     ["Analyze token exchange requests pivoting to internal cloud metadata.", "Extract first 20 hex chars of SHA256(\"oauth_ssrf_token_endpoint_v1\")."]),

    (3, "t3_oidc_dynamic_client_registration", 160,
     "RFC 7591 동적 클라이언트 등록(DCR) 비인가 악용",
     "RFC 7591 Dynamic Client Registration (DCR) Abuse",
     "인증 없이 개방된 RFC 7591 DCR 엔드포인트를 통해 악성 redirect_uri를 가진 신규 클라이언트를 등록하여 자격증명을 탈취하는 기법을 분석합니다.\n지정된 식별자 `oidc_dynamic_client_registration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_dynamic_client_registration_v1\") 앞 20자리}`",
     "Abuse unauthenticated RFC 7591 Dynamic Client Registration to register rogue clients with arbitrary redirect URIs.\nCompute the first 20 hex characters of SHA256(\"oidc_dynamic_client_registration_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_dynamic_client_registration_v1\") first 20 hex}`",
     ["DCR 엔드포인트에 초기 등록 토큰(Initial Access Token)을 강제해야 하는 보안 요건을 학습하세요.", "식별자 `oidc_dynamic_client_registration_v1`의 해시 앞 20자리를 추출하세요."],
     ["Require Initial Access Tokens for dynamic client registration.", "Submit first 20 hex of SHA256(\"oidc_dynamic_client_registration_v1\")."]),

    (3, "t3_oauth_cross_client_impersonation", 170,
     "동일 IdP 환경 다중 클라이언트 간 Audience 치환 공격",
     "Cross-Client Impersonation via Missing Audience Validation",
     "동일한 IDP를 공유하는 다중 서비스에서 서비스 A용으로 발급된 ID 토큰을 서비스 B에 제출할 때 aud 클레임을 검증하지 않아 발생하는 계정 가장을 분석합니다.\n지정된 식별자 `oauth_cross_client_impersonation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_cross_client_impersonation_v1\") 앞 20자리}`",
     "Impersonate users across clients sharing the same IdP when receiving services fail to validate token `aud` claims.\nCompute the first 20 hex characters of SHA256(\"oauth_cross_client_impersonation_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_cross_client_impersonation_v1\") first 20 hex}`",
     ["ID Token의 aud(Audience) 값이 수신 클라이언트 ID와 정확히 일치해야 함을 검증하세요.", "식별자 `oauth_cross_client_impersonation_v1`의 해시 앞 20자리를 제출하세요."],
     ["Validate that token aud strictly matches recipient client_id.", "Extract first 20 hex chars of SHA256(\"oauth_cross_client_impersonation_v1\")."]),

    (3, "t3_oidc_userinfo_injection", 180,
     "UserInfo 응답 조작을 통한 계정 선점 탈취 (Pre-ATO)",
     "UserInfo Response Tampering Pre-Account Takeover",
     "OIDC UserInfo 엔드포인트 응답에서 이메일 인증 여부(`email_verified: true`)를 미검증한 채 계정을 연동시켜 희생자 계정을 선점하는 취약점을 분석합니다.\n지정된 식별자 `oidc_userinfo_injection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_userinfo_injection_v1\") 앞 20자리}`",
     "Pre-hijack victim accounts by exploiting reliance on unverified email claims in UserInfo endpoint responses.\nCompute the first 20 hex characters of SHA256(\"oidc_userinfo_injection_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_userinfo_injection_v1\") first 20 hex}`",
     ["미인증 이메일을 통한 자동 계정 병합(Account Linking) 취약점 패턴을 분석하세요.", "식별자 `oidc_userinfo_injection_v1`의 해시 앞 20자리를 추출하세요."],
     ["Study dangerous automatic account merging on unverified emails.", "Submit first 20 hex of SHA256(\"oidc_userinfo_injection_v1\")."]),

    (3, "t3_oauth_dpop_proof_tampering", 190,
     "RFC 9449 DPoP 키 소유 증명 서명 위조 및 HTTP 메서드 불일치",
     "RFC 9449 DPoP Proof Tampering & HTTP Method Mismatch",
     "Bearer 토큰 도난을 방지하는 DPoP(Demonstrating Proof of Possession) 증명 JWT의 `htm`/`htu` 클레임 검증 결함을 파고드는 공격을 분석합니다.\n지정된 식별자 `oauth_dpop_proof_tampering_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_dpop_proof_tampering_v1\") 앞 20자리}`",
     "Tamper with RFC 9449 DPoP proof JWTs by exploiting loose validation of `htm` (HTTP method) and `htu` (HTTP URI).\nCompute the first 20 hex characters of SHA256(\"oauth_dpop_proof_tampering_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_dpop_proof_tampering_v1\") first 20 hex}`",
     ["DPoP 증명 토큰의 재사용 방지(jti 클레임 및 시간 윈도우) 검증을 학습하세요.", "식별자 `oauth_dpop_proof_tampering_v1`의 해시 앞 20자리를 제출하세요."],
     ["Examine DPoP proof jti replay cache and time window validation.", "Extract first 20 hex chars of SHA256(\"oauth_dpop_proof_tampering_v1\")."]),

    (3, "t3_oauth_jwt_embedded_x5c", 200,
     "JWT x5c 헤더 자체 서명 인증서 주입 공격",
     "JWT x5c Header Self-Signed Certificate Injection",
     "JWT 헤더의 x5c(X.509 Certificate Chain) 필드에 공격자가 생성한 자체 서명 인증서를 주입하여 신뢰 체인을 위조하는 취약점을 분석합니다.\n지정된 식별자 `oauth_jwt_embedded_x5c_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_jwt_embedded_x5c_v1\") 앞 20자리}`",
     "Inject attacker self-signed X.509 certificate chains into the JWT `x5c` header when servers fail to verify CA trust.\nCompute the first 20 hex characters of SHA256(\"oauth_jwt_embedded_x5c_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_jwt_embedded_x5c_v1\") first 20 hex}`",
     ["x5c 인증서가 신뢰할 수 있는 루트 CA에 도달하는지 경로 검증을 수행해야 합니다.", "식별자 `oauth_jwt_embedded_x5c_v1`의 해시 앞 20자리를 추출하세요."],
     ["Validate full PKI trust chain anchoring for embedded x5c certificates.", "Submit first 20 hex of SHA256(\"oauth_jwt_embedded_x5c_v1\")."]),

    (3, "t3_oauth_saml_oauth_bridge_flaw", 210,
     "SAML-OAuth 연합 브릿지 NameID 식별자 매핑 결함",
     "SAML-OAuth Federation Bridge NameID Mapping Flaw",
     "엔터프라이즈 SAML 2.0 단언을 OAuth/OIDC 토큰으로 변환하는 브릿지에서 NameID 서식 불일치를 이용한 관리자 계정 하이재킹을 분석합니다.\n지정된 식별자 `oauth_saml_oauth_bridge_flaw_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_saml_oauth_bridge_flaw_v1\") 앞 20자리}`",
     "Exploit enterprise SAML-to-OAuth federation bridges with inconsistent NameID canonicalization to hijack administrator identities.\nCompute the first 20 hex characters of SHA256(\"oauth_saml_oauth_bridge_flaw_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_saml_oauth_bridge_flaw_v1\") first 20 hex}`",
     ["SAML NameID와 OIDC sub 클레임의 정규화 매핑 무결성을 학습하세요.", "식별자 `oauth_saml_oauth_bridge_flaw_v1`의 해시 앞 20자리를 제출하세요."],
     ["Audit SAML assertion claim translation into OIDC sub claims.", "Extract first 20 hex chars of SHA256(\"oauth_saml_oauth_bridge_flaw_v1\")."]),

    # Tier 4 (최상위/엔터프라이즈: 7 challenges, points 250~500)
    (4, "t4_oauth_enterprise_sso_chain", 280,
     "엔터프라이즈 SSO 취약점 연쇄 침투 및 전사 도메인 장악",
     "Enterprise SSO Multi-Stage Vulnerability Chain Exploitation",
     "Redirect URI 우회, 인가 코드 가로채기, PKCE 무력화 및 ID 토큰 위조를 결합한 전사적 SSO 계정 장악 침투 체인을 분석합니다.\n지정된 식별자 `oauth_enterprise_sso_chain_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_enterprise_sso_chain_v1\") 앞 20자리}`",
     "Execute end-to-end SSO compromise chaining redirect URI bypass, authorization code theft, PKCE bypass, and token forgery.\nCompute the first 20 hex characters of SHA256(\"oauth_enterprise_sso_chain_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_enterprise_sso_chain_v1\") first 20 hex}`",
     ["프론트채널 누출과 백엔드 토큰 파싱 결함이 결합될 때 발생하는 파급력을 분석하세요.", "식별자 `oauth_enterprise_sso_chain_v1`의 해시 앞 20자리를 추출하세요."],
     ["Synthesize multi-layer SSO exploitation vectors across cloud apps.", "Submit first 20 hex of SHA256(\"oauth_enterprise_sso_chain_v1\")."]),

    (4, "t4_oidc_hybrid_flow_c_hash_forgery", 320,
     "OIDC Hybrid Flow c_hash 및 at_hash 무결성 검증 결함",
     "OIDC Hybrid Flow c_hash & at_hash Validation Failure",
     "ID 토큰과 인가 코드가 동시 전달되는 Hybrid Flow에서 c_hash(코드 해시) 검증 부재로 인한 중간자 코드 주입 공격을 분석합니다.\n지정된 식별자 `oidc_hybrid_flow_c_hash_forgery_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_hybrid_flow_c_hash_forgery_v1\") 앞 20자리}`",
     "Exploit missing c_hash and at_hash validations in OIDC Hybrid Flow responses to inject arbitrary authorization codes.\nCompute the first 20 hex characters of SHA256(\"oidc_hybrid_flow_c_hash_forgery_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_hybrid_flow_c_hash_forgery_v1\") first 20 hex}`",
     ["c_hash가 ID 토큰 서명 알고리즘 해시의 좌측 절반(ASCII)을 나타내는 규격을 검증하세요.", "식별자 `oidc_hybrid_flow_c_hash_forgery_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify c_hash calculations matching left-most half of hash output.", "Extract first 20 hex chars of SHA256(\"oidc_hybrid_flow_c_hash_forgery_v1\")."]),

    (4, "t4_oauth_mtls_sender_constrained_bypass", 360,
     "RFC 8705 mTLS 클라이언트 인증 및 Sender-Constrained 바인딩 우회",
     "RFC 8705 mTLS Client Authentication & Sender-Constrained Bypass",
     "토큰을 클라이언트 TLS 인증서(x5t#S256)에 영구 결합하는 RFC 8705 mTLS 바인딩의 리버스 프록시 헤더 스푸핑 공격을 분석합니다.\n지정된 식별자 `oauth_mtls_sender_constrained_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_mtls_sender_constrained_bypass_v1\") 앞 20자리}`",
     "Bypass RFC 8705 mutual TLS sender-constrained token protections by spoofing client certificate headers at reverse proxies.\nCompute the first 20 hex characters of SHA256(\"oauth_mtls_sender_constrained_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_mtls_sender_constrained_bypass_v1\") first 20 hex}`",
     ["X-Forwarded-Client-Cert(XFCC) 헤더 살균 부재 결함을 분석하세요.", "식별자 `oauth_mtls_sender_constrained_bypass_v1`의 해시 앞 20자리를 추출하세요."],
     ["Audit reverse proxy sanitation of client certificate forwarded headers.", "Submit first 20 hex of SHA256(\"oauth_mtls_sender_constrained_bypass_v1\")."]),

    (4, "t4_oidc_rar_rich_authorization_abuse", 400,
     "RFC 9396 Rich Authorization Requests (RAR) 구조화 파라미터 변조",
     "RFC 9396 Rich Authorization Requests (RAR) Parameter Tampering",
     "복잡한 금융 거래 및 권한 세부사항을 JSON 객체(`authorization_details`)로 전달하는 RAR 사양의 역직렬화 및 권한 조작을 분석합니다.\n지정된 식별자 `oidc_rar_rich_authorization_abuse_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oidc_rar_rich_authorization_abuse_v1\") 앞 20자리}`",
     "Tamper with JSON structured `authorization_details` under RFC 9396 to manipulate transaction authorization limits.\nCompute the first 20 hex characters of SHA256(\"oidc_rar_rich_authorization_abuse_v1\").\n\nFormat: `FLAG{SHA256(\"oidc_rar_rich_authorization_abuse_v1\") first 20 hex}`",
     ["JAR(RFC 9101 JWT-Secured Authorization Request) 서명 강제의 필요성을 분석하세요.", "식별자 `oidc_rar_rich_authorization_abuse_v1`의 해시 앞 20자리를 제출하세요."],
     ["Enforce JWT-Secured Authorization Request (JAR) integrity on RAR.", "Extract first 20 hex chars of SHA256(\"oidc_rar_rich_authorization_abuse_v1\")."]),

    (4, "t4_oauth_fapi_advanced_security_audit", 430,
     "Financial-grade API (FAPI 2.0) 고급 보안 프로파일 종합 감사",
     "Financial-grade API (FAPI 2.0) Advanced Security Profile Audit",
     "글로벌 오픈뱅킹 표준인 FAPI 2.0 Security Profile에서 요구하는 PKCE 필수, mTLS/DPoP 발신자 바인딩, PAR(Pushed Authorization Requests) 규격을 검증합니다.\n지정된 식별자 `oauth_fapi_advanced_security_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_fapi_advanced_security_audit_v1\") 앞 20자리}`",
     "Audit compliance against FAPI 2.0 Security Profile mandating PKCE S256, sender-constrained tokens, and PAR (RFC 9126).\nCompute the first 20 hex characters of SHA256(\"oauth_fapi_advanced_security_audit_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_fapi_advanced_security_audit_v1\") first 20 hex}`",
     ["프론트채널 쿼리 스트링 노출을 방지하는 PAR(RFC 9126)의 작동 원리를 확인하세요.", "식별자 `oauth_fapi_advanced_security_audit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review Pushed Authorization Requests (PAR) eliminating front-channel leaks.", "Submit first 20 hex of SHA256(\"oauth_fapi_advanced_security_audit_v1\")."]),

    (4, "t4_oauth_zero_trust_sso_hardening", 460,
     "지속적 접근 평가(CAEP/SSE) 및 제로 트러스트 SSO 방어",
     "Continuous Access Evaluation (CAEP/SSE) & Zero Trust SSO Hardening",
     "사용자 위험 감지 및 세션 폐기를 실시간 동기화하는 RFC Shared Signals & Events (SSE) 기반 제로 트러스트 토큰 라이프사이클을 분석합니다.\n지정된 식별자 `oauth_zero_trust_sso_hardening_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_zero_trust_sso_hardening_v1\") 앞 20자리}`",
     "Model Continuous Access Evaluation Protocol (CAEP) real-time session revocation under Zero Trust SSO architectures.\nCompute the first 20 hex characters of SHA256(\"oauth_zero_trust_sso_hardening_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_zero_trust_sso_hardening_v1\") first 20 hex}`",
     ["CAEP 세션 해지 신호 수신 시 리소스 서버의 토큰 즉시 무효화 절차를 학습하세요.", "식별자 `oauth_zero_trust_sso_hardening_v1`의 해시 앞 20자리를 제출하세요."],
     ["Implement real-time token revocation upon credential compromise alerts.", "Extract first 20 hex chars of SHA256(\"oauth_zero_trust_sso_hardening_v1\")."]),

    (4, "t4_oauth_capstone_sso_exploitation_audit", 500,
     "전사적 OAuth 2.0·OIDC SSO 보안 침투 및 종합 감사 캡스톤",
     "Enterprise OAuth 2.0 & OIDC SSO Security Audit Capstone",
     "리다이렉트 우회, PKCE 다운그레이드, 서명 위조, 발신자 바인딩 우회 등 엔터프라이즈 SSO 취약점 침투 체인을 총괄하고 하드닝을 완성하는 종합 캡스톤입니다.\n지정된 식별자 `oauth_capstone_sso_exploitation_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"oauth_capstone_sso_exploitation_audit_v1\") 앞 20자리}`",
     "Capstone challenge synthesizing end-to-end OAuth 2.0 & OIDC exploitation, audit methodology, and enterprise Zero Trust defense.\nCompute the first 20 hex characters of SHA256(\"oauth_capstone_sso_exploitation_audit_v1\").\n\nFormat: `FLAG{SHA256(\"oauth_capstone_sso_exploitation_audit_v1\") first 20 hex}`",
     ["사전 등록 완전 일치 검증, S256 강제, RS256 전용 검증, DPoP 바인딩 등 4대 방어선을 확립하세요.", "식별자 `oauth_capstone_sso_exploitation_audit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Establish full four-pillar defense: exact match, mandatory S256, strict RS256, DPoP binding.", "Submit first 20 hex of SHA256(\"oauth_capstone_sso_exploitation_audit_v1\")."])
]

# Topic rows to add to wargame/README.md for each tier table
TIER_TOPIC_ROWS = {
    0: '| `oauth` 🔑 OAuth 2.0·OIDC SSO 취약점 (7) | 인가 프레임워크 4대 역할 분석·권한 부여 인가 코드 방식 비교·아이디 토큰 클레임 명세·리다이렉션 경로 검증 원칙·무작위 세션 연동 상태값 메커니즘·코드챌린지 인가 확장 규격·메타데이터 검색 및 공개키 세트 엔드포인트 / authorization framework four roles analysis, grant type authorization code comparison, identity token claim specifications, redirection destination validation principles, random session binding state value mechanism, code challenge authorization extension, metadata discovery and public key set endpoints |',
    1: '| `oauth` 🔑 OAuth 2.0·OIDC SSO 취약점 (7) | 서브도메인 정규식 패턴 우회·디렉터리 순회 리다이렉트 탈취·매개변수 오염 특수문자 조작·상태값 누락 인가 코드 주입 공격·단편 식별자 토큰 유출·동의 화면 과도한 범위 요청·서명 미검증 알고리즘 공격 / subdomain regex pattern bypass, directory traversal redirect hijacking, parameter pollution special character tampering, missing state parameter code injection, fragment identifier token leakage, consent screen excessive scope request, unsigned token algorithm attack |',
    2: '| `oauth` 🔑 OAuth 2.0·OIDC SSO 취약점 (7) | 코드챌린지 평문 방식 다운그레이드·검증 인자 생략 공격·비대칭 공개키 대칭키 오인 서명 위조·키 식별자 헤더 경로 조작·공개키 세트 웹주소 스푸핑·인가 코드 다중 교환 재전송·모바일 커스텀 스킴 가로채기 / code challenge plain method downgrade, verification argument omission attack, asymmetric public key symmetric confusion forgery, key identifier header path manipulation, public key set web address spoofing, authorization code multiple exchange retransmission, mobile custom scheme interception |',
    3: '| `oauth` 🔑 OAuth 2.0·OIDC SSO 취약점 (7) | 토큰 발급 엔드포인트 서버측 요청 위조·동적 클라이언트 등록 악용·클라이언트 간 대상자 미검증 가장·사용자 정보 조작 계정 선점 탈취·발신자 소유 증명 서명 조작·내장 인증서 체인 주입 공격·연합 인증 브릿지 식별자 매핑 오류 / token endpoint server side request forgery, dynamic client registration abuse, cross client audience missing validation impersonation, userinfo tampering pre account takeover, sender proof of possession tampering, embedded certificate chain injection, federation bridge identifier mapping flaw |',
    4: '| `oauth` 🔑 OAuth 2.0·OIDC SSO 취약점 (7) | 전사 단일 로그인 체인 완전 장악·혼합 흐름 해시 검증 결함 공격·상호 전송 계층 보안 발신자 바인딩 우회·풍부한 인가 요청 파라미터 변조·금융 등급 고보안 규격 감사·지속적 평가 제로 트러스트 하드닝·엔터프라이즈 싱글 사인온 침투 캡스톤 / enterprise single sign on chain total takeover, hybrid flow hash validation flaw, mutual tls sender constrained binding bypass, rich authorization requests parameter tampering, financial grade high security specification audit, continuous assessment zero trust hardening, enterprise single sign on penetration capstone |'
}


def build_challenges():
    challenges = []
    ids = []
    for tier, cid, pts, t_ko, t_en, p_ko, p_en, h_ko, h_en in RAW_CHALLENGES:
        m = re.search(r'SHA256\("([^"]+)"\)', p_ko)
        if not m:
            raise ValueError(f"Seed not found in prompt for {cid}")
        seed = m.group(1)
        flag_val = f"FLAG{{{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:20]}}}"
        h = hashlib.sha256(flag_val.encode('utf-8')).hexdigest()

        chal = {
            "id": cid,
            "tier": tier,
            "cat": "oauth",
            "track": "oauth",
            "points": pts,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {"ko": t_ko, "en": t_en},
            "prompt": {"ko": p_ko, "en": p_en},
            "hints": {"ko": h_ko, "en": h_en},
            "hash": h
        }
        challenges.append(chal)
        ids.append(cid)
    return challenges, ids


def main():
    print("[*] Generating 35 OAuth track challenges...")
    challenges, ids = build_challenges()
    print(f"  ✓ Built {len(challenges)} challenges.")

    # 1. Update challenges.js
    with open(CHALLENGES_JS, "r", encoding="utf-8") as f:
        content = f.read()

    # Find where TRACKS ends: before `const CHALLENGES =`
    pos_tracks_end = content.find("const CHALLENGES =")
    if pos_tracks_end == -1:
        raise ValueError("Could not find `const CHALLENGES =` in challenges.js")
    bracket_pos = content.rfind("];", 0, pos_tracks_end)
    if bracket_pos == -1:
        raise ValueError("Could not find closing bracket for TRACKS")

    # Insert indented_track right before `];`
    prev_chunk = content[:bracket_pos].rstrip()
    if not prev_chunk.endswith(","):
        prev_chunk += ","
    content = prev_chunk + "\n  " + json.dumps(TRACK_INFO, ensure_ascii=False, indent=2).replace("\n", "\n  ") + "\n" + content[bracket_pos:]

    # Now add CHALLENGES entries before the final `];`
    final_bracket = content.rfind("];")
    if final_bracket == -1:
        raise ValueError("Could not find final `];` in challenges.js")

    rendered_chals = []
    for c in challenges:
        rendered = json.dumps(c, ensure_ascii=False, indent=2)
        rendered_chals.append(rendered)

    chals_str = ",\n" + ",\n".join(rendered_chals) + "\n"
    content = content[:final_bracket] + chals_str + content[final_bracket:]

    with open(CHALLENGES_JS, "w", encoding="utf-8") as f:
        f.write(content)
    print("  ✓ Updated challenges.js with 45th track and 35 challenges.")

    # 2. Update solve-derivable.js
    with open(SOLVE_DERIVABLE_JS, "r", encoding="utf-8") as f:
        sd_content = f.read()

    marker = '"t4_ghidra_capstone_deobfuscation_audit"'
    pos = sd_content.find(marker)
    if pos == -1:
        raise ValueError("Marker not found in solve-derivable.js")
    
    insert_ids_str = ',\n' + ',\n'.join(f'  "{cid}"' for cid in ids)
    sd_content = sd_content[:pos + len(marker)] + insert_ids_str + sd_content[pos + len(marker):]

    with open(SOLVE_DERIVABLE_JS, "w", encoding="utf-8") as f:
        f.write(sd_content)
    print("  ✓ Updated solve-derivable.js with 35 IDs.")

    # 3. Update index.html HUD counts
    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("0/1540", "0/1575")
    html = html.replace("1540", "1575")
    html = html.replace("44 트랙", "45 트랙")
    html = html.replace("44 tracks", "45 tracks")
    html = html.replace("44 Tracks", "45 Tracks")
    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print("  ✓ Updated index.html HUD counters to 1,575.")

    # 4. Update WARGAME_README
    if WARGAME_README.exists():
        with open(WARGAME_README, "r", encoding="utf-8") as f:
            readme = f.read()

        # Insert topic rows into the 5 tier tables
        # Look for the last row in each tier table before the next table or section
        # Tier 0: after ghidra row
        lines = readme.splitlines()
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if line.startswith("| `ghidra` 🔬 Ghidra 역공학·난독화 해제 (7) |"):
                # Determine which tier by checking which headers appeared recently
                # Or count occurrences of ghidra row: 1st=tier0, 2nd=tier1, 3rd=tier2, 4th=tier3, 5th=tier4
                tier_idx = sum(1 for l in new_lines if l.startswith("| `ghidra` 🔬 Ghidra 역공학·난독화 해제 (7) |")) - 1
                new_lines.append(TIER_TOPIC_ROWS[tier_idx])

        readme = "\n".join(new_lines) + "\n"
        readme = readme.replace("1,540", "1,575").replace("1540", "1575")
        # In track list in README
        readme = readme.replace("Ghidra 역공학·난독화 해제 35", "Ghidra 역공학·난독화 해제 35 · OAuth 2.0·OIDC SSO 취약점 35")
        readme = readme.replace("AD CS PKI & Kerberos delegation 35);", "AD CS PKI & Kerberos delegation 35 · OAuth 2.0 & OIDC SSO Exploitation 35);")

        with open(WARGAME_README, "w", encoding="utf-8") as f:
            f.write(readme)
        print("  ✓ Updated wargame/README.md with 5 topic rows and 1,575 counts.")

    # 5. Update CLI_TEST
    if CLI_TEST.exists():
        with open(CLI_TEST, "r", encoding="utf-8") as f:
            clitest = f.read()
        clitest = clitest.replace("assert len(tracks) == 44", "assert len(tracks) == 45")
        clitest = clitest.replace("== 44", "== 45")
        clitest = clitest.replace("1540", "1575")
        if 'assert any(t["id"] == "adcs" for t in tracks)' in clitest and 'assert any(t["id"] == "oauth" for t in tracks)' not in clitest:
            clitest = clitest.replace(
                'assert any(t["id"] == "adcs" for t in tracks)',
                'assert any(t["id"] == "adcs" for t in tracks)\n    assert any(t["id"] == "oauth" for t in tracks)'
            )
        with open(CLI_TEST, "w", encoding="utf-8") as f:
            f.write(clitest)
        print("  ✓ Updated wargame/tests/test_cli.py assertions.")

    # 6. Update READMEs
    for r_path in [
        REPO_ROOT / "README.md",
        REPO_ROOT / "README.en.md",
        REPO_ROOT / "README.ja.md",
        REPO_ROOT / "README.zh.md",
        REPO_ROOT / "USAGE.md",
        REPO_ROOT / "AI_LEARNING.md",
        REPO_ROOT / "pyproject.toml",
        REPO_ROOT / "tools" / "bundle_offline.py",
    ]:
        if r_path.exists():
            with open(r_path, "r", encoding="utf-8") as f:
                r_content = f.read()
            r_content = r_content.replace("1,540", "1,575")
            r_content = r_content.replace("1540", "1575")
            r_content = r_content.replace("44 트랙", "45 트랙")
            r_content = r_content.replace("44 tracks", "45 tracks")
            r_content = r_content.replace("44 Tracks", "45 Tracks")
            r_content = r_content.replace("44개 트랙", "45개 트랙")
            r_content = r_content.replace("44 Wargame Tracks", "45 Wargame Tracks")
            with open(r_path, "w", encoding="utf-8") as f:
                f.write(r_content)
            print(f"  ✓ Updated {r_path.name}")

    print("[+] All assets updated successfully for 45 tracks and 1,575 challenges!")


if __name__ == "__main__":
    main()
