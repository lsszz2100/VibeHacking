#!/usr/bin/env python3
"""
Generator for Track 73: ztnaapi (Zero Trust API & SPIFFE/SPIRE Workload Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,555 challenges milestone across 73 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "fundamentals_zero_trust_architecture_nist800_207",
        "title_ko": "NIST SP 800-207 제로 트러스트 아키텍처 기본 원칙",
        "title_en": "NIST SP 800-207 Zero Trust Architecture Fundamentals",
        "desc_ko": "네트워크 경계 보안의 한계를 극복하고 모든 자원 접근에 대해 명시적 검증(Explicit Verification)과 최소 권한을 부여하는 제로 트러스트 아키텍처(ZTA) 핵심 원칙을 분석합니다.\n지정된 식별자 `ztnaapi_fundamentals_zero_trust_architecture_nist800_207_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_fundamentals_zero_trust_architecture_nist800_207_v1\") 앞 20자리}",
        "desc_en": "Examine NIST SP 800-207 Zero Trust Architecture principles replacing perimeter security with explicit continuous verification.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_fundamentals_zero_trust_architecture_nist800_207_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_fundamentals_zero_trust_architecture_nist800_207_v1\")}"
    },
    {
        "tier": 0, "points": 25, "slug": "spiffe_id_naming_specification_and_trust_domain",
        "title_ko": "SPIFFE ID 표준 명명 체계 및 신뢰 도메인 구조",
        "title_en": "SPIFFE ID Naming Specification & Trust Domains",
        "desc_ko": "마이크로서비스 워크로드에 이식 가능한 암호학적 신원을 부여하는 URI 표준 형식(`spiffe://trust-domain/path`)과 신뢰 도메인(Trust Domain) 격리 구조를 분석합니다.\n지정된 식별자 `ztnaapi_spiffe_id_naming_specification_and_trust_domain_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_spiffe_id_naming_specification_and_trust_domain_v1\") 앞 20자리}",
        "desc_en": "Analyze SPIFFE URI naming conventions and trust domain boundaries providing portable cryptographic identity.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_spiffe_id_naming_specification_and_trust_domain_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_spiffe_id_naming_specification_and_trust_domain_v1\")}"
    },
    {
        "tier": 0, "points": 25, "slug": "mtls_bilateral_handshake_and_san_uri_authentication",
        "title_ko": "양방향 mTLS 핸드셰이크와 SAN URI 신원 검증",
        "title_en": "mTLS Mutual Handshake & SAN URI Authentication",
        "desc_ko": "클라이언트와 서버가 서로의 X.509 인증서를 검증하는 mTLS 프로토콜과 주체 대체 이름(SAN) 필드의 URI를 파싱하여 워크로드 신원을 확정하는 메커니즘을 이해합니다.\n지정된 식별자 `ztnaapi_mtls_bilateral_handshake_and_san_uri_authentication_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_mtls_bilateral_handshake_and_san_uri_authentication_v1\") 앞 20자리}",
        "desc_en": "Understand mutual TLS (mTLS) handshake workflows validating client X.509 certificates and parsing Subject Alternative Name (SAN) URIs.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_mtls_bilateral_handshake_and_san_uri_authentication_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_mtls_bilateral_handshake_and_san_uri_authentication_v1\")}"
    },
    {
        "tier": 0, "points": 25, "slug": "oauth2_dpop_proof_of_possession_rfc9449_concepts",
        "title_ko": "RFC 9449 OAuth 2.0 DPoP 소유 증명 기본 개념",
        "title_en": "RFC 9449 OAuth 2.0 DPoP Proof-of-Possession Concepts",
        "desc_ko": "단순 Bearer 토큰의 유출 및 무단 재전송 취약점을 극복하기 위해 클라이언트 개인키로 서명된 DPoP 증명을 요청에 바인딩하는 RFC 9449 표준을 학습합니다.\n지정된 식별자 `ztnaapi_oauth2_dpop_proof_of_possession_rfc9449_concepts_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_oauth2_dpop_proof_of_possession_rfc9449_concepts_v1\") 앞 20자리}",
        "desc_en": "Learn the RFC 9449 OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) standard preventing stolen bearer token misuse via asymmetric signing.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_oauth2_dpop_proof_of_possession_rfc9449_concepts_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_oauth2_dpop_proof_of_possession_rfc9449_concepts_v1\")}"
    },
    {
        "tier": 0, "points": 25, "slug": "envoy_proxy_filter_chain_and_wasm_extension_pipeline",
        "title_ko": "Envoy 프록시 필터 체인 및 WASM 확장 파이프라인",
        "title_en": "Envoy Proxy Filter Chain & WASM Extension Architecture",
        "desc_ko": "클라우드 네이티브 서비스 메시의 표준 L7 데이터 플레인인 Envoy 프록시의 HTTP 필터 체인 순서와 WebAssembly(WASM) 플러그인 인터셉트 아키텍처를 분석합니다.\n지정된 식별자 `ztnaapi_envoy_proxy_filter_chain_and_wasm_extension_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_envoy_proxy_filter_chain_and_wasm_extension_pipeline_v1\") 앞 20자리}",
        "desc_en": "Analyze Envoy proxy L7 HTTP filter chaining order and WebAssembly extension execution pipelines for request inspection.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_envoy_proxy_filter_chain_and_wasm_extension_pipeline_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_envoy_proxy_filter_chain_and_wasm_extension_pipeline_v1\")}"
    },
    {
        "tier": 0, "points": 25, "slug": "api_bearer_token_theft_and_replay_vulnerability",
        "title_ko": "API Bearer 토큰 탈취 및 재전송(Replay) 취약점 분석",
        "title_en": "API Bearer Token Theft & Replay Vulnerability",
        "desc_ko": "전송 계층 암호화(TLS)가 종단된 후 내부 마이크로서비스 간 통신에서 서명 검증 없는 Bearer 토큰이 탈취되어 재사용되는 인가 우회 위협을 평가합니다.\n지정된 식별자 `ztnaapi_api_bearer_token_theft_and_replay_vulnerability_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_api_bearer_token_theft_and_replay_vulnerability_v1\") 앞 20자리}",
        "desc_en": "Evaluate authorization bypass hazards where unconstrained bearer tokens are intercepted and replayed across internal services.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_api_bearer_token_theft_and_replay_vulnerability_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_api_bearer_token_theft_and_replay_vulnerability_v1\")}"
    },
    {
        "tier": 0, "points": 25, "slug": "zero_trust_maturity_model_and_microsegmentation",
        "title_ko": "제로 트러스트 성숙도 모델과 세분화 보안 경계 격리",
        "title_en": "Zero Trust Maturity Model & Fine-Grained Segmentation",
        "desc_ko": "CISA 제로 트러스트 성숙도 모델(신원·기기·네트워크·애플리케이션·데이터)과 동적 인라인 세분화 보안 격리 원칙을 분석합니다.\n지정된 식별자 `ztnaapi_zero_trust_maturity_model_and_microsegmentation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_zero_trust_maturity_model_and_microsegmentation_v1\") 앞 20자리}",
        "desc_en": "Review CISA Zero Trust Maturity Model pillars and dynamic fine-grained boundary isolation strategies restricting lateral movement.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_zero_trust_maturity_model_and_microsegmentation_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_zero_trust_maturity_model_and_microsegmentation_v1\")}"
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "envoy_xfcc_forwarded_client_cert_header_parsing",
        "title_ko": "Envoy XFCC(X-Forwarded-Client-Cert) 헤더 파싱 결함 분석",
        "title_en": "Envoy XFCC Header Parsing & Sanitization Vulnerabilities",
        "desc_ko": "엣지 프록시에서 주입된 XFCC 클라이언트 인증서 헤더를 백엔드가 맹신할 때 발생하는 헤더 스푸핑 공격과 비신뢰 상위 헤더 제거 규칙을 분석합니다.\n지정된 식별자 `ztnaapi_envoy_xfcc_forwarded_client_cert_header_parsing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_envoy_xfcc_forwarded_client_cert_header_parsing_v1\") 앞 20자리}",
        "desc_en": "Investigate X-Forwarded-Client-Cert (XFCC) header spoofing risks and upstream header stripping sanitization rules.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_envoy_xfcc_forwarded_client_cert_header_parsing_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_envoy_xfcc_forwarded_client_cert_header_parsing_v1\")}"
    },
    {
        "tier": 1, "points": 50, "slug": "spire_workload_api_unix_domain_socket_attestation",
        "title_ko": "SPIRE Workload API 유닉스 도메인 소켓 기반 워크로드 증명",
        "title_en": "SPIRE Workload API Unix Domain Socket Attestation",
        "desc_ko": "로컬 SPIRE 에이전트가 `/tmp/spire-agent/public/api.sock` 유닉스 소켓의 SO_PEERCRED 커널 시스콜을 호출하여 호출자 PID와 cgroup을 확인하는 증명 메커니즘을 분석합니다.\n지정된 식별자 `ztnaapi_spire_workload_api_unix_domain_socket_attestation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_spire_workload_api_unix_domain_socket_attestation_v1\") 앞 20자리}",
        "desc_en": "Examine SPIRE Agent local Unix domain socket attestation inspecting kernel peer credentials (SO_PEERCRED) and cgroups.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_spire_workload_api_unix_domain_socket_attestation_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_spire_workload_api_unix_domain_socket_attestation_v1\")}"
    },
    {
        "tier": 1, "points": 50, "slug": "dpop_proof_jwt_header_and_thumbprint_ath_structure",
        "title_ko": "DPoP 증명 JWT 헤더 규격 및 ath 토큰 지문 구조",
        "title_en": "DPoP Proof JWT Header & ath Token Thumbprint Structure",
        "desc_ko": "DPoP JWT 헤더의 `typ: dpop+jwt` 및 공개키 JWK 임베딩 규격과 액세스 토큰의 SHA-256 해시를 Base64URL 인코딩한 `ath` 클레임 일치성을 분석합니다.\n지정된 식별자 `ztnaapi_dpop_proof_jwt_header_and_thumbprint_ath_structure_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_dpop_proof_jwt_header_and_thumbprint_ath_structure_v1\") 앞 20자리}",
        "desc_en": "Analyze DPoP JWT typ:dpop+jwt headers, embedded client JWK keys, and ath (access token hash) Base64URL thumbprints.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_dpop_proof_jwt_header_and_thumbprint_ath_structure_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_dpop_proof_jwt_header_and_thumbprint_ath_structure_v1\")}"
    },
    {
        "tier": 1, "points": 50, "slug": "graphql_ast_query_depth_denial_of_wallet",
        "title_ko": "GraphQL AST 쿼리 심도 공격과 지갑 고갈(DoW) 위협",
        "title_en": "GraphQL AST Query Depth & Denial of Wallet Hazards",
        "desc_ko": "중첩된 GraphQL 관계형 질의가 백엔드 데이터베이스에 지수 함수적 조인을 유발하여 클라우드 비용 폭증(DoW) 및 서버 다운을 유발하는 구조를 분석합니다.\n지정된 식별자 `ztnaapi_graphql_ast_query_depth_denial_of_wallet_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_graphql_ast_query_depth_denial_of_wallet_v1\") 앞 20자리}",
        "desc_en": "Explore how recursive nested GraphQL queries cause exponential join explosions leading to cloud resource depletion and DoW.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_graphql_ast_query_depth_denial_of_wallet_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_graphql_ast_query_depth_denial_of_wallet_v1\")}"
    },
    {
        "tier": 1, "points": 50, "slug": "spiffe_x509_svid_certificate_chain_verification",
        "title_ko": "SPIFFE X.509 SVID 인증서 체인 및 짧은 TTL 갱신 주기",
        "title_en": "SPIFFE X.509 SVID Certificate Chain & Short TTL Renewal",
        "desc_ko": "워크로드에 발급되는 X.509-SVID가 1시간 미만의 초단기 수명(TTL)을 유지하며 인증서 해지 목록(CRL) 없이 자동 갱신되는 제로 트러스트 수명 주기를 분석합니다.\n지정된 식별자 `ztnaapi_spiffe_x509_svid_certificate_chain_verification_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_spiffe_x509_svid_certificate_chain_verification_v1\") 앞 20자리}",
        "desc_en": "Review short-lived X.509 SVID lifecycles where ephemeral TTLs eliminate CRL overhead via continuous automated re-issuance.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_spiffe_x509_svid_certificate_chain_verification_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_spiffe_x509_svid_certificate_chain_verification_v1\")}"
    },
    {
        "tier": 1, "points": 50, "slug": "envoy_ext_authz_grpc_sidecar_authorization",
        "title_ko": "Envoy ext_authz gRPC 사이드카 외부 인가 엔진 연동",
        "title_en": "Envoy ext_authz gRPC External Authorization Pipeline",
        "desc_ko": "Envoy 프록시가 트래픽을 업스트림에 전달하기 전 `envoy.filters.http.ext_authz` 필터를 통해 중앙 정책 결정 엔진(PDP)에 gRPC 인가 결정을 위임하는 구조를 분석합니다.\n지정된 식별자 `ztnaapi_envoy_ext_authz_grpc_sidecar_authorization_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_envoy_ext_authz_grpc_sidecar_authorization_v1\") 앞 20자리}",
        "desc_en": "Inspect Envoy ext_authz HTTP filters delegating real-time authorization checks to an external policy engine via gRPC.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_envoy_ext_authz_grpc_sidecar_authorization_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_envoy_ext_authz_grpc_sidecar_authorization_v1\")}"
    },
    {
        "tier": 1, "points": 50, "slug": "token_bucket_adaptive_rate_limiting_per_workload",
        "title_ko": "SPIFFE 신원 기반 토큰 버킷 적응형 속도 제한(Rate Limiting)",
        "title_en": "SPIFFE Identity-Based Token Bucket Adaptive Rate Limiting",
        "desc_ko": "단순 클라이언트 IP 대신 암호학적으로 검증된 SPIFFE ID별로 토큰 버킷 속도 제한 임계치를 동적 할당하여 API 남용을 차단하는 메커니즘을 분석합니다.\n지정된 식별자 `ztnaapi_token_bucket_adaptive_rate_limiting_per_workload_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_token_bucket_adaptive_rate_limiting_per_workload_v1\") 앞 20자리}",
        "desc_en": "Analyze token bucket rate-limiting algorithms assigning tiered throughput quotas keyed to verified SPIFFE workload identities.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_token_bucket_adaptive_rate_limiting_per_workload_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_token_bucket_adaptive_rate_limiting_per_workload_v1\")}"
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "spiffe_trust_domain_federation_and_bundle_exchange",
        "title_ko": "SPIFFE 신뢰 도메인 연합(Federation) 및 번들 교환 프로토콜",
        "title_en": "SPIFFE Trust Domain Federation & Bundle Exchange",
        "desc_ko": "서로 다른 쿠버네티스 클러스터 또는 멀티 클라우드 환경 간에 루트 CA 번들을 교환하여 교차 클라우드 mTLS 신뢰를 구축하는 SPIFFE 연합 프로토콜을 분석합니다.\n지정된 식별자 `ztnaapi_spiffe_trust_domain_federation_and_bundle_exchange_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_spiffe_trust_domain_federation_and_bundle_exchange_v1\") 앞 20자리}",
        "desc_en": "Examine SPIFFE Federation protocols securely exchanging root trust bundles across distinct multi-cloud Kubernetes clusters.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_spiffe_trust_domain_federation_and_bundle_exchange_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_spiffe_trust_domain_federation_and_bundle_exchange_v1\")}"
    },
    {
        "tier": 2, "points": 100, "slug": "spire_agent_cgroup_and_k8s_pod_attestor_rules",
        "title_ko": "SPIRE 에이전트 리눅스 cgroup 및 클러스터 워크로드 증명자 규칙",
        "title_en": "SPIRE Agent Linux cgroup & Cluster Workload Attestor Rules",
        "desc_ko": "SPIRE 에이전트가 리눅스 커널 procfs/cgroupv2 및 클러스터 API 서버의 워크로드 UID, 네임스페이스, 서비스 어카운트를 교차 검증하여 워크로드를 승인하는 메커니즘을 분석합니다.\n지정된 식별자 `ztnaapi_spire_agent_cgroup_and_k8s_pod_attestor_rules_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_spire_agent_cgroup_and_k8s_pod_attestor_rules_v1\") 앞 20자리}",
        "desc_en": "Understand SPIRE workload attestor plugins cross-validating workload UID, namespace, and service accounts against the kernel.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_spire_agent_cgroup_and_k8s_pod_attestor_rules_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_spire_agent_cgroup_and_k8s_pod_attestor_rules_v1\")}"
    },
    {
        "tier": 2, "points": 100, "slug": "dpop_jti_single_use_nonce_replay_neutralization",
        "title_ko": "DPoP jti 단일 사용 논스 캐시 및 시간차 리플레이 방어",
        "title_en": "DPoP jti Single-Use Nonce Cache & Time-Window Replay Defense",
        "desc_ko": "공격자가 유효한 DPoP 증명을 캡처하여 재전송하더라도 인메모리 분산 캐시(Redis)에 기록된 `jti` 식별자와 300초 타임스탬프 윈도우를 대조하여 즉각 차단하는 방어책을 분석합니다.\n지정된 식별자 `ztnaapi_dpop_jti_single_use_nonce_replay_neutralization_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_dpop_jti_single_use_nonce_replay_neutralization_v1\") 앞 20자리}",
        "desc_en": "Analyze distributed caching of jti nonce identifiers coupled with strict timestamp freshness windows neutralizing DPoP replay attempts.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_dpop_jti_single_use_nonce_replay_neutralization_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_dpop_jti_single_use_nonce_replay_neutralization_v1\")}"
    },
    {
        "tier": 2, "points": 100, "slug": "graphql_ast_field_complexity_budget_scoring",
        "title_ko": "GraphQL AST 정적 필드 복잡도 가중치 산정 및 예산 통제",
        "title_en": "GraphQL AST Static Field Complexity Budget Scoring",
        "desc_ko": "GraphQL AST 파서가 요청 수신 즉시 스키마의 필드별 가중치(DB 쿼리 유발 필드 +10점 등)와 곱셈 계수를 누적하여 최대 허용 점수(100점)를 초과 시 사전 차단하는 로직을 분석합니다.\n지정된 식별자 `ztnaapi_graphql_ast_field_complexity_budget_scoring_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_graphql_ast_field_complexity_budget_scoring_v1\") 앞 20자리}",
        "desc_en": "Explore AST static analysis assigning weighted complexity scores to schema fields to reject queries exceeding the execution budget.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_graphql_ast_field_complexity_budget_scoring_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_graphql_ast_field_complexity_budget_scoring_v1\")}"
    },
    {
        "tier": 2, "points": 100, "slug": "envoy_circuit_breaking_and_outlier_detection",
        "title_ko": "Envoy 서킷 브레이킹 및 이상치 감지(Outlier Detection) 격리",
        "title_en": "Envoy Circuit Breaking & Outlier Detection Containment",
        "desc_ko": "침해되거나 DoS 공격에 노출된 마이크로서비스 인스턴스를 Envoy Outlier Detection이 5xx 오류율 또는 연결 지연시간을 감지하여 풀에서 자동 퇴출하는 복원력 설계를 분석합니다.\n지정된 식별자 `ztnaapi_envoy_circuit_breaking_and_outlier_detection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_envoy_circuit_breaking_and_outlier_detection_v1\") 앞 20자리}",
        "desc_en": "Review Envoy circuit breaking and consecutive 5xx outlier ejection removing compromised or failing hosts from the load balancing pool.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_envoy_circuit_breaking_and_outlier_detection_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_envoy_circuit_breaking_and_outlier_detection_v1\")}"
    },
    {
        "tier": 2, "points": 100, "slug": "mtls_crl_and_ocsp_stapling_workload_revocation",
        "title_ko": "마이크로서비스 인증서 실시간 폐기 및 온라인 상태 질의 연동",
        "title_en": "Microservice Certificate Revocation & Online Status Validation",
        "desc_ko": "키 유출 사고 발생 시 긴급 폐기 통보를 서비스 메시 전체에 동기화하기 위한 온라인 인증 상태 유효성 캐싱 및 단축 TTL 기반 SVID 무효화 메커니즘을 분석합니다.\n지정된 식별자 `ztnaapi_mtls_crl_and_ocsp_stapling_workload_revocation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_mtls_crl_and_ocsp_stapling_workload_revocation_v1\") 앞 20자리}",
        "desc_en": "Assess certificate revocation dynamics and emergency SVID invalidation across service mesh Envoy proxies upon key compromise.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_mtls_crl_and_ocsp_stapling_workload_revocation_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_mtls_crl_and_ocsp_stapling_workload_revocation_v1\")}"
    },
    {
        "tier": 2, "points": 100, "slug": "workload_jwt_svid_audience_and_ttl_enforcement",
        "title_ko": "SPIFFE JWT-SVID 대상자(aud) 제한 및 엄격한 만료 검증",
        "title_en": "SPIFFE JWT-SVID Audience Restriction & Strict Expiry",
        "desc_ko": "L7 프록시를 통과할 수 없는 비-TLS 통신에서 JWT-SVID의 `aud` 클레임이 특정 수신 서비스로 한정되지 않을 때 발생하는 토큰 피싱 및 전용 취약점을 분석합니다.\n지정된 식별자 `ztnaapi_workload_jwt_svid_audience_and_ttl_enforcement_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_workload_jwt_svid_audience_and_ttl_enforcement_v1\") 앞 20자리}",
        "desc_en": "Investigate JWT-SVID audience claim enforcement preventing token relaying and phishing across non-TLS service boundaries.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_workload_jwt_svid_audience_and_ttl_enforcement_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_workload_jwt_svid_audience_and_ttl_enforcement_v1\")}"
    },

    # Tier 3 (7 challenges, 150 points each)
    {
        "tier": 3, "points": 150, "slug": "distributed_spire_server_nested_ha_topology",
        "title_ko": "분산 SPIRE 서버 중첩 HA 토폴로지 및 다운스트림 위임",
        "title_en": "Distributed SPIRE Server Nested HA Topology & Upstream Delegation",
        "desc_ko": "글로벌 멀티 리전 클러스터에서 중앙 상위 SPIRE 서버와 리전별 하위 SPIRE 서버 간 계층적 인증서 위임 및 고가용성 동기화 아키텍처를 분석합니다.\n지정된 식별자 `ztnaapi_distributed_spire_server_nested_ha_topology_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_distributed_spire_server_nested_ha_topology_v1\") 앞 20자리}",
        "desc_en": "Evaluate hierarchical SPIRE server deployments delegating intermediate CA signing authority across multi-region architectures.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_distributed_spire_server_nested_ha_topology_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_distributed_spire_server_nested_ha_topology_v1\")}"
    },
    {
        "tier": 3, "points": 150, "slug": "dpop_private_key_signature_proof_verification",
        "title_ko": "클라이언트 개인키 기반 DPoP 서명 유효성 암호학적 검증",
        "title_en": "Cryptographic Verification of DPoP Client Key Signatures",
        "desc_ko": "ES256(ECDSA P-256) 또는 RS256으로 서명된 DPoP 헤더의 공개키와 서명을 게이트웨이가 암호학적으로 검증하고 재생 공격을 봉쇄하는 알고리즘을 분석합니다.\n지정된 식별자 `ztnaapi_dpop_private_key_signature_proof_verification_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_dpop_private_key_signature_proof_verification_v1\") 앞 20자리}",
        "desc_en": "Analyze cryptographic verification routines inspecting client ES256/RS256 DPoP signatures and matching public keys against token bindings.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_dpop_private_key_signature_proof_verification_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_dpop_private_key_signature_proof_verification_v1\")}"
    },
    {
        "tier": 3, "points": 150, "slug": "graphql_circular_dependency_recursion_defense",
        "title_ko": "GraphQL 양방향 순환 참조(Circular Recursion) 탐지 및 방어",
        "title_en": "GraphQL Bidirectional Circular Recursion Detection",
        "desc_ko": "스키마의 순환 그래프 관계를 악용한 끝없는 재귀 확장 질의를 탐지하여 파서 단계에서 즉시 드롭하는 로직을 분석합니다.\n지정된 식별자 `ztnaapi_graphql_circular_dependency_recursion_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_graphql_circular_dependency_recursion_defense_v1\") 앞 20자리}",
        "desc_en": "Study recursive AST path tracing algorithms intercepting circular object references prior to resolver execution.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_graphql_circular_dependency_recursion_defense_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_graphql_circular_dependency_recursion_defense_v1\")}"
    },
    {
        "tier": 3, "points": 150, "slug": "service_mesh_canary_routing_with_spiffe_policies",
        "title_ko": "서비스 메시 점진적 릴리스 라우팅과 SPIFFE 신원 기반 트래픽 통제",
        "title_en": "Service Mesh Staged Release Routing with SPIFFE Policies",
        "desc_ko": "Envoy 가중치 클러스터 라우팅 중 신규 릴리스 버전으로의 접근을 특정 승인된 SPIFFE 신원에만 한정하는 신원 인가 정책을 분석합니다.\n지정된 식별자 `ztnaapi_service_mesh_canary_routing_with_spiffe_policies_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_service_mesh_canary_routing_with_spiffe_policies_v1\") 앞 20자리}",
        "desc_en": "Design fine-grained RBAC routing rules restricting phased release deployment traffic strictly to designated test SPIFFE identities.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_service_mesh_canary_routing_with_spiffe_policies_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_service_mesh_canary_routing_with_spiffe_policies_v1\")}"
    },
    {
        "tier": 3, "points": 150, "slug": "envoy_wasm_memory_sandbox_bounds_and_isolation",
        "title_ko": "Envoy WASM 런타임 메모리 샌드박스 경계 및 결함 격리",
        "title_en": "Envoy WASM Runtime Memory Sandbox Bounds & Fault Isolation",
        "desc_ko": "커스텀 보안 필터 WASM 모듈에서 메모리 충돌이 발생해도 Envoy 메인 워커 프로세스가 크래시되지 않도록 격리하는 Wasmtime 샌드박스를 분석합니다.\n지정된 식별자 `ztnaapi_envoy_wasm_memory_sandbox_bounds_and_isolation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_envoy_wasm_memory_sandbox_bounds_and_isolation_v1\") 앞 20자리}",
        "desc_en": "Examine WebAssembly Wasmtime sandbox boundaries isolating custom gateway filter execution crashes from Envoy core worker threads.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_envoy_wasm_memory_sandbox_bounds_and_isolation_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_envoy_wasm_memory_sandbox_bounds_and_isolation_v1\")}"
    },
    {
        "tier": 3, "points": 150, "slug": "spire_oidc_discovery_provider_federation",
        "title_ko": "SPIRE OIDC 디스커버리 프로바이더 및 외부 클라우드 신원 연동",
        "title_en": "SPIRE OIDC Discovery Provider & Cloud IAM Federation",
        "desc_ko": "SPIRE가 발행하는 JWT-SVID를 AWS IAM 또는 GCP Workload Identity가 OIDC JWKS 엔드포인트를 통해 신뢰하여 클라우드 키 없이 임시 자격증명을 발급하는 아키텍처를 분석합니다.\n지정된 식별자 `ztnaapi_spire_oidc_discovery_provider_federation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_spire_oidc_discovery_provider_federation_v1\") 앞 20자리}",
        "desc_en": "Analyze SPIRE OIDC Discovery endpoints enabling cloud providers (AWS/GCP) to validate workload JWT-SVIDs without static credentials.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_spire_oidc_discovery_provider_federation_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_spire_oidc_discovery_provider_federation_v1\")}"
    },
    {
        "tier": 3, "points": 150, "slug": "api_gateway_waf_and_zero_trust_anomaly_hunting",
        "title_ko": "API 게이트웨이 WAF 연동 및 비정상 신원 행동 헌팅",
        "title_en": "API Gateway WAF Integration & Anomaly Threat Hunting",
        "desc_ko": "Envoy 로그와 WAF 이벤트를 SIEM으로 집계하여 평소와 다른 파드 IP에서 유효한 SPIFFE SVID로 비정상 API를 대량 호출하는 크리덴셜 탈취 징후를 탐지하는 로직을 분석합니다.\n지정된 식별자 `ztnaapi_api_gateway_waf_and_zero_trust_anomaly_hunting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_api_gateway_waf_and_zero_trust_anomaly_hunting_v1\") 앞 20자리}",
        "desc_en": "Correlate Envoy access telemetry and WAF findings in SIEM to detect anomalous API access patterns from compromised valid workloads.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_api_gateway_waf_and_zero_trust_anomaly_hunting_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_api_gateway_waf_and_zero_trust_anomaly_hunting_v1\")}"
    },

    # Tier 4 (7 challenges, 250 points each)
    {
        "tier": 4, "points": 250, "slug": "enterprise_multicloud_spiffe_federation_mesh",
        "title_ko": "엔터프라이즈 멀티클라우드 하이브리드 SPIFFE 연합 메시 구축",
        "title_en": "Enterprise Multi-Cloud Hybrid SPIFFE Federation Mesh",
        "desc_ko": "온프레미스 데이터센터, AWS 클라우드, 구글 클라우드 간에 양방향 SPIFFE Federation을 구성하고 Envoy mTLS 상호 인증으로 크로스 클라우드 데이터 통신을 암호화하는 아키텍처를 분석합니다.\n지정된 식별자 `ztnaapi_enterprise_multicloud_spiffe_federation_mesh_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_enterprise_multicloud_spiffe_federation_mesh_v1\") 앞 20자리}",
        "desc_en": "Design an enterprise multi-cloud hybrid SPIFFE mesh linking on-prem, AWS cloud, and GCP workloads with end-to-end mTLS authentication.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_enterprise_multicloud_spiffe_federation_mesh_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_enterprise_multicloud_spiffe_federation_mesh_v1\")}"
    },
    {
        "tier": 4, "points": 250, "slug": "hardware_tee_spiffe_svid_attestation_binding",
        "title_ko": "하드웨어 기밀 컴퓨팅(TEE) 기반 SPIFFE SVID 원격 증명 바인딩",
        "title_en": "Hardware TEE Remote Attestation Binding for SPIFFE SVIDs",
        "desc_ko": "기밀 인클레이브 내부에서 실행되는 워크로드에만 SPIRE 에이전트가 하드웨어 증명 보고서(Attestation Report)를 검증하여 SVID를 발급하는 최고 수준 방어를 분석합니다.\n지정된 식별자 `ztnaapi_hardware_tee_spiffe_svid_attestation_binding_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_hardware_tee_spiffe_svid_attestation_binding_v1\") 앞 20자리}",
        "desc_en": "Integrate AMD SEV-SNP / Intel SGX hardware attestation into SPIRE agent plugins restricting SVID issuance strictly to verified enclaves.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_hardware_tee_spiffe_svid_attestation_binding_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_hardware_tee_spiffe_svid_attestation_binding_v1\")}"
    },
    {
        "tier": 4, "points": 250, "slug": "dpop_hardware_backed_enclave_key_protection",
        "title_ko": "하드웨어 HSM/Secure Enclave 기반 DPoP 개인키 유출 방어",
        "title_en": "Hardware HSM/Secure Enclave Key Protection for DPoP Proofs",
        "desc_ko": "클라이언트 DPoP 개인키를 메모리 덤프로부터 격리하기 위해 하드웨어 모듈 내부에서 비추출성(Non-exportable) 키로 서명 연산을 수행하는 설계를 분석합니다.\n지정된 식별자 `ztnaapi_dpop_hardware_backed_enclave_key_protection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_dpop_hardware_backed_enclave_key_protection_v1\") 앞 20자리}",
        "desc_en": "Implement non-exportable hardware TPM/Secure Enclave key generation for DPoP cryptographic proofs resisting memory extraction.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_dpop_hardware_backed_enclave_key_protection_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_dpop_hardware_backed_enclave_key_protection_v1\")}"
    },
    {
        "tier": 4, "points": 250, "slug": "graphql_ast_realtime_dos_mitigation_pipeline",
        "title_ko": "실시간 GraphQL AST 복잡도 스트리밍 분석 및 능동 차단",
        "title_en": "Real-Time GraphQL AST Streaming Complexity Analysis & Mitigation",
        "desc_ko": "WASM 고성능 파서를 활용하여 수 메가바이트 단위의 악성 대규모 GraphQL 페이로드가 유입되는 즉시 스트리밍 단계에서 복잡도를 계산하고 사전 드롭하는 인라인 엔진을 분석합니다.\n지정된 식별자 `ztnaapi_graphql_ast_realtime_dos_mitigation_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_graphql_ast_realtime_dos_mitigation_pipeline_v1\") 앞 20자리}",
        "desc_en": "Deploy in-flight streaming WASM AST parsers evaluating and neutralizing multi-megabyte malicious GraphQL payloads with sub-millisecond overhead.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_graphql_ast_realtime_dos_mitigation_pipeline_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_graphql_ast_realtime_dos_mitigation_pipeline_v1\")}"
    },
    {
        "tier": 4, "points": 250, "slug": "ebpf_xdp_api_gateway_kernel_bypass_defense",
        "title_ko": "eBPF/XDP 기반 API 게이트웨이 커널 계층 바이패스 탐지 및 방어",
        "title_en": "eBPF/XDP In-Kernel API Gateway Bypass Detection & Defense",
        "desc_ko": "유저랜드 Envoy 프록시를 통하지 않고 호스트 네트워크 인터페이스로 직접 유입되는 이상 패킷을 eBPF XDP 훅에서 포착하여 와이어 속도(Wire-speed)로 드롭하는 심층 방어 체계를 분석합니다.\n지정된 식별자 `ztnaapi_ebpf_xdp_api_gateway_kernel_bypass_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_ebpf_xdp_api_gateway_kernel_bypass_defense_v1\") 앞 20자리}",
        "desc_en": "Harness in-kernel eBPF XDP packet filters to intercept and discard rogue packets bypassing the userland Envoy proxy at wire speed.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_ebpf_xdp_api_gateway_kernel_bypass_defense_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_ebpf_xdp_api_gateway_kernel_bypass_defense_v1\")}"
    },
    {
        "tier": 4, "points": 250, "slug": "envoy_vulnerability_hotpatching_and_containment",
        "title_ko": "Envoy 제로데이 취약점 동적 핫패치 및 실시간 격리 플레이북",
        "title_en": "Envoy Zero-Day Dynamic Hotpatching & Containment Playbook",
        "desc_ko": "Envoy HTTP/2 또는 HTTP/3 프로토콜 스택 제로데이 취약점 발견 시 서비스 무중단 상태에서 WASM 필터를 동적 배포하여 악성 프레임을 무효화하는 핫패치 기법을 분석합니다.\n지정된 식별자 `ztnaapi_envoy_vulnerability_hotpatching_and_containment_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_envoy_vulnerability_hotpatching_and_containment_v1\") 앞 20자리}",
        "desc_en": "Execute zero-downtime hotpatching pipelines deploying dynamic WASM mitigation filters to neutralize protocol-level Envoy zero-day exploits.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_envoy_vulnerability_hotpatching_and_containment_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_envoy_vulnerability_hotpatching_and_containment_v1\")}"
    },
    {
        "tier": 4, "points": 250, "slug": "capstone_full_spectrum_zero_trust_api_defense",
        "title_ko": "엔터프라이즈 전방위 제로 트러스트 API 게이트웨이 종합 방어 캡스톤",
        "title_en": "Capstone: Full-Spectrum Enterprise Zero Trust API Defense",
        "desc_ko": "Envoy 프록시 인가, SPIFFE/SPIRE 워크로드 증명, RFC 9449 DPoP 바인딩, GraphQL AST 방어, eBPF 커널 텔레메트리를 통합 연계한 차세대 제로 트러스트 종합 방어 전략을 완성합니다.\n지정된 식별자 `ztnaapi_capstone_full_spectrum_zero_trust_api_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: FLAG{SHA256(\"ztnaapi_capstone_full_spectrum_zero_trust_api_defense_v1\") 앞 20자리}",
        "desc_en": "Synthesize Envoy proxy enforcement, SPIRE attestation, DPoP binding, GraphQL containment, and eBPF observability into an enterprise Zero Trust defense capstone.\nCompute the first 20 hex characters of SHA256(\"ztnaapi_capstone_full_spectrum_zero_trust_api_defense_v1\").\n\nFormat: FLAG{first 20 hex of SHA256(\"ztnaapi_capstone_full_spectrum_zero_trust_api_defense_v1\")}"
    }
]

TRACK_METADATA = {
    "id": "ztnaapi",
    "icon": "🌐",
    "ko": "제로 트러스트 API & SPIFFE/SPIRE 워크로드 방어",
    "en": "Zero Trust API & SPIFFE/SPIRE Workload Defense",
    "desc_ko": "Envoy WASM 인가 필터·mTLS SAN·SPIFFE/SPIRE 워크로드 증명·RFC 9449 DPoP 바인딩·GraphQL AST 복잡도 폭탄 방어.",
    "desc_en": "Envoy WASM auth filters, mTLS SAN validation, SPIFFE/SPIRE workload attestation, RFC 9449 DPoP binding, and GraphQL AST bomb containment."
}


def main():
    repo_root = Path(__file__).resolve().parent.parent
    challenges_js_path = repo_root / "wargame" / "assets" / "challenges.js"
    readme_path = repo_root / "wargame" / "README.md"
    solve_derivable_path = repo_root / "wargame" / "scripts" / "solve-derivable.js"

    # 1. Read challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")

    # Insert Track definition before ];\n\nconst CHALLENGES = [
    track_json = json.dumps(TRACK_METADATA, ensure_ascii=False, indent=2)
    track_insert = ",\n  " + track_json.replace("\n", "\n  ")
    target_tracks_end = "];\n\nconst CHALLENGES = ["
    if 'id: "ztnaapi"' in content or '"id": "ztnaapi"' in content:
        print("[-] Track ztnaapi already in challenges.js, skipping track insert.")
    else:
        assert target_tracks_end in content, "Could not find end of TRACKS in challenges.js"
        content = content.replace(target_tracks_end, track_insert + "\n];\n\nconst CHALLENGES = [")
        print("[+] Inserted Track 73 definition into TRACKS.")

    # Prepare formatted challenge objects
    new_challenges = []
    new_challenge_ids = []

    for c in CHALLENGES_DATA:
        tier = c["tier"]
        cid = f"t{tier}_ztnaapi_{c['slug']}"
        new_challenge_ids.append(cid)
        ident = f"ztnaapi_{c['slug']}_v1"
        flag_val = f"FLAG{{{hashlib.sha256(ident.encode('utf-8')).hexdigest()[:20]}}}"
        h = hashlib.sha256(flag_val.encode("utf-8")).hexdigest()

        ch_obj = {
            "id": cid,
            "tier": tier,
            "cat": "zerotrust",
            "track": "ztnaapi",
            "points": c["points"],
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {
                "ko": c["title_ko"],
                "en": c["title_en"]
            },
            "prompt": {
                "ko": c["desc_ko"],
                "en": c["desc_en"]
            },
            "hints": {
                "ko": [
                    f"식별자 `{ident}`의 암호화 해시를 통해 플래그를 정확하게 산출할 수 있습니다.",
                    f"식별자 `{ident}`의 해시 앞 20자리를 추출하세요."
                ],
                "en": [
                    f"Derive the target flag deterministically using SHA-256 over identifier `{ident}`.",
                    f"Extract the first 20 hex characters of SHA256(\"{ident}\")."
                ]
            },
            "hash": h
        }
        new_challenges.append(ch_obj)

    # Insert challenges before the final \n];
    challenges_insert = ""
    for ch in new_challenges:
        ch_json = json.dumps(ch, ensure_ascii=False, indent=2)
        indented = "  " + ch_json.replace("\n", "\n  ")
        challenges_insert += ",\n" + indented

    last_bracket_idx = content.rfind("\n];")
    assert last_bracket_idx != -1, "Could not find closing bracket of CHALLENGES"
    content = content[:last_bracket_idx] + challenges_insert + content[last_bracket_idx:]
    challenges_js_path.write_text(content, encoding="utf-8")
    print(f"[+] Appended {len(new_challenges)} challenges to CHALLENGES array in challenges.js.")

    # 2. Update solve-derivable.js
    sd_content = solve_derivable_path.read_text(encoding="utf-8")
    ids_insert = "  // 73rd Track: ztnaapi (35 challenges)\n" + ",\n".join([f'  "{cid}"' for cid in new_challenge_ids]) + ",\n"
    target_sd = '  // 72nd Track: quantumcrypt (35 challenges)'
    if target_sd in sd_content:
        sd_content = sd_content.replace(target_sd, ids_insert + target_sd)
        solve_derivable_path.write_text(sd_content, encoding="utf-8")
        print("[+] Added 35 challenge IDs to solve-derivable.js.")

    # 3. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    qc_tier_row = "| `quantumcrypt` ⚛️ 양자 암호 분석 & 포스트 양자 암호 방어 (7) | 쇼어 양자 위상 추정 탐색 방어 · 격자 기저 축소 난제 검증 · 도청 차단 순방향 비밀성 보장 · 상수시간 마스킹 다항식 연산 / Shor phase estimation search defense, lattice reduction hardness verification, eavesdropping defense forward secrecy assurance, and constant-time masked polynomial arithmetic |"
    ztna_tier_row = "| `ztnaapi` 🌐 제로 트러스트 API & SPIFFE/SPIRE 워크로드 방어 (7) | Envoy 인가 필터 체인 통제 · SPIFFE SVID 워크로드 신원 증명 · RFC 9449 DPoP 소유 증명 바인딩 · GraphQL AST 복잡도 심도 제한 / Envoy proxy filter chain control, SPIFFE SVID workload attestation, RFC 9449 DPoP proof binding, and GraphQL AST query depth complexity restriction |"

    if "| `ztnaapi` 🌐" not in readme:
        readme = readme.replace(qc_tier_row, qc_tier_row + "\n" + ztna_tier_row)
        print("[+] Added ztnaapi rows to all tier tables in wargame/README.md.")

    # Update tier counts and total in wargame/README.md
    readme = re.sub(r'총 \*\*2520문제\*\*', '총 **2555문제**', readme)
    readme = re.sub(r'Total \*\*2520 challenges\*\*', 'Total **2555 challenges**', readme)
    readme = readme.replace(
        '양자 암호 분석 & 포스트 양자 암호 방어 35)',
        '양자 암호 분석 & 포스트 양자 암호 방어 35 · 제로 트러스트 API & SPIFFE/SPIRE 워크로드 방어 35)'
    )

    # Tier counts: +7 per tier
    # T0: 259 -> 266
    # T1: 468 -> 475
    # T2: 620 -> 627
    # T3: 610 -> 617
    # T4: 563 -> 570
    readme = readme.replace('259 | 40%', '266 | 40%')
    readme = readme.replace('468 | 45%', '475 | 45%')
    readme = readme.replace('620 | 50%', '627 | 50%')
    readme = readme.replace('610 | 55%', '617 | 55%')
    readme = readme.replace('563 | 71%', '570 | 71%')

    readme = readme.replace('259문제', '266문제')
    readme = readme.replace('468문제', '475문제')
    readme = readme.replace('620문제', '627문제')
    readme = readme.replace('610문제', '617문제')
    readme = readme.replace('563문제', '570문제')

    readme = readme.replace('259 challenges', '266 challenges')
    readme = readme.replace('468 challenges', '475 challenges')
    readme = readme.replace('620 challenges', '627 challenges')
    readme = readme.replace('610 challenges', '617 challenges')
    readme = readme.replace('563 challenges', '570 challenges')

    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Updated wargame/README.md successfully.")

    # 4. Update HUD in wargame/index.html
    wargame_html = repo_root / "wargame" / "index.html"
    html_content = wargame_html.read_text(encoding="utf-8")
    html_content = html_content.replace('0/2520', '0/2555')
    html_content = html_content.replace('2520 challenges', '2555 challenges')
    html_content = html_content.replace('2,520 challenges', '2,555 challenges')
    html_content = html_content.replace('2520문제', '2555문제')
    html_content = html_content.replace('2,520문제', '2,555문제')
    wargame_html.write_text(html_content, encoding="utf-8")
    print("[+] Updated wargame/index.html successfully.")

    print("[*] Track 73 generation completed!")


if __name__ == "__main__":
    main()
