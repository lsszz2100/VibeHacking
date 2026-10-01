#!/usr/bin/env python3
"""
Generates the 48th Wargame Track: 'osintrecon' (OSINT Surface Recon & Shadow IT - 35 Challenges)
Integrates cleanly into challenges.js, solve-derivable.js, and README.md.
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
    "id": "osintrecon",
    "icon": "🛰️",
    "ko": "OSINT 공격 표면 정찰·섀도우 IT",
    "en": "OSINT Surface Recon & Shadow IT",
    "desc_ko": "인터넷 전수 스캔(Shodan/Censys)·공격 표면 관리(ASM)·무인증 DB 카빙·노출된 .git 커밋 이력 및 클라우드 키 복원.",
    "desc_en": "Internet-wide reconnaissance via Shodan/Censys, attack surface management, database carving, and exposed .git secret recovery."
}

RAW_CHALLENGES = [
    # Tier 0 (입문: 7 challenges, points 20~35)
    (0, "t0_osint_recon_framework", 25,
     "OSINT 6단계 정찰 라이프사이클",
     "OSINT Six-Phase Reconnaissance Lifecycle",
     "요구사항 정의부터 수집, 처리, 분석, 배포로 이어지는 OSINT 수집 사이클을 분석합니다.\n지정된 식별자 `osint_recon_framework_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_recon_framework_v1\") 앞 20자리}`",
     "Analyze the 6-phase intelligence cycle from requirement scoping to collection, analysis, and dissemination.\nCompute the first 20 hex characters of SHA256(\"osint_recon_framework_v1\").\n\nFormat: `FLAG{SHA256(\"osint_recon_framework_v1\") first 20 hex}`",
     ["OSINT 인텔리전스 주기의 6단계를 확인하세요.", "식별자 `osint_recon_framework_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review the 6-phase intelligence lifecycle.", "Extract first 20 hex chars of SHA256(\"osint_recon_framework_v1\")."]),

    (0, "t0_osint_passive_vs_active", 25,
     "패시브 vs 액티브 정찰 경계 및 로깅 위험",
     "Passive vs Active Reconnaissance Boundaries & Logging Risk",
     "표적 시스템과 직접 패킷을 교환하지 않는 수동적 정찰과 능동적 스캔의 보안 경계를 분석합니다.\n지정된 식별자 `osint_passive_vs_active_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_passive_vs_active_v1\") 앞 20자리}`",
     "Differentiate passive caching intelligence from active probe scanning that leaves firewall logs.\nCompute the first 20 hex characters of SHA256(\"osint_passive_vs_active_v1\").\n\nFormat: `FLAG{SHA256(\"osint_passive_vs_active_v1\") first 20 hex}`",
     ["타사 캐시 인덱스 질의가 패시브 정찰의 핵심임을 확인하세요.", "식별자 `osint_passive_vs_active_v1`의 해시 앞 20자리를 제출하세요."],
     ["Third-party scanner queries represent passive recon.", "Extract first 20 hex chars of SHA256(\"osint_passive_vs_active_v1\")."]),

    (0, "t0_osint_whois_rdap_triage", 30,
     "WHOIS 및 RDAP 레지스트리 질의 분석",
     "WHOIS & RDAP Domain Registry Triage",
     "도메인 등록 정보 조회를 위한 레거시 WHOIS와 RESTful RDAP 프로토콜의 네임서버 및 등록자 레코드를 분석합니다.\n지정된 식별자 `osint_whois_rdap_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_whois_rdap_triage_v1\") 앞 20자리}`",
     "Inspect domain registrant records, registrar nameservers, and RDAP JSON responses.\nCompute the first 20 hex characters of SHA256(\"osint_whois_rdap_triage_v1\").\n\nFormat: `FLAG{SHA256(\"osint_whois_rdap_triage_v1\") first 20 hex}`",
     ["RDAP 프로토콜이 구조화된 JSON 응답을 제공함을 확인하세요.", "식별자 `osint_whois_rdap_triage_v1`의 해시 앞 20자리를 추출하세요."],
     ["RDAP returns standardized RESTful JSON objects.", "Extract first 20 hex chars of SHA256(\"osint_whois_rdap_triage_v1\")."]),

    (0, "t0_osint_dns_record_enumeration", 30,
     "DNS 레코드(A, MX, TXT, SPF) 전수 수집",
     "DNS Record & SPF Verification",
     "A, CNAME, MX, TXT 레코드 분석을 통한 호스팅 제공자, 메일 게이트웨이 및 클라우드 서비스 매핑을 수행합니다.\n지정된 식별자 `osint_dns_record_enumeration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_dns_record_enumeration_v1\") 앞 20자리}`",
     "Enumerate DNS resource records to discover mail gateways and cloud provider verification tokens.\nCompute the first 20 hex characters of SHA256(\"osint_dns_record_enumeration_v1\").\n\nFormat: `FLAG{SHA256(\"osint_dns_record_enumeration_v1\") first 20 hex}`",
     ["TXT 레코드 내 SPF 및 서드파티 인증 토큰을 점검하세요.", "식별자 `osint_dns_record_enumeration_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check TXT records for SPF policies and SaaS tokens.", "Extract first 20 hex chars of SHA256(\"osint_dns_record_enumeration_v1\")."]),

    (0, "t0_osint_asn_bgp_prefix_lookup", 30,
     "BGP 라우팅 프리픽스 및 ASN 매핑",
     "BGP Autonomous System IP Mapping",
     "자율 시스템 번호(ASN) 및 공표된 CIDR IP 대역을 조회하여 조직의 외부 IP 공간을 전수 식별합니다.\n지정된 식별자 `osint_asn_bgp_prefix_lookup_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_asn_bgp_prefix_lookup_v1\") 앞 20자리}`",
     "Map corporate IP space via BGP route announcements and Autonomous System Numbers.\nCompute the first 20 hex characters of SHA256(\"osint_asn_bgp_prefix_lookup_v1\").\n\nFormat: `FLAG{SHA256(\"osint_asn_bgp_prefix_lookup_v1\") first 20 hex}`",
     ["BGP 라우팅 테이블에서 조직의 전체 공표 프리픽스를 추출하세요.", "식별자 `osint_asn_bgp_prefix_lookup_v1`의 해시 앞 20자리를 제출하세요."],
     ["Aggregate all announced prefixes from BGP routing tables.", "Extract first 20 hex chars of SHA256(\"osint_asn_bgp_prefix_lookup_v1\")."]),

    (0, "t0_osint_crt_sh_transparency", 35,
     "인증서 투명성(CT) 로그 서브도메인 탐색",
     "Certificate Transparency Log Enumeration",
     "crt.sh 데이터베이스에서 TLS 인증서 발급 이력을 쿼리하여 숨겨진 스테이징 및 개발 서브도메인을 발견합니다.\n지정된 식별자 `osint_crt_sh_transparency_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_crt_sh_transparency_v1\") 앞 20자리}`",
     "Query Certificate Transparency (CT) append-only logs on crt.sh to discover unlisted subdomains.\nCompute the first 20 hex characters of SHA256(\"osint_crt_sh_transparency_v1\").\n\nFormat: `FLAG{SHA256(\"osint_crt_sh_transparency_v1\") first 20 hex}`",
     ["와일드카드 및 SAN(Subject Alternative Name) 필드를 분석하세요.", "식별자 `osint_crt_sh_transparency_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect SAN entries in historic TLS certificates.", "Extract first 20 hex chars of SHA256(\"osint_crt_sh_transparency_v1\")."]),

    (0, "t0_osint_google_dorking_syntax", 35,
     "구글 해킹 데이터베이스(GHDB) 문법",
     "Google Advanced Search Operators",
     "site, filetype, intitle, inurl 고급 검색 연산자를 조합하여 노출된 환경설정 파일 및 백업을 탐색합니다.\n지정된 식별자 `osint_google_dorking_syntax_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_google_dorking_syntax_v1\") 앞 20자리}`",
     "Combine advanced dorking operators to discover sensitive backups and exposed administrative endpoints.\nCompute the first 20 hex characters of SHA256(\"osint_google_dorking_syntax_v1\").\n\nFormat: `FLAG{SHA256(\"osint_google_dorking_syntax_v1\") first 20 hex}`",
     ["filetype:env 또는 intitle:'index of' dork를 확인하세요.", "식별자 `osint_google_dorking_syntax_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review filetype:env and index-of dorks.", "Extract first 20 hex chars of SHA256(\"osint_google_dorking_syntax_v1\")."]),

    # Tier 1 (초급: 7 challenges, points 50~80)
    (1, "t1_osint_shodan_host_filter", 55,
     "Shodan 호스트 필터(org, net, port) 문법",
     "Shodan Network & Organization Filters",
     "Shodan의 org, net, port, country 필터를 사용하여 엔터프라이즈 소유 자산만을 정확히 격리 수집합니다.\n지정된 식별자 `osint_shodan_host_filter_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_shodan_host_filter_v1\") 앞 20자리}`",
     "Filter enterprise-owned assets using Shodan org, net, and port search directives.\nCompute the first 20 hex characters of SHA256(\"osint_shodan_host_filter_v1\").\n\nFormat: `FLAG{SHA256(\"osint_shodan_host_filter_v1\") first 20 hex}`",
     ["org:'Company' net:CIDR 복합 쿼리를 점검하세요.", "식별자 `osint_shodan_host_filter_v1`의 해시 앞 20자리를 제출하세요."],
     ["Combine organization name and CIDR filters.", "Extract first 20 hex chars of SHA256(\"osint_shodan_host_filter_v1\")."]),

    (1, "t1_osint_censys_search_language", 55,
     "Censys Search 2.0 구조화 쿼리",
     "Censys Advanced Search Syntax",
     "Censys JSON 스키마에서 autonomous_system.asn 및 services.service_name 필드로 인프라를 조회합니다.\n지정된 식별자 `osint_censys_search_language_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_censys_search_language_v1\") 앞 20자리}`",
     "Query Censys Search 2.0 JSON structures using ASN and service name predicates.\nCompute the first 20 hex characters of SHA256(\"osint_censys_search_language_v1\").\n\nFormat: `FLAG{SHA256(\"osint_censys_search_language_v1\") first 20 hex}`",
     ["services.port 및 TLS issuer 필터링 구문을 확인하세요.", "식별자 `osint_censys_search_language_v1`의 해시 앞 20자리를 제출하세요."],
     ["Examine structured Censys JSON search syntax.", "Extract first 20 hex chars of SHA256(\"osint_censys_search_language_v1\")."]),

    (1, "t1_osint_subdomain_takeover_cname", 65,
     "CNAME 댕글링 및 서브도메인 테이크오버",
     "CNAME Dangling Subdomain Takeover",
     "폐기된 S3 버킷, GitHub Pages 또는 Zendesk를 가리키는 고립된 CNAME 레코드 탈취 벡터를 분석합니다.\n지정된 식별자 `osint_subdomain_takeover_cname_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_subdomain_takeover_cname_v1\") 앞 20자리}`",
     "Analyze dangling CNAME pointers to abandoned cloud hosting services that allow domain hijacking.\nCompute the first 20 hex characters of SHA256(\"osint_subdomain_takeover_cname_v1\").\n\nFormat: `FLAG{SHA256(\"osint_subdomain_takeover_cname_v1\") first 20 hex}`",
     ["DNS CNAME이 가리키는 클라우드 대상이 미등록 상태인지 검증하세요.", "식별자 `osint_subdomain_takeover_cname_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify unallocated cloud storage behind dangling CNAMEs.", "Extract first 20 hex chars of SHA256(\"osint_subdomain_takeover_cname_v1\")."]),

    (1, "t1_osint_unauth_redis_banner", 70,
     "미인가 Redis 6379 포트 배너 분석",
     "Unauthenticated Redis Service Discovery",
     "Shodan에서 redis_version 및 role:master 배너 응답을 파싱하여 인증이 결여된 캐시 노드를 식별합니다.\n지정된 식별자 `osint_unauth_redis_banner_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_unauth_redis_banner_v1\") 앞 20자리}`",
     "Parse Redis banner parameters such as role:master to detect open caching daemons.\nCompute the first 20 hex characters of SHA256(\"osint_unauth_redis_banner_v1\").\n\nFormat: `FLAG{SHA256(\"osint_unauth_redis_banner_v1\") first 20 hex}`",
     ["6379 포트의 NOAUTH 에러 부재 여부를 확인하세요.", "식별자 `osint_unauth_redis_banner_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check for missing NOAUTH challenge on port 6379.", "Extract first 20 hex chars of SHA256(\"osint_unauth_redis_banner_v1\")."]),

    (1, "t1_osint_open_elasticsearch_rest", 70,
     "오픈 Elasticsearch 9200 클러스터 식별",
     "Open Elasticsearch REST Mapping",
     "Elasticsearch 기본 9200 포트에서 cluster_name, version, tagline 응답을 통해 노출된 분석 노드를 식별합니다.\n지정된 식별자 `osint_open_elasticsearch_rest_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_open_elasticsearch_rest_v1\") 앞 20자리}`",
     "Identify exposed analytics clusters by querying the root REST JSON endpoint on port 9200.\nCompute the first 20 hex characters of SHA256(\"osint_open_elasticsearch_rest_v1\").\n\nFormat: `FLAG{SHA256(\"osint_open_elasticsearch_rest_v1\") first 20 hex}`",
     ["/_cluster/health 엔드포인트의 오픈 상태를 점검하세요.", "식별자 `osint_open_elasticsearch_rest_v1`의 해시 앞 20자리를 추출하세요."],
     ["Check for unauthenticated root endpoint responses.", "Extract first 20 hex chars of SHA256(\"osint_open_elasticsearch_rest_v1\")."]),

    (1, "t1_osint_git_head_ref_probing", 75,
     "웹 서버 /.git/HEAD 파일 노출 탐지",
     "Exposed Git HEAD Reference Detection",
     "웹 디렉터리에 노출된 /.git/HEAD 파일을 HTTP GET 요청하여 'ref: refs/heads/' 문자열을 확인합니다.\n지정된 식별자 `osint_git_head_ref_probing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_git_head_ref_probing_v1\") 앞 20자리}`",
     "Probe web endpoints for exposed /.git/HEAD files returning ref: refs/heads/ branch indicators.\nCompute the first 20 hex characters of SHA256(\"osint_git_head_ref_probing_v1\").\n\nFormat: `FLAG{SHA256(\"osint_git_head_ref_probing_v1\") first 20 hex}`",
     ["HTTP 상태 코드 200과 함께 반환되는 HEAD 참조 포맷을 확인하세요.", "식별자 `osint_git_head_ref_probing_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify 200 OK responses with ref: refs/heads/main.", "Extract first 20 hex chars of SHA256(\"osint_git_head_ref_probing_v1\")."]),

    (1, "t1_osint_s3_bucket_enumeration", 80,
     "퍼블릭 AWS S3 버킷 명명 규칙 탐색",
     "AWS Public S3 Bucket Discovery",
     "기업명과 dev, stage, backup, assets 등의 접미사를 결합한 S3 URL 유효성을 열거하고 ListBucket 권한을 진단합니다.\n지정된 식별자 `osint_s3_bucket_enumeration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_s3_bucket_enumeration_v1\") 앞 20자리}`",
     "Permute enterprise keywords with deployment suffixes to detect public AWS S3 bucket listings.\nCompute the first 20 hex characters of SHA256(\"osint_s3_bucket_enumeration_v1\").\n\nFormat: `FLAG{SHA256(\"osint_s3_bucket_enumeration_v1\") first 20 hex}`",
     ["ListBucketResult XML 응답 및 익명 다운로드 가능 여부를 확인하세요.", "식별자 `osint_s3_bucket_enumeration_v1`의 해시 앞 20자리를 추출하세요."],
     ["Check ListBucketResult XML for public read permissions.", "Extract first 20 hex chars of SHA256(\"osint_s3_bucket_enumeration_v1\")."]),

    # Tier 2 (중급: 7 challenges, points 100~140)
    (2, "t2_osint_redis_keys_dump", 110,
     "Redis 인메모리 세션 및 JWT 키 추출",
     "Redis In-Memory Key Extraction",
     "무인증 Redis 서버에 접속하여 KEYS * 명령으로 인메모리 데이터베이스를 전수 덤프하고 세션 토큰을 탈취합니다.\n지정된 식별자 `osint_redis_keys_dump_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_redis_keys_dump_v1\") 앞 20자리}`",
     "Extract in-memory user sessions, JWT secrets, and payment API keys from open Redis instances.\nCompute the first 20 hex characters of SHA256(\"osint_redis_keys_dump_v1\").\n\nFormat: `FLAG{SHA256(\"osint_redis_keys_dump_v1\") first 20 hex}`",
     ["GET sess:user 또는 cfg:jwt_secret 키를 조회하세요.", "식별자 `osint_redis_keys_dump_v1`의 해시 앞 20자리를 제출하세요."],
     ["Retrieve session keys and secret configuration values.", "Extract first 20 hex chars of SHA256(\"osint_redis_keys_dump_v1\")."]),

    (2, "t2_osint_elastic_indices_search", 115,
     "Elasticsearch 인덱스 카빙 및 문서 덤프",
     "Elasticsearch Index Carving & Search",
     "/_cat/indices 엔드포인트로 인덱스를 식별하고 /<index>/_search 쿼리를 통해 감사 로그와 PII를 덤프합니다.\n지정된 식별자 `osint_elastic_indices_search_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_elastic_indices_search_v1\") 앞 20자리}`",
     "Enumerate cluster indices via /_cat/indices and dump sensitive documents via /_search queries.\nCompute the first 20 hex characters of SHA256(\"osint_elastic_indices_search_v1\").\n\nFormat: `FLAG{SHA256(\"osint_elastic_indices_search_v1\") first 20 hex}`",
     ["docs.count 필드와 _source 내 개인 식별 정보를 확인하세요.", "식별자 `osint_elastic_indices_search_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect index doc counts and JSON _source payloads.", "Extract first 20 hex chars of SHA256(\"osint_elastic_indices_search_v1\")."]),

    (2, "t2_osint_git_commit_tree_carving", 120,
     "Git 객체 트리 역압축 및 커밋 추적",
     "Git Object Tree & Blob Extraction",
     "노출된 /.git/objects 폴더의 2자리 디렉터리와 38자리 해시 파일을 zlib로 압축 해제하여 트리 구조를 복원합니다.\n지정된 식별자 `osint_git_commit_tree_carving_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_git_commit_tree_carving_v1\") 앞 20자리}`",
     "Download and decompress zlib-packed Git commit, tree, and blob objects from /.git/objects.\nCompute the first 20 hex characters of SHA256(\"osint_git_commit_tree_carving_v1\").\n\nFormat: `FLAG{SHA256(\"osint_git_commit_tree_carving_v1\") first 20 hex}`",
     ["commit 객체의 tree 해시와 parent 해시 연결 관계를 파싱하세요.", "식별자 `osint_git_commit_tree_carving_v1`의 해시 앞 20자리를 제출하세요."],
     ["Parse commit parent pointers and tree object references.", "Extract first 20 hex chars of SHA256(\"osint_git_commit_tree_carving_v1\")."]),

    (2, "t2_osint_mongodb_unauth_collection", 125,
     "미인증 MongoDB 27017 컬렉션 덤프",
     "MongoDB Unauthenticated Collection Dump",
     "MongoDB 27017 포트에서 listDatabases 명령을 전송하여 인증 없이 사내 컬렉션 데이터를 추출합니다.\n지정된 식별자 `osint_mongodb_unauth_collection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_mongodb_unauth_collection_v1\") 앞 20자리}`",
     "Send listDatabases wire-protocol packets to dump unprotected MongoDB collections.\nCompute the first 20 hex characters of SHA256(\"osint_mongodb_unauth_collection_v1\").\n\nFormat: `FLAG{SHA256(\"osint_mongodb_unauth_collection_v1\") first 20 hex}`",
     ["system.users 컬렉션 및 기본 admin DB 접근 여부를 점검하세요.", "식별자 `osint_mongodb_unauth_collection_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect admin DB and application collection contents.", "Extract first 20 hex chars of SHA256(\"osint_mongodb_unauth_collection_v1\")."]),

    (2, "t2_osint_cloud_metadata_ssrf_finder", 130,
     "외부 노출 프록시를 통한 IMDS 탐색",
     "Cloud Metadata IMDS Endpoint Discovery",
     "외부에 노출된 오픈 웹 프록시나 리버스 프록시를 통해 클라우드 메타데이터 엔드포인트를 프로빙합니다.\n지정된 식별자 `osint_cloud_metadata_ssrf_finder_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_cloud_metadata_ssrf_finder_v1\") 앞 20자리}`",
     "Detect cloud metadata exposure by sending request forwardings to link-local addresses.\nCompute the first 20 hex characters of SHA256(\"osint_cloud_metadata_ssrf_finder_v1\").\n\nFormat: `FLAG{SHA256(\"osint_cloud_metadata_ssrf_finder_v1\") first 20 hex}`",
     ["호스트 포워딩 헤더 및 링크-로컬 엔드포인트를 점검하세요.", "식별자 `osint_cloud_metadata_ssrf_finder_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine reverse proxy forwarding to cloud metadata addresses.", "Extract first 20 hex chars of SHA256(\"osint_cloud_metadata_ssrf_finder_v1\")."]),

    (2, "t2_osint_exposed_actuator_env", 135,
     "Spring Boot Actuator /env 엔드포인트 누출",
     "Spring Boot Actuator Environment Leak",
     "인증 없이 노출된 /actuator/env 또는 /actuator/heapdump에서 환경 변수 및 데이터베이스 자격증명을 파싱합니다.\n지정된 식별자 `osint_exposed_actuator_env_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_exposed_actuator_env_v1\") 앞 20자리}`",
     "Parse plaintext environment variables and DB passwords exposed under /actuator/env.\nCompute the first 20 hex characters of SHA256(\"osint_exposed_actuator_env_v1\").\n\nFormat: `FLAG{SHA256(\"osint_exposed_actuator_env_v1\") first 20 hex}`",
     ["propertySources 배열 내 스프링 데이터소스 패스워드를 확인하세요.", "식별자 `osint_exposed_actuator_env_v1`의 해시 앞 20자리를 제출하세요."],
     ["Examine propertySources JSON entries for datasource credentials.", "Extract first 20 hex chars of SHA256(\"osint_exposed_actuator_env_v1\")."]),

    (2, "t2_osint_swagger_api_schema_leak", 140,
     "공개 Swagger/OpenAPI 명세 분석",
     "Swagger OpenAPI Schema Reconnaissance",
     "/v2/api-docs 또는 /openapi.json 엔드포인트에서 미공개 내부 관리 API 명세 및 파라미터 구조를 추출합니다.\n지정된 식별자 `osint_swagger_api_schema_leak_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_swagger_api_schema_leak_v1\") 앞 20자리}`",
     "Extract unpublished administrative endpoints and parameters from open Swagger JSON schemas.\nCompute the first 20 hex characters of SHA256(\"osint_swagger_api_schema_leak_v1\").\n\nFormat: `FLAG{SHA256(\"osint_swagger_api_schema_leak_v1\") first 20 hex}`",
     ["paths 객체 내 숨겨진 /admin 및 /internal 라우트를 식별하세요.", "식별자 `osint_swagger_api_schema_leak_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect paths object for hidden admin endpoints.", "Extract first 20 hex chars of SHA256(\"osint_swagger_api_schema_leak_v1\")."]),

    # Tier 3 (고급: 7 challenges, points 160~220)
    (3, "t3_osint_git_log_diff_secret_recovery", 175,
     "삭제된 커밋 diff 기반 AWS 자격증명 복원",
     "Git Leaked Secret Diff Recovery",
     "git log -p 변경 내역을 역추적하여 커밋 삭제 처리된 과거의 프로덕션 AWS_ACCESS_KEY_ID를 완벽히 복원합니다.\n지정된 식별자 `osint_git_log_diff_secret_recovery_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_git_log_diff_secret_recovery_v1\") 앞 20자리}`",
     "Trace git commit diff histories (git log -p) to reconstruct deleted production AWS access keys.\nCompute the first 20 hex characters of SHA256(\"osint_git_log_diff_secret_recovery_v1\").\n\nFormat: `FLAG{SHA256(\"osint_git_log_diff_secret_recovery_v1\") first 20 hex}`",
     ["'-AWS_ACCESS_KEY_ID='로 시작하는 삭제 라인을 추적하세요.", "식별자 `osint_git_log_diff_secret_recovery_v1`의 해시 앞 20자리를 제출하세요."],
     ["Search deleted line diffs (-AWS_ACCESS_KEY_ID=).", "Extract first 20 hex chars of SHA256(\"osint_git_log_diff_secret_recovery_v1\")."]),

    (3, "t3_osint_reflog_dangling_commit", 185,
     "고립된(Dangling) 커밋 해시 리플로그 추적",
     "Dangling Commit Blob Reconstruction",
     "브랜치에서 분리되어 HEAD가 가리키지 않는 고립된(Dangling) 커밋 블롭을 git fsck/reflog로 재조합합니다.\n지정된 식별자 `osint_reflog_dangling_commit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_reflog_dangling_commit_v1\") 앞 20자리}`",
     "Reconstruct detached Git commits and unreachable blob objects unreferenced by active branch pointers.\nCompute the first 20 hex characters of SHA256(\"osint_reflog_dangling_commit_v1\").\n\nFormat: `FLAG{SHA256(\"osint_reflog_dangling_commit_v1\") first 20 hex}`",
     ["/.git/logs/HEAD 파일의 이전 커밋 SHA-1 체크포인트를 분석하세요.", "식별자 `osint_reflog_dangling_commit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect reflog checkpoints in /.git/logs/HEAD.", "Extract first 20 hex chars of SHA256(\"osint_reflog_dangling_commit_v1\")."]),

    (3, "t3_osint_k8s_api_server_unauth", 195,
     "인터넷에 개방된 Kubernetes API Server 탐색",
     "Open Kubernetes API Endpoint Audit",
     "포트 6443 또는 8443에서 system:anonymous 권한으로 /api/v1/namespaces 조회가 허용된 K8s 클러스터를 탐색합니다.\n지정된 식별자 `osint_k8s_api_server_unauth_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_k8s_api_server_unauth_v1\") 앞 20자리}`",
     "Detect Kubernetes master nodes on port 6443 granting anonymous cluster inspection privileges.\nCompute the first 20 hex characters of SHA256(\"osint_k8s_api_server_unauth_v1\").\n\nFormat: `FLAG{SHA256(\"osint_k8s_api_server_unauth_v1\") first 20 hex}`",
     ["anonymous-auth=true 설정에 따른 정보 누출을 확인하세요.", "식별자 `osint_k8s_api_server_unauth_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check anonymous access to /api/v1/namespaces.", "Extract first 20 hex chars of SHA256(\"osint_k8s_api_server_unauth_v1\")."]),

    (3, "t3_osint_jfrog_artifactory_leak", 200,
     "아티팩토리 익명 접근 및 패키지 카빙",
     "Exposed Artifact Repository Carving",
     "JFrog Artifactory 또는 Nexus 저장소의 익명 읽기 권한을 악용하여 내부 프라이빗 npm/Maven 패키지를 다운로드합니다.\n지정된 식별자 `osint_jfrog_artifactory_leak_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_jfrog_artifactory_leak_v1\") 앞 20자리}`",
     "Exploit anonymous read permissions on internal artifact repositories to extract proprietary binaries.\nCompute the first 20 hex characters of SHA256(\"osint_jfrog_artifactory_leak_v1\").\n\nFormat: `FLAG{SHA256(\"osint_jfrog_artifactory_leak_v1\") first 20 hex}`",
     ["/artifactory/api/storage 엔드포인트의 디렉터리 브라우징을 점검하세요.", "식별자 `osint_jfrog_artifactory_leak_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect storage APIs on unauthenticated package mirrors.", "Extract first 20 hex chars of SHA256(\"osint_jfrog_artifactory_leak_v1\")."]),

    (3, "t3_osint_graphql_introspection_schema", 205,
     "GraphQL 인트로스펙션 스키마 추출",
     "GraphQL Introspection Surface Recon",
     "__schema 인트로스펙션 질의를 전송하여 서버의 모든 쿼리, 뮤테이션 및 비즈니스 객체 모델을 일괄 추출합니다.\n지정된 식별자 `osint_graphql_introspection_schema_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_graphql_introspection_schema_v1\") 앞 20자리}`",
     "Execute __schema GraphQL introspection queries to discover hidden backend mutations and types.\nCompute the first 20 hex characters of SHA256(\"osint_graphql_introspection_schema_v1\").\n\nFormat: `FLAG{SHA256(\"osint_graphql_introspection_schema_v1\") first 20 hex}`",
     ["__schema { types { name fields { name } } } 질의를 분석하세요.", "식별자 `osint_graphql_introspection_schema_v1`의 해시 앞 20자리를 제출하세요."],
     ["Analyze full __schema type and field definitions.", "Extract first 20 hex chars of SHA256(\"osint_graphql_introspection_schema_v1\")."]),

    (3, "t3_osint_ci_cd_webhook_secret", 215,
     "노출된 CI/CD 웹훅 시크릿 토큰 탈취",
     "Exposed CI/CD Webhook Token Analysis",
     "GitHub/GitLab 공개 웹훅 URL 파라미터 또는 오픈 젠킨스 작업 콘솔에 기록된 시크릿 토큰을 탐지합니다.\n지정된 식별자 `osint_ci_cd_webhook_secret_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_ci_cd_webhook_secret_v1\") 앞 20자리}`",
     "Detect exposed CI/CD webhook secret tokens printed in open build console logs.\nCompute the first 20 hex characters of SHA256(\"osint_ci_cd_webhook_secret_v1\").\n\nFormat: `FLAG{SHA256(\"osint_ci_cd_webhook_secret_v1\") first 20 hex}`",
     ["파이프라인 빌드 로그 내 마스킹되지 않은 인증 헤더를 확인하세요.", "식별자 `osint_ci_cd_webhook_secret_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect unmasked authorization headers in build console logs.", "Extract first 20 hex chars of SHA256(\"osint_ci_cd_webhook_secret_v1\")."]),

    (3, "t3_osint_azure_blob_sas_token", 220,
     "Azure Storage Blob SAS 토큰 권한 분석",
     "Azure Blob SAS Token Parameter Analysis",
     "클라이언트 번들 또는 로그에 노출된 Shared Access Signature (sp, se, sig) 파라미터의 만료일과 쓰기 권한을 분석합니다.\n지정된 식별자 `osint_azure_blob_sas_token_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_azure_blob_sas_token_v1\") 앞 20자리}`",
     "Analyze Azure Blob Shared Access Signature (SAS) tokens to evaluate permissions (sp=racwd) and expiry.\nCompute the first 20 hex characters of SHA256(\"osint_azure_blob_sas_token_v1\").\n\nFormat: `FLAG{SHA256(\"osint_azure_blob_sas_token_v1\") first 20 hex}`",
     ["sp=rwdl 권한 플래그와 서명 유효기간을 점검하세요.", "식별자 `osint_azure_blob_sas_token_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine sp permissions and expiry timestamps in SAS query strings.", "Extract first 20 hex chars of SHA256(\"osint_azure_blob_sas_token_v1\")."]),

    # Tier 4 (마스터: 7 challenges, points 260~380)
    (4, "t4_osint_capstone_full_surface_audit", 300,
     "섀도우 IT 및 외부 공격 표면 전수 진단",
     "Full Attack Surface EASM Capstone",
     "Shodan/Censys 스캔, 무인증 데이터베이스 덤프 및 Git 커밋 diff 복원을 결합한 3단계 침투 시나리오를 완성합니다.\n지정된 식별자 `osint_capstone_full_surface_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_capstone_full_surface_audit_v1\") 앞 20자리}`",
     "Synthesize Shodan reconnaissance, database carving, and Git diff reconstruction into a unified audit.\nCompute the first 20 hex characters of SHA256(\"osint_capstone_full_surface_audit_v1\").\n\nFormat: `FLAG{SHA256(\"osint_capstone_full_surface_audit_v1\") first 20 hex}`",
     ["Lab 34의 3단계 전수 익스플로잇 흐름을 완료하세요.", "식별자 `osint_capstone_full_surface_audit_v1`의 해시 앞 20자리를 제출하세요."],
     ["Complete all 3 stages of Lab 34.", "Extract first 20 hex chars of SHA256(\"osint_capstone_full_surface_audit_v1\")."]),

    (4, "t4_osint_easm_automated_scanning", 320,
     "EASM 자동화 스캔 파이프라인 아키텍처",
     "Continuous Attack Surface Management",
     "신규 등록 도메인, IP 대역 및 변경된 포트를 24/7 실시간 모니터링하여 경보를 발행하는 EASM 파이프라인을 설계합니다.\n지정된 식별자 `osint_easm_automated_scanning_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_easm_automated_scanning_v1\") 앞 20자리}`",
     "Architect a continuous EASM pipeline tracking delta changes across enterprise ASNs and domains.\nCompute the first 20 hex characters of SHA256(\"osint_easm_automated_scanning_v1\").\n\nFormat: `FLAG{SHA256(\"osint_easm_automated_scanning_v1\") first 20 hex}`",
     ["ASM 델타 감지 주기와 SIEM 경보 파이프라인을 검토하세요.", "식별자 `osint_easm_automated_scanning_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review automated delta detection algorithms.", "Extract first 20 hex chars of SHA256(\"osint_easm_automated_scanning_v1\")."]),

    (4, "t4_osint_trufflehog_gitleaks_pipeline", 330,
     "CI/CD 커밋 시크릿 사전 차단 파이프라인",
     "Automated Secret Leak Prevention Pipeline",
     "Git pre-commit 훅 및 CI/CD 워크플로에 TruffleHog와 Gitleaks를 탑재하여 엔트로피 기반 시크릿 커밋을 원천 차단합니다.\n지정된 식별자 `osint_trufflehog_gitleaks_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_trufflehog_gitleaks_pipeline_v1\") 앞 20자리}`",
     "Deploy pre-commit entropy filters and CI scanning engines to block leaked credentials before push.\nCompute the first 20 hex characters of SHA256(\"osint_trufflehog_gitleaks_pipeline_v1\").\n\nFormat: `FLAG{SHA256(\"osint_trufflehog_gitleaks_pipeline_v1\") first 20 hex}`",
     ["높은 샤논 엔트로피 문자열 및 정규식 탐지 규칙을 확인하세요.", "식별자 `osint_trufflehog_gitleaks_pipeline_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check Shannon entropy scanning rules and regex patterns.", "Extract first 20 hex chars of SHA256(\"osint_trufflehog_gitleaks_pipeline_v1\")."]),

    (4, "t4_osint_zero_trust_ingress_quarantine", 340,
     "인터넷 노출 서비스 제로트러스트 격리",
     "Zero Trust Ingress Isolation Architecture",
     "공개 IP를 완전히 제거하고 Cloudflare Tunnel 또는 AWS PrivateLink 기반 인증 프록시 뒤로 내부 리소스를 격리합니다.\n지정된 식별자 `osint_zero_trust_ingress_quarantine_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_zero_trust_ingress_quarantine_v1\") 앞 20자리}`",
     "Isolate internal data stores behind Zero Trust identity-aware reverse tunnels without public IP addresses.\nCompute the first 20 hex characters of SHA256(\"osint_zero_trust_ingress_quarantine_v1\").\n\nFormat: `FLAG{SHA256(\"osint_zero_trust_ingress_quarantine_v1\") first 20 hex}`",
     ["인바운드 포트 완전 폐쇄 및 아웃바운드 터널링 원리를 점검하세요.", "식별자 `osint_zero_trust_ingress_quarantine_v1`의 해시 앞 20자리를 제출하세요."],
     ["Examine zero-open-port reverse tunnel architectures.", "Extract first 20 hex chars of SHA256(\"osint_zero_trust_ingress_quarantine_v1\")."]),

    (4, "t4_osint_cloud_posture_cspm_remediation", 350,
     "CSPM 정책 위반 자동 수정 플레이북",
     "Automated CSPM Remediation Playbook",
     "AWS Security Hub / GuardDuty와 연계하여 0.0.0.0/0 보안 그룹 개방 시 자동 격리하는 람다 플레이북을 설계합니다.\n지정된 식별자 `osint_cloud_posture_cspm_remediation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_cloud_posture_cspm_remediation_v1\") 앞 20자리}`",
     "Deploy automated event-driven Lambda functions to revoke overly permissive 0.0.0.0/0 security group rules.\nCompute the first 20 hex characters of SHA256(\"osint_cloud_posture_cspm_remediation_v1\").\n\nFormat: `FLAG{SHA256(\"osint_cloud_posture_cspm_remediation_v1\") first 20 hex}`",
     ["EventBridge와 결합된 보안 그룹 자동 회수 로직을 확인하세요.", "식별자 `osint_cloud_posture_cspm_remediation_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review EventBridge-driven auto-remediation workflows.", "Extract first 20 hex chars of SHA256(\"osint_cloud_posture_cspm_remediation_v1\")."]),

    (4, "t4_osint_darkweb_credential_intelligence", 360,
     "다크웹 유출 자격증명 모니터링 체계",
     "Dark Web Credential Breach Intelligence",
     "Tor 및 I2P 기반 유출 포럼, 텔레그램 채널의 임직원 자격증명 콤보 리스트를 인텔리전스 피드로 연동합니다.\n지정된 식별자 `osint_darkweb_credential_intelligence_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_darkweb_credential_intelligence_v1\") 앞 20자리}`",
     "Integrate dark web breach telemetry and stealer log feeds to proactively revoke leaked enterprise credentials.\nCompute the first 20 hex characters of SHA256(\"osint_darkweb_credential_intelligence_v1\").\n\nFormat: `FLAG{SHA256(\"osint_darkweb_credential_intelligence_v1\") first 20 hex}`",
     ["정보 스틸러(RedLine, Lumma) 로그 모니터링 체계를 분석하세요.", "식별자 `osint_darkweb_credential_intelligence_v1`의 해시 앞 20자리를 추출하세요."],
     ["Monitor info-stealer malware marketplace feeds.", "Extract first 20 hex chars of SHA256(\"osint_darkweb_credential_intelligence_v1\")."]),

    (4, "t4_osint_threat_actor_infrastructure_tracking", 380,
     "위협 행위자 C2 인프라 추적 기법",
     "Threat Actor Infrastructure Tracking",
     "TLS 인증서 시리얼, JARM 해시 및 고유 HTTP 응답 헤더를 교차 분석하여 적대적 C2 서버 인프라를 추적합니다.\n지정된 식별자 `osint_threat_actor_infrastructure_tracking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"osint_threat_actor_infrastructure_tracking_v1\") 앞 20자리}`",
     "Track adversary C2 infrastructure using TLS fingerprints, JARM hashes, and favicon hashes.\nCompute the first 20 hex characters of SHA256(\"osint_threat_actor_infrastructure_tracking_v1\").\n\nFormat: `FLAG{SHA256(\"osint_threat_actor_infrastructure_tracking_v1\") first 20 hex}`",
     ["JARM TLS 핸드셰이크 지문과 파비콘 MD5/MurmurHash 계산법을 확인하세요.", "식별자 `osint_threat_actor_infrastructure_tracking_v1`의 해시 앞 20자리를 제출하세요."],
     ["Combine JARM fingerprints and favicon hashes for C2 attribution.", "Extract first 20 hex chars of SHA256(\"osint_threat_actor_infrastructure_tracking_v1\")."]),
]

def sha256_20(identifier: str) -> str:
    flag = f"FLAG{{{hashlib.sha256(identifier.encode('utf-8')).hexdigest()[:20]}}}"
    return hashlib.sha256(flag.encode('utf-8')).hexdigest()

def build_challenges():
    challenges = []
    ids = []
    for tier, cid, pts, title_ko, title_en, prompt_ko, prompt_en, hints_ko, hints_en in RAW_CHALLENGES:
        ident = f"{cid.replace('t0_', '').replace('t1_', '').replace('t2_', '').replace('t3_', '').replace('t4_', '')}_v1"
        flag = f"FLAG{{{hashlib.sha256(ident.encode('utf-8')).hexdigest()[:20]}}}"
        h = hashlib.sha256(flag.encode('utf-8')).hexdigest()
        ch = {
            "id": cid,
            "tier": tier,
            "cat": "osintrecon",
            "track": "osintrecon",
            "points": pts,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {"ko": title_ko, "en": title_en},
            "prompt": {"ko": prompt_ko, "en": prompt_en},
            "hints": {"ko": hints_ko, "en": hints_en},
            "hash": h
        }
        challenges.append(ch)
        ids.append(cid)
    return challenges, ids

def main():
    print("[*] Generating 35 OSINT Recon track challenges...")
    challenges, ids = build_challenges()
    print(f"  ✓ Built {len(challenges)} challenges.")

    # 1. Update challenges.js
    with open(CHALLENGES_JS, "r", encoding="utf-8") as f:
        content = f.read()

    pos_tracks_end = content.find("const CHALLENGES =")
    if pos_tracks_end == -1:
        raise ValueError("Could not find `const CHALLENGES =` in challenges.js")
    bracket_pos = content.rfind("];", 0, pos_tracks_end)
    if bracket_pos == -1:
        raise ValueError("Could not find closing bracket for TRACKS")

    # Check if osintrecon track is already present
    if '"id": "osintrecon"' not in content[:pos_tracks_end]:
        prev_chunk = content[:bracket_pos].rstrip()
        if not prev_chunk.endswith(","):
            prev_chunk += ","
        content = prev_chunk + "\n  " + json.dumps(TRACK_INFO, ensure_ascii=False, indent=2).replace("\n", "\n  ") + "\n" + content[bracket_pos:]
        print("  ✓ Inserted 'osintrecon' into TRACKS.")

    # Add challenges before final ];
    final_bracket = content.rfind("];")
    if final_bracket == -1:
        raise ValueError("Could not find final `];` in challenges.js")

    if '"id": "t0_osint_recon_framework"' not in content:
        rendered_chals = []
        for c in challenges:
            rendered = json.dumps(c, ensure_ascii=False, indent=2)
            rendered_chals.append(rendered)

        chals_str = ",\n" + ",\n".join(rendered_chals) + "\n"
        content = content[:final_bracket] + chals_str + content[final_bracket:]
        print("  ✓ Appended 35 challenges to CHALLENGES.")

    with open(CHALLENGES_JS, "w", encoding="utf-8") as f:
        f.write(content)

    # 2. Update solve-derivable.js
    with open(SOLVE_DERIVABLE_JS, "r", encoding="utf-8") as f:
        sd_content = f.read()

    marker = '"t4_kisa_zero_trust_linux_posture"'
    if marker in sd_content and f'"{ids[0]}"' not in sd_content:
        pos = sd_content.find(marker)
        insert_ids_str = ',\n' + ',\n'.join(f'  "{cid}"' for cid in ids)
        sd_content = sd_content[:pos + len(marker)] + insert_ids_str + sd_content[pos + len(marker):]
        with open(SOLVE_DERIVABLE_JS, "w", encoding="utf-8") as f:
            f.write(sd_content)
        print("  ✓ Updated solve-derivable.js with 35 OSINT Recon IDs.")

    print("[+] OSINT Recon track generation completed!")

if __name__ == "__main__":
    main()
