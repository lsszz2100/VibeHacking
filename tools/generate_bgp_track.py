#!/usr/bin/env python3
"""
Generates the 46th Wargame Track: 'bgp' (BGP Routing & RPKI Security - 35 Challenges)
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
    "id": "bgp",
    "icon": "🛣️",
    "ko": "BGP 라우팅·RPKI 보안",
    "en": "BGP Routing & RPKI Security",
    "desc_ko": "BGP-4 피어링·Exact/Sub-prefix LPM 하이재킹·AS-Path 위조·경로 누출·RPKI ROA 검증 및 MANRS 하드닝.",
    "desc_en": "BGP-4 peering, exact/sub-prefix LPM hijacking, AS-Path forgery, route leaks, RPKI ROA validation, and MANRS hardening."
}

RAW_CHALLENGES = [
    # Tier 0 (입문: 7 challenges, points 20~35)
    (0, "t0_bgp_rfc4271_fsm", 25,
     "BGP-4 프로토콜 유한 상태 머신(FSM) 6단계 천이",
     "BGP-4 Finite State Machine (FSM) Six States",
     "RFC 4271 BGP-4의 유한 상태 머신(Idle, Connect, Active, OpenSent, OpenConfirm, Established) 천이 규칙을 분석합니다.\n지정된 식별자 `bgp_rfc4271_fsm_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_rfc4271_fsm_v1\") 앞 20자리}`",
     "Analyze the six finite state machine transitions defined in RFC 4271 for BGP-4 peering.\nCompute the first 20 hex characters of SHA256(\"bgp_rfc4271_fsm_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_rfc4271_fsm_v1\") first 20 hex}`",
     ["RFC 4271 Section 8 BGP FSM 상태 전이 다이어그램을 확인하세요.", "식별자 `bgp_rfc4271_fsm_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review RFC 4271 Section 8 BGP FSM specifications.", "Extract first 20 hex chars of SHA256(\"bgp_rfc4271_fsm_v1\")."]),

    (0, "t0_bgp_message_types", 25,
     "BGP 4대 핵심 메시지 유형 및 패킷 헤더 구조",
     "BGP Four Core Message Types & Header Framing",
     "BGP 세션에서 교환되는 OPEN, UPDATE, KEEPALIVE, NOTIFICATION 4대 메시지 유형의 기능과 19바이트 공통 헤더를 분석합니다.\n지정된 식별자 `bgp_message_types_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_message_types_v1\") 앞 20자리}`",
     "Examine the four primary BGP message formats and 19-byte common header framing.\nCompute the first 20 hex characters of SHA256(\"bgp_message_types_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_message_types_v1\") first 20 hex}`",
     ["UPDATE 메시지가 경로 광고 및 철회(Withdrawn Routes)를 수행함을 파악하세요.", "식별자 `bgp_message_types_v1`의 해시 앞 20자리를 제출하세요."],
     ["Observe that UPDATE carries route announcements and withdrawals.", "Extract first 20 hex chars of SHA256(\"bgp_message_types_v1\")."]),

    (0, "t0_bgp_as_numbering", 30,
     "자율 시스템 번호(ASN) 체계 및 사설 ASN 범위",
     "Autonomous System Numbers (ASN) & Private ASN Ranges",
     "2바이트 및 4바이트(RFC 6793) ASN 구조와 RFC 6996 사설 ASN 대역(64512~65534, 4200000000~4294967294)을 분석합니다.\n지정된 식별자 `bgp_as_numbering_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_as_numbering_v1\") 앞 20자리}`",
     "Inspect 2-byte and 4-byte ASN allocations and standard private ASN allocations under RFC 6996.\nCompute the first 20 hex characters of SHA256(\"bgp_as_numbering_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_as_numbering_v1\") first 20 hex}`",
     ["인터넷상으로 사설 ASN이 누출되지 않도록 필터링해야 함을 확인하세요.", "식별자 `bgp_as_numbering_v1`의 해시 앞 20자리를 추출하세요."],
     ["Private ASNs must be stripped before egress to public peers.", "Extract first 20 hex chars of SHA256(\"bgp_as_numbering_v1\")."]),

    (0, "t0_bgp_path_attributes", 30,
     "BGP 경로 속성(Path Attributes) 4대 범주 분류",
     "BGP Path Attributes Four Category Classification",
     "Well-known Mandatory, Well-known Discretionary, Optional Transitive, Optional Non-transitive 속성의 전파 특성을 분석합니다.\n지정된 식별자 `bgp_path_attributes_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_path_attributes_v1\") 앞 20자리}`",
     "Categorize BGP path attributes into mandatory, discretionary, and optional classes.\nCompute the first 20 hex characters of SHA256(\"bgp_path_attributes_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_path_attributes_v1\") first 20 hex}`",
     ["ORIGIN, AS_PATH, NEXT_HOP이 Well-known Mandatory임을 확인하세요.", "식별자 `bgp_path_attributes_v1`의 해시 앞 20자리를 제출하세요."],
     ["ORIGIN, AS_PATH, and NEXT_HOP are Well-known Mandatory.", "Extract first 20 hex chars of SHA256(\"bgp_path_attributes_v1\")."]),

    (0, "t0_bgp_decision_process", 30,
     "BGP 최적 경로 선출(Best Path Selection) 순차 알고리즘",
     "BGP Best Path Selection Tie-Breaking Algorithm",
     "Weight, Local-Pref, Local Originated, AS-Path 길이, Origin, MED, eBGP 우선, IGP 메트릭 순의 의사결정 체계를 분석합니다.\n지정된 식별자 `bgp_decision_process_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_decision_process_v1\") 앞 20자리}`",
     "Analyze standard BGP best path tie-breaking sequence from Local-Pref down to router ID.\nCompute the first 20 hex characters of SHA256(\"bgp_decision_process_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_decision_process_v1\") first 20 hex}`",
     ["AS-Path 길이가 짧을수록 경로 우선순위가 높아집니다.", "식별자 `bgp_decision_process_v1`의 해시 앞 20자리를 추출하세요."],
     ["Shorter AS-Path attributes win before MED evaluation.", "Extract first 20 hex chars of SHA256(\"bgp_decision_process_v1\")."]),

    (0, "t0_rpki_roa_structure", 35,
     "RPKI 경로 원점 인가(ROA) 페이로드 및 유효성 구조",
     "RPKI Route Origin Authorization (ROA) Structure",
     "RFC 6482에 정의된 ROA의 핵심 필드(Prefix, MaxLength, Origin AS, X.509 End-Entity Certificate)를 분석합니다.\n지정된 식별자 `rpki_roa_structure_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"rpki_roa_structure_v1\") 앞 20자리}`",
     "Examine the cryptographic payload of Route Origin Authorizations (ROAs) under RFC 6482.\nCompute the first 20 hex characters of SHA256(\"rpki_roa_structure_v1\").\n\nFormat: `FLAG{SHA256(\"rpki_roa_structure_v1\") first 20 hex}`",
     ["ROA는 특정 AS가 해당 IP 접두사를 광고할 수 있는 유일한 권한 증명서입니다.", "식별자 `rpki_roa_structure_v1`의 해시 앞 20자리를 제출하세요."],
     ["ROAs bind authorized origin ASNs to IP address prefixes.", "Extract first 20 hex chars of SHA256(\"rpki_roa_structure_v1\")."]),

    (0, "t0_bgp_peering_model", 35,
     "Transit vs Settlement-Free 피어링 및 Valley-Free 원칙",
     "Transit vs Settlement-Free Peering & Valley-Free Routing",
     "Customer-to-Provider, Peer-to-Peer 경제적 계약 관계와 피어 간 경로 무단 전송을 금지하는 Valley-Free 라우팅 모델을 분석합니다.\n지정된 식별자 `bgp_peering_model_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_peering_model_v1\") 앞 20자리}`",
     "Study inter-AS commercial relationships and the Valley-Free rule forbidding peer route export.\nCompute the first 20 hex characters of SHA256(\"bgp_peering_model_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_peering_model_v1\") first 20 hex}`",
     ["피어로부터 받은 경로는 고객에게만 보내야 하며 다른 피어나 업스트림에 보내면 안 됩니다.", "식별자 `bgp_peering_model_v1`의 해시 앞 20자리를 추출하세요."],
     ["Routes learned from a peer must only be exported to customers.", "Extract first 20 hex chars of SHA256(\"bgp_peering_model_v1\")."]),

    # Tier 1 (기초: 7 challenges, points 40~65)
    (1, "t1_bgp_exact_prefix_hijack", 45,
     "동일 접두사(Exact Prefix) BGP 하이재킹 공격 원리",
     "Exact Prefix BGP Hijacking Exploitation",
     "공격자 AS가 합법적 소유자와 동일한 접두사를 위조 광고하여 더 짧은 AS-Path로 트래픽을 가로채는 공격을 분석합니다.\n지정된 식별자 `bgp_exact_prefix_hijack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_exact_prefix_hijack_v1\") 앞 20자리}`",
     "Simulate exact prefix hijacking where an attacker announces an identical CIDR block with shorter AS-Path.\nCompute the first 20 hex characters of SHA256(\"bgp_exact_prefix_hijack_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_exact_prefix_hijack_v1\") first 20 hex}`",
     ["동일 접두사 하이재킹은 BGP Best Path의 AS-Path 길이에 따라 전 세계 트래픽의 일부가 유인됩니다.", "식별자 `bgp_exact_prefix_hijack_v1`의 해시 앞 20자리를 제출하세요."],
     ["Traffic splits globally based on which origin presents a shorter AS-Path.", "Extract first 20 hex chars of SHA256(\"bgp_exact_prefix_hijack_v1\")."]),

    (1, "t1_bgp_subprefix_lpm", 45,
     "서브넷 분할 최장 접두사 일치(LPM) 하이재킹",
     "Sub-prefix Longest Prefix Match (LPM) Hijacking",
     "피해자의 /24 슈퍼넷을 /25 단위로 쪼개어 광고함으로써 AS-Path 길이에 상관없이 모든 트래픽을 흡수하는 최장 일치 공격을 분석합니다.\n지정된 식별자 `bgp_subprefix_lpm_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_subprefix_lpm_v1\") 앞 20자리}`",
     "Exploit Longest Prefix Match routing behavior by announcing more specific subnets to override aggregate routes.\nCompute the first 20 hex characters of SHA256(\"bgp_subprefix_lpm_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_subprefix_lpm_v1\") first 20 hex}`",
     ["IP 라우팅 엔진은 BGP 메트릭보다 더 긴 서브넷 마스크(Longest Prefix)를 항상 최우선 처리합니다.", "식별자 `bgp_subprefix_lpm_v1`의 해시 앞 20자리를 추출하세요."],
     ["Longest prefix match takes precedence over any AS-Path length metric.", "Extract first 20 hex chars of SHA256(\"bgp_subprefix_lpm_v1\")."]),

    (1, "t1_bgp_tcp_md5_flaws", 50,
     "RFC 2385 TCP MD5 Signature 취약점 및 TCP-AO 전환",
     "RFC 2385 TCP MD5 Flaws & RFC 5925 TCP-AO Migration",
     "BGP TCP 포트 179 피어링 보호에 사용되던 MD5 서명의 암호학적 한계와 RFC 5925 TCP-AO(Authentication Option) 전환을 분석합니다.\n지정된 식별자 `bgp_tcp_md5_flaws_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_tcp_md5_flaws_v1\") 앞 20자리}`",
     "Analyze cryptographic weaknesses in TCP MD5 Signature and modern TCP-AO authentication.\nCompute the first 20 hex characters of SHA256(\"bgp_tcp_md5_flaws_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_tcp_md5_flaws_v1\") first 20 hex}`",
     ["TCP-AO는 SHA-1/AES-128-CMAC 및 마스터 키 롤오버를 지원합니다.", "식별자 `bgp_tcp_md5_flaws_v1`의 해시 앞 20자리를 제출하세요."],
     ["TCP-AO provides master key rollover and HMAC-SHA1/AES-CMAC protection.", "Extract first 20 hex chars of SHA256(\"bgp_tcp_md5_flaws_v1\")."]),

    (1, "t1_bgp_ttl_security_gtsm", 50,
     "일반 TTL 보안 메커니즘(GTSM)을 통한 BGP 스푸핑 방어",
     "Generalized TTL Security Mechanism (GTSM, RFC 5082)",
     "eBGP 패킷의 IP TTL을 255로 전송하고 수신단에서 TTL 254 이상만 수용하여 원격지의 BGP 패킷 주입을 차단하는 GTSM을 분석합니다.\n지정된 식별자 `bgp_ttl_security_gtsm_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_ttl_security_gtsm_v1\") 앞 20자리}`",
     "Evaluate Generalized TTL Security Mechanism (GTSM) discarding spoofed off-path packets.\nCompute the first 20 hex characters of SHA256(\"bgp_ttl_security_gtsm_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_ttl_security_gtsm_v1\") first 20 hex}`",
     ["수신 패킷의 TTL이 254 미만이면 1-hop 피어가 아닌 외부에서 라우팅된 공격 패킷으로 간주합니다.", "식별자 `bgp_ttl_security_gtsm_v1`의 해시 앞 20자리를 추출하세요."],
     ["Packets with TTL below 254 are dropped as off-path forged injection attempts.", "Extract first 20 hex chars of SHA256(\"bgp_ttl_security_gtsm_v1\")."]),

    (1, "t1_bgp_route_flapping_dampening", 55,
     "BGP 경로 플래핑 감쇠(RFD) 악용 및 가용성 저해",
     "BGP Route Flap Damping (RFD, RFC 2439) Exploitation",
     "주기적인 경로 인출/재선언(Flapping)으로 인해 패널티가 누적되어 정상 경로가 장시간 억제(Suppressed)되는 RFD 부작용을 분석합니다.\n지정된 식별자 `bgp_route_flapping_dampening_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_route_flapping_dampening_v1\") 앞 20자리}`",
     "Study Route Flap Damping denial-of-service where flapping penalties suppress reachability.\nCompute the first 20 hex characters of SHA256(\"bgp_route_flapping_dampening_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_route_flapping_dampening_v1\") first 20 hex}`",
     ["RIPE-378/580 권고에 따라 플래핑 감쇠 임계값을 완화해야 무고한 경로 차단을 방지할 수 있습니다.", "식별자 `bgp_route_flapping_dampening_v1`의 해시 앞 20자리를 제출하세요."],
     ["Improper flap damping parameters cause collateral reachability blackouts.", "Extract first 20 hex chars of SHA256(\"bgp_route_flapping_dampening_v1\")."]),

    (1, "t1_rpki_rov_states", 60,
     "RPKI ROV 3대 검증 상태(Valid/Invalid/NotFound) 판정",
     "RPKI Route Origin Validation (ROV) Three Validation States",
     "BGP 라우터가 수신한 경로를 ROA 캐시와 대조하여 Valid, Invalid, NotFound/Unknown으로 분류하고 Invalid를 폐기하는 절차를 분석합니다.\n지정된 식별자 `rpki_rov_states_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"rpki_rov_states_v1\") 앞 20자리}`",
     "Model BGP route state evaluation against local ROA table producing Valid, Invalid, and NotFound.\nCompute the first 20 hex characters of SHA256(\"rpki_rov_states_v1\").\n\nFormat: `FLAG{SHA256(\"rpki_rov_states_v1\") first 20 hex}`",
     ["ROA가 존재하지만 Origin ASN이나 서브넷 길이가 맞지 않으면 Invalid로 판정되어 즉시 드롭됩니다.", "식별자 `rpki_rov_states_v1`의 해시 앞 20자리를 추출하세요."],
     ["Routes conflicting with existing ROA records evaluate to Invalid and must be dropped.", "Extract first 20 hex chars of SHA256(\"rpki_rov_states_v1\")."]),

    (1, "t1_bgp_blackholing_rtbh", 65,
     "원격 트리거 블랙홀(RTBH) BGP 커뮤니티 기반 트래픽 폐기",
     "Remotely Triggered Black Hole (RTBH, RFC 3882) Filtering",
     "공격 대상 IP를 특수 BGP 커뮤니티(예: 65535:666 또는 BLACKHOLE)로 광고하여 업스트림 ISP 라우터에서 Null0 폐기시키는 기법을 분석합니다.\n지정된 식별자 `bgp_blackholing_rtbh_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_blackholing_rtbh_v1\") 앞 20자리}`",
     "Examine Remotely Triggered Black Hole (RTBH) routing to discard distributed denial of service traffic at line rate.\nCompute the first 20 hex characters of SHA256(\"bgp_blackholing_rtbh_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_blackholing_rtbh_v1\") first 20 hex}`",
     ["Next-Hop을 미라우팅 가능 IP(192.0.2.1 등)로 재작성하여 패킷을 드롭시킵니다.", "식별자 `bgp_blackholing_rtbh_v1`의 해시 앞 20자리를 제출하세요."],
     ["Next-Hop rewrite forces border routers to drop matching traffic into Null0.", "Extract first 20 hex chars of SHA256(\"bgp_blackholing_rtbh_v1\")."]),

    # Tier 2 (중급: 7 challenges, points 70~95)
    (2, "t2_bgp_aspath_prepending", 70,
     "BGP AS-Path Prepending 남용 및 트래픽 유입 엔지니어링",
     "BGP AS-Path Prepending Manipulation & Traffic Engineering",
     "자신의 ASN을 여러 번 반복 삽입하여 특정 업스트림 경로의 길이를 인위적으로 늘려 인바운드 트래픽을 편향시키는 기법을 분석합니다.\n지정된 식별자 `bgp_aspath_prepending_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_aspath_prepending_v1\") 앞 20자리}`",
     "Analyze AS-Path prepending abuse for inbound traffic engineering and its routing side effects.\nCompute the first 20 hex characters of SHA256(\"bgp_aspath_prepending_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_aspath_prepending_v1\") first 20 hex}`",
     ["과도한 Prepending은 글로벌 라우팅 테이블 메모리를 낭비하며 악의적 경로 선호 조작에 악용될 수 있습니다.", "식별자 `bgp_aspath_prepending_v1`의 해시 앞 20자리를 추출하세요."],
     ["Excessive prepending inflates RIB size and distorts inter-AS path selection.", "Extract first 20 hex chars of SHA256(\"bgp_aspath_prepending_v1\")."]),

    (2, "t2_bgp_route_leak_rfc7908", 75,
     "RFC 7908 정의 BGP 경로 누출(Route Leak) 6대 유형 분석",
     "RFC 7908 BGP Route Leak Taxonomy & Detection",
     "Peer-to-Peer 또는 Provider-to-Provider로 수신한 경로를 다른 피어나 업스트림에 무단 재광고하여 트래픽 병목 및 감청을 유발하는 경로 누출을 분석합니다.\n지정된 식별자 `bgp_route_leak_rfc7908_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_route_leak_rfc7908_v1\") 앞 20자리}`",
     "Study the six distinct route leak classes defined in RFC 7908 violating valley-free peering invariants.\nCompute the first 20 hex characters of SHA256(\"bgp_route_leak_rfc7908_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_route_leak_rfc7908_v1\") first 20 hex}`",
     ["Type 1: transit 공급자로부터 받은 경로를 다른 transit 공급자에게 재광고하는 누출입니다.", "식별자 `bgp_route_leak_rfc7908_v1`의 해시 앞 20자리를 제출하세요."],
     ["Type 1 involves re-advertising transit routes to a transit provider.", "Extract first 20 hex chars of SHA256(\"bgp_route_leak_rfc7908_v1\")."]),

    (2, "t2_bgp_aspath_spoofing", 80,
     "BGP 1-Hop AS-Path 위조를 통한 RPKI 출처 검증 우회",
     "1-Hop AS-Path Forgery Bypassing RPKI Origin Validation",
     "공격자 AS가 합법적 소유자의 ASN을 AS-Path 끝에 덧붙여 광고함으로써 단순 RPKI Origin AS 일치 검사를 통과하는 위조 공격을 분석합니다.\n지정된 식별자 `bgp_aspath_spoofing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_aspath_spoofing_v1\") 앞 20자리}`",
     "Simulate 1-hop AS-Path spoofing where an attacker appends the victim origin ASN to satisfy basic ROV.\nCompute the first 20 hex characters of SHA256(\"bgp_aspath_spoofing_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_aspath_spoofing_v1\") first 20 hex}`",
     ["ROV는 AS-Path의 마지막 ASN(Origin)만 검증하므로 중간 경로의 위조는 탐지하지 못합니다.", "식별자 `bgp_aspath_spoofing_v1`의 해시 앞 20자리를 추출하세요."],
     ["ROV checks only the rightmost ASN in AS_PATH, leaving path sequence unverified.", "Extract first 20 hex chars of SHA256(\"bgp_aspath_spoofing_v1\")."]),

    (2, "t2_rpki_maxlength_vulnerability", 80,
     "느슨한 RPKI ROA MaxLength 설정으로 인한 서브넷 공격면",
     "Permissive ROA MaxLength Vulnerability to Sub-prefix Attacks",
     "예를 들어 /20 접두사에 대해 MaxLength /24를 지정했을 때 공격자가 /24 서브넷을 합법적으로 사칭할 수 있게 되는 설정 결함을 분석합니다.\n지정된 식별자 `rpki_maxlength_vulnerability_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"rpki_maxlength_vulnerability_v1\") 앞 20자리}`",
     "Inspect vulnerabilities arising from loose MaxLength parameters in ROA registrations.\nCompute the first 20 hex characters of SHA256(\"rpki_maxlength_vulnerability_v1\").\n\nFormat: `FLAG{SHA256(\"rpki_maxlength_vulnerability_v1\") first 20 hex}`",
     ["RFC 9319 권고에 따라 ROA의 MaxLength는 실제 광고 중인 접두사 길이와 엄격히 일치시켜야 합니다.", "식별자 `rpki_maxlength_vulnerability_v1`의 해시 앞 20자리를 제출하세요."],
     ["RFC 9319 mandates matching ROA MaxLength exactly to announced prefix lengths.", "Extract first 20 hex chars of SHA256(\"rpki_maxlength_vulnerability_v1\")."]),

    (2, "t2_bgp_communities_manipulation", 85,
     "BGP Large Communities(RFC 8092) 속성 조작 및 라우팅 제어",
     "BGP Large Communities (RFC 8092) Manipulation",
     "12바이트(4-byte Global Admin : 4-byte Data 1 : 4-byte Data 2) Large Communities 속성을 조작하여 업스트림 ISP의 지역 선호도를 강제 변경하는 공격을 분석합니다.\n지정된 식별자 `bgp_communities_manipulation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_communities_manipulation_v1\") 앞 20자리}`",
     "Analyze BGP Large Communities attribute manipulation overriding upstream routing decisions.\nCompute the first 20 hex characters of SHA256(\"bgp_communities_manipulation_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_communities_manipulation_v1\") first 20 hex}`",
     ["인가되지 않은 인바운드 커뮤니티 태그는 피어 인그레스 필터에서 반드시 제거(Strip)되어야 합니다.", "식별자 `bgp_communities_manipulation_v1`의 해시 앞 20자리를 추출하세요."],
     ["Border ingress policies must strip unauthorized customer community tags.", "Extract first 20 hex chars of SHA256(\"bgp_communities_manipulation_v1\")."]),

    (2, "t2_bgp_flowspec_rfc5575", 90,
     "BGP FlowSpec (RFC 5575/8955) 주입을 통한 트래픽 필터링 오용",
     "BGP FlowSpec (RFC 5575/8955) Injection & Traffic Redirection",
     "BGP를 통해 5-tuple 방화벽 규칙을 배포하는 FlowSpec을 위조 주입하여 특정 대역 트래픽을 리다이렉트하거나 전면 차단하는 공격을 분석합니다.\n지정된 식별자 `bgp_flowspec_rfc5575_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_flowspec_rfc5575_v1\") 앞 20자리}`",
     "Evaluate BGP FlowSpec rule propagation and risks of unauthorized dynamic ACL injection.\nCompute the first 20 hex characters of SHA256(\"bgp_flowspec_rfc5575_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_flowspec_rfc5575_v1\") first 20 hex}`",
     ["RFC 8955 검증 규칙에 따라 피어가 자신이 소유하지 않은 접두사에 FlowSpec 룰을 선언하면 거부해야 합니다.", "식별자 `bgp_flowspec_rfc5575_v1`의 해시 앞 20자리를 제출하세요."],
     ["RFC 8955 validation prevents peers from injecting FlowSpec rules for foreign prefixes.", "Extract first 20 hex chars of SHA256(\"bgp_flowspec_rfc5575_v1\")."]),

    (2, "t2_bgp_ibgp_split_horizon", 95,
     "iBGP 스플릿 호라이즌 및 Route Reflector 루프 방지 메커니즘",
     "iBGP Split-Horizon & Route Reflector Cluster Loop Prevention",
     "iBGP 피어 간 재광고 금지 규칙과 Route Reflector 도입 시 ORIGINATOR_ID 및 CLUSTER_LIST 속성을 통한 루프 방지 원리를 분석합니다.\n지정된 식별자 `bgp_ibgp_split_horizon_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_ibgp_split_horizon_v1\") 앞 20자리}`",
     "Study iBGP split-horizon constraints and loop avoidance attributes in Route Reflector topologies.\nCompute the first 20 hex characters of SHA256(\"bgp_ibgp_split_horizon_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_ibgp_split_horizon_v1\") first 20 hex}`",
     ["자신의 Cluster ID가 CLUSTER_LIST에 포함되어 있으면 라우팅 루프로 판단하여 경로를 폐기합니다.", "식별자 `bgp_ibgp_split_horizon_v1`의 해시 앞 20자리를 추출하세요."],
     ["Route reflectors drop announcements containing their own cluster identifier in CLUSTER_LIST.", "Extract first 20 hex chars of SHA256(\"bgp_ibgp_split_horizon_v1\")."]),

    # Tier 3 (고급: 7 challenges, points 100~135)
    (3, "t3_bgp_otc_attribute_rfc9234", 105,
     "RFC 9234 Only to Customer (OTC) 속성을 통한 경로 누출 차단",
     "RFC 9234 Only to Customer (OTC) Leak Prevention Architecture",
     "경로가 고객(Customer)에게 전달되는 순간 비추이적(Non-transitive) OTC 속성을 부여하여 다른 피어나 공급자에게 재광고되는 것을 방어하는 기법을 분석합니다.\n지정된 식별자 `bgp_otc_attribute_rfc9234_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_otc_attribute_rfc9234_v1\") 앞 20자리}`",
     "Examine RFC 9234 Only to Customer (OTC) BGP attribute mitigating route leaks across peering boundaries.\nCompute the first 20 hex characters of SHA256(\"bgp_otc_attribute_rfc9234_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_otc_attribute_rfc9234_v1\") first 20 hex}`",
     ["피어 또는 공급자 인터페이스로 유입된 경로에 이미 OTC가 세팅되어 있다면 경로 누출로 간주하여 차단합니다.", "식별자 `bgp_otc_attribute_rfc9234_v1`의 해시 앞 20자리를 제출하세요."],
     ["OTC flags detect route propagation violations across lateral peering links.", "Extract first 20 hex chars of SHA256(\"bgp_otc_attribute_rfc9234_v1\")."]),

    (3, "t3_rpki_aspa_verification", 110,
     "ASPA(Autonomous System Provider Authorization) 기반 상류 경로 검증",
     "ASPA Verification of Upstream AS-Path Validity",
     "고객 AS가 자신의 공인 상류 공급자(Provider) ASN 목록을 RPKI 객체로 서명 등록하고, BGP 라우터가 수신한 AS-Path의 업링크 무결성을 검증하는 ASPA를 분석합니다.\n지정된 식별자 `rpki_aspa_verification_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"rpki_aspa_verification_v1\") 앞 20자리}`",
     "Model Autonomous System Provider Authorization (ASPA) validating AS_PATH upstream sequence integrity.\nCompute the first 20 hex characters of SHA256(\"rpki_aspa_verification_v1\").\n\nFormat: `FLAG{SHA256(\"rpki_aspa_verification_v1\") first 20 hex}`",
     ["ASPA는 ROV가 감지하지 못하는 1-hop AS-Path 위조 및 중간 경로 조작을 암호학적으로 차단합니다.", "식별자 `rpki_aspa_verification_v1`의 해시 앞 20자리를 추출하세요."],
     ["ASPA fills the path validation gap left open by origin-only ROV.", "Extract first 20 hex chars of SHA256(\"rpki_aspa_verification_v1\")."]),

    (3, "t3_bgp_bgpsec_path_validation", 115,
     "BGPsec (RFC 8205) 홉별 디지털 서명 경로 무결성 아키텍처",
     "BGPsec (RFC 8205) Hop-by-Hop Cryptographic Path Validation",
     "각 중간 라우터가 수신한 경로에 자신의 서명과 다음 타깃 AS 번호를 서명 체인으로 엮어 AS-Path의 위변조를 원천 차단하는 BGPsec을 분석합니다.\n지정된 식별자 `bgp_bgpsec_path_validation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_bgpsec_path_validation_v1\") 앞 20자리}`",
     "Analyze BGPsec (RFC 8205) public key cryptography and secure path attribute signature nesting.\nCompute the first 20 hex characters of SHA256(\"bgp_bgpsec_path_validation_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_bgpsec_path_validation_v1\") first 20 hex}`",
     ["BGPsec은 모든 홉에서 ECDSA 서명을 연쇄 계산하므로 높은 라우터 연산 자원을 요구합니다.", "식별자 `bgp_bgpsec_path_validation_v1`의 해시 앞 20자리를 제출하세요."],
     ["BGPsec mandates nested ECDSA signatures from each autonomous system along the route.", "Extract first 20 hex chars of SHA256(\"bgp_bgpsec_path_validation_v1\")."]),

    (3, "t3_rpki_rtr_cache_sync", 120,
     "RPKI-Router (RTR, RFC 6810/8210) 캐시 동기화 보안",
     "RPKI-to-Router (RTR, RFC 6810/8210) Transport Security",
     "로컬 BGP 라우터가 RPKI 유효성 검사기(Routinator, Stayrtr)로부터 검증된 VRP(Validated ROA Payloads)를 수신하는 RTR 프로토콜과 SSH/TLS 보안 세션을 분석합니다.\n지정된 식별자 `rpki_rtr_cache_sync_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"rpki_rtr_cache_sync_v1\") 앞 20자리}`",
     "Evaluate RPKI-to-Router (RTR) cache synchronization protocols and transport protection requirements.\nCompute the first 20 hex characters of SHA256(\"rpki_rtr_cache_sync_v1\").\n\nFormat: `FLAG{SHA256(\"rpki_rtr_cache_sync_v1\") first 20 hex}`",
     ["평문 TCP RTR 세션은 내부자 공격에 의해 VRP 테이블이 변조될 위험이 있으므로 SSH나 IPsec이 권장됩니다.", "식별자 `rpki_rtr_cache_sync_v1`의 해시 앞 20자리를 추출하세요."],
     ["Unencrypted RTR sessions are susceptible to local man-in-the-middle VRP table spoofing.", "Extract first 20 hex chars of SHA256(\"rpki_rtr_cache_sync_v1\")."]),

    (3, "t3_bgp_manrs_enterprise_actions", 125,
     "MANRS 라우팅 보안 4대 필수 실천 규범 준수 체계",
     "MANRS Routing Security Four Essential Actions Framework",
     "필터링(Filtering), 위조 방지(Anti-Spoofing, uRPF), 상호 협력(Coordination), 글로벌 검증(Global Validation) 4대 행동 지침을 분석합니다.\n지정된 식별자 `bgp_manrs_enterprise_actions_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_manrs_enterprise_actions_v1\") 앞 20자리}`",
     "Assess enterprise conformance to Mutually Agreed Norms for Routing Security (MANRS) actions.\nCompute the first 20 hex characters of SHA256(\"bgp_manrs_enterprise_actions_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_manrs_enterprise_actions_v1\") first 20 hex}`",
     ["uRPF(Strict/Loose)를 적용하여 발신지 IP가 스푸핑된 패킷을 네트워크 경계에서 차단합니다.", "식별자 `bgp_manrs_enterprise_actions_v1`의 해시 앞 20자리를 제출하세요."],
     ["Unicast Reverse Path Forwarding (uRPF) stops IP spoofing at network perimeters.", "Extract first 20 hex chars of SHA256(\"bgp_manrs_enterprise_actions_v1\")."]),

    (3, "t3_bgp_evpn_vxlan_interas", 130,
     "BGP EVPN (RFC 7432) 컨트롤 플레인 및 Inter-AS 옵션 공격면",
     "BGP EVPN (RFC 7432) Control Plane & Inter-AS Option Vulnerabilities",
     "데이터센터 오버레이 네트워킹을 위한 EVPN Type 2(MAC/IP) 및 Type 5(IP Prefix) 라우트 광고와 Inter-AS Option B/C 연동 취약점을 분석합니다.\n지정된 식별자 `bgp_evpn_vxlan_interas_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_evpn_vxlan_interas_v1\") 앞 20자리}`",
     "Analyze BGP EVPN overlay routing architectures and multi-tenant isolation risks across Inter-AS borders.\nCompute the first 20 hex characters of SHA256(\"bgp_evpn_vxlan_interas_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_evpn_vxlan_interas_v1\") first 20 hex}`",
     ["EVPN 컨트롤 플레인에 Route-Target 및 VNI 필터링이 누락되면 테넌트 간 트래픽이 침범될 수 있습니다.", "식별자 `bgp_evpn_vxlan_interas_v1`의 해시 앞 20자리를 추출하세요."],
     ["Missing Route-Target validation across Inter-AS borders compromises EVPN isolation.", "Extract first 20 hex chars of SHA256(\"bgp_evpn_vxlan_interas_v1\")."]),

    (3, "t3_bgp_bmp_monitoring_rfc7854", 135,
     "BGP Monitoring Protocol (BMP, RFC 7854) 텔레메트리 이상 탐지",
     "BGP Monitoring Protocol (BMP, RFC 7854) Real-Time Anomaly Telemetry",
     "라우터의 정책 적용 전(Pre-policy) 및 적용 후(Post-policy) BGP 피어링 텔레메트리를 수집하여 비정상 경로 선언을 실시간 탐지하는 BMP를 분석합니다.\n지정된 식별자 `bgp_bmp_monitoring_rfc7854_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_bmp_monitoring_rfc7854_v1\") 앞 20자리}`",
     "Study BGP Monitoring Protocol telemetry ingestion pipelines for zero-day route hijack detection.\nCompute the first 20 hex characters of SHA256(\"bgp_bmp_monitoring_rfc7854_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_bmp_monitoring_rfc7854_v1\") first 20 hex}`",
     ["Pre-policy RIB 데이터를 모니터링하면 라우터가 버린 비정상 하이재킹 시도까지 모두 추적할 수 있습니다.", "식별자 `bgp_bmp_monitoring_rfc7854_v1`의 해시 앞 20자리를 제출하세요."],
     ["Pre-policy monitoring captures dropped malicious route advertisements prior to filter execution.", "Extract first 20 hex chars of SHA256(\"bgp_bmp_monitoring_rfc7854_v1\")."]),

    # Tier 4 (전문가: 7 challenges, points 150~500)
    (4, "t4_bgp_crypto_currency_dns_hijack", 150,
     "Amazon Route 53 BGP 하이재킹 및 가상자산 지갑 탈취 포렌식",
     "Amazon Route 53 BGP Hijack & Crypto Wallet Takeover Forensics",
     "실제 발생했던 205.251.192.0/24 DNS 접두사 하이재킹, 권위 DNS 서버 사칭, SSL 인증서 위조 및 지갑 자산 탈취 공격 체인을 심층 분석합니다.\n지정된 식별자 `bgp_crypto_currency_dns_hijack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_crypto_currency_dns_hijack_v1\") 앞 20자리}`",
     "Reconstruct the historic Amazon Route 53 BGP hijack leading to DNS spoofing and cryptocurrency theft.\nCompute the first 20 hex characters of SHA256(\"bgp_crypto_currency_dns_hijack_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_crypto_currency_dns_hijack_v1\") first 20 hex}`",
     ["공격자 AS10297이 /24 서브넷을 전 세계에 전파하여 합법적 DNS 트래픽을 가로챘습니다.", "식별자 `bgp_crypto_currency_dns_hijack_v1`의 해시 앞 20자리를 추출하세요."],
     ["Attacker AS10297 announced specific /24 DNS subnets redirecting target resolution to rogue servers.", "Extract first 20 hex chars of SHA256(\"bgp_crypto_currency_dns_hijack_v1\")."]),

    (4, "t4_bgp_tier1_transit_interception", 175,
     "글로벌 Tier-1 통신망 피어링 경로 누출 및 국가간 감청 시뮬레이션",
     "Global Tier-1 Transit Peering Route Leak & Interception Simulation",
     "대형 통신사(Tier-1 Transit) 간 상호접속 지점에서 발생하는 경로 누출로 인해 대륙 간 민감 트래픽이 제3국으로 우회 감청되는 시나리오를 모델링합니다.\n지정된 식별자 `bgp_tier1_transit_interception_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_tier1_transit_interception_v1\") 앞 20자리}`",
     "Simulate geopolitical traffic interception orchestrated via strategic Tier-1 inter-AS route leaks.\nCompute the first 20 hex characters of SHA256(\"bgp_tier1_transit_interception_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_tier1_transit_interception_v1\") first 20 hex}`",
     ["트래픽이 원래 목적지에 정상 도달하도록 루프백 중계(Man-in-the-Middle)하므로 탐지가 극히 어렵습니다.", "식별자 `bgp_tier1_transit_interception_v1`의 해시 앞 20자리를 제출하세요."],
     ["Stealthy MITM forwarding conceals inter-continental traffic detour from end users.", "Extract first 20 hex chars of SHA256(\"bgp_tier1_transit_interception_v1\")."]),

    (4, "t4_rpki_tal_compromise_risk", 200,
     "RIR Trust Anchor Locator (TAL) 키 손상 위험 및 복원 거버넌스",
     "RIR Trust Anchor Locator (TAL) Compromise & Governance Risk",
     "5대 대륙별 인터넷 레지스트리(RIR)의 루트 TAL 개인키가 유출되거나 오염될 경우 전 세계 RPKI 유효성 판정에 미치는 영향도를 평가합니다.\n지정된 식별자 `rpki_tal_compromise_risk_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"rpki_tal_compromise_risk_v1\") 앞 20자리}`",
     "Evaluate catastrophic cascading routing failures if a Regional Internet Registry TAL root key is compromised.\nCompute the first 20 hex characters of SHA256(\"rpki_tal_compromise_risk_v1\").\n\nFormat: `FLAG{SHA256(\"rpki_tal_compromise_risk_v1\") first 20 hex}`",
     ["TAL 키가 손상되면 공격자가 위조 ROA를 전역 배포하여 합법적 인터넷 경로를 일괄 Invalid로 만들 수 있습니다.", "식별자 `rpki_tal_compromise_risk_v1`의 해시 앞 20자리를 추출하세요."],
     ["Root TAL key compromise enables global blackholing via forged conflicting ROAs.", "Extract first 20 hex chars of SHA256(\"rpki_tal_compromise_risk_v1\")."]),

    (4, "t4_bgp_zero_trust_peering_architecture", 250,
     "인터넷 익스체인지(IXP) 무신뢰 라우트 서버 및 자동 방어 파이프라인",
     "Internet Exchange Point (IXP) Zero-Trust Route Server Pipeline",
     "수백 개 AS가 모이는 IXP Route Server(RS)에서 RPKI ROV, IRRDB 역방향 검증, max-prefix 및 RPKI Invalid 자동 격리 파이프라인을 분석합니다.\n지정된 식별자 `bgp_zero_trust_peering_architecture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_zero_trust_peering_architecture_v1\") 앞 20자리}`",
     "Design a Zero Trust IXP route server automated validation pipeline enforcing strict RPKI/IRR filtering.\nCompute the first 20 hex characters of SHA256(\"bgp_zero_trust_peering_architecture_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_zero_trust_peering_architecture_v1\") first 20 hex}`",
     ["ARouteServer 등 자동화 프레임워크를 연동하여 인간의 오설정 없는 자율 보안 필터를 확립합니다.", "식별자 `bgp_zero_trust_peering_architecture_v1`의 해시 앞 20자리를 제출하세요."],
     ["Automated route server policy generation guarantees reproducible routing security standards.", "Extract first 20 hex chars of SHA256(\"bgp_zero_trust_peering_architecture_v1\")."]),

    (4, "t4_bgp_quantum_resistant_bgpsec", 300,
     "양자 컴퓨팅 시대 BGPsec 무력화 위협 및 PQC 마이그레이션",
     "Quantum-Resistant Post-Quantum BGPsec Architecture",
     "Shor 알고리즘에 의한 BGPsec ECDSA 서명 위조 가능성과 ML-DSA, Falcon 등 NIST 포스트 퀀텀 암호화 기반 하이브리드 라우팅 보호를 분석합니다.\n지정된 식별자 `bgp_quantum_resistant_bgpsec_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_quantum_resistant_bgpsec_v1\") 앞 20자리}`",
     "Assess post-quantum cryptography migration challenges for BGPsec hop-by-hop signing under packet MTU constraints.\nCompute the first 20 hex characters of SHA256(\"bgp_quantum_resistant_bgpsec_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_quantum_resistant_bgpsec_v1\") first 20 hex}`",
     ["PQC 서명의 거대한 바이트 크기는 BGP 메시지 최대 길이(4096바이트)를 초과할 수 있어 확장 프로토콜이 필수적입니다.", "식별자 `bgp_quantum_resistant_bgpsec_v1`의 해시 앞 20자리를 추출하세요."],
     ["PQC signature size overhead challenges standard BGP UPDATE maximum buffer limitations.", "Extract first 20 hex chars of SHA256(\"bgp_quantum_resistant_bgpsec_v1\")."]),

    (4, "t4_bgp_soar_automated_ir_isolation", 350,
     "실시간 BMP 텔레메트리 연동 SOAR BGP 세션 자동 차단 및 우회",
     "SOAR Automated BGP Incident Response & Route Isolation",
     "이상 라우팅 탐지 즉시 BGP 피어 세션을 비상 종료하고 백업 터널로 트래픽을 자동 우회시키는 SOAR 자동화 플레이북을 분석합니다.\n지정된 식별자 `bgp_soar_automated_ir_isolation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_soar_automated_ir_isolation_v1\") 앞 20자리}`",
     "Architect automated SOAR playbooks reacting to BMP telemetry by shutting compromised peer sessions in seconds.\nCompute the first 20 hex characters of SHA256(\"bgp_soar_automated_ir_isolation_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_soar_automated_ir_isolation_v1\") first 20 hex}`",
     ["NETCONF/RESTCONF API를 통해 인시던트 발생 라우터에 자동화된 폐쇄 ACL을 즉각 주입합니다.", "식별자 `bgp_soar_automated_ir_isolation_v1`의 해시 앞 20자리를 제출하세요."],
     ["Programmatic NETCONF APIs teardown compromised peering sessions without manual operator delay.", "Extract first 20 hex chars of SHA256(\"bgp_soar_automated_ir_isolation_v1\")."]),

    (4, "t4_bgp_capstone_global_routing_audit", 500,
     "글로벌 BGP 라우팅·RPKI ROA 보안 침투 및 종합 감사 캡스톤",
     "Global BGP Routing & RPKI Security Audit Capstone",
     "BGP-4 Exact/Sub-prefix 하이재킹, AS-Path 조작, 경로 누출 침투, RPKI ROV/ASPA/MANRS 전방위 방어 체계를 총괄하는 종합 캡스톤입니다.\n지정된 식별자 `bgp_capstone_global_routing_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"bgp_capstone_global_routing_audit_v1\") 앞 20자리}`",
     "Capstone challenge synthesizing end-to-end BGP-4 routing attacks, RPKI ROV defense, ASPA path validation, and global MANRS hardening.\nCompute the first 20 hex characters of SHA256(\"bgp_capstone_global_routing_audit_v1\").\n\nFormat: `FLAG{SHA256(\"bgp_capstone_global_routing_audit_v1\") first 20 hex}`",
     ["엄격한 ROV, ASPA 공급자 검증, RFC 9234 OTC 태그 강제, uRPF 스푸핑 방어의 다계층 방어선을 확립하세요.", "식별자 `bgp_capstone_global_routing_audit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Deploy multi-layered defense: strict ROV, ASPA validation, OTC enforcement, and uRPF anti-spoofing.", "Submit first 20 hex of SHA256(\"bgp_capstone_global_routing_audit_v1\")."])
]

# Topic rows for wargame/README.md for each tier table (verified 0 collisions)
TIER_TOPIC_ROWS = {
    0: '| `bgp` 🛣️ BGP 라우팅·RPKI 보안 (7) | 자율시스템 유한상태머신·프로토콜 핵심메시지·사설식별번호체계·경로속성분류·최적경로선정알고리즘·자원인증체계인가서·피어링경제모델 / state machine transitions, protocol message types, autonomous numbering, path attribute classes, best path selection algorithm, origin authorization statements, peering economic models |',
    1: '| `bgp` 🛣️ BGP 라우팅·RPKI 보안 (7) | 동일접두사유인공격·서브넷최장일치가로채기·전송계층인증취약점·일반보안메커니즘·경로플래핑감쇠부작용·출처검증상태폐기정책·원격트리거블랙홀링 / exact prefix diversion, longest prefix match interception, transport authentication flaws, generalized ttl security, route flap dampening side effects, origin validation router discard policies, remotely triggered blackholing |',
    2: '| `bgp` 🛣️ BGP 라우팅·RPKI 보안 (7) | 인바운드경로프리펜딩조작·피어간경로누출유형분석·일차홉출처위조기만·최대길이설정오류취약점·커뮤니티속성변조정책교란·플로우스펙트래픽차단오용·내부라우팅스플릿호라이즌 / inbound prepending manipulation, inter-peer route leak taxonomy, one hop origin forgery, max length vulnerability exposure, communities attribute tampering, flowspec traffic filter abuse, internal split horizon route reflectors |',
    3: '| `bgp` 🛣️ BGP 라우팅·RPKI 보안 (7) | 고객전용속성경로누출방어·공급자권한암호학적검증·홉별디지털경로출처검증·라우터동기화프로토콜·보안라우팅필수실천규범·이더넷가상사설망상호연결·프로토콜모니터링원격측정 / only to customer leak prevention, autonomous provider authorization, hop-by-hop provenance path validation, router cache sync protocol, routing security normative actions, evpn inter-as interconnects, protocol monitoring telemetry |',
    4: '| `bgp` 🛣️ BGP 라우팅·RPKI 보안 (7) | 네임서버하이재킹추적·글로벌최상위통신망감청시뮬레이션·신뢰앵커키손상영향도평가·인터넷교환노드무신뢰피어링·양자내성차세대서명체계·보안오케스트레이션자동격리·글로벌라우팅보안감사캡스톤 / nameserver hijack forensics, global tier-one interception simulation, trust anchor compromise assessment, internet exchange zero trust peering, quantum resistant asymmetric framework, security orchestration auto isolation, global routing security audit capstone |'
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
            "cat": "bgp",
            "track": "bgp",
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
    print("[*] Generating 35 BGP track challenges...")
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
    print("  ✓ Updated challenges.js with 46th track and 35 challenges.")

    # 2. Update solve-derivable.js
    with open(SOLVE_DERIVABLE_JS, "r", encoding="utf-8") as f:
        sd_content = f.read()

    marker = '"t4_oauth_capstone_sso_exploitation_audit"'
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

    html = html.replace("0/1575", "0/1610")
    html = html.replace("1575", "1610")
    html = html.replace("45 트랙", "46 트랙")
    html = html.replace("45 tracks", "46 tracks")
    html = html.replace("45 Tracks", "46 Tracks")
    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print("  ✓ Updated index.html HUD counters to 1,610.")

    # 4. Update WARGAME_README
    if WARGAME_README.exists():
        with open(WARGAME_README, "r", encoding="utf-8") as f:
            readme = f.read()

        lines = readme.splitlines()
        new_lines = []
        oauth_match = "| `oauth` 🔑 OAuth 2.0·OIDC SSO 취약점 (7) |"
        for line in lines:
            new_lines.append(line)
            if line.startswith(oauth_match):
                tier_idx = sum(1 for l in new_lines if l.startswith(oauth_match)) - 1
                new_lines.append(TIER_TOPIC_ROWS[tier_idx])

        readme = "\n".join(new_lines) + "\n"
        readme = readme.replace("1,575", "1,610").replace("1575", "1610")
        readme = readme.replace("OAuth 2.0·OIDC SSO 취약점 35", "OAuth 2.0·OIDC SSO 취약점 35 · BGP 라우팅·RPKI 보안 35")
        readme = readme.replace("OAuth 2.0 & OIDC SSO Exploitation 35);", "OAuth 2.0 & OIDC SSO Exploitation 35 · BGP Routing & RPKI Security 35);")

        with open(WARGAME_README, "w", encoding="utf-8") as f:
            f.write(readme)
        print("  ✓ Updated wargame/README.md with 5 topic rows and 1,610 counts.")

    # 5. Update CLI_TEST
    if CLI_TEST.exists():
        with open(CLI_TEST, "r", encoding="utf-8") as f:
            clitest = f.read()
        clitest = clitest.replace("assert len(tracks) == 45", "assert len(tracks) == 46")
        clitest = clitest.replace("== 45", "== 46")
        clitest = clitest.replace("1575", "1610")
        if 'assert any(t["id"] == "oauth" for t in tracks)' in clitest and 'assert any(t["id"] == "bgp" for t in tracks)' not in clitest:
            clitest = clitest.replace(
                'assert any(t["id"] == "oauth" for t in tracks)',
                'assert any(t["id"] == "oauth" for t in tracks)\n    assert any(t["id"] == "bgp" for t in tracks)'
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
            r_content = r_content.replace("1,575", "1,610")
            r_content = r_content.replace("1575", "1610")
            r_content = r_content.replace("45 트랙", "46 트랙")
            r_content = r_content.replace("45 tracks", "46 tracks")
            r_content = r_content.replace("45 Tracks", "46 Tracks")
            r_content = r_content.replace("45개 트랙", "46개 트랙")
            r_content = r_content.replace("45 Wargame Tracks", "46 Wargame Tracks")
            with open(r_path, "w", encoding="utf-8") as f:
                f.write(r_content)
            print(f"  ✓ Updated {r_path.name}")

    print("[+] All assets updated successfully for 46 tracks and 1,610 challenges!")


if __name__ == "__main__":
    main()
