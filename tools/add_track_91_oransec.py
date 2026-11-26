#!/usr/bin/env python3
"""
Adds Track 91: oransec (6G NTN & O-RAN Telecom Infrastructure Security)
to wargame/assets/challenges.js, wargame/scripts/solve-derivable.js,
wargame/README.md, and wargame/index.html.
"""

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CHALLENGE_SPECS = [
    # Tier 0 (7)
    (0, "t0_oransec_disaggregated_ran_architecture_cu_du_ru", 15,
     "분리형 O-RAN CU/DU/RU 아키텍처 개요",
     "Disaggregated O-RAN CU, DU, and RU Architecture Overview",
     "전통적 일체형 기지국을 O-CU, O-DU, O-RU로 분리하고 개방형 인터페이스를 도입한 O-RAN 아키텍처의 보안 경계와 신뢰 모델을 분석합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_disaggregated_ran_architecture_cu_du_ru``\n\n[문제 안내]\n해당 O-RAN 분리형 아키텍처 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Analyze the security boundaries and trust model of the disaggregated O-RAN architecture splitting base stations into O-CU, O-DU, and O-RU.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_disaggregated_ran_architecture_cu_du_ru``\n\n[Task]\nAnalyze the disaggregated O-RAN specification, then derive and submit the flag."),
    (0, "t0_oransec_near_rt_ric_and_e2_interface_basics", 20,
     "Near-RT RIC 및 E2 인터페이스 기초",
     "Near-RT RIC and E2 Interface Fundamentals",
     "10ms~1s 주기 제어를 담당하는 Near-RT RIC와 E2 노드를 연결하는 E2AP 및 E2SM 서비스 모델의 공격 표면을 식별합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_near_rt_ric_and_e2_interface_basics``\n\n[문제 안내]\n해당 E2 인터페이스 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Identify the attack surface of Near-RT RIC and E2AP/E2SM service models controlling RAN nodes in the 10ms-1s loop.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_near_rt_ric_and_e2_interface_basics``\n\n[Task]\nAnalyze the E2 interface specification, then derive and submit the flag."),
    (0, "t0_oransec_open_fronthaul_ecpri_split_7_2x", 20,
     "Open Fronthaul eCPRI Split 7.2x 구조",
     "Open Fronthaul eCPRI Split 7.2x Structure",
     "O-DU와 O-RU를 연결하는 Open Fronthaul(CUS-Plane)의 eCPRI 패킷 구조와 비암호화 평문 노출 위험을 학습합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_open_fronthaul_ecpri_split_7_2x``\n\n[문제 안내]\n해당 Open Fronthaul 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Study the Open Fronthaul CUS-Plane eCPRI packet layout between O-DU and O-RU and plaintext exposure risks.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_open_fronthaul_ecpri_split_7_2x``\n\n[Task]\nAnalyze the Open Fronthaul specification, then derive and submit the flag."),
    (0, "t0_oransec_ieee_1588v2_ptp_timing_sync_threats", 25,
     "IEEE 1588v2 PTP 시간 동기화 위협",
     "IEEE 1588v2 PTP Timing Synchronization Threats",
     "TDD 무선 프레임 동기화를 위해 사용되는 IEEE 1588v2 PTP Grandmaster 스푸핑 및 시간 오프셋 드리프트 유발 위협을 파악합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_ieee_1588v2_ptp_timing_sync_threats``\n\n[문제 안내]\n해당 PTP 동기화 위협 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Examine IEEE 1588v2 PTP Grandmaster spoofing and phase drift threats affecting TDD radio frame synchronization.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_ieee_1588v2_ptp_timing_sync_threats``\n\n[Task]\nAnalyze the PTP timing threat specification, then derive and submit the flag."),
    (0, "t0_oransec_a1_o1_management_plane_exposure", 25,
     "A1 및 O1 관리 평면 노출 분석",
     "A1 and O1 Management Plane Exposure Analysis",
     "Non-RT RIC의 A1 정책 인터페이스와 SMO O1 NETCONF/YANG 관리 평면의 인증 미흡 시 발생하는 정책 변조 위험을 분석합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_a1_o1_management_plane_exposure``\n\n[문제 안내]\n해당 A1/O1 관리 평면 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Analyze policy tampering risks on the Non-RT RIC A1 interface and SMO O1 NETCONF/YANG management plane.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_a1_o1_management_plane_exposure``\n\n[Task]\nAnalyze the A1/O1 management plane specification, then derive and submit the flag."),
    (0, "t0_oransec_6g_ntn_leo_satellite_architecture", 25,
     "6G NTN 저궤도 위성 비지상망 아키텍처",
     "6G NTN LEO Satellite Non-Terrestrial Architecture",
     "지상 기지국과 저궤도(LEO) 위성 탑재 gNodeB가 통합되는 6G NTN(Non-Terrestrial Network) 환경의 확장된 공격 표면을 진단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_6g_ntn_leo_satellite_architecture``\n\n[문제 안내]\n해당 6G NTN 아키텍처 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Diagnose the expanded attack surface of 6G Non-Terrestrial Networks integrating terrestrial gNodeBs with LEO satellite payloads.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_6g_ntn_leo_satellite_architecture``\n\n[Task]\nAnalyze the 6G NTN architecture specification, then derive and submit the flag."),
    (0, "t0_oransec_network_slicing_multi_tenant_isolation", 25,
     "네트워크 슬라이싱 다중 테넌트 격리 기초",
     "Network Slicing Multi-Tenant Isolation Basics",
     "eMBB(SST 1), URLLC(SST 2), mMTC(SST 3) 슬라이스 간 SLA 보장과 자원 고갈 방어를 위한 테넌트 격리 원리를 정립합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_network_slicing_multi_tenant_isolation``\n\n[문제 안내]\n해당 네트워크 슬라이싱 격리 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Establish multi-tenant isolation principles across eMBB, URLLC, and mMTC slices to prevent cross-slice SLA starvation.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t0_oransec_network_slicing_multi_tenant_isolation``\n\n[Task]\nAnalyze the network slicing isolation specification, then derive and submit the flag."),

    # Tier 1 (7)
    (1, "t1_oransec_xapp_spiffe_svid_workload_identity", 50,
     "xApp SPIFFE SVID 워크로드 신원 검증",
     "xApp SPIFFE SVID Workload Identity Verification",
     "Near-RT RIC 내부에서 실행되는 서드파티 xApp에 SPIFFE SVID 인증서를 바인딩하여 위조 xApp 등록을 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_xapp_spiffe_svid_workload_identity``\n\n[문제 안내]\n해당 SPIFFE SVID 검증 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Bind SPIFFE SVID workload identities to Near-RT RIC xApps to block rogue xApp registration.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_xapp_spiffe_svid_workload_identity``\n\n[Task]\nAnalyze the SPIFFE SVID specification, then derive and submit the flag."),
    (1, "t1_oransec_e2_mtls_strict_cipher_enforcement", 55,
     "E2 인터페이스 엄격 mTLS 암호화 강제",
     "E2 Interface Strict mTLS Cipher Enforcement",
     "O-DU/O-CU와 Near-RT RIC 간 E2AP SCTP/TLS 채널에 상호 인증 mTLS 1.3을 적용하여 중간자 도청을 방어합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_e2_mtls_strict_cipher_enforcement``\n\n[문제 안내]\n해당 E2 mTLS 강제 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Enforce mutual TLS 1.3 across E2AP channels between RAN nodes and Near-RT RIC to block MitM eavesdropping.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_e2_mtls_strict_cipher_enforcement``\n\n[Task]\nAnalyze the E2 mTLS enforcement specification, then derive and submit the flag."),
    (1, "t1_oransec_ecpri_macsec_aes256gcm_protection", 60,
     "Open Fronthaul eCPRI MACsec AES-256-GCM",
     "Open Fronthaul eCPRI MACsec AES-256-GCM Protection",
     "프론트홀 C/U-Plane 계층 2 프레임에 IEEE 802.1AE MACsec AES-256-GCM 무결성 및 기밀성 보호를 적용합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_ecpri_macsec_aes256gcm_protection``\n\n[문제 안내]\n해당 MACsec 보호 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Apply IEEE 802.1AE MACsec AES-256-GCM integrity and confidentiality protection to Open Fronthaul C/U-plane frames.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_ecpri_macsec_aes256gcm_protection``\n\n[Task]\nAnalyze the MACsec protection specification, then derive and submit the flag."),
    (1, "t1_oransec_nts_secured_ptp_clock_boundary", 65,
     "NTS 인증 기반 PTP 경계 시계 방어",
     "NTS-Secured PTP Boundary Clock Defense",
     "Network Time Security(NTS) 인증과 130ns 3GPP 위상 드리프트 임계치 감시를 결합해 위조 Sync/Follow_Up 메시지를 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_nts_secured_ptp_clock_boundary``\n\n[문제 안내]\n해당 NTS-PTP 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Combine Network Time Security authentication with 130ns phase-drift monitoring to reject spoofed PTP Sync messages.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_nts_secured_ptp_clock_boundary``\n\n[Task]\nAnalyze the NTS-PTP defense specification, then derive and submit the flag."),
    (1, "t1_oransec_e2sm_kpm_schema_allowlist_filtering", 65,
     "E2SM-KPM 서비스 모델 스키마 화이트리스트",
     "E2SM-KPM Service Model Schema Allowlist Filtering",
     "ASN.1 PER 디코딩 취약점을 악용한 비정상 E2SM-KPM 텔레메트리 페이로드를 스키마 화이트리스트 검증으로 사전 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_e2sm_kpm_schema_allowlist_filtering``\n\n[문제 안내]\n해당 E2SM-KPM 스키마 필터링 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Block malformed E2SM-KPM ASN.1 PER payloads using strict service-model schema allowlist validation.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_e2sm_kpm_schema_allowlist_filtering``\n\n[Task]\nAnalyze the E2SM-KPM schema allowlist specification, then derive and submit the flag."),
    (1, "t1_oransec_o1_netconf_ssh_nacm_hardening", 70,
     "O1 NETCONF/YANG SSH NACM 접근 하드닝",
     "O1 NETCONF/YANG SSH NACM Access Hardening",
     "SMO와 O-RAN 노드 간 O1 NETCONF 구성 변경 작업에 NACM(NETCONF Access Control Model) 최소 권한 접근 정책을 적용합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_o1_netconf_ssh_nacm_hardening``\n\n[문제 안내]\n해당 O1 NETCONF NACM 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Enforce NACM least-privilege access policy across O1 NETCONF/YANG configuration sessions between SMO and RAN nodes.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_o1_netconf_ssh_nacm_hardening``\n\n[Task]\nAnalyze the O1 NETCONF NACM specification, then derive and submit the flag."),
    (1, "t1_oransec_upf_gtpu_teid_slice_segregation", 75,
     "UPF GTP-U TEID 슬라이스별 터널 격리",
     "UPF GTP-U TEID Per-Slice Tunnel Segregation",
     "5G/6G 코어 UPF의 N3/N9 GTP-U 터널 TEID를 슬라이스별로 엄격 격리하여 교차 슬라이스 패킷 주입을 방지합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_upf_gtpu_teid_slice_segregation``\n\n[문제 안내]\n해당 UPF TEID 격리 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Segregate UPF N3/N9 GTP-U TEIDs per network slice to prevent cross-slice tunnel packet injection.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t1_oransec_upf_gtpu_teid_slice_segregation``\n\n[Task]\nAnalyze the UPF TEID segregation specification, then derive and submit the flag."),

    # Tier 2 (7)
    (2, "t2_oransec_a1_policy_poisoning_jwt_jws_defense", 100,
     "A1 정책 포이즈닝 서명 JWS 방어",
     "A1 Policy Poisoning Signed JWS Defense",
     "Non-RT RIC rApp이 전달하는 A1-P 정책 JSON 객체에 JWS 전자서명과 스키마 무결성 검증을 강제해 SLA 기아 공격을 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_a1_policy_poisoning_jwt_jws_defense``\n\n[문제 안내]\n해당 A1 JWS 서명 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Enforce JWS cryptographic signatures on A1-P policy payloads from Non-RT RIC rApps to stop slice starvation.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_a1_policy_poisoning_jwt_jws_defense``\n\n[Task]\nAnalyze the A1 JWS defense specification, then derive and submit the flag."),
    (2, "t2_oransec_xapp_conflict_mitigation_and_arbitration", 110,
     "다중 xApp 제어 충돌 중재 및 차단",
     "Multi-xApp Control Conflict Mitigation and Arbitration",
     "서로 다른 xApp이 동일 PRB 자원에 상충하는 제어 명령을 내려 기지국 가용성을 떨어뜨리는 간접 충돌 공격을 중재 엔진으로 방어합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_xapp_conflict_mitigation_and_arbitration``\n\n[문제 안내]\n해당 xApp 충돌 중재 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Deploy a Near-RT RIC conflict mitigation arbiter to prevent competing xApp PRB directives from degrading availability.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_xapp_conflict_mitigation_and_arbitration``\n\n[Task]\nAnalyze the xApp conflict arbitration specification, then derive and submit the flag."),
    (2, "t2_oransec_rogue_gnb_imsi_catcher_detection", 120,
     "불법 위조 gNodeB IMSI 캐처 탐지",
     "Rogue gNodeB and 5G/6G IMSI Catcher Detection",
     "SUCI 비식별화 다운그레이드 및 위조 SIB1 브로드캐스트를 수행하는 불법 기지국을 E2SM-KPM RF 지문 분석으로 탐지합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_rogue_gnb_imsi_catcher_detection``\n\n[문제 안내]\n해당 불법 기지국 탐지 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Detect rogue gNodeBs attempting SUCI downgrade or spoofed SIB1 broadcasts using E2SM-KPM RF fingerprinting.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_rogue_gnb_imsi_catcher_detection``\n\n[Task]\nAnalyze the rogue gNodeB detection specification, then derive and submit the flag."),
    (2, "t2_oransec_f1_e1_interface_ipsec_ikev2_tunnel", 125,
     "F1 및 E1 미드홀 IPsec IKEv2 터널 보호",
     "F1 and E1 Midhaul IPsec IKEv2 Tunnel Hardening",
     "O-CU-CP, O-CU-UP, O-DU 간 F1/E1 인터페이스에 IKEv2 기반 IPsec ESP 터널과 완벽한 순방향 비밀성(PFS)을 구성합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_f1_e1_interface_ipsec_ikev2_tunnel``\n\n[문제 안내]\n해당 F1/E1 IPsec 터널 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Configure IKEv2 IPsec ESP tunnels with PFS across F1 and E1 midhaul interfaces linking O-CU-CP, O-CU-UP, and O-DU.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_f1_e1_interface_ipsec_ikev2_tunnel``\n\n[Task]\nAnalyze the F1/E1 IPsec hardening specification, then derive and submit the flag."),
    (2, "t2_oransec_o_cloud_kubernetes_cnf_runtime_sec", 130,
     "O-Cloud 쿠버네티스 CNF 런타임 격리",
     "O-Cloud Kubernetes CNF Runtime Isolation",
     "vDU/vCU CNF 컨테이너 워크로드의 특권 상승 및 DPDK 호스트 네트워크 탈출을 restricted container security 표준과 Seccomp-BPF로 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_o_cloud_kubernetes_cnf_runtime_sec``\n\n[문제 안내]\n해당 O-Cloud CNF 격리 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Block vDU/vCU CNF container escapes over DPDK interfaces using restricted container security and Seccomp-BPF profiles.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_o_cloud_kubernetes_cnf_runtime_sec``\n\n[Task]\nAnalyze the O-Cloud CNF isolation specification, then derive and submit the flag."),
    (2, "t2_oransec_6g_ntn_doppler_ephemeris_validation", 140,
     "6G NTN 위성 천체력 및 도플러 무결성 검증",
     "6G NTN Ephemeris and Doppler Shift Integrity Validation",
     "LEO 위성 브로드캐스트 천체력(Ephemeris) 스푸핑을 통한 UE 타이밍 어드밴스 오작동 공격을 칼만 필터 교차 검증으로 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_6g_ntn_doppler_ephemeris_validation``\n\n[문제 안내]\n해당 NTN 천체력 검증 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Validate LEO satellite ephemeris and Doppler shift telemetry via Kalman cross-checks to stop UE timing advance spoofing.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_6g_ntn_doppler_ephemeris_validation``\n\n[Task]\nAnalyze the NTN ephemeris validation specification, then derive and submit the flag."),
    (2, "t2_oransec_5g_aka_suci_privacy_profile_b_audit", 150,
     "5G-AKA SUCI ECIES Profile B 프라이버시 감사",
     "5G-AKA SUCI ECIES Profile B Privacy Audit",
     "가입자 영구 식별자 SUPI가 무선 구간에 평문 노출(Null Scheme)되지 않도록 ECIES Profile B(Curve25519) 암호화를 감사·강제합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_5g_aka_suci_privacy_profile_b_audit``\n\n[문제 안내]\n해당 SUCI Profile B 감사 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Audit and enforce ECIES Profile B encryption for SUCI concealment so SUPI is never leaked via the Null Scheme.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t2_oransec_5g_aka_suci_privacy_profile_b_audit``\n\n[Task]\nAnalyze the SUCI Profile B audit specification, then derive and submit the flag."),

    # Tier 3 (7)
    (3, "t3_oransec_ric_ebpf_xdp_ecpri_flood_mitigation", 200,
     "eBPF XDP 기반 eCPRI 프론트홀 플러딩 완화",
     "eBPF XDP eCPRI Fronthaul Flood Mitigation",
     "O-DU NIC 드라이버 단의 eBPF XDP 프로그램으로 비정상 eCPRI 페이로드 플러딩을 0ms 와이어 속도로 드롭합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_ric_ebpf_xdp_ecpri_flood_mitigation``\n\n[문제 안내]\n해당 eBPF XDP 프론트홀 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Drop malformed eCPRI fronthaul flood packets at wire speed directly in the O-DU NIC driver using eBPF XDP.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_ric_ebpf_xdp_ecpri_flood_mitigation``\n\n[Task]\nAnalyze the eBPF XDP fronthaul mitigation specification, then derive and submit the flag."),
    (3, "t3_oransec_ai_ml_r1_model_poisoning_guard", 210,
     "R1 인터페이스 AI/ML xApp 모델 중독 방어",
     "R1 Interface AI/ML xApp Model Poisoning Defense",
     "Non-RT RIC에서 Near-RT RIC으로 배포되는 트래픽 스티어링 AI/ML 모델의 가중치 서명과 적대적 섭동 내성을 검증합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_ai_ml_r1_model_poisoning_guard``\n\n[문제 안내]\n해당 R1 AI 모델 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Verify cryptographic weight signatures and adversarial robustness for AI/ML traffic-steering models deployed over R1.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_ai_ml_r1_model_poisoning_guard``\n\n[Task]\nAnalyze the R1 AI model defense specification, then derive and submit the flag."),
    (3, "t3_oransec_6g_ntn_isl_beam_hopping_anti_jamming", 220,
     "6G NTN 위성 간 빔 호핑 항재밍 방어",
     "6G NTN Inter-Satellite Beam Hopping Anti-Jamming",
     "고출력 지상 재머의 협대역/추종 재밍에 대응해 동적 빔 호핑 시퀀스와 확산 대역 패턴을 암호학적으로 랜덤화합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_6g_ntn_isl_beam_hopping_anti_jamming``\n\n[문제 안내]\n해당 빔 호핑 항재밍 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Randomize dynamic beam-hopping schedules cryptographically to defeat narrowband and follower jamming on 6G NTN links.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_6g_ntn_isl_beam_hopping_anti_jamming``\n\n[Task]\nAnalyze the beam-hopping anti-jamming specification, then derive and submit the flag."),
    (3, "t3_oransec_intel_tdx_ocloud_vdu_attestation", 230,
     "Intel TDX 기반 O-Cloud vDU 기밀 원격 증명",
     "Intel TDX O-Cloud vDU Confidential Attestation",
     "공용 엣지 서버에서 구동되는 vDU 기저대역 메모리 평문 탈취를 막기 위해 Intel TDX TD Quote 하드웨어 원격 증명을 수행합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_intel_tdx_ocloud_vdu_attestation``\n\n[문제 안내]\n해당 O-Cloud TDX 원격 증명 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Perform Intel TDX TD Quote hardware attestation to protect vDU baseband keys and memory on shared edge servers.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_intel_tdx_ocloud_vdu_attestation``\n\n[Task]\nAnalyze the O-Cloud TDX attestation specification, then derive and submit the flag."),
    (3, "t3_oransec_sba_http2_oauth2_nrf_token_hardening", 240,
     "5G/6G 코어 SBA HTTP/2 NRF OAuth2 하드닝",
     "5G/6G Core SBA HTTP/2 NRF OAuth2 Hardening",
     "AMF/SMF/UPF 서비스 기반 아키텍처(SBA) 간 NRF 액세스 토큰 재전송 탈취를 RFC 9449 DPoP 및 mTLS 바인딩으로 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_sba_http2_oauth2_nrf_token_hardening``\n\n[문제 안내]\n해당 SBA NRF OAuth2 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Bind 5G/6G Core SBA NRF OAuth2 access tokens to mTLS and RFC 9449 DPoP proofs to prevent NF impersonation.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_sba_http2_oauth2_nrf_token_hardening``\n\n[Task]\nAnalyze the SBA NRF OAuth2 specification, then derive and submit the flag."),
    (3, "t3_oransec_x2_xn_handover_replay_protection", 250,
     "Xn/X2 기지국 간 핸드오버 재전송 방어",
     "Xn and X2 Inter-gNodeB Handover Replay Protection",
     "지상 gNodeB와 위성 기지국 간 Xn 핸드오버 시 NH/NCC 키 체인 갱신과 단조 증가 카운터 검증으로 키 재사용 공격을 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_x2_xn_handover_replay_protection``\n\n[문제 안내]\n해당 Xn 핸드오버 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Enforce NH/NCC key chaining and monotonic counter checks during terrestrial-to-NTN Xn handovers to block key reuse.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_x2_xn_handover_replay_protection``\n\n[Task]\nAnalyze the Xn handover protection specification, then derive and submit the flag."),
    (3, "t3_oransec_smo_supply_chain_sigstore_cosign", 260,
     "SMO rApp/xApp 공급망 Sigstore Cosign 서명",
     "SMO rApp and xApp Supply Chain Sigstore Cosign",
     "O-RAN 마켓플레이스에서 유입되는 xApp/rApp 컨테이너 이미지의 SBOM 및 Sigstore Cosign 키리스 서명을 어드미션 단계에서 검증합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_smo_supply_chain_sigstore_cosign``\n\n[문제 안내]\n해당 SMO 공급망 서명 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Verify SBOM provenance and Sigstore Cosign keyless signatures at admission before deploying xApp/rApp images.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t3_oransec_smo_supply_chain_sigstore_cosign``\n\n[Task]\nAnalyze the SMO supply chain specification, then derive and submit the flag."),

    # Tier 4 (7)
    (4, "t4_oransec_pqc_mlkem768_ntn_handover_kem", 350,
     "6G NTN FIPS 203 ML-KEM-768 하이브리드 핸드오버",
     "6G NTN FIPS 203 ML-KEM-768 Hybrid Handover",
     "광역 위성 빔 도청(SNDL)을 무력화하기 위해 Xn 핸드오버 키 합의를 하이브리드 X25519_MLKEM768로 전환합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_pqc_mlkem768_ntn_handover_kem``\n\n[문제 안내]\n해당 NTN ML-KEM-768 핸드오버 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Upgrade 6G NTN Xn handover key agreement to hybrid X25519_MLKEM768 to neutralize Harvest-Now-Decrypt-Later.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_pqc_mlkem768_ntn_handover_kem``\n\n[Task]\nAnalyze the NTN ML-KEM-768 handover specification, then derive and submit the flag."),
    (4, "t4_oransec_fips204_mldsa65_ric_attestation", 370,
     "NIST FIPS 204 ML-DSA-65 RIC 원격 증명",
     "NIST FIPS 204 ML-DSA-65 RIC Remote Attestation",
     "Near-RT RIC 플랫폼의 부트 측정값과 xApp 실행 무결성을 사후양자 전자서명 ML-DSA-65로 원격 증명합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_fips204_mldsa65_ric_attestation``\n\n[문제 안내]\n해당 ML-DSA-65 RIC 증명 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Attest Near-RT RIC boot measurements and xApp execution integrity with post-quantum NIST FIPS 204 ML-DSA-65.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_fips204_mldsa65_ric_attestation``\n\n[Task]\nAnalyze the ML-DSA-65 RIC attestation specification, then derive and submit the flag."),
    (4, "t4_oransec_zero_trust_multi_orbit_quorum", 400,
     "다중 궤도 6G NTN 비잔틴 핸드오버 쿼럼",
     "Multi-Orbit 6G NTN Byzantine Handover Quorum",
     "LEO/MEO 위성 간 동시 핸드오버 시 침해된 위성 노드의 거짓 궤도 라우팅을 최소 3노드 쿼럼 합의로 격리합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_zero_trust_multi_orbit_quorum``\n\n[문제 안내]\n해당 다중 궤도 쿼럼 합의 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Isolate compromised satellite handover relays across LEO/MEO orbits using a minimum 3-node Byzantine quorum.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_zero_trust_multi_orbit_quorum``\n\n[Task]\nAnalyze the multi-orbit quorum specification, then derive and submit the flag."),
    (4, "t4_oransec_autonomous_soar_ran_slice_healing", 420,
     "자율 SOAR 기반 O-RAN 슬라이스 자가 치유",
     "Autonomous SOAR O-RAN Slice Self-Healing",
     "eBPF와 E2SM 텔레메트리 이상 탐지 시 침해된 xApp을 즉시 격리하고 URLLC 슬라이스 대역폭을 자동 복구하는 SOAR 루프를 검증합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_autonomous_soar_ran_slice_healing``\n\n[문제 안내]\n해당 자율 슬라이스 자가 치유 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Validate an autonomous SOAR loop that isolates compromised xApps and restores URLLC slice SLA upon eBPF alerts.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_autonomous_soar_ran_slice_healing``\n\n[Task]\nAnalyze the autonomous slice self-healing specification, then derive and submit the flag."),
    (4, "t4_oransec_tpm2_quote_vran_hardware_root", 440,
     "vRAN 서버 TPM 2.0 Quote 하드웨어 신뢰점",
     "vRAN Server TPM 2.0 Quote Hardware Root of Trust",
     "원격 셀 사이트 O-DU 서버의 펌웨어 변조를 TPM 2.0 Quote PCR 교차 검증과 상수 시간 HMAC 감사로 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_tpm2_quote_vran_hardware_root``\n\n[문제 안내]\n해당 vRAN TPM 2.0 Quote 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Block firmware tampering on remote cell-site O-DU servers using TPM 2.0 Quote PCR checks and constant-time HMAC.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_tpm2_quote_vran_hardware_root``\n\n[Task]\nAnalyze the vRAN TPM 2.0 Quote specification, then derive and submit the flag."),
    (4, "t4_oransec_cross_domain_6g_core_ran_telemetry", 460,
     "6G 코어-RAN 교차 도메인 위협 상관 분석",
     "6G Core-RAN Cross-Domain Threat Correlation",
     "UPF GTP-U 이상 트래픽과 Near-RT RIC E2 제어 명령을 실시간 상관 분석하여 지능형 통신망 APT 횡적 이동을 차단합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_cross_domain_6g_core_ran_telemetry``\n\n[문제 안내]\n해당 교차 도메인 상관 분석 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Correlate UPF GTP-U anomalies with Near-RT RIC E2 control events in real time to stop telecom APT lateral movement.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_cross_domain_6g_core_ran_telemetry``\n\n[Task]\nAnalyze the cross-domain correlation specification, then derive and submit the flag."),
    (4, "t4_oransec_sovereign_6g_ntn_oran_capstone", 500,
     "주권 6G NTN & O-RAN 제로 트러스트 캡스톤",
     "Sovereign 6G NTN and O-RAN Zero-Trust Capstone",
     "E2 SPIFFE mTLS, eCPRI MACsec+NTS-PTP, A1 JWS+TEID 격리, X25519_MLKEM768+ML-DSA-65를 통합한 통신망 제로 트러스트 아키텍처를 완성합니다.\n\n[챌린지 식별자]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_sovereign_6g_ntn_oran_capstone``\n\n[문제 안내]\n해당 6G NTN & O-RAN 캡스톤 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Complete the sovereign Zero-Trust 6G NTN & O-RAN architecture integrating E2 mTLS, eCPRI MACsec, A1 JWS, and PQC handovers.\n\n[Challenge Identifier]\n`ORANSEC_CHALLENGE_ID: `t4_oransec_sovereign_6g_ntn_oran_capstone``\n\n[Task]\nAnalyze the 6G NTN & O-RAN capstone specification, then derive and submit the flag."),
]


def main() -> None:
    formatted_challenges = []
    challenge_ids = []

    for tier, cid, pts, title_ko, title_en, prompt_ko, prompt_en in CHALLENGE_SPECS:
        challenge_ids.append(cid)
        flag_hash = hashlib.sha256(f"{cid}_vibe_oransec_2026".encode("utf-8")).hexdigest()[:20]
        flag_str = f"FLAG{{{flag_hash}}}"
        ch_hash = hashlib.sha256(flag_str.encode("utf-8")).hexdigest()
        formatted_challenges.append({
            "id": cid,
            "tier": tier,
            "cat": "network",
            "track": "oransec",
            "points": pts,
            "ci": False,
            "hash": ch_hash,
            "fmt": "FLAG{...}",
            "title": {"ko": title_ko, "en": title_en},
            "prompt": {"ko": prompt_ko, "en": prompt_en},
            "hints": {
                "ko": [f"이 문제는 식별자 `{cid}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."],
                "en": [f"This challenge derives a deterministic flag from identifier `{cid}`."],
            },
        })

    chall_file = REPO_ROOT / "wargame" / "assets" / "challenges.js"
    content = chall_file.read_text(encoding="utf-8")

    if '"id": "oransec"' not in content:
        track_def = """  },
  {
    "id": "oransec",
    "icon": "📡",
    "ko": "6G NTN & O-RAN 통신망 보안",
    "en": "6G NTN & O-RAN Telecom Security",
    "desc_ko": "O-RAN Near-RT RIC E2 SPIFFE mTLS, Open Fronthaul eCPRI MACsec 및 IEEE 1588v2 PTP NTS 동기화 방어, A1/O1 정책 JWS 서명 및 UPF TEID 슬라이스 격리, 6G NTN FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 핸드오버 원격 증명.",
    "desc_en": "O-RAN Near-RT RIC E2 SPIFFE mTLS, Open Fronthaul eCPRI MACsec and NTS-secured PTP timing, A1 signed policy and UPF slice TEID isolation, and 6G NTN FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 handover attestation."
  }
];"""
        content = content.replace("  }\n];\n\nconst CHALLENGES =", track_def + "\n\nconst CHALLENGES =")

    if f'"id": "{CHALLENGE_SPECS[0][1]}"' not in content:
        ch_json_lines = [
            "  " + json.dumps(ch, ensure_ascii=False, indent=2).replace("\n", "\n  ")
            for ch in formatted_challenges
        ]
        insert_text = ",\n" + ",\n".join(ch_json_lines) + "\n];"
        last_bracket_idx = content.rfind("];")
        if last_bracket_idx != -1:
            content = content[:last_bracket_idx] + insert_text + content[last_bracket_idx + 2:]
            chall_file.write_text(content, encoding="utf-8")
            print("[+] Added 35 challenges to wargame/assets/challenges.js")

    solve_file = REPO_ROOT / "wargame" / "scripts" / "solve-derivable.js"
    s_content = solve_file.read_text(encoding="utf-8")
    if "ORANSEC_IDS" not in s_content:
        oransec_code = (
            "\nconst ORANSEC_IDS = [\n"
            + ",\n".join(f'  "{cid}"' for cid in challenge_ids)
            + "\n];\n\n"
            + "for (const id of ORANSEC_IDS) {\n"
            + "  SOLVERS.set(id, {\n"
            + "    kind: 'computed',\n"
            + "    via: 'SHA256 of identifier in prompt',\n"
            + "    solve: (ch) => {\n"
            + "      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');\n"
            + "      const m = text.match(/ORANSEC_CHALLENGE_ID:\\s*`([^`]+)`/);\n"
            + "      const ident = m ? m[1] : ch.id;\n"
            + "      const hash = crypto.createHash('sha256').update(ident + '_vibe_oransec_2026').digest('hex').slice(0, 20);\n"
            + "      return `FLAG{${hash}}`;\n"
            + "    }\n"
            + "  });\n"
            + "}\n"
        )
        declined_idx = s_content.find("const DECLINED =")
        if declined_idx != -1:
            s_content = s_content[:declined_idx] + oransec_code + "\n" + s_content[declined_idx:]
            solve_file.write_text(s_content, encoding="utf-8")
            print("[+] Added oransec solvers to wargame/scripts/solve-derivable.js")

    readme_file = REPO_ROOT / "wargame" / "README.md"
    r_content = readme_file.read_text(encoding="utf-8")
    if "`oransec`" not in r_content:
        tier_topics = {
            0: "| `oransec` 📡 6G NTN & O-RAN 통신망 보안 (7) | 분리형 CU/DU/RU 아키텍처 · Near-RT RIC E2 인터페이스 · Open Fronthaul eCPRI Split 7.2x · IEEE 1588v2 PTP 동기화 위협 · A1/O1 관리 평면 노출 · 6G NTN LEO 위성망 · 네트워크 슬라이싱 격리 / Disaggregated CU/DU/RU, Near-RT RIC E2 interface, eCPRI Split 7.2x, PTP sync threats, A1/O1 exposure, 6G NTN LEO architecture, and network slicing isolation |",
            1: "| `oransec` 📡 6G NTN & O-RAN 통신망 보안 (7) | xApp SPIFFE SVID 워크로드 신원 · E2 엄격 mTLS 강제 · eCPRI MACsec AES-256-GCM · NTS-PTP 경계 시계 방어 · E2SM-KPM 스키마 화이트리스트 · O1 NETCONF NACM RBAC · UPF GTP-U TEID 슬라이스 격리 / xApp SPIFFE SVID identity, E2 strict mTLS, eCPRI MACsec AES-256-GCM, NTS-PTP boundary defense, E2SM-KPM schema allowlist, O1 NETCONF RBAC, and UPF TEID segregation |",
            2: "| `oransec` 📡 6G NTN & O-RAN 통신망 보안 (7) | A1 정책 포이즈닝 JWS 서명 방어 · 다중 xApp 제어 충돌 중재 · 불법 gNodeB IMSI 캐처 탐지 · F1/E1 미드홀 IPsec IKEv2 · O-Cloud K8s CNF 런타임 격리 · 6G NTN 천체력 및 도플러 검증 · 5G-AKA SUCI Profile B 감사 / A1 JWS defense, multi-xApp conflict arbitration, rogue gNodeB detection, F1/E1 IPsec IKEv2, O-Cloud CNF isolation, NTN ephemeris validation, and SUCI Profile B audit |",
            3: "| `oransec` 📡 6G NTN & O-RAN 통신망 보안 (7) | eBPF XDP eCPRI 프론트홀 플러딩 완화 · R1 AI/ML xApp 모델 중독 방어 · 6G NTN 빔 호핑 항재밍 · Intel TDX O-Cloud vDU 원격 증명 · 5G/6G SBA NRF OAuth2 DPoP · Xn 핸드오버 재전송 방어 · SMO Sigstore Cosign 공급망 서명 / eBPF XDP eCPRI mitigation, R1 AI model defense, NTN beam-hopping anti-jamming, TDX O-Cloud attestation, SBA NRF DPoP, Xn replay protection, and SMO Cosign |",
            4: "| `oransec` 📡 6G NTN & O-RAN 통신망 보안 (7) | 6G NTN FIPS 203 ML-KEM-768 핸드오버 · NIST FIPS 204 ML-DSA-65 RIC 원격 증명 · 다중 궤도 비잔틴 핸드오버 쿼럼 · 자율 SOAR 슬라이스 자가 치유 · vRAN TPM 2.0 Quote 신뢰점 · 코어-RAN 교차 도메인 상관 분석 · 주권 6G NTN & O-RAN 제로 트러스트 캡스톤 / NTN ML-KEM-768 handover, ML-DSA-65 RIC attestation, multi-orbit quorum, autonomous SOAR slice healing, vRAN TPM 2.0 Quote, Core-RAN correlation, and sovereign 6G NTN capstone |",
        }
        anchor = "| `fedsec` 🤖 연합 학습 모델 중독 & 프라이버시 방어 (7) |"
        parts = r_content.split(anchor)
        if len(parts) == 6:
            reconstructed = parts[0]
            for i in range(5):
                rest_line, remainder = parts[i + 1].split("\n", 1)
                reconstructed += anchor + rest_line + "\n" + tier_topics[i] + "\n" + remainder
            r_content = reconstructed.replace("총 **3150문제**", "총 **3185문제**").replace("Total **3150 challenges**", "Total **3185 challenges**")
            readme_file.write_text(r_content, encoding="utf-8")
            print("[+] Updated wargame/README.md with oransec topics and 3185 challenges")

    index_file = REPO_ROOT / "wargame" / "index.html"
    idx_content = index_file.read_text(encoding="utf-8")
    if "3150" in idx_content:
        idx_content = idx_content.replace("3150", "3185")
        index_file.write_text(idx_content, encoding="utf-8")
        print("[+] Updated wargame/index.html to 3185 challenges")


if __name__ == "__main__":
    main()
