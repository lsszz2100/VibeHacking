"""VibeHacking CTF Competition & Scoreboard Engine (FastAPI)."""

import os
import sys
import time
import math
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="VibeHacking CTF Arena", version="1.2.0")


def compute_dynamic_score(
    initial_points: int = 500,
    solves_count: int = 0,
    min_points: int = 100,
    decay_rate: float = 0.85,
) -> int:
    """
    Dynamic Scoring 알고리즘:
    - 0 또는 1 solve: initial_points (기본 500pt)
    - solves_count >= 2: initial_points * (decay_rate ** (solves_count - 1))
    - 최소 보장 점수: min_points (기본 100pt)
    """
    if solves_count <= 1:
        return initial_points
    decayed = int(initial_points * (decay_rate ** (solves_count - 1)))
    return max(min_points, decayed)


class CTFState:
    def __init__(self):
        self.teams: Dict[str, dict] = {
            "Admin_RedTeam": {"name": "Admin_RedTeam", "score": 0, "solves": [], "first_bloods": [], "last_solve": 0, "unlocked_hints": {}},
            "BlueGuardians": {"name": "BlueGuardians", "score": 0, "solves": [], "first_bloods": [], "last_solve": 0, "unlocked_hints": {}},
        }
        self.challenges: Dict[str, dict] = {
            "LAB01_SQLI": {
                "id": "LAB01_SQLI",
                "title": "WebSec: SQL Injection Auth Bypass",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{sqli_admin_bypass_success_01}",
                "solves": [],
                "first_blood": None,
            },
            "LAB01_XSS": {
                "id": "LAB01_XSS",
                "title": "WebSec: Stored XSS Session Hijacking",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{stored_xss_cookie_theft_01}",
                "solves": [],
                "first_blood": None,
            },
            "LAB02_CMDI": {
                "id": "LAB02_CMDI",
                "title": "AppSec: Command Injection Shell",
                "category": "system",
                "initial_points": 500,
                "flag": "FLAG{cmdi_reverse_shell_02}",
                "solves": [],
                "first_blood": None,
            },
            "LAB03_TRAVERSAL": {
                "id": "LAB03_TRAVERSAL",
                "title": "WebSec: Directory Traversal Leak",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{lfi_traversal_passwd_leak_03}",
                "solves": [],
                "first_blood": None,
            },
            "LAB04_SSRF": {
                "id": "LAB04_SSRF",
                "title": "Cloud: Metadata SSRF Pivot",
                "category": "cloud",
                "initial_points": 500,
                "flag": "FLAG{ssrf_cloud_metadata_token_04}",
                "solves": [],
                "first_blood": None,
            },
            "LAB05_AUTH": {
                "id": "LAB05_AUTH",
                "title": "AuthSec: JWT None Algorithm Forgery",
                "category": "auth",
                "initial_points": 500,
                "flag": "FLAG{jwt_alg_none_admin_forged_05}",
                "solves": [],
                "first_blood": None,
            },
            "LAB06_DESERIAL": {
                "id": "LAB06_DESERIAL",
                "title": "AppSec: Pickle Deserialization RCE",
                "category": "appsec",
                "initial_points": 500,
                "flag": "FLAG{pickle_deserial_rce_06}",
                "solves": [],
                "first_blood": None,
            },
            "LAB07_GRAPHQL": {
                "id": "LAB07_GRAPHQL",
                "title": "WebSec: GraphQL Introspection & BOLA",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{graphql_introspection_leak_07}",
                "solves": [],
                "first_blood": None,
            },
            "LAB08_RACE": {
                "id": "LAB08_RACE",
                "title": "Logic: Race Condition Double Spend",
                "category": "logic",
                "initial_points": 500,
                "flag": "FLAG{race_condition_toctou_pwn_08}",
                "solves": [],
                "first_blood": None,
            },
            "LAB09_XXE": {
                "id": "LAB09_XXE",
                "title": "WebSec: XML External Entity Exfil",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{xxe_file_disclosure_09}",
                "solves": [],
                "first_blood": None,
            },
            "LAB10_WEBSOCKET": {
                "id": "LAB10_WEBSOCKET",
                "title": "Realtime: CSWSH Stream Hijacking",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{cswsh_stream_hijack_10}",
                "solves": [],
                "first_blood": None,
            },
            "LAB11_CACHE": {
                "id": "LAB11_CACHE",
                "title": "WebSec: Web Cache Deception",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{cache_deception_leak_11}",
                "solves": [],
                "first_blood": None,
            },
            "LAB12_CLICKJACK": {
                "id": "LAB12_CLICKJACK",
                "title": "Client: Nested Frame Clickjacking",
                "category": "client",
                "initial_points": 500,
                "flag": "FLAG{clickjacking_admin_action_12}",
                "solves": [],
                "first_blood": None,
            },
            "LAB13_CLOUDMETA": {
                "id": "LAB13_CLOUDMETA",
                "title": "Cloud: IMDSv2 Token Role Pivot",
                "category": "cloud",
                "initial_points": 500,
                "flag": "FLAG{cloud_metadata_v2_role_13}",
                "solves": [],
                "first_blood": None,
            },
            "LAB14_AD": {
                "id": "LAB14_AD",
                "title": "AD: Kerberoasting SPN Ticket Crack",
                "category": "ad",
                "initial_points": 500,
                "flag": "FLAG{ad_kerberoast_spn_ticket_14}",
                "solves": [],
                "first_blood": None,
            },
            "LAB15_CICD": {
                "id": "LAB15_CICD",
                "title": "DevSecOps: GitHub Actions Runner RCE",
                "category": "cicd",
                "initial_points": 500,
                "flag": "FLAG{cicd_runner_escape_token_15}",
                "solves": [],
                "first_blood": None,
            },
            "LAB16_REV": {
                "id": "LAB16_REV",
                "title": "Reversing: Bytecode Disassembly Keygen",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{bytecode_reverse_keygen_16}",
                "solves": [],
                "first_blood": None,
            },
            "LAB17_PWN": {
                "id": "LAB17_PWN",
                "title": "Pwn: Buffer Overflow Ret2win",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{ret2win_rip_overwrite_17}",
                "solves": [],
                "first_blood": None,
            },
            "LAB18_AI": {
                "id": "LAB18_AI",
                "title": "AISec: MCP Prompt Injection Exfil",
                "category": "ai",
                "initial_points": 500,
                "flag": "FLAG{mcp_tool_injection_exfil_18}",
                "solves": [],
                "first_blood": None,
            },
            "LAB19_ROOT": {
                "id": "LAB19_ROOT",
                "title": "DroidShield: Root Detection Bypass",
                "category": "mobile",
                "initial_points": 500,
                "flag": "FLAG{dr01d_r00t_byp4ss_succ3ss_9281}",
                "solves": [],
                "first_blood": None,
            },
            "LAB19_PINNING": {
                "id": "LAB19_PINNING",
                "title": "DroidShield: Universal SSL Unpinning",
                "category": "mobile",
                "initial_points": 500,
                "flag": "FLAG{ss1_p1nn1ng_fr1da_unp1nn3d_7143}",
                "solves": [],
                "first_blood": None,
            },
            "LAB19_JNI": {
                "id": "LAB19_JNI",
                "title": "DroidShield: JNI Native Return Hijack",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{jn1_n4t1v3_h00k_l1c3ns3_p4ss_3301}",
                "solves": [],
                "first_blood": None,
            },
            "LAB20_SEH": {
                "id": "LAB20_SEH",
                "title": "WinAppSec: SEH pop-pop-ret Overwrite",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{w1n_seh_0v3rwr1t3_p0p_p0p_r3t_9918}",
                "solves": [],
                "first_blood": None,
            },
            "LAB20_EGG": {
                "id": "LAB20_EGG",
                "title": "WinAppSec: 32-Byte Egg Hunter",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{3gg_hunt3r_w00tw00t_m3m_f0und_4412}",
                "solves": [],
                "first_blood": None,
            },
            "LAB20_HEVD": {
                "id": "LAB20_HEVD",
                "title": "WinAppSec: HEVD Kernel Token Stealing",
                "category": "kernel",
                "initial_points": 500,
                "flag": "FLAG{h3vd_r1ng0_t0k3n_st34l1ng_pwn3d_5532}",
                "solves": [],
                "first_blood": None,
            },
            "CARCAN_ECU": {
                "id": "CARCAN_ECU",
                "title": "CarCan: UDS ECU Hard Reset & Firmware Exfil",
                "category": "carcan",
                "initial_points": 500,
                "flag": "FLAG{carcan_uds_ecu_reset_pwned_35}",
                "solves": [],
                "first_blood": None,
            },
            "LAB21_CAN": {
                "id": "LAB21_CAN",
                "title": "CarCan: CAN Bus Speedometer Spoofing",
                "category": "carcan",
                "initial_points": 500,
                "flag": "FLAG{can_bus_arbitration_speed_spoof_8821}",
                "solves": [],
                "first_blood": None,
            },
            "LAB21_UDS": {
                "id": "LAB21_UDS",
                "title": "CarCan: UDS SecurityAccess Seed-Key Bypass",
                "category": "carcan",
                "initial_points": 500,
                "flag": "FLAG{uds_security_access_seed_key_unlocked_3714}",
                "solves": [],
                "first_blood": None,
            },
            "LAB22_BOLA": {
                "id": "LAB22_BOLA",
                "title": "APIGuard: BOLA & BFLA Privilege Escalation",
                "category": "api",
                "initial_points": 500,
                "flag": "FLAG{bola_idor_bfla_api_privilege_escalated_4822}",
                "solves": [],
                "first_blood": None,
            },
            "LAB22_GRAPHQL": {
                "id": "LAB22_GRAPHQL",
                "title": "APIGuard: GraphQL Introspection & Secret Vault Extraction",
                "category": "api",
                "initial_points": 500,
                "flag": "FLAG{graphql_introspection_batching_bypass_7193}",
                "solves": [],
                "first_blood": None,
            },
            "LAB22_JWT": {
                "id": "LAB22_JWT",
                "title": "APIGuard: JWT None Algorithm Signature Bypass",
                "category": "api",
                "initial_points": 500,
                "flag": "FLAG{jwt_alg_none_jwks_confusion_pwned_8842}",
                "solves": [],
                "first_blood": None,
            },
            "LAB23_SYSMON": {
                "id": "LAB23_SYSMON",
                "title": "SOCHunter: Sysmon RemoteThread Process Injection",
                "category": "dfir",
                "initial_points": 500,
                "flag": "FLAG{sysmon_parent_pid_spoofing_remote_thread_injected_3821}",
                "solves": [],
                "first_blood": None,
            },
            "LAB23_SURICATA": {
                "id": "LAB23_SURICATA",
                "title": "SOCHunter: Suricata DNS Tunneling & C2 JA3 Beacon",
                "category": "dfir",
                "initial_points": 500,
                "flag": "FLAG{suricata_dns_tunnel_ja3_c2_beacon_correlated_9482}",
                "solves": [],
                "first_blood": None,
            },
            "LAB23_SIEM": {
                "id": "LAB23_SIEM",
                "title": "SOCHunter: SIEM Pass-the-Hash & SOAR Remediation",
                "category": "dfir",
                "initial_points": 500,
                "flag": "FLAG{siem_lsass_mimikatz_pass_the_hash_soar_contained_7129}",
                "solves": [],
                "first_blood": None,
            },
            "LAB24_FUZZ": {
                "id": "LAB24_FUZZ",
                "title": "FuzzMaster: AFL++ Coverage Crash Trigger",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{afl_coverage_guided_crash_triggered_4918}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "타깃 바이너리의 매직 헤더는 'FUZZ'(0x46555a5a)이며, 0xdeadbeef 패턴으로 댕글링 포인터를 트리거합니다."}
                ],
            },
            "LAB24_ASAN": {
                "id": "LAB24_ASAN",
                "title": "FuzzMaster: ASAN Heap-UAF Shadow Memory Triage",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{asan_heap_uaf_shadow_memory_decoded_8372}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "ASAN 덤프에서 0xfd 섀도우 바이트와 free_session_chunk 호출 스택의 0x603000000040 주소를 분석하세요."}
                ],
            },
            "LAB24_TRIAGE": {
                "id": "LAB24_TRIAGE",
                "title": "FuzzMaster: CWE-416 PoC Synthesis & Patch Verification",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{crash_triage_cwe416_poc_reproduced_patch_verified_1054}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "취약점 분류는 CWE-416(Use-After-Free)이며, chunk->data = NULL; 패치로 댕글링 포인터를 무력화합니다."}
                ],
            },
            "LAB25_INDIRECT": {
                "id": "LAB25_INDIRECT",
                "title": "AIRedGuard: Indirect Prompt Injection & RAG Taint",
                "category": "ai",
                "initial_points": 500,
                "flag": "FLAG{indirect_prompt_injection_rag_taint_unlocked_9102}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "외부 문서 검색 청크에 시스템 지시 무효화 및 [AIRedGuard_FLAG_SECRET] 유출 명령을 심으세요."}
                ],
            },
            "LAB25_GUARDRAIL": {
                "id": "LAB25_GUARDRAIL",
                "title": "AIRedGuard: Token Splitting & Guardrail Bypass",
                "category": "ai",
                "initial_points": 500,
                "flag": "FLAG{adversarial_token_guardrail_bypass_verified_4819}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "BPE 서브워드 토큰 분할(p-a-s-s-w-o-r-d) 또는 유니코드 제로위드 공백(\\u200b)으로 금지어 필터를 우회하세요."}
                ],
            },
            "LAB25_SHADOW": {
                "id": "LAB25_SHADOW",
                "title": "AIRedGuard: MCP Tool Shadowing & Agent Sandbox Containment",
                "category": "ai",
                "initial_points": 500,
                "flag": "FLAG{mcp_tool_shadowing_agent_sandbox_contained_7341}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "동일 이름의 악성 MCP 도구를 선언하여 정상 도구를 섀도잉하고 격리 샌드박스 정책을 분석하세요."}
                ],
            },
            "LAB26_STATIC": {
                "id": "LAB26_STATIC",
                "title": "MalSandbox: PE Static Parsing & Entropy Decoding",
                "category": "malware",
                "initial_points": 500,
                "flag": "FLAG{pe_static_entropy_iat_unpacked_8192}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "UPX 패킹 섹션 엔트로피를 해제하고 PEB BeingDebugged 플래그를 패치하여 숨겨진 IAT를 복원하세요."}
                ],
            },
            "LAB26_YARA": {
                "id": "LAB26_YARA",
                "title": "MalSandbox: YARA Signature & C2 Heuristic Hunting",
                "category": "malware",
                "initial_points": 500,
                "flag": "FLAG{yara_heuristic_rule_c2_hunting_5301}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "VirtualAllocEx/CreateRemoteThread 인젝션 API와 PowerShell 다운로더 키워드를 매칭하는 룰을 작성하세요."}
                ],
            },
            "LAB26_SANDBOX": {
                "id": "LAB26_SANDBOX",
                "title": "MalSandbox: Dynamic Evasion Fast-Forward & Containment",
                "category": "malware",
                "initial_points": 500,
                "flag": "FLAG{dynamic_sandbox_telemetry_evasion_blocked_2748}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "Sleep(600s) 안티 샌드박스 대기를 스킵하고 cuckoomon API 텔레메트리로 Run키 지속성을 차단하세요."}
                ],
            },
            "LAB27_PMKID": {
                "id": "LAB27_PMKID",
                "title": "WiFiShield: RSN IE PMKID Offline Hashcat Crack",
                "category": "wireless",
                "initial_points": 500,
                "flag": "FLAG{pmkid_rsn_ie_offline_hashcat_cracked_8027}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "EAPOL 1/4 RSN IE의 HMAC-SHA1-128 해시를 Hashcat 22000 모드와 winter2026!corp 단어로 검증하세요."}
                ],
            },
            "LAB27_SAE": {
                "id": "LAB27_SAE",
                "title": "WiFiShield: WPA3 SAE Dragonfly Downgrade & Side-Channel",
                "category": "wireless",
                "initial_points": 500,
                "flag": "FLAG{dragonfly_sae_sidechannel_downgraded_9142}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "WPA3 Transition 모드의 폴백 취약점 또는 Group 19 PWE 타이밍 부채널(CVE-2019-9494)을 트리거하세요."}
                ],
            },
            "LAB27_MFP": {
                "id": "LAB27_MFP",
                "title": "WiFiShield: 802.11w PMF Required & Rogue AP Containment",
                "category": "wireless",
                "initial_points": 500,
                "flag": "FLAG{80211w_pmf_bip_deauth_flood_protected_5583}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "IEEE 802.11w PMF 모드를 optional이 아닌 'required'로 설정하고 Rogue BSSID(de:ad:be:ef:13:37)를 격리하세요."}
                ],
            },
            "LAB28_SNMP": {
                "id": "LAB28_SNMP",
                "title": "NetShield: Cisco SNMPv2c Running-Config Dump & Type 7 Decrypt",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{cisco_snmpv2c_rw_community_running_config_dumped_8028}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "SNMPv2c write 커뮤니티('private')로 ciscoConfigCopyMIB(1.3.6.1.4.1.9.9.96)를 호출하여 running-config를 추출하고 Type 7 XOR 복호화를 수행하세요."}
                ],
            },
            "LAB28_VLAN": {
                "id": "LAB28_VLAN",
                "title": "NetShield: DTP Dynamic Desirable Trunk Spoofing & STP Priority 0 Root Takeover",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{dtp_vlan_hopping_and_stp_bpdu_root_bridge_hijacked_4192}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "DTP desirable 프레임으로 트렁크 네고시에이션을 강제 체결하고 STP Priority 0 BPDU를 플러딩하여 루트 브리지를 선출시키세요."}
                ],
            },
            "LAB28_HARDEN": {
                "id": "LAB28_HARDEN",
                "title": "NetShield: Enterprise L2 Hardening (Port-Security/DAI/BPDU Guard/CoPP)",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{cisco_ios_l2_hardened_portsec_dai_bpduguard_copp_secured_7731}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "Port-Security, DHCP Snooping, Dynamic ARP Inspection(DAI), BPDU Guard 및 CoPP 제어 평면 정책을 적용하여 방어를 완성하세요."}
                ],
            },
            "LAB29_ESC1": {
                "id": "LAB29_ESC1",
                "title": "CertPwn: AD CS ESC1 Enrollee Supplies SAN Administrator Certificate Forgery",
                "category": "activedirectory",
                "initial_points": 500,
                "flag": "FLAG{adcs_esc1_enrollee_supplies_san_admin_cert_issued_8029}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "ESC1_WebAuth 템플릿의 CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT 취약점을 악용하여 SAN에 administrator@corp.local을 지정하여 인증서를 요청하세요."}
                ],
            },
            "LAB29_PKINIT": {
                "id": "LAB29_PKINIT",
                "title": "CertPwn: PKINIT Pass-the-Certificate TGT Request & UnPAC-the-Hash",
                "category": "activedirectory",
                "initial_points": 500,
                "flag": "FLAG{pkinit_tgt_acquired_pass_the_certificate_domain_admin_5921}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "발급받은 관리자 PFX 인증서로 KDC에 PKINIT 인증을 수행하여 TGT를 확보하고 PAC_CREDENTIAL_INFO에서 NTLM 해시를 복원하세요."}
                ],
            },
            "LAB29_DELEG": {
                "id": "LAB29_DELEG",
                "title": "CertPwn: Enterprise AD CS & Kerberos Hardening (Protected Users & Delegation Controls)",
                "category": "activedirectory",
                "initial_points": 500,
                "flag": "FLAG{kerberos_delegation_s4u_rbcd_hardened_protected_users_9312}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "관리자 계정에 USER_NOT_DELEGATED 및 Protected Users 보안 그룹을 적용하고 취약 템플릿과 NTLM 릴레이를 차단하세요."}
                ],
            },
            "LAB30_SYMBOL": {
                "id": "LAB30_SYMBOL",
                "title": "GhidraRev: Headless Symbol Analysis & Prologue Signature Matching",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{ghidra_headless_symbol_analysis_recovered_8030}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "x86_64 함수 프롤로그 시그니처(55 48 89 E5)를 매칭하고 0x00401200 위치의 심볼을 validate_license_core로 복원하세요."}
                ],
            },
            "LAB30_CFF": {
                "id": "LAB30_CFF",
                "title": "GhidraRev: Control Flow Flattening (CFF) Dispatcher Deflattening",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{control_flow_flattening_state_machine_defused_3921}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "중앙 switch(state) 디스패처 루프의 상태 전이 시퀀스 [10, 40, 25, 90]를 분석하고 불투명 술어를 제거하여 AST를 디플래트닝하세요."}
                ],
            },
            "LAB30_PATCH": {
                "id": "LAB30_PATCH",
                "title": "GhidraRev: Anti-Tamper Checksum Bypass & Inline Binary Patching",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{binary_patch_integrity_hash_bypassed_9942}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "가상 주소 0x00401337의 조건부 분기(74 18 jz)를 90 90 (nop nop) 또는 eb 18 (jmp)로 패치하고 자체 .text 체크섬을 우회하세요."}
                ],
            },
            "LAB31_REDIRECT": {
                "id": "LAB31_REDIRECT",
                "title": "SSOShield: Loose Regex Redirect URI Bypass & Auth Code Exfiltration",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{OAUTH_REDIRECT_URI_LEAK_7712}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "IdP의 느슨한 redirect_uri 검증 패턴을 우회할 수 있는 하위/상위 도메인을 조작하여 인가 코드를 탈취하세요."}
                ],
            },
            "LAB31_PKCE": {
                "id": "LAB31_PKCE",
                "title": "SSOShield: PKCE Downgrade & Code Verifier Omission Token Exchange",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{OAUTH_PKCE_DOWNGRADE_CSRF_8823}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "토큰 교환 요청 시 code_verifier를 누락하여 IdP의 PKCE 검증 누락 결함을 악용하세요."}
                ],
            },
            "LAB31_JWT": {
                "id": "LAB31_JWT",
                "title": "SSOShield: OIDC ID Token JWT Key Confusion & Admin Takeover",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{OAUTH_IDTOKEN_KEY_CONFUSION_9934}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "JWT 헤더의 kid 및 대칭키(HS256) 알고리즘 혼동을 활용하여 enterprise_admin 역할의 위조 ID 토큰을 생성하세요."}
                ],
            },
            "LAB32_PREFIX": {
                "id": "LAB32_PREFIX",
                "title": "BGPRouteGuard: Exact Prefix BGP Hijack & Traffic Interception",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{BGP_EXACT_PREFIX_HIJACK_4401}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "공격자 AS 64500에서 동일한 203.0.113.0/24 접두사를 BGP UPDATE로 선언하여 피어 AS 65001의 FIB를 조작하세요."}
                ],
            },
            "LAB32_SUBPREFIX": {
                "id": "LAB32_SUBPREFIX",
                "title": "BGPRouteGuard: Sub-prefix LPM Hijacking & Traffic Blackholing",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{BGP_SUBPREFIX_LPM_HIJACK_5512}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "더 긴 서브넷인 /25 접두사를 선언하여 BGP의 최장 접두사 일치(Longest Prefix Match) 원리를 통해 모든 서브넷 트래픽을 흡수하세요."}
                ],
            },
            "LAB32_LEAK": {
                "id": "LAB32_LEAK",
                "title": "BGPRouteGuard: AS-Path Forgery & Peer-to-Peer Route Leak",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{BGP_ASPATH_LEAK_INTERCEPTION_6623}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "AS-Path 끝에 정당한 AS 64496을 붙여 출처를 위조하고 피어 간 비정상 경로 누출(Route Leak)을 유발하세요."}
                ],
            },
            "LAB33_ACCOUNT": {
                "id": "LAB33_ACCOUNT",
                "title": "KisaAuditLab: U-01~U-04 Account Management Full Audit & Detection",
                "category": "compliance",
                "initial_points": 500,
                "flag": "FLAG{KISA_U01_U04_ACCOUNT_AUDIT_PWNED_1109}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "root 원격 접속, 패스워드 복잡도/잠금 임계값 및 shadow 권한 항목을 전수 진단하세요."}
                ],
            },
            "LAB33_SERVICE": {
                "id": "LAB33_SERVICE",
                "title": "KisaAuditLab: U-20 Anonymous FTP & U-44 SSH Weak Cipher Exploitation",
                "category": "compliance",
                "initial_points": 500,
                "flag": "FLAG{KISA_U20_U44_VULN_SERVICE_EXPLOITED_2241}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "Anonymous FTP 백업 파일 다운로드 및 SSH CBC 모드 암호 프로빙을 모두 완수하세요."}
                ],
            },
            "LAB33_HARDEN": {
                "id": "LAB33_HARDEN",
                "title": "KisaAuditLab: One-Click KISA Infrastructure Compliance Hardening",
                "category": "compliance",
                "initial_points": 500,
                "flag": "FLAG{KISA_HARDENING_COMPLIANCE_PASSED_3378}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "6대 핵심 취약 항목을 KISA 기술적 취약점 평가 '양호' 기준에 맞게 일괄 하드닝하세요."}
                ],
            },
            "LAB34_SHODAN": {
                "id": "LAB34_SHODAN",
                "title": "OsintHunterLab: Internet Attack Surface Discovery via Shodan / Censys",
                "category": "osint",
                "initial_points": 500,
                "flag": "FLAG{OSINT_SHODAN_EXPOSED_SERVICES_RECON_7712}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "조직명 또는 미인가 포트(Redis 6379, Elastic 9200) dork 쿼리로 노출된 인프라를 매핑하세요."}
                ],
            },
            "LAB34_DATABASE": {
                "id": "LAB34_DATABASE",
                "title": "OsintHunterLab: Unauthenticated Redis & Elasticsearch Dump & Key Carving",
                "category": "osint",
                "initial_points": 500,
                "flag": "FLAG{OSINT_ELASTIC_REDIS_UNAUTH_DUMP_PWNED_8823}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "열려 있는 Redis(6379) 또는 Elasticsearch(9200) 데이터베이스에 쿼리를 전송하여 내부 자격증명을 덤프하세요."}
                ],
            },
            "LAB34_GIT": {
                "id": "LAB34_GIT",
                "title": "OsintHunterLab: Exposed .git Commit History Tracing & Cloud Secret Recovery",
                "category": "osint",
                "initial_points": 500,
                "flag": "FLAG{OSINT_GIT_LEAKED_SECRET_RECONSTRUCTED_9934}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "노출된 /.git의 분리된 객체 및 커밋 변경 이력을 추적하여 과거 삭제된 AWS 프로덕션 API 키를 복구하세요."}
                ],
            },
            "LAB35_PASSROLE": {
                "id": "LAB35_PASSROLE",
                "title": "CloudPwnLab: Compute Instance Launch & iam:PassRole Escalation",
                "category": "cloud",
                "initial_points": 500,
                "flag": "FLAG{CLOUD_IAM_PASSROLE_EC2_PRIV_ESCALATED_1120}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "ec2:RunInstances 실행 시 고권한 CloudSecAdminRole을 인스턴스 프로파일로 위임하여 IMDS에서 자격증명을 탈취하세요."}
                ],
            },
            "LAB35_ASSUME": {
                "id": "LAB35_ASSUME",
                "title": "CloudPwnLab: Cross-Account Wildcard Trust sts:AssumeRole Abuse",
                "category": "cloud",
                "initial_points": 500,
                "flag": "FLAG{CLOUD_STS_ASSUMEROLE_TRUST_POLICY_PWNED_2231}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "신뢰 정책에 Principal: {'AWS': '*'} 와일드카드가 선언된 CrossAccountAuditRole 역할을 sts:AssumeRole로 획득하세요."}
                ],
            },
            "LAB35_SCP": {
                "id": "LAB35_SCP",
                "title": "CloudPwnLab: Multi-Layered Cloud Governance Hardening (SCP & Boundaries)",
                "category": "cloud",
                "initial_points": 500,
                "flag": "FLAG{CLOUD_ORG_SCP_PERMISSION_BOUNDARY_ENFORCED_3342}",
                "solves": [],
                "first_blood": None,
                "hints": [
                    {"index": 0, "cost": 50, "text": "AWS Organizations SCP와 개발자 권한 경계를 결합하여 무단 PassRole 및 외부 임의 AssumeRole을 원천 차단하세요."}
                ],
            },
        }
        self.submissions_log: List[dict] = []
        self.first_bloods_feed: List[dict] = []
        self.score_timeline: List[dict] = []
        self.subscribers: List[asyncio.Queue] = []

        # Initialize base timeline
        t0 = int(time.time()) - 60
        self.score_timeline.append({"time": t0, "team": "Admin_RedTeam", "score": 0, "chal_id": "INIT"})
        self.score_timeline.append({"time": t0, "team": "BlueGuardians", "score": 0, "chal_id": "INIT"})

    def broadcast_event(self, event: dict):
        """Broadcast real-time event to all connected SSE clients"""
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def get_points(self, chal_id: str) -> int:
        """Dynamic Scoring: 다음 solve 시 획득할 점수 (solves 수가 늘어날수록 점수 차감, 최저 100점)"""
        c = self.challenges.get(chal_id)
        if not c:
            return 100
        next_solve_count = len(c["solves"]) + 1
        return compute_dynamic_score(
            initial_points=c.get("initial_points", 500),
            solves_count=next_solve_count,
            min_points=100,
            decay_rate=0.85,
        )


state = CTFState()


class TeamRegisterRequest(BaseModel):
    team_name: str


class FlagSubmitRequest(BaseModel):
    team_name: str
    chal_id: str
    flag: str


class HintUnlockRequest(BaseModel):
    team_name: str
    chal_id: str
    hint_index: int = 0


@app.get("/api/ctf/challenges")
def get_challenges():
    """모의해킹 대회 문제 목록 및 현재 실시간 배점 반환"""
    data = []
    for cid, c in state.challenges.items():
        data.append({
            "id": cid,
            "title": c["title"],
            "category": c["category"],
            "initial_points": c.get("initial_points", 500),
            "current_points": state.get_points(cid),
            "solves_count": len(c["solves"]),
            "first_blood": c["first_blood"],
            "hints_count": len(c.get("hints", [])),
        })
    return {"challenges": data}


@app.get("/api/ctf/firstbloods")
def get_firstbloods():
    """First Blood 명예의 전당 피드 반환"""
    return {"first_bloods": state.first_bloods_feed}


@app.get("/api/ctf/timeline")
def get_timeline():
    """시계열 점수 추이 데이터 반환 (차트 렌더링용)"""
    return {
        "teams": list(state.teams.keys()),
        "timeline": state.score_timeline,
    }


@app.get("/api/ctf/team/{team_name}")
def get_team_profile(team_name: str):
    """특정 팀의 세부 해결 내역 및 First Blood 뱃지 반환"""
    team = state.teams.get(team_name)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    details = []
    for cid in team["solves"]:
        c = state.challenges.get(cid, {})
        details.append({
            "chal_id": cid,
            "title": c.get("title", cid),
            "category": c.get("category", "unknown"),
            "first_blood": cid in team.get("first_bloods", []),
        })
    return {
        "team": team_name,
        "score": team["score"],
        "solves_count": len(team["solves"]),
        "first_blood_count": len(team.get("first_bloods", [])),
        "solves": details,
        "unlocked_hints": team.get("unlocked_hints", {}),
    }


@app.get("/api/ctf/scoreboard")
def get_scoreboard():
    """실시간 스코어보드 순위, 점수, First Blood 뱃지 반환"""
    board = []
    for tname, t in state.teams.items():
        board.append({
            "team": tname,
            "score": t["score"],
            "solves_count": len(t["solves"]),
            "first_blood_count": len(t.get("first_bloods", [])),
            "last_solve": t["last_solve"],
        })
    # Sort by score desc, then last_solve asc
    board.sort(key=lambda x: (-x["score"], x["last_solve"]))
    for i, item in enumerate(board, 1):
        item["rank"] = i
    return {
        "scoreboard": board,
        "first_bloods": state.first_bloods_feed[-5:],
        "recent_activity": state.submissions_log[-10:],
    }


@app.get("/api/ctf/stream")
async def sse_stream(request: Request, once: bool = False):
    """실시간 점수 및 First Blood 스트리밍 (Server-Sent Events)"""
    async def event_generator():
        yield "event: handshake\ndata: {\"status\": \"connected\"}\n\n"
        if once:
            return

        queue = asyncio.Queue()
        state.subscribers.append(queue)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {event.get('type', 'message')}\ndata: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in state.subscribers:
                state.subscribers.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/ctf/register")
def register_team(req: TeamRegisterRequest):
    name = req.team_name.strip()
    if not name or len(name) < 2:
        raise HTTPException(status_code=400, detail="Team name too short")
    if name in state.teams:
        return {"status": "exists", "message": "Team already registered", "team": name}
    now = int(time.time())
    state.teams[name] = {"name": name, "score": 0, "solves": [], "first_bloods": [], "last_solve": 0, "unlocked_hints": {}}
    state.score_timeline.append({"time": now, "team": name, "score": 0, "chal_id": "REGISTER"})
    state.broadcast_event({"type": "team_registered", "team": name, "time": now})
    return {"status": "registered", "team": name}


@app.post("/api/ctf/submit")
def submit_flag(req: FlagSubmitRequest):
    """플래그 검증, First Blood 알림 및 동적 점수(Dynamic Scoring) 반영"""
    tname = req.team_name.strip()
    if tname not in state.teams:
        raise HTTPException(status_code=404, detail="Team not found. Please register first.")

    chal = state.challenges.get(req.chal_id)
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge not found")

    team = state.teams[tname]
    if req.chal_id in team["solves"]:
        return {"status": "already_solved", "message": "Challenge already solved by your team."}

    submitted_flag = req.flag.strip()
    is_correct = (submitted_flag == chal["flag"])

    now = int(time.time())
    state.submissions_log.append({
        "time": now,
        "team": tname,
        "chal_id": req.chal_id,
        "correct": is_correct,
    })

    if not is_correct:
        return {"status": "wrong_flag", "message": "Incorrect flag! Try again."}

    # First blood check
    is_first_blood = (len(chal["solves"]) == 0)
    pts = state.get_points(req.chal_id)
    first_blood_bonus = 0

    if is_first_blood:
        first_blood_bonus = 50
        pts += first_blood_bonus
        fb_entry = {
            "chal_id": req.chal_id,
            "title": chal["title"],
            "team": tname,
            "timestamp": now,
            "bonus": first_blood_bonus,
        }
        chal["first_blood"] = fb_entry
        team["first_bloods"].append(req.chal_id)
        state.first_bloods_feed.append(fb_entry)

    chal["solves"].append(tname)
    team["solves"].append(req.chal_id)
    team["score"] += pts
    team["last_solve"] = now

    # Record score timeline progression
    state.score_timeline.append({
        "time": now,
        "team": tname,
        "score": team["score"],
        "chal_id": req.chal_id,
        "pts": pts,
        "first_blood": is_first_blood,
    })

    # Broadcast event via SSE
    state.broadcast_event({
        "type": "flag_solve",
        "team": tname,
        "chal_id": req.chal_id,
        "title": chal["title"],
        "points": pts,
        "first_blood": is_first_blood,
        "bonus": first_blood_bonus,
        "time": now,
        "score": team["score"],
    })

    msg = f"Correct! Earned {pts} points."
    if is_first_blood:
        msg += f" [FIRST BLOOD! 🩸 +{first_blood_bonus}pt Bonus!]"

    return {
        "status": "correct",
        "message": msg,
        "points_awarded": pts,
        "first_blood": is_first_blood,
        "first_blood_bonus": first_blood_bonus,
        "total_score": team["score"],
    }


@app.post("/api/ctf/hints/unlock")
def unlock_hint(req: HintUnlockRequest):
    """CTF 힌트 구매 및 점수 차감 시스템"""
    tname = req.team_name.strip()
    if tname not in state.teams:
        raise HTTPException(status_code=404, detail="Team not found. Please register first.")
    
    chal = state.challenges.get(req.chal_id)
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge not found")
        
    hints = chal.get("hints", [])
    if not hints or req.hint_index < 0 or req.hint_index >= len(hints):
        raise HTTPException(status_code=404, detail="Hint not available for this challenge")
        
    team = state.teams[tname]
    team.setdefault("unlocked_hints", {})
    team["unlocked_hints"].setdefault(req.chal_id, [])
    
    target_hint = hints[req.hint_index]
    
    if req.hint_index in team["unlocked_hints"][req.chal_id]:
        return {
            "status": "already_unlocked",
            "message": "Hint already unlocked",
            "hint": target_hint["text"],
            "cost": 0,
            "remaining_score": team["score"],
        }
        
    cost = target_hint.get("cost", 50)
    team["score"] = max(0, team["score"] - cost)
    team["unlocked_hints"][req.chal_id].append(req.hint_index)
    now = int(time.time())
    
    # Record penalty in timeline
    state.score_timeline.append({
        "time": now,
        "team": tname,
        "score": team["score"],
        "chal_id": f"HINT_{req.chal_id}_{req.hint_index}",
        "cost": cost,
    })
    
    state.broadcast_event({
        "type": "hint_unlocked",
        "team": tname,
        "chal_id": req.chal_id,
        "hint_index": req.hint_index,
        "cost": cost,
        "score": team["score"],
        "time": now,
    })
    
    return {
        "status": "unlocked",
        "message": f"Hint unlocked! Deducted {cost} points.",
        "hint": target_hint["text"],
        "cost": cost,
        "remaining_score": team["score"],
    }


@app.get("/", response_class=HTMLResponse)
def ctf_home():
    return """
    <!DOCTYPE html>
    <html lang="ko">
    <head>
      <meta charset="UTF-8">
      <title>VibeHacking CTF Arena & Scoreboard</title>
      <style>
        :root {
          --bg: #0b0f19;
          --card: #1e293b;
          --card-border: #334155;
          --accent: #ec4899;
          --cyan: #38bdf8;
          --red: #f43f5e;
          --gold: #fbbf24;
          --green: #4ade80;
        }
        body { background: var(--bg); color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; padding: 2rem; margin: 0; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: var(--accent); margin-bottom: 0.5rem; display: flex; align-items: center; gap: 10px; }
        .banner { background: linear-gradient(90deg, #3730a3 0%, #1e1b4b 100%); border-left: 4px solid #818cf8; padding: 12px 16px; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.95rem; }
        .grid { display: grid; grid-template-columns: 1fr 360px; gap: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: #111827; border-radius: 8px; overflow: hidden; }
        th, td { padding: 12px 14px; border-bottom: 1px solid #1f2937; text-align: left; }
        th { background: #1f2937; color: var(--cyan); font-weight: 600; font-size: 0.9rem; }
        .rank-1 { color: var(--gold); font-weight: bold; background: rgba(251, 191, 36, 0.05); }
        .badge { background: var(--accent); color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
        .badge-fb { background: #dc2626; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
        .card { background: var(--card); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; border: 1px solid var(--card-border); }
        .input-box { background: #0f172a; border: 1px solid #475569; color: white; padding: 10px; border-radius: 6px; margin-right: 8px; font-size: 0.95rem; }
        button { background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background 0.2s; }
        button:hover { background: #db2777; }
        .fb-feed-item { padding: 8px 10px; border-bottom: 1px solid var(--card-border); font-size: 0.88rem; display: flex; align-items: center; justify-content: space-between; }
        .fb-feed-item:last-child { border-bottom: none; }
        .fb-team { color: var(--red); font-weight: bold; }
        .toast { position: fixed; top: 20px; right: 20px; background: rgba(244, 63, 94, 0.95); color: white; padding: 14px 20px; border-radius: 8px; font-weight: bold; box-shadow: 0 10px 25px rgba(0,0,0,0.5); z-index: 1000; display: none; animation: slideIn 0.3s forwards; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        
        /* Interactive Scoreboard Chart Canvas */
        .chart-box {
          background: #020617;
          border: 1px solid #1e293b;
          border-radius: 8px;
          padding: 1rem;
          margin-bottom: 1.5rem;
          position: relative;
        }
        canvas { width: 100%; height: 240px; display: block; }
        .live-tag { display: inline-flex; align-items: center; gap: 6px; color: var(--green); font-size: 0.85rem; font-weight: bold; }
        .live-dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%; animation: blink 1.2s infinite; }
        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.2; } 100% { opacity: 1; } }

        /* Challenges Grid & Hint Shop */
        .chal-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; margin-top: 1rem; max-height: 440px; overflow-y: auto; padding-right: 4px; }
        .chal-card { background: #0f172a; border: 1px solid var(--card-border); border-radius: 6px; padding: 12px; display: flex; flex-direction: column; justify-content: space-between; transition: border-color 0.2s, transform 0.15s; cursor: pointer; }
        .chal-card:hover { border-color: var(--cyan); transform: translateY(-2px); }
        .chal-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px; }
        .chal-cat { font-size: 0.72rem; padding: 2px 6px; border-radius: 4px; background: rgba(56, 189, 248, 0.15); color: var(--cyan); font-weight: bold; text-transform: uppercase; }
        .chal-points { font-size: 0.85rem; font-weight: bold; color: var(--gold); }
        .chal-title { font-size: 0.88rem; font-weight: 600; margin-bottom: 8px; color: #f1f5f9; line-height: 1.3; }
        .chal-footer { display: flex; justify-content: space-between; align-items: center; font-size: 0.78rem; color: #94a3b8; }
        .btn-hint { background: rgba(251, 191, 36, 0.15); border: 1px solid rgba(251, 191, 36, 0.4); color: var(--gold); padding: 4px 8px; border-radius: 4px; font-size: 0.78rem; cursor: pointer; font-weight: 600; }
        .btn-hint:hover { background: rgba(251, 191, 36, 0.3); }

        /* Modal Overlay */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); backdrop-filter: blur(4px); display: none; justify-content: center; align-items: center; z-index: 2000; }
        .modal-content { background: #1e293b; border: 1px solid var(--card-border); border-radius: 10px; width: 90%; max-width: 500px; padding: 1.5rem; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
        .modal-title { font-size: 1.1rem; font-weight: bold; color: var(--cyan); margin-top: 0; display: flex; align-items: center; gap: 8px; }
        .modal-body { margin: 1rem 0; font-size: 0.95rem; line-height: 1.5; color: #cbd5e1; }
        .modal-actions { display: flex; justify-content: flex-end; gap: 10px; }
        .btn-cancel { background: #334155; color: #cbd5e1; }
        .btn-cancel:hover { background: #475569; }
        .btn-confirm { background: var(--gold); color: #0f172a; }
        .btn-confirm:hover { background: #f59e0b; }
      </style>
    </head>
    <body>
      <div id="toastBox" class="toast"></div>

      <!-- Hint Modal -->
      <div id="hintModal" class="modal-overlay">
        <div class="modal-content">
          <h3 id="modalTitle" class="modal-title">💡 힌트 상점</h3>
          <div id="modalBody" class="modal-body"></div>
          <div class="modal-actions" id="modalActions">
            <button class="btn-cancel" onclick="closeHintModal()">닫기</button>
          </div>
        </div>
      </div>

      <div class="container">
        <h1>
          🏆 VibeHacking CTF Arena
          <span class="live-tag"><span class="live-dot"></span> LIVE SSE STREAMING</span>
        </h1>
        <p style="color: #94a3b8; margin-top: 0;">25개 실습 랩 40개 플래그 채점, 실시간 Dynamic Scoring & First Blood 영예의 전당</p>

        <div class="banner">
          ⚡ <b>Dynamic Scoring Engine:</b> 문제 기본 500pt에서 해결 팀 증가에 따라 점수 자동 감쇠(최저 100pt) | <b>🩸 First Blood:</b> 문제 최초 해결 시 <b>+50pt 추가 보너스</b> 지급! | <b>💡 힌트 상점:</b> 문제별 힌트 해금 시 50pt 차감
        </div>

        <!-- Interactive Score Timeline Chart -->
        <div class="chart-box">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <b style="color: var(--cyan); font-size: 0.95rem;">📈 팀별 실시간 점수 추이 그래프 (Score Progression Timeline)</b>
            <span id="chartLegend" style="font-size: 0.8rem; display: flex; gap: 12px;"></span>
          </div>
          <canvas id="scoreCanvas" width="1120" height="240"></canvas>
        </div>

        <!-- Challenges & Interactive Hint Shop -->
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <h3 style="margin: 0; color: var(--gold); display: flex; align-items: center; gap: 8px;">
              💡 챌린지 아레나 & 힌트 상점 (Challenge Arena & Hint Shop)
            </h3>
            <span style="font-size: 0.82rem; color: #94a3b8;">문제를 클릭하면 플래그 입력창에 자동 등록됩니다</span>
          </div>
          <div class="chal-grid" id="chalGrid">
            <div style="padding: 20px; color: #64748b; text-align: center; grid-column: 1 / -1;">챌린지 목록을 불러오는 중...</div>
          </div>
        </div>

        <div class="card">
          <h3 style="margin-top: 0;">🚩 플래그 제출 (Flag Submit)</h3>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <input id="teamInput" class="input-box" style="flex: 1; min-width: 150px;" placeholder="팀 이름 (예: Admin_RedTeam)">
            <input id="chalInput" class="input-box" style="flex: 1; min-width: 150px;" placeholder="문제 ID (예: LAB21_CAN)">
            <input id="flagInput" class="input-box" style="flex: 2; min-width: 250px;" placeholder="FLAG{...}">
            <button onclick="submitFlag()">제출하기</button>
          </div>
          <div id="submitResult" style="margin-top: 10px; font-weight: 500;"></div>
        </div>

        <div class="grid">
          <div>
            <h2 style="color: var(--cyan); margin-bottom: 0.5rem;">📊 실시간 리더보드 (Scoreboard)</h2>
            <table>
              <thead>
                <tr>
                  <th>순위</th>
                  <th>팀 이름</th>
                  <th>점수</th>
                  <th>해결 수</th>
                  <th>First Blood</th>
                </tr>
              </thead>
              <tbody id="boardBody"></tbody>
            </table>
          </div>

          <div>
            <h2 style="color: var(--red); margin-bottom: 0.5rem;">🩸 First Blood 피드</h2>
            <div class="card" style="padding: 0.5rem;" id="fbFeed">
              <div style="padding: 12px; color: #94a3b8; text-align: center;">아직 첫 피를 흘린 자가 없습니다...</div>
            </div>
          </div>
        </div>
      </div>

      <script>
        const TEAM_COLORS = ['#ec4899', '#38bdf8', '#fbbf24', '#4ade80', '#a855f7', '#f43f5e', '#34d399', '#f97316'];
        let cachedTimeline = [];

        function showToast(msg) {
          const t = document.getElementById('toastBox');
          t.innerHTML = msg;
          t.style.display = 'block';
          setTimeout(() => { t.style.display = 'none'; }, 4500);
        }

        async function drawTimelineChart() {
          try {
            const res = await fetch('/api/ctf/timeline');
            const data = await res.json();
            cachedTimeline = data.timeline;
            const teams = data.teams;

            const canvas = document.getElementById('scoreCanvas');
            const ctx = canvas.getContext('2d');
            const W = canvas.width;
            const H = canvas.height;
            ctx.clearRect(0, 0, W, H);

            // Group events by team
            const series = {};
            teams.forEach((t, i) => {
              series[t] = { color: TEAM_COLORS[i % TEAM_COLORS.length], points: [] };
            });

            data.timeline.forEach(ev => {
              if (series[ev.team]) {
                series[ev.team].points.push({ time: ev.time, score: ev.score });
              }
            });

            // Calculate min/max time and score
            let minT = Infinity, maxT = -Infinity, maxS = 500;
            data.timeline.forEach(ev => {
              if (ev.time < minT) minT = ev.time;
              if (ev.time > maxT) maxT = ev.time;
              if (ev.score > maxS) maxS = ev.score;
            });
            if (minT === maxT) maxT = minT + 60;
            maxS = Math.ceil(maxS * 1.15);

            // Draw grid lines
            ctx.strokeStyle = '#1e293b';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 4; i++) {
              const y = H - 30 - (i / 4) * (H - 50);
              ctx.beginPath();
              ctx.moveTo(40, y);
              ctx.lineTo(W - 20, y);
              ctx.stroke();

              ctx.fillStyle = '#64748b';
              ctx.font = '10px monospace';
              ctx.fillText(Math.round((i / 4) * maxS), 5, y + 3);
            }

            // Draw lines for each team
            const legendDiv = document.getElementById('chartLegend');
            legendDiv.innerHTML = teams.map((t, idx) => `
              <span style="color: ${TEAM_COLORS[idx % TEAM_COLORS.length]}; font-weight: bold;">■ ${t}</span>
            `).join('');

            teams.forEach((t) => {
              const s = series[t];
              if (!s.points.length) return;
              ctx.strokeStyle = s.color;
              ctx.lineWidth = 2.5;
              ctx.beginPath();

              s.points.forEach((pt, idx) => {
                const x = 40 + ((pt.time - minT) / (maxT - minT)) * (W - 60);
                const y = H - 30 - (pt.score / maxS) * (H - 50);
                if (idx === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
              });
              ctx.stroke();

              // Draw point circles
              s.points.forEach((pt) => {
                const x = 40 + ((pt.time - minT) / (maxT - minT)) * (W - 60);
                const y = H - 30 - (pt.score / maxS) * (H - 50);
                ctx.fillStyle = s.color;
                ctx.beginPath();
                ctx.arc(x, y, 4, 0, Math.PI * 2);
                ctx.fill();
              });
            });
          } catch (e) {
            console.error('차트 렌더링 실패:', e);
          }
        }

        async function loadBoard() {
          try {
            const res = await fetch('/api/ctf/scoreboard');
            const data = await res.json();
            const tbody = document.getElementById('boardBody');
            tbody.innerHTML = '';
            data.scoreboard.forEach(item => {
              const tr = document.createElement('tr');
              if (item.rank === 1) tr.className = 'rank-1';
              const fbBadge = item.first_blood_count > 0 
                ? `<span class="badge-fb">🩸 x${item.first_blood_count}</span>` 
                : `<span style="color: #64748b;">-</span>`;
              tr.innerHTML = `<td>#${item.rank}</td><td><b>${item.team}</b></td><td><b>${item.score}</b> pts</td><td>${item.solves_count}</td><td>${fbBadge}</td>`;
              tbody.appendChild(tr);
            });

            const feedDiv = document.getElementById('fbFeed');
            if (data.first_bloods && data.first_bloods.length > 0) {
              feedDiv.innerHTML = data.first_bloods.map(fb => `
                <div class="fb-feed-item">
                  <div>
                    <span class="fb-team">${fb.team}</span>님이 <span style="color: #e2e8f0;">${fb.title || fb.chal_id}</span> 문제를 최초 해결!
                  </div>
                  <span class="badge-fb">+${fb.bonus}pt</span>
                </div>
              `).reverse().join('');
            }
          } catch (e) {
            console.error('스코어보드 로드 실패:', e);
          }
        }

        async function loadChallenges() {
          try {
            const res = await fetch('/api/ctf/challenges');
            const data = await res.json();
            const grid = document.getElementById('chalGrid');
            if (!grid) return;
            grid.innerHTML = data.challenges.map(c => `
              <div class="chal-card" onclick="selectChal('${c.id}')">
                <div>
                  <div class="chal-header">
                    <span class="chal-cat">${c.category}</span>
                    <span class="chal-points">${c.current_points}pt</span>
                  </div>
                  <div class="chal-title">${c.title || c.id}</div>
                </div>
                <div class="chal-footer">
                  <span>🚩 Solves: ${c.solves_count}</span>
                  ${c.hints_count > 0 ? `<button class="btn-hint" onclick="event.stopPropagation(); requestHint('${c.id}', '${(c.title || c.id).replace(/'/g, "\\'")}')">💡 힌트 (50pt)</button>` : ''}
                </div>
              </div>
            `).join('');
          } catch (e) {
            console.error('챌린지 로드 실패:', e);
          }
        }

        function selectChal(id) {
          document.getElementById('chalInput').value = id;
          document.getElementById('flagInput').focus();
          showToast(`🎯 문제 [${id}]가 선택되었습니다.`);
        }

        function requestHint(chalId, title) {
          const team = document.getElementById('teamInput').value.trim() || 'Admin_RedTeam';
          const modal = document.getElementById('hintModal');
          const mTitle = document.getElementById('modalTitle');
          const mBody = document.getElementById('modalBody');
          const mActions = document.getElementById('modalActions');
          
          mTitle.innerHTML = `💡 힌트 상점: ${chalId}`;
          mBody.innerHTML = `
            <p style="margin-top:0;"><b>[${title}]</b> 문제의 힌트를 확인하시겠습니까?</p>
            <div style="background: rgba(251,191,36,0.1); border-left: 3px solid var(--gold); padding: 10px; margin: 10px 0; border-radius: 4px; font-size: 0.9rem;">
              ⚠️ 팀 <b>${team}</b>의 점수에서 <b>50pt</b>가 차감됩니다.<br>(이미 해금한 경우 차감 없이 무료로 재확인)
            </div>
          `;
          mActions.innerHTML = `
            <button class="btn-cancel" onclick="closeHintModal()">취소</button>
            <button class="btn-confirm" onclick="unlockHint('${chalId}')">50pt 지불 및 해금</button>
          `;
          modal.style.display = 'flex';
        }

        async function unlockHint(chalId) {
          const team = document.getElementById('teamInput').value.trim() || 'Admin_RedTeam';
          const mBody = document.getElementById('modalBody');
          const mActions = document.getElementById('modalActions');
          
          try {
            const res = await fetch('/api/ctf/hints/unlock', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({team_name: team, chal_id: chalId, hint_index: 0})
            });
            const data = await res.json();
            if (!res.ok) {
              mBody.innerHTML = `<p style="color: var(--red);">❌ 해금 실패: ${data.detail || data.message}</p>`;
              return;
            }
            
            mBody.innerHTML = `
              <div style="background: rgba(74, 222, 128, 0.1); border-left: 3px solid var(--green); padding: 12px; margin-bottom: 12px; border-radius: 4px;">
                <b style="color: var(--green);">🔓 ${data.status === 'already_unlocked' ? '기존 해금된 힌트' : '힌트 해금 완료 (-50pt)'}</b>
                <div style="margin-top: 8px; font-family: monospace; font-size: 0.95rem; color: #f1f5f9; line-height: 1.4;">${data.hint}</div>
              </div>
              <div style="font-size: 0.85rem; color: #94a3b8;">팀 ${team} 현재 점수: <b>${data.remaining_score}</b> pt</div>
            `;
            mActions.innerHTML = `<button class="btn-cancel" onclick="closeHintModal()">닫기</button>`;
            loadBoard();
            drawTimelineChart();
          } catch (e) {
            mBody.innerHTML = `<p style="color: var(--red);">오류 발생: ${e.message}</p>`;
          }
        }

        function closeHintModal() {
          document.getElementById('hintModal').style.display = 'none';
        }

        async function submitFlag() {
          const team = document.getElementById('teamInput').value;
          const chal = document.getElementById('chalInput').value;
          const flag = document.getElementById('flagInput').value;
          const resSpan = document.getElementById('submitResult');
          
          try {
            const res = await fetch('/api/ctf/submit', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({team_name: team, chal_id: chal, flag: flag})
            });
            const data = await res.json();
            resSpan.innerText = data.message;
            resSpan.style.color = data.status === 'correct' ? '#4ade80' : '#f87171';
            loadBoard();
            loadChallenges();
            drawTimelineChart();
          } catch (e) {
            resSpan.innerText = '오류 발생: ' + e.message;
            resSpan.style.color = '#f87171';
          }
        }

        // Connect real-time Server-Sent Events (SSE)
        function initSSE() {
          try {
            const es = new EventSource('/api/ctf/stream');
            es.addEventListener('flag_solve', (e) => {
              const ev = JSON.parse(e.data);
              if (ev.first_blood) {
                showToast(`🩸 <b>FIRST BLOOD!</b> <span style="color:#fbbf24;">${ev.team}</span>님이 <b>${ev.title || ev.chal_id}</b> 최초 해결! (+${ev.points}pt)`);
              } else {
                showToast(`🚩 <b>FLAG SOLVE!</b> <span style="color:#38bdf8;">${ev.team}</span>님이 <b>${ev.title || ev.chal_id}</b> 해결! (+${ev.points}pt)`);
              }
              loadBoard();
              loadChallenges();
              drawTimelineChart();
            });
            es.addEventListener('hint_unlocked', (e) => {
              const ev = JSON.parse(e.data);
              showToast(`💡 <b>힌트 해금!</b> <span style="color:#fbbf24;">${ev.team}</span>님이 <b>${ev.chal_id}</b> 힌트 구매 (-${ev.cost}pt)`);
              loadBoard();
              drawTimelineChart();
            });
            es.addEventListener('team_registered', (e) => {
              loadBoard();
              drawTimelineChart();
            });
            es.onerror = () => {
              // Reconnect automatically handled by browser EventSource
            };
          } catch (err) {
            console.warn('SSE 연결 실패, 폴링으로 전환:', err);
          }
        }

        loadBoard();
        loadChallenges();
        drawTimelineChart();
        initSSE();
        setInterval(() => { loadBoard(); loadChallenges(); }, 6000);
      </script>
    </body>
    </html>
    """
