#!/usr/bin/env python3
"""Script to add 37th track 'sochunt' (35 challenges, 1,295 milestone) to VibeHacking wargame."""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WG_DIR = REPO_ROOT / "wargame"

CHALLENGES_SPEC = [
    # Tier 0 (2)
    (0, "t0_sochunt_soc_tiers", 10, "sochunt_soc_tiers_v1",
     "SOC 조직 구조와 티어별 역할", "SOC Architecture & Tier Roles",
     "현대 엔터프라이즈 SOC의 Tier 1(경보 트리아지), Tier 2(사고 심층 분석/대응), Tier 3(선제적 위협 헌팅) 조직 체계 분석 챌린지입니다.\n지정된 식별자 `sochunt_soc_tiers_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_soc_tiers_v1\") 앞 20자리}`",
     "Analyze modern SOC tier architecture: Tier 1 (Alert Triage), Tier 2 (Incident Response), and Tier 3 (Proactive Threat Hunting).\nCompute the first 20 hex characters of SHA256(\"sochunt_soc_tiers_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_soc_tiers_v1\") first 20 hex}`",
     ["식별자 `sochunt_soc_tiers_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_soc_tiers_v1\").", "Wrap in `FLAG{...}` format."]),

    (0, "t0_sochunt_sysmon_eventids", 20, "sochunt_sysmon_eventids_v1",
     "Sysmon 핵심 Event ID 체계", "Sysmon Core Event ID Telemetry",
     "Windows 엔드포인트 텔레메트리 핵심인 Sysmon Event ID 1(프로세스 생성), 3(네트워크 연결), 8(CreateRemoteThread) 체계 분석 챌린지입니다.\n지정된 식별자 `sochunt_sysmon_eventids_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_sysmon_eventids_v1\") 앞 20자리}`",
     "Inspect Sysmon telemetry schema including Event ID 1 (ProcessCreate), 3 (NetworkConnect), and 8 (CreateRemoteThread).\nCompute the first 20 hex characters of SHA256(\"sochunt_sysmon_eventids_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_sysmon_eventids_v1\") first 20 hex}`",
     ["식별자 `sochunt_sysmon_eventids_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_sysmon_eventids_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 1 (6)
    (1, "t1_sochunt_suricata_fastlog", 30, "sochunt_suricata_fastlog_v1",
     "Suricata NIDS 경보 및 로그 포맷", "Suricata NIDS Alert & Log Format",
     "오픈소스 침입 탐지 시스템(Suricata)의 fast.log 및 eve.json 경보 포맷과 시그니처 매칭 분석 챌린지입니다.\n지정된 식별자 `sochunt_suricata_fastlog_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_suricata_fastlog_v1\") 앞 20자리}`",
     "Examine Suricata fast.log and eve.json alert schema for network signature matching.\nCompute the first 20 hex characters of SHA256(\"sochunt_suricata_fastlog_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_suricata_fastlog_v1\") first 20 hex}`",
     ["식별자 `sochunt_suricata_fastlog_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_suricata_fastlog_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_sochunt_winevent_security", 40, "sochunt_winevent_security_v1",
     "Windows 보안 이벤트 4624 로그온 구조", "Windows Security Event 4624 Logon Structure",
     "Windows Security.evtx의 대표 감사 로그 Event 4624(성공한 로그온) 필드 구조 및 인증 패키지 분석 챌린지입니다.\n지정된 식별자 `sochunt_winevent_security_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_winevent_security_v1\") 앞 20자리}`",
     "Analyze Windows Security event 4624 logon structure and authentication package attributes.\nCompute the first 20 hex characters of SHA256(\"sochunt_winevent_security_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_winevent_security_v1\") first 20 hex}`",
     ["식별자 `sochunt_winevent_security_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_winevent_security_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_sochunt_siem_cim", 50, "sochunt_siem_cim_v1",
     "SIEM 공통 정보 모델 (CIM) 정규화", "SIEM Common Information Model (CIM)",
     "이기종 보안 장비 로그를 일관된 필드로 정규화하는 Splunk CIM 및 Elastic ECS 데이터 모델 분석 챌린지입니다.\n지정된 식별자 `sochunt_siem_cim_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_siem_cim_v1\") 앞 20자리}`",
     "Understand multi-source normalization via Splunk Common Information Model (CIM) and Elastic ECS.\nCompute the first 20 hex characters of SHA256(\"sochunt_siem_cim_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_siem_cim_v1\") first 20 hex}`",
     ["식별자 `sochunt_siem_cim_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_siem_cim_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_sochunt_mitre_attack", 60, "sochunt_mitre_attack_v1",
     "MITRE ATT&CK 프레임워크 전술과 기법", "MITRE ATT&CK Tactics & Techniques",
     "사이버 위협 행위자의 침투 수명주기를 매핑하는 MITRE ATT&CK 전술 및 기법 분류 체계 분석 챌린지입니다.\n지정된 식별자 `sochunt_mitre_attack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_mitre_attack_v1\") 앞 20자리}`",
     "Map adversary behaviors using the MITRE ATT&CK matrix across enterprise tactics and techniques.\nCompute the first 20 hex characters of SHA256(\"sochunt_mitre_attack_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_mitre_attack_v1\") first 20 hex}`",
     ["식별자 `sochunt_mitre_attack_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_mitre_attack_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_sochunt_incident_picerl", 70, "sochunt_incident_picerl_v1",
     "SANS 침해사고 대응 6단계 (PICERL)", "SANS Incident Response Lifecycle (PICERL)",
     "SANS 표준 사고 대응 프레임워크(Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) 분석 챌린지입니다.\n지정된 식별자 `sochunt_incident_picerl_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_incident_picerl_v1\") 앞 20자리}`",
     "Review SANS 6-stage incident response methodology (PICERL).\nCompute the first 20 hex characters of SHA256(\"sochunt_incident_picerl_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_incident_picerl_v1\") first 20 hex}`",
     ["식별자 `sochunt_incident_picerl_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_incident_picerl_v1\").", "Wrap in `FLAG{...}` format."]),

    (1, "t1_sochunt_parent_pid_spoofing", 80, "sochunt_parent_pid_spoofing_v1",
     "Parent PID Spoofing 비정상 계층 식별", "Parent PID Spoofing Tree Anomaly",
     "Sysmon Event 1 로그에서 Office 문서가 비정상적으로 명령 셸 자식 프로세스를 기동하는 비정상 프로세스 계층 헌팅 챌린지입니다.\n지정된 식별자 `sochunt_parent_pid_spoofing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_parent_pid_spoofing_v1\") 앞 20자리}`",
     "Detect anomalous process hierarchies where productivity software spawns command interpreters.\nCompute the first 20 hex characters of SHA256(\"sochunt_parent_pid_spoofing_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_parent_pid_spoofing_v1\") first 20 hex}`",
     ["식별자 `sochunt_parent_pid_spoofing_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_parent_pid_spoofing_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 2 (12)
    (2, "t2_sochunt_dns_tunneling_entropy", 100, "sochunt_dns_tunneling_entropy_v1",
     "DNS 터널링 고엔트로피 서브도메인 탐지", "High Entropy DNS Tunneling Detection",
     "DNS 쿼리 서브도메인의 섀넌 엔트로피와 길이를 분석하여 데이터 유출 터널을 탐지하는 챌린지입니다.\n지정된 식별자 `sochunt_dns_tunneling_entropy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_dns_tunneling_entropy_v1\") 앞 20자리}`",
     "Analyze Shannon entropy and length of DNS query subdomains to detect data exfiltration tunnels.\nCompute the first 20 hex characters of SHA256(\"sochunt_dns_tunneling_entropy_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_dns_tunneling_entropy_v1\") first 20 hex}`",
     ["식별자 `sochunt_dns_tunneling_entropy_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_dns_tunneling_entropy_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_tls_ja3_fingerprint", 110, "sochunt_tls_ja3_fingerprint_v1",
     "TLS Client Hello JA3 해시 지문 분석", "TLS Client Hello JA3 Fingerprinting",
     "암호화 통신에서도 C2 프레임워크(Cobalt Strike, Sliver) 클라이언트를 식별할 수 있는 JA3 지문 분석 챌린지입니다.\n지정된 식별자 `sochunt_tls_ja3_fingerprint_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_tls_ja3_fingerprint_v1\") 앞 20자리}`",
     "Fingerprint encrypted C2 beaconing using TLS Client Hello JA3 hashing.\nCompute the first 20 hex characters of SHA256(\"sochunt_tls_ja3_fingerprint_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_tls_ja3_fingerprint_v1\") first 20 hex}`",
     ["식별자 `sochunt_tls_ja3_fingerprint_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_tls_ja3_fingerprint_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_lolbins_certutil", 120, "sochunt_lolbins_certutil_v1",
     "LOLBins Certutil 외부 다운로드 헌팅", "LOLBins Certutil Download Hunting",
     "윈도우 내장 유틸리티 certutil.exe의 urlcache 옵션을 악용한 외부 페이로드 다운로드 탐지 챌린지입니다.\n지정된 식별자 `sochunt_lolbins_certutil_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_lolbins_certutil_v1\") 앞 20자리}`",
     "Hunt living-off-the-land binaries downloading external payloads via certutil urlcache.\nCompute the first 20 hex characters of SHA256(\"sochunt_lolbins_certutil_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_lolbins_certutil_v1\") first 20 hex}`",
     ["식별자 `sochunt_lolbins_certutil_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_lolbins_certutil_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_lsass_access_mask", 130, "sochunt_lsass_access_mask_v1",
     "Sysmon Event 10 LSASS 메모리 접근 마스크", "Sysmon Event 10 LSASS Access Mask",
     "Mimikatz 등 자격증명 덤프 도구가 LSASS 프로세스에 요청하는 GrantedAccess 마스크(0x1010, 0x1410) 탐지 챌린지입니다.\n지정된 식별자 `sochunt_lsass_access_mask_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_lsass_access_mask_v1\") 앞 20자리}`",
     "Detect credential theft tools opening handles to LSASS with GrantedAccess masks like 0x1010.\nCompute the first 20 hex characters of SHA256(\"sochunt_lsass_access_mask_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_lsass_access_mask_v1\") first 20 hex}`",
     ["식별자 `sochunt_lsass_access_mask_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_lsass_access_mask_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_logon_type_9", 140, "sochunt_logon_type_9_v1",
     "Logon Type 9 NewCredentials 인증 추적", "Logon Type 9 NewCredentials Tracking",
     "Windows EventCode 4624 LogonType 9(NewCredentials)가 의미하는 Pass-the-Hash / Overpass-the-Hash 정황 분석 챌린지입니다.\n지정된 식별자 `sochunt_logon_type_9_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_logon_type_9_v1\") 앞 20자리}`",
     "Correlate Windows Logon Type 9 NewCredentials indicating Pass-the-Hash authentication.\nCompute the first 20 hex characters of SHA256(\"sochunt_logon_type_9_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_logon_type_9_v1\") first 20 hex}`",
     ["식별자 `sochunt_logon_type_9_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_logon_type_9_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_sigma_rule_syntax", 150, "sochunt_sigma_rule_syntax_v1",
     "Sigma 탐지 룰 표준 문법 작성", "Sigma Generic Detection Rule Syntax",
     "SIEM 벤더 독립적인 오픈소스 탐지 룰 포맷인 Sigma의 logsource, detection, condition 명세 분석 챌린지입니다.\n지정된 식별자 `sochunt_sigma_rule_syntax_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_sigma_rule_syntax_v1\") 앞 20자리}`",
     "Understand generic Sigma rule structures across logsource, detection selections, and conditions.\nCompute the first 20 hex characters of SHA256(\"sochunt_sigma_rule_syntax_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_sigma_rule_syntax_v1\") first 20 hex}`",
     ["식별자 `sochunt_sigma_rule_syntax_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_sigma_rule_syntax_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_remote_thread_injection", 160, "sochunt_remote_thread_injection_v1",
     "CreateRemoteThread (Event 8) 메모리 주입 분석", "CreateRemoteThread Memory Injection Analysis",
     "Sysmon Event 8 로그에서 원본 프로세스가 타깃 프로세스에 원격 스레드를 생성하는 DLL 인젝션 탐지 챌린지입니다.\n지정된 식별자 `sochunt_remote_thread_injection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_remote_thread_injection_v1\") 앞 20자리}`",
     "Analyze Sysmon Event 8 CreateRemoteThread to detect reflective DLL or shellcode injection.\nCompute the first 20 hex characters of SHA256(\"sochunt_remote_thread_injection_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_remote_thread_injection_v1\") first 20 hex}`",
     ["식별자 `sochunt_remote_thread_injection_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_remote_thread_injection_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_beacon_jitter_analysis", 170, "sochunt_beacon_jitter_analysis_v1",
     "C2 비콘 주기성 및 Jitter 통계적 헌팅", "Statistical C2 Beaconing & Jitter Hunting",
     "네트워크 연결 타임스탬프 델타(Delta) 편차를 계산하여 Jitter가 가미된 C2 비콘 주기를 밝혀내는 챌린지입니다.\n지정된 식별자 `sochunt_beacon_jitter_analysis_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_beacon_jitter_analysis_v1\") 앞 20자리}`",
     "Calculate connection interval variances to unmask periodic C2 beacons obscured by jitter.\nCompute the first 20 hex characters of SHA256(\"sochunt_beacon_jitter_analysis_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_beacon_jitter_analysis_v1\") first 20 hex}`",
     ["식별자 `sochunt_beacon_jitter_analysis_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_beacon_jitter_analysis_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_splunk_spl_lolbin", 180, "sochunt_splunk_spl_lolbin_v1",
     "Splunk SPL 파이프라인 상관분석 쿼리", "Splunk SPL Correlation Pipeline",
     "index=sysmon EventCode=1 Image=*\\certutil.exe 조건으로 필터링 및 통계를 산출하는 SPL 쿼리 작성 챌린지입니다.\n지정된 식별자 `sochunt_splunk_spl_lolbin_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_splunk_spl_lolbin_v1\") 앞 20자리}`",
     "Formulate Splunk Processing Language (SPL) search pipelines to isolate LOLBins command arguments.\nCompute the first 20 hex characters of SHA256(\"sochunt_splunk_spl_lolbin_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_splunk_spl_lolbin_v1\") first 20 hex}`",
     ["식별자 `sochunt_splunk_spl_lolbin_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_splunk_spl_lolbin_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_kql_lateral_movement", 190, "sochunt_kql_lateral_movement_v1",
     "Azure Sentinel KQL 횡적 이동 헌팅", "Azure Sentinel KQL Lateral Movement Hunting",
     "SecurityEvent 테이블에서 WMI 및 PowerShell 원격 명령 실행을 집계하는 Kusto Query Language(KQL) 챌린지입니다.\n지정된 식별자 `sochunt_kql_lateral_movement_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_kql_lateral_movement_v1\") 앞 20자리}`",
     "Construct KQL hunting queries in Microsoft Sentinel detecting remote process execution via WMI.\nCompute the first 20 hex characters of SHA256(\"sochunt_kql_lateral_movement_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_kql_lateral_movement_v1\") first 20 hex}`",
     ["식별자 `sochunt_kql_lateral_movement_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_kql_lateral_movement_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_zeek_conn_log", 200, "sochunt_zeek_conn_log_v1",
     "Zeek conn.log 연결 상태 플래그 분석", "Zeek conn.log Connection State Analysis",
     "네트워크 트래픽 메타데이터 엔진인 Zeek의 연결 상태 플래그(S0, SF, RSTO, REJ)를 해석하는 챌린지입니다.\n지정된 식별자 `sochunt_zeek_conn_log_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_zeek_conn_log_v1\") 앞 20자리}`",
     "Interpret Zeek connection state flags like S0 and RSTO to detect port scanning and blocked connections.\nCompute the first 20 hex characters of SHA256(\"sochunt_zeek_conn_log_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_zeek_conn_log_v1\") first 20 hex}`",
     ["식별자 `sochunt_zeek_conn_log_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_zeek_conn_log_v1\").", "Wrap in `FLAG{...}` format."]),

    (2, "t2_sochunt_mimikatz_sekurlsa", 210, "sochunt_mimikatz_sekurlsa_v1",
     "Mimikatz sekurlsa NTLM 덤프 행위 탐지", "Mimikatz sekurlsa NTLM Dump Detection",
     "LSASS 메모리에서 인증 공급자 보안 패키지를 탐색하여 NTLM 해시를 덤프하는 Mimikatz 행위 탐지 챌린지입니다.\n지정된 식별자 `sochunt_mimikatz_sekurlsa_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_mimikatz_sekurlsa_v1\") 앞 20자리}`",
     "Detect Mimikatz sekurlsa module querying authentication providers to dump plaintext/NTLM hashes.\nCompute the first 20 hex characters of SHA256(\"sochunt_mimikatz_sekurlsa_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_mimikatz_sekurlsa_v1\") first 20 hex}`",
     ["식별자 `sochunt_mimikatz_sekurlsa_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_mimikatz_sekurlsa_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 3 (10)
    (3, "t3_sochunt_soar_playbook_workflow", 230, "sochunt_soar_playbook_workflow_v1",
     "SOAR 자동화 격리 및 차단 플레이북", "SOAR Automated Containment Playbook",
     "고위험 위협 경보 발생 시 EDR API로 엔드포인트를 격리하고 방화벽에 IoC를 자동 배포하는 SOAR 워크플로우 챌린지입니다.\n지정된 식별자 `sochunt_soar_playbook_workflow_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_soar_playbook_workflow_v1\") 앞 20자리}`",
     "Design automated SOAR playbooks orchestrating host isolation via EDR and firewall IoC updates.\nCompute the first 20 hex characters of SHA256(\"sochunt_soar_playbook_workflow_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_soar_playbook_workflow_v1\") first 20 hex}`",
     ["식별자 `sochunt_soar_playbook_workflow_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_soar_playbook_workflow_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_process_hollowing_etw", 250, "sochunt_process_hollowing_etw_v1",
     "Process Hollowing 언매핑과 ETW 패칭 대응", "Process Hollowing Unmap & ETW Patching Defense",
     "합법 프로세스(svchost) 생성 후 메모리를 비우고 악성 코드를 주입하는 기법과 ETW 침묵 탐지 챌린지입니다.\n지정된 식별자 `sochunt_process_hollowing_etw_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_process_hollowing_etw_v1\") 앞 20자리}`",
     "Correlate Process Hollowing unmapping and EtwEventWrite user-mode tampering stubs.\nCompute the first 20 hex characters of SHA256(\"sochunt_process_hollowing_etw_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_process_hollowing_etw_v1\") first 20 hex}`",
     ["식별자 `sochunt_process_hollowing_etw_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_process_hollowing_etw_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_overpass_the_hash", 270, "sochunt_overpass_the_hash_v1",
     "Overpass-the-Hash Kerberos TGT 요청 헌팅", "Overpass-the-Hash Kerberos TGT Request Hunting",
     "NTLM 해시를 사용해 Kerberos AS-REQ을 요청하여 유효한 TGT 티켓을 획득하는 Overpass-the-Hash 탐지 챌린지입니다.\n지정된 식별자 `sochunt_overpass_the_hash_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_overpass_the_hash_v1\") 앞 20자리}`",
     "Identify Overpass-the-Hash by correlating Kerberos Event 4768 requesting RC4-HMAC encryption.\nCompute the first 20 hex characters of SHA256(\"sochunt_overpass_the_hash_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_overpass_the_hash_v1\") first 20 hex}`",
     ["식별자 `sochunt_overpass_the_hash_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_overpass_the_hash_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_dns_dga_clustering", 290, "sochunt_dns_dga_clustering_v1",
     "도메인 생성 알고리즘(DGA) C2 클러스터링", "Domain Generation Algorithm (DGA) Clustering",
     "악성코드가 C2 차단을 우회하기 위해 날짜 기반으로 대량 생성하는 DGA 도메인 탐지 및 차단 챌린지입니다.\n지정된 식별자 `sochunt_dns_dga_clustering_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_dns_dga_clustering_v1\") 앞 20자리}`",
     "Cluster algorithmic pseudo-random subdomains generated by DGA malware families.\nCompute the first 20 hex characters of SHA256(\"sochunt_dns_dga_clustering_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_dns_dga_clustering_v1\") first 20 hex}`",
     ["식별자 `sochunt_dns_dga_clustering_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_dns_dga_clustering_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_kernel_byovd_hunting", 310, "sochunt_kernel_byovd_hunting_v1",
     "BYOVD 취약 드라이버 로드 헌팅", "BYOVD Vulnerable Driver Load Hunting",
     "공격자가 커널 메모리 보호(DSE)를 우회하기 위해 정당하게 서명된 취약 드라이버를 로드하는 행위 탐지 챌린지입니다.\n지정된 식별자 `sochunt_kernel_byovd_hunting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_kernel_byovd_hunting_v1\") 앞 20자리}`",
     "Hunt Bring Your Own Vulnerable Driver (BYOVD) tactics abusing signed drivers via Sysmon Event 6/7.\nCompute the first 20 hex characters of SHA256(\"sochunt_kernel_byovd_hunting_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_kernel_byovd_hunting_v1\") first 20 hex}`",
     ["식별자 `sochunt_kernel_byovd_hunting_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_kernel_byovd_hunting_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_covert_icmp_tunnel", 330, "sochunt_covert_icmp_tunnel_v1",
     "ICMP 은닉 터널 데이터 유출 분석", "Covert ICMP Tunnel Data Exfiltration",
     "방화벽의 비인가 포트 차단을 회피하기 위해 ICMP Echo Request/Reply 데이터 필드에 정보를 은닉 전송하는 챌린지입니다.\n지정된 식별자 `sochunt_covert_icmp_tunnel_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_covert_icmp_tunnel_v1\") 앞 20자리}`",
     "Carve and reconstruct exfiltrated sensitive data hidden inside ICMP Echo Request payload fields.\nCompute the first 20 hex characters of SHA256(\"sochunt_covert_icmp_tunnel_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_covert_icmp_tunnel_v1\") first 20 hex}`",
     ["식별자 `sochunt_covert_icmp_tunnel_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_covert_icmp_tunnel_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_kerberoasting_spn", 350, "sochunt_kerberoasting_spn_v1",
     "Kerberoasting 서비스 티켓 대량 요청 탐지", "Kerberoasting Service Ticket Bulk Request",
     "서비스 주체 이름(SPN)이 등록된 도메인 계정의 TGS 티켓(Event 4769, 암호화 0x17 RC4)을 대량 요청하는 행위 헌팅 챌린지입니다.\n지정된 식별자 `sochunt_kerberoasting_spn_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_kerberoasting_spn_v1\") 앞 20자리}`",
     "Detect bulk Kerberos TGS-REQ ticket requests with RC4 encryption (0x17) characteristic of Kerberoasting.\nCompute the first 20 hex characters of SHA256(\"sochunt_kerberoasting_spn_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_kerberoasting_spn_v1\") first 20 hex}`",
     ["식별자 `sochunt_kerberoasting_spn_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_kerberoasting_spn_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_yara_l_chronicle", 370, "sochunt_yara_l_chronicle_v1",
     "Google SecOps YARA-L 멀티 이벤트 상관분석", "Google SecOps YARA-L Multi-Event Correlation",
     "클라우드 스케일 SIEM에서 프로세스 생성 이벤트와 네트워크 아웃바운드 연결 이벤트를 결합하는 YARA-L 룰 챌린지입니다.\n지정된 식별자 `sochunt_yara_l_chronicle_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_yara_l_chronicle_v1\") 앞 20자리}`",
     "Author multi-event detection logic correlating endpoint process events with network sockets in YARA-L.\nCompute the first 20 hex characters of SHA256(\"sochunt_yara_l_chronicle_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_yara_l_chronicle_v1\") first 20 hex}`",
     ["식별자 `sochunt_yara_l_chronicle_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_yara_l_chronicle_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_edr_telemetry_silencing", 390, "sochunt_edr_telemetry_silencing_v1",
     "EDR 텔레메트리 블라인드 침묵 공격 탐지", "EDR Telemetry Silencing & Blind Spot Detection",
     "공격자가 EDR 에이전트 서비스나 미니필터 드라이버를 중단하여 로그 유입을 차단하는 텔레메트리 공백(Heartbeat 결손) 헌팅 챌린지입니다.\n지정된 식별자 `sochunt_edr_telemetry_silencing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_edr_telemetry_silencing_v1\") 앞 20자리}`",
     "Identify blind spots caused by adversaries terminating EDR services or blinding kernel telemetry agents.\nCompute the first 20 hex characters of SHA256(\"sochunt_edr_telemetry_silencing_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_edr_telemetry_silencing_v1\") first 20 hex}`",
     ["식별자 `sochunt_edr_telemetry_silencing_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_edr_telemetry_silencing_v1\").", "Wrap in `FLAG{...}` format."]),

    (3, "t3_sochunt_apt_c2_ja3s_server_mesh", 410, "sochunt_apt_c2_ja3s_server_mesh_v1",
     "JA3S 서버 지문과 C2 인프라 클러스터링", "JA3S Server Fingerprinting & C2 Infrastructure Clustering",
     "서버 측 Server Hello JA3S 지문과 X.509 인증서 발급자 패턴을 결합하여 APT C2 통신 인프라망을 클러스터링하는 챌린지입니다.\n지정된 식별자 `sochunt_apt_c2_ja3s_server_mesh_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_apt_c2_ja3s_server_mesh_v1\") 앞 20자리}`",
     "Correlate JA3S server fingerprints and TLS certificate metadata to map adversary proxy infrastructure.\nCompute the first 20 hex characters of SHA256(\"sochunt_apt_c2_ja3s_server_mesh_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_apt_c2_ja3s_server_mesh_v1\") first 20 hex}`",
     ["식별자 `sochunt_apt_c2_ja3s_server_mesh_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_apt_c2_ja3s_server_mesh_v1\").", "Wrap in `FLAG{...}` format."]),

    # Tier 4 (5)
    (4, "t4_sochunt_golden_ticket_krbtgt", 450, "sochunt_golden_ticket_krbtgt_v1",
     "Golden Ticket KRBTGT NTLM 위조 헌팅", "Golden Ticket KRBTGT Forgery Hunting",
     "도메인 핵심 계정 KRBTGT 해시 유출로 인해 조작된 10년 만기 TGT 티켓과 비정상 SID 히스토리 헌팅 챌린지입니다.\n지정된 식별자 `sochunt_golden_ticket_krbtgt_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_golden_ticket_krbtgt_v1\") 앞 20자리}`",
     "Hunt Golden Ticket forgeries by auditing abnormal ticket lifetimes and extra SID injections.\nCompute the first 20 hex characters of SHA256(\"sochunt_golden_ticket_krbtgt_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_golden_ticket_krbtgt_v1\") first 20 hex}`",
     ["식별자 `sochunt_golden_ticket_krbtgt_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_golden_ticket_krbtgt_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_sochunt_shadow_admin_acl", 470, "sochunt_shadow_admin_acl_v1",
     "Shadow Admin 숨겨진 AD ACL 권한 헌팅", "Active Directory Shadow Admin ACL Hunting",
     "Domain Admins 그룹에 속하지 않으면서 GenericAll, WriteDacl 등 위험한 ACL로 도메인을 장악하는 Shadow Admin 탐지 챌린지입니다.\n지정된 식별자 `sochunt_shadow_admin_acl_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_shadow_admin_acl_v1\") 앞 20자리}`",
     "Detect covert Active Directory persistence via Shadow Admin accounts abusing excessive ACLs.\nCompute the first 20 hex characters of SHA256(\"sochunt_shadow_admin_acl_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_shadow_admin_acl_v1\") first 20 hex}`",
     ["식별자 `sochunt_shadow_admin_acl_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_shadow_admin_acl_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_sochunt_cloud_trail_imds_pivot", 480, "sochunt_cloud_trail_imds_pivot_v1",
     "AWS CloudTrail & IMDS 피벗 이상 헌팅", "AWS CloudTrail & IMDS Pivot Anomaly Hunting",
     "EC2 인스턴스 프로파일 자격증명이 엔드포인트 외부 인터넷 IP에서 호출되는 위험 징후를 추적하는 멀티 클라우드 헌팅 챌린지입니다.\n지정된 식별자 `sochunt_cloud_trail_imds_pivot_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_cloud_trail_imds_pivot_v1\") 앞 20자리}`",
     "Hunt IAM credential theft by correlating instance metadata token exfiltration with external CloudTrail API calls.\nCompute the first 20 hex characters of SHA256(\"sochunt_cloud_trail_imds_pivot_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_cloud_trail_imds_pivot_v1\") first 20 hex}`",
     ["식별자 `sochunt_cloud_trail_imds_pivot_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_cloud_trail_imds_pivot_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_sochunt_zero_trust_pipeline", 490, "sochunt_zero_trust_pipeline_v1",
     "엔터프라이즈 제로 트러스트 SOC 통합 파이프라인", "Enterprise Zero Trust SOC Pipeline Architecture",
     "엔드포인트, 신원, 네트워크, 클라우드의 모든 신호를 결합하여 실시간 동적 신뢰 평가를 수행하는 차세대 방어 체계 구축 챌린지입니다.\n지정된 식별자 `sochunt_zero_trust_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_zero_trust_pipeline_v1\") 앞 20자리}`",
     "Architect next-generation automated SOC defenses fusing continuous identity verification and EDR telemetry.\nCompute the first 20 hex characters of SHA256(\"sochunt_zero_trust_pipeline_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_zero_trust_pipeline_v1\") first 20 hex}`",
     ["식별자 `sochunt_zero_trust_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_zero_trust_pipeline_v1\").", "Wrap in `FLAG{...}` format."]),

    (4, "t4_sochunt_apt_capstone_incident", 500, "sochunt_apt_capstone_incident_v1",
     "SOC 위협 헌팅 캡스톤: APT 공격 풀체인 트리아지", "SOC Threat Hunting Capstone: Full APT Triage",
     "초기 피싱 매크로 -> Sysmon 인젝션 -> Suricata C2 탐지 -> LSASS 덤프 -> Pass-the-Hash -> SOAR 자동 격리 풀체인 종합 실전 챌린지입니다.\n지정된 식별자 `sochunt_apt_capstone_incident_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sochunt_apt_capstone_incident_v1\") 앞 20자리}`",
     "Execute comprehensive incident triage across phishing execution, process injection, C2 beacons, and automated containment.\nCompute the first 20 hex characters of SHA256(\"sochunt_apt_capstone_incident_v1\").\n\nFormat: `FLAG{SHA256(\"sochunt_apt_capstone_incident_v1\") first 20 hex}`",
     ["식별자 `sochunt_apt_capstone_incident_v1`의 SHA-256 해시 앞 20자리를 추출하세요.", "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."],
     ["Compute the first 20 hex chars of SHA-256(\"sochunt_apt_capstone_incident_v1\").", "Wrap in `FLAG{...}` format."])
]


def make_flag(ident: str) -> str:
    h = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
    return f"FLAG{{{h}}}"


def main():
    print(f"=== Generating 37th Track: sochunt ({len(CHALLENGES_SPEC)} challenges) ===")

    # 1. Update wargame/assets/challenges.js
    chal_js_path = WG_DIR / "assets" / "challenges.js"
    src = chal_js_path.read_text(encoding="utf-8")

    # Track definition
    track_def = """  {
      "id": "sochunt",
      "icon": "🛡️",
      "ko": "SOC 위협 헌팅·SIEM·IR",
      "en": "SOC Threat Hunting & Incident Response",
      "desc_ko": "Sysmon 프로세스 인젝션·Suricata NIDS 탐지·DNS 터널링 및 JA3 C2 비콘·Pass-the-Hash·SPL/KQL 상관분석·SOAR 자동 격리.",
      "desc_en": "Sysmon process injection, Suricata NIDS detection, DNS tunneling & JA3 C2 beacons, Pass-the-Hash, SPL/KQL correlation, SOAR auto containment."
  }"""

    if '"id": "sochunt"' not in src:
        # Insert before ]; of TRACKS
        tracks_end = src.find("const CHALLENGES = [")
        idx = src.rfind("}", 0, tracks_end)
        src = src[:idx+1] + ",\n" + track_def + "\n" + src[tracks_end-3:]
        print("Added track 'sochunt' to TRACKS in challenges.js")

    # Generate challenges JSON objects
    new_chals = []
    for tier, cid, pts, ident, t_ko, t_en, p_ko, p_en, h_ko, h_en in CHALLENGES_SPEC:
        flag = make_flag(ident)
        ch_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()
        obj = {
            "id": cid,
            "tier": tier,
            "cat": "sochunt",
            "track": "sochunt",
            "points": pts,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {"ko": t_ko, "en": t_en},
            "prompt": {"ko": p_ko, "en": p_en},
            "hints": {"ko": h_ko, "en": h_en},
            "hash": ch_hash
        }
        new_chals.append(obj)

    # Check if first challenge is already in challenges.js
    if CHALLENGES_SPEC[0][1] not in src:
        last_bracket = src.rfind("];")
        formatted_json = ",\n" + ",\n".join(json.dumps(c, ensure_ascii=False, indent=2) for c in new_chals)
        src = src[:last_bracket] + formatted_json + "\n" + src[last_bracket:]
        chal_js_path.write_text(src, encoding="utf-8")
        print(f"Added {len(new_chals)} challenges to CHALLENGES in challenges.js")

    # 2. Update wargame/scripts/solve-derivable.js
    sd_path = WG_DIR / "scripts" / "solve-derivable.js"
    sd_text = sd_path.read_text(encoding="utf-8")
    ids = [c[1] for c in CHALLENGES_SPEC]
    if ids[0] not in sd_text:
        formatted_ids = ',\n  '.join(f'"{i}"' for i in ids)
        sd_text = sd_text.replace(
            '"t4_apisec_modern_auth_capstone_pwn"',
            f'"t4_apisec_modern_auth_capstone_pwn",\n  {formatted_ids}'
        )
        sd_path.write_text(sd_text, encoding="utf-8")
        print("Updated wargame/scripts/solve-derivable.js")

    # 3. Update wargame/index.html
    idx_path = WG_DIR / "index.html"
    idx_text = idx_path.read_text(encoding="utf-8")
    idx_text = re.sub(r'0/1260', '0/1295', idx_text)
    if 'data-track="sochunt"' not in idx_text:
        idx_text = idx_text.replace(
            '<button class="track-btn" data-track="apisec" onclick="filterTrack(\'apisec\')">🌐 API보안</button>',
            '<button class="track-btn" data-track="apisec" onclick="filterTrack(\'apisec\')">🌐 API보안</button>\n      <button class="track-btn" data-track="sochunt" onclick="filterTrack(\'sochunt\')">🛡️ SOC헌팅</button>'
        )
    idx_path.write_text(idx_text, encoding="utf-8")
    print("Updated wargame/index.html")

    # 4. Update wargame/README.md
    wgr_path = WG_DIR / "README.md"
    wgr_text = wgr_path.read_text(encoding="utf-8")
    wgr_text = wgr_text.replace("총 **1260문제**", "총 **1295문제**")
    wgr_text = wgr_text.replace("Total **1260 challenges**", "Total **1295 challenges**")

    # Tier table counts:
    # Tier 0: 72 -> 74
    # Tier 1: 216 -> 222
    # Tier 2: 432 -> 444
    # Tier 3: 360 -> 370
    # Tier 4: 180 -> 185
    wgr_text = re.sub(r'(\| `perimeter` \| 0 \(입문\) \| )72( \|)', r'\g<1>74\2', wgr_text)
    wgr_text = re.sub(r'(\| `webserver` \| 1 \(기초\) \| )216( \|)', r'\g<1>222\2', wgr_text)
    wgr_text = re.sub(r'(\| `internal` \| 2 \(중급\) \| )432( \|)', r'\g<1>444\2', wgr_text)
    wgr_text = re.sub(r'(\| `vault` \| 3 \(고급\) \| )360( \|)', r'\g<1>370\2', wgr_text)
    wgr_text = re.sub(r'(\| `core` \| 4 \(마스터\) \| )180( \|)', r'\g<1>185\2', wgr_text)

    # Add sochunt track row to tracks table
    if '`sochunt`' not in wgr_text:
        apisec_row = '| `apisec` | 🌐 API 보안·REST·GraphQL·JWT | OWASP API Top 10·BOLA/IDOR·BFLA 권한 상승·GraphQL 인트로스펙션 및 배치 공격·JWT None 알고리즘·OAuth2 취약점 | 35 |'
        sochunt_row = '| `sochunt` | 🛡️ SOC 위협 헌팅·SIEM·IR | Sysmon 프로세스 인젝션·Suricata NIDS 탐지·DNS 터널링 및 JA3 C2 비콘·Pass-the-Hash·SPL/KQL 상관분석·SOAR 자동 격리 | 35 |'
        wgr_text = wgr_text.replace(apisec_row, apisec_row + '\n' + sochunt_row)

    wgr_path.write_text(wgr_text, encoding="utf-8")
    print("Updated wargame/README.md")

    # 5. Update wargame/tests/test_cli.py
    cli_test_path = WG_DIR / "tests" / "test_cli.py"
    if cli_test_path.exists():
        clit = cli_test_path.read_text(encoding="utf-8")
        clit = clit.replace("len(challenges) == 1260", "len(challenges) == 1295")
        clit = clit.replace("len(TRACKS) == 36", "len(TRACKS) == 37")
        cli_test_path.write_text(clit, encoding="utf-8")
        print("Updated wargame/tests/test_cli.py")

    # 6. Update tools/bundle_offline.py
    bundle_path = REPO_ROOT / "tools" / "bundle_offline.py"
    bt = bundle_path.read_text(encoding="utf-8")
    bt = bt.replace("1260 challenges across 36 tracks", "1295 challenges across 37 tracks")
    bt = bt.replace("id_count != 1260", "id_count != 1295")
    bt = bt.replace("len(track_ids) != 36", "len(track_ids) != 37")
    bundle_path.write_text(bt, encoding="utf-8")
    print("Updated tools/bundle_offline.py")

    # 7. Update root docs
    root_docs = ['README.md', 'README.en.md', 'README.ja.md', 'README.zh.md', 'USAGE.md', 'AI_LEARNING.md']
    for doc in root_docs:
        dp = REPO_ROOT / doc
        if dp.exists():
            dt = dp.read_text(encoding="utf-8")
            dt = dt.replace("1,260", "1,295")
            dt = dt.replace("1260", "1295")
            dt = dt.replace("36개", "37개")
            dt = dt.replace("36 tracks", "37 tracks")
            dp.write_text(dt, encoding="utf-8")
            print(f"Updated {doc}")

    # 8. Update vhack.py
    vhack_path = REPO_ROOT / "vhack.py"
    vt = vhack_path.read_text(encoding="utf-8")
    vt = vt.replace("36개 트랙, 1,260문제", "37개 트랙, 1,295문제")
    vt = vt.replace("36개 트랙 로드맵", "37개 트랙 로드맵")
    vhack_path.write_text(vt, encoding="utf-8")
    print("Updated vhack.py")


if __name__ == "__main__":
    main()
