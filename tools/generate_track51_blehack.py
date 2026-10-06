#!/usr/bin/env python3
"""
Generate Wargame Track 51 (blehack) Challenges
35 Challenges across 5 Tiers (2/6/8/9/10 Pyramid)
"""

import hashlib
import json
from pathlib import Path

def make_challenge(cid, tier, cat, points, title_ko, title_en, prompt_ko, prompt_en, hints_ko, hints_en, ident):
    # Compute sha256 of identifier (first 20 hex characters)
    inner_hash = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
    flag = f"FLAG{{{inner_hash}}}"
    # Target hash for wargame verification
    # ci: false -> flag is exact case
    target_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()
    
    full_prompt_ko = f"{prompt_ko}\n지정된 식별자 `{ident}`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{{SHA256(\"{ident}\") 앞 20자리}}`"
    full_prompt_en = f"{prompt_en}\nCompute the first 20 hex characters of SHA256(\"{ident}\").\n\nFormat: `FLAG{{SHA256(\"{ident}\") first 20 hex}}`"
    
    full_hints_ko = hints_ko + [f"식별자 `{ident}`의 해시 앞 20자리를 추출하세요."]
    full_hints_en = hints_en + [f"Extract first 20 hex chars of SHA256(\"{ident}\")."]
    
    return {
        "id": cid,
        "tier": tier,
        "cat": cat,
        "track": "blehack",
        "points": points,
        "ci": False,
        "fmt": "FLAG{...}",
        "title": {
            "ko": title_ko,
            "en": title_en
        },
        "prompt": {
            "ko": full_prompt_ko,
            "en": full_prompt_en
        },
        "hints": {
            "ko": full_hints_ko,
            "en": full_hints_en
        },
        "hash": target_hash
    }

# 35 challenges specification
raw_specs = [
    # Tier 0 (2)
    (
        "t0_blehack_gatt_architecture", 0, "blegatt", 25,
        "BLE GATT 계층 구조 및 서비스·특성 모델",
        "BLE GATT Architecture and Service-Characteristic Hierarchy",
        "BLE Generic Attribute Profile(GATT)의 Profile, Service, Characteristic, Descriptor 4단계 계층 구조와 ATT 프로토콜 속성 테이블을 분석합니다.",
        "Analyze the BLE GATT 4-tier hierarchy: Profile, Service, Characteristic, and Descriptor with ATT attribute tables.",
        ["GATT 계층 구조와 ATT 속성 테이블의 역할을 검토하세요."],
        ["Review the GATT hierarchy and ATT attribute table roles."],
        "blehack_gatt_architecture_profile_v1"
    ),
    (
        "t0_blehack_adv_packet_structure", 0, "blegatt", 25,
        "BLE 어드버타이징 패킷 PDU 및 AD 구조",
        "BLE Advertising Packet PDU and AD Data Structure",
        "BLE 31바이트 레거시 Advertising 데이터 패킷의 Length, AD Type(Flags, Complete UUIDs, Local Name), AD Data 구조를 분석합니다.",
        "Analyze the 31-byte legacy BLE Advertising data packet format including Length, AD Type, and AD Data fields.",
        ["어드버타이징 PDU의 AD Type 비트 구조를 확인하세요."],
        ["Inspect the AD Type bit layout in advertising PDUs."],
        "blehack_adv_packet_structure_format_v1"
    ),

    # Tier 1 (6)
    (
        "t1_blehack_uuid_handle_mapping", 1, "blegatt", 50,
        "ATT 프로토콜 UUID 및 16비트 Handle 매핑",
        "ATT Protocol UUID and 16-bit Handle Attribute Mapping",
        "ATT 프로토콜에서 128비트 표준/벤더 UUID가 16비트 순차 핸들(Handle)로 매핑되어 클라이언트와 통신하는 메커니즘을 분석합니다.",
        "Analyze how 128-bit standard and proprietary UUIDs map to 16-bit sequential attribute handles in the ATT protocol.",
        ["ATT 속성 핸들의 순차적 할당 규칙을 검토하세요."],
        ["Review sequential handle allocation rules in ATT tables."],
        "blehack_uuid_handle_mapping_att_v1"
    ),
    (
        "t1_blehack_char_properties_permissions", 1, "blegatt", 50,
        "Characteristic Properties 비트마스크 및 ATT 권한",
        "Characteristic Properties Bitmask and ATT Permissions",
        "Read, Write, Write Without Response, Notify, Indicate 등 특성 속성 비트마스크와 보안 권한 플래그의 차이를 분석합니다.",
        "Analyze the distinction between Characteristic Properties bitmasks (Read/Write/Notify) and security permissions.",
        ["속성 비트마스크(Properties)와 보안 권한(Permissions)의 차이를 확인하세요."],
        ["Distinguish property bitmasks from security access permissions."],
        "blehack_char_properties_permissions_bits_v1"
    ),
    (
        "t1_blehack_legacy_just_works_pairing", 1, "blepairing", 50,
        "레거시 Just Works 페어링 및 TK=0 취약점",
        "Legacy Just Works Pairing and Default Zero TK Flaw",
        "BLE 4.0/4.1 레거시 페어링의 Just Works 모드에서 임시 키(Temporary Key, TK)가 항상 0x00000000으로 고정되는 취약점을 분석합니다.",
        "Analyze the vulnerability where legacy Just Works pairing fixes the Temporary Key (TK) to 0x00000000.",
        ["Just Works 페어링 시 SMP 사양의 기본 TK 값을 확인하세요."],
        ["Check default TK specifications in legacy Just Works SMP."],
        "blehack_legacy_just_works_tk_zero_v1"
    ),
    (
        "t1_blehack_passkey_entry_mitm_risk", 1, "blepairing", 65,
        "Passkey Entry 6자리 PIN 오프라인 전수조사",
        "Passkey Entry 6-digit PIN Offline Brute Force Feasibility",
        "Display 또는 Keypad 기반 Passkey Entry에서 6자리 숫자(000000~999999, 약 20비트 엔트로피)가 오프라인 사전 공격에 노출되는 원리를 분석합니다.",
        "Analyze why 6-digit PIN Passkey Entry (000000-999999, ~20 bits entropy) is susceptible to offline brute-force attacks.",
        ["6자리 숫자의 제한된 키 공간과 SMP c1 함수를 고려하세요."],
        ["Consider the limited key space of 6 digits and SMP c1 function."],
        "blehack_passkey_entry_mitm_risk_smp_v1"
    ),
    (
        "t1_blehack_sdr_ook_ask_modulation", 1, "rfsdr", 65,
        "SDR RF 신호 수신 및 OOK/ASK 변조 원리",
        "SDR RF Signal Capture and OOK/ASK Modulation Principles",
        "Software Defined Radio(SDR)를 활용하여 315/433MHz 대역의 On-Off Keying(OOK) 및 진폭 편이 변조(ASK) 신호를 포착하는 원리를 분석합니다.",
        "Analyze how Software Defined Radio captures On-Off Keying (OOK) and Amplitude Shift Keying (ASK) in ISM bands.",
        ["진폭 유무로 비트를 표현하는 OOK 신호의 특징을 확인하세요."],
        ["Understand binary representation in amplitude-keyed signals."],
        "blehack_sdr_ook_ask_modulation_radio_v1"
    ),
    (
        "t1_blehack_rf_spectrum_waterfall", 1, "rfsdr", 65,
        "FFT 스펙트로그램 및 워터폴 대역 분석",
        "FFT Spectrogram and Waterfall RF Band Analysis",
        "GQRX 및 Inspectrum 도구를 통한 Fast Fourier Transform(FFT) 스펙트로그램 분석과 시간에 따른 주파수 점유(워터폴) 패턴을 분석합니다.",
        "Analyze RF spectral occupancy and temporal signal patterns using FFT spectrograms and waterfall displays.",
        ["워터폴 다이어그램에서 버스트 신호의 시간-주파수 특성을 확인하세요."],
        ["Analyze time-frequency signatures in waterfall plots."],
        "blehack_rf_spectrum_waterfall_fft_v1"
    ),

    # Tier 2 (8)
    (
        "t2_blehack_unauth_actuator_write", 2, "blegatt", 90,
        "비인가 Characteristic 쓰기를 통한 액추에이터 제어",
        "Unauthenticated Characteristic Write for Actuator Manipulation",
        "스마트 도어락이나 밸브 제어 특성에 인증 및 암호화 필수 비트가 누락되었을 때 임의 클라이언트가 UNLOCK 명령을 주입하는 기법을 분석합니다.",
        "Analyze how missing encryption/authentication permissions enable unauthorized clients to inject actuator unlock commands.",
        ["액추에이터 제어 핸들의 쓰기 권한 설정을 점검하세요."],
        ["Audit write permission bits on actuator control handles."],
        "blehack_unauth_actuator_write_pwn_v1"
    ),
    (
        "t2_blehack_client_char_config_cccd", 2, "blegatt", 90,
        "CCCD 디스크립터 조작 및 센서 데이터 비인가 수신",
        "CCCD Descriptor Manipulation for Unauthorized Telemetry Sniffing",
        "Client Characteristic Configuration Descriptor(CCCD, 0x2902)에 0x0001(Notify) 또는 0x0002(Indicate)를 써서 센서 스트림을 도청하는 기법을 분석합니다.",
        "Analyze unauthorized telemetry eavesdropping by writing 0x0001 (Notify) or 0x0002 (Indicate) to the CCCD descriptor.",
        ["CCCD 디스크립터(0x2902)의 알림 활성화 메커니즘을 확인하세요."],
        ["Check notification enablement mechanisms via CCCD handles."],
        "blehack_client_char_config_cccd_notify_v1"
    ),
    (
        "t2_blehack_stk_derivation_crack", 2, "blepairing", 100,
        "SMP c1 암호화 함수 및 STK(Short Term Key) 역산",
        "SMP c1 Cryptographic Function and STK Derivation Reversal",
        "스니핑된 Mrand, Srand, Mconfirm, Sconfirm 패킷과 추정된 TK를 입력으로 AES-128 기반 c1 함수를 역산하여 STK를 복원하는 절차를 분석합니다.",
        "Analyze the procedure for deriving the Short Term Key (STK) from captured Mrand/Srand/confirmations via SMP c1 function.",
        ["SMP c1 함수의 파라미터 구성과 STK 도출 과정을 검토하세요."],
        ["Review SMP c1 function inputs and STK derivation steps."],
        "blehack_stk_derivation_crack_c1_func_v1"
    ),
    (
        "t2_blehack_nonce_static_replay", 2, "blemitm", 100,
        "고정 Nonce 챌린지 패킷 재전송(Replay) 공격",
        "Static Nonce Challenge-Response Replay Attack",
        "애플리케이션 계층 챌린지-응답 인증에서 난수 생성기 결함으로 동일한 Nonce가 재사용될 때 인증 토큰을 재생하는 공격을 분석합니다.",
        "Analyze authentication bypass attacks exploiting predictable or static challenge nonces in BLE application layers.",
        ["챌린지 난수의 예측 가능성 및 단조 증가 검증 부재를 확인하세요."],
        ["Check predictable nonces and missing freshness validation."],
        "blehack_nonce_static_replay_attack_v1"
    ),
    (
        "t2_blehack_fsk_gfsk_deviation", 2, "rfsdr", 100,
        "GFSK 변조 대역폭 및 주파수 편이 복조",
        "GFSK Modulation Bandwidth and Frequency Deviation Demodulation",
        "Gaussian Frequency Shift Keying(GFSK)의 BT 곱(Bandwidth-Time Product) 0.5 필터링과 주파수 편이(Deviation) 특성을 복조하는 수학적 모델을 분석합니다.",
        "Analyze mathematical models for demodulating Gaussian Frequency Shift Keying (GFSK) with BT=0.5 filtering.",
        ["가우시안 필터와 심볼 전이 주파수 편이 관계를 검토하세요."],
        ["Examine Gaussian pulse shaping and frequency deviation."],
        "blehack_fsk_gfsk_deviation_demod_v1"
    ),
    (
        "t2_blehack_fixed_code_rf_replay", 2, "rfsdr", 110,
        "315/433MHz 고정 코드 무선 리모컨 Replay",
        "315/433MHz Fixed Code Wireless Remote Replay Attack",
        "DIP 스위치나 고정 ID를 송출하는 차고 문 및 도어락 무선 RF 패킷을 HackRF/RTL-SDR로 녹음하여 재송신(Replay)하는 취약점을 분석합니다.",
        "Analyze replay vulnerabilities in fixed-code garage doors and keyfobs captured via SDR and retransmitted directly.",
        ["고정 코드 무선 패킷의 롤링 코드 미적용 위험성을 확인하세요."],
        ["Evaluate security implications of missing rolling codes."],
        "blehack_fixed_code_rf_replay_hackrf_v1"
    ),
    (
        "t2_blehack_adv_channel_freq", 2, "rfsdr", 120,
        "BLE Advertising 37/38/39 채널 주파수 도약 계산",
        "BLE Primary Advertising Channels (37, 38, 39) Frequency Hopping",
        "Wi-Fi 채널 1, 6, 11 간섭을 회피하기 위해 배치된 BLE Advertising 채널 37(2402MHz), 38(2426MHz), 39(2480MHz)의 배치 원리를 분석합니다.",
        "Analyze frequency allocation of BLE primary advertising channels 37 (2402MHz), 38 (2426MHz), and 39 (2480MHz) avoiding Wi-Fi interference.",
        ["2.4GHz ISM 대역에서 Wi-Fi와 BLE 어드버타이징 채널 배치를 대조하세요."],
        ["Contrast Wi-Fi 1/6/11 frequencies with BLE advertising channels."],
        "blehack_adv_channel_freq_ch37_39_v1"
    ),
    (
        "t2_blehack_btlejuice_proxy_mitm", 2, "blemitm", 120,
        "BtleJuice/GATTacker 프록시 기반 BLE MITM",
        "BtleJuice and GATTacker Virtual Proxy Man-in-the-Middle",
        "BLE Central과 Peripheral 사이에 가상 프록시를 개입시켜 서비스 UUID와 특성을 복제하고 트래픽을 변조하는 MITM 아키텍처를 분석합니다.",
        "Analyze virtual proxy MITM architectures cloning peripheral GATT services to intercept and manipulate active BLE connections.",
        ["BtleJuice 프록시의 Core와 Agent 간 패킷 인터셉트 구조를 점검하세요."],
        ["Review packet interception between proxy core and agent."],
        "blehack_btlejuice_proxy_mitm_core_v1"
    ),

    # Tier 3 (9)
    (
        "t3_blehack_lesc_ecdh_p256_pairing", 3, "blepairing", 130,
        "LE Secure Connections (ECDH P-256) 비대칭 페어링",
        "LE Secure Connections ECDH P-256 Asymmetric Key Agreement",
        "NIST P-256 타원곡선 디피-헬만(ECDH)을 도입하여 수동 도청(Passive Eavesdropping)에 대한 완벽한 암호학적 내성을 제공하는 LESC 모델을 분석합니다.",
        "Analyze LE Secure Connections utilizing NIST P-256 ECDH to provide mathematical resilience against passive eavesdropping.",
        ["P-256 타원곡선 기반 비대칭 키 교환 및 LTK 파생 공식을 확인하세요."],
        ["Verify P-256 curve operations and long-term key derivation."],
        "blehack_lesc_ecdh_p256_pairing_lesc_v1"
    ),
    (
        "t3_blehack_numeric_comparison_mitm_guard", 3, "blepairing", 130,
        "Numeric Comparison 6자리 확인 코드 MITM 방어",
        "Numeric Comparison 6-digit Confirmation Code MITM Defense",
        "양방향 디스플레이 장치에서 6자리 확인 코드를 사용자가 시각적으로 대조하여 중간자 공격(MITM)을 수학적으로 탐지하는 프로토콜을 분석합니다.",
        "Analyze the Numeric Comparison association model verifying 6-digit confirmation codes to mathematically prevent active MITM.",
        ["Numeric Comparison 확인 코드의 암호학적 해시 생성 과정을 검토하세요."],
        ["Examine cryptographic hash derivation for confirmation codes."],
        "blehack_numeric_comparison_mitm_guard_check_v1"
    ),
    (
        "t3_blehack_l2cap_packet_overflow", 3, "blemitm", 140,
        "L2CAP 시그널링 MTU 경계 오버플로우 DoS",
        "L2CAP Signaling MTU Boundary Buffer Overflow DoS",
        "L2CAP 레이어의 Signaling 채널(CID 0x0005)에서 비정상적인 Command Reject 또는 과도한 길이 필드를 전송하여 블루투스 스택을 크래시시키는 기법을 분석합니다.",
        "Analyze L2CAP signaling channel buffer overflows triggering kernel or controller crashes via oversized length fields.",
        ["L2CAP MTU 경계값 처리 및 패킷 단편화 결함을 확인하세요."],
        ["Inspect MTU boundary handling and fragmentation bugs."],
        "blehack_l2cap_packet_overflow_mtu_v1"
    ),
    (
        "t3_blehack_keeloq_rolling_code_differential", 3, "rfsdr", 140,
        "KeeLoq 롤링 코드 NLFSR 상태 차분 공격",
        "KeeLoq Rolling Code NLFSR Non-Linear State Differential Cryptanalysis",
        "비선형 피드백 시프트 레지스터(NLFSR) 64비트 마스터 키 기반 KeeLoq 알고리즘의 차분 전력 분석(DPA) 및 암호학적 취약점을 분석합니다.",
        "Analyze differential power analysis and cryptographic weaknesses in 64-bit KeeLoq NLFSR rolling code implementations.",
        ["KeeLoq 32비트 호핑 코드와 카운터 동기화 원리를 검토하세요."],
        ["Review KeeLoq hopping code generation and counter synchronization."],
        "blehack_keeloq_rolling_code_differential_nlfsr_v1"
    ),
    (
        "t3_blehack_rolljam_two_stage_reactive", 3, "rfsdr", 150,
        "Rolljam 2단계 RF 재밍 및 미사용 코드 선점",
        "Rolljam Two-Stage Reactive RF Jamming and Desynchronization",
        "차량 수신기를 협대역 잡음으로 재밍하면서 첫 번째 롤링 코드를 도청하고, 2차 신호 수신 시 1차 코드를 릴레이하여 최신 코드를 비축하는 공격을 분석합니다.",
        "Analyze Rolljam attacks jamming receiver channels while capturing fresh rolling codes for subsequent unauthorized replay.",
        ["동시 재밍-스니핑 기법과 코드 비동기화 상태를 분석하세요."],
        ["Analyze simultaneous jamming-capturing and desync states."],
        "blehack_rolljam_two_stage_reactive_jam_v1"
    ),
    (
        "t3_blehack_anti_replay_monotonic_counter", 3, "blemitm", 150,
        "단조 증가 시퀀스 카운터 및 슬라이딩 윈도우 방어",
        "Monotonic Increment Counter and Sliding Window Anti-Replay",
        "무선 제어 패킷에 비휘발성 단조 증가 카운터와 슬라이딩 윈도우 알고리즘을 적용하여 이전 프레임의 재전송을 원천 무력화하는 방어 체계를 분석합니다.",
        "Analyze anti-replay defense architectures combining non-volatile monotonic counters with cryptographic sliding windows.",
        ["슬라이딩 윈도우의 비트마스크 추적 및 카운터 증가 검증을 확인하세요."],
        ["Check bitmask window tracking and counter freshness validation."],
        "blehack_anti_replay_monotonic_counter_seq_v1"
    ),
    (
        "t3_blehack_mac_address_resolvable_rpa", 3, "blepairing", 150,
        "Resolvable Private Address(RPA) 및 IRK 프라이버시",
        "Resolvable Private Address (RPA) and Identity Resolving Key Privacy",
        "기기 추적을 방지하기 위해 15분마다 변경되는 RPA 주소와 신뢰 기기 간 Identity Resolving Key(IRK) 해시 매칭 알고리즘을 분석합니다.",
        "Analyze RPA privacy mechanisms rotating MAC addresses periodically while enabling trusted peers to resolve identities via IRK.",
        ["ah 해시 함수(AES-128 기반)를 통한 RPA 주소 해석 원리를 검토하세요."],
        ["Examine RPA resolution using the AES-128 ah hash function."],
        "blehack_mac_address_resolvable_rpa_irk_v1"
    ),
    (
        "t3_blehack_sweyntooth_ble_firmware_flaws", 3, "blegatt", 160,
        "SweynTooth BLE SoC 펌웨어 취약점(LLID 데드락, 크래시)",
        "SweynTooth BLE SoC Controller Flaws (LLID Deadlock & Memory Corruption)",
        "주요 상용 BLE SoC 컨트롤러(TI, Nordic, Telink 등)의 Link Layer 패킷 처리 루틴에서 발견된 SweynTooth 계열 취약점을 분석합니다.",
        "Analyze SweynTooth vulnerabilities in commercial BLE SoC controllers triggering Link Layer deadlocks and crashes.",
        ["비정상적인 LLID 및 제어 PDU 시퀀스 처리 오류를 점검하세요."],
        ["Review malformed LLID and control PDU error handling."],
        "blehack_sweyntooth_ble_firmware_flaws_cve_v1"
    ),
    (
        "t3_blehack_authenticated_write_attribute_harden", 3, "blegatt", 160,
        "Authenticated Write 및 속성 레벨 암호화 강제",
        "Authenticated Write and Attribute-Level Cryptographic Enforcement",
        "GATT 속성 테이블에서 민감 제어 특성에 대해 Authenticated Signed Writes 또는 암호화된 링크(LESC) 필수 속성을 설정하는 하드닝 방안을 분석합니다.",
        "Analyze hardening configurations requiring Authenticated Signed Writes and LESC encrypted channels on sensitive characteristics.",
        ["ATT_ERR_INSUFFICIENT_AUTHENTICATION 오류 반환 규칙을 확인하세요."],
        ["Enforce ATT_ERR_INSUFFICIENT_AUTHENTICATION error policies."],
        "blehack_authenticated_write_attribute_harden_att_v1"
    ),

    # Tier 4 (10)
    (
        "t4_blehack_knob_encryption_key_negotiation", 4, "blepairing", 170,
        "KNOB(Key Negotiation of Bluetooth) 엔트로피 축소 공격",
        "KNOB (Key Negotiation of Bluetooth) Entropy Reduction Attack",
        "블루투스 암호화 키 협상 과정에서 공격자가 패킷을 주입하여 암호화 키 엔트로피를 1바이트(8비트)로 다운그레이드시키는 KNOB 취약점을 분석합니다.",
        "Analyze the KNOB attack manipulating LM encryption negotiation to reduce session key entropy to a single byte.",
        ["최소 암호화 키 엔트로피(16바이트) 강제 통제 방안을 검토하세요."],
        ["Enforce minimum 16-byte key entropy requirements in controllers."],
        "blehack_knob_encryption_key_negotiation_entropy_v1"
    ),
    (
        "t4_blehack_bluetooth_forward_secrecy_pfs", 4, "blepairing", 170,
        "BLE Perfect Forward Secrecy 및 임시 Diffie-Hellman",
        "BLE Perfect Forward Secrecy and Ephemeral Diffie-Hellman Keys",
        "장기 키(LTK)가 유출되더라도 과거 세션 트래픽이 복호화되지 않도록 보장하는 완전 순방향 비밀성(PFS) 아키텍처를 분석합니다.",
        "Analyze Perfect Forward Secrecy (PFS) in Bluetooth architectures protecting past session traffic against LTK compromise.",
        ["임시 ECDH 키 교환과 세션별 파생 키 폐기 주기를 확인하세요."],
        ["Inspect ephemeral key agreement and forward secrecy bounds."],
        "blehack_bluetooth_forward_secrecy_pfs_dhkey_v1"
    ),
    (
        "t4_blehack_ble_sniffing_whad_framework", 4, "blemitm", 180,
        "WHAD(Wireless Hacking Automation Device) 기반 패킷 인젝션",
        "WHAD Framework Automated Sniffing and Packet Injection Pipeline",
        "WHAD 프로토콜을 활용하여 nRF52 동글 및 SDR 장비를 단일 추상화 인터페이스로 제어하고 실시간 패킷 주입을 자동화하는 기술을 분석합니다.",
        "Analyze WHAD abstraction framework automating multi-hardware BLE packet capture, injection, and fuzzing pipelines.",
        ["WHAD 프로토콜 메시지 계층과 하드웨어 드라이버 추상화를 확인하세요."],
        ["Review WHAD protocol layers and hardware abstraction."],
        "blehack_ble_sniffing_whad_framework_packet_v1"
    ),
    (
        "t4_blehack_subghz_gnss_spoofing_resilience", 4, "rfsdr", 180,
        "Sub-GHz ISM 대역 RF 스푸핑 탐지 및 수신 감도 분석",
        "Sub-GHz ISM Band RF Spoofing Detection and Signal Power Triage",
        "SDR을 이용한 불법 RF 전송 시 비정상적인 RSSI 급증, SNR 변동, 도플러 시프트 이상을 탐지하여 RF 스푸핑을 방어하는 신호처리 기법을 분석합니다.",
        "Analyze signal processing heuristics detecting RF spoofing via anomalous RSSI spikes, SNR fluctuations, and Doppler shifts.",
        ["신호 대 잡음비(SNR) 및 전력 임계치를 활용한 이상 탐지를 검토하세요."],
        ["Evaluate power thresholds and SNR anomaly detection heuristics."],
        "blehack_subghz_gnss_spoofing_resilience_rf_v1"
    ),
    (
        "t4_blehack_bluetooth_mesh_replay_seq_cache", 4, "blemitm", 190,
        "BLE Mesh Sequence Number Cache 고갈 및 Replay",
        "BLE Mesh Replay Protection List (RPL) Cache Exhaustion and Replay",
        "BLE Mesh 네트워크에서 노드의 Replay Protection List(RPL) 캐시를 대량의 허위 시퀀스로 채워 고갈시킨 후 이전 메시지를 주입하는 취약점을 분석합니다.",
        "Analyze Replay Protection List (RPL) cache exhaustion attacks in BLE Mesh networks enabling stale message injection.",
        ["Mesh IV Index 업데이트 및 RPL 캐시 엔트리 보호 정책을 점검하세요."],
        ["Review IV Index synchronization and RPL eviction policies."],
        "blehack_bluetooth_mesh_replay_seq_cache_replay_v1"
    ),
    (
        "t4_blehack_ble_gatt_fuzzing_defensics", 4, "blegatt", 190,
        "BLE GATT 프로토콜 퍼징 및 크래시 트리아지",
        "BLE GATT Protocol Mutation Fuzzing and Crash Triage",
        "Defensics 및 커스텀 Scapy-BLE 스크립트를 통해 ATT 명령 필드에 경계값 및 돌연변이 페이로드를 주입하여 펌웨어 크래시를 트리거하는 퍼징을 분석합니다.",
        "Analyze protocol mutation fuzzing against ATT/GATT implementations evaluating memory safety and fault tolerance.",
        ["ATT Opcode, Handle, 길이 필드 변이 퍼징 기법을 검토하세요."],
        ["Examine mutational fuzzing heuristics for ATT packet headers."],
        "blehack_ble_gatt_fuzzing_defensics_protocol_v1"
    ),
    (
        "t4_blehack_sdr_iq_constellation_diagram", 4, "rfsdr", 200,
        "SDR I/Q 데이터 성좌도(Constellation) 왜곡 분석",
        "SDR I/Q Data Constellation Diagram Distortion and EVM Analysis",
        "In-phase(I) 및 Quadrature(Q) 기저대역 신호의 성좌도(Constellation) 다이어그램과 EVM(Error Vector Magnitude) 계측을 통한 RF 신호 무결성을 분석합니다.",
        "Analyze I/Q constellation diagrams and Error Vector Magnitude (EVM) metrics to audit RF transmitter physical integrity.",
        ["성좌도 상의 위상 잡음 및 진폭 불균형 왜곡 패턴을 확인하세요."],
        ["Inspect phase noise and amplitude imbalance patterns in I/Q plots."],
        "blehack_sdr_iq_constellation_diagram_quad_v1"
    ),
    (
        "t4_blehack_hardware_secure_element_ble_key", 4, "blepairing", 200,
        "하드웨어 보안 요소(SE) 기반 BLE 개인키 격리",
        "Hardware Secure Element (SE) Isolation for BLE Cryptographic Keys",
        "ATECC608 또는 전용 Secure Enclave를 통해 BLE ECDH 개인키와 LTK를 물리적으로 격리하고 DPA 부채널 방어를 적용하는 하드웨어 설계를 분석합니다.",
        "Analyze hardware Secure Element (SE) architectures isolating BLE ECDH private keys with physical side-channel defenses.",
        ["보안 요소의 하드웨어 암호화 가속기 및 키 래핑 원리를 검토하세요."],
        ["Review hardware crypto accelerator isolation and key wrapping."],
        "blehack_hardware_secure_element_ble_key_vault_v1"
    ),
    (
        "t4_blehack_zero_trust_wireless_mesh_defense", 4, "blemitm", 220,
        "무선 IoT 제로 트러스트 마이크로세그멘테이션",
        "Zero Trust Wireless IoT Microsegmentation and Dynamic Quarantine",
        "모든 무선 센서 및 BLE 게이트웨이에 대해 지속적인 동적 상호 인증, 행위 기반 텔레메트리 감사 및 자동 격리 정책을 강제하는 제로 트러스트를 분석합니다.",
        "Analyze Zero Trust architectures enforcing continuous mutual authentication and dynamic quarantine across wireless IoT nodes.",
        ["mTLS 또는 시그니처 기반 게이트웨이 인증 체계를 점검하세요."],
        ["Audit mutual authentication and dynamic isolation rules."],
        "blehack_zero_trust_wireless_mesh_defense_zt_v1"
    ),
    (
        "t4_blehack_capstone_rf_ble_full_audit", 4, "blegatt", 250,
        "엔터프라이즈 스마트 빌딩 BLE/SDR 무선 침투 종합 감사",
        "Enterprise Smart Facility BLE and SDR Full-Spectrum Wireless Audit",
        "스마트 도어락, 환경 센서, 무선 조명 제어기 등 시설 내 모든 BLE/SDR 자산에 대한 포괄적 침투 테스트와 다계층 무선 방어 거버넌스 수립을 분석합니다.",
        "Execute a full-spectrum wireless security audit assessing smart locks, sensors, and SDR perimeters across enterprise facilities.",
        ["물리-사이버 융합 환경에서의 무선 침투 및 종합 방어 대책을 종합 검토하세요."],
        ["Synthesize physical-cyber converged wireless assessment metrics."],
        "blehack_capstone_rf_ble_full_audit_enterprise_v1"
    )
]

challenges = []
for spec in raw_specs:
    ch = make_challenge(*spec)
    challenges.append(ch)

out_file = Path(__file__).resolve().parent / "track51_blehack_challenges.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(challenges, f, ensure_ascii=False, indent=2)

print(f"Generated {len(challenges)} challenges to {out_file}")
