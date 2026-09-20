#!/usr/bin/env python3
"""
Generate 35 challenges for Track 35: `carcan` (차량 보안 & CAN Bus / OBD-II / UDS 프로토콜).
Appends challenges to wargame/assets/challenges.js.
"""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_FILE = ROOT / "wargame" / "assets" / "challenges.js"

CARCAN_CHALLENGES = [
    # Tier 0 (2)
    {
        "id": "t0_carcan_can_bus_arbitration_id",
        "tier": 0, "points": 10,
        "title": {"ko": "CAN 버스 중재 ID 구조", "en": "CAN Bus Arbitration ID"},
        "desc_ko": "차량 네트워크 표준 CAN 2.0A에서 프레임 우선순위를 결정하는 11비트 중재 ID(Arbitration ID) 분석 챌린지입니다.",
        "desc_en": "Analyze standard 11-bit CAN Arbitration ID determining message priority in automotive networks.",
        "ident": "carcan_can_bus_arbitration_id_v1"
    },
    {
        "id": "t0_carcan_obd2_diagnostic_port",
        "tier": 0, "points": 20,
        "title": {"ko": "OBD-II 16핀 진단 커넥터", "en": "OBD-II 16-Pin Diagnostic Port"},
        "desc_ko": "차량 하단 온보드 진단 포트(OBD-II SAE J1962) 핀 배열 및 CAN High/Low(핀 6, 14) 분석 챌린지입니다.",
        "desc_en": "Identify CAN High and CAN Low pinout (pins 6 and 14) on the SAE J1962 OBD-II diagnostic port.",
        "ident": "carcan_obd2_diagnostic_port_v1"
    },

    # Tier 1 (6)
    {
        "id": "t1_carcan_can_dlc_data_length",
        "tier": 1, "points": 30,
        "title": {"ko": "CAN DLC 데이터 길이 코드", "en": "CAN DLC Data Length Code"},
        "desc_ko": "클래식 CAN 프레임 페이로드 바이트 크기를 정의하는 DLC(Data Length Code, 최대 8바이트) 분석 챌린지입니다.",
        "desc_en": "Inspect Data Length Code (DLC) defining classic CAN frame payload limits up to 8 bytes.",
        "ident": "carcan_can_dlc_data_length_v1"
    },
    {
        "id": "t1_carcan_candump_traffic_sniff",
        "tier": 1, "points": 40,
        "title": {"ko": "SocketCAN candump 트래픽 스니핑", "en": "SocketCAN candump Sniffing"},
        "desc_ko": "리눅스 can-utils 패키지의 candump 유틸리티로 vcan0 인터페이스의 실시간 브로드캐스트 패킷을 모니터링하는 챌린지입니다.",
        "desc_en": "Monitor real-time broadcast packets on SocketCAN interface vcan0 using the candump utility.",
        "ident": "carcan_candump_traffic_sniff_v1"
    },
    {
        "id": "t1_carcan_canplayer_replay_attack",
        "tier": 1, "points": 50,
        "title": {"ko": "canplayer CAN 프레임 재생 공격", "en": "canplayer CAN Replay Attack"},
        "desc_ko": "도어 언락 또는 클러스터 조작 패킷 로그를 캡처한 뒤 canplayer로 재생하여 액추에이터를 조작하는 챌린지입니다.",
        "desc_en": "Execute replay attack on vehicle actuators by feeding captured CAN log files into canplayer.",
        "ident": "carcan_canplayer_replay_attack_v1"
    },
    {
        "id": "t1_carcan_cansend_manual_frame",
        "tier": 1, "points": 60,
        "title": {"ko": "cansend 수동 프레임 인젝션", "en": "cansend Manual Frame Injection"},
        "desc_ko": "cansend 도구를 이용해 특정 중재 ID와 8바이트 16진수 페이로드를 직접 차량 CAN 버스에 인젝션하는 챌린지입니다.",
        "desc_en": "Directly transmit arbitrary CAN frames with specific Arbitration ID and hex payload using cansend.",
        "ident": "carcan_cansend_manual_frame_v1"
    },
    {
        "id": "t1_carcan_cangen_fuzzing_dos",
        "tier": 1, "points": 70,
        "title": {"ko": "cangen 무작위 프레임 플러딩 DoS", "en": "cangen Random Frame Flooding DoS"},
        "desc_ko": "cangen을 활용하여 ID 0x000(최고 우선순위) 프레임을 대량 주입하여 CAN 버스를 점유하고 ECU 통신을 마비시키는 챌린지입니다.",
        "desc_en": "Flood CAN bus with high-priority Arbitration ID 0x000 frames using cangen to induce denial of service.",
        "ident": "carcan_cangen_fuzzing_dos_v1"
    },
    {
        "id": "t1_carcan_vcan_virtual_driver",
        "tier": 1, "points": 80,
        "title": {"ko": "Linux vcan0 가상 인터페이스 구축", "en": "Linux vcan0 Virtual Driver Setup"},
        "desc_ko": "실제 하드웨어 없이 모의 해킹 환경을 구성하기 위해 ip link 커맨드로 가상 CAN(vcan0) 인터페이스를 활성화하는 챌린지입니다.",
        "desc_en": "Configure virtual CAN interface vcan0 using ip link command for isolated in-vehicle test environments.",
        "ident": "carcan_vcan_virtual_driver_v1"
    },

    # Tier 2 (12)
    {
        "id": "t2_carcan_obd2_speed_pid_service01",
        "tier": 2, "points": 100,
        "title": {"ko": "OBD-II Service 01 차속(Speed) 쿼리", "en": "OBD-II Service 01 Vehicle Speed"},
        "desc_ko": "차량 속도를 질의하기 위해 ID 0x7DF로 Service 01 PID 0x0D 요청 프레임을 전송하고 응답 바이트를 연산하는 챌린지입니다.",
        "desc_en": "Query vehicle speed via OBD-II PID 0x0D on diagnostic broadcast ID 0x7DF and parse response payload.",
        "ident": "carcan_obd2_speed_pid_service01_v1"
    },
    {
        "id": "t2_carcan_obd2_engine_rpm_calc",
        "tier": 2, "points": 110,
        "title": {"ko": "OBD-II 엔진 RPM 공식 연산", "en": "OBD-II Engine RPM Calculation"},
        "desc_ko": "Service 01 PID 0x0C 응답 데이터 2바이트 (A, B)를 공식 ((A*256)+B)/4 에 대입하여 정확한 분당 엔진 회전수를 도출하는 챌린지입니다.",
        "desc_en": "Calculate engine revolutions per minute from two response bytes using formula ((A*256)+B)/4.",
        "ident": "carcan_obd2_engine_rpm_calc_v1"
    },
    {
        "id": "t2_carcan_uds_diagnostic_session",
        "tier": 2, "points": 120,
        "title": {"ko": "UDS 진단 세션 제어 (0x10)", "en": "UDS DiagnosticSessionControl (0x10)"},
        "desc_ko": "ISO 14229 UDS 프로토콜에서 0x10 서비스를 호출하여 기본 세션에서 프로그래밍/확장 진단 세션(0x02, 0x03)으로 전환하는 챌린지입니다.",
        "desc_en": "Transition ECU from default to extended or programming diagnostic session via UDS service 0x10.",
        "ident": "carcan_uds_diagnostic_session_v1"
    },
    {
        "id": "t2_carcan_uds_security_access_seed",
        "tier": 2, "points": 130,
        "title": {"ko": "UDS SecurityAccess Seed 요청 (0x27)", "en": "UDS SecurityAccess Seed Request (0x27)"},
        "desc_ko": "보안 보호된 진단 루틴 실행을 위해 UDS 0x27 서브기능 0x01로 암호화 Seed 챌린지를 요청하는 챌린지입니다.",
        "desc_en": "Request pseudorandom security seed challenge from ECU via UDS service 0x27 subfunction 0x01.",
        "ident": "carcan_uds_security_access_seed_v1"
    },
    {
        "id": "t2_carcan_uds_seed_key_recovery",
        "tier": 2, "points": 140,
        "title": {"ko": "Seed-Key 알고리즘 역공학", "en": "Seed-Key Algorithm Reverse Engineering"},
        "desc_ko": "펌웨어 바이너리에서 추출한 Seed-Key 변환 로직(비트 회전 및 대칭 상수 XOR)을 분석하여 Key 검증을 통과하는 챌린지입니다.",
        "desc_en": "Reverse engineer proprietary bitwise shift and XOR constants from ECU firmware to generate valid security keys.",
        "ident": "carcan_uds_seed_key_recovery_v1"
    },
    {
        "id": "t2_carcan_isotp_flow_control_frame",
        "tier": 2, "points": 150,
        "title": {"ko": "ISO-TP Flow Control 프레임 제어", "en": "ISO-TP Flow Control Frame"},
        "desc_ko": "8바이트를 초과하는 진단 데이터 수신 시 ISO 15765-2 표준 Flow Control (0x30 00 00) 프레임으로 블록 전송을 제어하는 챌린지입니다.",
        "desc_en": "Control multi-frame segmented diagnostic transmission using ISO 15765-2 Flow Control (FC) frame 0x30.",
        "ident": "carcan_isotp_flow_control_frame_v1"
    },
    {
        "id": "t2_carcan_isotp_first_frame_chunk",
        "tier": 2, "points": 160,
        "title": {"ko": "ISO-TP First Frame(FF) 길이 파싱", "en": "ISO-TP First Frame Length Parsing"},
        "desc_ko": "연속 프레임 시작을 알리는 First Frame(상위 4비트 0x1)에서 12비트 전체 페이로드 길이 필드를 디코딩하는 챌린지입니다.",
        "desc_en": "Parse 12-bit total payload length field from ISO-TP First Frame header (nibble 0x1).",
        "ident": "carcan_isotp_first_frame_chunk_v1"
    },
    {
        "id": "t2_carcan_uds_read_did_vin",
        "tier": 2, "points": 170,
        "title": {"ko": "UDS 0x22 DID 차대번호(VIN) 조회", "en": "UDS 0x22 ReadDataByIdentifier VIN"},
        "desc_ko": "UDS 0x22 서비스와 표준 식별자 DID 0xF190을 호출하여 차량 17자리 고유 차대번호(VIN)를 획득하는 챌린지입니다.",
        "desc_en": "Query 17-character Vehicle Identification Number (VIN) using UDS service 0x22 and standardized DID 0xF190.",
        "ident": "carcan_uds_read_did_vin_v1"
    },
    {
        "id": "t2_carcan_uds_write_did_config",
        "tier": 2, "points": 180,
        "title": {"ko": "UDS 0x2E 파라미터 변조", "en": "UDS 0x2E WriteDataByIdentifier"},
        "desc_ko": "UDS WriteDataByIdentifier(0x2E) 명령어로 보안 인증 후 ECU 내부 코딩 파라미터(속도 제한 등)를 무단 변조하는 챌린지입니다.",
        "desc_en": "Overwrite ECU internal calibration parameters such as speed limiters using UDS service 0x2E.",
        "ident": "carcan_uds_write_did_config_v1"
    },
    {
        "id": "t2_carcan_uds_routine_control_abs",
        "tier": 2, "points": 190,
        "title": {"ko": "UDS 0x31 루틴 제어(RoutineControl)", "en": "UDS 0x31 RoutineControl ABS Test"},
        "desc_ko": "주행 중 UDS RoutineControl(0x31) 서비스를 트리거하여 ABS 밸브 점검 및 펌프 강제 구동 루틴을 오작동시키는 챌린지입니다.",
        "desc_en": "Trigger in-vehicle diagnostic actuator routines like ABS pump tests via UDS service 0x31.",
        "ident": "carcan_uds_routine_control_abs_v1"
    },
    {
        "id": "t2_carcan_dbc_signal_decoding",
        "tier": 2, "points": 200,
        "title": {"ko": "CAN DBC 파일 신호 역공학", "en": "CAN DBC Database Signal Decoding"},
        "desc_ko": "차량 CAN 데이터베이스 파일(.dbc) 문법(BO_, SG_)을 분석하여 조향각(Steering Angle) 신호의 시작 비트, 길이, 스케일링 팩터를 추출하는 챌린지입니다.",
        "desc_en": "Extract start bit, bit length, scale, and offset of steering angle signals by decoding CAN DBC database files.",
        "ident": "carcan_dbc_signal_decoding_v1"
    },
    {
        "id": "t2_carcan_crc16_checksum_bypass",
        "tier": 2, "points": 210,
        "title": {"ko": "CAN 프레임 카운터 및 체크섬 우회", "en": "CAN Alive Counter & CRC-16 Bypass"},
        "desc_ko": "ECU가 검증하는 4비트 Alive Counter 증분과 페이로드 CRC-16 체크섬을 실시간 재계산하여 위조 프레임을 주입하는 챌린지입니다.",
        "desc_en": "Recalculate rolling 4-bit message counter and CRC-16 checksums on the fly to inject spoofed safety frames.",
        "ident": "carcan_crc16_checksum_bypass_v1"
    },

    # Tier 3 (10)
    {
        "id": "t3_carcan_can_busoff_attack",
        "tier": 3, "points": 230,
        "title": {"ko": "ECU Bus-Off 고립 공격", "en": "Targeted ECU Bus-Off Isolation"},
        "desc_ko": "대상 ECU가 송신하는 특정 프레임의 ACK 비트 타이밍에 도미넌트 비트를 인위적으로 덮어써 송신 에러 카운터(TEC)가 255를 초과해 버스에서 영구 격리되도록 만드는 챌린지입니다.",
        "desc_en": "Inject dominant bits precisely during transmission to force target Transmit Error Counter (TEC) > 255 into Bus-Off.",
        "ident": "carcan_can_busoff_attack_v1"
    },
    {
        "id": "t3_carcan_error_frame_injection",
        "tier": 3, "points": 250,
        "title": {"ko": "능동 에러 프레임(Active Error) 인젝션", "en": "Active Error Frame Injection"},
        "desc_ko": "연속된 6개의 비트(Bit Stuffing 규칙 위반)를 강제로 송출하여 전 네트워크 노드에 에러 프레임을 전파하고 통신 무결성을 교란하는 챌린지입니다.",
        "desc_en": "Violate CAN bit stuffing rules by transmitting 6 consecutive dominant bits to trigger Active Error flags across all nodes.",
        "ident": "carcan_error_frame_injection_v1"
    },
    {
        "id": "t3_carcan_uds_ecu_reset_hard",
        "tier": 3, "points": 270,
        "title": {"ko": "UDS 0x11 ECU 하드 리셋 DoS", "en": "UDS 0x11 ECU Hard Reset DoS"},
        "desc_ko": "주행 중인 상태에서 UDS Service 0x11 (하드 리셋 0x01)을 엔진 컨트롤 유닛(ECU)에 연속 전송하여 시동 꺼짐을 유발하는 챌린지입니다.",
        "desc_en": "Send repetitive UDS service 0x11 subfunction 0x01 hard resets to force powertrain ECU reboot during operation.",
        "ident": "carcan_uds_ecu_reset_hard_v1"
    },
    {
        "id": "t3_carcan_uds_request_download_flash",
        "tier": 3, "points": 290,
        "title": {"ko": "UDS 0x34 RequestDownload 펌웨어 플래싱", "en": "UDS 0x34 RequestDownload Flashing"},
        "desc_ko": "UDS 0x34 서비스로 ECU 플래시 메모리 시작 주소와 크기를 지정하여 펌웨어 재작성 모드로 진입하는 챌린지입니다.",
        "desc_en": "Initiate firmware flashing sequence by specifying target memory address and uncompressed length via UDS 0x34.",
        "ident": "carcan_uds_request_download_flash_v1"
    },
    {
        "id": "t3_carcan_uds_transfer_data_block",
        "tier": 3, "points": 310,
        "title": {"ko": "UDS 0x36 TransferData 롬 블록 주입", "en": "UDS 0x36 TransferData Block Injection"},
        "desc_ko": "UDS 0x36 서비스로 블록 시퀀스 카운터(BSC)를 일치시키며 변조된 부트로더 바이너리를 ECU 플래시 메모리에 기록하는 챌린지입니다.",
        "desc_en": "Transmit malicious firmware blocks matching blockSequenceCounter to ECU flash memory via UDS 0x36.",
        "ident": "carcan_uds_transfer_data_block_v1"
    },
    {
        "id": "t3_carcan_uds_request_transfer_exit",
        "tier": 3, "points": 330,
        "title": {"ko": "UDS 0x37 RequestTransferExit 전송 종결", "en": "UDS 0x37 RequestTransferExit Validation"},
        "desc_ko": "UDS 0x37 서비스로 펌웨어 데이터 전송을 종결하고 ECU 내부 체크섬(CRC/해시) 검증 핸들러를 속여 재부팅을 유도하는 챌린지입니다.",
        "desc_en": "Conclude firmware flashing transfer and validate checksum handler bypass via UDS service 0x37.",
        "ident": "carcan_uds_request_transfer_exit_v1"
    },
    {
        "id": "t3_carcan_gateway_filtering_bypass",
        "tier": 3, "points": 350,
        "title": {"ko": "차량 중앙 게이트웨이(CGW) 필터링 우회", "en": "Central Gateway (CGW) Filter Bypass"},
        "desc_ko": "인포테인먼트 CAN에서 파워트레인 CAN으로 직접 전달되지 않는 방화벽 규칙을 진단 게이트웨이 터널링 프레임을 통해 우회하는 챌린지입니다.",
        "desc_en": "Bypass Central Gateway (CGW) inter-bus message filtering by encapsulating frames in diagnostic gateway routing services.",
        "ident": "carcan_gateway_filtering_bypass_v1"
    },
    {
        "id": "t3_carcan_someip_sd_spoofing",
        "tier": 3, "points": 370,
        "title": {"ko": "차량 이더넷 SOME/IP SD 스푸핑", "en": "Automotive Ethernet SOME/IP SD Spoofing"},
        "desc_ko": "차량용 이더넷 기반 SOME/IP Service Discovery 프로토콜의 멀티캐스트 오퍼(OfferService) 메시지를 스푸핑하여 악성 서비스로 라우팅하는 챌린지입니다.",
        "desc_en": "Spoof SOME/IP Service Discovery (SD) multicast OfferService entries to hijack automotive Ethernet RPC endpoints.",
        "ident": "carcan_someip_sd_spoofing_v1"
    },
    {
        "id": "t3_carcan_doip_uds_payload_extract",
        "tier": 3, "points": 390,
        "title": {"ko": "DoIP (ISO 13400) 진단 트래픽 탈취", "en": "DoIP (ISO 13400) Diagnostic Interception"},
        "desc_ko": "TCP 13400 포트로 전송되는 Diagnostics over IP(DoIP) 프로토콜 헤더를 파싱하고 캡슐화된 내부 UDS 페이로드를 탈취하는 챌린지입니다.",
        "desc_en": "Intercept TCP port 13400 Diagnostics over IP (DoIP) traffic and extract encapsulated UDS diagnostic payload bytes.",
        "ident": "carcan_doip_uds_payload_extract_v1"
    },
    {
        "id": "t3_carcan_secoc_freshness_value",
        "tier": 3, "points": 410,
        "title": {"ko": "AUTOSAR SecOC 보안 CAN MAC 분석", "en": "AUTOSAR SecOC MAC & Freshness Analysis"},
        "desc_ko": "AUTOSAR Secure Onboard Communication(SecOC)에서 재생 방지를 위해 적용된 Freshness Value와 CMAC-AES128 인증 태그를 분석하는 챌린지입니다.",
        "desc_en": "Analyze AUTOSAR SecOC truncated CMAC-AES128 authentication tags and Freshness Value counters preventing frame replay.",
        "ident": "carcan_secoc_freshness_value_v1"
    },

    # Tier 4 (5)
    {
        "id": "t4_carcan_connected_vehicle_capstone",
        "tier": 4, "points": 450,
        "title": {"ko": "커넥티드 카 텔레매틱스 침투 캡스톤", "en": "Connected Vehicle Telematics Capstone"},
        "desc_ko": "셀룰러 텔레매틱스 박스(TCU) 원격 취약점 익스플로잇 후 SPI/UART를 거쳐 차량 내부 CAN 버스로 피버팅하는 종합 침투 시나리오 챌린지입니다.",
        "desc_en": "Comprehensive incident response investigating remote cellular TCU exploit chaining to internal powertrain CAN bus.",
        "ident": "carcan_connected_vehicle_capstone_v1"
    },
    {
        "id": "t4_carcan_ecu_firmware_reverse_s19",
        "tier": 4, "points": 470,
        "title": {"ko": "Motorola S19 펌웨어 역공학", "en": "Motorola S19 ECU Firmware Reversing"},
        "desc_ko": "ECU 플래시 덤프 Motorola S-Record(S19/S28) 포맷의 체크섬과 베이스 주소를 복원하고 Ghidra로 Tricore/RH850 마이크로컨트롤러 코드를 분석하는 챌린지입니다.",
        "desc_en": "Reconstruct base address and memory maps from Motorola S-Record (S19) firmware dumps for Tricore microcontroller analysis.",
        "ident": "carcan_ecu_firmware_reverse_s19_v1"
    },
    {
        "id": "t4_carcan_adas_radar_spoofing",
        "tier": 4, "points": 480,
        "title": {"ko": "ADAS 전방 레이더 CAN 기만 공격", "en": "ADAS Forward Radar CAN Spoofing"},
        "desc_ko": "자율주행 ADAS ECU의 장애물 감지 CAN 프레임을 가로채 가상의 장애물 거리(Distance)와 상대 속도(Relative Velocity)를 조작하여 유령 제동을 유발하는 챌린지입니다.",
        "desc_en": "Inject spoofed forward radar obstacle distance and velocity signals into ADAS CAN bus to trigger phantom braking.",
        "ident": "carcan_adas_radar_spoofing_v1"
    },
    {
        "id": "t4_carcan_ota_firmware_tampering",
        "tier": 4, "points": 490,
        "title": {"ko": "차량 무선(OTA) 업데이트 변조", "en": "Automotive OTA Firmware Tampering"},
        "desc_ko": "차량 OTA(Over-The-Air) 패키지 다운로드 과정에서 TLS 인증서 검증 결함을 악용해 변조된 롬 바이너리를 전달하고 무결성 해시를 일치시키는 챌린지입니다.",
        "desc_en": "Exploit TLS validation flaw in automotive Over-The-Air (OTA) download client to push malicious ECU update packages.",
        "ident": "carcan_ota_firmware_tampering_v1"
    },
    {
        "id": "t4_carcan_zero_trust_in_vehicle_ids",
        "tier": 4, "points": 500,
        "title": {"ko": "차량 내부 제로 트러스트 침입탐지(IVN-IDS)", "en": "Zero Trust In-Vehicle IDS Defense"},
        "desc_ko": "차량 네트워크(CAN/Ethernet) 전 구간에 메시지 엔트로피, 송신 주기성(Inter-arrival Time), 하드웨어 송신원 핑거프린팅을 적용하는 차세대 IVN-IDS 방어 챌린지입니다.",
        "desc_en": "Design In-Vehicle Network IDS combining frame entropy, inter-arrival interval timing, and transceiver physical fingerprinting.",
        "ident": "carcan_zero_trust_in_vehicle_ids_v1"
    }
]

def make_challenge_entry(item):
    ident = item["ident"]
    h20 = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
    flag = f"FLAG{{{h20}}}"
    flag_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

    prompt_ko = (
        f"{item['desc_ko']}\n"
        f"지정된 식별자 `{ident}`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n"
        f"형식: `FLAG{{SHA256(\"{ident}\") 앞 20자리}}`"
    )
    prompt_en = (
        f"{item['desc_en']}\n"
        f"Compute the first 20 hex characters of SHA256(\"{ident}\").\n\n"
        f"Format: `FLAG{{SHA256(\"{ident}\") first 20 hex}}`"
    )
    hint_ko = [
        f"식별자 `{ident}`의 SHA-256 해시 앞 20자리를 추출하세요.",
        "대소문자를 구분하여 `FLAG{...}` 형태로 제출합니다."
    ]
    hint_en = [
        f"Compute the first 20 hex chars of SHA-256(\"{ident}\").",
        "Wrap in `FLAG{...}` format."
    ]

    return {
        "id": item["id"],
        "tier": item["tier"],
        "cat": "carcan",
        "track": "carcan",
        "points": item["points"],
        "ci": False,
        "fmt": "FLAG{...}",
        "title": item["title"],
        "prompt": {"ko": prompt_ko, "en": prompt_en},
        "hints": {"ko": hint_ko, "en": hint_en},
        "hash": flag_hash
    }

def main():
    content = CHALLENGES_FILE.read_text(encoding="utf-8").rstrip()
    
    # Strip trailing `];` or `]`
    if content.endswith("];"):
        content = content[:-2].rstrip()
    elif content.endswith("]"):
        content = content[:-1].rstrip()

    new_entries = [make_challenge_entry(c) for c in CARCAN_CHALLENGES]
    print(f"Generated {len(new_entries)} challenges for Track 35: carcan.")

    # Format JSON entries
    appended_json = ",\n" + ",\n".join(json.dumps(e, ensure_ascii=False, indent=2) for e in new_entries) + "\n];\n"
    
    CHALLENGES_FILE.write_text(content + appended_json, encoding="utf-8")
    print("Successfully appended Track 35 challenges to challenges.js.")

if __name__ == "__main__":
    main()
