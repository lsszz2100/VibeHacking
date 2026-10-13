const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function computeHash(id) {
  const flag = "FLAG{" + crypto.createHash('sha256').update(id + "_v1").digest('hex').substring(0, 20) + "}";
  return crypto.createHash('sha256').update(flag).digest('hex');
}

const challengesDef = [
  // Tier 0 (2)
  {
    id: "t0_dfir_rfc3227_order_of_volatility",
    tier: 0, cat: "dfir", track: "dfir", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "RFC 3227 디지털 증거 수집 휘발성 순서 (Order of Volatility)", en: "RFC 3227 Digital Evidence Order of Volatility" },
    prompt: {
      ko: "침해 호스트 분석 시 CPU 레지스터/캐시, 라우팅 테이블/ARP/커널 메모리, 임시 파일시스템, 디스크 영구 저장소 순으로 증거를 보존하는 RFC 3227 원칙을 분석합니다.\n지정된 식별자 `dfir_rfc3227_order_of_volatility_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_rfc3227_order_of_volatility_v1\") 앞 20자리}`",
      en: "Examine RFC 3227 order of volatility principles prioritizing CPU registers, routing cache, memory, and persistent disk artifacts.\nCompute the first 20 hex characters of SHA256(\"dfir_rfc3227_order_of_volatility_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_rfc3227_order_of_volatility_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["휘발성이 가장 높은 레지스터 및 RAM부터 우선 수집하고 전원을 즉시 차단하지 않아야 합니다.", "식별자 `dfir_rfc3227_order_of_volatility_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Prioritize volatile memory and active network sockets before powering down systems.", "Extract first 20 hex chars of SHA256(\"dfir_rfc3227_order_of_volatility_v1\")."]
    }
  },
  {
    id: "t0_dfir_incident_severity_matrix",
    tier: 0, cat: "dfir", track: "dfir", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "NIST SP 800-61 침해사고 심각도 매트릭스 (P1~P4 Triage)", en: "NIST SP 800-61 Incident Severity Matrix & Triage" },
    prompt: {
      ko: "침해 범위, 비즈니스 핵심 자산 영향도, 고객 데이터 유출 위험도를 종합 평가하여 P1(Critical)부터 P4(Low)까지 초기 심각도를 분류하는 NIST SP 800-61 프레임워크를 분석합니다.\n지정된 식별자 `dfir_incident_severity_matrix_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_incident_severity_matrix_v1\") 앞 20자리}`",
      en: "Review NIST SP 800-61 severity classification matrix mapping asset criticality, breach scope, and impact to P1-P4 triage levels.\nCompute the first 20 hex characters of SHA256(\"dfir_incident_severity_matrix_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_incident_severity_matrix_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["핵심 데이터 유출 및 랜섬웨어 확산은 즉시 P1 심각도로 긴급 대응팀을 소집해야 합니다.", "식별자 `dfir_incident_severity_matrix_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Enterprise data leaks and ransomware outbreaks classify as P1 critical response.", "Extract first 20 hex chars of SHA256(\"dfir_incident_severity_matrix_v1\")."]
    }
  },

  // Tier 1 (6)
  {
    id: "t1_dfir_sysmon_process_lineage_triage",
    tier: 1, cat: "dfir", track: "dfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Sysmon Event ID 1 프로세스 생성 계통 및 Parent PID 분석", en: "Sysmon Event ID 1 Process Lineage & Parent PID Analysis" },
    prompt: {
      ko: "Sysmon Event ID 1 프로세스 생성 텔레메트리에서 합법적 외형 뒤에 숨겨진 실제 ParentCommandLine 및 Creator PID 계통을 추적합니다.\n지정된 식별자 `dfir_sysmon_process_lineage_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_sysmon_process_lineage_triage_v1\") 앞 20자리}`",
      en: "Analyze Sysmon Event ID 1 telemetry tracking ParentCommandLine and creator PID lineage discrepancies.\nCompute the first 20 hex characters of SHA256(\"dfir_sysmon_process_lineage_triage_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_sysmon_process_lineage_triage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["프로세스 트리가 OS 정상 실행 계통과 일치하는지 ParentProcessId를 교차 검증하세요.", "식별자 `dfir_sysmon_process_lineage_triage_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Cross-verify parent process IDs against standard Windows architecture baselines.", "Extract first 20 hex chars of SHA256(\"dfir_sysmon_process_lineage_triage_v1\")."]
    }
  },
  {
    id: "t1_dfir_ppid_spoofing_detection",
    tier: 1, cat: "dfir", track: "dfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "PPID 스푸핑 및 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 탐지", en: "PPID Spoofing & Process Attribute Inspection" },
    prompt: {
      ko: "CreateProcess 계열 API 호출 시 UpdateProcThreadAttribute로 부모 프로세스를 services.exe 등으로 조작하는 PPID 스푸핑 기법을 포렌식적으로 식별합니다.\n지정된 식별자 `dfir_ppid_spoofing_detection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_ppid_spoofing_detection_v1\") 앞 20자리}`",
      en: "Detect Parent PID spoofing abusing PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attributes in CreateProcess API calls.\nCompute the first 20 hex characters of SHA256(\"dfir_ppid_spoofing_detection_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_ppid_spoofing_detection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["EPROCESS 구조체의 실제 생성 스레드와 토큰 토큰 상속 상태를 확인하세요.", "식별자 `dfir_ppid_spoofing_detection_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Inspect underlying creator thread IDs versus claimed parent process IDs.", "Extract first 20 hex chars of SHA256(\"dfir_ppid_spoofing_detection_v1\")."]
    }
  },
  {
    id: "t1_dfir_mft_usn_journal_parsing",
    tier: 1, cat: "dfir", track: "dfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "NTFS $MFT 및 USN 저널 트랜잭션 타임라인 추출", en: "NTFS $MFT & USN Journal Transaction Forensics" },
    prompt: {
      ko: "NTFS $MFT의 $STANDARD_INFORMATION 및 $FILE_NAME 타임스탬프와 $UsnJrnl 변경 내역을 파싱하여 파일 생성·수정·이름변경의 절대 타임라인을 재구성합니다.\n지정된 식별자 `dfir_mft_usn_journal_parsing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_mft_usn_journal_parsing_v1\") 앞 20자리}`",
      en: "Parse NTFS $MFT attributes and $UsnJrnl transaction records to reconstruct absolute file event chronologies.\nCompute the first 20 hex characters of SHA256(\"dfir_mft_usn_journal_parsing_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_mft_usn_journal_parsing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["타임스톰핑 공격을 탐지하려면 $SI와 $FN 타임스탬프 불일치를 비교하세요.", "식별자 `dfir_mft_usn_journal_parsing_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Compare $STANDARD_INFORMATION against $FILE_NAME timestamps to detect timestomping.", "Extract first 20 hex chars of SHA256(\"dfir_mft_usn_journal_parsing_v1\")."]
    }
  },
  {
    id: "t1_dfir_volume_shadow_deletion_vssadmin",
    tier: 1, cat: "dfir", track: "dfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "랜섬웨어 볼륨 섀도우 복사본 강제 삭제(vssadmin) 탐지", en: "Ransomware Shadow Copy Deletion (vssadmin) Detection" },
    prompt: {
      ko: "랜섬웨어 공격자가 시스템 복원을 무력화하기 위해 실행하는 `vssadmin.exe delete shadows /all /quiet` 및 wbadmin 백업 삭제 명령을 모니터링합니다.\n지정된 식별자 `dfir_volume_shadow_deletion_vssadmin_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_volume_shadow_deletion_vssadmin_v1\") 앞 20자리}`",
      en: "Detect malicious volume shadow deletion commands such as vssadmin delete shadows /all /quiet and wbadmin wipe scripts.\nCompute the first 20 hex characters of SHA256(\"dfir_volume_shadow_deletion_vssadmin_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_volume_shadow_deletion_vssadmin_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ASR(Attack Surface Reduction) 룰을 통해 비인가 vssadmin 호출을 원천 차단하세요.", "식별자 `dfir_volume_shadow_deletion_vssadmin_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Enforce ASR rules preventing untrusted processes from invoking vssadmin.", "Extract first 20 hex chars of SHA256(\"dfir_volume_shadow_deletion_vssadmin_v1\")."]
    }
  },
  {
    id: "t1_dfir_prefetch_execution_evidence",
    tier: 1, cat: "dfir", track: "dfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Windows Prefetch(.pf) 실행 빈도 및 타임스탬프 분석", en: "Windows Prefetch Execution Artifact Forensics" },
    prompt: {
      ko: "Windows Prefetch 디렉터리(`C:\\Windows\\Prefetch\\*.pf`)에서 실행 바이너리 해시, 실행 횟수, 최근 8회 실행 타임스탬프 및 참조 DLL 목록을 추출합니다.\n지정된 식별자 `dfir_prefetch_execution_evidence_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_prefetch_execution_evidence_v1\") 앞 20자리}`",
      en: "Extract binary hash, run counts, recent execution timestamps, and loaded DLL volumes from Windows Prefetch artifacts.\nCompute the first 20 hex characters of SHA256(\"dfir_prefetch_execution_evidence_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_prefetch_execution_evidence_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["MAM 압축 알고리즘을 해제하여 Prefetch 내부 헤더를 파싱하세요.", "식별자 `dfir_prefetch_execution_evidence_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Decompress Windows 10/11 MAM Prefetch files to read executable metadata.", "Extract first 20 hex chars of SHA256(\"dfir_prefetch_execution_evidence_v1\")."]
    }
  },
  {
    id: "t1_dfir_shimcache_amcache_execution",
    tier: 1, cat: "dfir", track: "dfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Shimcache(AppCompatCache) 및 Amcache.hve 프로그램 실행 흔적", en: "Shimcache & Amcache.hve Program Execution Tracking" },
    prompt: {
      ko: "SYSTEM 레지스트리의 AppCompatCache와 Amcache.hve 하이브를 분석하여 삭제된 임시 실행 파일의 전체 경로, 파일 크기, SHA-1 해시 및 컴파일 타임스탬프를 복원합니다.\n지정된 식별자 `dfir_shimcache_amcache_execution_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_shimcache_amcache_execution_v1\") 앞 20자리}`",
      en: "Recover deleted executable paths, file sizes, SHA-1 hashes, and compile timestamps from Shimcache and Amcache.hve.\nCompute the first 20 hex characters of SHA256(\"dfir_shimcache_amcache_execution_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_shimcache_amcache_execution_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["공격자가 디스크에서 악성코드를 삭제했더라도 Amcache에는 파일 해시가 영구 보존됩니다.", "식별자 `dfir_shimcache_amcache_execution_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Amcache preserves binary hashes even after executables are deleted from disk.", "Extract first 20 hex chars of SHA256(\"dfir_shimcache_amcache_execution_v1\")."]
    }
  },

  // Tier 2 (8)
  {
    id: "t2_dfir_c2_beacon_jitter_analysis",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "주기적 C2 비콘 통신 및 지터(Jitter) 분산 분석", en: "Periodic C2 Beaconing & Jitter Variance Analysis" },
    prompt: {
      ko: "네트워크 플로우 로그에서 일정한 수면 간격(Sleep)과 지터(예: 60s ± 15%)를 갖는 C2 비콘 통신의 델타 시간 분포(Delta Time Distribution)를 통계적으로 도출합니다.\n지정된 식별자 `dfir_c2_beacon_jitter_analysis_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_c2_beacon_jitter_analysis_v1\") 앞 20자리}`",
      en: "Calculate statistical delta-time distributions and jitter variance to unmask periodic HTTPS/DNS C2 beacon patterns.\nCompute the first 20 hex characters of SHA256(\"dfir_c2_beacon_jitter_analysis_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_c2_beacon_jitter_analysis_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["패킷 간격의 표준편차가 작고 정규분포를 이루는 통신 대상을 선별하세요.", "식별자 `dfir_c2_beacon_jitter_analysis_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Identify outbound destinations exhibiting low variance delta-time clusters.", "Extract first 20 hex chars of SHA256(\"dfir_c2_beacon_jitter_analysis_v1\")."]
    }
  },
  {
    id: "t2_dfir_dns_tunneling_txt_exfiltration",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "DNS 터널링 엔트로피 및 TXT 레코드 데이터 유출 식별", en: "DNS Tunneling Entropy & TXT Exfiltration Detection" },
    prompt: {
      ko: "서브도메인 라벨의 Shannon 엔트로피(>4.2), 긴 호스트네임 길이, 높은 요청 빈도 및 대용량 TXT 응답을 분석하여 DNS 터널링 유출 경로를 차단합니다.\n지정된 식별자 `dfir_dns_tunneling_txt_exfiltration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_dns_tunneling_txt_exfiltration_v1\") 앞 20자리}`",
      en: "Uncover DNS tunneling data exfiltration by analyzing subdomain Shannon entropy, label lengths, and volume of TXT queries.\nCompute the first 20 hex characters of SHA256(\"dfir_dns_tunneling_txt_exfiltration_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_dns_tunneling_txt_exfiltration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["엔터프라이즈 내부 DNS 리졸버에서 비정상 질의 도메인을 DNS Sinkhole로 유도하세요.", "식별자 `dfir_dns_tunneling_txt_exfiltration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Reroute high-entropy base32/base64 subdomain queries to enterprise DNS sinkholes.", "Extract first 20 hex chars of SHA256(\"dfir_dns_tunneling_txt_exfiltration_v1\")."]
    }
  },
  {
    id: "t2_dfir_scheduled_task_persistence",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "스케줄러 태스크(schtasks / XML) 지속성 식별 및 트리거 분석", en: "Scheduled Task Persistence & XML Definition Audit" },
    prompt: {
      ko: "`C:\\Windows\\System32\\Tasks\\` 디렉터리의 태스크 XML 파일과 Event ID 4698/4702를 대조하여 악성 지속성 예약 작업을 발본색원합니다.\n지정된 식별자 `dfir_scheduled_task_persistence_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_scheduled_task_persistence_v1\") 앞 20자리}`",
      en: "Audit Windows scheduled task XML definitions and Event IDs 4698/4702 to eradicate persistent backdoor triggers.\nCompute the first 20 hex characters of SHA256(\"dfir_scheduled_task_persistence_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_scheduled_task_persistence_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["숨겨진 작업이나 마이크로소프트 공식 경로 아래에 위장된 커스텀 태스크를 검사하세요.", "식별자 `dfir_scheduled_task_persistence_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Inspect tasks mimicking Microsoft directory names with hidden execution flags.", "Extract first 20 hex chars of SHA256(\"dfir_scheduled_task_persistence_v1\")."]
    }
  },
  {
    id: "t2_dfir_wmi_event_subscription_persistence",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "WMI 이벤트 필터 & CommandLineEventConsumer 지속성 적출", en: "WMI Event Subscription & Consumer Persistence Extraction" },
    prompt: {
      ko: "`ROOT\\subscription` 네임스페이스에 등록된 __EventFilter, CommandLineEventConsumer, __FilterToConsumerBinding 3요소를 적출하여 파일리스 지속성을 무력화합니다.\n지정된 식별자 `dfir_wmi_event_subscription_persistence_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_wmi_event_subscription_persistence_v1\") 앞 20자리}`",
      en: "Extract fileless WMI persistence bindings comprising __EventFilter and CommandLineEventConsumer objects in ROOT\\subscription.\nCompute the first 20 hex characters of SHA256(\"dfir_wmi_event_subscription_persistence_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_wmi_event_subscription_persistence_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Get-CimInstance를 사용해 시스템 부팅이나 타이머 조건으로 실행되는 컨슈머를 제거하세요.", "식별자 `dfir_wmi_event_subscription_persistence_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Query WMI subscriptions using CIM cmdlets and unbind rogue consumer bindings.", "Extract first 20 hex chars of SHA256(\"dfir_wmi_event_subscription_persistence_v1\")."]
    }
  },
  {
    id: "t2_dfir_powershell_script_block_logging",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "PowerShell Event ID 4104 Script Block 난독화 해제", en: "PowerShell Script Block Logging (EID 4104) Deobfuscation" },
    prompt: {
      ko: "Microsoft-Windows-PowerShell/Operational 로그의 Event ID 4104에서 다단계 Base64, SecureString 압축, 문자열 조작 난독화 스크립트를 평문으로 디코딩합니다.\n지정된 식별자 `dfir_powershell_script_block_logging_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_powershell_script_block_logging_v1\") 앞 20자리}`",
      en: "Deobfuscate layered Base64 and gzip payloads recorded under PowerShell Operational log Event ID 4104.\nCompute the first 20 hex characters of SHA256(\"dfir_powershell_script_block_logging_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_powershell_script_block_logging_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["스크립트 블록 로깅은 런타임 실행 시점의 최종 디인코딩 코드를 기록합니다.", "식별자 `dfir_powershell_script_block_logging_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Script Block Logging captures payloads immediately prior to AST compilation.", "Extract first 20 hex chars of SHA256(\"dfir_powershell_script_block_logging_v1\")."]
    }
  },
  {
    id: "t2_dfir_memory_reflective_dll_injection",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "Unbacked 메모리 영역 VAD 태그 및 리플렉티브 DLL 카빙", en: "Unbacked VAD Memory Triage & Reflective DLL Carving" },
    prompt: {
      ko: "Volatility 3 `windows.malfind` 및 VAD 트리를 분석하여 디스크에 백킹 파일이 없는 PAGE_EXECUTE_READWRITE 메모리 영역에서 PE 시그니처(`MZ`)를 카빙합니다.\n지정된 식별자 `dfir_memory_reflective_dll_injection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_memory_reflective_dll_injection_v1\") 앞 20자리}`",
      en: "Carve embedded MZ binary headers from unbacked PAGE_EXECUTE_READWRITE VAD regions identified via memory triage.\nCompute the first 20 hex characters of SHA256(\"dfir_memory_reflective_dll_injection_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_memory_reflective_dll_injection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["정상 DLL은 파일 매핑 VAD를 보유하므로 unbacked 실행 영역은 100% 인젝션 의심 대상입니다.", "식별자 `dfir_memory_reflective_dll_injection_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Legitimate shared libraries map to physical files; unbacked executable sections signal injection.", "Extract first 20 hex chars of SHA256(\"dfir_memory_reflective_dll_injection_v1\")."]
    }
  },
  {
    id: "t2_dfir_tls_ja3_ja4_fingerprinting",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "악성 C2 TLS Client Hello JA3/JA4 핑거프린트 상관분석", en: "Malicious TLS Client Hello JA3/JA4 Fingerprint Correlation" },
    prompt: {
      ko: "TLS Client Hello 패킷의 Cipher Suites, Extensions, Elliptic Curves 파라미터를 해시하여 알려진 C2 프레임워크(Cobalt Strike, Sliver)의 JA3/JA4 해시와 매핑합니다.\n지정된 식별자 `dfir_tls_ja3_ja4_fingerprinting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_tls_ja3_ja4_fingerprinting_v1\") 앞 20자리}`",
      en: "Correlate TLS Client Hello cipher suites and extensions against curated JA3/JA4 fingerprint signatures for C2 beacons.\nCompute the first 20 hex characters of SHA256(\"dfir_tls_ja3_ja4_fingerprinting_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_tls_ja3_ja4_fingerprinting_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["암호화된 페이로드를 복호화하지 않고도 클라이언트 TLS 스택을 즉시 식별할 수 있습니다.", "식별자 `dfir_tls_ja3_ja4_fingerprinting_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["JA3 enables fingerprinting the client application without inspecting encrypted TLS payloads.", "Extract first 20 hex chars of SHA256(\"dfir_tls_ja3_ja4_fingerprinting_v1\")."]
    }
  },
  {
    id: "t2_dfir_event_log_clearing_wevtutil",
    tier: 2, cat: "dfir", track: "dfir", points: 80, ci: false, fmt: "FLAG{...}",
    title: { ko: "이벤트 로그 삭제(Event ID 1102 / 104) 및 볼륨 섀도우 복원", en: "Event Log Clearing (EID 1102/104) & Forensic Shadow Recovery" },
    prompt: {
      ko: "공격자가 `wevtutil cl`을 실행해 보안 로그를 지우는 Event ID 1102/104 기록을 포착하고 볼륨 섀도우 백업에서 원본 .evtx 파일을 마운트해 복원합니다.\n지정된 식별자 `dfir_event_log_clearing_wevtutil_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_event_log_clearing_wevtutil_v1\") 앞 20자리}`",
      en: "Detect audit log wiping (Event ID 1102/104) and recover archived .evtx containers from volume shadow snapshots.\nCompute the first 20 hex characters of SHA256(\"dfir_event_log_clearing_wevtutil_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_event_log_clearing_wevtutil_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["로그 삭제 자체가 고위험 침해 지표이므로 SIEM에서 삭제 이벤트를 최고 우선순위로 트리거하세요.", "식별자 `dfir_event_log_clearing_wevtutil_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Audit log deletion commands represent immediate high-severity compromise alarms.", "Extract first 20 hex chars of SHA256(\"dfir_event_log_clearing_wevtutil_v1\")."]
    }
  },

  // Tier 3 (9)
  {
    id: "t3_dfir_ransomware_canary_file_tripwire",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "랜섬웨어 조기 탐지용 카나리(Canary) 파일 트립와이어", en: "Ransomware Early Detection Canary Tripwires" },
    prompt: {
      ko: "공유 폴더 최상위 디렉터리에 미끼 파일(Canary Files)을 배치하고 파일 시스템 미니필터로 변조 감지 시 공격 프로세스를 0.1초 내 강제 종료하는 방어 체계를 구축합니다.\n지정된 식별자 `dfir_ransomware_canary_file_tripwire_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_ransomware_canary_file_tripwire_v1\") 앞 20자리}`",
      en: "Deploy deceptive canary tripwires in shared volumes to trigger instant process suspension on write attempts.\nCompute the first 20 hex characters of SHA256(\"dfir_ransomware_canary_file_tripwire_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_ransomware_canary_file_tripwire_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["알파벳 앞글자(!0_canary.docx)로 네이밍하여 랜섬웨어의 순차 순회 초기에 포착하세요.", "식별자 `dfir_ransomware_canary_file_tripwire_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Prepend symbols or leading digits so recursive ransomware hits canary files first.", "Extract first 20 hex chars of SHA256(\"dfir_ransomware_canary_file_tripwire_v1\")."]
    }
  },
  {
    id: "t3_dfir_kerberos_golden_silver_ticket_triage",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "Kerberos Golden/Silver Ticket 위조 아티팩트 및 타임라인 트리아지", en: "Kerberos Golden & Silver Ticket Forgery Artifact Triage" },
    prompt: {
      ko: "KRBTGT 해시 또는 서비스 계정 키로 위조된 TGT/TGS 티켓의 유효 기간(10년 등), 비정상 PAC 체크섬 및 Event ID 4624/4769 이상치를 포렌식 분석합니다.\n지정된 식별자 `dfir_kerberos_golden_silver_ticket_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_kerberos_golden_silver_ticket_triage_v1\") 앞 20자리}`",
      en: "Triage forged Kerberos TGT and TGS tickets by analyzing anomalously long lifetimes and invalid PAC checksums.\nCompute the first 20 hex characters of SHA256(\"dfir_kerberos_golden_silver_ticket_triage_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_kerberos_golden_silver_ticket_triage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["도메인 컨트롤러에 TGS 요청 없이 도메인 멤버 서버에 TGS를 바로 제시하는 이상 패턴을 확인하세요.", "식별자 `dfir_kerberos_golden_silver_ticket_triage_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Check for missing TGT issuance logs (Event ID 4768) prior to service ticket presentations.", "Extract first 20 hex chars of SHA256(\"dfir_kerberos_golden_silver_ticket_triage_v1\")."]
    }
  },
  {
    id: "t3_dfir_dkom_hidden_process_dkon",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "EPROCESS ActiveProcessLinks DKOM 은닉 프로세스 크로스 트리아지", en: "EPROCESS ActiveProcessLinks DKOM Cross-Triage" },
    prompt: {
      ko: "커널 ActiveProcessLinks 이중 연결 리스트에서 링크 해제된 악성 프로세스를 PspCidTable, CSRSS 핸들 테이블, 스레드 풀 태그 3단계 교차 검증으로 찾아냅니다.\n지정된 식별자 `dfir_dkom_hidden_process_dkon_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_dkom_hidden_process_dkon_v1\") 앞 20자리}`",
      en: "Cross-validate unlinked EPROCESS structures against PspCidTable and CSRSS process tables to detect DKOM rootkits.\nCompute the first 20 hex characters of SHA256(\"dfir_dkom_hidden_process_dkon_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_dkom_hidden_process_dkon_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`pslist`에서는 보이지 않으나 `psscan`에서 살아있는 풀 태그를 확인하세요.", "식별자 `dfir_dkom_hidden_process_dkon_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["A process missing from pslist but present in psscan indicates active DKOM unlinking.", "Extract first 20 hex chars of SHA256(\"dfir_dkom_hidden_process_dkon_v1\")."]
    }
  },
  {
    id: "t3_dfir_network_host_containment_api",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "EDR 격리 API 및 엔터프라이즈 방화벽 자동 호스트 봉쇄", en: "EDR Host Network Isolation & Dynamic Quarantine" },
    prompt: {
      ko: "침해 감지 즉시 EDR 에이전트 커널 필터 드라이버를 통해 DNS 및 EDR 관제 콘솔 통신을 제외한 모든 인그레스/이그레스 트래픽을 단절하는 호스트 격리를 집행합니다.\n지정된 식별자 `dfir_network_host_containment_api_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_network_host_containment_api_v1\") 앞 20자리}`",
      en: "Enforce host-level network containment via EDR driver hooks, severing all traffic except designated management channels.\nCompute the first 20 hex characters of SHA256(\"dfir_network_host_containment_api_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_network_host_containment_api_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["측면 이동(Lateral Movement)을 방지하려면 인접 서브넷과의 SMB/RDP 통신을 우선 차단하세요.", "식별자 `dfir_network_host_containment_api_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Drop peer-to-peer SMB and RDP traffic across internal VLANs to freeze lateral spread.", "Extract first 20 hex chars of SHA256(\"dfir_network_host_containment_api_v1\")."]
    }
  },
  {
    id: "t3_dfir_cloud_aws_cloudtrail_guardduty_ir",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "AWS CloudTrail 이벤트 타임라인 및 GuardDuty 침해 지표 대응", en: "AWS CloudTrail Timeline & GuardDuty Threat Response" },
    prompt: {
      ko: "AWS CloudTrail 로그에서 이상 지역 IP의 STS AssumeRole, 비인가 보안 그룹 변경, S3 대량 GetObject 이벤트를 GuardDuty 위협 지표와 결합하여 분석합니다.\n지정된 식별자 `dfir_cloud_aws_cloudtrail_guardduty_ir_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_cloud_aws_cloudtrail_guardduty_ir_v1\") 앞 20자리}`",
      en: "Correlate AWS CloudTrail audit logs with GuardDuty findings to map compromised IAM roles and S3 data staging.\nCompute the first 20 hex characters of SHA256(\"dfir_cloud_aws_cloudtrail_guardduty_ir_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_cloud_aws_cloudtrail_guardduty_ir_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["IAM 역할의 세션 정책과 MFA 인증 여부를 CloudTrail eventName 별로 추적하세요.", "식별자 `dfir_cloud_aws_cloudtrail_guardduty_ir_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Filter CloudTrail for UnauthorizedOperation errors and rapid credential minting calls.", "Extract first 20 hex chars of SHA256(\"dfir_cloud_aws_cloudtrail_guardduty_ir_v1\")."]
    }
  },
  {
    id: "t3_dfir_k8s_container_escape_forensics",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "Kubernetes 컨테이너 탈옥 및 cgroup/nsenter 포렌식 트리아지", en: "Kubernetes Container Escape & Namespace Forensics" },
    prompt: {
      ko: "특권 컨테이너(privileged: true) 및 hostPath 볼륨 마운트를 악용한 노드 탈옥 흔적을 cgroup 마운트, 커널 release_agent, nsenter 실행 로그에서 적출합니다.\n지정된 식별자 `dfir_k8s_container_escape_forensics_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_k8s_container_escape_forensics_v1\") 앞 20자리}`",
      en: "Triage container breakouts exploiting privileged capabilities or release_agent hooks using node audit logs.\nCompute the first 20 hex characters of SHA256(\"dfir_k8s_container_escape_forensics_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_k8s_container_escape_forensics_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["컨테이너 내부와 호스트 노드의 PID 네임스페이스 매핑을 교차 검증하세요.", "식별자 `dfir_k8s_container_escape_forensics_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Inspect host-level PID namespaces for unexpected binaries originating from container cgroups.", "Extract first 20 hex chars of SHA256(\"dfir_k8s_container_escape_forensics_v1\")."]
    }
  },
  {
    id: "t3_dfir_active_directory_ntds_dit_dump",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "VSS 볼륨 스냅샷 ntds.dit 덤프 및 ntdsutil 침해 흔적 역추적", en: "VSS Snapshot NTDS.dit Dumping & Forensic Reconstruction" },
    prompt: {
      ko: "도메인 컨트롤러에서 ntdsutil `ac i ntds` 또는 VSS 섀도우 복사본을 통해 추출된 ntds.dit 및 SYSTEM 하이브 파일 카빙 아티팩트를 역추적합니다.\n지정된 식별자 `dfir_active_directory_ntds_dit_dump_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_active_directory_ntds_dit_dump_v1\") 앞 20자리}`",
      en: "Trace domain-wide credential exposure stemming from ntdsutil database extractions and VSS snapshot dumps.\nCompute the first 20 hex characters of SHA256(\"dfir_active_directory_ntds_dit_dump_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_active_directory_ntds_dit_dump_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Event ID 4799(로컬 보안 그룹 열람) 및 ntds.dit 접근 핸들을 Sysmon 10번 이벤트로 추적하세요.", "식별자 `dfir_active_directory_ntds_dit_dump_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Track unauthorized handles opened against NTDS service directories.", "Extract first 20 hex chars of SHA256(\"dfir_active_directory_ntds_dit_dump_v1\")."]
    }
  },
  {
    id: "t3_dfir_memory_string_carving_c2_config",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "덤프 메모리 YARA 스캔 및 암호화된 C2 설정 블록 카빙", en: "Memory Dump YARA Scanning & C2 Config Extraction" },
    prompt: {
      ko: "물리 메모리 덤프에서 YARA 룰셋으로 인메모리 프로세스를 스캔하고 0x2e 또는 0x69 바이트 XOR로 암호화된 C2 설정 블록(IP, User-Agent, 워터마크)을 복호화합니다.\n지정된 식별자 `dfir_memory_string_carving_c2_config_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_memory_string_carving_c2_config_v1\") 앞 20자리}`",
      en: "Scan memory dumps using YARA rules to extract and decrypt XOR-masked C2 beacon configurations and watermarks.\nCompute the first 20 hex characters of SHA256(\"dfir_memory_string_carving_c2_config_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_memory_string_carving_c2_config_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Cobalt Strike Malleable C2 설정 블록의 구조체 오프셋과 0x2e 단일 바이트 XOR를 해제하세요.", "식별자 `dfir_memory_string_carving_c2_config_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Unmask beacon configuration structures using single-byte XOR transforms.", "Extract first 20 hex chars of SHA256(\"dfir_memory_string_carving_c2_config_v1\")."]
    }
  },
  {
    id: "t3_dfir_browser_history_session_hijack",
    tier: 3, cat: "dfir", track: "dfir", points: 120, ci: false, fmt: "FLAG{...}",
    title: { ko: "Chromium SQLite 쿠키/세션 하이재킹 및 데이터 유출 흔적", en: "Chromium SQLite Cookie Theft & Session Hijack Forensics" },
    prompt: {
      ko: "인포스틸러가 탈취한 Chromium `Network\\Cookies` SQLite 파일의 DPAPI 복호화 마스터 키 사용 이력과 웹 세션 탈취 흔적을 분석합니다.\n지정된 식별자 `dfir_browser_history_session_hijack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_browser_history_session_hijack_v1\") 앞 20자리}`",
      en: "Analyze DPAPI master key decryption logs and Chromium SQLite cookie theft artifacts left by infostealers.\nCompute the first 20 hex characters of SHA256(\"dfir_browser_history_session_hijack_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_browser_history_session_hijack_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LSASS 프로세스 메모리에서 DPAPI 마스터키를 유출한 의심 프로세스를 추적하세요.", "식별자 `dfir_browser_history_session_hijack_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Trace anomalous DPAPI CryptUnprotectData invocations across non-browser processes.", "Extract first 20 hex chars of SHA256(\"dfir_browser_history_session_hijack_v1\")."]
    }
  },

  // Tier 4 (10)
  {
    id: "t4_dfir_soar_automated_playbook_orchestration",
    tier: 4, cat: "dfir", track: "dfir", points: 180, ci: false, fmt: "FLAG{...}",
    title: { ko: "SOAR 엔터프라이즈 자동화 침해 격리 및 박멸 플레이북", en: "SOAR Automated Containment & Eradication Playbook" },
    prompt: {
      ko: "SIEM 알람 발생 시 방화벽 IP 차단, Active Directory 계정 비활성화, EDR 호스트 격리, 티켓 생성을 30초 내 오케스트레이션하는 SOAR 파이프라인을 구축합니다.\n지정된 식별자 `dfir_soar_automated_playbook_orchestration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_soar_automated_playbook_orchestration_v1\") 앞 20자리}`",
      en: "Architect automated SOAR playbooks coordinating firewall IP blocks, AD user disablement, and EDR isolation.\nCompute the first 20 hex characters of SHA256(\"dfir_soar_automated_playbook_orchestration_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_soar_automated_playbook_orchestration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["오탐으로 인한 업무 중단을 방지하기 위해 2단계 신뢰도 스코어링 게이트를 적용하세요.", "식별자 `dfir_soar_automated_playbook_orchestration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Integrate multi-source confidence thresholds before executing disruptive isolation steps.", "Extract first 20 hex chars of SHA256(\"dfir_soar_automated_playbook_orchestration_v1\")."]
    }
  },
  {
    id: "t4_dfir_immutable_airgapped_backup_recovery",
    tier: 4, cat: "dfir", track: "dfir", points: 180, ci: false, fmt: "FLAG{...}",
    title: { ko: "WORM 불변 스토리지 및 에어갭 백업 무결성 복구 검증", en: "WORM Immutable Storage & Air-Gapped Disaster Recovery" },
    prompt: {
      ko: "랜섬웨어 침해 이후 WORM(Write Once, Read Many) 스토리지에 보관된 불변 스냅샷을 마운트하고 SHA-256 해시 체인으로 무결성을 검증하며 클린 복원합니다.\n지정된 식별자 `dfir_immutable_airgapped_backup_recovery_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_immutable_airgapped_backup_recovery_v1\") 앞 20자리}`",
      en: "Restore critical enterprise databases from WORM immutable air-gapped snapshots and verify SHA-256 hash chains.\nCompute the first 20 hex characters of SHA256(\"dfir_immutable_airgapped_backup_recovery_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_immutable_airgapped_backup_recovery_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["백업 시스템 관리자 계정이 침해되더라도 WORM 잠금 기간 동안은 데이터 삭제가 불가능해야 합니다.", "식별자 `dfir_immutable_airgapped_backup_recovery_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Object lock compliance retention policies protect backups even under root compromise.", "Extract first 20 hex chars of SHA256(\"dfir_immutable_airgapped_backup_recovery_v1\")."]
    }
  },
  {
    id: "t4_dfir_threat_intelligence_stix_taxii_sharing",
    tier: 4, cat: "dfir", track: "dfir", points: 190, ci: false, fmt: "FLAG{...}",
    title: { ko: "전사 IoC 지표화 및 STIX 2.1 / TAXII 연합 위협 공유", en: "Threat Intelligence STIX 2.1 & TAXII Federated Sharing" },
    prompt: {
      ko: "침해 현장에서 확보한 파일 해시, C2 네트워크 인프라, 공격 기법(TTP)을 STIX 2.1 JSON 번들로 표준화하고 TAXII 서버를 통해 파트너사와 실시간 공유합니다.\n지정된 식별자 `dfir_threat_intelligence_stix_taxii_sharing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_threat_intelligence_stix_taxii_sharing_v1\") 앞 20자리}`",
      en: "Structure carved indicators and adversary TTPs into STIX 2.1 JSON bundles for automated TAXII federation.\nCompute the first 20 hex characters of SHA256(\"dfir_threat_intelligence_stix_taxii_sharing_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_threat_intelligence_stix_taxii_sharing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["STIX Observed Data 및 Indicator 객체 간의 관계(relationship)를 모델링하세요.", "식별자 `dfir_threat_intelligence_stix_taxii_sharing_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Link STIX observable objects to attack pattern identifiers via relationship objects.", "Extract first 20 hex chars of SHA256(\"dfir_threat_intelligence_stix_taxii_sharing_v1\")."]
    }
  },
  {
    id: "t4_dfir_supply_chain_cicd_artifact_compromise",
    tier: 4, cat: "dfir", track: "dfir", points: 190, ci: false, fmt: "FLAG{...}",
    title: { ko: "CI/CD 빌드 파이프라인 아티팩트 오염 및 공급망 침해 대응", en: "CI/CD Pipeline Artifact Tampering & Supply Chain DFIR" },
    prompt: {
      ko: "GitHub Actions 러너 침투로 빌드 아티팩트에 악성 백도어가 삽입된 사고를 추적하고, SLSA 증명(Provenance) 및 Sigstore 서명 불일치로 오염 빌드를 차단합니다.\n지정된 식별자 `dfir_supply_chain_cicd_artifact_compromise_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_supply_chain_cicd_artifact_compromise_v1\") 앞 20자리}`",
      en: "Investigate CI/CD build worker compromise and isolate tampered binaries failing SLSA provenance verifications.\nCompute the first 20 hex characters of SHA256(\"dfir_supply_chain_cicd_artifact_compromise_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_supply_chain_cicd_artifact_compromise_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["임시 빌드 러너 환경에서 OIDC 토큰 탈취 여부와 레포지토리 시크릿 접근 로그를 검토하세요.", "식별자 `dfir_supply_chain_cicd_artifact_compromise_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Verify immutable commit SHAs against build provenance cryptographically signed by Cosign.", "Extract first 20 hex chars of SHA256(\"dfir_supply_chain_cicd_artifact_compromise_v1\")."]
    }
  },
  {
    id: "t4_dfir_llm_mcp_agent_unauthorized_exfiltration",
    tier: 4, cat: "dfir", track: "dfir", points: 190, ci: false, fmt: "FLAG{...}",
    title: { ko: "AI 에이전트 도구 권한 남용 및 간접 주입 침해 포렌식", en: "AI Agent Tool Abuse & Indirect Prompt Injection Forensics" },
    prompt: {
      ko: "RAG 문서 오염을 통해 LLM 에이전트가 MCP 도구(파일 읽기, 외부 웹훅 호출)를 임의로 실행한 비인가 데이터 유출 세션을 대화 트랜스크립트 로그에서 역추적합니다.\n지정된 식별자 `dfir_llm_mcp_agent_unauthorized_exfiltration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_llm_mcp_agent_unauthorized_exfiltration_v1\") 앞 20자리}`",
      en: "Perform forensic triage on indirect prompt injection payloads causing autonomous LLM tool misuse and exfiltration.\nCompute the first 20 hex characters of SHA256(\"dfir_llm_mcp_agent_unauthorized_exfiltration_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_llm_mcp_agent_unauthorized_exfiltration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["에이전트가 외부 문서를 읽는 시점과 샌드박스 외부로 HTTP POST 요청을 날린 시점을 연계 분석하세요.", "식별자 `dfir_llm_mcp_agent_unauthorized_exfiltration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Reconstruct the sequence between tainted RAG context ingestion and unapproved tool dispatch.", "Extract first 20 hex chars of SHA256(\"dfir_llm_mcp_agent_unauthorized_exfiltration_v1\")."]
    }
  },
  {
    id: "t4_dfir_kernel_rootkit_ebpf_integrity_audit",
    tier: 4, cat: "dfir", track: "dfir", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "커널 루트킷 및 악성 eBPF 프로그램 런타임 무결성 감사", en: "Kernel Rootkit & Rogue eBPF Program Integrity Audit" },
    prompt: {
      ko: "커널 fexit 및 kprobe 후킹으로 시스템콜을 조작하는 악성 eBPF 프로그램을 `bpftool prog` 및 커널 BPF 맵 덤프를 통해 적출하고 인메모리 언로드를 집행합니다.\n지정된 식별자 `dfir_kernel_rootkit_ebpf_integrity_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_kernel_rootkit_ebpf_integrity_audit_v1\") 앞 20자리}`",
      en: "Audit loaded eBPF programs via bpftool to detect stealthy kernel rootkits hooking syscall return addresses.\nCompute the first 20 hex characters of SHA256(\"dfir_kernel_rootkit_ebpf_integrity_audit_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_kernel_rootkit_ebpf_integrity_audit_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["서명되지 않은 eBPF 바이트코드 로드를 방지하기 위해 BPF LSM 가드레일을 활성화하세요.", "식별자 `dfir_kernel_rootkit_ebpf_integrity_audit_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Audit BPF programs lacking valid namespace tags and detach suspicious tracepoint probes.", "Extract first 20 hex chars of SHA256(\"dfir_kernel_rootkit_ebpf_integrity_audit_v1\")."]
    }
  },
  {
    id: "t4_dfir_cross_cloud_iam_session_revocation",
    tier: 4, cat: "dfir", track: "dfir", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "멀티클라우드(AWS/Azure/GCP) IAM 임시 세션 일괄 무효화", en: "Multi-Cloud (AWS/Azure/GCP) Global IAM Session Revocation" },
    prompt: {
      ko: "전사 크리덴셜 유출 사고 발생 시 인라인 세션 정책(aws:CurrentTime < RevokeBefore)을 즉시 주입하여 발급된 모든 STS 임시 토큰을 강제 만료시키는 비상 프로토콜을 가동합니다.\n지정된 식별자 `dfir_cross_cloud_iam_session_revocation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_cross_cloud_iam_session_revocation_v1\") 앞 20자리}`",
      en: "Execute global emergency session revocation across AWS, Azure, and GCP invalidating active temporary STS tokens.\nCompute the first 20 hex characters of SHA256(\"dfir_cross_cloud_iam_session_revocation_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_cross_cloud_iam_session_revocation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["단순 비밀번호 변경으로는 기발급된 STS 임시 세션 토큰이 만료되지 않으므로 Revocation 정책이 필수입니다.", "식별자 `dfir_cross_cloud_iam_session_revocation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Password changes do not revoke active STS session tokens; explicit revocation policies are required.", "Extract first 20 hex chars of SHA256(\"dfir_cross_cloud_iam_session_revocation_v1\")."]
    }
  },
  {
    id: "t4_dfir_post_incident_rca_and_lessons_learned",
    tier: 4, cat: "dfir", track: "dfir", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "NIST 근본 원인 분석(RCA) 및 사후 교훈 보고서 거버넌스", en: "NIST Root Cause Analysis (RCA) & Post-Incident Governance" },
    prompt: {
      ko: "침해사고 종결 후 5-Whys 및 어택 트리(Attack Tree)를 구성하여 최초 침투 경로, 측면 이동, 탐지 지연 요인을 분석하고 경영진 사후 교훈 보고서를 작성합니다.\n지정된 식별자 `dfir_post_incident_rca_and_lessons_learned_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_post_incident_rca_and_lessons_learned_v1\") 앞 20자리}`",
      en: "Synthesize post-incident Root Cause Analysis (RCA) and executive lessons-learned roadmaps to eliminate attack surfaces.\nCompute the first 20 hex characters of SHA256(\"dfir_post_incident_rca_and_lessons_learned_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_post_incident_rca_and_lessons_learned_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["MTTD(평균 탐지 시간)와 MTTR(평균 대응 시간) 개선 지표를 도출하세요.", "식별자 `dfir_post_incident_rca_and_lessons_learned_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Quantify MTTD and MTTR improvements to justify strategic security controls.", "Extract first 20 hex chars of SHA256(\"dfir_post_incident_rca_and_lessons_learned_v1\")."]
    }
  },
  {
    id: "t4_dfir_enterprise_resilience_tabletop_exercise",
    tier: 4, cat: "dfir", track: "dfir", points: 220, ci: false, fmt: "FLAG{...}",
    title: { ko: "전사 사이버 위기 대응 모의훈련(TTX) 시나리오 검증", en: "Enterprise Cyber Resilience Tabletop Exercise (TTX)" },
    prompt: {
      ko: "C-Level 경영진, 법무팀, 홍보팀, 보안팀이 참여하는 대규모 랜섬웨어 위기 모의훈련 시나리오를 구성하고 공시 의무(GDPR 72시간) 및 비상 커뮤니케이션을 검증합니다.\n지정된 식별자 `dfir_enterprise_resilience_tabletop_exercise_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_enterprise_resilience_tabletop_exercise_v1\") 앞 20자리}`",
      en: "Validate crisis governance, regulatory notification (GDPR 72h), and incident containment through executive TTX simulations.\nCompute the first 20 hex characters of SHA256(\"dfir_enterprise_resilience_tabletop_exercise_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_enterprise_resilience_tabletop_exercise_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["기술적 대응뿐만 아니라 규제 기관 보고 타임라인과 언론 대응 지침을 포함해야 합니다.", "식별자 `dfir_enterprise_resilience_tabletop_exercise_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Test cross-functional coordination between legal, communication, and DFIR response leads.", "Extract first 20 hex chars of SHA256(\"dfir_enterprise_resilience_tabletop_exercise_v1\")."]
    }
  },
  {
    id: "t4_dfir_capstone_full_spectrum_incident_response",
    tier: 4, cat: "dfir", track: "dfir", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "엔터프라이즈 풀스펙트럼 침해사고 대응 및 복구 캡스톤", en: "Enterprise Full-Spectrum Incident Response & Recovery Capstone" },
    prompt: {
      ko: "초기 라이브 메모리 트리아지부터 MFT 포렌식, 네트워크 격리, SOAR 자동 박멸, 불변 복구 및 위협 인텔리전스 공유에 이르는 엔터프라이즈 DFIR 전 과정을 총괄 완수합니다.\n지정된 식별자 `dfir_capstone_full_spectrum_incident_response_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dfir_capstone_full_spectrum_incident_response_v1\") 앞 20자리}`",
      en: "Synthesize end-to-end DFIR methodologies spanning live memory triage, MFT chronologies, network containment, and SOAR recovery.\nCompute the first 20 hex characters of SHA256(\"dfir_capstone_full_spectrum_incident_response_v1\").\n\nFormat: `FLAG{SHA256(\"dfir_capstone_full_spectrum_incident_response_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["NIST SP 800-61의 준비-탐지-봉쇄-박멸-복구-사후교훈 전 생명주기를 종합 검토하세요.", "식별자 `dfir_capstone_full_spectrum_incident_response_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Synthesize the complete NIST lifecycle from preparation and triage to eradication and post-incident lessons.", "Extract first 20 hex chars of SHA256(\"dfir_capstone_full_spectrum_incident_response_v1\")."]
    }
  }
];

// Add hash matching identifier in prompt
for (const ch of challengesDef) {
  const m = ch.prompt.ko.match(/SHA(?:-)?256\("([^"]+)"\)/);
  if (!m) throw new Error("Identifier not found in prompt: " + ch.id);
  const identifier = m[1];
  const flag = "FLAG{" + crypto.createHash('sha256').update(identifier).digest('hex').substring(0, 20) + "}";
  ch.hash = crypto.createHash('sha256').update(flag).digest('hex');
}

console.log("Generated challenges count:", challengesDef.length);
fs.writeFileSync('/tmp/track54_challenges.json', JSON.stringify(challengesDef, null, 2), 'utf8');
