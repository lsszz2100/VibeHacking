#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function computeHash(id) {
  const ident = id.replace(/^t\d_/, '') + "_v1";
  const flag = "FLAG{" + crypto.createHash('sha256').update(ident).digest('hex').substring(0, 20) + "}";
  return crypto.createHash('sha256').update(flag).digest('hex');
}

const challengesDef = [
  // Tier 0 (2)
  {
    id: "t0_sansdfir_fundamentals_evidence_of_execution",
    tier: 0, cat: "dfir", track: "sansdfir", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "SANS FOR508 실행 흔적 아티팩트 및 PECmd/ShimCache 파서 개요", en: "SANS FOR508 Evidence of Execution & PECmd/ShimCache Overview" },
    prompt: {
      ko: "침해사고 조사 시 공격자의 악성코드 실행 여부를 입증하기 위해 Prefetch, ShimCache, Amcache, UserAssist를 종합 트리아지하는 방법론을 분석합니다.\n지정된 식별자 `sansdfir_fundamentals_evidence_of_execution_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_fundamentals_evidence_of_execution_v1\") 앞 20자리}`",
      en: "Examine SANS FOR508 methodology for triangulating Evidence of Execution through Prefetch, ShimCache, Amcache, and UserAssist.\nCompute the first 20 hex characters of SHA256(\"sansdfir_fundamentals_evidence_of_execution_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_fundamentals_evidence_of_execution_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Windows 실행 흔적 아티팩트는 파일 이름뿐만 아니라 실행 횟수와 타임스탬프를 제공합니다.", "식별자 `sansdfir_fundamentals_evidence_of_execution_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Evidence of execution artifacts capture binary execution counts and timestamps.", "Extract first 20 hex chars of SHA256(\"sansdfir_fundamentals_evidence_of_execution_v1\")."]
    }
  },
  {
    id: "t0_sansdfir_forensic_timeline_concept",
    tier: 0, cat: "timeline", track: "sansdfir", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "포렌식 타임라인 분석 원리와 MACB 타임스탬프 체계", en: "Forensic Timeline Analysis & MACB Timestamp System" },
    prompt: {
      ko: "디지털 포렌식에서 수정(Modification), 접근(Access), MFT 변경(Change), 생성(Birth)을 기록하는 MACB 4요소 타임스탬프의 시간선 정렬 원리를 분석합니다.\n지정된 식별자 `sansdfir_forensic_timeline_concept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_forensic_timeline_concept_v1\") 앞 20자리}`",
      en: "Analyze the fundamental MACB (Modification, Access, Change, Birth) timestamp structure used to build unified forensic timelines.\nCompute the first 20 hex characters of SHA256(\"sansdfir_forensic_timeline_concept_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_forensic_timeline_concept_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["MACB 시간선은 서로 다른 증거 소스의 시간차를 UTC 기준으로 일치시키는 핵심 프레임워크입니다.", "식별자 `sansdfir_forensic_timeline_concept_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["MACB timestamps correlate evidence across disparate sources aligned to UTC.", "Extract first 20 hex chars of SHA256(\"sansdfir_forensic_timeline_concept_v1\")."]
    }
  },

  // Tier 1 (8)
  {
    id: "t1_sansdfir_prefetch_pecmd_analysis",
    tier: 1, cat: "prefetch", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Windows Prefetch 분석 및 마지막 실행 시각과 실행 횟수 산출", en: "Windows Prefetch Analysis & Execution Count Recovery via PECmd" },
    prompt: {
      ko: "Eric Zimmerman의 PECmd 도구를 활용하여 C:\\Windows\\Prefetch 디렉터리의 `.pf` 파일에서 마지막 8회 실행 시각과 참조된 DLL 목록을 추출하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_prefetch_pecmd_analysis_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_prefetch_pecmd_analysis_v1\") 앞 20자리}`",
      en: "Analyze how PECmd parses Windows Prefetch `.pf` records to reconstruct up to 8 run timestamps and loaded DLLs.\nCompute first 20 hex chars of SHA256(\"sansdfir_prefetch_pecmd_analysis_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_prefetch_pecmd_analysis_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Prefetch 파일 이름은 `실행파일명-해시.pf` 형식으로 생성되며, 실행 횟수 메타데이터가 보존됩니다.", "식별자 `sansdfir_prefetch_pecmd_analysis_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Prefetch files follow `binary-hash.pf` naming and preserve run count headers.", "Extract first 20 hex chars of SHA256(\"sansdfir_prefetch_pecmd_analysis_v1\")."]
    }
  },
  {
    id: "t1_sansdfir_shimcache_appcompatcache_triage",
    tier: 1, cat: "shimcache", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "AppCompatCache(ShimCache) 레지스트리 경로 및 실행 순서 복원", en: "AppCompatCache (ShimCache) Registry Path & Order Triage" },
    prompt: {
      ko: "SYSTEM 하이브 레지스트리 내 AppCompatCache에서 시스템 종료 시점에 기록되는 전체 파일 경로와 마지막 수정 시각을 파싱하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_shimcache_appcompatcache_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_shimcache_appcompatcache_triage_v1\") 앞 20자리}`",
      en: "Examine AppCompatCache parsing within the SYSTEM registry hive to trace historical file paths and insertion order.\nCompute first 20 hex chars of SHA256(\"sansdfir_shimcache_appcompatcache_triage_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_shimcache_appcompatcache_triage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ShimCache는 파일이 실제로 실행되었거나 디렉터리에 존재했음을 입증하는 강력한 지표입니다.", "식별자 `sansdfir_shimcache_appcompatcache_triage_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["ShimCache records prove execution context or file existence prior to shutdown.", "Extract first 20 hex chars of SHA256(\"sansdfir_shimcache_appcompatcache_triage_v1\")."]
    }
  },
  {
    id: "t1_sansdfir_amcache_hve_sha1_extraction",
    tier: 1, cat: "amcache", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Amcache.hve 파일 정보 및 미서명 바이너리 SHA-1 해시 카빙", en: "Amcache.hve File Metadata & Unsigned Binary SHA-1 Extraction" },
    prompt: {
      ko: "Windows 10/11의 `C:\\Windows\\AppCompat\\Programs\\Amcache.hve` 레지스트리 파일에서 실행 파일의 SHA-1 해시, 컴파일 타임, PE 파일 크기를 추출하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_amcache_hve_sha1_extraction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_amcache_hve_sha1_extraction_v1\") 앞 20자리}`",
      en: "Analyze Amcache.hve parser forensics extracting executable SHA-1 hashes, compilation headers, and file sizes.\nCompute first 20 hex chars of SHA256(\"sansdfir_amcache_hve_sha1_extraction_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_amcache_hve_sha1_extraction_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Amcache는 파일이 이미 디스크에서 삭제된 이후에도 바이너리의 고유 SHA-1 해시를 보존합니다.", "식별자 `sansdfir_amcache_hve_sha1_extraction_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Amcache preserves binary SHA-1 hashes even after the physical file is deleted.", "Extract first 20 hex chars of SHA256(\"sansdfir_amcache_hve_sha1_extraction_v1\")."]
    }
  },
  {
    id: "t1_sansdfir_userassist_rot13_decoding",
    tier: 1, cat: "registry", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "UserAssist 레지스트리 ROT-13 디코딩 및 GUI 프로그램 실행 기록", en: "UserAssist Registry ROT-13 Decoding & GUI Execution Profiling" },
    prompt: {
      ko: "NTUSER.DAT 레지스트리의 UserAssist 키에 ROT-13으로 인코딩된 사용자의 GUI 기반 실행 프로그램, 실행 횟수 및 포커스 시간을 디코딩하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_userassist_rot13_decoding_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_userassist_rot13_decoding_v1\") 앞 20자리}`",
      en: "Examine ROT-13 decoding of UserAssist values in NTUSER.DAT to profile user-interactive GUI executions and focus time.\nCompute first 20 hex chars of SHA256(\"sansdfir_userassist_rot13_decoding_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_userassist_rot13_decoding_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["UserAssist 항목은 악성 관리 도구가 대화형 GUI 세션에서 실행되었는지를 입증합니다.", "식별자 `sansdfir_userassist_rot13_decoding_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["UserAssist proves interactive GUI session execution by an active user.", "Extract first 20 hex chars of SHA256(\"sansdfir_userassist_rot13_decoding_v1\")."]
    }
  },
  {
    id: "t1_sansdfir_mft_record_structure_attributes",
    tier: 1, cat: "mft", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "NTFS $MFT 레코드 1024바이트 구조와 $STANDARD_INFO vs $FILE_NAME", en: "NTFS $MFT 1024-byte Record Structure: $STANDARD_INFO vs $FILE_NAME" },
    prompt: {
      ko: "NTFS 파일시스템의 1024바이트 $MFT 레코드에서 사용자 모드 API로 수정 가능한 `$STANDARD_INFORMATION`($0x10)과 커널만 갱신하는 `$FILE_NAME`($0x30)의 차이를 분석합니다.\n지정된 식별자 `sansdfir_mft_record_structure_attributes_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_mft_record_structure_attributes_v1\") 앞 20자리}`",
      en: "Analyze the 1024-byte NTFS $MFT record layout comparing user-modifiable $0x10 attributes with kernel-locked $0x30 attributes.\nCompute first 20 hex chars of SHA256(\"sansdfir_mft_record_structure_attributes_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_mft_record_structure_attributes_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["$0x10 속성은 타임스톰핑 도구로 조작될 수 있으나 $0x30 속성은 일반적으로 변경되지 않습니다.", "식별자 `sansdfir_mft_record_structure_attributes_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["$0x10 standard info is vulnerable to timestomping while $0x30 filename attributes remain immutable.", "Extract first 20 hex chars of SHA256(\"sansdfir_mft_record_structure_attributes_v1\")."]
    }
  },
  {
    id: "t1_sansdfir_usn_change_journal_reasons",
    tier: 1, cat: "usn", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "NTFS USN 저널 변경 사유 플래그와 안티포렌식 파일 삭제 추적", en: "NTFS USN Change Journal Reason Flags & Anti-Forensics Deletion Tracking" },
    prompt: {
      ko: "`$Extend\\$UsnJrnl:$J` 스트림에 기록되는 `USN_REASON_FILE_CREATE`, `USN_REASON_DATA_OVERWRITE`, `USN_REASON_FILE_DELETE` 사유 플래그를 통한 삭제 행위 재구성 기법을 분석합니다.\n지정된 식별자 `sansdfir_usn_change_journal_reasons_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_usn_change_journal_reasons_v1\") 앞 20자리}`",
      en: "Examine NTFS USN Change Journal reason flags reconstructing anti-forensic secure deletion sequences.\nCompute first 20 hex chars of SHA256(\"sansdfir_usn_change_journal_reasons_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_usn_change_journal_reasons_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["USN Journal은 파일이 $MFT에서 제거되더라도 저널 로그에 레코드 시퀀스를 유지합니다.", "식별자 `sansdfir_usn_change_journal_reasons_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The USN journal maintains historical transaction records even after MFT record deletion.", "Extract first 20 hex chars of SHA256(\"sansdfir_usn_change_journal_reasons_v1\")."]
    }
  },
  {
    id: "t1_sansdfir_shellbags_folder_access_tracking",
    tier: 1, cat: "shellbags", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "ShellBags 아티팩트 파싱 및 공격자의 폴더 탐색 경로 추적", en: "ShellBags Artifact Parsing & Attacker Directory Traversal Profiling" },
    prompt: {
      ko: "UsrClass.dat 레지스트리의 ShellBags 계층 구조를 파싱하여 공격자가 GUI 탐색기에서 진입했던 폴더명, 네트워크 공유 경로 및 생성 일자를 복원하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_shellbags_folder_access_tracking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_shellbags_folder_access_tracking_v1\") 앞 20자리}`",
      en: "Analyze ShellBags hierarchy in UsrClass.dat to reconstruct directory traversal, removable drives, and shared folders browsed by an attacker.\nCompute first 20 hex chars of SHA256(\"sansdfir_shellbags_folder_access_tracking_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_shellbags_folder_access_tracking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ShellBags는 폴더가 삭제된 이후에도 해당 폴더에 접근했던 사용자의 탐색 기록을 증명합니다.", "식별자 `sansdfir_shellbags_folder_access_tracking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["ShellBags prove folder access even if the target directories were subsequently wiped.", "Extract first 20 hex chars of SHA256(\"sansdfir_shellbags_folder_access_tracking_v1\")."]
    }
  },
  {
    id: "t1_sansdfir_lnk_and_jumplist_carving",
    tier: 1, cat: "lnk", track: "sansdfir", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "LNK 바로가기 파일 및 Jump Lists를 통한 외장 드라이브 및 문서 열람 분석", en: "LNK Shortcut Files & Jump Lists Forensics on Removable Media" },
    prompt: {
      ko: "최근 열람된 파일(AutomaticDestinations, CustomDestinations) Jump Lists와 LNK 바이너리 객체에서 원본 경로, 볼륨 시리얼 번호, MAC 주소를 파싱하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_lnk_and_jumplist_carving_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_lnk_and_jumplist_carving_v1\") 앞 20자리}`",
      en: "Examine LNK shortcut and Jump List binary stream parsing to reveal target paths, volume serials, and host MACs.\nCompute first 20 hex chars of SHA256(\"sansdfir_lnk_and_jumplist_carving_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_lnk_and_jumplist_carving_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LNK 파일 헤더에는 대상 시스템의 볼륨 시리얼 번호와 네트워크 드라이브 정보가 포함됩니다.", "식별자 `sansdfir_lnk_and_jumplist_carving_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["LNK metadata captures target volume serial numbers and host identifiers.", "Extract first 20 hex chars of SHA256(\"sansdfir_lnk_and_jumplist_carving_v1\")."]
    }
  },

  // Tier 2 (12)
  {
    id: "t2_sansdfir_timestomping_std_fn_discrepancy",
    tier: 2, cat: "timestomp", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "$STD와 $FN 타임스탬프 나노초 정밀도 불일치 판정을 통한 타임스톰핑 탐지", en: "Timestomping Detection via $STD vs $FN Timestamp Discrepancy" },
    prompt: {
      ko: "공격자가 SetFileTime API로 `$STANDARD_INFORMATION`의 나노초를 `0000000`으로 조작했을 때, `$FILE_NAME`의 실제 생성 시각과의 시간 역전을 판별하는 로직을 분석합니다.\n지정된 식별자 `sansdfir_timestomping_std_fn_discrepancy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_timestomping_std_fn_discrepancy_v1\") 앞 20자리}`",
      en: "Analyze timestomping heuristics comparing nanosecond precision truncation in $0x10 with authentic $0x30 timestamps.\nCompute first 20 hex chars of SHA256(\"sansdfir_timestomping_std_fn_discrepancy_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_timestomping_std_fn_discrepancy_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Windows 기본 파일 시스템은 100나노초 정밀도를 가지나 일반적인 타임스톰핑 도구는 초 단위 이하를 0으로 채웁니다.", "식별자 `sansdfir_timestomping_std_fn_discrepancy_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Authentic NTFS timestamps show full 100-ns precision while naive timestompers pad zeroes.", "Extract first 20 hex chars of SHA256(\"sansdfir_timestomping_std_fn_discrepancy_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_mft_nonresident_data_runs",
    tier: 2, cat: "mft", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "$MFT 논레지던트 $DATA 속성의 Data Run 바이트 디코딩 및 클러스터 카빙", en: "NTFS $DATA Non-Resident Data Run Byte Decoding & Cluster Carving" },
    prompt: {
      ko: "$MFT 레코드 내 런 리스트(Data Run) 바이트(길이/오프셋 니블 인코딩)를 파싱하여 단편화된 파일의 실제 LCN(Logical Cluster Number)을 매핑하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_mft_nonresident_data_runs_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_mft_nonresident_data_runs_v1\") 앞 20자리}`",
      en: "Examine Data Run nibble decoding in non-resident $DATA attributes to locate fragmented file clusters across volume sectors.\nCompute first 20 hex chars of SHA256(\"sansdfir_mft_nonresident_data_runs_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_mft_nonresident_data_runs_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["첫 번째 바이트의 상위 니블은 오프셋 바이트 수, 하위 니블은 클러스터 길이 바이트 수를 의미합니다.", "식별자 `sansdfir_mft_nonresident_data_runs_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The first byte nibbles dictate offset length and cluster run length respectively.", "Extract first 20 hex chars of SHA256(\"sansdfir_mft_nonresident_data_runs_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_logfile_transaction_rollback",
    tier: 2, cat: "logfile", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "NTFS $LogFile 트랜잭션 로그 분석 및 롤백된 메타데이터 복원", en: "NTFS $LogFile Transaction Log Carving & Metadata Rollback" },
    prompt: {
      ko: "NTFS의 `$LogFile` 원자적 트랜잭션 버퍼(Restart Area 및 Redo/Undo 오퍼레이션)에서 파일 삭제 직전의 메타데이터 변경을 추적하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_logfile_transaction_rollback_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_logfile_transaction_rollback_v1\") 앞 20자리}`",
      en: "Analyze NTFS $LogFile redo/undo transaction records to reconstruct file system states prior to defensive wiping.\nCompute first 20 hex chars of SHA256(\"sansdfir_logfile_transaction_rollback_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_logfile_transaction_rollback_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["$LogFile은 볼륨 무결성을 위해 메타데이터 트랜잭션의 Redo 및 Undo 연산을 보관합니다.", "식별자 `sansdfir_logfile_transaction_rollback_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["$LogFile logs redo and undo transaction buffers for file system consistency.", "Extract first 20 hex chars of SHA256(\"sansdfir_logfile_transaction_rollback_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_srum_network_and_energy_usage",
    tier: 2, cat: "srum", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Windows SRUM(System Resource Usage Monitor) ESE DB 기반 악성 C2 데이터 전송량 입증", en: "Windows SRUM ESE Database Forensics on Malicious C2 Data Exfiltration" },
    prompt: {
      ko: "`C:\\Windows\\System32\\sru\\SRUDB.dat` ESE 데이터베이스를 분석하여 특정 실행 파일이 네트워크 인터페이스를 통해 송수신한 총 바이트 수와 백그라운드 활성 기간을 추적하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_srum_network_and_energy_usage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_srum_network_and_energy_usage_v1\") 앞 20자리}`",
      en: "Examine SRUDB.dat ESE database parsing to quantify bytes sent and received by suspected malicious processes.\nCompute first 20 hex chars of SHA256(\"sansdfir_srum_network_and_energy_usage_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_srum_network_and_energy_usage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SRUM은 네트워크 패킷 캡처가 누락되었을 때 프로세스별 데이터 유출 규모를 입증하는 결정적 증거입니다.", "식별자 `sansdfir_srum_network_and_energy_usage_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["SRUM provides definitive byte-count telemetry per executable even without full packet captures.", "Extract first 20 hex chars of SHA256(\"sansdfir_srum_network_and_energy_usage_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_bam_dam_background_activity",
    tier: 2, cat: "bam", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "BAM/DAM(Background Activity Moderator) 레지스트리 기반 시스템 부팅 후 실행 시각 분석", en: "BAM/DAM Registry Analysis on Post-Boot Executable Timestamps" },
    prompt: {
      ko: "Windows 1709 이상에서 도입된 `SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings` 키에서 사용자 SID별로 기록되는 절대 실행 타임스탬프를 파싱하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_bam_dam_background_activity_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_bam_dam_background_activity_v1\") 앞 20자리}`",
      en: "Analyze BAM (Background Activity Moderator) registry keys capturing precise execution timestamps per user SID.\nCompute first 20 hex chars of SHA256(\"sansdfir_bam_dam_background_activity_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_bam_dam_background_activity_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["BAM은 64비트 Windows FILETIME 형식으로 바이너리 경로와 최근 실행 시각을 매핑합니다.", "식별자 `sansdfir_bam_dam_background_activity_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["BAM records standard Windows FILETIME values tied to user security identifiers.", "Extract first 20 hex chars of SHA256(\"sansdfir_bam_dam_background_activity_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_volatility3_psscan_vs_pslist",
    tier: 2, cat: "volatility", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Volatility 3 ActiveProcessLinks DKOM 언링크 프로세스 탐지", en: "Volatility 3 ActiveProcessLinks DKOM Unlinked Process Detection" },
    prompt: {
      ko: "윈도우 프로세스 이중 연결 리스트(ActiveProcessLinks)에서 분리된 은닉 EPROCESS 구조체를 커널 풀 태그 스캔(`windows.psscan`)으로 탐지하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_volatility3_psscan_vs_pslist_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_volatility3_psscan_vs_pslist_v1\") 앞 20자리}`",
      en: "Examine Volatility 3 `windows.psscan` cross-referencing against `windows.pslist` to expose unlinked DKOM processes.\nCompute first 20 hex chars of SHA256(\"sansdfir_volatility3_psscan_vs_pslist_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_volatility3_psscan_vs_pslist_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["pslist는 정상 링크를 순회하지만 psscan은 풀 메모리에서 'Proc' 태그 패턴을 직접 검색합니다.", "식별자 `sansdfir_volatility3_psscan_vs_pslist_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["psscan scans memory pools for unlinked EPROCESS structures bypassing active lists.", "Extract first 20 hex chars of SHA256(\"sansdfir_volatility3_psscan_vs_pslist_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_vad_tree_rwx_injection_hunting",
    tier: 2, cat: "vad", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "EPROCESS VAD 트리 순회 및 PAGE_EXECUTE_READWRITE 메모리 영역 쉘코드 식별", en: "EPROCESS VAD Tree Traversal & PAGE_EXECUTE_READWRITE Shellcode Triaging" },
    prompt: {
      ko: "프로세스 가상 주소 디스크립터(VAD) 이진 트리를 순회하여 디스크 백업 파일이 없는 비공개(Private) `PAGE_EXECUTE_READWRITE` 메모리 할당을 탐지하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_vad_tree_rwx_injection_hunting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_vad_tree_rwx_injection_hunting_v1\") 앞 20자리}`",
      en: "Analyze VAD tree inspection isolating anonymous PAGE_EXECUTE_READWRITE memory blocks harboring injected shellcodes.\nCompute first 20 hex chars of SHA256(\"sansdfir_vad_tree_rwx_injection_hunting_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_vad_tree_rwx_injection_hunting_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["일반적인 실행 파일은 PAGE_EXECUTE_READ이며, RWX 비공개 메모리는 악성 인젝션의 결정적 지표입니다.", "식별자 `sansdfir_vad_tree_rwx_injection_hunting_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Legitimate binaries map executable pages as RX; unmapped RWX blocks signal injection.", "Extract first 20 hex chars of SHA256(\"sansdfir_vad_tree_rwx_injection_hunting_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_malfind_vad_header_analysis",
    tier: 2, cat: "malfind", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Volatility 3 malfind 플러그인과 비공개 커밋 메모리 내 MZ/PE 헤더 트리아지", en: "Volatility 3 malfind Plugin & In-Memory Reflective PE Header Analysis" },
    prompt: {
      ko: "`windows.malfind` 플러그인을 사용하여 메모리 인젝션 영역의 첫 바이트(4D 5A, MZ 헤더)와 어셈블리 명령어를 카빙하는 분석 기법을 분석합니다.\n지정된 식별자 `sansdfir_malfind_vad_header_analysis_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_malfind_vad_header_analysis_v1\") 앞 20자리}`",
      en: "Examine `windows.malfind` output parsing reflective PE headers and shellcode stubs within injected memory pages.\nCompute first 20 hex chars of SHA256(\"sansdfir_malfind_vad_header_analysis_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_malfind_vad_header_analysis_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["malfind는 VAD 태그와 메모리 보호 속성을 분석하여 쉘코드 디스어셈블을 출력합니다.", "식별자 `sansdfir_malfind_vad_header_analysis_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["malfind combines VAD inspection with opcode disassembly for injected pages.", "Extract first 20 hex chars of SHA256(\"sansdfir_malfind_vad_header_analysis_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_network_netscan_socket_reconstruction",
    tier: 2, cat: "netscan", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "메모리 덤프 풀 태그 스캔을 통한 종료된 C2 네트워크 소켓 및 원격 IP 복원", en: "Memory Pool Tag Scanning for Terminated C2 Network Sockets & Remote IPs" },
    prompt: {
      ko: "`windows.netscan` 또는 `windows.netstat`을 통해 메모리에 잔존하는 TCP 엔드포인트 객체, 로컬/원격 IP 주소, 포트 및 바인딩 PID를 복원하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_network_netscan_socket_reconstruction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_network_netscan_socket_reconstruction_v1\") 앞 20자리}`",
      en: "Analyze memory pool tag scanning recovering active and closed TCP endpoint objects, remote IPs, and owning PIDs.\nCompute first 20 hex chars of SHA256(\"sansdfir_network_netscan_socket_reconstruction_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_network_netscan_socket_reconstruction_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["네트워크 커널 객체는 프로세스가 종료된 이후에도 일정 시간 물리 메모리에 잔존합니다.", "식별자 `sansdfir_network_netscan_socket_reconstruction_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Kernel TCP endpoint structures persist in unallocated memory pages after process termination.", "Extract first 20 hex chars of SHA256(\"sansdfir_network_netscan_socket_reconstruction_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_tshark_for572_dns_tunnel_filter",
    tier: 2, cat: "tshark", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "SANS FOR572 tshark 패킷 필터를 통한 DNS TXT 쿼리 터널링 세션 카빙", en: "SANS FOR572 tshark Display Filtering for DNS TXT Tunneling Exfiltration" },
    prompt: {
      ko: "SANS FOR572 실무 가이드에 따라 `tshark -r capture.pcap -Y 'dns.flags.response == 0 and dns.qry.type == 16' -T fields -e dns.qry.name`으로 고엔트로피 DNS 터널링을 필터링하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_tshark_for572_dns_tunnel_filter_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_tshark_for572_dns_tunnel_filter_v1\") 앞 20자리}`",
      en: "Examine SANS FOR572 tshark filtering isolating anomalous high-entropy DNS TXT queries utilized for covert data exfiltration.\nCompute first 20 hex chars of SHA256(\"sansdfir_tshark_for572_dns_tunnel_filter_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_tshark_for572_dns_tunnel_filter_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["DNS TXT(타입 16) 레코드는 긴 페이로드를 전달할 수 있어 C2 통신 및 데이터 유출에 빈번히 악용됩니다.", "식별자 `sansdfir_tshark_for572_dns_tunnel_filter_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["DNS TXT record payloads accommodate base64-encoded exfiltration streams.", "Extract first 20 hex chars of SHA256(\"sansdfir_tshark_for572_dns_tunnel_filter_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_tshark_tls_ja3_fingerprinting",
    tier: 2, cat: "ja3", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "tshark TLS Client Hello 패킷 기반 JA3/JA4 악성 C2 클라이언트 핑거프린팅", en: "tshark TLS Client Hello Extraction for JA3/JA4 Malicious C2 Fingerprinting" },
    prompt: {
      ko: "암호화된 TLS 통신에서 Client Hello의 암호 스위트, 확장 필드 순서를 해시화하여 악성 봇넷 및 코발트 스트라이크 비콘 클라이언트를 식별하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_tshark_tls_ja3_fingerprinting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_tshark_tls_ja3_fingerprinting_v1\") 앞 20자리}`",
      en: "Analyze JA3/JA4 fingerprinting hashing TLS Client Hello cipher suites and extensions to profile malicious C2 agents.\nCompute first 20 hex chars of SHA256(\"sansdfir_tshark_tls_ja3_fingerprinting_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_tshark_tls_ja3_fingerprinting_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["JA3는 패킷 본문이 암호화되어 있어도 클라이언트 소프트웨어의 고유 통신 특성을 식별합니다.", "식별자 `sansdfir_tshark_tls_ja3_fingerprinting_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["JA3 identifies agent software stacks prior to TLS session encryption.", "Extract first 20 hex chars of SHA256(\"sansdfir_tshark_tls_ja3_fingerprinting_v1\")."]
    }
  },
  {
    id: "t2_sansdfir_plaso_log2timeline_supertimeline",
    tier: 2, cat: "plaso", track: "sansdfir", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Plaso log2timeline 도구를 통한 다계층 아티팩트 통합 슈퍼타임라인 생성", en: "Plaso log2timeline Multi-Source Artifact Supertimeline Generation" },
    prompt: {
      ko: "디스크 이미지 전수에서 파일시스템, 이벤트 로그, 웹 히스토리, 레지스트리를 추출하여 시간순으로 일원화하는 `psort.py` 슈퍼타임라인 필터링 기법을 분석합니다.\n지정된 식별자 `sansdfir_plaso_log2timeline_supertimeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_plaso_log2timeline_supertimeline_v1\") 앞 20자리}`",
      en: "Examine Plaso `log2timeline` and `psort.py` pipelines unifying heterogeneous forensics into standardized supertimelines.\nCompute first 20 hex chars of SHA256(\"sansdfir_plaso_log2timeline_supertimeline_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_plaso_log2timeline_supertimeline_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["슈퍼타임라인은 서로 다른 포렌식 아티팩트의 상관관계를 한 화면에서 직관적으로 파악하게 해줍니다.", "식별자 `sansdfir_plaso_log2timeline_supertimeline_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Supertimelines correlate cross-artifact event streams on a synchronized timeline.", "Extract first 20 hex chars of SHA256(\"sansdfir_plaso_log2timeline_supertimeline_v1\")."]
    }
  },

  // Tier 3 (8)
  {
    id: "t3_sansdfir_rekall_driver_irp_hook_detection",
    tier: 3, cat: "irp", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Rekall 프레임워크 기반 커널 드라이버 MajorFunction IRP 후킹 및 루트킷 분석", en: "Kernel Driver MajorFunction IRP Hooking & Rootkit Analysis via Rekall" },
    prompt: {
      ko: "윈도우 I/O 요청 패킷(IRP) 핸들러 테이블을 순회하여 합법적 커널 드라이버 모듈 범위를 벗어난 언도큐먼트 메모리 주소로 분기하는 악성 후킹을 탐지하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_rekall_driver_irp_hook_detection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_rekall_driver_irp_hook_detection_v1\") 앞 20자리}`",
      en: "Analyze kernel IRP MajorFunction table traversal exposing malicious pointer redirects outside registered driver module boundaries.\nCompute first 20 hex chars of SHA256(\"sansdfir_rekall_driver_irp_hook_detection_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_rekall_driver_irp_hook_detection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["IRP_MJ_CREATE, IRP_MJ_READ 등의 함수 포인터가 로드된 ntoskrnl이나 공식 드라이버 외부에 있으면 루트킷입니다.", "식별자 `sansdfir_rekall_driver_irp_hook_detection_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["IRP handler addresses pointing outside legitimate driver modules reveal rootkit hooks.", "Extract first 20 hex chars of SHA256(\"sansdfir_rekall_driver_irp_hook_detection_v1\")."]
    }
  },
  {
    id: "t3_sansdfir_lsass_minidump_ssp_credentials",
    tier: 3, cat: "lsass", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "lsass.exe 메모리 덤프 분석과 보안 지원 공급자(SSP) WDigest/Kerberos 크리덴셜 탈취 추적", en: "lsass.exe Memory Dump Forensics & WDigest/Kerberos Credential Extraction" },
    prompt: {
      ko: "미미카츠 또는 comsvcs.dll로 덤프된 lsass.dmp 파일에서 WDigest 평문 패스워드 및 Kerberos TGT/TGS 티켓 암호키가 추출된 흔적을 추적하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_lsass_minidump_ssp_credentials_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_lsass_minidump_ssp_credentials_v1\") 앞 20자리}`",
      en: "Examine lsass.exe process minidump forensics investigating WDigest and Kerberos credential access attempts.\nCompute first 20 hex chars of SHA256(\"sansdfir_lsass_minidump_ssp_credentials_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_lsass_minidump_ssp_credentials_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LSA PPL(RunAsPPL) 보호가 비활성화된 시스템에서는 핸들 복제를 통한 lsass 덤프가 성립합니다.", "식별자 `sansdfir_lsass_minidump_ssp_credentials_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Unprotected LSASS processes permit memory minidumps via standard MiniDumpWriteDump APIs.", "Extract first 20 hex chars of SHA256(\"sansdfir_lsass_minidump_ssp_credentials_v1\")."]
    }
  },
  {
    id: "t3_sansdfir_anti_forensics_event_log_clearing",
    tier: 3, cat: "evtx", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Security Event ID 1102(감사 로그 삭제) 및 Event ID 104 시스템 이벤트 추적", en: "Security Event ID 1102 (Log Cleared) & Event ID 104 Anti-Forensics Triage" },
    prompt: {
      ko: "공격자가 wevtutil 명령어로 이벤트 로그를 삭제할 때 남는 Security EID 1102 및 System EID 104 레코드에서 수행 주체 계정과 세션 로그온 ID를 식별하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_anti_forensics_event_log_clearing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_anti_forensics_event_log_clearing_v1\") 앞 20자리}`",
      en: "Analyze Windows Event Log anti-forensics tracking Security EID 1102 and System EID 104 generated upon log clearing.\nCompute first 20 hex chars of SHA256(\"sansdfir_anti_forensics_event_log_clearing_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_anti_forensics_event_log_clearing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["이벤트 로그가 지워지더라도 로그 삭제 행위 자체는 지울 수 없는 단독 감사 이벤트로 기록됩니다.", "식별자 `sansdfir_anti_forensics_event_log_clearing_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The log clearing operation itself generates an immutable audit record.", "Extract first 20 hex chars of SHA256(\"sansdfir_anti_forensics_event_log_clearing_v1\")."]
    }
  },
  {
    id: "t3_sansdfir_ntfs_slack_space_carving",
    tier: 3, cat: "slack", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "클러스터 슬랙 공간 및 VSS 섀도 복사본에서의 삭제된 악성 쉘코드 바이너리 카빙", en: "NTFS Cluster Slack Space & VSS Volume Shadow Copy Shellcode Carving" },
    prompt: {
      ko: "파일 끝(EOF)과 클러스터 경계 사이의 슬랙 공간(RAM/File Slack) 및 VSS 스냅샷 차분 블록에서 덮어쓰여지지 않은 쉘코드 잔존 바이트를 카빙하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_ntfs_slack_space_carving_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_ntfs_slack_space_carving_v1\") 앞 20자리}`",
      en: "Examine carving methodologies extracting residual unallocated bytes from cluster slack and VSS snapshot differentials.\nCompute first 20 hex chars of SHA256(\"sansdfir_ntfs_slack_space_carving_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_ntfs_slack_space_carving_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["슬랙 공간은 디스크 할당 단위의 여백으로, 이전 삭제 파일의 잔재가 고스란히 남아있습니다.", "식별자 `sansdfir_ntfs_slack_space_carving_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Slack spaces harbor unpadded fragments of previously stored file contents.", "Extract first 20 hex chars of SHA256(\"sansdfir_ntfs_slack_space_carving_v1\")."]
    }
  },
  {
    id: "t3_sansdfir_for572_covert_icmp_tunnel_exfil",
    tier: 3, cat: "icmp", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "SANS FOR572 ICMP 페이로드 크기 및 엔트로피 분석을 통한 데이터 유출 채널 적발", en: "SANS FOR572 ICMP Tunneling & High-Entropy Payload Exfiltration Triage" },
    prompt: {
      ko: "정상 Echo Request의 기본 32/64바이트 패턴을 초과하여 대용량 암호화 데이터가 포함된 ICMP 터널링(Iptunnel/Hans) 세션을 tshark 바이트 분석으로 식별하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_for572_covert_icmp_tunnel_exfil_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_for572_covert_icmp_tunnel_exfil_v1\") 앞 20자리}`",
      en: "Analyze covert ICMP tunneling detection evaluating oversized echo request payloads and byte entropy distributions.\nCompute first 20 hex chars of SHA256(\"sansdfir_for572_covert_icmp_tunnel_exfil_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_for572_covert_icmp_tunnel_exfil_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["정상 ping 페이로드는 알파벳 순차 반복 패턴을 보이나 유출 터널은 높은 샤논 엔트로피를 갖습니다.", "식별자 `sansdfir_for572_covert_icmp_tunnel_exfil_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Standard ICMP echo requests carry predictable ASCII padding rather than high-entropy ciphertext.", "Extract first 20 hex chars of SHA256(\"sansdfir_for572_covert_icmp_tunnel_exfil_v1\")."]
    }
  },
  {
    id: "t3_sansdfir_wmi_repository_persistence",
    tier: 3, cat: "wmi", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "OBJECTS.DATA WMI 리포지토리 파싱 및 __EventFilter/__EventConsumer 영속성 분석", en: "OBJECTS.DATA WMI Repository Forensics on Event Consumer Persistence" },
    prompt: {
      ko: "WMI 리포지토리 파일에서 공격자가 영속성(Persistence) 유지를 위해 등록한 __EventFilter, CommandLineEventConsumer, FilterToConsumerBinding 인스턴스를 추출하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_wmi_repository_persistence_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_wmi_repository_persistence_v1\") 앞 20자리}`",
      en: "Examine WMI OBJECTS.DATA carving parsing __EventFilter and CommandLineEventConsumer persistence mechanisms.\nCompute first 20 hex chars of SHA256(\"sansdfir_wmi_repository_persistence_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_wmi_repository_persistence_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["WMI 이벤트 소비자는 디스크에 실행 파일 없이도 시스템 이벤트 발생 시 임의 스크립트를 백그라운드 구동합니다.", "식별자 `sansdfir_wmi_repository_persistence_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["WMI event subscriptions trigger script execution without dedicated auto-start registry run keys.", "Extract first 20 hex chars of SHA256(\"sansdfir_wmi_repository_persistence_v1\")."]
    }
  },
  {
    id: "t3_sansdfir_shimcache_cache_table_reconstruction",
    tier: 3, cat: "shimcache", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "AppCompatCache 내부 테이블 직렬화 구조 파싱 및 악성 실행 체인 역산", en: "AppCompatCache Table Deserialization & Malicious Execution Chain Triage" },
    prompt: {
      ko: "Windows 10의 4바이트 매직 시그니처(`0xee0f0dc0` 등)로 구분되는 ShimCache 직렬화 바이너리 블록에서 실행 플래그(0x02)와 인덱스를 역추적하는 분석 기법을 분석합니다.\n지정된 식별자 `sansdfir_shimcache_cache_table_reconstruction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_shimcache_cache_table_reconstruction_v1\") 앞 20자리}`",
      en: "Analyze low-level binary deserialization of Windows 10 AppCompatCache tables reconstructing lateral execution chains.\nCompute first 20 hex chars of SHA256(\"sansdfir_shimcache_cache_table_reconstruction_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_shimcache_cache_table_reconstruction_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ShimCache 테이블의 실행 플래그 유무는 바이너리가 단순 디렉터리 스캔인지 실제 실행되었는지를 구분합니다.", "식별자 `sansdfir_shimcache_cache_table_reconstruction_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Execution flags in ShimCache tables differentiate directory browsing from process launching.", "Extract first 20 hex chars of SHA256(\"sansdfir_shimcache_cache_table_reconstruction_v1\")."]
    }
  },
  {
    id: "t3_sansdfir_soar_automated_host_isolation_rule",
    tier: 3, cat: "soar", track: "sansdfir", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "SIEM/SOAR 플레이북을 통한 C2 비콘 발신 호스트의 실시간 네트워크 격리 API 연동", en: "SOAR Playbook Automation for Real-Time Infected Host Network Containment" },
    prompt: {
      ko: "EDR 텔레메트리와 SIEM 상관분석 룰이 침해 지표(IOC)를 감지했을 때, REST API를 통해 엔드포인트 방화벽을 격리 상태로 전환하는 SOAR 플레이북 설계를 분석합니다.\n지정된 식별자 `sansdfir_soar_automated_host_isolation_rule_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_soar_automated_host_isolation_rule_v1\") 앞 20자리}`",
      en: "Examine SOAR incident response playbooks triggering immediate host isolation via EDR agent containment APIs.\nCompute first 20 hex chars of SHA256(\"sansdfir_soar_automated_host_isolation_rule_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_soar_automated_host_isolation_rule_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["격리 플레이북은 오직 DFIR 분석 서버와의 통신만 허용하고 모든 인/아웃바운드 L4 트래픽을 즉시 차단합니다.", "식별자 `sansdfir_soar_automated_host_isolation_rule_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Network containment isolates the endpoint maintaining only management channels to the DFIR console.", "Extract first 20 hex chars of SHA256(\"sansdfir_soar_automated_host_isolation_rule_v1\")."]
    }
  },

  // Tier 4 (5)
  {
    id: "t4_sansdfir_full_memory_vad_reflective_pe_carve",
    tier: 4, cat: "carve", track: "sansdfir", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "커널 VAD 노드 순회, 메모리 보호 우회, 리플렉티브 DLL 수동 카빙 및 IAT 재구성", en: "Kernel VAD Traversal, Reflective DLL Memory Carving & IAT Reconstruction" },
    prompt: {
      ko: "프로세스 메모리 덤프에서 VAD 구조체를 파싱하여 언패킹된 리플렉티브 DLL의 섹션 헤더를 재정렬하고, 손상된 임포트 주소 테이블(IAT)을 디스크 바이너리로 복원하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_full_memory_vad_reflective_pe_carve_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_full_memory_vad_reflective_pe_carve_v1\") 앞 20자리}`",
      en: "Analyze advanced memory carving extracting unmapped reflective DLL sections from VAD pages and rebuilding valid PE headers and IAT tables.\nCompute first 20 hex chars of SHA256(\"sansdfir_full_memory_vad_reflective_pe_carve_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_full_memory_vad_reflective_pe_carve_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["메모리 상의 PE는 VirtualSize 단위로 정렬되어 있으므로 디스크 상의 PointerToRawData 크기로 재정렬해야 합니다.", "식별자 `sansdfir_full_memory_vad_reflective_pe_carve_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["In-memory PE images must be converted from VirtualAddress alignments back to RawData offsets.", "Extract first 20 hex chars of SHA256(\"sansdfir_full_memory_vad_reflective_pe_carve_v1\")."]
    }
  },
  {
    id: "t4_sansdfir_usn_and_mft_timeline_collision_triage",
    tier: 4, cat: "collision", track: "sansdfir", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "안티포렌식 도구에 의한 타임스탬프 위조와 USN 저널 시퀀스 번호 충돌 정밀 검증", en: "Anti-Forensics Timestomp Forgery & USN Journal Sequence Collision Triage" },
    prompt: {
      ko: "공격자가 파일 생성 시각을 3년 전으로 위조했으나, USN 저널의 64비트 단조 증가 USN 시퀀스 번호와 $LogFile LSN이 현재 시점을 가리킬 때 발생하는 시간 모순을 증명하는 기법을 분석합니다.\n지정된 식별자 `sansdfir_usn_and_mft_timeline_collision_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_usn_and_mft_timeline_collision_triage_v1\") 앞 20자리}`",
      en: "Examine collision triage comparing forged file creation timestamps against strictly monotonic 64-bit USN and LogFile sequence numbers.\nCompute first 20 hex chars of SHA256(\"sansdfir_usn_and_mft_timeline_collision_triage_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_usn_and_mft_timeline_collision_triage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["타임스탬프는 위조할 수 있지만 커널 트랜잭션 시퀀스 번호(USN)의 선후 관계는 역전될 수 없습니다.", "식별자 `sansdfir_usn_and_mft_timeline_collision_triage_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Adversaries can tamper with timestamp fields but cannot reverse monotonic transaction sequence numbers.", "Extract first 20 hex chars of SHA256(\"sansdfir_usn_and_mft_timeline_collision_triage_v1\")."]
    }
  },
  {
    id: "t4_sansdfir_kernel_pool_tag_scanner_rootkit",
    tier: 4, cat: "pooltag", track: "sansdfir", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "EPROCESS 비동기 풀 태그(Proc)와 드라이버 오브젝트 교차 검증을 통한 DKOM 은닉 무력화", en: "Kernel Pool Tag (Proc) & Driver Object Cross-Validation Defeating DKOM Stealth" },
    prompt: {
      ko: "DKOM으로 은닉된 스레드/프로세스를 적발하기 위해 커널 풀 헤더의 'Proc' 태그, ETHREAD KTHREAD 구조체, 핸들 테이블(CID)을 교차 검증하여 루트킷의 존재를 입증하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_kernel_pool_tag_scanner_rootkit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_kernel_pool_tag_scanner_rootkit_v1\") 앞 20자리}`",
      en: "Analyze multi-tier kernel structure cross-validation combining 'Proc' pool tags, ETHREAD structures, and CID tables to unmask DKOM rootkits.\nCompute first 20 hex chars of SHA256(\"sansdfir_kernel_pool_tag_scanner_rootkit_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_kernel_pool_tag_scanner_rootkit_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["프로세스 리스트가 언링크되어도 CPU 스케줄러가 스레드를 실행하려면 ETHREAD 객체는 유효해야 합니다.", "식별자 `sansdfir_kernel_pool_tag_scanner_rootkit_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Even when unlinked from EPROCESS lists, thread dispatching necessitates intact ETHREAD pointers.", "Extract first 20 hex chars of SHA256(\"sansdfir_kernel_pool_tag_scanner_rootkit_v1\")."]
    }
  },
  {
    id: "t4_sansdfir_enterprise_supertimeline_rca_pipeline",
    tier: 4, cat: "rca", track: "sansdfir", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "10만 건 이상의 아티팩트 이벤트 타임라인에서 다단계 APT 공격의 최초 침투(Root Cause) 자동 판별", en: "Automated Root Cause Analysis (RCA) Pipeline across Massive Supertimeline Data" },
    prompt: {
      ko: "엔터프라이즈 환경의 대규모 Plaso 타임라인 데이터셋에서 이상 탐지 알고리즘과 인과 그래프를 구성하여 최초 피싱 메일 수신부터 권한 상승까지의 체인을 역산하는 원리를 분석합니다.\n지정된 식별자 `sansdfir_enterprise_supertimeline_rca_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_enterprise_supertimeline_rca_pipeline_v1\") 앞 20자리}`",
      en: "Examine automated Root Cause Analysis algorithms building causal provenance graphs across massive enterprise supertimeline event stores.\nCompute first 20 hex chars of SHA256(\"sansdfir_enterprise_supertimeline_rca_pipeline_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_enterprise_supertimeline_rca_pipeline_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["프로세스 생성(EID 4688), 네트워크 접속, $MFT 생성 타임스탬프를 엣지로 연결하여 공격 전파 트리를 완성합니다.", "식별자 `sansdfir_enterprise_supertimeline_rca_pipeline_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Provenance graphs connect process spawn parentage with network telemetry and filesystem metadata.", "Extract first 20 hex chars of SHA256(\"sansdfir_enterprise_supertimeline_rca_pipeline_v1\")."]
    }
  },
  {
    id: "t4_sansdfir_capstone_full_spectrum_dfir_investigation",
    tier: 4, cat: "capstone", track: "sansdfir", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "피싱 문서 유입부터 메모리 인젝션 및 C2 유출 격리에 이르는 전 과정 종합 DFIR 포렌식 조사", en: "Capstone: Full-Spectrum SANS FOR508 & FOR572 Enterprise Incident Response Investigation" },
    prompt: {
      ko: "피싱 악성 매크로 실행(Prefetch/Amcache), $MFT Data Run 파일 카빙, Volatility 3 VAD 인젝션 트리아지, tshark C2 세션 분석 및 SOAR 호스트 격리를 총망라하는 캡스톤 DFIR 조사를 완수합니다.\n지정된 식별자 `sansdfir_capstone_full_spectrum_dfir_investigation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"sansdfir_capstone_full_spectrum_dfir_investigation_v1\") 앞 20자리}`",
      en: "Complete the capstone full-spectrum SANS FOR508 & FOR572 investigation correlating execution artifacts, memory injection, packet carving, and SOAR containment.\nCompute first 20 hex chars of SHA256(\"sansdfir_capstone_full_spectrum_dfir_investigation_v1\").\n\nFormat: `FLAG{SHA256(\"sansdfir_capstone_full_spectrum_dfir_investigation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SANS DFIR 핵심 철학: 모든 공격자는 발자국을 남기며, 메모리와 파일시스템, 네트워크 아티팩트의 교차 검증으로 사건 전모를 규명합니다.", "식별자 `sansdfir_capstone_full_spectrum_dfir_investigation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["SANS DFIR principle: Multi-tier cross-verification across memory, disk, and network triangulates truth.", "Extract first 20 hex chars of SHA256(\"sansdfir_capstone_full_spectrum_dfir_investigation_v1\")."]
    }
  }
];

// Add computed hash
challengesDef.forEach(c => {
  c.hash = computeHash(c.id);
});

console.log(`Generated ${challengesDef.length} challenges for sansdfir track.`);

// Write out JSON
fs.writeFileSync(path.join(__dirname, 'track62_challenges.json'), JSON.stringify(challengesDef, null, 2), 'utf8');
console.log('Saved to tools/track62_challenges.json');
