#!/usr/bin/env python3
"""
Generates the 44th Wargame Track: 'ghidra' (Ghidra Reverse Engineering & Deobfuscation - 35 Challenges)
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
    "id": "ghidra",
    "icon": "🔬",
    "ko": "Ghidra 역공학·난독화 해제",
    "en": "Ghidra Reverse Engineering & Deobfuscation",
    "desc_ko": "Ghidra Sleigh/P-Code 중간 표현·Headless 자동 분석·Control Flow Flattening(CFF) 상태 머신 해체·불투명 술어 제거·안티 탬퍼 체크섬 우회 및 인라인 패칭.",
    "desc_en": "Ghidra Sleigh/P-Code IR, Headless automated analysis, Control Flow Flattening (CFF) state machine deflattening, opaque predicate removal, self-integrity bypass, and binary patching."
}

RAW_CHALLENGES = [
    # Tier 0 (입문: 7 challenges, points 20~35)
    (0, "t0_ghidra_pcode_concept", 25,
     "Ghidra P-Code 중간 언어 기본 아키텍처",
     "Ghidra P-Code Intermediate Representation Architecture",
     "Ghidra 디컴파일러의 핵심인 약 40개 가상 마이크로 오퍼레이션(P-Code IR) 정규화 아키텍처를 분석합니다.\n지정된 식별자 `ghidra_pcode_concept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_pcode_concept_v1\") 앞 20자리}`",
     "Analyze Ghidra decompiler core normalizing machine instructions into ~40 P-Code micro-operations.\nCompute the first 20 hex characters of SHA256(\"ghidra_pcode_concept_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_pcode_concept_v1\") first 20 hex}`",
     ["Ghidra P-Code 연산자 명세(COPY, LOAD, STORE, INT_ADD, BRANCH)를 학습하세요.", "식별자 `ghidra_pcode_concept_v1`의 SHA-256 해시 앞 20자리를 추출하세요."],
     ["Review Ghidra P-Code micro-operations specifications.", "Compute first 20 hex chars of SHA256(\"ghidra_pcode_concept_v1\")."]),

    (0, "t0_ghidra_sleigh_spec", 25,
     "Sleigh 프로세서 명세 언어와 디스어셈블러",
     "Sleigh Processor Specification Language & Disassembly",
     "CPU 아키텍처별 명령어 바이트 시퀀스를 P-Code로 변환하는 Ghidra Sleigh 명세 언어 구조를 분석합니다.\n지정된 식별자 `ghidra_sleigh_spec_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_sleigh_spec_v1\") 앞 20자리}`",
     "Analyze Ghidra Sleigh language defining instruction semantics and translating bytes to P-Code.\nCompute the first 20 hex characters of SHA256(\"ghidra_sleigh_spec_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_sleigh_spec_v1\") first 20 hex}`",
     ["Sleigh .slaspec 및 .sinc 파일 구조를 확인하세요.", "식별자 `ghidra_sleigh_spec_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine Sleigh specification syntax.", "Extract the first 20 hex characters of SHA256(\"ghidra_sleigh_spec_v1\")."]),

    (0, "t0_ghidra_headless_cli", 30,
     "Ghidra Headless CLI 배치 분석 자동화",
     "Ghidra Headless CLI Batch Analysis Automation",
     "GUI 없이 수백 개의 바이너리를 일괄 역공학 분석하는 analyzeHeadless CLI 파라미터 구조를 분석합니다.\n지정된 식별자 `ghidra_headless_cli_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_headless_cli_v1\") 앞 20자리}`",
     "Inspect analyzeHeadless CLI utility automating batch binary reverse engineering without GUI.\nCompute the first 20 hex characters of SHA256(\"ghidra_headless_cli_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_headless_cli_v1\") first 20 hex}`",
     ["analyzeHeadless의 -import, -postScript, -overwrite 옵션을 학습하세요.", "식별자 `ghidra_headless_cli_v1`의 해시 앞 20자리를 제출하세요."],
     ["Understand analyzeHeadless script execution flags.", "Submit first 20 hex of SHA256(\"ghidra_headless_cli_v1\")."]),

    (0, "t0_ghidra_function_manager", 30,
     "FlatProgramAPI 및 FunctionManager 함수 열거",
     "FlatProgramAPI & FunctionManager Enumeration",
     "Ghidra Jython/Java API의 FlatProgramAPI와 FunctionManager를 활용한 전체 함수 엔트리포인트 열거를 실습합니다.\n지정된 식별자 `ghidra_function_manager_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_function_manager_v1\") 앞 20자리}`",
     "Practice enumerating all function entry points using FlatProgramAPI and FunctionManager.\nCompute the first 20 hex characters of SHA256(\"ghidra_function_manager_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_function_manager_v1\") first 20 hex}`",
     ["currentProgram.getFunctionManager().getFunctions(True) API를 확인하세요.", "식별자 `ghidra_function_manager_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review getFunctionManager API methods.", "Extract the first 20 hex characters of SHA256(\"ghidra_function_manager_v1\")."]),

    (0, "t0_ghidra_xref_tracing", 30,
     "문자열 상수 및 전역 참조(XREF) 분석",
     "String Constants & Cross-Reference (XREF) Tracing",
     "바이너리 내 민감 문자열(라이선스, C2, 암호키)과 이를 참조하는 함수 XREF 그래프를 추적합니다.\n지정된 식별자 `ghidra_xref_tracing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_xref_tracing_v1\") 앞 20자리}`",
     "Trace sensitive strings (license keys, C2 domains) and their caller function cross-reference graphs.\nCompute the first 20 hex characters of SHA256(\"ghidra_xref_tracing_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_xref_tracing_v1\") first 20 hex}`",
     ["getReferencesTo(addr) 메소드를 통한 호출점 역추적을 학습하세요.", "식별자 `ghidra_xref_tracing_v1`의 해시 앞 20자리를 제출하세요."],
     ["Use getReferencesTo for reference graph navigation.", "Extract first 20 hex chars of SHA256(\"ghidra_xref_tracing_v1\")."]),

    (0, "t0_ghidra_data_types", 35,
     "구조체 정의 및 디컴파일러 가독성 향상",
     "Structure Definitions & Decompiler Readability",
     "Ghidra DataTypeManager를 통해 C 구조체 필드를 정의하고 포인터 오프셋 가독성을 개선하는 기법을 분석합니다.\n지정된 식별자 `ghidra_data_types_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_data_types_v1\") 앞 20자리}`",
     "Apply DataTypeManager struct definitions to resolve raw pointer offsets into named struct fields.\nCompute the first 20 hex characters of SHA256(\"ghidra_data_types_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_data_types_v1\") first 20 hex}`",
     ["StructureDataType 생성 및 add(DataType, length, name) 메소드를 학습하세요.", "식별자 `ghidra_data_types_v1`의 해시 앞 20자리를 제출하세요."],
     ["Learn StructureDataType configuration in Ghidra.", "Submit first 20 hex of SHA256(\"ghidra_data_types_v1\")."]),

    (0, "t0_ghidra_entropy_packing", 35,
     "바이너리 섹션별 Shannon 엔트로피 분석",
     "Binary Section Shannon Entropy Analysis",
     "실행 파일 섹션(.text, .rdata, .data)의 Shannon 엔트로피(6.5+)를 측정하여 패킹 및 암호화 여부를 판별합니다.\n지정된 식별자 `ghidra_entropy_packing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_entropy_packing_v1\") 앞 20자리}`",
     "Measure section Shannon entropy (6.5+) to identify packed and encrypted binary payloads.\nCompute the first 20 hex characters of SHA256(\"ghidra_entropy_packing_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_entropy_packing_v1\") first 20 hex}`",
     ["엔트로피 7.0 이상은 고밀도 압축 또는 암호화된 페이로드를 의미합니다.", "식별자 `ghidra_entropy_packing_v1`의 해시 앞 20자리를 추출하세요."],
     ["Entropy above 7.0 indicates compression or encryption.", "Extract first 20 hex chars of SHA256(\"ghidra_entropy_packing_v1\")."]),

    # Tier 1 (기초: 7 challenges, points 40~65)
    (1, "t1_ghidra_prologue_scanning", 45,
     "x86_64 함수 프롤로그 시그니처 매칭",
     "x86_64 Function Prologue Signature Matching",
     "스트립트 바이너리의 표준 함수 프롤로그 바이트(`55 48 89 E5` - push rbp; mov rbp, rsp)를 스캔하여 미식별 함수를 정의합니다.\n지정된 식별자 `ghidra_prologue_scanning_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_prologue_scanning_v1\") 앞 20자리}`",
     "Scan standard function prologue bytes (`55 48 89 E5`) to identify uncataloged function entry points.\nCompute the first 20 hex characters of SHA256(\"ghidra_prologue_scanning_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_prologue_scanning_v1\") first 20 hex}`",
     ["findBytes API로 .text 섹션 내 55 48 89 E5 바이트를 탐색하세요.", "식별자 `ghidra_prologue_scanning_v1`의 해시 앞 20자리를 제출하세요."],
     ["Use findBytes to locate function prologues.", "Submit first 20 hex of SHA256(\"ghidra_prologue_scanning_v1\")."]),

    (1, "t1_ghidra_calling_conventions", 45,
     "System V AMD64 ABI vs MS x64 호출 규약 분석",
     "System V AMD64 ABI vs MS x64 Calling Convention",
     "레지스터 인자 전달 순서(System V: RDI, RSI, RDX, RCX, R8, R9 vs Windows: RCX, RDX, R8, R9)를 디컴파일러에 지정합니다.\n지정된 식별자 `ghidra_calling_conventions_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_calling_conventions_v1\") 앞 20자리}`",
     "Configure decompiler calling conventions to match System V AMD64 vs Microsoft x64 parameter registers.\nCompute the first 20 hex characters of SHA256(\"ghidra_calling_conventions_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_calling_conventions_v1\") first 20 hex}`",
     ["function.setCallingConvention('__fastcall' 또는 '__stdcall') 메소드를 학습하세요.", "식별자 `ghidra_calling_conventions_v1`의 해시 앞 20자리를 추출하세요."],
     ["Set accurate function calling convention models.", "Extract first 20 hex chars of SHA256(\"ghidra_calling_conventions_v1\")."]),

    (1, "t1_ghidra_decompiler_ast", 50,
     "Ghidra 디컴파일러 ClangTokenGroup AST 구조",
     "Ghidra Decompiler ClangTokenGroup AST Structure",
     "디컴파일러의 C 언어 출력 트리를 구성하는 ClangTokenGroup 및 ClangSyntaxToken 계층 구조를 분석합니다.\n지정된 식별자 `ghidra_decompiler_ast_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_decompiler_ast_v1\") 앞 20자리}`",
     "Inspect the ClangTokenGroup and ClangSyntaxToken hierarchical AST produced by the Ghidra decompiler.\nCompute the first 20 hex characters of SHA256(\"ghidra_decompiler_ast_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_decompiler_ast_v1\") first 20 hex}`",
     ["DecompInterface를 통해 생성된 C AST 토큰을 순회하세요.", "식별자 `ghidra_decompiler_ast_v1`의 해시 앞 20자리를 제출하세요."],
     ["Traverse decompiler AST tokens via DecompInterface.", "Submit first 20 hex of SHA256(\"ghidra_decompiler_ast_v1\")."]),

    (1, "t1_ghidra_cfg_basic_blocks", 55,
     "기본 블록 분할 및 제어 흐름 그래프(CFG)",
     "Basic Block Partitioning & Control Flow Graph (CFG)",
     "조건부 분기(Jcc) 및 무조건 점프(JMP)를 기준으로 단일 진입·단일 종출 기본 블록(Basic Block)을 모델링합니다.\n지정된 식별자 `ghidra_cfg_basic_blocks_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_cfg_basic_blocks_v1\") 앞 20자리}`",
     "Model single-entry, single-exit basic blocks and directed graph edges demarcated by Jcc and JMP instructions.\nCompute the first 20 hex characters of SHA256(\"ghidra_cfg_basic_blocks_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_cfg_basic_blocks_v1\") first 20 hex}`",
     ["BasicBlockModel API로 블록의 시작/종료 주소를 쿼리하세요.", "식별자 `ghidra_cfg_basic_blocks_v1`의 해시 앞 20자리를 추출하세요."],
     ["Use BasicBlockModel API to query block bounds.", "Extract first 20 hex chars of SHA256(\"ghidra_cfg_basic_blocks_v1\")."]),

    (1, "t1_ghidra_stripped_symbol_recovery", 55,
     "FID(Function ID) 데이터베이스 기반 스트립트 심볼 복원",
     "Function ID (FID) Database Stripped Symbol Recovery",
     "Ghidra FID(Function ID) 데이터베이스 및 패턴 해시를 사용하여 libc/CRT 정적 링크 심볼을 자동 복원합니다.\n지정된 식별자 `ghidra_stripped_symbol_recovery_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_stripped_symbol_recovery_v1\") 앞 20자리}`",
     "Utilize Ghidra Function ID (FID) databases to match and label statically-linked libc/CRT library symbols.\nCompute the first 20 hex characters of SHA256(\"ghidra_stripped_symbol_recovery_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_stripped_symbol_recovery_v1\") first 20 hex}`",
     ["FidService를 활성화하여 표준 라이브러리 함수 시그니처를 복원하세요.", "식별자 `ghidra_stripped_symbol_recovery_v1`의 해시 앞 20자리를 제출하세요."],
     ["Enable FidService for standard library symbol mapping.", "Submit first 20 hex of SHA256(\"ghidra_stripped_symbol_recovery_v1\")."]),

    (1, "t1_ghidra_opaque_predicate_math", 60,
     "수학적 불투명 술어(Opaque Predicate) 탐지",
     "Mathematical Opaque Predicate Detection",
     "항상 참으로 평가되는 수학적 항등식 `(y * (y + 1)) % 2 == 0` 불투명 술어 패턴을 탐지합니다.\n지정된 식별자 `ghidra_opaque_predicate_math_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_opaque_predicate_math_v1\") 앞 20자리}`",
     "Detect mathematical opaque predicates such as `(y * (y + 1)) % 2 == 0` invariant to all integer inputs.\nCompute the first 20 hex characters of SHA256(\"ghidra_opaque_predicate_math_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_opaque_predicate_math_v1\") first 20 hex}`",
     ["연속된 두 정수의 곱은 항상 짝수임을 이용한 더미 분기문입니다.", "식별자 `ghidra_opaque_predicate_math_v1`의 해시 앞 20자리를 추출하세요."],
     ["Opaque predicates inject dead branch complexity.", "Extract first 20 hex chars of SHA256(\"ghidra_opaque_predicate_math_v1\")."]),

    (1, "t1_ghidra_import_table_iat", 65,
     "ELF GOT/PLT 및 PE IAT 임포트 함수 추적",
     "ELF GOT/PLT & PE IAT Import Resolution",
     "동적 링커가 해결하는 라이브러리 임포트 테이블(GOT/PLT 및 IAT)의 악의적 후킹 및 간접 호출(Call [rip+offset])을 분석합니다.\n지정된 식별자 `ghidra_import_table_iat_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_import_table_iat_v1\") 앞 20자리}`",
     "Analyze indirect calls (CALL [rip+offset]) targeting the Global Offset Table (GOT) and Import Address Table (IAT).\nCompute the first 20 hex characters of SHA256(\"ghidra_import_table_iat_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_import_table_iat_v1\") first 20 hex}`",
     ["_GLOBAL_OFFSET_TABLE_ 섹션 엔트리와 점프 슬롯을 점검하세요.", "식별자 `ghidra_import_table_iat_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect GOT/PLT trampoline stub entries.", "Submit first 20 hex of SHA256(\"ghidra_import_table_iat_v1\")."]),

    # Tier 2 (중급: 7 challenges, points 75~120)
    (2, "t2_ghidra_cff_state_variable", 80,
     "CFF 상태 변수(State Variable) 레지스터 추적",
     "CFF State Variable Register Tracing",
     "OLLVM 제어 흐름 평탄화에서 중앙 디스패처로 전달되는 가상 상태 변수(예: EAX / [RBP-0x4])의 쓰기 지점을 추적합니다.\n지정된 식별자 `ghidra_cff_state_variable_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_cff_state_variable_v1\") 앞 20자리}`",
     "Trace write instructions to the virtual state variable register (e.g. EAX or [RBP-0x4]) governing CFF dispatch.\nCompute the first 20 hex characters of SHA256(\"ghidra_cff_state_variable_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_cff_state_variable_v1\") first 20 hex}`",
     ["각 기본 블록의 마지막에 나타나는 MOV [state], imm32 명령어를 탐색하세요.", "식별자 `ghidra_cff_state_variable_v1`의 해시 앞 20자리를 추출하세요."],
     ["Locate MOV state_var, imm instructions terminating basic blocks.", "Extract first 20 hex chars of SHA256(\"ghidra_cff_state_variable_v1\")."]),

    (2, "t2_ghidra_cff_dispatcher_switch", 85,
     "CFF 중앙 디스패처 switch-case 점프 테이블 분석",
     "CFF Central Dispatcher Switch-Case Jump Table",
     "모든 기본 블록의 반환 흐름이 집결하는 중앙 디스패처 루프 및 switch(state) 점프 테이블 가상 주소를 식별합니다.\n지정된 식별자 `ghidra_cff_dispatcher_switch_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_cff_dispatcher_switch_v1\") 앞 20자리}`",
     "Identify the central dispatcher switch(state) jump table and loop header collecting all flattened block returns.\nCompute the first 20 hex characters of SHA256(\"ghidra_cff_dispatcher_switch_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_cff_dispatcher_switch_v1\") first 20 hex}`",
     ["디스패처 루프 헤더의 CMP state, max_case 및 JMP [table + state*8] 구조를 확인하세요.", "식별자 `ghidra_cff_dispatcher_switch_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect jump table indexing calculations in dispatcher.", "Submit first 20 hex of SHA256(\"ghidra_cff_dispatcher_switch_v1\")."]),

    (2, "t2_ghidra_cff_state_transitions", 90,
     "CFF 상태 전이 시퀀스 [10, 40, 25, 90] 역산",
     "CFF State Transition Sequence Reconstruction",
     "평탄화된 제어 흐름 디스패처의 상태 전이 순서 `[10 -> 40 -> 25 -> 90]`를 역산하여 선형 실행 경로를 복원합니다.\n지정된 식별자 `ghidra_cff_state_transitions_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_cff_state_transitions_v1\") 앞 20자리}`",
     "Reconstruct the linear execution state transition chain `[10 -> 40 -> 25 -> 90]` through the central dispatcher.\nCompute the first 20 hex characters of SHA256(\"ghidra_cff_state_transitions_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_cff_state_transitions_v1\") first 20 hex}`",
     ["각 케이스 블록의 끝에서 state 변수에 대입되는 상수를 기록하세요.", "식별자 `ghidra_cff_state_transitions_v1`의 해시 앞 20자리를 추출하세요."],
     ["Log constant state assignments across all relevant blocks.", "Extract first 20 hex chars of SHA256(\"ghidra_cff_state_transitions_v1\")."]),

    (2, "t2_ghidra_pcode_nop_sled", 95,
     "P-Code 레벨 불투명 술어 조건부 분기 NOP화",
     "P-Code Level Opaque Predicate CBRANCH to NOP Transformation",
     "Ghidra P-Code 수준에서 불투명 술어에 해당하는 `CBRANCH` 연산자를 무조건 분기(`BRANCH`) 또는 `NOP`로 패치합니다.\n지정된 식별자 `ghidra_pcode_nop_sled_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_pcode_nop_sled_v1\") 앞 20자리}`",
     "Transform P-Code CBRANCH operations evaluated under opaque predicates into unconditional BRANCH or NOP ops.\nCompute the first 20 hex characters of SHA256(\"ghidra_pcode_nop_sled_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_pcode_nop_sled_v1\") first 20 hex}`",
     ["항상 거짓인 도달 불가능 분기 타깃을 제거하세요.", "식별자 `ghidra_pcode_nop_sled_v1`의 해시 앞 20자리를 제출하세요."],
     ["Eliminate unreachable branch targets from CFG.", "Submit first 20 hex of SHA256(\"ghidra_pcode_nop_sled_v1\")."]),

    (2, "t2_ghidra_binary_patch_nop", 100,
     "바이너리 인라인 조건부 점프 90 90 NOP 패치",
     "Binary Inline Conditional Jump 90 90 NOP Patching",
     "가상 주소 `0x00401337`의 조건부 점프 바이트 `74 18` (jz +0x18)을 `90 90` (nop; nop)으로 덮어써 인증 실패 분기를 무력화합니다.\n지정된 식별자 `ghidra_binary_patch_nop_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_binary_patch_nop_v1\") 앞 20자리}`",
     "Overwrite conditional jump bytes `74 18` (jz +0x18) at `0x00401337` with `90 90` (nop nop) to neutralize failure branch.\nCompute the first 20 hex characters of SHA256(\"ghidra_binary_patch_nop_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_binary_patch_nop_v1\") first 20 hex}`",
     ["x86_64 NOP 바이트는 단일 바이트 0x90 입니다.", "식별자 `ghidra_binary_patch_nop_v1`의 해시 앞 20자리를 추출하세요."],
     ["x86_64 NOP instruction byte is 0x90.", "Extract first 20 hex chars of SHA256(\"ghidra_binary_patch_nop_v1\")."]),

    (2, "t2_ghidra_binary_patch_jmp", 105,
     "인라인 점프 eb 18 무조건 분기 강제 패치",
     "Inline Jump eb 18 Unconditional Branch Forcing",
     "조건부 점프 `74 18` (jz)를 무조건 짧은 점프 `eb 18` (jmp short +0x18)로 치환하여 항상 라이선스 성공 루틴으로 리다이렉트합니다.\n지정된 식별자 `ghidra_binary_patch_jmp_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_binary_patch_jmp_v1\") 앞 20자리}`",
     "Substitute conditional `74 18` with unconditional short jump `eb 18` to force execution into valid license routines.\nCompute the first 20 hex characters of SHA256(\"ghidra_binary_patch_jmp_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_binary_patch_jmp_v1\") first 20 hex}`",
     ["0xEB 오프셋은 1바이트 상대 점프(jmp rel8)를 의미합니다.", "식별자 `ghidra_binary_patch_jmp_v1`의 해시 앞 20자리를 제출하세요."],
     ["Opcode 0xEB represents relative short unconditional jump.", "Submit first 20 hex of SHA256(\"ghidra_binary_patch_jmp_v1\")."]),

    (2, "t2_ghidra_self_checksum_algorithm", 110,
     "런타임 .text 자체 무결성 체크섬 루틴 식별",
     "Runtime .text Section Self-Checksum Routine Identification",
     "바이너리 초기화 과정에서 자신의 `.text` 섹션 메모리를 읽어 컴파일 시점 해시와 대조하는 안티 탬퍼 루틴을 식별합니다.\n지정된 식별자 `ghidra_self_checksum_algorithm_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_self_checksum_algorithm_v1\") 앞 20자리}`",
     "Locate the anti-tamper routine calculating CRC32/SHA-256 hashes over its own loaded `.text` memory section.\nCompute the first 20 hex characters of SHA256(\"ghidra_self_checksum_algorithm_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_self_checksum_algorithm_v1\") first 20 hex}`",
     ["verify_text_section_checksum 함수의 호출 지점과 abort 트리거를 추적하세요.", "식별자 `ghidra_self_checksum_algorithm_v1`의 해시 앞 20자리를 추출하세요."],
     ["Trace calls to self-checksum verification routines.", "Extract first 20 hex chars of SHA256(\"ghidra_self_checksum_algorithm_v1\")."]),

    # Tier 3 (고급: 7 challenges, points 150~250)
    (3, "t3_ghidra_symbolic_execution_deflat", 160,
     "기호 실행(Symbolic Execution)을 통한 CFF 상태 전이 해결",
     "Symbolic Execution CFF State Transition Resolution",
     "Triton/Angr 또는 Ghidra 기호 실행 엔진을 결합하여 CFF 디스패처의 복잡한 비트 연산 상태 전이 제약조건(SMT solver)을 해결합니다.\n지정된 식별자 `ghidra_symbolic_execution_deflat_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_symbolic_execution_deflat_v1\") 앞 20자리}`",
     "Employ symbolic execution (SMT solvers) to resolve arithmetic and bitwise constraints governing CFF state transitions.\nCompute the first 20 hex characters of SHA256(\"ghidra_symbolic_execution_deflat_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_symbolic_execution_deflat_v1\") first 20 hex}`",
     ["Z3 SMT 솔버를 활용하여 state 변수의 다음 값을 기호적으로 역산하세요.", "식별자 `ghidra_symbolic_execution_deflat_v1`의 해시 앞 20자리를 제출하세요."],
     ["Use Z3 SMT solver integration to solve state transitions.", "Submit first 20 hex of SHA256(\"ghidra_symbolic_execution_deflat_v1\")."]),

    (3, "t3_ghidra_pcode_ast_rewriting", 170,
     "Ghidra Low P-Code AST 재작성을 통한 디플래트닝",
     "Ghidra Low P-Code AST Rewriting for Deflattening",
     "디스패처 블록을 우회하여 선행 기본 블록의 출구를 후속 기본 블록의 입구로 직접 연결하도록 P-Code 점프 대상을 재작성합니다.\n지정된 식별자 `ghidra_pcode_ast_rewriting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_pcode_ast_rewriting_v1\") 앞 20자리}`",
     "Rewrite P-Code branch destinations to directly link predecessor blocks to real successors, bypassing dispatcher.\nCompute the first 20 hex characters of SHA256(\"ghidra_pcode_ast_rewriting_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_pcode_ast_rewriting_v1\") first 20 hex}`",
     ["PcodeOp.BRANCH 타깃을 디스패처가 아닌 실제 후속 블록 오프셋으로 수정합니다.", "식별자 `ghidra_pcode_ast_rewriting_v1`의 해시 앞 20자리를 추출하세요."],
     ["Patch PcodeOp branch targets to restore linear control flow.", "Extract first 20 hex chars of SHA256(\"ghidra_pcode_ast_rewriting_v1\")."]),

    (3, "t3_ghidra_bogus_control_flow", 180,
     "가짜 제어 흐름(Bogus Control Flow) 도달 불가 블록 제거",
     "Bogus Control Flow Unreachable Block Elimination",
     "OLLVM Bogus Control Flow 패스가 삽입한 조건부 불투명 술어로 보호되는 데드 코드 및 가짜 블록을 정적 슬라이싱으로 제거합니다.\n지정된 식별자 `ghidra_bogus_control_flow_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_bogus_control_flow_v1\") 앞 20자리}`",
     "Prune unreachable dead code blocks and phantom edges injected by OLLVM Bogus Control Flow passes via static slicing.\nCompute the first 20 hex characters of SHA256(\"ghidra_bogus_control_flow_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_bogus_control_flow_v1\") first 20 hex}`",
     ["정적 프로그램 슬라이싱(Static Slicing)으로 실행되지 않는 더미 블록을 필터링하세요.", "식별자 `ghidra_bogus_control_flow_v1`의 해시 앞 20자리를 제출하세요."],
     ["Filter out phantom blocks via static program slicing.", "Submit first 20 hex of SHA256(\"ghidra_bogus_control_flow_v1\")."]),

    (3, "t3_ghidra_instruction_substitution", 190,
     "명령어 대체(Instruction Substitution) 패턴 정규화",
     "Instruction Substitution Pattern Normalization",
     "기본 연산(예: `a + b`)을 복잡한 비트 동치식(`(a ^ b) + 2 * (a & b)`)으로 변환한 난독화 패턴을 원본 명령어로 정규화합니다.\n지정된 식별자 `ghidra_instruction_substitution_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_instruction_substitution_v1\") 앞 20자리}`",
     "Normalize obfuscated Boolean-arithmetic identities (e.g. `(a ^ b) + 2 * (a & b)`) back into standard arithmetic primitives.\nCompute the first 20 hex characters of SHA256(\"ghidra_instruction_substitution_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_instruction_substitution_v1\") first 20 hex}`",
     ["MBA(Mixed Boolean-Arithmetic) 간소화 룰셋을 적용하여 식을 단순화하세요.", "식별자 `ghidra_instruction_substitution_v1`의 해시 앞 20자리를 추출하세요."],
     ["Apply Mixed Boolean-Arithmetic (MBA) rewriting rules.", "Extract first 20 hex chars of SHA256(\"ghidra_instruction_substitution_v1\")."]),

    (3, "t3_ghidra_anti_tamper_bypass", 200,
     "안티 탬퍼 자체 체크섬 무력화 (Return 1 패치)",
     "Anti-Tamper Checksum Neutralization (Return 1 Patch)",
     "`verify_text_section_checksum` 함수의 에필로그를 `mov eax, 1; ret` (`B8 01 00 00 00 C3`)로 패치하여 무조건 무결성 검증을 통과시킵니다.\n지정된 식별자 `ghidra_anti_tamper_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_anti_tamper_bypass_v1\") 앞 20자리}`",
     "Patch verify_text_section_checksum function epilogue to `mov eax, 1; ret` (`B8 01 00 00 00 C3`) to bypass tamper detection.\nCompute the first 20 hex characters of SHA256(\"ghidra_anti_tamper_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_anti_tamper_bypass_v1\") first 20 hex}`",
     ["함수 시작점에 B8 01 00 00 00 C3 바이트를 기록하여 조기 반환(Early Return) 처리하세요.", "식별자 `ghidra_anti_tamper_bypass_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inject early return returning 1 in integrity checker.", "Submit first 20 hex of SHA256(\"ghidra_anti_tamper_bypass_v1\")."]),

    (3, "t3_ghidra_shadow_memory_redirection", 220,
     "섀도우 메모리(Shadow Memory) 리다이렉션을 통한 체크섬 기만",
     "Shadow Memory Redirection Tamper Deception",
     "체크섬 검증 루틴이 패치된 실제 실행 메모리가 아닌, 원본 바이너리 바이트가 복사된 섀도우 메모리 버퍼를 읽도록 포인터를 리다이렉트합니다.\n지정된 식별자 `ghidra_shadow_memory_redirection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_shadow_memory_redirection_v1\") 앞 20자리}`",
     "Redirect integrity verification pointers to read pristine original bytes from shadow memory buffers rather than patched memory.\nCompute the first 20 hex characters of SHA256(\"ghidra_shadow_memory_redirection_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_shadow_memory_redirection_v1\") first 20 hex}`",
     ["포인터 훅을 통해 패치된 바이트 은닉 및 체크섬 연산 기만을 달성하세요.", "식별자 `ghidra_shadow_memory_redirection_v1`의 해시 앞 20자리를 추출하세요."],
     ["Deceive memory checksum checks via pointer redirection.", "Extract first 20 hex chars of SHA256(\"ghidra_shadow_memory_redirection_v1\")."]),

    (3, "t3_ghidra_vm_interpreter_handler", 240,
     "가상 머신 기반 난독화(VM Obfuscation) 핸들러 식별",
     "Virtual Machine Obfuscation Bytecode Handler Identification",
     "커스텀 바이트코드 가상 머신 인터프리터의 가상 프로그램 카운터(VPC), 가상 레지스터(VRegs) 및 핸들러 디스패치 루프를 분석합니다.\n지정된 식별자 `ghidra_vm_interpreter_handler_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_vm_interpreter_handler_v1\") 앞 20자리}`",
     "Analyze custom bytecode VM interpreters: identify virtual PC (VPC), virtual registers, and opcode dispatch tables.\nCompute the first 20 hex characters of SHA256(\"ghidra_vm_interpreter_handler_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_vm_interpreter_handler_v1\") first 20 hex}`",
     ["가상 옵코드 핸들러 테이블의 간접 호출 패턴(call [handlers + opcode*8])을 역공학하세요.", "식별자 `ghidra_vm_interpreter_handler_v1`의 해시 앞 20자리를 제출하세요."],
     ["Reverse engineer bytecode handler jump arrays.", "Submit first 20 hex of SHA256(\"ghidra_vm_interpreter_handler_v1\")."]),

    # Tier 4 (전문가: 7 challenges, points 300~500)
    (4, "t4_ghidra_automated_deflat_plugin", 350,
     "Ghidra 전용 CFF 디플래트닝 자동화 플러그인 파이프라인",
     "Automated Ghidra CFF Deflattening Extension Pipeline",
     "디스패처 탐지, 기본 블록 기호 추적, P-Code 패칭 및 신규 CFG 재구성을 원클릭으로 수행하는 Ghidra 확장 플러그인을 구축합니다.\n지정된 식별자 `ghidra_automated_deflat_plugin_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_automated_deflat_plugin_v1\") 앞 20자리}`",
     "Build an end-to-end Ghidra Java/Python extension automating dispatcher detection, block tracing, and CFG reconstruction.\nCompute the first 20 hex characters of SHA256(\"ghidra_automated_deflat_plugin_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_automated_deflat_plugin_v1\") first 20 hex}`",
     ["Ghidra Plugin 및 ProgramCorrelator 인터페이스를 활용하세요.", "식별자 `ghidra_automated_deflat_plugin_v1`의 해시 앞 20자리를 추출하세요."],
     ["Implement automated Ghidra ProgramCorrelator pipelines.", "Extract first 20 hex chars of SHA256(\"ghidra_automated_deflat_plugin_v1\")."]),

    (4, "t4_ghidra_control_flow_integrity_cfi", 380,
     "Control Flow Integrity (CFI) 및 Intel CET 간접 분기 방어",
     "Control Flow Integrity (CFI) & Intel CET Branch Defense",
     "Clang Forward-Edge CFI 및 Intel CET IBT(Indirect Branch Tracking - `ENDBR64` 검증) 하드웨어 방어 메커니즘을 분석합니다.\n지정된 식별자 `ghidra_control_flow_integrity_cfi_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_control_flow_integrity_cfi_v1\") 앞 20자리}`",
     "Inspect Clang Forward-Edge CFI and Intel CET Indirect Branch Tracking (IBT) enforcing ENDBR64 at indirect call targets.\nCompute the first 20 hex characters of SHA256(\"ghidra_control_flow_integrity_cfi_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_control_flow_integrity_cfi_v1\") first 20 hex}`",
     ["ENDBR64 누락 시 발생하는 #CP(Control Protection) 예외를 학습하세요.", "식별자 `ghidra_control_flow_integrity_cfi_v1`의 해시 앞 20자리를 제출하세요."],
     ["Examine Control Protection exceptions triggered by invalid targets.", "Submit first 20 hex of SHA256(\"ghidra_control_flow_integrity_cfi_v1\")."]),

    (4, "t4_ghidra_authenticode_signature_bypass", 400,
     "디지털 코드 서명(Authenticode / IMA) 무결성 검증 방어 우회",
     "Digital Code Signing (Authenticode / IMA) Integrity Defense Bypass",
     "바이너리 바이트 패치 시 발생하는 PKCS#7 디지털 서명 검증 실패를 극복하기 위한 커널 로더 서명 검증 패치 기법을 분석합니다.\n지정된 식별자 `ghidra_authenticode_signature_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_authenticode_signature_bypass_v1\") 앞 20자리}`",
     "Analyze kernel-level digital signature validation bypass techniques defeating Authenticode and Linux IMA checks.\nCompute the first 20 hex characters of SHA256(\"ghidra_authenticode_signature_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_authenticode_signature_bypass_v1\") first 20 hex}`",
     ["WIN_CERTIFICATE 구조체 및 ci.dll / g_CiOptions 메모리 플래그를 학습하세요.", "식별자 `ghidra_authenticode_signature_bypass_v1`의 해시 앞 20자리를 추출하세요."],
     ["Understand WIN_CERTIFICATE headers and CI validation flags.", "Extract first 20 hex chars of SHA256(\"ghidra_authenticode_signature_bypass_v1\")."]),

    (4, "t4_ghidra_vmprotect_devirtualization", 420,
     "VMProtect 가상 바이트코드 트레이싱 및 디버추얼라이제이션",
     "VMProtect Bytecode Tracing & Devirtualization",
     "가상 머신 기반 프로텍터(VMProtect)의 난독화된 PUSH/POP 기반 바이트코드 실행 트레이스를 네이티브 x86_64 코드로 복원합니다.\n지정된 식별자 `ghidra_vmprotect_devirtualization_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_vmprotect_devirtualization_v1\") 앞 20자리}`",
     "Reconstruct native x86_64 code from virtualized stack-based bytecode execution traces produced by VMProtect.\nCompute the first 20 hex characters of SHA256(\"ghidra_vmprotect_devirtualization_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_vmprotect_devirtualization_v1\") first 20 hex}`",
     ["가상 스택(VStack)과 네이티브 스택 간의 데이터 흐름 동치성을 역산하세요.", "식별자 `ghidra_vmprotect_devirtualization_v1`의 해시 앞 20자리를 제출하세요."],
     ["Map virtual stack manipulations into native registers.", "Submit first 20 hex of SHA256(\"ghidra_vmprotect_devirtualization_v1\")."]),

    (4, "t4_ghidra_firmware_blob_headless_triage", 450,
     "임베디드 펌웨어 플래시 덤프 자동 파싱 및 암호키 역공학",
     "Embedded Firmware Flash Dump Automated Parsing & Key Recovery",
     "Ghidra Headless를 활용하여 비정형 임베디드 펌웨어 바이너리 블롭에서 부트로더, 커널 심볼, 하드코딩 AES 키를 자동 적출합니다.\n지정된 식별자 `ghidra_firmware_blob_headless_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_firmware_blob_headless_triage_v1\") 앞 20자리}`",
     "Automate raw firmware blob triage, base address calculation, and cryptographic key extraction via Ghidra Headless.\nCompute the first 20 hex characters of SHA256(\"ghidra_firmware_blob_headless_triage_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_firmware_blob_headless_triage_v1\") first 20 hex}`",
     ["메모리 맵 베이스 주소(Base Address) 역산 및 벡터 테이블을 정렬하세요.", "식별자 `ghidra_firmware_blob_headless_triage_v1`의 해시 앞 20자리를 추출하세요."],
     ["Calculate firmware loading base address and IVT vectors.", "Extract first 20 hex chars of SHA256(\"ghidra_firmware_blob_headless_triage_v1\")."]),

    (4, "t4_ghidra_secure_boot_remote_attestation", 480,
     "Secure Boot TPM 2.0 PCR 무결성 측정 및 원격 증명",
     "Secure Boot TPM 2.0 PCR Integrity Measurement & Remote Attestation",
     "하드웨어 신뢰점(Root of Trust) 기반 Secure Boot 체인과 TPM PCR 0/2/4 해시 로그 기반 원격 증명 아키텍처를 분석합니다.\n지정된 식별자 `ghidra_secure_boot_remote_attestation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_secure_boot_remote_attestation_v1\") 앞 20자리}`",
     "Analyze hardware Root-of-Trust Secure Boot chains and TPM PCR 0/2/4 measurement logs for remote attestation.\nCompute the first 20 hex characters of SHA256(\"ghidra_secure_boot_remote_attestation_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_secure_boot_remote_attestation_v1\") first 20 hex}`",
     ["UEFI Authenticated Variables 및 TCG 이벤트 로그를 검증하세요.", "식별자 `ghidra_secure_boot_remote_attestation_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify TCG event logs and TPM quote signatures.", "Submit first 20 hex of SHA256(\"ghidra_secure_boot_remote_attestation_v1\")."]),

    (4, "t4_ghidra_capstone_deobfuscation_audit", 500,
     "엔터프라이즈 바이너리 프로텍션 역공학 및 종합 보안 감사 캡스톤",
     "Enterprise Binary Protection Reversing & Capstone Security Audit",
     "심볼 스트립, CFF 디스패처, 불투명 술어, 안티 디버깅, 자체 체크섬이 복합 적용된 엔터프라이즈 바이너리를 완전 디오브젝션하는 종합 캡스톤입니다.\n지정된 식별자 `ghidra_capstone_deobfuscation_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ghidra_capstone_deobfuscation_audit_v1\") 앞 20자리}`",
     "Comprehensive capstone deobfuscating enterprise protected binaries combining stripped symbols, CFF, opaque predicates, and self-checks.\nCompute the first 20 hex characters of SHA256(\"ghidra_capstone_deobfuscation_audit_v1\").\n\nFormat: `FLAG{SHA256(\"ghidra_capstone_deobfuscation_audit_v1\") first 20 hex}`",
     ["Headless 분석 -> CFF 디플래트닝 -> 체크섬 우회 -> 클린 바이너리 패칭의 전 과정을 종합하세요.", "식별자 `ghidra_capstone_deobfuscation_audit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Synthesize headless analysis, deflattening, and integrity patch.", "Extract first 20 hex chars of SHA256(\"ghidra_capstone_deobfuscation_audit_v1\")."])
]


def build_challenges():
    challenges = []
    ids = []
    for tier, cid, pts, t_ko, t_en, p_ko, p_en, h_ko, h_en in RAW_CHALLENGES:
        # Extract seed from prompt
        m = re.search(r'SHA256\("([^"]+)"\)', p_ko)
        if not m:
            raise ValueError(f"Seed not found in prompt for {cid}")
        seed = m.group(1)
        flag_val = f"FLAG{{{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:20]}}}"
        h = hashlib.sha256(flag_val.encode('utf-8')).hexdigest()

        chal = {
            "id": cid,
            "tier": tier,
            "cat": "ghidra",
            "track": "ghidra",
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
    print("[*] Generating 35 Ghidra track challenges...")
    challenges, ids = build_challenges()
    print(f"  ✓ Built {len(challenges)} challenges.")

    # 1. Update challenges.js
    with open(CHALLENGES_JS, "r", encoding="utf-8") as f:
        content = f.read()

    # Add TRACKS entry
    track_entry = json.dumps(TRACK_INFO, ensure_ascii=False, indent=2)
    # indent by 2 spaces
    indented_track = "\n".join("  " + line for line in track_entry.splitlines()) + ",\n"

    # Find where TRACKS ends: before `const CHALLENGES =`
    pos_tracks_end = content.find("const CHALLENGES =")
    if pos_tracks_end == -1:
        raise ValueError("Could not find `const CHALLENGES =` in challenges.js")
    # find the `];` before pos_tracks_end
    bracket_pos = content.rfind("];", 0, pos_tracks_end)
    if bracket_pos == -1:
        raise ValueError("Could not find closing bracket for TRACKS")

    # Insert indented_track right before `];`
    content = content[:bracket_pos] + "  " + json.dumps(TRACK_INFO, ensure_ascii=False, indent=2).replace("\n", "\n  ") + "\n" + content[bracket_pos:]

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
    print("  ✓ Updated challenges.js with 44th track and 35 challenges.")

    # 2. Update solve-derivable.js
    with open(SOLVE_DERIVABLE_JS, "r", encoding="utf-8") as f:
        sd_content = f.read()

    # Find DROIDPWN_WINCLIENT_IDS array
    marker = '"t4_adcs_capstone_enterprise_pki_audit"'
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

    html = html.replace("0/1505", "0/1540")
    html = html.replace("1505", "1540")
    html = html.replace("43 트랙", "44 트랙")
    html = html.replace("43 tracks", "44 tracks")
    html = html.replace("43 Tracks", "44 Tracks")
    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print("  ✓ Updated index.html HUD counters to 1,540 and 44 tracks.")

    # 4. Update WARGAME_README
    if WARGAME_README.exists():
        with open(WARGAME_README, "r", encoding="utf-8") as f:
            readme = f.read()
        readme = readme.replace("1,505", "1,540").replace("1505", "1540").replace("43", "44")
        with open(WARGAME_README, "w", encoding="utf-8") as f:
            f.write(readme)
        print("  ✓ Updated wargame/README.md.")

    # 5. Update CLI_TEST
    if CLI_TEST.exists():
        with open(CLI_TEST, "r", encoding="utf-8") as f:
            clitest = f.read()
        clitest = clitest.replace("assert len(TRACKS) == 43", "assert len(TRACKS) == 44")
        clitest = clitest.replace("== 43", "== 44")
        clitest = clitest.replace("1505", "1540")
        with open(CLI_TEST, "w", encoding="utf-8") as f:
            f.write(clitest)
        print("  ✓ Updated wargame/tests/test_cli.py assertions.")

    print("[+] All assets updated successfully for 44 tracks and 1,540 challenges!")


if __name__ == "__main__":
    main()
