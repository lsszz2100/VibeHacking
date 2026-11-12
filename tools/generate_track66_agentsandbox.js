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
    id: "t0_agentsandbox_mcp_protocol_architecture",
    tier: 0, cat: "mcp", track: "agentsandbox", points: 25, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Model Context Protocol(MCP) JSON-RPC 아키텍처와 도구 호출 원리",
      en: "Model Context Protocol (MCP) JSON-RPC Architecture & Tool Invocation"
    },
    prompt: {
      ko: "LLM 에이전트와 외부 시스템(파일, 셸, API)을 연결하는 MCP의 JSON-RPC 2.0 프로토콜 규격 및 tools/call 실행 흐름을 분석합니다.\n지정된 식별자 `agentsandbox_mcp_protocol_architecture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_mcp_protocol_architecture_v1\") 앞 20자리}`",
      en: "Examine the MCP JSON-RPC 2.0 protocol specifications and tools/call execution flows connecting LLM agents to external host utilities.\nCompute the first 20 hex characters of SHA256(\"agentsandbox_mcp_protocol_architecture_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_mcp_protocol_architecture_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["MCP는 클라이언트-호스트-서버 3계층 구조로 JSON-RPC 메시지를 교환하여 자율 도구 실행을 조정합니다.", "식별자 `agentsandbox_mcp_protocol_architecture_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["MCP coordinates autonomous tool executions using standard JSON-RPC request/response contracts.", "Extract the first 20 hex characters of SHA256(\"agentsandbox_mcp_protocol_architecture_v1\")."]
    }
  },
  {
    id: "t0_agentsandbox_confused_deputy_problem",
    tier: 0, cat: "deputy", track: "agentsandbox", points: 25, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "AI 에이전트 권한 대행(Confused Deputy) 취약점 발생 메커니즘",
      en: "Confused Deputy Vulnerability Mechanisms in Autonomous AI Agents"
    },
    prompt: {
      ko: "낮은 권한의 외부 입력값이 높은 호스트 시스템 권한을 보유한 에이전트를 조작하여 권한을 대행 실행시키는 Confused Deputy 공격 모델을 분석합니다.\n지정된 식별자 `agentsandbox_confused_deputy_problem_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_confused_deputy_problem_v1\") 앞 20자리}`",
      en: "Analyze the Confused Deputy problem where low-privileged untrusted prompts manipulate a high-privileged agent into unauthorized host operations.\nCompute the first 20 hex characters of SHA256(\"agentsandbox_confused_deputy_problem_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_confused_deputy_problem_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["권한 대행 문제는 에이전트의 인가 범위와 실제 시스템 권한 사이의 경계 불일치에서 기인합니다.", "식별자 `agentsandbox_confused_deputy_problem_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The confused deputy vector arises from a mismatch between user permissions and agent-held host credentials.", "Extract the first 20 hex characters of SHA256(\"agentsandbox_confused_deputy_problem_v1\")."]
    }
  },

  // Tier 1 (8)
  {
    id: "t1_agentsandbox_indirect_prompt_injection_ipi",
    tier: 1, cat: "injection", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "웹 검색 및 문서 열람을 통한 간접 프롬프트 주입(IPI) 기법",
      en: "Indirect Prompt Injection (IPI) via Web Browsing & Document Parsing"
    },
    prompt: {
      ko: "에이전트가 외부 웹페이지나 PDF 문서를 검색·요약하는 과정에서 악성 프롬프트 지시사항이 주입되어 시스템 제어 흐름이 탈취되는 IPI 기법을 분석합니다.\n지정된 식별자 `agentsandbox_indirect_prompt_injection_ipi_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_indirect_prompt_injection_ipi_v1\") 앞 20자리}`",
      en: "Evaluate Indirect Prompt Injection (IPI) payloads embedded in external web data that hijack agent instruction streams during ingestion.\nCompute the first 20 hex characters of SHA256(\"agentsandbox_indirect_prompt_injection_ipi_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_indirect_prompt_injection_ipi_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["IPI는 데이터 평면(Data Plane)과 제어 평면(Control Plane)의 분리가 미흡할 때 명령어로 오인되어 실행됩니다.", "식별자 `agentsandbox_indirect_prompt_injection_ipi_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["IPI exploits the lack of strict demarcation between instruction tokens and ingested external context.", "Extract first 20 hex characters of SHA256(\"agentsandbox_indirect_prompt_injection_ipi_v1\")."]
    }
  },
  {
    id: "t1_agentsandbox_mcp_tool_schema_poisoning",
    tier: 1, cat: "poisoning", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "MCP 도구 JSON 스키마 조작 및 악성 매개변수 오염 주입",
      en: "MCP Tool JSON Schema Poisoning & Malicious Argument Manipulation"
    },
    prompt: {
      ko: "MCP 서버의 도구 정의 스키마(Tool Definition Schema)에 악성 기본값이나 오염된 파라미터 구조를 주입하여 임의 도구 호출을 강제하는 기법을 분석합니다.\n지정된 식별자 `agentsandbox_mcp_tool_schema_poisoning_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_mcp_tool_schema_poisoning_v1\") 앞 20자리}`",
      en: "Investigate MCP tool JSON schema tampering where poisoned property descriptions force LLM invocation of unauthorized tools.\nCompute the first 20 hex characters of SHA256(\"agentsandbox_mcp_tool_schema_poisoning_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_mcp_tool_schema_poisoning_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["도구 설명(Description)에 가짜 시스템 지침을 포함시키면 LLM이 해당 도구를 최우선적으로 호출하게 유도할 수 있습니다.", "식별자 `agentsandbox_mcp_tool_schema_poisoning_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Poisoned schema descriptions mislead LLMs into preferentially triggering attacker-controlled tools.", "Extract first 20 hex characters of SHA256(\"agentsandbox_mcp_tool_schema_poisoning_v1\")."]
    }
  },
  {
    id: "t1_agentsandbox_shadow_tool_definition_hijack",
    tier: 1, cat: "shadowing", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "동일 명칭 도구 정의를 통한 섀도우 툴 체인 하이재킹",
      en: "Shadow Tool Hijacking via Duplicate Name Registrations"
    },
    prompt: {
      ko: "정상 도구(예: `read_file`)와 동일한 이름을 가진 섀도우 도구를 후순위 MCP 서버에 등록하여 호출 우선순위를 가로채는 기법을 분석합니다.\n지정된 식별자 `agentsandbox_shadow_tool_definition_hijack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_shadow_tool_definition_hijack_v1\") 앞 20자리}`",
      en: "Examine Shadow Tool Hijacking where duplicate tool identifiers intercept legitimate function dispatches.\nCompute first 20 hex chars of SHA256(\"agentsandbox_shadow_tool_definition_hijack_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_shadow_tool_definition_hijack_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["도구 네임스페이스 격리가 부재할 경우 전역 네임스페이스 오염(Global Tool Shadowing)이 발생합니다.", "식별자 `agentsandbox_shadow_tool_definition_hijack_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Global namespace collision allows rogue servers to override core built-in operations.", "Extract first 20 hex characters of SHA256(\"agentsandbox_shadow_tool_definition_hijack_v1\")."]
    }
  },
  {
    id: "t1_agentsandbox_tool_parameter_type_confusion",
    tier: 1, cat: "typeconfusion", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "도구 인자 역직렬화 시 타입 혼동(Type Confusion) 취약점",
      en: "Parameter Type Confusion in Agent Tool Deserialization"
    },
    prompt: {
      ko: "문자열 인자를 기대하는 도구 파라미터에 배열 또는 객체를 전달하여 백엔드 파서의 예외를 유도하고 내부 경로를 우회하는 원리를 분석합니다.\n지정된 식별자 `agentsandbox_tool_parameter_type_confusion_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_tool_parameter_type_confusion_v1\") 앞 20자리}`",
      en: "Assess parameter type confusion where unexpected data structures bypass regex sanitization in agent handlers.\nCompute first 20 hex chars of SHA256(\"agentsandbox_tool_parameter_type_confusion_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_tool_parameter_type_confusion_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["엄격한 Pydantic/Zod 런타임 스키마 검증이 없을 때 타입 강제 형변환(Coercion) 버그가 발생합니다.", "식별자 `agentsandbox_tool_parameter_type_confusion_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Runtime type coercion failures allow structured inputs to bypass flat string validators.", "Extract first 20 hex characters of SHA256(\"agentsandbox_tool_parameter_type_confusion_v1\")."]
    }
  },
  {
    id: "t1_agentsandbox_context_window_smuggling",
    tier: 1, cat: "smuggling", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "컨텍스트 윈도우 스머글링을 통한 이전 시스템 프롬프트 무력화",
      en: "Context Window Smuggling & System Prompt Neutralization"
    },
    prompt: {
      ko: "대용량 더미 텍스트를 주입하여 안전 가드레일 프롬프트를 컨텍스트 상단으로 밀어내고 어텐션 가중치를 약화시키는 기법을 분석합니다.\n지정된 식별자 `agentsandbox_context_window_smuggling_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_context_window_smuggling_v1\") 앞 20자리}`",
      en: "Analyze context window smuggling where excessive padding degrades attention weights allocated to defensive system rules.\nCompute first 20 hex chars of SHA256(\"agentsandbox_context_window_smuggling_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_context_window_smuggling_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Attention Decay(주의력 감쇠) 현상은 컨텍스트 길이가 길어질수록 초반 시스템 지침의 영향력을 저하시킵니다.", "식별자 `agentsandbox_context_window_smuggling_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Attention decay attenuates the enforcement of initial defensive constraints in long contexts.", "Extract first 20 hex characters of SHA256(\"agentsandbox_context_window_smuggling_v1\")."]
    }
  },
  {
    id: "t1_agentsandbox_bpe_token_splitting_guardrail_bypass",
    tier: 1, cat: "bypass", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "BPE 바이트 쌍 토큰 분할을 악용한 키워드 필터 가드레일 우회",
      en: "BPE Token Splitting for Keyword Guardrail Evasion"
    },
    prompt: {
      ko: "단어 경계를 제로 너비 공백(ZWSP)이나 특수 분할 문자로 쪼개어 단순 문자열 필터는 우회하고 LLM 내부에서는 온전한 명령어로 복원되게 만드는 원리를 분석합니다.\n지정된 식별자 `agentsandbox_bpe_token_splitting_guardrail_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_bpe_token_splitting_guardrail_bypass_v1\") 앞 20자리}`",
      en: "Examine BPE token fragmentation where zero-width spaces evade keyword filters while preserving model intent.\nCompute first 20 hex chars of SHA256(\"agentsandbox_bpe_token_splitting_guardrail_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_bpe_token_splitting_guardrail_bypass_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["토크나이저 수준의 정규화(Unicode NFKC) 없이 텍스트 필터링을 수행하면 분할 우회에 노출됩니다.", "식별자 `agentsandbox_bpe_token_splitting_guardrail_bypass_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Absence of canonical Unicode normalization allows segmented payload reconstruction.", "Extract first 20 hex characters of SHA256(\"agentsandbox_bpe_token_splitting_guardrail_bypass_v1\")."]
    }
  },
  {
    id: "t1_agentsandbox_json_rpc_message_framing_injection",
    tier: 1, cat: "framing", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "JSON-RPC 전송 계층 메시지 프레이밍(Framing) 주입 공격",
      en: "JSON-RPC Message Framing Injection in Transport Channels"
    },
    prompt: {
      ko: "stdio 파이프라인에서 줄바꿈 문자(`\\n`)를 주입하여 다중 JSON-RPC 요청을 위조 주입(Pipeline Smuggling)하는 원리를 분석합니다.\n지정된 식별자 `agentsandbox_json_rpc_message_framing_injection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_json_rpc_message_framing_injection_v1\") 앞 20자리}`",
      en: "Analyze newline injection in stdio transport channels that leads to JSON-RPC request pipeline desynchronization.\nCompute first 20 hex chars of SHA256(\"agentsandbox_json_rpc_message_framing_injection_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_json_rpc_message_framing_injection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["줄바꿈 기반 프레이밍은 페이로드 내부의 캐리지 리턴 및 라인 피드 검증이 누락될 때 프로토콜 분열을 야기합니다.", "식별자 `agentsandbox_json_rpc_message_framing_injection_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Line-delimited JSON-RPC transports require strict sanitization of embedded control characters.", "Extract first 20 hex characters of SHA256(\"agentsandbox_json_rpc_message_framing_injection_v1\")."]
    }
  },
  {
    id: "t1_agentsandbox_agent_multi_hop_permission_drift",
    tier: 1, cat: "drift", track: "agentsandbox", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "멀티 에이전트 간 권한 위임 체인에서의 권한 드리프트(Permission Drift)",
      en: "Permission Drift Across Multi-Agent Delegation Chains"
    },
    prompt: {
      ko: "코디네이터 에이전트에서 하위 서브에이전트로 작업을 위임하는 과정에서 호출 컨텍스트와 권한 제약이 누락되어 발생하는 권한 확산 취약점을 분석합니다.\n지정된 식별자 `agentsandbox_agent_multi_hop_permission_drift_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_agent_multi_hop_permission_drift_v1\") 앞 20자리}`",
      en: "Examine permission drift where delegated subagents inherit broader access rights than initially authorized by the user.\nCompute first 20 hex chars of SHA256(\"agentsandbox_agent_multi_hop_permission_drift_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_agent_multi_hop_permission_drift_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["위임 체인마다 Macaroon 토큰이나 권한 범위(Scope)를 축소 전파(Attenuation)하지 않으면 권한 탈취가 용이해집니다.", "식별자 `agentsandbox_agent_multi_hop_permission_drift_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Cryptographic macaroon attenuation prevents privilege inflation during inter-agent delegation.", "Extract first 20 hex characters of SHA256(\"agentsandbox_agent_multi_hop_permission_drift_v1\")."]
    }
  },

  // Tier 2 (12)
  {
    id: "t2_agentsandbox_subprocess_shell_spawning_escape",
    tier: 2, cat: "escape", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "에이전트 서브프로세스 셸 스폰을 통한 컨테이너 격리 탈출 벡터",
      en: "Container Escape Vectors via Agent Subprocess Shell Spawning"
    },
    prompt: {
      ko: "에이전트가 `os.system` 또는 `subprocess.Popen(..., shell=True)`를 호출할 때 셸 메타문자 체이닝을 통해 호스트 셸을 획득하는 탈출 메커니즘을 분석합니다.\n지정된 식별자 `agentsandbox_subprocess_shell_spawning_escape_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_subprocess_shell_spawning_escape_v1\") 앞 20자리}`",
      en: "Assess subshell invocation vulnerabilities where unvalidated parameters trigger arbitrary host command execution.\nCompute first 20 hex chars of SHA256(\"agentsandbox_subprocess_shell_spawning_escape_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_subprocess_shell_spawning_escape_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["명령행 인자를 배열 형태로 직접 전달하고 shell=False를 강제하는 것이 명령 주입의 1차 방어선입니다.", "식별자 `agentsandbox_subprocess_shell_spawning_escape_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Direct executable execution with explicit argument vectors eliminates shell metacharacter parsing.", "Extract first 20 hex characters of SHA256(\"agentsandbox_subprocess_shell_spawning_escape_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_proc_filesystem_credential_carving",
    tier: 2, cat: "carving", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "/proc 의사 파일시스템 조회를 통한 상위 프로세스 환경변수 탈취",
      en: "Host Secret Exfiltration via /proc Pseudofilesystem Traversal"
    },
    prompt: {
      ko: "에이전트가 `/proc/1/environ` 및 `/proc/self/cmdline`을 열람하여 컨테이너 호스트의 클라우드 API 키와 마스터 토큰을 탈취하는 공격을 분석합니다.\n지정된 식별자 `agentsandbox_proc_filesystem_credential_carving_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_proc_filesystem_credential_carving_v1\") 앞 20자리}`",
      en: "Examine host credential theft where agent processes inspect /proc/1/environ to carve sensitive tokens.\nCompute first 20 hex chars of SHA256(\"agentsandbox_proc_filesystem_credential_carving_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_proc_filesystem_credential_carving_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["hidepid 마운트 옵션이나 Landlock 격리를 통해 /proc 파일시스템 노출을 차단해야 합니다.", "식별자 `agentsandbox_proc_filesystem_credential_carving_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Enforcing hidepid mount options and Landlock limits prevents unauthorized /proc access.", "Extract first 20 hex characters of SHA256(\"agentsandbox_proc_filesystem_credential_carving_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_linux_landlock_abi_v1_v3_internals",
    tier: 2, cat: "landlock", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Linux Landlock LSM 커널 아키텍처 및 비특권 자가 격리 원리",
      en: "Linux Landlock LSM Kernel Architecture & Unprivileged Self-Jailing"
    },
    prompt: {
      ko: "루트 권한 없이도 프로세스가 스스로의 파일시스템 접근 권한을 영구 축소하는 Linux Landlock LSM의 ruleset 생성 및 적용 메커니즘을 분석합니다.\n지정된 식별자 `agentsandbox_linux_landlock_abi_v1_v3_internals_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_linux_landlock_abi_v1_v3_internals_v1\") 앞 20자리}`",
      en: "Analyze the Linux Landlock LSM ruleset creation and enforcement pipeline allowing unprivileged processes to self-jail.\nCompute first 20 hex chars of SHA256(\"agentsandbox_linux_landlock_abi_v1_v3_internals_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_linux_landlock_abi_v1_v3_internals_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Landlock은 `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self` 시스템콜 3단계로 동작합니다.", "식별자 `agentsandbox_linux_landlock_abi_v1_v3_internals_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Landlock executes across three syscalls: landlock_create_ruleset, add_rule, and restrict_self.", "Extract first 20 hex characters of SHA256(\"agentsandbox_linux_landlock_abi_v1_v3_internals_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_landlock_handled_access_fs_ruleset",
    tier: 2, cat: "landlock", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Landlock handled_access_fs 플래그를 통한 세분화된 I/O 접근 통제",
      en: "Granular I/O Access Control via Landlock handled_access_fs Flags"
    },
    prompt: {
      ko: "READ, WRITE, EXECUTE, MAKE_DIR 등 파일시스템 접근 플래그를 비트마스크로 구성하여 지정된 워크스페이스에만 제한적 쓰기를 부여하는 정책을 설계합니다.\n지정된 식별자 `agentsandbox_landlock_handled_access_fs_ruleset_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_landlock_handled_access_fs_ruleset_v1\") 앞 20자리}`",
      en: "Configure Landlock handled_access_fs bitmasks to restrict write and execute privileges exclusively to approved workspace trees.\nCompute first 20 hex chars of SHA256(\"agentsandbox_landlock_handled_access_fs_ruleset_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_landlock_handled_access_fs_ruleset_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LANDLOCK_ACCESS_FS_EXECUTE와 WRITE_FILE 권한을 엄격히 분리하여 임의 바이너리 실행을 차단합니다.", "식별자 `agentsandbox_landlock_handled_access_fs_ruleset_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Separating execute permissions from writable directories prevents dropped binary execution.", "Extract first 20 hex characters of SHA256(\"agentsandbox_landlock_handled_access_fs_ruleset_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_prctl_no_new_privs_security_gate",
    tier: 2, cat: "prctl", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "prctl PR_SET_NO_NEW_PRIVS 게이트를 통한 setuid 권한 상승 방어",
      en: "Mitigating SUID Escalation with prctl PR_SET_NO_NEW_PRIVS"
    },
    prompt: {
      ko: "Landlock 적용 전 `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`를 호출하여 자식 프로세스가 execve를 통해 추가 권한을 획득하지 못하도록 봉쇄하는 원리를 분석합니다.\n지정된 식별자 `agentsandbox_prctl_no_new_privs_security_gate_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_prctl_no_new_privs_security_gate_v1\") 앞 20자리}`",
      en: "Analyze how prctl(PR_SET_NO_NEW_PRIVS, 1) prevents child processes from acquiring higher privileges across execve boundaries.\nCompute first 20 hex chars of SHA256(\"agentsandbox_prctl_no_new_privs_security_gate_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_prctl_no_new_privs_security_gate_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["PR_SET_NO_NEW_PRIVS 플래그는 setuid 바이너리의 권한 상승 효과를 무력화시키는 필수 사전 조건입니다.", "식별자 `agentsandbox_prctl_no_new_privs_security_gate_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["PR_SET_NO_NEW_PRIVS is a mandatory prerequisite for Landlock restriction without root credentials.", "Extract first 20 hex characters of SHA256(\"agentsandbox_prctl_no_new_privs_security_gate_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_unprivileged_worker_chroot_isolation",
    tier: 2, cat: "isolation", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "비특권 유저 네임스페이스와 피벗 루트(pivot_root) 디렉터리 격리",
      en: "Directory Isolation via User Namespaces & pivot_root"
    },
    prompt: {
      ko: "루트 권한 없이 사용자 네임스페이스(`CLONE_NEWUSER | CLONE_NEWNS`)를 생성하고 `pivot_root`를 수행하여 호스트 파일시스템 루트를 완전히 은닉하는 기법을 분석합니다.\n지정된 식별자 `agentsandbox_unprivileged_worker_chroot_isolation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_unprivileged_worker_chroot_isolation_v1\") 앞 20자리}`",
      en: "Examine user namespaces and pivot_root operations that isolate unprivileged agent processes from the host root hierarchy.\nCompute first 20 hex chars of SHA256(\"agentsandbox_unprivileged_worker_chroot_isolation_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_unprivileged_worker_chroot_isolation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["chroot 탈출 취약점은 `pivot_root`와 마운트 네임스페이스 격리를 병행할 때 완벽히 해소됩니다.", "식별자 `agentsandbox_unprivileged_worker_chroot_isolation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Combining user namespaces with pivot_root prevents classic chroot breakout vectors.", "Extract first 20 hex characters of SHA256(\"agentsandbox_unprivileged_worker_chroot_isolation_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_cgroup_v2_memory_cpu_starvation_mitigation",
    tier: 2, cat: "cgroup", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "cgroup v2 리소스 한도 설정을 통한 에이전트 DoS 및 포크 폭탄 방어",
      en: "Agent DoS & Fork Bomb Mitigation via cgroup v2 Resource Limits"
    },
    prompt: {
      ko: "악성 루프나 포크 폭탄(Fork Bomb)을 유도하는 프롬프트 공격에 대응하여 `pids.max` 및 `memory.max` 제약으로 시스템 자원 고갈을 방어하는 원리를 분석합니다.\n지정된 식별자 `agentsandbox_cgroup_v2_memory_cpu_starvation_mitigation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_cgroup_v2_memory_cpu_starvation_mitigation_v1\") 앞 20자리}`",
      en: "Analyze cgroup v2 pids.max and memory.max constraints that protect hosts from prompt-induced fork bombs and memory exhaustion.\nCompute first 20 hex chars of SHA256(\"agentsandbox_cgroup_v2_memory_cpu_starvation_mitigation_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_cgroup_v2_memory_cpu_starvation_mitigation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["cgroup v2 계층 구조는 비특권 에이전트 자식 프로세스가 시스템 리소스를 독점하지 못하도록 물리적 상한을 강제합니다.", "식별자 `agentsandbox_cgroup_v2_memory_cpu_starvation_mitigation_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Cgroup v2 hierarchies enforce strict memory and PID ceilings against rogue agent subprocesses.", "Extract first 20 hex characters of SHA256(\"agentsandbox_cgroup_v2_memory_cpu_starvation_mitigation_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_seccomp_bpf_filter_syscall_kill",
    tier: 2, cat: "seccomp", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Seccomp-BPF 필터를 통한 위험 시스템콜(ptrace, mount) 즉각 종료",
      en: "Immediate Termination of Dangerous Syscalls via Seccomp-BPF Filters"
    },
    prompt: {
      ko: "에이전트가 `ptrace`, `process_vm_writev`, `mount` 등 위험 시스템콜을 호출할 때 `SECCOMP_RET_KILL_PROCESS`로 즉시 프로세스를 사살하는 BPF 필터 설계를 분석합니다.\n지정된 식별자 `agentsandbox_seccomp_bpf_filter_syscall_kill_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_seccomp_bpf_filter_syscall_kill_v1\") 앞 20자리}`",
      en: "Design Seccomp-BPF filters issuing SECCOMP_RET_KILL_PROCESS upon detection of high-risk syscalls like ptrace or mount.\nCompute first 20 hex chars of SHA256(\"agentsandbox_seccomp_bpf_filter_syscall_kill_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_seccomp_bpf_filter_syscall_kill_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Seccomp 필터는 Landlock과 결합되어 파일 I/O 외의 시스템콜 전반을 강력히 하드닝합니다.", "식별자 `agentsandbox_seccomp_bpf_filter_syscall_kill_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Seccomp-BPF complements Landlock by filtering non-filesystem syscall vectors.", "Extract first 20 hex characters of SHA256(\"agentsandbox_seccomp_bpf_filter_syscall_kill_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_host_docker_socket_mounting_danger",
    tier: 2, cat: "escape", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "에이전트 컨테이너 내 도커 소켓(/var/run/docker.sock) 마운트 위험 분석",
      en: "Risks of Exposing /var/run/docker.sock in Agent Containers"
    },
    prompt: {
      ko: "에이전트 환경에 도커 소켓이 마운트되었을 때 REST API를 호출하여 호스트 루트 파티션을 마운트한 특권 컨테이너를 탈출 생성하는 공격을 분석합니다.\n지정된 식별자 `agentsandbox_host_docker_socket_mounting_danger_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_host_docker_socket_mounting_danger_v1\") 앞 20자리}`",
      en: "Examine Docker socket abuse where an agent uses the daemon API to spawn privileged root containers on the host.\nCompute first 20 hex chars of SHA256(\"agentsandbox_host_docker_socket_mounting_danger_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_host_docker_socket_mounting_danger_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["도커 소켓 접근 권한은 호스트 루트 권한과 사실상 동일하므로 에이전트 컨테이너에 절대 마운트해서는 안 됩니다.", "식별자 `agentsandbox_host_docker_socket_mounting_danger_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Docker socket exposure is equivalent to root on the host machine; never bind it to untrusted agent environments.", "Extract first 20 hex characters of SHA256(\"agentsandbox_host_docker_socket_mounting_danger_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_ebpf_kprobe_execve_intercept",
    tier: 2, cat: "ebpf", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "eBPF kprobe:sys_execve를 활용한 에이전트 실행 바이너리 인라인 감사",
      en: "Auditing Executed Binaries via eBPF kprobe:sys_execve Telemetry"
    },
    prompt: {
      ko: "에이전트 워커가 실행하는 바이너리 경로와 명령행 인자를 커널 레벨에서 후킹하여 실시간 보안 텔레메트리를 수집하는 eBPF 탐지 구조를 분석합니다.\n지정된 식별자 `agentsandbox_ebpf_kprobe_execve_intercept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_ebpf_kprobe_execve_intercept_v1\") 앞 20자리}`",
      en: "Analyze eBPF kprobe:sys_execve telemetry pipelines capturing binary paths and argument vectors invoked by agent processes.\nCompute first 20 hex chars of SHA256(\"agentsandbox_ebpf_kprobe_execve_intercept_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_ebpf_kprobe_execve_intercept_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["kprobe는 시스템콜 진입 시 레지스터 상태를 복사하여 사용자 공간 로그 변조를 원천 무력화합니다.", "식별자 `agentsandbox_ebpf_kprobe_execve_intercept_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["eBPF kprobes collect tamper-proof execution telemetry directly from kernel registers.", "Extract first 20 hex characters of SHA256(\"agentsandbox_ebpf_kprobe_execve_intercept_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_dual_llm_intent_arbitration",
    tier: 2, cat: "dualllm", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Dual-LLM 아키텍처를 통한 도구 실행 의도(Intent) 2차 중재 검증",
      en: "Dual-LLM Intent Arbitration for Secure Tool Execution"
    },
    prompt: {
      ko: "실행 에이전트가 도구 호출을 시도할 때 경량 검증 모델(Validator LLM)이 입력 프롬프트와 생성된 도구 인자의 보안 위협을 독립 검증하는 아키텍처를 분석합니다.\n지정된 식별자 `agentsandbox_dual_llm_intent_arbitration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_dual_llm_intent_arbitration_v1\") 앞 20자리}`",
      en: "Evaluate Dual-LLM architectures where an independent validator model evaluates tool invocation intents before execution.\nCompute first 20 hex chars of SHA256(\"agentsandbox_dual_llm_intent_arbitration_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_dual_llm_intent_arbitration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["검증 모델은 사용자 지침의 맥락을 모르는 상태에서 격리된 안전 정책만을 기준으로 도구 파라미터를 판정합니다.", "식별자 `agentsandbox_dual_llm_intent_arbitration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Validator models operate with isolated safety prompts, reducing susceptibility to complex multi-turn jailbreaks.", "Extract first 20 hex characters of SHA256(\"agentsandbox_dual_llm_intent_arbitration_v1\")."]
    }
  },
  {
    id: "t2_agentsandbox_spiffe_spire_agent_attestation",
    tier: 2, cat: "spiffe", track: "agentsandbox", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "SPIFFE/SPIRE 기반 에이전트 워크로드 암호학적 신원 증명(Attestation)",
      en: "Cryptographic Agent Workload Attestation with SPIFFE/SPIRE"
    },
    prompt: {
      ko: "분산 멀티 에이전트 환경에서 SPIFFE ID와 mTLS SVID를 발급하여 비인가 위조 에이전트의 도구 서버 접근을 차단하는 신원 증명 체계를 분석합니다.\n지정된 식별자 `agentsandbox_spiffe_spire_agent_attestation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_spiffe_spire_agent_attestation_v1\") 앞 20자리}`",
      en: "Analyze SPIFFE/SPIRE workload attestation issuing short-lived SVIDs to authenticate agent identities across microservices.\nCompute first 20 hex chars of SHA256(\"agentsandbox_spiffe_spire_agent_attestation_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_spiffe_spire_agent_attestation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SPIRE 에이전트는 cgroup, 바이너리 해시, 네임스페이스를 검증한 후 신원 토큰을 교부합니다.", "식별자 `agentsandbox_spiffe_spire_agent_attestation_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["SPIRE validates process attributes (cgroups, hashes) before issuing short-lived cryptographic credentials.", "Extract first 20 hex characters of SHA256(\"agentsandbox_spiffe_spire_agent_attestation_v1\")."]
    }
  },

  // Tier 3 (8)
  {
    id: "t3_agentsandbox_ebpf_lsm_bprm_check_security_hook",
    tier: 3, cat: "ebpflsm", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "eBPF LSM bpf_lsm_bprm_check_security 훅을 통한 인커널 실행 차단",
      en: "In-Kernel Execution Blocking with eBPF LSM bprm_check_security"
    },
    prompt: {
      ko: "바이너리 로드 시점에 `bpf_lsm_bprm_check_security` 훅을 실행하여 비인가 실행 파일에 대해 `-EACCES` 또는 `-EPERM`을 반환하는 인커널 차단 기법을 분석합니다.\n지정된 식별자 `agentsandbox_ebpf_lsm_bprm_check_security_hook_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_ebpf_lsm_bprm_check_security_hook_v1\") 앞 20자리}`",
      en: "Implement in-kernel execution blocking using bpf_lsm_bprm_check_security returning -EACCES for non-whitelisted binaries.\nCompute first 20 hex chars of SHA256(\"agentsandbox_ebpf_lsm_bprm_check_security_hook_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_ebpf_lsm_bprm_check_security_hook_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["eBPF LSM은 단순 kprobe 모니터링을 넘어 시스템콜 실행 자체를 거부할 수 있는 강력한 보안 계층입니다.", "식별자 `agentsandbox_ebpf_lsm_bprm_check_security_hook_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["eBPF LSM hooks provide active remediation by aborting unauthorized kernel operations with error codes.", "Extract first 20 hex characters of SHA256(\"agentsandbox_ebpf_lsm_bprm_check_security_hook_v1\")."]
    }
  },
  {
    id: "t3_agentsandbox_cilium_tetragon_tracing_policy_sigkill",
    tier: 3, cat: "tetragon", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Cilium Tetragon TracingPolicy 기반 실시간 프로세스 SIGKILL 차단",
      en: "Real-Time Process Termination via Cilium Tetragon TracingPolicy"
    },
    prompt: {
      ko: "에이전트 컨테이너가 네임스페이스 외부의 민감 파일(`/etc/shadow`)을 읽으려 할 때 Tetragon TracingPolicy가 즉시 인커널 SIGKILL 신호를 발령하는 방어 정책을 분석합니다.\n지정된 식별자 `agentsandbox_cilium_tetragon_tracing_policy_sigkill_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_cilium_tetragon_tracing_policy_sigkill_v1\") 앞 20자리}`",
      en: "Configure Cilium Tetragon TracingPolicies to deliver synchronous in-kernel SIGKILL signals upon unauthorized file open calls.\nCompute first 20 hex chars of SHA256(\"agentsandbox_cilium_tetragon_tracing_policy_sigkill_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_cilium_tetragon_tracing_policy_sigkill_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Tetragon은 사용자 공간으로 컨텍스트 스위칭하기 전에 커널 스택에서 즉시 위협 프로세스를 사살합니다.", "식별자 `agentsandbox_cilium_tetragon_tracing_policy_sigkill_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Tetragon enforces synchronous SIGKILL before process context can execute payload logic.", "Extract first 20 hex characters of SHA256(\"agentsandbox_cilium_tetragon_tracing_policy_sigkill_v1\")."]
    }
  },
  {
    id: "t3_agentsandbox_landlock_fs_path_beneath_rule_enforce",
    tier: 3, cat: "landlock", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Landlock path_beneath 룰 구조체를 통한 트리 단위 접근 격리",
      en: "Hierarchical Tree Isolation via Landlock path_beneath Rules"
    },
    prompt: {
      ko: "`landlock_path_beneath_attr` 구조체에 부모 디렉터리 파일 디스크립터를 전달하여 하위 모든 파일과 서브디렉터리에 일괄 접근 제어를 적용하는 구현을 분석합니다.\n지정된 식별자 `agentsandbox_landlock_fs_path_beneath_rule_enforce_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_landlock_fs_path_beneath_rule_enforce_v1\") 앞 20자리}`",
      en: "Analyze landlock_path_beneath_attr implementations enforcing recursive directory hierarchy restrictions.\nCompute first 20 hex chars of SHA256(\"agentsandbox_landlock_fs_path_beneath_rule_enforce_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_landlock_fs_path_beneath_rule_enforce_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["path_beneath 규칙은 O_PATH 플래그로 연 디렉터리 fd를 기준으로 하위 계층에 상속 적용됩니다.", "식별자 `agentsandbox_landlock_fs_path_beneath_rule_enforce_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Landlock path_beneath rules bind recursively to file descriptors opened with O_PATH.", "Extract first 20 hex characters of SHA256(\"agentsandbox_landlock_fs_path_beneath_rule_enforce_v1\")."]
    }
  },
  {
    id: "t3_agentsandbox_mcp_stdio_vs_sse_transport_containment",
    tier: 3, cat: "transport", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "MCP Stdio 파이프라인과 HTTP SSE 전송 계층의 보안 격리 비교",
      en: "Comparative Security Containment: MCP Stdio vs HTTP SSE"
    },
    prompt: {
      ko: "로컬 stdio 프로세스 파이프와 원격 Server-Sent Events(SSE) HTTP 전송 방식 간의 공격 표면, 샌드박싱 난이도 및 상호 인증 기법을 비교 분석합니다.\n지정된 식별자 `agentsandbox_mcp_stdio_vs_sse_transport_containment_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_mcp_stdio_vs_sse_transport_containment_v1\") 앞 20자리}`",
      en: "Compare attack surfaces and isolation boundaries between local stdio IPC pipelines and remote HTTP SSE transports.\nCompute first 20 hex chars of SHA256(\"agentsandbox_mcp_stdio_vs_sse_transport_containment_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_mcp_stdio_vs_sse_transport_containment_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["stdio 방식은 파일 디스크립터 상속 위험이 존재하며, SSE 방식은 네트워크 경계와 TLS 상호 인증을 필요로 합니다.", "식별자 `agentsandbox_mcp_stdio_vs_sse_transport_containment_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Stdio transports inherit file descriptors; SSE exposes HTTP attack surfaces requiring strict mTLS.", "Extract first 20 hex characters of SHA256(\"agentsandbox_mcp_stdio_vs_sse_transport_containment_v1\")."]
    }
  },
  {
    id: "t3_agentsandbox_confused_deputy_ssrf_cloud_metadata",
    tier: 3, cat: "ssrf", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "에이전트 URL fetch 도구를 통한 클라우드 IMDS 메타데이터 SSRF 탈취",
      en: "Cloud IMDS SSRF Exploitation via Agent URL Fetch Tools"
    },
    prompt: {
      ko: "에이전트의 `fetch_url` 도구를 조작하여 AWS `169.254.169.254` IMDSv1에 접근해 임시 인스턴스 자격증명을 탈취하는 SSRF 공격 및 IMDSv2 방어책을 분석합니다.\n지정된 식별자 `agentsandbox_confused_deputy_ssrf_cloud_metadata_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_confused_deputy_ssrf_cloud_metadata_v1\") 앞 20자리}`",
      en: "Analyze SSRF attacks targeting cloud IMDS (169.254.169.254) via agent HTTP tools and implement IMDSv2 token defenses.\nCompute first 20 hex chars of SHA256(\"agentsandbox_confused_deputy_ssrf_cloud_metadata_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_confused_deputy_ssrf_cloud_metadata_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["링크 로컬 주소(169.254.0.0/16) 및 사설 대역으로의 아웃바운드 HTTP 요청을 도구 계층에서 원천 필터링해야 합니다.", "식별자 `agentsandbox_confused_deputy_ssrf_cloud_metadata_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Network-level egress filters must drop outbound requests to link-local and private CIDR blocks.", "Extract first 20 hex characters of SHA256(\"agentsandbox_confused_deputy_ssrf_cloud_metadata_v1\")."]
    }
  },
  {
    id: "t3_agentsandbox_agent_multi_turn_persisted_backdoor",
    tier: 3, cat: "backdoor", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "에이전트 장기 메모리(RAG / Vector DB) 오염을 통한 지속성 백도어",
      en: "Persistent Backdoors via Agent Long-Term Memory (RAG) Poisoning"
    },
    prompt: {
      ko: "에이전트가 참조하는 지식 베이스 또는 벡터 데이터베이스에 슬리퍼 악성 프롬프트를 저장시켜 이후 질의 시 트리거되게 만드는 장기 지속성 공격을 분석합니다.\n지정된 식별자 `agentsandbox_agent_multi_turn_persisted_backdoor_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_agent_multi_turn_persisted_backdoor_v1\") 앞 20자리}`",
      en: "Examine persistent backdoor planting where poisoned embeddings in vector stores activate sleeper prompts across subsequent sessions.\nCompute first 20 hex chars of SHA256(\"agentsandbox_agent_multi_turn_persisted_backdoor_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_agent_multi_turn_persisted_backdoor_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["RAG 인덱싱 시점에 임베딩 데이터의 출처 신뢰도와 악성 지침 시그니처를 사전 정제해야 합니다.", "식별자 `agentsandbox_agent_multi_turn_persisted_backdoor_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Pre-ingestion sanitization of vector store documents neutralizes latent sleeper triggers.", "Extract first 20 hex characters of SHA256(\"agentsandbox_agent_multi_turn_persisted_backdoor_v1\")."]
    }
  },
  {
    id: "t3_agentsandbox_kernel_namespace_user_ns_escape_mitigation",
    tier: 3, cat: "userns", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "리눅스 사용자 네임스페이스 기반 취약점(CVE-2022-0185 등) 커널 하드닝",
      en: "Kernel Hardening Against User Namespace Escapes (CVE-2022-0185)"
    },
    prompt: {
      ko: "비특권 유저 네임스페이스의 취약점을 악용한 커널 힙 버퍼 오버플로우 탈출을 방어하기 위해 sysctl `kernel.unprivileged_userns_clone=0` 설정을 검증합니다.\n지정된 식별자 `agentsandbox_kernel_namespace_user_ns_escape_mitigation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_kernel_namespace_user_ns_escape_mitigation_v1\") 앞 20자리}`",
      en: "Evaluate kernel sysctl configurations mitigating unprivileged user namespace exploits like CVE-2022-0185.\nCompute first 20 hex chars of SHA256(\"agentsandbox_kernel_namespace_user_ns_escape_mitigation_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_kernel_namespace_user_ns_escape_mitigation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["불필요한 비특권 유저 네임스페이스 생성을 제한하면 커널 공격 표면을 극적으로 축소할 수 있습니다.", "식별자 `agentsandbox_kernel_namespace_user_ns_escape_mitigation_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Restricting unprivileged userns cloning closes off large swathes of legacy kernel attack surface.", "Extract first 20 hex characters of SHA256(\"agentsandbox_kernel_namespace_user_ns_escape_mitigation_v1\")."]
    }
  },
  {
    id: "t3_agentsandbox_ai_agent_zero_trust_least_privilege",
    tier: 3, cat: "zerotrust", track: "agentsandbox", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "AI 에이전트 제로 트러스트(Zero Trust) 최소 권한 아키텍처 수립",
      en: "Zero Trust Least-Privilege Architecture for Autonomous AI Agents"
    },
    prompt: {
      ko: "에이전트에게 필요한 최소한의 도구와 파일 범위만을 단기 토큰 형태로 부여하고 지속적으로 이상 징후를 모니터링하는 제로 트러스트 모델을 구현합니다.\n지정된 식별자 `agentsandbox_ai_agent_zero_trust_least_privilege_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_ai_agent_zero_trust_least_privilege_v1\") 앞 20자리}`",
      en: "Synthesize an AI agent Zero Trust least-privilege architecture enforcing ephemeral credentials and behavioral anomaly telemetry.\nCompute first 20 hex chars of SHA256(\"agentsandbox_ai_agent_zero_trust_least_privilege_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_ai_agent_zero_trust_least_privilege_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["지속적 검증(Continuous Verification)과 명시적 인가(Explicit Authorization)는 에이전트 탈취 피해를 최소화합니다.", "식별자 `agentsandbox_ai_agent_zero_trust_least_privilege_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Continuous verification ensures compromised agent instances cannot pivot laterally.", "Extract first 20 hex characters of SHA256(\"agentsandbox_ai_agent_zero_trust_least_privilege_v1\")."]
    }
  },

  // Tier 4 (5)
  {
    id: "t4_agentsandbox_autonomous_agent_jailbreak_triage",
    tier: 4, cat: "triage", track: "agentsandbox", points: 200, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "자율 에이전트 탈옥 및 도구 남용 사고 심층 포렌식 트리아지",
      en: "Deep Forensic Triage of Autonomous Agent Jailbreak Incidents"
    },
    prompt: {
      ko: "MCP 요청 로그, eBPF 감사 이벤트, LLM 입출력 토큰 기록을 상호 대조하여 IPI 주입 시점과 셸 탈출 경로를 역추적하는 엔터프라이즈 포렌식을 수행합니다.\n지정된 식별자 `agentsandbox_autonomous_agent_jailbreak_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_autonomous_agent_jailbreak_triage_v1\") 앞 20자리}`",
      en: "Perform forensic triage correlating MCP audit trails, eBPF telemetry, and token logs to reconstruct jailbreak and escape timelines.\nCompute first 20 hex chars of SHA256(\"agentsandbox_autonomous_agent_jailbreak_triage_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_autonomous_agent_jailbreak_triage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["토큰 타임라인과 커널 시스템콜 타임라인을 동기화하여 인젝션 원인 분석을 수행합니다.", "식별자 `agentsandbox_autonomous_agent_jailbreak_triage_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Aligning token prompt timestamps with kernel execve events isolates the exact injection vector.", "Extract first 20 hex characters of SHA256(\"agentsandbox_autonomous_agent_jailbreak_triage_v1\")."]
    }
  },
  {
    id: "t4_agentsandbox_landlock_lsm_hardened_runtime_sandbox",
    tier: 4, cat: "runtime", track: "agentsandbox", points: 200, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "Landlock LSM 및 gVisor 사용자 공간 커널 복합 샌드박스 구축",
      en: "Multi-Tiered Runtime Sandboxing with Landlock LSM & gVisor"
    },
    prompt: {
      ko: "호스트 커널 직접 접근을 차단하는 gVisor runsc 런타임과 Landlock LSM 파일시스템 샌드박스를 결합한 다계층 방어 체계를 구축합니다.\n지정된 식별자 `agentsandbox_landlock_lsm_hardened_runtime_sandbox_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_landlock_lsm_hardened_runtime_sandbox_v1\") 앞 20자리}`",
      en: "Design defense-in-depth container sandboxes integrating gVisor userspace kernel interception with Linux Landlock LSM policies.\nCompute first 20 hex chars of SHA256(\"agentsandbox_landlock_lsm_hardened_runtime_sandbox_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_landlock_lsm_hardened_runtime_sandbox_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["gVisor는 호스트 커널 시스템콜을 모방하고, Landlock은 컨테이너 내부의 비특권 탈출을 2중으로 방어합니다.", "식별자 `agentsandbox_landlock_lsm_hardened_runtime_sandbox_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["gVisor intercepts syscalls in userspace while Landlock enforces kernel-level directory confinement.", "Extract first 20 hex characters of SHA256(\"agentsandbox_landlock_lsm_hardened_runtime_sandbox_v1\")."]
    }
  },
  {
    id: "t4_agentsandbox_ebpf_dual_llm_zero_latency_shield",
    tier: 4, cat: "shield", track: "agentsandbox", points: 200, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "초저지연(Zero-Latency) eBPF 인라인 검증 및 비동기 LLM 감사 파이프라인",
      en: "Ultra-Low-Latency eBPF Syscall Filtering with Async LLM Auditing"
    },
    prompt: {
      ko: "실시간 시스템콜 지연을 최소화하기 위해 eBPF 레벨에서 화이트리스트 기반 1차 차단을 수행하고, 비동기 큐를 통해 검증 LLM이 정밀 분석하는 파이프라인을 분석합니다.\n지정된 식별자 `agentsandbox_ebpf_dual_llm_zero_latency_shield_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_ebpf_dual_llm_zero_latency_shield_v1\") 앞 20자리}`",
      en: "Architect ultra-low-latency defense pipelines combining wire-speed eBPF syscall filtering with asynchronous LLM audits.\nCompute first 20 hex chars of SHA256(\"agentsandbox_ebpf_dual_llm_zero_latency_shield_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_ebpf_dual_llm_zero_latency_shield_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["eBPF 맵(BPF RingBuffer)을 통해 사용자 공간 감사 데몬으로 제로 카피 이벤트 스트리밍을 구현합니다.", "식별자 `agentsandbox_ebpf_dual_llm_zero_latency_shield_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["RingBuffer primitives stream execution events to auditing daemons with sub-microsecond overhead.", "Extract first 20 hex characters of SHA256(\"agentsandbox_ebpf_dual_llm_zero_latency_shield_v1\")."]
    }
  },
  {
    id: "t4_agentsandbox_enterprise_agent_governance_framework",
    tier: 4, cat: "governance", track: "agentsandbox", points: 200, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "엔터프라이즈 AI 에이전트 거버넌스 및 NIST AI RMF 컴플라이언스 준수",
      en: "Enterprise AI Agent Governance & NIST AI RMF Compliance"
    },
    prompt: {
      ko: "NIST AI RMF 1.0 및 OWASP Top 10 for LLM 가이드라인에 부합하는 전사 AI 에이전트 인가, 권한 감사, SLA 및 비상 셧다운 프로토콜을 수립합니다.\n지정된 식별자 `agentsandbox_enterprise_agent_governance_framework_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_enterprise_agent_governance_framework_v1\") 앞 20자리}`",
      en: "Establish enterprise governance standards mapping autonomous agent workflows to NIST AI RMF and OWASP LLM guidelines.\nCompute first 20 hex chars of SHA256(\"agentsandbox_enterprise_agent_governance_framework_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_enterprise_agent_governance_framework_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["도구 호출 인가 로그의 불변성 보장과 비상 킬스위치(Emergency Kill-Switch)는 거버넌스의 핵심입니다.", "식별자 `agentsandbox_enterprise_agent_governance_framework_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Immutable audit trails paired with instantaneous kill-switches form the core of enterprise agent governance.", "Extract first 20 hex characters of SHA256(\"agentsandbox_enterprise_agent_governance_framework_v1\")."]
    }
  },
  {
    id: "t4_agentsandbox_capstone_full_spectrum_agent_defense",
    tier: 4, cat: "capstone", track: "agentsandbox", points: 250, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "통합 캡스톤: 자율 에이전트 도구 포이즈닝부터 커널 Landlock/eBPF 샌드박싱 종합 방어",
      en: "Capstone: Full-Spectrum AI Agent MCP Security & Kernel Sandboxing Defense"
    },
    prompt: {
      ko: "MCP 도구 포이즈닝 탐지, Confused Deputy 셸 탈출 차단, Linux Landlock LSM 비특권 파일 격리, eBPF Dual-LLM 실시간 가드레일 집행을 망라하는 차세대 엔드투엔드 AI 방어 시스템을 완성합니다.\n지정된 식별자 `agentsandbox_capstone_full_spectrum_agent_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"agentsandbox_capstone_full_spectrum_agent_defense_v1\") 앞 20자리}`",
      en: "Synthesize full-spectrum defenses: MCP schema auditing, Confused Deputy mitigation, unprivileged Landlock LSM containment, and in-kernel eBPF Dual-LLM shields.\nCompute first 20 hex chars of SHA256(\"agentsandbox_capstone_full_spectrum_agent_defense_v1\").\n\nFormat: `FLAG{SHA256(\"agentsandbox_capstone_full_spectrum_agent_defense_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["데이터 계층의 스키마 검증과 호스트 계층의 커널 샌드박싱이 결합될 때 완벽한 제로 트러스트 자율 에이전트 환경이 완성됩니다.", "식별자 `agentsandbox_capstone_full_spectrum_agent_defense_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Holistic AI resilience unifies application-level schema governance with host kernel-level LSM confinement.", "Extract first 20 hex characters of SHA256(\"agentsandbox_capstone_full_spectrum_agent_defense_v1\")."]
    }
  }
];

const processedChallenges = challengesDef.map(ch => {
  return {
    ...ch,
    hash: computeHash(ch.id)
  };
});

const outPath = path.join(__dirname, 'track66_challenges.json');
fs.writeFileSync(outPath, JSON.stringify(processedChallenges, null, 2), 'utf8');
console.log(`Generated 35 challenges for Track 66: agentsandbox at ${outPath}`);
