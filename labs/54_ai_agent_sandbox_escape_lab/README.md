# Lab 54: AgentSandboxGuard — AI 에이전트 MCP 샌드박스 탈출 & Landlock LSM / eBPF 방어 실습

## 실습 개요
생성형 AI 및 Model Context Protocol(MCP) 기반 자율 에이전트 환경에서 발생하는 신뢰되지 않은 도구 조작(Tool Poisoning), 권한 대행 취약점(Confused Deputy), 셸 서브프로세스 탈출(Subprocess Escape) 공격을 분석하고, Linux 커널 레벨의 비특권 파일시스템 샌드박싱(Landlock LSM) 및 런타임 시스템콜 후킹 차단(eBPF Dual-LLM Guardrail) 방어 체계를 실습합니다.

- **기본 포트**: `8054`
- **카테고리**: `ai` / `llm_security` / `kernel_hardening`
- **난이도**: ★★★★★
- **연계 교재**: `69_LLM_Security/08_ai_agent_sandbox_escape_and_landlock_defense_deepdive.md`
- **워게임 트랙**: `agentsandbox` (Track 66)

## 실습 단계 (Stages)
1. **Stage 1 (MCP Tool Poisoning & Shadowing)**:
   - 외부 비신뢰 데이터 주입을 통한 MCP 도구 스키마 오염 및 임의 매개변수 변조 공격 실증
   - 플래그: `FLAG{MCP_TOOL_POISONING_HIJACK_DEFLECTED_5401}`
2. **Stage 2 (Confused Deputy & Subprocess Escape)**:
   - 에이전트의 높은 권한을 악용한 내부 시스템 명령어 실행 및 호스트 환경변수/중요 파일 탈출 시도
   - 플래그: `FLAG{CONFUSED_DEPUTY_ESCAPE_VECTOR_CONTAINED_5402}`
3. **Stage 3 (Landlock LSM Unprivileged Sandboxing)**:
   - Linux Landlock LSM ruleset을 구성하여 비특권 에이전트 프로세스의 비인가 디렉터리(`/etc`, `/proc`, `/root`) 접근 차단
   - 플래그: `FLAG{LANDLOCK_LSM_FILE_SANDBOXING_ENFORCED_5403}`
4. **Stage 4 (eBPF Dual-LLM Guardrail & Runtime Enforcement)**:
   - 인커널 eBPF LSM 센서 및 보조 검증 모델을 연동한 실시간 도구 호출 및 시스템콜 인라인 차단 무력화 검증
   - 플래그: `FLAG{EBPF_DUAL_LLM_RUNTIME_SHIELD_ACTIVE_5404}`

## 빠른 실행
```bash
python3 vhack.py lab start 54
# 웹 콘솔: http://localhost:8054
```
