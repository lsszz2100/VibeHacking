# Lab 47: AgentGuard — AI 에이전트 & MCP 보안 실전 실습 환경

## 1. 개요
* **서비스 포트**: `8047`
* **관련 챕터**: `69_LLM_Security/07_mcp_agent_tool_poisoning_and_sandbox_deepdive.md`
* **주요 목표**:
  1. RAG 간접 프롬프트 주입(IPI)을 통한 에이전트 도구 호출 가로채기
  2. 악성 MCP 서버의 Tool Shadowing 및 토큰 유출 차단
  3. Confused Deputy 파라미터 변조 권한 상승 방어
  4. Dual LLM 가드레일 및 Landlock 샌드박스 보안 통제 활성화

## 2. 실습 실행
```bash
vhack lab start 47
vhack lab test 47
vhack solve 47
```
