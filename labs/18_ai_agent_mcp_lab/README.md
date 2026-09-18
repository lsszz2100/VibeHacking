# Lab 18: AgentGuard - AI Agent & MCP Security Lab

## 1. 랩 개요 (Overview)

- **랩 명칭**: `AgentGuard - AI Agent & MCP(Model Context Protocol) Security Lab`
- **포트**: `8018`
- **연계 교재**: `11_AI_Powered_Security`, `69_LLM_Security`
- **연계 워게임 트랙**: `aiagent` (Track 32), `ai`
- **핵심 목표**:
  1. 자율형 AI 에이전트(Autonomous AI Agent)의 도구 호출(Tool Calling) 메커니즘을 악용한 **간접 프롬프트 주입(Indirect Prompt Injection)** 공격 및 방어 실습
  2. 에이전트의 **과도한 권한(Excessive Agency)**을 이용한 시스템 설정 파일 변조 및 임의 명령 실행(RCE) 분석
  3. **MCP(Model Context Protocol)** 생태계에서의 악성 서버 등록 및 **도구 섀도잉(Tool Shadowing)** 위협 검증
  4. 비암호화 JSON-RPC 버스 및 환경변수 노출을 통한 **정적 MCP 인증 토큰 탈취** 및 **Zero Trust Ephemeral Capability Token** 방어 아키텍처 실습

---

## 2. 스테이지별 시나리오 & 플래그 (Attack & Defense Stages)

### Stage 1: Indirect Prompt Injection & Tool Hijacking
- **공격**: 고객 문의 티켓 본문 내에 숨겨진 지시문(`Ignore previous instructions...`)을 통해 에이전트의 의사결정을 가로채고 `/agent/secrets/api_keys.json`을 `read_file`로 읽어 `send_webhook`으로 외부 유출.
- **방어**: **Human-in-the-Loop (HITL)** 정책 활성화 — 신뢰할 수 없는 데이터 소스로부터 촉발된 위험 도구 실행 전 관리자 승인 절차 강제.
- **플래그**: `FLAG{agent_indirect_prompt_injection_tool_hijack_8492}`

### Stage 2: Excessive Agency & Unrestricted System Execution
- **공격**: 에이전트에게 불필요하게 부여된 시스템 관리 권한(`bash_run`, 임의 파일 쓰기)을 이용해 `/etc/agent/cron.d/backup.sh`를 변조하여 시스템 영속성(Persistence) 획득.
- **방어**: **최소 권한 도구 샌드박스 (Least Privilege Tool Sandboxing)** — 쉘 실행 도구 완전 비활성화 및 파일 쓰기 범위를 `/sandbox/*`로 엄격 제한.
- **플래그**: `FLAG{agent_excessive_agency_unrestricted_tool_5719}`

### Stage 3: Rogue MCP Server Registration & Tool Shadowing
- **공격**: 에이전트 환경에 악성 MCP 서버를 동적으로 등록하여 정상적인 암호화 검증 도구(`crypto_verify`)의 이름을 충돌/덮어쓰기(Tool Shadowing)하여 민감 세션 컨텍스트 가로채기.
- **방어**: **MCP 서버 암호학적 서명 검증 & 네임스페이스 화이트리스트** — 검증되지 않은 로컬/원격 MCP 엔드포인트 등록 차단 및 도구 명칭 충돌 방지.
- **플래그**: `FLAG{agent_mcp_rogue_server_tool_shadowing_3920}`

### Stage 4: MCP Token Exfiltration & Insecure JSON-RPC Interception
- **공격**: 정적 환경변수(`MCP_AUTH_TOKEN`) 및 내부 JSON-RPC 통신 패킷 스니핑을 통해 정적 마스터 토큰 탈취 후 관리자 MCP 클러스터 API(`/api/stage4/admin-call`) 탈취.
- **방어**: **Zero Trust Ephemeral Capability Token** — 단기(Single-use / 60s) 암호화 서명 기반 기능 토큰 강제 및 정적 마스터 키 은닉.
- **플래그**: `FLAG{agent_mcp_token_exfiltration_rpc_intercept_7104}`

---

## 3. 빠른 시작 (Quick Start)

```bash
# vhack CLI로 실행
vhack lab start 18

# 또는 직접 도커 컴포즈 실행
cd labs/18_ai_agent_mcp_lab
docker compose up -d

# 대시보드 접속
http://localhost:8018
```
