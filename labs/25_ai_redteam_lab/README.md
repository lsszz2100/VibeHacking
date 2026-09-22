# Lab 25: AIRedGuard - AI Red Teaming & Agent Jailbreak Lab

> **난이도**: ★★★★☆ | **포트**: `8025` | **연계 교재**: `56_AI_Red_Teaming`, `69_LLM_Security` | **워게임 트랙**: `airedteam`

---

## 1. 개요

현대 엔터프라이즈 환경에서는 LLM이 단순 텍스트 생성을 넘어 외부 데이터베이스(RAG), 검색 엔진, 클라우드 API, 그리고 로컬 셸을 자율적으로 제어하는 **에이전틱 AI(Agentic AI)**로 급격히 진화하고 있습니다.
본 실습 랩은 공격자가 프롬프트 주입(Prompt Injection), 적대적 토큰 조작(Adversarial Token Obfuscation), MCP 도구 섀도잉(Tool Shadowing)을 통해 AI 에이전트의 보안 가드레일을 우회하고 권한을 탈취하는 실전 공격 시나리오와, 이를 방어하기 위한 계층화된 검증 메커니즘을 시뮬레이션합니다.

---

## 2. 3단계 실습 목표 및 플래그 챌린지

### Step 1: 간접 프롬프트 인젝션 (Indirect Prompt Injection & Context Contamination)
- **엔드포인트**: `POST /api/chat/rag`
- **공격 시나리오**: RAG 외부 문서(`doc3`) 내부에 은닉된 공격자 지시문(`[INDIRECT_INJECTION: ...]`)이 에이전트의 컨텍스트를 오염시켜 기밀 Corporate Vault Token을 유출하도록 유도합니다.
- **방어 메커니즘**: `enable_sanitizer=True` 파라미터를 통해 외부 주입 패턴을 정제하고 엄격한 입력 경계 마커(Delimiters)를 강제합니다.
- **플래그**: `FLAG{indirect_prompt_injection_rag_taint_unlocked_9102}`

### Step 2: 적대적 토큰 및 가드레일 우회 (Adversarial Token & Semantic Evasion)
- **엔드포인트**: `POST /api/eval/guardrail`
- **공격 시나리오**: 단순 키워드 블랙리스트(`jailbreak`, `exploit` 등)를 우회하기 위해 제로 위드 스페이스(Zero-Width Space `\u200b`) 및 토큰 분할(Delimited Split)을 적용하여 적대적 프롬프트를 전송합니다.
- **방어 메커니즘**: `enable_semantic_defense=True`를 통해 NFKC 유니코드 정규화, 보이지 않는 문자 제거 및 의미론적 임베딩 거리 분석을 수행하여 난독화된 악성 패턴을 차단합니다.
- **플래그**: `FLAG{adversarial_token_guardrail_bypass_verified_4819}`

### Step 3: MCP 도구 섀도잉 및 에이전트 샌드박스 (Tool Shadowing & Sandboxing)
- **엔드포인트**: `POST /api/agent/dispatch`
- **공격 시나리오**: 에이전트가 안전한 일반 도구 대신 비인가된 악성 섀도우 특권 도구(`shadow_system_exec`)를 자율 호출하도록 유도하여 시스템 명령 실행을 시뮬레이션합니다.
- **방어 메커니즘**: `enable_sandbox=True`를 적용하여 Capabilities 기반 암호학적 토큰(`CAP_TOKEN_VERIFIED_7719`) 미보유 시 특권 도구 호출을 커널/런타임 수준에서 즉각 차단합니다.
- **플래그**: `FLAG{mcp_tool_shadowing_agent_sandbox_contained_7341}`

---

## 3. 실행 및 테스트

```bash
# 컨테이너 빌드 및 가동
docker compose up -d

# CLI 자동 솔버를 통한 익스플로잇 시뮬레이션
vhack solve 25 --step 1
vhack solve 25 --step 2
vhack solve 25 --step 3

# 단위 테스트 전수 검증
pytest labs/25_ai_redteam_lab/tests/test_ai_redteam_lab.py
```
