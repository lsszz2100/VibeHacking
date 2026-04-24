# 31. AI/ML 시스템 보안 — 모델 자체가 표적이 될 때

> **섹션 11과의 차이**: 11번은 "AI를 공격 도구로 쓰는" 관점이고, 이 섹션은 **AI/ML 시스템 자체가 공격 표적**이 되는 관점입니다.
> 모델·프롬프트·학습 데이터·에이전트 파이프라인에서 발생하는 고유한 위협과 방어를 다룹니다.

## 왜 별도 섹션인가

2024–2026년 사이 프로덕션 LLM과 에이전트가 일반 사용자 제품까지 흘러들어오면서,
공격 표면이 "모델의 가중치"에서 "에이전트가 접근하는 모든 외부 입력"으로 확장되었습니다.
기존 웹/시스템 보안 지식만으로는 다음 질문에 답할 수 없습니다.

- 첨부된 PDF 한 장으로 회사 LLM이 내부 이메일을 유출하는 경로는?
- 고객이 올린 이미지에 사람 눈에 안 보이는 노이즈가 섞이면 분류 모델이 어떻게 뚫리는가?
- 블랙박스 API만 호출해서 원본 모델을 훔칠 수 있을까? 몇 회 호출이면?
- RAG 검색기에 들어간 "오염된 문서 1건"이 전체 답변 품질을 어디까지 무너뜨리는가?

이 섹션은 각 질문의 위협 모델(threat model)과 **재현 가능한 PoC**, 그리고 실전에서 먹히는 완화책을 묶어 정리합니다.

## 목차

| # | 파일 | 주제 | 난이도 |
|---|------|------|--------|
| 01 | [adversarial_examples.md](01_adversarial_examples.md) | 적대적 예제 — FGSM·PGD·C&W, 전이 공격, 방어 전략 | ★★★ |
| 02 | [prompt_injection_jailbreak.md](02_prompt_injection_jailbreak.md) | 프롬프트 인젝션·간접 인젝션·탈옥·시스템 프롬프트 유출 | ★★★ |
| 03 | [model_extraction_inversion.md](03_model_extraction_inversion.md) | 모델 추출·멤버십 추론·데이터 재구성 | ★★★★ |
| 04 | [llm_agent_security.md](04_llm_agent_security.md) | 도구 사용 에이전트·RAG 중독·MCP 보안 | ★★★★ |

## 학습 목표

이 섹션을 끝내면 다음을 직접 수행할 수 있습니다.

- 이미지 분류기에 **사람이 인지하지 못하는 섭동(ε ≤ 8/255)** 을 주입해 오분류를 유도하고, 그 방어로 adversarial training을 구현한다.
- **직접 프롬프트 인젝션**과 **간접(문서·웹페이지 경유) 프롬프트 인젝션**을 구분하고, 각각에 대한 입력·출력 가드레일을 설계한다.
- 블랙박스 API에 대한 **쿼리 효율적 모델 추출**을 재현하고, 쿼리 레이트 제한·출력 교란으로 방어한다.
- RAG 파이프라인에 들어간 **오염된 단일 문서**가 임베딩 유사도를 어떻게 왜곡시키는지 실험하고, 검색 단계에서 차단한다.

## 위협 모델 맵 (한눈에 보기)

```
          [입력 단계]                [학습/인덱싱]              [추론/출력]
  ┌───────────────────────┐   ┌──────────────────────┐   ┌────────────────────┐
  │ - 적대적 예제         │   │ - 학습 데이터 오염   │   │ - 프롬프트 인젝션  │
  │ - 회피 공격           │   │ - 백도어 트리거      │   │ - 탈옥             │
  │ - 물리 세계 패치      │   │ - RAG 인덱스 오염    │   │ - 시스템 프롬프트  │
  │                       │   │                      │   │   유출             │
  └───────────────────────┘   └──────────────────────┘   └────────────────────┘
           │                           │                           │
           └──── 공통 방어 ────────────┴──────── 공통 방어 ─────────┘
              - 입력 정규화/검증     - 데이터 출처 검증           - 출력 검증·샌드박싱
              - 랜덤화 스무딩        - 학습 데이터 해시 고정      - 가드레일 + 외부 승인
```

## 이 섹션에서 쓰는 도구

- **PyTorch 2.3+** — 적대적 예제 구현
- **transformers / accelerate** — LLM 로딩
- **adversarial-robustness-toolbox (ART)** — IBM의 방어 평가 라이브러리
- **garak** — LLM 취약점 스캐너 (NVIDIA)
- **PyRIT** — Microsoft의 LLM 레드팀 프레임워크
- **llm-guard, prompt-armor** — 입출력 가드레일
- **sentence-transformers, faiss-cpu** — RAG 공격 재현

설치:

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install "torch>=2.3" "transformers>=4.40" adversarial-robustness-toolbox \
            garak pyrit llm-guard sentence-transformers faiss-cpu rich typer
```

## 참고 자료 (원문 링크)

- OWASP **Top 10 for LLM Applications** v1.1 / 2025 draft
- NIST **AI 100-2 E2023**: Adversarial Machine Learning Taxonomy
- MITRE **ATLAS** — AI 공격 전술·기법 매트릭스 (ATT&CK의 AI 버전)
- Greshake et al., *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* (2023)
- Carlini et al., *Extracting Training Data from Large Language Models* (USENIX Security 2021)

## 연관 섹션

- [11. AI 기반 사이버보안](../11_AI_Powered_Security/) — AI를 공격 도구로 사용
- [18. DevSecOps](../18_DevSecOps/) — AI 파이프라인의 CI/CD 보안
- [25. 위협 인텔리전스](../25_Threat_Intelligence/) — AI 공격자 트렌드
