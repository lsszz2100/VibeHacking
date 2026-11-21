#!/usr/bin/env python3
"""
Generator for Track 84: agentmem (AI Agent Long-Term Context Memory & Knowledge Graph Poisoning Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,940 challenges milestone across 84 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "long_term_memory_threat_model",
        "title_ko": "AI 에이전트 장기 메모리 및 지식 그래프 위협 모델",
        "title_en": "AI Agent Long-Term Memory & Knowledge Graph Threat Model",
        "desc_ko": "장기 기억(Episodic, Semantic Vector, GraphRAG) 아키텍처에서 발생하는 지속성 공격 표면과 잠복 지침 위협을 분석합니다.",
        "desc_en": "Analyze persistence attack surfaces and latent instruction threats across episodic, semantic vector, and GraphRAG architectures."
    },
    {
        "tier": 0, "points": 25, "slug": "vector_store_embedding_foundations",
        "title_ko": "벡터 저장소 임베딩 생성 및 코사인 유사도 검색 원리",
        "title_en": "Vector Store Embedding Generation & Cosine Similarity Search Principles",
        "desc_ko": "문맥 청크의 고차원 벡터 임베딩 변환 및 최근접 이웃(KNN) 기반 코사인 유사도 검색 인출 메커니즘을 학습합니다.",
        "desc_en": "Study high-dimensional vector embedding transformation of context chunks and KNN cosine similarity retrieval mechanics."
    },
    {
        "tier": 0, "points": 25, "slug": "episodic_context_retrieval_risks",
        "title_ko": "에피소딕 컨텍스트 저장과 비신뢰 데이터 인입 위험성",
        "title_en": "Episodic Context Persistence & Untrusted Input Ingestion Hazards",
        "desc_ko": "외부 대화 입력이 정제 없이 에이전트 장기 기억에 축적될 때 발생하는 인지 오염 및 교차 세션 오작동 위험을 파악합니다.",
        "desc_en": "Examine cognitive contamination and cross-session malfunction hazards from ingesting unscrubbed external inputs into episodic stores."
    },
    {
        "tier": 0, "points": 25, "slug": "knowledge_graphrag_schema_basics",
        "title_ko": "GraphRAG 지식 그래프 트리플렛 구조 및 노드 신뢰도",
        "title_en": "GraphRAG Knowledge Graph Triplet Structure & Node Trustworthiness",
        "desc_ko": "엔터티-관계-엔터티 트리플렛 그래프 구조와 지식 그래프 인덱싱 시 신뢰도 가중치 부여 원리를 분석합니다.",
        "desc_en": "Analyze entity-relationship-entity triplet graph representations and trust weight assignment during knowledge graph indexing."
    },
    {
        "tier": 0, "points": 25, "slug": "session_provenance_attestation_theory",
        "title_ko": "세션 출처(Provenance) 및 암호학적 메모리 서명 이론",
        "title_en": "Session Provenance & Cryptographic Memory Attestation Theory",
        "desc_ko": "기억 노드 생성 주체와 세션 무결성을 암호학적으로 바인딩하는 출처 증명 이론과 해시 체이닝 구조를 학습합니다.",
        "desc_en": "Learn provenance attestation theory and hash-chaining structures cryptographically binding memory creation to authentic sessions."
    },
    {
        "tier": 0, "points": 25, "slug": "sleeper_prompt_latent_trigger_mechanisms",
        "title_ko": "슬리퍼 프롬프트 잠복 패턴 및 지연 인출 메커니즘",
        "title_en": "Sleeper Prompt Latent Patterns & Delayed Retrieval Mechanisms",
        "desc_ko": "평상시 휴면 상태를 유지하다가 특정 관리자 질의 인입 시 코사인 유사도에 의해 활성화되는 지연 트리거 패턴을 탐색합니다.",
        "desc_en": "Explore delayed trigger patterns remaining dormant until activated by specific administrative queries matching cosine thresholds."
    },
    {
        "tier": 0, "points": 25, "slug": "dual_observer_cognitive_firewall_intro",
        "title_ko": "이중 관찰자 인지 방화벽 및 메모리 격리 아키텍처",
        "title_en": "Dual-Observer Cognitive Firewall & Memory Partition Architecture",
        "desc_ko": "에이전트 실행 파이프라인과 독립된 보조 인지 모델이 인출된 컨텍스트의 안전성을 상호 검증하는 격리 아키텍처를 이해합니다.",
        "desc_en": "Understand partitioned architectures where an independent auxiliary cognitive model verifies retrieved contexts before execution."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "context_injection_boundary_validation",
        "title_ko": "메모리 인입 데이터 경계 검증 및 메타데이터 정제",
        "title_en": "Memory Ingestion Boundary Validation & Metadata Sanitization",
        "desc_ko": "에피소딕 메모리에 저장되기 전 프롬프트 구분자 및 시스템 지침 메타데이터를 정규식으로 박멸하는 경계 필터를 구현합니다.",
        "desc_en": "Implement boundary filters stripping prompt delimiters and system instruction metadata before episodic storage."
    },
    {
        "tier": 1, "points": 50, "slug": "hmac_memory_node_signature_check",
        "title_ko": "HMAC-SHA256 메모리 노드 무결성 서명 및 세션 바인딩",
        "title_en": "HMAC-SHA256 Memory Node Signature & Session Cryptographic Binding",
        "desc_ko": "메모리 노드 저장 시 마스터키 기반 HMAC-SHA256 토큰을 발행하고 인출 시 변조 여부를 0-오차로 검증합니다.",
        "desc_en": "Issue master-key HMAC-SHA256 tokens upon memory insertion and verify integrity with zero tolerance upon retrieval."
    },
    {
        "tier": 1, "points": 50, "slug": "cosine_anomaly_drift_telemetry",
        "title_ko": "시맨틱 벡터 코사인 드리프트 및 이상치 탐지 텔레메트리",
        "title_en": "Semantic Vector Cosine Drift & Outlier Anomaly Telemetry",
        "desc_ko": "정상적인 지식 클러스터 중심점으로부터 비정상적으로 편향된 적대적 임베딩 벡터의 코사인 거리 이상치를 감지합니다.",
        "desc_en": "Detect cosine distance outliers in adversarial embeddings drifting aberrantly from legitimate knowledge cluster centroids."
    },
    {
        "tier": 1, "points": 50, "slug": "untrusted_node_quarantine_enforcement",
        "title_ko": "비신뢰 외부 입력 노드 격리 파티셔닝 강제",
        "title_en": "Untrusted Input Node Quarantine Partitioning Enforcement",
        "desc_ko": "외부 웹 및 사용자 입력에서 생성된 메모리 노드를 비신뢰(Untrusted)로 분류하여 특권 작업 인출에서 강제 배제합니다.",
        "desc_en": "Enforce untrusted tagging on external web/user memory nodes, strictly quarantining them from privileged executive tasks."
    },
    {
        "tier": 1, "points": 50, "slug": "knowledge_graph_relationship_audit",
        "title_ko": "지식 그래프 엔터티 관계 엣지 및 권한 불변성 감사",
        "title_en": "Knowledge Graph Entity Relation Edge & Privilege Immutability Audit",
        "desc_ko": "GraphRAG 지식 그래프 내에서 인가되지 않은 권한 부여 관계 엣지 생성을 동적으로 탐지하고 차단합니다.",
        "desc_en": "Dynamically audit and intercept unauthorized privilege relationship edges generated within the GraphRAG knowledge graph."
    },
    {
        "tier": 1, "points": 50, "slug": "episodic_reclamation_and_scrubbing",
        "title_ko": "메모리 회수(Reclamation) 및 잔류 컨텍스트 소각 루틴",
        "title_en": "Memory Reclamation & Residual Context Scrubbing Routine",
        "desc_ko": "세션 종료 시 휘발성 컨텍스트 버퍼를 제로화(Zeroization)하고 회수된 메모리 슬롯의 데이터 잔류를 영구 소각합니다.",
        "desc_en": "Zeroize volatile context buffers upon session closure and scrub reclaimed memory slots to eliminate residual data."
    },
    {
        "tier": 1, "points": 50, "slug": "agent_task_executor_prompt_boundary",
        "title_ko": "에이전트 태스크 실행기 프롬프트 격리 경계 보호",
        "title_en": "Agent Task Executor Prompt Isolation Boundary Protection",
        "desc_ko": "인출된 장기 메모리 텍스트를 실행 프롬프트에 주입할 때 샌드박스 인클로저로 감싸 실행 지침 오염을 방지합니다.",
        "desc_en": "Enclose retrieved long-term memory texts in sandbox delimiters when injecting into task executor prompts."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "adversarial_embedding_collision_analysis",
        "title_ko": "적대적 임베딩 충돌 및 의미론적 하이재킹 분석",
        "title_en": "Adversarial Embedding Collision & Semantic Hijacking Analysis",
        "desc_ko": "임베딩 공간 상에서 관리자 시스템 프롬프트와 극도로 가까운 거리를 갖도록 조작된 적대적 텍스트 충돌 공격을 분석합니다.",
        "desc_en": "Analyze adversarial collision attacks crafted to achieve minimal distance to administrator prompt vectors in embedding space."
    },
    {
        "tier": 2, "points": 100, "slug": "covert_sleeper_instruction_defusal",
        "title_ko": "잠복형 슬리퍼 지침 탐지 및 프롬프트 인젝션 중화",
        "title_en": "Covert Sleeper Instruction Detection & Prompt Injection Defusal",
        "desc_ko": "메모리 청크 내에 침투된 지연형 시스템 오버라이드 지시어를 신경망 인지 필터로 분석하여 사전에 무력화합니다.",
        "desc_en": "Examine and defuse covert delayed system override instructions embedded within memory chunks using neural cognitive filters."
    },
    {
        "tier": 2, "points": 100, "slug": "graphrag_triplet_poison_containment",
        "title_ko": "GraphRAG 트리플렛 위조 탐지 및 악성 엣지 차단",
        "title_en": "GraphRAG Triplet Forgery Detection & Malicious Edge Containment",
        "desc_ko": "공격자가 주입한 가짜 관리자 역할 부여 트리플렛 노드를 식별하고 그래프 추론 경로에서 즉각 차단합니다.",
        "desc_en": "Identify spoofed administrative role triplet nodes injected by adversaries and sever them from graph inference paths."
    },
    {
        "tier": 2, "points": 100, "slug": "session_key_rotation_memory_reencryption",
        "title_ko": "세션 마스터키 교체에 따른 장기 메모리 재암호화",
        "title_en": "Session Master Key Rotation & Long-Term Memory Re-Encryption",
        "desc_ko": "주기적 세션 키 로테이션 시 기존 벡터 및 그래프 메모리 블록을 새로운 HMAC 키로 재암호화하고 검증합니다.",
        "desc_en": "Re-encrypt and verify existing vector and graph memory blocks under new HMAC keys during periodic session key rotation."
    },
    {
        "tier": 2, "points": 100, "slug": "cross_agent_context_isolation_audit",
        "title_ko": "멀티 에이전트 간 컨텍스트 메모리 교차 유출 감사",
        "title_en": "Cross-Agent Context Memory Leak Audit & Boundary Verification",
        "desc_ko": "스웜 에이전트 간 공유 메모리 인덱스에서 권한이 서로 다른 워커 간의 컨텍스트 오염 및 정보 누출을 감사 통제합니다.",
        "desc_en": "Audit and enforce context separation across shared memory indexes to prevent contamination between different worker agents."
    },
    {
        "tier": 2, "points": 100, "slug": "dynamic_cognitive_firewall_policy",
        "title_ko": "동적 인지 방화벽 룰셋 컴파일 및 시스템 지침 보호",
        "title_en": "Dynamic Cognitive Firewall Policy Compilation & System Prompt Shield",
        "desc_ko": "에이전트 인출 컨텍스트에 포함될 수 없는 위험 토큰 룰셋을 동적으로 컴파일하여 시스템 코어 지침을 보호합니다.",
        "desc_en": "Dynamically compile cognitive firewall rule sets restricting dangerous token classes from retrieved agent contexts."
    },
    {
        "tier": 2, "points": 100, "slug": "vector_db_multi_tenant_segregation",
        "title_ko": "벡터 데이터베이스 멀티 테넌트 인덱스 분리 검증",
        "title_en": "Vector Database Multi-Tenant Index Segregation Verification",
        "desc_ko": "단일 벡터 DB 인스턴스 내에서 테넌트 네임스페이스 및 메타데이터 필터링 강제를 통해 교차 테넌트 인출을 원천 방어합니다.",
        "desc_en": "Enforce strict tenant namespace and metadata filtering within vector databases to block cross-tenant context retrieval."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "latent_trigger_activation_evasion_probe",
        "title_ko": "지연 폭탄 트리거 활성화 회피 기법 분석 및 방어",
        "title_en": "Latent Trigger Activation Evasion Analysis & Defense",
        "desc_ko": "다단계 논리 연쇄(Multi-Hop Reasoning)를 거쳐 은밀하게 시스템 권한을 획득하려는 지연 인젝션 기법을 정밀 분석합니다.",
        "desc_en": "Probe delayed injection techniques exploiting multi-hop reasoning chains to covertly escalate system authority."
    },
    {
        "tier": 3, "points": 200, "slug": "semantic_embedding_watermarking_guard",
        "title_ko": "시맨틱 임베딩 워터마킹 및 무단 변조 탐지 가드",
        "title_en": "Semantic Embedding Watermarking & Tampering Detection Guard",
        "desc_ko": "고차원 임베딩 벡터에 암호학적 워터마크 신호를 분산 인코딩하여 외부 주입이나 데이터 오염을 실시간 검증합니다.",
        "desc_en": "Dispersively encode cryptographic watermarks across high-dimensional embedding vectors to detect unauthorized injection."
    },
    {
        "tier": 3, "points": 200, "slug": "graph_topology_permission_invariant",
        "title_ko": "지식 그래프 위상 권한 불변성 수학적 증명 검증",
        "title_en": "Knowledge Graph Topological Privilege Invariant Proof Verification",
        "desc_ko": "지식 그래프의 권한 위상학적 불변식을 형식 증명 기법으로 대조하여 변조된 인접 행렬을 즉시 거부합니다.",
        "desc_en": "Validate topological privilege invariants in knowledge graphs using formal proofs to reject tampered adjacency matrices."
    },
    {
        "tier": 3, "points": 200, "slug": "dual_observer_cognitive_arbitration",
        "title_ko": "이중 관찰자 독립 검증 엔진 및 인출 컨텍스트 중재",
        "title_en": "Dual-Observer Independent Verification Engine & Retrieval Arbitration",
        "desc_ko": "서로 다른 아키텍처의 두 인지 엔진이 인출된 메모리의 의도를 병렬 교차 평가하여 일치할 때만 인출을 승인합니다.",
        "desc_en": "Cross-evaluate retrieved memory intent in parallel across dual heterogeneous cognitive engines, arbitrating on consensus."
    },
    {
        "tier": 3, "points": 200, "slug": "ephemeral_context_zeroization_pipeline",
        "title_ko": "임시 컨텍스트 파이프라인 제로화 및 누출 원천 방지",
        "title_en": "Ephemeral Context Pipeline Zeroization & Leak Prevention",
        "desc_ko": "인출 후 사용된 단기 메모리 파이프라인 버퍼를 암호학적으로 제로화하여 메모리 덤프 공격에 의한 누출을 방지합니다.",
        "desc_en": "Cryptographically zeroize short-term retrieval pipeline buffers after execution to prevent memory dump exfiltration."
    },
    {
        "tier": 3, "points": 200, "slug": "secure_memory_compaction_and_summarization",
        "title_ko": "안전한 메모리 요약·압축 및 적대적 잔류물 제거",
        "title_en": "Secure Memory Summarization, Compaction & Adversarial Residue Purging",
        "desc_ko": "장기 메모리 요약 압축 과정에서 요약 모델이 적대적 지시어를 증폭하거나 계승하지 않도록 정제 루프를 적용합니다.",
        "desc_en": "Apply recursive sanitization during memory summarization to prevent compression models from inheriting hostile directives."
    },
    {
        "tier": 3, "points": 200, "slug": "autonomous_privilege_escalation_interception",
        "title_ko": "장기 기억 기반 자율 권한 상승 행위 실시간 차단",
        "title_en": "Long-Term Memory Autonomous Privilege Escalation Interception",
        "desc_ko": "오염된 기억을 바탕으로 에이전트가 관리자 명령을 자율 발행하려는 이상 징후를 시스템 콜 경계에서 차단합니다.",
        "desc_en": "Intercept anomalous autonomous administrative command issuances at system call boundaries triggered by poisoned memories."
    },

    # Tier 4 (7 challenges, 400 points each)
    {
        "tier": 4, "points": 400, "slug": "capstone_agentic_memory_adversarial_drill",
        "title_ko": "[Capstone] 장기 메모리 오염 대항 실전 자율 공방 훈련",
        "title_en": "[Capstone] Agentic Memory Poisoning Adversarial Red-Blue Drill",
        "desc_ko": "실전 공격 체인(잠복형 슬리퍼 주입, 임베딩 충돌, 그래프 변조)에 맞서 메모리 정제, HMAC 증명, 인지 방화벽 전 과정을 통합 실증합니다.",
        "desc_en": "Validate integrated defenses spanning memory sanitization, HMAC attestation, and cognitive firewalls against live attack chains."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_enterprise_graphrag_cognitive_shield",
        "title_ko": "[Capstone] 엔터프라이즈 GraphRAG 인지 방어 인프라 종합 구축",
        "title_en": "[Capstone] Enterprise GraphRAG Cognitive Defense Infrastructure Deployment",
        "desc_ko": "대규모 엔터프라이즈 GraphRAG 시스템에서 권한 위상 불변성, 트리플렛 출처 검증, 악성 엣지 격리 체계를 완성합니다.",
        "desc_en": "Deploy full enterprise GraphRAG defenses covering topological privilege invariants, triplet provenance, and edge isolation."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_zero_trust_memory_mesh_attestation",
        "title_ko": "[Capstone] 제로 트러스트 메모리 메시 암호학적 원격 증명 체계",
        "title_en": "[Capstone] Zero-Trust Memory Mesh Cryptographic Remote Attestation System",
        "desc_ko": "모든 분산 메모리 노드에 제로 트러스트 암호학적 출처 토큰을 강제하고 런타임 위변조를 실시간 원격 증명합니다.",
        "desc_en": "Mandate zero-trust cryptographic provenance tokens across distributed memory meshes with real-time remote attestation."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_neural_cognitive_firewall_hardening",
        "title_ko": "[Capstone] 신경망 인지 방화벽 및 시스템 프롬프트 철벽 방어",
        "title_en": "[Capstone] Neural Cognitive Firewall & System Prompt Impenetrable Shield",
        "desc_ko": "이중 관찰자 신경망 인지 방화벽을 가동하여 인출 컨텍스트의 모든 지연형 지시어와 적대적 유도 신호를 100% 무력화합니다.",
        "desc_en": "Deploy dual-observer neural cognitive firewalls neutralizing 100% of delayed directives and adversarial steering cues."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_multi_modal_context_provenance_defense",
        "title_ko": "[Capstone] 멀티모달 컨텍스트 메모리 출처 무결성 보증 아키텍처",
        "title_en": "[Capstone] Multi-Modal Context Memory Provenance Assurance Architecture",
        "desc_ko": "이미지·오디오 임베딩과 텍스트가 혼합된 멀티모달 장기 기억에서 스테가노그래피 및 은닉 프롬프트 주입을 원천 방어합니다.",
        "desc_en": "Defend multi-modal long-term memory spanning text, image, and audio embeddings from steganographic prompt injection."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_distributed_memory_byzantine_isolation",
        "title_ko": "[Capstone] 분산 에이전트 메모리 비잔틴 변조 및 노드 격리 캡스톤",
        "title_en": "[Capstone] Distributed Agent Memory Byzantine Fault & Node Isolation Capstone",
        "desc_ko": "비잔틴 변조된 악성 에이전트 노드가 분산 메모리 풀을 오염시키려 할 때 합의 알고리즘으로 오염 노드를 즉각 배제합니다.",
        "desc_en": "Isolate Byzantine-compromised agent nodes attempting to poison shared memory pools using cryptographic consensus algorithms."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_sovereign_ai_cognitive_infrastructure",
        "title_ko": "[Capstone] 주권 AI(Sovereign AI) 인지 인프라 전방위 장기 메모리 방어 체계",
        "title_en": "[Capstone] Sovereign AI Cognitive Infrastructure Full-Spectrum Memory Defense System",
        "desc_ko": "국가 핵심 AI 에이전트 시스템의 장기 메모리, 벡터 DB, GraphRAG를 잠복 침투로부터 영구 보호하는 최고도 주권 방어망을 확립합니다.",
        "desc_en": "Establish sovereign defense shields protecting critical AI agent long-term memory, vector DBs, and GraphRAG from latent sabotage."
    }
]

def main():
    repo_root = Path(__file__).resolve().parent.parent
    challenges_js_path = repo_root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = repo_root / "wargame" / "scripts" / "solve-derivable.js"
    readme_path = repo_root / "wargame" / "README.md"
    index_html_path = repo_root / "wargame" / "index.html"

    # 1. Prepare challenge objects
    new_challenges = []
    agentmem_ids = []

    for item in CHALLENGES_DATA:
        tier = item["tier"]
        slug = item["slug"]
        cid = f"t{tier}_agentmem_{slug}"
        ident = f"ch_agentmem_t{tier}_{slug}"
        
        # Deterministic flag derived from identifier
        computed_hash = hashlib.sha256(f"{ident}_vibe_agentmem_2026".encode()).hexdigest()[:20]
        flag = f"FLAG{{{computed_hash}}}"
        flag_sha256 = hashlib.sha256(flag.encode()).hexdigest()

        ch_obj = {
            "id": cid,
            "tier": tier,
            "cat": "ai",
            "track": "agentmem",
            "points": item["points"],
            "ci": False,
            "hash": flag_sha256,
            "fmt": "FLAG{...}",
            "title": {
                "ko": item["title_ko"],
                "en": item["title_en"]
            },
            "prompt": {
                "ko": f"AI 에이전트 장기 메모리 오염 및 지식 그래프 방어 실무를 수행합니다.\n\n주제: {item['title_ko']}\n상세 분석 지침:\n- {item['desc_ko']}\n- 에이전트 인지 메모리 오염 벡터 및 GraphRAG 위상 무결성을 정밀 감사하십시오.\n- 검증 식별자 AGENTMEM_CHALLENGE_ID: `{ident}`\n- 보안 정책 및 무결성 검증을 충족하여 정상 플래그를 획득하십시오.",
                "en": f"Conduct technical hands-on verification of agent memory poisoning and knowledge graph defense.\n\nTopic: {item['title_en']}\nAnalysis Requirements:\n- {item['desc_en']}\n- Thoroughly audit agent cognitive memory poisoning vectors and GraphRAG topological integrity.\n- Verification Identifier AGENTMEM_CHALLENGE_ID: `{ident}`\n- Satisfy the security parameters and retrieve the authorized flag."
            },
            "hints": {
                "ko": [
                    f"이 문제는 식별자 `{ident}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
                ],
                "en": [
                    f"This challenge derives a deterministic flag from identifier `{ident}`."
                ]
            }
        }
        new_challenges.append(ch_obj)
        agentmem_ids.append(ch_obj["id"])

    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 84 (agentmem).")

    # 2. Update wargame/assets/challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    
    # 2-A. Ensure agentmem track is in TRACKS array
    track_agentmem_def = """  {
    "id": "agentmem",
    "icon": "🧠",
    "ko": "AI 에이전트 장기 메모리 오염 & 지식 그래프 방어",
    "en": "Agent Long-Term Memory & Knowledge Graph Defense",
    "desc_ko": "에피소딕/벡터 메모리 시맨틱 코사인 유사도 하이재킹 차단·HMAC-SHA256 세션 출처(Provenance) 및 암호학적 메모리 노드 원격 증명·지식 그래프(GraphRAG) 권한 엣지 위조 및 슬리퍼 프롬프트 지연 폭탄 격리·이중 관찰자(Dual-Observer) 인지 메모리 격리 방화벽.",
    "desc_en": "Episodic and vector memory semantic cosine similarity hijacking mitigation, HMAC-SHA256 session provenance and cryptographic memory node remote attestation, GraphRAG knowledge graph permission edge tampering and sleeper prompt delayed injection isolation, and dual-observer cognitive memory firewall containment."
  }"""
    if '"id": "agentmem"' not in content[:content.find("const CHALLENGES =")]:
        needle = '"id": "gpusec"'
        assert needle in content, "Could not find gpusec in TRACKS"
        gpu_idx = content.find(needle)
        gpu_end_brace = content.find("}", gpu_idx)
        content = content[:gpu_end_brace+1] + ",\n" + track_agentmem_def + content[gpu_end_brace+1:]
        print("[+] Inserted agentmem track into TRACKS array.")

    # 2-B. Remove any previous agentmem challenges and cleanly insert
    marker = "// Track 84:"
    if marker in content:
        idx = content.find(marker)
        brace_idx = content.rfind("}", 0, idx)
        prefix = content[:brace_idx+1]
    else:
        last_bracket_idx = content.rfind("];")
        assert last_bracket_idx != -1, "Could not find ];"
        prefix = content[:last_bracket_idx].rstrip()
        while prefix.endswith(","):
            prefix = prefix[:-1].rstrip()
    
    entries_json = []
    for ch in new_challenges:
        entries_json.append("  " + json.dumps(ch, ensure_ascii=False, indent=2).replace("\n", "\n  "))

    joined_entries = ",\n  // Track 84: agentmem - AI Agent Long-Term Context Memory & Knowledge Graph Poisoning Defense (35 challenges)\n" + ",\n".join(entries_json)

    new_content = prefix + joined_entries + "\n];\n"
    challenges_js_path.write_text(new_content, encoding="utf-8")
    print("[+] Successfully inserted 35 agentmem challenges into wargame/assets/challenges.js!")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    
    derivable_ids_formatted = json.dumps(agentmem_ids, indent=2)
    dollar_hash = "${hash}"
    derivable_code = f"""const AGENTMEM_IDS = {derivable_ids_formatted};

for (const id of AGENTMEM_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/AGENTMEM_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_agentmem_2026').digest('hex').slice(0, 20);
      return `FLAG{{{dollar_hash}}}`;
    }}
  }});
}}
"""
    if "const AGENTMEM_IDS = [" in solve_content:
        solve_content = re.sub(r'const AGENTMEM_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing AGENTMEM_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added agentmem derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/index.html HUD
    index_html = index_html_path.read_text(encoding="utf-8")
    index_html = re.sub(r'0/\d{4}', '0/2940', index_html)
    index_html_path.write_text(index_html, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD to 0/2940.")

    # 5. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    readme = re.sub(r'\*\*2,905\*\*', '**2,940**', readme)
    readme = re.sub(r'\b2905\b', '2940', readme)
    
    # Update tier counts
    readme = re.sub(r'(\| Tier 0 \| 25 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>343\g<2>', readme)
    readme = re.sub(r'(\| Tier 1 \| 50 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>552\g<2>', readme)
    readme = re.sub(r'(\| Tier 2 \| 100 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>704\g<2>', readme)
    readme = re.sub(r'(\| Tier 3 \| 200 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>694\g<2>', readme)
    readme = re.sub(r'(\| Tier 4 \| 400 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>647\g<2>', readme)
    
    # Add agentmem rows to each tier table if not already present
    t0_row = '| `agentmem` 🧠 AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 (7) | 에피소딕 컨텍스트 저장 구조 · 벡터 저장소 투영 생성 · 지식 그래프 트리플렛 모델 · 세션 출처 증명 이론 / Episodic context storage structure, vector store projection generation, knowledge graph triplet model, and session provenance theory |'
    t1_row = '| `agentmem` 🧠 AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 (7) | 프롬프트 경계 토큰 정제 · HMAC-SHA256 메모리 무결성 토큰 · 시맨틱 코사인 편향 탐지 · 비신뢰 노드 격리 구획 강제 / Prompt boundary token sanitization, HMAC-SHA256 memory node authenticity tokens, semantic cosine drift telemetry, and untrusted node isolation containment |'
    t2_row = '| `agentmem` 🧠 AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 (7) | 적대적 투영 충돌 분석 · 잠복 지침 중화 필터 · 지식 그래프 위조 엣지 차단 · 세션 키 갱신 재암호화 / Adversarial projection collision analysis, latent instruction neutralization, knowledge graph forged edge containment, and session key re-encryption |'
    t3_row = '| `agentmem` 🧠 AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 (7) | 시맨틱 투영 워터마킹 · 위상 권한 불변성 검증 · 이중 관찰자 인출 중재 합의 · 임시 컨텍스트 제로화 / Semantic projection watermarking, topological privilege invariant verification, dual-observer retrieval consensus mediation, and ephemeral context zeroization |'
    t4_row = '| `agentmem` 🧠 AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 (7) | 에이전트 메모리 자율 공방 훈련 · 엔터프라이즈 GraphRAG 인지 방어 인프라 · 제로 트러스트 메모리 원격 증명 · 주권 AI 인지 인프라 전방위 장기 메모리 방어 캡스톤 / Agentic memory adversarial drill, enterprise GraphRAG cognitive defense infrastructure, zero-trust memory remote attestation, and sovereign AI cognitive infrastructure memory capstone |'

    # Find the 5 gpusec rows and append the corresponding agentmem row
    tier_rows = [t0_row, t1_row, t2_row, t3_row, t4_row]
    gpusec_matches = list(re.finditer(r'\| `gpusec` ⚡ AI 가속기 GPU 사이드채널 & VRAM 격리 방어 \(7\) \| [^\n]+', readme))
    if len(gpusec_matches) == 5:
        # Reconstruct from bottom to top to preserve indices
        for i in reversed(range(5)):
            m = gpusec_matches[i]
            if "agentmem" not in readme[m.end():m.end()+400]:
                readme = readme[:m.end()] + "\n" + tier_rows[i] + readme[m.end():]
        print("[+] Inserted 5 agentmem rows into wargame/README.md tier tables.")
    else:
        print(f"[-] Warning: found {len(gpusec_matches)} gpusec matches in README.md")

    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Successfully updated wargame/README.md.")

    print("\n🎉 Track 84 agentmem generation completed successfully! Total: 2,940 challenges across 84 tracks.")

if __name__ == "__main__":
    main()
