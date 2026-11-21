# Lab 72: AI Agent Long-Term Context Memory & Knowledge Graph Poisoning Defense Lab
> **Port**: `8072` (Loopback `127.0.0.1` binding)  
> **Category**: AI Agent Security & Cognitive Firewall  
> **Defense Target**: Agent Episodic Context Sanitization, Semantic Embedding Cosine Anomaly Filtering, GraphRAG Topological Permission Invariant & Cryptographic HMAC Provenance

## 개요
본 랩은 LLM 에이전트의 장기 기억(Episodic Memory, Vector DB) 및 지식 그래프(GraphRAG) 환경에서 발생하는 잠복형 슬리퍼 프롬프트 주입 및 권한 상승 공격을 방어하는 종합 인지 방어 체계를 실습합니다.

## 스테이지 구성
1. **Stage 1**: 에피소딕 컨텍스트 메모리 정제 및 비신뢰 노드 격리 파티셔닝
2. **Stage 2**: 암호학적 세션 출처(Provenance) 검증 및 HMAC-SHA256 증명
3. **Stage 3**: 시맨틱 임베딩 코사인 드리프트 이상치 탐지 및 적대적 클러스터 필터링
4. **Stage 4**: GraphRAG 지식 그래프 위상 권한 불변성 검증 및 슬리퍼 트리거 무력화
