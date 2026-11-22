# Lab 78: FedAiPoisonDefenseLab (연합 학습 모델 중독 공격 및 차분 프라이버시 방어 랩)

## 1. 개요
- **실습 포트**: `8078` (`127.0.0.1` 로컬 루프백 격리)
- **보안 분류**: AI Security & Federated Learning (`ai_federated_security`)
- **실습 단계**: 4단계

## 2. 실습 시나리오
1. **Stage 1**: 비잔틴 클라이언트 가중치 그래디언트 폭탄 투하 차단 & L2-Norm 클리핑 및 코사인 유사도 이상치 검출
2. **Stage 2**: Multi-Krum 및 트림드 평균(Trimmed-Mean) 비잔틴 견고 집계 & 악의적 참여자 n-2f 노드 가중치 격리
3. **Stage 3**: 멤버십 추론 공격(MIA) 방어 & RDP 가우시안 노이즈 주입 및 차분 프라이버시 예산 Epsilon ($\epsilon \le 3.0$) 통제
4. **Stage 4**: 비밀 분할(Secret Sharing) 안전 집계 마스킹 & NIST FIPS 204 ML-DSA-87 연합 참여 노드 하드웨어 원격 증명
