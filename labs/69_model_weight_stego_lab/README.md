# Lab 69: AI Model Weight Steganography & SafeTensors Supply Chain Defense Lab

## 1. 개요 (Overview)
- **목적**: 딥러닝 AI 신경망 모델 가중치(Tensor Weights)를 악용한 APT 공격 기법(Pickle 임의 코드 실행 RCE, Float32 가중치 가수부 LSB 스테가노그래피 은닉, 모델 레지스트리 공급망 오염)을 분석하고, SafeTensors 헤더 엄격 검증, 가중치 가수부 비트마스크 양자화 살균, 통계적 카이제곱 & 샤논 엔트로피 이상 탐지, Sigstore Cosign 머클 트리 원격 증명을 통한 4단계 심층 방어 체계를 실증합니다.
- **포트**: `8069` (루프백 `127.0.0.1` 격리 바인딩)
- **버전**: `2.19.0`
- **카테고리**: `ai` (AI Security & Supply Chain Defense)

## 2. 4단계 실전 공방 시나리오 (4 Defense Stages)
1. **Stage 1: Legacy PyTorch/Pickle RCE vs SafeTensors 포맷 검증**
   - *공격 벡터*: 모델 가중치 배포 시 `torch.save` 기반 Pickle 바이너리(`__reduce__` 바이트코드)를 주입하여 모델 로드 시점 임의 셸코드 실행 시도.
   - *방어 대책*: 역직렬화 위험이 없는 무특권 SafeTensors 바이너리 포맷 강제, 제로 역직렬화 JSON 헤더 메타데이터 파싱 및 Pickle 매직 바이트(`\x80\x02`~`\x80\x05`) 전면 차단.
   - *플래그*: `FLAG{v219_s1_safetensors_pickle_deserialization_blocked}`

2. **Stage 2: 신경망 가중치 가수부 LSB 스테가노그래피 은닉 & 가수부 살균**
   - *공격 벡터*: 공격자가 트랜스포머 레이어 가중치(`float32`)의 최하위 비트(LSB Mantissa)에 악성 C2 IP/명령어 페이로드를 분산 은닉하여 상위 추론 정확도를 손상시키지 않고 은밀히 전파.
   - *방어 대책*: 가수부 하위 비트마스크 필터링 및 FP8/INT8 동적 양자화 클리핑(Quantization Clipping)을 적용하여 모델 성능 저하 없이 은닉 채널 완전 소멸.
   - *플래그*: `FLAG{v219_s2_neural_weight_lsb_stego_neutralized}`

3. **Stage 3: 통계적 카이제곱 적합도 검정 & 비트 엔트로피 이상치 탐지**
   - *공격 벡터*: 정교하게 조율된 가중치 변조로 단순 임계값 필터를 우회하는 고차원 스테가노그래피 주입.
   - *방어 대책*: 가우스 정규분포 적합도 카이제곱(Chi-Square) p-값 검정($p \ge 0.05$) 및 샤논 엔트로피($H \le 7.92$) 이상치 실시간 감사로 악성 텐서 조기 색출.
   - *플래그*: `FLAG{v219_s3_statistical_chi_square_weight_anomaly_detected}`

4. **Stage 4: Sigstore Cosign 머클 트리 서명 및 모델 출처 무결성 검증**
   - *공격 벡터*: 비인가 모델 미러 사이트 또는 탈취된 파이프라인에서 변조된 가중치 파일 밀반입.
   - *방어 대책*: Sigstore Rekor 투명성 로그 연동, SHA-256 머클 트리 루트 다이제스트 일치 확인 및 Ed25519/ECDSA 암호학적 서명 검증을 통한 공급망 불변 배포.
   - *플래그*: `FLAG{v219_s4_sigstore_model_provenance_merkle_verified}`

## 3. 실행 및 검증 (Execution & Verification)
```bash
# 실습 랩 시작
vhack lab start 69

# 자동 솔버 실행 및 플래그 획득
python3 labs/69_model_weight_stego_lab/solution/solve.py

# 단위 테스트 수행
pytest labs/69_model_weight_stego_lab/tests/
```
