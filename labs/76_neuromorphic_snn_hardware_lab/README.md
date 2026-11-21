# Lab 76: Neuromorphic SNN Hardware Security & Memristor Glitch Defense Lab

## 개요
- **포트**: `8076` (호스트 루프백 `127.0.0.1:8076:8076` 전용 바인딩)
- **카테고리**: Hardware & Neuromorphic Security
- **버전**: v2.26.0

## 4단계 방어 실증 시나리오
1. **Stage 1**: 비동기 AER(Address-Event Representation) 스파이크 타이밍 지문 추출 및 LIF 뉴런 발화 임계값 잠금
2. **Stage 2**: 멤리스터(Memristor) 크로스바 어레이 전압 글리치 및 레이저 고장 주입(LFI) 실시간 탐지 & 위상 지터 방어
3. **Stage 3**: 스파이크 타이밍 의존 가소성(STDP) 시냅틱 가중치 위변조 차단 & 하드웨어 RoT 바인딩
4. **Stage 4**: NIST FIPS 204 ML-DSA-87 서명 기반 뉴로모픽 펌웨어 및 멤리스터 어레이 원격 증명 (Remote Attestation)

## 실행 방법
```bash
# 랩 기동
vhack lab start 76
# 또는
bash labs/start_lab.sh 76

# 자동 익스플로잇 및 검증 솔버 실행
python3 labs/76_neuromorphic_snn_hardware_lab/solution/solve.py

# 단위 테스트
pytest labs/76_neuromorphic_snn_hardware_lab/tests/
```
