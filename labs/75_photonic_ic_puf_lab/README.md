# Lab 75: PhotonicIcPufSecurityLab
> **Photonic IC Physical Unclonable Function (PUF) & Silicon Hardware Security Lab**  
> 포트: `8075` (`127.0.0.1` 루프백 격리)  
> 표준: KISA ISMS-P 2.10.10, NIST CSF 2.0 PR.DS-11, OWASP Top 10 LLM10:2025

---

## 1. 랩 개요
반도체 실리콘 포토닉스(Silicon Photonics) 다이 제조 공정의 미세 광학 위상 편차를 이용해 암호학적 고유 지문(Optical PUF)을 유도하고, 머신러닝 기반 챌린지-응답 쌍(CRP) 모델링 공격을 능동 위상 스크램블링으로 차단하며, 칩let 분리 시 비가역적 광학 소광(Optical Erasure) 및 NIST FIPS 204 ML-DSA-87 기반 상호 원격 증명을 실습하는 골든 실습 랩입니다.

## 2. 4대 방어 스테이지
1. **Stage 1**: 광학 PUF 스페클 패턴 위상 지문 추출 및 엔트로피 기반 루트 키 유도 (`POST /api/stage1/eval`)
2. **Stage 2**: 마이크로 링 공진기(MRR) CRP 머신러닝 모델링 공격 차단 및 10GHz+ 능동 위상 스크램블링 (`POST /api/stage2/eval`)
3. **Stage 3**: 광 칩let 물리적 분리 감지 비가역적 광학 소광 및 하드웨어 RoT 바인딩 (`POST /api/stage3/eval`)
4. **Stage 4**: NIST FIPS 204 ML-DSA-87 서명 기반 칩let 상호 원격 증명 및 도파관 머클 트리 무결성 검증 (`POST /api/stage4/eval`)

## 3. 실행 방법
```bash
# 랩 기동
vhack lab start 75

# 단위 테스트
pytest labs/75_photonic_ic_puf_lab/tests/

# 자동 풀이 실행
python3 labs/75_photonic_ic_puf_lab/solution/solve.py
# 또는
vhack lab solve 75
```
