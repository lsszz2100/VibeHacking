# Lab 41: SupplyChainShield — 소프트웨어 공급망 보안 & SBOM 실전 랩

## 📌 개요
- **랩 ID**: `41`
- **디렉토리**: `labs/41_supply_chain_security_lab/`
- **코드네임**: `SupplyChainShield`
- **포트**: `8041` (`http://localhost:8041`)
- **난이도**: ★★★★★
- **관련 섹션**: `35_Supply_Chain_Attacks`, `18_DevSecOps`, `74_Code_Auditing`
- **핵심 표준**: SLSA v1.0 (Supply-chain Levels for Software Artifacts) / CycloneDX v1.6 / SPDX 3.0 / Sigstore Cosign

---

## 🎯 학습 목표
1. **Dependency Confusion & Typosquatting 탐지**: 사내 비공개 패키지와 공개 PyPI 레지스트리 간 우선순위 불일치를 악용한 버전 하이재킹 분석 및 레지스트리 스코핑/해시 피닝 방어
2. **CI/CD 러너 하이재킹 & Pwn Request 방어**: GitHub Actions `pull_request_target` 취약점을 통한 러너 시크릿(`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`) 유출 탐지 및 읽기 전용 격리
3. **SBOM 무결성 분석 & 백도어 컴포넌트 격리**: CycloneDX JSON 포맷의 소프트웨어 자재명세서(SBOM) 분석, xz-utils(CVE-2024-3094) 유사 M4 매크로/바이너리 변조 탐지 및 악성 의존성 격리
4. **SLSA Level 3 & Sigstore Cosign 증명 검증**: OIDC 키리스(Keyless) 서명 및 Rekor 투명성 로그 질의를 통한 Hermetic 빌드 무결성 정책 강제 및 변조 아티팩트 차단

---

## 🚀 빠른 시작
```bash
# 단독 실행
cd labs/41_supply_chain_security_lab
docker compose up -d

# vhack CLI를 통한 제어 및 테스트
python vhack.py lab start 41
python vhack.py lab test 41
python vhack.py solve 41
```

---

## 🔬 실습 단계 및 플래그 안내
1. **Stage 1 (Dependency Confusion & Typosquatting)**: `POST /api/stage1/resolve`
   - 플래그: `FLAG{supplychain_dependency_confusion_pypi_hijacked}`
2. **Stage 2 (CI/CD Runner Poisoning & Pwn Request)**: `POST /api/stage2/audit-pipeline`
   - 플래그: `FLAG{supplychain_pwn_request_actions_secret_leaked}`
3. **Stage 3 (SBOM Vulnerability Triage & Integrity Carving)**: `POST /api/stage3/triage-sbom`
   - 플래그: `FLAG{supplychain_sbom_cyclonedx_backdoor_isolated}`
4. **Stage 4 (SLSA Level 3 & Cosign Attestation Verification)**: `POST /api/stage4/verify-provenance`
   - 플래그: `FLAG{supplychain_slsa_cosign_hermetic_verified_100}`
