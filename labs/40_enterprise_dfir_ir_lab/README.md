# Lab 40: IRShield — 엔터프라이즈 침해사고 대응 & DFIR 실전 랩

## 📌 개요
- **랩 ID**: `40`
- **디렉토리**: `labs/40_enterprise_dfir_ir_lab/`
- **코드네임**: `IRShield`
- **포트**: `8040` (`http://localhost:8040`)
- **난이도**: ★★★★★
- **관련 섹션**: `44_Incident_Response_DFIR`, `07_Digital_Forensics`, `23_SOC_Blue_Team`
- **핵심 표준**: NIST SP 800-61 Rev 2 / RFC 3227 / CISA Incident Response Playbooks

---

## 🎯 학습 목표
1. **라이브 프로세스 & 메모리 트리아지**: PPID 스푸핑(`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) 및 백킹 파일이 없는 비정상 실행 메모리(`PAGE_EXECUTE_READWRITE`) 탐지
2. **$MFT & 랜섬웨어 아티팩트 포렌식**: 볼륨 섀도우 복사본 삭제(`vssadmin`), USN 저널 기반 대량 파일 암호화 타임라인 재구성 및 랜섬노트 추적
3. **C2 비콘 탐지 & 호스트 네트워크 격리**: 지터(Jitter) 기반 주기적 비콘 통신 분석, DNS 터널링 쿼리 식별 및 엔터프라이즈 방화벽/호스트 격리 봉쇄
4. **SOAR 자동 대응 플레이북 & 복구 무결성 검증**: 스케줄러 태스크 및 WMI 이벤트 구독 지속성 제거, 에어갭 골드 스냅샷 복구 및 SHA-256 무결성 검증

---

## 🚀 빠른 시작
```bash
# 단독 실행
cd labs/40_enterprise_dfir_ir_lab
docker compose up -d

# vhack CLI를 통한 제어 및 테스트
python vhack.py lab start 40
python vhack.py lab test 40
python vhack.py solve 40
```

---

## 🔬 실습 단계 및 플래그 안내
1. **Stage 1 (라이브 프로세스 트리아지)**: `POST /api/stage1/triage`
   - 플래그: `FLAG{dfir_live_process_triage_pid4920_detected}`
2. **Stage 2 (MFT 타임라인 & 랜섬웨어 분석)**: `POST /api/stage2/mft-analyze`
   - 플래그: `FLAG{dfir_mft_timeline_vssadmin_ransom_unmasked}`
3. **Stage 3 (C2 비콘 탐지 & 네트워크 격리)**: `POST /api/stage3/contain`
   - 플래그: `FLAG{dfir_c2_network_isolation_firewall_locked}`
4. **Stage 4 (SOAR 플레이북 & 복구 무결성 검증)**: `POST /api/stage4/remediate`
   - 플래그: `FLAG{dfir_soar_playbook_enterprise_remediated_100}`
