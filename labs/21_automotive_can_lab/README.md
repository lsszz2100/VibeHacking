# Lab 21: 차량 보안 & CAN Bus 실전 랩 (CarCanLab)

본 실습 환경은 자동차 내부 통신 프로토콜인 **CAN(Controller Area Network) 버스**와 전장 제어기(ECU) 진단 표준인 **UDS(ISO 14229 Unified Diagnostic Services)**의 보안 취약점을 심층 분석하고 실전 모의 침투를 수행하는 인터랙티브 실습 랩입니다.

---

## 📌 주요 학습 목표

1. **CAN Bus 패킷 분석 및 스푸핑**:
   - CAN 버스 ID 중재(Arbitration) 우선순위 및 프레임 구조(DLC, Data Field) 이해
   - 차속 센서(ID `0x120`), 엔진 RPM(ID `0x240`) 텔레메트리 스니핑 및 임의 값 주입 공격
2. **UDS Diagnostic 진단 프로토콜 침투**:
   - DiagnosticSessionControl(Mode `0x10`)을 통한 Extended 진단 세션 전환
   - SecurityAccess(Mode `0x27`) 시드-키(Seed-Key) 대칭 암호 알고리즘 역공학 및 인증 우회
3. **ECU 펌웨어 덤프 & 서비스 거부(DoS)**:
   - RequestDownload(Mode `0x34`) 펌웨어 메모리 블록 덤프
   - ECUReset(Mode `0x11`)을 통한 주행 중 제어기 강제 하드 리셋 및 페일세이프 유발

---

## 🚀 빠른 시작 (Quick Start)

```bash
# vhack CLI를 통한 랩 실행
vhack lab start 21

# 웹 대시보드 및 가상 계기판 접속
# http://localhost:8021
```

---

## 🎯 실습 미션 (Missions)

| 미션 | 목표 | 공격 벡터 & 타겟 엔드포인트 | 획득 플래그 |
| :---: | :--- | :--- | :--- |
| **Mission 1** | CAN 버스 속도 스푸핑 | CAN ID `0x120` 주입 (`POST /api/mission1/can_inject`) 속도 >= 200 km/h | `FLAG{can_bus_arbitration_speed_spoof_...}` |
| **Mission 2** | UDS SecurityAccess 언락 | 세션 전환 (`0x10 03`) ➔ Seed 요청 (`0x27 01`) ➔ Key 계산 및 언락 (`0x27 02`) | `FLAG{uds_security_access_seed_key_unlocked_...}` |
| **Mission 3** | ECU 펌웨어 덤프 & 하드 리셋 | 펌웨어 다운로드 (`0x34`) ➔ ECU hardReset (`0x11 01`) 격발 | `FLAG{uds_ecu_reset_hard_failsafe_pwned_...}` |

---

## 🛡️ 방어 및 완화 대책 (Mitigations)

1. **SecOC (Secure Onboard Communication, AUTOSAR 4.2+)**:
   - 대칭키 기반 CMAC(Cipher-based MAC) 및 신선도 값(Freshness Value)을 주입하여 CAN 프레임 재생 및 위조 방지.
2. **UDS SecurityAccess 난수 무결성 및 지연 방어**:
   - 진정한 하드웨어 난수 생성기(TRNG)를 활용하여 시드 예측 차단.
   - 키 인증 실패 시 지수 백오프(Exponential Backoff) 지연을 강제하여 무차별 대입 방지.
3. **게이트웨이 라우팅 필터링 (Central Gateway IDS)**:
   - OBD-II 진단 포트에서 파워트레인 내부 CAN 버스로의 위험 서비스(0x11, 0x27, 0x34) 인가되지 않은 라우팅 차단.
