# Lab 37: 블루투스 저에너지 & SDR 무선 보안 실전 랩 (BLEShield)

> **포트**: `8037` | **대상**: IoT 침투 분석관, 무선 보안 연구원, 임베디드 펌웨어 엔지니어  
> **연계 교재**: `71_Bluetooth_RF_Hacking`, `15_WiFi_Hacking`  
> **연계 워게임 트랙**: `blehack` (트랙 51)

---

## 1. 랩 개요

Bluetooth Low Energy(BLE)는 스마트 도어락, 웨어러블 헬스케어 기기, 스마트홈 IoT 등 일상과 산업 전반에 광범위하게 배포되어 있습니다. 그러나 다수의 BLE 기기가 부적절한 GATT 권한 설정, 레거시 Just Works 페어링(TK=0) 고착, 재생 공격(Replay Attack) 방어 부재로 인해 심각한 무선 보안 위협에 노출되어 있습니다.

본 실습 랩에서는 가상 스마트 도어락(`SmartLock-BLE-v4`)을 대상으로:
1. **BLE 어드버타이징 패킷 스니핑 및 GATT 서비스/특성 프로파일 정찰**
2. **비인가 Characteristic Write를 통한 스마트 도어락 임의 개방(Unauthenticated Pwn)**
3. **SMP 레거시 Just Works 페어링 트래픽 스니핑, TK=0 크래킹 및 토큰 Replay 공격**
4. **LE Secure Connections (LESC ECDH P-256) 암호화 강제, Authenticated Write 비트 설정, 단조 카운터 기반 Anti-Replay 하드닝**

체계를 단계별로 실습하고 검증합니다.

---

## 2. 실습 단계 및 플래그

| 단계 | 침투 / 방어 주제 | 획득 플래그 |
| :---: | :--- | :--- |
| **Step 1** | BLE 스니핑 & GATT 프로파일 정찰 (UUID 및 Handle 노출) | `FLAG{BLE_GATT_SERVICE_RECON_HANDLE_EXPOSED_8841}` |
| **Step 2** | 비인가 특성 쓰기를 통한 도어락 제어기 임의 언락 | `FLAG{BLE_UNAUTH_GATT_WRITE_DOORLOCK_OPENED_7732}` |
| **Step 3** | 레거시 Just Works TK 크래킹 및 인증 챌린지 재생 공격 | `FLAG{BLE_LEGACY_JUSTWORKS_REPLAY_MITM_CRACKED_5519}` |
| **Step 4** | LE Secure Connections (ECDH) 및 GATT 보안 속성 하드닝 | `FLAG{BLE_LESC_ECDH_SECURE_CONNECTIONS_HARDENED_9921}` |

---

## 3. 실습 가이드

### Step 1: BLE 스니핑 & GATT 정찰
1. 주변 BLE 기기 스캔:
   ```bash
   curl -s http://localhost:8037/api/ble/scan | jq .
   ```
2. 대상 기기(`AA:BB:CC:11:22:33`)의 GATT 서비스 및 특성 트리 덤프:
   ```bash
   curl -s "http://localhost:8037/api/ble/services?mac=AA:BB:CC:11:22:33" | jq .
   ```
3. 도어락 제어 특성(UUID `0xFFE2`, Handle `0x0014`)의 쓰기 권한이 인증 없이 노출되어 있음을 확인하고 Step 1 플래그를 획득합니다.

### Step 2: 비인가 Characteristic 쓰기 (도어락 언락)
1. Handle `0x0014`에 언락 커맨드(`01`)를 직접 쓰기 전송:
   ```bash
   curl -s -X POST http://localhost:8037/api/ble/write \
     -H "Content-Type: application/json" \
     -d '{"mac": "AA:BB:CC:11:22:33", "handle": "0x0014", "value": "01"}' | jq .
   ```
2. 도어락 액추에이터가 즉각 `UNLOCKED` 상태로 변경되며 Step 2 플래그를 획득합니다.

### Step 3: 레거시 Just Works 크래킹 & Replay 공격
1. 스니핑된 SMP 페어링 패킷 프레임 분석:
   ```bash
   curl -s http://localhost:8037/api/ble/snoop_traffic | jq .
   ```
2. 레거시 Just Works 기본 임시 키(`TK = 000000`) 크래킹 및 STK 산출:
   ```bash
   curl -s -X POST http://localhost:8037/api/ble/crack_pairing \
     -H "Content-Type: application/json" \
     -d '{"mac": "AA:BB:CC:11:22:33", "tk_guess": "000000"}' | jq .
   ```
3. 캡처된 인증 토큰(`BLE_AUTH_REPLAY_TKN_9942FA`) 재생 공격:
   ```bash
   curl -s -X POST http://localhost:8037/api/ble/replay_auth \
     -H "Content-Type: application/json" \
     -d '{"mac": "AA:BB:CC:11:22:33", "auth_token": "BLE_AUTH_REPLAY_TKN_9942FA"}' | jq .
   ```

### Step 4: LE Secure Connections & 보안 속성 하드닝
1. LESC ECDH 강제, Authenticated Write 강제, Anti-Replay 활성화:
   ```bash
   curl -s -X POST http://localhost:8037/api/ble/harden \
     -H "Content-Type: application/json" \
     -d '{"enforce_lesc_ecdh": true, "require_gatt_auth": true, "enable_anti_replay": true}' | jq .
   ```
2. 하드닝 적용 후 이전의 비인가 쓰기 및 재전송 공격이 모두 차단(`403 Forbidden`)됨을 검증하고 Step 4 플래그를 획득합니다.
