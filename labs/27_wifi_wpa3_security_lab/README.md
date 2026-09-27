# Lab 27: WiFiShield - 무선 네트워크 & WPA3 보안 실전 랩

> **포트**: `8027` | **난이도**: `★★★★` | **주요 공격/방어 기법**: WPA2/WPA3 PMKID 오프라인 사전 공격, WPA3 SAE Dragonfly 부채널 및 다운그레이드(Dragonblood), Evil Twin/Rogue AP 격리 & 802.11w 관리 프레임 보호(MFP/PMF)

---

## 1. 랩 개요

현대 무선 네트워크 환경은 WPA2-Personal에서 타원곡선 기반 대등 동시 인증(SAE: Simultaneous Authentication of Equals)을 적용한 WPA3-Personal로 전환되고 있습니다. 그러나 과도기 환경의 WPA3-Transition 모드 취약점, RSN IE를 활용한 클라이언트 비접속 PMKID 수집 공격, 그리고 관리 프레임 위조를 통한 Deauth/Evil Twin 공격 등 다양한 실전 위협이 상존합니다.

Lab 27(WiFiShield)에서는 가상 802.11 무선 스택 환경을 통해 실전 무선 침투 테스트 및 차세대 무선 암호 프로토콜의 취약점 분석, 그리고 802.11w PMF 방어 정책을 단계별로 실습합니다.

---

## 2. 실습 단계 및 플래그 획득

### Step 1: PMKID 수집 및 오프라인 사전 공격 (RSN IE EAPOL bypass)
- **공격 벡터**: 클라이언트의 4-Way Handshake를 기다리지 않고, AP에 직접 EAPOL 1/4 프레임을 유도하여 RSN IE 내의 PMKID(`HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)`)를 캡처합니다.
- **타깃**: `POST /api/wifi/pmkid/crack`
- **정답 사전 단어**: `winter2026!corp`
- **플래그 형식**: `FLAG{pmkid_rsn_ie_offline_hashcat_cracked_8027}`

### Step 2: WPA3 SAE (Dragonfly) 다운그레이드 & Dragonblood 분석
- **공격 벡터**: WPA3 PWE(Password Element) 도출 시의 타이밍/캐시 부채널 공격(CVE-2019-9494)을 시뮬레이션하거나 WPA3 Transition 모드 AP를 WPA2로 강제 다운그레이드(Transition Downgrade)합니다.
- **타깃**: `POST /api/wifi/sae/attack`
- **플래그 형식**: `FLAG{dragonfly_sae_sidechannel_downgraded_9142}`

### Step 3: Evil Twin Rogue AP 탐지 및 802.11w MFP(PMF) 방어
- **방어 대책**: 가짜 AP(Rogue AP)를 통한 Deauth 브로드캐스트 플러딩을 원천 차단하기 위해 IEEE 802.11w Protected Management Frames (PMF / BIP - Broadcast Integrity Protocol)를 `required`로 강제 활성화하고 Rogue AP를 격리합니다.
- **타깃**: `POST /api/wifi/defense/mfp`
- **플래그 형식**: `FLAG{80211w_pmf_bip_deauth_flood_protected_5583}`

---

## 3. 실행 및 테스트

```bash
# 랩 단독 실행
vhack lab start 27

# 브라우저 웹 대시보드 접속
open http://localhost:8027

# 자동 무결성 테스트 실행
vhack lab test 27
```
