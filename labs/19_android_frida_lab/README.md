# Lab 19: DroidShield — 안드로이드 악성코드 분석 & Frida 동적 후킹 랩

> **포트**: `8019` | **난이도**: ★★★★☆ | **카테고리**: 모바일 보안 / 동적 계측 / 리버싱  
> **연계 교재**: [28장 모바일 해킹 심층](file:///mnt/d/바이브해킹%20자료/vibe-hacking/28_Mobile_Hacking/07_frida_android_dynamic_analysis_deepdive.md) | **워게임 트랙**: `droidpwn` / `mobile`

---

## 1. 개요

현대 모바일 악성코드는 루팅 탐지, SSL 피닝, JNI 네이티브 은닉 기법을 활용해 동적 분석을 방해합니다.
본 실습 랩에서는 Frida를 이용한 동적 함수 후킹, 매개변수/반환값 조작, 그리고 난독화된 네트워크 통신 패킷 역공학을 실습합니다.

---

## 2. 랩 구성 및 미션

| 미션 | 목표 | 핵심 기술 | 엔드포인트 |
| :---: | :--- | :--- | :--- |
| **Mission 1** | 루팅 탐지 무력화 | `isDeviceRooted()` 바이패스, `File.exists` 후킹 | `POST /api/mission1/verify_device` |
| **Mission 2** | SSL Pinning 우회 | `TrustManagerImpl` / `CertificatePinner` 무력화 | `POST /api/mission2/verify_ssl` |
| **Mission 3** | JNI 네이티브 라이브러리 조작 | `Interceptor.attach` 및 리턴값 치환 | `POST /api/mission3/native_license` |
| **Mission 4** | C2 난독화 패킷 복호화 | XOR 0x5A 역산 및 명령 오버라이드 | `POST /api/mission4/c2_command` |

---

## 3. 실행 방법

```bash
# 실습 랩 시작
python3 vhack.py lab start 19

# 랩 상태 점검
python3 vhack.py lab status

# 자동 무결성 검증
python3 vhack.py lab test 19

# 실습 랩 종료
python3 vhack.py lab stop 19
```
