# 27. IoT 해킹 (IoT_Hacking)

> 📟 **VibeHacking 교재 섹션 27**
> - **CLI 학습**: `python3 vhack.py study 27`
> - **연계 실습 랩**: [Lab 06: 펌웨어 해킹 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_iot_attack_surface.md](./01_iot_attack_surface.md) | **IoT 공격 면 분석 (Attack Surface Analysis)** — IoT(Internet of Things)는 인터넷에 연결된 스마트 기기들의 집합이다. 공격 면(Attack Surface)은 공격자가 기기에 침투할 수 있는 모든 진입점의 총합이다.... |
| [02_firmware_analysis.md](./02_firmware_analysis.md) | **펌웨어 분석 심화 (Firmware Analysis)** — 펌웨어(Firmware)는 IoT 기기의 하드웨어를 제어하는 소프트웨어로, 기기의 ROM/플래시 메모리에 저장된다. 스마트폰의 OS처럼 기기 동작의 근본이 된다. 펌웨어 분석은 이 바... |
| [03_iot_exploitation.md](./03_iot_exploitation.md) | **IoT 실전 익스플로잇 (IoT Exploitation)** — IoT 익스플로잇은 IoT 기기의 소프트웨어/하드웨어 취약점을 실제로 공격하는 기법이다. 일반 서버 해킹과 달리, IoT 기기는 자원이 제한적이고(임베디드 리눅스, RTOS), 다양한... |
| [04_RF_Zigbee_Attacks.md](./04_RF_Zigbee_Attacks.md) | **RF/Zigbee/Z-Wave IoT 무선 프로토콜 공격** — IoT 기기의 상당수는 Wi-Fi가 아닌 전용 무선 프로토콜(RF 433MHz, Zigbee, Z-Wave)로 통신한다. 스마트 도어락, 차고 문, 무선 센서, 스마트홈 허브 등이 이... |
| [05_iot_security_hardening.md](./05_iot_security_hardening.md) | **IoT 보안 강화 — 펌웨어 서명·네트워크 격리·디바이스 감사** — IoT 보안 강화(Hardening)는 기기 공격 면을 최소화하여 침해 가능성을 줄이는 체계적인 과정이다. 단순히 보안 패치를 적용하는 것을 넘어, 펌웨어 무결성 검증, 네트워크 분리... |
| [06_iot_ctf_lab.md](./06_iot_ctf_lab.md) | **IoT 해킹 CTF 실습 랩** — version: "3.9" |

## 🎯 학습 목표

- IoT 공격 면 분석 (Attack Surface Analysis) 원리 및 실전 공격/방어 기법 습득
- 펌웨어 분석 심화 (Firmware Analysis) 원리 및 실전 공격/방어 기법 습득
- IoT 실전 익스플로잇 (IoT Exploitation) 원리 및 실전 공격/방어 기법 습득
- RF/Zigbee/Z-Wave IoT 무선 프로토콜 공격 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 27 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
