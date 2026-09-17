# 44. 사고 대응/DFIR (Incident_Response_DFIR)

> 🚨 **VibeHacking 교재 섹션 44**
> - **CLI 학습**: `python3 vhack.py study 44`
> - **연계 실습 랩**: [Lab 05: 전체 시나리오 통합 랩](../labs/), [Lab 11: Active Directory & Kerberos 침투 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_ir_methodology_and_playbooks.md](./01_ir_methodology_and_playbooks.md) | **인시던트 대응 방법론과 플레이북** — 보안 이벤트 vs 인시던트: |
| [02_memory_and_disk_forensics.md](./02_memory_and_disk_forensics.md) | **메모리 및 디스크 포렌식** — 왜 메모리가 중요한가: |
| [03_network_forensics_and_log_analysis.md](./03_network_forensics_and_log_analysis.md) | **네트워크 포렌식과 로그 분석** — 네트워크 포렌식(Network Forensics)은 네트워크를 오간 패킷 데이터를 수집·분석해 사이버 공격의 흔적을 찾는 조사 기법이다. 로그 분석은 시스템, 애플리케이션, 보안 장비... |
| [04_threat_containment_and_eradication.md](./04_threat_containment_and_eradication.md) | **위협 격리, 박멸, 복구** — 침해사고 대응(Incident Response)의 핵심 3단계다. 격리(Containment)는 감염된 시스템을 네트워크에서 차단해 피해가 번지지 않도록 막는다. 박멸(Eradicat... |
| [05_malware_triage_and_containment.md](./05_malware_triage_and_containment.md) | **악성코드 트리아지 및 억제** — 트리아지(Triage)는 의료 분야에서 유래한 용어로 "빠른 분류 및 우선순위 결정"을 의미한다. 악성코드 트리아지는 사고 발생 초기에 빠른 시간(수 분~수십 분) 안에 악성코드의 유... |
| [06_ir_dfir_ctf_lab.md](./06_ir_dfir_ctf_lab.md) | **침해사고 대응 / DFIR CTF 실습 랩** — pip install volatility3 yara-python scapy dpkt pyshark |

## 🎯 학습 목표

- 인시던트 대응 방법론과 플레이북 원리 및 실전 공격/방어 기법 습득
- 메모리 및 디스크 포렌식 원리 및 실전 공격/방어 기법 습득
- 네트워크 포렌식과 로그 분석 원리 및 실전 공격/방어 기법 습득
- 위협 격리, 박멸, 복구 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 44 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
