# 25. Threat Intelligence — 위협 인텔리전스

## 목차

| 파일 | 내용 |
|------|------|
| [01_cti_fundamentals.md](./01_cti_fundamentals.md) | CTI 계층, IOC 유형, MITRE ATT&CK, MISP 플랫폼, 보고서 구조 |
| [02_osint_for_threat_intel.md](./02_osint_for_threat_intel.md) | Shodan/Censys, 패시브 DNS, 악성코드 DB, C2 인프라 추적 |
| [03_incident_response.md](./03_incident_response.md) | IR 프레임워크, 증거 수집, 타임라인 재구성, 격리·박멸, 허니팟 |
| [04_cti_platform_operations.md](./04_cti_platform_operations.md) | **CTI 플랫폼 운영** — 대부분의 조직은 상용 CTI 서비스(VirusTotal, CrowdStrike 등)를 사용하지만, 자체 플랫폼이 필요한 경우도 있습니다. |
| [05_threat_intel_automation.md](./05_threat_intel_automation.md) | **위협 인텔리전스 자동화 — MISP·OpenCTI·IOC 보강·STIX/TAXII** — 위협 인텔리전스(Threat Intelligence, TI)는 사이버 공격자, 그들의 도구, 전술, 절차(TTP)에 대한 정보를 수집·분석·공유하는 체계입니다. "어떤 IP가 우리를 ... |
| [06_threat_intel_ctf_lab.md](./06_threat_intel_ctf_lab.md) | **위협 인텔리전스 CTF 실습 랩** — version: "3.9" |

## 학습 목표

- CTI 계층 구조와 IOC 신뢰도 모델 이해
- Shodan/패시브 DNS/abuse.ch 등 무료 피드 활용
- C2 인프라 JARM 핑거프린팅으로 공격자 인프라 추적
- 침해 사고 발생 시 체계적인 IR 절차 수행

## 핵심 포인트

```
CTI: IOC(해시/IP) → TTP(행동패턴) 순으로 고도화할수록 공격자 변경 비용 증가
OSINT: Shodan + crt.sh + MalwareBazaar로 무료 CTI 피드 구축 가능
IR: 격리 → 증거 수집 → 타임라인 재구성 → 박멸 순서 엄수
허니팟: 내부망에서 공격자 이동 감지에 효과적
```
