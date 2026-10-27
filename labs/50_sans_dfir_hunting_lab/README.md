# Lab 50: ArtifactHunter — SANS DFIR 실전 침해사고 헌팅 랩

## 개요
SANS FOR508(Advanced Incident Response) 및 FOR572(Advanced Network Forensics) 방법론을 기반으로 한 엔터프라이즈 침해사고 아티팩트 트리아지 및 슈퍼타임라인 격리 실전 실습 환경입니다.

## 실습 단계
1. **실행 흔적(Evidence of Execution) 분석**: Prefetch (PECmd) 및 ShimCache/Amcache를 통한 악성 바이너리 실행 증거 및 타임스탬프 역산
2. **파일시스템 & 삭제 흔적 카빙**: $MFT Data Run 분석, USN Journal 시간 역전 판정 및 삭제 파일 카빙
3. **메모리 인젝션 & VAD 트리 트리아지**: Volatility 3/Rekall 기반 Hidden Process unlinking (DKOM), RWX VAD 인젝션 코드 및 C2 소켓 복원
4. **네트워크 & 슈퍼타임라인 통합 방어**: SANS FOR572 tshark 패킷 카빙, Plaso log2timeline 사건 전모 재구성 및 SOAR 호스트 격리

## 실행 방법
```bash
# 단독 실행
vhack lab start 50
# 검증 테스트
vhack lab test 50
# 자동 익스플로잇 솔버
vhack solve 50
```
