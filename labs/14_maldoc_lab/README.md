# Lab 14: DocArmor - 문서형 악성코드 및 오피스/PDF 포렌식 분석 랩

> **표적 서비스**: `DocArmor Analytics Suite` (포트 `8014`)  
> **공격 및 방어 주제**: OLE 매크로 난독화 해제, PDF FlateDecode 스트림 분석, CVE-2017-11882 수식 에디터 RCE 및 CVE-2021-40444 MSHTML 외부 OLE 차단  
> **연계 교재**: [`06_Malware_Analysis/07_document_malware_analysis.md`](../../06_Malware_Analysis/07_document_malware_analysis.md)  
> **워게임 트랙**: `maldoc` (문서형 악성코드 트랙)

---

## 1. 랩 개요 (Lab Overview)

DocArmor 랩은 실제 APT 공격에서 빈번하게 악용되는 **MS Office 문서(`.doc`, `.docx`, `.docm`)** 및 **PDF 파일(`.pdf`)**의 취약점과 악성 매크로를 분석하고 차단하는 실전 대화형 인터랙티브 랩입니다.

### 4대 핵심 침투 및 분석 시나리오

1. **Stage 1 (VBA 매크로 난독화 해제)**: OLE 스트림 내에서 `ChrW` 함수 조합 및 XOR 난독화된 PowerShell 드롭퍼 페이로드를 역연산하여 C2 주소와 플래그 복원.
2. **Stage 2 (PDF FlateDecode 스트림 분석)**: 압축된 PDF 스트림 객체를 해제하고, `/OpenAction`과 `/JavaScript`에 숨겨진 힙스프레이 셸코드 주소를 탐지하여 플래그 획득.
3. **Stage 3 (CVE-2017-11882 수식 에디터 익스플로잇 분석)**: `EQNEDT32.EXE`의 글꼴 이름 버퍼 오버플로우 바이트 구조를 역추적하고 `WinExec` 호출 매개변수를 추출하여 플래그 획득.
4. **Stage 4 (CVE-2021-40444 MSHTML 외부 OLE 객체 방어)**: OOXML `document.xml.rels`의 악성 외부 CAB/ActiveX 참조를 탐지하고 차단 정책을 적용하여 시스템 방어 성공 플래그 획득.

---

## 2. 빠른 시작 (Quick Start)

### 실행 방법
```bash
# VibeHacking 루트에서 실행
python3 vhack.py lab start 14

# 또는 랩 디렉토리에서 수동 실행
cd labs/14_maldoc_lab
docker compose up -d --build
```

### 웹 대시보드 접속
- 브라우저 접속: `http://localhost:8014`
- 실시간 OLE 스트림 분석기, PDF 객체 트리 뷰어, CVE 모의 테스트 콘솔 제공.

### 자동 공격 및 검증 스크립트 실행
```bash
python3 labs/14_maldoc_lab/app/exploit_maldoc.py
# 4개 스테이지 자동 풀이 및 FLAG 획득
```

### 단위 테스트 실행
```bash
pytest labs/14_maldoc_lab/tests/
```

---

## 3. 플래그 일람 (Flag Table)

| 스테이지 | 목표 | 플래그 |
| :---: | :--- | :--- |
| **Stage 1** | VBA 매크로 난독화 해제 | `FLAG{VBA-OBFUSCATION-UNPACKED-7712}` |
| **Stage 2** | PDF FlateDecode 스트림 분석 | `FLAG{PDF-STREAM-FLATEDECODE-ANALYZED-8931}` |
| **Stage 3** | CVE-2017-11882 수식 에디터 RCE | `FLAG{CVE-2017-11882-EQUATION-PWNED-4419}` |
| **Stage 4** | CVE-2021-40444 MSHTML 방어 | `FLAG{MSHTML-CAB-INF-DEFENSE-PASSED-6602}` |

---

## 4. 종료 및 정리 (Teardown)
```bash
python3 vhack.py lab stop 14
```
