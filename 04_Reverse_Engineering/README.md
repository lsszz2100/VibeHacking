# 04. 리버스 엔지니어링

## 목차

| 파일 | 내용 |
|------|------|
| [01_assembly_and_registers.md](./01_assembly_and_registers.md) | IA-32 레지스터, 어셈블리 명령어, C언어 대응 |
| [02_ollydbg_practical.md](./02_ollydbg_practical.md) | OllyDbg/x64dbg 실전, 크랙, 안티디버깅 우회 |
| [03_pe_structure.md](./03_pe_structure.md) | PE 파일 구조, DLL, 메모리 공간, 레지스트리 |
| [04_ghidra_and_dynamic_analysis.md](./04_ghidra_and_dynamic_analysis.md) | **Ghidra 실전 분석 & WorstFit Unicode 취약점** — Ghidra는 어셈블리 코드를 C 유사 코드로 자동 변환(디컴파일)해주는 무료 역공학 도구입니다. 정적 분석(실행 없이 코드 읽기)의 핵심 도구이며, 동적 분석(실행하면서 관찰)과 함... |
| [05_advanced_unpacking_and_deobfuscation.md](./05_advanced_unpacking_and_deobfuscation.md) | **고급 언패킹 및 난독화 해제** — 패킹(Packing)은 실행 파일을 압축하거나 암호화해 분석을 방해하는 기법이다. 패킹된 파일은 실행 시 메모리에서 원본 코드를 복원(언패킹)한다. |
| [06_reversing_ctf_lab.md](./06_reversing_ctf_lab.md) | **CTF 스타일 리버싱 실습** — sudo apt-get install -y \ |

## 학습 목표
- x86 어셈블리 완전 이해
- OllyDbg로 바이너리 분석 및 패치
- PE 파일 구조와 IAT 분석
- 안티디버깅 기법과 우회 방법
