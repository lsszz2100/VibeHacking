# 65. 리버스 엔지니어링 고급 (Reverse_Engineering_Advanced)

> 🧬 **VibeHacking 교재 섹션 65**
> - **CLI 학습**: `python3 vhack.py study 65`
> - **연계 실습 랩**: [Lab 06: 펌웨어 해킹 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_anti_debugging_techniques.md](./01_anti_debugging_techniques.md) | **안티디버깅 기법 (Anti-Debugging Techniques)** — sudo apt install gdb ltrace strace |
| [02_obfuscation_and_unpacking.md](./02_obfuscation_and_unpacking.md) | **코드 난독화와 언패킹 (Obfuscation and Unpacking)** — sudo apt install upx-ucl |
| [03_symbolic_execution.md](./03_symbolic_execution.md) | **심볼릭 실행 (Symbolic Execution)** — python3 -m venv ~/.venv/angr && source ~/.venv/angr/bin/activate |
| [04_advanced_binary_analysis.md](./04_advanced_binary_analysis.md) | **고급 바이너리 분석 (Advanced Binary Analysis)** — sudo apt install radare2        # 또는 rizin: https://rizin.re |
| [05_firmware_reverse_engineering.md](./05_firmware_reverse_engineering.md) | **펌웨어 역공학 (Firmware Reverse Engineering)** — sudo apt install binwalk squashfs-tools qemu-user-static |
| [06_re_ctf_lab.md](./06_re_ctf_lab.md) | **고급 역공학 CTF 실습 랩** — 이 랩은 안티디버깅 우회, 패킹 해제, 심볼릭 실행, 난독화 복원 등 고급 역공학 기술을 CTF 형식으로 훈련합니다. 각 챌린지는 실제 CTF 대회에서 자주 출제되는 패턴을 기반으로 ... |

## 🎯 학습 목표

- 안티디버깅 기법 (Anti-Debugging Techniques) 원리 및 실전 공격/방어 기법 습득
- 코드 난독화와 언패킹 (Obfuscation and Unpacking) 원리 및 실전 공격/방어 기법 습득
- 심볼릭 실행 (Symbolic Execution) 원리 및 실전 공격/방어 기법 습득
- 고급 바이너리 분석 (Advanced Binary Analysis) 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 65 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
