# Lab 48: FirmwareGuard — 임베디드 펌웨어 & IoT RCE 실전 실습 환경

## 1. 개요
* **서비스 포트**: `8048`
* **관련 챕터**: `61_Firmware_Hacking/07_qemu_firmware_emulation_and_nvram_deepdive.md`
* **주요 목표**:
  1. Binwalk 기반 SquashFS 펌웨어 언패킹 및 파일시스템 분석
  2. QEMU MIPS 환경에서 libnvram.so 가상화 주입 (LD_PRELOAD)
  3. 임베디드 웹 CGI 원격 명령 실행(RCE) 익스플로잇
  4. DM-Verity 및 시큐어 부트 커널 무결성 하드닝
