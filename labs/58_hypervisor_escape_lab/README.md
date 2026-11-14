# Lab 58: MicroVM & Hypervisor Escape Defense Lab (하이퍼바이저 탈출 & MicroVM 격리 방어 실습)

## 📌 실습 개요
- **실습 번호**: `Lab 58`
- **실습 포트**: `8058` (`127.0.0.1:8058` 로컬 루프백 바인딩)
- **보안 카테고리**: 클라우드 인프라 보안 & 가상화 격리 (Cloud & Virtualization Security)
- **관련 MITRE ATT&CK**: `T1611` (Escape to Host) / `T1068` (Exploitation for Privilege Escalation)
- **CVSS 3.1 스코어**: `8.8` (HIGH) — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`

## 🎯 4단계 실전 시뮬레이션 파이프라인
1. **Stage 1 (VM-Exit 가로채기 & MMIO 에뮬레이션 취약점)**: EPT Violation 인터럽트 유도 및 취약한 하이퍼바이저 MMIO 핸들러 에뮬레이션 트리거
2. **Stage 2 (Virtio-Net 공유 메모리 링 버퍼 OOB 오염)**: vring 디스크립터 체인의 경계 초과(Out-of-Bounds) 변조를 통한 하이퍼바이저 힙 오염
3. **Stage 3 (KVM vCPU 레지스터 상태 조작 & 호스트 주소 유출)**: vCPU 컨텍스트 스위칭 시 MSR_LSTAR 레지스터 누출을 통한 호스트 커널 베이스 주소 역산
4. **Stage 4 (Seccomp/Landlock MicroVM 격리 & 하드닝 정책 강제)**: KVM ioctl 화이트리스트, Landlock 파일시스템 비특권 격리, MTE 메모리 태깅 적용

## 🚀 빠른 시작
```bash
docker compose up -d --build
# 또는 Python 직접 실행
pip install -r requirements.txt
uvicorn app.main:app --port 8058
```
