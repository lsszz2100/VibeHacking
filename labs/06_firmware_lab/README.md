# 펌웨어 해킹 랩 (06_firmware_lab)

이 랩은 임베디드 장치 펌웨어 추출, QEMU 에뮬레이션, 바이너리 분석을 실습하기 위한 환경입니다.
binwalk 기반 정적 분석부터 QEMU ARM 에뮬레이션을 통한 서비스 구동, 하드코딩 자격증명 발견 CTF까지 단계별로 진행합니다.
섹션 61 (펌웨어/IoT 보안) 과 연동됩니다.

---

## 요구사항

| 항목 | 최소 | 권장 |
|------|------|------|
| Docker Engine | 20.10+ | 24.x |
| Docker Compose | v2.0+ | v2.x |
| RAM | 8 GB 이상 | 16 GB |
| 운영체제 | Linux / WSL2 | Ubuntu 22.04 |

> **WSL2 사용자 주의**: QEMU 에뮬레이션 실습 시 WSL2 커널 버전이 5.15 이상인지 확인하세요.

---

## 서비스 구성

| 서비스 | 이미지 | 외부 포트 | 설명 |
|--------|--------|-----------|------|
| firmware_analyzer | ubuntu:22.04 | 8061 | binwalk·squashfs 분석 도구 환경 |
| firmware_web_panel | python:3.11-slim | 8062 | 취약한 펌웨어 업데이트 웹 패널 (CTF) |

---

## 사전 준비

```bash
# firmware_images 디렉토리 생성 (볼륨 마운트용)
mkdir -p labs/06_firmware_lab/firmware_images
```

이 디렉토리에 분석할 펌웨어 바이너리(.bin, .img, .trx 등)를 복사하면 컨테이너 내부 `/firmware` 경로로 마운트됩니다.

---

## 빠른 시작

```bash
cd labs/06_firmware_lab

# 랩 시작
docker compose up -d

# 서비스 상태 확인
docker compose ps

# 로그 확인 (도구 설치 완료까지 대기)
docker compose logs -f firmware_analyzer
```

### 종료

```bash
docker compose down

# 작업 공간 볼륨까지 삭제
docker compose down -v
```

---

## 실습 시나리오

### 시나리오 1 — 가상 임베디드 Linux 펌웨어 이미지 분석

binwalk로 펌웨어 구조를 파악하고 내부 파일시스템을 추출합니다.

```bash
# 분석 컨테이너 쉘 접속
docker exec -it firmware_analyzer bash

# 예시: 펌웨어 헤더 확인
file /firmware/<target.bin>
strings /firmware/<target.bin> | head -50

# binwalk 서명 스캔
binwalk /firmware/<target.bin>

# 자동 추출 (-e: extract, -M: matryoshka 재귀 추출)
binwalk -eM /firmware/<target.bin> -C /workspace/extracted/

# 추출된 파일시스템 탐색
ls /workspace/extracted/
```

### 시나리오 2 — QEMU ARM 에뮬레이션으로 서비스 실행

추출된 ARM ELF 바이너리를 QEMU user-mode로 실행합니다.

```bash
docker exec -it firmware_analyzer bash

# ARM ELF 확인
file /workspace/extracted/<binary>

# QEMU user-mode 실행 (ARM 32비트 예시)
qemu-arm-static /workspace/extracted/<binary>

# 라이브러리 의존성 확인 후 chroot 에뮬레이션
cp $(which qemu-arm-static) /workspace/extracted/usr/local/bin/
chroot /workspace/extracted/ qemu-arm-static /bin/sh
```

### 시나리오 3 — binwalk 자동 추출 도구 사용

```bash
docker exec -it firmware_analyzer bash

# SquashFS 이미지 직접 마운트
unsquashfs -d /workspace/squash_root /firmware/<squashfs.img>

# LZMA 압축 해제
binwalk --dd='lzma:lzma' /firmware/<target.bin>

# 엔트로피 분석 (암호화 영역 탐지)
binwalk -E /firmware/<target.bin>

# 특정 오프셋에서 데이터 추출
dd if=/firmware/<target.bin> bs=1 skip=<offset> count=<size> of=/workspace/chunk.bin
```

### 시나리오 4 — 하드코딩 자격증명 발견 CTF

취약한 웹 패널(`http://localhost:8062`)에서 플래그를 획득합니다.

```bash
# 패널 상태 확인
curl http://localhost:8062/

# 힌트: /upload 엔드포인트를 통해 단서를 얻고,
# 펌웨어 바이너리에서 자격증명을 추출하여 /login 엔드포인트를 공격하세요.

# 자격증명 검색 (strings 활용)
strings /firmware/<binary> | grep -iE 'admin|pass|key|secret|credential'

# 로그인 시도
curl -s -X POST http://localhost:8062/login \
  -H "Content-Type: application/json" \
  -d '{"user": "admin", "pass": "<discovered_password>"}'

# 업로드 엔드포인트 힌트 확인
curl -s -X POST http://localhost:8062/upload
```

**획득 가능한 플래그**: `CTF{firmware_hardcoded_cred_found}`

---

## 챌린지 힌트

| 챌린지 | 힌트 |
|--------|------|
| 자격증명 찾기 | `strings` + `grep` 조합으로 바이너리 내 ASCII 문자열 탐색 |
| SquashFS 추출 | `binwalk -e` 또는 `unsquashfs` 사용 |
| QEMU 실행 오류 | `qemu-arm-static` 경로를 chroot 환경 내부에 복사 |
| 암호화 섹션 | 엔트로피 분석(`binwalk -E`)으로 고엔트로피 영역 식별 후 키 탐색 |

---

## 네트워크 구성

```
[공격자 머신]
      |
  localhost:8061  →  firmware_analyzer  (172.19.0.10)
  localhost:8062  →  firmware_web_panel (172.19.0.20)
      |
  [firmware_lab_net: 172.19.0.0/24]
```

---

## 추천 도구

| 도구 | 용도 |
|------|------|
| binwalk | 펌웨어 서명 스캔 및 자동 추출 |
| squashfs-tools (unsquashfs) | SquashFS 파일시스템 추출 |
| qemu-user-static | ARM/MIPS 바이너리 에뮬레이션 |
| strings / file | 바이너리 기초 분석 |
| pycryptodome | Python 기반 암호화/복호화 |
| Ghidra / radare2 | 바이너리 역공학 (로컬 설치) |

---

## 주의사항

> **경고**: 이 랩은 의도적으로 취약하게 설계되어 있습니다.
> - 로컬 또는 격리된 환경에서만 실행하세요.
> - 실습 후 반드시 `docker compose down`으로 컨테이너를 종료하세요.
> - 실제 타사 제품의 펌웨어를 분석할 때는 해당 제조사의 라이선스 및 법률을 준수하세요.
