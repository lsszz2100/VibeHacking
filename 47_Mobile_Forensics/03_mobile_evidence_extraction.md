> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 모바일 증거 추출

## 목차
1. 추출 방식 비교
2. JTAG/Chip-off 방식 개요
3. dd/nanddump를 이용한 raw 이미지 추출
4. 해시값 검증 및 증거 무결성 체인
5. Python 자동 증거 수집 스크립트
6. 법적 증거능력 요건

---

## 1. 추출 방식 비교

### 추출 방식 계층 구조

```
물리적 추출 (Physical Extraction)
    └─ 가장 많은 데이터, 가장 어려움
파일시스템 추출 (File System Extraction)
    └─ 전체 파일시스템 접근
논리적 추출 (Logical Extraction)
    └─ 표준 API/백업 활용
클라우드 추출 (Cloud Extraction)
    └─ 계정 자격증명 또는 영장 필요
```

### 논리적 추출 (Logical Extraction)

```
정의: 기기의 표준 인터페이스(USB, API, 백업)를 통해 데이터 수집
     운영체제의 정상 채널 이용

장점:
- 기기 손상 위험 없음
- 빠른 수집
- 법적 근거 명확

단점:
- 삭제된 파일 복구 불가
- 접근 불가 파티션 존재
- 잠금 해제 필요

도구/방법:
- ADB (Android Debug Bridge)
- iTunes/Finder 백업
- Cellebrite UFED Logical
- MSAB XRY Logical
```

```bash
# Android 논리적 추출
adb backup -apk -shared -all -nosystem \
    -f logical_backup_$(date +%Y%m%d_%H%M%S).ab

# 특정 앱만 추출
adb backup -apk com.kakao.talk \
    -f kakao_backup_$(date +%Y%m%d).ab

# iOS 논리적 추출 (iTunes)
# macOS
idevicebackup2 backup --full ./ios_backup/
# Linux (libimobiledevice)
sudo apt install libimobiledevice-utils
idevicebackup2 backup ./ios_backup/
```

### 파일시스템 추출 (File System Extraction)

```
정의: 전체 파일시스템에 대한 접근 (루팅/탈옥 필요)
     논리적 추출보다 많은 데이터 수집 가능

Android 전제조건:
- 루팅된 기기 or ADB root 권한
- 또는 취약점(CVE) 활용

iOS 전제조건:
- 탈옥 (Jailbreak) 된 기기
- 또는 Cellebrite/GrayKey 취약점 활용
```

```bash
# Android 파일시스템 추출 (루팅 기기)
adb root
adb shell "tar czf /sdcard/fs_backup.tar.gz /data/ /system/"
adb pull /sdcard/fs_backup.tar.gz ./evidence/

# 특정 디렉토리만
adb shell "su -c 'cp -r /data/data /sdcard/app_data/'"
adb pull /sdcard/app_data/ ./evidence/app_data/

# iOS 파일시스템 추출 (탈옥 기기, OpenSSH 설치 필요)
ssh root@<device_ip> "tar czf - /private/var/mobile/" > ios_filesystem.tar.gz

# SHA256 즉시 계산
sha256sum ios_filesystem.tar.gz > ios_filesystem.sha256
```

### 물리적 추출 (Physical Extraction)

```
정의: 스토리지 칩에서 raw 바이트 단위 이미지 획득
     삭제 파일, 미할당 영역 포함

방법:
1. JTAG (Joint Test Action Group)
   - PCB의 테스트 포인트에 직접 연결
   - 기기 소분해 필요
   - 구형 기기에 효과적

2. Chip-off
   - 메모리 칩(eMMC/UFS/NAND) 물리적 제거
   - 전용 프로그래머로 직접 읽기
   - 기기 파괴 가능성
   - 최후 수단

3. ISP (In-System Programming)
   - 칩을 제거하지 않고 PCB에서 직접 읽기
   - Chip-off보다 덜 파괴적

4. eMMC/UFS 직접 읽기
   - 메인보드에서 eMMC 찾아 탐침 연결
   - 전용 인터페이스 어댑터 사용
```

### 클라우드 추출 (Cloud Extraction)

```
대상 서비스:
- iCloud (Apple)
- Google 계정 (Android)
- Samsung Cloud
- Kakao 서버 데이터
- SNS 플랫폼 (WhatsApp, Telegram)

방법:
1. 자격증명 기반 접근
   - 피의자/피해자 계정 정보 획득 시
   - 2FA 우회 필요할 수 있음

2. 법적 요청 (법원 영장)
   - Apple: https://www.apple.com/legal/privacy/law-enforcement/
   - Google: https://safety.google/transparency/
   - Meta: https://transparency.fb.com/

3. 토큰/쿠키 기반
   - 기기에서 인증 토큰 추출 후 재사용
   - 세션 하이재킹
```

---

## 2. JTAG/Chip-off 방식 개요

### JTAG (Joint Test Action Group)

```
표준: IEEE 1149.1
목적: 원래 PCB 제조 시 회로 테스트 용도
포렌식 활용: 기기 잠금 우회 없이 메모리 직접 읽기

JTAG 핀 구성:
- TDI (Test Data In)    : 데이터 입력
- TDO (Test Data Out)   : 데이터 출력
- TCK (Test Clock)      : 클럭 신호
- TMS (Test Mode Select): 모드 선택
- TRST (Test Reset)     : 리셋 (선택적)

작업 절차:
1. 기기 분해 (PCB 노출)
2. JTAG 핀 위치 확인 (데이터시트 또는 역공학)
3. JTAG 인터페이스(RIFF Box, HTC Box 등) 연결
4. 전용 소프트웨어로 메모리 덤프
5. 덤프 파일 포렌식 도구로 분석

지원 도구:
- RIFF Box 2 (www.riffbox.org)
- Octoplus Box
- Easy JTAG Box
- UFED Pro (Cellebrite, JTAG 포함)
```

### Chip-off

```
대상 칩:
- eMMC (Embedded MultiMediaCard): 스마트폰 주력
- UFS (Universal Flash Storage): 최신 고급 기기
- NAND Flash: 구형 기기

eMMC 패키지 유형:
- BGA (Ball Grid Array): 가장 흔함, 솔더링 필요
- LGA (Land Grid Array): 패드 형태

작업 절차:
1. 기기 완전 분해
2. PCB 확인, eMMC 칩 식별
3. 리워크 스테이션으로 칩 제거 (열풍기 또는 BGA 리워크)
4. 패드 세척 (플럭스 제거)
5. eMMC 소켓 어댑터에 장착
6. eMMC 프로그래머로 raw 덤프
7. 분석 후 필요 시 리볼링(재장착)

eMMC 프로그래머:
- UFi Box (UFi Soft)
- Easy JTAG Plus (Z3X)
- Medusa Pro 2
- ISP Pro (Moorc)

Chip-off 주의사항:
- 열 손상 위험: 과도한 열로 데이터 손실 가능
- 리볼링 필요: 데이터 읽은 후 원래 기기에 재장착
- 암호화: FDE/FBE 적용 시 raw 덤프만으로는 의미 없음
- 정전기 방지: ESD 방지 장갑 착용
```

### 암호화 고려사항

```
Android FDE (Full Disk Encryption, Android 5-9):
- 마스터 키: TEE(Trusted Execution Environment) 저장
- PIN/비밀번호 없이 복호화 불가
- Chip-off로 얻은 raw 덤프는 암호화 상태

Android FBE (File-Based Encryption, Android 7+):
- 파일별 개별 암호화
- CE(Credential Encrypted): PIN 입력 후 접근
- DE(Device Encrypted): 부팅 후 바로 접근 가능
- 일부 DE 파일은 PIN 없이 읽기 가능

iOS:
- 하드웨어 암호화 기본 적용 (AES-256)
- 파일별 보호 클래스 지정
- Secure Enclave: 암호화 키 관리
- PIN 없이 복호화 사실상 불가 (구형 기기 제외)
```

---

## 3. dd/nanddump를 이용한 raw 이미지 추출

### dd를 이용한 이미지 추출

```bash
# 기본 문법
dd if=<입력> of=<출력> bs=<블록크기> [conv=옵션]

# 전체 디스크 이미지 생성
dd if=/dev/sda of=disk_image.raw bs=4M status=progress conv=noerror,sync

# 파티션 이미지
dd if=/dev/sda2 of=data_partition.raw bs=4M status=progress

# 오류 발생 시 계속 진행 (noerror), 오류 블록을 0으로 채움 (sync)
dd if=/dev/mmcblk0 of=emmc_dump.raw bs=512 conv=noerror,sync status=progress

# 네트워크를 통한 원격 전송 (디스크 이미지를 다른 PC로)
# 수신 측에서 먼저 실행:
nc -l -p 9999 > remote_disk.raw
# 추출 측:
dd if=/dev/mmcblk0 bs=4M | nc <receiver_ip> 9999

# 분할 추출 (큰 디스크)
dd if=/dev/mmcblk0 bs=4M | split -b 2G - disk_split_
# 합치기:
cat disk_split_* > disk_image.raw
```

### Android 루팅 기기에서 파티션 추출

```bash
# 파티션 목록 확인
adb shell "su -c 'cat /proc/partitions'"
adb shell "su -c 'ls -la /dev/block/platform/*/by-name/'"

# 주요 파티션
# /dev/block/bootdevice/by-name/userdata  → /data 파티션
# /dev/block/bootdevice/by-name/system    → /system 파티션

# 루팅 기기에서 파티션 이미지 추출
adb shell "su -c 'dd if=/dev/block/bootdevice/by-name/userdata of=/sdcard/userdata.img bs=4096 conv=noerror,sync'"
adb pull /sdcard/userdata.img ./evidence/

# 또는 파이프로 직접 전송
adb shell "su -c 'dd if=/dev/block/bootdevice/by-name/userdata bs=4096 conv=noerror,sync'" > userdata.img

# 해시 검증 (추출 중 즉시)
adb shell "su -c 'dd if=/dev/block/bootdevice/by-name/userdata bs=4096 conv=noerror,sync | tee /sdcard/userdata.img | sha256sum'" > extraction_hash.txt
```

### nanddump (NAND 플래시)

```bash
# nanddump: MTD NAND 디바이스 덤프 도구
# 주로 구형 Android 기기 또는 임베디드 기기에 사용

# MTD 파티션 확인
cat /proc/mtd
# 예시 출력:
# dev:    size   erasesize  name
# mtd0: 00040000 00020000 "bootloader"
# mtd1: 00400000 00020000 "boot"
# mtd4: 0bc00000 00040000 "userdata"

# nanddump 기본 사용법
nanddump /dev/mtd4 -f userdata.nanddump

# ECC 오류 무시하고 덤프
nanddump -o /dev/mtd4 -f userdata_no_ecc.nanddump

# OOB (Out-Of-Band) 데이터 포함
nanddump --oob /dev/mtd4 -f userdata_with_oob.nanddump

# 특정 오프셋부터 덤프
nanddump -s 0x1000000 -l 0x4000000 /dev/mtd4 -f partial_dump.nanddump

# 진행상황 표시
nanddump -p /dev/mtd4 -f userdata.nanddump

# ADB를 통한 원격 nanddump
adb shell "su -c 'nanddump /dev/mtd4 -f /sdcard/mtd4.dump'"
adb pull /sdcard/mtd4.dump ./evidence/
```

### dcfldd (포렌식 특화 dd)

```bash
# dcfldd 설치
sudo apt install dcfldd

# 해시 계산하면서 복사 (MD5 + SHA256 동시)
dcfldd if=/dev/mmcblk0 of=device_image.raw \
    hash=md5,sha256 \
    hashwindow=1G \
    hashlog=hash_log.txt \
    errlog=error_log.txt \
    bs=4M \
    status=on

# 결과 검증
md5sum -c <(grep md5 hash_log.txt | awk '{print $3, $1}')

# 출력 분할
dcfldd if=/dev/sdb of=evidence_image.001 \
    hash=sha256 \
    hashlog=evidence_hash.txt \
    bs=512 \
    split=2G \
    splitformat=aa
```

---

## 4. 해시값 검증 및 증거 무결성 체인

### 해시 계산 명령어

```bash
# SHA256 (권장)
sha256sum evidence.img
sha256sum -c evidence.img.sha256   # 검증

# MD5 (호환성 목적)
md5sum evidence.img
md5sum -c evidence.img.md5

# SHA1
sha1sum evidence.img

# 여러 파일 동시 해시
find ./evidence/ -type f -exec sha256sum {} \; > all_files_hashes.txt

# 실시간 해시 (추출하면서 동시에)
dd if=/dev/mmcblk0 bs=4M | tee >(sha256sum > live_hash.txt) > device.img

# Python으로 대용량 파일 해시
python3 -c "
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], 'rb') as f:
    for chunk in iter(lambda: f.read(65536), b''):
        h.update(chunk)
print(h.hexdigest(), sys.argv[1])
" evidence.img
```

### 증거 무결성 체인 (Chain of Custody)

```
증거 수집 절차:
1. 현장 사진 촬영 (기기 상태, 화면)
2. 기기 식별 정보 기록 (모델, IMEI, 시리얼, 전화번호)
3. 원본 해시 계산 (수집 전)
4. 이미지 추출
5. 이미지 해시 계산 (수집 후)
6. 해시 비교 (원본 = 이미지)
7. 봉인 및 서명
8. 저장 (원본 분리 보관)

해시 불일치 시:
- 추출 과정 오류 → 재추출
- 장비 불량 → 다른 장비로 재시도
- 절대 원본 수정 금지
```

### 증거 태그 생성

```bash
# 기기 정보 수집 스크립트 (Android)
cat << 'EOF' > collect_device_info.sh
#!/bin/bash
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EVIDENCE_DIR="./evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "=== 증거 수집 시작 ===" | tee "$EVIDENCE_DIR/collection_log.txt"
echo "수집 시간 (UTC): $TIMESTAMP" | tee -a "$EVIDENCE_DIR/collection_log.txt"
echo "수집자: $(whoami)@$(hostname)" | tee -a "$EVIDENCE_DIR/collection_log.txt"

# 기기 정보 수집
echo "--- 기기 정보 ---" | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell getprop ro.product.model | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell getprop ro.serialno | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell getprop ro.build.version.release | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell settings get secure android_id | tee -a "$EVIDENCE_DIR/collection_log.txt"

echo "=== 수집 완료 ===" | tee -a "$EVIDENCE_DIR/collection_log.txt"
EOF
chmod +x collect_device_info.sh
```

### 검증 리포트 생성

```bash
# 증거 검증 보고서
generate_verification_report() {
    local IMAGE_FILE="$1"
    local REPORT_FILE="${IMAGE_FILE%.img}_verification.txt"

    echo "증거 무결성 검증 보고서" > "$REPORT_FILE"
    echo "========================" >> "$REPORT_FILE"
    echo "생성 시간: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "파일: $IMAGE_FILE" >> "$REPORT_FILE"
    echo "크기: $(stat -c '%s' "$IMAGE_FILE") bytes" >> "$REPORT_FILE"
    echo "MD5:    $(md5sum "$IMAGE_FILE" | awk '{print $1}')" >> "$REPORT_FILE"
    echo "SHA1:   $(sha1sum "$IMAGE_FILE" | awk '{print $1}')" >> "$REPORT_FILE"
    echo "SHA256: $(sha256sum "$IMAGE_FILE" | awk '{print $1}')" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "검증자: $(whoami)@$(hostname)" >> "$REPORT_FILE"
    cat "$REPORT_FILE"
}
```

---

## 5. Python 자동 증거 수집 스크립트

```python
#!/usr/bin/env python3
"""
모바일 포렌식 자동 증거 수집 스크립트

ADB 연결된 Android 기기 또는 지정된 이미지 파일에 대해
자동으로 증거를 수집하고, 해시를 검증하며 보고서를 생성합니다.

사용법:
    # Android 기기에서 수집
    python3 evidence_collector.py --device -o ./evidence_case001

    # 이미지 파일 검증 보고서 생성
    python3 evidence_collector.py --image device.img -o ./evidence_case001

    # 전체 옵션
    python3 evidence_collector.py --device -o ./output \
        --case-number KN-2025-001 \
        --examiner "홍길동" \
        --collect-adb \
        --collect-logs \
        --verbose
"""

import argparse
import hashlib
import json
import os
import platform
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── 데이터 클래스 ──────────────────────────────────────────

@dataclass
class DeviceInfo:
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    build_fingerprint: str = ""
    serial_number: str = ""
    android_id: str = ""
    imei: str = ""
    phone_number: str = ""
    timezone: str = ""
    device_time: str = ""
    battery_level: str = ""
    encryption_status: str = ""
    usb_debugging: bool = False


@dataclass
class FileHash:
    filepath: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    computed_at: str


@dataclass
class CollectionEvent:
    timestamp: str
    event_type: str
    description: str
    status: str  # "success" | "failure" | "warning"
    details: str = ""


@dataclass
class EvidenceReport:
    case_number: str
    examiner_name: str
    collection_start: str
    collection_end: str
    workstation: str
    os_version: str
    tool_version: str
    device_info: dict
    collected_files: list[dict]
    file_hashes: list[dict]
    events: list[dict]
    chain_of_custody: list[dict]


# ─── 유틸리티 함수 ──────────────────────────────────────────

def compute_hashes(filepath: Path) -> FileHash:
    """파일의 MD5, SHA1, SHA256 해시 동시 계산"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)

    return FileHash(
        filepath=str(filepath),
        size_bytes=size,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        computed_at=datetime.now(tz=timezone.utc).isoformat(),
    )


def run_command(cmd: list[str], timeout: int = 30) -> tuple[bool, str, str]:
    """명령 실행 및 결과 반환 (성공여부, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", f"타임아웃 ({timeout}초)"
    except FileNotFoundError:
        return False, "", f"명령을 찾을 수 없음: {cmd[0]}"


def adb(args: list[str], timeout: int = 30) -> tuple[bool, str, str]:
    """ADB 명령 래퍼"""
    return run_command(["adb", "shell"] + args, timeout=timeout)


def adb_pull(remote: str, local: Path, timeout: int = 300) -> bool:
    """ADB pull 명령"""
    ok, stdout, stderr = run_command(
        ["adb", "pull", remote, str(local)], timeout=timeout
    )
    return ok


# ─── 기기 정보 수집 ──────────────────────────────────────────

def collect_device_info() -> DeviceInfo:
    """Android 기기 정보 수집"""
    info = DeviceInfo()

    props = {
        "model": ["getprop", "ro.product.model"],
        "manufacturer": ["getprop", "ro.product.manufacturer"],
        "android_version": ["getprop", "ro.build.version.release"],
        "build_fingerprint": ["getprop", "ro.build.fingerprint"],
        "serial_number": ["getprop", "ro.serialno"],
        "timezone": ["getprop", "persist.sys.timezone"],
    }

    for attr, args in props.items():
        ok, stdout, _ = adb(args)
        if ok:
            setattr(info, attr, stdout)

    # Android ID
    ok, stdout, _ = adb(["settings", "get", "secure", "android_id"])
    if ok:
        info.android_id = stdout

    # 현재 시간
    ok, stdout, _ = adb(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"])
    if ok:
        info.device_time = stdout

    # 배터리
    ok, stdout, _ = adb(["dumpsys", "battery"])
    if ok:
        for line in stdout.split("\n"):
            if "level:" in line:
                info.battery_level = line.strip()
                break

    # 암호화 상태
    ok, stdout, _ = adb(["getprop", "ro.crypto.state"])
    if ok:
        info.encryption_status = stdout

    return info


# ─── ADB 아티팩트 수집 ───────────────────────────────────────

def collect_adb_artifacts(
    output_dir: Path,
    events: list[CollectionEvent],
    verbose: bool = False,
) -> list[Path]:
    """ADB를 통한 아티팩트 수집"""
    collected: list[Path] = []

    artifacts = [
        ("/sdcard/DCIM", "media/DCIM"),
        ("/sdcard/Download", "media/Download"),
        ("/sdcard/WhatsApp", "media/WhatsApp"),
        ("/sdcard/KakaoTalk", "media/KakaoTalk"),
        ("/sdcard/Telegram", "media/Telegram"),
    ]

    for remote_path, local_subdir in artifacts:
        local_path = output_dir / local_subdir
        local_path.mkdir(parents=True, exist_ok=True)

        if verbose:
            print(f"  수집 중: {remote_path}")

        ok = adb_pull(remote_path, local_path, timeout=600)
        status = "success" if ok else "failure"

        events.append(CollectionEvent(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            event_type="adb_pull",
            description=f"ADB Pull: {remote_path}",
            status=status,
            details=f"→ {local_path}",
        ))

        if ok:
            collected.append(local_path)

    return collected


def collect_system_logs(
    output_dir: Path,
    events: list[CollectionEvent],
) -> list[Path]:
    """시스템 로그 수집"""
    collected: list[Path] = []
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    log_commands = {
        "logcat_main.txt": ["logcat", "-d", "-b", "main"],
        "logcat_events.txt": ["logcat", "-d", "-b", "events"],
        "logcat_crash.txt": ["logcat", "-d", "-b", "crash"],
        "logcat_radio.txt": ["logcat", "-d", "-b", "radio"],
        "dumpsys_battery.txt": ["dumpsys", "battery"],
        "dumpsys_usagestats.txt": ["dumpsys", "usagestats"],
        "dumpsys_location.txt": ["dumpsys", "location"],
        "dumpsys_notification.txt": ["dumpsys", "notification"],
        "dumpsys_telephony.txt": ["dumpsys", "telephony.registry"],
        "packages.txt": ["pm", "list", "packages", "-f"],
        "processes.txt": ["ps", "-ef"],
        "netstat.txt": ["netstat", "-tnp"],
    }

    for filename, cmd in log_commands.items():
        output_file = logs_dir / filename
        ok, stdout, stderr = adb(cmd, timeout=60)

        if ok and stdout:
            output_file.write_text(stdout, encoding="utf-8")
            collected.append(output_file)
            events.append(CollectionEvent(
                timestamp=datetime.now(tz=timezone.utc).isoformat(),
                event_type="log_collection",
                description=f"로그 수집: {filename}",
                status="success",
                details=f"크기: {len(stdout)} bytes",
            ))
        else:
            events.append(CollectionEvent(
                timestamp=datetime.now(tz=timezone.utc).isoformat(),
                event_type="log_collection",
                description=f"로그 수집 실패: {filename}",
                status="failure",
                details=stderr[:200],
            ))

    return collected


# ─── 이미지 파일 검증 ────────────────────────────────────────

def verify_image_file(
    image_path: Path,
    output_dir: Path,
    events: list[CollectionEvent],
    verbose: bool = False,
) -> Optional[FileHash]:
    """이미지 파일 무결성 검증"""
    if not image_path.exists():
        events.append(CollectionEvent(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            event_type="image_verification",
            description=f"이미지 파일 없음: {image_path}",
            status="failure",
        ))
        return None

    if verbose:
        print(f"  해시 계산 중: {image_path} ({image_path.stat().st_size:,} bytes)")

    start_time = time.time()
    file_hash = compute_hashes(image_path)
    elapsed = time.time() - start_time

    events.append(CollectionEvent(
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        event_type="hash_computed",
        description=f"이미지 해시 계산 완료: {image_path.name}",
        status="success",
        details=f"SHA256: {file_hash.sha256} | 소요시간: {elapsed:.1f}초",
    ))

    # 해시 파일 저장
    hash_file = output_dir / f"{image_path.name}.hashes"
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(f"파일: {image_path}\n")
        f.write(f"크기: {file_hash.size_bytes:,} bytes\n")
        f.write(f"MD5:    {file_hash.md5}\n")
        f.write(f"SHA1:   {file_hash.sha1}\n")
        f.write(f"SHA256: {file_hash.sha256}\n")
        f.write(f"계산 시간: {file_hash.computed_at}\n")

    return file_hash


# ─── 보고서 생성 ─────────────────────────────────────────────

def collect_all_hashes(
    output_dir: Path,
    events: list[CollectionEvent],
    verbose: bool = False,
) -> list[FileHash]:
    """수집된 모든 파일의 해시 계산"""
    hashes: list[FileHash] = []

    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        # 보고서 파일 자체 제외
        if path.suffix in (".json", ".txt") and "report" in path.name:
            continue

        if verbose:
            print(f"  해시: {path.relative_to(output_dir)}")

        try:
            file_hash = compute_hashes(path)
            hashes.append(file_hash)
        except (OSError, PermissionError) as e:
            events.append(CollectionEvent(
                timestamp=datetime.now(tz=timezone.utc).isoformat(),
                event_type="hash_error",
                description=f"해시 계산 실패: {path}",
                status="failure",
                details=str(e),
            ))

    return hashes


def generate_report(
    case_number: str,
    examiner_name: str,
    start_time: str,
    device_info: Optional[DeviceInfo],
    collected_files: list[Path],
    hashes: list[FileHash],
    events: list[CollectionEvent],
    output_dir: Path,
) -> Path:
    """최종 포렌식 수집 보고서 생성"""
    end_time = datetime.now(tz=timezone.utc).isoformat()

    chain_of_custody = [
        {
            "단계": "수집",
            "시간": start_time,
            "담당자": examiner_name,
            "작업": "증거 수집 시작",
            "상태": "완료",
        },
        {
            "단계": "해시 검증",
            "시간": end_time,
            "담당자": examiner_name,
            "작업": f"{len(hashes)}개 파일 해시 계산",
            "상태": "완료",
        },
        {
            "단계": "보고서 생성",
            "시간": end_time,
            "담당자": examiner_name,
            "작업": "포렌식 수집 보고서 작성",
            "상태": "완료",
        },
    ]

    report_data = {
        "보고서_버전": "1.0",
        "사건_번호": case_number,
        "조사관": examiner_name,
        "수집_시작": start_time,
        "수집_완료": end_time,
        "수집_환경": {
            "워크스테이션": socket.gethostname(),
            "OS": platform.platform(),
            "Python": platform.python_version(),
        },
        "기기_정보": asdict(device_info) if device_info else {},
        "수집_파일_수": len(collected_files),
        "해시_검증_파일_수": len(hashes),
        "이벤트_로그": [asdict(e) for e in events],
        "증거_보관_체인": chain_of_custody,
        "파일_해시_목록": [asdict(h) for h in hashes],
    }

    json_path = output_dir / "evidence_collection_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)

    # 텍스트 요약 보고서
    txt_path = output_dir / "evidence_collection_report.txt"
    success_events = sum(1 for e in events if e.status == "success")
    fail_events = sum(1 for e in events if e.status == "failure")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("모바일 포렌식 증거 수집 보고서\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"사건 번호:    {case_number}\n")
        f.write(f"조사관:       {examiner_name}\n")
        f.write(f"수집 시작:    {start_time}\n")
        f.write(f"수집 완료:    {end_time}\n")
        f.write(f"워크스테이션: {socket.gethostname()}\n\n")

        if device_info:
            f.write("-" * 40 + "\n")
            f.write("기기 정보\n")
            f.write("-" * 40 + "\n")
            f.write(f"모델:          {device_info.model}\n")
            f.write(f"제조사:        {device_info.manufacturer}\n")
            f.write(f"Android 버전:  {device_info.android_version}\n")
            f.write(f"시리얼:        {device_info.serial_number}\n")
            f.write(f"Android ID:    {device_info.android_id}\n")
            f.write(f"기기 시간:     {device_info.device_time}\n")
            f.write(f"암호화 상태:   {device_info.encryption_status}\n\n")

        f.write("-" * 40 + "\n")
        f.write("수집 요약\n")
        f.write("-" * 40 + "\n")
        f.write(f"수집 파일:     {len(collected_files)}개\n")
        f.write(f"해시 검증:     {len(hashes)}개\n")
        f.write(f"성공 이벤트:   {success_events}개\n")
        f.write(f"실패 이벤트:   {fail_events}개\n\n")

        f.write("-" * 40 + "\n")
        f.write("파일 해시 (SHA256)\n")
        f.write("-" * 40 + "\n")
        for h in hashes[:50]:
            rel_path = Path(h.filepath).name
            f.write(f"{h.sha256}  {rel_path}\n")

        f.write("\n-" * 40 + "\n")
        f.write("이벤트 로그\n")
        f.write("-" * 40 + "\n")
        for event in events:
            status_mark = "✓" if event.status == "success" else "✗"
            f.write(f"[{event.timestamp}] {status_mark} {event.description}\n")
            if event.details:
                f.write(f"   {event.details}\n")

    return json_path


# ─── 메인 ────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="모바일 포렌식 자동 증거 수집 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s --device -o ./evidence
  %(prog)s --device -o ./evidence --case-number KN-2025-001 --examiner "홍길동"
  %(prog)s --image device.img -o ./evidence --case-number KN-2025-001
  %(prog)s --device -o ./evidence --collect-adb --collect-logs --verbose
        """,
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--device", action="store_true", help="ADB 연결 기기에서 수집")
    mode_group.add_argument("--image", help="이미지 파일 검증 및 보고서 생성")

    parser.add_argument("-o", "--output", required=True, help="출력 디렉토리")
    parser.add_argument("--case-number", default="CASE-UNKNOWN", help="사건 번호")
    parser.add_argument("--examiner", default="Unknown", help="조사관 이름")
    parser.add_argument("--collect-adb", action="store_true", help="ADB 아티팩트 수집")
    parser.add_argument("--collect-logs", action="store_true", help="시스템 로그 수집")
    parser.add_argument("--compute-hashes", action="store_true", help="수집 파일 해시 계산")
    parser.add_argument("--all", action="store_true", help="모든 수집 옵션 활성화")
    parser.add_argument("--verbose", "-v", action="store_true", help="상세 출력")

    args = parser.parse_args()

    if args.all:
        args.collect_adb = True
        args.collect_logs = True
        args.compute_hashes = True

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    start_time = datetime.now(tz=timezone.utc).isoformat()
    events: list[CollectionEvent] = []
    collected_files: list[Path] = []
    hashes: list[FileHash] = []
    device_info: Optional[DeviceInfo] = None

    events.append(CollectionEvent(
        timestamp=start_time,
        event_type="collection_start",
        description="증거 수집 프로세스 시작",
        status="success",
        details=f"사건 번호: {args.case_number} | 조사관: {args.examiner}",
    ))

    if args.device:
        print("[*] Android 기기 정보 수집 중...")
        device_info = collect_device_info()
        print(f"    모델: {device_info.model}")
        print(f"    Android: {device_info.android_version}")
        print(f"    시리얼: {device_info.serial_number}")
        print(f"    기기 시간 (UTC): {device_info.device_time}")

        events.append(CollectionEvent(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            event_type="device_info",
            description="기기 정보 수집 완료",
            status="success",
            details=f"모델: {device_info.model}, 시리얼: {device_info.serial_number}",
        ))

        if args.collect_adb:
            print("[*] ADB 아티팩트 수집 중...")
            new_files = collect_adb_artifacts(output_dir, events, args.verbose)
            collected_files.extend(new_files)
            print(f"    수집: {len(new_files)}개 경로")

        if args.collect_logs:
            print("[*] 시스템 로그 수집 중...")
            new_files = collect_system_logs(output_dir, events)
            collected_files.extend(new_files)
            print(f"    로그: {len(new_files)}개 파일")

    elif args.image:
        image_path = Path(args.image)
        print(f"[*] 이미지 파일 검증 중: {image_path}")
        file_hash = verify_image_file(image_path, output_dir, events, args.verbose)
        if file_hash:
            hashes.append(file_hash)
            print(f"    SHA256: {file_hash.sha256}")
            print(f"    크기: {file_hash.size_bytes:,} bytes")

    if args.compute_hashes:
        print("[*] 수집 파일 해시 계산 중...")
        hashes.extend(collect_all_hashes(output_dir, events, args.verbose))
        print(f"    계산 완료: {len(hashes)}개")

    print("[*] 증거 수집 보고서 생성 중...")
    report_path = generate_report(
        case_number=args.case_number,
        examiner_name=args.examiner,
        start_time=start_time,
        device_info=device_info,
        collected_files=collected_files,
        hashes=hashes,
        events=events,
        output_dir=output_dir,
    )
    print(f"    JSON: {report_path}")
    print(f"    TXT:  {output_dir / 'evidence_collection_report.txt'}")

    success_count = sum(1 for e in events if e.status == "success")
    fail_count = sum(1 for e in events if e.status == "failure")
    print(f"\n[완료] 성공: {success_count} | 실패: {fail_count}")
    print(f"[완료] 결과 저장: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. 법적 증거능력 요건

### 한국 형사소송법 관련 조항

**디지털 증거 관련 주요 조항**

```
형사소송법 제106조 (압수)
- 법원은 필요한 때에는 피고사건과 관계가 있다고 인정할 수 있는 것에 한정하여
  증거물 또는 몰수할 것으로 사료하는 물건을 압수할 수 있음

형사소송법 제215조 (압수, 수색, 검증)
- 검사 또는 사법경찰관은 범죄 수사에 필요한 때에는
  피의자가 죄를 범하였다고 의심할 만한 정황이 있고
  해당 사건과 관계가 있다고 인정할 수 있는 것에 한정하여
  지방법원판사에게 청구하여 발부받은 영장에 의하여 압수, 수색 또는 검증할 수 있음

디지털 증거의 증거능력:
- 동일성: 원본과 사본이 동일한가 (해시값으로 증명)
- 무결성: 수집 후 변경이 없었는가 (Chain of Custody)
- 진정성: 실제 기기에서 수집된 것인가
- 신뢰성: 수집 도구와 절차가 신뢰할 수 있는가
```

### 디지털 증거 수집 원칙

```
1. 원본 보존 원칙
   - 원본 기기/데이터는 절대 수정 금지
   - 쓰기 차단(Write Blocker) 사용
   - 읽기 전용 마운트 또는 이미지 사본으로 분석

2. 무결성 원칙
   - 수집 전후 해시값 기록 및 비교
   - 해시 불일치 시 수집 중단 및 재수집
   - 모든 단계 기록 유지

3. 문서화 원칙
   - 수집 일시, 장소, 담당자 기록
   - 사용 도구 및 버전 기록
   - 모든 작업 단계 로그 유지

4. 보관 연속성 (Chain of Custody)
   - 증거 이전 시마다 서명 및 기록
   - 보관 환경 기록 (온도, 습도, 접근 기록)
   - 포장 및 봉인 상태 유지
```

### 모바일 기기 압수 시 주의사항

```bash
현장 도착 즉시:
1. 기기 화면 상태 사진 촬영 (켜진 경우)
2. 기기 전원 상태 확인 (켜짐/꺼짐)
3. 네트워크 격리 (비행기 모드 또는 Faraday 가방)
4. 충전 상태 유지 (방전 방지)

켜진 기기 처리:
- Before First Unlock(BFU): 기기 끄지 말 것 → 켜진 상태로 보존
- After First Unlock(AFU): 더 많은 데이터 접근 가능
- USB Restricted Mode 확인 (iOS)

꺼진 기기 처리:
- 켜지 않는 것이 원칙 (PIN 입력 없이 BFU 상태 유지)
- JTAG/Chip-off 방식 검토

Faraday 가방 (전자기 차폐):
- RF 신호 완전 차단 (원격 삭제 방지)
- 네트워크 연결 불가 환경 유지
- 전자기 간섭 방지
```

### 증거 수집 동의서 및 영장

```
임의 제출:
- 피의자/참고인이 자발적으로 제출
- 영장 없이 수집 가능
- 동의서 작성 필수
- 동의 범위 명확히 특정 (기기 전체 vs 특정 데이터)

압수수색 영장:
- 혐의 사실 특정
- 압수 대상 물건 특정 (기기 종류, 데이터 유형)
- 영장 범위 내에서만 수집 가능
- 관련성 없는 데이터 수집 불가

통신사실확인자료:
- 형사소송법 제215조의2 이하
- 통화 기록, 위치 정보 등
- 법원 허가 필요
- 보존 기간: 통화 기록 12개월, 문자 3개월 (전기통신사업법)
```

### 디지털 증거 감정서 작성 요소

```
1. 감정 경위
   - 의뢰 기관, 의뢰 일자
   - 감정 대상물 수령 경위
   - 감정 목적

2. 감정 대상물 현황
   - 기기 외관 사진
   - 식별 정보 (모델, 시리얼, IMEI)
   - 수령 당시 상태

3. 감정 방법
   - 사용 도구 및 버전
   - 수집 절차
   - 분석 방법

4. 감정 결과
   - 원본 해시값
   - 이미지 해시값
   - 발견된 아티팩트
   - 타임라인

5. 감정 의견
   - 발견 사실 요약
   - 법적 판단에 도움이 되는 기술적 사실

6. 별첨
   - 해시값 비교표
   - 스크린샷
   - DB 분석 결과
```

---

## 실전 참고 명령어 모음

```bash
# 쓰기 차단 장치 없이 읽기 전용 마운트
mount -o ro,noexec,nosuid /dev/sdb1 /mnt/evidence

# 이미지에서 파티션 정보 확인
mmls device.img
fdisk -l device.img

# The Sleuth Kit (TSK) 활용
fls -r device.img 1                    # 파티션 1의 파일 목록
icat device.img 1 <inode>              # 특정 inode 내용 추출
ils device.img 1                       # 삭제된 inode 목록

# Autopsy GUI 실행
autopsy &

# Volatility (메모리 포렌식, 연계 활용)
# 모바일 RAM 덤프 분석
vol.py -f memory.lime --profile=LinuxAndroid imageinfo
vol.py -f memory.lime --profile=LinuxAndroid linux_pslist
```

---

<a name="english"></a>

# Mobile Evidence Extraction

## Table of Contents
1. Extraction Method Comparison
2. JTAG/Chip-off Method Overview
3. Raw Image Extraction with dd/nanddump
4. Hash Verification and Evidence Chain of Integrity
5. Python Automated Evidence Collection Script
6. Legal Admissibility Requirements

---

## 1. Extraction Method Comparison

### Extraction Method Hierarchy

```
Physical Extraction
    └─ Most data, most difficult
File System Extraction
    └─ Full filesystem access
Logical Extraction
    └─ Uses standard APIs/backups
Cloud Extraction
    └─ Requires account credentials or warrant
```

### Logical Extraction

```
Definition: Collect data via the device's standard interface (USB, API, backup)
            Uses the operating system's normal channels

Advantages:
- No risk of device damage
- Fast collection
- Clear legal basis

Disadvantages:
- Cannot recover deleted files
- Some partitions inaccessible
- Requires device unlock

Tools/Methods:
- ADB (Android Debug Bridge)
- iTunes/Finder backup
- Cellebrite UFED Logical
- MSAB XRY Logical
```

```bash
# Android logical extraction
adb backup -apk -shared -all -nosystem \
    -f logical_backup_$(date +%Y%m%d_%H%M%S).ab

# Extract specific app only
adb backup -apk com.kakao.talk \
    -f kakao_backup_$(date +%Y%m%d).ab

# iOS logical extraction (iTunes)
# macOS
idevicebackup2 backup --full ./ios_backup/
# Linux (libimobiledevice)
sudo apt install libimobiledevice-utils
idevicebackup2 backup ./ios_backup/
```

### File System Extraction

```
Definition: Full filesystem access (requires root/jailbreak)
            More data than logical extraction

Android prerequisites:
- Rooted device or ADB root access
- Or exploit a vulnerability (CVE)

iOS prerequisites:
- Jailbroken device
- Or Cellebrite/GrayKey exploit
```

```bash
# Android filesystem extraction (rooted device)
adb root
adb shell "tar czf /sdcard/fs_backup.tar.gz /data/ /system/"
adb pull /sdcard/fs_backup.tar.gz ./evidence/

# Specific directory only
adb shell "su -c 'cp -r /data/data /sdcard/app_data/'"
adb pull /sdcard/app_data/ ./evidence/app_data/

# iOS filesystem extraction (jailbroken device, requires OpenSSH)
ssh root@<device_ip> "tar czf - /private/var/mobile/" > ios_filesystem.tar.gz

# Compute SHA256 immediately
sha256sum ios_filesystem.tar.gz > ios_filesystem.sha256
```

### Physical Extraction

```
Definition: Acquire raw byte-level image from storage chip
            Includes deleted files and unallocated areas

Methods:
1. JTAG (Joint Test Action Group)
   - Connect directly to test points on PCB
   - Requires partial device disassembly
   - Effective on older devices

2. Chip-off
   - Physically remove memory chip (eMMC/UFS/NAND)
   - Read directly with dedicated programmer
   - Risk of device destruction
   - Last resort

3. ISP (In-System Programming)
   - Read directly from PCB without removing chip
   - Less destructive than chip-off

4. eMMC/UFS direct read
   - Find eMMC on motherboard and attach probe
   - Use dedicated interface adapter
```

### Cloud Extraction

```
Target services:
- iCloud (Apple)
- Google account (Android)
- Samsung Cloud
- Kakao server data
- SNS platforms (WhatsApp, Telegram)

Methods:
1. Credential-based access
   - When suspect/victim account info is obtained
   - May require 2FA bypass

2. Legal request (court warrant)
   - Apple: https://www.apple.com/legal/privacy/law-enforcement/
   - Google: https://safety.google/transparency/
   - Meta: https://transparency.fb.com/

3. Token/cookie-based
   - Extract auth tokens from device and reuse
   - Session hijacking
```

---

## 2. JTAG/Chip-off Method Overview

### JTAG (Joint Test Action Group)

```
Standard: IEEE 1149.1
Purpose: Originally used for circuit testing in PCB manufacturing
Forensic use: Read memory directly without bypassing device lock

JTAG pin configuration:
- TDI (Test Data In)    : Data input
- TDO (Test Data Out)   : Data output
- TCK (Test Clock)      : Clock signal
- TMS (Test Mode Select): Mode selection
- TRST (Test Reset)     : Reset (optional)

Procedure:
1. Disassemble device (expose PCB)
2. Locate JTAG pins (via datasheet or reverse engineering)
3. Connect JTAG interface (RIFF Box, HTC Box, etc.)
4. Dump memory with dedicated software
5. Analyze dump file with forensic tools

Supported tools:
- RIFF Box 2 (www.riffbox.org)
- Octoplus Box
- Easy JTAG Box
- UFED Pro (Cellebrite, includes JTAG)
```

### Chip-off

```
Target chips:
- eMMC (Embedded MultiMediaCard): Dominant in smartphones
- UFS (Universal Flash Storage): Latest high-end devices
- NAND Flash: Older devices

eMMC package types:
- BGA (Ball Grid Array): Most common, requires soldering
- LGA (Land Grid Array): Pad-based

Procedure:
1. Fully disassemble device
2. Identify PCB, locate eMMC chip
3. Remove chip with rework station (hot air or BGA rework)
4. Clean pads (remove flux)
5. Mount in eMMC socket adapter
6. Create raw dump with eMMC programmer
7. Reflow (remount) if needed after analysis

eMMC programmers:
- UFi Box (UFi Soft)
- Easy JTAG Plus (Z3X)
- Medusa Pro 2
- ISP Pro (Moorc)

Chip-off precautions:
- Heat damage risk: Excessive heat can cause data loss
- Reflowing required: Remount in original device after reading
- Encryption: FDE/FBE renders raw dump meaningless alone
- Anti-static: Wear ESD gloves
```

### Encryption Considerations

```
Android FDE (Full Disk Encryption, Android 5-9):
- Master key: Stored in TEE (Trusted Execution Environment)
- Cannot decrypt without PIN/password
- Raw dump obtained via chip-off remains encrypted

Android FBE (File-Based Encryption, Android 7+):
- Individual file encryption
- CE (Credential Encrypted): Accessible after PIN entry
- DE (Device Encrypted): Accessible immediately after boot
- Some DE files can be read without PIN

iOS:
- Hardware encryption by default (AES-256)
- Per-file protection class assignment
- Secure Enclave: Manages encryption keys
- Practically impossible to decrypt without PIN (except older devices)
```

---

## 3. Raw Image Extraction with dd/nanddump

### Image Extraction with dd

```bash
# Basic syntax
dd if=<input> of=<output> bs=<block_size> [conv=options]

# Create full disk image
dd if=/dev/sda of=disk_image.raw bs=4M status=progress conv=noerror,sync

# Partition image
dd if=/dev/sda2 of=data_partition.raw bs=4M status=progress

# Continue on error (noerror), fill error blocks with zeros (sync)
dd if=/dev/mmcblk0 of=emmc_dump.raw bs=512 conv=noerror,sync status=progress

# Remote transfer over network (send disk image to another PC)
# On receiver side first:
nc -l -p 9999 > remote_disk.raw
# On extraction side:
dd if=/dev/mmcblk0 bs=4M | nc <receiver_ip> 9999

# Split extraction (large disks)
dd if=/dev/mmcblk0 bs=4M | split -b 2G - disk_split_
# Reassemble:
cat disk_split_* > disk_image.raw
```

### Partition Extraction from Rooted Android Device

```bash
# List partitions
adb shell "su -c 'cat /proc/partitions'"
adb shell "su -c 'ls -la /dev/block/platform/*/by-name/'"

# Key partitions
# /dev/block/bootdevice/by-name/userdata  → /data partition
# /dev/block/bootdevice/by-name/system    → /system partition

# Extract partition image from rooted device
adb shell "su -c 'dd if=/dev/block/bootdevice/by-name/userdata of=/sdcard/userdata.img bs=4096 conv=noerror,sync'"
adb pull /sdcard/userdata.img ./evidence/

# Or pipe directly
adb shell "su -c 'dd if=/dev/block/bootdevice/by-name/userdata bs=4096 conv=noerror,sync'" > userdata.img

# Hash verification (immediate during extraction)
adb shell "su -c 'dd if=/dev/block/bootdevice/by-name/userdata bs=4096 conv=noerror,sync | tee /sdcard/userdata.img | sha256sum'" > extraction_hash.txt
```

### nanddump (NAND Flash)

```bash
# nanddump: MTD NAND device dump tool
# Mainly used for older Android devices or embedded devices

# Check MTD partitions
cat /proc/mtd
# Example output:
# dev:    size   erasesize  name
# mtd0: 00040000 00020000 "bootloader"
# mtd1: 00400000 00020000 "boot"
# mtd4: 0bc00000 00040000 "userdata"

# nanddump basic usage
nanddump /dev/mtd4 -f userdata.nanddump

# Dump ignoring ECC errors
nanddump -o /dev/mtd4 -f userdata_no_ecc.nanddump

# Include OOB (Out-Of-Band) data
nanddump --oob /dev/mtd4 -f userdata_with_oob.nanddump

# Dump from specific offset
nanddump -s 0x1000000 -l 0x4000000 /dev/mtd4 -f partial_dump.nanddump

# Show progress
nanddump -p /dev/mtd4 -f userdata.nanddump

# Remote nanddump via ADB
adb shell "su -c 'nanddump /dev/mtd4 -f /sdcard/mtd4.dump'"
adb pull /sdcard/mtd4.dump ./evidence/
```

### dcfldd (Forensic-Specialized dd)

```bash
# Install dcfldd
sudo apt install dcfldd

# Copy with simultaneous hash computation (MD5 + SHA256)
dcfldd if=/dev/mmcblk0 of=device_image.raw \
    hash=md5,sha256 \
    hashwindow=1G \
    hashlog=hash_log.txt \
    errlog=error_log.txt \
    bs=4M \
    status=on

# Verify result
md5sum -c <(grep md5 hash_log.txt | awk '{print $3, $1}')

# Split output
dcfldd if=/dev/sdb of=evidence_image.001 \
    hash=sha256 \
    hashlog=evidence_hash.txt \
    bs=512 \
    split=2G \
    splitformat=aa
```

---

## 4. Hash Verification and Evidence Chain of Integrity

### Hash Computation Commands

```bash
# SHA256 (recommended)
sha256sum evidence.img
sha256sum -c evidence.img.sha256   # Verify

# MD5 (for compatibility)
md5sum evidence.img
md5sum -c evidence.img.md5

# SHA1
sha1sum evidence.img

# Hash multiple files simultaneously
find ./evidence/ -type f -exec sha256sum {} \; > all_files_hashes.txt

# Live hash (compute simultaneously while extracting)
dd if=/dev/mmcblk0 bs=4M | tee >(sha256sum > live_hash.txt) > device.img

# Python hash for large files
python3 -c "
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], 'rb') as f:
    for chunk in iter(lambda: f.read(65536), b''):
        h.update(chunk)
print(h.hexdigest(), sys.argv[1])
" evidence.img
```

### Chain of Custody

```
Evidence collection procedure:
1. Photograph the scene (device condition, screen)
2. Record device identification info (model, IMEI, serial, phone number)
3. Compute original hash (before collection)
4. Extract image
5. Compute image hash (after collection)
6. Compare hashes (original = image)
7. Seal and sign
8. Store (keep original separately)

If hash mismatch:
- Extraction process error → Re-extract
- Equipment failure → Retry with different equipment
- Never modify the original
```

### Evidence Tag Generation

```bash
# Device info collection script (Android)
cat << 'EOF' > collect_device_info.sh
#!/bin/bash
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EVIDENCE_DIR="./evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "=== Evidence Collection Start ===" | tee "$EVIDENCE_DIR/collection_log.txt"
echo "Collection time (UTC): $TIMESTAMP" | tee -a "$EVIDENCE_DIR/collection_log.txt"
echo "Collector: $(whoami)@$(hostname)" | tee -a "$EVIDENCE_DIR/collection_log.txt"

# Device info collection
echo "--- Device Info ---" | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell getprop ro.product.model | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell getprop ro.serialno | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell getprop ro.build.version.release | tee -a "$EVIDENCE_DIR/collection_log.txt"
adb shell settings get secure android_id | tee -a "$EVIDENCE_DIR/collection_log.txt"

echo "=== Collection Complete ===" | tee -a "$EVIDENCE_DIR/collection_log.txt"
EOF
chmod +x collect_device_info.sh
```

---

## 5. Python Automated Evidence Collection Script

(See Korean section for the full Python script — code blocks are identical)

---

## 6. Legal Admissibility Requirements

### Key Articles of Korean Criminal Procedure Act

**Key provisions on digital evidence**

```
Criminal Procedure Act Article 106 (Seizure)
- The court may seize evidence or items believed subject to confiscation
  limited to items recognizable as related to the case

Criminal Procedure Act Article 215 (Seizure, Search, Inspection)
- A prosecutor or judicial police officer may, when necessary for investigation,
  with reasonable grounds to suspect the suspect committed the offense,
  seize, search, or inspect items limited to those recognizable as related
  to the case, by warrant issued by a district court judge

Admissibility of digital evidence:
- Identity: Is the copy identical to the original? (proven by hash values)
- Integrity: Was there no alteration after collection? (Chain of Custody)
- Authenticity: Was it actually collected from the device?
- Reliability: Are the collection tools and procedures reliable?
```

### Digital Evidence Collection Principles

```
1. Original Preservation Principle
   - Never modify original device/data
   - Use write blockers
   - Analyze using read-only mount or image copy

2. Integrity Principle
   - Record and compare hash values before and after collection
   - Stop collection and re-collect if hash mismatch
   - Maintain records of all steps

3. Documentation Principle
   - Record collection date/time, location, examiner
   - Record tools and versions used
   - Maintain logs of all operational steps

4. Chain of Custody
   - Sign and record each time evidence is transferred
   - Record storage conditions (temperature, humidity, access records)
   - Maintain packaging and seal integrity
```

### Precautions When Seizing Mobile Devices

```bash
Upon arrival at scene:
1. Photograph device screen condition (if on)
2. Check device power state (on/off)
3. Network isolation (airplane mode or Faraday bag)
4. Maintain charge state (prevent discharge)

Handling powered-on devices:
- Before First Unlock (BFU): Do not turn off → preserve as-is
- After First Unlock (AFU): More data accessible
- Check USB Restricted Mode (iOS)

Handling powered-off devices:
- Principle: Do not turn on (maintain BFU state without PIN entry)
- Consider JTAG/Chip-off methods

Faraday bag (electromagnetic shielding):
- Completely blocks RF signals (prevents remote wipe)
- Maintains no-network environment
- Prevents electromagnetic interference
```

### Consent Forms and Warrants

```
Voluntary submission:
- Suspect/witness voluntarily submits
- Collection possible without warrant
- Must complete consent form
- Clearly specify scope of consent (full device vs. specific data)

Search and seizure warrant:
- Specify offense charged
- Specify items to seize (device type, data type)
- Collection only within warrant scope
- Cannot collect unrelated data

Communications verification data:
- Criminal Procedure Act Article 215-2 et seq.
- Call records, location information, etc.
- Requires court authorization
- Retention period: call records 12 months, texts 3 months (Telecommunications Business Act)
```

### Elements of a Digital Evidence Expert Report

```
1. Background of examination
   - Requesting agency, request date
   - How examined items were received
   - Purpose of examination

2. Condition of examined items
   - Photographs of device exterior
   - Identification info (model, serial, IMEI)
   - Condition upon receipt

3. Examination method
   - Tools and versions used
   - Collection procedure
   - Analysis method

4. Examination results
   - Original hash values
   - Image hash values
   - Discovered artifacts
   - Timeline

5. Expert opinion
   - Summary of findings
   - Technical facts supporting legal determination

6. Attachments
   - Hash comparison table
   - Screenshots
   - DB analysis results
```

---

## Quick Reference Commands

```bash
# Read-only mount without write blocker
mount -o ro,noexec,nosuid /dev/sdb1 /mnt/evidence

# Check partition info from image
mmls device.img
fdisk -l device.img

# Using The Sleuth Kit (TSK)
fls -r device.img 1                    # File list of partition 1
icat device.img 1 <inode>              # Extract specific inode content
ils device.img 1                       # List deleted inodes

# Run Autopsy GUI
autopsy &

# Volatility (memory forensics, combined use)
# Android RAM dump analysis
vol.py -f memory.lime --profile=LinuxAndroid imageinfo
vol.py -f memory.lime --profile=LinuxAndroid linux_pslist
```
