> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Android 포렌식

## 0. 초보자를 위한 개념 이해

### Android 포렌식이란?

Android 포렌식은 안드로이드 스마트폰이나 태블릿에서 디지털 증거를 추출하고 분석하는 과학적 조사 기법이다. 삭제된 메시지, 통화 기록, 위치 정보, 앱 사용 기록 등 범죄 수사나 사고 조사에 결정적인 증거를 확보할 수 있다.

**왜 배우는가:**
```
Android 기기에서 확보 가능한 증거:

  통화/메시지
    ├── SMS/MMS 기록 (삭제된 것 포함)
    ├── 카카오톡, WhatsApp 대화 내역
    └── 통화 기록 (발신/수신/부재중)

  위치 정보
    ├── GPS 기록 (이동 경로)
    ├── 와이파이 연결 기록 (방문 장소)
    └── 구글 타임라인 데이터

  앱 데이터
    ├── 브라우저 히스토리
    ├── SNS 활동 기록
    └── 금융 앱 거래 내역

  시스템 정보
    ├── 마지막 부팅 시간
    ├── 설치/삭제된 앱 목록
    └── 파일 접근 타임스탬프
```

### 핵심 개념 정리

```
Android 포렌식 추출 방식 (쉬움 → 어려움):

1. 논리적 추출 (Logical)
   - ADB(Android Debug Bridge)로 파일 복사
   - 루팅 불필요, 빠름
   - 한계: 삭제된 데이터, 암호화 데이터 접근 불가

2. 파일시스템 추출 (File System)
   - 루팅 후 전체 파티션 이미징
   - /data, /sdcard 전체 접근 가능
   - 한계: 루팅 필요 (증거 무결성 논란)

3. 물리적 추출 (Physical)
   - JTAG, Chip-off로 낸드 플래시 직접 읽기
   - 화면 잠금 우회 가능, 삭제 데이터 복구 가능
   - 한계: 고급 장비 필요, 기기 손상 위험

ADB 주요 명령어:
  adb devices              # 연결된 기기 목록
  adb shell ls /data/data  # 앱 데이터 디렉토리
  adb pull /sdcard/ ./     # SD카드 전체 복사
  adb backup -all          # 전체 백업
```

### 필요한 도구 및 환경
- **ADB (Android Debug Bridge)**: Android SDK Platform Tools 포함
- **Autopsy**: 오픈소스 디지털 포렌식 플랫폼
- **JADX**: APK 역분석 도구 (Java 소스 복원)
- **SQLite Browser**: 안드로이드 DB 파일 (.db) 분석
- **Cellebrite UFED**: 상용 모바일 포렌식 솔루션

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
Android ADB 포렌식 자동화 — 기기에서 기본 증거 수집
실행 전: adb devices로 기기 연결 확인 필요
"""
import json
import subprocess
from datetime import datetime
from pathlib import Path


def run_adb(cmd: str) -> str:
    """ADB 명령어를 실행하고 결과를 반환한다."""
    try:
        result = subprocess.run(
            f"adb {cmd}", shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[타임아웃]"
    except Exception as e:
        return f"[오류] {e}"


def collect_basic_evidence(output_dir: str = "./evidence") -> dict:
    """
    Android 기기에서 기본 증거를 수집한다.
    실제 환경에서는 USB 디버깅 활성화된 기기 필요.
    """
    Path(output_dir).mkdir(exist_ok=True)
    evidence = {
        "수집시각": datetime.now().isoformat(),
        "기기정보": {},
        "수집항목": [],
    }

    # 기기 정보 수집
    evidence["기기정보"]["모델"] = run_adb("shell getprop ro.product.model")
    evidence["기기정보"]["안드로이드버전"] = run_adb("shell getprop ro.build.version.release")
    evidence["기기정보"]["시리얼"] = run_adb("get-serialno")
    evidence["기기정보"]["IMEI"] = run_adb("shell service call iphonesubinfo 1")

    # 수집 체크리스트
    collection_tasks = [
        ("설치된앱목록", "shell pm list packages -f"),
        ("실행중인프로세스", "shell ps -A"),
        ("네트워크연결", "shell netstat -an"),
        ("마지막부팅시간", "shell uptime"),
        ("파일시스템마운트", "shell mount"),
    ]

    for name, cmd in collection_tasks:
        result = run_adb(cmd)
        evidence["수집항목"].append({"항목": name, "결과줄수": len(result.splitlines())})
        # 실제 데이터는 파일로 저장
        with open(f"{output_dir}/{name}.txt", "w", encoding="utf-8") as f:
            f.write(result)

    return evidence


if __name__ == "__main__":
    print("[Android 포렌식 기초 증거 수집 시작]")
    print("주의: USB 디버깅이 활성화된 기기가 연결되어 있어야 합니다.")
    result = collect_basic_evidence()
    print(json.dumps(result, ensure_ascii=False, indent=2))
```

---

## 목차
1. Android 파일시스템 구조
2. ADB 포렌식 명령어 모음
3. Android 아티팩트 위치
4. SQLite DB 추출 및 분석
5. Python Android 백업 파싱 스크립트
6. Magisk/루팅 흔적 탐지

---

## 1. Android 파일시스템 구조

### 주요 파티션 구조

```
/boot          - 커널 및 ramdisk
/system        - Android OS 파일 (읽기 전용)
/vendor        - 제조사 전용 파일
/data          - 사용자 데이터 (포렌식 핵심)
/cache         - 임시 파일
/sdcard        - 외부 저장소 (내부 SD 마운트 포인트)
/mnt/sdcard    - /sdcard 심볼릭 링크
/proc          - 커널/프로세스 가상 파일시스템
/sys           - 하드웨어 정보 가상 파일시스템
```

### /data 파티션 상세 구조

```
/data/
├── data/                    # 앱 내부 데이터 (루트 필요)
│   ├── com.android.contacts/
│   │   └── databases/
│   │       └── contacts2.db
│   ├── com.android.providers.telephony/
│   │   └── databases/
│   │       ├── mmssms.db    # SMS/MMS 데이터
│   │       └── telephony.db
│   ├── com.android.providers.calendar/
│   │   └── databases/
│   │       └── calendar.db
│   ├── com.android.browser/
│   │   └── databases/
│   │       └── browser.db   # 브라우저 히스토리
│   └── com.google.android.gms/
│       └── databases/
│           └── icing_accounts.db
├── media/                   # 미디어 파일
├── misc/                    # 기타 설정 파일
│   ├── wifi/
│   │   └── WifiConfigStore.xml   # Wi-Fi 비밀번호
│   └── keystore/
├── system/                  # 시스템 설정
│   ├── accounts.db          # 계정 정보
│   ├── packages.xml         # 설치된 앱 목록
│   └── users/
│       └── 0/
│           └── settings_secure.xml
├── app/                     # 설치된 APK (시스템 외)
└── user/
    └── 0/                   # 사용자 0번 (기본 사용자)
```

### 파일시스템 유형

**ext4 (Extendable File System 4)**
- Android 4.x ~ 9.x 주력 파일시스템
- 저널링 지원 → 복구 가능성 높음
- 삭제 파일 일부 복구 가능

**F2FS (Flash-Friendly File System)**
- Android 10+ 점차 전환
- NAND 플래시 최적화
- 삭제 시 즉시 블록 초기화 → 복구 어려움

**확인 명령어**
```bash
adb shell mount | grep "/data"
adb shell cat /proc/mounts
adb shell df -h
```

---

## 2. ADB 포렌식 명령어 모음

### ADB 기본 설정

```bash
# ADB 서버 시작
adb start-server

# 연결된 디바이스 확인
adb devices -l

# 특정 디바이스 지정 (여러 기기 연결 시)
adb -s <serial_number> shell

# USB 디버깅 없이 Wi-Fi 연결 (Android 11+)
adb pair <ip>:<port>
adb connect <ip>:<port>

# ADB over TCP 활성화 (루팅된 기기)
adb shell setprop service.adb.tcp.port 5555
adb shell stop adbd
adb shell start adbd
```

### 기기 정보 수집

```bash
# 기기 식별 정보
adb shell getprop ro.product.model
adb shell getprop ro.product.manufacturer
adb shell getprop ro.build.version.release
adb shell getprop ro.build.fingerprint
adb shell getprop ro.serialno

# IMEI 확인 (루팅 필요 or 권한 필요)
adb shell service call iphonesubinfo 1

# 안드로이드 ID (고유 식별자)
adb shell settings get secure android_id

# 시스템 시간
adb shell date
adb shell getprop persist.sys.timezone

# 배터리 정보 (마지막 사용 흔적)
adb shell dumpsys battery

# 네트워크 정보
adb shell ip addr show
adb shell ip route
adb shell netstat -tnp
```

### 파일 수집 명령어

```bash
# 파일/디렉토리 복사 (로컬로)
adb pull /sdcard/DCIM ./evidence/photos/
adb pull /sdcard/Download ./evidence/downloads/
adb pull /sdcard/WhatsApp ./evidence/whatsapp/

# 루팅된 기기: 내부 데이터 추출
adb shell "su -c 'cp -r /data/data/com.android.providers.telephony/databases /sdcard/forensics/'"
adb pull /sdcard/forensics/ ./evidence/

# 여러 파일 동시 추출
adb shell "su -c 'tar czf /sdcard/forensics_data.tar.gz /data/data/'"
adb pull /sdcard/forensics_data.tar.gz ./evidence/

# 파일 목록 + 메타데이터
adb shell "find /sdcard -type f -exec ls -la {} \;" > file_listing.txt

# 최근 수정 파일 찾기
adb shell "find /sdcard -newer /sdcard/DCIM -type f 2>/dev/null"

# 숨김 파일 포함 목록
adb shell ls -la /sdcard/
```

### Logcat (로그 수집)

```bash
# 전체 로그 수집
adb logcat -d > device_log.txt

# 로그 레벨 필터 (V=Verbose, D=Debug, I=Info, W=Warn, E=Error)
adb logcat *:E > error_log.txt

# 태그 필터링
adb logcat -s ActivityManager:I PackageManager:D

# 바이너리 로그 덤프
adb logcat -b events -d > events_log.txt
adb logcat -b radio -d > radio_log.txt   # 통화/SMS 관련
adb logcat -b crash -d > crash_log.txt

# 로그 포맷 지정
adb logcat -v threadtime -d > detailed_log.txt

# 실시간 모니터링
adb logcat | grep -i "password\|token\|secret\|key"
```

### Bugreport 수집

```bash
# 전체 버그리포트 (시스템 상태 스냅샷)
adb bugreport ./evidence/bugreport_$(date +%Y%m%d_%H%M%S).zip

# 버그리포트 내용 (ZIP 압축 해제 후)
# - bugreport-<device>-<date>.txt : 메인 보고서
# - FS/data/system/packages.xml  : 설치 앱 목록
# - FS/data/system/usagestats/   : 앱 사용 통계

# 덤프시스 정보 수집
adb shell dumpsys > dumpsys_all.txt
adb shell dumpsys activity > activity_info.txt
adb shell dumpsys window > window_info.txt
adb shell dumpsys telephony.registry > telephony_info.txt
adb shell dumpsys usagestats > usage_stats.txt        # 앱 사용 시간
adb shell dumpsys notification > notifications.txt
adb shell dumpsys location > location_info.txt        # 위치 서비스
adb shell dumpsys alarm > scheduled_alarms.txt
```

### 프로세스/앱 분석

```bash
# 실행 중인 프로세스
adb shell ps -ef
adb shell top -n 1

# 설치된 앱 목록
adb shell pm list packages -f    # APK 경로 포함
adb shell pm list packages -3    # 서드파티 앱만
adb shell pm list packages -d    # 비활성화된 앱

# 앱 상세 정보
adb shell dumpsys package <package_name>

# 앱 백업 (ADB 백업, 암호화 선택)
adb backup -apk -shared -all -f backup_$(date +%Y%m%d).ab

# 스크린샷
adb shell screencap -p /sdcard/screenshot.png
adb pull /sdcard/screenshot.png ./evidence/

# 화면 녹화 (최대 3분)
adb shell screenrecord /sdcard/screen_record.mp4
```

---

## 3. Android 아티팩트 위치

### SMS/MMS

```
/data/data/com.android.providers.telephony/databases/mmssms.db

테이블:
- sms          : 문자 메시지
- mms          : 멀티미디어 메시지
- pdu          : MMS 데이터
- threads      : 대화 스레드
- canonical_addresses : 주소록
```

```sql
-- SMS 전체 조회
SELECT _id, thread_id, address, date, date_sent, type, body, read
FROM sms
ORDER BY date DESC;

-- type 값: 1=받은 메시지, 2=보낸 메시지, 3=임시저장, 5=실패

-- 삭제된 SMS (휴지통 포함)
SELECT * FROM sms WHERE thread_id IN (
    SELECT _id FROM threads WHERE recipient_ids = ''
);
```

### 연락처

```
/data/data/com.android.providers.contacts/databases/contacts2.db

테이블:
- contacts          : 연락처 기본 정보
- raw_contacts      : 소스별 연락처
- data              : 전화번호, 이메일 등 세부 정보
- call_log          : 통화 기록 (별도 DB일 수 있음)
```

```sql
-- 연락처 + 전화번호 조합 조회
SELECT c.display_name, d.data1 AS phone_number, d.data2 AS type
FROM contacts c
JOIN raw_contacts rc ON c._id = rc.contact_id
JOIN data d ON rc._id = d.raw_contact_id
WHERE d.mimetype_id = (
    SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/phone_v2'
);
```

### 통화 기록

```
/data/data/com.android.providers.contacts/databases/calllog.db
또는
/data/data/com.android.providers.contacts/databases/contacts2.db (calls 테이블)

컬럼:
- number       : 전화번호
- date         : Unix timestamp (밀리초)
- duration     : 통화 시간 (초)
- type         : 1=수신, 2=발신, 3=부재중, 4=보이스메일
```

### 브라우저 히스토리 (AOSP Browser)

```
/data/data/com.android.browser/databases/browser.db
/data/data/com.android.browser/databases/webview.db

테이블: bookmarks, history
```

### Chrome 브라우저

```
/data/data/com.android.chrome/app_chrome/Default/
├── History                    # SQLite: 방문 기록
├── Cookies                    # SQLite: 쿠키
├── Login Data                 # SQLite: 저장된 비밀번호
├── Web Data                   # SQLite: 자동완성
├── Bookmarks                  # JSON: 북마크
└── Preferences                # JSON: 설정
```

```sql
-- Chrome 방문 기록
SELECT url, title, visit_count, last_visit_time
FROM urls
ORDER BY last_visit_time DESC
LIMIT 100;

-- Chrome 저장 비밀번호
SELECT origin_url, username_value, password_value
FROM logins;
```

### 카카오톡

```
/data/data/com.kakao.talk/databases/
├── KakaoTalk.db               # 주 메시지 DB
├── talk_member.db             # 연락처
└── media.db                   # 미디어 메타데이터

/sdcard/KakaoTalk/
├── Emoticons/
├── media/
└── .backup/                   # 백업 파일 (암호화)
```

### Wi-Fi 연결 기록

```
/data/misc/wifi/WifiConfigStore.xml      # Android 10+
/data/misc/wifi/wpa_supplicant.conf      # Android 9 이하

포함 정보:
- SSID (네트워크 이름)
- BSSID (AP MAC 주소)
- Pre-shared key (비밀번호, 일부 암호화)
- 마지막 연결 시간
```

### 앱 사용 통계

```
/data/system/usagestats/0/               # 사용 이벤트 로그
/data/system_ce/0/usagestats/            # Android 9+

adb shell dumpsys usagestats --csv       # CSV 형태로 출력
```

### 위치 데이터

```
/data/data/com.google.android.gms/databases/
├── persisted_cache.db         # 캐시된 위치
└── icing_accounts.db

/data/data/com.google.android.location/databases/
└── locations.db               # 위치 기록

Google Maps:
/data/data/com.google.android.apps.maps/databases/
└── gmm_myplaces.db
```

---

## 4. SQLite DB 추출 및 분석

### SQLite 명령줄 분석

```bash
# SQLite3 기본 사용
sqlite3 contacts2.db

# 내부 명령어
.tables                    # 테이블 목록
.schema <table>            # 테이블 스키마
.headers on                # 컬럼 헤더 표시
.mode column               # 컬럼 정렬 모드
.mode csv                  # CSV 출력 모드
.output result.csv         # 파일로 출력
.dump                      # SQL dump 전체 출력
.quit                      # 종료

# 삭제된 레코드 복구 (freelist 페이지 분석)
# SQLite는 삭제 시 즉시 제거하지 않고 free page로 표시
sqlite3 mmssms.db "SELECT * FROM sqlite_master"
```

### 삭제 레코드 복구

```bash
# 방법 1: strings로 텍스트 추출
strings mmssms.db | grep -E "^\+?[0-9]{10,13}"

# 방법 2: hexdump로 raw 데이터 분석
hexdump -C mmssms.db | grep -A2 -B2 "text"

# 방법 3: SQLite 복구 도구 사용
pip install sqlite-utils
sqlite-utils rows mmssms.db sms

# 방법 4: undark (SQLite 복구 전문 도구)
# https://github.com/witwall/undark
./undark -i mmssms.db > recovered_sms.txt
```

### 타임스탬프 변환

```python
import datetime

# Android SMS 타임스탬프 (Unix ms)
ts_ms = 1700000000000
dt = datetime.datetime.fromtimestamp(ts_ms / 1000)
print(dt.strftime("%Y-%m-%d %H:%M:%S"))

# Chrome 타임스탬프 (WebKit 시간: 마이크로초, 1601-01-01 기준)
webkit_ts = 13305000000000000
epoch_diff = 11644473600  # 초 단위 차이
unix_ts = (webkit_ts / 1_000_000) - epoch_diff
dt = datetime.datetime.fromtimestamp(unix_ts)
print(dt.strftime("%Y-%m-%d %H:%M:%S"))
```

---

## 5. Python Android 백업 파싱 스크립트

ADB 백업 파일(.ab)은 zlib 압축된 tar 아카이브 형태입니다.

```python
#!/usr/bin/env python3
"""
Android ADB 백업(.ab) 파일 파싱 및 포렌식 분석 스크립트

사용법:
    python3 android_backup_parser.py -f backup.ab -o ./output
    python3 android_backup_parser.py -f backup.ab -o ./output --analyze-sms
    python3 android_backup_parser.py -f backup.ab -o ./output --all
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import sys
import tarfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class BackupHeader:
    version: int
    compressed: bool
    encrypted: bool
    encryption_algo: str
    password_salt: bytes = field(default_factory=bytes)
    user_iv: bytes = field(default_factory=bytes)
    master_key_blob: bytes = field(default_factory=bytes)


@dataclass
class SmsRecord:
    id: int
    address: str
    date: datetime
    body: str
    msg_type: int  # 1=수신, 2=발신
    read: bool


@dataclass
class ContactRecord:
    display_name: str
    phone_numbers: list[str]
    emails: list[str]


def compute_file_hash(filepath: Path) -> dict[str, str]:
    """파일의 MD5, SHA256 해시 계산"""
    hashes: dict[str, str] = {}
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)

    hashes["md5"] = md5.hexdigest()
    hashes["sha256"] = sha256.hexdigest()
    return hashes


def parse_backup_header(data: bytes) -> tuple[BackupHeader, int]:
    """
    ADB 백업 헤더 파싱
    형식:
        ANDROID BACKUP\n
        <version>\n
        <compressed: 0|1>\n
        <encryption: none|AES-256>\n
    """
    lines = []
    offset = 0

    for _ in range(5):
        end = data.index(b"\n", offset)
        lines.append(data[offset:end].decode("utf-8", errors="replace"))
        offset = end + 1

    if lines[0] != "ANDROID BACKUP":
        raise ValueError(f"유효하지 않은 ADB 백업 파일: 헤더 불일치")

    version = int(lines[1])
    compressed = lines[2] == "1"
    encryption_algo = lines[3]
    encrypted = encryption_algo != "none"

    header = BackupHeader(
        version=version,
        compressed=compressed,
        encrypted=encrypted,
        encryption_algo=encryption_algo,
    )
    return header, offset


def decompress_backup(backup_path: Path) -> bytes:
    """ADB 백업 파일을 읽어 tar 데이터로 변환"""
    with open(backup_path, "rb") as f:
        raw = f.read()

    header, data_offset = parse_backup_header(raw)

    if header.encrypted:
        raise NotImplementedError(
            "암호화된 백업은 비밀번호가 필요합니다. "
            "openssl을 사용하여 먼저 복호화하세요:\n"
            "  openssl enc -d -aes-256-cbc -md md5 -in backup.ab -out decrypted.ab"
        )

    payload = raw[data_offset:]

    if header.compressed:
        try:
            decompressed = zlib.decompress(payload)
        except zlib.error as e:
            raise RuntimeError(f"압축 해제 실패: {e}") from e
    else:
        decompressed = payload

    return decompressed


def extract_tar_to_directory(tar_data: bytes, output_dir: Path) -> list[str]:
    """tar 데이터를 디렉토리로 추출"""
    import io

    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_files: list[str] = []

    with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as tar:
        for member in tar.getmembers():
            try:
                tar.extract(member, path=output_dir, set_attrs=False)
                extracted_files.append(member.name)
            except (tarfile.ExtractError, PermissionError) as e:
                print(f"  [경고] 추출 실패: {member.name} - {e}", file=sys.stderr)

    return extracted_files


def find_sqlite_databases(base_dir: Path) -> list[Path]:
    """추출된 디렉토리에서 SQLite DB 파일 탐색"""
    db_files: list[Path] = []
    sqlite_magic = b"SQLite format 3\x00"

    for path in base_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as f:
                header = f.read(16)
            if header == sqlite_magic:
                db_files.append(path)
        except (OSError, PermissionError):
            continue

    return db_files


def analyze_sms_database(db_path: Path) -> list[SmsRecord]:
    """SMS 데이터베이스 분석"""
    records: list[SmsRecord] = []

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # 테이블 존재 확인
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sms'")
        if not cur.fetchone():
            conn.close()
            return records

        cur.execute("""
            SELECT _id, address, date, body, type, read
            FROM sms
            ORDER BY date DESC
        """)

        for row in cur.fetchall():
            try:
                ts = datetime.fromtimestamp(row["date"] / 1000)
            except (OSError, ValueError, OverflowError):
                ts = datetime.fromtimestamp(0)

            records.append(SmsRecord(
                id=row["_id"],
                address=row["address"] or "",
                date=ts,
                body=row["body"] or "",
                msg_type=row["type"],
                read=bool(row["read"]),
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [오류] SMS DB 분석 실패 ({db_path.name}): {e}", file=sys.stderr)

    return records


def analyze_contacts_database(db_path: Path) -> list[ContactRecord]:
    """연락처 데이터베이스 분석"""
    records: list[ContactRecord] = []

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='contacts'")
        if not cur.fetchone():
            conn.close()
            return records

        # 연락처별 전화번호/이메일 수집
        cur.execute("SELECT _id, display_name FROM contacts")
        contacts = cur.fetchall()

        for contact in contacts:
            phones: list[str] = []
            emails: list[str] = []

            try:
                cur.execute("""
                    SELECT d.data1, m.mimetype
                    FROM data d
                    JOIN raw_contacts rc ON d.raw_contact_id = rc._id
                    JOIN mimetypes m ON d.mimetype_id = m._id
                    WHERE rc.contact_id = ?
                      AND m.mimetype IN (
                          'vnd.android.cursor.item/phone_v2',
                          'vnd.android.cursor.item/email_v2'
                      )
                """, (contact["_id"],))

                for row in cur.fetchall():
                    if "phone" in row["mimetype"]:
                        phones.append(row["data1"] or "")
                    else:
                        emails.append(row["data1"] or "")
            except sqlite3.DatabaseError:
                pass

            records.append(ContactRecord(
                display_name=contact["display_name"] or "(이름 없음)",
                phone_numbers=phones,
                emails=emails,
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [오류] 연락처 DB 분석 실패 ({db_path.name}): {e}", file=sys.stderr)

    return records


def generate_report(
    backup_path: Path,
    output_dir: Path,
    file_hashes: dict[str, str],
    extracted_files: list[str],
    db_files: list[Path],
    sms_records: list[SmsRecord],
    contacts: list[ContactRecord],
) -> Path:
    """포렌식 보고서 생성"""
    report: dict = {
        "분석_시간": datetime.now().isoformat(),
        "원본_파일": str(backup_path),
        "파일_해시": file_hashes,
        "추출_파일_수": len(extracted_files),
        "발견된_DB_수": len(db_files),
        "발견된_DB_목록": [str(p.relative_to(output_dir)) for p in db_files],
        "SMS_분석": {
            "총_건수": len(sms_records),
            "수신": sum(1 for s in sms_records if s.msg_type == 1),
            "발신": sum(1 for s in sms_records if s.msg_type == 2),
            "미읽음": sum(1 for s in sms_records if not s.read),
            "최근_메시지": [
                {
                    "발신자": s.address,
                    "시간": s.date.isoformat(),
                    "내용_미리보기": s.body[:100],
                    "유형": "수신" if s.msg_type == 1 else "발신",
                }
                for s in sms_records[:20]
            ],
        },
        "연락처_분석": {
            "총_건수": len(contacts),
            "연락처_목록": [
                {
                    "이름": c.display_name,
                    "전화번호": c.phone_numbers,
                    "이메일": c.emails,
                }
                for c in contacts[:50]
            ],
        },
    }

    report_path = output_dir / "forensics_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 사람이 읽기 쉬운 텍스트 보고서도 생성
    txt_report_path = output_dir / "forensics_report.txt"
    with open(txt_report_path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("Android 포렌식 분석 보고서\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"분석 시간: {report['분석_시간']}\n")
        f.write(f"원본 파일: {backup_path}\n")
        f.write(f"MD5:    {file_hashes.get('md5', 'N/A')}\n")
        f.write(f"SHA256: {file_hashes.get('sha256', 'N/A')}\n\n")
        f.write(f"추출 파일 수: {len(extracted_files)}\n")
        f.write(f"발견된 SQLite DB 수: {len(db_files)}\n\n")

        f.write("-" * 40 + "\n")
        f.write(f"SMS 분석 (총 {len(sms_records)}건)\n")
        f.write("-" * 40 + "\n")
        for sms in sms_records[:20]:
            direction = "수신" if sms.msg_type == 1 else "발신"
            f.write(f"[{sms.date.strftime('%Y-%m-%d %H:%M:%S')}] {direction} | {sms.address}\n")
            f.write(f"  {sms.body[:80]}\n\n")

        f.write("-" * 40 + "\n")
        f.write(f"연락처 ({len(contacts)}명)\n")
        f.write("-" * 40 + "\n")
        for contact in contacts[:30]:
            f.write(f"{contact.display_name}\n")
            for phone in contact.phone_numbers:
                f.write(f"  전화: {phone}\n")
            for email in contact.emails:
                f.write(f"  이메일: {email}\n")
            f.write("\n")

    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Android ADB 백업 파일 포렌식 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s -f backup.ab -o ./output
  %(prog)s -f backup.ab -o ./output --analyze-sms --analyze-contacts
  %(prog)s -f backup.ab -o ./output --all
        """,
    )
    parser.add_argument("-f", "--file", required=True, help="ADB 백업 파일 경로 (.ab)")
    parser.add_argument("-o", "--output", required=True, help="출력 디렉토리 경로")
    parser.add_argument("--analyze-sms", action="store_true", help="SMS 분석 수행")
    parser.add_argument("--analyze-contacts", action="store_true", help="연락처 분석 수행")
    parser.add_argument("--all", action="store_true", help="모든 분석 수행")
    parser.add_argument("--no-extract", action="store_true", help="파일 추출 건너뜀 (이미 추출된 경우)")

    args = parser.parse_args()

    if args.all:
        args.analyze_sms = True
        args.analyze_contacts = True

    backup_path = Path(args.file)
    output_dir = Path(args.output)

    if not backup_path.exists():
        print(f"[오류] 백업 파일을 찾을 수 없습니다: {backup_path}", file=sys.stderr)
        return 1

    print(f"[*] 파일 해시 계산 중: {backup_path}")
    file_hashes = compute_file_hash(backup_path)
    print(f"    MD5:    {file_hashes['md5']}")
    print(f"    SHA256: {file_hashes['sha256']}")

    extracted_files: list[str] = []
    extract_dir = output_dir / "extracted"

    if not args.no_extract:
        print(f"\n[*] 백업 파일 압축 해제 중...")
        try:
            tar_data = decompress_backup(backup_path)
            print(f"[*] 파일 추출 중: {extract_dir}")
            extracted_files = extract_tar_to_directory(tar_data, extract_dir)
            print(f"    추출 완료: {len(extracted_files)}개 파일")
        except (ValueError, RuntimeError, NotImplementedError) as e:
            print(f"[오류] {e}", file=sys.stderr)
            return 1
    else:
        if extract_dir.exists():
            extracted_files = [str(p) for p in extract_dir.rglob("*") if p.is_file()]

    print(f"\n[*] SQLite DB 탐색 중...")
    db_files = find_sqlite_databases(extract_dir)
    print(f"    발견된 DB: {len(db_files)}개")
    for db in db_files:
        print(f"    - {db.relative_to(output_dir)}")

    sms_records: list[SmsRecord] = []
    contacts: list[ContactRecord] = []

    if args.analyze_sms:
        print(f"\n[*] SMS 분석 중...")
        for db in db_files:
            if "mmssms" in db.name or "telephony" in str(db):
                records = analyze_sms_database(db)
                sms_records.extend(records)
                print(f"    {db.name}: {len(records)}건")

    if args.analyze_contacts:
        print(f"\n[*] 연락처 분석 중...")
        for db in db_files:
            if "contacts2" in db.name or "contacts" in db.name:
                records = analyze_contacts_database(db)
                contacts.extend(records)
                print(f"    {db.name}: {len(records)}명")

    print(f"\n[*] 보고서 생성 중...")
    report_path = generate_report(
        backup_path, output_dir, file_hashes,
        extracted_files, db_files, sms_records, contacts,
    )
    print(f"    JSON 보고서: {report_path}")
    print(f"    TXT 보고서:  {output_dir / 'forensics_report.txt'}")

    print(f"\n[완료] 분석 결과 저장 위치: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. Magisk/루팅 흔적 탐지

### 루팅 흔적 파일/경로

```bash
# 루팅 바이너리 존재 여부
adb shell ls /system/bin/su 2>/dev/null
adb shell ls /system/xbin/su 2>/dev/null
adb shell ls /sbin/su 2>/dev/null
adb shell ls /data/local/bin/su 2>/dev/null
adb shell which su

# Magisk 관련 파일
adb shell ls /data/adb/magisk 2>/dev/null
adb shell ls /sbin/.magisk 2>/dev/null
adb shell ls /data/adb/modules 2>/dev/null

# SuperSU 흔적
adb shell ls /system/app/SuperSU/ 2>/dev/null

# Xposed Framework
adb shell ls /system/framework/XposedBridge.jar 2>/dev/null

# 커스텀 리커버리 (TWRP 등)
adb shell ls /cache/recovery/ 2>/dev/null
```

### 빌드 프로퍼티 분석

```bash
# 루팅 관련 프로퍼티 확인
adb shell getprop ro.build.tags          # "test-keys" → 비공식 빌드
adb shell getprop ro.build.type          # "userdebug" or "eng" → 디버그 빌드
adb shell getprop ro.debuggable          # "1" → 디버깅 가능 (루팅 가능성)
adb shell getprop ro.secure              # "0" → adb root 허용
adb shell getprop service.adb.root       # "1" → root adb 실행 중

# SELinux 상태
adb shell getenforce                     # "Permissive" → 보안 완화 상태
adb shell cat /proc/sys/fs/protected_hardlinks
```

### 루팅 앱 목록

```bash
# 루팅 관련 패키지 탐색
adb shell pm list packages | grep -iE "magisk|supersu|topjohnwu|chainfire|xposed"

# 알려진 루팅 앱 패키지명
# - com.topjohnwu.magisk      (Magisk Manager)
# - eu.chainfire.supersu       (SuperSU)
# - com.noshufou.android.su    (Superuser)
# - com.koushikdutta.superuser (Superuser)
# - de.robv.android.xposed.installer (Xposed)
```

### Python 루팅 탐지 스크립트

```python
#!/usr/bin/env python3
"""
Android 루팅/Magisk 흔적 자동 탐지 스크립트
adb 연결된 기기 대상으로 실행

사용법:
    python3 detect_root.py
    python3 detect_root.py --output root_report.json
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime


ROOT_INDICATORS: dict[str, list[str]] = {
    "루팅 바이너리": [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/bin/su",
        "/data/local/su",
    ],
    "Magisk 파일": [
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/data/adb/modules",
        "/data/adb/magisk.img",
        "/cache/.disable_magisk",
    ],
    "SuperSU/SuperUser": [
        "/system/app/SuperSU",
        "/system/app/Superuser",
        "/data/data/eu.chainfire.supersu",
    ],
    "Xposed Framework": [
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/data/data/de.robv.android.xposed.installer",
    ],
    "커스텀 리커버리": [
        "/cache/recovery",
        "/cache/recovery/command",
    ],
}

ROOT_PACKAGES: list[str] = [
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.koushikdutta.superuser",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
]

SUSPICIOUS_PROPS: dict[str, list[str]] = {
    "ro.build.tags": ["test-keys"],
    "ro.build.type": ["userdebug", "eng"],
    "ro.debuggable": ["1"],
    "ro.secure": ["0"],
    "service.adb.root": ["1"],
}


def run_adb(args: list[str], timeout: int = 10) -> tuple[bool, str]:
    """ADB 명령 실행"""
    try:
        result = subprocess.run(
            ["adb", "shell"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return True, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "타임아웃"
    except FileNotFoundError:
        return False, "adb를 찾을 수 없음"


def check_device_connected() -> bool:
    """ADB 디바이스 연결 확인"""
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        return any("device" in line and "List" not in line for line in lines)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_file_exists(path: str) -> bool:
    """기기에서 파일 존재 여부 확인"""
    ok, output = run_adb(["test", "-e", path, "&&", "echo", "EXISTS"])
    return ok and "EXISTS" in output


def get_property(prop: str) -> str:
    """Android 프로퍼티 값 조회"""
    ok, value = run_adb(["getprop", prop])
    return value if ok else ""


def get_installed_packages() -> list[str]:
    """설치된 패키지 목록 조회"""
    ok, output = run_adb(["pm", "list", "packages"])
    if not ok:
        return []
    return [line.replace("package:", "").strip() for line in output.split("\n") if line]


def get_selinux_status() -> str:
    """SELinux 상태 확인"""
    ok, status = run_adb(["getenforce"])
    return status if ok else "알 수 없음"


def scan_root_indicators() -> dict:
    """루팅 지표 전체 스캔"""
    results: dict = {
        "스캔_시간": datetime.now().isoformat(),
        "발견된_지표": [],
        "의심_프로퍼티": [],
        "루팅_앱": [],
        "selinux_상태": "",
        "루팅_가능성": "낮음",
    }

    print("[*] 루팅 바이너리 및 파일 검사 중...")
    for category, paths in ROOT_INDICATORS.items():
        for path in paths:
            if check_file_exists(path):
                results["발견된_지표"].append({"카테고리": category, "경로": path})
                print(f"    [발견] {path} ({category})")

    print("[*] 시스템 프로퍼티 검사 중...")
    for prop, suspicious_values in SUSPICIOUS_PROPS.items():
        value = get_property(prop)
        if value in suspicious_values:
            results["의심_프로퍼티"].append({"프로퍼티": prop, "값": value})
            print(f"    [의심] {prop} = {value}")

    print("[*] 루팅 관련 앱 검사 중...")
    installed = get_installed_packages()
    for pkg in ROOT_PACKAGES:
        if pkg in installed:
            results["루팅_앱"].append(pkg)
            print(f"    [발견] 루팅 앱: {pkg}")

    results["selinux_상태"] = get_selinux_status()
    print(f"[*] SELinux 상태: {results['selinux_상태']}")

    # 루팅 가능성 평가
    indicator_count = (
        len(results["발견된_지표"])
        + len(results["의심_프로퍼티"])
        + len(results["루팅_앱"])
    )
    selinux_permissive = results["selinux_상태"] == "Permissive"

    if indicator_count >= 3 or results["루팅_앱"]:
        results["루팅_가능성"] = "높음"
    elif indicator_count >= 1 or selinux_permissive:
        results["루팅_가능성"] = "중간"

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Android 루팅 흔적 탐지 도구")
    parser.add_argument("--output", "-o", help="결과를 저장할 JSON 파일 경로")
    args = parser.parse_args()

    if not check_device_connected():
        print("[오류] ADB 연결된 기기가 없습니다.", file=sys.stderr)
        print("  USB 디버깅이 활성화되어 있는지 확인하세요.", file=sys.stderr)
        return 1

    print("[*] Android 루팅 흔적 탐지 시작\n")
    results = scan_root_indicators()

    print(f"\n{'='*50}")
    print(f"루팅 가능성: {results['루팅_가능성']}")
    print(f"발견된 지표: {len(results['발견된_지표'])}개")
    print(f"의심 프로퍼티: {len(results['의심_프로퍼티'])}개")
    print(f"루팅 앱: {len(results['루팅_앱'])}개")
    print(f"SELinux: {results['selinux_상태']}")
    print(f"{'='*50}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n[*] 결과 저장: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 루팅 탐지 우회 기법 (방어 측 참고)

```bash
# Magisk Hide (현재는 DenyList로 변경됨)
# 특정 앱에서 루팅 탐지 우회
# Settings > Magisk > Configure DenyList

# 탐지 우회 모듈 예시 (이해 목적)
# - MagiskHide Props Config
# - Universal SafetyNet Fix
# - Shamiko

# SafetyNet/Play Integrity 상태 확인
adb shell cmd package check-permission android.permission.QUERY_ALL_PACKAGES com.topjohnwu.magisk

# 탐지 강화: 런타임 무결성 검사
# - /proc/self/maps 에서 magisk 관련 항목 탐색
adb shell "cat /proc/$(adb shell pidof com.target.app)/maps | grep -i magisk"
```

---

## 참고 도구 및 자료

| 도구 | 용도 | 설치 |
|------|------|------|
| ADB | Android 기기 연결/추출 | Android SDK Platform Tools |
| SQLite3 | DB 분석 | `apt install sqlite3` |
| Autopsy | GUI 포렌식 분석 | https://www.autopsy.com |
| AFLogical | Android 논리 추출 | https://github.com/nowsecure/android-forensics |
| ALEAPP | Android 아티팩트 파싱 | https://github.com/abrignoni/ALEAPP |
| MVT | 스파이웨어 탐지 | `pip install mvt` |
| androguard | APK 정적 분석 | `pip install androguard` |

```bash
# ALEAPP 설치 및 사용
git clone https://github.com/abrignoni/ALEAPP
cd ALEAPP
pip install -r requirements.txt

# GUI 실행
python aleappGUI.py

# CLI 실행
python aleapp.py -t fs -i /path/to/extraction -o /path/to/report
```

---

<!-- detect-validate-47 -->
## 안티포렌식 탐지와 Android 증거 검증

Android 포렌식은 *파일시스템·아티팩트·SQLite DB·루팅 흔적*에서 증거를 복원한다. 분석자는 *루팅 은폐·타임스탬프 조작·아티팩트 삭제* 같은 안티포렌식을 의식하고 **증거가 무결하고 교차 일치하는가**를 검증해야 한다. 검증은 **소유 기기/이미지**에서만.

### 안티포렌식 기법 → 노리는 포렌식 단계 → 분석자 대응 → 관찰 신호

| 기법 | 노리는 단계 | 분석자 대응 | 관찰 신호 |
|---|---|---|---|
| 루팅 은폐 | 무결성 가정 | Magisk/su 흔적 교차 | su·busybox·deny 목록 |
| 타임스탬프 조작 | 타임라인 신뢰 | 다중 아티팩트 교차 | DB ts↔파일 mtime 불일치 |
| 아티팩트 삭제 | 단일 소스 의존 | WAL/journal 잔존 | 삭제 행 -wal 잔존 |
| 백업 변조 | 백업 신뢰 | 해시·서명 검증 | 백업 해시 불일치 |

### 증거 검증 (직접 확인)

```bash
# 1) 소유 이미지의 루팅/은폐 흔적 — su/Magisk/busybox 잔존이 무결성 훼손 신호
adb shell 'ls -la /system/xbin/su /sbin/.magisk 2>/dev/null; pm list packages | grep -iE "magisk|supersu"' 2>/dev/null | head
# 2) SQLite 삭제 행이 WAL/journal에 잔존하는지(안티포렌식 우회) — 본 DB엔 없는데 -wal에 존재
sqlite3 mmssms.db 'PRAGMA journal_mode;' 2>/dev/null; strings mmssms.db-wal 2>/dev/null | grep -iE 'deleted|http' | head
```

> Android 증거 검증은 *증거가 무결·교차일치하는가*다 — "DB를 추출했다"와 "루팅 흔적이 교차되고 타임스탬프가 다중 아티팩트와 일치한다"는 다르다. 소유 기기/이미지에서 직접 확인한다([[07_Digital_Forensics]], [[28_Mobile_Hacking]], [[44_Incident_Response_DFIR]]).

**최신 기법·통제 (2025–2026):**
- Android 강화(FBE 암호화·스코프드 스토리지)로 추출 난이도 상승 — 논리/파일시스템 획득·앱데이터 분석. 검증: 획득이 무결성·재현을 보장하는가([[44_Incident_Response_DFIR]])
- 증거 연속성 — 보존되는지 확인

---

<a name="english"></a>

# Android Forensics

## Table of Contents
1. Android Filesystem Structure
2. ADB Forensics Command Reference
3. Android Artifact Locations
4. SQLite DB Extraction and Analysis
5. Python Android Backup Parsing Script
6. Magisk / Root Detection

---

## 1. Android Filesystem Structure

### Major Partition Layout

```
/boot          - Kernel and ramdisk
/system        - Android OS files (read-only)
/vendor        - Manufacturer-specific files
/data          - User data (core forensic target)
/cache         - Temporary files
/sdcard        - External storage (internal SD mount point)
/mnt/sdcard    - Symbolic link to /sdcard
/proc          - Kernel/process virtual filesystem
/sys           - Hardware info virtual filesystem
```

### Detailed /data Partition Structure

```
/data/
├── data/                    # App internal data (requires root)
│   ├── com.android.contacts/
│   │   └── databases/
│   │       └── contacts2.db
│   ├── com.android.providers.telephony/
│   │   └── databases/
│   │       ├── mmssms.db    # SMS/MMS data
│   │       └── telephony.db
│   ├── com.android.providers.calendar/
│   │   └── databases/
│   │       └── calendar.db
│   ├── com.android.browser/
│   │   └── databases/
│   │       └── browser.db   # Browser history
│   └── com.google.android.gms/
│       └── databases/
│           └── icing_accounts.db
├── media/                   # Media files
├── misc/                    # Miscellaneous configuration files
│   ├── wifi/
│   │   └── WifiConfigStore.xml   # Wi-Fi passwords
│   └── keystore/
├── system/                  # System configuration
│   ├── accounts.db          # Account information
│   ├── packages.xml         # Installed app list
│   └── users/
│       └── 0/
│           └── settings_secure.xml
├── app/                     # Installed APKs (non-system)
└── user/
    └── 0/                   # User 0 (default user)
```

### Filesystem Types

**ext4 (Extendable File System 4)**
- Primary filesystem for Android 4.x through 9.x
- Journaling support → higher recovery potential
- Partial recovery of deleted files is possible

**F2FS (Flash-Friendly File System)**
- Gradually adopted from Android 10+
- Optimized for NAND flash storage
- Blocks are immediately zeroed on deletion → recovery is difficult

**Verification Commands**
```bash
adb shell mount | grep "/data"
adb shell cat /proc/mounts
adb shell df -h
```

---

## 2. ADB Forensics Command Reference

### ADB Basic Setup

```bash
# Start ADB server
adb start-server

# List connected devices
adb devices -l

# Target a specific device (when multiple devices are connected)
adb -s <serial_number> shell

# Wi-Fi connection without USB debugging (Android 11+)
adb pair <ip>:<port>
adb connect <ip>:<port>

# Enable ADB over TCP (rooted device)
adb shell setprop service.adb.tcp.port 5555
adb shell stop adbd
adb shell start adbd
```

### Device Information Collection

```bash
# Device identification
adb shell getprop ro.product.model
adb shell getprop ro.product.manufacturer
adb shell getprop ro.build.version.release
adb shell getprop ro.build.fingerprint
adb shell getprop ro.serialno

# IMEI retrieval (requires root or specific permissions)
adb shell service call iphonesubinfo 1

# Android ID (unique device identifier)
adb shell settings get secure android_id

# System time
adb shell date
adb shell getprop persist.sys.timezone

# Battery information (indicates last usage)
adb shell dumpsys battery

# Network information
adb shell ip addr show
adb shell ip route
adb shell netstat -tnp
```

### File Collection Commands

```bash
# Copy files/directories to local machine
adb pull /sdcard/DCIM ./evidence/photos/
adb pull /sdcard/Download ./evidence/downloads/
adb pull /sdcard/WhatsApp ./evidence/whatsapp/

# Rooted device: extract internal data
adb shell "su -c 'cp -r /data/data/com.android.providers.telephony/databases /sdcard/forensics/'"
adb pull /sdcard/forensics/ ./evidence/

# Extract multiple files at once
adb shell "su -c 'tar czf /sdcard/forensics_data.tar.gz /data/data/'"
adb pull /sdcard/forensics_data.tar.gz ./evidence/

# File listing with metadata
adb shell "find /sdcard -type f -exec ls -la {} \;" > file_listing.txt

# Find recently modified files
adb shell "find /sdcard -newer /sdcard/DCIM -type f 2>/dev/null"

# List including hidden files
adb shell ls -la /sdcard/
```

### Logcat (Log Collection)

```bash
# Collect full log
adb logcat -d > device_log.txt

# Filter by log level (V=Verbose, D=Debug, I=Info, W=Warn, E=Error)
adb logcat *:E > error_log.txt

# Filter by tag
adb logcat -s ActivityManager:I PackageManager:D

# Binary log dump
adb logcat -b events -d > events_log.txt
adb logcat -b radio -d > radio_log.txt   # Call/SMS related
adb logcat -b crash -d > crash_log.txt

# Specify log format
adb logcat -v threadtime -d > detailed_log.txt

# Real-time monitoring for sensitive strings
adb logcat | grep -i "password\|token\|secret\|key"
```

### Bugreport Collection

```bash
# Full bug report (system state snapshot)
adb bugreport ./evidence/bugreport_$(date +%Y%m%d_%H%M%S).zip

# Bug report contents (after unzipping):
# - bugreport-<device>-<date>.txt : Main report
# - FS/data/system/packages.xml  : Installed app list
# - FS/data/system/usagestats/   : App usage statistics

# Dumpsys information collection
adb shell dumpsys > dumpsys_all.txt
adb shell dumpsys activity > activity_info.txt
adb shell dumpsys window > window_info.txt
adb shell dumpsys telephony.registry > telephony_info.txt
adb shell dumpsys usagestats > usage_stats.txt        # App usage time
adb shell dumpsys notification > notifications.txt
adb shell dumpsys location > location_info.txt        # Location services
adb shell dumpsys alarm > scheduled_alarms.txt
```

### Process / App Analysis

```bash
# Running processes
adb shell ps -ef
adb shell top -n 1

# Installed app list
adb shell pm list packages -f    # Include APK path
adb shell pm list packages -3    # Third-party apps only
adb shell pm list packages -d    # Disabled apps only

# Detailed app information
adb shell dumpsys package <package_name>

# App backup (ADB backup, optional encryption)
adb backup -apk -shared -all -f backup_$(date +%Y%m%d).ab

# Screenshot
adb shell screencap -p /sdcard/screenshot.png
adb pull /sdcard/screenshot.png ./evidence/

# Screen recording (up to 3 minutes)
adb shell screenrecord /sdcard/screen_record.mp4
```

---

## 3. Android Artifact Locations

### SMS/MMS

```
/data/data/com.android.providers.telephony/databases/mmssms.db

Tables:
- sms          : Text messages
- mms          : Multimedia messages
- pdu          : MMS data
- threads      : Conversation threads
- canonical_addresses : Address book
```

```sql
-- Query all SMS messages
SELECT _id, thread_id, address, date, date_sent, type, body, read
FROM sms
ORDER BY date DESC;

-- type values: 1=received, 2=sent, 3=draft, 5=failed

-- Deleted SMS (including trash)
SELECT * FROM sms WHERE thread_id IN (
    SELECT _id FROM threads WHERE recipient_ids = ''
);
```

### Contacts

```
/data/data/com.android.providers.contacts/databases/contacts2.db

Tables:
- contacts          : Basic contact information
- raw_contacts      : Contacts by source
- data              : Phone numbers, emails, and other details
- call_log          : Call history (may be in a separate DB)
```

```sql
-- Query contacts with phone numbers
SELECT c.display_name, d.data1 AS phone_number, d.data2 AS type
FROM contacts c
JOIN raw_contacts rc ON c._id = rc.contact_id
JOIN data d ON rc._id = d.raw_contact_id
WHERE d.mimetype_id = (
    SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/phone_v2'
);
```

### Call History

```
/data/data/com.android.providers.contacts/databases/calllog.db
or
/data/data/com.android.providers.contacts/databases/contacts2.db (calls table)

Columns:
- number       : Phone number
- date         : Unix timestamp (milliseconds)
- duration     : Call duration (seconds)
- type         : 1=incoming, 2=outgoing, 3=missed, 4=voicemail
```

### Browser History (AOSP Browser)

```
/data/data/com.android.browser/databases/browser.db
/data/data/com.android.browser/databases/webview.db

Tables: bookmarks, history
```

### Chrome Browser

```
/data/data/com.android.chrome/app_chrome/Default/
├── History                    # SQLite: browsing history
├── Cookies                    # SQLite: cookies
├── Login Data                 # SQLite: saved passwords
├── Web Data                   # SQLite: autofill data
├── Bookmarks                  # JSON: bookmarks
└── Preferences                # JSON: settings
```

```sql
-- Chrome browsing history
SELECT url, title, visit_count, last_visit_time
FROM urls
ORDER BY last_visit_time DESC
LIMIT 100;

-- Chrome saved passwords
SELECT origin_url, username_value, password_value
FROM logins;
```

### KakaoTalk

```
/data/data/com.kakao.talk/databases/
├── KakaoTalk.db               # Main message DB
├── talk_member.db             # Contacts
└── media.db                   # Media metadata

/sdcard/KakaoTalk/
├── Emoticons/
├── media/
└── .backup/                   # Backup files (encrypted)
```

### Wi-Fi Connection History

```
/data/misc/wifi/WifiConfigStore.xml      # Android 10+
/data/misc/wifi/wpa_supplicant.conf      # Android 9 and below

Information included:
- SSID (network name)
- BSSID (AP MAC address)
- Pre-shared key (password, partially encrypted)
- Last connection time
```

### App Usage Statistics

```
/data/system/usagestats/0/               # Usage event log
/data/system_ce/0/usagestats/            # Android 9+

adb shell dumpsys usagestats --csv       # Output in CSV format
```

### Location Data

```
/data/data/com.google.android.gms/databases/
├── persisted_cache.db         # Cached location
└── icing_accounts.db

/data/data/com.google.android.location/databases/
└── locations.db               # Location history

Google Maps:
/data/data/com.google.android.apps.maps/databases/
└── gmm_myplaces.db
```

---

## 4. SQLite DB Extraction and Analysis

### SQLite Command-Line Analysis

```bash
# Basic SQLite3 usage
sqlite3 contacts2.db

# Internal commands
.tables                    # List tables
.schema <table>            # Show table schema
.headers on                # Display column headers
.mode column               # Column alignment mode
.mode csv                  # CSV output mode
.output result.csv         # Write output to file
.dump                      # Full SQL dump output
.quit                      # Exit

# Recovering deleted records (freelist page analysis)
# SQLite marks deleted records as free pages rather than immediately removing them
sqlite3 mmssms.db "SELECT * FROM sqlite_master"
```

### Deleted Record Recovery

```bash
# Method 1: Extract text with strings
strings mmssms.db | grep -E "^\+?[0-9]{10,13}"

# Method 2: Analyze raw data with hexdump
hexdump -C mmssms.db | grep -A2 -B2 "text"

# Method 3: Use SQLite recovery tools
pip install sqlite-utils
sqlite-utils rows mmssms.db sms

# Method 4: undark (specialized SQLite recovery tool)
# https://github.com/witwall/undark
./undark -i mmssms.db > recovered_sms.txt
```

### Timestamp Conversion

```python
import datetime

# Android SMS timestamp (Unix milliseconds)
ts_ms = 1700000000000
dt = datetime.datetime.fromtimestamp(ts_ms / 1000)
print(dt.strftime("%Y-%m-%d %H:%M:%S"))

# Chrome timestamp (WebKit time: microseconds since 1601-01-01)
webkit_ts = 13305000000000000
epoch_diff = 11644473600  # Difference in seconds
unix_ts = (webkit_ts / 1_000_000) - epoch_diff
dt = datetime.datetime.fromtimestamp(unix_ts)
print(dt.strftime("%Y-%m-%d %H:%M:%S"))
```

---

## 5. Python Android Backup Parsing Script

ADB backup files (.ab) are zlib-compressed tar archives.

```python
#!/usr/bin/env python3
"""
Android ADB Backup (.ab) File Parsing and Forensic Analysis Script

Usage:
    python3 android_backup_parser.py -f backup.ab -o ./output
    python3 android_backup_parser.py -f backup.ab -o ./output --analyze-sms
    python3 android_backup_parser.py -f backup.ab -o ./output --all
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import sys
import tarfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class BackupHeader:
    version: int
    compressed: bool
    encrypted: bool
    encryption_algo: str
    password_salt: bytes = field(default_factory=bytes)
    user_iv: bytes = field(default_factory=bytes)
    master_key_blob: bytes = field(default_factory=bytes)


@dataclass
class SmsRecord:
    id: int
    address: str
    date: datetime
    body: str
    msg_type: int  # 1=received, 2=sent
    read: bool


@dataclass
class ContactRecord:
    display_name: str
    phone_numbers: list[str]
    emails: list[str]


def compute_file_hash(filepath: Path) -> dict[str, str]:
    """Compute MD5 and SHA256 hashes of a file"""
    hashes: dict[str, str] = {}
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)

    hashes["md5"] = md5.hexdigest()
    hashes["sha256"] = sha256.hexdigest()
    return hashes


def parse_backup_header(data: bytes) -> tuple[BackupHeader, int]:
    """
    Parse ADB backup header
    Format:
        ANDROID BACKUP\n
        <version>\n
        <compressed: 0|1>\n
        <encryption: none|AES-256>\n
    """
    lines = []
    offset = 0

    for _ in range(5):
        end = data.index(b"\n", offset)
        lines.append(data[offset:end].decode("utf-8", errors="replace"))
        offset = end + 1

    if lines[0] != "ANDROID BACKUP":
        raise ValueError(f"Invalid ADB backup file: header mismatch")

    version = int(lines[1])
    compressed = lines[2] == "1"
    encryption_algo = lines[3]
    encrypted = encryption_algo != "none"

    header = BackupHeader(
        version=version,
        compressed=compressed,
        encrypted=encrypted,
        encryption_algo=encryption_algo,
    )
    return header, offset


def decompress_backup(backup_path: Path) -> bytes:
    """Read ADB backup file and convert to tar data"""
    with open(backup_path, "rb") as f:
        raw = f.read()

    header, data_offset = parse_backup_header(raw)

    if header.encrypted:
        raise NotImplementedError(
            "Encrypted backups require a password. "
            "Decrypt first using openssl:\n"
            "  openssl enc -d -aes-256-cbc -md md5 -in backup.ab -out decrypted.ab"
        )

    payload = raw[data_offset:]

    if header.compressed:
        try:
            decompressed = zlib.decompress(payload)
        except zlib.error as e:
            raise RuntimeError(f"Decompression failed: {e}") from e
    else:
        decompressed = payload

    return decompressed


def extract_tar_to_directory(tar_data: bytes, output_dir: Path) -> list[str]:
    """Extract tar data to a directory"""
    import io

    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_files: list[str] = []

    with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as tar:
        for member in tar.getmembers():
            try:
                tar.extract(member, path=output_dir, set_attrs=False)
                extracted_files.append(member.name)
            except (tarfile.ExtractError, PermissionError) as e:
                print(f"  [WARNING] Extraction failed: {member.name} - {e}", file=sys.stderr)

    return extracted_files


def find_sqlite_databases(base_dir: Path) -> list[Path]:
    """Search for SQLite DB files in the extracted directory"""
    db_files: list[Path] = []
    sqlite_magic = b"SQLite format 3\x00"

    for path in base_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as f:
                header = f.read(16)
            if header == sqlite_magic:
                db_files.append(path)
        except (OSError, PermissionError):
            continue

    return db_files


def analyze_sms_database(db_path: Path) -> list[SmsRecord]:
    """Analyze SMS database"""
    records: list[SmsRecord] = []

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Verify table exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sms'")
        if not cur.fetchone():
            conn.close()
            return records

        cur.execute("""
            SELECT _id, address, date, body, type, read
            FROM sms
            ORDER BY date DESC
        """)

        for row in cur.fetchall():
            try:
                ts = datetime.fromtimestamp(row["date"] / 1000)
            except (OSError, ValueError, OverflowError):
                ts = datetime.fromtimestamp(0)

            records.append(SmsRecord(
                id=row["_id"],
                address=row["address"] or "",
                date=ts,
                body=row["body"] or "",
                msg_type=row["type"],
                read=bool(row["read"]),
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [ERROR] SMS DB analysis failed ({db_path.name}): {e}", file=sys.stderr)

    return records


def analyze_contacts_database(db_path: Path) -> list[ContactRecord]:
    """Analyze contacts database"""
    records: list[ContactRecord] = []

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='contacts'")
        if not cur.fetchone():
            conn.close()
            return records

        # Collect phone numbers/emails per contact
        cur.execute("SELECT _id, display_name FROM contacts")
        contacts = cur.fetchall()

        for contact in contacts:
            phones: list[str] = []
            emails: list[str] = []

            try:
                cur.execute("""
                    SELECT d.data1, m.mimetype
                    FROM data d
                    JOIN raw_contacts rc ON d.raw_contact_id = rc._id
                    JOIN mimetypes m ON d.mimetype_id = m._id
                    WHERE rc.contact_id = ?
                      AND m.mimetype IN (
                          'vnd.android.cursor.item/phone_v2',
                          'vnd.android.cursor.item/email_v2'
                      )
                """, (contact["_id"],))

                for row in cur.fetchall():
                    if "phone" in row["mimetype"]:
                        phones.append(row["data1"] or "")
                    else:
                        emails.append(row["data1"] or "")
            except sqlite3.DatabaseError:
                pass

            records.append(ContactRecord(
                display_name=contact["display_name"] or "(no name)",
                phone_numbers=phones,
                emails=emails,
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [ERROR] Contacts DB analysis failed ({db_path.name}): {e}", file=sys.stderr)

    return records


def generate_report(
    backup_path: Path,
    output_dir: Path,
    file_hashes: dict[str, str],
    extracted_files: list[str],
    db_files: list[Path],
    sms_records: list[SmsRecord],
    contacts: list[ContactRecord],
) -> Path:
    """Generate forensic report"""
    report: dict = {
        "analysis_time": datetime.now().isoformat(),
        "source_file": str(backup_path),
        "file_hashes": file_hashes,
        "extracted_file_count": len(extracted_files),
        "db_count": len(db_files),
        "db_list": [str(p.relative_to(output_dir)) for p in db_files],
        "sms_analysis": {
            "total": len(sms_records),
            "received": sum(1 for s in sms_records if s.msg_type == 1),
            "sent": sum(1 for s in sms_records if s.msg_type == 2),
            "unread": sum(1 for s in sms_records if not s.read),
            "recent_messages": [
                {
                    "sender": s.address,
                    "time": s.date.isoformat(),
                    "preview": s.body[:100],
                    "direction": "received" if s.msg_type == 1 else "sent",
                }
                for s in sms_records[:20]
            ],
        },
        "contacts_analysis": {
            "total": len(contacts),
            "contact_list": [
                {
                    "name": c.display_name,
                    "phone_numbers": c.phone_numbers,
                    "emails": c.emails,
                }
                for c in contacts[:50]
            ],
        },
    }

    report_path = output_dir / "forensics_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # Also generate a human-readable text report
    txt_report_path = output_dir / "forensics_report.txt"
    with open(txt_report_path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("Android Forensic Analysis Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Analysis time: {report['analysis_time']}\n")
        f.write(f"Source file: {backup_path}\n")
        f.write(f"MD5:    {file_hashes.get('md5', 'N/A')}\n")
        f.write(f"SHA256: {file_hashes.get('sha256', 'N/A')}\n\n")
        f.write(f"Extracted files: {len(extracted_files)}\n")
        f.write(f"SQLite DBs found: {len(db_files)}\n\n")

        f.write("-" * 40 + "\n")
        f.write(f"SMS Analysis (total: {len(sms_records)})\n")
        f.write("-" * 40 + "\n")
        for sms in sms_records[:20]:
            direction = "received" if sms.msg_type == 1 else "sent"
            f.write(f"[{sms.date.strftime('%Y-%m-%d %H:%M:%S')}] {direction} | {sms.address}\n")
            f.write(f"  {sms.body[:80]}\n\n")

        f.write("-" * 40 + "\n")
        f.write(f"Contacts ({len(contacts)} total)\n")
        f.write("-" * 40 + "\n")
        for contact in contacts[:30]:
            f.write(f"{contact.display_name}\n")
            for phone in contact.phone_numbers:
                f.write(f"  Phone: {phone}\n")
            for email in contact.emails:
                f.write(f"  Email: {email}\n")
            f.write("\n")

    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Android ADB Backup File Forensic Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f backup.ab -o ./output
  %(prog)s -f backup.ab -o ./output --analyze-sms --analyze-contacts
  %(prog)s -f backup.ab -o ./output --all
        """,
    )
    parser.add_argument("-f", "--file", required=True, help="Path to ADB backup file (.ab)")
    parser.add_argument("-o", "--output", required=True, help="Output directory path")
    parser.add_argument("--analyze-sms", action="store_true", help="Perform SMS analysis")
    parser.add_argument("--analyze-contacts", action="store_true", help="Perform contacts analysis")
    parser.add_argument("--all", action="store_true", help="Perform all analyses")
    parser.add_argument("--no-extract", action="store_true", help="Skip file extraction (if already extracted)")

    args = parser.parse_args()

    if args.all:
        args.analyze_sms = True
        args.analyze_contacts = True

    backup_path = Path(args.file)
    output_dir = Path(args.output)

    if not backup_path.exists():
        print(f"[ERROR] Backup file not found: {backup_path}", file=sys.stderr)
        return 1

    print(f"[*] Computing file hashes: {backup_path}")
    file_hashes = compute_file_hash(backup_path)
    print(f"    MD5:    {file_hashes['md5']}")
    print(f"    SHA256: {file_hashes['sha256']}")

    extracted_files: list[str] = []
    extract_dir = output_dir / "extracted"

    if not args.no_extract:
        print(f"\n[*] Decompressing backup file...")
        try:
            tar_data = decompress_backup(backup_path)
            print(f"[*] Extracting files to: {extract_dir}")
            extracted_files = extract_tar_to_directory(tar_data, extract_dir)
            print(f"    Extraction complete: {len(extracted_files)} files")
        except (ValueError, RuntimeError, NotImplementedError) as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 1
    else:
        if extract_dir.exists():
            extracted_files = [str(p) for p in extract_dir.rglob("*") if p.is_file()]

    print(f"\n[*] Searching for SQLite DBs...")
    db_files = find_sqlite_databases(extract_dir)
    print(f"    DBs found: {len(db_files)}")
    for db in db_files:
        print(f"    - {db.relative_to(output_dir)}")

    sms_records: list[SmsRecord] = []
    contacts: list[ContactRecord] = []

    if args.analyze_sms:
        print(f"\n[*] Analyzing SMS...")
        for db in db_files:
            if "mmssms" in db.name or "telephony" in str(db):
                records = analyze_sms_database(db)
                sms_records.extend(records)
                print(f"    {db.name}: {len(records)} messages")

    if args.analyze_contacts:
        print(f"\n[*] Analyzing contacts...")
        for db in db_files:
            if "contacts2" in db.name or "contacts" in db.name:
                records = analyze_contacts_database(db)
                contacts.extend(records)
                print(f"    {db.name}: {len(records)} contacts")

    print(f"\n[*] Generating report...")
    report_path = generate_report(
        backup_path, output_dir, file_hashes,
        extracted_files, db_files, sms_records, contacts,
    )
    print(f"    JSON report: {report_path}")
    print(f"    TXT report:  {output_dir / 'forensics_report.txt'}")

    print(f"\n[DONE] Results saved to: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. Magisk / Root Detection

### Root Artifact Files and Paths

```bash
# Check for root binaries
adb shell ls /system/bin/su 2>/dev/null
adb shell ls /system/xbin/su 2>/dev/null
adb shell ls /sbin/su 2>/dev/null
adb shell ls /data/local/bin/su 2>/dev/null
adb shell which su

# Magisk-related files
adb shell ls /data/adb/magisk 2>/dev/null
adb shell ls /sbin/.magisk 2>/dev/null
adb shell ls /data/adb/modules 2>/dev/null

# SuperSU artifacts
adb shell ls /system/app/SuperSU/ 2>/dev/null

# Xposed Framework
adb shell ls /system/framework/XposedBridge.jar 2>/dev/null

# Custom recovery (TWRP, etc.)
adb shell ls /cache/recovery/ 2>/dev/null
```

### Build Property Analysis

```bash
# Check root-related properties
adb shell getprop ro.build.tags          # "test-keys" → unofficial build
adb shell getprop ro.build.type          # "userdebug" or "eng" → debug build
adb shell getprop ro.debuggable          # "1" → debuggable (potential root)
adb shell getprop ro.secure              # "0" → adb root allowed
adb shell getprop service.adb.root       # "1" → root adb running

# SELinux status
adb shell getenforce                     # "Permissive" → reduced security mode
adb shell cat /proc/sys/fs/protected_hardlinks
```

### Root App Package List

```bash
# Search for root-related packages
adb shell pm list packages | grep -iE "magisk|supersu|topjohnwu|chainfire|xposed"

# Known root app package names:
# - com.topjohnwu.magisk      (Magisk Manager)
# - eu.chainfire.supersu       (SuperSU)
# - com.noshufou.android.su    (Superuser)
# - com.koushikdutta.superuser (Superuser)
# - de.robv.android.xposed.installer (Xposed)
```

### Python Root Detection Script

```python
#!/usr/bin/env python3
"""
Android Root / Magisk Artifact Auto-Detection Script
Runs against a device connected via ADB

Usage:
    python3 detect_root.py
    python3 detect_root.py --output root_report.json
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime


ROOT_INDICATORS: dict[str, list[str]] = {
    "Root Binaries": [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/bin/su",
        "/data/local/su",
    ],
    "Magisk Files": [
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/data/adb/modules",
        "/data/adb/magisk.img",
        "/cache/.disable_magisk",
    ],
    "SuperSU/SuperUser": [
        "/system/app/SuperSU",
        "/system/app/Superuser",
        "/data/data/eu.chainfire.supersu",
    ],
    "Xposed Framework": [
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/data/data/de.robv.android.xposed.installer",
    ],
    "Custom Recovery": [
        "/cache/recovery",
        "/cache/recovery/command",
    ],
}

ROOT_PACKAGES: list[str] = [
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.koushikdutta.superuser",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
]

SUSPICIOUS_PROPS: dict[str, list[str]] = {
    "ro.build.tags": ["test-keys"],
    "ro.build.type": ["userdebug", "eng"],
    "ro.debuggable": ["1"],
    "ro.secure": ["0"],
    "service.adb.root": ["1"],
}


def run_adb(args: list[str], timeout: int = 10) -> tuple[bool, str]:
    """Execute ADB command"""
    try:
        result = subprocess.run(
            ["adb", "shell"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return True, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except FileNotFoundError:
        return False, "adb not found"


def check_device_connected() -> bool:
    """Check if ADB device is connected"""
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        return any("device" in line and "List" not in line for line in lines)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_file_exists(path: str) -> bool:
    """Check if a file exists on the device"""
    ok, output = run_adb(["test", "-e", path, "&&", "echo", "EXISTS"])
    return ok and "EXISTS" in output


def get_property(prop: str) -> str:
    """Retrieve Android property value"""
    ok, value = run_adb(["getprop", prop])
    return value if ok else ""


def get_installed_packages() -> list[str]:
    """Retrieve list of installed packages"""
    ok, output = run_adb(["pm", "list", "packages"])
    if not ok:
        return []
    return [line.replace("package:", "").strip() for line in output.split("\n") if line]


def get_selinux_status() -> str:
    """Check SELinux status"""
    ok, status = run_adb(["getenforce"])
    return status if ok else "unknown"


def scan_root_indicators() -> dict:
    """Full scan of root indicators"""
    results: dict = {
        "scan_time": datetime.now().isoformat(),
        "found_indicators": [],
        "suspicious_properties": [],
        "root_apps": [],
        "selinux_status": "",
        "root_likelihood": "low",
    }

    print("[*] Checking root binaries and files...")
    for category, paths in ROOT_INDICATORS.items():
        for path in paths:
            if check_file_exists(path):
                results["found_indicators"].append({"category": category, "path": path})
                print(f"    [FOUND] {path} ({category})")

    print("[*] Checking system properties...")
    for prop, suspicious_values in SUSPICIOUS_PROPS.items():
        value = get_property(prop)
        if value in suspicious_values:
            results["suspicious_properties"].append({"property": prop, "value": value})
            print(f"    [SUSPICIOUS] {prop} = {value}")

    print("[*] Checking for root-related apps...")
    installed = get_installed_packages()
    for pkg in ROOT_PACKAGES:
        if pkg in installed:
            results["root_apps"].append(pkg)
            print(f"    [FOUND] Root app: {pkg}")

    results["selinux_status"] = get_selinux_status()
    print(f"[*] SELinux status: {results['selinux_status']}")

    # Assess root likelihood
    indicator_count = (
        len(results["found_indicators"])
        + len(results["suspicious_properties"])
        + len(results["root_apps"])
    )
    selinux_permissive = results["selinux_status"] == "Permissive"

    if indicator_count >= 3 or results["root_apps"]:
        results["root_likelihood"] = "high"
    elif indicator_count >= 1 or selinux_permissive:
        results["root_likelihood"] = "medium"

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Android Root Artifact Detection Tool")
    parser.add_argument("--output", "-o", help="Path to save results as JSON file")
    args = parser.parse_args()

    if not check_device_connected():
        print("[ERROR] No ADB-connected device found.", file=sys.stderr)
        print("  Ensure USB debugging is enabled.", file=sys.stderr)
        return 1

    print("[*] Starting Android root artifact detection\n")
    results = scan_root_indicators()

    print(f"\n{'='*50}")
    print(f"Root likelihood: {results['root_likelihood']}")
    print(f"Indicators found: {len(results['found_indicators'])}")
    print(f"Suspicious properties: {len(results['suspicious_properties'])}")
    print(f"Root apps: {len(results['root_apps'])}")
    print(f"SELinux: {results['selinux_status']}")
    print(f"{'='*50}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n[*] Results saved: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### Root Detection Bypass Techniques (Defender Reference)

```bash
# Magisk Hide (now replaced by DenyList)
# Bypass root detection for specific apps
# Settings > Magisk > Configure DenyList

# Example bypass modules (for educational understanding)
# - MagiskHide Props Config
# - Universal SafetyNet Fix
# - Shamiko

# Check SafetyNet/Play Integrity status
adb shell cmd package check-permission android.permission.QUERY_ALL_PACKAGES com.topjohnwu.magisk

# Enhanced detection: runtime integrity check
# - Search for magisk-related entries in /proc/self/maps
adb shell "cat /proc/$(adb shell pidof com.target.app)/maps | grep -i magisk"
```

---

## Reference Tools and Resources

| Tool | Purpose | Installation |
|------|---------|--------------|
| ADB | Android device connection/extraction | Android SDK Platform Tools |
| SQLite3 | DB analysis | `apt install sqlite3` |
| Autopsy | GUI forensic analysis | https://www.autopsy.com |
| AFLogical | Android logical extraction | https://github.com/nowsecure/android-forensics |
| ALEAPP | Android artifact parsing | https://github.com/abrignoni/ALEAPP |
| MVT | Spyware detection | `pip install mvt` |
| androguard | APK static analysis | `pip install androguard` |

```bash
# Install and use ALEAPP
git clone https://github.com/abrignoni/ALEAPP
cd ALEAPP
pip install -r requirements.txt

# Run GUI
python aleappGUI.py

# Run CLI
python aleapp.py -t fs -i /path/to/extraction -o /path/to/report
```

<!-- detect-validate-47 -->
## Anti-Forensics Detection and Android Evidence Validation

Android forensics recovers evidence from *the filesystem, artifacts, SQLite DBs, and rooting traces*. The analyst must be aware of anti-forensics like *root concealment, timestamp tampering, and artifact deletion* and verify **whether evidence is intact and cross-consistent**. Validate only on **owned devices/images**.

### Anti-forensic technique -> Targeted forensic step -> Analyst response -> Observable signal

| Technique | Targeted step | Analyst response | Observable signal |
|---|---|---|---|
| Root concealment | Integrity assumption | Cross-check Magisk/su traces | su, busybox, denylist |
| Timestamp tampering | Timeline trust | Cross multiple artifacts | DB ts != file mtime |
| Artifact deletion | Single-source reliance | WAL/journal remnants | Deleted rows in -wal |
| Backup tampering | Backup trust | Hash/signature verify | Backup hash mismatch |

### Evidence validation (verify directly)

```bash
# 1) Root/concealment traces in an owned image — su/Magisk/busybox remnants signal integrity compromise
adb shell 'ls -la /system/xbin/su /sbin/.magisk 2>/dev/null; pm list packages | grep -iE "magisk|supersu"' 2>/dev/null | head
# 2) Whether deleted SQLite rows remain in WAL/journal (anti-forensics bypass) — absent in main DB but present in -wal
sqlite3 mmssms.db 'PRAGMA journal_mode;' 2>/dev/null; strings mmssms.db-wal 2>/dev/null | grep -iE 'deleted|http' | head
```

> Android evidence validation is *whether evidence is intact and cross-consistent* -- "I extracted the DB" differs from "rooting traces cross-check and timestamps agree across multiple artifacts". Confirm on owned devices/images directly ([[07_Digital_Forensics]], [[28_Mobile_Hacking]], [[44_Incident_Response_DFIR]]).
