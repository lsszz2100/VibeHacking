> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# iOS 포렌식

## 0. 초보자를 위한 개념 이해

### iOS 포렌식이란?

iOS 포렌식은 iPhone, iPad에서 디지털 증거를 추출하고 분석하는 전문 기법이다. Apple의 강력한 암호화와 보안 체계 때문에 Android보다 훨씬 어렵지만, iTunes/iCloud 백업, 탈옥(Jailbreak) 또는 전용 장비를 통해 증거를 확보할 수 있다.

**왜 배우는가:**
```
iOS vs Android 포렌식 난이도 비교:

  Android
    - USB 디버깅(ADB)으로 상대적 쉬운 접근
    - 다양한 제조사 = 다양한 보안 수준

  iOS (훨씬 어려움)
    - Apple의 통일된 강력 암호화 (AES-256)
    - 화면 잠금 = 데이터 완전 암호화
    - GrayKey/Cellebrite만이 일부 우회 가능

  법집행기관이 iOS를 어려워하는 이유:
    - 잠금 화면 = 모든 데이터 암호화
    - Apple은 수사 협조 거부 사례 다수
    - USB Restricted Mode: 연결 1시간 후 데이터 전송 차단

  그래도 확보 가능한 것:
    - iTunes 로컬 백업 (암호 없으면 완전 복호화)
    - iCloud 백업 (Apple ID 비밀번호 필요)
    - 탈옥 기기 (ssh로 직접 접근)
```

### 핵심 개념 정리

```
iOS 백업 구조:

iTunes 로컬 백업 (암호화 안 된 경우)
  위치: ~/Library/Application Support/MobileSync/Backup/
  구조: [UDID]/ 폴더 안에 해시 파일명으로 저장
  → 파일명이 SHA1 해시라 직접 읽기 어려움
  → iMazing, libimobiledevice로 파싱 가능

iTunes 백업 파일 구성:
  Manifest.db  - 파일 목록 (SQLite DB)
  Manifest.plist - 기기 정보
  Info.plist   - 백업 메타데이터
  Status.plist - 백업 상태
  [해시파일들] - 실제 데이터 (250개 폴더에 분산)

주요 아티팩트 위치 (탈옥 기기 or 백업):
  /var/mobile/Library/SMS/sms.db          SMS
  /var/mobile/Library/CallHistory/       통화기록
  /var/mobile/Library/Safari/            브라우저
  /var/mobile/Library/Mail/              이메일
  /var/mobile/Media/DCIM/                사진/영상
```

### 필요한 도구 및 환경
- **libimobiledevice**: Linux/macOS에서 iOS 기기 접근 (`apt install libimobiledevice-utils`)
- **iMazing (상용)**: iTunes 백업 파싱 GUI 도구
- **mvt-ios**: Pegasus 스파이웨어 탐지 도구
- **SQLite Browser**: iOS DB 파일 (.db) 분석
- **Belkasoft / Cellebrite**: 전문 포렌식 솔루션

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
iTunes 백업에서 SMS 메시지를 추출하는 기초 스크립트
백업 암호화 해제 후 사용 (암호화 설정 시 복호화 필요)
"""
import json
import sqlite3
from pathlib import Path


def find_sms_db_in_backup(backup_path: str) -> Path | None:
    """
    iTunes 백업에서 SMS DB 파일을 찾는다.
    sms.db의 SHA1 해시: 3d0d7e5fb2ce288813306e4d4636395e047a3d28
    """
    sms_hash = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"
    backup_dir = Path(backup_path)

    # 백업 파일은 첫 2글자로 된 폴더 안에 저장됨
    sms_path = backup_dir / sms_hash[:2] / sms_hash
    if sms_path.exists():
        return sms_path

    return None


def extract_sms_messages(db_path: Path, limit: int = 20) -> list[dict]:
    """
    SMS DB에서 메시지를 추출한다.
    실제 sms.db 스키마 기반 (iOS 버전마다 다를 수 있음).
    """
    messages = []
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # iOS sms.db 기본 쿼리
        cursor.execute("""
            SELECT
                m.rowid,
                CASE m.is_from_me WHEN 1 THEN '발신' ELSE '수신' END as 방향,
                m.text as 내용,
                datetime(m.date/1000000000 + 978307200, 'unixepoch', 'localtime') as 시간,
                h.id as 상대방
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.rowid
            ORDER BY m.date DESC
            LIMIT ?
        """, (limit,))

        for row in cursor.fetchall():
            messages.append({
                "id": row[0],
                "방향": row[1],
                "내용": row[2] or "[미디어]",
                "시간": row[3],
                "상대방": row[4],
            })
        conn.close()
    except sqlite3.Error as e:
        messages.append({"오류": str(e), "원인": "암호화된 백업이거나 스키마 불일치"})

    return messages


if __name__ == "__main__":
    # 실제 사용 시 iTunes 백업 경로 입력
    # macOS: ~/Library/Application Support/MobileSync/Backup/[UDID]/
    backup_path = "./sample_backup"

    print("[iOS iTunes 백업 SMS 추출 도구]")
    print("주의: 법적 권한이 있는 기기의 백업만 분석할 것")

    db_path = find_sms_db_in_backup(backup_path)
    if db_path:
        messages = extract_sms_messages(db_path, limit=10)
        print(json.dumps(messages, ensure_ascii=False, indent=2))
    else:
        print(f"SMS DB를 찾을 수 없습니다. 백업 경로 확인: {backup_path}")
        print("예상 위치: [backup]/{3d0d7e.../3d0d7e...}")
```

---

## 목차
1. iOS 파일시스템 구조
2. iTunes 백업 구조 분석
3. iCloud 백업 vs 로컬 백업 차이
4. iOS 아티팩트 위치
5. Python iOS 백업 복호화/파싱 스크립트
6. GrayKey/Cellebrite 방식 개요

---

## 1. iOS 파일시스템 구조

### 파티션 구조

iOS 기기는 크게 두 개의 주요 파티션으로 구성됩니다.

```
/dev/disk0s1    →  /           (시스템 파티션, 읽기 전용, ~7-10GB)
/dev/disk0s2    →  /private/var (데이터 파티션, 읽기/쓰기, 나머지 용량)
```

**시스템 파티션 (읽기 전용)**
```
/bin/           - 기본 바이너리
/sbin/          - 시스템 바이너리
/lib/           - 공유 라이브러리
/usr/           - 사용자 유틸리티
/System/        - iOS 프레임워크
/Applications/  - 기본 앱 (Phone, Safari, Messages 등)
/private/etc/   - 시스템 설정
```

**데이터 파티션 (/private/var)**
```
/private/var/
├── mobile/                  # 기본 사용자 홈 디렉토리
│   ├── Applications/        # iOS 7 이하: 앱 데이터
│   ├── Containers/          # iOS 8+: 앱 데이터
│   │   ├── Bundle/          # 앱 바이너리 (UUID 기반)
│   │   └── Data/            # 앱 데이터 (UUID 기반)
│   │       └── Application/
│   │           └── <UUID>/
│   │               ├── Documents/
│   │               ├── Library/
│   │               │   ├── Caches/
│   │               │   └── Preferences/
│   │               └── tmp/
│   ├── Library/             # 사용자 라이브러리
│   │   ├── AddressBook/     # 연락처
│   │   ├── SMS/             # 문자 메시지
│   │   ├── CallHistory/     # 통화 기록
│   │   ├── Safari/          # 브라우저 데이터
│   │   ├── Mail/            # 이메일
│   │   ├── Notes/           # 노트
│   │   ├── Health/          # 건강 데이터
│   │   ├── Voicemail/       # 음성메일
│   │   ├── Maps/            # 지도/위치
│   │   └── Calendars/       # 캘린더
│   └── Media/               # 사용자 미디어
│       ├── DCIM/            # 사진/동영상
│       ├── PhotoData/       # 사진 메타데이터
│       └── iTunes_Control/  # iTunes 동기화
└── root/                    # 루트 사용자 (탈옥 시)
```

### HFS+ vs APFS

**HFS+ (Mac OS Extended)**
- iOS 10.2 이하 사용
- 타임스탬프: Mac Absolute Time (2001년 1월 1일 기준)
- 저널링 지원

**APFS (Apple File System)**
- iOS 10.3+ 사용
- 스냅샷(Snapshot) 지원 → 삭제 전 상태 복구 가능
- 공간 공유, Copy-on-Write
- 암호화: 파일별 개별 암호화 키
- 타임스탬프: 나노초 정밀도

```bash
# 탈옥 기기에서 파일시스템 확인
ideviceinfo | grep FSType

# SSH로 접근 (탈옥 기기)
ssh root@<device_ip>
mount | grep /dev/disk
df -h

# 파일시스템 정보 덤프
diskutil list  # Mac에서 연결 시
```

### 타임스탬프 변환

```python
from datetime import datetime, timezone

# Mac Absolute Time → Unix 시간
# Mac Absolute Time: 2001년 1월 1일 00:00:00 UTC 기준 초
MAC_EPOCH_OFFSET = 978307200  # 초 단위

def mac_absolute_to_datetime(mac_ts: float) -> datetime:
    unix_ts = mac_ts + MAC_EPOCH_OFFSET
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc)

# 예시
ts = mac_absolute_to_datetime(699123456)
print(ts.strftime("%Y-%m-%d %H:%M:%S %Z"))

# 나노초 타임스탬프 (APFS)
def apfs_timestamp_to_datetime(ns_ts: int) -> datetime:
    unix_ts = ns_ts / 1_000_000_000
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
```

---

## 2. iTunes 백업 구조 분석

### 백업 저장 위치

```
# macOS
~/Library/Application Support/MobileSync/Backup/<UDID>/

# Windows
%APPDATA%\Apple Computer\MobileSync\Backup\<UDID>\
또는
%USERPROFILE%\Apple\MobileSync\Backup\<UDID>\
```

### 백업 파일 구조

```
<UDID>/
├── Manifest.db          # 전체 파일 목록 (SQLite)
├── Manifest.plist       # 백업 메타데이터 (암호화 여부, iOS 버전 등)
├── Info.plist           # 기기 정보 (모델, IMEI, 전화번호 등)
├── Status.plist         # 백업 상태
└── <xx>/                # 파일 데이터 (해시 앞 2자리로 디렉토리 구분)
    └── <40자리 SHA1 해시>  # 실제 파일 데이터 (확장자 없음)
```

### Manifest.db 분석

```sql
-- Manifest.db 테이블 구조
-- Files 테이블: 백업된 파일 목록
SELECT fileID, domain, relativePath, flags, file
FROM Files
LIMIT 10;

-- domain: 앱/데이터 도메인 분류
-- HomeDomain: /var/mobile/Library/ 하위 파일
-- AppDomain: 앱 데이터
-- MediaDomain: 미디어 파일
-- DatabaseDomain: 데이터베이스
-- WirelessDomain: Wi-Fi 설정

-- 특정 파일 검색
SELECT fileID, relativePath
FROM Files
WHERE relativePath LIKE '%SMS%';

-- 앱 도메인 목록
SELECT DISTINCT domain FROM Files ORDER BY domain;
```

```bash
# 백업에서 특정 파일 추출 (Python 사용 권장)
sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE '%sms%'"

# fileID로 파일 찾기 (앞 2자리가 디렉토리명)
# fileID = "abc123..." → ./ab/abc123...
```

### Info.plist 분석

```bash
# plist 파일 읽기 (macOS)
plutil -p Info.plist

# Linux (libplist 사용)
apt install libplist-utils
plistutil -i Info.plist -o Info.xml
cat Info.xml
```

**Info.plist 주요 항목**
```xml
<key>Build Version</key>          <!-- iOS 빌드 버전 -->
<key>Device Name</key>            <!-- 기기 이름 -->
<key>GUID</key>                   <!-- 기기 고유 ID -->
<key>IMEI</key>                   <!-- IMEI 번호 -->
<key>Last Backup Date</key>       <!-- 마지막 백업 시간 -->
<key>Phone Number</key>           <!-- 전화번호 -->
<key>Product Type</key>           <!-- iPhone 모델 (e.g., iPhone14,2) -->
<key>Serial Number</key>          <!-- 시리얼 번호 -->
```

---

## 3. iCloud 백업 vs 로컬 백업 차이

### 비교표

| 항목 | 로컬 백업 (iTunes/Finder) | iCloud 백업 |
|------|--------------------------|-------------|
| 저장 위치 | 컴퓨터 로컬 | Apple 서버 |
| 암호화 | 선택적 (비밀번호) | 기본 암호화 |
| 포함 데이터 | 거의 모든 데이터 | 일부 제외 (iCloud 동기화 데이터) |
| 법적 접근 | 기기 또는 컴퓨터 압수 | 법원 영장 필요 |
| 접근 방법 | Manifest.db 분석 | Apple 법집행 요청 또는 계정 자격증명 |
| 포렌식 편의성 | 높음 (직접 접근) | 낮음 (Apple 협조 필요) |
| iTunes 백업 암호화 | 비밀번호 없으면 일부 제외 | 해당 없음 |

### 로컬 백업 암호화 여부 확인

```bash
# Manifest.plist에서 암호화 상태 확인
python3 -c "
import plistlib
with open('Manifest.plist', 'rb') as f:
    data = plistlib.load(f)
print('암호화:', data.get('IsEncrypted', False))
print('백업 날짜:', data.get('Date'))
"
```

### iCloud 백업 데이터 요청 (법집행 기관)

```
Apple 법집행 요청 프로세스:
1. 관할 법원 영장 발부
2. https://www.apple.com/legal/privacy/law-enforcement-guidelines-us.pdf 에 제출
3. Apple이 iCloud 데이터 추출 후 제공

iCloud 백업에 포함되는 데이터:
- SMS/iMessage (iCloud 메시지 비활성화 시)
- 앱 데이터
- 기기 설정
- 사진 (iCloud 사진 미사용 시)
- 통화 기록
- Safari 기록
- 연락처, 캘린더, 메모
```

### Apple 투명성 보고서

```
https://www.apple.com/legal/transparency/

한국 법집행 요청 현황:
- Apple은 반기별로 국가별 요청 건수 공개
- 계정 정보 요청 vs 기기 정보 요청 구분
- 준수율(Compliance Rate) 공개
```

---

## 4. iOS 아티팩트 위치

### iMessage / SMS

```
백업 내: HomeDomain/Library/SMS/sms.db

테이블:
- message          : 메시지 내용
- chat             : 대화 목록
- chat_message_join: 대화-메시지 연결
- handle           : 발신자/수신자 정보
- attachment       : 첨부파일
```

```sql
-- iMessage/SMS 전체 조회
SELECT
    m.rowid,
    h.id AS sender,
    datetime(m.date/1000000000 + 978307200, 'unixepoch', 'localtime') AS timestamp,
    m.text,
    m.is_from_me,
    m.service    -- 'SMS' or 'iMessage'
FROM message m
LEFT JOIN handle h ON m.handle_id = h.rowid
ORDER BY m.date DESC;

-- 첨부파일 포함 메시지
SELECT m.text, a.filename, a.mime_type
FROM message m
JOIN message_attachment_join maj ON m.rowid = maj.message_id
JOIN attachment a ON maj.attachment_id = a.rowid;

-- 삭제된 메시지 (cache_has_attachments 등 잔여 데이터)
SELECT * FROM message WHERE text IS NULL AND cache_has_attachments = 1;
```

### Safari 브라우저

```
백업 내:
- HomeDomain/Library/Safari/History.db         # 방문 기록
- HomeDomain/Library/Safari/Bookmarks.db       # 북마크
- HomeDomain/Library/Safari/BrowserState.db    # 탭 상태
- HomeDomain/Library/Cookies/Cookies.binarycookies  # 쿠키 (바이너리)
- HomeDomain/Library/Safari/Downloads.plist    # 다운로드 기록
```

```sql
-- Safari 방문 기록
SELECT
    hi.url,
    hv.title,
    datetime(hv.visit_time + 978307200, 'unixepoch', 'localtime') AS visited_at
FROM history_visits hv
JOIN history_items hi ON hv.history_item = hi.id
ORDER BY hv.visit_time DESC;
```

```python
# Safari 쿠키 파싱 (Binary Cookies 형식)
import struct

def parse_binarycookies(filepath: str) -> list[dict]:
    """Safari Binary Cookies 파일 파싱"""
    cookies: list[dict] = []

    with open(filepath, "rb") as f:
        magic = f.read(4)
        if magic != b"cook":
            raise ValueError("유효하지 않은 Binary Cookies 파일")

        num_pages = struct.unpack(">I", f.read(4))[0]
        page_sizes = [struct.unpack(">I", f.read(4))[0] for _ in range(num_pages)]

        for page_size in page_sizes:
            page_data = f.read(page_size)
            # 페이지 내 쿠키 파싱 (간략화)
            page_header = struct.unpack("<I", page_data[:4])[0]
            num_cookies = struct.unpack("<I", page_data[4:8])[0]

            for i in range(num_cookies):
                offset = struct.unpack("<I", page_data[8 + i * 4:12 + i * 4])[0]
                cookies.append({"raw_offset": offset, "page_header": page_header})

    return cookies
```

### 통화 기록

```
백업 내: HomeDomain/Library/CallHistory/CallHistory.storedata

NSPersistentStore (Core Data) 형식 → SQLite로 열 수 있음

SELECT
    ZADDRESS,
    ZDURATION,
    ZDATE,
    ZORIGINATED,  -- 0=수신, 1=발신
    ZCALLTYPE     -- 0=전화, 1=FaceTime Audio, 8=FaceTime Video
FROM ZCALLRECORD
ORDER BY ZDATE DESC;

-- 타임스탬프: Core Data (Mac Absolute Time)
SELECT
    ZADDRESS,
    datetime(ZDATE + 978307200, 'unixepoch', 'localtime') AS call_time,
    CAST(ZDURATION AS INT) || '초' AS duration
FROM ZCALLRECORD;
```

### 연락처

```
백업 내: HomeDomain/Library/AddressBook/AddressBook.sqlitedb

테이블:
- ABPerson            : 기본 연락처 정보
- ABMultiValue        : 전화번호, 이메일, URL 등
- ABMultiValueEntry   : 다중값 항목
```

```sql
-- 연락처 + 전화번호
SELECT
    p.First || ' ' || COALESCE(p.Last, '') AS name,
    mv.value AS phone,
    datetime(p.CreationDate + 978307200, 'unixepoch') AS created_at
FROM ABPerson p
JOIN ABMultiValue mv ON p.ROWID = mv.record_id
WHERE mv.property = 3   -- 3 = 전화번호
ORDER BY p.CreationDate DESC;
```

### Health 데이터

```
백업 내: HomeDomain/Library/Health/healthdb.sqlite
         HomeDomain/Library/Health/healthdb_secure.sqlite

포함 데이터:
- 걸음 수, 심박수, 혈압
- 수면 패턴
- 운동 기록 (경로 포함)
- 생리 주기
- 위치 기반 데이터 (운동 시)

-- 심박수 기록
SELECT
    quantity_samples.value,
    datetime(quantity_samples.start_date + 978307200, 'unixepoch') AS measured_at
FROM quantity_samples
JOIN data_provenances ON quantity_samples.data_provenance_id = data_provenances.ROWID
WHERE quantity_samples.data_type = 5  -- 5 = 심박수
ORDER BY quantity_samples.start_date DESC;
```

### 위치 데이터

```
백업 내:
- HomeDomain/Library/Caches/com.apple.routined/
  └── Local.sqlite           # 빈번 방문 위치 (Significant Locations)
- AppDomain-com.apple.Maps/Library/Maps/
  └── GeoHistory.mapsdata    # 지도 검색/경로 기록

탈옥 기기 직접 접근:
/private/var/mobile/Library/Caches/com.apple.routined/
/private/var/mobile/Library/CoreLocation/
```

### Notes

```
백업 내: AppDomain-com.apple.mobilenotes/Library/Notes/
         HomeDomain/Library/Notes/

SQLite Core Data 형식
테이블: ZICNOTEDATA, ZNOTE, ZICATTACHMENT

-- 메모 내용 추출 (암호화 안 된 경우)
SELECT ZTITLE, ZSNIPPET, datetime(ZCREATIONDATE + 978307200, 'unixepoch') AS created
FROM ZNOTE
ORDER BY ZCREATIONDATE DESC;
```

---

## 5. Python iOS 백업 복호화/파싱 스크립트

```python
#!/usr/bin/env python3
"""
iOS iTunes 백업 파싱 및 포렌식 분석 도구

암호화된 백업 복호화 및 아티팩트 추출
의존성: pip install cryptography pycryptodome

사용법:
    # 비암호화 백업 분석
    python3 ios_backup_parser.py -b ~/Library/Application\ Support/MobileSync/Backup/<UDID> -o ./output

    # 암호화 백업 복호화
    python3 ios_backup_parser.py -b <backup_dir> -o ./output -p <password>

    # 특정 아티팩트만 추출
    python3 ios_backup_parser.py -b <backup_dir> -o ./output --extract-sms --extract-calls
"""

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import sqlite3
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# 암호화 관련 (선택적 의존성)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


MAC_EPOCH_OFFSET = 978307200  # 2001-01-01 00:00:00 UTC → Unix epoch 오프셋


@dataclass
class BackupFile:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    file_metadata: bytes


@dataclass
class SmsMessage:
    rowid: int
    sender: str
    timestamp: datetime
    text: str
    is_from_me: bool
    service: str


@dataclass
class CallRecord:
    address: str
    duration: float
    date: datetime
    originated: bool
    call_type: int


@dataclass
class Contact:
    name: str
    phones: list[str]
    emails: list[str]
    created_at: Optional[datetime]


def mac_ts_to_datetime(mac_ts: float) -> datetime:
    """Mac Absolute Time을 datetime으로 변환"""
    try:
        unix_ts = mac_ts + MAC_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return datetime.fromtimestamp(0, tz=timezone.utc)


def load_manifest_db(backup_dir: Path) -> list[BackupFile]:
    """Manifest.db에서 파일 목록 로드"""
    manifest_path = backup_dir / "Manifest.db"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest.db를 찾을 수 없습니다: {manifest_path}")

    files: list[BackupFile] = []
    conn = sqlite3.connect(str(manifest_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute("SELECT fileID, domain, relativePath, flags, file FROM Files")
        for row in cur.fetchall():
            files.append(BackupFile(
                file_id=row["fileID"] or "",
                domain=row["domain"] or "",
                relative_path=row["relativePath"] or "",
                flags=row["flags"] or 0,
                file_metadata=row["file"] or b"",
            ))
    finally:
        conn.close()

    return files


def load_backup_info(backup_dir: Path) -> dict:
    """Info.plist에서 기기 정보 로드"""
    info_path = backup_dir / "Info.plist"
    if not info_path.exists():
        return {}

    with open(info_path, "rb") as f:
        return plistlib.load(f)


def get_backup_file_path(backup_dir: Path, file_id: str) -> Path:
    """fileID로 실제 파일 경로 계산"""
    return backup_dir / file_id[:2] / file_id


def find_file_by_domain_path(
    files: list[BackupFile],
    domain: str,
    relative_path: str,
) -> Optional[BackupFile]:
    """도메인과 상대 경로로 파일 검색"""
    for f in files:
        if f.domain == domain and f.relative_path == relative_path:
            return f
    return None


def find_files_by_domain(
    files: list[BackupFile],
    domain_prefix: str,
) -> list[BackupFile]:
    """도메인 접두사로 파일 목록 검색"""
    return [f for f in files if f.domain.startswith(domain_prefix)]


def copy_file_from_backup(
    backup_dir: Path,
    backup_file: BackupFile,
    output_path: Path,
) -> bool:
    """백업에서 파일을 출력 경로로 복사"""
    src = get_backup_file_path(backup_dir, backup_file.file_id)
    if not src.exists():
        return False

    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(output_path))
    return True


def extract_sms(backup_dir: Path, output_dir: Path, files: list[BackupFile]) -> list[SmsMessage]:
    """iMessage/SMS 추출"""
    messages: list[SmsMessage] = []

    sms_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/SMS/sms.db"
    )
    if not sms_file:
        print("  [경고] sms.db를 찾을 수 없습니다.", file=sys.stderr)
        return messages

    sms_db_path = output_dir / "sms.db"
    if not copy_file_from_backup(backup_dir, sms_file, sms_db_path):
        print("  [경고] sms.db 복사 실패.", file=sys.stderr)
        return messages

    try:
        conn = sqlite3.connect(str(sms_db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT
                m.rowid,
                COALESCE(h.id, 'me') AS sender,
                m.date,
                m.text,
                m.is_from_me,
                m.service
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.rowid
            WHERE m.text IS NOT NULL
            ORDER BY m.date DESC
            LIMIT 5000
        """)

        for row in cur.fetchall():
            # iOS 11+: date 단위가 나노초 (>= 1e16)
            # iOS 10 이하: Mac Absolute Time (초)
            raw_date = row["date"]
            if raw_date and raw_date > 1_000_000_000_000:
                ts = mac_ts_to_datetime(raw_date / 1_000_000_000)
            else:
                ts = mac_ts_to_datetime(raw_date or 0)

            messages.append(SmsMessage(
                rowid=row["rowid"],
                sender=row["sender"] or "",
                timestamp=ts,
                text=row["text"] or "",
                is_from_me=bool(row["is_from_me"]),
                service=row["service"] or "unknown",
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [오류] SMS 분석 실패: {e}", file=sys.stderr)

    return messages


def extract_call_history(
    backup_dir: Path,
    output_dir: Path,
    files: list[BackupFile],
) -> list[CallRecord]:
    """통화 기록 추출"""
    records: list[CallRecord] = []

    call_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/CallHistory/CallHistory.storedata"
    )
    if not call_file:
        print("  [경고] CallHistory.storedata를 찾을 수 없습니다.", file=sys.stderr)
        return records

    call_db_path = output_dir / "CallHistory.db"
    if not copy_file_from_backup(backup_dir, call_file, call_db_path):
        return records

    try:
        conn = sqlite3.connect(str(call_db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT ZADDRESS, ZDURATION, ZDATE, ZORIGINATED, ZCALLTYPE
            FROM ZCALLRECORD
            ORDER BY ZDATE DESC
            LIMIT 1000
        """)

        for row in cur.fetchall():
            records.append(CallRecord(
                address=row["ZADDRESS"] or "알 수 없음",
                duration=float(row["ZDURATION"] or 0),
                date=mac_ts_to_datetime(row["ZDATE"] or 0),
                originated=bool(row["ZORIGINATED"]),
                call_type=row["ZCALLTYPE"] or 0,
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [오류] 통화 기록 분석 실패: {e}", file=sys.stderr)

    return records


def extract_contacts(
    backup_dir: Path,
    output_dir: Path,
    files: list[BackupFile],
) -> list[Contact]:
    """연락처 추출"""
    contacts: list[Contact] = []

    ab_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"
    )
    if not ab_file:
        print("  [경고] AddressBook.sqlitedb를 찾을 수 없습니다.", file=sys.stderr)
        return contacts

    ab_path = output_dir / "AddressBook.db"
    if not copy_file_from_backup(backup_dir, ab_file, ab_path):
        return contacts

    try:
        conn = sqlite3.connect(str(ab_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT ROWID, First, Last, CreationDate
            FROM ABPerson
            ORDER BY CreationDate DESC
        """)
        persons = cur.fetchall()

        for person in persons:
            name_parts = [
                p for p in [person["First"], person["Last"]]
                if p
            ]
            name = " ".join(name_parts) if name_parts else "(이름 없음)"

            phones: list[str] = []
            emails: list[str] = []

            try:
                cur.execute("""
                    SELECT value, property FROM ABMultiValue
                    WHERE record_id = ?
                      AND property IN (3, 4)  -- 3=전화, 4=이메일
                """, (person["ROWID"],))

                for row in cur.fetchall():
                    if row["property"] == 3:
                        phones.append(row["value"] or "")
                    else:
                        emails.append(row["value"] or "")
            except sqlite3.DatabaseError:
                pass

            contacts.append(Contact(
                name=name,
                phones=phones,
                emails=emails,
                created_at=mac_ts_to_datetime(person["CreationDate"] or 0),
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [오류] 연락처 분석 실패: {e}", file=sys.stderr)

    return contacts


def extract_safari_history(
    backup_dir: Path,
    output_dir: Path,
    files: list[BackupFile],
) -> list[dict]:
    """Safari 브라우저 기록 추출"""
    history: list[dict] = []

    history_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/Safari/History.db"
    )
    if not history_file:
        print("  [경고] Safari History.db를 찾을 수 없습니다.", file=sys.stderr)
        return history

    hist_path = output_dir / "SafariHistory.db"
    if not copy_file_from_backup(backup_dir, history_file, hist_path):
        return history

    try:
        conn = sqlite3.connect(str(hist_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT hi.url, hv.title, hv.visit_time
            FROM history_visits hv
            JOIN history_items hi ON hv.history_item = hi.id
            ORDER BY hv.visit_time DESC
            LIMIT 2000
        """)

        for row in cur.fetchall():
            history.append({
                "url": row["url"],
                "title": row["title"] or "",
                "visited_at": mac_ts_to_datetime(row["visit_time"] or 0).isoformat(),
            })

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [오류] Safari 기록 분석 실패: {e}", file=sys.stderr)

    return history


def generate_forensics_report(
    backup_dir: Path,
    output_dir: Path,
    device_info: dict,
    sms_list: list[SmsMessage],
    calls: list[CallRecord],
    contacts: list[Contact],
    browser_history: list[dict],
) -> None:
    """포렌식 보고서 생성"""
    report = {
        "분석_시간": datetime.now(tz=timezone.utc).isoformat(),
        "백업_경로": str(backup_dir),
        "기기_정보": {
            "모델": device_info.get("Product Type", ""),
            "이름": device_info.get("Device Name", ""),
            "iOS_버전": device_info.get("Product Version", ""),
            "IMEI": device_info.get("IMEI", ""),
            "전화번호": device_info.get("Phone Number", ""),
            "시리얼": device_info.get("Serial Number", ""),
            "마지막_백업": str(device_info.get("Last Backup Date", "")),
        },
        "메시지_분석": {
            "총_건수": len(sms_list),
            "iMessage": sum(1 for m in sms_list if m.service == "iMessage"),
            "SMS": sum(1 for m in sms_list if m.service == "SMS"),
            "수신": sum(1 for m in sms_list if not m.is_from_me),
            "발신": sum(1 for m in sms_list if m.is_from_me),
            "최근_메시지": [
                {
                    "발신자": m.sender,
                    "시간": m.timestamp.isoformat(),
                    "서비스": m.service,
                    "방향": "발신" if m.is_from_me else "수신",
                    "내용_미리보기": m.text[:100],
                }
                for m in sms_list[:30]
            ],
        },
        "통화_기록": {
            "총_건수": len(calls),
            "발신": sum(1 for c in calls if c.originated),
            "수신": sum(1 for c in calls if not c.originated),
            "최근_통화": [
                {
                    "번호": c.address,
                    "시간": c.date.isoformat(),
                    "통화_시간_초": int(c.duration),
                    "방향": "발신" if c.originated else "수신",
                    "유형": {0: "전화", 1: "FaceTime Audio", 8: "FaceTime Video"}.get(c.call_type, "기타"),
                }
                for c in calls[:30]
            ],
        },
        "연락처": {
            "총_건수": len(contacts),
            "목록": [
                {"이름": c.name, "전화": c.phones, "이메일": c.emails}
                for c in contacts[:50]
            ],
        },
        "브라우저_기록": {
            "총_건수": len(browser_history),
            "최근": browser_history[:30],
        },
    }

    json_path = output_dir / "ios_forensics_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    txt_path = output_dir / "ios_forensics_report.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("iOS 포렌식 분석 보고서\n")
        f.write("=" * 60 + "\n\n")

        gi = report["기기_정보"]
        f.write(f"기기 모델:    {gi['모델']}\n")
        f.write(f"기기 이름:    {gi['이름']}\n")
        f.write(f"iOS 버전:     {gi['iOS_버전']}\n")
        f.write(f"IMEI:         {gi['IMEI']}\n")
        f.write(f"전화번호:     {gi['전화번호']}\n")
        f.write(f"시리얼번호:   {gi['시리얼']}\n")
        f.write(f"마지막 백업:  {gi['마지막_백업']}\n\n")

        f.write(f"[iMessage/SMS] 총 {len(sms_list)}건\n")
        for msg in sms_list[:20]:
            direction = "→" if msg.is_from_me else "←"
            f.write(
                f"  {direction} [{msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')}]"
                f" {msg.sender} ({msg.service})\n"
            )
            f.write(f"     {msg.text[:80]}\n\n")

        f.write(f"[통화 기록] 총 {len(calls)}건\n")
        for call in calls[:20]:
            direction = "발신" if call.originated else "수신"
            f.write(
                f"  [{call.date.strftime('%Y-%m-%d %H:%M:%S')}]"
                f" {direction} | {call.address}"
                f" | {int(call.duration)}초\n"
            )

        f.write(f"\n[연락처] 총 {len(contacts)}명\n")
        for contact in contacts[:20]:
            f.write(f"  {contact.name}: {', '.join(contact.phones)}\n")

    print(f"  JSON: {json_path}")
    print(f"  TXT:  {txt_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="iOS iTunes 백업 포렌식 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s -b ~/MobileSync/Backup/<UDID> -o ./output
  %(prog)s -b ./backup -o ./output --extract-sms --extract-calls
  %(prog)s -b ./backup -o ./output --all
        """,
    )
    parser.add_argument("-b", "--backup", required=True, help="iTunes 백업 디렉토리 경로")
    parser.add_argument("-o", "--output", required=True, help="출력 디렉토리 경로")
    parser.add_argument("-p", "--password", help="암호화 백업 비밀번호")
    parser.add_argument("--extract-sms", action="store_true", help="iMessage/SMS 추출")
    parser.add_argument("--extract-calls", action="store_true", help="통화 기록 추출")
    parser.add_argument("--extract-contacts", action="store_true", help="연락처 추출")
    parser.add_argument("--extract-safari", action="store_true", help="Safari 기록 추출")
    parser.add_argument("--all", action="store_true", help="모든 아티팩트 추출")

    args = parser.parse_args()

    if args.all:
        args.extract_sms = True
        args.extract_calls = True
        args.extract_contacts = True
        args.extract_safari = True

    backup_dir = Path(args.backup)
    output_dir = Path(args.output)

    if not backup_dir.exists():
        print(f"[오류] 백업 디렉토리를 찾을 수 없습니다: {backup_dir}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)

    print(f"[*] iOS 백업 파싱 중: {backup_dir}")
    device_info = load_backup_info(backup_dir)
    if device_info:
        print(f"    기기: {device_info.get('Product Type', 'N/A')}")
        print(f"    iOS:  {device_info.get('Product Version', 'N/A')}")
        print(f"    IMEI: {device_info.get('IMEI', 'N/A')}")

    print("[*] Manifest.db 로딩 중...")
    try:
        files = load_manifest_db(backup_dir)
        print(f"    파일 수: {len(files):,}개")
    except FileNotFoundError as e:
        print(f"[오류] {e}", file=sys.stderr)
        return 1

    sms_list: list[SmsMessage] = []
    calls: list[CallRecord] = []
    contacts: list[Contact] = []
    browser_history: list[dict] = []

    if args.extract_sms:
        print("[*] iMessage/SMS 추출 중...")
        sms_list = extract_sms(backup_dir, artifacts_dir, files)
        print(f"    추출: {len(sms_list)}건")

    if args.extract_calls:
        print("[*] 통화 기록 추출 중...")
        calls = extract_call_history(backup_dir, artifacts_dir, files)
        print(f"    추출: {len(calls)}건")

    if args.extract_contacts:
        print("[*] 연락처 추출 중...")
        contacts = extract_contacts(backup_dir, artifacts_dir, files)
        print(f"    추출: {len(contacts)}명")

    if args.extract_safari:
        print("[*] Safari 기록 추출 중...")
        browser_history = extract_safari_history(backup_dir, artifacts_dir, files)
        print(f"    추출: {len(browser_history)}건")

    print("[*] 포렌식 보고서 생성 중...")
    generate_forensics_report(
        backup_dir, output_dir, device_info,
        sms_list, calls, contacts, browser_history,
    )

    print(f"\n[완료] 결과 저장 위치: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. GrayKey / Cellebrite 방식 개요

### GrayKey (Grayshift)

**개요**
- 미국 Grayshift 사가 개발한 iOS 잠금 해제 장비
- 주요 고객: 미국 FBI, DEA, 지방 경찰서
- 2018년경 출시, 현재 최신 iOS에도 지속 업데이트

**작동 방식 (알려진 정보)**
1. iOS 취약점(Zero-Day 또는 N-Day)을 활용한 부트롬 또는 소프트웨어 익스플로잇
2. 핀코드/비밀번호 브루트포스 제한 우회
3. SEP(Secure Enclave Processor) 제한 우회 시도
4. After First Unlock(AFU) 상태에서 더 많은 데이터 접근 가능

**제한 사항**
- USB Restricted Mode (iPhone X+, iOS 11.4.1+): USB 연결 1시간 후 데이터 전송 차단
- A17 Pro / M 시리즈 칩: 접근 매우 어려움
- USB Restricted Mode 우회: 비공개 취약점 활용 (Graykey 일부 기기 지원)

**대응 방법 (포렌식 대상자 입장에서의 방어)**
```
# 기기 끄기 (Before First Unlock 상태로)
# USB Restricted Mode 활성화 확인
설정 → Face ID/Touch ID 및 암호 → USB 액세서리 → 비활성화

# 강력한 비밀번호 사용
설정 → 암호 → 맞춤 영숫자 코드 (8자리 이상 권장)
```

### Cellebrite UFED

**UFED (Universal Forensic Extraction Device)**
- 이스라엘 Cellebrite 사 제품
- 전 세계 150개국 이상 법집행 기관 사용
- iOS + Android + 피처폰 지원

**추출 방식 계층**

```
1. 논리적 추출 (Logical)
   - 백업 파일을 통한 접근
   - iCloud 백업 파싱
   - 가장 쉽고 안전, 데이터 제한적

2. 고급 논리적 추출 (Advanced Logical)
   - 탈옥 없이 Cellebrite 에이전트 설치
   - 더 많은 파일시스템 접근

3. 파일시스템 추출 (File System)
   - 전체 /private/var 접근
   - 일부 삭제 파일 복구 가능
   - 탈옥 또는 취약점 필요

4. 물리적 추출 (Physical)
   - 낸드 플래시 raw 덤프
   - JTAG 또는 Chip-off
   - 구형 기기에 주로 적용
```

**UFED 결과물**
```
UFED_<DeviceID>.ufd          # 추출 메타데이터
<device>_<date>/
├── Extraction.xml            # 추출 정보
├── FileSystem/               # 파일시스템 이미지
├── databases/                # 파싱된 DB
└── UFED_PA_Report.pdf        # 자동 생성 보고서
```

### MVT (Mobile Verification Toolkit)

**개발 배경**
- Amnesty International 개발
- Pegasus 스파이웨어 탐지 목적
- iOS/Android 모두 지원

```bash
# MVT 설치
pip install mvt

# iOS 백업 분석 (STIX2 IOC 사용)
mvt-ios check-backup \
    --iocs ~/iocs/pegasus.stix2 \
    --output ./mvt_output \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

# 암호화 백업
mvt-ios decrypt-backup \
    --password <password> \
    --destination ./decrypted_backup \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

mvt-ios check-backup \
    --iocs ~/iocs/pegasus.stix2 \
    --output ./mvt_output \
    ./decrypted_backup

# 탈옥 기기 직접 분석
mvt-ios check-fs \
    --iocs ~/iocs/pegasus.stix2 \
    --output ./mvt_output \
    /

# IOC 다운로드
wget https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2
```

**Pegasus 탐지 지표**
```
- 비정상적인 프로세스 충돌 (crash 로그)
- 알 수 없는 네트워크 연결
- DataUsage.sqlite의 비정상 프로세스
- process_info.plist의 비정상 실행 흔적
- 특정 도메인 DNS 조회 기록
```

---

## 실전 iOS 포렌식 체크리스트

```
사전 준비:
□ 기기 전원 상태 유지 (재시작 금지 → BFU 전환 방지)
□ 기기를 비행기 모드로 전환 (원격 삭제 방지)
□ USB Restricted Mode 상태 확인
□ 기기 잠금 상태 확인 (BFU vs AFU)

수집:
□ Info.plist 저장 (기기 식별 정보)
□ Manifest.db 저장 (파일 목록)
□ 백업 전체 해시 계산
□ 아티팩트 순서대로 추출

분석:
□ iMessage/SMS 추출 및 타임라인 재구성
□ 통화 기록 분석
□ 위치 데이터 지도 시각화
□ Safari/Chrome 기록 분석
□ 앱 데이터 (카카오톡, WhatsApp 등)
□ 사진 EXIF 메타데이터 분석
□ 삭제 파일 복구 시도
□ 클라우드 동기화 상태 확인
```

---

<!-- detect-validate-47 -->
## 안티포렌식 탐지와 iOS 증거 검증

iOS 포렌식은 *파일시스템·iTunes/iCloud 백업·아티팩트·키체인*에서 증거를 복원한다. 분석자는 *탈옥 은폐·백업 암호화·아티팩트 정리* 같은 안티포렌식을 의식하고 **백업이 복호·무결하고 교차 일치하는가**를 검증해야 한다. 검증은 **소유 기기/백업**에서만.

### 안티포렌식 기법 → 노리는 포렌식 단계 → 분석자 대응 → 관찰 신호

| 기법 | 노리는 단계 | 분석자 대응 | 관찰 신호 |
|---|---|---|---|
| 탈옥 은폐 | 무결성 가정 | Cydia/탈옥 흔적 교차 | /Applications 비표준 |
| 백업 암호화 | 접근 차단 | 패스워드/키 복원 | Manifest.plist 암호 플래그 |
| 아티팩트 정리 | 단일 소스 의존 | WAL·KnowledgeC 교차 | 삭제 행 잔존 |
| 시각 조작 | 타임라인 신뢰 | 다중 DB 교차 | ts↔Mft 불일치 |

### 증거 검증 (직접 확인)

```bash
# 1) 소유 백업 무결성/암호화 상태 — Manifest로 암호화 여부·파일수 교차(증거 일관성)
plutil -p Manifest.plist 2>/dev/null | grep -iE 'IsEncrypted|Date'; ls Manifest.db && echo "manifest present"
# 2) iOS DB 삭제 행이 WAL에 잔존하는지(안티포렌식 우회) — 본 DB엔 없는데 -wal에 존재
sqlite3 sms.db 'PRAGMA journal_mode;' 2>/dev/null; strings sms.db-wal 2>/dev/null | grep -iE 'http|message' | head
```

> iOS 증거 검증은 *백업이 복호·무결·교차일치하는가*다 — "백업을 열었다"와 "탈옥 흔적이 교차되고 삭제 행이 WAL과 일치한다"는 다르다. 소유 기기/백업에서 직접 확인한다([[07_Digital_Forensics]], [[28_Mobile_Hacking]], [[44_Incident_Response_DFIR]]).

**최신 기법·통제 (2025–2026):**
- iOS 데이터보호·Secure Enclave로 물리획득 제약 — 논리/백업 기반 분석. 검증: 획득 무결성·해시가 기록되는가([[44_Incident_Response_DFIR]])
- 클라우드 백업 상관 — 합법성 통제

---

<a name="english"></a>

# iOS Forensics

## Table of Contents
1. iOS Filesystem Structure
2. iTunes Backup Structure Analysis
3. iCloud Backup vs Local Backup Differences
4. iOS Artifact Locations
5. Python iOS Backup Decryption/Parsing Script
6. GrayKey/Cellebrite Methods Overview

---

## 1. iOS Filesystem Structure

### Partition Structure

iOS devices consist of two primary partitions.

```
/dev/disk0s1    →  /           (System partition, read-only, ~7-10GB)
/dev/disk0s2    →  /private/var (Data partition, read/write, remaining capacity)
```

**System Partition (Read-Only)**
```
/bin/           - Basic binaries
/sbin/          - System binaries
/lib/           - Shared libraries
/usr/           - User utilities
/System/        - iOS frameworks
/Applications/  - Default apps (Phone, Safari, Messages, etc.)
/private/etc/   - System configuration
```

**Data Partition (/private/var)**
```
/private/var/
├── mobile/                  # Default user home directory
│   ├── Applications/        # iOS 7 and below: app data
│   ├── Containers/          # iOS 8+: app data
│   │   ├── Bundle/          # App binaries (UUID-based)
│   │   └── Data/            # App data (UUID-based)
│   │       └── Application/
│   │           └── <UUID>/
│   │               ├── Documents/
│   │               ├── Library/
│   │               │   ├── Caches/
│   │               │   └── Preferences/
│   │               └── tmp/
│   ├── Library/             # User library
│   │   ├── AddressBook/     # Contacts
│   │   ├── SMS/             # Text messages
│   │   ├── CallHistory/     # Call history
│   │   ├── Safari/          # Browser data
│   │   ├── Mail/            # Email
│   │   ├── Notes/           # Notes
│   │   ├── Health/          # Health data
│   │   ├── Voicemail/       # Voicemail
│   │   ├── Maps/            # Maps/location
│   │   └── Calendars/       # Calendar
│   └── Media/               # User media
│       ├── DCIM/            # Photos/videos
│       ├── PhotoData/       # Photo metadata
│       └── iTunes_Control/  # iTunes sync
└── root/                    # Root user (jailbroken devices)
```

### HFS+ vs APFS

**HFS+ (Mac OS Extended)**
- Used on iOS 10.2 and below
- Timestamps: Mac Absolute Time (epoch: January 1, 2001)
- Journaling support

**APFS (Apple File System)**
- Used on iOS 10.3+
- Snapshot support → allows recovery of pre-deletion state
- Space sharing, Copy-on-Write
- Encryption: per-file individual encryption keys
- Timestamps: nanosecond precision

```bash
# Check filesystem on a jailbroken device
ideviceinfo | grep FSType

# Access via SSH (jailbroken device)
ssh root@<device_ip>
mount | grep /dev/disk
df -h

# Dump filesystem info
diskutil list  # when connected on Mac
```

### Timestamp Conversion

```python
from datetime import datetime, timezone

# Mac Absolute Time → Unix time
# Mac Absolute Time: seconds since 2001-01-01 00:00:00 UTC
MAC_EPOCH_OFFSET = 978307200  # in seconds

def mac_absolute_to_datetime(mac_ts: float) -> datetime:
    unix_ts = mac_ts + MAC_EPOCH_OFFSET
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc)

# Example
ts = mac_absolute_to_datetime(699123456)
print(ts.strftime("%Y-%m-%d %H:%M:%S %Z"))

# Nanosecond timestamp (APFS)
def apfs_timestamp_to_datetime(ns_ts: int) -> datetime:
    unix_ts = ns_ts / 1_000_000_000
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
```

---

## 2. iTunes Backup Structure Analysis

### Backup Storage Locations

```
# macOS
~/Library/Application Support/MobileSync/Backup/<UDID>/

# Windows
%APPDATA%\Apple Computer\MobileSync\Backup\<UDID>\
or
%USERPROFILE%\Apple\MobileSync\Backup\<UDID>\
```

### Backup File Structure

```
<UDID>/
├── Manifest.db          # Full file list (SQLite)
├── Manifest.plist       # Backup metadata (encryption status, iOS version, etc.)
├── Info.plist           # Device information (model, IMEI, phone number, etc.)
├── Status.plist         # Backup status
└── <xx>/                # File data (directory separated by first 2 chars of hash)
    └── <40-char SHA1 hash>  # Actual file data (no extension)
```

### Manifest.db Analysis

```sql
-- Manifest.db table structure
-- Files table: list of backed-up files
SELECT fileID, domain, relativePath, flags, file
FROM Files
LIMIT 10;

-- domain: app/data domain classification
-- HomeDomain: files under /var/mobile/Library/
-- AppDomain: app data
-- MediaDomain: media files
-- DatabaseDomain: databases
-- WirelessDomain: Wi-Fi settings

-- Search for specific files
SELECT fileID, relativePath
FROM Files
WHERE relativePath LIKE '%SMS%';

-- List of app domains
SELECT DISTINCT domain FROM Files ORDER BY domain;
```

```bash
# Extract specific files from backup (Python recommended)
sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE '%sms%'"

# Find file by fileID (first 2 chars are the directory name)
# fileID = "abc123..." → ./ab/abc123...
```

### Info.plist Analysis

```bash
# Read plist file (macOS)
plutil -p Info.plist

# Linux (using libplist)
apt install libplist-utils
plistutil -i Info.plist -o Info.xml
cat Info.xml
```

**Info.plist Key Fields**
```xml
<key>Build Version</key>          <!-- iOS build version -->
<key>Device Name</key>            <!-- Device name -->
<key>GUID</key>                   <!-- Device unique ID -->
<key>IMEI</key>                   <!-- IMEI number -->
<key>Last Backup Date</key>       <!-- Last backup time -->
<key>Phone Number</key>           <!-- Phone number -->
<key>Product Type</key>           <!-- iPhone model (e.g., iPhone14,2) -->
<key>Serial Number</key>          <!-- Serial number -->
```

---

## 3. iCloud Backup vs Local Backup Differences

### Comparison Table

| Item | Local Backup (iTunes/Finder) | iCloud Backup |
|------|------------------------------|---------------|
| Storage location | Local computer | Apple servers |
| Encryption | Optional (password) | Encrypted by default |
| Included data | Nearly all data | Some excluded (iCloud-synced data) |
| Legal access | Device or computer seizure | Court warrant required |
| Access method | Manifest.db analysis | Apple law enforcement request or account credentials |
| Forensic convenience | High (direct access) | Low (requires Apple cooperation) |
| iTunes backup encryption | Some data excluded without password | Not applicable |

### Checking Local Backup Encryption Status

```bash
# Check encryption status in Manifest.plist
python3 -c "
import plistlib
with open('Manifest.plist', 'rb') as f:
    data = plistlib.load(f)
print('Encrypted:', data.get('IsEncrypted', False))
print('Backup date:', data.get('Date'))
"
```

### iCloud Backup Data Requests (Law Enforcement)

```
Apple Law Enforcement Request Process:
1. Obtain a court warrant from the relevant jurisdiction
2. Submit to https://www.apple.com/legal/privacy/law-enforcement-guidelines-us.pdf
3. Apple extracts and provides iCloud data

Data included in iCloud backups:
- SMS/iMessage (when iCloud Messages is disabled)
- App data
- Device settings
- Photos (when iCloud Photos is not used)
- Call history
- Safari history
- Contacts, calendars, notes
```

### Apple Transparency Report

```
https://www.apple.com/legal/transparency/

Law enforcement request status:
- Apple publishes request counts by country on a semi-annual basis
- Distinguishes between account information requests and device information requests
- Compliance Rate is disclosed
```

---

## 4. iOS Artifact Locations

### iMessage / SMS

```
In backup: HomeDomain/Library/SMS/sms.db

Tables:
- message          : Message content
- chat             : Conversation list
- chat_message_join: Conversation-message join
- handle           : Sender/recipient information
- attachment       : Attachments
```

```sql
-- Full iMessage/SMS query
SELECT
    m.rowid,
    h.id AS sender,
    datetime(m.date/1000000000 + 978307200, 'unixepoch', 'localtime') AS timestamp,
    m.text,
    m.is_from_me,
    m.service    -- 'SMS' or 'iMessage'
FROM message m
LEFT JOIN handle h ON m.handle_id = h.rowid
ORDER BY m.date DESC;

-- Messages with attachments
SELECT m.text, a.filename, a.mime_type
FROM message m
JOIN message_attachment_join maj ON m.rowid = maj.message_id
JOIN attachment a ON maj.attachment_id = a.rowid;

-- Deleted messages (residual data such as cache_has_attachments)
SELECT * FROM message WHERE text IS NULL AND cache_has_attachments = 1;
```

### Safari Browser

```
In backup:
- HomeDomain/Library/Safari/History.db         # Browsing history
- HomeDomain/Library/Safari/Bookmarks.db       # Bookmarks
- HomeDomain/Library/Safari/BrowserState.db    # Tab state
- HomeDomain/Library/Cookies/Cookies.binarycookies  # Cookies (binary)
- HomeDomain/Library/Safari/Downloads.plist    # Download history
```

```sql
-- Safari browsing history
SELECT
    hi.url,
    hv.title,
    datetime(hv.visit_time + 978307200, 'unixepoch', 'localtime') AS visited_at
FROM history_visits hv
JOIN history_items hi ON hv.history_item = hi.id
ORDER BY hv.visit_time DESC;
```

```python
# Parse Safari cookies (Binary Cookies format)
import struct

def parse_binarycookies(filepath: str) -> list[dict]:
    """Parse Safari Binary Cookies file"""
    cookies: list[dict] = []

    with open(filepath, "rb") as f:
        magic = f.read(4)
        if magic != b"cook":
            raise ValueError("Invalid Binary Cookies file")

        num_pages = struct.unpack(">I", f.read(4))[0]
        page_sizes = [struct.unpack(">I", f.read(4))[0] for _ in range(num_pages)]

        for page_size in page_sizes:
            page_data = f.read(page_size)
            # Parse cookies within page (simplified)
            page_header = struct.unpack("<I", page_data[:4])[0]
            num_cookies = struct.unpack("<I", page_data[4:8])[0]

            for i in range(num_cookies):
                offset = struct.unpack("<I", page_data[8 + i * 4:12 + i * 4])[0]
                cookies.append({"raw_offset": offset, "page_header": page_header})

    return cookies
```

### Call History

```
In backup: HomeDomain/Library/CallHistory/CallHistory.storedata

NSPersistentStore (Core Data) format → can be opened as SQLite

SELECT
    ZADDRESS,
    ZDURATION,
    ZDATE,
    ZORIGINATED,  -- 0=incoming, 1=outgoing
    ZCALLTYPE     -- 0=phone call, 1=FaceTime Audio, 8=FaceTime Video
FROM ZCALLRECORD
ORDER BY ZDATE DESC;

-- Timestamps: Core Data (Mac Absolute Time)
SELECT
    ZADDRESS,
    datetime(ZDATE + 978307200, 'unixepoch', 'localtime') AS call_time,
    CAST(ZDURATION AS INT) || ' seconds' AS duration
FROM ZCALLRECORD;
```

### Contacts

```
In backup: HomeDomain/Library/AddressBook/AddressBook.sqlitedb

Tables:
- ABPerson            : Basic contact information
- ABMultiValue        : Phone numbers, emails, URLs, etc.
- ABMultiValueEntry   : Multi-value entries
```

```sql
-- Contacts + phone numbers
SELECT
    p.First || ' ' || COALESCE(p.Last, '') AS name,
    mv.value AS phone,
    datetime(p.CreationDate + 978307200, 'unixepoch') AS created_at
FROM ABPerson p
JOIN ABMultiValue mv ON p.ROWID = mv.record_id
WHERE mv.property = 3   -- 3 = phone number
ORDER BY p.CreationDate DESC;
```

### Health Data

```
In backup: HomeDomain/Library/Health/healthdb.sqlite
           HomeDomain/Library/Health/healthdb_secure.sqlite

Included data:
- Step count, heart rate, blood pressure
- Sleep patterns
- Exercise records (including routes)
- Menstrual cycle
- Location-based data (during exercise)

-- Heart rate records
SELECT
    quantity_samples.value,
    datetime(quantity_samples.start_date + 978307200, 'unixepoch') AS measured_at
FROM quantity_samples
JOIN data_provenances ON quantity_samples.data_provenance_id = data_provenances.ROWID
WHERE quantity_samples.data_type = 5  -- 5 = heart rate
ORDER BY quantity_samples.start_date DESC;
```

### Location Data

```
In backup:
- HomeDomain/Library/Caches/com.apple.routined/
  └── Local.sqlite           # Frequently visited locations (Significant Locations)
- AppDomain-com.apple.Maps/Library/Maps/
  └── GeoHistory.mapsdata    # Map search/route history

Direct access on jailbroken device:
/private/var/mobile/Library/Caches/com.apple.routined/
/private/var/mobile/Library/CoreLocation/
```

### Notes

```
In backup: AppDomain-com.apple.mobilenotes/Library/Notes/
           HomeDomain/Library/Notes/

SQLite Core Data format
Tables: ZICNOTEDATA, ZNOTE, ZICATTACHMENT

-- Extract note content (when not encrypted)
SELECT ZTITLE, ZSNIPPET, datetime(ZCREATIONDATE + 978307200, 'unixepoch') AS created
FROM ZNOTE
ORDER BY ZCREATIONDATE DESC;
```

---

## 5. Python iOS Backup Decryption/Parsing Script

```python
#!/usr/bin/env python3
"""
iOS iTunes Backup Parsing and Forensic Analysis Tool

Decrypt encrypted backups and extract artifacts
Dependencies: pip install cryptography pycryptodome

Usage:
    # Analyze unencrypted backup
    python3 ios_backup_parser.py -b ~/Library/Application\ Support/MobileSync/Backup/<UDID> -o ./output

    # Decrypt encrypted backup
    python3 ios_backup_parser.py -b <backup_dir> -o ./output -p <password>

    # Extract specific artifacts only
    python3 ios_backup_parser.py -b <backup_dir> -o ./output --extract-sms --extract-calls
"""

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import sqlite3
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Encryption-related (optional dependency)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


MAC_EPOCH_OFFSET = 978307200  # 2001-01-01 00:00:00 UTC → Unix epoch offset


@dataclass
class BackupFile:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    file_metadata: bytes


@dataclass
class SmsMessage:
    rowid: int
    sender: str
    timestamp: datetime
    text: str
    is_from_me: bool
    service: str


@dataclass
class CallRecord:
    address: str
    duration: float
    date: datetime
    originated: bool
    call_type: int


@dataclass
class Contact:
    name: str
    phones: list[str]
    emails: list[str]
    created_at: Optional[datetime]


def mac_ts_to_datetime(mac_ts: float) -> datetime:
    """Convert Mac Absolute Time to datetime"""
    try:
        unix_ts = mac_ts + MAC_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return datetime.fromtimestamp(0, tz=timezone.utc)


def load_manifest_db(backup_dir: Path) -> list[BackupFile]:
    """Load file list from Manifest.db"""
    manifest_path = backup_dir / "Manifest.db"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest.db not found: {manifest_path}")

    files: list[BackupFile] = []
    conn = sqlite3.connect(str(manifest_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute("SELECT fileID, domain, relativePath, flags, file FROM Files")
        for row in cur.fetchall():
            files.append(BackupFile(
                file_id=row["fileID"] or "",
                domain=row["domain"] or "",
                relative_path=row["relativePath"] or "",
                flags=row["flags"] or 0,
                file_metadata=row["file"] or b"",
            ))
    finally:
        conn.close()

    return files


def load_backup_info(backup_dir: Path) -> dict:
    """Load device information from Info.plist"""
    info_path = backup_dir / "Info.plist"
    if not info_path.exists():
        return {}

    with open(info_path, "rb") as f:
        return plistlib.load(f)


def get_backup_file_path(backup_dir: Path, file_id: str) -> Path:
    """Calculate actual file path from fileID"""
    return backup_dir / file_id[:2] / file_id


def find_file_by_domain_path(
    files: list[BackupFile],
    domain: str,
    relative_path: str,
) -> Optional[BackupFile]:
    """Search for a file by domain and relative path"""
    for f in files:
        if f.domain == domain and f.relative_path == relative_path:
            return f
    return None


def find_files_by_domain(
    files: list[BackupFile],
    domain_prefix: str,
) -> list[BackupFile]:
    """Search file list by domain prefix"""
    return [f for f in files if f.domain.startswith(domain_prefix)]


def copy_file_from_backup(
    backup_dir: Path,
    backup_file: BackupFile,
    output_path: Path,
) -> bool:
    """Copy file from backup to output path"""
    src = get_backup_file_path(backup_dir, backup_file.file_id)
    if not src.exists():
        return False

    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(output_path))
    return True


def extract_sms(backup_dir: Path, output_dir: Path, files: list[BackupFile]) -> list[SmsMessage]:
    """Extract iMessage/SMS"""
    messages: list[SmsMessage] = []

    sms_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/SMS/sms.db"
    )
    if not sms_file:
        print("  [WARNING] sms.db not found.", file=sys.stderr)
        return messages

    sms_db_path = output_dir / "sms.db"
    if not copy_file_from_backup(backup_dir, sms_file, sms_db_path):
        print("  [WARNING] Failed to copy sms.db.", file=sys.stderr)
        return messages

    try:
        conn = sqlite3.connect(str(sms_db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT
                m.rowid,
                COALESCE(h.id, 'me') AS sender,
                m.date,
                m.text,
                m.is_from_me,
                m.service
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.rowid
            WHERE m.text IS NOT NULL
            ORDER BY m.date DESC
            LIMIT 5000
        """)

        for row in cur.fetchall():
            # iOS 11+: date unit is nanoseconds (>= 1e16)
            # iOS 10 and below: Mac Absolute Time (seconds)
            raw_date = row["date"]
            if raw_date and raw_date > 1_000_000_000_000:
                ts = mac_ts_to_datetime(raw_date / 1_000_000_000)
            else:
                ts = mac_ts_to_datetime(raw_date or 0)

            messages.append(SmsMessage(
                rowid=row["rowid"],
                sender=row["sender"] or "",
                timestamp=ts,
                text=row["text"] or "",
                is_from_me=bool(row["is_from_me"]),
                service=row["service"] or "unknown",
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [ERROR] SMS analysis failed: {e}", file=sys.stderr)

    return messages


def extract_call_history(
    backup_dir: Path,
    output_dir: Path,
    files: list[BackupFile],
) -> list[CallRecord]:
    """Extract call history"""
    records: list[CallRecord] = []

    call_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/CallHistory/CallHistory.storedata"
    )
    if not call_file:
        print("  [WARNING] CallHistory.storedata not found.", file=sys.stderr)
        return records

    call_db_path = output_dir / "CallHistory.db"
    if not copy_file_from_backup(backup_dir, call_file, call_db_path):
        return records

    try:
        conn = sqlite3.connect(str(call_db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT ZADDRESS, ZDURATION, ZDATE, ZORIGINATED, ZCALLTYPE
            FROM ZCALLRECORD
            ORDER BY ZDATE DESC
            LIMIT 1000
        """)

        for row in cur.fetchall():
            records.append(CallRecord(
                address=row["ZADDRESS"] or "Unknown",
                duration=float(row["ZDURATION"] or 0),
                date=mac_ts_to_datetime(row["ZDATE"] or 0),
                originated=bool(row["ZORIGINATED"]),
                call_type=row["ZCALLTYPE"] or 0,
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [ERROR] Call history analysis failed: {e}", file=sys.stderr)

    return records


def extract_contacts(
    backup_dir: Path,
    output_dir: Path,
    files: list[BackupFile],
) -> list[Contact]:
    """Extract contacts"""
    contacts: list[Contact] = []

    ab_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"
    )
    if not ab_file:
        print("  [WARNING] AddressBook.sqlitedb not found.", file=sys.stderr)
        return contacts

    ab_path = output_dir / "AddressBook.db"
    if not copy_file_from_backup(backup_dir, ab_file, ab_path):
        return contacts

    try:
        conn = sqlite3.connect(str(ab_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT ROWID, First, Last, CreationDate
            FROM ABPerson
            ORDER BY CreationDate DESC
        """)
        persons = cur.fetchall()

        for person in persons:
            name_parts = [
                p for p in [person["First"], person["Last"]]
                if p
            ]
            name = " ".join(name_parts) if name_parts else "(No name)"

            phones: list[str] = []
            emails: list[str] = []

            try:
                cur.execute("""
                    SELECT value, property FROM ABMultiValue
                    WHERE record_id = ?
                      AND property IN (3, 4)  -- 3=phone, 4=email
                """, (person["ROWID"],))

                for row in cur.fetchall():
                    if row["property"] == 3:
                        phones.append(row["value"] or "")
                    else:
                        emails.append(row["value"] or "")
            except sqlite3.DatabaseError:
                pass

            contacts.append(Contact(
                name=name,
                phones=phones,
                emails=emails,
                created_at=mac_ts_to_datetime(person["CreationDate"] or 0),
            ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [ERROR] Contacts analysis failed: {e}", file=sys.stderr)

    return contacts


def extract_safari_history(
    backup_dir: Path,
    output_dir: Path,
    files: list[BackupFile],
) -> list[dict]:
    """Extract Safari browser history"""
    history: list[dict] = []

    history_file = find_file_by_domain_path(
        files, "HomeDomain", "Library/Safari/History.db"
    )
    if not history_file:
        print("  [WARNING] Safari History.db not found.", file=sys.stderr)
        return history

    hist_path = output_dir / "SafariHistory.db"
    if not copy_file_from_backup(backup_dir, history_file, hist_path):
        return history

    try:
        conn = sqlite3.connect(str(hist_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT hi.url, hv.title, hv.visit_time
            FROM history_visits hv
            JOIN history_items hi ON hv.history_item = hi.id
            ORDER BY hv.visit_time DESC
            LIMIT 2000
        """)

        for row in cur.fetchall():
            history.append({
                "url": row["url"],
                "title": row["title"] or "",
                "visited_at": mac_ts_to_datetime(row["visit_time"] or 0).isoformat(),
            })

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"  [ERROR] Safari history analysis failed: {e}", file=sys.stderr)

    return history


def generate_forensics_report(
    backup_dir: Path,
    output_dir: Path,
    device_info: dict,
    sms_list: list[SmsMessage],
    calls: list[CallRecord],
    contacts: list[Contact],
    browser_history: list[dict],
) -> None:
    """Generate forensics report"""
    report = {
        "analysis_time": datetime.now(tz=timezone.utc).isoformat(),
        "backup_path": str(backup_dir),
        "device_info": {
            "model": device_info.get("Product Type", ""),
            "name": device_info.get("Device Name", ""),
            "ios_version": device_info.get("Product Version", ""),
            "imei": device_info.get("IMEI", ""),
            "phone_number": device_info.get("Phone Number", ""),
            "serial": device_info.get("Serial Number", ""),
            "last_backup": str(device_info.get("Last Backup Date", "")),
        },
        "message_analysis": {
            "total_count": len(sms_list),
            "iMessage": sum(1 for m in sms_list if m.service == "iMessage"),
            "SMS": sum(1 for m in sms_list if m.service == "SMS"),
            "received": sum(1 for m in sms_list if not m.is_from_me),
            "sent": sum(1 for m in sms_list if m.is_from_me),
            "recent_messages": [
                {
                    "sender": m.sender,
                    "time": m.timestamp.isoformat(),
                    "service": m.service,
                    "direction": "sent" if m.is_from_me else "received",
                    "content_preview": m.text[:100],
                }
                for m in sms_list[:30]
            ],
        },
        "call_history": {
            "total_count": len(calls),
            "outgoing": sum(1 for c in calls if c.originated),
            "incoming": sum(1 for c in calls if not c.originated),
            "recent_calls": [
                {
                    "number": c.address,
                    "time": c.date.isoformat(),
                    "duration_seconds": int(c.duration),
                    "direction": "outgoing" if c.originated else "incoming",
                    "type": {0: "Phone", 1: "FaceTime Audio", 8: "FaceTime Video"}.get(c.call_type, "Other"),
                }
                for c in calls[:30]
            ],
        },
        "contacts": {
            "total_count": len(contacts),
            "list": [
                {"name": c.name, "phones": c.phones, "emails": c.emails}
                for c in contacts[:50]
            ],
        },
        "browser_history": {
            "total_count": len(browser_history),
            "recent": browser_history[:30],
        },
    }

    json_path = output_dir / "ios_forensics_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    txt_path = output_dir / "ios_forensics_report.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("iOS Forensic Analysis Report\n")
        f.write("=" * 60 + "\n\n")

        gi = report["device_info"]
        f.write(f"Device Model:   {gi['model']}\n")
        f.write(f"Device Name:    {gi['name']}\n")
        f.write(f"iOS Version:    {gi['ios_version']}\n")
        f.write(f"IMEI:           {gi['imei']}\n")
        f.write(f"Phone Number:   {gi['phone_number']}\n")
        f.write(f"Serial Number:  {gi['serial']}\n")
        f.write(f"Last Backup:    {gi['last_backup']}\n\n")

        f.write(f"[iMessage/SMS] Total: {len(sms_list)}\n")
        for msg in sms_list[:20]:
            direction = "→" if msg.is_from_me else "←"
            f.write(
                f"  {direction} [{msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')}]"
                f" {msg.sender} ({msg.service})\n"
            )
            f.write(f"     {msg.text[:80]}\n\n")

        f.write(f"[Call History] Total: {len(calls)}\n")
        for call in calls[:20]:
            direction = "outgoing" if call.originated else "incoming"
            f.write(
                f"  [{call.date.strftime('%Y-%m-%d %H:%M:%S')}]"
                f" {direction} | {call.address}"
                f" | {int(call.duration)} seconds\n"
            )

        f.write(f"\n[Contacts] Total: {len(contacts)}\n")
        for contact in contacts[:20]:
            f.write(f"  {contact.name}: {', '.join(contact.phones)}\n")

    print(f"  JSON: {json_path}")
    print(f"  TXT:  {txt_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="iOS iTunes Backup Forensic Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -b ~/MobileSync/Backup/<UDID> -o ./output
  %(prog)s -b ./backup -o ./output --extract-sms --extract-calls
  %(prog)s -b ./backup -o ./output --all
        """,
    )
    parser.add_argument("-b", "--backup", required=True, help="iTunes backup directory path")
    parser.add_argument("-o", "--output", required=True, help="Output directory path")
    parser.add_argument("-p", "--password", help="Encrypted backup password")
    parser.add_argument("--extract-sms", action="store_true", help="Extract iMessage/SMS")
    parser.add_argument("--extract-calls", action="store_true", help="Extract call history")
    parser.add_argument("--extract-contacts", action="store_true", help="Extract contacts")
    parser.add_argument("--extract-safari", action="store_true", help="Extract Safari history")
    parser.add_argument("--all", action="store_true", help="Extract all artifacts")

    args = parser.parse_args()

    if args.all:
        args.extract_sms = True
        args.extract_calls = True
        args.extract_contacts = True
        args.extract_safari = True

    backup_dir = Path(args.backup)
    output_dir = Path(args.output)

    if not backup_dir.exists():
        print(f"[ERROR] Backup directory not found: {backup_dir}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)

    print(f"[*] Parsing iOS backup: {backup_dir}")
    device_info = load_backup_info(backup_dir)
    if device_info:
        print(f"    Device: {device_info.get('Product Type', 'N/A')}")
        print(f"    iOS:    {device_info.get('Product Version', 'N/A')}")
        print(f"    IMEI:   {device_info.get('IMEI', 'N/A')}")

    print("[*] Loading Manifest.db...")
    try:
        files = load_manifest_db(backup_dir)
        print(f"    File count: {len(files):,}")
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    sms_list: list[SmsMessage] = []
    calls: list[CallRecord] = []
    contacts: list[Contact] = []
    browser_history: list[dict] = []

    if args.extract_sms:
        print("[*] Extracting iMessage/SMS...")
        sms_list = extract_sms(backup_dir, artifacts_dir, files)
        print(f"    Extracted: {len(sms_list)}")

    if args.extract_calls:
        print("[*] Extracting call history...")
        calls = extract_call_history(backup_dir, artifacts_dir, files)
        print(f"    Extracted: {len(calls)}")

    if args.extract_contacts:
        print("[*] Extracting contacts...")
        contacts = extract_contacts(backup_dir, artifacts_dir, files)
        print(f"    Extracted: {len(contacts)}")

    if args.extract_safari:
        print("[*] Extracting Safari history...")
        browser_history = extract_safari_history(backup_dir, artifacts_dir, files)
        print(f"    Extracted: {len(browser_history)}")

    print("[*] Generating forensics report...")
    generate_forensics_report(
        backup_dir, output_dir, device_info,
        sms_list, calls, contacts, browser_history,
    )

    print(f"\n[DONE] Results saved to: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. GrayKey / Cellebrite Methods Overview

### GrayKey (Grayshift)

**Overview**
- iOS unlock device developed by U.S.-based Grayshift
- Primary customers: U.S. FBI, DEA, local police departments
- Released around 2018, continuously updated for latest iOS versions

**How It Works (Known Information)**
1. Bootrom or software exploit using iOS vulnerabilities (Zero-Day or N-Day)
2. Bypasses PIN code/password brute-force restrictions
3. Attempts to bypass SEP (Secure Enclave Processor) limitations
4. More data is accessible in the After First Unlock (AFU) state

**Limitations**
- USB Restricted Mode (iPhone X+, iOS 11.4.1+): blocks data transfer 1 hour after USB connection
- A17 Pro / M-series chips: very difficult to access
- USB Restricted Mode bypass: uses undisclosed vulnerabilities (GrayKey supports some devices)

**Countermeasures (Defense from the forensic target's perspective)**
```
# Power off the device (to place in Before First Unlock state)
# Verify USB Restricted Mode is enabled
Settings → Face ID/Touch ID & Passcode → USB Accessories → Disable

# Use a strong passcode
Settings → Passcode → Custom Alphanumeric Code (8+ characters recommended)
```

### Cellebrite UFED

**UFED (Universal Forensic Extraction Device)**
- Product by Israel-based Cellebrite
- Used by law enforcement agencies in 150+ countries worldwide
- Supports iOS + Android + feature phones

**Extraction Method Tiers**

```
1. Logical Extraction
   - Access through backup files
   - iCloud backup parsing
   - Easiest and safest, but limited data

2. Advanced Logical Extraction
   - Install Cellebrite agent without jailbreak
   - Access to more filesystem data

3. File System Extraction
   - Full /private/var access
   - Can recover some deleted files
   - Requires jailbreak or vulnerability

4. Physical Extraction
   - NAND flash raw dump
   - JTAG or Chip-off
   - Primarily applied to older devices
```

**UFED Output**
```
UFED_<DeviceID>.ufd          # Extraction metadata
<device>_<date>/
├── Extraction.xml            # Extraction information
├── FileSystem/               # Filesystem image
├── databases/                # Parsed DBs
└── UFED_PA_Report.pdf        # Auto-generated report
```

### MVT (Mobile Verification Toolkit)

**Development Background**
- Developed by Amnesty International
- Purpose: detect Pegasus spyware
- Supports both iOS and Android

```bash
# Install MVT
pip install mvt

# Analyze iOS backup (using STIX2 IOC)
mvt-ios check-backup \
    --iocs ~/iocs/pegasus.stix2 \
    --output ./mvt_output \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

# Encrypted backup
mvt-ios decrypt-backup \
    --password <password> \
    --destination ./decrypted_backup \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

mvt-ios check-backup \
    --iocs ~/iocs/pegasus.stix2 \
    --output ./mvt_output \
    ./decrypted_backup

# Direct analysis on jailbroken device
mvt-ios check-fs \
    --iocs ~/iocs/pegasus.stix2 \
    --output ./mvt_output \
    /

# Download IOCs
wget https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2
```

**Pegasus Detection Indicators**
```
- Abnormal process crashes (crash logs)
- Unknown network connections
- Abnormal processes in DataUsage.sqlite
- Abnormal execution traces in process_info.plist
- DNS lookup records for specific domains
```

---

## Practical iOS Forensics Checklist

```
Preparation:
□ Keep device powered on (do not restart → prevents transition to BFU state)
□ Switch device to airplane mode (prevents remote wipe)
□ Check USB Restricted Mode status
□ Check device lock state (BFU vs AFU)

Collection:
□ Save Info.plist (device identification info)
□ Save Manifest.db (file list)
□ Calculate hash of entire backup
□ Extract artifacts in order

Analysis:
□ Extract iMessage/SMS and reconstruct timeline
□ Analyze call history
□ Map visualization of location data
□ Analyze Safari/Chrome history
□ App data (KakaoTalk, WhatsApp, etc.)
□ Analyze photo EXIF metadata
□ Attempt deleted file recovery
□ Check cloud sync status
```

<!-- detect-validate-47 -->
## Anti-Forensics Detection and iOS Evidence Validation

iOS forensics recovers evidence from *the filesystem, iTunes/iCloud backups, artifacts, and keychain*. The analyst must be aware of anti-forensics like *jailbreak concealment, backup encryption, and artifact cleanup* and verify **whether the backup is decrypted, intact, and cross-consistent**. Validate only on **owned devices/backups**.

### Anti-forensic technique -> Targeted forensic step -> Analyst response -> Observable signal

| Technique | Targeted step | Analyst response | Observable signal |
|---|---|---|---|
| Jailbreak concealment | Integrity assumption | Cross-check Cydia/JB traces | Non-standard /Applications |
| Backup encryption | Block access | Recover password/key | Manifest.plist encrypted flag |
| Artifact cleanup | Single-source reliance | Cross WAL, KnowledgeC | Deleted rows remain |
| Time tampering | Timeline trust | Cross multiple DBs | ts != Mft |

### Evidence validation (verify directly)

```bash
# 1) Owned-backup integrity/encryption state — cross-check encryption and file count via Manifest (evidence consistency)
plutil -p Manifest.plist 2>/dev/null | grep -iE 'IsEncrypted|Date'; ls Manifest.db && echo "manifest present"
# 2) Whether deleted iOS DB rows remain in WAL (anti-forensics bypass) — absent in main DB but present in -wal
sqlite3 sms.db 'PRAGMA journal_mode;' 2>/dev/null; strings sms.db-wal 2>/dev/null | grep -iE 'http|message' | head
```

> iOS evidence validation is *whether the backup is decrypted, intact, and cross-consistent* -- "I opened the backup" differs from "jailbreak traces cross-check and deleted rows agree with the WAL". Confirm on owned devices/backups directly ([[07_Digital_Forensics]], [[28_Mobile_Hacking]], [[44_Incident_Response_DFIR]]).
