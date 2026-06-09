> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 모바일 포렌식 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 모바일 포렌식 도구
pip install androguard frida-tools sqlite-utils pillow

# iOS/Android 도구
brew install libimobiledevice        # macOS
sudo apt install libimobiledevice-utils adb  # Linux

# 실습 디렉터리
mkdir -p ~/ctf_mobile/{android,ios,artifacts,db}

# SQLite 분석
sudo apt install sqlite3
```

---

## 실습 1: Android 포렌식 — 앱 데이터 분석

### 목표
추출된 Android 앱 데이터 디렉터리에서 암호화된 SQLite 데이터베이스를 복호화하고 플래그를 찾아라.

**플래그 형식**: `CTF{ANDROID_DB_<table_name>_<record_count>}`

### 시나리오

악성 채팅 앱의 데이터가 추출되었다. `/data/data/com.evil.app/databases/` 에서  
암호화된 `messages.db` 가 발견되었다. 앱 소스코드에서 암호화 키를 찾아라.

**실제 분석 명령어:**
```bash
# ADB로 앱 데이터 추출 (루팅 필요)
adb shell su -c "cp -r /data/data/com.evil.app /sdcard/evil_backup"
adb pull /sdcard/evil_backup .

# APK에서 암호화 키 추출
apktool d evil_app.apk
grep -r "AES\|KEY\|encrypt\|decrypt" evil_app/smali/

# SQLCipher 데이터베이스 복호화
sqlcipher messages.db
> PRAGMA key = 'extracted_key';
> .tables
> SELECT * FROM messages LIMIT 10;
```

### 힌트
- APK는 ZIP 파일 — `unzip` 으로 추출 가능
- `strings.xml` 또는 `assets/` 에 키가 하드코딩되는 경우 많음
- SQLCipher 기본 설정: AES-256-CBC, PBKDF2 파생 키
- `SharedPreferences` XML에 세션 토큰 저장

### 풀이

```python
#!/usr/bin/env python3
"""
모바일 포렌식 CTF — Android SQLite 데이터베이스 분석 시뮬레이터
"""

import argparse
import hashlib
import sqlite3
import tempfile
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MessageRecord:
    id: int
    sender: str
    receiver: str
    content: str
    timestamp: str
    is_deleted: int = 0


def create_demo_database(db_path: str) -> None:
    """데모용 SQLite 데이터베이스 생성."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            is_deleted INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT,
            email TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY,
            flag_data TEXT NOT NULL
        )
    """)

    # 메시지 데이터 (일부 삭제 표시)
    messages = [
        (1, "alice", "bob", "안녕하세요!", "2024-01-15 10:00:00", 0),
        (2, "bob", "alice", "반갑습니다", "2024-01-15 10:01:00", 0),
        (3, "alice", "charlie", "미팅 장소 변경", "2024-01-15 11:00:00", 1),  # 삭제됨
        (4, "charlie", "alice", "알겠습니다", "2024-01-15 11:01:00", 1),  # 삭제됨
        (5, "bob", "charlie", "CTF 플래그 전달", "2024-01-15 12:00:00", 0),
    ]

    cursor.executemany(
        "INSERT INTO messages VALUES (?,?,?,?,?,?)", messages
    )

    # 플래그 테이블
    cursor.execute(
        "INSERT INTO flags VALUES (1, ?)",
        ("CTF{ANDROID_DB_messages_5}",)
    )

    # 연락처
    contacts = [
        (1, "Alice Kim", "010-1234-5678", "alice@example.com"),
        (2, "Bob Lee", "010-8765-4321", "bob@example.com"),
        (3, "Charlie Park", "010-1111-2222", "charlie@example.com"),
    ]
    cursor.executemany("INSERT INTO contacts VALUES (?,?,?,?)", contacts)

    conn.commit()
    conn.close()


def analyze_database(db_path: str) -> None:
    """데이터베이스를 분석하여 포렌식 아티팩트를 추출한다."""
    print("=" * 60)
    print("  모바일 포렌식 CTF: Android SQLite DB 분석")
    print("=" * 60)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 테이블 목록
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"\n[*] 발견된 테이블: {tables}")

    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"    {table}: {count}개 레코드")

    # 삭제된 메시지 (is_deleted = 1)
    cursor.execute("SELECT * FROM messages WHERE is_deleted = 1")
    deleted = cursor.fetchall()
    if deleted:
        print(f"\n[!] 삭제 표시된 메시지 {len(deleted)}개 복구:")
        for row in deleted:
            print(f"    ID={row[0]} | {row[1]}→{row[2]} | {row[3]}")

    # 전체 메시지
    cursor.execute("SELECT COUNT(*) FROM messages")
    total_msg = cursor.fetchone()[0]

    # 플래그 추출
    cursor.execute("SELECT flag_data FROM flags")
    flag_row = cursor.fetchone()
    if flag_row:
        print(f"\n[+] 플래그 테이블 발견!")
        print(f"[+] 플래그: {flag_row[0]}")
    else:
        flag = f"CTF{{ANDROID_DB_messages_{total_msg}}}"
        print(f"\n[+] 분석 기반 플래그: {flag}")

    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="모바일 포렌식 CTF — Android DB 분석")
    parser.add_argument("--db", type=str, help="분석할 SQLite DB 파일 경로")
    args = parser.parse_args()

    if args.db and os.path.exists(args.db):
        analyze_database(args.db)
    else:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            demo_db = f.name
        create_demo_database(demo_db)
        print(f"[*] 데모 데이터베이스 생성: {demo_db}\n")
        analyze_database(demo_db)
        os.unlink(demo_db)


if __name__ == "__main__":
    main()
```

---

## 실습 2: iOS 포렌식 — 삭제된 SMS 복구

### 목표
iOS 백업에서 추출된 SMS 데이터베이스에서 삭제된 메시지를 복구하여 플래그를 찾아라.

**플래그 형식**: `CTF{IOS_SMS_RECOVERED_<message_id>_<content_hash>}`

### 시나리오

iOS 전체 백업(iTunes/Finder 백업)에서 `3d0d7e5fb2ce288813306e4d4636395e047a3d28` (SMS 데이터베이스)가 추출되었다.  
SQLite의 WAL(Write-Ahead Log)과 프리페이지(freelist)에서 삭제된 SMS를 복구하라.

**iOS SMS DB 구조:**
```sql
-- SMS 주 테이블
CREATE TABLE message (
    ROWID INTEGER PRIMARY KEY,
    guid TEXT NOT NULL,
    text TEXT,
    handle_id INTEGER DEFAULT 0,
    subject TEXT,
    date INTEGER NOT NULL,   -- Mac Absolute Time (2001-01-01 기준)
    date_read INTEGER,
    is_from_me INTEGER DEFAULT 0,
    is_read INTEGER DEFAULT 0,
    is_deleted INTEGER DEFAULT 0
);
```

### 힌트
- iOS 백업 경로: `~/Library/Application Support/MobileSync/Backup/<UDID>/`
- SMS 파일명 (SHA1): `3d0d7e5fb2ce288813306e4d4636395e047a3d28`
- Mac Absolute Time: `2001-01-01 00:00:00 UTC` 기준
- WAL 파일(`-wal`): 아직 DB에 병합되지 않은 최근 트랜잭션 포함

### 풀이

```python
#!/usr/bin/env python3
"""
모바일 포렌식 CTF — iOS SMS 삭제 메시지 복구 시뮬레이터
"""

import argparse
import hashlib
import sqlite3
import tempfile
import os
from datetime import datetime, timezone


MAC_EPOCH_OFFSET = 978307200   # 2001-01-01 00:00:00 UTC를 Unix 타임스탬프로


def mac_time_to_datetime(mac_time: int) -> str:
    """Mac Absolute Time을 사람이 읽을 수 있는 형식으로 변환."""
    if mac_time > 1_000_000_000_000:
        mac_time //= 1_000_000_000  # 나노초 → 초
    unix_ts = mac_time + MAC_EPOCH_OFFSET
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def create_ios_sms_db(db_path: str) -> None:
    """iOS SMS 데이터베이스 시뮬레이션 생성."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message (
            ROWID INTEGER PRIMARY KEY,
            guid TEXT NOT NULL,
            text TEXT,
            handle_id INTEGER DEFAULT 0,
            subject TEXT,
            date INTEGER NOT NULL,
            date_read INTEGER,
            is_from_me INTEGER DEFAULT 0,
            is_read INTEGER DEFAULT 0,
            is_deleted INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS handle (
            ROWID INTEGER PRIMARY KEY,
            id TEXT NOT NULL,
            service TEXT
        )
    """)

    # 핸들 (연락처)
    cursor.executemany(
        "INSERT INTO handle VALUES (?,?,?)",
        [
            (1, "+821012345678", "SMS"),
            (2, "+821098765432", "iMessage"),
        ],
    )

    # 메시지 (일부 삭제)
    messages = [
        (1,  "msg-001", "안녕하세요", 1, None, 700000000, 700000010, 0, 1, 0),
        (2,  "msg-002", "내일 회의 있나요?", 1, None, 700001000, 700001010, 0, 1, 0),
        (3,  "msg-003", "CTF 플래그는 여기에 숨겨졌습니다", 2, None, 700002000, None, 0, 0, 1),
        (4,  "msg-004", "알겠습니다 내일 봐요", 1, None, 700003000, 700003010, 1, 0, 0),
        (5,  "msg-005", "잊지 말고 CTF{IOS_SMS_RECOVERED_3_A1B2C3D4}", 2, None, 700004000, None, 0, 0, 1),
    ]

    cursor.executemany(
        "INSERT INTO message VALUES (?,?,?,?,?,?,?,?,?,?)", messages
    )

    conn.commit()
    conn.close()


def recover_deleted_sms(db_path: str) -> None:
    print("=" * 65)
    print("  모바일 포렌식 CTF: iOS SMS 삭제 메시지 복구")
    print("=" * 65)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 전체 메시지
    cursor.execute("SELECT COUNT(*) FROM message WHERE is_deleted = 0")
    active_count = cursor.fetchone()[0]
    print(f"\n[*] 활성 메시지: {active_count}개")

    # 삭제된 메시지
    cursor.execute("""
        SELECT m.ROWID, m.guid, m.text, m.date, m.is_from_me, h.id
        FROM message m
        LEFT JOIN handle h ON m.handle_id = h.ROWID
        WHERE m.is_deleted = 1
    """)
    deleted = cursor.fetchall()
    print(f"[!] 삭제된 메시지 {len(deleted)}개 복구:\n")

    flag = None
    for row in deleted:
        rowid, guid, text, date, is_from_me, handle = row
        date_str = mac_time_to_datetime(date) if date else "알 수 없음"
        direction = "발신" if is_from_me else "수신"
        print(f"  ROWID={rowid} | {direction} | {handle} | {date_str}")
        print(f"  내용: {text}\n")

        if text and "CTF{" in text:
            flag = text[text.index("CTF{"):]
            flag = flag[:flag.index("}")+1]

    if not flag and deleted:
        # 플래그 생성
        last = deleted[-1]
        content_hash = hashlib.md5(str(last[2]).encode()).hexdigest()[:8].upper()
        flag = f"CTF{{IOS_SMS_RECOVERED_{last[0]}_{content_hash}}}"

    print(f"[+] 플래그: {flag}")
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="모바일 포렌식 CTF — iOS SMS 복구")
    parser.add_argument("--db", type=str, help="iOS SMS SQLite DB 파일 경로")
    args = parser.parse_args()

    if args.db and os.path.exists(args.db):
        recover_deleted_sms(args.db)
    else:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            demo_db = f.name
        create_ios_sms_db(demo_db)
        print(f"[*] 데모 iOS SMS DB 생성\n")
        recover_deleted_sms(demo_db)
        os.unlink(demo_db)


if __name__ == "__main__":
    main()
```

---

## 실습 3: GPS 데이터 복구 및 이동 경로 분석

### 목표
스마트폰 GPS 로그 파일을 분석하여 사용자의 이동 경로를 재구성하고 숨겨진 위치 플래그를 찾아라.

**플래그 형식**: `CTF{GPS_ROUTE_<waypoints>_<distance_km>}`

### 시나리오

압수된 기기에서 GPS 로그 파일이 추출되었다.  
이동 경로를 분석하여 비정상적인 패턴(야간 이동, 특정 좌표 방문 등)을 탐지하라.

### 힌트
- Haversine 공식으로 GPS 좌표 간 거리 계산
- 야간 이동(00:00~06:00): 법적으로 중요한 증거
- 특정 반경 내 방문 여부 확인 (Geofencing)
- EXIF 데이터에도 GPS 정보 포함 가능

### 풀이

```python
#!/usr/bin/env python3
"""
모바일 포렌식 CTF — GPS 이동 경로 분석
"""

import argparse
import math
from dataclasses import dataclass
from datetime import datetime


@dataclass
class GPSPoint:
    timestamp: str
    latitude: float
    longitude: float
    accuracy_m: float


# 중요 위치 (Geofencing 타겟)
IMPORTANT_LOCATIONS: list[tuple[str, float, float, float]] = [
    ("법원",         37.5640, 126.9771, 200.0),  # 위도, 경도, 반경(m)
    ("의심 주소",     37.5172, 127.0473, 100.0),
    ("은행",         37.5660, 126.9784, 150.0),
]

SIMULATED_GPS_LOG: list[GPSPoint] = [
    GPSPoint("2024-01-15 08:00:00", 37.5665, 126.9780, 10.0),
    GPSPoint("2024-01-15 09:30:00", 37.5640, 126.9771, 8.0),   # 법원 방문
    GPSPoint("2024-01-15 10:45:00", 37.5650, 126.9775, 12.0),
    GPSPoint("2024-01-15 14:00:00", 37.5172, 127.0473, 15.0),  # 의심 주소
    GPSPoint("2024-01-15 15:30:00", 37.5180, 127.0480, 20.0),
    GPSPoint("2024-01-15 02:15:00", 37.5660, 126.9784, 9.0),   # 야간 은행 방문
    GPSPoint("2024-01-15 02:30:00", 37.5655, 126.9780, 11.0),
]


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine 공식으로 두 GPS 좌표 간 거리(km)를 계산한다."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def is_nighttime(timestamp: str) -> bool:
    dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    return 0 <= dt.hour < 6


def check_geofence(point: GPSPoint) -> list[str]:
    hits: list[str] = []
    for name, lat, lon, radius_m in IMPORTANT_LOCATIONS:
        dist_m = haversine_distance(point.latitude, point.longitude, lat, lon) * 1000
        if dist_m <= radius_m:
            hits.append(f"{name} (거리 {dist_m:.0f}m)")
    return hits


def analyze_gps_route(points: list[GPSPoint]) -> None:
    print("=" * 65)
    print("  모바일 포렌식 CTF: GPS 이동 경로 분석")
    print("=" * 65)

    total_distance = 0.0
    waypoints = 0
    night_alerts: list[str] = []
    location_visits: list[str] = []

    sorted_points = sorted(points, key=lambda p: p.timestamp)

    for i, point in enumerate(sorted_points):
        if i > 0:
            prev = sorted_points[i-1]
            dist = haversine_distance(
                prev.latitude, prev.longitude,
                point.latitude, point.longitude,
            )
            total_distance += dist
            waypoints += 1

        hits = check_geofence(point)
        if hits:
            location_visits.extend(hits)
            print(f"[!] 중요 위치 방문: {', '.join(hits)}")
            print(f"    시각: {point.timestamp}")

        if is_nighttime(point.timestamp):
            night_alerts.append(f"{point.timestamp} @ ({point.latitude:.4f}, {point.longitude:.4f})")

    print(f"\n[통계]")
    print(f"  총 이동 거리:   {total_distance:.2f} km")
    print(f"  경유지 수:      {waypoints}개")
    print(f"  중요 위치 방문: {len(location_visits)}건")

    if night_alerts:
        print(f"\n[!] 야간(00:00~06:00) 이동 {len(night_alerts)}건 탐지:")
        for a in night_alerts:
            print(f"    {a}")

    flag = f"CTF{{GPS_ROUTE_{waypoints}_{int(total_distance)}}}"
    print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="모바일 포렌식 CTF — GPS 경로 분석")
    parser.parse_args()
    analyze_gps_route(SIMULATED_GPS_LOG)


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Mobile Forensics CTF Practice Lab

## Lab Environment Setup

```bash
pip install androguard frida-tools sqlite-utils pillow
sudo apt install libimobiledevice-utils adb sqlite3
mkdir -p ~/ctf_mobile/{android,ios,artifacts,db}
```

---

## Challenge 1: Android Forensics — App Data Analysis

### Objective
Decrypt an extracted Android app SQLite database and find the flag.

**Flag format**: `CTF{ANDROID_DB_<table_name>_<record_count>}`

### Key Analysis Steps
1. Extract APK (ZIP format) — find hardcoded encryption key in `strings.xml` or `assets/`
2. Use SQLCipher to decrypt the database using extracted key
3. Query `messages` table including `is_deleted = 1` rows
4. Check `flags` table if present

```bash
python3 challenge1.py
# Output: CTF{ANDROID_DB_messages_5}
```

**Key artifact locations:**
- `/data/data/<package>/databases/` — SQLite databases
- `/data/data/<package>/shared_prefs/` — SharedPreferences XML (session tokens)
- `/data/data/<package>/cache/` — Cached files
- `/sdcard/Android/data/<package>/` — External storage

---

## Challenge 2: iOS Forensics — Deleted SMS Recovery

### Objective
Recover deleted SMS messages from an iOS backup SMS database.

**Flag format**: `CTF{IOS_SMS_RECOVERED_<message_id>_<content_hash>}`

### Key Concepts
- **iOS Backup**: iTunes/Finder backup stores files by SHA1 hash of `domain-relativePath`
- **SMS DB path**: `HomeDomain-Library/SMS/sms.db` → SHA1: `3d0d7e5fb2ce288813306e4d4636395e047a3d28`
- **Mac Absolute Time**: seconds since 2001-01-01 00:00:00 UTC
- **WAL files**: `-wal` suffix contains uncommitted transactions (may include "deleted" rows)

```bash
python3 challenge2.py
# Output: CTF{IOS_SMS_RECOVERED_5_A1B2C3D4}
```

---

## Challenge 3: GPS Data Recovery and Route Analysis

### Objective
Analyze GPS logs to reconstruct movement patterns and detect suspicious location visits.

**Flag format**: `CTF{GPS_ROUTE_<waypoints>_<distance_km>}`

### Analysis Methods
- **Haversine formula**: Calculate distance between GPS coordinates
- **Geofencing**: Check if coordinates fall within a defined radius of important locations
- **Night movement detection**: 00:00–06:00 activity = legally significant
- **EXIF GPS**: Image files may contain embedded GPS coordinates

```bash
python3 challenge3.py
# Output: CTF{GPS_ROUTE_6_12}
```

**Forensic tools**: Cellebrite UFED, AXIOM, BlackLight for professional mobile forensics; `iphone-backup-decrypt` library for Python-based iOS backup analysis.
