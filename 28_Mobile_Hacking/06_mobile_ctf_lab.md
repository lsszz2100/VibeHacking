> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 모바일 해킹 CTF 실습 랩

## 실습 환경 준비

### 필수 도구 설치

```bash
# Android 분석 도구
pip install androguard frida-tools objection

# APK 디컴파일
sudo apt install -y apktool default-jdk
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d jadx/

# ADB
sudo apt install -y android-tools-adb

# Frida 서버 (에뮬레이터/기기에 설치)
# https://github.com/frida/frida/releases
```

### Docker 분석 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  apk-analyzer:
    image: python:3.11-slim
    container_name: apk-analyzer
    volumes:
      - ./apk-samples:/samples
      - ./tools:/tools
    command: >
      sh -c "pip install androguard -q && sleep infinity"
    tty: true

  backend-server:
    image: python:3.11-slim
    container_name: backend-server
    ports:
      - "5000:5000"
    command: >
      sh -c "pip install flask -q &&
             python3 /app/server.py"
    volumes:
      - ./server.py:/app/server.py
```

---

## 실습 1: APK 역공학 - 하드코딩된 비밀 키 추출

### 목표

안드로이드 APK 파일을 역공학하여 소스코드에 하드코딩된 API 키, 시크릿, 플래그를 추출한다.

**플래그 형식**: `CTF{apk_<secret_type>_extracted}`

### 시나리오

뱅킹 앱의 APK 파일이 제공됐다. 역공학을 통해 소스코드 내 하드코딩된 비밀 정보와 플래그를 찾아라.

### 테스트용 APK 소스코드 시뮬레이션

```python
#!/usr/bin/env python3
"""APK 역공학 실습을 위한 가상 DEX 파일 생성"""

import zipfile
import os
from pathlib import Path


# 가상의 디컴파일된 Java 소스 (실습용)
DECOMPILED_SOURCES = {
    "MainActivity.java": """
package com.ctfbank.app;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    // TODO: 프로덕션 전 제거 필요
    private static final String API_KEY = "sk-bank-prod-9f8e7d6c5b4a3210";
    private static final String SECRET_FLAG = "CTF{apk_hardcoded_api_key_extracted}";
    private static final String BACKEND_URL = "https://api.ctfbank.internal";
    private static final String DEBUG_PASS = "d3bug_m0d3_2024";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // ...
    }
}
""",
    "NetworkHelper.java": """
package com.ctfbank.app.network;

public class NetworkHelper {
    private static final String CERT_PIN_SHA256 =
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    public void disableCertPinning() {
        // CVE-2024-XXXX: Pinning bypass for debug builds
        if (BuildConfig.DEBUG) {
            trustAllCerts();
        }
    }
}
""",
    "res/values/strings.xml": """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">CTFBank</string>
    <string name="api_endpoint">https://api.ctfbank.internal/v2</string>
    <string name="auth_token">Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret</string>
</resources>
""",
}


def create_fake_apk(output_path: str) -> None:
    """가상 APK 아카이브 생성 (ZIP 기반)"""
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in DECOMPILED_SOURCES.items():
            zf.writestr(f"smali/{filename}", content)

        # AndroidManifest.xml 시뮬레이션
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.ctfbank.app"
    android:versionCode="5"
    android:versionName="2.1.0">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <application android:debuggable="true" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>"""
        zf.writestr("AndroidManifest.xml", manifest)

    print(f"[+] 가상 APK 생성: {output_path}")


if __name__ == "__main__":
    Path("apk-samples").mkdir(exist_ok=True)
    create_fake_apk("apk-samples/ctfbank_v2.1.0.apk")
```

### 힌트

1. `apktool d ctfbank.apk -o decompiled/` 으로 APK 디컴파일
2. `grep -r "API_KEY\|SECRET\|CTF{" decompiled/` 로 비밀 정보 검색
3. `strings.xml`, `BuildConfig.java`, `*.smali` 파일 확인

### 풀이

```python
#!/usr/bin/env python3
"""APK 정적 분석 도구"""

import argparse
import re
import zipfile
from pathlib import Path


SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r"CTF\{[^}]+\}", "CTF 플래그"),
    (r'(?i)api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "API 키"),
    (r'(?i)secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,})["\']?', "시크릿"),
    (r'(?i)(password|passwd)\s*[=:]\s*["\']?(\S{6,})["\']?', "패스워드"),
    (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', "Bearer 토큰"),
    (r'https?://[^\s"\'<>]+', "URL"),
    (r'sha256/[A-Za-z0-9+/]{43}=', "인증서 핀"),
]

DANGEROUS_PERMISSIONS = [
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_CONTACTS",
    "READ_SMS",
    "CAMERA",
    "RECORD_AUDIO",
]


def extract_apk_contents(apk_path: str) -> dict[str, str]:
    """APK(ZIP) 내용 추출"""
    contents: dict[str, str] = {}

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                try:
                    data = zf.read(name).decode("utf-8", errors="ignore")
                    contents[name] = data
                except Exception:
                    pass
    except zipfile.BadZipFile:
        print(f"[-] APK(ZIP) 형식 오류: {apk_path}")

    return contents


def scan_for_secrets(contents: dict[str, str]) -> dict[str, list[dict]]:
    """소스 파일에서 민감 정보 탐색"""
    results: dict[str, list[dict]] = {}

    for filename, content in contents.items():
        file_findings: list[dict] = []

        for pattern, label in SENSITIVE_PATTERNS:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for m in matches:
                line_num = content[:m.start()].count("\n") + 1
                file_findings.append({
                    "label": label,
                    "value": m.group()[:120],
                    "line": line_num,
                })

        if file_findings:
            results[filename] = file_findings

    return results


def check_manifest_issues(manifest_content: str) -> list[str]:
    """AndroidManifest.xml 보안 문제 탐지"""
    issues: list[str] = []

    if 'android:debuggable="true"' in manifest_content:
        issues.append("DEBUG 모드 활성화 (android:debuggable=true)")
    if 'android:allowBackup="true"' in manifest_content:
        issues.append("백업 허용 (android:allowBackup=true) - 데이터 유출 위험")

    for perm in DANGEROUS_PERMISSIONS:
        if perm in manifest_content:
            issues.append(f"위험 권한: {perm}")

    return issues


def analyze_apk(apk_path: str) -> None:
    path = Path(apk_path)
    if not path.exists():
        print(f"[-] 파일 없음: {apk_path}")
        return

    print(f"[*] APK 분석: {path.name}")
    contents = extract_apk_contents(apk_path)
    print(f"[*] 파일 수: {len(contents)}")

    # 매니페스트 분석
    manifest = contents.get("AndroidManifest.xml", "")
    if manifest:
        issues = check_manifest_issues(manifest)
        if issues:
            print("\n=== 매니페스트 보안 문제 ===")
            for issue in issues:
                print(f"  [!] {issue}")

    # 시크릿 스캔
    findings = scan_for_secrets(contents)
    print("\n=== 민감 정보 발견 ===")
    all_flags: list[str] = []

    for filename, file_findings in findings.items():
        print(f"\n  파일: {filename}")
        for f in file_findings:
            print(f"    [{f['label']}] L{f['line']}: {f['value'][:80]}")
            if f["label"] == "CTF 플래그":
                all_flags.append(f["value"])

    if all_flags:
        print("\n[+] 플래그:")
        for flag in set(all_flags):
            print(f"    {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="APK 정적 분석 도구")
    parser.add_argument("apk", help="분석할 APK 파일 경로")
    args = parser.parse_args()
    analyze_apk(args.apk)


if __name__ == "__main__":
    main()
```

---

## 실습 2: 인증서 핀닝 우회 (Frida)

### 목표

Frida를 이용하여 Android 앱의 SSL/TLS 인증서 핀닝을 우회하고 HTTPS 트래픽을 가로챈다.

**플래그 형식**: `CTF{pinning_bypass_<method>_traffic_intercepted}`

### 시나리오

뱅킹 앱이 SSL 핀닝으로 HTTPS 트래픽 분석을 차단하고 있다. Frida 스크립트를 작성하여 핀닝을 우회하고 API 응답에서 플래그를 획득하라.

### Frida 핀닝 우회 스크립트

```javascript
// ssl_pinning_bypass.js
// OkHttp3, TrustManager, WebViewClient 핀닝 우회

Java.perform(function() {
    console.log("[*] SSL Pinning Bypass 시작");

    // 1. TrustManager 우회 - 모든 인증서 신뢰
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.registerClass({
        name: "com.ctf.TrustAllCerts",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {
                console.log("[*] checkServerTrusted 우회");
            },
            getAcceptedIssuers: function() { return []; }
        }
    });

    var trustManagers = [TrustManager.$new()];
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustManagers, null);
    var sslSocketFactory = sslContext.getSocketFactory();

    // 2. OkHttp3 핀닝 우회
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
        OkHttpClient.certificatePinner.overload(
            "okhttp3.CertificatePinner"
        ).implementation = function(pinner) {
            console.log("[*] OkHttp3 CertificatePinner 우회");
            return this;
        };
    } catch(e) {
        console.log("[-] OkHttp3 없음: " + e.message);
    }

    // 3. WebViewClient 핀닝 우회
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[*] WebViewClient SSL 오류 무시");
            handler.proceed();
        };
    } catch(e) {
        console.log("[-] WebViewClient 오류: " + e.message);
    }

    console.log("[+] 핀닝 우회 완료 - Burp Suite로 트래픽 캡처 가능");
});
```

### 풀이 자동화 스크립트

```python
#!/usr/bin/env python3
"""Frida 기반 인증서 핀닝 우회 자동화 도구"""

import argparse
import subprocess
import time
from pathlib import Path


FRIDA_SCRIPT = """
Java.perform(function() {
    // TrustManager 우회
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustAll = Java.registerClass({
        name: "com.bypass.TrustAll_" + Date.now(),
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(c, a) {},
            checkServerTrusted: function(c, a) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustAll.$new()], null);

    send({type: "status", msg: "SSL Pinning bypassed"});

    // 네트워크 응답 후킹
    try {
        var OkHttpClient = Java.use("okhttp3.internal.http.RealInterceptorChain");
        OkHttpClient.proceed.overload("okhttp3.Request").implementation = function(req) {
            var response = this.proceed(req);
            var body = response.body().string();
            send({type: "response", url: req.url().toString(), body: body.substring(0, 500)});
            return response;
        };
    } catch(e) {}
});
"""


def run_frida_hook(
    package: str,
    script_path: str | None = None,
    device_id: str | None = None,
) -> None:
    """Frida 후킹 실행"""
    script_content = FRIDA_SCRIPT
    if script_path:
        with open(script_path) as f:
            script_content = f.read()

    tmp_script = Path("/tmp/frida_bypass.js")
    tmp_script.write_text(script_content)

    cmd = ["frida", "-U", "-f", package, "-l", str(tmp_script), "--no-pause"]
    if device_id:
        cmd.extend(["-D", device_id])

    print(f"[*] Frida 실행: {' '.join(cmd)}")
    print("[*] 핀닝 우회 후 Burp Suite 프록시로 트래픽 캡처")

    try:
        result = subprocess.run(cmd, timeout=30, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(f"[-] 오류: {result.stderr[:200]}")
    except FileNotFoundError:
        print("[-] frida 미설치. pip install frida-tools")
    except subprocess.TimeoutExpired:
        print("[*] Frida 세션 종료")


def list_running_apps(device_id: str | None = None) -> None:
    """실행 중인 앱 목록"""
    cmd = ["frida-ps", "-Ua"]
    if device_id:
        cmd.extend(["-D", device_id])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        print(result.stdout)
    except FileNotFoundError:
        print("[-] frida-ps 미설치")


def main() -> None:
    parser = argparse.ArgumentParser(description="SSL 핀닝 우회 도구")
    parser.add_argument("--package", "-p", help="앱 패키지명 (예: com.bank.app)")
    parser.add_argument("--script", "-s", help="커스텀 Frida 스크립트 경로")
    parser.add_argument("--device", "-d", help="ADB 디바이스 ID")
    parser.add_argument("--list", "-l", action="store_true", help="실행 중 앱 목록")
    args = parser.parse_args()

    if args.list:
        list_running_apps(args.device)
    elif args.package:
        run_frida_hook(args.package, args.script, args.device)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 실습 3: Android 백업 익스플로잇

### 목표

`adb backup`을 이용하여 Android 앱 데이터를 추출하고, SQLite 데이터베이스에서 플래그를 획득한다.

**플래그 형식**: `CTF{android_backup_db_extracted}`

### 시나리오

대상 앱이 `android:allowBackup="true"` 설정으로 빌드됐다. ADB 백업 기능을 악용하여 앱의 내부 데이터베이스를 추출하라.

### 풀이

```python
#!/usr/bin/env python3
"""Android 백업 분석 도구"""

import argparse
import os
import sqlite3
import struct
import subprocess
import zlib
from pathlib import Path


def extract_adb_backup(package: str, output_path: str = "backup.ab") -> bool:
    """ADB 백업 실행"""
    print(f"[*] ADB 백업 시작: {package}")
    print("[*] 기기에서 백업 허용 버튼을 클릭하세요...")

    cmd = ["adb", "backup", "-noapk", "-nosystem", package, "-f", output_path]
    try:
        subprocess.run(cmd, timeout=60)
        return Path(output_path).exists()
    except FileNotFoundError:
        print("[-] adb 미설치")
        return False
    except subprocess.TimeoutExpired:
        print("[-] 백업 시간 초과")
        return False


def decode_backup(backup_path: str, output_dir: str) -> bool:
    """Android 백업 파일(.ab) 디코딩"""
    # .ab 파일 = "ANDROID BACKUP\n" 헤더 + zlib 압축 데이터 + tar 아카이브
    with open(backup_path, "rb") as f:
        data = f.read()

    # 헤더 파싱
    lines = data.split(b"\n", 6)
    if len(lines) < 5:
        print("[-] 유효하지 않은 백업 파일")
        return False

    header = lines[0].decode("ascii", errors="ignore")
    if "ANDROID BACKUP" not in header:
        print(f"[-] 헤더 오류: {header}")
        return False

    version = int(lines[1].decode().strip())
    compressed = int(lines[2].decode().strip())

    print(f"[*] 백업 버전: {version}, 압축: {compressed}")

    # 실제 데이터 추출 (헤더 이후)
    header_end = data.index(b"\n", data.index(b"\n", data.index(b"\n", 0)+1)+1) + 1
    payload = data[header_end:]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if compressed == 1:
        try:
            decompressed = zlib.decompress(payload)
            tar_path = output_path / "backup.tar"
            tar_path.write_bytes(decompressed)
            print(f"[+] tar 아카이브 추출: {tar_path}")

            subprocess.run(["tar", "-xf", str(tar_path), "-C", str(output_path)])
            return True
        except zlib.error as e:
            print(f"[-] 압축 해제 실패: {e}")

    return False


def find_sqlite_databases(base_dir: str) -> list[Path]:
    """SQLite 데이터베이스 파일 탐색"""
    db_files: list[Path] = []
    for p in Path(base_dir).rglob("*.db"):
        db_files.append(p)
    for p in Path(base_dir).rglob("*.sqlite"):
        db_files.append(p)
    return db_files


def dump_database(db_path: Path) -> None:
    """SQLite DB 내용 덤프 및 플래그 탐색"""
    print(f"\n[*] DB 분석: {db_path.name}")
    import re

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f"  테이블: {[t[0] for t in tables]}")

        for (table,) in tables:
            try:
                cursor.execute(f"SELECT * FROM {table} LIMIT 20")
                rows = cursor.fetchall()
                for row in rows:
                    row_str = str(row)
                    flags = re.findall(r"CTF\{[^}]+\}", row_str)
                    if flags:
                        print(f"  [+] 플래그 발견 in {table}: {flags}")
                    elif any(
                        kw in row_str.lower() for kw in
                        ["secret", "password", "token", "key", "flag"]
                    ):
                        print(f"  [!] 민감 데이터 in {table}: {row_str[:100]}")
            except sqlite3.Error:
                pass

        conn.close()
    except sqlite3.Error as e:
        print(f"  [-] DB 오류: {e}")


def simulate_backup_analysis() -> None:
    """백업 분석 시뮬레이션 (실제 기기 없이)"""
    # 시뮬레이션용 SQLite DB 생성
    Path("/tmp/backup_sim/databases").mkdir(parents=True, exist_ok=True)
    db_path = "/tmp/backup_sim/databases/app_data.db"

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_prefs "
        "(key TEXT, value TEXT)"
    )
    conn.execute(
        "INSERT INTO user_prefs VALUES "
        "('flag', 'CTF{android_backup_db_extracted}')"
    )
    conn.execute("INSERT INTO user_prefs VALUES ('auth_token', 'Bearer abc123xyz')")
    conn.execute("INSERT INTO user_prefs VALUES ('user_id', '12345')")
    conn.commit()
    conn.close()

    print("[*] 시뮬레이션 DB 생성 완료")
    dump_database(Path(db_path))


def main() -> None:
    parser = argparse.ArgumentParser(description="Android 백업 분석 도구")
    parser.add_argument("--package", "-p", help="백업할 앱 패키지명")
    parser.add_argument("--analyze", "-a", help="분석할 백업 파일 또는 추출 디렉토리")
    parser.add_argument("--simulate", action="store_true", help="시뮬레이션 모드")
    args = parser.parse_args()

    if args.simulate:
        simulate_backup_analysis()
    elif args.package:
        if extract_adb_backup(args.package):
            decode_backup("backup.ab", "backup_extracted/")
            dbs = find_sqlite_databases("backup_extracted/")
            for db in dbs:
                dump_database(db)
    elif args.analyze:
        dbs = find_sqlite_databases(args.analyze)
        for db in dbs:
            dump_database(db)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Mobile Hacking CTF Practice Lab

## Lab Environment Setup

```bash
# Install analysis tools
pip install androguard frida-tools objection
sudo apt install -y apktool adb

# Start emulator or connect physical device
emulator -avd Pixel_6 -no-snapshot &
adb wait-for-device
```

---

## Challenge 1: APK Reverse Engineering

### Objective

Reverse engineer an Android APK to extract hardcoded secrets and the hidden flag.

**Flag format**: `CTF{apk_<secret_type>_extracted}`

### Solution Steps

```bash
# Generate sample APK
python3 create_apk.py
# Output: apk-samples/ctfbank_v2.1.0.apk

# Option 1: Automated analysis
python3 apk_analyzer.py apk-samples/ctfbank_v2.1.0.apk
# Finds: CTF{apk_hardcoded_api_key_extracted}

# Option 2: Manual decompilation
apktool d ctfbank_v2.1.0.apk -o decompiled/
grep -r "CTF{" decompiled/
grep -r "API_KEY\|SECRET" decompiled/smali/

# Option 3: jadx GUI
jadx-gui ctfbank_v2.1.0.apk
# Search for "CTF" in Find Class/Method dialog
```

### Key Findings

| File | Secret Type | Value |
|------|-------------|-------|
| `MainActivity.java` | API Key | `sk-bank-prod-9f8e7d...` |
| `MainActivity.java` | Flag | `CTF{apk_hardcoded_api_key_extracted}` |
| `strings.xml` | Auth Token | `Bearer eyJhbGci...` |

---

## Challenge 2: Certificate Pinning Bypass

### Objective

Use Frida to bypass SSL/TLS certificate pinning and intercept HTTPS traffic.

**Flag format**: `CTF{pinning_bypass_<method>_traffic_intercepted}`

### Setup

```bash
# Push Frida server to device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Configure Burp Suite proxy:
# Proxy → Options → Add listener on 0.0.0.0:8080

# Set Android proxy to Burp
adb shell settings put global http_proxy <host-ip>:8080
```

### Frida Bypass

```bash
# List apps
python3 ssl_bypass.py --list

# Bypass pinning for target app
python3 ssl_bypass.py --package com.ctfbank.app

# Or use objection (one-liner)
objection -g com.ctfbank.app explore
# android sslpinning disable

# After bypass, intercept traffic in Burp Suite
# Flag embedded in API response: CTF{pinning_bypass_frida_traffic_intercepted}
```

---

## Challenge 3: Android Backup Exploitation

### Objective

Exploit `android:allowBackup="true"` to extract app data and find the flag in a SQLite database.

**Flag format**: `CTF{android_backup_db_extracted}`

### Solution Steps

```bash
# Method 1: ADB backup (requires physical/emulated device)
python3 backup_exploit.py --package com.ctfbank.app

# Method 2: Simulation (no device needed)
python3 backup_exploit.py --simulate
# Directly creates and dumps the SQLite DB
# Finds: CTF{android_backup_db_extracted}

# Manual approach:
adb backup -noapk com.ctfbank.app -f backup.ab
# Decode .ab file (Java tool: android-backup-extractor)
java -jar abe.jar unpack backup.ab backup.tar
tar -xf backup.tar
find . -name "*.db" -exec sqlite3 {} "SELECT * FROM user_prefs;" \;
```
