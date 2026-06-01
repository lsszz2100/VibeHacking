> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 모바일 앱 보안 테스트 — 자동화 분석·런타임 후킹·API 감사

## 1. 모바일 앱 테스트 방법론

```
모바일 앱 보안 테스트
    │
    ├── 정적 분석
    │     - APK/IPA 언패킹
    │     - 소스코드 디컴파일
    │     - 하드코딩 자격증명·API 키
    │     - AndroidManifest / Info.plist 분석
    │
    ├── 동적 분석
    │     - 런타임 Frida 후킹
    │     - 트래픽 인터셉트 (Burp Suite)
    │     - 인증서 고정 우회
    │
    └── API 감사
          - 엔드포인트 추출 (JS/소스)
          - 인증 토큰 재사용
          - IDOR / 권한 우회
```

---

## 2. APK 자동 정적 분석

```python
#!/usr/bin/env python3
"""APK 정적 분석 — 권한·하드코딩 시크릿·취약 설정 탐지."""

import argparse
import json
import re
import subprocess
import zipfile
from pathlib import Path


SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API 키"),
    (r'(?i)password\s*[=:]\s*["\']([^"\']{6,})["\']', "패스워드"),
    (r'(?i)secret\s*[=:]\s*["\']([^"\']{8,})["\']', "시크릿"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'(?i)firebase.*["\']([A-Za-z0-9_-]{39})["\']', "Firebase 키"),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "개인키"),
    (r'https?://[a-zA-Z0-9._-]+\.(internal|local|corp)\b', "내부 엔드포인트"),
]

DANGEROUS_PERMISSIONS: list[str] = [
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
]


def extract_apk(apk_path: Path, out_dir: Path) -> bool:
    try:
        with zipfile.ZipFile(apk_path) as zf:
            zf.extractall(out_dir)
        return True
    except zipfile.BadZipFile:
        return False


def decompile_apk(apk_path: Path, out_dir: Path) -> bool:
    """jadx로 APK 디컴파일."""
    try:
        result = subprocess.run(
            ["jadx", "-d", str(out_dir), str(apk_path)],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("jadx 설치 필요: https://github.com/skylot/jadx")
        return False


def parse_manifest(manifest_path: Path) -> dict:
    """AndroidManifest.xml 분석."""
    import xml.etree.ElementTree as ET

    result = {
        "package": "",
        "permissions": [],
        "dangerous_permissions": [],
        "exported_components": [],
        "debuggable": False,
        "backup_allowed": False,
    }

    try:
        content = manifest_path.read_text(errors="ignore")
        tree = ET.fromstring(content)

        ns = {"android": "http://schemas.android.com/apk/res/android"}
        result["package"] = tree.get("package", "")

        # 디버그 모드
        app = tree.find("application")
        if app is not None:
            result["debuggable"] = app.get("{http://schemas.android.com/apk/res/android}debuggable", "false") == "true"
            result["backup_allowed"] = app.get("{http://schemas.android.com/apk/res/android}allowBackup", "true") == "true"

        # 권한
        for perm in tree.findall("uses-permission"):
            perm_name = perm.get("{http://schemas.android.com/apk/res/android}name", "")
            result["permissions"].append(perm_name)
            if perm_name in DANGEROUS_PERMISSIONS:
                result["dangerous_permissions"].append(perm_name)

        # 외부 노출 컴포넌트
        for tag in ["activity", "service", "receiver", "provider"]:
            for elem in tree.iter(tag):
                exported = elem.get("{http://schemas.android.com/apk/res/android}exported", "")
                if exported == "true":
                    name = elem.get("{http://schemas.android.com/apk/res/android}name", "")
                    result["exported_components"].append({"type": tag, "name": name})

    except Exception as e:
        result["parse_error"] = str(e)

    return result


def scan_secrets(search_dir: Path) -> list[dict]:
    """디컴파일된 소스에서 민감 정보 탐지."""
    findings = []

    for filepath in search_dir.rglob("*"):
        if not filepath.is_file():
            continue
        if filepath.suffix not in (".java", ".kt", ".xml", ".json", ".properties", ".gradle"):
            continue

        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            continue

        for pattern, label in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "file": str(filepath.relative_to(search_dir)),
                    "type": label,
                    "count": len(matches),
                    "sample": str(matches[0])[:60],
                })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="APK 정적 분석")
    sub = parser.add_subparsers(dest="cmd", required=True)

    analyze_p = sub.add_parser("analyze", help="APK 전체 분석")
    analyze_p.add_argument("apk", type=Path)
    analyze_p.add_argument("-o", "--output", type=Path, default=Path("./apk_analysis"))

    secrets_p = sub.add_parser("secrets", help="디컴파일 디렉터리 시크릿 스캔")
    secrets_p.add_argument("dir", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "analyze":
            out_dir = args.output
            out_dir.mkdir(parents=True, exist_ok=True)

            print(f"[*] APK 분석: {args.apk.name}")

            # 압축 해제
            raw_dir = out_dir / "raw"
            extract_apk(args.apk, raw_dir)

            # 디컴파일
            src_dir = out_dir / "source"
            decompile_apk(args.apk, src_dir)

            # 매니페스트 분석
            manifest = raw_dir / "AndroidManifest.xml"
            if manifest.exists():
                manifest_result = parse_manifest(manifest)
                print(f"\n패키지: {manifest_result['package']}")
                print(f"디버그 모드: {manifest_result['debuggable']}")
                print(f"백업 허용: {manifest_result['backup_allowed']}")
                print(f"위험 권한 {len(manifest_result['dangerous_permissions'])}개: "
                      f"{manifest_result['dangerous_permissions'][:3]}")
                print(f"외부 노출 컴포넌트: {len(manifest_result['exported_components'])}개")

            # 시크릿 스캔
            if src_dir.exists():
                secrets = scan_secrets(src_dir)
                if secrets:
                    print(f"\n[!] 민감 정보 {len(secrets)}개:")
                    for s in secrets:
                        print(f"  [{s['type']}] {s['file']}: {s['sample']}")

        case "secrets":
            secrets = scan_secrets(args.dir)
            for s in secrets:
                print(f"[{s['type']}] {s['file']}: {s['sample']}")


if __name__ == "__main__":
    main()
```

---

## 3. Frida 런타임 후킹

```javascript
// frida_hooks.js — SSL 핀닝 우회 + 민감 API 모니터링

// SSL 핀닝 우회 (Android)
Java.perform(function() {
    // TrustManager 우회
    var TrustManager = Java.registerClass({
        name: 'com.hook.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
        this.init(km, [TrustManager.$new()], sr);
    };

    console.log('[+] SSL 핀닝 우회 완료');

    // SharedPreferences 모니터링 (저장된 자격증명 탐지)
    var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferences.getString.overload('java.lang.String', 'java.lang.String')
    .implementation = function(key, defVal) {
        var result = this.getString(key, defVal);
        if (key.toLowerCase().includes('password') ||
            key.toLowerCase().includes('token') ||
            key.toLowerCase().includes('secret')) {
            console.log('[SharedPrefs] ' + key + ' = ' + result);
        }
        return result;
    };

    // WebView URL 모니터링
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[WebView] URL: ' + url);
        return this.loadUrl(url);
    };
});
```

```python
#!/usr/bin/env python3
"""Frida 기반 모바일 앱 동적 분석 자동화."""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def list_apps(device: str = "usb") -> list[dict]:
    """연결된 디바이스의 앱 목록."""
    try:
        result = subprocess.run(
            ["frida-ps", f"-{device[0]}", "-a"],
            capture_output=True, text=True, timeout=10,
        )
        apps = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                apps.append({"pid": parts[0], "name": parts[1]})
        return apps
    except FileNotFoundError:
        print("frida-tools 설치 필요: pip install frida-tools")
        return []


def inject_script(
    package: str,
    script_path: Path,
    device: str = "usb",
    spawn: bool = True,
) -> None:
    """Frida 스크립트 주입."""
    cmd = ["frida"]
    cmd += [f"-{device[0]}"]

    if spawn:
        cmd += ["-f", package, "--no-pause"]
    else:
        cmd += ["-n", package]

    cmd += ["-l", str(script_path)]

    print(f"[*] {package} 에 스크립트 주입 중...")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[*] 중단")
    except FileNotFoundError:
        print("frida 설치 필요")


def main() -> None:
    parser = argparse.ArgumentParser(description="Frida 모바일 동적 분석")
    sub = parser.add_subparsers(dest="cmd", required=True)

    list_p = sub.add_parser("list", help="앱 목록")
    list_p.add_argument("--device", default="usb", choices=["usb", "remote"])

    inject_p = sub.add_parser("inject", help="스크립트 주입")
    inject_p.add_argument("package", help="패키지명 (예: com.example.app)")
    inject_p.add_argument("script", type=Path, help="Frida JS 스크립트")
    inject_p.add_argument("--no-spawn", action="store_true")

    ssl_p = sub.add_parser("ssl-bypass", help="SSL 핀닝 우회")
    ssl_p.add_argument("package")

    args = parser.parse_args()

    match args.cmd:
        case "list":
            apps = list_apps(args.device)
            for app in apps:
                print(f"  PID {app['pid']}: {app['name']}")

        case "inject":
            inject_script(args.package, args.script, spawn=not args.no_spawn)

        case "ssl-bypass":
            # 내장 SSL 우회 스크립트 생성 후 주입
            script = Path("/tmp/ssl_bypass.js")
            script.write_text("""
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var TrustManager = Java.registerClass({
        name: 'com.hook.TM', implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: { checkClientTrusted: function(){}, checkServerTrusted: function(){},
                   getAcceptedIssuers: function(){ return []; } }
    });
    Java.use('javax.net.ssl.SSLContext').init.overload(
        '[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom'
    ).implementation = function(a,b,c){ this.init(a,[TrustManager.$new()],c); };
    console.log('[+] SSL bypass active');
});
""")
            inject_script(args.package, script)


if __name__ == "__main__":
    main()
```

---

## 4. 모바일 보안 테스트 요약

| 테스트 항목 | 도구 | 탐지 대상 |
|-------------|------|-----------|
| APK 디컴파일 | jadx, apktool | 하드코딩 자격증명, API 키 |
| 런타임 후킹 | Frida | SSL 핀닝, 암호화 함수 |
| 트래픽 분석 | Burp Suite + ProxyDroid | API 엔드포인트, 토큰 |
| 인증서 고정 | frida-ssl-pinning-bypass | 핀닝 우회 |
| 저장소 분석 | adb shell | SharedPreferences, SQLite |
| OWASP MASVS | MobSF | 자동 정적+동적 분석 |

---

<a name="english"></a>

# Mobile App Security Testing — Automated Analysis, Runtime Hooking, API Auditing

## 1. Mobile App Testing Methodology

Key testing areas for mobile application security:

- **OWASP MASVS**: Mobile Application Security Verification Standard
- **Static analysis**: Source code, binary, configuration
- **Dynamic analysis**: Runtime behavior, network traffic
- **API security**: Authentication, authorization, data exposure

## Key Testing Tools Summary

| Testing Area | Tool | Method |
|-------------|------|--------|
| Runtime hooking | Frida | SSL pinning, encryption functions |
| Traffic analysis | Burp Suite + ProxyDroid | API endpoints, tokens |
| Certificate pinning | frida-ssl-pinning-bypass | Bypass pinning |
| Storage analysis | adb shell | SharedPreferences, SQLite |
| OWASP MASVS | MobSF | Automated static+dynamic analysis |

## Common Vulnerabilities

- **Insecure data storage**: Sensitive data in SharedPreferences, SQLite, log files
- **Broken authentication**: Weak token handling, no expiry
- **Insufficient cryptography**: Weak algorithms, hardcoded keys
- **Client-side injection**: SQLite injection, JavaScript injection in WebViews
- **Improper session handling**: Token reuse, inadequate logout
