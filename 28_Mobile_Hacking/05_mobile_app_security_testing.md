> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 모바일 앱 보안 테스트 — 자동화 분석·런타임 후킹·API 감사

## 0. 초보자를 위한 개념 이해

### 모바일 앱 보안 테스트란?

모바일 앱 보안 테스트는 앱의 설계부터 구현, 배포까지 전 과정에서 보안 취약점을 찾아내는 체계적인 평가 과정이다. OWASP Mobile Security Testing Guide(MSTG)라는 국제 표준 방법론을 따르며, 정적/동적 분석, 네트워크 분석, API 테스트를 모두 포함한다. 앱 출시 전 보안 검증이나 버그 바운티 프로그램에 필수적이다.

**왜 배우는가:**
```
모바일 앱 보안 테스트의 중요성

출시 전 미발견 시 결과:
  하드코딩 API 키     → 서버 비용 폭발, 데이터 유출
  평문 데이터 저장    → 기기 분실 시 개인정보 유출
  취약한 인증         → 다른 사용자 계정 접근
  인증서 미검증       → 공공 Wi-Fi에서 자격증명 탈취

체계적 테스트로 방지 가능:
  OWASP Mobile Top 10 기준 → 99% 이상의 일반 취약점 포괄
```

### 핵심 개념 정리

```
모바일 앱 보안 테스트 체계

테스트 종류    도구                   목표
──────────────────────────────────────────────────
정적 분석      MobSF, jadx, apktool   코드·설정 취약점
동적 분석      Frida, objection       런타임 행위
네트워크 분석  Burp Suite, mitmproxy  API 취약점
데이터 분석    SQLite 브라우저, adb    저장 데이터 보안
```

### 필요한 도구 및 환경
- **MobSF**: 통합 정적/동적 분석 플랫폼 (Docker 권장)
- **objection**: `pip install objection` (Frida 기반 올인원)
- **Frida**: `pip install frida-tools`
- **Burp Suite**: HTTPS 프록시 (무료 커뮤니티 에디션)

### 기초 실습 예제
```bash
# 1. MobSF 실행 (Docker)
docker run -it --rm -p 8000:8000 \
    opensecurity/mobile-security-framework-mobsf:latest
# → http://localhost:8000 에서 APK/IPA 업로드 후 자동 분석

# 2. objection으로 런타임 분석 시작
# (에뮬레이터 또는 탈옥 기기에서 앱 실행 후)
objection -g com.example.app explore

# objection 명령어:
# android sslpinning disable          # SSL 핀닝 우회
# android hooking list activities     # 액티비티 목록
# android hooking list services       # 서비스 목록
# android intent launch_activity com.example.app.AdminActivity

# 3. 로컬 데이터베이스 확인 (adb)
adb shell
run-as com.example.app
ls databases/
sqlite3 databases/user_data.db
.tables
SELECT * FROM credentials;  # 평문 저장 여부 확인
```

---

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

## 2. OWASP Mobile Top 10 (2024) — 완전 해설

OWASP(Open Web Application Security Project)는 모바일 앱에서 가장 많이 발견되는 10가지 취약점을 정리한 **Mobile Top 10** 목록을 발표한다. 2024년 업데이트에서는 AI·생체인증 관련 위협이 새로 추가됐다.

### 현실 비유: 집에 잠금장치가 없는 것

모바일 앱 취약점을 집에 비유하면 이해하기 쉽다:
- 잠금장치 없는 현관문 = 인증 없는 엔드포인트
- 창문에 붙여놓은 집 열쇠 = 하드코딩 비밀키
- 도어캠 영상을 아무나 볼 수 있음 = 암호화 없는 로컬 데이터

```
OWASP Mobile Top 10 (2024)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
M1  부적절한 자격증명 관리   API 키, 토큰을 코드/파일에 하드코딩
M2  불충분한 공급망 보안     악성 SDK, 오염된 라이브러리
M3  안전하지 않은 인증/인가  약한 토큰, 바이오메트릭 우회
M4  불충분한 입력/출력 검증  SQLi, XSS in WebView, Path traversal
M5  안전하지 않은 통신       자가 서명 인증서, 핀닝 없음
M6  부적절한 프라이버시 제어  과도한 권한, 민감 데이터 전송
M7  불충분한 바이너리 보호   루팅 탐지 없음, 디버그 가능
M8  보안 설정 오류           AndroidManifest exported=true 남용
M9  안전하지 않은 데이터 저장 SharedPrefs/SQLite 평문 저장
M10 불충분한 암호화          약한 알고리즘, 하드코딩 IV/키
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### M1 — 부적절한 자격증명 관리

가장 흔한 취약점. 개발자가 API 키를 strings.xml, BuildConfig, 또는 Java/Kotlin 소스 파일에 직접 써넣는다.

```java
// 취약한 코드 예시 (실제로 이런 코드가 APK에 남음)
private static final String API_KEY = "FAKE_API_KEY_HARDCODED_DEMO_ONLY";
private static final String DB_PASSWORD = "mySecretPass123";
private static final String FIREBASE_KEY = "AIzaSy...";
```

**왜 위험한가**: APK는 ZIP 파일이다. jadx나 apktool로 누구나 5분 안에 디컴파일할 수 있다.

### M5 — 안전하지 않은 통신 (인증서 핀닝)

일반 HTTPS는 Man-in-the-Middle 공격에 취약하다. 공격자가 Burp Suite 인증서를 디바이스에 설치하면 모든 트래픽을 볼 수 있다.

**인증서 핀닝**은 앱이 특정 인증서 지문만 신뢰하도록 강제하는 방어 기법이다.

```
핀닝 없을 때:                    핀닝 있을 때:
앱 → 서버: 아무 인증서 신뢰     앱 → 서버: 하드코딩 지문만 신뢰
     ↑                                ↑
   Burp가 중간에서 가로챔          Burp 인증서 거부 → 앱 종료
```

### M9 — 안전하지 않은 데이터 저장

```
Android 앱이 민감 데이터를 저장하는 위치:
┌────────────────────────────────────────────────┐
│ /data/data/com.example.app/                    │
│   shared_prefs/user_prefs.xml  ← 토큰, 패스워드 │
│   databases/app.db             ← SQLite        │
│   cache/                       ← 임시 파일      │
│   files/                       ← 다운로드 파일  │
└────────────────────────────────────────────────┘

루팅된 기기 or adb backup으로 모두 추출 가능
```

---

## 3. 정적 분석 vs 동적 분석 비교

| 항목 | 정적 분석 | 동적 분석 |
|------|-----------|-----------|
| 분석 시점 | 실행 전 | 실행 중 |
| 필요 장비 | 컴퓨터만 | 실제 기기/에뮬레이터 |
| 발견 취약점 | 하드코딩, 취약 API 호출, 설정 오류 | 런타임 암호화, 실제 API 통신 |
| 난독화 우회 | 어려움 | 쉬움 (메모리에서 복호화됨) |
| 주요 도구 | jadx, apktool, MobSF, semgrep | Frida, Burp Suite, objection |
| 소요 시간 | 빠름 (자동화 가능) | 느림 (수동 탐색 필요) |
| 루팅/탈옥 필요 | 불필요 | 종종 필요 |
| 장점 | 전체 코드 스캔 가능 | 실제 동작 확인 가능 |
| 단점 | 동적 생성 코드 놓침 | 커버리지 제한 |

---

## 4. MobSF 설치 및 사용 튜토리얼

MobSF(Mobile Security Framework)는 오픈소스 자동 모바일 앱 분석 도구로, 정적·동적 분석을 모두 지원한다.

### 4.1 설치

```bash
# Docker로 빠르게 설치 (추천)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 \
  -v /path/to/apks:/home/mobsf/.MobSF/uploads \
  opensecurity/mobile-security-framework-mobsf

# 직접 설치 (Python 3.10+)
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

### 4.2 API를 통한 자동 분석

```python
#!/usr/bin/env python3
"""
mobsf_auto.py — MobSF REST API를 사용한 APK 배치 분석 자동화
사용: python3 mobsf_auto.py scan ./apks/ --format json
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

MOBSF_URL = "http://localhost:8000"
MOBSF_KEY = "your_api_key_here"  # MobSF UI에서 확인


def upload_apk(apk_path: Path, session: requests.Session) -> str | None:
    """APK 업로드 후 해시 반환."""
    with open(apk_path, "rb") as f:
        resp = session.post(
            f"{MOBSF_URL}/api/v1/upload",
            files={"file": (apk_path.name, f, "application/octet-stream")},
        )
    if resp.status_code == 200:
        return resp.json().get("hash")
    print(f"[!] 업로드 실패: {resp.status_code}", file=sys.stderr)
    return None


def trigger_scan(file_hash: str, session: requests.Session) -> bool:
    """정적 분석 실행."""
    resp = session.post(
        f"{MOBSF_URL}/api/v1/scan",
        data={"hash": file_hash, "scan_type": "apk"},
    )
    return resp.status_code == 200


def get_report(file_hash: str, session: requests.Session) -> dict:
    """분석 리포트 JSON 반환."""
    resp = session.post(
        f"{MOBSF_URL}/api/v1/report_json",
        data={"hash": file_hash},
    )
    if resp.status_code == 200:
        return resp.json()
    return {}


def extract_findings(report: dict) -> dict:
    """리포트에서 핵심 취약점만 추출."""
    findings = {
        "app_name": report.get("app_name", "Unknown"),
        "package": report.get("package_name", ""),
        "security_score": report.get("average_cvss", 0),
        "critical_issues": [],
        "high_issues": [],
        "permissions": report.get("permissions", {}),
    }

    # 취약한 API 호출
    for vuln in report.get("android_api", {}).values():
        severity = vuln.get("severity", "")
        desc = vuln.get("description", "")
        if severity == "high":
            findings["high_issues"].append(desc)

    # 하드코딩 시크릿
    secrets = report.get("secrets", [])
    if secrets:
        findings["critical_issues"].append(
            f"하드코딩 시크릿 {len(secrets)}개 발견"
        )

    # 인증서 핀닝
    if not report.get("network_security", {}).get("certificate_pinning"):
        findings["high_issues"].append("인증서 핀닝 없음")

    # 디버그 모드
    if report.get("manifest_analysis", {}).get("debuggable"):
        findings["critical_issues"].append("디버그 모드 활성화됨")

    return findings


def scan_batch(
    apk_dir: Path,
    output_format: str = "json",
) -> list[dict]:
    """디렉터리 내 모든 APK 배치 분석."""
    session = requests.Session()
    session.headers.update({"Authorization": MOBSF_KEY})

    apks = list(apk_dir.glob("*.apk"))
    if not apks:
        print(f"[!] {apk_dir}에 APK 파일 없음")
        return []

    results = []
    for i, apk in enumerate(apks, 1):
        print(f"[{i}/{len(apks)}] 분석 중: {apk.name}")

        file_hash = upload_apk(apk, session)
        if not file_hash:
            continue

        if not trigger_scan(file_hash, session):
            print(f"  [!] 스캔 트리거 실패")
            continue

        time.sleep(3)  # 분석 완료 대기
        report = get_report(file_hash, session)
        findings = extract_findings(report)
        findings["apk_file"] = apk.name
        results.append(findings)

        score = findings["security_score"]
        crit = len(findings["critical_issues"])
        high = len(findings["high_issues"])
        print(f"  점수: {score:.1f}/10 | 심각: {crit}개 | 높음: {high}개")

    return results


def print_summary(results: list[dict]) -> None:
    """분석 결과 요약 출력."""
    print("\n" + "=" * 60)
    print("MobSF 배치 분석 결과 요약")
    print("=" * 60)

    for r in sorted(results, key=lambda x: x["security_score"]):
        print(f"\n앱: {r['app_name']} ({r['apk_file']})")
        print(f"패키지: {r['package']}")
        print(f"보안 점수: {r['security_score']:.1f}/10")

        if r["critical_issues"]:
            print("  [심각]")
            for issue in r["critical_issues"]:
                print(f"    - {issue}")

        if r["high_issues"][:3]:
            print("  [높음]")
            for issue in r["high_issues"][:3]:
                print(f"    - {issue}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MobSF API 기반 APK 배치 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 mobsf_auto.py scan ./apks/
  python3 mobsf_auto.py scan ./apks/ --format json --output results.json
  python3 mobsf_auto.py scan ./apks/ --url http://192.168.1.10:8000
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="APK 디렉터리 스캔")
    scan_p.add_argument("directory", type=Path, help="APK 파일이 있는 디렉터리")
    scan_p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식",
    )
    scan_p.add_argument("--output", type=Path, help="결과 저장 파일")
    scan_p.add_argument("--url", default=MOBSF_URL, help="MobSF 서버 URL")
    scan_p.add_argument("--key", default=MOBSF_KEY, help="MobSF API 키")

    args = parser.parse_args()

    global MOBSF_URL, MOBSF_KEY
    MOBSF_URL = args.url
    MOBSF_KEY = args.key

    match args.cmd:
        case "scan":
            results = scan_batch(args.directory, args.format)

            if args.format == "json":
                output = json.dumps(results, ensure_ascii=False, indent=2)
                if args.output:
                    args.output.write_text(output)
                    print(f"[+] 결과 저장: {args.output}")
                else:
                    print(output)
            else:
                print_summary(results)


if __name__ == "__main__":
    main()
```

---

## 5. APK 자동 정적 분석

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

## 6. Frida 런타임 후킹

### 6.1 Frida란?

Frida는 앱이 실행 중일 때 코드를 **주입(inject)**해서 함수 호출을 가로채거나 변경하는 도구다. 앱을 수정하거나 재컴파일하지 않고도 동작한다.

현실 비유: 은행 금고 열쇠를 복사하는 대신, 금고 관리인이 열쇠를 꽂는 순간 뒤에서 동작을 관찰하는 것.

```
Frida 동작 원리:
┌─────────────────────────────────────────────────┐
│   Android 프로세스 (com.example.app)             │
│                                                 │
│   Java 런타임                                   │
│   ┌───────────────┐                             │
│   │  SSLContext   │ ← Frida가 init() 함수 후킹  │
│   │  .init()      │   → 신뢰 인증서 목록 교체   │
│   └───────────────┘                             │
│                                                 │
│   ↑ Frida Agent (frida-server)가 주입           │
└─────────────────────────────────────────────────┘
```

### 6.2 Frida 설치 및 기본 설정

```bash
# 호스트 PC에 frida-tools 설치
pip install frida-tools

# Android 기기에 frida-server 설치
# 1. 아키텍처 확인
adb shell getprop ro.product.cpu.abi
# 출력 예: arm64-v8a

# 2. https://github.com/frida/frida/releases 에서 맞는 버전 다운로드
# frida-server-16.x.x-android-arm64.xz

# 3. 기기에 업로드 및 실행
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# 4. 연결 확인
frida-ps -U  # USB 연결된 기기의 프로세스 목록
```

### 6.3 Frida 스크립트 예시

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

### 6.4 루트 탐지 우회 Frida 스크립트

루팅 탐지를 우회하면 루팅된 기기에서 앱을 정상적으로 실행할 수 있다.

```javascript
// root_bypass.js — 루트 탐지 우회
Java.perform(function() {
    // RootBeer, SafetyNet 등 루트 탐지 라이브러리 우회

    // 1. 파일 존재 확인 우회
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/su', '/system/xbin/su', '/sbin/su',
                         '/system/bin/su', '/magisk', '/.magisk'];
        if (rootPaths.some(p => path.includes(p))) {
            console.log('[Root Bypass] 차단: ' + path);
            return false;
        }
        return this.exists();
    };

    // 2. 루트 앱 패키지 탐지 우회
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int')
    .implementation = function(pkg, flags) {
        var rootPackages = ['com.topjohnwu.magisk', 'com.noshufou.android.su',
                            'eu.chainfire.supersu', 'com.koushikdutta.superuser'];
        if (rootPackages.includes(pkg)) {
            throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new();
        }
        return this.getPackageInfo(pkg, flags);
    };

    // 3. 빌드 태그 검사 우회
    var Build = Java.use('android.os.Build');
    var BuildTags = Build.TAGS.value;
    if (BuildTags && BuildTags.includes('test-keys')) {
        Build.TAGS.value = 'release-keys';
    }

    console.log('[+] 루트 탐지 우회 스크립트 로드 완료');
});
```

### 6.5 암호화 키 추출 스크립트

```javascript
// crypto_trace.js — 암호화/복호화 함수 추적으로 키 추출
Java.perform(function() {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String')
    .implementation = function(keyBytes, algorithm) {
        var keyHex = Array.from(keyBytes)
            .map(b => ('0' + (b & 0xff).toString(16)).slice(-2))
            .join('');
        console.log('[암호화 키] 알고리즘: ' + algorithm);
        console.log('[암호화 키] 키(hex): ' + keyHex);
        // 스택 트레이스로 어디서 키를 생성하는지 확인
        console.log('[스택] ' + Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new()));
        return this.$init(keyBytes, algorithm);
    };

    // AES 복호화 결과 출력
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(data) {
        var result = this.doFinal(data);
        try {
            var resultStr = Java.use('java.lang.String')
                .$new(result, 'UTF-8');
            console.log('[복호화 결과] ' + resultStr.substring(0, 200));
        } catch(e) {}
        return result;
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

    root_p = sub.add_parser("root-bypass", help="루트 탐지 우회")
    root_p.add_argument("package")

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

        case "root-bypass":
            script = Path("/tmp/root_bypass.js")
            script.write_text("""
Java.perform(function() {
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/su','/system/xbin/su','/magisk','/.magisk'];
        if (rootPaths.some(p => path.includes(p))) return false;
        return this.exists();
    };
    console.log('[+] Root detection bypass active');
});
""")
            inject_script(args.package, script)


if __name__ == "__main__":
    main()
```

---

## 6.5 루팅/탈옥 탐지 우회에 대한 서버측 무결성 검증 (Play Integrity / DeviceCheck)

앞서 본 Frida 훅으로 클라이언트 측 루팅 탐지는 대부분 우회 가능하다 — 앱이 스스로 "나는 루팅되지 않았다"고 판단하는 로직은 결국 그 판단 자체를 조작당할 수 있기 때문이다. 근본 대응은 **판단을 기기가 아니라 서버가 하도록** 옮기는 것이다. Android의 Play Integrity API와 iOS의 DeviceCheck/App Attest는 OS·하드웨어 수준에서 서명된 증명(attestation)을 생성해, 이를 서버가 구글/애플 서버에 직접 검증하도록 한다 — Frida가 앱 프로세스를 후킹해도 이 증명 자체는 위조할 수 없다(하드웨어 키로 서명되기 때문).

```kotlin
// Android 클라이언트 — Play Integrity API로 무결성 토큰 요청
val integrityManager = IntegrityManagerFactory.create(applicationContext)
val request = IntegrityTokenRequest.builder()
    .setNonce(serverProvidedNonce)  // 서버가 발급한 1회용 nonce (재전송 공격 방지)
    .build()

integrityManager.requestIntegrityToken(request)
    .addOnSuccessListener { response ->
        val token = response.token()
        // 이 토큰을 그대로 서버에 전송 — 클라이언트는 토큰 내용을 해석하지 않는다
        sendTokenToServer(token)
    }
```

```python
#!/usr/bin/env python3
"""서버 측 — Play Integrity 토큰을 구글 API로 검증 (앱 신뢰 여부는 여기서 최종 판단)."""
import requests


def verify_integrity_token(token: str, package_name: str, access_token: str) -> dict:
    url = (
        f"https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken"
    )
    resp = requests.post(
        url,
        json={"integrity_token": token},
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    result = resp.json().get("tokenPayloadExternal", {})

    device_verdict = result.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
    app_verdict = result.get("appIntegrity", {}).get("appRecognitionVerdict")

    is_trusted = "MEETS_DEVICE_INTEGRITY" in device_verdict and app_verdict == "PLAY_RECOGNIZED"
    return {"trusted": is_trusted, "device": device_verdict, "app": app_verdict}


if __name__ == "__main__":
    result = verify_integrity_token("TOKEN_FROM_CLIENT", "com.example.app", "SERVER_ACCESS_TOKEN")
    print(f"[{'+' if result['trusted'] else '!'}] 무결성 검증: {result}")
```

**핵심**: 클라이언트 측 루팅 탐지(이 절 위쪽 내용)는 사용자 경험 저하 없이 대략적인 위험 신호를 걸러내는 1차 필터 정도로만 쓰고, 결제·계정 보안 같은 진짜 민감한 로직의 신뢰 판단은 반드시 **서버가 Play Integrity/DeviceCheck 토큰을 직접 검증한 결과**에 근거해야 한다. nonce를 서버가 매 요청마다 새로 발급해야 재전송(replay) 공격도 막을 수 있다.

---

## 7. ADB 커맨드 치트시트 (초보자용)

ADB(Android Debug Bridge)는 컴퓨터와 안드로이드 기기 사이를 연결하는 도구다.

```bash
# ===== 기기 연결 확인 =====
adb devices                         # 연결된 기기 목록
adb connect 192.168.1.100:5555      # WiFi ADB 연결
adb -s SERIAL shell                 # 특정 기기에 쉘 접속

# ===== 앱 관리 =====
adb install app.apk                 # APK 설치
adb install -r app.apk              # 재설치 (데이터 유지)
adb uninstall com.example.app       # 앱 제거
adb shell pm list packages          # 설치된 앱 패키지 목록
adb shell pm list packages -3       # 서드파티 앱만
adb shell pm path com.example.app   # 앱 APK 경로 확인

# ===== APK 추출 =====
adb shell pm path com.example.app
# 출력: package:/data/app/com.example.app-1/base.apk
adb pull /data/app/com.example.app-1/base.apk ./target.apk

# ===== 데이터 탐색 (루팅 필요) =====
adb shell run-as com.example.app    # 앱 권한으로 쉘 (비루팅)
adb shell
su                                  # 루트 전환
ls /data/data/com.example.app/      # 앱 데이터 디렉터리

# SharedPreferences 확인
cat /data/data/com.example.app/shared_prefs/user_prefs.xml

# SQLite DB 확인
sqlite3 /data/data/com.example.app/databases/app.db
.tables
SELECT * FROM users;

# ===== 로그 확인 =====
adb logcat                          # 전체 로그
adb logcat | grep com.example.app   # 특정 앱 로그
adb logcat -s "MyApp"               # 태그 필터
adb logcat *:E                      # 에러만

# ===== 파일 전송 =====
adb push local_file /sdcard/
adb pull /sdcard/remote_file ./

# ===== 네트워크 =====
adb shell netstat -tlnp             # 열린 포트 확인
adb shell cat /proc/net/tcp         # TCP 연결
adb forward tcp:8080 tcp:8080       # 포트 포워딩 (PC → 기기)
adb reverse tcp:8080 tcp:8080       # 역방향 포워딩

# ===== 스크린샷/녹화 =====
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png
adb shell screenrecord /sdcard/video.mp4

# ===== 인텐트 실행 =====
adb shell am start -n com.example.app/.MainActivity
adb shell am start -a android.intent.action.VIEW -d "http://evil.com"

# ===== 백업 (루팅 없이 데이터 추출) =====
adb backup -f backup.ab -apk -shared com.example.app
# backup.ab를 ABE(Android Backup Extractor)로 변환
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar
```

---

## 8. MSTG 체크리스트

OWASP MSTG(Mobile Security Testing Guide) 기반 최소 점검 항목:

```
MSTG 체크리스트 (Android)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

정적 분석:
[ ] AndroidManifest.xml
    [ ] android:debuggable="false"
    [ ] android:allowBackup="false" (민감 앱)
    [ ] exported 컴포넌트에 권한 설정 확인
    [ ] 최소 권한 원칙 (불필요한 권한 제거)

[ ] 코드 분석
    [ ] 하드코딩 자격증명/API 키 없음
    [ ] 취약한 암호화 알고리즘 없음 (MD5, DES, ECB 모드)
    [ ] 로그에 민감 정보 출력 안 함
    [ ] WebView.setJavaScriptEnabled(true) + addJavascriptInterface 조합 없음

동적 분석:
[ ] 네트워크
    [ ] 인증서 핀닝 구현 및 정상 동작
    [ ] HTTPS 전용 통신 (HTTP 없음)
    [ ] 민감 데이터 쿼리스트링에 없음

[ ] 저장소
    [ ] SharedPreferences 암호화 여부
    [ ] SQLite DB 암호화 여부
    [ ] 외부 저장소(SD카드)에 민감 데이터 없음
    [ ] 로그/임시 파일에 민감 데이터 없음

[ ] 인증
    [ ] 토큰 만료 처리
    [ ] 로그아웃 시 서버 세션 무효화
    [ ] 생체인증 우회 불가

[ ] 바이너리 보호
    [ ] 루팅/탈옥 탐지
    [ ] 에뮬레이터 탐지 (선택)
    [ ] 코드 난독화 적용
    [ ] 무결성 검사
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 9. 모바일 보안 테스트 요약

| 테스트 항목 | 도구 | 탐지 대상 |
|-------------|------|-----------|
| APK 디컴파일 | jadx, apktool | 하드코딩 자격증명, API 키 |
| 런타임 후킹 | Frida | SSL 핀닝, 암호화 함수 |
| 트래픽 분석 | Burp Suite + ProxyDroid | API 엔드포인트, 토큰 |
| 인증서 고정 | frida-ssl-pinning-bypass | 핀닝 우회 |
| 저장소 분석 | adb shell | SharedPreferences, SQLite |
| OWASP MASVS | MobSF | 자동 정적+동적 분석 |

---

<!-- detect-validate-28 -->
## 모바일 앱 보안 테스트 작동 검증과 회귀

보안 테스트는 *돌렸다*가 아니라 *취약을 실제로 잡고 오탐을 거르는가*로 가치가 갈린다. 방어자는 **자동 분석·런타임 후킹·API 감사가 발화·재현되는가**를 검증해야 한다. 검증은 **소유 앱**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 정적 분석(MobSF) | 취약에 발화하나? | 검출 vs 알려진 결함 | 룰 미갱신 |
| 런타임 후킹 | 핀/루팅탐지 우회되나? | 후킹 성공률 | 후킹 미동작 무시 |
| API 감사 | IDOR/인증결함 잡나? | 401/403 일관성 | 토큰 무효화 미확인 |
| 회귀 | 재빌드 후 재발 안 하나? | 재테스트 통과율 | 이전 결과 신뢰 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 앱 정적 분석 발화 확인(MobSF, 소유 앱) — 알려진 결함을 잡는지
curl -s -F "file=@app.apk" -H "Authorization: $MOBSF_KEY" http://localhost:8000/api/v1/upload 2>/dev/null | head
# 2) API IDOR 검증 — 소유 계정 토큰으로 타 계정 객체 접근 시 403이어야 함
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer TOKEN_A" https://api.example.com/users/USER_B/data
```

> 보안 테스트 검증은 *돌렸는가*가 아니라 *잡고 재현되는가*다 — "MobSF 돌렸다"와 "알려진 결함에 발화하고 IDOR이 403으로 막히며 재빌드 후에도 재현된다"는 다르다. 소유 앱에서 발화·IDOR 응답코드를 직접 확인한다([[52_API_Security]], [[12_Bug_Bounty]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- OWASP MASVS/MASTG가 표준 — 저장·통신·인증·회복력 검증. 검증: 각 통제가 실제 강제되는지 재현([[48_Threat_Modeling]])
- CI 통합 모바일 SAST/DAST — 신규 취약이 차단되는지 확인

---

<a name="english"></a>

# Mobile App Security Testing — Automated Analysis, Runtime Hooking, API Auditing

## 1. Mobile App Testing Methodology

Key testing areas for mobile application security:

- **OWASP MASVS**: Mobile Application Security Verification Standard
- **Static analysis**: Source code, binary, configuration
- **Dynamic analysis**: Runtime behavior, network traffic
- **API security**: Authentication, authorization, data exposure

```
Mobile App Security Testing
    │
    ├── Static Analysis
    │     - APK/IPA unpacking and decompilation
    │     - Hardcoded credentials and API keys
    │     - AndroidManifest / Info.plist review
    │
    ├── Dynamic Analysis
    │     - Runtime hooking with Frida
    │     - Traffic interception (Burp Suite)
    │     - Certificate pinning bypass
    │
    └── API Auditing
          - Endpoint extraction (JS/source)
          - Auth token reuse
          - IDOR / privilege bypass
```

---

## 2. OWASP Mobile Top 10 (2024) — Complete Explanation

The OWASP Mobile Top 10 is a list of the 10 most critical mobile application security risks. Understanding these is the foundation of any mobile pentest.

### Real-World Analogy: Your House's Security

Think of mobile app vulnerabilities like home security issues:
- No lock on the front door = unauthenticated endpoints
- Key taped to window = hardcoded secret in source code
- Security camera feed publicly visible = unencrypted local data storage

```
OWASP Mobile Top 10 (2024)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
M1  Improper Credential Usage     API keys/tokens hardcoded in source
M2  Inadequate Supply Chain       Malicious SDKs, tainted libraries
M3  Insecure Authentication/Authz Weak tokens, biometric bypass
M4  Insufficient Input/Output     SQLi, XSS in WebView, path traversal
M5  Insecure Communication        Self-signed certs, no pinning
M6  Inadequate Privacy Controls   Excessive permissions, sensitive data leak
M7  Insufficient Binary Protection No root detection, debuggable builds
M8  Security Misconfiguration     AndroidManifest exported=true abuse
M9  Insecure Data Storage         Plaintext in SharedPrefs/SQLite
M10 Insufficient Cryptography     Weak algorithms, hardcoded IV/keys
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### M1 — Improper Credential Usage (Most Common)

Developers hardcode API keys and passwords directly into strings.xml, BuildConfig, or Java/Kotlin source files.

```java
// Vulnerable code example (actually found in production APKs)
private static final String API_KEY = "FAKE_API_KEY_HARDCODED_DEMO_ONLY";
private static final String DB_PASSWORD = "mySecretPass123";
```

**Why it's dangerous**: An APK is just a ZIP file. Anyone can decompile it with jadx in under 5 minutes.

### M5 — Insecure Communication (Certificate Pinning)

Standard HTTPS is vulnerable to Man-in-the-Middle attacks. If an attacker installs Burp Suite's certificate on a device, they can see all traffic.

**Certificate Pinning** forces the app to trust only a specific certificate fingerprint.

```
Without pinning:                  With pinning:
App → Server: Trust any cert      App → Server: Only trust hardcoded fingerprint
     ↑                                 ↑
  Burp intercepts all traffic      Burp cert rejected → App closes connection
```

---

## 3. Static vs Dynamic Analysis Comparison

| Aspect | Static Analysis | Dynamic Analysis |
|--------|----------------|-----------------|
| When performed | Before execution | During execution |
| Equipment needed | Computer only | Real device/emulator |
| Vulnerabilities found | Hardcoded secrets, weak APIs, misconfigs | Runtime encryption, live API comms |
| Obfuscation | Hard to defeat | Easy (decrypted in memory) |
| Primary tools | jadx, apktool, MobSF, semgrep | Frida, Burp Suite, objection |
| Time required | Fast (automatable) | Slow (manual exploration) |
| Root/jailbreak needed | Not required | Often required |
| Advantage | Full code scan possible | Observe actual runtime behavior |
| Disadvantage | Misses dynamically generated code | Limited coverage |

---

## 4. MobSF Setup and Usage Tutorial

MobSF (Mobile Security Framework) is an open-source automated mobile app analysis tool supporting both static and dynamic analysis.

### Step 1: Install MobSF

```bash
# Docker installation (recommended — fastest way to get started)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 \
  -v $(pwd)/uploads:/home/mobsf/.MobSF/uploads \
  opensecurity/mobile-security-framework-mobsf:latest

# Verify: open http://localhost:8000 in your browser
```

### Step 2: Perform Your First Scan

```bash
# Get your API key from MobSF web UI (REST API section)
# Then scan an APK via API:

curl -F "file=@target.apk" \
     -H "Authorization: YOUR_API_KEY" \
     http://localhost:8000/api/v1/upload

# Response: {"analyzer": "static_analyzer", "status": "success", "hash": "abc123..."}

# Trigger scan
curl -X POST \
     -d "hash=abc123&scan_type=apk" \
     -H "Authorization: YOUR_API_KEY" \
     http://localhost:8000/api/v1/scan

# Get report
curl -X POST \
     -d "hash=abc123" \
     -H "Authorization: YOUR_API_KEY" \
     http://localhost:8000/api/v1/report_json > report.json
```

### Step 3: Interpret Results

Key sections in the MobSF report to focus on:

```
MobSF Report Sections (Priority Order)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Security Score (0-10)   — Overall risk rating
2. Secrets Found           — Hardcoded credentials (CRITICAL)
3. Android API Analysis    — Dangerous API usage
4. Manifest Analysis       — Exported components, debuggable
5. Network Security        — Certificate pinning, cleartext
6. Permissions             — Dangerous permissions requested
7. Binary Analysis         — Anti-tampering, obfuscation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 5. Frida Script Examples

### Bypassing Root Detection

Most banking and fintech apps detect rooted devices and refuse to run. Frida can bypass these checks at runtime without modifying the APK.

```javascript
// root_bypass.js — Bypass common root detection techniques
Java.perform(function() {
    // 1. File existence check bypass (su binary detection)
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootIndicators = [
            '/su', '/system/xbin/su', '/sbin/su',
            '/system/bin/su', '/magisk', '/.magisk',
            '/system/app/SuperUser.apk'
        ];
        if (rootIndicators.some(indicator => path.includes(indicator))) {
            console.log('[Root Bypass] Blocked check for: ' + path);
            return false;
        }
        return this.exists();
    };

    // 2. Root app package detection bypass
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int')
    .implementation = function(packageName, flags) {
        var rootApps = [
            'com.topjohnwu.magisk',
            'com.noshufou.android.su',
            'eu.chainfire.supersu',
            'com.koushikdutta.superuser'
        ];
        if (rootApps.includes(packageName)) {
            // Throw exception as if app doesn't exist
            throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new();
        }
        return this.getPackageInfo(packageName, flags);
    };

    // 3. Runtime.exec() command bypass (which su)
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.includes('su') || cmd.includes('which')) {
            console.log('[Root Bypass] Blocked exec: ' + cmd);
            return this.exec('echo');  // Return harmless command
        }
        return this.exec(cmd);
    };

    console.log('[+] Root detection bypass loaded');
});
```

### SSL Pinning Bypass — Deep Dive

```javascript
// ssl_pinning_bypass_advanced.js
// Handles OkHttp, Retrofit, TrustKit, and native SSL

Java.perform(function() {
    // === Method 1: Override X509TrustManager ===
    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustAllManager',
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
        console.log('[SSL] SSLContext.init() hooked — replacing TrustManager');
        this.init(km, [TrustManager.$new()], sr);
    };

    // === Method 2: OkHttp CertificatePinner bypass ===
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(hostname, peerCertificates) {
            console.log('[OkHttp] CertificatePinner.check() bypassed for: ' + hostname);
            // Simply return without throwing — no more pinning!
        };
        console.log('[+] OkHttp pinning bypassed');
    } catch(e) {
        console.log('[-] OkHttp not found, skipping');
    }

    // === Method 3: TrustKit bypass ===
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
        .implementation = function(hostname, session) {
            console.log('[TrustKit] Verification bypassed for: ' + hostname);
            return true;
        };
    } catch(e) {}

    console.log('[+] SSL pinning bypass complete');
});
```

---

## 5.5 Server-Side Integrity Verification Against Root/Jailbreak Detection Bypass (Play Integrity / DeviceCheck)

The Frida hooks shown above defeat most client-side root detection — because the logic an app uses to decide "I'm not rooted" for itself can, in the end, be tampered with just as easily as that decision. The real fix is to **move the decision off the device and onto the server**. Android's Play Integrity API and iOS's DeviceCheck/App Attest generate a signed attestation at the OS/hardware level, which the server verifies directly against Google's or Apple's servers — even if Frida hooks the app process, it can't forge that attestation itself, since it's signed with a hardware-backed key.

```kotlin
// Android client -- request an integrity token via the Play Integrity API
val integrityManager = IntegrityManagerFactory.create(applicationContext)
val request = IntegrityTokenRequest.builder()
    .setNonce(serverProvidedNonce)  // one-time nonce issued by the server (prevents replay)
    .build()

integrityManager.requestIntegrityToken(request)
    .addOnSuccessListener { response ->
        val token = response.token()
        // send this token to the server as-is -- the client never interprets its contents
        sendTokenToServer(token)
    }
```

```python
#!/usr/bin/env python3
"""Server side -- verify a Play Integrity token against Google's API (this is where app trust is finally decided)."""
import requests


def verify_integrity_token(token: str, package_name: str, access_token: str) -> dict:
    url = (
        f"https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken"
    )
    resp = requests.post(
        url,
        json={"integrity_token": token},
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    result = resp.json().get("tokenPayloadExternal", {})

    device_verdict = result.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
    app_verdict = result.get("appIntegrity", {}).get("appRecognitionVerdict")

    is_trusted = "MEETS_DEVICE_INTEGRITY" in device_verdict and app_verdict == "PLAY_RECOGNIZED"
    return {"trusted": is_trusted, "device": device_verdict, "app": app_verdict}


if __name__ == "__main__":
    result = verify_integrity_token("TOKEN_FROM_CLIENT", "com.example.app", "SERVER_ACCESS_TOKEN")
    print(f"[{'+' if result['trusted'] else '!'}] Integrity check: {result}")
```

**Key point**: treat client-side root detection (covered earlier in this section) as no more than a first-pass filter for filtering out obvious risk signals without hurting UX — trust decisions for genuinely sensitive logic like payments or account security must instead rest on **the server directly verifying a Play Integrity/DeviceCheck token**. The server must also issue a fresh nonce on every request, or replay attacks become possible again.

---

## 6. ADB Command Cheatsheet for Beginners

ADB (Android Debug Bridge) is the main command-line tool for communicating with Android devices. Think of it as a remote control for your Android device.

```bash
# ===== DEVICE CONNECTION =====
adb devices                          # List connected devices
adb connect 192.168.1.100:5555       # Connect via WiFi
adb shell                            # Open device shell

# ===== APP MANAGEMENT =====
adb install target.apk               # Install APK
adb shell pm list packages -3        # List third-party apps
adb shell pm path com.example.app    # Find APK location on device
adb pull /data/app/com.example.app-1/base.apk ./extracted.apk  # Pull APK

# ===== DATA EXTRACTION (requires root) =====
# View SharedPreferences (login tokens, settings)
adb shell cat /data/data/com.example.app/shared_prefs/user.xml

# Interact with SQLite database
adb shell sqlite3 /data/data/com.example.app/databases/main.db
# Inside sqlite3:
# .tables              — list all tables
# SELECT * FROM users; — dump user table

# ===== LOG MONITORING =====
adb logcat | grep -i "password\|token\|secret\|key"  # Find credential leaks
adb logcat -s "NetworkTraffic"       # App-specific tag

# ===== NETWORK =====
adb shell netstat -tlnp              # Open ports on device
adb forward tcp:8080 tcp:8080        # Forward device port to PC (for Burp)
# After forwarding, set proxy to 127.0.0.1:8080 on device

# ===== INTENT ATTACKS =====
# Test exported Activity directly (M8 vulnerability)
adb shell am start -n com.example.app/.AdminActivity
adb shell am start -n com.example.app/.DeepLinkActivity \
    -d "app://promo?code=ADMIN50"

# ===== BACKUP EXTRACTION (no root needed) =====
adb backup -f backup.ab -apk com.example.app
# Convert .ab to .tar:
dd if=backup.ab bs=24 skip=1 | python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
tar xf backup.tar
```

---

## 7. MSTG Checklist

The OWASP Mobile Security Testing Guide (MSTG) provides a comprehensive test checklist. Here are the most critical checks:

```
MSTG Minimum Checklist (Android)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Static Analysis:
[ ] AndroidManifest.xml
    [ ] android:debuggable="false"
    [ ] android:allowBackup="false" for sensitive apps
    [ ] Exported components require proper permissions
    [ ] Minimum necessary permissions declared

[ ] Code Review
    [ ] No hardcoded credentials/API keys
    [ ] No weak crypto (MD5, DES, AES-ECB)
    [ ] No sensitive data in logs
    [ ] No WebView.addJavascriptInterface() on Android < 4.2

Dynamic Analysis:
[ ] Network Traffic
    [ ] Certificate pinning implemented and working
    [ ] All communication over HTTPS
    [ ] No credentials in URL query strings

[ ] Data Storage
    [ ] SharedPreferences encrypted (use EncryptedSharedPreferences)
    [ ] SQLite database encrypted if sensitive
    [ ] No sensitive data on external storage (SD card)
    [ ] Temp/cache files cleared on logout

[ ] Authentication
    [ ] Tokens expire appropriately
    [ ] Server session invalidated on logout
    [ ] Biometric authentication cannot be bypassed

[ ] Binary Protections
    [ ] Root/jailbreak detection present
    [ ] Code obfuscation applied (ProGuard/R8)
    [ ] Integrity verification (signature check)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 8. Python APK Batch Analysis Automation

```python
#!/usr/bin/env python3
"""
apk_batch_analyzer.py — Automated batch APK analysis pipeline.

Combines static analysis (jadx decompile + secret scan) with
MobSF API for comprehensive reporting across multiple APKs.

Usage:
  python3 apk_batch_analyzer.py scan ./apks/ --output report.json
  python3 apk_batch_analyzer.py single target.apk --verbose
"""

import argparse
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, label, severity)
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "CRITICAL"),
    (r'(?i)api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key", "HIGH"),
    (r'(?i)password\s*[=:]\s*["\']([^"\']{8,})["\']', "Hardcoded Password", "HIGH"),
    (r'(?i)secret\s*[=:]\s*["\']([^"\']{10,})["\']', "Secret Value", "HIGH"),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
    (r'(?i)firebase.*["\']AIza[A-Za-z0-9_-]{35}["\']', "Firebase Key", "HIGH"),
    (r'(?i)jdbc:[a-z]+://[^\s"\']+password=[^\s"\']+', "DB Connection String", "CRITICAL"),
    (r'https?://[a-zA-Z0-9._-]+\.(internal|local|corp|intranet)\b', "Internal Endpoint", "MEDIUM"),
    (r'(?i)slack.*xox[baprs]-[A-Za-z0-9-]+', "Slack Token", "HIGH"),
]

DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}


@dataclass
class SecretFinding:
    file: str
    label: str
    severity: str
    sample: str
    line_number: int = 0


@dataclass
class ApkReport:
    apk_name: str
    package: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    debuggable: bool = False
    backup_allowed: bool = True
    dangerous_permissions: list[str] = field(default_factory=list)
    exported_components: list[dict] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    risk_score: int = 0
    errors: list[str] = field(default_factory=list)

    def calculate_risk(self) -> int:
        """Simple risk scoring 0-100."""
        score = 0
        critical = sum(1 for s in self.secrets if s.severity == "CRITICAL")
        high = sum(1 for s in self.secrets if s.severity == "HIGH")
        score += critical * 25
        score += high * 10
        if self.debuggable:
            score += 20
        if self.backup_allowed:
            score += 5
        score += len(self.dangerous_permissions) * 2
        score += min(len(self.exported_components) * 3, 15)
        self.risk_score = min(score, 100)
        return self.risk_score


def extract_and_decompile(apk_path: Path, work_dir: Path) -> tuple[Path, Path]:
    """Extract raw APK and decompile with jadx."""
    raw_dir = work_dir / "raw"
    src_dir = work_dir / "src"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # Extract ZIP
    try:
        with zipfile.ZipFile(apk_path) as zf:
            zf.extractall(raw_dir)
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"Not a valid APK: {e}") from e

    # Decompile with jadx (if available)
    jadx_result = subprocess.run(
        ["jadx", "-d", str(src_dir), "--no-res", str(apk_path)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if jadx_result.returncode != 0:
        # Fall back to apktool for smali
        subprocess.run(
            ["apktool", "d", str(apk_path), "-o", str(src_dir), "-f"],
            capture_output=True,
            timeout=120,
        )

    return raw_dir, src_dir


def parse_manifest(manifest_path: Path) -> dict:
    """Parse AndroidManifest.xml."""
    import xml.etree.ElementTree as ET

    result: dict = {
        "package": "",
        "min_sdk": 0,
        "target_sdk": 0,
        "debuggable": False,
        "backup_allowed": True,
        "dangerous_permissions": [],
        "exported_components": [],
    }

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = "http://schemas.android.com/apk/res/android"

        result["package"] = root.get("package", "")

        # SDK versions
        sdk = root.find("uses-sdk")
        if sdk is not None:
            result["min_sdk"] = int(sdk.get(f"{{{ns}}}minSdkVersion", 0) or 0)
            result["target_sdk"] = int(sdk.get(f"{{{ns}}}targetSdkVersion", 0) or 0)

        # Application attributes
        app = root.find("application")
        if app is not None:
            result["debuggable"] = app.get(f"{{{ns}}}debuggable", "false").lower() == "true"
            result["backup_allowed"] = app.get(f"{{{ns}}}allowBackup", "true").lower() == "true"

        # Permissions
        for perm in root.findall("uses-permission"):
            name = perm.get(f"{{{ns}}}name", "")
            if name in DANGEROUS_PERMISSIONS:
                result["dangerous_permissions"].append(name)

        # Exported components
        for tag in ("activity", "service", "receiver", "provider"):
            for elem in root.iter(tag):
                exported = elem.get(f"{{{ns}}}exported", "")
                if exported == "true":
                    name = elem.get(f"{{{ns}}}name", "?")
                    result["exported_components"].append(
                        {"type": tag, "name": name}
                    )

    except ET.ParseError:
        result["parse_error"] = "Binary manifest — decode with apktool"

    return result


def scan_secrets(src_dir: Path) -> list[SecretFinding]:
    """Scan decompiled source for secrets."""
    findings: list[SecretFinding] = []
    extensions = {".java", ".kt", ".xml", ".json", ".properties", ".gradle", ".smali"}

    for fpath in src_dir.rglob("*"):
        if not fpath.is_file() or fpath.suffix not in extensions:
            continue
        try:
            content = fpath.read_text(errors="ignore")
        except OSError:
            continue

        for pattern, label, severity in SENSITIVE_PATTERNS:
            for line_num, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    findings.append(
                        SecretFinding(
                            file=str(fpath.relative_to(src_dir)),
                            label=label,
                            severity=severity,
                            sample=line.strip()[:80],
                            line_number=line_num,
                        )
                    )

    return findings


def analyze_single_apk(apk_path: Path, work_dir: Path) -> ApkReport:
    """Full analysis pipeline for a single APK."""
    report = ApkReport(apk_name=apk_path.name)
    apk_work = work_dir / apk_path.stem

    try:
        raw_dir, src_dir = extract_and_decompile(apk_path, apk_work)
    except RuntimeError as e:
        report.errors.append(str(e))
        return report

    # Parse manifest
    manifest_path = raw_dir / "AndroidManifest.xml"
    if manifest_path.exists():
        manifest_data = parse_manifest(manifest_path)
        report.package = manifest_data["package"]
        report.min_sdk = manifest_data["min_sdk"]
        report.target_sdk = manifest_data["target_sdk"]
        report.debuggable = manifest_data["debuggable"]
        report.backup_allowed = manifest_data["backup_allowed"]
        report.dangerous_permissions = manifest_data["dangerous_permissions"]
        report.exported_components = manifest_data["exported_components"]

    # Scan secrets
    if src_dir.exists():
        report.secrets = scan_secrets(src_dir)

    report.calculate_risk()
    return report


def format_report_text(reports: list[ApkReport]) -> str:
    """Format reports as human-readable text."""
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("APK BATCH SECURITY ANALYSIS REPORT")
    lines.append("=" * 70)

    for r in sorted(reports, key=lambda x: x.risk_score, reverse=True):
        lines.append(f"\n[{'CRITICAL' if r.risk_score >= 70 else 'HIGH' if r.risk_score >= 40 else 'MEDIUM'}]"
                     f" {r.apk_name} (Risk Score: {r.risk_score}/100)")
        lines.append(f"  Package     : {r.package}")
        lines.append(f"  Min SDK     : {r.min_sdk}  Target SDK: {r.target_sdk}")
        lines.append(f"  Debuggable  : {'YES (CRITICAL)' if r.debuggable else 'no'}")
        lines.append(f"  Backup      : {'YES (risky)' if r.backup_allowed else 'disabled'}")

        if r.dangerous_permissions:
            lines.append(f"  Dangerous permissions ({len(r.dangerous_permissions)}):")
            for p in r.dangerous_permissions[:5]:
                lines.append(f"    - {p.split('.')[-1]}")

        if r.exported_components:
            lines.append(f"  Exported components: {len(r.exported_components)}")
            for c in r.exported_components[:3]:
                lines.append(f"    - [{c['type']}] {c['name'].split('.')[-1]}")

        if r.secrets:
            crit = [s for s in r.secrets if s.severity == "CRITICAL"]
            high = [s for s in r.secrets if s.severity == "HIGH"]
            lines.append(f"  Secrets found: {len(r.secrets)} "
                         f"(CRITICAL: {len(crit)}, HIGH: {len(high)})")
            for s in (crit + high)[:3]:
                lines.append(f"    [{s.severity}] {s.label} in {s.file}:{s.line_number}")
                lines.append(f"      {s.sample}")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="APK batch security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 apk_batch_analyzer.py scan ./apks/
  python3 apk_batch_analyzer.py scan ./apks/ --output report.json --format json
  python3 apk_batch_analyzer.py single target.apk --work-dir /tmp/apk_work
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Scan all APKs in a directory")
    scan_p.add_argument("directory", type=Path)
    scan_p.add_argument("--output", "-o", type=Path, help="Output file")
    scan_p.add_argument("--format", choices=["text", "json"], default="text")
    scan_p.add_argument("--work-dir", type=Path, default=Path("/tmp/apk_analysis"))

    single_p = sub.add_parser("single", help="Analyze a single APK")
    single_p.add_argument("apk", type=Path)
    single_p.add_argument("--work-dir", type=Path, default=Path("/tmp/apk_analysis"))
    single_p.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    match args.cmd:
        case "scan":
            apks = list(args.directory.glob("*.apk"))
            if not apks:
                print(f"[!] No APK files found in {args.directory}")
                sys.exit(1)

            print(f"[*] Found {len(apks)} APK files")
            reports: list[ApkReport] = []

            for i, apk in enumerate(apks, 1):
                print(f"[{i}/{len(apks)}] Analyzing: {apk.name}")
                report = analyze_single_apk(apk, args.work_dir)
                reports.append(report)
                print(f"  Risk: {report.risk_score}/100 | "
                      f"Secrets: {len(report.secrets)} | "
                      f"Exported: {len(report.exported_components)}")

            if args.format == "json":
                output = json.dumps(
                    [
                        {
                            "apk": r.apk_name,
                            "package": r.package,
                            "risk_score": r.risk_score,
                            "debuggable": r.debuggable,
                            "secrets": [
                                {"label": s.label, "severity": s.severity,
                                 "file": s.file, "line": s.line_number}
                                for s in r.secrets
                            ],
                            "dangerous_permissions": r.dangerous_permissions,
                        }
                        for r in reports
                    ],
                    ensure_ascii=False,
                    indent=2,
                )
            else:
                output = format_report_text(reports)

            if args.output:
                args.output.write_text(output, encoding="utf-8")
                print(f"\n[+] Report saved to: {args.output}")
            else:
                print("\n" + output)

        case "single":
            report = analyze_single_apk(args.apk, args.work_dir)
            report.calculate_risk()

            print(f"\n{'=' * 50}")
            print(f"APK: {report.apk_name}")
            print(f"Package: {report.package}")
            print(f"Risk Score: {report.risk_score}/100")
            print(f"Debuggable: {report.debuggable}")
            print(f"Backup: {report.backup_allowed}")
            print(f"Secrets: {len(report.secrets)}")

            if args.verbose:
                for s in report.secrets:
                    print(f"  [{s.severity}] {s.label}: {s.sample}")


if __name__ == "__main__":
    main()
```

---

## 9. Key Testing Tools Summary

| Testing Area | Tool | Method |
|-------------|------|--------|
| APK decompilation | jadx, apktool | Static source analysis |
| Runtime hooking | Frida | SSL pinning, encryption functions |
| Traffic analysis | Burp Suite + ProxyDroid | API endpoints, tokens |
| Certificate pinning | frida-ssl-pinning-bypass | Bypass pinning |
| Storage analysis | adb shell | SharedPreferences, SQLite |
| Automated scanning | MobSF | Automated static+dynamic analysis |
| Batch analysis | Custom Python (above) | Multi-APK secret scanning |

## Common Vulnerabilities

- **Insecure data storage**: Sensitive data in SharedPreferences, SQLite, log files
- **Broken authentication**: Weak token handling, no expiry
- **Insufficient cryptography**: Weak algorithms, hardcoded keys
- **Client-side injection**: SQLite injection, JavaScript injection in WebViews
- **Improper session handling**: Token reuse, inadequate logout
- **Hardcoded secrets**: API keys, private keys embedded in APK code
- **Exported components**: Activities/Services accessible without authentication

<!-- detect-validate-28 -->
## Mobile App Security Testing Effectiveness Validation and Regression

Security testing's value comes not from *whether it ran* but from *whether it actually catches vulnerabilities and filters false positives*. Defenders must verify **whether automated analysis, runtime hooking, and API auditing fire and reproduce**. Validate only on **owned apps**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| Static analysis (MobSF) | Does it fire on vulns? | Detections vs known flaws | Stale rules |
| Runtime hooking | Are pinning/root checks bypassable? | Hook success rate | Ignoring non-working hooks |
| API auditing | Does it catch IDOR/auth flaws? | 401/403 consistency | Unverified token revocation |
| Regression | No recurrence after rebuild? | Retest pass rate | Trusting prior results |

### Defense validation (verify directly)

```bash
# 1) Confirm your app's static analysis fires (MobSF, owned app) — does it catch known flaws
curl -s -F "file=@app.apk" -H "Authorization: $MOBSF_KEY" http://localhost:8000/api/v1/upload 2>/dev/null | head
# 2) API IDOR check — accessing another account's object with your token must return 403
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer TOKEN_A" https://api.example.com/users/USER_B/data
```

> Security-testing validation is *whether it catches and reproduces*, not *whether it ran* -- "we ran MobSF" differs from "it fires on known flaws, IDOR is blocked with 403, and it reproduces after rebuild". Confirm firing and IDOR response codes on owned apps directly ([[52_API_Security]], [[12_Bug_Bounty]], [[13_SOC_Blue_Team]]).
