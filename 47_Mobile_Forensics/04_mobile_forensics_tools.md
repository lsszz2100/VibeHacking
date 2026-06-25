> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 모바일 포렌식 도구

## 0. 초보자를 위한 개념 이해

### 모바일 포렌식 도구란?

모바일 포렌식 도구는 스마트폰에서 디지털 증거를 추출하고 분석하는 전문 소프트웨어다. 무료 오픈소스 도구부터 수천만 원짜리 전문 장비까지 다양하다. 올바른 도구 선택이 증거 수집 성공 여부를 좌우한다.

**왜 배우는가:**
```
도구 카테고리별 사용 시나리오:

  무료 도구
    ADB         → 루팅 안 된 Android 기본 데이터
    Autopsy     → 이미지 파일 분석 (플랫폼)
    MVT         → Pegasus 스파이웨어 탐지 (NGO/언론인)
    JADX        → APK 역분석 (악성 앱 분석)

  상용 도구 (법집행기관)
    Cellebrite UFED  → 물리적 추출 + 분석 (가장 널리 사용)
    MSAB XRY         → 물리적 추출 전문
    Oxygen Forensics → 클라우드 데이터 + 앱 분석

  선택 기준:
    - 예산: 무료 vs 상용
    - 목적: 조사 vs 연구 vs 사고대응
    - 법적 요건: 법정 제출 목적이면 검증된 상용 도구
    - 기기 종류: Android만 vs iOS 포함 vs 모두
```

### 핵심 개념 정리

```
핵심 도구 개요:

Autopsy (무료, 오픈소스)
  - 그래픽 포렌식 플랫폼 (Sleuth Kit 기반)
  - 모바일 이미지, 디스크 이미지 모두 분석
  - 타임라인, 키워드 검색, 파일 복구 기능

Cellebrite UFED (상용, 업계 표준)
  - 물리/논리 추출 모두 지원
  - 1만 5천 개 이상 기기 지원
  - 법정 증거 채택 검증 완료

MVT - Mobile Verification Toolkit (무료)
  - Pegasus 등 정부 스파이웨어 탐지
  - NGO, 언론인, 인권 활동가 대상
  - iOS/Android 모두 지원

Frida (무료, 동적 분석)
  - 런타임에 앱 함수 후킹
  - 암호화 키, 네트워크 통신 실시간 캡처
  - CTF 모바일 문제에 특히 유용

JADX (무료, 정적 분석)
  - APK → Java 소스 코드 역컴파일
  - Kotlin, Smali 코드도 지원
  - 악성 앱, CTF 앱 분석에 필수
```

### 필요한 도구 및 환경
- **Autopsy**: https://www.autopsy.com/download/
- **JADX**: `apt install jadx` 또는 https://github.com/skylot/jadx
- **MVT**: `pip install mvt`
- **Frida**: `pip install frida-tools`
- **apktool**: `apt install apktool` (Smali 레벨 분석)

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
APK 기초 분석 도구 — JADX 없이 APK에서 메타데이터와 권한을 추출한다
실제 환경에서는 JADX/apktool 사용 권장
"""
import json
import struct
import zipfile
from pathlib import Path


def extract_apk_manifest_info(apk_path: str) -> dict:
    """
    APK 파일(실제로는 ZIP)에서 기본 정보를 추출한다.
    AndroidManifest.xml은 바이너리 XML 형식이라 완전한 파싱은 axmldec 필요.
    """
    info = {
        "파일명": Path(apk_path).name,
        "파일크기_MB": round(Path(apk_path).stat().st_size / 1024 / 1024, 2),
        "APK_내용물": [],
        "DEX_파일": [],
        "네이티브_라이브러리": [],
        "포함된_에셋": [],
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            for item in apk.namelist():
                if item.endswith(".dex"):
                    info["DEX_파일"].append(item)
                elif item.endswith(".so"):
                    info["네이티브_라이브러리"].append(item)
                elif item.startswith("assets/"):
                    info["포함된_에셋"].append(item)

            # 파일 수 요약
            info["전체_파일수"] = len(apk.namelist())
            info["APK_내용물"] = apk.namelist()[:10]  # 처음 10개만

    except zipfile.BadZipFile:
        info["오류"] = "올바른 APK 파일이 아님"
    except FileNotFoundError:
        info["오류"] = f"파일 없음: {apk_path}"

    return info


def check_suspicious_permissions(permissions: list[str]) -> list[dict]:
    """
    위험한 권한 목록을 확인한다.
    실제 권한은 apktool로 AndroidManifest.xml 디코딩 후 추출.
    """
    dangerous_permissions = {
        "READ_SMS": ("높음", "SMS 메시지 읽기 — 개인정보 탈취 위험"),
        "SEND_SMS": ("높음", "SMS 발송 — 요금 부과, 스미싱"),
        "READ_CONTACTS": ("중간", "연락처 전체 읽기"),
        "ACCESS_FINE_LOCATION": ("중간", "정밀 GPS 위치 추적"),
        "RECORD_AUDIO": ("높음", "마이크 녹음"),
        "CAMERA": ("중간", "카메라 접근"),
        "READ_CALL_LOG": ("높음", "통화 기록 읽기"),
        "PROCESS_OUTGOING_CALLS": ("높음", "발신 전화 가로채기"),
        "RECEIVE_BOOT_COMPLETED": ("낮음", "부팅 시 자동 실행 — 지속성"),
        "BIND_ACCESSIBILITY_SERVICE": ("치명", "화면 전체 읽기 — 뱅킹 앱 정보 탈취"),
    }

    findings = []
    for perm in permissions:
        perm_key = perm.split(".")[-1]  # android.permission.READ_SMS → READ_SMS
        if perm_key in dangerous_permissions:
            level, desc = dangerous_permissions[perm_key]
            findings.append({"권한": perm_key, "위험도": level, "설명": desc})

    return sorted(findings, key=lambda x: ["치명", "높음", "중간", "낮음"].index(x["위험도"]))


if __name__ == "__main__":
    import sys

    # 데모: 존재하지 않는 APK 경로로 오류 처리 확인
    apk = sys.argv[1] if len(sys.argv) > 1 else "sample.apk"
    result = extract_apk_manifest_info(apk)
    print(json.dumps(result, ensure_ascii=False, indent=2))

    # 권한 분석 데모
    sample_perms = [
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    ]
    print("\n[권한 위험도 분석]")
    risks = check_suspicious_permissions(sample_perms)
    print(json.dumps(risks, ensure_ascii=False, indent=2))
```

---

## 목차
1. Autopsy 모바일 분석 설정
2. Cellebrite UFED / MSAB XRY 개요
3. MVT - Pegasus 스파이웨어 탐지
4. Frida를 이용한 동적 앱 분석
5. APK 역분석 (jadx, apktool, dex2jar)
6. Python APK 자동 분석 스크립트
7. 실전 CTF 모바일 포렌식 시나리오

---

## 1. Autopsy 모바일 분석 설정

### 설치 및 기본 설정

```bash
# Ubuntu/Debian
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0.zip
unzip autopsy-4.21.0.zip

# 의존성 설치
sudo apt install -y default-jdk testdisk autopsy

# macOS (Homebrew)
brew install sleuthkit

# Windows: MSI 인스톨러 다운로드 후 설치
# https://www.autopsy.com/download/

# Autopsy 실행
cd autopsy-4.21.0
./bin/autopsy &
```

### 모바일 포렌식 케이스 생성

```
1. 새 케이스 생성
   File → New Case
   - Case Name: KN-2025-001
   - Base Directory: /cases/
   - Case Type: Single-user

2. 데이터 소스 추가
   Add Data Source → 유형 선택:
   - Disk Image or VM File  : raw/E01/AFF 이미지
   - Local Disk             : 직접 연결된 디스크
   - Logical Files          : 추출된 파일/폴더
   - Unallocated Space Files: 미할당 영역

3. Android 이미지 추가 시
   - Disk Image (.img, .raw) 선택
   - Ingest Modules 선택:
     ☑ Android Analyzer      : Android 아티팩트 파싱
     ☑ Keyword Search         : 키워드 검색
     ☑ Hash Lookup            : NSRL 해시 비교
     ☑ File Type Identification: 파일 유형 탐지
     ☑ Exif Parser            : 사진 메타데이터
     ☑ Extension Mismatch Detector: 위장 파일 탐지
```

### Android Analyzer 모듈 설정

```
Autopsy Android Analyzer가 파싱하는 아티팩트:
- SMS/MMS (mmssms.db)
- Call Log (calllog.db)
- Contacts (contacts2.db)
- Browser History (browser.db, History)
- Calendar
- GPS 이동 경로
- Wi-Fi 연결 기록
- 설치된 앱 목록

결과 확인:
Autopsy → Data Artifacts → Communication Artifacts
                         → GPS Artifacts
                         → Web Artifacts
                         → Installed Programs
```

### Autopsy CLI 모드 (자동화)

```bash
# 케이스 생성 및 분석 자동화
# autopsy_casecreate.py (Autopsy Python 스크립트)

java -Xmx4g \
    -cp "/opt/autopsy/autopsy/modules/ext/*:/opt/autopsy/platform/core/core.jar" \
    org.sleuthkit.autopsy.commandlineingest.CommandLineIngestManager \
    --createCase \
    --caseDir /cases/ \
    --caseName KN-2025-001 \
    --dataSourcePath /evidence/device.img \
    --outputDir /cases/KN-2025-001/

# 결과는 /cases/KN-2025-001/Reports/ 에 저장
```

### Autopsy 플러그인 개발 (Python)

```python
# Autopsy Ingest Module 예시
# 파일 저장 위치: ~/.autopsy/dev/python_modules/MyAndroidModule/

import jarray
import inspect
import os
import sys

from java.lang import System
from org.sleuthkit.datamodel import SleuthkitCase, AbstractFile
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices


class AndroidKakaoTalkAnalyzerFactory:
    """카카오톡 DB 분석 모듈"""
    moduleDisplayName = "KakaoTalk Analyzer"
    moduleDescription = "카카오톡 메시지 추출"

    def getDisplayName(self):
        return self.moduleDisplayName

    def getDescription(self):
        return self.moduleDescription

    def createDataSourceIngestModule(self, settings):
        return AndroidKakaoTalkAnalyzer()


class AndroidKakaoTalkAnalyzer(DataSourceIngestModule):
    KAKAO_DB = "KakaoTalk.db"

    def process(self, data_source, progress_bar):
        # 파일 검색
        file_manager = Case.getCurrentCase().getServices().getFileManager()
        files = file_manager.findFiles(data_source, self.KAKAO_DB)

        for kakao_file in files:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.DATA,
                    "KakaoTalk Analyzer",
                    f"발견: {kakao_file.getName()}",
                )
            )

        return IngestModule.ProcessResult.OK
```

---

## 2. Cellebrite UFED / MSAB XRY 개요

### Cellebrite UFED Touch 2 / 4PC

```
제품 라인업:
- UFED Touch 2   : 독립형 하드웨어 기기
- UFED 4PC       : PC 소프트웨어 버전
- UFED Premium   : 잠금 해제 + 고급 추출
- UFED Cloud     : 클라우드 데이터 수집

지원 기기 수:
- Android/iOS 포함 35,000+ 기기 지원
- 주기적 업데이트로 최신 기기 추가

추출 프로세스 (UFED 4PC):
1. UFED 4PC 실행
2. 기기 연결 (USB)
3. 기기 모델 자동 감지
4. 추출 방식 선택 (논리/파일시스템/물리)
5. 추출 실행
6. Physical Analyzer로 결과 분석

결과물 형식:
- .ufdx        : UFED 추출 패키지
- .zip         : 논리적 추출
- Extraction.xml : 추출 메타데이터

Physical Analyzer 기능:
- 타임라인 시각화
- 삭제 데이터 복구
- 앱별 아티팩트 분류
- 지도 시각화 (위치 데이터)
- 보고서 자동 생성 (PDF, HTML, Excel)
```

### MSAB XRY

```
제품군:
- XRY Complete : 하드웨어 + 소프트웨어
- XRY Logical  : 논리적 추출
- XRY Physical : 물리적 추출
- XAMN Analyst : 분석 소프트웨어

XRY 특징:
- 스웨덴 법집행기관에서 개발 시작
- 독립적인 검증 가능 (Validation)
- NIST CFTT 인증

XRY 추출 절차:
1. XRY 실행 후 새 케이스 생성
2. 기기 연결
3. 기기 자동 인식 또는 수동 선택
4. 추출 방식 선택
5. 핀 요청 시 입력 (보유한 경우)
6. 추출 진행
7. XAMN으로 결과 분석

출력 파일:
- .xry        : XRY 케이스 파일
- .ufd        : 추출 데이터
```

### 공통 추출 고려사항

```bash
# 추출 전 반드시 확인
1. USB Restricted Mode (iOS 11.4.1+)
   - 기기 잠금 전 USB 연결 상태 유지 필요
   - 1시간 내 연결 시 데이터 전송 가능

2. Airplane Mode 설정
   - 원격 삭제 방지
   - 증거 변경 방지

3. 암호화 상태
   - Android FBE: PIN 입력 후 추출하면 더 많은 데이터
   - iOS: PIN 없이는 대부분 암호화 상태

4. 배터리
   - 추출 중 방전 방지
   - 외부 전원 연결 권장
```

---

## 3. MVT (Mobile Verification Toolkit) - Pegasus 탐지

### MVT 설치

```bash
# pip으로 설치
pip install mvt

# 또는 소스에서 설치
git clone https://github.com/mvt-project/mvt
cd mvt
pip install .

# 의존성 확인
mvt-ios --help
mvt-android --help

# libimobiledevice 설치 (iOS)
# Ubuntu
sudo apt install libimobiledevice-utils ideviceinstaller
# macOS
brew install libimobiledevice
```

### IOC (Indicators of Compromise) 다운로드

```bash
# Pegasus IOC (Amnesty International)
wget https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2 \
    -O pegasus.stix2

# MVT 공식 IOC 저장소 (정기 업데이트됨)
# https://github.com/mvt-project/mvt-indicators

# 여러 IOC 파일 병합 사용 가능
ls *.stix2
```

### iOS 분석

```bash
# 1. 로컬 백업 분석 (비암호화)
mvt-ios check-backup \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

# 2. 암호화 백업 먼저 복호화
mvt-ios decrypt-backup \
    --password "백업비밀번호" \
    --destination ./decrypted_backup \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

mvt-ios check-backup \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios \
    ./decrypted_backup

# 3. 탈옥 기기 직접 분석 (SSH 필요)
mvt-ios check-fs \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios \
    /   # 탈옥 기기의 루트

# 4. 연결된 기기에서 직접
mvt-ios check-iocs \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios
```

### Android 분석

```bash
# 1. ADB를 통한 분석
mvt-android check-adb \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_android

# 2. ADB 백업 분석
mvt-android check-backup \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_android \
    ./android_backup.ab

# 3. APK 확인
mvt-android download-apks \
    --output ./apks/

# 특정 앱만 다운로드
mvt-android download-apks \
    --output ./apks/ \
    --all-processes

# 4. SMS 분석 (피싱 링크 탐지)
mvt-android check-adb \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output \
    --module SMSModule
```

### MVT 결과 해석

```bash
# 결과 파일 구조
ls ./mvt_output_ios/
# 출력 예시:
# accessibility.json        - 접근성 서비스 사용 앱
# calls.json                - 통화 기록
# chrome_visits.json        - Chrome 방문 기록
# datausage.json            - 앱별 데이터 사용량
# id.json                   - 기기 식별자
# network_extensions.json   - 네트워크 확장
# processes.json            - 프로세스 목록
# sms.json                  - SMS 기록
# sms_attachments.json      - SMS 첨부
# timeline.json             - 전체 타임라인
# version_history.json      - iOS 버전 기록
# wifi_networks.json        - Wi-Fi 기록
# DETECTIONS.json           - 탐지된 IOC (핵심!)

# DETECTIONS.json 분석
python3 -c "
import json
with open('./mvt_output_ios/DETECTIONS.json') as f:
    detections = json.load(f)
for d in detections:
    print(f'[탐지] {d[\"type\"]}: {d[\"indicator\"]}')
    print(f'  발견 위치: {d[\"file\"]}')
    print(f'  타임스탬프: {d.get(\"timestamp\", \"N/A\")}')
"

# 타임라인 시각화
python3 -c "
import json
from datetime import datetime
with open('./mvt_output_ios/timeline.json') as f:
    events = json.load(f)
for event in sorted(events, key=lambda x: x.get('timestamp', '')):
    print(f\"{event.get('timestamp', 'N/A')[:19]} | {event.get('module', '')} | {event.get('event', '')[:80]}\")
"
```

### Pegasus 감염 지표

```
알려진 Pegasus 도메인 패턴 (IOC 예시):
- *.nsosrv.com
- *.cloudfront.net (일부)
- 특정 1-click 또는 0-click 페이로드 도메인

프로세스 이상 지표:
- bh (백그라운드 하이재킹)
- roleaboutd (iOS 지속성 데몬)
- coredistld
- aggregatenotd
- 알 수 없는 BundleID를 가진 충돌 로그

네트워크 지표:
- 비정상적인 DNS 조회
- 암호화된 C2 통신
- 짧은 간격의 핑
```

---

## 4. Frida를 이용한 동적 앱 분석

### Frida 설치 및 설정

```bash
# Frida 설치 (분석 PC)
pip install frida frida-tools

# 버전 확인
frida --version
frida-ps --version

# Android 기기에 frida-server 설치 (루팅 필요)
# 기기 아키텍처 확인
adb shell getprop ro.product.cpu.abi
# 출력: arm64-v8a, armeabi-v7a, x86, x86_64

# frida-server 다운로드 (버전 일치 필수)
FRIDA_VER=$(frida --version)
ARCH="arm64"  # 기기 아키텍처에 맞게 변경
wget "https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-${ARCH}.xz"
unxz "frida-server-${FRIDA_VER}-android-${ARCH}.xz"

# 기기에 업로드
adb push "frida-server-${FRIDA_VER}-android-${ARCH}" /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# 포트 포워딩
adb forward tcp:27042 tcp:27042

# 연결 확인
frida-ps -U   # USB 연결 기기의 프로세스 목록
```

### Frida 기본 사용법

```bash
# 실행 중인 앱 목록
frida-ps -U -a

# 특정 앱에 스크립트 삽입 (앱 실행 중)
frida -U -n "com.kakao.talk" -l hook_script.js

# 앱 시작 시 삽입 (--spawn)
frida -U -f "com.example.app" -l hook_script.js --no-pause

# 인터랙티브 REPL
frida -U -n "com.example.app"
```

### Frida 후킹 스크립트 (JavaScript)

```javascript
// hook_crypto.js - 암호화 함수 후킹
Java.perform(function() {
    // AES 암호화 후킹
    var Cipher = Java.use("javax.crypto.Cipher");
    
    Cipher.doFinal.overload("[B").implementation = function(input) {
        console.log("[*] Cipher.doFinal() 호출");
        console.log("    알고리즘: " + this.getAlgorithm());
        console.log("    입력 (hex): " + bytesToHex(input));
        
        var result = this.doFinal(input);
        console.log("    출력 (hex): " + bytesToHex(result));
        return result;
    };
    
    // Base64 디코딩 후킹
    var Base64 = Java.use("android.util.Base64");
    Base64.decode.overload("[B", "int").implementation = function(input, flags) {
        var result = this.decode(input, flags);
        console.log("[*] Base64.decode():");
        console.log("    입력: " + new java.lang.String(input));
        console.log("    출력 (hex): " + bytesToHex(result));
        return result;
    };
    
    // SharedPreferences 읽기 후킹 (저장된 데이터 모니터링)
    var SharedPrefsImpl = Java.use("android.app.SharedPreferencesImpl");
    SharedPrefsImpl.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        if (value !== null && value !== defValue) {
            console.log("[*] SharedPreferences.getString():");
            console.log("    키: " + key);
            console.log("    값: " + value);
        }
        return value;
    };
});

function bytesToHex(bytes) {
    if (!bytes) return "null";
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}
```

```javascript
// hook_network.js - 네트워크 트래픽 후킹
Java.perform(function() {
    // OkHttp 후킹 (앱 네트워크 요청 모니터링)
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");
        
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.execute.implementation = function() {
            var request = this.request();
            console.log("[*] HTTP 요청:");
            console.log("    URL: " + request.url().toString());
            console.log("    Method: " + request.method());
            
            // 헤더 출력
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log("    " + headers.name(i) + ": " + headers.value(i));
            }
            
            return this.execute();
        };
    } catch(e) {
        console.log("OkHttp 없음: " + e.message);
    }
    
    // SSL 핀닝 우회
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            console.log("[*] SSL 핀닝 우회: " + host);
            return untrustedChain;
        };
    } catch(e) {
        console.log("TrustManagerImpl 없음");
    }
    
    // 일반적인 SSL 검증 우회
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    ).implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[*] SSLContext.init() 우회");
        this.init(keyManager, null, secureRandom);
    };
});
```

```javascript
// hook_sqlite.js - SQLite 쿼리 모니터링
Java.perform(function() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    // 쿼리 실행 후킹
    SQLiteDatabase.rawQuery.overload(
        "java.lang.String", "[Ljava.lang.String;"
    ).implementation = function(sql, selectionArgs) {
        console.log("[*] SQLite rawQuery:");
        console.log("    SQL: " + sql);
        if (selectionArgs) {
            console.log("    Args: " + selectionArgs.join(", "));
        }
        return this.rawQuery(sql, selectionArgs);
    };
    
    // INSERT 후킹
    SQLiteDatabase.insert.implementation = function(table, nullColumnHack, values) {
        console.log("[*] SQLite insert:");
        console.log("    Table: " + table);
        console.log("    Values: " + values.toString());
        return this.insert(table, nullColumnHack, values);
    };
});
```

```bash
# 스크립트 실행
frida -U -f "com.target.app" \
    -l hook_crypto.js \
    -l hook_network.js \
    -l hook_sqlite.js \
    --no-pause

# 결과를 파일로 저장
frida -U -f "com.target.app" \
    -l hook_crypto.js \
    --no-pause \
    2>&1 | tee frida_output.log
```

---

## 5. APK 역분석 (jadx, apktool, dex2jar)

### APK 구조

```
application.apk (ZIP 형식)
├── AndroidManifest.xml    # 앱 메타데이터 (바이너리 XML)
├── classes.dex            # Dalvik 바이트코드 (주 코드)
├── classes2.dex           # 추가 DEX (멀티덱스)
├── resources.arsc         # 컴파일된 리소스
├── res/                   # 리소스 파일
│   ├── layout/            # UI 레이아웃 (바이너리 XML)
│   ├── drawable/          # 이미지
│   └── values/            # 문자열, 색상 등
├── lib/                   # 네이티브 라이브러리 (.so)
│   ├── arm64-v8a/
│   ├── armeabi-v7a/
│   └── x86_64/
├── assets/                # 정적 파일 (암호화된 데이터 등)
├── META-INF/              # 서명 파일
│   ├── CERT.RSA
│   ├── CERT.SF
│   └── MANIFEST.MF
└── kotlin/                # Kotlin 메타데이터 (Kotlin 앱)
```

### jadx 사용법 (DEX → Java)

```bash
# 설치
# GitHub: https://github.com/skylot/jadx
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d jadx

# GUI 실행
./jadx/bin/jadx-gui

# CLI 역컴파일
./jadx/bin/jadx -d ./output_src/ target.apk

# 디컴파일 옵션
./jadx/bin/jadx \
    -d ./output/ \
    --show-bad-code \        # 역컴파일 실패 코드도 표시
    --no-imports \           # import 생략
    --deobf \                # 난독화 해제 시도
    --deobf-min 3 \          # 최소 이름 길이 (난독화 해제 기준)
    target.apk

# 특정 클래스만
./jadx/bin/jadx -d ./output/ \
    --class-name "com.target.LoginActivity" \
    target.apk

# 결과 검색
grep -r "password\|token\|secret\|apikey\|api_key" ./output/ --include="*.java"
grep -r "http://\|https://" ./output/ --include="*.java" | grep -v "//.*http"
grep -r "AES\|RSA\|DES\|Cipher" ./output/ --include="*.java"
```

### apktool 사용법 (리소스 + Smali)

```bash
# 설치
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar
echo '#!/bin/bash\njava -jar /opt/apktool.jar "$@"' > /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool

# APK 디컴파일 (Smali + 리소스)
apktool d target.apk -o ./output_apktool/

# 결과 구조
ls ./output_apktool/
# AndroidManifest.xml   (사람이 읽을 수 있는 XML)
# apktool.yml           (메타데이터)
# res/                  (디코딩된 리소스)
# smali/                (Dalvik 어셈블리)

# Smali 코드 검색
grep -r "invoke-virtual.*Cipher\|invoke-static.*Base64" ./output_apktool/smali/

# AndroidManifest.xml 분석
cat ./output_apktool/AndroidManifest.xml
# 권한, 컴포넌트, 인텐트 필터 확인

# 수정 후 재패키징
apktool b ./output_apktool/ -o modified.apk

# 서명 (재패키징 후 반드시 필요)
keytool -genkey -v -keystore debug.jks -alias debug -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks debug.jks --ks-key-alias debug modified.apk
# 또는
jarsigner -verbose -keystore debug.jks modified.apk debug

# 설치
adb install modified.apk
```

### dex2jar 사용법

```bash
# 설치
wget https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip
unzip dex-tools-v2.4.zip

# APK/DEX → JAR 변환
./dex-tools-v2.4/d2j-dex2jar.sh target.apk -o target.jar
./dex-tools-v2.4/d2j-dex2jar.sh classes.dex -o classes.jar

# JAR → Java 소스 (JD-GUI 사용)
# GUI: https://java-decompiler.github.io/
java -jar jd-gui.jar target.jar

# 또는 procyon 사용
java -jar procyon-decompiler.jar target.jar -o ./java_src/

# 특정 패키지만 추출
./dex-tools-v2.4/d2j-dex2jar.sh target.apk
jar tf target-dex2jar.jar | grep "com/target/"
jar xf target-dex2jar.jar com/target/security/
```

### 인증서 분석

```bash
# APK 서명 정보 확인
apksigner verify --print-certs target.apk

# keytool로 상세 확인
keytool -printcert -jarfile target.apk

# 서명 유형 확인
# v1: JAR 서명 (META-INF/*.RSA)
# v2: APK 서명 블록 (Android 7.0+)
# v3: 서명 업데이트 지원 (Android 9+)

# 개발/프로덕션 서명 구분
# 개발용 자가 서명: CN=Android Debug, O=Android, C=US
# 프로덕션: CN에 회사/개발자 이름
```

---

## 6. Python APK 자동 분석 스크립트

```python
#!/usr/bin/env python3
"""
APK 자동 정적 분석 스크립트

권한 추출, URL/도메인 추출, 암호화 사용 탐지,
하드코딩된 비밀 탐지 등 자동 수행

의존성:
    pip install androguard

사용법:
    python3 apk_analyzer.py -f target.apk -o ./report/
    python3 apk_analyzer.py -f target.apk -o ./report/ --all --verbose
    python3 apk_analyzer.py -d ./apks/ -o ./reports/ --batch
"""

import argparse
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# androguard 선택적 임포트
try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    print("[경고] androguard 미설치: pip install androguard", file=sys.stderr)


# ─── 탐지 패턴 ───────────────────────────────────────────────

URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
)

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "API 키 패턴": re.compile(r"['\"]?(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", re.I),
    "JWT 토큰": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "AWS 키": re.compile(r"AKIA[0-9A-Z]{16}"),
    "구글 API 키": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "비밀번호 패턴": re.compile(r"['\"]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]", re.I),
    "시크릿 키": re.compile(r"['\"]?(?:secret|private[_-]?key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{8,})['\"]", re.I),
    "Firebase URL": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "Hardcoded IP": IP_PATTERN,
}

CRYPTO_PATTERNS: dict[str, list[str]] = {
    "대칭 암호화": ["AES", "DES", "3DES", "TripleDES", "Blowfish", "RC4", "ChaCha20"],
    "비대칭 암호화": ["RSA", "DSA", "ECDSA", "EC", "DH", "ECDH"],
    "해시 함수": ["MD5", "SHA-1", "SHA1", "SHA-256", "SHA256", "SHA-512", "SHA512"],
    "약한 알고리즘": ["MD5", "SHA1", "SHA-1", "DES", "RC4", "ECB"],
}

DANGEROUS_PERMISSIONS: list[str] = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
]


# ─── 데이터 클래스 ──────────────────────────────────────────

@dataclass
class ApkInfo:
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    file_size: int = 0
    md5: str = ""
    sha256: str = ""
    signing_cert_md5: str = ""
    signing_cert_sha256: str = ""


@dataclass
class AnalysisResult:
    apk_path: str
    analyzed_at: str
    apk_info: dict
    all_permissions: list[str]
    dangerous_permissions: list[str]
    custom_permissions: list[str]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]
    exported_components: list[dict]
    urls_found: list[str]
    ips_found: list[str]
    secrets_found: list[dict]
    crypto_usage: dict[str, list[str]]
    native_libraries: list[str]
    assets: list[str]
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)


# ─── APK 기본 분석 ───────────────────────────────────────────

def compute_apk_hash(apk_path: Path) -> tuple[str, str]:
    """APK 파일 해시 계산"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def extract_strings_from_bytes(data: bytes) -> list[str]:
    """바이너리 데이터에서 문자열 추출 (strings 명령어 유사)"""
    pattern = re.compile(rb"[ -~]{6,}")
    return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def analyze_apk_zip(apk_path: Path) -> tuple[list[str], list[str]]:
    """APK를 ZIP으로 열어 파일 목록과 문자열 추출"""
    files: list[str] = []
    all_strings: list[str] = []

    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            files = z.namelist()
            for name in files:
                if name.endswith((".dex", ".xml", ".json", ".properties", ".txt")):
                    try:
                        data = z.read(name)
                        all_strings.extend(extract_strings_from_bytes(data))
                    except (zipfile.BadZipFile, KeyError):
                        continue
    except zipfile.BadZipFile as e:
        print(f"  [오류] ZIP 파싱 실패: {e}", file=sys.stderr)

    return files, list(set(all_strings))


def find_urls_in_strings(strings: list[str]) -> tuple[list[str], list[str]]:
    """문자열 목록에서 URL과 IP 주소 추출"""
    urls: set[str] = set()
    ips: set[str] = set()

    for s in strings:
        for url in URL_PATTERN.findall(s):
            # 노이즈 필터링
            if not any(noise in url for noise in ["schemas.android.com", "www.w3.org"]):
                urls.add(url)
        for ip in IP_PATTERN.findall(s):
            ips.add(ip)

    # 로컬호스트/사설 IP 제외
    private_prefixes = ("127.", "192.168.", "10.", "172.16.", "172.17.",
                        "172.18.", "172.19.", "172.20.", "172.31.")
    ips = {ip for ip in ips if not any(ip.startswith(p) for p in private_prefixes)}

    return sorted(urls), sorted(ips)


def detect_secrets(strings: list[str]) -> list[dict]:
    """하드코딩된 시크릿/자격증명 탐지"""
    found: list[dict] = []
    seen: set[str] = set()

    for s in strings:
        for pattern_name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(s):
                value = match.group(0)
                if value not in seen:
                    seen.add(value)
                    found.append({
                        "유형": pattern_name,
                        "값": value[:100],
                        "컨텍스트": s[:200],
                    })

    return found


def detect_crypto_usage(strings: list[str]) -> dict[str, list[str]]:
    """암호화 알고리즘 사용 탐지"""
    found: dict[str, list[str]] = {}

    for category, keywords in CRYPTO_PATTERNS.items():
        detected: list[str] = []
        for kw in keywords:
            if any(kw.lower() in s.lower() for s in strings):
                detected.append(kw)
        if detected:
            found[category] = list(set(detected))

    return found


# ─── Androguard 기반 분석 ────────────────────────────────────

def analyze_with_androguard(apk_path: Path, verbose: bool = False) -> dict:
    """androguard를 사용한 심층 APK 분석"""
    result: dict = {}

    if not ANDROGUARD_AVAILABLE:
        return result

    try:
        if verbose:
            print("  androguard 분석 중...")

        apk, dex_list, analysis = AnalyzeAPK(str(apk_path))

        # 앱 정보
        result["package"] = apk.get_package()
        result["app_name"] = apk.get_app_name()
        result["version_name"] = apk.get_androidversion_name()
        result["version_code"] = apk.get_androidversion_code()
        result["min_sdk"] = apk.get_min_sdk_version()
        result["target_sdk"] = apk.get_target_sdk_version()

        # 권한
        result["permissions"] = apk.get_permissions()
        result["declared_permissions"] = list(apk.get_declared_permissions().keys())

        # 컴포넌트
        result["activities"] = apk.get_activities()
        result["services"] = apk.get_services()
        result["receivers"] = apk.get_receivers()
        result["providers"] = apk.get_providers()

        # 내보낸(exported) 컴포넌트 - 취약점 포인트
        exported: list[dict] = []
        for activity in apk.get_activities():
            if apk.get_element("activity", activity) is not None:
                exported.append({"유형": "Activity", "이름": activity})
        result["exported_components"] = exported

        # 인증서 정보
        try:
            cert = apk.get_certificate(apk.get_signature_names()[0])
            result["cert_md5"] = hashlib.md5(cert.dump()).hexdigest()
            result["cert_sha256"] = hashlib.sha256(cert.dump()).hexdigest()
        except (IndexError, Exception):
            result["cert_md5"] = ""
            result["cert_sha256"] = ""

        # 네이티브 라이브러리
        result["native_libs"] = apk.get_libraries()

        # DEX 문자열 (상세 분석)
        dex_strings: list[str] = []
        for dex in dex_list:
            for string in dex.get_strings():
                if len(string) > 5:
                    dex_strings.append(string)
        result["dex_strings"] = dex_strings[:5000]  # 최대 5000개

    except Exception as e:
        if verbose:
            print(f"  [경고] androguard 오류: {e}", file=sys.stderr)

    return result


# ─── 위험도 평가 ─────────────────────────────────────────────

def calculate_risk_score(result: AnalysisResult) -> tuple[int, list[str]]:
    """APK 위험도 점수 계산 (0-100)"""
    score = 0
    factors: list[str] = []

    # 위험 권한
    for perm in result.dangerous_permissions:
        score += 3
        short_perm = perm.split(".")[-1]
        factors.append(f"위험 권한: {short_perm}")

    # 시크릿 탐지
    for secret in result.secrets_found:
        score += 10
        factors.append(f"하드코딩된 {secret['유형']} 발견")

    # 약한 암호화
    weak_algos = result.crypto_usage.get("약한 알고리즘", [])
    for algo in weak_algos:
        score += 5
        factors.append(f"약한 암호화 알고리즘: {algo}")

    # 외부 URL (C2 가능성)
    if len(result.urls_found) > 20:
        score += 5
        factors.append(f"다수의 외부 URL ({len(result.urls_found)}개)")

    # IP 하드코딩
    if result.ips_found:
        score += 8
        factors.append(f"하드코딩된 IP 주소: {', '.join(result.ips_found[:3])}")

    # 외부 IP 접속
    suspicious_perms = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ]
    for perm in suspicious_perms:
        if perm in result.all_permissions:
            score += 15
            factors.append(f"고위험 권한: {perm.split('.')[-1]}")

    return min(score, 100), factors


# ─── 보고서 생성 ─────────────────────────────────────────────

def generate_analysis_report(result: AnalysisResult, output_dir: Path) -> Path:
    """분석 결과 보고서 생성"""
    output_dir.mkdir(parents=True, exist_ok=True)

    pkg = result.apk_info.get("package_name", "unknown")
    safe_pkg = re.sub(r"[^a-zA-Z0-9._-]", "_", pkg)

    json_path = output_dir / f"{safe_pkg}_analysis.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(asdict(result), f, ensure_ascii=False, indent=2)

    txt_path = output_dir / f"{safe_pkg}_analysis.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"APK 정적 분석 보고서\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"분석 파일: {result.apk_path}\n")
        f.write(f"분석 시간: {result.analyzed_at}\n\n")

        info = result.apk_info
        f.write("-" * 40 + "\n앱 정보\n" + "-" * 40 + "\n")
        f.write(f"패키지: {info.get('package_name', 'N/A')}\n")
        f.write(f"이름: {info.get('app_name', 'N/A')}\n")
        f.write(f"버전: {info.get('version_name', 'N/A')} ({info.get('version_code', 'N/A')})\n")
        f.write(f"Min SDK: {info.get('min_sdk', 'N/A')}\n")
        f.write(f"Target SDK: {info.get('target_sdk', 'N/A')}\n")
        f.write(f"MD5:    {info.get('md5', 'N/A')}\n")
        f.write(f"SHA256: {info.get('sha256', 'N/A')}\n\n")

        f.write(f"-" * 40 + "\n위험도 평가\n" + "-" * 40 + "\n")
        f.write(f"위험 점수: {result.risk_score}/100\n")
        for factor in result.risk_factors:
            f.write(f"  - {factor}\n")
        f.write("\n")

        f.write(f"-" * 40 + "\n위험 권한 ({len(result.dangerous_permissions)}개)\n" + "-" * 40 + "\n")
        for perm in result.dangerous_permissions:
            f.write(f"  {perm}\n")
        f.write("\n")

        if result.secrets_found:
            f.write(f"-" * 40 + "\n발견된 시크릿 ({len(result.secrets_found)}개)\n" + "-" * 40 + "\n")
            for secret in result.secrets_found[:10]:
                f.write(f"  [{secret['유형']}] {secret['값'][:60]}\n")
            f.write("\n")

        if result.urls_found:
            f.write(f"-" * 40 + "\n발견된 URL ({len(result.urls_found)}개)\n" + "-" * 40 + "\n")
            for url in result.urls_found[:20]:
                f.write(f"  {url}\n")
            f.write("\n")

        if result.ips_found:
            f.write(f"-" * 40 + "\n발견된 IP ({len(result.ips_found)}개)\n" + "-" * 40 + "\n")
            for ip in result.ips_found:
                f.write(f"  {ip}\n")
            f.write("\n")

        if result.crypto_usage:
            f.write(f"-" * 40 + "\n암호화 사용\n" + "-" * 40 + "\n")
            for category, algos in result.crypto_usage.items():
                f.write(f"  {category}: {', '.join(algos)}\n")
            f.write("\n")

    return json_path


# ─── 메인 분석 함수 ──────────────────────────────────────────

def analyze_apk(apk_path: Path, output_dir: Path, verbose: bool = False) -> AnalysisResult:
    """APK 종합 분석"""
    if verbose:
        print(f"  파일 해시 계산 중...")
    md5, sha256 = compute_apk_hash(apk_path)

    if verbose:
        print(f"  ZIP 분석 중...")
    zip_files, zip_strings = analyze_apk_zip(apk_path)

    if verbose:
        print(f"  androguard 분석 중...")
    ag_data = analyze_with_androguard(apk_path, verbose)

    all_strings = zip_strings + ag_data.get("dex_strings", [])

    if verbose:
        print(f"  URL/IP 탐지 중...")
    urls, ips = find_urls_in_strings(all_strings)

    if verbose:
        print(f"  시크릿 탐지 중...")
    secrets = detect_secrets(all_strings)

    if verbose:
        print(f"  암호화 분석 중...")
    crypto = detect_crypto_usage(all_strings)

    permissions = ag_data.get("permissions", [])
    dangerous_perms = [p for p in permissions if p in DANGEROUS_PERMISSIONS]

    native_libs = [f for f in zip_files if f.endswith(".so")]
    assets = [f for f in zip_files if f.startswith("assets/")]

    apk_info: dict = {
        "package_name": ag_data.get("package", ""),
        "app_name": ag_data.get("app_name", ""),
        "version_name": ag_data.get("version_name", ""),
        "version_code": ag_data.get("version_code", ""),
        "min_sdk": ag_data.get("min_sdk", ""),
        "target_sdk": ag_data.get("target_sdk", ""),
        "file_size": apk_path.stat().st_size,
        "md5": md5,
        "sha256": sha256,
        "cert_md5": ag_data.get("cert_md5", ""),
        "cert_sha256": ag_data.get("cert_sha256", ""),
    }

    result = AnalysisResult(
        apk_path=str(apk_path),
        analyzed_at=datetime.now(tz=timezone.utc).isoformat(),
        apk_info=apk_info,
        all_permissions=permissions,
        dangerous_permissions=dangerous_perms,
        custom_permissions=ag_data.get("declared_permissions", []),
        activities=ag_data.get("activities", []),
        services=ag_data.get("services", []),
        receivers=ag_data.get("receivers", []),
        providers=ag_data.get("providers", []),
        exported_components=ag_data.get("exported_components", []),
        urls_found=urls,
        ips_found=ips,
        secrets_found=secrets,
        crypto_usage=crypto,
        native_libraries=native_libs,
        assets=assets,
    )

    result.risk_score, result.risk_factors = calculate_risk_score(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="APK 자동 정적 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s -f target.apk -o ./report/
  %(prog)s -d ./apks/ -o ./reports/ --batch
  %(prog)s -f target.apk -o ./report/ --verbose
        """,
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-f", "--file", help="분석할 APK 파일")
    mode_group.add_argument("-d", "--directory", help="APK 디렉토리 (배치 분석)")

    parser.add_argument("-o", "--output", required=True, help="보고서 출력 디렉토리")
    parser.add_argument("--batch", action="store_true", help="디렉토리 내 모든 APK 분석")
    parser.add_argument("--verbose", "-v", action="store_true", help="상세 출력")
    parser.add_argument("--min-risk", type=int, default=0,
                        help="최소 위험 점수 필터 (배치 모드)")

    args = parser.parse_args()
    output_dir = Path(args.output)

    apk_files: list[Path] = []
    if args.file:
        apk_path = Path(args.file)
        if not apk_path.exists():
            print(f"[오류] 파일 없음: {apk_path}", file=sys.stderr)
            return 1
        apk_files = [apk_path]
    elif args.directory:
        dir_path = Path(args.directory)
        apk_files = list(dir_path.glob("**/*.apk"))
        print(f"[*] 발견된 APK: {len(apk_files)}개")

    for apk_path in apk_files:
        print(f"\n[*] 분석 중: {apk_path.name}")
        try:
            result = analyze_apk(apk_path, output_dir, args.verbose)

            if result.risk_score < args.min_risk:
                print(f"    건너뜀 (위험 점수 {result.risk_score} < {args.min_risk})")
                continue

            report_path = generate_analysis_report(result, output_dir)

            print(f"    패키지: {result.apk_info.get('package_name', 'N/A')}")
            print(f"    위험 점수: {result.risk_score}/100")
            print(f"    위험 권한: {len(result.dangerous_permissions)}개")
            print(f"    발견된 URL: {len(result.urls_found)}개")
            print(f"    발견된 시크릿: {len(result.secrets_found)}개")
            print(f"    보고서: {report_path}")

        except Exception as e:
            print(f"  [오류] 분석 실패: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()

    print(f"\n[완료] 결과 저장: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. 실전 CTF 모바일 포렌식 시나리오

### 시나리오 1: Android 앱에서 숨겨진 플래그 찾기

```bash
# 1단계: APK 다운로드 및 기본 분석
file challenge.apk
unzip -l challenge.apk

# 2단계: AndroidManifest.xml 확인
apktool d challenge.apk -o ./challenge_decompile/
cat ./challenge_decompile/AndroidManifest.xml
# MainActivity, 권한, exported 컴포넌트 확인

# 3단계: jadx로 Java 소스 추출
jadx -d ./challenge_src/ challenge.apk

# 4단계: 플래그 패턴 검색
grep -r "CTF{" ./challenge_src/ 2>/dev/null
grep -r "flag{" ./challenge_src/ 2>/dev/null
grep -r "FLAG" ./challenge_src/ 2>/dev/null

# 5단계: 암호화된 플래그 탐색
grep -r "Base64\|decrypt\|decode" ./challenge_src/ --include="*.java" -l

# 6단계: assets/res 파일 검사
ls ./challenge_decompile/assets/
strings ./challenge_decompile/assets/secret.bin 2>/dev/null
xxd ./challenge_decompile/assets/secret.bin | head -20

# 7단계: shared_prefs XML 파일 검사 (실제 기기 실행 후)
adb pull /data/data/com.ctf.challenge/shared_prefs/ ./shared_prefs/
cat ./shared_prefs/*.xml

# 8단계: 동적 분석 (Frida)
frida -U -f "com.ctf.challenge" -l hook_crypto.js --no-pause
# 암호화/복호화 시 플래그 출력될 수 있음
```

### 시나리오 2: iOS 백업에서 증거 추출

```bash
# 1단계: 백업 구조 파악
ls -la ~/Library/Application\ Support/MobileSync/Backup/<UDID>/
sqlite3 Manifest.db ".tables"
sqlite3 Manifest.db "SELECT domain, relativePath FROM Files LIMIT 20"

# 2단계: SMS DB 추출
FILEID=$(sqlite3 Manifest.db "SELECT fileID FROM Files WHERE relativePath='Library/SMS/sms.db' AND domain='HomeDomain'")
cp ${FILEID:0:2}/$FILEID ./sms.db

# 3단계: SMS 분석
sqlite3 ./sms.db "
SELECT
    datetime(date/1000000000 + 978307200, 'unixepoch', 'localtime') AS time,
    CASE is_from_me WHEN 1 THEN '발신' ELSE '수신' END AS direction,
    (SELECT id FROM handle WHERE rowid = message.handle_id) AS contact,
    text
FROM message
WHERE text NOT NULL
ORDER BY date DESC
LIMIT 50;"

# 4단계: 위치 데이터 추출
LOCID=$(sqlite3 Manifest.db "SELECT fileID FROM Files WHERE relativePath LIKE '%routined%Local.sqlite%'")
cp ${LOCID:0:2}/$LOCID ./locations.db

sqlite3 ./locations.db ".tables"
sqlite3 ./locations.db "SELECT * FROM ZRTLEARNEDLOCATIONOFINTERESTMO LIMIT 10"

# 5단계: 사진 EXIF 데이터
DCIM_FILES=$(sqlite3 Manifest.db "SELECT fileID FROM Files WHERE domain='CameraRollDomain' AND relativePath LIKE '%.jpg'")
for fid in $DCIM_FILES; do
    cp ${fid:0:2}/$fid ./photos/$fid.jpg
    exiftool ./photos/$fid.jpg 2>/dev/null | grep -E "Date|GPS|Location"
done
```

### 시나리오 3: 루팅/탈옥 기기 앱 데이터 추출

```bash
# Android 루팅 기기에서 앱 DB 직접 추출
TARGET_APP="com.target.messenger"

# 앱 데이터 디렉토리 접근
adb shell "su -c 'ls /data/data/${TARGET_APP}/databases/'"

# DB 복사
adb shell "su -c 'cp /data/data/${TARGET_APP}/databases/*.db /sdcard/tmp_forensics/'"
adb pull /sdcard/tmp_forensics/ ./extracted_db/

# 각 DB 분석
for db in ./extracted_db/*.db; do
    echo "=== $(basename $db) ==="
    sqlite3 "$db" ".tables"
done

# 암호화된 DB (SQLCipher) 탐지
file ./extracted_db/*.db
sqlite3 ./extracted_db/messages.db "SELECT count(*) FROM sqlite_master" 2>&1
# "file is not a database" → 암호화됨

# SQLCipher 브루트포스 (단순 비밀번호)
python3 -c "
passwords = ['1234', 'password', '', 'changeit', 'secret']
# sqlcipher를 파이썬으로 접근하려면:
# pip install pysqlcipher3
# from pysqlcipher3 import dbapi2 as sqlcipher
for pwd in passwords:
    print(f'시도: {pwd}')
"
```

### 시나리오 4: 메모리 포렌식 연계

```bash
# Android 메모리 덤프 (LiME 모듈)
# https://github.com/504ensicsLabs/LiME

# LiME 커널 모듈 컴파일 (기기 커널 버전 일치 필요)
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make -C /path/to/kernel/source M=$(pwd) modules

# 기기에 업로드 및 로드
adb push lime.ko /data/local/tmp/
adb shell "su -c 'insmod /data/local/tmp/lime.ko path=/sdcard/memory.lime format=lime'"
adb pull /sdcard/memory.lime ./evidence/

# Volatility로 분석
volatility -f memory.lime --profile=LinuxAndroid_<version> linux_pslist
volatility -f memory.lime --profile=LinuxAndroid_<version> linux_netstat
volatility -f memory.lime --profile=LinuxAndroid_<version> linux_bash
```

### CTF 체크리스트

```
Android APK 분석:
□ AndroidManifest.xml - 권한, 컴포넌트, exported
□ strings.xml - 하드코딩된 값
□ assets/ - 숨겨진 파일
□ res/raw/ - 리소스 파일
□ lib/*.so - 네이티브 코드 (strings, radare2)
□ classes.dex - Java 역컴파일
□ 동적 분석 (Frida, Xposed)

iOS 분석:
□ Manifest.db - 파일 맵
□ Info.plist - 기기 정보
□ sms.db - 메시지
□ CallHistory.storedata - 통화
□ AddressBook.sqlitedb - 연락처
□ Safari History.db - 브라우저
□ 사진 EXIF - 위치/시간
□ Health 데이터
□ keychain - 암호화된 자격증명 (탈옥 필요)

공통:
□ 타임라인 재구성
□ 삭제 파일 복구 시도
□ 암호화 여부 확인
□ 해시값 기록
```

---

## 도구 요약표

| 도구 | 유형 | 주요 용도 | 설치 |
|------|------|-----------|------|
| jadx | 오픈소스 | APK → Java 역컴파일 | GitHub |
| apktool | 오픈소스 | APK → Smali + 리소스 | GitHub |
| dex2jar | 오픈소스 | DEX → JAR 변환 | GitHub |
| Frida | 오픈소스 | 동적 계측/후킹 | `pip install frida` |
| Autopsy | 오픈소스 | GUI 포렌식 분석 | autopsy.com |
| MVT | 오픈소스 | 스파이웨어 탐지 | `pip install mvt` |
| androguard | 오픈소스 | Python APK 분석 | `pip install androguard` |
| ALEAPP | 오픈소스 | Android 아티팩트 파싱 | GitHub |
| iLEAPP | 오픈소스 | iOS 아티팩트 파싱 | GitHub |
| Cellebrite UFED | 상용 | 종합 모바일 추출 | 라이선스 |
| MSAB XRY | 상용 | 종합 모바일 추출 | 라이선스 |
| GrayKey | 상용 | iOS 잠금 해제 | 라이선스 |
| Oxygen Forensics | 상용 | 클라우드+모바일 분석 | 라이선스 |

```bash
# iLEAPP 설치 및 사용 (iOS 아티팩트 파싱)
git clone https://github.com/abrignoni/iLEAPP
cd iLEAPP
pip install -r requirements.txt

# GUI
python ileappGUI.py

# CLI
python ileapp.py -t fs -i /path/to/ios_filesystem -o /path/to/output

# ALEAPP (Android)
git clone https://github.com/abrignoni/ALEAPP
cd ALEAPP
pip install -r requirements.txt
python aleapp.py -t fs -i /path/to/android_filesystem -o /path/to/output
```

---

<!-- detect-validate-47 -->
## 모바일 포렌식 도구 발견 검증과 오탐 관리

모바일 포렌식 도구(Autopsy·MVT/Pegasus·Frida·jadx)는 *아티팩트 파싱·IOC 매칭·동적 계측·역분석*으로 결과를 낸다. 도구 출력은 오탐·버전 의존이 섞이므로 분석자는 **발견을 1차 아티팩트로 교차·재현**해야 한다. 검증은 **소유 기기/이미지**에서만.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| IOC 매칭(MVT) | 1차 근거 있나? | DB/로그서 IOC 재확인 | STIX 단정 |
| 도구 교차 | 다른 도구 일치? | jadx↔apktool 동일 | 단일 도구 |
| 동적 후킹 | 의도 함수? | Frida 후킹 카운트 | 잘못된 시그니처 |
| 재현성 | 동일 입력 동일? | 재실행 동일 출력 | 비결정 |

### 발견 검증 (직접 확인)

```bash
# 1) MVT가 표시한 Pegasus IOC를 1차 아티팩트로 교차(소유 백업) — DB/로그서 재확인돼야 신뢰
mvt-ios check-backup --output out backup_dir 2>/dev/null; grep -rIiE 'detected|malicious' out/ 2>/dev/null | head
# 2) APK 역분석 도구 교차 — jadx↔apktool가 같은 권한/엔드포인트 보고하면 신뢰 상승
apktool d -f app.apk -o ad >/dev/null 2>&1; grep -iE 'INTERNET|SMS|http' ad/AndroidManifest.xml 2>/dev/null | head
```

> 모바일 도구 사용은 *발견이 교차·재현되는가*다 — "MVT가 탐지했다"와 "그 IOC가 1차 아티팩트에서 재확인되고 도구 간 일치한다"는 다르다. 소유 기기/이미지에서 교차 검증한다([[06_Malware_Analysis]], [[28_Mobile_Hacking]], [[25_Threat_Intelligence]]).

---

<a name="english"></a>

# Mobile Forensics Tools

## Table of Contents
1. Autopsy Mobile Analysis Setup
2. Cellebrite UFED / MSAB XRY Overview
3. MVT - Pegasus Spyware Detection
4. Dynamic App Analysis with Frida
5. APK Reverse Engineering (jadx, apktool, dex2jar)
6. Python APK Automated Analysis Script
7. Practical CTF Mobile Forensics Scenarios

---

## 1. Autopsy Mobile Analysis Setup

### Installation and Basic Configuration

```bash
# Ubuntu/Debian
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0.zip
unzip autopsy-4.21.0.zip

# Install dependencies
sudo apt install -y default-jdk testdisk autopsy

# macOS (Homebrew)
brew install sleuthkit

# Windows: Download MSI installer and run
# https://www.autopsy.com/download/

# Launch Autopsy
cd autopsy-4.21.0
./bin/autopsy &
```

### Creating a Mobile Forensics Case

```
1. Create a new case
   File → New Case
   - Case Name: KN-2025-001
   - Base Directory: /cases/
   - Case Type: Single-user

2. Add data source
   Add Data Source → Select type:
   - Disk Image or VM File  : raw/E01/AFF image
   - Local Disk             : directly connected disk
   - Logical Files          : extracted files/folders
   - Unallocated Space Files: unallocated space

3. When adding an Android image
   - Select Disk Image (.img, .raw)
   - Select Ingest Modules:
     ☑ Android Analyzer      : parse Android artifacts
     ☑ Keyword Search         : keyword search
     ☑ Hash Lookup            : NSRL hash comparison
     ☑ File Type Identification: file type detection
     ☑ Exif Parser            : photo metadata
     ☑ Extension Mismatch Detector: disguised file detection
```

### Android Analyzer Module Configuration

```
Artifacts parsed by Autopsy Android Analyzer:
- SMS/MMS (mmssms.db)
- Call Log (calllog.db)
- Contacts (contacts2.db)
- Browser History (browser.db, History)
- Calendar
- GPS movement history
- Wi-Fi connection history
- List of installed apps

Viewing results:
Autopsy → Data Artifacts → Communication Artifacts
                         → GPS Artifacts
                         → Web Artifacts
                         → Installed Programs
```

### Autopsy CLI Mode (Automation)

```bash
# Automate case creation and analysis
# autopsy_casecreate.py (Autopsy Python script)

java -Xmx4g \
    -cp "/opt/autopsy/autopsy/modules/ext/*:/opt/autopsy/platform/core/core.jar" \
    org.sleuthkit.autopsy.commandlineingest.CommandLineIngestManager \
    --createCase \
    --caseDir /cases/ \
    --caseName KN-2025-001 \
    --dataSourcePath /evidence/device.img \
    --outputDir /cases/KN-2025-001/

# Results are saved in /cases/KN-2025-001/Reports/
```

### Autopsy Plugin Development (Python)

```python
# Autopsy Ingest Module example
# File location: ~/.autopsy/dev/python_modules/MyAndroidModule/

import jarray
import inspect
import os
import sys

from java.lang import System
from org.sleuthkit.datamodel import SleuthkitCase, AbstractFile
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices


class AndroidKakaoTalkAnalyzerFactory:
    """KakaoTalk DB analysis module"""
    moduleDisplayName = "KakaoTalk Analyzer"
    moduleDescription = "Extract KakaoTalk messages"

    def getDisplayName(self):
        return self.moduleDisplayName

    def getDescription(self):
        return self.moduleDescription

    def createDataSourceIngestModule(self, settings):
        return AndroidKakaoTalkAnalyzer()


class AndroidKakaoTalkAnalyzer(DataSourceIngestModule):
    KAKAO_DB = "KakaoTalk.db"

    def process(self, data_source, progress_bar):
        # Search for files
        file_manager = Case.getCurrentCase().getServices().getFileManager()
        files = file_manager.findFiles(data_source, self.KAKAO_DB)

        for kakao_file in files:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.DATA,
                    "KakaoTalk Analyzer",
                    f"Found: {kakao_file.getName()}",
                )
            )

        return IngestModule.ProcessResult.OK
```

---

## 2. Cellebrite UFED / MSAB XRY Overview

### Cellebrite UFED Touch 2 / 4PC

```
Product lineup:
- UFED Touch 2   : standalone hardware device
- UFED 4PC       : PC software version
- UFED Premium   : unlock + advanced extraction
- UFED Cloud     : cloud data collection

Supported devices:
- 35,000+ devices including Android/iOS
- New devices added via periodic updates

Extraction process (UFED 4PC):
1. Launch UFED 4PC
2. Connect device (USB)
3. Auto-detect device model
4. Select extraction method (logical/filesystem/physical)
5. Run extraction
6. Analyze results with Physical Analyzer

Output formats:
- .ufdx        : UFED extraction package
- .zip         : logical extraction
- Extraction.xml : extraction metadata

Physical Analyzer features:
- Timeline visualization
- Deleted data recovery
- Per-app artifact classification
- Map visualization (location data)
- Automatic report generation (PDF, HTML, Excel)
```

### MSAB XRY

```
Product line:
- XRY Complete : hardware + software
- XRY Logical  : logical extraction
- XRY Physical : physical extraction
- XAMN Analyst : analysis software

XRY characteristics:
- Originally developed by Swedish law enforcement
- Independent validation possible
- NIST CFTT certified

XRY extraction procedure:
1. Launch XRY and create a new case
2. Connect device
3. Auto-detect device or select manually
4. Select extraction method
5. Enter PIN if prompted (if available)
6. Proceed with extraction
7. Analyze results with XAMN

Output files:
- .xry        : XRY case file
- .ufd        : extracted data
```

### Common Extraction Considerations

```bash
# Always check before extraction
1. USB Restricted Mode (iOS 11.4.1+)
   - USB must remain connected before device locks
   - Data transfer possible if connected within 1 hour

2. Set Airplane Mode
   - Prevent remote wipe
   - Prevent evidence modification

3. Encryption status
   - Android FBE: more data available when extracted after entering PIN
   - iOS: most data encrypted without PIN

4. Battery
   - Prevent discharge during extraction
   - Recommend connecting external power
```

---

## 3. MVT (Mobile Verification Toolkit) - Pegasus Detection

### MVT Installation

```bash
# Install via pip
pip install mvt

# Or install from source
git clone https://github.com/mvt-project/mvt
cd mvt
pip install .

# Verify installation
mvt-ios --help
mvt-android --help

# Install libimobiledevice (iOS)
# Ubuntu
sudo apt install libimobiledevice-utils ideviceinstaller
# macOS
brew install libimobiledevice
```

### Download IOC (Indicators of Compromise)

```bash
# Pegasus IOC (Amnesty International)
wget https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2 \
    -O pegasus.stix2

# MVT official IOC repository (updated regularly)
# https://github.com/mvt-project/mvt-indicators

# Multiple IOC files can be merged and used
ls *.stix2
```

### iOS Analysis

```bash
# 1. Analyze local backup (unencrypted)
mvt-ios check-backup \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

# 2. Decrypt encrypted backup first
mvt-ios decrypt-backup \
    --password "backup_password" \
    --destination ./decrypted_backup \
    ~/Library/Application\ Support/MobileSync/Backup/<UDID>

mvt-ios check-backup \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios \
    ./decrypted_backup

# 3. Directly analyze jailbroken device (requires SSH)
mvt-ios check-fs \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios \
    /   # root of jailbroken device

# 4. Directly from connected device
mvt-ios check-iocs \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_ios
```

### Android Analysis

```bash
# 1. Analysis via ADB
mvt-android check-adb \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_android

# 2. Analyze ADB backup
mvt-android check-backup \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output_android \
    ./android_backup.ab

# 3. Check APKs
mvt-android download-apks \
    --output ./apks/

# Download specific apps only
mvt-android download-apks \
    --output ./apks/ \
    --all-processes

# 4. SMS analysis (phishing link detection)
mvt-android check-adb \
    --iocs ./pegasus.stix2 \
    --output ./mvt_output \
    --module SMSModule
```

### Interpreting MVT Results

```bash
# Output file structure
ls ./mvt_output_ios/
# Example output:
# accessibility.json        - apps using accessibility services
# calls.json                - call history
# chrome_visits.json        - Chrome browsing history
# datausage.json            - data usage per app
# id.json                   - device identifiers
# network_extensions.json   - network extensions
# processes.json            - process list
# sms.json                  - SMS history
# sms_attachments.json      - SMS attachments
# timeline.json             - full timeline
# version_history.json      - iOS version history
# wifi_networks.json        - Wi-Fi history
# DETECTIONS.json           - detected IOCs (key file!)

# Analyze DETECTIONS.json
python3 -c "
import json
with open('./mvt_output_ios/DETECTIONS.json') as f:
    detections = json.load(f)
for d in detections:
    print(f'[DETECTED] {d[\"type\"]}: {d[\"indicator\"]}')
    print(f'  Found in: {d[\"file\"]}')
    print(f'  Timestamp: {d.get(\"timestamp\", \"N/A\")}')
"

# Timeline visualization
python3 -c "
import json
from datetime import datetime
with open('./mvt_output_ios/timeline.json') as f:
    events = json.load(f)
for event in sorted(events, key=lambda x: x.get('timestamp', '')):
    print(f\"{event.get('timestamp', 'N/A')[:19]} | {event.get('module', '')} | {event.get('event', '')[:80]}\")
"
```

### Pegasus Infection Indicators

```
Known Pegasus domain patterns (IOC examples):
- *.nsosrv.com
- *.cloudfront.net (some)
- specific 1-click or 0-click payload domains

Process anomaly indicators:
- bh (background hijacking)
- roleaboutd (iOS persistence daemon)
- coredistld
- aggregatenotd
- crash logs with unknown BundleID

Network indicators:
- abnormal DNS queries
- encrypted C2 communication
- short-interval pings
```

<!-- detect-validate-47 -->
## Mobile Forensics Tool Finding Validation and False-Positive Management

Mobile forensics tools (Autopsy, MVT/Pegasus, Frida, jadx) produce results via *artifact parsing, IOC matching, dynamic instrumentation, and decompilation*. Tool output mixes false positives and version dependence, so the analyst must **cross-check and reproduce findings against primary artifacts**. Validate only on **owned devices/images**.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| IOC match (MVT) | Primary basis? | IOC re-confirmed in DB/log | STIX assertion |
| Tool cross-check | Other tool agrees? | jadx == apktool | Single tool |
| Dynamic hook | Intended function? | Frida hook count | Wrong signature |
| Reproducibility | Same input, same? | Re-run same output | Non-deterministic |

### Finding validation (verify directly)

```bash
# 1) Cross-check an MVT-flagged Pegasus IOC against primary artifacts (owned backup) — trust it only if re-confirmed in DB/log
mvt-ios check-backup --output out backup_dir 2>/dev/null; grep -rIiE 'detected|malicious' out/ 2>/dev/null | head
# 2) APK decompilation tool cross-check — jadx and apktool reporting the same permissions/endpoints raises confidence
apktool d -f app.apk -o ad >/dev/null 2>&1; grep -iE 'INTERNET|SMS|http' ad/AndroidManifest.xml 2>/dev/null | head
```

> Using mobile tools is *whether findings cross-check and reproduce* -- "MVT detected it" differs from "the IOC is re-confirmed in primary artifacts and tools agree". Cross-validate on owned devices/images directly ([[06_Malware_Analysis]], [[28_Mobile_Hacking]], [[25_Threat_Intelligence]]).
