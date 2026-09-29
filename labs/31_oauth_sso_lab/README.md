# Lab 31: SSOShield — OAuth 2.0 & OIDC 기업용 SSO 침투 실습 랩 (OAuth SSO Lab)

> 🔑 **포트**: `8031`  
> 🎯 **연계 교재**: [05장 웹 해킹: 07_advanced_oauth2_oidc_and_sso_exploitation_deepdive.md](../../05_Web_Hacking/07_advanced_oauth2_oidc_and_sso_exploitation_deepdive.md)  
> 🚩 **연계 워게임 트랙**: `oauth` (OAuth 2.0·OIDC & SSO 보안 35제)

---

## 1. 랩 개요

현대 엔터프라이즈 환경(Google Workspace, Microsoft Entra ID, Okta, GitHub OAuth 등)에서는 싱글 사인온(SSO)과 API 접근 제어를 위해 **OAuth 2.0(RFC 6749)** 및 **OpenID Connect(OIDC Core 1.0)** 프로토콜을 광범위하게 채택하고 있습니다.

그러나 인가 코드(Authorization Code) 전달 검증 미흡, PKCE(RFC 7636) 구현 상의 다운그레이드 결함, JWT ID Token의 서명 검증 키 혼동(`kid` 헤더 인젝션 / HMAC confusion) 등이 결합되면 공격자는 단 한 번의 요청 조작으로 **엔터프라이즈 관리자 계정 전면 탈취(Account Takeover)**를 달성할 수 있습니다.

본 랩에서는 실전 OAuth 2.0 / OIDC 인프라에서 발생하는 3단계 풀체인 침투 시나리오와 방어 하드닝을 실습합니다.

```
+-------------------------------------------------------------------------------+
|                       SSOShield 침투 & 계정 탈취 공격 체인                     |
+-------------------------------------------------------------------------------+
  [ 피해자 사용자 / 브라우저 ]
          │
          ▼  Step 1: Loose Regex Redirect URI 우회 (https://attacker-corp-app.com)
  [ 인가 코드 (Authorization Code) 유출 및 가로채기 ]
          │
          ▼  Step 2: PKCE 다운그레이드 / Code Verifier 검증 생략 토큰 교환
  [ 피해자 Access Token & ID Token 탈취 ]
          │
          ▼  Step 3: JWT Key Confusion & 'kid' 헤더 인젝션을 통한 관리자 ID Token 위조
  [ 👑 기업 최고 관리자 (enterprise_admin) 세션 획득 & 전 시스템 장악 ]
+-------------------------------------------------------------------------------+
```

---

## 2. 랩 실행 방법

```bash
# vhack CLI를 통한 실행 (권장)
vhack lab start 31

# 또는 docker compose 직접 실행
cd labs/31_oauth_sso_lab
docker compose up -d --build

# 웹 콘솔 접속
http://localhost:8031
```

---

## 3. 실습 단계 및 플래그

### Step 1: Redirect URI 정규식 우회 & 인가 코드 탈취
- **취약점**: IdP가 등록된 리다이렉트 URI를 완전 일치(`exact match`)로 검증하지 않고, 느슨한 정규식(`^https?://.*corp-app\.com.*`)으로 처리하여 `https://attacker-corp-app.com` 또는 `https://corp-app.com.attacker.com`과 같은 공격자 도메인으로의 인가 코드 전송을 허용합니다.
- **플래그**: `FLAG{OAUTH_REDIRECT_URI_LEAK_7712}`

### Step 2: PKCE 다운그레이드 & Code Verifier 검증 우회
- **취약점**: 모바일/SPA 클라이언트를 보호하기 위한 PKCE(RFC 7636) 프로토콜에서, 토큰 교환 요청 시 `code_verifier`를 누락하거나 `plain`으로 전송해도 IdP가 필수 검증을 강제하지 않고 토큰을 발급합니다.
- **플래그**: `FLAG{OAUTH_PKCE_DOWNGRADE_CSRF_8823}`

### Step 3: IdP JWT Key Confusion & 'kid' 헤더 인젝션 관리자 탈취
- **취약점**: 클라이언트 애플리케이션이 ID Token 서명 검증 시 신뢰할 수 있는 IdP의 공개키를 엄격히 고정(Pinning)하지 않고, 공격자가 제어하는 `kid` 또는 HMAC 대칭키 알고리즘을 신뢰하여 임의 관리자 클레임(`sub: admin`, `role: enterprise_admin`)의 토큰을 인증합니다.
- **플래그**: `FLAG{OAUTH_IDTOKEN_KEY_CONFUSION_9934}`

---

## 4. 방어 및 하드닝 (Defense & Hardening)

1. **Strict Exact-Match Redirect URI Whitelisting**: 정규식 패턴이나 와일드카드(`*`), 서브도메인 허용을 일체 금지하고 사전 등록된 완전 일치 URL만을 허용합니다.
2. **Mandatory RFC 7636 S256 PKCE Enforcement**: 인가 코드 발급 및 토큰 교환 시 SHA-256 기반 `code_challenge` 및 `code_verifier` 일치를 필수 강제합니다.
3. **Cryptographic State & Nonce Anti-CSRF**: 클라이언트-세션 간 암호학적 난수 `state` 및 ID 토큰 내 `nonce` 일치를 검증하여 재생 및 CSRF 주입을 차단합니다.
4. **Strict JWKS Pinning & RS256 Whitelisting**: IdP 메타데이터와 신뢰할 수 있는 Asymmetric Public Key만을 고정 바인딩하고, 대칭키(HS256) 혼동이나 임의 `kid` 파라미터를 배격합니다.
