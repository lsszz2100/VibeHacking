# Lab 44: ExtensionGuard — 브라우저 확장 프로그램 보안 & Manifest V3 감사 실습

현대 브라우저 확장 프로그램 환경(Chrome/Chromium Manifest V3)에서의 권한 과잉 부여, 웹 리소스 노출, 콘텐츠 스크립트 DOM XSS 및 강화 기법을 시뮬레이션하는 인터랙티브 실습 랩입니다.

## 🎯 실습 목표
1. **Stage 1 (Manifest V3 Permission Audit)**: manifest.json 보안 명세 감사, 과도한 위험 권한(`<all_urls>`, `webRequestBlocking`, `cookies`) 및 백그라운드 서비스 워커 수명주기 진단
2. **Stage 2 (Web Accessible Resources Leak)**: `web_accessible_resources`의 와일드카드 매칭 오류를 통한 내부 설정 파일(`assets/auth_config.json`) 및 마스터 토큰 탈취
3. **Stage 3 (Content Script DOM XSS & Sniffing)**: 웹페이지에 주입된 `content.js`의 안전하지 않은 `innerHTML` DOM 싱크 악용 및 비밀번호 입력 필드 가로채기 분석
4. **Stage 4 (DNR Ruleset & Extension CSP Hardening)**: 레거시 webRequest를 차세대 Declarative Net Request(DNR)로 전환하고, 격리된 실행 환경 및 엄격한 CSP 정책 강화

## 🚀 빠른 시작

### 로컬 실행 (Python)
```bash
cd labs/44_browser_extension_security_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8044
```

### Docker 실행
```bash
docker-compose up -d --build
```
브라우저에서 `http://127.0.0.1:8044` 접속

## 🧪 테스트 실행
```bash
pytest -v labs/44_browser_extension_security_lab/tests/
```
