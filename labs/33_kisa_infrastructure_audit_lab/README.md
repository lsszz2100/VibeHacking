# Lab 33 — KisaAuditLab: KISA 주요정보통신기반시설 취약점 분석·평가 자동 진단 & 하드닝 랩

이 랩은 대한민국 정보통신망법 및 주요정보통신기반시설 기술적 취약점 분석·평가 기준(KISA 가이드라인)에 따라 엔터프라이즈 Unix/Linux 서버의 계정, 파일 권한, 서비스 보안을 자동 진단하고, 발견된 취약점 침투 모의 및 원클릭 컴플라이언스 하드닝을 수행하는 실전 실습 환경입니다.

---

## 1. 랩 개요

- **타깃 시스템**: 엔터프라이즈 리눅스(CentOS/RHEL 계열) 운영 코어 서버
- **접속 포트**: `127.0.0.1:8033` (웹 대시보드 및 REST 진단 API)
- **점검 기준**: KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드 (Unix/Linux 서버 편)
- **주요 점검 분야**:
  - **계정 관리**: root 원격 접속 제한(U-01), 패스워드 복잡도(U-02), 계정 잠금 임계값(U-03), shadow 파일 권한(U-04)
  - **서비스 관리**: 익명 FTP 차단(U-20), SSH 취약 암호화 알고리즘 차단 및 배너 은닉(U-44)
  - **보안 하드닝**: 전 항목 컴플라이언스 기준 100% 양호 조치

---

## 2. 3단계 실전 진단/침투 시나리오 & 획득 플래그

### Step 1: 계정 관리 취약점 전수 진단 (U-01 ~ U-04)
- **진단 원리**: 시스템 감사 스크립트가 `/etc/ssh/sshd_config`, `/etc/security/pwquality.conf`, `/etc/pam.d/system-auth`, `/etc/shadow`를 검사하여 root 직접 원격 로그인 허용, 4자리 단순 비밀번호 허용, 무차별 대입 방어(faillock) 미적용, shadow 파일 0644 권한 노출을 적발합니다.
- **API**: `POST /api/kisa/audit/accounts`
- **획득 플래그**: `FLAG{KISA_U01_U04_ACCOUNT_AUDIT_PWNED_1109}`

### Step 2: 취약 네트워크 서비스 익스플로잇 (U-20, U-44)
- **공격 원리**:
  1. `U-20`: vsftpd 익명 로그인(`anonymous:anonymous`)을 악용하여 `/var/ftp/pub`에 방치된 내부 백업 정보 및 암호화 자격증명 파일을 탈취합니다.
  2. `U-44`: 취약한 레거시 암호(3DES-CBC, AES-CBC) 및 OS 버전 정보가 노출된 SSH 배너를 프로빙하여 공격 표면을 수집합니다.
- **API**: `POST /api/kisa/exploit/services`
- **획득 플래그**: `FLAG{KISA_U20_U44_VULN_SERVICE_EXPLOITED_2241}`

### Step 3: 원클릭 보안 하드닝 & 컴플라이언스 인증 통과
- **방어 원리**: KISA 가이드라인 기준에 맞추어 `PermitRootLogin no`, `pwquality minlen=8`, `pam_faillock deny=5`, `chmod 400 /etc/shadow`, `anonymous_enable=NO`, SSH 안전한 GCM/Poly1305 암호군 강제 적용을 일괄 수행하여 컴플라이언스 100% PASS 인증을 달성합니다.
- **API**: `POST /api/kisa/harden`
- **획득 플래그**: `FLAG{KISA_HARDENING_COMPLIANCE_PASSED_3378}`

---

## 3. 빠른 시작

```bash
# 실습 랩 시작
vhack lab start 33

# 상태 점검
vhack lab status

# 자동 PoC 솔버 실행
vhack solve 33 --step 1
vhack solve 33 --step 2
vhack solve 33 --step 3
```
