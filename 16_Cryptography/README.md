# 16. 암호학 (Cryptography)

> 🔐 **VibeHacking 교재 섹션 16**
> - **CLI 학습**: `python3 vhack.py study 16`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_cryptography_for_hackers.md](./01_cryptography_for_hackers.md) | **해커를 위한 암호학** — 암호학(Cryptography)은 데이터를 안전하게 변환하여 허가된 사람만 읽을 수 있게 하는 학문입니다. 해커 관점에서는 잘못 구현된 암호화, 취약한 알고리즘, 키 관리 실수를 찾아... |
| [02_hash_attacks.md](./02_hash_attacks.md) | **해시 공격 기법 완전 정복** — 해시 함수는 임의 길이의 데이터를 고정 길이의 값(다이제스트)으로 변환하는 단방향 함수입니다. 패스워드 저장, 파일 무결성 검증, 디지털 서명에 필수적이지만, MD5·SHA-1처럼 취... |
| [03_applied_cryptography.md](./03_applied_cryptography.md) | **응용 암호학 — 실전 취약점과 방어** — 응용 암호학은 이론적 암호 알고리즘이 실제 시스템에서 어떻게 구현되고, 그 구현에서 어떤 취약점이 발생하는지를 다루는 분야입니다. 완벽한 알고리즘도 잘못된 모드(ECB), 재사용 IV... |
| [04_PKI_TLS_Attacks.md](./04_PKI_TLS_Attacks.md) | **PKI 인프라 및 TLS/SSL 공격** — PKI(Public Key Infrastructure)는 인터넷 보안의 신뢰 기반으로, 인증서를 통해 서버의 신원을 보증하는 체계입니다. TLS(Transport Layer Secur... |
| [05_crypto_implementation_attacks.md](./05_crypto_implementation_attacks.md) | **암호화 구현 취약점 공격 — 패딩 오라클·타이밍 공격·약한 난수** — 암호화 알고리즘 자체는 안전해도, 잘못된 구현 방식이 공격 경로를 만들어냅니다. 패딩 오라클 공격은 서버의 패딩 에러 응답을 이용해 암호문을 바이트 단위로 복호화합니다. 타이밍 공격은... |
| [06_crypto_ctf_practical_lab.md](./06_crypto_ctf_practical_lab.md) | **암호학 CTF 실습 랩 — 고전암호·RSA·ECC·해시 종합** — pip install pycryptodome sympy gmpy2 |

## 🎯 학습 목표

- 해커를 위한 암호학 원리 및 실전 공격/방어 기법 습득
- 해시 공격 기법 완전 정복 원리 및 실전 공격/방어 기법 습득
- 응용 암호학 — 실전 취약점과 방어 원리 및 실전 공격/방어 기법 습득
- PKI 인프라 및 TLS/SSL 공격 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 16 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
