> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 57-4. NIST PQC 표준화: 라운드별 현황, 최종 선정, FIPS 표준

## 0. 초보자를 위한 개념 이해

### NIST PQC 표준화란?

NIST(미국 국립표준기술연구소)가 양자 컴퓨터 위협에 대비하여 2016년부터 8년간 전 세계 암호학자들과 함께 진행한 차세대 암호 표준화 프로젝트이다. 2024년 8월에 최종 3개 표준(FIPS 203·204·205)이 확정되었으며, 이는 인터넷 보안 역사상 가장 중요한 전환점 중 하나이다. 기업과 정부기관은 이 표준으로 기존 암호 시스템을 교체해야 한다.

**왜 배우는가:**
```
[NIST PQC 표준화 타임라인]

2016 ── 제출 요청 공고 (69개 후보 제출)
  │
2019 ── 1라운드 → 26개로 압축
  │
2020 ── 2라운드 → 15개로 압축
  │
2022 ── 3라운드 종료 → 4개 최종 후보 선정
  │         ML-KEM (키 교환)
  │         ML-DSA, SLH-DSA (디지털 서명)
  │         FALCON (추가 서명)
  │
2024 ── FIPS 203/204/205 공식 표준 발표 ★
  │
2030 ── 기존 RSA/ECC 완전 퇴출 목표 (CNSA 2.0)

영향 범위: TLS, SSH, 코드 서명, VPN, PKI 등 모든 보안 인프라
```

### 핵심 개념 정리

```
주요 용어:
- FIPS(Federal Information Processing Standard): 미국 연방 정보처리 표준
- FIPS 203 (ML-KEM): 키 캡슐화 메커니즘 표준 - HTTPS 키 교환에 사용
- FIPS 204 (ML-DSA): 모듈 격자 기반 디지털 서명 표준
- FIPS 205 (SLH-DSA): 해시 기반 디지털 서명 표준 (가장 보수적·안전)
- CNSA 2.0: 미국 NSA의 양자 내성 알고리즘 사용 권고안 (2022)
- 하이브리드 모드: 전환기에 기존 알고리즘 + PQC를 병행 사용하는 방식
- 암호 민첩성(Crypto Agility): 알고리즘을 쉽게 교체할 수 있는 시스템 설계
```

### 필요한 도구 및 환경
- **Python 3.10+**: cryptography 라이브러리
- **OpenSSL 3.4+**: FIPS 203/204 지원 버전
- **OQS-Provider**: OpenSSL에서 PQC 알고리즘을 사용하기 위한 플러그인
- **참고 문서**: https://csrc.nist.gov/pubs/fips/203/final

### 기초 실습 예제
```python
# FIPS 표준 알고리즘 파라미터 비교 및 선택 가이드
from dataclasses import dataclass

@dataclass
class PQCAlgorithm:
    """NIST PQC 표준 알고리즘 정보"""
    fips_number: str    # FIPS 표준 번호
    name: str           # 알고리즘 이름
    purpose: str        # 용도
    security_level: int # NIST 보안 레벨 (1~5)
    public_key_bytes: int
    signature_bytes: int | None
    ciphertext_bytes: int | None
    notes: str

# NIST 확정 표준 알고리즘 목록
nist_standards = [
    PQCAlgorithm("FIPS 203", "ML-KEM-512",  "키 교환", 1,  800,  None, 768,  "경량 IoT 기기"),
    PQCAlgorithm("FIPS 203", "ML-KEM-768",  "키 교환", 3, 1184,  None, 1088, "일반 권장 (TLS)"),
    PQCAlgorithm("FIPS 203", "ML-KEM-1024", "키 교환", 5, 1568,  None, 1568, "고보안 환경"),
    PQCAlgorithm("FIPS 204", "ML-DSA-44",   "서명",    2, 1312,  2420, None, "빠른 서명 필요"),
    PQCAlgorithm("FIPS 204", "ML-DSA-65",   "서명",    3, 1952,  3293, None, "일반 권장"),
    PQCAlgorithm("FIPS 204", "ML-DSA-87",   "서명",    5, 2592,  4595, None, "장기 보안"),
    PQCAlgorithm("FIPS 205", "SLH-DSA-128s","서명",    1,   32, 7856, None, "작은 키, 느린 서명"),
    PQCAlgorithm("FIPS 205", "SLH-DSA-256f","서명",    5,   64, 49856,None, "빠른 서명, 큰 크기"),
]

print("=== NIST PQC 표준 알고리즘 비교 ===\n")
print(f"{'표준':<10} {'알고리즘':<16} {'용도':<8} {'보안레벨':<10} {'공개키(B)':<12} {'비고'}")
print("-" * 75)
for alg in nist_standards:
    print(f"{alg.fips_number:<10} {alg.name:<16} {alg.purpose:<8} "
          f"Level {alg.security_level:<5} {alg.public_key_bytes:<12} {alg.notes}")

print("\n=== 용도별 권장 알고리즘 ===")
recommendations = {
    "TLS 1.3 키 교환": "ML-KEM-768 (FIPS 203, Level 3)",
    "코드 서명":        "ML-DSA-65 (FIPS 204, Level 3)",
    "장기 보관 문서":   "SLH-DSA-256f (FIPS 205, Level 5)",
    "IoT/경량 기기":   "ML-KEM-512 + ML-DSA-44",
    "전환기 하이브리드": "X25519 + ML-KEM-768 (동시 사용)",
}
for use_case, rec in recommendations.items():
    print(f"  {use_case:<20}: {rec}")
```

---

## 개요

미국 국립표준기술연구소(NIST)는 2016년 양자 컴퓨터에 안전한 암호 알고리즘 표준화 프로젝트를 시작했다. 2024년 8월, 8년간의 심층 평가 끝에 3개의 최종 표준(FIPS 203, 204, 205)을 공식 발표했다. 이는 인터넷 보안 인프라 전반에 영향을 미치는 역사적 전환점이다.

---

## 1. NIST PQC 표준화 라운드별 진행 현황

### 1.1 전체 타임라인

| 단계 | 기간 | 주요 사건 |
|------|------|---------|
| 공모 시작 | 2016년 12월 | NIST 알고리즘 제출 요청 공고 |
| 제출 마감 | 2017년 11월 | 69개 완전 후보, 13개 부분 후보 |
| 1라운드 | 2017~2019년 | 69개 → 26개 선정 |
| 2라운드 | 2019~2020년 | 26개 → 15개 (7 Finalist + 8 Alternate) |
| 3라운드 | 2020~2022년 | 15개 → 7개 최종 후보 |
| 최종 선정 발표 | 2022년 7월 | 4개 알고리즘 선정 |
| FIPS 초안 발표 | 2023년 8월 | FIPS 203/204/205 초안 공개 |
| **FIPS 최종 확정** | **2024년 8월** | **FIPS 203/204/205 공식 표준** |
| 4라운드 (서명) | 2022~현재 | KEM 이외 추가 서명 알고리즘 평가 |

### 1.2 1라운드 후보 (69개) 분류

| 분류 | 후보 수 | 주요 제출 알고리즘 |
|------|--------|-----------------|
| 격자 기반 KEM | 21개 | CRYSTALS-Kyber, NTRU, SABER, LAC, LIMA ... |
| 격자 기반 서명 | 6개 | CRYSTALS-Dilithium, FALCON, NTRU Prime ... |
| 코드 기반 | 17개 | Classic McEliece, BIKE, HQC, NTS-KEM ... |
| 해시 기반 서명 | 2개 | SPHINCS, GRAVITY-SPHINCS |
| 다변수 | 7개 | GeMSS, Rainbow, MQDSS ... |
| 동종 | 6개 | SIKE, CSIDH, SIDH ... |
| 기타 | 10개 | Frodo, NewHope, ... |

### 1.3 2라운드 진출 후보 (26개)

| 유형 | Finalist (7개) | Alternate (8개) | 탈락 이유 |
|------|--------------|---------------|----------|
| KEM | CRYSTALS-Kyber, NTRU, SABER, Classic McEliece | BIKE, FrodoKEM, HQC, NTRU Prime | 성능/크기 균형 미흡 |
| 서명 | CRYSTALS-Dilithium, FALCON, Rainbow, SPHINCS+ | GeMSS, Picnic, LUOV, ... | 보안 분석 우려 |

### 1.4 3라운드 결과 및 최종 선정

| 알고리즘 | 유형 | 결과 | 탈락 이유 (해당 시) |
|---------|------|------|------------------|
| **CRYSTALS-Kyber** | KEM | **최종 선정** | - |
| **CRYSTALS-Dilithium** | 서명 | **최종 선정** | - |
| **FALCON** | 서명 | **최종 선정** | - |
| **SPHINCS+** | 서명 | **최종 선정** | - |
| NTRU | KEM | 철수 | 특허 문제, Kyber 유사 |
| SABER | KEM | 탈락 | Kyber 대비 성능 열세 |
| Rainbow | 서명 | **분석으로 붕괴** | Ward Beullens의 실용적 공격 (2022) |
| Classic McEliece | KEM | 4라운드 | 공개키 크기 문제 |
| BIKE, HQC | KEM | 4라운드 | 추가 분석 진행 중 |
| SIKE | KEM | **완전 붕괴** | 동종 공격으로 수시간 내 분해 (2022) |
| GeMSS | 서명 | 탈락 | 보안 분석 우려 |

---

## 2. 최종 선정 알고리즘 상세

### 2.1 알고리즘별 특성 및 용도 비교

| 속성 | ML-KEM (Kyber) | ML-DSA (Dilithium) | SLH-DSA (SPHINCS+) | FN-DSA (FALCON) |
|------|---------------|-------------------|-------------------|----------------|
| **FIPS 번호** | FIPS 203 | FIPS 204 | FIPS 205 | FIPS 206 (예정) |
| **용도** | 키 캡슐화 (KEM) | 디지털 서명 | 디지털 서명 | 디지털 서명 |
| **수학 기반** | Module-LWE | Module-LWE + SIS | 해시 함수 | NTRU 격자 |
| **보안 레벨** | 1/3/5 (128/192/256) | 2/3/5 | 1/3/5 | 1/5 |
| **공개키 (L3)** | 1,184 B | 1,952 B | 32~64 B | - |
| **비밀키 (L3)** | 2,400 B | 4,000 B | 64~128 B | - |
| **출력 크기 (L3)** | 1,088 B (암호문) | 3,293 B (서명) | 7,856~49,856 B | 690~1,330 B |
| **키 생성 속도** | 매우 빠름 | 빠름 | 빠름 | 느림 (트랩도어) |
| **서명/암호화** | 매우 빠름 | 빠름 | 매우 느림 | 빠름 |
| **검증/복호화** | 매우 빠름 | 매우 빠름 | 빠름 | 매우 빠름 |
| **주요 적합 용도** | TLS, 키 교환 | 일반 서명, PKI | 장기 보존, 패치 | 소형 서명 필요 시 |
| **구현 복잡도** | 낮음 | 낮음 | 낮음 | 높음 (Gaussian 샘플링) |
| **부채널 공격** | 중간 위험 | 낮음 | 낮음 | 높은 주의 필요 |

### 2.2 보안 레벨 정의

NIST는 5가지 보안 레벨을 정의했다:

| 레벨 | 고전 보안 강도 | 양자 보안 강도 | 동등한 고전 알고리즘 |
|------|-------------|-------------|-----------------|
| 1 | 128비트 이상 | AES-128 수준 | AES-128 전수 조사보다 어렵거나 같음 |
| 2 | - | SHA-256 충돌 수준 | SHA-256 충돌 찾기보다 어렵거나 같음 |
| 3 | 192비트 이상 | AES-192 수준 | AES-192 전수 조사보다 어렵거나 같음 |
| 4 | - | SHA-384 충돌 수준 | SHA-384 충돌 찾기보다 어렵거나 같음 |
| 5 | 256비트 이상 | AES-256 수준 | AES-256 전수 조사보다 어렵거나 같음 |

---

## 3. FIPS 표준 개요

### 3.1 FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)

**공식 발표**: 2024년 8월 13일

**주요 내용:**
- ML-KEM-512 (보안 레벨 1)
- ML-KEM-768 (보안 레벨 3, **권장**)
- ML-KEM-1024 (보안 레벨 5)

**KEM의 역할:**
```
Alice                     Bob
  |                        |
  |--- 공개키 pk -------->  |
  |                        | 공유 비밀 K, 암호문 c 생성
  |<-- 암호문 c ----------  |
  | K = Decap(sk, c)       |
```

KEM은 키 합의 프로토콜(DH, ECDH)을 대체하며, TLS 1.3의 키 교환 단계에 사용된다.

### 3.2 FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)

**공식 발표**: 2024년 8월 13일

**주요 내용:**
- ML-DSA-44 (보안 레벨 2, CRYSTALS-Dilithium2에 대응)
- ML-DSA-65 (보안 레벨 3, CRYSTALS-Dilithium3에 대응, **권장**)
- ML-DSA-87 (보안 레벨 5, CRYSTALS-Dilithium5에 대응)

**Fiat-Shamir with Aborts** 기법 사용:
- 서명 알고리즘이 실패할 경우 재시도 (평균 약 4~7회 시도)
- 이는 결정론적이지 않아 구현 시 주의 필요

### 3.3 FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)

**공식 발표**: 2024년 8월 13일

**주요 내용:**
- SLH-DSA-SHA2-128s/128f (보안 레벨 1)
- SLH-DSA-SHA2-192s/192f (보안 레벨 3)
- SLH-DSA-SHA2-256s/256f (보안 레벨 5)
- SHA-3 변형도 존재 (SLH-DSA-SHAKE-...)

**s vs f 변형:**

| 변형 | 서명 크기 | 서명 속도 | 적합 용도 |
|------|---------|---------|---------|
| **-s (small)** | 작음 | 느림 | 서명 크기 제약 시 |
| **-f (fast)** | 큼 | 빠름 | 서명 속도 중요 시 |

---

## 4. 기존 TLS vs 하이브리드 PQC-TLS 비교

### 4.1 TLS 1.3 핸드셰이크 비교

| 단계 | 기존 TLS 1.3 | PQC-TLS 1.3 | 하이브리드 TLS 1.3 |
|------|------------|------------|-----------------|
| 키 교환 | ECDHE (P-256) | ML-KEM-768 | X25519+Kyber768 |
| 서버 인증 | ECDSA P-256 | ML-DSA-65 | ECDSA+ML-DSA |
| 클라이언트 인증 | RSA/ECDSA | ML-DSA-65 | RSA+ML-DSA |
| 대칭 암호 | AES-128-GCM | AES-256-GCM | AES-256-GCM |
| 데이터 무결성 | SHA-256 | SHA-256 이상 | SHA-256 이상 |
| 핸드셰이크 크기 | ~300B | ~2,500B | ~2,800B |
| 양자 저항성 | 없음 | 완전 | 하이브리드 보장 |

### 4.2 하이브리드 키 교환 표준화 현황

IETF는 TLS 1.3을 위한 하이브리드 KEM 그룹을 표준화 중이다:

| 하이브리드 그룹 이름 | 구성 | 상태 |
|-----------------|------|------|
| `X25519Kyber768Draft00` | X25519 + Kyber-768 | Chrome/Firefox 실험적 지원 |
| `SecP256r1Kyber768Draft00` | ECDH P-256 + Kyber-768 | 시험 중 |
| `X25519MLKEM768` | X25519 + ML-KEM-768 | IETF RFC 초안 |

**Google Chrome**은 2023년부터 하이브리드 KEM(X25519Kyber768)을 기본 활성화했다.

---

## 5. Python CLI: PQC 인증서 생성 시뮬레이터

```python
#!/usr/bin/env python3
"""
PQC 인증서 생성 시뮬레이터
ML-KEM/ML-DSA 파라미터를 사용하여 X.509 유사 구조의 PQC 인증서를 시뮬레이션
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


# NIST FIPS 알고리즘 OID 시뮬레이션 (실제 OID 기반)
ALGORITHM_OID = {
    "ml-kem-512":  "2.16.840.1.101.3.4.4.1",
    "ml-kem-768":  "2.16.840.1.101.3.4.4.2",
    "ml-kem-1024": "2.16.840.1.101.3.4.4.3",
    "ml-dsa-44":   "2.16.840.1.101.3.4.3.17",
    "ml-dsa-65":   "2.16.840.1.101.3.4.3.18",
    "ml-dsa-87":   "2.16.840.1.101.3.4.3.19",
    "slh-dsa-sha2-128s": "2.16.840.1.101.3.4.3.20",
    "slh-dsa-sha2-256s": "2.16.840.1.101.3.4.3.22",
}

# 알고리즘별 키 크기 파라미터 (NIST FIPS 기준)
ALGORITHM_PARAMS = {
    "ml-kem-512":  {"pk_size": 800,  "sk_size": 1632, "ct_size": 768,  "level": 1, "type": "KEM"},
    "ml-kem-768":  {"pk_size": 1184, "sk_size": 2400, "ct_size": 1088, "level": 3, "type": "KEM"},
    "ml-kem-1024": {"pk_size": 1568, "sk_size": 3168, "ct_size": 1568, "level": 5, "type": "KEM"},
    "ml-dsa-44":   {"pk_size": 1312, "sk_size": 2528, "sig_size": 2420, "level": 2, "type": "DSA"},
    "ml-dsa-65":   {"pk_size": 1952, "sk_size": 4000, "sig_size": 3293, "level": 3, "type": "DSA"},
    "ml-dsa-87":   {"pk_size": 2592, "sk_size": 4864, "sig_size": 4595, "level": 5, "type": "DSA"},
    "slh-dsa-sha2-128s": {"pk_size": 32,  "sk_size": 64,  "sig_size": 7856,  "level": 1, "type": "DSA"},
    "slh-dsa-sha2-256s": {"pk_size": 64,  "sk_size": 128, "sig_size": 29792, "level": 5, "type": "DSA"},
}


@dataclass
class PQCPublicKey:
    """PQC 공개키 구조"""
    algorithm: str
    key_bytes: bytes
    oid: str

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "oid": self.oid,
            "key_length_bytes": len(self.key_bytes),
            "key_hex_preview": self.key_bytes[:16].hex() + "...",
        }


@dataclass
class PQCPrivateKey:
    """PQC 비밀키 구조"""
    algorithm: str
    key_bytes: bytes
    public_key: PQCPublicKey


@dataclass
class CertificateSubject:
    """인증서 주체 정보"""
    common_name: str
    organization: str = "PQC Example Org"
    country: str = "KR"
    state: str = "Seoul"

    def to_distinguished_name(self) -> str:
        return (f"CN={self.common_name}, O={self.organization}, "
                f"ST={self.state}, C={self.country}")


@dataclass
class PQCCertificate:
    """X.509 유사 PQC 인증서 구조"""
    version: int
    serial_number: int
    subject: CertificateSubject
    issuer: CertificateSubject
    not_before: datetime
    not_after: datetime
    public_key: PQCPublicKey
    signature_algorithm: str
    signature: bytes
    extensions: dict = field(default_factory=dict)
    fingerprint: str = field(default="")

    def __post_init__(self) -> None:
        self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        """인증서 핑거프린트 계산 (SHA-256)"""
        data = (
            str(self.serial_number) +
            self.subject.to_distinguished_name() +
            self.not_before.isoformat() +
            self.public_key.key_bytes[:32].hex()
        )
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "serial_number": self.serial_number,
            "subject": self.subject.to_distinguished_name(),
            "issuer": self.issuer.to_distinguished_name(),
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "public_key": self.public_key.to_dict(),
            "signature_algorithm": self.signature_algorithm,
            "signature_length_bytes": len(self.signature),
            "signature_hex_preview": self.signature[:16].hex() + "...",
            "fingerprint_sha256": self.fingerprint,
            "extensions": self.extensions,
        }


def generate_pqc_keypair(algorithm: str) -> tuple[PQCPublicKey, PQCPrivateKey]:
    """PQC 키 쌍 생성 시뮬레이션"""
    if algorithm not in ALGORITHM_PARAMS:
        raise ValueError(f"지원하지 않는 알고리즘: {algorithm}")

    params = ALGORITHM_PARAMS[algorithm]
    oid = ALGORITHM_OID.get(algorithm, "0.0.0")

    # 결정론적 키 생성 시뮬레이션
    seed = os.urandom(32)
    pk_bytes = hashlib.shake_256(b"pk" + seed).digest(params["pk_size"])
    sk_bytes = hashlib.shake_256(b"sk" + seed).digest(params["sk_size"])

    pub_key = PQCPublicKey(algorithm=algorithm, key_bytes=pk_bytes, oid=oid)
    priv_key = PQCPrivateKey(algorithm=algorithm, key_bytes=sk_bytes, public_key=pub_key)

    return pub_key, priv_key


def generate_pqc_signature(
    priv_key: PQCPrivateKey,
    data: bytes,
    sig_algorithm: str
) -> bytes:
    """PQC 서명 생성 시뮬레이션"""
    if sig_algorithm not in ALGORITHM_PARAMS:
        raise ValueError(f"서명 알고리즘 미지원: {sig_algorithm}")
    if ALGORITHM_PARAMS[sig_algorithm]["type"] != "DSA":
        raise ValueError(f"{sig_algorithm}은 서명 알고리즘이 아닙니다.")

    sig_size = ALGORITHM_PARAMS[sig_algorithm]["sig_size"]
    sig_hash = hashlib.sha3_512(data + priv_key.key_bytes[:32]).digest()
    # 서명 크기 맞추기
    sig = hashlib.shake_256(sig_hash).digest(sig_size)
    return sig


def create_pqc_certificate(
    subject_cn: str,
    kem_algorithm: str,
    sig_algorithm: str,
    validity_days: int,
    is_ca: bool = False,
    issuer_cn: Optional[str] = None
) -> tuple[PQCCertificate, PQCPrivateKey]:
    """PQC 인증서 생성"""
    # 키 쌍 생성
    pub_key, priv_key = generate_pqc_keypair(kem_algorithm)

    # 자기 서명 CA 또는 일반 인증서
    subject = CertificateSubject(common_name=subject_cn)
    issuer = CertificateSubject(common_name=issuer_cn or subject_cn)

    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=validity_days)

    # 시리얼 넘버 생성
    serial = int.from_bytes(os.urandom(8), "big")

    # TBS(To Be Signed) 데이터 구성
    tbs_data = (
        str(serial) +
        subject.to_distinguished_name() +
        issuer.to_distinguished_name() +
        now.isoformat() +
        not_after.isoformat() +
        pub_key.key_bytes.hex()
    ).encode()

    # 서명 알고리즘이 DSA 타입이면 서명 생성
    if sig_algorithm in ALGORITHM_PARAMS and ALGORITHM_PARAMS[sig_algorithm]["type"] == "DSA":
        _, sig_priv = generate_pqc_keypair(sig_algorithm)
        signature = generate_pqc_signature(sig_priv, tbs_data, sig_algorithm)
    else:
        signature = os.urandom(ALGORITHM_PARAMS.get("ml-dsa-65", {}).get("sig_size", 3293))

    # 확장 필드 설정
    extensions = {
        "basicConstraints": {
            "isCA": is_ca,
            "pathLenConstraint": 0 if is_ca else None,
        },
        "keyUsage": (
            ["keyCertSign", "cRLSign"] if is_ca
            else ["keyEncipherment", "keyAgreement"]
        ),
        "subjectKeyIdentifier": hashlib.sha1(pub_key.key_bytes[:32]).hexdigest(),
        "pqcSecurityLevel": ALGORITHM_PARAMS[kem_algorithm]["level"],
        "fipsStandard": {
            "ml-kem-512": "FIPS 203",
            "ml-kem-768": "FIPS 203",
            "ml-kem-1024": "FIPS 203",
            "ml-dsa-44": "FIPS 204",
            "ml-dsa-65": "FIPS 204",
            "ml-dsa-87": "FIPS 204",
            "slh-dsa-sha2-128s": "FIPS 205",
            "slh-dsa-sha2-256s": "FIPS 205",
        }.get(kem_algorithm, "TBD"),
    }

    cert = PQCCertificate(
        version=3,
        serial_number=serial,
        subject=subject,
        issuer=issuer,
        not_before=now,
        not_after=not_after,
        public_key=pub_key,
        signature_algorithm=sig_algorithm,
        signature=signature,
        extensions=extensions,
    )

    return cert, priv_key


def save_certificate(
    cert: PQCCertificate,
    output_dir: Path,
    filename_prefix: str
) -> dict[str, Path]:
    """인증서를 파일로 저장"""
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_files: dict[str, Path] = {}

    # JSON 형식 인증서 저장
    json_path = output_dir / f"{filename_prefix}_cert.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(cert.to_dict(), f, indent=2, ensure_ascii=False)
    saved_files["certificate_json"] = json_path

    # 공개키 바이너리 저장
    pk_path = output_dir / f"{filename_prefix}_pk.bin"
    pk_path.write_bytes(cert.public_key.key_bytes)
    saved_files["public_key"] = pk_path

    # 서명 바이너리 저장
    sig_path = output_dir / f"{filename_prefix}_sig.bin"
    sig_path.write_bytes(cert.signature)
    saved_files["signature"] = sig_path

    # 인증서 요약 텍스트 저장
    summary_path = output_dir / f"{filename_prefix}_summary.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write("PQC 인증서 요약\n")
        f.write("=" * 60 + "\n")
        f.write(f"주체: {cert.subject.to_distinguished_name()}\n")
        f.write(f"발급자: {cert.issuer.to_distinguished_name()}\n")
        f.write(f"유효 기간: {cert.not_before.strftime('%Y-%m-%d')} ~ {cert.not_after.strftime('%Y-%m-%d')}\n")
        f.write(f"공개키 알고리즘: {cert.public_key.algorithm}\n")
        f.write(f"공개키 OID: {cert.public_key.oid}\n")
        f.write(f"공개키 크기: {len(cert.public_key.key_bytes):,} 바이트\n")
        f.write(f"서명 알고리즘: {cert.signature_algorithm}\n")
        f.write(f"서명 크기: {len(cert.signature):,} 바이트\n")
        f.write(f"시리얼 번호: {cert.serial_number}\n")
        f.write(f"핑거프린트(SHA-256): {cert.fingerprint}\n")
        for ext_name, ext_value in cert.extensions.items():
            f.write(f"확장: {ext_name} = {ext_value}\n")
    saved_files["summary"] = summary_path

    return saved_files


def print_certificate_info(cert: PQCCertificate) -> None:
    """인증서 정보 출력"""
    print("\n  인증서 상세 정보:")
    print(f"  {'버전':<20}: {cert.version}")
    print(f"  {'시리얼 번호':<20}: {cert.serial_number}")
    print(f"  {'주체':<20}: {cert.subject.to_distinguished_name()}")
    print(f"  {'발급자':<20}: {cert.issuer.to_distinguished_name()}")
    print(f"  {'유효 시작':<20}: {cert.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {'유효 종료':<20}: {cert.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"\n  공개키 정보:")
    print(f"  {'알고리즘':<20}: {cert.public_key.algorithm.upper()}")
    print(f"  {'OID':<20}: {cert.public_key.oid}")
    print(f"  {'공개키 크기':<20}: {len(cert.public_key.key_bytes):,} 바이트")
    print(f"  {'공개키 미리보기':<20}: {cert.public_key.key_bytes[:8].hex()}...")
    print(f"\n  서명 정보:")
    print(f"  {'서명 알고리즘':<20}: {cert.signature_algorithm.upper()}")
    print(f"  {'서명 크기':<20}: {len(cert.signature):,} 바이트")
    print(f"  {'서명 미리보기':<20}: {cert.signature[:8].hex()}...")
    print(f"\n  보안 정보:")
    print(f"  {'핑거프린트':<20}: {cert.fingerprint[:32]}...")
    print(f"  {'NIST 보안 레벨':<20}: Level {cert.extensions.get('pqcSecurityLevel', 'N/A')}")
    print(f"  {'FIPS 표준':<20}: {cert.extensions.get('fipsStandard', 'N/A')}")


def run_certificate_generation(args: argparse.Namespace) -> int:
    """인증서 생성 메인 실행"""
    algorithm: str = args.algorithm
    output_dir = Path(args.output_dir)
    validity_days: int = args.validity_days
    sig_algorithm: str = args.sig_algorithm
    subject_cn: str = args.common_name
    is_ca: bool = args.ca

    print("=" * 68)
    print("  PQC 인증서 생성 시뮬레이터 (NIST FIPS 203/204/205)")
    print("=" * 68)

    print(f"\n  설정:")
    print(f"  - KEM 알고리즘    : {algorithm}")
    print(f"  - 서명 알고리즘   : {sig_algorithm}")
    print(f"  - 출력 디렉토리   : {output_dir}")
    print(f"  - 유효 기간       : {validity_days}일")
    print(f"  - 주체 CN         : {subject_cn}")
    print(f"  - CA 인증서       : {'예' if is_ca else '아니오'}")

    # 알고리즘 검증
    if algorithm not in ALGORITHM_PARAMS:
        print(f"\n오류: 지원하지 않는 KEM 알고리즘: {algorithm}", file=sys.stderr)
        print(f"지원 목록: {', '.join(ALGORITHM_PARAMS.keys())}", file=sys.stderr)
        return 1

    if sig_algorithm not in ALGORITHM_PARAMS:
        print(f"\n오류: 지원하지 않는 서명 알고리즘: {sig_algorithm}", file=sys.stderr)
        return 1

    if ALGORITHM_PARAMS[sig_algorithm]["type"] != "DSA":
        print(f"\n오류: {sig_algorithm}은 서명 알고리즘이 아닙니다.", file=sys.stderr)
        return 1

    print(f"\n  인증서 생성 중...")

    try:
        cert, priv_key = create_pqc_certificate(
            subject_cn=subject_cn,
            kem_algorithm=algorithm,
            sig_algorithm=sig_algorithm,
            validity_days=validity_days,
            is_ca=is_ca,
        )
    except ValueError as e:
        print(f"\n오류: {e}", file=sys.stderr)
        return 1

    print_certificate_info(cert)

    # 파일 저장
    prefix = subject_cn.replace(" ", "_").replace(".", "_").lower()
    print(f"\n  파일 저장 중 ({output_dir})...")

    try:
        saved = save_certificate(cert, output_dir, prefix)
        print("\n  저장된 파일:")
        for file_type, file_path in saved.items():
            size = file_path.stat().st_size
            print(f"  - {file_type:<20}: {file_path.name} ({size:,}B)")
    except OSError as e:
        print(f"\n오류: 파일 저장 실패 - {e}", file=sys.stderr)
        return 1

    # 기존 RSA/ECDSA 대비 크기 비교
    print("\n  PQC vs 고전 암호 인증서 크기 비교:")
    print(f"  {'항목':<25}  {'RSA-2048':>10}  {'ECDSA P-256':>12}  {algorithm.upper():>16}")
    pk_size = len(cert.public_key.key_bytes)
    sig_size = len(cert.signature)
    rows = [
        ("공개키 크기 (B)", 256, 65, pk_size),
        ("서명 크기 (B)", 256, 71, sig_size),
        ("합계 (B)", 512, 136, pk_size + sig_size),
    ]
    for label, rsa_v, ecdsa_v, pqc_v in rows:
        print(f"  {label:<25}  {rsa_v:>10,}  {ecdsa_v:>12,}  {pqc_v:>16,}")

    print(f"\n  크기 증가율 (RSA-2048 대비):")
    print(f"  - 공개키: {pk_size / 256:.1f}배")
    print(f"  - 서명:   {sig_size / 256:.1f}배")

    print("\n  인증서 생성 완료.")
    return 0


def parse_arguments() -> argparse.Namespace:
    """명령행 인수 파싱"""
    parser = argparse.ArgumentParser(
        prog="pqc_cert_generator",
        description="PQC 인증서 생성 시뮬레이터 (NIST FIPS 203/204/205 기반)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python 04_nist_pqc_standards.py --algorithm ml-kem-768
  python 04_nist_pqc_standards.py --algorithm ml-kem-1024 --sig-algorithm ml-dsa-87
  python 04_nist_pqc_standards.py --algorithm ml-kem-768 --output-dir ./certs --validity-days 365
  python 04_nist_pqc_standards.py --algorithm ml-kem-512 --ca --common-name "PQC Root CA"

KEM 알고리즘: ml-kem-512, ml-kem-768, ml-kem-1024
서명 알고리즘: ml-dsa-44, ml-dsa-65, ml-dsa-87, slh-dsa-sha2-128s, slh-dsa-sha2-256s
        """
    )
    parser.add_argument(
        "--algorithm",
        choices=list(ALGORITHM_PARAMS.keys()),
        default="ml-kem-768",
        help="KEM 공개키 알고리즘 (기본값: ml-kem-768)"
    )
    parser.add_argument(
        "--sig-algorithm",
        choices=[k for k, v in ALGORITHM_PARAMS.items() if v["type"] == "DSA"],
        default="ml-dsa-65",
        help="서명 알고리즘 (기본값: ml-dsa-65)"
    )
    parser.add_argument(
        "--output-dir",
        default="./pqc_certs",
        help="인증서 파일 출력 디렉토리 (기본값: ./pqc_certs)"
    )
    parser.add_argument(
        "--validity-days",
        type=int,
        default=365,
        metavar="DAYS",
        help="인증서 유효 기간 (일, 기본값: 365)"
    )
    parser.add_argument(
        "--common-name",
        default="PQC Example Certificate",
        metavar="CN",
        help="인증서 주체 Common Name (기본값: 'PQC Example Certificate')"
    )
    parser.add_argument(
        "--ca",
        action="store_true",
        help="CA(인증기관) 인증서로 생성"
    )
    return parser.parse_args()


def main() -> None:
    """메인 진입점"""
    args = parse_arguments()

    if args.validity_days < 1:
        print("오류: --validity-days는 1 이상이어야 합니다.", file=sys.stderr)
        sys.exit(1)
    if args.validity_days > 36500:
        print("경고: --validity-days가 100년을 초과합니다.", file=sys.stderr)

    try:
        exit_code = run_certificate_generation(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n작업이 중단되었습니다.")
        sys.exit(0)
    except Exception as e:
        print(f"\n예상치 못한 오류: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 6. 국가별 PQC 대응 현황

### 6.1 주요 국가/기관 현황 표

| 국가/기관 | 주요 동향 | 의무화 시기 |
|---------|---------|----------|
| **미국 NSA** | CNSA 2.0 발표 (2022): 2030년까지 PQC 전환 의무 | 2033년 (일부 2030년) |
| **미국 CISA** | PQC 전환 가이드라인 발행 | 2035년까지 전환 |
| **EU ENISA** | PQC 권고 보고서 발행, 하이브리드 모드 권장 | 2030년 이후 |
| **독일 BSI** | TR-02102에 PQC 알고리즘 추가 | 2025년부터 권장 |
| **영국 NCSC** | PQC 마이그레이션 가이드 발행 | 2035년까지 |
| **한국 KISA** | 양자 내성 암호 전환 로드맵 수립 중 | 2030년 목표 |
| **중국** | 독자 PQC 표준 개발 (SM-시리즈 확장) | 별도 국가 표준 |
| **일본 CRYPTREC** | PQC 평가 연구 진행 | 2030년 목표 |

---

<a name="english"></a>

# 57-4. NIST PQC Standardization: Round-by-Round Progress, Final Selections, and FIPS Standards

## Overview

The National Institute of Standards and Technology (NIST) launched a project in 2016 to standardize cryptographic algorithms that are secure against quantum computers. In August 2024, after eight years of in-depth evaluation, NIST officially published three final standards (FIPS 203, 204, and 205). This represents a historic turning point that affects the entire Internet security infrastructure.

---

## 1. NIST PQC Standardization Round-by-Round Progress

### 1.1 Overall Timeline

| Stage | Period | Key Events |
|-------|--------|------------|
| Call for Submissions | December 2016 | NIST announces algorithm submission request |
| Submission Deadline | November 2017 | 69 complete candidates, 13 partial candidates |
| Round 1 | 2017–2019 | 69 → 26 selected |
| Round 2 | 2019–2020 | 26 → 15 (7 Finalists + 8 Alternates) |
| Round 3 | 2020–2022 | 15 → 7 finalists |
| Final Selection Announcement | July 2022 | 4 algorithms selected |
| FIPS Draft Publication | August 2023 | FIPS 203/204/205 draft published |
| **FIPS Final Confirmation** | **August 2024** | **FIPS 203/204/205 officially standardized** |
| Round 4 (Signatures) | 2022–present | Additional signature algorithm evaluation beyond KEM |

### 1.2 Round 1 Candidates (69) by Category

| Category | Count | Key Submitted Algorithms |
|----------|-------|--------------------------|
| Lattice-based KEM | 21 | CRYSTALS-Kyber, NTRU, SABER, LAC, LIMA ... |
| Lattice-based Signatures | 6 | CRYSTALS-Dilithium, FALCON, NTRU Prime ... |
| Code-based | 17 | Classic McEliece, BIKE, HQC, NTS-KEM ... |
| Hash-based Signatures | 2 | SPHINCS, GRAVITY-SPHINCS |
| Multivariate | 7 | GeMSS, Rainbow, MQDSS ... |
| Isogeny-based | 6 | SIKE, CSIDH, SIDH ... |
| Other | 10 | Frodo, NewHope, ... |

### 1.3 Round 2 Candidates (26)

| Type | Finalists (7) | Alternates (8) | Elimination Reason |
|------|---------------|----------------|-------------------|
| KEM | CRYSTALS-Kyber, NTRU, SABER, Classic McEliece | BIKE, FrodoKEM, HQC, NTRU Prime | Insufficient performance/size balance |
| Signature | CRYSTALS-Dilithium, FALCON, Rainbow, SPHINCS+ | GeMSS, Picnic, LUOV, ... | Security analysis concerns |

### 1.4 Round 3 Results and Final Selections

| Algorithm | Type | Result | Elimination Reason (if applicable) |
|-----------|------|--------|-------------------------------------|
| **CRYSTALS-Kyber** | KEM | **Selected** | — |
| **CRYSTALS-Dilithium** | Signature | **Selected** | — |
| **FALCON** | Signature | **Selected** | — |
| **SPHINCS+** | Signature | **Selected** | — |
| NTRU | KEM | Withdrawn | Patent issues, similar to Kyber |
| SABER | KEM | Eliminated | Performance inferior to Kyber |
| Rainbow | Signature | **Cryptanalytic break** | Practical attack by Ward Beullens (2022) |
| Classic McEliece | KEM | Round 4 | Public key size issues |
| BIKE, HQC | KEM | Round 4 | Under further analysis |
| SIKE | KEM | **Complete break** | Isogeny attack breaks it in hours (2022) |
| GeMSS | Signature | Eliminated | Security analysis concerns |

---

## 2. Final Selected Algorithms in Detail

### 2.1 Algorithm Characteristics and Use Cases

| Property | ML-KEM (Kyber) | ML-DSA (Dilithium) | SLH-DSA (SPHINCS+) | FN-DSA (FALCON) |
|----------|----------------|-------------------|-------------------|----------------|
| **FIPS Number** | FIPS 203 | FIPS 204 | FIPS 205 | FIPS 206 (upcoming) |
| **Use** | Key Encapsulation (KEM) | Digital Signature | Digital Signature | Digital Signature |
| **Math Basis** | Module-LWE | Module-LWE + SIS | Hash function | NTRU lattice |
| **Security Levels** | 1/3/5 (128/192/256) | 2/3/5 | 1/3/5 | 1/5 |
| **Public Key (L3)** | 1,184 B | 1,952 B | 32~64 B | — |
| **Secret Key (L3)** | 2,400 B | 4,000 B | 64~128 B | — |
| **Output Size (L3)** | 1,088 B (ciphertext) | 3,293 B (signature) | 7,856~49,856 B | 690~1,330 B |
| **Key Generation Speed** | Very Fast | Fast | Fast | Slow (trapdoor) |
| **Sign/Encrypt** | Very Fast | Fast | Very Slow | Fast |
| **Verify/Decrypt** | Very Fast | Very Fast | Fast | Very Fast |
| **Primary Use Cases** | TLS, key exchange | General signing, PKI | Long-term archival, patches | When compact signatures are needed |
| **Implementation Complexity** | Low | Low | Low | High (Gaussian sampling) |
| **Side-Channel Risk** | Medium | Low | Low | High caution needed |

### 2.2 Security Level Definitions

NIST defined five security levels:

| Level | Classical Security | Quantum Security | Equivalent Classical Algorithm |
|-------|-------------------|-----------------|-------------------------------|
| 1 | ≥128 bits | AES-128 level | At least as hard as AES-128 exhaustive search |
| 2 | — | SHA-256 collision level | At least as hard as SHA-256 collision finding |
| 3 | ≥192 bits | AES-192 level | At least as hard as AES-192 exhaustive search |
| 4 | — | SHA-384 collision level | At least as hard as SHA-384 collision finding |
| 5 | ≥256 bits | AES-256 level | At least as hard as AES-256 exhaustive search |

---

## 3. FIPS Standards Overview

### 3.1 FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)

**Official Publication**: August 13, 2024

**Key Contents:**
- ML-KEM-512 (Security Level 1)
- ML-KEM-768 (Security Level 3, **recommended**)
- ML-KEM-1024 (Security Level 5)

**Role of KEM:**
```
Alice                     Bob
  |                        |
  |--- Public Key pk ---->  |
  |                        | Generate shared secret K, ciphertext c
  |<-- Ciphertext c ------  |
  | K = Decap(sk, c)       |
```

KEM replaces key agreement protocols (DH, ECDH) and is used in the key exchange phase of TLS 1.3.

### 3.2 FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)

**Official Publication**: August 13, 2024

**Key Contents:**
- ML-DSA-44 (Security Level 2, corresponds to CRYSTALS-Dilithium2)
- ML-DSA-65 (Security Level 3, corresponds to CRYSTALS-Dilithium3, **recommended**)
- ML-DSA-87 (Security Level 5, corresponds to CRYSTALS-Dilithium5)

Uses **Fiat-Shamir with Aborts** technique:
- The signing algorithm retries on failure (averages ~4–7 attempts)
- Non-deterministic, so extra care is needed in implementation

### 3.3 FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)

**Official Publication**: August 13, 2024

**Key Contents:**
- SLH-DSA-SHA2-128s/128f (Security Level 1)
- SLH-DSA-SHA2-192s/192f (Security Level 3)
- SLH-DSA-SHA2-256s/256f (Security Level 5)
- SHA-3 variants also available (SLH-DSA-SHAKE-...)

**s vs f variants:**

| Variant | Signature Size | Signing Speed | Suitable For |
|---------|---------------|--------------|--------------|
| **-s (small)** | Small | Slow | When signature size is constrained |
| **-f (fast)** | Large | Fast | When signing speed is critical |

---

## 4. Classic TLS vs Hybrid PQC-TLS Comparison

### 4.1 TLS 1.3 Handshake Comparison

| Stage | Classic TLS 1.3 | PQC-TLS 1.3 | Hybrid TLS 1.3 |
|-------|----------------|------------|---------------|
| Key Exchange | ECDHE (P-256) | ML-KEM-768 | X25519+Kyber768 |
| Server Authentication | ECDSA P-256 | ML-DSA-65 | ECDSA+ML-DSA |
| Client Authentication | RSA/ECDSA | ML-DSA-65 | RSA+ML-DSA |
| Symmetric Cipher | AES-128-GCM | AES-256-GCM | AES-256-GCM |
| Data Integrity | SHA-256 | SHA-256+ | SHA-256+ |
| Handshake Size | ~300B | ~2,500B | ~2,800B |
| Quantum Resistance | None | Full | Hybrid guarantee |

### 4.2 Hybrid Key Exchange Standardization Status

IETF is standardizing hybrid KEM groups for TLS 1.3:

| Hybrid Group Name | Composition | Status |
|------------------|-------------|--------|
| `X25519Kyber768Draft00` | X25519 + Kyber-768 | Chrome/Firefox experimental support |
| `SecP256r1Kyber768Draft00` | ECDH P-256 + Kyber-768 | Under testing |
| `X25519MLKEM768` | X25519 + ML-KEM-768 | IETF RFC draft |

**Google Chrome** has had hybrid KEM (X25519Kyber768) enabled by default since 2023.

---

## 5. Python CLI: PQC Certificate Generation Simulator

See the Korean section above for the full Python code listing.

---

## 6. Global PQC Readiness Status

### 6.1 Key Countries/Organizations

| Country/Organization | Key Developments | Mandatory By |
|---------------------|-----------------|--------------|
| **US NSA** | CNSA 2.0 published (2022): PQC transition mandatory by 2030 | 2033 (some by 2030) |
| **US CISA** | PQC transition guidelines published | Transition by 2035 |
| **EU ENISA** | PQC advisory report published, hybrid mode recommended | After 2030 |
| **Germany BSI** | PQC algorithms added to TR-02102 | Recommended from 2025 |
| **UK NCSC** | PQC migration guide published | By 2035 |
| **Korea KISA** | Quantum-resistant cryptography transition roadmap being developed | 2030 target |
| **China** | Developing independent PQC standards (SM-series extension) | Separate national standards |
| **Japan CRYPTREC** | PQC evaluation research underway | 2030 target |
