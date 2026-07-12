> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 단거리 무선 보안 방어

## 0. 초보자를 위한 개념 이해

### 왜 무선 방어가 어려운가?

무선 방어를 처음 배우는 분을 위한 비유: 유선 네트워크는 **자물쇠가 달린 방**이고, 무선 네트워크는 **유리로 된 방**입니다. 누가 도청하는지 물리적으로 확인하기 어렵고, 신호는 벽을 통과해 퍼져나갑니다. 따라서 방어도 레이어드(계층적)으로 해야 합니다.

```
무선 보안 방어 레이어:

  Layer 1: 물리 보안     → 기기 위치, 신호 차폐
  Layer 2: 프로토콜 보안 → 올바른 페어링, 암호화 설정
  Layer 3: 네트워크 보안 → 격리, 방화벽, 모니터링
  Layer 4: 기기 보안     → 펌웨어 업데이트, 기본값 변경
  Layer 5: 정책/교육     → 직원 교육, 보안 정책

  모든 레이어가 동시에 지켜져야 효과적
```

---

## 1. 블루투스 보안 설정 강화

### 운영 체제별 블루투스 보안 설정

```bash
# Linux (BlueZ) 보안 설정 강화

# 1. 기기를 Non-Discoverable 모드로 설정
bluetoothctl
  [bluetoothctl] discoverable off
  [bluetoothctl] pairable off

# 2. /etc/bluetooth/main.conf 설정 강화
sudo nano /etc/bluetooth/main.conf
```

```ini
[Policy]
# 자동 연결 거부
AutoEnable=false

[General]
# 최대 보안 강도 강제
ControllerMode = dual
# 기기 이름 식별자 제거
Name = BT-Device

[Security]
# Just Works 페어링 금지 (Passkey 강제)
Passkey = 00000
```

```bash
# 3. 불필요한 블루투스 프로파일 비활성화
# /etc/bluetooth/audio.conf 에서 불필요 프로파일 제거

# 4. 블루투스 사용하지 않을 때 완전 비활성화
sudo rfkill block bluetooth

# 5. 상태 확인
rfkill list
```

### 페어링 보안 점검

```bash
#!/usr/bin/env bash
# bt_security_check.sh — 블루투스 보안 상태 점검

echo "=== 블루투스 보안 점검 ==="
echo ""

# 인터페이스 상태
echo "[1] 블루투스 인터페이스 상태:"
hciconfig 2>/dev/null || echo "  hciconfig 없음 (bluez 설치 확인)"
echo ""

# Discoverable 상태
echo "[2] 검색 가능(Discoverable) 여부:"
if bluetoothctl show 2>/dev/null | grep -q "Discoverable: yes"; then
    echo "  ⚠ 경고: 기기가 검색 가능 상태 → 즉시 비활성화 권장"
    echo "    명령: bluetoothctl discoverable off"
else
    echo "  ✓ 비검색 상태 (안전)"
fi
echo ""

# 페어링된 기기 목록
echo "[3] 페어링된 기기 목록:"
bluetoothctl paired-devices 2>/dev/null || echo "  (오류 또는 없음)"
echo ""

# rfkill 상태
echo "[4] RF Kill 상태:"
rfkill list bluetooth 2>/dev/null || echo "  rfkill 없음"
echo ""

echo "점검 완료. 불필요한 블루투스 기기 연결 해제 권장."
```

---

## 2. BLE 암호화 구현 (개발자 가이드)

### 안전한 BLE 특성 설정 (Python bleak 서버 개념)

```python
#!/usr/bin/env python3
"""
ble_secure_server.py — 안전한 BLE 서버 구현 예시
실제 BLE 서버는 임베디드 펌웨어에서 구현하지만,
이 스크립트는 보안 요구사항을 문서화하고 검증합니다.
"""

import argparse
import sys
from dataclasses import dataclass
from enum import IntEnum


class SecurityLevel(IntEnum):
    """BLE 보안 수준 정의"""
    NONE = 0          # 암호화 없음, 인증 없음 (위험)
    ENCRYPTED = 1     # 암호화 있음, 인증 없음
    AUTHENTICATED = 2 # 암호화 + Passkey 인증
    SECURE = 3        # 암호화 + ECDH + LE Secure Connections


@dataclass
class BLECharacteristic:
    uuid: str
    name: str
    can_read: bool
    can_write: bool
    can_notify: bool
    required_security: SecurityLevel
    data_sensitivity: str  # "low", "medium", "high", "critical"


class BLESecurityAuditor:
    """BLE 서비스 보안 감사 도구"""

    # 알려진 취약한 패턴
    RISKY_PATTERNS = {
        SecurityLevel.NONE: "암호화 없음 - 도청 위험",
        SecurityLevel.ENCRYPTED: "인증 없음 - MitM 공격 위험",
    }

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self.characteristics: list[BLECharacteristic] = []
        self.findings: list[str] = []

    def add_characteristic(self, char: BLECharacteristic) -> None:
        self.characteristics.append(char)

    def audit(self) -> bool:
        """보안 감사 실행, True = 이슈 없음"""
        print(f"\n[*] BLE 서비스 보안 감사: {self.service_name}")
        print("=" * 60)
        self.findings.clear()

        for char in self.characteristics:
            issues: list[str] = []

            # 민감 데이터 + 낮은 보안 수준 체크
            if char.data_sensitivity in ("high", "critical"):
                if char.required_security < SecurityLevel.AUTHENTICATED:
                    issues.append(
                        f"민감 데이터({char.data_sensitivity})에 "
                        f"보안 수준 부족 ({char.required_security.name})"
                    )

            # 쓰기 가능 특성 보안 체크
            if char.can_write and char.required_security == SecurityLevel.NONE:
                issues.append("쓰기 가능 특성에 인증 없음 (인증 없는 쓰기 공격 위험)")

            # 알림 특성 보안 체크
            if char.can_notify and char.required_security == SecurityLevel.NONE:
                issues.append("알림 데이터 암호화 없이 전송 (도청 위험)")

            # 결과 출력
            status = "✓" if not issues else "⚠"
            print(f"\n  {status} {char.name} (UUID: {char.uuid})")
            print(f"    속성: {'읽기 ' if char.can_read else ''}{'쓰기 ' if char.can_write else ''}{'알림' if char.can_notify else ''}")
            print(f"    보안 수준: {char.required_security.name}")
            print(f"    데이터 민감도: {char.data_sensitivity}")

            if issues:
                for issue in issues:
                    print(f"    🚨 이슈: {issue}")
                    self.findings.append(f"[{char.name}] {issue}")

        print("\n" + "=" * 60)
        if self.findings:
            print(f"[!] 총 {len(self.findings)}개 보안 이슈 발견:")
            for finding in self.findings:
                print(f"    - {finding}")
            return False
        else:
            print("[+] 보안 이슈 없음")
            return True

    def generate_report(self) -> str:
        """보안 보고서 생성"""
        lines = [
            f"BLE 보안 감사 보고서: {self.service_name}",
            "=" * 60,
            f"특성 수: {len(self.characteristics)}",
            f"발견된 이슈: {len(self.findings)}",
            "",
            "권고사항:",
        ]
        if self.findings:
            for f in self.findings:
                lines.append(f"  - {f}")
        else:
            lines.append("  - 없음 (양호)")
        return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BLE 서비스 보안 감사")
    parser.add_argument("--demo", action="store_true", help="데모 취약 서비스 감사 실행")
    parser.add_argument("--report", action="store_true", help="보안 보고서 출력")
    return parser.parse_args()


def demo_audit() -> BLESecurityAuditor:
    """데모: 취약한 스마트 자물쇠 서비스 감사"""
    auditor = BLESecurityAuditor("SmartLock-Pro BLE Service")

    # 취약한 특성들 (현실의 저가 제품 패턴)
    auditor.add_characteristic(BLECharacteristic(
        uuid="12345678-0001-1234-1234-123456789abc",
        name="잠금 제어",
        can_read=False, can_write=True, can_notify=False,
        required_security=SecurityLevel.NONE,  # 취약!
        data_sensitivity="critical",
    ))
    auditor.add_characteristic(BLECharacteristic(
        uuid="12345678-0002-1234-1234-123456789abc",
        name="배터리 잔량",
        can_read=True, can_write=False, can_notify=True,
        required_security=SecurityLevel.NONE,
        data_sensitivity="low",
    ))
    auditor.add_characteristic(BLECharacteristic(
        uuid="12345678-0003-1234-1234-123456789abc",
        name="사용자 PIN",
        can_read=True, can_write=True, can_notify=False,
        required_security=SecurityLevel.ENCRYPTED,  # 인증 없음!
        data_sensitivity="critical",
    ))

    return auditor


def secure_design_example() -> BLESecurityAuditor:
    """올바른 설계: 보안이 강화된 스마트 자물쇠"""
    auditor = BLESecurityAuditor("SmartLock-SecureV2 BLE Service (개선된 설계)")

    auditor.add_characteristic(BLECharacteristic(
        uuid="AAAABBBB-0001-CCCC-DDDD-EEEEEEEEEEEE",
        name="잠금 제어 (개선됨)",
        can_read=False, can_write=True, can_notify=False,
        required_security=SecurityLevel.SECURE,  # ECDH + 인증
        data_sensitivity="critical",
    ))
    auditor.add_characteristic(BLECharacteristic(
        uuid="AAAABBBB-0002-CCCC-DDDD-EEEEEEEEEEEE",
        name="배터리 잔량 (개선됨)",
        can_read=True, can_write=False, can_notify=True,
        required_security=SecurityLevel.AUTHENTICATED,
        data_sensitivity="low",
    ))

    return auditor


def main() -> None:
    args = parse_args()

    if args.demo:
        print("[ 취약한 설계 감사 ]")
        auditor = demo_audit()
        auditor.audit()

        print("\n\n[ 안전한 설계 감사 ]")
        secure = secure_design_example()
        secure.audit()

        if args.report:
            print("\n\n" + auditor.generate_report())
    else:
        print("사용법: python3 ble_secure_server.py --demo [--report]")
        print("  --demo   : 취약한/안전한 BLE 서비스 비교 감사")
        print("  --report : 상세 보고서 출력")


if __name__ == "__main__":
    main()
```

### 실행 예시

```bash
python3 ble_secure_server.py --demo --report

# 출력:
# [ 취약한 설계 감사 ]
# [*] BLE 서비스 보안 감사: SmartLock-Pro BLE Service
# ============================================================
#   ⚠ 잠금 제어 (UUID: 12345678-0001-...)
#     속성: 쓰기
#     보안 수준: NONE
#     데이터 민감도: critical
#     🚨 이슈: 민감 데이터(critical)에 보안 수준 부족 (NONE)
#     🚨 이슈: 쓰기 가능 특성에 인증 없음 (인증 없는 쓰기 공격 위험)
# ...
# [!] 총 4개 보안 이슈 발견
```

---

## 3. Zigbee 보안 키 관리

```bash
# Zigbee2MQTT 보안 강화 설정
# /opt/zigbee2mqtt/data/configuration.yaml

advanced:
  # 기본 TC 링크 키 변경 (필수!)
  network_key:
    - 0xAB  # 실제 환경: 랜덤 16바이트 사용
    - 0xCD
    - 0xEF
    - 0x01
    - 0x23
    - 0x45
    - 0x67
    - 0x89
    - 0x01
    - 0x23
    - 0x45
    - 0x67
    - 0x89
    - 0xAB
    - 0xCD
    - 0xEF

  # 네트워크 키 주기적 교체 활성화
  # (주요 상업 시스템에서는 자동 키 교체 필요)

# 조인 허용 시간 제한 (기기 추가 시에만 활성화)
permit_join: false  # 기본값 false, 기기 추가 시에만 잠깐 true
```

### 랜덤 네트워크 키 생성 스크립트

```python
#!/usr/bin/env python3
"""zigbee_keygen.py — 안전한 Zigbee 네트워크 키 생성"""
import secrets


def generate_network_key() -> list[int]:
    """암호학적으로 안전한 16바이트 네트워크 키 생성"""
    return [secrets.randbelow(256) for _ in range(16)]


def format_for_yaml(key: list[int]) -> str:
    lines = ["network_key:"]
    for byte in key:
        lines.append(f"  - 0x{byte:02X}")
    return "\n".join(lines)


def main() -> None:
    key = generate_network_key()
    hex_key = " ".join(f"{b:02X}" for b in key)
    print(f"[+] 새 네트워크 키 (hex): {hex_key}")
    print()
    print("[+] configuration.yaml 형식:")
    print(format_for_yaml(key))
    print()
    print("[!] 이 키를 안전한 곳에 보관하세요.")
    print("    분실 시 모든 Zigbee 기기 재페어링 필요.")


if __name__ == "__main__":
    main()
```

---

## 4. 기업 환경 무선 보안 정책

### 블루투스 보안 정책 (예시)

```
기업 블루투스 보안 정책 v1.0

1. 허용 기기 관리
   - IT 승인 기기 목록(whitelist) 유지
   - MDM(Mobile Device Management)으로 미승인 기기 차단
   - 분기별 페어링 기기 목록 검토

2. 페어링 정책
   - 공용 장소에서 블루투스 기기 페어링 금지
   - Just Works 방식 사용 금지 (최소 Passkey)
   - 페어링 후 불필요 기기 즉시 제거

3. 기기 설정
   - Discoverable 모드: 사용 시에만 활성화, 즉시 비활성화
   - 블루투스 미사용 시 완전 비활성화

4. 고위험 구역
   - 서버룸/데이터센터: 블루투스 기기 반입 금지
   - 보안 회의실: RF 차폐 처리 권장

5. 모니터링
   - 비인가 블루투스 기기 탐지 솔루션 운영
   - 이상 신호 탐지 시 즉시 보안팀 알림
```

---

## 5. RF 신호 차폐 (패러데이 케이지)

### 개념

```
패러데이 케이지 원리:
  전도성 물질(금속망, 알루미늄)이 전자기파를 차단
  → 내부 기기의 신호가 외부로 나가지 않음
  → 외부 신호도 내부로 들어오지 않음

실용적 구현:
  방법 1: 알루미늄 호일 박스
    → 저가, 임시 차폐 (고주파는 투과 가능)
    → 블루투스 실습용 격리 환경 제작에 적합

  방법 2: 금속 서랍/금고
    → 두꺼운 금속 = 더 효과적 차폐

  방법 3: RF 차폐 텐트/백
    → 전문 포렌식 장비 차폐에 사용
    → 스마트폰 포렌식 시 원격 초기화 방지

  방법 4: 전문 차폐룸 (EMC 실험실)
    → 기업 보안 설계, 제품 인증 테스트
```

### 간이 패러데이 케이지 제작

```
재료: 알루미늄 호일, 강철 파이프망, 절연 테이프

제작 방법:
  1. 금속 박스(쿠키 틴 등) 내부에 절연재 붙이기
  2. 기기 넣고 뚜껑 닫기
  3. 이음새를 알루미늄 테이프로 밀봉

테스트 방법:
  1. 스마트폰을 케이지에 넣고 전화 걸어보기
    → 연결 안 되면 차폐 성공
  2. WiFi/블루투스 스캔으로 케이지 내 기기 탐지 안 되면 성공

활용:
  - 블루투스 실습 시 신호 격리
  - 스마트폰 포렌식 분석
  - 자동차 키 보관 (릴레이 어택 방어)
```

---

## 6. 취약 기기 탐지 도구

### 자동화 스캐너

```bash
# bettercap 설치
sudo apt install bettercap

# 블루투스 스캐닝 모드
sudo bettercap
> ble.recon on
> ble.show

# 모든 BLE 기기 목록과 RSSI 표시
# 비정상적 신호 패턴 식별

# kismet (무선 IDS)
sudo apt install kismet
sudo kismet
# 웹 UI: http://localhost:2501
# 블루투스, WiFi, Zigbee 이상 징후 탐지
```

### 기기 취약점 체크리스트

```
스마트홈 기기 보안 점검 항목:

  □ 기기 펌웨어 최신 버전인가?
  □ 기본 비밀번호 변경했는가?
  □ BLE 페어링: Just Works 사용하지 않는가?
  □ Zigbee: 기본 TC 링크 키 "ZigBeeAlliance09" 그대로인가?
  □ Z-Wave: S2 보안 사용 중인가?
  □ 앱: 공식 스토어 앱만 사용하는가?
  □ 클라우드: TLS 사용, 인증서 검증하는가?
  □ 불필요한 기능(블루투스, WiFi) 비활성화했는가?
  □ 게스트 네트워크(IoT VLAN)에 격리했는가?
  □ 비정상 연결 시도 알림 설정했는가?
```

---

## 복제 BLE 비콘 탐지 — 신원 재사용이 여러 MAC에 분산되는 이상

정상 BLE 기기는 프라이버시를 위해 **분해 가능한 임의 주소(RPA)**를 주기적으로 로테이션한다 — 즉 MAC이 바뀌는 것 자체는 정상이다. 그러나 공격자가 비콘을 복제/스푸핑하면 **동일한 광고 페이로드·서비스 UUID라는 '신원'**이 짧은 시간 안에 지나치게 많은 서로 다른 MAC에서, 종종 비정상적인 RSSI 편차와 함께 나타난다. 소유·통제 RF 공간에서 광고를 신원 단위로 클러스터링하면 합법 로테이션과 복제를 구분할 수 있다.

```python
#!/usr/bin/env python3
"""BLE 광고 캡처에서 동일 신원(광고 페이로드/서비스 UUID 해시)이 서로 다른 MAC에
짧은 시간 안에 과다하게 나타나는지 검사해 복제/스푸핑 비콘을 표시한다.
소유·통제 RF 공간의 방어 모니터링용(합법 RPA 로테이션과 구분)."""
from collections import defaultdict


def detect_clones(adverts: list[dict], window_s: int = 60, mac_threshold: int = 3) -> list[dict]:
    """adverts: [{"mac", "payload_id", "rssi", "ts"}] — payload_id는 광고 데이터 해시."""
    by_identity: dict[str, list] = defaultdict(list)
    for a in adverts:
        by_identity[a["payload_id"]].append(a)
    flagged = []
    for pid, seen in by_identity.items():
        seen.sort(key=lambda x: x["ts"])
        macs = {s["mac"] for s in seen}
        span = seen[-1]["ts"] - seen[0]["ts"]
        rssi_spread = max(s["rssi"] for s in seen) - min(s["rssi"] for s in seen)
        if len(macs) >= mac_threshold and span <= window_s:
            flagged.append({"payload_id": pid, "distinct_macs": len(macs),
                            "window_s": span, "rssi_spread": rssi_spread})
    return sorted(flagged, key=lambda x: -x["distinct_macs"])
```

| 신호 | 설명 | 오탐/보정 요인 |
|------|------|----------------|
| 동일 신원 → 다수 MAC(짧은 창) | RPA 로테이션보다 빠른 복제 의심 | 혼잡 환경의 정상 로테이션이 겹칠 수 있음 |
| 큰 RSSI 편차 | 물리적으로 여러 위치의 송신원 = 복제 신호 | 멀티패스·이동체는 정상적으로도 편차 큼 |
| 광고 간격 불규칙 | 재생/스푸핑 타이밍 흔적 | 저전력 스케줄링으로 정상 지터 존재 |

**탐지/방어**: 이 탐지는 자산이 아니라 **모니터링 신호**이므로 알려진 기기 인벤토리(허용 MAC/신원)와 대조해 오탐을 걷어내고, 페어링은 LE Secure Connections(MITM 보호)를 강제한다([[15_WiFi_Hacking]], [[27_IoT_Hacking]]). 임의 무선 환경 캡처는 법적 문제가 되므로 캡처·검증은 **소유·통제 RF 공간**에서만.

---

<!-- detect-validate-71 -->
## 7. 무선 위협 탐지 (Wireless IDS)와 한계

유선 네트워크와 달리 RF 공격은 **흔적이 공중에만 남고 호스트 로그에 남지 않는** 경우가 많습니다. 패시브 모니터링 센서가 없으면 재밍·스푸핑·로그 기기는 사실상 무탐지로 지나갑니다.

| 위협 | 관측 가능한 신호 | 센서/도구 |
|---|---|---|
| RF 재밍(Jamming) | 특정 대역 노이즈 플로어 급상승, 패킷 손실률 | SDR 스펙트럼 모니터, RSSI 베이스라인 |
| BLE 광고 스푸핑 | 동일 MAC/이름의 중복 광고, RSSI 불일치 | Kismet, bettercap `ble.recon` |
| 로그 Zigbee 코디네이터 | 비인가 PAN ID, 비정상 조인 요청 | Zigbee 스니퍼(CC2531), Zigbee2MQTT 로그 |
| 디오센티케이션/연결 끊김 폭주 | 짧은 시간 다수 disconnect 이벤트 | BlueZ 이벤트 로그, WIDS |

```python
# RSSI 베이스라인 이상탐지 개념 (의사코드 수준 핵심 로직)
def detect_anomaly(readings: list[float], baseline_mean: float, baseline_std: float) -> bool:
    """관측 RSSI가 베이스라인에서 통계적으로 벗어나면 이상으로 판정."""
    if not readings:
        return False
    current = sum(readings) / len(readings)
    # 3-시그마 규칙: 평균에서 3 표준편차 이상 벗어나면 이상
    return abs(current - baseline_mean) > 3 * baseline_std
```

> 탐지의 현실적 한계: 무선 탐지는 센서가 물리적으로 그 공간에 있어야만 작동합니다(전파 도달 범위 한계). 그래서 무선 보안은 탐지보다 **예방(강한 페어링·암호화·세그먼트 격리)이 우선**이며, 탐지는 고가치 자산 주변에 한정 배치하는 것이 비용 대비 효과적입니다. WIDS를 도입했다면 알려진 공격(재밍·스푸핑)을 통제된 환경에서 재현해 실제로 탐지되는지 검증합니다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- 무선 IDS(Kismet·모니터링)로 로그·스푸핑·비인가 비콘 탐지 — 룰이 실제 공격 신호에서 발화하는지 검증
- 자산 인벤토리·펌웨어 패치·강한 페어링 정책의 결합이 방어 표준 — 통제가 실제 강제되는지 재현([[27_IoT_Hacking]])

---

<a name="english"></a>

# Short-Range Wireless Security Defense

## 0. Beginner Concepts

### Why Is Wireless Defense Hard?

Wired networks are a **locked room**; wireless networks are a **glass room**. It is hard to see who is eavesdropping, and signals pass through walls. Defense must be layered.

```
Defense Layers:

  Layer 1: Physical       → Device placement, signal shielding
  Layer 2: Protocol       → Correct pairing, encryption settings
  Layer 3: Network        → Isolation, firewall, monitoring
  Layer 4: Device         → Firmware updates, change defaults
  Layer 5: Policy/Training → Employee education, security policies
```

---

## 1. Hardening Bluetooth Security

### Linux (BlueZ) Configuration

```bash
# Set device to non-discoverable
bluetoothctl
  [bluetoothctl] discoverable off
  [bluetoothctl] pairable off

# Disable Bluetooth completely when not in use
sudo rfkill block bluetooth
```

Key `/etc/bluetooth/main.conf` settings:

```ini
[Policy]
AutoEnable=false

[General]
Name = BT-Device    # Remove identifying name

[Security]
# Passkey required (prevents Just Works)
Passkey = 00000
```

Run the `bt_security_check.sh` script (Korean section) to audit current Bluetooth posture.

---

## 2. Secure BLE Implementation for Developers

Run the Python auditor to compare vulnerable vs. secure BLE service designs:

```bash
python3 ble_secure_server.py --demo --report
```

Key rules for secure BLE development:

```
✓ Sensitive Write characteristics → Security Level SECURE (ECDH + auth)
✓ Never use Just Works pairing for anything sensitive
✓ All Notify characteristics → minimum Security Level AUTHENTICATED
✓ Validate all written values server-side
✓ Rate-limit connection attempts
✓ Log and alert on unexpected connect/disconnect events
```

---

## 3. Zigbee Key Management

```bash
# Generate a cryptographically secure network key
python3 zigbee_keygen.py

# Apply generated key to /opt/zigbee2mqtt/data/configuration.yaml
# Set permit_join: false by default — enable only when adding devices

# Verify no device is using the default "ZigBeeAlliance09" TC Link Key
# (Zigbee2MQTT logs a warning if the default key is detected)
```

---

## 4. Enterprise Wireless Security Policy

```
Corporate Bluetooth Security Policy (template):

1. Device approval whitelist — MDM enforced
2. No pairing in public spaces
3. Just Works pairing prohibited — minimum Passkey
4. Discoverable mode: only when actively pairing
5. Server rooms / data centers: Bluetooth devices prohibited
6. Meeting rooms: RF shielding recommended
7. Unauthorized device detection tooling required
8. Security team alert on anomalous signals
```

---

## 5. RF Shielding (Faraday Cage)

```
Faraday cage principle:
  Conductive material (metal mesh, aluminum) blocks EM waves
  → Device signals cannot escape; external signals cannot enter

Practical options:
  Option 1: Aluminum foil box (DIY, cheap, good for BLE lab isolation)
  Option 2: Metal drawer or steel cabinet
  Option 3: RF shielding bag (used in forensics to prevent remote wipe)
  Option 4: Professional EMC shielded room (enterprise/research)

Car key Faraday pouch:
  → Prevents relay attacks on keyless-entry vehicles
  → Available commercially for ~$10–20
```

---

## 6. Vulnerable Device Detection

```bash
# bettercap BLE recon
sudo bettercap
> ble.recon on
> ble.show

# kismet — wireless IDS (Bluetooth, WiFi, Zigbee)
sudo apt install kismet
sudo kismet
# Web UI: http://localhost:2501
```

### Device Security Checklist

```
□ Is firmware up to date?
□ Default password changed?
□ BLE pairing: no Just Works for sensitive functions?
□ Zigbee: default TC Link Key "ZigBeeAlliance09" replaced?
□ Z-Wave: using S2 security?
□ Apps: official store only?
□ Cloud: TLS + certificate validation enabled?
□ Unnecessary features (BT, WiFi) disabled?
□ Isolated to IoT VLAN / guest network?
□ Alerts configured for unexpected connections?
```

## Cloned BLE Beacon Detection — Identity Reuse Spread Across Multiple MACs

Normal BLE devices rotate **resolvable private addresses (RPAs)** periodically for privacy — so a changing MAC is itself normal. But when an attacker clones or spoofs a beacon, the same **"identity" (advertising payload / service UUID)** appears across too many distinct MACs in a short window, often with anomalous RSSI spread. Clustering advertisements by identity in owned/controlled RF space distinguishes legitimate rotation from cloning.

```python
#!/usr/bin/env python3
"""Check a BLE advertising capture for the same identity (hash of advertising
payload / service UUID) appearing across too many distinct MACs in a short window,
flagging cloned/spoofed beacons. For defensive monitoring in owned/controlled RF
space (distinguished from legitimate RPA rotation)."""
from collections import defaultdict


def detect_clones(adverts: list[dict], window_s: int = 60, mac_threshold: int = 3) -> list[dict]:
    """adverts: [{"mac", "payload_id", "rssi", "ts"}] — payload_id is the advert-data hash."""
    by_identity: dict[str, list] = defaultdict(list)
    for a in adverts:
        by_identity[a["payload_id"]].append(a)
    flagged = []
    for pid, seen in by_identity.items():
        seen.sort(key=lambda x: x["ts"])
        macs = {s["mac"] for s in seen}
        span = seen[-1]["ts"] - seen[0]["ts"]
        rssi_spread = max(s["rssi"] for s in seen) - min(s["rssi"] for s in seen)
        if len(macs) >= mac_threshold and span <= window_s:
            flagged.append({"payload_id": pid, "distinct_macs": len(macs),
                            "window_s": span, "rssi_spread": rssi_spread})
    return sorted(flagged, key=lambda x: -x["distinct_macs"])
```

| Signal | Meaning | False-positive / adjustment factor |
|--------|---------|-------------------------------------|
| One identity -> many MACs (short window) | Cloning suspected, faster than RPA rotation | Normal rotation in congested environments may overlap |
| Large RSSI spread | Transmitters physically in several places = clone signal | Multipath / moving devices also spread naturally |
| Irregular advertising interval | Replay/spoof timing artifact | Low-power scheduling produces normal jitter |

**Detection/defense**: This detection is a **monitoring signal**, not an asset — correlate against a known-device inventory (allowed MAC/identity) to strip false positives, and enforce LE Secure Connections (MITM protection) for pairing ([[15_WiFi_Hacking]], [[27_IoT_Hacking]]). Capturing arbitrary RF is a legal matter, so capture and validate only in **owned/controlled RF space**.

---

<!-- detect-validate-71 -->
## 7. Wireless IDS and Its Limits

Unlike wired networks, RF attacks often leave **traces only in the air, not in host logs**. Without a passive monitoring sensor, jamming, spoofing, and rogue devices pass essentially undetected.

| Threat | Observable signal | Sensor/tool |
|---|---|---|
| RF jamming | Sudden noise-floor spike in a band, high packet loss | SDR spectrum monitor, RSSI baseline |
| BLE advertisement spoofing | Duplicate adverts with same MAC/name, RSSI mismatch | Kismet, bettercap `ble.recon` |
| Rogue Zigbee coordinator | Unauthorized PAN ID, abnormal join requests | Zigbee sniffer (CC2531), Zigbee2MQTT logs |
| Deauth/disconnect floods | Many disconnect events in a short window | BlueZ event log, WIDS |

```python
# RSSI baseline anomaly detection (core logic, pseudocode level)
def detect_anomaly(readings: list[float], baseline_mean: float, baseline_std: float) -> bool:
    """Flag as anomalous if observed RSSI deviates statistically from baseline."""
    if not readings:
        return False
    current = sum(readings) / len(readings)
    # 3-sigma rule: anomalous if more than 3 std devs from the mean
    return abs(current - baseline_mean) > 3 * baseline_std
```

> Practical limit: wireless detection only works where a sensor physically sits (radio range). So wireless security prioritizes **prevention (strong pairing, encryption, segmentation) over detection**, deploying detection only around high-value assets for cost-effectiveness. If you run a WIDS, reproduce known attacks (jamming, spoofing) in a controlled environment to verify they are actually detected (see [[68_Purple_Team]]).
