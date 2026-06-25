> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 하드웨어 보안 방어 — 시큐어 부트·TPM·물리 보안·변조 감지

## 0. 초보자를 위한 개념 이해

### 하드웨어 보안이란?

소프트웨어 보안이 아무리 강해도 물리적으로 장치에 접근할 수 있다면 무용지물이 될 수 있습니다. 하드웨어 보안은 물리적 공격(콜드 부트, JTAG, 글리칭), 공급망 공격, 부트 과정 조작을 방어합니다.

```
하드웨어 보안 위협 계층:

  부트 체인:
    BIOS/UEFI 취약점  → 부트킷 설치, 시큐어 부트 우회
    부트로더 변조     → OS 이전 악성코드 실행
    커널 변조         → 루트킷, 하이퍼바이저 공격

  런타임:
    DMA 공격          → PCIe/FireWire로 메모리 직접 읽기
    Cold Boot Attack  → 메모리 모듈 냉각 후 내용 추출
    TPM 스니핑        → LPC 버스에서 TPM 통신 감청

  물리적:
    JTAG/SWD 디버그  → 직접 메모리/레지스터 읽기/쓰기
    글리칭            → 전압/클럭 조작으로 보안 검사 우회
    측채널 공격       → 전력/전자기 방사로 키 복원
```

---

## 1. UEFI 시큐어 부트 구현 및 검증

### 1.1 시큐어 부트 개념

```
시큐어 부트 체인:

  UEFI 펌웨어 (ROM)
      │ 서명 검증 (Platform Key PK)
      ▼
  UEFI 부트로더
      │ 서명 검증 (Key Exchange Key → db allowlist)
      ▼
  부트로더 (GRUB2/systemd-boot)
      │ 서명 검증
      ▼
  커널 이미지
      │ 서명 검증
      ▼
  initramfs
      │ dm-verity로 루트 파일시스템 무결성 검증
      ▼
  운영체제

  각 단계에서 이전 단계가 서명 검증 → 신뢰 체인 구성
  하나라도 실패하면 부팅 중단 → 변조 감지
```

### 1.2 Linux 시큐어 부트 상태 확인

```bash
# 시큐어 부트 활성화 확인
mokutil --sb-state
# 출력: SecureBoot enabled

# UEFI 서명 데이터베이스 조회
efi-readvar -v PK    # Platform Key
efi-readvar -v KEK   # Key Exchange Keys
efi-readvar -v db    # Allowed Signatures Database
efi-readvar -v dbx   # Forbidden Signatures Database

# 커널 모듈 서명 확인
cat /proc/sys/kernel/modules_disabled
modinfo <module_name> | grep signer

# 시스템 펌웨어 무결성 체크 (fwupdmgr 사용)
fwupdmgr security
```

```python
#!/usr/bin/env python3
"""
시큐어 부트 및 TPM 상태 자동 확인 스크립트.
방어자용 시스템 부트 보안 검증 도구.
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def check_secure_boot() -> dict[str, object]:
    """시큐어 부트 활성화 여부 및 모드 확인."""
    result: dict[str, object] = {
        "enabled": False,
        "mode": "unknown",
        "secure": False,
    }

    # mokutil 사용
    try:
        out = subprocess.run(
            ["mokutil", "--sb-state"],
            capture_output=True, text=True, check=False
        ).stdout.lower()
        result["enabled"] = "secureboot enabled" in out
        result["mode"] = "uefi" if result["enabled"] else "legacy or disabled"
        result["secure"] = result["enabled"]
        log.info("시큐어 부트: %s", out.strip())
    except FileNotFoundError:
        # efivar 대안
        sb_path = Path("/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data")
        if sb_path.exists():
            data = sb_path.read_bytes()
            result["enabled"] = len(data) > 4 and data[4] == 1
            result["mode"] = "uefi"
            result["secure"] = result["enabled"]

    return result


def check_tpm() -> dict[str, object]:
    """TPM 존재 여부 및 버전 확인."""
    result: dict[str, object] = {
        "present": False,
        "version": "none",
        "pcr_bank_sha256": False,
    }

    # tpm2-tools 사용
    try:
        out = subprocess.run(
            ["tpm2_getcap", "properties-fixed"],
            capture_output=True, text=True, check=False
        )
        if out.returncode == 0:
            result["present"] = True
            if "2.0" in out.stdout:
                result["version"] = "2.0"
            elif "1.2" in out.stdout:
                result["version"] = "1.2"
            result["pcr_bank_sha256"] = "sha256" in out.stdout.lower()
            log.info("TPM 감지: 버전 %s", result["version"])
    except FileNotFoundError:
        # /sys/class/tpm 확인
        tpm_path = Path("/sys/class/tpm")
        if tpm_path.exists():
            result["present"] = any(tpm_path.iterdir())

    return result


def check_kernel_integrity() -> dict[str, object]:
    """커널 무결성 보호 기능 확인."""
    result: dict[str, object] = {}

    # IMA (Integrity Measurement Architecture) 활성화 확인
    ima_path = Path("/sys/kernel/security/ima/policy")
    result["ima_enabled"] = ima_path.exists()

    # dm-verity 활성화 확인 (Android/ChromeOS 스타일)
    try:
        out = subprocess.run(
            ["veritysetup", "status", "/"],
            capture_output=True, text=True, check=False
        )
        result["dm_verity"] = "active" in out.stdout.lower()
    except FileNotFoundError:
        result["dm_verity"] = False

    # 커널 모듈 서명 필수 여부
    lockdown_path = Path("/sys/kernel/security/lockdown")
    if lockdown_path.exists():
        lockdown = lockdown_path.read_text().strip()
        result["kernel_lockdown"] = lockdown
    else:
        result["kernel_lockdown"] = "none"

    # KASLR
    try:
        dmesg_out = subprocess.run(["dmesg"], capture_output=True, text=True, check=False).stdout
        result["kaslr"] = "KASLR" in dmesg_out
    except Exception:
        result["kaslr"] = False

    return result


def full_boot_security_audit() -> dict[str, object]:
    """전체 부트 보안 감사."""
    report = {
        "secure_boot": check_secure_boot(),
        "tpm": check_tpm(),
        "kernel_integrity": check_kernel_integrity(),
    }

    # 보안 점수 계산
    score = 0
    if report["secure_boot"]["enabled"]:
        score += 30
    if report["tpm"]["present"] and report["tpm"]["version"] == "2.0":
        score += 25
    if report["kernel_integrity"]["ima_enabled"]:
        score += 15
    if report["kernel_integrity"]["kernel_lockdown"] not in ("none", ""):
        score += 20
    if report["kernel_integrity"]["kaslr"]:
        score += 10

    report["security_score"] = score
    report["security_grade"] = (
        "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D"
    )
    return report


if __name__ == "__main__":
    import json
    audit = full_boot_security_audit()
    print(json.dumps(audit, indent=2, ensure_ascii=False))
    print(f"\n부트 보안 점수: {audit['security_score']}/100 (등급: {audit['security_grade']})")
```

---

## 2. TPM 기반 키 관리

### 2.1 TPM 2.0을 이용한 디스크 암호화

```bash
# LUKS + TPM2 통합 (systemd-cryptenroll)
# TPM2 PCR 정책으로 암호화 키 봉인

# 현재 PCR 값 확인 (부트 상태 해시)
tpm2_pcrread sha256:0,1,2,3,4,5,6,7

# LUKS 볼륨에 TPM2 키 등록 (PCR 7 = 시큐어 부트 상태에 바인딩)
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/sda2

# 부트 시 자동 잠금 해제 설정
echo "luks_volume /dev/sda2 - tpm2-device=auto,tpm2-pcrs=7" | sudo tee -a /etc/crypttab

# Clevis를 이용한 LUKS+TPM 통합 (대안)
sudo clevis luks bind -d /dev/sda2 tpm2 '{"pcr_ids":"7"}'
```

```python
#!/usr/bin/env python3
"""
TPM2 활용 키 봉인 및 PCR 정책 검증 스크립트.
tpm2-tools 설치 필요.
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def read_pcr_values(pcr_list: list[int] = list(range(8))) -> dict[int, str]:
    """TPM2 PCR 값 읽기."""
    pcr_arg = ",".join(map(str, pcr_list))
    result = subprocess.run(
        ["tpm2_pcrread", f"sha256:{pcr_arg}"],
        capture_output=True, text=True, check=False
    )
    values: dict[int, str] = {}
    for line in result.stdout.splitlines():
        # 형식: "  0 : 0xABCDEF..."
        import re
        m = re.match(r"\s*(\d+)\s*:\s*(0x[0-9A-Fa-f]+)", line)
        if m:
            values[int(m.group(1))] = m.group(2)
    return values


def seal_secret_to_tpm(secret: bytes, pcr_values: list[int] = [7]) -> bool:
    """
    TPM2로 비밀값 봉인 (특정 PCR 값에 바인딩).
    PCR 값이 변경되면 봉인 해제 불가.
    예: PCR 7 = 시큐어 부트 설정에 바인딩
    """
    pcr_arg = "+".join(f"sha256:{p}" for p in pcr_values)

    # 비밀값 임시 파일에 저장
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(secret)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["tpm2_create", "-C", "o", "-u", "/tmp/sealed.pub",
             "-r", "/tmp/sealed.priv", "-L", pcr_arg,
             "-i", tmp_path],
            check=False, capture_output=True
        )
        success = result.returncode == 0
        if success:
            log.info("TPM 봉인 성공 (PCR: %s)", pcr_arg)
        else:
            log.error("TPM 봉인 실패: %s", result.stderr.decode())
        return success
    finally:
        os.unlink(tmp_path)


def verify_boot_integrity(
    expected_pcr_file: str,
    current_pcrs: Optional[dict[int, str]] = None,
) -> dict[str, object]:
    """
    저장된 PCR 값과 현재 PCR 값 비교.
    변경이 있으면 부트 체인 조작 의심.
    """
    import json

    if current_pcrs is None:
        current_pcrs = read_pcr_values()

    expected_path = Path(expected_pcr_file)
    if not expected_path.exists():
        # 최초 실행: 현재 값 저장
        expected_path.write_text(json.dumps(current_pcrs, indent=2))
        log.info("PCR 기준값 저장: %s", expected_pcr_file)
        return {"status": "baseline_created", "changes": []}

    expected = json.loads(expected_path.read_text())
    changes = []
    for pcr_id, current_val in current_pcrs.items():
        expected_val = expected.get(str(pcr_id), expected.get(pcr_id))
        if expected_val and expected_val != current_val:
            changes.append({
                "pcr": pcr_id,
                "expected": expected_val,
                "current": current_val,
            })
            log.warning("PCR %d 변경 감지: %s → %s", pcr_id, expected_val, current_val)

    return {
        "status": "changed" if changes else "ok",
        "changes": changes,
        "tampered": bool(changes),
    }
```

---

## 3. 물리 보안 통제

```python
#!/usr/bin/env python3
"""
물리 보안 감사 체크리스트 자동화.
서버/네트워크 장비 물리 보안 정책 준수 확인.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PhysicalSecurityCheck:
    category: str
    check: str
    compliant: bool
    risk: str
    notes: str = ""


PHYSICAL_SECURITY_CHECKLIST = [
    # 데이터센터/서버실
    ("접근 통제", "서버실 잠금 및 배지 접근 시스템", "badge_lock"),
    ("접근 통제", "CCTV 24/7 모니터링", "cctv"),
    ("접근 통제", "방문자 로그 기록 (6개월 이상 보관)", "visitor_log"),
    ("접근 통제", "이중 인증 물리 접근 (배지+PIN)", "dual_factor_physical"),
    # 장비 보호
    ("장비 보안", "서버 케이스 잠금", "case_lock"),
    ("장비 보안", "USB 포트 물리적 차단 또는 비활성화", "usb_disabled"),
    ("장비 보안", "광학 드라이브 없음 또는 BIOS에서 비활성화", "optical_disabled"),
    ("장비 보안", "카파 잠금 (Kensington) 랩톱 보안", "cable_lock"),
    # 네트워크 보안
    ("네트워크 물리", "미사용 네트워크 포트 비활성화", "unused_ports_disabled"),
    ("네트워크 물리", "네트워크 케이블 표시 및 문서화", "cable_labeled"),
    # 환경 보안
    ("환경", "화재 감지 및 자동 소화 시스템", "fire_suppression"),
    ("환경", "UPS 및 발전기 백업 전력", "power_backup"),
    ("환경", "온도/습도 모니터링", "environmental_monitoring"),
    # 폐기
    ("폐기", "하드디스크 물리 파쇄 또는 DoD 7회 덮어쓰기", "secure_disposal"),
    ("폐기", "폐기 기록 문서화", "disposal_records"),
]


def run_physical_security_audit(
    responses: dict[str, bool],
) -> list[PhysicalSecurityCheck]:
    """
    물리 보안 체크리스트 실행.
    responses: {"badge_lock": True, "cctv": False, ...}
    """
    risk_map = {
        "badge_lock": "High", "cctv": "Medium", "visitor_log": "Medium",
        "dual_factor_physical": "High", "case_lock": "Medium",
        "usb_disabled": "High", "optical_disabled": "Medium",
        "cable_lock": "Medium", "unused_ports_disabled": "High",
        "secure_disposal": "Critical", "fire_suppression": "High",
    }

    results = []
    for category, check, key in PHYSICAL_SECURITY_CHECKLIST:
        compliant = responses.get(key, False)
        risk = risk_map.get(key, "Low")
        results.append(PhysicalSecurityCheck(
            category=category,
            check=check,
            compliant=compliant,
            risk=risk,
        ))

    return results


def tamper_detection_setup() -> str:
    """
    변조 감지 권장 설정 가이드 출력.
    """
    guide = """
변조 감지 체계:

  소프트웨어:
    AIDE/Tripwire    → 파일 무결성 모니터링 (설치 직후 기준값 생성)
    dm-verity        → 블록 디바이스 수준 무결성 검증
    TPM PCR 감시    → 부트 체인 변조 감지

  하드웨어:
    TCG 변조 감지 스위치  → 케이스 개봉 시 TPM이 기록
    에폭시/레진 봉인      → 커넥터에 실링 → 물리 변조 흔적 남김
    홀로그램 스티커       → 외관 변조 감지 (보조 수단)
    능동형 메시 쉴딩      → HSM에서 변조 시 키 자동 삭제

  모니터링:
    IPMI/BMC 원격 모니터링 → 전원/온도/센서 이상 감지
    전력 소비 분석        → 비정상 전력 패턴 → 글리칭 공격 감지

  대응:
    변조 감지 → 자동 암호화 키 삭제 (HSM)
    변조 감지 → 즉각 보안팀 알림
    변조 감지 → 해당 장비 격리 및 포렌식 조사
"""
    return guide


if __name__ == "__main__":
    print(tamper_detection_setup())
```

---

## 4. 참고 자료

- **UEFI 시큐어 부트 가이드 (Microsoft)**: https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot
- **TCG TPM 2.0 명세**: https://trustedcomputinggroup.org/resource/tpm-library-specification/
- **Linux IMA 문서**: https://www.kernel.org/doc/html/latest/security/IMA-templates.html

---

<!-- detect-validate-34 -->
## 하드웨어 방어 검증 (설정됨 ≠ 작동함)

하드웨어 방어는 *UEFI 시큐어 부트·TPM 키 관리·물리 보안·변조 감지*로 구성된다. "활성화했다"는 설정과 "위협 모델대로 작동한다"는 다르다 — 각 방어를 소유 기기에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 시큐어 부트 | 강제 모드인가? | SecureBoot=1·Setup=0 | Setup 모드 방치 |
| TPM 봉인 | 키가 PCR에 봉인됐나? | 변경 시 unseal 실패 | PCR 미바인딩 |
| 펌웨어 롤백 | 구버전 거부? | 다운그레이드 차단 | 롤백 카운터 없음 |
| 변조 감지 | 트리거 시 소거? | 탬퍼 이벤트→키 소거 | 로그만, 무대응 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 호스트의 시큐어 부트 강제 여부 — SecureBoot=1 이고 Setup 모드 아님이어야 함
mokutil --sb-state 2>/dev/null; bootctl status 2>/dev/null | grep -i 'secure boot'
# 2) TPM PCR 봉인 검증 — 부트 상태 변경 시 unseal 실패가 정상(소유 기기)
tpm2_pcrread sha256:0,7 2>/dev/null | head
```

> 하드웨어 방어는 *통제가 강제되는가*다 — "시큐어 부트 켰다"와 "SecureBoot=1·Setup 모드 아님이고 키가 PCR에 봉인돼 변경 시 unseal이 실패한다"는 다르다. 각 방어를 소유 기기에서 직접 검증한다([[34_Hardware_Hacking]], [[39_Zero_Trust_Architecture]], [[26_Linux_Hardening]]).

---

<a name="english"></a>

# Hardware Security Defense — Secure Boot, TPM, Physical Security, Tamper Detection

## Overview

No matter how strong the software security is, physical access can defeat it. Hardware security defends against boot-time attacks, physical tampering, DMA attacks, and cold-boot memory extraction.

## Defense-in-Depth for Hardware

```
Physical Layer:    Locked rooms, CCTV, tamper-evident seals
Firmware Layer:    Secure Boot, UEFI password, disable boot devices
Boot Layer:        TPM PCR binding, measured boot, kernel lockdown
OS Layer:          dm-verity, IMA, full-disk encryption
Runtime Layer:     IOMMU/VT-d (DMA protection), CET
```

## Quick Start

```bash
# Check secure boot status
mokutil --sb-state

# Verify TPM 2.0 presence
tpm2_getcap properties-fixed

# Run full boot security audit
python3 boot_security_audit.py

# Bind LUKS disk encryption to TPM PCR 7 (Secure Boot state)
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/sda2

# Verify boot integrity (PCR monitoring)
python3 tpm_monitor.py --baseline /etc/security/pcr_baseline.json
```

## Key Metrics

| Control | Implementation | Protects Against |
|---------|---------------|-----------------|
| Secure Boot | UEFI + signed kernel | Bootkits, rootkits |
| TPM 2.0 + PCR | systemd-cryptenroll | Cold boot, LUKS bypass |
| IMA | Kernel module signatures | Kernel module tampering |
| Full-disk encryption | LUKS2 | Physical disk theft |
| Case tamper switch | TCG spec | Physical case opening |

## References

- TCG TPM 2.0 Spec: https://trustedcomputinggroup.org/resource/tpm-library-specification/
- Linux IMA: https://www.kernel.org/doc/html/latest/security/IMA-templates.html


<!-- detect-validate-34 -->
## Hardware Defense Validation (Configured != Working)

Hardware defense comprises *UEFI Secure Boot, TPM key management, physical security, and tamper detection*. "We enabled it" differs from "it works per the threat model" -- validate each defense on owned devices.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| Secure Boot | Enforcing mode? | SecureBoot=1, Setup=0 | Left in Setup mode |
| TPM sealing | Keys sealed to PCR? | unseal fails on change | No PCR binding |
| Firmware rollback | Old versions rejected? | Downgrade blocked | No rollback counter |
| Tamper detect | Erase on trigger? | Tamper event -> key wipe | Log only, no action |

### Defense validation (verify directly)

```bash
# 1) Whether Secure Boot is enforcing on the owned host — should be SecureBoot=1 and not in Setup mode
mokutil --sb-state 2>/dev/null; bootctl status 2>/dev/null | grep -i 'secure boot'
# 2) TPM PCR sealing check — on a boot-state change, an unseal failure is correct (owned device)
tpm2_pcrread sha256:0,7 2>/dev/null | head
```

> Hardware defense is *whether controls are enforced* -- "Secure Boot is on" differs from "SecureBoot=1, not in Setup mode, and keys are PCR-sealed so unseal fails on change". Validate each defense on owned devices directly ([[34_Hardware_Hacking]], [[39_Zero_Trust_Architecture]], [[26_Linux_Hardening]]).
