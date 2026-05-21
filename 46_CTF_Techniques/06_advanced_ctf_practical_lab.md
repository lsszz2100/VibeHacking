# 고급 CTF 실습 랩 — Pwn·Crypto·Forensics·Misc 종합

## 1. CTF 대회 전략 개요

### 카테고리별 접근 우선순위

| 우선순위 | 카테고리   | 예상 점수 범위 | 권장 투자 시간 | 팀원 배치 기준              |
|----------|------------|---------------|---------------|---------------------------|
| 1        | Misc       | 50–150        | 10–30분       | 전체 팀 빠른 확인          |
| 2        | Crypto     | 100–300       | 30–90분       | 수학·알고리즘 전문 팀원    |
| 3        | Forensics  | 100–300       | 30–90분       | 도구 숙련 팀원             |
| 4        | Web        | 150–500       | 60–180분      | 웹 전문 팀원               |
| 5        | Pwn        | 200–500+      | 90–300분      | 바이너리 전문 팀원         |
| 6        | Reversing  | 150–400       | 60–240분      | 리버싱 전문 팀원           |

### 팀 협업 도구 및 워크플로우

| 단계         | 도구/방법                          | 설명                                          |
|--------------|------------------------------------|----------------------------------------------|
| 문제 배분    | CTFd / rCTF 대시보드 + Notion      | 문제 상태(진행중/해결/포기) 실시간 공유       |
| 소통         | Discord (채널별 카테고리 분리)     | #pwn, #crypto, #forensics, #misc 채널 운영   |
| 파일 공유    | Nextcloud / Google Drive           | 문제 파일·익스플로잇 스크립트 공유            |
| 코드 협업    | Git + GitHub Private Repo          | 익스플로잇 버전 관리, PR로 리뷰               |
| 힌트 관리    | Shared Google Doc                  | 사용한 힌트·차감 점수 기록                    |
| 타임라인     | Pomodoro 50/10 사이클              | 90분 단위로 문제 재배분 검토                  |
| 플래그 제출  | 자동화 스크립트 (rate limit 주의)  | 연속 실패 시 팀 알림 발송                     |

---

## 2. 고급 Pwn: Kernel Exploitation 입문

### 커널 pwn 환경 설정 (QEMU + buildroot)

커널 CTF 문제는 일반적으로 QEMU로 실행되는 커스텀 리눅스 이미지와 취약한 커널 모듈을 제공한다.

**필수 도구 설치:**

```bash
sudo apt install -y qemu-system-x86 qemu-utils gcc make flex bison \
    libssl-dev libelf-dev bc cpio python3 python3-pip
pip install pwntools keystone-engine capstone
```

**buildroot로 최소 루트파일시스템 빌드:**

```bash
git clone https://github.com/buildroot/buildroot.git
cd buildroot
make qemu_x86_64_defconfig
make menuconfig
# -> Target packages -> Show packages that are also provided by busybox
# -> Filesystem images -> ext2/3/4 root filesystem 활성화
make -j$(nproc)
```

**QEMU 실행 스크립트 (`run.sh`) 예시:**

```bash
#!/bin/bash
qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -append "console=ttyS0 quiet panic=1 pti=on kaslr" \
    -cpu kvm64,+smep,+smap \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::4444-:4444 \
    -no-reboot
```

**주요 커널 보호기법:**

| 보호기법 | 설명                                    | 우회 난이도 |
|----------|-----------------------------------------|-------------|
| KASLR    | 커널 주소 공간 배치 무작위화            | 중          |
| SMEP     | 유저 페이지에서 커널 실행 차단          | 높음        |
| SMAP     | 유저 페이지 커널 접근 차단              | 높음        |
| KPTI     | 커널/유저 페이지 테이블 분리            | 높음        |
| Stack Canary | 커널 스택 카나리                    | 중          |

### ret2usr 기법 개요

SMEP/SMAP이 비활성화된 환경에서 사용 가능한 기초 커널 익스플로잇 기법이다.

1. 커널 모듈의 취약점(버퍼 오버플로, UAF 등)으로 RIP 제어 획득
2. 커널 컨텍스트에서 유저스페이스 함수 실행
3. `commit_creds(prepare_kernel_cred(NULL))` 호출로 root 권한 획득
4. `swapgs` → `iretq`로 유저 컨텍스트 복귀

```c
// 권한 상승 페이로드 (유저스페이스 C 코드)
void escalate_privs(void) {
    __asm__ volatile(
        "movq $0, %rdi\n"
        "call prepare_kernel_cred\n"
        "movq %rax, %rdi\n"
        "call commit_creds\n"
    );
    // 커널 컨텍스트 복귀
    __asm__ volatile(
        "swapgs\n"
        "movq %0, 0x20(%%rsp)\n"
        "iretq\n"
        : : "r"(user_cs)
    );
}
```

### Python CLI: 커널 CTF 자동화 익스플로잇 프레임워크

```python
#!/usr/bin/env python3
"""
커널 CTF 자동화 익스플로잇 프레임워크

사용법:
    python3 kernel_exploit_framework.py --exploit-script exploit.c \
        --target qemu --escalate --qemu-port 4444
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import tempfile
import os
import shutil
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="커널 CTF 자동화 익스플로잇 프레임워크",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--exploit-script",
        required=True,
        type=Path,
        help="컴파일할 C 익스플로잇 소스 파일 경로",
    )
    parser.add_argument(
        "--target",
        choices=["local", "qemu"],
        default="qemu",
        help="실행 대상 환경 (local: 로컬 커널 모듈, qemu: QEMU VM)",
    )
    parser.add_argument(
        "--escalate",
        action="store_true",
        help="권한 상승 성공 여부 자동 확인",
    )
    parser.add_argument(
        "--qemu-port",
        type=int,
        default=4444,
        help="QEMU SSH 포트 (--target qemu 시 사용)",
    )
    parser.add_argument(
        "--qemu-host",
        default="127.0.0.1",
        help="QEMU 호스트 주소",
    )
    parser.add_argument(
        "--static",
        action="store_true",
        help="정적 바이너리로 컴파일 (QEMU 환경 호환성 향상)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="명령 실행 타임아웃 (초)",
    )
    return parser.parse_args()


def compile_exploit(
    source: Path,
    static: bool,
    output_dir: Path,
) -> Path:
    """C 소스를 컴파일하여 바이너리 생성."""
    output = output_dir / "exploit"
    cmd: list[str] = [
        "gcc",
        str(source),
        "-o", str(output),
        "-Wall",
        "-O2",
    ]
    if static:
        cmd.append("-static")

    print(f"[*] 컴파일: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] 컴파일 실패:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    output.chmod(0o755)
    print(f"[+] 컴파일 완료: {output}")
    return output


def run_local(
    binary: Path,
    escalate: bool,
    timeout: int,
) -> None:
    """로컬 환경에서 익스플로잇 실행."""
    print(f"[*] 로컬 실행: {binary}")
    try:
        result = subprocess.run(
            [str(binary)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        print(result.stdout)
        if result.stderr:
            print(f"[stderr]\n{result.stderr}", file=sys.stderr)

        if escalate:
            check_escalation_output(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"[!] 타임아웃 ({timeout}초) 초과", file=sys.stderr)
        sys.exit(1)


def run_qemu(
    binary: Path,
    host: str,
    port: int,
    escalate: bool,
    timeout: int,
) -> None:
    """QEMU VM에 바이너리를 전송하고 실행."""
    if not shutil.which("scp") or not shutil.which("ssh"):
        print("[!] scp/ssh 명령을 찾을 수 없습니다.", file=sys.stderr)
        sys.exit(1)

    ssh_opts = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(port),
    ]

    # 바이너리 전송
    print(f"[*] QEMU({host}:{port})로 바이너리 전송 중...")
    scp_cmd = ["scp"] + ssh_opts + [str(binary), f"root@{host}:/tmp/exploit"]
    result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=timeout)

    if result.returncode != 0:
        print(f"[!] 전송 실패:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    # 실행 권한 설정 및 실행
    ssh_cmd = ["ssh"] + ssh_opts + [
        f"root@{host}",
        "chmod +x /tmp/exploit && /tmp/exploit",
    ]
    print("[*] QEMU에서 익스플로잇 실행 중...")
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)

    print(result.stdout)
    if result.stderr:
        print(f"[stderr]\n{result.stderr}", file=sys.stderr)

    if escalate:
        check_escalation_output(result.stdout)


def check_escalation_output(output: str) -> None:
    """출력에서 권한 상승 성공 여부 판단."""
    success_patterns = ["uid=0", "root", "# ", "successfully escalated"]
    for pattern in success_patterns:
        if pattern.lower() in output.lower():
            print(f"\n[+] 권한 상승 성공! (패턴: '{pattern}')")
            return
    print("\n[-] 권한 상승 확인 실패. 출력을 직접 검토하세요.")


def main() -> None:
    args = parse_args()

    if not args.exploit_script.exists():
        print(f"[!] 파일 없음: {args.exploit_script}", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="kernel_exploit_") as tmpdir:
        tmp_path = Path(tmpdir)
        binary = compile_exploit(args.exploit_script, args.static, tmp_path)

        if args.target == "local":
            run_local(binary, args.escalate, args.timeout)
        else:
            run_qemu(
                binary,
                args.qemu_host,
                args.qemu_port,
                args.escalate,
                args.timeout,
            )


if __name__ == "__main__":
    main()
```

---

## 3. 고급 Crypto: LCG 상태 복구 + MT19937 예측

### 선형 합동 생성기(LCG) 역산

LCG는 `X_{n+1} = (a * X_n + c) mod m` 형태의 PRNG이다. 연속된 출력값 3개면 파라미터와 시드를 복구할 수 있다.

**LCG 역산 원리:**

```
d1 = X2 - X1
d2 = X3 - X2
d3 = X4 - X3

m = gcd(d2*d1 - d3*d2, d3*d1 - d2^2)  # 후보 모듈러스
a = (X2 - X1) * modinv(X1 - X0, m) mod m
c = X1 - a * X0 mod m
```

### Mersenne Twister(MT19937) 상태 예측

파이썬 `random` 모듈의 기반 알고리즘이다. 624개의 32비트 출력값을 관측하면 내부 상태를 완전히 복구할 수 있다.

**상태 역변환 (Untemper):**

```python
def untemper(y: int) -> int:
    # 역 오른쪽 시프트 XOR
    y ^= y >> 18
    # 역 왼쪽 시프트 XOR (마스크 0x9d2c5680)
    y ^= (y << 15) & 0xefc60000
    # 역 왼쪽 시프트 XOR (마스크 0xefc60000)
    b = 0x9d2c5680
    tmp = y ^ ((y << 7) & b)
    tmp = y ^ ((tmp << 7) & b)
    tmp = y ^ ((tmp << 7) & b)
    tmp = y ^ ((tmp << 7) & b)
    y = y ^ ((tmp << 7) & b)
    # 역 오른쪽 시프트 XOR 11비트
    tmp = y ^ (y >> 11)
    y = y ^ (tmp >> 11)
    return y
```

### Python CLI: PRNG 공격기

```python
#!/usr/bin/env python3
"""
PRNG 공격기 — LCG 역산 및 MT19937 상태 복구

사용법:
    # LCG 파라미터 역산
    python3 prng_attacker.py --prng lcg --samples "1234,5678,91011,12131" \
        --output lcg_state.txt

    # MT19937 상태 복구 (624개 샘플)
    python3 prng_attacker.py --prng mt19937 --samples-file mt_outputs.txt \
        --predict 10 --output mt_prediction.txt
"""

from __future__ import annotations

import argparse
import sys
import math
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PRNG 공격기 — LCG 역산 / MT19937 상태 복구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--prng",
        choices=["lcg", "mt19937"],
        required=True,
        help="공격할 PRNG 종류",
    )
    parser.add_argument(
        "--samples",
        type=str,
        help="관측된 출력값 (콤마 구분)",
    )
    parser.add_argument(
        "--samples-file",
        type=Path,
        help="관측된 출력값 파일 (한 줄에 하나씩)",
    )
    parser.add_argument(
        "--predict",
        type=int,
        default=5,
        help="복구 후 생성할 미래 값 개수",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="결과를 저장할 파일 경로",
    )
    return parser.parse_args()


def load_samples(args: argparse.Namespace) -> list[int]:
    samples: list[int] = []
    if args.samples:
        samples = [int(x.strip()) for x in args.samples.split(",")]
    elif args.samples_file:
        text = args.samples_file.read_text()
        samples = [int(line.strip()) for line in text.splitlines() if line.strip()]
    else:
        print("[!] --samples 또는 --samples-file 중 하나를 지정하세요.", file=sys.stderr)
        sys.exit(1)
    return samples


# ── LCG ──────────────────────────────────────────────────────────────────────

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int | None:
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        return None
    return x % m


def recover_lcg(samples: list[int]) -> dict[str, int] | None:
    """LCG 파라미터(m, a, c)와 다음 시드를 복구한다."""
    if len(samples) < 4:
        print("[!] LCG 복구에는 최소 4개의 연속 출력값이 필요합니다.", file=sys.stderr)
        return None

    # 차분 계산
    diffs = [samples[i + 1] - samples[i] for i in range(len(samples) - 1)]

    # 모듈러스 후보: gcd(|d[i]*d[i-1] - d[i+1]*d[i]|)
    candidates: list[int] = []
    for i in range(len(diffs) - 2):
        val = abs(diffs[i + 1] * diffs[i - 1] - diffs[i] ** 2) if i > 0 else abs(
            diffs[i + 1] * diffs[i] - diffs[i + 1] * diffs[i]
        )
        if val > 1:
            candidates.append(val)

    # 모든 연속 쌍의 차분 곱으로 m 후보 산출
    t_vals: list[int] = []
    for i in range(len(diffs) - 1):
        t = abs(diffs[i + 1] * diffs[i - 1] - diffs[i] ** 2) if i > 0 else 0
        if t > 1:
            t_vals.append(t)

    m = 0
    if t_vals:
        m = t_vals[0]
        for v in t_vals[1:]:
            m = gcd(m, v)

    if m <= 1:
        # 단순 연속 차분으로 재시도
        m = gcd(abs(diffs[1] * diffs[0] - diffs[2] * diffs[1]),
                abs(diffs[2] * diffs[1] - diffs[3] * diffs[2])) if len(diffs) >= 4 else 0

    if m <= 1:
        print("[!] 모듈러스 복구 실패. 더 많은 샘플이 필요합니다.", file=sys.stderr)
        return None

    # a, c 복구
    inv_d0 = modinv(diffs[0] % m, m)
    if inv_d0 is None:
        print("[!] a 복구 실패 (역원 없음).", file=sys.stderr)
        return None

    a = (diffs[1] * inv_d0) % m
    c = (samples[1] - a * samples[0]) % m

    return {"m": m, "a": a, "c": c, "last": samples[-1]}


def lcg_next(state: dict[str, int]) -> int:
    return (state["a"] * state["last"] + state["c"]) % state["m"]


# ── MT19937 ───────────────────────────────────────────────────────────────────

N = 624
M = 397
MATRIX_A = 0x9908b0df
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff


def untemper(y: int) -> int:
    """MT19937 출력값을 내부 상태값으로 역변환."""
    # 역 오른쪽 시프트 XOR 18
    y ^= y >> 18
    # 역 왼쪽 시프트 XOR 15 (마스크 0xefc60000)
    y ^= (y << 15) & 0xefc60000
    # 역 왼쪽 시프트 XOR 7 (마스크 0x9d2c5680)
    b = 0x9d2c5680
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & b)
    y = tmp
    # 역 오른쪽 시프트 XOR 11
    tmp = y ^ (y >> 11)
    y = y ^ (tmp >> 11)
    return y & 0xffffffff


def mt_generate(mt: list[int]) -> list[int]:
    """MT 내부 상태에서 624개의 값을 생성."""
    output: list[int] = []
    mag01 = [0, MATRIX_A]
    for kk in range(N):
        y = (mt[kk] & UPPER_MASK) | (mt[(kk + 1) % N] & LOWER_MASK)
        mt[kk] = mt[(kk + M) % N] ^ (y >> 1) ^ mag01[y & 1]

    for kk in range(N):
        y = mt[kk]
        y ^= y >> 11
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= y >> 18
        output.append(y & 0xffffffff)
    return output


def recover_mt19937(samples: list[int]) -> list[int] | None:
    if len(samples) < N:
        print(f"[!] MT19937 복구에는 {N}개의 출력값이 필요합니다. 현재: {len(samples)}", file=sys.stderr)
        return None

    state = [untemper(s) for s in samples[:N]]
    return state


def attack_prng(args: argparse.Namespace, samples: list[int]) -> str:
    lines: list[str] = []

    if args.prng == "lcg":
        lines.append("=== LCG 공격 결과 ===")
        state = recover_lcg(samples)
        if state is None:
            return "[!] LCG 복구 실패"
        lines.append(f"모듈러스 m = {state['m']}")
        lines.append(f"승수    a = {state['a']}")
        lines.append(f"증분    c = {state['c']}")
        lines.append(f"\n다음 {args.predict}개 예측값:")
        current = state["last"]
        for i in range(args.predict):
            current = (state["a"] * current + state["c"]) % state["m"]
            lines.append(f"  [{i + 1}] {current}")

    elif args.prng == "mt19937":
        lines.append("=== MT19937 공격 결과 ===")
        mt_state = recover_mt19937(samples)
        if mt_state is None:
            return "[!] MT19937 복구 실패"
        lines.append(f"내부 상태 복구 완료 ({N}개 워드)")
        next_vals = mt_generate(list(mt_state))
        lines.append(f"\n다음 {args.predict}개 예측값:")
        for i, v in enumerate(next_vals[: args.predict]):
            lines.append(f"  [{i + 1}] {v}")

    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    samples = load_samples(args)
    print(f"[*] 로드된 샘플 수: {len(samples)}")

    result = attack_prng(args, samples)
    print(result)

    if args.output:
        args.output.write_text(result)
        print(f"\n[+] 결과 저장 완료: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 4. 고급 Forensics: 스테가노그래피 + 트래픽 분석

### LSB 스테가노그래피 탐지/추출

LSB(Least Significant Bit) 기법은 이미지 각 픽셀의 최하위 비트에 비밀 데이터를 숨긴다.

**탐지 지표:**

| 지표              | 정상 이미지            | LSB 삽입 이미지             |
|-------------------|------------------------|-----------------------------|
| Chi-square 통계   | 낮음                   | 유의미하게 높음              |
| 인접 픽셀 상관관계| 높음                   | 약간 감소                    |
| 히스토그램 분포   | 부드러운 곡선          | 짝수/홀수 픽셀값 대칭 패턴   |
| 파일 크기         | 기대치                 | 기대치 (무변화)              |

**PCAP 플래그 추출 도구 조합:**

```bash
# Wireshark 필터: HTTP 응답에서 플래그 패턴 검색
tshark -r capture.pcap -Y "http" -T fields -e http.file_data \
    | xxd | grep -i "flag{"

# DNS 터널링 탐지
tshark -r capture.pcap -Y "dns.qry.name contains \"flag\"" \
    -T fields -e dns.qry.name
```

### Python CLI: 스테가노그래피 탐지기

```python
#!/usr/bin/env python3
"""
스테가노그래피 탐지기 — LSB·DCT·메타데이터 분석 및 추출

사용법:
    # LSB 탐지 및 추출
    python3 steg_detector.py --image flag.png --mode lsb --extract

    # 메타데이터에서 플래그 검색
    python3 steg_detector.py --image challenge.jpg --mode metadata

    # LSB 추출 결과를 파일로 저장
    python3 steg_detector.py --image steg.png --mode lsb --extract \
        --output extracted.bin
"""

from __future__ import annotations

import argparse
import re
import sys
import struct
from pathlib import Path


FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{2,10}\{[^\}]{1,64}\}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="스테가노그래피 탐지기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--image",
        required=True,
        type=Path,
        help="분석할 이미지 파일 경로",
    )
    parser.add_argument(
        "--mode",
        choices=["lsb", "dct", "metadata"],
        default="lsb",
        help="분석 모드 (lsb / dct / metadata)",
    )
    parser.add_argument(
        "--extract",
        action="store_true",
        help="은닉 데이터 추출 시도",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="추출 결과를 저장할 경로",
    )
    parser.add_argument(
        "--bits",
        type=int,
        default=1,
        help="LSB 추출 시 사용할 비트 수 (1–4)",
    )
    parser.add_argument(
        "--channel",
        choices=["R", "G", "B", "A", "all"],
        default="all",
        help="추출할 채널 선택",
    )
    return parser.parse_args()


def try_import_pil() -> object | None:
    try:
        from PIL import Image  # type: ignore
        return Image
    except ImportError:
        return None


def extract_lsb(image_path: Path, bits: int, channel: str) -> bytes:
    """PIL을 사용하여 이미지에서 LSB 데이터를 추출한다."""
    Image = try_import_pil()
    if Image is None:
        print("[!] Pillow 미설치. pip install Pillow 로 설치하세요.", file=sys.stderr)
        sys.exit(1)

    img = Image.open(image_path).convert("RGBA")
    pixels = list(img.getdata())

    channel_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    channels: list[int] = (
        list(channel_map.values()) if channel == "all" else [channel_map[channel]]
    )

    bit_stream: list[int] = []
    mask = (1 << bits) - 1

    for pixel in pixels:
        for ch in channels:
            val = pixel[ch]
            extracted = val & mask
            # bits 개의 비트를 MSB 순서로 추가
            for b in range(bits - 1, -1, -1):
                bit_stream.append((extracted >> b) & 1)

    # 비트스트림을 바이트로 변환
    byte_data: list[int] = []
    for i in range(0, len(bit_stream) - 7, 8):
        byte_val = 0
        for b in range(8):
            byte_val = (byte_val << 1) | bit_stream[i + b]
        byte_data.append(byte_val)
        # null 바이트 연속 10개 이상이면 종료
        if len(byte_data) > 20 and all(v == 0 for v in byte_data[-10:]):
            break

    return bytes(byte_data)


def analyze_metadata(image_path: Path) -> dict[str, str]:
    """이미지 메타데이터(EXIF/XMP/Comment)에서 숨겨진 데이터를 탐색한다."""
    Image = try_import_pil()
    if Image is None:
        print("[!] Pillow 미설치.", file=sys.stderr)
        sys.exit(1)

    metadata: dict[str, str] = {}
    img = Image.open(image_path)

    # EXIF 데이터
    exif_data = img._getexif() if hasattr(img, "_getexif") else None
    if exif_data:
        for tag_id, value in exif_data.items():
            if isinstance(value, (str, bytes)):
                key = f"EXIF_{tag_id}"
                val_str = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
                metadata[key] = val_str

    # PNG 텍스트 청크
    if hasattr(img, "text"):
        for k, v in img.text.items():
            metadata[f"PNG_text_{k}"] = v

    # 파일 코멘트
    if hasattr(img, "info"):
        for k, v in img.info.items():
            if isinstance(v, (str, bytes)):
                val_str = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                metadata[f"info_{k}"] = val_str

    return metadata


def detect_chi_square(image_path: Path) -> float:
    """Chi-square 통계로 LSB 삽입 여부를 추정한다."""
    Image = try_import_pil()
    if Image is None:
        return -1.0

    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    r_vals = [p[0] for p in pixels]

    # 짝수/홀수 픽셀값의 빈도 차이 계산
    freq: dict[int, int] = {}
    for v in r_vals:
        freq[v] = freq.get(v, 0) + 1

    chi_sq = 0.0
    for i in range(0, 256, 2):
        f_even = freq.get(i, 0)
        f_odd = freq.get(i + 1, 0)
        expected = (f_even + f_odd) / 2.0
        if expected > 0:
            chi_sq += ((f_even - expected) ** 2 + (f_odd - expected) ** 2) / expected

    return chi_sq


def search_flags(data: bytes) -> list[str]:
    """바이트 데이터에서 플래그 패턴을 검색한다."""
    text = data.decode("utf-8", errors="replace")
    return FLAG_PATTERN.findall(text)


def run_lsb_mode(args: argparse.Namespace) -> None:
    print(f"[*] LSB 분석: {args.image}")
    chi = detect_chi_square(args.image)
    if chi >= 0:
        verdict = "의심됨" if chi > 100 else "정상 범위"
        print(f"[*] Chi-square 통계: {chi:.2f} → {verdict}")

    if args.extract:
        print(f"[*] LSB 추출 중 (bits={args.bits}, channel={args.channel})...")
        raw = extract_lsb(args.image, args.bits, args.channel)
        flags = search_flags(raw)
        if flags:
            print(f"[+] 플래그 발견: {flags}")
        else:
            print("[-] 명확한 플래그 패턴 없음 (원시 데이터 확인 필요)")

        if args.output:
            args.output.write_bytes(raw)
            print(f"[+] 추출 데이터 저장: {args.output} ({len(raw)} bytes)")


def run_metadata_mode(args: argparse.Namespace) -> None:
    print(f"[*] 메타데이터 분석: {args.image}")
    meta = analyze_metadata(args.image)
    if not meta:
        print("[-] 메타데이터 없음")
        return

    for key, val in meta.items():
        flags = FLAG_PATTERN.findall(val)
        flag_mark = " ← [플래그!]" if flags else ""
        preview = val[:120].replace("\n", " ")
        print(f"  {key}: {preview}{flag_mark}")


def run_dct_mode(args: argparse.Namespace) -> None:
    print(f"[*] DCT 분석: {args.image}")
    print("[*] DCT 스테가노그래피 탐지는 steghide/steganalysis 도구를 권장합니다.")
    print("    외부 명령: steghide extract -sf <image> -p <password>")
    print("    또는:      stegsolve.jar 사용")


def main() -> None:
    args = parse_args()

    if not args.image.exists():
        print(f"[!] 파일 없음: {args.image}", file=sys.stderr)
        sys.exit(1)

    mode_handlers = {
        "lsb": run_lsb_mode,
        "metadata": run_metadata_mode,
        "dct": run_dct_mode,
    }
    mode_handlers[args.mode](args)


if __name__ == "__main__":
    main()
```

---

## 5. Misc: OSINT + 인코딩 체인

### 다층 인코딩 자동 해독

CTF Misc 문제에서 자주 등장하는 인코딩 조합:

| 인코딩   | 식별 방법                          | 예시 입력          |
|----------|------------------------------------|--------------------|
| Base64   | `[A-Za-z0-9+/=]`, 길이 % 4 == 0  | `SGVsbG8=`         |
| Base32   | `[A-Z2-7=]`, 대문자+숫자          | `JBSWY3DP`         |
| Hex      | `[0-9a-fA-F]`, 짝수 길이          | `48656c6c6f`       |
| ROT13    | 영문자만 치환                      | `Uryyb`            |
| URL      | `%XX` 패턴 포함                    | `Hello%20World`    |
| Morse    | `.`, `-`, `/`, 공백               | `.... . .-.. .-..` |
| Binary   | `[01]`, 8의 배수 길이              | `01001000`         |
| Caesar   | 알파벳 시프트 (ROT-N)              | 브루트포스 필요    |

### Python CLI: 범용 인코딩 체인 디코더

```python
#!/usr/bin/env python3
"""
범용 인코딩 체인 디코더 — 다층 인코딩 자동 해독

사용법:
    # 단일 문자열 자동 해독
    python3 chain_decoder.py --input "SGVsbG8gV29ybGQ="

    # 파일에서 읽기, 최대 깊이 10, 브루트포스 활성화
    python3 chain_decoder.py --input-file encoded.txt \
        --max-depth 10 --brute-force

    # 알 수 없는 시저 시프트 브루트포스
    python3 chain_decoder.py --input "Khoor Zruog" --brute-force
"""

from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys
import urllib.parse
from pathlib import Path
from dataclasses import dataclass, field


FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{2,10}\{[^\}]{1,64}\}")


@dataclass
class DecodeStep:
    method: str
    result: str
    depth: int


@dataclass
class DecodeResult:
    steps: list[DecodeStep] = field(default_factory=list)
    final: str = ""
    flag_found: list[str] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="범용 인코딩 체인 디코더",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", type=str, help="디코딩할 입력 문자열")
    group.add_argument("--input-file", type=Path, help="디코딩할 입력 파일")
    parser.add_argument(
        "--max-depth",
        type=int,
        default=8,
        help="최대 재귀 깊이 (기본값: 8)",
    )
    parser.add_argument(
        "--brute-force",
        action="store_true",
        help="시저 암호 등 브루트포스 시도",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="결과를 저장할 파일",
    )
    return parser.parse_args()


def try_base64(s: str) -> str | None:
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        decoded = base64.b64decode(s)
        return decoded.decode("utf-8", errors="strict")
    except Exception:
        return None


def try_base32(s: str) -> str | None:
    s = s.strip().upper()
    try:
        padding = 8 - len(s) % 8
        if padding != 8:
            s += "=" * padding
        decoded = base64.b32decode(s)
        return decoded.decode("utf-8", errors="strict")
    except Exception:
        return None


def try_hex(s: str) -> str | None:
    s = s.strip().replace(" ", "").replace("0x", "")
    if len(s) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        return bytes.fromhex(s).decode("utf-8", errors="strict")
    except Exception:
        return None


def try_rot13(s: str) -> str | None:
    result = s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))
    return result if result != s else None


def try_url(s: str) -> str | None:
    if "%" not in s:
        return None
    try:
        decoded = urllib.parse.unquote(s)
        return decoded if decoded != s else None
    except Exception:
        return None


def try_morse(s: str) -> str | None:
    morse_map = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9",
    }
    if not re.search(r"[.\-]", s):
        return None
    words = s.strip().split(" / ")
    result_chars: list[str] = []
    for word in words:
        for code in word.strip().split():
            ch = morse_map.get(code)
            if ch is None:
                return None
            result_chars.append(ch)
        result_chars.append(" ")
    return "".join(result_chars).strip() or None


def try_binary(s: str) -> str | None:
    s = s.strip().replace(" ", "")
    if not re.fullmatch(r"[01]+", s) or len(s) % 8 != 0:
        return None
    try:
        chars = [chr(int(s[i:i+8], 2)) for i in range(0, len(s), 8)]
        return "".join(chars)
    except Exception:
        return None


def try_caesar_brute(s: str) -> list[tuple[int, str]]:
    """ROT-1 ~ ROT-25를 모두 시도하고 플래그 패턴이 있는 것을 반환한다."""
    results: list[tuple[int, str]] = []
    for shift in range(1, 26):
        decoded = []
        for ch in s:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                decoded.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                decoded.append(ch)
        candidate = "".join(decoded)
        if FLAG_PATTERN.search(candidate) or any(
            word in candidate.lower() for word in ["flag", "key", "secret", "password"]
        ):
            results.append((shift, candidate))
    return results


DECODERS: list[tuple[str, object]] = [
    ("base64", try_base64),
    ("base32", try_base32),
    ("hex", try_hex),
    ("url", try_url),
    ("binary", try_binary),
    ("morse", try_morse),
    ("rot13", try_rot13),
]


def decode_chain(
    text: str,
    max_depth: int,
    brute_force: bool,
    current_depth: int = 0,
    steps: list[DecodeStep] | None = None,
) -> DecodeResult:
    if steps is None:
        steps = []

    result = DecodeResult(steps=steps, final=text)
    flags = FLAG_PATTERN.findall(text)
    if flags:
        result.flag_found = flags

    if current_depth >= max_depth or flags:
        return result

    for method_name, decoder in DECODERS:
        try:
            decoded = decoder(text)  # type: ignore
        except Exception:
            continue

        if decoded and decoded != text and decoded.isprintable():
            step = DecodeStep(method=method_name, result=decoded, depth=current_depth + 1)
            child = decode_chain(
                decoded,
                max_depth,
                brute_force,
                current_depth + 1,
                steps + [step],
            )
            if child.flag_found or child.steps:
                return child

    if brute_force and current_depth == 0:
        caesar_results = try_caesar_brute(text)
        for shift, candidate in caesar_results:
            step = DecodeStep(method=f"caesar-{shift}", result=candidate, depth=1)
            child = decode_chain(candidate, max_depth, False, 1, steps + [step])
            if child.flag_found:
                return child

    return result


def format_result(result: DecodeResult) -> str:
    lines: list[str] = ["=== 디코딩 결과 ==="]
    if result.steps:
        lines.append(f"총 {len(result.steps)}단계 디코딩:")
        for step in result.steps:
            preview = step.result[:80].replace("\n", " ")
            lines.append(f"  [{step.depth}] {step.method}: {preview}")
    else:
        lines.append("디코딩 변환 없음 (이미 평문이거나 알 수 없는 인코딩)")

    lines.append(f"\n최종 결과:\n{result.final}")

    if result.flag_found:
        lines.append(f"\n[+] 플래그 발견: {result.flag_found}")
    else:
        lines.append("\n[-] 플래그 패턴 미발견")

    return "\n".join(lines)


def main() -> None:
    args = parse_args()

    if args.input:
        text = args.input
    else:
        text = args.input_file.read_text(encoding="utf-8").strip()

    print(f"[*] 입력 길이: {len(text)}자")
    print(f"[*] 최대 깊이: {args.max_depth}, 브루트포스: {args.brute_force}")

    result = decode_chain(text, args.max_depth, args.brute_force)
    output = format_result(result)
    print(output)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"\n[+] 결과 저장 완료: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 6. CTF 성과 추적 대시보드

### Python CLI: CTF 팀 점수판

```python
#!/usr/bin/env python3
"""
CTF 팀 점수판 — JSON 기반 성과 추적 및 리포트 생성

scores.json 형식 예시:
{
  "ctf_name": "DEF CON CTF 2025",
  "team": "0xTeam",
  "challenges": [
    {"name": "baby_pwn", "category": "Pwn", "points": 100,
     "solved": true, "solver": "alice", "time": "2025-08-10T10:23:00"},
    {"name": "lcg_madness", "category": "Crypto", "points": 300,
     "solved": false, "solver": null, "time": null}
  ]
}

사용법:
    python3 ctf_scoreboard.py --scores-json scores.json --output-format text
    python3 ctf_scoreboard.py --scores-json scores.json --output-format markdown
    python3 ctf_scoreboard.py --scores-json scores.json --output-format html \
        --output report.html
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CTF 팀 점수판 및 성과 추적",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scores-json",
        required=True,
        type=Path,
        help="scores.json 파일 경로",
    )
    parser.add_argument(
        "--output-format",
        choices=["text", "markdown", "html"],
        default="text",
        help="출력 형식",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="결과 파일 경로 (미지정 시 stdout)",
    )
    parser.add_argument(
        "--sort-by",
        choices=["category", "points", "solver", "time"],
        default="category",
        help="정렬 기준",
    )
    return parser.parse_args()


def load_scores(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[!] scores.json 로드 실패: {e}", file=sys.stderr)
        sys.exit(1)


def compute_stats(data: dict) -> dict:
    challenges: list[dict] = data.get("challenges", [])
    solved = [c for c in challenges if c.get("solved")]
    unsolved = [c for c in challenges if not c.get("solved")]

    total_points = sum(c.get("points", 0) for c in solved)
    max_possible = sum(c.get("points", 0) for c in challenges)

    by_category: dict[str, dict] = defaultdict(lambda: {"solved": 0, "total": 0, "points": 0})
    for c in challenges:
        cat = c.get("category", "Unknown")
        by_category[cat]["total"] += 1
        if c.get("solved"):
            by_category[cat]["solved"] += 1
            by_category[cat]["points"] += c.get("points", 0)

    by_solver: dict[str, int] = defaultdict(int)
    for c in solved:
        solver = c.get("solver") or "unknown"
        by_solver[solver] += 1

    return {
        "total_points": total_points,
        "max_possible": max_possible,
        "solved_count": len(solved),
        "total_count": len(challenges),
        "unsolved_count": len(unsolved),
        "solve_rate": len(solved) / len(challenges) * 100 if challenges else 0,
        "by_category": dict(by_category),
        "by_solver": dict(by_solver),
        "solved": solved,
        "unsolved": unsolved,
    }


def format_text(data: dict, stats: dict, sort_by: str) -> str:
    lines: list[str] = []
    lines.append(f"{'='*60}")
    lines.append(f"CTF: {data.get('ctf_name', 'Unknown')}")
    lines.append(f"팀:  {data.get('team', 'Unknown')}")
    lines.append(f"{'='*60}")
    lines.append(f"총점:    {stats['total_points']} / {stats['max_possible']}")
    lines.append(f"해결:    {stats['solved_count']} / {stats['total_count']} "
                 f"({stats['solve_rate']:.1f}%)")
    lines.append("")
    lines.append("[카테고리별 현황]")
    for cat, info in sorted(stats["by_category"].items()):
        bar = "#" * info["solved"] + "-" * (info["total"] - info["solved"])
        lines.append(f"  {cat:<12} [{bar:<10}] "
                     f"{info['solved']}/{info['total']} ({info['points']}점)")
    lines.append("")
    lines.append("[팀원별 해결 수]")
    for solver, count in sorted(stats["by_solver"].items(), key=lambda x: -x[1]):
        lines.append(f"  {solver:<16} {count}문제")
    lines.append("")
    lines.append("[미해결 문제]")
    for c in stats["unsolved"]:
        lines.append(f"  [{c.get('category','?')}] {c.get('name','?')} — {c.get('points',0)}점")
    return "\n".join(lines)


def format_markdown(data: dict, stats: dict, sort_by: str) -> str:
    lines: list[str] = []
    lines.append(f"# CTF 성과 리포트: {data.get('ctf_name', 'Unknown')}")
    lines.append(f"\n**팀:** {data.get('team', 'Unknown')}  ")
    lines.append(f"**총점:** {stats['total_points']} / {stats['max_possible']}  ")
    lines.append(f"**해결률:** {stats['solved_count']}/{stats['total_count']} "
                 f"({stats['solve_rate']:.1f}%)  ")
    lines.append("\n## 카테고리별 현황\n")
    lines.append("| 카테고리 | 해결 | 전체 | 획득점수 |")
    lines.append("|----------|------|------|----------|")
    for cat, info in sorted(stats["by_category"].items()):
        lines.append(f"| {cat} | {info['solved']} | {info['total']} | {info['points']} |")
    lines.append("\n## 팀원별 해결 현황\n")
    lines.append("| 팀원 | 해결 문제 수 |")
    lines.append("|------|-------------|")
    for solver, count in sorted(stats["by_solver"].items(), key=lambda x: -x[1]):
        lines.append(f"| {solver} | {count} |")
    lines.append("\n## 미해결 문제\n")
    for c in stats["unsolved"]:
        lines.append(f"- **[{c.get('category','?')}]** {c.get('name','?')} — {c.get('points',0)}점")
    lines.append("\n## 해결 문제 목록\n")
    lines.append("| 문제명 | 카테고리 | 점수 | 해결자 | 시간 |")
    lines.append("|--------|----------|------|--------|------|")
    for c in stats["solved"]:
        t = c.get("time", "-") or "-"
        lines.append(
            f"| {c.get('name','?')} | {c.get('category','?')} | "
            f"{c.get('points',0)} | {c.get('solver','-') or '-'} | {t} |"
        )
    return "\n".join(lines)


def format_html(data: dict, stats: dict, sort_by: str) -> str:
    title = f"CTF 성과 리포트: {data.get('ctf_name', 'Unknown')}"
    rows_cat = ""
    for cat, info in sorted(stats["by_category"].items()):
        rows_cat += (
            f"<tr><td>{cat}</td><td>{info['solved']}</td>"
            f"<td>{info['total']}</td><td>{info['points']}</td></tr>\n"
        )
    rows_solver = ""
    for solver, count in sorted(stats["by_solver"].items(), key=lambda x: -x[1]):
        rows_solver += f"<tr><td>{solver}</td><td>{count}</td></tr>\n"

    return f"""<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><title>{title}</title>
<style>
  body {{ font-family: monospace; max-width: 900px; margin: 2em auto; }}
  h1 {{ color: #2c3e50; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 12px; text-align: left; }}
  th {{ background: #2c3e50; color: white; }}
  tr:nth-child(even) {{ background: #f5f5f5; }}
  .summary {{ background: #eaf4fb; padding: 1em; border-radius: 4px; }}
</style></head>
<body>
<h1>{title}</h1>
<div class="summary">
  <p><strong>팀:</strong> {data.get('team','Unknown')}</p>
  <p><strong>총점:</strong> {stats['total_points']} / {stats['max_possible']}</p>
  <p><strong>해결률:</strong> {stats['solved_count']}/{stats['total_count']}
     ({stats['solve_rate']:.1f}%)</p>
</div>
<h2>카테고리별 현황</h2>
<table><tr><th>카테고리</th><th>해결</th><th>전체</th><th>획득점수</th></tr>
{rows_cat}</table>
<h2>팀원별 해결 현황</h2>
<table><tr><th>팀원</th><th>해결 문제 수</th></tr>
{rows_solver}</table>
</body></html>"""


def main() -> None:
    args = parse_args()
    data = load_scores(args.scores_json)
    stats = compute_stats(data)

    formatters = {
        "text": format_text,
        "markdown": format_markdown,
        "html": format_html,
    }
    output = formatters[args.output_format](data, stats, args.sort_by)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"[+] 리포트 저장: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
```

---

## 참고 리소스 및 학습 체크리스트

| 항목                                | 완료 |
|-------------------------------------|------|
| QEMU 커널 디버깅 환경 구성          | [ ]  |
| ret2usr 기법 이해 및 직접 구현      | [ ]  |
| LCG 파라미터 역산 수식 이해         | [ ]  |
| MT19937 상태 복구 624개 실습        | [ ]  |
| LSB 스테가노그래피 직접 삽입/추출   | [ ]  |
| PCAP 플래그 추출 (Wireshark CLI)    | [ ]  |
| 다층 인코딩 체인 5단계 이상 해독    | [ ]  |
| CTF 점수판 JSON 형식 직접 운영      | [ ]  |

**참고 자료:**
- [pwn.college](https://pwn.college) — 커널 익스플로잇 커리큘럼
- [CryptoHack](https://cryptohack.org) — 암호학 CTF 문제
- [PicoCTF](https://picoctf.org) — 입문자 친화적 CTF
- CTFtime.org — 전 세계 CTF 일정 및 팀 랭킹
- pwntools 공식 문서 — CTF 바이너리 익스플로잇 자동화
