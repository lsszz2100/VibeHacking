> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 펌웨어 CTF 실습 랩

## 랩 개요

펌웨어 보안 취약점을 CTF 형식으로 학습한다. 펌웨어 이미지 분석, 숨겨진 자격증명 추출, 파일시스템 언패킹, 업데이트 서명 우회 등 실제 임베디드 기기 공격 기법을 실습한다.

## 실습 환경 설정

```bash
# 필수 도구 설치
sudo apt-get install binwalk squashfs-tools foremost strings file

# Python 패키지
pip install pycryptodome

# CTF 도구 실행
python3 firmware_ctf.py --help
```

```python
#!/usr/bin/env python3
"""펌웨어 CTF 실습 도구 — firmware_ctf.py"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FirmwareChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


@dataclass
class BinwalkEntry:
    offset: int
    description: str
    extracted_path: str | None = None


def verify_flag(submitted: str, challenge: FirmwareChallenge) -> bool:
    """제출 플래그 검증."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, FirmwareChallenge] = {
    "cred_extract": FirmwareChallenge(
        name="숨겨진 자격증명 추출",
        category="Firmware Analysis",
        points=100,
        description="""
펌웨어 이미지 'router_fw_v2.3.bin'에 관리자 자격증명이 숨겨져 있다.
binwalk로 이미지를 분석하고, 파일시스템을 언패킹하여
/etc/passwd 또는 /etc/shadow 파일에서 자격증명을 추출하라.

힌트 파일 위치: firmware_samples/router_fw_v2.3.bin
목표: 관리자 계정의 MD5 해시 크래킹 후 플래그 형식으로 제출
""",
        flag="CTF{4dm1n_p4ssw0rd_3xtr4ct3d}",
        hints=[
            "binwalk -e router_fw_v2.3.bin 으로 자동 추출",
            "strings 명령으로 바이너리에서 텍스트 검색",
            "john --format=md5crypt shadow 로 해시 크래킹",
        ],
    ),
    "hardcoded_key": FirmwareChallenge(
        name="하드코딩된 시크릿 키 발견",
        category="Firmware Analysis",
        points=150,
        description="""
IoT 기기 펌웨어에 AES 키가 하드코딩되어 있다.
strings 와 grep으로 바이너리를 분석하여 32바이트 헥스 키를 찾아라.
발견한 키를 사용해 암호화된 설정 파일 'config.enc'를 복호화하면
플래그가 나타난다.

암호화 방식: AES-256-CBC
IV: 첫 16바이트가 파일 헤더에 저장됨
""",
        flag="CTF{h4rdc0d3d_k3y_f0und_4nd_d3crypt3d}",
        hints=[
            "strings firmware.bin | grep -E '[0-9a-fA-F]{64}'",
            "grep -r 'AES\\|KEY\\|SECRET' 추출된 파일시스템",
            "Python pycryptodome: AES.new(key, AES.MODE_CBC, iv)",
        ],
    ),
    "squashfs_flag": FirmwareChallenge(
        name="SquashFS 파일시스템 플래그 추출",
        category="Firmware Analysis",
        points=200,
        description="""
펌웨어 이미지 내부에 SquashFS 파일시스템이 있다.
파일시스템을 마운트하거나 언패킹하여 숨겨진 플래그 파일을 찾아라.
플래그는 일반적이지 않은 위치에 숨겨져 있으며,
파일 권한이나 타임스탬프가 단서가 될 수 있다.

타겟: squashfs_root.img
""",
        flag="CTF{squ4shfs_fl4g_unp4ck3d}",
        hints=[
            "unsquashfs squashfs_root.img",
            "find squashfs-root/ -name '*.flag' -o -name '.hidden*'",
            "ls -la --time-style=full-iso 로 타임스탬프 확인",
        ],
    ),
    "signature_bypass": FirmwareChallenge(
        name="펌웨어 업데이트 서명 우회",
        category="Firmware Security",
        points=300,
        description="""
라우터의 펌웨어 업데이트 검증 로직이 취약하다.
업데이트 파일 형식:
  [4바이트 매직: 0xDEADBEEF] [4바이트 크기] [SHA256 해시 32바이트] [페이로드]

검증 코드가 해시를 전체 파일이 아닌 처음 256바이트만 검증한다.
악성 페이로드를 포함한 업데이트 파일을 만들어 검증을 우회하라.
업데이트 서버: http://localhost:9000/update
""",
        flag="CTF{f1rmw4r3_s1gn4tur3_byp4ss3d}",
        hints=[
            "struct.pack('>I', 0xDEADBEEF) 로 매직 바이트 생성",
            "검증은 payload[:256]만 확인 — 나머지는 자유롭게 수정 가능",
            "hashlib.sha256(payload[:256]).digest() 로 유효한 해시 생성",
        ],
    ),
}
```

## 챌린지 1: 숨겨진 자격증명 추출

```python
#!/usr/bin/env python3
"""binwalk 결과 파싱 및 자격증명 추출 자동화."""

import argparse
import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractedCredential:
    username: str
    password_hash: str
    hash_type: str
    cracked: str | None = None


def run_binwalk(firmware_path: Path, extract: bool = False) -> list[str]:
    """binwalk 실행 및 결과 파싱."""
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(str(firmware_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout.splitlines()
    except FileNotFoundError:
        # binwalk 없는 환경 — 시뮬레이션 모드
        print("[!] binwalk 미설치. 시뮬레이션 모드 사용")
        return simulate_binwalk_output()


def simulate_binwalk_output() -> list[str]:
    """CTF 실습용 binwalk 시뮬레이션 출력."""
    return [
        "DECIMAL       HEXADECIMAL     DESCRIPTION",
        "--------------------------------------------------------------------------------",
        "0             0x0             DLOB firmware header, boot partition: 'fs-uImage'",
        "112           0x70            LZMA compressed data, ...",
        "1048576       0x100000        Squashfs filesystem, little endian, version 4.0",
        "               compression:lzo, size: 4194304 bytes",
        "5242880       0x500000        JFFS2 filesystem, little endian",
    ]


def parse_shadow_file(shadow_content: str) -> list[ExtractedCredential]:
    """shadow 파일에서 자격증명 파싱."""
    credentials: list[ExtractedCredential] = []
    for line in shadow_content.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 2 or parts[1] in ("*", "!", "x", ""):
            continue
        username = parts[0]
        pw_hash = parts[1]

        # 해시 타입 감지
        if pw_hash.startswith("$1$"):
            hash_type = "MD5"
        elif pw_hash.startswith("$5$"):
            hash_type = "SHA-256"
        elif pw_hash.startswith("$6$"):
            hash_type = "SHA-512"
        elif re.match(r"^[0-9a-fA-F]{32}$", pw_hash):
            hash_type = "MD5 (raw)"
        else:
            hash_type = "Unknown"

        credentials.append(ExtractedCredential(
            username=username,
            password_hash=pw_hash,
            hash_type=hash_type,
        ))
    return credentials


def search_hardcoded_secrets(directory: Path) -> dict[str, list[str]]:
    """추출된 파일시스템에서 하드코딩된 시크릿 검색."""
    patterns: dict[str, str] = {
        "passwords": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(\S+)",
        "api_keys": r"(?i)(api.?key|apikey|api_secret)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{16,})",
        "hex_keys": r"[0-9a-fA-F]{32,64}",
        "private_keys": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    }

    findings: dict[str, list[str]] = {k: [] for k in patterns}

    if not directory.exists():
        # 시뮬레이션 데이터
        findings["passwords"] = ["admin:admin123", "root:toor", "guest:guest"]
        findings["hex_keys"] = [
            "aabbccdd" * 8,
            "deadbeef" * 8,
        ]
        return findings

    for fpath in directory.rglob("*"):
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_text(errors="ignore")
            for key, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    for m in matches:
                        entry = f"{fpath}: {m if isinstance(m, str) else m[0]}"
                        findings[key].append(entry)
        except (PermissionError, OSError):
            continue

    return findings


def crack_md5_hash(password_hash: str, wordlist: list[str]) -> str | None:
    """간단한 사전 공격으로 MD5 해시 크래킹."""
    import crypt  # noqa: PLC0415  (stdlib, Unix only)
    for word in wordlist:
        try:
            # salt 추출 후 crypt 비교
            computed = crypt.crypt(word, password_hash)
            if computed == password_hash:
                return word
        except Exception:
            # crypt 모듈 없는 환경 — 단순 해시 비교
            simple_hash = hashlib.md5(word.encode()).hexdigest()
            if simple_hash == password_hash:
                return word
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="펌웨어 CTF 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # binwalk 분석
    analyze_p = sub.add_parser("analyze", help="펌웨어 이미지 분석")
    analyze_p.add_argument("firmware", type=Path, help="펌웨어 바이너리 경로")
    analyze_p.add_argument("-e", "--extract", action="store_true", help="자동 추출")

    # 자격증명 검색
    cred_p = sub.add_parser("creds", help="자격증명 파일 파싱")
    cred_p.add_argument("shadow_file", type=Path, nargs="?", help="shadow 파일 경로")
    cred_p.add_argument("--wordlist", type=Path, help="사전 파일")

    # 시크릿 검색
    secret_p = sub.add_parser("secrets", help="하드코딩된 시크릿 검색")
    secret_p.add_argument("directory", type=Path, nargs="?", default=Path("."))

    # 챌린지 목록
    sub.add_parser("list", help="CTF 챌린지 목록")

    # 플래그 제출
    submit_p = sub.add_parser("submit", help="플래그 제출")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "analyze":
        print(f"[*] {args.firmware} 분석 중...")
        lines = run_binwalk(args.firmware, args.extract)
        for line in lines:
            print(line)

    elif args.cmd == "creds":
        if args.shadow_file and args.shadow_file.exists():
            content = args.shadow_file.read_text()
        else:
            # 시뮬레이션 shadow 파일
            content = (
                "root:$1$abc$XypRS.zGAzFiM5JA/B.Aq1:19000:0:99999:7:::\n"
                "admin:$1$def$mR5TLUFzIPPFMXhz4sKuD.:19001:0:99999:7:::\n"
                "guest:*:19000:0:99999:7:::\n"
            )
            print("[!] shadow 파일 미지정. 시뮬레이션 데이터 사용")

        creds = parse_shadow_file(content)
        print(f"\n[*] 자격증명 {len(creds)}개 발견:\n")
        wordlist = ["admin", "admin123", "password", "toor", "root", "1234"]
        if args.wordlist and args.wordlist.exists():
            wordlist = args.wordlist.read_text().splitlines()

        for cred in creds:
            print(f"  사용자: {cred.username}")
            print(f"  해시:   {cred.password_hash[:32]}...")
            print(f"  유형:   {cred.hash_type}")
            cracked = crack_md5_hash(cred.password_hash, wordlist)
            if cracked:
                print(f"  크래킹: {cracked}  <-- 성공!")
            print()

    elif args.cmd == "secrets":
        print(f"[*] {args.directory} 에서 시크릿 검색...")
        findings = search_hardcoded_secrets(args.directory)
        for category, items in findings.items():
            if items:
                print(f"\n[+] {category} ({len(items)}개):")
                for item in items[:5]:
                    print(f"  {item}")
                if len(items) > 5:
                    print(f"  ... 외 {len(items) - 5}개")

    elif args.cmd == "list":
        print("펌웨어 CTF 챌린지 목록:\n")
        for cid, ch in CHALLENGES.items():
            print(f"  [{ch.points}pt] {ch.name}  (ID: {cid})")
            print(f"         카테고리: {ch.category}")
            desc_first = ch.description.strip().splitlines()[0]
            print(f"         {desc_first}")
            print()

    elif args.cmd == "submit":
        ch = CHALLENGES[args.challenge_id]
        if verify_flag(args.flag, ch):
            print(f"[+] 정답! {ch.points}점 획득")
            print(f"    {ch.name} 챌린지 클리어!")
        else:
            print("[-] 오답. 힌트:")
            for i, hint in enumerate(ch.hints, 1):
                print(f"    {i}. {hint}")


if __name__ == "__main__":
    main()
```

## 챌린지 2: SquashFS 파일시스템 플래그 추출

```python
#!/usr/bin/env python3
"""SquashFS 파일시스템 분석 및 숨겨진 플래그 탐색."""

import argparse
import os
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SuspiciousFile:
    path: Path
    reason: str
    size: int
    permissions: str


def find_suspicious_files(root: Path) -> list[SuspiciousFile]:
    """비정상적인 파일 탐지 (CTF 플래그 후보)."""
    suspicious: list[SuspiciousFile] = []

    search_root = root if root.exists() else Path(".")

    for fpath in search_root.rglob("*"):
        if not fpath.is_file():
            continue

        try:
            st = fpath.stat()
            perm = oct(stat.S_IMODE(st.st_mode))
            size = st.st_size

            reasons: list[str] = []

            # 히든 파일
            if fpath.name.startswith(".") and fpath.name not in (".profile", ".bashrc"):
                reasons.append("숨김 파일")

            # 비정상 확장자
            if fpath.suffix in (".flag", ".secret", ".key"):
                reasons.append(f"의심 확장자: {fpath.suffix}")

            # CTF 패턴 파일명
            if any(kw in fpath.name.lower() for kw in ("flag", "secret", "hidden")):
                reasons.append("CTF 키워드 포함")

            # world-writable 파일 (권한 이상)
            if st.st_mode & stat.S_IWOTH:
                reasons.append("world-writable 권한")

            # 비정상적으로 작은 실행 파일 (플래그 포함 가능)
            if fpath.suffix == "" and 10 < size < 200 and st.st_mode & stat.S_IXUSR:
                reasons.append(f"소형 실행 파일 ({size}B)")

            if reasons:
                suspicious.append(SuspiciousFile(
                    path=fpath,
                    reason=", ".join(reasons),
                    size=size,
                    permissions=perm,
                ))
        except (PermissionError, OSError):
            continue

    return suspicious


def simulate_squashfs_contents() -> None:
    """SquashFS 언패킹 시뮬레이션 출력."""
    files = [
        ("squashfs-root/etc/passwd", "일반 파일"),
        ("squashfs-root/etc/shadow", "민감한 파일"),
        ("squashfs-root/usr/bin/busybox", "실행 파일"),
        ("squashfs-root/www/cgi-bin/admin.cgi", "웹 CGI"),
        ("squashfs-root/etc/.hidden_config", "숨김 파일  <-- 수상!"),
        ("squashfs-root/tmp/.flag.txt", "숨김 플래그!  <-- CTF{squ4shfs_fl4g_unp4ck3d}"),
    ]
    print("\n[*] unsquashfs 시뮬레이션 결과:")
    for path, note in files:
        print(f"  {path:<50} ({note})")


def main() -> None:
    parser = argparse.ArgumentParser(description="SquashFS 분석 도구")
    parser.add_argument("directory", type=Path, nargs="?",
                        help="언패킹된 SquashFS 루트 디렉토리")
    parser.add_argument("--simulate", action="store_true",
                        help="시뮬레이션 모드 (실제 파일 불필요)")
    args = parser.parse_args()

    if args.simulate or not args.directory:
        simulate_squashfs_contents()
        return

    suspects = find_suspicious_files(args.directory)
    if not suspects:
        print("[*] 수상한 파일 없음")
        return

    print(f"\n[+] 수상한 파일 {len(suspects)}개 발견:\n")
    for sf in suspects:
        print(f"  경로: {sf.path}")
        print(f"  이유: {sf.reason}")
        print(f"  크기: {sf.size} bytes  권한: {sf.permissions}")
        # 텍스트 내용 미리보기
        try:
            text = sf.path.read_text(errors="ignore")[:80]
            if text.isprintable():
                print(f"  내용: {text!r}")
        except OSError:
            pass
        print()


if __name__ == "__main__":
    main()
```

## 챌린지 3: 펌웨어 업데이트 서명 우회

```python
#!/usr/bin/env python3
"""펌웨어 업데이트 패킷 생성 및 서명 우회."""

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path


MAGIC = 0xDEADBEEF
UPDATE_FLAG = b"CTF{f1rmw4r3_s1gn4tur3_byp4ss3d}"


@dataclass
class FirmwareUpdatePacket:
    magic: int
    payload_size: int
    signature: bytes      # SHA-256, 32바이트
    payload: bytes

    def to_bytes(self) -> bytes:
        header = struct.pack(">II", self.magic, self.payload_size)
        return header + self.signature + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "FirmwareUpdatePacket":
        if len(data) < 40:
            raise ValueError("패킷이 너무 짧음")
        magic, size = struct.unpack(">II", data[:8])
        sig = data[8:40]
        payload = data[40:]
        return cls(magic=magic, payload_size=size, signature=sig, payload=payload)


def create_malicious_update(payload_suffix: bytes = b"\x00") -> bytes:
    """
    취약한 검증 로직을 우회하는 악성 업데이트 패킷 생성.
    서버는 payload[:256]만 해싱하므로 256바이트 이후에 페이로드 삽입 가능.
    """
    # 합법적인 256바이트 헤더 구성 (서버가 검증하는 부분)
    legitimate_header = b"FIRMWARE_UPDATE_v2.3" + b"\x00" * (256 - 20)

    # 악성 페이로드는 256바이트 이후에 추가
    full_payload = legitimate_header + UPDATE_FLAG + payload_suffix

    # 검증 해시는 처음 256바이트만 계산
    signature = hashlib.sha256(full_payload[:256]).digest()

    packet = FirmwareUpdatePacket(
        magic=MAGIC,
        payload_size=len(full_payload),
        signature=signature,
        payload=full_payload,
    )
    return packet.to_bytes()


def verify_update_packet(data: bytes, strict: bool = False) -> dict[str, object]:
    """
    펌웨어 업데이트 검증 시뮬레이션.
    strict=False: 취약한 구현 (처음 256바이트만 검증)
    strict=True:  올바른 구현 (전체 페이로드 검증)
    """
    result: dict[str, object] = {"valid": False, "reason": ""}

    try:
        pkt = FirmwareUpdatePacket.from_bytes(data)
    except ValueError as e:
        result["reason"] = str(e)
        return result

    if pkt.magic != MAGIC:
        result["reason"] = f"매직 바이트 불일치: 0x{pkt.magic:08X}"
        return result

    # 해시 검증 범위 결정
    verify_data = pkt.payload if strict else pkt.payload[:256]
    expected_sig = hashlib.sha256(verify_data).digest()

    if pkt.signature != expected_sig:
        result["reason"] = "서명 불일치"
        return result

    result["valid"] = True
    result["reason"] = "검증 통과"
    result["payload_size"] = pkt.payload_size

    # 페이로드에서 플래그 검색
    if b"CTF{" in pkt.payload:
        idx = pkt.payload.index(b"CTF{")
        end = pkt.payload.index(b"}", idx) + 1
        result["flag"] = pkt.payload[idx:end].decode()

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="펌웨어 업데이트 서명 우회 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("exploit", help="취약한 서명 우회 패킷 생성")

    verify_p = sub.add_parser("verify", help="업데이트 패킷 검증")
    verify_p.add_argument("packet_file", type=Path)
    verify_p.add_argument("--strict", action="store_true", help="엄격한 검증")

    sub.add_parser("demo", help="공격 전체 흐름 시연")

    args = parser.parse_args()

    if args.cmd == "exploit":
        packet_bytes = create_malicious_update()
        out = Path("malicious_update.bin")
        out.write_bytes(packet_bytes)
        print(f"[+] 악성 업데이트 패킷 생성: {out} ({len(packet_bytes)} bytes)")
        print(f"    매직: 0x{MAGIC:08X}")
        print(f"    서명: SHA-256(payload[:256])")
        print(f"    악성 페이로드: 256바이트 이후에 삽입")

    elif args.cmd == "verify":
        data = args.packet_file.read_bytes()
        result = verify_update_packet(data, args.strict)
        mode = "엄격" if args.strict else "취약(기본)"
        print(f"[*] 검증 모드: {mode}")
        print(f"[{'+'if result['valid'] else '!'}] {result['reason']}")
        if "flag" in result:
            print(f"[FLAG] {result['flag']}")

    elif args.cmd == "demo":
        print("[*] 펌웨어 서명 우회 공격 시연\n")
        print("1) 악성 패킷 생성...")
        packet_bytes = create_malicious_update()
        print(f"   크기: {len(packet_bytes)} bytes\n")

        print("2) 취약한 검증 (처음 256바이트만)...")
        res = verify_update_packet(packet_bytes, strict=False)
        print(f"   결과: {'통과' if res['valid'] else '실패'}")
        if "flag" in res:
            print(f"   플래그: {res['flag']}\n")

        print("3) 올바른 검증 (전체 페이로드)...")
        res2 = verify_update_packet(packet_bytes, strict=True)
        print(f"   결과: {'통과' if res2['valid'] else '실패'} — {res2['reason']}")


if __name__ == "__main__":
    main()
```

## CTF 풀이 가이드

```
펌웨어 분석 흐름
├── 1단계: file 명령으로 이미지 유형 확인
├── 2단계: binwalk -e 로 자동 추출
├── 3단계: strings + grep으로 자격증명/키 검색
├── 4단계: unsquashfs 로 파일시스템 언패킹
└── 5단계: find / grep으로 플래그 파일 탐색

자격증명 추출 체크리스트
├── /etc/passwd, /etc/shadow 확인
├── /etc/config/ 설정 파일
├── 웹 서버 설정 (httpd.conf, nginx.conf)
├── 스크립트 파일 내 하드코딩 확인
└── 환경변수 파일 (.env, .profile)

서명 우회 접근법
├── 해시 범위 확인: 전체 vs 부분 검증
├── 매직 바이트 위조: struct.pack 활용
├── 길이 익스텐션 공격: SHA 계열 취약점
└── 타임스탬프 조작: 버전 다운그레이드
```

실제 CVE 참조 사례:
- CVE-2017-14491 (dnsmasq): 펌웨어 내 버퍼 오버플로
- CVE-2019-16920 (D-Link): 인증 우회 후 RCE
- CVE-2021-20090 (Arcadyan): 경로 탐색으로 설정 파일 접근

## 심화 도전

1. **펌웨어 에뮬레이션**: QEMU + buildroot로 펌웨어를 에뮬레이트하고 동적 분석 수행
2. **부트로더 잠금 해제**: U-Boot 환경 변수 조작으로 시리얼 콘솔 접근
3. **JTAG/UART 인터페이스**: 하드웨어 디버깅 포트 식별 및 접근
4. **OTA 업데이트 가로채기**: MITM으로 펌웨어 업데이트 트래픽 캡처 및 조작

---

<a name="english"></a>

# Firmware CTF Lab

## Lab Overview

Learn firmware security vulnerabilities in CTF format. Practice real-world embedded device attack techniques including firmware image analysis, hidden credential extraction, filesystem unpacking, and update signature bypass.

## Lab Environment Setup

```bash
# Install required tools
sudo apt-get install binwalk squashfs-tools foremost strings file

# Python packages
pip install pycryptodome

# Run CTF tool
python3 firmware_ctf.py --help
```

```python
#!/usr/bin/env python3
"""Firmware CTF lab tool — firmware_ctf.py"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FirmwareChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


@dataclass
class BinwalkEntry:
    offset: int
    description: str
    extracted_path: str | None = None


def verify_flag(submitted: str, challenge: FirmwareChallenge) -> bool:
    """Verify submitted flag."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, FirmwareChallenge] = {
    "cred_extract": FirmwareChallenge(
        name="Hidden Credential Extraction",
        category="Firmware Analysis",
        points=100,
        description="""
Admin credentials are hidden inside the firmware image 'router_fw_v2.3.bin'.
Use binwalk to analyze the image, unpack the filesystem,
and extract credentials from /etc/passwd or /etc/shadow.

Hint file location: firmware_samples/router_fw_v2.3.bin
Goal: Crack the admin account's MD5 hash and submit in flag format
""",
        flag="CTF{4dm1n_p4ssw0rd_3xtr4ct3d}",
        hints=[
            "Use 'binwalk -e router_fw_v2.3.bin' for automatic extraction",
            "Use 'strings' command to search for text in binaries",
            "Use 'john --format=md5crypt shadow' to crack hashes",
        ],
    ),
    "hardcoded_key": FirmwareChallenge(
        name="Hardcoded Secret Key Discovery",
        category="Firmware Analysis",
        points=150,
        description="""
An AES key is hardcoded in the IoT device firmware.
Use strings and grep to analyze the binary and find the 32-byte hex key.
Use the discovered key to decrypt the encrypted config file 'config.enc'
to reveal the flag.

Encryption: AES-256-CBC
IV: First 16 bytes stored in file header
""",
        flag="CTF{h4rdc0d3d_k3y_f0und_4nd_d3crypt3d}",
        hints=[
            "strings firmware.bin | grep -E '[0-9a-fA-F]{64}'",
            "grep -r 'AES|KEY|SECRET' in the extracted filesystem",
            "Python pycryptodome: AES.new(key, AES.MODE_CBC, iv)",
        ],
    ),
    "squashfs_flag": FirmwareChallenge(
        name="SquashFS Filesystem Flag Extraction",
        category="Firmware Analysis",
        points=200,
        description="""
There is a SquashFS filesystem inside the firmware image.
Mount or unpack the filesystem to find the hidden flag file.
The flag is hidden in an unusual location —
file permissions or timestamps may provide clues.

Target: squashfs_root.img
""",
        flag="CTF{squ4shfs_fl4g_unp4ck3d}",
        hints=[
            "unsquashfs squashfs_root.img",
            "find squashfs-root/ -name '*.flag' -o -name '.hidden*'",
            "Use 'ls -la --time-style=full-iso' to check timestamps",
        ],
    ),
    "signature_bypass": FirmwareChallenge(
        name="Firmware Update Signature Bypass",
        category="Firmware Security",
        points=300,
        description="""
The router's firmware update verification logic is vulnerable.
Update file format:
  [4-byte magic: 0xDEADBEEF] [4-byte size] [SHA256 hash 32 bytes] [payload]

The verification code only hashes the first 256 bytes, not the full file.
Create a malicious update file that bypasses verification.
Update server: http://localhost:9000/update
""",
        flag="CTF{f1rmw4r3_s1gn4tur3_byp4ss3d}",
        hints=[
            "Use struct.pack('>I', 0xDEADBEEF) to generate magic bytes",
            "Verification checks only payload[:256] — the rest can be freely modified",
            "Generate a valid hash with hashlib.sha256(payload[:256]).digest()",
        ],
    ),
}
```

## Challenge 1: Hidden Credential Extraction

```python
#!/usr/bin/env python3
"""Automate binwalk result parsing and credential extraction."""

import argparse
import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractedCredential:
    username: str
    password_hash: str
    hash_type: str
    cracked: str | None = None


def run_binwalk(firmware_path: Path, extract: bool = False) -> list[str]:
    """Run binwalk and parse output."""
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(str(firmware_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout.splitlines()
    except FileNotFoundError:
        print("[!] binwalk not installed. Using simulation mode")
        return simulate_binwalk_output()


def simulate_binwalk_output() -> list[str]:
    """Simulated binwalk output for CTF practice."""
    return [
        "DECIMAL       HEXADECIMAL     DESCRIPTION",
        "--------------------------------------------------------------------------------",
        "0             0x0             DLOB firmware header, boot partition: 'fs-uImage'",
        "112           0x70            LZMA compressed data, ...",
        "1048576       0x100000        Squashfs filesystem, little endian, version 4.0",
        "               compression:lzo, size: 4194304 bytes",
        "5242880       0x500000        JFFS2 filesystem, little endian",
    ]


def parse_shadow_file(shadow_content: str) -> list[ExtractedCredential]:
    """Parse credentials from shadow file."""
    credentials: list[ExtractedCredential] = []
    for line in shadow_content.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 2 or parts[1] in ("*", "!", "x", ""):
            continue
        username = parts[0]
        pw_hash = parts[1]

        if pw_hash.startswith("$1$"):
            hash_type = "MD5"
        elif pw_hash.startswith("$5$"):
            hash_type = "SHA-256"
        elif pw_hash.startswith("$6$"):
            hash_type = "SHA-512"
        elif re.match(r"^[0-9a-fA-F]{32}$", pw_hash):
            hash_type = "MD5 (raw)"
        else:
            hash_type = "Unknown"

        credentials.append(ExtractedCredential(
            username=username,
            password_hash=pw_hash,
            hash_type=hash_type,
        ))
    return credentials


def search_hardcoded_secrets(directory: Path) -> dict[str, list[str]]:
    """Search extracted filesystem for hardcoded secrets."""
    patterns: dict[str, str] = {
        "passwords": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(\S+)",
        "api_keys": r"(?i)(api.?key|apikey|api_secret)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{16,})",
        "hex_keys": r"[0-9a-fA-F]{32,64}",
        "private_keys": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    }

    findings: dict[str, list[str]] = {k: [] for k in patterns}

    if not directory.exists():
        findings["passwords"] = ["admin:admin123", "root:toor", "guest:guest"]
        findings["hex_keys"] = ["aabbccdd" * 8, "deadbeef" * 8]
        return findings

    for fpath in directory.rglob("*"):
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_text(errors="ignore")
            for key, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    for m in matches:
                        entry = f"{fpath}: {m if isinstance(m, str) else m[0]}"
                        findings[key].append(entry)
        except (PermissionError, OSError):
            continue

    return findings


def crack_md5_hash(password_hash: str, wordlist: list[str]) -> str | None:
    """Simple dictionary attack to crack MD5 hash."""
    import crypt  # noqa: PLC0415
    for word in wordlist:
        try:
            computed = crypt.crypt(word, password_hash)
            if computed == password_hash:
                return word
        except Exception:
            simple_hash = hashlib.md5(word.encode()).hexdigest()
            if simple_hash == password_hash:
                return word
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Firmware CTF automation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze firmware image")
    analyze_p.add_argument("firmware", type=Path, help="Firmware binary path")
    analyze_p.add_argument("-e", "--extract", action="store_true", help="Auto-extract")

    cred_p = sub.add_parser("creds", help="Parse credential files")
    cred_p.add_argument("shadow_file", type=Path, nargs="?", help="Shadow file path")
    cred_p.add_argument("--wordlist", type=Path, help="Dictionary file")

    secret_p = sub.add_parser("secrets", help="Search for hardcoded secrets")
    secret_p.add_argument("directory", type=Path, nargs="?", default=Path("."))

    sub.add_parser("list", help="List CTF challenges")

    submit_p = sub.add_parser("submit", help="Submit flag")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "analyze":
        print(f"[*] Analyzing {args.firmware}...")
        lines = run_binwalk(args.firmware, args.extract)
        for line in lines:
            print(line)

    elif args.cmd == "creds":
        if args.shadow_file and args.shadow_file.exists():
            content = args.shadow_file.read_text()
        else:
            content = (
                "root:$1$abc$XypRS.zGAzFiM5JA/B.Aq1:19000:0:99999:7:::\n"
                "admin:$1$def$mR5TLUFzIPPFMXhz4sKuD.:19001:0:99999:7:::\n"
                "guest:*:19000:0:99999:7:::\n"
            )
            print("[!] No shadow file specified. Using simulation data")

        creds = parse_shadow_file(content)
        print(f"\n[*] Found {len(creds)} credentials:\n")
        wordlist = ["admin", "admin123", "password", "toor", "root", "1234"]
        if args.wordlist and args.wordlist.exists():
            wordlist = args.wordlist.read_text().splitlines()

        for cred in creds:
            print(f"  User:    {cred.username}")
            print(f"  Hash:    {cred.password_hash[:32]}...")
            print(f"  Type:    {cred.hash_type}")
            cracked = crack_md5_hash(cred.password_hash, wordlist)
            if cracked:
                print(f"  Cracked: {cracked}  <-- SUCCESS!")
            print()

    elif args.cmd == "secrets":
        print(f"[*] Searching {args.directory} for secrets...")
        findings = search_hardcoded_secrets(args.directory)
        for category, items in findings.items():
            if items:
                print(f"\n[+] {category} ({len(items)} found):")
                for item in items[:5]:
                    print(f"  {item}")
                if len(items) > 5:
                    print(f"  ... and {len(items) - 5} more")

    elif args.cmd == "list":
        print("Firmware CTF Challenge List:\n")
        for cid, ch in CHALLENGES.items():
            print(f"  [{ch.points}pt] {ch.name}  (ID: {cid})")
            print(f"         Category: {ch.category}")
            desc_first = ch.description.strip().splitlines()[0]
            print(f"         {desc_first}")
            print()

    elif args.cmd == "submit":
        ch = CHALLENGES[args.challenge_id]
        if verify_flag(args.flag, ch):
            print(f"[+] Correct! {ch.points} points earned")
            print(f"    {ch.name} challenge cleared!")
        else:
            print("[-] Wrong answer. Hints:")
            for i, hint in enumerate(ch.hints, 1):
                print(f"    {i}. {hint}")


if __name__ == "__main__":
    main()
```

## Challenge 3: Firmware Update Signature Bypass

```python
#!/usr/bin/env python3
"""Firmware update packet crafting and signature bypass."""

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path


MAGIC = 0xDEADBEEF
UPDATE_FLAG = b"CTF{f1rmw4r3_s1gn4tur3_byp4ss3d}"


@dataclass
class FirmwareUpdatePacket:
    magic: int
    payload_size: int
    signature: bytes
    payload: bytes

    def to_bytes(self) -> bytes:
        header = struct.pack(">II", self.magic, self.payload_size)
        return header + self.signature + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "FirmwareUpdatePacket":
        if len(data) < 40:
            raise ValueError("Packet too short")
        magic, size = struct.unpack(">II", data[:8])
        sig = data[8:40]
        payload = data[40:]
        return cls(magic=magic, payload_size=size, signature=sig, payload=payload)


def create_malicious_update(payload_suffix: bytes = b"\x00") -> bytes:
    """
    Create a malicious update packet that bypasses vulnerable verification.
    Server only hashes payload[:256], so anything after is freely modifiable.
    """
    legitimate_header = b"FIRMWARE_UPDATE_v2.3" + b"\x00" * (256 - 20)
    full_payload = legitimate_header + UPDATE_FLAG + payload_suffix
    signature = hashlib.sha256(full_payload[:256]).digest()
    packet = FirmwareUpdatePacket(
        magic=MAGIC,
        payload_size=len(full_payload),
        signature=signature,
        payload=full_payload,
    )
    return packet.to_bytes()


def verify_update_packet(data: bytes, strict: bool = False) -> dict[str, object]:
    """
    Simulate firmware update verification.
    strict=False: vulnerable implementation (checks only first 256 bytes)
    strict=True:  correct implementation (checks entire payload)
    """
    result: dict[str, object] = {"valid": False, "reason": ""}

    try:
        pkt = FirmwareUpdatePacket.from_bytes(data)
    except ValueError as e:
        result["reason"] = str(e)
        return result

    if pkt.magic != MAGIC:
        result["reason"] = f"Magic mismatch: 0x{pkt.magic:08X}"
        return result

    verify_data = pkt.payload if strict else pkt.payload[:256]
    expected_sig = hashlib.sha256(verify_data).digest()

    if pkt.signature != expected_sig:
        result["reason"] = "Signature mismatch"
        return result

    result["valid"] = True
    result["reason"] = "Verification passed"
    result["payload_size"] = pkt.payload_size

    if b"CTF{" in pkt.payload:
        idx = pkt.payload.index(b"CTF{")
        end = pkt.payload.index(b"}", idx) + 1
        result["flag"] = pkt.payload[idx:end].decode()

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Firmware update signature bypass tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("exploit", help="Generate bypass update packet")

    verify_p = sub.add_parser("verify", help="Verify update packet")
    verify_p.add_argument("packet_file", type=Path)
    verify_p.add_argument("--strict", action="store_true", help="Strict verification")

    sub.add_parser("demo", help="Demonstrate full attack flow")

    args = parser.parse_args()

    if args.cmd == "exploit":
        packet_bytes = create_malicious_update()
        out = Path("malicious_update.bin")
        out.write_bytes(packet_bytes)
        print(f"[+] Malicious update packet created: {out} ({len(packet_bytes)} bytes)")
        print(f"    Magic: 0x{MAGIC:08X}")
        print(f"    Signature: SHA-256(payload[:256])")
        print(f"    Malicious payload: inserted after byte 256")

    elif args.cmd == "verify":
        data = args.packet_file.read_bytes()
        result = verify_update_packet(data, args.strict)
        mode = "Strict" if args.strict else "Vulnerable (default)"
        print(f"[*] Verification mode: {mode}")
        print(f"[{'+'if result['valid'] else '!'}] {result['reason']}")
        if "flag" in result:
            print(f"[FLAG] {result['flag']}")

    elif args.cmd == "demo":
        print("[*] Firmware signature bypass attack demo\n")
        print("1) Creating malicious packet...")
        packet_bytes = create_malicious_update()
        print(f"   Size: {len(packet_bytes)} bytes\n")

        print("2) Vulnerable verification (first 256 bytes only)...")
        res = verify_update_packet(packet_bytes, strict=False)
        print(f"   Result: {'PASS' if res['valid'] else 'FAIL'}")
        if "flag" in res:
            print(f"   Flag: {res['flag']}\n")

        print("3) Correct verification (full payload)...")
        res2 = verify_update_packet(packet_bytes, strict=True)
        print(f"   Result: {'PASS' if res2['valid'] else 'FAIL'} — {res2['reason']}")


if __name__ == "__main__":
    main()
```

## CTF Solving Guide

```
Firmware Analysis Flow
├── Step 1: Use 'file' command to identify image type
├── Step 2: Use 'binwalk -e' for automatic extraction
├── Step 3: Use 'strings + grep' to search for credentials/keys
├── Step 4: Use 'unsquashfs' to unpack filesystem
└── Step 5: Use 'find / grep' to locate flag files

Credential Extraction Checklist
├── Check /etc/passwd, /etc/shadow
├── Check /etc/config/ configuration files
├── Web server configs (httpd.conf, nginx.conf)
├── Hardcoded values in script files
└── Environment variable files (.env, .profile)

Signature Bypass Approaches
├── Check hash scope: full vs partial verification
├── Forge magic bytes: use struct.pack
├── Length extension attack: SHA family vulnerability
└── Timestamp manipulation: version downgrade
```

Real-world CVE references:
- CVE-2017-14491 (dnsmasq): Buffer overflow in firmware
- CVE-2019-16920 (D-Link): Auth bypass leading to RCE
- CVE-2021-20090 (Arcadyan): Path traversal to config file access

## Advanced Challenges

1. **Firmware Emulation**: Emulate firmware with QEMU + buildroot for dynamic analysis
2. **Bootloader Unlock**: Manipulate U-Boot environment variables to access serial console
3. **JTAG/UART Interface**: Identify and access hardware debugging ports
4. **OTA Update Interception**: Capture and manipulate firmware update traffic via MITM
