> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 인텔리전스 CTF 실습 랩

## 랩 개요

위협 인텔리전스 플랫폼(TIP) 보안 분석을 CTF 형식으로 학습한다. MISP IOC 체인 추적, C2 서버 식별, YARA 룰 역공학, STIX/TAXII APT 그룹 TTP 매핑 등 실제 위협 인텔리전스 분석 기법을 실습한다.

## 실습 환경 설정

```bash
# 필수 패키지 설치
pip install yara-python stix2 taxii2-client pymisp requests

# CTF 도구 실행
python3 tip_ctf.py --help
```

```python
#!/usr/bin/env python3
"""위협 인텔리전스 CTF 실습 도구 — tip_ctf.py"""

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TIPChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


def verify_flag(submitted: str, challenge: TIPChallenge) -> bool:
    """제출 플래그 검증."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, TIPChallenge] = {
    "ioc_chain": TIPChallenge(
        name="MISP IOC 체인 추적",
        category="MISP/IOC",
        points=100,
        description="""
MISP 이벤트 덤프 파일(misp_export.json)에서 숨겨진 IOC 체인을 추적하라.
공격자는 도메인 → IP → 해시 → 이메일 순서로 IOC를 연결했다.
체인의 마지막 이메일 주소에서 플래그 형식의 로컬 파트를 추출하라.

IOC 연결 기준: 같은 태그(tag: 'ctf-chain') + 'related-event' 필드
목표: 이메일 local-part를 CTF{} 형식으로 제출
""",
        flag="CTF{1oc_ch41n_tr4ck3d}",
        hints=[
            "MISP 이벤트의 Attribute 중 type='email-src' 필터링",
            "related-event ID를 재귀적으로 추적",
            "최종 이메일의 '@' 앞부분이 플래그 내용",
        ],
    ),
    "c2_identify": TIPChallenge(
        name="C2 서버 식별 — WHOIS/DNS 분석",
        category="Threat Intelligence",
        points=150,
        description="""
악성 도메인 목록(suspicious_domains.txt)에서 실제 C2 서버를 식별하라.
다음 조건을 모두 만족하는 도메인이 C2다:
  1. 등록 기간이 30일 미만 (최근 등록)
  2. NS 레코드가 bulletproof 호스팅 제공자 중 하나
  3. WHOIS 정보가 Privacy Protected
  4. A 레코드가 ASN 44477, 209588, 62355 중 하나에 속함

식별한 도메인의 MD5 해시를 CTF{} 형식으로 제출
""",
        flag="CTF{c2_s3rv3r_1d3nt1f13d}",
        hints=[
            "도메인 나이 계산: datetime.now() - whois.creation_date",
            "bulletproof NS: ns1.njalla.no, ns2.njalla.no, cloudns.net",
            "hashlib.md5(domain.encode()).hexdigest() 로 해시 생성",
        ],
    ),
    "yara_reverse": TIPChallenge(
        name="YARA 룰 역공학",
        category="YARA",
        points=200,
        description="""
다음 YARA 룰을 분석하고, 룰의 모든 조건을 만족하는 파일을 생성하라.
생성된 파일이 YARA 룰에 매치되면 플래그가 반환된다.

rule ctf_challenge {
    meta:
        description = "CTF YARA Challenge"
    strings:
        $magic  = { 4D 5A 90 00 }      // PE 매직
        $marker = "CTF_YARA_MARKER"    // 마커 문자열
        $xor_key = { 41 42 43 44 }     // XOR 키 패턴
    condition:
        $magic at 0 and $marker and $xor_key
        and filesize < 1024
        and uint32(0x3C) == 0x40        // PE 헤더 오프셋
}
""",
        flag="CTF{y4r4_rul3_r3v3rs3d_4nd_m4tch3d}",
        hints=[
            "struct.pack('<I', 0x40) 로 오프셋 0x3C에 PE 헤더 위치 설정",
            "파일에 모든 $strings 포함, filesize < 1024 준수",
            "python3 tip_ctf.py yara-solve 로 자동 생성",
        ],
    ),
    "stix_ttp": TIPChallenge(
        name="STIX/TAXII APT TTP 매핑으로 플래그 획득",
        category="STIX/TAXII",
        points=300,
        description="""
STIX 2.1 번들 파일(apt_bundle.json)에서 특정 APT 그룹의 TTPs를 분석하라.
ATT&CK 기법 ID T1059.003, T1543.003, T1027.002 를 모두 사용하는
APT 그룹의 이름과 UUID를 찾아 조합하면 플래그가 나온다.

플래그 형식: CTF{<그룹명>_<UUID 앞 8자리>}
예시: CTF{APT99_deadbeef}
""",
        flag="CTF{APT_SHADOW_a1b2c3d4}",
        hints=[
            "STIX Relationship 객체: relationship_type='uses'",
            "Attack-Pattern의 external_references에서 ATT&CK ID 확인",
            "Intrusion-Set 객체의 name과 id 필드 추출",
        ],
    ),
}
```

## 챌린지 1: MISP IOC 파서 및 체인 추적

```python
#!/usr/bin/env python3
"""MISP 이벤트 파싱 및 IOC 체인 추적 도구."""

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MISPAttribute:
    attr_id: str
    attr_type: str
    value: str
    tags: list[str] = field(default_factory=list)
    event_id: str = ""
    related_events: list[str] = field(default_factory=list)


@dataclass
class MISPEvent:
    event_id: str
    info: str
    attributes: list[MISPAttribute] = field(default_factory=list)
    related_events: list[str] = field(default_factory=list)


def parse_misp_export(data: dict) -> list[MISPEvent]:
    """MISP JSON 내보내기 파싱."""
    events: list[MISPEvent] = []
    raw_events = data.get("response", data.get("Event", []))
    if isinstance(raw_events, dict):
        raw_events = [raw_events]

    for raw in raw_events:
        event_data = raw.get("Event", raw)
        event = MISPEvent(
            event_id=str(event_data.get("id", "")),
            info=event_data.get("info", ""),
            related_events=[
                str(r.get("id", "")) for r in event_data.get("RelatedEvent", [])
            ],
        )
        for attr in event_data.get("Attribute", []):
            tags = [t.get("name", "") for t in attr.get("Tag", [])]
            event.attributes.append(MISPAttribute(
                attr_id=str(attr.get("id", "")),
                attr_type=attr.get("type", ""),
                value=attr.get("value", ""),
                tags=tags,
                event_id=event.event_id,
                related_events=event.related_events,
            ))
        events.append(event)
    return events


def generate_sample_misp() -> dict:
    """CTF용 샘플 MISP 이벤트 생성."""
    return {
        "response": [
            {
                "Event": {
                    "id": "1001",
                    "info": "CTF Challenge - Initial Phishing",
                    "RelatedEvent": [{"id": "1002"}],
                    "Attribute": [
                        {
                            "id": "2001",
                            "type": "domain",
                            "value": "evil-phish.example.com",
                            "Tag": [{"name": "ctf-chain"}, {"name": "tlp:red"}],
                        },
                        {
                            "id": "2002",
                            "type": "ip-dst",
                            "value": "192.168.100.1",
                            "Tag": [{"name": "ctf-chain"}],
                        },
                    ],
                }
            },
            {
                "Event": {
                    "id": "1002",
                    "info": "CTF Challenge - C2 Infrastructure",
                    "RelatedEvent": [{"id": "1003"}],
                    "Attribute": [
                        {
                            "id": "2003",
                            "type": "md5",
                            "value": "d41d8cd98f00b204e9800998ecf8427e",
                            "Tag": [{"name": "ctf-chain"}],
                        },
                        {
                            "id": "2004",
                            "type": "sha256",
                            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            "Tag": [{"name": "ctf-chain"}],
                        },
                    ],
                }
            },
            {
                "Event": {
                    "id": "1003",
                    "info": "CTF Challenge - Attribution",
                    "RelatedEvent": [],
                    "Attribute": [
                        {
                            "id": "2005",
                            "type": "email-src",
                            "value": "1oc_ch41n_tr4ck3d@ctf.example.com",
                            "Tag": [{"name": "ctf-chain"}, {"name": "attribution"}],
                        },
                    ],
                }
            },
        ]
    }


def trace_ioc_chain(events: list[MISPEvent], chain_tag: str = "ctf-chain") -> list[MISPAttribute]:
    """IOC 체인 추적 — 'ctf-chain' 태그를 따라 연결된 IOC 수집."""
    chain: list[MISPAttribute] = []
    event_map = {e.event_id: e for e in events}
    visited: set[str] = set()

    def _trace(event_id: str) -> None:
        if event_id in visited:
            return
        visited.add(event_id)
        event = event_map.get(event_id)
        if not event:
            return
        for attr in event.attributes:
            if chain_tag in attr.tags:
                chain.append(attr)
        for rel_id in event.related_events:
            _trace(rel_id)

    # 시작점: 가장 낮은 ID의 이벤트
    if events:
        _trace(min(events, key=lambda e: int(e.event_id or 0)).event_id)
    return chain


def extract_flag_from_email(email: str) -> str | None:
    """이메일 로컬 파트에서 플래그 추출."""
    m = re.match(r"^([^@]+)@", email)
    if m:
        local = m.group(1)
        return f"CTF{{{local}}}"
    return None


def analyze_ioc_types(attributes: list[MISPAttribute]) -> dict[str, list[str]]:
    """IOC 유형별 분류."""
    by_type: dict[str, list[str]] = {}
    for attr in attributes:
        by_type.setdefault(attr.attr_type, []).append(attr.value)
    return by_type


def main_misp() -> None:
    parser = argparse.ArgumentParser(description="MISP IOC 체인 추적 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    parse_p = sub.add_parser("parse", help="MISP 이벤트 파싱")
    parse_p.add_argument("misp_file", type=Path, nargs="?")
    parse_p.add_argument("--tag", default="ctf-chain")

    sub.add_parser("solve", help="IOC 체인 자동 추적 시연")
    sub.add_parser("sample", help="샘플 MISP 이벤트 생성")

    args = parser.parse_args()

    if args.cmd == "sample":
        data = generate_sample_misp()
        out = Path("misp_export.json")
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"[+] 샘플 MISP 이벤트 생성: {out}")

    elif args.cmd == "parse":
        if args.misp_file and args.misp_file.exists():
            data = json.loads(args.misp_file.read_text())
        else:
            print("[!] 파일 없음. 샘플 데이터 사용")
            data = generate_sample_misp()

        events = parse_misp_export(data)
        chain = trace_ioc_chain(events, args.tag)
        by_type = analyze_ioc_types(chain)
        print(f"[*] IOC 체인 ({len(chain)}개):")
        for ioc_type, values in by_type.items():
            print(f"\n  [{ioc_type}]")
            for v in values:
                print(f"    {v}")

    elif args.cmd == "solve":
        data = generate_sample_misp()
        events = parse_misp_export(data)
        chain = trace_ioc_chain(events)
        print(f"[*] IOC 체인 추적 완료: {len(chain)}개 IOC\n")
        for attr in chain:
            if attr.attr_type == "email-src":
                flag = extract_flag_from_email(attr.value)
                print(f"[+] 이메일 발견: {attr.value}")
                print(f"[+] 플래그: {flag}")
                break


if __name__ == "__main__":
    main_misp()
```

## 챌린지 2: YARA 룰 검증기 및 파일 생성기

```python
#!/usr/bin/env python3
"""YARA 룰 역공학 — 룰 조건을 만족하는 파일 생성."""

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


CTF_YARA_RULE = r"""
rule ctf_challenge {
    meta:
        description = "CTF YARA Challenge"
    strings:
        $magic  = { 4D 5A 90 00 }
        $marker = "CTF_YARA_MARKER"
        $xor_key = { 41 42 43 44 }
    condition:
        $magic at 0 and $marker and $xor_key
        and filesize < 1024
        and uint32(0x3C) == 0x40
}
"""

FLAG_YARA = "CTF{y4r4_rul3_r3v3rs3d_4nd_m4tch3d}"


@dataclass
class YARARequirement:
    """분석된 YARA 룰 요구사항."""
    magic_bytes: bytes            # 오프셋 0
    pe_header_offset: int        # 오프셋 0x3C에 저장될 값
    required_strings: list[bytes]
    max_filesize: int


def parse_yara_requirements(rule_text: str) -> YARARequirement:
    """YARA 룰에서 요구사항 추출 (간이 파서)."""
    import re

    # 문자열 패턴 추출
    required_strings: list[bytes] = []

    # 헥스 패턴
    for hex_match in re.findall(r'\$\w+\s*=\s*\{([0-9A-Fa-f\s]+)\}', rule_text):
        hex_str = re.sub(r'\s+', '', hex_match)
        required_strings.append(bytes.fromhex(hex_str))

    # 텍스트 패턴
    for str_match in re.findall(r'\$\w+\s*=\s*"([^"]+)"', rule_text):
        required_strings.append(str_match.encode())

    # filesize 제한
    size_match = re.search(r'filesize\s*<\s*(\d+)', rule_text)
    max_size = int(size_match.group(1)) if size_match else 65536

    # uint32 오프셋 조건
    uint32_match = re.search(r'uint32\(0x([0-9A-Fa-f]+)\)\s*==\s*0x([0-9A-Fa-f]+)', rule_text)
    pe_offset_val = int(uint32_match.group(2), 16) if uint32_match else 0x40

    return YARARequirement(
        magic_bytes=bytes.fromhex("4D5A9000"),
        pe_header_offset=pe_offset_val,
        required_strings=required_strings,
        max_filesize=max_size,
    )


def build_yara_matching_file(req: YARARequirement) -> bytes:
    """YARA 룰 조건을 모두 만족하는 최소 파일 생성."""
    # 기본 버퍼 — filesize < 1024 만족
    buf = bytearray(512)

    # 조건 1: $magic at 0 — 첫 4바이트
    buf[0:4] = req.magic_bytes

    # 조건 2: uint32(0x3C) == 0x40 — PE 헤더 오프셋
    struct.pack_into("<I", buf, 0x3C, req.pe_header_offset)

    # 조건 3: 모든 $strings 포함
    insert_pos = 0x60  # PE 헤더 이후
    for s in req.required_strings:
        # $magic 은 이미 오프셋 0에 있으므로 중복 삽입 불필요
        if s == req.magic_bytes:
            continue
        buf[insert_pos:insert_pos + len(s)] = s
        insert_pos += len(s) + 1

    # 플래그도 포함 (YARA 매치 후 서버가 확인)
    flag_bytes = FLAG_YARA.encode()
    flag_pos = 0xC0
    buf[flag_pos:flag_pos + len(flag_bytes)] = flag_bytes

    return bytes(buf)


def verify_with_yara(file_bytes: bytes, rule_text: str) -> dict[str, object]:
    """YARA 룰로 파일 검증 (yara-python 없으면 수동 검증)."""
    try:
        import yara  # type: ignore[import]
        rule = yara.compile(source=rule_text)
        matches = rule.match(data=file_bytes)
        matched = bool(matches)
        rule_names = [m.rule for m in matches]
    except ImportError:
        # yara-python 미설치 — 수동 조건 검증
        matched = (
            file_bytes[:4] == bytes.fromhex("4D5A9000")
            and b"CTF_YARA_MARKER" in file_bytes
            and b"ABCD" in file_bytes         # { 41 42 43 44 }
            and len(file_bytes) < 1024
            and struct.unpack_from("<I", file_bytes, 0x3C)[0] == 0x40
        )
        rule_names = ["ctf_challenge"] if matched else []

    result: dict[str, object] = {
        "matched": matched,
        "rules": rule_names,
    }
    if matched and FLAG_YARA.encode() in file_bytes:
        result["flag"] = FLAG_YARA
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="YARA CTF 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("show-rule", help="CTF YARA 룰 출력")
    sub.add_parser("yara-solve", help="룰 조건 만족 파일 자동 생성 및 검증")

    verify_p = sub.add_parser("verify", help="파일이 YARA 룰에 매치되는지 검증")
    verify_p.add_argument("file", type=Path, help="검증할 파일")

    args = parser.parse_args()

    if args.cmd == "show-rule":
        print(CTF_YARA_RULE)

    elif args.cmd == "yara-solve":
        print("[*] YARA 룰 분석 중...\n")
        req = parse_yara_requirements(CTF_YARA_RULE)
        print(f"  매직 바이트: {req.magic_bytes.hex()}")
        print(f"  PE 오프셋 조건: uint32(0x3C) == 0x{req.pe_header_offset:02X}")
        print(f"  최대 파일 크기: {req.max_filesize} bytes")
        print(f"  필수 문자열: {len(req.required_strings)}개\n")

        file_bytes = build_yara_matching_file(req)
        out = Path("ctf_match.bin")
        out.write_bytes(file_bytes)
        print(f"[+] 파일 생성: {out} ({len(file_bytes)} bytes)")

        result = verify_with_yara(file_bytes, CTF_YARA_RULE)
        print(f"[{'+'if result['matched'] else '!'}] YARA 매치: {result['matched']}")
        if "flag" in result:
            print(f"[FLAG] {result['flag']}")

    elif args.cmd == "verify":
        file_bytes = args.file.read_bytes()
        result = verify_with_yara(file_bytes, CTF_YARA_RULE)
        print(f"[{'+'if result['matched'] else '!'}] 매치: {result['matched']}")
        if result.get("rules"):
            print(f"    룰: {', '.join(result['rules'])}")
        if "flag" in result:
            print(f"[FLAG] {result['flag']}")


if __name__ == "__main__":
    main()
```

## 챌린지 3: STIX 2.1 파서 및 APT TTP 매핑

```python
#!/usr/bin/env python3
"""STIX 2.1 번들 파싱 및 APT 그룹 TTP 매핑."""

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path


# ATT&CK 기법 ID (챌린지 타겟)
TARGET_TECHNIQUES = {"T1059.003", "T1543.003", "T1027.002"}

FLAG_STIX = "CTF{APT_SHADOW_a1b2c3d4}"


@dataclass
class STIXObject:
    stix_id: str
    stix_type: str
    properties: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.properties.get("name", "")

    def get_attack_ids(self) -> list[str]:
        """ATT&CK 기법 ID 추출."""
        refs = self.properties.get("external_references", [])
        return [
            r.get("external_id", "")
            for r in refs
            if r.get("source_name", "") == "mitre-attack"
        ]


def parse_stix_bundle(bundle_data: dict) -> list[STIXObject]:
    """STIX 2.1 번들 파싱."""
    objects: list[STIXObject] = []
    for obj in bundle_data.get("objects", []):
        stix_obj = STIXObject(
            stix_id=obj.get("id", ""),
            stix_type=obj.get("type", ""),
            properties={k: v for k, v in obj.items() if k not in ("id", "type")},
        )
        objects.append(stix_obj)
    return objects


def generate_sample_stix_bundle() -> dict:
    """CTF용 샘플 STIX 2.1 번들 생성."""
    return {
        "type": "bundle",
        "id": "bundle--ctf-001",
        "objects": [
            # APT 그룹 1 (타겟이 아님)
            {
                "type": "intrusion-set",
                "id": "intrusion-set--11111111-aaaa-bbbb-cccc-111111111111",
                "name": "APT_NOISE",
                "aliases": ["NoisyBear"],
            },
            # APT 그룹 2 (타겟)
            {
                "type": "intrusion-set",
                "id": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "name": "APT_SHADOW",
                "aliases": ["ShadowPanda", "DarkCobra"],
                "description": "Advanced persistent threat targeting critical infrastructure",
            },
            # 기법 1: T1059.003 (Windows Command Shell)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
                "name": "Windows Command Shell",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.003"}
                ],
            },
            # 기법 2: T1543.003 (Windows Service)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32",
                "name": "Windows Service",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1543.003"}
                ],
            },
            # 기법 3: T1027.002 (Software Packing)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--deb98323-e13f-4b0c-8d94-175379069062",
                "name": "Software Packing",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1027.002"}
                ],
            },
            # 노이즈 기법: T1078 (Valid Accounts)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
                "name": "Valid Accounts",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1078"}
                ],
            },
            # 관계: APT_NOISE uses T1078 (타겟 아님)
            {
                "type": "relationship",
                "id": "relationship--noise-001",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--11111111-aaaa-bbbb-cccc-111111111111",
                "target_ref": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
            },
            # 관계: APT_SHADOW uses T1059.003
            {
                "type": "relationship",
                "id": "relationship--shadow-001",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "target_ref": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
            },
            # 관계: APT_SHADOW uses T1543.003
            {
                "type": "relationship",
                "id": "relationship--shadow-002",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "target_ref": "attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32",
            },
            # 관계: APT_SHADOW uses T1027.002
            {
                "type": "relationship",
                "id": "relationship--shadow-003",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "target_ref": "attack-pattern--deb98323-e13f-4b0c-8d94-175379069062",
            },
        ],
    }


def find_apt_by_techniques(
    stix_objects: list[STIXObject],
    target_techniques: set[str],
) -> list[tuple[STIXObject, set[str]]]:
    """특정 ATT&CK 기법을 모두 사용하는 APT 그룹 탐색."""
    # 오브젝트 ID → 객체 맵
    obj_map = {o.stix_id: o for o in stix_objects}

    # ATT&CK ID → attack-pattern ID 맵
    technique_to_id: dict[str, str] = {}
    for obj in stix_objects:
        if obj.stix_type == "attack-pattern":
            for att_id in obj.get_attack_ids():
                technique_to_id[att_id] = obj.stix_id

    # intrusion-set → 사용 기법 집합
    group_techniques: dict[str, set[str]] = {}
    for obj in stix_objects:
        if obj.stix_type == "relationship":
            props = obj.properties
            if props.get("relationship_type") != "uses":
                continue
            src = props.get("source_ref", "")
            tgt = props.get("target_ref", "")
            src_obj = obj_map.get(src)
            tgt_obj = obj_map.get(tgt)
            if src_obj and tgt_obj and src_obj.stix_type == "intrusion-set":
                for att_id, ap_id in technique_to_id.items():
                    if ap_id == tgt:
                        group_techniques.setdefault(src, set()).add(att_id)

    # 타겟 기법 집합을 모두 포함하는 그룹 필터링
    results: list[tuple[STIXObject, set[str]]] = []
    for group_id, techniques in group_techniques.items():
        if target_techniques.issubset(techniques):
            group_obj = obj_map.get(group_id)
            if group_obj:
                results.append((group_obj, techniques))
    return results


def derive_flag_from_group(group: STIXObject) -> str:
    """그룹 이름과 UUID에서 플래그 유도."""
    name = group.name
    uuid_short = group.stix_id.split("--")[-1][:8]
    return f"CTF{{{name}_{uuid_short}}}"


def main() -> None:
    parser = argparse.ArgumentParser(description="STIX/TAXII TIP CTF 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    parse_p = sub.add_parser("parse", help="STIX 번들 파싱")
    parse_p.add_argument("bundle_file", type=Path, nargs="?")

    sub.add_parser("solve", help="APT TTP 매핑 자동 분석")
    sub.add_parser("sample", help="샘플 STIX 번들 생성")

    list_p = sub.add_parser("list", help="CTF 챌린지 목록")

    submit_p = sub.add_parser("submit", help="플래그 제출")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "sample":
        bundle = generate_sample_stix_bundle()
        out = Path("apt_bundle.json")
        out.write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
        print(f"[+] 샘플 STIX 번들 생성: {out}")
        print(f"    객체: {len(bundle['objects'])}개")

    elif args.cmd == "parse":
        if args.bundle_file and args.bundle_file.exists():
            bundle = json.loads(args.bundle_file.read_text())
        else:
            print("[!] 파일 없음. 샘플 데이터 사용")
            bundle = generate_sample_stix_bundle()
        stix_objs = parse_stix_bundle(bundle)
        print(f"[*] STIX 객체 {len(stix_objs)}개 파싱 완료")
        type_count: dict[str, int] = {}
        for o in stix_objs:
            type_count[o.stix_type] = type_count.get(o.stix_type, 0) + 1
        for t, c in sorted(type_count.items()):
            print(f"  {t}: {c}개")

    elif args.cmd == "solve":
        print(f"[*] APT TTP 매핑 분석\n")
        print(f"    타겟 기법: {', '.join(sorted(TARGET_TECHNIQUES))}\n")
        bundle = generate_sample_stix_bundle()
        stix_objs = parse_stix_bundle(bundle)
        matches = find_apt_by_techniques(stix_objs, TARGET_TECHNIQUES)
        if not matches:
            print("[!] 조건 만족 APT 그룹 없음")
        for group, techniques in matches:
            flag = derive_flag_from_group(group)
            print(f"[+] 발견: {group.name}")
            print(f"    ID: {group.stix_id}")
            print(f"    TTPs: {', '.join(sorted(techniques))}")
            print(f"    플래그: {flag}")

    elif args.cmd == "list":
        print("위협 인텔리전스 CTF 챌린지 목록:\n")
        for cid, ch in CHALLENGES.items():
            print(f"  [{ch.points}pt] {ch.name}  (ID: {cid})")
            print(f"         카테고리: {ch.category}")
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

## CTF 풀이 가이드

```
MISP IOC 체인 추적 전략
├── 태그 필터링: 'ctf-chain' 태그 속성만 수집
├── 이벤트 그래프: RelatedEvent 필드로 방향 그래프 구성
├── BFS/DFS 탐색: 시작 이벤트부터 연결 이벤트 순회
└── IOC 유형별 분류: domain → ip-dst → md5 → email-src 순서

C2 식별 체크리스트
├── 도메인 나이: whois.creation_date ± 30일 이내
├── 무결성 지표: WHOIS Privacy Protected 여부
├── 인프라 중복: 같은 ASN 내 다수 의심 도메인
└── 수동 분석: MX 없음 + 짧은 TTL (<300) = 의심

YARA 역공학 방법론
├── 1단계: 문자열 조건 추출 → 모두 포함
├── 2단계: 파일 시작/오프셋 조건 확인 (at 0, uint32())
├── 3단계: filesize 제한 준수
├── 4단계: 모듈 조건 (pe., elf.) → 헤더 구조 생성
└── 5단계: yara 명령으로 최종 검증

STIX/TAXII TTP 매핑
├── Relationship 객체: source(APT) → uses → target(attack-pattern)
├── ATT&CK ID: external_references에서 'mitre-attack' 소스
├── 교집합: 그룹별 기법 집합 ∩ 타겟 기법 집합
└── 플래그 유도: 그룹명 + UUID 앞 8자리 조합
```

## 심화 도전

1. **MISP 자동화**: PyMISP로 실제 MISP 인스턴스 API 연동, 자동 IOC 수집 및 상관관계 분석
2. **다이아몬드 모델**: 적대자/역량/인프라/피해자 4축으로 캠페인 구조화
3. **TAXII 서버 구축**: taxii2-server로 커스텀 위협 피드 게시, STIX 번들 자동 배포
4. **머신러닝 IOC 분류**: scikit-learn으로 도메인 생성 알고리즘(DGA) 탐지 모델 구현

---

<a name="english"></a>

# Threat Intelligence Platform CTF Lab

## Lab Overview

Learn Threat Intelligence Platform (TIP) security analysis in CTF format. Practice real-world threat intelligence analysis techniques including MISP IOC chain tracking, C2 server identification, YARA rule reverse engineering, and STIX/TAXII APT group TTP mapping.

## Lab Environment Setup

```bash
# Install required packages
pip install yara-python stix2 taxii2-client pymisp requests

# Run CTF tool
python3 tip_ctf.py --help
```

```python
#!/usr/bin/env python3
"""Threat Intelligence CTF lab tool — tip_ctf.py"""

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TIPChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


def verify_flag(submitted: str, challenge: TIPChallenge) -> bool:
    """Verify submitted flag."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, TIPChallenge] = {
    "ioc_chain": TIPChallenge(
        name="MISP IOC Chain Tracking",
        category="MISP/IOC",
        points=100,
        description="""
Track the hidden IOC chain in the MISP event dump file (misp_export.json).
The attacker linked IOCs in the order: domain → IP → hash → email.
Extract the flag-formatted local part from the final email address in the chain.

IOC linkage criterion: same tag ('ctf-chain') + 'related-event' field
Goal: Submit email local-part in CTF{} format
""",
        flag="CTF{1oc_ch41n_tr4ck3d}",
        hints=[
            "Filter MISP event Attributes where type='email-src'",
            "Recursively follow related-event IDs",
            "The part before '@' in the final email is the flag content",
        ],
    ),
    "c2_identify": TIPChallenge(
        name="C2 Server Identification — WHOIS/DNS Analysis",
        category="Threat Intelligence",
        points=150,
        description="""
Identify the real C2 server from the list of suspicious domains (suspicious_domains.txt).
The C2 domain satisfies all of the following:
  1. Registration age less than 30 days (recently registered)
  2. NS record belongs to a bulletproof hosting provider
  3. WHOIS information is Privacy Protected
  4. A record belongs to ASN 44477, 209588, or 62355

Submit the MD5 hash of the identified domain in CTF{} format
""",
        flag="CTF{c2_s3rv3r_1d3nt1f13d}",
        hints=[
            "Domain age: datetime.now() - whois.creation_date",
            "Bulletproof NS: ns1.njalla.no, ns2.njalla.no, cloudns.net",
            "hashlib.md5(domain.encode()).hexdigest() to generate hash",
        ],
    ),
    "yara_reverse": TIPChallenge(
        name="YARA Rule Reverse Engineering",
        category="YARA",
        points=200,
        description="""
Analyze the following YARA rule and create a file that satisfies all conditions.
The flag is returned when the generated file matches the YARA rule.

rule ctf_challenge {
    meta:
        description = "CTF YARA Challenge"
    strings:
        $magic  = { 4D 5A 90 00 }      // PE magic
        $marker = "CTF_YARA_MARKER"    // marker string
        $xor_key = { 41 42 43 44 }     // XOR key pattern
    condition:
        $magic at 0 and $marker and $xor_key
        and filesize < 1024
        and uint32(0x3C) == 0x40        // PE header offset
}
""",
        flag="CTF{y4r4_rul3_r3v3rs3d_4nd_m4tch3d}",
        hints=[
            "Use struct.pack('<I', 0x40) to set PE header position at offset 0x3C",
            "Include all $strings in the file, keep filesize < 1024",
            "Use 'python3 tip_ctf.py yara-solve' for automatic generation",
        ],
    ),
    "stix_ttp": TIPChallenge(
        name="STIX/TAXII APT TTP Mapping for Flag",
        category="STIX/TAXII",
        points=300,
        description="""
Analyze the TTPs of a specific APT group in the STIX 2.1 bundle file (apt_bundle.json).
Find the APT group that uses all three ATT&CK technique IDs:
T1059.003, T1543.003, and T1027.002.
Combine the group's name and UUID to form the flag.

Flag format: CTF{<group_name>_<first 8 chars of UUID>}
Example: CTF{APT99_deadbeef}
""",
        flag="CTF{APT_SHADOW_a1b2c3d4}",
        hints=[
            "STIX Relationship object: relationship_type='uses'",
            "Check ATT&CK ID in attack-pattern's external_references",
            "Extract name and id fields from Intrusion-Set object",
        ],
    ),
}
```

## Challenge 1: MISP IOC Parser and Chain Tracker

```python
#!/usr/bin/env python3
"""MISP event parsing and IOC chain tracking tool."""

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MISPAttribute:
    attr_id: str
    attr_type: str
    value: str
    tags: list[str] = field(default_factory=list)
    event_id: str = ""
    related_events: list[str] = field(default_factory=list)


@dataclass
class MISPEvent:
    event_id: str
    info: str
    attributes: list[MISPAttribute] = field(default_factory=list)
    related_events: list[str] = field(default_factory=list)


def parse_misp_export(data: dict) -> list[MISPEvent]:
    """Parse MISP JSON export."""
    events: list[MISPEvent] = []
    raw_events = data.get("response", data.get("Event", []))
    if isinstance(raw_events, dict):
        raw_events = [raw_events]

    for raw in raw_events:
        event_data = raw.get("Event", raw)
        event = MISPEvent(
            event_id=str(event_data.get("id", "")),
            info=event_data.get("info", ""),
            related_events=[
                str(r.get("id", "")) for r in event_data.get("RelatedEvent", [])
            ],
        )
        for attr in event_data.get("Attribute", []):
            tags = [t.get("name", "") for t in attr.get("Tag", [])]
            event.attributes.append(MISPAttribute(
                attr_id=str(attr.get("id", "")),
                attr_type=attr.get("type", ""),
                value=attr.get("value", ""),
                tags=tags,
                event_id=event.event_id,
                related_events=event.related_events,
            ))
        events.append(event)
    return events


def generate_sample_misp() -> dict:
    """Generate sample MISP event for CTF."""
    return {
        "response": [
            {
                "Event": {
                    "id": "1001",
                    "info": "CTF Challenge - Initial Phishing",
                    "RelatedEvent": [{"id": "1002"}],
                    "Attribute": [
                        {
                            "id": "2001",
                            "type": "domain",
                            "value": "evil-phish.example.com",
                            "Tag": [{"name": "ctf-chain"}, {"name": "tlp:red"}],
                        },
                        {
                            "id": "2002",
                            "type": "ip-dst",
                            "value": "192.168.100.1",
                            "Tag": [{"name": "ctf-chain"}],
                        },
                    ],
                }
            },
            {
                "Event": {
                    "id": "1002",
                    "info": "CTF Challenge - C2 Infrastructure",
                    "RelatedEvent": [{"id": "1003"}],
                    "Attribute": [
                        {
                            "id": "2003",
                            "type": "md5",
                            "value": "d41d8cd98f00b204e9800998ecf8427e",
                            "Tag": [{"name": "ctf-chain"}],
                        },
                    ],
                }
            },
            {
                "Event": {
                    "id": "1003",
                    "info": "CTF Challenge - Attribution",
                    "RelatedEvent": [],
                    "Attribute": [
                        {
                            "id": "2005",
                            "type": "email-src",
                            "value": "1oc_ch41n_tr4ck3d@ctf.example.com",
                            "Tag": [{"name": "ctf-chain"}, {"name": "attribution"}],
                        },
                    ],
                }
            },
        ]
    }


def trace_ioc_chain(events: list[MISPEvent], chain_tag: str = "ctf-chain") -> list[MISPAttribute]:
    """Trace IOC chain — collect IOCs connected by 'ctf-chain' tag."""
    chain: list[MISPAttribute] = []
    event_map = {e.event_id: e for e in events}
    visited: set[str] = set()

    def _trace(event_id: str) -> None:
        if event_id in visited:
            return
        visited.add(event_id)
        event = event_map.get(event_id)
        if not event:
            return
        for attr in event.attributes:
            if chain_tag in attr.tags:
                chain.append(attr)
        for rel_id in event.related_events:
            _trace(rel_id)

    if events:
        _trace(min(events, key=lambda e: int(e.event_id or 0)).event_id)
    return chain


def extract_flag_from_email(email: str) -> str | None:
    """Extract flag from email local part."""
    m = re.match(r"^([^@]+)@", email)
    return f"CTF{{{m.group(1)}}}" if m else None


def main() -> None:
    parser = argparse.ArgumentParser(description="MISP IOC Chain Tracking Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("solve", help="Automatic IOC chain tracking demo")
    sub.add_parser("sample", help="Generate sample MISP event")

    args = parser.parse_args()

    if args.cmd == "sample":
        data = generate_sample_misp()
        out = Path("misp_export.json")
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"[+] Sample MISP event created: {out}")

    elif args.cmd == "solve":
        data = generate_sample_misp()
        events = parse_misp_export(data)
        chain = trace_ioc_chain(events)
        print(f"[*] IOC chain traced: {len(chain)} IOCs\n")
        for attr in chain:
            if attr.attr_type == "email-src":
                flag = extract_flag_from_email(attr.value)
                print(f"[+] Email found: {attr.value}")
                print(f"[+] Flag: {flag}")
                break


if __name__ == "__main__":
    main()
```

## Challenge 2: STIX 2.1 Parser and APT TTP Mapping

```python
#!/usr/bin/env python3
"""STIX 2.1 bundle parsing and APT group TTP mapping."""

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path


TARGET_TECHNIQUES = {"T1059.003", "T1543.003", "T1027.002"}
FLAG_STIX = "CTF{APT_SHADOW_a1b2c3d4}"


@dataclass
class STIXObject:
    stix_id: str
    stix_type: str
    properties: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.properties.get("name", "")

    def get_attack_ids(self) -> list[str]:
        refs = self.properties.get("external_references", [])
        return [
            r.get("external_id", "")
            for r in refs
            if r.get("source_name", "") == "mitre-attack"
        ]


def parse_stix_bundle(bundle_data: dict) -> list[STIXObject]:
    """Parse STIX 2.1 bundle."""
    objects: list[STIXObject] = []
    for obj in bundle_data.get("objects", []):
        stix_obj = STIXObject(
            stix_id=obj.get("id", ""),
            stix_type=obj.get("type", ""),
            properties={k: v for k, v in obj.items() if k not in ("id", "type")},
        )
        objects.append(stix_obj)
    return objects


def generate_sample_stix_bundle() -> dict:
    """Generate sample STIX 2.1 bundle for CTF."""
    return {
        "type": "bundle",
        "id": "bundle--ctf-001",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--11111111-aaaa-bbbb-cccc-111111111111",
                "name": "APT_NOISE",
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "name": "APT_SHADOW",
                "description": "Advanced persistent threat targeting critical infrastructure",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
                "name": "Windows Command Shell",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.003"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32",
                "name": "Windows Service",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1543.003"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--deb98323-e13f-4b0c-8d94-175379069062",
                "name": "Software Packing",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1027.002"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
                "name": "Valid Accounts",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1078"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--noise-001",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--11111111-aaaa-bbbb-cccc-111111111111",
                "target_ref": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
            },
            {
                "type": "relationship",
                "id": "relationship--shadow-001",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "target_ref": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
            },
            {
                "type": "relationship",
                "id": "relationship--shadow-002",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "target_ref": "attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32",
            },
            {
                "type": "relationship",
                "id": "relationship--shadow-003",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--a1b2c3d4-0000-0000-0000-000000000000",
                "target_ref": "attack-pattern--deb98323-e13f-4b0c-8d94-175379069062",
            },
        ],
    }


def find_apt_by_techniques(
    stix_objects: list[STIXObject],
    target_techniques: set[str],
) -> list[tuple[STIXObject, set[str]]]:
    """Find APT groups that use all specified ATT&CK techniques."""
    obj_map = {o.stix_id: o for o in stix_objects}

    technique_to_id: dict[str, str] = {}
    for obj in stix_objects:
        if obj.stix_type == "attack-pattern":
            for att_id in obj.get_attack_ids():
                technique_to_id[att_id] = obj.stix_id

    group_techniques: dict[str, set[str]] = {}
    for obj in stix_objects:
        if obj.stix_type == "relationship":
            props = obj.properties
            if props.get("relationship_type") != "uses":
                continue
            src = props.get("source_ref", "")
            tgt = props.get("target_ref", "")
            src_obj = obj_map.get(src)
            if src_obj and src_obj.stix_type == "intrusion-set":
                for att_id, ap_id in technique_to_id.items():
                    if ap_id == tgt:
                        group_techniques.setdefault(src, set()).add(att_id)

    results: list[tuple[STIXObject, set[str]]] = []
    for group_id, techniques in group_techniques.items():
        if target_techniques.issubset(techniques):
            group_obj = obj_map.get(group_id)
            if group_obj:
                results.append((group_obj, techniques))
    return results


def derive_flag_from_group(group: STIXObject) -> str:
    """Derive flag from group name and UUID."""
    name = group.name
    uuid_short = group.stix_id.split("--")[-1][:8]
    return f"CTF{{{name}_{uuid_short}}}"


def main() -> None:
    parser = argparse.ArgumentParser(description="STIX/TAXII TIP CTF Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("solve", help="Automatic APT TTP mapping analysis")
    sub.add_parser("sample", help="Generate sample STIX bundle")
    sub.add_parser("list", help="List CTF challenges")

    submit_p = sub.add_parser("submit", help="Submit flag")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "sample":
        bundle = generate_sample_stix_bundle()
        out = Path("apt_bundle.json")
        out.write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
        print(f"[+] Sample STIX bundle created: {out}")

    elif args.cmd == "solve":
        print(f"[*] APT TTP mapping analysis\n")
        print(f"    Target techniques: {', '.join(sorted(TARGET_TECHNIQUES))}\n")
        bundle = generate_sample_stix_bundle()
        stix_objs = parse_stix_bundle(bundle)
        matches = find_apt_by_techniques(stix_objs, TARGET_TECHNIQUES)
        if not matches:
            print("[!] No APT group found matching all conditions")
        for group, techniques in matches:
            flag = derive_flag_from_group(group)
            print(f"[+] Found: {group.name}")
            print(f"    ID: {group.stix_id}")
            print(f"    TTPs: {', '.join(sorted(techniques))}")
            print(f"    Flag: {flag}")

    elif args.cmd == "list":
        print("Threat Intelligence CTF Challenge List:\n")
        for cid, ch in CHALLENGES.items():
            print(f"  [{ch.points}pt] {ch.name}  (ID: {cid})")
            print(f"         Category: {ch.category}")
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

## CTF Solving Guide

```
MISP IOC Chain Tracking Strategy
├── Tag filtering: collect only attributes with 'ctf-chain' tag
├── Event graph: build directed graph from RelatedEvent fields
├── BFS/DFS traversal: walk from start event to connected events
└── IOC type classification: domain → ip-dst → md5 → email-src order

C2 Identification Checklist
├── Domain age: whois.creation_date within ±30 days
├── Integrity indicators: WHOIS Privacy Protected status
├── Infrastructure overlap: many suspicious domains in same ASN
└── Manual analysis: no MX record + short TTL (<300) = suspicious

YARA Reverse Engineering Methodology
├── Step 1: Extract string conditions → include all
├── Step 2: Check file start/offset conditions (at 0, uint32())
├── Step 3: Respect filesize limit
├── Step 4: Module conditions (pe., elf.) → build header structure
└── Step 5: Final validation with yara command

STIX/TAXII TTP Mapping
├── Relationship objects: source(APT) → uses → target(attack-pattern)
├── ATT&CK ID: from 'mitre-attack' source in external_references
├── Intersection: group technique set ∩ target technique set
└── Flag derivation: group name + first 8 chars of UUID
```

## Advanced Challenges

1. **MISP Automation**: Integrate with a live MISP instance via PyMISP API for automated IOC collection and correlation analysis
2. **Diamond Model**: Structure campaigns across 4 axes: adversary, capability, infrastructure, victim
3. **TAXII Server Setup**: Publish custom threat feeds with taxii2-server, auto-distribute STIX bundles
4. **ML IOC Classification**: Implement a DGA (Domain Generation Algorithm) detection model with scikit-learn
