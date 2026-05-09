# 자동화 위협 헌팅

## 1. 헌팅 자동화 플랫폼

### 1.1 OpenCTI

OpenCTI(Open Cyber Threat Intelligence)는 위협 인텔리전스 데이터를 저장, 구조화, 시각화, 공유하는 오픈소스 플랫폼이다. STIX 2.1 표준을 기반으로 하며 ATT&CK, MISP, TheHive 등과 통합된다.

**설치 (Docker Compose)**:
```bash
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker
cp .env.sample .env
# .env 파일에서 비밀번호, UUID 설정 후:
docker compose up -d
```

**핵심 기능**:
- **지식 그래프**: 위협 행위자, 캠페인, 악성코드, 취약점 간 관계 시각화
- **TTP 매핑**: MITRE ATT&CK 자동 매핑
- **피드 통합**: MISP, AlienVault OTX, Shodan, VirusTotal 커넥터
- **알림 규칙**: 새 IOC/TTP 발견 시 자동 알림
- **Playbook**: 트리거 기반 자동 대응 액션

**API 활용 예시 (Python)**:
```python
import requests

OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = "your_api_token"

headers = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type": "application/json",
}

# 위협 행위자 조회
query = """
{
  threatActors {
    edges {
      node {
        name
        description
        sophistication
        country { name }
      }
    }
  }
}
"""
resp = requests.post(f"{OPENCTI_URL}/graphql", json={"query": query}, headers=headers, timeout=30)
data = resp.json()
```

### 1.2 MISP (Malware Information Sharing Platform)

MISP는 위협 인텔리전스 공유에 특화된 오픈소스 플랫폼이다. IOC, 악성코드 샘플, TTP를 구조화하여 커뮤니티와 공유한다.

**설치**:
```bash
# Ubuntu 20.04 기준
curl -s https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh | bash
```

**핵심 기능**:
- **이벤트(Event)**: 보안 사고/캠페인 단위의 인텔리전스 묶음
- **속성(Attribute)**: IP, 도메인, 해시, 이메일 등 IOC
- **오브젝트(Object)**: 복잡한 개체 표현 (파일, 네트워크 연결 등)
- **피드(Feed)**: 외부 소스에서 자동 IOC 수집
- **공유 그룹**: 신뢰 그룹 간 정보 공유 제어

**PyMISP 활용**:
```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP("https://misp.example.com", "your_api_key", ssl=True)

# 새 이벤트 생성
event = MISPEvent()
event.info = "APT28 피싱 캠페인 2024-Q1"
event.threat_level_id = 2  # Medium
event.analysis = 1          # Ongoing
event.distribution = 1      # Community

# IOC 추가
attr = MISPAttribute()
attr.type = "domain"
attr.value = "malicious-domain.example.com"
attr.category = "Network activity"
attr.comment = "C2 서버 도메인"
event.add_attribute(attr)

result = misp.add_event(event)
```

### 1.3 TheHive

TheHive는 보안 운영 팀을 위한 확장 가능한 인시던트 대응 플랫폼이다. MISP, OpenCTI와 연동하여 헌팅 결과를 인시던트로 전환하는 워크플로를 자동화한다.

**설치 (Docker)**:
```bash
docker pull strangebee/thehive:5
docker run -d --name thehive \
  -p 9000:9000 \
  -v thehive_data:/opt/thehive/data \
  strangebee/thehive:5
```

**핵심 기능**:
- **케이스(Case)**: 인시던트 추적 단위
- **태스크(Task)**: 케이스 내 작업 항목
- **옵저버블(Observable)**: 분석 대상 IOC
- **Responders**: 자동 대응 액션 (IP 차단, 사용자 비활성화 등)
- **Analyzers**: IOC 자동 분석 (VirusTotal, Shodan 등 90개+)

---

## 2. Sigma 규칙 작성 및 변환

### 2.1 Sigma란

Sigma는 로그 이벤트를 탐지하기 위한 오픈 표준 형식이다. SIEM/로그 플랫폼에 독립적인 탐지 규칙을 작성하고, 변환 도구로 플랫폼별 쿼리(KQL, SPL, Lucene 등)로 변환한다.

### 2.2 Sigma 규칙 구조

```yaml
# sigma_rule_example.yml
title: Suspicious PowerShell Encoded Command
id: 9b2c74f3-8e7a-4c1d-b8f2-3a5e6d9f1234
status: experimental
description: |
  공격자가 PowerShell 인코딩 파라미터를 사용하여
  탐지를 우회하려는 시도를 탐지합니다.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: threat-hunting-team
date: 2024/01/15
modified: 2024/03/20
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - '-'
      - 'enc'
  filter_legitimate:
    CommandLine|contains:
      - 'MpCmdRun'
      - 'WindowsDefender'
  condition: selection and not filter_legitimate
falsepositives:
  - 일부 관리 스크립트
  - 백업 소프트웨어
level: high
```

### 2.3 Sigma 규칙 핵심 요소

**logsource**: 탐지 대상 로그 소스
```yaml
# 방법 1: 카테고리 기반 (권장)
logsource:
  category: process_creation   # 프로세스 생성
  product: windows

# 방법 2: 제품/서비스 기반
logsource:
  product: windows
  service: security  # Windows Security 이벤트

# 방법 3: 직접 지정
logsource:
  product: linux
  service: auth
```

**detection 조건**:
```yaml
detection:
  # 단순 매칭
  selection_basic:
    EventID: 4688
    NewProcessName: '*mimikatz*'

  # 여러 값 중 하나 (OR)
  selection_lolbas:
    CommandLine|contains:
      - 'certutil -urlcache'
      - 'certutil -decode'
      - 'regsvr32 /s /n /u /i'

  # 모두 포함 (AND within field)
  selection_all:
    CommandLine|contains|all:
      - 'powershell'
      - '-exec'
      - 'bypass'

  # 수치 비교
  selection_size:
    CommandLine|re: '.{500,}'   # 500자 이상

  # 제외
  filter_admin:
    SubjectUserName|endswith: '$'

  condition: (selection_basic or selection_lolbas or selection_all or selection_size)
             and not filter_admin
```

### 2.4 Sigma 변환 (sigma-cli)

```bash
# 설치
pip install sigma-cli

# 플러그인 설치
sigma plugin install splunk
sigma plugin install microsoft365defender  # KQL용
sigma plugin install elasticsearch

# 변환 예시
sigma convert -t splunk -p ecs_windows sigma_rule.yml

sigma convert -t microsoft365defender sigma_rule.yml

sigma convert -t elasticsearch -p ecs_windows sigma_rule.yml

# 디렉토리 전체 변환
sigma convert -t splunk -p ecs_windows ./sigma_rules/ -o output.txt

# 파이프라인 지정
sigma convert -t splunk \
  --pipeline splunk_windows \
  --pipeline sysmon \
  sigma_rule.yml
```

---

## 3. YARA 규칙으로 메모리/파일 헌팅

### 3.1 YARA 기초

YARA는 악성코드 식별 및 분류를 위한 패턴 매칭 도구다. 텍스트/이진 패턴, 정규식, 불리언 조건으로 악성 파일을 탐지한다.

### 3.2 YARA 규칙 작성

```yara
// 기본 구조
rule RuleName {
    meta:
        description = "규칙 설명"
        author = "분석가"
        date = "2024-01-15"
        reference = "https://..."
        hash = "파일 해시"

    strings:
        // 텍스트 문자열
        $str1 = "malicious_string"
        $str2 = "another_string" nocase  // 대소문자 무시
        $str3 = "wide_string" wide       // UTF-16LE
        $str4 = "both" wide ascii        // 둘 다

        // 16진수 패턴
        $hex1 = { 4D 5A 90 00 03 00 00 00 }  // PE 헤더
        $hex2 = { 6A ?? 68 [2-4] FF D5 }     // 와일드카드/점프

        // 정규식
        $re1 = /[a-zA-Z]{6,10}\.(exe|dll|scr)/
        $re2 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}/  // IP 기반 URL

    condition:
        uint16(0) == 0x5A4D  // PE 파일 시그니처
        and filesize < 5MB
        and all of ($str*)
        or ($hex1 at 0 and $re1)
}
```

### 3.3 실전 YARA 규칙

**Mimikatz 탐지**:
```yara
rule Mimikatz_Generic {
    meta:
        description = "Mimikatz 메모리 덤프 도구 탐지"
        reference = "https://attack.mitre.org/software/S0002/"
        tags = "T1003.001"

    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::" nocase
        $s3 = "lsadump::" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "crypto::capi" nocase
        $hex1 = { 6B 61 73 6B 72 62 74 }  // "kaskrbt"
        $hex2 = { 74 73 63 61 6E 6E 69 6E 67 }  // "tscanning"

    condition:
        any of ($s1, $s2, $s3, $s4, $s5)
        or (2 of ($hex*))
}
```

**웹쉘 탐지**:
```yara
rule Webshell_Generic_PHP {
    meta:
        description = "일반적인 PHP 웹쉘 패턴 탐지"
        tags = "T1505.003"

    strings:
        $php_tag = "<?php"
        $eval = "eval(" nocase
        $base64 = "base64_decode(" nocase
        $system = /system\s*\(/ nocase
        $exec = /exec\s*\(/ nocase
        $passthru = "passthru(" nocase
        $shell_exec = "shell_exec(" nocase
        $cmd = "$_GET" nocase
        $post = "$_POST" nocase
        $req = "$_REQUEST" nocase

    condition:
        $php_tag and (
            ($eval and ($base64 or $cmd or $post or $req))
            or (any of ($system, $exec, $passthru, $shell_exec) and any of ($cmd, $post, $req))
        )
}
```

**YARA 실행**:
```bash
# 단일 파일 스캔
yara rule.yar target_file

# 디렉토리 재귀 스캔
yara -r rule.yar /suspicious/directory/

# 프로세스 메모리 스캔
yara rule.yar -p <PID>

# 모든 룰 디렉토리 적용
yara -r /rules/*.yar /malware/samples/

# 매치 문자열 출력
yara -s rule.yar sample.exe

# JSON 출력
yara --json rule.yar sample.exe
```

---

## 4. EDR API 활용

### 4.1 CrowdStrike Falcon API

**OAuth2 인증 및 기본 사용법**:
```python
# pip install crowdstrike-falconpy
from falconpy import Hosts, QueryDevicesByFilterScroll, ProcessesApiMixin

falcon = Hosts(
    client_id="your_client_id",
    client_secret="your_client_secret",
    base_url="https://api.crowdstrike.com"
)

# 호스트 조회
response = falcon.query_devices_by_filter(
    filter="hostname:'workstation-01'",
    limit=10
)
device_ids = response["body"]["resources"]

# 디바이스 상세 정보
details = falcon.get_device_details(ids=device_ids)
```

**RTR(Real Time Response) - 원격 명령 실행**:
```python
from falconpy import RealTimeResponse

rtr = RealTimeResponse(
    client_id="your_client_id",
    client_secret="your_client_secret",
)

# 세션 시작
session = rtr.init_session(
    device_id="device-id-here",
    origin="threat_hunting"
)
session_id = session["body"]["resources"][0]["session_id"]

# 명령 실행
cmd = rtr.execute_command(
    base_command="ls",
    command_string="ls -la /tmp",
    session_id=session_id,
)
```

### 4.2 Carbon Black Cloud API

```python
import requests

API_URL = "https://defense.conferdeploy.net"
ORG_KEY = "your_org_key"
API_ID = "your_api_id"
API_SECRET = "your_api_secret"

headers = {
    "X-Auth-Token": f"{API_SECRET}/{API_ID}",
    "Content-Type": "application/json",
}

# 프로세스 이벤트 조회
payload = {
    "criteria": {
        "process_name": ["powershell.exe"],
        "parent_name": ["winword.exe", "excel.exe"]
    },
    "time_range": {"window": "-1d"},
    "rows": 100,
    "sort": [{"field": "device_timestamp", "order": "desc"}]
}

resp = requests.post(
    f"{API_URL}/api/investigate/v2/orgs/{ORG_KEY}/processes/search_jobs",
    json=payload,
    headers=headers,
    timeout=30,
)
```

---

## 5. Jupyter Notebook 기반 헌팅 워크플로

### 5.1 헌팅 노트북 구조

```
hunt_notebook/
├── 00_setup.ipynb          # 환경 설정, 데이터 연결
├── 01_data_collection.ipynb # 데이터 수집 및 전처리
├── 02_hypothesis_testing.ipynb # 가설 검증
├── 03_visualization.ipynb  # 시각화 및 분석
├── 04_findings_report.ipynb # 결과 보고
└── data/
    ├── raw/
    └── processed/
```

### 5.2 pandas 기반 기본 헌팅 패턴

```python
import pandas as pd
from pathlib import Path

# 데이터 로드
df = pd.read_csv("process_events.csv", parse_dates=["timestamp"])

# 비정상 PowerShell 탐지
suspicious_ps = df[
    (df["process_name"].str.lower() == "powershell.exe") &
    (df["command_line"].str.contains(r"-[Ee][Nn][Cc]", regex=True, na=False))
]

# 프로세스 계층 분석
parent_child = df.groupby(["parent_name", "process_name"]).size().reset_index(name="count")
rare_chains = parent_child[parent_child["count"] < 3]

# 시간대별 집계
df["hour"] = df["timestamp"].dt.hour
hourly_counts = df.groupby(["hour", "process_name"]).size().unstack(fill_value=0)
```

---

## 6. Python: Sigma 규칙 파서 및 쿼리 변환 도구

```python
#!/usr/bin/env python3
"""
Sigma 규칙 파서 및 쿼리 변환 CLI 도구
의존성: pip install pyyaml

지원 변환 대상: Splunk SPL, Microsoft Sentinel KQL, Elasticsearch Lucene

사용법: python3 sigma_converter.py [command] [options]
"""

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# ── Sigma 규칙 파서 ──────────────────────────────────────────────────────────

class SigmaParseError(Exception):
    pass


class SigmaRule:
    """Sigma 규칙 파싱 및 표현."""

    REQUIRED_FIELDS = {"title", "logsource", "detection"}

    def __init__(self, raw: dict) -> None:
        self._raw = raw
        self._validate()

    def _validate(self) -> None:
        missing = self.REQUIRED_FIELDS - set(self._raw.keys())
        if missing:
            raise SigmaParseError(f"필수 필드 누락: {missing}")

    @property
    def title(self) -> str:
        return self._raw.get("title", "Untitled")

    @property
    def rule_id(self) -> str:
        return self._raw.get("id", "")

    @property
    def description(self) -> str:
        return self._raw.get("description", "")

    @property
    def status(self) -> str:
        return self._raw.get("status", "experimental")

    @property
    def level(self) -> str:
        return self._raw.get("level", "medium")

    @property
    def tags(self) -> list[str]:
        return self._raw.get("tags", [])

    @property
    def logsource(self) -> dict:
        return self._raw.get("logsource", {})

    @property
    def detection(self) -> dict:
        return self._raw.get("detection", {})

    @property
    def falsepositives(self) -> list[str]:
        return self._raw.get("falsepositives", [])

    @property
    def mitre_techniques(self) -> list[str]:
        """태그에서 MITRE ATT&CK 기술 ID 추출."""
        return [
            tag.replace("attack.t", "T").replace(".", ".").upper()
            for tag in self.tags
            if re.match(r"attack\.t\d{4}", tag, re.IGNORECASE)
        ]

    def __repr__(self) -> str:
        return f"SigmaRule(title={self.title!r}, level={self.level!r})"


def load_sigma_file(path: Path) -> SigmaRule:
    """YAML 파일에서 Sigma 규칙 로드."""
    if not YAML_AVAILABLE:
        raise RuntimeError("PyYAML이 필요합니다: pip install pyyaml")
    if not path.exists():
        raise FileNotFoundError(f"파일 없음: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SigmaParseError("YAML 최상위가 dict가 아닙니다.")
        return SigmaRule(raw)
    except yaml.YAMLError as e:
        raise SigmaParseError(f"YAML 파싱 실패: {e}") from e


# ── 탐지 조건 파서 ────────────────────────────────────────────────────────────

class DetectionParser:
    """Sigma detection 블록 파싱."""

    MODIFIER_MAP = {
        "contains": "contains",
        "startswith": "startswith",
        "endswith": "endswith",
        "re": "regex",
        "base64": "base64",
        "all": "all",
        "nocase": "nocase",
        "windash": "windash",
    }

    def parse_field_value(
        self, field: str, value: Any
    ) -> list[dict[str, Any]]:
        """필드|수정자 형식 파싱."""
        parts = field.split("|")
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []
        values = value if isinstance(value, list) else [value]

        return [{
            "field": field_name,
            "modifiers": modifiers,
            "values": values,
        }]

    def parse_selection(self, selection: dict) -> list[dict[str, Any]]:
        """단일 selection 블록 파싱."""
        conditions = []
        for field, value in selection.items():
            if field.startswith("_"):
                continue
            conditions.extend(self.parse_field_value(field, value))
        return conditions

    def get_selection_names(self, detection: dict) -> list[str]:
        """condition 이외의 selection 이름 목록 반환."""
        return [k for k in detection.keys() if k != "condition"]

    def parse_condition(self, condition_str: str) -> str:
        """condition 문자열 정규화."""
        return condition_str.strip()


# ── 쿼리 생성기 ────────────────────────────────────────────────────────────────

class BaseQueryGenerator:
    """쿼리 생성기 기본 클래스."""

    PLATFORM = "generic"
    parser = DetectionParser()

    def _escape(self, value: str) -> str:
        return str(value).replace('"', '\\"').replace("\\", "\\\\")

    def _build_field_condition(
        self, field: str, modifiers: list[str], values: list[Any]
    ) -> str:
        raise NotImplementedError

    def _build_selection(self, name: str, selection: dict) -> str:
        raise NotImplementedError

    def generate(self, rule: SigmaRule) -> str:
        raise NotImplementedError

    def _resolve_logsource(self, logsource: dict) -> str:
        """로그 소스를 플랫폼별 테이블/인덱스로 변환 (기본 구현)."""
        category = logsource.get("category", "")
        product = logsource.get("product", "")
        return f"{product}_{category}" if (product and category) else (product or category or "logs")


class SplunkQueryGenerator(BaseQueryGenerator):
    """Splunk SPL 쿼리 생성."""

    PLATFORM = "splunk"

    # 카테고리 → Splunk 인덱스/소스타입 매핑
    LOGSOURCE_MAP = {
        ("windows", "process_creation"): "index=windows EventCode=4688",
        ("windows", "network_connection"): "index=windows EventCode=3",
        ("windows", "registry_event"): "index=windows (EventCode=4656 OR EventCode=4663)",
        ("windows", "file_event"): "index=windows EventCode=4663",
        ("linux", "process_creation"): "index=linux sourcetype=syslog",
        ("windows", "security"): "index=wineventlog sourcetype=\"WinEventLog:Security\"",
    }

    def _resolve_logsource(self, logsource: dict) -> str:
        product = logsource.get("product", "").lower()
        category = logsource.get("category", "").lower()
        service = logsource.get("service", "").lower()
        key = (product, category or service)
        return self.LOGSOURCE_MAP.get(key, f"index={product or 'main'}")

    def _build_field_condition(
        self, field: str, modifiers: list[str], values: list[Any]
    ) -> str:
        is_all = "all" in modifiers
        is_nocase = "nocase" in modifiers
        parts = []

        for val in values:
            escaped = self._escape(str(val))
            if "re" in modifiers:
                cond = f'{field}="{escaped}"'  # SPL regex는 별도 처리 필요
            elif "contains" in modifiers:
                cond = f'{field}="*{escaped}*"'
            elif "startswith" in modifiers:
                cond = f'{field}="{escaped}*"'
            elif "endswith" in modifiers:
                cond = f'{field}="*{escaped}"'
            else:
                cond = f'{field}="{escaped}"'
            parts.append(cond)

        if not parts:
            return ""
        if is_all:
            return "(" + " AND ".join(parts) + ")"
        return "(" + " OR ".join(parts) + ")"

    def _build_selection(self, selection: dict) -> str:
        conditions = self.parser.parse_selection(selection)
        parts = []
        for cond in conditions:
            part = self._build_field_condition(
                cond["field"], cond["modifiers"], cond["values"]
            )
            if part:
                parts.append(part)
        return " AND ".join(parts) if parts else "1=1"

    def generate(self, rule: SigmaRule) -> str:
        detection = rule.detection
        condition = detection.get("condition", "")
        selection_names = self.parser.get_selection_names(detection)

        # 각 selection 조건 생성
        selection_queries: dict[str, str] = {}
        for name in selection_names:
            sel = detection[name]
            if isinstance(sel, dict):
                selection_queries[name] = self._build_selection(sel)
            elif isinstance(sel, list):
                # OR 조건 목록
                parts = []
                for item in sel:
                    if isinstance(item, dict):
                        parts.append(f"({self._build_selection(item)})")
                selection_queries[name] = " OR ".join(parts)

        # condition 문자열 처리
        final_condition = condition
        for name, query in selection_queries.items():
            final_condition = final_condition.replace(name, f"({query})")

        # "not" 처리
        final_condition = re.sub(r"\bnot\s+\(", "NOT (", final_condition)
        final_condition = re.sub(r"\band\b", "AND", final_condition)
        final_condition = re.sub(r"\bor\b", "OR", final_condition)

        logsource_prefix = self._resolve_logsource(rule.logsource)
        return f"{logsource_prefix}\n| search {final_condition}\n| table _time, host, *"


class KQLQueryGenerator(BaseQueryGenerator):
    """Microsoft Sentinel KQL 쿼리 생성."""

    PLATFORM = "kql"

    LOGSOURCE_MAP = {
        ("windows", "process_creation"): "DeviceProcessEvents",
        ("windows", "network_connection"): "DeviceNetworkEvents",
        ("windows", "registry_event"): "DeviceRegistryEvents",
        ("windows", "file_event"): "DeviceFileEvents",
        ("windows", "security"): "SecurityEvent",
        ("linux", "process_creation"): "Syslog",
        ("", "dns"): "DnsEvents",
    }

    def _resolve_logsource(self, logsource: dict) -> str:
        product = logsource.get("product", "").lower()
        category = logsource.get("category", "").lower()
        service = logsource.get("service", "").lower()
        key = (product, category or service)
        return self.LOGSOURCE_MAP.get(key, "SecurityEvent")

    def _build_field_condition(
        self, field: str, modifiers: list[str], values: list[Any]
    ) -> str:
        is_all = "all" in modifiers
        parts = []

        for val in values:
            escaped = self._escape(str(val))
            if "re" in modifiers:
                cond = f'{field} matches regex @"{escaped}"'
            elif "contains" in modifiers:
                cond = f'{field} has "{escaped}"'
            elif "startswith" in modifiers:
                cond = f'{field} startswith "{escaped}"'
            elif "endswith" in modifiers:
                cond = f'{field} endswith "{escaped}"'
            else:
                cond = f'{field} =~ "{escaped}"'
            parts.append(cond)

        if not parts:
            return ""
        if is_all:
            # has_all for 'has' type
            if "contains" in modifiers:
                vals_list = ", ".join(f'"{self._escape(str(v))}"' for v in values)
                return f'{field} has_all ({vals_list})'
            return "(" + " and ".join(parts) + ")"
        if len(parts) == 1:
            return parts[0]
        if "contains" in modifiers:
            vals_list = ", ".join(f'"{self._escape(str(v))}"' for v in values)
            return f'{field} has_any ({vals_list})'
        return "(" + " or ".join(parts) + ")"

    def _build_selection(self, selection: dict) -> str:
        conditions = self.parser.parse_selection(selection)
        parts = []
        for cond in conditions:
            part = self._build_field_condition(
                cond["field"], cond["modifiers"], cond["values"]
            )
            if part:
                parts.append(part)
        return "\n    and ".join(parts) if parts else "true"

    def generate(self, rule: SigmaRule) -> str:
        detection = rule.detection
        condition = detection.get("condition", "")
        selection_names = self.parser.get_selection_names(detection)

        selection_queries: dict[str, str] = {}
        for name in selection_names:
            sel = detection[name]
            if isinstance(sel, dict):
                selection_queries[name] = self._build_selection(sel)
            elif isinstance(sel, list):
                parts = []
                for item in sel:
                    if isinstance(item, dict):
                        parts.append(f"(\n    {self._build_selection(item)}\n)")
                selection_queries[name] = " or ".join(parts)

        final_condition = condition
        for name, query in selection_queries.items():
            final_condition = final_condition.replace(name, f"(\n    {query}\n)")

        final_condition = re.sub(r"\bnot\s+", "not ", final_condition)

        table = self._resolve_logsource(rule.logsource)
        time_filter = "| where TimeGenerated > ago(24h)"
        return (
            f"// Rule: {rule.title}\n"
            f"// Level: {rule.level} | MITRE: {', '.join(rule.mitre_techniques)}\n"
            f"{table}\n"
            f"{time_filter}\n"
            f"| where {final_condition}\n"
            f"| project TimeGenerated, DeviceName, *\n"
            f"| order by TimeGenerated desc\n"
        )


GENERATORS: dict[str, type[BaseQueryGenerator]] = {
    "splunk": SplunkQueryGenerator,
    "kql": KQLQueryGenerator,
}


# ── CLI 명령어 ──────────────────────────────────────────────────────────────

def cmd_convert(args: argparse.Namespace) -> None:
    """Sigma 규칙을 지정 플랫폼 쿼리로 변환."""
    if not YAML_AVAILABLE:
        print("[ERROR] pyyaml이 필요합니다: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    generator_cls = GENERATORS.get(args.target)
    if not generator_cls:
        print(f"[ERROR] 지원하지 않는 대상: {args.target}. 지원: {list(GENERATORS.keys())}", file=sys.stderr)
        sys.exit(1)

    input_path = Path(args.rule)
    if not input_path.exists():
        print(f"[ERROR] 파일 없음: {args.rule}", file=sys.stderr)
        sys.exit(1)

    try:
        rule = load_sigma_file(input_path)
    except (SigmaParseError, FileNotFoundError) as e:
        print(f"[ERROR] 규칙 로드 실패: {e}", file=sys.stderr)
        sys.exit(1)

    gen = generator_cls()
    query = gen.generate(rule)

    print(f"// === Sigma 규칙 변환 결과 ===")
    print(f"// 원본: {input_path.name}")
    print(f"// 대상: {args.target.upper()}")
    print(f"// 규칙: {rule.title} ({rule.level})")
    print(f"// ID: {rule.rule_id}")
    print()
    print(query)

    if args.output:
        Path(args.output).write_text(query, encoding="utf-8")
        print(f"\n[+] 저장: {args.output}")


def cmd_batch_convert(args: argparse.Namespace) -> None:
    """디렉토리 내 Sigma 규칙 일괄 변환."""
    if not YAML_AVAILABLE:
        print("[ERROR] pyyaml이 필요합니다: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    generator_cls = GENERATORS.get(args.target)
    if not generator_cls:
        print(f"[ERROR] 지원하지 않는 대상: {args.target}", file=sys.stderr)
        sys.exit(1)

    input_dir = Path(args.directory)
    if not input_dir.is_dir():
        print(f"[ERROR] 디렉토리 없음: {args.directory}", file=sys.stderr)
        sys.exit(1)

    rule_files = list(input_dir.rglob("*.yml")) + list(input_dir.rglob("*.yaml"))
    if not rule_files:
        print("[-] yml/yaml 파일을 찾을 수 없습니다.")
        return

    print(f"[*] {len(rule_files)}개 Sigma 규칙 일괄 변환 시작...")

    def convert_one(path: Path) -> tuple[str, Optional[str], Optional[str]]:
        """단일 규칙 변환, (파일명, 쿼리, 에러) 반환."""
        try:
            rule = load_sigma_file(path)
            gen = generator_cls()
            query = gen.generate(rule)
            return str(path.name), query, None
        except Exception as e:
            return str(path.name), None, str(e)

    results: list[tuple[str, Optional[str], Optional[str]]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(rule_files))) as executor:
        futures = {executor.submit(convert_one, f): f for f in rule_files}
        for future in as_completed(futures):
            results.append(future.result())

    success = [(n, q) for n, q, e in results if q is not None]
    failed = [(n, e) for n, q, e in results if e is not None]

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, query in success:
            stem = Path(name).stem
            out_path = out_dir / f"{stem}.{args.target}.txt"
            out_path.write_text(query, encoding="utf-8")

    print(f"\n[완료] 성공: {len(success)}, 실패: {len(failed)}")
    if failed:
        print("\n[실패 목록]")
        for name, err in failed:
            print(f"  {name}: {err}")
    if args.output_dir:
        print(f"[+] 변환된 쿼리 저장: {args.output_dir}")


def cmd_validate(args: argparse.Namespace) -> None:
    """Sigma 규칙 유효성 검사."""
    if not YAML_AVAILABLE:
        print("[ERROR] pyyaml이 필요합니다: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    path = Path(args.rule)
    if not path.exists():
        print(f"[ERROR] 파일 없음: {args.rule}", file=sys.stderr)
        sys.exit(1)

    try:
        rule = load_sigma_file(path)
    except SigmaParseError as e:
        print(f"[FAIL] 파싱 실패: {e}")
        sys.exit(1)

    issues = []
    warnings = []

    # 필수 필드 확인
    if not rule.rule_id:
        warnings.append("id 필드 없음")
    if not rule.description:
        warnings.append("description 필드 없음")
    if rule.status not in ("stable", "test", "experimental", "deprecated"):
        warnings.append(f"비표준 status: {rule.status}")
    if not rule.tags:
        warnings.append("tags 없음 (MITRE ATT&CK 태그 권장)")
    if not rule.falsepositives:
        warnings.append("falsepositives 없음")

    # detection 구조 확인
    detection = rule.detection
    if "condition" not in detection:
        issues.append("detection.condition 누락")
    condition = detection.get("condition", "")
    for name in re.findall(r"\b\w+\b", condition):
        if name.lower() in ("and", "or", "not", "1", "of", "all", "them"):
            continue
        if name not in detection:
            issues.append(f"condition에서 참조하는 selection '{name}' 이 detection에 없음")

    print(f"\n유효성 검사: {path.name}")
    print(f"{'='*50}")
    print(f"제목   : {rule.title}")
    print(f"상태   : {rule.status}")
    print(f"레벨   : {rule.level}")
    print(f"MITRE  : {', '.join(rule.mitre_techniques) or '없음'}")

    if issues:
        print(f"\n[오류 {len(issues)}개]")
        for issue in issues:
            print(f"  ✗ {issue}")
    if warnings:
        print(f"\n[경고 {len(warnings)}개]")
        for warn in warnings:
            print(f"  ⚠ {warn}")
    if not issues and not warnings:
        print("\n[OK] 유효성 검사 통과")
    elif not issues:
        print("\n[OK] 오류 없음 (경고만 존재)")
    else:
        print("\n[FAIL] 수정이 필요합니다.")
        sys.exit(1)


def cmd_info(args: argparse.Namespace) -> None:
    """Sigma 규칙 정보 요약 출력."""
    if not YAML_AVAILABLE:
        print("[ERROR] pyyaml이 필요합니다: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    path = Path(args.rule)
    try:
        rule = load_sigma_file(path)
    except (SigmaParseError, FileNotFoundError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*50}")
    print(f"Sigma 규칙 정보")
    print(f"{'='*50}")
    print(f"제목        : {rule.title}")
    print(f"ID          : {rule.rule_id or '없음'}")
    print(f"상태        : {rule.status}")
    print(f"레벨        : {rule.level}")
    print(f"로그 소스   : {rule.logsource}")
    print(f"MITRE 기술  : {', '.join(rule.mitre_techniques) or '없음'}")
    print(f"태그        : {', '.join(rule.tags)}")
    print(f"False Pos.  : {len(rule.falsepositives)}개")
    print(f"\n설명:")
    desc = rule.description.strip()
    print(f"  {desc[:300]}{'...' if len(desc) > 300 else ''}")

    detection_keys = [k for k in rule.detection.keys() if k != "condition"]
    print(f"\nDetection 블록: {', '.join(detection_keys)}")
    print(f"Condition     : {rule.detection.get('condition', 'N/A')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sigma 규칙 파서 및 쿼리 변환 CLI 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 sigma_converter.py convert --rule my_rule.yml --target kql
  python3 sigma_converter.py convert --rule my_rule.yml --target splunk --output query.spl
  python3 sigma_converter.py batch-convert --directory ./rules/ --target kql --output-dir ./kql_queries/
  python3 sigma_converter.py validate --rule my_rule.yml
  python3 sigma_converter.py info --rule my_rule.yml
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    target_choices = list(GENERATORS.keys())

    # convert
    p_c = sub.add_parser("convert", help="단일 Sigma 규칙 변환")
    p_c.add_argument("--rule", required=True, help="Sigma 규칙 YAML 파일")
    p_c.add_argument("--target", required=True, choices=target_choices, help="변환 대상 플랫폼")
    p_c.add_argument("--output", help="출력 파일 경로")
    p_c.set_defaults(func=cmd_convert)

    # batch-convert
    p_b = sub.add_parser("batch-convert", help="디렉토리 일괄 변환")
    p_b.add_argument("--directory", required=True, help="Sigma 규칙 디렉토리")
    p_b.add_argument("--target", required=True, choices=target_choices, help="변환 대상 플랫폼")
    p_b.add_argument("--output-dir", help="변환된 쿼리 저장 디렉토리")
    p_b.set_defaults(func=cmd_batch_convert)

    # validate
    p_v = sub.add_parser("validate", help="Sigma 규칙 유효성 검사")
    p_v.add_argument("--rule", required=True, help="Sigma 규칙 YAML 파일")
    p_v.set_defaults(func=cmd_validate)

    # info
    p_i = sub.add_parser("info", help="Sigma 규칙 정보 출력")
    p_i.add_argument("--rule", required=True, help="Sigma 규칙 YAML 파일")
    p_i.set_defaults(func=cmd_info)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
```

---

## 7. 헌팅 자동화 아키텍처

### 7.1 자동화 헌팅 파이프라인

```
[위협 인텔리전스]       [헌팅 규칙 저장소]
     MISP/OpenCTI  →    Sigma/YARA 규칙
          │                    │
          ▼                    ▼
     [자동 변환 엔진]    [규칙 배포]
     sigma_converter  →  SIEM/EDR 배포
          │
          ▼
     [자동 실행]          [결과 수집]
     스케줄러 (cron)  →  매치 이벤트
          │
          ▼
     [알림/에스컬레이션]
     TheHive 케이스 생성 → SOC 팀 대응
```

### 7.2 Sigma 규칙 관리 모범 사례

1. **버전 관리**: Git으로 규칙 히스토리 관리
2. **CI/CD 통합**: 새 규칙 커밋 시 자동 유효성 검사 및 배포
3. **테스트 데이터**: Atomic Red Team과 연계하여 규칙 검증
4. **False Positive 추적**: 오탐 발생 시 규칙 개선 프로세스
5. **커버리지 대시보드**: 어떤 ATT&CK 기술이 커버되는지 시각화

### 7.3 YARA 규칙 배포 전략

| 배포 위치 | 목적 | 도구 |
|-----------|------|------|
| EDR 에이전트 | 실시간 파일/메모리 스캔 | CrowdStrike Custom IOA |
| 이메일 게이트웨이 | 첨부파일 스캔 | Proofpoint, Mimecast |
| 샌드박스 | 제출 파일 분석 | Cuckoo, ANY.RUN |
| 파일 서버 | 정기 스캔 | YARA CLI + 스케줄러 |
| 메모리 포렌식 | 침해 조사 | Volatility3 |
