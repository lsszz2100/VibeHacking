> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AI 시스템 위협 모델링

LLM, ML 파이프라인, AI 기반 제품에 특화된 위협 모델을 구축한다. STRIDE를 AI 시스템에 적용하는 방법, 프롬프트 인젝션·모델 탈취·데이터 포이즈닝 등 AI 고유 위협을 분석하고 완화 전략을 수립한다.

---

## 1. AI 시스템 위협 분류

### 1.1 AI 특화 위협 개요

```
기존 위협 + AI 고유 위협:

입력 조작:
  ├── 프롬프트 인젝션 (Prompt Injection)
  ├── 적대적 입력 (Adversarial Examples)
  └── Jailbreak / 가드레일 우회

모델 공격:
  ├── 모델 탈취 (Model Extraction)
  ├── 맴버십 추론 (Membership Inference)
  └── 모델 역전 (Model Inversion)

데이터 공격:
  ├── 데이터 포이즈닝 (Data Poisoning)
  ├── 백도어 공격 (Backdoor/Trojan)
  └── 훈련 데이터 유출

인프라 공격:
  ├── ML 파이프라인 공격
  ├── 모델 서빙 서버 취약점
  └── 공급망 공격 (악성 사전훈련 모델)
```

### 1.2 AI STRIDE 매핑

```python
#!/usr/bin/env python3
"""AI 시스템 STRIDE 위협 모델링 도구"""
import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class AIThreat:
    stride_category: str
    threat_name: str
    description: str
    ai_specific: bool
    mitre_atlas: str  # MITRE ATLAS ID
    severity: str     # Critical / High / Medium / Low
    likelihood: str   # High / Medium / Low
    mitigations: list[str] = field(default_factory=list)


AI_THREAT_CATALOG: list[AIThreat] = [
    # Spoofing
    AIThreat(
        "Spoofing", "프롬프트 인젝션을 통한 사용자 사칭",
        "악성 사용자가 시스템 프롬프트를 조작하여 다른 사용자나 관리자로 사칭",
        True, "AML.T0051",
        "Critical", "High",
        ["입력 검증 및 샌드박싱", "시스템/사용자 프롬프트 분리", "프롬프트 서명"],
    ),
    # Tampering
    AIThreat(
        "Tampering", "훈련 데이터 포이즈닝",
        "공격자가 훈련 데이터를 조작하여 모델 동작을 왜곡",
        True, "AML.T0020",
        "High", "Medium",
        ["데이터 출처 검증", "이상 탐지", "데이터 서명 및 무결성 확인"],
    ),
    AIThreat(
        "Tampering", "모델 가중치 조작",
        "서빙 모델 파일을 대체하거나 수정하여 백도어 삽입",
        True, "AML.T0031",
        "Critical", "Low",
        ["모델 파일 무결성 검증 (해시)", "안전한 모델 레지스트리", "코드 서명"],
    ),
    # Repudiation
    AIThreat(
        "Repudiation", "AI 생성 콘텐츠 부인",
        "AI가 생성한 유해 콘텐츠에 대한 출처 추적 불가",
        True, "AML.T0040",
        "Medium", "High",
        ["생성 콘텐츠 워터마킹", "입출력 로깅", "감사 추적"],
    ),
    # Information Disclosure
    AIThreat(
        "Information Disclosure", "훈련 데이터 추출",
        "모델 출력을 반복 쿼리하여 훈련 데이터의 개인정보 복원",
        True, "AML.T0024",
        "High", "Medium",
        ["차등 프라이버시 적용", "출력 후처리", "쿼리 속도 제한"],
    ),
    AIThreat(
        "Information Disclosure", "모델 탈취",
        "대량 API 쿼리로 기능적으로 동일한 모델 복제",
        True, "AML.T0005",
        "High", "High",
        ["API 호출 속도 제한", "워터마킹", "쿼리 패턴 모니터링"],
    ),
    # Denial of Service
    AIThreat(
        "Denial of Service", "적대적 입력으로 인한 추론 지연",
        "계산 비용이 높은 입력으로 서빙 서버 과부하",
        True, "AML.T0029",
        "Medium", "Medium",
        ["입력 길이/복잡도 제한", "타임아웃 설정", "샌드박싱"],
    ),
    # Elevation of Privilege
    AIThreat(
        "Elevation of Privilege", "Jailbreak을 통한 안전장치 우회",
        "특수 프롬프트로 콘텐츠 필터와 시스템 프롬프트 제한 우회",
        True, "AML.T0054",
        "High", "High",
        ["레드팀 테스트", "다층 필터링", "적대적 프롬프트 탐지"],
    ),
]


def build_threat_model(system_name: str, components: list[str]) -> dict:
    model = {
        "system": system_name,
        "components": components,
        "date": datetime.now().isoformat(),
        "threats": [],
        "risk_summary": {},
    }

    for threat in AI_THREAT_CATALOG:
        model["threats"].append({
            "id": f"THREAT-{len(model['threats'])+1:03d}",
            "stride": threat.stride_category,
            "name": threat.threat_name,
            "atlas": threat.mitre_atlas,
            "severity": threat.severity,
            "likelihood": threat.likelihood,
            "mitigations": threat.mitigations,
        })

    severity_counts = {}
    for t in model["threats"]:
        severity_counts[t["severity"]] = severity_counts.get(t["severity"], 0) + 1
    model["risk_summary"] = severity_counts

    return model


def main() -> None:
    parser = argparse.ArgumentParser(description="AI 시스템 위협 모델링")
    parser.add_argument("system_name", help="시스템 이름 (예: 'LLM 고객상담 챗봇')")
    parser.add_argument("--components", nargs="+", default=["LLM API", "벡터 DB", "사용자 인터페이스"])
    parser.add_argument("-o", "--output", default="ai_threat_model.json")
    args = parser.parse_args()

    model = build_threat_model(args.system_name, args.components)
    Path(args.output).write_text(json.dumps(model, indent=2, ensure_ascii=False))

    print(f"[+] 위협 모델 생성: {args.output}")
    print(f"[+] 총 위협 수: {len(model['threats'])}개")
    for severity, count in model["risk_summary"].items():
        print(f"  {severity}: {count}개")


if __name__ == "__main__":
    main()
```

---

## 2. 프롬프트 인젝션 위협

### 2.1 인젝션 패턴 탐지

```python
#!/usr/bin/env python3
"""프롬프트 인젝션 공격 탐지 및 완화"""
import argparse
import re
from dataclasses import dataclass


@dataclass
class InjectionPattern:
    name: str
    patterns: list[str]
    severity: str


INJECTION_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        "시스템 프롬프트 무시 시도",
        [
            r"ignore (all |your )?(previous |above )?instructions",
            r"forget (everything|all|what) you",
            r"disregard (your |all )?previous",
            r"system (prompt|instruction).*ignore",
            r"지금부터.*무시",
            r"이전.*지시.*무시",
        ],
        "High",
    ),
    InjectionPattern(
        "역할 변경 시도 (DAN/Jailbreak)",
        [
            r"\bDAN\b",
            r"do anything now",
            r"you are now (a |an )?",
            r"act as (a |an )?",
            r"pretend (you are|to be)",
            r"roleplay as",
            r"너는 이제.*야",
        ],
        "High",
    ),
    InjectionPattern(
        "간접 인젝션 (외부 콘텐츠 경유)",
        [
            r"<\?xml.*?>.*<inject",
            r"<!--.*instruction.*-->",
            r"\[INST\].*\[/INST\]",
            r"<system>.*</system>",
        ],
        "Critical",
    ),
    InjectionPattern(
        "데이터 추출 시도",
        [
            r"(show|print|reveal|tell me) (your |the )?(system|initial) prompt",
            r"what (are|were) your instructions",
            r"repeat (the |your |everything) (above|before|system)",
            r"시스템 프롬프트.*보여",
            r"초기 지시.*알려",
        ],
        "High",
    ),
    InjectionPattern(
        "인코딩 우회",
        [
            r"base64.*decode",
            r"\\u[0-9a-fA-F]{4}.*ignore",
            r"rot13.*ignore",
        ],
        "Medium",
    ),
]


class PromptInjectionDefender:
    def __init__(self) -> None:
        self.compiled = [
            (p.name, p.severity, [re.compile(pat, re.IGNORECASE | re.DOTALL) for pat in p.patterns])
            for p in INJECTION_PATTERNS
        ]

    def analyze(self, user_input: str) -> dict:
        findings = []

        for name, severity, patterns in self.compiled:
            for pattern in patterns:
                if pattern.search(user_input):
                    findings.append({
                        "type": name,
                        "severity": severity,
                        "pattern": pattern.pattern,
                    })
                    break

        return {
            "input": user_input[:100],
            "is_injection": len(findings) > 0,
            "findings": findings,
            "action": "BLOCK" if any(f["severity"] in ("High", "Critical") for f in findings) else "ALLOW",
        }

    def sanitize(self, user_input: str) -> str:
        analysis = self.analyze(user_input)
        if analysis["action"] == "BLOCK":
            raise ValueError(f"잠재적 프롬프트 인젝션 탐지: {[f['type'] for f in analysis['findings']]}")
        # 추가 정화 처리
        sanitized = user_input.replace("<", "&lt;").replace(">", "&gt;")
        return sanitized[:4096]  # 최대 길이 제한


def main() -> None:
    parser = argparse.ArgumentParser(description="프롬프트 인젝션 탐지")
    parser.add_argument("input", help="검사할 사용자 입력")
    args = parser.parse_args()

    defender = PromptInjectionDefender()
    result = defender.analyze(args.input)

    print(f"판정: {result['action']}")
    for finding in result["findings"]:
        print(f"  [{finding['severity']}] {finding['type']}")


if __name__ == "__main__":
    main()
```

### 2.2 간접 프롬프트 인젝션 방어

```python
#!/usr/bin/env python3
"""웹 콘텐츠 경유 간접 인젝션 탐지"""
import re
from typing import Optional


class IndirectInjectionDetector:
    # 웹 페이지나 문서에 숨겨진 인젝션 패턴
    HIDDEN_INJECTION_PATTERNS = [
        # HTML 주석
        r"<!--.*?(ignore|instruction|system|prompt).*?-->",
        # 보이지 않는 텍스트 (CSS 흰색 글자 등)
        r'style="[^"]*color:\s*white[^"]*"[^>]*>.*?<',
        # 제로 너비 공백으로 숨기기
        r"[​‌‍﻿]+",
        # 마크다운 주석
        r"\[comment\]:.*?ignore",
        # LaTeX 주석
        r"%.*?ignore.*?instructions",
    ]

    def scan_content(self, content: str) -> list[dict]:
        findings = []
        for pattern in self.HIDDEN_INJECTION_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": str(match)[:100],
                })
        return findings

    def strip_hidden_content(self, content: str) -> str:
        # 제로 너비 문자 제거
        for char in "​‌‍﻿":
            content = content.replace(char, "")
        # HTML 태그 내 이벤트 핸들러 제거
        content = re.sub(r'\s+on\w+="[^"]*"', "", content)
        return content


# RAG 시스템 보안 레이어
class SecureRAGPipeline:
    def __init__(self) -> None:
        self.injection_detector = IndirectInjectionDetector()

    def process_document(self, document: str, source: str) -> Optional[str]:
        findings = self.injection_detector.scan_content(document)
        if findings:
            print(f"[!] 문서 '{source}'에서 간접 인젝션 의심 패턴 발견: {len(findings)}건")
            return None  # 해당 문서 제외

        cleaned = self.injection_detector.strip_hidden_content(document)
        max_len = 8000
        return cleaned[:max_len]
```

---

## 3. ML 모델 보안 평가

### 3.1 맴버십 추론 공격 탐지

```python
#!/usr/bin/env python3
"""맴버십 추론 공격 취약성 평가"""
import argparse
import numpy as np
from typing import Callable


def membership_inference_audit(
    model_predict: Callable,
    train_samples: list,
    test_samples: list,
    n_shadow_queries: int = 100,
) -> dict:
    """
    모델이 훈련 데이터를 '기억'하는 정도를 측정.
    높은 공격 성공률 = 과적합 및 프라이버시 위험.
    """
    train_confidences = []
    for sample in train_samples[:n_shadow_queries]:
        probs = model_predict(sample)
        train_confidences.append(max(probs))

    test_confidences = []
    for sample in test_samples[:n_shadow_queries]:
        probs = model_predict(sample)
        test_confidences.append(max(probs))

    avg_train_conf = np.mean(train_confidences)
    avg_test_conf = np.mean(test_confidences)
    confidence_gap = avg_train_conf - avg_test_conf

    # 공격 성공률 추정 (임계값 기반)
    threshold = (avg_train_conf + avg_test_conf) / 2
    tp = sum(1 for c in train_confidences if c >= threshold)
    fp = sum(1 for c in test_confidences if c >= threshold)
    attack_accuracy = (tp + (n_shadow_queries - fp)) / (2 * n_shadow_queries)

    return {
        "train_confidence": float(avg_train_conf),
        "test_confidence": float(avg_test_conf),
        "confidence_gap": float(confidence_gap),
        "attack_accuracy": float(attack_accuracy),
        "privacy_risk": "HIGH" if confidence_gap > 0.1 else "MEDIUM" if confidence_gap > 0.05 else "LOW",
        "recommendation": "차등 프라이버시 적용 권고" if confidence_gap > 0.1 else "정기 모니터링 권고",
    }
```

### 3.2 모델 탈취 탐지

```python
#!/usr/bin/env python3
"""ML API 모델 탈취 공격 모니터링"""
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class ModelExtractionMonitor:
    query_window: int = 3600  # 1시간
    query_threshold: int = 1000  # 최대 쿼리 수
    similarity_threshold: float = 0.8  # 입력 다양성 임계값
    client_queries: dict = field(default_factory=lambda: defaultdict(list))

    def record_query(self, client_id: str, query_hash: str) -> dict:
        now = time.time()
        window_start = now - self.query_window

        # 윈도우 외 쿼리 제거
        self.client_queries[client_id] = [
            (ts, h) for ts, h in self.client_queries[client_id]
            if ts > window_start
        ]
        self.client_queries[client_id].append((now, query_hash))

        query_count = len(self.client_queries[client_id])
        unique_queries = len(set(h for _, h in self.client_queries[client_id]))
        diversity = unique_queries / max(query_count, 1)

        is_suspicious = (
            query_count > self.query_threshold and
            diversity > self.similarity_threshold
        )

        return {
            "client_id": client_id,
            "query_count": query_count,
            "unique_count": unique_queries,
            "diversity": round(diversity, 3),
            "suspicious": is_suspicious,
            "action": "THROTTLE" if is_suspicious else "ALLOW",
        }
```

---

## 4. AI 시스템 보안 체크리스트

```
입력 레이어:
  □ 프롬프트 인젝션 탐지 레이어 구현
  □ 입력 길이/토큰 수 제한
  □ 간접 인젝션 (RAG 문서) 검사
  □ 사용자 입력 샌드박싱

모델 레이어:
  □ 모델 파일 무결성 해시 검증
  □ 안전한 모델 레지스트리 사용
  □ 훈련 데이터 출처 및 서명 관리
  □ 차등 프라이버시 훈련 적용 검토

출력 레이어:
  □ 콘텐츠 필터링 다층 구성
  □ PII 마스킹 (출력에서 개인정보 제거)
  □ 출력 로깅 및 모니터링
  □ 생성 콘텐츠 워터마킹

인프라 레이어:
  □ API 속도 제한 (모델 탈취 방어)
  □ 이상 쿼리 패턴 모니터링
  □ 모델 서빙 서버 보안 강화
  □ 공급망 검증 (Hugging Face 모델 서명)
```

| 위협 | MITRE ATLAS | 완화 기법 | 구현 난이도 |
|------|------------|---------|-----------|
| 프롬프트 인젝션 | AML.T0051 | 입력 검증, 멀티레이어 필터 | 중간 |
| 모델 탈취 | AML.T0005 | 속도 제한, 워터마킹 | 낮음 |
| 데이터 포이즈닝 | AML.T0020 | 데이터 검증, 무결성 서명 | 높음 |
| 맴버십 추론 | AML.T0024 | 차등 프라이버시 | 높음 |
| Jailbreak | AML.T0054 | 레드팀, RLHF 강화 | 높음 |
| 간접 인젝션 | AML.T0051.000 | RAG 콘텐츠 스캔 | 중간 |

---

<a name="english"></a>

# AI System Threat Modeling

Build threat models specialized for LLMs, ML pipelines, and AI-powered products. Learn how to apply STRIDE to AI systems, analyze AI-specific threats such as prompt injection, model extraction, and data poisoning, and establish mitigation strategies.

---

## 1. AI System Threat Classification

### 1.1 Overview of AI-Specific Threats

```
Traditional Threats + AI-Specific Threats:

Input Manipulation:
  ├── Prompt Injection
  ├── Adversarial Examples
  └── Jailbreak / Guardrail Bypass

Model Attacks:
  ├── Model Extraction
  ├── Membership Inference
  └── Model Inversion

Data Attacks:
  ├── Data Poisoning
  ├── Backdoor/Trojan Attacks
  └── Training Data Leakage

Infrastructure Attacks:
  ├── ML Pipeline Attacks
  ├── Model Serving Server Vulnerabilities
  └── Supply Chain Attacks (malicious pre-trained models)
```

### 1.2 AI STRIDE Mapping

```python
#!/usr/bin/env python3
"""AI System STRIDE Threat Modeling Tool"""
import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class AIThreat:
    stride_category: str
    threat_name: str
    description: str
    ai_specific: bool
    mitre_atlas: str  # MITRE ATLAS ID
    severity: str     # Critical / High / Medium / Low
    likelihood: str   # High / Medium / Low
    mitigations: list[str] = field(default_factory=list)


AI_THREAT_CATALOG: list[AIThreat] = [
    # Spoofing
    AIThreat(
        "Spoofing", "User impersonation via prompt injection",
        "Malicious user manipulates system prompt to impersonate other users or admins",
        True, "AML.T0051",
        "Critical", "High",
        ["Input validation and sandboxing", "System/user prompt separation", "Prompt signing"],
    ),
    # Tampering
    AIThreat(
        "Tampering", "Training data poisoning",
        "Attacker manipulates training data to distort model behavior",
        True, "AML.T0020",
        "High", "Medium",
        ["Data provenance verification", "Anomaly detection", "Data signing and integrity checks"],
    ),
    AIThreat(
        "Tampering", "Model weight manipulation",
        "Replace or modify serving model files to insert backdoors",
        True, "AML.T0031",
        "Critical", "Low",
        ["Model file integrity verification (hashing)", "Secure model registry", "Code signing"],
    ),
    # Repudiation
    AIThreat(
        "Repudiation", "Denial of AI-generated content",
        "Unable to trace source of harmful content generated by AI",
        True, "AML.T0040",
        "Medium", "High",
        ["Generated content watermarking", "Input/output logging", "Audit trail"],
    ),
    # Information Disclosure
    AIThreat(
        "Information Disclosure", "Training data extraction",
        "Repeated model queries to recover personal info from training data",
        True, "AML.T0024",
        "High", "Medium",
        ["Apply differential privacy", "Output post-processing", "Query rate limiting"],
    ),
    AIThreat(
        "Information Disclosure", "Model extraction",
        "Replicate a functionally equivalent model via mass API queries",
        True, "AML.T0005",
        "High", "High",
        ["API call rate limiting", "Watermarking", "Query pattern monitoring"],
    ),
    # Denial of Service
    AIThreat(
        "Denial of Service", "Inference latency via adversarial inputs",
        "Overload serving server with computationally expensive inputs",
        True, "AML.T0029",
        "Medium", "Medium",
        ["Input length/complexity limits", "Timeout settings", "Sandboxing"],
    ),
    # Elevation of Privilege
    AIThreat(
        "Elevation of Privilege", "Safety bypass via jailbreak",
        "Bypass content filters and system prompt restrictions with special prompts",
        True, "AML.T0054",
        "High", "High",
        ["Red team testing", "Multi-layer filtering", "Adversarial prompt detection"],
    ),
]


def build_threat_model(system_name: str, components: list[str]) -> dict:
    model = {
        "system": system_name,
        "components": components,
        "date": datetime.now().isoformat(),
        "threats": [],
        "risk_summary": {},
    }

    for threat in AI_THREAT_CATALOG:
        model["threats"].append({
            "id": f"THREAT-{len(model['threats'])+1:03d}",
            "stride": threat.stride_category,
            "name": threat.threat_name,
            "atlas": threat.mitre_atlas,
            "severity": threat.severity,
            "likelihood": threat.likelihood,
            "mitigations": threat.mitigations,
        })

    severity_counts = {}
    for t in model["threats"]:
        severity_counts[t["severity"]] = severity_counts.get(t["severity"], 0) + 1
    model["risk_summary"] = severity_counts

    return model


def main() -> None:
    parser = argparse.ArgumentParser(description="AI System Threat Modeling")
    parser.add_argument("system_name", help="System name (e.g., 'LLM Customer Support Chatbot')")
    parser.add_argument("--components", nargs="+", default=["LLM API", "Vector DB", "User Interface"])
    parser.add_argument("-o", "--output", default="ai_threat_model.json")
    args = parser.parse_args()

    model = build_threat_model(args.system_name, args.components)
    Path(args.output).write_text(json.dumps(model, indent=2, ensure_ascii=False))

    print(f"[+] Threat model generated: {args.output}")
    print(f"[+] Total threats: {len(model['threats'])}")
    for severity, count in model["risk_summary"].items():
        print(f"  {severity}: {count}")


if __name__ == "__main__":
    main()
```

---

## 2. Prompt Injection Threats

### 2.1 Injection Pattern Detection

```python
#!/usr/bin/env python3
"""Prompt injection attack detection and mitigation"""
import argparse
import re
from dataclasses import dataclass


@dataclass
class InjectionPattern:
    name: str
    patterns: list[str]
    severity: str


INJECTION_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        "System Prompt Override Attempt",
        [
            r"ignore (all |your )?(previous |above )?instructions",
            r"forget (everything|all|what) you",
            r"disregard (your |all )?previous",
            r"system (prompt|instruction).*ignore",
        ],
        "High",
    ),
    InjectionPattern(
        "Role Change Attempt (DAN/Jailbreak)",
        [
            r"\bDAN\b",
            r"do anything now",
            r"you are now (a |an )?",
            r"act as (a |an )?",
            r"pretend (you are|to be)",
            r"roleplay as",
        ],
        "High",
    ),
    InjectionPattern(
        "Indirect Injection (via external content)",
        [
            r"<\?xml.*?>.*<inject",
            r"<!--.*instruction.*-->",
            r"\[INST\].*\[/INST\]",
            r"<system>.*</system>",
        ],
        "Critical",
    ),
    InjectionPattern(
        "Data Extraction Attempt",
        [
            r"(show|print|reveal|tell me) (your |the )?(system|initial) prompt",
            r"what (are|were) your instructions",
            r"repeat (the |your |everything) (above|before|system)",
        ],
        "High",
    ),
    InjectionPattern(
        "Encoding Bypass",
        [
            r"base64.*decode",
            r"\\u[0-9a-fA-F]{4}.*ignore",
            r"rot13.*ignore",
        ],
        "Medium",
    ),
]


class PromptInjectionDefender:
    def __init__(self) -> None:
        self.compiled = [
            (p.name, p.severity, [re.compile(pat, re.IGNORECASE | re.DOTALL) for pat in p.patterns])
            for p in INJECTION_PATTERNS
        ]

    def analyze(self, user_input: str) -> dict:
        findings = []

        for name, severity, patterns in self.compiled:
            for pattern in patterns:
                if pattern.search(user_input):
                    findings.append({
                        "type": name,
                        "severity": severity,
                        "pattern": pattern.pattern,
                    })
                    break

        return {
            "input": user_input[:100],
            "is_injection": len(findings) > 0,
            "findings": findings,
            "action": "BLOCK" if any(f["severity"] in ("High", "Critical") for f in findings) else "ALLOW",
        }

    def sanitize(self, user_input: str) -> str:
        analysis = self.analyze(user_input)
        if analysis["action"] == "BLOCK":
            raise ValueError(f"Potential prompt injection detected: {[f['type'] for f in analysis['findings']]}")
        # Additional sanitization
        sanitized = user_input.replace("<", "&lt;").replace(">", "&gt;")
        return sanitized[:4096]  # Maximum length limit


def main() -> None:
    parser = argparse.ArgumentParser(description="Prompt injection detection")
    parser.add_argument("input", help="User input to analyze")
    args = parser.parse_args()

    defender = PromptInjectionDefender()
    result = defender.analyze(args.input)

    print(f"Verdict: {result['action']}")
    for finding in result["findings"]:
        print(f"  [{finding['severity']}] {finding['type']}")


if __name__ == "__main__":
    main()
```

### 2.2 Indirect Prompt Injection Defense

```python
#!/usr/bin/env python3
"""Indirect injection detection via web content"""
import re
from typing import Optional


class IndirectInjectionDetector:
    # Injection patterns hidden in web pages or documents
    HIDDEN_INJECTION_PATTERNS = [
        # HTML comments
        r"<!--.*?(ignore|instruction|system|prompt).*?-->",
        # Invisible text (CSS white text, etc.)
        r'style="[^"]*color:\s*white[^"]*"[^>]*>.*?<',
        # Zero-width space hiding
        r"[​‌‍﻿]+",
        # Markdown comments
        r"\[comment\]:.*?ignore",
        # LaTeX comments
        r"%.*?ignore.*?instructions",
    ]

    def scan_content(self, content: str) -> list[dict]:
        findings = []
        for pattern in self.HIDDEN_INJECTION_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": str(match)[:100],
                })
        return findings

    def strip_hidden_content(self, content: str) -> str:
        # Remove zero-width characters
        for char in "​‌‍﻿":
            content = content.replace(char, "")
        # Remove event handlers inside HTML tags
        content = re.sub(r'\s+on\w+="[^"]*"', "", content)
        return content


# RAG system security layer
class SecureRAGPipeline:
    def __init__(self) -> None:
        self.injection_detector = IndirectInjectionDetector()

    def process_document(self, document: str, source: str) -> Optional[str]:
        findings = self.injection_detector.scan_content(document)
        if findings:
            print(f"[!] Suspicious indirect injection patterns found in '{source}': {len(findings)} instances")
            return None  # Exclude this document

        cleaned = self.injection_detector.strip_hidden_content(document)
        max_len = 8000
        return cleaned[:max_len]
```

---

## 3. ML Model Security Assessment

### 3.1 Membership Inference Attack Detection

```python
#!/usr/bin/env python3
"""Membership inference attack vulnerability assessment"""
import argparse
import numpy as np
from typing import Callable


def membership_inference_audit(
    model_predict: Callable,
    train_samples: list,
    test_samples: list,
    n_shadow_queries: int = 100,
) -> dict:
    """
    Measure how much the model 'memorizes' training data.
    High attack success rate = overfitting and privacy risk.
    """
    train_confidences = []
    for sample in train_samples[:n_shadow_queries]:
        probs = model_predict(sample)
        train_confidences.append(max(probs))

    test_confidences = []
    for sample in test_samples[:n_shadow_queries]:
        probs = model_predict(sample)
        test_confidences.append(max(probs))

    avg_train_conf = np.mean(train_confidences)
    avg_test_conf = np.mean(test_confidences)
    confidence_gap = avg_train_conf - avg_test_conf

    # Estimate attack success rate (threshold-based)
    threshold = (avg_train_conf + avg_test_conf) / 2
    tp = sum(1 for c in train_confidences if c >= threshold)
    fp = sum(1 for c in test_confidences if c >= threshold)
    attack_accuracy = (tp + (n_shadow_queries - fp)) / (2 * n_shadow_queries)

    return {
        "train_confidence": float(avg_train_conf),
        "test_confidence": float(avg_test_conf),
        "confidence_gap": float(confidence_gap),
        "attack_accuracy": float(attack_accuracy),
        "privacy_risk": "HIGH" if confidence_gap > 0.1 else "MEDIUM" if confidence_gap > 0.05 else "LOW",
        "recommendation": "Apply differential privacy" if confidence_gap > 0.1 else "Regular monitoring recommended",
    }
```

### 3.2 Model Extraction Detection

```python
#!/usr/bin/env python3
"""ML API model extraction attack monitoring"""
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class ModelExtractionMonitor:
    query_window: int = 3600  # 1 hour
    query_threshold: int = 1000  # maximum queries
    similarity_threshold: float = 0.8  # input diversity threshold
    client_queries: dict = field(default_factory=lambda: defaultdict(list))

    def record_query(self, client_id: str, query_hash: str) -> dict:
        now = time.time()
        window_start = now - self.query_window

        # Remove queries outside window
        self.client_queries[client_id] = [
            (ts, h) for ts, h in self.client_queries[client_id]
            if ts > window_start
        ]
        self.client_queries[client_id].append((now, query_hash))

        query_count = len(self.client_queries[client_id])
        unique_queries = len(set(h for _, h in self.client_queries[client_id]))
        diversity = unique_queries / max(query_count, 1)

        is_suspicious = (
            query_count > self.query_threshold and
            diversity > self.similarity_threshold
        )

        return {
            "client_id": client_id,
            "query_count": query_count,
            "unique_count": unique_queries,
            "diversity": round(diversity, 3),
            "suspicious": is_suspicious,
            "action": "THROTTLE" if is_suspicious else "ALLOW",
        }
```

---

## 4. AI System Security Checklist

```
Input Layer:
  □ Implement prompt injection detection layer
  □ Restrict input length / token count
  □ Scan for indirect injection (RAG documents)
  □ Sandbox user inputs

Model Layer:
  □ Verify model file integrity with hashing
  □ Use secure model registry
  □ Manage training data provenance and signing
  □ Evaluate applying differential privacy training

Output Layer:
  □ Implement multi-layer content filtering
  □ PII masking (remove personal info from output)
  □ Output logging and monitoring
  □ Watermark generated content

Infrastructure Layer:
  □ API rate limiting (defend against model extraction)
  □ Monitor anomalous query patterns
  □ Harden model serving servers
  □ Supply chain verification (Hugging Face model signing)
```

| Threat | MITRE ATLAS | Mitigation Technique | Implementation Difficulty |
|--------|-------------|---------------------|--------------------------|
| Prompt Injection | AML.T0051 | Input validation, multi-layer filter | Medium |
| Model Extraction | AML.T0005 | Rate limiting, watermarking | Low |
| Data Poisoning | AML.T0020 | Data validation, integrity signing | High |
| Membership Inference | AML.T0024 | Differential privacy | High |
| Jailbreak | AML.T0054 | Red team, RLHF reinforcement | High |
| Indirect Injection | AML.T0051.000 | RAG content scanning | Medium |
