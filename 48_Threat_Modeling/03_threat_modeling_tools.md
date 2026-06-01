> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 모델링 도구 및 자동화

## 목차
1. [Microsoft Threat Modeling Tool](#microsoft-threat-modeling-tool)
2. [OWASP Threat Dragon](#owasp-threat-dragon)
3. [IriusRisk](#iriusrisk)
4. [draw.io로 DFD 작성](#drawio로-dfd-작성)
5. [Threat Modeling Manifesto](#threat-modeling-manifesto)
6. [TMT XML → HTML 보고서 스크립트](#tmt-xml--html-보고서-스크립트)
7. [CI/CD 파이프라인 통합](#cicd-파이프라인-통합)

---

## Microsoft Threat Modeling Tool

Microsoft TMT(Threat Modeling Tool)는 STRIDE 기반 위협 모델링을 지원하는 무료 데스크톱 도구다.

### 설치 및 환경

```
지원 환경: Windows 10/11
다운로드: https://aka.ms/threatmodelingtool

최신 버전: Threat Modeling Tool 2016 (7.x)
파일 형식: .tm7 (XML 기반)
```

### 주요 기능

```
1. DFD 시각적 편집기
   - 드래그 앤 드롭으로 요소 추가
   - 신뢰 경계 시각화
   - 사전 정의된 스텐실 (Web Application, Azure, Generic)

2. 자동 위협 생성
   - 요소 유형과 연결에 기반한 자동 위협 탐지
   - STRIDE per Element 자동 적용

3. 위협 관리
   - 위협 상태 추적 (Needs Investigation, Mitigated, Not Applicable)
   - 완화 방안 문서화

4. 보고서 생성
   - HTML 보고서 내보내기
   - CSV 내보내기
```

### TMT 사용 절차

```
1. 새 위협 모델 생성
   File → New → 템플릿 선택

2. 스텐실 선택
   - Web Application (웹앱 분석에 최적)
   - Azure (Azure 서비스 분석)
   - Generic (일반 시스템)

3. DFD 구성
   a. 외부 엔티티 배치 (브라우저, 외부 서비스)
   b. 프로세스 배치 (웹 서버, API, 서비스)
   c. 데이터 저장소 배치 (DB, 파일, 캐시)
   d. 데이터 흐름 연결 (화살표)
   e. 신뢰 경계 박스 설정

4. 위협 분석
   View → Analysis View
   → 자동 생성된 위협 목록 검토

5. 위협 상태 업데이트
   각 위협에 대해 상태 및 완화 방안 입력

6. 보고서 생성
   Reports → Generate Report
```

### TMT 파일 구조 (.tm7)

```xml
<?xml version="1.0" encoding="utf-8"?>
<ThreatModel Name="전자상거래 시스템">
  <DrawingSurfaceModel>
    <Elements>
      <ExternalInteractor Id="1" Name="웹 브라우저">
        <Properties>
          <Property Name="Out Of Scope" Value="false"/>
        </Properties>
      </ExternalInteractor>
      <Process Id="2" Name="웹 서버">
        <Properties>
          <Property Name="Code Type" Value="Managed"/>
          <Property Name="Implementation Languages" Value="Python"/>
          <Property Name="Out Of Scope" Value="false"/>
        </Properties>
      </Process>
      <DataStore Id="3" Name="사용자 DB">
        <Properties>
          <Property Name="Store Type" Value="SQL"/>
          <Property Name="CIA Requirements" Value="High-High-High"/>
        </Properties>
      </DataStore>
      <Flow Id="4" Name="HTTPS 요청"
            SourceGuid="1" TargetGuid="2">
        <Properties>
          <Property Name="Protocol" Value="HTTP"/>
          <Property Name="HTTP Protocol" Value="HTTPS"/>
        </Properties>
      </Flow>
    </Elements>
    <Threats>
      <Threat Id="5" Category="Spoofing" Status="Mitigated">
        <Title>웹 서버 신원 위조</Title>
        <Description>공격자가 웹 서버를 위장</Description>
        <Mitigation>mTLS 적용</Mitigation>
      </Threat>
    </Threats>
  </DrawingSurfaceModel>
</ThreatModel>
```

### 커스텀 템플릿 작성

```
TMT는 .tb7 형식의 커스텀 스텐실 지원

커스텀 위협 규칙 추가:
1. 기존 .tb7 파일 복사
2. ThreatCategories 섹션에 새 위협 추가
3. 트리거 조건 (ThreatApplicabilityCondition) 설정

유용한 커스텀 규칙:
- Kubernetes Pod: 컨테이너 탈출 위협
- API Gateway: JWT 검증 누락
- 마이크로서비스: 서비스 간 인증 미적용
```

---

## OWASP Threat Dragon

OWASP Threat Dragon은 오픈소스 위협 모델링 도구로 웹 기반과 데스크톱 버전을 제공한다.

### 설치 방법

```bash
# 방법 1: npm 글로벌 설치 (데스크톱)
npm install -g @owasp-threat-dragon/td-desktop

# 방법 2: Docker
docker pull owasp/threat-dragon:stable
docker run -d \
  -p 3000:3000 \
  -e GITHUB_CLIENT_ID=your_id \
  -e GITHUB_CLIENT_SECRET=your_secret \
  owasp/threat-dragon:stable

# 방법 3: 소스에서 빌드
git clone https://github.com/OWASP/threat-dragon
cd threat-dragon
npm install
npm start
# http://localhost:3000

# 방법 4: GitHub 연동 없이 로컬 사용
docker run -d -p 3000:3000 \
  -e NODE_ENV=production \
  -e SERVER_API_PROTOCOL=http \
  owasp/threat-dragon:stable
```

### Threat Dragon 파일 형식 (.json)

```json
{
  "summary": {
    "title": "전자상거래 위협 모델",
    "owner": "",
    "description": "REST API 기반 쇼핑몰",
    "id": 0
  },
  "detail": {
    "contributors": [],
    "diagrams": [
      {
        "title": "메인 DFD",
        "diagramType": "STRIDE",
        "id": 0,
        "cells": [
          {
            "type": "tm.Process",
            "attrs": {
              "text": { "text": "API Server" }
            },
            "threats": [
              {
                "title": "SQL Injection",
                "type": "Tampering",
                "description": "입력값 검증 없이 DB 쿼리 실행",
                "mitigation": "파라미터화 쿼리 사용",
                "modelType": "STRIDE",
                "status": "Open",
                "severity": "High"
              }
            ]
          }
        ]
      }
    ],
    "diagramTop": 0,
    "reviewer": "",
    "threatTop": 0
  }
}
```

### CLI 도구 활용

```bash
# Threat Dragon CLI 설치
pip3 install threatdragon-cli

# 위협 모델 검증
td-cli validate --model mymodel.json

# 보고서 생성
td-cli report --model mymodel.json --format pdf --output report.pdf

# 위협 목록 추출
td-cli list-threats --model mymodel.json --format csv
```

### GitHub 연동 설정

```bash
# GitHub OAuth App 생성
# Settings → Developer Settings → OAuth Apps → New OAuth App
# Homepage URL: http://localhost:3000
# Callback URL: http://localhost:3000/oauth/github

# 환경변수 설정
export GITHUB_CLIENT_ID="your_client_id"
export GITHUB_CLIENT_SECRET="your_client_secret"
export SESSION_SIGNING_KEY=$(openssl rand -hex 32)
export SESSION_ENCRYPTION_KEYS='[{"isPrimary": true, "id": 0, "value": "0123456789abcdef0123456789abcdef"}]'
```

---

## IriusRisk

IriusRisk는 엔터프라이즈급 위협 모델링 플랫폼으로, 자동화된 위협 식별과 보안 요구사항 관리를 지원한다.

### 주요 기능

```
무료 버전 (Community Edition):
- 기본 위협 모델링
- STRIDE 지원
- PDF/CSV 내보내기
- API 접근

유료 버전 (Enterprise):
- JIRA/ServiceNow 통합
- CI/CD 파이프라인 통합
- 커스텀 위협 라이브러리
- 규제 준수 매핑 (PCI-DSS, HIPAA, GDPR)
- SSO 지원

URL: https://www.iriusrisk.com
Community: https://community.iriusrisk.com
```

### IriusRisk API 활용

```bash
# API 키 설정
export IRIUS_API_KEY="your_api_key"
export IRIUS_URL="https://app.iriusrisk.com"

# 프로젝트 목록 조회
curl -s -H "api-token: $IRIUS_API_KEY" \
  "$IRIUS_URL/api/v1/products" | python3 -m json.tool

# 위협 목록 조회
curl -s -H "api-token: $IRIUS_API_KEY" \
  "$IRIUS_URL/api/v1/products/{product_id}/threats" \
  | python3 -m json.tool

# 위협 상태 업데이트
curl -X PUT \
  -H "api-token: $IRIUS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "IMPLEMENTED"}' \
  "$IRIUS_URL/api/v1/products/{product_id}/threats/{threat_id}"
```

---

## draw.io로 DFD 작성

draw.io(diagrams.net)는 무료 다이어그램 도구로 DFD 작성에 활용할 수 있다.

### 설치 및 접속

```bash
# 웹 버전: https://app.diagrams.net

# 데스크톱 버전 설치
# Windows
winget install JGraph.Draw

# Linux
wget https://github.com/jgraph/drawio-desktop/releases/latest/download/drawio-amd64-*.deb
sudo dpkg -i drawio-amd64-*.deb

# Docker
docker run -p 8080:8080 \
  -e DRAWIO_SERVER_URL=http://localhost:8080 \
  jgraph/drawio
```

### DFD 스텐실 구성

```
draw.io DFD 요소 설정:

1. 프로세스 (원/타원)
   Shape: Ellipse
   색상: 밝은 파란색 (#dae8fc)
   외곽선: 파란색 (#6c8ebf)

2. 데이터 저장소 (평행선)
   Shape: mxgraph.flowchart.annotation (또는 Cylinder)
   색상: 밝은 노란색 (#fff2cc)

3. 외부 엔티티 (직사각형)
   Shape: Rectangle
   색상: 밝은 녹색 (#d5e8d4)

4. 데이터 흐름 (화살표)
   Arrow: 실선 화살표
   레이블: 데이터 명칭 + 프로토콜

5. 신뢰 경계 (점선 박스)
   Shape: Rectangle (점선)
   Style: dashed=1;strokeColor=#FF0000;fillColor=none;
```

### DFD XML 템플릿

```xml
<mxfile>
  <diagram name="DFD - 전자상거래">
    <mxGraphModel>
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>

        <!-- 신뢰 경계 -->
        <mxCell id="tb1" value="신뢰 경계: 인터넷-DMZ"
          style="rounded=1;dashed=1;strokeColor=#FF0000;fillColor=none;
                 fontSize=12;fontStyle=1;verticalAlign=top;"
          vertex="1" parent="1">
          <mxGeometry x="10" y="10" width="600" height="400" as="geometry"/>
        </mxCell>

        <!-- 외부 엔티티: 브라우저 -->
        <mxCell id="e1" value="웹 브라우저"
          style="shape=mxgraph.dfd.externalEntity;fillColor=#d5e8d4;strokeColor=#82b366;"
          vertex="1" parent="1">
          <mxGeometry x="50" y="200" width="120" height="60" as="geometry"/>
        </mxCell>

        <!-- 프로세스: API 서버 -->
        <mxCell id="p1" value="API 서버"
          style="ellipse;fillColor=#dae8fc;strokeColor=#6c8ebf;"
          vertex="1" parent="1">
          <mxGeometry x="250" y="180" width="120" height="80" as="geometry"/>
        </mxCell>

        <!-- 데이터 저장소: DB -->
        <mxCell id="ds1" value="사용자 DB"
          style="shape=cylinder3;fillColor=#fff2cc;strokeColor=#d6b656;"
          vertex="1" parent="1">
          <mxGeometry x="450" y="180" width="120" height="80" as="geometry"/>
        </mxCell>

        <!-- 데이터 흐름 -->
        <mxCell id="df1" value="HTTPS 요청"
          style="edgeStyle=orthogonalEdgeStyle;rounded=0;"
          edge="1" source="e1" target="p1" parent="1">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>
        <mxCell id="df2" value="SQL 쿼리"
          style="edgeStyle=orthogonalEdgeStyle;rounded=0;"
          edge="1" source="p1" target="ds1" parent="1">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
```

### draw.io 활용 팁

```
위협 주석 추가:
1. 요소 우클릭 → Edit Tooltip
2. 해당 요소의 STRIDE 위협 목록 입력
3. View → Tooltips 활성화로 확인

컬러 코딩 규칙:
- 빨간 테두리: 신뢰 경계
- 주황 강조: 위협 발생 지점
- 녹색 체크: 완화 조치 적용

레이어 활용:
1. View → Layers → 새 레이어 추가
2. "위협 표시" 레이어 토글로 DFD와 위협 분리 관리

내보내기:
File → Export As → PNG/SVG/PDF
Edit → XML로 다이어그램 소스 직접 편집
```

---

## Threat Modeling Manifesto

Threat Modeling Manifesto(2020)는 15명의 위협 모델링 전문가가 합의한 핵심 원칙이다.

### 핵심 가치 (Values)

```
1. "문화와 역량 향상"을 "일회성 활동"보다 우선시한다
   → 위협 모델링은 SDLC에 지속적으로 통합되어야 함

2. "인원과 협업"을 "방법론 및 도구"보다 우선시한다
   → 올바른 사람들의 참여가 완벽한 도구보다 중요

3. "적절한 단순성 추구"를 "완전성 추구"보다 우선시한다
   → 과도한 완벽함 추구는 실행을 방해함

4. "반복적인 개선"을 "단일 완결"보다 우선시한다
   → 점진적으로 발전하는 위협 모델이 더 현실적
```

### 핵심 원칙 (Principles)

```
1. 모두가 위협 모델링을 할 수 있고 해야 한다
   - 보안 전문가만의 영역이 아님
   - 개발자, 아키텍트, QA 모두 참여

2. 위협 모델링의 목표는 최선의 결과 도출
   - "무엇을 틀릴 수 있는가?" 질문에 집중
   - 형식보다 내용이 중요

3. 다이어그램은 수단이지 목적이 아니다
   - DFD가 목적이 아니라 이해를 돕는 도구

4. 이른 시작, 지속 반복
   - 아키텍처 설계 단계부터 시작
   - 변경이 있을 때마다 업데이트

5. 위협 모델링 결과물은 실행 가능해야 한다
   - 추상적 위협 목록이 아닌 구체적 개선 행동
```

### 4가지 핵심 질문 (Four Key Questions)

```
1. 우리가 무엇을 만들고 있는가?
   (What are we building?)
   → 아키텍처 다이어그램, DFD

2. 무엇이 잘못될 수 있는가?
   (What can go wrong?)
   → STRIDE, PASTA, Attack Trees

3. 그것에 대해 무엇을 할 것인가?
   (What are we going to do about it?)
   → 완화 방안, 설계 변경, 수용

4. 우리가 충분히 했는가?
   (Did we do a good job?)
   → 위협 모델 검토, 검증
```

---

## TMT XML → HTML 보고서 스크립트

```python
#!/usr/bin/env python3
"""
Microsoft Threat Modeling Tool (.tm7) XML 파싱 및 HTML/JSON 보고서 생성

사용법:
    python3 tmt_parser.py --input model.tm7 --output report.html
    python3 tmt_parser.py --input model.tm7 --format json --output model.json
    python3 tmt_parser.py --input model.tm7 --summary
    python3 tmt_parser.py --demo --output demo_report.html
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET


@dataclass
class TmtElement:
    element_id: str
    name: str
    element_type: str  # Process, ExternalInteractor, DataStore, Flow
    properties: dict[str, str] = field(default_factory=dict)
    out_of_scope: bool = False


@dataclass
class TmtThreat:
    threat_id: str
    category: str         # Spoofing, Tampering, Repudiation, etc.
    title: str
    description: str
    mitigation: str
    status: str           # Needs Investigation, Mitigated, Not Applicable
    severity: str = "Medium"
    justification: str = ""
    affected_element: str = ""


@dataclass
class TmtModel:
    name: str = "위협 모델"
    description: str = ""
    elements: list[TmtElement] = field(default_factory=list)
    threats: list[TmtThreat] = field(default_factory=list)
    generated_at: str = ""

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()

    def get_summary(self) -> dict:
        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for threat in self.threats:
            by_category[threat.category] = by_category.get(threat.category, 0) + 1
            by_status[threat.status] = by_status.get(threat.status, 0) + 1

        return {
            "total_elements": len(self.elements),
            "total_threats": len(self.threats),
            "by_category": by_category,
            "by_status": by_status,
            "mitigated": by_status.get("Mitigated", 0),
            "needs_investigation": by_status.get("Needs Investigation", 0),
            "not_applicable": by_status.get("Not Applicable", 0),
        }


class Tm7Parser:
    """Microsoft TMT .tm7 파일 파서"""

    CATEGORY_STRIDE_MAP = {
        "Spoofing": "S - Spoofing",
        "Tampering": "T - Tampering",
        "Repudiation": "R - Repudiation",
        "Information Disclosure": "I - Information Disclosure",
        "Denial Of Service": "D - Denial of Service",
        "Elevation Of Privilege": "E - Elevation of Privilege",
    }

    def parse(self, path: Path) -> TmtModel:
        try:
            tree = ET.parse(str(path))
        except ET.ParseError as e:
            raise ValueError(f"XML 파싱 오류: {e}") from e
        except OSError as e:
            raise ValueError(f"파일 읽기 오류: {e}") from e

        root = tree.getroot()
        model_name = root.get("Name", path.stem)
        model = TmtModel(name=model_name)

        self._parse_elements(root, model)
        self._parse_threats(root, model)

        return model

    def _parse_elements(self, root: ET.Element, model: TmtModel) -> None:
        # .tm7 네임스페이스 처리
        ns_prefix = ""
        if root.tag.startswith("{"):
            ns_prefix = root.tag.split("}")[0] + "}"

        element_paths = [
            f".//{ns_prefix}ExternalInteractor",
            f".//{ns_prefix}Process",
            f".//{ns_prefix}DataStore",
            f".//{ns_prefix}Flow",
        ]

        for path in element_paths:
            for elem in root.findall(path):
                elem_id = elem.get("Id", "")
                elem_name = elem.get("Name", "알 수 없음")
                elem_type = elem.tag.replace(ns_prefix, "").replace("}", "")

                properties: dict[str, str] = {}
                out_of_scope = False

                props_elem = elem.find(f"{ns_prefix}Properties")
                if props_elem is not None:
                    for prop in props_elem.findall(f"{ns_prefix}Property"):
                        prop_name = prop.get("Name", "")
                        prop_value = prop.get("Value", "")
                        properties[prop_name] = prop_value
                        if prop_name == "Out Of Scope" and prop_value.lower() == "true":
                            out_of_scope = True

                model.elements.append(TmtElement(
                    element_id=elem_id,
                    name=elem_name,
                    element_type=elem_type,
                    properties=properties,
                    out_of_scope=out_of_scope,
                ))

    def _parse_threats(self, root: ET.Element, model: TmtModel) -> None:
        ns_prefix = ""
        if root.tag.startswith("{"):
            ns_prefix = root.tag.split("}")[0] + "}"

        for threat in root.findall(f".//{ns_prefix}Threat"):
            threat_id = threat.get("Id", "")
            category = threat.get("Category", "")
            status = threat.get("Status", "Needs Investigation")

            title_elem = threat.find(f"{ns_prefix}Title")
            desc_elem = threat.find(f"{ns_prefix}Description")
            mitigation_elem = threat.find(f"{ns_prefix}Mitigation")
            justification_elem = threat.find(f"{ns_prefix}Justification")

            model.threats.append(TmtThreat(
                threat_id=threat_id,
                category=category,
                title=title_elem.text if title_elem is not None else "제목 없음",
                description=desc_elem.text if desc_elem is not None else "",
                mitigation=mitigation_elem.text if mitigation_elem is not None else "",
                justification=justification_elem.text if justification_elem is not None else "",
                status=status,
            ))


class TmtReportGenerator:
    """TmtModel → HTML/JSON 보고서 생성기"""

    STATUS_COLORS = {
        "Mitigated": "#28a745",
        "Needs Investigation": "#dc3545",
        "Not Applicable": "#6c757d",
    }

    CATEGORY_COLORS = {
        "Spoofing": "#6610f2",
        "Tampering": "#fd7e14",
        "Repudiation": "#20c997",
        "Information Disclosure": "#17a2b8",
        "Denial Of Service": "#dc3545",
        "Elevation Of Privilege": "#e83e8c",
    }

    def __init__(self, model: TmtModel) -> None:
        self.model = model

    def generate_html(self) -> str:
        summary = self.model.get_summary()

        # 요소 테이블
        element_rows = []
        for elem in self.model.elements:
            scope_label = "제외" if elem.out_of_scope else "포함"
            scope_color = "#6c757d" if elem.out_of_scope else "#28a745"
            element_rows.append(
                f"<tr>"
                f"<td>{elem.element_id}</td>"
                f"<td><strong>{elem.name}</strong></td>"
                f"<td>{elem.element_type}</td>"
                f"<td><span style='color:{scope_color}'>{scope_label}</span></td>"
                f"</tr>"
            )

        # 위협 테이블
        threat_rows = []
        for threat in self.model.threats:
            status_color = self.STATUS_COLORS.get(threat.status, "#333")
            cat_color = self.CATEGORY_COLORS.get(threat.category, "#333")

            threat_rows.append(
                f"<tr>"
                f"<td>{threat.threat_id}</td>"
                f"<td><span style='color:{cat_color};font-weight:bold'>"
                f"{threat.category}</span></td>"
                f"<td>{threat.title}</td>"
                f"<td>{threat.description or '-'}</td>"
                f"<td>{threat.mitigation or '<span style=\"color:#dc3545\">미완화</span>'}</td>"
                f"<td><span style='color:{status_color};font-weight:bold'>"
                f"{threat.status}</span></td>"
                f"</tr>"
            )

        # 통계 카드
        stat_cards = []
        for cat, count in summary["by_category"].items():
            color = self.CATEGORY_COLORS.get(cat, "#6c757d")
            stat_cards.append(
                f"<div style='display:inline-block;margin:8px;padding:12px;"
                f"background:{color}22;border-left:4px solid {color};"
                f"min-width:160px;border-radius:4px'>"
                f"<div style='font-size:1.8em;font-weight:bold;color:{color}'>{count}</div>"
                f"<div style='font-size:0.85em;color:#555'>{cat}</div>"
                f"</div>"
            )

        # 완화율 계산
        total = summary["total_threats"]
        mitigated = summary["mitigated"]
        mitigation_rate = (mitigated / total * 100) if total > 0 else 0

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>위협 모델 보고서 - {self.model.name}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Malgun Gothic', Arial, sans-serif; background: #f4f6f9; color: #333; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e);
             color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
  .header h1 {{ font-size: 1.8em; margin-bottom: 5px; }}
  .header p {{ color: #aaa; font-size: 0.9em; }}
  .card {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px;
           box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .progress-bar {{ background: #e9ecef; border-radius: 10px; height: 20px; margin: 10px 0; }}
  .progress-fill {{ background: linear-gradient(90deg, #28a745, #20c997);
                    height: 100%; border-radius: 10px; transition: width 0.3s; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #343a40; color: white; padding: 12px 10px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #dee2e6; vertical-align: top; }}
  tr:hover {{ background: #f8f9fa; }}
  .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px;
            font-size: 0.8em; font-weight: bold; }}
  h2 {{ font-size: 1.2em; margin-bottom: 15px; color: #333; border-bottom: 2px solid #007bff;
        padding-bottom: 8px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>위협 모델 보고서: {self.model.name}</h1>
    <p>생성 일시: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')}</p>
    <p>{self.model.description}</p>
  </div>

  <div class="card">
    <h2>요약</h2>
    <p>총 요소: <strong>{summary['total_elements']}</strong> |
       총 위협: <strong>{summary['total_threats']}</strong> |
       완화율: <strong>{mitigation_rate:.1f}%</strong></p>
    <div class="progress-bar">
      <div class="progress-fill" style="width:{mitigation_rate:.1f}%"></div>
    </div>
    <p style="margin-top:10px">
      <span style="color:#dc3545">미해결: {summary['needs_investigation']}</span> |
      <span style="color:#28a745">완화됨: {summary['mitigated']}</span> |
      <span style="color:#6c757d">해당없음: {summary['not_applicable']}</span>
    </p>
  </div>

  <div class="card">
    <h2>STRIDE 범주별 위협 분포</h2>
    {''.join(stat_cards)}
  </div>

  <div class="card">
    <h2>DFD 요소 목록</h2>
    <table>
    <tr><th>ID</th><th>이름</th><th>유형</th><th>범위</th></tr>
    {''.join(element_rows)}
    </table>
  </div>

  <div class="card">
    <h2>위협 목록</h2>
    <table>
    <tr>
      <th>ID</th><th>범주</th><th>위협명</th><th>설명</th><th>완화 방안</th><th>상태</th>
    </tr>
    {''.join(threat_rows)}
    </table>
  </div>
</div>
</body>
</html>"""

    def generate_json(self) -> str:
        summary = self.model.get_summary()
        return json.dumps({
            "metadata": {
                "model_name": self.model.name,
                "description": self.model.description,
                "generated_at": datetime.now().isoformat(),
            },
            "summary": summary,
            "elements": [
                {
                    "id": e.element_id,
                    "name": e.name,
                    "type": e.element_type,
                    "out_of_scope": e.out_of_scope,
                    "properties": e.properties,
                }
                for e in self.model.elements
            ],
            "threats": [
                {
                    "id": t.threat_id,
                    "category": t.category,
                    "title": t.title,
                    "description": t.description,
                    "mitigation": t.mitigation,
                    "status": t.status,
                    "justification": t.justification,
                }
                for t in self.model.threats
            ],
        }, ensure_ascii=False, indent=2)

    def generate_markdown(self) -> str:
        summary = self.model.get_summary()
        lines = [
            f"# 위협 모델 보고서: {self.model.name}",
            f"\n생성: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"\n## 요약\n",
            f"- 총 위협: {summary['total_threats']}",
            f"- 미해결: {summary['needs_investigation']}",
            f"- 완화됨: {summary['mitigated']}",
            f"\n## STRIDE 범주별\n",
        ]
        for cat, count in summary["by_category"].items():
            lines.append(f"- {cat}: {count}건")

        lines.append("\n## 위협 목록\n")
        for threat in self.model.threats:
            lines.extend([
                f"### {threat.threat_id}: {threat.title}",
                f"- **범주**: {threat.category}",
                f"- **상태**: {threat.status}",
                f"- **설명**: {threat.description or '-'}",
                f"- **완화**: {threat.mitigation or '미완화'}",
                "",
            ])

        return "\n".join(lines)


def create_demo_model() -> TmtModel:
    """데모 위협 모델 생성"""
    model = TmtModel(
        name="전자상거래 시스템 (Demo)",
        description="REST API 기반 전자상거래 플랫폼 위협 모델",
    )

    elements = [
        TmtElement("E001", "웹 브라우저", "ExternalInteractor"),
        TmtElement("P001", "API Gateway", "Process",
                   properties={"Technology": "Kong", "Runs As": "Standard User"}),
        TmtElement("P002", "인증 서비스", "Process",
                   properties={"Technology": "FastAPI", "Runs As": "Standard User"}),
        TmtElement("P003", "주문 서비스", "Process",
                   properties={"Technology": "FastAPI"}),
        TmtElement("DS001", "사용자 DB", "DataStore",
                   properties={"Store Type": "SQL", "Encrypted": "Yes"}),
        TmtElement("DS002", "세션 캐시", "DataStore",
                   properties={"Store Type": "Redis"}),
        TmtElement("F001", "HTTPS 요청", "Flow"),
        TmtElement("F002", "DB 쿼리", "Flow"),
        TmtElement("E002", "결제 게이트웨이", "ExternalInteractor"),
    ]

    threats = [
        TmtThreat("T001", "Spoofing", "세션 토큰 탈취로 사용자 위장",
                  "공격자가 XSS를 통해 세션 쿠키 탈취 후 피해자로 위장",
                  "HttpOnly/Secure 쿠키 설정, CSP 헤더 적용",
                  "Mitigated"),
        TmtThreat("T002", "Tampering", "주문 금액 파라미터 변조",
                  "클라이언트 측 금액 파라미터를 조작하여 낮은 가격으로 결제",
                  "서버 측 금액 재계산, 서명된 결제 요청",
                  "Needs Investigation"),
        TmtThreat("T003", "Repudiation", "주문 취소 감사 로그 미비",
                  "악의적 관리자가 주문 강제 취소 후 부인",
                  "불변 감사 로그 구현, SIEM 연동",
                  "Needs Investigation"),
        TmtThreat("T004", "Information Disclosure", "API 에러 메시지 정보 노출",
                  "500 에러 시 스택 트레이스에 DB 구조 노출",
                  "제네릭 에러 메시지 반환, 에러 로깅 분리",
                  "Mitigated"),
        TmtThreat("T005", "Denial Of Service", "로그인 API 브루트포스",
                  "Rate Limit 미적용으로 자격증명 브루트포스 가능",
                  "Rate Limiting 5 req/min, 계정 잠금 정책",
                  "Needs Investigation"),
        TmtThreat("T006", "Elevation Of Privilege", "IDOR로 관리자 API 접근",
                  "일반 사용자가 /api/admin/* 엔드포인트에 직접 접근",
                  "모든 API에 역할 기반 접근 제어(RBAC) 적용",
                  "Mitigated"),
        TmtThreat("T007", "Spoofing", "내부 서비스 간 mTLS 미적용",
                  "내부 마이크로서비스 간 통신에 인증 없음",
                  "서비스 메시(Istio) 배포, mTLS 강제 적용",
                  "Not Applicable"),
        TmtThreat("T008", "Information Disclosure", "환경변수 노출",
                  "/health 엔드포인트에서 DB 연결 문자열 노출",
                  "환경변수 필터링, Secret Manager 사용",
                  "Needs Investigation"),
    ]

    for elem in elements:
        model.elements.append(elem)
    for threat in threats:
        model.threats.append(threat)

    return model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TMT 위협 모델 파서 및 보고서 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s --input model.tm7 --output report.html
  %(prog)s --input model.tm7 --format json --output model.json
  %(prog)s --demo --output demo_report.html
  %(prog)s --input model.tm7 --summary
        """,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--input", type=Path, help=".tm7 파일 경로")
    source_group.add_argument("--demo", action="store_true", help="데모 모델 사용")

    parser.add_argument(
        "--format", choices=["html", "json", "markdown"], default="html",
        help="출력 형식",
    )
    parser.add_argument("--output", type=Path, help="출력 파일 경로")
    parser.add_argument("--summary", action="store_true", help="요약만 출력")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.demo:
        model = create_demo_model()
        print(f"데모 모델 생성: {model.name}")
    else:
        parser = Tm7Parser()
        try:
            model = parser.parse(args.input)
            print(f"모델 로드 완료: {model.name}")
        except ValueError as e:
            print(f"오류: {e}", file=sys.stderr)
            return 1

    summary = model.get_summary()
    print(f"\n=== 모델 요약 ===")
    print(f"  총 요소: {summary['total_elements']}")
    print(f"  총 위협: {summary['total_threats']}")
    print(f"  미해결: {summary['needs_investigation']}")
    print(f"  완화됨: {summary['mitigated']}")
    print(f"  해당없음: {summary['not_applicable']}")

    if args.summary:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if not args.output:
        suffix = {"html": ".html", "json": ".json", "markdown": ".md"}.get(args.format, ".txt")
        args.output = Path(f"threat_model_report{suffix}")

    generator = TmtReportGenerator(model)
    try:
        if args.format == "html":
            content = generator.generate_html()
        elif args.format == "json":
            content = generator.generate_json()
        else:
            content = generator.generate_markdown()

        args.output.write_text(content, encoding="utf-8")
        print(f"\n보고서 저장: {args.output}")
    except OSError as e:
        print(f"저장 실패: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 실행 방법

```bash
# 데모 HTML 보고서
python3 tmt_parser.py --demo --output demo_report.html

# 실제 .tm7 파일 파싱
python3 tmt_parser.py --input mymodel.tm7 --output report.html

# JSON 형식 출력
python3 tmt_parser.py --input mymodel.tm7 --format json --output model.json

# 요약만 출력
python3 tmt_parser.py --demo --summary
```

---

## CI/CD 파이프라인 통합

### GitHub Actions 통합

```yaml
# .github/workflows/threat-model.yml
name: Threat Model Validation

on:
  push:
    paths:
      - 'threat-models/**'
      - 'architecture/**'
  pull_request:
    branches: [main]

jobs:
  validate-threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Python 환경 설정
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: 의존성 설치
        run: pip install -r requirements-security.txt

      - name: 위협 모델 검증
        run: |
          python3 tmt_parser.py \
            --input threat-models/main.tm7 \
            --format json \
            --output /tmp/threat_model.json
          
          python3 scripts/validate_threats.py \
            --input /tmp/threat_model.json \
            --fail-on-unmitigated

      - name: HTML 보고서 생성
        run: |
          python3 tmt_parser.py \
            --input threat-models/main.tm7 \
            --format html \
            --output threat_report.html

      - name: 보고서 아티팩트 저장
        uses: actions/upload-artifact@v4
        with:
          name: threat-model-report
          path: threat_report.html
          retention-days: 30

  check-new-threats:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: 새 위협 검사
        run: |
          # PR에서 추가된 위협이 모두 완화 상태인지 확인
          python3 scripts/check_pr_threats.py \
            --base-branch main \
            --fail-on-new-unmitigated
```

### 위협 검증 스크립트

```python
#!/usr/bin/env python3
"""CI/CD용 위협 모델 검증 스크립트"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def validate_threats(input_path: Path, fail_on_unmitigated: bool = True) -> int:
    """위협 모델 JSON 검증 - 미완화 위협 확인"""
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"파일 로드 실패: {e}", file=sys.stderr)
        return 1

    threats = data.get("threats", [])
    unmitigated = [
        t for t in threats
        if t.get("status") == "Needs Investigation"
    ]

    print(f"총 위협: {len(threats)}")
    print(f"미해결 위협: {len(unmitigated)}")

    if unmitigated:
        print("\n⚠ 미해결 위협 목록:")
        for t in unmitigated:
            print(f"  - [{t.get('id')}] {t.get('title')} ({t.get('category')})")

        if fail_on_unmitigated:
            print("\n✗ 미해결 위협이 있어 빌드를 실패합니다.")
            return 1

    print("\n✓ 위협 모델 검증 완료")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="위협 모델 검증")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--fail-on-unmitigated", action="store_true")
    args = parser.parse_args()
    return validate_threats(args.input, args.fail_on_unmitigated)


if __name__ == "__main__":
    sys.exit(main())
```

### pre-commit 훅 통합

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: threat-model-check
        name: 위협 모델 검증
        entry: python3 scripts/validate_threats.py
        language: python
        files: '\.tm7$|threat_model\.json$'
        args: ["--input", "threat-models/main.tm7"]
        pass_filenames: false
```

### 파이프라인 통합 전략

```
DevSecOps 통합 단계:

1. 설계 단계 (Design Phase)
   - 아키텍처 변경 시 위협 모델 업데이트 필수
   - PR 템플릿에 위협 모델 체크리스트 추가

2. 개발 단계 (Development Phase)
   - 코드 리뷰 시 새 기능에 대한 위협 검토
   - SAST 도구와 위협 모델 연계

3. 테스트 단계 (Testing Phase)
   - 위협 모델의 각 위협에 대한 보안 테스트 케이스 생성
   - 완화 방안 검증

4. 배포 단계 (Deployment Phase)
   - 미완화 Critical/High 위협 있으면 배포 차단
   - 위협 모델 버전을 코드 버전과 함께 태그

5. 운영 단계 (Operations Phase)
   - 새 CVE 발견 시 위협 모델 재검토
   - 분기별 위협 모델 리뷰
```

---

## 참고 자료

- [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [IriusRisk Community](https://community.iriusrisk.com)
- [draw.io / diagrams.net](https://app.diagrams.net)
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org)
- [OWASP 위협 모델링 치트 시트](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)

---

<a name="english"></a>

# Threat Modeling Tools and Automation

## Table of Contents
1. [Microsoft Threat Modeling Tool](#microsoft-threat-modeling-tool-en)
2. [OWASP Threat Dragon](#owasp-threat-dragon-en)
3. [IriusRisk](#iriusrisk-en)
4. [Creating DFDs with draw.io](#creating-dfds-with-drawio)
5. [Threat Modeling Manifesto](#threat-modeling-manifesto-en)
6. [TMT XML → HTML Report Script](#tmt-xml--html-report-script)
7. [CI/CD Pipeline Integration](#cicd-pipeline-integration)

---

<a name="microsoft-threat-modeling-tool-en"></a>
## Microsoft Threat Modeling Tool

Microsoft TMT (Threat Modeling Tool) is a free desktop tool that supports STRIDE-based threat modeling.

### Installation and Environment

```
Supported OS: Windows 10/11
Download: https://aka.ms/threatmodelingtool

Latest version: Threat Modeling Tool 2016 (7.x)
File format: .tm7 (XML-based)
```

### Key Features

```
1. Visual DFD Editor
   - Add elements via drag and drop
   - Visualize trust boundaries
   - Pre-defined stencils (Web Application, Azure, Generic)

2. Automatic Threat Generation
   - Automatic threat detection based on element types and connections
   - Automatic application of STRIDE per Element

3. Threat Management
   - Track threat status (Needs Investigation, Mitigated, Not Applicable)
   - Document mitigations

4. Report Generation
   - Export HTML reports
   - Export CSV
```

### TMT Usage Procedure

```
1. Create a new threat model
   File → New → Select template

2. Select stencil
   - Web Application (optimal for web app analysis)
   - Azure (Azure service analysis)
   - Generic (general systems)

3. Build DFD
   a. Place external entities (browser, external services)
   b. Place processes (web server, API, services)
   c. Place data stores (DB, files, cache)
   d. Connect data flows (arrows)
   e. Set trust boundary boxes

4. Threat analysis
   View → Analysis View
   → Review auto-generated threat list

5. Update threat status
   Enter status and mitigation for each threat

6. Generate report
   Reports → Generate Report
```

### TMT File Structure (.tm7)

```xml
<?xml version="1.0" encoding="utf-8"?>
<ThreatModel Name="E-commerce System">
  <DrawingSurfaceModel>
    <Elements>
      <ExternalInteractor Id="1" Name="Web Browser">
        <Properties>
          <Property Name="Out Of Scope" Value="false"/>
        </Properties>
      </ExternalInteractor>
      <Process Id="2" Name="Web Server">
        <Properties>
          <Property Name="Code Type" Value="Managed"/>
          <Property Name="Implementation Languages" Value="Python"/>
          <Property Name="Out Of Scope" Value="false"/>
        </Properties>
      </Process>
      <DataStore Id="3" Name="User DB">
        <Properties>
          <Property Name="Store Type" Value="SQL"/>
          <Property Name="CIA Requirements" Value="High-High-High"/>
        </Properties>
      </DataStore>
      <Flow Id="4" Name="HTTPS Request"
            SourceGuid="1" TargetGuid="2">
        <Properties>
          <Property Name="Protocol" Value="HTTP"/>
          <Property Name="HTTP Protocol" Value="HTTPS"/>
        </Properties>
      </Flow>
    </Elements>
    <Threats>
      <Threat Id="5" Category="Spoofing" Status="Mitigated">
        <Title>Web Server Identity Spoofing</Title>
        <Description>Attacker impersonates the web server</Description>
        <Mitigation>Apply mTLS</Mitigation>
      </Threat>
    </Threats>
  </DrawingSurfaceModel>
</ThreatModel>
```

### Custom Template Creation

```
TMT supports custom stencils in .tb7 format

Adding custom threat rules:
1. Copy existing .tb7 file
2. Add new threats to ThreatCategories section
3. Set trigger conditions (ThreatApplicabilityCondition)

Useful custom rules:
- Kubernetes Pod: container escape threats
- API Gateway: missing JWT validation
- Microservices: no inter-service authentication
```

---

<a name="owasp-threat-dragon-en"></a>
## OWASP Threat Dragon

OWASP Threat Dragon is an open-source threat modeling tool providing both web-based and desktop versions.

### Installation

```bash
# Method 1: npm global install (desktop)
npm install -g @owasp-threat-dragon/td-desktop

# Method 2: Docker
docker pull owasp/threat-dragon:stable
docker run -d \
  -p 3000:3000 \
  -e GITHUB_CLIENT_ID=your_id \
  -e GITHUB_CLIENT_SECRET=your_secret \
  owasp/threat-dragon:stable

# Method 3: Build from source
git clone https://github.com/OWASP/threat-dragon
cd threat-dragon
npm install
npm start
# http://localhost:3000

# Method 4: Local use without GitHub integration
docker run -d -p 3000:3000 \
  -e NODE_ENV=production \
  -e SERVER_API_PROTOCOL=http \
  owasp/threat-dragon:stable
```

### Threat Dragon File Format (.json)

```json
{
  "summary": {
    "title": "E-commerce Threat Model",
    "owner": "",
    "description": "REST API-based online shop",
    "id": 0
  },
  "detail": {
    "contributors": [],
    "diagrams": [
      {
        "title": "Main DFD",
        "diagramType": "STRIDE",
        "id": 0,
        "cells": [
          {
            "type": "tm.Process",
            "attrs": {
              "text": { "text": "API Server" }
            },
            "threats": [
              {
                "title": "SQL Injection",
                "type": "Tampering",
                "description": "Execute DB query without input validation",
                "mitigation": "Use parameterized queries",
                "modelType": "STRIDE",
                "status": "Open",
                "severity": "High"
              }
            ]
          }
        ]
      }
    ],
    "diagramTop": 0,
    "reviewer": "",
    "threatTop": 0
  }
}
```

### CLI Tool Usage

```bash
# Install Threat Dragon CLI
pip3 install threatdragon-cli

# Validate threat model
td-cli validate --model mymodel.json

# Generate report
td-cli report --model mymodel.json --format pdf --output report.pdf

# Extract threat list
td-cli list-threats --model mymodel.json --format csv
```

### GitHub Integration Setup

```bash
# Create GitHub OAuth App
# Settings → Developer Settings → OAuth Apps → New OAuth App
# Homepage URL: http://localhost:3000
# Callback URL: http://localhost:3000/oauth/github

# Set environment variables
export GITHUB_CLIENT_ID="your_client_id"
export GITHUB_CLIENT_SECRET="your_client_secret"
export SESSION_SIGNING_KEY=$(openssl rand -hex 32)
export SESSION_ENCRYPTION_KEYS='[{"isPrimary": true, "id": 0, "value": "0123456789abcdef0123456789abcdef"}]'
```

---

<a name="iriusrisk-en"></a>
## IriusRisk

IriusRisk is an enterprise-grade threat modeling platform supporting automated threat identification and security requirements management.

### Key Features

```
Free Version (Community Edition):
- Basic threat modeling
- STRIDE support
- PDF/CSV export
- API access

Paid Version (Enterprise):
- JIRA/ServiceNow integration
- CI/CD pipeline integration
- Custom threat library
- Regulatory compliance mapping (PCI-DSS, HIPAA, GDPR)
- SSO support

URL: https://www.iriusrisk.com
Community: https://community.iriusrisk.com
```

### IriusRisk API Usage

```bash
# Set API key
export IRIUS_API_KEY="your_api_key"
export IRIUS_URL="https://app.iriusrisk.com"

# List projects
curl -s -H "api-token: $IRIUS_API_KEY" \
  "$IRIUS_URL/api/v1/products" | python3 -m json.tool

# List threats
curl -s -H "api-token: $IRIUS_API_KEY" \
  "$IRIUS_URL/api/v1/products/{product_id}/threats" \
  | python3 -m json.tool

# Update threat status
curl -X PUT \
  -H "api-token: $IRIUS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "IMPLEMENTED"}' \
  "$IRIUS_URL/api/v1/products/{product_id}/threats/{threat_id}"
```

---

<a name="creating-dfds-with-drawio"></a>
## Creating DFDs with draw.io

draw.io (diagrams.net) is a free diagramming tool that can be used to create DFDs.

### Installation and Access

```bash
# Web version: https://app.diagrams.net

# Desktop version installation
# Windows
winget install JGraph.Draw

# Linux
wget https://github.com/jgraph/drawio-desktop/releases/latest/download/drawio-amd64-*.deb
sudo dpkg -i drawio-amd64-*.deb

# Docker
docker run -p 8080:8080 \
  -e DRAWIO_SERVER_URL=http://localhost:8080 \
  jgraph/drawio
```

### DFD Stencil Configuration

```
draw.io DFD element settings:

1. Process (circle/ellipse)
   Shape: Ellipse
   Color: light blue (#dae8fc)
   Border: blue (#6c8ebf)

2. Data Store (parallel lines)
   Shape: mxgraph.flowchart.annotation (or Cylinder)
   Color: light yellow (#fff2cc)

3. External Entity (rectangle)
   Shape: Rectangle
   Color: light green (#d5e8d4)

4. Data Flow (arrow)
   Arrow: solid arrow
   Label: data name + protocol

5. Trust Boundary (dashed box)
   Shape: Rectangle (dashed)
   Style: dashed=1;strokeColor=#FF0000;fillColor=none;
```

### DFD XML Template

```xml
<mxfile>
  <diagram name="DFD - E-commerce">
    <mxGraphModel>
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>

        <!-- Trust boundary -->
        <mxCell id="tb1" value="Trust Boundary: Internet-DMZ"
          style="rounded=1;dashed=1;strokeColor=#FF0000;fillColor=none;
                 fontSize=12;fontStyle=1;verticalAlign=top;"
          vertex="1" parent="1">
          <mxGeometry x="10" y="10" width="600" height="400" as="geometry"/>
        </mxCell>

        <!-- External entity: Browser -->
        <mxCell id="e1" value="Web Browser"
          style="shape=mxgraph.dfd.externalEntity;fillColor=#d5e8d4;strokeColor=#82b366;"
          vertex="1" parent="1">
          <mxGeometry x="50" y="200" width="120" height="60" as="geometry"/>
        </mxCell>

        <!-- Process: API Server -->
        <mxCell id="p1" value="API Server"
          style="ellipse;fillColor=#dae8fc;strokeColor=#6c8ebf;"
          vertex="1" parent="1">
          <mxGeometry x="250" y="180" width="120" height="80" as="geometry"/>
        </mxCell>

        <!-- Data store: DB -->
        <mxCell id="ds1" value="User DB"
          style="shape=cylinder3;fillColor=#fff2cc;strokeColor=#d6b656;"
          vertex="1" parent="1">
          <mxGeometry x="450" y="180" width="120" height="80" as="geometry"/>
        </mxCell>

        <!-- Data flows -->
        <mxCell id="df1" value="HTTPS Request"
          style="edgeStyle=orthogonalEdgeStyle;rounded=0;"
          edge="1" source="e1" target="p1" parent="1">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>
        <mxCell id="df2" value="SQL Query"
          style="edgeStyle=orthogonalEdgeStyle;rounded=0;"
          edge="1" source="p1" target="ds1" parent="1">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
```

### draw.io Usage Tips

```
Adding threat annotations:
1. Right-click element → Edit Tooltip
2. Enter the STRIDE threat list for that element
3. View → Tooltips to verify

Color-coding rules:
- Red border: trust boundary
- Orange highlight: threat occurrence point
- Green check: mitigation applied

Using layers:
1. View → Layers → Add new layer
2. Toggle "Show Threats" layer to separately manage DFD and threats

Export:
File → Export As → PNG/SVG/PDF
Edit → XML to directly edit diagram source
```

---

<a name="threat-modeling-manifesto-en"></a>
## Threat Modeling Manifesto

The Threat Modeling Manifesto (2020) represents core principles agreed upon by 15 threat modeling experts.

### Core Values

```
1. "A culture of security" over "a compliance checkbox"
   → Threat modeling must be continuously integrated into the SDLC

2. "People and collaboration" over "methodology and tools"
   → The right people's participation matters more than perfect tools

3. "Appropriate simplification" over "perfection"
   → Pursuing excessive perfection hinders execution

4. "Iterative improvement" over "single delivery"
   → An incrementally evolving threat model is more realistic
```

### Core Principles

```
1. Everyone can and should do threat modeling
   - Not the exclusive domain of security professionals
   - Developers, architects, and QA all participate

2. The goal of threat modeling is to produce the best outcomes
   - Focus on the question "What can go wrong?"
   - Substance matters more than form

3. Diagrams are a means, not an end
   - DFDs are a tool to aid understanding, not the goal itself

4. Start early, iterate continuously
   - Begin at the architecture design phase
   - Update whenever changes occur

5. Threat modeling outputs must be actionable
   - Concrete improvement actions, not abstract threat lists
```

### Four Key Questions

```
1. What are we building?
   → Architecture diagrams, DFDs

2. What can go wrong?
   → STRIDE, PASTA, Attack Trees

3. What are we going to do about it?
   → Mitigations, design changes, acceptance

4. Did we do a good job?
   → Threat model review, validation
```

---

<a name="tmt-xml--html-report-script"></a>
## TMT XML → HTML Report Script

```python
#!/usr/bin/env python3
"""
Microsoft Threat Modeling Tool (.tm7) XML parser and HTML/JSON report generator

Usage:
    python3 tmt_parser.py --input model.tm7 --output report.html
    python3 tmt_parser.py --input model.tm7 --format json --output model.json
    python3 tmt_parser.py --input model.tm7 --summary
    python3 tmt_parser.py --demo --output demo_report.html
"""
# (See Korean section for full source code — identical implementation)
```

### Running the Script

```bash
# Demo HTML report
python3 tmt_parser.py --demo --output demo_report.html

# Parse actual .tm7 file
python3 tmt_parser.py --input mymodel.tm7 --output report.html

# JSON format output
python3 tmt_parser.py --input mymodel.tm7 --format json --output model.json

# Summary only
python3 tmt_parser.py --demo --summary
```

---

<a name="cicd-pipeline-integration"></a>
## CI/CD Pipeline Integration

### GitHub Actions Integration

```yaml
# .github/workflows/threat-model.yml
name: Threat Model Validation

on:
  push:
    paths:
      - 'threat-models/**'
      - 'architecture/**'
  pull_request:
    branches: [main]

jobs:
  validate-threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python environment
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements-security.txt

      - name: Validate threat model
        run: |
          python3 tmt_parser.py \
            --input threat-models/main.tm7 \
            --format json \
            --output /tmp/threat_model.json
          
          python3 scripts/validate_threats.py \
            --input /tmp/threat_model.json \
            --fail-on-unmitigated

      - name: Generate HTML report
        run: |
          python3 tmt_parser.py \
            --input threat-models/main.tm7 \
            --format html \
            --output threat_report.html

      - name: Save report artifact
        uses: actions/upload-artifact@v4
        with:
          name: threat-model-report
          path: threat_report.html
          retention-days: 30

  check-new-threats:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Check for new threats
        run: |
          # Verify that all threats added in the PR are in mitigated state
          python3 scripts/check_pr_threats.py \
            --base-branch main \
            --fail-on-new-unmitigated
```

### Threat Validation Script

```python
#!/usr/bin/env python3
"""Threat model validation script for CI/CD"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def validate_threats(input_path: Path, fail_on_unmitigated: bool = True) -> int:
    """Validate threat model JSON — check for unmitigated threats"""
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Failed to load file: {e}", file=sys.stderr)
        return 1

    threats = data.get("threats", [])
    unmitigated = [
        t for t in threats
        if t.get("status") == "Needs Investigation"
    ]

    print(f"Total threats: {len(threats)}")
    print(f"Unmitigated threats: {len(unmitigated)}")

    if unmitigated:
        print("\nUnmitigated threat list:")
        for t in unmitigated:
            print(f"  - [{t.get('id')}] {t.get('title')} ({t.get('category')})")

        if fail_on_unmitigated:
            print("\nBuild failed due to unmitigated threats.")
            return 1

    print("\nThreat model validation complete.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Threat model validation")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--fail-on-unmitigated", action="store_true")
    args = parser.parse_args()
    return validate_threats(args.input, args.fail_on_unmitigated)


if __name__ == "__main__":
    sys.exit(main())
```

### pre-commit Hook Integration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: threat-model-check
        name: Threat model validation
        entry: python3 scripts/validate_threats.py
        language: python
        files: '\.tm7$|threat_model\.json$'
        args: ["--input", "threat-models/main.tm7"]
        pass_filenames: false
```

### Pipeline Integration Strategy

```
DevSecOps integration phases:

1. Design Phase
   - Mandatory threat model update when architecture changes
   - Add threat model checklist to PR template

2. Development Phase
   - Review threats for new features during code review
   - Link SAST tools with threat model

3. Testing Phase
   - Create security test cases for each threat in the threat model
   - Validate mitigations

4. Deployment Phase
   - Block deployment if unmitigated Critical/High threats exist
   - Tag threat model version alongside code version

5. Operations Phase
   - Re-examine threat model when new CVEs are discovered
   - Quarterly threat model review
```

---

## References

- [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [IriusRisk Community](https://community.iriusrisk.com)
- [draw.io / diagrams.net](https://app.diagrams.net)
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
