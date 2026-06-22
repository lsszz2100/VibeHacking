> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 설치 가이드 — VibeHacking CLI & 실습 환경

## 목차

1. [시스템 요구사항](#1-시스템-요구사항)
2. [빠른 시작 (3단계)](#2-빠른-시작-3단계)
3. [상세 설치 — Linux/macOS](#3-상세-설치--linuxmacos)
4. [상세 설치 — Windows (WSL2)](#4-상세-설치--windows-wsl2)
5. [상세 설치 — Windows (PowerShell)](#5-상세-설치--windows-powershell)
6. [Docker 실습 환경 설치](#6-docker-실습-환경-설치)
7. [설치 확인 및 문제 해결](#7-설치-확인-및-문제-해결)
8. [권장 추가 도구](#8-권장-추가-도구)

---

## 1. 시스템 요구사항

| 항목 | 최소 | 권장 |
|------|------|------|
| **운영체제** | Linux / macOS / Windows 10+ | Ubuntu 22.04 / Kali Linux |
| **Python** | 3.10+ | 3.12+ |
| **Docker** | 20.10+ (실습 환경용) | 24.x + |
| **Docker Compose** | v2.0+ | v2.x |
| **RAM** | 2 GB (CLI만) | 8 GB (전체 랩) |
| **디스크** | 500 MB (CLI) | 20 GB (전체 랩 이미지) |
| **git** | 2.x | 최신 |

> **Note:** CLI(`vhack.py`)는 Python 표준 라이브러리만 사용하므로 `pip install` 없이도 동작합니다.

---

## 2. 빠른 시작 (3단계)

```bash
# 1. 저장소 클론
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking

# 2. alias 등록 → 어디서나 vhack 으로 사용
python3 vhack.py alias install
source ~/.bashrc          # 현재 세션 즉시 적용 (zsh: source ~/.zshrc)

# 3. (선택) 웹 해킹 실습 환경 시작 — Docker 필요
vhack lab start 01
# → DVWA: http://localhost:8080/dvwa/  Juice Shop: http://localhost:3001  WebGoat: http://localhost:8081/WebGoat
```

---

## 3. 상세 설치 — Linux/macOS

### 3-1. Python 3.10+ 설치

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y python3 python3-pip git

# macOS (Homebrew)
brew install python3 git

# 버전 확인
python3 --version   # Python 3.10.x 이상
```

### 3-2. 저장소 클론

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
```

### 3-3. (선택) vhack 명령어를 어디서든 실행

```bash
# 권장: alias 자동 등록 명령어 (셸 자동 감지)
python3 vhack.py alias install
source ~/.bashrc      # bash 즉시 적용
# source ~/.zshrc     # zsh인 경우

# 이후 어디서나 사용 가능
vhack list
vhack study 5

# 현황 확인
vhack alias status

# 제거가 필요한 경우
vhack alias remove
```

> `alias install` 은 `$SHELL` 환경변수로 현재 셸을 자동 감지하고
> (`bash` → `~/.bashrc`, `zsh` → `~/.zshrc`, `fish` → `~/.config/fish/config.fish`)
> 해당 RC 파일에 alias 줄을 추가합니다. 중복 실행해도 안전합니다.
>
> 특정 파일에만 설치하려면: `python3 vhack.py alias install --profile ~/.zshrc`

### 3-4. Docker 설치 (실습 환경 필요 시)

```bash
# Ubuntu — 공식 방법
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker   # 또는 재로그인

# 설치 확인
docker --version
docker compose version
```

---

## 4. 상세 설치 — Windows (WSL2) ← 권장

WSL2(Windows Subsystem for Linux) + Ubuntu를 사용하면 Linux와 동일한 환경을 Windows에서 사용할 수 있습니다.

### 4-1. WSL2 + Ubuntu 설치

```powershell
# PowerShell (관리자 권한)
wsl --install
# → 재부팅 후 Ubuntu 자동 설치됨
```

### 4-2. Ubuntu 터미널에서 설치

```bash
# Python, git 설치
sudo apt update && sudo apt install -y python3 python3-pip git

# 저장소 클론
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking

# alias 자동 등록
python3 vhack.py alias install
source ~/.bashrc

# 확인
vhack list
vhack alias status
```

### 4-3. Docker Desktop (WSL2 통합)

1. [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/) 다운로드·설치
2. 설정 → Resources → WSL Integration → Ubuntu 활성화
3. Ubuntu 터미널에서 `docker --version` 확인

---

## 5. 상세 설치 — Windows (PowerShell)

WSL2 없이 Windows 네이티브 환경에서 사용하는 방법입니다.

### 5-1. Python 설치

1. [python.org/downloads](https://www.python.org/downloads/) 에서 Python 3.12 다운로드
2. 설치 시 **"Add Python to PATH"** 체크 필수
3. 확인: `python --version`

### 5-2. git 설치

1. [git-scm.com](https://git-scm.com/download/win) 에서 Git for Windows 다운로드·설치
2. 확인: `git --version`

### 5-3. 저장소 클론

```powershell
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking

# CLI 실행
python vhack.py list
python vhack.py study 5
```

### 5-4. (선택) 명령어 단축

```powershell
# alias 자동 등록 (PowerShell 프로파일에 function 추가)
python vhack.py alias install

# 현재 세션에 즉시 적용
. $PROFILE

# 이후 PowerShell 어디서나 사용
vhack list
vhack alias status
```

> `alias install` 이 PowerShell 감지에 실패하면 수동으로 지정:
> ```powershell
> python vhack.py alias install --profile $PROFILE
> ```

---

## 6. Docker 실습 환경 설치

실습 환경은 Docker를 사용합니다. Docker만 있으면 별도 설정 없이 바로 실행됩니다.

### 6-1. 실습 환경 목록

| 번호 | 이름 | 내용 | 포트 |
|------|------|------|------|
| 01 | 웹 해킹 랩 | DVWA, Juice Shop, WebGoat | 8080(DVWA·SQLi) / 3001(Juice Shop) / 8081(WebGoat) |
| 02 | 바이너리 익스플로잇 랩 | BOF, ROP, heap 취약 서버 | localhost:10001~5 |
| 03 | 네트워크 해킹 랩 | SSH, FTP, DNS, SMTP 취약 서비스 | Docker 내부 네트워크 |
| 04 | 클라우드/컨테이너 보안 랩 | AWS IMDS, K8s, 컨테이너 탈출 | localhost:8080/8443 |
| 05 | 전체 시나리오 통합 랩 | APT 공격 체인 시뮬레이션 | localhost:8888 |
| 06 | 펌웨어 해킹 랩 | binwalk, QEMU 에뮬레이션, 하드코딩 자격증명 | localhost:8062 (웹 패널) |
| 07 | 모바일 보안 랩 | APK 정적분석, Frida, JWT alg:none 우회 | localhost:8072 (취약 API) |

### 6-2. 개별 랩 시작

```bash
# CLI로 시작 (권장)
python3 vhack.py lab start 01   # 웹 해킹 랩
python3 vhack.py lab start 02   # 바이너리 익스플로잇 랩

# 또는 직접 docker compose 사용
cd labs/01_web_hacking_lab
docker compose up -d
```

### 6-3. 모든 랩 시작 (고사양 PC 필요)

```bash
# CLI
python3 vhack.py lab start 01
python3 vhack.py lab start 02
# ... 필요한 랩만 선택적으로 시작

# 또는 start_lab.sh 사용 (Linux/macOS/WSL2)
cd labs
bash start_lab.sh all
```

### 6-4. 랩 종료

```bash
# 특정 랩 종료
python3 vhack.py lab stop 01

# 모든 랩 종료
python3 vhack.py lab stop --all

# 또는
cd labs
bash stop_all.sh
```

### 6-5. 주의사항

> ⚠️ **보안 경고**
> - 이 실습 환경은 **의도적으로 취약**하게 설계되어 있습니다.
> - **로컬 또는 격리된 네트워크**에서만 실행하세요.
> - 인터넷에 노출된 서버에 절대 배포하지 마세요.
> - 학습 완료 후 반드시 `vhack lab stop --all`로 종료하세요.

---

## 7. 설치 확인 및 문제 해결

### 정상 설치 확인

```bash
# CLI 동작 확인
python3 vhack.py --help

# 섹션 목록 확인
python3 vhack.py list

# alias 등록 확인 (등록한 경우)
python3 vhack.py alias status
# ● /home/user/.bashrc  설치됨
# ✓ 현재 세션에서 사용 가능: /usr/local/bin/vhack (source 적용 후)

# Docker 확인 (실습 환경 사용 시)
python3 vhack.py lab status
```

### 자주 발생하는 오류

**`python3: command not found`**
```bash
# Python 설치 확인
which python3 || which python
python3 --version
```

**`docker: command not found`**
```bash
# Docker 설치 확인
https://docs.docker.com/get-docker/
```

**`permission denied: ./vhack.py`**
```bash
chmod +x vhack.py
```

**`ModuleNotFoundError`**
```bash
# vhack.py는 표준 라이브러리만 사용하므로 이 오류가 발생하면
# Python 버전을 확인하세요
python3 --version  # 3.10+ 필요
```

**WSL2에서 Docker 연결 실패**
```bash
# Docker Desktop이 실행 중인지 확인
# Docker Desktop → Settings → Resources → WSL Integration → Ubuntu 활성화
```

**포트 충돌 (8080 already in use)**
```bash
# 사용 중인 포트 확인
sudo lsof -i :8080
# docker-compose.yml에서 포트 변경 후 재시작
```

---

## 8. 권장 추가 도구

실습을 위해 다음 도구를 함께 설치하면 좋습니다.

### 웹 해킹
```bash
# Burp Suite Community (필수)
# https://portswigger.net/burp/communitydownload

# sqlmap
pip install sqlmap
# 또는
sudo apt install sqlmap

# nikto (웹 취약점 스캐너)
sudo apt install nikto
```

### 바이너리 익스플로잇
```bash
# pwntools
pip install pwntools

# GDB + pwndbg
sudo apt install gdb
git clone https://github.com/pwndbg/pwndbg.git
cd pwndbg && ./setup.sh

# ROPgadget
pip install ROPgadget
```

### 네트워크
```bash
# nmap
sudo apt install nmap

# Wireshark
sudo apt install wireshark

# netcat / ncat
sudo apt install netcat-openbsd
```

### 포렌식/분석
```bash
# Ghidra (역공학) — https://ghidra-sre.org
# Volatility3 (메모리 포렌식)
pip install volatility3

# strings, binwalk, file
sudo apt install binwalk
```

---

> **다음 단계:** [USAGE.md](./USAGE.md) 에서 `vhack` 명령어 전체 레퍼런스를 확인하세요.

---

<a name="english"></a>

# Installation Guide — VibeHacking CLI & Lab Environments

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Start (3 Steps)](#quick-start-3-steps)
3. [Linux / macOS](#linux--macos)
4. [Windows (WSL2 — Recommended)](#windows-wsl2--recommended)
5. [Windows (PowerShell)](#windows-powershell)
6. [Docker Lab Environments](#docker-lab-environments)
7. [Verification & Troubleshooting](#verification--troubleshooting)
8. [Recommended Additional Tools](#recommended-additional-tools)

---

## System Requirements

| Item | Minimum | Recommended |
|------|---------|-------------|
| **OS** | Linux / macOS / Windows 10+ | Ubuntu 22.04 / Kali Linux |
| **Python** | 3.10+ | 3.12+ |
| **Docker** | 20.10+ (for labs) | 24.x+ |
| **Docker Compose** | v2.0+ | v2.x |
| **RAM** | 2 GB (CLI only) | 8 GB (full labs) |
| **Disk** | 500 MB (CLI) | 20 GB (all lab images) |
| **git** | 2.x | latest |

> **Note:** `vhack.py` uses only Python standard library — no `pip install` required.

---

## Quick Start (3 Steps)

```bash
# 1. Clone the repository
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking

# 2. Register alias → use vhack from anywhere
python3 vhack.py alias install
source ~/.bashrc          # apply to current session (zsh: source ~/.zshrc)

# 3. (Optional) Start web hacking lab — requires Docker
vhack lab start 01
# → DVWA: http://localhost:8080/dvwa/  Juice Shop: http://localhost:3001  WebGoat: http://localhost:8081/WebGoat
```

---

## Linux / macOS

```bash
# Install Python & git
sudo apt update && sudo apt install -y python3 git    # Ubuntu
brew install python3 git                               # macOS

# Clone repository
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking

# Register alias (auto-detects bash/zsh/fish)
python3 vhack.py alias install
source ~/.bashrc    # or: source ~/.zshrc

# Install Docker (for labs)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

---

## Windows (WSL2 — Recommended)

```powershell
# 1. Install WSL2 + Ubuntu (PowerShell as Administrator)
wsl --install

# 2. In Ubuntu terminal:
sudo apt update && sudo apt install -y python3 git
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
python3 vhack.py alias install   # register alias
source ~/.bashrc
vhack list

# 3. Install Docker Desktop for Windows
# https://www.docker.com/products/docker-desktop/
# Settings → WSL Integration → Enable Ubuntu
```

---

## Windows (PowerShell)

```powershell
# 1. Install Python from https://python.org (check "Add to PATH")
# 2. Install git from https://git-scm.com

# Clone & register alias
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
python vhack.py alias install   # adds function vhack { ... } to $PROFILE
. $PROFILE                      # apply to current session
vhack list
```

---

## Docker Lab Environments

```bash
# Start specific lab
python3 vhack.py lab start 01   # Web hacking (DVWA, Juice Shop)
python3 vhack.py lab start 02   # Binary exploitation (BOF, ROP)
python3 vhack.py lab start 03   # Network hacking
python3 vhack.py lab start 04   # Cloud/container security
python3 vhack.py lab start 05   # Full APT scenario
python3 vhack.py lab start 06   # Firmware hacking (binwalk, QEMU)
python3 vhack.py lab start 07   # Mobile security (APK, Frida, JWT alg:none)

# Check running labs
python3 vhack.py lab status

# Stop all labs
python3 vhack.py lab stop --all
```

> ⚠️ **Security Warning**: These environments are intentionally vulnerable. Run in isolated/local networks only. Never expose to the internet.

---

## Verification & Troubleshooting

```bash
python3 vhack.py --help        # Show help
python3 vhack.py list          # List all 75 sections
python3 vhack.py alias status  # Check alias registration
python3 vhack.py lab status    # Show running containers

# Common fixes:
# "python3: not found"     → Install Python 3.10+
# "docker: not found"      → Install Docker Desktop
# "vhack: not found"       → Run: python3 vhack.py alias install && source ~/.bashrc
# Port 8080 conflict       → Edit ports in docker-compose.yml
```

---

## Recommended Additional Tools

```bash
pip install pwntools          # Binary exploitation framework
pip install sqlmap            # SQL injection automation
sudo apt install nmap gdb wireshark binwalk
# Burp Suite: https://portswigger.net/burp/communitydownload
# Ghidra:     https://ghidra-sre.org
```

> **Next step:** See [USAGE.md](./USAGE.md) for the complete `vhack` command reference.
