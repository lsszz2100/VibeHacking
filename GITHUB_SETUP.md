# GitHub 업로드 가이드

## 1. Git 초기화 및 첫 커밋

```bash
# vibe-hacking 폴더로 이동
cd /path/to/vibe-hacking

# Git 초기화
git init

# 전체 파일 추가
git add .

# 첫 커밋
git commit -m "Initial commit: 바이브 해킹 보안 자료 완전 정리"
```

## 2. GitHub 저장소 생성 및 연결

```bash
# GitHub에서 새 저장소 생성 후:
# Repository name: vibe-hacking
# Description: 실전 사이버보안 완전 정복 - 이론부터 실습까지
# Public (공개) 선택

# 원격 저장소 연결
git remote add origin https://github.com/YOUR_USERNAME/vibe-hacking.git

# 업로드
git branch -M main
git push -u origin main
```

## 3. GitHub Pages 설정 (선택)

```
Settings → Pages → Source → main branch → /docs
```

## 4. 저장소 설정 권장사항

```
Topics 추가:
cybersecurity, hacking, penetration-testing, 
security, kali-linux, ctf, exploit, reverse-engineering,
malware-analysis, digital-forensics, python-security

Description:
실전 사이버보안 완전 정복 — Linux, 네트워크, 시스템, 웹, 
리버싱, 악성코드 분석, 디지털 포렌식, 파이썬 해킹 도구 개발
```

## 5. 파일 구조 최종 확인

```
vibe-hacking/
├── README.md                          # 메인 페이지
├── SECURITY.md                        # 보안 정책
├── .gitignore                         # 제외 파일 목록
├── 01_Linux_Basics/
│   ├── 01_linux_essential_commands.md
│   ├── 02_kali_linux_setup.md
│   └── 03_bash_scripting.md
├── 02_Network_Hacking/
│   ├── 01_osi_tcpip.md
│   ├── 02_packet_analysis.md
│   └── 03_wireless_hacking.md
├── 03_System_Hacking/
│   ├── 01_password_cracking.md
│   └── 02_buffer_overflow.md
├── 04_Reverse_Engineering/
│   ├── 01_assembly_and_registers.md
│   ├── 02_ollydbg_practical.md
│   └── 03_pe_structure.md
├── 05_Web_Hacking/
│   └── 01_owasp_top10.md
├── 06_Malware_Analysis/
│   └── 01_malware_analysis.md
├── 07_Digital_Forensics/
│   └── 01_digital_forensics.md
├── 08_Python_Hacking/
│   └── 01_python_hacking_tools.md
├── 09_Exploit_Techniques/
│   └── 01_advanced_exploitation.md
└── 10_Pentest_Methodology/
    └── 01_pentest_methodology.md
```
