<div align="center">

# ⚔️ VibeHacking

### 实战网络安全完全攻略 — AI时代的黑客圣经

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-64-blueviolet)](#目录)
[![Files](https://img.shields.io/badge/Docs-343%20Files-brightgreen)](#目录)
[![Lines](https://img.shields.io/badge/Lines-225%2C000%2B-orange)](#目录)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-ai驱动的网络安全)

<br/>

> 从理论到实践，涵盖CTF、漏洞赏金、渗透测试、红队行动的网络安全知识库。
> 全面覆盖**2026年Mythos・GPT-5.4-Cyber时代**的AI漏洞研究、云安全、无线安全与密码学。

**🌐 Language / 言語 / 语言:**
[한국어](README.md) · [English](README.en.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## 关于本项目

为了帮助安全学习者提升实战技能，本项目汇集了可直接运行的代码与系统化的方法论。  
从CTF到漏洞赏金、红队到AI安全，这是一个**多语言、实战导向的安全知识中心**。

**VibeHacking的特点：**

- **代码优先** — 每个章节均包含可直接复制粘贴的命令和代码
- **AI集成** — 介绍如何将Claude/GPT-5.4-Cyber作为安全分析工具使用
- **紧跟前沿** — 涵盖2026年AI安全生态系统，包括Anthropic Mythos和OpenAI GPT-5.4-Cyber
- **多语言支持** — 提供韩语、英语、日语和中文版本
- **全面覆盖** — 漏洞赏金、SOC、云安全、WiFi、密码学、红队等全领域

---

## 🛠️ CLI + 实验环境 — 立即开始

### 1分钟安装

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
python3 vhack.py list        # 浏览全部 64 个章节
```

> 📖 详细安装指南 → **[INSTALL.md](./INSTALL.md)**
> 📘 完整命令参考 → **[USAGE.md](./USAGE.md)**

### `vhack` 主要命令

```bash
# 浏览与学习
python3 vhack.py list                    # 全部 64 个章节列表
python3 vhack.py list --search web       # 按关键词过滤章节
python3 vhack.py study 5                 # Web 渗透章节文件列表
python3 vhack.py study 5 1               # 在终端阅读 OWASP Top 10
python3 vhack.py search "Kerberoasting"  # 全文搜索所有文档

# Docker 实验环境管理 (需要 Docker)
python3 vhack.py lab ls                  # 实验环境列表 + 访问地址
python3 vhack.py lab start 01            # 启动 Web 渗透实验室 → localhost:8080
python3 vhack.py lab start 02            # 启动二进制漏洞利用实验室
python3 vhack.py lab status              # 查看运行中的容器
python3 vhack.py lab stop --all          # 停止所有实验室

# 更新
python3 vhack.py update                  # git pull 获取最新内容
```

### 实验环境 (基于 Docker)

| # | 实验室名称 | 内容 | 访问地址 | 难度 |
|:-:|-----------|------|----------|:----:|
| **01** | Web 渗透实验室 | DVWA · Juice Shop · WebGoat | http://localhost:8080 | ★★☆ |
| **02** | 二进制漏洞利用实验室 | BOF · ROP · heap · fmtstr | nc localhost 10001 | ★★★ |
| **03** | 网络渗透实验室 | SSH · FTP · DNS · SMTP 漏洞服务 | docker exec shell | ★★☆ |
| **04** | 云/容器安全实验室 | SSRF · AWS IMDS · K8s 逃逸 | http://localhost:8080 | ★★★ |
| **05** | 综合场景实验室 | APT 攻击链模拟 | http://localhost:8888 | ★★★★ |

```bash
# 快速实践示例：Web 渗透
python3 vhack.py study 5 1        # ① 阅读 OWASP Top 10 理论
python3 vhack.py lab start 01     # ② 启动 DVWA/Juice Shop 实验室
# ③ 打开 http://localhost:8080 开始实践
python3 vhack.py lab stop 01      # ④ 完成后停止
```

---

## 目录

| # | 章节 | 核心内容 | 文件数 |
|---|------|---------|-------|
| 01 | [Linux基础 & Kali Linux](#01-linux基础--kali-linux) | 必备命令、Kali配置、Bash脚本 | 3 |
| 02 | [网络黑客技术](#02-网络黑客技术) | OSI/TCP-IP、数据包分析、无线攻击 | 3 |
| 03 | [系统入侵](#03-系统入侵) | 密码破解、缓冲区溢出 | 2 |
| 04 | [逆向工程](#04-逆向工程) | 汇编语言、OllyDbg、PE结构 | 3 |
| 05 | [Web渗透](#05-web渗透) | OWASP Top 10、SQL注入进阶、XSS/CSRF | 3 |
| 06 | [恶意代码分析](#06-恶意代码分析) | 静态/动态分析、Volatility、Android | 3 |
| 07 | [数字取证](#07-数字取证) | 取证流程、Windows痕迹、网络取证 | 3 |
| 08 | [Python黑客技术](#08-python黑客技术) | 工具开发、网络扫描器、Web自动化 | 3 |
| 09 | [漏洞利用技术](#09-漏洞利用技术) | ROP Chain、SEH、Linux BOF、提权 | 2 |
| 10 | [渗透测试方法论](#10-渗透测试方法论) | 渗透流程、OSINT侦察、报告撰写 | 3 |
| 11 | [**AI驱动的网络安全**](#11-ai驱动的网络安全) | Mythos、GPT-5.4-Cyber、LLM漏洞研究、CTF自动化 | 4 |
| 12 | [**漏洞赏金**](#12-漏洞赏金) | 方法论、Burp Suite进阶、自动化工具 | 3 |
| 13 | [**SOC & 蓝队**](#13-soc--蓝队) | SOC运营、Splunk分析、威胁狩猎 | 3 |
| 14 | [**云安全**](#14-云安全) | AWS/Azure/GCP攻击向量、渗透测试、清单 | 3 |
| 15 | [**WiFi黑客技术**](#15-wifi黑客技术) | WPA2破解、PMKID、Evil Twin、自动化 | 3 |
| 16 | [**密码学**](#16-密码学) | 黑客密码学、哈希攻击、应用密码学 | 3 |
| 17 | [**红队行动**](#17-红队行动) | 作战手册、钓鱼/社会工程学、API渗透 | 3 |
| 18 | [**DevSecOps**](#18-devsecops) | SAST/SCA/DAST、容器安全、CI/CD流水线 | 3 |
| 19 | [**汇编语言**](#19-汇编语言) | x86/x64基础、shellcode开发、反汇编分析 | 3 |
| 20 | [**Shell脚本**](#20-shell脚本) | Bash基础、渗透自动化、后渗透脚本 | 3 |
| 21 | [**Windows漏洞利用**](#21-windows漏洞利用) | Windows内部结构、提权、防御规避 | 3 |
| 22 | [**密码破解**](#22-密码破解) | 哈希类型/字典、Hashcat/John、高级技术 | 3 |
| 23 | [**数据库攻击**](#23-数据库攻击) | Oracle/MySQL攻击、DB提权、取证与审计 | 4 |
| 24 | [**网络基础设施安全**](#24-网络基础设施安全) | DNS攻击、邮件服务器(SPF/DKIM/DMARC)、SSH隧道 | 4 |
| 25 | [**威胁情报**](#25-威胁情报) | CTI基础、OSINT/Shodan、事件响应、蜜罐 | 4 |
| 26 | [**Linux加固**](#26-linux加固) | iptables/nftables、PAM认证、KISA漏洞评估 | 4 |
| 27 | [**IoT黑客技术**](#27-iot黑客技术) | 攻击面分析、固件分析、IoT漏洞利用 | 3 |
| 28 | [**移动端攻击**](#28-移动端攻击) | Android渗透测试、iOS渗透测试、移动流量分析 | 3 |
| 29 | [**容器/Kubernetes安全**](#29-容器kubernetes安全) | Docker安全、Kubernetes攻击、容器逃逸 | 3 |
| 30 | [**漏洞研究**](#30-漏洞研究) | 模糊测试技术、漏洞分析、高级利用开发 | 3 |
| 31 | [**AI/ML系统安全**](#31-aiml系统安全) | 对抗样本、提示注入、模型提取、智能体安全 | 5 |
| 32 | [**网络设备攻击**](#32-网络设备攻击) | IOS侦察、L2攻击、路由协议操控、管理平面利用 | 5 |
| 33 | [**OSINT与社会工程学**](#33-osint与社会工程学) | 信息收集方法论、目标画像、钓鱼基础设施构建与规避 | 5 |
| 34 | [**硬件攻击**](#34-硬件攻击) | 接口分析(UART/JTAG/SPI)、固件提取、侧信道与故障注入 | 4 |
| 35 | [**供应链攻击**](#35-供应链攻击) | 软件供应链入侵、CI/CD投毒、SolarWinds·XZ模式分析 | 3 |
| 36 | [**汽车黑客技术**](#36-汽车黑客技术) | CAN总线分析、ECU利用、车联网与OTA攻击 | 4 |
| 37 | [**ICS/SCADA安全**](#37-icsscada安全) | ICS协议侦察、SCADA利用、OT网络攻防 | 4 |
| 38 | [**云原生安全**](#38-云原生安全) | CNAPP、eBPF运行时安全、镜像加固、容器逃逸 | 4 |
| 39 | [**零信任架构**](#39-零信任架构) | ZTA原则、身份/设备信任、微分段、SASE | 4 |
| 40 | [**威胁狩猎**](#40-威胁狩猎) | 狩猎方法论、MITRE ATT&CK场景、100+ KQL/SPL查询、SOAR自动化 | 4 |
| 41 | [**韩国安全认证**](#41-韩国安全认证) | 信息安全工程师、ISMS-P、CISSP/OSCP路线图、安全法规 | 5 |
| 42 | [**区块链/Web3安全**](#42-区块链web3安全) | EVM结构、智能合约审计、DeFi攻击、Web3渗透工具 | 4 |
| 43 | [**物理安全渗透**](#43-物理安全渗透) | 物理渗透测试方法论、门锁破解、RFID克隆、社会工程学 | 4 |
| 44 | [**事件响应/DFIR**](#44-事件响应dfir) | IR手册、内存/磁盘取证、网络取证、封控与清除 | 4 |
| 45 | [**恶意代码开发**](#45-恶意代码开发) | PE结构、shellcode/注入、C2框架、AV/EDR规避 | 4 |
| 46 | [**CTF技巧**](#46-ctf技巧) | CTF方法论/工具、PWN/REV、Web/密码学、自动化框架 | 4 |
| 47 | [**移动取证**](#47-移动取证) | Android/iOS取证、证据提取、移动取证工具 | 4 |
| 48 | [**威胁建模**](#48-威胁建模) | STRIDE/PASTA/DREAD、攻击树、威胁建模工具 | 4 |
| 49 | [**红队基础设施**](#49-红队基础设施) | C2框架、域前置、OPSEC、基础设施自动化 | 4 |
| 50 | [**游戏黑客**](#50-游戏黑客) | 内存操控、Cheat Engine、数据包操控、反作弊分析 | 4 |
| 51 | [**浏览器扩展安全**](#51-浏览器扩展安全) | MV2/V3、恶意扩展分析、Content Script XSS | 4 |
| 52 | [**API安全**](#52-api安全) | OWASP API Top 10、BOLA、GraphQL、模糊测试、OAuth2 | 4 |
| 53 | [**无服务器安全**](#53-无服务器安全) | Lambda攻击、事件注入、IAM滥用、IaC扫描 | 4 |
| 54 | [**Active Directory攻击**](#54-active-directory攻击) | AD枚举、Kerberoasting、DCSync、黄金票据 | 4 |
| 55 | [**检测规避技术**](#55-检测规避技术) | AV/EDR绕过、IDS/IPS规避、直接syscall、痕迹清除 | 4 |
| 🧪 | [**CTF实验环境（labs/）**](#ctf实验环境labs) | Web/二进制/网络/云原生/综合场景Docker CTF实验 | 50 |

---

## 学习路线图

```
[入门]
  Linux基础  ──►  网络基础  ──►  Web渗透入门
                                      │
[中级]                                 ▼
  系统入侵  ◄──  Python自动化  ◄──  恶意代码分析
      │
      ▼
[高级]
  逆向工程  ──►  漏洞利用开发  ──►  渗透测试方法论
                                          │
[专家]                                    ▼
  WiFi黑客  ──►  云安全  ──►  红队行动  ──►  漏洞赏金
  密码学    ──►  SOC/蓝队  ──►  AI安全研究  ──►  DevSecOps
```

---

## 实验环境

| 组件 | 推荐配置 |
|------|---------|
| 攻击机 | Kali Linux 2024.x |
| 虚拟化 | VMware Workstation / VirtualBox |
| 靶机环境 | Metasploitable2、DVWA、HackTheBox、TryHackMe、CloudGoat |
| 分析工具 | Wireshark、Burp Suite、IDA Pro / Ghidra、OllyDbg |
| 编程语言 | Python 3.x、Bash、pwntools |
| AI工具 | Claude Opus 4.6、GPT-5.4-Cyber（TAC认证） |
| 无线网卡 | Alfa AWUS036ACH（支持2.4/5GHz监听模式） |
| 云平台 | AWS Free Tier、CloudGoat |

---

## 01. Linux基础 & Kali Linux

```
01_Linux_Basics/
├── 01_linux_essential_commands.md   ← 文件/进程/网络必备命令
├── 02_kali_linux_setup.md           ← Kali初始配置、工具安装
└── 03_bash_scripting.md             ← 自动化脚本、实战示例
```

**核心内容：** 文件系统、进程管理、网络命令、权限管理、30+个Bash自动化脚本

---

## 02. 网络黑客技术

```
02_Network_Hacking/
├── 01_osi_tcpip.md          ← OSI七层、TCP/IP协议栈、协议分析
├── 02_packet_analysis.md    ← Wireshark实战、tcpdump、数据包操控
└── 03_wireless_hacking.md   ← WEP/WPA2破解、Evil Twin、无线攻击
```

**核心内容：** 数据包捕获与分析、ARP欺骗、MITM中间人攻击、无线网络攻击、防火墙绕过

---

## 03. 系统入侵

```
03_System_Hacking/
├── 01_password_cracking.md       ← Hashcat、John、彩虹表、在线破解
├── 02_buffer_overflow.md         ← 栈溢出原理、shellcode、实战示例
└── 03_active_directory_attack.md ← AD攻击完全指南、Kerberoasting、DCSync
```

**核心内容：** 哈希破解策略、从原理到漏洞利用的BOF完整链路、Active Directory攻击链完全攻略

---

## 04. 逆向工程

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md   ← x86/x64汇编、寄存器、栈帧
├── 02_ollydbg_practical.md        ← OllyDbg/x64dbg实战分析
└── 03_pe_structure.md             ← PE文件结构、IAT/EAT、加壳
```

**核心内容：** 汇编语言、调试器使用、PE结构深度分析、IDA Pro/Ghidra

---

## 05. Web渗透

```
05_Web_Hacking/
├── 01_owasp_top10.md              ← OWASP Top 10（2021）、Burp Suite、Nikto
├── 02_sql_injection_advanced.md   ← Blind/时间盲注、NoSQL、SQLMap实战
└── 03_xss_csrf_file_upload.md     ← Stored/Reflected/DOM XSS、CSRF、Webshell
```

**核心内容：** OWASP Top 10实战、SQL注入完全攻略、XSS/CSRF/文件上传/XXE/SSRF

---

## 06. 恶意代码分析

```
06_Malware_Analysis/
├── 01_malware_analysis.md            ← 分类、分析环境、静态/动态分析、YARA
├── 02_memory_forensics_malware.md    ← Volatility完全攻略、代码注入检测
└── 03_android_malware_analysis.md    ← APK分析、Frida Hook、MobSF
```

**核心内容：** 静态・动态・内存分析全流程、Volatility插件、Android恶意代码

---

## 07. 数字取证

```
07_Digital_Forensics/
├── 01_digital_forensics.md               ← 取证原则、证据收集、镜像分析
├── 02_windows_forensics_artifacts.md     ← 注册表、事件日志、Prefetch、浏览器痕迹
└── 03_network_forensics.md               ← Wireshark、Zeek、Suricata、事件响应
```

**核心内容：** 证据收集规程、Windows痕迹完整分析、网络取证、时间线分析

---

## 08. Python黑客技术

```
08_Python_Hacking/
├── 01_python_hacking_tools.md       ← 端口扫描器、嗅探器、后门等30+个示例
├── 02_python_network_scanner.md     ← 多线程扫描器、ARP、DNS枚举、SSH爆破
└── 03_python_web_exploitation.md    ← Web爬虫、SQLi自动化、XSS扫描器、报告生成
```

**核心内容：** 基于Scapy、paramiko、requests的安全工具开发，50+个完整可运行代码

---

## 09. 漏洞利用技术

```
09_Exploit_Techniques/
├── 01_advanced_exploitation.md   ← ROP Chain、Heap Spray、SEH、Win32 shellcoding
├── 02_linux_exploitation.md      ← Linux BOF、Ret2Libc、格式化字符串、提权
└── 03_heap_exploitation.md       ← tcache投毒、UAF、House of系列、pwndbg
```

**核心内容：** DEP/ASLR/NX绕过、ROP链构造、格式化字符串漏洞利用、堆漏洞完全攻略

---

## 10. 渗透测试方法论

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← 完整渗透测试流程、MITRE ATT&CK、报告撰写
├── 02_osint_recon.md           ← Google Dorks、Shodan、子域名枚举、GitHub敏感信息挖掘
└── 03_report_writing.md        ← 专业报告撰写、CVSS评分、PoC编写、管理层/技术报告模板
```

**核心内容：** 系统化渗透测试方法论、OSINT工具完整运用、专业报告撰写（CVSS・PoC・合规要求）

---

## 11. AI驱动的网络安全

> **2026年，AI正在重塑网络安全格局。**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Mythos・GPT-5.4-Cyber・Project Glasswing全景图
├── 02_llm_vulnerability_research.md   ← 用LLM发现零日漏洞、AI模糊测试、代码分析自动化
├── 03_ai_assisted_pentesting.md       ← AI辅助渗透测试工作流、提示词工程
└── 04_ai_ctf_automation.md            ← CTF自动化AI智能体、密码/Web/取证专业子智能体
```

### 2026年AI安全格局

| 模型 | 机构 | 能力 | 访问方式 |
|-----|------|------|---------|
| **Claude Mythos** | Anthropic | 自主发现17年历史FreeBSD RCE漏洞，数千个零日 | Project Glasswing（仅12家合作伙伴） |
| **GPT-5.4-Cyber** | OpenAI | 二进制逆向、76%自主解决CTF、YARA生成 | TAC认证（chatgpt.com/cyber） |
| **Claude Opus 4.6** | Anthropic | 代码漏洞分析、CTF辅助、YARA自动化 | 公开可用 |

**核心内容：** AI安全生态系统完整分析、基于Claude API的漏洞扫描器实现、AI辅助渗透测试自动化、CTF解题AI智能体（密码学/Web/取证/逆向专业子智能体）

---

## 12. 漏洞赏金

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd方法论、IDOR、XSS绕过、自动化
├── 02_burp_suite_advanced.md      ← Burp Suite完全攻略、JWT攻击、请求走私
└── 03_bug_bounty_automation.md    ← Nuclei、ffuf、dalfox、自动化流水线
```

**核心内容：** 漏洞赏金完整工作流、Burp Suite高级功能、侦察→漏洞→报告自动化

---

## 13. SOC & 蓝队

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md       ← SOC架构、事件响应、关键事件ID、EDR
├── 02_splunk_siem_analysis.md   ← Splunk SPL完全攻略、100+检测查询
└── 03_threat_hunting.md         ← 威胁狩猎、勒索软件入侵调查、APT追踪
```

**核心内容：** SOC各层级职责、100+攻击检测模式、Splunk/QRadar/ELK查询、威胁狩猎方法论

---

## 14. 云安全

```
14_Cloud_Security/
├── 01_cloud_attack_vectors.md        ← AWS/Azure/GCP/K8s攻击向量完整分析
├── 02_aws_pentest.md                 ← AWS渗透测试方法论、提权、自动化
└── 03_cloud_security_checklist.md    ← CIS检查清单、Terraform、SCP策略
```

**核心内容：** IAM权限滥用、S3配置错误、容器逃逸、Kubernetes攻击、云安全检查清单

---

## 15. WiFi黑客技术

```
15_WiFi_Hacking/
├── 01_wifi_hacking_fundamentals.md   ← WEP/WPA/WPA2/WPA3理论、aircrack-ng基础
├── 02_wpa2_cracking.md               ← Hashcat/Aircrack、PMKID攻击、字典优化
└── 03_advanced_wifi_attacks.md       ← Evil Twin、KARMA、Bettercap、Scapy操控
```

**核心内容：** 四次握手、PMKID捕获、GPU破解、Evil Twin搭建、无线自动化

---

## 16. 密码学

```
16_Cryptography/
├── 01_cryptography_for_hackers.md   ← AES模式攻击、RSA漏洞、XOR破解
├── 02_hash_attacks.md               ← MD5碰撞、彩虹表、Kerberoasting
└── 03_applied_cryptography.md       ← Padding Oracle、ECDSA随机数重用、JWT攻击
```

**核心内容：** 密码实现漏洞、CTF密码学题型、安全密码实现指南

---

## 17. 红队行动

```
17_Red_Team_Operations/
├── 01_red_team_playbook.md               ← 行动架构、Cobalt Strike/Havoc、AV/EDR绕过
├── 02_phishing_and_social_engineering.md ← GoPhish、Evilginx2、鱼叉式钓鱼、BEC
└── 03_api_hacking.md                     ← OWASP API Top 10、GraphQL、Fuzzer开发
```

**核心内容：** 红队vs渗透测试区别、C2框架运营、钓鱼基础设施、API漏洞完全攻略

---

## 18. DevSecOps

```
18_DevSecOps/
├── 01_devsecops_fundamentals.md    ← Shift Left、Semgrep、SonarQube、Snyk、ZAP
├── 02_container_security.md        ← Dockerfile安全、Trivy、Falco、K8s RBAC、cosign
└── 03_github_actions_security.md   ← CI/CD安全、OIDC、SHA固定、完整安全流水线
```

**核心内容：** 安全左移（Shift Left）、SAST/SCA/DAST/IaC扫描自动化、容器运行时检测、GitLab/Jenkins/GitHub Actions安全流水线完整实现

---

## 19. 汇编语言

```
19_Assembly_Language/
├── 01_x86_x64_Fundamentals.md   ← 寄存器、指令、栈帧、调用约定
├── 02_Shellcode_Development.md  ← shellcode编写、坏字节去除、ctypes执行测试
└── 03_Disassembly_Analysis.md   ← GDB/pwndbg、IDA/Ghidra、Capstone自动化
```

**核心内容：** x86/x64寄存器完全攻略、NASM编码、64位execve shellcode实现、基于Capstone的自动反汇编器

---

## 20. Shell脚本

```
20_Shell_Scripting/
├── 01_Bash_Scripting_Basics.md       ← 变量/数组/条件/循环/函数、awk/sed、端口扫描器
├── 02_Pentest_Automation.md          ← 侦察自动化、子域名枚举、漏洞扫描封装
└── 03_Post_Exploitation_Scripts.md   ← 反弹Shell、持久化、Python C2套接字实现
```

**核心内容：** Bash实战脚本、从侦察到后渗透全流程自动化、7种反弹Shell一行命令、Python C2实现

---

## 21. Windows漏洞利用

```
21_Windows_Exploitation/
├── 01_Windows_Internals.md              ← PE格式、PEB/TEB、WinAPI核心函数、PE解析器代码
├── 02_Windows_Privilege_Escalation.md   ← 服务/注册表/DLL劫持、UAC绕过、令牌模拟
└── 03_Defense_Evasion.md                ← AMSI/ETW绕过、6种进程注入、LOLBAS、AES载荷加密
```

**核心内容：** Windows内部结构深度解析、提权完全攻略、AMSI/AV/EDR绕过技术

---

## 22. 密码破解

```
22_Password_Cracking/
├── 01_Hash_Types_and_Wordlists.md      ← 哈希算法对比、hashid、CeWL/Crunch/CUPP、Python破解器
├── 02_Hashcat_and_John.md              ← 所有攻击模式、哈希类型模式号、规则编写、实战工作流
└── 03_Advanced_Cracking_Techniques.md  ← 彩虹表、PRINCE、高级掩码、密码喷洒工具
```

**核心内容：** NTLM/WPA/ZIP/PDF破解策略、GPU优化、限速绕过密码喷洒自动化

---

## 23. 数据库攻击

```
23_Database_Hacking/
├── 01_oracle_mysql_attack.md       ← Oracle/MySQL/MSSQL攻击向量、盲注、带外数据提取
├── 02_db_privilege_escalation.md   ← 数据库用户提权、存储过程滥用、UDF注入、链接服务器
└── 03_db_forensics_defense.md      ← 数据库取证、审计日志、查询监控、加固清单
```

**核心内容：** 跨多DB的攻击链、通过数据库引擎提权、取证分析与防御加固

---

## 24. 网络基础设施安全

```
24_Network_Infrastructure_Security/
├── 01_dns_attack_defense.md                ← DNS劫持、区域传送、缓存投毒、DNSSEC绕过
├── 02_mail_server_security.md              ← SPF/DKIM/DMARC绕过、邮件服务器入侵、邮件伪造
└── 03_ssh_tunneling_port_forwarding.md     ← SSH隧道、动态端口转发、SOCKS代理、内网穿透
```

**核心内容：** DNS/邮件/SSH基础设施层面攻击、服务利用、通过内网穿透横向移动

---

## 25. 威胁情报

```
25_Threat_Intelligence/
├── 01_cti_fundamentals.md          ← CTI框架(MITRE ATT&CK/STIX/TAXII)、威胁行为者画像
├── 02_osint_for_threat_intel.md    ← Shodan/Censys自动化、暗网OSINT、IOC收集流水线
└── 03_incident_response.md         ← IR手册、证据收集、恶意代码分类、蜜罐
```

**核心内容：** CTI生命周期、威胁行为者归因分析、IOC管理、自动化事件响应流程

---

## 26. Linux加固

```
26_Linux_Hardening/
├── 01_firewall_and_iptables.md          ← iptables/nftables/ufw规则、防火墙审计、状态过滤
├── 02_pam_and_auth_hardening.md         ← PAM配置、SSH加固、MFA设置、sudo策略
└── 03_kisa_vulnerability_assessment.md  ← KISA安全检查清单、CIS基准、自动化评估脚本
```

**核心内容：** 防火墙规则设计、认证加固、符合KISA/CIS标准的自动化安全评估

---

## 27. IoT黑客技术

```
27_IoT_Hacking/
├── 01_iot_attack_surface.md    ← 攻击面分析、OWASP IoT Top 10、Shodan/Censys扫描
├── 02_firmware_analysis.md     ← 固件提取分析、binwalk/Ghidra、硬编码凭据检测
└── 03_iot_exploitation.md      ← UART/JTAG接入、嵌入式漏洞利用、实战攻击场景
```

**核心内容：** 基于OWASP IoT Top 10的攻击面分析、固件逆向(binwalk/Ghidra)、UART/JTAG硬件攻击、IoT设备实战渗透

---

## 28. 移动端攻击

```
28_Mobile_Hacking/
├── 01_android_pentesting.md        ← APK分析、ADB Root、Frida动态插桩、SSL Pinning绕过
├── 02_ios_pentesting.md            ← IPA提取、Objective-C/Swift逆向、越狱检测绕过
└── 03_mobile_traffic_analysis.md   ← Burp Suite移动代理、证书固定绕过、API模糊测试
```

**核心内容：** Android/iOS完整分析流水线、基于Frida的运行时插桩、移动端中间人攻击、SSL Pinning绕过技术

---

## 29. 容器/Kubernetes安全

```
29_Container_Kubernetes_Security/
├── 01_docker_security.md      ← Docker安全配置、容器逃逸技术、镜像漏洞扫描
├── 02_kubernetes_attack.md    ← RBAC提权、etcd夺取、Kubernetes攻击向量完整分析
└── 03_container_escape.md     ← cgroup/namespace逃逸、runc漏洞、实战容器逃逸PoC
```

**核心内容：** Docker/Kubernetes攻防策略、RBAC提权、容器逃逸技术、基于Trivy/Falco的运行时安全

---

## 30. 漏洞研究

```
30_Vulnerability_Research/
├── 01_fuzzing_techniques.md            ← AFL++/libFuzzer/Boofuzz、覆盖率引导模糊测试、网络模糊测试
├── 02_vulnerability_analysis.md        ← CVSS分析、CWE分类、静态/动态分析、源码审计
└── 03_exploit_development_advanced.md  ← 高级堆漏洞利用、浏览器漏洞利用、内核漏洞开发
```

**核心内容：** 基于AFL++/libFuzzer的自动化漏洞发现、系统化CVSS/CWE分析、高级堆/浏览器/内核漏洞利用开发

---

## 31. AI/ML系统安全

```
31_AI_ML_Security/
├── 01_adversarial_examples.md         ← FGSM/PGD/C&W、迁移攻击、对抗训练与随机平滑防御
├── 02_prompt_injection_jailbreak.md   ← 直接/间接提示注入、越狱、garak/PyRIT自动红队测试
├── 03_model_extraction_inversion.md   ← 模型提取、成员推断(LiRA)、训练数据重构、DP-SGD防御
└── 04_llm_agent_security.md           ← 工具调用SSRF/RCE、RAG索引投毒、MCP安全、双LLM架构
```

如果第11章是"将AI用作攻击工具"，那么第31章聚焦于**AI/ML系统本身作为攻击目标**的攻防。基于OWASP LLM Top 10 / NIST AI 100-2 / MITRE ATLAS，包含可复现的PyTorch/Anthropic SDK PoC。

---

## 32. 网络设备攻击

```
32_Network_Device_Hacking/
├── 01_ios_fundamentals_and_recon.md      ← Cisco IOS/IOS XE结构、设备指纹识别、管理协议侦察
├── 02_layer2_attacks.md                  ← VLAN跳跃、STP/DHCP攻击、CAM溢出、DAI绕过
├── 03_routing_protocol_attacks.md        ← OSPF/EIGRP/BGP路由注入、HSRP/VRRP劫持
└── 04_management_plane_exploitation.md   ← SNMP/TACACS+/NETCONF利用、配置文件提取、后门识别
```

第02章聚焦流量嗅探/MITM，第24章聚焦DNS/邮件/SSH服务层面，第32章则直接攻击**路由器/交换机的管理/控制/数据平面**。收录2025–2026年Cisco CVE复现PoC（CVE-2025-20188等）和GNS3/EVE-NG实验拓扑。

---

## 33. OSINT与社会工程学

```
33_OSINT_Social_Engineering/
├── 01_osint_methodology_and_search.md  ← 信息收集方法论、Shodan/Censys/FOFA、高级Dork技巧
├── 02_target_profiling.md              ← 人员/组织画像、社交媒体分析、邮件验证、域名侦察
├── 03_social_engineering_attacks.md    ← 钓鱼/鱼叉钓鱼/语音钓鱼/短信钓鱼、BEC、托词攻击
└── 04_phishing_infra_and_evasion.md    ← GoPhish/Evilginx2基础设施、URL绕过、反钓鱼检测规避
```

将OSINT作为**攻击链侦察阶段**而非简单信息检索。涵盖Shodan/FOFA/Censys查询自动化、基于LinkedIn/GitHub/社交媒体的目标画像，以及GoPhish/Evilginx2钓鱼基础设施构建，以红队实战视角呈现。

---

## 34. 硬件攻击

```
34_Hardware_Hacking/
├── 01_hardware_recon_and_interfaces.md    ← UART/JTAG/SPI/I²C接口识别与数据提取、引脚分析
├── 02_firmware_analysis.md                ← binwalk提取、文件系统分析、硬编码密钥、危险函数检测
└── 03_side_channel_and_fault_injection.md ← 功耗分析(SPA/DPA)、时序攻击、毛刺注入、ChipWhisperer
```

涵盖电子设备的物理攻击面——通过UART串口获取root Shell、通过JTAG完整转储固件，以及通过侧信道分析提取加密密钥。使用minicom、OpenOCD、binwalk、ChipWhisperer等工具，覆盖硬件安全研究的核心技术。

---

## 35. 供应链攻击

```
35_Supply_Chain_Attacks/
├── 01_software_supply_chain.md   ← 开源包投毒、域名抢注、依赖混淆攻击
└── 02_build_and_ci_poisoning.md  ← CI/CD流水线入侵、GitHub Actions滥用、SolarWinds·XZ Utils模式分析
```

解剖SolarWinds、XZ Utils、3CX等真实供应链入侵案例。涵盖PyPI/npm/Maven包投毒、GitHub Actions工作流权限劫持、构建系统后门植入——证明整个软件开发流水线都是攻击面。

---

## 36. 汽车黑客技术

```
36_Automotive_Hacking/
├── 01_can_bus_analysis.md           ← CAN总线结构、OBD-II诊断、报文嗅探与重放
├── 02_ecu_exploitation.md           ← ECU固件分析、UDS诊断协议滥用、刷写调参
└── 03_telematics_and_ota_attacks.md ← V2X通信、车联网单元渗透、OTA更新拦截
```

现代汽车是拥有100+个ECU和数十种通信协议的移动计算机。从CAN总线嗅探到UDS诊断协议滥用、车联网远程攻击，以及Jeep Cherokee/Tesla真实入侵复现——以python-can、Scapy、CANalyzer为工具，全栈覆盖汽车安全研究。

---

## 37. ICS/SCADA安全

```
37_ICS_SCADA/
├── 01_ics_protocols_and_recon.md  ← Modbus/DNP3/IEC 61850/EtherNet/IP深度解析、Shodan侦察、多协议扫描器
├── 02_scada_exploitation.md       ← HMI/Historian/PLC漏洞、TRITON·INDUSTROYER分析、SCADA扫描器
└── 03_ot_network_attacks.md       ← Purdue模型分层攻击、IT→OT横向移动、无线OT、OT拓扑映射器
```

分析控制发电站、炼油厂、水处理、铁路等关键基础设施的ICS/OT环境。解剖Stuxnet、TRITON、INDUSTROYER、PIPEDREAM等真实网络武器——从Modbus线圈强制写入到PLC DB块补丁、Historian数据逆注入、OT拓扑自动映射，全面呈现可用性优先环境的攻防实战。

---

## 38. 云原生安全

```
38_Cloud_Native_Security/
├── 01_cloud_native_threat_model.md      ← STRIDE威胁建模、CNAPP、容器/无服务器/服务网格威胁
├── 02_ebpf_runtime_security.md          ← Falco/Tetragon/Cilium、eBPF运行时检测与网络策略
├── 03_image_hardening_supply_chain.md   ← Trivy/Grype镜像扫描、Cosign签名、SBOM、OPA Gatekeeper
└── 04_cloud_native_attack_techniques.md ← 容器逃逸、服务网格MITM、无服务器事件注入、KSPM
```

涵盖云原生环境（Kubernetes、无服务器、服务网格）的攻防技术。从eBPF运行时安全（Falco/Tetragon）、容器镜像签名与SBOM、OPA策略网关，到实际容器逃逸技术、服务网格MITM、AWS Lambda事件注入——以CNAPP视角系统整理。

---

## 39. 零信任架构

```
39_Zero_Trust_Architecture/
├── 01_zero_trust_principles.md         ← BeyondCorp模型、NIST SP 800-207、ZTA成熟度模型
├── 02_identity_and_device_trust.md     ← IdP/MFA/通行密钥、设备信任（MDM/EDR）、SCIM预置
├── 03_microsegmentation_and_network.md ← 微分段、mTLS、SASE/SD-WAN、eBPF网络策略
└── 04_zero_trust_implementation.md     ← Cloudflare/Zscaler/BeyondCorp实施、ZTA审计自动化
```

"永不信任，始终验证" — 基于NIST SP 800-207的零信任架构实务解析。涵盖BeyondCorp案例、身份/设备信任体系、微分段、SASE引入，以及ZTA成熟度自评工具。

---

## 40. 威胁狩猎

```
40_Threat_Hunting/
├── 01_threat_hunting_methodology.md  ← 狩猎周期、假设驱动狩猎、PEAK框架、TTP漂移
├── 02_mitre_attack_hunting.md        ← ATT&CK战术狩猎场景、组织画像、Atomic Red Team
├── 03_hunting_queries_kql_spl.md     ← 100+ Sentinel KQL/Splunk SPL狩猎查询、异常检测模式
└── 04_automated_threat_hunting.md    ← SOAR自动化、ML异常检测、狩猎剧本自动化
```

主动威胁狩猎——发现日志未告诉你的内容。涵盖PEAK框架假设构建、MITRE ATT&CK战术狩猎场景、100+ Sentinel KQL/Splunk SPL查询示例，以及SOAR自动化剧本，可在SOC中即时部署。

---

## 41. 韩国安全认证

```
41_Korean_Certifications/
├── 01_information_security_engineer.md           ← 信息安全工程师笔试 — 5科目完全攻略
├── 02_information_security_engineer_practical.md ← 实操题型、密码学/网络/系统实验
├── 03_ISMS_P_certification.md                    ← ISMS-P认证体系、80项控制措施、审核准备
├── 04_international_certifications.md            ← CISSP/CEH/OSCP/CISA路线图、域比较
└── 05_security_laws_and_compliance.md            ← 韩国个人信息保护法·IT安全法规、GDPR对比
```

将韩国安全认证（信息安全工程师、ISMS-P）与国际认证（CISSP/CEH/OSCP/CISA）汇聚一处。包含法律法规与合规（个人信息保护法、GDPR），涵盖韩国安全从业者必须掌握的制度基础。

---

## 42. 区块链/Web3安全

```
42_Blockchain_Web3_Security/
├── 01_blockchain_fundamentals_and_threats.md ← EVM架构、UTXO vs 账户模型、51%攻击、eclipse攻击
├── 02_smart_contract_auditing.md             ← 重入/整数溢出/tx.origin/delegatecall、Slither/Mythril/Echidna
├── 03_defi_protocol_attacks.md               ← 闪电贷、预言机操控、MEV三明治攻击、Rug Pull检测
└── 04_web3_pentest_tools.md                  ← Foundry（forge/cast/anvil/chisel）、静态分析工具、RPC安全评估
```

从区块链基础到DeFi攻击分析与智能合约审计，一站式学习。使用web3.py 6.x和Foundry进行实操PoC演示。涵盖真实事件（Euler Finance $197M闪电贷）、MEV机器人原理、Slither/Mythril漏洞扫描、RPC端点安全评估。

---

## 43. 物理安全渗透

```
43_Physical_Security_Pentesting/
├── 01_physical_pentest_methodology.md    ← PTES物理领域5阶段、授权书模板、漏洞检查清单
├── 02_lock_bypass_and_access_control.md  ← 弹子锁拨片（SPP/梳妆/碰撞）、电子门禁缺陷分析
├── 03_rfid_nfc_cloning.md                ← Proxmark3 LF/HF、MIFARE Classic嵌套攻击、nfcpy NFC分析
└── 04_physical_recon_and_social_engineering.md ← 被动侦察、尾随、借口攻击、西奥迪尼6原则
```

从方法论到实施，全面覆盖物理渗透测试。涵盖锁具破解、RFID/NFC克隆（Proxmark3）、基于西奥迪尼影响原则的社会工程学。包含门禁日志异常检测与物理渗透报告生成的Python CLI工具。

---

## 44. 事件响应/DFIR

```
44_Incident_Response_DFIR/
├── 01_ir_methodology_and_playbooks.md     ← NIST SP 800-61r2、PICERL、勒索软件/钓鱼手册、日志时间线
├── 02_memory_and_disk_forensics.md        ← Volatility3、MFT分析、MACB时间戳、Plaso时间线
├── 03_network_forensics_and_log_analysis.md ← 100+ tshark过滤器、Zeek日志、Windows Event ID、Sysmon、PCAP C2 IOC
└── 04_threat_containment_and_eradication.md ← 网络隔离、持久化痕迹收集、5-Why分析
```

完整的DFIR工作流：检测→分析→封控→清除→恢复。Python CLI工具涵盖可疑进程检测（白名单比对、名称伪装）、基于PCAP的C2 IOC提取（信标检测/DNS隧道）、Windows持久化痕迹收集与风险评分。

---

## 45. 恶意代码开发

```
45_Malware_Development/
├── 01_malware_fundamentals_and_pe_structure.md ← PE文件结构、IAT、香农熵、可疑API分类
├── 02_shellcode_and_injection_techniques.md    ← PIC shellcode、XOR编码、CreateRemoteThread/APC/进程镂空
├── 03_c2_framework_development.md              ← C2架构、HTTP C2服务端+代理、DNS隧道、商用C2对比
└── 04_av_edr_evasion.md                        ← 直接系统调用、NTDLL解钩、ETW/AMSI补丁、沙箱检测
```

面向红队和恶意代码分析师的开发与规避技术。Python CLI涵盖PE文件分析（熵/API分类）、shellcode XOR编码/反汇编、字符串混淆、沙箱检测。深入讲解直接syscall（NASM存根）、NTDLL解钩、ETW补丁、AMSI绕过等概念。

---

## 46. CTF技巧

```
46_CTF_Techniques/
├── 01_ctf_methodology_and_tools.md        ← CTF类型、工具生态、Docker Pwnbox Dockerfile、平台指南
├── 02_pwn_and_rev_ctf.md                  ← 完整pwntools模板（ret2win/ret2libc/格式字符串/堆）、angr解题
├── 03_web_and_crypto_ctf.md               ← 盲注自动化、SSTI利用、JWT攻击、RSA/AES/哈希长度扩展攻击
└── 04_ctf_automation_and_frameworks.md    ← DynELF、GDB tmux分屏、angr自动化、Frida Android、取证流水线
```

从方法论到自动化，全方位覆盖CTF技巧。包含所有常见二进制题型的pwntools模板、angr符号执行、Frida动态插桩（Android CTF）、取证自动化流水线，以及CTFd API客户端用于题目管理和Flag提交。

---

## 47. 移动取证

```
47_Mobile_Forensics/
├── 01_android_forensics.md          ← Android文件系统/ADB取证/SQLite制品/备份解析CLI
├── 02_ios_forensics.md              ← iOS APFS结构/iTunes备份解析/iMessage/Health数据提取CLI
├── 03_mobile_evidence_extraction.md ← 逻辑/文件系统/物理提取/哈希完整性/自动取证CLI
└── 04_mobile_forensics_tools.md     ← Autopsy/MVT/Frida/jadx/APK自动分析CLI
```

Android/iOS移动取证全流程。ADB制品提取、iTunes备份解密/解析、MVT检测Pegasus间谍软件、APK逆向工程，含法律证据完整性维护方法。

---

## 48. 威胁建模

```
48_Threat_Modeling/
├── 01_stride_methodology.md         ← STRIDE六类/DFD绘制/信任边界/自动分析CLI
├── 02_pasta_dread_attack_trees.md   ← PASTA七步/DREAD评分/攻击树/Kill Chain/ATT&CK
├── 03_threat_modeling_tools.md      ← MS TMT/Threat Dragon/IriusRisk/CI/CD集成/XML→HTML CLI
└── 04_threat_modeling_practice.md   ← 电商/移动银行/K8s实战场景/完整工作流CLI
```

实战应用STRIDE、PASTA、DREAD方法论。从DFD绘制到威胁识别、缓解措施推导、CI/CD流水线集成，一个Python CLI自动化全流程。

---

## 49. 红队基础设施

```
49_Red_Team_Infrastructure/
├── 01_c2_frameworks.md               ← Cobalt Strike/Sliver/Havoc结构/HTTP C2实现/检测规则
├── 02_domain_fronting_redirectors.md ← CDN前置/Apache/Nginx重定向器/DNS隧道/流量过滤CLI
├── 03_opsec_infrastructure.md        ← OPSEC五步/Long-Short Haul C2/CT日志/OPSEC审计CLI
└── 04_red_team_automation.md         ← Ansible/Terraform基础设施/载荷流水线/行动管理CLI
```

红队C2基础设施与OPSEC。Sliver/Havoc框架、Apache重定向器、DNS隧道、Terraform AWS自动化，适用于授权红队演练、CTF和安全研究。

---

## 50. 游戏安全

```
50_Game_Hacking/
├── 01_memory_manipulation.md        ← 游戏内存/ReadProcessMemory/AOB扫描/指针链CLI
├── 02_cheat_engine_advanced.md      ← CE Lua脚本/自动汇编/结构体分析/CT文件解析CLI
├── 03_packet_manipulation.md        ← 游戏包捕获/mitmproxy/protobuf逆向/重放CLI
└── 04_anti_cheat_analysis.md        ← VAC/EAC/BattlEye原理/检测技术/进程分析CLI/CTF题型
```

游戏安全研究与CTF游戏题目。Cheat Engine内存操作、数据包中间人分析、反作弊内部机制，适用于教育、CTF和安全研究目的。

---

## 51. 浏览器扩展安全

```
51_Browser_Extension_Security/
├── 01_extension_architecture.md       ← MV2/V3对比/Background/Content Script/CSP/攻击面分析
├── 02_malicious_extension_analysis.md ← 恶意扩展类型/IOC/混淆分析/CRX自动分析CLI
├── 03_extension_pentesting.md         ← Content Script XSS/跨扩展攻击/Selenium自动扫描CLI
└── 04_extension_security_hardening.md ← MV3安全加固/最小权限/企业GPO/风险评估CLI
```

浏览器扩展安全全面覆盖。恶意扩展IOC检测、CRX自动分析、Content Script XSS和postMessage攻击、Selenium动态漏洞扫描器、企业策略管理。

---

## CTF实验环境（labs/）

```
labs/
├── 01_web_hacking_lab/      ← SQLi/XSS/SSRF/JWT漏洞Flask应用（Docker）
├── 02_pwn_lab/              ← BOF/格式字符串/堆利用漏洞二进制环境
├── 03_network_lab/          ← 数据包分析/MITM/ARP欺骗pcap+实验环境
├── 04_cloud_container_lab/  ← 漏洞Docker/K8s环境、容器逃逸场景
├── 05_full_scenario_lab/    ← 侦察→入侵→横向移动→权限提升→数据外泄综合场景
├── start_lab.sh             ← 一键docker-compose up启动全部实验
└── stop_all.sh              ← 停止全部实验
```

5个Docker化CTF漏洞环境——Web、二进制、网络、云原生、综合场景，可在本地即时实验。共12个Flag，`start_lab.sh`一键启动全部环境。

---

## 免责声明

> **本项目中所有技术必须仅在授权环境中使用。**

- 仅在CTF、漏洞赏金或合同范围内的渗透测试中使用
- 发现漏洞时遵循负责任披露（Responsible Disclosure）原则
- 未经授权访问他人系统违反《网络安全法》等相关法律法规

---

<div align="center">

**⚔️ VibeHacking** — 成为实战安全专家的旅程


</div>
