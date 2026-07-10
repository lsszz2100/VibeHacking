<div align="center">

# ⚔️ VibeHacking

### 实战网络安全完全攻略 — AI时代的黑客圣经

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-75-blueviolet)](#目录)
[![Files](https://img.shields.io/badge/Docs-491%2B%20Files-brightgreen)](#目录)
[![Lines](https://img.shields.io/badge/Lines-550%2C000%2B-orange)](#目录)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-ai驱动的网络安全)
[![Play Wargame](https://img.shields.io/badge/Play_Wargame-terminal_infiltration·75-9933ff)](https://lsszz2100.github.io/VibeHacking/)

> 🎮 **浏览器终端渗透 CTF 战争游戏** — 用伪 Shell（`connect`·`cat`·`submit`）逐层攻破目标 `vibe.corp` 的 5 道安全层（外围→Web→内网→金库→核心），通关 75 道挑战。含启动序列、`ACCESS GRANTED` 演出、矩阵雨、音效、提示与中英文。取材自本仓库的 75 个章节。([介绍](wargame/README.md) · 启用 GitHub Pages 后可访问)

<br/>

> 从理论到实践，涵盖CTF、漏洞赏金、渗透测试、红队行动的网络安全知识库。
> 全面覆盖**2026年Claude・GPT-4o时代**的AI漏洞研究、云安全、无线安全与密码学。

**🌐 Language / 言語 / 语言:**
[한국어](README.md) · [English](README.en.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## 关于本项目

为了帮助安全学习者提升实战技能，本项目汇集了可直接运行的代码与系统化的方法论。  
从CTF到漏洞赏金、红队到AI安全，这是一个**多语言、实战导向的安全知识中心**。

**VibeHacking的特点：**

- **代码优先** — 每个章节均包含可直接复制粘贴的命令和代码
- **AI集成** — 介绍如何将Claude/GPT-4o作为安全分析工具使用
- **紧跟前沿** — 涵盖2026年AI安全生态系统，包括Anthropic Claude和OpenAI GPT-4o
- **多语言支持** — 提供韩语、英语、日语和中文版本
- **全面覆盖** — 漏洞赏金、SOC、云安全、WiFi、密码学、红队等全领域

---

## 🤖 用 AI CLI 自然语言学习

在 **仓库目录内** 运行 `claude` / `codex` / `gemini`，AI 会将全部 75 个章节作为上下文读取，成为你的自然语言辅导员。无需手动搜索文件，一句话即可完成学习与实践。

```bash
cd VibeHacking
claude   # 或: codex / gemini
```

| AI CLI | 安装 | 优势 |
|--------|------|------|
| **Claude Code** | `npm i -g @anthropic-ai/claude-code` | 文件读取 + 命令执行，中文流畅 |
| **Codex CLI** | `npm i -g @openai/codex` | 代码生成与分析专精 |
| **Gemini CLI** | `npm i -g @google/gemini-cli` | 最大上下文窗口 (100万+ token) |

**即用提示词：**

```
「我是完全的安全初学者，这个仓库应该按什么顺序学习？」
「读取 05_Web_Hacking/02_sql_injection_advanced.md 并解释核心攻击技术」
「启动 Web 渗透 Lab 01，一步步引导我在 DVWA 上完成 SQL 注入练习」
「这道 CTF 题只给我提示，不要直接给解答」
「解释 Kerberoasting 概念，并告诉我如何搭建练习环境」
```

> 🤖 完整指南 + 4个学习场景 + 提示词模板 → **[AI_LEARNING.md](./AI_LEARNING.md)**

---

## 🛠️ CLI + 实验环境 — 立即开始

### 1分钟安装

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
python3 vhack.py list        # 浏览全部 75 个章节
```

> 📖 详细安装指南 → **[INSTALL.md](./INSTALL.md)**
> 📘 完整命令参考 → **[USAGE.md](./USAGE.md)**
> 🤖 用 AI CLI 自然语言学习 → **[AI_LEARNING.md](./AI_LEARNING.md)**

### `vhack` 主要命令

```bash
# 浏览与学习
python3 vhack.py list                    # 全部 75 个章节列表
python3 vhack.py list --search web       # 按关键词过滤章节
python3 vhack.py study 5                 # Web 渗透章节文件列表
python3 vhack.py study 5 1               # 在终端阅读 OWASP Top 10
python3 vhack.py search "Kerberoasting"  # 全文搜索所有文档

# Docker 实验环境管理 (需要 Docker)
python3 vhack.py lab ls                  # 实验环境列表 + 访问地址
python3 vhack.py lab start 01            # 启动 Web 渗透实验室 → 8080/dvwa · 3001 · 8081
python3 vhack.py lab start 02            # 启动二进制漏洞利用实验室
python3 vhack.py lab status              # 查看运行中的容器
python3 vhack.py lab stop --all          # 停止所有实验室

# Shell alias — 全局使用 vhack（一次性设置）
python3 vhack.py alias install           # 自动检测 shell → 写入 RC 文件
python3 vhack.py alias status            # 查看安装状态
python3 vhack.py alias remove            # 删除 alias

# 更新
python3 vhack.py update                  # git pull 获取最新内容
```

### 快速参考

| 命令 | 说明 |
|------|------|
| `vhack list` | 列出全部 75 个章节 |
| `vhack list --search <关键词>` | 按关键词过滤章节 |
| `vhack study <编号>` | 章节文件列表 |
| `vhack study <编号> <文件>` | 在终端中阅读文件 |
| `vhack search <关键词>` | 全文搜索所有文档 |
| `vhack info <编号>` | 章节详细信息 |
| `vhack lab ls` | 实验室列表 + 访问地址 |
| `vhack lab start <id>` | 启动实验室 |
| `vhack lab stop <id>` | 停止实验室 |
| `vhack lab stop --all` | 停止所有实验室 |
| `vhack lab status` | 查看运行中的容器 |
| `vhack lab logs <id>` | 实时日志流 |
| `vhack alias install` | 注册 shell alias |
| `vhack alias install --profile <文件>` | 指定配置文件 |
| `vhack alias status` | 查看安装状态 |
| `vhack alias remove` | 删除 alias |
| `vhack update` | `git pull` 更新内容 |

### 实验环境 (基于 Docker)

| # | 实验室名称 | 内容 | 访问地址 | 难度 |
|:-:|-----------|------|----------|:----:|
| **01** | Web 渗透实验室 | DVWA · Juice Shop · WebGoat | 8080(DVWA·SQLi) / 3001(Juice Shop) / 8081(WebGoat) | ★★☆ |
| **02** | 二进制漏洞利用实验室 | BOF · ret2libc · ROP · fmtstr · heap | nc localhost 10001~10005 | ★★★ |
| **03** | 网络渗透实验室 | SSH · FTP · DNS · SMTP 漏洞服务 | docker exec shell | ★★☆ |
| **04** | 云/容器安全实验室 | SSRF · AWS IMDS · K8s 逃逸 | http://localhost:8080 | ★★★ |
| **05** | 综合场景实验室 | APT 攻击链模拟 | http://localhost:8888 | ★★★★ |
| **06** | 固件渗透实验室 | binwalk · QEMU 仿真 · 硬编码凭证 | http://localhost:8062 | ★★★ |
| **07** | 移动安全实验室 | APK 静态分析 · Frida · JWT alg:none 绕过 | http://localhost:8072 | ★★★ |

```bash
# 快速实践示例：Web 渗透
python3 vhack.py study 5 1        # ① 阅读 OWASP Top 10 理论
python3 vhack.py lab start 01     # ② 启动 DVWA/Juice Shop 实验室
# ③ DVWA: http://localhost:8080/dvwa/  Juice Shop: http://localhost:3001
python3 vhack.py lab stop 01      # ④ 完成后停止
```

---

## 目录

| # | 章节 | 核心内容 | 文件数 |
|---|------|---------|-------|
| 01 | [Linux基础 & Kali Linux](#01-linux基础--kali-linux) | 必备命令、Kali配置、Bash脚本 | 6 |
| 02 | [网络黑客技术](#02-网络黑客技术) | OSI/TCP-IP、数据包分析、无线攻击 | 6 |
| 03 | [系统入侵](#03-系统入侵) | 密码破解、缓冲区溢出 | 6 |
| 04 | [逆向工程](#04-逆向工程) | 汇编语言、x64dbg、PE结构 | 6 |
| 05 | [Web渗透](#05-web渗透) | OWASP Top 10、SQL注入进阶、XSS/CSRF | 6 |
| 06 | [恶意代码分析](#06-恶意代码分析) | 静态/动态分析、Volatility、Android | 6 |
| 07 | [数字取证](#07-数字取证) | 取证流程、Windows痕迹、网络取证 | 6 |
| 08 | [Python黑客技术](#08-python黑客技术) | 工具开发、网络扫描器、Web自动化 | 6 |
| 09 | [漏洞利用技术](#09-漏洞利用技术) | ROP Chain、SEH、Linux BOF、提权 | 6 |
| 10 | [渗透测试方法论](#10-渗透测试方法论) | 渗透流程、OSINT侦察、报告撰写 | 6 |
| 11 | [**AI驱动的网络安全**](#11-ai驱动的网络安全) | Claude Opus 4、GPT-4o、LLM漏洞研究、CTF自动化 | 6 |
| 12 | [**漏洞赏金**](#12-漏洞赏金) | 方法论、Burp Suite进阶、自动化工具 | 6 |
| 13 | [**SOC & 蓝队**](#13-soc--蓝队) | SOC运营、Splunk分析、威胁狩猎 | 6 |
| 14 | [**云安全**](#14-云安全) | AWS/Azure/GCP攻击向量、渗透测试、清单 | 6 |
| 15 | [**WiFi黑客技术**](#15-wifi黑客技术) | WPA2破解、PMKID、Evil Twin、自动化 | 6 |
| 16 | [**密码学**](#16-密码学) | 黑客密码学、哈希攻击、应用密码学 | 6 |
| 17 | [**红队行动**](#17-红队行动) | 作战手册、钓鱼/社会工程学、API渗透 | 6 |
| 18 | [**DevSecOps**](#18-devsecops) | SAST/SCA/DAST、容器安全、CI/CD流水线 | 6 |
| 19 | [**汇编语言**](#19-汇编语言) | x86/x64基础、shellcode开发、反汇编分析 | 6 |
| 20 | [**Shell脚本**](#20-shell脚本) | Bash基础、渗透自动化、后渗透脚本 | 6 |
| 21 | [**Windows漏洞利用**](#21-windows漏洞利用) | Windows内部结构、提权、防御规避 | 6 |
| 22 | [**密码破解**](#22-密码破解) | 哈希类型/字典、Hashcat/John、高级技术 | 6 |
| 23 | [**数据库攻击**](#23-数据库攻击) | Oracle/MySQL攻击、DB提权、取证与审计 | 6 |
| 24 | [**网络基础设施安全**](#24-网络基础设施安全) | DNS攻击、邮件服务器(SPF/DKIM/DMARC)、SSH隧道 | 6 |
| 25 | [**威胁情报**](#25-威胁情报) | CTI基础、OSINT/Shodan、事件响应、蜜罐 | 6 |
| 26 | [**Linux加固**](#26-linux加固) | iptables/nftables、PAM认证、KISA漏洞评估 | 6 |
| 27 | [**IoT黑客技术**](#27-iot黑客技术) | 攻击面分析、固件分析、IoT漏洞利用 | 6 |
| 28 | [**移动端攻击**](#28-移动端攻击) | Android渗透测试、iOS渗透测试、移动流量分析 | 6 |
| 29 | [**容器/Kubernetes安全**](#29-容器kubernetes安全) | Docker安全、Kubernetes攻击、容器逃逸 | 6 |
| 30 | [**漏洞研究**](#30-漏洞研究) | 模糊测试技术、漏洞分析、高级利用开发 | 6 |
| 31 | [**AI/ML系统安全**](#31-aiml系统安全) | 对抗样本、提示注入、模型提取、智能体安全 | 6 |
| 32 | [**网络设备攻击**](#32-网络设备攻击) | IOS侦察、L2攻击、路由协议操控、管理平面利用 | 6 |
| 33 | [**OSINT与社会工程学**](#33-osint与社会工程学) | 信息收集方法论、目标画像、钓鱼基础设施构建与规避 | 6 |
| 34 | [**硬件攻击**](#34-硬件攻击) | 接口分析(UART/JTAG/SPI)、固件提取、侧信道与故障注入 | 6 |
| 35 | [**供应链攻击**](#35-供应链攻击) | 软件供应链入侵、CI/CD投毒、SolarWinds·XZ模式分析 | 6 |
| 36 | [**汽车黑客技术**](#36-汽车黑客技术) | CAN总线分析、ECU利用、车联网与OTA攻击 | 6 |
| 37 | [**ICS/SCADA安全**](#37-icsscada安全) | ICS协议侦察、SCADA利用、OT网络攻防 | 6 |
| 38 | [**云原生安全**](#38-云原生安全) | CNAPP、eBPF运行时安全、镜像加固、容器逃逸 | 6 |
| 39 | [**零信任架构**](#39-零信任架构) | ZTA原则、身份/设备信任、微分段、SASE | 6 |
| 40 | [**威胁狩猎**](#40-威胁狩猎) | 狩猎方法论、MITRE ATT&CK场景、100+ KQL/SPL查询、SOAR自动化 | 6 |
| 41 | [**韩国安全认证**](#41-韩国安全认证) | 信息安全工程师、ISMS-P、CISSP/OSCP路线图、安全法规 | 6 |
| 42 | [**区块链/Web3安全**](#42-区块链web3安全) | EVM结构、智能合约审计、DeFi攻击、Web3渗透工具 | 6 |
| 43 | [**物理安全渗透**](#43-物理安全渗透) | 物理渗透测试方法论、门锁破解、RFID克隆、社会工程学 | 6 |
| 44 | [**事件响应/DFIR**](#44-事件响应dfir) | IR手册、内存/磁盘取证、网络取证、封控与清除 | 6 |
| 45 | [**恶意代码开发**](#45-恶意代码开发) | PE结构、shellcode/注入、C2框架、AV/EDR规避 | 6 |
| 46 | [**CTF技巧**](#46-ctf技巧) | CTF方法论/工具、PWN/REV、Web/密码学、自动化框架 | 6 |
| 47 | [**移动取证**](#47-移动取证) | Android/iOS取证、证据提取、移动取证工具 | 6 |
| 48 | [**威胁建模**](#48-威胁建模) | STRIDE/PASTA/DREAD、攻击树、威胁建模工具 | 6 |
| 49 | [**红队基础设施**](#49-红队基础设施) | C2框架、域前置、OPSEC、基础设施自动化 | 6 |
| 50 | [**游戏黑客**](#50-游戏黑客) | 内存操控、Cheat Engine、数据包操控、反作弊分析 | 6 |
| 51 | [**浏览器扩展安全**](#51-浏览器扩展安全) | MV2/V3、恶意扩展分析、Content Script XSS | 6 |
| 52 | [**API安全**](#52-api安全) | OWASP API Top 10、BOLA、GraphQL、模糊测试、OAuth2 | 6 |
| 53 | [**无服务器安全**](#53-无服务器安全) | Lambda攻击、事件注入、IAM滥用、IaC扫描 | 6 |
| 54 | [**Active Directory攻击**](#54-active-directory攻击) | AD枚举、Kerberoasting、DCSync、黄金票据 | 6 |
| 55 | [**检测规避技术**](#55-检测规避技术) | AV/EDR绕过、IDS/IPS规避、直接syscall、痕迹清除 | 6 |
| 56 | [**AI红队**](#56-ai红队) | 提示注入、模型提取、对抗样本 | 6 |
| 57 | [**量子密码学**](#57-量子密码学) | QKD、后量子算法、NIST PQC | 6 |
| 58 | [**云事件响应**](#58-云事件响应) | CloudTrail取证、Azure/GCP IR、威胁狩猎 | 6 |
| 59 | [**供应链安全**](#59-供应链安全) | SBOM、依赖混淆、SLSA构建完整性 | 6 |
| 60 | [**浏览器安全进阶**](#60-浏览器安全进阶) | JS引擎利用、沙箱逃逸、MV3 | 6 |
| 61 | [**固件黑客**](#61-固件黑客) | 固件提取、Ghidra分析、QEMU模拟 | 6 |
| 62 | [**汽车安全**](#62-汽车安全) | CAN总线、ECU/UDS、V2X攻击 | 6 |
| 63 | [**OT/ICS进阶**](#63-otics进阶) | SCADA、PLC利用、工业协议 | 6 |
| 64 | [**威胁情报平台**](#64-威胁情报平台) | MISP、威胁情报源、IOC自动化 | 6 |
| 65 | [**逆向工程进阶**](#65-逆向工程进阶) | 反调试、脱壳、符号执行 | 6 |
| 66 | [**漏洞利用开发**](#66-漏洞利用开发) | ROP链、堆/内核/浏览器利用 | 6 |
| 67 | [**恶意软件开发解析**](#67-恶意软件开发解析) | C2架构、Shellcode、持久化、规避 | 6 |
| 68 | [**紫队运营**](#68-紫队运营) | 攻击模拟、检测工程、ATT&CK | 6 |
| 69 | [**LLM安全**](#69-llm安全) | OWASP LLM Top 10、提示注入、护栏 | 6 |
| 70 | [**Kubernetes安全**](#70-kubernetes安全) | RBAC滥用、Pod逃逸、etcd、加固 | 6 |
| 71 | [**蓝牙/RF黑客**](#71-蓝牙rf黑客) | BLE攻击、RTL-SDR、Zigbee IoT安全 | 6 |
| 72 | [**恶意软件沙箱分析**](#72-恶意软件沙箱分析) | ANY.RUN/VirusTotal、PE分析、IOC提取 | 6 |
| 73 | [**漏洞赏金自动化**](#73-漏洞赏金自动化) | HackerOne、subfinder/nuclei流水线、CVSS报告 | 6 |
| 74 | [**代码审计**](#74-代码审计) | Semgrep/CodeQL、Source-Sink追踪、CI/CD安全门 | 6 |
| 75 | [**红队报告撰写**](#75-红队报告撰写) | ATT&CK映射、双受众报告、复盘 | 6 |
| 🧪 | [**CTF实验环境（labs/）**](#ctf实验环境labs) | Web/二进制/网络/云原生/综合场景/固件/移动Docker CTF实验 | 50 |

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
| 攻击机 | Kali Linux (最新) |
| 虚拟化 | VMware Workstation / VirtualBox |
| 靶机环境 | Metasploitable2、DVWA、HackTheBox、TryHackMe、CloudGoat |
| 分析工具 | Wireshark、Burp Suite、IDA Pro / Ghidra、x64dbg |
| 编程语言 | Python 3.x、Bash、pwntools |
| AI工具 | Claude Opus 4.6、GPT-4o（） |
| 无线网卡 | Alfa AWUS036ACH（支持2.4/5GHz监听模式） |
| 云平台 | AWS Free Tier、CloudGoat |

---

## 01. Linux基础 & Kali Linux

```
01_Linux_Basics/
├── 01_linux_essential_commands.md   ← 文件/进程/网络必备命令
├── 02_kali_linux_setup.md           ← Kali初始配置、工具安装
├── 03_bash_scripting.md             ← 自动化脚本、实战示例
├── 04_linux_privilege_escalation.md ← Linux权限提升 — sudo · SUID · Capabilities · 内核利用
├── 05_linux_security_tools.md       ← Linux安全工具参考
└── 06_linux_ctf_practical_lab.md    ← Linux CTF实战实验室 — 权限提升 · SUID · Cron · 环境变量
```

**核心内容：** 文件系统、进程管理、网络命令、权限管理、30+个Bash自动化脚本

---

## 02. 网络黑客技术

```
02_Network_Hacking/
├── 01_osi_tcpip.md          ← OSI七层、TCP/IP协议栈、协议分析
├── 02_packet_analysis.md    ← Wireshark实战、tcpdump、数据包操控
├── 03_wireless_hacking.md   ← WEP/WPA2破解、Evil Twin、无线攻击
├── 04_mitm_advanced.md      ← MITM进阶 — ARP欺骗 · SSL剥离 · bettercap · mitmproxy
├── 05_network_exploitation_techniques.md ← 高级网络利用技术
└── 06_network_ctf_lab.md    ← CTF风格网络黑客实验室
```

**核心内容：** 数据包捕获与分析、ARP欺骗、MITM中间人攻击、无线网络攻击、防火墙绕过

---

## 03. 系统入侵

```
03_System_Hacking/
├── 01_password_cracking.md       ← Hashcat、John、彩虹表、在线破解
├── 02_buffer_overflow.md         ← 栈溢出原理、shellcode、实战示例
├── 03_active_directory_attack.md ← AD攻击完全指南、Kerberoasting、DCSync
├── 04_kerberos_delegation_attacks.md ← Kerberos委派攻击 — 完整指南
├── 05_system_defense_and_detection.md ← 系统攻击检测与防御
└── 06_system_ctf_lab.md          ← CTF风格系统黑客实验室
```

**核心内容：** 哈希破解策略、从原理到漏洞利用的BOF完整链路、Active Directory攻击链完全攻略

---

## 04. 逆向工程

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md   ← x86/x64汇编、寄存器、栈帧
├── 02_ollydbg_practical.md        ← x64dbg实战分析
├── 03_pe_structure.md             ← PE文件结构、IAT/EAT、加壳
├── 04_ghidra_and_dynamic_analysis.md ← Ghidra实战分析与WorstFit Unicode漏洞
├── 05_advanced_unpacking_and_deobfuscation.md ← 高级脱壳与反混淆
└── 06_reversing_ctf_lab.md        ← CTF风格逆向实验室
```

**核心内容：** 汇编语言、调试器使用、PE结构深度分析、IDA Pro/Ghidra

---

## 05. Web渗透

```
05_Web_Hacking/
├── 01_owasp_top10.md              ← OWASP Top 10（2021）、Burp Suite、Nikto
├── 02_sql_injection_advanced.md   ← Blind/时间盲注、NoSQL、SQLMap实战
├── 03_xss_csrf_file_upload.md     ← Stored/Reflected/DOM XSS、CSRF、Webshell
├── 04_waf_bypass_advanced_web.md  ← WAF绕过与高级Web攻击技术
├── 05_web_security_tools_and_automation.md ← Web安全工具与自动化
└── 06_web_ctf_practical_lab.md    ← Web黑客CTF实战实验室 — SQL注入、XSS、SSRF、SSTI综合
```

**核心内容：** OWASP Top 10实战、SQL注入完全攻略、XSS/CSRF/文件上传/XXE/SSRF

---

## 06. 恶意代码分析

```
06_Malware_Analysis/
├── 01_malware_analysis.md            ← 分类、分析环境、静态/动态分析、YARA
├── 02_memory_forensics_malware.md    ← Volatility完全攻略、代码注入检测
├── 03_android_malware_analysis.md    ← APK分析、Frida Hook、MobSF
├── 04_yara_and_detection.md          ← YARA规则开发与恶意软件自动检测
├── 05_malware_defense_and_hunting.md ← 恶意软件防御与狩猎
└── 06_malware_ctf_practical_lab.md   ← 恶意软件分析CTF实战实验室 — 静态/动态分析、脱壳
```

**核心内容：** 静态・动态・内存分析全流程、Volatility插件、Android恶意代码

---

## 07. 数字取证

```
07_Digital_Forensics/
├── 01_digital_forensics.md               ← 取证原则、证据收集、镜像分析
├── 02_windows_forensics_artifacts.md     ← 注册表、事件日志、Prefetch、浏览器痕迹
├── 03_network_forensics.md               ← Wireshark、Zeek、Suricata、事件响应
├── 04_advanced_volatility.md             ← Volatility3进阶 — 进程分析、网络与恶意软件检测
├── 05_forensics_automation_and_tools.md  ← 取证自动化与工具
└── 06_forensics_ctf_lab.md               ← 取证 CTF实验室
```

**核心内容：** 证据收集规程、Windows痕迹完整分析、网络取证、时间线分析

---

## 08. Python黑客技术

```
08_Python_Hacking/
├── 01_python_hacking_tools.md       ← 端口扫描器、嗅探器、后门等30+个示例
├── 02_python_network_scanner.md     ← 多线程扫描器、ARP、DNS枚举、SSH爆破
├── 03_python_web_exploitation.md    ← Web爬虫、SQLi自动化、XSS扫描器、报告生成
├── 04_python_exploit_automation.md  ← Python漏洞利用自动化 — pwntools、ROPgadget与CTF工具
├── 05_python_security_automation.md ← Python安全自动化 — Scapy、requests、paramiko、自动化工具
└── 06_python_hacking_ctf_lab.md     ← Python黑客 CTF实战实验室
```

**核心内容：** 基于Scapy、paramiko、requests的安全工具开发，50+个完整可运行代码

---

## 09. 漏洞利用技术

```
09_Exploit_Techniques/
├── 01_advanced_exploitation.md   ← ROP Chain、Heap Spray、SEH、Win32 shellcoding
├── 02_linux_exploitation.md      ← Linux BOF、Ret2Libc、格式化字符串、提权
├── 03_heap_exploitation.md       ← tcache投毒、UAF、House of系列、pwndbg
├── 04_format_string_exploits.md  ← 格式化字符串利用 — 任意读写与GOT覆写
├── 05_exploit_defense_and_mitigation.md ← 漏洞利用防御与缓解 — ASLR、DEP/NX、栈金丝雀、CFG
└── 06_exploit_ctf_lab.md         ← 漏洞利用技术 CTF实战实验室
```

**核心内容：** DEP/ASLR/NX绕过、ROP链构造、格式化字符串漏洞利用、堆漏洞完全攻略

---

## 10. 渗透测试方法论

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← 完整渗透测试流程、MITRE ATT&CK、报告撰写
├── 02_osint_recon.md           ← Google Dorks、Shodan、子域名枚举、GitHub敏感信息挖掘
├── 03_report_writing.md        ← 专业报告撰写、CVSS评分、PoC编写、管理层/技术报告模板
├── 04_post_exploitation.md     ← 后渗透方法论 — 持久化、信息收集、权限提升
├── 05_pentest_reporting_and_remediation.md ← 渗透测试报告与修复 — CVSS评分、报告撰写
└── 06_pentest_ctf_lab.md       ← 渗透测试方法论 CTF实战实验室
```

**核心内容：** 系统化渗透测试方法论、OSINT工具完整运用、专业报告撰写（CVSS・PoC・合规要求）

---

## 11. AI驱动的网络安全

> **2026年，AI正在重塑网络安全格局。**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Claude・GPT-4o・내부 연구 프로그램全景图
├── 02_llm_vulnerability_research.md   ← 用LLM发现零日漏洞、AI模糊测试、代码分析自动化
├── 03_ai_assisted_pentesting.md       ← AI辅助渗透测试工作流、提示词工程
├── 04_ai_ctf_automation.md            ← CTF自动化AI智能体、密码/Web/取证专业子智能体
├── 05_claude_gpt_cyber_integration.md ← AI集成 — Claude + GPT-4o安全分析工具指南
└── 06_ai_security_ctf_lab.md          ← CTF风格AI安全实验室
```

### 2026年AI安全格局

| 模型 | 机构 | 能力 | 访问方式 |
|-----|------|------|---------|
| **Claude Opus 4** | Anthropic | 自主发现17年历史FreeBSD RCE漏洞，数千个零日 | 내부 연구 프로그램（仅12家合作伙伴） |
| **GPT-4o** | OpenAI | 二进制逆向、76%自主解决CTF、YARA生成 | （openai.com） |
| **Claude Opus 4.6** | Anthropic | 代码漏洞分析、CTF辅助、YARA自动化 | 公开可用 |

**核心内容：** AI安全生态系统完整分析、基于Claude API的漏洞扫描器实现、AI辅助渗透测试自动化、CTF解题AI智能体（密码学/Web/取证/逆向专业子智能体）

---

## 12. 漏洞赏金

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd方法论、IDOR、XSS绕过、自动化
├── 02_burp_suite_advanced.md      ← Burp Suite完全攻略、JWT攻击、请求走私
├── 03_bug_bounty_automation.md    ← Nuclei、ffuf、dalfox、自动化流水线
├── 04_api_security_testing.md     ← API安全测试与漏洞赏金实战指南
├── 05_advanced_vuln_chains.md     ← 漏洞赏金进阶 — 漏洞链、子域名接管、账户接管
└── 06_bug_bounty_ctf_lab.md       ← 漏洞赏金 CTF实战实验室
```

**核心内容：** 漏洞赏金完整工作流、Burp Suite高级功能、侦察→漏洞→报告自动化

---

## 13. SOC & 蓝队

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md       ← SOC架构、事件响应、关键事件ID、EDR
├── 02_splunk_siem_analysis.md   ← Splunk SPL完全攻略、100+检测查询
├── 03_threat_hunting.md         ← 威胁狩猎、勒索软件入侵调查、APT追踪
├── 04_qradar_xdr_blue_team.md   ← IBM QRadar与Azure Sentinel KQL与XDR蓝队实战指南
├── 05_detection_engineering.md  ← 检测工程 — 基于Sigma与MITRE ATT&CK的规则开发
└── 06_soc_ctf_lab.md            ← SOC/蓝队 CTF实验室
```

**核心内容：** SOC各层级职责、100+攻击检测模式、Splunk/QRadar/ELK查询、威胁狩猎方法论

---

## 14. 云安全

```
14_Cloud_Security/
├── 01_cloud_attack_vectors.md        ← AWS/Azure/GCP/K8s攻击向量完整分析
├── 02_aws_pentest.md                 ← AWS渗透测试方法论、提权、自动化
├── 03_cloud_security_checklist.md    ← CIS检查清单、Terraform、SCP策略
├── 04_GCP_Azure_Pentest.md           ← GCP与Azure渗透测试
├── 05_cloud_lateral_movement.md      ← 云横向移动 — 账户跳转、跨服务移动与权限提升
└── 06_cloud_security_ctf_lab.md      ← 云安全 CTF实战实验室
```

**核心内容：** IAM权限滥用、S3配置错误、容器逃逸、Kubernetes攻击、云安全检查清单

---

## 15. WiFi黑客技术

```
15_WiFi_Hacking/
├── 01_wifi_hacking_fundamentals.md   ← WEP/WPA/WPA2/WPA3理论、aircrack-ng基础
├── 02_wpa2_cracking.md               ← Hashcat/Aircrack、PMKID攻击、字典优化
├── 03_advanced_wifi_attacks.md       ← Evil Twin、KARMA、Bettercap、Scapy操控
├── 04_Enterprise_WiFi_Attacks.md     ← 企业WiFi攻击（WPA2-Enterprise / RADIUS）
├── 05_rogue_ap_and_detection.md      ← 恶意AP、强制门户、WiFi监控与检测
└── 06_wifi_ctf_lab.md                ← WiFi黑客 CTF实战实验室
```

**核心内容：** 四次握手、PMKID捕获、GPU破解、Evil Twin搭建、无线自动化

---

## 16. 密码学

```
16_Cryptography/
├── 01_cryptography_for_hackers.md   ← AES模式攻击、RSA漏洞、XOR破解
├── 02_hash_attacks.md               ← MD5碰撞、彩虹表、Kerberoasting
├── 03_applied_cryptography.md       ← Padding Oracle、ECDSA随机数重用、JWT攻击
├── 04_PKI_TLS_Attacks.md            ← PKI基础设施与TLS/SSL攻击
├── 05_crypto_implementation_attacks.md ← 密码实现攻击 — Padding Oracle、时序攻击、弱RNG
└── 06_crypto_ctf_practical_lab.md   ← 密码学CTF实战实验室 — 古典密码、RSA、ECC与哈希
```

**核心内容：** 密码实现漏洞、CTF密码学题型、安全密码实现指南

---

## 17. 红队行动

```
17_Red_Team_Operations/
├── 01_red_team_playbook.md               ← 行动架构、Cobalt Strike/Havoc、AV/EDR绕过
├── 02_phishing_and_social_engineering.md ← GoPhish、Evilginx2、鱼叉式钓鱼、BEC
├── 03_api_hacking.md                     ← OWASP API Top 10、GraphQL、Fuzzer开发
├── 04_C2_Infrastructure.md               ← C2（命令与控制）基础设施搭建与运营
├── 05_red_team_reporting.md              ← 红队报告 — 结果分析、利用链文档化
└── 06_red_team_ctf_lab.md                ← 红队行动 CTF实战实验室
```

**核心内容：** 红队vs渗透测试区别、C2框架运营、钓鱼基础设施、API漏洞完全攻略

---

## 18. DevSecOps

```
18_DevSecOps/
├── 01_devsecops_fundamentals.md    ← Shift Left、Semgrep、SonarQube、Snyk、ZAP
├── 02_container_security.md        ← Dockerfile安全、Trivy、Falco、K8s RBAC、cosign
├── 03_github_actions_security.md   ← CI/CD安全、OIDC、SHA固定、完整安全流水线
├── 04_Secret_Detection_and_SBOM.md ← 密钥检测与SBOM（软件物料清单）
├── 05_supply_chain_security.md     ← 供应链安全 — 依赖攻击、SLSA、签名验证
└── 06_devsecops_ctf_lab.md         ← DevSecOps CTF实战实验室
```

**核心内容：** 安全左移（Shift Left）、SAST/SCA/DAST/IaC扫描自动化、容器运行时检测、GitLab/Jenkins/GitHub Actions安全流水线完整实现

---

## 19. 汇编语言

```
19_Assembly_Language/
├── 01_x86_x64_Fundamentals.md   ← 寄存器、指令、栈帧、调用约定
├── 02_Shellcode_Development.md  ← shellcode编写、坏字节去除、ctypes执行测试
├── 03_Disassembly_Analysis.md   ← GDB/pwndbg、IDA/Ghidra、Capstone自动化
├── 04_ROP_Chain_Programming.md  ← ROP（面向返回编程）链构造
├── 05_shellcode_analysis_and_detection.md ← Shellcode分析与检测 — 静态/动态分析与签名编写
└── 06_assembly_ctf_lab.md       ← 汇编语言 CTF实战实验室
```

**核心内容：** x86/x64寄存器完全攻略、NASM编码、64位execve shellcode实现、基于Capstone的自动反汇编器

---

## 20. Shell脚本

```
20_Shell_Scripting/
├── 01_Bash_Scripting_Basics.md       ← 变量/数组/条件/循环/函数、awk/sed、端口扫描器
├── 02_Pentest_Automation.md          ← 侦察自动化、子域名枚举、漏洞扫描封装
├── 03_Post_Exploitation_Scripts.md   ← 反弹Shell、持久化、Python C2套接字实现
├── 04_Advanced_Obfuscation_Evasion.md ← Shell脚本混淆与检测规避
├── 05_bash_forensics_and_monitoring.md ← Bash取证与监控自动化 — 日志分析、异常检测
└── 06_shell_ctf_lab.md               ← Shell脚本 CTF实战实验室
```

**核心内容：** Bash实战脚本、从侦察到后渗透全流程自动化、7种反弹Shell一行命令、Python C2实现

---

## 21. Windows漏洞利用

```
21_Windows_Exploitation/
├── 01_Windows_Internals.md              ← PE格式、PEB/TEB、WinAPI核心函数、PE解析器代码
├── 02_Windows_Privilege_Escalation.md   ← 服务/注册表/DLL劫持、UAC绕过、令牌模拟
├── 03_Defense_Evasion.md                ← AMSI/ETW绕过、6种进程注入、LOLBAS、AES载荷加密
├── 04_COM_Object_Hijacking.md           ← COM对象劫持与WMI滥用
├── 05_windows_persistence_detection.md  ← Windows持久化检测 — 注册表、服务与WMI后门分析
└── 06_windows_ctf_lab.md                ← Windows漏洞利用 CTF实战实验室
```

**核心内容：** Windows内部结构深度解析、提权完全攻略、AMSI/AV/EDR绕过技术

---

## 22. 密码破解

```
22_Password_Cracking/
├── 01_Hash_Types_and_Wordlists.md      ← 哈希算法对比、hashid、CeWL/Crunch/CUPP、Python破解器
├── 02_Hashcat_and_John.md              ← 所有攻击模式、哈希类型模式号、规则编写、实战工作流
├── 03_Advanced_Cracking_Techniques.md  ← 彩虹表、PRINCE、高级掩码、密码喷洒工具
├── 04_Credential_Stuffing_Automation.md ← 撞库攻击与密码分析自动化
├── 05_password_policy_audit.md         ← 密码策略审计 — 弱策略检测、哈希强度分析
└── 06_password_ctf_lab.md              ← 密码破解 CTF实战实验室
```

**核心内容：** NTLM/WPA/ZIP/PDF破解策略、GPU优化、限速绕过密码喷洒自动化

---

## 23. 数据库攻击

```
23_Database_Hacking/
├── 01_oracle_mysql_attack.md       ← Oracle/MySQL/MSSQL攻击向量、盲注、带外数据提取
├── 02_db_privilege_escalation.md   ← 数据库用户提权、存储过程滥用、UDF注入、链接服务器
├── 03_db_forensics_defense.md      ← 数据库取证、审计日志、查询监控、加固清单
├── 04_nosql_and_cloud_db_attacks.md ← NoSQL与云数据库攻击
├── 05_database_defense_and_hardening.md ← 数据库防御与加固
└── 06_database_ctf_lab.md          ← 数据库黑客 CTF实验室
```

**核心内容：** 跨多DB的攻击链、通过数据库引擎提权、取证分析与防御加固

---

## 24. 网络基础设施安全

```
24_Network_Infrastructure_Security/
├── 01_dns_attack_defense.md                ← DNS劫持、区域传送、缓存投毒、DNSSEC绕过
├── 02_mail_server_security.md              ← SPF/DKIM/DMARC绕过、邮件服务器入侵、邮件伪造
├── 03_ssh_tunneling_port_forwarding.md     ← SSH隧道、动态端口转发、SOCKS代理、内网穿透
├── 04_network_security_automation.md       ← 网络安全自动化
├── 05_network_defense_automation.md        ← 网络防御自动化 — IDS/IPS调优、防火墙自动化
└── 06_network_infra_ctf_lab.md             ← 网络基础设施 CTF实验室
```

**核心内容：** DNS/邮件/SSH基础设施层面攻击、服务利用、通过内网穿透横向移动

---

## 25. 威胁情报

```
25_Threat_Intelligence/
├── 01_cti_fundamentals.md          ← CTI框架(MITRE ATT&CK/STIX/TAXII)、威胁行为者画像
├── 02_osint_for_threat_intel.md    ← Shodan/Censys自动化、暗网OSINT、IOC收集流水线
├── 03_incident_response.md         ← IR手册、证据收集、恶意代码分类、蜜罐
├── 04_cti_platform_operations.md   ← CTI平台运营
├── 05_threat_intel_automation.md   ← 威胁情报自动化 — MISP、OpenCTI、IOC富化、STIX/TAXII
└── 06_threat_intel_ctf_lab.md      ← 威胁情报 CTF实战实验室
```

**核心内容：** CTI生命周期、威胁行为者归因分析、IOC管理、自动化事件响应流程

---

## 26. Linux加固

```
26_Linux_Hardening/
├── 01_firewall_and_iptables.md          ← iptables/nftables/ufw规则、防火墙审计、状态过滤
├── 02_pam_and_auth_hardening.md         ← PAM配置、SSH加固、MFA设置、sudo策略
├── 03_kisa_vulnerability_assessment.md  ← KISA安全检查清单、CIS基准、自动化评估脚本
├── 04_linux_security_auditing.md        ← Linux安全审计
├── 05_linux_hardening_automation.md     ← Linux加固自动化 — CIS基准、Ansible Playbook、审计
└── 06_linux_hardening_ctf_lab.md        ← Linux加固 CTF实战实验室
```

**核心内容：** 防火墙规则设计、认证加固、符合KISA/CIS标准的自动化安全评估

---

## 27. IoT黑客技术

```
27_IoT_Hacking/
├── 01_iot_attack_surface.md    ← 攻击面分析、OWASP IoT Top 10、Shodan/Censys扫描
├── 02_firmware_analysis.md     ← 固件提取分析、binwalk/Ghidra、硬编码凭据检测
├── 03_iot_exploitation.md      ← UART/JTAG接入、嵌入式漏洞利用、实战攻击场景
├── 04_RF_Zigbee_Attacks.md     ← RF/Zigbee/Z-Wave IoT无线协议攻击
├── 05_iot_security_hardening.md ← IoT安全加固 — 固件签名、网络隔离、设备管理
└── 06_iot_ctf_lab.md           ← IoT黑客 CTF实战实验室
```

**核心内容：** 基于OWASP IoT Top 10的攻击面分析、固件逆向(binwalk/Ghidra)、UART/JTAG硬件攻击、IoT设备实战渗透

---

## 28. 移动端攻击

```
28_Mobile_Hacking/
├── 01_android_pentesting.md        ← APK分析、ADB Root、Frida动态插桩、SSL Pinning绕过
├── 02_ios_pentesting.md            ← IPA提取、Objective-C/Swift逆向、越狱检测绕过
├── 03_mobile_traffic_analysis.md   ← Burp Suite移动代理、证书固定绕过、API模糊测试
├── 04_Mobile_Malware_Analysis.md   ← 移动恶意软件分析（Android/iOS）
├── 05_mobile_app_security_testing.md ← 移动应用安全测试 — 自动化分析、运行时Hook、API测试
└── 06_mobile_ctf_lab.md            ← 移动黑客 CTF实战实验室
```

**核心内容：** Android/iOS完整分析流水线、基于Frida的运行时插桩、移动端中间人攻击、SSL Pinning绕过技术

---

## 29. 容器/Kubernetes安全

```
29_Container_Kubernetes_Security/
├── 01_docker_security.md      ← Docker安全配置、容器逃逸技术、镜像漏洞扫描
├── 02_kubernetes_attack.md    ← RBAC提权、etcd夺取、Kubernetes攻击向量完整分析
├── 03_container_escape.md     ← cgroup/namespace逃逸、runc漏洞、实战容器逃逸PoC
├── 04_Service_Mesh_API_Gateway_Attacks.md ← 服务网格与API网关攻击
├── 05_kubernetes_rbac_audit.md ← Kubernetes RBAC审计 — 权限分析、过度权限检测
└── 06_container_ctf_lab.md    ← 容器与Kubernetes安全 CTF实战实验室
```

**核心内容：** Docker/Kubernetes攻防策略、RBAC提权、容器逃逸技术、基于Trivy/Falco的运行时安全

---

## 30. 漏洞研究

```
30_Vulnerability_Research/
├── 01_fuzzing_techniques.md            ← AFL++/libFuzzer/Boofuzz、覆盖率引导模糊测试、网络模糊测试
├── 02_vulnerability_analysis.md        ← CVSS分析、CWE分类、静态/动态分析、源码审计
├── 03_exploit_development_advanced.md  ← 高级堆漏洞利用、浏览器漏洞利用、内核漏洞开发
├── 04_CVE_Writeup_Methodology.md       ← CVE漏洞分析与PoC编写方法论
├── 05_responsible_disclosure.md        ← 负责任的漏洞披露 — CVE申请、协调
└── 06_vuln_research_ctf_lab.md         ← 漏洞研究 CTF实战实验室
```

**核心内容：** 基于AFL++/libFuzzer的自动化漏洞发现、系统化CVSS/CWE分析、高级堆/浏览器/内核漏洞利用开发

---

## 31. AI/ML系统安全

```
31_AI_ML_Security/
├── 01_adversarial_examples.md         ← FGSM/PGD/C&W、迁移攻击、对抗训练与随机平滑防御
├── 02_prompt_injection_jailbreak.md   ← 直接/间接提示注入、越狱、garak/PyRIT自动红队测试
├── 03_model_extraction_inversion.md   ← 模型提取、成员推断(LiRA)、训练数据重构、DP-SGD防御
├── 04_llm_agent_security.md           ← 工具调用SSRF/RCE、RAG索引投毒、MCP安全、双LLM架构
├── 05_ai_security_defense.md          ← AI/ML安全防御 — 对抗鲁棒性、模型监控、OWASP ML Top 10
└── 06_ai_ml_ctf_lab.md                ← AI/ML安全 CTF实战实验室
```

如果第11章是"将AI用作攻击工具"，那么第31章聚焦于**AI/ML系统本身作为攻击目标**的攻防。基于OWASP LLM Top 10 / NIST AI 100-2 / MITRE ATLAS，包含可复现的PyTorch/Anthropic SDK PoC。

---

## 32. 网络设备攻击

```
32_Network_Device_Hacking/
├── 01_ios_fundamentals_and_recon.md      ← Cisco IOS/IOS XE结构、设备指纹识别、管理协议侦察
├── 02_layer2_attacks.md                  ← VLAN跳跃、STP/DHCP攻击、CAM溢出、DAI绕过
├── 03_routing_protocol_attacks.md        ← OSPF/EIGRP/BGP路由注入、HSRP/VRRP劫持
├── 04_management_plane_exploitation.md   ← SNMP/TACACS+/NETCONF利用、配置文件提取、后门识别
├── 05_network_device_hardening.md        ← 网络设备加固 — Cisco/Juniper安全配置
└── 06_network_device_ctf_lab.md          ← 网络设备黑客 CTF实战实验室
```

第02章聚焦流量嗅探/MITM，第24章聚焦DNS/邮件/SSH服务层面，第32章则直接攻击**路由器/交换机的管理/控制/数据平面**。收录2025–2026年Cisco CVE复现PoC（CVE-2025-20188等）和GNS3/EVE-NG实验拓扑。

---

## 33. OSINT与社会工程学

```
33_OSINT_Social_Engineering/
├── 01_osint_methodology_and_search.md  ← 信息收集方法论、Shodan/Censys/FOFA、高级Dork技巧
├── 02_target_profiling.md              ← 人员/组织画像、社交媒体分析、邮件验证、域名侦察
├── 03_social_engineering_attacks.md    ← 钓鱼/鱼叉钓鱼/语音钓鱼/短信钓鱼、BEC、托词攻击
├── 04_phishing_infra_and_evasion.md    ← GoPhish/Evilginx2基础设施、URL绕过、反钓鱼检测规避
├── 05_osint_defense_and_counter_intelligence.md ← OSINT防御与反情报 — 数字足迹缩减
└── 06_osint_ctf_lab.md                 ← OSINT与社会工程 CTF实战实验室
```

将OSINT作为**攻击链侦察阶段**而非简单信息检索。涵盖Shodan/FOFA/Censys查询自动化、基于LinkedIn/GitHub/社交媒体的目标画像，以及GoPhish/Evilginx2钓鱼基础设施构建，以红队实战视角呈现。

---

## 34. 硬件攻击

```
34_Hardware_Hacking/
├── 01_hardware_recon_and_interfaces.md    ← UART/JTAG/SPI/I²C接口识别与数据提取、引脚分析
├── 02_firmware_analysis.md                ← binwalk提取、文件系统分析、硬编码密钥、危险函数检测
├── 03_side_channel_and_fault_injection.md ← 功耗分析(SPA/DPA)、时序攻击、毛刺注入、ChipWhisperer
├── 04_hardware_security_assessment.md     ← 硬件安全评估 — 设备审计、物理安全
├── 05_hardware_security_defense.md        ← 硬件安全防御 — 安全启动、TPM、物理安全、防篡改
└── 06_hardware_ctf_lab.md                 ← 硬件黑客 CTF实战实验室
```

涵盖电子设备的物理攻击面——通过UART串口获取root Shell、通过JTAG完整转储固件，以及通过侧信道分析提取加密密钥。使用minicom、OpenOCD、binwalk、ChipWhisperer等工具，覆盖硬件安全研究的核心技术。

---

## 35. 供应链攻击

```
35_Supply_Chain_Attacks/
├── 01_software_supply_chain.md   ← 开源包投毒、域名抢注、依赖混淆攻击
├── 02_build_and_ci_poisoning.md  ← CI/CD流水线入侵、GitHub Actions滥用、SolarWinds·XZ Utils模式分析
├── 03_Dependency_Confusion_and_Typosquatting.md ← 依赖混淆攻击与拼写抢注
├── 04_Open_Source_Backdoor_Techniques.md ← 开源后门植入技术
├── 05_supply_chain_defense.md    ← 供应链安全防御 — SBOM、依赖扫描、供应商风险
└── 06_supply_chain_ctf_lab.md    ← 供应链攻击 CTF实战实验室
```

解剖SolarWinds、XZ Utils、3CX等真实供应链入侵案例。涵盖PyPI/npm/Maven包投毒、GitHub Actions工作流权限劫持、构建系统后门植入——证明整个软件开发流水线都是攻击面。

---

## 36. 汽车黑客技术

```
36_Automotive_Hacking/
├── 01_can_bus_analysis.md           ← CAN总线结构、OBD-II诊断、报文嗅探与重放
├── 02_ecu_exploitation.md           ← ECU固件分析、UDS诊断协议滥用、刷写调参
├── 03_telematics_and_ota_attacks.md ← V2X通信、车联网单元渗透、OTA更新拦截
├── 04_automotive_security_testing.md ← 汽车安全测试 — 渗透测试、模糊测试与认证测试
├── 05_automotive_security_defense.md ← 汽车网络安全防御 — ISO/SAE 21434、UNECE WP.29、安全OTA
└── 06_automotive_ctf_lab.md         ← 汽车黑客 CTF实验室
```

现代汽车是拥有100+个ECU和数十种通信协议的移动计算机。从CAN总线嗅探到UDS诊断协议滥用、车联网远程攻击，以及Jeep Cherokee/Tesla真实入侵复现——以python-can、Scapy、CANalyzer为工具，全栈覆盖汽车安全研究。

---

## 37. ICS/SCADA安全

```
37_ICS_SCADA/
├── 01_ics_protocols_and_recon.md  ← Modbus/DNP3/IEC 61850/EtherNet/IP深度解析、Shodan侦察、多协议扫描器
├── 02_scada_exploitation.md       ← HMI/Historian/PLC漏洞、TRITON·INDUSTROYER分析、SCADA扫描器
├── 03_ot_network_attacks.md       ← Purdue模型分层攻击、IT→OT横向移动、无线OT、OT拓扑映射器
├── 04_ics_security_architecture.md ← 04 — ICS安全架构与防御战略
├── 05_ics_security_defense.md     ← ICS/SCADA安全防御 — IEC 62443、网络分段、OT监控
└── 06_ics_ctf_lab.md              ← ICS/SCADA CTF实验室
```

分析控制发电站、炼油厂、水处理、铁路等关键基础设施的ICS/OT环境。解剖Stuxnet、TRITON、INDUSTROYER、PIPEDREAM等真实网络武器——从Modbus线圈强制写入到PLC DB块补丁、Historian数据逆注入、OT拓扑自动映射，全面呈现可用性优先环境的攻防实战。

---

## 38. 云原生安全

```
38_Cloud_Native_Security/
├── 01_cloud_native_threat_model.md      ← STRIDE威胁建模、CNAPP、容器/无服务器/服务网格威胁
├── 02_ebpf_runtime_security.md          ← Falco/Tetragon/Cilium、eBPF运行时检测与网络策略
├── 03_image_hardening_supply_chain.md   ← Trivy/Grype镜像扫描、Cosign签名、SBOM、OPA Gatekeeper
├── 04_cloud_native_attack_techniques.md ← 容器逃逸、服务网格MITM、无服务器事件注入、KSPM
├── 05_cloud_native_defense.md           ← 05 — 云原生安全防御框架
└── 06_cloud_native_ctf_lab.md           ← 云原生安全 CTF实验室
```

涵盖云原生环境（Kubernetes、无服务器、服务网格）的攻防技术。从eBPF运行时安全（Falco/Tetragon）、容器镜像签名与SBOM、OPA策略网关，到实际容器逃逸技术、服务网格MITM、AWS Lambda事件注入——以CNAPP视角系统整理。

---

## 39. 零信任架构

```
39_Zero_Trust_Architecture/
├── 01_zero_trust_principles.md         ← BeyondCorp模型、NIST SP 800-207、ZTA成熟度模型
├── 02_identity_and_device_trust.md     ← IdP/MFA/通行密钥、设备信任（MDM/EDR）、SCIM预置
├── 03_microsegmentation_and_network.md ← 微分段、mTLS、SASE/SD-WAN、eBPF网络策略
├── 04_zero_trust_implementation.md     ← Cloudflare/Zscaler/BeyondCorp实施、ZTA审计自动化
├── 05_zero_trust_maturity.md           ← 05 — 零信任成熟度评估与运营
└── 06_zero_trust_ctf_lab.md            ← 零信任架构 CTF实验室
```

"永不信任，始终验证" — 基于NIST SP 800-207的零信任架构实务解析。涵盖BeyondCorp案例、身份/设备信任体系、微分段、SASE引入，以及ZTA成熟度自评工具。

---

## 40. 威胁狩猎

```
40_Threat_Hunting/
├── 01_threat_hunting_methodology.md  ← 狩猎周期、假设驱动狩猎、PEAK框架、TTP漂移
├── 02_mitre_attack_hunting.md        ← ATT&CK战术狩猎场景、组织画像、Atomic Red Team
├── 03_hunting_queries_kql_spl.md     ← 100+ Sentinel KQL/Splunk SPL狩猎查询、异常检测模式
├── 04_automated_threat_hunting.md    ← SOAR自动化、ML异常检测、狩猎剧本自动化
├── 05_threat_hunting_program.md      ← 05 — 威胁狩猎计划运营
└── 06_threat_hunting_ctf_lab.md      ← 威胁狩猎 CTF实验室
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
├── 05_security_laws_and_compliance.md            ← 韩国个人信息保护法·IT安全法规、GDPR对比
└── 06_korean_cert_ctf_lab.md                     ← 韩国信息安全认证 CTF实战实验室
```

将韩国安全认证（信息安全工程师、ISMS-P）与国际认证（CISSP/CEH/OSCP/CISA）汇聚一处。包含法律法规与合规（个人信息保护法、GDPR），涵盖韩国安全从业者必须掌握的制度基础。

---

## 42. 区块链/Web3安全

```
42_Blockchain_Web3_Security/
├── 01_blockchain_fundamentals_and_threats.md ← EVM架构、UTXO vs 账户模型、51%攻击、eclipse攻击
├── 02_smart_contract_auditing.md             ← 重入/整数溢出/tx.origin/delegatecall、Slither/Mythril/Echidna
├── 03_defi_protocol_attacks.md               ← 闪电贷、预言机操控、MEV三明治攻击、Rug Pull检测
├── 04_web3_pentest_tools.md                  ← Foundry（forge/cast/anvil/chisel）、静态分析工具、RPC安全评估
├── 05_web3_incident_response.md              ← Web3事件响应
└── 06_blockchain_ctf_lab.md                  ← 区块链/Web3安全 CTF实战实验室
```

从区块链基础到DeFi攻击分析与智能合约审计，一站式学习。使用web3.py 6.x和Foundry进行实操PoC演示。涵盖真实事件（Euler Finance $197M闪电贷）、MEV机器人原理、Slither/Mythril漏洞扫描、RPC端点安全评估。

---

## 43. 物理安全渗透

```
43_Physical_Security_Pentesting/
├── 01_physical_pentest_methodology.md          ← PTES物理领域5阶段、授权书模板、漏洞检查清单
├── 02_lock_bypass_and_access_control.md        ← 弹子锁拨片（SPP/梳妆/碰撞）、电子门禁缺陷分析
├── 03_rfid_nfc_cloning.md                      ← Proxmark3 LF/HF、MIFARE Classic嵌套攻击、nfcpy NFC分析
├── 04_physical_recon_and_social_engineering.md ← 被动侦察、尾随、借口攻击、西奥迪尼6原则
├── 05_physical_security_assessment.md          ← 物理安全评估
└── 06_physical_ctf_lab.md                      ← 物理安全渗透测试 CTF实战实验室
```

从方法论到实施，全面覆盖物理渗透测试。涵盖锁具破解、RFID/NFC克隆（Proxmark3）、基于西奥迪尼影响原则的社会工程学。包含门禁日志异常检测与物理渗透报告生成的Python CLI工具。

---

## 44. 事件响应/DFIR

```
44_Incident_Response_DFIR/
├── 01_ir_methodology_and_playbooks.md       ← NIST SP 800-61r2、PICERL、勒索软件/钓鱼手册、日志时间线
├── 02_memory_and_disk_forensics.md          ← Volatility3、MFT分析、MACB时间戳、Plaso时间线
├── 03_network_forensics_and_log_analysis.md ← 100+ tshark过滤器、Zeek日志、Windows Event ID、Sysmon、PCAP C2 IOC
├── 04_threat_containment_and_eradication.md ← 网络隔离、持久化痕迹收集、5-Why分析
├── 05_malware_triage_and_containment.md     ← 恶意软件分类与遏制
└── 06_ir_dfir_ctf_lab.md                    ← 事件响应/DFIR CTF实战实验室
```

完整的DFIR工作流：检测→分析→封控→清除→恢复。Python CLI工具涵盖可疑进程检测（白名单比对、名称伪装）、基于PCAP的C2 IOC提取（信标检测/DNS隧道）、Windows持久化痕迹收集与风险评分。

---

## 45. 恶意代码开发

```
45_Malware_Development/
├── 01_malware_fundamentals_and_pe_structure.md ← PE文件结构、IAT、香农熵、可疑API分类
├── 02_shellcode_and_injection_techniques.md    ← PIC shellcode、XOR编码、CreateRemoteThread/APC/进程镂空
├── 03_c2_framework_development.md              ← C2架构、HTTP C2服务端+代理、DNS隧道、商用C2对比
├── 04_av_edr_evasion.md                        ← 直接系统调用、NTDLL解钩、ETW/AMSI补丁、沙箱检测
├── 05_detection_resistant_techniques.md        ← 抗检测技术分析（防御者视角）
└── 06_malware_dev_ctf_lab.md                   ← 恶意软件开发/分析 CTF实战实验室
```

面向红队和恶意代码分析师的开发与规避技术。Python CLI涵盖PE文件分析（熵/API分类）、shellcode XOR编码/反汇编、字符串混淆、沙箱检测。深入讲解直接syscall（NASM存根）、NTDLL解钩、ETW补丁、AMSI绕过等概念。

---

## 46. CTF技巧

```
46_CTF_Techniques/
├── 01_ctf_methodology_and_tools.md        ← CTF类型、工具生态、Docker Pwnbox Dockerfile、平台指南
├── 02_pwn_and_rev_ctf.md                  ← 完整pwntools模板（ret2win/ret2libc/格式字符串/堆）、angr解题
├── 03_web_and_crypto_ctf.md               ← 盲注自动化、SSTI利用、JWT攻击、RSA/AES/哈希长度扩展攻击
├── 04_ctf_automation_and_frameworks.md    ← DynELF、GDB tmux分屏、angr自动化、Frida Android、取证流水线
├── 05_ctf_writeup_methodology.md          ← CTF Writeup方法论
└── 06_advanced_ctf_practical_lab.md       ← 高级CTF实战实验室 — Pwn · Crypto · Forensics · Misc综合
```

从方法论到自动化，全方位覆盖CTF技巧。包含所有常见二进制题型的pwntools模板、angr符号执行、Frida动态插桩（Android CTF）、取证自动化流水线，以及CTFd API客户端用于题目管理和Flag提交。

---

## 47. 移动取证

```
47_Mobile_Forensics/
├── 01_android_forensics.md          ← Android文件系统/ADB取证/SQLite制品/备份解析CLI
├── 02_ios_forensics.md              ← iOS APFS结构/iTunes备份解析/iMessage/Health数据提取CLI
├── 03_mobile_evidence_extraction.md ← 逻辑/文件系统/物理提取/哈希完整性/自动取证CLI
├── 04_mobile_forensics_tools.md     ← Autopsy/MVT/Frida/jadx/APK自动分析CLI
├── 05_mobile_malware_analysis.md    ← 移动恶意软件分析
└── 06_mobile_forensics_ctf_lab.md   ← 移动取证 CTF实战实验室
```

Android/iOS移动取证全流程。ADB制品提取、iTunes备份解密/解析、MVT检测Pegasus间谍软件、APK逆向工程，含法律证据完整性维护方法。

---

## 48. 威胁建模

```
48_Threat_Modeling/
├── 01_stride_methodology.md         ← STRIDE六类/DFD绘制/信任边界/自动分析CLI
├── 02_pasta_dread_attack_trees.md   ← PASTA七步/DREAD评分/攻击树/Kill Chain/ATT&CK
├── 03_threat_modeling_tools.md      ← MS TMT/Threat Dragon/IriusRisk/CI/CD集成/XML→HTML CLI
├── 04_threat_modeling_practice.md   ← 电商/移动银行/K8s实战场景/完整工作流CLI
├── 05_ai_system_threat_modeling.md  ← AI系统威胁建模
└── 06_threat_modeling_ctf_lab.md    ← 威胁建模 CTF实战实验室
```

实战应用STRIDE、PASTA、DREAD方法论。从DFD绘制到威胁识别、缓解措施推导、CI/CD流水线集成，一个Python CLI自动化全流程。

---

## 49. 红队基础设施

```
49_Red_Team_Infrastructure/
├── 01_c2_frameworks.md               ← Cobalt Strike/Sliver/Havoc结构/HTTP C2实现/检测规则
├── 02_domain_fronting_redirectors.md ← CDN前置/Apache/Nginx重定向器/DNS隧道/流量过滤CLI
├── 03_opsec_infrastructure.md        ← OPSEC五步/Long-Short Haul C2/CT日志/OPSEC审计CLI
├── 04_red_team_automation.md         ← Ansible/Terraform基础设施/载荷流水线/行动管理CLI
├── 05_red_team_detection_evasion.md  ← 红队基础设施检测规避（防御者视角）
└── 06_red_team_infra_ctf_lab.md      ← 红队基础设施 CTF实战实验室
```

红队C2基础设施与OPSEC。Sliver/Havoc框架、Apache重定向器、DNS隧道、Terraform AWS自动化，适用于授权红队演练、CTF和安全研究。

---

## 50. 游戏安全

```
50_Game_Hacking/
├── 01_memory_manipulation.md        ← 游戏内存/ReadProcessMemory/AOB扫描/指针链CLI
├── 02_cheat_engine_advanced.md      ← CE Lua脚本/自动汇编/结构体分析/CT文件解析CLI
├── 03_packet_manipulation.md        ← 游戏包捕获/mitmproxy/protobuf逆向/重放CLI
├── 04_anti_cheat_analysis.md        ← VAC/EAC/BattlEye原理/检测技术/进程分析CLI/CTF题型
├── 05_game_server_exploitation.md   ← 游戏服务器漏洞研究
└── 06_game_ctf_lab.md               ← 游戏黑客 CTF实战实验室
```

游戏安全研究与CTF游戏题目。Cheat Engine内存操作、数据包中间人分析、反作弊内部机制，适用于教育、CTF和安全研究目的。

---

## 51. 浏览器扩展安全

```
51_Browser_Extension_Security/
├── 01_extension_architecture.md       ← MV2/V3对比/Background/Content Script/CSP/攻击面分析
├── 02_malicious_extension_analysis.md ← 恶意扩展类型/IOC/混淆分析/CRX自动分析CLI
├── 03_extension_pentesting.md         ← Content Script XSS/跨扩展攻击/Selenium自动扫描CLI
├── 04_extension_security_hardening.md ← MV3安全加固/最小权限/企业GPO/风险评估CLI
├── 05_extension_malware_campaigns.md  ← 浏览器扩展恶意软件活动分析
└── 06_browser_extension_ctf_lab.md    ← 浏览器扩展安全 CTF实战实验室
```

浏览器扩展安全全面覆盖。恶意扩展IOC检测、CRX自动分析、Content Script XSS和postMessage攻击、Selenium动态漏洞扫描器、企业策略管理。

---

## 52. API安全

```
52_API_Security/
├── 01_rest_api_security.md               ← OWASP API Top 10/BOLA扫描器/JWT漏洞分析
├── 02_graphql_security.md                ← 内省查询/批量查询/深度攻击/Schema自动分析
├── 03_api_fuzzing.md                     ← ffuf/基于OpenAPI的自动模糊器/参数污染/响应分析
├── 04_api_security_hardening.md          ← OAuth2 PKCE/速率限制/Kong/NGINX网关
├── 05_api_security_testing_automation.md ← API安全测试自动化流水线
└── 06_api_ctf_lab.md                     ← CTF: API漏洞实验
```

REST/GraphQL API漏洞全面覆盖。BOLA自动扫描器、JWT伪造与破解、OAuth2 PKCE实现、API网关安全。

---

## 53. 无服务器安全

```
53_Serverless_Security/
├── 01_lambda_function_attacks.md      ← 环境变量窃取/IMDSv1 SSRF/事件注入
├── 02_serverless_injection.md         ← SQS/S3事件注入/拼写抢注/命令注入静态分析
├── 03_serverless_iam_abuse.md         ← 角色权限过大/AssumeRole链/最小权限策略自动生成
├── 04_serverless_hardening.md         ← IaC安全扫描/Terraform安全配置/Lambda Extension
├── 05_serverless_incident_response.md ← 无服务器事件响应/CloudTrail分析/自动隔离
└── 06_serverless_ctf_lab.md           ← CTF: Lambda环境变量/事件注入/IAM滥用实验
```

AWS Lambda无服务器环境攻防。IMDSv1 SSRF、事件源注入、IAM角色滥用、IaC（Checkov/cfn-guard）扫描。

---

## 54. Active Directory攻击

```
54_Active_Directory_Attacks/
├── 01_ad_enumeration.md            ← BloodHound/LDAP枚举/SPN/AS-REP账户自动枚举
├── 02_kerberos_attacks.md          ← Kerberoasting/AS-REP Roasting/Pass-the-Ticket
├── 03_lateral_movement_ad.md       ← PtH/NTLM中继/DCSync/多主机横向移动
├── 04_ad_persistence.md            ← 黄金票据/Shadow Credentials/ACL滥用/持久化检测
├── 05_ad_defense_and_detection.md  ← AD事件监控/蜜罐账户/加固清单
└── 06_ad_ctf_lab.md                ← CTF: Kerberoasting/攻击路径分析/DCSync实验
```

Active Directory攻击链全面覆盖。BloodHound收集与Cypher查询、Kerberoasting/AS-REP Roasting自动化、NTLM中继/DCSync、黄金/白银票据、AdminSDHolder/Shadow Credentials持久化。

---

## 55. 检测规避技术

```
55_Evasion_Techniques/
├── 01_av_evasion.md                    ← XOR编码器/沙箱检测/进程注入/AMSI绕过
├── 02_ids_ips_evasion.md               ← 数据包分片/DNS隧道/流量伪装/Snort规则分析
├── 03_edr_bypass.md                    ← 直接syscall/NTDLL钩子检测/内存注入检测
├── 04_log_evasion.md                   ← 事件日志篡改/时间戳伪造/痕迹清除自动化
├── 05_evasion_detection_and_hunting.md ← 规避技术威胁狩猎/检测规则/行为分析
└── 06_evasion_ctf_lab.md               ← CTF: 编码绕过/日志篡改检测实验
```

AV/EDR/IDS规避技术全面覆盖。XOR/AES载荷编码器、直接/间接syscall、NTDLL钩子检测、DNS/ICMP隧道、C2流量伪装、痕迹清除清单。

---

## 56. AI红队

```
56_AI_Red_Teaming/
├── 01_ai_attack_fundamentals.md    ← AI攻击基础、攻击面、威胁建模
├── 02_prompt_injection.md          ← 直接/间接/多模态注入、越狱技术
├── 03_model_extraction.md          ← 模型提取/成员推理、基于查询的攻击
├── 04_adversarial_examples.md      ← FGSM/PGD、迁移攻击、防御技术
├── 05_ai_red_team_defense.md       ← 模型加固、输入验证、AI安全架构
└── 06_ai_red_team_ctf_lab.md       ← CTF: 提示注入/模型提取实验
```

AI系统红队方法论、提示注入自动化、模型提取攻击、防御技术。

---

## 57. 量子密码学

```
57_Quantum_Cryptography/
├── 01_quantum_computing_basics.md  ← 量子计算、Grover/Shor算法、对密码学的影响
├── 02_quantum_key_distribution.md  ← QKD协议（BB84/E91）、量子信道攻击
├── 03_post_quantum_algorithms.md   ← CRYSTALS-Kyber/Dilithium、SPHINCS+、实现指南
├── 04_nist_pqc_standards.md        ← NIST PQC标准化进程、FIPS 203/204/205
├── 05_pqc_migration_strategy.md    ← 混合加密、密码资产清单、迁移策略
└── 06_quantum_crypto_ctf_lab.md    ← CTF: 量子密码原理/PQC实验
```

量子计算对RSA/ECC的影响、NIST PQC标准算法、向后量子密码的迁移策略。

---

## 58. 云事件响应

```
58_Cloud_IR/
├── 01_cloud_ir_fundamentals.md     ← Cloud IR框架、AWS/Azure/GCP入侵指标
├── 02_aws_forensics.md             ← CloudTrail分析、S3/EC2取证、GuardDuty联动
├── 03_azure_forensics.md           ← Azure Sentinel调查、Activity Log分析
├── 04_gcp_forensics.md             ← GCP Chronicle、Audit Log取证
├── 05_cloud_threat_hunting.md      ← 云威胁狩猎、异常检测、KQL查询
└── 06_cloud_ir_ctf_lab.md          ← CTF: CloudTrail分析/入侵场景实验
```

Cloud IR全流程。CloudTrail/Activity Log分析、云环境取证、威胁狩猎自动化。

---

## 59. 供应链安全

```
59_Supply_Chain_Security/
├── 01_supply_chain_fundamentals.md     ← 供应链攻击类型、入侵指标、威胁模型
├── 02_software_supply_chain_attacks.md ← SolarWinds/Codecov等真实案例分析、检测策略
├── 03_dependency_confusion.md          ← 依赖混淆攻击、拼写抢注、防御
├── 04_build_integrity.md               ← 构建完整性验证、签名、SLSA框架
├── 05_supply_chain_defense.md          ← SBOM管理、供应商风险管理、防御策略
└── 06_supply_chain_ctf_lab.md          ← CTF: 依赖混淆/SBOM分析实验
```

软件供应链全流程安全。SBOM、依赖混淆、SLSA框架、供应商风险管理。

---

## 60. 浏览器安全进阶

```
60_Browser_Security/
├── 01_browser_attack_surface.md         ← 浏览器攻击面、漏洞类型、防御模型
├── 02_javascript_engine_exploitation.md ← V8/SpiderMonkey漏洞、JIT编译器Bug
├── 03_sandbox_escape.md                 ← 沙箱逃逸技术、进程隔离绕过
├── 04_browser_extension_advanced.md     ← 恶意扩展分析、MV3安全模型
├── 05_browser_security_hardening.md     ← 浏览器安全配置、企业策略
└── 06_browser_security_ctf_lab.md       ← 浏览器安全CTF实验
```

JS引擎漏洞（V8/SpiderMonkey）、沙箱逃逸、浏览器进程模型、Chrome/Firefox Bug模式。

---

## 61. 固件黑客

```
61_Firmware_Hacking/
├── 01_firmware_fundamentals.md     ← 固件类型、提取方法、分析环境搭建
├── 02_firmware_extraction.md       ← JTAG/UART/SPI转储、binwalk提取、文件系统挂载
├── 03_firmware_analysis.md         ← Ghidra逆向分析、脆弱函数检测、硬编码密钥
├── 04_firmware_emulation.md        ← QEMU模拟、firmwalker、动态分析
├── 05_firmware_exploitation.md     ← 缓冲区溢出、命令注入、Web接口攻击
└── 06_firmware_ctf_lab.md          ← CTF: 固件提取/分析/利用实验
```

固件分析全流程。从硬件转储到Ghidra逆向分析、QEMU模拟、漏洞利用。

---

## 62. 汽车安全

```
62_Automotive_Security/
├── 01_automotive_security_fundamentals.md ← 汽车网络架构、CAN/LIN/FlexRay
├── 02_can_bus_hacking.md                  ← CAN总线嗅探、消息重放、模糊测试自动化
├── 03_ecu_analysis.md                     ← ECU固件提取、UDS诊断、参数篡改
├── 04_v2x_security.md                     ← V2X通信安全、DSRC/C-V2X漏洞
├── 05_automotive_penetration_testing.md   ← 汽车渗透测试方法论、报告撰写
└── 06_automotive_ctf_lab.md               ← CTF: CAN总线/UDS/ECU实验
```

CAN总线嗅探与篡改、ECU固件分析、UDS诊断协议滥用、V2X/OTA攻击。python-can/Scapy/CANalyzer实战。

---

## 63. OT/ICS进阶

```
63_OT_ICS_Advanced/
├── 01_ot_ics_fundamentals.md       ← OT/ICS架构、Purdue模型、主要协议
├── 02_scada_attacks.md             ← HMI攻击、SCADA服务器漏洞、真实案例分析
├── 03_plc_exploitation.md          ← PLC编程漏洞、梯形逻辑篡改、漏洞利用
├── 04_industrial_protocols.md      ← Modbus/DNP3/IEC 104协议攻击、流量分析
├── 05_ot_defense_and_monitoring.md ← OT安全架构、网络隔离、异常检测
└── 06_ot_ics_ctf_lab.md            ← CTF: Modbus/PLC/SCADA实验
```

解剖Stuxnet、TRITON、INDUSTROYER、PIPEDREAM等真实网络武器。Modbus强制写入、PLC篡改、OT专用防御架构。

---

## 64. 威胁情报平台

```
64_Threat_Intel_Platform/
├── 01_tip_fundamentals.md            ← TIP架构、数据模型（STIX 2.1）、平台对比
├── 02_misp_platform.md               ← MISP部署运维、事件管理、API自动化
├── 03_threat_feeds_and_enrichment.md ← 威胁情报源收集/质量评估/IoC富化
├── 04_ioc_management.md              ← IOC生命周期、降噪、TAXII集成
├── 05_tip_automation.md              ← SOAR集成、自动响应、情报源编排
└── 06_tip_ctf_lab.md                 ← CTF: MISP事件/IOC分析实验
```

TIP平台（MISP/OpenCTI）构建运维、威胁情报源自动化、IOC管理、SOAR集成自动响应。

---

## 65. 逆向工程进阶

```
65_Reverse_Engineering_Advanced/
├── 01_anti_debugging_techniques.md    ← IsDebuggerPresent/时间差/异常检测、GDB/x64dbg绕过
├── 02_obfuscation_and_unpacking.md    ← UPX/Themida脱壳、代码混淆、二进制规范化
├── 03_symbolic_execution.md           ← angr符号执行、路径探索、条件分支绕过自动化
├── 04_advanced_binary_analysis.md     ← CFG重建、脆弱函数检测、Ghidra脚本
├── 05_firmware_reverse_engineering.md ← 固件逆向分析、binwalk、QEMU模拟
└── 06_re_ctf_lab.md                   ← CTF: 反调试绕过/脱壳/符号执行/反混淆
```

反调试检测与绕过、UPX/Themida脱壳、angr符号执行、CFG分析。含pwntools/angr实战CTF 4个挑战。

---

## 66. 漏洞利用开发

```
66_Exploit_Development/
├── 01_rop_chain_techniques.md       ← ROP gadget收集/链构建、NX绕过、ASLR暴力破解
├── 02_heap_exploitation.md          ← glibc ptmalloc2、堆溢出、UAF、House-of-Force
├── 03_kernel_exploitation.md        ← 内核BOF、ret2usr、SMEP/KPTI绕过、LPE
├── 04_browser_exploitation.md       ← V8 JIT Bug、OOB读写、渲染器→浏览器逃逸
├── 05_exploit_mitigation_bypass.md  ← Canary/ASLR/NX/PIE组合绕过、FSOP
└── 06_exploit_ctf_lab.md            ← CTF: 栈BOF/ROP链/堆UAF/组合绕过
```

ROP链构建、堆利用（ptmalloc2）、内核LPE、浏览器V8 Bug。含pwntools实战CTF 4个挑战。

---

## 67. 恶意软件开发解析

```
67_Malware_Development_Advanced/
├── 01_malware_architecture.md       ← 恶意软件结构、Dropper/载荷/C2架构
├── 02_shellcode_development.md      ← 位置无关Shellcode、编码、分阶段加载
├── 03_c2_framework_design.md        ← C2通信信道、信标间隔、HTTPS/DNS隧道
├── 04_persistence_mechanisms.md     ← 注册表/服务/计划任务/WMI持久化
├── 05_evasion_and_detection.md      ← AMSI绕过、ETW补丁、内存注入、行为检测
└── 06_maldev_ctf_lab.md             ← CTF: XOR解密/注册表检测/C2分析/内存取证
```

C2架构与信标、Shellcode开发、四种持久化技术、AMSI/ETW绕过。含Volatility内存取证CTF 4个挑战。

---

## 68. 紫队运营

```
68_Purple_Team/
├── 01_purple_team_fundamentals.md   ← 紫队方法论、红蓝协作框架
├── 02_attack_simulation.md          ← Atomic Red Team、CALDERA、攻击模拟自动化
├── 03_detection_engineering.md      ← Sigma规则编写、SIEM集成、检测覆盖率测量
├── 04_threat_emulation.md           ← APT仿真、TTP复现、MITRE ATT&CK映射
├── 05_purple_team_reporting.md      ← 差距分析、检测率报告、改进路线图
└── 06_purple_ctf_lab.md             ← CTF: ATT&CK映射/Sigma规则/检测率测量
```

红蓝队协作、Atomic Red Team/CALDERA模拟、Sigma规则编写、检测覆盖率测量。含基于ATT&CK的CTF 4个挑战。

---

## 69. LLM安全

```
69_LLM_Security/
├── 01_llm_security_fundamentals.md      ← LLM攻击面、OWASP LLM Top 10、威胁模型
├── 02_prompt_injection.md               ← 直接/间接注入、越狱、多模态攻击
├── 03_model_extraction_and_inversion.md ← 模型提取、训练数据反演、成员推理
├── 04_adversarial_attacks_on_llm.md     ← 对抗性后缀、迁移攻击、输入操纵
├── 05_llm_security_defense.md           ← 护栏、输出验证、安全LLM架构
└── 06_llm_security_ctf_lab.md           ← CTF: 基础注入/Base64绕过/Token走私
```

OWASP LLM Top 10、提示注入与越狱、模型提取、对抗攻击、LLM安全架构。含4个挑战的CTF。

---

## 70. Kubernetes安全

```
70_Kubernetes_Security/
├── 01_k8s_attack_surface.md         ← K8s架构/攻击面、minikube实验环境、kube-bench
├── 02_rbac_exploitation.md          ← RBAC错误配置利用、通配符权限、ClusterRole审计
├── 03_pod_escape.md                 ← privileged Pod逃逸、hostPath滥用、服务账户窃取
├── 04_network_attacks.md            ← 网络策略缺失、Pod间嗅探、DNS欺骗
├── 05_k8s_hardening.md              ← CIS Benchmark、PSS、OPA Gatekeeper、Vault密钥
└── 06_k8s_ctf_lab.md                ← CTF: RBAC窃取/Pod逃逸/服务账户/etcd访问
```

从K8s攻击面到RBAC错误配置利用、privileged Pod逃逸、etcd密钥转储。kube-bench CIS审计实战。含新手友好的minikube环境搭建。

---

## 71. 蓝牙/RF黑客

```
71_Bluetooth_RF_Hacking/
├── 01_bluetooth_fundamentals.md     ← 蓝牙 vs BLE、配对/协议栈结构、BlueSnarfing
├── 02_ble_attacks.md                ← GATT/GAP、脆弱特征值写入、bleak枚举BLE设备
├── 03_rf_signal_analysis.md         ← SDR概念、RTL-SDR安装、GNU Radio、频率分析
├── 04_zigbee_attacks.md             ← Zigbee架构、信道扫描、Zigbee2MQTT监控
├── 05_wireless_defense.md           ← BLE加密加固、Zigbee密钥管理、RF屏蔽方法
└── 06_wireless_ctf_lab.md           ← CTF: BLE GATT旗标/PIN暴力破解/RF重放
```

蓝牙/BLE漏洞分析、RTL-SDR频率分析、Zigbee IoT攻击。bleak/paho-mqtt/GNU Radio实战。低成本RTL-SDR硬件即可入门。

---

## 72. 恶意软件沙箱分析

```
72_Malware_Sandbox_Analysis/
├── 01_sandbox_fundamentals.md       ← 沙箱概念、静态vs动态分析、VM环境搭建
├── 02_online_sandbox_tools.md       ← ANY.RUN/VirusTotal/Joe Sandbox对比、vt-py API
├── 03_static_analysis.md            ← PE头分析、熵值、YARA规则、pefile实战
├── 04_dynamic_analysis.md           ← 进程监控、FakeNet、Wireshark、psutil脚本
├── 05_ioc_extraction.md             ← IOC提取自动化、MITRE ATT&CK映射、STIX/TAXII
└── 06_malware_ctf_lab.md            ← CTF: C2提取/XOR解密/注册表分析/UPX脱壳模拟
```

在线沙箱（ANY.RUN/VirusTotal）应用、PE静态分析、psutil动态监控、IOC自动提取。完全免费工具即可新手入门。

---

## 73. 漏洞赏金自动化

```
73_Bug_Bounty_Automation/
├── 01_bug_bounty_fundamentals.md    ← HackerOne/Bugcrowd生态、负责任披露、范围理解
├── 02_recon_automation.md           ← subfinder/amass/httpx/naabu流水线、Python自动化
├── 03_vulnerability_scanning.md     ← Nuclei模板、自定义规则、误报过滤、Burp集成
├── 04_report_writing.md             ← CVSS v3计算、PoC编写、Markdown报告自动生成
├── 05_advanced_techniques.md        ← 漏洞链、逻辑漏洞、API模糊测试、OAuth漏洞
└── 06_bug_bounty_ctf_lab.md         ← CTF: 子域名接管/IDOR检测/Nuclei实验
```

HackerOne/Bugcrowd平台应用、ProjectDiscovery工具链（subfinder/nuclei）自动化、基于CVSS的报告撰写。端到端实践真实漏洞赏金流程。

---

## 74. 代码审计

```
74_Code_Auditing/
├── 01_code_audit_fundamentals.md    ← STRIDE威胁建模、代码审计vs渗透测试、攻击面分析
├── 02_vulnerability_patterns.md     ← OWASP Top 10代码模式、脆弱/安全代码对比、各语言危险函数
├── 03_static_analysis_tools.md      ← Semgrep自定义规则、Bandit、CodeQL + GitHub Actions集成
├── 04_manual_review_techniques.md   ← Source/Sink追踪、基于AST的数据流分析、人工审查清单
├── 05_sast_cicd_integration.md      ← Pre-commit Hook、CI安全门、SARIF解析器、TP/FP分诊
└── 06_code_audit_ctf_lab.md         ← CTF: SQL注入审计/密钥检测/认证绕过模式检测
```

Semgrep/Bandit/CodeQL静态分析、Source→Sink数据流追踪、CI/CD安全门构建。含脆弱Flask应用实验环境。

---

## 75. 红队报告撰写

```
75_Red_Team_Reporting/
├── 01_red_team_fundamentals.md      ← 红队/蓝队/紫队区别、RoE、MITRE ATT&CK概述
├── 02_operation_planning.md         ← 基于杀伤链的行动计划、时间线自动生成、团队分工
├── 03_ttps_documentation.md         ← TTP文档化、ATT&CK映射自动化、IOC清单编制
├── 04_report_writing.md             ← 双受众报告（管理层/技术团队）、CVSS风险评估、自动生成器
├── 05_debrief_lessons.md            ← 复盘流程、经验教训提炼、紫队转型、检测率分析
└── 06_red_team_ctf_lab.md           ← CTF: ATT&CK映射/CloudStore报告/杀伤链计划
```

基于MITRE ATT&CK的TTP文档化、管理层/技术团队双受众报告撰写、复盘→紫队转型流程。含Python报告自动化工具。

---

## CTF实验环境（labs/）

```
labs/
├── 01_web_hacking_lab/      ← SQLi/XSS/SSRF/JWT漏洞Flask应用（Docker）
├── 02_pwn_lab/              ← BOF/格式字符串/堆利用漏洞二进制环境
├── 03_network_lab/          ← 数据包分析/MITM/ARP欺骗pcap+实验环境
├── 04_cloud_container_lab/  ← 漏洞Docker/K8s环境、容器逃逸场景
├── 05_full_scenario_lab/    ← 侦察→入侵→横向移动→权限提升→数据外泄综合场景
├── 06_firmware_lab/         ← binwalk 提取 · QEMU ARM 仿真 · 硬编码凭证 CTF
├── 07_mobile_lab/           ← Android APK 静态分析 · Frida · JWT alg:none 绕过 CTF
├── start_lab.sh             ← 一键docker-compose up启动全部实验
└── stop_all.sh              ← 停止全部实验
```

7个Docker化CTF漏洞环境——Web、二进制、网络、云原生、综合场景、固件、移动，可在本地即时实验。共13个Flag，`start_lab.sh`一键启动全部环境。

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
