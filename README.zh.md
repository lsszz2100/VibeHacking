<div align="center">

# ⚔️ VibeHacking

### 实战网络安全完全攻略 — AI时代的黑客圣经

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-31-blueviolet)](#目录)
[![Files](https://img.shields.io/badge/Docs-118%20Files-brightgreen)](#目录)
[![Lines](https://img.shields.io/badge/Lines-85%2C000%2B-orange)](#目录)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-ai驱动的网络安全)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-gray)](https://claude.ai/code)

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

## 免责声明

> **本项目中所有技术必须仅在授权环境中使用。**

- 仅在CTF、漏洞赏金或合同范围内的渗透测试中使用
- 发现漏洞时遵循负责任披露（Responsible Disclosure）原则
- 未经授权访问他人系统违反《网络安全法》等相关法律法规

---

<div align="center">

**⚔️ VibeHacking** — 成为实战安全专家的旅程

*Built with [Claude Code](https://claude.ai/code)*

</div>
