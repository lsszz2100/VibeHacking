<div align="center">

# ⚔️ VibeHacking

### 実践サイバーセキュリティ完全攻略 — AI時代のハッキングバイブル

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-18-blueviolet)](#目次)
[![Files](https://img.shields.io/badge/Docs-97%2B%20Files-brightgreen)](#目次)
[![Lines](https://img.shields.io/badge/Lines-48%2C000%2B-orange)](#目次)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-aiを活用したサイバーセキュリティ)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-gray)](https://claude.ai/code)

<br/>

> 理論から実習まで、CTF・バグバウンティ・ペネトレーションテスト・レッドチームに実戦投入できるレベルでまとめたセキュリティ知識リポジトリ。
> **2026年Mythos・GPT-5.4-Cyber時代**のAIベース脆弱性研究からクラウド・無線・暗号理論まで完全網羅。

**🌐 Language / 言語 / 语言:**
[한국어](README.md) · [English](README.en.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## このリポジトリについて

実戦力を高めたいセキュリティ学習者のために、すぐに実行できるコードと体系的な方法論を一か所にまとめました。  
CTF・バグバウンティ・レッドチーム・AIセキュリティまで、**多言語で設計された実践中心の知識ハブ**です。

**VibeHackingの強み:**

- **コード優先** — 全セクションにコピー＆ペースト可能なコマンドとコードを収録
- **AI統合** — Claude/GPT-5.4-Cyberをセキュリティ分析ツールとして活用する方法を解説
- **最新動向反映** — Anthropic Mythos、OpenAI GPT-5.4-CyberなどAI最先端セキュリティエコシステムを網羅
- **多言語対応** — 韓国語・英語・日本語・中国語で提供
- **完全なカバレッジ** — バグバウンティ・SOC・クラウド・WiFi・暗号理論・レッドチームまで全領域

---

## 目次

| # | セクション | 主要内容 | ファイル数 |
|---|-----------|---------|----------|
| 01 | [Linux基礎 & Kali Linux](#01-linux基礎--kali-linux) | 必須コマンド、Kaliセットアップ、Bashスクリプト | 3 |
| 02 | [ネットワークハッキング](#02-ネットワークハッキング) | OSI/TCP-IP、パケット分析、無線ハッキング | 3 |
| 03 | [システムハッキング](#03-システムハッキング) | パスワードクラック、Buffer Overflow | 2 |
| 04 | [リバースエンジニアリング](#04-リバースエンジニアリング) | アセンブリ、OllyDbg、PE構造 | 3 |
| 05 | [Webハッキング](#05-webハッキング) | OWASP Top 10、SQLi深掘り、XSS/CSRF | 3 |
| 06 | [マルウェア分析](#06-マルウェア分析) | 静的/動的分析、Volatility、Android | 3 |
| 07 | [デジタルフォレンジクス](#07-デジタルフォレンジクス) | 証拠収集、Windowsアーティファクト、ネットワーク | 3 |
| 08 | [Pythonハッキング](#08-pythonハッキング) | ツール開発、ネットワークスキャナ、Web自動化 | 3 |
| 09 | [エクスプロイト技法](#09-エクスプロイト技法) | ROP Chain、SEH、Linux BOF、権限昇格 | 2 |
| 10 | [ペネトレーションテスト方法論](#10-ペネトレーションテスト方法論) | ペンテスト手順、OSINT偵察、報告書作成 | 3 |
| 11 | [**AIを活用したサイバーセキュリティ**](#11-aiを活用したサイバーセキュリティ) | Mythos、GPT-5.4-Cyber、LLM脆弱性研究、CTF自動化 | 4 |
| 12 | [**バグバウンティ**](#12-バグバウンティ) | 方法論、Burp Suite上級、自動化ツール | 3 |
| 13 | [**SOC & Blue Team**](#13-soc--blue-team) | SOC運用、Splunk分析、脅威ハンティング | 3 |
| 14 | [**クラウドセキュリティ**](#14-クラウドセキュリティ) | AWS/Azure/GCP攻撃ベクター、ペンテスト、チェックリスト | 3 |
| 15 | [**WiFiハッキング**](#15-wifiハッキング) | WPA2クラック、PMKID、Evil Twin、自動化 | 3 |
| 16 | [**暗号理論**](#16-暗号理論) | ハッカーのための暗号学、ハッシュ攻撃、応用暗号 | 3 |
| 17 | [**レッドチーム運営**](#17-レッドチーム運営) | プレイブック、フィッシング/ソーシャルエンジニアリング、APIハッキング | 3 |
| 18 | [**DevSecOps**](#18-devsecops) | SAST/SCA/DAST、コンテナセキュリティ、CI/CDパイプライン | 3 |

---

## 学習ロードマップ

```
[入門]
  Linux基礎  ──►  ネットワーク基礎  ──►  Webハッキング入門
                                               │
[中級]                                          ▼
  システムハッキング  ◄──  Python自動化  ◄──  マルウェア分析
          │
          ▼
[上級]
  リバースエンジニアリング  ──►  エクスプロイト開発  ──►  ペンテスト方法論
                                                              │
[専門家]                                                       ▼
  WiFiハッキング  ──►  クラウドセキュリティ  ──►  レッドチーム  ──►  バグバウンティ
  暗号理論       ──►  SOC/Blue Team      ──►  AIセキュリティ  ──►  DevSecOps
```

---

## 実習環境

| コンポーネント | 推奨事項 |
|-------------|--------|
| 攻撃マシン | Kali Linux 2024.x |
| 仮想化 | VMware Workstation / VirtualBox |
| 脆弱な環境 | Metasploitable2、DVWA、HackTheBox、TryHackMe、CloudGoat |
| 分析ツール | Wireshark、Burp Suite、IDA Pro / Ghidra、OllyDbg |
| 言語 | Python 3.x、Bash、pwntools |
| AIツール | Claude Opus 4.6、GPT-5.4-Cyber（TAC認定） |
| 無線 | Alfa AWUS036ACH（2.4/5GHzモニターモード対応） |
| クラウド | AWS Free Tier、CloudGoat |

---

## 01. Linux基礎 & Kali Linux

```
01_Linux_Basics/
├── 01_linux_essential_commands.md   ← ファイル/プロセス/ネットワーク必須コマンド
├── 02_kali_linux_setup.md           ← Kali初期設定、ツールインストール
└── 03_bash_scripting.md             ← 自動化スクリプト、実践例
```

**主要内容:** ファイルシステム、プロセス管理、ネットワークコマンド、権限管理、30以上のBash自動化スクリプト

---

## 02. ネットワークハッキング

```
02_Network_Hacking/
├── 01_osi_tcpip.md          ← OSI 7層、TCP/IPスタック、プロトコル分析
├── 02_packet_analysis.md    ← Wireshark実践、tcpdump、パケット操作
└── 03_wireless_hacking.md   ← WEP/WPA2クラック、Evil Twin、無線ハッキング
```

**主要内容:** パケットキャプチャ・分析、ARPスプーフィング、MITM、無線ネットワーク攻撃、ファイアウォール回避

---

## 03. システムハッキング

```
03_System_Hacking/
├── 01_password_cracking.md       ← Hashcat、John、Rainbow Table、オンラインクラック
├── 02_buffer_overflow.md         ← スタックBOF原理、シェルコード、実践例
└── 03_active_directory_attack.md ← AD攻撃完全ガイド、Kerberoasting、DCSync
```

**主要内容:** ハッシュクラック戦略、BOF原理からエクスプロイトまで、Active Directory攻撃チェーン完全攻略

---

## 04. リバースエンジニアリング

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md   ← x86/x64アセンブリ、レジスタ、スタックフレーム
├── 02_ollydbg_practical.md        ← OllyDbg/x64dbg実践分析
└── 03_pe_structure.md             ← PEファイル構造、IAT/EAT、パッキング
```

**主要内容:** アセンブリ言語、デバッガ使用法、PE構造の深掘り分析、IDA Pro/Ghidra

---

## 05. Webハッキング

```
05_Web_Hacking/
├── 01_owasp_top10.md              ← OWASP Top 10（2021）、Burp Suite、Nikto
├── 02_sql_injection_advanced.md   ← Blind/Time-based SQLi、NoSQL、SQLMap実践
└── 03_xss_csrf_file_upload.md     ← Stored/Reflected/DOM XSS、CSRF、Webシェル
```

**主要内容:** OWASP Top 10実践、SQL Injection完全攻略、XSS/CSRF/ファイルアップロード/XXE/SSRF

---

## 06. マルウェア分析

```
06_Malware_Analysis/
├── 01_malware_analysis.md            ← 分類、分析環境、静的/動的分析、YARA
├── 02_memory_forensics_malware.md    ← Volatility完全攻略、コードインジェクション検出
└── 03_android_malware_analysis.md    ← APK分析、Fridaフッキング、MobSF
```

**主要内容:** 静的・動的・メモリ分析の全工程、Volatilityプラグイン、Androidマルウェア

---

## 07. デジタルフォレンジクス

```
07_Digital_Forensics/
├── 01_digital_forensics.md               ← フォレンジクス原則、証拠収集、イメージ分析
├── 02_windows_forensics_artifacts.md     ← レジストリ、イベントログ、Prefetch、ブラウザ
└── 03_network_forensics.md               ← Wireshark、Zeek、Suricata、インシデント対応
```

**主要内容:** 証拠収集手順、Windowsアーティファクト完全分析、ネットワークフォレンジクス、タイムライン分析

---

## 08. Pythonハッキング

```
08_Python_Hacking/
├── 01_python_hacking_tools.md       ← ポートスキャナ・スニッファ・バックドアなど30以上のサンプル
├── 02_python_network_scanner.md     ← マルチスレッドスキャナ、ARP、DNS列挙、SSHブルートフォーサ
└── 03_python_web_exploitation.md    ← Webクローラ、SQLi自動化、XSSスキャナ、レポート生成
```

**主要内容:** Scapy、paramiko、requestsを活用したセキュリティツール開発、50以上の完全動作コード

---

## 09. エクスプロイト技法

```
09_Exploit_Techniques/
├── 01_advanced_exploitation.md   ← ROP Chain、Heap Spray、SEH、Win32シェルコーディング
├── 02_linux_exploitation.md      ← Linux BOF、Ret2Libc、フォーマット文字列、権限昇格
└── 03_heap_exploitation.md       ← tcacheポイズニング、UAF、House ofシリーズ、pwndbg
```

**主要内容:** DEP/ASLR/NXバイパス、ROPチェーン構成、フォーマット文字列エクスプロイト、ヒープエクスプロイト完全攻略

---

## 10. ペネトレーションテスト方法論

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← ペンテスト全手順、MITRE ATT&CK、報告書作成
├── 02_osint_recon.md           ← Google Dorks、Shodan、サブドメイン列挙、GitHub秘密情報検出
└── 03_report_writing.md        ← プロ報告書作成、CVSS算定、PoC作成、経営者/技術報告書テンプレート
```

**主要内容:** 体系的なペンテスト方法論、OSINTツール完全活用、プロ報告書作成（CVSS・PoC・コンプライアンス対応）

---

## 11. AIを活用したサイバーセキュリティ

> **2026年現在、AIがサイバーセキュリティの勢力図を塗り替えている。**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Mythos・GPT-5.4-Cyber・Project Glasswing全体俯瞰
├── 02_llm_vulnerability_research.md   ← LLMによるゼロデイ発見、AIファジング、コード分析自動化
├── 03_ai_assisted_pentesting.md       ← AI支援ペンテストワークフロー、プロンプトエンジニアリング
└── 04_ai_ctf_automation.md            ← CTF自動化AIエージェント、暗号/Web/フォレンジクス専門サブエージェント
```

### 2026年 AIセキュリティ勢力図

| モデル | 組織 | 能力 | アクセス方法 |
|-------|------|------|------------|
| **Claude Mythos** | Anthropic | 17年間放置されたFreeBSD RCEを自律発見、数千のゼロデイ | Project Glasswing（12パートナー企業のみ） |
| **GPT-5.4-Cyber** | OpenAI | バイナリリバーシング、CTF 76%自律解決、YARA生成 | TAC認定（chatgpt.com/cyber） |
| **Claude Opus 4.6** | Anthropic | コード脆弱性分析、CTF補助、YARA自動化 | 一般公開 |

**主要内容:** AIセキュリティエコシステム完全分析、Claude APIベースの脆弱性スキャナ実装、AI支援ペンテスト自動化、CTF解法AIエージェント（暗号/Web/フォレンジクス/リバーシング専門サブエージェント含む）

---

## 12. バグバウンティ

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd方法論、IDOR、XSSバイパス、自動化
├── 02_burp_suite_advanced.md      ← Burp Suite完全攻略、JWT攻撃、Request Smuggling
└── 03_bug_bounty_automation.md    ← Nuclei、ffuf、dalfox、自動化パイプライン
```

**主要内容:** バグバウンティ全ワークフロー、Burp Suite高度な機能、偵察→脆弱性→報告書の自動化

---

## 13. SOC & Blue Team

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md       ← SOC構造、インシデント対応、主要イベントID、EDR
├── 02_splunk_siem_analysis.md   ← Splunk SPL完全攻略、100以上の検出クエリ
└── 03_threat_hunting.md         ← 脅威ハンティング、ランサムウェア侵害調査、APT追跡
```

**主要内容:** SOCティア別役割、攻撃検出パターン100以上、Splunk/QRadar/ELKクエリ、脅威ハンティング方法論

---

## 14. クラウドセキュリティ

```
14_Cloud_Security/
├── 01_cloud_attack_vectors.md        ← AWS/Azure/GCP/K8s攻撃ベクター完全分析
├── 02_aws_pentest.md                 ← AWSペンテスト方法論、権限昇格、自動化
└── 03_cloud_security_checklist.md    ← CISチェックリスト、Terraform、SCPポリシー
```

**主要内容:** IAM権限悪用、S3誤設定、コンテナエスケープ、Kubernetes攻撃、クラウドセキュリティチェックリスト

---

## 15. WiFiハッキング

```
15_WiFi_Hacking/
├── 01_wifi_hacking_fundamentals.md   ← WEP/WPA/WPA2/WPA3理論、aircrack-ng基礎
├── 02_wpa2_cracking.md               ← Hashcat/Aircrack、PMKID攻撃、ワードリスト最適化
└── 03_advanced_wifi_attacks.md       ← Evil Twin、KARMA、Bettercap、Scapy操作
```

**主要内容:** 4-Way Handshake、PMKIDキャプチャ、GPUクラッキング、Evil Twin構築、無線自動化

---

## 16. 暗号理論

```
16_Cryptography/
├── 01_cryptography_for_hackers.md   ← AESモード攻撃、RSA脆弱性、XORクラッキング
├── 02_hash_attacks.md               ← MD5衝突、レインボーテーブル、Kerberoasting
└── 03_applied_cryptography.md       ← Padding Oracle、ECDSAノンス再利用、JWT攻撃
```

**主要内容:** 暗号実装の脆弱性、CTF暗号問題パターン、安全な暗号化実装ガイド

---

## 17. レッドチーム運営

```
17_Red_Team_Operations/
├── 01_red_team_playbook.md               ← 運営構造、Cobalt Strike/Havoc、AV/EDRバイパス
├── 02_phishing_and_social_engineering.md ← GoPhish、Evilginx2、スピアフィッシング、BEC
└── 03_api_hacking.md                     ← OWASP API Top 10、GraphQL、ファザー開発
```

**主要内容:** レッドチームvsペンテストの違い、C2フレームワーク運営、フィッシングインフラ、API脆弱性完全攻略

---

## 18. DevSecOps

```
18_DevSecOps/
├── 01_devsecops_fundamentals.md    ← Shift Left、Semgrep、SonarQube、Snyk、ZAP
├── 02_container_security.md        ← Dockerfileセキュリティ、Trivy、Falco、K8s RBAC、cosign
└── 03_github_actions_security.md   ← CI/CDセキュリティ、OIDC、SHAピン留め、完全セキュリティパイプライン
```

**主要内容:** セキュリティ内在化（Shift Left）、SAST/SCA/DAST/IaCスキャン自動化、コンテナランタイム検出、GitLab/Jenkins/GitHub Actionsセキュアパイプライン完全実装

---

## 注意事項

> **このリポジトリのすべての技術は、必ず許可された環境でのみ使用してください。**

- CTF、バグバウンティ、契約されたペンテストの範囲内で活用
- 脆弱性発見時は責任ある開示（Responsible Disclosure）の原則に従う
- 不正なシステムアクセスは不正アクセス禁止法をはじめとする関連法規に違反します

---

<div align="center">

**⚔️ VibeHacking** — 実践セキュリティのプロへの旅

*Built with [Claude Code](https://claude.ai/code)*

</div>
