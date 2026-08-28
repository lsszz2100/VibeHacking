<div align="center">

# ⚔️ VibeHacking

### 実践サイバーセキュリティ完全攻略 — AI時代のハッキングバイブル

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-75-blueviolet)](#目次)
[![Files](https://img.shields.io/badge/Docs-491%2B%20Files-brightgreen)](#目次)
[![Lines](https://img.shields.io/badge/Lines-560%2C000%2B-orange)](#目次)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-aiを活用したサイバーセキュリティ)
[![Play Wargame](https://img.shields.io/badge/Play_Wargame-terminal_infiltration·490-9933ff)](https://lsszz2100.github.io/VibeHacking/)

> 🎮 **ブラウザのターミナルで遊ぶ侵入CTFワーゲーム** — 偽シェル（`connect`・`cat`・`submit`）でターゲット `vibe.corp` のセキュリティ層5つ（外周→Web→内部→金庫→コア）を1層ずつ突破し、490問をクリア。起動シーケンス・`ACCESS GRANTED` 演出・マトリックスレイン・サウンド・ヒント・日英対応。本リポジトリの75セクション基盤。([紹介](wargame/README.md) · GitHub Pages有効化後にアクセス可能)

<br/>

> 理論から実習まで、CTF・バグバウンティ・ペネトレーションテスト・レッドチームに実戦投入できるレベルでまとめたセキュリティ知識リポジトリ。
> **2026年Claude・GPT-4o時代**のAIベース脆弱性研究からクラウド・無線・暗号理論まで完全網羅。

**🌐 Language / 言語 / 语言:**
[한국어](README.md) · [English](README.en.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## このリポジトリについて

実戦力を高めたいセキュリティ学習者のために、すぐに実行できるコードと体系的な方法論を一か所にまとめました。  
CTF・バグバウンティ・レッドチーム・AIセキュリティまで、**多言語で設計された実践中心の知識ハブ**です。

**VibeHackingの強み:**

- **コード優先** — 全セクションにコピー＆ペースト可能なコマンドとコードを収録
- **AI統合** — Claude/GPT-4oをセキュリティ分析ツールとして活用する方法を解説
- **最新動向反映** — Anthropic Claude、OpenAI GPT-4oなどAI最先端セキュリティエコシステムを網羅
- **多言語対応** — 韓国語・英語・日本語・中国語で提供
- **完全なカバレッジ** — バグバウンティ・SOC・クラウド・WiFi・暗号理論・レッドチームまで全領域

---

## 🤖 AI CLIで自然言語学習

`claude` / `codex` / `gemini` を **レポジトリのディレクトリ内で** 実行すると、AIが75セクション全てをコンテキストとして読み込み、自然言語のチューターになります。ファイルを手動で探さなくても、一言で学習・実習が可能です。

```bash
cd VibeHacking
claude   # または: codex / gemini
```

| AI CLI | インストール | 強み |
|--------|------------|------|
| **Claude Code** | `npm i -g @anthropic-ai/claude-code` | ファイル読み取り + コマンド実行、自然な日本語対応 |
| **Codex CLI** | `npm i -g @openai/codex` | コード生成・解析に特化 |
| **Gemini CLI** | `npm i -g @google/gemini-cli` | 最大コンテキスト (100万トークン+) |

**すぐに使えるプロンプト:**

```
「セキュリティ完全初心者です。このリポジトリで何から学べばいいですか？」
「05_Web_Hacking/02_sql_injection_advanced.md を読んでSQL攻撃の核心技法を説明して」
「Webハッキング Lab 01 を起動して、DVWAでSQL インジェクション実習をステップごとに案内して」
「このCTF問題のヒントだけ教えて。解答は自分でやる」
「Kerberoastingの概念を説明して、実習環境の構成方法も教えて」
```

> 🤖 完全ガイド + 学習シナリオ4つ + プロンプトテンプレート → **[AI_LEARNING.md](./AI_LEARNING.md)**

---

## 🛠️ CLI + 実習環境 — すぐに始める

### 1分セットアップ

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
python3 vhack.py list        # 75セクション一覧を表示
```

> 📖 詳細インストールガイド → **[INSTALL.md](./INSTALL.md)**
> 📘 コマンドリファレンス → **[USAGE.md](./USAGE.md)**
> 🤖 AI CLIで自然言語学習 → **[AI_LEARNING.md](./AI_LEARNING.md)**

### `vhack` 主要コマンド

```bash
# 学習コンテンツを探索
python3 vhack.py list                    # 75セクション全一覧
python3 vhack.py list --search web       # キーワードでフィルタ
python3 vhack.py study 5                 # Webハッキング セクション ファイル一覧
python3 vhack.py study 5 1               # OWASP Top 10 をターミナルで読む
python3 vhack.py search "Kerberoasting"  # 全ドキュメント全文検索

# Docker実習環境管理 (Docker必要)
python3 vhack.py lab ls                  # 実習環境一覧 + アクセスURL
python3 vhack.py lab start 01            # Webハッキングラボ起動 → 8080/dvwa · 3001 · 8081
python3 vhack.py lab start 02            # バイナリエクスプロイトラボ起動
python3 vhack.py lab status              # 実行中コンテナ確認
python3 vhack.py lab stop --all          # 全ラボ停止

# シェルエイリアス — どこからでも vhack を実行 (初回のみ)
python3 vhack.py alias install           # シェル自動検出 → RCファイルに登録
python3 vhack.py alias status            # インストール状況確認
python3 vhack.py alias remove            # エイリアス削除

# アップデート
python3 vhack.py update                  # git pull で最新コンテンツ取得
```

### クイックリファレンス

| コマンド | 説明 |
|----------|------|
| `vhack list` | 75セクション全一覧 |
| `vhack list --search <キーワード>` | セクション名でフィルタ |
| `vhack study <番号>` | セクションのファイル一覧 |
| `vhack study <番号> <ファイル>` | ターミナルでファイルを読む |
| `vhack search <キーワード>` | 全ドキュメント全文検索 |
| `vhack info <番号>` | セクション詳細情報 |
| `vhack lab ls` | 実習環境一覧 + アクセスURL |
| `vhack lab start <id>` | 実習環境を起動 |
| `vhack lab stop <id>` | 実習環境を停止 |
| `vhack lab stop --all` | 全ラボ停止 |
| `vhack lab status` | 実行中コンテナ確認 |
| `vhack lab logs <id>` | ライブログ表示 |
| `vhack alias install` | シェルエイリアス登録 |
| `vhack alias install --profile <ファイル>` | 特定プロファイルに登録 |
| `vhack alias status` | インストール状況確認 |
| `vhack alias remove` | エイリアス削除 |
| `vhack update` | `git pull` で最新化 |

### 実習環境 (Dockerベース)

| # | ラボ名 | 内容 | アクセス | 難易度 |
|:-:|--------|------|----------|:------:|
| **01** | Webハッキングラボ | DVWA · Juice Shop · WebGoat | 8080(DVWA·SQLi) / 3001(Juice Shop) / 8081(WebGoat) | ★★☆ |
| **02** | バイナリエクスプロイトラボ | BOF · ret2libc · ROP · fmtstr · heap | nc localhost 10001~10005 | ★★★ |
| **03** | ネットワークハッキングラボ | SSH · FTP · DNS · SMTP脆弱サービス | docker exec シェル | ★★☆ |
| **04** | クラウド/コンテナセキュリティラボ | SSRF · AWS IMDS · K8s脱出 | http://localhost:8080 | ★★★ |
| **05** | 総合シナリオラボ | APT攻撃チェーンシミュレーション | http://localhost:8888 | ★★★★ |
| **06** | ファームウェアハッキングラボ | binwalk · QEMUエミュレーション · ハードコード資格情報 | http://localhost:8062 | ★★★ |
| **07** | モバイルセキュリティラボ | APK静的解析 · Frida · JWT alg:none バイパス | http://localhost:8072 | ★★★ |

```bash
# 実習例: Webハッキング
python3 vhack.py study 5 1        # ① OWASP Top 10 理論学習
python3 vhack.py lab start 01     # ② DVWA/Juice Shop ラボ起動
# ③ DVWA: http://localhost:8080/dvwa/  Juice Shop: http://localhost:3001
python3 vhack.py lab stop 01      # ④ 完了後に停止
```

---

## 目次

| # | セクション | 主要内容 | ファイル数 |
|---|-----------|---------|----------|
| 01 | [Linux基礎 & Kali Linux](#01-linux基礎--kali-linux) | 必須コマンド、Kaliセットアップ、Bashスクリプト | 6 |
| 02 | [ネットワークハッキング](#02-ネットワークハッキング) | OSI/TCP-IP、パケット分析、無線ハッキング | 6 |
| 03 | [システムハッキング](#03-システムハッキング) | パスワードクラック、Buffer Overflow | 6 |
| 04 | [リバースエンジニアリング](#04-リバースエンジニアリング) | アセンブリ、x64dbg、PE構造 | 6 |
| 05 | [Webハッキング](#05-webハッキング) | OWASP Top 10、SQLi深掘り、XSS/CSRF | 6 |
| 06 | [マルウェア分析](#06-マルウェア分析) | 静的/動的分析、Volatility、Android | 6 |
| 07 | [デジタルフォレンジクス](#07-デジタルフォレンジクス) | 証拠収集、Windowsアーティファクト、ネットワーク | 6 |
| 08 | [Pythonハッキング](#08-pythonハッキング) | ツール開発、ネットワークスキャナ、Web自動化 | 6 |
| 09 | [エクスプロイト技法](#09-エクスプロイト技法) | ROP Chain、SEH、Linux BOF、権限昇格 | 6 |
| 10 | [ペネトレーションテスト方法論](#10-ペネトレーションテスト方法論) | ペンテスト手順、OSINT偵察、報告書作成 | 6 |
| 11 | [**AIを活用したサイバーセキュリティ**](#11-aiを活用したサイバーセキュリティ) | Claude Opus 4、GPT-4o、LLM脆弱性研究、CTF自動化 | 6 |
| 12 | [**バグバウンティ**](#12-バグバウンティ) | 方法論、Burp Suite上級、自動化ツール | 6 |
| 13 | [**SOC & Blue Team**](#13-soc--blue-team) | SOC運用、Splunk分析、脅威ハンティング | 6 |
| 14 | [**クラウドセキュリティ**](#14-クラウドセキュリティ) | AWS/Azure/GCP攻撃ベクター、ペンテスト、チェックリスト | 6 |
| 15 | [**WiFiハッキング**](#15-wifiハッキング) | WPA2クラック、PMKID、Evil Twin、自動化 | 6 |
| 16 | [**暗号理論**](#16-暗号理論) | ハッカーのための暗号学、ハッシュ攻撃、応用暗号 | 6 |
| 17 | [**レッドチーム運営**](#17-レッドチーム運営) | プレイブック、フィッシング/ソーシャルエンジニアリング、APIハッキング | 6 |
| 18 | [**DevSecOps**](#18-devsecops) | SAST/SCA/DAST、コンテナセキュリティ、CI/CDパイプライン | 6 |
| 19 | [**アセンブリ言語**](#19-アセンブリ言語) | x86/x64基礎、シェルコード開発、逆アセンブリ解析 | 6 |
| 20 | [**シェルスクリプト**](#20-シェルスクリプト) | Bash基礎、侵入自動化、事後エクスプロイト | 6 |
| 21 | [**Windows エクスプロイト**](#21-windows-エクスプロイト) | Windows内部構造、権限昇格、防御回避 | 6 |
| 22 | [**パスワードクラッキング**](#22-パスワードクラッキング) | ハッシュ種類/ワードリスト、Hashcat/John、高度な手法 | 6 |
| 23 | [**データベースハッキング**](#23-データベースハッキング) | Oracle/MySQL攻撃、DB権限昇格、フォレンジクス・監査 | 6 |
| 24 | [**ネットワークインフラセキュリティ**](#24-ネットワークインフラセキュリティ) | DNS攻撃、メールサーバ(SPF/DKIM/DMARC)、SSHトンネリング | 6 |
| 25 | [**脅威インテリジェンス**](#25-脅威インテリジェンス) | CTI基礎、OSINT/Shodan、インシデント対応、ハニーポット | 6 |
| 26 | [**Linux ハードニング**](#26-linux-ハードニング) | iptables/nftables、PAM認証、KISA脆弱性評価 | 6 |
| 27 | [**IoT ハッキング**](#27-iot-ハッキング) | 攻撃面分析、ファームウェア分析、IoTエクスプロイト | 6 |
| 28 | [**モバイルハッキング**](#28-モバイルハッキング) | Androidペンテスト、iOSペンテスト、モバイルトラフィック分析 | 6 |
| 29 | [**コンテナ/Kubernetesセキュリティ**](#29-コンテナkubernetesセキュリティ) | Dockerセキュリティ、Kubernetes攻撃、コンテナ脱出 | 6 |
| 30 | [**脆弱性研究**](#30-脆弱性研究) | ファジング技法、脆弱性分析、高度なエクスプロイト開発 | 6 |
| 31 | [**AI/ML システムセキュリティ**](#31-aiml-システムセキュリティ) | 敵対的サンプル、プロンプトインジェクション、モデル抽出、エージェントセキュリティ | 6 |
| 32 | [**ネットワーク機器ハッキング**](#32-ネットワーク機器ハッキング) | IOS偵察、L2攻撃、ルーティングプロトコル操作、管理プレーンエクスプロイト | 6 |
| 33 | [**OSINT & ソーシャルエンジニアリング**](#33-osint--ソーシャルエンジニアリング) | 情報収集方法論、ターゲットプロファイリング、フィッシングインフラ構築・回避 | 6 |
| 34 | [**ハードウェアハッキング**](#34-ハードウェアハッキング) | インターフェース分析(UART/JTAG/SPI)、ファームウェア抽出、サイドチャネル・フォルトインジェクション | 6 |
| 35 | [**サプライチェーン攻撃**](#35-サプライチェーン攻撃) | ソフトウェア供給網侵害、CI/CDパイプライン汚染、SolarWinds・XZパターン分析 | 6 |
| 36 | [**自動車ハッキング**](#36-自動車ハッキング) | CANバス分析、ECUエクスプロイト、テレマティクス・OTA攻撃 | 6 |
| 37 | [**ICS/SCADA セキュリティ**](#37-icsscada-セキュリティ) | ICSプロトコル偵察、SCADAエクスプロイト、OTネットワーク攻撃・防御 | 6 |
| 38 | [**Cloud Nativeセキュリティ**](#38-cloud-nativeセキュリティ) | CNAPP、eBPFランタイムセキュリティ、イメージ強化、コンテナ脱出 | 6 |
| 39 | [**Zero Trustアーキテクチャ**](#39-zero-trustアーキテクチャ) | ZTA原則、アイデンティティ/デバイス信頼、マイクロセグメンテーション、SASE | 6 |
| 40 | [**脅威ハンティング**](#40-脅威ハンティング) | ハンティング方法論、MITRE ATT&CKシナリオ、100+ KQL/SPLクエリ、SOAR | 6 |
| 41 | [**韓国セキュリティ資格**](#41-韓国セキュリティ資格) | 情報セキュリティ技術士、ISMS-P、CISSP/OSCPロードマップ、安全法令 | 6 |
| 42 | [**ブロックチェーン/Web3セキュリティ**](#42-ブロックチェーンweb3セキュリティ) | EVM構造、スマートコントラクト監査、DeFi攻撃、Web3ペンテストツール | 6 |
| 43 | [**物理セキュリティペンテスト**](#43-物理セキュリティペンテスト) | 物理ペンテスト方法論、錠前解除、RFIDクローン、ソーシャルエンジニアリング | 6 |
| 44 | [**インシデントレスポンス/DFIR**](#44-インシデントレスポンスdfir) | IRプレイブック、メモリ/ディスクフォレンジクス、ネットワークフォレンジクス、封じ込め | 6 |
| 45 | [**マルウェア開発**](#45-マルウェア開発) | PE構造、シェルコード/インジェクション、C2フレームワーク、AV/EDR回避 | 6 |
| 46 | [**CTF技法**](#46-ctf技法) | CTF方法論/ツール、PWN/REV、Web/暗号、自動化フレームワーク | 6 |
| 47 | [**モバイルフォレンジクス**](#47-モバイルフォレンジクス) | Android/iOSフォレンジクス、証拠抽出、モバイルツール | 6 |
| 48 | [**脅威モデリング**](#48-脅威モデリング) | STRIDE/PASTA/DREAD、アタックツリー、ツール | 6 |
| 49 | [**レッドチームインフラ**](#49-レッドチームインフラ) | C2フレームワーク、ドメインフロンティング、OPSEC | 6 |
| 50 | [**ゲームハッキング**](#50-ゲームハッキング) | メモリ操作、Cheat Engine、パケット操作、アンチチート分析 | 6 |
| 51 | [**ブラウザ拡張セキュリティ**](#51-ブラウザ拡張セキュリティ) | MV2/V3、悪意ある拡張分析、Content Script XSS | 6 |
| 52 | [**APIセキュリティ**](#52-apiセキュリティ) | OWASP API Top 10、BOLA、GraphQL、ファジング、OAuth2 | 6 |
| 53 | [**サーバーレスセキュリティ**](#53-サーバーレスセキュリティ) | Lambda攻撃、イベントインジェクション、IAM乱用、IaCスキャン | 6 |
| 54 | [**Active Directory攻撃**](#54-active-directory攻撃) | AD列挙、Kerberoasting、DCSync、ゴールデンチケット | 6 |
| 55 | [**検知回避技法**](#55-検知回避技法) | AV/EDR回避、IDS/IPS回避、syscall直接呼出し、痕跡削除 | 6 |
| 56 | [**AIレッドチーム**](#56-aiレッドチーム) | プロンプトインジェクション、モデル抽出、敵対的サンプル | 6 |
| 57 | [**量子暗号**](#57-量子暗号) | QKD、ポスト量子アルゴリズム、NIST PQC | 6 |
| 58 | [**クラウドインシデント対応**](#58-クラウドインシデント対応) | CloudTrailフォレンジック、Azure/GCP IR、脅威ハンティング | 6 |
| 59 | [**サプライチェーンセキュリティ**](#59-サプライチェーンセキュリティ) | SBOM、依存関係混乱攻撃、SLSAビルド完全性 | 6 |
| 60 | [**ブラウザセキュリティ上級**](#60-ブラウザセキュリティ上級) | JSエンジン攻撃、サンドボックス脱出、MV3 | 6 |
| 61 | [**ファームウェアハッキング**](#61-ファームウェアハッキング) | ファームウェア抽出、Ghidra解析、QEMUエミュレーション | 6 |
| 62 | [**自動車セキュリティ**](#62-自動車セキュリティ) | CANバス、ECU/UDS、V2X攻撃 | 6 |
| 63 | [**OT/ICS上級**](#63-otics上級) | SCADA、PLCエクスプロイト、産業用プロトコル | 6 |
| 64 | [**脅威インテリジェンスプラットフォーム**](#64-脅威インテリジェンスプラットフォーム) | MISP、脅威フィード、IOC自動化 | 6 |
| 65 | [**リバースエンジニアリング上級**](#65-リバースエンジニアリング上級) | アンチデバッグ、アンパッキング、シンボリック実行 | 6 |
| 66 | [**エクスプロイト開発**](#66-エクスプロイト開発) | ROPチェーン、ヒープ/カーネル/ブラウザ攻撃 | 6 |
| 67 | [**マルウェア開発の理解**](#67-マルウェア開発の理解) | C2アーキテクチャ、シェルコード、永続化、回避 | 6 |
| 68 | [**パープルチーム運用**](#68-パープルチーム運用) | 攻撃シミュレーション、検知エンジニアリング、ATT&CK | 6 |
| 69 | [**LLMセキュリティ**](#69-llmセキュリティ) | OWASP LLM Top 10、プロンプトインジェクション、ガードレール | 6 |
| 70 | [**Kubernetesセキュリティ**](#70-kubernetesセキュリティ) | RBAC悪用、Pod脱出、etcd、強化 | 6 |
| 71 | [**Bluetooth/RFハッキング**](#71-bluetoothrfハッキング) | BLE攻撃、RTL-SDR、Zigbee IoTセキュリティ | 6 |
| 72 | [**マルウェアサンドボックス分析**](#72-マルウェアサンドボックス分析) | ANY.RUN/VirusTotal、PE解析、IOC抽出 | 6 |
| 73 | [**バグバウンティ自動化**](#73-バグバウンティ自動化) | HackerOne、subfinder/nucleiパイプライン、CVSSレポート | 6 |
| 74 | [**コード監査**](#74-コード監査) | Semgrep/CodeQL、Source-Sink追跡、CI/CDゲート | 6 |
| 75 | [**レッドチームレポート作成**](#75-レッドチームレポート作成) | ATT&CKマッピング、二重読者レポート、デブリーフィング | 6 |
| 🧪 | [**CTF実習環境（labs/）**](#ctf実習環境labs) | Web・バイナリ・ネットワーク・クラウド・統合・ファームウェア・モバイルDockerラボCTF | 50 |

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
| 攻撃マシン | Kali Linux (最新) |
| 仮想化 | VMware Workstation / VirtualBox |
| 脆弱な環境 | Metasploitable2、DVWA、HackTheBox、TryHackMe、CloudGoat |
| 分析ツール | Wireshark、Burp Suite、IDA Pro / Ghidra、x64dbg |
| 言語 | Python 3.x、Bash、pwntools |
| AIツール | Claude Opus 4.6、GPT-4o（） |
| 無線 | Alfa AWUS036ACH（2.4/5GHzモニターモード対応） |
| クラウド | AWS Free Tier、CloudGoat |

---

## 01. Linux基礎 & Kali Linux

```
01_Linux_Basics/
├── 01_linux_essential_commands.md   ← ファイル/プロセス/ネットワーク必須コマンド
├── 02_kali_linux_setup.md           ← Kali初期設定、ツールインストール
├── 03_bash_scripting.md             ← 自動化スクリプト、実践例
├── 04_linux_privilege_escalation.md ← Linux権限昇格 — sudo · SUID · Capabilities · カーネルエクスプロイト
├── 05_linux_security_tools.md       ← Linuxセキュリティツールリファレンス
└── 06_linux_ctf_practical_lab.md    ← Linux CTF実践ラボ — 権限昇格 · SUID · Cron · 環境変数
```

**主要内容:** ファイルシステム、プロセス管理、ネットワークコマンド、権限管理、30以上のBash自動化スクリプト

---

## 02. ネットワークハッキング

```
02_Network_Hacking/
├── 01_osi_tcpip.md          ← OSI 7層、TCP/IPスタック、プロトコル分析
├── 02_packet_analysis.md    ← Wireshark実践、tcpdump、パケット操作
├── 03_wireless_hacking.md   ← WEP/WPA2クラック、Evil Twin、無線ハッキング
├── 04_mitm_advanced.md      ← MITM上級 — ARPスプーフィング · SSLストリッピング · bettercap · mitmproxy
├── 05_network_exploitation_techniques.md ← 高度なネットワーク攻撃技法
└── 06_network_ctf_lab.md    ← CTF形式ネットワークハッキングラボ
```

**主要内容:** パケットキャプチャ・分析、ARPスプーフィング、MITM、無線ネットワーク攻撃、ファイアウォール回避

---

## 03. システムハッキング

```
03_System_Hacking/
├── 01_password_cracking.md       ← Hashcat、John、Rainbow Table、オンラインクラック
├── 02_buffer_overflow.md         ← スタックBOF原理、シェルコード、実践例
├── 03_active_directory_attack.md ← AD攻撃完全ガイド、Kerberoasting、DCSync
├── 04_kerberos_delegation_attacks.md ← Kerberos委任攻撃 — 完全ガイド
├── 05_system_defense_and_detection.md ← システム攻撃の検知と防御
└── 06_system_ctf_lab.md          ← CTF形式システムハッキングラボ
```

**主要内容:** ハッシュクラック戦略、BOF原理からエクスプロイトまで、Active Directory攻撃チェーン完全攻略

---

## 04. リバースエンジニアリング

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md   ← x86/x64アセンブリ、レジスタ、スタックフレーム
├── 02_ollydbg_practical.md        ← x64dbg実践分析
├── 03_pe_structure.md             ← PEファイル構造、IAT/EAT、パッキング
├── 04_ghidra_and_dynamic_analysis.md ← Ghidra実践分析＆WorstFit Unicode脆弱性
├── 05_advanced_unpacking_and_deobfuscation.md ← 高度なアンパッキングと難読化解除
└── 06_reversing_ctf_lab.md        ← CTF形式リバーシングラボ
```

**主要内容:** アセンブリ言語、デバッガ使用法、PE構造の深掘り分析、IDA Pro/Ghidra

---

## 05. Webハッキング

```
05_Web_Hacking/
├── 01_owasp_top10.md              ← OWASP Top 10（2021）、Burp Suite、Nikto
├── 02_sql_injection_advanced.md   ← Blind/Time-based SQLi、NoSQL、SQLMap実践
├── 03_xss_csrf_file_upload.md     ← Stored/Reflected/DOM XSS、CSRF、Webシェル
├── 04_waf_bypass_advanced_web.md  ← WAFバイパス＆高度なWeb攻撃技法
├── 05_web_security_tools_and_automation.md ← Webセキュリティツールと自動化
└── 06_web_ctf_practical_lab.md    ← WebハッキングCTF実践ラボ — SQLインジェクション、XSS、SSRF、SSTI総合
```

**主要内容:** OWASP Top 10実践、SQL Injection完全攻略、XSS/CSRF/ファイルアップロード/XXE/SSRF

---

## 06. マルウェア分析

```
06_Malware_Analysis/
├── 01_malware_analysis.md            ← 分類、分析環境、静的/動的分析、YARA
├── 02_memory_forensics_malware.md    ← Volatility完全攻略、コードインジェクション検出
├── 03_android_malware_analysis.md    ← APK分析、Fridaフッキング、MobSF
├── 04_yara_and_detection.md          ← YARAルール開発とマルウェア自動検知
├── 05_malware_defense_and_hunting.md ← マルウェア防御とハンティング
└── 06_malware_ctf_practical_lab.md   ← マルウェア分析CTF実践ラボ — 静的/動的分析、アンパッキング
```

**主要内容:** 静的・動的・メモリ分析の全工程、Volatilityプラグイン、Androidマルウェア

---

## 07. デジタルフォレンジクス

```
07_Digital_Forensics/
├── 01_digital_forensics.md               ← フォレンジクス原則、証拠収集、イメージ分析
├── 02_windows_forensics_artifacts.md     ← レジストリ、イベントログ、Prefetch、ブラウザ
├── 03_network_forensics.md               ← Wireshark、Zeek、Suricata、インシデント対応
├── 04_advanced_volatility.md             ← Volatility3上級 — プロセス分析、ネットワーク、マルウェア検知
├── 05_forensics_automation_and_tools.md  ← フォレンジック自動化とツール
└── 06_forensics_ctf_lab.md               ← フォレンジック CTFラボ
```

**主要内容:** 証拠収集手順、Windowsアーティファクト完全分析、ネットワークフォレンジクス、タイムライン分析

---

## 08. Pythonハッキング

```
08_Python_Hacking/
├── 01_python_hacking_tools.md       ← ポートスキャナ・スニッファ・バックドアなど30以上のサンプル
├── 02_python_network_scanner.md     ← マルチスレッドスキャナ、ARP、DNS列挙、SSHブルートフォーサ
├── 03_python_web_exploitation.md    ← Webクローラ、SQLi自動化、XSSスキャナ、レポート生成
├── 04_python_exploit_automation.md  ← Pythonエクスプロイト自動化 — pwntools、ROPgadget、CTFツール
├── 05_python_security_automation.md ← Pythonセキュリティ自動化 — Scapy、requests、paramiko、自動化ツール
└── 06_python_hacking_ctf_lab.md     ← Pythonハッキング CTF実践ラボ
```

**主要内容:** Scapy、paramiko、requestsを活用したセキュリティツール開発、50以上の完全動作コード

---

## 09. エクスプロイト技法

```
09_Exploit_Techniques/
├── 01_advanced_exploitation.md   ← ROP Chain、Heap Spray、SEH、Win32シェルコーディング
├── 02_linux_exploitation.md      ← Linux BOF、Ret2Libc、フォーマット文字列、権限昇格
├── 03_heap_exploitation.md       ← tcacheポイズニング、UAF、House ofシリーズ、pwndbg
├── 04_format_string_exploits.md  ← 書式文字列エクスプロイト — 任意読み書き、GOT上書き
├── 05_exploit_defense_and_mitigation.md ← エクスプロイト防御と緩和 — ASLR、DEP/NX、スタックカナリア、CFG
└── 06_exploit_ctf_lab.md         ← エクスプロイト技法 CTF実践ラボ
```

**主要内容:** DEP/ASLR/NXバイパス、ROPチェーン構成、フォーマット文字列エクスプロイト、ヒープエクスプロイト完全攻略

---

## 10. ペネトレーションテスト方法論

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← ペンテスト全手順、MITRE ATT&CK、報告書作成
├── 02_osint_recon.md           ← Google Dorks、Shodan、サブドメイン列挙、GitHub秘密情報検出
├── 03_report_writing.md        ← プロ報告書作成、CVSS算定、PoC作成、経営者/技術報告書テンプレート
├── 04_post_exploitation.md     ← ポストエクスプロイト方法論 — 永続化、情報収集、権限昇格
├── 05_pentest_reporting_and_remediation.md ← 侵入テスト報告と是正 — CVSSスコアリング、レポート作成
└── 06_pentest_ctf_lab.md       ← 侵入テスト方法論 CTF実践ラボ
```

**主要内容:** 体系的なペンテスト方法論、OSINTツール完全活用、プロ報告書作成（CVSS・PoC・コンプライアンス対応）

---

## 11. AIを活用したサイバーセキュリティ

> **2026年現在、AIがサイバーセキュリティの勢力図を塗り替えている。**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Claude・GPT-4o・내부 연구 프로그램全体俯瞰
├── 02_llm_vulnerability_research.md   ← LLMによるゼロデイ発見、AIファジング、コード分析自動化
├── 03_ai_assisted_pentesting.md       ← AI支援ペンテストワークフロー、プロンプトエンジニアリング
├── 04_ai_ctf_automation.md            ← CTF自動化AIエージェント、暗号/Web/フォレンジクス専門サブエージェント
├── 05_claude_gpt_cyber_integration.md ← AI統合 — Claude + GPT-4oセキュリティ分析ツールガイド
└── 06_ai_security_ctf_lab.md          ← CTF形式AIセキュリティラボ
```

### 2026年 AIセキュリティ勢力図

| モデル | 組織 | 能力 | アクセス方法 |
|-------|------|------|------------|
| **Claude Opus 4** | Anthropic | 17年間放置されたFreeBSD RCEを自律発見、数千のゼロデイ | 내부 연구 프로그램（12パートナー企業のみ） |
| **GPT-4o** | OpenAI | バイナリリバーシング、CTF 76%自律解決、YARA生成 | （openai.com） |
| **Claude Opus 4.6** | Anthropic | コード脆弱性分析、CTF補助、YARA自動化 | 一般公開 |

**主要内容:** AIセキュリティエコシステム完全分析、Claude APIベースの脆弱性スキャナ実装、AI支援ペンテスト自動化、CTF解法AIエージェント（暗号/Web/フォレンジクス/リバーシング専門サブエージェント含む）

---

## 12. バグバウンティ

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd方法論、IDOR、XSSバイパス、自動化
├── 02_burp_suite_advanced.md      ← Burp Suite完全攻略、JWT攻撃、Request Smuggling
├── 03_bug_bounty_automation.md    ← Nuclei、ffuf、dalfox、自動化パイプライン
├── 04_api_security_testing.md     ← APIセキュリティテスト＆バグバウンティ実践ガイド
├── 05_advanced_vuln_chains.md     ← バグバウンティ上級 — 脆弱性チェーン、サブドメイン乗っ取り、アカウント乗っ取り
└── 06_bug_bounty_ctf_lab.md       ← バグバウンティ CTF実践ラボ
```

**主要内容:** バグバウンティ全ワークフロー、Burp Suite高度な機能、偵察→脆弱性→報告書の自動化

---

## 13. SOC & Blue Team

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md       ← SOC構造、インシデント対応、主要イベントID、EDR
├── 02_splunk_siem_analysis.md   ← Splunk SPL完全攻略、100以上の検出クエリ
├── 03_threat_hunting.md         ← 脅威ハンティング、ランサムウェア侵害調査、APT追跡
├── 04_qradar_xdr_blue_team.md   ← IBM QRadar＆Azure Sentinel KQL＆XDRブルーチーム実践ガイド
├── 05_detection_engineering.md  ← 検知エンジニアリング — Sigma＆MITRE ATT&CKベースのルール開発
└── 06_soc_ctf_lab.md            ← SOC/ブルーチーム CTFラボ
```

**主要内容:** SOCティア別役割、攻撃検出パターン100以上、Splunk/QRadar/ELKクエリ、脅威ハンティング方法論

---

## 14. クラウドセキュリティ

```
14_Cloud_Security/
├── 01_cloud_attack_vectors.md        ← AWS/Azure/GCP/K8s攻撃ベクター完全分析
├── 02_aws_pentest.md                 ← AWSペンテスト方法論、権限昇格、自動化
├── 03_cloud_security_checklist.md    ← CISチェックリスト、Terraform、SCPポリシー
├── 04_GCP_Azure_Pentest.md           ← GCP・Azure侵入テスト
├── 05_cloud_lateral_movement.md      ← クラウド水平移動 — アカウントピボット、サービス間移動、権限昇格
└── 06_cloud_security_ctf_lab.md      ← クラウドセキュリティ CTF実践ラボ
```

**主要内容:** IAM権限悪用、S3誤設定、コンテナエスケープ、Kubernetes攻撃、クラウドセキュリティチェックリスト

---

## 15. WiFiハッキング

```
15_WiFi_Hacking/
├── 01_wifi_hacking_fundamentals.md   ← WEP/WPA/WPA2/WPA3理論、aircrack-ng基礎
├── 02_wpa2_cracking.md               ← Hashcat/Aircrack、PMKID攻撃、ワードリスト最適化
├── 03_advanced_wifi_attacks.md       ← Evil Twin、KARMA、Bettercap、Scapy操作
├── 04_Enterprise_WiFi_Attacks.md     ← エンタープライズWiFi攻撃（WPA2-Enterprise / RADIUS）
├── 05_rogue_ap_and_detection.md      ← 不正AP、キャプティブポータル、WiFi監視と検知
└── 06_wifi_ctf_lab.md                ← WiFiハッキング CTF実践ラボ
```

**主要内容:** 4-Way Handshake、PMKIDキャプチャ、GPUクラッキング、Evil Twin構築、無線自動化

---

## 16. 暗号理論

```
16_Cryptography/
├── 01_cryptography_for_hackers.md   ← AESモード攻撃、RSA脆弱性、XORクラッキング
├── 02_hash_attacks.md               ← MD5衝突、レインボーテーブル、Kerberoasting
├── 03_applied_cryptography.md       ← Padding Oracle、ECDSAノンス再利用、JWT攻撃
├── 04_PKI_TLS_Attacks.md            ← PKIインフラとTLS/SSL攻撃
├── 05_crypto_implementation_attacks.md ← 暗号実装攻撃 — パディングオラクル、タイミング攻撃、脆弱なRNG
└── 06_crypto_ctf_practical_lab.md   ← 暗号CTF実践ラボ — 古典暗号、RSA、ECC、ハッシュ
```

**主要内容:** 暗号実装の脆弱性、CTF暗号問題パターン、安全な暗号化実装ガイド

---

## 17. レッドチーム運営

```
17_Red_Team_Operations/
├── 01_red_team_playbook.md               ← 運営構造、Cobalt Strike/Havoc、AV/EDRバイパス
├── 02_phishing_and_social_engineering.md ← GoPhish、Evilginx2、スピアフィッシング、BEC
├── 03_api_hacking.md                     ← OWASP API Top 10、GraphQL、ファザー開発
├── 04_C2_Infrastructure.md               ← C2（コマンド＆コントロール）インフラ構築と運用
├── 05_red_team_reporting.md              ← レッドチーム報告 — 結果分析、エクスプロイトチェーン文書化
└── 06_red_team_ctf_lab.md                ← レッドチーム作戦 CTF実践ラボ
```

**主要内容:** レッドチームvsペンテストの違い、C2フレームワーク運営、フィッシングインフラ、API脆弱性完全攻略

---

## 18. DevSecOps

```
18_DevSecOps/
├── 01_devsecops_fundamentals.md    ← Shift Left、Semgrep、SonarQube、Snyk、ZAP
├── 02_container_security.md        ← Dockerfileセキュリティ、Trivy、Falco、K8s RBAC、cosign
├── 03_github_actions_security.md   ← CI/CDセキュリティ、OIDC、SHAピン留め、完全セキュリティパイプライン
├── 04_Secret_Detection_and_SBOM.md ← シークレット検出とSBOM（ソフトウェア部品表）
├── 05_supply_chain_security.md     ← サプライチェーンセキュリティ — 依存関係攻撃、SLSA、署名検証
└── 06_devsecops_ctf_lab.md         ← DevSecOps CTF実践ラボ
```

**主要内容:** セキュリティ内在化（Shift Left）、SAST/SCA/DAST/IaCスキャン自動化、コンテナランタイム検出、GitLab/Jenkins/GitHub Actionsセキュアパイプライン完全実装

---

## 19. アセンブリ言語

```
19_Assembly_Language/
├── 01_x86_x64_Fundamentals.md   ← レジスタ、命令、スタックフレーム、呼び出し規約
├── 02_Shellcode_Development.md  ← シェルコード作成、バッドバイト除去、ctypes実行テスト
├── 03_Disassembly_Analysis.md   ← GDB/pwndbg、IDA/Ghidra、Capstone自動化
├── 04_ROP_Chain_Programming.md  ← ROP（Return-Oriented Programming）チェーン構築
├── 05_shellcode_analysis_and_detection.md ← シェルコード分析と検知 — 静的/動的分析とシグネチャ作成
└── 06_assembly_ctf_lab.md       ← アセンブリ言語 CTF実践ラボ
```

**主要内容:** x86/x64レジスタ完全攻略、NASMコーディング、64ビットexecveシェルコード実装、Capstoneベース自動逆アセンブラ

---

## 20. シェルスクリプト

```
20_Shell_Scripting/
├── 01_Bash_Scripting_Basics.md       ← 変数/配列/条件/ループ/関数、awk/sed、ポートスキャナ
├── 02_Pentest_Automation.md          ← 偵察自動化、サブドメイン列挙、脆弱性スキャンラッパー
├── 03_Post_Exploitation_Scripts.md   ← リバースシェル、永続化、Python C2ソケット実装
├── 04_Advanced_Obfuscation_Evasion.md ← シェルスクリプト難読化と検知回避
├── 05_bash_forensics_and_monitoring.md ← Bashフォレンジック＆監視自動化 — ログ分析、異常検知
└── 06_shell_ctf_lab.md               ← シェルスクリプト CTF実践ラボ
```

**主要内容:** Bash実践スクリプト、偵察から事後エクスプロイトまで全工程自動化、リバースシェルワンライナー7種、Python C2実装

---

## 21. Windows エクスプロイト

```
21_Windows_Exploitation/
├── 01_Windows_Internals.md              ← PEフォーマット、PEB/TEB、WinAPIコア関数、PEパーサコード
├── 02_Windows_Privilege_Escalation.md   ← サービス/レジストリ/DLLハイジャッキング、UACバイパス、トークンインパーソネーション
├── 03_Defense_Evasion.md                ← AMSI/ETWバイパス、プロセスインジェクション6種、LOLBAS、AESペイロード暗号化
├── 04_COM_Object_Hijacking.md           ← COMオブジェクトハイジャックとWMI悪用
├── 05_windows_persistence_detection.md  ← Windows永続化検知 — レジストリ、サービス、WMIバックドア分析
└── 06_windows_ctf_lab.md                ← Windowsエクスプロイト CTF実践ラボ
```

**主要内容:** Windows内部構造の深掘り、権限昇格完全攻略、AMSI/AV/EDRバイパス技法

---

## 22. パスワードクラッキング

```
22_Password_Cracking/
├── 01_Hash_Types_and_Wordlists.md      ← ハッシュアルゴリズム比較、hashid、CeWL/Crunch/CUPP、Pythonクラッカー
├── 02_Hashcat_and_John.md              ← 全攻撃モード、ハッシュタイプ別モード番号、ルール作成、実戦ワークフロー
├── 03_Advanced_Cracking_Techniques.md  ← レインボーテーブル、PRINCE、マスク上級、パスワードスプレーツール
├── 04_Credential_Stuffing_Automation.md ← クレデンシャルスタッフィングとパスワード分析自動化
├── 05_password_policy_audit.md         ← パスワードポリシー監査 — 脆弱ポリシー検出、ハッシュ強度分析
└── 06_password_ctf_lab.md              ← パスワードクラッキング CTF実践ラボ
```

**主要内容:** NTLM/WPA/ZIP/PDFクラッキング戦略、GPU最適化、レートリミット回避パスワードスプレー自動化

---

## 23. データベースハッキング

```
23_Database_Hacking/
├── 01_oracle_mysql_attack.md       ← Oracle/MySQL/MSSQL攻撃ベクター、ブラインドSQLi、帯域外抽出
├── 02_db_privilege_escalation.md   ← DBユーザ権限昇格、ストアドプロシージャ悪用、UDFインジェクション
├── 03_db_forensics_defense.md      ← データベースフォレンジクス、監査ログ、クエリ監視、ハードニング
├── 04_nosql_and_cloud_db_attacks.md ← NoSQL・クラウドDB攻撃
├── 05_database_defense_and_hardening.md ← データベース防御とハードニング
└── 06_database_ctf_lab.md          ← データベースハッキング CTFラボ
```

**主要内容:** 複数DBにわたる攻撃チェーン、DBエンジン経由の権限昇格、フォレンジクス分析と防御強化

---

## 24. ネットワークインフラセキュリティ

```
24_Network_Infrastructure_Security/
├── 01_dns_attack_defense.md                ← DNSハイジャック、ゾーン転送、キャッシュポイズニング、DNSSECバイパス
├── 02_mail_server_security.md              ← SPF/DKIM/DMARCバイパス、メールサーバ侵害、メールスプーフィング
├── 03_ssh_tunneling_port_forwarding.md     ← SSHトンネリング、動的ポートフォワーディング、SOCKSプロキシ、ピボッティング
├── 04_network_security_automation.md       ← ネットワークセキュリティ自動化
├── 05_network_defense_automation.md        ← ネットワーク防御自動化 — IDS/IPSチューニング、ファイアウォール自動化
└── 06_network_infra_ctf_lab.md             ← ネットワークインフラ CTFラボ
```

**主要内容:** DNS/メール/SSHインフラレベルの攻撃、サービス侵害、ピボッティングによる横断的移動

---

## 25. 脅威インテリジェンス

```
25_Threat_Intelligence/
├── 01_cti_fundamentals.md          ← CTIフレームワーク(MITRE ATT&CK/STIX/TAXII)、脅威アクタープロファイリング
├── 02_osint_for_threat_intel.md    ← Shodan/Censys自動化、ダークウェブOSINT、IOC収集パイプライン
├── 03_incident_response.md         ← IRプレイブック、証拠収集、マルウェアトリアージ、ハニーポット
├── 04_cti_platform_operations.md   ← CTIプラットフォーム運用
├── 05_threat_intel_automation.md   ← 脅威インテリジェンス自動化 — MISP、OpenCTI、IOCエンリッチメント、STIX/TAXII
└── 06_threat_intel_ctf_lab.md      ← 脅威インテリジェンス CTF実践ラボ
```

**主要内容:** CTIライフサイクル、脅威アクター帰属分析、IOC管理、自動化インシデント対応手順

---

## 26. Linux ハードニング

```
26_Linux_Hardening/
├── 01_firewall_and_iptables.md          ← iptables/nftables/ufwルール、ファイアウォール監査、ステートフルフィルタリング
├── 02_pam_and_auth_hardening.md         ← PAM設定、SSHハードニング、MFA設定、sudoポリシー
├── 03_kisa_vulnerability_assessment.md  ← KISAセキュリティチェックリスト、CISベンチマーク、自動評価スクリプト
├── 04_linux_security_auditing.md        ← Linuxセキュリティ監査
├── 05_linux_hardening_automation.md     ← Linuxハードニング自動化 — CISベンチマーク、Ansible Playbook、監査
└── 06_linux_hardening_ctf_lab.md        ← Linuxハードニング CTF実践ラボ
```

**主要内容:** ファイアウォールルール設計、認証強化、KISA/CIS準拠の自動セキュリティ評価

---

## 27. IoT ハッキング

```
27_IoT_Hacking/
├── 01_iot_attack_surface.md    ← 攻撃面分析、OWASP IoT Top 10、Shodan/Censysスキャニング
├── 02_firmware_analysis.md     ← ファームウェア抽出・分析、binwalk/Ghidra、ハードコード脆弱性検出
├── 03_iot_exploitation.md      ← UART/JTAGアクセス、組み込みエクスプロイト、実戦攻撃シナリオ
├── 04_RF_Zigbee_Attacks.md     ← RF/Zigbee/Z-Wave IoT無線プロトコル攻撃
├── 05_iot_security_hardening.md ← IoTセキュリティハードニング — ファームウェア署名、ネットワーク分離、デバイス管理
└── 06_iot_ctf_lab.md           ← IoTハッキング CTF実践ラボ
```

**主要内容:** OWASP IoT Top 10ベース攻撃面分析、ファームウェアリバースエンジニアリング(binwalk/Ghidra)、UART/JTAGハードウェアハッキング、IoTデバイス実戦侵入

---

## 28. モバイルハッキング

```
28_Mobile_Hacking/
├── 01_android_pentesting.md        ← APK分析、ADBルーティング、Frida動的計装、SSLピニングバイパス
├── 02_ios_pentesting.md            ← IPA抽出、Objective-C/Swiftリバーシング、脱獄検出バイパス
├── 03_mobile_traffic_analysis.md   ← Burp Suiteモバイルプロキシ、証明書固定バイパス、APIファジング
├── 04_Mobile_Malware_Analysis.md   ← モバイルマルウェア分析（Android/iOS）
├── 05_mobile_app_security_testing.md ← モバイルアプリセキュリティテスト — 自動分析、ランタイムフック、APIテスト
└── 06_mobile_ctf_lab.md            ← モバイルハッキング CTF実践ラボ
```

**主要内容:** Android/iOS完全分析パイプライン、Fridaベースランタイム計装、モバイルMITM攻撃、SSLピニングバイパス技法

---

## 29. コンテナ/Kubernetesセキュリティ

```
29_Container_Kubernetes_Security/
├── 01_docker_security.md      ← Dockerセキュリティ設定、コンテナ脱出技法、イメージ脆弱性スキャン
├── 02_kubernetes_attack.md    ← RBAC権限昇格、etcd奪取、Kubernetes攻撃ベクター完全分析
├── 03_container_escape.md     ← cgroup/namespace脱出、runc脆弱性、実戦コンテナ脱出PoC
├── 04_Service_Mesh_API_Gateway_Attacks.md ← サービスメッシュとAPIゲートウェイ攻撃
├── 05_kubernetes_rbac_audit.md ← Kubernetes RBAC監査 — 権限分析、過剰権限検出
└── 06_container_ctf_lab.md    ← コンテナ＆Kubernetesセキュリティ CTF実践ラボ
```

**主要内容:** Docker/Kubernetes攻撃・防御戦略、RBAC権限昇格、コンテナ脱出技法、Trivy/Falcoベースランタイムセキュリティ

---

## 30. 脆弱性研究

```
30_Vulnerability_Research/
├── 01_fuzzing_techniques.md            ← AFL++/libFuzzer/Boofuzz、カバレッジガイドファジング、ネットワークファジング
├── 02_vulnerability_analysis.md        ← CVSS分析、CWE分類、静的/動的分析、ソースコード監査
├── 03_exploit_development_advanced.md  ← 高度なヒープエクスプロイト、ブラウザエクスプロイト、カーネル脆弱性開発
├── 04_CVE_Writeup_Methodology.md       ← CVE脆弱性分析とPoC作成方法論
├── 05_responsible_disclosure.md        ← 責任ある脆弱性開示 — CVE申請、調整
└── 06_vuln_research_ctf_lab.md         ← 脆弱性研究 CTF実践ラボ
```

**主要内容:** AFL++/libFuzzerベース自動脆弱性発見、体系的CVSS/CWE分析、高度なヒープ/ブラウザ/カーネルエクスプロイト開発

---

## 31. AI/ML システムセキュリティ

```
31_AI_ML_Security/
├── 01_adversarial_examples.md         ← FGSM/PGD/C&W、転移攻撃、adversarial training・randomized smoothing防御
├── 02_prompt_injection_jailbreak.md   ← 直接・間接プロンプトインジェクション、脱獄、garak/PyRIT自動レッドチーム
├── 03_model_extraction_inversion.md   ← モデル抽出、メンバーシップ推論(LiRA)、学習データ再構成、DP-SGD防御
├── 04_llm_agent_security.md           ← ツール呼び出しSSRF/RCE、RAGインデックス汚染、MCPセキュリティ、ダブルLLMアーキテクチャ
├── 05_ai_security_defense.md          ← AI/MLセキュリティ防御 — 敵対的ロバスト性、モデル監視、OWASP ML Top 10
└── 06_ai_ml_ctf_lab.md                ← AI/MLセキュリティ CTF実践ラボ
```

セクション11が「AIを攻撃ツールとして使用する」視点であるのに対し、セクション31は**AI/MLシステム自体が標的**となる攻撃と防御を扱います。OWASP LLM Top 10・NIST AI 100-2・MITRE ATLASに基づき、再現可能なPyTorch/Anthropic SDK PoCを収録。

---

## 32. ネットワーク機器ハッキング

```
32_Network_Device_Hacking/
├── 01_ios_fundamentals_and_recon.md      ← Cisco IOS/IOS XE構造、機器フィンガープリンティング、管理プロトコル偵察
├── 02_layer2_attacks.md                  ← VLANホッピング、STP/DHCP攻撃、CAMオーバーフロー、DAIバイパス
├── 03_routing_protocol_attacks.md        ← OSPF/EIGRP/BGP経路注入、HSRP/VRRPハイジャッキング
├── 04_management_plane_exploitation.md   ← SNMP/TACACS+/NETCONF侵害、設定ファイル抽出、バックドア識別
├── 05_network_device_hardening.md        ← ネットワーク機器ハードニング — Cisco/Juniperセキュリティ設定
└── 06_network_device_ctf_lab.md          ← ネットワーク機器ハッキング CTF実践ラボ
```

セクション02がトラフィックスニッフィング・MITM視点、セクション24がDNS・メール・SSHサービス視点であるのに対し、セクション32は**ルータ・スイッチの管理/制御/データプレーン自体**を攻撃します。2025–2026年 Cisco CVE PoC（CVE-2025-20188等）とGNS3/EVE-NGラボトポロジを収録。

---

## 33. OSINT & ソーシャルエンジニアリング

```
33_OSINT_Social_Engineering/
├── 01_osint_methodology_and_search.md  ← 情報収集方法論、Shodan/Censys/FOFA、高度なドーキング
├── 02_target_profiling.md              ← 人物・組織プロファイリング、SNS分析、メール検証、ドメイン偵察
├── 03_social_engineering_attacks.md    ← フィッシング・スピアフィッシング・ビッシング・スミッシング、BEC、プリテキスティング
├── 04_phishing_infra_and_evasion.md    ← GoPhish/Evilginx2インフラ、URLバイパス、アンチフィッシング検出回避
├── 05_osint_defense_and_counter_intelligence.md ← OSINT防御とカウンターインテリジェンス — デジタルフットプリント削減
└── 06_osint_ctf_lab.md                 ← OSINT＆ソーシャルエンジニアリング CTF実践ラボ
```

OSINTを単純な情報検索ではなく、**攻撃チェーンの偵察フェーズ**として活用する方法論に焦点を当てます。Shodan/FOFA/Censysクエリ自動化、LinkedIn/GitHub/SNSベースのターゲットプロファイリング、GoPhish/Evilginx2フィッシングインフラ構築まで、レッドチーム実戦視点で解説します。

---

## 34. ハードウェアハッキング

```
34_Hardware_Hacking/
├── 01_hardware_recon_and_interfaces.md    ← UART/JTAG/SPI/I²Cインターフェース識別・ダンプ、ピンアウト分析
├── 02_firmware_analysis.md                ← binwalk抽出、ファイルシステム分析、ハードコード秘密、脆弱関数検出
├── 03_side_channel_and_fault_injection.md ← 電力分析(SPA/DPA)、タイミング攻撃、グリッチング、ChipWhisperer
├── 04_hardware_security_assessment.md     ← ハードウェアセキュリティ評価 — デバイス監査、物理セキュリティ
├── 05_hardware_security_defense.md        ← ハードウェアセキュリティ防御 — セキュアブート、TPM、物理セキュリティ、耐タンパー
└── 06_hardware_ctf_lab.md                 ← ハードウェアハッキング CTF実践ラボ
```

電子機器の物理的攻撃面を扱います。UARTシリアルコンソールでrootシェル取得、JTAGでファームウェア全体ダンプ、サイドチャネル分析で暗号鍵抽出まで — IoT・組み込み・ハードウェアセキュリティ研究のコア技術を実践ツール（minicom、OpenOCD、binwalk、ChipWhisperer）とともに解説。

---

## 35. サプライチェーン攻撃

```
35_Supply_Chain_Attacks/
├── 01_software_supply_chain.md   ← オープンソースパッケージ汚染、タイポスクワッティング、依存関係混乱攻撃
├── 02_build_and_ci_poisoning.md  ← CI/CDパイプライン侵害、GitHub Actions悪用、SolarWinds・XZ Utilsパターン分析
├── 03_Dependency_Confusion_and_Typosquatting.md ← 依存関係混乱攻撃とタイポスクワッティング
├── 04_Open_Source_Backdoor_Techniques.md ← オープンソースバックドア挿入技法
├── 05_supply_chain_defense.md    ← サプライチェーンセキュリティ防御 — SBOM、依存関係スキャン、ベンダーリスク
└── 06_supply_chain_ctf_lab.md    ← サプライチェーン攻撃 CTF実践ラボ
```

SolarWinds・XZ Utils・3CXなどの実際のサプライチェーン侵害事例を解剖します。PyPI/npm/Mavenパッケージ汚染、GitHub Actionsワークフロー権限奪取、ビルドシステムへのバックドア挿入まで — ソフトウェア開発パイプライン全体が攻撃面であることを実証します。

---

## 36. 自動車ハッキング

```
36_Automotive_Hacking/
├── 01_can_bus_analysis.md           ← CANバス構造、OBD-II診断、メッセージスニッフィング・リプレイ
├── 02_ecu_exploitation.md           ← ECUファームウェア分析、UDS診断プロトコル悪用、リマッピング
├── 03_telematics_and_ota_attacks.md ← V2X通信、テレマティクスユニット侵入、OTAアップデート傍受
├── 04_automotive_security_testing.md ← 自動車セキュリティテスト — 侵入テスト、ファジング、認証テスト
├── 05_automotive_security_defense.md ← 自動車サイバーセキュリティ防御 — ISO/SAE 21434、UNECE WP.29、セキュアOTA
└── 06_automotive_ctf_lab.md         ← 自動車ハッキング CTFラボ
```

現代の自動車は100以上のECUと数十の通信プロトコルが絡み合う走る計算機です。CANバススニッフィングからUDS診断プロトコル悪用、テレマティクスリモート攻撃、Jeep Cherokee・Tesla実際のハッキング再現まで — python-can・Scapy・CANalyzer視点で自動車セキュリティ研究の全スタックを解説。

---

## 37. ICS/SCADA セキュリティ

```
37_ICS_SCADA/
├── 01_ics_protocols_and_recon.md  ← Modbus/DNP3/IEC 61850/EtherNet/IP詳解、Shodan偵察、マルチプロトコルスキャナ
├── 02_scada_exploitation.md       ← HMI/Historian/PLC脆弱性、TRITON・INDUSTROYER分析、SCADAスキャナ
├── 03_ot_network_attacks.md       ← Purdueモデル層別攻撃、IT→OT横断移動、無線OT、OTトポロジマッパー
├── 04_ics_security_architecture.md ← 04 — ICSセキュリティアーキテクチャと防御戦略
├── 05_ics_security_defense.md     ← ICS/SCADAセキュリティ防御 — IEC 62443、ネットワーク分離、OT監視
└── 06_ics_ctf_lab.md              ← ICS/SCADA CTFラボ
```

発電所・製油所・水処理・鉄道などの重要インフラを制御するICS/OT環境を分析します。Stuxnet・TRITON・INDUSTROYER・PIPEDREAMなどの実際のサイバー兵器を解剖し、Modbusコイル強制書き込みからPLC DBブロックパッチ、Historianデータ逆注入、OT専用トポロジ自動マッピングまで — 可用性最優先環境の攻撃と防御を実戦コードとともに解説。

---

## 38. Cloud Nativeセキュリティ

```
38_Cloud_Native_Security/
├── 01_cloud_native_threat_model.md      ← STRIDE脅威モデル、CNAPP、コンテナ・サーバレス・サービスメッシュの脅威
├── 02_ebpf_runtime_security.md          ← Falco/Tetragon/Cilium、eBPFベースランタイム検知・ネットワークポリシー
├── 03_image_hardening_supply_chain.md   ← Trivy/Grypeイメージスキャン、Cosign署名、SBOM、OPA Gatekeeper
├── 04_cloud_native_attack_techniques.md ← コンテナ脱出、サービスメッシュMITM、サーバレスイベント注入、KSPM
├── 05_cloud_native_defense.md           ← 05 — クラウドネイティブセキュリティ防御フレームワーク
└── 06_cloud_native_ctf_lab.md           ← クラウドネイティブセキュリティ CTFラボ
```

Cloud Native環境（Kubernetes・サーバレス・サービスメッシュ）の攻防を解説。eBPFベースのランタイムセキュリティ（Falco/Tetragon）、コンテナイメージ署名・SBOM、OPAポリシーゲートウェイから、実際のコンテナ脱出手法、サービスメッシュMITM、AWS Lambdaイベント注入まで — CNAPPの観点でまとめました。

---

## 39. Zero Trustアーキテクチャ

```
39_Zero_Trust_Architecture/
├── 01_zero_trust_principles.md         ← BeyondCorpモデル、NIST SP 800-207、ZTA成熟度モデル
├── 02_identity_and_device_trust.md     ← IdP/MFA/パスキー、デバイス信頼（MDM/EDR）、SCIMプロビジョニング
├── 03_microsegmentation_and_network.md ← マイクロセグメンテーション、mTLS、SASE/SD-WAN、eBPFネットワークポリシー
├── 04_zero_trust_implementation.md     ← Cloudflare/Zscaler/BeyondCorp実装、ZTA監査自動化
├── 05_zero_trust_maturity.md           ← 05 — ゼロトラスト成熟度評価と運用
└── 06_zero_trust_ctf_lab.md            ← ゼロトラストアーキテクチャ CTFラボ
```

「決して信頼せず、常に検証せよ」 — NIST SP 800-207ベースのZero Trustアーキテクチャを実務視点で解説。BeyondCorpの事例、アイデンティティ/デバイス信頼フレームワーク、マイクロセグメンテーション、SASE導入まで、実践的な実装ガイドとZTA成熟度自己評価ツールを含みます。

---

## 40. 脅威ハンティング

```
40_Threat_Hunting/
├── 01_threat_hunting_methodology.md  ← ハンティングサイクル、仮説ベースハンティング、PEAKフレームワーク
├── 02_mitre_attack_hunting.md        ← ATT&CK戦術別ハンティングシナリオ、グループプロファイル
├── 03_hunting_queries_kql_spl.md     ← Sentinel KQL/Splunk SPLハンティングクエリ100+、異常検知パターン
├── 04_automated_threat_hunting.md    ← SOAR自動化、ML異常検知、ハンティングプレイブック自動化
├── 05_threat_hunting_program.md      ← 05 — 脅威ハンティングプログラム運用
└── 06_threat_hunting_ctf_lab.md      ← 脅威ハンティング CTFラボ
```

ログが語らないものを探し出す能動的脅威ハンティング。PEAKフレームワークによる仮説設定、MITRE ATT&CK戦術別ハンティングシナリオ、Sentinel KQL/Splunk SPLクエリ100+例、SOARベースの自動化プレイブックまで — SOCで即座に適用できる実戦的なハンティング技術を解説。

---

## 41. 韓国セキュリティ資格

```
41_Korean_Certifications/
├── 01_information_security_engineer.md           ← 情報セキュリティ技術士筆記試験 — 5科目完全攻略
├── 02_information_security_engineer_practical.md ← 実技試験傾向、暗号化・ネットワーク・システム実習
├── 03_ISMS_P_certification.md                    ← ISMS-P認証体系、80の管理項目、審査準備
├── 04_international_certifications.md            ← CISSP/CEH/OSCP/CISAロードマップ、ドメイン比較
├── 05_security_laws_and_compliance.md            ← 韓国個人情報保護法・IT安全法令、GDPR比較
└── 06_korean_cert_ctf_lab.md                     ← 韓国情報セキュリティ資格 CTF実践ラボ
```

韓国のセキュリティ資格（情報セキュリティ技術士・ISMS-P）と国際資格（CISSP/CEH/OSCP/CISA）を一か所にまとめました。法令・コンプライアンス（個人情報保護法・GDPR）も含め、韓国のセキュリティ実務者が知るべき制度的基盤を解説します。

---

## 42. ブロックチェーン/Web3セキュリティ

```
42_Blockchain_Web3_Security/
├── 01_blockchain_fundamentals_and_threats.md ← EVMアーキテクチャ、UTXO vs アカウントモデル、51%攻撃、eclipse攻撃
├── 02_smart_contract_auditing.md             ← Reentrancy/overflow/tx.origin/delegatecall、Slither/Mythril/Echidna
├── 03_defi_protocol_attacks.md               ← Flash Loan、オラクル操作、MEVサンドイッチ、Rug Pull検出
├── 04_web3_pentest_tools.md                  ← Foundry（forge/cast/anvil/chisel）、静的解析ツール、RPCセキュリティ
├── 05_web3_incident_response.md              ← Web3インシデント対応
└── 06_blockchain_ctf_lab.md                  ← ブロックチェーン/Web3セキュリティ CTF実践ラボ
```

ブロックチェーン基礎からDeFi攻撃分析・スマートコントラクト監査まで一か所にまとめました。web3.py 6.xとFoundryを使ったハンズオンPoC付き。実際のインシデント（Euler Finance $197Mフラッシュローン）、MEVボットの仕組み、Slither/Mythril脆弱性スキャン、RPCエンドポイントセキュリティ評価を解説。

---

## 43. 物理セキュリティペンテスト

```
43_Physical_Security_Pentesting/
├── 01_physical_pentest_methodology.md          ← PTES物理ドメイン5段階、委任状テンプレート、脆弱性チェックリスト
├── 02_lock_bypass_and_access_control.md        ← ピンタンブラー錠前解除（SPP/レーキング/バンピング）、電子アクセス制御の欠陥
├── 03_rfid_nfc_cloning.md                      ← Proxmark3 LF/HF、MIFARE Classicネスト攻撃、nfcpy NFC分析
├── 04_physical_recon_and_social_engineering.md ← パッシブ偵察、テールゲーティング、プリテキスティング、チャルディーニの6原則
├── 05_physical_security_assessment.md          ← 物理セキュリティ評価
└── 06_physical_ctf_lab.md                      ← 物理セキュリティ侵入テスト CTF実践ラボ
```

方法論から実行まで、物理ペネトレーションテストを完全解説。錠前解除、RFID/NFCクローン（Proxmark3）、チャルディーニの影響原則を用いたソーシャルエンジニアリングをカバー。アクセス制御ログ異常検出と物理ペンテストレポート生成のPython CLIを収録。

---

## 44. インシデントレスポンス/DFIR

```
44_Incident_Response_DFIR/
├── 01_ir_methodology_and_playbooks.md       ← NIST SP 800-61r2、PICERL、ランサムウェア/フィッシングプレイブック
├── 02_memory_and_disk_forensics.md          ← Volatility3、MFT分析、MACBタイムスタンプ、Plasoタイムライン
├── 03_network_forensics_and_log_analysis.md ← 100+ tsharkフィルタ、Zeekログ、Windows Event ID、Sysmon、PCAP C2 IOC
├── 04_threat_containment_and_eradication.md ← ネットワーク隔離、永続化アーティファクト収集、5-Why分析
├── 05_malware_triage_and_containment.md     ← マルウェアトリアージと封じ込め
└── 06_ir_dfir_ctf_lab.md                    ← インシデント対応/DFIR CTF実践ラボ
```

検出→分析→封じ込め→根絶→復旧の完全DFIRワークフロー。不審プロセス検出（ホワイトリスト比較・名前なりすまし）、PCAPベースC2 IOC抽出（ビーコニング/DNSトンネリング）、Windowsパーシスタンスアーティファクト収集のPython CLIを収録。

---

## 45. マルウェア開発

```
45_Malware_Development/
├── 01_malware_fundamentals_and_pe_structure.md ← PEファイルレイアウト、IAT、シャノンエントロピー、不審API分類
├── 02_shellcode_and_injection_techniques.md    ← PICシェルコード、XORエンコード、CreateRemoteThread/APC/プロセスホローイング
├── 03_c2_framework_development.md              ← C2アーキテクチャ、HTTP C2サーバ+エージェント、DNSトンネリング、商用C2比較
├── 04_av_edr_evasion.md                        ← 直接システムコール、NTDLLアンフッキング、ETW/AMSIパッチ、サンドボックス検出
├── 05_detection_resistant_techniques.md        ← 検知回避技法分析（防御者視点）
└── 06_malware_dev_ctf_lab.md                   ← マルウェア開発/分析 CTF実践ラボ
```

レッドチームとマルウェアアナリスト向けのマルウェア開発と防御回避。PEファイル解析（エントロピー/API分類）、シェルコードXORエンコード/逆アセンブリ、文字列難読化、サンドボックス検出のPython CLIを収録。直接syscall（NASMスタブ）、NTDLLアンフッキング、ETWパッチ、AMSIバイパスの概念を解説。

---

## 46. CTF技法

```
46_CTF_Techniques/
├── 01_ctf_methodology_and_tools.md        ← CTF種別、ツールエコシステム、Docker Pwnbox Dockerfile、プラットフォームガイド
├── 02_pwn_and_rev_ctf.md                  ← 完全pwntoolsテンプレート（ret2win/ret2libc/フォーマット文字列/ヒープ）、angrクラックミー
├── 03_web_and_crypto_ctf.md               ← ブラインドSQLi自動化、SSTI攻撃、JWT攻撃、RSA/AES/ハッシュ拡張攻撃
├── 04_ctf_automation_and_frameworks.md    ← DynELF、GDB tmux分割、angr自動化、Frida Android、フォレンジクスパイプライン
├── 05_ctf_writeup_methodology.md          ← CTF Writeup方法論
└── 06_advanced_ctf_practical_lab.md       ← 上級CTF実践ラボ — Pwn · Crypto · Forensics · Misc総合
```

CTF方法論から自動化まで完全網羅。全バイナリチャレンジタイプのpwntoolsテンプレート、angrシンボリック実行、Fridaダイナミックインストゥルメンテーション、フォレンジクス自動化パイプラインを収録。CTFdクライアントによるチャレンジ管理とフラグ提出機能付き。

---

## 47. モバイルフォレンジクス

```
47_Mobile_Forensics/
├── 01_android_forensics.md          ← Androidファイルシステム・ADBフォレンジクス・SQLiteアーティファクト・バックアップCLI
├── 02_ios_forensics.md              ← iOS APFS構造・iTunesバックアップ解析・iMessage/Health抽出CLI
├── 03_mobile_evidence_extraction.md ← 論理/ファイルシステム/物理抽出・ハッシュ検証・証拠収集CLI
├── 04_mobile_forensics_tools.md     ← Autopsy・MVT・Frida・jadx・APK自動解析CLI
├── 05_mobile_malware_analysis.md    ← モバイルマルウェア分析
└── 06_mobile_forensics_ctf_lab.md   ← モバイルフォレンジック CTF実践ラボ
```

Android/iOSモバイルフォレンジクスの全工程。ADBアーティファクト抽出、iTunesバックアップ復号/解析、MVTによるPegasusスパイウェア検出、APKリバースエンジニアリングまで。

---

## 48. 脅威モデリング

```
48_Threat_Modeling/
├── 01_stride_methodology.md         ← STRIDE 6カテゴリ・DFD作成・信頼境界・自動分析CLI
├── 02_pasta_dread_attack_trees.md   ← PASTA 7段階・DREADスコア・Attack Tree・Kill Chain・ATT&CK
├── 03_threat_modeling_tools.md      ← MS TMT・Threat Dragon・IriusRisk・CI/CD統合・XML→HTML CLI
├── 04_threat_modeling_practice.md   ← EC/モバイルバンキング/K8s実践シナリオ・完全ワークフローCLI
├── 05_ai_system_threat_modeling.md  ← AIシステム脅威モデリング
└── 06_threat_modeling_ctf_lab.md    ← 脅威モデリング CTF実践ラボ
```

STRIDE・PASTA・DREADを実践に適用。DFD作成から脅威識別、緩和策導出、CI/CDパイプライン統合まで。

---

## 49. レッドチームインフラ

```
49_Red_Team_Infrastructure/
├── 01_c2_frameworks.md               ← Cobalt Strike/Sliver/Havoc構造・HTTP C2実装・検出ルール
├── 02_domain_fronting_redirectors.md ← CDNフロンティング・Apache/Nginxリダイレクター・DNSトンネリングCLI
├── 03_opsec_infrastructure.md        ← OPSEC 5段階・Long/Short Haul C2・CT ログ・OPSEC監査CLI
├── 04_red_team_automation.md         ← Ansible/Terraform・ペイロードパイプライン・キャンペーン管理CLI
├── 05_red_team_detection_evasion.md  ← レッドチームインフラ検知回避（防御者視点）
└── 06_red_team_infra_ctf_lab.md      ← レッドチームインフラ CTF実践ラボ
```

レッドチームC2インフラとOPSEC。Sliver/Havocフレームワーク、Apacheリダイレクター、DNSTunneling、Terraform AWS自動化まで — 許可されたレッドチーム・CTF・セキュリティ研究目的。

---

## 50. ゲームハッキング

```
50_Game_Hacking/
├── 01_memory_manipulation.md        ← ゲームメモリ・ReadProcessMemory・AOBスキャン・ポインタチェーンCLI
├── 02_cheat_engine_advanced.md      ← CE Luaスクリプト・自動アセンブラ・構造体解析・CTファイルパーサCLI
├── 03_packet_manipulation.md        ← ゲームパケットキャプチャ・mitmproxy・protobuf逆解析・リプレイCLI
├── 04_anti_cheat_analysis.md        ← VAC/EAC/BattlEye内部構造・検出技法・プロセス解析CLI・CTF対策
├── 05_game_server_exploitation.md   ← ゲームサーバー脆弱性研究
└── 06_game_ctf_lab.md               ← ゲームハッキング CTF実践ラボ
```

ゲームセキュリティ研究とCTFゲームハッキング。Cheat Engineメモリ操作、パケットMITM分析、アンチチート内部構造理解まで — 教育・CTF・セキュリティ研究目的。

---

## 51. ブラウザ拡張機能セキュリティ

```
51_Browser_Extension_Security/
├── 01_extension_architecture.md       ← MV2/V3比較・Background/Content Script・CSP・攻撃面分析
├── 02_malicious_extension_analysis.md ← 悪意ある拡張機能・IOC・難読化解析・CRX自動解析CLI
├── 03_extension_pentesting.md         ← Content Script XSS・クロス拡張攻撃・Selenium自動スキャンCLI
├── 04_extension_security_hardening.md ← MV3セキュリティ強化・最小権限・企業GPO・リスク評価CLI
├── 05_extension_malware_campaigns.md  ← ブラウザ拡張マルウェアキャンペーン分析
└── 06_browser_extension_ctf_lab.md    ← ブラウザ拡張セキュリティ CTF実践ラボ
```

ブラウザ拡張機能セキュリティの全範囲。悪意ある拡張機能IOC検出、CRX自動解析、Content Script XSS攻撃、Seleniumダイナミック脆弱性スキャナ、企業ポリシー管理まで。

---

## 52. APIセキュリティ

```
52_API_Security/
├── 01_rest_api_security.md               ← OWASP API Top 10・BOLAスキャナ・JWT脆弱性分析
├── 02_graphql_security.md                ← イントロスペクション・バッチクエリ・深さ攻撃・スキーマ自動分析
├── 03_api_fuzzing.md                     ← ffuf・OpenAPIベース自動ファザー・パラメータ汚染・応答分析
├── 04_api_security_hardening.md          ← OAuth2 PKCE・Rate Limiting・Kong/NGINXゲートウェイ
├── 05_api_security_testing_automation.md ← APIセキュリティテスト自動化パイプライン
└── 06_api_ctf_lab.md                     ← CTF: API脆弱性実習ラボ
```

REST・GraphQL API脆弱性の全範囲。BOLA自動スキャナ、JWT偽造・クラッキング、OAuth2 PKCE実装、APIゲートウェイセキュリティ。

---

## 53. サーバーレスセキュリティ

```
53_Serverless_Security/
├── 01_lambda_function_attacks.md      ← 環境変数窃取・IMDSv1 SSRF・イベントインジェクション
├── 02_serverless_injection.md         ← SQS/S3イベントインジェクション・タイポスクワッティング・静的分析
├── 03_serverless_iam_abuse.md         ← ロール過剰権限・AssumeRoleチェーン・最小権限ポリシー自動生成
├── 04_serverless_hardening.md         ← IaCセキュリティスキャン・Terraform設定・Lambda Extension
├── 05_serverless_incident_response.md ← サーバーレスインシデント対応・CloudTrail分析・自動隔離
└── 06_serverless_ctf_lab.md           ← CTF: Lambda環境変数・イベントインジェクション・IAM乱用実習
```

AWS Lambdaサーバーレス環境の攻撃・防御。IMDSv1 SSRF、イベントソースインジェクション、IAMロール乱用、IaC（Checkov/cfn-guard）スキャン。

---

## 54. Active Directory攻撃

```
54_Active_Directory_Attacks/
├── 01_ad_enumeration.md            ← BloodHound・LDAP列挙・SPN/AS-REPアカウント自動列挙
├── 02_kerberos_attacks.md          ← Kerberoasting・AS-REP Roasting・Pass-the-Ticket
├── 03_lateral_movement_ad.md       ← PtH・NTLMリレー・DCSync・マルチホスト横断移動
├── 04_ad_persistence.md            ← Golden Ticket・Shadow Credentials・ACL乱用・永続化検知
├── 05_ad_defense_and_detection.md  ← ADイベント監視・ハニーポットアカウント・強化チェックリスト
└── 06_ad_ctf_lab.md                ← CTF: Kerberoasting・攻撃経路分析・DCSync実習
```

Active Directory攻撃チェーンの全範囲。BloodHound収集とCypherクエリ、Kerberoasting/AS-REP Roasting自動化、NTLMリレー・DCSync、Golden/Silver Ticket、AdminSDHolder・Shadow Credentials永続化。

---

## 55. 検知回避技法

```
55_Evasion_Techniques/
├── 01_av_evasion.md                    ← XORエンコーダ・サンドボックス検知・プロセスインジェクション・AMSI回避
├── 02_ids_ips_evasion.md               ← パケット断片化・DNSトンネリング・トラフィック偽装・Snortルール分析
├── 03_edr_bypass.md                    ← 直接syscall・NTDLLフッキング検知・メモリインジェクション検知
├── 04_log_evasion.md                   ← イベントログ操作・タイムスタンプ偽造・痕跡削除自動化
├── 05_evasion_detection_and_hunting.md ← 回避技法の脅威ハンティング・検知ルール・挙動分析
└── 06_evasion_ctf_lab.md               ← CTF: エンコーディング回避・ログ操作検知実習
```

AV/EDR/IDS回避技法の全範囲。XOR/AESペイロードエンコーダ、直接・間接syscall、NTDLLフッキング検知、DNS/ICMPトンネリング、C2トラフィック偽装、痕跡削除チェックリスト。

---

## 56. AIレッドチーム

```
56_AI_Red_Teaming/
├── 01_ai_attack_fundamentals.md    ← AI攻撃の基礎、攻撃対象領域、脅威モデリング
├── 02_prompt_injection.md          ← 直接・間接・マルチモーダルインジェクション、脱獄技法
├── 03_model_extraction.md          ← モデル抽出・メンバーシップ推論、クエリベース攻撃
├── 04_adversarial_examples.md      ← FGSM/PGD、転移攻撃、防御技法
├── 05_ai_red_team_defense.md       ← モデル強化、入力検証、AIセキュリティアーキテクチャ
└── 06_ai_red_team_ctf_lab.md       ← CTF: プロンプトインジェクション・モデル抽出実習
```

AIシステムレッドチーム方法論、プロンプトインジェクション自動化、モデル抽出攻撃、防御技法。

---

## 57. 量子暗号

```
57_Quantum_Cryptography/
├── 01_quantum_computing_basics.md  ← 量子コンピューティング、Grover/Shorアルゴリズム、暗号への影響
├── 02_quantum_key_distribution.md  ← QKDプロトコル（BB84/E91）、量子チャネル攻撃
├── 03_post_quantum_algorithms.md   ← CRYSTALS-Kyber/Dilithium、SPHINCS+、実装ガイド
├── 04_nist_pqc_standards.md        ← NIST PQC標準化プロセス、FIPS 203/204/205
├── 05_pqc_migration_strategy.md    ← ハイブリッド暗号化、暗号資産インベントリ、移行戦略
└── 06_quantum_crypto_ctf_lab.md    ← CTF: 量子暗号原理・PQC実習
```

量子コンピューティングがRSA/ECCに与える影響、NIST PQC標準アルゴリズム、ポスト量子暗号への移行戦略。

---

## 58. クラウドインシデント対応

```
58_Cloud_IR/
├── 01_cloud_ir_fundamentals.md     ← Cloud IRフレームワーク、AWS/Azure/GCP侵害指標
├── 02_aws_forensics.md             ← CloudTrail分析、S3/EC2フォレンジック、GuardDuty連携
├── 03_azure_forensics.md           ← Azure Sentinel調査、Activity Log分析
├── 04_gcp_forensics.md             ← GCP Chronicle、Audit Logフォレンジック
├── 05_cloud_threat_hunting.md      ← クラウド脅威ハンティング、異常検知、KQLクエリ
└── 06_cloud_ir_ctf_lab.md          ← CTF: CloudTrail分析・侵害シナリオ実習
```

Cloud IRの全プロセス。CloudTrail/Activity Log分析、クラウド環境フォレンジック、脅威ハンティング自動化。

---

## 59. サプライチェーンセキュリティ

```
59_Supply_Chain_Security/
├── 01_supply_chain_fundamentals.md     ← サプライチェーン攻撃の類型、侵害指標、脅威モデル
├── 02_software_supply_chain_attacks.md ← SolarWinds・Codecov等の実例分析、検知戦略
├── 03_dependency_confusion.md          ← 依存関係混乱攻撃、タイポスクワッティング、防御
├── 04_build_integrity.md               ← ビルド完全性検証、署名、SLSAフレームワーク
├── 05_supply_chain_defense.md          ← SBOM管理、ベンダーリスク管理、防御戦略
└── 06_supply_chain_ctf_lab.md          ← CTF: 依存関係混乱・SBOM分析実習
```

ソフトウェアサプライチェーン全体のセキュリティ。SBOM、依存関係混乱攻撃、SLSAフレームワーク、ベンダーリスク管理。

---

## 60. ブラウザセキュリティ上級

```
60_Browser_Security/
├── 01_browser_attack_surface.md         ← ブラウザ攻撃対象領域、脆弱性類型、防御モデル
├── 02_javascript_engine_exploitation.md ← V8/SpiderMonkey脆弱性、JITコンパイラバグ
├── 03_sandbox_escape.md                 ← サンドボックス脱出技法、プロセス分離バイパス
├── 04_browser_extension_advanced.md     ← 悪意ある拡張機能分析、MV3セキュリティモデル
├── 05_browser_security_hardening.md     ← ブラウザセキュリティ設定、エンタープライズポリシー
└── 06_browser_security_ctf_lab.md       ← ブラウザセキュリティCTF実習ラボ
```

JSエンジン脆弱性（V8/SpiderMonkey）、サンドボックス脱出、ブラウザプロセスモデル、Chrome/Firefoxバグパターン。

---

## 61. ファームウェアハッキング

```
61_Firmware_Hacking/
├── 01_firmware_fundamentals.md     ← ファームウェアの類型、抽出方法、分析環境構築
├── 02_firmware_extraction.md       ← JTAG/UART/SPIダンプ、binwalk抽出、ファイルシステムマウント
├── 03_firmware_analysis.md         ← Ghidraリバースエンジニアリング、脆弱関数検出、ハードコード秘密情報
├── 04_firmware_emulation.md        ← QEMUエミュレーション、firmwalker、動的分析
├── 05_firmware_exploitation.md     ← バッファオーバーフロー、コマンドインジェクション、Webインターフェース攻撃
└── 06_firmware_ctf_lab.md          ← CTF: ファームウェア抽出・分析・エクスプロイト実習
```

ファームウェア分析の全プロセス。ハードウェアダンプからGhidraリバースエンジニアリング、QEMUエミュレーション、脆弱性エクスプロイトまで。

---

## 62. 自動車セキュリティ

```
62_Automotive_Security/
├── 01_automotive_security_fundamentals.md ← 自動車ネットワークアーキテクチャ、CAN/LIN/FlexRay
├── 02_can_bus_hacking.md                  ← CANバススニッフィング、メッセージ再送、ファジング自動化
├── 03_ecu_analysis.md                     ← ECUファームウェア抽出、UDS診断、パラメータ操作
├── 04_v2x_security.md                     ← V2X通信セキュリティ、DSRC/C-V2X脆弱性
├── 05_automotive_penetration_testing.md   ← 自動車ペネトレーションテスト方法論、レポート作成
└── 06_automotive_ctf_lab.md               ← CTF: CANバス・UDS・ECU実習
```

CANバススニッフィング・操作、ECUファームウェア分析、UDS診断プロトコル悪用、V2X/OTA攻撃。python-can・Scapy・CANalyzer実践。

---

## 63. OT/ICS上級

```
63_OT_ICS_Advanced/
├── 01_ot_ics_fundamentals.md       ← OT/ICSアーキテクチャ、Purdueモデル、主要プロトコル
├── 02_scada_attacks.md             ← HMI攻撃、SCADAサーバー脆弱性、実例分析
├── 03_plc_exploitation.md          ← PLCプログラミング脆弱性、ラダーロジック操作、エクスプロイト
├── 04_industrial_protocols.md      ← Modbus/DNP3/IEC 104プロトコル攻撃、トラフィック分析
├── 05_ot_defense_and_monitoring.md ← OTセキュリティアーキテクチャ、ネットワーク分離、異常検知
└── 06_ot_ics_ctf_lab.md            ← CTF: Modbus・PLC・SCADA実習
```

Stuxnet・TRITON・INDUSTROYER・PIPEDREAMといった実際のサイバー兵器の解剖。Modbus強制書き込み、PLC操作、OT専用防御アーキテクチャ。

---

## 64. 脅威インテリジェンスプラットフォーム

```
64_Threat_Intel_Platform/
├── 01_tip_fundamentals.md            ← TIPアーキテクチャ、データモデル（STIX 2.1）、プラットフォーム比較
├── 02_misp_platform.md               ← MISP構築・運用、イベント管理、API自動化
├── 03_threat_feeds_and_enrichment.md ← 脅威フィード収集・品質評価・IoCエンリッチメント
├── 04_ioc_management.md              ← IOCライフサイクル、ノイズ削減、TAXII連携
├── 05_tip_automation.md              ← SOAR連携、自動対応、脅威フィードオーケストレーション
└── 06_tip_ctf_lab.md                 ← CTF: MISPイベント・IOC分析実習
```

TIPプラットフォーム（MISP/OpenCTI）の構築・運用、脅威フィード自動化、IOC管理、SOAR連携自動対応。

---

## 65. リバースエンジニアリング上級

```
65_Reverse_Engineering_Advanced/
├── 01_anti_debugging_techniques.md    ← IsDebuggerPresent・タイミング・例外ベース検知、GDB/x64dbg回避
├── 02_obfuscation_and_unpacking.md    ← UPX/Themidaアンパッキング、コード難読化、バイナリ正規化
├── 03_symbolic_execution.md           ← angrシンボリック実行、経路探索、条件分岐バイパス自動化
├── 04_advanced_binary_analysis.md     ← CFG再構成、脆弱関数検出、Ghidraスクリプティング
├── 05_firmware_reverse_engineering.md ← ファームウェアリバースエンジニアリング、binwalk、QEMU
└── 06_re_ctf_lab.md                   ← CTF: アンチデバッグ回避・アンパッキング・シンボリック実行
```

アンチデバッグ検知・回避、UPX/Themidaアンパッキング、angrシンボリック実行、CFG分析。pwntools・angr実践CTF 4チャレンジ収録。

---

## 66. エクスプロイト開発

```
66_Exploit_Development/
├── 01_rop_chain_techniques.md       ← ROPガジェット収集・チェーン構成、NXバイパス、ASLRブルートフォース
├── 02_heap_exploitation.md          ← glibc ptmalloc2、ヒープオーバーフロー、UAF、House-of-Force
├── 03_kernel_exploitation.md        ← カーネルBOF、ret2usr、SMEP/KPTIバイパス、LPE
├── 04_browser_exploitation.md       ← V8 JITバグ、OOB R/W、レンダラー→ブラウザ脱出
├── 05_exploit_mitigation_bypass.md  ← カナリア・ASLR・NX・PIE同時バイパス、FSOP
└── 06_exploit_ctf_lab.md            ← CTF: スタックBOF・ROPチェーン・ヒープUAF・同時バイパス
```

ROPチェーン構成、ヒープエクスプロイト（ptmalloc2）、カーネルLPE、ブラウザV8バグ。pwntools実践CTF 4チャレンジ収録。

---

## 67. マルウェア開発の理解

```
67_Malware_Development_Advanced/
├── 01_malware_architecture.md       ← マルウェア構造、ドロッパー・ペイロード・C2アーキテクチャ
├── 02_shellcode_development.md      ← 位置独立シェルコード、エンコーディング、ステージング
├── 03_c2_framework_design.md        ← C2通信チャネル、ビーコン間隔、HTTPS/DNSトンネリング
├── 04_persistence_mechanisms.md     ← レジストリ・サービス・スケジューラ・WMI永続化
├── 05_evasion_and_detection.md      ← AMSI回避、ETWパッチ、メモリインジェクション、挙動検知
└── 06_maldev_ctf_lab.md             ← CTF: XOR復号・レジストリ検知・C2分析・メモリフォレンジック
```

C2アーキテクチャ・ビーコン、シェルコード開発、永続化4技法、AMSI/ETW回避。VolatilityメモリフォレンジックCTF 4チャレンジ収録。

---

## 68. パープルチーム運用

```
68_Purple_Team/
├── 01_purple_team_fundamentals.md   ← パープルチーム方法論、レッド・ブルー協業フレームワーク
├── 02_attack_simulation.md          ← Atomic Red Team、CALDERA、攻撃シミュレーション自動化
├── 03_detection_engineering.md      ← Sigmaルール作成、SIEM連携、検知カバレッジ測定
├── 04_threat_emulation.md           ← APTエミュレーション、TTP再現、MITRE ATT&CKマッピング
├── 05_purple_team_reporting.md      ← ギャップ分析、検知率レポート、改善ロードマップ
└── 06_purple_ctf_lab.md             ← CTF: ATT&CKマッピング・Sigmaルール・検知率測定
```

レッド・ブルーチーム協業、Atomic Red Team・CALDERAシミュレーション、Sigmaルール作成、検知カバレッジ測定。ATT&CKベースCTF 4チャレンジ収録。

---

## 69. LLMセキュリティ

```
69_LLM_Security/
├── 01_llm_security_fundamentals.md      ← LLM攻撃対象領域、OWASP LLM Top 10、脅威モデル
├── 02_prompt_injection.md               ← 直接・間接インジェクション、脱獄、マルチモーダル攻撃
├── 03_model_extraction_and_inversion.md ← モデル抽出、訓練データ逆推論、メンバーシップ推論
├── 04_adversarial_attacks_on_llm.md     ← 敵対的サフィックス、転移攻撃、入力操作
├── 05_llm_security_defense.md           ← ガードレール、出力検証、安全なLLMアーキテクチャ
└── 06_llm_security_ctf_lab.md           ← CTF: 基本インジェクション・Base64回避・トークンスマグリング
```

OWASP LLM Top 10、プロンプトインジェクション・脱獄、モデル抽出、敵対的攻撃、LLMセキュリティアーキテクチャ。4チャレンジCTF収録。

---

## 70. Kubernetesセキュリティ

```
70_Kubernetes_Security/
├── 01_k8s_attack_surface.md         ← K8sアーキテクチャ・攻撃対象領域、minikube実習環境、kube-bench
├── 02_rbac_exploitation.md          ← RBAC設定ミス悪用、ワイルドカード権限、ClusterRole監査
├── 03_pod_escape.md                 ← privileged Pod脱出、hostPath悪用、サービスアカウント窃取
├── 04_network_attacks.md            ← ネットワークポリシー未適用、Pod間スニッフィング、DNSスプーフィング
├── 05_k8s_hardening.md              ← CIS Benchmark、PSS、OPA Gatekeeper、Vaultシークレット
└── 06_k8s_ctf_lab.md                ← CTF: RBAC窃取・Pod脱出・サービスアカウント・etcdアクセス
```

K8s攻撃対象領域からRBAC設定ミス悪用、privileged Pod脱出、etcdシークレットダンプまで。kube-bench CIS監査実践。初心者向けminikube環境構築収録。

---

## 71. Bluetooth/RFハッキング

```
71_Bluetooth_RF_Hacking/
├── 01_bluetooth_fundamentals.md     ← Bluetooth vs BLE、ペアリング・スタック構造、BlueSnarfing
├── 02_ble_attacks.md                ← GATT/GAP、脆弱なCharacteristic書き込み、bleakでのBLE列挙
├── 03_rf_signal_analysis.md         ← SDR概念、RTL-SDRセットアップ、GNU Radio、周波数分析
├── 04_zigbee_attacks.md             ← Zigbeeアーキテクチャ、チャネルスキャン、Zigbee2MQTT監視
├── 05_wireless_defense.md           ← BLE暗号化強化、Zigbee鍵管理、RFシールド方法
└── 06_wireless_ctf_lab.md           ← CTF: BLE GATTフラグ・PINブルートフォース・RFリプレイ
```

Bluetooth/BLE脆弱性分析、RTL-SDR周波数分析、Zigbee IoT攻撃。bleak・paho-mqtt・GNU Radio実践。低価格RTL-SDRハードウェアで入門可能。

---

## 72. マルウェアサンドボックス分析

```
72_Malware_Sandbox_Analysis/
├── 01_sandbox_fundamentals.md       ← サンドボックス概念、静的vs動的分析、VM環境構築
├── 02_online_sandbox_tools.md       ← ANY.RUN・VirusTotal・Joe Sandbox比較、vt-py API
├── 03_static_analysis.md            ← PEヘッダ分析、エントロピー、YARAルール、pefile実践
├── 04_dynamic_analysis.md           ← プロセス監視、FakeNet、Wireshark、psutilスクリプト
├── 05_ioc_extraction.md             ← IOC抽出自動化、MITRE ATT&CKマッピング、STIX/TAXII
└── 06_malware_ctf_lab.md            ← CTF: C2抽出・XOR復号・レジストリ分析・UPXアンパッキング
```

オンラインサンドボックス（ANY.RUN/VirusTotal）活用、PE静的分析、psutil動的監視、IOC自動抽出。完全無料ツールで初心者入門可能。

---

## 73. バグバウンティ自動化

```
73_Bug_Bounty_Automation/
├── 01_bug_bounty_fundamentals.md    ← HackerOne・Bugcrowdエコシステム、責任ある開示、スコープ理解
├── 02_recon_automation.md           ← subfinder・amass・httpx・naabuパイプライン、Python自動化
├── 03_vulnerability_scanning.md     ← Nucleiテンプレート、カスタムルール、FPフィルタリング、Burp連携
├── 04_report_writing.md             ← CVSS v3計算、PoC作成、Markdownレポート自動生成
├── 05_advanced_techniques.md        ← 脆弱性チェイニング、ロジックバグ、APIファジング、OAuth脆弱性
└── 06_bug_bounty_ctf_lab.md         ← CTF: サブドメインテイクオーバー・IDOR検出・Nuclei実習
```

HackerOne/Bugcrowdプラットフォーム活用、ProjectDiscoveryツールチェーン（subfinder/nuclei）自動化、CVSSベースレポート作成。実際のバグバウンティプロセスをエンドツーエンドで実習。

---

## 74. コード監査

```
74_Code_Auditing/
├── 01_code_audit_fundamentals.md    ← STRIDE脅威モデリング、コード監査vsペンテスト、攻撃対象領域分析
├── 02_vulnerability_patterns.md     ← OWASP Top 10コードパターン、脆弱/安全コード比較、言語別危険関数
├── 03_static_analysis_tools.md      ← Semgrepカスタムルール、Bandit、CodeQL + GitHub Actions連携
├── 04_manual_review_techniques.md   ← Source/Sink追跡、ASTベースデータフロー分析、手動レビューチェックリスト
├── 05_sast_cicd_integration.md      ← Pre-commit Hook、CIセキュリティゲート、SARIFパーサー、TP/FPトリアージ
└── 06_code_audit_ctf_lab.md         ← CTF: SQLインジェクション監査・シークレット検出・認証バイパス検出
```

Semgrep/Bandit/CodeQL静的分析、Source→Sinkデータフロー追跡、CI/CDセキュリティゲート構築。脆弱なFlaskアプリ実習環境収録。

---

## 75. レッドチームレポート作成

```
75_Red_Team_Reporting/
├── 01_red_team_fundamentals.md      ← レッド・ブルー・パープルチームの違い、RoE、MITRE ATT&CK概要
├── 02_operation_planning.md         ← キルチェーンベース作戦計画、タイムライン自動生成、チーム役割分担
├── 03_ttps_documentation.md         ← TTP文書化、ATT&CKマッピング自動化、IOCリスト作成
├── 04_report_writing.md             ← 二重読者レポート（経営層/技術チーム）、CVSSリスク評価、自動生成器
├── 05_debrief_lessons.md            ← デブリーフィングプロセス、教訓導出、パープルチーム転換、検知率分析
└── 06_red_team_ctf_lab.md           ← CTF: ATT&CKマッピング・CloudStoreレポート・キルチェーン計画
```

MITRE ATT&CKベースTTP文書化、経営層/技術チーム二重レポート作成、デブリーフィング→パープルチーム転換プロセス。Pythonレポート自動化ツール収録。

---

## CTF実習環境（labs/）

```
labs/
├── 01_web_hacking_lab/      ← SQLi・XSS・SSRF・JWT脆弱Flaskアプリ（Docker）
├── 02_pwn_lab/              ← BOF・フォーマット文字列・ヒープ脆弱バイナリ環境
├── 03_network_lab/          ← パケット分析・MITM・ARPスプーフィングpcap+実習環境
├── 04_cloud_container_lab/  ← 脆弱Docker/K8s環境、コンテナ脱出シナリオ
├── 05_full_scenario_lab/    ← 偵察→侵入→横断移動→権限昇格→流出 統合シナリオ
├── 06_firmware_lab/         ← binwalk抽出・QEMU ARMエミュレーション・ハードコード資格情報CTF
├── 07_mobile_lab/           ← Android APK静的解析・Frida・JWT alg:none バイパスCTF
├── start_lab.sh             ← 全ラボdocker-compose up自動化
└── stop_all.sh              ← 全ラボ停止
```

7つのDockerベースCTF脆弱環境 — Web・バイナリ・ネットワーク・クラウド・統合シナリオ・ファームウェア・モバイルをローカルで即座に実習。フラグ13個、`start_lab.sh` 一発で全環境起動。

---

## 注意事項

> **このリポジトリのすべての技術は、必ず許可された環境でのみ使用してください。**

- CTF、バグバウンティ、契約されたペンテストの範囲内で活用
- 脆弱性発見時は責任ある開示（Responsible Disclosure）の原則に従う
- 不正なシステムアクセスは不正アクセス禁止法をはじめとする関連法規に違反します

---

<div align="center">

**⚔️ VibeHacking** — 実践セキュリティのプロへの旅


</div>
