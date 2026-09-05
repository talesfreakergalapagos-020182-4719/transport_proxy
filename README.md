# tproxy — Cross-Platform Transparent Proxy Gateway

> **Windows・Ubuntu (Linux) 両対応。** OS やアプリの設定を一切変えずに、PC 上の全通信をポリシー制御・監査・中継する多機能プロキシゲートウェイ。

---

## 📑 目次
- [⚡ クイックスタート（最短 3 ステップで起動）](#クイックスタート最短-3-ステップで起動)
  - [Windows の場合](#a-windows-の場合)
  - [Ubuntu (Linux) の場合](#b-ubuntu-linux-の場合)
  - [動作確認](#c-動作確認)
- [🎯 代表的な設定レシピ（ユースケース別）](#代表的な設定レシピユースケース別)
  - [レシピ 1: ホワイトリスト運用（推奨・セキュア環境）](#レシピ-1-ホワイトリスト運用推奨セキュア環境)
  - [レシピ 2: ブラックリスト運用（特定サイトの遮断）](#レシピ-2-ブラックリスト運用特定サイトの遮断)
  - [レシピ 3: 全通し・監査モード（動作確認用）](#レシピ-3-全通し監査モード動作確認用)
  - [レシピ 4: 社内プロキシ・PAC 連携（自動検出 & 手動指定）](#レシピ-4-社内プロキシpac-連携)
  - [レシピ 5: DNS の設定（DoH 暗号化 vs 社内 DNS 直通）](#レシピ-5-dns-の設定doh-暗号化-vs-社内-dns-直通)
  - [レシピ 6: 常時接続維持（RDP・SSH・DB・リモートデスクトップ用）](#レシピ-6-常時接続維持rdpsshdbリモートデスクトップ用)
- [💻 WSL2 での利用](#wsl2-での利用)
- [📖 設定ファイル（config.json）完全リファレンス](#設定ファイルconfigjson完全リファレンス)
- [⚙️ 起動オプション（CLI 引数）](#起動オプションcli-引数)
- [🏛️ アーキテクチャと内部構造（詳細解説）](#アーキテクチャと内部構造詳細解説)
- [📁 ディレクトリ構成](#ディレクトリ構成)
- [🛠️ 動作要件 & セキュリティポリシー](#動作要件--セキュリティポリシー)
  - [動作環境](#動作環境)
  - [Go 言語を採用している理由（なぜ高速なのか）](#-go-言語を採用している理由なぜ高速なのか)
- [🧪 テスト・クロスプラットフォーム検証](#テストクロスプラットフォーム検証)

---

## ⚡ クイックスタート（最短 3 ステップで起動）

`tproxy` は、アプリ側にプロキシ設定（`HTTP_PROXY` 等）を一切行わなくても、OS カーネル層でパケットを透過的に捕捉して制御します。まずはデフォルト設定（全通しモード）で起動してみましょう。

```
【ブラウザ / curl / SSH / Docker など】
       | （プロキシ設定一切不要）
       v
  [ tproxy ]  <-- カーネル層で自動キャプチャ & ポリシー制御
       |
       v
【インターネット / 社内プロキシ】
```

---

### A. Windows の場合

#### 1. 事前準備（初回のみ）
[WinDivert 公式](https://reqrypt.org/windivert.html) または [GitHub Releases](https://github.com/basil00/Divert/releases) から最新 zip をダウンロードし、`x64\` フォルダ内の以下 2 ファイルを本リポジトリ直下に配置します：
* `WinDivert.dll`
* `WinDivert64.sys`

#### 2. ビルド & 起動
**「管理者として実行」した PowerShell** で以下を実行します：

```powershell
# ビルド
go build -ldflags="-s -w" -o tproxy.exe ./cmd/tproxy

# 起動（管理者権限必須）
.\tproxy.exe
```

これだけで、Windows PC 上のすべての通信が透過的に制御されます。

#### 3. 停止
`Ctrl + C` を押すと、WinDivert ドライバが即座に自動アンロードされ、OS の通常通信へ瞬時に復元します。

---

### B. Ubuntu (Linux) の場合

外部ドライバの追加インストールは不要です。Linux 標準の `iptables` を使用します。

#### 1. ビルド & 起動
```bash
# ビルド（Ubuntu 上で実行）
go build -ldflags="-s -w" -o tproxy ./cmd/tproxy

# 起動（sudo 必須）
sudo ./tproxy
```
> ※ Windows から Linux 向けにクロスコンパイルする場合は以下を実行します：  
> `$env:GOOS="linux"; $env:GOARCH="amd64"; go build -ldflags="-s -w" -o tproxy ./cmd/tproxy`

#### 2. 停止
`Ctrl + C` を押すと、追加された `iptables` ルールが全自動でクリーンアップされ、通常通信へ即時復元します。

#### 3. systemd による常駐サービス化（推奨）
常時バックグラウンド実行したい場合は、付属スクリプトを実行するだけで自動起動サービスとして登録できます：
```bash
sudo ./scripts/install-ubuntu.sh
```

---

### C. 動作確認

`tproxy` を起動した状態で別ターミナルから通信を行うと、コンソールにリアルタイムでパケット解析・中継ログが表示されます：

```bash
curl -I https://github.com
```

**ログ出力例:**
```text
[ALLOW] DNS-DoH          | Client: 192.168.1.10:54320 | Target: 1.1.1.2:53           | Query: github.com (A) -> DoH (15ms)
[ALLOW] HTTPS            | Client: 192.168.1.10:54321 | Target: github.com:443        -> DIRECT
[CLOSE] Client: 192.168.1.10:54321 | Target: github.com:443 | Sent: 1.7 KB | Recv: 91.6 KB | Duration: 451ms
```

---

## 🎯 代表的な設定レシピ（ユースケース別）

設定ファイル `config.json` を編集することで、通信ポリシーを柔軟に変更できます。  
**ホットリロード対応**のため、稼働中にファイルを上書き保存するだけで即座に反映されます（再起動不要）。

### レシピ 1: ホワイトリスト運用（推奨・セキュア環境）
許可したドメイン・IP 宛てのみを通過させ、それ以外をすべて 403 / RST で遮断します：

```json
{
  "filter_mode": "whitelist",
  "allowed_domains": [
    "github.com", "*.github.com", "*.githubusercontent.com",
    "*.microsoft.com", "*.windowsupdate.com",
    "google.com", "*.google.com"
  ],
  "allowed_ips": [
    "127.0.0.1", "::1",
    "192.168.0.0/16", "10.0.0.0/8"
  ]
}
```

### レシピ 2: ブラックリスト運用（特定サイトの遮断）
特定の危険サイトや広告ドメインのみ遮断し、他をすべて許可します：

```json
{
  "filter_mode": "blacklist",
  "blocked_domains": ["*.malicious.com", "badsite.example.org"],
  "blocked_ips": ["198.51.100.25", "203.0.113.0/24"]
}
```

### レシピ 3: 全通し・監査モード（動作確認用）
通信を一切遮断せず、すべてのアクセスをログ記録します：

```json
{
  "filter_mode": "all"
}
```

### レシピ 4: 社内プロキシ・PAC 連携

本ソフトは、上位の社内プロキシや PAC（Proxy Auto-Config）スクリプトを経由させた中継に対応しています。

#### パターン A: OS プロキシ設定の完全自動検出（推奨・設定不要）
`config.json` 内で `pac_url` および `upstream_proxy` を空（デフォルト）にしておくだけで、OS のプロキシ設定が自動的に検出されます：
* **Windows の場合**: OS の「インターネット オプション」や「設定 > ネットワークとインターネット > プロキシ」から、**手動プロキシ設定（ホスト:ポート）**、**セットアップ スクリプト（PAC URL）**、および **WPAD 自動検出（DHCP / DNS）** を WinHTTP API で自動取得します。
* **Linux の場合**: OS の標準環境変数（`https_proxy`, `http_proxy`, `all_proxy` 等）からプロキシ URL を自動取得します。

```json
{
  "filter_mode": "all",
  "pac_url": "",
  "upstream_proxy": ""
}
```

#### パターン B: 手動指定（特定プロキシや PAC の強制）
OS 設定とは別に、特定の社内プロキシや PAC スクリプトを明示的に指定する場合：

```json
{
  "filter_mode": "all",
  "pac_url": "http://wpad.corp.local/wpad.dat",
  "upstream_proxy": "http://proxy.corp.local:8080"
}
```

#### 認証と PAC エンジンに関する重要な仕様
* **認証対応**: 
  * **Windows**: プロキシが要求する **Windows 統合認証（SSPI / Negotiate / NTLM / Kerberos）を完全自動解決**。現在 Windows にログオン中のユーザー資格情報（SSO）を利用するため、パスワードの入力や設定ファイルへの保存は一切不要です。
  * **Linux**: URL 内のクレデンシャル（`http://user:pass@proxy:8080`）による **HTTP Basic 認証** に対応（接続開始時に事前送信して往復遅延を削減）。  
    > **⚠️ Linux での注意**: Linux には Windows SSPI API が存在しないため、**NTLM / Kerberos 認証プロキシには非対応**です。社内プロキシが NTLM 必須の環境で Linux (WSL2) を利用したい場合は、後述の [WSL2 での利用](#-wsl2-での利用) を参照し、Windows 側で `tproxy.exe` を動かしてミラーモード経由で利用してください（Windows 資格情報で自動認証されます）。
* **PAC エンジン**: 
  * Windows は OS 標準の **WinHTTP API**（`WinHttpGetProxyForUrl`）を使用。
  * Linux / WSL は内蔵ピュア Go JS エンジン（**goja**）で PAC を自動ダウンロード・評価します。

### レシピ 5: DNS の設定（DoH 暗号化 vs 社内 DNS 直通）

* **A. 一般インターネット（デフォルト）: 自動 DoH 暗号化**
  ```json
  {
    "dns_servers": []
  }
  ```
  平文の UDP 53 クエリを自動捕捉し、**Cloudflare Security DNS (`1.1.1.2`, `1.0.0.2`) による DoH（HTTPS 暗号化）** へ変換して安全に名前解決します（マルウェア・フィッシング自動ブロック）。

* **B. 社内 DNS やクラウド VPC（GCP / AWS 等）: 直通バイパス**
  ```json
  {
    "dns_servers": [
      "10.0.0.2",
      "169.254.169.254"
    ]
  }
  ```
  社内ドメイン（`*.corp`）やクラウド内部メタデータ DNS（`169.254.169.254`）を指定すると、そのサーバー宛ての平文 UDP 53 は直接バイパスされ、社内名前解決が確実に成功します。

### レシピ 6: 常時接続維持（RDP・SSH・DB・リモートデスクトップ用）
```json
{
  "idle_timeout_sec": 0
}
```
`"idle_timeout_sec": 0` を指定すると、無通信タイムアウトを無効化し、OS の TCP Keep-Alive（30 秒間隔）でセッションを常時維持します。大容量ファイル転送や長時間放置した SSH/RDP も切断されません。

---

## 💻 WSL2 での利用

WSL2 から Windows 側の `tproxy` を利用する場合、WSL2 のネットワークモードを **ミラーモード** に設定します。

### 1. `.wslconfig` の設定
`%UserProfile%\.wslconfig` に以下を記述します：

```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=false
firewall=true
```

> **💡 各設定項目の理由**:  
> * **`networkingMode=mirrored`**: デフォルトの NAT モードでは WSL2 が別サブネットの仮想アダプタ扱いとなり Windows 側の WFP で透過キャプチャできません。ミラーモードに設定することでホストと同一のネットワークインターフェース・IP を共有させ、ホスト側 WinDivert で確実にパケットを捕捉します。  
> * **`dnsTunneling=false`**: `dnsTunneling=true` だと DNS が Windows 内部プロキシ経由となり DoH 昇格をバイパスしてしまいます。`dnsTunneling=false` に設定することで、WSL2 からの DNS クエリが外部 UDP 53 パケットとして送出され、`tproxy` の DoH 変換エンジンで確実にキャプチャ・暗号化されます。  
> * **`firewall=true`**: WSL2 のミラーモード通信を Windows ホストの WFP（Windows Filtering Platform）と完全統合させるために必須です。これを `true` に設定することで、WSL2 内部から発信されるパケットが Windows 側の WinDivert（`tproxy`）で確実にキャプチャされ、透過プロキシ制御・中継が行われます（`false` だと WFP をバイパスして社内プロキシへの接続失敗や制御漏れの原因になります）。

設定後、PowerShell で `wsl --shutdown` を実行して再起動すれば、WSL2 内部の curl・apt・Docker 等の通信が設定不要で透過制御されます。

### 2. 明示的プロキシの利用（環境変数）
特殊な CLI ツールなどで明示的にプロキシポートを指定したい場合も対応しています：
```bash
export http_proxy=http://127.0.0.1:18080
export https_proxy=http://127.0.0.1:18080
export all_proxy=http://127.0.0.1:18080
```
> **🔒 セキュリティ**: ポート `18080` への接続元が `127.0.0.1` / `::1` またはローカル仮想サブネット以外の場合、即座に `403 Forbidden` で遮断されます（オープンプロキシ化防止）。

---

## 📖 設定ファイル（config.json）完全リファレンス

設定ファイルは**ホットリロード対応**です（デフォルト: 5 秒周期で変更検知）。  
フィルタリングルール（ドメイン・IP）、上位プロキシ/PAC URL、DNS サーバーバイパス設定、DoH 動作パラメータ、各種タイムアウト、ログ出力先ファイルなどは、稼働中の上書き保存で即座に反映されます（※カーネル層の待受け・ドライバモードを初期化する `listen_addr` および `dry_run` の変更のみプロセスの再起動が必要です）。

全 22 種類のパラメータ一覧です。環境に合わせて設定が必要な主要項目は [config.json.sample](file:///t:/agy_test/transport_proxy/config.json.sample) に記載されています（細かい数値パラメータは省略時に推奨デフォルト値が自動適用されます）。

| キー | 型 | デフォルト | ホットリロード | 説明 |
| :--- | :---: | :---: | :---: | :--- |
| `filter_mode` | `string` | `"whitelist"` | ✅ 対応 | 動作モード。`"whitelist"` / `"blacklist"` / `"all"`（全通し）。`"none"`, `"disabled"` 等も全通しエイリアス |
| `allowed_domains` | `[]string` | `[]` | ✅ 対応 | **ホワイトリスト**で許可するドメイン・ワイルドカード（例: `"*.github.com"`） |
| `allowed_ips` | `[]string` | `[]` | ✅ 対応 | **ホワイトリスト**で許可する IP / CIDR（例: `"10.0.0.0/8"`） |
| `blocked_domains` | `[]string` | `[]` | ✅ 対応 | **ブラックリスト**で遮断するドメイン・ワイルドカード |
| `blocked_ips` | `[]string` | `[]` | ✅ 対応 | **ブラックリスト**で遮断する IP / CIDR |
| `listen_addr` | `string` | `"0.0.0.0:18080"` | ❌ 要再起動 | ローカルプロキシ待受けアドレス（ポート衝突時は自動退避） |
| `pac_url` | `string` | `""` | ✅ 対応 | 上位プロキシの PAC/WPAD URL。**空時は OS 設定（WinHTTP / WPAD）から自動検出**。WinHTTP (Win) / goja (Linux) で自動評価 |
| `upstream_proxy` | `string` | `""` | ✅ 対応 | 固定上位プロキシ URL（例: `"http://user:pass@proxy.corp.local:8080"`）。**空時は OS 設定（Win）や環境変数（Linux）から自動検出** |
| `bypass_sspi` | `bool` | `false` | ✅ 対応 | `true` で Windows SSPI 認証をスキップし、URL クレデンシャルによる Basic 認証を事前送信 |
| `dns_servers` | `[]string` | `[]` | ✅ 対応 | 上位 DNS サーバー一覧。指定時は UDP 53 直通バイパス。**空時は自動で Cloudflare Security DoH** |
| `doh_enabled` | `bool` | `true` | ✅ 対応 | DNS クエリを自動的に DoH（DNS over HTTPS）に昇格するかどうか |
| `doh_timeout_sec` | `int` | `3` | ✅ 対応 | DoH クエリのタイムアウト秒数 |
| `fallback_to_udp` | `bool` | `true` | ✅ 対応 | DoH 失敗時に平文 UDP 53 へフォールバックするかどうか |
| `dns_cache_enabled` | `bool` | `true` | ✅ 対応 | インメモリ DNS キャッシュ（2回目以降 0ms 応答）の有効/無効 |
| `dns_cache_ttl_sec` | `int` | `300` | ✅ 対応 | DNS キャッシュの最大保持秒数（TTL） |
| `connect_timeout_sec` | `int` | `10` | ✅ 対応 | 上流サーバー / 上位プロキシへの TCP 接続タイムアウト秒数 |
| `idle_timeout_sec` | `int` | `60` | ✅ 対応 | 無通信接続の切断秒数。`0` で無期限維持（RDP・SSH に推奨） |
| `reload_interval_sec` | `int` | `5` | ✅ 対応 | 設定ファイルのホットリロード変更検知周期（秒。変更時は即座に再設定） |
| `log_file` | `string` | `""` | ✅ 対応 | ログ出力先ファイルパス（変更時は新しいファイルへ自動切り替え） |
| `filter_udp` | `bool` | `false` | ✅ 対応 | 一般 UDP 通信（DNS 53/QUIC 443以外）の監査・制御。`filter_mode: "all"` 時は制限せず `[ALLOW] UDP` ログ出力＆パススルー |
| `dry_run` | `bool` | `false` | ❌ 要再起動 | `true` で通信を遮断・変更せず監査ログ出力のみ行うモード |
| `divert_filter` | `string` | `""` | ❌ 要再起動 | WinDivert のカスタムキャプチャ条件（通常は空文字推奨） |

---

## ⚙️ 起動オプション（CLI 引数）

```powershell
# 構文
.\tproxy.exe [オプション]

# 例: 詳細デバッグログをコンソール出力しつつファイルにも保存
.\tproxy.exe -v -log tproxy.log
```

| オプション | 短縮形 | デフォルト | 説明 |
| :--- | :---: | :---: | :--- |
| `-c <file>` | — | `config.json` | 設定ファイルのパスを指定 |
| `-v` | `-verbose` | `false` | 詳細デバッグログを出力（SNI 抽出やバイパス判定の詳細） |
| `-d` | `-dry-run` | `false` | ドライラン（監査）モード。通信を変更せず通過パケットをログ出力 |
| `-log <file>` | `-l <file>` | `""` | コンソール出力に加えて指定ファイルへも同期保存 |
| `-V` | `-version` | — | バージョン情報を表示して終了 |
| `-cleanup` | — | — | 異常終了時に残った OS レベルの転送ルール（iptables 等）を削除して終了 |

---

## 🏛️ アーキテクチャと内部構造（詳細解説）

### 1. Windows 版のパケットフロー

Windows 版は **WinDivert**（WFP: Windows Filtering Platform カーネルドライバ）を使用し、OS ネットワーク層でアウトバウンドパケットを直接キャプチャします。

```text
【Windows ホスト上のアプリ】
  ブラウザ / SSH / RDP / curl など（プロキシ設定なし）
         |
         v  カーネル層でキャプチャ（WFP）
  [1] WinDivert
         |
         +-- UDP 443 (QUIC) -> 自動ドロップ（ブラウザを安全に TCP/TLS へフォールバック）
         |
         +-- UDP 53 (DNS) ---> DNS ワーカースレッド（16並列）
         |                      |  Singleflight 重複排除 + DoH 昇格 + キャッシュ
         |                      v
         |                    WinDivert で応答パケットをカーネルへ直接インジェクト
         |
         +-- UDP (その他) ----> filter_udp=true 時: フロー重複排除 + 監査ログ出力
         |                      (filter_mode: "all" 時は制限せず無遅延パススルー)
         |
         +-- TCP (その他)  --> パケットをローカルプロキシへリダイレクト
                                |
                                v
  [2] ローカルプロキシ [::]:18080  <---- WSL2 / 外部ツール（明示的 CONNECT）
       |  NATテーブル逆引きで本来の宛先 IP:Port を復元
       v
  [3] フィルタエンジン（ホワイト/ブラックリスト）
       |  不許可 --> 強制切断 (403 / RST)
       |  許可
       v
  [4] L7 プロトコルディスパッチャー（TLS SNI / HTTP Host / SSH / RDP 等を自動判別）
       |  上位プロキシ未設定 --> DIRECT 接続
       |  上位プロキシ設定時 --> SSPI/NTLM/Basic 自動認証 --> プロキシ経由
       v
  [5] 上流サーバー / 社内プロキシ
```

#### HTTP/3 (QUIC) 自動フォールバック機構
Chrome や Edge などのモダンブラウザは、デフォルトで HTTP/3（QUIC: UDP 443）通信を優先して試行します。UDP 443 が通過すると TLS SNI 検査やプロキシ中継をすり抜けてしまうため、WinDivert レイヤーで UDP 443 パケットを自動的にドロップ（破棄）します。これにより、ブラウザは標準仕様に則って即座に TCP（HTTP/1.1・HTTP/2 / TLS）へ安全にフォールバックし、本ソフトによる確実なポリシー制御・プロキシ中継が行われます。

#### 一般 UDP 通信の監査・パススルー（`filter_udp`）
`filter_udp: true` を設定すると、DNS (53) や QUIC (443) 以外の一般的な UDP 通信（NTP、WebRTC、各種業務アプリ等）も監査・制御の対象に含めることができます。  
* **フロー重複排除（UDP Flow Table）**: UDP は 1 秒間に数百パケット流れるため、通信ペア（送信元 ↔ 宛先）をメモリ上で軽量追跡し、セッション開始時にのみ監査ログ（`[ALLOW] UDP` または `[BLOCK] UDP`）を出力します。
* **`filter_mode: "all"` での無制限パススルー**: `filter_mode` が `"all"` の場合、通信を一切ブロックせず `[ALLOW] UDP` ログを記録した上で、そのままネットワークへ再インジェクト（通過）させます。業務通信に遅延や影響を与えることなく、全 UDP 通信の可視化が可能です。

#### Windows 独自のポート保護機構（PortGuard）
Windows 版では、プロキシ自身が発する上流へのアウトバウンド接続が WinDivert に再キャプチャされて無限ループに陥るのを防ぐため、送信元ポート範囲（`40000-48999`）を予約しています。  
外部の別アプリがこのポート範囲を誤ってバインドして通信が不安定化するのを防止するため、**`PortGuard` 機構**が常時バックグラウンドで稼働します：

1. **OS カーネル排他予約**: 起動時に `netsh int ipv4/ipv6 add excludedportrange` を実行し、Windows カーネルのポート割り当てテーブルで `40000-48999` を排他予約（終了時に自動解除）。
2. **アクティブ TCP スキャナー**: 15 秒周期で OS の TCP 接続テーブルを自動巡回スキャンし、他プロセスが万一このポート範囲を使用していた場合、警告ログを発行して管理者に通知します。

---

### 2. Ubuntu (Linux) 版のパケットフロー

Ubuntu 版は Linux 標準の **Netfilter** (`iptables`) を使い、ローカル発の TCP/UDP パケットをローカルプロキシへリダイレクトします。

```text
【Ubuntu ホスト / Docker コンテナ上のアプリ】
  curl / apt / ブラウザ / Docker など（プロキシ設定なし）
         |
         +-- ホスト発通信 (OUTPUT チェイン: TPROXY_RULES)
         |     |-- UDP 53 (DNS) --> 127.0.0.1:18180 (プロキシポート + 100)
         |     \-- TCP (その他) --> 0.0.0.0:18080 (ローカルプロキシ)
         |
         +-- Docker / 転送パケット (PREROUTING チェイン: TPROXY_PRE)
               |-- UDP 53 (DNS) --> 0.0.0.0:18181 (プロキシポート + 101)
               \-- TCP (その他) --> 0.0.0.0:18080 (ローカルプロキシ)
                                      |
                                      v
  [1] DNS UDP デュアルリスナー (:18180 / :18181)
        |  SO_MARK=0xff でループ防止
        |  Singleflight 重複排除 + DoH 昇格 + キャッシュ (passthrough 時は平文 UDP 転送)
        v
      UDP 応答をクライアントへ直接返送

  [2] ローカルプロキシ 0.0.0.0:18080
       |  SO_ORIGINAL_DST で本来の宛先 IP:Port を取得
       v
  [3] フィルタエンジン（ホワイト/ブラックリスト）
       |  不許可 --> 強制切断
       |  許可
       v
  [4] L7 プロトコルディスパッチャー
       |  上位プロキシ未設定 --> DIRECT 接続
       |  上位プロキシ設定時 --> Basic 認証等 --> プロキシ経由
       v
  [5] 上流サーバー / 社内プロキシ
```

> **デュアル DNS リスナー構成**: ホスト自身からの DNS クエリ（OUTPUT チェイン）は `127.0.0.1:18180` で捕捉し、Docker コンテナやブリッジからの転送 DNS クエリ（PREROUTING チェイン）は `:18181`（プロキシポート + 101）で捕捉してそれぞれ安全に DoH 昇格・返送します。プロキシ自身が発する DoH 通信および TCP アウトバウンド接続には `SO_MARK=0xff` を付与して iptables ルールをバイパスし、自己ループを防止しています。

---

### 3. Windows 版と Ubuntu 版の詳細比較

| 比較項目 | Windows 版 | Ubuntu 版 |
| :--- | :--- | :--- |
| **パケット取得レイヤー** | WFP（Windows Filtering Platform）カーネル層 | Netfilter / iptables（Linux カーネル） |
| **使用コンポーネント** | WinDivert.dll + WinDivert64.sys（外部ドライバ） | iptables / ip6tables（OS 標準） |
| **宛先 IP の復元方法** | WinDivert NAT テーブル逆引き | `SO_ORIGINAL_DST` ソケットオプション |
| **DNS パケットの取得方法** | WinDivert が UDP 53 をカーネル層で直接キャプチャ | iptables REDIRECT で UDP リスナー（ホスト: :18180, Docker: :18181）へ転送 |
| **DNS 応答の返送方法** | WinDivert で偽造パケットを直接インジェクト | UDP ソケットでクライアントへ直接 `WriteTo` |  
| **DoH ループ防止** | WinDivert フィルタのポート範囲で自動除外 | プロキシ発パケットに `SO_MARK=0xff` を付与して iptables をバイパス |
| **自己ポート保護** | PortGuard（netsh ポート排他予約 + 15s スキャナー） | iptables `--mark 0xff` / `--uid-owner` 除外 |
| **起動権限** | 管理者（Administrator）必須 | sudo 必須 |
| **終了時のクリーンアップ** | WinDivert ドライバ自動アンロード | iptables / ip6tables ルール自動削除 |
| **PAC 評価エンジン** | WinHTTP API（OS 標準） | ピュア Go `goja`（JS エンジン内蔵） |
| **プロキシ自動判別の情報源** | Windows OS 設定（WinHTTP / WPAD / インターネット設定） | 環境変数（`https_proxy`, `http_proxy` 等） |
| **上位プロキシ認証** | SSPI / NTLM / Kerberos（Windows SSO）＋ Basic 認証 | Basic 認証（事前送信 / チャレンジ応答。※ SSPI/NTLM 非対応） |
| **HTTP/3 (QUIC) 制御** | UDP 443 自動ドロップ（ブラウザを安全に TCP へフォールバック） | iptables による TCP / DNS リダイレクト |
| **常駐サービス化** | 非対応（手動起動） | `systemd` スクリプト付属 |
| **WSL2 との関係** | WSL2 の通信源として機能 | WSL2 自体が Ubuntu 版相当 |

---

### 4. L7 プロトコル自動判別（シグネチャ自動検知）

通信開始の先頭数バイトを読み取り、**ポート番号に依存せずプロトコルを自動識別**します：

| プロトコル | シグネチャ | 動作 |
| :--- | :--- | :--- |
| **HTTPS (TLS)** | `0x16 0x03`（TLS ClientHello） | SNI（サーバー名）を抽出してポリシー判定 |
| **HTTP（平文）** | `GET ` / `POST ` / `CONNECT ` 等 | `Host:` ヘッダーを抽出してポリシー判定 |
| **RDP** | `0x03 0x00 ... 0xE0`（TPKT v3 + X.224 CR） | DIRECT + アイドルタイムアウト自動解除 |
| **SSH** | `"SSH-"`（RFC 4253 バナー） | DIRECT + アイドルタイムアウト自動解除 |
| **VNC** | `"RFB "`（RFC 6143 バナー） | DIRECT + アイドルタイムアウト自動解除 |
| **その他 TCP** | 上記以外 | 宛先 IP:Port に基づき DIRECT |

---

## 📁 ディレクトリ構成

```text
transport_proxy/
├── cmd/tproxy/
│   ├── main.go              # エントリポイント・Graceful Shutdown・ホットリロード統括
│   ├── main_test.go         # CLI 引数・同期ロガー単体テスト
│   ├── admin_windows.go     # Windows 管理者権限チェック・クリーンアップスタブ
│   └── admin_linux.go       # Linux root/sudo 権限チェック・iptables クリーンアップ
├── internal/
│   ├── config/              # 設定読み込み・動的ホットリロード・WinDivert フィルタ生成
│   ├── dns/                 # DNS-to-DoH 昇格・RFC 1035/8484 パーサー・Singleflight・キャッシュ
│   ├── filter/              # ホワイトリスト/ブラックリスト判定エンジン
│   ├── interceptor/         # WinDivert (Win) / iptables (Linux) 傍受・NAT・PortGuard
│   ├── pac/                 # WinHTTP (Win) / goja JS エンジン (Linux) PAC 自動解決
│   ├── proxy/               # 透過 + 明示的ハイブリッドプロキシ・Basic/SSPI 認証・双方向パイプ
│   ├── sspi/                # Windows SSPI (secur32.dll) SSO 認証 & Basic 認証ハンドシェイク
│   └── logger/              # デバッグ・コンソールロガー
├── tools/mock_proxy/        # 検証用モックプロキシ（NTLM/SSO/Basic 認証・PAC サーバー内蔵）
├── scripts/
│   ├── install-ubuntu.sh    # Ubuntu systemd サービス登録スクリプト
│   ├── run_tests_all.ps1    # Win / WSL / Docker 3環境一括自動テストスクリプト
│   └── tproxy.service       # systemd ユニットファイル
├── Dockerfile.test          # Docker (Ubuntu) テスト実行用コンテナ定義
├── WinDivert.dll            # WinDivert x64 ライブラリ
├── WinDivert64.sys          # WinDivert x64 カーネルドライバ
├── config.json              # 設定ファイル
└── config.json.sample       # 設定ファイルのサンプル（全パラメータ記載）
```

---

## 🛠️ 動作要件 & セキュリティポリシー

### 動作環境

| 項目 | Windows 版 | Ubuntu 版 |
| :--- | :--- | :--- |
| **OS** | Windows 10 / 11 / Server 2016 以降（64-bit） | Ubuntu 20.04 以降 / 任意の Linux |
| **権限** | 管理者（Administrator） | sudo |
| **追加ドライバ** | WinDivert.dll + WinDivert64.sys | 不要（iptables 使用） |
| **Go バージョン** | Go 1.21 以上（CGO 不要） | Go 1.21 以上（CGO 不要） |

### ⚠️ ビルド済みバイナリを配布していない理由

本ソフトウェアは、OS のネットワーク通信をカーネル層で直接操作するという性質上、利用者に「このソフトに悪意がないこと」を確信したうえで使っていただきたいと考えています。そのため、**ビルド済みの実行ファイル（exe・バイナリ）はあえて配布していません。**

ソースコードをご自身の目で確認し、納得したうえで `go build` でビルドしてください。すべてのコードはこのリポジトリ内で公開されています。

### ⚡ Go 言語を採用している理由（なぜ高速なのか）

本ソフトは、OS 全体のネットワーク通信を高スループット・極小レイテンシで中継するために **Go 言語（Golang）** を採用しています：

* **ネイティブマシンコード直接実行**: Python や Java のようなインタプリタや仮想マシン（JVM）を挟まず、OS ネイティブの x64 マシン語へ直接コンパイルされるため、起動がミリ秒単位で CPU 実行オーバーヘッドが極小です。
* **超軽量スレッド（ゴルーチン / Goroutine）**: OS スレッド（通常 1〜2 MB）と異なり、初期スタック約 2 KB で動作するため、数万〜数十万の同時セッションをわずかなメモリ消費で並行処理できます。
* **OS 最速の非同期 I/O（`netpoller`）**: Windows の **IOCP** や Linux の **epoll** を Go ランタイムが自動利用し、OS カーネル限界レベルのネットワークスループットを引き出します。
* **マイクロ秒単位の超低遅延 GC**: ガベージコレクションの一時停止が通常 1 ミリ秒未満（数十〜数百マイクロ秒）に抑えられており、パケット中継やリアルタイム通信がカクつきません。
* **実績あるインフラ標準**: Docker、Kubernetes、Cloudflare プロキシ基盤、Caddy、Tailscale など、現代の世界規模ネットワークインフラの多くが Go で構築されていることからも、その通信性能と安定性が証明されています。

---

## 🧪 テスト・クロスプラットフォーム検証

本プロジェクトには、Windows ネイティブ・WSL (Linux)・Docker (Ubuntu) の 3 環境で自動テストを実行できるテストオーケストレーションツールおよび 60 以上の単体・結合テストが備わっています。

### 1. 全環境一括自動テスト（推奨）

Windows の PowerShell から以下のスクリプトを実行するだけで、**Windows・WSL・Docker (Ubuntu) の 3 環境を順番に自動検出し、全テストスイートを実行** します。

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_tests_all.ps1
```

```powershell
# オプション例
.\scripts\run_tests_all.ps1 -SkipWSL     # WSL テストをスキップ
.\scripts\run_tests_all.ps1 -SkipDocker  # Docker テストをスキップ
.\scripts\run_tests_all.ps1 -SkipWindows # Windows テストをスキップ
```

### 2. 環境別の個別テスト実行

* **A. Windows ネイティブで実行**:
  ```powershell
  go test -v ./...
  ```
* **B. WSL (Linux) から実行**:
  ```powershell
  wsl -- bash -c "cd \"\$(wslpath '$PWD')\" && go test -v ./..."
  ```
* **C. Docker (Ubuntu コンテナ) で実行**:
  ```bash
  wsl -- bash -c "docker build -f Dockerfile.test -t tproxy-test . && docker run --rm tproxy-test"
  ```

### 3. 主なテスト対象と検証内容

| テスト項目 | 対象パッケージ | 主な検証内容 |
| :--- | :--- | :--- |
| **エントリポイント** | `cmd/tproxy` | CLI 引数パース、バージョン定数整合性、リアルタイム同期ログ書き込み |
| **設定・ホットリロード** | `internal/config` | JSON パース、サンプル設定整合性、動的パラメータ反映、WinDivert フィルタ生成 |
| **ドメインフィルタ** | `internal/filter` | ホワイト/ブラック/All-Pass モード、大文字小文字・末尾ドット・IPv6 等 16 境界値、並行更新 |
| **パケット傍受・NAT** | `internal/interceptor` | L7 スニッフィング、高速チェックサム計算、DNS 直通トグル、ポート競合検知 |
| **プロキシ転送・可用性** | `internal/proxy` | E2E プロキシトンネル、20MB 大容量ファイル転送、常時維持判定、Server-First 判定 |
| **社内プロキシ・認証** | `internal/sspi` | Windows SSPI (NTLM/Negotiate)、Basic 認証事前送信、407 切断検知、特殊記号認証 |
| **PAC エンジン** | `internal/pac` | WinHTTP API (Win) / goja (Linux) PAC 自動評価、タイムアウト遮断、ホットリロード |
| **DNS 昇格・DoH** | `internal/dns` | RFC 1035/8484 パース、キャッシュ、**Singleflight 重複排除・パニック安全性** |
